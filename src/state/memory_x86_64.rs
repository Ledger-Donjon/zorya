// SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::fs::{self, File};
use std::io::Write;
use std::io::{self, BufRead, BufReader, Read, SeekFrom};
use std::path::Path;
use std::rc::Rc;
use std::sync::RwLock;

use regex::Regex;
use z3::{
    ast::{Ast, BV},
    Context,
};

use super::VirtualFileSystem;
use crate::concolic::{ConcolicVar, ConcreteVar, Logger, SymbolicVar};
use crate::target_info::GLOBAL_TARGET_INFO;

pub type MemoryReadResult<'ctx> = (Vec<u8>, Vec<Option<Rc<BV<'ctx>>>>);

macro_rules! log {
    ($logger:expr, $($arg:tt)*) => {{
        if ($logger).is_enabled() {
        writeln!($logger, $($arg)*).unwrap();
        }
    }};
}

// Protection flags for memory regions
const PROT_READ: i32 = 0x1;
const PROT_WRITE: i32 = 0x2;
const PROT_EXEC: i32 = 0x4;

#[derive(Debug)]
pub enum MemoryError {
    OutOfBounds(u64, usize),
    WriteOutOfBounds,
    ReadOutOfBounds,
    IncorrectSliceLength,
    IoError(io::Error),
    RegexError(regex::Error),
    ParseIntError(std::num::ParseIntError),
    InvalidString,
    InvalidFileDescriptor,
    AddressOverflow,
    Other(String),
}

impl Error for MemoryError {}

impl fmt::Display for MemoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MemoryError::OutOfBounds(addr, size) => write!(
                f,
                "Out of bounds access at address 0x{:x} with size {}",
                addr, size
            ),
            MemoryError::WriteOutOfBounds => write!(f, "Write out of bounds"),
            MemoryError::ReadOutOfBounds => write!(f, "Read out of bounds"),
            MemoryError::IncorrectSliceLength => write!(f, "Incorrect slice length"),
            MemoryError::IoError(err) => write!(f, "IO error: {}", err),
            MemoryError::RegexError(err) => write!(f, "Regex error: {}", err),
            MemoryError::ParseIntError(err) => write!(f, "ParseInt error: {}", err),
            MemoryError::InvalidString => write!(f, "Invalid string"),
            MemoryError::InvalidFileDescriptor => write!(f, "Invalid file descriptor"),
            MemoryError::AddressOverflow => write!(f, "Address overflow"),
            MemoryError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl From<io::Error> for MemoryError {
    fn from(err: io::Error) -> Self {
        MemoryError::IoError(err)
    }
}

impl From<regex::Error> for MemoryError {
    fn from(err: regex::Error) -> Self {
        MemoryError::RegexError(err)
    }
}

impl From<std::num::ParseIntError> for MemoryError {
    fn from(err: std::num::ParseIntError) -> Self {
        MemoryError::ParseIntError(err)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct MemoryValue<'ctx> {
    pub concrete: u64,
    pub symbolic: BV<'ctx>,
    pub size: u32, // in bits
}

impl<'ctx> MemoryValue<'ctx> {
    pub fn new(concrete: u64, symbolic: BV<'ctx>, size: u32) -> Self {
        MemoryValue {
            concrete,
            symbolic,
            size,
        }
    }
}

#[derive(Debug)]
pub struct MemoryRegion<'ctx> {
    pub start_address: u64,
    pub end_address: u64,
    pub concrete_data: Vec<u8>, // Holds only the concrete data (compact, 1 byte per memory cell)
    pub symbolic_data: BTreeMap<usize, Rc<BV<'ctx>>>, // Holds symbolic data for only some addresses, sorted by offset
    pub prot: i32, // Protection flags (e.g., PROT_READ, PROT_WRITE)
}

impl<'ctx> MemoryRegion<'ctx> {
    pub fn contains(&self, address: u64, size: usize) -> bool {
        let size_u64 = size as u64;
        if address < self.start_address {
            return false;
        }
        match address.checked_add(size_u64) {
            Some(end_address) => end_address <= self.end_address,
            None => false,
        }
    }

    pub fn offset(&self, address: u64) -> usize {
        (address - self.start_address) as usize
    }

    /// Initialize a new `MemoryRegion` with the given size and protection flags.
    pub fn new(start_address: u64, size: usize, prot: i32) -> Self {
        Self {
            start_address,
            end_address: start_address + size as u64,
            concrete_data: vec![0; size], // Initialize the concrete data with zeros
            symbolic_data: BTreeMap::new(), // Initially, no symbolic values
            prot,
        }
    }

    /// Write a symbolic value to a given offset.
    pub fn write_symbolic(&mut self, offset: usize, symbolic: Rc<BV<'ctx>>) {
        self.symbolic_data.insert(offset, symbolic);
    }

    /// Read a symbolic value from a given offset (if it exists).
    pub fn read_symbolic(&self, offset: usize) -> Option<Rc<BV<'ctx>>> {
        self.symbolic_data.get(&offset).cloned()
    }

    /// Remove a symbolic value from a given offset (if it exists).
    pub fn remove_symbolic(&mut self, offset: usize) {
        self.symbolic_data.remove(&offset);
    }
}

#[derive(Clone, Debug)]
pub struct MemoryX86_64<'ctx> {
    pub regions: Rc<RwLock<Vec<MemoryRegion<'ctx>>>>,
    pub ctx: &'ctx Context,
    pub vfs: Rc<RwLock<VirtualFileSystem>>,
}

impl<'ctx> MemoryX86_64<'ctx> {
    pub fn new(
        ctx: &'ctx Context,
        vfs: Rc<RwLock<VirtualFileSystem>>,
    ) -> Result<Self, MemoryError> {
        Ok(MemoryX86_64 {
            regions: Rc::new(RwLock::new(Vec::new())),
            ctx,
            vfs,
        })
    }

    pub fn load_all_dumps(&self) -> Result<(), MemoryError> {
        let zorya_dir = {
            let info = GLOBAL_TARGET_INFO.lock().unwrap();
            info.zorya_path.clone()
        };

        let dumps_dir_path = zorya_dir
            .join("results")
            .join("initialization_data")
            .join("dumps");

        let entries = fs::read_dir(dumps_dir_path)?;
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() && path.extension().is_some_and(|e| e == "bin") {
                crate::tprintln!("Initializing memory section from file: {:?}", path);
                self.load_memory_dump_with_dynamic_chunk_size(&path)?;
            }
        }
        Ok(())
    }

    /// Load memory dump with dynamic chunk size and handle symbolic values separately.
    pub fn load_memory_dump_with_dynamic_chunk_size(
        &self,
        file_path: &Path,
    ) -> Result<(), MemoryError> {
        let start_addr = self.parse_start_address_from_path(file_path)?;
        let file = File::open(file_path)?;
        let file_len = file.metadata()?.len();

        let chunk_size = match file_len {
            0..=100_000_000 => 64 * 1024, // 64 KB chunks for small files
            100_000_001..=1_000_000_000 => 256 * 1024, // 256 KB chunks for medium files
            _ => 1024 * 1024,             // 1 MB chunks for large files
        };

        let mut memory_region =
            MemoryRegion::new(start_addr, file_len as usize, PROT_READ | PROT_WRITE);

        let mut current_offset = 0usize;
        let mut reader = BufReader::new(file);
        let mut buffer = vec![0; chunk_size]; // Buffer for reading chunks

        while current_offset < file_len as usize {
            let bytes_read = reader.read(&mut buffer)?;
            if bytes_read == 0 {
                break; // EOF reached
            }

            // Only process concrete data (no symbolic data yet)
            for (i, &byte) in buffer[..bytes_read].iter().enumerate() {
                memory_region.concrete_data[current_offset + i] = byte;
            }

            current_offset += bytes_read;
        }

        let mut regions = self.regions.write().unwrap();
        regions.push(memory_region);
        regions.sort_by_key(|region| region.start_address);

        Ok(())
    }

    fn parse_start_address_from_path(&self, path: &Path) -> Result<u64, MemoryError> {
        let file_name = path.file_name().ok_or(io::Error::new(
            io::ErrorKind::NotFound,
            "File name not found",
        ))?;
        let file_str = file_name.to_str().ok_or(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid file name",
        ))?;
        let re = Regex::new(r"^(0x[[:xdigit:]]+)-")?;
        let caps = re.captures(file_str).ok_or(io::Error::new(
            io::ErrorKind::InvalidData,
            "Regex capture failed",
        ))?;
        let start_str = caps
            .get(1)
            .ok_or(io::Error::new(
                io::ErrorKind::InvalidData,
                "Capture group empty",
            ))?
            .as_str();
        let start_addr = u64::from_str_radix(&start_str[2..], 16)?;
        Ok(start_addr)
    }

    /// Reads a concrete value from memory.
    pub fn read_concrete(&self, address: u64, size: usize) -> Result<Vec<u8>, MemoryError> {
        let regions = self.regions.read().unwrap();
        for region in regions.iter() {
            if region.contains(address, size) {
                let offset = region.offset(address);
                return Ok(region.concrete_data[offset..offset + size].to_vec());
            }
        }
        Err(MemoryError::ReadOutOfBounds)
    }

    /// Reads a symbolic value from memory (if it exists).
    pub fn read_symbolic(&self, address: u64) -> Result<Option<Rc<BV<'ctx>>>, MemoryError> {
        let regions = self.regions.read().unwrap();
        for region in regions.iter() {
            if region.contains(address, 1) {
                let offset = region.offset(address);
                return Ok(region.read_symbolic(offset));
            }
        }
        Err(MemoryError::ReadOutOfBounds)
    }

    /// Reads both concrete and symbolic data from memory.
    /// Only returns symbolic data if it has been explicitly initialized.
    pub fn read_memory(
        &self,
        address: u64,
        size: usize,
    ) -> Result<MemoryReadResult<'ctx>, MemoryError> {
        let regions = self.regions.read().unwrap();

        for region in regions.iter() {
            if region.contains(address, size) {
                let offset = region.offset(address);

                if offset + size > region.concrete_data.len() {
                    return Err(MemoryError::ReadOutOfBounds);
                }

                let concrete = region.concrete_data[offset..offset + size].to_vec();

                let symbolic = (offset..offset + size)
                    .map(|i| region.symbolic_data.get(&i).cloned())
                    .collect();

                return Ok((concrete, symbolic));
            }
        }

        Err(MemoryError::ReadOutOfBounds)
    }

    /// Finds the start address of the memory region containing the given address
    /// Returns (start_address, end_address) of the containing region
    /// This is useful for overlay operations that need to identify regions
    pub fn find_region_bounds(&self, address: u64, size: usize) -> Option<(u64, u64)> {
        let regions = self.regions.read().unwrap();
        regions
            .iter()
            .find(|region| region.contains(address, size))
            .map(|region| (region.start_address, region.end_address))
    }

    /// Gets a raw pointer to a memory region by start address (unsafe, used for overlay)
    /// SAFETY: Caller must ensure the region pointer is not used after regions are modified
    pub fn get_region_ptr(&self, start_address: u64) -> Option<*const MemoryRegion<'ctx>> {
        let regions = self.regions.read().unwrap();
        regions
            .iter()
            .find(|region| region.start_address == start_address)
            .map(|region| region as *const MemoryRegion<'ctx>)
    }

    /// Reads a sequence of bytes from memory (concrete data only).
    pub fn read_bytes(&self, address: u64, size: usize) -> Result<Vec<u8>, MemoryError> {
        let (concrete, _) = self.read_memory(address, size)?;
        Ok(concrete)
    }

    /// Reads a null-terminated string from memory (concrete data only).
    pub fn read_string(&self, address: u64) -> Result<String, MemoryError> {
        // Read in bulk rather than one byte at a time. A single read_memory
        // call of `CHUNK` bytes does one region lookup + memcpy, avoiding the
        // massive overhead of locking per byte.
        const CHUNK: usize = 4096; // Linux PATH_MAX — no legit C string exceeds this.

        let concrete = match self.read_memory(address, CHUNK) {
            Ok((bytes, _)) => bytes,
            Err(_) => {
                // Region doesn't cover the full CHUNK; fall back to a smaller
                // attempt so we can still read short strings at region edges.
                match self.read_memory(address, 256) {
                    Ok((bytes, _)) => bytes,
                    Err(e) => return Err(e),
                }
            }
        };

        // Scan the bulk buffer for a NUL terminator.
        match concrete.iter().position(|&b| b == 0) {
            Some(pos) => {
                String::from_utf8(concrete[..pos].to_vec()).map_err(|_| MemoryError::InvalidString)
            }
            None => Err(MemoryError::InvalidString),
        }
    }

    /// Reads exactly one byte from memory, returning a ConcolicVar (concrete and symbolic).
    pub fn read_byte(&self, address: u64) -> Result<ConcolicVar<'ctx>, MemoryError> {
        let (concrete, symbolic) = self.read_memory(address, 1)?;
        let cbyte = concrete[0] as u64;

        let sym_bv = symbolic[0]
            .clone()
            .unwrap_or_else(|| Rc::new(BV::from_u64(self.ctx, cbyte, 8)));

        Ok(ConcolicVar {
            concrete: ConcreteVar::Int(cbyte),
            symbolic: SymbolicVar::Int((*sym_bv).clone()),
            ctx: self.ctx,
        })
    }

    /// Reads a MemoryValue (both concrete and symbolic) from memory
    pub fn read_value(
        &self,
        address: u64,
        size: u32,
        logger: &mut Logger,
    ) -> Result<ConcolicVar<'ctx>, MemoryError> {
        if size > 128 {
            // Handle large values (256-bit, 512-bit, etc.) by reading in 64-bit chunks
            log!(
                logger,
                "Reading {}-bit value from address 0x{:x}",
                size,
                address
            );

            let num_chunks = size.div_ceil(64) as usize; // Round up to nearest 64-bit chunk
            let mut concrete_chunks = Vec::with_capacity(num_chunks);
            let mut symbolic_chunks = Vec::with_capacity(num_chunks);

            for i in 0..num_chunks {
                let chunk_addr = address + (i as u64 * 8);
                let (concrete_bytes, symbolic_bytes) = self.read_memory(chunk_addr, 8)?;

                let chunk_value = u64::from_le_bytes(concrete_bytes.as_slice().try_into().unwrap());
                concrete_chunks.push(chunk_value);

                let symbolic_chunk = Self::concatenate_symbolic_bytes(
                    &symbolic_bytes,
                    &concrete_bytes,
                    self.ctx,
                    logger,
                    chunk_addr,
                );
                symbolic_chunks.push(symbolic_chunk);
            }

            let concrete = ConcreteVar::LargeInt(concrete_chunks);
            let symbolic = SymbolicVar::LargeInt(symbolic_chunks);

            Ok(ConcolicVar {
                concrete,
                symbolic,
                ctx: self.ctx,
            })
        } else if size == 128 {
            log!(logger, "Reading 128-bit value from address 0x{:x}", address);

            let (concrete_low, symbolic_low) = self.read_memory(address, 8)?;
            let (concrete_high, symbolic_high) = self.read_memory(address + 8, 8)?;

            let low = u64::from_le_bytes(concrete_low.as_slice().try_into().unwrap());
            let high = u64::from_le_bytes(concrete_high.as_slice().try_into().unwrap());

            let concrete = ConcreteVar::LargeInt(vec![low, high]);

            //log!(logger, "Building low 64-bit symbolic value:");
            let symbolic_low_concat = Self::concatenate_symbolic_bytes(
                &symbolic_low,
                &concrete_low,
                self.ctx,
                logger,
                address,
            );

            //log!(logger, "Building high 64-bit symbolic value:");
            let symbolic_high_concat = Self::concatenate_symbolic_bytes(
                &symbolic_high,
                &concrete_high,
                self.ctx,
                logger,
                address + 8,
            );

            let symbolic = SymbolicVar::LargeInt(vec![symbolic_low_concat, symbolic_high_concat]);

            Ok(ConcolicVar {
                concrete,
                symbolic,
                ctx: self.ctx,
            })
        } else if size <= 64 {
            let byte_size = size.div_ceil(8) as usize;
            let (mut concrete, symbolic) = self.read_memory(address, byte_size)?;

            //log!(logger, "Reading {}-bit value ({} bytes) from address 0x{:x}", size, byte_size, address);
            //log!(logger, "Raw concrete bytes: {:02x?}", concrete);

            // Pad concrete data if needed
            if concrete.len() < 8 {
                let original_len = concrete.len();
                let mut padded = vec![0u8; 8];
                padded[..concrete.len()].copy_from_slice(&concrete);
                concrete = padded;
                log!(
                    logger,
                    "Padded concrete from {} to 8 bytes: {:02x?}",
                    original_len,
                    concrete
                );
            }

            // Convert to integer value
            let value = u64::from_le_bytes(concrete.as_slice().try_into().unwrap());
            let mask = if size < 64 {
                (1u64 << size) - 1
            } else {
                u64::MAX
            };
            let masked = value & mask;
            let concrete_var = ConcreteVar::Int(masked);

            //log!(logger, "Concrete value: raw=0x{:x}, masked=0x{:x} (for {} bits)", value, masked, size);

            // Build symbolic value with detailed logging
            // log!(logger, "Building symbolic value from {} bytes:", byte_size);
            // for (i, sym_opt) in symbolic.iter().enumerate() {
            //     let byte_addr = address + i as u64;
            //     match sym_opt {
            //         Some(sym) => {
            //             log!(logger, "  Byte {} at 0x{:x}: HAS symbolic data: {:?}", i, byte_addr, sym.simplify());
            //         }
            //         None => {
            //             log!(logger, "  Byte {} at 0x{:x}: NO symbolic data (concrete: 0x{:02x})", i, byte_addr, concrete[i]);
            //         }
            //     }
            // }

            let symbolic_concat = Self::concatenate_symbolic_bytes(
                &symbolic[..byte_size], // Only use the actual bytes we read
                &concrete[..byte_size],
                self.ctx,
                logger,
                address,
            );

            // Resize symbolic value if needed
            let resized_sym = if symbolic_concat.get_size() < size {
                //log!(logger, "Zero-extending symbolic from {} to {} bits", symbolic_concat.get_size(), size);
                symbolic_concat.zero_ext(size - symbolic_concat.get_size())
            } else if symbolic_concat.get_size() > size {
                //log!(logger, "Extracting {} bits from {}-bit symbolic value", size, symbolic_concat.get_size());
                symbolic_concat.extract(size - 1, 0)
            } else {
                //log!(logger, "Symbolic size {} matches requested size {}", symbolic_concat.get_size(), size);
                symbolic_concat
            };

            let symbolic_var = SymbolicVar::Int(resized_sym.clone());

            //log!(logger, "Final result: concrete=0x{:x}, symbolic={:?}", masked, resized_sym.simplify());

            Ok(ConcolicVar {
                concrete: concrete_var,
                symbolic: symbolic_var,
                ctx: self.ctx,
            })
        } else {
            Err(MemoryError::InvalidString)
        }
    }

    /// Helper function to concatenate symbolic bytes into a single BV with detailed logging
    fn concatenate_symbolic_bytes(
        symbolic_bytes: &[Option<Rc<BV<'ctx>>>],
        concrete_bytes: &[u8],
        ctx: &'ctx Context,
        logger: &mut Logger,
        address: u64,
    ) -> BV<'ctx> {
        // Fast path: if no byte has symbolic data, build the BV directly from the concrete
        // value.  This avoids 7 `BV::from_u64` + 7 `concat` Z3 node allocations for the
        // common case of fully-concrete memory (e.g. code/rodata regions, freshly-written
        // stack slots).
        if symbolic_bytes.iter().all(|s| s.is_none()) {
            let size_bits = (symbolic_bytes.len() * 8) as u32;
            // Assemble the concrete value from the bytes (little-endian)
            let mut padded = [0u8; 8];
            let copy_len = concrete_bytes.len().min(8);
            padded[..copy_len].copy_from_slice(&concrete_bytes[..copy_len]);
            let value = u64::from_le_bytes(padded);
            let mask = if size_bits < 64 {
                (1u64 << size_bits) - 1
            } else {
                u64::MAX
            };
            return BV::from_u64(ctx, value & mask, size_bits);
        }

        let mut result: Option<BV<'ctx>> = None;

        // Process bytes in reverse order (little-endian: least significant byte first)
        for (byte_index, (sym_opt, &concrete_byte)) in symbolic_bytes
            .iter()
            .zip(concrete_bytes.iter())
            .enumerate()
            .rev()
        {
            let _byte_addr = address + byte_index as u64;

            let byte_bv = match sym_opt {
                Some(symbolic_ref) => {
                    let sym_bv = symbolic_ref.as_ref().clone();
                    // log!(
                    //     logger,
                    //     "Byte {} at 0x{:x}: Using SYMBOLIC value {:?} (concrete=0x{:02x})",
                    //     byte_index, byte_addr, sym_bv.simplify(), concrete_byte
                    // );
                    sym_bv
                }
                None => {
                    let concrete_bv = BV::from_u64(ctx, concrete_byte as u64, 8);
                    // log!(
                    //     logger,
                    //     "Byte {} at 0x{:x}: Using CONCRETE value 0x{:02x} -> BV(0x{:02x})",
                    //     byte_index, byte_addr, concrete_byte, concrete_byte
                    // );
                    concrete_bv
                }
            };

            // Build the result by concatenating
            result = match result {
                None => {
                    // log!(logger, "  Starting with byte {}: {:?}", byte_index, byte_bv.simplify());
                    Some(byte_bv)
                }
                Some(accumulated) => {
                    let new_result = accumulated.concat(&byte_bv);
                    // log!(
                    //     logger,
                    //     "  Concatenating byte {} to existing {} bits -> {} bits total",
                    //     byte_index,
                    //     accumulated.get_size(),
                    //     new_result.get_size()
                    // );
                    // log!(logger, "    Previous: {:?}", accumulated.simplify());
                    // log!(logger, "    Added: {:?}", byte_bv.simplify());
                    // log!(logger, "    Result: {:?}", new_result.simplify());
                    Some(new_result)
                }
            };
        }

        let final_result = result.unwrap_or_else(|| {
            log!(logger, "WARNING: No bytes processed, creating zero BV");
            BV::from_u64(ctx, 0, 8)
        });

        // log!(
        //     logger,
        //     "Final concatenated result: {} bits, {:?}",
        //     final_result.get_size(),
        //     final_result.simplify()
        // );
        // log!(logger, "=== END SYMBOLIC CONCATENATION DEBUG ===");

        final_result
    }

    /// Writes concrete and symbolic memory to a given address range.
    pub fn write_memory(
        &self,
        address: u64,
        concrete: &[u8],
        symbolic: &[Option<Rc<BV<'ctx>>>],
    ) -> Result<(), MemoryError> {
        if concrete.len() != symbolic.len() {
            return Err(MemoryError::IncorrectSliceLength);
        }

        let mut regions = self.regions.write().unwrap();
        // Check if the address falls within an existing memory region
        for region in regions.iter_mut() {
            if region.contains(address, concrete.len()) {
                let offset = region.offset(address);

                // Write concrete data
                for (i, &byte) in concrete.iter().enumerate() {
                    region.concrete_data[offset + i] = byte;
                }

                // Write or remove symbolic data
                for (i, symb) in symbolic.iter().enumerate() {
                    if let Some(symb) = symb {
                        region.write_symbolic(offset + i, symb.clone());
                    } else {
                        region.remove_symbolic(offset + i); // Remove symbolic data if `None`
                    }
                }

                return Ok(());
            }
        }

        // If we reach here, the address is out of bounds of all current regions
        Err(MemoryError::WriteOutOfBounds)
    }

    /// Writes a sequence of bytes to memory.
    pub fn write_bytes(&self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        // Create a vector of `None` for symbolic values as we're only dealing with concrete data
        let symbolic: Vec<Option<Rc<BV<'ctx>>>> = vec![None; bytes.len()];

        self.write_memory(address, bytes, &symbolic)
    }

    /// Writes a MemoryValue (both concrete and symbolic) to memory.
    pub fn write_value(&self, address: u64, value: &MemoryValue<'ctx>) -> Result<(), MemoryError> {
        let byte_size = value.size.div_ceil(8) as usize; // Calculate the byte size from the bit size

        // Prepare concrete bytes for storage, padded as needed
        let mut concrete_bytes = Vec::with_capacity(byte_size);

        if byte_size > 8 {
            // If the size exceeds 8 bytes (e.g., 128 bits), split the value into parts
            let mut remaining_value = value.concrete;
            for _ in 0..byte_size {
                concrete_bytes.push((remaining_value & 0xFF) as u8); // Extract 1 byte at a time
                remaining_value >>= 8; // Shift the remaining bits
            }
        } else {
            // If the size is 8 bytes or less, use `u64::to_le_bytes()`
            concrete_bytes.extend_from_slice(&value.concrete.to_le_bytes()[..byte_size]);
        }

        // Fast path: avoid building per-byte symbolic extracts when the value is
        // fully concrete (numeral BV). This is the common case in libc-heavy
        // traces and removes a large amount of Z3 AST allocation in STORE paths.
        let symbolic: Vec<Option<Rc<BV<'ctx>>>> =
            if value.symbolic.as_u64().is_some() || value.symbolic.simplify().as_u64().is_some() {
                vec![None; byte_size]
            } else {
                let mut symbolic_bytes = Vec::with_capacity(byte_size);
                for i in 0..byte_size {
                    let low = (i * 8) as u32;
                    let high = if low + 7 >= value.size {
                        value.size - 1
                    } else {
                        low + 7
                    };
                    let byte_bv = value.symbolic.extract(high, low);
                    symbolic_bytes.push(byte_bv);
                }
                symbolic_bytes
                    .into_iter()
                    .map(|bv| Some(Rc::new(bv)))
                    .collect()
            };

        // Write to memory
        self.write_memory(address, &concrete_bytes, &symbolic)
    }

    // Additional methods for reading and writing standard data types
    pub fn read_u64(
        &self,
        address: u64,
        logger: &mut Logger,
    ) -> Result<ConcolicVar<'ctx>, MemoryError> {
        self.read_value(address, 64, logger)
    }

    pub fn write_u64(&self, address: u64, value: &MemoryValue<'ctx>) -> Result<(), MemoryError> {
        self.write_value(address, value)
    }

    pub fn read_u32(
        &self,
        address: u64,
        logger: &mut Logger,
    ) -> Result<ConcolicVar<'ctx>, MemoryError> {
        self.read_value(address, 32, logger)
    }

    pub fn write_u32(&self, address: u64, value: &MemoryValue<'ctx>) -> Result<(), MemoryError> {
        self.write_value(address, value)
    }

    pub fn initialize_cpuid_memory_variables(&self) -> Result<(), MemoryError> {
        // Initial values for EAX, EBX, ECX, EDX (you can set these values as per your requirements)
        let values = [0x00000000, 0x00000000, 0x00000000, 0x00000000];

        // Start address for the variables
        let start_address = 0x300000;

        // create a 4KB memory region that includes this start_address
        let mut regions = self.regions.write().unwrap();

        // Check if any region already covers the address 0x300000
        let region_exists = regions
            .iter()
            .any(|region| region.contains(start_address, 4 * values.len()));

        // If no region covers the 0x300000 address, we create a new one
        if !region_exists {
            let new_region = MemoryRegion::new(start_address, 0x1000, PROT_READ | PROT_WRITE); // 4KB region
            regions.push(new_region);
            regions.sort_by_key(|region| region.start_address);
        }

        drop(regions); // Drop the lock after modifying the regions

        // Now write the values to memory
        for (i, &concrete_value) in values.iter().enumerate() {
            let address = start_address + (i as u64) * 4; // Calculate address for each variable
            let symbolic_value = BV::from_u64(self.ctx, concrete_value as u64, 32);

            let mem_value = MemoryValue {
                concrete: concrete_value as u64,
                symbolic: symbolic_value,
                size: 32,
            };
            self.write_value(address, &mem_value)?; // Writing values to memory
        }
        crate::tprintln!(
            "Initialized CPUID memory variables at address 0x{:x}",
            start_address
        );

        Ok(())
    }

    pub fn read_sigaction(
        &self,
        address: u64,
        logger: &mut Logger,
    ) -> Result<Sigaction<'ctx>, MemoryError> {
        // Read the sigaction structure from memory
        let handler = self.read_u64(address, logger)?.to_memory_value_u64();
        let flags = self.read_u64(address + 8, logger)?.to_memory_value_u64();
        let restorer = self.read_u64(address + 16, logger)?.to_memory_value_u64();
        let mask = self.read_u64(address + 24, logger)?.to_memory_value_u64();
        Ok(Sigaction {
            handler,
            flags,
            restorer,
            mask,
        })
    }

    pub fn write_sigaction(
        &self,
        address: u64,
        sigaction: &Sigaction<'ctx>,
    ) -> Result<(), MemoryError> {
        // Write the sigaction structure to memory
        self.write_u64(address, &sigaction.handler)?;
        self.write_u64(address + 8, &sigaction.flags)?;
        self.write_u64(address + 16, &sigaction.restorer)?;
        self.write_u64(address + 24, &sigaction.mask)?;
        Ok(())
    }

    /// Maps a memory region, either anonymous or file-backed.
    pub fn mmap(
        &self,
        addr: u64,
        length: usize,
        prot: i32,
        flags: i32,
        fd: i32,
        offset: usize,
    ) -> Result<u64, MemoryError> {
        const MAP_ANONYMOUS: i32 = 0x20;
        const MAP_FIXED: i32 = 0x10;
        const MAX_USER_ADDRESS: u64 = 0x0000_7FFF_FFFF_FFFF; // Highest user space address

        let mut regions = self.regions.write().unwrap();

        // Determine the starting address
        let start_address = if addr != 0 && (flags & MAP_FIXED) != 0 {
            addr
        } else {
            // Start from a default base address
            let mut proposed_address = 0x1000_0000; // Adjust as needed for your application

            // Loop to find a suitable address
            loop {
                // Ensure proposed_address is within user space
                if proposed_address > MAX_USER_ADDRESS {
                    return Err(MemoryError::AddressOverflow);
                }

                let end_address = proposed_address
                    .checked_add(length as u64)
                    .ok_or(MemoryError::AddressOverflow)?;
                if end_address > MAX_USER_ADDRESS {
                    return Err(MemoryError::AddressOverflow);
                }

                // Check for overlaps with existing regions within user space
                let overlap = regions.iter().any(|region| {
                    // Skip regions outside user space
                    if region.end_address > MAX_USER_ADDRESS {
                        return false;
                    }

                    (proposed_address >= region.start_address
                        && proposed_address < region.end_address)
                        || (end_address > region.start_address && end_address <= region.end_address)
                });

                if !overlap {
                    break; // Found a suitable address
                }

                // Move proposed_address forward
                proposed_address = proposed_address
                    .checked_add(0x10000)
                    .ok_or(MemoryError::AddressOverflow)?; // Increment by 64 KiB
            }

            proposed_address
        };

        // Ensure end_address does not exceed MAX_USER_ADDRESS
        let end_address = start_address
            .checked_add(length as u64)
            .ok_or(MemoryError::AddressOverflow)?;
        if end_address > MAX_USER_ADDRESS {
            return Err(MemoryError::AddressOverflow);
        }

        // Create a new memory region
        let mut concrete_data = vec![0; length];
        let symbolic_data = BTreeMap::new();

        if (flags & MAP_ANONYMOUS) != 0 {
            // Anonymous mapping: leave the concrete data as zeros and no symbolic values
        } else {
            // File-backed mapping
            if fd < 0 {
                return Err(MemoryError::InvalidFileDescriptor);
            }

            // Access the virtual file system to read data
            let vfs = self.vfs.read().unwrap();
            let file = vfs
                .get_file(fd as u32)
                .ok_or(MemoryError::InvalidFileDescriptor)?;

            // Lock the file descriptor to perform operations
            let mut file_guard = file.lock().unwrap();

            // Seek to the specified offset
            file_guard.seek(SeekFrom::Start(offset as u64))?;

            // Read the data from the file into the concrete_data vector
            let bytes_read = file_guard.read(&mut concrete_data)?;
            // If the file is shorter than `length`, fill the rest with zeros
            if bytes_read < length {
                concrete_data[bytes_read..].fill(0);
            }
        }

        // Create and insert the new memory region
        let memory_region = MemoryRegion {
            start_address,
            end_address,
            concrete_data,
            symbolic_data,
            prot,
        };

        regions.push(memory_region);
        regions.sort_by_key(|region| region.start_address);

        Ok(start_address)
    }

    /// Check if a given address is within any of the memory regions.
    pub fn is_valid_address(&self, address: u64) -> bool {
        let regions = self.regions.read().unwrap();
        for region in regions.iter() {
            if address >= region.start_address && address < region.end_address {
                return true;
            }
        }
        false
    }

    // A small helper to parse 'r--p', 'r-xp', etc. into PROT_READ, PROT_WRITE, PROT_EXEC bits
    fn parse_protection(perms: &str) -> i32 {
        let mut prot_flags = 0;
        let chars: Vec<char> = perms.chars().collect();

        // Typically perms is something like 'r--p' or 'r-xp'
        // e.g.  [0] = 'r', [1] = '-', [2] = 'x', [3] = 'p'
        if chars.first() == Some(&'r') {
            prot_flags |= PROT_READ;
        }
        if chars.get(1) == Some(&'w') {
            prot_flags |= PROT_WRITE;
        }
        if chars.get(2) == Some(&'x') {
            prot_flags |= PROT_EXEC;
        }
        // The 'p' or 's' typically indicates private vs. shared, we won't worry about that in PROT_ flags

        prot_flags
    }

    /// True if `s` is a hex address as emitted by GDB (`0x...` or bare hex).
    fn is_hex_addr(s: &str) -> bool {
        let digits = s
            .strip_prefix("0x")
            .or_else(|| s.strip_prefix("0X"))
            .unwrap_or(s);
        !digits.is_empty() && digits.chars().all(|c| c.is_ascii_hexdigit())
    }

    /// Reads the gdb-style memory_mapping.txt and ensures each range is covered
    /// by a MemoryRegion in `self.regions`. If not, create a zero-initialized
    /// region with the appropriate permission flags.
    pub fn ensure_gdb_mappings_covered<P: AsRef<Path>>(
        &self,
        mapping_file: P,
    ) -> Result<(), MemoryError> {
        let mapping_path = mapping_file.as_ref().to_path_buf();
        let file = fs::File::open(&mapping_path)?;
        let file_len = file.metadata().map(|m| m.len()).unwrap_or(0);
        let reader = io::BufReader::new(file);

        let mut valid_rows: usize = 0;
        let mut saw_gdb_register_diagnostic = false;

        // We'll parse lines that look like:
        //  Start Addr    End Addr    Size    Offset   Perms  objfile
        //  0x200000      0x20c000    0xc000  0x0      r--p   /path/to/binary
        for line in reader.lines() {
            let line = line?;
            let trimmed = line.trim();
            // Skip blank lines, GDB headers, and diagnostics that can leak into
            // the mapping dump (e.g. QEMU user-mode / Apple Silicon Docker):
            // "Couldn't get registers: Input/output error"
            if trimmed.starts_with("Couldn't get registers") {
                saw_gdb_register_diagnostic = true;
                continue;
            }
            if trimmed.is_empty()
                || trimmed.contains("Addr")
                || trimmed.starts_with("process")
                || trimmed.starts_with("warning:")
            {
                continue;
            }

            let parts: Vec<_> = trimmed.split_whitespace().collect();
            if parts.len() < 5 {
                // At least: Start, End, Size, Offset, Perms
                continue;
            }

            let start_str = parts[0];
            let end_str = parts[1];
            let perms_str = parts[4];

            // GDB diagnostics often have >= 5 tokens; only mapping rows start
            // with hex addresses. Skip anything else instead of ParseInt-failing.
            if !Self::is_hex_addr(start_str) || !Self::is_hex_addr(end_str) {
                continue;
            }

            let start_addr = u64::from_str_radix(start_str.trim_start_matches("0x"), 16)?;
            let end_addr = u64::from_str_radix(end_str.trim_start_matches("0x"), 16)?;
            if end_addr <= start_addr {
                continue;
            }
            let size = (end_addr - start_addr) as usize;

            let prot_flags = Self::parse_protection(perms_str);

            self.ensure_region_exists(start_addr, size, prot_flags)?;
            valid_rows += 1;
        }

        // If the file had content but yielded no mapping rows, the GDB dump is
        // degenerate (e.g. only ptrace diagnostics on QEMU-user / Apple Silicon
        // Docker AMD64). Surface this loudly rather than continuing with no
        // additional coverage — which would lead to opaque out-of-bounds errors
        // deep in the concolic run.
        if file_len > 0 && valid_rows == 0 {
            let mut msg = format!(
                "GDB memory-mapping dump {} contains no parseable mapping rows",
                mapping_path.display()
            );
            if saw_gdb_register_diagnostic {
                msg.push_str(
                    ". The dump only contains \"Couldn't get registers\" diagnostics, \
                     which usually means GDB's ptrace failed inside the container \
                     (common on AMD64 Docker images on Apple Silicon / QEMU-user). \
                     Re-run dump_memory.sh on a native AMD64 host, or use \
                     FORCE_PTY=true, or drop into a VM (see the QEMU section of \
                     dump_memory.sh) so GDB can attach to the inferior correctly.",
                );
            }
            return Err(MemoryError::Other(msg));
        }

        Ok(())
    }

    // Checks if we already have a MemoryRegion covering `[start_addr, start_addr + size)`.
    // If not, create one with zero-initialized data and the given `prot_flags`.
    pub fn ensure_region_exists(
        &self,
        start_addr: u64,
        size: usize,
        prot_flags: i32,
    ) -> Result<(), MemoryError> {
        let mut regions = self.regions.write().unwrap();

        // See if any existing region fully covers this address range
        let already_covered = regions
            .iter()
            .any(|r| r.start_address <= start_addr && r.end_address >= (start_addr + size as u64));

        if !already_covered {
            // Create a new region
            let new_region = MemoryRegion::new(start_addr, size, prot_flags);
            regions.push(new_region);
            // Keep regions sorted by starting address
            regions.sort_by_key(|r| r.start_address);
        }

        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct Sigaction<'ctx> {
    pub handler: MemoryValue<'ctx>,  // sa_handler or sa_sigaction (union)
    pub flags: MemoryValue<'ctx>,    // sa_flags
    pub restorer: MemoryValue<'ctx>, // sa_restorer (deprecated)
    pub mask: MemoryValue<'ctx>,     // sa_mask
}

impl<'ctx> Sigaction<'ctx> {
    pub fn new_default(ctx: &'ctx Context) -> Self {
        Sigaction {
            handler: MemoryValue {
                concrete: 0, // Default to SIG_DFL
                symbolic: BV::from_u64(ctx, 0, 64),
                size: 64,
            },
            flags: MemoryValue {
                concrete: 0, // No special flags
                symbolic: BV::from_u64(ctx, 0, 64),
                size: 64,
            },
            restorer: MemoryValue {
                concrete: 0, // Typically unused
                symbolic: BV::from_u64(ctx, 0, 64),
                size: 64,
            },
            mask: MemoryValue {
                concrete: 0, // No signals blocked
                symbolic: BV::from_u64(ctx, 0, 64),
                size: 64,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write;
    use std::sync::RwLock;

    use z3::{Config, Context};

    use super::*;
    use crate::state::VirtualFileSystem;

    fn write_temp_mapping(contents: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "zorya_gdb_mappings_{}_{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut file = fs::File::create(&path).unwrap();
        file.write_all(contents.as_bytes()).unwrap();
        path
    }

    #[test]
    fn skips_gdb_couldnt_get_registers_diagnostic() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let vfs = Rc::new(RwLock::new(VirtualFileSystem::new()));
        let memory = MemoryX86_64::new(&ctx, vfs).unwrap();

        let mapping = "\
process 1
Start Addr           End Addr       Size     Offset  Perms  objfile
0x200000             0x20c000       0xc000   0x0     r--p   /bin/example
Couldn't get registers: Input/output error
0x20c000             0x21c000       0x10000  0xc000  r-xp   /bin/example
";
        let path = write_temp_mapping(mapping);
        let result = memory.ensure_gdb_mappings_covered(&path);
        let _ = fs::remove_file(&path);
        assert!(
            result.is_ok(),
            "GDB diagnostic must not fail mapping parse: {:?}",
            result.err()
        );

        let regions = memory.regions.read().unwrap();
        assert_eq!(regions.len(), 2);
        assert_eq!(regions[0].start_address, 0x200000);
        assert_eq!(regions[0].end_address, 0x20c000);
        assert_eq!(regions[1].start_address, 0x20c000);
        assert_eq!(regions[1].end_address, 0x21c000);
    }

    #[test]
    fn errors_when_mapping_file_is_all_gdb_diagnostics() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let vfs = Rc::new(RwLock::new(VirtualFileSystem::new()));
        let memory = MemoryX86_64::new(&ctx, vfs).unwrap();

        // Reproduces the total ptrace-failure case on Apple Silicon Docker
        // AMD64: `info proc mappings` produced no rows, only diagnostics.
        let mapping = "\
Couldn't get registers: Input/output error
Couldn't get registers: Input/output error
";
        let path = write_temp_mapping(mapping);
        let result = memory.ensure_gdb_mappings_covered(&path);
        let _ = fs::remove_file(&path);
        assert!(
            result.is_err(),
            "A dump containing only GDB diagnostics must surface as an error, \
             not silently succeed with zero extra coverage"
        );
        let err = result.err().unwrap().to_string();
        assert!(
            err.contains("Couldn't get registers") || err.contains("ptrace"),
            "Error message should hint at the QEMU-user / ptrace root cause, got: {err}"
        );
    }
}
