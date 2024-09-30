use std::error::Error;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, SeekFrom};
use std::path::Path;
use std::sync::{Arc, RwLock};
use libc::{madvise, MADV_SEQUENTIAL};

use memmap2::Mmap;
use regex::Regex;
use z3::{ast::BV, Context};

use super::VirtualFileSystem;
use crate::target_info::GLOBAL_TARGET_INFO;

// Protection flags for memory regions
const PROT_READ: i32 = 0x1;
const PROT_WRITE: i32 = 0x2;

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
}

impl Error for MemoryError {}

impl fmt::Display for MemoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MemoryError::OutOfBounds(addr, size) => write!(f, "Out of bounds access at address 0x{:x} with size {}", addr, size),
            MemoryError::WriteOutOfBounds => write!(f, "Write out of bounds"),
            MemoryError::ReadOutOfBounds => write!(f, "Read out of bounds"),
            MemoryError::IncorrectSliceLength => write!(f, "Incorrect slice length"),
            MemoryError::IoError(err) => write!(f, "IO error: {}", err),
            MemoryError::RegexError(err) => write!(f, "Regex error: {}", err),
            MemoryError::ParseIntError(err) => write!(f, "ParseInt error: {}", err),
            MemoryError::InvalidString => write!(f, "Invalid string"),
            MemoryError::InvalidFileDescriptor => write!(f, "Invalid file descriptor"),
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

#[derive(Clone, Debug)]
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

#[derive(Clone, Debug)]
pub struct MemoryCell<'ctx> {
    pub concrete: u8,
    pub symbolic: BV<'ctx>,
}

impl<'ctx> MemoryCell<'ctx> {
    pub fn new(concrete: u8, symbolic: BV<'ctx>) -> Self {
        MemoryCell { concrete, symbolic }
    }
}

#[derive(Debug)]
pub struct MemoryRegion<'ctx> {
    pub start_address: u64,
    pub end_address: u64,
    pub data: Vec<MemoryCell<'ctx>>, // Holds both concrete and symbolic data
    pub prot: i32, // Protection flags (e.g., PROT_READ, PROT_WRITE)
}

impl<'ctx> MemoryRegion<'ctx> {
    pub fn contains(&self, address: u64, size: usize) -> bool {
        address >= self.start_address && (address + size as u64) <= self.end_address
    }

    pub fn offset(&self, address: u64) -> usize {
        (address - self.start_address) as usize
    }
}

#[derive(Clone, Debug)]
pub struct MemoryX86_64<'ctx> {
    pub regions: Arc<RwLock<Vec<MemoryRegion<'ctx>>>>,
    pub ctx: &'ctx Context,
    pub memory_size: u64,
    pub vfs: Arc<RwLock<VirtualFileSystem>>,
}

impl<'ctx> MemoryX86_64<'ctx> {
    pub fn new(ctx: &'ctx Context, memory_size: u64, vfs: Arc<RwLock<VirtualFileSystem>>) -> Result<Self, MemoryError> {
        Ok(MemoryX86_64 {
            regions: Arc::new(RwLock::new(Vec::new())),
            ctx,
            memory_size,
            vfs,
        })
    }

    pub fn load_all_dumps(&self) -> Result<(), MemoryError> {
        let dumps_dir = {
            let info = GLOBAL_TARGET_INFO.lock().unwrap();
            info.memory_dumps.clone()
        };

        let dumps_dir_path = dumps_dir.join("dumps");

        let entries = fs::read_dir(dumps_dir_path)?;
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() && path.extension().map_or(false, |e| e == "bin") {
                println!("Initializing memory section from file: {:?}", path);
                self.load_memory_dump_with_mmap_and_advice(&path)?;
            }
        }
        Ok(())
    }

    pub fn load_memory_dump_with_mmap_and_advice(&self, file_path: &Path) -> Result<(), MemoryError> {
        let start_addr = self.parse_start_address_from_path(file_path)?;
    
        // Open the file and create a memory map
        let file = File::open(file_path)?;
        let mmap = unsafe { Mmap::map(&file)? };
    
        // Provide advice to the kernel on how the memory will be used
        unsafe {
            madvise(mmap.as_ptr() as *mut _, mmap.len(), MADV_SEQUENTIAL); // or MADV_WILLNEED for prefetching
        }
    
        let symbolic = BV::new_const(self.ctx, 0, 8);
    
        let mut memory_region = MemoryRegion {
            start_address: start_addr,
            end_address: start_addr + mmap.len() as u64,
            data: Vec::new(),
            prot: PROT_READ | PROT_WRITE,
        };
    
        for &byte in mmap.iter() {
            memory_region.data.push(MemoryCell::new(byte, symbolic.clone()));
        }
    
        let mut regions = self.regions.write().unwrap();
        regions.push(memory_region);
    
        regions.sort_by_key(|region| region.start_address);
    
        Ok(())
    }

    fn parse_start_address_from_path(&self, path: &Path) -> Result<u64, MemoryError> {
        let file_name = path.file_name().ok_or(io::Error::new(io::ErrorKind::NotFound, "File name not found"))?;
        let file_str = file_name.to_str().ok_or(io::Error::new(io::ErrorKind::InvalidData, "Invalid file name"))?;
        let re = Regex::new(r"^(0x[[:xdigit:]]+)-")?;
        let caps = re.captures(file_str).ok_or(io::Error::new(io::ErrorKind::InvalidData, "Regex capture failed"))?;
        let start_str = caps.get(1).ok_or(io::Error::new(io::ErrorKind::InvalidData, "Capture group empty"))?.as_str();
        let start_addr = u64::from_str_radix(&start_str[2..], 16)?;
        Ok(start_addr)
    }

    /// Reads a sequence of MemoryCells (both concrete and symbolic) from memory.
    pub fn read_memory(&self, address: u64, size: usize) -> Result<Vec<MemoryCell<'ctx>>, MemoryError> {
        let regions = self.regions.read().unwrap();

        // Binary search for the region containing the address
        match regions.binary_search_by(|region| {
            if region.contains(address, size) {
                std::cmp::Ordering::Equal
            } else if address < region.start_address {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Less
            }
        }) {
            Ok(idx) => {
                let region = &regions[idx];
                let offset = region.offset(address);
                let data = &region.data;
                if offset + size <= data.len() {
                    let cells = data[offset..offset + size].to_vec();
                    Ok(cells)
                } else {
                    Err(MemoryError::ReadOutOfBounds)
                }
            }
            Err(_) => Err(MemoryError::ReadOutOfBounds),
        }
    }

    /// Reads a sequence of bytes from memory.
    pub fn read_bytes(&self, address: u64, size: usize) -> Result<Vec<u8>, MemoryError> {
        let cells = self.read_memory(address, size)?;
        Ok(cells.iter().map(|cell| cell.concrete).collect())
    }

    /// Reads a null-terminated string from memory.
    pub fn read_string(&self, address: u64) -> Result<String, MemoryError> {
        let mut result = Vec::new();
        let mut addr = address;

        loop {
            let cell = self.read_memory(addr, 1)?;
            let byte = cell[0].concrete;
            if byte == 0 {
                break;
            }
            result.push(byte);
            addr += 1;
        }

        String::from_utf8(result).map_err(|_| MemoryError::InvalidString)
    }

    /// Reads a MemoryValue (both concrete and symbolic) from memory.
    pub fn read_value(&self, address: u64, size: u32) -> Result<MemoryValue<'ctx>, MemoryError> {
        let byte_size = ((size + 7) / 8) as usize;
        let cells = self.read_memory(address, byte_size)?;

        // Assemble the concrete value
        let concrete_bytes = cells.iter().map(|cell| cell.concrete).collect::<Vec<u8>>();
        let concrete = {
            let mut padded = concrete_bytes.clone();
            while padded.len() < 8 {
                padded.push(0);
            }
            u64::from_le_bytes(padded.as_slice().try_into().unwrap())
        };

        // Assemble the symbolic value
        let mut symbolic = cells[cells.len() - 1].symbolic.clone();
        for cell in cells.iter().rev().skip(1) {
            symbolic = cell.symbolic.concat(&symbolic);
        }

        Ok(MemoryValue {
            concrete,
            symbolic,
            size,
        })
    }

    /// Writes a sequence of MemoryCells (both concrete and symbolic) to memory.
    pub fn write_memory(&self, address: u64, values: &[MemoryCell<'ctx>]) -> Result<(), MemoryError> {
        let mut regions = self.regions.write().unwrap();

        // Find the region containing the address
        match regions.binary_search_by(|region| {
            if region.contains(address, values.len()) {
                std::cmp::Ordering::Equal
            } else if address < region.start_address {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Less
            }
        }) {
            Ok(idx) => {
                let region = &mut regions[idx];
                let offset = region.offset(address);
                let data = &mut region.data;
                if offset + values.len() <= data.len() {
                    for (i, cell) in values.iter().enumerate() {
                        data[offset + i] = cell.clone();
                    }
                    Ok(())
                } else {
                    Err(MemoryError::WriteOutOfBounds)
                }
            }
            Err(_) => Err(MemoryError::WriteOutOfBounds),
        }
    }

    /// Writes a sequence of bytes to memory.
    pub fn write_bytes(&self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        let ctx = self.ctx;
        let cells: Vec<MemoryCell<'ctx>> = bytes.iter().map(|&byte| {
            let symbolic = BV::from_u64(ctx, byte as u64, 8);
            MemoryCell::new(byte, symbolic)
        }).collect();

        self.write_memory(address, &cells)
    }

    /// Writes a MemoryValue (both concrete and symbolic) to memory.
    pub fn write_value(&self, address: u64, value: &MemoryValue<'ctx>) -> Result<(), MemoryError> {
        let byte_size = ((value.size + 7) / 8) as usize;
        let concrete_bytes = &value.concrete.to_le_bytes()[..byte_size];

        // Split symbolic value into bytes
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

        // Create MemoryCell instances
        let mut cells = Vec::with_capacity(byte_size);
        for (concrete_byte, symbolic_byte) in concrete_bytes.iter().zip(symbolic_bytes.iter()) {
            cells.push(MemoryCell {
                concrete: *concrete_byte,
                symbolic: symbolic_byte.clone(),
            });
        }

        self.write_memory(address, &cells)
    }

    // Additional methods for reading and writing standard data types
    pub fn read_u64(&self, address: u64) -> Result<MemoryValue<'ctx>, MemoryError> {
        self.read_value(address, 64)
    }

    pub fn write_u64(&self, address: u64, value: &MemoryValue<'ctx>) -> Result<(), MemoryError> {
        self.write_value(address, value)
    }

    pub fn read_u32(&self, address: u64) -> Result<MemoryValue<'ctx>, MemoryError> {
        self.read_value(address, 32)
    }

    pub fn write_u32(&self, address: u64, value: &MemoryValue<'ctx>) -> Result<(), MemoryError> {
        self.write_value(address, value)
    }

    pub fn initialize_cpuid_memory_variables(&self) -> Result<(), MemoryError> {
        // Initial values for EAX, EBX, ECX, EDX (you can set these values as per your requirements)
        let values = [0x00000000, 0x00000000, 0x00000000, 0x00000000];

        // Start address for the variables
        let start_address = 0x300000;

        for (i, &concrete_value) in values.iter().enumerate() {
            let address = start_address + (i as u64) * 4; // Calculate address for each variable
            let symbolic_value = BV::from_u64(self.ctx, concrete_value as u64, 32);

            let mem_value = MemoryValue {
                concrete: concrete_value as u64,
                symbolic: symbolic_value,
                size: 32,
            };
            self.write_value(address, &mem_value)?;
        }

        Ok(())
    }

    pub fn read_sigaction(&self, address: u64) -> Result<Sigaction<'ctx>, MemoryError> {
        // Read the sigaction structure from memory
        let handler = self.read_u64(address)?;
        let flags = self.read_u64(address + 8)?;
        let restorer = self.read_u64(address + 16)?;
        let mask = self.read_u64(address + 24)?;
        Ok(Sigaction { handler, flags, restorer, mask })
    }

    pub fn write_sigaction(&self, address: u64, sigaction: &Sigaction<'ctx>) -> Result<(), MemoryError> {
        // Write the sigaction structure to memory
        self.write_u64(address, &sigaction.handler)?;
        self.write_u64(address + 8, &sigaction.flags)?;
        self.write_u64(address + 16, &sigaction.restorer)?;
        self.write_u64(address + 24, &sigaction.mask)?;
        Ok(())
    }

    /// Maps a memory region, either anonymous or file-backed.
    pub fn mmap(&self, addr: u64, length: usize, prot: i32, flags: i32, fd: i32, offset: usize) -> Result<u64, MemoryError> {
        // Constants for flags (define as per your system)
        const MAP_ANONYMOUS: i32 = 0x20;
        const MAP_FIXED: i32 = 0x10;

        let mut regions = self.regions.write().unwrap();

        // Determine the starting address
        let start_address = if addr != 0 && (flags & MAP_FIXED) != 0 {
            addr
        } else {
            // Find a suitable address (simple implementation: find the highest address and add some padding)
            regions
                .last()
                .map(|region| region.end_address + 0x1000) // Add a page size
                .unwrap_or(0x1000_0000) // Start from a default address if no regions exist
        };

        // Create the memory cells
        let mut data_cells = Vec::with_capacity(length);

        if (flags & MAP_ANONYMOUS) != 0 {
            // Anonymous mapping: initialize with zeros
            for _ in 0..length {
                let symbolic = BV::from_u64(self.ctx, 0, 8);
                data_cells.push(MemoryCell::new(0, symbolic));
            }
        } else {
            // File-backed mapping
            if fd < 0 {
                return Err(MemoryError::InvalidFileDescriptor);
            }

            // Access the virtual file system to read data
            let vfs = self.vfs.read().unwrap();
            let file = vfs.get_file(fd as u32).ok_or(MemoryError::InvalidFileDescriptor)?;

            // Lock the FileDescriptor to perform operations
            let mut file_guard = file.lock().unwrap();

            // Seek to the specified offset
            file_guard.seek(SeekFrom::Start(offset as u64))?;

            // Read data from the file starting at the given offset
            let mut buffer = vec![0u8; length];
            let bytes_read = file_guard.read(&mut buffer)?;

            // Initialize memory cells with the file data
            for &byte in &buffer[..bytes_read] {
                let symbolic = BV::from_u64(self.ctx, byte as u64, 8);
                data_cells.push(MemoryCell::new(byte, symbolic));
            }

            // If bytes_read < length, pad the rest with zeros
            for _ in bytes_read..length {
                let symbolic = BV::from_u64(self.ctx, 0, 8);
                data_cells.push(MemoryCell::new(0, symbolic));
            }
        }

        // Create and insert the new memory region
        let end_address = start_address + length as u64;
        let memory_region = MemoryRegion {
            start_address,
            end_address,
            data: data_cells,
            prot, // Set protection flags
        };
        regions.push(memory_region);

        // Keep regions sorted
        regions.sort_by_key(|region| region.start_address);

        Ok(start_address)
    }

}

#[derive(Clone, Debug)]
pub struct Sigaction<'ctx> {
    pub handler: MemoryValue<'ctx>,   // sa_handler or sa_sigaction (union)
    pub flags: MemoryValue<'ctx>,     // sa_flags
    pub restorer: MemoryValue<'ctx>,  // sa_restorer (deprecated)
    pub mask: MemoryValue<'ctx>,      // sa_mask
}
