use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, BufReader, Read, SeekFrom};
use std::path::Path;
use std::sync::{Arc, RwLock};

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

#[derive(Debug)]
pub struct MemoryRegion<'ctx> {
    pub start_address: u64,
    pub end_address: u64,
    pub concrete_data: Vec<u8>,  // Holds only the concrete data (compact, 1 byte per memory cell)
    pub symbolic_data: BTreeMap<usize, Arc<BV<'ctx>>>, // Holds symbolic data for only some addresses, sorted by offset
    pub prot: i32,  // Protection flags (e.g., PROT_READ, PROT_WRITE)
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
            symbolic_data: BTreeMap::new(),  // Initially, no symbolic values
            prot,
        }
    }

    /// Write a symbolic value to a given offset.
    pub fn write_symbolic(&mut self, offset: usize, symbolic: Arc<BV<'ctx>>) {
        self.symbolic_data.insert(offset, symbolic);
    }

    /// Read a symbolic value from a given offset (if it exists).
    pub fn read_symbolic(&self, offset: usize) -> Option<Arc<BV<'ctx>>> {
        self.symbolic_data.get(&offset).cloned()
    }

    /// Remove a symbolic value from a given offset (if it exists).
    pub fn remove_symbolic(&mut self, offset: usize) {
        self.symbolic_data.remove(&offset);
    }
}

#[derive(Clone, Debug)]
pub struct MemoryX86_64<'ctx> {
    pub regions: Arc<RwLock<Vec<MemoryRegion<'ctx>>>>,
    pub ctx: &'ctx Context,
    pub vfs: Arc<RwLock<VirtualFileSystem>>,
}

impl<'ctx> MemoryX86_64<'ctx> {
    pub fn new(ctx: &'ctx Context, vfs: Arc<RwLock<VirtualFileSystem>>) -> Result<Self, MemoryError> {
        Ok(MemoryX86_64 {
            regions: Arc::new(RwLock::new(Vec::new())),
            ctx,
            vfs,
        })
    }

    pub fn load_all_dumps(&self) -> Result<(), MemoryError> {
        let zorya_dir = {
            let info = GLOBAL_TARGET_INFO.lock().unwrap();
            info.zorya_path.clone()
        };

        let dumps_dir_path = zorya_dir.join("external").join("qemu-mount").join("dumps");

        let entries = fs::read_dir(dumps_dir_path)?;
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() && path.extension().map_or(false, |e| e == "bin") {
                println!("Initializing memory section from file: {:?}", path);
                self.load_memory_dump_with_dynamic_chunk_size(&path)?;
            }
        }
        Ok(())
    }

    /// Load memory dump with dynamic chunk size and handle symbolic values separately.
    pub fn load_memory_dump_with_dynamic_chunk_size(&self, file_path: &Path) -> Result<(), MemoryError> {
        let start_addr = self.parse_start_address_from_path(file_path)?;
        let file = File::open(file_path)?;
        let file_len = file.metadata()?.len();
    
        let chunk_size = match file_len {
            0..=100_000_000 => 64 * 1024, // 64 KB chunks for small files
            100_000_001..=1_000_000_000 => 256 * 1024, // 256 KB chunks for medium files
            _ => 1 * 1024 * 1024, // 1 MB chunks for large files
        };
    
        let mut memory_region = MemoryRegion::new(start_addr, file_len as usize, PROT_READ | PROT_WRITE);
    
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
        let file_name = path.file_name().ok_or(io::Error::new(io::ErrorKind::NotFound, "File name not found"))?;
        let file_str = file_name.to_str().ok_or(io::Error::new(io::ErrorKind::InvalidData, "Invalid file name"))?;
        let re = Regex::new(r"^(0x[[:xdigit:]]+)-")?;
        let caps = re.captures(file_str).ok_or(io::Error::new(io::ErrorKind::InvalidData, "Regex capture failed"))?;
        let start_str = caps.get(1).ok_or(io::Error::new(io::ErrorKind::InvalidData, "Capture group empty"))?.as_str();
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
    pub fn read_symbolic(&self, address: u64) -> Result<Option<Arc<BV<'ctx>>>, MemoryError> {
        let regions = self.regions.read().unwrap();
        for region in regions.iter() {
            if region.contains(address, 1) {
                let offset = region.offset(address);
                return Ok(region.read_symbolic(offset));
            }
        }
        Err(MemoryError::ReadOutOfBounds)
    }

    /// Reads concrete and symbolic memory from a given address range.
    pub fn read_memory(&self, address: u64, size: usize) -> Result<(Vec<u8>, Vec<Option<Arc<BV<'ctx>>>>), MemoryError> {
        let regions = self.regions.read().unwrap();

        for region in regions.iter() {
            if region.contains(address, size) {
                let offset = region.offset(address);

                // Collect concrete data
                let concrete = region.concrete_data[offset..offset + size].to_vec();

                // Collect symbolic data (where it exists)
                let symbolic: Vec<Option<Arc<BV<'ctx>>>> = (0..size)
                    .map(|i| region.symbolic_data.get(&(offset + i)).cloned())
                    .collect();

                return Ok((concrete, symbolic));
            }
        }

        Err(MemoryError::ReadOutOfBounds)
    }

    /// Reads a sequence of bytes from memory.
    pub fn read_bytes(&self, address: u64, size: usize) -> Result<Vec<u8>, MemoryError> {
        let (concrete, _symbolic) = self.read_memory(address, size)?;  // Only use the concrete part
        Ok(concrete)
    }
    /// Reads a null-terminated string from memory.
    pub fn read_string(&self, address: u64) -> Result<String, MemoryError> {
        let mut result = Vec::new();
        let mut addr = address;

        loop {
            let (concrete, _symbolic) = self.read_memory(addr, 1)?;  // Only use the concrete part
            let byte = concrete[0];  // Access the first byte
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
        let (concrete, symbolic) = self.read_memory(address, byte_size)?;  // Get both parts
        
        // Build the concrete value
        let concrete_value = {
            let mut padded = concrete.clone();
            while padded.len() < 8 {
                padded.push(0);
            }
            u64::from_le_bytes(padded.as_slice().try_into().unwrap())
        };

        // Start with a default symbolic value if the last symbolic is None
        let mut symbolic_value = match symbolic.last().and_then(|s| s.clone()) {
            Some(symb) => symb,  // Use the last symbolic value if it exists
            None => Arc::new(BV::from_u64(self.ctx, concrete_value, size)),  // Default to a concrete-based symbolic value
        };

        // Iterate through the rest of the symbolic values and concatenate them
        for symb in symbolic.iter().rev().skip(1) {
            if let Some(symb) = symb {
                symbolic_value = Arc::new(symb.concat(&symbolic_value));
            }
        }

        Ok(MemoryValue {
            concrete: concrete_value,
            symbolic: (*symbolic_value).clone(),
            size,
        })
    }   

    /// Writes concrete and symbolic memory to a given address range.
    pub fn write_memory(&self, address: u64, concrete: &[u8], symbolic: &[Option<Arc<BV<'ctx>>>]) -> Result<(), MemoryError> {
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
                        region.remove_symbolic(offset + i);  // Remove symbolic data if `None`
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
        let symbolic: Vec<Option<Arc<BV<'ctx>>>> = vec![None; bytes.len()];

        self.write_memory(address, bytes, &symbolic)
    }

    /// Writes a MemoryValue (both concrete and symbolic) to memory.
    pub fn write_value(&self, address: u64, value: &MemoryValue<'ctx>) -> Result<(), MemoryError> {
        let byte_size = ((value.size + 7) / 8) as usize; // Calculate the byte size from the bit size
        
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

        // Prepare symbolic bytes
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

        // Write concrete and symbolic parts separately
        let symbolic: Vec<Option<Arc<BV<'ctx>>>> = symbolic_bytes
            .into_iter()
            .map(|bv| Some(Arc::new(bv)))
            .collect();

        // Write to memory
        self.write_memory(address, &concrete_bytes, &symbolic)
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
    
        // create a 4KB memory region that includes this start_address
        let mut regions = self.regions.write().unwrap();
    
        // Check if any region already covers the address 0x300000
        let region_exists = regions.iter().any(|region| region.contains(start_address, 4 * values.len()));
    
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
        println!("Initialized CPUID memory variables at address 0x{:x}", start_address);
    
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
        const MAP_ANONYMOUS: i32 = 0x20;
        const MAP_FIXED: i32 = 0x10;

        let mut regions = self.regions.write().unwrap();

        // Determine the starting address
        let start_address = if addr != 0 && (flags & MAP_FIXED) != 0 {
            addr
        } else {
            regions
                .last()
                .map(|region| region.end_address + 0x1000) // Add a page size
                .unwrap_or(0x1000_0000) // Start from a default address if no regions exist
        };

        // Create a new memory region
        let mut concrete_data = vec![0; length];
        let symbolic_data = BTreeMap::new();

        if (flags & MAP_ANONYMOUS) != 0 {
            // Anonymous mapping: leave the concrete data as zeros and no symbolic values
            // No need to check `fd`
        } else {
            // File-backed mapping
            if fd < 0 {
                return Err(MemoryError::InvalidFileDescriptor);
            }

            // Access the virtual file system to read data
            let vfs = self.vfs.read().unwrap();
            let file = vfs.get_file(fd as u32).ok_or(MemoryError::InvalidFileDescriptor)?;

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
            end_address: start_address + length as u64,
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
}

#[derive(Clone, Debug)]
pub struct Sigaction<'ctx> {
    pub handler: MemoryValue<'ctx>,   // sa_handler or sa_sigaction (union)
    pub flags: MemoryValue<'ctx>,     // sa_flags
    pub restorer: MemoryValue<'ctx>,  // sa_restorer (deprecated)
    pub mask: MemoryValue<'ctx>,      // sa_mask
}
