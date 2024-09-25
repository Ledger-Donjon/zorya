use nix::libc::MAP_FIXED;
/// Memory model for x86-64 binaries

use regex::Regex;
use z3::{ast::BV, Context};
use std::collections::BTreeMap;
use std::error::Error;
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::sync::{Arc, RwLock};
use std::{fmt, io};
use std::path::Path;


use crate::concolic::{ConcreteVar, SymbolicVar};
use crate::target_info::GLOBAL_TARGET_INFO;

// // Value fixed according to current usage
// const MAP_FIXED: i32 = 0x10;

#[derive(Debug)]
pub enum MemoryError {
    OutOfBounds(u64, usize),
    IncorrectSliceLength,
    WriteOutOfBounds,
    SymbolicAccessError,
    UninitializedAccess(u64),
    NullDereference(u64),
    IoError(io::Error),
    RegexError(regex::Error),
    ParseIntError(std::num::ParseIntError),
}

impl Error for MemoryError {}

impl fmt::Display for MemoryError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Memory error occurred")
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
pub struct MemoryConcolicValue<'ctx> {
    pub concrete: ConcreteVar, 
    pub symbolic: SymbolicVar<'ctx>,
    pub ctx: &'ctx Context,
}

impl<'ctx> MemoryConcolicValue<'ctx> {
    pub fn new(ctx: &'ctx Context, concrete_value: u64, symbolic_value: BV<'ctx>, size: u32) -> Self {
        MemoryConcolicValue {
            concrete: ConcreteVar::Int(concrete_value),
            symbolic: SymbolicVar::Int(symbolic_value),
            ctx,
        }
    }

    // Creates a default memory value zero-initialized.
    pub fn default(ctx: &'ctx Context, size: u32) -> Self {
        MemoryConcolicValue {
            concrete: ConcreteVar::Int(0),
            symbolic: SymbolicVar::Int(BV::from_u64(ctx, 0, size)),
            ctx,
        }
    }

    pub fn concolic_zero_extend(&self, new_size: u32) -> Result<Self, &'static str> {
        let current_size = self.symbolic.get_size() as u32;
        if new_size <= current_size {
            return Err("New size must be greater than current size.");
        }
        
        let extension_size = new_size - current_size;
        let zero_extended_symbolic = match &self.symbolic {
            SymbolicVar::Int(bv) => SymbolicVar::Int(bv.zero_ext(extension_size)),
            _ => return Err("Zero extension is only applicable to integer bit vectors."),
        };

        Ok(Self {
            concrete: ConcreteVar::Int(self.concrete.to_u64()),  // Concrete value remains unchanged
            symbolic: zero_extended_symbolic,
            ctx: self.ctx,
        })
    }

    // Truncate both concrete and symbolic values
    pub fn truncate(&self, offset: usize, new_size: u32, ctx: &'ctx Context) -> Result<Self, &'static str> {
        // Check if the new size and offset are valid
        if offset + new_size as usize > self.symbolic.get_size() as usize {
            return Err("Truncation range out of bounds");
        }

        // Adjust the symbolic extraction
        let high = (offset + new_size as usize - 1) as u32;
        let low = offset as u32;
        let new_symbolic = self.symbolic.extract(high, low)
            .map_err(|_| "Failed to extract symbolic part")?;  // Properly handle the Result from extract

        // Adjust the concrete value: mask the bits after shifting right
        let mask = (1u64 << new_size) - 1;
        let new_concrete = match self.concrete {
            ConcreteVar::Int(value) => (value >> offset) & mask,
            _ => return Err("Unsupported operation for this concrete type"),
        };

        Ok(MemoryConcolicValue {
            concrete: ConcreteVar::Int(new_concrete),
            symbolic: new_symbolic,
            ctx,
        })
    }
    

    // Method to retrieve the concrete u64 value
    pub fn get_concrete_value(&self) -> Result<u64, String> {
        match self.concrete {
            ConcreteVar::Int(value) => Ok(value),
            ConcreteVar::Float(value) => Ok(value as u64),  // Simplistic conversion
            ConcreteVar::Str(ref s) => u64::from_str_radix(s.trim_start_matches("0x"), 16)
                .map_err(|_| format!("Failed to parse '{}' as a hexadecimal number", s)),
            ConcreteVar::Bool(value) => Ok(value as u64),
            ConcreteVar::LargeInt(ref values) => Ok(values[0]), // Return the lower 64 bits
        }
    }     

    pub fn get_size(&self) -> u32 {
        match &self.concrete {
            ConcreteVar::Int(_) => 64,  // all integers are u64
            ConcreteVar::Float(_) => 64, // double precision floats
            ConcreteVar::Str(s) => (s.len() * 8) as u32,  // ?
            ConcreteVar::Bool(_) => 1,
            ConcreteVar::LargeInt(values) => (values.len() * 64) as u32, // Size in bits
        }
    }

    pub fn get_context_id(&self) -> String {
        format!("{:p}", self.ctx)
    }

    pub fn is_bool(&self) -> bool {
        match &self.concrete {
            ConcreteVar::Bool(_) => true,
            _ => false,
        }
    }
}

impl<'ctx> fmt::Display for MemoryConcolicValue<'ctx> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Concrete: Int(0x{:x}), Symbolic: {:?}", self.concrete, self.symbolic)
    }
}

#[derive(Clone, Debug, Default)]
pub struct Sigaction {
    pub handler: u64,   // sa_handler or sa_sigaction (union)
    pub flags: u64,     // sa_flags
    pub restorer: u64,  // sa_restorer (deprecated)
    pub mask: u64,      // sa_mask
}

#[allow(dead_code)] // for not used memory_size var for Debug
#[derive(Clone, Debug)]
pub struct MemoryX86_64<'ctx> {
    pub memory: Arc<RwLock<BTreeMap<u64, MemoryConcolicValue<'ctx>>>>,
    pub ctx: &'ctx Context,
    pub memory_size: u64,
}

impl<'ctx> MemoryX86_64<'ctx> {
    pub fn new(ctx: &'ctx Context, memory_size: u64) -> Result<Self, MemoryError> {
        Ok(MemoryX86_64 {
            memory: Arc::new(RwLock::new(BTreeMap::new())),
            ctx,
            memory_size,
        })
    }

    pub fn get_memory_concolic_var(&self, ctx: &'ctx Context, value: u64, size: u32) -> MemoryConcolicValue<'ctx> {
        println!("Inside get_or_create_memory_concolic_var function");

        let memory_read = self.memory.read().unwrap();
        let memory_value = memory_read.get(&value) // Check if the value exists in memory
            .unwrap(); 

        let memory_concolic_value = MemoryConcolicValue::new(ctx, memory_value.concrete.to_u64(), memory_value.symbolic.to_bv(ctx), size);
        memory_concolic_value
    }

    pub fn read_memory(&self, address: u64, size: usize) -> Result<Vec<u8>, MemoryError> {
        let memory = self.memory.read().unwrap();
        let mut result = Vec::with_capacity(size);
        for offset in 0..size as u64 {
            let current_address = address + offset;
            if let Some(memory_value) = memory.get(&current_address) {
                match memory_value.concrete {
                    ConcreteVar::Int(val) => result.push(val as u8),
                    _ => return Err(MemoryError::IncorrectSliceLength),
                }
            } else {
                println!("Uninitialized memory at address 0x{:x}! Set to 0x0.", current_address);
                result.push(0);
            }
        }
        if result.len() == size {
            Ok(result)
        } else {
            Err(MemoryError::IncorrectSliceLength)
        }
    }
    
    pub fn write_memory(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        let mut memory = self.memory.write().unwrap(); // Acquire write lock
        let end_address = address.checked_add(bytes.len() as u64).ok_or(MemoryError::WriteOutOfBounds)?;

        for (offset, &byte) in bytes.iter().enumerate() {
            let current_address = address + offset as u64;
            if current_address >= end_address {
                return Err(MemoryError::WriteOutOfBounds);
            }
            let byte_symbolic = BV::from_u64(self.ctx, byte as u64, 8);
            memory.insert(current_address, MemoryConcolicValue::new(self.ctx, byte.into(), byte_symbolic, 8));
        }

        Ok(())
    }

    pub fn read_sigaction(&self, address: u64) -> Result<Sigaction, MemoryError> {
        // Read the sigaction structure from memory
        let handler = self.read_u64(address)?;
        let flags = self.read_u64(address + 8)?;
        let restorer = self.read_u64(address + 16)?;
        let mask = self.read_u64(address + 24)?;
        Ok(Sigaction { handler, flags, restorer, mask })
    }

    pub fn write_sigaction(&mut self, address: u64, sigaction: &Sigaction) -> Result<(), MemoryError> {
        // Write the sigaction structure to memory
        self.write_u64(address, sigaction.handler)?;
        self.write_u64(address + 8, sigaction.flags)?;
        self.write_u64(address + 16, sigaction.restorer)?;
        self.write_u64(address + 24, sigaction.mask)?;
        Ok(())
    }

    // Helper methods to read and write u64 values
    pub fn read_u64(&self, address: u64) -> Result<u64, MemoryError> {
        let bytes = self.read_memory(address, 8)?;
        if bytes.len() == 8 {
            Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
        } else {
            Err(MemoryError::IncorrectSliceLength)
        }
    }

    pub fn write_u64(&mut self, address: u64, value: u64) -> Result<(), MemoryError> {
        let bytes = value.to_le_bytes(); // Convert u64 to 8 bytes in little-endian order
        self.write_memory(address, &bytes)
    }

    pub fn load_all_dumps(&self) -> Result<(), MemoryError> {
        let dumps_dir = {
            let info = GLOBAL_TARGET_INFO.lock().unwrap();
            info.memory_dumps.clone()
        };

        let dumps_dir_path = dumps_dir.join("dumps");

        // let dumps_dir_path = PathBuf::from("/home/kgorna/Documents/zorya/src/state/working_files/additiongo_all-u-need");

        let entries = fs::read_dir(dumps_dir_path)?;
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() && path.extension().map_or(false, |e| e == "bin") {
                println!("Initializing memory section from file: {:?}", path);
                self.load_memory_dump(&path)?;
            }
        }
        Ok(())
    }

    fn load_memory_dump(&self, file_path: &Path) -> Result<(), MemoryError> {
        let file = File::open(file_path)?;
        let mut reader = BufReader::new(file);
        let mut contents = Vec::new();
        reader.read_to_end(&mut contents)?;

        let start_addr = self.parse_start_address_from_path(file_path)?;

        let mut memory = self.memory.write().unwrap();  // Lock memory for writing
        for (offset, &byte) in contents.iter().enumerate() {
            let address = start_addr + offset as u64;
            let byte_symbolic = BV::from_u64(self.ctx, byte as u64, 8);
            memory.insert(address, MemoryConcolicValue::new(self.ctx, byte.into(), byte_symbolic, 8));
        }

        Ok(())
    }

    fn parse_start_address_from_path(&self, path: &Path) -> Result<u64, MemoryError> {
        let file_name = path.file_name().ok_or(io::Error::new(io::ErrorKind::NotFound, "File name not found"))?;
        let file_str = file_name.to_str().ok_or(io::Error::new(io::ErrorKind::InvalidData, "Invalid file name"))?;
        let re = Regex::new(r"^(0x[a-fA-F0-9]+)")?;
        let caps = re.captures(file_str).ok_or(io::Error::new(io::ErrorKind::InvalidData, "Regex capture failed"))?;
        let start_str = caps.get(1).ok_or(io::Error::new(io::ErrorKind::InvalidData, "Capture group empty"))?.as_str();
        let start_addr = u64::from_str_radix(&start_str[2..], 16)?;
        Ok(start_addr)
    }

    // Memory regions for storing temporary values of subregisters used by CPUID instruction (see executor_callother.rs)
    pub fn initialize_cpuid_memory_variables(&mut self) -> Result<(), MemoryError> {
        // Initial values for EAX, EBX, ECX, EDX (you can set these values as per your requirements)
        let values = [0x0000000, 0x0000000, 0x0000000, 0x0000000];
    
        // Start address for the variables
        let start_address = 0x300000;
    
        for (i, &value) in values.iter().enumerate() {
            let address = start_address + (i as u64) * 4; // Calculate address for each variable
            self.write_word(address, value)?;
        }
    
        Ok(())
    }

    // Read a 64-bit (quad) value from memory
    pub fn read_quad(&mut self, offset: u64) -> Result<u64, MemoryError> {
        self.read_memory(offset, 8).and_then(|bytes| {
            if bytes.len() == 8 {
                Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
            } else {
                Err(MemoryError::IncorrectSliceLength)
            }
        })
    }

    // Read a 32-bit (word) value from memory
    pub fn read_word(&mut self, offset: u64) -> Result<u32, MemoryError> {
        self.read_memory(offset, 4).and_then(|bytes| {
            if bytes.len() == 4 {
                Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
            } else {
                Err(MemoryError::IncorrectSliceLength)
            }
        })
    }

    // Read a 16-bit (half) value from memory
    pub fn read_half(&mut self, offset: u64) -> Result<u16, MemoryError> {
        self.read_memory(offset, 2).and_then(|bytes| {
            if bytes.len() == 2 {
                Ok(u16::from_le_bytes(bytes.try_into().unwrap()))
            } else {
                Err(MemoryError::IncorrectSliceLength)
            }
        })
    }

    // Read an 8-bit (byte) value from memory
    pub fn read_byte(&mut self, offset: u64) -> Result<u8, MemoryError> {
        self.read_memory(offset, 1).and_then(|bytes| {
            if bytes.len() == 1 {
                Ok(bytes[0])
            } else {
                Err(MemoryError::IncorrectSliceLength)
            }
        })
    }

    pub fn read_bytes(&mut self, address: u64, size: usize) -> Result<Vec<u8>, MemoryError> {
        let mut bytes = Vec::new();
        for i in 0..size {
            let byte = self.read_byte(address + i as u64)?;
            bytes.push(byte);
        }
        Ok(bytes)
    }

    /// Reads a null-terminated string starting from the specified memory address.
    ///
    /// This method dynamically determines the length of the string by reading each byte until
    /// a null terminator (0x00) is encountered. It constructs a `String` from the bytes read
    /// from memory, assuming they are valid UTF-8 encoded characters. This approach is commonly
    /// used for C-style strings.
    pub fn read_string(&mut self, address: u64) -> Result<String, MemoryError> {
        let mut bytes = Vec::new(); // Vector to hold the bytes that make up the string.
        let mut offset = 0; // Offset from the starting address, used to read each successive byte.

        loop {
            // Read a single byte from memory at the current address+offset.
            let byte = self.read_byte(address + offset)?;
            // Check if the byte is the null terminator (0x00), indicating the end of the string.
            if byte == 0 {
                break; // Exit the loop if we've reached the end of the string.
            }
            bytes.push(byte); // Add the byte to the vector if it's not the null terminator.
            offset += 1; // Increment the offset to move to the next byte in memory.
        }

        // Attempt to convert the bytes vector into a UTF-8 string.
        // This may fail if the bytes do not form valid UTF-8 encoded text.
        Ok(String::from_utf8(bytes).map_err(|_| MemoryError::IncorrectSliceLength)?)
    }

    // Write a 64-bit (quad) value to memory
    pub fn write_quad(&mut self, offset: u64, value: u64) -> Result<(), MemoryError> {
        let bytes = value.to_le_bytes(); // Convert the u64 value into an array of 8 bytes
        self.write_memory(offset, &bytes)
    }

    // Write a 32-bit (word) value to memory
    pub fn write_word(&mut self, offset: u64, value: u32) -> Result<(), MemoryError> {
        let bytes = value.to_le_bytes(); // Convert the u32 value into an array of 4 bytes
        self.write_memory(offset, &bytes)
    }

    // Write a 16-bit (half) value to memory
    pub fn write_half(&mut self, offset: u64, value: u16) -> Result<(), MemoryError> {
        let bytes = value.to_le_bytes(); // Convert the u16 value into an array of 2 bytes
        self.write_memory(offset, &bytes)
    }

    // Write an 8-bit (byte) value to memory
    pub fn write_bytes(&self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        let mut memory = self.memory.write().unwrap();
        for (i, &byte) in bytes.iter().enumerate() {
            let byte_symbolic = BV::from_u64(self.ctx, byte as u64, 8);
            memory.insert(address + i as u64, MemoryConcolicValue::new(self.ctx, byte.into(), byte_symbolic, 8));
        }
        Ok(())
    } 

    /// Simulates the mmap syscall with conflict checking for MAP_FIXED.
    pub fn mmap(&mut self, addr: u64, length: usize, prot: i32, flags: i32, fd: i32, offset: usize) -> Result<u64, MemoryError> {
        let page_size = 4096;
        let length_aligned = (length + page_size - 1) & !(page_size - 1);
        let start_addr = if (addr == 0 || flags & MAP_FIXED == 0) && flags & MAP_FIXED == 0 {
            self.find_free_region(length_aligned as u64)
        } else {
            Ok(addr)
        };

        let start_addr = start_addr?;

        // Clear existing mapping if MAP_FIXED is used
        if flags & MAP_FIXED != 0 {
            for i in (start_addr..start_addr + length_aligned as u64).step_by(page_size) {
                if self.memory.read().unwrap().contains_key(&i) {
                    // Conflict: Address already occupied
                    return Err(MemoryError::OutOfBounds(i, length));
                }
            }

            for i in (start_addr..start_addr + length_aligned as u64).step_by(page_size) {
                self.memory.write().unwrap().remove(&i);
            }
        }

        // Insert new mapping
        for i in (start_addr..start_addr + length_aligned as u64).step_by(page_size) {
            let memory_value = MemoryConcolicValue::default(self.ctx, 64);
            self.memory.write().unwrap().insert(i, memory_value);
        }

        Ok(start_addr)
    }

    /// Finds a free region in the virtual memory to map pages.
    fn find_free_region(&self, length: u64) -> Result<u64, MemoryError> {
        let mut base_address = 0x10000000; // Start from a base address (e.g., 256MB)
        while base_address < 0x7fffffffffff { // Below the typical user-space limit for 64-bit
            let mut occupied = false;
            for i in (base_address..base_address + length).step_by(4096) {
                if self.memory.read().unwrap().contains_key(&i) {
                    occupied = true;
                    break;
                }
            }
            if !occupied {
                return Ok(base_address);
            }
            base_address += length; // Increment by the length to find the next potential base address
        }
        Err(MemoryError::OutOfBounds(base_address, length as usize)) // No free region found
    }

    // Display trait to visualize memory state (not for cloning)
    pub fn display_memory(&self) -> fmt::Result {
        let memory = self.memory.read().unwrap();
        println!("Overview of the initialized memory:");
        for (address, memory_value) in memory.iter().take(20) {
            let concrete_value = match &memory_value.concrete {
                ConcreteVar::Int(val) => val.to_string(),
                ConcreteVar::Float(val) => val.to_string(),
                ConcreteVar::Str(val) => val.clone(),
                ConcreteVar::Bool(val) => val.to_string(),
                ConcreteVar::LargeInt(values) => {
                    let mut result = String::new();
                    for &value in values.iter().rev() {
                        result.push_str(&format!("{:016x}", value)); // Convert each u64 to a zero-padded hex string
                    }
                    // Remove leading zeros if needed
                    result.trim_start_matches('0').to_string()
                },
            };

            let symbolic_value = match &memory_value.symbolic {
                SymbolicVar::Int(bv) => format!("{}", bv),
                SymbolicVar::Float(float) => format!("{}", float),
                SymbolicVar::Bool(b) => format!("{}", b),
                SymbolicVar::LargeInt(vec) => {
                    vec.iter().map(|bv| bv.to_string()).collect::<Vec<_>>().join(" | ")
                },
            };

            println!("  {:#x}: MemoryConcolicValue {{ concrete: {}, symbolic: {} }}",
                     address, concrete_value, symbolic_value);
        }
        Ok(())
    } 
}
