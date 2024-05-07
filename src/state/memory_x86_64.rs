/// Memory model for x86-64 binaries

use regex::Regex;
use z3::{ast::BV, Context};
use std::collections::BTreeMap;
use std::error::Error;
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::sync::{Arc, RwLock};
use std::{fmt, io};
use std::path::{Path, PathBuf};

use crate::target_info::GLOBAL_TARGET_INFO;
use crate::concolic::{ConcolicEnum, ConcolicVar, ConcreteVar, SymbolicVar};

use super::cpu_state::CpuConcolicValue;

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
    pub fn new(ctx: &'ctx Context, concrete_value: u64) -> Self {
        MemoryConcolicValue {
            concrete: ConcreteVar::Int(concrete_value),
            symbolic: SymbolicVar::Int(BV::from_u64(ctx, concrete_value, 64)),
            ctx,
        }
    }

    // Creates a default memory value zero-initialized.
    pub fn default(ctx: &'ctx Context) -> Self {
        MemoryConcolicValue {
            concrete: ConcreteVar::Int(0),
            symbolic: SymbolicVar::Int(BV::from_u64(ctx, 0, 64)), // 64-bit
            ctx,
        }
    }

    // Add operation on two memory concolic variables 
    pub fn add(self, other: Self) -> Result<Self, &'static str> {
        let new_concrete = self.concrete.add(&other.concrete);
        let new_symbolic = self.symbolic.add(&other.symbolic)?;
        Ok(Self {
            concrete: new_concrete,
            symbolic: new_symbolic,
            ctx: self.ctx,
        })
    }

    // Add a memory concolic value to a const var
    pub fn add_with_var(self, var: ConcolicVar<'ctx>) -> Result<ConcolicEnum<'ctx>, &'static str> {
        let new_concrete = self.concrete.add(&var.concrete);
        let new_symbolic = self.symbolic.add(&var.symbolic)?;
        Ok(ConcolicEnum::MemoryConcolicValue(MemoryConcolicValue {
            concrete: new_concrete,
            symbolic: new_symbolic,
            ctx: self.ctx,
        }))
    }

    // Add a memory concolic value to a const var
    pub fn add_with_other(self, var: CpuConcolicValue<'ctx>) -> Result<ConcolicEnum<'ctx>, &'static str> {
        let new_concrete = self.concrete.add(&var.concrete);
        let new_symbolic = self.symbolic.add(&var.symbolic)?;
        Ok(ConcolicEnum::CpuConcolicValue(CpuConcolicValue {
            concrete: new_concrete,
            symbolic: new_symbolic,
            ctx: self.ctx,
        }))
    }

    // Method to retrieve the concrete u64 value
    pub fn get_concrete_value(&self) -> Result<u64, String> {
        match self.concrete {
            ConcreteVar::Int(value) => Ok(value),
            ConcreteVar::Float(value) => Ok(value as u64),  // Simplistic conversion
            ConcreteVar::Str(ref s) => u64::from_str_radix(s.trim_start_matches("0x"), 16)
                .map_err(|_| format!("Failed to parse '{}' as a hexadecimal number", s)),
        }
    }

    pub fn get_size(&self) -> u32 {
        match &self.concrete {
            ConcreteVar::Int(_) => 64,  // Assuming all integers are u64
            ConcreteVar::Float(_) => 64, // Assuming double precision floats
            ConcreteVar::Str(s) => (s.len() * 8) as u32,  // Example, size in bits
        }
    }
}

#[allow(dead_code)] // for not used memory_size var for Debug
#[derive(Clone, Debug)]
pub struct MemoryX86_64<'ctx> {
    pub memory: Arc<RwLock<BTreeMap<u64, MemoryConcolicValue<'ctx>>>>,
    ctx: &'ctx Context,
    memory_size: u64,
}

impl<'ctx> MemoryX86_64<'ctx> {
    pub fn new(ctx: &'ctx Context, memory_size: u64) -> Result<Self, MemoryError> {
        Ok(MemoryX86_64 {
            memory: Arc::new(RwLock::new(BTreeMap::new())),
            ctx,
            memory_size,
        })
    }

    pub fn get_or_create_memory_concolic_var(&self, ctx: &'ctx Context, value: u64) -> MemoryConcolicValue<'ctx> {
        println!("Inside get_or_create_memory_concolic_var function");

        // Try to read the value with read lock first
        {
            let memory_read = self.memory.read().unwrap();
            if let Some(memory_value) = memory_read.get(&value) {
                // If the memory address already exists, return the existing concolic value
                return memory_value.clone();
            }
        }

        // Only acquire write lock if the value does not exist
        let memory_write = self.memory.write().unwrap();
        // Check again in case another thread has created it before we acquired the write lock
        if let Some(memory_value) = memory_write.get(&value) {
            memory_value.clone()
        } else {
            // If the memory address doesn't exist, create a new concolic value and insert it into memory
            let concolic_value = MemoryConcolicValue::new(ctx, value);
            // Do not insert the value into the Memory model because it is just a temporary working value
            // memory_write.insert(value, concolic_value.clone());
            concolic_value
        }
    }

    pub fn read_memory(&self, address: u64, size: usize) -> Result<Vec<u8>, MemoryError> {
        let memory = self.memory.read().unwrap(); // Acquire read lock
        let mut result = Vec::with_capacity(size);
        for offset in 0..size as u64 {
            let current_address = address + offset;
            if let Some(memory_value) = memory.get(&current_address) {
                match memory_value.concrete {
                    ConcreteVar::Int(val) => result.push(val as u8),
                    _ => return Err(MemoryError::IncorrectSliceLength),
                }
            } else {
                // Return a default value for uninitialized memory
                result.push(0);
            }
        }
        Ok(result)
    }

    // Ensure a specific address range is initialized
    pub fn ensure_address_initialized(&self, address: u64, size: usize) {
        // Acquire read lock for initialization
        let mut memory = self.memory.write().unwrap();
        for offset in 0..size {
            let current_address = address + offset as u64;
            memory.entry(current_address).or_insert_with(|| MemoryConcolicValue::default(self.ctx));
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
            memory.insert(current_address, MemoryConcolicValue::new(self.ctx, byte.into()));
        }

        Ok(())
    }

    pub fn load_all_dumps(&self) -> Result<(), MemoryError> {
        // let dumps_dir = {
        //     let info = GLOBAL_TARGET_INFO.lock().unwrap();
        //     info.memory_dumps.clone()
        // };

        // let dumps_dir_path = dumps_dir.join("dumps");

        let dumps_dir_path = PathBuf::from("value/home/kgorna/Documents/zorya/src/state/working_files/additiongo_all-u-need");

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
            memory.insert(address, MemoryConcolicValue::new(self.ctx, byte.into()));
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
    pub fn write_byte(&mut self, offset: u64, value: u8) -> Result<(), MemoryError> {
        self.write_memory(offset, &[value]) // Directly write the single byte
    }

    // Display trait to visualize memory state (not for cloning)
    pub fn display_memory(&self) -> std::fmt::Result {
        let memory = self.memory.read().unwrap();
        println!("Overview of the initialized memory:");
        for (address, memory_value) in memory.iter().take(20) {
            let concrete_value = match &memory_value.concrete {
                ConcreteVar::Int(val) => val.to_string(),
                ConcreteVar::Float(val) => val.to_string(),
                ConcreteVar::Str(val) => val.to_string(),
            };

            let symbolic_value = match &memory_value.symbolic {
                SymbolicVar::Int(bv) => format!("{}", bv),
                SymbolicVar::Float(float) => format!("{}", float),
            };

            println!("  {:#x}: MemoryConcolicValue {{ concrete: {}, symbolic: {} }}",
                     address, concrete_value, symbolic_value);
        }
        Ok(())
    }

    
}