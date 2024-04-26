/// Memory model for x86-64 binaries

use regex::Regex;
use z3::{ast::BV, Context};
use std::collections::BTreeMap;
use std::error::Error;
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::{fmt, io};
use std::path::Path;

use crate::target_info::GLOBAL_TARGET_INFO;
use crate::concolic::{ConcreteVar, SymbolicVar};

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
pub struct MemoryConcolicValue<'a> {
    pub concrete: ConcreteVar, 
    pub symbolic: SymbolicVar<'a>,
}

impl<'ctx> MemoryConcolicValue<'ctx> {
    pub fn new(ctx: &'ctx Context, concrete_value: u64) -> Self {
        MemoryConcolicValue {
            concrete: ConcreteVar::Int(concrete_value),
            symbolic: SymbolicVar::Int(BV::from_u64(ctx, concrete_value, 64)),
        }
    }

    // Creates a default memory value zero-initialized.
    pub fn default(ctx: &'ctx Context) -> Self {
        MemoryConcolicValue {
            concrete: ConcreteVar::Int(0),
            symbolic: SymbolicVar::Int(BV::from_u64(ctx, 0, 64)), // 64-bit
        }
    }
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct MemoryX86_64<'ctx> {
    pub memory: BTreeMap<u64, MemoryConcolicValue<'ctx>>,
    ctx: &'ctx Context,
    memory_size: u64,
}

impl<'ctx> MemoryX86_64<'ctx> {
    pub fn new(ctx: &'ctx Context, memory_size: u64) -> Result<Self, MemoryError> {
        let mut memory_model = MemoryX86_64 {
            memory: BTreeMap::new(),
            ctx,
            memory_size,
        };

        // Automatically load all dumps from the working_files_dir specified in GLOBAL_TARGET_INFO
        memory_model.load_all_dumps()?;

        Ok(memory_model)
    }

    fn load_memory_dump(&mut self, file_path: &Path) -> Result<(), MemoryError> {
        let file = File::open(file_path)?;
        let mut reader = BufReader::new(file);
        let mut contents = Vec::new();
        reader.read_to_end(&mut contents)?;

        let start_addr = self.parse_start_address_from_path(file_path)?;

        println!("Loading memory section from {:#x}...", start_addr); // Print the section being loaded

        for (offset, &byte) in contents.iter().enumerate() {
            let address = start_addr + offset as u64;
            self.memory.insert(address, MemoryConcolicValue::new(self.ctx, byte.into()));
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

    fn load_all_dumps(&mut self) -> Result<(), MemoryError> {

        let dumps_dir_path = {
            let info = GLOBAL_TARGET_INFO.lock().unwrap();
            info.memory_dumps.clone()
        };

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

    pub fn ensure_address_initialized(&mut self, address: u64, size: usize) {
        for offset in 0..size {
            let current_address = address + offset as u64;
            self.memory.entry(current_address).or_insert_with(|| MemoryConcolicValue::default(self.ctx));
        }
    }

    // Read a block of memory from a specified address with a given size
    // Handles UninitializedAccess by returning a default value
    pub fn read_memory(&mut self, address: u64, size: usize) -> Result<Vec<u8>, MemoryError> {
        self.ensure_address_initialized(address, size);
        let mut result = Vec::with_capacity(size);
        for offset in 0..size as u64 {
            let current_address = address + offset;
            match self.memory.get(&current_address) {
                Some(memory_value) => {
                    match memory_value.concrete {
                        ConcreteVar::Int(val) => result.push(val as u8),
                        _ => return Err(MemoryError::IncorrectSliceLength),
                    }
                },
                None => {
                    // Handling uninitialized memory: return a default value zero
                    result.push(0);
                },
            }
        }

        Ok(result)
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

    // Writes a slice of bytes to memory starting from a specified address.
    pub fn write_memory(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        // Calculate the end address to prevent writing beyond memory bounds
        let end_address = address.checked_add(bytes.len() as u64).ok_or(MemoryError::WriteOutOfBounds)?;
        
        for (offset, &byte) in bytes.iter().enumerate() {
            let current_address = address + offset as u64;
            if current_address >= end_address {
                return Err(MemoryError::WriteOutOfBounds); // Prevent out-of-bounds write
            }
            // Insert the byte into memory, converting it to a `MemoryConcolicValue`
            self.memory.insert(current_address, MemoryConcolicValue {
                concrete: ConcreteVar::Int(byte.into()),
                symbolic: SymbolicVar::Int(BV::from_u64(self.ctx, byte.into(), 8)), // 8-bit byte size assumed
            });
        }
        
        Ok(())
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
}

impl<'ctx> fmt::Display for MemoryX86_64<'ctx> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Overview of the initialized memory:")?;
        for (address, memory_value) in self.memory.iter().take(20) {
            let concrete_value = match &memory_value.concrete {
                ConcreteVar::Int(val) => val.to_string(),
                ConcreteVar::Float(val) => val.to_string(),
                ConcreteVar::Str(val) => val.to_string(),
            };

            let symbolic_value = match &memory_value.symbolic {
                SymbolicVar::Int(bv) => format!("{}", bv),
                SymbolicVar::Float(float) => format!("{}", float),
            };

            writeln!(
                f,
                "  {:#x}: MemoryConcolicValue {{ concrete: {}, symbolic: {} }}",
                address, concrete_value, symbolic_value
            )?;
        }
        writeln!(f, "  etc...")?;

        Ok(())
    }
}