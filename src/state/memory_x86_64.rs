/// Memory model for x86-64 binaries

use regex::Regex;
use z3::{ast::BV, Context};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};

use crate::target_info::GLOBAL_TARGET_INFO;
use crate::concolic::{concrete_var, ConcreteVar, SymbolicVar};

#[derive(Debug, PartialEq, Eq)]
pub enum MemoryError {
    OutOfBounds(u64, usize),
    IncorrectSliceLength,
    WriteOutOfBounds,
    SymbolicAccessError,
    UninitializedAccess(u64),
    NullDereference(u64),
}

impl Error for MemoryError {}

impl fmt::Display for MemoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MemoryError::OutOfBounds(addr, size) => write!(f, "Memory access out of bounds with address {:#x} and size : {:#x}", addr, size),
            MemoryError::IncorrectSliceLength => write!(f, "Incorrect slice length"),
            MemoryError::WriteOutOfBounds => write!(f, "Memory write out of bounds"),
            MemoryError::SymbolicAccessError => write!(f, "Symbolic memory access error"),
            MemoryError::UninitializedAccess(addr) => write!(f, "Attempted to access uninitialized memory at address {:#x}", addr),
	    MemoryError::NullDereference(addr) => write! (f, "Potential null dereference detected at {:#x}", addr),
        }
    }
}

impl From<concrete_var::VarError> for MemoryError {
    fn from(err: concrete_var::VarError) -> MemoryError {
        match err {
            concrete_var::VarError::ConversionError => MemoryError::SymbolicAccessError,
        }
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
    pub fn new(ctx: &'ctx Context, memory_size: u64) -> Result<Self, Box<dyn Error>> {
        let mut memory_model = MemoryX86_64 {
            memory: BTreeMap::new(),
            ctx,
            memory_size,
        };

        // Automatically load all dumps from the working_files_dir specified in GLOBAL_TARGET_INFO
        memory_model.load_all_dumps()?;

        Ok(memory_model)
    }

    // Function to load a memory dump from a .bin file
    pub fn load_memory_dump(&mut self, file_path: &str, start_addr: u64) -> Result<(), Box<dyn std::error::Error>> {
        let contents = std::fs::read(file_path)?;
        
        for (offset, &byte) in contents.iter().enumerate() {
            let address = start_addr + offset as u64;
            self.write_byte(address, byte)?;
        }

        Ok(())
    }

    /// Function to load all memory dumps at initialization or manually
    pub fn load_all_dumps(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!(">>>>> Loading all dumps to the memory... Be patient :)");

        // Get the path to the working_files dir from global target info
        let working_files_dir = {
            let info = GLOBAL_TARGET_INFO.lock().unwrap();
            info.working_files_dir.clone()
        };

        // Construct the directory path where dumps are stored
        let binary_name = {
            let info = GLOBAL_TARGET_INFO.lock().unwrap();
            Path::new(&info.binary_path).file_stem().unwrap().to_str().unwrap().to_string()
        };

        // TO BE ADAPTED
        // let dumps_dir_path = working_files_dir.join(format!("{}_all-u-need", binary_name));
        let dumps_dir_path = PathBuf::from("/home/kgorna/Documents/zorya/external/bin/dumps"); 

        // Read the directory containing dump files
        let entries = std::fs::read_dir(dumps_dir_path.clone())?;

        // Regex to extract start and end addresses from dump filenames
        let dump_file_regex = Regex::new(r"^(0x[a-fA-F0-9]+)[-_](0x[a-fA-F0-9]+)(_zeros)?\.bin$")?;

        let mut loaded_files = false;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() && path.extension().map_or(false, |e| e == "bin") {
                let file_name = path.file_name().unwrap().to_str().unwrap();

                // Use regex to capture start and end addresses
                if let Some(caps) = dump_file_regex.captures(file_name) {
                    let start_addr = u64::from_str_radix(&caps[1][2..], 16)?; // Skip '0x'
                    let end_addr = u64::from_str_radix(&caps[2][2..], 16)?; // Skip '0x'
                    self.load_memory_dump(path.to_str().unwrap(), start_addr)?;
                    println!("Loaded memory dump from {:#x} to {:#x} from file: {}", start_addr, end_addr, file_name);
                    loaded_files = true;
                }
            }
        }

        if !loaded_files {
            println!("No valid dump files found in the directory: {:?}", dumps_dir_path);
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::NotFound, "No valid dump files detected.")));
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