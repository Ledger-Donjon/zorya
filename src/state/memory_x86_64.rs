/// Memory model for x86-64 binaries

use z3::{ast::BV, Context};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

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
pub struct MemoryValue<'a> {
    pub concrete: ConcreteVar, 
    pub symbolic: SymbolicVar<'a>,
}

impl<'ctx> MemoryValue<'ctx> {
    // Creates a default memory value zero-initialized.
    pub fn default(ctx: &'ctx Context) -> Self {
        MemoryValue {
            concrete: ConcreteVar::Int(0),
            symbolic: SymbolicVar::Int(BV::from_u64(ctx, 0, 64)), // 64-bit
        }
    }
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct MemoryX86_64<'ctx> {
    pub memory: BTreeMap<u64, MemoryValue<'ctx>>,
    ctx: &'ctx Context,
    memory_size: u64,
}

impl<'ctx> MemoryX86_64<'ctx> {
    pub fn new(ctx: &'ctx Context, memory_size: u64) -> Self {
        MemoryX86_64 {
            memory: BTreeMap::new(),
            ctx,
            memory_size,
        }
    }

    pub fn ensure_address_initialized(&mut self, address: u64, size: usize) {
        for offset in 0..size {
            let current_address = address + offset as u64;
            self.memory.entry(current_address).or_insert_with(|| MemoryValue::default(self.ctx));
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

    // Writes a slice of bytes to memory starting from a specified address.
    pub fn write_memory(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        // Calculate the end address to prevent writing beyond memory bounds
        let end_address = address.checked_add(bytes.len() as u64).ok_or(MemoryError::WriteOutOfBounds)?;
        
        for (offset, &byte) in bytes.iter().enumerate() {
            let current_address = address + offset as u64;
            if current_address >= end_address {
                return Err(MemoryError::WriteOutOfBounds); // Prevent out-of-bounds write
            }
            // Insert the byte into memory, converting it to a `MemoryValue`
            self.memory.insert(current_address, MemoryValue {
                concrete: ConcreteVar::Int(byte.into()),
                symbolic: SymbolicVar::Int(BV::from_u64(self.ctx, byte.into(), 8)), // 8-bit byte size assumed
            });
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

    /// Reads a null-terminated string starting from the specified memory address.
    ///
    /// This method dynamically determines the length of the string by reading each byte until
    /// a null terminator (0x00) is encountered. It constructs a `String` from the bytes read
    /// from memory, assuming they are valid UTF-8 encoded characters. This approach is commonly
    /// used for C-style strings.
    ///
    /// # Arguments
    ///
    /// * `address` - The starting address in memory where the string is located.
    ///
    /// # Returns
    ///
    /// A `Result` which is either:
    /// - `Ok(String)` containing the read string if successful.
    /// - `Err(MemoryError)` if an error occurs during the read operation, including if the
    ///   memory address is out of bounds or the data at the address does not represent a valid
    ///   UTF-8 string.
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
}
