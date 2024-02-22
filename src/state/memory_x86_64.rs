/// Memory model for x86-64 binaries

use z3::{ast::BV, Context};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use parser::parser::Inst;

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

#[derive(Debug)]
pub struct MemoryValue<'a> {
    pub concrete: ConcreteVar, 
    pub symbolic: SymbolicVar<'a>,
}

#[derive(Debug)]
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
    const ENTRY_POINT_ADDRESS: u64 = 0x45f5c0;

    // Read a block of memory from a specified address with a given size.
    pub fn read_memory(&mut self, address: u64, size: usize) -> Result<Vec<u8>, MemoryError> {
        let mut result = Vec::with_capacity(size);
        for offset in 0..size as u64 {
            let current_address = address + offset;
            match self.memory.get(&current_address) {
                Some(memory_value) => {
                    // Assuming concrete is the value you want to read, and it stores an integer representation of the byte.
                    match memory_value.concrete {
                        ConcreteVar::Int(val) => {
                            // Ensure you're extracting the byte value correctly from your ConcreteVar::Int variant.
                            // This example assumes ConcreteVar::Int stores the byte as is, which might not be your implementation.
                            result.push(val as u8); // Cast to u8, assuming val contains the byte value directly.
                        },
                        // Handle other variants of ConcreteVar if necessary
                        _ => return Err(MemoryError::IncorrectSliceLength), // or an appropriate error
                    }
                },
                None => return Err(MemoryError::UninitializedAccess(current_address)),
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

    pub fn check_nil_deref(&mut self, address: u64, current_address: u64, instruction: &Inst) -> Result<(), String> {
    	// Special case for entry point where accessing 0x0 might be expected
    	if current_address == Self::ENTRY_POINT_ADDRESS && address == 0x0 {
        	println!("Special case at entry point, accessing 0x0 is not considered a nil dereference.");
        	return Ok(());
    	}

    	// General case for nil dereference check: Ensure the accessed address is not 0x0
    	if address == 0x0 {
        	// If the address being accessed is 0x0, this is considered a nil dereference.
        	return Err(format!("Nil dereference detected: Attempted to access address 0x0 at address 0x{:x} with instruction {:?}", current_address, instruction));
    	}

    	// If the address being accessed is not 0x0, no error is reported.
    	Ok(())
     }


}
