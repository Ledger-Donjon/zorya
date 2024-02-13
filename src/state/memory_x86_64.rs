// Memory model for x86-64 binaries

use z3::{ast::BV, Context};
use std::collections::HashMap;
use std::error::Error;
use std::fmt;

#[derive(Debug, PartialEq, Eq)]
pub enum MemoryError {
    OutOfBounds,
    IncorrectSliceLength,
    WriteOutOfBounds,
    SymbolicAccessError,
}

impl Error for MemoryError {}

impl fmt::Display for MemoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MemoryError::OutOfBounds => write!(f, "Memory access out of bounds"),
            MemoryError::IncorrectSliceLength => write!(f, "Incorrect slice length"),
            MemoryError::WriteOutOfBounds => write!(f, "Memory write out of bounds"),
            MemoryError::SymbolicAccessError => write!(f, "Symbolic memory access error"),
        }
    }
}

#[derive(Debug)]
pub enum MemoryValue<'ctx> {
    Concrete(Vec<u8>),
    Symbolic(BV<'ctx>),
}

#[derive(Debug)]
pub struct MemoryX86_64<'ctx> {
    pub memory: HashMap<u64, MemoryValue<'ctx>>,
    ctx: &'ctx Context,
}

impl<'ctx> MemoryX86_64<'ctx> {
    pub fn new(ctx: &'ctx Context) -> Self {
        MemoryX86_64 {
            memory: HashMap::new(),
            ctx,
        }
    }

    fn ensure_memory_initialized(&mut self, address: u64, size: usize) {
        self.memory.entry(address).or_insert_with(|| MemoryValue::Concrete(vec![0; size]));
    }

    pub fn read_memory(&mut self, address: u64, size: usize) -> Result<Vec<u8>, MemoryError> {
        self.ensure_memory_initialized(address, size);
        match self.memory.get(&address) {
            Some(MemoryValue::Concrete(data)) => {
                data.get(..size).map(|slice| slice.to_vec()).ok_or(MemoryError::OutOfBounds)
            },
            Some(MemoryValue::Symbolic(_symbolic_var)) => {
                let read_var_name = format!("read_{}_{}", address, size);
                // Dereference the String to &str before passing
                let read_var = BV::new_const(self.ctx, &read_var_name[..], size as u32 * 8);
                Err(MemoryError::SymbolicAccessError)
            },
            None => Err(MemoryError::OutOfBounds),
        }
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

    // General function to write a slice of memory, initializing memory if it's not already initialized
    pub fn write_memory(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        self.ensure_memory_initialized(address, bytes.len());
        match self.memory.get_mut(&address) {
            Some(MemoryValue::Concrete(segment)) => {
                if segment.len() < bytes.len() {
                    segment.resize(bytes.len(), 0);
                }
                segment[..bytes.len()].copy_from_slice(bytes);
                Ok(())
            },
            Some(MemoryValue::Symbolic(_symbolic_var)) => {
                let new_state_var_name = format!("mem_{}_{}_new_state", address, bytes.len());
                // Dereference the String to &str before passing
                let new_state_var = BV::new_const(self.ctx, &new_state_var_name[..], bytes.len() as u32 * 8);
                self.memory.insert(address, MemoryValue::Symbolic(new_state_var));
                Ok(())
            },
            None => Err(MemoryError::OutOfBounds),
        }
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
