// Memory model for x86-64 binaries

use std::convert::TryInto;

const MEMORY_SIZE: usize = 1024 * 1024; // 1MB of memory for simulation purposes.

#[derive(Debug)]
pub struct MemoryX86_64 {
    memory: Vec<u8>, // This simulates the RAM.
}

impl MemoryX86_64 {
    pub fn new() -> Self {
        MemoryX86_64 {
            memory: vec![0; MEMORY_SIZE],
        }
    }

    pub fn read_quad(&self, offset: u64) -> Result<u64, &'static str> {
        let base = offset as usize;
        self.memory.get(base..base + 8)
            .ok_or("Memory read out of bounds")
            .map(|bytes| u64::from_le_bytes(bytes.try_into().expect("slice with incorrect length")))
    }

    pub fn read_word(&self, offset: u64) -> Result<u32, &'static str> {
        let base = offset as usize;
        self.memory.get(base..base + 4)
            .ok_or("Memory read out of bounds")
            .map(|bytes| u32::from_le_bytes(bytes.try_into().expect("slice with incorrect length")))
    }

    pub fn read_half(&self, offset: u64) -> Result<u16, &'static str> {
        let base = offset as usize;
        self.memory.get(base..base + 2)
            .ok_or("Memory read out of bounds")
            .map(|bytes| u16::from_le_bytes(bytes.try_into().expect("slice with incorrect length")))
    }

    pub fn read_byte(&self, offset: u64) -> Result<u8, &'static str> {
        self.memory.get(offset as usize)
            .copied()
            .ok_or("Memory read out of bounds")
    }

    pub fn write_quad(&mut self, offset: u64, value: u64) -> Result<(), &'static str> {
        let base = offset as usize;
        let bytes = value.to_le_bytes();
        self.memory.get_mut(base..base + 8)
            .ok_or("Memory write out of bounds")
            .map(|slice| slice.copy_from_slice(&bytes))
    }

    pub fn write_word(&mut self, offset: u64, value: u32) -> Result<(), &'static str> {
        let base = offset as usize;
        let bytes = value.to_le_bytes();
        self.memory.get_mut(base..base + 4)
            .ok_or("Memory write out of bounds")
            .map(|slice| slice.copy_from_slice(&bytes))
    }

    pub fn write_half(&mut self, offset: u64, value: u16) -> Result<(), &'static str> {
        let base = offset as usize;
        let bytes = value.to_le_bytes();
        self.memory.get_mut(base..base + 2)
            .ok_or("Memory write out of bounds")
            .map(|slice| slice.copy_from_slice(&bytes))
    }

    pub fn write_byte(&mut self, offset: u64, value: u8) -> Result<(), &'static str> {
        let base = offset as usize;
        self.memory.get_mut(base)
            .ok_or("Memory write out of bounds")
            .map(|byte| *byte = value)
    }
}
