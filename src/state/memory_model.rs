use std::collections::HashMap;

pub type Address = u64;  // Modify ?
pub type Value = i64;    // Modify ?

#[derive(Debug)]
pub struct MemoryModel {
    memory: HashMap<Address, Value>,
}

impl MemoryModel {
    pub fn new() -> Self {
        MemoryModel {
            memory: HashMap::new(),
        }
    }

    pub fn read_memory(&self, address: Address) -> Option<Value> {
        self.memory.get(&address).copied()
    }

    pub fn write_memory(&mut self, address: Address, value: Value) {
        self.memory.insert(address, value);
    }
}
