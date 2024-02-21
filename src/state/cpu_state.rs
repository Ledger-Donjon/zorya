/// Maintains the state of CPU registers and possibly other aspects of the CPU's status

use std::collections::BTreeMap;

#[derive(Debug)]
pub struct CpuState {
    pub gpr: BTreeMap<String, u64>, // General-purpose registers
    pub segment_registers: BTreeMap<String, u16>, // Segment registers
    pub control_registers: BTreeMap<String, u64>, // Control registers
}

impl CpuState {
    pub fn new() -> Self {
        let mut gpr = BTreeMap::new();
        let segment_registers = BTreeMap::new();
        let control_registers = BTreeMap::new();

        // Initialize GPRs to 0
        let registers = ["RAX", "RBX", "RCX", "RDX", "RSP", "RBP", "RSI", "RDI", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"];
        for (_index, &reg) in registers.iter().enumerate() {
            gpr.insert(reg.to_string(), 0);
        }

        CpuState {
            gpr,
            segment_registers,
            control_registers,
        }
    }

    // Converts a register number to its name.
    fn reg_num_to_name(reg_num: u64) -> Option<&'static str> {
        let registers = ["RAX", "RBX", "RCX", "RDX", "RSP", "RBP", "RSI", "RDI", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"];
        registers.get(reg_num as usize).copied()
    }
    // Get the value of a general purpose register
    pub fn get_register_value(&self, reg_num: u64) -> Option<u64> {
        match Self::reg_num_to_name(reg_num) {
            Some(reg_name) => self.gpr.get(reg_name).cloned(),
            None => None,
        }
    }

    // Set the value of a general purpose register
    pub fn set_register_value(&mut self, reg_num: u64, value: u64) {
        if let Some(reg_name) = Self::reg_num_to_name(reg_num) {
            self.gpr.insert(reg_name.to_string(), value);
        }
    }

    // Get the value of a segment register
    pub fn get_segment_register_value(&self, reg: &str) -> Option<u16> {
        self.segment_registers.get(reg).cloned()
    }

    // Set the value of a segment register
    pub fn set_segment_register_value(&mut self, reg: &str, value: u16) {
        self.segment_registers.insert(reg.to_string(), value);
    }

    // Get the value of a control register
    pub fn get_control_register_value(&self, reg: &str) -> Option<u64> {
        self.control_registers.get(reg).cloned()
    }

    // Set the value of a control register
    pub fn set_control_register_value(&mut self, reg: &str, value: u64) {
        self.control_registers.insert(reg.to_string(), value);
    }
}
