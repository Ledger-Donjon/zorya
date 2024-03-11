/// Maintains the state of CPU registers and possibly other aspects of the CPU's status

use std::collections::BTreeMap;

#[derive(Debug)]
pub struct CpuState {
    pub gpr: BTreeMap<String, u64>, // General-purpose registers
    pub segment_registers: BTreeMap<String, u16>, // Segment registers
    pub control_registers: BTreeMap<String, u64>, // Control registers
    pub pc: u64, // Program Counter
}

impl CpuState {
    pub fn new() -> Self {
        let mut gpr = BTreeMap::new();
        let segment_registers = BTreeMap::new();
        let control_registers = BTreeMap::new();
        let pc = 0;

        // Initialize GPRs
        let registers = ["RAX", "RBX", "RCX", "RDX", "RSP", "RBP", "RSI", "RDI", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", "R32"];
        for (_index, &reg) in registers.iter().enumerate() {
            gpr.insert(reg.to_string(), 0);
        }

        println!("CpuState initialized with GPRs set to 0");

        CpuState {
            gpr,
            segment_registers,
            control_registers,
            pc,
        }
    } 

    // Converts a register number to its name.
    pub fn reg_num_to_name(reg_num: u64) -> Option<&'static str> {
        let register_map: BTreeMap<u64, &str> = [
            (0, "RAX"), (1, "RBX"), (2, "RCX"), (3, "RDX"),
            (4, "RSP"), (5, "RBP"), (6, "RSI"), (7, "RDI"),
            (8, "R8"), (9, "R9"), (10, "R10"), (11, "R11"),
            (12, "R12"), (13, "R13"), (14, "R14"), (15, "R15"),
            
            // required by the pcode
            (32, "R32"),

        ].iter().cloned().collect();
    
        register_map.get(&reg_num).copied()
    }
    
    // Get the value of a general purpose register
    pub fn get_register_value(&self, reg_num: u64) -> Option<u64> {
        match Self::reg_num_to_name(reg_num) {
            Some(reg_name) => {
                let value = self.gpr.get(reg_name);
                println!("Fetching value for register {}: {:?}", reg_name, value);
                value.cloned()
            },
            None => {
                println!("Failed to fetch register value: No register found with ID {}", reg_num);
                None
            },
        }
    }

    // Set the value of a general purpose register
    pub fn set_register_value(&mut self, reg_num: u64, value: u64) {
        if let Some(reg_name) = Self::reg_num_to_name(reg_num) {
            println!("Setting value for register {}: {}", reg_name, value);
            self.gpr.insert(reg_name.to_string(), value);
        } else {
            println!("Failed to set register value: No register found with ID {}", reg_num);
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
