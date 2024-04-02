/// Maintains the state of CPU registers and possibly other aspects of the CPU's status

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::Mutex;

lazy_static! {
    // Assuming the use of lazy_static to hold a mutable state across the application
    pub static ref GLOBAL_CPU_STATE: Mutex<CpuState> = Mutex::new(CpuState::default());
}

#[derive(Debug, Clone, Default)]
pub struct CpuState {
    registers: HashMap<String, String>,
}

impl CpuState {
    pub fn new() -> Self {
        GLOBAL_CPU_STATE.lock().unwrap().clone()
    }

    pub fn default() -> Self {
        let mut registers = HashMap::new();
        // Initialize default values for each register
        for reg in ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip", "eflags", "cs", "ss", "ds", "es", "fs", "gs", "fctrl", "fstat", "ftag", "fiseg", "fioff", "foseg", "fooff", "fop", "mxcsr", "r16", "r32", "r48", "r56", "r512", "r518"].iter() {
            registers.insert(reg.to_string(), "0x0".to_owned());
        }

        Self { registers }
    }

    pub fn set_register_value_by_name(&mut self, reg_name: &str, value: String) {
        self.registers.insert(reg_name.to_owned(), value);
    }

    pub fn get_register_value_by_name(&self, reg_name: &str) -> Option<&String> {
        self.registers.get(reg_name)
    }
    
    // Converts a register number to its name.
    pub fn reg_num_to_name(reg_num: u64) -> Option<String> {
        let mut register_map = BTreeMap::new();
    
        // General-purpose registers (GPRs)
        let gprs = vec![
            "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
            "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
        ];
        for (i, &reg) in gprs.iter().enumerate() {
            register_map.insert(i as u64, reg.to_string());
        }
    
        // Specific additional registers
        let additional_registers = vec![
            (16, "r16"), (32, "r32"), (48, "r48"), (56, "r56"), 
            (512, "r512"), (518, "r518")
        ];
        for &(num, name) in &additional_registers {
            register_map.insert(num, name.to_string());
        }
    
        // System and control registers commonly used in x86-64 architecture
        let system_registers = vec![
            (64, "rip"), (65, "eflags"), 
            (66, "cs"), (67, "ss"), (68, "ds"), (69, "es"), (70, "fs"), (71, "gs")
        ];
        for &(num, name) in &system_registers {
            register_map.insert(num, name.to_string());
        }
    
        // Floating-point unit (FPU) and other state registers
        let fpu_registers = vec![
            (72, "fctrl"), (73, "fstat"), (74, "ftag"), 
            (75, "fiseg"), (76, "fioff"), (77, "foseg"), (78, "fooff"), (79, "fop"), 
            (80, "mxcsr")
        ];
        for &(num, name) in &fpu_registers {
            register_map.insert(num, name.to_string());
        }
    
        // Retrieve the register name by its number
        register_map.get(&reg_num).cloned()
    }
    

    
}

impl fmt::Display for CpuState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "CPU State:")?;

        // Collect into a vector so we can sort it
        let mut registers: Vec<(&String, &String)> = self.registers.iter().collect();

        // Sort the vector by register names (alphabetically)
        registers.sort_by(|a, b| a.0.cmp(b.0));

        // Iterate over the sorted registers and print each
        for (reg_name, reg_value) in &registers {
            writeln!(f, "  {}: {}", reg_name, reg_value)?;
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registers_are_properly_initialized() {
        // Initialize GLOBAL_CPU_STATE with some test data
        let mut cpu_state = CpuState::default();
        cpu_state.set_register_value_by_name("rax", "0x123".to_owned());
        cpu_state.set_register_value_by_name("rbx", "0x456".to_owned());
        cpu_state.set_register_value_by_name("rip", "0x789".to_owned());
        // Lock the GLOBAL_CPU_STATE and replace it with our test state
        let mut global_state = GLOBAL_CPU_STATE.lock().unwrap();
        *global_state = cpu_state;

        // Verify that the CPU state has been initialized with the expected values
        assert_eq!(global_state.get_register_value_by_name("rax"), Some(&"0x123".to_owned()));
        assert_eq!(global_state.get_register_value_by_name("rbx"), Some(&"0x456".to_owned()));
        assert_eq!(global_state.get_register_value_by_name("rip"), Some(&"0x789".to_owned()));
    }
}
