/// Maintains the state of CPU registers and possibly other aspects of the CPU's status

use std::{collections::BTreeMap, sync::Mutex};
use std::fmt;
use anyhow::{Result, anyhow};
use std::sync::Arc;

use z3::{ast::BV, Context};

use crate::concolic::{ConcreteVar, SymbolicVar};

pub type SharedCpuState<'a> = Arc<Mutex<CpuState<'a>>>;

#[derive(Debug, Clone)]
pub struct CpuConcolicValue<'a> {
    pub concrete: ConcreteVar,
    pub symbolic: SymbolicVar<'a>,
}

impl<'ctx> CpuConcolicValue<'ctx> {
    pub fn new(ctx: &'ctx Context, concrete_value: u64) -> Self {
        CpuConcolicValue {
            concrete: ConcreteVar::Int(concrete_value),
            symbolic: SymbolicVar::Int(BV::from_u64(ctx, concrete_value, 64)),
        }
    }

    // Method to retrieve the concrete u64 value
    pub fn get_concrete_value(&self) -> Result<u64, String> {
        match self.concrete {
            ConcreteVar::Int(value) => Ok(value),
            ConcreteVar::Float(value) => Ok(value as u64),  // Simplistic conversion
            ConcreteVar::Str(ref s) => u64::from_str_radix(s.trim_start_matches("0x"), 16)
                .map_err(|_| format!("Failed to parse '{}' as a hexadecimal number", s)),
        }
    }
}


impl<'ctx> fmt::Display for CpuConcolicValue<'ctx> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Concrete: {:?}, Symbolic: {:?}", self.concrete, self.symbolic)
    }
}

#[derive(Debug, Clone)]
pub struct CpuState<'ctx> {
    pub registers: BTreeMap<String, CpuConcolicValue<'ctx>>,
    ctx: &'ctx Context,

}

impl<'ctx> CpuState<'ctx> {
    pub fn new(ctx: &'ctx Context) -> Self {
        let mut cpu_state = CpuState {
            registers: BTreeMap::new(),
            ctx,
        };
        cpu_state.initialize_registers();
        cpu_state
    }

    fn initialize_registers(&mut self) {
        let register_names = [
            "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
            "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
            "rip", "eflags", "cs", "ss", "ds", "es", "fs", "gs",
            "st0", "st1", "st2", "st3", "st4", "st5", "st6", "st7",
            "fctrl", "fstat", "ftag", "fiseg", "fioff", "foseg", "fooff", "fop",
            "fs_base", "gs_base", "k_gs_base", "cr0", "cr2", "cr3", "cr4", "cr8",
            "efer", "mxcsr", "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5",
            "xmm6", "xmm7", "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13",
            "xmm14", "xmm15"
        ];
        for &name in &register_names {
            self.registers.insert(name.to_string(), CpuConcolicValue::new(self.ctx, 0));
        }
    } 

    pub fn set_register_value(&mut self, name: &str, value: u64) -> Result<()> {
        if let Some(reg) = self.registers.get_mut(name) {
            reg.concrete = ConcreteVar::Int(value);
            reg.symbolic = SymbolicVar::Int(BV::from_u64(self.ctx, value, 64));
            println!("{:?} set to concrete {:?}", reg, value);
            Ok(())
        } else {
            println!("Register not found: {}", name);  // Error handling
            Err(anyhow!("Register '{}' does not exist", name))
        }
    }

    pub fn get_register_value(&self, name: &str) -> Option<u64> {
        self.registers.get(name).and_then(|val| val.get_concrete_value().ok())
    }
    
    // Converts a register number to its name. TO BE MODIFIED
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

impl fmt::Display for CpuState<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "CPU State:")?;
        for (reg, value) in &self.registers {
            writeln!(f, "  {}: {}", reg, value)?;
        }
        Ok(())
    }
}

// Newtype wrapper around Arc<Mutex<CpuState>>
pub struct DisplayableCpuState<'ctx>(pub Arc<Mutex<CpuState<'ctx>>>);

impl<'ctx> fmt::Display for DisplayableCpuState<'ctx> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let cpu_state = self.0.lock().unwrap(); // Lock the mutex to access the CPU state
        write!(f, "{}", cpu_state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use z3::Config;

    #[test]
    fn test_get_register_value() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let mut cpu_state = CpuState::new(&ctx);

        // Set initial values
        cpu_state.set_register_value("rax", 123).unwrap();

        assert_eq!(cpu_state.get_register_value("rax"), Some(123));

        // Testing with a non-existent register
        assert_eq!(cpu_state.get_register_value("non_existent"), None);

        // Testing error handling in parsing 
        cpu_state.registers.insert("rbx".to_string(), CpuConcolicValue {
            concrete: ConcreteVar::Str("not_a_number".to_string()),
            symbolic: SymbolicVar::Int(BV::from_u64(&ctx, 0, 64)),  // Arbitrary 
        });

        assert_eq!(cpu_state.get_register_value("rbx"), None);
    }
}

