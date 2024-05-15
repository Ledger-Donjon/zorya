/// Maintains the state of CPU registers and possibly other aspects of the CPU's status

use std::{collections::BTreeMap, sync::Mutex};
use std::fmt;
use anyhow::Result;
use std::sync::Arc;

use z3::{ast::BV, Context};

use crate::concolic::{ConcolicEnum, ConcolicVar, ConcreteVar, SymbolicVar};

use super::memory_x86_64::MemoryConcolicValue;

pub type SharedCpuState<'a> = Arc<Mutex<CpuState<'a>>>;

#[derive(Debug, Clone)]
pub struct CpuConcolicValue<'ctx> {
    pub concrete: ConcreteVar,
    pub symbolic: SymbolicVar<'ctx>,
    pub ctx: &'ctx Context,  // Include context directly in the struct
}

impl<'ctx> CpuConcolicValue<'ctx> {
    pub fn new(ctx: &'ctx Context, concrete_value: u64) -> Self {
        CpuConcolicValue {
            concrete: ConcreteVar::Int(concrete_value),
            symbolic: SymbolicVar::Int(BV::from_u64(ctx, concrete_value, 64)),
            ctx,
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

    // Add operation on two CPU concolic variables 
    pub fn add(self, other: Self) -> Result<Self, &'static str> {
        let new_concrete = self.concrete.add(&other.concrete.clone());
        let new_symbolic = self.symbolic.add(&other.symbolic)?;
        Ok(CpuConcolicValue {
            concrete: new_concrete,
            symbolic: new_symbolic,
            ctx: self.ctx,
        })
    }

    // Add a CPU concolic value to a const var
    pub fn add_with_var(self, var: ConcolicVar<'ctx>) -> Result<ConcolicEnum<'ctx>, &'static str> {
        let new_concrete = self.concrete.add(&var.concrete);
        let new_symbolic = self.symbolic.add(&var.symbolic)?;
        Ok(ConcolicEnum::CpuConcolicValue(CpuConcolicValue {
            concrete: new_concrete,
            symbolic: new_symbolic,
            ctx: self.ctx,
        }))
    }

    // Add a memory concolic value to a const var
    pub fn add_with_other(self, var: MemoryConcolicValue<'ctx>) -> Result<ConcolicEnum<'ctx>, &'static str> {
        let new_concrete = self.concrete.add(&var.concrete);
        let new_symbolic = self.symbolic.add(&var.symbolic)?;
        Ok(ConcolicEnum::CpuConcolicValue(CpuConcolicValue {
            concrete: new_concrete,
            symbolic: new_symbolic,
            ctx: self.ctx,
        }))
    }

    pub fn get_size(&self) -> u32 {
        match &self.concrete {
            ConcreteVar::Int(_) => 64,  // Assuming all integers are u64
            ConcreteVar::Float(_) => 64, // Assuming double precision floats
            ConcreteVar::Str(s) => (s.len() * 8) as u32,  // Example, size in bits
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
    pub register_map: BTreeMap<u64, String>, // Contains the offset of a register and its name (ie <"0x10", "RDX">)
    ctx: &'ctx Context,

}

impl<'ctx> CpuState<'ctx> {
    pub fn new(ctx: &'ctx Context) -> Self {
        let mut cpu_state = CpuState {
            registers: BTreeMap::new(),
            register_map: BTreeMap::new(),
            ctx,
        };
        cpu_state.initialize_registers();
        cpu_state
    }

    fn initialize_registers(&mut self) {
        // General-purpose registers (GPRs)
        let gprs = vec![
            "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
            "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
        ];
        for (i, &reg) in gprs.iter().enumerate() {
            self.register_map.insert(i as u64, reg.to_string());
            self.registers.insert(reg.to_string(), CpuConcolicValue::new(self.ctx, 0));
        }

        // System and control registers commonly used in x86-64 architecture
        let system_registers = vec![
            (16, "r16"), (64, "rip"), (65, "eflags"), 
            (66, "cs"), (67, "ss"), (68, "ds"), (69, "es"), (70, "fs"), (71, "gs")
        ];
        for &(num, name) in &system_registers {
            self.register_map.insert(num, name.to_string());
            self.registers.insert(name.to_string(), CpuConcolicValue::new(self.ctx, 0x5));
        }

        // Floating-point unit (FPU) and other state registers
        let fpu_registers = vec![
            (72, "fctrl"), (73, "fstat"), (74, "ftag"), 
            (75, "fiseg"), (76, "fioff"), (77, "foseg"), (78, "fooff"), (79, "fop"), 
            (80, "mxcsr")
        ];
        for &(num, name) in &fpu_registers {
            self.register_map.insert(num, name.to_string());
            self.registers.insert(name.to_string(), CpuConcolicValue::new(self.ctx, 0));
        }
    }

    pub fn set_register_value(&mut self, name: &str, value: u64) -> Result<()> {
        let reg = self.registers.entry(name.to_string()).or_insert_with(|| CpuConcolicValue::new(self.ctx, 0));
        reg.concrete = ConcreteVar::Int(value);
        reg.symbolic = SymbolicVar::Int(BV::from_u64(self.ctx, value, 64));
        println!("{} set to {}", name, value);
        Ok(())
    }

    pub fn get_register_value(&self, name: &str) -> Option<u64> {
        self.registers.get(name).and_then(|val| match val.concrete {
            ConcreteVar::Int(value) => Some(value),
            _ => None
        })
    }
    
    pub fn get_or_init_register(&mut self, reg_num: u64) -> &CpuConcolicValue<'ctx> {
        let reg_name = self.reg_num_to_name(reg_num); // Ensure to get or create the name
        self.registers.entry(reg_name.clone()).or_insert_with(|| {
            println!("Initializing register {}: 0x0", reg_name);
            CpuConcolicValue::new(self.ctx, 0)
        })
    }

    /// Converts a register number to its name. It also ensures that if a register does not exist,
    /// it creates one, initializes it, and logs the process.
    pub fn reg_num_to_name(&mut self, reg_num: u64) -> String {
        // Try to get the register name from the map; if not found, create a new register.
        self.register_map.entry(reg_num)
            .or_insert_with(|| {
                let new_name = format!("{}", reg_num);
                // Create and initialize a new register if it does not exist
                self.registers.entry(new_name.clone()).or_insert_with(|| {
                    println!("No such existing register. Creating and initializing new register '{}' to 0x0", new_name);
                    CpuConcolicValue::new(self.ctx, 0)
                });
                new_name
            }).clone()
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
            ctx: &ctx,
        });

        assert_eq!(cpu_state.get_register_value("rbx"), None);
    }
}

