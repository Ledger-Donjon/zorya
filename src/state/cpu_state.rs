use std::path::Path;
/// Maintains the state of CPU registers and possibly other aspects of the CPU's status

use std::{collections::BTreeMap, sync::Mutex};
use std::{fmt, fs};
use anyhow::{Error, Result};
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
    pub registers: BTreeMap<u64, CpuConcolicValue<'ctx>>,
    pub register_map: BTreeMap<u64, String>,
    ctx: &'ctx Context,
}

impl<'ctx> CpuState<'ctx> {
    pub fn new(ctx: &'ctx Context) -> Self {
        let mut cpu_state = CpuState {
            registers: BTreeMap::new(),
            register_map: BTreeMap::new(),
            ctx,
        };
        cpu_state.initialize_registers().expect("Failed to initialize registers");
        cpu_state
    }

    fn initialize_registers(&mut self) -> Result<(), Error> {
        let path = Path::new("src/concolic/specfiles/x86-64.sla");
        let sla_file_content = fs::read_to_string(path)?;
    
        for line in sla_file_content.lines() {
            if line.contains("space=\"register\"") {
                let name = self.extract_value(line, "name=\"", "\"").to_uppercase();
                let offset = u64::from_str_radix(self.extract_value(line, "offset=\"0x", "\""), 16)?;
    
                let concolic_value = CpuConcolicValue::new(self.ctx, 0);  
                self.registers.insert(offset, concolic_value);
                self.register_map.insert(offset, name.clone());
                println!("Register {} at offset 0x{:x} initialized.", name, offset);
            }
        }
        Ok(())
    }    

    fn extract_value<'a>(&self, from: &'a str, start_delim: &str, end_delim: &str) -> &'a str {
        from.split(start_delim).nth(1).unwrap().split(end_delim).next().unwrap()
    }

    /// Sets the value of a register identified by its offset.
    pub fn set_register_value_by_offset(&mut self, offset: u64, value: u64) -> Result<(), String> {
        if let Some(reg) = self.registers.get_mut(&offset) {
            reg.concrete = ConcreteVar::Int(value);
            reg.symbolic = SymbolicVar::Int(BV::from_u64(self.ctx, value, 64));  // Assuming the size of the register is known to be 64 bits
            if let Some(name) = self.register_map.get(&offset) {
                println!("Register {} set to {:x}", name, value);
            }
            Ok(())
        } else {
            Err(format!("No register found at offset 0x{:x}", offset))
        }
    }

    /// Retrieves the value of a register identified by its offset.
    pub fn get_register_value_by_offset(&self, offset: u64) -> Option<u64> {
        self.registers.get(&offset).and_then(|reg| match reg.concrete {
            ConcreteVar::Int(value) => Some(value),
            _ => None,
        })
    }

    /// Ensures that a register exists at the given offset, initializes it if not.
    pub fn get_or_init_register_by_offset(&mut self, offset: u64) -> &CpuConcolicValue<'ctx> {
        if !self.registers.contains_key(&offset) {
            // We create a new name for the register if it's not found in the register_map
            let reg_name = self.register_map.entry(offset).or_insert_with(|| {
                format!("Unknown_0x{:x}", offset)
            }).clone(); // Clone the String to use in the println!

            // Insert a new CpuConcolicValue at the given offset if it does not already exist
            self.registers.insert(offset, CpuConcolicValue::new(self.ctx, 0));
            println!("Initializing register {}: 0x0", reg_name);
        }

        // return the reference as the entry exists for sure
        self.registers.get(&offset).unwrap()
    }
}

impl fmt::Display for CpuState<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "CPU State:")?;
        for (reg, value) in &self.registers {
            writeln!(f, "  {}: {}", reg, value)?;
        }
        writeln!(f, "Register map:")?;
        println!("{:?}", &self.register_map);
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