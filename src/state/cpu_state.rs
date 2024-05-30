use std::path::Path;
/// Maintains the state of CPU registers and possibly other aspects of the CPU's status

use std::{collections::BTreeMap, sync::Mutex};
use std::{fmt, fs};
use anyhow::{Error, Result};
use z3::ast::Bool;
use std::sync::Arc;
use anyhow::anyhow;

use z3::{ast::BV, Context};

use crate::concolic::{ConcolicEnum, ConcolicVar, ConcreteVar, SymbolicVar};

use super::memory_x86_64::MemoryConcolicValue;

pub type SharedCpuState<'a> = Arc<Mutex<CpuState<'a>>>;

#[derive(Debug, Clone)]
pub struct CpuConcolicValue<'ctx> {
    pub concrete: ConcreteVar,
    pub symbolic: SymbolicVar<'ctx>,
    pub ctx: &'ctx Context, 
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
    pub fn add_with_var(self, var: ConcolicVar<'ctx>) -> Result<CpuConcolicValue<'ctx>, &'static str> {
        let new_concrete = self.concrete.add(&var.concrete);
        let new_symbolic = self.symbolic.add(&var.symbolic)?;
        Ok(CpuConcolicValue {
            concrete: new_concrete,
            symbolic: new_symbolic,
            ctx: self.ctx,
        })
    }

    // Add a memory concolic value to a const var
    pub fn add_with_other(self, var: MemoryConcolicValue<'ctx>) -> Result<CpuConcolicValue<'ctx>, &'static str> {
        let new_concrete = self.concrete.add(&var.concrete);
        let new_symbolic = self.symbolic.add(&var.symbolic)?;
        Ok(CpuConcolicValue {
            concrete: new_concrete,
            symbolic: new_symbolic,
            ctx: self.ctx,
        })
    }

    // Function to perform a carrying addition on two CpuConcolicValues
    pub fn carrying_add(&self, other: &CpuConcolicValue<'ctx>, carry: bool) -> (CpuConcolicValue<'ctx>, bool) {
        let (result, overflow) = self.concrete.carrying_add(&other.concrete, carry);
        let symbolic_result = self.symbolic.add(&other.symbolic);  
        let result_var = CpuConcolicValue {
            concrete: result,
            symbolic: symbolic_result.unwrap(),
            ctx: self.ctx,
        };
        (result_var, overflow)
    }

    // Carrying add operation between a ConcolicVar and a MemoryConcolicValue
    pub fn carrying_add_with_mem(&self, other: &MemoryConcolicValue<'ctx>, carry: bool) -> (CpuConcolicValue<'ctx>, bool) {
        let (result, overflow) = self.concrete.carrying_add(&other.concrete, carry);
        let symbolic_result = self.symbolic.add(&other.symbolic);  
        let result_var = CpuConcolicValue {
            concrete: result,
            symbolic: symbolic_result.unwrap(),
            ctx: self.ctx,
        };
        (result_var, overflow)
    }

    // Method to perform signed addition and detect overflow
    pub fn signed_add(&self, other: &Self) -> Result<(Self, bool), &'static str> {
        let (result, overflow) = self.concrete.to_i64()?.overflowing_add(other.concrete.to_i64()?);
        let new_concrete = ConcreteVar::Int(result as u64);
        let new_symbolic = self.symbolic.add(&other.symbolic)?;
        Ok((CpuConcolicValue {
            concrete: new_concrete,
            symbolic: new_symbolic,
            ctx: self.ctx,
        }, overflow))
    }

    // Method to perform signed addition with MemoryConcolicValue and detect overflow
    pub fn signed_add_with_mem(&self, other: &MemoryConcolicValue<'ctx>) -> Result<(MemoryConcolicValue<'ctx>, bool), &'static str> {
        let (result, overflow) = self.concrete.to_i64()?.overflowing_add(other.concrete.to_i64()?);
        let new_concrete = ConcreteVar::Int(result as u64);
        let new_symbolic = self.symbolic.add(&other.symbolic)?;
        Ok((MemoryConcolicValue {
            concrete: new_concrete,
            symbolic: new_symbolic,
            ctx: self.ctx,
        }, overflow))
    }

    pub fn sub(self, other: CpuConcolicValue<'ctx>, ctx: &'ctx Context) -> Result<CpuConcolicValue<'ctx>, &'static str> {
        let (new_concrete, overflow) = self.concrete.to_u64().overflowing_sub(other.concrete.to_u64());
        if overflow {
            Err("Overflow or underflow occurred during subtraction")
        } else {
            let new_symbolic = self.symbolic.sub(&other.symbolic, ctx)?;
            Ok(CpuConcolicValue {
                concrete: ConcreteVar::Int(new_concrete),
                symbolic: new_symbolic,
                ctx,
            })
        }
    }

    pub fn sub_with_var(self, other: ConcolicVar<'ctx>, ctx: &'ctx Context) -> Result<CpuConcolicValue<'ctx>, &'static str> {
        let (new_concrete, overflow) = self.concrete.to_u64().overflowing_sub(other.concrete.to_u64());
        if overflow {
            Err("Overflow or underflow occurred during subtraction")
        } else {
            let new_symbolic = self.symbolic.sub(&other.symbolic, ctx)?;
            Ok(CpuConcolicValue {
                concrete: ConcreteVar::Int(new_concrete),
                symbolic: new_symbolic,
                ctx,
            })
        }
    }

    pub fn sub_with_other(self, other: MemoryConcolicValue<'ctx>, ctx: &'ctx Context) -> Result<CpuConcolicValue<'ctx>, &'static str> {
        let (new_concrete, overflow) = self.concrete.to_u64().overflowing_sub(other.concrete.to_u64());
        if overflow {
            Err("Overflow or underflow occurred during subtraction")
        } else {
            let new_symbolic = self.symbolic.sub(&other.symbolic, ctx)?;
            Ok(CpuConcolicValue {
                concrete: ConcreteVar::Int(new_concrete),
                symbolic: new_symbolic,
                ctx,
            })
        }
    }

    pub fn signed_sub(self, other: Self, ctx: &'ctx Context) -> Result<Self, &'static str> {
        let (new_concrete, overflow) = self.concrete.signed_sub_overflow(&other.concrete);
        if overflow {
            return Err("Signed subtraction overflow detected");
        }
        let new_symbolic = self.symbolic.sub(&other.symbolic, ctx)?;
        Ok(CpuConcolicValue {
            concrete: new_concrete,
            symbolic: new_symbolic,
            ctx: self.ctx,
        })
    }
    
    // Handle signed subtraction with another ConcolicVar
    pub fn signed_sub_with_var(self, var: ConcolicVar<'ctx>, ctx: &'ctx Context) -> Result<CpuConcolicValue<'ctx>, &'static str> {
        let (new_concrete, overflow) = self.concrete.signed_sub_overflow(&var.concrete);
        if overflow {
            return Err("Signed subtraction overflow detected");
        }
        let new_symbolic = self.symbolic.sub(&var.symbolic, ctx)?;
        Ok(CpuConcolicValue {
            concrete: new_concrete,
            symbolic: new_symbolic,
            ctx: self.ctx,
        })
    }
    
    pub fn handle_overflow_condition(&self, overflow: Bool) -> bool {
        overflow.as_bool().unwrap_or(false)
    }

    // Logical AND operation between CpuConcolicValue and ConcolicVar
    pub fn and_with_var(self, var: ConcolicVar<'ctx>) -> Result<CpuConcolicValue<'ctx>, &'static str> {
        let concrete_value = self.concrete.to_u64() & var.concrete.to_u64();
        let new_symbolic = self.symbolic.and(&var.symbolic, self.ctx)
            .map_err(|_| "Failed to combine symbolic values")?;

        Ok(CpuConcolicValue {
            concrete: ConcreteVar::Int(concrete_value),
            symbolic: new_symbolic,
            ctx: self.ctx,
        })
    }

    // Logical AND operation between two CpuConcolicValues
    pub fn and(self, other: Self) -> Result<Self, &'static str> {
        let concrete_value = self.concrete.to_u64() & other.concrete.to_u64();
        let new_symbolic = self.symbolic.and(&other.symbolic, self.ctx)
            .map_err(|_| "Failed to combine symbolic values")?;

        Ok(CpuConcolicValue {
            concrete: ConcreteVar::Int(concrete_value),
            symbolic: new_symbolic,
            ctx: self.ctx,
        })
    }

    // Logical AND operation with MemoryConcolicValue
    pub fn and_with_memory(self, other: MemoryConcolicValue<'ctx>) -> Result<CpuConcolicValue<'ctx>, &'static str> {
        let concrete_value = self.concrete.to_u64() & other.concrete.to_u64();
        let new_symbolic = self.symbolic.and(&other.symbolic, self.ctx)
            .map_err(|_| "Failed to combine symbolic values")?;

        Ok(CpuConcolicValue {
            concrete: ConcreteVar::Int(concrete_value),
            symbolic: new_symbolic,
            ctx: self.ctx,
        })
    }

    pub fn popcount(&self) -> BV<'ctx> {
        self.symbolic.popcount()
    }

    // Logical OR operation with ConcolicVar
    pub fn or_with_var(self, var: ConcolicVar<'ctx>) -> Result<CpuConcolicValue<'ctx>, &'static str> {
        let concrete_value = self.concrete.to_u64() | var.concrete.to_u64();
        let new_symbolic = self.symbolic.or(&var.symbolic, self.ctx)
            .map_err(|_| "Failed to combine symbolic values")?;
        Ok(CpuConcolicValue {
            concrete: ConcreteVar::Int(concrete_value),
            symbolic: new_symbolic,
            ctx: self.ctx,
        })
    }

    // Logical OR operation between two CpuConcolicValues
    pub fn or(self, other: Self) -> Result<Self, &'static str> {
        let concrete_value = self.concrete.to_u64() | other.concrete.to_u64();
        let new_symbolic = self.symbolic.or(&other.symbolic, self.ctx)
            .map_err(|_| "Failed to combine symbolic values")?;
        Ok(CpuConcolicValue {
            concrete: ConcreteVar::Int(concrete_value),
            symbolic: new_symbolic,
            ctx: self.ctx,
        })
    }

    // Logical OR operation with MemoryConcolicValue
    pub fn or_with_memory(self, other: MemoryConcolicValue<'ctx>) -> Result<CpuConcolicValue<'ctx>, &'static str> {
        let concrete_value = self.concrete.to_u64() | other.concrete.to_u64();
        let new_symbolic = self.symbolic.or(&other.symbolic, self.ctx)
            .map_err(|_| "Failed to combine symbolic values")?;
        Ok(CpuConcolicValue {
            concrete: ConcreteVar::Int(concrete_value),
            symbolic: new_symbolic,
            ctx: self.ctx,
        })
    }

    pub fn get_context_id(&self) -> String {
        format!("{:p}", self.ctx)
    } 

    pub fn get_size(&self) -> u32 {
        match &self.concrete {
            ConcreteVar::Int(_) => 64,  // Assuming all integers are u64
            ConcreteVar::Float(_) => 64, // Assuming double precision floats
            ConcreteVar::Str(s) => (s.len() * 8) as u32,  // Example, size in bits
        }
    }

    // Helper method to convert CpuConcolicValue or MemoryConcolicValue to ConcolicVar
    pub fn as_var(&self) -> Result<ConcolicVar<'ctx>, &'static str> {
        match self {
            CpuConcolicValue { concrete: mem_var, symbolic, ctx } => Ok(ConcolicVar::new_concrete_and_symbolic_int(mem_var.to_u64(), &symbolic.to_str(), *ctx, 64)),
            _ => Err("Unsupported type for conversion"),
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

    /// Tried to initialized registers from x86-64.sla file but several same offsets found!
    /// 
    // fn initialize_registers(&mut self) -> Result<(), Error> {
    //     let path = Path::new("src/concolic/specfiles/x86-64.sla");
    //     let sla_file_content = fs::read_to_string(path)?;
    
    //     for line in sla_file_content.lines() {
    //         if line.contains("space=\"register\"") {
    //             let name = self.extract_value(line, "name=\"", "\"").to_uppercase();
    //             let offset = u64::from_str_radix(self.extract_value(line, "offset=\"0x", "\""), 16)?;
    
    //             let concolic_value = CpuConcolicValue::new(self.ctx, 0);  
    //             self.registers.insert(offset, concolic_value);
    //             self.register_map.insert(offset, name.clone());
    //             println!("Register {} at offset 0x{:x} initialized.", name, offset);
    //         }
    //     }
    //     Ok(())
    // }    
    // fn extract_value<'a>(&self, from: &'a str, start_delim: &str, end_delim: &str) -> &'a str {
    //     from.split(start_delim).nth(1).unwrap().split(end_delim).next().unwrap()
    // }

    fn initialize_registers(&mut self) -> Result<(), Error> {

        // From ia.sinc
        let register_definitions = [
            // General Purpose Registers (64-bit mode)
            ("RAX", "0x0", "8"), ("RCX", "0x8", "8"), ("RDX", "0x10", "8"), ("RBX", "0x18", "8"),
            ("RSP", "0x20", "8"), ("RBP", "0x28", "8"), ("RSI", "0x30", "8"), ("RDI", "0x38", "8"),
            ("R8", "0x80", "8"), ("R9", "0x88", "8"), ("R10", "0x90", "8"), ("R11", "0x98", "8"),
            ("R12", "0xa0", "8"), ("R13", "0xa8", "8"), ("R14", "0xb0", "8"), ("R15", "0xb8", "8"),

            // Segment Registers
            ("ES", "0x100", "2"), ("CS", "0x102", "2"), ("SS", "0x104", "2"), ("DS", "0x106", "2"),
            ("FS", "0x108", "2"), ("GS", "0x10a", "2"), ("FS_OFFSET", "0x110", "8"), ("GS_OFFSET", "0x118", "8"),

            // Individual Flags within the Flag Register
            ("CF", "0x200", "1"),   // Carry Flag
            ("F1", "0x201", "1"),   // Reserved (always 1)
            ("PF", "0x202", "1"),   // Parity Flag
            ("F3", "0x203", "1"),   // Reserved
            ("AF", "0x204", "1"),   // Auxiliary Carry Flag
            ("F5", "0x205", "1"),   // Reserved
            ("ZF", "0x206", "1"),   // Zero Flag
            ("SF", "0x207", "1"),   // Sign Flag
            ("TF", "0x208", "1"),   // Trap Flag (Single Step)
            ("IF", "0x209", "1"),   // Interrupt Enable Flag
            ("DF", "0x20a", "1"),   // Direction Flag
            ("OF", "0x20b", "1"),   // Overflow Flag
            ("IOPL", "0x20c", "2"), // I/O Privilege Level (2 bits)
            ("NT", "0x20d", "1"),   // Nested Task Flag
            ("F15", "0x20e", "1"),  // Reserved
            ("RF", "0x20f", "1"),   // Resume Flag
            ("VM", "0x210", "1"),   // Virtual 8086 Mode
            ("AC", "0x211", "1"),   // Alignment Check (Alignment Mask)
            ("VIF", "0x212", "1"),  // Virtual Interrupt Flag
            ("VIP", "0x213", "1"),  // Virtual Interrupt Pending
            ("ID", "0x214", "1"),   // ID Flag 
            
            // RIP
            ("RIP", "0x288", "8"),

            // Debug and Control Registers
            ("DR0", "0x300", "8"), ("DR1", "0x308", "8"), ("DR2", "0x310", "8"), ("DR3", "0x318", "8"),
            ("DR4", "0x320", "8"), ("DR5", "0x328", "8"), ("DR6", "0x330", "8"), ("DR7", "0x338", "8"),
            ("CR0", "0x380", "8"), ("CR2", "0x390", "8"), ("CR3", "0x398", "8"), ("CR4", "0x3a0", "8"),
            ("CR8", "0x3c0", "8"),

            // Processor State Register and MPX Registers
            ("XCR0", "0x600", "8"), ("BNDCFGS", "0x700", "8"), ("BNDCFGU", "0x708", "8"),
            ("BNDSTATUS", "0x710", "8"), ("BND0", "0x740", "16"), ("BND1", "0x750", "16"),
            ("BND2", "0x760", "16"), ("BND3", "0x770", "16"),

            // ST registers
            ("MXCSR", "0x1094", "4"),

            // Extended SIMD Registers
            ("YMM0", "0x1200", "32"), ("YMM1", "0x1220", "32"), ("YMM2", "0x1240", "32"), ("YMM3", "0x1260", "32"),
            ("YMM4", "0x1280", "32"), ("YMM5", "0x12a0", "32"), ("YMM6", "0x12c0", "32"), ("YMM7", "0x12e0", "32"),
            ("YMM8", "0x1300", "32"), ("YMM9", "0x1320", "32"), ("YMM10", "0x1340", "32"), ("YMM11", "0x1360", "32"),
            ("YMM12", "0x1380", "32"), ("YMM13", "0x13a0", "32"), ("YMM14", "0x13c0", "32"), ("YMM15", "0x13e0", "32"),

            // Temporary SIMD Registers (for intermediate calculations etc.)
            ("xmmTmp1", "0x1400", "16"), ("xmmTmp2", "0x1410", "16"),
        ];

        for &(name, offset_hex, _size_str) in register_definitions.iter() {
            let offset = u64::from_str_radix(offset_hex.trim_start_matches("0x"), 16)
                .map_err(|e| anyhow!("Error parsing offset for {}: {}", name, e))?;

            if !self.is_valid_register_offset(name, offset) {
                return Err(anyhow!("Invalid register offset 0x{:X} for {}", offset, name));
            }

            let initial_value = 0;  // Default initialization value for all registers.

            // Create a new concolic value for the register.
            let concolic_value = CpuConcolicValue::new(self.ctx, initial_value);
            // Insert the new register into the map using its offset as the key.
            self.registers.insert(offset, concolic_value);
            // Map the offset to the register name for easy lookup
            self.register_map.insert(offset, name.to_string());

            // Print debug info to trace the initialization of registers
            // println!("Initialized register {} at offset 0x{:X} with size {}.", name, offset, size);
        }

        Ok(())
    }

    // Function to check if a given offset corresponds to a valid x86-64 register from the x86-64.sla file
    pub fn is_valid_register_offset(&self, name: &str, offset: u64) -> bool {
        let path = Path::new("src/concolic/specfiles/x86-64.sla");
        let sla_file_content = fs::read_to_string(path).expect("Failed to read SLA file");

        let relevant_section = sla_file_content.split("<start_sym name=\"inst_start\"").last().unwrap_or("");

        for line in relevant_section.lines() {
            if line.contains("<varnode_sym") && line.contains(format!("name=\"{}\"", name).as_str()) {
                let line_offset_hex = self.extract_value(line, "offset=\"", "\"");
                let line_offset = u64::from_str_radix(line_offset_hex.trim_start_matches("0x"), 16).unwrap();

                // Print debug info to trace the value comparisons
                // println!("Checking Register: {}, Given Offset: 0x{:X}, Found Offset in SLA: 0x{:X}, Line: {}", name, offset, line_offset, line);

                if offset == line_offset {
                    return true;
                }
            }
        }

        println!("No matching register found for {} with offset 0x{:X}", name, offset);
        false
    }

    // Helper function to extract a value from a string using start and end delimiters
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