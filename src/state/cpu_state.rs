/// Maintains the state of CPU registers and possibly other aspects of the CPU's status

use std::{collections::BTreeMap, sync::Mutex};
use std::{fmt, fs};
use anyhow::{Error, Result};
use std::sync::Arc;
use anyhow::anyhow;
use std::path::Path;

use z3::{ast::BV, Context};

use crate::concolic::{ConcolicVar, ConcreteVar, SymbolicVar};

pub type SharedCpuState<'a> = Arc<Mutex<CpuState<'a>>>;

#[derive(Debug, Clone)]
pub struct CpuConcolicValue<'ctx> {
    pub concrete: ConcreteVar,
    pub symbolic: SymbolicVar<'ctx>,
    pub ctx: &'ctx Context, 
}

impl<'ctx> CpuConcolicValue<'ctx> {
    pub fn new(ctx: &'ctx Context, concrete_value: u64, size: u32) -> Self {
        CpuConcolicValue {
            concrete: ConcreteVar::Int(concrete_value),
            symbolic: SymbolicVar::Int(BV::from_u64(ctx, concrete_value, size)),  
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
            ConcreteVar::Bool(value) => Ok(value as u64),
        }
    }

    // Method to retrieve the symbolic value
    pub fn get_symbolic_value(&self) -> &SymbolicVar<'ctx> {
        &self.symbolic
    }

    // Resize the value of a register if working with sub registers (e. g. ESI is 32 bits, while RSI is 64 bits)
    pub fn resize(&mut self, new_size: u32, ctx: &'ctx Context) {
        if new_size == 0 || new_size > 256 {
            panic!("Resize to invalid bit size: size must be between 1 and 256");
        }

        let current_size = self.symbolic.to_bv(ctx).get_size() as u32;

        if new_size < current_size {
            // If reducing size, mask the concrete value and extract the needed bits from symbolic.
            let mask = (1u64.wrapping_shl(new_size as u32).wrapping_sub(1)) as u64;
            self.concrete = ConcreteVar::Int(self.concrete.to_u64() & mask);
            self.symbolic = SymbolicVar::Int(self.symbolic.to_bv(ctx).extract(new_size - 1, 0));
        } else if new_size > current_size {
            // If increasing size, zero extend the symbolic value. No change needed for concrete value if it's smaller.
            self.symbolic = SymbolicVar::Int(self.symbolic.to_bv(ctx).zero_ext(new_size - current_size));
        }
        // If sizes are equal, no resize operation is needed.
    }

    pub fn popcount(&self) -> BV<'ctx> {
        self.symbolic.popcount()
    }

    pub fn concolic_zero_extend(&self, new_size: u32) -> Result<Self, &'static str> {
        let current_size = self.symbolic.get_size() as u32;
        if new_size <= current_size {
            return Err("New size must be greater than current size.");
        }
        
        let extension_size = new_size - current_size;
        let zero_extended_symbolic = match &self.symbolic {
            SymbolicVar::Int(bv) => SymbolicVar::Int(bv.zero_ext(extension_size)),
            _ => return Err("Zero extension is only applicable to integer bit vectors."),
        };

        Ok(Self {
            concrete: ConcreteVar::Int(self.concrete.to_u64()),  // Concrete value remains unchanged
            symbolic: zero_extended_symbolic,
            ctx: self.ctx,
        })
    }

    // Truncate both concrete and symbolic values
    pub fn truncate(&self, offset: usize, new_size: u32, ctx: &'ctx Context) -> Result<Self, &'static str> {
        // Check if the new size and offset are valid
        if offset + new_size as usize > self.symbolic.get_size() as usize {
            return Err("Truncation range out of bounds");
        }

        // Adjust the symbolic extraction
        let high = (offset + new_size as usize - 1) as u32;
        let low = offset as u32;
        let new_symbolic = self.symbolic.extract(high, low)
            .map_err(|_| "Failed to extract symbolic part")?;  // Properly handle the Result from extract

        // Adjust the concrete value: mask the bits after shifting right
        let mask = (1u64 << new_size) - 1;
        let new_concrete = match self.concrete {
            ConcreteVar::Int(value) => (value >> offset) & mask,
            _ => return Err("Unsupported operation for this concrete type"),
        };

        Ok(CpuConcolicValue {
            concrete: ConcreteVar::Int(new_concrete),
            symbolic: new_symbolic,
            ctx,
        })
    } 

    pub fn get_context_id(&self) -> String {
        format!("{:p}", self.ctx)
    } 

    pub fn get_size(&self) -> u32 {
        match &self.concrete {
            ConcreteVar::Int(_) => 64,  // all integers are u64
            ConcreteVar::Float(_) => 64, // double precision floats
            ConcreteVar::Str(s) => (s.len() * 8) as u32,  // ?
            ConcreteVar::Bool(_) => 1,
        }
    }
}


impl<'ctx> fmt::Display for CpuConcolicValue<'ctx> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Concrete: Int(0x{:x}), Symbolic: {:?}", self.concrete, self.symbolic)
    }
}

#[derive(Debug, Clone)]
pub struct CpuState<'ctx> {
    pub registers: BTreeMap<u64, CpuConcolicValue<'ctx>>,
    pub register_map: BTreeMap<u64, (String, u32)>, // Map of register offsets to register names and sizes
    pub ctx: &'ctx Context,
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

        // From ia.sinc
        let register_definitions = [
        // General Purpose Registers (64-bit mode)
        ("RAX", "0x0", "64"), ("RCX", "0x8", "64"), ("RDX", "0x10", "64"), ("RBX", "0x18", "64"),
        ("RSP", "0x20", "64"), ("RBP", "0x28", "64"), ("RSI", "0x30", "64"), ("RDI", "0x38", "64"),
        ("R8", "0x80", "64"), ("R9", "0x88", "64"), ("R10", "0x90", "64"), ("R11", "0x98", "64"),
        ("R12", "0xa0", "64"), ("R13", "0xa8", "64"), ("R14", "0xb0", "64"), ("R15", "0xb8", "64"),

        // Segment Registers
        ("ES", "0x100", "16"), ("CS", "0x102", "16"), ("SS", "0x104", "16"), ("DS", "0x106", "16"),
        ("FS", "0x108", "16"), ("GS", "0x10a", "16"), ("FS_OFFSET", "0x110", "64"), ("GS_OFFSET", "0x118", "64"),

        // Individual Flags within the Flag Register
        ("CF", "0x200", "8"),   // Carry Flag
        ("F1", "0x201", "8"),   // Reserved (always 1)
        ("PF", "0x202", "8"),   // Parity Flag
        ("F3", "0x203", "8"),   // Reserved
        ("AF", "0x204", "8"),   // Auxiliary Carry Flag
        ("F5", "0x205", "8"),   // Reserved
        ("ZF", "0x206", "8"),   // Zero Flag
        ("SF", "0x207", "8"),   // Sign Flag
        ("TF", "0x208", "8"),   // Trap Flag (Single Step)
        ("IF", "0x209", "8"),   // Interrupt Enable Flag
        ("DF", "0x20a", "8"),   // Direction Flag
        ("OF", "0x20b", "8"),   // Overflow Flag
        ("IOPL", "0x20c", "16"), // I/O Privilege Level (2 bits)
        ("NT", "0x20d", "8"),   // Nested Task Flag
        ("F15", "0x20e", "8"),  // Reserved
        ("RF", "0x20f", "8"),   // Resume Flag
        ("VM", "0x210", "8"),   // Virtual 8086 Mode
        ("AC", "0x211", "8"),   // Alignment Check (Alignment Mask)
        ("VIF", "0x212", "8"),  // Virtual Interrupt Flag
        ("VIP", "0x213", "8"),  // Virtual Interrupt Pending
        ("ID", "0x214", "8"),   // ID Flag 

        // RIP
        ("RIP", "0x288", "64"),

        // Debug and Control Registers
        ("DR0", "0x300", "64"), ("DR1", "0x308", "64"), ("DR2", "0x310", "64"), ("DR3", "0x318", "64"),
        ("DR4", "0x320", "64"), ("DR5", "0x328", "64"), ("DR6", "0x330", "64"), ("DR7", "0x338", "64"),
        ("CR0", "0x380", "64"), ("CR2", "0x390", "64"), ("CR3", "0x398", "64"), ("CR4", "0x3a0", "64"),
        ("CR8", "0x3c0", "64"),

        // Processor State Register and MPX Registers
        ("XCR0", "0x600", "64"), ("BNDCFGS", "0x700", "64"), ("BNDCFGU", "0x708", "64"),
        ("BNDSTATUS", "0x710", "64"), ("BND0", "0x740", "128"), ("BND1", "0x750", "128"),
        ("BND2", "0x760", "128"), ("BND3", "0x770", "128"),

        // ST registers
        ("MXCSR", "0x1094", "32"),

        // Extended SIMD Registers
        ("YMM0", "0x1200", "256"), ("YMM1", "0x1220", "256"), ("YMM2", "0x1240", "256"), ("YMM3", "0x1260", "256"),
        ("YMM4", "0x1280", "256"), ("YMM5", "0x12a0", "256"), ("YMM6", "0x12c0", "256"), ("YMM7", "0x12e0", "256"),
        ("YMM8", "0x1300", "256"), ("YMM9", "0x1320", "256"), ("YMM10", "0x1340", "256"), ("YMM11", "0x1360", "256"),
        ("YMM12", "0x1380", "256"), ("YMM13", "0x13a0", "256"), ("YMM14", "0x13c0", "256"), ("YMM15", "0x13e0", "256"),

        // Temporary SIMD Registers (for intermediate calculations etc.)
        ("xmmTmp1", "0x1400", "128"), ("xmmTmp2", "0x1410", "128"),
    ];

        for &(name, offset_hex, size_str) in register_definitions.iter() {
            let offset = u64::from_str_radix(offset_hex.trim_start_matches("0x"), 16)
                .map_err(|e| anyhow!("Error parsing offset for {}: {}", name, e))?;
            let size = size_str.parse::<u32>()
                .map_err(|e| anyhow!("Error parsing size for {}: {}", name, e))?;

            if !self.is_valid_register_offset(name, offset) {
                return Err(anyhow!("Invalid register offset 0x{:X} for {}", offset, name));
            }

            let initial_value = 0;  // Default initialization value for all registers.

            // Create a new concolic value for the register.
            let concolic_value = CpuConcolicValue::new(self.ctx, initial_value, size);
            // Insert the new register into the map using its offset as the key.
            self.registers.insert(offset, concolic_value);
            // Map the offset to the register name for easy lookup
            self.register_map.insert(offset, (name.to_string(), size));

            // Print debug info to trace the initialization of registers
            println!("Initialized register {} at offset 0x{:X} with size {}.", name, offset, size);
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
    pub fn set_register_value_by_offset(&mut self, offset: u64, value: ConcolicVar<'ctx>, size: u32) -> Result<(), String> {
        if let Some(reg) = self.registers.get_mut(&offset) {
            // Resize the value according to the register size
            let mask = if size >= 64 {
                u64::MAX
            } else {
                (1 << size) - 1
            };
            let resized_concrete = value.concrete.to_u64() & mask;
            let resized_symbolic = value.symbolic.to_bv(self.ctx).extract(size - 1, 0);

            reg.concrete = ConcreteVar::Int(resized_concrete);
            reg.symbolic = SymbolicVar::Int(resized_symbolic);

            println!("Register at offset 0x{:x} set to {:x} with size {:?}", offset, resized_concrete, size);
            Ok(())
        } else {
            Err(format!("Register at offset 0x{:x} not found", offset))
        }
    }

    // Function to get a register by its offset, accounting for sub-register accesses
    pub fn get_register_by_offset(&self, offset: u64, access_size: u32) -> Option<CpuConcolicValue<'ctx>> {
        // Check if the exact register exists
        if let Some(reg) = self.registers.get(&offset) {
            return Some(reg.clone());
        }

        // Handle sub-register access
        for (base_offset, reg) in &self.registers {
            let size_in_bytes = reg.symbolic.get_size() as u64 / 8;
            if offset >= *base_offset && offset < *base_offset + size_in_bytes {
                // Calculate byte offset within the larger register
                let byte_offset = offset - base_offset;
                // Calculate bit offset (e.g., accessing a word 16 bits in)
                let bit_offset = byte_offset * 8;
                let effective_access_size = access_size.min(reg.symbolic.get_size() as u32 - bit_offset as u32);

                // Ensure proper typing for bit operations
                let high_bit = bit_offset + u64::from(effective_access_size) - 1;
                let low_bit = bit_offset as u32;

                // Safely perform the extraction
                let new_symbolic = reg.symbolic.to_bv(self.ctx).extract(high_bit as u32, low_bit);

                let mask = (1u64 << effective_access_size) - 1;
                let new_concrete = (reg.concrete.to_u64() >> low_bit) & mask;

                return Some(CpuConcolicValue {
                    concrete: ConcreteVar::Int(new_concrete),
                    symbolic: SymbolicVar::Int(new_symbolic),
                    ctx: self.ctx,
                });
            }
        }
        None
    }

    /// Gets the concolic value of a register identified by its offset.
    pub fn get_concolic_register_by_offset(&self, offset: u64, size: u32) -> Option<ConcolicVar<'ctx>> {
        if let Some(reg) = self.registers.get(&offset) {
            let concrete = reg.concrete.to_u64();
            let symbolic = reg.symbolic.to_bv(self.ctx);
            Some(ConcolicVar::new_concrete_and_symbolic_int(concrete, symbolic, self.ctx, size))
        } else {
            None
        }
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