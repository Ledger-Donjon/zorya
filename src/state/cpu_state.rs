/// Maintains the state of CPU registers and possibly other aspects of the CPU's status

use std::{collections::BTreeMap, sync::Mutex};
use std::{fmt, fs};
use anyhow::{Error, Result};
use regex::Regex;
use z3::ast::Ast;
use std::sync::Arc;
use anyhow::anyhow;
use std::path::Path;

use z3::{ast::BV, Context};

use crate::concolic::{ConcolicVar, ConcreteVar, SymbolicVar};
pub type SharedCpuState<'a> = Arc<Mutex<CpuState<'a>>>;
use crate::target_info::GLOBAL_TARGET_INFO;

#[derive(Debug, Clone)]
pub struct CpuConcolicValue<'ctx> {
    pub concrete: ConcreteVar,
    pub symbolic: SymbolicVar<'ctx>,
    pub ctx: &'ctx Context, 
}

impl<'ctx> CpuConcolicValue<'ctx> {
    pub fn new(ctx: &'ctx Context, initial_value: u64, size: u32) -> Self {
        let concrete = if size > 64 {
            // Split the initial_value into 64-bit chunks (little-endian order)
            let mut chunks = vec![];
            let mut remaining_value = initial_value;

            for _ in 0..(size / 64) {
                chunks.push(remaining_value & 0xFFFFFFFFFFFFFFFF); // Take the least significant 64 bits
                remaining_value >>= 64 - 1; // Shift right by 64 bits
            }

            // Handle any leftover bits if the size is not a multiple of 64
            if size % 64 != 0 {
                chunks.push(remaining_value & ((1u64 << (size % 64)) - 1)); // Mask the remaining bits
            }

            ConcreteVar::LargeInt(chunks)
        } else {
            ConcreteVar::Int(initial_value)
        };

        // Initialize the symbolic part based on size.
        let symbolic = if size > 64 {
            let num_bvs = (size as usize + 63) / 64; // Number of 64-bit BV chunks needed
            let bvs = (0..num_bvs).map(|_| BV::from_u64(ctx, initial_value, 64)).collect();
            SymbolicVar::LargeInt(bvs)
        } else {
            SymbolicVar::Int(BV::from_u64(ctx, initial_value, size))
        };

        println!("Created new CpuConcolicValue with concrete: {:?}, symbolic: {:?}", concrete, symbolic);

        CpuConcolicValue {
            concrete,
            symbolic,
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
            ConcreteVar::LargeInt(ref values) => Ok(values[0]), // Return the lower 64 bits
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
        let new_symbolic = self.symbolic.to_bv(ctx).extract(high, low);

        // Adjust the concrete value: mask the bits after shifting right
        let mask = (1u64 << new_size) - 1;
        let new_concrete = match &self.concrete {
            ConcreteVar::Int(value) => (value >> offset) & mask,
            ConcreteVar::LargeInt(values) => {
                // Handle LargeInt truncation
                let mut truncated_value = 0u64;
                for (i, &chunk) in values.iter().enumerate().skip(offset / 64) {
                    let shift = offset % 64;
                    truncated_value |= chunk >> shift;
                    if i < new_size as usize / 64 {
                        truncated_value |= values[i + 1] << (64 - shift);
                    }
                }
                truncated_value & mask
            }
            _ => return Err("Unsupported operation for this concrete type"),
        };

        Ok(CpuConcolicValue {
            concrete: ConcreteVar::Int(new_concrete),
            symbolic: SymbolicVar::Int(new_symbolic),
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
            ConcreteVar::LargeInt(values) => (values.len() * 64) as u32, // Size in bits
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
            self.registers.insert(offset, concolic_value.clone());
            // Map the offset to the register name for easy lookup
            self.register_map.insert(offset, (name.to_string(), size));

            // Print debug info to trace the initialization of registers
            // println!("Initialized register {} at offset 0x{:X} with value {:?} and size {}.", name, offset, concolic_value, size);
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

    pub fn upload_dumps_to_cpu_registers(&mut self) -> Result<()> {  
        let dumps_dir = {
                let info = GLOBAL_TARGET_INFO.lock().unwrap();
                info.memory_dumps.clone()
            };
    
        let cpu_output_path = dumps_dir.join("cpu_mapping.txt");    
        let cpu_output = fs::read_to_string(&cpu_output_path);    
        let result = Self::parse_and_update_cpu_state_from_gdb_output(self, &cpu_output.unwrap());
        if let Err(e) = result {
            println!("Error during CPU state update: {}", e);
            return Err(e);
        } 
    
        Ok(())
    }
    
    // Function to parse GDB output and update CPU state
    fn parse_and_update_cpu_state_from_gdb_output(&mut self, gdb_output: &str) -> Result<()> {
        let re_general = Regex::new(r"^\s*(\w+)\s+0x([\da-f]+)").unwrap();
        let re_flags = Regex::new(r"^\s*eflags\s+0x[0-9a-f]+\s+\[(.*?)\]").unwrap();
    
        // Display current state of flag registrations for debugging
        println!("Flag Registrations:");
        for (offset, (name, size)) in self.register_map.iter() {
            println!("{}: offset = 0x{:x}, size = {}", name, offset, size);
        }
    
        // Parse general registers
        for line in gdb_output.lines() {
            if let Some(caps) = re_general.captures(line) {
                let register_name = caps.get(1).unwrap().as_str().to_uppercase();
                let value_concrete = u64::from_str_radix(caps.get(2).unwrap().as_str(), 16)
                    .map_err(|e| anyhow!("Failed to parse hex value for {}: {}", register_name, e))?;
    
                if let Some((offset, size)) = self.clone().register_map.iter().find(|&(_, (name, _))| *name == register_name).map(|(&k, (_, s))| (k, s)) {
                    let value_symbolic = BV::from_u64(&self.ctx, value_concrete, *size);
                    let value_concolic = ConcolicVar::new_concrete_and_symbolic_int(value_concrete, value_symbolic, &self.ctx, *size);
                    let _ = self.set_register_value_by_offset(offset, value_concolic, *size);
                    println!("Updated register {} with value {}", register_name, value_concrete);
                }
            }
        }
    
        // Special handling for flags within eflags output
        for line in gdb_output.lines() {
            if let Some(caps) = re_flags.captures(line) {
                let flags_line = caps.get(1).unwrap().as_str();
                println!("Parsed flags line: {}", flags_line);  // Debug statement
    
                let flag_list = ["CF", "PF", "ZF", "SF", "TF", "IF", "DF", "OF", "NT", "RF", "AC", "ID"];
    
                for &flag in flag_list.iter() {
                    let flag_concrete = if flags_line.contains(flag) { 1 } else { 0 };
                    if let Some((offset, size)) = self.clone().register_map.iter().find(|&(_, (name, _))| *name == flag).map(|(&k, (_, s))| (k, s)) {
                        println!("Setting flag {} to {}", flag, flag_concrete);  // Debug statement
                        let flag_symbolic = BV::from_u64(&self.ctx, flag_concrete, *size);
                        let flag_concolic = ConcolicVar::new_concrete_and_symbolic_int(flag_concrete, flag_symbolic, &self.ctx, *size);
                        let _ = self.set_register_value_by_offset(offset, flag_concolic, *size);
                        
                        // Verify update
                        let updated_value = self.get_register_by_offset(offset, *size).map(|v| v.concrete.to_u64());
                        println!("Verification: {} is now set to {:?}", flag, updated_value);
                    } else {
                        println!("Flag {} not found in register_map", flag);
                    }
                }
            }
        }
    
        // Verify final state of specific flags
        for &flag in ["CF", "PF", "ZF", "SF", "TF", "IF", "DF", "OF", "NT", "RF", "AC", "ID"].iter() {
            if let Some((offset, size)) = self.register_map.iter().find(|&(_, (name, _))| *name == flag).map(|(&k, (_, s))| (k, s)) {
                let flag_value = self.get_register_by_offset(offset, *size).map(|v| v.concrete.to_u64()).unwrap_or(0);
                println!("{} flag value: {}", flag, flag_value);  // Debug statement
            }
        }
    
        Ok(())
    }

    // Helper function to extract a value from a string using start and end delimiters
    fn extract_value<'a>(&self, from: &'a str, start_delim: &str, end_delim: &str) -> &'a str {
        from.split(start_delim).nth(1).unwrap().split(end_delim).next().unwrap()
    }

    /// Sets the value of a register based on its offset
    pub fn set_register_value_by_offset(&mut self, offset: u64, new_value: ConcolicVar<'ctx>, new_size: u32) -> Result<(), String> {
        // Find the closest register that covers or contains the offset
        let closest_reg = self.registers.range_mut(..=offset).rev().find(|&(key, _)| *key <= offset);

        match closest_reg {
            Some((base_offset, reg)) => {
                let offset_within_reg = offset - base_offset;
                let bit_offset = offset_within_reg * 8; // Convert byte offset to bit offset within the register
                let full_reg_size = reg.symbolic.get_size() as u64; // Full size of the register in bits

                println!("Closest register found at offset 0x{:x}, register size: {}", base_offset, full_reg_size);
                println!("Calculated bit offset: {}, within register", bit_offset);

                // Ensure the bit offset + new size does not exceed the register size
                if bit_offset + new_size as u64 > full_reg_size {
                    println!("Error: Bit offset + new size exceeds full register size.");
                    return Err(format!("Cannot fit value into register starting at offset 0x{:x}: size overflow", base_offset));
                }

                // Determine the mask to update only the affected bits
                let mask = if new_size < 64 {
                    (1u64 << new_size) - 1
                } else {
                    u64::MAX
                };

                println!("Mask created for the relevant part: 0x{:x}", mask);

                // ----------------------
                // CONCRETE VALUE HANDLING
                // ----------------------
                if let ConcreteVar::LargeInt(ref mut large_concrete) = reg.concrete {
                    println!("Handling large concrete values for large register (LargeInt)");

                    let idx = (bit_offset / 64) as usize; // Index in the Vec<u64>
                    let inner_bit_offset = (bit_offset % 64) as u32; // Offset within the specific u64 element

                    println!("Index within Vec<u64>: {}, inner bit offset: {}", idx, inner_bit_offset);

                    if idx >= large_concrete.len() {
                        println!("Error: Bit offset exceeds size of the large integer register");
                        return Err("Bit offset exceeds size of the large integer register".to_string());
                    }

                    // Update the relevant portion of the chunk, handle carry between chunks
                    let new_concrete_part = (new_value.concrete.to_u64() & mask) << inner_bit_offset;
                    println!("Applying mask to large integer chunk {}, new_concrete_part: 0x{:x}", idx, new_concrete_part);

                    // Update the relevant portion of the concrete value without affecting other parts
                    large_concrete[idx] = (large_concrete[idx] & !(mask << inner_bit_offset)) | new_concrete_part;

                    // Handle carry over to the next chunk if necessary
                    if inner_bit_offset + new_size as u32 > 64 && idx + 1 < large_concrete.len() {
                        let remaining_bits = new_value.concrete.to_u64() >> (64 - inner_bit_offset);
                        large_concrete[idx + 1] = (large_concrete[idx + 1] & !(mask >> (64 - inner_bit_offset))) | (remaining_bits & (mask >> (64 - inner_bit_offset)));
                    }
                } else {
                    // Ensure that small registers remain as Int
                    let safe_shift = if bit_offset < 64 {
                        (new_value.concrete.to_u64() & mask) << bit_offset
                    } else {
                        0 // If bit_offset >= 64, shifting would overflow, so leave as 0
                    };
                    println!("Safe shift calculated: 0x{:x}", safe_shift);

                    let new_concrete_value = safe_shift & mask;
                    println!("New concrete value after applying mask: 0x{:x}", new_concrete_value);

                    // Update the concrete value while preserving the rest of the register
                    let new_concrete = (reg.concrete.to_u64() & !mask) | new_concrete_value;
                    println!("Final concrete value for register: 0x{:x}", new_concrete);

                    reg.concrete = ConcreteVar::Int(new_concrete);
                }

                // ----------------------
                // SYMBOLIC VALUE HANDLING
                // ----------------------
                if let SymbolicVar::LargeInt(ref mut large_symbolic) = reg.symbolic {
                    println!("Handling symbolic value for large integer register");
                
                    let idx = (bit_offset / 64) as usize;
                    let inner_bit_offset = (bit_offset % 64) as u32;
                
                    if idx >= large_symbolic.len() {
                        println!("Error: Bit offset exceeds size of the large integer symbolic register");
                        return Err("Bit offset exceeds size of the large integer symbolic register".to_string());
                    }
                
                    // Handle boolean symbolic values and convert them to bit-vectors
                    let symbolic_value_part = if new_value.symbolic.is_bool() {
                        // Convert the Boolean result into a bit-vector of size 8 (for byte-sized registers)
                        let bv_bool = new_value.symbolic.to_bv(self.ctx);
                        let bv_bool_extended = bv_bool.zero_ext(7);  // Convert to 8 bits (1 bit Boolean -> 8 bits)
                        bv_bool_extended.bvshl(&BV::from_u64(self.ctx, inner_bit_offset.into(), 8))
                    } else {
                        // Standard case for bit-vectors
                        let extension_size = 64 as u32 - new_size; // each chunk is 64 bits
                
                        if extension_size > 0 {
                            new_value.symbolic
                                .to_bv(self.ctx)
                                .zero_ext(extension_size)
                                .bvshl(&BV::from_u64(self.ctx, inner_bit_offset.into(), full_reg_size as u32))
                        } else {
                            new_value.symbolic
                                .to_bv(self.ctx)
                                .bvshl(&BV::from_u64(self.ctx, inner_bit_offset.into(), full_reg_size as u32))
                        }
                    };
                
                    if symbolic_value_part.get_z3_ast().is_null() {
                        println!("Error: Symbolic update failed (null AST)");
                        return Err("Symbolic update failed, resulting in a null AST".to_string());
                    }
                
                    println!("Symbolic value for the relevant part: {:?}", symbolic_value_part);
                
                    // Update symbolic value while preserving the rest of the symbolic state
                    let updated_symbolic = large_symbolic[idx]
                        .bvand(&BV::from_u64(self.ctx, !(mask << inner_bit_offset), 64)) // Clear the relevant bits
                        .bvor(&symbolic_value_part); // Set the new symbolic value for the target bits
                
                    if updated_symbolic.get_z3_ast().is_null() {
                        println!("Error: Updated symbolic value is null for chunk {}", idx);
                        return Err("Symbolic update failed, resulting in a null AST".to_string());
                    }
                
                    large_symbolic[idx] = updated_symbolic;
                
                    // Handle carry over to the next chunk if needed
                    if inner_bit_offset + new_size as u32 > 64 && idx + 1 < large_symbolic.len() {
                        let remaining_symbolic_bits = new_value.symbolic.to_bv(self.ctx)
                            .extract((new_size - (64 - inner_bit_offset)) as u32, 0);
                        large_symbolic[idx + 1] = large_symbolic[idx + 1].bvor(&remaining_symbolic_bits);
                    }
                } else {
                    println!("full_reg_size: {}", full_reg_size);
                    println!("new_size: {}", new_size);
                    println!("bit_offset: {}", bit_offset);
                    println!("new_value.symbolic: {:?} with size {}", new_value.symbolic, new_value.symbolic.get_size());
                    println!("new_value.symbolic.to_bv(self.ctx): {:?} with size {}", new_value.symbolic.to_bv(self.ctx), new_value.symbolic.to_bv(self.ctx).get_size());
                
                    // For smaller registers or if the symbolic value is an Int
                    let new_symbolic_value = if new_value.symbolic.is_bool() {
                        // Convert Boolean to a bit-vector of size 8 (for byte-sized registers)
                        let bv_bool = new_value.symbolic.to_bv(self.ctx);
                        let bv_bool_extended = bv_bool.zero_ext(7);  // Convert to 8 bits
                        bv_bool_extended.bvshl(&BV::from_u64(self.ctx, bit_offset, 8))
                    } else {
                        let extension_size = full_reg_size as u32 - new_size;
                
                        if extension_size > 0 {
                            new_value.symbolic.to_bv(self.ctx).zero_ext(extension_size).bvshl(&BV::from_u64(self.ctx, bit_offset, full_reg_size as u32))
                        } else {
                            new_value.symbolic.to_bv(self.ctx).bvshl(&BV::from_u64(self.ctx, bit_offset, full_reg_size as u32))
                        }
                    };
                
                    if new_symbolic_value.get_z3_ast().is_null() {
                        println!("Error: New symbolic value is null");
                        return Err("New symbolic value is null".to_string());
                    }
                
                    let combined_symbolic = reg.symbolic.to_bv(self.ctx)
                        .bvand(&BV::from_u64(self.ctx, !mask, full_reg_size as u32)) // Clear target bits
                        .bvor(&new_symbolic_value); // Set the new symbolic value for those bits
                
                    if combined_symbolic.get_z3_ast().is_null() {
                        println!("Error: Combined symbolic value is null");
                        return Err("Symbolic extraction resulted in an invalid state".to_string());
                    }
                
                    reg.symbolic = SymbolicVar::Int(combined_symbolic);
                }               

                println!("Register at base offset 0x{:x} updated with size {} bits, preserving total size of {} bits.", base_offset, new_size, full_reg_size);
                Ok(())
            }
            None => {
                println!("Error: No suitable register found for offset 0x{:x}", offset);
                Err(format!("No suitable register found for offset 0x{:x}", offset))
            }
        }
    }     
                                
    // Function to get a register by its offset, accounting for sub-register accesses and handling large registers
    pub fn get_register_by_offset(&self, offset: u64, access_size: u32) -> Option<CpuConcolicValue<'ctx>> {
        // Iterate over all registers to find one that spans the requested offset
        for (&base_offset, reg) in &self.registers {
            let reg_size_bits = reg.symbolic.get_size();  // Size of the register in bits
            let reg_size_bytes = reg_size_bits as u64 / 8;  // Size of the register in bytes

            // Check if the offset is within the range of this register
            if offset >= base_offset && offset < base_offset + reg_size_bytes {
                let byte_offset = offset - base_offset;  // Offset within the register in bytes
                let bit_offset = byte_offset * 8;  // Offset within the register in bits
                let effective_access_size = access_size.min(reg_size_bits - bit_offset as u32);  // Effective bits to access

                if bit_offset >= reg_size_bits as u64 {
                    // If the bit offset is outside the actual size of the register, skip
                    continue;
                }

                // Calculate the high bit index and ensure it does not exceed the register size
                let high_bit_index = std::cmp::min(bit_offset + effective_access_size as u64, reg_size_bits as u64) - 1;

                // Handling for LargeInt types
                if let ConcreteVar::LargeInt(ref values) = reg.concrete {
                    // Extract the correct u64 value from the vector based on bit offset
                    let index = (bit_offset / 64) as usize;
                    let concrete_value = if index < values.len() {
                        values[index]
                    } else {
                        0 // If index is out of bounds, assume the value is zero
                    };

                    // Symbolic extraction should handle vectors too
                    if let SymbolicVar::LargeInt(ref bvs) = reg.symbolic {
                        let symbolic_value = if index < bvs.len() {
                            bvs[index].clone() // Clone to maintain context integrity
                        } else {
                            BV::from_u64(self.ctx, 0, 64) // Default to zero if out of bounds
                        };

                        return Some(CpuConcolicValue {
                            concrete: ConcreteVar::Int(concrete_value),
                            symbolic: SymbolicVar::Int(symbolic_value),
                            ctx: self.ctx,
                        });
                    }
                } else {
                    // Standard extraction for non-LargeInt types
                    let new_symbolic = reg.symbolic.to_bv(self.ctx).extract(high_bit_index as u32, bit_offset as u32);
                    let mask = if effective_access_size < 64 {
                        (1u64 << effective_access_size) - 1
                    } else {
                        u64::MAX
                    };
                    let new_concrete = if effective_access_size == 0 || bit_offset >= 64 {
                        0  // No need to shift if effective access size is zero or bit_offset is too large
                    } else {
                        (reg.concrete.to_u64() >> bit_offset) & mask
                    };

                    return Some(CpuConcolicValue {
                        concrete: ConcreteVar::Int(new_concrete),
                        symbolic: SymbolicVar::Int(new_symbolic),
                        ctx: self.ctx,
                    });
                }
            }
        }
        // Return None if no suitable register found
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