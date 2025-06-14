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

        //println!("Created new CpuConcolicValue with concrete: {:?}, symbolic: {:?}", concrete, symbolic);

        CpuConcolicValue {
            concrete,
            symbolic,
            ctx,
        }
    }

    /// Creates a new CpuConcolicValue where the symbolic part is built from fresh constants.
    /// If the register size is greater than 64, it creates a vector of fresh 64‑bit BVs.
    pub fn new_with_symbolic(ctx: &'ctx Context, initial_value: u64, reg_name: &str, size: u32,) -> Self {
        if size > 64 {
            let num_chunks = ((size as usize) + 63) / 64; // Number of 64-bit chunks needed.
            let mut fresh_chunks = Vec::with_capacity(num_chunks);
            for i in 0..num_chunks {
                let chunk = BV::fresh_const(ctx, &format!("{}_chunk_{}", reg_name, i), 64);
                fresh_chunks.push(chunk);
            }
            // For the concrete part, split initial_value into chunks.
            let mut chunks = Vec::new();
            let num_full_chunks = (size / 64) as usize;
            let mut remaining_value = initial_value;
            for i in 0..num_full_chunks {
                chunks.push(remaining_value & 0xFFFFFFFFFFFFFFFF);
                // Only shift if this is not the last full chunk.
                if i < num_full_chunks - 1 {
                    // Use checked_shr to safely shift.
                    remaining_value = remaining_value.checked_shr(64).unwrap_or(0);
                }
            }
            if size % 64 != 0 {
                // Handle any leftover bits.
                chunks.push(remaining_value & ((1u64 << (size % 64)) - 1));
            }
            let concrete = ConcreteVar::LargeInt(chunks);
            let symbolic = SymbolicVar::LargeInt(fresh_chunks);
            CpuConcolicValue { concrete, symbolic, ctx }
        } else {
            let sym_bv = BV::fresh_const(ctx, &format!("reg_{}", reg_name), size);
            let concrete = ConcreteVar::Int(initial_value);
            let symbolic = SymbolicVar::Int(sym_bv);
            CpuConcolicValue { concrete, symbolic, ctx }
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

    pub fn is_bool(&self) -> bool {
        match &self.concrete {
            ConcreteVar::Bool(_) => true,
            _ => false,
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
        
            // Use 0 as the default concrete value.
            let initial_concrete = 0;
        
            // Create a new concolic value with a fresh symbolic BV (or vector of BVs if size > 64).
            let concolic_value = CpuConcolicValue::new_with_symbolic(self.ctx, initial_concrete, name, size);
            self.registers.insert(offset, concolic_value.clone());
            self.register_map.insert(offset, (name.to_string(), size));
        }    

        Ok(())
    }

    pub fn resolve_offset_from_register_name(&self, reg_name: &str) -> Option<u64> {
        self.register_map
            .iter()
            .find_map(|(offset, (name, _))| {
                if name == reg_name {
                    Some(*offset)
                } else {
                    None
                }
            })
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
        false
    }

    pub fn upload_dumps_to_cpu_registers(&mut self) -> Result<()> {
        let zorya_dir = {
            let info = GLOBAL_TARGET_INFO.lock().unwrap();
            info.zorya_path.clone()
        };

        let cpu_output_path = zorya_dir.join("results").join("initialization_data").join("cpu_mapping.txt");
        
        // Attempt to read the file and print the file path if it fails
        let cpu_output = fs::read_to_string(&cpu_output_path);
        match cpu_output {
            Ok(content) => {
                // Proceed if the file was read successfully
                let result = Self::parse_and_update_cpu_state_from_gdb_output(self, &content);
                if let Err(e) = result {
                    println!("Error during CPU state update: {}", e);
                    return Err(anyhow::Error::from(e));
                }
            }
            Err(e) => {
                // Print an error message showing the path and error if the file could not be read
                println!(
                    "Failed to read cpu_mapping.txt at path: {}. Error: {}",
                    cpu_output_path.display(),
                    e
                );
                return Err(e.into());
            }
        }

        Ok(())
    } 
    
    // Function to parse GDB output and update CPU state
    fn parse_and_update_cpu_state_from_gdb_output(&mut self, gdb_output: &str) -> Result<()> {
        let re_general = Regex::new(r"^\s*(\w+)\s+0x([\da-f]+)").unwrap();
        let re_flags = Regex::new(r"^\s*eflags\s+0x[0-9a-f]+\s+\[(.*?)\]").unwrap();
    
        // Display current state of flag registrations for debugging
        //println!("Flag Registrations:");
        //for (offset, (name, size)) in self.register_map.iter() {
        //    println!("{}: offset = 0x{:x}, size = {}", name, offset, size);
        //}
    
        // Parse general registers
        for line in gdb_output.lines() {
            if let Some(caps) = re_general.captures(line) {
                let register_name = caps.get(1).unwrap().as_str().to_uppercase();
                let value_concrete = u64::from_str_radix(caps.get(2).unwrap().as_str(), 16)
                    .map_err(|e| anyhow!("Failed to parse hex value for {}: {}", register_name, e))?;
    
                if let Some((offset, size)) = self.clone().register_map.iter().find(|&(_, (name, _))| *name == register_name).map(|(&k, (_, s))| (k, s)) {
                    let value_symbolic = BV::from_u64(&self.ctx, value_concrete, *size);
                    let value_concolic = ConcolicVar::new_concrete_and_symbolic_int(value_concrete, value_symbolic, &self.ctx, *size);
                    self.set_register_value_by_offset(offset, value_concolic, *size).map_err(|e| {
                        anyhow!("Failed to set register value for {}: {}", register_name, e)
                    })?;
                    println!("Updated register {} at offset 0x{:x} with value 0x{:x}", register_name, offset, value_concrete);
                }
            }
        }
    
        // Special handling for flags within eflags output
        for line in gdb_output.lines() {
            if let Some(caps) = re_flags.captures(line) {
                let flags_line = caps.get(1).unwrap().as_str();
    
                let flag_list = ["CF", "PF", "ZF", "SF", "TF", "IF", "DF", "OF", "NT", "RF", "AC", "ID"];
    
                for &flag in flag_list.iter() {
                    let flag_concrete = if flags_line.contains(flag) { 1 } else { 0 };
                    if let Some((offset, size)) = self.clone().register_map.iter().find(|&(_, (name, _))| *name == flag).map(|(&k, (_, s))| (k, s)) {
                        let flag_symbolic = BV::from_u64(&self.ctx, flag_concrete, *size);
                        let flag_concolic = ConcolicVar::new_concrete_and_symbolic_int(flag_concrete, flag_symbolic, &self.ctx, *size);
                        self.set_register_value_by_offset(offset, flag_concolic, *size).map_err(|e| {
                            anyhow!("Failed to set flag value for {}: {}", flag, e)
                        })?;
                        println!("Updated flag {} at offset 0x{:x} with value {}", flag, offset, flag_concrete);
                    } else {
                        println!("Flag {} not found in register_map", flag);
                    }
                }
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
        // Find the register that contains the offset
        for (&reg_offset, reg) in self.registers.iter_mut() {
            let reg_size_bits = reg.symbolic.get_size() as u64;
            let reg_size_bytes = reg_size_bits / 8;
            if offset >= reg_offset && (offset + (new_size as u64 / 8)) <= (reg_offset + reg_size_bytes)
            {
                let offset_within_reg = offset - reg_offset;
                let bit_offset = offset_within_reg * 8; // Convert byte offset to bit offset within the register
                let full_reg_size = reg_size_bits; // Full size of the register in bits

                // Ensure the bit offset + new size does not exceed the register size
                if bit_offset + new_size as u64 > full_reg_size {
                    println!("Error: Bit offset + new size exceeds full register size.");
                    return Err(format!(
                        "Cannot fit value into register starting at offset 0x{:x}: size overflow",
                        reg_offset
                    ));
                }

                // ----------------------
                // CONCRETE VALUE HANDLING
                // ----------------------
                if let ConcreteVar::LargeInt(ref mut large_concrete) = reg.concrete {
                    let mut remaining_bits = new_size as u64;
                    let mut current_bit_offset = bit_offset;
                    let mut value = new_value.concrete.to_u64();
                    while remaining_bits > 0 {
                        let idx = (current_bit_offset / 64) as usize; // Index in the Vec<u64>
                        let inner_bit_offset = (current_bit_offset % 64) as u32; // Offset within the specific u64 element

                        if idx >= large_concrete.len() {
                            println!(
                                "Error: Bit offset exceeds size of the large integer register"
                            );
                            return Err(
                                "Bit offset exceeds size of the large integer register".to_string(),
                            );
                        }

                        let bits_in_chunk =
                            std::cmp::min(64 - inner_bit_offset as u64, remaining_bits);
                        let mask = Self::safe_left_mask(bits_in_chunk) << inner_bit_offset;

                        let value_part =
                            (value & Self::safe_left_mask(bits_in_chunk)) << inner_bit_offset;

                        large_concrete[idx] =
                            (large_concrete[idx] & !mask) | value_part;

                        remaining_bits -= bits_in_chunk;
                        current_bit_offset += bits_in_chunk;

                        // Adjust value shift
                        if bits_in_chunk < 64 {
                            value >>= bits_in_chunk;
                        } else {
                            value = 0;
                        }
                    }
                } else {
                    // Ensure that small registers remain as Int
                    let safe_shift = if bit_offset < 64 {
                        (new_value.concrete.to_u64()
                            & Self::safe_left_mask(new_size as u64))
                            << bit_offset
                    } else {
                        0 // If bit_offset >= 64, shifting would overflow, so leave as 0
                    };

                    let mask = if new_size >= 64 {
                        !0u64
                    } else {
                        (1u64 << new_size) - 1
                    };
                    let new_concrete_value = safe_shift & (mask << bit_offset);

                    // Update the concrete value while preserving the rest of the register
                    let new_concrete =
                        (reg.concrete.to_u64() & !(mask << bit_offset)) | new_concrete_value;

                    reg.concrete = ConcreteVar::Int(new_concrete);
                }

                // ----------------------
                // SYMBOLIC VALUE HANDLING
                // ----------------------
                if let SymbolicVar::LargeInt(ref mut large_symbolic) = reg.symbolic {
                    let mut remaining_bits = new_size as u64;
                    let mut current_bit_offset = bit_offset;
                    let new_symbolic_bv = new_value.symbolic.to_bv_of_size(self.ctx, new_size);

                    while remaining_bits > 0 {
                        let idx = (current_bit_offset / 64) as usize;
                        let inner_bit_offset = (current_bit_offset % 64) as u32;

                        if idx >= large_symbolic.len() {
                            println!(
                                "Error: Bit offset exceeds size of the large integer symbolic register"
                            );
                            return Err(
                                "Bit offset exceeds size of the large integer symbolic register"
                                    .to_string(),
                            );
                        }

                        let bits_in_chunk =
                            std::cmp::min(64 - inner_bit_offset as u64, remaining_bits);
                        let bits_in_chunk_u32 = bits_in_chunk as u32;

                        // Extract the relevant bits from new_symbolic_bv
                        let high_bit = (remaining_bits - 1) as u32;
                        let low_bit = (remaining_bits - bits_in_chunk) as u32;

                        let symbolic_value_part = new_symbolic_bv
                            .extract(high_bit, low_bit)
                            .zero_ext(64 - bits_in_chunk_u32);
                        let shift_amount_bv =
                            BV::from_u64(self.ctx, inner_bit_offset as u64, 64);

                        let symbolic_value_part_shifted =
                            symbolic_value_part.bvshl(&shift_amount_bv);

                        if symbolic_value_part_shifted.get_z3_ast().is_null() {
                            println!("Error: Symbolic update failed (null AST)");
                            return Err(
                                "Symbolic update failed, resulting in a null AST".to_string(),
                            );
                        }

                        // Mask to clear only the relevant bits in the current chunk
                        let mask =
                            Self::safe_left_mask(bits_in_chunk_u32 as u64) << inner_bit_offset;

                        let updated_symbolic = large_symbolic[idx]
                            .bvand(&BV::from_u64(self.ctx, !mask, 64)) // Clear the relevant bits
                            .bvor(&symbolic_value_part_shifted); // Set the new symbolic value for the target bits

                        if updated_symbolic.get_z3_ast().is_null() {
                            println!(
                                "Error: Updated symbolic value is null for chunk {}",
                                idx
                            );
                            return Err(
                                "Symbolic update failed, resulting in a null AST".to_string(),
                            );
                        }

                        large_symbolic[idx] = updated_symbolic;

                        remaining_bits -= bits_in_chunk;
                        current_bit_offset += bits_in_chunk;
                    }
                } else {
                    // Get the symbolic value as BV of the appropriate size
                    let new_symbolic_bv = new_value.symbolic.to_bv_of_size(self.ctx, new_size);

                    // Ensure small symbolic values remain as Int
                    let new_symbolic_value = new_symbolic_bv
                        .zero_ext(full_reg_size as u32 - new_size)
                        .bvshl(&BV::from_u64(self.ctx, bit_offset, full_reg_size as u32));

                    if new_symbolic_value.get_z3_ast().is_null() {
                        println!("Error: New symbolic value is null");
                        return Err("New symbolic value is null".to_string());
                    }
                    let mask = if new_size >= 64 {
                        !0u64
                    } else {
                        (1u64 << new_size) - 1
                    };

                    let combined_symbolic = reg
                        .symbolic
                        .to_bv(self.ctx)
                        .bvand(&BV::from_u64(self.ctx, !(mask << bit_offset), full_reg_size as u32)) // Clear target bits
                        .bvor(&new_symbolic_value); // Set the new symbolic value for those bits

                    if combined_symbolic.get_z3_ast().is_null() {
                        println!("Error: Combined symbolic value is null");
                        return Err(
                            "Symbolic extraction resulted in an invalid state".to_string(),
                        );
                    }
                    reg.symbolic = SymbolicVar::Int(combined_symbolic);
                }
                return Ok(());
            }
        }
        // If we reach here, no suitable register was found
        println!("Error: No suitable register found for offset 0x{:x}", offset);
        Err(format!(
            "No suitable register found for offset 0x{:x}",
            offset
        ))
    }       
                                
    // Function to get a register by its offset, accounting for sub-register accesses and handling large registers
    pub fn get_register_by_offset(&self, offset: u64, access_size: u32) -> Option<CpuConcolicValue<'ctx>> {
        // Iterate over all registers to find one that spans the requested offset
        for (&base_offset, reg) in &self.registers {
            let reg_size_bits = reg.symbolic.get_size(); // Size of the register in bits
            let reg_size_bytes = reg_size_bits as u64 / 8; // Size of the register in bytes

            // Check if the offset is within the range of this register
            if offset >= base_offset && offset < base_offset + reg_size_bytes {
                let byte_offset = offset - base_offset; // Offset within the register in bytes
                let bit_offset = byte_offset * 8; // Offset within the register in bits
                let effective_access_size = access_size.min(reg_size_bits - bit_offset as u32); // Effective bits to access

                if bit_offset >= reg_size_bits as u64 {
                    // If the bit offset is outside the actual size of the register, skip
                    continue;
                }

                // Calculate the start and end bit indices
                let start_bit = bit_offset;
                let end_bit = start_bit + effective_access_size as u64 - 1;

                // Handling for LargeInt types
                if let ConcreteVar::LargeInt(ref values) = reg.concrete {
                    let concrete_value = Self::extract_bits_from_large_int(values, start_bit, end_bit);
                    // For symbolic value
                    if let SymbolicVar::LargeInt(ref bvs) = reg.symbolic {
                        let symbolic_value =
                            Self::extract_symbolic_bits_from_large_int(self.ctx, bvs, start_bit, end_bit);
                        return Some(CpuConcolicValue {
                            concrete: concrete_value,
                            symbolic: symbolic_value,
                            ctx: self.ctx,
                        });
                    }
                } else {
                    // Standard extraction for non-LargeInt types
                    let new_symbolic =
                        reg.symbolic.to_bv(self.ctx).extract(end_bit as u32, start_bit as u32);
                    let mask = if effective_access_size < 64 {
                        (1u64 << effective_access_size) - 1
                    } else {
                        u64::MAX
                    };
                    let new_concrete = if effective_access_size == 0 || bit_offset >= 64 {
                        0 // No need to shift if effective access size is zero or bit_offset is too large
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

    // Helper functions for safe shifts
    fn safe_shift_left(value: u64, shift: u64) -> u64 {
        if shift >= 64 {
            0
        } else {
            value << shift
        }
    }

    fn safe_shift_right(value: u64, shift: u64) -> u64 {
        if shift >= 64 {
            0
        } else {
            value >> shift
        }
    }

    fn safe_left_mask(bits: u64) -> u64 {
        if bits >= 64 {
            !0u64
        } else {
            (1u64 << bits) - 1
        }
    }

    // Function to extract bits from a large integer (Vec<u64>), returns ConcreteVar
    pub fn extract_bits_from_large_int(values: &[u64], start_bit: u64, end_bit: u64) -> ConcreteVar {
        if start_bit > end_bit {
            // Invalid range, return zero
            return ConcreteVar::Int(0);
        }
    
        let total_bits = end_bit - start_bit + 1;
        if total_bits <= 64 {
            let mut result = 0u64;
            let mut bit_pos = 0u64;
            let mut current_bit = start_bit;
    
            while current_bit <= end_bit {
                let chunk_index = (current_bit / 64) as usize;
                let bit_in_chunk = current_bit % 64;
    
                let bits_left_in_chunk = 64 - bit_in_chunk;
                if bits_left_in_chunk == 0 {
                    current_bit += 1;
                    continue;
                }
    
                let bits_left_in_extract = end_bit - current_bit + 1;
                if bits_left_in_extract == 0 {
                    break;
                }
    
                let bits_to_take = std::cmp::min(bits_left_in_chunk, bits_left_in_extract);
    
                let chunk = values.get(chunk_index).copied().unwrap_or(0);
    
                let mask = Self::safe_left_mask(bits_to_take) << bit_in_chunk;
                let bits = Self::safe_shift_right(chunk & mask, bit_in_chunk);
    
                result |= Self::safe_shift_left(bits, bit_pos);
    
                current_bit += bits_to_take;
                bit_pos += bits_to_take;
            }
    
            ConcreteVar::Int(result)
        } else {
            // Extract into a Vec<u64>
            let num_u64s = ((total_bits + 63) / 64) as usize;
            let mut result = vec![0u64; num_u64s];
            let mut bit_pos = 0u64;
            let mut current_bit = start_bit;
    
            while current_bit <= end_bit {
                let chunk_index = (current_bit / 64) as usize;
                let bit_in_chunk = current_bit % 64;
    
                let bits_left_in_chunk = 64 - bit_in_chunk;
                if bits_left_in_chunk == 0 {
                    current_bit += 1;
                    continue;
                }
    
                let bits_left_in_extract = end_bit - current_bit + 1;
                if bits_left_in_extract == 0 {
                    break;
                }
    
                let bits_to_take = std::cmp::min(bits_left_in_chunk, bits_left_in_extract);
    
                let chunk = values.get(chunk_index).copied().unwrap_or(0);
    
                let mask = Self::safe_left_mask(bits_to_take) << bit_in_chunk;
                let bits = Self::safe_shift_right(chunk & mask, bit_in_chunk);
    
                let result_index = (bit_pos / 64) as usize;
                let result_bit_offset = bit_pos % 64;
    
                if result_bit_offset + bits_to_take <= 64 {
                    // All bits fit within current u64
                    result[result_index] |= Self::safe_shift_left(bits, result_bit_offset);
                } else {
                    // Bits span across two u64s
                    let bits_in_current = 64 - result_bit_offset;
    
                    let bits_in_current_mask = Self::safe_left_mask(bits_in_current);
                    result[result_index] |= Self::safe_shift_left(bits & bits_in_current_mask, result_bit_offset);
                    result[result_index + 1] |= Self::safe_shift_right(bits, bits_in_current);
                }
    
                current_bit += bits_to_take;
                bit_pos += bits_to_take;
            }
    
            ConcreteVar::LargeInt(result)
        }
    }        

    // Function to extract bits from a large symbolic value (Vec<BV<'ctx>>), returns SymbolicVar
    pub fn extract_symbolic_bits_from_large_int(ctx: &'ctx Context, bvs: &[BV<'ctx>], start_bit: u64, end_bit: u64) -> SymbolicVar<'ctx> {
            if start_bit > end_bit {
                // Invalid range, return zero
                return SymbolicVar::Int(BV::from_u64(ctx, 0, 1));
            }
        
            let total_bits = (end_bit - start_bit + 1) as u32;
            if total_bits <= 64 {
                let mut result_bv = BV::from_u64(ctx, 0, total_bits);
                let mut current_bit = start_bit;
                let mut result_bit_pos = 0u32;
        
                while current_bit <= end_bit {
                    let chunk_index = (current_bit / 64) as usize;
                    let bit_in_chunk = (current_bit % 64) as u32;
        
                    let bits_left_in_chunk = 64 - bit_in_chunk;
                    if bits_left_in_chunk == 0 {
                        current_bit += 1;
                        continue;
                    }
        
                    let bits_left_in_extract = (end_bit - current_bit + 1) as u32;
                    if bits_left_in_extract == 0 {
                        break;
                    }
        
                    let bits_to_take = std::cmp::min(bits_left_in_chunk, bits_left_in_extract);
        
                    let bv_chunk = bvs
                        .get(chunk_index)
                        .cloned()
                        .unwrap_or_else(|| BV::from_u64(ctx, 0, 64));
        
                    let extracted_bv = bv_chunk.extract(bit_in_chunk + bits_to_take - 1, bit_in_chunk).simplify();
        
                    let shifted_extracted_bv = if result_bit_pos > 0 {
                        extracted_bv
                            .zero_ext(total_bits - bits_to_take - result_bit_pos)
                            .bvshl(&BV::from_u64(ctx, result_bit_pos as u64, total_bits))
                            .simplify()
                    } else {
                        extracted_bv.zero_ext(total_bits - bits_to_take).simplify()
                    };
        
                    result_bv = result_bv.bvor(&shifted_extracted_bv).simplify();
        
                    current_bit += bits_to_take as u64;
                    result_bit_pos += bits_to_take;
                }
        
                SymbolicVar::Int(result_bv)
            } else {
                // Extract into a Vec<BV<'ctx>>
                let num_bvs = ((total_bits + 63) / 64) as usize;
                let mut result_bvs = vec![BV::from_u64(ctx, 0, 64); num_bvs];
                let mut current_bit = start_bit;
                let mut result_bit_pos = 0u64;
        
                while current_bit <= end_bit {
                    let chunk_index = (current_bit / 64) as usize;
                    let bit_in_chunk = (current_bit % 64) as u32;
        
                    let bits_left_in_chunk = 64 - bit_in_chunk;
                    if bits_left_in_chunk == 0 {
                        current_bit += 1;
                        continue;
                    }
        
                    let bits_left_in_extract = end_bit - current_bit + 1;
                    if bits_left_in_extract == 0 {
                        break;
                    }
        
                    let bits_to_take = std::cmp::min(bits_left_in_chunk as u64, bits_left_in_extract);
        
                    let bits_to_take_u32 = bits_to_take as u32;
        
                    let bv_chunk = bvs
                        .get(chunk_index)
                        .cloned()
                        .unwrap_or_else(|| BV::from_u64(ctx, 0, 64));
        
                    let extracted_bv = bv_chunk.extract(bit_in_chunk + bits_to_take_u32 - 1, bit_in_chunk).simplify();
        
                    let result_index = (result_bit_pos / 64) as usize;
                    let result_bit_offset = (result_bit_pos % 64) as u32;
        
                    if result_bit_offset + bits_to_take_u32 <= 64 {
                        // All bits fit within current BV
                        let shifted_extracted_bv = if result_bit_offset > 0 {
                            extracted_bv
                                .zero_ext(64 - bits_to_take_u32 - result_bit_offset)
                                .bvshl(&BV::from_u64(ctx, result_bit_offset as u64, 64))
                                .simplify()
                        } else {
                            extracted_bv.zero_ext(64 - bits_to_take_u32).simplify()
                        };
        
                        result_bvs[result_index] = result_bvs[result_index].bvor(&shifted_extracted_bv).simplify();
                    } else {
                        // Bits span across two BVs
                        let bits_in_current = 64 - result_bit_offset;
                        let bits_in_current_u32 = bits_in_current as u32;
        
                        let extracted_bv_current = extracted_bv.extract(bits_in_current_u32 - 1, 0).simplify();
        
                        let extracted_bv_next = extracted_bv.extract(bits_to_take_u32 - 1, bits_in_current_u32).simplify();
        
                        let shifted_extracted_bv_current = if result_bit_offset > 0 {
                            extracted_bv_current
                                .zero_ext(64 - bits_in_current_u32 - result_bit_offset)
                                .bvshl(&BV::from_u64(ctx, result_bit_offset as u64, 64))
                                .simplify()
                        } else {
                            extracted_bv_current.zero_ext(64 - bits_in_current_u32).simplify()
                        };
        
                        result_bvs[result_index] = result_bvs[result_index].bvor(&shifted_extracted_bv_current).simplify();
        
                        result_bvs[result_index + 1] = result_bvs[result_index + 1].bvor(&extracted_bv_next).simplify();
                    }
        
                    current_bit += bits_to_take;
                    result_bit_pos += bits_to_take;
                }
        
                SymbolicVar::LargeInt(result_bvs)
            }
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