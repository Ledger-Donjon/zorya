use core::str;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::io::Write;
use std::process::Command;
use std::sync::MutexGuard;
use std::process;

use crate::state::cpu_state::CpuConcolicValue;
use crate::state::memory_x86_64::MemoryValue;
use crate::state::state_manager::FunctionFrame;
use crate::state::state_manager::Logger;
use crate::state::CpuState;
use crate::state::State;
use goblin::elf;
use goblin::elf::sym::STT_FUNC;
use goblin::elf::Elf;
use parser::parser::{Inst, Opcode, Var, Varnode};
use serde::Deserialize;
use z3::ast::Ast;
use z3::ast::Bool;
use z3::ast::BV;
use z3::{Context, Solver};
use crate::concolic::ConcolicVar;
use super::executor_bool;
use super::executor_callother;
use super::executor_float;
use super::executor_int;
use super::ConcolicEnum;
pub use super::ConcreteVar;
pub use super::SymbolicVar;

macro_rules! log {
    ($logger:expr, $($arg:tt)*) => {{
        writeln!($logger, $($arg)*).unwrap();
    }};
}

#[derive(Clone, Debug)]
pub struct ConcolicExecutor<'ctx> {
    pub context: &'ctx Context,
    pub solver: Solver<'ctx>,
    pub state: State<'ctx>,
    pub current_address: Option<u64>,
    pub symbol_table: BTreeMap<String, String>,
    pub instruction_counter: usize,
    pub unique_variables: BTreeMap<String, ConcolicVar<'ctx>>, // Stores unique variables and their values
    pub pcode_internal_lines_to_be_jumped: i64, // known line number of the current instruction in the pcode file, usefull for branch instructions
    pub initialiazed_var : BTreeMap<String, u64>, // check if the variable has been initialized before using it
    pub inside_jump_table: bool, // check if the current instruction is handling a jump table
    pub trace_logger: Logger,
}

impl<'ctx> ConcolicExecutor<'ctx> {
    pub fn new(context: &'ctx Context, logger: Logger, trace_logger: Logger) -> Result<Self, Box<dyn Error>> {
        let solver = Solver::new(context);
        let state = State::new(context, logger)?;
        Ok(ConcolicExecutor {
            context,
            solver,
            state,
            symbol_table: BTreeMap::new(),
            current_address: None,
            instruction_counter: 0,
            unique_variables: BTreeMap::new(),
            pcode_internal_lines_to_be_jumped: 0, // number of lines to skip in case of branch instructions
            initialiazed_var: BTreeMap::new(),
            inside_jump_table: false,
            trace_logger,
         })
    }

    pub fn populate_symbol_table(&mut self, elf_data: &[u8]) -> Result<(), goblin::error::Error> {
        let elf = Elf::parse(elf_data)?;
    
        // Populate static function symbols from the symbol table
        for sym in &elf.syms {
            if goblin::elf::sym::st_type(sym.st_info) == goblin::elf::sym::STT_FUNC {
                if let Some(name) = elf.strtab.get_at(sym.st_name) {
                    let address_hex = format!("{:x}", sym.st_value);
                    self.symbol_table.insert(address_hex, name.to_string());
                }
            }
        }
    
        // Populate dynamic function symbols from the dynamic symbol table
        for dynsym in &elf.dynsyms {
            if goblin::elf::sym::st_type(dynsym.st_info) == goblin::elf::sym::STT_FUNC {
                if let Some(name) = elf.dynstrtab.get_at(dynsym.st_name) {
                    let address_hex = format!("{:x}", dynsym.st_value);
                    self.symbol_table.insert(address_hex, name.to_string());
                }
            }
        }
    
        // Resolve .plt section entries if present
        if let Some(plt_section) = elf.section_headers.iter().find(|section| {
            if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
                name == ".plt"
            } else {
                false
            }
        }) {
            let plt_start = plt_section.sh_addr;
            let plt_size = plt_section.sh_size;
            let plt_end = plt_start + plt_size;
    
            // Process each address in .plt section
            for addr in (plt_start..plt_end).step_by(16) {
                // Check if this address is already resolved
                if let Some(symbol_name) = self.symbol_table.get(&format!("{:x}", addr)) {
                    continue; // Skip if already resolved
                }
    
                // Try resolving via GOT
                if let Some(external_name) = self.resolve_got_function(&elf, addr) {
                    self.symbol_table
                        .insert(format!("{:x}", addr), format!("plt_{}", external_name));
                } else {
                    // Fallback to synthetic naming if unresolved
                    self.symbol_table.insert(
                        format!("{:x}", addr),
                        format!("plt_function_{:x}", addr),
                    );
                }
            }
        }
    
        Ok(())
    }
    
    // Helper function to resolve function names via GOT
    fn resolve_got_function(&mut self, elf: &Elf, plt_addr: u64) -> Option<String> {
        // Look for GOT entries that are referenced by the dynamic symbol table
        for dynsym in &elf.dynsyms {
            if let Some(name) = elf.dynstrtab.get_at(dynsym.st_name) {
                if dynsym.st_value == plt_addr {
                    return Some(name.to_string());
                }
            }
        }
    
        // If no direct match is found, attempt to find corresponding GOT address
        if let Some(got_section) = elf.section_headers.iter().find(|section| {
            if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
                name == ".got.plt" || name == ".got"
            } else {
                false
            }
        }) {
            let got_start = got_section.sh_addr;
            let got_end = got_start + got_section.sh_size;
    
            for addr in (got_start..got_end).step_by(8) {
                if addr == plt_addr {
                    // Attempt to match the GOT entry with a dynamic symbol
                    for dynsym in &elf.dynsyms {
                        if dynsym.st_value == addr {
                            if let Some(name) = elf.dynstrtab.get_at(dynsym.st_name) {
                                return Some(name.to_string());
                            }
                        }
                    }
                }
            }
        }
    
        None // Could not resolve
    }    
    
    pub fn execute_instruction(&mut self, instruction: Inst, current_addr: u64, next_addr_in_map: u64, next_inst: &Inst, instructions_map: &BTreeMap<u64, Vec<Inst>>) -> Result<(), String> {
        // Convert current_addr to hexadecimal string to match with symbol table keys
        let current_addr_hex = format!("{:x}", current_addr);
        
        // Check if we are processing a new address block
        if Some(current_addr) != self.current_address {
            // Reset the unique variables for the new address
            self.unique_variables.clear();

            // Update the current address
            self.current_address = Some(current_addr);
            // Reset the instruction counter for the new address
            self.instruction_counter = 1; // Start counting from 1 for each address block

            // Check if the current address corresponds to the "runtime.nilPanic" function
            if let Some(symbol_name) = self.symbol_table.get(&current_addr_hex) {
                if symbol_name == "runtime.nilPanic" {
                    log!(self.state.logger.clone(), "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                    log!(self.state.logger.clone(), "Attempt to execute 'runtime.nilPanic' detected at address 0x{}.", current_addr_hex);
                    log!(self.state.logger.clone(), "You are trying to dereference a nil pointer.");
                    log!(self.state.logger.clone(), "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                    process::exit(0);
                }
                if symbol_name == "runtime.nilMapPanic" {
                    log!(self.state.logger.clone(), "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                    log!(self.state.logger.clone(), "Attempt to execute 'runtime.nilMapPanic' detected at address 0x{}.", current_addr_hex);
                    log!(self.state.logger.clone(), "You are trying to add an entry to a nil map.");
                    log!(self.state.logger.clone(), "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                    process::exit(0);
                }
                if symbol_name == "runtime._panic" {
                    log!(self.state.logger.clone(), "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                    log!(self.state.logger.clone(), "Attempt to execute 'runtime._panic' detected at address 0x{}.", current_addr_hex);
                    log!(self.state.logger.clone(), "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                    process::exit(0);
                }
                if symbol_name == "runtime.recordForPanic" {
                    log!(self.state.logger.clone(), "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                    log!(self.state.logger.clone(), "Attempt to execute 'runtime.recordForPanic' detected at address 0x{}.", current_addr_hex);
                    log!(self.state.logger.clone(), "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                    process::exit(0);
                }
                if symbol_name == "runtime.slicePanic" {
                    log!(self.state.logger.clone(), "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                    log!(self.state.logger.clone(), "Attempt to execute 'runtime.slicePanic' detected at address 0x{}.", current_addr_hex);
                    log!(self.state.logger.clone(), "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                    process::exit(0);
                }
                if symbol_name == "runtime.lookupPanic" {
                    log!(self.state.logger.clone(), "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                    log!(self.state.logger.clone(), "Attempt to execute 'runtime.lookupPanic' detected at address 0x{}.", current_addr_hex);
                    log!(self.state.logger.clone(), "You are trying to access an array or slice out of bounds.");
                    log!(self.state.logger.clone(), "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                    process::exit(0);
                }
                if symbol_name == "runtime.runtimePanic" {
                    log!(self.state.logger.clone(), "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                    log!(self.state.logger.clone(), "Attempt to execute 'runtime.runtimePanic' detected at address 0x{}.", current_addr_hex);
                    log!(self.state.logger.clone(), "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                    process::exit(0);
                }
                if symbol_name == "runtime.chanMakePanic" {
                    log!(self.state.logger.clone(), "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                    log!(self.state.logger.clone(), "Attempt to execute 'runtime.chanMakePanic' detected at address 0x{}.", current_addr_hex);
                    log!(self.state.logger.clone(), "You are trying to create a new channel that is too big.");
                    log!(self.state.logger.clone(), "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                    process::exit(0);
                }
                if symbol_name == "runtime.negativeShiftPanic" {
                    log!(self.state.logger.clone(), "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                    log!(self.state.logger.clone(), "Attempt to execute 'runtime.negativeShiftPanic' detected at address 0x{}.", current_addr_hex);
                    log!(self.state.logger.clone(), "The shift value is negative.");
                    log!(self.state.logger.clone(), "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                    process::exit(0);
                }
            }
        } else {
            // Same address block, increment the instruction counter
            self.instruction_counter += 1;
        }

        match instruction.opcode {
            Opcode::Blank => panic!("Opcode Blank is not implemented yet"),
            Opcode::Branch => self.handle_branch(instruction), // unconditional jump to a specified address
            Opcode::BranchInd => self.handle_branchind(instruction),
            Opcode::Build => panic!("Opcode Build is not implemented yet"),
            Opcode::Call => self.handle_call(instruction), // function call, semantically similar to a branch but represents execution flow transferring to a subroutine
            Opcode::CallInd => self.handle_callind(instruction), // indirect call to a dynamically determined address
            Opcode::Ceil => panic!("Opcode Ceil is not implemented yet"),
            Opcode::CBranch => self.handle_cbranch(instruction, next_addr_in_map), // adds a condition to the jump
            Opcode::Copy => self.handle_copy(instruction),
            Opcode::CPoolRef => panic!("Opcode CPoolRef is not implemented yet"), // returns runtime-dependent values from the constant pool
            Opcode::CrossBuild => panic!("Opcode CrossBuild is not implemented yet"),
            Opcode::DelaySlot => panic!("Opcode DelaySlot is not implemented yet"),
            Opcode::Label => panic!("Opcode Label is not implemented yet"),
            Opcode::Load => self.handle_load(instruction, next_inst, instructions_map),
            Opcode::LZCount => panic!("Opcode LZCount is not implemented yet"), //self.handle_lzcount(instruction),
            Opcode::New => panic!("Opcode New is not implemented yet"), // allocates memory for an object and returns a pointer to that memory
            Opcode::Piece => panic!("Opcode Piece is not implemented yet"), // concatenation operation that combines two inputs
            Opcode::PopCount => self.handle_popcount(instruction),
            Opcode::Return => self.handle_return(instruction), // indicates a return from a subroutine
            Opcode::Round => panic!("Opcode Round is not implemented yet"),
            Opcode::SegmentOp => panic!("Opcode SegmentOp is not implemented yet"),
            Opcode::Store => self.handle_store(instruction),
            Opcode::SubPiece => self.handle_subpiece(instruction),
            Opcode::Trunc => panic!("Opcode Trunc is not implemented yet"),
            Opcode::Unused1 => panic!("Opcode Unused1 is not implemented yet"),
            
            // Check executor_bool.rs for functions' implementations
            Opcode::BoolAnd => executor_bool::handle_bool_and(self, instruction),
            Opcode::BoolNegate => executor_bool::handle_bool_negate(self, instruction),
            Opcode::BoolOr => executor_bool::handle_bool_or(self, instruction),
            Opcode::BoolXor => executor_bool::handle_bool_xor(self, instruction),
            
            // Check executor_callother.rs for functions' implementations
            Opcode::CallOther => executor_callother::handle_callother(self, instruction),
            
            // Check executor_float.rs for functions' implementations
            Opcode::Float2Float => panic!("Opcode is not implemented yet"), //executor_float::handle_float2float(self, instruction),
            Opcode::FloatAbs => panic!("Opcode is not implemented yet"), //executor_float::handle_float_abs(self, instruction),
            Opcode::FloatAdd => panic!("Opcode is not implemented yet"), //executor_float::handle_float_add(self, instruction),
            Opcode::FloatDiv => panic!("Opcode is not implemented yet"), //executor_float::handle_float_div(self, instruction),
            Opcode::FloatEqual => executor_float::handle_float_equal(self, instruction),
            Opcode::FloatLess => executor_float::handle_float_less(self, instruction),
            Opcode::FloatLessEqual => panic!("Opcode is not implemented yet"), //executor_float::handle_float_lessequal(self, instruction),
            Opcode::FloatMult => panic!("Opcode is not implemented yet"), //executor_float::handle_float_mult(self, instruction),
            Opcode::FloatNaN => executor_float::handle_float_nan(self, instruction),
            Opcode::FloatNeg => panic!("Opcode is not implemented yet"), //executor_float::handle_float_neg(self, instruction),
            Opcode::FloatNotEqual => panic!("Opcode is not implemented yet"), //executor_float::handle_float_notequal(self, instruction),
            Opcode::FloatSqrt => panic!("Opcode is not implemented yet"), //executor_float::handle_float_sqrt(self, instruction),
            Opcode::FloatSub => panic!("Opcode is not implemented yet"), //executor_float::handle_float_sub(self, instruction),
            Opcode::FloatFloor => panic!("Opcode is not implemented yet"), //executor_float::handle_float_floor(self, instruction),

            // Check executor_int.rs for functions' implementations
            Opcode::Int2Comp => executor_int::handle_int_2comp(self, instruction),
            Opcode::Int2Float => executor_int::handle_int2float(self, instruction),
            Opcode::IntAdd => executor_int::handle_int_add(self, instruction),
            Opcode::IntAnd => executor_int::handle_int_and(self, instruction),
            Opcode::IntCarry => executor_int::handle_int_carry(self, instruction),
            Opcode::IntDiv => executor_int::handle_int_div(self, instruction),
            Opcode::IntEqual => executor_int::handle_int_equal(self, instruction),
            Opcode::IntLeft => executor_int::handle_int_left(self, instruction),
            Opcode::IntLess => executor_int::handle_int_less(self, instruction),
            Opcode::IntLessEqual => executor_int::handle_int_lessequal(self, instruction),
            Opcode::IntMult => executor_int::handle_int_mult(self, instruction),
            Opcode::IntNegate => executor_int::handle_int_negate(self, instruction),
            Opcode::IntNotEqual => executor_int::handle_int_notequal(self, instruction),
            Opcode::IntOr => executor_int::handle_int_or(self, instruction),
            Opcode::IntRem => executor_int::handle_int_rem(self, instruction),
            Opcode::IntRight => executor_int::handle_int_right(self, instruction),
            Opcode::IntSDiv => executor_int::handle_int_sdiv(self, instruction),
            Opcode::IntSExt => executor_int::handle_int_sext(self, instruction),
            Opcode::IntSCarry => executor_int::handle_int_scarry(self, instruction),
            Opcode::IntSBorrow => executor_int::handle_int_sborrow(self, instruction),
            Opcode::IntSRem => executor_int::handle_int_srem(self, instruction),
            Opcode::IntSLess => executor_int::handle_int_sless(self, instruction),
            Opcode::IntSLessEqual => executor_int::handle_int_slessequal(self, instruction),
            Opcode::IntSRight => executor_int::handle_int_sright(self, instruction),
            Opcode::IntSub => executor_int::handle_int_sub(self, instruction),
            Opcode::IntXor => executor_int::handle_int_xor(self, instruction),
            Opcode::IntZExt => executor_int::handle_int_zext(self, instruction),
        }?;
        Ok(())
    }

    // Transform the varnode.var into a concolic object in zorya
    pub fn varnode_to_concolic(&mut self, varnode: &Varnode) -> Result<ConcolicEnum<'ctx>, String> {
        let cpu_state_guard = self.state.cpu_state.lock().unwrap();
    
        log!(self.state.logger.clone(), "Converting Varnode to concolic type: {:?}", varnode.var);
    
        let bit_size = varnode.size.to_bitvector_size() as u32; // size in bits
        match &varnode.var {
            Var::Register(offset, _) => {
                log!(self.state.logger.clone(), "Varnode is a CPU register with offset: 0x{:x} and requested bit size: {}", offset, bit_size);
    
                if let Some(&(ref _name, reg_size)) = cpu_state_guard.register_map.get(offset) {
                    if reg_size == bit_size {
                        log!(self.state.logger.clone(), "Directly processing register found in register_map with matching size at offset 0x{:x}", offset);
                        let cpu_concolic_value = cpu_state_guard.get_register_by_offset(*offset, reg_size)
                            .ok_or_else(|| format!("Failed to retrieve register by offset 0x{:x}", offset))?;
                        Ok(ConcolicEnum::CpuConcolicValue(cpu_concolic_value))
                    } else {
                        log!(self.state.logger.clone(), "Register at offset 0x{:x} exists but with size {} bits, needs {} bits, extraction needed", offset, reg_size, bit_size);
                        self.extract_and_create_concolic_value(&cpu_state_guard, *offset, bit_size)
                    }
                } else {
                    log!(self.state.logger.clone(), "No direct register match found at offset 0x{:x}, extraction required", offset);
                    self.extract_and_create_concolic_value(&cpu_state_guard, *offset, bit_size)
                }
            },
            Var::Unique(id) => {
                log!(self.state.logger.clone(), "Varnode is of type 'unique' with ID: 0x{:x}", id);
                let unique_name = format!("Unique(0x{:x})", id);
    
                let unique_var = self.unique_variables.entry(unique_name.clone()).or_insert_with(|| {
                    log!(self.state.logger.clone(), "Initializing new Unique variable '{}'", unique_name);
                    
                    if bit_size == 1 {
                        ConcolicVar {
                            concrete: ConcreteVar::Bool(false),
                            symbolic: SymbolicVar::Bool(Bool::from_bool(self.context, false)),
                            ctx: self.context,
                        }
                    } else if bit_size > 64 {
                        let symbolic_values = vec![BV::from_u64(self.context, 0, 64); ((bit_size + 63) / 64).try_into().unwrap()];
                        let mut combined_bv = symbolic_values[0].clone();
                        for i in 1..symbolic_values.len() {
                            combined_bv = symbolic_values[i].concat(&combined_bv);
                        }
                        ConcolicVar {
                            concrete: ConcreteVar::LargeInt(vec![0; ((bit_size + 63) / 64).try_into().unwrap()]),
                            symbolic: SymbolicVar::LargeInt(symbolic_values),
                            ctx: self.context,
                        }
                    } else {
                        ConcolicVar {
                            concrete: ConcreteVar::Int(0),
                            symbolic: SymbolicVar::Int(BV::from_u64(self.context, 0, bit_size)),
                            ctx: self.context,
                        }
                    }
                });
    
                // Ensure Correct Symbolic Type
                let final_symbolic = match &unique_var.symbolic {
                    SymbolicVar::Bool(b) => SymbolicVar::Bool(b.clone()),  // Ensure boolean stays boolean
                    SymbolicVar::Int(bv) => SymbolicVar::Int(bv.clone()),
                    SymbolicVar::LargeInt(bv_vec) => {
                        if bit_size <= 64 {
                            SymbolicVar::Int(bv_vec[0].clone())
                        } else {
                            let mut combined_bv = bv_vec[0].clone();
                            for i in 1..bv_vec.len() {
                                combined_bv = bv_vec[i].concat(&combined_bv); // high <- low (little endian)
                            }
                            SymbolicVar::LargeInt(vec![combined_bv])
                        }
                    }                    
                    _ => return Err("Unexpected symbolic type for Unique variable".to_string()),
                };
    
                let final_var = ConcolicVar {
                    concrete: unique_var.concrete.clone(),
                    symbolic: final_symbolic,
                    ctx: self.context,
                };
    
                log!(self.state.logger.clone(), "Retrieved unique variable: {:?} with symbolic size: {}", final_var.concrete, bit_size);
                Ok(ConcolicEnum::ConcolicVar(final_var))
            },
            Var::Const(value) => {
                log!(self.state.logger.clone(), "Varnode is a constant with value: {}", value);
                // First, parse the constant as an unsigned 64-bit value.
                let parsed_value_u64 = if value.starts_with("0x") {
                    u64::from_str_radix(&value[2..], 16)
                } else {
                    value.parse::<u64>()
                }.map_err(|e| format!("Failed to parse value '{}' as u64: {}", value, e))?;
                
                // Interpret the parsed value as signed, based on the requested bit size.
                let parsed_value: i64 = if bit_size < 64 {
                    // For example, if bit_size is 32, then the sign bit is 1 << 31.
                    let sign_bit = 1u64 << (bit_size - 1);
                    let mask = (1u64 << bit_size) - 1;
                    let x = parsed_value_u64 & mask;
                    if x & sign_bit != 0 {
                        // Negative value: subtract 1 << bit_size
                        (x as i64) - ((1u64 << bit_size) as i64)
                    } else {
                        x as i64
                    }
                } else {
                    // For 64 bits, we assume the value is already in two's complement form.
                    parsed_value_u64 as i64
                };
                
                log!(self.state.logger.clone(), "Parsed value (signed): {}", parsed_value);
                
                // For the concrete part, we want to keep the bit pattern in the proper width.
                // For sizes <64, we re-encode the signed value as two's complement in bit_size bits.
                let concrete_val = if bit_size < 64 {
                    let mask = (1u64 << bit_size) - 1;
                    if parsed_value < 0 {
                        ((parsed_value + (1 << bit_size)) as u64) & mask
                    } else {
                        (parsed_value as u64) & mask
                    }
                } else {
                    parsed_value_u64
                };
                
                // Build the symbolic value using BV::from_i64 (which takes a signed i64)
                let parsed_value_symbolic = BV::from_i64(self.context, parsed_value, bit_size);
                
                let mem_value = MemoryValue {
                    concrete: concrete_val,
                    symbolic: parsed_value_symbolic,
                    size: bit_size,
                };
                
                log!(self.state.logger.clone(), 
                     "Constant treated as memory value: {:?} with symbolic size {:?}", 
                     mem_value.concrete, mem_value.symbolic.get_size());
                Ok(ConcolicEnum::MemoryValue(mem_value))
            }                 
            Var::MemoryRam => {
                log!(self.state.logger.clone(), "Varnode is MemoryRam");
                // Assuming MemoryRam represents general memory starting at address 0
                // let mem_value = self.state.memory.read_value(0, bit_size)
                //     .map_err(|e| format!("Failed to read MemoryRam: {:?}", e))?;
                //log!(self.state.logger.clone(), "MemoryRam treated as general memory space, retrieved: {:?}", mem_value.concrete);
                Ok(ConcolicEnum::MemoryValue(MemoryValue {
                    concrete: 0,
                    symbolic: BV::new_const(self.context, "MemoryRam", bit_size),
                    size: bit_size,
                }))
            },
            Var::Memory(addr) => {
                log!(self.state.logger.clone(), "Varnode is a specific memory address: 0x{:x}", addr);
    
                // Read the value from memory
                let mem_value = self.state.memory.read_value(*addr, bit_size)
                    .map_err(|e| format!("Failed to read memory at address 0x{:x}: {:?}", addr, e))?;
    
                log!(self.state.logger.clone(), "Retrieved memory value: {:x} with symbolic size: {:?}", mem_value.concrete, mem_value.symbolic.get_size());
                // The type is ConcolicVar because the memory value can be a large integer so MemoryValue type is not enough
                Ok(ConcolicEnum::ConcolicVar(mem_value))
            },
        }
    }     

    // Extracts a value from a register and creates a new concolic value
    fn extract_and_create_concolic_value(&self, cpu_state_guard: &MutexGuard<'_, CpuState<'ctx>>, offset: u64, bit_size: u32) -> Result<ConcolicEnum<'ctx>, String> {
        let closest_register = cpu_state_guard
            .register_map
            .range(..=offset)
            .rev()
            .next()
            .ok_or(format!("No register found before offset 0x{:x}", offset))?;
        let (base_register_offset, &(_, register_size)) = closest_register;
        log!(self.state.logger.clone(), "Closest register found at offset 0x{:x} with size {}", base_register_offset, register_size);
    
        let bit_offset = (offset - base_register_offset) * 8; // Calculate the bit offset within the register
    
        if bit_offset + u64::from(bit_size) > u64::from(register_size) {
            return Err(format!(
                "Attempted to extract beyond the register's limit at offset 0x{:x}. Total bits requested: {}",
                offset,
                bit_offset + u64::from(bit_size)
            ));
        }
    
        let original_register = cpu_state_guard
            .get_register_by_offset(*base_register_offset, register_size)
            .ok_or_else(|| {
                format!(
                    "Failed to retrieve register for extraction at offset 0x{:x}",
                    base_register_offset
                )
            })?;
    
        match &original_register.concrete {
            ConcreteVar::Int(value) => {
                // Handle the concrete extraction
                let mask: u64 = if bit_size < 64 {
                    (1u64 << bit_size) - 1
                } else {
                    u64::MAX
                };
                let extracted_value = (*value >> bit_offset) & mask;
    
                // Symbolic extraction explicitly simplified
                let symbolic_bv = original_register.symbolic.to_bv(&cpu_state_guard.ctx);
                let high_bit = (bit_offset + u64::from(bit_size) - 1) as u32;
                let low_bit = bit_offset as u32;

                let extracted_symbolic = symbolic_bv
                    .extract(high_bit, low_bit)
                    .simplify(); 

                if extracted_symbolic.get_z3_ast().is_null() {
                    return Err("Symbolic extraction resulted in an invalid state".to_string());
                } 
    
                Ok(ConcolicEnum::CpuConcolicValue(CpuConcolicValue {
                    concrete: ConcreteVar::Int(extracted_value),
                    symbolic: SymbolicVar::Int(extracted_symbolic),
                    ctx: cpu_state_guard.ctx,
                }))
            }
            ConcreteVar::LargeInt(values) => {
                // Handle the concrete extraction from LargeInt
                let start_bit = bit_offset;
                let end_bit = start_bit + u64::from(bit_size) - 1;
                let extracted_concrete = CpuState::extract_bits_from_large_int(values, start_bit, end_bit);

                // Use extract_symbolic_bits_from_large_int to extract the symbolic value
                if let SymbolicVar::LargeInt(ref bvs) = original_register.symbolic {
                    let extracted_symbolic = CpuState::extract_symbolic_bits_from_large_int(
                        &cpu_state_guard.ctx,
                        bvs,
                        start_bit,
                        end_bit,
                    )
                    .simplify();

                    Ok(ConcolicEnum::CpuConcolicValue(CpuConcolicValue {
                        concrete: extracted_concrete,
                        symbolic: extracted_symbolic,
                        ctx: cpu_state_guard.ctx,
                    }))
                } else {
                    return Err("Expected LargeInt symbolic variable".to_string());
                }
            }
            _ => Err("Unsupported concrete variable type for extraction".to_string()),
        }
    }    
    
    pub fn handle_output(&mut self, output_varnode: Option<&Varnode>, result_value: ConcolicVar<'ctx>) -> Result<(), String> {
        if let Some(varnode) = output_varnode {
            // Resize the result_value according to the output size specification
            let bit_size = varnode.size.to_bitvector_size() as u32; // size in bits
    
            match &varnode.var {
                Var::Unique(id) => {
                    log!(self.state.logger.clone(), "Writing {:x} to the unique variable with ID: 0x{:x}", result_value.concrete.to_u64(), id);
                    let unique_name = format!("Unique(0x{:x})", id);
                    self.unique_variables.insert(unique_name, result_value.clone());
                    log!(self.state.logger.clone(), "Updated unique variable: Unique(0x{:x}) with concrete part : {:x}, concrete size {} bits and symbolic size {} bits", id, result_value.concrete.to_u64(), bit_size, result_value.symbolic.get_size());
                    Ok(())
                }, 
                Var::Register(offset, _) => {
                    log!(self.state.logger.clone(), "Output is a Register type");
                    let mut cpu_state_guard = self.state.cpu_state.lock().unwrap();
    
                    match cpu_state_guard.set_register_value_by_offset(*offset, result_value.clone(), bit_size) {
                        Ok(_) => {
                            // check
                            let register = cpu_state_guard.get_register_by_offset(*offset, bit_size).unwrap();
                            log!(self.state.logger.clone(), "Updated register at offset 0x{:x} with concrete value 0x{:x}, concrete size {} bits and symbolic size {:?} bits", offset, register.concrete.to_u64(), bit_size, register.symbolic.get_size());
                            Ok(())
                        },
                        Err(e) => {
                            let error_msg = format!("Failed to update register at offset 0x{:x}: {}", offset, e);
                            log!(self.state.logger.clone(), "{}", error_msg);
                            Err(error_msg)
                        }
                    }
                },
                Var::Memory(addr) => {
                    log!(self.state.logger.clone(), "Output is a Memory type at address 0x{:x}", addr);
                    
                    // Extract concrete value
                    let concrete_value = result_value.concrete.to_u64();
    
                    // Extract symbolic value
                    let symbolic_bv = result_value.symbolic.to_bv(self.context);
    
                    // Ensure symbolic value size matches bit_size
                    let symbolic_size = symbolic_bv.get_size();
                    log!(self.state.logger.clone(), "symbolic_size: {}, bit_size: {}", symbolic_size, bit_size);
                    if symbolic_size != bit_size {
                        return Err(format!("Symbolic size {} does not match bit size {}", symbolic_size, bit_size));
                    }
    
                    // Create a MemoryValue
                    let mem_value = MemoryValue {
                        concrete: concrete_value,
                        symbolic: symbolic_bv.clone(),
                        size: bit_size,
                    };
    
                    // Write the MemoryValue to memory
                    match self.state.memory.write_value(*addr, &mem_value) {
                        Ok(_) => {
                            log!(self.state.logger.clone(), "Wrote value 0x{:x} to memory at address 0x{:x}, with symbolic part : {:?} and symbolic size {:?} bits", concrete_value, addr, symbolic_bv.simplify(), symbolic_size);
                            Ok(())
                        },
                        Err(e) => {
                            let error_msg = format!("Failed to write to memory at address 0x{:x}: {:?}", addr, e);
                            log!(self.state.logger.clone(), "{}", error_msg);
                            Err(error_msg)
                        }
                    }
                },                
                _ => {
                    let error_msg = "Output type is unsupported".to_string();
                    log!(self.state.logger.clone(), "{}", error_msg);
                    Err(error_msg)
                }
            }
        } else {
            Err("No output varnode specified".to_string())
        }
    }                                              
    
    // Handle branch operation
    pub fn handle_branch(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::Branch || instruction.inputs.len() != 1 {
            return Err("Invalid instruction format for BRANCH".to_string());
        }

        let branch_target_varnode = &instruction.inputs[0];
        log!(self.state.logger.clone(), "* Fetching branch target from instruction.input[0]");
        let branch_target_address = self.extract_branch_target_address(branch_target_varnode, instruction.clone())?;

        // Create concolic variable for branch target and update RIP register
        let symbolic_var = SymbolicVar::from_u64(&self.context, branch_target_address, 64).to_bv(&self.context);
        let branch_target_concolic = ConcolicVar::new_concrete_and_symbolic_int(branch_target_address, symbolic_var, &self.context, 64);
    
        // Update the instruction counter
        self.instruction_counter += 1;

        // Log the branch decision as a concolic variable for tracking
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}-{:02}-branch", current_addr_hex, self.instruction_counter);
        self.state.create_or_update_concolic_variable_int(&result_var_name, branch_target_address, branch_target_concolic.symbolic);

        Ok(())
    }

    // For BRANCHIND, CALLIND, BRANCH and CBRANCH instruction
    // However, this function is not used in handle_cbranch, but in mains.rs when doing checks related to CBRANCH instruction
    pub fn extract_branch_target_address(&mut self, varnode: &Varnode, instruction: Inst) -> Result<u64, String> {
        match &varnode.var {
            Var::Memory(addr) => {
                log!(self.state.logger.clone(), "Branch target is a specific memory address: 0x{:x}", addr);

                // Case when CALLIND * [ram]addr or BRANCHIND * [ram]addr (this is not documented in the doc...)
                let dereferenced_value = if instruction.opcode == Opcode::BranchInd || instruction.opcode == Opcode::CallInd {
                    // Dereference the memory address
                    // Read the value from memory
                    let mem_value = self.state.memory.read_value(*addr, varnode.size.to_bitvector_size())
                        .map_err(|e| format!("Failed to read memory at address 0x{:x}: {:?}", addr, e))?;
                    let dereferenced_value = ConcolicVar::new_from_memory_value(&mem_value.to_memory_value_u64());
                    dereferenced_value
                } else { // Case when BRANCH * [ram]addr (no need for a dereference) or CBRANCH * [ram]addr
                    // Return the memory address as is
                    let dereferenced_value = ConcolicVar::new_concrete_and_symbolic_int(*addr, SymbolicVar::from_u64(&self.context, *addr, 64).to_bv(&self.context), &self.context, 64);
                    dereferenced_value
                };
                
                // Update the RIP register to the new branch target address, except for Cbranch, where a check has to be done
                if instruction.opcode == Opcode::BranchInd || instruction.opcode == Opcode::CallInd || instruction.opcode == Opcode::Branch {
                    {
                        let mut cpu_state_guard = self.state.cpu_state.lock().unwrap();
                        cpu_state_guard.set_register_value_by_offset(0x288, dereferenced_value, 64)?;
                    }
                    log!(self.state.logger.clone(), "Branching to address 0x{:x}", addr);
                }                 

                Ok(*addr)
            },
            Var::Const(value) => {
                log!(self.state.logger.clone(), "Branch target is a constant value indicating the number of lines to jump: {:?}", value);
                // Parse as unsigned first.
                let parsed_value_u64 = if value.starts_with("0x") {
                    u64::from_str_radix(&value[2..], 16)
                } else {
                    value.parse::<u64>()
                }.map_err(|e| format!("Failed to parse value '{}' as u64: {}", value, e))?;
        
                // For a Word (32-bit) constant, manually sign-extend.
                let bit_size = varnode.size.to_bitvector_size(); // e.g. 32 for Word
                let parsed_value: i64 = if bit_size < 64 {
                    let sign_bit = 1u64 << (bit_size - 1);
                    let mask = (1u64 << bit_size) - 1;
                    let x = parsed_value_u64 & mask;
                    if x & sign_bit != 0 {
                        (x as i64) - ((1u64 << bit_size) as i64)
                    } else {
                        x as i64
                    }
                } else {
                    parsed_value_u64 as i64
                };
                log!(self.state.logger.clone(), "Parsed branch target (signed): {}", parsed_value);
        
                // Use the signed value for jumping (if a negative offset means to jump back).
                self.pcode_internal_lines_to_be_jumped = parsed_value;
        
                Ok(parsed_value as u64)
            },    
            Var::Register(offset, size) => {
                log!(self.state.logger.clone(), "Branch target is a Register at offset: 0x{:x} with size: {:?}", offset, size);
                
                // Validate that the register size matches the expected size
                let expected_bit_size = 64; // Assuming branch targets are 64-bit addresses; adjust if necessary
                if size.to_bitvector_size() != expected_bit_size {
                    return Err(format!(
                        "Unsupported register bit size for INT_SLESS: {}, expected {}",
                        size.to_bitvector_size(),
                        expected_bit_size
                    ));
                }
                
                // Retrieve the register's concrete and symbolic values
                let mut cpu_state_guard = self.state.cpu_state.lock().unwrap();
                let register_value = cpu_state_guard.get_register_by_offset(*offset, expected_bit_size)
                    .ok_or_else(|| format!("Failed to retrieve register by offset 0x{:x}", offset))?;
                
                let concrete_value = match register_value.concrete {
                    ConcreteVar::Int(val) => val,
                    _ => return Err(format!("Unsupported concrete type for register at offset 0x{:x}", offset)),
                };
                
                let symbolic_value = match &register_value.symbolic {
                    SymbolicVar::Int(bv) => bv.clone(),
                    _ => return Err(format!("Unsupported symbolic type for register at offset 0x{:x}", offset)),
                };
                
                // Update the RIP register with the branch target address
                {
                    cpu_state_guard.set_register_value_by_offset(
                        0x288, // Assuming RIP is at offset 0x288; adjust as per your architecture
                        ConcolicVar::new_concrete_and_symbolic_int(
                            concrete_value,
                            symbolic_value.clone(),
                            &self.context,
                            expected_bit_size,
                        ),
                        expected_bit_size,
                    )?;
                }
                
                log!(self.state.logger.clone(), "Branching to address 0x{:x} from register at offset 0x{:x}", concrete_value, offset);
                
                Ok(concrete_value)
            },
            Var::Unique(id) => {
                log!(self.state.logger.clone(), "Branch target is a unique variable with id: 0x{:x}", id);
                let unique_name = format!("Unique(0x{:x})", id);
                let unique_var = self.unique_variables.get(&unique_name)
                    .ok_or_else(|| format!("Failed to retrieve unique variable with id 0x{:x}", id))?;
                
                let concrete_value = match unique_var.concrete {
                    ConcreteVar::Int(val) => val,
                    _ => return Err(format!("Unsupported concrete type for unique variable with id 0x{:x}", id)),
                };
                
                let symbolic_value = match &unique_var.symbolic {
                    SymbolicVar::Int(bv) => bv.clone(),
                    _ => return Err(format!("Unsupported symbolic type for unique variable with id 0x{:x}", id)),
                };
                
                // Update the RIP register with the branch target address
                {
                    let mut cpu_state_guard = self.state.cpu_state.lock().unwrap();
                    cpu_state_guard.set_register_value_by_offset(
                        0x288, 
                        ConcolicVar::new_concrete_and_symbolic_int(
                            concrete_value,
                            symbolic_value.clone(),
                            &self.context,
                            64,
                        ),
                        64,
                    )?;
                }
                
                log!(self.state.logger.clone(), "Branching to address 0x{:x} from unique variable with id 0x{:x}", concrete_value, id);
                
                Ok(concrete_value)
            }
            _ => {
                Err(format!("Branch instruction does not support this variable type: {:?}", varnode.var))
            }
        }
    }

    // Handle indirect branch operation
    pub fn handle_branchind(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::BranchInd || instruction.inputs.len() != 1 {
            return Err("Invalid instruction format for BRANCHIND".to_string());
        }
    
        log!(self.state.logger.clone(), "* Fetching branch target from instruction.input[0]");
        let branch_target_varnode = &instruction.inputs[0];
        let branch_target_address = self.extract_branch_target_address(branch_target_varnode, instruction.clone())?;

        log!(self.state.logger.clone(), "Branching to address 0x{:x}", branch_target_address);
    
        // Create concolic variable for branch target and update RIP register
        let symbolic_var = SymbolicVar::from_u64(&self.context, branch_target_address, 64).to_bv(&self.context);
        let branch_target_concolic = ConcolicVar::new_concrete_and_symbolic_int(branch_target_address, symbolic_var, &self.context, 64);
    
        // Update the instruction counter
        self.instruction_counter += 1;
    
        // Log the branch decision as a concolic variable for tracking
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}-{:02}-branchind", current_addr_hex, self.instruction_counter);
        self.state.create_or_update_concolic_variable_int(&result_var_name, branch_target_address, branch_target_concolic.symbolic);
    
        Ok(())
    }    

    // Handle conditional branch operation
    pub fn handle_cbranch(&mut self, instruction: Inst, next_inst_in_map: u64) -> Result<(), String> {
        if instruction.opcode != Opcode::CBranch || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for CBRANCH".to_string());
        }
    
        // Fetch the branch target (input0)
        log!(self.state.logger.clone(), "* Fetching branch target from instruction.input[0]");
        let branch_target_varnode = &instruction.inputs[0];
    
        // Check if the branch target is a memory address or a constant
        match &branch_target_varnode.var {
            Var::Memory(addr) => {
                log!(self.state.logger.clone(), "Branch target is a specific memory address: 0x{:x}", addr);
        
                // Fetch the branch condition (input1)
                log!(self.state.logger.clone(), "* Fetching branch condition from instruction.input[1]");
                let branch_condition_concolic = self.varnode_to_concolic(&instruction.inputs[1])
                    .map_err(|e| e.to_string())?
                    .to_concolic_var()
                    .unwrap();
    
                // Extract a plain Rust bool from the concolic condition's concrete part
                let condition_concrete_bool = branch_condition_concolic.concrete.to_bool();
                log!(self.state.logger.clone(), "Branch condition concrete: {}", condition_concrete_bool);
    
                // Create symbolic BV values for the two potential RIP values (if condition true vs false)
                let rip1 = BV::from_u64(self.context, *addr, 64);
                let rip0 = BV::from_u64(self.context, next_inst_in_map, 64);
    
                // Build a Z3 Bool from the Rust bool
                let branch_condition_bool = Bool::from_bool(self.context, condition_concrete_bool);
                // Use the Bool's ite method to create an if-then-else expression over BVs
                let branch_condition_symbolic = branch_condition_bool.ite(&rip1, &rip0);
    
                // Decide which branch to take based on the plain bool
                let branch_target_concolic = if condition_concrete_bool {
                    log!(self.state.logger.clone(), "Branch condition is true, branching to address 0x{:x}", addr);
                    let mut cpu_state_guard = self.state.cpu_state.lock().unwrap();
                    let target = ConcolicVar::new_concrete_and_symbolic_int(*addr, branch_condition_symbolic, self.context, 64);
                    cpu_state_guard.set_register_value_by_offset(0x288, target.clone(), 64)
                        .map_err(|e| e.to_string())?;
                    log!(self.state.logger.clone(), "Updated RIP register with branch target: 0x{:x}", addr);
                    target
                } else {
                    log!(self.state.logger.clone(), "Branch condition is false, continuing to next instruction (0x{:x})", next_inst_in_map);
                    ConcolicVar::new_concrete_and_symbolic_int(next_inst_in_map, branch_condition_symbolic, self.context, 64)
                };
    
                // Create or update a concolic variable for logging/tracking the branch decision
                let current_addr_hex = self.current_address
                    .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
                let result_var_name = format!("{}-{:02}-cbranch", current_addr_hex, self.instruction_counter);
                self.state.create_or_update_concolic_variable_int(
                    &result_var_name,
                    branch_target_concolic.concrete.to_u64(),
                    branch_condition_concolic.symbolic
                );
            },
            Var::Const(value) => {
                // Log the value to be parsed
                log!(self.state.logger.clone(), "Attempting to parse branch target constant: {:?}", value);
                let value_string = value.to_string(); 
                let value_str = value_string.trim_start_matches("0x");
    
                // Attempt to parse the string as a hexadecimal number
                let value_u64 = match u64::from_str_radix(value_str, 16) {
                    Ok(parsed) => {
                        log!(self.state.logger.clone(), "Branch target is a constant: 0x{:x}, which means this is a sub instruction of a pcode instruction.", parsed);
                        parsed
                    },
                    Err(e) => {
                        log!(self.state.logger.clone(), "Failed to parse constant as u64: {:?}", e);
                        return Err(format!("Failed to parse constant as u64: {:?}", e));
                    }
                };
    
                // Fetch the branch condition (input1)
                log!(self.state.logger.clone(), "* Fetching branch condition from instruction.input[1]");
                let branch_condition_concolic = self.varnode_to_concolic(&instruction.inputs[1])
                    .map_err(|e| e.to_string())?
                    .to_concolic_var()
                    .unwrap();
    
                // Extract a plain Rust bool from the concolic condition's concrete part
                let condition_concrete_bool = branch_condition_concolic.concrete.to_bool();
                log!(self.state.logger.clone(), "Branch condition concrete: {}", condition_concrete_bool);
    
                // Create two BV values: 
                //  - rip0 for next_inst_in_map (condition false)
                //  - rip1 for value_u64 (condition true, i.e. "jump x lines")
                let rip0 = BV::from_u64(self.context, next_inst_in_map, 64);
                let rip1 = BV::from_u64(self.context, value_u64, 64);
    
                // Build a Z3 Bool from the Rust bool
                let branch_condition_bool = Bool::from_bool(self.context, condition_concrete_bool);
                // Create the ITE: if condition then rip1 else rip0
                let branch_condition_symbolic = branch_condition_bool.ite(&rip1, &rip0);
    
                // Check the condition
                let branch_target_concolic = if condition_concrete_bool {
                    log!(self.state.logger.clone(), "Branch condition is true, and because it is a sub-instruction, the execution jumps of {:x} lines.", value_u64);
                    // setting the number of lines to skip
                    self.pcode_internal_lines_to_be_jumped = value_u64 as i64;
                    ConcolicVar::new_concrete_and_symbolic_int(value_u64, branch_condition_symbolic, self.context, 64)
                } else {
                    log!(self.state.logger.clone(), "Branch condition is false, continuing to the next instruction.");
                    ConcolicVar::new_concrete_and_symbolic_int(next_inst_in_map, branch_condition_symbolic, self.context, 64)
                };
    
                // Create or update a concolic variable for logging/tracking
                let current_addr_hex = self.current_address
                    .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
                let result_var_name = format!("{}-{:02}-cbranch", current_addr_hex, self.instruction_counter);
                self.state.create_or_update_concolic_variable_int(
                    &result_var_name,
                    branch_target_concolic.concrete.to_u64(),
                    branch_condition_concolic.symbolic
                );
            },
            _ => {
                // For other Var types not handled by cbranch
                log!(self.state.logger.clone(), "Branch instruction doesn't handle this type of Var: {:?}", branch_target_varnode.var);
            }
        };
    
        // Update the instruction counter
        self.instruction_counter += 1;
    
        Ok(())
    }
    
    pub fn handle_call(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::Call || instruction.inputs.len() < 1 {
            return Err("Invalid instruction format for CALL".to_string());
        }

        // Push a new function frame onto the call stack
        self.push_function_frame();
    
        // Fetch the branch target (input0)
        // Fetch the data to be stored (treated as assembly address directly)
        log!(self.state.logger.clone(), "* Fetching data to store from instruction.input[0]");
        let data_to_call_varnode = &instruction.inputs[0];
        let data_to_call_concrete = match &data_to_call_varnode.var {
            Var::Memory(value) => {
                // Convert value to u64
                log!(self.state.logger.clone(), "Data to store is a constant with value: 0x{:x}", value);
                *value
            }
            _ => {
                let data_to_store_concolic = self.varnode_to_concolic(data_to_call_varnode).map_err(|e| e.to_string())?;
                data_to_store_concolic.get_concrete_value()
            }
        };
        let data_to_call_symbolic = BV::from_u64(self.context, data_to_call_concrete, 64);
        let data_to_call_concolic = ConcolicVar::new_concrete_and_symbolic_int(data_to_call_concrete, data_to_call_symbolic, self.context, 64);

        log!(self.state.logger.clone(), "Data to call: {:x}", data_to_call_concrete); 

        // Update the RIP register to the branch target address
        {
            let mut cpu_state_guard = self.state.cpu_state.lock().unwrap();
            cpu_state_guard.set_register_value_by_offset(0x288, data_to_call_concolic, 64).map_err(|e| e.to_string())?;
        }
        // Update the instruction counter
        self.instruction_counter += 1;

        // Create or update a concolic variable for the result (CALL doesn't produce a result, but we log the branch decision)
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}-{:02}-call", current_addr_hex, self.instruction_counter);
        self.state.create_or_update_concolic_variable_int(&result_var_name, data_to_call_concrete, SymbolicVar::Int(BV::from_u64(self.context, data_to_call_concrete, 64)));

        Ok(())
    } 
    
    pub fn handle_callind(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::CallInd || instruction.inputs.len() < 1 {
            return Err("Invalid instruction format for CALLIND".to_string());
        }
    
        // Fetch the target address from the first input
        log!(self.state.logger.clone(), "* Fetching target address from instruction.input[0]");
        let target_address_concolic = self.varnode_to_concolic(&instruction.inputs[0])
            .map_err(|e| e.to_string())?;
        let target_address_concrete = target_address_concolic.get_concrete_value();
        let target_address_symbolic = target_address_concolic.get_symbolic_value_bv(self.context);
    
        log!(self.state.logger.clone(), "Target address concrete: 0x{:x}", target_address_concrete);
    
        // Update RIP to the target address
        {
            let mut cpu_state_guard = self.state.cpu_state.lock().unwrap();
            let target_address_concolic = ConcolicVar::new_concrete_and_symbolic_int(
                target_address_concrete,
                target_address_symbolic,
                self.context,
                64,
            );
            cpu_state_guard
                .set_register_value_by_offset(0x288, target_address_concolic.clone(), 64)
                .map_err(|e| e.to_string())?;
        }
    
        // Update the instruction counter
        self.instruction_counter += 1;
    
        // Log the callind operation
        let current_addr_hex = format!("{:x}", self.current_address.unwrap_or(0));
        let result_var_name = format!("{}-{:02}-callind", current_addr_hex, self.instruction_counter);
        self.state.create_or_update_concolic_variable_int(
            &result_var_name,
            target_address_concrete,
            target_address_concolic.to_concolic_var().unwrap().symbolic,
        );
    
        // Update current_address to the new RIP
        self.current_address = Some(target_address_concrete);
    
        Ok(())
    }    
    
    // Handle return operation
    pub fn handle_return(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::Return || instruction.inputs.len() != 1 {
            return Err("Invalid instruction format for RETURN".to_string());
        }

        // Pop the function frame and clean up variables
        self.pop_function_frame();

        // Fetch the branch target (input0)
        log!(self.state.logger.clone(), "* Fetching branch target from instruction.input[0]");
        let branch_target_concolic = self.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
        let branch_target_concrete = branch_target_concolic.get_concrete_value();
        let branch_target_symbolic = match branch_target_concolic {
            ConcolicEnum::ConcolicVar(var) => var.symbolic,
            ConcolicEnum::CpuConcolicValue(cpu_var) => cpu_var.symbolic,
            ConcolicEnum::MemoryValue(mem_var) => SymbolicVar::Int(mem_var.symbolic),
        };
        log!(self.state.logger.clone(), "Branch target concrete : 0x{:x}", branch_target_concrete);

        let branch_target_concolic = ConcolicVar::new_concrete_and_symbolic_int(branch_target_concrete, branch_target_symbolic.to_bv(&self.context), self.context, 64); 

        // Update the RIP register to the branch target address
        {
            let mut cpu_state_guard = self.state.cpu_state.lock().unwrap();
            cpu_state_guard.set_register_value_by_offset(0x288, branch_target_concolic, 64).map_err(|e| e.to_string())?;
        }
        // Update the instruction counter
        self.instruction_counter += 1;

        // Create or update a concolic variable for the result (RETURN doesn't produce a result, but we log the branch decision)
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}-{:02}-return", current_addr_hex, self.instruction_counter);
        self.state.create_or_update_concolic_variable_int(&result_var_name, branch_target_concrete, branch_target_symbolic);

        Ok(())
    }    
 
    pub fn handle_load(&mut self, instruction: Inst, next_inst: &Inst, instructions_map: &BTreeMap<u64, Vec<Inst>>) -> Result<(), String> {
        if instruction.opcode != Opcode::Load || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for LOAD".to_string());
        }
    
        log!(self.state.logger.clone(), "* FYI, the space ID is not used during zorya execution.");
        log!(self.state.logger.clone(), "* Fetching pointer offset from instruction.input[1]");
    
        let pointer_offset_concolic = self.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;
        let pointer_offset_concrete = pointer_offset_concolic.get_concrete_value();
        log!(self.state.logger.clone(), "Pointer offset to be dereferenced : {:x}", pointer_offset_concrete);
    
        // Check if the pointer offset is NULL
        if pointer_offset_concrete == 0 {
            log!(self.state.logger.clone(), "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
            log!(self.state.logger.clone(), "VULN: Zorya caught the dereferencing of a NULL pointer, execution stopped!");
            log!(self.state.logger.clone(), "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
            process::exit(1);
        }

        // Cases covered : 'void a(void) { b(); c(); }', do the 'reinitialization'' of variables used by b() when b() finishes.
        // Implement scope management for variables
        // Clean up variables from functions that have finished
        self.cleanup_finished_function_variables(&instruction);

        // Check if the memory address has been initialized in the current scope (mainly working for C code)
        // if !self.is_address_initialized_in_current_scope(pointer_offset_concrete) {
        //     log!(self.state.logger.clone(), "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
        //     log!(self.state.logger.clone(), "VULN: Zorya detected uninitialized memory access at address 0x{:x}", pointer_offset_concrete);
        //     log!(self.state.logger.clone(), "Execution halted due to uninitialized memory access!");
        //     log!(self.state.logger.clone(), "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
        //     return Err(format!("Uninitialized memory access at address 0x{:x}", pointer_offset_concrete));
        // }

        // Determine the size of the data to load
        let load_size_bits = instruction.output.as_ref()
            .map(|varnode| varnode.size.to_bitvector_size() as u32)
            .unwrap_or(64); // Default to 64 bits if output size is not specified
        log!(self.state.logger.clone(), "Load size in bits: {}", load_size_bits);

        // Misalignment check
        // if pointer_offset_concrete % load_size_bytes != 0 {
        //     log!(self.state.logger.clone(), "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
        //     log!(self.state.logger.clone(), "VULN: Zorya detected a misaligned memory access at address 0x{:x}, load size: {} bytes", pointer_offset_concrete, load_size_bytes);
        //     log!(self.state.logger.clone(), "Execution stopped due to misaligned access!");
        //     log!(self.state.logger.clone(), "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
        //     process::exit(1);
        // }
            
        let mem_size = pointer_offset_concolic.get_symbolic_value_bv(self.context).get_size();
        log!(self.state.logger.clone(), "Memory size in bits: {}", mem_size);

        // Read memory value at the pointer offset.
        let mut mem_value = self.state.memory.read_value(pointer_offset_concrete, load_size_bits)
            .map_err(|e| format!("Failed to read memory at address 0x{:x}: {:?}", pointer_offset_concrete, e))?;
        let mem_value_size = mem_value.concrete.get_size();

        // For narrow memory values (<=64 bits), adjust if needed.
        if mem_value_size <= 64 {
            if load_size_bits > mem_size {
                mem_value = ConcolicVar::new_concrete_and_symbolic_int(
                    mem_value.concrete.to_u64(),
                    mem_value.symbolic.to_bv(&self.context),
                    &self.context,
                    load_size_bits,
                );
            }
            if load_size_bits < mem_size {
                let extracted_symbolic = mem_value.symbolic.to_bv(&self.context)
                    .extract(load_size_bits - 1, 0);
                mem_value = ConcolicVar::new_concrete_and_symbolic_int(
                    mem_value.concrete.to_u64(),
                    extracted_symbolic,
                    &self.context,
                    load_size_bits,
                );
            }
        }

        let mem_value_size = mem_value.concrete.get_size();
        log!(self.state.logger.clone(), "Dereferenced value: 0x{:x}, with size {:?}", mem_value.concrete, mem_value_size);

        // --- Handle jump table access versus regular LOAD ---
        let dereferenced_concolic = if self.inside_jump_table {
            // ---- Jump Table Branch ----
            log!(self.state.logger.clone(), "Handling jump table access.");
            self.inside_jump_table = false; // Reset jump table flag

            // Lookup the jump table corresponding to the pointer offset.
            let jump_table = {
                let tables = &self.state.jump_tables;
                tables.values()
                    .find(|table| table.table_address == pointer_offset_concrete)
                    .cloned()
                    .ok_or_else(|| "Pointer offset does not match any known jump table.".to_string())?
            };
            log!(self.state.logger.clone(), "Matched jump table.");

            // Resolve the jump table index (this function is assumed to exist).
            let index_bv = self.get_jump_table_index(self.context, instructions_map)
                .map_err(|e| format!("Failed to resolve jump table index: {}", e))?;
            log!(self.state.logger.clone(), "Resolved jump table index.");

            // Build a cascading ITE (if-then-else) to select the jump destination.
            let mut result = BV::from_u64(self.context, 0, 64);
            for (case_index, entry) in jump_table.cases.iter().enumerate() {
                let condition = index_bv._eq(&BV::from_u64(self.context, case_index as u64, 64));
                let destination_bv = BV::from_u64(self.context, entry.destination, 64);
                result = condition.ite(&destination_bv, &result);
            }

            // Now, update the symbolic portion of the loaded memory.
            if mem_value_size > 64 {
                let full_sym: BV = if mem_value.symbolic.get_size() < load_size_bits {
                    mem_value.symbolic.to_bv(&self.context)
                        .zero_ext(load_size_bits - mem_value.symbolic.get_size())
                } else {
                    mem_value.symbolic.to_bv(&self.context)
                };
                let full_sym_size = full_sym.get_size();
                let num_chunks = ((load_size_bits + 63) / 64) as usize;
                let mut large_sym = Vec::with_capacity(num_chunks);
                for i in 0..num_chunks {
                    let low = i * 64;
                    let high = std::cmp::min(full_sym_size, low as u32 + 64) - 1;
                    if high < low as u32 {
                        return Err(format!(
                            "[ERROR] Invalid BV extraction range: {} to {}, effective symbolic size: {}",
                            low, high, full_sym_size
                        ));
                    }
                    large_sym.push(full_sym.extract(high, low as u32));
                }
                ConcolicVar::new_concrete_and_symbolic_large_int(
                    mem_value.concrete.to_largeint(),
                    large_sym,
                    self.context
                )
            } else {
                ConcolicVar::new_concrete_and_symbolic_int(
                    mem_value.concrete.to_u64(),
                    mem_value.symbolic.clone().to_bv(&self.context),
                    self.context,
                    load_size_bits,
                )
            }
        } else {
            // ---- Regular LOAD Branch ----
            if mem_value_size > 64 {
                let full_sym: BV = if mem_value.symbolic.get_size() < load_size_bits {
                    mem_value.symbolic.to_bv(&self.context)
                        .zero_ext(load_size_bits - mem_value.symbolic.get_size())
                } else {
                    mem_value.symbolic.to_bv(&self.context)
                };
                let full_sym_size = full_sym.get_size();
                let num_chunks = ((load_size_bits + 63) / 64) as usize;
                let mut large_sym = Vec::with_capacity(num_chunks);
                for i in 0..num_chunks {
                    let low = i * 64;
                    let high = std::cmp::min(full_sym_size, low as u32 + 64) - 1;
                    if high < low as u32 {
                        return Err(format!(
                            "[ERROR] Invalid BV extraction range: {} to {}, effective symbolic size: {}",
                            low, high, full_sym_size
                        ));
                    }
                    large_sym.push(full_sym.extract(high, low as u32));
                }
                ConcolicVar::new_concrete_and_symbolic_large_int(
                    mem_value.concrete.to_largeint(),
                    large_sym,
                    self.context
                )
            } else {
                ConcolicVar::new_concrete_and_symbolic_int(
                    mem_value.concrete.to_u64(),
                    mem_value.symbolic.clone().to_bv(&self.context),
                    self.context,
                    load_size_bits,
                )
            }
        };

        // --- End of dereferenced value construction ---

        // Write the loaded value into the output.
        if let Some(output_varnode) = instruction.output.as_ref() {
            match &output_varnode.var {
                Var::Unique(id) => {
                    log!(self.state.logger.clone(), "Output is a Unique type with ID: 0x{:x}", id);
                    let unique_name = format!("Unique(0x{:x})", id);
                    self.unique_variables.insert(unique_name.clone(), dereferenced_concolic.clone());
                    log!(self.state.logger.clone(), "Updated Unique(0x{:x}) with concrete value 0x{:x} and size {:?}", 
                        id, dereferenced_concolic.concrete.to_u64(), dereferenced_concolic.concrete.get_size());
                },
                Var::Register(offset, _) => {
                    log!(self.state.logger.clone(), "Output is a Register type");
                    let mut cpu_state_guard = self.state.cpu_state.lock().unwrap();
                    match cpu_state_guard.set_register_value_by_offset(*offset, dereferenced_concolic.clone(), load_size_bits) {
                        Ok(_) => {
                            log!(self.state.logger.clone(), "Updated register at offset 0x{:x} with value 0x{:x}", 
                                offset, dereferenced_concolic.concrete.to_u64());
                        },
                        Err(e) => {
                            let error_msg = format!("Failed to update register at offset 0x{:x}: {:?}", offset, e);
                            log!(self.state.logger.clone(), "{}", error_msg);
                            return Err(error_msg);
                        }
                    }
                },
                _ => {
                    let error_msg = "Output type is unsupported".to_string();
                    log!(self.state.logger.clone(), "{}", error_msg);
                    return Err(error_msg);
                }
            }
        } else {
            return Err("No output variable specified for LOAD instruction".to_string());
        }
            
        // For debugging, create a named concolic variable for the result.
        let current_addr_hex = self.current_address
            .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}-{:02}-load", current_addr_hex, self.instruction_counter);
        if mem_value_size > 64 {
            self.state.create_or_update_concolic_variable_largeint(
                &result_var_name,
                mem_value.concrete.to_largeint(),
                SymbolicVar::LargeInt(mem_value.symbolic.clone().to_largebv())
            );
        } else { 
            self.state.create_or_update_concolic_variable_int(
                &result_var_name,
                mem_value.concrete.to_u64(),
                SymbolicVar::Int(mem_value.symbolic.clone().to_bv(self.context))
            );
        }
        Ok(())
    } 

    pub fn get_jump_table_index(&mut self, context: &'ctx z3::Context, instructions_map: &BTreeMap<u64, Vec<Inst>>) -> Result<BV<'ctx>, String> {
        // Traverse the instruction map to find the defining COPY, INT_MULT, and INT_ADD instructions
        let mut base_bv = None; // Base register BV (from COPY)
        let mut scale_bv = None; // Scale factor BV (from INT_MULT)
        let mut index_bv = None; // Final index BV (from INT_ADD)
    
        // Start from the current instruction and move backward
        for (_addr, insts) in instructions_map.iter().rev() {
            for inst in insts.iter().rev() {
                match inst.opcode {
                    Opcode::Copy => {
                        if base_bv.is_none() {
                            // Delegate to `handle_copy` to extract the base register
                            self.handle_copy(inst.clone())?;
                            base_bv = Some(self.varnode_to_concolic(&inst.output.as_ref().unwrap())?.get_symbolic_value_bv(context));
                        }
                    }
                    Opcode::IntMult => {
                        if scale_bv.is_none() {
                            // Delegate to `handle_int_mult` to extract the scaled value
                            executor_int::handle_int_mult(self, inst.clone())?;
                            scale_bv = Some(self.varnode_to_concolic(&inst.output.as_ref().unwrap())?.get_symbolic_value_bv(context));
                        }
                    }
                    Opcode::IntAdd => {
                        if index_bv.is_none() {
                            // Delegate to `handle_int_add` to calculate the final index
                            executor_int::handle_int_add(self, inst.clone())?;
                            index_bv = Some(self.varnode_to_concolic(&inst.output.as_ref().unwrap())?.get_symbolic_value_bv(context));
                            break; // No need to continue once the final index is resolved
                        }
                    }
                    _ => {}
                }
    
                // Stop if we have resolved all components
                if base_bv.is_some() && scale_bv.is_some() && index_bv.is_some() {
                    break;
                }
            }
        }
    
        // Combine the resolved components into the final index
        if let (Some(base), Some(scale), Some(index)) = (base_bv, scale_bv, index_bv) {
            log!(self.state.logger.clone(), "Base: {:?}, Scale: {:?}, Index: {:?}", base, scale, index);
            Ok(index)
        } else {
            Err("Failed to resolve jump table index: Missing one or more components.".to_string())
        }
        
    }

    // Handle STORE operation
    pub fn handle_store(&mut self, instruction: Inst) -> Result<(), String> {
        // Validate the instruction format
        if instruction.opcode != Opcode::Store || instruction.inputs.len() != 3 {
            return Err("Invalid instruction format for STORE".to_string());
        }
    
        // Fetch the pointer offset
        log!(self.state.logger.clone(), "* Fetching pointer offset from instruction.input[1]");
        let pointer_offset_var = self.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;
        let pointer_offset_concrete = pointer_offset_var.get_concrete_value();
        log!(self.state.logger.clone(), "Pointer offset concrete: {:x}", pointer_offset_concrete);
    
        // Mark the memory address as initialized
        self.initialiazed_var.insert(format!("{:x}", pointer_offset_concrete), self.current_address.unwrap_or(0));
        log!(self.state.logger.clone(), "Marked address 0x{:x} as initialized", pointer_offset_concrete);

        // Validate pointer to prevent null dereference
        if pointer_offset_concrete == 0 {
            log!(self.state.logger.clone(), "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
            log!(self.state.logger.clone(), "VULN: Null pointer dereference attempt detected, execution halted!");
            log!(self.state.logger.clone(), "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
            return Err("Attempted null pointer dereference".to_string());
        }
    
        // Fetch the data to be stored
        log!(self.state.logger.clone(), "* Fetching data to store from instruction.input[2]");
        let data_to_store_var = &instruction.inputs[2];
        let data_to_store_concolic = self.varnode_to_concolic(data_to_store_var).map_err(|e| e.to_string())?;
        let data_to_store_concrete = data_to_store_concolic.get_concrete_value();
        let data_to_store_symbolic = data_to_store_concolic.get_symbolic_value_bv(self.context);
        log!(self.state.logger.clone(), "Data to store: 0x{:x}", data_to_store_concrete);
    
        // Determine the size of the data to store
        let data_size_bits = data_to_store_var.size.to_bitvector_size() as u32;
        log!(self.state.logger.clone(), "Data size in bits: {}", data_size_bits);
    
        // Ensure symbolic value size matches data size
        let symbolic_size = data_to_store_symbolic.get_size();
        if symbolic_size != data_size_bits {
            return Err(format!("Symbolic size {} does not match data size {}", symbolic_size, data_size_bits));
        }
    
        // Create a MemoryValue
        let mem_value = MemoryValue {
            concrete: data_to_store_concrete,
            symbolic: data_to_store_symbolic.clone(),
            size: data_size_bits,
        };
    
        // Write the MemoryValue to memory
        match self.state.memory.write_value(pointer_offset_concrete, &mem_value) {
            Ok(_) => {
                log!(self.state.logger.clone(), "Stored value 0x{:x} to memory at address 0x{:x}", data_to_store_concrete, pointer_offset_concrete);
            },
            Err(e) => {
                let error_msg = format!("Failed to write to memory at address 0x{:x}: {:?}", pointer_offset_concrete, e);
                log!(self.state.logger.clone(), "{}", error_msg);
                return Err(error_msg);
            }
        }
    
        // Checks if the used variable has been initialized in the current scope (C code vulnerability)
        // TODO: handle more complex cases in C code by checking RSP register (that both CALL and RET use)
        // Mark the memory address as initialized
        let address_str = format!("{:x}", pointer_offset_concrete);
        self.initialiazed_var.insert(address_str.clone(), self.current_address.unwrap_or(0));
        log!(self.state.logger.clone(), "Marked address 0x{:x} as initialized", pointer_offset_concrete);

        // Add the address to the current function frame's local variables
        // if let Some(current_frame) = self.state.call_stack.last_mut() {
        //     current_frame.local_variables.insert(address_str.clone());
        //     log!(self.state.logger.clone(), "Added address 0x{:x} to current function frame's local variables", pointer_offset_concrete);
        // } else {
        //     log!(self.state.logger.clone(), "No function frame found at address 0x{:x}", pointer_offset_concrete);
        // }

        // update CPU register if the address maps to one
        let mut cpu_state_guard = self.state.cpu_state.lock().unwrap();
        if let Some(_register_value) = cpu_state_guard.get_register_by_offset(pointer_offset_concrete, data_size_bits) {
            match cpu_state_guard.set_register_value_by_offset(pointer_offset_concrete, data_to_store_concolic.to_concolic_var().unwrap(), data_size_bits) {
                Ok(_) => {
                    log!(self.state.logger.clone(), "Updated register at offset 0x{:x} with value 0x{:x} and symbolic part {:?}", pointer_offset_concrete, data_to_store_concrete, data_to_store_symbolic.simplify());
                },
                Err(e) => {
                    let error_msg = format!("Failed to update register at offset 0x{:x}: {}", pointer_offset_concrete, e);
                    log!(self.state.logger.clone(), "{}", error_msg);
                    return Err(error_msg);
                }
            }
        }
        drop(cpu_state_guard);
    
        // Record the operation for traceability (if needed in your context)
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}-{:02}-store", current_addr_hex, self.instruction_counter);
        self.state.create_or_update_concolic_variable_int(&result_var_name, data_to_store_concrete, SymbolicVar::Int(data_to_store_symbolic.clone()));
    
        Ok(())
    }

    pub fn handle_copy(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::Copy || instruction.inputs.len() != 1 {
            return Err("[ERROR] Invalid instruction format for COPY".to_string());
        }
    
        let output_varnode = instruction.output.as_ref().unwrap();
        let output_size_bits = output_varnode.size.to_bitvector_size() as u32;
    
        log!(self.state.logger.clone(), "Output size in bits: {}", output_size_bits);
    
        // Fetch the source explicitly
        log!(self.state.logger.clone(), "* Fetching source from instruction.input[0]");
        let source_concolic = self.varnode_to_concolic(&instruction.inputs[0])?
            .to_concolic_var()
            .unwrap();
    
        let new_symbolic = match &source_concolic.symbolic {
            SymbolicVar::LargeInt(bv_vec) => {
                if output_size_bits <= 64 {
                    if bv_vec.is_empty() {
                        return Err("[ERROR] Empty LargeInt vector in COPY".to_string());
                    }
                    let first_bv = bv_vec[0].clone(); // clone to avoid partial move
                    SymbolicVar::Int(first_bv.extract(output_size_bits - 1, 0))
                } else {
                    // Recombine only the necessary number of bits
                    let mut remaining_bits = output_size_bits;
                    let mut result_bv_opt = None;
    
                    for bv in bv_vec.iter().rev() {
                        if remaining_bits == 0 {
                            break;
                        }
                        let size = bv.get_size().min(remaining_bits);
                        let extracted = bv.extract(size - 1, 0);
    
                        result_bv_opt = Some(match result_bv_opt {
                            Some(prev) => extracted.concat(&prev),
                            None => extracted,
                        });
    
                        remaining_bits -= size;
                    }
    
                    match result_bv_opt {
                        Some(bv) => SymbolicVar::Int(bv),
                        None => return Err("[ERROR] Could not reconstruct symbolic from LargeInt".to_string()),
                    }
                }
            }
            SymbolicVar::Int(bv) => {
                if bv.get_size() > output_size_bits {
                    SymbolicVar::Int(bv.extract(output_size_bits - 1, 0).simplify())
                } else if bv.get_size() < output_size_bits {
                    SymbolicVar::Int(bv.zero_ext(output_size_bits - bv.get_size()).simplify())
                } else {
                    SymbolicVar::Int(bv.clone())
                }
            }
            SymbolicVar::Bool(b) => {
                let bv_int = b.ite(
                    &BV::from_u64(self.context, 1, output_size_bits),
                    &BV::from_u64(self.context, 0, output_size_bits),
                );
                SymbolicVar::Int(bv_int)
            }
            _ => return Err("[ERROR] Unsupported symbolic type in COPY".to_string()),
        };
    
        // Handle concrete copy
        let num_chunks = ((output_size_bits + 63) / 64) as usize;
        let mut concrete_chunks = vec![0u64; num_chunks];
    
        match &source_concolic.concrete {
            ConcreteVar::LargeInt(values) => {
                for (i, &val) in values.iter().enumerate().take(num_chunks) {
                    concrete_chunks[i] = val;
                }
            }
            ConcreteVar::Int(val) => concrete_chunks[0] = *val,
            ConcreteVar::Bool(b_val) => concrete_chunks[0] = if *b_val { 1u64 } else { 0u64 },
            _ => return Err("[ERROR] Unsupported concrete type in COPY".to_string()),
        }
    
        // Construct final ConcolicVar
        let new_concolic_var = if output_size_bits > 64 {
            // Turn symbolic Int into LargeInt representation
            let bv = match &new_symbolic {
                SymbolicVar::Int(bv) => bv.clone(),
                _ => return Err("[ERROR] Unexpected symbolic type for LargeInt copy".to_string()),
            };
    
            let mut bv_vec = Vec::new();
            let mut bits_left = bv.get_size();
            let mut curr_bv = bv;
    
            while bits_left > 64 {
                let chunk = curr_bv.extract(63, 0);
                bv_vec.push(chunk);
                curr_bv = curr_bv.extract(bits_left - 1, 64);
                bits_left -= 64;
            }
    
            bv_vec.push(curr_bv);
    
            ConcolicVar {
                concrete: ConcreteVar::LargeInt(concrete_chunks.clone()),
                symbolic: SymbolicVar::LargeInt(bv_vec),
                ctx: self.context,
            }
        } else {
            ConcolicVar {
                concrete: ConcreteVar::Int(concrete_chunks[0]),
                symbolic: match &new_symbolic {
                    SymbolicVar::Int(bv) => SymbolicVar::Int(bv.clone()),
                    SymbolicVar::LargeInt(bv_vec) => {
                        if bv_vec.is_empty() {
                            return Err("[ERROR] Empty LargeInt symbolic in COPY (small case)".to_string());
                        }
                        SymbolicVar::Int(bv_vec[0].clone())
                    }
                    _ => return Err("[ERROR] Unexpected symbolic type for small COPY".to_string()),
                },
                ctx: self.context,
            }
        }; 
    
        // Write to the target
        match &output_varnode.var {
            Var::Unique(id) => {
                self.unique_variables
                    .insert(format!("Unique(0x{:x})", id), new_concolic_var);
            }
            Var::Register(offset, _) => {
                let mut cpu_state_guard = self.state.cpu_state.lock().unwrap();
                cpu_state_guard.set_register_value_by_offset(*offset, new_concolic_var, output_size_bits)?;
            }
            Var::Memory(addr) => {
                let mem_value = MemoryValue {
                    concrete: concrete_chunks[0],
                    symbolic: new_symbolic.to_bv(self.context),
                    size: output_size_bits,
                };
                self.state
                    .memory
                    .write_value(*addr, &mem_value)
                    .map_err(|e| e.to_string())?;
            }
            _ => return Err("[ERROR] Unsupported output type in COPY".to_string()),
        }
    
        Ok(())
    }            
    
    // The function to handle POPCOUNT instruction
    pub fn handle_popcount(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::PopCount || instruction.inputs.len() != 1 || instruction.output.is_none() {
            return Err("Invalid instruction format for POPCOUNT".to_string());
        }

        log!(self.state.logger.clone(), "* Fetching instruction.input[0] for POPCOUNT");
        let input_var = self.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| {
            log!(self.state.logger.clone(), "Error converting varnode to concolic: {}", e);
            e.to_string()
        })?;

        let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;

        let result_concrete = input_var.get_concrete_value().count_ones();

        let symbolic_input = input_var.to_concolic_var().unwrap().symbolic;
        let result_symbolic = match symbolic_input {
            SymbolicVar::Int(bv) => {
                if bv.get_size() <= 8 {
                    // Naively popcount 8-bit symbolic by summing extracted bits
                    let mut bits = vec![];
                    for i in 0..bv.get_size() {
                        let b = bv.extract(i, i).zero_ext(output_size_bits); // Fixed: extract(i, i)
                        bits.push(b);
                    }
                    let mut sum = bits[0].clone();
                    for b in bits.iter().skip(1) {
                        sum = sum.bvadd(b);
                    }
                    sum.extract(output_size_bits - 1, 0)
                } else {
                    log!(self.state.logger.clone(), "Warning: POPCOUNT symbolic input too large, approximating to 0");
                    BV::from_u64(self.context, 0, output_size_bits)
                }
            }
            _ => {
                log!(self.state.logger.clone(), "Warning: Unsupported symbolic type for POPCOUNT");
                BV::from_u64(self.context, 0, output_size_bits)
            }
        };

        let popcount_result = ConcolicVar::new_concrete_and_symbolic_int(result_concrete as u64, result_symbolic, self.context, output_size_bits);

        self.handle_output(instruction.output.as_ref(), popcount_result.clone())?;

        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}-{:02}-popcount", current_addr_hex, self.instruction_counter);
        self.state.create_or_update_concolic_variable_int(&result_var_name, popcount_result.concrete.to_u64(), popcount_result.symbolic);

        Ok(())
    }
   

    // Handle the SUBPIECE operation
    pub fn handle_subpiece(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::SubPiece || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for SUBPIECE".to_string());
        }
    
        log!(
            self.state.logger.clone(),
            "* Fetching source data from instruction.input[0] for SUBPIECE"
        );
    
        let source_concolic = self
            .varnode_to_concolic(&instruction.inputs[0])
            .map_err(|e| format!("Failed to fetch source data: {}", e))?
            .to_concolic_var()
            .unwrap();
        let source_concrete = &source_concolic.concrete;
        let source_symbolic = &source_concolic.symbolic;
    
        log!(
            self.state.logger.clone(),
            "* Fetching truncation offset from instruction.input[1] for SUBPIECE"
        );
    
        // Parse the truncation offset (in bytes) from the constant input.
        let offset_value = if let Var::Const(value) = &instruction.inputs[1].var {
            u32::from_str_radix(value.trim_start_matches("0x"), 16)
                .map_err(|e| format!("Failed to parse offset value: {}", e))?
        } else {
            return Err("SUBPIECE expects a constant for input1".to_string());
        };
    
        let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
        let bit_offset = offset_value * 8; // Convert byte offset to bits
    
        // --- Handle Concrete Value Extraction ---
        let truncated_concrete = match source_concrete {
            ConcreteVar::Int(value) => {
                let total_bits = 64;
                let shifted = if bit_offset >= total_bits {
                    0u64
                } else {
                    *value >> bit_offset
                };
                let mask = if output_size_bits >= 64 {
                    u64::MAX
                } else {
                    (1u64 << output_size_bits) - 1
                };
                ConcreteVar::Int(shifted & mask)
            }
            ConcreteVar::LargeInt(values) => {
                let shifted_values = Self::lshr_largeint(values, bit_offset);
                let masked_values = Self::mask_largeint(&shifted_values, output_size_bits);
                ConcreteVar::LargeInt(masked_values)
            }
            _ => return Err("Unsupported concrete variable type in SUBPIECE".to_string()),
        };
    
        // --- Handle Symbolic Value Extraction ---
        let truncated_symbolic = match source_symbolic {
            SymbolicVar::Int(bv) => {
                // Perform logical shift right on the BV then extract the desired bits.
                let safe_bv = Self::subpiece_bv(self.context, bv, bit_offset, output_size_bits);
                SymbolicVar::Int(safe_bv)
            }
            SymbolicVar::LargeInt(bv_vec) => {
                let combined = Self::combine_largeint(self.context, bv_vec);
                let safe_bv = Self::subpiece_bv(self.context, &combined, bit_offset, output_size_bits);
                // Now, if the output_size_bits is multiple of 64, you can split back:
                let chunk_count = (output_size_bits + 63) / 64;
                let splitted = Self::split_largeint(self.context, &safe_bv, chunk_count as usize);
                SymbolicVar::LargeInt(splitted)
            }
            _ => return Err("Unsupported symbolic variable type in SUBPIECE".to_string()),
        };
    
        // Create the result ConcolicVar from the truncated concrete and symbolic parts.
        let result_value = ConcolicVar {
            concrete: truncated_concrete,
            symbolic: truncated_symbolic,
            ctx: self.context,
        };
    
        // Output the result to the destination.
        self.handle_output(instruction.output.as_ref(), result_value.clone())?;
    
        // Create or update a named concolic variable for debugging/tracking.
        let current_addr_hex = self
            .current_address
            .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}-{:02}-subpiece", current_addr_hex, self.instruction_counter);
        // If the result is wide (>64 bits), use the largeint update; otherwise, use the int update.
        if output_size_bits > 64 {
            self.state.create_or_update_concolic_variable_largeint(
                &result_var_name,
                match result_value.concrete {
                    ConcreteVar::LargeInt(ref vec) => vec.clone(),
                    _ => vec![result_value.concrete.to_u64()],
                },
                result_value.symbolic.clone(),
            );
        } else {
            self.state.create_or_update_concolic_variable_int(
                &result_var_name,
                result_value.concrete.to_u64(),
                result_value.symbolic.clone(),
            );
        }
    
        log!(self.state.logger.clone(), "SUBPIECE operation completed successfully.");
        Ok(())
    }    

    // Logical shift right on Vec<u64>
    fn lshr_largeint(values: &Vec<u64>, shift: u32) -> Vec<u64> {
        let total_bits = (values.len() * 64) as u32;
        if shift >= total_bits {
            return vec![0; values.len()];
        }

        let mut result = vec![0; values.len()];
        let full_shifts = (shift / 64) as usize;
        let bit_shift = shift % 64;

        for i in 0..(values.len() - full_shifts) {
            let src_index = i + full_shifts;
            let lower = values[src_index] >> bit_shift;
            let upper = if bit_shift > 0 && src_index + 1 < values.len() {
                values[src_index + 1] << (64 - bit_shift)
            } else {
                0
            };
            result[i] = lower | upper;
        }
        result
    }

    // Logical shift right on Vec<BV<'ctx>>
    fn bvlshr_largeint(ctx: &'ctx Context, bv_vec: &Vec<BV<'ctx>>, shift: u32) -> Vec<BV<'ctx>> {
        let total_bits = (bv_vec.len() * 64) as u32;
        if shift >= total_bits {
            return vec![BV::from_u64(ctx, 0, 64); bv_vec.len()];
        }

        let mut result = vec![BV::from_u64(ctx, 0, 64); bv_vec.len()];
        let full_shifts = (shift / 64) as usize;
        let bit_shift = shift % 64;

        for i in 0..(bv_vec.len() - full_shifts) {
            let src_index = i + full_shifts;
            let lower = bv_vec[src_index].bvlshr(&BV::from_u64(ctx, bit_shift as u64, 64));
            let upper = if bit_shift > 0 && src_index + 1 < bv_vec.len() {
                bv_vec[src_index + 1].bvshl(&BV::from_u64(ctx, (64 - bit_shift) as u64, 64))
            } else {
                BV::from_u64(ctx, 0, 64)
            };
            result[i] = lower.bvor(&upper);
        }
        result
    }

    // Mask the lower 'num_bits' bits of Vec<BV<'ctx>>
    fn mask_largeint_bv(ctx: &'ctx Context, bv_vec: &Vec<BV<'ctx>>, num_bits: u32) -> Vec<BV<'ctx>> {
        let total_bits = (bv_vec.len() * 64) as u32;
        if num_bits >= total_bits {
            return bv_vec.clone();
        }

        let mut result = bv_vec.clone();
        let bits_to_clear = total_bits - num_bits;
        let bits_in_partial_word = bits_to_clear % 64;

        // Zero out the higher words
        for i in ((num_bits / 64) as usize + 1)..bv_vec.len() {
            result[i] = BV::from_u64(ctx, 0, 64);
        }

        // Mask the partial word
        if bits_in_partial_word > 0 && ((num_bits / 64) as usize) < bv_vec.len() {
            let idx = (num_bits / 64) as usize;
            let mask = (1u64 << (64 - bits_in_partial_word)) - 1;
            let mask_bv = BV::from_u64(ctx, mask, 64);
            result[idx] = result[idx].bvand(&mask_bv);
        }

        result
    }


    // Mask the lower 'num_bits' bits of Vec<u64>
    fn mask_largeint(values: &Vec<u64>, num_bits: u32) -> Vec<u64> {
        let total_bits = (values.len() * 64) as u32;
        if num_bits >= total_bits {
            return values.clone();
        }

        let mut result = values.clone();
        let bits_to_clear = total_bits - num_bits;
        let bits_in_partial_word = bits_to_clear % 64;

        // Zero out the higher words
        for i in ((num_bits / 64) as usize + 1)..values.len() {
            result[i] = 0;
        }

        // Mask the partial word
        if bits_in_partial_word > 0 && ((num_bits / 64) as usize) < values.len() {
            let idx = (num_bits / 64) as usize;
            let mask = (1u64 << (64 - bits_in_partial_word)) - 1;
            result[idx] &= mask;
        }

        result
    }

    // Extract `out_bits` starting at `bit_offset` from `src_bv`,
    // returning a BV of exactly `out_bits` bits. If offset or size
    // is out of range, it gracefully zeros out everything that is
    // beyond the source BV's length.
    fn subpiece_bv(ctx: &'ctx Context, src_bv: &BV<'ctx>, bit_offset: u32, out_bits: u32) -> BV<'ctx> {
        let src_size = src_bv.get_size();

        // If you asked for 0 bits, just return a 0-bit or 1-bit of zero.
        // (In practice, out_bits=0 may never happen, but let's be safe.)
        if out_bits == 0 {
            // We'll return a 1-bit zero for convenience, or could panic.
            return BV::from_u64(ctx, 0, 1);
        }

        // If the offset is >= src_size, everything is shifted out.
        // So the entire subpiece is just zero.
        if bit_offset >= src_size {
            return BV::from_u64(ctx, 0, out_bits);
        }

        // The maximum bits we can extract from `src_bv` after `bit_offset`
        // is `src_size - bit_offset`.
        let available_bits = src_size - bit_offset;

        // We only need `out_bits`, but if out_bits > available_bits,
        // we'll zero-extend what's left.
        let final_bits = std::cmp::min(out_bits, available_bits);

        // 1) Shift right by `bit_offset`.
        //    This puts the desired subpiece at the bottom of `shifted`.
        let shifted = src_bv.bvlshr(&BV::from_u64(ctx, bit_offset as u64, src_size));

        // 2) Extract the lower `final_bits` bits from `shifted`.
        //    If final_bits == 0, we’d skip and just produce 0,
        //    but we already guaranteed bit_offset < src_size => final_bits > 0
        let extracted = shifted.extract(final_bits - 1, 0);

        // 3) If final_bits < out_bits, we must zero-extend to get the full `out_bits`.
        if final_bits < out_bits {
            extracted.zero_ext((out_bits - final_bits) as u32)
        } else {
            extracted
        }
    }

    /// Combine a Vec<BV<ctx>> into a single BV (lowest index = least significant 64 bits).
    fn combine_largeint(ctx: &'ctx Context, bv_vec: &Vec<BV<'ctx>>) -> BV<'ctx> {
        // Assume bv_vec[0] = low 64 bits, bv_vec[1] = next 64, etc.
        let mut iter = bv_vec.iter().rev(); // Start from the highest chunk
        if let Some(first) = iter.next() {
            let mut combined = first.clone();
            for chunk in iter {
                // Shift combined left 64 bits, then OR in the next chunk
                combined = combined.bvshl(&BV::from_u64(ctx, 64, combined.get_size()));
                combined = combined.concat(chunk);
            }
            combined
        } else {
            // If empty, return a 1-bit zero
            BV::from_u64(ctx, 0, 1)
        }
    }

    fn split_largeint(ctx: &'ctx Context, bv: &BV<'ctx>, total_chunks: usize) -> Vec<BV<'ctx>> {
        let total_bits = bv.get_size();
        let chunk_bits = 64;
        let mut result = Vec::with_capacity(total_chunks);
        let mut offset = 0;
        for _ in 0..total_chunks {
            let high_bit = std::cmp::min(offset + chunk_bits, total_bits) - 1;
            let extracted = bv.extract(high_bit, offset);
            // Next chunk
            offset += chunk_bits;
            result.push(extracted);
            if offset >= total_bits {
                // Zero-extend or fill the rest with 0 if needed
                while result.len() < total_chunks {
                    result.push(BV::from_u64(ctx, 0, 64));
                }
                break;
            }
        }
        result
    }

    // Helper function to extend the size of a Bool when there is an operation between a Bool (size 1) and an Integer (usually size 8)
    fn adapt_var(&self, var: ConcolicEnum<'ctx>, bit_size: u32, ctx: &'ctx Context) -> Result<ConcolicEnum<'ctx>, String> {
        let concolic_var = var.to_concolic_var().unwrap();
        match &concolic_var.symbolic {
            SymbolicVar::Bool(b) => {
                log!(self.state.logger.clone(), "Adapting Bool to size {}", bit_size);
                // Convert Bool to BV of bit_size
                let bv = b.ite(&BV::from_u64(ctx, 1, bit_size), &BV::from_u64(ctx, 0, bit_size));
                // Convert concrete Bool to u64
                let concrete_value = match concolic_var.concrete {
                    ConcreteVar::Bool(b_val) => if b_val { 1u64 } else { 0u64 },
                    _ => return Err("Expected ConcreteVar::Bool".to_string()),
                };
                // Resize concrete value
                let mask = if bit_size >= 64 {
                    u64::MAX
                } else {
                    (1u64 << bit_size) - 1
                };
                let resized_concrete = concrete_value & mask;
                Ok(ConcolicEnum::ConcolicVar(ConcolicVar {
                    concrete: ConcreteVar::Int(resized_concrete),
                    symbolic: SymbolicVar::Int(bv),
                    ctx,
                }))
            },
            SymbolicVar::Int(bv) => {
                log!(self.state.logger.clone(), "Adapting Int to size {}", bit_size);
                // Resize BV to bit_size if necessary
                let current_size = bv.get_size();
                let resized_bv = if current_size < bit_size {
                    bv.zero_ext(bit_size - current_size)
                } else if current_size > bit_size {
                    bv.extract(bit_size - 1, 0)
                } else {
                    bv.clone()
                };
                // Resize concrete value
                let concrete_value = match concolic_var.concrete {
                    ConcreteVar::Int(value) => value,
                    _ => return Err("Expected ConcreteVar::Int".to_string()),
                };
                let mask = if bit_size >= 64 {
                    u64::MAX
                } else {
                    (1u64 << bit_size) - 1
                };
                let resized_concrete = concrete_value & mask;
                Ok(ConcolicEnum::ConcolicVar(ConcolicVar {
                    concrete: ConcreteVar::Int(resized_concrete),
                    symbolic: SymbolicVar::Int(resized_bv),
                    ctx,
                }))
            },
            _ => {
                // Return the original variable without modification
                Ok(ConcolicEnum::ConcolicVar(concolic_var))
            },
        } 
    }

    pub fn adapt_types(&self, var1: ConcolicEnum<'ctx>, var2: ConcolicEnum<'ctx>, bit_size: u32) -> Result<(ConcolicEnum<'ctx>, ConcolicEnum<'ctx>), String> {
        let ctx = self.context;

        let adapted_var1 = self.adapt_var(var1, bit_size, ctx)?;
        let adapted_var2 = self.adapt_var(var2, bit_size, ctx)?;

        Ok((adapted_var1, adapted_var2))
    }

    // Push a new function frame onto the call stack
    pub fn push_function_frame(&mut self) {
        self.state.call_stack.push(FunctionFrame {
            local_variables: BTreeSet::new(),
        });
        log!(self.state.logger.clone(), "Pushed a new function frame onto the call stack.");
    }

    // Pop the top function frame from the call stack and clean up variables
    pub fn pop_function_frame(&mut self) {
        if let Some(finished_frame) = self.state.call_stack.pop() {
            // Remove variables associated with this function's scope from initialized variables
            for var_address in &finished_frame.local_variables {
                self.initialiazed_var.remove(var_address);
                self.state.concolic_vars.remove(var_address);
                log!(self.state.logger.clone(), "Cleaned up variable at address 0x{} ", var_address);
            }
            log!(self.state.logger.clone(), "Popped a function frame from the call stack.");
        } else {
            log!(self.state.logger.clone(), "Call stack is empty. No frame to pop.");
        }
    }

    // Check if the current instruction is a function return
    fn is_function_return(&self, instruction: &Inst) -> bool {
        instruction.opcode == Opcode::Return
    }

    fn cleanup_finished_function_variables(&mut self, instruction: &Inst) {
        // Check if the current instruction is a function return
        if self.is_function_return(instruction) {
            // Pop the function frame and clean up variables
            self.pop_function_frame();
        }
    } 
}             

impl<'ctx> fmt::Display for ConcolicExecutor<'ctx> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "***")?;
        writeln!(f, "ConcolicExecutor State after the instruction:")?;
        writeln!(f, "Current Address: {:x}", self.current_address.unwrap())?;
        writeln!(f, "Instruction Counter: {}", self.instruction_counter)?;
        writeln!(f, "Unique Variables:")?;
        for (key, value) in &self.unique_variables {
            writeln!(f, "  {}: {}", key, value)?;
        }
        Ok(())
    }
}


