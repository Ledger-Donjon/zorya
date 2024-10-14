use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::io::Write;
use std::sync::MutexGuard;
use std::process;

use crate::state::cpu_state::CpuConcolicValue;
use crate::state::memory_x86_64::MemoryValue;
use crate::state::state_manager::Logger;
use crate::state::CpuState;
use crate::state::State;
use goblin::elf;
use goblin::elf::sym::STT_FUNC;
use goblin::elf::Elf;
use parser::parser::{Inst, Opcode, Var, Varnode};
use z3::ast::Ast;
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
    pub pcode_internal_lines_to_be_jumped: usize, // known line number of the current instruction in the pcode file, usefull for branch instructions
}

impl<'ctx> ConcolicExecutor<'ctx> {
    pub fn new(context: &'ctx Context, logger: Logger) -> Result<Self, Box<dyn Error>> {
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
         })
    }

    pub fn populate_symbol_table(&mut self, elf_data: &[u8]) -> Result<(), goblin::error::Error> {
        let elf = Elf::parse(elf_data)?;
        // Iterate over the symbol tables
        for sym in &elf.syms {
            if elf::sym::st_type(sym.st_info) == STT_FUNC {
                if let Some(name) = elf.strtab.get_at(sym.st_name) {
                    // Convert address to hexadecimal string
                    let address_hex = format!("{:x}", sym.st_value);
                    // Insert the hexadecimal address and the name into the symbol_table
                    self.symbol_table.insert(address_hex, name.to_string());
                }
            }
        }
        Ok(())
    }      

    pub fn execute_instruction(&mut self, instruction: Inst, current_addr: u64) -> Result<(), String> {
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
            Opcode::CBranch => self.handle_cbranch(instruction), // adds a condition to the jump
            Opcode::Copy => self.handle_copy(instruction),
            Opcode::CPoolRef => panic!("Opcode CPoolRef is not implemented yet"), // returns runtime-dependent values from the constant pool
            Opcode::CrossBuild => panic!("Opcode CrossBuild is not implemented yet"),
            Opcode::DelaySlot => panic!("Opcode DelaySlot is not implemented yet"),
            Opcode::Label => panic!("Opcode Label is not implemented yet"),
            Opcode::Load => self.handle_load(instruction),
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
                log!(self.state.logger.clone(), "Varnode is of type 'unique' with ID: {:x}", id);
                let unique_name = format!("Unique(0x{:x})", id);
                let unique_symbolic = BV::new_const(self.context, unique_name.clone(), bit_size);
                let var = self.unique_variables.entry(unique_name.clone())
                    .or_insert_with(|| {
                        log!(self.state.logger.clone(), "Creating new unique variable '{}' with initial value {:x} and size {:?}", unique_name, *id as u64, varnode.size);
                        ConcolicVar::new_concrete_and_symbolic_int(*id as u64, unique_symbolic.clone(), self.context, bit_size)
                    })
                    .clone();
                log!(self.state.logger.clone(), "Retrieved unique variable: {:?} with symbolic size: {:?}", var.concrete, var.symbolic.get_size());
                Ok(ConcolicEnum::ConcolicVar(var))
            },
            Var::Const(value) => {
                log!(self.state.logger.clone(), "Varnode is a constant with value: {}", value);
                // Improved parsing that handles hexadecimal values prefixed with '0x'
                let parsed_value = if value.starts_with("0x") {
                    u64::from_str_radix(&value[2..], 16)
                } else {
                    value.parse::<u64>()
                }.map_err(|e| format!("Failed to parse value '{}' as u64: {}", value, e))?;
                log!(self.state.logger.clone(), "Parsed value: {}", parsed_value);
                let parsed_value_symbolic = BV::from_u64(self.context, parsed_value, bit_size);
                let mem_value = MemoryValue {
                    concrete: parsed_value,
                    symbolic: parsed_value_symbolic,
                    size: bit_size,
                };
                log!(self.state.logger.clone(), "Constant treated as memory value: {:?} with symbolic size {:?}", mem_value.concrete, mem_value.symbolic.get_size());
                Ok(ConcolicEnum::MemoryValue(mem_value))
            },
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
    
                log!(self.state.logger.clone(), "Retrieved memory value: {:?} with symbolic size: {:?}", mem_value.concrete, mem_value.symbolic.get_size());
                Ok(ConcolicEnum::MemoryValue(mem_value))
            },
        }
    }     

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
    
                // Handle the symbolic extraction
                let symbolic_bv = original_register.symbolic.to_bv(&cpu_state_guard.ctx);
                let high_bit = (bit_offset + u64::from(bit_size) - 1) as u32;
                let low_bit = bit_offset as u32;
                let extracted_symbolic = symbolic_bv.extract(high_bit, low_bit).simplify();
    
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
                    );    
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
                    log!(self.state.logger.clone(), "Output is a Unique type with ID: 0x{:x}", id);
                    let unique_name = format!("Unique(0x{:x})", id);
                    self.unique_variables.insert(unique_name, result_value.clone());
                    log!(self.state.logger.clone(), "Updated unique variable: Unique(0x{:x}) with concrete size {} bits, symbolic size {} bits", id, bit_size, result_value.symbolic.get_size());
                    Ok(())
                }, 
                Var::Register(offset, _) => {
                    log!(self.state.logger.clone(), "Output is a Register type");
                    let mut cpu_state_guard = self.state.cpu_state.lock().unwrap();
    
                    match cpu_state_guard.set_register_value_by_offset(*offset, result_value.clone(), bit_size) {
                        Ok(_) => {
                            // check
                            let register = cpu_state_guard.get_register_by_offset(*offset, bit_size);
                            log!(self.state.logger.clone(), "Updated register at offset 0x{:x} with value 0x{:x}, size {} bits", offset, register.unwrap().concrete.to_u64(), bit_size);
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
                    if symbolic_size != bit_size {
                        return Err(format!("Symbolic size {} does not match bit size {}", symbolic_size, bit_size));
                    }
    
                    // Create a MemoryValue
                    let mem_value = MemoryValue {
                        concrete: concrete_value,
                        symbolic: symbolic_bv,
                        size: bit_size,
                    };
    
                    // Write the MemoryValue to memory
                    match self.state.memory.write_value(*addr, &mem_value) {
                        Ok(_) => {
                            log!(self.state.logger.clone(), "Wrote value 0x{:x} to memory at address 0x{:x}", concrete_value, addr);
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
        let branch_target_address = self.extract_branch_target_address(branch_target_varnode)?;

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

    fn extract_branch_target_address(&mut self, varnode: &Varnode) -> Result<u64, String> {
        match &varnode.var {
            Var::Memory(addr) => {
                log!(self.state.logger.clone(), "Branch target is a specific memory address: 0x{:x}", addr);
                // Update the RIP register to the new branch target address
                {
                    let mut cpu_state_guard = self.state.cpu_state.lock().unwrap();
                    cpu_state_guard.set_register_value_by_offset(0x288, ConcolicVar::new_concrete_and_symbolic_int(*addr, SymbolicVar::from_u64(&self.context, *addr, 64).to_bv(&self.context), &self.context, 64), 64)?;
                }
                log!(self.state.logger.clone(), "Branching to address 0x{:x}", addr);

                Ok(*addr)
            },
            Var::Const(value) => {
                // Log the value to be parsed
                log!(self.state.logger.clone(), "Attempting to parse branch target constant: {:?}", value);
                
                // Convert value to a string and remove the '0x' prefix
                let value_string = value.to_string(); // Extend lifetime by storing in a variable
                let value_str = value_string.trim_start_matches("0x"); // Now, this is safe
                
                // Attempt to parse the string as a hexadecimal number
                let value_u64 = match u64::from_str_radix(value_str, 16) {
                    Ok(value_u64) => {
                        log!(self.state.logger.clone(), "Branch target is a constant: 0x{:x}, which means this is a sub instruction of a pcode instruction.", value_u64);
                        value_u64
                    },
                    Err(e) => {
                        // Log the error and return an error message
                        log!(self.state.logger.clone(), "Failed to parse constant as u64: {:?}", e);
                        return Err(format!("Failed to parse constant as u64: {:?}", e));
                    }
                }; 

                self.pcode_internal_lines_to_be_jumped = value_u64 as usize;  // setting the number of lines to skip
                
                Ok(value_u64)
            }
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
        let branch_target_address = self.extract_branch_target_address(branch_target_varnode)?;
    
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
    pub fn handle_cbranch(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::CBranch || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for CBRANCH".to_string());
        }
    
        // Fetch the branch target (input0)
        log!(self.state.logger.clone(), "* Fetching branch target from instruction.input[0]");
        let branch_target_varnode = &instruction.inputs[0];
    
        // Check if the branch target is a memory address
        match &branch_target_varnode.var {
            Var::Memory(addr) => {
                log!(self.state.logger.clone(), "Branch target is a specific memory address: 0x{:x}", addr);
                let branch_target_varnode_symbolic = SymbolicVar::from_u64(&self.context, *addr, 64).to_bv(&self.context);

                // Fetch the branch condition (input1)
                log!(self.state.logger.clone(), "* Fetching branch condition from instruction.input[1]");
                let branch_condition_concolic = self.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;
                let branch_condition_concrete = branch_condition_concolic.get_concrete_value();
                let branch_condition_symbolic = match branch_condition_concolic {
                    ConcolicEnum::ConcolicVar(var) => var.symbolic,
                    ConcolicEnum::CpuConcolicValue(cpu_var) => cpu_var.symbolic,
                    ConcolicEnum::MemoryValue(mem_var) => SymbolicVar::Int(mem_var.symbolic),
                };
                log!(self.state.logger.clone(), "Branch condition concrete : {}", branch_condition_concrete);

                let branch_target_concolic = ConcolicVar::new_concrete_and_symbolic_int(*addr, branch_target_varnode_symbolic, self.context, 64);
            
                // Check the branch condition
                if branch_condition_concrete != 0 {
                    log!(self.state.logger.clone(), "Branch condition is true, branching to address {:x}", *addr);
                    // Update the RIP register to the branch target address
                    let mut cpu_state_guard = self.state.cpu_state.lock().unwrap();
                    cpu_state_guard.set_register_value_by_offset(0x288, branch_target_concolic, 64).map_err(|e| e.to_string())?;
                } else {
                    log!(self.state.logger.clone(), "Branch condition is false, continuing to next instruction");
                }

                // Create or update a concolic variable for the result (CBRANCH doesn't produce a result, but we log the branch decision)
                let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
                let result_var_name = format!("{}-{:02}-cbranch", current_addr_hex, self.instruction_counter);
                self.state.create_or_update_concolic_variable_int(&result_var_name, branch_condition_concrete, branch_condition_symbolic);
            }
            Var::Const(value) => {
                // Log the value to be parsed
                log!(self.state.logger.clone(), "Attempting to parse branch target constant: {:?}", value);
                
                // Convert value to a string and remove the '0x' prefix
                let value_string = value.to_string(); // Extend lifetime by storing in a variable
                let value_str = value_string.trim_start_matches("0x"); // Now, this is safe
                
                // Attempt to parse the string as a hexadecimal number
                let value_u64 = match u64::from_str_radix(value_str, 16) {
                    Ok(value_u64) => {
                        log!(self.state.logger.clone(), "Branch target is a constant: 0x{:x}, which means this is a sub instruction of a pcode instruction.", value_u64);
                        value_u64
                    },
                    Err(e) => {
                        // Log the error and return an error message
                        log!(self.state.logger.clone(), "Failed to parse constant as u64: {:?}", e);
                        return Err(format!("Failed to parse constant as u64: {:?}", e));
                    }
                }; 

                // Fetch the branch condition (input1)
                log!(self.state.logger.clone(), "* Fetching branch condition from instruction.input[1]");
                let branch_condition_concolic = self.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;
                let branch_condition_concrete = branch_condition_concolic.get_concrete_value();
                let branch_condition_symbolic = match branch_condition_concolic {
                    ConcolicEnum::ConcolicVar(var) => var.symbolic,
                    ConcolicEnum::CpuConcolicValue(cpu_var) => cpu_var.symbolic,
                    ConcolicEnum::MemoryValue(mem_var) => SymbolicVar::Int(mem_var.symbolic),
                };
                log!(self.state.logger.clone(), "Branch condition concrete : {}", branch_condition_concrete);
            
                // Check the branch condition
                if branch_condition_concrete != 0 {
                    log!(self.state.logger.clone(), "Branch condition is true, and because it is a sub-instruction, the execution jumps of {:x} lines.", value_u64);
                    self.pcode_internal_lines_to_be_jumped = value_u64 as usize;  // setting the number of lines to skip
                } else {
                    log!(self.state.logger.clone(), "Branch condition is false, continuing to the next instruction.");
                }

                // Create or update a concolic variable for the result (CBRANCH doesn't produce a result, but we log the branch decision)
                let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
                let result_var_name = format!("{}-{:02}-cbranch", current_addr_hex, self.instruction_counter);
                self.state.create_or_update_concolic_variable_int(&result_var_name, branch_condition_concrete, branch_condition_symbolic);
            }                
            _ => {
                // Fetch the concolic variable if it's not a memory address
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

        // Create or update a concolic variable for the result (BRANCHIND doesn't produce a result, but we log the branch decision)
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
            return Err("Invalid instruction format for BRANCHIND".to_string());
        }

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

        // Create or update a concolic variable for the result (BRANCHIND doesn't produce a result, but we log the branch decision)
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}-{:02}-return", current_addr_hex, self.instruction_counter);
        self.state.create_or_update_concolic_variable_int(&result_var_name, branch_target_concrete, branch_target_symbolic);

        Ok(())
    }    

    pub fn handle_load(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::Load || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for LOAD".to_string());
        }
    
        log!(self.state.logger.clone(), "* FYI, the space ID is not used during zorya execution.");
        log!(self.state.logger.clone(), "* Fetching pointer offset from instruction.input[1]");
    
        let pointer_offset_concolic = self.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;
        let pointer_offset_concrete = pointer_offset_concolic.get_concrete_value();
        log!(self.state.logger.clone(), "Pointer offset to be dereferenced : {:x}", pointer_offset_concrete);
    
        if pointer_offset_concrete == 0 {
            log!(self.state.logger.clone(), "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
            log!(self.state.logger.clone(), "VULN: Zorya caught the dereferencing of a NULL pointer, execution stopped!");
            log!(self.state.logger.clone(), "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
            process::exit(1);
        }
    
        // Determine the size of the data to load
        let load_size_bits = instruction.output.as_ref()
            .map(|varnode| varnode.size.to_bitvector_size() as u32)
            .unwrap_or(64); // Default to 64 bits if output size is not specified
        
        let mem_size = pointer_offset_concolic.get_symbolic_value_bv(self.context).get_size();
        log!(self.state.logger.clone(), "Load size in bits: {}", mem_size);
    
        // Dereference the address from memory
        let mut mem_value = self.state.memory.read_value(pointer_offset_concrete, mem_size)
            .map_err(|e| format!("Failed to read memory at address 0x{:x}: {:?}", pointer_offset_concrete, e))?;

        if load_size_bits > mem_size {
            mem_value.symbolic = mem_value.symbolic.zero_ext(load_size_bits - mem_size);
        }
        if load_size_bits < mem_size {
            mem_value.symbolic = mem_value.symbolic.extract(load_size_bits - 1, 0);
        }
    
        log!(self.state.logger.clone(), "Dereferenced value: 0x{:x}", mem_value.concrete);
    
        // Create a concolic variable for the dereferenced value
        let dereferenced_concolic = ConcolicVar::new_concrete_and_symbolic_int(
            mem_value.concrete,
            mem_value.symbolic.clone(),
            self.context,
            load_size_bits,
        );
    
        // Determine the output variable and update it with the loaded data
        if let Some(output_varnode) = instruction.output.as_ref() {
            match &output_varnode.var {
                Var::Unique(id) => {
                    log!(self.state.logger.clone(), "Output is a Unique type with ID: 0x{:x}", id);
                    let unique_name = format!("Unique(0x{:x})", id);
                    self.unique_variables.insert(unique_name.clone(), dereferenced_concolic.clone());
                    log!(self.state.logger.clone(), "Updated unique variable: {} with concrete value 0x{:x}", unique_name, dereferenced_concolic.concrete.to_u64());
                },
                Var::Register(offset, _) => {
                    log!(self.state.logger.clone(), "Output is a Register type");
                    let mut cpu_state_guard = self.state.cpu_state.lock().unwrap();
                    match cpu_state_guard.set_register_value_by_offset(*offset, dereferenced_concolic.clone(), load_size_bits) {
                        Ok(_) => {
                            log!(self.state.logger.clone(), "Updated register at offset 0x{:x} with value 0x{:x}", offset, dereferenced_concolic.concrete.to_u64());
                        },
                        Err(e) => {
                            let error_msg = format!("Failed to update register at offset 0x{:x}: {}", offset, e);
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
        
        // Create a concolic variable for the result
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}-{:02}-load", current_addr_hex, self.instruction_counter);
        self.state.create_or_update_concolic_variable_int(&result_var_name, mem_value.concrete, SymbolicVar::Int(mem_value.symbolic.clone()));
        
        Ok(())
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
    
        // update CPU register if the address maps to one
        let mut cpu_state_guard = self.state.cpu_state.lock().unwrap();
        if let Some(_register_value) = cpu_state_guard.get_register_by_offset(pointer_offset_concrete, data_size_bits) {
            match cpu_state_guard.set_register_value_by_offset(pointer_offset_concrete, data_to_store_concolic.to_concolic_var().unwrap(), data_size_bits) {
                Ok(_) => {
                    log!(self.state.logger.clone(), "Updated register at offset 0x{:x} with value 0x{:x}", pointer_offset_concrete, data_to_store_concrete);
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
            return Err("Invalid instruction format for COPY".to_string());
        }
    
        let bit_size = instruction.inputs[0].size.to_bitvector_size() as u32; // size in bits

        // Fetch the branch target (input0)
        log!(self.state.logger.clone(), "* Fetching branch target from instruction.input[0]");
        let source_concolic = self.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
        let source_concrete = source_concolic.get_concrete_value();
        let source_symbolic = match source_concolic {
            ConcolicEnum::ConcolicVar(var) => var.symbolic.to_bv(&self.context),
            ConcolicEnum::CpuConcolicValue(cpu_var) => cpu_var.symbolic.to_bv(self.context),
            ConcolicEnum::MemoryValue(mem_var) => SymbolicVar::Int(mem_var.symbolic).to_bv(&self.context), 
        };
        let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
        log!(self.state.logger.clone(), "Output size in bits: {}", output_size_bits);
    
        let source_concolic = ConcolicVar::new_concrete_and_symbolic_int(source_concrete, source_symbolic.clone(), self.context, output_size_bits);
    
        // Check the output destination and copy the source to it
        if let Some(output_varnode) = instruction.output.as_ref() {
            match &output_varnode.var {
                Var::Unique(id) => {
                    log!(self.state.logger.clone(), "Output is a Unique type");
                    let unique_symbolic = SymbolicVar::Int(BV::new_const(self.context, format!("Unique(0x{:x})", id), output_size_bits));
                    let unique_name = format!("Unique(0x{:x})", id);
                    // Convert source to ConcolicVar if needed and update or insert into unique variables
                    let concolic_var = ConcolicVar::new_concrete_and_symbolic_int(
                        source_concrete,
                        unique_symbolic.to_bv(&self.context),
                        self.context,
                        output_size_bits
                    );
                    self.unique_variables.insert(unique_name.clone(), concolic_var.clone());
                    log!(self.state.logger.clone(), "Content of output {:?} after copying: {:?}", unique_name, concolic_var.concrete);
                },
                Var::Register(offset, _) => {
                    log!(self.state.logger.clone(), "Output is a Register type");
                    let mut cpu_state_guard = self.state.cpu_state.lock().unwrap();
                    let _ = cpu_state_guard.set_register_value_by_offset(*offset, source_concolic, output_size_bits);
                    log!(self.state.logger.clone(), "Updated register at offset 0x{:x}", offset);
                    drop(cpu_state_guard);
                },
                Var::Memory(addr) => {
                    log!(self.state.logger.clone(), "Output is a Memory type at address 0x{:x}", addr);
    
                    // Extract concrete value
                    let concrete_value = source_concolic.concrete.to_u64();
    
                    // Extract symbolic value
                    let symbolic_bv = source_concolic.symbolic.to_bv(self.context);
    
                    // Ensure symbolic value size matches bit_size
                    let symbolic_size = symbolic_bv.get_size();
                    if symbolic_size != bit_size {
                        return Err(format!("Symbolic size {} does not match bit size {}", symbolic_size, bit_size));
                    }
    
                    // Create a MemoryValue
                    let mem_value = MemoryValue {
                        concrete: concrete_value,
                        symbolic: symbolic_bv,
                        size: bit_size,
                    };
    
                    // Write the MemoryValue to memory
                    match self.state.memory.write_value(*addr, &mem_value) {
                        Ok(_) => {
                            log!(self.state.logger.clone(), "Wrote value 0x{:x} to memory at address 0x{:x}", concrete_value, addr);
                            return Ok(());
                        },
                        Err(e) => {
                            let error_msg = format!("Failed to write to memory at address 0x{:x}: {:?}", addr, e);
                            log!(self.state.logger.clone(), "{}", error_msg);
                            return Err(error_msg);
                        }
                    }
                },            
                _ => {
                    log!(self.state.logger.clone(), "Output type is unsupported for COPY");
                    return Err("Output type not supported".to_string());
                }
            }
        } else {
            return Err("No output variable specified for COPY instruction".to_string());
        }
    
        // Create or update a concolic variable for the result
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}-{:02}-copy", current_addr_hex, self.instruction_counter);
        self.state.create_or_update_concolic_variable_int(&result_var_name, source_concrete, SymbolicVar::Int(source_symbolic));
    
        Ok(())
    }    

    // The function to handle POPCOUNT instruction
    pub fn handle_popcount(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::PopCount || instruction.inputs.len() != 1 || instruction.output.is_none() {
            return Err("Invalid instruction format for POPCOUNT".to_string());
        }
    
        // Fetch concolic variable
        log!(self.state.logger.clone(), "* Fetching instruction.input[0] for POPCOUNT");
        let input_var = self.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| {
            log!(self.state.logger.clone(), "Error converting varnode to concolic: {}", e);
            e.to_string()
        })?;

        // Get the size of the output in bits
        let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;

        // Perform the popcount operation
        let result_concrete = input_var.get_concrete_value().count_ones();
        let mut result_symbolic = input_var.to_concolic_var().unwrap().symbolic.popcount();

        // Ensure the result size matches the output size
        result_symbolic = result_symbolic.extract(output_size_bits - 1, 0); // Truncate to output size
        let popcount_result = ConcolicVar::new_concrete_and_symbolic_int(result_concrete as u64, result_symbolic, self.context, output_size_bits);

        // Handle the result based on the output varnode
        self.handle_output(instruction.output.as_ref(), popcount_result.clone())?;
        
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}-{:02}-popcount", current_addr_hex, self.instruction_counter);
        self.state.create_or_update_concolic_variable_int(&result_var_name, popcount_result.concrete.to_u64(), popcount_result.symbolic); 
        
        Ok(())
    }   

    // pub fn handle_lzcount(&mut self, instruction: Inst) -> Result<(), String> {
    //     if instruction.opcode != Opcode::LZCount || instruction.inputs.len() != 1 {
    //         return Err("Invalid instruction format for LZCOUNT".to_string());
    //     }
    
    //     let input_varnode = &instruction.inputs[0];
    //     let input_var = self.initialize_var_if_absent(input_varnode)?;
    
    //     // Perform leading zero count on the concrete value
    //     let lzcount = input_var.leading_zeros() as u64; // leading_zeros returns u32, convert to u64 for consistency
    
    //     if let Some(output_varnode) = &instruction.output {
    //         let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    //         let result_var_name = format!("{}_{:02}_{}", current_addr_hex, self.instruction_counter, format!("{:?}", output_varnode.var));
    //         let bitvector_size = output_varnode.size.to_bitvector_size();
    
    //         //self.state.create_concolic_var_int(&result_var_name, lzcount, bitvector_size);
    //     }
    
    //     Ok(())
    // }    

    // Handle the SUBPIECE operation
    pub fn handle_subpiece(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::SubPiece || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for SUBPIECE".to_string());
        }
    
        log!(self.state.logger.clone(), "* Fetching source data from instruction.input[0] for SUBPIECE");
        let source_concolic = self.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| format!("Failed to fetch source data: {}", e))?;
        let source_value = source_concolic.get_concrete_value();
        let source_symbolic = source_concolic.get_symbolic_value_bv(self.context);
    
        log!(self.state.logger.clone(), "* Fetching truncation offset from instruction.input[1] for SUBPIECE");
        let offset_value = if let Var::Const(value) = &instruction.inputs[1].var {
            value.trim_start_matches("0x").parse::<u32>().map_err(|e| format!("Failed to parse offset value: {}", e))?
        } else {
            return Err("SUBPIECE expects a constant for input1".to_string());
        };
    
        let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
        let byte_offset = offset_value * 8;  // Offset is in bytes, convert to bits
    
        // Check for invalid operations
        if byte_offset >= source_symbolic.get_size() {
            log!(self.state.logger.clone(), "Offset exceeds the size of the source data.");
            return Err("Offset exceeds the size of the source data".to_string());
        }
    
        let truncated_symbolic = source_symbolic.bvlshr(&BV::from_u64(self.context, byte_offset as u64, source_symbolic.get_size()));
        let truncated_concrete = if byte_offset >= 64 {
            0  // If the offset is larger than the size of a u64, the result is zero
        } else {
            source_value >> byte_offset  // Shift right to truncate
        };
    
        log!(self.state.logger.clone(), "Truncated concrete value: 0x{:x}", truncated_concrete);
        log!(self.state.logger.clone(), "Output size in bits: {}", output_size_bits);
    
        let result_value = ConcolicVar::new_concrete_and_symbolic_int(
            truncated_concrete,
            truncated_symbolic,
            self.context,
            output_size_bits
        );
    
        self.handle_output(instruction.output.as_ref(), result_value)?;
    
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}-{:02}-subpiece", current_addr_hex, self.instruction_counter);
        self.state.create_or_update_concolic_variable_int(&result_var_name, truncated_concrete, source_concolic.to_concolic_var().unwrap().symbolic);
    
        Ok(())
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


