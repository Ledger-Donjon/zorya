use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::io::Write;
use std::sync::MutexGuard;
use std::process;

use crate::state::cpu_state::CpuConcolicValue;
use crate::state::memory_x86_64::MemoryConcolicValue;
use crate::state::state_manager::Logger;
use crate::state::CpuState;
use crate::state::MemoryX86_64;
use crate::state::State;
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
            current_address: None,
            instruction_counter: 0,
            unique_variables: BTreeMap::new(),
            pcode_internal_lines_to_be_jumped: 0, // number of lines to skip in case of branch instructions
         })
    }

    pub fn execute_instruction(&mut self, instruction: Inst, current_addr: u64) -> Result<(), String> {
        // Check if we are processing a new address block
        if Some(current_addr) != self.current_address {
            // Reset the unique variables for the new address
            self.unique_variables.clear();

            // Update the current address
            self.current_address = Some(current_addr);
            // Reset the instruction counter for the new address
            self.instruction_counter = 1; // Start counting from 1 for each address block
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
                        self.extract_and_create_concolic_value(&cpu_state_guard, *offset, reg_size, bit_size)
                    }
                } else {
                    log!(self.state.logger.clone(), "No direct register match found at offset 0x{:x}, extraction required", offset);
                    let closest_register = cpu_state_guard.register_map.range(..offset).rev().next()
                        .ok_or(format!("No register found before offset 0x{:x}", offset))?;
                    log!(self.state.logger.clone(), "Closest register found at offset 0x{:x} with size {}", *closest_register.0, closest_register.1 .1);
                    self.extract_and_create_concolic_value(&cpu_state_guard, *offset, closest_register.1 .1, bit_size)
                }
            },
            // Keep track of the unique variables defined inside one address execution
            Var::Unique(id) => {
                log!(self.state.logger.clone(), "Varnode is of type 'unique' with ID: {:x}", id);
                let unique_name = format!("Unique(0x{:x})", id);
                let unique_symbolic = SymbolicVar::Int(BV::new_const(self.context, unique_name.clone(), bit_size));
                let var = self.unique_variables.entry(unique_name.clone())
                    .or_insert_with(|| {
                        log!(self.state.logger.clone(), "Creating new unique variable '{}' with initial value {:x} and size {:?}", unique_name, *id as u64, varnode.size);
                        ConcolicVar::new_concrete_and_symbolic_int(*id as u64, unique_symbolic.to_bv(&self.context), self.context, bit_size)
                    })
                    .clone();
                //log!(self.state.logger.clone(), "Retrieved unique variable: {} with symbolic size: {:?}", var, var.symbolic.get_size());
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
                let memory_var = MemoryConcolicValue::new( self.context, parsed_value, parsed_value_symbolic, bit_size);
                log!(self.state.logger.clone(), "Constant treated as memory address, created or retrieved: {} with symbolic size {:?}", memory_var, memory_var.symbolic.get_size());
                Ok(ConcolicEnum::MemoryConcolicValue(memory_var))
            },
            // Handle MemoryRam case
            Var::MemoryRam => {
                log!(self.state.logger.clone(), "Varnode is MemoryRam");
                let memory_var = MemoryX86_64::get_memory_concolic_var(&self.state.memory, self.context, 0, bit_size); // Assume 0 is the base address for RAM
                log!(self.state.logger.clone(), "MemoryRam treated as general memory space, created or retrieved: {}", memory_var);
                Ok(ConcolicEnum::MemoryConcolicValue(memory_var))
            },
            // Handle specific memory addresses
            Var::Memory(addr) => {
                log!(self.state.logger.clone(), "Varnode is a specific memory address: 0x{:x}", addr);
                let memory_var = MemoryX86_64::get_memory_concolic_var(&self.state.memory, self.context, *addr, bit_size);
                log!(self.state.logger.clone(), "Retrieved memory address: {} with symbolic size: {:?}", memory_var, memory_var.symbolic.get_size());
                Ok(ConcolicEnum::MemoryConcolicValue(memory_var))
            },   
        }
    }

    fn extract_and_create_concolic_value(&self, cpu_state_guard: &MutexGuard<'_, CpuState<'ctx>>, offset: u64, register_size: u32, bit_size: u32) -> Result<ConcolicEnum<'ctx>, String> {
        if register_size == 0 || bit_size > register_size {
            return Err(format!("Cannot extract {} bits from a register of size {} at offset 0x{:x}", bit_size, register_size, offset));
        }
    
        // Calculate base register offset and bit offset within the register
        let base_register_offset = offset - (offset % (register_size / 8) as u64);
        let bit_offset = (offset - base_register_offset) * 8; // Offset within the register, in bits
    
        if (bit_offset + bit_size as u64) > register_size as u64 {
            return Err(format!("Attempted to extract beyond the register's limit at offset 0x{:x}. Total bits requested: {}", offset, bit_offset + bit_size as u64));
        }
    
        let original_register = cpu_state_guard.get_register_by_offset(base_register_offset, register_size)
            .ok_or_else(|| format!("Failed to retrieve register for extraction at offset 0x{:x}", base_register_offset))?;
    
        // Adjust bit_offset for operations exceeding the u64 range
        let safe_bit_offset = if bit_offset >= 64 {
            return Err(format!("Bit offset exceeds 64 bits, resulting in a shift overflow at offset 0x{:x}", offset));
        } else {
            bit_offset
        };
    
        // Calculate mask and perform extraction
        let mask: u64 = if bit_size < 64 {
            (1u64 << bit_size) - 1
        } else {
            u64::MAX
        };
    
        let extracted_value = (original_register.concrete.to_u64() >> safe_bit_offset) & mask;
        let extracted_symbolic = original_register.symbolic.to_bv(&cpu_state_guard.ctx)
            .extract((safe_bit_offset + bit_size as u64 - 1) as u32, safe_bit_offset as u32)
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
        let result_var_name = format!("{}-{:02}-branchind", current_addr_hex, self.instruction_counter);
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
                log!(self.state.logger.clone(), "Branch target concrete : {:x}", addr); 

                // Fetch the branch condition (input1)
                log!(self.state.logger.clone(), "* Fetching branch condition from instruction.input[1]");
                let branch_condition_concolic = self.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;
                let branch_condition_concrete = branch_condition_concolic.get_concrete_value();
                let branch_condition_symbolic = match branch_condition_concolic {
                    ConcolicEnum::ConcolicVar(var) => var.symbolic,
                    ConcolicEnum::CpuConcolicValue(cpu_var) => cpu_var.symbolic,
                    ConcolicEnum::MemoryConcolicValue(mem_var) => mem_var.symbolic,
                };
                log!(self.state.logger.clone(), "Branch condition concrete : {}", branch_condition_concrete);

                let branch_target_concolic = ConcolicVar::new_concrete_and_symbolic_int(*addr, branch_condition_symbolic.to_bv(&self.context), self.context, 64);
            
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
                    ConcolicEnum::MemoryConcolicValue(mem_var) => mem_var.symbolic,
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
    
        // Fetch the offset of the next instruction from the first input
        log!(self.state.logger.clone(), "* Fetching offset of the next instruction from instruction.input[0]");
        let next_instruction_offset_concolic = self.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
        let next_instruction_offset_concrete = next_instruction_offset_concolic.get_concrete_value();
        let next_instruction_offset_symbolic = match next_instruction_offset_concolic {
            ConcolicEnum::ConcolicVar(var) => var.symbolic,
            ConcolicEnum::CpuConcolicValue(cpu_var) => cpu_var.symbolic,
            ConcolicEnum::MemoryConcolicValue(mem_var) => mem_var.symbolic,
        };
        log!(self.state.logger.clone(), "Next instruction offset concrete: {:x}", next_instruction_offset_concrete);
    
        // Perform the branch to the next instruction location
        self.current_address = Some(next_instruction_offset_concrete);
        log!(self.state.logger.clone(), "Branched to next instruction location: {:x}", next_instruction_offset_concrete);
        
        // Create or update a concolic variable for the result of the callind operation (optional, depends on the semantics)
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}-{:02}-callind", current_addr_hex, self.instruction_counter);
        self.state.create_or_update_concolic_variable_int(&result_var_name, next_instruction_offset_concrete, next_instruction_offset_symbolic);
        
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
            ConcolicEnum::MemoryConcolicValue(mem_var) => mem_var.symbolic,
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
    
        // Dereference the address from the CPU registers or memory
        let (dereferenced_concrete_value, dereferenced_symbolic_value) = {
            let cpu_state_guard = self.state.cpu_state.lock().unwrap();
            // Get the size of the input in bits
            let input_size_bits = instruction.inputs[1].size.to_bitvector_size() as u32;
            log!(self.state.logger.clone(), "Input size in bits: {}", input_size_bits);
            // Use the offset directly to retrieve register value
            if let Some(value) = cpu_state_guard.get_register_by_offset(pointer_offset_concrete, input_size_bits) {
                let value_u64 = value.get_concrete_value()?;
                let value_symbolic = value.get_symbolic_value().to_bv(&self.context);
                log!(self.state.logger.clone(), "Dereferenced CPU register value for 0x{:x}: 0x{:x}", pointer_offset_concrete, value_u64);
                (value_u64, value_symbolic)
            } else {
                // If not found in registers, dereference from memory and assemble the 64-bit value from 8 bytes
                let memory_guard = self.state.memory.memory.read().unwrap();
                let mut full_value = 0u64;

                log!(self.state.logger.clone(), "Starting assembly of 64-bit value from memory starting at 0x{:x}", pointer_offset_concrete);

                for i in 0..8 {
                    // Calculate the address of each byte by adding the offset to the base address
                    let byte_address = pointer_offset_concrete + i as u64;
                    log!(self.state.logger.clone(), "Calculating byte address: 0x{:x} + {} = 0x{:x}", pointer_offset_concrete, i, byte_address);

                    // Retrieve the byte value from the memory, or use 0 if the byte is not found
                    let byte_value = memory_guard.get(&byte_address).map_or(0, |v| {
                        let concrete_value = v.concrete.to_u64() as u64;
                        log!(self.state.logger.clone(), "Retrieved byte value from address 0x{:x}: 0x{:x}", byte_address, concrete_value);
                        concrete_value
                    });

                    // Assemble the 64-bit value by shifting each byte value to the appropriate position
                    log!(self.state.logger.clone(), "Shifting byte value 0x{:x} left by {} bits", byte_value, 8 * i);
                    full_value |= byte_value << (8 * i);
                    log!(self.state.logger.clone(), "Intermediate 64-bit value: 0x{:x}", full_value);
                }

                // Log the assembled 64-bit value from memory
                log!(self.state.logger.clone(), "Assembled 64-bit value from memory starting at 0x{:x}: 0x{:x}", pointer_offset_concrete, full_value);

                let symbolic_value = BV::from_u64(self.context, full_value, 64);
                (full_value, symbolic_value)

            }
        };

        log!(self.state.logger.clone(), "Dereferenced value: 0x{:x}", dereferenced_concrete_value);
        let dereferenced_concolic = ConcolicVar::new_concrete_and_symbolic_int(dereferenced_concrete_value, dereferenced_symbolic_value, self.context, 64);
    
        // Determine the output variable and update it with the loaded data
        if let Some(output_varnode) = instruction.output.as_ref() {
            match &output_varnode.var {
                Var::Unique(id) => {
                    log!(self.state.logger.clone(), "Output is a Unique type with ID: 0x{:x}", id);
                    let unique_symbolic = SymbolicVar::Int(BV::from_u64(self.context, *id, output_varnode.size.to_bitvector_size()));
                    let concolic_var = ConcolicVar::new_concrete_and_symbolic_int(
                        dereferenced_concrete_value,
                        unique_symbolic.to_bv(&self.context),
                        self.context,
                        output_varnode.size.to_bitvector_size(),
                    );
                    let unique_name = format!("Unique(0x{:x})", id);
                    self.unique_variables.insert(unique_name.clone(), concolic_var.clone());
                },
                Var::Register(offset, _) => {
                    log!(self.state.logger.clone(), "Output is a Register type");
                    let mut cpu_state_guard = self.state.cpu_state.lock().unwrap();
                    // Use offset directly to set the register value
                    let _ = cpu_state_guard.set_register_value_by_offset(*offset, dereferenced_concolic, output_varnode.size.to_bitvector_size());
                    log!(self.state.logger.clone(), "Updated register at offset 0x{:x} with value 0x{:x}", offset, dereferenced_concrete_value);
                },
                _ => {
                    log!(self.state.logger.clone(), "Output type is unsupported");
                    return Err("Output type not supported".to_string());
                }
            }
        } else {
            return Err("No output variable specified for LOAD instruction".to_string());
        }
        
        // Create a concolic variable for the result
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}-{:02}-load", current_addr_hex, self.instruction_counter);
        self.state.create_or_update_concolic_variable_int(&result_var_name, dereferenced_concrete_value, SymbolicVar::Int(BV::from_u64(self.context, dereferenced_concrete_value, 64)));
        
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
        let data_to_store_concrete = match &data_to_store_var.var {
            Var::Const(value) => {
                let parsed_value = u128::from_str_radix(&value.trim_start_matches("0x"), 16).map_err(|e| e.to_string())?;
                log!(self.state.logger.clone(), "Data to store is a constant with value: 0x{:x}", parsed_value);
                parsed_value
            },
            _ => {
                let data_var = self.varnode_to_concolic(data_to_store_var).map_err(|e| e.to_string())?;
                data_var.get_concrete_value() as u128
            }
        };
    
        // Convert data to symbolic form and create concolic value
        let data_size_bits = data_to_store_var.size.to_bitvector_size() as u32;
        let data_to_store_symbolic = BV::from_u64(self.context, data_to_store_concrete as u64, data_size_bits);
        let data_to_store_concolic = ConcolicVar::new_concrete_and_symbolic_int(data_to_store_concrete as u64, data_to_store_symbolic, self.context, data_size_bits);
    
        log!(self.state.logger.clone(), "Data to store concrete: {:x}", data_to_store_concrete);
    
        // Store the data in memory, handling each byte
        let mut memory_guard = self.state.memory.memory.write().unwrap();
        let total_bytes = (data_size_bits / 8) as u64;
        for i in 0..total_bytes {
            let byte_address = pointer_offset_concrete.checked_add(i).ok_or_else(|| "Address calculation overflow".to_string())?;
            let byte_value = ((data_to_store_concrete >> (8 * i)) & 0xFF) as u8; // Extract each byte
            let byte_value_symbolic = BV::from_u64(self.context, byte_value as u64, 8);
            memory_guard.insert(byte_address, MemoryConcolicValue::new(self.context, byte_value as u64, byte_value_symbolic, 8));
            log!(self.state.logger.clone(), "Stored byte 0x{:x} at offset 0x{:x}", byte_value, byte_address);
        }
    
        // Optionally update CPU register if the address maps to one
        let mut cpu_state_guard = self.state.cpu_state.lock().unwrap();
        if let Some(_register_value) = cpu_state_guard.get_register_by_offset(pointer_offset_concrete, data_size_bits) {
            cpu_state_guard.set_register_value_by_offset(pointer_offset_concrete, data_to_store_concolic, data_size_bits)?;
            log!(self.state.logger.clone(), "Updated register at offset 0x{:x} with value 0x{:x}", pointer_offset_concrete, data_to_store_concrete);
        }
        drop(memory_guard);
        drop(cpu_state_guard);

        // Record the operation for traceability
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}-{:02}-store", current_addr_hex, self.instruction_counter);
        self.state.create_or_update_concolic_variable_int(&result_var_name, data_to_store_concrete as u64, SymbolicVar::Int(BV::from_u64(self.context, data_to_store_concrete as u64, data_size_bits)));
    
        Ok(())
    }
    

    pub fn handle_copy(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::Copy || instruction.inputs.len() != 1 {
            return Err("Invalid instruction format for COPY".to_string());
        }
    
        let cpu_state_guard = self.state.cpu_state.lock().unwrap();
        let bit_size = instruction.inputs[0].size.to_bitvector_size() as u32; // size in bits
        let byte_count = (bit_size / 8) as usize;

        let (source_concrete_value, source_symbolic_value) = match &instruction.inputs[0].var {
            Var::Register(offset, _) => {
                log!(self.state.logger.clone(), "Varnode is a CPU register with offset: 0x{:x} and requested bit size: {}", offset, bit_size);
    
                if let Some(&(ref _name, reg_size)) = cpu_state_guard.register_map.get(offset) {
                    if reg_size == bit_size {
                        log!(self.state.logger.clone(), "Directly processing register found in register_map with matching size at offset 0x{:x}", offset);
                        let cpu_concolic_value = cpu_state_guard.get_register_by_offset(*offset, reg_size)
                            .ok_or_else(|| format!("Failed to retrieve register by offset 0x{:x}", offset))?;
                        (cpu_concolic_value.get_concrete_value().unwrap(), cpu_concolic_value.get_symbolic_value().to_bv(&self.context))
                    } else {
                        log!(self.state.logger.clone(), "Register at offset 0x{:x} exists but with size {} bits, needs {} bits, extraction needed", offset, reg_size, bit_size);
                        let result = self.extract_and_create_concolic_value(&cpu_state_guard, *offset, reg_size, bit_size).unwrap();
                        (result.get_concrete_value(), result.get_symbolic_value_bv(&self.context))
                    }
                } else {
                    log!(self.state.logger.clone(), "No direct register match found at offset 0x{:x}, extraction required", offset);
                    // Find the closest register that is less than the provided offset
                    let closest_register = cpu_state_guard.register_map.range(..offset).rev().next()
                        .ok_or(format!("No register found before offset 0x{:x}", offset))?;
                    log!(self.state.logger.clone(), "Closest register found at offset 0x{:x} with size {}", *closest_register.0, closest_register.1 .1);
                    
                    let result = self.extract_and_create_concolic_value(&cpu_state_guard, *offset, closest_register.1 .1, bit_size).unwrap();
                    (result.get_concrete_value(), result.get_symbolic_value_bv(&self.context))
                }
            },
            Var::Unique(id) => {
                log!(self.state.logger.clone(), "Varnode is of type 'unique' with ID: {:x}", id);
                let unique_name = format!("Unique(0x{:x})", id);
                let unique_symbolic = SymbolicVar::Int(BV::new_const(self.context, unique_name.clone(), bit_size));
                let var = self.unique_variables.entry(unique_name.clone())
                    .or_insert_with(|| {
                        log!(self.state.logger.clone(), "Creating new unique variable '{}' with initial value {:x} and size {:?}", unique_name, *id as u64, instruction.inputs[0].size);
                        ConcolicVar::new_concrete_and_symbolic_int(*id as u64, unique_symbolic.to_bv(&self.context), self.context, bit_size)
                    })
                    .clone();
                (var.concrete.to_u64(), var.symbolic.to_bv(&self.context))
            },
            Var::Const(value) => {
                log!(self.state.logger.clone(), "Varnode is a constant with value: {}", value);
                let parsed_value = if value.starts_with("0x") {
                    u64::from_str_radix(&value[2..], 16)
                } else {
                    value.parse::<u64>()
                }.map_err(|e| format!("Failed to parse value '{}' as u64: {}", value, e))?;
                log!(self.state.logger.clone(), "Parsed value: {}", parsed_value);
                let parsed_value_symbolic = BV::from_u64(self.context, parsed_value, bit_size);
                let memory_var = MemoryConcolicValue::new(self.context, parsed_value, parsed_value_symbolic, bit_size);
                log!(self.state.logger.clone(), "Constant treated as memory address, created or retrieved: {} with symbolic size {:?}", memory_var, memory_var.symbolic.get_size());
                (memory_var.concrete.to_u64(), memory_var.symbolic.to_bv(&self.context))
            },
            Var::MemoryRam => {
                log!(self.state.logger.clone(), "Varnode is MemoryRam");
                let memory_var = MemoryX86_64::get_memory_concolic_var(&self.state.memory, self.context, 0, bit_size); // Assume 0 is the base address for RAM
                log!(self.state.logger.clone(), "MemoryRam treated as general memory space, created or retrieved: {}", memory_var);
                (memory_var.concrete.to_u64(), memory_var.symbolic.to_bv(&self.context))
            },
            Var::Memory(addr) => {
                log!(self.state.logger.clone(), "Varnode is a specific memory address: 0x{:x}", addr);
                let memory_bytes = self.state.memory.read_memory(*addr, byte_count)
                    .unwrap_or_else(|_| vec![0; byte_count]); // Provide default bytes if read fails
    
                let padded_bytes = if memory_bytes.len() < 8 {
                    log!(self.state.logger.clone(), "Padding memory read with zeros to fit u64.");
                    memory_bytes.clone().into_iter().chain(std::iter::repeat(0).take(8 - memory_bytes.len())).collect::<Vec<_>>()
                } else {
                    memory_bytes[0..8].to_vec() // Ensure no more than 8 bytes are taken
                };
    
                let concrete_value = u64::from_le_bytes(padded_bytes.try_into().unwrap()); // This should now always be valid
                let symbolic_value = BV::from_u64(self.context, concrete_value, bit_size);
                (concrete_value, symbolic_value)
            },
        };
    
        let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
        log!(self.state.logger.clone(), "Output size in bits: {}", output_size_bits);
    
        let source_concolic = ConcolicVar::new_concrete_and_symbolic_int(source_concrete_value, source_symbolic_value.clone(), self.context, output_size_bits);
    
        drop(cpu_state_guard);
        // Check the output destination and copy the source to it
        if let Some(output_varnode) = instruction.output.as_ref() {
            match &output_varnode.var {
                Var::Unique(id) => {
                    log!(self.state.logger.clone(), "Output is a Unique type");
                    let unique_symbolic = SymbolicVar::Int(BV::new_const(self.context, format!("Unique(0x{:x})", id), output_size_bits));
                    let unique_name = format!("Unique(0x{:x})", id);
                    // Convert source to ConcolicVar if needed and update or insert into unique variables
                    let concolic_var = ConcolicVar::new_concrete_and_symbolic_int(
                        source_concrete_value,
                        unique_symbolic.to_bv(&self.context),
                        self.context,
                        output_size_bits
                    );
                    self.unique_variables.insert(unique_name.clone(), concolic_var.clone());
                    //log!(self.state.logger.clone(), "Content of output {:?} after copying: {:?}", unique_name, concolic_var);
                },
                Var::Register(offset, _) => {
                    log!(self.state.logger.clone(), "Output is a Register type");
                    let mut cpu_state_guard = self.state.cpu_state.lock().unwrap();
                    let _ = cpu_state_guard.set_register_value_by_offset(*offset, source_concolic, output_size_bits);
                    log!(self.state.logger.clone(), "Updated register at offset 0x{:x}", offset);
                    drop(cpu_state_guard);
                },
                Var::Memory(addr) => {
                    log!(self.state.logger.clone(), "Output is a Memory type");
                    let mut memory_guard = self.state.memory.memory.write().unwrap();
                    let memory_var = MemoryConcolicValue::new(self.context, source_concrete_value, source_symbolic_value.clone(), output_size_bits);
                    memory_guard.insert(*addr, memory_var);
                    log!(self.state.logger.clone(), "Updated memory at address 0x{:x}", addr);
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
        self.state.create_or_update_concolic_variable_int(&result_var_name, source_concrete_value, SymbolicVar::Int(source_symbolic_value));
    
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

        // Get the size of the input and output in bits
        let input_size_bits = instruction.inputs[0].size.to_bitvector_size() as u32;
        log!(self.state.logger.clone(), "Input size in bits: {}", input_size_bits);
        let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
        log!(self.state.logger.clone(), "Output size in bits: {}", output_size_bits);
    
        let popcount_result = match input_var {
            ConcolicEnum::ConcolicVar(concolic_var) => {
                let concrete_value = concolic_var.concrete.to_u64();
                let popcount = concrete_value.count_ones() as u64;
                log!(self.state.logger.clone(), "Concrete value: {}, Popcount: {}", concrete_value, popcount);
                let symbolic_value = concolic_var.popcount();
                ConcolicVar::new_concrete_and_symbolic_int(popcount, symbolic_value, self.context, output_size_bits)
            },
            ConcolicEnum::CpuConcolicValue(cpu_var) => {
                let concrete_value = cpu_var.get_concrete_value().unwrap_or(0);
                let popcount = concrete_value.count_ones() as u64;
                log!(self.state.logger.clone(), "CPU concrete value: {}, Popcount: {}", concrete_value, popcount);
                let symbolic_value = cpu_var.popcount();
                ConcolicVar::new_concrete_and_symbolic_int(popcount, symbolic_value, self.context, output_size_bits)
            },
            ConcolicEnum::MemoryConcolicValue(mem_var) => {
                let concrete_value = mem_var.get_concrete_value().unwrap_or(0);
                let popcount = concrete_value.count_ones() as u64;
                log!(self.state.logger.clone(), "Memory concrete value: {}, Popcount: {}", concrete_value, popcount);
                let symbolic_value = mem_var.popcount();
                ConcolicVar::new_concrete_and_symbolic_int(popcount, symbolic_value, self.context, output_size_bits)
            },
        };
    
        //log!(self.state.logger.clone(), "*** The result of POPCOUNT is: {:?}", popcount_result.clone());
    
        match instruction.output.as_ref().map(|v| &v.var) {
            Some(Var::Unique(id)) => {
                let unique_name = format!("Unique(0x{:x})", id);
                self.unique_variables.insert(unique_name.clone(), popcount_result.clone());
                log!(self.state.logger.clone(), "Updated unique variable: {} with concrete size {:?} and symbolic size {:?}", unique_name, popcount_result.concrete.get_size(), popcount_result.symbolic.get_size());
            },
            Some(Var::Register(offset, _)) => {
                log!(self.state.logger.clone(), "Output is a Register type");
                let mut cpu_state_guard = self.state.cpu_state.lock().unwrap();
                let concrete_value = popcount_result.concrete.to_u64();
                log!(self.state.logger.clone(), "Setting register value at offset 0x{:x} to {}", offset, concrete_value);
                let set_result = cpu_state_guard.set_register_value_by_offset(*offset, popcount_result.clone(), output_size_bits);
                match set_result {
                    Ok(_) => {
                        let updated_value = cpu_state_guard.get_register_by_offset(*offset, input_size_bits).unwrap();
                        if updated_value.get_concrete_value()? == concrete_value {
                            log!(self.state.logger.clone(), "Successfully updated register at offset 0x{:x} with value {}", offset, updated_value);
                        } else {
                            log!(self.state.logger.clone(), "Failed to verify updated register at offset 0x{:x}", offset);
                            return Err(format!("Failed to verify updated register value at offset 0x{:x}", offset));
                        }
                    },
                    Err(e) => {
                        log!(self.state.logger.clone(), "Failed to set register value: {}", e);
                        return Err(format!("Failed to set register value at offset 0x{:x}", offset));
                    }
                }
            },
            _ => {
                log!(self.state.logger.clone(), "Output type is unsupported");
                return Err("Output type not supported".to_string());
            }
        }
        
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
    
    pub fn handle_output(&mut self, output_varnode: Option<&Varnode>, mut result_value: ConcolicVar<'ctx>) -> Result<(), String> {
        if let Some(varnode) = output_varnode {
            // Resize the result_value according to the output size specification
            let size_bits = varnode.size.to_bitvector_size() as u32;
            result_value.resize(size_bits);

            match &varnode.var {
                Var::Unique(id) => {
                    let unique_name = format!("Unique(0x{:x})", id);
                    self.unique_variables.insert(unique_name, result_value.clone());
                    log!(self.state.logger.clone(), "Updated unique variable: Unique(0x{:x}) with concrete size {} bits, symbolic size {} bits", id, size_bits, result_value.symbolic.get_size());
                    Ok(())
                },
                Var::Register(offset, _) => {
                    log!(self.state.logger.clone(), "Output is a Register type");
                    let mut cpu_state_guard = self.state.cpu_state.lock().unwrap();
                    let concrete_value = result_value.concrete.to_u64();
    
                    match cpu_state_guard.set_register_value_by_offset(*offset, result_value.clone(), size_bits) {
                        Ok(_) => {
                            log!(self.state.logger.clone(), "Updated register at offset 0x{:x} with value 0x{:x}, size {} bits", offset, concrete_value, size_bits);
                            Ok(())
                        },
                        Err(e) => {
                            log!(self.state.logger.clone(), "Error updating register at offset 0x{:x}: {}", offset, e);
                            let closest_offset = cpu_state_guard.registers.keys().rev().find(|&&key| key <= *offset);
                            if let Some(&base_offset) = closest_offset {
                                let diff = *offset - base_offset;
                                let full_reg_size = cpu_state_guard.register_map.get(&base_offset).map(|&(_, size)| size).unwrap_or(64);
    
                                if (diff * 8 + size_bits as u64 > 64) {
                                    return Err(format!("Shift calculation exceeds 64 bits at offset 0x{:x}", offset));
                                }
    
                                let mask = if size_bits < 64 {
                                    ((1u64 << size_bits) - 1) << (diff * 8)
                                } else {
                                    u64::MAX
                                };
    
                                let new_value = (concrete_value & mask) | (concrete_value << (diff * 8));
                                cpu_state_guard.set_register_value_by_offset(base_offset, ConcolicVar::new_concrete_and_symbolic_int(new_value, result_value.symbolic.to_bv(&self.context).clone(), self.context, full_reg_size), full_reg_size)?;
    
                                log!(self.state.logger.clone(), "Updated sub-register at offset 0x{:x} with value 0x{:x}, size {} bits", offset, new_value, size_bits);
                                Ok(())
                            } else {
                                Err(format!("No suitable register found for offset 0x{:x}", offset))
                            }
                        }
                    }
                },
                _ => {
                    log!(self.state.logger.clone(), "Output type is unsupported");
                    Err("Output type not supported".to_string())
                }
            }
        } else {
            Err("No output varnode specified".to_string())
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


