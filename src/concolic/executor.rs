use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use crate::state::memory_x86_64::MemoryConcolicValue;
use crate::state::MemoryX86_64;
use crate::state::State;
use parser::parser::{Inst, Opcode, Var, Varnode};
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
    pub logger: Logger,
}

impl<'ctx> ConcolicExecutor<'ctx> {
    pub fn new(context: &'ctx Context, logger: Logger) -> Result<Self, Box<dyn Error>> {
        let solver = Solver::new(context);
        let state = State::new(context)?;
        Ok(ConcolicExecutor {
            context,
            solver,
            state,
            current_address: None,
            instruction_counter: 0,
            unique_variables: BTreeMap::new(),
            logger,
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

        let _ = match instruction.opcode {
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
            Opcode::LZCount => self.handle_lzcount(instruction),
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
            Opcode::Float2Float => executor_float::handle_float2float(self, instruction),
            Opcode::FloatAbs => executor_float::handle_float_abs(self, instruction),
            Opcode::FloatAdd => executor_float::handle_float_add(self, instruction),
            Opcode::FloatDiv => executor_float::handle_float_div(self, instruction),
            Opcode::FloatEqual => executor_float::handle_float_equal(self, instruction),
            Opcode::FloatLess => executor_float::handle_float_less(self, instruction),
            Opcode::FloatLessEqual => executor_float::handle_float_lessequal(self, instruction),
            Opcode::FloatMult => executor_float::handle_float_mult(self, instruction),
            Opcode::FloatNaN => executor_float::handle_float_nan(self, instruction),
            Opcode::FloatNeg => executor_float::handle_float_neg(self, instruction),
            Opcode::FloatNotEqual => executor_float::handle_float_notequal(self, instruction),
            Opcode::FloatSqrt => executor_float::handle_float_sqrt(self, instruction),
            Opcode::FloatSub => executor_float::handle_float_sub(self, instruction),
            Opcode::FloatFloor => executor_float::handle_float_floor(self, instruction),

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
            Opcode::IntNotEqual => executor_int::handle_int_not_equal(self, instruction),
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
        };
        Ok(())
    }

    // Transform the varnode.var into a concolic object in zorya
    pub fn varnode_to_concolic(&mut self, varnode: &Varnode) -> Result<ConcolicEnum<'ctx>, String> {
        let mut cpu_state_guard = self.state.cpu_state.lock().unwrap();

        log!(self.logger.clone(), "Converting Varnode to concolic type: {:?}", varnode.var);

        match &varnode.var {
            // It is a CPU register address
            Var::Register(offset, _) => {
                log!(self.logger.clone(), "Varnode is a CPU register with offset: {:x}", offset);
                // Using the offset directly to get or initialize the register
                let register = cpu_state_guard.get_or_init_register_by_offset(*offset);
                log!(self.logger.clone(), "Retrieved register: {}", register);
                Ok(ConcolicEnum::CpuConcolicValue(register.clone()))
            },
            // Keep track of the unique variables defined inside one address execution
            Var::Unique(id) => {
                log!(self.logger.clone(), "Varnode is of type 'unique' with ID: {:x}", id);
                let unique_name = format!("Unique(0x{:x})", id);
                let var = self.unique_variables.entry(unique_name.clone())
                    .or_insert_with(|| {
                        log!(self.logger.clone(), "Creating new unique variable '{}' with initial value {} and size {:?}", unique_name, *id as u64, varnode.size);
                        ConcolicVar::new_concrete_and_symbolic_int(*id as u64, &unique_name, self.context, varnode.size as u32)
                    })
                    .clone();
                log!(self.logger.clone(), "Retrieved unique variable: {} with symbolic size: {:?}", var, var.symbolic.get_size());
                Ok(ConcolicEnum::ConcolicVar(var))
            },
            Var::Const(value) => {
                log!(self.logger.clone(), "Varnode is a constant with value: {}", value);
                // Improved parsing that handles hexadecimal values prefixed with '0x'
                let parsed_value = if value.starts_with("0x") {
                    u64::from_str_radix(&value[2..], 16)
                } else {
                    value.parse::<u64>()
                }.map_err(|e| format!("Failed to parse value '{}' as u64: {}", value, e))?;
                log!(self.logger.clone(), "parsed value: {}", parsed_value);
                let memory_var = MemoryX86_64::get_or_create_memory_concolic_var(&self.state.memory, self.context, parsed_value);
                log!(self.logger.clone(), "Constant treated as memory address, created or retrieved: {:?}", memory_var);
                Ok(ConcolicEnum::MemoryConcolicValue(memory_var))
            },
            // Handle MemoryRam case
            Var::MemoryRam => {
                log!(self.logger.clone(), "Varnode is MemoryRam");
                let memory_var = MemoryX86_64::get_or_create_memory_concolic_var(&self.state.memory, self.context, 0); // Assume 0 is the base address for RAM
                log!(self.logger.clone(), "MemoryRam treated as general memory space, created or retrieved: {:?}", memory_var);
                Ok(ConcolicEnum::MemoryConcolicValue(memory_var))
            },
            // Handle specific memory addresses
            Var::Memory(addr) => {
                log!(self.logger.clone(), "Varnode is a specific memory address: 0x{:x}", addr);
                let memory_var = MemoryX86_64::get_or_create_memory_concolic_var(&self.state.memory, self.context, *addr);
                log!(self.logger.clone(), "Retrieved memory address: {}", memory_var);
                Ok(ConcolicEnum::MemoryConcolicValue(memory_var))
            },
        }
    }

    // Handle branch operation
    pub fn handle_branch(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::Branch || instruction.inputs.len() != 1 {
            return Err("Invalid instruction format for BRANCH".to_string());
        }

        // Fetch the branch target (input0) and condition (input1)
        log!(self.logger.clone(), "* Fetching branch target from instruction.input[0]");
        let branch_target_concolic = self.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
        let branch_target_concrete = branch_target_concolic.get_concrete_value();
        let branch_target_symbolic = match branch_target_concolic {
            ConcolicEnum::ConcolicVar(var) => var.symbolic,
            ConcolicEnum::CpuConcolicValue(cpu_var) => cpu_var.symbolic,
            ConcolicEnum::MemoryConcolicValue(mem_var) => mem_var.symbolic,
        };
        log!(self.logger.clone(), "Branch target concrete : {:x}", branch_target_concrete); 

        log!(self.logger.clone(), "Branching to address {:x}", branch_target_concrete);
        // Update the RIP register to the branch target address
        {
        let mut cpu_state_guard = self.state.cpu_state.lock().unwrap();
        cpu_state_guard.set_register_value_by_offset(0x288, branch_target_concrete).map_err(|e| e.to_string())?;
        }
        // Update the instruction counter
        self.instruction_counter += 1;

        log!(self.logger.clone(), "{}\n", self);

        // Create or update a concolic variable for the result (CBRANCH doesn't produce a result, but we log the branch decision)
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}-{:02}-branch", current_addr_hex, self.instruction_counter);

        // Move the mutable borrow outside of the block
        self.state.create_or_update_concolic_variable_int(&result_var_name, branch_target_concrete, branch_target_symbolic);

        log!(self.logger.clone(), "{}", self.state);

        Ok(())
    } 
    
    // Handle indirect branch operation
    pub fn handle_branchind(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::BranchInd || instruction.inputs.len() != 1 {
            return Err("Invalid instruction format for BRANCHIND".to_string());
        }

        // Fetch the branch target (input0)
        log!(self.logger.clone(), "* Fetching branch target from instruction.input[0]");
        let branch_target_concolic = self.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
        let branch_target_concrete = branch_target_concolic.get_concrete_value();
        let branch_target_symbolic = match branch_target_concolic {
            ConcolicEnum::ConcolicVar(var) => var.symbolic,
            ConcolicEnum::CpuConcolicValue(cpu_var) => cpu_var.symbolic,
            ConcolicEnum::MemoryConcolicValue(mem_var) => mem_var.symbolic,
        };
        log!(self.logger.clone(), "Branch target concrete : {:x}", branch_target_concrete);

        log!(self.logger.clone(), "Branching to address {:x}", branch_target_concrete);
        // Update the RIP register to the branch target address
        {
            let mut cpu_state_guard = self.state.cpu_state.lock().unwrap();
            cpu_state_guard.set_register_value_by_offset(0x288, branch_target_concrete).map_err(|e| e.to_string())?;
        }
        // Update the instruction counter
        self.instruction_counter += 1;

        log!(self.logger.clone(), "{}\n", self);

        // Create or update a concolic variable for the result (BRANCHIND doesn't produce a result, but we log the branch decision)
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}-{:02}-branchind", current_addr_hex, self.instruction_counter);
        self.state.create_or_update_concolic_variable_int(&result_var_name, branch_target_concrete, branch_target_symbolic);

        log!(self.logger.clone(), "{}", self.state);

        Ok(())
    }
 
    // Handle conditional branch operation
    pub fn handle_cbranch(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::CBranch || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for CBRANCH".to_string());
        }

        // Fetch the branch target (input0) and condition (input1)
        log!(self.logger.clone(), "* Fetching branch target from instruction.input[0]");
        let branch_target_concolic = self.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
        let branch_target_concrete = branch_target_concolic.get_concrete_value();
        log!(self.logger.clone(), "Branch target concrete : {:x}", branch_target_concrete);

        log!(self.logger.clone(), "* Fetching branch condition from instruction.input[1]");
        let branch_condition_concolic = self.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;
        let branch_condition_concrete = branch_condition_concolic.get_concrete_value();
        let branch_condition_symbolic = match branch_condition_concolic {
            ConcolicEnum::ConcolicVar(var) => var.symbolic,
            ConcolicEnum::CpuConcolicValue(cpu_var) => cpu_var.symbolic,
            ConcolicEnum::MemoryConcolicValue(mem_var) => mem_var.symbolic,
        };
        log!(self.logger.clone(), "Branch condition concrete : {}", branch_condition_concrete);

        // Check the branch condition
        if branch_condition_concrete != 0 {
            log!(self.logger.clone(), "Branch condition is true, branching to address {:x}", branch_target_concrete);
            // Update the RIP register to the branch target address
            let mut cpu_state_guard = self.state.cpu_state.lock().unwrap();
            cpu_state_guard.set_register_value_by_offset(0x288, branch_target_concrete).map_err(|e| e.to_string())?;
        } else {
            log!(self.logger.clone(), "Branch condition is false, continuing to next instruction");
        }

        // Update the instruction counter
        self.instruction_counter += 1;

        log!(self.logger.clone(), "{}\n", self);

        // Create or update a concolic variable for the result (CBRANCH doesn't produce a result, but we log the branch decision)
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}-{:02}-cbranch", current_addr_hex, self.instruction_counter);
        self.state.create_or_update_concolic_variable_int(&result_var_name, branch_condition_concrete, branch_condition_symbolic);

        log!(self.logger.clone(), "{}", self.state);

        Ok(())
    } 
    
    pub fn handle_call(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::Call || instruction.inputs.len() < 1 {
            return Err("Invalid instruction format for CALL".to_string());
        }
    
        // Fetch the location of the next instruction to execute
        log!(self.logger.clone(), "* Fetching next instruction location from instruction.input[0]");
        let next_instruction_location_concolic = self.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
        let next_instruction_location_concrete = next_instruction_location_concolic.get_concrete_value();
        let next_instruction_location_symbolic = match next_instruction_location_concolic {
            ConcolicEnum::ConcolicVar(var) => var.symbolic,
            ConcolicEnum::CpuConcolicValue(cpu_var) => cpu_var.symbolic,
            ConcolicEnum::MemoryConcolicValue(mem_var) => mem_var.symbolic,
        };
        log!(self.logger.clone(), "Next instruction location concrete: {:x}", next_instruction_location_concrete);
    
        // Perform the branch to the next instruction location
        self.current_address = Some(next_instruction_location_concrete);
        log!(self.logger.clone(), "Branched to next instruction location: {:x}", next_instruction_location_concrete);
    
        log!(self.logger.clone(), "{}\n", self);
    
        // Create or update a concolic variable for the result of the call operation (optional, depends on the semantics)
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}-{:02}-call", current_addr_hex, self.instruction_counter);
        self.state.create_or_update_concolic_variable_int(&result_var_name, next_instruction_location_concrete, next_instruction_location_symbolic);
    
        log!(self.logger.clone(), "{}", self.state);
    
        Ok(())
    } 
    
    pub fn handle_callind(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::CallInd || instruction.inputs.len() < 1 {
            return Err("Invalid instruction format for CALLIND".to_string());
        }
    
        // Fetch the offset of the next instruction from the first input
        log!(self.logger.clone(), "* Fetching offset of the next instruction from instruction.input[0]");
        let next_instruction_offset_concolic = self.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
        let next_instruction_offset_concrete = next_instruction_offset_concolic.get_concrete_value();
        let next_instruction_offset_symbolic = match next_instruction_offset_concolic {
            ConcolicEnum::ConcolicVar(var) => var.symbolic,
            ConcolicEnum::CpuConcolicValue(cpu_var) => cpu_var.symbolic,
            ConcolicEnum::MemoryConcolicValue(mem_var) => mem_var.symbolic,
        };
        log!(self.logger.clone(), "Next instruction offset concrete: {:x}", next_instruction_offset_concrete);
    
        // Perform the branch to the next instruction location
        self.current_address = Some(next_instruction_offset_concrete);
        log!(self.logger.clone(), "Branched to next instruction location: {:x}", next_instruction_offset_concrete);
    
        log!(self.logger.clone(), "{}\n", self);
    
        // Create or update a concolic variable for the result of the callind operation (optional, depends on the semantics)
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}-{:02}-callind", current_addr_hex, self.instruction_counter);
        self.state.create_or_update_concolic_variable_int(&result_var_name, next_instruction_offset_concrete, next_instruction_offset_symbolic);
    
        log!(self.logger.clone(), "{}", self.state);
    
        Ok(())
    }
    
    // Handle return operation
    pub fn handle_return(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::BranchInd || instruction.inputs.len() != 1 {
            return Err("Invalid instruction format for BRANCHIND".to_string());
        }

        // Fetch the branch target (input0)
        log!(self.logger.clone(), "* Fetching branch target from instruction.input[0]");
        let branch_target_concolic = self.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
        let branch_target_concrete = branch_target_concolic.get_concrete_value();
        let branch_target_symbolic = match branch_target_concolic {
            ConcolicEnum::ConcolicVar(var) => var.symbolic,
            ConcolicEnum::CpuConcolicValue(cpu_var) => cpu_var.symbolic,
            ConcolicEnum::MemoryConcolicValue(mem_var) => mem_var.symbolic,
        };
        log!(self.logger.clone(), "Branch target concrete : {:x}", branch_target_concrete);

        log!(self.logger.clone(), "Branching to address {:x}", branch_target_concrete);
        // Update the RIP register to the branch target address
        {
            let mut cpu_state_guard = self.state.cpu_state.lock().unwrap();
            cpu_state_guard.set_register_value_by_offset(0x288, branch_target_concrete).map_err(|e| e.to_string())?;
        }
        // Update the instruction counter
        self.instruction_counter += 1;

        log!(self.logger.clone(), "{}\n", self);

        // Create or update a concolic variable for the result (BRANCHIND doesn't produce a result, but we log the branch decision)
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}-{:02}-return", current_addr_hex, self.instruction_counter);
        self.state.create_or_update_concolic_variable_int(&result_var_name, branch_target_concrete, branch_target_symbolic);

        log!(self.logger.clone(), "{}", self.state);

        Ok(())
    }    

    pub fn handle_load(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::Load || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for LOAD".to_string());
        }
    
        log!(self.logger.clone(), "* FYI, the space ID is not used during zorya execution.");
        log!(self.logger.clone(), "* Fetching pointer offset from instruction.input[1]");
    
        let pointer_offset_concolic = self.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;
        let pointer_offset_concrete = pointer_offset_concolic.get_concrete_value();
        log!(self.logger.clone(), "pointer offset concrete : {:x}", pointer_offset_concrete);
    
        // Attempt to dereference the address from the CPU registers first
        let dereferenced_concrete_value = {
            let cpu_state_guard = self.state.cpu_state.lock().unwrap();
            // Use the offset directly to retrieve register value
            let value = cpu_state_guard.get_register_value_by_offset(pointer_offset_concrete);
    
            if let Some(value) = value {
                log!(self.logger.clone(), "Dereferenced CPU register value for 0x{:x}: {:?}", pointer_offset_concrete, value);
                value.to_string()
            } else {
                // If not found in registers, attempt to dereference from memory
                let memory_guard = self.state.memory.memory.read().unwrap();
                if let Some(value) = memory_guard.get(&pointer_offset_concrete) {
                    value.concrete.to_str()
                } else {
                    log!(self.logger.clone(), "Memory at address 0x{:x} not initialized, initializing now.", pointer_offset_concrete);
                    // Ensure the address range is initialized
                    self.state.memory.ensure_address_initialized(pointer_offset_concrete, 8);
                    let memory_guard = self.state.memory.memory.read().unwrap();
                    if let Some(value) = memory_guard.get(&pointer_offset_concrete) {
                        value.concrete.to_str()
                    } else {
                        return Err(format!("Failed to dereference address from memory or registers: {:x}", pointer_offset_concrete));
                    }
                }
            }
        };
        log!(self.logger.clone(), "Dereferenced value: {:?}", dereferenced_concrete_value);
    
        // Determine the output variable and update it with the loaded data
        if let Some(output_varnode) = instruction.output.as_ref() {
            match &output_varnode.var {
                Var::Unique(id) => {
                    log!(self.logger.clone(), "Output is a Unique type with ID: 0x{:x}", id);
                    let concrete_value = dereferenced_concrete_value.parse::<u64>().map_err(|e| format!("Failed to parse dereferenced value: {}", e))?;
                    let concolic_var = ConcolicVar::new_concrete_and_symbolic_int(
                        concrete_value,
                        &format!("Unique(0x{:x})", id),
                        self.context,
                        output_varnode.size.to_bitvector_size(),
                    );
                    let unique_name = format!("Unique(0x{:x})", id);
                    self.unique_variables.insert(unique_name.clone(), concolic_var.clone());
                },
                Var::Register(offset, _) => {
                    log!(self.logger.clone(), "Output is a Register type");
                    let concrete_value = dereferenced_concrete_value.parse::<u64>().map_err(|e| format!("Failed to parse dereferenced value: {}", e))?;
                    let mut cpu_state_guard = self.state.cpu_state.lock().unwrap();
                    // Use offset directly to set the register value
                    let _ = cpu_state_guard.set_register_value_by_offset(*offset, concrete_value);
                    log!(self.logger.clone(), "Updated register at offset 0x{:x} with value {}", offset, concrete_value);
                },
                _ => {
                    log!(self.logger.clone(), "Output type is unsupported");
                    return Err("Output type not supported".to_string());
                }
            }
        } else {
            return Err("No output variable specified for LOAD instruction".to_string());
        }
    
        log!(self.logger.clone(), "{}\n", self);
    
        // Create a concolic variable for the result
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}-{:02}-load", current_addr_hex, self.instruction_counter);
        let concrete_value = dereferenced_concrete_value.parse::<u64>().map_err(|e| format!("Failed to parse dereferenced value: {}", e))?;
        self.state.create_or_update_concolic_variable_int(&result_var_name, concrete_value, SymbolicVar::Int(BV::from_u64(self.context, concrete_value, 64)));
    
        log!(self.logger.clone(), "{}", self.state);
    
        Ok(())
    }  

    pub fn handle_store(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::Store || instruction.inputs.len() != 3 {
            return Err("Invalid instruction format for STORE".to_string());
        }
    
        // Fetch the pointer offset
        log!(self.logger.clone(), "* Fetching pointer offset from instruction.input[1]");
        let pointer_offset_concolic = self.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;
        let pointer_offset_concrete = pointer_offset_concolic.get_concrete_value();
        log!(self.logger.clone(), "Pointer offset concrete: {:x}", pointer_offset_concrete);
    
        // Fetch the data to be stored
        log!(self.logger.clone(), "* Fetching data to store from instruction.input[2]");
        let data_to_store_concolic = self.varnode_to_concolic(&instruction.inputs[2]).map_err(|e| e.to_string())?;
        let data_to_store_concrete = data_to_store_concolic.get_concrete_value();
        let data_to_store_symbolic = match data_to_store_concolic.clone() {
            ConcolicEnum::ConcolicVar(var) => var.symbolic,
            ConcolicEnum::CpuConcolicValue(cpu_var) => cpu_var.symbolic,
            ConcolicEnum::MemoryConcolicValue(mem_var) => mem_var.symbolic,
        };
        log!(self.logger.clone(), "Data to store concrete: {:x}", data_to_store_concrete);
    
        // Store the data in the memory at the calculated offset
        {
            let mut memory_guard = self.state.memory.memory.write().unwrap();
            memory_guard.insert(pointer_offset_concrete, MemoryConcolicValue::new(self.context, data_to_store_concrete));
            log!(self.logger.clone(), "Stored data at byte offset 0x{:x}: {:?}", pointer_offset_concrete, data_to_store_concolic);
        }
    
        // If the address falls within the range of the CPU registers, update the register as well
        {
            let mut cpu_state_guard = self.state.cpu_state.lock().unwrap();
            if let Some(_register_value) = cpu_state_guard.get_register_value_by_offset(pointer_offset_concrete) {
                cpu_state_guard.set_register_value_by_offset(pointer_offset_concrete, data_to_store_concrete)?;
                log!(self.logger.clone(), "Updated register at offset 0x{:x} with value 0x{:x}", pointer_offset_concrete, data_to_store_concrete);
            }
        }
    
        log!(self.logger.clone(), "{}\n", self);
    
        // Create or update a concolic variable for the result of the store operation
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}-{:02}-store", current_addr_hex, self.instruction_counter);
        self.state.create_or_update_concolic_variable_int(&result_var_name, data_to_store_concrete, data_to_store_symbolic);
    
        log!(self.logger.clone(), "{}", self.state);
    
        Ok(())
    }    
    
    // Helper function
    pub fn initialize_var_if_absent(&mut self, varnode: &Varnode) -> Result<u64, String> {
        let var_name = format!("{:?}", varnode.var);
    
        match self.state.get_concrete_var(varnode) {
            Ok(ConcreteVar::Int(val)) => Ok(val), // Directly return u64 value
            Ok(ConcreteVar::Float(_)) => Err("Expected an integer value, found a float".to_string()),
            Ok(ConcreteVar::Str(_)) => Err("Expected an integer value, found a str".to_string()),
            Err(_) => {
                // If the variable is not found, initialize it as an integer with a default value
                let initial_value = 0u64; // Use u64 for initialization to match ConcreteVar::Int
                self.state.create_concolic_var_int(&var_name, initial_value, varnode.size.to_bitvector_size());
                Ok(initial_value)
            }
        }
    }
        
    pub fn handle_copy(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::Copy || instruction.inputs.len() != 1 {
            return Err("Invalid instruction format for COPY".to_string());
        }
    
        // Fetch the source varnode
        log!(self.logger.clone(), "* Fetching source from instruction.input[0]");
        let source_var = self.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
        let source_concrete_value = source_var.get_concrete_value();
        let source_symbolic_value = match source_var.clone() {
            ConcolicEnum::ConcolicVar(var) => var.symbolic,
            ConcolicEnum::CpuConcolicValue(cpu_var) => cpu_var.symbolic,
            ConcolicEnum::MemoryConcolicValue(mem_var) => mem_var.symbolic,
        };
        log!(self.logger.clone(), "Value to be copied into output: {:?}", source_var);
        
        // Check the output destination and copy the source to it
        if let Some(output_varnode) = instruction.output.as_ref() {
            match &output_varnode.var {
                Var::Unique(id) => {
                    log!(self.logger.clone(), "Output is a Unique type");
                    let unique_name = format!("Unique(0x{:x})", id);
                    // Convert source to ConcolicVar if needed and update or insert into unique variables
                    let concolic_var = ConcolicVar::new_concrete_and_symbolic_int(
                        source_concrete_value,
                        &unique_name,
                        self.context,
                        source_symbolic_value.get_size()  
                    );
                    self.unique_variables.insert(unique_name.clone(), concolic_var.clone());
                    log!(self.logger.clone(), "Content of output {:?} after copying: {:?}", unique_name, concolic_var);
                },
                Var::Register(offset, _) => {
                    log!(self.logger.clone(), "Output is a Register type");
                    let mut cpu_state_guard = self.state.cpu_state.lock().unwrap();
                    let _ = cpu_state_guard.set_register_value_by_offset(*offset, source_concrete_value);
                    log!(self.logger.clone(), "Updated register at offset 0x{:x} with value {}", offset, source_concrete_value);
                },
                _ => {
                    log!(self.logger.clone(), "Output type is unsupported for COPY");
                    return Err("Output type not supported".to_string());
                }
            }
        } else {
            return Err("No output variable specified for COPY instruction".to_string());
        }
    
        log!(self.logger.clone(), "{}", self);
    
        // Create or update a concolic variable for the result
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}-{:02}-copy", current_addr_hex, self.instruction_counter);
        self.state.create_or_update_concolic_variable_int(&result_var_name, source_concrete_value, source_symbolic_value);
    
        log!(self.logger.clone(), "{}", self.state);
    
        Ok(())
    }    

    // The function to handle POPCOUNT instruction
    pub fn handle_popcount(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::PopCount || instruction.inputs.len() != 1 || instruction.output.is_none() {
            return Err("Invalid instruction format for POPCOUNT".to_string());
        }
    
        // Fetch concolic variable
        log!(self.logger.clone(), "* Fetching instruction.input[0] for POPCOUNT");
        let input_var = self.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| {
            log!(self.logger.clone(), "Error converting varnode to concolic: {}", e);
            e.to_string()
        })?;
    
        let popcount_result = match input_var {
            ConcolicEnum::ConcolicVar(concolic_var) => {
                let concrete_value = concolic_var.concrete.to_u64();
                let popcount = concrete_value.count_ones() as u64;
                log!(self.logger.clone(), "Concrete value: {}, Popcount: {}", concrete_value, popcount);
                let symbolic_value = concolic_var.popcount();
                ConcolicVar::new_concrete_and_symbolic_int(popcount, &symbolic_value.to_string(), self.context, concolic_var.concrete.get_size())
            },
            ConcolicEnum::CpuConcolicValue(cpu_var) => {
                let concrete_value = cpu_var.get_concrete_value().unwrap_or(0);
                let popcount = concrete_value.count_ones() as u64;
                log!(self.logger.clone(), "CPU concrete value: {}, Popcount: {}", concrete_value, popcount);
                let symbolic_value = cpu_var.popcount();
                ConcolicVar::new_concrete_and_symbolic_int(popcount, &symbolic_value.to_string(), self.context, cpu_var.concrete.get_size())
            },
            ConcolicEnum::MemoryConcolicValue(mem_var) => {
                let concrete_value = mem_var.get_concrete_value().unwrap_or(0);
                let popcount = concrete_value.count_ones() as u64;
                log!(self.logger.clone(), "Memory concrete value: {}, Popcount: {}", concrete_value, popcount);
                let symbolic_value = mem_var.popcount();
                ConcolicVar::new_concrete_and_symbolic_int(popcount, &symbolic_value.to_string(), self.context, mem_var.concrete.get_size())
            },
        };
    
        log!(self.logger.clone(), "*** The result of POPCOUNT is: {:?}", popcount_result.clone());
    
        match instruction.output.as_ref().map(|v| &v.var) {
            Some(Var::Unique(id)) => {
                let unique_name = format!("Unique(0x{:x})", id);
                self.unique_variables.insert(unique_name.clone(), popcount_result.clone());
                log!(self.logger.clone(), "Updated unique variable: {}", unique_name);
            },
            Some(Var::Register(offset, _)) => {
                log!(self.logger.clone(), "Output is a Register type");
                let mut cpu_state_guard = self.state.cpu_state.lock().unwrap();
                let concrete_value = popcount_result.concrete.to_u64();
                log!(self.logger.clone(), "Setting register value at offset 0x{:x} to {}", offset, concrete_value);
                let set_result = cpu_state_guard.set_register_value_by_offset(*offset, concrete_value);
                match set_result {
                    Ok(_) => {
                        let updated_value = cpu_state_guard.get_register_value_by_offset(*offset).unwrap_or(0);
                        if updated_value == concrete_value {
                            log!(self.logger.clone(), "Successfully updated register at offset 0x{:x} with value {}", offset, updated_value);
                        } else {
                            log!(self.logger.clone(), "Failed to verify updated register at offset 0x{:x}", offset);
                            return Err(format!("Failed to verify updated register value at offset 0x{:x}", offset));
                        }
                    },
                    Err(e) => {
                        log!(self.logger.clone(), "Failed to set register value: {}", e);
                        return Err(format!("Failed to set register value at offset 0x{:x}", offset));
                    }
                }
            },
            _ => {
                log!(self.logger.clone(), "Output type is unsupported");
                return Err("Output type not supported".to_string());
            }
        }
    
        log!(self.logger.clone(), "{}\n", self);
    
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}-{:02}-popcount", current_addr_hex, self.instruction_counter);
        self.state.create_or_update_concolic_variable_int(&result_var_name, popcount_result.concrete.to_u64(), popcount_result.symbolic); 
    
        log!(self.logger.clone(), "{}\n", self.state);
    
        Ok(())
    }   

    pub fn handle_lzcount(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::LZCount || instruction.inputs.len() != 1 {
            return Err("Invalid instruction format for LZCOUNT".to_string());
        }
    
        let input_varnode = &instruction.inputs[0];
        let input_var = self.initialize_var_if_absent(input_varnode)?;
    
        // Perform leading zero count on the concrete value
        let lzcount = input_var.leading_zeros() as u64; // leading_zeros returns u32, convert to u64 for consistency
    
        if let Some(output_varnode) = &instruction.output {
            let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
            let result_var_name = format!("{}_{:02}_{}", current_addr_hex, self.instruction_counter, format!("{:?}", output_varnode.var));
            let bitvector_size = output_varnode.size.to_bitvector_size();
    
            self.state.create_concolic_var_int(&result_var_name, lzcount, bitvector_size);
        }
    
        Ok(())
    }    

    pub fn handle_subpiece(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::SubPiece || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for SUBPIECE".to_string());
        }
    
        let source_varnode = &instruction.inputs[0];
        let truncate_bytes_constant = match instruction.inputs[1].var {
            Var::Const(ref val_str) => {
                // Check if the string starts with "0x" for a hexadecimal constant
                if val_str.starts_with("0x") {
                    // Strip the "0x" prefix and parse the remaining string as a hexadecimal number
                    usize::from_str_radix(&val_str[2..], 16).map_err(|e| format!("Failed to parse constant for truncation from '{}': {}", val_str, e))
                } else {
                    // Directly parse the string as a decimal number
                    val_str.parse::<usize>().map_err(|e| format!("Failed to parse constant for truncation from '{}': {}", val_str, e))
                }
            },
            _ => Err("Second input for SUBPIECE must be a constant representing the number of bytes to truncate.".to_string()),
        }?;
    
        let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required for SUBPIECE".to_string())?;
    
        // Fetch the concrete value for the source variable
        let source_value = self.state.get_concrete_var(source_varnode)?;
        match source_value {
            ConcreteVar::Int(source_int) => {
                // Assuming the source integer is treated as a byte array, we need to truncate it accordingly.
                // This approach is simplistic and might need adjustment based on your actual data representation.
                let source_bytes = source_int.to_le_bytes(); // Convert to bytes assuming little-endian
                let truncated_bytes = &source_bytes[truncate_bytes_constant.min(8)..]; // Ensure we don't exceed the length
                let truncated_int = u64::from_le_bytes(truncated_bytes.try_into().unwrap_or_default()); // Convert back to int
    
                // Create or update the variable for the truncated value
                let var_name = format!("subpiece_result_{:?}", output_varnode.var);
                self.state.create_or_update_concolic_var_int(&var_name, truncated_int, output_varnode.size.to_bitvector_size());
            },
            _ => return Err("SUBPIECE operation currently supports only integer source data".to_string()),
        }
    
        Ok(())
    }        
}

impl<'ctx> fmt::Display for ConcolicExecutor<'ctx> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "***")?;
        writeln!(f, "ConcolicExecutor State after the instruction:")?;
        writeln!(f, "Current Address: {:?}", self.current_address)?;
        writeln!(f, "Instruction Counter: {}", self.instruction_counter)?;
        writeln!(f, "Unique Variables:")?;
        for (key, value) in &self.unique_variables {
            writeln!(f, "  {}: {:?}", key, value)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct Logger {
    file: Arc<Mutex<File>>,
    terminal: Arc<Mutex<io::Stdout>>,
}

impl Logger {
    pub fn new(file_path: &str) -> io::Result<Self> {
        let file = File::create(file_path)?;
        let terminal = io::stdout();
        Ok(Logger {
            file: Arc::new(Mutex::new(file)),
            terminal: Arc::new(Mutex::new(terminal)),
        })
    }
}

impl Write for Logger {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut file = self.file.lock().unwrap();
        let mut terminal = self.terminal.lock().unwrap();

        file.write_all(buf)?;
        terminal.write_all(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut file = self.file.lock().unwrap();
        let mut terminal = self.terminal.lock().unwrap();

        file.flush()?;
        terminal.flush()?;
        Ok(())
    }
}

