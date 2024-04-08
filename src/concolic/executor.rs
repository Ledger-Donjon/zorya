use std::io;
use std::sync::MutexGuard;
use crate::state::cpu_state::GLOBAL_CPU_STATE;
use crate::state::CpuState;
use crate::state::State;
use parser::parser::{Inst, Opcode, Var, Varnode};
use z3::{Context, Solver};
use crate::concolic::ConcolicVar;
use super::executor_bool;
use super::executor_callother;
use super::executor_float;
use super::executor_int;
pub use super::ConcreteVar;
pub use super::SymbolicVar;

#[derive(Debug)]
pub struct ConcolicExecutor<'a> {
    pub context: &'a Context,
    pub solver: Solver<'a>,
    pub state: State<'a>,
    pub current_address: Option<u64>, // Store the current address being processed
    pub instruction_counter: usize, // Counter for instructions under the same address
}

impl<'a> ConcolicExecutor<'a> {
    pub fn new(context: &'a Context) -> Result<Self, io::Error> {        
        let solver = Solver::new(context);
        let state = match State::new(context) {
            Ok(state) => {
                println!("State successfully initialized.");
                state
            },
            Err(e) => {
                eprintln!("Failed to initialize State: {}", e);
                return Err(io::Error::new(io::ErrorKind::Other, "Failed to initialize State"));
            }
        };

        Ok(ConcolicExecutor {
            context,
            solver,
            state,
            current_address: None,
            instruction_counter: 0,
        })
    }

    pub fn execute_instruction(&mut self, instruction: Inst, current_addr: u64) -> Result<(), String> {
        // Check if we are processing a new address block
        if Some(current_addr) != self.current_address {
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

    pub fn handle_branch(&mut self, instruction: Inst) -> Result<(), String> {
        // Ensure there is one input representing the destination.
        if instruction.inputs.len() != 1 {
            return Err("Branch instruction must have exactly one input".to_string());
        }

        let destination = &instruction.inputs[0];
        let dest_address = match &destination.var {
            Var::Const(addr_str) => addr_str.parse::<u64>()
                .map_err(|_| "Failed to parse destination address from Const variant in BRANCH operation".to_string())?,
            Var::Unique(addr) | Var::Memory(addr) => *addr,
            Var::Register(addr, _size) => *addr,
        };

        // Update the program counter (RIP) in the global CPU state as a hexadecimal string.
    {
        let mut cpu_state = GLOBAL_CPU_STATE.lock().unwrap();
        cpu_state.set_register_value_by_name("rip", format!("0x{:X}", dest_address));
    }

        // Update the concolic state to reflect the branch taken.
        let var_name = format!("branch_{:x}", dest_address);
        self.state.create_concolic_var_int(&var_name, dest_address, 64); // Assume 64-bit addresses.

        Ok(())
    }

    // Handle indirect branch operation
    pub fn handle_branchind(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.inputs.is_empty() {
            return Err("BRANCHIND operation requires an input".to_string());
        }

        let target_address = match &instruction.inputs[0].var {
            Var::Const(addr_str) => addr_str.parse::<u64>().map_err(|_| "Failed to parse target address from Const variant".to_string())?,
            Var::Unique(addr) | Var::Memory(addr) => *addr,
            Var::Register(addr, _size) => *addr,
        };

        // Update the program counter in the global CPU state.
        {
            let mut cpu_state = GLOBAL_CPU_STATE.lock().unwrap();
            cpu_state.set_register_value_by_name("rip", format!("0x{:X}", target_address));
        }


        // Update the concolic variable
        let target_address_result = self.state.get_concrete_var(&instruction.inputs[0]);
        let target_address = match target_address_result {
            Ok(ConcreteVar::Int(addr)) => addr,
            _ => return Err("Unable to evaluate target address for BRANCHIND operation".to_string()),
        };
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let var_name = format!("{}_{}_branchind", current_addr_hex, format!("{:02}", self.instruction_counter));
        self.state.create_concolic_var_int(&var_name, target_address, 64); // x86-64, thus 64 bits

        Ok(())
    }

    // Handle conditional branch operation
    pub fn handle_cbranch(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.inputs.len() != 2 {
            return Err("CBRANCH operation requires two inputs".to_string());
        }

        // Lock the GLOBAL_CPU_STATE once at the beginning of your method
        let cpu_state_guard: MutexGuard<CpuState> = GLOBAL_CPU_STATE.lock().unwrap();
    
        let condition = match &instruction.inputs[1].var {
            Var::Const(val) => {
                val.parse::<u64>().map_err(|_| "Failed to parse condition from Const variant".to_string())? != 0
            },
            Var::Register(addr, _size) => {
                let reg_name = CpuState::reg_num_to_name(*addr)
                    .ok_or_else(|| "Failed to fetch register name".to_string())?;

                // Access the GLOBAL_CPU_STATE directly via the lock obtained above
                let reg_value_str = cpu_state_guard.get_register_value_by_name(&reg_name)
                    .ok_or_else(|| format!("Failed to fetch value for register {}", reg_name))?;

                // Convert the register value from a hexadecimal string to u64 before comparing
                let reg_value = u64::from_str_radix(reg_value_str.trim_start_matches("0x"), 16)
                    .map_err(|_| format!("Failed to parse value for register {} as number", reg_name))?;

                reg_value != 0
            },
            Var::Unique(_addr) | Var::Memory(_addr) => {
                true // modify ?
            },
        };
    
        if condition {
            // Directly handle the branch using the first input as in handle_branch function
            let target_address = match &instruction.inputs[0].var {
                Var::Const(addr_str) => addr_str.parse::<u64>()
                    .map_err(|_| "Failed to parse target address from Const variant in CBRANCH operation".to_string())?,
                Var::Unique(addr) | Var::Memory(addr) => *addr,
                Var::Register(addr, _size) => *addr,
            };
    
            // Proceed with the branch logic as in handle_branch
            {
                let mut cpu_state = GLOBAL_CPU_STATE.lock().unwrap();
                cpu_state.set_register_value_by_name("rip", format!("0x{:X}", target_address));
            }

            let var_name = format!("cbranch_{:x}", target_address);
            self.state.create_concolic_var_int(&var_name, target_address, 64); // Assume 64-bit addresses.
        }
    
        Ok(())
    }
    

    pub fn handle_call(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::Call || instruction.inputs.len() < 1 {
            return Err("Invalid instruction format for CALL".to_string());
        }
    
        // Assuming a method exists to resolve the target address for CALL operations
        let target_address = self.resolve_varnode_to_address(&instruction.inputs[0])
            .ok_or_else(|| "Unable to evaluate target address for CALL operation".to_string())?;
    
        // Update the current execution address to the target address
        self.current_address = Some(target_address);
    
        // Update the concolic variable
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let var_name = format!("{}_{}_call", current_addr_hex, format!("{:02}", self.instruction_counter));
        self.state.create_concolic_var_int(&var_name, target_address, 64); // Assuming x86-64 architecture, thus 64 bits
    
        Ok(())
    }
    
    // Helper function
    fn resolve_varnode_to_address(&self, varnode: &Varnode) -> Option<u64> {
        match &varnode.var {
            Var::Register(addr, _size) => {
                // if needed add the use of addr
                Some(*addr)
            },
            Var::Unique(addr) | Var::Memory(addr) => {
                Some(*addr)
            },
            Var::Const(addr_str) => {
                // Address is in hexadecimal format without the "0x" prefix
                let addr_str = addr_str.trim_start_matches("0x");
                u64::from_str_radix(addr_str, 16).ok()
            },
        }
    }

    
    pub fn handle_callind(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::CallInd || instruction.inputs.len() < 1 {
            return Err("Invalid instruction format for CALLIND".to_string());
        }
    
        // Evaluate the target address based on the type of the input variable
        let target_address = match &instruction.inputs[0].var {
            Var::Const(addr_str) => addr_str.parse::<u64>().map_err(|_| "Failed to parse target address from Const variant".to_string())?,
            Var::Unique(addr) | Var::Memory(addr) => *addr,
            Var::Register(addr, _size) => *addr,
        };
    
        // Update the current execution address to the target address
        self.current_address = Some(target_address);
    
        // Update the concolic variable to reflect the indirect call
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let var_name = format!("callind_{}_{}", current_addr_hex, format!("{:02}", self.instruction_counter));
        self.state.create_concolic_var_int(&var_name, target_address, 64); // Assuming x86-64 architecture, thus 64 bits
    
        Ok(())
    }
    
    pub fn handle_return(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::Return || instruction.inputs.is_empty() {
            return Err("Invalid instruction format for RETURN".to_string());
        }
    
        // Evaluate the return address based on the type of the input variable
        let return_address = match &instruction.inputs[0].var {
            // Adjusted parsing strategy for Const variant to handle x86-64 specific formatting
            Var::Const(addr_str) => {
                let addr_str = addr_str.trim_start_matches("0x");
                u64::from_str_radix(addr_str, 16)
                    .map_err(|_| format!("Failed to parse return address '{}' from Const variant in RETURN operation", addr_str))
            },
            Var::Unique(addr) | Var::Memory(addr) => Ok(*addr),
            Var::Register(addr, _size) => Ok(*addr),
        }?;
    
        // Update the current execution address to the return address
        self.current_address = Some(return_address);
    
        // Update the concolic variable to reflect the return operation
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let var_name = format!("return_{}_{}", current_addr_hex, format!("{:02}", self.instruction_counter));
        self.state.create_concolic_var_int(&var_name, return_address, 64); // Assuming x86-64 architecture, thus 64 bits
    
        Ok(())
    }    

    // Helper function
    // Evaluates a varnode and returns its concrete u64 value
    pub fn evaluate_varnode_as_u64(&self, varnode: &Varnode) -> Result<u64, String> {
        match self.state.get_concolic_var(&format!("{:?}", varnode.var)) {
            Some(concolic_var) => match concolic_var.concrete {
                ConcreteVar::Int(value) => Ok(value),
                _ => Err("Unsupported varnode type for this operation.".to_string()),
            },
            None => Err("Varnode not found.".to_string()),
        }
    }

    pub fn handle_load(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::Load || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for LOAD".to_string());
        }

        // Lock the GLOBAL_CPU_STATE once at the beginning of your method
        let cpu_state_guard: MutexGuard<CpuState> = GLOBAL_CPU_STATE.lock().unwrap();

        let output_varnode = instruction.output.as_ref().ok_or_else(|| "Output varnode is required for LOAD".to_string())?;

        let base_address = match &instruction.inputs[1].var {
            Var::Const(ref address_str) => {
                let addr_str = address_str.trim_start_matches("0x");
                u64::from_str_radix(addr_str, 16).map_err(|_| "Failed to parse address".to_string())?
            },
            Var::Register(reg_num, _size) => {
                let reg_name = CpuState::reg_num_to_name(*reg_num)
                    .ok_or_else(|| "Failed to fetch register name".to_string())?;

                // Access the GLOBAL_CPU_STATE directly via the lock obtained above
                let reg_value_str = cpu_state_guard.get_register_value_by_name(&reg_name)
                    .ok_or_else(|| format!("Failed to fetch value for register {}", reg_name))?;

                // Convert the register value from a hexadecimal string to u64
                u64::from_str_radix(reg_value_str.trim_start_matches("0x"), 16)
                    .map_err(|_| format!("Failed to parse value for register {} as number", reg_name))?
            },
            Var::Unique(_) | Var::Memory(_) => {
                self.resolve_varnode_to_address(&instruction.inputs[1])
                    .ok_or_else(|| "Failed to resolve Unique or Memory varnode to concrete address".to_string())?
            },
        };

        let size = output_varnode.size.to_bitvector_size() / 8;

        match self.state.memory.read_memory(base_address, size as usize) {
            Ok(data) => {
                let read_value = data.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
                let var_name = format!("load_{}_{}", base_address, size);
                self.state.create_or_update_concolic_var_int(&var_name, read_value, 64);
            },
            Err(e) => return Err(format!("Memory read error at address 0x{:x}: {:?}", base_address, e)),
        }

        Ok(())
    }


    pub fn handle_store(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::Store || instruction.inputs.len() != 3 {
            return Err("Invalid instruction format for STORE".to_string());
        }
    
        // Evaluate the address from input1 to determine the destination for storing the data.
        let address = match &instruction.inputs[1].var {
            Var::Const(addr_str) => {
                let addr_str = addr_str.trim_start_matches("0x");
                u64::from_str_radix(addr_str, 16)
                    .map_err(|_| format!("Failed to parse return address '{}' from Const variant in RETURN operation", addr_str))
            },
            Var::Unique(addr) | Var::Memory(addr) => Ok(*addr),
            Var::Register(addr, _size) => Ok(*addr),
        }?;
    
        // Evaluate the value from input2 to be stored.
        let value = match &instruction.inputs[2].var {
            Var::Const(val_str) => {
                let val_str = val_str.trim_start_matches("0x"); // Remove "0x" prefix if present
                u64::from_str_radix(val_str, 16)
                    .map_err(|_| format!("Failed to parse value '{}' from Const variant in STORE operation", val_str))
            },
            Var::Unique(addr) | Var::Memory(addr) => Ok(*addr),
            Var::Register(addr, _size) => Ok(*addr),
        }?;
    
        // Determine the size of the value to be stored based on the size attribute of input2.
        let size_in_bytes = instruction.inputs[2].size.to_bitvector_size() / 8;

        // Prepare the value bytes for storage, considering endianess.
        let mut value_bytes = Vec::with_capacity(size_in_bytes as usize);
        for i in 0..size_in_bytes {
            // Protect against shifting more bits than exist in the type.
            if i * 8 < 64 {
                value_bytes.push(((value >> (8 * i)) & 0xFF) as u8);
            } else {
                // Handle error or break as needed if this case should not occur
                return Err(format!("Attempted to shift {} bits, exceeding the u64 limit", 8 * i));
            }
        } 
    
        // Check for null dereference
        // let current_address_value = self.current_address.unwrap_or(0);
        // self.state.check_nil_deref(address, current_address_value, &instruction)
        //    .map_err(|e| format!("{} at address 0x{:x} with instruction {:?}", e, current_address_value, instruction))?;
    
        // Perform the memory write operation.
        self.state.memory.write_memory(address, &value_bytes)
            .map_err(|e| format!("Error writing memory for STORE: {}", e))?;
    
        // Update the concolic variable for the stored value with a unique name based on the current address and instruction counter.
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let var_name = format!("store_{}_{}_{}", current_addr_hex, format!("{:02}", self.instruction_counter), format!("{:?}", instruction.inputs[2].var));
        self.state.create_or_update_concolic_var_int(&var_name, value, 64); // Assuming the value is always an integer, adjust as needed.
    
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
    
        let input0 = self.initialize_var_if_absent(&instruction.inputs[0])?;
    
        // Ensure the sizes match
        let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required for COPY")?;
        if instruction.inputs[0].size != output_varnode.size {
            return Err("Input and output sizes must match for COPY".to_string());
        }
    
        // Perform the copy
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}_{:02}_{}", current_addr_hex, self.instruction_counter, format!("{:?}", output_varnode.var));
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(input0.into(), &result_var_name, self.context, output_varnode.size.to_bitvector_size()));
    
        Ok(())
    }
    
    

    pub fn handle_popcount(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::PopCount || instruction.inputs.len() != 1 {
            return Err("Invalid instruction format for POPCOUNT".to_string());
        }
    
        let input_varnode = &instruction.inputs[0];
        let input_var = self.initialize_var_if_absent(input_varnode)?;
    
        // Perform population count on the concrete value
        let popcount = input_var.count_ones() as u64; // count_ones returns u32, convert to u64 for consistency
    
        if let Some(output_varnode) = &instruction.output {
            let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
            let result_var_name = format!("{}_{:02}_{}", current_addr_hex, self.instruction_counter, format!("{:?}", output_varnode.var));
            let bitvector_size = output_varnode.size.to_bitvector_size();
    
            self.state.create_concolic_var_int(&result_var_name, popcount, bitvector_size);
        }
    
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

