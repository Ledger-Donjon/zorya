use std::io;
use crate::state::State;
use parser::parser::{Inst, Opcode, Size, Var, Varnode};
use z3::{Context, Solver};
use crate::concolic::ConcolicVar;
pub use super::ConcreteVar;
pub use super::SymbolicVar;

#[derive(Debug)]
pub struct ConcolicExecutor<'a> {
    pub context: &'a Context,
    pub solver: Solver<'a>,
    pub state: State<'a>,
    pub current_address: Option<u64>, // Store the current address being processed
    instruction_counter: usize, // Counter for instructions under the same address
}

impl<'a> ConcolicExecutor<'a> {
    pub fn new(context: &'a Context, binary_path: &str) -> Result<Self, io::Error> {
        let solver = Solver::new(context);
        let state = State::new(context, binary_path)?;

        Ok(ConcolicExecutor {
            context,
            solver,
            state,
            current_address: None,
            instruction_counter: 0,
        })
    }

    pub fn execute_instruction(&mut self, instruction: Inst, current_addr: u64) {
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
        match instruction.opcode {
            Opcode::Blank => panic!("Opcode Blank is not implemented yet"),
            Opcode::BoolAnd => self.handle_bool_and(instruction),
            Opcode::BoolNegate => self.handle_bool_negate(instruction),
            Opcode::BoolOr => self.handle_bool_or(instruction),
            Opcode::BoolXor => self.handle_bool_xor(instruction),
            Opcode::Branch => self.handle_branch(instruction), // unconditional jump to a specified address
            Opcode::BranchInd => self.handle_branchind(instruction),
            Opcode::Build => panic!("Opcode Build is not implemented yet"),
            Opcode::Call => self.handle_call(instruction), // function call, semantically similar to a branch but represents execution flow transferring to a subroutine
            Opcode::CallInd => self.handle_callind(instruction), // indirect call to a dynamically determined address
            Opcode::CallOther => self.handle_callother(instruction), // user-defined opcode 
            Opcode::Ceil => panic!("Opcode Ceil is not implemented yet"),
            Opcode::CBranch => self.handle_cbranch(instruction), // adds a condition to the jump
            Opcode::Copy => self.handle_copy(instruction),
            Opcode::CPoolRef => panic!("Opcode CPoolRef is not implemented yet"), // returns runtime-dependent values from the constant pool
            Opcode::CrossBuild => panic!("Opcode CrossBuild is not implemented yet"),
            Opcode::DelaySlot => panic!("Opcode DelaySlot is not implemented yet"),
            Opcode::Float2Float => self.handle_float2float(instruction),
            Opcode::FloatAbs => self.handle_float_abs(instruction),
            Opcode::FloatAdd => self.handle_float_add(instruction),
            Opcode::FloatDiv => self.handle_float_div(instruction),
            Opcode::FloatEqual => self.handle_float_equal(instruction),
            Opcode::FloatLess => self.handle_float_less(instruction),
            Opcode::FloatLessEqual => self.handle_float_lessequal(instruction),
            Opcode::FloatMult => self.handle_float_mult(instruction),
            Opcode::FloatNaN => self.handle_float_nan(instruction),
            Opcode::FloatNeg => self.handle_float_neg(instruction),
            Opcode::FloatNotEqual => self.handle_float_notequal(instruction),
            Opcode::FloatSqrt => self.handle_float_sqrt(instruction),
            Opcode::FloatSub => self.handle_float_sub(instruction),
            Opcode::FloatFloor => self.handle_float_floor(instruction),
            Opcode::Int2Comp => self.handle_int_2comp(instruction),
            Opcode::Int2Float => self.handle_int2float(instruction),
            Opcode::IntAdd => self.handle_int_add(instruction),
            Opcode::IntAnd => self.handle_int_and(instruction),
            Opcode::IntCarry => self.handle_int_carry(instruction),
            Opcode::IntDiv => self.handle_int_div(instruction),
            Opcode::IntEqual => self.handle_int_equal(instruction),
            Opcode::IntLeft => self.handle_int_left(instruction),
            Opcode::IntLess => self.handle_int_less(instruction),
            Opcode::IntLessEqual => self.handle_int_lessequal(instruction),
            Opcode::IntMult => self.handle_int_mult(instruction),
            Opcode::IntNegate => self.handle_int_negate(instruction),
            Opcode::IntNotEqual => self.handle_int_not_equal(instruction),
            Opcode::IntOr => self.handle_int_or(instruction),
            Opcode::IntRem => self.handle_int_rem(instruction),
            Opcode::IntRight => self.handle_int_right(instruction),
            Opcode::IntSDiv => self.handle_int_sdiv(instruction),
            Opcode::IntSExt => self.handle_int_sext(instruction),
            Opcode::IntSCarry => self.handle_int_scarry(instruction),
            Opcode::IntSBorrow => self.handle_int_sborrow(instruction),
            Opcode::IntSRem => self.handle_int_srem(instruction),
            Opcode::IntSLess => self.handle_int_sless(instruction),
            Opcode::IntSLessEqual => self.handle_int_slessequal(instruction),
            Opcode::IntSRight => self.handle_int_sright(instruction),
            Opcode::IntSub => self.handle_int_sub(instruction),
            Opcode::IntXor => self.handle_int_xor(instruction),
            Opcode::IntZExt => self.handle_int_zext(instruction),
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
        }.expect("REASON");
    }

    pub fn handle_bool_and(&mut self, instruction: Inst) -> Result<(), String> {
        // Validate instruction format and sizes
        if instruction.opcode != Opcode::BoolAnd || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for BOOL_AND".to_string());
        }
    
        let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
        if output_varnode.size != Size::Byte {
            return Err("Output must be size 1 (Byte) for BOOL_AND".to_string());
        }
    
        let input0_value = self.initialize_var_if_absent(&instruction.inputs[0])?;
        let input1_value = self.initialize_var_if_absent(&instruction.inputs[1])?;
    
        // Perform boolean AND
        let result = (input0_value & input1_value) & 1; // Ensure result is boolean (0 or 1)
    
        // Store the result
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}_{:02}_{}", current_addr_hex, self.instruction_counter, format!("{:?}", output_varnode.var));
        self.state.create_concolic_var_int(&result_var_name, result as u64, 1);
    
        Ok(())
    }

    pub fn handle_bool_negate(&mut self, instruction: Inst) -> Result<(), String> {
        // Validate instruction format and sizes
        if instruction.opcode != Opcode::BoolNegate || instruction.inputs.len() != 1 {
            return Err("Invalid instruction format for BOOL_NEGATE".to_string());
        }
    
        let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
        if output_varnode.size != Size::Byte {
            return Err("Output must be size 1 (Byte) for BOOL_NEGATE".to_string());
        }
    
        let input0_value = self.initialize_var_if_absent(&instruction.inputs[0])?;
    
        // Perform boolean negation
        let result = !input0_value & 1; // Ensure result is boolean (0 or 1)
    
        // Store the result
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}_{:02}_{}", current_addr_hex, self.instruction_counter, format!("{:?}", output_varnode.var));
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result.into(), &result_var_name, self.context, 1));
    
        Ok(())
    }

    pub fn handle_bool_or(&mut self, instruction: Inst) -> Result<(), String> {
        // Validate instruction format and sizes
        if instruction.opcode != Opcode::BoolOr || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for BOOL_OR".to_string());
        }
    
        let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
        if output_varnode.size != Size::Byte {
            return Err("Output must be size 1 (Byte) for BOOL_OR".to_string());
        }
    
        let input0_value = self.initialize_var_if_absent(&instruction.inputs[0])?;
        let input1_value = self.initialize_var_if_absent(&instruction.inputs[1])?;
    
        // Perform boolean OR
        let result = (input0_value | input1_value) & 1; // Ensure result is boolean (0 or 1)
    
        // Store the result
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}_{:02}_{}", current_addr_hex, self.instruction_counter, format!("{:?}", output_varnode.var));
        self.state.create_concolic_var_int(&result_var_name, result as u64, 1);
        Ok(())
    }

    pub fn handle_bool_xor(&mut self, instruction: Inst) -> Result<(), String> {
        // Validate instruction format and sizes
        if instruction.opcode != Opcode::BoolXor || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for BOOL_XOR".to_string());
        }
    
        let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
        if output_varnode.size != Size::Byte {
            return Err("Output must be size 1 (Byte) for BOOL_XOR".to_string());
        }
    
        let input0_value = self.initialize_var_if_absent(&instruction.inputs[0])?;
        let input1_value = self.initialize_var_if_absent(&instruction.inputs[1])?;
    
        // Perform boolean XOR
        let result = (input0_value ^ input1_value) & 1; // Ensure result is boolean (0 or 1)
    
        // Store the result
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}_{:02}_{}", current_addr_hex, self.instruction_counter, format!("{:?}", output_varnode.var));
        self.state.create_concolic_var_int(&result_var_name, result as u64, 1);

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

        // Update the program counter in the CPU state.
        self.state.cpu_state.pc = dest_address;

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

        // Update the PC directly
        self.state.cpu_state.pc = target_address;

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
    
        let condition = match &instruction.inputs[1].var {
            Var::Const(val) => {
                val.parse::<u64>().map_err(|_| "Failed to parse condition from Const variant".to_string())? != 0
            },
            Var::Register(addr, _size) => {
                self.state.cpu_state.get_register_value(*addr)
                    .ok_or_else(|| format!("Failed to fetch value for register at address {}", addr))?
                    != 0
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
            self.state.cpu_state.pc = target_address;
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

    pub fn handle_float_equal(&mut self, instruction: Inst) -> Result<(), String> {
        // Validate the instruction format and ensure there are exactly two inputs
        if instruction.opcode != Opcode::FloatEqual || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for FLOAT_EQUAL".to_string());
        }
    
        // Ensure the output is defined and its size is appropriate for a boolean result
        let output_varnode = instruction.output.as_ref().expect("Output varnode is required");
        if output_varnode.size != Size::Byte {
            return Err("Output must be size 1 for FLOAT_EQUAL".to_string());
        }
    
        // Fetch the floating-point values from the inputs
        let input0_value = self.state.get_concrete_var(&instruction.inputs[0])?;
        let input1_value = self.state.get_concrete_var(&instruction.inputs[1])?;

        // Adjusted check for NaN and floating-point equality
        let result = match (input0_value, input1_value) {
            (ConcreteVar::Float(f0), ConcreteVar::Float(f1)) => {
                if f0.is_nan() || f1.is_nan() {
                    0.0 // Represent false as 0.0 due to NaN
                } else if (f0 - f1).abs() < f64::EPSILON {
                    1.0 // Represent true as 1.0 if within epsilon
                } else {
                    0.0 // Represent false as 0.0
                }
            },
            _ => return Err("Expected floating-point values for FLOAT_EQUAL".to_string()),
        };

        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}_{:02}_{}", current_addr_hex, self.instruction_counter, format!("{:?}", output_varnode.var));
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_float(result, &result_var_name, self.state.ctx));

        Ok(())
    }
    
    pub fn handle_float_notequal(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::FloatNotEqual || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for FLOAT_NOTEQUAL".to_string());
        }
    
        let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
        if output_varnode.size != Size::Byte {
            return Err("Output must be size 1 for FLOAT_NOTEQUAL".to_string());
        }
    
        let input0_value = self.state.get_concrete_var(&instruction.inputs[0])?; 
        let input1_value = self.state.get_concrete_var(&instruction.inputs[1])?;
    
        let result = match (input0_value, input1_value) {
            (ConcreteVar::Float(f0), ConcreteVar::Float(f1)) => {
                if f0.is_nan() || f1.is_nan() {
                    0.0 // Use 0.0 to represent false due to NaN
                } else if (f0 - f1).abs() >= f64::EPSILON {
                    1.0 // Use 1.0 to represent true if not equal
                } else {
                    0.0 // Use 0.0 otherwise
                }
            },
            _ => return Err("Expected floating-point values for FLOAT_NOTEQUAL".to_string()),
        };
    
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}_{:02}_{}", current_addr_hex, self.instruction_counter, format!("{:?}", output_varnode.var));
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_float(result, &result_var_name, self.state.ctx));
    
        Ok(())
    }
    
    pub fn handle_float_less(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::FloatLess || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for FLOAT_LESS".to_string());
        }
    
        let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
        if output_varnode.size != Size::Byte {
            return Err("Output must be size 1 for FLOAT_LESS".to_string());
        }
    
        let input0_value = self.state.get_concrete_var(&instruction.inputs[0])?; 
        let input1_value = self.state.get_concrete_var(&instruction.inputs[1])?; 
        let result = match (input0_value, input1_value) {
            (ConcreteVar::Float(f0), ConcreteVar::Float(f1)) => {
                if f0.is_nan() || f1.is_nan() {
                    0.0 // False in case of NaN
                } else {
                    // True if f0 < f1, False otherwise
                    if f0 < f1 { 1.0 } else { 0.0 }
                }
            },
            _ => return Err("Expected floating-point values for FLOAT_LESS".to_string()),
        };    
    
        // Store the result as a floating-point concolic variable
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}_{:02}_{}", current_addr_hex, self.instruction_counter, format!("{:?}", output_varnode.var));
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_float(result, &result_var_name, self.context));
    
        Ok(())
    }
    
    pub fn handle_float_lessequal(&mut self, instruction: Inst) -> Result<(), String> {
        // Validate the instruction format and ensure exactly two inputs are provided
        if instruction.opcode != Opcode::FloatLessEqual || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for FLOAT_LESSEQUAL".to_string());
        }
    
        // Ensure the output is defined and its size is appropriate for a boolean result
        let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
        if output_varnode.size != Size::Byte {
            return Err("Output must be size 1 for FLOAT_LESSEQUAL".to_string());
        }
    
        // Retrieve the concrete values of the input operands
        let input0_value = self.state.get_concrete_var(&instruction.inputs[0])?;
        let input1_value = self.state.get_concrete_var(&instruction.inputs[1])?;
    
        // Perform the comparison, taking into account the handling of NaN values
        let result = match (input0_value, input1_value) {
            (ConcreteVar::Float(f0), ConcreteVar::Float(f1)) => {
                if f0.is_nan() || f1.is_nan() {
                    0.0 // False if either input is NaN
                } else {
                    if f0 <= f1 { 1.0 } else { 0.0 }
                }
            },
            _ => return Err("Expected floating-point values for FLOAT_LESSEQUAL".to_string()),
        };
    
        // Create and store the result as a floating-point concolic variable.
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}_{:02}_{}", current_addr_hex, self.instruction_counter, format!("{:?}", output_varnode.var));
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_float(result, &result_var_name, self.context));
    
        Ok(())
    }
      
    pub fn handle_float_add(&mut self, instruction: Inst) -> Result<(), String> {
        // Validate the instruction format and ensure exactly two inputs are provided
        if instruction.opcode != Opcode::FloatAdd || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for FLOAT_ADD".to_string());
        }

        // Ensure the output varnode is defined
        let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
        
        // Retrieve the concrete values of the input operands
        let input0_value = self.state.get_concrete_var(&instruction.inputs[0])?;
        let input1_value = self.state.get_concrete_var(&instruction.inputs[1])?;

        // Perform the addition, handling NaN conditions explicitly
        let result = match (input0_value, input1_value) {
            (ConcreteVar::Float(f0), ConcreteVar::Float(f1)) => {
                if f0.is_nan() || f1.is_nan() {
                    f64::NAN // Use f64::NAN directly for NaN case
                } else {
                    f0 + f1 // Compute the sum
                }
            },
            _ => return Err("Expected floating-point values for FLOAT_ADD".to_string()),
        };

        // Create and store the result as a floating-point concolic variable
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}_{:02}_{}", current_addr_hex, self.instruction_counter, format!("{:?}", output_varnode.var));
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_float(result, &result_var_name, self.context));

        Ok(())
    }

    pub fn handle_float_sub(&mut self, instruction: Inst) -> Result<(), String> {
        // Validate the instruction format and ensure exactly two inputs are provided
        if instruction.opcode != Opcode::FloatSub || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for FLOAT_SUB".to_string());
        }
    
        // Ensure the output varnode is defined
        let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
        
        // Retrieve the concrete values of the input operands
        let input0_value = self.state.get_concrete_var(&instruction.inputs[0])?;
        let input1_value = self.state.get_concrete_var(&instruction.inputs[1])?;
    
        // Perform the subtraction, handling NaN conditions explicitly
        let result = match (input0_value, input1_value) {
            (ConcreteVar::Float(f0), ConcreteVar::Float(f1)) => {
                if f0.is_nan() || f1.is_nan() {
                    f64::NAN // Use f64::NAN for NaN case
                } else {
                    f0 - f1 // Compute the subtraction
                }
            },
            _ => return Err("Expected floating-point values for FLOAT_SUB".to_string()),
        };

        // Create and store the result as a floating-point concolic variable.
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}_{:02}_{}", current_addr_hex, self.instruction_counter, format!("{:?}", output_varnode.var));
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_float(result, &result_var_name, self.context));
    
        Ok(())
    }

    pub fn handle_float_floor(&mut self, instruction: Inst) -> Result<(), String> {
        // Validate the instruction format and ensure exactly one input is provided
        if instruction.opcode != Opcode::FloatFloor || instruction.inputs.len() != 1 {
            return Err("Invalid instruction format for FLOAT_FLOOR".to_string());
        }
    
        // Ensure the output varnode is defined
        let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    
        // Retrieve the concrete value of the input operand
        let input0_value = self.state.get_concrete_var(&instruction.inputs[0])?;
    
        let result = match input0_value {
            ConcreteVar::Float(f0) => {
                if f0.is_nan() {
                    f64::NAN // Keep NaN if input is NaN
                } else {
                    f0.floor() // Apply the floor operation
                }
            },
            _ => return Err("Expected a floating-point value for FLOAT_FLOOR".to_string()),
        };
    
        // Create and store the result as a floating-point concolic variable.
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}_{:02}_{}", current_addr_hex, self.instruction_counter, format!("{:?}", output_varnode.var));
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_float(result, &result_var_name, self.context));
    
        Ok(())
    }
    

    pub fn handle_float_mult(&mut self, instruction: Inst) -> Result<(), String> {
        // Validate the instruction format and ensure exactly two inputs are provided
        if instruction.opcode != Opcode::FloatMult || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for FLOAT_MULT".to_string());
        }

        // Ensure the output varnode is defined and matches the required size
        let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
        
        // Retrieve the concrete values of the input operands
        let input0_value = self.state.get_concrete_var(&instruction.inputs[0])?;
        let input1_value = self.state.get_concrete_var(&instruction.inputs[1])?;

        // Perform the multiplication, handling NaN and overflow conditions
        let result = match (input0_value, input1_value) {
            (ConcreteVar::Float(f0), ConcreteVar::Float(f1)) => {
                if f0.is_nan() || f1.is_nan() {
                    f64::NAN
                } else {
                    f0 * f1 // Perform the multiplication
                }
            },
            _ => return Err("Expected floating-point values for FLOAT_MULT".to_string()),
        };

        // Store the result as a floating-point concolic variable
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}_{:02}_{}", current_addr_hex, self.instruction_counter, format!("{:?}", output_varnode.var));
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_float(result, &result_var_name, self.context));

        Ok(())
    }

    pub fn handle_float_div(&mut self, instruction: Inst) -> Result<(), String> {
        // Validate the instruction format and ensure exactly two inputs are provided
        if instruction.opcode != Opcode::FloatDiv || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for FLOAT_DIV".to_string());
        }

        // Ensure the output varnode is defined and matches the required size
        let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
        
        // Retrieve the concrete values of the input operands.
        let input0_value = self.state.get_concrete_var(&instruction.inputs[0])?;
        let input1_value = self.state.get_concrete_var(&instruction.inputs[1])?;

        // Perform the division, handling NaN, overflow, and division by zero conditions.
        let result = match (input0_value, input1_value) {
            (ConcreteVar::Float(f0), ConcreteVar::Float(f1)) => {
                if f0.is_nan() || f1.is_nan() || f1 == 0.0 {
                    f64::NAN
                } else {
                    f0 / f1
                }
            },
            _ => return Err("Expected floating-point values for FLOAT_DIV".to_string()),
        };

        // Store the result as a floating-point concolic variable
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}_{:02}_{}", current_addr_hex, self.instruction_counter, format!("{:?}", output_varnode.var));
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_float(result, &result_var_name, self.context));

        Ok(())
    }

    pub fn handle_float_neg(&mut self, instruction: Inst) -> Result<(), String> {
        // Validate the instruction format and ensure exactly one input is provided
        if instruction.opcode != Opcode::FloatNeg || instruction.inputs.len() != 1 {
            return Err("Invalid instruction format for FLOAT_NEG".to_string());
        }
    
        // Ensure the output varnode is defined and matches the required size
        let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
        
        // Retrieve the concrete value of the input operand
        let input0_value = self.state.get_concrete_var(&instruction.inputs[0])?;
    
        // Perform the negation, handling NaN conditions
        let result = match input0_value {
            ConcreteVar::Float(f0) => {
                if f0.is_nan() {
                    f64::NAN
                } else {
                    -f0
                }
            },
            _ => return Err("Expected a floating-point value for FLOAT_NEG".to_string()),
        };
    
        // Store the result as a floating-point concolic variable.
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}_{:02}_{}", current_addr_hex, self.instruction_counter, format!("{:?}", output_varnode.var));
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_float(result, &result_var_name, self.context));
    
        Ok(())
    }

    pub fn handle_float_abs(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::FloatAbs || instruction.inputs.len() != 1 {
            return Err("Invalid instruction format for FLOAT_ABS".to_string());
        }
    
        let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
        
        let input0_value = self.state.get_concrete_var(&instruction.inputs[0])?;
    
        let result = match input0_value {
            ConcreteVar::Float(f0) => f0.abs(), // Compute the absolute value, NaN stays NaN.
            _ => return Err("Expected a floating-point value for FLOAT_ABS".to_string()),
        };
    
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}_{:02}_{}", current_addr_hex, self.instruction_counter, format!("{:?}", output_varnode.var));
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_float(result, &result_var_name, self.context));
    
        Ok(())
    }

    pub fn handle_float_sqrt(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::FloatSqrt || instruction.inputs.len() != 1 {
            return Err("Invalid instruction format for FLOAT_SQRT".to_string());
        }
    
        let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
        
        let input0_value = self.state.get_concrete_var(&instruction.inputs[0])?;
    
        let result = match input0_value {
            ConcreteVar::Float(f0) => f0.sqrt(), // Correctly handle sqrt operation, including NaN and negative inputs.
            _ => return Err("Expected a floating-point value for FLOAT_SQRT".to_string()),
        };

        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}_{:02}_{}", current_addr_hex, self.instruction_counter, format!("{:?}", output_varnode.var));
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_float(result, &result_var_name, self.context));
    
        Ok(())
    } 

    pub fn handle_float_nan(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::FloatNaN || instruction.inputs.len() != 1 {
            return Err("Invalid instruction format for FLOAT_NAN".to_string());
        }
    
        let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required".to_string())?;
        
        let input0_value = self.state.get_concrete_var(&instruction.inputs[0])?;
    
        let result = match input0_value {
            ConcreteVar::Float(f0) => if f0.is_nan() { 1.0 } else { 0.0 },
            _ => return Err("Expected a floating-point value for FLOAT_NAN".to_string()),
        };

        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}_{:02}_{}", current_addr_hex, self.instruction_counter, format!("{:?}", output_varnode.var));
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_float(result, &result_var_name, self.context));
    
        Ok(())
    }
    
    pub fn handle_int2float(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::Int2Float || instruction.inputs.len() != 1 {
            return Err("Invalid instruction format for INT2FLOAT".to_string());
        }
    
        let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required".to_string())?;
        
        let input0_value = self.state.get_concrete_var(&instruction.inputs[0])?;
    
        let result = match input0_value {
            ConcreteVar::Int(i0) => i0 as f64, // Handle conversion from integer to float.
            _ => return Err("Expected an integer value for INT2FLOAT".to_string()),
        };

        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}_{:02}_{}", current_addr_hex, self.instruction_counter, format!("{:?}", output_varnode.var));
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_float(result, &result_var_name, self.context));
    
        Ok(())
    }

    pub fn handle_float2float(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::Float2Float || instruction.inputs.len() != 1 {
            return Err("Invalid instruction format for FLOAT2FLOAT".to_string());
        }
    
        let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required".to_string())?;
        
        let input0_value = self.state.get_concrete_var(&instruction.inputs[0])?;

        let result = match input0_value {
            ConcreteVar::Float(f0) => f0, // Directly pass the floating-point value
            _ => return Err("Expected a floating-point value for FLOAT2FLOAT".to_string()),
        };
    
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}_{:02}_{}", current_addr_hex, self.instruction_counter, format!("{:?}", output_varnode.var));
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_float(result, &result_var_name, self.context));
    
        Ok(())
    }

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

        let output_varnode = instruction.output.as_ref().ok_or_else(|| "Output varnode is required for LOAD".to_string())?;

        let base_address = match &instruction.inputs[1].var {
            Var::Const(ref address_str) => {
                let addr_str = address_str.trim_start_matches("0x");
                u64::from_str_radix(addr_str, 16).map_err(|_| "Failed to parse address".to_string())?
            },
            Var::Register(reg_num, _size) => {
                self.state.cpu_state.get_register_value(*reg_num).ok_or_else(|| "Failed to fetch register value".to_string())?
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

    
    pub fn handle_int_carry(&mut self, instruction: Inst) -> Result<(), String> {
        // Ensure the correct instruction format
        if instruction.opcode != Opcode::IntCarry || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for INT_CARRY".to_string());
        }
    
        let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
        if output_varnode.size != Size::Byte {
            return Err("Output varnode size must be 1 (Byte) for INT_CARRY".to_string());
        }
    
        let input0 = &instruction.inputs[0];
        let input1 = &instruction.inputs[1];
    
        if input0.size != input1.size {
            return Err("Inputs must be the same size for INT_CARRY".to_string());
        }
    
        let value0 = self.initialize_var_if_absent(&instruction.inputs[0])?;
        let value1 = self.initialize_var_if_absent(&instruction.inputs[1])?;
    
        // Ensure that the values are treated as u32
        let value0_u32 = value0 as u32;
        let value1_u32 = value1 as u32;
    
        // Check for carry for u32 values. The sum is cast to u64 to avoid overflow
        let carry = (value0_u32 as u64 + value1_u32 as u64) > 0xFFFFFFFF;
    
        // Convert the carry to f64 representation (0.0 for false, 1.0 for true)
        let carry_as_u64 = if carry { 1 } else { 0 };
    
        // Store the result of the carry condition
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}_{:02}_{}", current_addr_hex, self.instruction_counter, format!("{:?}", output_varnode.var));
        let bitvector_size = output_varnode.size.to_bitvector_size();
        self.state.create_concolic_var_int(&result_var_name, carry_as_u64, bitvector_size);
    
        Ok(())
    }
    
    fn initialize_var_if_absent(&mut self, varnode: &Varnode) -> Result<u64, String> {
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
  
    pub fn handle_int_scarry(&mut self, instruction: Inst) -> Result<(), String> {
        // Ensure the correct instruction format
        if instruction.opcode != Opcode::IntSCarry || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for INT_SCARRY".to_string());
        }

        let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
        if output_varnode.size != Size::Byte {
            return Err("Output varnode size must be 1 (Byte) for INT_SCARRY".to_string());
        }

        let input0 = &instruction.inputs[0];
        let input1 = &instruction.inputs[1];

        if input0.size != input1.size {
            return Err("Inputs must be the same size for INT_SCARRY".to_string());
        }

        let value0 = self.initialize_var_if_absent(input0)?;
        let value1 = self.initialize_var_if_absent(input1)?;

        // Calculate signed overflow
        let overflow_occurred = match input0.size {
            Size::Quad => {
                let value0_i64 = value0 as i64;
                let value1_i64 = value1 as i64;
                value0_i64.checked_add(value1_i64).is_none()
            },
            Size::Word => {
                let value0_i32 = value0 as i32;
                let value1_i32 = value1 as i32;
                value0_i32.checked_add(value1_i32).is_none()
            },
            Size::Half => {
                let value0_i16 = value0 as i16;
                let value1_i16 = value1 as i16;
                value0_i16.checked_add(value1_i16).is_none()
            },
            Size::Byte => {
                let value0_i8 = value0 as i8;
                let value1_i8 = value1 as i8;
                value0_i8.checked_add(value1_i8).is_none()
            },
        };

        // Store the result of the signed overflow condition
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}_{:02}_{}", current_addr_hex, self.instruction_counter, format!("{:?}", output_varnode.var));
        let overflow_occurred_as_int = if overflow_occurred { 1 } else { 0 };
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(overflow_occurred_as_int, &result_var_name, self.context, 1));

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
            value_bytes.push(((value >> (8 * i)) & 0xFF) as u8);
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
    
       
    pub fn handle_int_add(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::IntAdd || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for INT_ADD".to_string());
        }
    
        // Ensure the input varnodes exist and initialize them if not
        let input0_var = self.initialize_var_if_absent(&instruction.inputs[0])?;
        let input1_var = self.initialize_var_if_absent(&instruction.inputs[1])?;
    
        // Perform integer addition
        let result_value = input0_var.wrapping_add(input1_var);
    
        // Ensure the sizes match
        let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required for INT_ADD")?;
        if instruction.inputs[0].size != instruction.inputs[1].size || instruction.inputs[0].size != output_varnode.size {
            return Err("Input and output sizes must match for INT_ADD".to_string());
        }
    
        // Create or update a concolic variable for the result
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}_{:02}_{}", current_addr_hex, self.instruction_counter, format!("{:?}", output_varnode.var));
        let bitvector_size = output_varnode.size.to_bitvector_size();
    
        // Assuming create_concolic_var_int is corrected to handle u64 for concrete values
        self.state.create_concolic_var_int(&result_var_name, result_value.into(), bitvector_size);
    
        Ok(())
    }
    
    
    pub fn handle_int_sub(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::IntSub || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for INT_SUB".to_string());
        }
    
        let input0_var = self.initialize_var_if_absent(&instruction.inputs[0])?;
        let input1_var = self.initialize_var_if_absent(&instruction.inputs[1])?;
    
        // Ensure the sizes match
        let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required for INT_SUB")?;
        if instruction.inputs[0].size != instruction.inputs[1].size || instruction.inputs[0].size != output_varnode.size {
            return Err("Input and output sizes must match for INT_SUB".to_string());
        }
    
        // Perform the subtraction
        let result_value = input0_var.wrapping_sub(input1_var);
    
        // Create or update a concolic variable for the result
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}_{:02}_{}", current_addr_hex, self.instruction_counter, format!("{:?}", output_varnode.var));
        let bitvector_size = output_varnode.size.to_bitvector_size();
        self.state.create_concolic_var_int(&result_var_name, result_value.into(), bitvector_size);
    
        Ok(())
    }

    pub fn handle_int_xor(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::IntXor || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for INT_XOR".to_string());
        }
    
        // Retrieve the concrete integer values for both inputs
        let input0_val = self.initialize_var_if_absent(&instruction.inputs[0])?;
        let input1_val = self.initialize_var_if_absent(&instruction.inputs[1])?;
    
        // Perform XOR operation on the concrete integer values
        let result_concrete = input0_val ^ input1_val;
    
        // Prepare for the symbolic computation
        let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}_{:02}_{}", current_addr_hex, self.instruction_counter, format!("{:?}", output_varnode.var));
        let bitvector_size = output_varnode.size.to_bitvector_size();
    
        // Update or create the concolic variable with the concrete result and a new symbolic expression
        self.state.create_concolic_var_int(&result_var_name, result_concrete, bitvector_size);
    
        Ok(())
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
    
    pub fn handle_int_equal(&mut self, instruction: Inst) -> Result<(), String> {
        // Ensure the correct instruction format
        if instruction.opcode != Opcode::IntEqual || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for INT_EQUAL".to_string());
        }
    
        let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
        // Ensure output size is 1 (boolean)
        if output_varnode.size != Size::Byte {
            return Err("Output varnode size must be 1 (Byte) for INT_EQUAL".to_string());
        }
    
        let value0 = self.initialize_var_if_absent(&instruction.inputs[0])?;
        let value1 = self.initialize_var_if_absent(&instruction.inputs[1])?;
    
        // Compare the two values
        let result = (value0 == value1) as u32; // Convert boolean result to u32
    
        // Store the result
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}_{:02}_{}", current_addr_hex, self.instruction_counter, format!("{:?}", output_varnode.var));
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result.into(), &result_var_name, self.context, 1));
    
        Ok(())
    }

    pub fn handle_int_not_equal(&mut self, instruction: Inst) -> Result<(), String> {
        // Ensure the correct instruction format
        if instruction.opcode != Opcode::IntNotEqual || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for INT_NOTEQUAL".to_string());
        }
    
        let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
        // Ensure output size is 1 (boolean)
        if output_varnode.size != Size::Byte {
            return Err("Output varnode size must be 1 (Byte) for INT_NOTEQUAL".to_string());
        }
    
        let value0 = self.initialize_var_if_absent(&instruction.inputs[0])?;
        let value1 = self.initialize_var_if_absent(&instruction.inputs[1])?;
    
        // Compare the two values
        let result = (value0 != value1) as u32; // Convert boolean result to u32
    
        // Store the result
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}_{:02}_{}", current_addr_hex, self.instruction_counter, format!("{:?}", output_varnode.var));
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result.into(), &result_var_name, self.context, 1));
    
        Ok(())
    }
    
    pub fn handle_int_less(&mut self, instruction: Inst) -> Result<(), String> {
        // Ensure the correct instruction format
        if instruction.opcode != Opcode::IntLess || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for INT_LESS".to_string());
        }
    
        let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
        // Ensure output size is 1 (boolean)
        if output_varnode.size != Size::Byte {
            return Err("Output varnode size must be 1 (Byte) for INT_LESS".to_string());
        }
    
        let value0 = self.initialize_var_if_absent(&instruction.inputs[0])?;
        let value1 = self.initialize_var_if_absent(&instruction.inputs[1])?;
    
        // Perform unsigned comparison
        let result = (value0 < value1) as u32; // Convert boolean result to u32
    
        // Store the result
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}_{:02}_{}", current_addr_hex, self.instruction_counter, format!("{:?}", output_varnode.var));
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result.into(), &result_var_name, self.context, 1));
    
        Ok(())
    }

    pub fn handle_int_sless(&mut self, instruction: Inst) -> Result<(), String> {
        // Ensure the correct instruction format
        if instruction.opcode != Opcode::IntSLess || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for INT_SLESS".to_string());
        }
    
        let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
        // Ensure output size is 1 (boolean)
        if output_varnode.size != Size::Byte {
            return Err("Output varnode size must be 1 (Byte) for INT_SLESS".to_string());
        }
    
        let value0 = self.initialize_var_if_absent(&instruction.inputs[0])?;
        let value1 = self.initialize_var_if_absent(&instruction.inputs[1])?;
    
        // Convert unsigned values to signed for comparison
        let signed_value0 = match instruction.inputs[0].size {
            Size::Quad => (value0 as u64) as i64 as i32, // keep i32?
            Size::Word => (value0 as u32) as i32,
            Size::Half => (value0 as u16) as i16 as i32,
            Size::Byte => (value0 as u8) as i8 as i32,
        };
    
        let signed_value1 = match instruction.inputs[1].size {
            Size::Quad => (value1 as u64) as i64 as i32, 
            Size::Word => (value1 as u32) as i32,
            Size::Half => (value1 as u16) as i16 as i32,
            Size::Byte => (value1 as u8) as i8 as i32,
        };
    
        // Perform signed comparison
        let result = (signed_value0 < signed_value1) as u32; // Convert boolean result to u32
    
        // Store the result
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}_{:02}_{}", current_addr_hex, self.instruction_counter, format!("{:?}", output_varnode.var));
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result.into(), &result_var_name, self.context, 1));
    
        Ok(())
    }
    
    pub fn handle_int_lessequal(&mut self, instruction: Inst) -> Result<(), String> {
        // Ensure the correct instruction format
        if instruction.opcode != Opcode::IntLessEqual || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for INT_LESSEQUAL".to_string());
        }
    
        let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
        // Ensure output size is 1 (boolean)
        if output_varnode.size != Size::Byte {
            return Err("Output varnode size must be 1 (Byte) for INT_LESSEQUAL".to_string());
        }
    
        let value0 = self.initialize_var_if_absent(&instruction.inputs[0])?;
        let value1 = self.initialize_var_if_absent(&instruction.inputs[1])?;
    
        // Perform unsigned comparison
        let result = (value0 <= value1) as u32; // Convert boolean result to u32
    
        // Store the result
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}_{:02}_{}", current_addr_hex, self.instruction_counter, format!("{:?}", output_varnode.var));
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result.into(), &result_var_name, self.context, 1));
    
        Ok(())
    }

    pub fn handle_int_slessequal(&mut self, instruction: Inst) -> Result<(), String> {
        // Ensure the correct instruction format
        if instruction.opcode != Opcode::IntSLessEqual || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for INT_SLESSEQUAL".to_string());
        }
    
        let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
        // Ensure output size is 1 (boolean)
        if output_varnode.size != Size::Byte {
            return Err("Output varnode size must be 1 (Byte) for INT_SLESSEQUAL".to_string());
        }
    
        let value0 = self.initialize_var_if_absent(&instruction.inputs[0])?;
        let value1 = self.initialize_var_if_absent(&instruction.inputs[1])?;
    
        // Assuming the conversion logic for signed values based on their actual size (?)
        let signed_value0 = value0 as i32; 
        let signed_value1 = value1 as i32; 
    
        // Perform signed comparison
        let result = (signed_value0 <= signed_value1) as u32; // Convert boolean result to u32
    
        // Store the result
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}_{:02}_{}", current_addr_hex, self.instruction_counter, format!("{:?}", output_varnode.var));
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result.into(), &result_var_name, self.context, 1));
    
        Ok(())
    }
    
    pub fn handle_int_zext(&mut self, instruction: Inst) -> Result<(), String> {
        // Validate instruction format and sizes
        if instruction.opcode != Opcode::IntZExt || instruction.inputs.len() != 1 {
            return Err("Invalid instruction format for INT_ZEXT".to_string());
        }
    
        let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
        if instruction.inputs[0].size >= output_varnode.size {
            return Err("Output size must be strictly bigger than input size for INT_ZEXT".to_string());
        }
   
        let input_value = self.initialize_var_if_absent(&instruction.inputs[0])?;
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}_{:02}_{}", current_addr_hex, self.instruction_counter, format!("{:?}", output_varnode.var));
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(input_value.into(), &result_var_name, self.context, output_varnode.size.to_bitvector_size()));
    
        Ok(())
    }

    pub fn handle_int_sext(&mut self, instruction: Inst) -> Result<(), String> {
        // Validate instruction format and sizes
        if instruction.opcode != Opcode::IntSExt || instruction.inputs.len() != 1 {
            return Err("Invalid instruction format for INT_SEXT".to_string());
        }
    
        let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
        if instruction.inputs[0].size >= output_varnode.size {
            return Err("Output size must be strictly bigger than input size for INT_SEXT".to_string());
        }
    
        let input_value = self.initialize_var_if_absent(&instruction.inputs[0])?;
        // Determine the input size in bits to calculate the shift needed for sign extension
        let input_bits = instruction.inputs[0].size.to_bitvector_size() * 8; // Assuming 8 bits per size unit for simplicity
    
        // Perform sign-extension by shifting left then arithmetic right shifting back to extend the sign
        let extended_value = match instruction.inputs[0].size {
            Size::Byte => ((input_value as i8) as i64).wrapping_shl(64 - input_bits) as u64,
            Size::Half => ((input_value as i16) as i64).wrapping_shl(64 - input_bits) as u64,
            Size::Word => ((input_value as i32) as i64).wrapping_shl(64 - input_bits) as u64,
            Size::Quad => input_value as u64, // No extension needed if input is already the largest size
        };
    
        // Store the sign-extended value
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}_{:02}_{}", current_addr_hex, self.instruction_counter, format!("{:?}", output_varnode.var));
        // Ensure the value is truncated or zero-extended based on the output size
        let result = extended_value & ((1u64 << (output_varnode.size.to_bitvector_size() * 8)) - 1);
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result, &result_var_name, self.context, output_varnode.size.to_bitvector_size()));
    
        Ok(())
    }
    
    pub fn handle_int_sborrow(&mut self, instruction: Inst) -> Result<(), String> {
        // Validate instruction format and sizes
        if instruction.opcode != Opcode::IntSBorrow || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for INT_SBORROW".to_string());
        }
    
        let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
        if output_varnode.size != Size::Byte {
            return Err("Output size must be 1 (Byte) for INT_SBORROW".to_string());
        }
    
        if instruction.inputs[0].size != instruction.inputs[1].size {
            return Err("Inputs must be the same size for INT_SBORROW".to_string());
        }
    
        let input0_value = self.initialize_var_if_absent(&instruction.inputs[0])? as i64;
        let input1_value = self.initialize_var_if_absent(&instruction.inputs[1])? as i64;
    
        // Perform signed subtraction
        let (sub_result, _overflowed) = input0_value.overflowing_sub(input1_value);
    
        // Convert the subtraction result to u64
        let result_u64 = sub_result as u64;
    
        // Store the result
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}_{:02}_{}", current_addr_hex, self.instruction_counter, format!("{:?}", output_varnode.var));
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result_u64, &result_var_name, self.context, output_varnode.size.to_bitvector_size()));
    
        Ok(())
    }
    
    pub fn handle_int_2comp(&mut self, instruction: Inst) -> Result<(), String> {
        // Validate instruction format
        if instruction.opcode != Opcode::Int2Comp || instruction.inputs.len() != 1 {
            return Err("Invalid instruction format for INT_2COMP".to_string());
        }
    
        let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
        if instruction.inputs[0].size != output_varnode.size {
            return Err("Input and output must be the same size for INT_2COMP".to_string());
        }
    
        let input_value = self.initialize_var_if_absent(&instruction.inputs[0])?;
    
        // Perform two's complement negation
        let negated_value = (!input_value).wrapping_add(1); // Bitwise NOT then add one
    
        // Store the negated value
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}_{:02}_{}", current_addr_hex, self.instruction_counter, format!("{:?}", output_varnode.var));
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(negated_value.into(), &result_var_name, self.context, output_varnode.size.to_bitvector_size()));
    
        Ok(())
    }

    pub fn handle_int_and(&mut self, instruction: Inst) -> Result<(), String> {
        // Validate instruction format and sizes
        if instruction.opcode != Opcode::IntAnd || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for INT_AND".to_string());
        }
    
        let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
        if instruction.inputs[0].size != instruction.inputs[1].size || instruction.inputs[0].size != output_varnode.size {
            return Err("All inputs and output must be the same size for INT_AND".to_string());
        }
    
        let input0_value = self.initialize_var_if_absent(&instruction.inputs[0])?;
        let input1_value = self.initialize_var_if_absent(&instruction.inputs[1])?;
    
        // Perform bitwise AND
        let result = input0_value & input1_value;
    
        // Store the result
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}_{:02}_{}", current_addr_hex, self.instruction_counter, format!("{:?}", output_varnode.var));
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result.into(), &result_var_name, self.context, output_varnode.size.to_bitvector_size()));
    
        Ok(())
    }

    pub fn handle_int_or(&mut self, instruction: Inst) -> Result<(), String> {
        // Validate instruction format and sizes
        if instruction.opcode != Opcode::IntOr || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for INT_OR".to_string());
        }
    
        let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
        if instruction.inputs[0].size != instruction.inputs[1].size || instruction.inputs[0].size != output_varnode.size {
            return Err("All inputs and output must be the same size for INT_OR".to_string());
        }
    
        let input0_value = self.initialize_var_if_absent(&instruction.inputs[0])?;
        let input1_value = self.initialize_var_if_absent(&instruction.inputs[1])?;
    
        // Perform bitwise OR
        let result = input0_value | input1_value;
    
        // Store the result
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}_{:02}_{}", current_addr_hex, self.instruction_counter, format!("{:?}", output_varnode.var));
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result.into(), &result_var_name, self.context, output_varnode.size.to_bitvector_size()));
    
        Ok(())
    }

    pub fn handle_int_left(&mut self, instruction: Inst) -> Result<(), String> {
        // Validate instruction format and sizes
        if instruction.opcode != Opcode::IntLeft || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for INT_LEFT".to_string());
        }
    
        let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
        if instruction.inputs[0].size != output_varnode.size {
            return Err("Input0 and output must be the same size for INT_LEFT".to_string());
        }
    
        let input0_value = self.initialize_var_if_absent(&instruction.inputs[0])?;
        let shift_amount = self.initialize_var_if_absent(&instruction.inputs[1])? as usize;
    
        // Perform left shift operation
        let result = if shift_amount < (output_varnode.size.to_bitvector_size() * 8) as usize {
            input0_value << shift_amount
        } else {
            0 // Shift amount is larger than the number of bits in output, result is zero
        };
    
        // Store the result
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}_{:02}_{}", current_addr_hex, self.instruction_counter, format!("{:?}", output_varnode.var));
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result.into(), &result_var_name, self.context, output_varnode.size.to_bitvector_size()));
    
        Ok(())
    }

    pub fn handle_int_right(&mut self, instruction: Inst) -> Result<(), String> {
        // Validate instruction format and sizes
        if instruction.opcode != Opcode::IntRight || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for INT_RIGHT".to_string());
        }
    
        let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
        if instruction.inputs[0].size != output_varnode.size {
            return Err("Input0 and output must be the same size for INT_RIGHT".to_string());
        }
    
        let input0_value = self.initialize_var_if_absent(&instruction.inputs[0])?;
        let shift_amount = self.initialize_var_if_absent(&instruction.inputs[1])? as usize;
    
        // Perform unsigned right shift operation
        let result = if shift_amount < (output_varnode.size.to_bitvector_size() * 8) as usize {
            input0_value >> shift_amount
        } else {
            0 // Shift amount is larger than the number of bits in output, result is zero
        };
    
        // Store the result
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}_{:02}_{}", current_addr_hex, self.instruction_counter, format!("{:?}", output_varnode.var));
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result.into(), &result_var_name, self.context, output_varnode.size.to_bitvector_size()));
    
        Ok(())
    }

    pub fn handle_int_sright(&mut self, instruction: Inst) -> Result<(), String> {
        // Validate instruction format and sizes
        if instruction.opcode != Opcode::IntSRight || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for INT_SRIGHT".to_string());
        }
    
        let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
        if instruction.inputs[0].size != output_varnode.size {
            return Err("Input0 and output must be the same size for INT_SRIGHT".to_string());
        }
    
        let input0_value = self.initialize_var_if_absent(&instruction.inputs[0])? as i64; // Cast to signed integer
        let shift_amount = self.initialize_var_if_absent(&instruction.inputs[1])? as usize;
    
        // Perform signed right shift operation
        let result = if shift_amount < (output_varnode.size.to_bitvector_size() * 8) as usize {
            (input0_value >> shift_amount) as u32 // Ensure result fits within the original size
        } else {
            if input0_value < 0 {
                !0 // If input is negative and shift amount is too large, result is all 1-bits
            } else {
                0 // Otherwise, result is zero
            }
        };
    
        // Store the result
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}_{:02}_{}", current_addr_hex, self.instruction_counter, format!("{:?}", output_varnode.var));
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result.into(), &result_var_name, self.context, output_varnode.size.to_bitvector_size()));
    
        Ok(())
    }
    
    pub fn handle_int_mult(&mut self, instruction: Inst) -> Result<(), String> {
        // Validate instruction format and sizes
        if instruction.opcode != Opcode::IntMult || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for INT_MULT".to_string());
        }
    
        let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
        if instruction.inputs[0].size != instruction.inputs[1].size || instruction.inputs[0].size != output_varnode.size {
            return Err("All inputs and output must be the same size for INT_MULT".to_string());
        }
    
        let input0_value = self.initialize_var_if_absent(&instruction.inputs[0])?;
        let input1_value = self.initialize_var_if_absent(&instruction.inputs[1])?;
    
        // Perform multiplication
        let result = input0_value.wrapping_mul(input1_value); // Use wrapping_mul to handle overflow
    
        // Store the result
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}_{:02}_{}", current_addr_hex, self.instruction_counter, format!("{:?}", output_varnode.var));
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result.into(), &result_var_name, self.context, output_varnode.size.to_bitvector_size()));
    
        Ok(())
    }

    pub fn handle_int_negate(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::IntNegate || instruction.inputs.len() != 1 {
            return Err("Invalid instruction format for INT_NEGATE".to_string());
        }
    
        // Retrieve the concrete integer value for the input
        let input_val = self.initialize_var_if_absent(&instruction.inputs[0])?;
    
        // Perform NOT operation on the concrete integer value
        let negated_concrete = !input_val;
    
        // Prepare for the symbolic computation
        let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}_{:02}_{}", current_addr_hex, self.instruction_counter, format!("{:?}", output_varnode.var));
        let bitvector_size = output_varnode.size.to_bitvector_size();
    
        // Create or update the output concolic variable with the negated concrete value
        self.state.create_concolic_var_int(&result_var_name, negated_concrete, bitvector_size);
    
        Ok(())
    }
    
    pub fn handle_int_div(&mut self, instruction: Inst) -> Result<(), String> {
        // Validate instruction format and sizes
        if instruction.opcode != Opcode::IntDiv || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for INT_DIV".to_string());
        }
    
        let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
        if instruction.inputs[0].size != instruction.inputs[1].size || instruction.inputs[0].size != output_varnode.size {
            return Err("All inputs and output must be the same size for INT_DIV".to_string());
        }
    
        let input0_value = self.initialize_var_if_absent(&instruction.inputs[0])?;
        let input1_value = self.initialize_var_if_absent(&instruction.inputs[1])?;
    
        // Check for division by zero
        // if input1_value == 0 {
        //     // Instead of proceeding with division, return an error
        //     return Err("Division by zero encountered in INT_DIV".to_string());
        // }
    
        // Check for division by zero
        let result = if input1_value == 0 {
            // Log division by zero 
            println!("Warning: Division by zero encountered in INT_DIV at address {:x}. Using default value 0.", self.current_address.unwrap_or(0));
            0 
        } else {
            // Perform division
            input0_value / input1_value
        };
    
        // Store the result
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}_{:02}_{}", current_addr_hex, self.instruction_counter, format!("{:?}", output_varnode.var));
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result.into(), &result_var_name, self.context, output_varnode.size.to_bitvector_size()));
    
        Ok(())
    }

    pub fn handle_int_rem(&mut self, instruction: Inst) -> Result<(), String> {
        // Validate instruction format and sizes
        if instruction.opcode != Opcode::IntRem || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for INT_REM".to_string());
        }
    
        let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
        if instruction.inputs[0].size != instruction.inputs[1].size || instruction.inputs[0].size != output_varnode.size {
            return Err("All inputs and output must be the same size for INT_REM".to_string());
        }
    
        let input0_value = self.initialize_var_if_absent(&instruction.inputs[0])?;
        let input1_value = self.initialize_var_if_absent(&instruction.inputs[1])?;
    
        // Check for division by zero
        if input1_value == 0 {
            // Instead of proceeding with the remainder calculation, return an error
            return Err("Division by zero encountered in INT_REM".to_string());
        }
    
        // Perform remainder operation
        let result = input0_value % input1_value;
    
        // Store the result
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}_{:02}_{}", current_addr_hex, self.instruction_counter, format!("{:?}", output_varnode.var));
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result.into(), &result_var_name, self.context, output_varnode.size.to_bitvector_size()));
    
        Ok(())
    }
    
    pub fn handle_int_sdiv(&mut self, instruction: Inst) -> Result<(), String> {
        // Validate instruction format and sizes
        if instruction.opcode != Opcode::IntSDiv || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for INT_SDIV".to_string());
        }
    
        let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
        if instruction.inputs[0].size != instruction.inputs[1].size || instruction.inputs[0].size != output_varnode.size {
            return Err("All inputs and output must be the same size for INT_SDIV".to_string());
        }
    
        let input0_value = self.initialize_var_if_absent(&instruction.inputs[0])? as i32; // Cast to signed
        let input1_value = self.initialize_var_if_absent(&instruction.inputs[1])? as i32;
    
        // Check for division by zero
        if input1_value == 0 {
            return Err("Division by zero encountered in INT_SDIV".to_string());
        }
    
        // Perform signed division
        let result = input0_value / input1_value;
    
        // Store the result
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}_{:02}_{}", current_addr_hex, self.instruction_counter, format!("{:?}", output_varnode.var));
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result.try_into().unwrap(), &result_var_name, self.context, output_varnode.size.to_bitvector_size()));
    
        Ok(())
    }

    pub fn handle_int_srem(&mut self, instruction: Inst) -> Result<(), String> {
        // Validate instruction format and sizes
        if instruction.opcode != Opcode::IntSRem || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for INT_SREM".to_string());
        }
    
        let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
        if instruction.inputs[0].size != instruction.inputs[1].size || instruction.inputs[0].size != output_varnode.size {
            return Err("All inputs and output must be the same size for INT_SREM".to_string());
        }
    
        let input0_value = self.initialize_var_if_absent(&instruction.inputs[0])? as i32;
        let input1_value = self.initialize_var_if_absent(&instruction.inputs[1])? as i32;
    
        // Check for division by zero
        if input1_value == 0 {
            return Err("Division by zero encountered in INT_SREM".to_string());
        }
    
        // Perform signed remainder operation
        let result = input0_value % input1_value;
    
        // Store the result
        let current_addr_hex = self.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}_{:02}_{}", current_addr_hex, self.instruction_counter, format!("{:?}", output_varnode.var));
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result.try_into().unwrap(), &result_var_name, self.context, output_varnode.size.to_bitvector_size()));
    
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
    
    pub fn handle_callother(&mut self, instruction: Inst) -> Result<(), String> {
        let operation_index = match instruction.inputs.get(0) {
            Some(Varnode { var: Var::Const(index), .. }) => {
                let index = index.trim_start_matches("0x"); // Remove "0x" if present
                u32::from_str_radix(index, 16) // Parse as base-16 number
                    .map_err(|_| format!("Failed to parse operation index '{}'", index))
            },
            _ => Err("CALLOTHER operation requires the first input to be a constant index.".to_string()),
        }?;

        match operation_index {
            // Operations probably used in Go runtime

            0x5 => self.handle_syscall(),
            //0xb => self.handle_rdtscp(instruction),
            0x10 => self.handle_swi(instruction),
            // 0x11 => self.handle_lock(instruction),
            // 0x12 => self.handle_unlock(instruction),
            // 0x2c => self.handle_cpuid(instruction),
            // 0x2d => self.handle_cpuid_basic_info(instruction),
            // 0x2e => self.handle_cpuid_version_info(instruction),
            // 0x2f => self.handle_cpuid_cache_tlb_info(instruction),
            // 0x30 => self.handle_cpuid_serial_info(instruction),
            // 0x31 => self.handle_cpuid_deterministic_cache_parameters_info(instruction),
            // 0x32 => self.handle_cpuid_monitor_mwait_features_info(instruction),
            // 0x33 => self.handle_cpuid_thermal_power_management_info(instruction),
            // 0x34 => self.handle_cpuid_extended_feature_enumeration_info(instruction),
            // 0x35 => self.handle_cpuid_direct_cache_access_info(instruction),
            // 0x36 => self.handle_cpuid_architectural_performance_monitoring_info(instruction),
            // 0x37 => self.handle_cpuid_extended_topology_info(instruction),
            // 0x38 => self.handle_cpuid_processor_extended_states_info(instruction),
            // 0x39 => self.handle_cpuid_quality_of_service_info(instruction),
            // 0x3a => self.handle_cpuid_brand_part1_info(instruction),
            // 0x3b => self.handle_cpuid_brand_part2_info(instruction),
            // 0x3c => self.handle_cpuid_brand_part3_info(instruction),
            // 0x4a => self.handle_rdtsc(instruction),
            // 0x97 => self.handle_pshufb(instruction),
            // 0x98 => self.handle_pshufhw(instruction),
            // 0xdc => self.handle_aesenc(instruction),
            // 0x13a => self.handle_vmovdqu_avx(instruction),
            // 0x144 => self.handle_vmovntdq_avx(instruction),
            // 0x1be => self.handle_vptest_avx(instruction),
            // 0x1c7 => self.handle_vpxor_avx(instruction),
            // 0x203 => self.handle_vpand_avx2(instruction),
            // 0x209 => self.handle_vpcmpeqb_avx2(instruction),
            // 0x25d => self.handle_vpbroadcastb_avx2(instruction),
            _ => return Err(format!("Unsupported CALLOTHER operation index: {:x}", operation_index)),
        }
    }
    
    pub fn handle_syscall(&mut self) -> Result<(), String> {
        let syscall_number = self.state.cpu_state.gpr.get("RAX").copied()
            .ok_or_else(|| "Syscall number not found".to_string())?;

        match syscall_number {
            // Open
            2 => {
                let path_addr = self.state.cpu_state.gpr.get("RDI").copied()
                    .ok_or_else(|| "Path address for open not found".to_string())?;

                let path = self.state.memory.read_string(path_addr)
                    .map_err(|e| e.to_string())?;

                let file_descriptor = self.state.vfs.open(&path).map_err(|e| e.to_string())?;

                let fd_id = self.state.next_fd_id();
                self.state.file_descriptors.insert(fd_id, file_descriptor);
                self.state.cpu_state.gpr.insert("RAX".to_string(), fd_id);

                // Update concolic state for open
                let result_var_name = format!("syscall_open_{}", self.state.cpu_state.pc); // Use PC as a unique identifier
                self.state.create_or_update_concolic_var_int(&result_var_name, fd_id, 64);

                Ok(())
            },
            // Read
            0 => {
                let fd_id = self.state.cpu_state.gpr.get("RDI").copied()
                    .ok_or_else(|| "File descriptor for read not found".to_string())? as u64;
                let buf_addr = self.state.cpu_state.gpr.get("RSI").copied()
                    .ok_or_else(|| "Buffer address for read not found".to_string())?;
                let count = self.state.cpu_state.gpr.get("RDX").copied()
                    .ok_or_else(|| "Count for read not found".to_string())? as usize;

                if let Some(file_descriptor) = self.state.file_descriptors.get(&fd_id) {
                    let mut buffer = vec![0u8; count];
                    self.state.vfs.read(file_descriptor, &mut buffer, count).map_err(|e| e.to_string())?;
                    self.state.memory.write_memory(buf_addr, &buffer).map_err(|e| e.to_string())?;
                    self.state.cpu_state.gpr.insert("RAX".to_string(), buffer.len() as u64);

                    // Update concolic state for read
                    let result_var_name = format!("syscall_read_{}", self.state.cpu_state.pc); // Use PC as a unique identifier
                    self.state.create_or_update_concolic_var_int(&result_var_name, buffer.len() as u64, 64);

                    Ok(())
                } else {
                    Err("Invalid file descriptor".to_string())
                }
            },
            // Write
            1 => {
                let fd_id = self.state.cpu_state.gpr.get("RDI").copied()
                    .ok_or_else(|| "File descriptor for write not found".to_string())? as u64;
                let buf_addr = self.state.cpu_state.gpr.get("RSI").copied()
                    .ok_or_else(|| "Buffer address for write not found".to_string())?;
                let count = self.state.cpu_state.gpr.get("RDX").copied()
                    .ok_or_else(|| "Count for write not found".to_string())? as usize;

                if let Some(file_descriptor) = self.state.file_descriptors.get_mut(&fd_id) {
                    let buffer = self.state.memory.read_memory(buf_addr, count).map_err(|e| e.to_string())?;
                    self.state.vfs.write(file_descriptor, &buffer).map_err(|e| e.to_string())?;

                    self.state.cpu_state.gpr.insert("RAX".to_string(), count as u64);

                    // Update concolic state for write
                    let result_var_name = format!("syscall_write_{}", self.state.cpu_state.pc); // Use PC as a unique identifier
                    self.state.create_or_update_concolic_var_int(&result_var_name, count as u64, 64);

                    Ok(())
                } else {
                    Err("Invalid file descriptor".to_string())
                }
            },
            _ => Err("Unsupported syscall".to_string()),
        }
    }


    // Handles the Software Interrupt (SWI) operation.
    fn handle_swi(&mut self, instruction: Inst) -> Result<(), String> {
        // Extract the interrupt number from the instruction, if available
        if let Some(Varnode { var: Var::Const(interrupt_number), .. }) = instruction.inputs.get(0) {
            // Convert the interrupt number to an integer for processing
            match interrupt_number.parse::<u8>() {
                Ok(0x3) => {
                    // INT3 (debug breakpoint) handling
                    eprintln!("INT3 (debug breakpoint) encountered. Aborting execution.");

                    // Update concolic state
                    let swi_result_var_name = format!("swi_int3_{}", self.state.cpu_state.pc); // Use PC as a unique identifier
                    self.state.create_or_update_concolic_var_int(&swi_result_var_name, 0x3, 8);
                    
                    return Err("Execution aborted due to INT3 (debug breakpoint).".to_string());
                },
                // Handle other software interrupts ?
                _ => {
                    eprintln!("Unhandled software interrupt (SWI) encountered: {}", interrupt_number);
                    return Err(format!("Unhandled software interrupt (SWI) encountered: {}", interrupt_number));
                }
            }
        } else {
            // If the interrupt number is missing or invalid, report an error
            return Err("SWI operation requires a valid interrupt number.".to_string());
        }
    }

}

