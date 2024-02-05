use crate::{concolic_var::SymbolicValue, state::State};
use parser::parser::{Inst, Opcode, Var, Size, Varnode};
use z3::{Context, Solver};
use crate::concolic::ConcolicVar;

#[derive(Debug)]
pub struct ConcolicExecutor<'a> {
    pub context: &'a Context,
    pub solver: Solver<'a>,
    pub state: State<'a>,
}

impl<'a> ConcolicExecutor<'a> {
    pub fn new(context: &'a Context) -> Self {
        let solver = z3::Solver::new(context);
        let state = State::new(context); 

        ConcolicExecutor { context, solver, state }
    }

    pub fn execute_instruction(&mut self, instruction: Inst) {
        match instruction.opcode {
            Opcode::Blank => todo!(),
            Opcode::BoolAnd => self.handle_bool_and(instruction),
            Opcode::BoolNegate => self.handle_bool_negate(instruction),
            Opcode::BoolOr => self.handle_bool_or(instruction),
            Opcode::BoolXor => self.handle_bool_xor(instruction),
            Opcode::Branch => todo!(), // unconditional jump to a specified address
            Opcode::BranchInd => todo!(),
            Opcode::Build => todo!(),
            Opcode::Call => todo!(), // function call, semantically similar to a branch but represents execution flow transferring to a subroutine
            Opcode::CallInd => todo!(), // indirect call to a dynamically determined address
            Opcode::CallOther => todo!(), // not existing anymore
            Opcode::Cast => todo!(),
            Opcode::Ceil => todo!(),
            Opcode::CBranch => todo!(), // adds a condition to the jump, taken if a specified condition evaluates to true
            Opcode::Copy => self.handle_copy(instruction),
            Opcode::CPoolRef => todo!(), // returns runtime-dependent values from the constant pool
            Opcode::CrossBuild => todo!(),
            Opcode::DelaySlot => todo!(),
            Opcode::Extract => todo!(),
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
            Opcode::Floor => todo!(),
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
            Opcode::Insert => todo!(),
            Opcode::Label => todo!(),
            Opcode::Load => self.handle_load(instruction),
            Opcode::LZCount => self.handle_lzcount(instruction),
            Opcode::New => todo!(), // allocates memory for an object and returns a pointer to that memory
            Opcode::Piece => todo!(), // concatenation operation that combines two inputs
            Opcode::PopCount => self.handle_popcount(instruction),
            Opcode::Return => todo!(), // indicates a return from a subroutine
            Opcode::Round => todo!(),
            Opcode::SegmentOp => todo!(),
            Opcode::Store => self.handle_store(instruction),
            Opcode::SubPiece => todo!(),
            Opcode::Trunc => self.handle_trunc(instruction),
            Opcode::Unused1 => todo!(),
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
        let result_var_name = format!("{:?}", output_varnode.var);
        self.state.create_concolic_var(&result_var_name, result as f64, 1);
    
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
        let result_var_name = format!("{:?}", output_varnode.var);
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
        let result_var_name = format!("{:?}", output_varnode.var);
        self.state.create_concolic_var(&result_var_name, result as f64, 1);
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
        let result_var_name = format!("{:?}", output_varnode.var);
        self.state.create_concolic_var(&result_var_name, result as f64, 1);

        Ok(())
    }

    

    pub fn handle_float_equal(&mut self, instruction: Inst) -> Result<(), String> {
        // Validate the instruction format and ensure there are exactly two inputs
        if instruction.opcode != Opcode::FloatEqual || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for FLOAT_EQUAL".to_string());
        }
    
        // Ensure the output is defined and its size is appropriate for a boolean result
        let output = instruction.output.as_ref().expect("Output varnode is required");
        if output.size != Size::Byte {
            return Err("Output must be size 1 for FLOAT_EQUAL".to_string());
        }
    
        // Fetch the floating-point values from the inputs
        let input0_value = self.state.get_concrete_var(&instruction.inputs[0])?; 
        let input1_value = self.state.get_concrete_var(&instruction.inputs[1])?; 
    
        // Perform the floating-point equality check
        let result = if input0_value.is_nan() || input1_value.is_nan() {
            0.0 // Represent false as 0.0
        } else {
            // For equality, consider two values equal if the difference is within a small epsilon
            if (input0_value - input1_value).abs() < f64::EPSILON {
                1.0 // Represent true as 1.0
            } else {
                0.0 // Represent false as 0.0
            }
        };
    
        // Store the result as a floating-point concolic variable
        let result_var_name = format!("{:?}", output.var);
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_float(result, &result_var_name, self.context));
    
        Ok(())
    }
    
    pub fn handle_float_notequal(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::FloatNotEqual || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for FLOAT_NOTEQUAL".to_string());
        }
    
        let output = instruction.output.as_ref().ok_or("Output varnode is required")?;
        if output.size != Size::Byte {
            return Err("Output must be size 1 for FLOAT_NOTEQUAL".to_string());
        }
    
        let input0_value = self.state.get_concrete_var(&instruction.inputs[0])?; 
        let input1_value = self.state.get_concrete_var(&instruction.inputs[1])?;
    
        let result = if input0_value.is_nan() || input1_value.is_nan() {
            0.0 // Use 0.0 to represent false
        } else {
            // Use 1.0 to represent true if not equal, 0.0 otherwise
            if (input0_value - input1_value).abs() >= f64::EPSILON {
                1.0
            } else {
                0.0
            }
        };
    
        // Store the result as a floating-point concolic variable
        let result_var_name = format!("{:?}", output.var);
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_float(result, &result_var_name, self.context));
    
        Ok(())
    }    

    pub fn handle_float_less(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::FloatLess || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for FLOAT_LESS".to_string());
        }
    
        let output = instruction.output.as_ref().ok_or("Output varnode is required")?;
        if output.size != Size::Byte {
            return Err("Output must be size 1 for FLOAT_LESS".to_string());
        }
    
        let input0_value = self.state.get_concrete_var(&instruction.inputs[0])?; 
        let input1_value = self.state.get_concrete_var(&instruction.inputs[1])?; 
        let result = if input0_value.is_nan() || input1_value.is_nan() {
            0.0 // Use 0.0 to represent false in case of NaN
        } else {
            // Use 1.0 to represent true (input0 < input1), 0.0 otherwise
            if input0_value < input1_value {
                1.0
            } else {
                0.0
            }
        };
    
        // Store the result as a floating-point concolic variable
        let result_var_name = format!("{:?}", output.var);
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_float(result, &result_var_name, self.context));
    
        Ok(())
    }
    
    pub fn handle_float_lessequal(&mut self, instruction: Inst) -> Result<(), String> {
        // Validate the instruction format and ensure exactly two inputs are provided
        if instruction.opcode != Opcode::FloatLessEqual || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for FLOAT_LESSEQUAL".to_string());
        }
    
        // Ensure the output is defined and its size is appropriate for a boolean result
        let output = instruction.output.as_ref().ok_or("Output varnode is required")?;
        if output.size != Size::Byte {
            return Err("Output must be size 1 for FLOAT_LESSEQUAL".to_string());
        }
    
        // Retrieve the concrete values of the input operands
        let input0_value = self.state.get_concrete_var(&instruction.inputs[0])?;
        let input1_value = self.state.get_concrete_var(&instruction.inputs[1])?;
    
        // Perform the comparison, taking into account the handling of NaN values
        let result = if input0_value.is_nan() || input1_value.is_nan() {
            0.0 // False if either input is NaN
        } else {
            if input0_value <= input1_value {
                1.0 
            } else {
                0.0 
            }
        };
    
        // Create and store the result as a floating-point concolic variable.
        let result_var_name = format!("{:?}", output.var);
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_float(result, &result_var_name, self.context));
    
        Ok(())
    }
      
    pub fn handle_float_add(&mut self, instruction: Inst) -> Result<(), String> {
        // Validate the instruction format and ensure exactly two inputs are provided
        if instruction.opcode != Opcode::FloatAdd || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for FLOAT_ADD".to_string());
        }

        // Ensure the output varnode is defined
        let output = instruction.output.as_ref().ok_or("Output varnode is required")?;
        
        // Retrieve the concrete values of the input operands
        let input0_value = self.state.get_concrete_var(&instruction.inputs[0])?;
        let input1_value = self.state.get_concrete_var(&instruction.inputs[1])?;

        // Perform the addition, handling NaN conditions explicitly
        let result = if input0_value.is_nan() || input1_value.is_nan() {
            f64::NAN // Set result to NaN if either input is NaN
        } else {
            input0_value + input1_value // Otherwise, compute the sum
        };

        // Create and store the result as a floating-point concolic variable
        let result_var_name = format!("{:?}", output.var);
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_float(result, &result_var_name, self.context));

        Ok(())
    }

    pub fn handle_float_sub(&mut self, instruction: Inst) -> Result<(), String> {
        // Validate the instruction format and ensure exactly two inputs are provided
        if instruction.opcode != Opcode::FloatSub || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for FLOAT_SUB".to_string());
        }
    
        // Ensure the output varnode is defined
        let output = instruction.output.as_ref().ok_or("Output varnode is required")?;
        
        // Retrieve the concrete values of the input operands
        let input0_value = self.state.get_concrete_var(&instruction.inputs[0])?;
        let input1_value = self.state.get_concrete_var(&instruction.inputs[1])?;
    
        // Perform the subtraction, handling NaN conditions explicitly
        let result = if input0_value.is_nan() || input1_value.is_nan() {
            f64::NAN // Set result to NaN if either input is NaN
        } else {
            input0_value - input1_value 
        };
    
        // Create and store the result as a floating-point concolic variable.
        let result_var_name = format!("{:?}", output.var);
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_float(result, &result_var_name, self.context));
    
        Ok(())
    }

    pub fn handle_float_mult(&mut self, instruction: Inst) -> Result<(), String> {
        // Validate the instruction format and ensure exactly two inputs are provided
        if instruction.opcode != Opcode::FloatMult || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for FLOAT_MULT".to_string());
        }

        // Ensure the output varnode is defined and matches the required size
        let output = instruction.output.as_ref().ok_or("Output varnode is required")?;
        
        // Retrieve the concrete values of the input operands
        let input0_value = self.state.get_concrete_var(&instruction.inputs[0])?;
        let input1_value = self.state.get_concrete_var(&instruction.inputs[1])?;

        // Perform the multiplication, handling NaN and overflow conditions
        let result = if input0_value.is_nan() || input1_value.is_nan() {
            f64::NAN 
        } else {
            input0_value * input1_value 
        };

        // Store the result as a floating-point concolic variable
        let result_var_name = format!("{:?}", output.var);
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_float(result, &result_var_name, self.context));

        Ok(())
    }

    pub fn handle_float_div(&mut self, instruction: Inst) -> Result<(), String> {
        // Validate the instruction format and ensure exactly two inputs are provided
        if instruction.opcode != Opcode::FloatDiv || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for FLOAT_DIV".to_string());
        }

        // Ensure the output varnode is defined and matches the required size
        let output = instruction.output.as_ref().ok_or("Output varnode is required")?;
        
        // Retrieve the concrete values of the input operands.
        let input0_value = self.state.get_concrete_var(&instruction.inputs[0])?;
        let input1_value = self.state.get_concrete_var(&instruction.inputs[1])?;

        // Perform the division, handling NaN, overflow, and division by zero conditions.
        let result = if input0_value.is_nan() || input1_value.is_nan() || input1_value == 0.0 {
            f64::NAN 
        } else {
            input0_value / input1_value 
        };

        // Store the result as a floating-point concolic variable
        let result_var_name = format!("{:?}", output.var);
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_float(result, &result_var_name, self.context));

        Ok(())
    }

    pub fn handle_float_neg(&mut self, instruction: Inst) -> Result<(), String> {
        // Validate the instruction format and ensure exactly one input is provided
        if instruction.opcode != Opcode::FloatNeg || instruction.inputs.len() != 1 {
            return Err("Invalid instruction format for FLOAT_NEG".to_string());
        }
    
        // Ensure the output varnode is defined and matches the required size
        let output = instruction.output.as_ref().ok_or("Output varnode is required")?;
        
        // Retrieve the concrete value of the input operand
        let input0_value = self.state.get_concrete_var(&instruction.inputs[0])?;
    
        // Perform the negation, handling NaN conditions
        let result = if input0_value.is_nan() {
            f64::NAN 
        } else {
            -input0_value 
        };
    
        // Store the result as a floating-point concolic variable.
        let result_var_name = format!("{:?}", output.var);
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_float(result, &result_var_name, self.context));
    
        Ok(())
    }

    pub fn handle_float_abs(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::FloatAbs || instruction.inputs.len() != 1 {
            return Err("Invalid instruction format for FLOAT_ABS".to_string());
        }
    
        let output = instruction.output.as_ref().ok_or("Output varnode is required")?;
        
        let input0_value = self.state.get_concrete_var(&instruction.inputs[0])?;
    
        let result = input0_value.abs(); // Compute the absolute value, NaN stays NaN.
    
        let result_var_name = format!("{:?}", output.var);
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_float(result, &result_var_name, self.context));
    
        Ok(())
    }

    pub fn handle_float_sqrt(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::FloatSqrt || instruction.inputs.len() != 1 {
            return Err("Invalid instruction format for FLOAT_SQRT".to_string());
        }
    
        let output = instruction.output.as_ref().ok_or("Output varnode is required")?;
        
        let input0_value = self.state.get_concrete_var(&instruction.inputs[0])?;
    
        let result = input0_value.sqrt(); // Compute the square root, NaN stays NaN.
    
        let result_var_name = format!("{:?}", output.var);
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_float(result, &result_var_name, self.context));
    
        Ok(())
    } 

    pub fn handle_float_nan(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::FloatNaN || instruction.inputs.len() != 1 {
            return Err("Invalid instruction format for FLOAT_NAN".to_string());
        }
    
        let output = instruction.output.as_ref().ok_or("Output varnode is required".to_string())?;
        
        let input0_value = self.state.get_concrete_var(&instruction.inputs[0])?;
    
        let result = if input0_value.is_nan() { 1.0 } else { 0.0 }; // True if NaN, represented as 1.0; false as 0.0.
    
        let result_var_name = format!("{:?}", output.var);
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_float(result, &result_var_name, self.context));
    
        Ok(())
    }
    
    pub fn handle_int2float(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::Int2Float || instruction.inputs.len() != 1 {
            return Err("Invalid instruction format for INT2FLOAT".to_string());
        }
    
        let output = instruction.output.as_ref().ok_or("Output varnode is required".to_string())?;
        
        let input0_value = self.state.get_concrete_var(&instruction.inputs[0])?;
    
        // Assuming input0_value is retrieved as an i64, convert to f64 for floating-point representation.
        let result = input0_value as f64;
    
        let result_var_name = format!("{:?}", output.var);
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_float(result, &result_var_name, self.context));
    
        Ok(())
    }

    pub fn handle_float2float(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::Float2Float || instruction.inputs.len() != 1 {
            return Err("Invalid instruction format for FLOAT2FLOAT".to_string());
        }
    
        let output = instruction.output.as_ref().ok_or("Output varnode is required".to_string())?;
        
        // Directly pass the floating-point value through since Rust handles f64 by default
        let input0_value = self.state.get_concrete_var(&instruction.inputs[0])?;
    
        // No conversion logic needed in Rust for f64 to f64 (?)
        let result = input0_value;
    
        let result_var_name = format!("{:?}", output.var);
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_float(result, &result_var_name, self.context));
    
        Ok(())
    }

    pub fn handle_trunc(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::Trunc || instruction.inputs.len() != 1 {
            return Err("Invalid instruction format for TRUNC".to_string());
        }
    
        let output = instruction.output.as_ref().ok_or("Output varnode is required".to_string())?;
        
        let input0_value = self.state.get_concrete_var(&instruction.inputs[0])?;
    
        // Convert floating-point value to integer by truncating the fractional part.
        let result = input0_value.trunc(); // Result is still f64, but without the fractional part.
    
        let bitvector_size = output.size.to_bitvector_size(); 
    
        self.state.create_concolic_var(&format!("{:?}", output.var), result, bitvector_size);
    
        Ok(())
    }

    pub fn handle_load(&mut self, instruction: Inst) -> Result<(), String> {
        // Ensure the correct instruction format
        if instruction.opcode != Opcode::Load || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for LOAD".to_string());
        }

        // Resolve the offset
        let offset = match instruction.inputs[1].var {
            Var::Register(reg) | Var::Unique(reg) => reg,
            _ => return Err("Input1 must be a Register or Unique type for offset".to_string()),
        };

        // Read the value from the resolved address
        let value = match instruction.output.as_ref().unwrap().size {
            Size::Quad => self.state.memory.read_quad(offset).map_err(|e| e.to_string())?,
            Size::Word => u64::from(self.state.memory.read_word(offset).map_err(|e| e.to_string())?),
            Size::Half => u64::from(self.state.memory.read_half(offset).map_err(|e| e.to_string())?),
            Size::Byte => u64::from(self.state.memory.read_byte(offset).map_err(|e| e.to_string())?),
        };

        // Create a new concolic variable with the read value and add it to the state
        let var_name = format!("{:?}", instruction.output.clone().unwrap().var);
        let _concolic_value = self.state.create_concolic_var(&var_name, value as f64, instruction.output.clone().unwrap().size.to_bitvector_size());

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
        let carry_as_f64 = if carry { 1.0 } else { 0.0 };
    
        // Store the result of the carry condition
        let result_var_name = format!("{:?}", output_varnode.var);
        let bitvector_size = output_varnode.size.to_bitvector_size();
        self.state.create_concolic_var(&result_var_name, carry_as_f64, bitvector_size);
    
        Ok(())
    }
    
    fn initialize_var_if_absent(&mut self, varnode: &Varnode) -> Result<u32, String> {
        match self.state.get_concrete_var(varnode) {
            Ok(val) => Ok(val as u32), // Ensure the return type is u32
            Err(_) => {
                let initial_value = 0u32; // Always treat as u32 for initialization
                let var_name = format!("{:?}", varnode.var);
    
                // Create a new concolic variable when initializing
                self.state.create_concolic_var(&var_name, initial_value as f64, varnode.size.to_bitvector_size());
    
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
        let result_var_name = format!("{:?}", output_varnode.var);
        let overflow_occurred_as_int = if overflow_occurred { 1 } else { 0 };
        let overflow_occurred_as_f64 = overflow_occurred_as_int as f64;
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(overflow_occurred_as_f64, &result_var_name, self.context, 1));

        Ok(())
    }

    pub fn handle_store(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::Store || instruction.inputs.len() != 3 {
            return Err("Invalid instruction format for STORE".to_string());
        }
    
        let address_varnode = &instruction.inputs[1];
        let value_varnode = &instruction.inputs[2];
    
        let address_var_name = format!("{:?}", address_varnode.var);
        let value_var_name = format!("{:?}", value_varnode.var);
    
        // Clone the concolic variables if they already exist, or create new ones.
        let address_var = self.state.concolic_vars.get(&address_var_name)
            .cloned()
            .unwrap_or_else(|| self.state.create_concolic_var(&address_var_name, 0.0, address_varnode.size.to_bitvector_size()).clone());
        let value_var = self.state.concolic_vars.get(&value_var_name)
            .cloned()
            .unwrap_or_else(|| self.state.create_concolic_var(&value_var_name, 0.0, value_varnode.size.to_bitvector_size()).clone());
    
        //if ConcolicVar::can_address_be_zero(&self.state.ctx, &address_var) {
        //    return Err("Potential bug: Address can be symbolically zero".to_string());
        //}
    
        let wordsize = 1.0; // Placeholder
        let byte_offset = (address_var.concrete * wordsize) as u64;
    
        // Perform the store operation
        match value_varnode.size {
            Size::Quad => self.state.memory.write_quad(byte_offset.into(), value_var.concrete as u64)?,
            Size::Word => self.state.memory.write_word(byte_offset.into(), value_var.concrete as u32)?,
            Size::Half => self.state.memory.write_half(byte_offset.into(), value_var.concrete as u16)?,
            Size::Byte => self.state.memory.write_byte(byte_offset.into(), value_var.concrete as u8)?,
        }
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
        let result_var_name = format!("{:?}", output_varnode.var);
        let bitvector_size = output_varnode.size.to_bitvector_size();
    
        // Update or create the concolic variable with the computed result
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result_value as f64, &result_var_name, self.context, bitvector_size));
    
        Ok(())
    }
    
    pub fn handle_int_sub(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::IntSub || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for INT_SUB".to_string());
        }

        let input0 = self.initialize_var_if_absent(&instruction.inputs[0])?;
        let input1 = self.initialize_var_if_absent(&instruction.inputs[1])?;

        // Ensure the sizes match
        let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required for INT_SUB")?;
        if instruction.inputs[0].size != instruction.inputs[1].size || instruction.inputs[0].size != output_varnode.size {
            return Err("Input and output sizes must match for INT_SUB".to_string());
        }

        // Perform the subtraction
        let result = input0.wrapping_sub(input1);

        // Create or update a concolic variable for the result
        let result_var_name = format!("{:?}", output_varnode.var);
        let bitvector_size = output_varnode.size.to_bitvector_size();
        self.state.create_concolic_var(&result_var_name, result as f64, bitvector_size);
        
        Ok(())
    }

    pub fn handle_int_xor(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::IntXor || instruction.inputs.len() != 2 {
            return Err("Invalid instruction format for COPY".to_string());
        }

        let input0_varnode = &instruction.inputs[0];
        let input1_varnode = &instruction.inputs[1];
        let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    
        let input0_var_name = format!("{:?}", input0_varnode.var);
        let input1_var_name = format!("{:?}", input1_varnode.var);
    
        let input0_concolic_var = self.state.get_concolic_var(&input0_var_name)
            .ok_or_else(|| format!("Input0 variable {} not found", input0_var_name))?;
        let input1_concolic_var = self.state.get_concolic_var(&input1_var_name)
            .ok_or_else(|| format!("Input1 variable {} not found", input1_var_name))?;
    
        if let (SymbolicValue::Int(input0_bv), SymbolicValue::Int(input1_bv)) = (&input0_concolic_var.symbolic, &input1_concolic_var.symbolic) {
            let result_bv = input0_bv.bvxor(input1_bv);
    
            // Calculate the concrete value for XOR. This simplistic approach may need adjustment
            let result_concrete = f64::from_bits(input0_concolic_var.concrete.to_bits() ^ input1_concolic_var.concrete.to_bits());
    
            let output_var_name = format!("{:?}", output_varnode.var);
            self.state.create_concolic_var(&output_var_name, result_concrete, output_varnode.size.to_bitvector_size());
    
            // Update the symbolic part of the output concolic variable
            self.state.concolic_vars.get_mut(&output_var_name).unwrap().update_symbolic_int(result_bv);
        } else {
            return Err("INT_XOR operation requires integer symbolic values".to_string());
        }
    
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
        let result_var_name = format!("{:?}", output_varnode.var);
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
        let result_var_name = format!("{:?}", output_varnode.var);
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
        let result_var_name = format!("{:?}", output_varnode.var);
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
        let result_var_name = format!("{:?}", output_varnode.var);
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
        let result_var_name = format!("{:?}", output_varnode.var);
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
        let result_var_name = format!("{:?}", output_varnode.var);
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
        let result_var_name = format!("{:?}", output_varnode.var);
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
    
        // No actual extension code is required here since we're working within a symbolic execution context
        // The symbolic variable's size dictates the bit-width, and the concrete value is unaffected by the extension
        let input_value = self.initialize_var_if_absent(&instruction.inputs[0])?;
        let result_var_name = format!("{:?}", output_varnode.var);
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
        let result_var_name = format!("{:?}", output_varnode.var);
        // Ensure the value is truncated or zero-extended based on the output size
        let result = extended_value & ((1u64 << (output_varnode.size.to_bitvector_size() * 8)) - 1);
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result as f64, &result_var_name, self.context, output_varnode.size.to_bitvector_size()));
    
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
    
        // Convert the subtraction result to f64
        let result_f64 = sub_result as f64;
    
        // Store the result
        let result_var_name = format!("{:?}", output_varnode.var);
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result_f64, &result_var_name, self.context, output_varnode.size.to_bitvector_size()));
    
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
        let result_var_name = format!("{:?}", output_varnode.var);
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
        let result_var_name = format!("{:?}", output_varnode.var);
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
        let result_var_name = format!("{:?}", output_varnode.var);
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
        let result_var_name = format!("{:?}", output_varnode.var);
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
        let result_var_name = format!("{:?}", output_varnode.var);
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
        let result_var_name = format!("{:?}", output_varnode.var);
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
        let result_var_name = format!("{:?}", output_varnode.var);
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result.into(), &result_var_name, self.context, output_varnode.size.to_bitvector_size()));
    
        Ok(())
    }

    pub fn handle_int_negate(&mut self, instruction: Inst) -> Result<(), String> {
        // Validate instruction format and sizes
        if instruction.opcode != Opcode::IntNegate || instruction.inputs.len() != 1 {
            return Err("Invalid instruction format for INT_DIV".to_string());
        }

        let input_varnode = &instruction.inputs[0];
        let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    
        let var_name = format!("{:?}", input_varnode.var);
        let input_concolic_var = self.state.get_concolic_var(&var_name)
            .ok_or_else(|| format!("Input variable {} not found", var_name))?;
    
        // Verify if the symbolic value is an integer
        if let SymbolicValue::Int(input_bv) = &input_concolic_var.symbolic {
            // Perform bitwise NOT on the symbolic bit-vector
            let negated_bv = input_bv.bvnot();
    
            // The concrete value calculation depends on your system's handling of f64 to integer mappings
            let negated_concrete = !input_concolic_var.concrete.to_bits() as f64;
    
            // Create or update the output concolic variable
            let output_var_name = format!("{:?}", output_varnode.var);
            self.state.create_concolic_var(&output_var_name, negated_concrete, output_varnode.size.to_bitvector_size());
    
            // Update the symbolic part of the output concolic variable
            self.state.concolic_vars.get_mut(&output_var_name).unwrap().update_symbolic_int(negated_bv);
        } else {
            return Err("INT_NEGATE operation requires an integer symbolic value".to_string());
        }
    
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
        if input1_value == 0 {
            // Instead of proceeding with division, return an error
            return Err("Division by zero encountered in INT_DIV".to_string());
        }
    
        // Perform division
        let result = input0_value / input1_value;
    
        // Store the result
        let result_var_name = format!("{:?}", output_varnode.var);
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
        let result_var_name = format!("{:?}", output_varnode.var);
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
        let result_var_name = format!("{:?}", output_varnode.var);
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result.into(), &result_var_name, self.context, output_varnode.size.to_bitvector_size()));
    
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
        let result_var_name = format!("{:?}", output_varnode.var);
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result.into(), &result_var_name, self.context, output_varnode.size.to_bitvector_size()));
    
        Ok(())
    }

    pub fn handle_popcount(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::PopCount || instruction.inputs.len() != 1 {
            return Err("Invalid instruction format for POPCOUNT".to_string());
        }

        let input_varnode = &instruction.inputs[0];
        let input_var_name = format!("{:?}", input_varnode.var);
        let input_concolic_var = self.state.get_concolic_var(&input_var_name)
            .ok_or_else(|| format!("Input variable {} not found", input_var_name))?;
        
        let input_value = input_concolic_var.concrete as u64;
        let popcount = input_value.count_ones() as f64;

        if let Some(output_varnode) = &instruction.output {
            let output_var_name = format!("{:?}", output_varnode.var);
            self.state.create_concolic_var(&output_var_name, popcount, 32); // Adjust the bitvector size as necessary.
        }

        Ok(())
    }

    pub fn handle_lzcount(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::LZCount || instruction.inputs.len() != 1 {
            return Err("Invalid instruction format for LZCOUNT".to_string());
        }
    
        let input_varnode = &instruction.inputs[0];
        let input_var_name = format!("{:?}", input_varnode.var);
        let input_concolic_var = self.state.get_concolic_var(&input_var_name)
            .ok_or_else(|| format!("Input variable {} not found", input_var_name))?;
        
        let input_value = input_concolic_var.concrete as u64;
        let lzcount = input_value.leading_zeros() as f64;
    
        if let Some(output_varnode) = &instruction.output {
            let output_var_name = format!("{:?}", output_varnode.var);
            self.state.create_concolic_var(&output_var_name, lzcount, 32); // Adjust the bitvector size as necessary.
        }
    
        Ok(())
    }
    


    

    
    
}

#[cfg(test)]
mod tests {
    use super::*;
    use parser::parser::{Opcode, Var, Varnode, Size};

    #[test]
    fn test_handle_load() {
        let context = Context::new(&z3::Config::new());
        let mut executor = ConcolicExecutor::new(&context);

        // Mock instruction for LOAD
        let instruction = Inst {
            opcode: Opcode::Load,
            inputs: vec![
                Varnode { var: Var::Register(1), size: Size::Word },
                Varnode { var: Var::Unique(2), size: Size::Word },
            ],
            output: Some(Varnode { var: Var::Unique(3), size: Size::Word }),
        };

        // Execute handle_load
        let result = executor.handle_load(instruction);
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_int_carry() {
        let context = Context::new(&z3::Config::new());
        let mut executor = ConcolicExecutor::new(&context);

        // Mock instruction for INT_CARRY
        let instruction = Inst {
            opcode: Opcode::IntCarry,
            inputs: vec![
                Varnode { var: Var::Register(1), size: Size::Byte },
                Varnode { var: Var::Register(2), size: Size::Byte },
            ],
            output: Some(Varnode { var: Var::Register(3), size: Size::Byte }),
        };

        // Initialize the variables involved in the instruction
        executor.state.set_var("Register(1)", ConcolicVar::new_concrete_and_symbolic_int(100.0, "Register(1)", &context, 8));
        executor.state.set_var("Register(2)", ConcolicVar::new_concrete_and_symbolic_int(200.0, "Register(2)", &context, 8));

        // Execute handle_int_carry
        let result = executor.handle_int_carry(instruction);
        assert!(result.is_ok());
    }
}
