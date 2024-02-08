use crate::{concolic_var::{ConcreteValue, SymbolicValue}, state::State};
use parser::parser::{Inst, Opcode, Size, Varnode};
use z3::{ast::BV, Context, Solver};
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
        //state.setup();

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
            Opcode::Ceil => todo!(),
            Opcode::CBranch => todo!(), // adds a condition to the jump, taken if a specified condition evaluates to true
            Opcode::Copy => self.handle_copy(instruction),
            Opcode::CPoolRef => todo!(), // returns runtime-dependent values from the constant pool
            Opcode::CrossBuild => todo!(),
            Opcode::DelaySlot => todo!(),
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
        let result_var_name = format!("{:?}", output_varnode.var);
        self.state.create_concolic_var_int(&result_var_name, result as u64, 1);

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

        // Adjusted check for NaN and floating-point equality
        let result = match (input0_value, input1_value) {
            (ConcreteValue::Float(f0), ConcreteValue::Float(f1)) => {
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
    
        let result = match (input0_value, input1_value) {
            (ConcreteValue::Float(f0), ConcreteValue::Float(f1)) => {
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
    
        let result_var_name = format!("{:?}", output.var);
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_float(result, &result_var_name, self.state.ctx));
    
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
        let result = match (input0_value, input1_value) {
            (ConcreteValue::Float(f0), ConcreteValue::Float(f1)) => {
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
        let result = match (input0_value, input1_value) {
            (ConcreteValue::Float(f0), ConcreteValue::Float(f1)) => {
                if f0.is_nan() || f1.is_nan() {
                    0.0 // False if either input is NaN
                } else {
                    if f0 <= f1 { 1.0 } else { 0.0 }
                }
            },
            _ => return Err("Expected floating-point values for FLOAT_LESSEQUAL".to_string()),
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
        let result = match (input0_value, input1_value) {
            (ConcreteValue::Float(f0), ConcreteValue::Float(f1)) => {
                if f0.is_nan() || f1.is_nan() {
                    f64::NAN // Use f64::NAN directly for NaN case
                } else {
                    f0 + f1 // Compute the sum
                }
            },
            _ => return Err("Expected floating-point values for FLOAT_ADD".to_string()),
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
        let result = match (input0_value, input1_value) {
            (ConcreteValue::Float(f0), ConcreteValue::Float(f1)) => {
                if f0.is_nan() || f1.is_nan() {
                    f64::NAN // Use f64::NAN for NaN case
                } else {
                    f0 - f1 // Compute the subtraction
                }
            },
            _ => return Err("Expected floating-point values for FLOAT_SUB".to_string()),
        };

        // Create and store the result as a floating-point concolic variable.
        let result_var_name = format!("{:?}", output.var);
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_float(result, &result_var_name, self.context));
    
        Ok(())
    }

    pub fn handle_float_floor(&mut self, instruction: Inst) -> Result<(), String> {
        // Validate the instruction format and ensure exactly one input is provided
        if instruction.opcode != Opcode::FloatFloor || instruction.inputs.len() != 1 {
            return Err("Invalid instruction format for FLOAT_FLOOR".to_string());
        }
    
        // Ensure the output varnode is defined
        let output = instruction.output.as_ref().ok_or("Output varnode is required")?;
    
        // Retrieve the concrete value of the input operand
        let input0_value = self.state.get_concrete_var(&instruction.inputs[0])?;
    
        let result = match input0_value {
            ConcreteValue::Float(f0) => {
                if f0.is_nan() {
                    f64::NAN // Keep NaN if input is NaN
                } else {
                    f0.floor() // Apply the floor operation
                }
            },
            _ => return Err("Expected a floating-point value for FLOAT_FLOOR".to_string()),
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
        let result = match (input0_value, input1_value) {
            (ConcreteValue::Float(f0), ConcreteValue::Float(f1)) => {
                if f0.is_nan() || f1.is_nan() {
                    f64::NAN
                } else {
                    f0 * f1 // Perform the multiplication
                }
            },
            _ => return Err("Expected floating-point values for FLOAT_MULT".to_string()),
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
        let result = match (input0_value, input1_value) {
            (ConcreteValue::Float(f0), ConcreteValue::Float(f1)) => {
                if f0.is_nan() || f1.is_nan() || f1 == 0.0 {
                    f64::NAN
                } else {
                    f0 / f1
                }
            },
            _ => return Err("Expected floating-point values for FLOAT_DIV".to_string()),
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
        let result = match input0_value {
            ConcreteValue::Float(f0) => {
                if f0.is_nan() {
                    f64::NAN
                } else {
                    -f0
                }
            },
            _ => return Err("Expected a floating-point value for FLOAT_NEG".to_string()),
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
    
        let result = match input0_value {
            ConcreteValue::Float(f0) => f0.abs(), // Compute the absolute value, NaN stays NaN.
            _ => return Err("Expected a floating-point value for FLOAT_ABS".to_string()),
        };
    
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
    
        let result = match input0_value {
            ConcreteValue::Float(f0) => f0.sqrt(), // Correctly handle sqrt operation, including NaN and negative inputs.
            _ => return Err("Expected a floating-point value for FLOAT_SQRT".to_string()),
        };

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
    
        let result = match input0_value {
            ConcreteValue::Float(f0) => if f0.is_nan() { 1.0 } else { 0.0 },
            _ => return Err("Expected a floating-point value for FLOAT_NAN".to_string()),
        };

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
    
        let result = match input0_value {
            ConcreteValue::Int(i0) => i0 as f64, // Handle conversion from integer to float.
            _ => return Err("Expected an integer value for INT2FLOAT".to_string()),
        };

        let result_var_name = format!("{:?}", output.var);
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_float(result, &result_var_name, self.context));
    
        Ok(())
    }

    pub fn handle_float2float(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::Float2Float || instruction.inputs.len() != 1 {
            return Err("Invalid instruction format for FLOAT2FLOAT".to_string());
        }
    
        let output = instruction.output.as_ref().ok_or("Output varnode is required".to_string())?;
        
        let input0_value = self.state.get_concrete_var(&instruction.inputs[0])?;

        let result = match input0_value {
            ConcreteValue::Float(f0) => f0, // Directly pass the floating-point value
            _ => return Err("Expected a floating-point value for FLOAT2FLOAT".to_string()),
        };
    
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
    
        let result = match input0_value {
            ConcreteValue::Float(f0) => f0.trunc(), // Truncate the fractional part
            _ => return Err("Expected a floating-point value for TRUNC".to_string()),
        };
    
        // Convert the truncated f64 to a u64 for storage as an integer variable.
        let result_as_int = result as u64;
        let bitvector_size = output.size.to_bitvector_size(); 
    
        self.state.create_concolic_var_int(&format!("{:?}", output.var), result_as_int, bitvector_size);
    
        Ok(())
    }

    pub fn handle_load(&mut self, instruction: Inst) -> Result<(), String> {
        // Ensure the instruction has an output and the correct number of inputs.
        let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required for LOAD")?;
        let offset_var = self.state.get_concolic_var(&format!("{:?}", instruction.inputs[1].var))
            .ok_or("Offset variable not found")?;
    
        if let ConcreteValue::Int(offset) = offset_var.concrete {
            // Determine the number of bytes to read based on the output size.
            let size_in_bytes = match output_varnode.size {
                Size::Byte => 1,
                Size::Half => 2,
                Size::Word => 4,
                Size::Quad => 8,
            };
    
            // Perform the memory read operation.
            let data_result = self.state.memory.read_memory(offset, size_in_bytes)
                .map_err(|e| format!("Error reading memory for LOAD: {}", e));
    
            match data_result {
                Ok(data) => {
                    // Convert the read bytes to a concrete value. (int values)
                    let mut read_value: u64 = 0;
                    for (i, byte) in data.iter().enumerate() {
                        read_value |= (*byte as u64) << (8 * i);
                    }
    
                    // Update the concrete state with the read value.
                    let concrete_value = ConcreteValue::Int(read_value);
    
                    // For symbolic execution, create a new symbolic expression representing this load.
                    // The symbolic name is now directly based on the offset, simplifying the representation.
                    let symbolic_name = format!("{}", offset);
                    let symbolic_value = BV::new_const(&self.state.ctx, &*symbolic_name, (size_in_bytes * 8).try_into().unwrap());
    
                    // Update the state with the new concolic variable.
                    let new_concolic_var = ConcolicVar {
                        concrete: concrete_value,
                        symbolic: SymbolicValue::Int(symbolic_value),
                    };
                    self.state.set_var(&format!("{:?}", output_varnode.var), new_concolic_var);
                },
                Err(e) => return Err(e),
            }
        } else {
            return Err("Offset must be an integer for LOAD operation".to_string());
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
        let result_var_name = format!("{:?}", output_varnode.var);
        let bitvector_size = output_varnode.size.to_bitvector_size();
        self.state.create_concolic_var_int(&result_var_name, carry_as_u64, bitvector_size);
    
        Ok(())
    }
    
    fn initialize_var_if_absent(&mut self, varnode: &Varnode) -> Result<u64, String> {
        let var_name = format!("{:?}", varnode.var);
    
        match self.state.get_concrete_var(varnode) {
            Ok(ConcreteValue::Int(val)) => Ok(val), // Directly return u64 value
            Ok(ConcreteValue::Float(_)) => Err("Expected an integer value, found a float".to_string()),
            Err(_) => {
                // If the variable is not found, initialize it as an integer with a default value
                let initial_value = 0u64; // Use u64 for initialization to match ConcreteValue::Int
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
        let result_var_name = format!("{:?}", output_varnode.var);
        let overflow_occurred_as_int = if overflow_occurred { 1 } else { 0 };
        self.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(overflow_occurred_as_int, &result_var_name, self.context, 1));

        Ok(())
    }

    pub fn handle_store(&mut self, instruction: Inst) -> Result<(), String> {
        if instruction.opcode != Opcode::Store || instruction.inputs.len() != 3 {
            return Err("Invalid instruction format for STORE".to_string());
        }

        let address_varnode = &instruction.inputs[1];
        let value_varnode = &instruction.inputs[2];

        // Retrieve or initialize the address variable as u64.
        let address = self.initialize_var_if_absent(address_varnode)
            .map_err(|e| format!("Failed to get or initialize address variable: {}", e))?;

        // Retrieve or initialize the value variable as u64, but use it according to its actual size.
        let value = self.initialize_var_if_absent(value_varnode)
            .map_err(|e| format!("Failed to get or initialize value variable: {}", e))?;

        match value_varnode.size {
            Size::Quad => self.state.memory.write_quad(address.into(), value.into())
                .map_err(|e| e.to_string()),

            Size::Word => {
                if u64::from(value) <= u32::MAX as u64 {
                    self.state.memory.write_word(address.into(), value as u32)
                        .map_err(|e| e.to_string())
                } else {
                    Err("Value out of range for a 32-bit write operation".to_string())
                }
            },

            Size::Half => {
                if u64::from(value) <= u16::MAX as u64 {
                    self.state.memory.write_half(address.into(), value as u16)
                        .map_err(|e| e.to_string())
                } else {
                    Err("Value out of range for a 16-bit write operation".to_string())
                }
            },

            Size::Byte => {
                if u64::from(value) <= u8::MAX as u64 {
                    self.state.memory.write_byte(address.into(), value as u8)
                        .map_err(|e| e.to_string())
                } else {
                    Err("Value out of range for an 8-bit write operation".to_string())
                }
            },
        }
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
        let result_var_name = format!("{:?}", output_varnode.var);
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
        let output_var_name = format!("{:?}", output_varnode.var);
        let bitvector_size = output_varnode.size.to_bitvector_size();
    
        // Update or create the concolic variable with the concrete result and a new symbolic expression
        self.state.create_concolic_var_int(&output_var_name, result_concrete, bitvector_size);
    
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
        let result_var_name = format!("{:?}", output_varnode.var);
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
        if instruction.opcode != Opcode::IntNegate || instruction.inputs.len() != 1 {
            return Err("Invalid instruction format for INT_NEGATE".to_string());
        }
    
        // Retrieve the concrete integer value for the input
        let input_val = self.initialize_var_if_absent(&instruction.inputs[0])?;
    
        // Perform NOT operation on the concrete integer value
        let negated_concrete = !input_val;
    
        // Prepare for the symbolic computation
        let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
        let output_var_name = format!("{:?}", output_varnode.var);
        let bitvector_size = output_varnode.size.to_bitvector_size();
    
        // Create or update the output concolic variable with the negated concrete value
        self.state.create_concolic_var_int(&output_var_name, negated_concrete, bitvector_size);
    
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
        let result_var_name = format!("{:?}", output_varnode.var);
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
            let output_var_name = format!("{:?}", output_varnode.var);
            let bitvector_size = output_varnode.size.to_bitvector_size();
    
            self.state.create_concolic_var_int(&output_var_name, popcount, bitvector_size);
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
            let output_var_name = format!("{:?}", output_varnode.var);
            let bitvector_size = output_varnode.size.to_bitvector_size();
    
            self.state.create_concolic_var_int(&output_var_name, lzcount, bitvector_size);
        }
    
        Ok(())
    }    
    
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::concolic_var::{ConcolicVar, ConcreteValue};
    use parser::parser::Var;
    use z3::{Config, Context};

    #[test]
    fn test_handle_load() {
        let context = Context::new(&Config::new());
        let mut executor = ConcolicExecutor::new(&context);

        // Mock memory address and value
        let memory_address: u64 = 0x100;
        let memory_value: u64 = 0xDEADBEEF;

        // Initialize memory with the value at the specified address
        executor.state.memory.write_quad(memory_address, memory_value).expect("Failed to write to memory");

        let offset_var_name = format!("{:?}", Var::Const("offset_var".to_string())); // Ensure this matches how handle_load retrieves it
        executor.state.set_var(&offset_var_name, ConcolicVar::new_concrete_and_symbolic_int(memory_address, &offset_var_name, &context, 64));

        // Mock instruction for LOAD
        let instruction = Inst {
            opcode: Opcode::Load,
            inputs: vec![
                Varnode { var: Var::Unique(memory_address), size: Size::Quad }, // Placeholder for memory space ID
                Varnode { var: Var::Const("offset_var".to_string()), size: Size::Quad }, // Offset into the memory
            ],
            output: Some(Varnode { var: Var::Register(1), size: Size::Quad }), // Destination register
        };

        // Execute handle_load
        let result = executor.handle_load(instruction);
        assert!(result.is_ok(), "handle_load failed with error: {:?}", result.err());

        // Verify the loaded value
        if let Some(concolic_var) = executor.state.get_concolic_var("Register(1)") {
            match concolic_var.concrete {
                ConcreteValue::Int(val) => assert_eq!(val, memory_value, "Loaded value does not match expected memory value"),
                _ => panic!("Output variable has incorrect type"),
            }
        } else {
            panic!("Output variable Register(1) not found");
        }
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
        executor.state.set_var("Register(1)", ConcolicVar::new_concrete_and_symbolic_int(100, "Register(1)", &context, 8));
        executor.state.set_var("Register(2)", ConcolicVar::new_concrete_and_symbolic_int(200, "Register(2)", &context, 8));

        // Execute handle_int_carry
        let result = executor.handle_int_carry(instruction);
        assert!(result.is_ok());
    }
}
