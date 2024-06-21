/// Focuses on implementing the execution of the FLOAT related opcodes from Ghidra's Pcode specification
/// This implementation relies on Ghidra 11.0.1 with the specfiles in /specfiles

use crate::executor::ConcolicExecutor;
use parser::parser::{Inst, Opcode, Size};

use super::ConcreteVar;

pub fn handle_float_equal(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
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
    let input0_value = executor.state.get_concrete_var(&instruction.inputs[0])?;
    let input1_value = executor.state.get_concrete_var(&instruction.inputs[1])?;

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

    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    //executor.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_float(result, &result_var_name, executor.state.ctx));

    Ok(())
}

pub fn handle_float_notequal(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::FloatNotEqual || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for FLOAT_NOTEQUAL".to_string());
    }

    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    if output_varnode.size != Size::Byte {
        return Err("Output must be size 1 for FLOAT_NOTEQUAL".to_string());
    }

    let input0_value = executor.state.get_concrete_var(&instruction.inputs[0])?; 
    let input1_value = executor.state.get_concrete_var(&instruction.inputs[1])?;

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

    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    //executor.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_float(result, &result_var_name, executor.state.ctx));

    Ok(())
}

pub fn handle_float_less(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::FloatLess || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for FLOAT_LESS".to_string());
    }

    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    if output_varnode.size != Size::Byte {
        return Err("Output must be size 1 for FLOAT_LESS".to_string());
    }

    let input0_value = executor.state.get_concrete_var(&instruction.inputs[0])?; 
    let input1_value = executor.state.get_concrete_var(&instruction.inputs[1])?; 
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
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    //executor.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_float(result, &result_var_name, executor.context));

    Ok(())
}

pub fn handle_float_lessequal(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
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
    let input0_value = executor.state.get_concrete_var(&instruction.inputs[0])?;
    let input1_value = executor.state.get_concrete_var(&instruction.inputs[1])?;

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
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    //executor.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_float(result, &result_var_name, executor.context));

    Ok(())
}
  
pub fn handle_float_add(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Validate the instruction format and ensure exactly two inputs are provided
    if instruction.opcode != Opcode::FloatAdd || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for FLOAT_ADD".to_string());
    }

    // Ensure the output varnode is defined
    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    
    // Retrieve the concrete values of the input operands
    let input0_value = executor.state.get_concrete_var(&instruction.inputs[0])?;
    let input1_value = executor.state.get_concrete_var(&instruction.inputs[1])?;

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
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    //executor.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_float(result, &result_var_name, executor.context));

    Ok(())
}

pub fn handle_float_sub(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Validate the instruction format and ensure exactly two inputs are provided
    if instruction.opcode != Opcode::FloatSub || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for FLOAT_SUB".to_string());
    }

    // Ensure the output varnode is defined
    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    
    // Retrieve the concrete values of the input operands
    let input0_value = executor.state.get_concrete_var(&instruction.inputs[0])?;
    let input1_value = executor.state.get_concrete_var(&instruction.inputs[1])?;

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
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    //executor.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_float(result, &result_var_name, executor.context));

    Ok(())
}

pub fn handle_float_floor(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Validate the instruction format and ensure exactly one input is provided
    if instruction.opcode != Opcode::FloatFloor || instruction.inputs.len() != 1 {
        return Err("Invalid instruction format for FLOAT_FLOOR".to_string());
    }

    // Ensure the output varnode is defined
    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;

    // Retrieve the concrete value of the input operand
    let input0_value = executor.state.get_concrete_var(&instruction.inputs[0])?;

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
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    //executor.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_float(result, &result_var_name, executor.context));

    Ok(())
}


pub fn handle_float_mult(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Validate the instruction format and ensure exactly two inputs are provided
    if instruction.opcode != Opcode::FloatMult || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for FLOAT_MULT".to_string());
    }

    // Ensure the output varnode is defined and matches the required size
    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    
    // Retrieve the concrete values of the input operands
    let input0_value = executor.state.get_concrete_var(&instruction.inputs[0])?;
    let input1_value = executor.state.get_concrete_var(&instruction.inputs[1])?;

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
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    //executor.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_float(result, &result_var_name, executor.context));

    Ok(())
}

pub fn handle_float_div(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Validate the instruction format and ensure exactly two inputs are provided
    if instruction.opcode != Opcode::FloatDiv || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for FLOAT_DIV".to_string());
    }

    // Ensure the output varnode is defined and matches the required size
    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    
    // Retrieve the concrete values of the input operands.
    let input0_value = executor.state.get_concrete_var(&instruction.inputs[0])?;
    let input1_value = executor.state.get_concrete_var(&instruction.inputs[1])?;

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
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    //executor.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_float(result, &result_var_name, executor.context));

    Ok(())
}

pub fn handle_float_neg(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Validate the instruction format and ensure exactly one input is provided
    if instruction.opcode != Opcode::FloatNeg || instruction.inputs.len() != 1 {
        return Err("Invalid instruction format for FLOAT_NEG".to_string());
    }

    // Ensure the output varnode is defined and matches the required size
    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    
    // Retrieve the concrete value of the input operand
    let input0_value = executor.state.get_concrete_var(&instruction.inputs[0])?;

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
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    //executor.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_float(result, &result_var_name, executor.context));

    Ok(())
}

pub fn handle_float_abs(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::FloatAbs || instruction.inputs.len() != 1 {
        return Err("Invalid instruction format for FLOAT_ABS".to_string());
    }

    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    
    let input0_value = executor.state.get_concrete_var(&instruction.inputs[0])?;

    let result = match input0_value {
        ConcreteVar::Float(f0) => f0.abs(), // Compute the absolute value, NaN stays NaN.
        _ => return Err("Expected a floating-point value for FLOAT_ABS".to_string()),
    };

    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    //executor.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_float(result, &result_var_name, executor.context));

    Ok(())
}

pub fn handle_float_sqrt(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::FloatSqrt || instruction.inputs.len() != 1 {
        return Err("Invalid instruction format for FLOAT_SQRT".to_string());
    }

    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    
    let input0_value = executor.state.get_concrete_var(&instruction.inputs[0])?;

    let result = match input0_value {
        ConcreteVar::Float(f0) => f0.sqrt(), // Correctly handle sqrt operation, including NaN and negative inputs.
        _ => return Err("Expected a floating-point value for FLOAT_SQRT".to_string()),
    };

    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    //executor.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_float(result, &result_var_name, executor.context));

    Ok(())
} 

pub fn handle_float_nan(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::FloatNaN || instruction.inputs.len() != 1 {
        return Err("Invalid instruction format for FLOAT_NAN".to_string());
    }

    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required".to_string())?;
    
    let input0_value = executor.state.get_concrete_var(&instruction.inputs[0])?;

    let result = match input0_value {
        ConcreteVar::Float(f0) => if f0.is_nan() { 1.0 } else { 0.0 },
        _ => return Err("Expected a floating-point value for FLOAT_NAN".to_string()),
    };

    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    //executor.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_float(result, &result_var_name, executor.context));

    Ok(())
}

pub fn handle_float2float(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::Float2Float || instruction.inputs.len() != 1 {
        return Err("Invalid instruction format for FLOAT2FLOAT".to_string());
    }

    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required".to_string())?;
    
    let input0_value = executor.state.get_concrete_var(&instruction.inputs[0])?;

    let result = match input0_value {
        ConcreteVar::Float(f0) => f0, // Directly pass the floating-point value
        _ => return Err("Expected a floating-point value for FLOAT2FLOAT".to_string()),
    };

    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    //executor.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_float(result, &result_var_name, executor.context));

    Ok(())
}