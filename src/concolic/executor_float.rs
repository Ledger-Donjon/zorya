/// Focuses on implementing the execution of the FLOAT related opcodes from Ghidra's Pcode specification
/// This implementation relies on Ghidra 11.0.1 with the specfiles in /specfiles

use crate::{concolic::ConcolicVar, executor::ConcolicExecutor};
use parser::parser::{Inst, Opcode, Size, Var, Varnode};
use z3::ast::{Bool, BV};
use std::io::Write;
use z3::ast::Ast;
use super::ConcreteVar;

macro_rules! log {
    ($logger:expr, $($arg:tt)*) => {{
        writeln!($logger, $($arg)*).unwrap();
    }};
}

fn handle_output<'ctx>(executor: &mut ConcolicExecutor<'ctx>, output_varnode: Option<&Varnode>, mut result_value: ConcolicVar<'ctx>) -> Result<(), String> {
    if let Some(varnode) = output_varnode {
        // Resize the result_value according to the output size specification
        let size_bits = varnode.size.to_bitvector_size() as u32;
        result_value.resize(size_bits);

        match &varnode.var {
            Var::Unique(id) => {
                let unique_name = format!("Unique(0x{:x})", id);
                executor.unique_variables.insert(unique_name, result_value.clone());
                log!(executor.state.logger.clone(), "Updated unique variable: Unique(0x{:x}) with concrete size {} bits, symbolic size {} bits", id, size_bits, result_value.symbolic.get_size());
                Ok(())
            },
            Var::Register(offset, _) => {
                log!(executor.state.logger.clone(), "Output is a Register type");
                let mut cpu_state_guard = executor.state.cpu_state.lock().unwrap();
                let concrete_value = result_value.concrete.to_u64();

                match cpu_state_guard.set_register_value_by_offset(*offset, result_value.clone(), size_bits) {
                    Ok(_) => {
                        log!(executor.state.logger.clone(), "Updated register at offset 0x{:x} with value 0x{:x}, size {} bits", offset, concrete_value, size_bits);
                        Ok(())
                    },
                    Err(e) => {
                        log!(executor.state.logger.clone(), "Error updating register at offset 0x{:x}: {}", offset, e);
                        // Handle the case where the register offset might be a sub-register
                        let closest_offset = cpu_state_guard.registers.keys().rev().find(|&&key| key < *offset);
                        if let Some(&base_offset) = closest_offset {
                            let diff = *offset - base_offset;
                            let full_reg_size = cpu_state_guard.register_map.get(&base_offset).map(|&(_, size)| size).unwrap_or(64);

                            if (diff * 8) + size_bits as u64 <= full_reg_size as u64 {
                                let original_value = cpu_state_guard.get_register_by_offset(base_offset, full_reg_size).unwrap();
                                let mask = ((1u64 << size_bits) - 1) << (diff * 8);
                                let new_value = (original_value.concrete.to_u64() & !mask) | ((concrete_value & ((1u64 << size_bits) - 1)) << (diff * 8));

                                cpu_state_guard.set_register_value_by_offset(base_offset, result_value.clone(), full_reg_size)
                                    .map_err(|e| {
                                        log!(executor.state.logger.clone(), "Error updating sub-register at offset 0x{:x}: {}", offset, e);
                                        e
                                    })
                                    .and_then(|_| {
                                        log!(executor.state.logger.clone(), "Updated sub-register at offset 0x{:x} with value 0x{:x}, size {} bits", offset, new_value, size_bits);
                                        Ok(())
                                    })
                            } else {
                                Err(format!("Cannot fit value into register at offset 0x{:x}", offset))
                            }
                        } else {
                            Err(format!("No suitable register found for offset 0x{:x}", offset))
                        }
                    }
                }
            },
            _ => {
                log!(executor.state.logger.clone(), "Output type is unsupported");
                Err("Output type not supported".to_string())
            }
        }
    } else {
        Err("No output varnode specified".to_string())
    }
}

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

    log!(executor.state.logger.clone(), "* Fetching floating-point input for FLOAT_NAN");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;

    let input_value = f64::from_bits(input0_var.get_concrete_value()); // Assumes floating-point input is stored as u64
    let result_concrete = input_value.is_nan();

    // Directly create a Bool from the boolean result
    let result_symbolic = Bool::from_bool(executor.context, result_concrete);

    log!(executor.state.logger.clone(), "Result of FLOAT_NAN check: {}", result_concrete);

    // The output should be a boolean value, ensure the output varnode is set properly
    if let Some(output_varnode) = instruction.output.as_ref() {
        let result_value = ConcolicVar::new_concrete_and_symbolic_bool(
            result_concrete,
            result_symbolic,
            executor.context,
            output_varnode.size.to_bitvector_size() as u32,
        );

        // Handle the result based on the output varnode
        handle_output(executor, Some(output_varnode), result_value.clone())?;

        // Create or update a concolic variable for the result
        let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}-{:02}-floatnan", current_addr_hex, executor.instruction_counter);
        executor.state.create_or_update_concolic_variable_bool(&result_var_name, result_value.concrete.to_bool(), result_value.symbolic);
    } else {
        return Err("Output varnode not specified for FLOAT_NAN instruction".to_string());
    }

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