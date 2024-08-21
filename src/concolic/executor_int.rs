/// Focuses on implementing the execution of the INT related opcodes from Ghidra's Pcode specification
/// This implementation relies on Ghidra 11.0.1 with the specfiles in /specfiles

use crate::concolic::executor::ConcolicExecutor;
use parser::parser::{Inst, Opcode, Var, Varnode};
use z3::ast::{Bool, Float, BV};
use std::io::Write;

use super::ConcolicVar;

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

// Function to handle INT_CARRY instruction
pub fn handle_int_carry(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntCarry || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_CARRY".to_string());
    }

    // Fetch the concolic variables for the inputs
    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for INT_CARRY");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
    log!(executor.state.logger.clone(), "* Fetching instruction.input[1] for INT_CARRY");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;

    let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    // Perform the unsigned addition and check for carry
    let bv_size = instruction.inputs[0].size.to_bitvector_size() as u32;
    let result_concrete = input0_var.get_concrete_value() as u128 + input1_var.get_concrete_value() as u128; // Use u128 to ensure no overflow in Rust
    let carry_concrete = result_concrete >> bv_size != 0; // If the result requires more bits than the size, there was a carry

    // Symbolic carry check
    let zero_bv = BV::from_u64(executor.context, 0, bv_size);
    let result_symbolic = input0_var.get_symbolic_value_bv(executor.context).bvadd(&input1_var.get_symbolic_value_bv(executor.context));
    let carry_symbolic = result_symbolic.bvadd_no_overflow(&zero_bv, false); // false for unsigned overflow check

    let result_value = ConcolicVar::new_concrete_and_symbolic_bool(carry_concrete, carry_symbolic, executor.context, output_size_bits);

    log!(executor.state.logger.clone(), "*** The result of INT_CARRY is: {:?}\n", carry_concrete);

    // Handle the result based on the output varnode
    handle_output(executor, instruction.output.as_ref(), result_value)?;

    Ok(())
}
  
pub fn handle_int_scarry(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntSCarry || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_SCARRY".to_string());
    }

    // Fetch the concolic variables for the inputs
    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for INT_SCARRY");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
    log!(executor.state.logger.clone(), "* Fetching instruction.input[1] for INT_SCARRY");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;

    let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    let input0_value = input0_var.get_concrete_value() as i64;
    let input1_value = input1_var.get_concrete_value() as i64;
    let result_concrete = input0_value.wrapping_add(input1_value);
    let overflow_concrete = (input0_value > 0 && input1_value > 0 && result_concrete < 0) ||
                            (input0_value < 0 && input1_value < 0 && result_concrete > 0);

    // Symbolic overflow check
    let input0_sym = input0_var.get_symbolic_value_bv(executor.context);
    let input1_sym = input1_var.get_symbolic_value_bv(executor.context);
    let result_symbolic = input0_sym.bvadd(&input1_sym);
    let overflow_symbolic = result_symbolic.bvadd_no_overflow(&input0_sym, true); // true for signed overflow check

    let result_value = ConcolicVar::new_concrete_and_symbolic_bool(overflow_concrete, overflow_symbolic, executor.context, output_size_bits);

    log!(executor.state.logger.clone(), "*** The result of INT_SCARRY is: {:?}\n", overflow_concrete);

    // Handle the result based on the output varnode
    handle_output(executor, instruction.output.as_ref(), result_value)?;

    Ok(())
}

pub fn handle_int_add(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntAdd || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_ADD".to_string());
    }

    // Fetch concolic variables
    log!(executor.state.logger.clone(), "* Fetching instruction.input[0]");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
    log!(executor.state.logger.clone(), "* Fetching instruction.input[1]");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;

    let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size();
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    // Perform the addition
    // Wrapping is used to handle overflow in Rust
    let result_concrete = input0_var.get_concrete_value().wrapping_add(input1_var.get_concrete_value());
    let result_symbolic = input0_var.get_symbolic_value_bv(executor.context).bvadd(&input1_var.get_symbolic_value_bv(executor.context));
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(result_concrete, result_symbolic, executor.context, output_size_bits);

    log!(executor.state.logger.clone(), "*** The result of INT_ADD is: {:x}\n", result_concrete.clone());

    // Handle the result based on the output varnode
    handle_output(executor, instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intadd", current_addr_hex, executor.instruction_counter);
    executor.state.create_or_update_concolic_variable_int(&result_var_name, result_value.concrete.to_u64(), result_value.symbolic);

    //log!(executor.state.logger.clone(), "{}\n", executor.state);

    Ok(())
}

pub fn handle_int_sub(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntSub || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_SUB".to_string());
    }

    // Fetch concolic variables
    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for INT_SUB");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
    log!(executor.state.logger.clone(), "* Fetching instruction.input[1] for INT_SUB");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;

    let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    // Perform the subtraction using signed integers and ensure correct handling of the output size
    let result_concrete = (input0_var.get_concrete_value() as i64).wrapping_sub(input1_var.get_concrete_value() as i64);

    // Truncate the result to fit the output size
    let truncated_result = match output_size_bits {
        32 => result_concrete as i32 as i64, // Handle 32-bit result truncation
        64 => result_concrete,
        _ => result_concrete & ((1 << output_size_bits) - 1),
    };

    let result_symbolic = input0_var.get_symbolic_value_bv(executor.context).bvsub(&input1_var.get_symbolic_value_bv(executor.context));
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(truncated_result as u64, result_symbolic, executor.context, output_size_bits);

    log!(executor.state.logger.clone(), "*** The result of INT_SUB is: {:?}\n", truncated_result);

    // Handle the result based on the output varnode
    handle_output(executor, instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intsub", current_addr_hex, executor.instruction_counter);
    executor.state.create_or_update_concolic_variable_int(&result_var_name, result_value.concrete.to_u64(), result_value.symbolic);

    Ok(())
}

pub fn handle_int_xor(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntXor || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_XOR".to_string());
    }

    // Fetch concolic variables
    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for INT_XOR");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
    log!(executor.state.logger.clone(), "* Fetching instruction.input[1] for INT_XOR");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;

    // Ensure both inputs are of the same size, if not, log error and return
    if input0_var.get_size() != input1_var.get_size() {
        log!(executor.state.logger.clone(), "Input sizes do not match for XOR operation");
        return Err("Input sizes for INT_XOR must match".to_string());
    }

    let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    // Perform the XOR operation
    let result_concrete = input0_var.get_concrete_value() ^ input1_var.get_concrete_value();
    let result_symbolic = input0_var.get_symbolic_value_bv(executor.context).bvxor(&input1_var.get_symbolic_value_bv(executor.context));
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(result_concrete, result_symbolic, executor.context, output_size_bits);

    log!(executor.state.logger.clone(), "*** The result of INT_XOR is: {:?}\n", result_concrete);

    // Handle the result based on the output varnode
    handle_output(executor, instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intxor", current_addr_hex, executor.instruction_counter);
    executor.state.create_or_update_concolic_variable_int(&result_var_name, result_value.concrete.to_u64(), result_value.symbolic);

    Ok(())
}

pub fn handle_int_equal(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntEqual || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_EQUAL".to_string());
    }

    // Fetch concolic variables
    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for INT_EQUAL");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
    log!(executor.state.logger.clone(), "* Fetching instruction.input[1] for INT_EQUAL");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;

    let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    // Perform the equality comparison
    let result_concrete = input0_var.get_concrete_value() == input1_var.get_concrete_value();
    let result_symbolic = input0_var.get_symbolic_value_bv(executor.context).eq(&input1_var.get_symbolic_value_bv(executor.context));
    let result_value = ConcolicVar::new_concrete_and_symbolic_bool(result_concrete, Bool::from_bool(executor.context, result_symbolic), executor.context, output_size_bits);  

    log!(executor.state.logger.clone(), "*** The result of INT_EQUAL is: {:?}\n", result_value.concrete.to_u64());

    // Handle the result based on the output varnode
    handle_output(executor, instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intequal", current_addr_hex, executor.instruction_counter);
    executor.state.create_or_update_concolic_variable_int(&result_var_name, result_value.concrete.to_u64(), result_value.symbolic);

    Ok(())
}

pub fn handle_int_notequal(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntNotEqual || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_NOTEQUAL".to_string());
    }

    // Fetch concolic variables
    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for INT_NOTEQUAL");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
    log!(executor.state.logger.clone(), "* Fetching instruction.input[1] for INT_NOTEQUAL");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;

    let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    // Perform the inequality comparison
    let result_concrete = input0_var.get_concrete_value() != input1_var.get_concrete_value();
    let result_symbolic = input0_var.get_symbolic_value_bv(executor.context).ne(&input1_var.get_symbolic_value_bv(executor.context));
    let result_value = ConcolicVar::new_concrete_and_symbolic_bool(result_concrete, Bool::from_bool(executor.context, result_symbolic), executor.context, output_size_bits);

    log!(executor.state.logger.clone(), "*** The result of INT_NOTEQUAL is: {:?}\n", result_concrete.clone());

    // Handle the result based on the output varnode
    handle_output(executor, instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intnotequal", current_addr_hex, executor.instruction_counter);
    executor.state.create_or_update_concolic_variable_int(&result_var_name, result_value.concrete.to_u64(), result_value.symbolic);

    Ok(())
}

pub fn handle_int_less(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntLess || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_LESS".to_string());
    }

    // Fetch concolic variables
    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for INT_LESS");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
    log!(executor.state.logger.clone(), "* Fetching instruction.input[1] for INT_LESS");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;

    let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    // Perform the less than comparison
    let result_concrete = input0_var.get_concrete_value() < input1_var.get_concrete_value();
    let result_symbolic = input0_var.get_symbolic_value_bv(executor.context).bvult(&input1_var.get_symbolic_value_bv(executor.context));
    let result_value = ConcolicVar::new_concrete_and_symbolic_bool(result_concrete, result_symbolic, executor.context, output_size_bits);

    log!(executor.state.logger.clone(), "*** The result of INT_LESS is: {:?}\n", result_concrete.clone());

    // Handle the result based on the output varnode
    handle_output(executor, instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intless", current_addr_hex, executor.instruction_counter);
    executor.state.create_or_update_concolic_variable_int(&result_var_name, result_value.concrete.to_u64(), result_value.symbolic);

    Ok(())
}

pub fn handle_int_sless(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntSLess || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_SLESS".to_string());
    }

    // Fetch concolic variables
    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for INT_SLESS");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
    log!(executor.state.logger.clone(), "* Fetching instruction.input[1] for INT_SLESS");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;

    let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    // Determine the type based on size and perform signed comparison
    let result_concrete;
    let result_symbolic;
    match instruction.inputs[0].size.to_bitvector_size() {
        32 => {
            let input0_concrete = input0_var.get_concrete_value() as i32 as i64;  // Sign-extend if necessary
            let input1_concrete = input1_var.get_concrete_value() as i32 as i64;  // Sign-extend if necessary
            result_concrete = input0_concrete < input1_concrete;
            result_symbolic = input0_var.get_symbolic_value_bv(executor.context).bvslt(&input1_var.get_symbolic_value_bv(executor.context));
        },
        64 => {
            let input0_concrete = input0_var.get_concrete_value() as i64;  // Direct cast to i64
            let input1_concrete = input1_var.get_concrete_value() as i64;  // Direct cast to i64
            result_concrete = input0_concrete < input1_concrete;
            result_symbolic = input0_var.get_symbolic_value_bv(executor.context).bvslt(&input1_var.get_symbolic_value_bv(executor.context));
        },
        _ => return Err("Unsupported bit size for INT_SLESS".to_string()),
    }

    log!(executor.state.logger.clone(), "*** The result of INT_SLESS is: {:?}", result_concrete);

    let result_value = ConcolicVar::new_concrete_and_symbolic_bool(result_concrete, result_symbolic, executor.context, output_size_bits);

    // Handle the result based on the output varnode
    handle_output(executor, instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intsless", current_addr_hex, executor.instruction_counter);
    executor.state.create_or_update_concolic_variable_bool(&result_var_name, result_value.concrete.to_bool(), result_value.symbolic);

    Ok(())
}

pub fn handle_int_lessequal(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntLessEqual || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_LESSEQUAL".to_string());
    }

    // Fetch concolic variables
    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for INT_LESSEQUAL");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
    log!(executor.state.logger.clone(), "* Fetching instruction.input[1] for INT_LESSEQUAL");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;

    let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    // Perform the unsigned less than or equal comparison
    let result_concrete = input0_var.get_concrete_value() <= input1_var.get_concrete_value();
    let result_symbolic = input0_var.get_symbolic_value_bv(executor.context).bvule(&input1_var.get_symbolic_value_bv(executor.context));
    let result_value = ConcolicVar::new_concrete_and_symbolic_bool(result_concrete, result_symbolic, executor.context, output_size_bits);

    log!(executor.state.logger.clone(), "*** The result of INT_LESSEQUAL is: {:?}", result_concrete);

    // Handle the result based on the output varnode
    handle_output(executor, instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intlessequal", current_addr_hex, executor.instruction_counter);
    executor.state.create_or_update_concolic_variable_int(&result_var_name, result_value.concrete.to_u64(), result_value.symbolic);

    Ok(())
}

pub fn handle_int_slessequal(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntSLessEqual || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_SLESSEQUAL".to_string());
    }

    // Fetch concolic variables
    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for INT_SLESSEQUAL");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
    log!(executor.state.logger.clone(), "* Fetching instruction.input[1] for INT_SLESSEQUAL");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;

    let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    // Perform the signed less than or equal comparison
    let result_concrete = input0_var.get_concrete_value() as i64 <= input1_var.get_concrete_value() as i64;
    let result_symbolic = input0_var.get_symbolic_value_bv(executor.context).bvule(&input1_var.get_symbolic_value_bv(executor.context));
    let result_value = ConcolicVar::new_concrete_and_symbolic_bool(result_concrete, result_symbolic, executor.context, output_size_bits);

    log!(executor.state.logger.clone(), "*** The result of INT_SLESSEQUAL is: {:?}\n", result_concrete);

    // Handle the result based on the output varnode
    handle_output(executor, instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intslessequal", current_addr_hex, executor.instruction_counter);
    executor.state.create_or_update_concolic_variable_int(&result_var_name, result_value.concrete.to_u64(), result_value.symbolic);

    Ok(())
}

// Handle INT_ZEXT instruction
pub fn handle_int_zext(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntZExt || instruction.inputs.len() != 1 || instruction.output.is_none() {
        return Err("Invalid instruction format for INT_ZEXT".to_string());
    }

    // Fetch concolic variables
    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for INT_ZEXT");
    let input_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;

    // Ensure output varnode has a larger size than the input
    let output_varnode = instruction.output.as_ref().unwrap();
    if output_varnode.size.to_bitvector_size() <= instruction.inputs[0].size.to_bitvector_size() {
        return Err("Output size must be larger than input size for zero-extension".to_string());
    }

    let input_size = instruction.inputs[0].size.to_bitvector_size() as usize;
    let output_size = output_varnode.size.to_bitvector_size() as usize;

    // Safe mask application to avoid shift overflow
    let mask = if input_size >= 64 {
        u64::MAX
    } else {
        (1u64 << input_size) - 1
    };
    let zero_extended_value = input_var.get_concrete_value() & mask;
    let result_symbolic = input_var.get_symbolic_value_bv(executor.context).zero_ext((output_size - input_size) as u32);

    // Ensure the result_symbolic is valid
    if result_symbolic.get_size() == 0 {
        return Err("Zero-extended symbolic value is null".to_string());
    }

    let result_value = ConcolicVar::new_concrete_and_symbolic_int(
        zero_extended_value,
        result_symbolic,
        executor.context,
        output_varnode.size.to_bitvector_size()
    );

    log!(executor.state.logger.clone(), "*** The result of INT_ZEXT is: 0x{:x}\n", zero_extended_value);

    // Handle the result based on the output varnode
    handle_output(executor, instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intzext", current_addr_hex, executor.instruction_counter);
    executor.state.create_or_update_concolic_variable_int(&result_var_name, result_value.concrete.to_u64(), result_value.symbolic);

    Ok(())
}

pub fn handle_int_sext(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntSExt || instruction.inputs.len() != 1 || instruction.output.is_none() {
        return Err("Invalid instruction format for INT_SEXT".to_string());
    }

    // Fetch concolic variables
    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for INT_SEXT");
    let input_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;

    // Ensure output varnode has a larger size than the input
    let output_varnode = instruction.output.as_ref().unwrap();
    if output_varnode.size.to_bitvector_size() <= instruction.inputs[0].size.to_bitvector_size() {
        return Err("Output size must be larger than input size for sign-extension".to_string());
    }

    // Perform the sign-extension
    let input_size = instruction.inputs[0].size.to_bitvector_size() as usize;
    let output_size = output_varnode.size.to_bitvector_size() as usize;
    let input_concrete = input_var.get_concrete_value();

    // Determine the sign bit of the input and create a mask for sign-extension
    let sign_bit = (input_concrete >> (input_size - 1)) & 1;
    let sign_extension = if sign_bit == 1 {
        ((1u64 << (output_size - input_size)) - 1) << input_size // Fill higher bits with 1s if sign bit is 1
    } else {
        0 // Fill higher bits with 0s if sign bit is 0
    };
    let result_concrete = input_concrete | sign_extension;
    let result_symbolic = input_var.get_symbolic_value_bv(executor.context).sign_ext((output_size - input_size).try_into().unwrap());

    let result_value = ConcolicVar::new_concrete_and_symbolic_int(
        result_concrete, 
        result_symbolic, 
        executor.context, 
        output_varnode.size.to_bitvector_size()
    );

    log!(executor.state.logger.clone(), "*** The result of INT_SEXT is: 0x{:x}\n", result_concrete);

    // Handle the result based on the output varnode
    handle_output(executor, instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intsext", current_addr_hex, executor.instruction_counter);
    executor.state.create_or_update_concolic_variable_int(&result_var_name, result_value.concrete.to_u64(), result_value.symbolic);

    Ok(())
}

pub fn handle_int_sborrow(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntSBorrow || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_SBORROW".to_string());
    }

    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for INT_SBORROW");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
    log!(executor.state.logger.clone(), "The value of input0_var is: {:?}", input0_var.get_concrete_value());
    log!(executor.state.logger.clone(), "* Fetching instruction.input[1] for INT_SBORROW");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;
    log!(executor.state.logger.clone(), "The value of input1_var is: {:?}", input1_var.get_concrete_value());
   
    let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;

    // Convert values to i64 for correct signed arithmetic handling
    let value0 = input0_var.get_concrete_value() as i64;
    let value1 = input1_var.get_concrete_value() as i64;

    // Check for underflow
    let result = value0.checked_sub(value1);
    let underflow_occurred = match result {
        Some(_) => false,
        None => true,
    };
    log!(executor.state.logger.clone(), "Checked sub result is : {:?}", result);

    let result_symbolic = z3::ast::Bool::from_bool(executor.context, underflow_occurred);

    let result_value = ConcolicVar::new_concrete_and_symbolic_bool(underflow_occurred, result_symbolic, executor.context, output_size_bits);

    log!(executor.state.logger.clone(), "*** The result of INT_SBORROW is underflow: {:?}\n", underflow_occurred);

    // Handle the result based on the output varnode
    handle_output(executor, instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intsborrow", current_addr_hex, executor.instruction_counter);
    executor.state.create_or_update_concolic_variable_int(&result_var_name, result_value.concrete.to_u64(), result_value.symbolic);

    Ok(())
}

pub fn handle_int_2comp(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::Int2Comp || instruction.inputs.len() != 1 {
        return Err("Invalid instruction format for INT_2COMP".to_string());
    }

    // Fetch concolic variables
    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for INT_2COMP");
    let input_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;

    let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    // Perform the twos complement negation
    let result_concrete = input_var.get_concrete_value().wrapping_neg();
    let result_symbolic = input_var.get_symbolic_value_bv(executor.context).bvneg();
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(result_concrete, result_symbolic, executor.context, output_size_bits);

    log!(executor.state.logger.clone(), "*** The result of INT_2COMP is: {:?}\n", result_concrete);

    // Handle the result based on the output varnode
    handle_output(executor, instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-int2comp", current_addr_hex, executor.instruction_counter);
    executor.state.create_or_update_concolic_variable_int(&result_var_name, result_value.concrete.to_u64(), result_value.symbolic);

    Ok(())
}

pub fn handle_int_and(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntAnd || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_AND".to_string());
    }

    // Fetch concolic variables
    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for INT_AND");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
    log!(executor.state.logger.clone(), "* Fetching instruction.input[1] for INT_AND");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;

    // Ensure both inputs are of the same size, if not, log error and return
    if input0_var.get_size() != input1_var.get_size() {
        log!(executor.state.logger.clone(), "Input sizes do not match for AND operation");
        return Err("Input sizes for INT_AND must match".to_string());
    }

    let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    // Perform the AND operation
    let result_concrete = input0_var.get_concrete_value() & input1_var.get_concrete_value();
    let result_symbolic = input0_var.get_symbolic_value_bv(executor.context).bvand(&input1_var.get_symbolic_value_bv(executor.context));
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(result_concrete, result_symbolic, executor.context, output_size_bits);

    log!(executor.state.logger.clone(), "*** The result of INT_AND is: {:?}\n", result_concrete);

    // Handle the result based on the output varnode
    handle_output(executor, instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intand", current_addr_hex, executor.instruction_counter);
    executor.state.create_or_update_concolic_variable_int(&result_var_name, result_value.concrete.to_u64(), result_value.symbolic);

    Ok(())
}

pub fn handle_int_or(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntOr || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_OR".to_string());
    }

    // Fetch concolic variables
    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for INT_OR");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
    log!(executor.state.logger.clone(), "* Fetching instruction.input[1] for INT_OR");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;

    // Ensure both inputs are of the same size
    if input0_var.get_size() != input1_var.get_size() {
        log!(executor.state.logger.clone(), "Input sizes do not match for OR operation");
        return Err("Input sizes for INT_OR must match".to_string());
    }

    let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    // Perform the OR operation
    let result_concrete = input0_var.get_concrete_value() | input1_var.get_concrete_value();
    let result_symbolic = input0_var.get_symbolic_value_bv(executor.context).bvor(&input1_var.get_symbolic_value_bv(executor.context));
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(result_concrete, result_symbolic, executor.context, output_size_bits);

    log!(executor.state.logger.clone(), "*** The result of INT_OR is: {:?}\n", result_concrete);

    // Handle the result based on the output varnode
    handle_output(executor, instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intor", current_addr_hex, executor.instruction_counter);
    executor.state.create_or_update_concolic_variable_int(&result_var_name, result_value.concrete.to_u64(), result_value.symbolic);

    Ok(())
}

pub fn handle_int_left(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntLeft || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_LEFT".to_string());
    }

    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for INT_LEFT");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
    log!(executor.state.logger.clone(), "* Fetching instruction.input[1] for INT_LEFT");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;

    let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    let shift_amount = input1_var.get_concrete_value() as usize;

    // Check if the shift amount is valid
    if shift_amount >= 64 {
        log!(executor.state.logger.clone(), "Shift amount {} exceeds bit width, adjusting to maximum", shift_amount);
        return Err(format!("Shift amount exceeds bit width: {}", shift_amount));
    }

    let result_concrete = input0_var.get_concrete_value().wrapping_shl(shift_amount as u32);
    let result_symbolic = input0_var.get_symbolic_value_bv(executor.context).bvshl(&BV::from_u64(executor.context, shift_amount as u64, output_size_bits));

    let result_value = ConcolicVar::new_concrete_and_symbolic_int(result_concrete, result_symbolic, executor.context, output_size_bits);

    log!(executor.state.logger.clone(), "*** The result of INT_LEFT is: {:x}", result_concrete);

    handle_output(executor, instruction.output.as_ref(), result_value.clone())?;

    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intleft", current_addr_hex, executor.instruction_counter);
    executor.state.create_or_update_concolic_variable_int(&result_var_name, result_value.concrete.to_u64(), result_value.symbolic);

    Ok(())
}

pub fn handle_int_right(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntRight || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_RIGHT".to_string());
    }

    // Fetch concolic variables
    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for INT_RIGHT");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
    log!(executor.state.logger.clone(), "* Fetching instruction.input[1] for INT_RIGHT");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;

    let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    // Perform the right shift operation
    let shift_amount = input1_var.get_concrete_value() as usize;
    let result_concrete = input0_var.get_concrete_value() >> shift_amount;
    let result_symbolic = input0_var.get_symbolic_value_bv(executor.context).bvlshr(&BV::from_u64(executor.context, shift_amount as u64, output_size_bits));

    let result_value = ConcolicVar::new_concrete_and_symbolic_int(result_concrete, result_symbolic, executor.context, output_size_bits);

    log!(executor.state.logger.clone(), "*** The result of INT_RIGHT is: {:?}\n", result_concrete);

    // Handle the result based on the output varnode
    handle_output(executor, instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intright", current_addr_hex, executor.instruction_counter);
    executor.state.create_or_update_concolic_variable_int(&result_var_name, result_value.concrete.to_u64(), result_value.symbolic);

    Ok(())
}

pub fn handle_int_sright(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntSRight || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_SRIGHT".to_string());
    }

    // Fetch concolic variables
    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for INT_SRIGHT");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
    log!(executor.state.logger.clone(), "* Fetching instruction.input[1] for INT_SRIGHT");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;

    let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    // Perform the arithmetic right shift operation
    let shift_amount = input1_var.get_concrete_value() as usize;
    let result_concrete = ((input0_var.get_concrete_value() as i64) >> shift_amount) as u64;
    let result_symbolic = input0_var.get_symbolic_value_bv(executor.context).bvashr(&BV::from_u64(executor.context, shift_amount as u64, output_size_bits));

    let result_value = ConcolicVar::new_concrete_and_symbolic_int(result_concrete, result_symbolic, executor.context, output_size_bits);

    log!(executor.state.logger.clone(), "*** The result of INT_SRIGHT is: {:?}\n", result_concrete);

    // Handle the result based on the output varnode
    handle_output(executor, instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intsright", current_addr_hex, executor.instruction_counter);
    executor.state.create_or_update_concolic_variable_int(&result_var_name, result_value.concrete.to_u64(), result_value.symbolic);

    Ok(())
}

pub fn handle_int_mult(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntMult || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_MULT".to_string());
    }

    // Fetch concolic variables
    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for INT_MULT");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
    log!(executor.state.logger.clone(), "* Fetching instruction.input[1] for INT_MULT");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;

    let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    // Perform the multiplication
    let result_concrete = input0_var.get_concrete_value().wrapping_mul(input1_var.get_concrete_value());
    let result_symbolic = input0_var.get_symbolic_value_bv(executor.context).bvmul(&input1_var.get_symbolic_value_bv(executor.context));
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(result_concrete, result_symbolic, executor.context, output_size_bits);

    log!(executor.state.logger.clone(), "*** The result of INT_MULT is: {:?}\n", result_concrete);

    // Handle the result based on the output varnode
    handle_output(executor, instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intmult", current_addr_hex, executor.instruction_counter);
    executor.state.create_or_update_concolic_variable_int(&result_var_name, result_value.concrete.to_u64(), result_value.symbolic);

    Ok(())
}

pub fn handle_int_negate(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntNegate || instruction.inputs.len() != 1 {
        return Err("Invalid instruction format for INT_NEGATE".to_string());
    }

    // Fetch the concolic variable for the input
    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for INT_NEGATE");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;

    let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    // Perform the bitwise negation
    let result_concrete = !input0_var.get_concrete_value();
    let result_symbolic = input0_var.get_symbolic_value_bv(executor.context).bvnot();
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(result_concrete, result_symbolic, executor.context, output_size_bits);

    log!(executor.state.logger.clone(), "*** The result of INT_NEGATE is: {:?}\n", result_concrete);

    // Handle the result based on the output varnode
    handle_output(executor, instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intnegate", current_addr_hex, executor.instruction_counter);
    executor.state.create_or_update_concolic_variable_int(&result_var_name, result_value.concrete.to_u64(), result_value.symbolic);

    Ok(())
}

pub fn handle_int_div(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntDiv || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_DIV".to_string());
    }

    // Fetch the concolic variables for the inputs
    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for INT_DIV");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
    log!(executor.state.logger.clone(), "* Fetching instruction.input[1] for INT_DIV");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;

    // Check for division by zero
    if input1_var.get_concrete_value() == 0 {
        return Err("Division by zero".to_string());
    }

    let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    // Perform the division
    let result_concrete = input0_var.get_concrete_value().wrapping_div(input1_var.get_concrete_value());
    let result_symbolic = input0_var.get_symbolic_value_bv(executor.context).bvudiv(&input1_var.get_symbolic_value_bv(executor.context));
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(result_concrete, result_symbolic, executor.context, output_size_bits);

    log!(executor.state.logger.clone(), "*** The result of INT_DIV is: {:?}\n", result_concrete);

    // Handle the result based on the output varnode
    handle_output(executor, instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intdiv", current_addr_hex, executor.instruction_counter);
    executor.state.create_or_update_concolic_variable_int(&result_var_name, result_value.concrete.to_u64(), result_value.symbolic);

    Ok(())
}

pub fn handle_int_rem(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntRem || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_REM".to_string());
    }

    // Fetch the concolic variables for the inputs
    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for INT_REM");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
    log!(executor.state.logger.clone(), "* Fetching instruction.input[1] for INT_REM");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;

    // Check for division by zero
    if input1_var.get_concrete_value() == 0 {
        return Err("Division by zero".to_string());
    }

    let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    // Perform the remainder operation
    let result_concrete = input0_var.get_concrete_value() % input1_var.get_concrete_value();
    let result_symbolic = input0_var.get_symbolic_value_bv(executor.context).bvurem(&input1_var.get_symbolic_value_bv(executor.context));
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(result_concrete, result_symbolic, executor.context, output_size_bits);

    log!(executor.state.logger.clone(), "*** The result of INT_REM is: {:?}\n", result_concrete);

    // Handle the result based on the output varnode
    handle_output(executor, instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intrem", current_addr_hex, executor.instruction_counter);
    executor.state.create_or_update_concolic_variable_int(&result_var_name, result_value.concrete.to_u64(), result_value.symbolic);

    Ok(())
}

pub fn handle_int_sdiv(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntSDiv || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_SDIV".to_string());
    }

    // Fetch the concolic variables for the inputs
    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for INT_SDIV");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
    log!(executor.state.logger.clone(), "* Fetching instruction.input[1] for INT_SDIV");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;

    // Check for division by zero
    if input1_var.get_concrete_value() == 0 {
        return Err("Division by zero".to_string());
    }

    let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    // Perform the signed division
    let result_concrete = (input0_var.get_concrete_value() as i64 / input1_var.get_concrete_value() as i64) as u64;
    let result_symbolic = input0_var.get_symbolic_value_bv(executor.context).bvsdiv(&input1_var.get_symbolic_value_bv(executor.context));
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(result_concrete, result_symbolic, executor.context, output_size_bits);

    log!(executor.state.logger.clone(), "*** The result of INT_SDIV is: {:?}\n", result_concrete);

    // Handle the result based on the output varnode
    handle_output(executor, instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intsdiv", current_addr_hex, executor.instruction_counter);
    executor.state.create_or_update_concolic_variable_int(&result_var_name, result_value.concrete.to_u64(), result_value.symbolic);

    Ok(())
}

pub fn handle_int_srem(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntSRem || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_SREM".to_string());
    }

    // Fetch the concolic variables for the inputs
    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for INT_SREM");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
    log!(executor.state.logger.clone(), "* Fetching instruction.input[1] for INT_SREM");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;

    // Check for division by zero
    if input1_var.get_concrete_value() == 0 {
        return Err("Division by zero".to_string());
    }

    let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    // Perform the signed remainder operation
    let result_concrete = ((input0_var.get_concrete_value() as i64) % (input1_var.get_concrete_value() as i64)) as u64;
    let result_symbolic = input0_var.get_symbolic_value_bv(executor.context).bvsrem(&input1_var.get_symbolic_value_bv(executor.context));
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(result_concrete, result_symbolic, executor.context, output_size_bits);

    log!(executor.state.logger.clone(), "*** The result of INT_SREM is: {:?}\n", result_concrete);

    // Handle the result based on the output varnode
    handle_output(executor, instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intsrem", current_addr_hex, executor.instruction_counter);
    executor.state.create_or_update_concolic_variable_int(&result_var_name, result_value.concrete.to_u64(), result_value.symbolic);

    Ok(())
}

pub fn handle_int2float(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::Int2Float || instruction.inputs.len() != 1 {
        return Err("Invalid instruction format for INT2FLOAT".to_string());
    }

    // Fetch the concolic variable for the input
    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for INT2FLOAT");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;

    let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    // Perform the conversion
    let result_concrete = input0_var.get_concrete_value() as f64; // input is a signed integer
    let result_symbolic = Float::from_f64(&executor.context, result_concrete);

    let result_value = ConcolicVar::new_concrete_and_symbolic_float(result_concrete, result_symbolic, executor.context, output_size_bits);

    log!(executor.state.logger.clone(), "*** The result of INT2FLOAT is: {:?}\n", result_concrete);

    // Handle the result based on the output varnode
    handle_output(executor, instruction.output.as_ref(), result_value)?;

    Ok(())
}

