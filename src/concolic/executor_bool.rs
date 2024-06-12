/// Focuses on implementing the execution of the BOOL related opcodes from Ghidra's Pcode specification
/// This implementation relies on Ghidra 11.0.1 with the specfiles in /specfiles

use crate::{concolic::ConcolicEnum, executor::ConcolicExecutor};
use parser::parser::{Inst, Opcode, Size, Var};
use std::io::Write;

use super::ConcolicVar;

macro_rules! log {
    ($logger:expr, $($arg:tt)*) => {{
        writeln!($logger, $($arg)*).unwrap();
    }};
}

pub fn handle_bool_and(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Validate instruction format and sizes
    if instruction.opcode != Opcode::BoolAnd || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for BOOL_AND".to_string());
    }

    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    if output_varnode.size != Size::Byte {
        return Err("Output must be size 1 (Byte) for BOOL_AND".to_string());
    }

    let input0_value = executor.initialize_var_if_absent(&instruction.inputs[0])?;
    let input1_value = executor.initialize_var_if_absent(&instruction.inputs[1])?;

    // Perform boolean AND
    let result = (input0_value & input1_value) & 1; // Ensure result is boolean (0 or 1)

    // Store the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    executor.state.create_concolic_var_int(&result_var_name, result as u64, 1);

    Ok(())
}

pub fn handle_bool_negate(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Validate instruction format and sizes
    if instruction.opcode != Opcode::BoolNegate || instruction.inputs.len() != 1 {
        return Err("Invalid instruction format for BOOL_NEGATE".to_string());
    }

    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    if output_varnode.size != Size::Byte {
        return Err("Output must be size 1 (Byte) for BOOL_NEGATE".to_string());
    }

    let input0_value = executor.initialize_var_if_absent(&instruction.inputs[0])?;

    // Perform boolean negation
    let result = !input0_value & 1; // Ensure result is boolean (0 or 1)

    // Store the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    executor.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result.into(), &result_var_name, executor.context, 1));

    Ok(())
}

pub fn handle_bool_or(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::BoolOr || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for BOOL_OR".to_string());
    }
    
    // Fetch concolic variables
    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for BOOL_OR");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| {
        log!(executor.state.logger.clone(), "Error converting input0_var: {}", e);
        e.to_string()
    })?;
    log!(executor.state.logger.clone(), "* Fetching instruction.input[1] for BOOL_OR");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| {
        log!(executor.state.logger.clone(), "Error converting input1_var: {}", e);
        e.to_string()
    })?;

    log!(executor.state.logger.clone(), "Just before result calculation");
    // Perform the OR operation
    let result_value = input0_var.concolic_or(input1_var, executor.context).map_err(|e| {
        log!(executor.state.logger.clone(), "Error performing OR operation: {}", e);
        e.to_string()
    })?;
    log!(executor.state.logger.clone(), "*** The result of BOOL_OR is: {:?}\n", result_value.clone());

    // Handle the result based on the output varnode
    match instruction.output.as_ref().map(|v| &v.var) {
        Some(Var::Unique(id)) => {
            log!(executor.state.logger.clone(), "Output is a Unique type");
            let unique_name = format!("Unique(0x{:x})", id);
            match &result_value {
                ConcolicEnum::ConcolicVar(concolic_var) => {
                    executor.unique_variables.insert(unique_name.clone(), concolic_var.clone());
                },
                ConcolicEnum::CpuConcolicValue(cpu_var) => {
                    let concolic_var = ConcolicVar::new_concrete_and_symbolic_int(
                        cpu_var.get_concrete_value().unwrap_or(0),
                        &cpu_var.symbolic.to_str(),
                        executor.context,
                        cpu_var.get_size()
                    );
                    executor.unique_variables.insert(unique_name.clone(), concolic_var);
                },
                _ => return Err("Result of BOOL_OR is not a ConcolicVar or CpuConcolicValue".to_string()),
            }
        },
        Some(Var::Register(offset, _)) => {
            log!(executor.state.logger.clone(), "Output is a Register type");
            let mut cpu_state_guard = executor.state.cpu_state.lock().unwrap();
            match &result_value {
                ConcolicEnum::ConcolicVar(var) => {
                    let concrete_value = var.concrete.to_u64();
                    let set_result = cpu_state_guard.set_register_value_by_offset(*offset, concrete_value);
                    match set_result {
                        Ok(_) => {
                            let updated_value = cpu_state_guard.get_register_value_by_offset(*offset).unwrap_or(0);
                            if updated_value == concrete_value {
                                log!(executor.state.logger.clone(), "Successfully updated register at offset 0x{:x} with value {}", offset, updated_value);
                            } else {
                                log!(executor.state.logger.clone(), "Failed to verify updated register at offset 0x{:x}", offset);
                                return Err(format!("Failed to verify updated register value at offset 0x{:x}", offset));
                            }
                        },
                        Err(e) => {
                            log!(executor.state.logger.clone(), "Failed to set register value: {}", e);
                            return Err(format!("Failed to set register value at offset 0x{:x}", offset));
                        }
                    }
                },
                ConcolicEnum::CpuConcolicValue(cpu_var) => {
                    let concrete_value = cpu_var.get_concrete_value().unwrap_or(0);
                    let set_result = cpu_state_guard.set_register_value_by_offset(*offset, concrete_value);
                    match set_result {
                        Ok(_) => {
                            let updated_value = cpu_state_guard.get_register_value_by_offset(*offset).unwrap_or(0);
                            if updated_value == concrete_value {
                                log!(executor.state.logger.clone(), "Successfully updated register at offset 0x{:x} with value {}", offset, updated_value);
                            } else {
                                log!(executor.state.logger.clone(), "Failed to verify updated register at offset 0x{:x}", offset);
                                return Err(format!("Failed to verify updated register value at offset 0x{:x}", offset));
                            }
                        },
                        Err(e) => {
                            log!(executor.state.logger.clone(), "Failed to set register value: {}", e);
                            return Err(format!("Failed to set register value at offset 0x{:x}", offset));
                        }
                    }
                },
                _ => return Err("Result of BOOL_OR is not a ConcolicVar or CpuConcolicValue".to_string()),
            }
        },
        _ => {
            log!(executor.state.logger.clone(), "Output type is unsupported");
            return Err("Output type not supported".to_string());
        }
    }

    log!(executor.state.logger.clone(), "{}\n", executor);

    // Create a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intequal", current_addr_hex, executor.instruction_counter);
    match result_value {
        ConcolicEnum::ConcolicVar(var) => {
            executor.state.create_or_update_concolic_variable_int(&result_var_name, var.concrete.to_u64(), var.symbolic);
            log!(executor.state.logger.clone(), "Created concolic variable for the result: {}", result_var_name);
        },
        ConcolicEnum::CpuConcolicValue(cpu_var) => {
            executor.state.create_or_update_concolic_variable_int(&result_var_name, cpu_var.get_concrete_value().unwrap_or(0), cpu_var.symbolic);
            log!(executor.state.logger.clone(), "Created concolic variable for the result: {}", result_var_name);
        },
        _ => return Err("Result of INT_EQUAL is not a ConcolicVar or CpuConcolicValue".to_string()),
    } 

    //log!(executor.state.logger.clone(), "{}\n", executor.state);

    Ok(())
}

pub fn handle_bool_xor(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Validate instruction format and sizes
    if instruction.opcode != Opcode::BoolXor || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for BOOL_XOR".to_string());
    }

    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    if output_varnode.size != Size::Byte {
        return Err("Output must be size 1 (Byte) for BOOL_XOR".to_string());
    }

    let input0_value = executor.initialize_var_if_absent(&instruction.inputs[0])?;
    let input1_value = executor.initialize_var_if_absent(&instruction.inputs[1])?;

    // Perform boolean XOR
    let result = (input0_value ^ input1_value) & 1; // Ensure result is boolean (0 or 1)

    // Store the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    executor.state.create_concolic_var_int(&result_var_name, result as u64, 1);

    Ok(())
}
