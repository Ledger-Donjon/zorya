/// Focuses on implementing the execution of the INT related opcodes from Ghidra's Pcode specification
/// This implementation relies on Ghidra 11.0.1 with the specfiles in /specfiles

use crate::concolic::{executor::ConcolicExecutor, ConcolicEnum, SymbolicVar};
use parser::parser::{Inst, Opcode, Size, Var};
use ethnum::I256;
use z3::ast::BV;
use std::io::Write;

use super::{ConcolicVar, ConcreteVar};
use log::error;

macro_rules! log {
    ($logger:expr, $($arg:tt)*) => {{
        writeln!($logger, $($arg)*).unwrap();
    }};
}

// Function to handle INT_CARRY instruction
pub fn handle_int_carry(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntCarry || instruction.inputs.len() != 2 || instruction.output.is_none() {
        return Err("Invalid instruction format for INT_CARRY".to_string());
    }

    log!(executor.state.logger.clone(), "* Fetching inputs for INT_CARRY");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;

    let carry_result = input0_var.concolic_carry(input1_var).map_err(|e| e.to_string())?;
    log!(executor.state.logger.clone(), "*** The result of INT_CARRY is: {:?}", carry_result);  

    // Handle output based on the type of the output variable
    match instruction.output.as_ref().map(|v| &v.var) {
        Some(Var::Unique(id)) => {
            let unique_name = format!("Unique(0x{:x})", id);
            // Convert result to ConcolicVar if necessary
            if let ConcolicEnum::ConcolicVar(var) = carry_result.clone() {
                executor.unique_variables.insert(unique_name.clone(), var);
            } else {
                return Err("Expected ConcolicVar type for unique variable output".to_string());
            }
            log!(executor.state.logger.clone(), "Updated unique variable: {}", unique_name);
        },
        Some(Var::Register(offset, _)) => {
            log!(executor.state.logger.clone(), "Output is a Register type");
            let mut cpu_state_guard = executor.state.cpu_state.lock().unwrap();
            if let ConcolicEnum::CpuConcolicValue(cpu_var) = carry_result.clone() {
                let concrete_value = cpu_var.get_concrete_value()?;
                cpu_state_guard.set_register_value_by_offset(*offset, concrete_value)?;
                log!(executor.state.logger.clone(), "Updated register at offset 0x{:x} with carry result {}", offset, concrete_value);
            } else {
                return Err("Expected CpuConcolicValue type for register output".to_string());
            }
        },
        _ => {
            log!(executor.state.logger.clone(), "Output type is unsupported for INT_CARRY");
            return Err("Output type not supported".to_string());
        }
    }

    log!(executor.state.logger.clone(), "{}\n", executor);

    // Create a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intcarry", current_addr_hex, executor.instruction_counter);
    match carry_result {
        ConcolicEnum::ConcolicVar(var) => {
            executor.state.create_or_update_concolic_variable_int(&result_var_name, var.concrete.to_u64(), var.symbolic);
        },
        ConcolicEnum::CpuConcolicValue(cpu_var) => {
            executor.state.create_or_update_concolic_variable_int(&result_var_name, cpu_var.get_concrete_value().unwrap_or(0), cpu_var.symbolic);
        },
        ConcolicEnum::MemoryConcolicValue(mem_var) => {
            executor.state.create_or_update_concolic_variable_int(&result_var_name, mem_var.concrete.to_u64(), mem_var.symbolic);
        },
    }

    //log!(executor.state.logger.clone(), "{}\n", executor.state);

    Ok(())
}
  
pub fn handle_int_scarry(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntSCarry || instruction.inputs.len() != 2 || instruction.output.is_none() {
        return Err("Invalid instruction format for INT_SCARRY".to_string());
    }

    log!(executor.state.logger.clone(), "* Fetching inputs for INT_SCARRY");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;

    let scarry_result = input0_var.concolic_scarry(input1_var, executor).map_err(|e| e.to_string())?;
    log!(executor.state.logger.clone(), "*** The result of INT_SCARRY is: {:?}", scarry_result);

    // Handle output based on the type of the output variable
    match instruction.output.as_ref().map(|v| &v.var) {
        Some(Var::Unique(id)) => {
            let unique_name = format!("Unique(0x{:x})", id);
            // Insert the ConcolicVar into unique_variables
            match scarry_result.clone() {
                ConcolicEnum::ConcolicVar(var) => {
                    executor.unique_variables.insert(unique_name.clone(), var);
                    log!(executor.state.logger.clone(), "Updated unique variable: {}", unique_name);
                },
                _ => return Err("Expected ConcolicVar type for unique variable output".to_string()),
            }
        },
        Some(Var::Register(offset, _)) => {
            log!(executor.state.logger.clone(), "Output is a Register type");
            let mut cpu_state_guard = executor.state.cpu_state.lock().unwrap();
            if let ConcolicEnum::ConcolicVar(var) = scarry_result.clone() {
                let concrete_value = var.concrete.to_u64();
                cpu_state_guard.set_register_value_by_offset(*offset, concrete_value)?;
                log!(executor.state.logger.clone(), "Updated register at offset 0x{:x} with scarry result {}", offset, concrete_value);
            } else {
                return Err("Expected ConcolicVar type for register output".to_string());
            }
        },
        _ => {
            log!(executor.state.logger.clone(), "Output type is unsupported for INT_SCARRY");
            return Err("Output type not supported".to_string());
        }
    }

    log!(executor.state.logger.clone(), "{}\n", executor);

    // Create a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intscarry", current_addr_hex, executor.instruction_counter);
    match scarry_result {
        ConcolicEnum::ConcolicVar(var) => {
            executor.state.create_or_update_concolic_variable_int(&result_var_name, var.concrete.to_u64(), var.symbolic);
        },
        ConcolicEnum::CpuConcolicValue(cpu_var) => {
            executor.state.create_or_update_concolic_variable_int(&result_var_name, cpu_var.get_concrete_value().unwrap_or(0), cpu_var.symbolic);
        },
        ConcolicEnum::MemoryConcolicValue(mem_var) => {
            executor.state.create_or_update_concolic_variable_int(&result_var_name, mem_var.concrete.to_u64(), mem_var.symbolic);
        },
    }

    //log!(executor.state.logger.clone(), "{}\n", executor.state);

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

    // Perform the addition
    let result_value = input0_var.concolic_add(input1_var).map_err(|e| e.to_string())?;
    log!(executor.state.logger.clone(), "*** The result of INT_ADD is: {:?}\n", result_value.clone());

    match instruction.output.as_ref().map(|v| &v.var) {
        Some(Var::Unique(id)) => {
            // Check and convert result_value to ConcolicVar
            let concolic_var = match result_value.clone() {
                ConcolicEnum::ConcolicVar(var) => var,
                ConcolicEnum::CpuConcolicValue(cpu_var) => {
                    // Convert CpuConcolicValue to ConcolicVar
                    ConcolicVar::new_concrete_and_symbolic_int(
                        cpu_var.concrete.to_u64(), 
                        &cpu_var.symbolic.to_str(), 
                        cpu_var.ctx, 
                        cpu_var.get_size()
                    )
                },
                ConcolicEnum::MemoryConcolicValue(mem_var) => {
                    // Convert MemoryConcolicValue to ConcolicVar
                    ConcolicVar::new_concrete_and_symbolic_int(
                        mem_var.concrete.to_u64(), 
                        &mem_var.symbolic.to_str(),
                        mem_var.ctx, 
                        mem_var.get_size()
                    )
                }
            };
            let unique_name = format!("Unique(0x{:x})", id);
            executor.unique_variables.insert(unique_name, concolic_var);
        },
        Some(Var::Register(offset, _)) => {
            log!(executor.state.logger.clone(), "Output is a Register type");
            let mut cpu_state_guard = executor.state.cpu_state.lock().unwrap();
            let concrete_value = result_value.get_concrete_value();
            let _ = cpu_state_guard.set_register_value_by_offset(*offset, concrete_value);
            log!(executor.state.logger.clone(), "Updated register at offset 0x{:x} with value {}", offset, concrete_value); 
        },
        _ => {
            log!(executor.state.logger.clone(), "Output type is unsupported");
            return Err("Output type not supported".to_string());
        }
    }

    log!(executor.state.logger.clone(), "{}\n", executor);

    // Create or update a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intadd", current_addr_hex, executor.instruction_counter);
    match result_value {
        ConcolicEnum::ConcolicVar(var) => {
            executor.state.create_or_update_concolic_variable_int(&result_var_name, var.concrete.to_u64(), var.symbolic);
        },
        ConcolicEnum::CpuConcolicValue(cpu_var) => {
            executor.state.create_or_update_concolic_variable_int(&result_var_name, cpu_var.get_concrete_value().unwrap_or(0), cpu_var.symbolic);
        },
        ConcolicEnum::MemoryConcolicValue(mem_var) => {
            executor.state.create_or_update_concolic_variable_int(&result_var_name, mem_var.concrete.to_u64(), mem_var.symbolic);
        },
    }

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

    // Perform the subtraction operation
    let result_value = input0_var.concolic_sub(input1_var, executor.context).map_err(|e| e.to_string())?;
    log!(executor.state.logger.clone(), "*** The result of INT_SUB is: {:?}\n", result_value.clone());

    // Handle the result based on the output varnode
    match instruction.output.as_ref().map(|v| &v.var) {
        Some(Var::Unique(id)) => {
            // Handle unique variable
            match &result_value {
                ConcolicEnum::ConcolicVar(concolic_var) => {
                    let unique_name = format!("Unique(0x{:x})", id);
                    executor.unique_variables.insert(unique_name, concolic_var.clone());
                    log!(executor.state.logger.clone(), "Updated unique variable: Unique(0x{:x})", id);
                },
                ConcolicEnum::CpuConcolicValue(cpu_var) => {
                    let concolic_var = ConcolicVar::new_concrete_and_symbolic_int(
                        cpu_var.get_concrete_value().unwrap_or(0),
                        &cpu_var.symbolic.to_str(),
                        executor.context,
                        cpu_var.get_size() 
                    );
                    let unique_name = format!("Unique(0x{:x})", id);
                    executor.unique_variables.insert(unique_name, concolic_var);
                    log!(executor.state.logger.clone(), "Converted CpuConcolicValue to ConcolicVar and updated unique variable: Unique(0x{:x})", id);
                },
                ConcolicEnum::MemoryConcolicValue(mem_var) => {
                    let concolic_var = ConcolicVar::new_concrete_and_symbolic_int(
                        mem_var.get_concrete_value().unwrap_or(0),
                        &mem_var.symbolic.to_str(),
                        executor.context,
                        mem_var.get_size()
                    );
                    let unique_name = format!("Unique(0x{:x})", id);
                    executor.unique_variables.insert(unique_name, concolic_var);
                    log!(executor.state.logger.clone(), "Converted MemoryConcolicValue to ConcolicVar and updated unique variable: Unique(0x{:x})", id);
                },
            }
        },
        Some(Var::Register(offset, _)) => {
            log!(executor.state.logger.clone(), "Output is a Register type");
            let mut cpu_state_guard = executor.state.cpu_state.lock().unwrap();
            match &result_value {
                ConcolicEnum::ConcolicVar(var) => {
                    let concrete_value = var.concrete.to_u64();
                    log!(executor.state.logger.clone(), "Setting register value at offset 0x{:x} to {}", offset, concrete_value);
                    let set_result = cpu_state_guard.set_register_value_by_offset(*offset, concrete_value);
                    match set_result {
                        Ok(_) => {
                            // Verify if the register value is set correctly
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
                    log!(executor.state.logger.clone(), "Setting register value at offset 0x{:x} to {}", offset, concrete_value);
                    let set_result = cpu_state_guard.set_register_value_by_offset(*offset, concrete_value);
                    match set_result {
                        Ok(_) => {
                            // Verify if the register value is set correctly
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
                ConcolicEnum::MemoryConcolicValue(mem_var) => {
                    let concrete_value = mem_var.get_concrete_value().unwrap_or(0);
                    log!(executor.state.logger.clone(), "Setting register value at offset 0x{:x} to {}", offset, concrete_value);
                    let set_result = cpu_state_guard.set_register_value_by_offset(*offset, concrete_value);
                    match set_result {
                        Ok(_) => {
                            // Verify if the register value is set correctly
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
    let result_var_name = format!("{}-{:02}-intsub", current_addr_hex, executor.instruction_counter);
    match result_value {
        ConcolicEnum::ConcolicVar(var) => {
            executor.state.create_or_update_concolic_variable_int(&result_var_name, var.concrete.to_u64(), var.symbolic);
        },
        ConcolicEnum::CpuConcolicValue(cpu_var) => {
            executor.state.create_or_update_concolic_variable_int(&result_var_name, cpu_var.get_concrete_value().unwrap_or(0), cpu_var.symbolic);
        },
        ConcolicEnum::MemoryConcolicValue(mem_var) => {
            executor.state.create_or_update_concolic_variable_int(&result_var_name, mem_var.concrete.to_u64(), mem_var.symbolic);
        },
    }

    //log!(executor.state.logger.clone(), "{}\n", executor.state);

    Ok(())
}

pub fn handle_int_xor(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntXor || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_XOR".to_string());
    }

    // Retrieve the concrete integer values for both inputs
    let input0_val = executor.initialize_var_if_absent(&instruction.inputs[0])?;
    let input1_val = executor.initialize_var_if_absent(&instruction.inputs[1])?;

    // Perform XOR operation on the concrete integer values
    let result_concrete = input0_val ^ input1_val;

    // Prepare for the symbolic computation
    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    let bitvector_size = output_varnode.size.to_bitvector_size();

    // Update or create the concolic variable with the concrete result and a new symbolic expression
    executor.state.create_concolic_var_int(&result_var_name, result_concrete, bitvector_size);

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

    // Perform the equality comparison
    //let result_value = input0_var.concolic_equal(input1_var, executor.context, executor).map_err(|e| e.to_string())?;
    log!(executor.state.logger.clone(), "Comparing input0: {:?} with input1: {:?}", input0_var.get_concrete(), input1_var.get_concrete());
    let result_bool = input0_var.get_concrete_value() == input1_var.get_concrete_value();
    log!(executor.state.logger.clone(), "*** The result of INT_EQUAL is: {:?}\n", result_bool.clone());

    // Handle the result based on the output varnode
    match instruction.output.as_ref().unwrap().var {
        Var::Unique(id) => {
            let unique_name = format!("Unique(0x{:x})", id);
            let concolic_var = ConcolicVar::new_concrete_and_symbolic_int(result_bool.into(), &unique_name, executor.context, 1);
            executor.unique_variables.insert(unique_name, concolic_var);
            log!(executor.state.logger.clone(), "Updated unique variable with result: Unique(0x{:x})", id);
        },
        Var::Register(offset, size) if size == Size::Byte => {
            let mut cpu_state_guard = executor.state.cpu_state.lock().unwrap();
            let concrete_value = result_bool as u64;
            cpu_state_guard.set_register_value_by_offset(offset, concrete_value).map_err(|e| e.to_string())?;
            log!(executor.state.logger.clone(), "Set register at offset 0x{:x} with value {}", offset, concrete_value);
        },
        _ => {
            log!(executor.state.logger.clone(), "Unsupported output type for INT_EQUAL");
            return Err("Output type not supported".to_string());
        }
    }

    // match instruction.output.as_ref().map(|v| &v.var) {
    //     Some(Var::Unique(id)) => {
    //         // Handle unique variable
    //         match &result_value {
    //             ConcolicEnum::ConcolicVar(concolic_var) => {
    //                 let unique_name = format!("Unique(0x{:x})", id);
    //                 executor.unique_variables.insert(unique_name, concolic_var.clone());
    //                 log!(executor.state.logger.clone(), "Updated unique variable: Unique(0x{:x})", id);
    //             },
    //             ConcolicEnum::CpuConcolicValue(cpu_var) => {
    //                 let concolic_var = ConcolicVar::new_concrete_and_symbolic_int(
    //                     cpu_var.get_concrete_value().unwrap_or(0),
    //                     &cpu_var.symbolic.to_str(),
    //                     executor.context,
    //                     cpu_var.get_size()
    //                 );
    //                 let unique_name = format!("Unique(0x{:x})", id);
    //                 executor.unique_variables.insert(unique_name, concolic_var);
    //                 log!(executor.state.logger.clone(), "Converted CpuConcolicValue to ConcolicVar and updated unique variable: Unique(0x{:x})", id);
    //             },
    //             ConcolicEnum::MemoryConcolicValue(mem_var) => {
    //                 let concolic_var = ConcolicVar::new_concrete_and_symbolic_int(
    //                     mem_var.get_concrete_value().unwrap_or(0),
    //                     &mem_var.symbolic.to_str(),
    //                     executor.context,
    //                     mem_var.get_size()
    //                 );
    //                 let unique_name = format!("Unique(0x{:x})", id);
    //                 executor.unique_variables.insert(unique_name, concolic_var);
    //                 log!(executor.state.logger.clone(), "Converted MemoryConcolicValue to ConcolicVar and updated unique variable: Unique(0x{:x})", id);
    //             },
    //         }
    //     },
    //     Some(Var::Register(offset, _)) => {
    //         log!(executor.state.logger.clone(), "Output is a Register type");
    //         let mut cpu_state_guard = executor.state.cpu_state.lock().unwrap();
    //         match &result_value {
    //             ConcolicEnum::ConcolicVar(var) => {
    //                 let concrete_value = var.concrete.to_u64();
    //                 let equal_bool = concrete_value != 0;
    //                 log!(executor.state.logger.clone(), "Setting register value at offset 0x{:x} to {}", offset, equal_bool as u64);
    //                 let set_result = cpu_state_guard.set_register_value_by_offset(*offset, equal_bool as u64);
    //                 match set_result {
    //                     Ok(_) => {
    //                         // Verify if the register value is set correctly
    //                         let updated_value = cpu_state_guard.get_register_value_by_offset(*offset).unwrap_or(0);
    //                         if updated_value == equal_bool as u64 {
    //                             log!(executor.state.logger.clone(), "Successfully updated register at offset 0x{:x} with value {}", offset, updated_value);
    //                         } else {
    //                             log!(executor.state.logger.clone(), "Failed to verify updated register at offset 0x{:x}", offset);
    //                             return Err(format!("Failed to verify updated register value at offset 0x{:x}", offset));
    //                         }
    //                     },
    //                     Err(e) => {
    //                         log!(executor.state.logger.clone(), "Failed to set register value: {}", e);
    //                         return Err(format!("Failed to set register value at offset 0x{:x}", offset));
    //                     }
    //                 }
    //             },
    //             ConcolicEnum::CpuConcolicValue(cpu_var) => {
    //                 let concrete_value = cpu_var.get_concrete_value().unwrap_or(0);
    //                 let equal_bool = concrete_value != 0;
    //                 log!(executor.state.logger.clone(), "Setting register value at offset 0x{:x} to {}", offset, equal_bool as u64);
    //                 let set_result = cpu_state_guard.set_register_value_by_offset(*offset, equal_bool as u64);
    //                 match set_result {
    //                     Ok(_) => {
    //                         // Verify if the register value is set correctly
    //                         let updated_value = cpu_state_guard.get_register_value_by_offset(*offset).unwrap_or(0);
    //                         if updated_value == equal_bool as u64 {
    //                             log!(executor.state.logger.clone(), "Successfully updated register at offset 0x{:x} with value {}", offset, updated_value);
    //                         } else {
    //                             log!(executor.state.logger.clone(), "Failed to verify updated register at offset 0x{:x}", offset);
    //                             return Err(format!("Failed to verify updated register value at offset 0x{:x}", offset));
    //                         }
    //                     },
    //                     Err(e) => {
    //                         log!(executor.state.logger.clone(), "Failed to set register value: {}", e);
    //                         return Err(format!("Failed to set register value at offset 0x{:x}", offset));
    //                     }
    //                 }
    //             },
    //             _ => return Err("Result of INT_EQUAL is not a ConcolicVar or CpuConcolicValue".to_string()),
    //         }
    //     },
    //     _ => {
    //         log!(executor.state.logger.clone(), "Output type is unsupported");
    //         return Err("Output type not supported".to_string());
    //     }
    // }

    // log!(executor.state.logger.clone(), "{}\n", executor);

    // // Create a concolic variable for the result
    // let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    // let result_var_name = format!("{}-{:02}-intequal", current_addr_hex, executor.instruction_counter);
    // match result_value {
    //     ConcolicEnum::ConcolicVar(var) => {
    //         executor.state.create_or_update_concolic_variable_int(&result_var_name, var.concrete.to_u64(), var.symbolic);
    //     },
    //     ConcolicEnum::CpuConcolicValue(cpu_var) => {
    //         executor.state.create_or_update_concolic_variable_int(&result_var_name, cpu_var.get_concrete_value().unwrap_or(0), cpu_var.symbolic);
    //     },
    //     ConcolicEnum::MemoryConcolicValue(mem_var) => {
    //         executor.state.create_or_update_concolic_variable_int(&result_var_name, mem_var.concrete.to_u64(), mem_var.symbolic);
    //     },
    // }

    //log!(executor.state.logger.clone(), "{}\n", executor.state);

    Ok(())
}

pub fn handle_int_notequal(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntNotEqual || instruction.inputs.len() != 2 || instruction.output.is_none() {
        return Err("Invalid instruction format for INT_NOTEQUAL".to_string());
    }

    log!(executor.state.logger.clone(), "* Fetching operands for INT_NOTEQUAL");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;

    if input0_var.get_size() != input1_var.get_size() {
        return Err("Inputs sizes do not match".to_string());
    }

    let result_bool = input0_var.get_concrete_value() != input1_var.get_concrete_value();
    log!(executor.state.logger.clone(), "*** INT_NOTEQUAL result: {}", result_bool);

    // Convert the result to a ConcolicVar or handle directly as a boolean
    match instruction.output.as_ref().unwrap().var {
        Var::Unique(id) => {
            let unique_name = format!("Unique(0x{:x})", id);
            let concolic_var = ConcolicVar::new_concrete_and_symbolic_int(result_bool.into(), &unique_name, executor.context, 1);
            executor.unique_variables.insert(unique_name, concolic_var);
            log!(executor.state.logger.clone(), "Updated unique variable with result: Unique(0x{:x})", id);
        },
        Var::Register(offset, size) if size == Size::Byte => {
            let mut cpu_state_guard = executor.state.cpu_state.lock().unwrap();
            let concrete_value = result_bool as u64;
            cpu_state_guard.set_register_value_by_offset(offset, concrete_value).map_err(|e| e.to_string())?;
            log!(executor.state.logger.clone(), "Set register at offset 0x{:x} with value {}", offset, concrete_value);
        },
        _ => {
            log!(executor.state.logger.clone(), "Unsupported output type for INT_NOTEQUAL");
            return Err("Output type not supported".to_string());
        }
    }

    Ok(())
}

pub fn handle_int_less(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntLess || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_LESS".to_string());
    }

    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for INT_LESS");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
    log!(executor.state.logger.clone(), "* Fetching instruction.input[1] for INT_LESS");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;

    // Perform the comparison
    let result_value = input0_var.concolic_less_than(input1_var, executor.context).map_err(|e| e.to_string())?;
    log!(executor.state.logger.clone(), "*** The result of INT_LESS is: {:?}", result_value.clone());

    // The result of the comparison is a boolean
    match instruction.output.as_ref().map(|v| &v.var) {
        Some(Var::Unique(id)) => {
            // Check and convert result_value to ConcolicVar
            let concolic_var = match result_value.clone() {
                ConcolicEnum::ConcolicVar(var) => var,
                ConcolicEnum::CpuConcolicValue(cpu_var) => {
                    // Convert CpuConcolicValue to ConcolicVar
                    ConcolicVar::new_concrete_and_symbolic_int(
                        cpu_var.get_concrete_value()? as u64, 
                        &format!("Unique(0x{:x})", id), 
                        executor.context, 
                        cpu_var.get_size()
                    )
                },
                ConcolicEnum::MemoryConcolicValue(mem_var) => {
                    // Convert MemoryConcolicValue to ConcolicVar
                    ConcolicVar::new_concrete_and_symbolic_int(
                        mem_var.get_concrete_value()? as u64, 
                        &format!("Unique(0x{:x})", id),
                        executor.context, 
                        mem_var.get_size()
                    )
                },
            };
            let unique_name = format!("Unique(0x{:x})", id);
            executor.unique_variables.insert(unique_name, concolic_var);
            log!(executor.state.logger.clone(), "Updated unique_variables with new comparison result: {:?}", executor.unique_variables);
        },
        Some(Var::Register(offset, _)) => {
            log!(executor.state.logger.clone(), "Output is a Register type");
            let mut cpu_state_guard = executor.state.cpu_state.lock().unwrap();
            let concrete_value = result_value.get_concrete_value();
            let _ = cpu_state_guard.set_register_value_by_offset(*offset, concrete_value);
            log!(executor.state.logger.clone(), "Updated register at offset 0x{:x} with value {}", offset, concrete_value);
        },
        _ => {
            log!(executor.state.logger.clone(), "Output type is unsupported for INT_LESS");
            return Err("Output type not supported".to_string());
        }
    }

    log!(executor.state.logger.clone(), "{}\n", executor);

    // Create a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intless", current_addr_hex, executor.instruction_counter);
    match result_value {
        ConcolicEnum::ConcolicVar(var) => {
            executor.state.create_or_update_concolic_variable_int(&result_var_name, var.concrete.to_u64(), var.symbolic);
        },
        ConcolicEnum::CpuConcolicValue(cpu_var) => {
            executor.state.create_or_update_concolic_variable_int(&result_var_name, cpu_var.get_concrete_value().unwrap_or(0), cpu_var.symbolic);
        },
        ConcolicEnum::MemoryConcolicValue(mem_var) => {
            executor.state.create_or_update_concolic_variable_int(&result_var_name, mem_var.concrete.to_u64(), mem_var.symbolic);
        },
    } 

    //log!(executor.state.logger.clone(), "{}\n", executor.state);

    Ok(())
}

pub fn handle_int_sless(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntSLess || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_SLESS".to_string());
    }

    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for INT_SLESS");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
    log!(executor.state.logger.clone(), "* Fetching instruction.input[1] for INT_SLESS");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;

    // Perform the signed less-than comparison
    let result_value = input0_var.concolic_sless(input1_var, executor.context).map_err(|e| e.to_string())?;
    log!(executor.state.logger.clone(), "*** The result of INT_SLESS is: {:?}", result_value.clone());

    // The result of the comparison is a boolean
    match instruction.output.as_ref().map(|v| &v.var) {
        Some(Var::Unique(id)) => {
            // Check and convert result_value to ConcolicVar
            let concolic_var = match result_value.clone() {
                ConcolicEnum::ConcolicVar(var) => var,
                ConcolicEnum::CpuConcolicValue(cpu_var) => {
                    // Convert CpuConcolicValue to ConcolicVar
                    ConcolicVar::new_concrete_and_symbolic_int(
                        cpu_var.get_concrete_value()? as u64, 
                        &format!("Unique(0x{:x})", id), 
                        executor.context, 
                        cpu_var.get_size()
                    )
                },
                ConcolicEnum::MemoryConcolicValue(mem_var) => {
                    // Convert MemoryConcolicValue to ConcolicVar
                    ConcolicVar::new_concrete_and_symbolic_int(
                        mem_var.get_concrete_value()? as u64, 
                        &format!("Unique(0x{:x})", id),
                        executor.context, 
                        mem_var.get_size()
                    )
                },
            };
            let unique_name = format!("Unique(0x{:x})", id);
            executor.unique_variables.insert(unique_name.clone(), concolic_var);
            log!(executor.state.logger.clone(), "Updated unique_variables with new comparison result: {:?}", executor.unique_variables);
        },
        Some(Var::Register(offset, _)) => {
            log!(executor.state.logger.clone(), "Output is a Register type");
            let mut cpu_state_guard = executor.state.cpu_state.lock().unwrap();
            let concrete_value = result_value.get_concrete_value();
            let _ = cpu_state_guard.set_register_value_by_offset(*offset, concrete_value);
            log!(executor.state.logger.clone(), "Updated register at offset 0x{:x} with value {}", offset, concrete_value);
        },
        _ => {
            log!(executor.state.logger.clone(), "Output type is unsupported for INT_SLESS");
            return Err("Output type not supported".to_string());
        }
    }

    log!(executor.state.logger.clone(), "{}\n", executor);

    // Create a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intsless", current_addr_hex, executor.instruction_counter);
    match result_value {
        ConcolicEnum::ConcolicVar(var) => {
            executor.state.create_or_update_concolic_variable_int(&result_var_name, var.concrete.to_u64(), var.symbolic);
        },
        ConcolicEnum::CpuConcolicValue(cpu_var) => {
            executor.state.create_or_update_concolic_variable_int(&result_var_name, cpu_var.get_concrete_value().unwrap_or(0), cpu_var.symbolic);
        },
        ConcolicEnum::MemoryConcolicValue(mem_var) => {
            executor.state.create_or_update_concolic_variable_int(&result_var_name, mem_var.concrete.to_u64(), mem_var.symbolic);
        },
    }  

    //log!(executor.state.logger.clone(), "{}\n", executor.state);

    Ok(())
}

pub fn handle_int_lessequal(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Ensure the correct instruction format
    if instruction.opcode != Opcode::IntLessEqual || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_LESSEQUAL".to_string());
    }

    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    // Ensure output size is 1 (boolean)
    if output_varnode.size != Size::Byte {
        return Err("Output varnode size must be 1 (Byte) for INT_LESSEQUAL".to_string());
    }

    let value0 = executor.initialize_var_if_absent(&instruction.inputs[0])?;
    let value1 = executor.initialize_var_if_absent(&instruction.inputs[1])?;

    // Perform unsigned comparison
    let result = (value0 <= value1) as u32; // Convert boolean result to u32

    // Store the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    executor.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result.into(), &result_var_name, executor.context, 1));

    Ok(())
}

pub fn handle_int_slessequal(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Ensure the correct instruction format
    if instruction.opcode != Opcode::IntSLessEqual || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_SLESSEQUAL".to_string());
    }

    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    // Ensure output size is 1 (boolean)
    if output_varnode.size != Size::Byte {
        return Err("Output varnode size must be 1 (Byte) for INT_SLESSEQUAL".to_string());
    }

    let value0 = executor.initialize_var_if_absent(&instruction.inputs[0])?;
    let value1 = executor.initialize_var_if_absent(&instruction.inputs[1])?;

    // Assuming the conversion logic for signed values based on their actual size (?)
    let signed_value0 = value0 as i32; 
    let signed_value1 = value1 as i32; 

    // Perform signed comparison
    let result = (signed_value0 <= signed_value1) as u32; // Convert boolean result to u32

    // Store the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    executor.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result.into(), &result_var_name, executor.context, 1));

    Ok(())
}

// Handle INT_ZEXT instruction
pub fn handle_int_zext(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntZExt || instruction.inputs.len() != 1 || instruction.output.is_none() {
        return Err("Invalid instruction format for INT_ZEXT".to_string());
    }

    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for INT_ZEXT");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
    let output_size = instruction.output.as_ref().unwrap().size.to_bitvector_size();  // Ensure to_bitvector_size() returns u32
    
    // Zero-extend the input variable
    let result_value = input0_var.concolic_zero_extend(output_size).map_err(|e| e.to_string())?;
    log!(executor.state.logger.clone(), "*** The result of INT_ZEXT is: {:?}", result_value.clone());

    // Determine the output variable and update it with the zero-extended data
    if let Some(output_varnode) = instruction.output.as_ref() {
        match &output_varnode.var {
            Var::Unique(id) => {
                let concolic_var = match result_value.clone() {
                    ConcolicEnum::ConcolicVar(var) => var,
                    ConcolicEnum::CpuConcolicValue(cpu_var) => {
                        // Convert CpuConcolicValue to ConcolicVar
                        ConcolicVar::new_concrete_and_symbolic_int(
                            cpu_var.get_concrete_value()? as u64, 
                            &format!("Unique(0x{:x})", id), 
                            executor.context, 
                            cpu_var.get_size()
                        )
                    },
                    ConcolicEnum::MemoryConcolicValue(mem_var) => {
                        // Convert MemoryConcolicValue to ConcolicVar
                        ConcolicVar::new_concrete_and_symbolic_int(
                            mem_var.get_concrete_value()? as u64, 
                            &format!("Unique(0x{:x})", id),
                            executor.context, 
                            mem_var.get_size()
                        )
                    },
                };
                let unique_name = format!("Unique(0x{:x})", id);
                executor.unique_variables.insert(unique_name, concolic_var);
                log!(executor.state.logger.clone(), "Updated unique_variables with new comparison result: {:?}", executor.unique_variables);
            },
            Var::Register(offset, _) => {
                log!(executor.state.logger.clone(), "Output is a Register type");
                let mut cpu_state_guard = executor.state.cpu_state.lock().unwrap();
                let concrete_value = result_value.get_concrete_value();
                let _ = cpu_state_guard.set_register_value_by_offset(*offset, concrete_value);
                log!(executor.state.logger.clone(), "Updated register at offset 0x{:x} with value {}", offset, concrete_value);
            },
            _ => {
                log!(executor.state.logger.clone(), "Output type is unsupported for INT_ZEXT");
                return Err("Output type not supported".to_string());
            }
        }
    } else {
        return Err("No output variable specified for ZEXT instruction".to_string());
    }

    log!(executor.state.logger.clone(), "{}\n", executor);

    // Create a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intzext", current_addr_hex, executor.instruction_counter);
    match result_value {
        ConcolicEnum::ConcolicVar(var) => {
            executor.state.create_or_update_concolic_variable_int(&result_var_name, var.concrete.to_u64(), var.symbolic);
        },
        ConcolicEnum::CpuConcolicValue(cpu_var) => {
            executor.state.create_or_update_concolic_variable_int(&result_var_name, cpu_var.get_concrete_value().unwrap_or(0), cpu_var.symbolic);
        },
        ConcolicEnum::MemoryConcolicValue(mem_var) => {
            executor.state.create_or_update_concolic_variable_int(&result_var_name, mem_var.concrete.to_u64(), mem_var.symbolic);
        },
    }

    //log!(executor.state.logger.clone(), "{}\n", executor.state);

    Ok(())
}

pub fn handle_int_sext(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Validate instruction format and sizes
    if instruction.opcode != Opcode::IntSExt || instruction.inputs.len() != 1 {
        return Err("Invalid instruction format for INT_SEXT".to_string());
    }

    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    if instruction.inputs[0].size >= output_varnode.size {
        return Err("Output size must be strictly bigger than input size for INT_SEXT".to_string());
    }

    let input_value = executor.initialize_var_if_absent(&instruction.inputs[0])?;
    let input_bits = instruction.inputs[0].size.to_bitvector_size() * 8;
    let shift_amount = 64u32.saturating_sub(input_bits);

    let extended_value = match instruction.inputs[0].size {
        Size::QuadQuad => I256::from(input_value),
        Size::DoubleQuad => (input_value as i128).into(),
        Size::Byte => (((input_value as i8) as i128).wrapping_shl(shift_amount) as u128).try_into().unwrap(),
        Size::Half => (((input_value as i16) as i128).wrapping_shl(shift_amount) as u128).try_into().unwrap(),
        Size::Word => (((input_value as i32) as i128).wrapping_shl(shift_amount) as u128).try_into().unwrap(),
        Size::Quad => (((input_value as i64) as i128).wrapping_shl(shift_amount) as u128).try_into().unwrap(),
    }; 

    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    
    // Ensure no left shift overflow occurs
    let bitmask = if output_varnode.size.to_bitvector_size() == 256 {
        I256::MAX
    } else {
        // For sizes less than 256 bits, construct the bitmask using shifting.
        // Note: I256 does not support shifting by u32 directly, so we convert to usize.
        let shift_amount = (output_varnode.size.to_bitvector_size() * 8) as usize;
        if shift_amount >= 256 {
            return Err("Shift amount exceeds 256 bits".to_string());
        }
        (I256::ONE << shift_amount) - I256::ONE
    };

    // Attempt to downcast to u64, handling potential overflow
    let result: u64 = (extended_value & bitmask).try_into().map_err(|_| "Value cannot be downcasted to u64 without loss".to_string())?;
    executor.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result, &result_var_name, executor.context, output_varnode.size.to_bitvector_size()));

    Ok(())
}

pub fn handle_int_sborrow(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntSBorrow || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for SBORROW".to_string());
    }

    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for SBORROW");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
    log!(executor.state.logger.clone(), "* Fetching instruction.input[1] for SBORROW");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;

    // Perform the signed subtraction with overflow check
    let overflow = match input0_var.concolic_sborrow(input1_var, executor.context) {
        Ok(overflow) => overflow,
        Err(e) => {
            log!(executor.state.logger.clone(), "Overflow detected during SBORROW operation: {}", e);
            return Err("Overflow during SBORROW operation".to_string());
        }
    };
    log!(executor.state.logger.clone(), "*** Overflow occurred: {}\n", overflow);

    // Create a ConcolicVar representing the overflow result
    let concolic_var = ConcolicVar::new_concrete_and_symbolic_int(
        overflow as u64,
        "sborrow_overflow",
        executor.context,
        1, // boolean is 1 bit
    );

    // Store the result based on the output varnode
    match instruction.output.as_ref().map(|v| &v.var) {
        Some(Var::Unique(id)) => {
            let unique_name = format!("Unique(0x{:x})", id);
            executor.unique_variables.insert(unique_name, concolic_var.clone());
            log!(executor.state.logger.clone(), "Updated unique_variables with new comparison result: {:?}", executor.unique_variables);
        },
        Some(Var::Register(offset, _)) => {
            log!(executor.state.logger.clone(), "Output is a Register type");
            let mut cpu_state_guard = executor.state.cpu_state.lock().unwrap();
            let concrete_value = concolic_var.concrete.to_u64();
            let _ = cpu_state_guard.set_register_value_by_offset(*offset, concrete_value);
            log!(executor.state.logger.clone(), "Updated register at offset 0x{:x} with value {}", offset, concrete_value);
        },
        _ => {
            log!(executor.state.logger.clone(), "Output type is unsupported for SBORROW");
            return Err("Output type not supported".to_string());
        }
    }

    log!(executor.state.logger.clone(), "{}\n", executor);

    // Create a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-sborrow", current_addr_hex, executor.instruction_counter);
    executor.state.create_or_update_concolic_variable_int(&result_var_name, overflow as u64, SymbolicVar::Int(BV::from_u64(&executor.context, overflow as u64, 1)));

    //log!(executor.state.logger.clone(), "{}\n", executor.state);

    Ok(())
}

pub fn handle_int_2comp(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Validate instruction format
    if instruction.opcode != Opcode::Int2Comp || instruction.inputs.len() != 1 {
        return Err("Invalid instruction format for INT_2COMP".to_string());
    }

    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    if instruction.inputs[0].size != output_varnode.size {
        return Err("Input and output must be the same size for INT_2COMP".to_string());
    }

    let input_value = executor.initialize_var_if_absent(&instruction.inputs[0])?;

    // Perform two's complement negation
    let negated_value = (!input_value).wrapping_add(1); // Bitwise NOT then add one

    // Store the negated value
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    executor.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(negated_value.into(), &result_var_name, executor.context, output_varnode.size.to_bitvector_size()));

    Ok(())
}

pub fn handle_int_and(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntAnd || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_AND".to_string());
    }

    // Fetch concolic variables
    log!(executor.state.logger.clone(), "Fetching instruction.input[0] for INT_AND");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
    log!(executor.state.logger.clone(), "Fetching instruction.input[1] for INT_AND");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;

    // Perform the logical-and operation using concolic_and
    log!(executor.state.logger.clone(), "Performing logical AND operation");
    let result_value = input0_var.concolic_and(executor.context, input1_var)?;
    log!(executor.state.logger.clone(), "The result of INT_AND is: {:?}", result_value);

    // Handle the result based on the output varnode
    match instruction.output.as_ref().map(|v| &v.var) {
        Some(Var::Unique(id)) => {
            log!(executor.state.logger.clone(), "Handling unique variable");
            match result_value.clone() {
                ConcolicEnum::ConcolicVar(concolic_var) => {
                    let unique_name = format!("Unique(0x{:x})", id);
                    executor.unique_variables.insert(unique_name, concolic_var);
                    log!(executor.state.logger.clone(), "Updated unique variable: Unique(0x{:x})", id);
                },
                ConcolicEnum::MemoryConcolicValue(mem_var) => {
                    let concolic_var = ConcolicVar::new_concrete_and_symbolic_int(
                        mem_var.concrete.to_u64(),
                        &mem_var.symbolic.to_str(),
                        executor.context,
                        mem_var.get_size(),
                    );
                    let unique_name = format!("Unique(0x{:x})", id);
                    executor.unique_variables.insert(unique_name, concolic_var);
                    log!(executor.state.logger.clone(), "Converted MemoryConcolicValue to ConcolicVar and updated unique variable: Unique(0x{:x})", id);
                },
                ConcolicEnum::CpuConcolicValue(cpu_var) => {
                    let concolic_var = ConcolicVar::new_concrete_and_symbolic_int(
                        cpu_var.concrete.to_u64(),
                        &cpu_var.symbolic.to_str(),
                        executor.context,
                        cpu_var.get_size(),
                    );
                    let unique_name = format!("Unique(0x{:x})", id);
                    executor.unique_variables.insert(unique_name, concolic_var);
                    log!(executor.state.logger.clone(), "Updated unique variable: Unique(0x{:x})", id);
                },
            }
        },
        Some(Var::Register(offset, _)) => {
            log!(executor.state.logger.clone(), "Output is a Register type");
            let mut cpu_state_guard = executor.state.cpu_state.lock().unwrap();
            match result_value.clone() {
                ConcolicEnum::CpuConcolicValue(var) => {
                    let concrete_value = var.concrete.to_u64();
                    log!(executor.state.logger.clone(), "Setting register value at offset 0x{:x} to {}", offset, concrete_value);
                    let set_result = cpu_state_guard.set_register_value_by_offset(*offset, concrete_value);
                    match set_result {
                        Ok(_) => {
                            // Verify if the register value is set correctly
                            let updated_value = cpu_state_guard.get_register_value_by_offset(*offset).unwrap_or(0);
                            if updated_value == concrete_value {
                                log!(executor.state.logger.clone(), "Successfully updated register at offset 0x{:x} with value {}", offset, updated_value);
                            } else {
                                error!("Failed to verify updated register at offset 0x{:x}", offset);
                                return Err(format!("Failed to verify updated register value at offset 0x{:x}", offset));
                            }
                        },
                        Err(e) => {
                            error!("Failed to set register value: {}", e);
                            return Err(format!("Failed to set register value at offset 0x{:x}", offset));
                        }
                    }
                },
                ConcolicEnum::MemoryConcolicValue(var) => {
                    let concrete_value = var.concrete.to_u64();
                    log!(executor.state.logger.clone(), "Setting register value at offset 0x{:x} to {}", offset, concrete_value);
                    let set_result = cpu_state_guard.set_register_value_by_offset(*offset, concrete_value);
                    match set_result {
                        Ok(_) => {
                            // Verify if the register value is set correctly
                            let updated_value = cpu_state_guard.get_register_value_by_offset(*offset).unwrap_or(0);
                            if updated_value == concrete_value {
                                log!(executor.state.logger.clone(), "Successfully updated register at offset 0x{:x} with value {}", offset, updated_value);
                            } else {
                                error!("Failed to verify updated register at offset 0x{:x}", offset);
                                return Err(format!("Failed to verify updated register value at offset 0x{:x}", offset));
                            }
                        },
                        Err(e) => {
                            error!("Failed to set register value: {}", e);
                            return Err(format!("Failed to set register value at offset 0x{:x}", offset));
                        }
                    }
                },
                _ => return Err("Result of INT_AND is not a ConcolicVar or CpuConcolicValue or MemoryConcolicValue".to_string()),
            }
        },
        _ => {
            log!(executor.state.logger.clone(), "Output type is unsupported");
            return Err("Output type not supported".to_string());
        }
    }

    log!(executor.state.logger.clone(), "{}", executor);

    // Create a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intand", current_addr_hex, executor.instruction_counter);
    match result_value {
        ConcolicEnum::ConcolicVar(var) => {
            executor.state.create_or_update_concolic_variable_int(&result_var_name, var.concrete.to_u64(), var.symbolic);
            log!(executor.state.logger.clone(), "Created concolic variable for the result: {}", result_var_name);
        },
        ConcolicEnum::CpuConcolicValue(var) => {
            executor.state.create_or_update_concolic_variable_int(&result_var_name, var.concrete.to_u64(), var.symbolic);
            log!(executor.state.logger.clone(), "Created concolic variable for the result: {}", result_var_name);
        },
        ConcolicEnum::MemoryConcolicValue(var) => {
            executor.state.create_or_update_concolic_variable_int(&result_var_name, var.concrete.to_u64(), var.symbolic);
            log!(executor.state.logger.clone(), "Created concolic variable for the result: {}", result_var_name);
        },
    }

    //log!(executor.state.logger.clone(), "{}", executor.state);

    Ok(())
}


pub fn handle_int_or(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Validate instruction format and sizes
    if instruction.opcode != Opcode::IntOr || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_OR".to_string());
    }

    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    if instruction.inputs[0].size != instruction.inputs[1].size || instruction.inputs[0].size != output_varnode.size {
        return Err("All inputs and output must be the same size for INT_OR".to_string());
    }

    let input0_value = executor.initialize_var_if_absent(&instruction.inputs[0])?;
    let input1_value = executor.initialize_var_if_absent(&instruction.inputs[1])?;

    // Perform bitwise OR
    let result = input0_value | input1_value;

    // Store the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    executor.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result.into(), &result_var_name, executor.context, output_varnode.size.to_bitvector_size()));

    Ok(())
}

pub fn handle_int_left(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Validate instruction format and sizes
    if instruction.opcode != Opcode::IntLeft || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_LEFT".to_string());
    }

    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    if instruction.inputs[0].size != output_varnode.size {
        return Err("Input0 and output must be the same size for INT_LEFT".to_string());
    }

    let input0_value = executor.initialize_var_if_absent(&instruction.inputs[0])?;
    let shift_amount = executor.initialize_var_if_absent(&instruction.inputs[1])? as usize;

    // Perform left shift operation
    let result = if shift_amount < (output_varnode.size.to_bitvector_size() * 8) as usize {
        input0_value << shift_amount
    } else {
        0 // Shift amount is larger than the number of bits in output, result is zero
    };

    // Store the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    executor.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result.into(), &result_var_name, executor.context, output_varnode.size.to_bitvector_size()));

    Ok(())
}

pub fn handle_int_right(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Validate instruction format and sizes
    if instruction.opcode != Opcode::IntRight || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_RIGHT".to_string());
    }

    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    if instruction.inputs[0].size != output_varnode.size {
        return Err("Input0 and output must be the same size for INT_RIGHT".to_string());
    }

    let input0_value = executor.initialize_var_if_absent(&instruction.inputs[0])?;
    let shift_amount = executor.initialize_var_if_absent(&instruction.inputs[1])? as usize;

    // Perform unsigned right shift operation
    let result = if shift_amount < (output_varnode.size.to_bitvector_size() * 8) as usize {
        input0_value >> shift_amount
    } else {
        0 // Shift amount is larger than the number of bits in output, result is zero
    };

    // Store the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    executor.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result.into(), &result_var_name, executor.context, output_varnode.size.to_bitvector_size()));

    Ok(())
}

pub fn handle_int_sright(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Validate instruction format and sizes
    if instruction.opcode != Opcode::IntSRight || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_SRIGHT".to_string());
    }

    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    if instruction.inputs[0].size != output_varnode.size {
        return Err("Input0 and output must be the same size for INT_SRIGHT".to_string());
    }

    let input0_value = executor.initialize_var_if_absent(&instruction.inputs[0])? as i64; // Cast to signed integer
    let shift_amount = executor.initialize_var_if_absent(&instruction.inputs[1])? as usize;

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
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    executor.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result.into(), &result_var_name, executor.context, output_varnode.size.to_bitvector_size()));

    Ok(())
}

pub fn handle_int_mult(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Validate instruction format and sizes
    if instruction.opcode != Opcode::IntMult || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_MULT".to_string());
    }

    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    if instruction.inputs[0].size != instruction.inputs[1].size || instruction.inputs[0].size != output_varnode.size {
        return Err("All inputs and output must be the same size for INT_MULT".to_string());
    }

    let input0_value = executor.initialize_var_if_absent(&instruction.inputs[0])?;
    let input1_value = executor.initialize_var_if_absent(&instruction.inputs[1])?;

    // Perform multiplication
    let result = input0_value.wrapping_mul(input1_value); // Use wrapping_mul to handle overflow

    // Store the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    executor.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result.into(), &result_var_name, executor.context, output_varnode.size.to_bitvector_size()));

    Ok(())
}

pub fn handle_int_negate(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntNegate || instruction.inputs.len() != 1 {
        return Err("Invalid instruction format for INT_NEGATE".to_string());
    }

    // Retrieve the concrete integer value for the input
    let input_val = executor.initialize_var_if_absent(&instruction.inputs[0])?;

    // Perform NOT operation on the concrete integer value
    let negated_concrete = !input_val;

    // Prepare for the symbolic computation
    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    let bitvector_size = output_varnode.size.to_bitvector_size();

    // Create or update the output concolic variable with the negated concrete value
    executor.state.create_concolic_var_int(&result_var_name, negated_concrete, bitvector_size);

    Ok(())
}

pub fn handle_int_div(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Validate instruction format and sizes
    if instruction.opcode != Opcode::IntDiv || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_DIV".to_string());
    }

    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    if instruction.inputs[0].size != instruction.inputs[1].size || instruction.inputs[0].size != output_varnode.size {
        return Err("All inputs and output must be the same size for INT_DIV".to_string());
    }

    let input0_value = executor.initialize_var_if_absent(&instruction.inputs[0])?;
    let input1_value = executor.initialize_var_if_absent(&instruction.inputs[1])?;

    // Check for division by zero
    // if input1_value == 0 {
    //     // Instead of proceeding with division, return an error
    //     return Err("Division by zero encountered in INT_DIV".to_string());
    // }

    // Check for division by zero
    let result = if input1_value == 0 {
        // Log division by zero 
        log!(executor.state.logger.clone(), "Warning: Division by zero encountered in INT_DIV at address {:x}. Using default value 0.", executor.current_address.unwrap_or(0));
        0 
    } else {
        // Perform division
        input0_value / input1_value
    };

    // Store the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    executor.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result.into(), &result_var_name, executor.context, output_varnode.size.to_bitvector_size()));

    Ok(())
}

pub fn handle_int_rem(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Validate instruction format and sizes
    if instruction.opcode != Opcode::IntRem || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_REM".to_string());
    }

    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    if instruction.inputs[0].size != instruction.inputs[1].size || instruction.inputs[0].size != output_varnode.size {
        return Err("All inputs and output must be the same size for INT_REM".to_string());
    }

    let input0_value = executor.initialize_var_if_absent(&instruction.inputs[0])?;
    let input1_value = executor.initialize_var_if_absent(&instruction.inputs[1])?;

    // Check for division by zero
    if input1_value == 0 {
        // Instead of proceeding with the remainder calculation, return an error
        return Err("Division by zero encountered in INT_REM".to_string());
    }

    // Perform remainder operation
    let result = input0_value % input1_value;

    // Store the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    executor.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result.into(), &result_var_name, executor.context, output_varnode.size.to_bitvector_size()));

    Ok(())
}

pub fn handle_int_sdiv(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Validate instruction format and sizes
    if instruction.opcode != Opcode::IntSDiv || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_SDIV".to_string());
    }

    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    if instruction.inputs[0].size != instruction.inputs[1].size || instruction.inputs[0].size != output_varnode.size {
        return Err("All inputs and output must be the same size for INT_SDIV".to_string());
    }

    let input0_value = executor.initialize_var_if_absent(&instruction.inputs[0])? as i32; // Cast to signed
    let input1_value = executor.initialize_var_if_absent(&instruction.inputs[1])? as i32;

    // Check for division by zero
    if input1_value == 0 {
        return Err("Division by zero encountered in INT_SDIV".to_string());
    }

    // Perform signed division
    let result = input0_value / input1_value;

    // Store the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    executor.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result.try_into().unwrap(), &result_var_name, executor.context, output_varnode.size.to_bitvector_size()));

    Ok(())
}

pub fn handle_int_srem(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Validate instruction format and sizes
    if instruction.opcode != Opcode::IntSRem || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_SREM".to_string());
    }

    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    if instruction.inputs[0].size != instruction.inputs[1].size || instruction.inputs[0].size != output_varnode.size {
        return Err("All inputs and output must be the same size for INT_SREM".to_string());
    }

    let input0_value = executor.initialize_var_if_absent(&instruction.inputs[0])? as i32;
    let input1_value = executor.initialize_var_if_absent(&instruction.inputs[1])? as i32;

    // Check for division by zero
    if input1_value == 0 {
        return Err("Division by zero encountered in INT_SREM".to_string());
    }

    // Perform signed remainder operation
    let result = input0_value % input1_value;

    // Store the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    executor.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result.try_into().unwrap(), &result_var_name, executor.context, output_varnode.size.to_bitvector_size()));

    Ok(())
}

pub fn handle_int2float(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::Int2Float || instruction.inputs.len() != 1 {
        return Err("Invalid instruction format for INT2FLOAT".to_string());
    }

    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required".to_string())?;
    
    let input0_value = executor.state.get_concrete_var(&instruction.inputs[0])?;

    let result = match input0_value {
        ConcreteVar::Int(i0) => i0 as f64, // Handle conversion from integer to float.
        _ => return Err("Expected an integer value for INT2FLOAT".to_string()),
    };

    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    executor.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_float(result, &result_var_name, executor.context));

    Ok(())
}
