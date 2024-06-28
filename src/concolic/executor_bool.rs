/// Focuses on implementing the execution of the BOOL related opcodes from Ghidra's Pcode specification
/// This implementation relies on Ghidra 11.0.1 with the specfiles in /specfiles

use crate::concolic::executor::ConcolicExecutor;
use parser::parser::{Inst, Opcode, Size, Var, Varnode};
use z3::ast::Bool;
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

// Handle the BOOL_AND instruction
pub fn handle_bool_and(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::BoolAnd || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for BOOL_AND".to_string());
    }

    // Fetch the concolic variables for the inputs
    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for BOOL_AND");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
    log!(executor.state.logger.clone(), "* Fetching instruction.input[1] for BOOL_AND");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;

    let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    // Perform the logical AND operation
    let result_concrete = input0_var.get_concrete_value() != 0 && input1_var.get_concrete_value() != 0;
    let context = &executor.context;
    let result_symbolic = Bool::and(
        context,
        &[&input0_var.get_symbolic_value_bool(), &input1_var.get_symbolic_value_bool()]
    );

    let result_value = ConcolicVar::new_concrete_and_symbolic_bool(result_concrete, result_symbolic, executor.context, output_size_bits);

    log!(executor.state.logger.clone(), "*** The result of BOOL_AND is: {:?}\n", result_concrete);

    // Handle the result based on the output varnode
    handle_output(executor, instruction.output.as_ref(), result_value.clone())?;

    log!(executor.state.logger.clone(), "{}\n", executor);

    Ok(())
}

// Handle the BOOL_NEGATE instruction
pub fn handle_bool_negate(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::BoolNegate || instruction.inputs.len() != 1 {
        return Err("Invalid instruction format for BOOL_NEGATE".to_string());
    }

    // Fetch the concolic variable for the input
    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for BOOL_NEGATE");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;

    let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    // Perform the logical negation
    let result_concrete = !(input0_var.get_concrete_value() != 0);
    let result_symbolic = input0_var.get_symbolic_value_bool().not();

    let result_value = ConcolicVar::new_concrete_and_symbolic_bool(result_concrete, result_symbolic, executor.context, output_size_bits);

    log!(executor.state.logger.clone(), "*** The result of BOOL_NEGATE is: {:?}\n", result_concrete);

    // Handle the result based on the output varnode
    handle_output(executor, instruction.output.as_ref(), result_value.clone())?;

    log!(executor.state.logger.clone(), "{}\n", executor);

    Ok(())
}


// Handle the BOOL_OR instruction
pub fn handle_bool_or(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::BoolOr || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for BOOL_OR".to_string());
    }

    // Fetch the concolic variables for the inputs
    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for BOOL_OR");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
    log!(executor.state.logger.clone(), "* Fetching instruction.input[1] for BOOL_OR");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;

    let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    // Perform the logical OR operation
    let result_concrete = input0_var.get_concrete_value() != 0 || input1_var.get_concrete_value() != 0;
    let result_symbolic = Bool::or(&executor.context, &[&input0_var.get_symbolic_value_bool(), &input1_var.get_symbolic_value_bool()]);

    let result_value = ConcolicVar::new_concrete_and_symbolic_bool(result_concrete, result_symbolic, executor.context, output_size_bits);

    log!(executor.state.logger.clone(), "*** The result of BOOL_OR is: {:?}\n", result_concrete);

    // Handle the result based on the output varnode
    handle_output(executor, instruction.output.as_ref(), result_value.clone())?;

    log!(executor.state.logger.clone(), "{}\n", executor);

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
    let _result = (input0_value ^ input1_value) & 1; // Ensure result is boolean (0 or 1)

    // Store the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let _result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    //executor.state.create_concolic_var_int(&result_var_name, result as u64, 1);

    Ok(())
}
