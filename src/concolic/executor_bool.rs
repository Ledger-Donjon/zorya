/// Focuses on implementing the execution of the BOOL related opcodes from Ghidra's Pcode specification
/// This implementation relies on Ghidra 11.0.1 with the specfiles in /specfiles

use crate::executor::ConcolicExecutor;
use parser::parser::{Inst, Opcode, Size};

use super::ConcolicVar;

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
    // Validate instruction format and sizes
    if instruction.opcode != Opcode::BoolOr || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for BOOL_OR".to_string());
    }

    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    if output_varnode.size != Size::Byte {
        return Err("Output must be size 1 (Byte) for BOOL_OR".to_string());
    }

    let input0_value = executor.initialize_var_if_absent(&instruction.inputs[0])?;
    let input1_value = executor.initialize_var_if_absent(&instruction.inputs[1])?;

    // Perform boolean OR
    let result = (input0_value | input1_value) & 1; // Ensure result is boolean (0 or 1)

    // Store the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    executor.state.create_concolic_var_int(&result_var_name, result as u64, 1);
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
