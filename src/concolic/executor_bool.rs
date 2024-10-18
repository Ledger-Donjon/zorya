/// Focuses on implementing the execution of the BOOL related opcodes from Ghidra's Pcode specification
/// This implementation relies on Ghidra 11.0.1 with the specfiles in /specfiles

use crate::concolic::executor::ConcolicExecutor;
use parser::parser::{Inst, Opcode};
use z3::ast::Bool;
use std::io::Write;

use super::ConcolicVar;

macro_rules! log {
    ($logger:expr, $($arg:tt)*) => {{
        writeln!($logger, $($arg)*).unwrap();
    }};
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
    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

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
    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

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
    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

    Ok(())
}

// Handle the BOOL_XOR instruction
pub fn handle_bool_xor(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::BoolXor || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for BOOL_XOR".to_string());
    }

    // Fetch the concolic variables for the inputs
    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for BOOL_XOR");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
    log!(executor.state.logger.clone(), "* Fetching instruction.input[1] for BOOL_XOR");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;

    let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    // Perform the logical XOR operation
    let result_concrete = (input0_var.get_concrete_value() != 0) ^ (input1_var.get_concrete_value() != 0);
    
    // Correct use of the Bool::xor function for symbolic values
    let result_symbolic = Bool::xor(
        &input0_var.get_symbolic_value_bool(),
        &input1_var.get_symbolic_value_bool()
    );

    let result_value = ConcolicVar::new_concrete_and_symbolic_bool(result_concrete, result_symbolic, executor.context, output_size_bits);

    log!(executor.state.logger.clone(), "*** The result of BOOL_XOR is: {:?}\n", result_concrete);

    // Handle the result based on the output varnode
    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

    Ok(())
}
