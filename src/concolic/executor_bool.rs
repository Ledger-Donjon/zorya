/// Focuses on implementing the execution of the BOOL related opcodes from Ghidra's Pcode specification
/// This implementation relies on Ghidra 11.0.1 with the specfiles in /specfiles

use crate::concolic::executor::ConcolicExecutor;
use parser::parser::{Inst, Opcode};
use z3::ast::{Ast, Bool, BV};
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

    // Fetch concolic variables for inputs
    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for BOOL_AND");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;

    log!(executor.state.logger.clone(), "* Fetching instruction.input[1] for BOOL_AND");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;

    let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    // Get symbolic values and zero BV for comparison
    let symbolic_bv0 = input0_var.to_concolic_var().unwrap().symbolic.to_bv(executor.context);
    let symbolic_bv1 = input1_var.to_concolic_var().unwrap().symbolic.to_bv(executor.context);
    let zero_bv = BV::from_u64(executor.context, 0, symbolic_bv0.get_size());

    // Correctly perform logical AND using Z3's Bool::and associated function
    let result_symbolic_bool = Bool::and(executor.context, &[
        &symbolic_bv0._eq(&zero_bv).not(),
        &symbolic_bv1._eq(&zero_bv).not()
    ]).simplify();

    let result_symbolic_bv = result_symbolic_bool.ite(
        &BV::from_u64(executor.context, 1, output_size_bits),
        &BV::from_u64(executor.context, 0, output_size_bits),
    ).simplify();

    // Perform logical AND concretely
    let result_concrete = input0_var.get_concrete_value() != 0 && input1_var.get_concrete_value() != 0;
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(
        result_concrete as u64,
        result_symbolic_bv,
        executor.context,
        output_size_bits
    );

    log!(executor.state.logger.clone(), "*** The result of BOOL_AND is: {:?}\n", result_concrete);

    executor.handle_output(instruction.output.as_ref(), result_value)?;

    Ok(())
}

// Handle the BOOL_NEGATE instruction
pub fn handle_bool_negate(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::BoolNegate || instruction.inputs.len() != 1 {
        return Err("Invalid instruction format for BOOL_NEGATE".to_string());
    }

    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for BOOL_NEGATE");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;

    let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    // Perform correct logical negation
    let symbolic_bv = input0_var.to_concolic_var().unwrap().symbolic.to_bv(executor.context);
    let zero_bv = BV::from_u64(executor.context, 0, symbolic_bv.get_size());

    let result_symbolic_bv = symbolic_bv._eq(&zero_bv).ite(
        &BV::from_u64(executor.context, 1, output_size_bits),
        &BV::from_u64(executor.context, 0, output_size_bits),
    );

    // equivalent to : !(input0_var.get_concrete_value() != 0);
    let result_concrete = input0_var.get_concrete_value() == 0;
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(result_concrete as u64, result_symbolic_bv, executor.context, output_size_bits);

    log!(executor.state.logger.clone(), "*** The result of BOOL_NEGATE is: {:?}\n", result_concrete);

    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

    Ok(())
}

// Handle the BOOL_OR instruction
pub fn handle_bool_or(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::BoolOr || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for BOOL_OR".to_string());
    }

    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for BOOL_OR");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
    log!(executor.state.logger.clone(), "* Fetching instruction.input[1] for BOOL_OR");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;

    let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    let symbolic_bv0 = input0_var.to_concolic_var().unwrap().symbolic.to_bv(executor.context);
    let symbolic_bv1 = input1_var.to_concolic_var().unwrap().symbolic.to_bv(executor.context);
    let zero_bv = BV::from_u64(executor.context, 0, symbolic_bv0.get_size());

    let symbolic_bool0 = symbolic_bv0._eq(&zero_bv).not();
    let symbolic_bool1 = symbolic_bv1._eq(&zero_bv).not();

    let result_symbolic_bool = Bool::or(executor.context, &[&symbolic_bool0, &symbolic_bool1]).simplify();

    let result_symbolic_bv = result_symbolic_bool.ite(
        &BV::from_u64(executor.context, 1, output_size_bits),
        &BV::from_u64(executor.context, 0, output_size_bits),
    ).simplify();

    let result_concrete = input0_var.get_concrete_value() != 0 || input1_var.get_concrete_value() != 0;

    let result_value = ConcolicVar::new_concrete_and_symbolic_int(result_concrete as u64, result_symbolic_bv, executor.context, output_size_bits);

    log!(executor.state.logger.clone(), "*** The result of BOOL_OR is: {:?}\n", result_concrete);

    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

    Ok(())
}

// Handle the BOOL_XOR instruction
pub fn handle_bool_xor(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::BoolXor || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for BOOL_XOR".to_string());
    }

    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for BOOL_XOR");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
    log!(executor.state.logger.clone(), "* Fetching instruction.input[1] for BOOL_XOR");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;

    let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    let symbolic_bv0 = input0_var.to_concolic_var().unwrap().symbolic.to_bv(executor.context);
    let symbolic_bv1 = input1_var.to_concolic_var().unwrap().symbolic.to_bv(executor.context);
    let zero_bv = BV::from_u64(executor.context, 0, symbolic_bv0.get_size());

    let symbolic_bool0 = symbolic_bv0._eq(&zero_bv).not();
    let symbolic_bool1 = symbolic_bv1._eq(&zero_bv).not();

    let result_symbolic = symbolic_bool0.xor(&symbolic_bool1);

    let result_symbolic_bv = result_symbolic.ite(
        &BV::from_u64(executor.context, 1, output_size_bits),
        &BV::from_u64(executor.context, 0, output_size_bits),
    ).simplify();

    let result_concrete = (input0_var.get_concrete_value() != 0) ^ (input1_var.get_concrete_value() != 0);

    let result_value = ConcolicVar::new_concrete_and_symbolic_int(result_concrete as u64, result_symbolic_bv, executor.context, output_size_bits);

    log!(executor.state.logger.clone(), "*** The result of BOOL_XOR is: {:?}\n", result_concrete);

    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

    Ok(())
}