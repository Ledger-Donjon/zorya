/// Focuses on implementing the execution of the FLOAT related opcodes from Ghidra's Pcode specification
/// This implementation relies on Ghidra 11.0.1 with the specfiles in /specfiles

use crate::{concolic::{ConcolicEnum, ConcolicVar, SymbolicVar}, executor::ConcolicExecutor};
use parser::parser::{Inst, Opcode};
use z3::ast::Bool;
use std::io::Write;
use super::ConcreteVar;

macro_rules! log {
    ($logger:expr, $($arg:tt)*) => {{
        writeln!($logger, $($arg)*).unwrap();
    }};
}
pub fn handle_float_nan(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::FloatNaN || instruction.inputs.len() != 1 {
        return Err("Invalid instruction format for FLOAT_NAN".to_string());
    }

    log!(executor.state.logger.clone(), "* Fetching floating-point input for FLOAT_NAN");
    let input0_enum = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;

    let (result_concrete, result_symbolic) = match input0_enum {
        ConcolicEnum::ConcolicVar(var) => {
            match var.concrete.get_size() {
                32 => {
                    let input_value = f32::from_bits(var.concrete.to_u32().unwrap()); // Assumes it's safe to convert
                    (input_value.is_nan(), SymbolicVar::Bool(Bool::from_bool(executor.context, input_value.is_nan())))
                },
                64 => {
                    let input_value = f64::from_bits(var.concrete.to_u64()); // Assumes it's safe to convert
                    (input_value.is_nan(), SymbolicVar::Bool(Bool::from_bool(executor.context, input_value.is_nan())))
                },
                _ => return Err("Unsupported float size for NaN check".to_string())
            }
        },
        _ => return Err("Unsupported ConcolicEnum variant for this operation".to_string())
    };

    log!(executor.state.logger.clone(), "Result of FLOAT_NAN check: {}", result_concrete);

    if let Some(output_varnode) = instruction.output.as_ref() {
        let result_value = ConcolicVar {
            concrete: ConcreteVar::Bool(result_concrete),
            symbolic: result_symbolic,
            ctx: executor.context
        };

        executor.handle_output(Some(output_varnode), result_value.clone())?;

        let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}-{:02}-floatnan", current_addr_hex, executor.instruction_counter);
        executor.state.create_or_update_concolic_variable_bool(&result_var_name, result_value.concrete.to_bool(), result_value.symbolic);
    } else {
        return Err("Output varnode not specified for FLOAT_NAN instruction".to_string());
    }

    Ok(())
}


pub fn handle_float_equal(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::FloatEqual || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for FLOAT_EQUAL".to_string());
    }

    log!(executor.state.logger.clone(), "* Fetching floating-point inputs for FLOAT_EQUAL");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;

    let input0_value = f64::from_bits(input0_var.get_concrete_value());
    let input1_value = f64::from_bits(input1_var.get_concrete_value());

    let result_concrete = input0_value == input1_value && !input0_value.is_nan() && !input1_value.is_nan();
    let result_symbolic = Bool::from_bool(executor.context, result_concrete);

    log!(executor.state.logger.clone(), "Result of FLOAT_EQUAL check: {}", result_concrete);

    if let Some(output_varnode) = instruction.output.as_ref() {
        let result_value = ConcolicVar::new_concrete_and_symbolic_bool(
            result_concrete,
            result_symbolic,
            executor.context,
            output_varnode.size.to_bitvector_size() as u32,
        );

        executor.handle_output(Some(output_varnode), result_value.clone())?;

        let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}-{:02}-floateq", current_addr_hex, executor.instruction_counter);
        executor.state.create_or_update_concolic_variable_bool(&result_var_name, result_value.concrete.to_bool(), result_value.symbolic);
    } else {
        return Err("Output varnode not specified for FLOAT_EQUAL instruction".to_string());
    }

    Ok(())
}

pub fn handle_float_less(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::FloatLess || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for FLOAT_LESS".to_string());
    }

    log!(executor.state.logger.clone(), "* Fetching floating-point inputs for FLOAT_LESS");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;

    let input0_value = f64::from_bits(input0_var.get_concrete_value());
    let input1_value = f64::from_bits(input1_var.get_concrete_value());

    let result_concrete = input0_value < input1_value && !input0_value.is_nan() && !input1_value.is_nan();
    let result_symbolic = Bool::from_bool(executor.context, result_concrete);

    log!(executor.state.logger.clone(), "Result of FLOAT_LESS check: {}", result_concrete);

    if let Some(output_varnode) = instruction.output.as_ref() {
        let result_value = ConcolicVar::new_concrete_and_symbolic_bool(
            result_concrete,
            result_symbolic,
            executor.context,
            output_varnode.size.to_bitvector_size() as u32,
        );

        executor.handle_output(Some(output_varnode), result_value.clone())?;

        let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!("{}-{:02}-floatless", current_addr_hex, executor.instruction_counter);
        executor.state.create_or_update_concolic_variable_bool(&result_var_name, result_value.concrete.to_bool(), result_value.symbolic);
    } else {
        return Err("Output varnode not specified for FLOAT_LESS instruction".to_string());
    }

    Ok(())
}
