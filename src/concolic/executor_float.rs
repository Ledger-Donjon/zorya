// SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

use super::ConcreteVar;
/// Focuses on implementing the execution of the FLOAT related opcodes from Ghidra's Pcode specification
/// This implementation relies on Ghidra 11.0.1 with the specfiles in /specfiles
use crate::{
    concolic::{ConcolicEnum, ConcolicVar, SymbolicVar},
    executor::ConcolicExecutor,
};
use parser::parser::{Inst, Opcode};
use std::io::Write;
use z3::ast::{Ast, Bool, BV};

macro_rules! log {
    ($logger:expr, $($arg:tt)*) => {{
        if ($logger).is_enabled() {
        writeln!($logger, $($arg)*).unwrap();
        }
    }};
}

fn build_symbolic_is_nan_32<'ctx>(ctx: &'ctx z3::Context, bv: &BV<'ctx>) -> Bool<'ctx> {
    // If `bv` is 64 bits, extract the lower 32 bits
    let size = bv.get_size();
    let v32 = if size == 32 {
        bv.clone()
    } else if size == 64 {
        bv.extract(31, 0)
    } else {
        return Bool::from_bool(ctx, false);
    };
    let exp = v32.extract(30, 23);
    let frac = v32.extract(22, 0);
    let exp_all_ones = exp._eq(&BV::from_u64(ctx, 0xFF, 8));
    let frac_nonzero = frac._eq(&BV::from_u64(ctx, 0, 23)).not();
    Bool::and(ctx, &[&exp_all_ones, &frac_nonzero])
}

fn build_symbolic_is_nan_64<'ctx>(ctx: &'ctx z3::Context, bv: &BV<'ctx>) -> Bool<'ctx> {
    if bv.get_size() != 64 {
        return Bool::from_bool(ctx, false);
    }
    let exp = bv.extract(62, 52);
    let frac = bv.extract(51, 0);
    let exp_all_ones = exp._eq(&BV::from_u64(ctx, 0x7FF, 11));
    let frac_nonzero = frac._eq(&BV::from_u64(ctx, 0, 52)).not();
    Bool::and(ctx, &[&exp_all_ones, &frac_nonzero])
}

fn check_concrete_is_nan(concrete_u64: u64, bit_size: u32) -> Result<bool, String> {
    match bit_size {
        32 => {
            let val_f32 = f32::from_bits(concrete_u64 as u32);
            Ok(val_f32.is_nan())
        }
        64 => {
            let val_f64 = f64::from_bits(concrete_u64);
            Ok(val_f64.is_nan())
        }
        _ => Err(format!("Unsupported float size = {}", bit_size)),
    }
}

fn check_symbolic_is_nan<'ctx>(
    ctx: &'ctx z3::Context,
    bv: &BV<'ctx>,
    bit_size: u32,
) -> Result<Bool<'ctx>, String> {
    match bit_size {
        32 => Ok(build_symbolic_is_nan_32(ctx, bv)),
        64 => Ok(build_symbolic_is_nan_64(ctx, bv)),
        _ => Err(format!("Unsupported float size = {}", bit_size)),
    }
}

/// The single "does everything" helper for 32/64-bit float checks.
fn float_nan_check_simple<'ctx>(
    ctx: &'ctx z3::Context,
    concrete_val: u64,
    symbolic_bv: &BV<'ctx>,
    size_in_bits: u32,
) -> Result<(bool, Bool<'ctx>), String> {
    let is_nan_concrete = check_concrete_is_nan(concrete_val, size_in_bits)?;
    let is_nan_symbolic = check_symbolic_is_nan(ctx, symbolic_bv, size_in_bits)?;
    Ok((is_nan_concrete, is_nan_symbolic))
}

pub fn handle_float_nan(executor: &mut ConcolicExecutor, inst: Inst) -> Result<(), String> {
    if inst.inputs.len() != 1 {
        return Err("Bad FLOAT_NAN (needs 1 input)".to_string());
    }
    let input_enum = executor.varnode_to_concolic(&inst.inputs[0])?;
    let (res_bool, res_sym) = match input_enum {
        // 1) MemoryValue
        ConcolicEnum::MemoryValue(ref mem) => {
            float_nan_check_simple(executor.context, mem.concrete, &mem.symbolic, mem.size)?
        }
        // 2) CPU-concolic
        ConcolicEnum::CpuConcolicValue(ref cpu) => {
            let concrete_bits = cpu.concrete.to_u64();
            let symbolic_bv = match &cpu.symbolic {
                SymbolicVar::Float(_f) => {
                    // For float NaN detection, we need bit-level operations
                    // Use the concrete bit representation as a BV
                    BV::from_u64(executor.context, concrete_bits, cpu.concrete.get_size())
                }
                _ => cpu.symbolic.to_bv(executor.context),
            };
            let size_bits = cpu.concrete.get_size();
            float_nan_check_simple(executor.context, concrete_bits, &symbolic_bv, size_bits)?
        }
        // 3) ConcolicVar
        ConcolicEnum::ConcolicVar(ref var) => {
            let concrete_bits = var.concrete.to_u64();
            let symbolic_bv = match &var.symbolic {
                SymbolicVar::Float(_f) => {
                    // For float NaN detection, we need bit-level operations
                    // Use the concrete bit representation as a BV
                    BV::from_u64(executor.context, concrete_bits, var.concrete.get_size())
                }
                _ => var.symbolic.to_bv(executor.context),
            };
            let size_bits = var.concrete.get_size();
            float_nan_check_simple(executor.context, concrete_bits, &symbolic_bv, size_bits)?
        }
    };

    // Build a single bool result
    let out_var = inst.output.as_ref().ok_or("No output varnode")?;
    let result_concolic = ConcolicVar {
        concrete: ConcreteVar::Bool(res_bool),
        symbolic: SymbolicVar::Bool(res_sym),
        ctx: executor.context,
    };

    executor.handle_output(Some(out_var), result_concolic.clone())?;
    let name = format!(
        "{:x}-{:02}-floatnan",
        executor.current_address.unwrap_or(0),
        executor.instruction_counter
    );
    executor.state.create_or_update_concolic_variable_bool(
        &name,
        res_bool,
        result_concolic.symbolic,
    );
    Ok(())
}

pub fn handle_float_equal(
    executor: &mut ConcolicExecutor,
    instruction: Inst,
) -> Result<(), String> {
    if instruction.opcode != Opcode::FloatEqual || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for FLOAT_EQUAL".to_string());
    }

    log!(
        executor.state.logger.clone(),
        "* Fetching floating-point inputs for FLOAT_EQUAL"
    );
    let input0_var = executor
        .varnode_to_concolic(&instruction.inputs[0])
        .map_err(|e| e.to_string())?;
    let input1_var = executor
        .varnode_to_concolic(&instruction.inputs[1])
        .map_err(|e| e.to_string())?;

    let input0_value = f64::from_bits(input0_var.get_concrete_value());
    let input1_value = f64::from_bits(input1_var.get_concrete_value());

    let result_concrete =
        input0_value == input1_value && !input0_value.is_nan() && !input1_value.is_nan();
    let result_symbolic = Bool::from_bool(executor.context, result_concrete);

    log!(
        executor.state.logger.clone(),
        "Result of FLOAT_EQUAL check: {}",
        result_concrete
    );

    if let Some(output_varnode) = instruction.output.as_ref() {
        let result_value = ConcolicVar::new_concrete_and_symbolic_bool(
            result_concrete,
            result_symbolic,
            executor.context,
            output_varnode.size.to_bitvector_size(),
        );

        executor.handle_output(Some(output_varnode), result_value.clone())?;

        let current_addr_hex = executor
            .current_address
            .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!(
            "{}-{:02}-floateq",
            current_addr_hex, executor.instruction_counter
        );
        executor.state.create_or_update_concolic_variable_bool(
            &result_var_name,
            result_value.concrete.to_bool(),
            result_value.symbolic,
        );
    } else {
        return Err("Output varnode not specified for FLOAT_EQUAL instruction".to_string());
    }

    Ok(())
}

pub fn handle_float_less(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::FloatLess || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for FLOAT_LESS".to_string());
    }

    log!(
        executor.state.logger.clone(),
        "* Fetching floating-point inputs for FLOAT_LESS"
    );
    let input0_var = executor
        .varnode_to_concolic(&instruction.inputs[0])
        .map_err(|e| e.to_string())?;
    let input1_var = executor
        .varnode_to_concolic(&instruction.inputs[1])
        .map_err(|e| e.to_string())?;

    let input0_value = f64::from_bits(input0_var.get_concrete_value());
    let input1_value = f64::from_bits(input1_var.get_concrete_value());

    let result_concrete =
        input0_value < input1_value && !input0_value.is_nan() && !input1_value.is_nan();
    let result_symbolic = Bool::from_bool(executor.context, result_concrete);

    log!(
        executor.state.logger.clone(),
        "Result of FLOAT_LESS check: {}",
        result_concrete
    );

    if let Some(output_varnode) = instruction.output.as_ref() {
        let result_value = ConcolicVar::new_concrete_and_symbolic_bool(
            result_concrete,
            result_symbolic,
            executor.context,
            output_varnode.size.to_bitvector_size(),
        );

        executor.handle_output(Some(output_varnode), result_value.clone())?;

        let current_addr_hex = executor
            .current_address
            .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
        let result_var_name = format!(
            "{}-{:02}-floatless",
            current_addr_hex, executor.instruction_counter
        );
        executor.state.create_or_update_concolic_variable_bool(
            &result_var_name,
            result_value.concrete.to_bool(),
            result_value.symbolic,
        );
    } else {
        return Err("Output varnode not specified for FLOAT_LESS instruction".to_string());
    }

    Ok(())
}

pub fn handle_float_mult(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::FloatMult || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for FLOAT_MULT".to_string());
    }

    log!(
        executor.state.logger.clone(),
        "* Fetching floating-point inputs for FLOAT_MULT"
    );
    let input0_var = executor
        .varnode_to_concolic(&instruction.inputs[0])
        .map_err(|e| e.to_string())?;
    let input1_var = executor
        .varnode_to_concolic(&instruction.inputs[1])
        .map_err(|e| e.to_string())?;

    // Get the output size to determine if we're working with f32 or f64
    let output_size_bits = instruction
        .output
        .as_ref()
        .ok_or("Output varnode not specified")?
        .size
        .to_bitvector_size();

    // Read the bit patterns and convert to floats
    let input0_bits = input0_var.get_concrete_value();
    let input1_bits = input1_var.get_concrete_value();

    let (result_bits, result_concrete_f64) = if output_size_bits == 32 {
        // 32-bit float (f32) multiplication
        let input0_f32 = f32::from_bits(input0_bits as u32);
        let input1_f32 = f32::from_bits(input1_bits as u32);

        // Check for NaN inputs
        if input0_f32.is_nan() || input1_f32.is_nan() {
            let nan_f32 = f32::NAN;
            (nan_f32.to_bits() as u64, nan_f32 as f64)
        } else {
            let result_f32 = input0_f32 * input1_f32;
            // Check for overflow/underflow resulting in NaN or infinity
            if !result_f32.is_finite() {
                let nan_f32 = f32::NAN;
                (nan_f32.to_bits() as u64, nan_f32 as f64)
            } else {
                (result_f32.to_bits() as u64, result_f32 as f64)
            }
        }
    } else if output_size_bits == 64 {
        // 64-bit float (f64) multiplication
        let input0_f64 = f64::from_bits(input0_bits);
        let input1_f64 = f64::from_bits(input1_bits);

        // Check for NaN inputs
        if input0_f64.is_nan() || input1_f64.is_nan() {
            (f64::NAN.to_bits(), f64::NAN)
        } else {
            let result_f64 = input0_f64 * input1_f64;
            // Check for overflow/underflow resulting in NaN or infinity
            if !result_f64.is_finite() {
                (f64::NAN.to_bits(), f64::NAN)
            } else {
                (result_f64.to_bits(), result_f64)
            }
        }
    } else {
        return Err(format!(
            "Unsupported float size for FLOAT_MULT: {} bits",
            output_size_bits
        ));
    };

    log!(
        executor.state.logger.clone(),
        "*** Result of FLOAT_MULT: {} (bits: 0x{:x})",
        result_concrete_f64,
        result_bits
    );

    // Create symbolic bitvector from the concrete result
    // For now, we use concrete symbolic value since float arithmetic is complex
    let result_symbolic_bv = BV::from_u64(executor.context, result_bits, output_size_bits);

    // Create an integer ConcolicVar with the bit representation
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(
        result_bits,
        result_symbolic_bv,
        executor.context,
    );

    // Handle the result based on the output varnode
    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

    // Log the operation for tracking
    let current_addr_hex = executor
        .current_address
        .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!(
        "{}-{:02}-floatmult",
        current_addr_hex, executor.instruction_counter
    );
    executor.state.create_or_update_concolic_variable_int(
        &result_var_name,
        result_bits,
        result_value.symbolic,
    );

    Ok(())
}

/// TRUNC: Float to Integer conversion (truncate towards zero)
/// Converts a floating-point value to a signed integer by dropping the fractional part
pub fn handle_trunc(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::Trunc || instruction.inputs.len() != 1 {
        return Err("Invalid instruction format for TRUNC".to_string());
    }

    log!(
        executor.state.logger.clone(),
        "* Fetching floating-point input for TRUNC"
    );

    let input_var = executor
        .varnode_to_concolic(&instruction.inputs[0])
        .map_err(|e| e.to_string())?;

    // Get input and output sizes
    let input_size_bits = instruction.inputs[0].size.to_bitvector_size();
    let output_size_bits = instruction
        .output
        .as_ref()
        .ok_or("Output varnode not specified for TRUNC")?
        .size
        .to_bitvector_size();

    // Read the input as bit pattern
    let input_bits = input_var.get_concrete_value();

    // Convert floating-point to integer by truncating
    let result_int = if input_size_bits == 32 {
        // 32-bit float (f32) to integer
        let input_f32 = f32::from_bits(input_bits as u32);

        if input_f32.is_nan() {
            log!(
                executor.state.logger.clone(),
                "TRUNC: Input is NaN, returning 0"
            );
            0i64
        } else if input_f32.is_infinite() {
            log!(
                executor.state.logger.clone(),
                "TRUNC: Input is infinite ({}), clamping to max/min",
                if input_f32.is_sign_positive() {
                    "+inf"
                } else {
                    "-inf"
                }
            );
            // Clamp to output range
            if input_f32.is_sign_positive() {
                match output_size_bits {
                    8 => i8::MAX as i64,
                    16 => i16::MAX as i64,
                    32 => i32::MAX as i64,
                    64 => i64::MAX,
                    _ => i64::MAX,
                }
            } else {
                match output_size_bits {
                    8 => i8::MIN as i64,
                    16 => i16::MIN as i64,
                    32 => i32::MIN as i64,
                    64 => i64::MIN,
                    _ => i64::MIN,
                }
            }
        } else {
            // Normal truncation: round towards zero
            input_f32.trunc() as i64
        }
    } else if input_size_bits == 64 {
        // 64-bit float (f64) to integer
        let input_f64 = f64::from_bits(input_bits);

        if input_f64.is_nan() {
            log!(
                executor.state.logger.clone(),
                "TRUNC: Input is NaN, returning 0"
            );
            0i64
        } else if input_f64.is_infinite() {
            log!(
                executor.state.logger.clone(),
                "TRUNC: Input is infinite ({}), clamping to max/min",
                if input_f64.is_sign_positive() {
                    "+inf"
                } else {
                    "-inf"
                }
            );
            // Clamp to output range
            if input_f64.is_sign_positive() {
                match output_size_bits {
                    8 => i8::MAX as i64,
                    16 => i16::MAX as i64,
                    32 => i32::MAX as i64,
                    64 => i64::MAX,
                    _ => i64::MAX,
                }
            } else {
                match output_size_bits {
                    8 => i8::MIN as i64,
                    16 => i16::MIN as i64,
                    32 => i32::MIN as i64,
                    64 => i64::MIN,
                    _ => i64::MIN,
                }
            }
        } else {
            // Normal truncation: round towards zero
            input_f64.trunc() as i64
        }
    } else {
        return Err(format!(
            "Unsupported input float size for TRUNC: {} bits (expected 32 or 64)",
            input_size_bits
        ));
    };

    // Convert to unsigned representation for the output
    let result_u64 = result_int as u64;

    // Mask the result to fit the output size
    let result_masked = if output_size_bits < 64 {
        result_u64 & ((1u64 << output_size_bits) - 1)
    } else {
        result_u64
    };

    log!(
        executor.state.logger.clone(),
        "*** Result of TRUNC: {} (0x{:x}) -> integer output 0x{:x} ({} bits)",
        if input_size_bits == 32 {
            f32::from_bits(input_bits as u32) as f64
        } else {
            f64::from_bits(input_bits)
        },
        input_bits,
        result_masked,
        output_size_bits
    );

    // Create symbolic bitvector from the concrete result
    // For now, use concrete symbolic value since float-to-int conversion is complex symbolically
    let result_symbolic_bv = BV::from_u64(executor.context, result_masked, output_size_bits);

    // Create an integer ConcolicVar with the truncated result
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(
        result_masked,
        result_symbolic_bv,
        executor.context,
    );

    // Handle the result based on the output varnode
    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

    // Log the operation for tracking
    let current_addr_hex = executor
        .current_address
        .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!(
        "{}-{:02}-trunc",
        current_addr_hex, executor.instruction_counter
    );
    executor.state.create_or_update_concolic_variable_int(
        &result_var_name,
        result_masked,
        result_value.symbolic,
    );

    Ok(())
}
