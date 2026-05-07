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
    let varnode_size_bits = inst.inputs[0].size.to_bitvector_size();
    let input_enum = executor.varnode_to_concolic(&inst.inputs[0])?;
    let (res_bool, res_sym) = match input_enum {
        // 1) MemoryValue
        ConcolicEnum::MemoryValue(ref mem) => float_nan_check_simple(
            executor.context,
            mem.concrete,
            &mem.symbolic,
            varnode_size_bits,
        )?,
        // 2) CPU-concolic
        ConcolicEnum::CpuConcolicValue(ref cpu) => {
            let concrete_bits = cpu.concrete.to_u64();
            let symbolic_bv = match &cpu.symbolic {
                SymbolicVar::Float(_f) => {
                    BV::from_u64(executor.context, concrete_bits, varnode_size_bits)
                }
                _ => cpu.symbolic.to_bv(executor.context),
            };
            float_nan_check_simple(
                executor.context,
                concrete_bits,
                &symbolic_bv,
                varnode_size_bits,
            )?
        }
        // 3) ConcolicVar
        ConcolicEnum::ConcolicVar(ref var) => {
            let concrete_bits = var.concrete.to_u64();
            let symbolic_bv = match &var.symbolic {
                SymbolicVar::Float(_f) => {
                    BV::from_u64(executor.context, concrete_bits, varnode_size_bits)
                }
                _ => var.symbolic.to_bv(executor.context),
            };
            float_nan_check_simple(
                executor.context,
                concrete_bits,
                &symbolic_bv,
                varnode_size_bits,
            )?
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
    let input_size_bits = instruction.inputs[0].size.to_bitvector_size();
    let input0_var = executor
        .varnode_to_concolic(&instruction.inputs[0])
        .map_err(|e| e.to_string())?;
    let input1_var = executor
        .varnode_to_concolic(&instruction.inputs[1])
        .map_err(|e| e.to_string())?;

    let input0_bits = input0_var.get_concrete_value();
    let input1_bits = input1_var.get_concrete_value();

    let result_concrete = if input_size_bits == 32 {
        let v0 = f32::from_bits(input0_bits as u32);
        let v1 = f32::from_bits(input1_bits as u32);
        v0 == v1 && !v0.is_nan() && !v1.is_nan()
    } else {
        let v0 = f64::from_bits(input0_bits);
        let v1 = f64::from_bits(input1_bits);
        v0 == v1 && !v0.is_nan() && !v1.is_nan()
    };
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
    let input_size_bits = instruction.inputs[0].size.to_bitvector_size();
    let input0_var = executor
        .varnode_to_concolic(&instruction.inputs[0])
        .map_err(|e| e.to_string())?;
    let input1_var = executor
        .varnode_to_concolic(&instruction.inputs[1])
        .map_err(|e| e.to_string())?;

    let input0_bits = input0_var.get_concrete_value();
    let input1_bits = input1_var.get_concrete_value();

    let result_concrete = if input_size_bits == 32 {
        let v0 = f32::from_bits(input0_bits as u32);
        let v1 = f32::from_bits(input1_bits as u32);
        v0 < v1 && !v0.is_nan() && !v1.is_nan()
    } else {
        let v0 = f64::from_bits(input0_bits);
        let v1 = f64::from_bits(input1_bits);
        v0 < v1 && !v0.is_nan() && !v1.is_nan()
    };
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
/// Symbolic oracle for float-to-int truncation overflow.
///
/// Inspects the IEEE-754 fields of the symbolic input directly (the codebase
/// stores floats as their bit pattern in BVs — see `to_bv` in `symbolic_var.rs`)
/// and asks Z3 whether there is a model where the float input is NaN, ±Inf,
/// or has a magnitude that does not fit in a signed N-bit destination, under
/// the current path constraints.
///
/// Gating mirrors the INT_MULT / INT_ADD overflow oracles:
///   * the symbolic input must not be a Z3 numeral constant,
///   * at least one tracked function-mode argument must appear in the
///     symbolic expression of the input,
///   * destination width must be 8/16/32/64 bits and source must be 32/64.
fn try_check_trunc_overflow<'ctx>(
    executor: &mut ConcolicExecutor<'ctx>,
    input_var: &ConcolicEnum<'ctx>,
    input_size_bits: u32,
    output_size_bits: u32,
) {
    if executor.function_symbolic_arguments.is_empty() {
        return;
    }
    if input_size_bits != 32 && input_size_bits != 64 {
        return;
    }
    if !matches!(output_size_bits, 8 | 16 | 32 | 64) {
        return;
    }

    let ctx = executor.context;
    let input_bv_full = input_var.get_symbolic_value_bv(ctx);
    // Skip if the input is just a Z3 numeral constant — overflow is then
    // a fixed property and there is nothing to solve for.
    if input_bv_full.as_u64().is_some() {
        return;
    }

    // The BV may be wider than the float (e.g. 80 or 128 bits when read
    // from a register slot).  Take the low `input_size_bits` for the
    // IEEE-754 layout.
    let input_bv = if input_bv_full.get_size() == input_size_bits {
        input_bv_full.clone()
    } else if input_bv_full.get_size() > input_size_bits {
        input_bv_full.extract(input_size_bits - 1, 0)
    } else {
        // Source narrower than declared float width — bail out, this
        // would not be a real cvttsd2si lowering.
        return;
    };

    let expr = format!("{:?}", input_bv);
    let source_lang = std::env::var("SOURCE_LANG").unwrap_or_else(|_| "go".to_string());
    let involves_tracked = executor
        .function_symbolic_arguments
        .iter()
        .any(|(_, sym_var)| {
            if let SymbolicVar::Int(bv) = sym_var {
                let z3_name = format!("{:?}", bv);
                if source_lang == "c" {
                    expr.contains(&z3_name)
                } else {
                    let is_pointer_metadata =
                        z3_name.contains("__ptr") || z3_name.contains("__cap");
                    !is_pointer_metadata && expr.contains(&z3_name)
                }
            } else {
                false
            }
        });
    if !involves_tracked {
        return;
    }

    // IEEE-754 field layout for the input float.
    let (exp_high, exp_low, frac_high, frac_low, exp_bits, exp_all_ones, bias_plus_n_minus_1) = {
        let n_minus_1 = (output_size_bits as i64) - 1;
        match input_size_bits {
            32 => {
                let bias: i64 = 127;
                (
                    30u32,
                    23u32,
                    22u32,
                    0u32,
                    8u32,
                    0xFFu64,
                    (bias + n_minus_1) as u64,
                )
            }
            64 => {
                let bias: i64 = 1023;
                (
                    62u32,
                    52u32,
                    51u32,
                    0u32,
                    11u32,
                    0x7FFu64,
                    (bias + n_minus_1) as u64,
                )
            }
            _ => return,
        }
    };

    let exp = input_bv.extract(exp_high, exp_low);
    let frac = input_bv.extract(frac_high, frac_low);

    let exp_all_ones_bv = BV::from_u64(ctx, exp_all_ones, exp_bits);
    let frac_zero = frac._eq(&BV::from_u64(ctx, 0, frac.get_size()));
    let exp_is_max = exp._eq(&exp_all_ones_bv);

    // NaN: exp == all-ones AND frac != 0
    let is_nan = Bool::and(ctx, &[&exp_is_max, &frac_zero.clone().not()]);
    // ±Inf: exp == all-ones AND frac == 0
    let is_inf = Bool::and(ctx, &[&exp_is_max, &frac_zero]);
    // |v| ≥ 2^(N-1) iff exp ≥ bias + (N-1)  (also catches all-ones)
    let threshold_bv = BV::from_u64(ctx, bias_plus_n_minus_1, exp_bits);
    let too_large = exp.bvuge(&threshold_bv);

    let overflow_condition = Bool::or(ctx, &[&is_nan, &is_inf, &too_large]);

    log!(
        executor.state.logger.clone(),
        "[OVERFLOW-CHECK] Checking for float-to-int truncation overflow at 0x{:x} (f{} → i{})",
        executor.current_address.unwrap_or(0),
        input_size_bits,
        output_size_bits
    );

    let solver = z3::Solver::new(ctx);
    solver.assert(&overflow_condition);
    for constraint in &executor.constraint_vector {
        solver.assert(constraint);
    }

    let solve_start = std::time::Instant::now();
    let solve_result = solver.check();
    let solve_elapsed = solve_start.elapsed();
    crate::Z3_CUMULATIVE_MS.fetch_add(
        solve_elapsed.as_millis() as u64,
        std::sync::atomic::Ordering::Relaxed,
    );

    log!(
        executor.state.logger.clone(),
        "[Z3-SOLVER] Float-to-int overflow check at TRUNC took {:.3}s (result: {:?})",
        solve_elapsed.as_secs_f64(),
        solve_result
    );

    if solve_result != z3::SatResult::Sat {
        return;
    }

    eprintln!(
        "[Z3-SOLVER] Float-to-int overflow check took {:.3}s",
        solve_elapsed.as_secs_f64()
    );

    log!(executor.state.logger.clone(), "~~~~~~~~~~~");
    log!(
        executor.state.logger.clone(),
        "SATISFIABLE: Float-to-int truncation overflow detected — \
         f{} input can be NaN / ±Inf / |v| ≥ 2^{} so the i{} cast is \
         implementation-defined (silent integrity bug, no Go panic)",
        input_size_bits,
        output_size_bits.saturating_sub(1),
        output_size_bits
    );
    log!(executor.state.logger.clone(), "~~~~~~~~~~~");

    let model = match solver.get_model() {
        Some(m) => m,
        None => return,
    };
    let addr = executor.current_address.unwrap_or(0);

    let evaluation_content =
        crate::state::evaluate_z3::build_unified_evaluation_content(&model, executor, None, None);

    for line in evaluation_content.lines() {
        log!(executor.state.logger.clone(), "{}", line);
    }

    let elapsed = Some(crate::state::evaluate_z3::get_elapsed_since_start());
    let detection_method = if executor.is_overlay_mode() {
        "Exploring the not taken path with Overlay Execution"
    } else {
        "Float-to-int truncation overflow: input float can be NaN/±Inf or |v| ≥ 2^(N-1) for the destination integer width"
    };
    if let Err(e) = crate::state::evaluate_z3::log_sat_state_to_file_and_terminal(
        &evaluation_content,
        &std::env::var("MODE").unwrap_or_else(|_| "unknown".to_string()),
        Some(addr),
        elapsed,
        Some(addr),
        Some("TRUNC"),
        Some(detection_method),
    ) {
        log!(
            executor.state.logger.clone(),
            "WARNING: Failed to write trunc-overflow SAT state to file: {}",
            e
        );
    }

    let det_line = format!("Detection method: {}", detection_method);
    crate::state::evaluate_z3::report_vulnerability(
        &mut executor.state.logger.clone(),
        "Float-to-int truncation overflow",
        addr,
        &[
            "Opcode: TRUNC",
            &det_line,
            &format!(
                "f{} input can be NaN / ±Inf / |v| ≥ 2^{} so the i{} cast is implementation-defined",
                input_size_bits,
                output_size_bits.saturating_sub(1),
                output_size_bits
            ),
            "More details in: results/FOUND_SAT_STATE.txt",
        ],
    );
}

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

    // ── Float-to-int truncation overflow check ─────────────────────────
    // TRUNC lifts cvttsd2si/cvttss2si — the float-to-signed-int conversion
    // When the source is NaN / ±Inf / out of the destination integer range,
    // x86 returns the "integer indefinite" pattern (0x80…0) and Go does NOT
    // raise any runtime check.
    //
    // The oracle parses the IEEE-754 exponent/fraction fields of the
    // symbolic input bit-pattern and asks Z3 whether there is a model
    // such that:
    //    v is NaN ∨ v is ±Inf ∨ |v| ≥ 2^(N-1)
    // where N = output_size_bits, under the accumulated path constraints.
    try_check_trunc_overflow(executor, &input_var, input_size_bits, output_size_bits);
    // ── End float-to-int overflow check ────────────────────────────────

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
