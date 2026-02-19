// SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

/// Focuses on implementing the execution of the BOOL related opcodes from Ghidra's Pcode specification
/// This implementation relies on Ghidra 11.0.1 with the specfiles in /specfiles
use crate::concolic::executor::ConcolicExecutor;
use crate::concolic::SymbolicVar;
use parser::parser::{Inst, Opcode};
use std::io::Write;
use z3::ast::{Ast, Bool, BV};

use super::ConcolicVar;

macro_rules! log {
    ($logger:expr, $($arg:tt)*) => {{
        if ($logger).is_enabled() {
            writeln!($logger, $($arg)*).unwrap();
        }
    }};
}

// Handle the BOOL_AND instruction
pub fn handle_bool_and(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::BoolAnd || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for BOOL_AND".to_string());
    }

    log!(
        executor.state.logger.clone(),
        "* Fetching instruction.input[0] for BOOL_AND"
    );
    let input0_var = executor
        .varnode_to_concolic(&instruction.inputs[0])
        .map_err(|e| e.to_string())?;

    log!(
        executor.state.logger.clone(),
        "* Fetching instruction.input[1] for BOOL_AND"
    );
    let input1_var = executor
        .varnode_to_concolic(&instruction.inputs[1])
        .map_err(|e| e.to_string())?;

    let output_size_bits = instruction
        .output
        .as_ref()
        .unwrap()
        .size
        .to_bitvector_size() as u32;
    log!(
        executor.state.logger.clone(),
        "Output size in bits: {}",
        output_size_bits
    );

    let input0_concolic = input0_var.to_concolic_var().unwrap();
    let input1_concolic = input1_var.to_concolic_var().unwrap();

    // Perform logical AND concretely
    let result_concrete =
        input0_var.get_concrete_value() != 0 && input1_var.get_concrete_value() != 0;

    // Create symbolic result that preserves symbolic information
    let result_symbolic_bv = match (&input0_concolic.symbolic, &input1_concolic.symbolic) {
        (SymbolicVar::Bool(bool0), SymbolicVar::Bool(bool1)) => {
            // Both Bool: use direct boolean AND
            let result_bool = Bool::and(executor.context, &[bool0, bool1]);
            result_bool.ite(
                &BV::from_u64(executor.context, 1, output_size_bits),
                &BV::from_u64(executor.context, 0, output_size_bits),
            )
        }
        _ => {
            // Mixed or BV types: convert to boolean conditions preserving symbolic info
            let bool0 = match &input0_concolic.symbolic {
                SymbolicVar::Bool(b) => b.clone(),
                SymbolicVar::Int(bv) => {
                    let zero_bv = BV::from_u64(executor.context, 0, bv.get_size());
                    bv._eq(&zero_bv).not()
                }
                _ => {
                    // Fallback to concrete for unsupported types
                    let concrete_bool = input0_concolic.concrete.to_u64() != 0;
                    if concrete_bool {
                        Bool::from_bool(executor.context, true)
                    } else {
                        Bool::from_bool(executor.context, false)
                    }
                }
            };

            let bool1 = match &input1_concolic.symbolic {
                SymbolicVar::Bool(b) => b.clone(),
                SymbolicVar::Int(bv) => {
                    let zero_bv = BV::from_u64(executor.context, 0, bv.get_size());
                    bv._eq(&zero_bv).not()
                }
                _ => {
                    let concrete_bool = input1_concolic.concrete.to_u64() != 0;
                    if concrete_bool {
                        Bool::from_bool(executor.context, true)
                    } else {
                        Bool::from_bool(executor.context, false)
                    }
                }
            };

            let result_bool = Bool::and(executor.context, &[&bool0, &bool1]);
            result_bool.ite(
                &BV::from_u64(executor.context, 1, output_size_bits),
                &BV::from_u64(executor.context, 0, output_size_bits),
            )
        }
    };

    let result_value = ConcolicVar::new_concrete_and_symbolic_int(
        result_concrete as u64,
        result_symbolic_bv,
        executor.context,
    );

    log!(
        executor.state.logger.clone(),
        "*** The result of BOOL_AND is: {:?}\n",
        result_concrete
    );

    executor.handle_output(instruction.output.as_ref(), result_value)?;

    Ok(())
}

// Handle the BOOL_NEGATE instruction
pub fn handle_bool_negate(
    executor: &mut ConcolicExecutor,
    instruction: Inst,
) -> Result<(), String> {
    if instruction.opcode != Opcode::BoolNegate || instruction.inputs.len() != 1 {
        return Err("Invalid instruction format for BOOL_NEGATE".to_string());
    }

    log!(
        executor.state.logger.clone(),
        "* Fetching instruction.input[0] for BOOL_NEGATE"
    );
    let input0_var = executor
        .varnode_to_concolic(&instruction.inputs[0])
        .map_err(|e| e.to_string())?;

    let input0_concolic = input0_var.to_concolic_var().unwrap();

    log!(
        executor.state.logger.clone(),
        "Input0 symbolic: {:?}",
        input0_concolic.symbolic.simplify()
    );

    let output_size_bits = instruction
        .output
        .as_ref()
        .unwrap()
        .size
        .to_bitvector_size() as u32;
    log!(
        executor.state.logger.clone(),
        "Output size in bits: {}",
        output_size_bits
    );

    // Perform boolean negation using concrete value
    let result_concrete = input0_var.get_concrete_value() == 0;

    // Create symbolic result that preserves the input's symbolic information
    let result_symbolic_bv = match &input0_concolic.symbolic {
        SymbolicVar::Int(bv) => {
            // For BV input, check if it's zero and negate that condition
            let zero_bv = BV::from_u64(executor.context, 0, bv.get_size());
            let is_zero = bv._eq(&zero_bv); // This preserves the symbolic relationship

            // Convert boolean result to BV using ite to preserve symbolic info
            is_zero.ite(
                &BV::from_u64(executor.context, 1, output_size_bits), // input was zero, result is 1
                &BV::from_u64(executor.context, 0, output_size_bits), // input was non-zero, result is 0
            )
        }
        SymbolicVar::Bool(bool_expr) => {
            // For Bool input, directly negate the boolean expression
            let negated_bool = bool_expr.not();

            // Convert to BV using ite to preserve symbolic info
            negated_bool.ite(
                &BV::from_u64(executor.context, 1, output_size_bits),
                &BV::from_u64(executor.context, 0, output_size_bits),
            )
        }
        _ => {
            // For other types, fall back to concrete-based result
            // This preserves the existing behavior for unsupported types
            if result_concrete {
                BV::from_u64(executor.context, 1, output_size_bits)
            } else {
                BV::from_u64(executor.context, 0, output_size_bits)
            }
        }
    };

    let result_value = ConcolicVar::new_concrete_and_symbolic_int(
        result_concrete as u64,
        result_symbolic_bv,
        executor.context,
    );

    log!(
        executor.state.logger.clone(),
        "*** The result of BOOL_NEGATE is: {:?}\n",
        result_concrete
    );

    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

    Ok(())
}

// Handle the BOOL_OR instruction
pub fn handle_bool_or(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::BoolOr || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for BOOL_OR".to_string());
    }

    log!(
        executor.state.logger.clone(),
        "* Fetching instruction.input[0] for BOOL_OR"
    );
    let input0_var = executor
        .varnode_to_concolic(&instruction.inputs[0])
        .map_err(|e| e.to_string())?;
    log!(
        executor.state.logger.clone(),
        "* Fetching instruction.input[1] for BOOL_OR"
    );
    let input1_var = executor
        .varnode_to_concolic(&instruction.inputs[1])
        .map_err(|e| e.to_string())?;

    let output_size_bits = instruction
        .output
        .as_ref()
        .unwrap()
        .size
        .to_bitvector_size() as u32;
    log!(
        executor.state.logger.clone(),
        "Output size in bits: {}",
        output_size_bits
    );

    let input0_concolic = input0_var.to_concolic_var().unwrap();
    let input1_concolic = input1_var.to_concolic_var().unwrap();

    let result_concrete =
        input0_var.get_concrete_value() != 0 || input1_var.get_concrete_value() != 0;

    // Create symbolic result that preserves symbolic information
    let result_symbolic_bv = match (&input0_concolic.symbolic, &input1_concolic.symbolic) {
        (SymbolicVar::Bool(bool0), SymbolicVar::Bool(bool1)) => {
            // Both Bool: use direct boolean OR
            let result_bool = Bool::or(executor.context, &[bool0, bool1]);
            result_bool.ite(
                &BV::from_u64(executor.context, 1, output_size_bits),
                &BV::from_u64(executor.context, 0, output_size_bits),
            )
        }
        _ => {
            // Mixed or BV types: convert to boolean conditions preserving symbolic info
            let bool0 = match &input0_concolic.symbolic {
                SymbolicVar::Bool(b) => b.clone(),
                SymbolicVar::Int(bv) => {
                    let zero_bv = BV::from_u64(executor.context, 0, bv.get_size());
                    bv._eq(&zero_bv).not()
                }
                _ => {
                    let concrete_bool = input0_concolic.concrete.to_u64() != 0;
                    if concrete_bool {
                        Bool::from_bool(executor.context, true)
                    } else {
                        Bool::from_bool(executor.context, false)
                    }
                }
            };

            let bool1 = match &input1_concolic.symbolic {
                SymbolicVar::Bool(b) => b.clone(),
                SymbolicVar::Int(bv) => {
                    let zero_bv = BV::from_u64(executor.context, 0, bv.get_size());
                    bv._eq(&zero_bv).not()
                }
                _ => {
                    let concrete_bool = input1_concolic.concrete.to_u64() != 0;
                    if concrete_bool {
                        Bool::from_bool(executor.context, true)
                    } else {
                        Bool::from_bool(executor.context, false)
                    }
                }
            };

            let result_bool = Bool::or(executor.context, &[&bool0, &bool1]);
            result_bool.ite(
                &BV::from_u64(executor.context, 1, output_size_bits),
                &BV::from_u64(executor.context, 0, output_size_bits),
            )
        }
    };

    let result_value = ConcolicVar::new_concrete_and_symbolic_int(
        result_concrete as u64,
        result_symbolic_bv,
        executor.context,
    );

    log!(
        executor.state.logger.clone(),
        "*** The result of BOOL_OR is: {:?}\n",
        result_concrete
    );

    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

    Ok(())
}

// Handle the BOOL_XOR instruction
pub fn handle_bool_xor(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::BoolXor || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for BOOL_XOR".to_string());
    }

    log!(
        executor.state.logger.clone(),
        "* Fetching instruction.input[0] for BOOL_XOR"
    );
    let input0_var = executor
        .varnode_to_concolic(&instruction.inputs[0])
        .map_err(|e| e.to_string())?;
    log!(
        executor.state.logger.clone(),
        "* Fetching instruction.input[1] for BOOL_XOR"
    );
    let input1_var = executor
        .varnode_to_concolic(&instruction.inputs[1])
        .map_err(|e| e.to_string())?;

    let output_size_bits = instruction
        .output
        .as_ref()
        .unwrap()
        .size
        .to_bitvector_size() as u32;
    log!(
        executor.state.logger.clone(),
        "Output size in bits: {}",
        output_size_bits
    );

    let input0_concolic = input0_var.to_concolic_var().unwrap();
    let input1_concolic = input1_var.to_concolic_var().unwrap();

    let result_concrete =
        (input0_var.get_concrete_value() != 0) ^ (input1_var.get_concrete_value() != 0);

    // Create symbolic result that preserves symbolic information
    let result_symbolic_bv = match (&input0_concolic.symbolic, &input1_concolic.symbolic) {
        (SymbolicVar::Bool(bool0), SymbolicVar::Bool(bool1)) => {
            // Both Bool: use direct boolean XOR
            let result_bool = bool0.xor(bool1);
            result_bool.ite(
                &BV::from_u64(executor.context, 1, output_size_bits),
                &BV::from_u64(executor.context, 0, output_size_bits),
            )
        }
        _ => {
            // Mixed or BV types: convert to boolean conditions preserving symbolic info
            let bool0 = match &input0_concolic.symbolic {
                SymbolicVar::Bool(b) => b.clone(),
                SymbolicVar::Int(bv) => {
                    let zero_bv = BV::from_u64(executor.context, 0, bv.get_size());
                    bv._eq(&zero_bv).not()
                }
                _ => {
                    let concrete_bool = input0_concolic.concrete.to_u64() != 0;
                    if concrete_bool {
                        Bool::from_bool(executor.context, true)
                    } else {
                        Bool::from_bool(executor.context, false)
                    }
                }
            };

            let bool1 = match &input1_concolic.symbolic {
                SymbolicVar::Bool(b) => b.clone(),
                SymbolicVar::Int(bv) => {
                    let zero_bv = BV::from_u64(executor.context, 0, bv.get_size());
                    bv._eq(&zero_bv).not()
                }
                _ => {
                    let concrete_bool = input1_concolic.concrete.to_u64() != 0;
                    if concrete_bool {
                        Bool::from_bool(executor.context, true)
                    } else {
                        Bool::from_bool(executor.context, false)
                    }
                }
            };

            let result_bool = bool0.xor(&bool1);
            result_bool.ite(
                &BV::from_u64(executor.context, 1, output_size_bits),
                &BV::from_u64(executor.context, 0, output_size_bits),
            )
        }
    };

    let result_value = ConcolicVar::new_concrete_and_symbolic_int(
        result_concrete as u64,
        result_symbolic_bv,
        executor.context,
    );

    log!(
        executor.state.logger.clone(),
        "*** The result of BOOL_XOR is: {:?}\n",
        result_concrete
    );

    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

    Ok(())
}
