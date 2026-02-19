// SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

/// Focuses on implementing the execution of the INT related opcodes from Ghidra's Pcode specification
/// This implementation relies on Ghidra 11.0.1 with the specfiles in /specfiles
use crate::concolic::{executor::ConcolicExecutor, SymbolicVar};
use parser::parser::{Inst, Opcode, Var};
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

// Function to handle INT_CARRY instruction
pub fn handle_int_carry(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntCarry || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_CARRY".to_string());
    }

    log!(
        executor.state.logger.clone(),
        "* Fetching instruction.input[0] for INT_CARRY"
    );
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0])?;
    log!(
        executor.state.logger.clone(),
        "* Fetching instruction.input[1] for INT_CARRY"
    );
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1])?;

    let output_varnode = instruction
        .output
        .as_ref()
        .ok_or("Output varnode not specified")?;
    let output_size_bits = output_varnode.size.to_bitvector_size() as u32;
    let bv_size = instruction.inputs[0].size.to_bitvector_size() as u32;

    // Concrete computation explicitly
    let input0_concrete = input0_var.get_concrete_value() as u128;
    let input1_concrete = input1_var.get_concrete_value() as u128;
    let sum_concrete = input0_concrete + input1_concrete;
    let carry_concrete = (sum_concrete >> bv_size) & 1 == 1;

    // Symbolic computation explicitly simplified
    let input0_bv = input0_var
        .get_symbolic_value_bv(executor.context)
        .simplify();
    let input1_bv = input1_var
        .get_symbolic_value_bv(executor.context)
        .simplify();

    let sum_ext = input0_bv
        .zero_ext(1)
        .bvadd(&input1_bv.zero_ext(1))
        .simplify();

    // Extract carry bit clearly, then simplify to avoid unnecessary complexity
    let carry_bv = sum_ext.extract(bv_size, bv_size).simplify();

    let carry_bv_final = if output_size_bits > 1 {
        carry_bv.zero_ext(output_size_bits - 1).simplify()
    } else {
        carry_bv
    };

    // Create concolic variable explicitly
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(
        carry_concrete as u64,
        carry_bv_final,
        executor.context,
    );

    log!(
        executor.state.logger.clone(),
        "*** INT_CARRY concrete result: {}",
        carry_concrete
    );

    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor
        .current_address
        .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!(
        "{}-{:02}-intcarry",
        current_addr_hex, executor.instruction_counter
    );
    executor.state.create_or_update_concolic_variable_int(
        &result_var_name,
        result_value.concrete.to_u64(),
        result_value.symbolic,
    );

    Ok(())
}

pub fn handle_int_scarry(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntSCarry || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_SCARRY".to_string());
    }

    log!(
        executor.state.logger.clone(),
        "* Fetching instruction.input[0] for INT_SCARRY"
    );
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0])?;
    log!(
        executor.state.logger.clone(),
        "* Fetching instruction.input[1] for INT_SCARRY"
    );
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1])?;
    let output_varnode = instruction
        .output
        .as_ref()
        .ok_or("Output varnode not specified")?;
    let output_size_bits = output_varnode.size.to_bitvector_size() as u32;
    log!(
        executor.state.logger.clone(),
        "Output size in bits: {}",
        output_size_bits
    );

    // Explicit symbolic simplification
    let input0_bv = input0_var
        .get_symbolic_value_bv(executor.context)
        .simplify();
    let input1_bv = input1_var
        .get_symbolic_value_bv(executor.context)
        .simplify();

    // Concrete signed addition with overflow
    let input0_concrete = input0_var.get_concrete_value() as i64;
    let input1_concrete = input1_var.get_concrete_value() as i64;
    let (_result_concrete, overflow_concrete) = input0_concrete.overflowing_add(input1_concrete);

    // Symbolic overflow explicitly simplified
    let overflow_symbolic_bool = input0_bv
        .bvadd_no_overflow(&input1_bv, true)
        .not()
        .simplify();

    // Explicitly convert overflow (Bool) into simplified symbolic BV form
    let overflow_bv = overflow_symbolic_bool
        .ite(
            &BV::from_u64(executor.context, 1, output_size_bits),
            &BV::from_u64(executor.context, 0, output_size_bits),
        )
        .simplify();

    // Store overflow explicitly as int (0 or 1)
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(
        overflow_concrete as u64,
        overflow_bv,
        executor.context,
    );

    log!(
        executor.state.logger.clone(),
        "*** INT_SCARRY concrete result: {}",
        overflow_concrete
    );

    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor
        .current_address
        .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!(
        "{}-{:02}-intscarry",
        current_addr_hex, executor.instruction_counter
    );
    executor.state.create_or_update_concolic_variable_int(
        &result_var_name,
        result_value.concrete.to_u64(),
        result_value.symbolic,
    );

    Ok(())
}

pub fn handle_int_add(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntAdd || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_ADD".to_string());
    }

    // Fetch concolic variables
    log!(
        executor.state.logger.clone(),
        "* Fetching instruction.input[0]"
    );
    let input0_var = executor
        .varnode_to_concolic(&instruction.inputs[0])
        .map_err(|e| e.to_string())?;
    log!(
        executor.state.logger.clone(),
        "* Fetching instruction.input[1]"
    );
    let input1_var = executor
        .varnode_to_concolic(&instruction.inputs[1])
        .map_err(|e| e.to_string())?;

    let output_size_bits = instruction
        .output
        .as_ref()
        .unwrap()
        .size
        .to_bitvector_size();
    log!(
        executor.state.logger.clone(),
        "Output size in bits: {}",
        output_size_bits
    );

    // Perform the addition
    // Wrapping is used to handle overflow in Rust
    let result_concrete = input0_var
        .get_concrete_value()
        .wrapping_add(input1_var.get_concrete_value());
    let result_symbolic = input0_var
        .get_symbolic_value_bv(executor.context)
        .bvadd(&input1_var.get_symbolic_value_bv(executor.context));
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(
        result_concrete,
        result_symbolic,
        executor.context,
    );

    log!(
        executor.state.logger.clone(),
        "*** The result of INT_ADD is: {:x}\n",
        result_concrete.clone()
    );

    // Handle the result based on the output varnode
    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor
        .current_address
        .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!(
        "{}-{:02}-intadd",
        current_addr_hex, executor.instruction_counter
    );
    executor.state.create_or_update_concolic_variable_int(
        &result_var_name,
        result_value.concrete.to_u64(),
        result_value.symbolic,
    );

    Ok(())
}

pub fn handle_int_sub(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntSub || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_SUB".to_string());
    }

    // Fetch concolic variables
    log!(
        executor.state.logger.clone(),
        "* Fetching instruction.input[0] for INT_SUB"
    );
    let input0_var = executor
        .varnode_to_concolic(&instruction.inputs[0])
        .map_err(|e| e.to_string())?;
    log!(
        executor.state.logger.clone(),
        "* Fetching instruction.input[1] for INT_SUB"
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

    // Perform the subtraction using signed integers and ensure correct handling of the output size
    let result_concrete = (input0_var.get_concrete_value() as i64)
        .wrapping_sub(input1_var.get_concrete_value() as i64);

    // Truncate the result to fit the output size
    let truncated_result = match output_size_bits {
        32 => result_concrete as i32 as i64, // Handle 32-bit result truncation
        64 => result_concrete,
        _ => result_concrete & ((1 << output_size_bits) - 1),
    };

    let result_symbolic = input0_var
        .get_symbolic_value_bv(executor.context)
        .bvsub(&input1_var.get_symbolic_value_bv(executor.context));
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(
        truncated_result as u64,
        result_symbolic,
        executor.context,
    );

    log!(
        executor.state.logger.clone(),
        "*** The result of INT_SUB is: {:?}\n",
        truncated_result
    );

    // Handle the result based on the output varnode
    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor
        .current_address
        .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!(
        "{}-{:02}-intsub",
        current_addr_hex, executor.instruction_counter
    );
    executor.state.create_or_update_concolic_variable_int(
        &result_var_name,
        result_value.concrete.to_u64(),
        result_value.symbolic,
    );

    Ok(())
}

pub fn handle_int_xor(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntXor || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_XOR".to_string());
    }

    log!(
        executor.state.logger.clone(),
        "* Fetching instruction.input[0] for INT_XOR"
    );
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0])?;
    log!(
        executor.state.logger.clone(),
        "* Fetching instruction.input[1] for INT_XOR"
    );
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1])?;
    log!(
        executor.state.logger.clone(),
        "input0_var: {:?}, input1_var: {:?}",
        input0_var.get_concrete_value(),
        input1_var.get_concrete_value()
    );

    let output_varnode = instruction
        .output
        .as_ref()
        .ok_or("Output varnode not specified")?;

    let output_size_bits = output_varnode.size.to_bitvector_size() as u32;
    log!(
        executor.state.logger.clone(),
        "Output size in bits: {}",
        output_size_bits
    );

    let input0_var = input0_var.to_concolic_var().unwrap();
    let input1_var = input1_var.to_concolic_var().unwrap();

    // Perform the XOR operation
    let result_concrete = input0_var.concrete.to_u64() ^ input1_var.concrete.to_u64();

    // Convert symbolic values to properly sized BVs using the safe helper method
    let input0_bv = input0_var.symbolic.to_bv_with_concrete(
        executor.context,
        input0_var.concrete.to_u64(),
        output_size_bits,
    );

    let input1_bv = input1_var.symbolic.to_bv_with_concrete(
        executor.context,
        input1_var.concrete.to_u64(),
        output_size_bits,
    );

    // Perform BV XOR on properly sized operands
    let result_symbolic = input0_bv.bvxor(&input1_bv);

    // Create the result ConcolicVar
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(
        result_concrete,
        result_symbolic,
        executor.context,
    );

    log!(
        executor.state.logger.clone(),
        "*** The result of INT_XOR is: 0x{:X}",
        result_concrete
    );

    // Handle the result based on the output varnode
    executor.handle_output(Some(output_varnode), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor
        .current_address
        .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!(
        "{}-{:02}-intxor",
        current_addr_hex, executor.instruction_counter
    );
    executor.state.create_or_update_concolic_variable_int(
        &result_var_name,
        result_value.concrete.to_u64(),
        result_value.symbolic,
    );

    Ok(())
}

pub fn handle_int_equal(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntEqual || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_EQUAL".to_string());
    }

    log!(
        executor.state.logger.clone(),
        "=== STARTING INT_EQUAL DEBUG ==="
    );

    // Fetch concolic variables
    log!(
        executor.state.logger.clone(),
        "* Fetching instruction.input[0] for INT_EQUAL"
    );
    let input0_var = executor
        .varnode_to_concolic(&instruction.inputs[0])
        .map_err(|e| e.to_string())?;
    log!(
        executor.state.logger.clone(),
        "* Fetching instruction.input[1] for INT_EQUAL"
    );
    let input1_var = executor
        .varnode_to_concolic(&instruction.inputs[1])
        .map_err(|e| e.to_string())?;

    log!(
        executor.state.logger.clone(),
        "input0_var concrete: {:?}, input1_var concrete: {:?}",
        input0_var.get_concrete_value(),
        input1_var.get_concrete_value()
    );

    // Now check after get_symbolic_value_bv conversion
    log!(
        executor.state.logger.clone(),
        "=== CHECKING AFTER get_symbolic_value_bv ==="
    );
    let input0_bv = input0_var.get_symbolic_value_bv(executor.context);
    let input1_bv = input1_var.get_symbolic_value_bv(executor.context);

    log!(
        executor.state.logger.clone(),
        "input0_bv: {:?}",
        input0_bv.simplify()
    );
    log!(
        executor.state.logger.clone(),
        "input1_bv: {:?}",
        input1_bv.simplify()
    );

    // Check after simplify
    log!(
        executor.state.logger.clone(),
        "=== CHECKING AFTER SIMPLIFY ==="
    );
    let input0_simplified = input0_bv.simplify();
    let input1_simplified = input1_bv.simplify();

    log!(
        executor.state.logger.clone(),
        "input0 simplified: {:?}",
        input0_simplified
    );
    log!(
        executor.state.logger.clone(),
        "input1 simplified: {:?}",
        input1_simplified
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

    // Perform the equality comparison
    let result_concrete = input0_var.get_concrete_value() == input1_var.get_concrete_value();
    log!(
        executor.state.logger.clone(),
        "=== PERFORMING EQUALITY COMPARISON ==="
    );
    log!(
        executor.state.logger.clone(),
        "result_concrete: {}",
        result_concrete
    );

    // Prefer a constant Bool when both operands simplify to numerals to avoid spurious taint
    let result_symbolic =
        if input0_simplified.as_u64().is_some() && input1_simplified.as_u64().is_some() {
            Bool::from_bool(executor.context, result_concrete)
        } else {
            input0_simplified._eq(&input1_simplified)
        };
    log!(
        executor.state.logger.clone(),
        "result_symbolic (Bool): {:?}",
        result_symbolic.simplify()
    );

    log!(
        executor.state.logger.clone(),
        "=== CREATING CONCOLIC VAR ==="
    );
    let result_value = ConcolicVar::new_concrete_and_symbolic_bool(
        result_concrete,
        result_symbolic.clone(),
        executor.context,
        output_size_bits,
    );

    // Check if the created ConcolicVar has ITE
    match &result_value.symbolic {
        SymbolicVar::Bool(b) => {
            log!(
                executor.state.logger.clone(),
                "result_value symbolic (Bool): {:?}",
                b
            );
        }
        SymbolicVar::Int(bv) => {
            log!(
                executor.state.logger.clone(),
                "result_value symbolic (Int): {:?}",
                bv
            );
        }
        _ => {
            log!(
                executor.state.logger.clone(),
                "result_value symbolic (Other): {:?}",
                result_value.symbolic
            );
        }
    }

    log!(
        executor.state.logger.clone(),
        "*** The result of INT_EQUAL is: {:?}",
        result_value.concrete.to_u64()
    );

    log!(
        executor.state.logger.clone(),
        "=== CALLING handle_output ==="
    );
    // Handle the result based on the output varnode
    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

    log!(
        executor.state.logger.clone(),
        "=== AFTER handle_output - CHECKING FINAL REGISTER STATE ==="
    );
    // Check the final register state
    if let Some(output_varnode) = instruction.output.as_ref() {
        if let Var::Register(offset, _) = &output_varnode.var {
            let cpu_state_guard = executor.state.cpu_state.lock().unwrap();
            if let Some(final_register) =
                cpu_state_guard.get_register_by_offset(*offset, output_size_bits)
            {
                log!(
                    executor.state.logger.clone(),
                    "Final register symbolic: {:?}",
                    final_register.symbolic.simplify()
                );
            }
        }
    }

    // Create or update a concolic variable for the result
    let current_addr_hex = executor
        .current_address
        .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!(
        "{}-{:02}-intequal",
        current_addr_hex, executor.instruction_counter
    );
    executor.state.create_or_update_concolic_variable_int(
        &result_var_name,
        result_value.concrete.to_u64(),
        result_value.symbolic,
    );

    log!(executor.state.logger.clone(), "=== END INT_EQUAL DEBUG ===");
    Ok(())
}

pub fn handle_int_notequal(
    executor: &mut ConcolicExecutor,
    instruction: Inst,
) -> Result<(), String> {
    if instruction.opcode != Opcode::IntNotEqual || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_NOTEQUAL".to_string());
    }

    // Fetch concolic variables
    log!(
        executor.state.logger.clone(),
        "* Fetching instruction.input[0] for INT_NOTEQUAL"
    );
    let input0_var = executor
        .varnode_to_concolic(&instruction.inputs[0])
        .map_err(|e| e.to_string())?;
    log!(
        executor.state.logger.clone(),
        "* Fetching instruction.input[1] for INT_NOTEQUAL"
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

    // Perform the inequality comparison
    let result_concrete = input0_var.get_concrete_value() != input1_var.get_concrete_value();
    let bv0 = input0_var
        .get_symbolic_value_bv(executor.context)
        .simplify();
    let bv1 = input1_var
        .get_symbolic_value_bv(executor.context)
        .simplify();
    let result_symbolic_bool = if bv0.as_u64().is_some() && bv1.as_u64().is_some() {
        Bool::from_bool(executor.context, result_concrete)
    } else {
        !bv0._eq(&bv1)
    };

    // Explicitly convert Bool to BV
    let result_symbolic_bv = result_symbolic_bool.ite(
        &BV::from_u64(executor.context, 1, output_size_bits),
        &BV::from_u64(executor.context, 0, output_size_bits),
    );
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(
        result_concrete as u64,
        result_symbolic_bv,
        executor.context,
    );

    log!(
        executor.state.logger.clone(),
        "*** The result of INT_NOTEQUAL is: {:?}\n",
        result_concrete.clone()
    );

    // Handle the result based on the output varnode
    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor
        .current_address
        .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!(
        "{}-{:02}-intnotequal",
        current_addr_hex, executor.instruction_counter
    );
    executor.state.create_or_update_concolic_variable_int(
        &result_var_name,
        result_value.concrete.to_u64(),
        result_value.symbolic,
    );

    Ok(())
}

pub fn handle_int_less(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntLess || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_LESS".to_string());
    }

    log!(
        executor.state.logger.clone(),
        "* Fetching instruction.input[0] for INT_LESS"
    );
    let input0_var = executor
        .varnode_to_concolic(&instruction.inputs[0])
        .map_err(|e| e.to_string())?;
    log!(
        executor.state.logger.clone(),
        "* Fetching instruction.input[1] for INT_LESS"
    );
    let input1_var = executor
        .varnode_to_concolic(&instruction.inputs[1])
        .map_err(|e| e.to_string())?;
    log!(
        executor.state.logger.clone(),
        "input0_var symbolic : {:?}, input1_var symbolic: {:?}",
        input0_var
            .get_symbolic_value_bv(executor.context)
            .simplify(),
        input1_var
            .get_symbolic_value_bv(executor.context)
            .simplify()
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

    // Perform symbolic comparison
    let result_concrete = input0_var.get_concrete_value() < input1_var.get_concrete_value();
    let symbolic_bv0 = input0_var
        .get_symbolic_value_bv(executor.context)
        .simplify();
    let symbolic_bv1 = input1_var
        .get_symbolic_value_bv(executor.context)
        .simplify();
    let result_symbolic_bool = if symbolic_bv0.as_u64().is_some() && symbolic_bv1.as_u64().is_some()
    {
        Bool::from_bool(executor.context, result_concrete)
    } else {
        symbolic_bv0.bvult(&symbolic_bv1)
    };

    log!(
        executor.state.logger.clone(),
        "*** INT_LESS concrete result: {}",
        result_concrete
    );

    let result_value = ConcolicVar::new_concrete_and_symbolic_bool(
        result_concrete,
        result_symbolic_bool,
        executor.context,
        output_size_bits,
    );

    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

    let current_addr_hex = executor
        .current_address
        .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!(
        "{}-{:02}-intless",
        current_addr_hex, executor.instruction_counter
    );
    executor.state.create_or_update_concolic_variable_int(
        &result_var_name,
        result_value.concrete.to_u64(),
        result_value.symbolic.clone(),
    );

    Ok(())
}

pub fn handle_int_sless(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntSLess || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_SLESS".to_string());
    }

    log!(
        executor.state.logger,
        "* Fetching instruction.input[0] for INT_SLESS"
    );

    let input0_var = executor
        .varnode_to_concolic(&instruction.inputs[0])
        .map_err(|e| format!("Failed to convert input[0]: {}", e))?
        .to_concolic_var()
        .unwrap();

    log!(
        executor.state.logger,
        "* Fetching instruction.input[1] for INT_SLESS"
    );

    let input1_var = executor
        .varnode_to_concolic(&instruction.inputs[1])
        .map_err(|e| format!("Failed to convert input[1]: {}", e))?
        .to_concolic_var()
        .unwrap();

    let output_varnode = instruction
        .output
        .as_ref()
        .ok_or("Output varnode not specified")?;
    let output_size_bits = output_varnode.size.to_bitvector_size() as u32;

    log!(
        executor.state.logger,
        "Output size in bits: {}",
        output_size_bits
    );
    log!(
        executor.state.logger,
        "input0_var concrete: {}, input1_var concrete: {}",
        input0_var.concrete.to_u64(),
        input1_var.concrete.to_u64()
    );

    // Get operand widths from symbolic variables
    let input0_bv_raw = input0_var.symbolic.to_bv(executor.context);
    let input1_bv_raw = input1_var.symbolic.to_bv(executor.context);

    let input0_bit_width = input0_bv_raw.get_size();
    let input1_bit_width = input1_bv_raw.get_size();

    log!(
        executor.state.logger,
        "input0 bit width: {}, input1 bit width: {}",
        input0_bit_width,
        input1_bit_width
    );

    // Use a common comparison width independent of the output width
    let cmp_width = std::cmp::max(input0_bit_width, input1_bit_width);

    // Sign-extend inputs to the common comparison width
    let input0_extended = if input0_bit_width < cmp_width {
        log!(
            executor.state.logger,
            "Sign-extending input0 from {} to {} bits for comparison",
            input0_bit_width,
            cmp_width
        );
        sign_extend_concolic_var(executor, input0_var, cmp_width)?
    } else {
        input0_var
    };

    let input1_extended = if input1_bit_width < cmp_width {
        log!(
            executor.state.logger,
            "Sign-extending input1 from {} to {} bits for comparison",
            input1_bit_width,
            cmp_width
        );
        sign_extend_concolic_var(executor, input1_var, cmp_width)?
    } else {
        input1_var
    };

    // Extract correctly sign-extended concrete values
    let input0_concrete = input0_extended
        .get_concrete_value_signed(cmp_width)
        .map_err(|e| format!("Failed to get signed concrete value for input0: {}", e))?;
    let input1_concrete = input1_extended
        .get_concrete_value_signed(cmp_width)
        .map_err(|e| format!("Failed to get signed concrete value for input1: {}", e))?;

    let result_concrete = input0_concrete < input1_concrete;

    log!(
        executor.state.logger,
        "Signed comparison: {} < {} = {}",
        input0_concrete,
        input1_concrete,
        result_concrete
    );

    // Get symbolic BVs for comparison
    let input0_bv = input0_extended.symbolic.to_bv(executor.context);
    let input1_bv = input1_extended.symbolic.to_bv(executor.context);

    // Perform signed less-than comparison
    let result_symbolic = input0_bv.bvslt(&input1_bv);

    log!(
        executor.state.logger,
        "result_concrete: {}",
        result_concrete
    );
    log!(
        executor.state.logger,
        "result_symbolic (Bool): {:?}",
        result_symbolic.simplify()
    );

    // Convert Bool to BV for the required output width (boolean as 0/1 widened)
    let result_symbolic_bv = if output_size_bits == 1 {
        // For 1-bit output, convert bool to 1-bit BV
        result_symbolic.ite(
            &BV::from_u64(executor.context, 1, 1),
            &BV::from_u64(executor.context, 0, 1),
        )
    } else {
        // For larger outputs, zero-extend to required size
        result_symbolic.ite(
            &BV::from_u64(executor.context, 1, output_size_bits),
            &BV::from_u64(executor.context, 0, output_size_bits),
        )
    };

    log!(
        executor.state.logger,
        "result_value symbolic (BV): {:?}",
        result_symbolic_bv.simplify()
    );

    let result_value = ConcolicVar::new_concrete_and_symbolic_int(
        result_concrete as u64,
        result_symbolic_bv.clone(),
        executor.context,
    );

    log!(
        executor.state.logger,
        "*** The result of INT_SLESS is: {}",
        result_concrete as u64
    );

    executor.handle_output(Some(output_varnode), result_value.clone())?;

    // Create or update a concolic variable for tracking
    let current_addr_hex = executor
        .current_address
        .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!(
        "{}-{:02}-intsless",
        current_addr_hex, executor.instruction_counter
    );

    executor.state.create_or_update_concolic_variable_bool(
        &result_var_name,
        result_value.concrete.to_bool(),
        result_value.symbolic,
    );

    Ok(())
}

pub fn handle_int_lessequal(
    executor: &mut ConcolicExecutor,
    instruction: Inst,
) -> Result<(), String> {
    if instruction.opcode != Opcode::IntLessEqual || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_LESSEQUAL".to_string());
    }

    // Fetch concolic variables
    log!(
        executor.state.logger.clone(),
        "* Fetching instruction.input[0] for INT_LESSEQUAL"
    );
    let input0_var = executor
        .varnode_to_concolic(&instruction.inputs[0])
        .map_err(|e| e.to_string())?;
    log!(
        executor.state.logger.clone(),
        "* Fetching instruction.input[1] for INT_LESSEQUAL"
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

    // Perform the unsigned less than or equal comparison
    let result_concrete = input0_var.get_concrete_value() <= input1_var.get_concrete_value();
    let result_symbolic = input0_var
        .get_symbolic_value_bv(executor.context)
        .bvule(&input1_var.get_symbolic_value_bv(executor.context));

    // Explicitly convert Bool to BV
    let result_symbolic_bv = result_symbolic.ite(
        &BV::from_u64(executor.context, 1, output_size_bits),
        &BV::from_u64(executor.context, 0, output_size_bits),
    );
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(
        result_concrete as u64,
        result_symbolic_bv,
        executor.context,
    );

    log!(
        executor.state.logger.clone(),
        "*** The result of INT_LESSEQUAL is: {:?}",
        result_concrete
    );

    // Handle the result based on the output varnode
    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor
        .current_address
        .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!(
        "{}-{:02}-intlessequal",
        current_addr_hex, executor.instruction_counter
    );
    executor.state.create_or_update_concolic_variable_int(
        &result_var_name,
        result_value.concrete.to_u64(),
        result_value.symbolic,
    );

    Ok(())
}

pub fn handle_int_slessequal(
    executor: &mut ConcolicExecutor,
    instruction: Inst,
) -> Result<(), String> {
    if instruction.opcode != Opcode::IntSLessEqual || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_SLESSEQUAL".to_string());
    }

    // Fetch concolic variables
    log!(
        executor.state.logger.clone(),
        "* Fetching instruction.input[0] for INT_SLESSEQUAL"
    );
    let input0_var = executor
        .varnode_to_concolic(&instruction.inputs[0])
        .map_err(|e| e.to_string())?
        .to_concolic_var()
        .unwrap();
    log!(
        executor.state.logger.clone(),
        "* Fetching instruction.input[1] for INT_SLESSEQUAL"
    );
    let input1_var = executor
        .varnode_to_concolic(&instruction.inputs[1])
        .map_err(|e| e.to_string())?
        .to_concolic_var()
        .unwrap();

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

    // Use operand widths, not the output width, for signed comparison
    let in0_bv = input0_var.symbolic.to_bv(executor.context);
    let in1_bv = input1_var.symbolic.to_bv(executor.context);
    let cmp_width = std::cmp::max(in0_bv.get_size(), in1_bv.get_size());

    let in0_ext = if in0_bv.get_size() < cmp_width {
        in0_bv.sign_ext(cmp_width - in0_bv.get_size())
    } else {
        in0_bv
    };
    let in1_ext = if in1_bv.get_size() < cmp_width {
        in1_bv.sign_ext(cmp_width - in1_bv.get_size())
    } else {
        in1_bv
    };

    // Concrete using the declared width
    let c0 = input0_var
        .get_concrete_value_signed(cmp_width)
        .map_err(|e| e.to_string())?;
    let c1 = input1_var
        .get_concrete_value_signed(cmp_width)
        .map_err(|e| e.to_string())?;
    let result_concrete = c0 <= c1;
    let result_symbolic = in0_ext.bvsle(&in1_ext);

    // Explicitly convert Bool to BV
    let result_symbolic_bv = result_symbolic.ite(
        &BV::from_u64(executor.context, 1, output_size_bits),
        &BV::from_u64(executor.context, 0, output_size_bits),
    );
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(
        result_concrete as u64,
        result_symbolic_bv,
        executor.context,
    );

    log!(
        executor.state.logger.clone(),
        "*** The result of INT_SLESSEQUAL is: {:?}\n",
        result_concrete
    );

    // Handle the result based on the output varnode
    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor
        .current_address
        .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!(
        "{}-{:02}-intslessequal",
        current_addr_hex, executor.instruction_counter
    );
    executor.state.create_or_update_concolic_variable_int(
        &result_var_name,
        result_value.concrete.to_u64(),
        result_value.symbolic,
    );

    Ok(())
}

// Handle INT_ZEXT instruction
pub fn handle_int_zext(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntZExt
        || instruction.inputs.len() != 1
        || instruction.output.is_none()
    {
        return Err("Invalid instruction format for INT_ZEXT".to_string());
    }

    log!(
        executor.state.logger.clone(),
        "* Fetching instruction.input[0] for INT_ZEXT"
    );
    let input_var = executor.varnode_to_concolic(&instruction.inputs[0])?;

    let output_varnode = instruction.output.as_ref().unwrap();
    let input_size = instruction.inputs[0].size.to_bitvector_size() as usize;
    let output_size = output_varnode.size.to_bitvector_size() as usize;

    // Build symbolic result depending on size relation
    let symbolic_input_bv = input_var.get_symbolic_value_bv(executor.context);
    let (result_concrete, result_symbolic) = if output_size > input_size {
        // Zero-extend
        let extracted_symbolic = symbolic_input_bv
            .extract((input_size - 1) as u32, 0)
            .simplify();
        let sym = extracted_symbolic
            .zero_ext((output_size - input_size) as u32)
            .simplify();
        let mask = if input_size >= 64 {
            u64::MAX
        } else {
            (1u64 << input_size) - 1
        };
        let conc = input_var.get_concrete_value() & mask;
        (conc, sym)
    } else if output_size == input_size {
        // Pass-through (mask low bits for safety)
        let mask = if output_size >= 64 {
            u64::MAX
        } else {
            (1u64 << output_size) - 1
        };
        let conc = input_var.get_concrete_value() & mask;
        let sym = symbolic_input_bv
            .extract((output_size - 1) as u32, 0)
            .simplify();
        (conc, sym)
    } else {
        // Truncate low bits
        let sym = symbolic_input_bv
            .extract((output_size - 1) as u32, 0)
            .simplify();
        let mask = if output_size >= 64 {
            u64::MAX
        } else {
            (1u64 << output_size) - 1
        };
        let conc = input_var.get_concrete_value() & mask;
        (conc, sym)
    };

    let result_value = ConcolicVar::new_concrete_and_symbolic_int(
        result_concrete,
        result_symbolic.clone(),
        executor.context,
    );

    log!(
        executor.state.logger.clone(),
        "*** INT_ZEXT concrete result: 0x{:x}",
        result_concrete
    );

    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

    let current_addr_hex = executor
        .current_address
        .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!(
        "{}-{:02}-intzext",
        current_addr_hex, executor.instruction_counter
    );
    executor.state.create_or_update_concolic_variable_int(
        &result_var_name,
        result_value.concrete.to_u64(),
        result_value.symbolic,
    );

    Ok(())
}

pub fn handle_int_sext(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntSExt
        || instruction.inputs.len() != 1
        || instruction.output.is_none()
    {
        return Err("Invalid instruction format for INT_SEXT".to_string());
    }

    // Fetch concolic variables
    log!(
        executor.state.logger.clone(),
        "* Fetching instruction.input[0] for INT_SEXT"
    );
    let input_var = executor
        .varnode_to_concolic(&instruction.inputs[0])
        .map_err(|e| e.to_string())?;

    // Ensure output varnode has a larger size than the input
    let output_varnode = instruction.output.as_ref().unwrap();
    if output_varnode.size.to_bitvector_size() <= instruction.inputs[0].size.to_bitvector_size() {
        return Err("Output size must be larger than input size for sign-extension".to_string());
    }

    // Perform the sign-extension
    let input_size = instruction.inputs[0].size.to_bitvector_size() as usize;
    let output_size = output_varnode.size.to_bitvector_size() as usize;
    let input_concrete = input_var.get_concrete_value();

    // Determine the sign bit of the input and create a mask for sign-extension
    let sign_bit = (input_concrete >> (input_size - 1)) & 1;
    let sign_extension = if sign_bit == 1 {
        ((1u64 << (output_size - input_size)) - 1) << input_size // Fill higher bits with 1s if sign bit is 1
    } else {
        0 // Fill higher bits with 0s if sign bit is 0
    };
    let result_concrete = input_concrete | sign_extension;
    let result_symbolic = input_var
        .get_symbolic_value_bv(executor.context)
        .sign_ext((output_size - input_size).try_into().unwrap());

    let result_value = ConcolicVar::new_concrete_and_symbolic_int(
        result_concrete,
        result_symbolic,
        executor.context,
    );

    log!(
        executor.state.logger.clone(),
        "*** The result of INT_SEXT is: 0x{:x}\n",
        result_concrete
    );

    // Handle the result based on the output varnode
    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor
        .current_address
        .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!(
        "{}-{:02}-intsext",
        current_addr_hex, executor.instruction_counter
    );
    executor.state.create_or_update_concolic_variable_int(
        &result_var_name,
        result_value.concrete.to_u64(),
        result_value.symbolic,
    );

    Ok(())
}

pub fn sign_extend_concolic_var<'a, 'ctx>(
    executor: &'a mut ConcolicExecutor<'ctx>,
    var: ConcolicVar<'ctx>,
    target_bit_size: u32,
) -> Result<ConcolicVar<'ctx>, String> {
    let current_bit_size = var.get_size_bits();

    // If already at target size, return as-is
    if current_bit_size == target_bit_size {
        return Ok(var);
    }

    // Prevent invalid sign-extension (e.g., 64-bit -> 8-bit)
    if current_bit_size > target_bit_size {
        return Err(format!(
            "Invalid sign extension: Cannot sign-extend from {} bits to {} bits",
            current_bit_size, target_bit_size
        ));
    }

    // Ensure proper two's complement sign extension
    let concrete_value = var
        .get_concrete_value_signed(current_bit_size)
        .map_err(|e| e.to_string())?;
    let sign_extended_value = if concrete_value < 0 {
        match target_bit_size {
            8 => (concrete_value as i8) as i64,
            16 => (concrete_value as i16) as i64,
            32 => (concrete_value as i32) as i64,
            64 => concrete_value as i64,
            _ => {
                return Err(format!(
                    "Unsupported bit size for sign extension: {}",
                    target_bit_size
                ))
            }
        }
    } else {
        concrete_value // No change if already positive
    };

    // Sign-extend the symbolic value safely using to_bv_with_concrete
    let symbolic_bv =
        var.symbolic
            .to_bv_with_concrete(executor.context, var.concrete.to_u64(), current_bit_size);

    let symbolic_extended = symbolic_bv.sign_ext(target_bit_size - current_bit_size);

    Ok(ConcolicVar::new_concrete_and_symbolic_int(
        sign_extended_value as u64,
        symbolic_extended,
        executor.context,
    ))
}

// INT_SBORROW detects signed integer overflow during subtraction. It returns:
// 1 if (a - b) would cause signed overflow/underflow
// 0 if the subtraction is safe
pub fn handle_int_sborrow(
    executor: &mut ConcolicExecutor,
    instruction: Inst,
) -> Result<(), String> {
    if instruction.opcode != Opcode::IntSBorrow || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_SBORROW".to_string());
    }

    log!(executor.state.logger, "=== STARTING INT_SBORROW DEBUG ===");

    log!(
        executor.state.logger,
        "* Fetching instruction.input[0] for INT_SBORROW"
    );

    let input0_var = executor
        .varnode_to_concolic(&instruction.inputs[0])
        .map_err(|e| format!("Failed to convert input[0]: {}", e))?
        .to_concolic_var()
        .unwrap();

    log!(
        executor.state.logger,
        "* Fetching instruction.input[1] for INT_SBORROW"
    );

    let input1_var = executor
        .varnode_to_concolic(&instruction.inputs[1])
        .map_err(|e| format!("Failed to convert input[1]: {}", e))?
        .to_concolic_var()
        .unwrap();

    let output_varnode = instruction
        .output
        .as_ref()
        .ok_or("Output varnode not specified")?;
    let output_size_bits = output_varnode.size.to_bitvector_size() as u32;

    log!(
        executor.state.logger,
        "Output size in bits: {}",
        output_size_bits
    );
    log!(
        executor.state.logger,
        "input0_var concrete: {}, input1_var concrete: {}",
        input0_var.concrete.to_u64(),
        input1_var.concrete.to_u64()
    );

    // Get input bit widths for proper handling
    let input0_bv = input0_var.symbolic.to_bv(executor.context);
    let input1_bv = input1_var.symbolic.to_bv(executor.context);

    log!(executor.state.logger, "=== AFTER to_bv() CONVERSION ===");
    log!(
        executor.state.logger,
        "input0_bv: {:?}",
        input0_bv.simplify()
    );
    log!(
        executor.state.logger,
        "input1_bv: {:?}",
        input1_bv.simplify()
    );

    let input0_bit_width = input0_bv.get_size();
    let input1_bit_width = input1_bv.get_size();

    log!(
        executor.state.logger,
        "input0 bit width: {}, input1 bit width: {}",
        input0_bit_width,
        input1_bit_width
    );

    // Ensure both inputs have the same bit width (use the larger one)
    let common_bit_width = std::cmp::max(input0_bit_width, input1_bit_width);

    let bv0 = if input0_bit_width < common_bit_width {
        input0_bv.sign_ext(common_bit_width - input0_bit_width)
    } else {
        input0_bv
    };

    let bv1 = if input1_bit_width < common_bit_width {
        input1_bv.sign_ext(common_bit_width - input1_bit_width)
    } else {
        input1_bv
    };

    log!(executor.state.logger, "=== AFTER SIGN EXTENSION ===");
    log!(
        executor.state.logger,
        "bv0 (extended): {:?}",
        bv0.simplify()
    );
    log!(
        executor.state.logger,
        "bv1 (extended): {:?}",
        bv1.simplify()
    );

    // Replace with actual constants if they simplify to numerals
    log!(
        executor.state.logger,
        "=== CONVERTING TO TRUE CONSTANTS IF POSSIBLE ==="
    );

    let bv0 = {
        let simplified = bv0.simplify();
        if let Some(val) = simplified.as_u64() {
            log!(
                executor.state.logger,
                "Converting bv0 to true constant: 0x{:x}",
                val
            );
            BV::from_u64(executor.context, val, common_bit_width)
        } else {
            log!(
                executor.state.logger,
                "bv0 is not a constant, keeping symbolic"
            );
            bv0
        }
    };

    let bv1 = {
        let simplified = bv1.simplify();
        if let Some(val) = simplified.as_u64() {
            log!(
                executor.state.logger,
                "Converting bv1 to true constant: 0x{:x}",
                val
            );
            BV::from_u64(executor.context, val, common_bit_width)
        } else {
            log!(
                executor.state.logger,
                "bv1 is not a constant, keeping symbolic"
            );
            bv1
        }
    };

    // Check if inputs are constants
    log!(
        executor.state.logger,
        "=== CHECKING IF INPUTS ARE CONSTANTS ==="
    );

    let bv0_is_const = bv0.as_u64().is_some();
    let bv1_is_const = bv1.as_u64().is_some();

    log!(executor.state.logger, "bv0.is_numeral(): {}", bv0_is_const);
    log!(executor.state.logger, "bv1.is_numeral(): {}", bv1_is_const);

    if let Some(val) = bv0.as_u64() {
        log!(executor.state.logger, "bv0 is constant: 0x{:x}", val);
    }
    if let Some(val) = bv1.as_u64() {
        log!(executor.state.logger, "bv1 is constant: 0x{:x}", val);
    }

    // Use Z3's built-in signed overflow detection (negated because we want overflow, not no-overflow)
    log!(executor.state.logger, "=== CALLING bvsub_no_overflow ===");

    let no_overflow = bv0.bvsub_no_overflow(&bv1);

    log!(
        executor.state.logger,
        "no_overflow (before NOT): {:?}",
        no_overflow.simplify()
    );

    let borrow_symbolic_bool = no_overflow.not();

    log!(
        executor.state.logger,
        "borrow_symbolic (Bool): {:?}",
        borrow_symbolic_bool.simplify()
    );

    // Convert bool to output-sized bitvector
    let borrow_bv = if output_size_bits == 1 {
        borrow_symbolic_bool.ite(
            &BV::from_u64(executor.context, 1, 1),
            &BV::from_u64(executor.context, 0, 1),
        )
    } else {
        borrow_symbolic_bool.ite(
            &BV::from_u64(executor.context, 1, output_size_bits),
            &BV::from_u64(executor.context, 0, output_size_bits),
        )
    };

    log!(executor.state.logger, "=== AFTER ITE CONVERSION ===");
    log!(
        executor.state.logger,
        "borrow_bv (simplified): {:?}",
        borrow_bv.simplify()
    );

    // Concrete computation - proper signed overflow detection
    let input0_concrete_signed = input0_var
        .get_concrete_value_signed(common_bit_width)
        .map_err(|e| format!("Failed to get signed value for input0: {}", e))?;
    let input1_concrete_signed = input1_var
        .get_concrete_value_signed(common_bit_width)
        .map_err(|e| format!("Failed to get signed value for input1: {}", e))?;

    // Check for signed overflow using Rust's built-in overflow detection
    let (result_concrete, overflow_concrete) =
        input0_concrete_signed.overflowing_sub(input1_concrete_signed);

    log!(executor.state.logger, "=== CONCRETE COMPUTATION ===");
    log!(
        executor.state.logger,
        "Signed subtraction: {} - {} = {} (overflow: {})",
        input0_concrete_signed,
        input1_concrete_signed,
        result_concrete,
        overflow_concrete
    );

    log!(
        executor.state.logger,
        "result_value symbolic (BV): {:?}",
        borrow_bv.simplify()
    );

    let result_value = ConcolicVar::new_concrete_and_symbolic_int(
        overflow_concrete as u64,
        borrow_bv.clone(),
        executor.context,
    );

    log!(executor.state.logger, "=== FINAL RESULT ===");
    log!(
        executor.state.logger,
        "*** The result of INT_SBORROW is: {}",
        overflow_concrete as u64
    );
    log!(
        executor.state.logger,
        "result_value.concrete: {}",
        result_value.concrete.to_u64()
    );

    log!(executor.state.logger, "=== CALLING handle_output ===");
    executor.handle_output(Some(output_varnode), result_value.clone())?;

    // Create tracking variable
    let current_addr_hex = executor
        .current_address
        .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!(
        "{}-{:02}-intsborrow",
        current_addr_hex, executor.instruction_counter
    );

    executor.state.create_or_update_concolic_variable_bool(
        &result_var_name,
        result_value.concrete.to_bool(),
        result_value.symbolic.clone(),
    );

    log!(executor.state.logger, "=== END INT_SBORROW DEBUG ===");
    Ok(())
}

pub fn handle_int_2comp(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::Int2Comp || instruction.inputs.len() != 1 {
        return Err("Invalid instruction format for INT_2COMP".to_string());
    }

    // Fetch concolic variables
    log!(
        executor.state.logger.clone(),
        "* Fetching instruction.input[0] for INT_2COMP"
    );
    let input_var = executor
        .varnode_to_concolic(&instruction.inputs[0])
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

    // Perform the twos complement negation
    let result_concrete = input_var.get_concrete_value().wrapping_neg();
    let result_symbolic = input_var.get_symbolic_value_bv(executor.context).bvneg();
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(
        result_concrete,
        result_symbolic,
        executor.context,
    );

    log!(
        executor.state.logger.clone(),
        "*** The result of INT_2COMP is: {:?}\n",
        result_concrete
    );

    // Handle the result based on the output varnode
    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor
        .current_address
        .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!(
        "{}-{:02}-int2comp",
        current_addr_hex, executor.instruction_counter
    );
    executor.state.create_or_update_concolic_variable_int(
        &result_var_name,
        result_value.concrete.to_u64(),
        result_value.symbolic,
    );

    Ok(())
}

pub fn handle_int_and(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntAnd || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_AND".to_string());
    }

    // Fetch concolic variables
    log!(
        executor.state.logger.clone(),
        "* Fetching instruction.input[0] for INT_AND"
    );
    let input0_var = executor
        .varnode_to_concolic(&instruction.inputs[0])
        .map_err(|e| e.to_string())?;
    log!(
        executor.state.logger.clone(),
        "* Fetching instruction.input[1] for INT_AND"
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

    // Perform the AND operation
    let result_concrete = input0_var.get_concrete_value() & input1_var.get_concrete_value();
    let result_symbolic = input0_var
        .get_symbolic_value_bv(executor.context)
        .bvand(&input1_var.get_symbolic_value_bv(executor.context));
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(
        result_concrete,
        result_symbolic,
        executor.context,
    );

    log!(
        executor.state.logger.clone(),
        "*** The result of INT_AND is: {:?}\n",
        result_concrete
    );

    // Handle the result based on the output varnode
    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor
        .current_address
        .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!(
        "{}-{:02}-intand",
        current_addr_hex, executor.instruction_counter
    );
    executor.state.create_or_update_concolic_variable_int(
        &result_var_name,
        result_value.concrete.to_u64(),
        result_value.symbolic,
    );

    Ok(())
}

pub fn handle_int_or(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntOr || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_OR".to_string());
    }

    // Fetch concolic variables
    log!(
        executor.state.logger.clone(),
        "* Fetching instruction.input[0] for INT_OR"
    );
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0])?;
    log!(
        executor.state.logger.clone(),
        "* Fetching instruction.input[1] for INT_OR"
    );
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1])?;

    let output_varnode = instruction
        .output
        .as_ref()
        .ok_or("Output varnode not specified")?;

    let output_size_bits = output_varnode.size.to_bitvector_size() as u32;
    log!(
        executor.state.logger.clone(),
        "Output size in bits: {}",
        output_size_bits
    );

    let input0_var = input0_var.to_concolic_var().unwrap();
    let input1_var = input1_var.to_concolic_var().unwrap();

    // Perform the OR operation
    let result_concrete = input0_var.concrete.to_u64() | input1_var.concrete.to_u64();

    // Convert symbolic values to properly sized BVs using the safe helper method
    let input0_bv = input0_var.symbolic.to_bv_with_concrete(
        executor.context,
        input0_var.concrete.to_u64(),
        output_size_bits,
    );

    let input1_bv = input1_var.symbolic.to_bv_with_concrete(
        executor.context,
        input1_var.concrete.to_u64(),
        output_size_bits,
    );

    // Perform bitwise OR on properly sized operands
    let result_symbolic = input0_bv.bvor(&input1_bv);

    if result_symbolic.get_size() == 0 {
        return Err("Symbolic value is null".to_string());
    }

    // Create the result ConcolicVar
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(
        result_concrete,
        result_symbolic,
        executor.context,
    );

    log!(
        executor.state.logger.clone(),
        "*** The result of INT_OR is: 0x{:X}",
        result_concrete
    );

    // Handle the result based on the output varnode
    executor.handle_output(Some(output_varnode), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor
        .current_address
        .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!(
        "{}-{:02}-intor",
        current_addr_hex, executor.instruction_counter
    );
    executor.state.create_or_update_concolic_variable_int(
        &result_var_name,
        result_value.concrete.to_u64(),
        result_value.symbolic,
    );

    Ok(())
}

pub fn handle_int_left(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntLeft || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_LEFT".to_string());
    }

    log!(
        executor.state.logger.clone(),
        "* Fetching instruction.input[0] for INT_LEFT"
    );
    let input0_var = executor
        .varnode_to_concolic(&instruction.inputs[0])
        .map_err(|e| e.to_string())?;
    log!(
        executor.state.logger.clone(),
        "* Fetching instruction.input[1] for INT_LEFT"
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

    let input0_var = input0_var.to_concolic_var().unwrap();
    let input1_var = input1_var.to_concolic_var().unwrap();

    let shift_amount = input1_var.concrete.to_u64() as usize;

    // Handle shift amount exceeding bit width
    let result_concrete = if shift_amount >= output_size_bits as usize {
        log!(
            executor.state.logger.clone(),
            "Shift amount {} exceeds bit width {}, setting result to zero",
            shift_amount,
            output_size_bits
        );
        0
    } else {
        input0_var
            .concrete
            .to_u64()
            .wrapping_shl(shift_amount as u32)
    };

    // Convert symbolic values to bitvectors with proper Bool handling
    let input0_symbolic = match &input0_var.symbolic {
        SymbolicVar::Int(bv) => bv.clone(),
        SymbolicVar::Bool(_) => {
            let concrete_bool = input0_var.concrete.to_u64() != 0;
            BV::from_u64(executor.context, concrete_bool as u64, output_size_bits)
        }
        _ => {
            return Err("Unsupported symbolic type for INT_LEFT input0".to_string());
        }
    };

    let input1_symbolic = match &input1_var.symbolic {
        SymbolicVar::Int(bv) => bv.clone(),
        SymbolicVar::Bool(_) => {
            let concrete_bool = input1_var.concrete.to_u64() != 0;
            BV::from_u64(executor.context, concrete_bool as u64, output_size_bits)
        }
        _ => {
            return Err("Unsupported symbolic type for INT_LEFT input1".to_string());
        }
    };

    log!(
        executor.state.logger.clone(),
        "Input0 symbolic size: {}, Input1 symbolic size: {}, Output size: {}",
        input0_symbolic.get_size(),
        input1_symbolic.get_size(),
        output_size_bits
    );

    // Resize operands to match output size requirements
    // Z3 requires both operands of bvshl to have the same bit width
    let sized_input0 = if input0_symbolic.get_size() > output_size_bits {
        input0_symbolic.extract(output_size_bits - 1, 0)
    } else if input0_symbolic.get_size() < output_size_bits {
        input0_symbolic.zero_ext(output_size_bits - input0_symbolic.get_size())
    } else {
        input0_symbolic
    };

    let sized_input1 = if input1_symbolic.get_size() > output_size_bits {
        input1_symbolic.extract(output_size_bits - 1, 0)
    } else if input1_symbolic.get_size() < output_size_bits {
        input1_symbolic.zero_ext(output_size_bits - input1_symbolic.get_size())
    } else {
        input1_symbolic
    };

    // Follow concrete execution path to avoid complex symbolic conditionals
    // This eliminates ite expressions for overflow conditions
    let result_symbolic = if shift_amount >= output_size_bits as usize {
        BV::from_u64(executor.context, 0, output_size_bits)
    } else {
        sized_input0.bvshl(&sized_input1)
    };

    // Verify the result is valid
    if result_symbolic.get_size() == 0 {
        return Err("Failed to create symbolic shift result - null AST".to_string());
    }

    let result_value = ConcolicVar::new_concrete_and_symbolic_int(
        result_concrete,
        result_symbolic,
        executor.context,
    );

    log!(
        executor.state.logger.clone(),
        "*** The result of INT_LEFT is: {:x}",
        result_concrete
    );

    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

    let current_addr_hex = executor
        .current_address
        .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!(
        "{}-{:02}-intleft",
        current_addr_hex, executor.instruction_counter
    );
    executor.state.create_or_update_concolic_variable_int(
        &result_var_name,
        result_value.concrete.to_u64(),
        result_value.symbolic,
    );

    Ok(())
}

pub fn handle_int_right(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntRight || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_RIGHT".to_string());
    }

    log!(
        executor.state.logger.clone(),
        "* Fetching instruction.input[0] for INT_RIGHT"
    );
    let input0_var = executor
        .varnode_to_concolic(&instruction.inputs[0])
        .map_err(|e| e.to_string())?;
    log!(
        executor.state.logger.clone(),
        "* Fetching instruction.input[1] for INT_RIGHT"
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

    // Perform the right shift operation
    let shift_amount = input1_var.get_concrete_value() as u64;

    // Use Z3 BitVector for shifting
    let shift_bv = BV::from_u64(executor.context, shift_amount, output_size_bits);
    let result_symbolic = input0_var
        .get_symbolic_value_bv(executor.context)
        .bvlshr(&shift_bv);

    // Compute concrete value
    let result_concrete = if shift_amount >= output_size_bits as u64 {
        0
    } else {
        input0_var.get_concrete_value() >> shift_amount
    };

    let result_value = ConcolicVar::new_concrete_and_symbolic_int(
        result_concrete,
        result_symbolic,
        executor.context,
    );

    log!(
        executor.state.logger.clone(),
        "*** The result of INT_RIGHT is: {:x}",
        result_concrete
    );

    // Handle the result based on the output varnode
    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

    let current_addr_hex = executor
        .current_address
        .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!(
        "{}-{:02}-intright",
        current_addr_hex, executor.instruction_counter
    );
    executor.state.create_or_update_concolic_variable_int(
        &result_var_name,
        result_value.concrete.to_u64(),
        result_value.symbolic,
    );

    Ok(())
}

pub fn handle_int_sright(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntSRight || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_SRIGHT".to_string());
    }

    // Fetch concolic variables
    log!(
        executor.state.logger.clone(),
        "* Fetching instruction.input[0] for INT_SRIGHT"
    );
    let input0_var = executor
        .varnode_to_concolic(&instruction.inputs[0])
        .map_err(|e| e.to_string())?;
    log!(
        executor.state.logger.clone(),
        "* Fetching instruction.input[1] for INT_SRIGHT"
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

    // Perform the arithmetic right shift operation
    let shift_amount = input1_var.get_concrete_value() as usize;
    let result_concrete = ((input0_var.get_concrete_value() as i64) >> shift_amount) as u64;
    let result_symbolic = input0_var
        .get_symbolic_value_bv(executor.context)
        .bvashr(&BV::from_u64(
            executor.context,
            shift_amount as u64,
            output_size_bits,
        ));

    let result_value = ConcolicVar::new_concrete_and_symbolic_int(
        result_concrete,
        result_symbolic,
        executor.context,
    );

    log!(
        executor.state.logger.clone(),
        "*** The result of INT_SRIGHT is: {:?}\n",
        result_concrete
    );

    // Handle the result based on the output varnode
    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor
        .current_address
        .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!(
        "{}-{:02}-intsright",
        current_addr_hex, executor.instruction_counter
    );
    executor.state.create_or_update_concolic_variable_int(
        &result_var_name,
        result_value.concrete.to_u64(),
        result_value.symbolic,
    );

    Ok(())
}

pub fn handle_int_mult(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntMult || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_MULT".to_string());
    }

    // Fetch concolic variables
    log!(
        executor.state.logger.clone(),
        "* Fetching instruction.input[0] for INT_MULT"
    );
    let input0_var = executor
        .varnode_to_concolic(&instruction.inputs[0])
        .map_err(|e| e.to_string())?;
    log!(
        executor.state.logger.clone(),
        "* Fetching instruction.input[1] for INT_MULT"
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

    // Perform the multiplication
    let result_concrete = input0_var
        .get_concrete_value()
        .wrapping_mul(input1_var.get_concrete_value());
    let result_symbolic = input0_var
        .get_symbolic_value_bv(executor.context)
        .bvmul(&input1_var.get_symbolic_value_bv(executor.context));
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(
        result_concrete,
        result_symbolic,
        executor.context,
    );

    log!(
        executor.state.logger.clone(),
        "*** The result of INT_MULT is: {:?}\n",
        result_concrete
    );

    // Handle the result based on the output varnode
    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor
        .current_address
        .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!(
        "{}-{:02}-intmult",
        current_addr_hex, executor.instruction_counter
    );
    executor.state.create_or_update_concolic_variable_int(
        &result_var_name,
        result_value.concrete.to_u64(),
        result_value.symbolic,
    );

    Ok(())
}

pub fn handle_int_negate(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntNegate || instruction.inputs.len() != 1 {
        return Err("Invalid instruction format for INT_NEGATE".to_string());
    }

    // Fetch the concolic variable for the input
    log!(
        executor.state.logger.clone(),
        "* Fetching instruction.input[0] for INT_NEGATE"
    );
    let input0_var = executor
        .varnode_to_concolic(&instruction.inputs[0])
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

    // Perform the bitwise negation
    let result_concrete = !input0_var.get_concrete_value();
    let result_symbolic = input0_var.get_symbolic_value_bv(executor.context).bvnot();
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(
        result_concrete,
        result_symbolic,
        executor.context,
    );

    log!(
        executor.state.logger.clone(),
        "*** The result of INT_NEGATE is: {:?}\n",
        result_concrete
    );

    // Handle the result based on the output varnode
    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor
        .current_address
        .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!(
        "{}-{:02}-intnegate",
        current_addr_hex, executor.instruction_counter
    );
    executor.state.create_or_update_concolic_variable_int(
        &result_var_name,
        result_value.concrete.to_u64(),
        result_value.symbolic,
    );

    Ok(())
}

pub fn handle_int_div(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntDiv || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_DIV".to_string());
    }

    // Fetch the concolic variables for the inputs
    log!(
        executor.state.logger.clone(),
        "* Fetching instruction.input[0] for INT_DIV"
    );
    let input0_var = executor
        .varnode_to_concolic(&instruction.inputs[0])
        .map_err(|e| e.to_string())?;
    log!(
        executor.state.logger.clone(),
        "* Fetching instruction.input[1] for INT_DIV"
    );
    let input1_var = executor
        .varnode_to_concolic(&instruction.inputs[1])
        .map_err(|e| e.to_string())?;

    // Check for division by zero
    if input1_var.get_concrete_value() == 0 {
        return Err("Division by zero".to_string());
    }

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

    // Perform the division
    let result_concrete = input0_var
        .get_concrete_value()
        .wrapping_div(input1_var.get_concrete_value());
    let result_symbolic = input0_var
        .get_symbolic_value_bv(executor.context)
        .bvudiv(&input1_var.get_symbolic_value_bv(executor.context));
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(
        result_concrete,
        result_symbolic,
        executor.context,
    );

    log!(
        executor.state.logger.clone(),
        "*** The result of INT_DIV is: {:?}\n",
        result_concrete
    );

    // Handle the result based on the output varnode
    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor
        .current_address
        .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!(
        "{}-{:02}-intdiv",
        current_addr_hex, executor.instruction_counter
    );
    executor.state.create_or_update_concolic_variable_int(
        &result_var_name,
        result_value.concrete.to_u64(),
        result_value.symbolic,
    );

    Ok(())
}

pub fn handle_int_rem(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntRem || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_REM".to_string());
    }

    // Fetch the concolic variables for the inputs
    log!(
        executor.state.logger.clone(),
        "* Fetching instruction.input[0] for INT_REM"
    );
    let input0_var = executor
        .varnode_to_concolic(&instruction.inputs[0])
        .map_err(|e| e.to_string())?;
    log!(
        executor.state.logger.clone(),
        "* Fetching instruction.input[1] for INT_REM"
    );
    let input1_var = executor
        .varnode_to_concolic(&instruction.inputs[1])
        .map_err(|e| e.to_string())?;

    // Check for division by zero
    if input1_var.get_concrete_value() == 0 {
        return Err("Division by zero".to_string());
    }

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

    // Perform the remainder operation
    let result_concrete = input0_var.get_concrete_value() % input1_var.get_concrete_value();
    let result_symbolic = input0_var
        .get_symbolic_value_bv(executor.context)
        .bvurem(&input1_var.get_symbolic_value_bv(executor.context));
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(
        result_concrete,
        result_symbolic,
        executor.context,
    );

    log!(
        executor.state.logger.clone(),
        "*** The result of INT_REM is: {:?}\n",
        result_concrete
    );

    // Handle the result based on the output varnode
    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor
        .current_address
        .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!(
        "{}-{:02}-intrem",
        current_addr_hex, executor.instruction_counter
    );
    executor.state.create_or_update_concolic_variable_int(
        &result_var_name,
        result_value.concrete.to_u64(),
        result_value.symbolic,
    );

    Ok(())
}

pub fn handle_int_sdiv(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntSDiv || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_SDIV".to_string());
    }

    // Fetch the concolic variables for the inputs
    log!(
        executor.state.logger.clone(),
        "* Fetching instruction.input[0] for INT_SDIV"
    );
    let input0_var = executor
        .varnode_to_concolic(&instruction.inputs[0])
        .map_err(|e| e.to_string())?;
    log!(
        executor.state.logger.clone(),
        "* Fetching instruction.input[1] for INT_SDIV"
    );
    let input1_var = executor
        .varnode_to_concolic(&instruction.inputs[1])
        .map_err(|e| e.to_string())?;

    // Check for division by zero
    if input1_var.get_concrete_value() == 0 {
        return Err("Division by zero".to_string());
    }

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

    // Perform the signed division
    let result_concrete =
        (input0_var.get_concrete_value() as i64 / input1_var.get_concrete_value() as i64) as u64;
    let result_symbolic = input0_var
        .get_symbolic_value_bv(executor.context)
        .bvsdiv(&input1_var.get_symbolic_value_bv(executor.context));
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(
        result_concrete,
        result_symbolic,
        executor.context,
    );

    log!(
        executor.state.logger.clone(),
        "*** The result of INT_SDIV is: {:?}\n",
        result_concrete
    );

    // Handle the result based on the output varnode
    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor
        .current_address
        .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!(
        "{}-{:02}-intsdiv",
        current_addr_hex, executor.instruction_counter
    );
    executor.state.create_or_update_concolic_variable_int(
        &result_var_name,
        result_value.concrete.to_u64(),
        result_value.symbolic,
    );

    Ok(())
}

pub fn handle_int_srem(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntSRem || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_SREM".to_string());
    }

    // Fetch the concolic variables for the inputs
    log!(
        executor.state.logger.clone(),
        "* Fetching instruction.input[0] for INT_SREM"
    );
    let input0_var = executor
        .varnode_to_concolic(&instruction.inputs[0])
        .map_err(|e| e.to_string())?;
    log!(
        executor.state.logger.clone(),
        "* Fetching instruction.input[1] for INT_SREM"
    );
    let input1_var = executor
        .varnode_to_concolic(&instruction.inputs[1])
        .map_err(|e| e.to_string())?;

    // Check for division by zero
    if input1_var.get_concrete_value() == 0 {
        return Err("Division by zero".to_string());
    }

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

    // Perform the signed remainder operation
    let result_concrete = ((input0_var.get_concrete_value() as i64)
        % (input1_var.get_concrete_value() as i64)) as u64;
    let result_symbolic = input0_var
        .get_symbolic_value_bv(executor.context)
        .bvsrem(&input1_var.get_symbolic_value_bv(executor.context));
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(
        result_concrete,
        result_symbolic,
        executor.context,
    );

    log!(
        executor.state.logger.clone(),
        "*** The result of INT_SREM is: {:?}\n",
        result_concrete
    );

    // Handle the result based on the output varnode
    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor
        .current_address
        .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!(
        "{}-{:02}-intsrem",
        current_addr_hex, executor.instruction_counter
    );
    executor.state.create_or_update_concolic_variable_int(
        &result_var_name,
        result_value.concrete.to_u64(),
        result_value.symbolic,
    );

    Ok(())
}

pub fn handle_int2float(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::Int2Float || instruction.inputs.len() != 1 {
        return Err("Invalid instruction format for INT2FLOAT".to_string());
    }

    // Fetch the concolic variable for the input
    log!(
        executor.state.logger.clone(),
        "* Fetching instruction.input[0] for INT2FLOAT"
    );
    let input0_var = executor
        .varnode_to_concolic(&instruction.inputs[0])
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

    // Perform the conversion
    let result_concrete_float = input0_var.get_concrete_value() as f64; // input is a signed integer

    log!(
        executor.state.logger.clone(),
        "*** The result of INT2FLOAT is: {:?}\n",
        result_concrete_float
    );

    // Convert the float to its IEEE 754 bit representation for storage in registers
    // Floats are stored as bit patterns in registers, not as actual float types
    let result_bits = result_concrete_float.to_bits();

    // For the symbolic part, create a bitvector from the concrete bits
    // This maintains correctness while avoiding complex Z3 FFI
    // The symbolic float-to-bv conversion is handled in SymbolicVar::to_bv if needed later
    let result_symbolic_bv = BV::from_u64(executor.context, result_bits, output_size_bits);

    // Create an integer ConcolicVar with the bit representation
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(
        result_bits,
        result_symbolic_bv,
        executor.context,
    );

    // Handle the result based on the output varnode
    executor.handle_output(instruction.output.as_ref(), result_value)?;

    Ok(())
}
