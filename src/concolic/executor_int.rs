/// Focuses on implementing the execution of the INT related opcodes from Ghidra's Pcode specification
/// This implementation relies on Ghidra 11.0.1 with the specfiles in /specfiles

use crate::concolic::executor::ConcolicExecutor;
use parser::parser::{Inst, Opcode};
use z3::ast::{Ast, Bool, Float, BV};
use std::io::Write;

use super::ConcolicVar;

macro_rules! log {
    ($logger:expr, $($arg:tt)*) => {{
        writeln!($logger, $($arg)*).unwrap();
    }};
}

// Function to handle INT_CARRY instruction
pub fn handle_int_carry(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntCarry || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_CARRY".to_string());
    }

    // Fetch input concolic variables explicitly
    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for INT_CARRY");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0])?;
    log!(executor.state.logger.clone(), "* Fetching instruction.input[1] for INT_CARRY");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1])?;

    // Determine bit sizes explicitly
    let output_varnode = instruction.output.as_ref().ok_or("Output varnode not specified")?;
    let output_size_bits = output_varnode.size.to_bitvector_size() as u32;
    let bv_size = instruction.inputs[0].size.to_bitvector_size() as u32;

    // Concrete computation explicitly
    let input0_concrete = input0_var.get_concrete_value() as u128;
    let input1_concrete = input1_var.get_concrete_value() as u128;
    let sum_concrete = input0_concrete + input1_concrete;
    let carry_concrete = (sum_concrete >> bv_size) & 1 == 1;

    // Symbolic computation explicitly
    let input0_symbolic_ext = input0_var.get_symbolic_value_bv(executor.context).zero_ext(1);
    let input1_symbolic_ext = input1_var.get_symbolic_value_bv(executor.context).zero_ext(1);
    let sum_symbolic_ext = input0_symbolic_ext.bvadd(&input1_symbolic_ext);

    // Explicitly extract carry bit (MSB)
    let carry_symbolic_bv = sum_symbolic_ext.extract(bv_size, bv_size);

    // Explicitly convert carry bit to correct output size
    let carry_symbolic_ext = if output_size_bits > 1 {
        carry_symbolic_bv.zero_ext(output_size_bits - 1)
    } else {
        carry_symbolic_bv
    };

    // Create concolic variable explicitly
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(
        carry_concrete as u64,
        carry_symbolic_ext,
        executor.context,
        output_size_bits,
    );

    log!(executor.state.logger.clone(), "*** The result of INT_CARRY is: {:?}\n", carry_concrete);

    // Handle the result based on the output varnode
    executor.handle_output(instruction.output.as_ref(), result_value)?;

    Ok(())
}
  
pub fn handle_int_scarry(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntSCarry || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_SCARRY".to_string());
    }

    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for INT_SCARRY");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0])?;
    log!(executor.state.logger.clone(), "* Fetching instruction.input[1] for INT_SCARRY");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1])?;
    let output_varnode = instruction.output.as_ref().ok_or("Output varnode not specified")?;
    let output_size_bits = output_varnode.size.to_bitvector_size() as u32;
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    let input0_bv = input0_var.get_symbolic_value_bv(executor.context);
    let input1_bv = input1_var.get_symbolic_value_bv(executor.context);

    // Concrete signed addition
    let input0_concrete = input0_var.get_concrete_value() as i64;
    let input1_concrete = input1_var.get_concrete_value() as i64;
    let (_result_concrete, overflow_concrete) = input0_concrete.overflowing_add(input1_concrete);

    // Correctly check signed addition overflow symbolically
    let overflow_symbolic_bool = input0_bv.bvadd_no_overflow(&input1_bv, true).not();

    // Convert symbolic overflow flag (Bool) explicitly into BV(8) form
    let overflow_bv = overflow_symbolic_bool.ite(
        &BV::from_u64(executor.context, 1, output_size_bits),
        &BV::from_u64(executor.context, 0, output_size_bits),
    );

    // Store overflow explicitly as int (0 or 1)
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(
        overflow_concrete as u64,
        overflow_bv,
        executor.context,
        output_size_bits,
    );

    log!(executor.state.logger.clone(), "*** The result of INT_SCARRY is: {:?}\n", overflow_concrete);

    // Handle the result based on the output varnode
    executor.handle_output(instruction.output.as_ref(), result_value)?;

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

    let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size();
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    // Perform the addition
    // Wrapping is used to handle overflow in Rust
    let result_concrete = input0_var.get_concrete_value().wrapping_add(input1_var.get_concrete_value());
    let result_symbolic = input0_var.get_symbolic_value_bv(executor.context).bvadd(&input1_var.get_symbolic_value_bv(executor.context));
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(result_concrete, result_symbolic, executor.context, output_size_bits);

    log!(executor.state.logger.clone(), "*** The result of INT_ADD is: {:x}\n", result_concrete.clone());

    // Handle the result based on the output varnode
    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intadd", current_addr_hex, executor.instruction_counter);
    executor.state.create_or_update_concolic_variable_int(&result_var_name, result_value.concrete.to_u64(), result_value.symbolic);

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

    let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    // Perform the subtraction using signed integers and ensure correct handling of the output size
    let result_concrete = (input0_var.get_concrete_value() as i64).wrapping_sub(input1_var.get_concrete_value() as i64);

    // Truncate the result to fit the output size
    let truncated_result = match output_size_bits {
        32 => result_concrete as i32 as i64, // Handle 32-bit result truncation
        64 => result_concrete,
        _ => result_concrete & ((1 << output_size_bits) - 1),
    };

    let result_symbolic = input0_var.get_symbolic_value_bv(executor.context).bvsub(&input1_var.get_symbolic_value_bv(executor.context));
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(truncated_result as u64, result_symbolic, executor.context, output_size_bits);

    log!(executor.state.logger.clone(), "*** The result of INT_SUB is: {:?}\n", truncated_result);

    // Handle the result based on the output varnode
    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intsub", current_addr_hex, executor.instruction_counter);
    executor.state.create_or_update_concolic_variable_int(&result_var_name, result_value.concrete.to_u64(), result_value.symbolic);

    Ok(())
}

pub fn handle_int_xor(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntXor || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_XOR".to_string());
    }

    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for INT_XOR");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0])?;
    log!(executor.state.logger.clone(), "* Fetching instruction.input[1] for INT_XOR");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1])?;
    log!(executor.state.logger.clone(), "input0_var: {:?}, input1_var: {:?}", input0_var.get_concrete_value(), input1_var.get_concrete_value());

    let output_varnode = instruction.output.as_ref().ok_or("Output varnode not specified")?;

    let output_size_bits = output_varnode.size.to_bitvector_size() as u32;
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    // Adapt types of input variables (in case of an operation between a Bool (size 1) and an Int (usually size 8))
    let (adapted_input0_var, adapted_input1_var) = 
    if input0_var.is_bool() 
        || input1_var.is_bool() 
        || input0_var.to_concolic_var().unwrap().symbolic.get_size() != output_size_bits 
        || input1_var.to_concolic_var().unwrap().symbolic.get_size() != output_size_bits {
        log!(executor.state.logger.clone(), "Adapting Boolean and Integer types for INT_OR");
        executor.adapt_types(input0_var.clone(), input1_var.clone(), output_size_bits)?
    } else {
        (input0_var, input1_var)
    };

    // Convert ConcolicEnum back to ConcolicVar
    let input0_var = adapted_input0_var.to_concolic_var().unwrap();
    let input1_var = adapted_input1_var.to_concolic_var().unwrap();

    // Fetch symbolic values
    let input0_symbolic = input0_var.symbolic.to_bv(executor.context);
    let input1_symbolic = input1_var.symbolic.to_bv(executor.context);

    // Perform the XOR operation
    let result_concrete = input0_var.concrete.to_u64() ^ input1_var.concrete.to_u64();
    let result_symbolic = input0_symbolic.bvxor(&input1_symbolic);

    // Create the result ConcolicVar
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(
        result_concrete,
        result_symbolic,
        executor.context,
        output_size_bits
    );

    log!(executor.state.logger.clone(), "*** The result of INT_XOR is: 0x{:X}", result_concrete);

    // Handle the result based on the output varnode
    executor.handle_output(Some(output_varnode), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intxor", current_addr_hex, executor.instruction_counter);
    executor.state.create_or_update_concolic_variable_int(&result_var_name, result_value.concrete.to_u64(), result_value.symbolic);

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

    let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    // Perform the equality comparison
    let result_concrete = input0_var.get_concrete_value() == input1_var.get_concrete_value();
    let result_symbolic = input0_var.get_symbolic_value_bv(executor.context)._eq(&input1_var.get_symbolic_value_bv(executor.context));
    
    // Explicitly convert Bool to BV
    let result_symbolic_bv = result_symbolic.ite(
        &BV::from_u64(executor.context, 1, output_size_bits),
        &BV::from_u64(executor.context, 0, output_size_bits),
    );
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(result_concrete as u64, result_symbolic_bv, executor.context, output_size_bits);  

    log!(executor.state.logger.clone(), "*** The result of INT_EQUAL is: {:?}\n", result_value.concrete.to_u64());

    // Handle the result based on the output varnode
    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intequal", current_addr_hex, executor.instruction_counter);
    executor.state.create_or_update_concolic_variable_int(&result_var_name, result_value.concrete.to_u64(), result_value.symbolic);

    Ok(())
}

pub fn handle_int_notequal(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntNotEqual || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_NOTEQUAL".to_string());
    }

    // Fetch concolic variables
    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for INT_NOTEQUAL");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
    log!(executor.state.logger.clone(), "* Fetching instruction.input[1] for INT_NOTEQUAL");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;

    let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    // Perform the inequality comparison
    let result_concrete = input0_var.get_concrete_value() != input1_var.get_concrete_value();
    let result_symbolic = !input0_var.get_symbolic_value_bv(executor.context)._eq(&input1_var.get_symbolic_value_bv(executor.context));
    
    // Explicitly convert Bool to BV
    let result_symbolic_bv = result_symbolic.ite(
        &BV::from_u64(executor.context, 1, output_size_bits),
        &BV::from_u64(executor.context, 0, output_size_bits),
    );
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(result_concrete as u64, result_symbolic_bv, executor.context, output_size_bits);  

    log!(executor.state.logger.clone(), "*** The result of INT_NOTEQUAL is: {:?}\n", result_concrete.clone());

    // Handle the result based on the output varnode
    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intnotequal", current_addr_hex, executor.instruction_counter);
    executor.state.create_or_update_concolic_variable_int(&result_var_name, result_value.concrete.to_u64(), result_value.symbolic);

    Ok(())
}

pub fn handle_int_less(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntLess || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_LESS".to_string());
    }

    // Fetch concolic variables
    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for INT_LESS");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
    log!(executor.state.logger.clone(), "* Fetching instruction.input[1] for INT_LESS");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;

    let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    // Perform the less than comparison
    let result_concrete = input0_var.get_concrete_value() < input1_var.get_concrete_value();
    let result_symbolic = input0_var.get_symbolic_value_bv(executor.context).bvult(&input1_var.get_symbolic_value_bv(executor.context));

    // Explicitly convert Bool to BV
    let result_symbolic_bv = result_symbolic.ite(
        &BV::from_u64(executor.context, 1, output_size_bits),
        &BV::from_u64(executor.context, 0, output_size_bits),
    );
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(result_concrete as u64, result_symbolic_bv, executor.context, output_size_bits);  

    log!(executor.state.logger.clone(), "*** The result of INT_LESS is: {:?}\n", result_concrete.clone());

    // Handle the result based on the output varnode
    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intless", current_addr_hex, executor.instruction_counter);
    executor.state.create_or_update_concolic_variable_int(&result_var_name, result_value.concrete.to_u64(), result_value.symbolic);

    Ok(())
}

pub fn handle_int_sless(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntSLess || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_SLESS".to_string());
    }

    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for INT_SLESS");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0])?;
    log!(executor.state.logger.clone(), "* Fetching instruction.input[1] for INT_SLESS");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1])?;

    let output_varnode = instruction.output.as_ref().ok_or("Output varnode not specified")?;
    let output_size_bits = output_varnode.size.to_bitvector_size() as u32;
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    // Only sign-extend if the bit size is increasing
    let input0_var = if input0_var.to_concolic_var().unwrap().concrete.get_size() < output_size_bits {
        sign_extend_concolic_var(executor, input0_var.clone().to_concolic_var().unwrap(), output_size_bits)?
    } else {
        input0_var.to_concolic_var().unwrap()
    };

    let input1_var = if input1_var.to_concolic_var().unwrap().concrete.get_size() < output_size_bits {
        sign_extend_concolic_var(executor, input1_var.clone().to_concolic_var().unwrap(), output_size_bits)?
    } else {
        input1_var.to_concolic_var().unwrap()
    };

    // Extract correctly sign-extended concrete values
    let input0_concrete = input0_var.get_concrete_value_signed(output_size_bits).map_err(|e| e.to_string())?;
    let input1_concrete = input1_var.get_concrete_value_signed(output_size_bits).map_err(|e| e.to_string())?;
    let result_concrete = input0_concrete < input1_concrete;

    // Symbolic execution: ensure BV representation correctly reflects sign-extension
    let result_symbolic = input0_var.symbolic.to_bv(executor.context).bvslt(&input1_var.symbolic.to_bv(executor.context));

    log!(executor.state.logger.clone(), "*** The result of INT_SLESS is: {:?}", result_concrete);

    // Explicitly convert Bool to BV
    let result_symbolic_bv = result_symbolic.ite(
        &BV::from_u64(executor.context, 1, output_size_bits),
        &BV::from_u64(executor.context, 0, output_size_bits),
    );
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(result_concrete as u64, result_symbolic_bv, executor.context, output_size_bits);  

    executor.handle_output(Some(output_varnode), result_value.clone())?;

    // Create or update a concolic variable for tracking
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intsless", current_addr_hex, executor.instruction_counter);
    executor.state.create_or_update_concolic_variable_bool(&result_var_name, result_value.concrete.to_bool(), result_value.symbolic);

    Ok(())
}


pub fn handle_int_lessequal(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntLessEqual || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_LESSEQUAL".to_string());
    }

    // Fetch concolic variables
    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for INT_LESSEQUAL");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
    log!(executor.state.logger.clone(), "* Fetching instruction.input[1] for INT_LESSEQUAL");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;

    let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    // Perform the unsigned less than or equal comparison
    let result_concrete = input0_var.get_concrete_value() <= input1_var.get_concrete_value();
    let result_symbolic = input0_var.get_symbolic_value_bv(executor.context).bvule(&input1_var.get_symbolic_value_bv(executor.context));
    
    // Explicitly convert Bool to BV
    let result_symbolic_bv = result_symbolic.ite(
        &BV::from_u64(executor.context, 1, output_size_bits),
        &BV::from_u64(executor.context, 0, output_size_bits),
    );
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(result_concrete as u64, result_symbolic_bv, executor.context, output_size_bits);  

    log!(executor.state.logger.clone(), "*** The result of INT_LESSEQUAL is: {:?}", result_concrete);

    // Handle the result based on the output varnode
    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intlessequal", current_addr_hex, executor.instruction_counter);
    executor.state.create_or_update_concolic_variable_int(&result_var_name, result_value.concrete.to_u64(), result_value.symbolic);

    Ok(())
}

pub fn handle_int_slessequal(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntSLessEqual || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_SLESSEQUAL".to_string());
    }

    // Fetch concolic variables
    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for INT_SLESSEQUAL");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
    log!(executor.state.logger.clone(), "* Fetching instruction.input[1] for INT_SLESSEQUAL");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;

    let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    // Perform the signed less than or equal comparison
    let result_concrete = input0_var.get_concrete_value() as i64 <= input1_var.get_concrete_value() as i64;
    let result_symbolic = input0_var.get_symbolic_value_bv(executor.context).bvsle(&input1_var.get_symbolic_value_bv(executor.context));
    
    // Explicitly convert Bool to BV
    let result_symbolic_bv = result_symbolic.ite(
        &BV::from_u64(executor.context, 1, output_size_bits),
        &BV::from_u64(executor.context, 0, output_size_bits),
    );
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(result_concrete as u64, result_symbolic_bv, executor.context, output_size_bits);  

    log!(executor.state.logger.clone(), "*** The result of INT_SLESSEQUAL is: {:?}\n", result_concrete);

    // Handle the result based on the output varnode
    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intslessequal", current_addr_hex, executor.instruction_counter);
    executor.state.create_or_update_concolic_variable_int(&result_var_name, result_value.concrete.to_u64(), result_value.symbolic);

    Ok(())
}

// Handle INT_ZEXT instruction
pub fn handle_int_zext(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntZExt || instruction.inputs.len() != 1 || instruction.output.is_none() {
        return Err("Invalid instruction format for INT_ZEXT".to_string());
    }

    // Fetch concolic variables
    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for INT_ZEXT");
    let input_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;

    // Ensure output varnode has a larger size than the input
    let output_varnode = instruction.output.as_ref().unwrap();
    if output_varnode.size.to_bitvector_size() <= instruction.inputs[0].size.to_bitvector_size() {
        return Err("Output size must be larger than input size for zero-extension".to_string());
    }

    let input_size = instruction.inputs[0].size.to_bitvector_size() as usize;
    let output_size = output_varnode.size.to_bitvector_size() as usize;

    // Safe mask application to avoid shift overflow
    let mask = if input_size >= 64 {
        u64::MAX
    } else {
        (1u64 << input_size) - 1
    };
    let zero_extended_value = input_var.get_concrete_value() & mask;
    let result_symbolic = input_var.get_symbolic_value_bv(executor.context).zero_ext((output_size - input_size) as u32);

    // Ensure the result_symbolic is valid
    if result_symbolic.get_size() == 0 {
        return Err("Zero-extended symbolic value is null".to_string());
    }

    let result_value = ConcolicVar::new_concrete_and_symbolic_int(
        zero_extended_value,
        result_symbolic,
        executor.context,
        output_varnode.size.to_bitvector_size()
    );

    log!(executor.state.logger.clone(), "*** The result of INT_ZEXT is: 0x{:x}\n", zero_extended_value);

    // Handle the result based on the output varnode
    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intzext", current_addr_hex, executor.instruction_counter);
    executor.state.create_or_update_concolic_variable_int(&result_var_name, result_value.concrete.to_u64(), result_value.symbolic);

    Ok(())
}

pub fn handle_int_sext(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntSExt || instruction.inputs.len() != 1 || instruction.output.is_none() {
        return Err("Invalid instruction format for INT_SEXT".to_string());
    }

    // Fetch concolic variables
    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for INT_SEXT");
    let input_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;

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
    let result_symbolic = input_var.get_symbolic_value_bv(executor.context).sign_ext((output_size - input_size).try_into().unwrap());

    let result_value = ConcolicVar::new_concrete_and_symbolic_int(
        result_concrete, 
        result_symbolic, 
        executor.context, 
        output_varnode.size.to_bitvector_size()
    );

    log!(executor.state.logger.clone(), "*** The result of INT_SEXT is: 0x{:x}\n", result_concrete);

    // Handle the result based on the output varnode
    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intsext", current_addr_hex, executor.instruction_counter);
    executor.state.create_or_update_concolic_variable_int(&result_var_name, result_value.concrete.to_u64(), result_value.symbolic);

    Ok(())
}

pub fn sign_extend_concolic_var<'a, 'ctx>(executor: &'a mut ConcolicExecutor<'ctx>, var: ConcolicVar<'ctx>, target_bit_size: u32) -> Result<ConcolicVar<'ctx>, String> {
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
    let concrete_value = var.get_concrete_value_signed(current_bit_size).map_err(|e| e.to_string())?;
    let sign_extended_value = if concrete_value < 0 {
        match target_bit_size {
            8 => (concrete_value as i8) as i64,
            16 => (concrete_value as i16) as i64,
            32 => (concrete_value as i32) as i64,
            64 => concrete_value as i64,
            _ => return Err(format!("Unsupported bit size for sign extension: {}", target_bit_size)),
        }
    } else {
        concrete_value // No change if already positive
    };

    // Sign-extend the symbolic value in Z3
    let symbolic_extended = var.symbolic.to_bv(executor.context).sign_ext(target_bit_size - current_bit_size);

    Ok(ConcolicVar::new_concrete_and_symbolic_int(
        sign_extended_value as u64,
        symbolic_extended,
        executor.context,
        target_bit_size,
    ))
}

pub fn handle_int_sborrow(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntSBorrow || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_SBORROW".to_string());
    }

    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for INT_SBORROW");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0])?;
    log!(executor.state.logger.clone(), "* Fetching instruction.input[1] for INT_SBORROW");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1])?;

    let output_varnode = instruction.output.as_ref().ok_or("Output varnode not specified")?;
    let output_size_bits = output_varnode.size.to_bitvector_size() as u32;

    // Symbolic bitvectors explicitly
    let bv0 = input0_var.get_symbolic_value_bv(executor.context);
    let bv1 = input1_var.get_symbolic_value_bv(executor.context);

    // Correct signed overflow check explicitly:
    let borrow_symbolic_bool = bv0.bvsub_no_overflow(&bv1).not(); // true for signed check

    // Explicitly convert the symbolic bool to a bitvector (0/1)
    let borrow_bv = borrow_symbolic_bool.ite(
        &BV::from_u64(executor.context, 1, output_size_bits),
        &BV::from_u64(executor.context, 0, output_size_bits),
    );

    // Concrete computation explicitly:
    let input0_concrete = input0_var.get_concrete_value_signed().unwrap();
    let input1_concrete = input1_var.get_concrete_value_signed().unwrap();
    let (_, overflow_concrete) = input0_concrete.overflowing_sub(input1_concrete);

    let result_value = ConcolicVar::new_concrete_and_symbolic_int(
        overflow_concrete as u64,
        borrow_bv,
        executor.context,
        output_size_bits,
    );

    executor.handle_output(Some(output_varnode), result_value.clone())?; 

    Ok(())
}

pub fn handle_int_2comp(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::Int2Comp || instruction.inputs.len() != 1 {
        return Err("Invalid instruction format for INT_2COMP".to_string());
    }

    // Fetch concolic variables
    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for INT_2COMP");
    let input_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;

    let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    // Perform the twos complement negation
    let result_concrete = input_var.get_concrete_value().wrapping_neg();
    let result_symbolic = input_var.get_symbolic_value_bv(executor.context).bvneg();
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(result_concrete, result_symbolic, executor.context, output_size_bits);

    log!(executor.state.logger.clone(), "*** The result of INT_2COMP is: {:?}\n", result_concrete);

    // Handle the result based on the output varnode
    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-int2comp", current_addr_hex, executor.instruction_counter);
    executor.state.create_or_update_concolic_variable_int(&result_var_name, result_value.concrete.to_u64(), result_value.symbolic);

    Ok(())
}

pub fn handle_int_and(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntAnd || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_AND".to_string());
    }

    // Fetch concolic variables
    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for INT_AND");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
    log!(executor.state.logger.clone(), "* Fetching instruction.input[1] for INT_AND");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;

    let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    // Adapt types of input variables (in case of an operation between a Bool (size 1) and an Int (usually size 8))
    let (adapted_input0_var, adapted_input1_var) = 
    if input0_var.is_bool() 
        || input1_var.is_bool() 
        || input0_var.to_concolic_var().unwrap().symbolic.get_size() != output_size_bits 
        || input1_var.to_concolic_var().unwrap().symbolic.get_size() != output_size_bits {
        log!(executor.state.logger.clone(), "Adapting Boolean and Integer types for INT_OR");
        executor.adapt_types(input0_var.clone(), input1_var.clone(), output_size_bits)?
    } else {
        (input0_var, input1_var)
    };

    // Perform the AND operation
    let result_concrete = adapted_input0_var.get_concrete_value() & adapted_input1_var.get_concrete_value();
    let result_symbolic = adapted_input0_var.get_symbolic_value_bv(executor.context).bvand(&adapted_input1_var.get_symbolic_value_bv(executor.context));
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(result_concrete, result_symbolic, executor.context, output_size_bits);

    log!(executor.state.logger.clone(), "*** The result of INT_AND is: {:?}\n", result_concrete);

    // Handle the result based on the output varnode
    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intand", current_addr_hex, executor.instruction_counter);
    executor.state.create_or_update_concolic_variable_int(&result_var_name, result_value.concrete.to_u64(), result_value.symbolic);

    Ok(())
}

pub fn handle_int_or(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntOr || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_OR".to_string());
    }

    // Fetch concolic variables
    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for INT_OR");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0])?;
    log!(executor.state.logger.clone(), "* Fetching instruction.input[1] for INT_OR");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1])?;

    let output_varnode = instruction.output.as_ref().ok_or("Output varnode not specified")?;

    let output_size_bits = output_varnode.size.to_bitvector_size() as u32;
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    // Adapt types of input variables (in case of an operation between a Bool (size 1) and an Int (usually size 8))
    let (adapted_input0_var, adapted_input1_var) = 
    if input0_var.is_bool() 
        || input1_var.is_bool() 
        || input0_var.to_concolic_var().unwrap().symbolic.get_size() != output_size_bits 
        || input1_var.to_concolic_var().unwrap().symbolic.get_size() != output_size_bits {
        log!(executor.state.logger.clone(), "Adapting Boolean and Integer types for INT_OR");
        executor.adapt_types(input0_var.clone(), input1_var.clone(), output_size_bits)?
    } else {
        (input0_var, input1_var)
    };

    // Convert ConcolicEnum back to ConcolicVar
    let input0_var = adapted_input0_var.to_concolic_var().unwrap();
    let input1_var = adapted_input1_var.to_concolic_var().unwrap();

    // Fetch symbolic values
    let input0_symbolic = input0_var.symbolic.to_bv(executor.context);
    let input1_symbolic = input1_var.symbolic.to_bv(executor.context);


    // Perform the OR operation
    let result_concrete = input0_var.concrete.to_u64() | input1_var.concrete.to_u64();
    let result_symbolic = input0_symbolic.bvor(&input1_symbolic);

    if result_symbolic.get_size() == 0 {
        return Err("Symbolic value is null".to_string());
    }

    // Create the result ConcolicVar
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(result_concrete, result_symbolic, executor.context, output_size_bits);

    log!(executor.state.logger.clone(), "*** The result of INT_OR is: 0x{:X}", result_concrete);

    // Handle the result based on the output varnode
    executor.handle_output(Some(output_varnode), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intor", current_addr_hex, executor.instruction_counter);
    executor.state.create_or_update_concolic_variable_int(&result_var_name, result_value.concrete.to_u64(), result_value.symbolic);

    Ok(())
}

pub fn handle_int_left(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntLeft || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_LEFT".to_string());
    }

    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for INT_LEFT");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
    log!(executor.state.logger.clone(), "* Fetching instruction.input[1] for INT_LEFT");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;

    let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    // Adapt input types if necessary
    let (adapted_input0_var, adapted_input1_var) = if input1_var.to_concolic_var().unwrap().symbolic.get_size() != output_size_bits {
        log!(executor.state.logger.clone(), "Adapting types for INT_LEFT");
        executor.adapt_types(input0_var.clone(), input1_var.clone(), output_size_bits)?
    } else {
        (input0_var, input1_var)
    };

    let input0_var = adapted_input0_var.to_concolic_var().unwrap();
    let input1_var = adapted_input1_var.to_concolic_var().unwrap();

    let shift_amount = input1_var.concrete.to_u64() as usize;

    // Handle shift amount exceeding bit width
    let result_concrete = if shift_amount >= output_size_bits as usize {
        log!(executor.state.logger.clone(), "Shift amount {} exceeds bit width {}, setting result to zero", shift_amount, output_size_bits);
        0
    } else {
        input0_var.concrete.to_u64().wrapping_shl(shift_amount as u32)
    };

    let shift_bv = input1_var.symbolic.to_bv(executor.context);

    let shift_limit = BV::from_u64(executor.context, output_size_bits as u64, shift_bv.get_size());
    let condition = shift_bv.bvuge(&shift_limit);

    let zero_bv = BV::from_u64(executor.context, 0, output_size_bits);
    let shifted_bv = input0_var.symbolic.to_bv(executor.context).bvshl(&shift_bv);

    let result_symbolic = condition.ite(&zero_bv, &shifted_bv);

    let result_value = ConcolicVar::new_concrete_and_symbolic_int(result_concrete, result_symbolic, executor.context, output_size_bits); 

    log!(executor.state.logger.clone(), "*** The result of INT_LEFT is: {:x}", result_concrete);

    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intleft", current_addr_hex, executor.instruction_counter);
    executor.state.create_or_update_concolic_variable_int(&result_var_name, result_value.concrete.to_u64(), result_value.symbolic);

    Ok(())
}

pub fn handle_int_right(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntRight || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_RIGHT".to_string());
    }

    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for INT_RIGHT");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
    log!(executor.state.logger.clone(), "* Fetching instruction.input[1] for INT_RIGHT");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;

    let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    // Perform the right shift operation
    let shift_amount = input1_var.get_concrete_value() as u64;

    // Use Z3 BitVector for shifting
    let shift_bv = BV::from_u64(executor.context, shift_amount, output_size_bits);
    let result_symbolic = input0_var.get_symbolic_value_bv(executor.context).bvlshr(&shift_bv);

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
        output_size_bits,
    );

    log!(executor.state.logger.clone(), "*** The result of INT_RIGHT is: {:x}", result_concrete);

    // Handle the result based on the output varnode
    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

    let current_addr_hex = executor
        .current_address
        .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intright", current_addr_hex, executor.instruction_counter);
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
    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for INT_SRIGHT");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
    log!(executor.state.logger.clone(), "* Fetching instruction.input[1] for INT_SRIGHT");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;

    let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    // Perform the arithmetic right shift operation
    let shift_amount = input1_var.get_concrete_value() as usize;
    let result_concrete = ((input0_var.get_concrete_value() as i64) >> shift_amount) as u64;
    let result_symbolic = input0_var.get_symbolic_value_bv(executor.context).bvashr(&BV::from_u64(executor.context, shift_amount as u64, output_size_bits));

    let result_value = ConcolicVar::new_concrete_and_symbolic_int(result_concrete, result_symbolic, executor.context, output_size_bits);

    log!(executor.state.logger.clone(), "*** The result of INT_SRIGHT is: {:?}\n", result_concrete);

    // Handle the result based on the output varnode
    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intsright", current_addr_hex, executor.instruction_counter);
    executor.state.create_or_update_concolic_variable_int(&result_var_name, result_value.concrete.to_u64(), result_value.symbolic);

    Ok(())
}

pub fn handle_int_mult(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntMult || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_MULT".to_string());
    }

    // Fetch concolic variables
    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for INT_MULT");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
    log!(executor.state.logger.clone(), "* Fetching instruction.input[1] for INT_MULT");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;

    let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    // Adapt types of input variables (in case of an operation between a Bool (size 1) and an Int (usually size 8))
    let (adapted_input0_var, adapted_input1_var) = 
    if input0_var.is_bool() 
        || input1_var.is_bool() 
        || input0_var.to_concolic_var().unwrap().symbolic.get_size() != output_size_bits 
        || input1_var.to_concolic_var().unwrap().symbolic.get_size() != output_size_bits {
        log!(executor.state.logger.clone(), "Adapting Boolean and Integer types for INT_OR");
        executor.adapt_types(input0_var.clone(), input1_var.clone(), output_size_bits)?
    } else {
        (input0_var, input1_var)
    };

    // Perform the multiplication
    let result_concrete = adapted_input0_var.get_concrete_value().wrapping_mul(adapted_input1_var.get_concrete_value());
    let result_symbolic = adapted_input0_var.get_symbolic_value_bv(executor.context).bvmul(&adapted_input1_var.get_symbolic_value_bv(executor.context));
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(result_concrete, result_symbolic, executor.context, output_size_bits);

    log!(executor.state.logger.clone(), "*** The result of INT_MULT is: {:?}\n", result_concrete);

    // Handle the result based on the output varnode
    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intmult", current_addr_hex, executor.instruction_counter);
    executor.state.create_or_update_concolic_variable_int(&result_var_name, result_value.concrete.to_u64(), result_value.symbolic);

    Ok(())
}

pub fn handle_int_negate(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntNegate || instruction.inputs.len() != 1 {
        return Err("Invalid instruction format for INT_NEGATE".to_string());
    }

    // Fetch the concolic variable for the input
    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for INT_NEGATE");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;

    let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    // Perform the bitwise negation
    let result_concrete = !input0_var.get_concrete_value();
    let result_symbolic = input0_var.get_symbolic_value_bv(executor.context).bvnot();
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(result_concrete, result_symbolic, executor.context, output_size_bits);

    log!(executor.state.logger.clone(), "*** The result of INT_NEGATE is: {:?}\n", result_concrete);

    // Handle the result based on the output varnode
    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intnegate", current_addr_hex, executor.instruction_counter);
    executor.state.create_or_update_concolic_variable_int(&result_var_name, result_value.concrete.to_u64(), result_value.symbolic);

    Ok(())
}

pub fn handle_int_div(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntDiv || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_DIV".to_string());
    }

    // Fetch the concolic variables for the inputs
    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for INT_DIV");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
    log!(executor.state.logger.clone(), "* Fetching instruction.input[1] for INT_DIV");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;

    // Check for division by zero
    if input1_var.get_concrete_value() == 0 {
        return Err("Division by zero".to_string());
    }

    let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    // Perform the division
    let result_concrete = input0_var.get_concrete_value().wrapping_div(input1_var.get_concrete_value());
    let result_symbolic = input0_var.get_symbolic_value_bv(executor.context).bvudiv(&input1_var.get_symbolic_value_bv(executor.context));
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(result_concrete, result_symbolic, executor.context, output_size_bits);

    log!(executor.state.logger.clone(), "*** The result of INT_DIV is: {:?}\n", result_concrete);

    // Handle the result based on the output varnode
    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intdiv", current_addr_hex, executor.instruction_counter);
    executor.state.create_or_update_concolic_variable_int(&result_var_name, result_value.concrete.to_u64(), result_value.symbolic);

    Ok(())
}

pub fn handle_int_rem(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntRem || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_REM".to_string());
    }

    // Fetch the concolic variables for the inputs
    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for INT_REM");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
    log!(executor.state.logger.clone(), "* Fetching instruction.input[1] for INT_REM");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;

    // Check for division by zero
    if input1_var.get_concrete_value() == 0 {
        return Err("Division by zero".to_string());
    }

    let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    // Perform the remainder operation
    let result_concrete = input0_var.get_concrete_value() % input1_var.get_concrete_value();
    let result_symbolic = input0_var.get_symbolic_value_bv(executor.context).bvurem(&input1_var.get_symbolic_value_bv(executor.context));
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(result_concrete, result_symbolic, executor.context, output_size_bits);

    log!(executor.state.logger.clone(), "*** The result of INT_REM is: {:?}\n", result_concrete);

    // Handle the result based on the output varnode
    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intrem", current_addr_hex, executor.instruction_counter);
    executor.state.create_or_update_concolic_variable_int(&result_var_name, result_value.concrete.to_u64(), result_value.symbolic);

    Ok(())
}

pub fn handle_int_sdiv(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntSDiv || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_SDIV".to_string());
    }

    // Fetch the concolic variables for the inputs
    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for INT_SDIV");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
    log!(executor.state.logger.clone(), "* Fetching instruction.input[1] for INT_SDIV");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;

    // Check for division by zero
    if input1_var.get_concrete_value() == 0 {
        return Err("Division by zero".to_string());
    }

    let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    // Perform the signed division
    let result_concrete = (input0_var.get_concrete_value() as i64 / input1_var.get_concrete_value() as i64) as u64;
    let result_symbolic = input0_var.get_symbolic_value_bv(executor.context).bvsdiv(&input1_var.get_symbolic_value_bv(executor.context));
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(result_concrete, result_symbolic, executor.context, output_size_bits);

    log!(executor.state.logger.clone(), "*** The result of INT_SDIV is: {:?}\n", result_concrete);

    // Handle the result based on the output varnode
    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intsdiv", current_addr_hex, executor.instruction_counter);
    executor.state.create_or_update_concolic_variable_int(&result_var_name, result_value.concrete.to_u64(), result_value.symbolic);

    Ok(())
}

pub fn handle_int_srem(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntSRem || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_SREM".to_string());
    }

    // Fetch the concolic variables for the inputs
    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for INT_SREM");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
    log!(executor.state.logger.clone(), "* Fetching instruction.input[1] for INT_SREM");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;

    // Check for division by zero
    if input1_var.get_concrete_value() == 0 {
        return Err("Division by zero".to_string());
    }

    let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    // Perform the signed remainder operation
    let result_concrete = ((input0_var.get_concrete_value() as i64) % (input1_var.get_concrete_value() as i64)) as u64;
    let result_symbolic = input0_var.get_symbolic_value_bv(executor.context).bvsrem(&input1_var.get_symbolic_value_bv(executor.context));
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(result_concrete, result_symbolic, executor.context, output_size_bits);

    log!(executor.state.logger.clone(), "*** The result of INT_SREM is: {:?}\n", result_concrete);

    // Handle the result based on the output varnode
    executor.handle_output(instruction.output.as_ref(), result_value.clone())?;

    // Create or update a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intsrem", current_addr_hex, executor.instruction_counter);
    executor.state.create_or_update_concolic_variable_int(&result_var_name, result_value.concrete.to_u64(), result_value.symbolic);

    Ok(())
}

pub fn handle_int2float(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::Int2Float || instruction.inputs.len() != 1 {
        return Err("Invalid instruction format for INT2FLOAT".to_string());
    }

    // Fetch the concolic variable for the input
    log!(executor.state.logger.clone(), "* Fetching instruction.input[0] for INT2FLOAT");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;

    let output_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
    log!(executor.state.logger.clone(), "Output size in bits: {}", output_size_bits);

    // Perform the conversion
    let result_concrete = input0_var.get_concrete_value() as f64; // input is a signed integer
    let result_symbolic = Float::from_f64(&executor.context, result_concrete);

    let result_value = ConcolicVar::new_concrete_and_symbolic_float(result_concrete, result_symbolic, executor.context, output_size_bits);

    log!(executor.state.logger.clone(), "*** The result of INT2FLOAT is: {:?}\n", result_concrete);

    // Handle the result based on the output varnode
    executor.handle_output(instruction.output.as_ref(), result_value)?;

    Ok(())
}
