/// Focuses on implementing the execution of the INT related opcodes from Ghidra's Pcode specification
/// This implementation relies on Ghidra 11.0.1 with the specfiles in /specfiles

use crate::{concolic::ConcolicEnum, executor::ConcolicExecutor};
use parser::parser::{Inst, Opcode, Size, Var};
use ethnum::I256;

use super::{ConcolicVar, ConcreteVar};

pub fn handle_int_carry(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Ensure the correct instruction format
    if instruction.opcode != Opcode::IntCarry || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_CARRY".to_string());
    }

    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    if output_varnode.size != Size::Byte {
        return Err("Output varnode size must be 1 (Byte) for INT_CARRY".to_string());
    }

    let input0 = &instruction.inputs[0];
    let input1 = &instruction.inputs[1];

    if input0.size != input1.size {
        return Err("Inputs must be the same size for INT_CARRY".to_string());
    }

    let value0 = executor.initialize_var_if_absent(&instruction.inputs[0])?;
    let value1 = executor.initialize_var_if_absent(&instruction.inputs[1])?;

    // Ensure that the values are treated as u32
    let value0_u32 = value0 as u32;
    let value1_u32 = value1 as u32;

    // Check for carry for u32 values. The sum is cast to u64 to avoid overflow
    let carry = (value0_u32 as u64 + value1_u32 as u64) > 0xFFFFFFFF;

    // Convert the carry to f64 representation (0.0 for false, 1.0 for true)
    let carry_as_u64 = if carry { 1 } else { 0 };

    // Store the result of the carry condition
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    let bitvector_size = output_varnode.size.to_bitvector_size();
    executor.state.create_concolic_var_int(&result_var_name, carry_as_u64, bitvector_size);

    Ok(())
}   
  
pub fn handle_int_scarry(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Ensure the correct instruction format
    if instruction.opcode != Opcode::IntSCarry || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_SCARRY".to_string());
    }

    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    if output_varnode.size != Size::Byte {
        return Err("Output varnode size must be 1 (Byte) for INT_SCARRY".to_string());
    }

    let input0 = &instruction.inputs[0];
    let input1 = &instruction.inputs[1];

    if input0.size != input1.size {
        return Err("Inputs must be the same size for INT_SCARRY".to_string());
    }

    let value0 = executor.initialize_var_if_absent(input0)?;
    let value1 = executor.initialize_var_if_absent(input1)?;

    // Calculate signed overflow
    let overflow_occurred = match input0.size {
        Size::QuadQuad => {
            let value0_i256 = I256::from(value0); // Convert to I256
            let value1_i256 = I256::from(value1);
            value0_i256.checked_add(value1_i256).is_none()
        },
        Size::DoubleQuad => {
            let value0_i128 = value0 as i128;
            let value1_i128 = value1 as i128;
            value0_i128.checked_add(value1_i128).is_none()
        },
        Size::Quad => {
            let value0_i64 = value0 as i64;
            let value1_i64 = value1 as i64;
            value0_i64.checked_add(value1_i64).is_none()
        },
        Size::Word => {
            let value0_i32 = value0 as i32;
            let value1_i32 = value1 as i32;
            value0_i32.checked_add(value1_i32).is_none()
        },
        Size::Half => {
            let value0_i16 = value0 as i16;
            let value1_i16 = value1 as i16;
            value0_i16.checked_add(value1_i16).is_none()
        },
        Size::Byte => {
            let value0_i8 = value0 as i8;
            let value1_i8 = value1 as i8;
            value0_i8.checked_add(value1_i8).is_none()
        },
    };

    // Store the result of the signed overflow condition
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    let overflow_occurred_as_int = if overflow_occurred { 1 } else { 0 };
    executor.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(overflow_occurred_as_int, &result_var_name, executor.context, 1));

    Ok(())
}

pub fn handle_int_add(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntAdd || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_ADD".to_string());
    }

    // Fetch concolic variables
    println!("* Fetching instruction.input[0]");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
    println!("* Fetching instruction.input[1]");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;

    // Perform the addition
    let result_value = input0_var.concolic_add(input1_var).map_err(|e| e.to_string())?;
    println!("*** The result of INT_ADD is: {:?}\n", result_value.clone());

    match instruction.output.as_ref().map(|v| &v.var) {
        Some(Var::Unique(id)) => {
            // Check and convert result_value to ConcolicVar
            let concolic_var = match result_value.clone() {
                ConcolicEnum::ConcolicVar(var) => var,
                ConcolicEnum::CpuConcolicValue(cpu_var) => {
                    // Convert CpuConcolicValue to ConcolicVar
                    ConcolicVar::new_concrete_and_symbolic_int(
                        cpu_var.concrete.to_u64(), 
                        &cpu_var.symbolic.to_str(), 
                        cpu_var.ctx, 
                        cpu_var.get_size()
                    )
                },
                ConcolicEnum::MemoryConcolicValue(mem_var) => {
                    // Convert MemoryConcolicValue to ConcolicVar
                    ConcolicVar::new_concrete_and_symbolic_int(
                        mem_var.concrete.to_u64(), 
                        &mem_var.symbolic.to_str(),
                        mem_var.ctx, 
                        mem_var.get_size()
                    )
                }
            };
            let unique_name = format!("Unique(0x{:x})", id);
            executor.unique_variables.insert(unique_name, concolic_var);
        },
        Some(Var::Register(reg_num, _)) => {
            println!("Output is a Register type");
            let mut cpu_state_guard = executor.state.cpu_state.lock().unwrap();
            let reg_name = cpu_state_guard.reg_num_to_name(*reg_num);
            let concrete_value = result_value.get_concrete_value();
            let _ = cpu_state_guard.set_register_value(&reg_name, concrete_value);
            println!("Updated register {} with value {}", reg_name, concrete_value);
        },
        _ => {
            println!("Output type is unsupported");
            return Err("Output type not supported".to_string());
        }
    }

    println!("{}\n", executor);

    // Create a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intadd", current_addr_hex, executor.instruction_counter);
    executor.state.create_concolic_var_int(&result_var_name, result_value.get_concrete_value(), result_value.get_size());

    println!("{}\n", executor.state);

    Ok(())
}


pub fn handle_int_sub(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntSub || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_SUB".to_string());
    }

    let input0_var = executor.initialize_var_if_absent(&instruction.inputs[0])?;
    let input1_var = executor.initialize_var_if_absent(&instruction.inputs[1])?;

    // Ensure the sizes match
    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required for INT_SUB")?;
    if instruction.inputs[0].size != instruction.inputs[1].size || instruction.inputs[0].size != output_varnode.size {
        return Err("Input and output sizes must match for INT_SUB".to_string());
    }

    // Perform the subtraction
    let result_value = input0_var.wrapping_sub(input1_var);

    // Create or update a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    let bitvector_size = output_varnode.size.to_bitvector_size();
    executor.state.create_concolic_var_int(&result_var_name, result_value.into(), bitvector_size);

    Ok(())
}

pub fn handle_int_xor(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntXor || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_XOR".to_string());
    }

    // Retrieve the concrete integer values for both inputs
    let input0_val = executor.initialize_var_if_absent(&instruction.inputs[0])?;
    let input1_val = executor.initialize_var_if_absent(&instruction.inputs[1])?;

    // Perform XOR operation on the concrete integer values
    let result_concrete = input0_val ^ input1_val;

    // Prepare for the symbolic computation
    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    let bitvector_size = output_varnode.size.to_bitvector_size();

    // Update or create the concolic variable with the concrete result and a new symbolic expression
    executor.state.create_concolic_var_int(&result_var_name, result_concrete, bitvector_size);

    Ok(())
}      

pub fn handle_int_equal(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Ensure the correct instruction format
    if instruction.opcode != Opcode::IntEqual || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_EQUAL".to_string());
    }

    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    // Ensure output size is 1 (boolean)
    if output_varnode.size != Size::Byte {
        return Err("Output varnode size must be 1 (Byte) for INT_EQUAL".to_string());
    }

    let value0 = executor.initialize_var_if_absent(&instruction.inputs[0])?;
    let value1 = executor.initialize_var_if_absent(&instruction.inputs[1])?;

    // Compare the two values
    let result = (value0 == value1) as u32; // Convert boolean result to u32

    // Store the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    executor.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result.into(), &result_var_name, executor.context, 1));

    Ok(())
}

pub fn handle_int_not_equal(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Ensure the correct instruction format
    if instruction.opcode != Opcode::IntNotEqual || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_NOTEQUAL".to_string());
    }

    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    // Ensure output size is 1 (boolean)
    if output_varnode.size != Size::Byte {
        return Err("Output varnode size must be 1 (Byte) for INT_NOTEQUAL".to_string());
    }

    let value0 = executor.initialize_var_if_absent(&instruction.inputs[0])?;
    let value1 = executor.initialize_var_if_absent(&instruction.inputs[1])?;

    // Compare the two values
    let result = (value0 != value1) as u32; // Convert boolean result to u32

    // Store the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    executor.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result.into(), &result_var_name, executor.context, 1));

    Ok(())
}

pub fn handle_int_less(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntLess || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_LESS".to_string());
    }

    println!("* Fetching instruction.input[0] for INT_LESS");
    let input0_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
    println!("* Fetching instruction.input[1] for INT_LESS");
    let input1_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;

    // Perform the comparison
    let result_value = input0_var.concolic_less_than(input1_var, executor.context).map_err(|e| e.to_string())?;
    println!("*** The result of INT_LESS is: {:?}", result_value.clone());

    // The result of the comparison is a boolean
    match instruction.output.as_ref().map(|v| &v.var) {
        Some(Var::Unique(id)) => {
            // Check and convert result_value to ConcolicVar
            let concolic_var = match result_value.clone() {
                ConcolicEnum::ConcolicVar(var) => var,
                ConcolicEnum::CpuConcolicValue(cpu_var) => {
                    // Convert CpuConcolicValue to ConcolicVar
                    ConcolicVar::new_concrete_and_symbolic_int(
                        cpu_var.get_concrete_value()? as u64, 
                        &format!("Unique(0x{:x})", id), 
                        executor.context, 
                        1 // boolean is 1 bit
                    )
                },
                ConcolicEnum::MemoryConcolicValue(mem_var) => {
                    // Convert MemoryConcolicValue to ConcolicVar
                    ConcolicVar::new_concrete_and_symbolic_int(
                        mem_var.get_concrete_value()? as u64, 
                        &format!("Unique(0x{:x})", id),
                        executor.context, 
                        1 // boolean is 1 bit
                    )
                },
            };
            let unique_name = format!("Unique(0x{:x})", id);
            executor.unique_variables.insert(unique_name, concolic_var);
            println!("Updated unique_variables with new comparison result: {:?}", executor.unique_variables);
        },
        Some(Var::Register(reg_num, _)) => {
            println!("Output is a Register type for INT_LESS");
            let mut cpu_state_guard = executor.state.cpu_state.lock().unwrap();
            let reg_name = cpu_state_guard.reg_num_to_name(*reg_num);
            let concrete_value = result_value.clone().get_concrete_value();
            let _ = cpu_state_guard.set_register_value(&reg_name, concrete_value);
            println!("Updated register {} with comparison result {}", reg_name, concrete_value);
        },
        _ => {
            println!("Output type is unsupported for INT_LESS");
            return Err("Output type not supported".to_string());
        }
    }

    println!("{}\n", executor);

    // Create a concolic variable for the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-intless", current_addr_hex, executor.instruction_counter);
    executor.state.create_concolic_var_int(&result_var_name, result_value.get_concrete_value(), result_value.get_size());

    println!("{}\n", executor.state);

    Ok(())
}


pub fn handle_int_sless(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Ensure the correct instruction format
    if instruction.opcode != Opcode::IntSLess || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_SLESS".to_string());
    }

    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    // Ensure output size is 1 (boolean)
    if output_varnode.size != Size::Byte {
        return Err("Output varnode size must be 1 (Byte) for INT_SLESS".to_string());
    }

    let value0 = executor.initialize_var_if_absent(&instruction.inputs[0])?;
    let value1 = executor.initialize_var_if_absent(&instruction.inputs[1])?;

    // Convert unsigned values to signed for comparison
    let signed_value0 = match instruction.inputs[0].size {
        Size::QuadQuad => I256::from(value0),
        Size::DoubleQuad => ((value0 as u128) as i128 as i32).into(), // is it correct?
        Size::Quad => ((value0 as u64) as i64 as i32).into(), // ?
        Size::Word => ((value0 as u32) as i32).into(),
        Size::Half => ((value0 as u16) as i16 as i32).into(),
        Size::Byte => ((value0 as u8) as i8 as i32).into(),
    };

    let signed_value1 = match instruction.inputs[1].size {
        Size::QuadQuad => I256::from(value1),
        Size::DoubleQuad => ((value0 as u128) as i128 as i32).into(), // ?
        Size::Quad => ((value1 as u64) as i64 as i32).into(), // ?
        Size::Word => ((value1 as u32) as i32).into(),
        Size::Half => ((value1 as u16) as i16 as i32).into(),
        Size::Byte => ((value1 as u8) as i8 as i32).into(),
    };

    // Perform signed comparison
    let result = (signed_value0 < signed_value1) as u32; // Convert boolean result to u32

    // Store the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    executor.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result.into(), &result_var_name, executor.context, 1));

    Ok(())
}

pub fn handle_int_lessequal(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Ensure the correct instruction format
    if instruction.opcode != Opcode::IntLessEqual || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_LESSEQUAL".to_string());
    }

    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    // Ensure output size is 1 (boolean)
    if output_varnode.size != Size::Byte {
        return Err("Output varnode size must be 1 (Byte) for INT_LESSEQUAL".to_string());
    }

    let value0 = executor.initialize_var_if_absent(&instruction.inputs[0])?;
    let value1 = executor.initialize_var_if_absent(&instruction.inputs[1])?;

    // Perform unsigned comparison
    let result = (value0 <= value1) as u32; // Convert boolean result to u32

    // Store the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    executor.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result.into(), &result_var_name, executor.context, 1));

    Ok(())
}

pub fn handle_int_slessequal(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Ensure the correct instruction format
    if instruction.opcode != Opcode::IntSLessEqual || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_SLESSEQUAL".to_string());
    }

    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    // Ensure output size is 1 (boolean)
    if output_varnode.size != Size::Byte {
        return Err("Output varnode size must be 1 (Byte) for INT_SLESSEQUAL".to_string());
    }

    let value0 = executor.initialize_var_if_absent(&instruction.inputs[0])?;
    let value1 = executor.initialize_var_if_absent(&instruction.inputs[1])?;

    // Assuming the conversion logic for signed values based on their actual size (?)
    let signed_value0 = value0 as i32; 
    let signed_value1 = value1 as i32; 

    // Perform signed comparison
    let result = (signed_value0 <= signed_value1) as u32; // Convert boolean result to u32

    // Store the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    executor.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result.into(), &result_var_name, executor.context, 1));

    Ok(())
}

pub fn handle_int_zext(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Validate instruction format and sizes
    if instruction.opcode != Opcode::IntZExt || instruction.inputs.len() != 1 {
        return Err("Invalid instruction format for INT_ZEXT".to_string());
    }

    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    if instruction.inputs[0].size >= output_varnode.size {
        return Err("Output size must be strictly bigger than input size for INT_ZEXT".to_string());
    }

    let input_value = executor.initialize_var_if_absent(&instruction.inputs[0])?;
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    executor.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(input_value.into(), &result_var_name, executor.context, output_varnode.size.to_bitvector_size()));

    Ok(())
}

pub fn handle_int_sext(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Validate instruction format and sizes
    if instruction.opcode != Opcode::IntSExt || instruction.inputs.len() != 1 {
        return Err("Invalid instruction format for INT_SEXT".to_string());
    }

    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    if instruction.inputs[0].size >= output_varnode.size {
        return Err("Output size must be strictly bigger than input size for INT_SEXT".to_string());
    }

    let input_value = executor.initialize_var_if_absent(&instruction.inputs[0])?;
    let input_bits = instruction.inputs[0].size.to_bitvector_size() * 8;
    let shift_amount = 64u32.saturating_sub(input_bits);

    let extended_value = match instruction.inputs[0].size {
        Size::QuadQuad => I256::from(input_value),
        Size::DoubleQuad => (input_value as i128).into(),
        Size::Byte => (((input_value as i8) as i128).wrapping_shl(shift_amount) as u128).try_into().unwrap(),
        Size::Half => (((input_value as i16) as i128).wrapping_shl(shift_amount) as u128).try_into().unwrap(),
        Size::Word => (((input_value as i32) as i128).wrapping_shl(shift_amount) as u128).try_into().unwrap(),
        Size::Quad => (((input_value as i64) as i128).wrapping_shl(shift_amount) as u128).try_into().unwrap(),
    }; 

    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    
    // Ensure no left shift overflow occurs
    let bitmask = if output_varnode.size.to_bitvector_size() == 256 {
        I256::MAX
    } else {
        // For sizes less than 256 bits, construct the bitmask using shifting.
        // Note: I256 does not support shifting by u32 directly, so we convert to usize.
        let shift_amount = (output_varnode.size.to_bitvector_size() * 8) as usize;
        if shift_amount >= 256 {
            return Err("Shift amount exceeds 256 bits".to_string());
        }
        (I256::ONE << shift_amount) - I256::ONE
    };

    // Attempt to downcast to u64, handling potential overflow
    let result: u64 = (extended_value & bitmask).try_into().map_err(|_| "Value cannot be downcasted to u64 without loss".to_string())?;
    executor.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result, &result_var_name, executor.context, output_varnode.size.to_bitvector_size()));

    Ok(())
}

pub fn handle_int_sborrow(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Validate instruction format and sizes
    if instruction.opcode != Opcode::IntSBorrow || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_SBORROW".to_string());
    }

    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    if output_varnode.size != Size::Byte {
        return Err("Output size must be 1 (Byte) for INT_SBORROW".to_string());
    }

    if instruction.inputs[0].size != instruction.inputs[1].size {
        return Err("Inputs must be the same size for INT_SBORROW".to_string());
    }

    let input0_value = executor.initialize_var_if_absent(&instruction.inputs[0])? as i64;
    let input1_value = executor.initialize_var_if_absent(&instruction.inputs[1])? as i64;

    // Perform signed subtraction
    let (sub_result, _overflowed) = input0_value.overflowing_sub(input1_value);

    // Convert the subtraction result to u64
    let result_u64 = sub_result as u64;

    // Store the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    executor.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result_u64, &result_var_name, executor.context, output_varnode.size.to_bitvector_size()));

    Ok(())
}

pub fn handle_int_2comp(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Validate instruction format
    if instruction.opcode != Opcode::Int2Comp || instruction.inputs.len() != 1 {
        return Err("Invalid instruction format for INT_2COMP".to_string());
    }

    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    if instruction.inputs[0].size != output_varnode.size {
        return Err("Input and output must be the same size for INT_2COMP".to_string());
    }

    let input_value = executor.initialize_var_if_absent(&instruction.inputs[0])?;

    // Perform two's complement negation
    let negated_value = (!input_value).wrapping_add(1); // Bitwise NOT then add one

    // Store the negated value
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    executor.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(negated_value.into(), &result_var_name, executor.context, output_varnode.size.to_bitvector_size()));

    Ok(())
}

pub fn handle_int_and(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Validate instruction format and sizes
    if instruction.opcode != Opcode::IntAnd || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_AND".to_string());
    }

    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    if instruction.inputs[0].size != instruction.inputs[1].size || instruction.inputs[0].size != output_varnode.size {
        return Err("All inputs and output must be the same size for INT_AND".to_string());
    }

    let input0_value = executor.initialize_var_if_absent(&instruction.inputs[0])?;
    let input1_value = executor.initialize_var_if_absent(&instruction.inputs[1])?;

    // Perform bitwise AND
    let result = input0_value & input1_value;

    // Store the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    executor.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result.into(), &result_var_name, executor.context, output_varnode.size.to_bitvector_size()));

    Ok(())
}

pub fn handle_int_or(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Validate instruction format and sizes
    if instruction.opcode != Opcode::IntOr || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_OR".to_string());
    }

    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    if instruction.inputs[0].size != instruction.inputs[1].size || instruction.inputs[0].size != output_varnode.size {
        return Err("All inputs and output must be the same size for INT_OR".to_string());
    }

    let input0_value = executor.initialize_var_if_absent(&instruction.inputs[0])?;
    let input1_value = executor.initialize_var_if_absent(&instruction.inputs[1])?;

    // Perform bitwise OR
    let result = input0_value | input1_value;

    // Store the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    executor.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result.into(), &result_var_name, executor.context, output_varnode.size.to_bitvector_size()));

    Ok(())
}

pub fn handle_int_left(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Validate instruction format and sizes
    if instruction.opcode != Opcode::IntLeft || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_LEFT".to_string());
    }

    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    if instruction.inputs[0].size != output_varnode.size {
        return Err("Input0 and output must be the same size for INT_LEFT".to_string());
    }

    let input0_value = executor.initialize_var_if_absent(&instruction.inputs[0])?;
    let shift_amount = executor.initialize_var_if_absent(&instruction.inputs[1])? as usize;

    // Perform left shift operation
    let result = if shift_amount < (output_varnode.size.to_bitvector_size() * 8) as usize {
        input0_value << shift_amount
    } else {
        0 // Shift amount is larger than the number of bits in output, result is zero
    };

    // Store the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    executor.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result.into(), &result_var_name, executor.context, output_varnode.size.to_bitvector_size()));

    Ok(())
}

pub fn handle_int_right(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Validate instruction format and sizes
    if instruction.opcode != Opcode::IntRight || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_RIGHT".to_string());
    }

    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    if instruction.inputs[0].size != output_varnode.size {
        return Err("Input0 and output must be the same size for INT_RIGHT".to_string());
    }

    let input0_value = executor.initialize_var_if_absent(&instruction.inputs[0])?;
    let shift_amount = executor.initialize_var_if_absent(&instruction.inputs[1])? as usize;

    // Perform unsigned right shift operation
    let result = if shift_amount < (output_varnode.size.to_bitvector_size() * 8) as usize {
        input0_value >> shift_amount
    } else {
        0 // Shift amount is larger than the number of bits in output, result is zero
    };

    // Store the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    executor.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result.into(), &result_var_name, executor.context, output_varnode.size.to_bitvector_size()));

    Ok(())
}

pub fn handle_int_sright(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Validate instruction format and sizes
    if instruction.opcode != Opcode::IntSRight || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_SRIGHT".to_string());
    }

    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    if instruction.inputs[0].size != output_varnode.size {
        return Err("Input0 and output must be the same size for INT_SRIGHT".to_string());
    }

    let input0_value = executor.initialize_var_if_absent(&instruction.inputs[0])? as i64; // Cast to signed integer
    let shift_amount = executor.initialize_var_if_absent(&instruction.inputs[1])? as usize;

    // Perform signed right shift operation
    let result = if shift_amount < (output_varnode.size.to_bitvector_size() * 8) as usize {
        (input0_value >> shift_amount) as u32 // Ensure result fits within the original size
    } else {
        if input0_value < 0 {
            !0 // If input is negative and shift amount is too large, result is all 1-bits
        } else {
            0 // Otherwise, result is zero
        }
    };

    // Store the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    executor.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result.into(), &result_var_name, executor.context, output_varnode.size.to_bitvector_size()));

    Ok(())
}

pub fn handle_int_mult(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Validate instruction format and sizes
    if instruction.opcode != Opcode::IntMult || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_MULT".to_string());
    }

    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    if instruction.inputs[0].size != instruction.inputs[1].size || instruction.inputs[0].size != output_varnode.size {
        return Err("All inputs and output must be the same size for INT_MULT".to_string());
    }

    let input0_value = executor.initialize_var_if_absent(&instruction.inputs[0])?;
    let input1_value = executor.initialize_var_if_absent(&instruction.inputs[1])?;

    // Perform multiplication
    let result = input0_value.wrapping_mul(input1_value); // Use wrapping_mul to handle overflow

    // Store the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    executor.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result.into(), &result_var_name, executor.context, output_varnode.size.to_bitvector_size()));

    Ok(())
}

pub fn handle_int_negate(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::IntNegate || instruction.inputs.len() != 1 {
        return Err("Invalid instruction format for INT_NEGATE".to_string());
    }

    // Retrieve the concrete integer value for the input
    let input_val = executor.initialize_var_if_absent(&instruction.inputs[0])?;

    // Perform NOT operation on the concrete integer value
    let negated_concrete = !input_val;

    // Prepare for the symbolic computation
    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    let bitvector_size = output_varnode.size.to_bitvector_size();

    // Create or update the output concolic variable with the negated concrete value
    executor.state.create_concolic_var_int(&result_var_name, negated_concrete, bitvector_size);

    Ok(())
}

pub fn handle_int_div(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Validate instruction format and sizes
    if instruction.opcode != Opcode::IntDiv || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_DIV".to_string());
    }

    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    if instruction.inputs[0].size != instruction.inputs[1].size || instruction.inputs[0].size != output_varnode.size {
        return Err("All inputs and output must be the same size for INT_DIV".to_string());
    }

    let input0_value = executor.initialize_var_if_absent(&instruction.inputs[0])?;
    let input1_value = executor.initialize_var_if_absent(&instruction.inputs[1])?;

    // Check for division by zero
    // if input1_value == 0 {
    //     // Instead of proceeding with division, return an error
    //     return Err("Division by zero encountered in INT_DIV".to_string());
    // }

    // Check for division by zero
    let result = if input1_value == 0 {
        // Log division by zero 
        println!("Warning: Division by zero encountered in INT_DIV at address {:x}. Using default value 0.", executor.current_address.unwrap_or(0));
        0 
    } else {
        // Perform division
        input0_value / input1_value
    };

    // Store the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    executor.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result.into(), &result_var_name, executor.context, output_varnode.size.to_bitvector_size()));

    Ok(())
}

pub fn handle_int_rem(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Validate instruction format and sizes
    if instruction.opcode != Opcode::IntRem || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_REM".to_string());
    }

    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    if instruction.inputs[0].size != instruction.inputs[1].size || instruction.inputs[0].size != output_varnode.size {
        return Err("All inputs and output must be the same size for INT_REM".to_string());
    }

    let input0_value = executor.initialize_var_if_absent(&instruction.inputs[0])?;
    let input1_value = executor.initialize_var_if_absent(&instruction.inputs[1])?;

    // Check for division by zero
    if input1_value == 0 {
        // Instead of proceeding with the remainder calculation, return an error
        return Err("Division by zero encountered in INT_REM".to_string());
    }

    // Perform remainder operation
    let result = input0_value % input1_value;

    // Store the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    executor.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result.into(), &result_var_name, executor.context, output_varnode.size.to_bitvector_size()));

    Ok(())
}

pub fn handle_int_sdiv(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Validate instruction format and sizes
    if instruction.opcode != Opcode::IntSDiv || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_SDIV".to_string());
    }

    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    if instruction.inputs[0].size != instruction.inputs[1].size || instruction.inputs[0].size != output_varnode.size {
        return Err("All inputs and output must be the same size for INT_SDIV".to_string());
    }

    let input0_value = executor.initialize_var_if_absent(&instruction.inputs[0])? as i32; // Cast to signed
    let input1_value = executor.initialize_var_if_absent(&instruction.inputs[1])? as i32;

    // Check for division by zero
    if input1_value == 0 {
        return Err("Division by zero encountered in INT_SDIV".to_string());
    }

    // Perform signed division
    let result = input0_value / input1_value;

    // Store the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    executor.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result.try_into().unwrap(), &result_var_name, executor.context, output_varnode.size.to_bitvector_size()));

    Ok(())
}

pub fn handle_int_srem(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Validate instruction format and sizes
    if instruction.opcode != Opcode::IntSRem || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for INT_SREM".to_string());
    }

    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required")?;
    if instruction.inputs[0].size != instruction.inputs[1].size || instruction.inputs[0].size != output_varnode.size {
        return Err("All inputs and output must be the same size for INT_SREM".to_string());
    }

    let input0_value = executor.initialize_var_if_absent(&instruction.inputs[0])? as i32;
    let input1_value = executor.initialize_var_if_absent(&instruction.inputs[1])? as i32;

    // Check for division by zero
    if input1_value == 0 {
        return Err("Division by zero encountered in INT_SREM".to_string());
    }

    // Perform signed remainder operation
    let result = input0_value % input1_value;

    // Store the result
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    executor.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_int(result.try_into().unwrap(), &result_var_name, executor.context, output_varnode.size.to_bitvector_size()));

    Ok(())
}

pub fn handle_int2float(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::Int2Float || instruction.inputs.len() != 1 {
        return Err("Invalid instruction format for INT2FLOAT".to_string());
    }

    let output_varnode = instruction.output.as_ref().ok_or("Output varnode is required".to_string())?;
    
    let input0_value = executor.state.get_concrete_var(&instruction.inputs[0])?;

    let result = match input0_value {
        ConcreteVar::Int(i0) => i0 as f64, // Handle conversion from integer to float.
        _ => return Err("Expected an integer value for INT2FLOAT".to_string()),
    };

    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_{}", current_addr_hex, executor.instruction_counter, format!("{:?}", output_varnode.var));
    executor.state.set_var(&result_var_name, ConcolicVar::new_concrete_and_symbolic_float(result, &result_var_name, executor.context));

    Ok(())
}