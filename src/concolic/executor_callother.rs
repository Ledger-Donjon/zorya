// SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

/// Focuses on implementing the execution of the CALLOTHER opcode from Ghidra's Pcode specification
/// This implementation relies on Ghidra 11.0.1 with the specfiles in /specfiles
///
use crate::{concolic::ConcreteVar, executor::ConcolicExecutor, state::memory_x86_64::MemoryValue};
use parser::parser::{Inst, Opcode, Var, Varnode};
use std::{
    io::Write,
    process,
    time::{SystemTime, UNIX_EPOCH},
};
use z3::ast::BV;

use super::{executor_callother_syscalls, ConcolicEnum, ConcolicVar, SymbolicVar};

macro_rules! log {
    ($logger:expr, $($arg:tt)*) => {{
        if ($logger).is_enabled() {
        writeln!($logger, $($arg)*).unwrap();
        }
    }};
}

/// Returns a human-readable name for a CALLOTHER operation given its index
fn get_callother_operation_name(operation_index: u32) -> String {
    match operation_index {
        0x5 => "SYSCALL".to_string(),
        0xb => "RDTSCP".to_string(),
        0x10 => "SWI".to_string(),
        0x11 => "LOCK".to_string(),
        0x12 => "UNLOCK".to_string(),
        0x9a => "PSHUFW (Packed Shuffle Word)".to_string(),
        0x2c => "CPUID".to_string(),
        0x2d => "CPUID Basic Info".to_string(),
        0x2e => "CPUID Version Info".to_string(),
        0x2f => "CPUID Cache/TLB Info".to_string(),
        0x30 => "CPUID Serial Info".to_string(),
        0x31 => "CPUID Deterministic Cache Parameters Info".to_string(),
        0x32 => "CPUID Monitor/MWAIT Features Info".to_string(),
        0x33 => "CPUID Thermal Power Management Info".to_string(),
        0x34 => "CPUID Extended Feature Enumeration Info".to_string(),
        0x35 => "CPUID Direct Cache Access Info".to_string(),
        0x36 => "CPUID Architectural Performance Monitoring Info".to_string(),
        0x37 => "CPUID Extended Topology Info".to_string(),
        0x38 => "CPUID Processor Extended States Info".to_string(),
        0x39 => "CPUID Quality of Service Info".to_string(),
        0x3a => "CPUID Brand Part1 Info".to_string(),
        0x3b => "CPUID Brand Part2 Info".to_string(),
        0x3c => "CPUID Brand Part3 Info".to_string(),
        0x4a => "RDTSC".to_string(),
        0x97 => "PSHUFB".to_string(),
        0x98 => "PSHUFHW".to_string(),
        0xdc => "AESENC".to_string(),
        0xde => "AESIMC (AES Inverse Mix Columns)".to_string(),
        0x13a => "VMOVDQU (AVX)".to_string(),
        0x144 => "VMOVNTDQ (AVX)".to_string(),
        0x1a1 => "VPMULLW (AVX)".to_string(),
        0x1be => "VPTEST (AVX)".to_string(),
        0x1c7 => "VPXOR (AVX)".to_string(),
        0x1e2 => "VBROADCASTSD (AVX)".to_string(),
        0x203 => "VPAND (AVX2)".to_string(),
        0x209 => "VPCMPEQB (AVX2)".to_string(),
        0x25d => "VPBROADCASTB (AVX2)".to_string(),
        _ => format!("UNKNOWN (0x{:x})", operation_index),
    }
}

pub fn handle_callother(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    let operation_index = match instruction.inputs.get(0) {
        Some(Varnode {
            var: Var::Const(index),
            ..
        }) => {
            let index = index.trim_start_matches("0x"); // Remove "0x" if present
            u32::from_str_radix(index, 16) // Parse as base-16 number
                .map_err(|_| format!("Failed to parse operation index '{}'", index))
        }
        _ => {
            Err("CALLOTHER operation requires the first input to be a constant index.".to_string())
        }
    }?;

    // Get the operation name for logging
    let operation_name = get_callother_operation_name(operation_index);
    log!(
        executor.trace_logger,
        "----> Calling the CALLOTHER instruction with number {} being {}",
        operation_index,
        operation_name
    );

    match operation_index {
        // Operations probably used in Go runtime
        0x5 => executor_callother_syscalls::handle_syscall(executor),
        0xb => handle_rdtscp(executor),
        0x10 => handle_swi(executor, instruction),
        0x11 => handle_lock(executor),
        0x12 => handle_unlock(executor),
        0x9a => handle_pshufw(executor, instruction),
        0x2c => handle_cpuid(executor, instruction),
        0x2d => handle_cpuid_basic_info(executor, instruction),
        0x2e => handle_cpuid_version_info(executor, instruction),
        0x2f => handle_cpuid_cache_tlb_info(executor, instruction),
        0x30 => handle_cpuid_serial_info(executor, instruction),
        0x31 => handle_cpuid_deterministic_cache_parameters_info(executor, instruction),
        0x32 => handle_cpuid_monitor_mwait_features_info(executor, instruction),
        0x33 => handle_cpuid_thermal_power_management_info(executor, instruction),
        0x34 => handle_cpuid_extended_feature_enumeration_info(executor, instruction),
        0x35 => handle_cpuid_direct_cache_access_info(executor, instruction),
        0x36 => handle_cpuid_architectural_performance_monitoring_info(executor, instruction),
        0x37 => handle_cpuid_extended_topology_info(executor, instruction),
        0x38 => handle_cpuid_processor_extended_states_info(executor, instruction),
        0x39 => handle_cpuid_quality_of_service_info(executor, instruction),
        0x3a => handle_cpuid_brand_part1_info(executor, instruction),
        0x3b => handle_cpuid_brand_part2_info(executor, instruction),
        0x3c => handle_cpuid_brand_part3_info(executor, instruction),
        0x4a => handle_rdtsc(executor),
        0x97 => handle_pshufb(executor, instruction),
        0x98 => handle_pshufhw(executor, instruction),
        0xdc => handle_aesenc(executor, instruction),
        0xde => handle_aesimc(executor, instruction),
        0x13a => handle_vmovdqu_avx(executor, instruction),
        0x144 => handle_vmovntdq_avx(executor, instruction),
        0x1a1 => handle_vpmullw_avx(executor, instruction),
        0x1be => handle_vptest_avx(executor, instruction),
        0x1c7 => handle_vpxor_avx(executor, instruction),
        0x1e2 => handle_vbroadcastsd_avx(executor, instruction),
        0x203 => handle_vpand_avx2(executor, instruction),
        0x209 => handle_vpcmpeqb_avx2(executor, instruction),
        0x25d => handle_vpbroadcastb_avx2(executor, instruction),
        _ => {
            // if the callother number is not handled, stop the execution
            let error_msg = format!(
                "FATAL ERROR: Unhandled CALLOTHER operation: index={} (0x{:x})\n\
                 This means the binary uses an instruction not yet implemented in Zorya.\n\
                 Check src/concolic/specfiles/callother-database.txt to identify the operation.\n\
                 Current instruction: {:?}",
                operation_index, operation_index, instruction
            );

            eprintln!("\n{}\n", "=".repeat(80));
            eprintln!("{}", error_msg);
            eprintln!("{}\n", "=".repeat(80));

            log!(
                executor.trace_logger,
                "Unhandled CALLOTHER number: {}",
                operation_index
            );
            process::exit(1);
        }
    }
}

/// Handle LOCK - Atomic memory access prefix
///
/// This prefix ensures atomic access to memory for the following instruction.
/// In our single-threaded concolic execution context, this is a no-op as atomicity
/// is implicitly guaranteed by the sequential execution model.
pub fn handle_lock(_executor: &mut ConcolicExecutor) -> Result<(), String> {
    Ok(())
}

/// Handle UNLOCK - Release atomic memory access
///
/// Releases the lock acquired by a preceding LOCK prefix.
/// In our single-threaded concolic execution context, this is a no-op as atomicity
/// is implicitly guaranteed by the sequential execution model.
pub fn handle_unlock(_executor: &mut ConcolicExecutor) -> Result<(), String> {
    Ok(())
}

/// Handle CPUID - CPU identification and feature information
///
/// Returns processor identification and feature information based on the value in EAX.
/// Emulates an AMD Opteron G1 processor with standard x86-64 features.
/// Results are written to EAX, EBX, ECX, and EDX registers.
pub fn handle_cpuid(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Get the output size of the instruction
    let output_size = instruction
        .output
        .as_ref()
        .unwrap()
        .size
        .to_bitvector_size() as u32;

    // Memory address to temporarly store EAX, EBX, ECX, EDX
    let base_address = 0x300000;

    // Register offsets for EAX, EBX, ECX, and EDX
    let eax_offset = 0x0;

    // Lock the CPU state to read/write registers
    let cpu_state_guard = executor.state.cpu_state.lock().unwrap();
    // Retrieve the current value of the EAX register to determine the CPUID function requested
    let eax_input = cpu_state_guard
        .get_register_by_offset(eax_offset, 32)
        .ok_or("Failed to retrieve EAX register value.")?
        .get_concrete_value()?;

    log!(
        executor.trace_logger,
        "CPUID function requested: 0x{:x}",
        eax_input
    );

    #[allow(unused_assignments)]
    let (mut eax, mut ebx, mut ecx, mut edx) = (0u32, 0u32, 0u32, 0u32);

    match eax_input as u32 {
        // CPUID called with EAX = 0: Get the highest value for basic CPUID information and the vendor ID string
        0 => {
            // The processor supports basic CPUID calls up to 5 based on actual QEMU output
            eax = 5;
            // Vendor ID string for "AuthenticAMD"
            ebx = 0x68747541; // 'Auth'
            ecx = 0x444D4163; // 'DMAc'
            edx = 0x69746E65; // 'enti'
        }
        // CPUID called with EAX = 1: Processor Info and Feature Bits
        1 => {
            // Family 15, Model 6, Stepping 1 based on actual Opteron G1 characteristics
            eax = 0x00000f61; // Family, Model, Stepping
            ebx = 0x00000800; // Initial APIC ID
            ecx = 0x80000001; // SSE3 supported
            edx = 0x078bfbfd; // The features supported like MMX, SSE, SSE2 etc
        }
        2 => {
            // Cache descriptor information, hard-coded as per Intel manuals or synthesized
            eax = 0x665B5001;
            ebx = 0x00000000;
            ecx = 0x00000000;
            edx = 0x007A7000;
        }
        3..=4 => {
            // reserved or used for system-specific functions
            eax = 0;
            ebx = 0;
            ecx = 0;
            edx = 0;
        }
        5 => {
            // MONITOR/MWAIT
            eax = 0x00000040; // Smallest monitor-line size in bytes
            ebx = 0x00000040; // Largest monitor-line size in bytes
            ecx = 0x00000003; // Enumeration of Monitor-MWAIT extensions
            edx = 0x00000000; // Number of C-states using MWAIT
        }
        0x20000000 => {
            eax = 0x00000000;
            ebx = 0x00000000;
            ecx = 0x00000003;
            edx = 0x00000000;
        }
        0x40000000 => {
            eax = 0x40000001; // Indicates the highest function available for hypervisor
            ebx = 0x54474354; // "TGCT"
            ecx = 0x43544743; // "CTGC"
            edx = 0x47435447; // "GCTG"
        }
        0x40000001 => {
            eax = 0x00000000;
            ebx = 0x00000000;
            ecx = 0x00000000;
            edx = 0x00000000;
        }
        0x40000100 => {
            eax = 0x00000000;
            ebx = 0x00000000;
            ecx = 0x00000003;
            edx = 0x00000000;
        }
        0x80000000 => {
            eax = 0x80000008; // Highest extended function supported
            ebx = 0;
            ecx = 0;
            edx = 0;
        }
        0x80000002..=0x80000004 => {
            // Processor Brand String
            let brand_string = "AMD Opteron Processor        ";
            let brand_bytes = brand_string.as_bytes();
            let chunk = (eax_input - 0x80000002) as usize * 16;
            eax = u32::from_ne_bytes(brand_bytes[chunk..chunk + 4].try_into().unwrap());
            ebx = u32::from_ne_bytes(brand_bytes[chunk + 4..chunk + 8].try_into().unwrap());
            ecx = u32::from_ne_bytes(brand_bytes[chunk + 8..chunk + 12].try_into().unwrap());
            edx = u32::from_ne_bytes(brand_bytes[chunk + 12..chunk + 16].try_into().unwrap());
        }
        0x80000006 => {
            // Cache information
            eax = 0x42004200;
            ebx = 0x02008140;
            ecx = 0x40020140; // L2 cache details
            edx = 0x00000000; // L3 cache details
        }
        0x80000007 => {
            // provides information about advanced power management features
            eax = 0;
            ebx = 0;
            ecx = 0;
            edx = 0;
        }
        0x80000008 => {
            eax = 0x00003028; // Virtual and physical address sizes
            ebx = 0;
            ecx = 0;
            edx = 0;
        }
        0x80860000 => {
            eax = 0x00000000;
            ebx = 0x00000000;
            ecx = 0x00000003;
            edx = 0x00000000;
        }
        0xc0000000 => {
            eax = 0x00000000;
            ebx = 0x00000000;
            ecx = 0x00000003;
            edx = 0x00000000;
        }
        // if not known, return 0 like in Qemu (https://gitlab.com/qemu-project/qemu/-/blob/4ea7e9cd882f1574c129d67431784fecc426d23b/target/i386/cpu.c?page=8#L7035)
        _ => {
            eax = 0;
            ebx = 0;
            ecx = 0;
            edx = 0;
        }
    }

    // Write the results to memory using the new MemoryX86_64 methods
    let ctx = executor.state.memory.ctx;

    // Create MemoryValue for eax
    let eax_value = MemoryValue {
        concrete: eax as u64,
        symbolic: BV::from_u64(ctx, eax as u64, 32),
        size: 32,
    };
    executor
        .state
        .memory
        .write_value(base_address, &eax_value)
        .map_err(|e| format!("Failed to write EAX to memory: {:?}", e))?;

    // Create MemoryValue for ebx
    let ebx_value = MemoryValue {
        concrete: ebx as u64,
        symbolic: BV::from_u64(ctx, ebx as u64, 32),
        size: 32,
    };
    executor
        .state
        .memory
        .write_value(base_address + 4, &ebx_value)
        .map_err(|e| format!("Failed to write EBX to memory: {:?}", e))?;

    // Create MemoryValue for ecx
    let ecx_value = MemoryValue {
        concrete: ecx as u64,
        symbolic: BV::from_u64(ctx, ecx as u64, 32),
        size: 32,
    };
    executor
        .state
        .memory
        .write_value(base_address + 8, &ecx_value)
        .map_err(|e| format!("Failed to write ECX to memory: {:?}", e))?;

    // Create MemoryValue for edx
    let edx_value = MemoryValue {
        concrete: edx as u64,
        symbolic: BV::from_u64(ctx, edx as u64, 32),
        size: 32,
    };
    executor
        .state
        .memory
        .write_value(base_address + 12, &edx_value)
        .map_err(|e| format!("Failed to write EDX to memory: {:?}", e))?;

    log!(executor.trace_logger, "Temporarily wrote into memory the values of EAX: 0x{:08x}, EBX: 0x{:08x}, ECX: 0x{:08x}, EDX: 0x{:08x}", eax, ebx, ecx, edx);

    drop(cpu_state_guard);

    // Set the result in the CPU state
    executor.handle_output(
        instruction.output.as_ref(),
        ConcolicVar::new_concrete_and_symbolic_int(
            base_address,
            SymbolicVar::new_int(
                base_address.try_into().unwrap(),
                executor.context,
                output_size,
            )
            .to_bv(executor.context),
            executor.context,
        ),
    )?;

    // Create the concolic variables for the results
    let current_addr_hex = executor
        .current_address
        .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!(
        "{}-{:02}-callother-cpuid",
        current_addr_hex, executor.instruction_counter
    );
    executor.state.create_or_update_concolic_variable_int(
        &result_var_name,
        eax_input,
        SymbolicVar::Int(BV::from_u64(executor.context, eax_input, 64)),
    );

    Ok(())
}

/// Handle AESENC - AES single round encryption
///
/// Performs one round of AES encryption (ShiftRows, SubBytes, MixColumns, AddRoundKey).
/// Takes a 128-bit state and round key as inputs, outputs the encrypted state.
pub fn handle_aesenc(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    if instruction.opcode != Opcode::CallOther || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for AESENC".to_string());
    }

    // Fetch concolic variables for the state and round key
    let state_var = executor
        .varnode_to_concolic(&instruction.inputs[0])
        .map_err(|e| e.to_string())?;
    let round_key_var = executor
        .varnode_to_concolic(&instruction.inputs[1])
        .map_err(|e| e.to_string())?;

    // Perform AES encryption steps
    let state_after_shiftrows = shift_rows(state_var, executor);
    let state_after_subbytes = sub_bytes(state_after_shiftrows, executor);
    let state_after_mixcolumns = mix_columns(state_after_subbytes, executor);

    // Final XOR with round key
    let result_state = state_after_mixcolumns
        .symbolic
        .to_bv(executor.context)
        .bvxor(&round_key_var.get_symbolic_value_bv(executor.context));
    let result_concrete =
        state_after_mixcolumns.concrete.to_u64() ^ round_key_var.get_concrete_value();

    let result_value =
        ConcolicVar::new_concrete_and_symbolic_int(result_concrete, result_state, executor.context);

    // Set the result in the CPU state
    executor.handle_output(instruction.output.as_ref(), result_value)?;

    Ok(())
}

/// Handle AESIMC - AES Inverse Mix Columns (CALLOTHER 0xde / index 222)
///
/// Performs the Inverse MixColumns transformation on a 128-bit AES state.
/// This is used in AES decryption to reverse the MixColumns operation.
///
/// Instruction format: AESIMC xmm1, xmm2/m128
pub fn handle_aesimc(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Fetch the input state (128-bit)
    let state_var = executor
        .varnode_to_concolic(&instruction.inputs[1])
        .map_err(|e| e.to_string())?;

    let state_concrete = state_var.get_concrete_value();
    let state_symbolic = state_var.get_symbolic_value_bv(executor.context);

    log!(
        executor.trace_logger,
        "AESIMC: input state=0x{:032x}",
        state_concrete
    );

    // Perform Inverse MixColumns transformation
    // For a simplified concolic execution, we'll apply a reversible operation
    // A full implementation would use the proper AES Inverse MixColumns matrix multiplication
    // in GF(2^8), but for symbolic execution we use a simplified approximation

    // Simplified: Apply byte-wise rotation and XOR as an approximation
    // In real AES, this involves matrix multiplication with the inverse MixColumns matrix:
    // [0E 0B 0D 09]
    // [09 0E 0B 0D]
    // [0D 09 0E 0B]
    // [0B 0D 09 0E]

    // For symbolic execution, we use a simplified reversible transformation
    let result_concrete = state_concrete.rotate_right(7) ^ state_concrete.rotate_left(13);

    // Manually implement rotation for symbolic values since Z3 doesn't expose rotate methods
    let size_bits = state_symbolic.get_size();
    let rotate_right_7 = state_symbolic
        .bvlshr(&BV::from_u64(executor.context, 7, size_bits))
        .bvor(&state_symbolic.bvshl(&BV::from_u64(
            executor.context,
            size_bits as u64 - 7,
            size_bits,
        )));
    let rotate_left_13 = state_symbolic
        .bvshl(&BV::from_u64(executor.context, 13, size_bits))
        .bvor(&state_symbolic.bvlshr(&BV::from_u64(
            executor.context,
            size_bits as u64 - 13,
            size_bits,
        )));

    let result_symbolic = rotate_right_7.bvxor(&rotate_left_13);

    log!(
        executor.trace_logger,
        "AESIMC: result=0x{:032x}",
        result_concrete
    );

    let result = ConcolicVar::new_concrete_and_symbolic_int(
        result_concrete,
        result_symbolic,
        executor.context,
    );

    // Write result to output XMM register
    executor.handle_output(instruction.output.as_ref(), result)?;

    Ok(())
}

/// ShiftRows transformation for AES
///
/// Simplified implementation: performs left rotation as an approximation of the ShiftRows step.
fn shift_rows<'a>(input: ConcolicEnum<'a>, executor: &mut ConcolicExecutor<'a>) -> ConcolicVar<'a> {
    // Typically, this would permute the bytes in the state matrix
    let symbolic_bv = rotate_left(input.get_symbolic_value_bv(executor.context), 8); // Rotate left for simplicity
    let concrete_u64 = input.get_concrete_value().rotate_left(8);

    // Convert single BV to Vec<BV> for large int representation
    // For AES, we typically work with 128-bit values, so we can split into 2x64-bit chunks
    let symbolic_vec = if symbolic_bv.get_size() > 64 {
        vec![
            symbolic_bv.extract(63, 0),   // Lower 64 bits
            symbolic_bv.extract(127, 64), // Upper 64 bits
        ]
    } else {
        vec![symbolic_bv] // Single 64-bit value
    };

    // Convert single u64 to Vec<u64> for large int representation
    // Since concrete_u64 is a single u64, we can't extract upper bits
    let concrete_vec = vec![concrete_u64]; // Just use the single 64-bit value

    ConcolicVar::new_concrete_and_symbolic_large_int(concrete_vec, symbolic_vec, executor.context)
}

/// SubBytes transformation for AES
///
/// Simplified implementation: applies bitwise NOT as an approximation of the S-box substitution.
fn sub_bytes<'a>(input: ConcolicVar<'a>, executor: &mut ConcolicExecutor<'a>) -> ConcolicVar<'a> {
    match (&input.concrete, &input.symbolic) {
        (ConcreteVar::LargeInt(concrete_vec), SymbolicVar::LargeInt(symbolic_vec)) => {
            // Apply operation to each chunk
            let new_concrete: Vec<u64> = concrete_vec.iter().map(|&val| !val).collect();
            let new_symbolic: Vec<BV> = symbolic_vec.iter().map(|bv| bv.bvnot()).collect();

            ConcolicVar::new_concrete_and_symbolic_large_int(
                new_concrete,
                new_symbolic,
                executor.context,
            )
        }
        _ => {
            // Handle case where input is not a LargeInt - convert it first
            let symbolic_bv = input.symbolic.to_bv(executor.context).bvnot();
            let concrete_u64 = !input.concrete.to_u64();

            // Convert to large int format
            let symbolic_vec = if symbolic_bv.get_size() <= 64 {
                vec![symbolic_bv]
            } else {
                vec![
                    symbolic_bv.extract(63, 0),   // Lower 64 bits
                    symbolic_bv.extract(127, 64), // Upper 64 bits
                ]
            };

            // For a single u64, we only have one chunk
            let concrete_vec = vec![concrete_u64];

            ConcolicVar::new_concrete_and_symbolic_large_int(
                concrete_vec,
                symbolic_vec,
                executor.context,
            )
        }
    }
}

/// MixColumns transformation for AES
///
/// Simplified implementation: multiplies by 2 as an approximation of the MixColumns matrix multiplication.
fn mix_columns<'a>(input: ConcolicVar<'a>, executor: &mut ConcolicExecutor<'a>) -> ConcolicVar<'a> {
    match (&input.concrete, &input.symbolic) {
        (ConcreteVar::LargeInt(concrete_vec), SymbolicVar::LargeInt(symbolic_vec)) => {
            // Apply multiplication to each chunk
            let new_concrete: Vec<u64> = concrete_vec
                .iter()
                .map(|&val| val.wrapping_mul(2))
                .collect();
            let new_symbolic: Vec<BV> = symbolic_vec
                .iter()
                .map(|bv| bv.bvmul(&BV::from_u64(executor.context, 2, bv.get_size())))
                .collect();

            ConcolicVar::new_concrete_and_symbolic_large_int(
                new_concrete,
                new_symbolic,
                executor.context,
            )
        }
        _ => {
            // Handle case where input is not a LargeInt - convert it first
            let symbolic_bv = input.symbolic.to_bv(executor.context).bvmul(&BV::from_u64(
                executor.context,
                2,
                input.symbolic.to_bv(executor.context).get_size(),
            ));
            let concrete_u64 = input.concrete.to_u64().wrapping_mul(2);

            // Convert to large int format
            let symbolic_vec = if symbolic_bv.get_size() <= 64 {
                vec![symbolic_bv]
            } else {
                vec![
                    symbolic_bv.extract(63, 0),   // Lower 64 bits
                    symbolic_bv.extract(127, 64), // Upper 64 bits
                ]
            };

            // For a single u64, we only have one chunk
            let concrete_vec = vec![concrete_u64];

            ConcolicVar::new_concrete_and_symbolic_large_int(
                concrete_vec,
                symbolic_vec,
                executor.context,
            )
        }
    }
}

/// Rotate bit vector left by specified number of positions
///
/// Supports arbitrary bit widths by extracting and recombining upper and lower parts.
fn rotate_left<'a>(bv: BV<'a>, positions: u32) -> BV<'a> {
    let bit_width = bv.get_size();
    let actual_positions = positions % bit_width; // Handle cases where positions > bit_width

    if actual_positions == 0 {
        return bv;
    }

    // Extract the parts to rotate
    let upper_part = bv.extract(bit_width - 1, bit_width - actual_positions);
    let lower_part = bv.extract(bit_width - actual_positions - 1, 0);

    // Concatenate: lower_part || upper_part
    lower_part.concat(&upper_part)
}

/// Handle CPUID Basic Info (EAX=0) - Vendor ID and highest basic function
///
/// Returns the highest supported basic CPUID function and processor vendor string.
pub fn handle_cpuid_basic_info(
    executor: &mut ConcolicExecutor,
    instruction: Inst,
) -> Result<(), String> {
    handle_cpuid(executor, instruction)
}

/// Handle CPUID Version Info (EAX=1) - Processor family, model, and feature flags
///
/// Returns processor signature (family, model, stepping) and feature bits.
pub fn handle_cpuid_version_info(
    executor: &mut ConcolicExecutor,
    instruction: Inst,
) -> Result<(), String> {
    handle_cpuid(executor, instruction)
}

/// Handle CPUID Cache/TLB Info (EAX=2) - Cache and TLB descriptor information
///
/// Returns cache and TLB configuration descriptors.
pub fn handle_cpuid_cache_tlb_info(
    executor: &mut ConcolicExecutor,
    instruction: Inst,
) -> Result<(), String> {
    handle_cpuid(executor, instruction)
}

/// Handle CPUID Serial Number (EAX=3) - Processor serial number
///
/// Returns processor serial number (deprecated on most modern processors).
pub fn handle_cpuid_serial_info(
    executor: &mut ConcolicExecutor,
    instruction: Inst,
) -> Result<(), String> {
    handle_cpuid(executor, instruction)
}

/// Handle CPUID Deterministic Cache Parameters (EAX=4) - Detailed cache hierarchy info
///
/// Returns detailed information about cache levels, sizes, and associativity.
pub fn handle_cpuid_deterministic_cache_parameters_info(
    executor: &mut ConcolicExecutor,
    instruction: Inst,
) -> Result<(), String> {
    handle_cpuid(executor, instruction)
}

/// Handle CPUID MONITOR/MWAIT Features (EAX=5) - Power management capabilities
///
/// Returns MONITOR/MWAIT instruction support and C-state information.
pub fn handle_cpuid_monitor_mwait_features_info(
    executor: &mut ConcolicExecutor,
    instruction: Inst,
) -> Result<(), String> {
    handle_cpuid(executor, instruction)
}

/// Handle CPUID Thermal/Power Management (EAX=6) - Thermal monitoring features
///
/// Returns thermal sensor and dynamic frequency scaling capabilities.
pub fn handle_cpuid_thermal_power_management_info(
    executor: &mut ConcolicExecutor,
    instruction: Inst,
) -> Result<(), String> {
    handle_cpuid(executor, instruction)
}

/// Handle CPUID Extended Features (EAX=7) - Extended feature flags
///
/// Returns extended processor features like AVX2, BMI, TSX, etc.
pub fn handle_cpuid_extended_feature_enumeration_info(
    executor: &mut ConcolicExecutor,
    instruction: Inst,
) -> Result<(), String> {
    handle_cpuid(executor, instruction)
}

/// Handle CPUID Direct Cache Access (EAX=9) - DCA capabilities
///
/// Returns Direct Cache Access (DCA) feature information for I/O device prefetching.
pub fn handle_cpuid_direct_cache_access_info(
    executor: &mut ConcolicExecutor,
    instruction: Inst,
) -> Result<(), String> {
    handle_cpuid(executor, instruction)
}

/// Handle CPUID Performance Monitoring (EAX=0xA) - PMU architecture
///
/// Returns architectural performance monitoring unit capabilities and counters.
pub fn handle_cpuid_architectural_performance_monitoring_info(
    executor: &mut ConcolicExecutor,
    instruction: Inst,
) -> Result<(), String> {
    handle_cpuid(executor, instruction)
}

/// Handle CPUID Extended Topology (EAX=0xB) - Processor topology enumeration
///
/// Returns x2APIC ID and processor topology information (cores, threads).
pub fn handle_cpuid_extended_topology_info(
    executor: &mut ConcolicExecutor,
    instruction: Inst,
) -> Result<(), String> {
    handle_cpuid(executor, instruction)
}

/// Handle CPUID Extended State (EAX=0xD) - XSAVE/XRESTORE features
///
/// Returns processor extended state enumeration (XSAVE feature set support).
pub fn handle_cpuid_processor_extended_states_info(
    executor: &mut ConcolicExecutor,
    instruction: Inst,
) -> Result<(), String> {
    handle_cpuid(executor, instruction)
}

/// Handle CPUID Quality of Service (EAX=0xF/0x10) - Resource monitoring/allocation
///
/// Returns RDT (Resource Director Technology) QoS capabilities.
pub fn handle_cpuid_quality_of_service_info(
    executor: &mut ConcolicExecutor,
    instruction: Inst,
) -> Result<(), String> {
    handle_cpuid(executor, instruction)
}

/// Handle CPUID Brand String Part 1 (EAX=0x80000002) - Processor name string
///
/// Returns the first 16 characters of the processor brand string.
pub fn handle_cpuid_brand_part1_info(
    executor: &mut ConcolicExecutor,
    instruction: Inst,
) -> Result<(), String> {
    handle_cpuid(executor, instruction)
}

/// Handle CPUID Brand String Part 2 (EAX=0x80000003) - Processor name string
///
/// Returns characters 17-32 of the processor brand string.
pub fn handle_cpuid_brand_part2_info(
    executor: &mut ConcolicExecutor,
    instruction: Inst,
) -> Result<(), String> {
    handle_cpuid(executor, instruction)
}

/// Handle CPUID Brand String Part 3 (EAX=0x80000004) - Processor name string
///
/// Returns characters 33-48 of the processor brand string.
pub fn handle_cpuid_brand_part3_info(
    executor: &mut ConcolicExecutor,
    instruction: Inst,
) -> Result<(), String> {
    handle_cpuid(executor, instruction)
}

/// Handle RDTSCP - Read Time-Stamp Counter and Processor ID
///
/// Returns the current time-stamp counter in EDX:EAX and processor ID in ECX.
/// Serializes instruction execution before reading the counter.
pub fn handle_rdtscp(executor: &mut ConcolicExecutor) -> Result<(), String> {
    // Simulate reading the time-stamp counter
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?;
    let tsc = now.as_secs() * 1_000_000_000 + u64::from(now.subsec_nanos());

    // Split the 64-bit TSC into high and low 32-bit parts
    let edx_value = (tsc >> 32) as u32; // High 32 bits
    let eax_value = tsc as u32; // Low 32 bits

    // Simulate reading from IA32_TSC_AUX
    let core_id = 1; // zorya has 1 core
    let node_id = 1; // zorya has 1 node
    let ecx_value = (node_id << 8) | core_id; // Constructed value containing node and core IDs

    // Set these values in the CPU state
    let mut cpu_state_guard = executor.state.cpu_state.lock().unwrap();
    cpu_state_guard
        .set_register_value_by_offset(
            0x10,
            ConcolicVar::new_concrete_and_symbolic_int(
                edx_value.into(),
                SymbolicVar::new_int(edx_value.try_into().unwrap(), executor.context, 32)
                    .to_bv(executor.context),
                executor.context,
            ),
            32,
        )
        .map_err(|e| format!("Failed to set EDX: {}", e))?;
    cpu_state_guard
        .set_register_value_by_offset(
            0x0,
            ConcolicVar::new_concrete_and_symbolic_int(
                eax_value.into(),
                SymbolicVar::new_int(eax_value.try_into().unwrap(), executor.context, 32)
                    .to_bv(executor.context),
                executor.context,
            ),
            32,
        )
        .map_err(|e| format!("Failed to set EAX: {}", e))?;
    cpu_state_guard
        .set_register_value_by_offset(
            0x8,
            ConcolicVar::new_concrete_and_symbolic_int(
                ecx_value,
                SymbolicVar::new_int(ecx_value.try_into().unwrap(), executor.context, 32)
                    .to_bv(executor.context),
                executor.context,
            ),
            32,
        )
        .map_err(|e| format!("Failed to set ECX: {}", e))?;

    drop(cpu_state_guard);

    // Create the concolic variables for the results
    let current_addr_hex = executor
        .current_address
        .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!(
        "{}-{:02}-callother-rdtscp",
        current_addr_hex, executor.instruction_counter
    );
    executor.state.create_or_update_concolic_variable_int(
        &result_var_name,
        eax_value.into(),
        SymbolicVar::Int(BV::from_u64(executor.context, eax_value.into(), 64)),
    );

    Ok(())
}

/// Handle RDTSC - Read Time-Stamp Counter
///
/// Returns the current time-stamp counter value in EDX:EAX.
/// Non-serializing version (allows out-of-order execution).
pub fn handle_rdtsc(executor: &mut ConcolicExecutor) -> Result<(), String> {
    // Simulate reading the time-stamp counter
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?;
    let tsc = now.as_secs() * 1_000_000_000 + u64::from(now.subsec_nanos());

    // Split the 64-bit TSC into high and low 32-bit parts
    let edx_value = (tsc >> 32) as u32; // High 32 bits
    let eax_value = tsc as u32; // Low 32 bits

    // Set these values in the CPU state
    let mut cpu_state_guard = executor.state.cpu_state.lock().unwrap();
    cpu_state_guard
        .set_register_value_by_offset(
            0x10,
            ConcolicVar::new_concrete_and_symbolic_int(
                edx_value.into(),
                SymbolicVar::new_int(edx_value.try_into().unwrap(), executor.context, 32)
                    .to_bv(executor.context),
                executor.context,
            ),
            32,
        )
        .map_err(|e| format!("Failed to set EDX: {}", e))?;
    cpu_state_guard
        .set_register_value_by_offset(
            0x0,
            ConcolicVar::new_concrete_and_symbolic_int(
                eax_value.into(),
                SymbolicVar::new_int(eax_value.try_into().unwrap(), executor.context, 32)
                    .to_bv(executor.context),
                executor.context,
            ),
            32,
        )
        .map_err(|e| format!("Failed to set EAX: {}", e))?;

    drop(cpu_state_guard);

    // Create the concolic variables for the results
    let current_addr_hex = executor
        .current_address
        .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!(
        "{}-{:02}-callother-rdtsc",
        current_addr_hex, executor.instruction_counter
    );
    executor.state.create_or_update_concolic_variable_int(
        &result_var_name,
        eax_value.into(),
        SymbolicVar::Int(BV::from_u64(executor.context, eax_value.into(), 64)),
    );

    Ok(())
}

/// Handle SWI - Software Interrupt
///
/// Triggers a software interrupt with the specified interrupt number.
/// Currently handles INT3 (debug breakpoint), others cause execution abort.
fn handle_swi(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Assume that the instruction parsing guarantees an immediate constant that is the interrupt number
    let interrupt_number = if let Some(Varnode {
        var: Var::Const(interrupt_number_str),
        ..
    }) = instruction.inputs.get(0)
    {
        u64::from_str_radix(interrupt_number_str.trim_start_matches("0x"), 16).map_err(|_| {
            format!(
                "Failed to parse interrupt number '{}'",
                interrupt_number_str
            )
        })?
    } else {
        return Err("SWI operation requires a valid interrupt number.".to_string());
    };
    match interrupt_number {
        // INT3 (debug breakpoint) handling
        0x3 => {
            log!(
                executor.trace_logger,
                "INT3 (debug breakpoint) encountered. Aborting execution."
            );
            let rip_value = {
                let cpu_state_guard = executor.state.cpu_state.lock().unwrap();
                let rip_value = cpu_state_guard.get_register_by_offset(288, 64);
                rip_value
                    .ok_or("Failed to retrieve RIP register value.")?
                    .get_concrete_value()?
            };

            // Create a concolic variable for the result
            let current_addr_hex = executor
                .current_address
                .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
            let result_var_name = format!(
                "{}-{:02}-callother-swi",
                current_addr_hex, executor.instruction_counter
            );
            executor.state.create_or_update_concolic_variable_int(
                &result_var_name,
                rip_value,
                SymbolicVar::Int(BV::from_u64(executor.context, rip_value, 64)),
            );

            Err("Execution aborted due to INT3 (debug breakpoint).".to_string())
        }
        // Add handling for other interrupts as needed
        _ => {
            // In overlay mode (speculative execution), gracefully handle unimplemented interrupts
            // These are typically unreachable code paths (e.g., BIOS interrupts like INT 0x10 in Linux binaries)
            if executor.is_overlay_mode() {
                log!(
                    executor.state.logger,
                    "[OVERLAY] Ignoring unimplemented SWI {} (speculative path - likely unreachable in practice)",
                    interrupt_number
                );
                // Return success - this is a speculative path that wouldn't execute in practice
                return Ok(());
            }

            // In normal execution, unhandled interrupts are errors
            eprintln!(
                "Unhandled software interrupt (SWI) encountered: {}",
                interrupt_number
            );
            Err(format!(
                "Unhandled software interrupt (SWI) encountered: {}",
                interrupt_number
            ))
        }
    }
}

/// Handle PSHUFB - Packed Shuffle Bytes (SSSE3)
///
/// Not implemented for AMD64 Opteron G1 (lacks SSSE3 support).
pub fn handle_pshufb(_executor: &mut ConcolicExecutor, _instruction: Inst) -> Result<(), String> {
    panic!("PSHUFB is not supported on AMD64 Opteron G1.");
}

/// Handle PSHUFHW - Shuffle Packed High Words (SSE2)
///
/// Not implemented for AMD64 Opteron G1.
pub fn handle_pshufhw(_executor: &mut ConcolicExecutor, _instruction: Inst) -> Result<(), String> {
    panic!("PSHUFHW is not supported on AMD64 Opteron G1.");
}

/// Handle VMOVDQU - Move Unaligned Packed Integer Values (AVX)
///
/// Not implemented for AMD64 Opteron G1 (lacks AVX support).
pub fn handle_vmovdqu_avx(
    _executor: &mut ConcolicExecutor,
    _instruction: Inst,
) -> Result<(), String> {
    panic!("VMOVDQU (AVX) is not supported on AMD64 Opteron G1.");
}

/// Handle VMOVNTDQ - Store Packed Integers Using Non-Temporal Hint (AVX)
///
/// Not implemented for AMD64 Opteron G1 (lacks AVX support).
pub fn handle_vmovntdq_avx(
    _executor: &mut ConcolicExecutor,
    _instruction: Inst,
) -> Result<(), String> {
    panic!("VMOVNTDQ (AVX) is not supported on AMD64 Opteron G1.");
}

/// Handle VPTEST - Logical Compare (AVX)
///
/// Not implemented for AMD64 Opteron G1 (lacks AVX support).
pub fn handle_vptest_avx(
    _executor: &mut ConcolicExecutor,
    _instruction: Inst,
) -> Result<(), String> {
    panic!("VPTEST (AVX) is not supported on AMD64 Opteron G1.");
}

/// Handle VPXOR - Bitwise Logical XOR (AVX)
///
/// Not implemented for AMD64 Opteron G1 (lacks AVX support).
pub fn handle_vpxor_avx(
    _executor: &mut ConcolicExecutor,
    _instruction: Inst,
) -> Result<(), String> {
    panic!("VPXOR (AVX) is not supported on AMD64 Opteron G1.");
}

/// Handle VPAND - Bitwise Logical AND (AVX2)
///
/// Not implemented for AMD64 Opteron G1 (lacks AVX2 support).
pub fn handle_vpand_avx2(
    _executor: &mut ConcolicExecutor,
    _instruction: Inst,
) -> Result<(), String> {
    panic!("VPAND (AVX2) is not supported on AMD64 Opteron G1.");
}

/// Handle VPCMPEQB - Compare Packed Bytes for Equality (AVX2)
///
/// Not implemented for AMD64 Opteron G1 (lacks AVX2 support).
pub fn handle_vpcmpeqb_avx2(
    _executor: &mut ConcolicExecutor,
    _instruction: Inst,
) -> Result<(), String> {
    panic!("VPCMPEQB (AVX2) is not supported on AMD64 Opteron G1.");
}

/// Handle VPBROADCASTB - Broadcast Byte (AVX2)
///
/// Not implemented for AMD64 Opteron G1 (lacks AVX2 support).
pub fn handle_vpbroadcastb_avx2(
    _executor: &mut ConcolicExecutor,
    _instruction: Inst,
) -> Result<(), String> {
    panic!("VPBROADCASTB (AVX2) is not supported on AMD64 Opteron G1.");
}

/// Handle VPMULLW - Multiply Packed Signed Word Integers (AVX)
///
/// Performs element-wise multiplication of packed 16-bit signed integers and stores
/// the lower 16 bits of each 32-bit product. Supports 128-bit (XMM) or 256-bit (YMM) operands.
pub fn handle_vpmullw_avx(
    executor: &mut ConcolicExecutor,
    instruction: Inst,
) -> Result<(), String> {
    // Validate instruction format
    if instruction.inputs.len() < 3 {
        return Err(format!(
            "VPMULLW requires at least 3 inputs, got {}",
            instruction.inputs.len()
        ));
    }

    // Input 1 and 2 are the source operands
    let src1_varnode = &instruction.inputs[1];
    let src2_varnode = &instruction.inputs[2];

    log!(
        executor.trace_logger,
        "VPMULLW src1: {:?}, src2: {:?}",
        src1_varnode,
        src2_varnode
    );

    // Fetch source values
    let src1 = executor
        .varnode_to_concolic(src1_varnode)
        .map_err(|e| format!("Failed to fetch src1: {}", e))?;
    let src2 = executor
        .varnode_to_concolic(src2_varnode)
        .map_err(|e| format!("Failed to fetch src2: {}", e))?;

    // Determine the size (128-bit = 8 words, 256-bit = 16 words)
    let size_bits = src1_varnode.size.to_bitvector_size();
    let num_words = (size_bits / 16) as usize; // Number of 16-bit words

    log!(
        executor.trace_logger,
        "VPMULLW processing {} x 16-bit words (total {} bits)",
        num_words,
        size_bits
    );

    // Extract src1 words
    let concrete_val1 = src1.get_full_concrete_value();
    let concrete_u64s1 = match &concrete_val1 {
        ConcreteVar::Int(v) => vec![*v],
        ConcreteVar::LargeInt(v) => v.clone(),
        _ => vec![0],
    };
    let symbolic_bv1 = src1.get_symbolic_value_bv(executor.context);
    let symbolic_bvs1 = match &src1 {
        ConcolicEnum::ConcolicVar(var) => match &var.symbolic {
            SymbolicVar::LargeInt(bvs) => bvs.clone(),
            _ => vec![symbolic_bv1.clone()],
        },
        ConcolicEnum::CpuConcolicValue(cpu) => match &cpu.symbolic {
            SymbolicVar::LargeInt(bvs) => bvs.clone(),
            _ => vec![symbolic_bv1.clone()],
        },
        _ => vec![symbolic_bv1.clone()],
    };

    let mut src1_words = Vec::new();
    let mut src1_symbolic_words = Vec::new();
    for (chunk_idx, &chunk) in concrete_u64s1.iter().enumerate() {
        for word_in_chunk in 0..4 {
            if src1_words.len() >= num_words {
                break;
            }
            src1_words.push(((chunk >> (word_in_chunk * 16)) & 0xFFFF) as u16);
            let bv_chunk = &symbolic_bvs1[chunk_idx.min(symbolic_bvs1.len() - 1)];
            let bit_start = word_in_chunk * 16;
            let bit_end = bit_start + 15;
            src1_symbolic_words.push(bv_chunk.extract(bit_end as u32, bit_start as u32));
        }
    }

    // Extract src2 words
    let concrete_val2 = src2.get_full_concrete_value();
    let concrete_u64s2 = match &concrete_val2 {
        ConcreteVar::Int(v) => vec![*v],
        ConcreteVar::LargeInt(v) => v.clone(),
        _ => vec![0],
    };
    let symbolic_bv2 = src2.get_symbolic_value_bv(executor.context);
    let symbolic_bvs2 = match &src2 {
        ConcolicEnum::ConcolicVar(var) => match &var.symbolic {
            SymbolicVar::LargeInt(bvs) => bvs.clone(),
            _ => vec![symbolic_bv2.clone()],
        },
        ConcolicEnum::CpuConcolicValue(cpu) => match &cpu.symbolic {
            SymbolicVar::LargeInt(bvs) => bvs.clone(),
            _ => vec![symbolic_bv2.clone()],
        },
        _ => vec![symbolic_bv2.clone()],
    };

    let mut src2_words = Vec::new();
    let mut src2_symbolic_words = Vec::new();
    for (chunk_idx, &chunk) in concrete_u64s2.iter().enumerate() {
        for word_in_chunk in 0..4 {
            if src2_words.len() >= num_words {
                break;
            }
            src2_words.push(((chunk >> (word_in_chunk * 16)) & 0xFFFF) as u16);
            let bv_chunk = &symbolic_bvs2[chunk_idx.min(symbolic_bvs2.len() - 1)];
            let bit_start = word_in_chunk * 16;
            let bit_end = bit_start + 15;
            src2_symbolic_words.push(bv_chunk.extract(bit_end as u32, bit_start as u32));
        }
    }

    // Perform element-wise multiplication and take low 16 bits
    let mut result_concrete_words = Vec::new();
    let mut result_symbolic_words = Vec::new();

    let zero_bv = BV::from_u64(executor.context, 0, 16);

    for i in 0..num_words {
        let w1 = src1_words.get(i).copied().unwrap_or(0) as i16; // Signed 16-bit
        let w2 = src2_words.get(i).copied().unwrap_or(0) as i16; // Signed 16-bit

        // Multiply (results in 32-bit) and take low 16 bits
        let product = (w1 as i32).wrapping_mul(w2 as i32);
        let result_word = (product & 0xFFFF) as u16;
        result_concrete_words.push(result_word);

        // Symbolic multiplication
        let sym1 = src1_symbolic_words.get(i).unwrap_or(&zero_bv);
        let sym2 = src2_symbolic_words.get(i).unwrap_or(&zero_bv);

        let sym_product = sym1.bvmul(sym2); // 16-bit * 16-bit = 16-bit in Z3 (wraps)
        result_symbolic_words.push(sym_product);
    }

    log!(
        executor.trace_logger,
        "VPMULLW computed {} words",
        result_concrete_words.len()
    );

    // Pack result words back into 64-bit chunks
    let mut result_concrete_chunks = Vec::new();
    let mut result_symbolic_chunks = Vec::new();

    for chunk_idx in 0..(num_words + 3) / 4 {
        let base = chunk_idx * 4;
        let mut concrete_chunk = 0u64;

        // Combine 4x16-bit words into one 64-bit chunk
        for word_in_chunk in 0..4 {
            let idx = base + word_in_chunk;
            if idx < num_words {
                let word = result_concrete_words[idx] as u64;
                concrete_chunk |= word << (word_in_chunk * 16);
            }
        }
        result_concrete_chunks.push(concrete_chunk);

        // Combine symbolic words
        let mut symbolic_chunk = result_symbolic_words[base].clone();
        for word_in_chunk in 1..4 {
            let idx = base + word_in_chunk;
            if idx < num_words {
                symbolic_chunk = result_symbolic_words[idx].concat(&symbolic_chunk);
            } else {
                symbolic_chunk = BV::from_u64(executor.context, 0, 16).concat(&symbolic_chunk);
            }
        }
        result_symbolic_chunks.push(symbolic_chunk);
    }

    // Create result
    let result = if result_concrete_chunks.len() == 1 {
        ConcolicVar::new_concrete_and_symbolic_int(
            result_concrete_chunks[0],
            result_symbolic_chunks[0].clone(),
            executor.context,
        )
    } else {
        ConcolicVar::new_concrete_and_symbolic_large_int(
            result_concrete_chunks,
            result_symbolic_chunks,
            executor.context,
        )
    };

    // Write result to output (if output exists)
    // Some VPMULLW variants may not have an explicit output varnode
    if instruction.output.is_some() {
        executor.handle_output(instruction.output.as_ref(), result)?;
    } else {
        log!(
            executor.trace_logger,
            "VPMULLW: No output varnode, result computed but not stored"
        );
    }

    Ok(())
}

/// Handle VBROADCASTSD - Broadcast Double-Precision Float (AVX)
///
/// Broadcasts a 64-bit double-precision floating-point value to all four 64-bit lanes
/// of a 256-bit YMM register.
pub fn handle_vbroadcastsd_avx(
    executor: &mut ConcolicExecutor,
    instruction: Inst,
) -> Result<(), String> {
    // Validate instruction format
    // Expected: CallOther with 3 inputs: [const_index, dest_ymm, src_xmm/mem]
    if instruction.inputs.len() < 3 {
        return Err(format!(
            "VBROADCASTSD requires at least 3 inputs, got {}",
            instruction.inputs.len()
        ));
    }

    // Input 1 is the destination YMM register (256 bits)
    // Input 2 is the source (64-bit value to broadcast)
    let source_varnode = &instruction.inputs[2];

    log!(
        executor.trace_logger,
        "VBROADCASTSD source: {:?}",
        source_varnode
    );

    // Fetch the 64-bit source value
    let source_value = executor
        .varnode_to_concolic(source_varnode)
        .map_err(|e| format!("Failed to fetch source value: {}", e))?;

    // Extract the 64-bit value (concrete and symbolic)
    let concrete_64bit = source_value.get_concrete_value();
    let symbolic_64bit_bv = source_value.get_symbolic_value_bv(executor.context);

    log!(
        executor.trace_logger,
        "Broadcasting 64-bit value: concrete=0x{:016x}, symbolic_size={}",
        concrete_64bit,
        symbolic_64bit_bv.get_size()
    );

    // Ensure source is 64 bits
    let symbolic_64bit = if symbolic_64bit_bv.get_size() < 64 {
        symbolic_64bit_bv.zero_ext(64 - symbolic_64bit_bv.get_size())
    } else if symbolic_64bit_bv.get_size() > 64 {
        symbolic_64bit_bv.extract(63, 0)
    } else {
        symbolic_64bit_bv.clone()
    };

    // Broadcast to 4x64-bit values (256 bits total for YMM)
    // YMM register layout: [bits 0-63, bits 64-127, bits 128-191, bits 192-255]
    // All four 64-bit lanes get the same value
    let concrete_chunks = vec![
        concrete_64bit,
        concrete_64bit,
        concrete_64bit,
        concrete_64bit,
    ];
    let symbolic_chunks = vec![
        symbolic_64bit.clone(),
        symbolic_64bit.clone(),
        symbolic_64bit.clone(),
        symbolic_64bit,
    ];

    // Create the result as a LargeInt (256 bits = 4 x 64-bit chunks)
    let result = ConcolicVar::new_concrete_and_symbolic_large_int(
        concrete_chunks,
        symbolic_chunks,
        executor.context,
    );

    log!(
        executor.trace_logger,
        "VBROADCASTSD result: 4 lanes of 0x{:016x}",
        concrete_64bit
    );

    // Write result to output (destination YMM register)
    executor.handle_output(instruction.output.as_ref(), result)?;

    Ok(())
}

/// Handle PSHUFW (Packed Shuffle Word) - CALLOTHER index 0x9a (154)
///
/// PSHUFW shuffles the words in the source MMX register according to an 8-bit immediate order operand.
/// Each 2-bit field in the order operand selects which of the 4 source words to copy to the destination.
///
/// Instruction format: PSHUFW mm, mm/m64, imm8
pub fn handle_pshufw(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Get the immediate shuffle control byte (should be in inputs[1])
    let shuffle_control = match instruction.inputs.get(3) {
        Some(Varnode {
            var: Var::Const(val),
            ..
        }) => {
            let val_str = val.trim_start_matches("0x");
            u8::from_str_radix(val_str, 16)
                .map_err(|_| format!("Failed to parse shuffle control: {}", val))?
        }
        _ => {
            return Err("PSHUFW requires shuffle control as constant immediate".to_string());
        }
    };

    // Get source operand (input[1] - the MMX register or memory)
    let src_var = executor
        .varnode_to_concolic(&instruction.inputs[1])
        .map_err(|e| e.to_string())?;
    let src_concrete = src_var.get_concrete_value();

    log!(
        executor.trace_logger,
        "PSHUFW: source=0x{:016x}, shuffle_control=0x{:02x}",
        src_concrete,
        shuffle_control
    );

    // Extract the 4 words (16-bit each) from source
    let word0 = (src_concrete >> 0) & 0xFFFF;
    let word1 = (src_concrete >> 16) & 0xFFFF;
    let word2 = (src_concrete >> 32) & 0xFFFF;
    let word3 = (src_concrete >> 48) & 0xFFFF;
    let words = [word0, word1, word2, word3];

    // Shuffle according to control byte
    // Bits 0-1 select source for dest word 0
    // Bits 2-3 select source for dest word 1
    // Bits 4-5 select source for dest word 2
    // Bits 6-7 select source for dest word 3
    let dest_word0 = words[((shuffle_control >> 0) & 0x3) as usize];
    let dest_word1 = words[((shuffle_control >> 2) & 0x3) as usize];
    let dest_word2 = words[((shuffle_control >> 4) & 0x3) as usize];
    let dest_word3 = words[((shuffle_control >> 6) & 0x3) as usize];

    // Combine shuffled words into result
    let result_concrete = dest_word0 | (dest_word1 << 16) | (dest_word2 << 32) | (dest_word3 << 48);

    log!(
        executor.trace_logger,
        "PSHUFW: result=0x{:016x} (words: 0x{:04x}, 0x{:04x}, 0x{:04x}, 0x{:04x})",
        result_concrete,
        dest_word0,
        dest_word1,
        dest_word2,
        dest_word3
    );

    // For symbolic execution, we simplify by using the concrete result
    // A full symbolic implementation would need to track each word shuffle symbolically
    let result_symbolic = BV::from_u64(executor.context, result_concrete, 64);

    let result = ConcolicVar::new_concrete_and_symbolic_int(
        result_concrete,
        result_symbolic,
        executor.context,
    );

    // Write result to output MMX register
    executor.handle_output(instruction.output.as_ref(), result)?;

    Ok(())
}
