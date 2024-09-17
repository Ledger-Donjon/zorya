/// Focuses on implementing the execution of the CALLOTHER opcode from Ghidra's Pcode specification
/// This implementation relies on Ghidra 11.0.1 with the specfiles in /specfiles

use crate::executor::ConcolicExecutor;
use parser::parser::{Inst, Opcode, Var, Varnode};
use z3::ast::BV;
use std::{io::Write, process, time::{SystemTime, UNIX_EPOCH}};

use super::{executor_callother_syscalls, ConcolicEnum, ConcolicVar, SymbolicVar};

macro_rules! log {
    ($logger:expr, $($arg:tt)*) => {{
        writeln!($logger, $($arg)*).unwrap();
    }};
}

pub fn handle_callother(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    let operation_index = match instruction.inputs.get(0) {
        Some(Varnode { var: Var::Const(index), .. }) => {
            let index = index.trim_start_matches("0x"); // Remove "0x" if present
            u32::from_str_radix(index, 16) // Parse as base-16 number
                .map_err(|_| format!("Failed to parse operation index '{}'", index))
        },
        _ => Err("CALLOTHER operation requires the first input to be a constant index.".to_string()),
    }?;

    match operation_index {
        // Operations probably used in Go runtime
        0x5 => executor_callother_syscalls::handle_syscall(executor),
        0xb => handle_rdtscp(executor),
        0x10 => handle_swi(executor, instruction),
        0x11 => handle_lock(executor),
        0x12 => handle_unlock(executor),
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
        0x13a => handle_vmovdqu_avx(executor, instruction), 
        0x144 => handle_vmovntdq_avx(executor, instruction), 
        0x1be => handle_vptest_avx(executor, instruction),
        0x1c7 => handle_vpxor_avx(executor, instruction),
        0x203 => handle_vpand_avx2(executor, instruction),
        0x209 => handle_vpcmpeqb_avx2(executor, instruction),
        0x25d => handle_vpbroadcastb_avx2(executor, instruction),
        _ => {
            // if the callother number is not handled, stop the execution
            log!(executor.state.logger.clone(), "Unhandled CALLOTHER number: {}", operation_index);
            process::exit(1);            
        }
    }
}

pub fn handle_lock(executor: &mut ConcolicExecutor) -> Result<(), String> {
    // the locking mechanism acts as a barrier to prevent other threads from accessing the same resource,
    // and mainly for CPU registers. However, in this context, we can ignore it because the locking and 
    // unlocking are already handled by the CPU state lock mechanism.
    // We considere that this operation has no impact on the symbolic execution
    log!(executor.state.logger.clone(), "This CALLOTHER operation is a LOCK operation.");
    Ok(())
}

pub fn handle_unlock(executor: &mut ConcolicExecutor) -> Result<(), String> {
    // the locking mechanism acts as a barrier to prevent other threads from accessing the same resource,
    // and mainly for CPU registers. However, in this context, we can ignore it because the locking and 
    // unlocking are already handled by the CPU state lock mechanism.
    // We considere that this operation has no impact on the symbolic execution
    log!(executor.state.logger.clone(), "This CALLOTHER operation is an UNLOCK operation.");
    Ok(())
}

pub fn handle_cpuid(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    log!(executor.state.logger.clone(), "This CALLOTHER operation is an CPUID operation.");

    // Memory starting address for EAX, EBX, ECX, EDX
    let base_address = 0x300000;

    // Register offsets for EAX, EBX, ECX, and EDX
    let eax_offset = 0x0;

    // Lock the CPU state to read/write registers
    let cpu_state_guard = executor.state.cpu_state.lock().unwrap();
    // Retrieve the current value of the EAX register to determine the CPUID function requested
    let eax_input = cpu_state_guard.get_register_by_offset(eax_offset, 32)
        .ok_or("Failed to retrieve EAX register value.")?
        .get_concrete_value()?;

    log!(executor.state.logger.clone(), "CPUID function requested: 0x{:x}", eax_input);

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
        },
        // CPUID called with EAX = 1: Processor Info and Feature Bits
        1 => {
            // Family 15, Model 6, Stepping 1 based on actual Opteron G1 characteristics
            eax = 0x00000f61; // Family, Model, Stepping
            ebx = 0x00000800; // Initial APIC ID
            ecx = 0x80000001; // SSE3 supported
            edx = 0x078bfbfd; // The features supported like MMX, SSE, SSE2 etc
        },
        2 => {
            // Cache descriptor information, hard-coded as per Intel manuals or synthesized
            eax = 0x665B5001;
            ebx = 0x00000000;
            ecx = 0x00000000;
            edx = 0x007A7000;
        },
        3..=4 => {
            // reserved or used for system-specific functions
            eax = 0;
            ebx = 0;
            ecx = 0;
            edx = 0;
        },
        5 => {
            // MONITOR/MWAIT
            eax = 0x00000040; // Smallest monitor-line size in bytes
            ebx = 0x00000040; // Largest monitor-line size in bytes
            ecx = 0x00000003; // Enumeration of Monitor-MWAIT extensions
            edx = 0x00000000; // Number of C-states using MWAIT
        },
        0x20000000 => {
            eax = 0x00000000;
            ebx = 0x00000000;
            ecx = 0x00000003; 
            edx = 0x00000000;
        },
        0x40000000 => {
            eax = 0x40000001; // Indicates the highest function available for hypervisor
            ebx = 0x54474354; // "TGCT"
            ecx = 0x43544743; // "CTGC"
            edx = 0x47435447; // "GCTG"
        },
        0x40000001 => {
            eax = 0x00000000;
            ebx = 0x00000000;
            ecx = 0x00000000;
            edx = 0x00000000;
        },
        0x40000100 => {
            eax = 0x00000000;
            ebx = 0x00000000;
            ecx = 0x00000003; 
            edx = 0x00000000;
        },
        0x80000000 => {
            eax = 0x80000008; // Highest extended function supported
            ebx = 0;
            ecx = 0;
            edx = 0;
        },
        0x80000002..=0x80000004 => {
            // Processor Brand String
            let brand_string = "AMD Opteron Processor        ";
            let brand_bytes = brand_string.as_bytes();
            let chunk = (eax_input - 0x80000002) as usize * 16;
            eax = u32::from_ne_bytes(brand_bytes[chunk..chunk+4].try_into().unwrap());
            ebx = u32::from_ne_bytes(brand_bytes[chunk+4..chunk+8].try_into().unwrap());
            ecx = u32::from_ne_bytes(brand_bytes[chunk+8..chunk+12].try_into().unwrap());
            edx = u32::from_ne_bytes(brand_bytes[chunk+12..chunk+16].try_into().unwrap());
        },
        0x80000006 => {
            // Cache information
            eax = 0x42004200;
            ebx = 0x02008140;
            ecx = 0x40020140; // L2 cache details
            edx = 0x00000000; // L3 cache details
        },
        0x80000007 => {
            // provides information about advanced power management features
            eax = 0;
            ebx = 0;
            ecx = 0;
            edx = 0;
        },
        0x80000008 => {
            eax = 0x00003028; // Virtual and physical address sizes
            ebx = 0;
            ecx = 0;
            edx = 0;
        },
        0x80860000 => {
            eax = 0x00000000;
            ebx = 0x00000000;
            ecx = 0x00000003; 
            edx = 0x00000000;
        },
        0xc0000000 => {
            eax = 0x00000000;
            ebx = 0x00000000;
            ecx = 0x00000003; 
            edx = 0x00000000;
        },
        // if not known, return 0 like in Qemu (https://gitlab.com/qemu-project/qemu/-/blob/4ea7e9cd882f1574c129d67431784fecc426d23b/target/i386/cpu.c?page=8#L7035)
        _ => {
            eax = 0;
            ebx = 0;
            ecx = 0;
            edx = 0;
        },
    }

    // Write the results to memory instead of CPU registers
    let _ = executor.state.memory.write_word(base_address, eax);
    let _ = executor.state.memory.write_word(base_address + 4, ebx);
    let _ = executor.state.memory.write_word(base_address + 8, ecx);
    let _ = executor.state.memory.write_word(base_address + 12, edx);
    log!(executor.state.logger.clone(), "Temporarly writing into memory the values of EAX: 0x{:x}, EBX: 0x{:x}, ECX: 0x{:x}, EDX: 0x{:x}", eax, ebx, ecx, edx);
    
    drop(cpu_state_guard);

    // Set the result in the CPU state
    executor.handle_output(instruction.output.as_ref(), ConcolicVar::new_concrete_and_symbolic_int(base_address, SymbolicVar::new_int(base_address.try_into().unwrap(), executor.context, 64).to_bv(executor.context), executor.context, 64))?;

    // Create the concolic variables for the results
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-callother-cpuid", current_addr_hex, executor.instruction_counter);
    executor.state.create_or_update_concolic_variable_int(&result_var_name, eax_input, SymbolicVar::Int(BV::from_u64(executor.context, eax_input, 64)));

    Ok(())
}

// Handle the AES encryption instruction
pub fn handle_aesenc(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    log!(executor.state.logger.clone(), "This CALLOTHER operation is an AESENC operation.");

    if instruction.opcode != Opcode::CallOther || instruction.inputs.len() != 2 {
        return Err("Invalid instruction format for AESENC".to_string());
    }

    // Fetch concolic variables for the state and round key
    let state_var = executor.varnode_to_concolic(&instruction.inputs[0]).map_err(|e| e.to_string())?;
    let round_key_var = executor.varnode_to_concolic(&instruction.inputs[1]).map_err(|e| e.to_string())?;

    // Perform AES encryption steps
    let state_after_shiftrows = shift_rows(state_var, executor);
    let state_after_subbytes = sub_bytes(state_after_shiftrows, executor);
    let state_after_mixcolumns = mix_columns(state_after_subbytes, executor);
    
    // Final XOR with round key
    let result_state = state_after_mixcolumns.symbolic.to_bv(executor.context).bvxor(&round_key_var.get_symbolic_value_bv(executor.context));
    let result_concrete = state_after_mixcolumns.concrete.to_u64() ^ round_key_var.get_concrete_value();

    // Create a new concolic variable for the result state
    let result_size_bits = instruction.output.as_ref().unwrap().size.to_bitvector_size() as u32;
    let result_value = ConcolicVar::new_concrete_and_symbolic_int(result_concrete, result_state, executor.context, result_size_bits);

    // Set the result in the CPU state
    executor.handle_output(instruction.output.as_ref(), result_value)?;
    
    Ok(())
}

// Mock function to simulate the ShiftRows step in AES
fn shift_rows<'a>(input: ConcolicEnum<'a>, executor: &mut ConcolicExecutor<'a>) -> ConcolicVar<'a> {
    // Typically, this would permute the bytes in the state matrix
    let symbolic = rotate_left(input.get_symbolic_value_bv(executor.context), 8); // Rotate left for simplicity
    let concrete = input.get_concrete_value().rotate_left(8);
    ConcolicVar::new_concrete_and_symbolic_int(concrete, symbolic, executor.context, 128)
}

// Mock function to simulate the SubBytes step in AES
fn sub_bytes<'a>(input: ConcolicVar<'a>, executor: &mut ConcolicExecutor<'a>) -> ConcolicVar<'a> {
    // Typically, this would apply a non-linear byte substitution using an S-box
    let symbolic = input.symbolic.to_bv(executor.context).bvnot(); // Not operation for simplicity
    let concrete = !input.concrete.to_u64();
    ConcolicVar::new_concrete_and_symbolic_int(concrete, symbolic, input.ctx, 128)
}

// Mock function to simulate the MixColumns step in AES
fn mix_columns<'a>(input: ConcolicVar<'a>, executor: &mut ConcolicExecutor<'a>) -> ConcolicVar<'a> {
    // Typically, this would perform matrix multiplication in GF(2^8)
    let symbolic = input.symbolic.to_bv(executor.context).bvmul(&BV::from_u64(input.ctx, 0x02, 128)); // Multiply for simplicity
    let concrete = input.concrete.to_u64() * 2;
    ConcolicVar::new_concrete_and_symbolic_int(concrete, symbolic, input.ctx, 128)
}

// Helper functions for bit manipulations
fn rotate_left(bv: BV, bits: u32) -> BV {
    let size = bv.get_size() as u32;
    bv.extract(size - 1, bits).concat(&bv.extract(bits - 1, 0))
}

pub fn handle_cpuid_basic_info(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Example basic information handler
    handle_cpuid(executor, instruction)
}

pub fn handle_cpuid_version_info(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Example version information handler, might include specific processor version details
    handle_cpuid(executor, instruction)
}

pub fn handle_cpuid_cache_tlb_info(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Cache and TLB configuration details
    handle_cpuid(executor, instruction)
}

pub fn handle_cpuid_serial_info(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Processor serial number information (if applicable)
    handle_cpuid(executor, instruction)
}

pub fn handle_cpuid_deterministic_cache_parameters_info(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Detailed cache parameters
    handle_cpuid(executor, instruction)
}

pub fn handle_cpuid_monitor_mwait_features_info(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // MONITOR/MWAIT features
    handle_cpuid(executor, instruction)
}

pub fn handle_cpuid_thermal_power_management_info(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Thermal and power management capabilities
    handle_cpuid(executor, instruction)
}

pub fn handle_cpuid_extended_feature_enumeration_info(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Extended processor feature flags
    handle_cpuid(executor, instruction)
}

pub fn handle_cpuid_direct_cache_access_info(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Direct Cache Access information
    handle_cpuid(executor, instruction)
}

pub fn handle_cpuid_architectural_performance_monitoring_info(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Performance monitoring features
    handle_cpuid(executor, instruction)
}

pub fn handle_cpuid_extended_topology_info(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Extended topology enumeration
    handle_cpuid(executor, instruction)
}

pub fn handle_cpuid_processor_extended_states_info(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Extended states like XSAVE/XRESTORE capabilities
    handle_cpuid(executor, instruction)
}

pub fn handle_cpuid_quality_of_service_info(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // QoS feature information
    handle_cpuid(executor, instruction)
}

pub fn handle_cpuid_brand_part1_info(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Brand string part 1
    handle_cpuid(executor, instruction)
}

pub fn handle_cpuid_brand_part2_info(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Brand string part 2
    handle_cpuid(executor, instruction)
}

pub fn handle_cpuid_brand_part3_info(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Brand string part 3
    handle_cpuid(executor, instruction)
}

// Handle the Read Time-Stamp Counter and Processor ID (RDTSCP) instruction
pub fn handle_rdtscp(executor: &mut ConcolicExecutor) -> Result<(), String> {
    log!(executor.state.logger.clone(), "This CALLOTHER operation is an RDTSCP operation.");

    // Simulate reading the time-stamp counter
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e| e.to_string())?;
    let tsc = now.as_secs() * 1_000_000_000 + u64::from(now.subsec_nanos());

    // Split the 64-bit TSC into high and low 32-bit parts
    let edx_value = (tsc >> 32) as u32; // High 32 bits
    let eax_value = tsc as u32;         // Low 32 bits

    // Simulate reading from IA32_TSC_AUX
    let core_id = 1; // zorya has 1 core
    let node_id = 1; // zorya has 1 node
    let ecx_value = (node_id << 8) | core_id; // Constructed value containing node and core IDs

    // Set these values in the CPU state
    let mut cpu_state_guard = executor.state.cpu_state.lock().unwrap();
    cpu_state_guard.set_register_value_by_offset(0x10, ConcolicVar::new_concrete_and_symbolic_int(edx_value.into(), SymbolicVar::new_int(edx_value.try_into().unwrap(), executor.context, 32).to_bv(executor.context), executor.context, 32), 32)
        .map_err(|e| format!("Failed to set EDX: {}", e))?;
    cpu_state_guard.set_register_value_by_offset(0x0, ConcolicVar::new_concrete_and_symbolic_int(eax_value.into(), SymbolicVar::new_int(eax_value.try_into().unwrap(), executor.context, 32).to_bv(executor.context), executor.context, 32), 32)
        .map_err(|e| format!("Failed to set EAX: {}", e))?;
    cpu_state_guard.set_register_value_by_offset(0x8, ConcolicVar::new_concrete_and_symbolic_int(ecx_value, SymbolicVar::new_int(ecx_value.try_into().unwrap(), executor.context, 32).to_bv(executor.context), executor.context, 32), 32)
        .map_err(|e| format!("Failed to set ECX: {}", e))?;

    drop(cpu_state_guard);

    // Create the concolic variables for the results
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-callother-rdtscp", current_addr_hex, executor.instruction_counter);
    executor.state.create_or_update_concolic_variable_int(&result_var_name, eax_value.into(), SymbolicVar::Int(BV::from_u64(executor.context, eax_value.into(), 64)));

    Ok(())
}

// Handle the Read Time-Stamp Counter (RDTSC) instruction
pub fn handle_rdtsc(executor: &mut ConcolicExecutor) -> Result<(), String> {
    log!(executor.state.logger.clone(), "This CALLOTHER operation is an RDTSC operation.");

    // Simulate reading the time-stamp counter
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e| e.to_string())?;
    let tsc = now.as_secs() * 1_000_000_000 + u64::from(now.subsec_nanos());

    // Split the 64-bit TSC into high and low 32-bit parts
    let edx_value = (tsc >> 32) as u32; // High 32 bits
    let eax_value = tsc as u32;         // Low 32 bits

    // Set these values in the CPU state
    let mut cpu_state_guard = executor.state.cpu_state.lock().unwrap();
    cpu_state_guard.set_register_value_by_offset(0x10, ConcolicVar::new_concrete_and_symbolic_int(edx_value.into(), SymbolicVar::new_int(edx_value.try_into().unwrap(), executor.context, 32).to_bv(executor.context), executor.context, 32), 32)
        .map_err(|e| format!("Failed to set EDX: {}", e))?;
    cpu_state_guard.set_register_value_by_offset(0x0, ConcolicVar::new_concrete_and_symbolic_int(eax_value.into(), SymbolicVar::new_int(eax_value.try_into().unwrap(), executor.context, 32).to_bv(executor.context), executor.context, 32), 32)
        .map_err(|e| format!("Failed to set EAX: {}", e))?;

    drop(cpu_state_guard);
    
    // Create the concolic variables for the results
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}-{:02}-callother-rdtsc", current_addr_hex, executor.instruction_counter);
    executor.state.create_or_update_concolic_variable_int(&result_var_name, eax_value.into(), SymbolicVar::Int(BV::from_u64(executor.context, eax_value.into(), 64)));

    Ok(())
}

// Handle the Software Interrupt (SWI) instruction
fn handle_swi(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    log!(executor.state.logger.clone(), "This CALLOTHER operation is a SWI operation.");

    // Assume that the instruction parsing guarantees an immediate constant that is the interrupt number
    let interrupt_number = if let Some(Varnode { var: Var::Const(interrupt_number_str), .. }) = instruction.inputs.get(0) {
        u64::from_str_radix(interrupt_number_str.trim_start_matches("0x"), 16)
            .map_err(|_| format!("Failed to parse interrupt number '{}'", interrupt_number_str))?
    } else {
        return Err("SWI operation requires a valid interrupt number.".to_string());
    };
    match interrupt_number {
        // INT3 (debug breakpoint) handling
        0x3 => {
            log!(executor.state.logger.clone(),"INT3 (debug breakpoint) encountered. Aborting execution.");
            let rip_value = {
                let cpu_state_guard = executor.state.cpu_state.lock().unwrap();
                let rip_value = cpu_state_guard.get_register_by_offset(288, 64);
                rip_value.ok_or("Failed to retrieve RIP register value.")?.get_concrete_value()?
            };
            
            // Create a concolic variable for the result
            let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
            let result_var_name = format!("{}-{:02}-callother-swi", current_addr_hex, executor.instruction_counter);
            executor.state.create_or_update_concolic_variable_int(&result_var_name, rip_value, SymbolicVar::Int(BV::from_u64(executor.context, rip_value, 64)));

            Err("Execution aborted due to INT3 (debug breakpoint).".to_string())
        },
        // Add handling for other interrupts as needed
        _ => {
            eprintln!("Unhandled software interrupt (SWI) encountered: {}", interrupt_number);
            Err(format!("Unhandled software interrupt (SWI) encountered: {}", interrupt_number))
        }
    }
    
}

pub fn handle_pshufb(_executor: &mut ConcolicExecutor, _instruction: Inst) -> Result<(), String> {
    panic!("Handle_pshufb is not handled in AMD64 Opteron G1.");
}

pub fn handle_pshufhw(_executor: &mut ConcolicExecutor, _instruction: Inst) -> Result<(), String> {
    panic!("Handle_pshufhw is not handled in AMD64 Opteron G1.");
}

pub fn handle_vmovdqu_avx(_executor: &mut ConcolicExecutor, _instruction: Inst) -> Result<(), String> {
    panic!("Handle_vmovdqu_avx is not handled in AMD64 Opteron G1.");
}

pub fn handle_vmovntdq_avx(_executor: &mut ConcolicExecutor, _instruction: Inst) -> Result<(), String> {
    panic!("Handle_vmovntdq_avx is not handled in AMD64 Opteron G1.");
}

pub fn handle_vptest_avx(_executor: &mut ConcolicExecutor, _instruction: Inst) -> Result<(), String> {
    panic!("handle_vptest_avx is not handled in AMD64 Opteron G1.");
}

pub fn handle_vpxor_avx(_executor: &mut ConcolicExecutor, _instruction: Inst) -> Result<(), String> {
    panic!("Handle_vpxor_avx is not handled in AMD64 Opteron G1.");
}

pub fn handle_vpand_avx2(_executor: &mut ConcolicExecutor, _instruction: Inst) -> Result<(), String> {
    panic!("Handle_vpand_avx2 is not handled in AMD64 Opteron G1.");
}

pub fn handle_vpcmpeqb_avx2(_executor: &mut ConcolicExecutor, _instruction: Inst) -> Result<(), String> {
    panic!("Handle_vpcmpeqb_avx2 is not handled in AMD64 Opteron G1.");
}

pub fn handle_vpbroadcastb_avx2(_executor: &mut ConcolicExecutor, _instruction: Inst) -> Result<(), String> {
    panic!("Handle_vpbroadcastb_avx2 is not handled in AMD64 Opteron G1.");
}


