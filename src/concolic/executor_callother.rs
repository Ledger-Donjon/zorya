/// Focuses on implementing the execution of the CALLOTHER opcode from Ghidra's Pcode specification
/// This implementation relies on Ghidra 11.0.1 with the specfiles in /specfiles

use crate::executor::ConcolicExecutor;
use nix::libc::{SIG_BLOCK, SIG_SETMASK, SIG_UNBLOCK};
use parser::parser::{Inst, Opcode, Var, Varnode};
use z3::ast::BV;
use std::{io::Write, time::{SystemTime, UNIX_EPOCH}};

use super::{ConcolicEnum, ConcolicVar, SymbolicVar};

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

        0x5 => handle_syscall(executor),
        0xb => handle_rdtscp(executor),
        0x10 => handle_swi(executor, instruction),
        0x11 => handle_lock(executor),
        0x12 => handle_unlock(executor),
        0x2c => handle_cpuid(executor),
        0x2d => handle_cpuid_basic_info(executor),
        0x2e => handle_cpuid_version_info(executor),
        0x2f => handle_cpuid_cache_tlb_info(executor),
        0x30 => handle_cpuid_serial_info(executor),
        0x31 => handle_cpuid_deterministic_cache_parameters_info(executor),
        0x32 => handle_cpuid_monitor_mwait_features_info(executor),
        0x33 => handle_cpuid_thermal_power_management_info(executor),
        0x34 => handle_cpuid_extended_feature_enumeration_info(executor),
        0x35 => handle_cpuid_direct_cache_access_info(executor),
        0x36 => handle_cpuid_architectural_performance_monitoring_info(executor),
        0x37 => handle_cpuid_extended_topology_info(executor),
        0x38 => handle_cpuid_processor_extended_states_info(executor),
        0x39 => handle_cpuid_quality_of_service_info(executor),
        0x3a => handle_cpuid_brand_part1_info(executor),
        0x3b => handle_cpuid_brand_part2_info(executor),
        0x3c => handle_cpuid_brand_part3_info(executor),
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
        _ => return Err(format!("Unsupported CALLOTHER operation index: {:x}", operation_index)),
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

pub fn handle_cpuid(executor: &mut ConcolicExecutor) -> Result<(), String> {
    log!(executor.state.logger.clone(), "This CALLOTHER operation is an CPUID operation.");

    // Register offsets for EAX, EBX, ECX, and EDX
    let eax_offset = 0x0;
    let ebx_offset = 0x18; 
    let ecx_offset = 0x8; 
    let edx_offset = 0x10; 

    // Lock the CPU state to read/write registers
    let mut cpu_state_guard = executor.state.cpu_state.lock().unwrap();
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
        3..=5 => {
            // reserved or used for system-specific functions
            eax = 0;
            ebx = 0;
            ecx = 0;
            edx = 0;
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
        0x80000002 => {
            eax = 0x20444d41; // " AMD"
            ebx = 0x6574704f; // "Opte"
            ecx = 0x206e6f72; // "ron "
            edx = 0x20303432; // " G1"
        },
        0x80000003 => {
            eax = 0x6e654728; // Part of the brand string
            ebx = 0x43203120; // More brand string
            ecx = 0x7373616c; 
            edx = 0x74704f20; 
        },
        0x80000004 => {
            eax = 0x6e6f7265; // Ending part of the brand string
            ebx = 0x00000029; // Padding
            ecx = 0x00000000; 
            edx = 0x00000000; 
        },
        0x80000005 => {
            // L1 cache identifiers
            eax = 0x01ff01ff; 
            ebx = 0x01ff01ff; 
            ecx = 0x40020140; 
            edx = 0x40020140; 
        },
        0x80000006 => {
            // L2 cache identifiers
            eax = 0x00000000; 
            ebx = 0x42004200; 
            ecx = 0x02008140; 
            edx = 0x00808140; 
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

    // Update the CPU state with the results of the CPUID function
    cpu_state_guard.set_register_value_by_offset(eax_offset, ConcolicVar::new_concrete_and_symbolic_int(eax.into(), SymbolicVar::new_int(eax.try_into().unwrap(), executor.context, 32).to_bv(executor.context), executor.context, 32), 32)?;
    cpu_state_guard.set_register_value_by_offset(ebx_offset, ConcolicVar::new_concrete_and_symbolic_int(ebx.into(), SymbolicVar::new_int(ebx.try_into().unwrap(), executor.context, 32).to_bv(executor.context), executor.context, 32), 32)?;
    cpu_state_guard.set_register_value_by_offset(ecx_offset, ConcolicVar::new_concrete_and_symbolic_int(ecx.into(), SymbolicVar::new_int(ecx.try_into().unwrap(), executor.context, 32).to_bv(executor.context), executor.context, 32), 32)?;
    cpu_state_guard.set_register_value_by_offset(edx_offset, ConcolicVar::new_concrete_and_symbolic_int(edx.into(), SymbolicVar::new_int(edx.try_into().unwrap(), executor.context, 32).to_bv(executor.context), executor.context, 32), 32)?;

    drop(cpu_state_guard);

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
    handle_output(executor, instruction.output.as_ref(), result_value)?;
    
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

fn handle_output<'ctx>(executor: &mut ConcolicExecutor<'ctx>, output_varnode: Option<&Varnode>, mut result_value: ConcolicVar<'ctx>) -> Result<(), String> {
    if let Some(varnode) = output_varnode {
        // Resize the result_value according to the output size specification
        let size_bits = varnode.size.to_bitvector_size() as u32;
        result_value.resize(size_bits);

        match &varnode.var {
            Var::Unique(id) => {
                let unique_name = format!("Unique(0x{:x})", id);
                executor.unique_variables.insert(unique_name, result_value.clone());
                log!(executor.state.logger.clone(), "Updated unique variable: Unique(0x{:x}) with concrete size {} bits, symbolic size {} bits", id, size_bits, result_value.symbolic.get_size());
                Ok(())
            },
            Var::Register(offset, _) => {
                log!(executor.state.logger.clone(), "Output is a Register type");
                let mut cpu_state_guard = executor.state.cpu_state.lock().unwrap();
                let concrete_value = result_value.concrete.to_u64();

                match cpu_state_guard.set_register_value_by_offset(*offset, result_value.clone(), size_bits) {
                    Ok(_) => {
                        log!(executor.state.logger.clone(), "Updated register at offset 0x{:x} with value 0x{:x}, size {} bits", offset, concrete_value, size_bits);
                        Ok(())
                    },
                    Err(e) => {
                        log!(executor.state.logger.clone(), "Error updating register at offset 0x{:x}: {}", offset, e);
                        // Handle the case where the register offset might be a sub-register
                        let closest_offset = cpu_state_guard.registers.keys().rev().find(|&&key| key < *offset);
                        if let Some(&base_offset) = closest_offset {
                            let diff = *offset - base_offset;
                            let full_reg_size = cpu_state_guard.register_map.get(&base_offset).map(|&(_, size)| size).unwrap_or(64);

                            if (diff * 8) + size_bits as u64 <= full_reg_size as u64 {
                                let original_value = cpu_state_guard.get_register_by_offset(base_offset, full_reg_size).unwrap();
                                let mask = ((1u64 << size_bits) - 1) << (diff * 8);
                                let new_value = (original_value.concrete.to_u64() & !mask) | ((concrete_value & ((1u64 << size_bits) - 1)) << (diff * 8));

                                cpu_state_guard.set_register_value_by_offset(base_offset, result_value.clone(), full_reg_size)
                                    .map_err(|e| {
                                        log!(executor.state.logger.clone(), "Error updating sub-register at offset 0x{:x}: {}", offset, e);
                                        e
                                    })
                                    .and_then(|_| {
                                        log!(executor.state.logger.clone(), "Updated sub-register at offset 0x{:x} with value 0x{:x}, size {} bits", offset, new_value, size_bits);
                                        Ok(())
                                    })
                            } else {
                                Err(format!("Cannot fit value into register at offset 0x{:x}", offset))
                            }
                        } else {
                            Err(format!("No suitable register found for offset 0x{:x}", offset))
                        }
                    }
                }
            },
            _ => {
                log!(executor.state.logger.clone(), "Output type is unsupported");
                Err("Output type not supported".to_string())
            }
        }
    } else {
        Err("No output varnode specified".to_string())
    }
}

pub fn handle_cpuid_basic_info(executor: &mut ConcolicExecutor) -> Result<(), String> {
    // Example basic information handler
    handle_cpuid(executor)
}

pub fn handle_cpuid_version_info(executor: &mut ConcolicExecutor) -> Result<(), String> {
    // Example version information handler, might include specific processor version details
    handle_cpuid(executor)
}

pub fn handle_cpuid_cache_tlb_info(executor: &mut ConcolicExecutor) -> Result<(), String> {
    // Cache and TLB configuration details
    handle_cpuid(executor)
}

pub fn handle_cpuid_serial_info(executor: &mut ConcolicExecutor) -> Result<(), String> {
    // Processor serial number information (if applicable)
    handle_cpuid(executor)
}

pub fn handle_cpuid_deterministic_cache_parameters_info(executor: &mut ConcolicExecutor) -> Result<(), String> {
    // Detailed cache parameters
    handle_cpuid(executor)
}

pub fn handle_cpuid_monitor_mwait_features_info(executor: &mut ConcolicExecutor) -> Result<(), String> {
    // MONITOR/MWAIT features
    handle_cpuid(executor)
}

pub fn handle_cpuid_thermal_power_management_info(executor: &mut ConcolicExecutor) -> Result<(), String> {
    // Thermal and power management capabilities
    handle_cpuid(executor)
}

pub fn handle_cpuid_extended_feature_enumeration_info(executor: &mut ConcolicExecutor) -> Result<(), String> {
    // Extended processor feature flags
    handle_cpuid(executor)
}

pub fn handle_cpuid_direct_cache_access_info(executor: &mut ConcolicExecutor) -> Result<(), String> {
    // Direct Cache Access information
    handle_cpuid(executor)
}

pub fn handle_cpuid_architectural_performance_monitoring_info(executor: &mut ConcolicExecutor) -> Result<(), String> {
    // Performance monitoring features
    handle_cpuid(executor)
}

pub fn handle_cpuid_extended_topology_info(executor: &mut ConcolicExecutor) -> Result<(), String> {
    // Extended topology enumeration
    handle_cpuid(executor)
}

pub fn handle_cpuid_processor_extended_states_info(executor: &mut ConcolicExecutor) -> Result<(), String> {
    // Extended states like XSAVE/XRESTORE capabilities
    handle_cpuid(executor)
}

pub fn handle_cpuid_quality_of_service_info(executor: &mut ConcolicExecutor) -> Result<(), String> {
    // QoS feature information
    handle_cpuid(executor)
}

pub fn handle_cpuid_brand_part1_info(executor: &mut ConcolicExecutor) -> Result<(), String> {
    // Brand string part 1
    handle_cpuid(executor)
}

pub fn handle_cpuid_brand_part2_info(executor: &mut ConcolicExecutor) -> Result<(), String> {
    // Brand string part 2
    handle_cpuid(executor)
}

pub fn handle_cpuid_brand_part3_info(executor: &mut ConcolicExecutor) -> Result<(), String> {
    // Brand string part 3
    handle_cpuid(executor)
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

pub fn handle_syscall(executor: &mut ConcolicExecutor) -> Result<(), String> {
    log!(executor.state.logger.clone(), "This CALLOTHER operation is a SYSCALL operation.");

    // Lock the CPU state and retrieve the value in the RAX register to determine the syscall
    let mut cpu_state_guard = executor.state.cpu_state.lock().unwrap();
    let rax_offset = 0x0; // RAX register offset
    let rax = cpu_state_guard.get_register_by_offset(rax_offset, 64).unwrap().get_concrete_value()?;

    log!(executor.state.logger.clone(), "Syscall number: {}", rax);

    match rax {
        0 => { // sys_read
            log!(executor.state.logger.clone(), "Syscall type: sys_read");
            let fd_offset = 0x38; // RDI register offset for 'fd'
            let fd = cpu_state_guard.get_register_by_offset(fd_offset, 64).unwrap().get_concrete_value()? as u32;

            let buf_ptr_offset = 0x30; // RSI register offset for 'buf_ptr'
            let buf_ptr = cpu_state_guard.get_register_by_offset(buf_ptr_offset, 64).unwrap().get_concrete_value()?;

            let count_offset = 0x10; // RDX register offset for 'count'
            let count = cpu_state_guard.get_register_by_offset(count_offset, 64).unwrap().get_concrete_value()? as usize;

            let mut buffer = vec![0u8; count];
            let bytes_read = executor.state.vfs.read(fd, &mut buffer);

            let _ = executor.state.memory.write_bytes(buf_ptr, &buffer);

            cpu_state_guard.set_register_value_by_offset(rax_offset, ConcolicVar::new_concrete_and_symbolic_int(bytes_read as u64, SymbolicVar::new_int(bytes_read as i32, executor.context, 64).to_bv(executor.context), executor.context, 64), 64)?;
            
            drop(cpu_state_guard);

            // Create the concolic variables for the results
            let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
            let result_var_name = format!("{}-{:02}-callother-sys-read", current_addr_hex, executor.instruction_counter);
            executor.state.create_or_update_concolic_variable_int(&result_var_name, bytes_read.try_into().unwrap(), SymbolicVar::Int(BV::from_u64(executor.context, bytes_read.try_into().unwrap(), 64)));

        },
        1 => { // sys_write
            log!(executor.state.logger.clone(), "Syscall type: sys_write");
            let fd_offset = 0x38;
            let fd = cpu_state_guard.get_register_by_offset(fd_offset, 64).unwrap().get_concrete_value()? as u32;

            let buf_ptr_offset = 0x30;
            let buf_ptr = cpu_state_guard.get_register_by_offset(buf_ptr_offset, 64).unwrap().get_concrete_value()?;

            let count_offset = 0x10;
            let count = cpu_state_guard.get_register_by_offset(count_offset, 64).unwrap().get_concrete_value()? as usize;

            let data = executor.state.memory.read_bytes(buf_ptr, count).map_err(|e| e.to_string())?;
            let bytes_written = executor.state.vfs.write(fd, &data);

            cpu_state_guard.set_register_value_by_offset(rax_offset, ConcolicVar::new_concrete_and_symbolic_int(bytes_written as u64, SymbolicVar::new_int(bytes_written as i32, executor.context, 64).to_bv(executor.context), executor.context, 64), 64)?;
        
            drop(cpu_state_guard);
            
            // Create the concolic variables for the results
            let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
            let result_var_name = format!("{}-{:02}-callother-sys-write", current_addr_hex, executor.instruction_counter);
            executor.state.create_or_update_concolic_variable_int(&result_var_name, bytes_written.try_into().unwrap(), SymbolicVar::Int(BV::from_u64(executor.context, bytes_written.try_into().unwrap(), 64)));
        },
        2 => { // sys_open
            log!(executor.state.logger.clone(), "Syscall type: sys_open");
            let filename_ptr_offset = 0x38;
            let filename_ptr = cpu_state_guard.get_register_by_offset(filename_ptr_offset, 64).unwrap().get_concrete_value()?;

            let filename = executor.state.memory.read_string(filename_ptr).map_err(|e| e.to_string())?;

            let fd = executor.state.vfs.open(&filename);

            cpu_state_guard.set_register_value_by_offset(rax_offset, ConcolicVar::new_concrete_and_symbolic_int(fd as u64, SymbolicVar::new_int(fd as i32, executor.context, 64).to_bv(executor.context), executor.context, 64), 64)?;
        
            drop(cpu_state_guard);
            
            // Create the concolic variables for the results
            let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
            let result_var_name = format!("{}-{:02}-callother-sys-open", current_addr_hex, executor.instruction_counter);
            executor.state.create_or_update_concolic_variable_int(&result_var_name, fd.try_into().unwrap(), SymbolicVar::Int(BV::from_u64(executor.context, fd.try_into().unwrap(), 64)));
        },
        3 => { // sys_close
            log!(executor.state.logger.clone(), "Syscall type: sys_close");
            let fd_offset = 0x38;
            let fd = cpu_state_guard.get_register_by_offset(fd_offset, 64).unwrap().get_concrete_value()? as u32;

            executor.state.vfs.close(fd);

            cpu_state_guard.set_register_value_by_offset(rax_offset, ConcolicVar::new_concrete_and_symbolic_int(0, SymbolicVar::new_int(0, executor.context, 64).to_bv(executor.context), executor.context, 64), 64)?;
        
            drop(cpu_state_guard);
            
            // Create the concolic variables for the results
            let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
            let result_var_name = format!("{}-{:02}-callother-sys-close", current_addr_hex, executor.instruction_counter);
            executor.state.create_or_update_concolic_variable_int(&result_var_name, fd.try_into().unwrap(), SymbolicVar::Int(BV::from_u64(executor.context, fd.try_into().unwrap(), 64)));
        },
        9 => { // sys_mmap
            log!(executor.state.logger.clone(), "Syscall type: sys_mmap");
            let addr = cpu_state_guard.get_register_by_offset(0x38, 64).unwrap().get_concrete_value()?;
            let length = cpu_state_guard.get_register_by_offset(0x30, 64).unwrap().get_concrete_value()? as usize;
            let prot = cpu_state_guard.get_register_by_offset(0x28, 64).unwrap().get_concrete_value()? as i32;
            let flags = cpu_state_guard.get_register_by_offset(0x20, 64).unwrap().get_concrete_value()? as i32;
            let fd = cpu_state_guard.get_register_by_offset(0x18, 64).unwrap().get_concrete_value()? as i32;
            let offset = cpu_state_guard.get_register_by_offset(0x10, 64).unwrap().get_concrete_value()? as usize; 
        
            // Handle mmap logic
            let result_addr = executor.state.memory.mmap(addr, length, prot, flags, fd, offset).map_err(|e| e.to_string())?;
            
            log!(executor.state.logger.clone(), "Mapped memory at addr: 0x{:x}, length: {}, prot: {}, flags: {}, fd: {}, offset: {}", result_addr, length, prot, flags, fd, offset);
        
            // Set return value (the address to which the file has been mapped)
            cpu_state_guard.set_register_value_by_offset(rax_offset, ConcolicVar::new_concrete_and_symbolic_int(result_addr, SymbolicVar::new_int(result_addr as i32, executor.context, 64).to_bv(executor.context), executor.context, 64), 64)?;
            
            drop(cpu_state_guard);

            // Create the concolic variables for the results
            let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
            let result_var_name = format!("{}-{:02}-callother-sys-mmap", current_addr_hex, executor.instruction_counter);
            executor.state.create_or_update_concolic_variable_int(&result_var_name, addr.try_into().unwrap(), SymbolicVar::Int(BV::from_u64(executor.context, addr.try_into().unwrap(), 64)));
        }
        14 => { // sys_sigprocmask
            log!(executor.state.logger.clone(), "Syscall type: sys_sigprocmask");
            // Read the 'how' argument from the RDI register, which specifies the action on the signal mask.
            let how = cpu_state_guard.get_register_by_offset(0x38, 64).unwrap().get_concrete_value()? as i32;

            // Read the pointer to the new signal set from the RSI register.
            let set_ptr = cpu_state_guard.get_register_by_offset(0x30, 64).unwrap().get_concrete_value()?;

            // Read the pointer to the old signal set from the RDX register.
            let oldset_ptr = cpu_state_guard.get_register_by_offset(0x28, 64).unwrap().get_concrete_value()?;

            // If oldset_ptr is not NULL, store the current signal mask at that memory location.
            if oldset_ptr != 0 {
                let old_mask = executor.state.signal_mask;
                let _ = executor.state.memory.write_quad(oldset_ptr, old_mask as u64);
            }

            // If set_ptr is not NULL, apply the new mask to the current signal mask based on the 'how' directive.
            if set_ptr != 0 {
                let new_mask = executor.state.memory.read_quad(set_ptr).unwrap() as u32;
                
                match how {
                    // Add the signals from set to the current mask.
                    SIG_BLOCK => {
                        executor.state.signal_mask |= new_mask;
                    },
                    // Remove the signals from set from the current mask.
                    SIG_UNBLOCK => {
                        executor.state.signal_mask &= !new_mask;
                    },
                    // Set the current mask to the signals from set.
                    SIG_SETMASK => {
                        executor.state.signal_mask = new_mask;
                    },
                    // Handle invalid 'how' arguments.
                    _ => return Err("Invalid 'how' argument for sys_sigprocmask".to_string()),
                }
            }

            // Update the RAX register to indicate successful operation.
            cpu_state_guard.set_register_value_by_offset(0x0, ConcolicVar::new_concrete_and_symbolic_int(0, SymbolicVar::new_int(0, executor.context, 64).to_bv(executor.context), executor.context, 64), 64)?;
        },
        59 => { // sys_execve
            log!(executor.state.logger.clone(), "Syscall type: sys_execve");
            let path_ptr = cpu_state_guard.get_register_by_offset(0x38, 64).unwrap().get_concrete_value()?;
            let argv_ptr = cpu_state_guard.get_register_by_offset(0x30, 64).unwrap().get_concrete_value()?;
            let envp_ptr = cpu_state_guard.get_register_by_offset(0x28, 64).unwrap().get_concrete_value()?;
        
            // Read the file path from memory
            let path = executor.state.memory.read_string(path_ptr).map_err(|e| e.to_string())?;
            log!(executor.state.logger.clone(), "Executing program at path: {}", path);
        
            // Retrieve and log the arguments
            let mut argv = Vec::new();
            let mut i = 0;
            loop {
                let arg_ptr = executor.state.memory.read_quad(argv_ptr + (i * 8)).map_err(|e| e.to_string())?;
                if arg_ptr == 0 {
                    break; // Null pointer indicates the end of the argv array
                }
                let arg = executor.state.memory.read_string(arg_ptr).map_err(|e| e.to_string())?;
                argv.push(arg);
                i += 1;
            }
            log!(executor.state.logger.clone(), "With arguments: {:?}", argv);
        
            // Retrieve and log the environment variables
            let mut envp = Vec::new();
            let mut j = 0;
            loop {
                let env_ptr = executor.state.memory.read_quad(envp_ptr + (j * 8)).map_err(|e| e.to_string())?;
                if env_ptr == 0 {
                    break; // Null pointer indicates the end of the envp array
                }
                let env = executor.state.memory.read_string(env_ptr).map_err(|e| e.to_string())?;
                envp.push(env);
                j += 1;
            }
            log!(executor.state.logger.clone(), "And environment: {:?}", envp);
        
            // Normally, execve replaces the current process with a new process specified by path.
            // In a symbolic execution framework, this might entail loading the program for analysis,
            // or simply logging that this would happen.
            log!(executor.state.logger.clone(), "Simulated execve would now load and execute the new program.");

            drop(cpu_state_guard);
            
            // Create the concolic variables for the results
            let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
            let result_var_name = format!("{}-{:02}-callother-sys-execve", current_addr_hex, executor.instruction_counter);
            executor.state.create_or_update_concolic_variable_int(&result_var_name, path_ptr.try_into().unwrap(), SymbolicVar::Int(BV::from_u64(executor.context, path_ptr.try_into().unwrap(), 64)));
        }
        60 => { // sys_exit
            log!(executor.state.logger.clone(), "Syscall type: sys_exit");
            let status = cpu_state_guard.get_register_by_offset(0x38, 64).unwrap().get_concrete_value()?;
            log!(executor.state.logger.clone(), "Exiting with status code: {}", status);
            drop(cpu_state_guard);

            // Create the concolic variables for the results
            let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
            let result_var_name = format!("{}-{:02}-callother-sys-exit", current_addr_hex, executor.instruction_counter);
            executor.state.create_or_update_concolic_variable_int(&result_var_name, status.try_into().unwrap(), SymbolicVar::Int(BV::from_u64(executor.context, status.try_into().unwrap(), 64)));
        },
        158 => { // sys_arch_prctl : set architecture-specific thread state
            log!(executor.state.logger.clone(), "Syscall type: sys_arch_prctl");
            let code = cpu_state_guard.get_register_by_offset(0x38, 64).unwrap().get_concrete_value()?;
            let addr = cpu_state_guard.get_register_by_offset(0x30, 64).unwrap().get_concrete_value()?;
            
            log!(executor.state.logger.clone(), "Setting architecture-specific setting code {} to address {}", code, addr);

            drop(cpu_state_guard);
            
            // Create the concolic variables for the results
            let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
            let result_var_name = format!("{}-{:02}-callother-sys-arch_prctl", current_addr_hex, executor.instruction_counter);
            executor.state.create_or_update_concolic_variable_int(&result_var_name, code.try_into().unwrap(), SymbolicVar::Int(BV::from_u64(executor.context, code.try_into().unwrap(), 64)));
        },
        204 => { // sys_sched_getaffinity : gets the CPU affinity mask of a process
            log!(executor.state.logger.clone(), "Syscall type: sys_sched_getaffinity");
            let pid = cpu_state_guard.get_register_by_offset(0x38, 64).unwrap().get_concrete_value()? as u32;
            let cpusetsize = cpu_state_guard.get_register_by_offset(0x30, 64).unwrap().get_concrete_value()? as usize;
            let mask_ptr = cpu_state_guard.get_register_by_offset(0x28, 64).unwrap().get_concrete_value()?;

            // Simulate getting the CPU affinity for the given pid and cpusetsize
            let simulated_mask = (1u64 << cpusetsize) - 1; // This sets 'cpusetsize' bits to 1
            executor.state.memory.write_quad(mask_ptr, simulated_mask).map_err(|e| e.to_string())?;

            log!(executor.state.logger.clone(), "Getting CPU affinity for PID {}, size {}", pid, cpusetsize);

            drop(cpu_state_guard);
            
            // Create the concolic variables for the results
            let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
            let result_var_name = format!("{}-{:02}-callother-sys-sched_getaffinity", current_addr_hex, executor.instruction_counter);
            executor.state.create_or_update_concolic_variable_int(&result_var_name, simulated_mask.try_into().unwrap(), SymbolicVar::Int(BV::from_u64(executor.context, simulated_mask.try_into().unwrap(), 64)));
        },
        257 => { // sys_openat : open file relative to a directory file descriptor
            log!(executor.state.logger.clone(), "Syscall type: sys_openat");
            let pathname_ptr = cpu_state_guard.get_register_by_offset(0x30, 64).unwrap().get_concrete_value()?;
            let flags = cpu_state_guard.get_register_by_offset(0x28, 64).unwrap().get_concrete_value()? as i32;
            let mode = cpu_state_guard.get_register_by_offset(0x20, 64).unwrap().get_concrete_value()? as u32;
            
            let pathname = executor.state.memory.read_string(pathname_ptr).map_err(|e| e.to_string())?;
            let fd = executor.state.vfs.open(&pathname); // Simulate opening the file
            log!(executor.state.logger.clone(), "Opened file at path: '{}' with flags: {}, mode: {}, returned FD: {}", pathname, flags, mode, fd);
            
            cpu_state_guard.set_register_value_by_offset(rax_offset, ConcolicVar::new_concrete_and_symbolic_int(fd as u64, SymbolicVar::new_int(fd as i32, executor.context, 64).to_bv(executor.context), executor.context, 64), 64)?;
        
            drop(cpu_state_guard);
            
            // Create the concolic variables for the results
            let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
            let result_var_name = format!("{}-{:02}-callother-sys-openat", current_addr_hex, executor.instruction_counter);
            executor.state.create_or_update_concolic_variable_int(&result_var_name, pathname_ptr.try_into().unwrap(), SymbolicVar::Int(BV::from_u64(executor.context, pathname_ptr.try_into().unwrap(), 64)));
        },
        _ => return Err(format!("Unsupported syscall ID : {}", rax))
    }

    Ok(())
}
