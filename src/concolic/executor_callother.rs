/// Focuses on implementing the execution of the CALLOTHER opcode from Ghidra's Pcode specification
/// This implementation relies on Ghidra 11.0.1 with the specfiles in /specfiles

use crate::executor::ConcolicExecutor;
use parser::parser::{Inst, Var, Varnode};

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
        //0xb => handle_rdtscp(instruction),
        0x10 => handle_swi(executor, instruction),
        // 0x11 => handle_lock(executor, instruction),
        // 0x12 => handle_unlock(executor, instruction),
        // 0x2c => handle_cpuid(executor, instruction),
        // 0x2d => handle_cpuid_basic_info(executor, instruction),
        // 0x2e => handle_cpuid_version_info(executor, instruction),
        // 0x2f => handle_cpuid_cache_tlb_info(executor, instruction),
        // 0x30 => handle_cpuid_serial_info(executor, instruction),
        // 0x31 => handle_cpuid_deterministic_cache_parameters_info(executor, instruction),
        // 0x32 => handle_cpuid_monitor_mwait_features_info(executor, instruction),
        // 0x33 => handle_cpuid_thermal_power_management_info(executor, instruction),
        // 0x34 => handle_cpuid_extended_feature_enumeration_info(executor, instruction),
        // 0x35 => handle_cpuid_direct_cache_access_info(executor, instruction),
        // 0x36 => handle_cpuid_architectural_performance_monitoring_info(executor, instruction),
        // 0x37 => handle_cpuid_extended_topology_info(executor, instruction),
        // 0x38 => handle_cpuid_processor_extended_states_info(executor, instruction),
        // 0x39 => handle_cpuid_quality_of_service_info(executor, instruction),
        // 0x3a => handle_cpuid_brand_part1_info(executor, instruction),
        // 0x3b => handle_cpuid_brand_part2_info(executor, instruction),
        // 0x3c => handle_cpuid_brand_part3_info(executor, instruction),
        // 0x4a => handle_rdtsc(executor, instruction),
        // 0x97 => handle_pshufb(executor, instruction),
        // 0x98 => handle_pshufhw(executor, instruction),
        // 0xdc => handle_aesenc(executor, instruction),
        // 0x13a => handle_vmovdqu_avx(executor, instruction),
        // 0x144 => handle_vmovntdq_avx(executor, instruction),
        // 0x1be => handle_vptest_avx(executor, instruction),
        // 0x1c7 => handle_vpxor_avx(executor, instruction),
        // 0x203 => handle_vpand_avx2(executor, instruction),
        // 0x209 => handle_vpcmpeqb_avx2(executor, instruction),
        // 0x25d => handle_vpbroadcastb_avx2(executor, instruction),
        _ => return Err(format!("Unsupported CALLOTHER operation index: {:x}", operation_index)),
    }
}

pub fn handle_syscall(executor: &mut ConcolicExecutor) -> Result<(), String> {
    let syscall_number = executor.state.cpu_state.gpr.get("RAX").copied()
        .ok_or_else(|| "Syscall number not found".to_string())?;

    match syscall_number {
        // Open
        2 => {
            let path_addr = executor.state.cpu_state.gpr.get("RDI").copied()
                .ok_or_else(|| "Path address for open not found".to_string())?;

            let path = executor.state.memory.read_string(path_addr)
                .map_err(|e| e.to_string())?;

            let file_descriptor = executor.state.vfs.open(&path).map_err(|e| e.to_string())?;

            let fd_id = executor.state.next_fd_id();
            executor.state.file_descriptors.insert(fd_id, file_descriptor);
            executor.state.cpu_state.gpr.insert("RAX".to_string(), fd_id);

            // Update concolic state for open
            let result_var_name = format!("syscall_open_{}", executor.state.cpu_state.pc); // Use PC as a unique identifier
            executor.state.create_or_update_concolic_var_int(&result_var_name, fd_id, 64);

            Ok(())
        },
        // Read
        0 => {
            let fd_id = executor.state.cpu_state.gpr.get("RDI").copied()
                .ok_or_else(|| "File descriptor for read not found".to_string())? as u64;
            let buf_addr = executor.state.cpu_state.gpr.get("RSI").copied()
                .ok_or_else(|| "Buffer address for read not found".to_string())?;
            let count = executor.state.cpu_state.gpr.get("RDX").copied()
                .ok_or_else(|| "Count for read not found".to_string())? as usize;

            if let Some(file_descriptor) = executor.state.file_descriptors.get(&fd_id) {
                let mut buffer = vec![0u8; count];
                executor.state.vfs.read(file_descriptor, &mut buffer, count).map_err(|e| e.to_string())?;
                executor.state.memory.write_memory(buf_addr, &buffer).map_err(|e| e.to_string())?;
                executor.state.cpu_state.gpr.insert("RAX".to_string(), buffer.len() as u64);

                // Update concolic state for read
                let result_var_name = format!("syscall_read_{}", executor.state.cpu_state.pc); // Use PC as a unique identifier
                executor.state.create_or_update_concolic_var_int(&result_var_name, buffer.len() as u64, 64);

                Ok(())
            } else {
                Err("Invalid file descriptor".to_string())
            }
        },
        // Write
        1 => {
            let fd_id = executor.state.cpu_state.gpr.get("RDI").copied()
                .ok_or_else(|| "File descriptor for write not found".to_string())? as u64;
            let buf_addr = executor.state.cpu_state.gpr.get("RSI").copied()
                .ok_or_else(|| "Buffer address for write not found".to_string())?;
            let count = executor.state.cpu_state.gpr.get("RDX").copied()
                .ok_or_else(|| "Count for write not found".to_string())? as usize;

            if let Some(file_descriptor) = executor.state.file_descriptors.get_mut(&fd_id) {
                let buffer = executor.state.memory.read_memory(buf_addr, count).map_err(|e| e.to_string())?;
                executor.state.vfs.write(file_descriptor, &buffer).map_err(|e| e.to_string())?;

                executor.state.cpu_state.gpr.insert("RAX".to_string(), count as u64);

                // Update concolic state for write
                let result_var_name = format!("syscall_write_{}", executor.state.cpu_state.pc); // Use PC as a unique identifier
                executor.state.create_or_update_concolic_var_int(&result_var_name, count as u64, 64);

                Ok(())
            } else {
                Err("Invalid file descriptor".to_string())
            }
        },
        _ => Err("Unsupported syscall".to_string()),
    }
}


// Handles the Software Interrupt (SWI) operation.
fn handle_swi(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    // Extract the interrupt number from the instruction, if available
    if let Some(Varnode { var: Var::Const(interrupt_number), .. }) = instruction.inputs.get(0) {
        // Convert the interrupt number to an integer for processing
        match interrupt_number.parse::<u8>() {
            Ok(0x3) => {
                // INT3 (debug breakpoint) handling
                eprintln!("INT3 (debug breakpoint) encountered. Aborting execution.");

                // Update concolic state
                let swi_result_var_name = format!("swi_int3_{}", executor.state.cpu_state.pc); // Use PC as a unique identifier
                executor.state.create_or_update_concolic_var_int(&swi_result_var_name, 0x3, 8);
                
                return Err("Execution aborted due to INT3 (debug breakpoint).".to_string());
            },
            // Handle other software interrupts ?
            _ => {
                eprintln!("Unhandled software interrupt (SWI) encountered: {}", interrupt_number);
                return Err(format!("Unhandled software interrupt (SWI) encountered: {}", interrupt_number));
            }
        }
    } else {
        // If the interrupt number is missing or invalid, report an error
        return Err("SWI operation requires a valid interrupt number.".to_string());
    }
}

