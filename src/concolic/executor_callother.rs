use std::sync::MutexGuard;

/// Focuses on implementing the execution of the CALLOTHER opcode from Ghidra's Pcode specification
/// This implementation relies on Ghidra 11.0.1 with the specfiles in /specfiles

use crate::{executor::ConcolicExecutor, state::{cpu_state::GLOBAL_CPU_STATE, CpuState}};
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
    let mut cpu_state_guard = GLOBAL_CPU_STATE.lock().unwrap();

    // Parsing syscall number from the "rax" register
    let syscall_number_str = cpu_state_guard.get_register_value_by_name("rax")
        .ok_or_else(|| "Syscall number not found".to_string())?;
    let syscall_number = u64::from_str_radix(syscall_number_str.trim_start_matches("0x"), 16)
        .map_err(|_| "Failed to parse syscall number".to_string())?;

    match syscall_number {
        // Open syscall handling
        2 => handle_sys_open(executor, &mut cpu_state_guard),
        // Read syscall handling
        0 => handle_sys_read(executor, &mut cpu_state_guard),
        // Write syscall handling
        1 => handle_sys_write(executor, &mut cpu_state_guard),
        _ => Err("Unsupported syscall".to_string()),
    }
}

fn handle_sys_open(executor: &mut ConcolicExecutor, cpu_state_guard: &mut MutexGuard<CpuState>) -> Result<(), String> {
    let path_addr_str = cpu_state_guard.get_register_value_by_name("rdi")
        .ok_or_else(|| "Path address for open not found".to_string())?;
    let path_addr = u64::from_str_radix(path_addr_str.trim_start_matches("0x"), 16)
        .map_err(|_| "Failed to parse path address".to_string())?;

    let path = executor.state.memory.read_string(path_addr)
        .map_err(|e| e.to_string())?;
    let file_descriptor = executor.state.vfs.open(&path)
        .map_err(|e| e.to_string())?;

    let fd_id = executor.state.next_fd_id();
    executor.state.file_descriptors.insert(fd_id, file_descriptor);
    // Register the file path with the newly created file descriptor ID.
    executor.state.register_fd_path(fd_id, std::path::PathBuf::from(path));
    cpu_state_guard.set_register_value_by_name("rax", format!("0x{:x}", fd_id));

    let rip_str = cpu_state_guard.get_register_value_by_name("rip")
        .ok_or_else(|| "RIP value not found".to_string())?;
    let result_var_name = format!("syscall_open_{}", rip_str);
    executor.state.create_or_update_concolic_var_int(&result_var_name, fd_id as u64, 64);

    Ok(())
}


fn handle_sys_read(executor: &mut ConcolicExecutor, cpu_state_guard: &mut MutexGuard<CpuState>) -> Result<(), String> {
    let fd_id_str = cpu_state_guard.get_register_value_by_name("rdi")
        .ok_or_else(|| "File descriptor for read not found".to_string())?;
    let fd_id = u64::from_str_radix(fd_id_str.trim_start_matches("0x"), 16)
        .map_err(|_| "Failed to parse file descriptor".to_string())?;

    // Convert FD to file path
    let file_path = executor.state.fd_to_path(fd_id)?; 

    // Open file by path 
    let file_descriptor = executor.state.vfs.open(&file_path) 
        .map_err(|e| e.to_string())?;

    let buf_addr_str = cpu_state_guard.get_register_value_by_name("rsi")
        .ok_or_else(|| "Buffer address for read not found".to_string())?;
    let buf_addr = u64::from_str_radix(buf_addr_str.trim_start_matches("0x"), 16)
        .map_err(|_| "Failed to parse buffer address".to_string())?;

    let count_str = cpu_state_guard.get_register_value_by_name("rdx")
        .ok_or_else(|| "Count for read not found".to_string())?;
    let count = usize::from_str_radix(count_str.trim_start_matches("0x"), 16)
        .map_err(|_| "Failed to parse count".to_string())?;

    let mut buffer = vec![0u8; count];
    executor.state.vfs.read(&file_descriptor, &mut buffer, count)
        .map_err(|e| e.to_string())?;

    executor.state.memory.write_memory(buf_addr, &buffer)
        .map_err(|e| e.to_string())?;

    cpu_state_guard.set_register_value_by_name("rax", format!("0x{:x}", buffer.len()));

    let rip_str = cpu_state_guard.get_register_value_by_name("rip").unwrap();
    let result_var_name = format!("syscall_read_{}", rip_str);
    executor.state.create_or_update_concolic_var_int(&result_var_name, buffer.len() as u64, 64);

    Ok(())
}

fn handle_sys_write(executor: &mut ConcolicExecutor, cpu_state_guard: &mut MutexGuard<CpuState>) -> Result<(), String> {
    // Extract the file descriptor ID as a u64 from a hexadecimal string.
    let fd_id_str = cpu_state_guard.get_register_value_by_name("rdi")
        .ok_or_else(|| "File descriptor for write not found".to_string())?;
    let fd_id = u64::from_str_radix(fd_id_str.trim_start_matches("0x"), 16)
        .map_err(|_| "Failed to parse file descriptor".to_string())?;

    // Use fd_to_path to convert fd_id to the file path associated with this file descriptor.
    let file_path = executor.state.fd_to_path(fd_id)
        .map_err(|e| e.to_string())?;

    // Now, instead of opening by fd_id, open the file by its path.
    let mut file_descriptor = executor.state.vfs.open(&file_path)
        .map_err(|e| e.to_string())?;

    // Convert buffer address from a hexadecimal string to a u64.
    let buf_addr_str = cpu_state_guard.get_register_value_by_name("rsi")
        .ok_or_else(|| "Buffer address for write not found".to_string())?;
    let buf_addr = u64::from_str_radix(buf_addr_str.trim_start_matches("0x"), 16)
        .map_err(|_| "Failed to parse buffer address".to_string())?;

    // Convert count from a hexadecimal string to usize.
    let count_str = cpu_state_guard.get_register_value_by_name("rdx")
        .ok_or_else(|| "Count for write not found".to_string())?;
    let count = usize::from_str_radix(count_str.trim_start_matches("0x"), 16)
        .map_err(|_| "Failed to parse count".to_string())?;

    // Read the data from memory to be written to the file.
    let buffer = executor.state.memory.read_memory(buf_addr, count)
        .map_err(|e| e.to_string())?;

    let write_result = executor.state.vfs.write(&mut file_descriptor, &buffer);

    // Assuming vfs.write is corrected to return Result<usize, String> where usize is the number of bytes written.
    match write_result {
        Ok(bytes_written) => {
            cpu_state_guard.set_register_value_by_name("rax", format!("0x{:x}", bytes_written));

            let rip_str = cpu_state_guard.get_register_value_by_name("rip").unwrap();
            let result_var_name = format!("syscall_write_{}", rip_str);
            executor.state.create_or_update_concolic_var_int(&result_var_name, bytes_written as u64, 64);

            Ok(())
        },
        Err(e) => Err(e.to_string())
    }
}


// Handles the Software Interrupt (SWI) operation.
fn handle_swi(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    let cpu_state_guard = GLOBAL_CPU_STATE.lock().unwrap();

    // Extract and handle the software interrupt number
    if let Some(Varnode { var: Var::Const(interrupt_number_str), .. }) = instruction.inputs.get(0) {
        let interrupt_number = u64::from_str_radix(interrupt_number_str.trim_start_matches("0x"), 16)
            .map_err(|_| format!("Failed to parse interrupt number '{}'", interrupt_number_str))?;

        match interrupt_number {
            // INT3 (debug breakpoint) handling
            0x3 => {
                eprintln!("INT3 (debug breakpoint) encountered. Aborting execution.");
                let swi_result_var_name = format!("swi_int3_{}", cpu_state_guard.get_register_value_by_name("rip").unwrap());
                executor.state.create_or_update_concolic_var_int(&swi_result_var_name, 0x3, 8);
                Err("Execution aborted due to INT3 (debug breakpoint).".to_string())
            },
            // Add handling for other interrupts as needed
            _ => {
                eprintln!("Unhandled software interrupt (SWI) encountered: {}", interrupt_number);
                Err(format!("Unhandled software interrupt (SWI) encountered: {}", interrupt_number))
            }
        }
    } else {
        Err("SWI operation requires a valid interrupt number.".to_string())
    }
}