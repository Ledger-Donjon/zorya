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

    // Directly get the syscall number as u64 from the "rax" register
    let syscall_number = {
        // Access the shared CPU state with a lock
        let cpu_state_guard = executor.state.cpu_state.lock().unwrap();
        // cpu_state_guard.get_register_value("rax")
        //     .ok_or_else(|| "Syscall number not found".to_string())?
    };


    println!("Debug SYSCALL : syscall number is {:?}", syscall_number);

    match syscall_number {
        // Open syscall handling
        // 2 => handle_sys_open(executor),
        // // Read syscall handling
        // 0 => handle_sys_read(executor),
        // Write syscall handling
        //1 => handle_sys_write(executor),
        _ => Err("Unsupported syscall".to_string()),
    }
}

fn handle_sys_open(executor: &mut ConcolicExecutor) -> Result<(), String> {
    // Extract necessary data from CPU state within a limited scope.
    let path_addr = {
        let cpu_state_guard = executor.state.cpu_state.lock().unwrap();
        // cpu_state_guard.get_register_value("rdi")
        //     .ok_or_else(|| "Path address for open not found".to_string())?
    };

    // Fetch the next file descriptor ID without locking the CPU state.
    let fd_id = executor.state.next_fd_id();

    // Proceed with file operations now that we no longer need to lock the CPU state.
    // let path = executor.state.memory.read_string(path_addr)
    //     .map_err(|e| e.to_string())?;

    // let file_descriptor = executor.state.vfs.open(&path)
    //     .map_err(|e| e.to_string())?;

    // Safely store the file descriptor and path.
    // executor.state.file_descriptors.insert(fd_id, file_descriptor);
    // executor.state.register_fd_path(fd_id, std::path::PathBuf::from(path));

    // Lock the CPU state again to update it.
    {
        let mut cpu_state_guard = executor.state.cpu_state.lock().unwrap();
        // cpu_state_guard.set_register_value("rax", fd_id)
        //     .map_err(|e| e.to_string())?;  // Convert error to String
    }

    // Create or update concolic variables.
    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    let result_var_name = format!("{}_{:02}_sys-open", current_addr_hex, executor.instruction_counter);
    //executor.state.create_or_update_concolic_var_int(&result_var_name, fd_id as u64, 64);

    Ok(())
}


fn handle_sys_read(executor: &mut ConcolicExecutor) -> Result<(), String> {
    // let (fd_id, buf_addr, count) = {
    //     let cpu_state_guard = executor.state.cpu_state.lock().unwrap();

    //     let fd_id = cpu_state_guard.get_register_value("rdi")
    //         .ok_or_else(|| "File descriptor for read not found".to_string())?;
    //     let buf_addr = cpu_state_guard.get_register_value("rsi")
    //         .ok_or_else(|| "Buffer address for read not found".to_string())?;
    //     let count = cpu_state_guard.get_register_value("rdx")
    //         .ok_or_else(|| "Count for read not found".to_string())? as usize;
    //     (fd_id, buf_addr, count)
    // };

    // let file_descriptor = executor.state.get_file_descriptor(fd_id)?;
    // let mut buffer = vec![0u8; count];
    // executor.state.vfs.read(file_descriptor, &mut buffer, count)
    //     .map_err(|e| e.to_string())?;

    // executor.state.memory.write_memory(buf_addr, &buffer)
    //     .map_err(|e| e.to_string())?;

    // {
    //     let mut cpu_state_guard = executor.state.cpu_state.lock().unwrap();
    //     cpu_state_guard.set_register_value("rax", buffer.len() as u64)
    //         .map_err(|e| e.to_string())?;  // Convert error to String
    // }

    // let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
    // let result_var_name = format!("{}_{:02}_sys-read", current_addr_hex, executor.instruction_counter);
    // executor.state.create_or_update_concolic_var_int(&result_var_name, buffer.len() as u64, 64);

    Ok(())
}


// fn handle_sys_write(executor: &mut ConcolicExecutor, cpu_state: &mut CpuState) -> Result<(), String> {
//     let fd_id = cpu_state.get_register_value("rdi")
//         .ok_or_else(|| "File descriptor for write not found".to_string())?;
    
//     let buf_addr = cpu_state.get_register_value("rsi")
//         .ok_or_else(|| "Buffer address for write not found".to_string())?;

//     let count = cpu_state.get_register_value("rdx")
//         .ok_or_else(|| "Count for write not found".to_string())? as usize;

//     let buffer = executor.state.memory.read_memory(buf_addr, count)
//         .map_err(|e| e.to_string())?;

//     // First, separate the mutable borrow into its own scope
//     let bytes_written = {
//         let file_descriptor = executor.state.get_file_descriptor_mut(fd_id)?;
//         executor.state.vfs.write(file_descriptor, &buffer)
//             .map_err(|e| e.to_string())?
//     };

//     // Now `file_descriptor` borrow is dropped and you can freely access `executor.state`
//     cpu_state.set_register_value("rax", bytes_written as u64);

//     let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
//     let result_var_name = format!("{}_{:02}_sys-write", current_addr_hex, executor.instruction_counter);
//     executor.state.create_or_update_concolic_var_int(&result_var_name, bytes_written as u64, 64);

//     Ok(())
// }



fn handle_swi(executor: &mut ConcolicExecutor, instruction: Inst) -> Result<(), String> {
    
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
            eprintln!("INT3 (debug breakpoint) encountered. Aborting execution.");
            let rip_value = {
                let cpu_state_guard = executor.state.cpu_state.lock().unwrap();
                // cpu_state_guard.get_register_value("rip")
                //     .ok_or_else(|| "Failed to get RIP register value.".to_string())?;
            };
            
            let swi_result_var_name = format!("swi_int3_{:?}", rip_value);
            //executor.state.create_or_update_concolic_var_int(&swi_result_var_name, 0x3, 8);
            Err("Execution aborted due to INT3 (debug breakpoint).".to_string())
        },
        // Add handling for other interrupts as needed
        _ => {
            eprintln!("Unhandled software interrupt (SWI) encountered: {}", interrupt_number);
            Err(format!("Unhandled software interrupt (SWI) encountered: {}", interrupt_number))
        }
    }
}
