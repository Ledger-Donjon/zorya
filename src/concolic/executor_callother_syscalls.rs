/// Focuses on implementing the execution of the CALLOTHER opcode, especially syscalls, from Ghidra's Pcode specification
/// This implementation relies on Ghidra 11.0.1 with the specfiles in /specfiles

use crate::executor::ConcolicExecutor;
use nix::libc::{gettid, SIG_BLOCK, SIG_SETMASK, SIG_UNBLOCK};
use z3::ast::BV;
use std::{io::Write, process, time::Duration};

use super::{ConcolicVar, SymbolicVar};

// constants for sys_futex operations
const FUTEX_WAIT: u64 = 0;
const FUTEX_WAKE: u64 = 1;
const FUTEX_REQUEUE: u64 = 2;
const FUTEX_PRIVATE_FLAG: u64 = 128;
// constants for sys_sigaltstack
const SS_DISABLE: u32 = 1;
const MINSIGSTKSZ: usize = 2048;
// constants for sys_madvise
const MADV_NORMAL: u64 = 0;
const MADV_RANDOM: u64 = 1;
const MADV_SEQUENTIAL: u64 = 2;
const MADV_WILLNEED: u64 = 3;
const MADV_DONTNEED: u64 = 4;
const MADV_REMOVE: u64 = 9;
const MADV_DONTFORK: u64 = 10;
const MADV_DOFORK: u64 = 11;
const MADV_HWPOISON: u64 = 100;
const MADV_SOFT_OFFLINE: u64 = 101;
const MADV_MERGEABLE: u64 = 12;
const MADV_UNMERGEABLE: u64 = 13;
const MADV_HUGEPAGE: u64 = 14;
const MADV_NOHUGEPAGE: u64 = 15;
const MADV_DONTDUMP: u64 = 16;
const MADV_DODUMP: u64 = 17;

// constants for sys_arch_prctl
mod arch {
    pub const ARCH_SET_GS: u64 = 0x1001;
    pub const ARCH_SET_FS: u64 = 0x1002; 
    pub const ARCH_GET_FS: u64 = 0x1003;
    pub const ARCH_GET_GS: u64 = 0x1004;
}

macro_rules! log {
    ($logger:expr, $($arg:tt)*) => {{
        writeln!($logger, $($arg)*).unwrap();
    }};
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
        14 => { // sys_rt_sigprocmask
            log!(executor.state.logger.clone(), "Syscall type: sys_rt_sigprocmask");
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
            drop(cpu_state_guard);

            // Create the concolic variables for the results
            let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
            let result_var_name = format!("{}-{:02}-callother-sys-rt_sigprocmask", current_addr_hex, executor.instruction_counter);
            executor.state.create_or_update_concolic_variable_int(&result_var_name, how.try_into().unwrap(), SymbolicVar::Int(BV::from_u64(executor.context, how.try_into().unwrap(), 64)));
        },
        28 => {  // sys_madvise
            log!(executor.state.logger.clone(), "Syscall type: sys_madvise");
        
            // Read arguments from registers
            let addr = cpu_state_guard.get_register_by_offset(0x38, 64).unwrap().get_concrete_value()?;
            let length = cpu_state_guard.get_register_by_offset(0x30, 64).unwrap().get_concrete_value()?;
            let advice = cpu_state_guard.get_register_by_offset(0x28, 32).unwrap().get_concrete_value()?;
        
            log!(executor.state.logger.clone(), "madvise addr: 0x{:x}, length: {}, advice: {}", addr, length, advice);
        
            // Simulate the behavior of madvise based on the advice provided
            // this operation has no real impact on the concolic execution
            match advice {
                MADV_NORMAL => {
                    log!(executor.state.logger.clone(), "Advice: MADV_NORMAL");
                    // No special treatment
                }
                MADV_RANDOM => {
                    log!(executor.state.logger.clone(), "Advice: MADV_RANDOM");
                    // Expect page references in random order
                }
                MADV_SEQUENTIAL => {
                    log!(executor.state.logger.clone(), "Advice: MADV_SEQUENTIAL");
                    // Expect page references in sequential order
                }
                MADV_WILLNEED => {
                    log!(executor.state.logger.clone(), "Advice: MADV_WILLNEED");
                    // Expect access in the near future
                }
                MADV_DONTNEED => {
                    log!(executor.state.logger.clone(), "Advice: MADV_DONTNEED");
                    // Do not expect access in the near future
                }
                MADV_REMOVE => {
                    log!(executor.state.logger.clone(), "Advice: MADV_REMOVE");
                    // Free up a given range of pages
                }
                MADV_DONTFORK => {
                    log!(executor.state.logger.clone(), "Advice: MADV_DONTFORK");
                    // Do not make the pages in this range available to the child after a fork
                }
                MADV_DOFORK => {
                    log!(executor.state.logger.clone(), "Advice: MADV_DOFORK");
                    // Undo the effect of MADV_DONTFORK
                }
                MADV_HWPOISON => {
                    log!(executor.state.logger.clone(), "Advice: MADV_HWPOISON");
                    // Poison a page and handle it like a hardware memory corruption
                }
                MADV_SOFT_OFFLINE => {
                    log!(executor.state.logger.clone(), "Advice: MADV_SOFT_OFFLINE");
                    // Soft offline the pages in the range specified
                }
                MADV_MERGEABLE => {
                    log!(executor.state.logger.clone(), "Advice: MADV_MERGEABLE");
                    // Enable Kernel Samepage Merging (KSM)
                }
                MADV_UNMERGEABLE => {
                    log!(executor.state.logger.clone(), "Advice: MADV_UNMERGEABLE");
                    // Undo the effect of an earlier MADV_MERGEABLE operation
                }
                MADV_HUGEPAGE => {
                    log!(executor.state.logger.clone(), "Advice: MADV_HUGEPAGE");
                    // Enable Transparent Huge Pages (THP)
                }
                MADV_NOHUGEPAGE => {
                    log!(executor.state.logger.clone(), "Advice: MADV_NOHUGEPAGE");
                    // Ensure that memory in the address range will not be collapsed into huge pages
                }
                MADV_DONTDUMP => {
                    log!(executor.state.logger.clone(), "Advice: MADV_DONTDUMP");
                    // Exclude from a core dump those pages in the range specified
                }
                MADV_DODUMP => {
                    log!(executor.state.logger.clone(), "Advice: MADV_DODUMP");
                    // Undo the effect of an earlier MADV_DONTDUMP
                }
                _ => {
                    log!(executor.state.logger.clone(), "Unknown advice: {}", advice);
                    return Err("EINVAL: Invalid advice".to_string());
                }
            }
        
            cpu_state_guard.set_register_value_by_offset(rax_offset, ConcolicVar::new_concrete_and_symbolic_int(0, SymbolicVar::new_int(0, executor.context, 64).to_bv(executor.context), executor.context, 64), 64)?;
            drop(cpu_state_guard);
        
            // Create the concolic variables for the results
            let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
            let result_var_name = format!("{}-{:02}-callother-sys-madvise", current_addr_hex, executor.instruction_counter);
            executor.state.create_or_update_concolic_variable_int(&result_var_name, addr.try_into().unwrap(), SymbolicVar::Int(BV::from_u64(executor.context, addr.try_into().unwrap(), 64)));
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
        131 => { // sys_sigaltstack
            log!(executor.state.logger.clone(), "Syscall type: sys_sigaltstack");
        
            // Retrieve the pointer to the new signal stack structure (ss) from the RDI register
            let ss_offset = 0x38; // RDI register offset for 'ss'
            let ss_ptr = match cpu_state_guard.get_register_by_offset(ss_offset, 64) {
                // If the register is found, get its concrete value
                Some(register) => match register.get_concrete_value() {
                    Ok(value) => value,
                    Err(e) => {
                        // Log an error if the concrete value cannot be obtained
                        log!(executor.state.logger.clone(), "Error getting concrete value for ss_ptr: {:?}", e);
                        return Err("Failed to get concrete value for ss_ptr".to_string());
                    },
                },
                // Log an error if the register is not found
                None => {
                    log!(executor.state.logger.clone(), "Error: Register at offset 0x38 not found");
                    return Err("Failed to get register by offset for ss_ptr".to_string());
                },
            };
            log!(executor.state.logger.clone(), "ss_ptr: 0x{:x}", ss_ptr);
        
            // Retrieve the pointer to the old signal stack structure (oss) from the RSI register
            let oss_offset = 0x30; // RSI register offset for 'oss'
            let oss_ptr = match cpu_state_guard.get_register_by_offset(oss_offset, 64) {
                // If the register is found, get its concrete value
                Some(register) => match register.get_concrete_value() {
                    Ok(value) => value,
                    Err(e) => {
                        // Log an error if the concrete value cannot be obtained
                        log!(executor.state.logger.clone(), "Error getting concrete value for oss_ptr: {:?}", e);
                        return Err("Failed to get concrete value for oss_ptr".to_string());
                    },
                },
                // Log an error if the register is not found
                None => {
                    log!(executor.state.logger.clone(), "Error: Register at offset 0x30 not found");
                    return Err("Failed to get register by offset for oss_ptr".to_string());
                },
            };
            log!(executor.state.logger.clone(), "oss_ptr: 0x{:x}", oss_ptr);
        
            if ss_ptr != 0 {
                // If ss_ptr is not null, read the new signal stack structure from memory
                let ss_sp = match executor.state.memory.read_quad(ss_ptr) {
                    Ok(value) => value,
                    Err(e) => {
                        // Log an error if the stack pointer cannot be read from memory
                        log!(executor.state.logger.clone(), "Error reading ss_sp from memory: {:?}", e);
                        return Err("Failed to read ss_sp from memory".to_string());
                    },
                };
                log!(executor.state.logger.clone(), "Read ss_sp: 0x{:x}", ss_sp);
        
                let ss_flags = match executor.state.memory.read_word(ss_ptr + 8) {
                    Ok(value) => value,
                    Err(e) => {
                        // Log an error if the stack flags cannot be read from memory
                        log!(executor.state.logger.clone(), "Error reading ss_flags from memory: {:?}", e);
                        return Err("Failed to read ss_flags from memory".to_string());
                    },
                };
                log!(executor.state.logger.clone(), "Read ss_flags: 0x{:x}", ss_flags);
        
                let ss_size = match executor.state.memory.read_quad(ss_ptr + 16) {
                    Ok(value) => value,
                    Err(e) => {
                        // Log an error if the stack size cannot be read from memory
                        log!(executor.state.logger.clone(), "Error reading ss_size from memory: {:?}", e);
                        return Err("Failed to read ss_size from memory".to_string());
                    },
                };
                log!(executor.state.logger.clone(), "Read ss_size: 0x{:x}", ss_size);
        
                // Validate the stack flags
                if ss_flags != 0 && ss_flags != SS_DISABLE.into() {
                    log!(executor.state.logger.clone(), "Invalid ss_flags: 0x{:x}", ss_flags);
                    return Err("EINVAL: Invalid ss_flags".to_string());
                }
        
                // Validate the stack size
                if ss_flags == 0 && ss_size < MINSIGSTKSZ as u64 {
                    log!(executor.state.logger.clone(), "Stack size too small: 0x{:x}", ss_size);
                    return Err("ENOMEM: Stack size too small".to_string());
                }
        
                // Update the alternate signal stack with the new values
                executor.state.altstack.ss_sp = ss_sp;
                executor.state.altstack.ss_flags = ss_flags as u64;
                executor.state.altstack.ss_size = ss_size;
                log!(executor.state.logger.clone(), "Updated altstack: ss_sp=0x{:x}, ss_flags=0x{:x}, ss_size=0x{:x}", ss_sp, ss_flags, ss_size);
            }
        
            if oss_ptr != 0 {
                // If oss_ptr is not null, return the current alternate signal stack
                let current_ss_sp = executor.state.altstack.ss_sp;
                let current_ss_flags = executor.state.altstack.ss_flags;
                let current_ss_size = executor.state.altstack.ss_size;
                log!(executor.state.logger.clone(), "Returning current altstack: ss_sp=0x{:x}, ss_flags=0x{:x}, ss_size=0x{:x}", current_ss_sp, current_ss_flags, current_ss_size);
        
                // Write the current alternate signal stack information to memory
                if let Err(e) = executor.state.memory.write_quad(oss_ptr, current_ss_sp) {
                    log!(executor.state.logger.clone(), "Error writing current_ss_sp to memory: {:?}", e);
                    return Err("Failed to write current_ss_sp to memory".to_string());
                }
                if let Err(e) = executor.state.memory.write_word(oss_ptr + 8, current_ss_flags.try_into().unwrap()) {
                    log!(executor.state.logger.clone(), "Error writing current_ss_flags to memory: {:?}", e);
                    return Err("Failed to write current_ss_flags to memory".to_string());
                }
                if let Err(e) = executor.state.memory.write_quad(oss_ptr + 16, current_ss_size) {
                    log!(executor.state.logger.clone(), "Error writing current_ss_size to memory: {:?}", e);
                    return Err("Failed to write current_ss_size to memory".to_string());
                }
            }
        
            // Set the result of the syscall (0 for success) in the RAX register
            cpu_state_guard.set_register_value_by_offset(rax_offset, ConcolicVar::new_concrete_and_symbolic_int(0, SymbolicVar::new_int(0, executor.context, 64).to_bv(executor.context), executor.context, 64), 64)?;
            drop(cpu_state_guard);
        
            // Create the concolic variables for the results
            let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
            let result_var_name = format!("{}-{:02}-callother-sys-sigaltstack", current_addr_hex, executor.instruction_counter);
            executor.state.create_or_update_concolic_variable_int(&result_var_name, oss_ptr.try_into().unwrap(), SymbolicVar::Int(BV::from_u64(executor.context, oss_ptr.try_into().unwrap(), 64)));
        },        
        158 => { // sys_arch_prctl: set architecture-specific thread state
            log!(executor.state.logger.clone(), "Syscall invoked: sys_arch_prctl");
                
            let code = cpu_state_guard.get_register_by_offset(0x38, 64)
                .ok_or("Failed to retrieve code from register")?
                .get_concrete_value().map_err(|e| e.to_string())?;
        
            let addr = cpu_state_guard.get_register_by_offset(0x30, 64)
                .ok_or("Failed to retrieve address from register")?
                .get_concrete_value().map_err(|e| e.to_string())?;
        
            let addr_concolic = cpu_state_guard.get_concolic_register_by_offset(0x30, 64)
                .ok_or("Failed to retrieve address from register")?;

            log!(executor.state.logger.clone(), "Arch-prctl code: {:#x}, Address: {:#x}", code, addr);
        
            let result = match code {
                // Constants assumed to be defined. Replace placeholders with actual values.
                arch::ARCH_SET_FS => {
                    log!(executor.state.logger, "Setting FS base to {:#x}", addr);
                    // Perform the operation to set FS base
                    cpu_state_guard.set_register_value_by_offset(0x110, addr_concolic, 64)?;
                    addr
                },
                arch::ARCH_GET_FS => {
                    log!(executor.state.logger, "Getting FS base");
                    // Store the FS base at the address provided in `addr`
                    cpu_state_guard.get_register_by_offset(0x110, 64).unwrap().get_concrete_value()?
                },
                arch::ARCH_SET_GS => {
                    log!(executor.state.logger, "Setting GS base to {:#x}", addr);
                    // Perform the operation to set GS base
                    cpu_state_guard.get_register_by_offset(0x118, 64).unwrap().get_concrete_value()?
                },
                arch::ARCH_GET_GS => {
                    log!(executor.state.logger, "Getting GS base");
                    // Store the GS base at the address provided in `addr`
                    cpu_state_guard.set_register_value_by_offset(0x118, addr_concolic, 64)?;
                    addr
                },
                _ => {
                    log!(executor.state.logger, "Unsupported arch-prctl code: {:#x}", code);
                    return Err(format!("Unsupported arch-prctl code: {:#x}", code));
                }
            };

            drop(cpu_state_guard);
        
            // Reflect changes or checks
            let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
            let result_var_name = format!("{}-{:02}-syscall-arch_prctl", current_addr_hex, executor.instruction_counter);
            executor.state.create_or_update_concolic_variable_int(&result_var_name, code.try_into().unwrap(), SymbolicVar::Int(BV::from_u64(executor.context, code.try_into().unwrap(), 64)));
        
            log!(executor.state.logger.clone(), "sys_arch_prctl operation completed successfully");
        
        }        
        186 => { // sys_gettid
            log!(executor.state.logger.clone(), "Syscall type: sys_gettid");

            // Get the actual TID using nix crate
            let tid = unsafe { gettid() } as u64;

            // Set the TID in RAX
            cpu_state_guard.set_register_value_by_offset(rax_offset, ConcolicVar::new_concrete_and_symbolic_int(tid, SymbolicVar::new_int(tid as i32, executor.context, 64).to_bv(executor.context), executor.context, 64), 64)?;

            drop(cpu_state_guard);

            // Create the concolic variables for the results
            let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
            let result_var_name = format!("{}-{:02}-callother-sys-gettid", current_addr_hex, executor.instruction_counter);
            executor.state.create_or_update_concolic_variable_int(&result_var_name, tid.try_into().unwrap(), SymbolicVar::Int(BV::from_u64(executor.context, tid.try_into().unwrap(), 64)));
        },
        202 => {  // sys_futex
            log!(executor.state.logger.clone(), "Syscall type: sys_futex");
        
            // Read arguments from registers
            let uaddr = cpu_state_guard.get_register_by_offset(0x38, 64).unwrap().get_concrete_value()?;
            let op = cpu_state_guard.get_register_by_offset(0x30, 32).unwrap().get_concrete_value()?;
            let val = cpu_state_guard.get_register_by_offset(0x28, 32).unwrap().get_concrete_value()?;
            let timeout_ptr = cpu_state_guard.get_register_by_offset(0x20, 64).unwrap().get_concrete_value()?;
            let uaddr2 = cpu_state_guard.get_register_by_offset(0x18, 64).unwrap().get_concrete_value()?;
            let val3 = cpu_state_guard.get_register_by_offset(0x10, 32).unwrap().get_concrete_value()?;
        
            let timeout = if timeout_ptr != 0 {
                // TODO : Read the timeout value from the memory location
                Some(Duration::from_secs(5)) // for now, use a 5-second timeout 
            } else {
                None
            };
        
            let is_private = (op & FUTEX_PRIVATE_FLAG) != 0;
            let operation = op & !FUTEX_PRIVATE_FLAG;
        
            match operation {
                FUTEX_WAIT => {
                    log!(executor.state.logger.clone(), "Futex type: FUTEX_WAIT");
                    // This should block the thread if *uaddr == val, until *uaddr changes or optionally timeout expires
                    let futex_uaddr = uaddr as u64;
                    let futex_val = val as i32;
                    // ignore this operation for now
                    // executor.state.futex_manager.futex_wait(futex_uaddr, futex_val, timeout)?;
        
                    drop(cpu_state_guard);
                
                    // Create the concolic variables for the results
                    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
                    let result_var_name = format!("{}-{:02}-callother-sys-futex_wait", current_addr_hex, executor.instruction_counter);
                    executor.state.create_or_update_concolic_variable_int(&result_var_name, futex_uaddr.try_into().unwrap(), SymbolicVar::Int(BV::from_u64(executor.context, futex_uaddr.try_into().unwrap(), 64)));
                },
                FUTEX_WAKE => {
                    log!(executor.state.logger.clone(), "Futex type: FUTEX_WAKE");
                    // This should wake up to 'val' number of threads waiting on 'uaddr'
                    let futex_uaddr = uaddr as u64;
                    let futex_val = val as usize;
                    if is_private {
                        executor.state.futex_manager.futex_wake_private(futex_uaddr, futex_val)?;
                    } else {
                        executor.state.futex_manager.futex_wake(futex_uaddr, futex_val)?;
                    }
        
                    drop(cpu_state_guard);
                
                    // Create the concolic variables for the results
                    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
                    let result_var_name = format!("{}-{:02}-callother-sys-futex_wake", current_addr_hex, executor.instruction_counter);
                    executor.state.create_or_update_concolic_variable_int(&result_var_name, futex_uaddr.try_into().unwrap(), SymbolicVar::Int(BV::from_u64(executor.context, futex_uaddr.try_into().unwrap(), 64)));
                },
                FUTEX_REQUEUE => {
                    log!(executor.state.logger.clone(), "Futex type: FUTEX_REQUEUE");
                    // This should requeue up to 'val' number of threads from 'uaddr' to 'uaddr2'
                    let futex_uaddr = uaddr as u64;
                    let futex_val = val as usize;
                    let futex_uaddr2 = uaddr2 as u64;
                    let futex_val3 = val3 as usize;
                    executor.state.futex_manager.futex_requeue(futex_uaddr, futex_val, futex_uaddr2, futex_val3)?;
        
                    drop(cpu_state_guard);
                
                    // Create the concolic variables for the results
                    let current_addr_hex = executor.current_address.map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
                    let result_var_name = format!("{}-{:02}-callother-sys-futex_requeue", current_addr_hex, executor.instruction_counter);
                    executor.state.create_or_update_concolic_variable_int(&result_var_name, futex_uaddr.try_into().unwrap(), SymbolicVar::Int(BV::from_u64(executor.context, futex_uaddr.try_into().unwrap(), 64)));
                },
                _ => {
                    // if the callother number is not handled, stop the execution
                    log!(executor.state.logger.clone(), "Unhandled FUTEX type: op={}", op);
                    log!(executor.state.logger.clone(), "For information, the value of operation (op & !FUTEX_PRIVATE_FLAG) is : {}", operation);
                    process::exit(1);            
                } 
            }
        }        
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
        _ => {
            // if the syscall is not handled, stop the execution
            log!(executor.state.logger.clone(), "Unhandled syscall number: {}", rax);
            process::exit(1);            
        }
    }
    Ok(())
}