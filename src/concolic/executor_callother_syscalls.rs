// SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

/// Focuses on implementing the execution of the CALLOTHER opcode, especially syscalls, from Ghidra's Pcode specification
/// This implementation relies on Ghidra 11.0.1 with the specfiles in /specfiles
/// https://github.com/torvalds/linux/blob/master/arch/x86/entry/syscalls/syscall_64.tbl
use crate::{
    concolic::ConcreteVar,
    executor::ConcolicExecutor,
    state::memory_x86_64::{MemoryValue, Sigaction},
};
use byteorder::{LittleEndian, WriteBytesExt};
use nix::libc::gettid;
use std::{io::Write, process, time::Duration};
use z3::ast::BV;

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
        if ($logger).is_enabled() {
            writeln!($logger, $($arg)*).unwrap();
        }
    }};
}

pub fn handle_syscall(executor: &mut ConcolicExecutor) -> Result<(), String> {
    log!(
        executor.state.logger.clone(),
        "This CALLOTHER operation is a SYSCALL operation."
    );

    // NOTE: We do NOT switch threads at syscalls to mimic real Go scheduler behavior.
    // Real Go scheduler:
    // - Hands off processor P when a goroutine BLOCKS in a syscall (not when it enters)
    // - Threads dumped by GDB are already in blocked/waiting state with invalid register values
    // - Switching here would execute syscalls with garbage register values (e.g., RAX=-516, buf_ptr=0x0)
    //
    // Instead, we only switch at function calls (user code), which are safe points.
    // This matches Go's cooperative preemption model where switches happen at:
    // 1. Function prologues (stack growth checks)
    // 2. Blocking operations (channels, sync primitives) - handled by gopark
    // 3. Explicit yields (runtime.Gosched)
    //
    // See: https://nghiant3223.github.io/2025/04/15/go-scheduler.html

    // Still count this instruction for time slicing
    {
        let mut tm = executor.state.thread_manager.lock().unwrap();
        tm.tick_instruction();
        drop(tm);
    }

    // Check if we're in overlay mode (speculative execution)
    let in_overlay_mode = executor.is_overlay_mode();

    // Lock the CPU state - needed for all register accesses in syscall handlers
    let mut cpu_state_guard = executor.state.cpu_state.lock().unwrap();

    // Retrieve the value in the RAX register to determine the syscall
    // In overlay mode, we should use overlay-aware register access for RAX
    let rax_offset = 0x0; // RAX register offset
    let rax = if in_overlay_mode {
        // Drop the guard temporarily to use overlay-aware access
        drop(cpu_state_guard);
        let rax_val = executor
            .get_register_overlay_aware(rax_offset, 64)
            .ok_or("Failed to get RAX in overlay mode")?
            .get_concrete_value()?;
        // Re-acquire the guard for subsequent operations
        cpu_state_guard = executor.state.cpu_state.lock().unwrap();
        rax_val
    } else {
        cpu_state_guard
            .get_register_by_offset(rax_offset, 64)
            .unwrap()
            .get_concrete_value()?
    };

    log!(executor.state.logger.clone(), "Syscall number: {}", rax);

    // Validate syscall number - in overlay mode, invalid syscalls are common
    // due to speculative execution with incomplete register state
    let max_valid_syscall: u64 = 500; // Linux has ~400 syscalls, use 500 as reasonable upper bound
    if rax > max_valid_syscall {
        if in_overlay_mode {
            log!(
                executor.state.logger.clone(),
                "[OVERLAY] Invalid syscall number {} (likely pointer/garbage) - stopping speculative execution",
                rax
            );
            return Err(format!(
                "Invalid syscall number {} in overlay mode - stopping speculative execution",
                rax
            ));
        }
        // Not in overlay mode - this is a real issue, will be handled in match default case
    }

    log!(
        executor.trace_logger,
        "----> Calling the syscall with number {}",
        rax
    );

    match rax {
        0 => {
            // sys_read
            log!(executor.state.logger.clone(), "Syscall type: sys_read");

            // Retrieve file descriptor (FD) from RDI (offset 0x38)
            let fd_offset = 0x38;
            let fd_var = cpu_state_guard
                .get_register_by_offset(fd_offset, 64)
                .ok_or("Failed to retrieve FD from RDI.")?;
            let fd = fd_var.concrete.to_u64() as u32;

            // Retrieve buffer pointer from RSI (offset 0x30)
            let buf_ptr_offset = 0x30;
            let buf_ptr_var = cpu_state_guard
                .get_register_by_offset(buf_ptr_offset, 64)
                .ok_or("Failed to retrieve buffer pointer from RSI.")?;
            let buf_ptr = buf_ptr_var.concrete.to_u64();

            // Retrieve count from RDX (offset 0x10)
            let count_offset = 0x10;
            let count_var = cpu_state_guard
                .get_register_by_offset(count_offset, 64)
                .ok_or("Failed to retrieve count from RDX.")?;
            let count = count_var.concrete.to_u64() as usize;

            log!(
                executor.state.logger.clone(),
                "FD: {}, buf_ptr: 0x{:x}, count: {}",
                fd,
                buf_ptr,
                count
            );

            // Read from the virtual file system
            let mut buffer = vec![0u8; count];
            let bytes_read = {
                let vfs = executor.state.vfs.read().unwrap();
                vfs.read(fd, &mut buffer)
            };

            // Write the buffer to memory using the new method
            executor
                .state
                .memory
                .write_bytes(buf_ptr, &buffer[..bytes_read])
                .map_err(|e| format!("Failed to write bytes to memory: {}", e))?;

            // Update RAX with the number of bytes read
            let bytes_read_concolic = ConcolicVar::new_concrete_and_symbolic_int(
                bytes_read as u64,
                BV::from_u64(executor.context, bytes_read as u64, 64),
                executor.context,
            );
            cpu_state_guard
                .set_register_value_by_offset(rax_offset, bytes_read_concolic, 64)
                .map_err(|e| format!("Failed to set RAX: {}", e))?;

            drop(cpu_state_guard);

            // Record the operation
            let current_addr_hex = executor
                .current_address
                .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
            let result_var_name = format!(
                "{}-{:02}-callother-sys-read",
                current_addr_hex, executor.instruction_counter
            );
            executor.state.create_or_update_concolic_variable_int(
                &result_var_name,
                bytes_read as u64,
                SymbolicVar::Int(BV::from_u64(executor.context, bytes_read as u64, 64)),
            );
        }
        1 => {
            // sys_write
            log!(executor.state.logger.clone(), "Syscall type: sys_write");

            // Retrieve file descriptor (FD) from RDI (offset 0x38)
            let fd_offset = 0x38;
            let fd_var = cpu_state_guard
                .get_register_by_offset(fd_offset, 64)
                .ok_or("Failed to retrieve FD from RDI.")?;
            let fd = fd_var.concrete.to_u64() as u32;

            // Retrieve buffer pointer from RSI (offset 0x30)
            let buf_ptr_offset = 0x30;
            let buf_ptr_var = cpu_state_guard
                .get_register_by_offset(buf_ptr_offset, 64)
                .ok_or("Failed to retrieve buffer pointer from RSI.")?;
            let buf_ptr = buf_ptr_var.concrete.to_u64();

            // Retrieve count from RDX (offset 0x10)
            let count_offset = 0x10;
            let count_var = cpu_state_guard
                .get_register_by_offset(count_offset, 64)
                .ok_or("Failed to retrieve count from RDX.")?;
            let count = count_var.concrete.to_u64() as usize;

            log!(
                executor.state.logger.clone(),
                "FD: {}, buf_ptr: 0x{:x}, count: {}",
                fd,
                buf_ptr,
                count
            );

            // Read data from memory using the new method
            let data = executor
                .state
                .memory
                .read_bytes(buf_ptr, count)
                .map_err(|e| format!("Failed to read bytes from memory: {}", e))?;

            // Write data to the virtual file system
            let bytes_written = {
                let vfs = executor.state.vfs.read().unwrap();
                vfs.write(fd, &data)
            };

            log!(
                executor.state.logger.clone(),
                "Bytes written: {}",
                bytes_written
            );

            // Update RAX with the number of bytes written
            let bytes_written_concolic = ConcolicVar::new_concrete_and_symbolic_int(
                bytes_written as u64,
                BV::from_u64(executor.context, bytes_written as u64, 64),
                executor.context,
            );
            cpu_state_guard
                .set_register_value_by_offset(rax_offset, bytes_written_concolic, 64)
                .map_err(|e| format!("Failed to set RAX: {}", e))?;

            drop(cpu_state_guard);

            // Record the operation for tracing
            let current_addr_hex = executor
                .current_address
                .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
            let result_var_name = format!(
                "{}-{:02}-callother-sys-write",
                current_addr_hex, executor.instruction_counter
            );
            executor.state.create_or_update_concolic_variable_int(
                &result_var_name,
                bytes_written as u64,
                SymbolicVar::Int(BV::from_u64(executor.context, bytes_written as u64, 64)),
            );
        }
        2 => {
            // sys_open
            log!(executor.state.logger.clone(), "Syscall type: sys_open");

            // Retrieve filename pointer from RDI (offset 0x38)
            let filename_ptr_offset = 0x38;
            let filename_ptr_var = cpu_state_guard
                .get_register_by_offset(filename_ptr_offset, 64)
                .ok_or("Failed to retrieve filename pointer from RDI.")?;
            let filename_ptr = filename_ptr_var.concrete.to_u64();

            // Read the filename from memory using the new method
            let filename = executor
                .state
                .memory
                .read_string(filename_ptr)
                .map_err(|e| format!("Failed to read filename from memory: {}", e))?;

            log!(executor.state.logger.clone(), "Filename: {}", filename);

            // Open the file using the virtual file system
            let fd = {
                let mut vfs = executor.state.vfs.write().unwrap();
                vfs.open(&filename)
            };

            // Update RAX with the file descriptor
            let fd_concolic = ConcolicVar::new_concrete_and_symbolic_int(
                fd as u64,
                BV::from_u64(executor.context, fd as u64, 64),
                executor.context,
            );
            cpu_state_guard
                .set_register_value_by_offset(rax_offset, fd_concolic, 64)
                .map_err(|e| format!("Failed to set RAX: {}", e))?;

            drop(cpu_state_guard);

            // Record the operation
            let current_addr_hex = executor
                .current_address
                .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
            let result_var_name = format!(
                "{}-{:02}-callother-sys-open",
                current_addr_hex, executor.instruction_counter
            );
            executor.state.create_or_update_concolic_variable_int(
                &result_var_name,
                fd as u64,
                SymbolicVar::Int(BV::from_u64(executor.context, fd as u64, 64)),
            );
        }
        3 => {
            // sys_close
            log!(executor.state.logger.clone(), "Syscall type: sys_close");

            // Retrieve file descriptor (FD) from RDI (offset 0x38)
            let fd_offset = 0x38;
            let fd_var = cpu_state_guard
                .get_register_by_offset(fd_offset, 64)
                .ok_or("Failed to retrieve FD from RDI.")?;
            let fd = fd_var.concrete.to_u64() as u32;

            // Close the file using the virtual file system
            {
                let mut vfs = executor.state.vfs.write().unwrap();
                vfs.close(fd);
            }

            // Update RAX with 0 to indicate success
            let success_concolic = ConcolicVar::new_concrete_and_symbolic_int(
                0,
                BV::from_u64(executor.context, 0, 64),
                executor.context,
            );
            cpu_state_guard
                .set_register_value_by_offset(rax_offset, success_concolic, 64)
                .map_err(|e| format!("Failed to set RAX: {}", e))?;

            drop(cpu_state_guard);

            // Record the operation
            let current_addr_hex = executor
                .current_address
                .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
            let result_var_name = format!(
                "{}-{:02}-callother-sys-close",
                current_addr_hex, executor.instruction_counter
            );
            executor.state.create_or_update_concolic_variable_int(
                &result_var_name,
                fd as u64,
                SymbolicVar::Int(BV::from_u64(executor.context, fd as u64, 64)),
            );
        }
        9 => {
            // sys_mmap
            log!(executor.state.logger.clone(), "Syscall type: sys_mmap");
            let addr = cpu_state_guard
                .get_register_by_offset(0x38, 64)
                .unwrap()
                .get_concrete_value()?;
            let length = cpu_state_guard
                .get_register_by_offset(0x30, 64)
                .unwrap()
                .get_concrete_value()? as usize;
            let prot = cpu_state_guard
                .get_register_by_offset(0x10, 64)
                .unwrap()
                .get_concrete_value()? as i32;
            let flags = cpu_state_guard
                .get_register_by_offset(0x90, 64)
                .unwrap()
                .get_concrete_value()? as i32;
            let fd = cpu_state_guard
                .get_register_by_offset(0x80, 64)
                .unwrap()
                .get_concrete_value()? as i64 as i32;
            let offset = cpu_state_guard
                .get_register_by_offset(0x88, 64)
                .unwrap()
                .get_concrete_value()? as usize;
            log!(
                executor.state.logger.clone(),
                "addr: 0x{:x}, length: {}, prot: {}, flags: 0x{:x}, fd: {}, offset: {}",
                addr,
                length,
                prot,
                flags,
                fd,
                offset
            );
            // Handle mmap logic
            let result_addr = executor
                .state
                .memory
                .mmap(addr, length, prot, flags, fd, offset)
                .map_err(|e| e.to_string())?;

            log!(executor.state.logger.clone(), "Mapped memory at addr: 0x{:x}, length: {}, prot: {}, flags: {}, fd: {}, offset: {}", result_addr, length, prot, flags, fd, offset);

            drop(cpu_state_guard);

            // Set return value (the address to which the file has been mapped)
            // Use overlay-aware register write
            executor.set_register_overlay_aware(
                rax_offset,
                ConcolicVar::new_concrete_and_symbolic_int(
                    result_addr,
                    SymbolicVar::new_int(result_addr.try_into().unwrap(), executor.context, 64)
                        .to_bv(executor.context),
                    executor.context,
                ),
                64,
            )?;

            // Create the concolic variables for the results
            let current_addr_hex = executor
                .current_address
                .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
            let result_var_name = format!(
                "{}-{:02}-callother-sys-mmap",
                current_addr_hex, executor.instruction_counter
            );
            executor.state.create_or_update_concolic_variable_int(
                &result_var_name,
                addr.try_into().unwrap(),
                SymbolicVar::Int(BV::from_u64(executor.context, addr.try_into().unwrap(), 64)),
            );
        }
        13 => {
            // rt_sigaction
            log!(executor.state.logger.clone(), "Syscall type: rt_sigaction");

            let signum = cpu_state_guard
                .get_register_by_offset(0x38, 64)
                .unwrap()
                .get_concrete_value()? as i32;
            let act_ptr = cpu_state_guard
                .get_register_by_offset(0x30, 64)
                .unwrap()
                .get_concrete_value()?;
            let oldact_ptr = cpu_state_guard
                .get_register_by_offset(0x28, 64)
                .unwrap()
                .get_concrete_value()?;
            // from R10 register
            let sigsetsize = cpu_state_guard
                .get_register_by_offset(0x90, 64)
                .unwrap()
                .get_concrete_value()? as usize;

            log!(executor.state.logger.clone(),
                "rt_sigaction called with signum: {}, act_ptr: 0x{:x}, oldact_ptr: 0x{:x}, sigsetsize: {}",
                signum, act_ptr, oldact_ptr, sigsetsize
            );

            // Handle oldact_ptr: Save current action if requested
            if oldact_ptr != 0 && executor.state.memory.is_valid_address(oldact_ptr) {
                let current_action = executor
                    .state
                    .signal_handlers
                    .get(&signum)
                    .cloned()
                    .unwrap_or_else(|| {
                        log!(
                            executor.state.logger.clone(),
                            "Using default signal action for signum: {}",
                            signum
                        );
                        Sigaction::new_default(executor.context)
                    });

                match executor
                    .state
                    .memory
                    .write_sigaction(oldact_ptr, &current_action)
                {
                    Ok(_) => log!(
                        executor.state.logger.clone(),
                        "Wrote old action to 0x{:x} for signum: {}",
                        oldact_ptr,
                        signum
                    ),
                    Err(e) => log!(
                        executor.state.logger.clone(),
                        "Warning: Could not write old action to 0x{:x}: {}. Skipping.",
                        oldact_ptr,
                        e
                    ),
                }
            }

            // Handle act_ptr: Read and install new action if valid
            if act_ptr != 0 && executor.state.memory.is_valid_address(act_ptr) {
                match executor
                    .state
                    .memory
                    .read_sigaction(act_ptr, &mut executor.state.logger.clone())
                {
                    Ok(new_action) => {
                        if new_action.handler.concrete == 0 {
                            log!(
                                executor.state.logger.clone(),
                                "Warning: Installing NULL signal handler for signum {}",
                                signum
                            );
                        }
                        executor.state.signal_handlers.insert(signum, new_action);
                        log!(
                            executor.state.logger.clone(),
                            "Installed new action for signum {} from 0x{:x}",
                            signum,
                            act_ptr
                        );
                    }
                    Err(e) => log!(
                        executor.state.logger.clone(),
                        "Error: Failed to read new action from 0x{:x}: {}",
                        act_ptr,
                        e
                    ),
                }
            }

            // Indicate success in RAX
            cpu_state_guard
                .set_register_value_by_offset(
                    rax_offset,
                    ConcolicVar::new_concrete_and_symbolic_int(
                        0,
                        BV::from_u64(executor.context, 0, 64),
                        executor.context,
                    ),
                    64,
                )
                .map_err(|e| format!("Failed to set RAX: {}", e))?;

            drop(cpu_state_guard);
        }

        14 => {
            // sys_rt_sigprocmask
            log!(
                executor.state.logger.clone(),
                "Syscall type: sys_rt_sigprocmask"
            );

            let how = cpu_state_guard
                .get_register_by_offset(0x38, 64)
                .unwrap()
                .get_concrete_value()? as i32;
            let set_ptr = cpu_state_guard
                .get_register_by_offset(0x30, 64)
                .unwrap()
                .get_concrete_value()?;
            let oldset_ptr = cpu_state_guard
                .get_register_by_offset(0x28, 64)
                .unwrap()
                .get_concrete_value()?;
            let sigsetsize = cpu_state_guard
                .get_register_by_offset(0x90, 64)
                .unwrap()
                .get_concrete_value()? as usize;

            log!(executor.state.logger.clone(), "Sigsetsize: {}", sigsetsize);

            if sigsetsize != 8 && sigsetsize != 16 {
                return Err(format!("Unexpected sigsetsize: {}", sigsetsize));
            }

            // Handle oldset_ptr: Save current signal mask if requested
            if oldset_ptr != 0 && executor.state.memory.is_valid_address(oldset_ptr) {
                let current_mask = executor.state.signal_mask;
                let mem_value = MemoryValue {
                    concrete: current_mask,
                    symbolic: BV::from_u64(executor.context, current_mask, 64),
                    size: 64,
                };

                match executor.state.memory.write_value(oldset_ptr, &mem_value) {
                    Ok(_) => log!(
                        executor.state.logger.clone(),
                        "Saved old signal mask to 0x{:x}",
                        oldset_ptr
                    ),
                    Err(e) => return Err(format!("Failed to write old signal mask: {}", e)),
                }
            }

            // Handle set_ptr: Apply new mask if provided
            if set_ptr != 0 && executor.state.memory.is_valid_address(set_ptr) {
                let new_mask = executor
                    .state
                    .memory
                    .read_u64(set_ptr, &mut executor.state.logger.clone())
                    .map_err(|e| format!("Failed to read new signal mask from memory: {}", e))?
                    .concrete
                    .to_u64();

                match how {
                    nix::libc::SIG_BLOCK => executor.state.signal_mask |= new_mask,
                    nix::libc::SIG_UNBLOCK => executor.state.signal_mask &= !new_mask,
                    nix::libc::SIG_SETMASK => executor.state.signal_mask = new_mask,
                    _ => {
                        return Err(format!(
                            "Invalid 'how' argument for sys_rt_sigprocmask: {}",
                            how
                        ))
                    }
                }
            }

            // Indicate success in RAX
            cpu_state_guard
                .set_register_value_by_offset(
                    rax_offset,
                    ConcolicVar::new_concrete_and_symbolic_int(
                        0,
                        BV::from_u64(executor.context, 0, 64),
                        executor.context,
                    ),
                    64,
                )
                .map_err(|e| format!("Failed to set RAX: {}", e))?;

            drop(cpu_state_guard);
        }
        24 => {
            // sys_sched_yield
            log!(
                executor.state.logger.clone(),
                "Syscall type: sys_sched_yield"
            );
            // sys_sched_yield() causes the calling thread to relinquish the CPU
            log!(executor.state.logger.clone(), "Yielding the CPU");

            // Normally, sched_yield returns 0 upon successful call
            //cpu_state_guard.set_register_value_by_offset(0x0, // RAX register offset
            //    ConcolicVar::new_concrete_and_symbolic_int(0, SymbolicVar::new_int(0, executor.context, 64).to_bv(executor.context), executor.context, 64),
            //    64)?;
            drop(cpu_state_guard);

            // Create the concolic variables for the result
            let current_addr_hex = executor
                .current_address
                .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
            let result_var_name = format!(
                "{}-{:02}-callother-sys-sched_yield",
                current_addr_hex, executor.instruction_counter
            );
            executor.state.create_or_update_concolic_variable_int(
                &result_var_name,
                0,
                SymbolicVar::Int(BV::from_u64(executor.context, 0, 64)),
            );

            log!(executor.state.logger.clone(), "CPU yielded successfully");
        }
        35 => {
            // sys_nanosleep
            log!(executor.state.logger.clone(), "Syscall type: sys_nanosleep");

            // Retrieve 'req' pointer from RDI (offset 0x38)
            let req_ptr_offset = 0x38; // RDI register offset
            let req_ptr_var = cpu_state_guard
                .get_register_by_offset(req_ptr_offset, 64)
                .ok_or("Failed to retrieve 'req' pointer from RDI.")?;
            let req_ptr = req_ptr_var.concrete.to_u64();

            // Retrieve 'rem' pointer from RSI (offset 0x30)
            let rem_ptr_offset = 0x30; // RSI register offset
            let rem_ptr_var = cpu_state_guard
                .get_register_by_offset(rem_ptr_offset, 64)
                .ok_or("Failed to retrieve 'rem' pointer from RSI.")?;
            let rem_ptr = rem_ptr_var.concrete.to_u64();

            log!(
                executor.state.logger.clone(),
                "nanosleep: req=0x{:x}, rem=0x{:x}",
                req_ptr,
                rem_ptr
            );

            // Read the timespec structure from memory at req_ptr
            // struct timespec { time_t tv_sec; long tv_nsec; }
            // Both fields are 8 bytes on x86_64
            if req_ptr != 0 && executor.state.memory.is_valid_address(req_ptr) {
                let tv_sec = executor
                    .state
                    .memory
                    .read_u64(req_ptr, &mut executor.state.logger.clone())
                    .map_err(|e| format!("Failed to read tv_sec: {}", e))?
                    .concrete
                    .to_u64();

                let tv_nsec = executor
                    .state
                    .memory
                    .read_u64(req_ptr + 8, &mut executor.state.logger.clone())
                    .map_err(|e| format!("Failed to read tv_nsec: {}", e))?
                    .concrete
                    .to_u64();

                log!(
                    executor.state.logger.clone(),
                    "nanosleep: requested sleep time: {}s {}ns",
                    tv_sec,
                    tv_nsec
                );

                // Validate tv_nsec is in valid range [0, 999999999]
                if tv_nsec > 999_999_999 {
                    log!(
                        executor.state.logger.clone(),
                        "nanosleep: invalid tv_nsec value: {}",
                        tv_nsec
                    );
                    drop(cpu_state_guard);
                    // Return -EINVAL (22)
                    // Use overlay-aware register write
                    executor.set_register_overlay_aware(
                        rax_offset,
                        ConcolicVar::new_concrete_and_symbolic_int(
                            (-22i64) as u64, // -EINVAL
                            BV::from_u64(executor.context, (-22i64) as u64, 64),
                            executor.context,
                        ),
                        64,
                    )?;
                    return Ok(());
                }

                // For concolic execution, we don't actually sleep
                // We simulate immediate successful completion
                log!(
                    executor.state.logger.clone(),
                    "nanosleep: simulating immediate completion (no actual sleep)"
                );

                // If rem is provided and not NULL, write zeros (no remaining time)
                if rem_ptr != 0 && executor.state.memory.is_valid_address(rem_ptr) {
                    let zero_timespec = vec![0u8; 16]; // Two 64-bit fields
                    executor
                        .state
                        .memory
                        .write_bytes(rem_ptr, &zero_timespec)
                        .map_err(|e| format!("Failed to write rem timespec: {}", e))?;

                    log!(
                        executor.state.logger.clone(),
                        "nanosleep: wrote zero remaining time to rem pointer"
                    );
                }
            } else {
                log!(
                    executor.state.logger.clone(),
                    "nanosleep: invalid req pointer: 0x{:x}",
                    req_ptr
                );
                drop(cpu_state_guard);
                // Return -EFAULT (14)
                // Use overlay-aware register write
                executor.set_register_overlay_aware(
                    rax_offset,
                    ConcolicVar::new_concrete_and_symbolic_int(
                        (-14i64) as u64, // -EFAULT
                        BV::from_u64(executor.context, (-14i64) as u64, 64),
                        executor.context,
                    ),
                    64,
                )?;
                return Ok(());
            }

            // Set return value to 0 (success)
            let rax_value = ConcolicVar::new_concrete_and_symbolic_int(
                0,
                BV::from_u64(executor.context, 0, 64),
                executor.context,
            );
            cpu_state_guard
                .set_register_value_by_offset(rax_offset, rax_value, 64)
                .map_err(|e| format!("Failed to set RAX: {}", e))?;

            drop(cpu_state_guard);

            // Record the operation for tracing
            let current_addr_hex = executor
                .current_address
                .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
            let result_var_name = format!(
                "{}-{:02}-callother-sys-nanosleep",
                current_addr_hex, executor.instruction_counter
            );
            executor.state.create_or_update_concolic_variable_int(
                &result_var_name,
                0u64,
                SymbolicVar::Int(BV::from_u64(executor.context, 0u64, 64)),
            );

            log!(
                executor.state.logger.clone(),
                "sys_nanosleep executed successfully"
            );
        }
        28 => {
            // sys_madvise
            log!(executor.state.logger.clone(), "Syscall type: sys_madvise");

            // Read arguments from registers
            let addr = cpu_state_guard
                .get_register_by_offset(0x38, 64)
                .unwrap()
                .get_concrete_value()?;
            let length = cpu_state_guard
                .get_register_by_offset(0x30, 64)
                .unwrap()
                .get_concrete_value()?;
            let advice = cpu_state_guard
                .get_register_by_offset(0x28, 32)
                .unwrap()
                .get_concrete_value()?;

            log!(
                executor.state.logger.clone(),
                "madvise addr: 0x{:x}, length: {}, advice: {}",
                addr,
                length,
                advice
            );

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

            drop(cpu_state_guard);

            // Use overlay-aware register write
            executor.set_register_overlay_aware(
                rax_offset,
                ConcolicVar::new_concrete_and_symbolic_int(
                    0,
                    SymbolicVar::new_int(0, executor.context, 64).to_bv(executor.context),
                    executor.context,
                ),
                64,
            )?;

            // Create the concolic variables for the results
            let current_addr_hex = executor
                .current_address
                .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
            let result_var_name = format!(
                "{}-{:02}-callother-sys-madvise",
                current_addr_hex, executor.instruction_counter
            );
            executor.state.create_or_update_concolic_variable_int(
                &result_var_name,
                addr.try_into().unwrap(),
                SymbolicVar::Int(BV::from_u64(executor.context, addr.try_into().unwrap(), 64)),
            );
        }
        39 => {
            // sys_getpid
            log!(executor.state.logger.clone(), "Syscall type: sys_getpid");

            // For simplicity, we'll return a fixed PID
            let pid: u32 = 1000; // fix PID for this environment

            log!(executor.state.logger.clone(), "Returning PID: {}", pid);

            // Set return value to PID
            let pid_concolic = ConcolicVar::new_concrete_and_symbolic_int(
                pid as u64,
                BV::from_u64(executor.context, pid as u64, 64),
                executor.context,
            );
            cpu_state_guard
                .set_register_value_by_offset(rax_offset, pid_concolic, 64)
                .map_err(|e| format!("Failed to set RAX: {}", e))?;

            drop(cpu_state_guard);

            // Record the operation for tracing
            let current_addr_hex = executor
                .current_address
                .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
            let result_var_name = format!(
                "{}-{:02}-callother-sys-getpid",
                current_addr_hex, executor.instruction_counter
            );
            executor.state.create_or_update_concolic_variable_int(
                &result_var_name,
                pid as u64,
                SymbolicVar::Int(BV::from_u64(executor.context, pid as u64, 64)),
            );

            log!(
                executor.state.logger.clone(),
                "sys_getpid executed successfully"
            );
        }
        59 => {
            // sys_execve
            log!(executor.state.logger.clone(), "Syscall type: sys_execve");

            // 1. Retrieve 'path_ptr' from RDI (offset 0x38)
            let path_ptr_var = cpu_state_guard
                .get_register_by_offset(0x38, 64)
                .ok_or("Failed to retrieve 'path_ptr' from RDI.")?;
            let path_ptr = path_ptr_var.concrete.to_u64();

            // 2. Retrieve 'argv_ptr' from RSI (offset 0x30)
            let argv_ptr_var = cpu_state_guard
                .get_register_by_offset(0x30, 64)
                .ok_or("Failed to retrieve 'argv_ptr' from RSI.")?;
            let argv_ptr = argv_ptr_var.concrete.to_u64();

            // 3. Retrieve 'envp_ptr' from RDX (offset 0x28)
            let envp_ptr_var = cpu_state_guard
                .get_register_by_offset(0x28, 64)
                .ok_or("Failed to retrieve 'envp_ptr' from RDX.")?;
            let envp_ptr = envp_ptr_var.concrete.to_u64();

            // 4. Read the file path from memory
            let path = executor
                .state
                .memory
                .read_string(path_ptr)
                .map_err(|e| format!("Failed to read execve path: {}", e))?;
            log!(
                executor.state.logger.clone(),
                "Executing program at path: {}",
                path
            );

            // 5. Retrieve and log the arguments
            let mut argv = Vec::new();
            let mut i = 0;
            loop {
                let arg_ptr = executor
                    .state
                    .memory
                    .read_u64(argv_ptr + (i * 8), &mut executor.state.logger.clone())
                    .map_err(|e| format!("Failed to read argv_ptr at index {}: {}", i, e))?
                    .concrete;
                if arg_ptr == ConcreteVar::Int(0) {
                    break; // Null pointer indicates the end of the argv array
                }
                let arg = executor
                    .state
                    .memory
                    .read_string(arg_ptr.to_u64())
                    .map_err(|e| format!("Failed to read argv[{}]: {}", i, e))?;
                argv.push(arg);
                i += 1;
            }
            log!(executor.state.logger.clone(), "With arguments: {:?}", argv);

            // 6. Retrieve and log the environment variables
            let mut envp = Vec::new();
            let mut j = 0;
            loop {
                let env_ptr = executor
                    .state
                    .memory
                    .read_u64(envp_ptr + (j * 8), &mut executor.state.logger.clone())
                    .map_err(|e| format!("Failed to read envp_ptr at index {}: {}", j, e))?
                    .concrete;
                if env_ptr == ConcreteVar::Int(0) {
                    break; // Null pointer indicates the end of the envp array
                }
                let env = executor
                    .state
                    .memory
                    .read_string(env_ptr.to_u64())
                    .map_err(|e| format!("Failed to read envp[{}]: {}", j, e))?;
                envp.push(env);
                j += 1;
            }
            log!(executor.state.logger.clone(), "And environment: {:?}", envp);

            // 7. Simulate execve operation by loading and executing the new program - TODO
            log!(
                executor.state.logger.clone(),
                "Simulated execve would now load and execute the new program."
            );

            // 8. Set RAX to 0 to indicate success
            let rax_value = MemoryValue {
                concrete: 0,
                symbolic: BV::from_u64(executor.context, 0, 64),
                size: 64,
            };
            let rax_concolic_var = ConcolicVar::new_from_memory_value(&rax_value);
            cpu_state_guard
                .set_register_value_by_offset(0x0, rax_concolic_var, 64)
                .map_err(|e| format!("Failed to set RAX: {}", e))?;

            drop(cpu_state_guard);

            // 9. Record the operation in concolic variables (if applicable)
            let current_addr_hex = executor
                .current_address
                .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
            let result_var_name = format!(
                "{}-{:02}-callother-sys-execve",
                current_addr_hex, executor.instruction_counter
            );
            executor.state.create_or_update_concolic_variable_int(
                &result_var_name,
                path_ptr.try_into().unwrap(),
                SymbolicVar::Int(BV::from_u64(
                    executor.context,
                    path_ptr.try_into().unwrap(),
                    64,
                )),
            );
        }
        56 => {
            // sys_clone - Create a new OS thread (used by Go runtime newosproc)
            log!(executor.state.logger.clone(), "Syscall type: sys_clone");

            // Arguments for clone syscall (x86-64 ABI):
            // RDI: clone_flags
            // RSI: stack_pointer (child stack)
            // RDX: parent_tid_ptr (CLONE_PARENT_SETTID)
            // R10: child_tid_ptr (CLONE_CHILD_SETTID)
            // R8: tls (TLS descriptor)

            let clone_flags = cpu_state_guard
                .get_register_by_offset(0x38, 64) // RDI
                .ok_or("Failed to retrieve clone_flags from RDI")?
                .get_concrete_value()?;

            let child_stack = cpu_state_guard
                .get_register_by_offset(0x30, 64) // RSI
                .ok_or("Failed to retrieve child_stack from RSI")?
                .get_concrete_value()?;

            let parent_tid_ptr_val = cpu_state_guard
                .get_register_by_offset(0x10, 64) // RDX
                .ok_or("Failed to retrieve parent_tid_ptr from RDX")?
                .get_concrete_value()?;
            let parent_tid_ptr = if parent_tid_ptr_val != 0 {
                Some(parent_tid_ptr_val)
            } else {
                None
            };

            let child_tid_ptr_val = cpu_state_guard
                .get_register_by_offset(0x98, 64) // R10
                .ok_or("Failed to retrieve child_tid_ptr from R10")?
                .get_concrete_value()?;
            let child_tid_ptr = if child_tid_ptr_val != 0 {
                Some(child_tid_ptr_val)
            } else {
                None
            };

            let tls_base = cpu_state_guard
                .get_register_by_offset(0x80, 64) // R8
                .ok_or("Failed to retrieve tls from R8")?
                .get_concrete_value()?;

            log!(
                executor.state.logger.clone(),
                "clone: flags=0x{:x}, stack=0x{:x}, tls=0x{:x}",
                clone_flags,
                child_stack,
                tls_base
            );

            // Get the entry point (instruction after syscall)
            let entry_point = executor.current_address.unwrap_or(0);

            // Release CPU lock before calling thread_manager
            drop(cpu_state_guard);

            // Create the new thread using ThreadManager
            let new_tid = executor
                .state
                .thread_manager
                .lock()
                .unwrap()
                .clone_thread(
                    child_stack,
                    entry_point,
                    tls_base,
                    clone_flags,
                    child_tid_ptr,
                    None, // child_cleartid_ptr is set via CLONE_CHILD_CLEARTID flag handling
                )
                .map_err(|e| format!("Failed to clone thread: {}", e))?;

            // Handle CLONE_PARENT_SETTID: write new TID to parent's memory
            if let Some(parent_ptr) = parent_tid_ptr {
                if clone_flags & 0x00100000 != 0 {
                    // CLONE_PARENT_SETTID
                    let tid_symbolic = BV::from_u64(executor.context, new_tid, 64);
                    let tid_value = MemoryValue::new(new_tid, tid_symbolic, 64);
                    executor
                        .state
                        .memory
                        .write_u64(parent_ptr, &tid_value)
                        .map_err(|e| format!("Failed to write parent TID: {:?}", e))?;
                    log!(
                        executor.state.logger.clone(),
                        "clone: wrote TID {} to parent ptr 0x{:x}",
                        new_tid,
                        parent_ptr
                    );
                }
            }

            // Handle CLONE_CHILD_SETTID: will be written by child when it runs
            if let Some(child_ptr) = child_tid_ptr {
                if clone_flags & 0x01000000 != 0 {
                    // CLONE_CHILD_SETTID
                    let tid_symbolic = BV::from_u64(executor.context, new_tid, 64);
                    let tid_value = MemoryValue::new(new_tid, tid_symbolic, 64);
                    executor
                        .state
                        .memory
                        .write_u64(child_ptr, &tid_value)
                        .map_err(|e| format!("Failed to write child TID: {:?}", e))?;
                    log!(
                        executor.state.logger.clone(),
                        "clone: wrote TID {} to child ptr 0x{:x}",
                        new_tid,
                        child_ptr
                    );
                }
            }

            // For the parent thread: return the new child TID in RAX
            let rax_offset = 0x0; // RAX offset
            let rax_size = 64;
            let value_symbolic = BV::from_u64(executor.context, new_tid, rax_size);
            let value_concolic = ConcolicVar::new_concrete_and_symbolic_int(
                new_tid,
                value_symbolic,
                executor.context,
            );

            // Use overlay-aware register write
            executor.set_register_overlay_aware(rax_offset, value_concolic, rax_size)?;

            log!(
                executor.state.logger.clone(),
                "clone: returned TID {} to parent thread",
                new_tid
            );
        }
        60 => {
            // sys_exit
            log!(executor.state.logger.clone(), "Syscall type: sys_exit");
            let status = cpu_state_guard
                .get_register_by_offset(0x38, 64)
                .unwrap()
                .get_concrete_value()?;
            log!(
                executor.state.logger.clone(),
                "Exiting with status code: {}",
                status
            );
            drop(cpu_state_guard);

            // Create the concolic variables for the results
            let current_addr_hex = executor
                .current_address
                .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
            let result_var_name = format!(
                "{}-{:02}-callother-sys-exit",
                current_addr_hex, executor.instruction_counter
            );
            executor.state.create_or_update_concolic_variable_int(
                &result_var_name,
                status.try_into().unwrap(),
                SymbolicVar::Int(BV::from_u64(
                    executor.context,
                    status.try_into().unwrap(),
                    64,
                )),
            );
        }
        97 => {
            // sys_getrlimit
            log!(executor.state.logger.clone(), "Syscall type: sys_getrlimit");

            // Retrieve 'resource' from RDI
            let resource_offset = 0x38; // RDI register offset
            let resource_var = cpu_state_guard
                .get_register_by_offset(resource_offset, 64)
                .ok_or("Failed to retrieve 'resource' from RDI.")?;
            let resource = resource_var.concrete.to_u64() as u32;

            // Retrieve 'rlim' pointer from RSI
            let rlim_ptr_offset = 0x30; // RSI register offset
            let rlim_ptr_var = cpu_state_guard
                .get_register_by_offset(rlim_ptr_offset, 64)
                .ok_or("Failed to retrieve 'rlim' pointer from RSI.")?;
            let rlim_ptr = rlim_ptr_var.concrete.to_u64();

            log!(
                executor.state.logger.clone(),
                "sys_getrlimit called with resource: {}, rlim_ptr: 0x{:x}",
                resource,
                rlim_ptr
            );

            // For simplicity, set rlim_cur and rlim_max to RLIM_INFINITY
            const RLIM_INFINITY: u64 = 0xffff_ffff_ffff_ffff;

            // Create a buffer to hold the rlimit data
            let mut rlimit_bytes = Vec::with_capacity(16); // 8 bytes for rlim_cur and 8 bytes for rlim_max

            // Write rlim_cur and rlim_max to the buffer
            rlimit_bytes
                .write_u64::<LittleEndian>(RLIM_INFINITY)
                .map_err(|e| format!("Failed to write rlim_cur to buffer: {}", e))?;
            rlimit_bytes
                .write_u64::<LittleEndian>(RLIM_INFINITY)
                .map_err(|e| format!("Failed to write rlim_max to buffer: {}", e))?;

            // Write the rlimit data to memory at rlim_ptr
            executor
                .state
                .memory
                .write_bytes(rlim_ptr, &rlimit_bytes)
                .map_err(|e| format!("Failed to write rlimit to memory: {}", e))?;

            // Set return value to 0 (success)
            let rax_value = ConcolicVar::new_concrete_and_symbolic_int(
                0,
                BV::from_u64(executor.context, 0, 64),
                executor.context,
            );
            cpu_state_guard
                .set_register_value_by_offset(rax_offset, rax_value, 64)
                .map_err(|e| format!("Failed to set RAX: {}", e))?;

            drop(cpu_state_guard);

            // Record the operation for tracing
            let current_addr_hex = executor
                .current_address
                .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
            let result_var_name = format!(
                "{}-{:02}-callother-sys-getrlimit",
                current_addr_hex, executor.instruction_counter
            );
            executor.state.create_or_update_concolic_variable_int(
                &result_var_name,
                0u64,
                SymbolicVar::Int(BV::from_u64(executor.context, 0u64, 64)),
            );

            log!(
                executor.state.logger.clone(),
                "sys_getrlimit executed successfully"
            );
        }
        131 => {
            // sys_sigaltstack
            log!(
                executor.state.logger.clone(),
                "Syscall type: sys_sigaltstack"
            );

            // Retrieve the pointer to the new signal stack structure (ss) from the RDI register
            let ss_offset = 0x38; // RDI register offset for 'ss'
            let ss_ptr = match cpu_state_guard.get_register_by_offset(ss_offset, 64) {
                // If the register is found, get its concrete value
                Some(register) => match register.get_concrete_value() {
                    Ok(value) => value,
                    Err(e) => {
                        // Log an error if the concrete value cannot be obtained
                        log!(
                            executor.state.logger.clone(),
                            "Error getting concrete value for ss_ptr: {:?}",
                            e
                        );
                        return Err("Failed to get concrete value for ss_ptr".to_string());
                    }
                },
                // Log an error if the register is not found
                None => {
                    log!(
                        executor.state.logger.clone(),
                        "Error: Register at offset 0x38 not found"
                    );
                    return Err("Failed to get register by offset for ss_ptr".to_string());
                }
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
                        log!(
                            executor.state.logger.clone(),
                            "Error getting concrete value for oss_ptr: {:?}",
                            e
                        );
                        return Err("Failed to get concrete value for oss_ptr".to_string());
                    }
                },
                // Log an error if the register is not found
                None => {
                    log!(
                        executor.state.logger.clone(),
                        "Error: Register at offset 0x30 not found"
                    );
                    return Err("Failed to get register by offset for oss_ptr".to_string());
                }
            };
            log!(executor.state.logger.clone(), "oss_ptr: 0x{:x}", oss_ptr);

            if ss_ptr != 0 {
                // If ss_ptr is not null, read the new signal stack structure from memory
                let ss_sp = match executor
                    .state
                    .memory
                    .read_u64(ss_ptr, &mut executor.state.logger.clone())
                {
                    Ok(value) => value.concrete,
                    Err(e) => {
                        log!(
                            executor.state.logger.clone(),
                            "Error reading ss_sp from memory: {:?}",
                            e
                        );
                        return Err("Failed to read ss_sp from memory".to_string());
                    }
                };
                log!(executor.state.logger.clone(), "Read ss_sp: 0x{:x}", ss_sp);

                let ss_flags = match executor
                    .state
                    .memory
                    .read_u32(ss_ptr + 8, &mut executor.state.logger.clone())
                {
                    Ok(value) => value.concrete.to_i32(),
                    Err(e) => {
                        log!(
                            executor.state.logger.clone(),
                            "Error reading ss_flags from memory: {:?}",
                            e
                        );
                        return Err("Failed to read ss_flags from memory".to_string());
                    }
                };
                log!(
                    executor.state.logger.clone(),
                    "Read ss_flags: 0x{:?}",
                    ss_flags
                );

                let ss_size = match executor
                    .state
                    .memory
                    .read_u64(ss_ptr + 16, &mut executor.state.logger.clone())
                {
                    Ok(value) => value.concrete,
                    Err(e) => {
                        log!(
                            executor.state.logger.clone(),
                            "Error reading ss_size from memory: {:?}",
                            e
                        );
                        return Err("Failed to read ss_size from memory".to_string());
                    }
                };
                log!(
                    executor.state.logger.clone(),
                    "Read ss_size: 0x{:x}",
                    ss_size
                );

                // Validate the stack flags
                if ss_flags != Ok(0i32) && ss_flags != Ok(SS_DISABLE as i32) {
                    log!(
                        executor.state.logger.clone(),
                        "Invalid ss_flags: 0x{:?}",
                        ss_flags
                    );
                    return Err("EINVAL: Invalid ss_flags".to_string());
                }

                // Validate the stack size
                if ss_flags == Ok(0) && ss_size.to_u64() < MINSIGSTKSZ as u64 {
                    log!(
                        executor.state.logger.clone(),
                        "Stack size too small: 0x{:x}",
                        ss_size
                    );
                    return Err("ENOMEM: Stack size too small".to_string());
                }

                // Update the alternate signal stack with the new values
                executor.state.altstack.ss_sp = ss_sp.to_u64();
                executor.state.altstack.ss_flags = ss_flags.unwrap() as u64;
                executor.state.altstack.ss_size = ss_size.to_u64();
                log!(
                    executor.state.logger.clone(),
                    "Updated altstack: ss_sp=0x{:x}, ss_flags=0x{:?}, ss_size=0x{:x}",
                    ss_sp,
                    ss_flags,
                    ss_size
                );
            }

            if oss_ptr != 0 {
                // If oss_ptr is not null, return the current alternate signal stack
                let current_ss_sp = executor.state.altstack.ss_sp;
                let current_ss_sp_symbolic =
                    SymbolicVar::new_int(current_ss_sp as i64, executor.context, 64)
                        .to_bv(executor.context);
                let current_ss_flags = executor.state.altstack.ss_flags;
                let current_ss_flags_symbolic =
                    SymbolicVar::new_int(current_ss_flags as i64, executor.context, 32)
                        .to_bv(executor.context);
                let current_ss_size = executor.state.altstack.ss_size;
                let current_ss_size_symbolic =
                    SymbolicVar::new_int(current_ss_size as i64, executor.context, 64)
                        .to_bv(executor.context);
                log!(
                    executor.state.logger.clone(),
                    "Returning current altstack: ss_sp=0x{:x}, ss_flags=0x{:x}, ss_size=0x{:x}",
                    current_ss_sp,
                    current_ss_flags,
                    current_ss_size
                );

                // Write the current alternate signal stack information to memory
                if let Err(e) = executor.state.memory.write_u64(
                    oss_ptr,
                    &MemoryValue::new(current_ss_sp, current_ss_sp_symbolic, 64),
                ) {
                    log!(
                        executor.state.logger.clone(),
                        "Error writing current_ss_sp to memory: {:?}",
                        e
                    );
                    return Err("Failed to write current_ss_sp to memory".to_string());
                }
                if let Err(e) = executor.state.memory.write_u32(
                    oss_ptr + 8,
                    &MemoryValue::new(current_ss_flags, current_ss_flags_symbolic, 32),
                ) {
                    log!(
                        executor.state.logger.clone(),
                        "Error writing current_ss_flags to memory: {:?}",
                        e
                    );
                    return Err("Failed to write current_ss_flags to memory".to_string());
                }
                if let Err(e) = executor.state.memory.write_u64(
                    oss_ptr + 16,
                    &MemoryValue::new(current_ss_size, current_ss_size_symbolic, 64),
                ) {
                    log!(
                        executor.state.logger.clone(),
                        "Error writing current_ss_size to memory: {:?}",
                        e
                    );
                    return Err("Failed to write current_ss_size to memory".to_string());
                }
            }

            drop(cpu_state_guard);

            // Set the result of the syscall (0 for success) in the RAX register
            // Use overlay-aware register write
            executor.set_register_overlay_aware(
                rax_offset,
                ConcolicVar::new_concrete_and_symbolic_int(
                    0,
                    SymbolicVar::new_int(0, executor.context, 64).to_bv(executor.context),
                    executor.context,
                ),
                64,
            )?;

            // Create the concolic variables for the results
            let current_addr_hex = executor
                .current_address
                .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
            let result_var_name = format!(
                "{}-{:02}-callother-sys-sigaltstack",
                current_addr_hex, executor.instruction_counter
            );
            executor.state.create_or_update_concolic_variable_int(
                &result_var_name,
                oss_ptr.try_into().unwrap(),
                SymbolicVar::Int(BV::from_u64(
                    executor.context,
                    oss_ptr.try_into().unwrap(),
                    64,
                )),
            );
        }
        158 => {
            // sys_arch_prctl: set architecture-specific thread state
            log!(
                executor.state.logger.clone(),
                "Syscall invoked: sys_arch_prctl"
            );

            let code = cpu_state_guard
                .get_register_by_offset(0x38, 64)
                .ok_or("Failed to retrieve code from register")?
                .get_concrete_value()
                .map_err(|e| e.to_string())?;

            let addr = cpu_state_guard
                .get_register_by_offset(0x30, 64)
                .ok_or("Failed to retrieve address from register")?
                .get_concrete_value()
                .map_err(|e| e.to_string())?;

            let addr_concolic_reg = cpu_state_guard
                .get_register_by_offset(0x30, 64)
                .ok_or("Failed to retrieve address from register")?;

            let addr_concolic = ConcolicVar::new_concrete_and_symbolic_int(
                addr_concolic_reg.concrete.to_u64(),
                addr_concolic_reg.symbolic.to_bv(executor.context),
                executor.context,
            );

            log!(
                executor.state.logger.clone(),
                "Arch-prctl code: {:#x}, Address: {:#x}",
                code,
                addr
            );

            match code {
                // Constants per Linux arch_prctl for x86_64
                arch::ARCH_SET_FS => {
                    log!(executor.state.logger, "Setting FS base to {:#x}", addr);
                    drop(cpu_state_guard);
                    // Set FS base from RSI - use overlay-aware register write
                    executor.set_register_overlay_aware(0x110, addr_concolic, 64)?;
                    // Return 0 in RAX for success - use overlay-aware register write
                    executor.set_register_overlay_aware(
                        rax_offset,
                        ConcolicVar::new_concrete_and_symbolic_int(
                            0,
                            SymbolicVar::new_int(0, executor.context, 64).to_bv(executor.context),
                            executor.context,
                        ),
                        64,
                    )?;
                    return Ok(());
                }
                arch::ARCH_GET_FS => {
                    log!(
                        executor.state.logger,
                        "Getting FS base to memory at 0x{:x}",
                        addr
                    );
                    // Read FS base and write it back to the user pointer (RSI)
                    let fs_val = cpu_state_guard
                        .get_register_by_offset(0x110, 64)
                        .ok_or("Failed to read FS base register")?;
                    let fs_conc = fs_val.get_concrete_value().map_err(|e| e.to_string())?;
                    let fs_sym = fs_val.symbolic.to_bv(executor.context);
                    drop(cpu_state_guard);
                    let mem_value = MemoryValue::new(fs_conc, fs_sym, 64);
                    executor
                        .state
                        .memory
                        .write_value(addr, &mem_value)
                        .map_err(|e| format!("Failed to write FS base to memory: {:?}", e))?;
                    // Return 0 in RAX for success - use overlay-aware register write
                    executor.set_register_overlay_aware(
                        rax_offset,
                        ConcolicVar::new_concrete_and_symbolic_int(
                            0,
                            SymbolicVar::new_int(0, executor.context, 64).to_bv(executor.context),
                            executor.context,
                        ),
                        64,
                    )?;
                    return Ok(());
                }
                arch::ARCH_SET_GS => {
                    log!(executor.state.logger, "Setting GS base to {:#x}", addr);
                    drop(cpu_state_guard);
                    // Set GS base from RSI - use overlay-aware register write
                    executor.set_register_overlay_aware(0x118, addr_concolic, 64)?;
                    // Return 0 in RAX for success - use overlay-aware register write
                    executor.set_register_overlay_aware(
                        rax_offset,
                        ConcolicVar::new_concrete_and_symbolic_int(
                            0,
                            SymbolicVar::new_int(0, executor.context, 64).to_bv(executor.context),
                            executor.context,
                        ),
                        64,
                    )?;
                    return Ok(());
                }
                arch::ARCH_GET_GS => {
                    log!(
                        executor.state.logger,
                        "Getting GS base to memory at 0x{:x}",
                        addr
                    );
                    // Read GS base and write it back to the user pointer (RSI)
                    let gs_val = cpu_state_guard
                        .get_register_by_offset(0x118, 64)
                        .ok_or("Failed to read GS base register")?;
                    let gs_conc = gs_val.get_concrete_value().map_err(|e| e.to_string())?;
                    let gs_sym = gs_val.symbolic.to_bv(executor.context);
                    drop(cpu_state_guard);
                    let mem_value = MemoryValue::new(gs_conc, gs_sym, 64);
                    executor
                        .state
                        .memory
                        .write_value(addr, &mem_value)
                        .map_err(|e| format!("Failed to write GS base to memory: {:?}", e))?;
                    // Return 0 in RAX for success - use overlay-aware register write
                    executor.set_register_overlay_aware(
                        rax_offset,
                        ConcolicVar::new_concrete_and_symbolic_int(
                            0,
                            SymbolicVar::new_int(0, executor.context, 64).to_bv(executor.context),
                            executor.context,
                        ),
                        64,
                    )?;
                    return Ok(());
                }
                _ => {
                    log!(
                        executor.state.logger,
                        "Unsupported arch-prctl code: {:#x}",
                        code
                    );
                    return Err(format!("Unsupported arch-prctl code: {:#x}", code));
                }
            }
            // Note: All match arms return, so no code needed here
        }
        186 => {
            // sys_gettid
            log!(executor.state.logger.clone(), "Syscall type: sys_gettid");

            // Get the actual TID using nix crate
            let tid = unsafe { gettid() } as u64;

            drop(cpu_state_guard);

            // Set the TID in RAX - use overlay-aware register write
            executor.set_register_overlay_aware(
                rax_offset,
                ConcolicVar::new_concrete_and_symbolic_int(
                    tid,
                    SymbolicVar::new_int(tid as i64, executor.context, 64).to_bv(executor.context),
                    executor.context,
                ),
                64,
            )?;

            // Create the concolic variables for the results
            let current_addr_hex = executor
                .current_address
                .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
            let result_var_name = format!(
                "{}-{:02}-callother-sys-gettid",
                current_addr_hex, executor.instruction_counter
            );
            executor.state.create_or_update_concolic_variable_int(
                &result_var_name,
                tid.try_into().unwrap(),
                SymbolicVar::Int(BV::from_u64(executor.context, tid.try_into().unwrap(), 64)),
            );
        }
        202 => {
            // sys_futex
            log!(executor.state.logger.clone(), "Syscall type: sys_futex");

            // Read arguments from registers
            let uaddr = cpu_state_guard
                .get_register_by_offset(0x38, 64)
                .unwrap()
                .get_concrete_value()?;
            let op = cpu_state_guard
                .get_register_by_offset(0x30, 32)
                .unwrap()
                .get_concrete_value()?;
            let val = cpu_state_guard
                .get_register_by_offset(0x28, 32)
                .unwrap()
                .get_concrete_value()?;
            let timeout_ptr = cpu_state_guard
                .get_register_by_offset(0x20, 64)
                .unwrap()
                .get_concrete_value()?;
            let uaddr2 = cpu_state_guard
                .get_register_by_offset(0x18, 64)
                .unwrap()
                .get_concrete_value()?;
            let val3 = cpu_state_guard
                .get_register_by_offset(0x10, 32)
                .unwrap()
                .get_concrete_value()?;

            let _timeout = if timeout_ptr != 0 {
                // TODO : Read the timeout value from the memory location
                Some(Duration::from_secs(5)) // for now, use a 5-second timeout
            } else {
                None
            };

            let operation = op & !FUTEX_PRIVATE_FLAG;

            match operation {
                FUTEX_WAIT => {
                    log!(executor.state.logger.clone(), "Futex type: FUTEX_WAIT");
                    // This should block the thread if *uaddr == val, until *uaddr changes or optionally timeout expires
                    let futex_uaddr = uaddr as u64;
                    let _futex_val = val as i32;
                    // ignore this operation for now
                    // executor.state.futex_manager.futex_wait(futex_uaddr, futex_val, timeout)?;

                    drop(cpu_state_guard);

                    // Create the concolic variables for the results
                    let current_addr_hex = executor
                        .current_address
                        .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
                    let result_var_name = format!(
                        "{}-{:02}-callother-sys-futex_wait",
                        current_addr_hex, executor.instruction_counter
                    );
                    executor.state.create_or_update_concolic_variable_int(
                        &result_var_name,
                        futex_uaddr.try_into().unwrap(),
                        SymbolicVar::Int(BV::from_u64(
                            executor.context,
                            futex_uaddr.try_into().unwrap(),
                            64,
                        )),
                    );
                }
                FUTEX_WAKE => {
                    log!(executor.state.logger.clone(), "Futex type: FUTEX_WAKE");
                    // This should wake up to 'val' number of threads waiting on 'uaddr'
                    let futex_uaddr = uaddr as u64;
                    let futex_val = val as usize;

                    executor.state.futex_manager.futex_wake(
                        futex_uaddr,
                        futex_val.try_into().map_err(|_| "Invalid futex_val")?,
                    )?;

                    drop(cpu_state_guard);

                    // Create the concolic variables for the results
                    let current_addr_hex = executor
                        .current_address
                        .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
                    let result_var_name = format!(
                        "{}-{:02}-callother-sys-futex_wake",
                        current_addr_hex, executor.instruction_counter
                    );
                    executor.state.create_or_update_concolic_variable_int(
                        &result_var_name,
                        futex_uaddr.try_into().unwrap(),
                        SymbolicVar::Int(BV::from_u64(
                            executor.context,
                            futex_uaddr.try_into().unwrap(),
                            64,
                        )),
                    );
                }
                FUTEX_REQUEUE => {
                    log!(executor.state.logger.clone(), "Futex type: FUTEX_REQUEUE");
                    // This should requeue up to 'val' number of threads from 'uaddr' to 'uaddr2'
                    let futex_uaddr = uaddr as u64;
                    let futex_val = val as usize;
                    let futex_uaddr2 = uaddr2 as u64;
                    let futex_val3 = val3 as usize;
                    executor.state.futex_manager.futex_requeue(
                        futex_uaddr,
                        futex_val,
                        futex_uaddr2,
                        futex_val3,
                    )?;

                    drop(cpu_state_guard);

                    // Create the concolic variables for the results
                    let current_addr_hex = executor
                        .current_address
                        .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
                    let result_var_name = format!(
                        "{}-{:02}-callother-sys-futex_requeue",
                        current_addr_hex, executor.instruction_counter
                    );
                    executor.state.create_or_update_concolic_variable_int(
                        &result_var_name,
                        futex_uaddr.try_into().unwrap(),
                        SymbolicVar::Int(BV::from_u64(
                            executor.context,
                            futex_uaddr.try_into().unwrap(),
                            64,
                        )),
                    );
                }
                _ => {
                    // if the callother number is not handled, stop the execution
                    log!(
                        executor.state.logger.clone(),
                        "Unhandled FUTEX type: op={}",
                        op
                    );
                    log!(executor.state.logger.clone(), "For information, the value of operation (op & !FUTEX_PRIVATE_FLAG) is : {}", operation);
                    process::exit(1);
                }
            }
        }
        204 => {
            // sys_sched_getaffinity : gets the CPU affinity mask of a process
            log!(
                executor.state.logger.clone(),
                "Syscall type: sys_sched_getaffinity"
            );

            // 1. Retrieve 'pid' from RDI (offset 0x38)
            let pid_var = cpu_state_guard
                .get_register_by_offset(0x38, 64)
                .ok_or("Failed to retrieve 'pid' from RDI.")?;
            let pid = pid_var.concrete.to_u64() as u32;

            // 2. Retrieve 'cpusetsize' from RSI (offset 0x30)
            let cpusetsize_var = cpu_state_guard
                .get_register_by_offset(0x30, 64)
                .ok_or("Failed to retrieve 'cpusetsize' from RSI.")?;
            let cpusetsize = cpusetsize_var.concrete.to_u64() as usize;

            // 3. Retrieve 'mask_ptr' from RDX (offset 0x28)
            let mask_ptr_var = cpu_state_guard
                .get_register_by_offset(0x28, 64)
                .ok_or("Failed to retrieve 'mask_ptr' from RDX.")?;
            let mask_ptr = mask_ptr_var.concrete.to_u64();

            // 4. Validate 'cpusetsize'
            if cpusetsize > 64 {
                log!(
                    executor.state.logger.clone(),
                    "Error: cpusetsize of {} exceeds 64 bits, which is not supported.",
                    cpusetsize
                );
                return Err(format!(
                    "cpusetsize of {} is too large to handle",
                    cpusetsize
                ));
            }

            // 5. Simulate getting the CPU affinity for the given pid and cpusetsize
            let simulated_mask = if cpusetsize == 0 {
                0u64
            } else {
                (1u64.checked_shl(cpusetsize as u32).unwrap_or(0) - 1) & 0xFFFFFFFFFFFFFFFF
            };

            log!(
                executor.state.logger.clone(),
                "Getting CPU affinity for PID {}, size {}",
                pid,
                cpusetsize
            );

            // 6. Write the simulated mask to the memory location pointed to by mask_ptr
            let mask_memory_value = MemoryValue {
                concrete: simulated_mask,
                symbolic: BV::from_u64(executor.context, simulated_mask, 64),
                size: 64,
            };
            executor
                .state
                .memory
                .write_value(mask_ptr, &mask_memory_value)
                .map_err(|e| format!("Failed to write CPU affinity mask to memory: {}", e))?;

            // 7. Set RAX to 0 to indicate success
            let rax_value = MemoryValue {
                concrete: 0,
                symbolic: BV::from_u64(executor.context, 0, 64),
                size: 64,
            };
            let rax_concolic_var = ConcolicVar::new_from_memory_value(&rax_value);
            cpu_state_guard
                .set_register_value_by_offset(0x0, rax_concolic_var, 64)
                .map_err(|e| format!("Failed to set RAX: {}", e))?;

            drop(cpu_state_guard);

            // 8. Record the operation in concolic variables
            let current_addr_hex = executor
                .current_address
                .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
            let result_var_name = format!(
                "{}-{:02}-callother-sys-sched_getaffinity",
                current_addr_hex, executor.instruction_counter
            );
            executor.state.create_or_update_concolic_variable_int(
                &result_var_name,
                simulated_mask,
                SymbolicVar::Int(BV::from_u64(executor.context, simulated_mask, 64)),
            );
        }

        231 => {
            // sys_exit_group
            log!(
                executor.state.logger.clone(),
                "Syscall type: sys_exit_group"
            );
            let status = cpu_state_guard
                .get_register_by_offset(0x38, 64)
                .unwrap()
                .get_concrete_value()?;
            log!(
                executor.state.logger.clone(),
                "Exiting group with status code: {}",
                status
            );
            drop(cpu_state_guard);

            // Set the exit status and termination flag
            executor.state.exit_status = Some(status as i32);
            executor.state.is_terminated = true;

            // Create the concolic variables for the results
            let current_addr_hex = executor
                .current_address
                .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
            let result_var_name = format!(
                "{}-{:02}-callother-sys-exit_group",
                current_addr_hex, executor.instruction_counter
            );
            executor.state.create_or_update_concolic_variable_int(
                &result_var_name,
                status.try_into().unwrap(),
                SymbolicVar::Int(BV::from_u64(
                    executor.context,
                    status.try_into().unwrap(),
                    64,
                )),
            );
        }
        228 => {
            // sys_clock_gettime
            log!(
                executor.state.logger.clone(),
                "Syscall type: sys_clock_gettime"
            );

            // Retrieve 'clk_id' from RDI
            let clk_id_offset = 0x38; // RDI register offset
            let clk_id_var = cpu_state_guard
                .get_register_by_offset(clk_id_offset, 64)
                .ok_or("Failed to retrieve 'clk_id' from RDI.")?;
            let clk_id = clk_id_var.concrete.to_u64() as i32;

            // Retrieve 'tp' pointer from RSI
            let tp_ptr_offset = 0x30; // RSI register offset
            let tp_ptr_var = cpu_state_guard
                .get_register_by_offset(tp_ptr_offset, 64)
                .ok_or("Failed to retrieve 'tp' pointer from RSI.")?;
            let tp_ptr = tp_ptr_var.concrete.to_u64();

            log!(
                executor.state.logger.clone(),
                "sys_clock_gettime called with clk_id: {}, tp_ptr: 0x{:x}",
                clk_id,
                tp_ptr
            );

            // Drop the CPU state guard before calling overlay-aware methods
            drop(cpu_state_guard);

            // Retrieve the current time based on clk_id
            let time_result: Result<(i64, i64), String> = {
                use std::time::{Instant, SystemTime, UNIX_EPOCH};

                match clk_id {
                    0 => {
                        // CLOCK_REALTIME
                        let now = SystemTime::now();
                        let duration_since_epoch = now
                            .duration_since(UNIX_EPOCH)
                            .map_err(|e| format!("Time error: {}", e))?;

                        let tv_sec = duration_since_epoch.as_secs() as i64;
                        let tv_nsec = duration_since_epoch.subsec_nanos() as i64;

                        Ok((tv_sec, tv_nsec))
                    }
                    1 => {
                        // CLOCK_MONOTONIC
                        let now = Instant::now();
                        let duration_since_start = now.elapsed();

                        let tv_sec = duration_since_start.as_secs() as i64;
                        let tv_nsec = duration_since_start.subsec_nanos() as i64;

                        Ok((tv_sec, tv_nsec))
                    }
                    4 => {
                        // CLOCK_MONOTONIC_RAW
                        // Since Rust's standard library doesn't provide a direct equivalent for CLOCK_MONOTONIC_RAW,
                        // we can use the same as CLOCK_MONOTONIC for simplicity.
                        let now = Instant::now();
                        let duration_since_start = now.elapsed();

                        let tv_sec = duration_since_start.as_secs() as i64;
                        let tv_nsec = duration_since_start.subsec_nanos() as i64;

                        Ok((tv_sec, tv_nsec))
                    }
                    _ => Err(format!("Unsupported clk_id: {}", clk_id)),
                }
            };

            // Handle error case with overlay-aware register write
            let (tv_sec, tv_nsec) = match time_result {
                Ok((sec, nsec)) => (sec, nsec),
                Err(e) => {
                    // Unsupported clk_id - set RAX to -1 to indicate error
                    let rax_value = ConcolicVar::new_concrete_and_symbolic_int(
                        -1i64 as u64,
                        BV::from_u64(executor.context, (-1i64) as u64, 64),
                        executor.context,
                    );
                    // Use overlay-aware register write to not corrupt base state
                    executor
                        .set_register_overlay_aware(rax_offset, rax_value, 64)
                        .map_err(|err| format!("Failed to set RAX: {}", err))?;

                    return Err(e);
                }
            };

            // Create a buffer to hold the timespec data
            let mut timespec_bytes = Vec::with_capacity(16); // 8 bytes for tv_sec and 8 bytes for tv_nsec

            // Write tv_sec and tv_nsec to the buffer
            timespec_bytes
                .write_i64::<LittleEndian>(tv_sec)
                .map_err(|e| format!("Failed to write tv_sec to buffer: {}", e))?;
            timespec_bytes
                .write_i64::<LittleEndian>(tv_nsec)
                .map_err(|e| format!("Failed to write tv_nsec to buffer: {}", e))?;

            // Write the timespec data to memory at tp_ptr
            // Use overlay-aware memory write if in overlay mode
            if in_overlay_mode {
                // Write to overlay memory
                if let Some(ref mut overlay) = executor.overlay_state {
                    overlay.write_memory_bytes(tp_ptr, &timespec_bytes);
                }
            } else {
                // Write to base memory
                executor
                    .state
                    .memory
                    .write_bytes(tp_ptr, &timespec_bytes)
                    .map_err(|e| format!("Failed to write timespec to memory: {}", e))?;
            }

            // Set return value to 0 (success) using overlay-aware register write
            let rax_value = ConcolicVar::new_concrete_and_symbolic_int(
                0,
                BV::from_u64(executor.context, 0, 64),
                executor.context,
            );
            executor
                .set_register_overlay_aware(rax_offset, rax_value, 64)
                .map_err(|e| format!("Failed to set RAX: {}", e))?;

            // Record the operation for tracing
            let current_addr_hex = executor
                .current_address
                .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
            let result_var_name = format!(
                "{}-{:02}-callother-sys-clock_gettime",
                current_addr_hex, executor.instruction_counter
            );
            executor.state.create_or_update_concolic_variable_int(
                &result_var_name,
                0u64,
                SymbolicVar::Int(BV::from_u64(executor.context, 0u64, 64)),
            );

            log!(
                executor.state.logger.clone(),
                "sys_clock_gettime executed successfully"
            );
        }
        257 => {
            // sys_openat : open file relative to a directory file descriptor
            log!(executor.state.logger.clone(), "Syscall type: sys_openat");

            let pathname_ptr = {
                // Lock the CPU state and retrieve the relevant register values
                let mut cpu_state_guard = executor.state.cpu_state.lock().unwrap();

                // 1. Retrieve 'pathname_ptr' from RDI (offset 0x30)
                let pathname_ptr_var = cpu_state_guard
                    .get_register_by_offset(0x30, 64)
                    .ok_or("Failed to retrieve 'pathname_ptr' from RDI.")?;
                let pathname_ptr = pathname_ptr_var.concrete.to_u64();

                // 2. Retrieve 'flags' from RSI (offset 0x28)
                let flags_var = cpu_state_guard
                    .get_register_by_offset(0x28, 64)
                    .ok_or("Failed to retrieve 'flags' from RSI.")?;
                let flags = flags_var.concrete.to_u64() as i32;

                // 3. Retrieve 'mode' from RDX (offset 0x20)
                let mode_var = cpu_state_guard
                    .get_register_by_offset(0x20, 64)
                    .ok_or("Failed to retrieve 'mode' from RDX.")?;
                let mode = mode_var.concrete.to_u64() as u32;

                // 4. Read the pathname string from memory
                let pathname = executor
                    .state
                    .memory
                    .read_string(pathname_ptr)
                    .map_err(|e| format!("Failed to read pathname string: {}", e))?;

                // 5. Simulate opening the file via the virtual file system
                let fd = {
                    let mut vfs_guard = executor.state.vfs.write().unwrap(); // Acquire mutable lock
                    vfs_guard.open(&pathname)
                };

                log!(
                    executor.state.logger.clone(),
                    "Opened file at path: '{}' with flags: {}, mode: {}, returned FD: {}",
                    pathname,
                    flags,
                    mode,
                    fd
                );

                // 6. Set the return value (FD) in the RAX register
                let rax_memory_value = MemoryValue {
                    concrete: fd as u64,
                    symbolic: BV::from_u64(executor.context, fd as u64, 64),
                    size: 64,
                };
                let rax_concolic_var = ConcolicVar::new_from_memory_value(&rax_memory_value);
                cpu_state_guard
                    .set_register_value_by_offset(0x0, rax_concolic_var, 64)
                    .map_err(|e| format!("Failed to set RAX: {}", e))?;
                pathname_ptr
            };
            drop(cpu_state_guard);

            // 7. Record the operation in concolic variables (now safe to mutably borrow executor.state)
            let current_addr_hex = executor
                .current_address
                .map_or_else(|| "unknown".to_string(), |addr| format!("{:x}", addr));
            let result_var_name = format!(
                "{}-{:02}-callother-sys-openat",
                current_addr_hex, executor.instruction_counter
            );
            executor.state.create_or_update_concolic_variable_int(
                &result_var_name,
                pathname_ptr,
                SymbolicVar::Int(BV::from_u64(executor.context, pathname_ptr, 64)),
            );
        }
        _ => {
            // Invalid syscall (negative numbers from thread switches or unimplemented syscalls)
            let signed_rax = rax as i64;

            // In overlay mode, just return error instead of exiting
            if in_overlay_mode {
                log!(
                    executor.state.logger.clone(),
                    "[OVERLAY] Unhandled syscall {} in overlay mode - stopping speculative execution",
                    signed_rax
                );
                return Err(format!("Unhandled syscall {} in overlay mode", signed_rax));
            }

            // Print clear error message to stderr and exit
            if signed_rax < 0 {
                eprintln!("\n{}\n", "=".repeat(80));
                eprintln!(
                    "WARNING: Invalid syscall number: {} (likely from corrupted register state)",
                    signed_rax
                );
                eprintln!("This might indicate thread switching issues or invalid CPU state.");
                eprintln!("Execution cannot continue safely.");
                eprintln!("{}\n", "=".repeat(80));
            } else {
                eprintln!("\n{}\n", "=".repeat(80));
                eprintln!("FATAL ERROR: Unhandled syscall number: {}", rax);
                eprintln!(
                    "This means the binary is using a Linux syscall not yet implemented in Zorya."
                );
                eprintln!("Check https://github.com/torvalds/linux/blob/master/arch/x86/entry/syscalls/syscall_64.tbl");
                eprintln!(
                    "to identify the syscall and implement it in executor_callother_syscalls.rs"
                );
                eprintln!("{}\n", "=".repeat(80));
            }

            log!(
                executor.state.logger.clone(),
                "Unhandled/invalid syscall number: {} - stopping execution\n",
                signed_rax
            );

            process::exit(1);
        }
    }
    Ok(())
}
