// SPDX-FileCopyrightText: 2026 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

//! Summary application: implements the register/memory effects of each
//! [`SummaryEffect`] variant.
//!
//! This module contains the logic that the concolic executor invokes when a
//! function call matches a summary table entry. Instead of stepping through
//! thousands of pcode instructions inside a runtime helper, the engine calls
//! [`apply`] to model the observable effects (allocation, return values) and
//! then simulates a function return.

use std::rc::Rc;
use std::sync::Mutex;

use z3::ast::BV;
use z3::Context;

use crate::concolic::ConcolicVar;
use crate::state::cpu_state::CpuState;
use crate::state::memory_x86_64::MemoryX86_64;

use super::SummaryEffect;

/// Outcome of applying a summary effect.
pub enum ApplyOutcome {
    /// Effect applied successfully. The caller should simulate a function return.
    Ok,
    /// A channel was created at `ptr`; the caller should notify the chancheck
    /// plugin with this address and the current thread id.
    ChannelCreated { ptr: u64 },
}

/// Apply the register and memory effects of a summary.
///
/// # Arguments
/// - `effect`: Which effect to apply.
/// - `z3_ctx`: The Z3 context for constructing bitvector constants.
/// - `cpu`: The CPU state (registers).
/// - `memory`: The memory subsystem (for allocation zeroing).
/// - `heap_ptr`: Mutable reference to the synthetic summary heap pointer.
///   Bumped forward on each allocation.
///
/// After this returns [`ApplyOutcome::Ok`] (or `ChannelCreated`), the caller
/// is responsible for simulating the function return (pop RSP, set RIP).
pub fn apply<'ctx>(
    effect: &SummaryEffect,
    z3_ctx: &'ctx Context,
    cpu: &Rc<Mutex<CpuState<'ctx>>>,
    memory: &MemoryX86_64<'ctx>,
    heap_ptr: &mut u64,
) -> ApplyOutcome {
    match effect {
        SummaryEffect::Alloc | SummaryEffect::NewObject => {
            let size = {
                let cpu_lock = cpu.lock().unwrap();
                cpu_lock
                    .get_register_by_offset(0x0, 64)
                    .map(|v| v.concrete.to_u64())
                    .unwrap_or(64)
            };
            let alloc_size = if size == 0 { 8 } else { size.min(4096) };
            let ptr = *heap_ptr;
            *heap_ptr += (alloc_size + 15) & !15;
            let zeros = vec![0u8; alloc_size as usize];
            let _ = memory.write_bytes(ptr, &zeros);
            let result_cv = ConcolicVar::new_concrete_and_symbolic_int(
                ptr,
                BV::from_u64(z3_ctx, ptr, 64),
                z3_ctx,
            );
            let _ = cpu
                .lock()
                .unwrap()
                .set_register_value_by_offset(0x0, result_cv, 64);
            ApplyOutcome::Ok
        }

        SummaryEffect::AllocSlice => {
            let len = {
                let cpu_lock = cpu.lock().unwrap();
                cpu_lock
                    .get_register_by_offset(0x18, 64) // BX = input length
                    .map(|v| v.concrete.to_u64())
                    .unwrap_or(64)
            };
            let alloc_size = if len == 0 { 1 } else { len.min(4096) };
            let ptr = *heap_ptr;
            *heap_ptr += (alloc_size + 15) & !15;
            let zeros = vec![0u8; alloc_size as usize];
            let _ = memory.write_bytes(ptr, &zeros);
            let ptr_cv = ConcolicVar::new_concrete_and_symbolic_int(
                ptr,
                BV::from_u64(z3_ctx, ptr, 64),
                z3_ctx,
            );
            let len_cv = ConcolicVar::new_concrete_and_symbolic_int(
                alloc_size,
                BV::from_u64(z3_ctx, alloc_size, 64),
                z3_ctx,
            );
            {
                let mut cpu_lock = cpu.lock().unwrap();
                let _ = cpu_lock.set_register_value_by_offset(0x0, ptr_cv, 64); // AX = ptr
                let _ = cpu_lock.set_register_value_by_offset(0x18, len_cv.clone(), 64); // BX = len
                let _ = cpu_lock.set_register_value_by_offset(0x8, len_cv, 64); // CX = cap
            }
            ApplyOutcome::Ok
        }

        SummaryEffect::MakeChan => {
            let hchan_size: u64 = 96;
            let ptr = *heap_ptr;
            *heap_ptr += (hchan_size + 15) & !15;
            let zeros = vec![0u8; hchan_size as usize];
            let _ = memory.write_bytes(ptr, &zeros);
            let ptr_cv = ConcolicVar::new_concrete_and_symbolic_int(
                ptr,
                BV::from_u64(z3_ctx, ptr, 64),
                z3_ctx,
            );
            let _ = cpu
                .lock()
                .unwrap()
                .set_register_value_by_offset(0x0, ptr_cv, 64);
            ApplyOutcome::ChannelCreated { ptr }
        }

        SummaryEffect::RoundUpSize => {
            let size = {
                let cpu_lock = cpu.lock().unwrap();
                cpu_lock
                    .get_register_by_offset(0x0, 64)
                    .map(|v| v.concrete.to_u64())
                    .unwrap_or(8)
            };
            let rounded = (size + 7) & !7;
            let result_cv = ConcolicVar::new_concrete_and_symbolic_int(
                rounded,
                BV::from_u64(z3_ctx, rounded, 64),
                z3_ctx,
            );
            let _ = cpu
                .lock()
                .unwrap()
                .set_register_value_by_offset(0x0, result_cv, 64);
            ApplyOutcome::Ok
        }

        SummaryEffect::Nop => ApplyOutcome::Ok,

        SummaryEffect::ReturnZero => {
            let zero_cv =
                ConcolicVar::new_concrete_and_symbolic_int(0, BV::from_u64(z3_ctx, 0, 64), z3_ctx);
            let _ = cpu
                .lock()
                .unwrap()
                .set_register_value_by_offset(0x0, zero_cv, 64);
            ApplyOutcome::Ok
        }
    }
}

/// Clear the Go error return registers appropriate for the given effect.
///
/// Go's register-based ABI uses different registers for the error return
/// depending on the function signature:
/// - `(ptr, error)`: AX=ptr, BX=error_type, CX=error_data
/// - `([]byte, error)`: AX=ptr, BX=len, CX=cap, DI=error_type
///
/// This function zeroes the appropriate error registers so callers don't
/// spuriously take the error path after a summary.
pub fn clear_error_registers<'ctx>(
    effect: &SummaryEffect,
    z3_ctx: &'ctx Context,
    cpu: &Rc<Mutex<CpuState<'ctx>>>,
) {
    match effect {
        SummaryEffect::AllocSlice => {
            let zero_di =
                ConcolicVar::new_concrete_and_symbolic_int(0, BV::from_u64(z3_ctx, 0, 64), z3_ctx);
            let _ = cpu
                .lock()
                .unwrap()
                .set_register_value_by_offset(0x38, zero_di, 64); // DI = nil error
        }
        SummaryEffect::Alloc | SummaryEffect::ReturnZero => {
            let zero =
                ConcolicVar::new_concrete_and_symbolic_int(0, BV::from_u64(z3_ctx, 0, 64), z3_ctx);
            let zero2 =
                ConcolicVar::new_concrete_and_symbolic_int(0, BV::from_u64(z3_ctx, 0, 64), z3_ctx);
            let mut cpu_lock = cpu.lock().unwrap();
            let _ = cpu_lock.set_register_value_by_offset(0x18, zero, 64); // BX = nil type
            let _ = cpu_lock.set_register_value_by_offset(0x8, zero2, 64); // CX = nil data
        }
        _ => {
            // Nop, MakeChan, RoundUpSize, NewObject: don't touch error registers
        }
    }
}
