// SPDX-FileCopyrightText: 2026 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

//! Function summaries — pre-computed input/output relations for runtime helpers.
//!
//! When the concolic executor reaches a call to a known Go runtime helper
//! (e.g. `runtime.mallocgc`, `runtime.makechan`, `runtime.stringtoslicebyte`),
//! instead of symbolically executing thousands of instructions inside the
//! allocator, the summary system:
//!
//! 1. Captures the arguments from the calling convention registers.
//! 2. Applies the summary's modelled effect (e.g. "returns a fresh concrete
//!    pointer to a zeroed region of the requested size").
//! 3. Simulates the function return (writes RAX, pops the return address).
//!
//! This is the "symbolic summaries for heavy runtime helpers" mechanism
//! proposed to bypass the scalability barrier that prevents the engine from
//! reaching application-level synchronisation logic (channel ops, mutex calls)
//! within budget.
//!
//! ## Design decisions
//!
//! - **Soundness**: Summaries are over-approximate. A `mallocgc` summary
//!   returns a valid pointer to fresh memory — the engine doesn't know about
//!   GC headers, size-class pools, or mcache freelists, so any downstream
//!   read of those internal fields gets a concrete zero (safe default).
//!
//! - **Enabling condition**: Summaries fire only for functions in the
//!   `SUMMARY_TABLE`. The engine falls back to normal execution for anything
//!   not listed. A `ZORYA_DISABLE_SUMMARIES=1` env var disables the system.
//!
//! - **Interaction with plugins**: Plugin dispatch still fires `Event::Call`
//!   for the summarised function, so Volos and other detectors still see the
//!   call. The memory effects of the summary (zeroing the allocated region)
//!   go through the engine's memory layer but are tagged `AccessOrigin::Engine`
//!   so they don't reach plugins as spurious `MemWrite` events.

pub mod apply;
pub mod table;

pub use apply::{apply, clear_error_registers, ApplyOutcome};
pub use table::{FunctionSummary, SummaryEffect, SummaryTable, RUNTIME_SUMMARIES};
