// SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

pub mod cpu_state;
pub mod evaluate_z3;
pub mod explore_ast;
pub mod function_signatures;
mod futex_manager;
pub mod gating_stats;
pub mod memory_x86_64;
pub mod overlay_path_analysis;
pub mod overlay_state;
pub mod panic_reach;
pub mod runtime_info;
pub mod simplify_z3;
pub mod state_manager;
pub mod thread_loader;
pub mod thread_manager;
pub mod virtual_file_system;

pub use cpu_state::CpuState;
pub use evaluate_z3::evaluate_args_z3;
pub use function_signatures::FunctionSignature;
pub use memory_x86_64::MemoryX86_64;
pub use overlay_path_analysis::{
    analyze_untaken_path_with_overlay, OverlayPathAnalysisResult, DEFAULT_MAX_OVERLAY_DEPTH,
    PLUGIN_MAX_OVERLAY_DEPTH,
};
pub use overlay_state::{CpuStateOverlay, MemoryRegionOverlay, OverlayState};
pub use runtime_info::{RuntimeGOffsets, RuntimeInfo};
pub use state_manager::State;
pub use thread_loader::load_threads_from_dumps;
pub use thread_manager::{CheckpointType, OSThread, SchedulingPolicy, ThreadManager, ThreadStatus};
pub use virtual_file_system::VirtualFileSystem;
