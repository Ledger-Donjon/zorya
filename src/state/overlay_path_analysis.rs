// SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

/// Overlay path analysis module for exploring untaken paths
/// This performs full concolic execution on unexplored paths using copy-on-write state
use crate::executor::ConcolicExecutor;
use crate::state::overlay_state::OverlayState;
use parser::parser::{Inst, Opcode};
use std::collections::BTreeMap;
use std::io::Write;

const MAX_OVERLAY_DEPTH: usize = 15; // Maximum instructions to analyze in overlay mode

macro_rules! log {
    ($logger:expr, $($arg:tt)*) => {{
        writeln!($logger, $($arg)*).unwrap();
    }};
}

/// Result of overlay path analysis
#[derive(Debug, Clone)]
pub enum OverlayPathAnalysisResult {
    /// Vulnerability found: (type, address, description)
    VulnerabilityFound(String, u64, String),
    /// No vulnerability found within depth limit
    Safe,
    /// Execution error (not a vulnerability)
    Error(String),
    /// Reached depth limit without finding anything
    DepthLimitReached,
}

/// Analyze an untaken path using overlay mechanism
/// This creates an overlay state and executes instructions without modifying the base state
pub fn analyze_untaken_path_with_overlay<'ctx>(
    executor: &mut ConcolicExecutor<'ctx>,
    untaken_address: u64,
    instructions_map: &BTreeMap<u64, Vec<Inst>>,
    max_depth: usize,
) -> OverlayPathAnalysisResult {
    log!(
        executor.state.logger,
        "\n╔══════════════════════════════════════════════════════════════════════╗"
    );
    log!(
        executor.state.logger,
        "║  OVERLAY MODE: Exploring UNTAKEN path (speculative execution)        ║"
    );
    log!(
        executor.state.logger,
        "║  Starting address: 0x{:x}  |  Max depth: {} instructions           ║",
        untaken_address,
        max_depth
    );
    log!(
        executor.state.logger,
        "╚══════════════════════════════════════════════════════════════════════╝"
    );

    // Get RIP register offset
    let rip_offset = match executor.state.cpu_state.lock() {
        Ok(cpu) => match cpu.resolve_offset_from_register_name("RIP") {
            Some(offset) => offset,
            None => {
                log!(
                    executor.state.logger,
                    ">>> ERROR: Could not resolve RIP register offset"
                );
                return OverlayPathAnalysisResult::Error(
                    "Could not resolve RIP register offset".to_string(),
                );
            }
        },
        Err(e) => {
            log!(
                executor.state.logger,
                ">>> ERROR: Failed to lock CPU state: {}",
                e
            );
            return OverlayPathAnalysisResult::Error(format!("Failed to lock CPU state: {}", e));
        }
    };

    // Save unique variables and current address before entering overlay mode
    // These are temporary computation results that must be preserved across overlay exploration
    let saved_unique_variables = executor.unique_variables.clone();
    let saved_current_address = executor.current_address;

    // Save call stack state before overlay (for dangling pointer detection cleanup)
    let saved_call_stack_depth = executor.state.call_stack.len();
    let saved_freed_frames_count = executor.state.freed_stack_frames.len();

    log!(
        executor.state.logger,
        "[OVERLAY] Saved {} unique variables before overlay exploration",
        saved_unique_variables.len()
    );
    log!(
        executor.state.logger,
        "[OVERLAY] Saved current_address before overlay: {:?}",
        saved_current_address
    );
    log!(
        executor.state.logger,
        "[OVERLAY] Saved call stack state: depth={}, freed_frames={}",
        saved_call_stack_depth,
        saved_freed_frames_count
    );

    // Create overlay state
    let overlay_state = match executor.state.cpu_state.lock() {
        Ok(cpu) => match OverlayState::new(&*cpu, rip_offset, untaken_address, executor.context) {
            Ok(state) => state,
            Err(e) => {
                log!(
                    executor.state.logger,
                    ">>> ERROR: Failed to create overlay state: {}",
                    e
                );
                return OverlayPathAnalysisResult::Error(format!(
                    "Failed to create overlay state: {}",
                    e
                ));
            }
        },
        Err(e) => {
            log!(
                executor.state.logger,
                ">>> ERROR: Failed to lock CPU state: {}",
                e
            );
            return OverlayPathAnalysisResult::Error(format!("Failed to lock CPU state: {}", e));
        }
    };

    // Set overlay state in executor
    executor.overlay_state = Some(overlay_state);

    // Reset per-variable NULL check cache so the solver is invoked fresh in this overlay
    executor.null_check_cache.clear();

    // Execute instructions using the existing executor infrastructure
    let result = execute_with_overlay(
        executor,
        untaken_address,
        instructions_map,
        max_depth.min(MAX_OVERLAY_DEPTH),
    );

    // Collect metrics before clearing overlay state
    if executor.overlay_state.is_some() {
        log_overlay_metrics(executor);
    }

    // Clear overlay state
    executor.overlay_state = None;

    // Restore call stack state - remove any frames pushed/freed during overlay
    // This prevents speculative execution from polluting dangling pointer detection
    executor.state.call_stack.truncate(saved_call_stack_depth);
    executor
        .state
        .freed_stack_frames
        .truncate(saved_freed_frames_count);
    log!(
        executor.state.logger,
        "[OVERLAY] Restored call stack state: depth={}, freed_frames={}",
        executor.state.call_stack.len(),
        executor.state.freed_stack_frames.len()
    );

    // Restore unique variables and current address after overlay exploration
    // This prevents overlay execution from polluting the real execution state
    executor.unique_variables = saved_unique_variables;
    executor.current_address = saved_current_address;
    log!(
        executor.state.logger,
        "[OVERLAY] Restored {} unique variables after overlay exploration",
        executor.unique_variables.len()
    );
    log!(
        executor.state.logger,
        "[OVERLAY] Restored current_address after overlay: {:?}",
        executor.current_address
    );

    // Verify RIP was not corrupted after clearing overlay
    let rip_after_overlay = match executor.state.cpu_state.lock() {
        Ok(cpu) => match cpu.get_register_by_offset(0x288, 64) {
            Some(rip_val) => {
                let rip = rip_val.get_concrete_value().unwrap();
                log!(
                    executor.state.logger,
                    "[OVERLAY] RIP after clearing overlay: 0x{:x}",
                    rip
                );
                rip
            }
            None => {
                log!(
                    executor.state.logger,
                    "[OVERLAY] ERROR: Could not read RIP after overlay (None)"
                );
                0
            }
        },
        Err(e) => {
            log!(
                executor.state.logger,
                "[OVERLAY] ERROR: Could not lock CPU state after overlay: {}",
                e
            );
            0
        }
    };

    log!(
        executor.state.logger,
        "╔══════════════════════════════════════════════════════════════════════╗"
    );
    log!(
        executor.state.logger,
        "║  OVERLAY MODE ENDED - Returning to real execution path               ║"
    );
    log!(
        executor.state.logger,
        "║  RIP value after overlay: 0x{:x}                                   ║",
        rip_after_overlay
    );
    log!(
        executor.state.logger,
        "╚══════════════════════════════════════════════════════════════════════╝\n"
    );

    result
}

/// Execute instructions using the overlay state
/// Uses the existing executor logic, which now checks for overlay mode
fn execute_with_overlay<'ctx>(
    executor: &mut ConcolicExecutor<'ctx>,
    start_address: u64,
    instructions_map: &BTreeMap<u64, Vec<Inst>>,
    max_depth: usize,
) -> OverlayPathAnalysisResult {
    let mut current_addr = start_address;
    let mut visited = std::collections::HashSet::new();
    let mut instruction_count = 0;

    log!(
        executor.state.logger,
        "[OVERLAY] Speculative execution starting at 0x{:x}",
        current_addr
    );

    while instruction_count < max_depth {
        // Check for loops
        if visited.contains(&current_addr) {
            log!(
                executor.state.logger,
                "[OVERLAY] Loop detected at 0x{:x}, stopping speculative execution",
                current_addr
            );
            return OverlayPathAnalysisResult::DepthLimitReached;
        }
        visited.insert(current_addr);

        // Get instructions at current address
        let instructions = match instructions_map.get(&current_addr) {
            Some(insts) => insts,
            None => {
                log!(
                    executor.state.logger,
                    "[OVERLAY]  No instructions at 0x{:x}, stopping speculative execution",
                    current_addr
                );
                return OverlayPathAnalysisResult::DepthLimitReached;
            }
        };

        // Get next address for fallthrough
        let next_addr = instructions_map
            .range((current_addr + 1)..)
            .next()
            .map(|(addr, _)| *addr)
            .unwrap_or(current_addr);

        // Track if we explicitly changed control flow (to skip fallthrough update)
        let mut explicit_control_flow = false;

        // Execute each instruction using the existing executor
        for (idx, inst) in instructions.iter().enumerate() {
            instruction_count += 1;

            log!(
                executor.state.logger,
                "[OVERLAY] [depth {}] 0x{:x}:{} {:?}",
                instruction_count,
                current_addr,
                idx,
                inst.opcode
            );

            // Check for vulnerability patterns BEFORE execution
            // This catches null pointer dereferences before they cause errors
            if let Some(vuln_result) = check_instruction_for_vulnerabilities_before_execution(
                inst,
                executor,
                current_addr,
                idx,
            ) {
                return vuln_result;
            }

            // Execute instruction using existing executor infrastructure
            // The executor will automatically use overlay mode for reads/writes
            // CALLOTHER operations are executed normally - overlay handles memory correctly
            match executor.execute_instruction(
                inst.clone(),
                current_addr,
                next_addr,
                instructions_map,
            ) {
                Ok(()) => {
                    // Check if this was a control flow instruction
                    match inst.opcode {
                        Opcode::Branch => {
                            // Extract target address from instruction
                            if let Some(target_varnode) = inst.inputs.get(0) {
                                if let parser::parser::Var::Memory(target) = target_varnode.var {
                                    log!(
                                        executor.state.logger,
                                        "[OVERLAY] Following branch to 0x{:x}",
                                        target
                                    );
                                    current_addr = target;
                                    explicit_control_flow = true;
                                    break; // Exit instruction loop, continue with new address
                                }
                            }
                            log!(
                                executor.state.logger,
                                "[OVERLAY] Cannot determine branch target, stopping the overlay execution"
                            );
                            return OverlayPathAnalysisResult::DepthLimitReached;
                        }
                        Opcode::Return => {
                            log!(
                                executor.state.logger,
                                "[OVERLAY] Reached return at 0x{:x}, ending the overlay execution",
                                current_addr
                            );
                            return OverlayPathAnalysisResult::Safe;
                        }
                        Opcode::CBranch => {
                            // For simplicity, don't follow conditional branches in overlay
                            // Continue with fallthrough
                            log!(
                                executor.state.logger,
                                "[OVERLAY] Ignoring CBranch, continuing with fallthrough"
                            );
                        }
                        _ => {
                            // Normal instruction, continue
                        }
                    }
                }
                Err(e) => {
                    // Execution error during overlay analysis.
                    // Specific vulnerability checks (NULL ptr, div-by-zero) happen before
                    // execution in check_vulnerabilities_before_execution, so errors here
                    // are typically non-vulnerability issues (unimplemented opcodes, etc.)
                    log!(
                        executor.state.logger,
                        "[OVERLAY] Execution error at 0x{:x}: {}",
                        current_addr,
                        e
                    );
                    return OverlayPathAnalysisResult::Error(e);
                }
            }

            if instruction_count >= max_depth {
                log!(
                    executor.state.logger,
                    "[OVERLAY] Reached max depth at 0x{:x}, stopping speculative execution",
                    current_addr
                );
                return OverlayPathAnalysisResult::DepthLimitReached;
            }
        }

        // Move to next instruction block (fallthrough) unless we explicitly jumped
        if !explicit_control_flow {
            current_addr = next_addr;
        }
    }

    OverlayPathAnalysisResult::DepthLimitReached
}

/// Check instruction for vulnerability patterns BEFORE execution
/// This allows us to detect issues like null pointer dereferences before they cause errors
fn check_instruction_for_vulnerabilities_before_execution<'ctx>(
    inst: &Inst,
    executor: &mut ConcolicExecutor<'ctx>,
    current_addr: u64,
    inst_idx: usize,
) -> Option<OverlayPathAnalysisResult> {
    // Check for LOAD with potentially null pointer
    if inst.opcode == Opcode::Load {
        if let Some(pointer_varnode) = inst.inputs.get(1) {
            if let Ok(pointer_concolic) = executor.varnode_to_concolic(pointer_varnode) {
                let pointer_value = pointer_concolic.get_concrete_value();
                if pointer_value == 0 {
                    // Concrete NULL detected during overlay execution.
                    // Call evaluate_args_z3 to:
                    // 1. Confirm it's SAT with Z3
                    // 2. Generate FOUND_SAT_STATE.txt
                    // 3. Get consistent vulnerability reporting
                    let pointer_bv = pointer_concolic.get_symbolic_value_bv(executor.context);

                    match crate::state::evaluate_z3::evaluate_args_z3(
                        executor,
                        inst,
                        None,               // no conditional flag
                        Some(current_addr), // instruction address
                        None,               // no branch target
                        Some(current_addr), // use current address as "panic address"
                        Some(&pointer_bv),  // NULL check on this pointer
                    ) {
                        Ok(true) => {
                            // SAT confirmed - vulnerability already reported by evaluate_args_z3
                            return Some(OverlayPathAnalysisResult::VulnerabilityFound(
                                "NULL_DEREF_LOAD".to_string(),
                                current_addr,
                                format!(
                                    "Null pointer dereference (LOAD) at instruction {}",
                                    inst_idx
                                ),
                            ));
                        }
                        Ok(false) => {
                            // UNSAT - not a real vulnerability (shouldn't happen for concrete NULL)
                        }
                        Err(e) => {
                            log!(
                                executor.state.logger,
                                "[OVERLAY] Error during NULL check evaluation: {}",
                                e
                            );
                        }
                    }
                }
            }
        }
    }

    // Check for STORE with potentially null pointer
    if inst.opcode == Opcode::Store {
        if let Some(pointer_varnode) = inst.inputs.get(1) {
            if let Ok(pointer_concolic) = executor.varnode_to_concolic(pointer_varnode) {
                let pointer_value = pointer_concolic.get_concrete_value();
                if pointer_value == 0 {
                    // Concrete NULL detected during overlay execution.
                    // Call evaluate_args_z3 to generate SAT state file and get unified reporting
                    let pointer_bv = pointer_concolic.get_symbolic_value_bv(executor.context);

                    match crate::state::evaluate_z3::evaluate_args_z3(
                        executor,
                        inst,
                        None,               // no conditional flag
                        Some(current_addr), // instruction address
                        None,               // no branch target
                        Some(current_addr), // use current address as "panic address"
                        Some(&pointer_bv),  // NULL check on this pointer
                    ) {
                        Ok(true) => {
                            // SAT confirmed - vulnerability already reported by evaluate_args_z3
                            return Some(OverlayPathAnalysisResult::VulnerabilityFound(
                                "NULL_DEREF_STORE".to_string(),
                                current_addr,
                                format!("Null pointer write (STORE) at instruction {}", inst_idx),
                            ));
                        }
                        Ok(false) => {
                            // UNSAT - not a real vulnerability (shouldn't happen for concrete NULL)
                        }
                        Err(e) => {
                            log!(
                                executor.state.logger,
                                "[OVERLAY] Error during NULL check evaluation: {}",
                                e
                            );
                        }
                    }
                }
            }
        }
    }

    // Check for division by zero
    if matches!(
        inst.opcode,
        Opcode::IntDiv | Opcode::IntRem | Opcode::IntSDiv | Opcode::IntSRem
    ) {
        if let Some(divisor_varnode) = inst.inputs.get(1) {
            if let Ok(divisor_concolic) = executor.varnode_to_concolic(divisor_varnode) {
                let divisor_value = divisor_concolic.get_concrete_value();
                if divisor_value == 0 {
                    let vuln_desc = format!("Division by zero at instruction {}", inst_idx);
                    crate::state::evaluate_z3::report_vulnerability(
                        &mut executor.state.logger.clone(),
                        "Division by zero (overlay execution)",
                        current_addr,
                        &[
                            "Opcode: INT_DIV / INT_REM",
                            "Detection method: Exploring the not taken path with Overlay Execution",
                            &vuln_desc,
                        ],
                    );
                    return Some(OverlayPathAnalysisResult::VulnerabilityFound(
                        "DIV_BY_ZERO".to_string(),
                        current_addr,
                        vuln_desc,
                    ));
                }
            }
        }
    }

    None
}

/// Log overlay execution metrics
fn log_overlay_metrics<'ctx>(executor: &mut ConcolicExecutor<'ctx>) {
    // Get overlay or return early
    let overlay = match executor.overlay_state.as_ref() {
        Some(o) => o,
        None => return,
    };

    log!(
        executor.state.logger,
        "\n╔══════════════════════════════════════════════════════════════════════╗"
    );
    log!(
        executor.state.logger,
        "║  OVERLAY EXECUTION METRICS                                           ║"
    );
    log!(
        executor.state.logger,
        "╚══════════════════════════════════════════════════════════════════════╝"
    );

    // Register modifications
    let modified_regs = overlay.get_modified_registers();
    log!(
        executor.state.logger,
        "[OVERLAY METRICS] Modified registers: {}",
        modified_regs.len()
    );

    if !modified_regs.is_empty() {
        log!(executor.state.logger, "[OVERLAY METRICS] Register changes:");
        for (_offset, reg_info) in &modified_regs {
            log!(executor.state.logger, "  - {}", reg_info);
        }
    }

    // Memory modifications
    let modified_memory = overlay.get_modified_memory_regions();
    log!(
        executor.state.logger,
        "[OVERLAY METRICS] Modified memory regions: {}",
        modified_memory.len()
    );

    if !modified_memory.is_empty() {
        log!(executor.state.logger, "[OVERLAY METRICS] Memory changes:");
        for (region_start, region_end, modified_addrs) in &modified_memory {
            log!(
                executor.state.logger,
                "  - Region [0x{:x} - 0x{:x}]:",
                region_start,
                region_end
            );
            if !modified_addrs.is_empty() {
                log!(
                    executor.state.logger,
                    "    Specific addresses modified: {}",
                    modified_addrs.len()
                );
                // Log first few addresses to avoid spam
                for addr in modified_addrs.iter().take(10) {
                    log!(executor.state.logger, "      * 0x{:x}", addr);
                }
                if modified_addrs.len() > 10 {
                    log!(
                        executor.state.logger,
                        "      ... and {} more",
                        modified_addrs.len() - 10
                    );
                }
            }
        }
    }

    log!(
        executor.state.logger,
        "[OVERLAY METRICS] Exploration depth reached: {}",
        overlay.get_depth()
    );

    log!(
        executor.state.logger,
        "╚══════════════════════════════════════════════════════════════════════╝\n"
    );
}
