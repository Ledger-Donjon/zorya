// SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

/// Overlay path analysis module for exploring untaken paths
/// This performs full concolic execution on unexplored paths using copy-on-write state
use crate::executor::ConcolicExecutor;
use crate::state::overlay_state::OverlayState;
use crate::summaries::SummaryTable;
use parser::parser::{Inst, Opcode};
use std::collections::BTreeMap;
use std::io::Write;
use z3::ast::Bool;

pub const DEFAULT_MAX_OVERLAY_DEPTH: usize = 30;

pub const PLUGIN_MAX_OVERLAY_DEPTH: usize = 500;

/// Go runtime syscall-scheduler bookkeeping functions that the overlay must
/// NOT step into. They manipulate the goroutine (`g`) / machine (`m`) scheduler
/// structures — reading fields like `g.m`, `g.sched`, `m.p` — which live in
/// runtime memory that is only partially reflected in the overlay concolic
/// execution shadow. Executing them in overlay concolic execution yields
/// `ReadOutOfBounds` (e.g. a read
/// at offset 0x30 off a null base) or steps into `runtime.abort` (INT3/SWI),
/// terminating the overlay before it reaches the syscalls we care about.
fn is_overlay_skippable_runtime_fn(name: &str) -> bool {
    matches!(
        name,
        "runtime.entersyscall"
            | "runtime.exitsyscall"
            | "runtime.reentersyscall"
            | "runtime.entersyscallblock"
            | "runtime.exitsyscallfast"
            | "runtime.exitsyscall0"
            | "runtime.save"
            | "runtime.casgstatus"
            | "runtime.getcallerfp"
            | "runtime.getfp"
    )
}

macro_rules! log {
    ($logger:expr, $($arg:tt)*) => {{
        if ($logger).is_enabled() {
        writeln!($logger, $($arg)*).unwrap();
        }
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
    explored_gate: Option<Bool<'ctx>>,
) -> OverlayPathAnalysisResult {
    log!(
        executor.state.logger,
        "\n╔══════════════════════════════════════════════════════════════════════╗"
    );
    log!(
        executor.state.logger,
        "║  OVERLAY MODE: Exploring UNTAKEN path (overlay concolic execution)        ║"
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
    let saved_constraint_vector = executor.constraint_vector.clone();

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
        Ok(cpu) => match OverlayState::new(&cpu, rip_offset, untaken_address, executor.context) {
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

    // Save the NULL check cache so we can restore it after overlay exploration.
    // The overlay runs on a overlay concolic execution path — its SAT/UNSAT results must not
    // pollute the real execution's cache, and the real execution's cached
    // results must survive overlay round-trips.
    let saved_null_check_cache = executor.null_check_cache.clone();

    // Keep SAT entries (permanently confirmed nullable — vulnerability already
    // reported, never re-report) but clear UNSAT entries (they were established
    // under the real path's constraints; the overlay negates a branch, so an
    // UNSAT variable might become SAT and must be re-checked).
    executor.null_check_cache.retain(|_, &mut (sat, _)| sat);

    // Overlay-entry path condition φ: the main path condition accumulated up
    // to this branch, conjoined with the gate that selects the untaken
    // (vulnerable) branch. This is the *clean* predicate describing the input
    // class that reaches the branch. It must NOT be mixed with the branch
    // constraints the overlay accumulates afterwards: the overlay keeps the
    // original concrete input, so those later constraints are derived from that
    // concrete value and would contradict the gate (making φ trivially UNSAT).
    // We hand this clean φ to plugins at overlay end so they can Z3-solve the
    // triggering input for anything they observed on this path.
    let overlay_entry_phi: Vec<Bool<'ctx>> = {
        let mut v = saved_constraint_vector.clone();
        if let Some(gate) = &explored_gate {
            v.push(gate.clone());
        }
        v
    };

    // Overlay execution explores the untaken branch. Attach that gate so events
    // emitted from overlay concolic execution instructions carry the correct path predicate.
    if let Some(gate) = explored_gate {
        executor.constraint_vector.push(gate);
    }

    // Execute instructions using the existing executor infrastructure
    let result = execute_with_overlay(executor, untaken_address, instructions_map, max_depth);

    // Before tearing down the overlay, give plugins a chance to reason about
    // what they observed on this untaken path. We pass the clean overlay-entry
    // φ (main path ∧ gate) so a detector like TOCTOU can Z3-solve the concrete
    // inputs that drive a check it recorded here and remember them for
    // reporting once we are back on the real path.
    executor.dispatch_overlay_end(&overlay_entry_phi);

    // Collect metrics before clearing overlay state
    if executor.overlay_state.is_some() {
        log_overlay_metrics(executor);
    }

    // Clear overlay state
    executor.overlay_state = None;

    // Restore call stack state - remove any frames pushed/freed during overlay
    // This prevents overlay concolic execution from polluting dangling pointer detection
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

    // Restore unique variables, current address, and NULL check cache after overlay exploration
    // This prevents overlay execution from polluting the real execution state
    executor.unique_variables = saved_unique_variables;
    executor.current_address = saved_current_address;
    executor.null_check_cache = saved_null_check_cache;
    executor.constraint_vector = saved_constraint_vector;
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
    let mut overlay_call_stack: Vec<u64> = Vec::new();

    // Function summaries must be applied during overlay concolic execution too.
    // Without this, the overlay steps into the full pcode body of runtime
    // helpers like `runtime.newobject` → `mallocgc`, which wander through the
    // Go allocator/scheduler and eventually hit `runtime.abort` (INT3/SWI),
    // killing the overlay concolic execution path before it reaches the interesting syscalls
    // (e.g. the getsockopt/readlink TOCTOU check→use pair). The summary heap
    // uses a distinct base from the main loop's so the two never collide.
    let overlay_summary_table = SummaryTable::new();
    let mut overlay_summary_heap_ptr: u64 = 0x7000_8000_0000;

    log!(
        executor.state.logger,
        "[OVERLAY] Overlay concolic execution starting at 0x{:x}",
        current_addr
    );

    while instruction_count < max_depth {
        // Check for loops (keyed on address + call depth to allow recursive calls)
        let visit_key = (current_addr, overlay_call_stack.len());
        if visited.contains(&visit_key) {
            log!(
                executor.state.logger,
                "[OVERLAY] Loop detected at 0x{:x} (call depth {}), stopping overlay concolic execution",
                current_addr,
                overlay_call_stack.len()
            );
            return OverlayPathAnalysisResult::DepthLimitReached;
        }
        visited.insert(visit_key);

        // Count overlay-explored blocks in the global coverage metric.
        // visited_blocks is NOT restored after overlay cleanup, so these
        // blocks remain counted, which is correct: Zorya analysed them.
        executor.visited_blocks.insert(current_addr);

        // Get instructions at current address
        let instructions = match instructions_map.get(&current_addr) {
            Some(insts) => insts,
            None => {
                // Address not in the instruction map (external library, etc.)
                // If we're inside a call, treat as returning from it
                if let Some(return_addr) = overlay_call_stack.pop() {
                    log!(
                        executor.state.logger,
                        "[OVERLAY] No instructions at 0x{:x}, returning to caller 0x{:x}",
                        current_addr,
                        return_addr
                    );
                    current_addr = return_addr;
                    continue;
                }
                log!(
                    executor.state.logger,
                    "[OVERLAY] No instructions at 0x{:x}, stopping overlay concolic execution",
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

            // Intercept runtime calls BEFORE executing them. Two cases:
            //
            //  1. Summarizable runtime calls (runtime.newobject, mallocgc,
            //     slicebytetostring, gcWriteBarrier, …). The main loop applies
            //     these summaries; the overlay must do the same or it steps into
            //     the allocator and hits runtime.abort (SWI), aborting the
            //     overlay concolic execution path before the check→use syscalls are reached.
            //
            //  2. Go syscall-scheduler bookkeeping (runtime.entersyscall,
            //     exitsyscall, reentersyscall, save, …). These manipulate the
            //     goroutine/M scheduler structures and read fields such as
            //     g.m off unmapped shadow memory, producing spurious
            //     ReadOutOfBounds errors that kill the overlay concolic execution path. They
            //     carry NO data flow relevant to TOCTOU/chancheck detection, so
            //     the overlay skips them entirely and flows straight through
            //     Syscall6 → RawSyscall6 → linux.Syscall6 → the real SYSCALL,
            //     where Event::Syscall is dispatched to the plugins.
            if inst.opcode == Opcode::Call {
                if let Some(target_varnode) = inst.inputs.first() {
                    if let parser::parser::Var::Memory(target) = target_varnode.var {
                        let sym = executor.symbol_table.get(&format!("{:x}", target)).cloned();
                        if let Some(sym_name) = sym {
                            if is_overlay_skippable_runtime_fn(&sym_name) {
                                // The x86 `call` is lowered to several p-code ops;
                                // the return-address push (RSP -= 8) has ALREADY
                                // executed by the time we reach the `Call` op here.
                                // Skipping the callee also skips its `ret` (which
                                // would pop, RSP += 8), so we must undo the push
                                // ourselves to keep RSP balanced — otherwise every
                                // subsequent [rsp+disp] access in the caller is
                                // shifted by 8 bytes (reading the wrong stack slot,
                                // e.g. the saved syscall number turns into a stale
                                // return address, yielding a garbage syscall nr).
                                if let Some(rsp) = executor.get_register_overlay_aware(0x20, 64) {
                                    if let Ok(rsp_val) = rsp.get_concrete_value() {
                                        let new_rsp = rsp_val.wrapping_add(8);
                                        let _ = executor.set_register_overlay_aware(
                                            0x20,
                                            crate::concolic::ConcolicVar::new_concrete_and_symbolic_int(
                                                new_rsp,
                                                z3::ast::BV::from_u64(
                                                    executor.context,
                                                    new_rsp,
                                                    64,
                                                ),
                                                executor.context,
                                            ),
                                            64,
                                        );
                                    }
                                }
                                log!(
                                    executor.state.logger,
                                    "[OVERLAY] Skipping scheduler bookkeeping fn {} at 0x{:x} (no-op, RSP rebalanced +8, avoids unmapped scheduler-state reads)",
                                    sym_name,
                                    target
                                );
                                current_addr = next_addr;
                                explicit_control_flow = true;
                                break;
                            }
                            if let Some(effect) = overlay_summary_table.lookup(&sym_name) {
                                let effect = effect.clone();
                                log!(
                                    executor.state.logger,
                                    "[OVERLAY] Applying summary for {} at call target 0x{:x} (skipping body)",
                                    sym_name,
                                    target
                                );
                                let _ = crate::summaries::apply(
                                    &effect,
                                    executor.context,
                                    &executor.state.cpu_state,
                                    &executor.state.memory,
                                    &mut overlay_summary_heap_ptr,
                                );
                                crate::summaries::clear_error_registers(
                                    &effect,
                                    executor.context,
                                    &executor.state.cpu_state,
                                );
                                // Simulate the function return: continue at the
                                // fallthrough block (the post-call return point).
                                current_addr = next_addr;
                                explicit_control_flow = true;
                                break;
                            }
                        }
                    }
                }
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
                            if let Some(target_varnode) = inst.inputs.first() {
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
                        Opcode::Call => {
                            // Follow function calls: extract target and enter the callee
                            if let Some(target_varnode) = inst.inputs.first() {
                                if let parser::parser::Var::Memory(target) = target_varnode.var {
                                    // Only follow if the target is in the instruction map
                                    if instructions_map.contains_key(&target) {
                                        // Push return address (next block after current)
                                        overlay_call_stack.push(next_addr);
                                        log!(
                                            executor.state.logger,
                                            "[OVERLAY] Entering function call to 0x{:x} (return to 0x{:x}, stack depth {})",
                                            target,
                                            next_addr,
                                            overlay_call_stack.len()
                                        );
                                        current_addr = target;
                                        explicit_control_flow = true;
                                        break;
                                    } else {
                                        log!(
                                            executor.state.logger,
                                            "[OVERLAY] Call target 0x{:x} not in instruction map, skipping",
                                            target
                                        );
                                    }
                                }
                            }
                        }
                        Opcode::Return => {
                            if let Some(return_addr) = overlay_call_stack.pop() {
                                log!(
                                    executor.state.logger,
                                    "[OVERLAY] Returning from function to 0x{:x} (stack depth {})",
                                    return_addr,
                                    overlay_call_stack.len()
                                );
                                current_addr = return_addr;
                                explicit_control_flow = true;
                                break;
                            } else {
                                log!(
                                    executor.state.logger,
                                    "[OVERLAY] Reached return at top level (0x{:x}), ending overlay",
                                    current_addr
                                );
                                return OverlayPathAnalysisResult::Safe;
                            }
                        }
                        Opcode::CBranch => {
                            // Evaluate the branch condition concretely and follow
                            // the correct edge. Blindly taking the fallthrough (the
                            // old behaviour) walks the overlay into Go runtime
                            // error/abort paths — e.g. reentersyscall's scheduler
                            // checks fall through to runtime.abort (INT3/SWI),
                            // killing the overlay concolic execution path before it reaches the
                            // syscalls we care about. The concrete state is valid
                            // here, so we can decide the branch exactly as the main
                            // executor would.
                            let cond_taken = inst
                                .inputs
                                .get(1)
                                .and_then(|vn| executor.varnode_to_concolic(vn).ok())
                                .and_then(|c| c.to_concolic_var())
                                .map(|cv| cv.concrete.to_u64() != 0)
                                .unwrap_or(false);

                            if cond_taken {
                                if let Some(target_varnode) = inst.inputs.first() {
                                    if let parser::parser::Var::Memory(target) = target_varnode.var
                                    {
                                        log!(
                                            executor.state.logger,
                                            "[OVERLAY] CBranch taken to 0x{:x}",
                                            target
                                        );
                                        current_addr = target;
                                        explicit_control_flow = true;
                                        break;
                                    }
                                }
                                // Pcode-relative (intra-instruction) branch target:
                                // keep the safe fallthrough behaviour.
                                log!(
                                    executor.state.logger,
                                    "[OVERLAY] CBranch taken but non-memory target; continuing fallthrough"
                                );
                            } else {
                                log!(
                                    executor.state.logger,
                                    "[OVERLAY] CBranch not taken, continuing with fallthrough"
                                );
                            }
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
                    "[OVERLAY] Reached max depth at 0x{:x}, stopping overlay concolic execution",
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
                    // No Z3 evaluation needed — the pointer is concretely NULL on this path.

                    // Try to identify the pointer name by checking if it's symbolic
                    let ptr_bv = pointer_concolic.to_bv(executor.context);
                    let mut pointer_name = None;

                    // Try to match it against tracked symbolic variables
                    for (arg_name, sym_var) in &executor.function_symbolic_arguments {
                        if let crate::concolic::SymbolicVar::Int(bv) = sym_var {
                            if ptr_bv.to_string() == bv.to_string() {
                                pointer_name = Some(arg_name.clone());
                                break;
                            }
                        }
                    }

                    let desc = format!(
                        "Null pointer dereference (LOAD) at instruction {}",
                        inst_idx
                    );
                    if let Err(e) = crate::state::evaluate_z3::log_vuln_to_file_and_terminal(
                        &mut executor.state.logger.clone(),
                        "NULL pointer dereference",
                        current_addr,
                        "LOAD",
                        &desc,
                        pointer_name.as_deref(),
                    ) {
                        log!(executor.state.logger, "[OVERLAY] Error logging bug: {}", e);
                    }
                    return Some(OverlayPathAnalysisResult::VulnerabilityFound(
                        "NULL_DEREF_LOAD".to_string(),
                        current_addr,
                        desc,
                    ));
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
                    // No Z3 evaluation needed — the pointer is concretely NULL on this path.

                    // Try to identify the pointer name by checking if it's symbolic
                    let ptr_bv = pointer_concolic.to_bv(executor.context);
                    let mut pointer_name = None;

                    // Try to match it against tracked symbolic variables
                    for (arg_name, sym_var) in &executor.function_symbolic_arguments {
                        if let crate::concolic::SymbolicVar::Int(bv) = sym_var {
                            if ptr_bv.to_string() == bv.to_string() {
                                pointer_name = Some(arg_name.clone());
                                break;
                            }
                        }
                    }

                    let desc = format!("Null pointer write (STORE) at instruction {}", inst_idx);
                    if let Err(e) = crate::state::evaluate_z3::log_vuln_to_file_and_terminal(
                        &mut executor.state.logger.clone(),
                        "NULL pointer dereference",
                        current_addr,
                        "STORE",
                        &desc,
                        pointer_name.as_deref(),
                    ) {
                        log!(executor.state.logger, "[OVERLAY] Error logging bug: {}", e);
                    }
                    return Some(OverlayPathAnalysisResult::VulnerabilityFound(
                        "NULL_DEREF_STORE".to_string(),
                        current_addr,
                        desc,
                    ));
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
