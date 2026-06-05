// SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

use core::panic;
use std::collections::{BTreeMap, HashMap};
use std::env;
use std::error::Error;
use std::fs::{self, File};
use std::io::{self, BufRead, Write};
use std::path::Path;
use std::process::Command;
use std::rc::Rc;

use parser::parser::{Inst, Opcode, Var};
use z3::{
    ast::{Ast, BV},
    Config, Context,
};
use zorya::concolic::symbolic_initialization::{
    clear_go_stack_preempt, init_struct_types_cache, initialize_interface_argument,
    initialize_single_register_argument, initialize_single_register_slice,
    initialize_slice_argument, initialize_slice_memory_contents, initialize_string_argument,
    initialize_string_memory_contents, initialize_struct_pointer_fields, is_stack_location,
    is_struct_pointer_type, parse_stack_offset,
};
use zorya::concolic::{ConcolicVar, Logger};
use zorya::executor::{ConcolicExecutor, SymbolicVar};
use zorya::state::evaluate_z3::{
    evaluate_args_z3, get_os_args_address, init_invocation_command_line, init_sat_timer_start,
};
use zorya::state::explore_ast::explore_ast_for_panic;
use zorya::state::function_signatures::{
    load_function_args_map, load_go_function_args_map, precompute_function_signatures_via_ghidra,
    GoFunctionArg,
};
use zorya::state::gating_stats::{
    get_allowed_by_xref_fallback, get_gated_by_reach, inc_gated_by_reach,
};
use zorya::state::memory_x86_64::MemoryValue;
use zorya::state::overlay_path_analysis::{
    analyze_untaken_path_with_overlay, OverlayPathAnalysisResult,
};
use zorya::state::panic_reach::precompute_panic_reach;
use zorya::state::simplify_z3::extract_underlying_condition_from_flag_ast;
use zorya::state::thread_manager::CheckpointType;
use zorya::target_info::GLOBAL_TARGET_INFO;
use zorya::{teprintln, tprintln};

macro_rules! log {
    ($logger:expr, $($arg:tt)*) => {{
        if ($logger).is_enabled() {
        writeln!($logger, $($arg)*).unwrap();
        }
    }};
}

/// Functions we want to completely ignore / skip execution in the TinyGo runtime.
const IGNORED_TINYGO_FUNCS: &[&str] = &[
    // "runtime.markRoots",
    // "runtime.alloc",
    // "runtime.markStack",
    // "runtime.runGC",
    // "runtime.markRoot",
    // "runtime.findGlobals",
];

/// End-of-analysis hook for the plugin event bus.
///
/// Runs every plugin's `on_finish`, drains the accumulated findings, and
/// writes them to `results/plugin_findings.txt`. Idempotent: calling it
/// after every termination path of the executor loop is safe; the second
/// call sees an empty `findings` buffer and writes a header-only file.
///
/// We split this out as a helper because `execute_instructions_from`
/// has multiple early-return paths (sys_exit_group termination, hard
/// errors, panic-detected termination). Funnelling all of them through
/// this single call keeps the contract "every analysis run produces a
/// findings report, exactly once" intact.
fn finalize_plugin_analysis(executor: &mut ConcolicExecutor) {
    let pc = executor.current_address.unwrap_or(0);
    let tid = executor
        .state
        .thread_manager
        .lock()
        .map(|tm| tm.current_tid)
        .unwrap_or(0);
    let goid = executor.get_current_goroutine_id().ok();
    let icnt = executor.instruction_counter;
    let st = executor.start_time;
    let z3_ctx = executor.context;

    // 1. on_finish — plugins like volos run their end-of-trace race
    //    check here and push findings into the bus's buffer. The final
    //    path condition is threaded through so detectors that solve for an
    //    input class at end-of-trace can reuse the engine's constraints.
    let path_constraints = &executor.constraint_vector;
    let n = executor
        .event_bus
        .run_finish_with(z3_ctx, pc, tid, goid, icnt, st, path_constraints);
    log!(
        executor.state.logger,
        "[PLUGINS] on_finish complete: {} findings",
        n
    );

    // Memory-access boundary audit. Makes the binary-vs-engine split
    // observable: how many accesses were surfaced to plugins (binary
    // LOAD/STORE pcode ops) vs suppressed as engine-internal bookkeeping.
    log!(
        executor.state.logger,
        "[PLUGINS] mem-access boundary: {} surfaced (binary), {} suppressed (engine)",
        executor.mem_events_surfaced,
        executor.mem_events_suppressed
    );

    // 2. Drain and write to disk. Always create the file — even with zero
    //    findings — so callers (CI, scripts, the user) can reliably check
    //    `results/plugin_findings.txt` after every run without having to
    //    handle a missing file as a special case.
    let findings = executor.event_bus.take_findings();
    let _ = std::fs::create_dir_all("results");
    if let Ok(mut f) = std::fs::File::create("results/plugin_findings.txt") {
        let _ = writeln!(f, "# zorya plugin findings");
        let _ = writeln!(f, "# {} finding(s)", findings.len());
        if findings.is_empty() {
            let _ = writeln!(f, "# No issues found.");
        }
        for finding in &findings {
            let _ = writeln!(
                f,
                "\n[{}::{}] {} (pc=0x{:x}, severity={:?})",
                finding.plugin, finding.rule, finding.title, finding.pc, finding.severity
            );
            for d in &finding.details {
                let _ = writeln!(f, "    {}", d);
            }
        }
        log!(
            executor.state.logger,
            "[PLUGINS] Wrote {} finding(s) to results/plugin_findings.txt",
            findings.len()
        );
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    // Initialize wall-clock timer to measure time until first SAT state
    init_sat_timer_start();
    // Record command line invocation for SAT result file
    init_invocation_command_line();
    // Normalize key CLI flags into environment variables so running without the wrapper works
    // Only set if not already present in the environment.
    {
        let mut args_iter = env::args().peekable();
        while let Some(arg) = args_iter.next() {
            match arg.as_str() {
                "--thread-scheduling" => {
                    if env::var("THREAD_SCHEDULING").is_err() {
                        if let Some(val) = args_iter.peek() {
                            // Don't consume flags as values
                            if !val.starts_with("--") {
                                if let Some(v) = args_iter.next() {
                                    env::set_var("THREAD_SCHEDULING", v);
                                }
                            }
                        }
                    } else {
                        // Skip potential value to keep parsing aligned
                        if let Some(val) = args_iter.peek() {
                            if !val.starts_with("--") {
                                args_iter.next();
                            }
                        }
                    }
                }
                "--lang" => {
                    if env::var("SOURCE_LANG").is_err() {
                        if let Some(val) = args_iter.peek() {
                            if !val.starts_with("--") {
                                if let Some(v) = args_iter.next() {
                                    env::set_var("SOURCE_LANG", v);
                                }
                            }
                        }
                    } else if let Some(val) = args_iter.peek() {
                        if !val.starts_with("--") {
                            args_iter.next();
                        }
                    }
                }
                "--compiler" => {
                    if env::var("COMPILER").is_err() {
                        if let Some(val) = args_iter.peek() {
                            if !val.starts_with("--") {
                                if let Some(v) = args_iter.next() {
                                    env::set_var("COMPILER", v);
                                }
                            }
                        }
                    } else if let Some(val) = args_iter.peek() {
                        if !val.starts_with("--") {
                            args_iter.next();
                        }
                    }
                }
                _ => {
                    // Ignore other args here
                }
            }
        }
    }
    // Normalize scheduler env and set defaults early (before thread manager config).
    // Thread scheduling is supported for Go GC, C, and C++ binaries; TinyGo stays
    // MainOnly because its goroutine scheduler doesn't match the cooperative model.
    {
        let source_lang_norm = env::var("SOURCE_LANG")
            .unwrap_or_else(|_| String::new())
            .to_lowercase();
        let compiler_norm = env::var("COMPILER")
            .unwrap_or_else(|_| String::new())
            .to_lowercase();
        let sched_choice = env::var("THREAD_SCHEDULING")
            .unwrap_or_else(|_| String::new())
            .to_lowercase();

        let scheduling_supported = matches!(source_lang_norm.as_str(), "go" | "c" | "c++")
            && !(source_lang_norm == "go" && compiler_norm == "tinygo");

        if scheduling_supported {
            match sched_choice.as_str() {
                "all-threads" | "all_threads" | "roundrobin" | "round_robin" | "rr" => {
                    env::set_var("THREAD_SCHEDULING", "round_robin");
                    tprintln!(
                        "[THREAD-CONFIG] Enabled multi-thread scheduling (cooperative at function calls)"
                    );

                    if env::var("THREAD_SWITCH_DEPTH").is_err() {
                        env::set_var("THREAD_SWITCH_DEPTH", "100");
                        tprintln!("[THREAD-CONFIG] Set thread switch depth to 100");
                    }

                    if env::var("THREAD_TIME_SLICE").is_err() {
                        // Time-slice defaults are tuned per language family.
                        //
                        // Go GC — 10 000 instructions
                        //   Go emits goroutines via `runtime.newproc` which itself runs
                        //   thousands of pcode ops (allocator, scheduler bookkeeping).
                        //   A large slice lets each goroutine run a meaningful block of
                        //   work before switching, keeping overhead low.
                        //
                        // C / C++ — 50 instructions
                        //   pthreads threads are already alive in the GDB dump when
                        //   Zorya starts (captured while spinning at a barrier).  The
                        //   test entry point (`zorya_entry`) exits via direct_exit()
                        //   (SYS_exit), so Zorya's sys_exit handler switches to the
                        //   writers without ever relying on the time-slice.  50 gives
                        //   each writer enough pcode ops to exit zorya_spin, write to
                        //   counter, and call direct_exit() in a single slice, keeping
                        //   context-switch noise minimal.
                        //
                        // To tune: change the constants below.  Do NOT expose this as
                        // a CLI flag — the right value is an implementation detail of
                        // how the binary under test is structured, not a user concern.
                        let default_slice = if source_lang_norm == "go" {
                            "10000"
                        } else {
                            "50"
                        };
                        env::set_var("THREAD_TIME_SLICE", default_slice);
                        tprintln!(
                            "[THREAD-CONFIG] Set time slice to {} instructions",
                            default_slice
                        );
                    }
                }
                "main-only" | "main_only" | "mainonly" | "none" => {
                    env::set_var("THREAD_SCHEDULING", "main_only");
                    tprintln!(
                        "[THREAD-CONFIG] Using main-only thread policy (single thread execution)"
                    );
                }
                _ => {
                    // Leave unknown values as-is; thread manager will warn and default to MainOnly
                }
            }
        }
    }
    // Clean up previous SAT state file before starting new execution
    let sat_state_file = "results/FOUND_SAT_STATE.txt";
    if Path::new(sat_state_file).exists() {
        match fs::remove_file(sat_state_file) {
            Ok(()) => {
                tprintln!("Cleaned up previous SAT state file: {}", sat_state_file);
            }
            Err(e) => {
                teprintln!(
                    "Warning: Failed to remove previous SAT state file {}: {}",
                    sat_state_file,
                    e
                );
                teprintln!("Continuing with execution, new results will be appended...");
            }
        }
    }

    let config = Config::new();
    let context = Context::new(&config);
    // Logging mode: "verbose" (default) writes execution_log.txt; "trace_only" disables it
    let log_mode = env::var("LOG_MODE")
        .unwrap_or_else(|_| "verbose".to_string())
        .to_lowercase();
    let logger_path = if log_mode == "trace_only" {
        "/dev/null"
    } else {
        "results/execution_log.txt"
    };
    let logger = Logger::new(logger_path, false).expect("Failed to create logger"); // detailed log (file only when not trace_only)

    // Detect whether the shell wrapper is teeing all terminal output to the
    // trace file.  When it is, we must NOT also write directly to the file
    // from the Rust binary — that would produce duplicate lines.
    //
    // Two modes:
    //   ZORYA_TRACE_BY_SHELL=1  → shell handles the file; use stdout-only logger.
    //   otherwise               → binary writes the file itself; use append-mode
    //                             logger so it doesn't overwrite the TRACE_FILE
    //                             handle (which also opens in append mode).
    let trace_by_shell = std::env::var("ZORYA_TRACE_BY_SHELL")
        .map(|v| v == "1")
        .unwrap_or(false);

    let trace_logger = if trace_by_shell {
        // Shell is teeing stdout → file.  Logger must not write to the file.
        Logger::new_stdout_only().expect("Failed to create stdout-only trace logger")
    } else {
        // Standalone run: truncate the trace file once, then open both handles
        // in append mode so they serialize writes correctly.
        let _ = std::fs::File::create("results/execution_trace.txt"); // truncate
        Logger::new_append("results/execution_trace.txt", true)
            .expect("Failed to create trace logger")
    };

    if !trace_by_shell {
        // Initialise the global TRACE_FILE handle (append mode) used by
        // tprintln!/teprintln!.  Only needed when not running via the wrapper.
        zorya::init_trace_file("results/execution_trace.txt");

        // Mirror the "Running command:" line into the trace file so the file
        // is self-contained when running without the shell wrapper.
        if let Ok(cmd) = std::env::var("ZORYA_CMD") {
            tprintln!("Running command: {}", cmd);
            tprintln!();
        }
    }
    let mut executor: ConcolicExecutor<'_> =
        ConcolicExecutor::new(&context, logger.clone(), trace_logger.clone())
            .map_err(|e| e.to_string())?;

    log!(
        executor.state.logger,
        "Configuration and context have been initialized."
    );

    let (binary_path, pcode_file_path, main_program_addr) = {
        let target_info = GLOBAL_TARGET_INFO.lock().unwrap();
        log!(executor.state.logger, "Acquired target information.");
        (
            target_info.binary_path.clone(),
            target_info.pcode_file_path.clone(),
            target_info.main_program_addr.clone(),
        )
    };
    log!(executor.state.logger, "Binary path: {}", binary_path);
    let pcode_file_path_str = pcode_file_path
        .to_str()
        .expect("The file path contains invalid Unicode characters.");

    // Adapt scenaris according to the chosen mode in the command
    let mode = env::var("MODE").expect("MODE environment variable is not set");
    let arguments = env::var("ARGS").expect("MODE environment variable is not set");
    let source_lang =
        std::env::var("SOURCE_LANG").expect("SOURCE_LANG environment variable is not set");

    // Populate the symbol table
    let elf_data = fs::read(binary_path.clone())?;
    executor.populate_symbol_table(&elf_data)?;
    log!(
        executor.state.logger,
        "The symbols table has been populated."
    );

    log!(
        executor.state.logger,
        "Path to the p-code file: {}",
        pcode_file_path_str
    );
    // Preprocess the p-code file to get a map of addresses to instructions
    let mut instructions_map = preprocess_pcode_file(pcode_file_path_str, &mut executor)
        .expect("Failed to preprocess the p-code file.");

    tprintln!("Building the P-Code for the VDSO section (this may take a moment)...");
    // Merge VDSO p-code if available
    merge_vdso_pcode(&mut instructions_map, &mut executor);

    tprintln!("Precomputing the tables of cross references of potential panics in the programs (for bug detection)...");
    // Get the tables of cross references of potential panics in the programs (for bug detection)
    get_cross_references(&binary_path)?;

    let start_address = u64::from_str_radix(main_program_addr.trim_start_matches("0x"), 16)
        .expect("The format of the main program address is invalid.");

    if mode == "function" {
        log!(
            executor.state.logger,
            "Mode is 'function'. Adapting the context..."
        );
        log!(
            executor.state.logger,
            "Start address is {:?}",
            format!("{:x}", start_address)
        );

        // Making the difference between Go and the rest because Ghidra's ABI has issues with Go
        // Both methods create a file called function_signature.json in the results directory
        let function_args_map = match source_lang.to_lowercase().as_str() {
            // --- C / C++ branch ---
            "c" | "c++" => {
                log!(
                    executor.state.logger,
                    "Precomputing function signatures using Ghidra headless…"
                );
                precompute_function_signatures_via_ghidra(&binary_path, &mut executor)?;

                log!(executor.state.logger, "Loading raw C signatures…");
                // now returns HashMap<u64, (String, Vec<(arg, Vec<reg>, typ)>)>
                let raw = load_function_args_map();
                log!(
                    executor.state.logger,
                    "Loaded {} raw C signatures.",
                    raw.len()
                );

                let mut unified = HashMap::new();
                let cpu = executor.state.cpu_state.lock().unwrap();

                for (addr, (fn_name, raw_args)) in raw {
                    let mut args: Vec<(String, String, String)> = Vec::new();

                    for (arg_name, regs, typ) in raw_args {
                        // we expect at least one register name
                        if regs.is_empty() {
                            continue;
                        }

                        // keep single-register as is, multi-register joined with “,” (like we do for Go)
                        let reg_repr = if regs.len() == 1 {
                            regs[0].clone()
                        } else {
                            regs.join(",")
                        };

                        // optional sanity-check against CPU register map
                        let reg_ok = regs
                            .iter()
                            .all(|r| cpu.resolve_offset_from_register_name(r).is_some());
                        if !reg_ok {
                            log!(
                                executor.state.logger,
                                "WARNING: unknown register(s) {:?} for arg '{}' @0x{:x}",
                                regs,
                                arg_name,
                                addr
                            );
                        }

                        args.push((arg_name, reg_repr, typ));
                    }
                    unified.insert(addr, (fn_name, args));
                }

                log!(
                    executor.state.logger,
                    "Unified {} C signatures.",
                    unified.len()
                );
                unified
            }
            // --- Go branch ---
            "go" => {
                let func_signatures_path = "results/function_signatures_go.json";

                // Step 1: Extract runtime.g struct offsets (goid, etc.) for goroutine ID tracking.
                // The Go tool parses DWARF to find the runtime.g struct layout and writes
                // results/runtime_g_offsets.json, which is loaded at runtime by runtime_info.rs.
                // NOTE: The Go tool also writes function_signatures_go.json; step 2 overwrites it
                // with the more complete llvm-dwarfdump output, which is why we run Go first.
                let zorya_dir = env::var("ZORYA_DIR")?;
                let go_tool_dir = format!("{}/scripts/get-funct-arg-types", zorya_dir);
                log!(
                    executor.state.logger,
                    "Extracting runtime.g offsets from DWARF..."
                );
                let abs_binary = std::fs::canonicalize(&binary_path)
                    .unwrap_or_else(|_| std::path::Path::new(&binary_path).to_path_buf());
                let abs_signatures =
                    std::fs::canonicalize(func_signatures_path).unwrap_or_else(|_| {
                        std::env::current_dir().unwrap().join(func_signatures_path)
                    });
                let go_out = std::process::Command::new("go")
                    .arg("run")
                    .arg(".")
                    .arg(abs_binary.to_str().unwrap_or(&binary_path))
                    .arg(abs_signatures.to_str().unwrap_or(func_signatures_path))
                    .arg("--extract-runtime-g")
                    .current_dir(&go_tool_dir)
                    .output();
                match go_out {
                    Ok(o) if o.status.success() => {
                        log!(
                            executor.state.logger,
                            "runtime.g offsets extracted successfully."
                        );
                    }
                    Ok(o) => {
                        log!(
                            executor.state.logger,
                            "Warning: runtime.g extraction failed: {}",
                            String::from_utf8_lossy(&o.stderr)
                        );
                    }
                    Err(e) => {
                        log!(
                            executor.state.logger,
                            "Warning: Could not run Go tool for runtime.g extraction: {}",
                            e
                        );
                    }
                }

                // Step 2: Extract full function signatures with llvm-dwarfdump (Python).
                // This runs AFTER the Go tool so its output (which covers all functions
                // including unexported ones like parseID) is the final version.
                log!(
                    executor.state.logger,
                    "Extracting Go function signatures using llvm-dwarfdump..."
                );
                let llvm_script = format!(
                    "{}/scripts/llvm_extract_function_signatures.py",
                    env::var("ZORYA_DIR")?
                );
                let out = std::process::Command::new("python3")
                    .arg(&llvm_script)
                    .arg(&binary_path)
                    .arg(func_signatures_path)
                    .output()?;
                if !out.status.success() {
                    return Err(format!(
                        "llvm-dwarfdump extraction failed: {}",
                        String::from_utf8_lossy(&out.stderr)
                    )
                    .into());
                }

                log!(
                    executor.state.logger,
                    "Loading Go signatures from {}...",
                    func_signatures_path
                );

                // Read and parse the Go JSON file directly
                let file = std::fs::File::open(func_signatures_path)
                    .map_err(|e| format!("Failed to open {}: {}", func_signatures_path, e))?;
                let reader = std::io::BufReader::new(file);
                let functions: Vec<GoFunctionArg> =
                    serde_json::from_reader(reader).map_err(|e| {
                        format!("Failed to parse JSON from {}: {}", func_signatures_path, e)
                    })?;

                log!(
                    executor.state.logger,
                    "Loaded {} functions from JSON.",
                    functions.len()
                );

                // Load struct type definitions for struct pointer field symbolization
                let struct_types_path = "results/function_signatures_go_structs.json";
                init_struct_types_cache(struct_types_path);

                // Build the final HashMap directly
                let mut go_signatures = HashMap::new();
                for func in functions {
                    // Parse hex address
                    if let Ok(addr) = u64::from_str_radix(func.address.trim_start_matches("0x"), 16)
                    {
                        let mut args = Vec::new();
                        for arg in func.arguments {
                            let reg_list = arg.registers.join(",");
                            args.push((arg.name, reg_list, arg.arg_type));
                        }
                        go_signatures.insert(addr, (func.name, args));
                    } else {
                        log!(
                            executor.state.logger,
                            "Warning: Failed to parse address {} for function {}",
                            func.address,
                            func.name
                        );
                    }
                }

                log!(
                    executor.state.logger,
                    "Processed {} Go signatures.",
                    go_signatures.len()
                );
                go_signatures
            }
            // --- unsupported ---
            other => {
                log!(executor.state.logger, "Unsupported language: {}", other);
                return Err("Unsupported source language".into());
            }
        };

        // In function mode: initialize symbolic arguments
        if let Some((func_name, args)) = function_args_map.get(&start_address) {
            tprintln!(
                "Function mode: initializing {} symbolic argument(s) for function '{}' at 0x{:x}...",
                args.len(),
                func_name,
                start_address
            );
            log!(
                executor.state.logger,
                "Found {} arguments for function '{}' at 0x{:x}",
                args.len(),
                func_name,
                start_address
            );

            let mut concrete_values_of_args = Vec::new();

            // Phase 1: Initialize slice/string/argument structures
            log!(
                executor.state.logger,
                "=== PHASE 1: Initializing argument structures ==="
            );

            for (arg_name, reg_spec, arg_type) in args.iter() {
                // reg_spec is a comma-separated string like "RAX,RBX,RCX" or "RDI"
                // Split it back into a Vec for uniform handling
                let regs: Vec<&str> = if reg_spec.is_empty() {
                    vec![]
                } else {
                    reg_spec.split(',').collect()
                };

                log!(
                    executor.state.logger,
                    "Assigning symbolic var '{}' to register '{}' of type {}",
                    arg_name,
                    reg_spec,
                    arg_type
                );

                // Special handling for Go strings: two registers (ptr, len)
                if arg_type == "string" && regs.len() == 2 {
                    initialize_string_argument(
                        arg_name,
                        &regs,
                        &mut concrete_values_of_args,
                        &mut executor,
                    );
                    continue;
                } else if arg_type == "string" && regs.len() != 2 {
                    log!(
                        executor.state.logger,
                        "WARNING: unexpected registers '{}' for string '{}', skipping",
                        reg_spec,
                        arg_name
                    );
                    continue;
                }

                // Go interface{} / any: two registers (itab in regs[0], data in regs[1]).
                // The itab is pinned to its concrete value so the type-switch follows
                // the same arm as the snapshot; the data slot is made fully symbolic so
                // the TRUNC oracle can see the float64 bits when the arm is `case float64:`.
                if (arg_type == "interface {}" || arg_type == "any") && regs.len() == 2 {
                    initialize_interface_argument(
                        arg_name,
                        &regs,
                        &mut concrete_values_of_args,
                        &mut executor,
                    );
                    continue;
                } else if (arg_type == "interface {}" || arg_type == "any") && regs.len() != 2 {
                    log!(
                        executor.state.logger,
                        "WARNING: unexpected register count {} for interface{{}} '{}', expected 2 — skipping",
                        regs.len(),
                        arg_name
                    );
                    continue;
                }

                // Handle slice types (including multi-dimensional slices like [][32]byte)
                if arg_type.starts_with("[]") {
                    if regs.len() > 1 {
                        // Multi-register slice (ptr, len, cap)
                        initialize_slice_argument(
                            arg_name,
                            arg_type,
                            &regs,
                            &mut concrete_values_of_args,
                            &mut executor,
                        );
                    } else if regs.len() == 1 {
                        // Single register slice (just pointer)
                        initialize_single_register_slice(
                            arg_name,
                            arg_type,
                            regs[0],
                            &mut concrete_values_of_args,
                            &mut executor,
                        );
                    } else {
                        log!(
                            executor.state.logger,
                            "WARNING: no registers for slice '{}', skipping",
                            arg_name
                        );
                    }
                    continue;
                }

                // General case: single-register arguments
                if regs.len() == 1 {
                    initialize_single_register_argument(
                        arg_name,
                        regs[0],
                        arg_type,
                        &mut concrete_values_of_args,
                        &mut executor,
                    );

                    // Check if this is a pointer to a struct and symbolize its fields
                    if let Some(struct_name) = is_struct_pointer_type(arg_type) {
                        log!(
                            executor.state.logger,
                            "Detected struct pointer '{}' -> '{}', symbolizing struct fields...",
                            arg_name,
                            struct_name
                        );
                        initialize_struct_pointer_fields(
                            &mut executor,
                            arg_name,
                            regs[0],
                            &struct_name,
                        );
                    }
                } else if regs.is_empty() {
                    log!(
                        executor.state.logger,
                        "WARNING: no register for argument '{}', skipping",
                        arg_name
                    );
                } else {
                    log!(
                        executor.state.logger,
                        "WARNING: multiple registers '{}' for non-slice/string argument '{}', using first register",
                        reg_spec,
                        arg_name
                    );
                    initialize_single_register_argument(
                        arg_name,
                        regs[0],
                        arg_type,
                        &mut concrete_values_of_args,
                        &mut executor,
                    );

                    // Check if this is a pointer to a struct and symbolize its fields
                    if let Some(struct_name) = is_struct_pointer_type(arg_type) {
                        log!(
                            executor.state.logger,
                            "Detected struct pointer '{}' -> '{}', symbolizing struct fields...",
                            arg_name,
                            struct_name
                        );
                        initialize_struct_pointer_fields(
                            &mut executor,
                            arg_name,
                            regs[0],
                            &struct_name,
                        );
                    }
                }
            }

            // Phase 2: Initialize memory contents pointed to by slices
            log!(
                executor.state.logger,
                "=== PHASE 2: Initializing slice memory contents ==="
            );

            let slice_args: Vec<_> = args
                .iter()
                .filter(|(_, _, arg_type)| arg_type.starts_with("[]"))
                .collect();

            if !slice_args.is_empty() {
                log!(
                    executor.state.logger,
                    "Found {} slice arguments to initialize memory for",
                    slice_args.len()
                );

                // Convert to the format expected by initialize_slice_memory_contents
                let slice_args_owned: Vec<(String, String, String)> = slice_args
                    .into_iter()
                    .map(|(name, reg, typ)| (name.clone(), reg.clone(), typ.clone()))
                    .collect();

                initialize_slice_memory_contents(&mut executor, &slice_args_owned);
            } else {
                log!(
                    executor.state.logger,
                    "No slice arguments found, skipping memory initialization"
                );
            }

            // Initialize string memory contents (make string bytes symbolic)
            log!(
                executor.state.logger,
                "Initializing string memory contents..."
            );
            initialize_string_memory_contents(&mut executor, args);

            log!(
                executor.state.logger,
                "=== INITIALIZATION COMPLETE: {} total arguments processed ===",
                args.len()
            );
        } else {
            log!(
                executor.state.logger,
                "No signature at start_address 0x{:x}, skipping symbolic init",
                start_address
            );
        }
    } else if mode == "start" || mode == "main" {
        if source_lang == "go" {
            let os_args_addr = get_os_args_address(&binary_path)?;
            log!(
                executor.state.logger,
                "os.Args slice address: 0x{:x}",
                os_args_addr
            );
            tprintln!("**************************************************************************");
            tprintln!("Initializing symbolic variables for the program arguments (os.Args)...");
            initialize_symbolic_part_args(&mut executor, os_args_addr)?;
            log!(executor.state.logger, "Updating argc and argv on the stack");
            update_argc_argv(&mut executor, &arguments)?;
        } else if mode == "main" {
            // A C/C++ binary halted at the user `main` reads argc/argv from the
            // System V argument registers RDI/RSI (saved into the stack frame by
            // the prologue), NOT from the kernel `_start` layout at rsp+8. Build
            // a real, partially-symbolic argv and point RDI/RSI at it so that
            // input-dependent branches on argv become symbolic path conditions.
            tprintln!("**************************************************************************");
            tprintln!("Initializing symbolic variables for the program arguments (argv)...");
            setup_c_main_args(&mut executor, &arguments, &binary_path)?;
        } else {
            // C/C++ at the ELF entry (`_start`): the kernel stack layout applies.
            log!(executor.state.logger, "Updating argc and argv on the stack");
            update_argc_argv(&mut executor, &arguments)?;
        }
    } else if mode == "advanced" {
        log!(
            executor.state.logger,
            "Mode is 'advanced'. Fine-grained symbolic variable selection."
        );
        tprintln!("**************************************************************************");
        tprintln!("Advanced mode: configuring symbolic registers and memory...");

        // --- Symbolic registers ---
        let sym_regs_env = env::var("SYMBOLIC_REGISTERS").unwrap_or_else(|_| String::new());
        let sym_regs_input = if sym_regs_env.is_empty() {
            tprintln!("Which registers do you want to make symbolic? (space-separated, e.g. RAX RDI RSI, or 'none')");
            let mut input = String::new();
            io::stdin()
                .read_line(&mut input)
                .expect("Failed to read stdin");
            input.trim().to_string()
        } else {
            sym_regs_env
        };

        if !sym_regs_input.is_empty() && sym_regs_input != "none" {
            let reg_names: Vec<&str> = sym_regs_input.split_whitespace().collect();
            let mut cpu = executor.state.cpu_state.lock().unwrap();
            for reg_name in &reg_names {
                let upper = reg_name.to_uppercase();
                if let Some(offset) = cpu.resolve_offset_from_register_name(&upper) {
                    let (_, bit_width) = cpu.register_map.get(&offset).unwrap().clone();
                    let bv_name = format!("adv_reg_{}", upper);
                    let fresh_bv = BV::fresh_const(executor.context, &bv_name, bit_width);

                    let current_concrete = cpu
                        .get_register_by_offset(offset, bit_width)
                        .map(|v| v.concrete.to_u64())
                        .unwrap_or(0);

                    let concolic = ConcolicVar::new_concrete_and_symbolic_int(
                        current_concrete,
                        fresh_bv.clone(),
                        executor.context,
                    );
                    cpu.set_register_value_by_offset(offset, concolic, bit_width)
                        .expect("Failed to set symbolic register");

                    drop(cpu);
                    executor
                        .function_symbolic_arguments
                        .insert(bv_name.clone(), SymbolicVar::Int(fresh_bv));
                    log!(
                        executor.state.logger,
                        "Advanced mode: made register {} symbolic as '{}'",
                        upper,
                        bv_name
                    );
                    tprintln!(
                        "  -> Register {} is now symbolic (tracked as '{}')",
                        upper,
                        bv_name
                    );
                    cpu = executor.state.cpu_state.lock().unwrap();
                } else {
                    tprintln!(
                        "  [WARNING] Unknown register '{}', skipping. Valid: RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8-R15",
                        upper
                    );
                    log!(
                        executor.state.logger,
                        "Advanced mode: unknown register '{}', skipped",
                        upper
                    );
                }
            }
            drop(cpu);
        }

        // --- Symbolic memory ranges ---
        let sym_mem_env = env::var("SYMBOLIC_MEMORY").unwrap_or_else(|_| String::new());
        let sym_mem_input = if sym_mem_env.is_empty() {
            tprintln!("Which memory addresses do you want to make symbolic? (format: 0xADDR:SIZE_BYTES, space-separated, or 'none')");
            tprintln!("  Example: 0x7fff0010:8 0x404000:16");
            let mut input = String::new();
            io::stdin()
                .read_line(&mut input)
                .expect("Failed to read stdin");
            input.trim().to_string()
        } else {
            sym_mem_env
        };

        if !sym_mem_input.is_empty() && sym_mem_input != "none" {
            let ranges: Vec<&str> = sym_mem_input.split_whitespace().collect();
            for range_spec in &ranges {
                let parts: Vec<&str> = range_spec.split(':').collect();
                if parts.len() != 2 {
                    tprintln!(
                        "  [WARNING] Invalid format '{}', expected 0xADDR:SIZE. Skipping.",
                        range_spec
                    );
                    continue;
                }
                let addr_str = parts[0].trim_start_matches("0x").trim_start_matches("0X");
                let size_str = parts[1];

                let addr = match u64::from_str_radix(addr_str, 16) {
                    Ok(a) => a,
                    Err(_) => {
                        tprintln!("  [WARNING] Invalid hex address '{}'. Skipping.", parts[0]);
                        continue;
                    }
                };
                let size: usize = match size_str.parse() {
                    Ok(s) => s,
                    Err(_) => {
                        tprintln!("  [WARNING] Invalid size '{}'. Skipping.", size_str);
                        continue;
                    }
                };

                let concrete_bytes = executor
                    .state
                    .memory
                    .read_bytes(addr, size)
                    .unwrap_or_else(|_| vec![0u8; size]);

                let mut fresh_symbolic = Vec::with_capacity(size);
                for byte_idx in 0..size {
                    let bv_name = format!("adv_mem_0x{:x}_byte_{}", addr, byte_idx);
                    let fresh_bv = BV::fresh_const(executor.context, &bv_name, 8);
                    executor
                        .function_symbolic_arguments
                        .insert(bv_name.clone(), SymbolicVar::Int(fresh_bv.clone()));
                    fresh_symbolic.push(Some(Rc::new(fresh_bv)));
                }

                executor
                    .state
                    .memory
                    .write_memory(addr, &concrete_bytes, &fresh_symbolic)
                    .expect("Failed to write symbolic memory");

                log!(
                    executor.state.logger,
                    "Advanced mode: made {} bytes at 0x{:x} symbolic",
                    size,
                    addr
                );
                tprintln!(
                    "  -> Memory range 0x{:x}..0x{:x} ({} bytes) is now symbolic",
                    addr,
                    addr + size as u64,
                    size
                );
            }
        }

        log!(executor.state.logger, "Updating argc and argv on the stack");
        update_argc_argv(&mut executor, &arguments)?;

        tprintln!("");
        tprintln!("Note: os.Args is NOT symbolized in advanced mode. At an arbitrary address,");
        tprintln!("  the program has already read os.Args into local registers/memory. Use");
        tprintln!("  --symbolic-registers and --symbolic-memory to target the live copies.");
        log!(
            executor.state.logger,
            "Advanced mode: os.Args not symbolized (values are already in local registers/memory at this execution point)"
        );

        tprintln!("");
        tprintln!("Advanced mode initialization complete.");
        tprintln!(
            "  Tracked symbolic variables: {}",
            executor.function_symbolic_arguments.len()
        );
        tprintln!("**************************************************************************");
    } else {
        log!(
            executor.state.logger,
            "[WARNING] Unknown mode '{}' used.",
            mode
        );
    }

    // For Go binaries: clear the goroutine stackPreempt flag if set.
    // When stackguard0 == runtime.stackPreempt, every Go function prologue
    // triggers goroutine preemption, preventing execution of the function body.
    if source_lang.to_lowercase() == "go" {
        log!(
            executor.state.logger,
            "[GO-INIT] Checking for goroutine stackPreempt flag..."
        );
        clear_go_stack_preempt(&mut executor);
    }

    // Precompute reverse panic reachability set (O(V+E)), then O(1) queries
    let _ = precompute_panic_reach(&binary_path)?;

    // *****************************
    // CORE COMMAND
    tprintln!("**************************************************************************");
    tprintln!("THE CONCOLIC EXECUTION OF THE BINARY HAS STARTED!");
    if log_mode == "trace_only" {
        tprintln!("Trace-only logging enabled (LOG_MODE=trace_only). Writing results/execution_trace.txt only.");
    } else {
        tprintln!("Find the logs in results/execution_log.txt and results/execution_trace.txt");
    }
    tprintln!("**************************************************************************");

    execute_instructions_from(
        &mut executor,
        start_address,
        &instructions_map,
        &binary_path,
    );
    // *****************************

    // Erase the sticky coverage bar from rows 998/999 so the shell prompt
    // does not get painted on top of leftover bar text.
    zorya::clear_coverage_bar();

    Ok(())
}

/// Update the sticky coverage bar that stays pinned to the last terminal line.
///
/// Stores the rendered bar text in the global `zorya::COVERAGE_BAR` so that
/// every subsequent `tprintln!` / `teprintln!` call automatically erases the
/// bar before its message and redraws it afterwards.  The bar itself is written
/// to stdout (same stream as all other output) so there is no cross-stream
/// interleaving.
///
/// When stdout is not a TTY the function is a no-op (the fallback plain-text
/// line is produced by the non-TTY branch of `tprintln!` / `teprintln!`).
/// Update the sticky coverage bar pinned to the bottom of the user's terminal.
///
/// Writes directly to `/dev/tty` so the bar is visible even when stdout is
/// piped through the zorya wrapper's `tee` process substitution.
/// No-op when there is no controlling terminal (CI, fully piped runs, etc.).
/// Update the sticky coverage bar pinned to the last terminal line.
///
/// Writes through the same /dev/tty fd used by `tprintln!` / `teprintln!`,
/// so bar updates and normal messages are always serialised — no race condition
/// is possible.  No-op when there is no controlling terminal.
/// Render the sticky status bar at the bottom of the terminal.
///
/// Includes block-level coverage, elapsed time, active function, and
/// constraint count — the four signals most useful for spotting a stall:
///
/// * **Coverage** — are new blocks being reached?
/// * **Elapsed** — overall wall-clock time
/// * **Function** — where in the binary execution currently is
/// * **Constraints** — proxy for SMT solver complexity; a rapidly growing
///   count suggests the solver will slow down soon
///
/// Render the sticky status bar.
///
/// Metrics shown — chosen to give a flamegraph-like view of where time goes:
///
/// * **Coverage bar + %** — are new basic blocks being reached?
/// * **⏱ Elapsed** — wall-clock time since execution started
/// * **Z3 time / Z3 %** — cumulative SMT-solver time and its share of elapsed.
///   This is the key flamegraph-equivalent: a high Z3 % means the solver is
///   the bottleneck (constraints too complex); a low Z3 % with slow execution
///   points to p-code emulation being the bottleneck.
/// * **🔗 Constraints** — size of the constraint set fed to Z3; a proxy for
///   how hard future solver calls will be.
fn print_coverage_bar(
    visited: usize,
    total: usize,
    elapsed_secs: f64,
    z3_cumulative_ms: u64,
    constraint_count: usize,
) {
    if zorya::TTY.is_none() {
        return;
    }

    let pct = (visited as f64 / total as f64) * 100.0;

    const BAR_WIDTH: usize = 20;
    let filled = ((pct / 100.0 * BAR_WIDTH as f64) as usize)
        .max(if visited > 0 { 1 } else { 0 })
        .min(BAR_WIDTH);

    let coloured_fill = format!(
        "\x1b[32m{}\x1b[90m{}\x1b[0m",
        "█".repeat(filled),
        "░".repeat(BAR_WIDTH - filled),
    );

    // Elapsed: switch to m:ss once past 60 s
    let elapsed_str = if elapsed_secs >= 60.0 {
        format!(
            "{:.0}m{:.0}s",
            (elapsed_secs / 60.0).floor(),
            elapsed_secs % 60.0
        )
    } else {
        format!("{:.1}s", elapsed_secs)
    };

    // Z3 cumulative time and its share of wall-clock time
    let z3_secs = z3_cumulative_ms as f64 / 1000.0;
    let z3_pct = if elapsed_secs > 0.0 {
        (z3_secs / elapsed_secs * 100.0).min(100.0)
    } else {
        0.0
    };
    // Colour the Z3 % red when it dominates (> 50 %), yellow when notable (> 20 %)
    let z3_colour = if z3_pct > 50.0 {
        "31"
    } else if z3_pct > 20.0 {
        "33"
    } else {
        "32"
    };
    let z3_str = format!("\x1b[{}m{:.1}s ({:.0}%)\x1b[0m", z3_colour, z3_secs, z3_pct);

    let bar_text = format!(
        "\x1b[1;36m[Coverage]\x1b[0m [{}] \x1b[1m{}/{}\x1b[0m ({:.3}%) \
         \x1b[90m|\x1b[0m t:\x1b[33m{}\x1b[0m \
         \x1b[90m|\x1b[0m Z3:{} \
         \x1b[90m|\x1b[0m cst:\x1b[33m{}\x1b[0m",
        coloured_fill, visited, total, pct, elapsed_str, z3_str, constraint_count,
    );

    if let Ok(mut guard) = zorya::COVERAGE_BAR.lock() {
        *guard = bar_text.clone();
    }
    // \n before the bar so there is always a blank separator line between
    // the last output line and the coverage bar.
    zorya::tty_write(&format!(
        "\x1b[s\x1b[998;1H\x1b[2K\x1b[999;1H\x1b[2K{}\x1b[u",
        bar_text
    ));
}

// Function to execute the instructions from the map of addresses to instructions
fn execute_instructions_from(
    executor: &mut ConcolicExecutor,
    start_address: u64,
    instructions_map: &BTreeMap<u64, Vec<Inst>>,
    binary_path: &str,
) {
    let mut current_rip = start_address;
    let mut local_line_number: i64 = 0; // Index of the current instruction within the block
    let end_address: u64 = 0x0; //no specific end address

    // For debugging
    //let address: u64 = 0x7fffffffe4b0;
    //let range = 0x8;

    log!(
        executor.state.logger,
        "Logging the addresses of the XREFs of Panic functions..."
    );
    // Read the panic addresses from the file once before the main loop
    log!(
        executor.state.logger,
        "Beginning execution from address: 0x{:x}",
        start_address
    );

    // Set RIP to start_address once before entering the loop
    {
        let mut cpu_state_guard = executor.state.cpu_state.lock().unwrap();
        cpu_state_guard
            .set_register_value_by_offset(
                0x288,
                ConcolicVar::new_concrete_and_symbolic_int(
                    current_rip,
                    SymbolicVar::new_int(current_rip.try_into().unwrap(), executor.context, 64)
                        .to_bv(executor.context),
                    executor.context,
                ),
                64,
            )
            .map_err(|e| e.to_string())
            .unwrap();
    }

    // Load the function arguments map
    // TODO: optimize that
    log!(executor.state.logger, "Loading function arguments map...");
    let lang = env::var("SOURCE_LANG").expect("SOURCE_LANG environment variable is not set");

    let function_args_map = if lang == "go" {
        log!(
            executor.state.logger,
            "Loading Go function arguments map..."
        );
        let function_args_map =
            load_go_function_args_map(binary_path, executor).unwrap_or_else(|e| {
                log!(
                    executor.state.logger,
                    "Error loading Go function arguments map: {}",
                    e
                );
                HashMap::new() // Return an empty map if loading fails
            });
        function_args_map
    } else {
        log!(executor.state.logger, "Loading C function arguments map...");

        load_function_args_map()
    };

    // Check up-front that p-code exists for the start address so the user
    // gets an actionable error instead of a silent no-op.
    if !instructions_map.contains_key(&current_rip) {
        let msg = format!(
            "ERROR: No P-Code found for start address 0x{:x}. \
             Pcode-generator tool may have failed to decode this function \
             (e.g. it is an autogenerated stub or a LowlevelError was emitted). \
             Please check the pcode file and verify the target address is correct.",
            current_rip
        );
        teprintln!("{}", msg);
        log!(executor.state.logger, "{}", msg);
        finalize_plugin_analysis(executor);
        return;
    }

    loop {
        // External-function boundary check. `current_rip` is "external" when:
        //   * it has no lifted pcode (the thread-exit sentinel, or a libc
        //     return target), or
        //   * it is a PLT stub. PLT stubs *do* carry lifted pcode (the `.plt`
        //     section is executable), but executing it would run the lazy
        //     resolver / jump into libc, which Zorya does not model. We
        //     intercept at the named stub instead.
        //
        // The external-call handler spawns threads (pthread_create), satisfies
        // joins (pthread_join), yields to another ready thread, or terminates —
        // rather than silently ending the whole run.
        let treat_as_external = current_rip == zorya::executor::THREAD_EXIT_SENTINEL
            || !instructions_map.contains_key(&current_rip)
            || executor
                .symbol_table
                .get(&format!("{:x}", current_rip))
                .map(|s| s.starts_with("plt_"))
                .unwrap_or(false);
        if treat_as_external {
            if executor.state.is_terminated {
                break;
            }
            match executor.handle_external_boundary(current_rip) {
                zorya::executor::ExternalOutcome::Resume(next_rip) => {
                    current_rip = next_rip;
                    continue;
                }
                zorya::executor::ExternalOutcome::Terminate => break,
            }
        }

        // ---------------------------------------------------------------
        // Thread-scheduling checkpoint — the SINGLE authoritative switch
        // point. It runs here, at the top of the per-instruction loop, which
        // is an x86 *instruction* boundary: `current_rip` is the next whole
        // instruction the running thread will execute and the CPU state is
        // fully consistent (no half-applied pcode micro-ops in flight).
        //
        // This placement is load-bearing. Earlier the switch lived inside the
        // inner pcode loop, so the time slice could expire *between* the
        // micro-ops of one instruction (e.g. between `mov rsp,rbp` and
        // `pop rbp` of a `leave`). Switching there restored the incoming
        // thread's registers and then ran the outgoing instruction's leftover
        // micro-ops against them, corrupting the incoming thread (a stray
        // `pop rbp` clobbered main's RBP and crashed the run). Keeping the one
        // checkpoint here makes that class of corruption impossible.
        {
            let mut tm = executor.state.thread_manager.lock().unwrap();
            tm.tick_instruction();
            let pre_switch_tid = tm.current_tid;
            if let Ok(Some(_new_tid)) = tm.maybe_switch_thread(CheckpointType::FunctionCall) {
                // Save the outgoing thread, pinning its resume RIP to the
                // current instruction boundary. The RIP register can be stale
                // after a sequential instruction (it tracks the executed op,
                // not the next one), so we set it explicitly before snapshotting
                // to guarantee a clean re-entry.
                {
                    let mut cpu = executor.state.cpu_state.lock().unwrap();
                    let rip_cv = ConcolicVar::new_concrete_and_symbolic_int(
                        current_rip,
                        BV::from_u64(executor.context, current_rip, 64),
                        executor.context,
                    );
                    let _ = cpu.set_register_value_by_offset(0x288, rip_cv, 64);
                    let snap = cpu.clone();
                    drop(cpu);
                    if let Some(old_thread) = tm.threads.get_mut(&pre_switch_tid) {
                        old_thread.cpu_state = snap;
                    }
                }

                // Load the incoming thread's saved CPU state and resume the
                // outer loop at its RIP (the external-boundary check at the top
                // handles sentinels / PLT stubs for the incoming thread).
                if let Ok(new_thread) = tm.current_thread() {
                    let new_cpu = new_thread.cpu_state.clone();
                    *executor.state.cpu_state.lock().unwrap() = new_cpu;
                }
                drop(tm);

                current_rip = executor
                    .state
                    .cpu_state
                    .lock()
                    .unwrap()
                    .get_register_by_offset(0x288, 64)
                    .unwrap()
                    .get_concrete_value()
                    .unwrap();
                continue;
            }
        }

        let instructions = match instructions_map.get(&current_rip) {
            Some(insts) => insts,
            None => break,
        };
        if current_rip == end_address {
            log!(
                executor.state.logger,
                "END ADDRESS 0x{:x} REACHED, STOP THE EXECUTION",
                end_address
            );
            break; // Stop execution if end address is reached
        }

        log!(
            executor.state.logger,
            "*******************************************"
        );
        log!(
            executor.state.logger,
            "EXECUTING INSTRUCTIONS AT ADDRESS: 0x{:x}",
            current_rip
        );
        log!(
            executor.state.logger,
            "*******************************************"
        );

        let current_rip_hex = format!("{:x}", current_rip);

        // Block-level coverage: update the sticky bar at the bottom of the terminal
        // whenever a genuinely new block is entered.
        if executor.visited_blocks.insert(current_rip) {
            print_coverage_bar(
                executor.visited_blocks.len(),
                instructions_map.len(),
                executor.start_time.elapsed().as_secs_f64(),
                zorya::Z3_CUMULATIVE_MS.load(std::sync::atomic::Ordering::Relaxed),
                executor.constraint_vector.len(),
            );
        }

        // This block is only to get data about the execution in results/execution_trace.txt
        if let Some(symbol_name) = executor.symbol_table.get(&current_rip_hex) {
            // If entering strconv numeric parsing, proactively constrain argument bytes to digits
            if symbol_name == "strconv.Atoi" || symbol_name == "strconv.ParseInt" {
                if let Some((_, args)) = function_args_map.get(&current_rip) {
                    // Find a string argument (two locations: ptr,len). Prefer exact type match.
                    if let Some((_, reg_names, _)) = args
                        .iter()
                        .find(|(_, _, t)| t == "string")
                        .or_else(|| args.iter().find(|(_, _, t)| t.contains("string")))
                    {
                        // Resolve (ptr,len) locations from reg_names which may include registers or stack specs
                        let mut ptr_opt: Option<u64> = None;
                        let mut len_opt: Option<u64> = None;
                        let cpu = executor.state.cpu_state.lock().unwrap();
                        for (idx, s) in reg_names.iter().enumerate() {
                            let s = s.as_str();
                            let val = if is_stack_location(s) {
                                parse_stack_offset(s)
                                    .and_then(|off| {
                                        cpu.get_register_by_offset(0x20, 64).map(|rsp| {
                                            let addr = (rsp.concrete.to_u64() as i64 + off) as u64;
                                            // Read memory at computed stack address
                                            executor
                                                .state
                                                .memory
                                                .read_u64(addr, &mut executor.state.logger.clone())
                                                .ok()
                                                .map(|cv| cv.concrete.to_u64())
                                        })
                                    })
                                    .flatten()
                            } else {
                                cpu.resolve_offset_from_register_name(s)
                                    .and_then(|off| cpu.get_register_by_offset(off, 64))
                                    .map(|v| v.concrete.to_u64())
                            };
                            if idx == 0 {
                                ptr_opt = val;
                            } else if idx == 1 {
                                len_opt = val;
                            }
                        }
                        if let (Some(ptr), Some(len)) = (ptr_opt, len_opt) {
                            let max_len = std::cmp::min(len, 256);
                            let mut first_byte_bv: Option<z3::ast::BV> = None;
                            for j in 0..max_len {
                                if let Ok(byte_read) = executor.state.memory.read_byte(ptr + j) {
                                    let byte_bv = byte_read.symbolic.to_bv(executor.context);
                                    if j == 0 {
                                        first_byte_bv = Some(byte_bv.clone());
                                    }
                                    let zero =
                                        z3::ast::BV::from_u64(executor.context, b'0' as u64, 8);
                                    let nine =
                                        z3::ast::BV::from_u64(executor.context, b'9' as u64, 8);
                                    let is_digit = byte_bv.bvuge(&zero) & byte_bv.bvule(&nine);
                                    if j == 0 {
                                        let dash =
                                            z3::ast::BV::from_u64(executor.context, b'-' as u64, 8);
                                        let is_dash = byte_bv._eq(&dash);
                                        let allowed = z3::ast::Bool::or(
                                            executor.context,
                                            &[&is_dash, &is_digit],
                                        );
                                        executor.solver.assert(&allowed);
                                    } else {
                                        executor.solver.assert(&is_digit);
                                    }
                                }
                            }
                            if let Some(fb) = first_byte_bv {
                                let one64 = z3::ast::BV::from_u64(executor.context, 1, 64);
                                let len_bv = z3::ast::BV::from_u64(executor.context, len, 64);
                                let len_eq_one = len_bv._eq(&one64);
                                let dash8 = z3::ast::BV::from_u64(executor.context, b'-' as u64, 8);
                                let first_is_dash = fb._eq(&dash8);
                                let lone_dash = z3::ast::Bool::and(
                                    executor.context,
                                    &[&len_eq_one, &first_is_dash],
                                );
                                executor.solver.assert(&lone_dash.not());
                            }
                            log!(
                                executor.state.logger,
                                "Applied numeric ASCII constraints to strconv arg (ptr=0x{:x}, len={})",
                                ptr,
                                len
                            );
                        }
                    }
                }
            }
            if let Some((_, args)) = function_args_map.get(&current_rip) {
                let mut arg_values = Vec::new();
                let cpu = executor.state.cpu_state.lock().unwrap();
                for (arg_name, reg_names, _arg_type) in args {
                    for reg_name in reg_names {
                        if let Some(offset) = cpu.resolve_offset_from_register_name(reg_name) {
                            if let Some(value) = cpu.get_register_by_offset(offset, 64) {
                                arg_values.push(format!(
                                    "{}=0x{:x} (reg={} @0x{:x})",
                                    arg_name, value.concrete, reg_name, offset
                                ));
                            }
                        }
                    }
                }
                if !arg_values.is_empty() {
                    let log_string = format!(
                        "Address: {:x}, Symbol: {} -> {}",
                        current_rip,
                        symbol_name,
                        arg_values.join(", ")
                    );
                    log!(executor.trace_logger, "{}", log_string);
                }
            } else {
                log!(
                    executor.trace_logger,
                    "Address: {:x}, Symbol: {}",
                    current_rip,
                    symbol_name
                );
            }
        }

        // Inner loop: process each instruction in the current block.
        let mut end_of_block = false;

        while local_line_number < instructions.len().try_into().unwrap() && !end_of_block {
            // Calculate the potential next address taken by RIP, for the purpose of updating the symbolic part of CBRANCH and the lightweight path analysis
            let (next_addr_in_map, _) = instructions_map.range((current_rip + 1)..).next().unwrap();

            let inst = &instructions[local_line_number as usize];
            log!(
                executor.state.logger,
                "-------> Processing instruction at index: {}, {:?}",
                local_line_number,
                inst
            );

            // Check NEGATE_PATH_FLAG first - if disabled, skip all expensive CBranch preprocessing
            let negate_path_flag =
                std::env::var("NEGATE_PATH_FLAG").unwrap_or_else(|_| "false".to_string());

            // If this is a branch-type instruction, do symbolic checks (only if negate_path_flag is enabled)
            if inst.opcode == Opcode::CBranch && negate_path_flag == "true" {
                // Treat Const targets as p-code internal (jump table/sub-instruction): skip AST/speculation later
                let is_internal_target = matches!(&inst.inputs[0].var, Var::Const(_));

                // Check if branch condition involves tracked symbolic variables
                // ONLY explore if the condition contains symbolic variables we're tracking
                let condition_varnode_tmp = inst.inputs[1].clone();
                let condition_symbolic_tmp = executor
                    .varnode_to_concolic(&condition_varnode_tmp)
                    .map_err(|e| e.to_string())
                    .ok();

                let involves_tracked_symbolic = if let Some(cond) = condition_symbolic_tmp {
                    // Fast path 1: if branch condition is concrete, it cannot involve
                    // tracked symbolic inputs. Avoid expensive AST stringification.
                    let cond_bv = cond.get_symbolic_value_bv(executor.context);
                    if cond_bv.as_u64().is_some() {
                        false
                    } else {
                        // Fast path 2: for multithreaded C/C++ runs, skip negate-path
                        // pre-analysis in shared libraries (libc/ld/VDSO) where branch
                        // conditions are large solver terms unrelated to argv tracking.
                        let source_lang_norm = std::env::var("SOURCE_LANG")
                            .unwrap_or_default()
                            .to_lowercase();
                        let is_c_family = source_lang_norm == "c" || source_lang_norm == "c++";
                        let in_shared_lib_space = current_rip >= 0x7000_0000_0000;
                        if is_c_family && in_shared_lib_space {
                            false
                        } else {
                            let cond_var = cond.to_concolic_var().unwrap();
                            let expr_string = format!("{:?}", cond_var.symbolic);
                            let keys: Vec<&String> =
                                executor.function_symbolic_arguments.keys().collect();
                            let found = keys
                                .iter()
                                .any(|arg_name| expr_string.contains(arg_name.as_str()));
                            if !found {
                                log!(
                                    executor.state.logger,
                                    "Branch at 0x{:x}: condition does not involve tracked keys {:?}",
                                    current_rip,
                                    keys
                                );
                            }
                            found
                        }
                    }
                } else {
                    false
                };

                // SIMPLIFIED GATING: Only explore if branch condition involves tracked symbolic variables
                if !involves_tracked_symbolic {
                    inc_gated_by_reach();
                    log!(
                        executor.state.logger,
                        "Skipping overlay analysis at 0x{:x}: branch condition does not involve tracked symbolic variables",
                        current_rip
                    );
                } else {
                    log!(
                        executor.state.logger,
                        "Branch at 0x{:x} involves tracked symbolic variables; performing overlay analysis...",
                        current_rip
                    );
                    log!(
                        executor.state.logger,
                        " Possible panic function reference detected: entrying symbolic checks..."
                    );
                    let branch_target_varnode = inst.inputs[0].clone();
                    let branch_target_address = executor
                        .from_varnode_var_to_branch_address(&branch_target_varnode)
                        .map_err(|e| e.to_string())
                        .unwrap();
                    let conditional_flag = inst.inputs[1].clone();
                    let conditional_flag = executor
                        .varnode_to_concolic(&conditional_flag)
                        .map_err(|e| e.to_string())
                        .unwrap()
                        .to_concolic_var()
                        .unwrap();
                    let conditional_flag_u64 = conditional_flag.concrete.to_u64();

                    let address_of_negated_path_exploration = if conditional_flag_u64 == 0 {
                        // We want to explore the branch that is not taken
                        log!(executor.state.logger, ">>> Branch condition is false (0x{:x}), performing lightweight path analysis on the other branch...", conditional_flag_u64);

                        branch_target_address
                    } else {
                        // We want to explore the branch that is taken
                        log!(executor.state.logger, ">>> Branch condition is true (0x{:x}), performing lightweight path analysis on the other branch...", conditional_flag_u64);
                        let addr = next_addr_in_map;
                        *addr
                    };

                    // Check if internal p-code target
                    if is_internal_target {
                        log!(executor.state.logger, ">>> Internal p-code branch target detected; skipping overlay exploration.");
                    } else {
                        // Not an internal target - proceed with overlay exploration
                        log!(
                            executor.state.logger,
                            ">>> Real branch target (non-internal) with tracked symbolic variables - performing overlay exploration."
                        );

                        // Get compiler/language info for AST exploration decision later
                        let source_lang_inner =
                            env::var("SOURCE_LANG").unwrap_or_else(|_| "unknown".to_string());
                        let compiler_inner = env::var("COMPILER").unwrap_or_else(|_| String::new());

                        // CONCOLIC OVERLAY PATH ANALYSIS: Always perform for tracked symbolic variables
                        {
                            // CONCOLIC OVERLAY ANALYSIS: Full concolic execution with COW state
                            log!(
                                    executor.state.logger,
                                    ">>> Performing concolic overlay path analysis on negated path at 0x{:x}...",
                                    address_of_negated_path_exploration
                                );

                            let overlay_depth: usize = std::env::var("OVERLAY_DEPTH")
                                .ok()
                                .and_then(|v| v.parse().ok())
                                .unwrap_or(15);

                            // Overlay explores the opposite branch, so compute the
                            // corresponding gate and carry it during speculative
                            // execution. This keeps plugin path predicates coherent.
                            let cond_bv = conditional_flag.symbolic.to_bv(executor.context);
                            let branch_taken_to_explore = conditional_flag_u64 == 0;
                            let explored_condition = extract_underlying_condition_from_flag_ast(
                                &cond_bv,
                                branch_taken_to_explore,
                                &mut executor.state.logger.clone(),
                            );

                            let analysis_result = analyze_untaken_path_with_overlay(
                                executor,
                                address_of_negated_path_exploration,
                                instructions_map,
                                overlay_depth,
                                Some(explored_condition),
                            );

                            // Refresh coverage bar : overlay may have added new blocks
                            print_coverage_bar(
                                executor.visited_blocks.len(),
                                instructions_map.len(),
                                executor.start_time.elapsed().as_secs_f64(),
                                zorya::Z3_CUMULATIVE_MS.load(std::sync::atomic::Ordering::Relaxed),
                                executor.constraint_vector.len(),
                            );

                            match analysis_result {
                                OverlayPathAnalysisResult::VulnerabilityFound(
                                    _vuln_type,
                                    vuln_addr,
                                    _desc,
                                ) => {
                                    // Try to find a satisfying input
                                    let _ = evaluate_args_z3(
                                            executor,
                                            inst,
                                            Some(conditional_flag.clone()),
                                            Some(current_rip),
                                            Some(branch_target_address),
                                            Some(vuln_addr),
                                            None, // no NULL check for overlay vulnerabilities
                                        )
                                        .unwrap_or_else(|e| {
                                            log!(
                                                executor.state.logger,
                                                "Error evaluating arguments for vulnerability at 0x{:x}: {}",
                                                vuln_addr,
                                                e
                                            );
                                            false
                                        });
                                }
                                OverlayPathAnalysisResult::Safe => {
                                    log!(
                                            executor.state.logger,
                                            ">>> Concolic overlay analysis found no vulnerabilities in negated path"
                                        );
                                }
                                OverlayPathAnalysisResult::DepthLimitReached => {
                                    log!(
                                        executor.state.logger,
                                        ">>> Concolic overlay analysis reached depth limit"
                                    );
                                }
                                OverlayPathAnalysisResult::Error(e) => {
                                    log!(
                                        executor.state.logger,
                                        ">>> Concolic overlay analysis error: {}",
                                        e
                                    );
                                }
                            }
                        }

                        // AST EXPLORATION: For TinyGo and Go GC binaries (detect explicit panic calls)
                        let use_ast_exploration =
                            match (source_lang_inner.as_str(), compiler_inner.as_str()) {
                                ("go", _) => true, // All Go binaries
                                _ => false,        // C/C++ don't have panic infrastructure
                            };

                        let ast_panic_result = if use_ast_exploration {
                            log!(
                                executor.state.logger,
                                ">>> Performing AST-based panic exploration..."
                            );
                            explore_ast_for_panic(
                                executor,
                                address_of_negated_path_exploration,
                                binary_path,
                            )
                        } else {
                            log!(
                                executor.state.logger,
                                ">>> Skipping AST exploration (not applicable for this language/compiler)"
                        );
                            "NO_PANIC_XREF_FOUND".to_string()
                        };

                        if ast_panic_result.starts_with("FOUND_PANIC_XREF_AT 0x") {
                            if let Some(panic_addr_str) = ast_panic_result.split_whitespace().last()
                            {
                                if let Some(stripped) = panic_addr_str.strip_prefix("0x") {
                                    if let Ok(parsed_addr) = u64::from_str_radix(stripped, 16) {
                                        log!(executor.state.logger, ">>> The AST exploration found a potential call to a panic address at 0x{:x}", parsed_addr);
                                    } else {
                                        log!(
                                            executor.state.logger,
                                            "Could not parse panic address from AST result: '{}'",
                                            panic_addr_str
                                        );
                                    }
                                }
                            }

                            // Extract panic address from AST result
                            let panic_addr = if let Some(panic_addr_str) =
                                ast_panic_result.split_whitespace().last()
                            {
                                if let Some(stripped) = panic_addr_str.strip_prefix("0x") {
                                    u64::from_str_radix(stripped, 16).ok()
                                } else {
                                    None
                                }
                            } else {
                                None
                            };

                            // Run only a single evaluation once panic address is known
                            let _ = evaluate_args_z3(
                                executor,
                                inst,
                                Some(conditional_flag.clone()),
                                Some(current_rip),
                                Some(branch_target_address),
                                panic_addr,
                                None, // no NULL check for CBranch panics
                            )
                            .unwrap_or_else(|e| {
                                log!(
                                    executor.state.logger,
                                    "Error evaluating arguments for branch at 0x{:x}: {}",
                                    branch_target_address,
                                    e
                                );
                                false
                            });
                        } else {
                            log!(executor.state.logger, ">>> No panic function found in the AST exploration with the current max depth exploration");
                        }
                    }
                }
            }

            // Calculate the potential next address taken by RIP, for the purpose of updating the symbolic part of CBRANCH
            let (next_addr_in_map, _) = instructions_map.range((current_rip + 1)..).next().unwrap();

            // MAIN PART OF THE CODE
            // Execute the instruction and handle errors
            match executor.execute_instruction(
                inst.clone(),
                current_rip,
                *next_addr_in_map,
                instructions_map,
            ) {
                Ok(_) => {
                    // Check if the process has terminated
                    if executor.state.is_terminated {
                        log!(
                            executor.state.logger,
                            "Execution terminated with status: {:?}",
                            executor.state.exit_status
                        );
                        finalize_plugin_analysis(executor);
                        return; // Exit the function as execution has terminated
                    }
                }
                Err(e) => {
                    log!(executor.state.logger, "Execution error: {}", e);
                    if executor.state.is_terminated {
                        log!(
                            executor.state.logger,
                            "Process terminated via syscall with exit status: {:?}",
                            executor.state.exit_status
                        );
                        finalize_plugin_analysis(executor);
                        return; // Exit the function as execution has terminated
                    } else {
                        // Handle other errors as needed
                        log!(executor.state.logger, "Unhandled execution error: {}", e);
                        finalize_plugin_analysis(executor);
                        return; // Exit the function or handle the error appropriately
                    }
                }
            }

            // NOTE: Thread scheduling is performed once per x86 instruction at
            // the top of the outer loop (see the "Thread-scheduling checkpoint"
            // block above). It must NOT be done here, inside the pcode-micro-op
            // loop, because a switch between micro-ops of a single instruction
            // corrupts the incoming thread's registers.

            // For debugging
            //log!(executor.state.logger, "Printing memory content around 0x{:x} with range 0x{:x}", address, range);
            //executor.state.print_memory_content(address, range);
            if std::env::var("ZORYA_DUMP_REGS_EACH_INST")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false)
            {
                let register0x0 = executor
                    .state
                    .cpu_state
                    .lock()
                    .unwrap()
                    .get_register_by_offset(0x0, 64)
                    .unwrap();
                log!(
                    executor.state.logger,
                    "The value of register at offset 0x0 - RAX is {:x} and symbolic {}",
                    register0x0.concrete,
                    register0x0.symbolic.simplify().to_string()
                );
                let register0x8 = executor
                    .state
                    .cpu_state
                    .lock()
                    .unwrap()
                    .get_register_by_offset(0x8, 64)
                    .unwrap();
                log!(
                    executor.state.logger,
                    "The value of register at offset 0x8 - RCX is {:x} and symbolic {}",
                    register0x8.concrete,
                    register0x8.symbolic.simplify().to_string()
                );
                let register0x10 = executor
                    .state
                    .cpu_state
                    .lock()
                    .unwrap()
                    .get_register_by_offset(0x10, 64)
                    .unwrap();
                log!(
                    executor.state.logger,
                    "The value of register at offset 0x10 - RDX is {:x} and symbolic {}",
                    register0x10.concrete,
                    register0x10.symbolic.simplify().to_string()
                );
                let register0x18 = executor
                    .state
                    .cpu_state
                    .lock()
                    .unwrap()
                    .get_register_by_offset(0x18, 64)
                    .unwrap();
                log!(
                    executor.state.logger,
                    "The value of register at offset 0x18 - RBX is {:x} and symbolic {}",
                    register0x18.concrete,
                    register0x18.symbolic.simplify().to_string()
                );
                let register0x20 = executor
                    .state
                    .cpu_state
                    .lock()
                    .unwrap()
                    .get_register_by_offset(0x20, 64)
                    .unwrap();
                log!(
                    executor.state.logger,
                    "The value of register at offset 0x20 - RSP is {:x} and symbolic {}",
                    register0x20.concrete,
                    register0x20.symbolic.simplify().to_string()
                );
                let register0x28 = executor
                    .state
                    .cpu_state
                    .lock()
                    .unwrap()
                    .get_register_by_offset(0x28, 64)
                    .unwrap();
                log!(
                    executor.state.logger,
                    "The value of register at offset 0x28 - RBP is {:x} and symbolic {}",
                    register0x28.concrete,
                    register0x28.symbolic.simplify().to_string()
                );
                let register0x30 = executor
                    .state
                    .cpu_state
                    .lock()
                    .unwrap()
                    .get_register_by_offset(0x30, 64)
                    .unwrap();
                log!(
                    executor.state.logger,
                    "The value of register at offset 0x30 - RSI is {:x} and symbolic {}",
                    register0x30.concrete,
                    register0x30.symbolic.simplify().to_string()
                );
                let register0x38 = executor
                    .state
                    .cpu_state
                    .lock()
                    .unwrap()
                    .get_register_by_offset(0x38, 64)
                    .unwrap();
                log!(
                    executor.state.logger,
                    "The value of register at offset 0x38 - RDI is {:x} and symbolic {}",
                    register0x38.concrete,
                    register0x38.symbolic.simplify().to_string()
                );
                let register0x80 = executor
                    .state
                    .cpu_state
                    .lock()
                    .unwrap()
                    .get_register_by_offset(0x80, 64)
                    .unwrap();
                log!(
                    executor.state.logger,
                    "The value of register at offset 0x80 - R8 is {:x} and symbolic {}",
                    register0x80.concrete,
                    register0x80.symbolic.simplify().to_string()
                );
                let register0x88 = executor
                    .state
                    .cpu_state
                    .lock()
                    .unwrap()
                    .get_register_by_offset(0x88, 64)
                    .unwrap();
                log!(
                    executor.state.logger,
                    "The value of register at offset 0x88 - R9 is {:x} and symbolic {}",
                    register0x88.concrete,
                    register0x88.symbolic.simplify().to_string()
                );
                let register0x90 = executor
                    .state
                    .cpu_state
                    .lock()
                    .unwrap()
                    .get_register_by_offset(0x90, 64)
                    .unwrap();
                log!(
                    executor.state.logger,
                    "The value of register at offset 0x90 - R10 is {:x} and symbolic {}",
                    register0x90.concrete,
                    register0x90.symbolic.simplify().to_string()
                );
                let register0x98 = executor
                    .state
                    .cpu_state
                    .lock()
                    .unwrap()
                    .get_register_by_offset(0x98, 64)
                    .unwrap();
                log!(
                    executor.state.logger,
                    "The value of register at offset 0x98 - R11 is {:x} and symbolic {}",
                    register0x98.concrete,
                    register0x98.symbolic.simplify().to_string()
                );
                let register0xa0 = executor
                    .state
                    .cpu_state
                    .lock()
                    .unwrap()
                    .get_register_by_offset(0xa0, 64)
                    .unwrap();
                log!(
                    executor.state.logger,
                    "The value of register at offset 0xa0 - R12 is {:x} and symbolic {}",
                    register0xa0.concrete,
                    register0xa0.symbolic.simplify().to_string()
                );
                let register0xa8 = executor
                    .state
                    .cpu_state
                    .lock()
                    .unwrap()
                    .get_register_by_offset(0xa8, 64)
                    .unwrap();
                log!(
                    executor.state.logger,
                    "The value of register at offset 0xa8 - R13 is {:x} and symbolic {}",
                    register0xa8.concrete,
                    register0xa8.symbolic.simplify().to_string()
                );
                let register0xb0 = executor
                    .state
                    .cpu_state
                    .lock()
                    .unwrap()
                    .get_register_by_offset(0xb0, 64)
                    .unwrap();
                log!(
                    executor.state.logger,
                    "The value of register at offset 0xb0 - R14 is {:x} and symbolic {}",
                    register0xb0.concrete,
                    register0xb0.symbolic.simplify().to_string()
                );
                let register0xb8 = executor
                    .state
                    .cpu_state
                    .lock()
                    .unwrap()
                    .get_register_by_offset(0xb8, 64)
                    .unwrap();
                log!(
                    executor.state.logger,
                    "The value of register at offset 0xb8 - R15 is {:x} and symbolic {}",
                    register0xb8.concrete,
                    register0xb8.symbolic.simplify().to_string()
                );
                let register0x1200 = executor
                    .state
                    .cpu_state
                    .lock()
                    .unwrap()
                    .get_register_by_offset(0x1200, 256)
                    .unwrap();
                log!(
                    executor.state.logger,
                    "The value of register at offset 0x1200 - YMM0 is {:x}, i.e. {:?}",
                    register0x1200.concrete,
                    register0x1200.concrete
                );
                let register0x1220 = executor
                    .state
                    .cpu_state
                    .lock()
                    .unwrap()
                    .get_register_by_offset(0x1220, 256)
                    .unwrap();
                log!(
                    executor.state.logger,
                    "The value of register at offset 0x1220 - YMM1 is {:x}, i.e. {:?}",
                    register0x1220.concrete,
                    register0x1220.concrete
                );
                let register0x200 = executor
                    .state
                    .cpu_state
                    .lock()
                    .unwrap()
                    .get_register_by_offset(0x200, 64)
                    .unwrap();
                log!(
                    executor.state.logger,
                    "The value of register at offset 0x200 - CF is {:x} and symbolic {}",
                    register0x200.concrete,
                    register0x200.symbolic.simplify().to_string()
                );
                let register0x202 = executor
                    .state
                    .cpu_state
                    .lock()
                    .unwrap()
                    .get_register_by_offset(0x202, 64)
                    .unwrap();
                log!(
                    executor.state.logger,
                    "The value of register at offset 0x202 - PF is {:x} and symbolic {}",
                    register0x202.concrete,
                    register0x202.symbolic.simplify().to_string()
                );
                let register0x206 = executor
                    .state
                    .cpu_state
                    .lock()
                    .unwrap()
                    .get_register_by_offset(0x206, 64)
                    .unwrap();
                log!(
                    executor.state.logger,
                    "The value of register at offset 0x206 - ZF is {:x} and symbolic {}",
                    register0x206.concrete,
                    register0x206.symbolic.simplify().to_string()
                );
                let register0x207 = executor
                    .state
                    .cpu_state
                    .lock()
                    .unwrap()
                    .get_register_by_offset(0x207, 64)
                    .unwrap();
                log!(
                    executor.state.logger,
                    "The value of register at offset 0x207 - SF is {:x} and symbolic {}",
                    register0x207.concrete,
                    register0x207.symbolic.simplify().to_string()
                );
                let register0x20b = executor
                    .state
                    .cpu_state
                    .lock()
                    .unwrap()
                    .get_register_by_offset(0x20b, 64)
                    .unwrap();
                log!(
                    executor.state.logger,
                    "The value of register at offset 0x20b - OF is {:x} and symbolic {}",
                    register0x20b.concrete,
                    register0x20b.symbolic.simplify().to_string()
                );
                let register0x110 = executor
                    .state
                    .cpu_state
                    .lock()
                    .unwrap()
                    .get_register_by_offset(0x110, 64)
                    .unwrap();
                log!(
                    executor.state.logger,
                    "The value of register at offset 0x110 - FS_OFFSET is {:x}",
                    register0x110.concrete
                );
            }

            // Check if there's a requested jump within the current block
            if executor.pcode_internal_lines_to_be_jumped != 0 {
                let proposed_jump_target =
                    local_line_number + executor.pcode_internal_lines_to_be_jumped;
                // Ensure the jump target does not exceed the bounds of the instruction list
                let jump_target = if proposed_jump_target < instructions.len().try_into().unwrap() {
                    proposed_jump_target
                } else {
                    (instructions.len() - 1).try_into().unwrap() // set to the last valid index if the calculated target is too high
                };

                log!(
                    executor.state.logger,
                    "Jumping from line {} to line {}",
                    local_line_number,
                    jump_target
                );
                executor.pcode_internal_lines_to_be_jumped = 0; // Reset after handling
                local_line_number = jump_target; // Perform the jump within the block
                continue; // Move directly to the jump target line
            }

            // Update RIP if the instruction modifies it
            let possible_new_rip = executor
                .state
                .cpu_state
                .lock()
                .unwrap()
                .get_register_by_offset(0x288, 64)
                .unwrap()
                .get_concrete_value()
                .unwrap();
            let possible_new_rip_hex = format!("{:x}", possible_new_rip);
            log!(
                executor.state.logger,
                "Possible new RIP: 0x{:x}",
                possible_new_rip
            );
            log!(executor.state.logger, "Current RIP: 0x{:x}", current_rip);
            log!(
                executor.state.logger,
                "local_line_number: {}, instructions.len()-1: {}",
                local_line_number,
                (instructions.len() - 1) as i64
            );

            // Check if there is a new RIP to set, beeing aware that all the instructions in the block have been executed, except for case with CBranch
            // FYI, the two blocks can not be put in a function because the varibales that are modified are not global, TODO: optimize this
            if inst.opcode == Opcode::CBranch {
                if possible_new_rip != current_rip {
                    log!(
                        executor.state.logger,
                        "Control flow change detected, new RIP: 0x{:x}",
                        possible_new_rip
                    );
                    if let Some(symbol_name_potential_new_rip) =
                        executor.symbol_table.get(&possible_new_rip_hex)
                    {
                        // Found a symbol, check if it's blacklisted, etc.
                        if IGNORED_TINYGO_FUNCS.contains(&symbol_name_potential_new_rip.as_str()) {
                            log!(
                                executor.state.logger,
                                "Skipping function '{:?}' at 0x{:x} because it is blacklisted.",
                                symbol_name_potential_new_rip,
                                current_rip
                            );

                            // When skipping a function, we need to update the stack pointer i.e. add 8 to RSP
                            let rsp_value_concrete = executor
                                .state
                                .cpu_state
                                .lock()
                                .unwrap()
                                .get_register_by_offset(0x20, 64)
                                .unwrap()
                                .concrete
                                .to_u64();
                            let rsp_value_symbolic = executor
                                .state
                                .cpu_state
                                .lock()
                                .unwrap()
                                .get_register_by_offset(0x20, 64)
                                .unwrap()
                                .symbolic
                                .to_bv(executor.context)
                                .clone();
                            let next_rsp_value_concrete = rsp_value_concrete + 8;
                            let next_rsp_value_symbolic =
                                rsp_value_symbolic.bvadd(&BV::from_u64(executor.context, 8, 64));
                            let next_rsp_value = ConcolicVar::new_concrete_and_symbolic_int(
                                next_rsp_value_concrete,
                                next_rsp_value_symbolic,
                                executor.context,
                            );
                            executor
                                .state
                                .cpu_state
                                .lock()
                                .unwrap()
                                .set_register_value_by_offset(0x20, next_rsp_value, 64)
                                .expect("Failed to set register value by offset");

                            let (next_addr_in_map, _) =
                                instructions_map.range((current_rip + 1)..).next().unwrap();
                            current_rip = *next_addr_in_map;
                            local_line_number = 0; // Reset instruction index
                            end_of_block = true; // Indicate end of current block execution
                            log!(executor.state.logger, "Jumping to 0x{:x}", next_addr_in_map);
                        } else {
                            // Manage the case where the RIP update points beyond the current block
                            current_rip = possible_new_rip;
                            local_line_number = 0; // Reset instruction index for new RIP
                            end_of_block = true; // Indicate end of current block execution
                            log!(executor.state.logger, "Control flow change detected, switching execution to new address: 0x{:x}", current_rip);
                        }
                    } else {
                        // Manage the case where the RIP update points beyond the current block
                        current_rip = possible_new_rip;
                        local_line_number = 0; // Reset instruction index for new RIP
                        end_of_block = true; // Indicate end of current block execution
                        log!(executor.state.logger, "Control flow change detected, switching execution to new address: 0x{:x}", current_rip);
                    }
                } else {
                    // Regular progression to the next instruction
                    local_line_number += 1;
                }
            } else if possible_new_rip != current_rip
                && local_line_number >= (instructions.len() - 1).try_into().unwrap()
            {
                log!(
                    executor.state.logger,
                    "local_line_number: {}, instructions.len()-1: {}",
                    local_line_number,
                    (instructions.len() - 1) as i64
                );
                log!(
                    executor.state.logger,
                    "Control flow change detected, new RIP: 0x{:x}",
                    possible_new_rip
                );
                if let Some(symbol_name_potential_new_rip) =
                    executor.symbol_table.get(&possible_new_rip_hex)
                {
                    // Found a symbol, check if it's blacklisted, etc.
                    if IGNORED_TINYGO_FUNCS.contains(&symbol_name_potential_new_rip.as_str()) {
                        log!(
                            executor.state.logger,
                            "Skipping function '{:?}' at 0x{:x} because it is blacklisted.",
                            symbol_name_potential_new_rip,
                            current_rip
                        );

                        // When skipping a function, we need to update the stack pointer i.e. add 8 to RSP
                        let rsp_value_concrete = executor
                            .state
                            .cpu_state
                            .lock()
                            .unwrap()
                            .get_register_by_offset(0x20, 64)
                            .unwrap()
                            .concrete
                            .to_u64();
                        let rsp_value_symbolic = executor
                            .state
                            .cpu_state
                            .lock()
                            .unwrap()
                            .get_register_by_offset(0x20, 64)
                            .unwrap()
                            .symbolic
                            .to_bv(executor.context)
                            .clone();
                        let next_rsp_value_concrete = rsp_value_concrete + 8;
                        let next_rsp_value_symbolic =
                            rsp_value_symbolic.bvadd(&BV::from_u64(executor.context, 8, 64));
                        let next_rsp_value = ConcolicVar::new_concrete_and_symbolic_int(
                            next_rsp_value_concrete,
                            next_rsp_value_symbolic,
                            executor.context,
                        );
                        executor
                            .state
                            .cpu_state
                            .lock()
                            .unwrap()
                            .set_register_value_by_offset(0x20, next_rsp_value, 64)
                            .expect("Failed to set register value by offset");

                        let (next_addr_in_map, _) =
                            instructions_map.range((current_rip + 1)..).next().unwrap();
                        current_rip = *next_addr_in_map;
                        local_line_number = 0; // Reset instruction index
                        end_of_block = true; // Indicate end of current block execution
                        log!(executor.state.logger, "Jumping to 0x{:x}", next_addr_in_map);
                    } else {
                        // Manage the case where the RIP update points beyond the current block
                        current_rip = possible_new_rip;
                        local_line_number = 0; // Reset instruction index for new RIP
                        end_of_block = true; // Indicate end of current block execution
                        log!(executor.state.logger, "Control flow change detected, switching execution to new address: 0x{:x}", current_rip);
                    }
                } else {
                    // Manage the case where the RIP update points beyond the current block
                    current_rip = possible_new_rip;
                    local_line_number = 0; // Reset instruction index for new RIP
                    end_of_block = true; // Indicate end of current block execution
                    log!(
                        executor.state.logger,
                        "Control flow change detected, switching execution to new address: 0x{:x}",
                        current_rip
                    );
                }
            } else {
                // Regular progression to the next instruction
                local_line_number += 1;
            }
        }

        // Reset for new block or continue execution at new RIP if set within the block
        if !end_of_block {
            if let Some((&next_rip, _)) = instructions_map.range((current_rip + 1)..).next() {
                let next_rip_hex = format!("{:x}", next_rip);
                if let Some(symbol_name_new_rip) = executor.symbol_table.get(&next_rip_hex) {
                    // Found a symbol, check if it's blacklisted
                    if IGNORED_TINYGO_FUNCS.contains(&symbol_name_new_rip.as_str()) {
                        log!(
                            executor.state.logger,
                            "Skipping function '{:?}' at 0x{:x} because it is blacklisted.",
                            symbol_name_new_rip,
                            current_rip
                        );

                        // When skipping a function, we need to update the stack pointer i.e. add 8 to RSP
                        let rsp_value_concrete = executor
                            .state
                            .cpu_state
                            .lock()
                            .unwrap()
                            .get_register_by_offset(0x20, 64)
                            .unwrap()
                            .concrete
                            .to_u64();
                        let rsp_value_symbolic = executor
                            .state
                            .cpu_state
                            .lock()
                            .unwrap()
                            .get_register_by_offset(0x20, 64)
                            .unwrap()
                            .symbolic
                            .to_bv(executor.context)
                            .clone();
                        let next_rsp_value_concrete = rsp_value_concrete + 8;
                        let next_rsp_value_symbolic =
                            rsp_value_symbolic.bvadd(&BV::from_u64(executor.context, 8, 64));
                        let next_rsp_value = ConcolicVar::new_concrete_and_symbolic_int(
                            next_rsp_value_concrete,
                            next_rsp_value_symbolic,
                            executor.context,
                        );
                        executor
                            .state
                            .cpu_state
                            .lock()
                            .unwrap()
                            .set_register_value_by_offset(0x20, next_rsp_value, 64)
                            .expect("Failed to set register value by offset");

                        let (next_addr_in_map, _) =
                            instructions_map.range((current_rip + 1)..).next().unwrap();
                        current_rip = *next_addr_in_map;
                        local_line_number = 0; // Reset instruction index
                        log!(executor.state.logger, "Jumping to 0x{:x}", next_addr_in_map);
                    }
                } else {
                    current_rip = next_rip;
                    local_line_number = 0; // Reset for new block

                    let current_rip_symbolic = executor
                        .state
                        .cpu_state
                        .lock()
                        .unwrap()
                        .get_register_by_offset(0x288, 64)
                        .unwrap()
                        .symbolic
                        .to_bv(executor.context)
                        .clone();

                    let next_rip_concolic = ConcolicVar::new_concrete_and_symbolic_int(
                        next_rip,
                        current_rip_symbolic,
                        executor.context,
                    );
                    executor
                        .state
                        .cpu_state
                        .lock()
                        .unwrap()
                        .set_register_value_by_offset(0x288, next_rip_concolic, 64)
                        .expect("Failed to set register value by offset");

                    log!(
                        executor.state.logger,
                        "Moving to next address block: 0x{:x}",
                        next_rip
                    );
                }
            } else {
                log!(
                    executor.state.logger,
                    "No further instructions. Execution completed."
                );
                break; // Exit the loop if there are no more instructions
            }
        }
    }
    log!(
        executor.state.logger,
        "Panic gating stats: gated_by_reach={}, allowed_by_xref_fallback={}",
        get_gated_by_reach(),
        get_allowed_by_xref_fallback()
    );
    // Note: addresses with no lifted pcode (PLT stubs such as pthread_create /
    // pthread_join, the thread-exit sentinel, or unresolved libc targets) are
    // handled inside the loop by `ConcolicExecutor::handle_external_boundary`,
    // which spawns threads, satisfies joins, or yields to other ready threads.
    // Reaching this point means the loop hit a genuine `break`
    // (`is_terminated`, end address, or no runnable work remaining).
    finalize_plugin_analysis(executor);
}

// Function to initialize the symbolic part of os.Args
pub fn initialize_symbolic_part_args(
    executor: &mut ConcolicExecutor,
    args_addr: u64,
) -> Result<(), Box<dyn Error>> {
    // Read os.Args slice header (Pointer, Len, Cap)
    let mem = &executor.state.memory;
    let slice_ptr = mem
        .read_u64(args_addr, &mut executor.state.logger.clone())?
        .concrete
        .to_u64(); // Pointer to backing array
    let slice_len = mem
        .read_u64(args_addr + 8, &mut executor.state.logger.clone())?
        .concrete
        .to_u64(); // Length (number of arguments)
    let _slice_cap = mem
        .read_u64(args_addr + 16, &mut executor.state.logger.clone())?
        .concrete
        .to_u64(); // Capacity (not used)

    log!(
        executor.state.logger,
        "os.Args -> ptr=0x{:?}, len={}, cap={}",
        slice_ptr,
        slice_len,
        _slice_cap
    );

    // Iterate through each argument
    for i in 0..slice_len {
        let string_struct_addr = slice_ptr + i * 16; // Each Go string struct is 16 bytes
        let str_data_ptr = mem
            .read_u64(string_struct_addr, &mut executor.state.logger.clone())?
            .concrete
            .to_u64(); // Pointer to actual string data
        let str_data_len = mem
            .read_u64(string_struct_addr + 8, &mut executor.state.logger.clone())?
            .concrete
            .to_u64(); // Length of the string

        log!(
            executor.state.logger,
            "os.Args[{}] -> string ptr=0x{:x}, len={}",
            i,
            str_data_ptr,
            str_data_len
        );

        if str_data_ptr == 0 || str_data_len == 0 {
            // Possibly an empty argument? Just skip or handle specially
            continue;
        }

        // Read the actual string bytes
        let concrete_str_bytes = mem.read_bytes(str_data_ptr, str_data_len as usize)?;

        // Create fresh symbolic variables for each byte of this argument
        let mut fresh_symbolic = Vec::with_capacity(str_data_len as usize);
        for (byte_index, _) in concrete_str_bytes.iter().enumerate() {
            let bv_name = format!("arg{}_byte_{}", i, byte_index);
            let fresh_bv = BV::fresh_const(executor.context, &bv_name, 8);
            // Register this symbolic byte so negated-path detection can recognize it
            executor
                .function_symbolic_arguments
                .insert(bv_name.clone(), SymbolicVar::Int(fresh_bv.clone()));
            fresh_symbolic.push(Some(Rc::new(fresh_bv)));
        }

        // Write those symbolic values back into memory
        mem.write_memory(str_data_ptr, &concrete_str_bytes, &fresh_symbolic)?;

        log!(
            executor.state.logger,
            "Successfully replaced os.Args[{}] with {} symbolic bytes.",
            i,
            str_data_len
        );
    }

    Ok(())
}

// Function to execute the Python script to get the cross references of potential panics in the programs (for bug detetcion)
fn get_cross_references(binary_path: &str) -> Result<(), Box<dyn Error>> {
    let zorya_dir = {
        let info = GLOBAL_TARGET_INFO.lock().unwrap();
        info.zorya_path.clone()
    };
    let python_script_path = zorya_dir.join("scripts").join("find_panic_xrefs.py");

    if !python_script_path.exists() {
        panic!("Python script not found at {:?}", python_script_path);
    }

    tprintln!("[GHIDRA] Launching Ghidra + Pyhidra to collect panic cross-references (this may take a bit)...");

    let output = Command::new("python3")
        .arg(python_script_path)
        .arg(binary_path)
        .output()
        .expect("Failed to execute Python script");

    // Check if the script ran successfully
    if !output.status.success() {
        teprintln!(
            "[WARNING]: Python script error: {}\n",
            String::from_utf8_lossy(&output.stderr)
        );
        return Err(Box::from("Python script failed"));
    } else {
        tprintln!("[GHIDRA] Panic cross-reference analysis completed. Results written to results/xref_addresses.txt.\n");
    }

    // Ensure the file was created
    if !Path::new("results/xref_addresses.txt").exists() {
        panic!("[ERROR]: xref_addresses.txt not found after running the Python script\n");
    }

    Ok(())
}

// Function to preprocess the p-code file and return a map of addresses to instructions
fn preprocess_pcode_file(
    path: &str,
    executor: &mut ConcolicExecutor,
) -> io::Result<BTreeMap<u64, Vec<Inst>>> {
    let file = File::open(path)?;
    let reader = io::BufReader::new(file);
    let mut instructions_map = BTreeMap::new();
    let mut current_address: Option<u64> = None;

    log!(executor.state.logger, "Preprocessing the p-code file...");

    for line in reader.lines().map_while(Result::ok) {
        if line.trim_start().starts_with("0x") {
            current_address = Some(u64::from_str_radix(&line.trim()[2..], 16).unwrap());
            instructions_map
                .entry(current_address.unwrap())
                .or_insert_with(Vec::new);
        } else {
            match line.parse::<Inst>() {
                Ok(inst) => {
                    if let Some(addr) = current_address {
                        instructions_map.get_mut(&addr).unwrap().push(inst);
                    } else {
                        log!(
                            executor.state.logger,
                            "Instruction found without a preceding address: {}",
                            line
                        );
                    }
                }
                Err(e) => {
                    log!(
                        executor.state.logger,
                        "Error parsing line at address 0x{:x}: {}\nError: {}",
                        current_address.unwrap_or(0),
                        line,
                        e
                    );
                    return Err(io::Error::other(format!(
                        "Error parsing line at address 0x{:x}: {}\nError: {}",
                        current_address.unwrap_or(0),
                        line,
                        e
                    )));
                }
            }
        }
    }

    log!(executor.state.logger, "Completed preprocessing.\n");

    Ok(instructions_map)
}

// Function to merge VDSO p-code into the main instructions map
fn merge_vdso_pcode(
    instructions_map: &mut BTreeMap<u64, Vec<Inst>>,
    executor: &mut ConcolicExecutor,
) {
    let zorya_path = env::var("ZORYA_DIR").expect("ZORYA_DIR environment variable is not set");
    let vdso_pcode_path = Path::new(&zorya_path)
        .join("results")
        .join("initialization_data")
        .join("vdso")
        .join("vdso_low_pcode.txt");

    // Check if VDSO p-code file exists
    if !vdso_pcode_path.exists() {
        log!(
            executor.state.logger,
            "[WARNING]: VDSO p-code file not found, skipping VDSO merge: {:?}\n",
            vdso_pcode_path
        );
        return;
    }

    log!(
        executor.state.logger,
        "Merging VDSO p-code from: {:?}\n",
        vdso_pcode_path
    );

    // Parse VDSO p-code file
    match preprocess_pcode_file(
        vdso_pcode_path.to_str().expect("Invalid VDSO p-code path"),
        executor,
    ) {
        Ok(vdso_map) => {
            let vdso_instr_count = vdso_map.len();
            // Merge VDSO instructions into main map
            for (addr, insts) in vdso_map {
                instructions_map.insert(addr, insts);
            }
            log!(
                executor.state.logger,
                "Successfully merged {} VDSO instruction blocks\n",
                vdso_instr_count
            );
            tprintln!(
                "Merged {} VDSO instruction blocks into execution map\n",
                vdso_instr_count
            );
        }
        Err(e) => {
            log!(
                executor.state.logger,
                "Failed to parse VDSO p-code: {}\n",
                e
            );
            teprintln!("[WARNING]: Failed to merge VDSO p-code: {}\n", e);
        }
    }
}

// Function to read the panic addresses from the file
// Function to add the arguments of the target binary from the user's command
fn update_argc_argv(
    executor: &mut ConcolicExecutor,
    arguments: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let cpu_state_guard = executor.state.cpu_state.lock().unwrap();

    if arguments == "none" {
        return Ok(());
    }

    // Parse arguments
    let args: Vec<String> = shell_words::split(arguments)?;
    let argc = args.len() as u64;

    log!(executor.state.logger, "Symbolically setting argc: {}", argc);

    let rsp = cpu_state_guard
        .get_register_by_offset(0x20, 64)
        .unwrap()
        .concrete
        .to_u64();

    // Write argc (concrete)
    executor.state.memory.write_value(
        rsp,
        &MemoryValue::new(argc, BV::from_u64(executor.context, argc, 64), 64),
    )?;

    let argv_ptr_base = rsp + 8;
    let mut current_string_address = argv_ptr_base + (argc + 1) * 8;

    for (i, arg) in args.iter().enumerate() {
        // Write argv[i] pointer
        executor.state.memory.write_value(
            argv_ptr_base + (i as u64 * 8),
            &MemoryValue::new(
                current_string_address,
                BV::from_u64(executor.context, current_string_address, 64),
                64,
            ),
        )?;

        log!(
            executor.state.logger,
            "Set argv[{}] pointer at: 0x{:x}",
            i,
            current_string_address
        );

        let arg_bytes = arg.as_bytes();

        for offset in 0..arg_bytes.len() {
            let sym_byte =
                BV::fresh_const(executor.context, &format!("arg{}_byte{}", i, offset), 8);

            // Add ASCII constraints for printable characters (32-126)
            let printable_min = BV::from_u64(executor.context, 32, 8);
            let printable_max = BV::from_u64(executor.context, 126, 8);
            let ascii_constraint = sym_byte.bvuge(&printable_min) & sym_byte.bvule(&printable_max);
            executor.solver.assert(&ascii_constraint);

            executor.state.memory.write_value(
                current_string_address + offset as u64,
                &MemoryValue::new(0, sym_byte.clone(), 8),
            )?;
        }

        // NULL terminator
        executor.state.memory.write_value(
            current_string_address + arg_bytes.len() as u64,
            &MemoryValue::new(0, BV::from_u64(executor.context, 0, 8), 8),
        )?;

        current_string_address += ((arg_bytes.len() + 8) as u64) & !7; // align to 8 bytes
    }

    // Write argv NULL terminator pointer
    executor.state.memory.write_value(
        argv_ptr_base + argc * 8,
        &MemoryValue::new(0, BV::from_u64(executor.context, 0, 64), 64),
    )?;

    Ok(())
}

/// Set up `argc`/`argv` for a C/C++ binary stopped at the user `main`.
///
/// Unlike [`update_argc_argv`], which reconstructs the kernel `_start` stack
/// layout at `rsp+8`, a binary halted at `main` has already gone through libc
/// startup and reads its parameters from the System V argument registers:
/// `RDI = argc`, `RSI = argv`. This function:
///
///   1. Allocates a fresh private/anonymous R/W region for the `argv` pointer
///      array plus the NUL-terminated argument strings.
///   2. Writes `argv[0]` (the program name) as concrete bytes and every
///      *user-supplied* argument as fresh symbolic bytes (printable-ASCII
///      bounded), registering each byte so negated-path exploration and the
///      path condition pick them up.
///   3. Points `RDI`/`RSI` at the freshly built vector.
///
/// The symbolic argument bytes are what let input-dependent branches (e.g.
/// `if (argv[1][0] == 'K')`) surface in the path condition, which downstream
/// plugins such as `volos` use to classify input-gated concurrency bugs.
fn setup_c_main_args(
    executor: &mut ConcolicExecutor,
    arguments: &str,
    binary_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // argv[0] = program name (concrete); user arguments follow and are symbolic.
    let mut argv: Vec<String> = vec![binary_path.to_string()];
    if arguments != "none" {
        argv.extend(shell_words::split(arguments)?);
    }
    let argc = argv.len() as u64;

    // Allocate a private, anonymous, read/write region for the pointer array
    // followed by the argument strings.
    const PROT_RW: i32 = 0x1 | 0x2; // PROT_READ | PROT_WRITE
    const MAP_PRIVATE_ANON: i32 = 0x2 | 0x20; // MAP_PRIVATE | MAP_ANONYMOUS
    const ARGV_REGION_SIZE: usize = 0x1000; // 4 KiB is ample for argv + strings
    let ptr_array_base = executor
        .state
        .memory
        .mmap(0, ARGV_REGION_SIZE, PROT_RW, MAP_PRIVATE_ANON, -1, 0)
        .map_err(|e| format!("setup_c_main_args: argv mmap failed: {:?}", e))?;

    // Strings start right after the pointer array (argc entries + NULL term).
    let mut cursor = ptr_array_base + (argc + 1) * 8;

    for (i, arg) in argv.iter().enumerate() {
        // argv[i] pointer -> current string address (concrete).
        executor.state.memory.write_value(
            ptr_array_base + (i as u64) * 8,
            &MemoryValue::new(cursor, BV::from_u64(executor.context, cursor, 64), 64),
        )?;

        let bytes = arg.as_bytes();
        for (off, &b) in bytes.iter().enumerate() {
            let mv = if i == 0 {
                // Program name: keep concrete.
                MemoryValue::new(b as u64, BV::from_u64(executor.context, b as u64, 8), 8)
            } else {
                // User argument byte: fresh symbolic with printable-ASCII bound.
                let name = format!("arg{}_byte{}", i, off);
                let sym = BV::fresh_const(executor.context, &name, 8);
                let lo = BV::from_u64(executor.context, 32, 8);
                let hi = BV::from_u64(executor.context, 126, 8);
                executor.solver.assert(&(sym.bvuge(&lo) & sym.bvule(&hi)));
                executor
                    .function_symbolic_arguments
                    .insert(name, SymbolicVar::Int(sym.clone()));
                MemoryValue::new(b as u64, sym, 8)
            };
            executor
                .state
                .memory
                .write_value(cursor + off as u64, &mv)?;
        }
        // NUL terminator (concrete).
        executor.state.memory.write_value(
            cursor + bytes.len() as u64,
            &MemoryValue::new(0, BV::from_u64(executor.context, 0, 8), 8),
        )?;

        // Advance the cursor past the string + NUL, 8-byte aligned.
        cursor = (cursor + bytes.len() as u64 + 1 + 7) & !7u64;
    }

    // argv[argc] = NULL.
    executor.state.memory.write_value(
        ptr_array_base + argc * 8,
        &MemoryValue::new(0, BV::from_u64(executor.context, 0, 64), 64),
    )?;

    // Point the SysV argument registers at the freshly built vector:
    //   RDI (offset 0x38) = argc, RSI (offset 0x30) = argv.
    {
        let mut cpu = executor.state.cpu_state.lock().unwrap();
        let argc_cv = ConcolicVar::new_concrete_and_symbolic_int(
            argc,
            BV::from_u64(executor.context, argc, 64),
            executor.context,
        );
        cpu.set_register_value_by_offset(0x38, argc_cv, 64)
            .map_err(|e| format!("setup_c_main_args: set RDI failed: {}", e))?;
        let argv_cv = ConcolicVar::new_concrete_and_symbolic_int(
            ptr_array_base,
            BV::from_u64(executor.context, ptr_array_base, 64),
            executor.context,
        );
        cpu.set_register_value_by_offset(0x30, argv_cv, 64)
            .map_err(|e| format!("setup_c_main_args: set RSI failed: {}", e))?;
    }

    log!(
        executor.state.logger,
        "C argv set up at 0x{:x}: argc={} ({} symbolic argument(s))",
        ptr_array_base,
        argc,
        argc.saturating_sub(1)
    );

    Ok(())
}
