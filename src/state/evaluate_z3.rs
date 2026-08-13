// SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

use std::io::Write;
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use std::{error::Error, process::Command};

// use super::explore_ast::explore_ast_for_panic;  // Removed to avoid duplication
use crate::concolic::{ConcolicExecutor, ConcolicVar, SymbolicVar};
/// Write SAT state details to file and log to terminal
use crate::state::gating_stats::{get_allowed_by_xref_fallback, get_gated_by_reach};
use crate::state::simplify_z3::add_constraints_from_vector;
use crate::target_info::GLOBAL_TARGET_INFO;
use crate::tprintln;

use chrono::{DateTime, Utc};
use parser::parser::{Inst, Opcode};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs::OpenOptions;
use std::path::Path;
use z3::ast::{Ast, Int};
use z3::SatResult;

macro_rules! log {
    ($logger:expr, $($arg:tt)*) => {{
        if ($logger).is_enabled() {
        writeln!($logger, $($arg)*).unwrap();
        }
    }};
}

// Global timer to measure elapsed time until first SAT state is found
static START_INSTANT: OnceLock<Instant> = OnceLock::new();
static INVOCATION_CMDLINE: OnceLock<String> = OnceLock::new();

/// Initialize the global SAT timer start. Safe to call multiple times; only first wins.
pub fn init_sat_timer_start() {
    let _ = START_INSTANT.set(Instant::now());
}

/// Get elapsed time since Zorya started (for consistent vulnerability reporting)
pub fn get_elapsed_since_start() -> Duration {
    START_INSTANT
        .get()
        .map(|s| s.elapsed())
        .unwrap_or_else(|| Duration::from_secs(0))
}

/// Unified vulnerability reporting — writes the same formatted block to both
/// the log file and to stdout so that every vulnerability looks identical
/// regardless of where it was detected (concrete path, overlay execution, CBRANCH, etc.).
pub fn report_vulnerability(
    logger: &mut crate::state::state_manager::Logger,
    vuln_type: &str,
    address: u64,
    details: &[&str],
) {
    let bar = "========================================================================";
    let elapsed = get_elapsed_since_start();
    let elapsed_str = format!("{:.3}s", elapsed.as_secs_f64());

    // -- log file --
    log!(logger, "{}", bar);
    log!(logger, "BUG / VULNERABILITY: {}", vuln_type);
    log!(logger, "  Address: 0x{:x}", address);
    log!(logger, "  Elapsed: {}", elapsed_str);
    for line in details {
        log!(logger, "  {}", line);
    }
    log!(logger, "{}\n", bar);

    // -- terminal (stdout) --
    tprintln!();
    tprintln!("{}", bar);
    tprintln!("BUG / VULNERABILITY: {}", vuln_type);
    tprintln!("  Address: 0x{:x}", address);
    tprintln!("  Elapsed: {}", elapsed_str);
    for line in details {
        tprintln!("  {}", line);
    }
    tprintln!("{}", bar);
    tprintln!();
}

/// Log a bug found on the overlay concolic path to both FOUND_SAT_STATE.txt and terminal.
/// Used when the pointer is concretely NULL during overlay execution. The Z3 CBRANCH check
/// that follows will determine the triggering input values.
pub fn log_vuln_to_file_and_terminal(
    logger: &mut crate::state::state_manager::Logger,
    vuln_type: &str,
    address: u64,
    opcode_str: &str,
    description: &str,
    pointer_name: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let elapsed = get_elapsed_since_start();
    let mode = std::env::var("MODE").unwrap_or_else(|_| "unknown".to_string());

    // --- Terminal report ---
    let bar = "========================================================================";
    let elapsed_str = format!("{:.3}s", elapsed.as_secs_f64());

    log!(logger, "{}", bar);
    log!(
        logger,
        "BUG / VULNERABILITY (overlay concolic path): {}",
        vuln_type
    );
    log!(logger, "  Crash address: 0x{:x}", address);
    log!(logger, "  Elapsed: {}", elapsed_str);
    log!(logger, "  Opcode: {}", opcode_str);
    log!(logger, "  {}", description);
    log!(
        logger,
        "  (Z3 solver will now determine the triggering input, see CBRANCH analysis)"
    );
    log!(logger, "  More details in: results/FOUND_SAT_STATE.txt");
    log!(logger, "{}\n", bar);

    tprintln!();
    tprintln!("{}", bar);
    tprintln!("BUG / VULNERABILITY (overlay concolic path): {}", vuln_type);
    tprintln!("  Crash address: 0x{:x}", address);
    tprintln!("  Elapsed: {}", elapsed_str);
    tprintln!("  Opcode: {}", opcode_str);
    tprintln!("  {}", description);
    tprintln!("  (Z3 solver will now determine the triggering input, see CBRANCH analysis)");
    tprintln!("  More details in: results/FOUND_SAT_STATE.txt");
    tprintln!("{}", bar);
    tprintln!();

    // --- File report (FOUND_SAT_STATE.txt) ---
    std::fs::create_dir_all("results")?;

    let file_path = "results/FOUND_SAT_STATE.txt";
    let file_exists = Path::new(file_path).exists();

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(file_path)?;

    let timestamp: DateTime<Utc> = Utc::now();
    let timestamp_str = timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string();

    if file_exists {
        writeln!(file, "\n{}", "=".repeat(80))?;
    }

    if let Some(inv) = INVOCATION_CMDLINE.get() {
        writeln!(file, "Running command: {}", inv)?;
    }
    writeln!(
        file,
        "[*] BUG DETECTED (overlay concolic path, not the concrete execution)"
    )?;
    writeln!(file, "Timestamp: {}", timestamp_str)?;
    writeln!(file, "Mode: {}", mode)?;
    writeln!(
        file,
        "Elapsed since start: {}.{:03}s",
        elapsed.as_secs(),
        elapsed.subsec_millis()
    )?;
    writeln!(file, "Crash Address: 0x{:x}", address)?;
    writeln!(file, "{}", "-".repeat(60))?;
    writeln!(file, "Bug: {}", vuln_type)?;
    writeln!(file, "Opcode: {}", opcode_str)?;
    writeln!(file, "{}", description)?;
    writeln!(file)?;
    if let Some(ptr_name) = pointer_name {
        writeln!(file, "Pointer: {}", ptr_name)?;
    }
    writeln!(
        file,
        "This bug was found on the OVERLAY CONCOLIC path, not on the concrete execution."
    )?;
    writeln!(
        file,
        "The pointer is unconditionally NULL once this code path is entered."
    )?;
    writeln!(
        file,
        "The Z3 constraint solver analysis (CBRANCH) below determines what"
    )?;
    writeln!(
        file,
        "input values are needed to reach this path from the program entry."
    )?;
    writeln!(file, "{}", "=".repeat(80))?;

    file.flush()?;

    Ok(())
}

/// Initialize the recorded command line invocation including key environment variables.
pub fn init_invocation_command_line() {
    // Try to reconstruct the full wrapper-style command
    let zorya_dir = std::env::var("ZORYA_DIR").ok();
    let bin_path = std::env::var("BIN_PATH").ok();
    let start_point = std::env::var("START_POINT").ok();
    let mode = std::env::var("MODE").ok();
    let source_lang = std::env::var("SOURCE_LANG").ok();
    let compiler = std::env::var("COMPILER").ok();
    let args_env = std::env::var("ARGS").ok();
    let negate_flag = std::env::var("NEGATE_PATH_FLAG").ok();

    let reconstructed = match (zorya_dir, bin_path, start_point, mode) {
        (Some(zdir), Some(bin), Some(start), Some(mode_val)) => {
            let mut s = format!("{}/zorya {} --mode {} {}", zdir, bin, mode_val, start);
            if let Some(lang) = source_lang {
                if !lang.is_empty() {
                    s.push_str(&format!(" --lang {}", lang));
                }
            }
            if let Some(comp) = compiler {
                if !comp.is_empty() {
                    s.push_str(&format!(" --compiler {}", comp));
                }
            }
            if let Some(a) = args_env {
                if !a.is_empty() && a != "none" {
                    s.push_str(&format!(" --arg \"{}\"", a));
                }
            }
            if let Some(neg) = negate_flag {
                if neg == "true" {
                    s.push_str(" --negate-path-exploration");
                } else if neg == "false" {
                    s.push_str(" --no-negate-path-exploration");
                }
            }
            s
        }
        _ => {
            // Fallback: argv join
            let mut parts: Vec<String> = Vec::new();
            for arg in std::env::args() {
                let needs_quotes = arg.contains(' ') || arg.contains('\t');
                let escaped = arg.replace('"', "\\\"");
                if needs_quotes {
                    parts.push(format!("\"{}\"", escaped));
                } else {
                    parts.push(escaped);
                }
            }
            parts.join(" ")
        }
    };

    let _ = INVOCATION_CMDLINE.set(reconstructed);
}

/// Add ASCII constraints for argument bytes to ensure readable output
fn add_ascii_constraints_for_args<'ctx>(
    executor: &mut ConcolicExecutor<'ctx>,
    binary_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let ascii_profile = std::env::var("ARG_ASCII_PROFILE")
        .unwrap_or_else(|_| "auto".to_string())
        .to_lowercase();

    // Auto-detect numeric arguments by parsing the execution trace for calls
    // to strconv.Atoi / strconv.ParseInt and capture the first argument pointer.
    let mut numeric_arg_ptrs: HashSet<u64> = HashSet::new();
    if ascii_profile == "auto" {
        if let Ok(trace) = std::fs::read_to_string("results/execution_trace.txt") {
            for line in trace.lines() {
                if line.contains("Symbol: strconv.Atoi")
                    || line.contains("Symbol: strconv.ParseInt")
                {
                    // Heuristic: find the first "=0x..." after the arrow
                    if let Some(arrow_idx) = line.find("->") {
                        let after = &line[arrow_idx + 2..];
                        if let Some(s_idx) = after.find("=0x") {
                            let hex_start = s_idx + 3;
                            let mut hex_end = hex_start;
                            let bytes = after.as_bytes();
                            while hex_end < after.len() && bytes[hex_end].is_ascii_hexdigit() {
                                hex_end += 1;
                            }
                            if let Ok(val) = u64::from_str_radix(&after[hex_start..hex_end], 16) {
                                numeric_arg_ptrs.insert(val);
                            }
                        }
                    }
                }
            }
        }
    }
    if let Ok(os_args_addr) = get_os_args_address(binary_path) {
        if let Ok(slice_ptr_bv) = executor
            .state
            .memory
            .read_u64(os_args_addr, &mut executor.state.logger.clone())
        {
            if let Ok(slice_len_bv) = executor
                .state
                .memory
                .read_u64(os_args_addr + 8, &mut executor.state.logger.clone())
            {
                let slice_ptr_val = slice_ptr_bv.concrete.to_u64();
                let slice_len_val = slice_len_bv.concrete.to_u64();

                // Add ASCII constraints for each argument byte
                for i in 1..slice_len_val.min(10) {
                    // Limit to first 10 args for performance
                    let string_struct_addr = slice_ptr_val + i * 16;

                    if let Ok(str_data_ptr_cv) = executor
                        .state
                        .memory
                        .read_u64(string_struct_addr, &mut executor.state.logger.clone())
                    {
                        if let Ok(str_data_len_cv) = executor
                            .state
                            .memory
                            .read_u64(string_struct_addr + 8, &mut executor.state.logger.clone())
                        {
                            let str_data_ptr_val = str_data_ptr_cv.concrete.to_u64();
                            let str_data_len_val = str_data_len_cv.concrete.to_u64();
                            let str_data_len_bv_sym =
                                str_data_len_cv.symbolic.to_bv(executor.context);

                            if str_data_ptr_val != 0 && str_data_len_val > 0 {
                                // Decide constraint profile for this specific arg (auto/digits/printable)
                                let apply_digits_for_this_arg = match ascii_profile.as_str() {
                                    "digits" => true,
                                    "printable" => false,
                                    _ => numeric_arg_ptrs.contains(&str_data_ptr_val),
                                };
                                // Limit string length for performance
                                let max_len = str_data_len_val.min(256);
                                let mut first_byte_bv_opt: Option<z3::ast::BV> = None;
                                for j in 0..max_len {
                                    if let Ok(byte_read) =
                                        executor.state.memory.read_byte(str_data_ptr_val + j)
                                    {
                                        let byte_bv = byte_read.symbolic.to_bv(executor.context);
                                        if j == 0 {
                                            first_byte_bv_opt = Some(byte_bv.clone());
                                        }
                                        if apply_digits_for_this_arg {
                                            // Allow only digits '0'-'9'; allow optional leading '-' at position 0
                                            let zero = z3::ast::BV::from_u64(
                                                executor.context,
                                                b'0' as u64,
                                                8,
                                            );
                                            let nine = z3::ast::BV::from_u64(
                                                executor.context,
                                                b'9' as u64,
                                                8,
                                            );
                                            let is_digit =
                                                byte_bv.bvuge(&zero) & byte_bv.bvule(&nine);

                                            if j == 0 {
                                                let dash = z3::ast::BV::from_u64(
                                                    executor.context,
                                                    b'-' as u64,
                                                    8,
                                                );
                                                let is_dash = byte_bv._eq(&dash);
                                                let allowed = z3::ast::Bool::or(
                                                    executor.context,
                                                    &[&is_dash, &is_digit],
                                                );
                                                executor.solver.assert(&allowed);
                                            } else {
                                                executor.solver.assert(&is_digit);
                                            }
                                        } else {
                                            // Default: printable ASCII (32-126)
                                            let printable_min =
                                                z3::ast::BV::from_u64(executor.context, 32, 8);
                                            let printable_max =
                                                z3::ast::BV::from_u64(executor.context, 126, 8);
                                            let printable_constraint = byte_bv
                                                .bvuge(&printable_min)
                                                & byte_bv.bvule(&printable_max);
                                            executor.solver.assert(&printable_constraint);
                                        }
                                    }
                                }
                                // For digits profile, forbid a lone '-' when length == 1
                                if apply_digits_for_this_arg {
                                    if let Some(first_byte_bv) = first_byte_bv_opt {
                                        let one64 = z3::ast::BV::from_u64(executor.context, 1, 64);
                                        let len_eq_one = str_data_len_bv_sym._eq(&one64);
                                        let dash8 =
                                            z3::ast::BV::from_u64(executor.context, b'-' as u64, 8);
                                        let first_is_dash = first_byte_bv._eq(&dash8);
                                        let lone_dash = z3::ast::Bool::and(
                                            executor.context,
                                            &[&len_eq_one, &first_is_dash],
                                        );
                                        let not_lone_dash = lone_dash.not();
                                        executor.solver.assert(&not_lone_dash);
                                    }
                                }
                            }
                        }
                    }
                }

                match ascii_profile.as_str() {
                    "digits" => log!(executor.state.logger, "Added ASCII constraints for argument bytes (digits mode)"),
                    "printable" => log!(executor.state.logger, "Added ASCII constraints for argument bytes (printable mode)"),
                    _ => log!(executor.state.logger, "Added ASCII constraints for argument bytes (auto mode: digits applied to detected numeric args)"),
                }
            }
        }
    }
    Ok(())
}

pub fn log_sat_state_to_file_and_terminal(
    evaluation_content: &str,
    mode: &str,
    panic_addr: Option<u64>,
    elapsed_since_start: Option<Duration>,
    instruction_addr: Option<u64>,
    opcode_str: Option<&str>,
    detection_method: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Create results directory if it doesn't exist
    std::fs::create_dir_all("results")?;

    let file_path = "results/FOUND_SAT_STATE.txt";
    let file_exists = Path::new(file_path).exists();

    // Open file in append mode (creates if doesn't exist)
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(file_path)?;

    // Get current timestamp
    let timestamp: DateTime<Utc> = Utc::now();
    let timestamp_str = timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string();

    // Write header separator
    if file_exists {
        writeln!(file, "\n{}", "=".repeat(80))?;
    }

    // Write SAT state entry
    if let Some(inv) = INVOCATION_CMDLINE.get() {
        writeln!(file, "Running command: {}", inv)?;
    }
    writeln!(file, "[*] SATISFIABLE STATE FOUND")?;
    writeln!(file, "Timestamp: {}", timestamp_str)?;
    writeln!(file, "Mode: {}", mode)?;
    if let Some(dur) = elapsed_since_start {
        let secs = dur.as_secs();
        let millis = dur.subsec_millis();
        writeln!(file, "Elapsed since start: {}.{:03}s", secs, millis)?;
    }
    if let Some(addr) = instruction_addr {
        writeln!(file, "Instruction Address: 0x{:x}", addr)?;
    }
    if let Some(addr) = panic_addr {
        writeln!(file, "Panic Address: 0x{:x}", addr)?;
    }
    if let Some(opcode) = opcode_str {
        writeln!(file, "Opcode: {}", opcode)?;
    }
    if let Some(method) = detection_method {
        writeln!(file, "Detection method: {}", method)?;
    }

    writeln!(file, "{}", "-".repeat(60))?;
    // Gating stats summary
    let gated = get_gated_by_reach();
    let allowed = get_allowed_by_xref_fallback();
    writeln!(file, "Panic gating stats:")?;
    writeln!(
        file,
        "  gated_by_reach = {} (branches skipped by reverse CFG reachability)",
        gated
    )?;
    writeln!(file, "  allowed_by_xref_fallback = {} (branches allowed because target matched a known panic xref)", allowed)?;
    writeln!(file, "{}", "-".repeat(60))?;
    writeln!(file, "{}", evaluation_content)?;
    writeln!(file, "{}", "=".repeat(80))?;

    file.flush()?;

    Ok(())
}

/// Capture simple value assignments for constrained inputs
fn capture_constrained_values_section(
    executor: &ConcolicExecutor,
    model: &z3::Model,
    symbolic_arguments: &BTreeMap<String, SymbolicVar>,
    extra_expressions: &[String],
) -> String {
    // Recompute constrained labels similarly to capture_constrained_inputs_section
    let mut constraint_strings: Vec<String> = Vec::new();
    for c in &executor.constraint_vector {
        constraint_strings.push(format!("{:?}", c.simplify()));
    }
    constraint_strings.extend(extra_expressions.iter().cloned());

    // Build label set we will evaluate
    let mut label_set: BTreeSet<String> = BTreeSet::new();

    fn collect_symbols<'ctx>(
        label: &str,
        sym: &SymbolicVar<'ctx>,
        labels: &mut BTreeSet<String>,
        constraints: &[String],
    ) {
        match sym {
            SymbolicVar::Int(bv) => {
                let name = bv.to_string();
                if constraints.iter().any(|s| s.contains(&name)) {
                    labels.insert(label.to_string());
                }
            }
            SymbolicVar::Bool(b) => {
                let name = b.to_string();
                if constraints.iter().any(|s| s.contains(&name)) {
                    labels.insert(label.to_string());
                }
            }
            SymbolicVar::Float(f) => {
                let name = f.to_string();
                if constraints.iter().any(|s| s.contains(&name)) {
                    labels.insert(label.to_string());
                }
            }
            SymbolicVar::Slice(slice) => {
                let p = slice.pointer.to_string();
                if constraints.iter().any(|s| s.contains(&p)) {
                    labels.insert(format!("{}.ptr", label));
                }
                let l = slice.length.to_string();
                if constraints.iter().any(|s| s.contains(&l)) {
                    labels.insert(format!("{}.len", label));
                }
                let c = slice.capacity.to_string();
                if constraints.iter().any(|s| s.contains(&c)) {
                    labels.insert(format!("{}.cap", label));
                }
                for (i, elem) in slice.elements.iter().enumerate() {
                    let child = format!("{}[{}]", label, i);
                    collect_symbols(&child, elem, labels, constraints);
                }
            }
            SymbolicVar::LargeInt(vec_bv) => {
                for (i, bv) in vec_bv.iter().enumerate() {
                    let name = bv.to_string();
                    if constraints.iter().any(|s| s.contains(&name)) {
                        labels.insert(format!("{}[{}]", label, i));
                    }
                }
            }
        }
    }

    // Collect only arguments that appear in constraints
    for (arg, sym) in symbolic_arguments.iter() {
        collect_symbols(arg, sym, &mut label_set, &constraint_strings);
    }

    // Helper to render ASCII description for small integers
    fn ascii_desc(v: u64) -> String {
        if v <= 0xff {
            let b = v as u8;
            match b {
                32..=126 => format!("'{}'", b as char),
                0 => "\\0".to_string(),
                9 => "\\t".to_string(),
                10 => "\\n".to_string(),
                13 => "\\r".to_string(),
                _ => format!("non-printable 0x{:02x}", b),
            }
        } else {
            "n/a".to_string()
        }
    }

    // Render sentences for labels we can evaluate
    let mut out = String::new();
    if label_set.is_empty() {
        return out;
    }
    out.push_str("RESULTS\n");
    out.push_str("The program can panic if its inputs are the following:\n");

    for label in label_set {
        // Try to evaluate by pattern-matching against the arguments
        let rendered = if let Some(dot) = label.rfind('.') {
            // Possibly slice comp: arg.len/cap/ptr OR struct field like b.header
            let (arg, field) = label.split_at(dot);
            let field = &field[1..];
            if let Some(SymbolicVar::Slice(slice)) = symbolic_arguments.get(arg) {
                match field {
                    "len" => match model.eval(&slice.length, true).and_then(|v| v.as_u64()) {
                        Some(v) => {
                            let signed = v as i64;
                            let ascii = ascii_desc(v);
                            format!(
                                "  - The input '{}' must be {} (unsigned: {}; signed: {}; ASCII: {})\n",
                                label, v, v, signed, ascii
                            )
                        }
                        None => format!("  - The input '{}' has unknown value\n", label),
                    },
                    "cap" => match model.eval(&slice.capacity, true).and_then(|v| v.as_u64()) {
                        Some(v) => {
                            let signed = v as i64;
                            let ascii = ascii_desc(v);
                            format!(
                                "  - The input '{}' must be {} (unsigned: {}; signed: {}; ASCII: {})\n",
                                label, v, v, signed, ascii
                            )
                        }
                        None => format!("  - The input '{}' has unknown value\n", label),
                    },
                    "ptr" => match model.eval(&slice.pointer, true).and_then(|v| v.as_u64()) {
                        Some(v) => format!("  - The pointer '{}' must be 0x{:x}\n", label, v),
                        None => format!("  - The pointer '{}' has unknown value\n", label),
                    },
                    _ => String::new(),
                }
            } else if let Some(sym) = symbolic_arguments.get(&label) {
                // Fallback: Try looking up the full dotted name (for struct fields like b.header)
                match sym {
                    SymbolicVar::Int(bv) => match model.eval(bv, true).and_then(|v| v.as_u64()) {
                        Some(v) => {
                            let signed = v as i64;
                            let ascii = ascii_desc(v);
                            // Special formatting for pointers (likely nil if 0)
                            if v == 0 {
                                format!("  - The pointer '{}' must be NULL (nil)\n", label)
                            } else {
                                format!(
                                    "  - The input '{}' must be 0x{:x} (unsigned: {}; signed: {}; ASCII: {})\n",
                                    label, v, v, signed, ascii
                                )
                            }
                        }
                        None => format!("  - The input '{}' has unknown value\n", label),
                    },
                    SymbolicVar::Bool(b) => match model.eval(b, true).and_then(|v| v.as_bool()) {
                        Some(v) => format!("  - The input '{}' must be {}\n", label, v),
                        None => format!("  - The input '{}' has unknown value\n", label),
                    },
                    SymbolicVar::Float(f) => match model.eval(f, true).map(|v| v.to_string()) {
                        Some(s) => format!("  - The input '{}' must be {}\n", label, s),
                        None => format!("  - The input '{}' has unknown value\n", label),
                    },
                    _ => format!("  - The input '{}' = <complex>\n", label),
                }
            } else {
                String::new()
            }
        } else if let Some(bracket) = label.find('[') {
            // Element access: arg[i]
            let arg = &label[..bracket];
            let idx_str = &label[bracket + 1..label.len() - 1];
            let idx = idx_str.parse::<usize>().unwrap_or(usize::MAX);

            // First, try direct lookup for cases where "indices[0]" itself is a tracked variable
            if let Some(sym) = symbolic_arguments.get(&label) {
                match sym {
                    SymbolicVar::Int(bv) => match model.eval(bv, true).and_then(|v| v.as_u64()) {
                        Some(v) => {
                            let signed = v as i64;
                            let ascii = ascii_desc(v);
                            format!(
                                    "  - The input '{}' must be {} (unsigned: {}; signed: {}; ASCII: {})\n",
                                    label, v, v, signed, ascii
                                )
                        }
                        None => format!("  - The input '{}' has unknown value\n", label),
                    },
                    SymbolicVar::Bool(b) => match model.eval(b, true).and_then(|v| v.as_bool()) {
                        Some(v) => format!("  - The input '{}' must be {}\n", label, v),
                        None => format!("  - The input '{}' has unknown value\n", label),
                    },
                    SymbolicVar::Float(f) => match model.eval(f, true).map(|v| v.to_string()) {
                        Some(s) => format!("  - The input '{}' must be {}\n", label, s),
                        None => format!("  - The input '{}' has unknown value\n", label),
                    },
                    _ => format!("  {} = <complex>\n", label),
                }
            } else if let Some(sym) = symbolic_arguments.get(arg) {
                // Otherwise, lookup parent slice and access element
                match sym {
                    SymbolicVar::Slice(slice) => {
                        if idx < slice.elements.len() {
                            match &slice.elements[idx] {
                                SymbolicVar::Int(bv) => {
                                    match model.eval(bv, true).and_then(|v| v.as_u64()) {
                                        Some(v) => {
                                            let signed = v as i64;
                                            let ascii = ascii_desc(v);
                                            format!(
                                            "  - The input '{}' must be {} (unsigned: {}; signed: {}; ASCII: {})\n",
                                            label, v, v, signed, ascii
                                        )
                                        }
                                        None => {
                                            format!("  - The input '{}' has unknown value\n", label)
                                        }
                                    }
                                }
                                SymbolicVar::Bool(b) => match model
                                    .eval(b, true)
                                    .and_then(|v| v.as_bool())
                                {
                                    Some(v) => format!("  - The input '{}' must be {}\n", label, v),
                                    None => format!("  -The input '{}' has unknown value\n", label),
                                },
                                SymbolicVar::Float(f) => match model
                                    .eval(f, true)
                                    .map(|v| v.to_string())
                                {
                                    Some(s) => format!("  -The input '{}' must be {}\n", label, s),
                                    None => {
                                        format!("  - The input '{}' has unknown value\n", label)
                                    }
                                },
                                _ => format!("  {} = <complex>\n", label),
                            }
                        } else {
                            String::new()
                        }
                    }
                    SymbolicVar::LargeInt(vec_bv) => {
                        if idx < vec_bv.len() {
                            match model.eval(&vec_bv[idx], true).and_then(|v| v.as_u64()) {
                                Some(v) => {
                                    let signed = v as i64;
                                    let ascii = ascii_desc(v);
                                    format!(
                                        "  - The input '{}' must be {} (unsigned: {}; signed: {}; ASCII: {})\n",
                                        label, v, v, signed, ascii
                                    )
                                }
                                None => format!("  - The input '{}' has unknown value\n", label),
                            }
                        } else {
                            String::new()
                        }
                    }
                    _ => String::new(),
                }
            } else {
                String::new()
            }
        } else {
            // Base arg (Int/Bool/Float)
            if let Some(sym) = symbolic_arguments.get(&label) {
                match sym {
                    SymbolicVar::Int(bv) => match model.eval(bv, true).and_then(|v| v.as_u64()) {
                        Some(v) => {
                            let signed = v as i64;
                            let ascii = ascii_desc(v);
                            format!(
                                "  - The input '{}' must be {} (unsigned: {}; signed: {}; ASCII: {})\n",
                                label, v, v, signed, ascii
                            )
                        }
                        None => format!("  - The input '{}' has unknown value\n", label),
                    },
                    SymbolicVar::Bool(b) => match model.eval(b, true).and_then(|v| v.as_bool()) {
                        Some(v) => format!("  - The input '{}' must be {}\n", label, v),
                        None => format!("  - The input '{}' has unknown value\n", label),
                    },
                    SymbolicVar::Float(f) => match model.eval(f, true).map(|v| v.to_string()) {
                        Some(s) => format!("  - The input '{}' must be {}\n", label, s),
                        None => format!("  - The input '{}' has unknown value\n", label),
                    },
                    _ => String::new(),
                }
            } else {
                String::new()
            }
        };
        out.push_str(&rendered);
    }

    out.push('\n');
    out
}

/// Capture the evaluation content as a string (similar to what goes to the logger)
fn capture_symbolic_arguments_evaluation(
    model: &z3::Model,
    function_symbolic_arguments: &std::collections::BTreeMap<String, SymbolicVar>,
) -> String {
    let mut output = String::new();

    output.push_str("=== FULL EVALUATION OF Z3 VARIABLES (TRACKED AND UNTRACKED) ===\n\n");

    for (arg_name, symbolic_var) in function_symbolic_arguments {
        match symbolic_var {
            SymbolicVar::Slice(slice) => {
                output.push_str(&format!("Argument '{}':\n", arg_name));
                output.push_str("  Slice components:\n");

                // Evaluate slice metadata
                if let Some(ptr_val) = model.eval(&slice.pointer, true) {
                    if let Some(ptr_u64) = ptr_val.as_u64() {
                        output.push_str(&format!(
                            "    pointer ({}) = #x{:016x}\n",
                            slice.pointer, ptr_u64
                        ));
                        output.push_str(&format!("      (hex: 0x{:x})\n", ptr_u64));
                    }
                }

                if let Some(len_val) = model.eval(&slice.length, true) {
                    if let Some(len_u64) = len_val.as_u64() {
                        output.push_str(&format!(
                            "    length ({}) = #x{:016x}\n",
                            slice.length, len_u64
                        ));
                        output.push_str(&format!("      (decimal: {})\n", len_u64));
                    }
                }

                if let Some(cap_val) = model.eval(&slice.capacity, true) {
                    if let Some(cap_u64) = cap_val.as_u64() {
                        output.push_str(&format!(
                            "    capacity ({}) = #x{:016x}\n",
                            slice.capacity, cap_u64
                        ));
                        output.push_str(&format!("      (decimal: {})\n", cap_u64));
                    }
                }

                output.push('\n');
            }
            SymbolicVar::Int(bv) => {
                if let Some(val) = model.eval(bv, true) {
                    output.push_str(&format!("Argument '{}':\n", arg_name));

                    // Check if this is a string component (ptr or len)
                    let is_string_ptr = arg_name.ends_with("__ptr");
                    let is_string_len = arg_name.ends_with("__len");

                    if bv.get_size() <= 64 {
                        if let Some(val_u64) = val.as_u64() {
                            output.push_str(&format!("  {} = #x{:016x}\n", bv, val_u64));

                            // Special display for string components
                            if is_string_ptr {
                                output
                                    .push_str(&format!("    (string pointer: 0x{:x})\n", val_u64));
                            } else if is_string_len {
                                output.push_str(&format!("    (string length: {})\n", val_u64));
                            } else {
                                let signed_val = val_u64 as i64;
                                output.push_str(&format!("    (unsigned: {})\n", val_u64));
                                output.push_str(&format!("    (signed: {})\n", signed_val));
                            }

                            // Add ASCII interpretation when value fits in a byte (skip for string components)
                            if !is_string_ptr && !is_string_len && val_u64 <= 255 {
                                let byte_val = val_u64 as u8;
                                if (32..=126).contains(&byte_val) {
                                    // Printable ASCII
                                    output.push_str(&format!(
                                        "    (ASCII: '{}')\n",
                                        char::from(byte_val)
                                    ));
                                } else if byte_val == 0 {
                                    output.push_str("    (ASCII: '\\0' - null byte)\n");
                                } else if byte_val == 9 {
                                    output.push_str("    (ASCII: '\\t' - tab)\n");
                                } else if byte_val == 10 {
                                    output.push_str("    (ASCII: '\\n' - newline)\n");
                                } else if byte_val == 13 {
                                    output.push_str("    (ASCII: '\\r' - carriage return)\n");
                                } else {
                                    output.push_str(&format!(
                                        "    (ASCII: non-printable, code {})\n",
                                        byte_val
                                    ));
                                }
                            } else if !is_string_ptr && !is_string_len {
                                // Provide LSB ASCII hint for larger integers (skip for string components)
                                let b0 = (val_u64 & 0xff) as u8;
                                let ascii = if (32..=126).contains(&b0) {
                                    format!("'{}'", b0 as char)
                                } else if b0 == 0 {
                                    "\\0".to_string()
                                } else if b0 == 9 {
                                    "\\t".to_string()
                                } else if b0 == 10 {
                                    "\\n".to_string()
                                } else if b0 == 13 {
                                    "\\r".to_string()
                                } else {
                                    format!("non-printable 0x{:02x}", b0)
                                };
                                output.push_str(&format!("    (ASCII LSB: {})\n", ascii));
                            }
                        }
                    } else {
                        // For large bit vectors (like 256-bit arrays)
                        output.push_str(&format!("  {} = {}\n", bv, val));
                        output.push_str("    (unsigned: n/a)\n");
                        output.push_str("    (signed: n/a)\n");
                    }

                    output.push('\n');
                }
            }
            SymbolicVar::LargeInt(bvs) => {
                // Handle LargeInt, which we use for Go strings (ptr + len)
                output.push_str(&format!("Argument '{}':\n", arg_name));

                // Check if this looks like a Go string (2 x 64-bit values)
                if bvs.len() == 2 && bvs[0].get_size() == 64 && bvs[1].get_size() == 64 {
                    output.push_str("  Go string components:\n");

                    // First BV is ptr
                    if let Some(ptr_val) = model.eval(&bvs[0], true) {
                        if let Some(ptr_u64) = ptr_val.as_u64() {
                            output
                                .push_str(&format!("    ptr ({}) = #x{:016x}\n", bvs[0], ptr_u64));
                            output.push_str(&format!("      (hex: 0x{:x})\n", ptr_u64));
                        } else {
                            output.push_str(&format!("    ptr = {}\n", ptr_val));
                        }
                    }

                    // Second BV is len
                    if let Some(len_val) = model.eval(&bvs[1], true) {
                        if let Some(len_u64) = len_val.as_u64() {
                            output
                                .push_str(&format!("    len ({}) = #x{:016x}\n", bvs[1], len_u64));
                            output.push_str(&format!("      (decimal: {})\n", len_u64));
                        } else {
                            output.push_str(&format!("    len = {}\n", len_val));
                        }
                    }
                } else {
                    // Generic LargeInt display
                    output.push_str(&format!("  LargeInt with {} components:\n", bvs.len()));
                    for (i, bv) in bvs.iter().enumerate() {
                        if let Some(val) = model.eval(bv, true) {
                            output.push_str(&format!("    [{}] {} = {}\n", i, bv, val));
                        }
                    }
                }
                output.push('\n');
            }
            _ => {
                output.push_str(&format!(
                    "Argument '{}': (unsupported type for evaluation)\n\n",
                    arg_name
                ));
            }
        }
    }

    output.push_str("=== END TRACKED Z3 VARIABLES EVALUATION ===\n");
    output
}

/// Build a unified evaluation content string used for both file output and terminal logs
pub fn build_unified_evaluation_content<'ctx>(
    model: &z3::Model,
    executor: &ConcolicExecutor,
    conditional_flag: Option<&ConcolicVar>,
    null_check_pointer: Option<&z3::ast::BV<'ctx>>,
) -> String {
    let mut content = String::new();

    // Include current conditional flag expression to aid constrained input detection
    let mut extra_exprs: Vec<String> = Vec::new();
    if let Some(cf) = conditional_flag.as_ref() {
        match &cf.symbolic {
            SymbolicVar::Bool(b) => extra_exprs.push(format!("{:?}", b.simplify())),
            SymbolicVar::Int(bv) => extra_exprs.push(format!("{:?}", bv.simplify())),
            _ => {}
        }
    }

    // Include NULL pointer expression if checking for NULL dereference
    if let Some(pointer_bv) = null_check_pointer {
        extra_exprs.push(format!("{:?}", pointer_bv.simplify()));
    }

    // Constrained values first
    content.push_str(&capture_constrained_values_section(
        executor,
        model,
        &executor.function_symbolic_arguments,
        &extra_exprs,
    ));
    content.push_str("(If the result is not in the expected format, try to set the ARG_ASCII_PROFILE environment variable to 'printable' or 'digits', by running 'ARG_ASCII_PROFILE=printable zorya ...' for instance)\n");
    content.push_str("------------------------------------------------------------\n");
    // Then full tracked/untracked variable evaluation
    content.push_str(&capture_symbolic_arguments_evaluation(
        model,
        &executor.function_symbolic_arguments,
    ));

    content
}

pub fn evaluate_args_z3<'ctx>(
    executor: &mut ConcolicExecutor<'ctx>,
    inst: &Inst,
    conditional_flag: Option<ConcolicVar<'ctx>>,
    instruction_addr: Option<u64>,
    branch_target_addr: Option<u64>,
    panic_addr: Option<u64>, // Add panic address parameter to avoid re-exploration
    null_check_pointer: Option<&z3::ast::BV<'ctx>>, // for NULL pointer dereference checks (LOAD/STORE)
) -> Result<bool, Box<dyn std::error::Error>> {
    // return bool indicating SAT
    use std::env;
    let mode = env::var("MODE").expect("MODE environment variable is not set");

    if mode == "function" {
        // Use panic_addr passed from caller instead of re-doing AST exploration
        if let Some(parsed_addr) = panic_addr {
            log!(
                executor.state.logger,
                ">>> Using panic address from caller: 0x{:x}",
                parsed_addr
            );

            executor.solver.push();

            // The evaluation can be done for CBranch instructions, and also for Load and Store instructions
            if inst.opcode == Opcode::CBranch {
                // When evaluating arguments during a CBRANCH leading to a panic, assert the simple boolean condition that leads to the panic.
                if let Some(ref conditional_flag) = conditional_flag {
                    let panic_causing_flag_u64 = conditional_flag.concrete.to_u64();
                    // Handle both Bool and BV types
                    let condition = match &conditional_flag.symbolic {
                        SymbolicVar::Bool(bool_expr) => {
                            log!(
                                executor.state.logger,
                                "Conditional flag Bool simplified: {:?}",
                                bool_expr.simplify()
                            );
                            // Flip the observed condition to explore the negated branch
                            let condition = if panic_causing_flag_u64 == 0 {
                                // Observed false; require true
                                bool_expr.not().not() // i.e., bool_expr == true
                            } else {
                                // Observed true; require false
                                bool_expr.not()
                            };
                            condition
                        }
                        SymbolicVar::Int(bv) => {
                            log!(
                                executor.state.logger,
                                "Conditional flag BV simplified: {:?}",
                                bv.simplify()
                            );
                            // Extract underlying Bool from BV and assert the negation of observed path
                            let bool_cond = crate::state::simplify_z3::bv_to_bool_smart(bv);
                            if panic_causing_flag_u64 == 0 {
                                bool_cond
                            } else {
                                bool_cond.not()
                            }
                        }
                        _ => {
                            return Err("Unsupported symbolic variable type for conditional flag"
                                .to_string()
                                .into());
                        }
                    };
                    // Assert the new condition
                    let simplified = condition.simplify();
                    log!(
                        executor.state.logger,
                        "Asserting branch condition to the solver: {:?}",
                        simplified
                    );
                    executor.solver.assert(&simplified);
                } else {
                    log!(
                        executor.state.logger,
                        "No conditional flag provided, continuing."
                    );
                }
            } else if let Some(pointer_bv) = null_check_pointer {
                // ── Fast path: NULL pointer dereference check ──────────────
                // Use a fresh z3::Solver (NOT Optimize) for NULL checks.
                // Rationale: Optimize adds multi-objective minimization (x²
                // per tracked variable) which is 10-100× slower than a plain
                // SAT check.  NULL checks only need a yes/no answer + a
                // witness model; minimized values are irrelevant.
                let null_solver = z3::Solver::new(executor.context);

                // Assert: pointer == 0
                let null_bv = z3::ast::BV::from_u64(executor.context, 0, pointer_bv.get_size());
                let null_condition = pointer_bv._eq(&null_bv);

                log!(
                    executor.state.logger,
                    "Asserting NULL pointer condition to the solver: pointer == 0"
                );
                log!(
                    executor.state.logger,
                    "Pointer expression: {:?}",
                    pointer_bv.simplify()
                );

                null_solver.assert(&null_condition);

                // Assert accumulated path constraints (raw — no custom
                // simplification overhead; the plain solver handles them fine)
                for constraint in &executor.constraint_vector {
                    null_solver.assert(constraint);
                }

                // Check SAT/UNSAT — no minimization objectives
                let solve_start = Instant::now();
                let solve_result = null_solver.check();
                let solve_elapsed = solve_start.elapsed();
                crate::Z3_CUMULATIVE_MS.fetch_add(
                    solve_elapsed.as_millis() as u64,
                    std::sync::atomic::Ordering::Relaxed,
                );

                // Always log to file so execution_log records every check
                log!(
                    executor.state.logger,
                    "[Z3-SOLVER] NULL pointer check took {:.3}s (result: {:?})",
                    solve_elapsed.as_secs_f64(),
                    solve_result
                );

                match solve_result {
                    SatResult::Sat => {
                        // Print to terminal only when SAT (vulnerability found)
                        crate::teprintln!(
                            "[Z3-SOLVER] NULL pointer check took {:.3}s",
                            solve_elapsed.as_secs_f64()
                        );

                        log!(executor.state.logger, "~~~~~~~~~~~");
                        log!(
                            executor.state.logger,
                            "SATISFIABLE: Symbolic execution can lead to a panic function."
                        );
                        log!(executor.state.logger, "~~~~~~~~~~~");

                        let model = null_solver.get_model().unwrap();

                        log!(
                            executor.state.logger,
                            "To enter a panic function, the following conditions must be satisfied:"
                        );

                        // Build unified evaluation content (same model type as Optimize)
                        let evaluation_content = build_unified_evaluation_content(
                            &model,
                            executor,
                            conditional_flag.as_ref(),
                            null_check_pointer,
                        );

                        // Log to terminal using the same structure
                        for line in evaluation_content.lines() {
                            log!(executor.state.logger, "{}", line);
                        }

                        // Write to file
                        let elapsed = START_INSTANT.get().map(|s| s.elapsed());
                        let opcode_str = match inst.opcode {
                            Opcode::Load => "LOAD",
                            Opcode::Store => "STORE",
                            _ => "UNKNOWN",
                        };
                        let detection_method = if executor.overlay_state.is_some() {
                            "Exploring the not taken path with Overlay Execution"
                        } else {
                            "Exploring the current path with a symbolic check on the pointer"
                        };

                        if let Err(e) = log_sat_state_to_file_and_terminal(
                            &evaluation_content,
                            &mode,
                            panic_addr,
                            elapsed,
                            instruction_addr,
                            Some(opcode_str),
                            Some(detection_method),
                        ) {
                            log!(
                                executor.state.logger,
                                "WARNING: Failed to write SAT state to file: {}",
                                e
                            );
                        }

                        // Report NULL pointer dereference vulnerability
                        let addr = instruction_addr.or(panic_addr).unwrap_or(0);
                        let det = if executor.overlay_state.is_some() {
                            "Detection method: Exploring the not taken path with Overlay Execution"
                        } else {
                            "Detection method: Exploring the current path with a symbolic check on the pointer"
                        };
                        report_vulnerability(
                            &mut executor.state.logger.clone(),
                            "Symbolic NULL pointer dereference",
                            addr,
                            &[
                                &format!("Opcode: {}", opcode_str),
                                det,
                                "More details in: results/FOUND_SAT_STATE.txt",
                            ],
                        );

                        log!(executor.state.logger, "~~~~~~~~~~~");

                        executor.solver.pop();
                        return Ok(true); // SAT - vulnerability found
                    }
                    SatResult::Unsat => {
                        log!(executor.state.logger, "~~~~~~~~~~~");
                        log!(
                            executor.state.logger,
                            "NULL pointer check is UNSAT => pointer cannot be NULL"
                        );
                        log!(executor.state.logger, "~~~~~~~~~~~");

                        executor.solver.pop();
                        return Ok(false);
                    }
                    SatResult::Unknown => {
                        log!(
                            executor.state.logger,
                            "NULL pointer solver => Unknown (timeout?)"
                        );
                        executor.solver.pop();
                        return Ok(false);
                    }
                }
                // ── End fast NULL check path ───────────────────────────────
            }

            // ── CBranch path: use Optimize with minimization ───────────
            // List constraints and assert them to solver
            add_constraints_from_vector(executor);

            // Minimize symbolic variables to produce readable witnesses.
            // We minimize the UNSIGNED BV value directly instead of converting
            // to Int and squaring (which mixes BV + integer theories and is
            // extremely expensive for 64-bit variables).
            for symbolic_var in executor.function_symbolic_arguments.values() {
                match symbolic_var {
                    SymbolicVar::Int(bv_var) => {
                        // Direct BV minimization — stays in bitvector theory
                        executor.solver.minimize(bv_var);
                    }
                    SymbolicVar::Slice(slice) => {
                        // Prefer smallest slice length first (lexicographic objective)
                        executor.solver.minimize(&slice.length);

                        // Heuristic domain constraints for slice length
                        let len_int = Int::from_bv(&slice.length, false);

                        let zero = Int::from_i64(executor.context, 0);
                        executor.solver.assert(&len_int.ge(&zero));

                        let materialized = slice.elements.len() as i64;
                        if materialized > 0 {
                            let max_len = Int::from_i64(executor.context, materialized);
                            executor.solver.assert(&len_int.le(&max_len));
                        }

                        // Then minimize each element
                        for elem in &slice.elements {
                            match elem {
                                SymbolicVar::Int(bv_elem) => {
                                    executor.solver.minimize(bv_elem);
                                }
                                SymbolicVar::Slice(slice_elem) => {
                                    executor.solver.minimize(&slice_elem.length);
                                }
                                _ => {}
                            }
                        }
                    }
                    _ => {}
                }
            }

            let solve_start = Instant::now();
            let solve_result = executor.solver.check(&[]);
            let solve_elapsed = solve_start.elapsed();
            crate::Z3_CUMULATIVE_MS.fetch_add(
                solve_elapsed.as_millis() as u64,
                std::sync::atomic::Ordering::Relaxed,
            );

            // Always log to file so execution_log records every check
            log!(
                executor.state.logger,
                "[Z3-OPTIMIZE] CBranch evaluation took {:.3}s (result: {:?})",
                solve_elapsed.as_secs_f64(),
                solve_result
            );

            match solve_result {
                SatResult::Sat => {
                    // Print to terminal only when SAT (vulnerability found)
                    crate::teprintln!(
                        "[Z3-OPTIMIZE] CBranch evaluation took {:.3}s",
                        solve_elapsed.as_secs_f64()
                    );

                    log!(executor.state.logger, "~~~~~~~~~~~");
                    log!(
                        executor.state.logger,
                        "SATISFIABLE: Symbolic execution can lead to a panic function."
                    );
                    log!(executor.state.logger, "~~~~~~~~~~~");

                    let model = executor.solver.get_model().unwrap();

                    log!(
                        executor.state.logger,
                        "To enter a panic function, the following conditions must be satisfied:"
                    );

                    // Build unified evaluation content
                    let evaluation_content = build_unified_evaluation_content(
                        &model,
                        executor,
                        conditional_flag.as_ref(),
                        null_check_pointer,
                    );

                    // Log to terminal using the same structure
                    for line in evaluation_content.lines() {
                        log!(executor.state.logger, "{}", line);
                    }

                    // Write to file (for both CBRANCH and NULL checks)
                    let elapsed = START_INSTANT.get().map(|s| s.elapsed());

                    // Determine opcode and detection method strings for file logging
                    let opcode_str = "CBRANCH";

                    let detection_method = if executor.overlay_state.is_some() {
                        "Exploring the not taken path with Overlay Execution"
                    } else {
                        "Exploring the current path with a symbolic check on the pointer"
                    };

                    if let Err(e) = log_sat_state_to_file_and_terminal(
                        &evaluation_content,
                        &mode,
                        panic_addr,
                        elapsed,
                        instruction_addr,
                        Some(opcode_str),
                        Some(detection_method),
                    ) {
                        log!(
                            executor.state.logger,
                            "WARNING: Failed to write SAT state to file: {}",
                            e
                        );
                    }

                    // Report CBRANCH vulnerability to terminal
                    let addr = instruction_addr.or(panic_addr).unwrap_or(0);
                    report_vulnerability(
                        &mut executor.state.logger.clone(),
                        "Satisfiable path to panic/crash",
                        addr,
                        &[
                            "Opcode: CBRANCH",
                            "Detection method: Overlay concolic path exploration",
                            "More details in: results/FOUND_SAT_STATE.txt",
                        ],
                    );

                    log!(executor.state.logger, "~~~~~~~~~~~");

                    executor.solver.pop();
                    Ok(true) // SAT - vulnerability found
                }
                SatResult::Unsat => {
                    log!(executor.state.logger, "~~~~~~~~~~~");
                    log!(
                        executor.state.logger,
                        "Branch to panic is UNSAT => no input can make that branch lead to panic"
                    );
                    log!(executor.state.logger, "~~~~~~~~~~~");

                    executor.solver.pop();
                    Ok(false) // UNSAT - no vulnerability
                }
                SatResult::Unknown => {
                    log!(executor.state.logger, "Solver => Unknown feasibility");
                    executor.solver.pop();
                    Ok(false) // Unknown treated as no vulnerability
                }
            }
        } else {
            log!(executor.state.logger, ">>> No panic function found in the AST exploration with the current max depth exploration");
            Ok(false) // No panic found
        }
    // TODO: Add detection method for NULL pointer dereference checks (LOAD/STORE) like in function mode
    } else if mode == "start" || mode == "main" {
        let binary_path = {
            let target_info = GLOBAL_TARGET_INFO.lock().unwrap();
            target_info.binary_path.clone()
        };

        // 1) Push the solver context.
        executor.solver.push();

        // 2) Process the branch condition.
        let cond_varnode = &inst.inputs[1];
        let cond_concolic = executor
            .varnode_to_concolic(cond_varnode)
            .map_err(|e| e.to_string())
            .unwrap()
            .to_concolic_var()
            .unwrap();
        let cond_bv = cond_concolic.symbolic.to_bv(executor.context);

        // List constraints and assert them to solver
        add_constraints_from_vector(executor);

        // Minimize only slice lengths to prefer smaller witnesses (no other variable objectives)
        for symbolic_var in executor.function_symbolic_arguments.values() {
            if let SymbolicVar::Slice(slice) = symbolic_var {
                executor.solver.minimize(&slice.length);
            }
        }

        // Optionally enforce ASCII profiles for argv bytes (off by default)
        if let Ok(profile) = std::env::var("ARG_ASCII_PROFILE") {
            let prof = profile.to_lowercase();
            if prof == "printable" || prof == "digits" || prof == "auto" {
                let _ = add_ascii_constraints_for_args(executor, &binary_path);
            }
        }

        // We are exploring the negated path: assert the opposite of the observed flag
        let observed_flag = cond_concolic.concrete.to_u64();
        // Convert the BV flag to a Bool like in function mode and assert/negate accordingly
        let branch_bool = crate::state::simplify_z3::bv_to_bool_smart(&cond_bv);
        let condition = if observed_flag == 0 {
            branch_bool
        } else {
            branch_bool.not()
        };
        let simplified = condition.simplify();
        log!(
            executor.state.logger,
            "Asserting branch condition to the solver: {:?}",
            simplified
        );
        log!(
            executor.state.logger,
            "Simplified branch condition: {:?}",
            simplified
        );
        executor.solver.assert(&simplified);

        // 4) check feasibility
        let solve_start = Instant::now();
        let solve_result = executor.solver.check(&[]);
        let solve_elapsed = solve_start.elapsed();
        crate::Z3_CUMULATIVE_MS.fetch_add(
            solve_elapsed.as_millis() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );

        // Always log to file so execution_log records every check
        log!(
            executor.state.logger,
            "[Z3-OPTIMIZE] CBranch evaluation took {:.3}s (result: {:?})",
            solve_elapsed.as_secs_f64(),
            solve_result
        );

        match solve_result {
            z3::SatResult::Sat => {
                // Print to terminal only when SAT (vulnerability found)
                crate::teprintln!(
                    "[Z3-OPTIMIZE] CBranch evaluation took {:.3}s",
                    solve_elapsed.as_secs_f64()
                );

                log!(executor.state.logger, "~~~~~~~~~~~");
                log!(
                    executor.state.logger,
                    "SATISFIABLE: Symbolic execution can lead to a panic function."
                );
                log!(executor.state.logger, "~~~~~~~~~~~");

                let model = executor.solver.get_model().unwrap();

                // Build unified evaluation content
                let evaluation_content = build_unified_evaluation_content(
                    &model,
                    executor,
                    conditional_flag.as_ref(),
                    null_check_pointer,
                );

                // Log to terminal using the same structure
                for line in evaluation_content.lines() {
                    log!(executor.state.logger, "{}", line);
                }

                // Write to file and report to terminal
                let elapsed = START_INSTANT.get().map(|s| s.elapsed());
                if let Err(e) = log_sat_state_to_file_and_terminal(
                    &evaluation_content,
                    &mode,
                    branch_target_addr,
                    elapsed,
                    instruction_addr,
                    Some("CBRANCH"),
                    Some("Exploring the not taken path with Overlay Execution"),
                ) {
                    log!(
                        executor.state.logger,
                        "WARNING: Failed to write SAT state to file: {}",
                        e
                    );
                }

                // Report CBRANCH vulnerability to terminal
                let addr = instruction_addr.or(branch_target_addr).unwrap_or(0);
                report_vulnerability(
                    &mut executor.state.logger.clone(),
                    "Satisfiable path to panic/crash",
                    addr,
                    &[
                        "Opcode: CBRANCH",
                        "Detection method: Overlay concolic path exploration",
                        "More details in: results/FOUND_SAT_STATE.txt",
                    ],
                );

                log!(executor.state.logger, "~~~~~~~~~~~");

                // 6) pop the solver context
                executor.solver.pop();
                Ok(true) // SAT - vulnerability found
            }

            z3::SatResult::Unsat => {
                log!(executor.state.logger, "~~~~~~~~~~~");
                log!(
                    executor.state.logger,
                    "Branch to panic is UNSAT => no input can make that branch lead to panic"
                );
                log!(executor.state.logger, "~~~~~~~~~~~");

                // 6) pop the solver context
                executor.solver.pop();
                Ok(false) // UNSAT - no vulnerability
            }
            z3::SatResult::Unknown => {
                log!(executor.state.logger, "Solver => Unknown feasibility");
                // 6) pop the solver context
                executor.solver.pop();
                Ok(false) // Unknown treated as no vulnerability
            }
        }
    } else {
        log!(
            executor.state.logger,
            "Unsupported mode for evaluating arguments: {}",
            mode
        );
        Ok(false)
    }
}

// Function to get the address of the os.Args slice in the target binary
pub fn get_os_args_address(binary_path: &str) -> Result<u64, Box<dyn Error>> {
    let output = Command::new("objdump")
        .arg("-t")
        .arg(binary_path)
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("objdump failed: {}", stderr).into());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Example line we might see:
    // 0000000000236e68 l     O .bss   0000000000000018 os.Args
    for line in stdout.lines() {
        if line.contains("os.Args") {
            // The first token is the address in hex, like "0000000000236e68"
            let parts: Vec<&str> = line.split_whitespace().collect();
            if !parts.is_empty() {
                let addr_hex = parts[0];
                // Convert from hex string to u64
                let addr = u64::from_str_radix(addr_hex, 16)?;
                return Ok(addr);
            }
        }
    }
    Err("Could not find os.Args in objdump output".into())
}
