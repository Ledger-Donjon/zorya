// SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, fs, io::Write, path::Path, sync::Arc};

use crate::{
    concolic::{ConcolicExecutor, ConcolicVar, ConcreteVar, SymbolicVar},
    state::{function_signatures::TypeDesc, memory_x86_64::MemoryValue},
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use z3::ast::{Ast, BV};

// ────────────────────────────────────────────────────────────
//  Struct Type Definitions (loaded from DWARF extraction)
// ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructMemberDef {
    pub name: String,
    pub offset: u64,
    #[serde(rename = "type")]
    pub typ: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructTypeDef {
    pub name: String,
    pub size: u64,
    pub members: Vec<StructMemberDef>,
}

/// Global cache of struct type definitions
static mut STRUCT_TYPES: Option<HashMap<String, StructTypeDef>> = None;

/// Load struct type definitions from JSON file
pub fn load_struct_types(json_path: &str) -> Result<HashMap<String, StructTypeDef>, String> {
    let path = Path::new(json_path);
    if !path.exists() {
        return Err(format!("Struct types file not found: {}", json_path));
    }

    let content =
        fs::read_to_string(path).map_err(|e| format!("Failed to read struct types file: {}", e))?;

    let struct_types: HashMap<String, StructTypeDef> = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse struct types JSON: {}", e))?;

    println!(
        "[STRUCT-TYPES] Loaded {} struct type definitions",
        struct_types.len()
    );

    Ok(struct_types)
}

/// Get struct type definition by name
pub fn get_struct_type(struct_name: &str) -> Option<StructTypeDef> {
    unsafe {
        STRUCT_TYPES
            .as_ref()
            .and_then(|types| types.get(struct_name).cloned())
    }
}

/// Initialize the global struct types cache
pub fn init_struct_types_cache(json_path: &str) {
    match load_struct_types(json_path) {
        Ok(types) => unsafe {
            STRUCT_TYPES = Some(types);
        },
        Err(e) => {
            eprintln!("[STRUCT-TYPES] Warning: {}", e);
            eprintln!("[STRUCT-TYPES] Struct field symbolization will be disabled");
        }
    }
}

/// Check if a type string represents a pointer to a struct
pub fn is_struct_pointer_type(type_str: &str) -> Option<String> {
    // Go struct pointer types look like: "package/path.StructName *"
    if type_str.ends_with(" *") || type_str.ends_with("*") {
        let struct_name = type_str.trim_end_matches(" *").trim_end_matches('*');
        // Verify it's a struct (not a primitive pointer)
        if struct_name.contains('.') || struct_name.contains('/') {
            return Some(struct_name.to_string());
        }
    }
    None
}

macro_rules! log {
    ($logger:expr, $($arg:tt)*) => {{
        writeln!($logger, $($arg)*).unwrap();
    }};
}

// ────────────────────────────────────────────────────────────
//  Go Runtime: stackPreempt clearing for function-mode analysis
// ────────────────────────────────────────────────────────────

/// Go runtime's stackPreempt sentinel value (0xfffffffffffffade on 64-bit).
/// When a goroutine's stackguard0 has this value, the runtime wants to preempt
/// this goroutine. Every Go function's prologue compares RSP against stackguard0;
/// because stackPreempt is enormous, the comparison always triggers the
/// "stack needs growth" path, which then calls runtime.gopreempt_m →
/// runtime.goschedImpl, descheduling the goroutine. For function-mode concolic
/// analysis this means the actual function body is never reached.
const GO_STACK_PREEMPT: u64 = 0xfffffffffffffade;

/// Default offset of stackguard0 in runtime.g struct (stable across Go versions).
const GO_G_STACKGUARD0_OFFSET: u64 = 0x10;

/// Default offset of stack.lo in runtime.g struct.
const GO_G_STACK_LO_OFFSET: u64 = 0x0;

/// Clear the Go goroutine stackPreempt flag if it is set.
///
/// In Go, register R14 holds the current goroutine pointer (`g`).
/// If `g.stackguard0 == runtime.stackPreempt`, every function prologue will
/// trigger preemption and execution never reaches the function body.
/// This function replaces the sentinel with `g.stack.lo` (the real stack guard),
/// allowing the function body to execute normally during concolic analysis.
pub fn clear_go_stack_preempt<'a>(executor: &mut ConcolicExecutor<'a>) -> bool {
    // Read R14 (the g pointer in Go gc runtime)
    let g_ptr = {
        let cpu_state = executor.state.cpu_state.lock().unwrap();
        match cpu_state.get_register_by_offset(0xb0, 64) {
            // R14
            Some(val) => val.concrete.to_u64(),
            None => {
                log!(
                    executor.state.logger,
                    "[GO-PREEMPT] Cannot read R14 (g pointer) - skipping stackPreempt check"
                );
                return false;
            }
        }
    };

    if g_ptr == 0 {
        log!(
            executor.state.logger,
            "[GO-PREEMPT] g pointer is nil - skipping stackPreempt check"
        );
        return false;
    }

    let stackguard0_addr = g_ptr + GO_G_STACKGUARD0_OFFSET;

    // Read the current stackguard0 value
    let stackguard0_val = match executor.state.memory.read_value(
        stackguard0_addr,
        64,
        &mut executor.state.logger.clone(),
    ) {
        Ok(val) => val.concrete.to_u64(),
        Err(e) => {
            log!(
                executor.state.logger,
                "[GO-PREEMPT] Cannot read stackguard0 at 0x{:x}: {:?}",
                stackguard0_addr,
                e
            );
            return false;
        }
    };

    if stackguard0_val != GO_STACK_PREEMPT {
        log!(
            executor.state.logger,
            "[GO-PREEMPT] stackguard0 = 0x{:x} (not stackPreempt) - no clearing needed",
            stackguard0_val
        );
        return false;
    }

    log!(
        executor.state.logger,
        "[GO-PREEMPT] Detected stackPreempt (0x{:x}) in goroutine g=0x{:x}",
        GO_STACK_PREEMPT,
        g_ptr
    );

    // Read stack.lo to get the safe replacement value
    let stack_lo_addr = g_ptr + GO_G_STACK_LO_OFFSET;
    let stack_lo = match executor.state.memory.read_value(
        stack_lo_addr,
        64,
        &mut executor.state.logger.clone(),
    ) {
        Ok(val) => val.concrete.to_u64(),
        Err(e) => {
            log!(
                executor.state.logger,
                "[GO-PREEMPT] Cannot read stack.lo at 0x{:x}: {:?}",
                stack_lo_addr,
                e
            );
            return false;
        }
    };

    log!(
        executor.state.logger,
        "[GO-PREEMPT] stack.lo = 0x{:x}, replacing stackguard0",
        stack_lo
    );

    // Write stack.lo to stackguard0 (clearing the preemption flag)
    let new_stackguard =
        MemoryValue::new(stack_lo, BV::from_u64(executor.context, stack_lo, 64), 64);

    match executor
        .state
        .memory
        .write_value(stackguard0_addr, &new_stackguard)
    {
        Ok(()) => {
            log!(
                executor.state.logger,
                "[GO-PREEMPT] ✓ Cleared stackPreempt: stackguard0 at 0x{:x} set to 0x{:x}",
                stackguard0_addr,
                stack_lo
            );
            println!(
                "[GO-PREEMPT] Cleared goroutine stackPreempt flag (was blocking function execution)"
            );
            true
        }
        Err(e) => {
            log!(
                executor.state.logger,
                "[GO-PREEMPT] Failed to write stackguard0: {:?}",
                e
            );
            false
        }
    }
}

// Helper function to check if a register specification is a stack location
pub fn is_stack_location(reg_spec: &str) -> bool {
    reg_spec.starts_with("STACK+") || reg_spec.starts_with("STACK-")
}

// Helper function to parse stack offset from "STACK+0x8" format
pub fn parse_stack_offset(reg_spec: &str) -> Option<i64> {
    if let Some(offset_str) = reg_spec.strip_prefix("STACK+") {
        if let Ok(offset) =
            i64::from_str_radix(offset_str.strip_prefix("0x").unwrap_or(offset_str), 16)
        {
            return Some(offset);
        }
    } else if let Some(offset_str) = reg_spec.strip_prefix("STACK-") {
        if let Ok(offset) =
            i64::from_str_radix(offset_str.strip_prefix("0x").unwrap_or(offset_str), 16)
        {
            return Some(-offset);
        }
    }
    None
}

// ────────────────────────────────────────────────────────────
//  String   (two regs)
// ────────────────────────────────────────────────────────────
pub fn initialize_string_argument<'a>(
    arg_name: &str,
    regs: &[&str], // exactly 2 regs
    conc: &mut Vec<ConcreteVar>,
    exec: &mut ConcolicExecutor<'a>,
) {
    // Go swap: if first reg is RDX/R8/R10 → (len,ptr)
    let (ptr_reg, len_reg) = match regs {
        [r1, r2] if *r1 == "RDX" || *r1 == "R8" || *r1 == "R10" => (*r2, *r1),
        [r1, r2] => (*r1, *r2),
        _ => {
            return;
        }
    };

    // Try to read the concrete length before we take any mutable borrows on `exec`
    let reg_spec = format!("{},{}", ptr_reg, len_reg);
    let concrete_len_opt = get_concrete_string_len_value_from_regs(&*exec, &reg_spec);

    let ctx = exec.context;
    let cpu = &mut exec.state.cpu_state.lock().unwrap();
    let log = &mut exec.state.logger;
    let solver = &mut exec.solver;

    println!(
        "Retrieved string argument '{}' – creating a symbolic Go string with ptr in {} and len in {}...",
        arg_name, ptr_reg, len_reg
    );

    let bv_ptr = BV::fresh_const(ctx, &format!("{}__ptr", arg_name), 64);
    let bv_len = BV::fresh_const(ctx, &format!("{}__len", arg_name), 64);

    exec.function_symbolic_arguments.insert(
        format!("{}__ptr", arg_name),
        SymbolicVar::Int(bv_ptr.clone()),
    );
    exec.function_symbolic_arguments.insert(
        format!("{}__len", arg_name),
        SymbolicVar::Int(bv_len.clone()),
    );

    // ptr ≠ 0, 8-byte aligned  |  len ≥ 1
    solver.assert(
        &bv_ptr
            .bvand(&BV::from_u64(ctx, 7, 64))
            ._eq(&BV::from_u64(ctx, 0, 64)),
    );
    solver.assert(&bv_ptr._eq(&BV::from_u64(ctx, 0, 64)).not());
    solver.assert(&bv_len.bvuge(&BV::from_u64(ctx, 1, 64)));

    // If we can read a concrete length for this string from the current dump/registers,
    // constrain the symbolic length to match it. This avoids unrealistic models where
    // len is an arbitrary 64-bit value (e.g., 2^64-1)
    if let Some(concrete_len) = concrete_len_opt {
        let len_bv_conc = BV::from_u64(ctx, concrete_len, 64);
        solver.assert(&bv_len._eq(&len_bv_conc));
        log!(
            log,
            "Constraining string '{}' symbolic length to concrete len={} from registers ({})",
            arg_name,
            concrete_len,
            reg_spec
        );
    }

    // helper: write symbolic BV into a register
    let mut write = |reg: &str, bv: &BV<'a>| {
        if let Some(off) = cpu.resolve_offset_from_register_name(reg) {
            let w = cpu.register_map.get(&off).map(|(_, w)| *w).unwrap_or(64);
            if let Some(orig) = cpu.get_register_by_offset(off, w) {
                conc.push(orig.concrete.clone());
                let cv = ConcolicVar {
                    concrete: orig.concrete.clone(),
                    symbolic: SymbolicVar::Int(bv.clone()),
                    ctx,
                };
                cpu.set_register_value_by_offset(off, cv, w).ok();
            }
        } else {
            log!(log, "WARN: unknown reg {}", reg);
        }
    };

    write(ptr_reg, &bv_ptr);
    write(len_reg, &bv_len);
    log!(
        log,
        "Init Go string '{}'  ptr:{} len:{}",
        arg_name,
        ptr_reg,
        len_reg
    );
}

/// Initialize string memory contents as symbolic bytes
/// This should be called after string arguments have been initialized
pub fn initialize_string_memory_contents<'a>(
    executor: &mut ConcolicExecutor<'a>,
    function_args: &[(String, String, String)],
) {
    log!(
        executor.state.logger,
        "=== INITIALIZING STRING MEMORY CONTENTS ==="
    );

    for (arg_name, reg_name, arg_type) in function_args {
        // Only process string types
        if arg_type != "string" {
            continue;
        }

        log!(
            executor.state.logger,
            "Processing string memory for '{}' of type '{}' (registers: {})",
            arg_name,
            arg_type,
            reg_name
        );

        // Get the string's pointer and length from tracked symbolic variables
        let ptr_var_name = format!("{}__ptr", arg_name);
        let len_var_name = format!("{}__len", arg_name);

        if let (Some(ptr_sym_var), Some(len_sym_var)) = (
            executor.function_symbolic_arguments.get(&ptr_var_name),
            executor.function_symbolic_arguments.get(&len_var_name),
        ) {
            if let (SymbolicVar::Int(_ptr_bv), SymbolicVar::Int(_len_bv)) =
                (ptr_sym_var, len_sym_var)
            {
                // Get concrete values from the actual registers specified in the signature
                let ptr_concrete = get_concrete_string_ptr_value_from_regs(executor, reg_name);
                let len_concrete = get_concrete_string_len_value_from_regs(executor, reg_name);

                if let (Some(ptr_addr), Some(str_len)) = (ptr_concrete, len_concrete) {
                    log!(
                        executor.state.logger,
                        "String '{}': ptr=0x{:x}, len={}",
                        arg_name,
                        ptr_addr,
                        str_len
                    );

                    // Clamp string length for performance (similar to slice clamping)
                    let bytes_to_init = {
                        let cap: u64 = 256; // Maximum string length to symbolically initialize
                        let actual_len = if str_len == 0 { 1 } else { str_len };
                        let clamped = if actual_len > cap { cap } else { actual_len };
                        if actual_len > cap {
                            log!(
                                executor.state.logger,
                                "Clamping string '{}' init from {} to {} bytes",
                                arg_name,
                                actual_len,
                                cap
                            );
                        }
                        clamped
                    };

                    // Initialize each byte of the string as symbolic
                    for i in 0..bytes_to_init {
                        let byte_addr = ptr_addr + i;
                        let byte_var_name = format!("{}_byte_{}", arg_name, i);

                        initialize_string_byte_memory(
                            executor,
                            &byte_var_name,
                            byte_addr,
                            arg_name,
                            i,
                        );
                    }
                } else {
                    log!(
                        executor.state.logger,
                        "WARNING: Could not extract concrete values for string '{}' (ptr={:?}, len={:?})",
                        arg_name,
                        ptr_concrete,
                        len_concrete
                    );
                }
            }
        }
    }

    log!(
        executor.state.logger,
        "=== FINISHED STRING MEMORY INITIALIZATION ==="
    );
}

/// Get concrete pointer value for a string argument from register specification
fn get_concrete_string_ptr_value_from_regs<'a>(
    executor: &ConcolicExecutor<'a>,
    reg_spec: &str,
) -> Option<u64> {
    // Parse register specification (e.g., "RAX,RBX" or "RDI,RSI")
    let regs: Vec<&str> = reg_spec.split(',').map(|s| s.trim()).collect();

    if regs.is_empty() {
        return None;
    }

    // For Go strings, the first register typically holds the pointer
    let ptr_reg = regs[0];

    log!(
        executor.state.logger.clone(),
        "[DEBUG]: Extracting string pointer from register '{}' (from spec '{}')",
        ptr_reg,
        reg_spec
    );

    if let Some(val) = get_concrete_value_from_location(executor, ptr_reg) {
        log!(
            executor.state.logger.clone(),
            "String pointer from register '{}' = 0x{:x}",
            ptr_reg,
            val
        );
        return Some(val);
    }

    None
}

/// Get concrete length value for a string argument from register specification
fn get_concrete_string_len_value_from_regs<'a>(
    executor: &ConcolicExecutor<'a>,
    reg_spec: &str,
) -> Option<u64> {
    // Parse register specification (e.g., "RAX,RBX" or "RDI,RSI")
    let regs: Vec<&str> = reg_spec.split(',').map(|s| s.trim()).collect();

    if regs.len() < 2 {
        log!(
            executor.state.logger.clone(),
            "WARNING: String register specification '{}' has less than 2 registers, cannot extract length",
            reg_spec
        );
        return None;
    }

    // For Go strings, the second register typically holds the length
    let len_reg = regs[1];

    log!(
        executor.state.logger.clone(),
        "[DEBUG]: Extracting string length from register '{}' (from spec '{}')",
        len_reg,
        reg_spec
    );

    if let Some(val) = get_concrete_value_from_location(executor, len_reg) {
        log!(
            executor.state.logger.clone(),
            "String length from register '{}' = {}",
            len_reg,
            val
        );
        return Some(val);
    }

    None
}

/// Initialize a single byte of string memory as symbolic
fn initialize_string_byte_memory<'a>(
    executor: &mut ConcolicExecutor<'a>,
    byte_var_name: &str,
    byte_addr: u64,
    string_name: &str,
    byte_index: u64,
) {
    log!(
        executor.state.logger,
        "Initializing string byte '{}' at 0x{:x} (string '{}', index {})",
        byte_var_name,
        byte_addr,
        string_name,
        byte_index
    );

    // Check if this memory address is valid
    if !executor.state.memory.is_valid_address(byte_addr) {
        log!(
            executor.state.logger,
            "WARNING: Invalid memory address 0x{:x} for string byte '{}' - skipping",
            byte_addr,
            byte_var_name
        );
        return;
    }

    // Read current byte value from memory
    match executor.state.memory.read_byte(byte_addr) {
        Ok(current_byte) => {
            log!(
                executor.state.logger,
                "Successfully read current byte from 0x{:x}: concrete=0x{:02x} ('{}')",
                byte_addr,
                current_byte.concrete.to_u64(),
                if current_byte.concrete.to_u64() >= 32 && current_byte.concrete.to_u64() <= 126 {
                    char::from(current_byte.concrete.to_u64() as u8).to_string()
                } else {
                    "non-printable".to_string()
                }
            );

            // Create fresh symbolic variable for this byte
            let byte_bv = BV::fresh_const(
                executor.context,
                byte_var_name,
                8, // 8 bits for a byte
            );

            // Add to tracked symbolic arguments
            executor
                .function_symbolic_arguments
                .insert(byte_var_name.to_string(), SymbolicVar::Int(byte_bv.clone()));

            // Create memory value with original concrete data but new symbolic variable
            let symbolic_memory_value =
                MemoryValue::new(current_byte.concrete.to_u64(), byte_bv.clone(), 8);

            // Write symbolic value back to memory
            match executor
                .state
                .memory
                .write_value(byte_addr, &symbolic_memory_value)
            {
                Ok(()) => {
                    log!(
                        executor.state.logger,
                        "✓ Successfully initialized string byte '{}' at 0x{:x} with fresh symbolic variable",
                        byte_var_name,
                        byte_addr
                    );
                }
                Err(e) => {
                    log!(
                        executor.state.logger,
                        "✗ Failed to write symbolic value for string byte '{}' at 0x{:x}: {}",
                        byte_var_name,
                        byte_addr,
                        e
                    );
                }
            }
        }
        Err(e) => {
            log!(
                executor.state.logger,
                "✗ Failed to read current byte for string '{}' at 0x{:x}: {}",
                byte_var_name,
                byte_addr,
                e
            );
        }
    }
}

// Enhanced helper function for single-register argument initialization that handles stack locations
pub fn initialize_single_register_argument<'a>(
    arg_name: &str,
    reg_spec: &str,
    arg_type: &str,
    concrete_values: &mut Vec<ConcreteVar>,
    executor: &mut ConcolicExecutor<'a>,
) {
    println!(
        "Retrieved single-register argument '{}' of type '{}' in '{}' – creating a symbolic register variable...",
        arg_name, arg_type, reg_spec
    );

    if is_stack_location(reg_spec) {
        // Handle stack location
        initialize_stack_argument(arg_name, reg_spec, arg_type, concrete_values, executor);
    } else {
        // Handle regular register
        initialize_register_argument(arg_name, reg_spec, arg_type, concrete_values, executor);
    }
}

// Handle regular register initialization
pub fn initialize_register_argument<'a>(
    arg_name: &str,
    reg_name: &str,
    arg_type: &str,
    concrete_values: &mut Vec<ConcreteVar>,
    executor: &mut ConcolicExecutor<'a>,
) {
    let cpu = &mut executor.state.cpu_state.lock().unwrap();
    if let Some(offset) = cpu.resolve_offset_from_register_name(reg_name) {
        let bit_width = cpu.register_map.get(&offset).map(|(_, w)| *w).unwrap_or(64);
        if let Some(original) = cpu.get_register_by_offset(offset, bit_width) {
            let orig_conc = original.concrete.clone();
            concrete_values.push(orig_conc.clone());

            let bv = BV::fresh_const(
                executor.context,
                &format!("{}_{}", arg_name, reg_name),
                bit_width,
            );
            // Type-driven domain constraints (no user flags):
            // - Signed Go ints (int, int{8,16,32,64}): enforce non-negative and <= type max
            // - Unsigned Go ints (uint, uint{8,16,32,64}, byte, uintptr): enforce <= type max
            {
                let is_signed_int =
                    matches!(arg_type, "int" | "int64" | "int32" | "int16" | "int8");
                let is_unsigned_int = matches!(
                    arg_type,
                    "uint" | "uint64" | "uint32" | "uint16" | "uint8" | "byte" | "uintptr"
                );
                if is_signed_int {
                    let typed_bits: u32 = match arg_type {
                        "int8" => 8,
                        "int16" => 16,
                        "int32" => 32,
                        _ => 64, // int or int64 on amd64
                    };
                    // lower bound: 0 (reflect typical CLI domain and avoid negative models)
                    let zero = BV::from_u64(executor.context, 0, bit_width);
                    executor.solver.assert(&bv.bvuge(&zero));
                    // upper bound: max signed for logical width
                    let max_signed = if typed_bits == 64 {
                        u64::MAX >> 1
                    } else {
                        ((1u128 << (typed_bits - 1)) - 1) as u64
                    };
                    let upper = BV::from_u64(executor.context, max_signed, bit_width);
                    executor.solver.assert(&bv.bvule(&upper));
                    log!(
                        executor.state.logger,
                        "Applied signed int domain for '{}' [0..{}] ({} bits logical, {} bits reg)",
                        arg_name,
                        max_signed,
                        typed_bits,
                        bit_width
                    );
                } else if is_unsigned_int {
                    let typed_bits: u32 = match arg_type {
                        "uint8" | "byte" => 8,
                        "uint16" => 16,
                        "uint32" => 32,
                        _ => 64, // uint, uint64, uintptr
                    };
                    let max_val = if typed_bits == 64 {
                        u64::MAX
                    } else {
                        ((1u128 << typed_bits) - 1) as u64
                    };
                    let upper = BV::from_u64(executor.context, max_val, bit_width);
                    executor.solver.assert(&bv.bvule(&upper));
                    log!(
                        executor.state.logger,
                        "Applied unsigned int domain for '{}' [0..{}] ({} bits logical, {} bits reg)",
                        arg_name,
                        max_val,
                        typed_bits,
                        bit_width
                    );
                }
            }
            executor
                .function_symbolic_arguments
                .insert(arg_name.to_string(), SymbolicVar::Int(bv.clone()));

            let sym = SymbolicVar::Int(bv.clone());
            let conc = ConcolicVar {
                concrete: orig_conc,
                symbolic: sym,
                ctx: executor.context,
            };

            match cpu.set_register_value_by_offset(offset, conc, bit_width) {
                Ok(()) => log!(
                    executor.state.logger,
                    "Initialized '{}' => {} (0x{:x}) as symbolic {}",
                    arg_name,
                    reg_name,
                    offset,
                    arg_type
                ),
                Err(e) => log!(executor.state.logger, "Failed to set {}: {}", reg_name, e),
            }
        }
    } else {
        log!(
            executor.state.logger,
            "WARNING: unknown register '{}' for arg {}",
            reg_name,
            arg_name
        );
    }
}

// Handle stack location initialization
pub fn initialize_stack_argument<'a>(
    arg_name: &str,
    stack_spec: &str,
    arg_type: &str,
    concrete_values: &mut Vec<ConcreteVar>,
    executor: &mut ConcolicExecutor<'a>,
) {
    if let Some(stack_offset) = parse_stack_offset(stack_spec) {
        // Get current RSP value
        if let Some(rsp_reg) = executor
            .state
            .cpu_state
            .lock()
            .unwrap()
            .get_register_by_offset(0x20, 64)
        {
            let rsp_value = rsp_reg.concrete.to_u64();
            let stack_address = (rsp_value as i64 + stack_offset) as u64;

            log!(
                executor.state.logger,
                "Calculating stack address: RSP(0x{:x}) + offset({}) = 0x{:x}",
                rsp_value,
                stack_offset,
                stack_address
            );

            // Read current value from stack
            match executor
                .state
                .memory
                .read_u64(stack_address, &mut executor.state.logger)
            {
                Ok(current_stack_value) => {
                    concrete_values.push(current_stack_value.concrete.clone());

                    // Create symbolic variable for stack location
                    let bv = BV::fresh_const(
                        executor.context,
                        &format!(
                            "{}_{}",
                            arg_name,
                            stack_spec.replace("+", "plus").replace("-", "minus")
                        ),
                        64,
                    );

                    // Type-driven domain constraints for stack-based integer args
                    {
                        let is_signed_int =
                            matches!(arg_type, "int" | "int64" | "int32" | "int16" | "int8");
                        let is_unsigned_int = matches!(
                            arg_type,
                            "uint" | "uint64" | "uint32" | "uint16" | "uint8" | "byte" | "uintptr"
                        );
                        if is_signed_int {
                            let typed_bits: u32 = match arg_type {
                                "int8" => 8,
                                "int16" => 16,
                                "int32" => 32,
                                _ => 64,
                            };
                            let zero = BV::from_u64(executor.context, 0, 64);
                            executor.solver.assert(&bv.bvuge(&zero));
                            let max_signed = if typed_bits == 64 {
                                u64::MAX >> 1
                            } else {
                                ((1u128 << (typed_bits - 1)) - 1) as u64
                            };
                            let upper = BV::from_u64(executor.context, max_signed, 64);
                            executor.solver.assert(&bv.bvule(&upper));
                            log!(
                                executor.state.logger,
                                "Applied signed int domain for '{}' [0..{}] ({} bits logical, 64 bits stack)",
                                arg_name,
                                max_signed,
                                typed_bits
                            );
                        } else if is_unsigned_int {
                            let typed_bits: u32 = match arg_type {
                                "uint8" | "byte" => 8,
                                "uint16" => 16,
                                "uint32" => 32,
                                _ => 64,
                            };
                            let max_val = if typed_bits == 64 {
                                u64::MAX
                            } else {
                                ((1u128 << typed_bits) - 1) as u64
                            };
                            let upper = BV::from_u64(executor.context, max_val, 64);
                            executor.solver.assert(&bv.bvule(&upper));
                            log!(
                                executor.state.logger,
                                "Applied unsigned int domain for '{}' [0..{}] ({} bits logical, 64 bits stack)",
                                arg_name,
                                max_val,
                                typed_bits
                            );
                        }
                    }

                    executor
                        .function_symbolic_arguments
                        .insert(arg_name.to_string(), SymbolicVar::Int(bv.clone()));

                    // Create concolic variable with original concrete value but new symbolic value
                    let stack_concolic_mem =
                        MemoryValue::new(current_stack_value.concrete.to_u64(), bv.clone(), 64);

                    // Write symbolic value back to stack
                    match executor
                        .state
                        .memory
                        .write_u64(stack_address, &stack_concolic_mem)
                    {
                        Ok(()) => log!(
                            executor.state.logger,
                            "Initialized '{}' => {} (0x{:x}) as symbolic {} on stack",
                            arg_name,
                            stack_spec,
                            stack_address,
                            arg_type
                        ),
                        Err(e) => log!(
                            executor.state.logger,
                            "Failed to write symbolic value to stack address 0x{:x}: {}",
                            stack_address,
                            e
                        ),
                    }
                }
                Err(e) => log!(
                    executor.state.logger,
                    "Failed to read from stack address 0x{:x}: {}",
                    stack_address,
                    e
                ),
            }
        } else {
            log!(
                executor.state.logger,
                "WARNING: Could not get RSP register value for stack calculation"
            );
        }
    } else {
        log!(
            executor.state.logger,
            "WARNING: Could not parse stack offset from '{}'",
            stack_spec
        );
    }
}

// ────────────────────────────────────────────────────────────
//  Multi-register slice ([]T)
// ────────────────────────────────────────────────────────────
// Enhanced slice initialization that handles mixed register/stack specifications
pub fn initialize_slice_argument<'a>(
    arg_name: &str,
    arg_type: &str,
    regs: &[&str],
    conc: &mut Vec<ConcreteVar>,
    executor: &mut ConcolicExecutor<'a>,
) {
    if regs.len() < 2 {
        log!(
            executor.state.logger,
            "Slice '{}' has <2 locations: {:?}",
            arg_name,
            regs
        );
        return;
    }

    let ctx = executor.context;
    // Determine correct mapping of (ptr,len,cap) from concrete values to avoid mis-ordered DWARF/ABI cases
    let mut ptr_spec = regs[0];
    let mut len_spec = regs[1];
    let mut cap_spec: Option<&str> = if regs.len() >= 3 { Some(regs[2]) } else { None };

    let inner_ty = &arg_type[2..];
    let elem_desc = if inner_ty.starts_with('[') {
        // Handle array type, e.g., "[3]byte" or "[4]int"
        if let Some(caps) = Regex::new(r"^\[(\d+)\](.+)$").unwrap().captures(inner_ty) {
            TypeDesc::Array {
                element: Box::new(TypeDesc::Primitive(caps[2].trim().into())),
                count: Some(caps[1].parse::<u64>().unwrap()),
            }
        } else {
            TypeDesc::Unknown(inner_ty.into())
        }
    } else {
        TypeDesc::Primitive(inner_ty.to_string())
    };

    let default_len = 3;
    let slice_sv = SymbolicVar::make_symbolic_slice(ctx, arg_name, &elem_desc, default_len);
    executor
        .function_symbolic_arguments
        .insert(arg_name.into(), slice_sv.clone());

    if let SymbolicVar::Slice(slice) = &slice_sv {
        // Optionally re-map (ptr,len,cap) based on concrete values and plausibility checks
        {
            // Gather candidates
            let mut specs: Vec<&str> = Vec::new();
            specs.push(ptr_spec);
            specs.push(len_spec);
            if let Some(c3) = cap_spec {
                specs.push(c3);
            }

            // Identify pointer-like spec: non-zero, 8-byte aligned, valid address
            let mut detected_ptr: Option<&str> = None;
            for s in &specs {
                if let Some(v) = get_concrete_value_from_location(executor, s) {
                    if v != 0 && (v & 7) == 0 && executor.state.memory.is_valid_address(v) {
                        detected_ptr = Some(*s);
                        break;
                    }
                }
            }

            if let Some(p) = detected_ptr {
                // Remaining are numeric; choose len/cap by magnitude (len <= cap when both present)
                let rest: Vec<&str> = specs.into_iter().filter(|x| *x != p).collect();
                if !rest.is_empty() {
                    // Read their concrete values (fallback to u64::MAX if missing)
                    let mut vals: Vec<(u64, &str)> = rest
                        .iter()
                        .map(|s| {
                            (
                                get_concrete_value_from_location(executor, s).unwrap_or(u64::MAX),
                                *s,
                            )
                        })
                        .collect();
                    vals.sort_by_key(|(v, _)| *v);
                    // Smallest -> len, next -> cap (if exists)
                    ptr_spec = p;
                    len_spec = vals[0].1;
                    cap_spec = if vals.len() >= 2 {
                        Some(vals[1].1)
                    } else {
                        None
                    };
                } else {
                    // Only pointer detected (2-reg slice), keep original len
                    ptr_spec = p;
                }
                log!(
                    executor.state.logger,
                    "Resolved slice '{}' mapping: ptr={}, len={}{}",
                    arg_name,
                    ptr_spec,
                    len_spec,
                    cap_spec.map(|c| format!(", cap={}", c)).unwrap_or_default()
                );
            }
        }

        // Handle solver assertions
        {
            let solver = &mut executor.solver;
            solver.assert(&slice.pointer._eq(&BV::from_u64(ctx, 0, 64)).not());
            solver.assert(
                &slice
                    .pointer
                    .bvand(&BV::from_u64(ctx, 7, 64))
                    ._eq(&BV::from_u64(ctx, 0, 64)),
            );
            solver.assert(&slice.length.bvuge(&BV::from_u64(ctx, 1, 64)));
        }

        // Write pointer (can be register or stack)
        write_symbolic_to_location(ptr_spec, &slice.pointer, conc, executor, "ptr", true);

        // Write length (can be register or stack)
        write_symbolic_to_location(len_spec, &slice.length, conc, executor, "len", false);

        // Handle capacity if present
        if let Some(cap_loc) = cap_spec {
            let cap_bv = BV::fresh_const(ctx, &format!("{}_cap", arg_name), 64);
            write_symbolic_to_location(cap_loc, &cap_bv, conc, executor, "cap", false);
        }

        log!(
            executor.state.logger,
            "Initialized slice '{}' ptr:{} len:{} with UNIFIED variables",
            arg_name,
            ptr_spec,
            len_spec
        );
    }
}

// Helper function to write a symbolic BV to either a register or stack location
fn write_symbolic_to_location<'a>(
    location_spec: &str,
    symbolic_bv: &BV<'a>,
    conc: &mut Vec<ConcreteVar>,
    executor: &mut ConcolicExecutor<'a>,
    field_name: &str,
    anchor_to_concrete: bool,
) {
    if is_stack_location(location_spec) {
        // Handle stack location
        if let Some(stack_offset) = parse_stack_offset(location_spec) {
            if let Some(rsp_reg) = executor
                .state
                .cpu_state
                .lock()
                .unwrap()
                .get_register_by_offset(0x20, 64)
            {
                let rsp_value = rsp_reg.concrete.to_u64();
                let stack_address = (rsp_value as i64 + stack_offset) as u64;

                if let Ok(current_val) = executor
                    .state
                    .memory
                    .read_u64(stack_address, &mut executor.state.logger)
                {
                    conc.push(current_val.concrete.clone());

                    let stack_concolic_mem =
                        MemoryValue::new(current_val.concrete.to_u64(), symbolic_bv.clone(), 64);

                    // Optionally anchor symbol to the current concrete value for reproducibility
                    if anchor_to_concrete {
                        let ctx = executor.context;
                        let solver = &mut executor.solver;
                        solver.assert(&symbolic_bv._eq(&BV::from_u64(
                            ctx,
                            current_val.concrete.to_u64(),
                            64,
                        )));
                    }

                    executor
                        .state
                        .memory
                        .write_u64(stack_address, &stack_concolic_mem)
                        .ok();
                    log!(
                        executor.state.logger,
                        "Wrote {} to stack location {} (0x{:x})",
                        field_name,
                        location_spec,
                        stack_address
                    );
                }
            }
        }
    } else {
        // Handle register location
        let cpu = &mut executor.state.cpu_state.lock().unwrap();
        if let Some(offset) = cpu.resolve_offset_from_register_name(location_spec) {
            let bit_width = cpu.register_map.get(&offset).map(|(_, w)| *w).unwrap_or(64);
            if let Some(original) = cpu.get_register_by_offset(offset, bit_width) {
                conc.push(original.concrete.clone());

                let reg_concolic = ConcolicVar {
                    concrete: original.concrete.clone(),
                    symbolic: SymbolicVar::Int(symbolic_bv.clone()),
                    ctx: executor.context,
                };

                // Optionally anchor symbol to the current concrete value for reproducibility
                if anchor_to_concrete {
                    let ctx = executor.context;
                    let solver = &mut executor.solver;
                    solver.assert(&symbolic_bv._eq(&BV::from_u64(
                        ctx,
                        original.concrete.to_u64(),
                        bit_width,
                    )));
                }

                cpu.set_register_value_by_offset(offset, reg_concolic, bit_width)
                    .ok();
                log!(
                    executor.state.logger,
                    "Wrote {} to register {} (0x{:x})",
                    field_name,
                    location_spec,
                    offset
                );
            }
        }
    }
}

// ────────────────────────────────────────────────────────────
//  Single-register slice (rare)
// ────────────────────────────────────────────────────────────
pub fn initialize_single_register_slice<'a>(
    arg_name: &str,
    arg_type: &str,
    reg: &str,
    conc: &mut Vec<ConcreteVar>,
    exec: &mut ConcolicExecutor<'a>,
) {
    let ctx = exec.context;

    let elem_td = TypeDesc::Primitive(arg_type[2..].to_string());
    let sv = SymbolicVar::make_symbolic_slice(ctx, arg_name, &elem_td, 2);
    exec.function_symbolic_arguments
        .insert(arg_name.into(), sv.clone());

    if let SymbolicVar::Slice(slice) = &sv {
        // Handle solver assertions
        {
            let solver = &mut exec.solver;
            solver.assert(
                &slice
                    .pointer
                    .bvand(&BV::from_u64(ctx, 7, 64))
                    ._eq(&BV::from_u64(ctx, 0, 64)),
            );
            solver.assert(&slice.pointer._eq(&BV::from_u64(ctx, 0, 64)).not());
            solver.assert(&slice.length.bvuge(&BV::from_u64(ctx, 1, 64)));
        }

        // Handle CPU state
        {
            let cpu = &mut exec.state.cpu_state.lock().unwrap();
            if let Some(off) = cpu.resolve_offset_from_register_name(reg) {
                let w = cpu.register_map.get(&off).map(|(_, w)| *w).unwrap_or(64);
                if let Some(orig) = cpu.get_register_by_offset(off, w) {
                    conc.push(orig.concrete.clone());
                    let cv = ConcolicVar {
                        concrete: orig.concrete.clone(),
                        symbolic: SymbolicVar::Int(slice.pointer.clone()),
                        ctx,
                    };
                    cpu.set_register_value_by_offset(off, cv, w).ok();
                }
            } else {
                log!(
                    exec.state.logger,
                    "WARN: unknown reg '{}' for '{}'",
                    reg,
                    arg_name
                );
            }
        }
    }
}

/// Initializes the memory contents pointed to by slices symbolically
/// This should be called after all slice arguments have been initialized
pub fn initialize_slice_memory_contents<'a>(
    executor: &mut ConcolicExecutor<'a>,
    function_args: &[(String, String, String)],
) {
    log!(
        executor.state.logger,
        "=== INITIALIZING SLICE MEMORY CONTENTS ==="
    );

    for (arg_name, reg_name, arg_type) in function_args {
        // Only process slice types
        if !arg_type.starts_with("[]") {
            continue;
        }

        log!(
            executor.state.logger,
            "Processing slice memory for '{}' of type '{}'",
            arg_name,
            arg_type
        );

        // Get the slice's symbolic variables
        if let Some(slice_sym_var) = executor.function_symbolic_arguments.get(arg_name) {
            if let SymbolicVar::Slice(_slice) = slice_sym_var {
                // Get concrete values from registers to determine memory layout
                let (ptr_concrete, len_concrete, _cap_concrete) =
                    extract_slice_concrete_values(executor, reg_name);

                if let (Some(ptr_addr), Some(slice_len)) = (ptr_concrete, len_concrete) {
                    // If the slice header points outside the captured memory, don't spam per‑element warnings:
                    if !executor.state.memory.is_valid_address(ptr_addr) {
                        log!(
                    executor.state.logger,
                    "WARNING: Slice '{}' header has invalid ptr=0x{:x} (len={}) – skipping concrete element initialization and keeping only the symbolic header.",
                    arg_name,
                    ptr_addr,
                    slice_len
                );
                        continue;
                    }

                    // Determine element size and type
                    let (element_size, element_type) = parse_slice_element_info(arg_type);

                    log!(
                        executor.state.logger,
                        "Slice '{}': ptr=0x{:x}, len={}, element_size={}, element_type='{}'",
                        arg_name,
                        ptr_addr,
                        slice_len,
                        element_size,
                        element_type
                    );

                    // Clamp initialization; also ensure we materialize at least 3 elements
                    let elems_to_init = {
                        let cap: u64 = 64;
                        let base = if slice_len == 0 { 1 } else { slice_len };
                        let n = if base > cap { cap } else { base };
                        let m = if n < 3 { 3 } else { n };
                        if base > cap {
                            log!(
                                executor.state.logger,
                                "Clamping slice '{}' init from {} to {} elements",
                                arg_name,
                                base,
                                cap
                            );
                        }
                        m
                    };

                    // Initialize memory for each element in the slice (clamped)
                    for i in 0..elems_to_init {
                        let element_addr = ptr_addr + (i * element_size);

                        // Create symbolic variable for this element
                        let element_var_name = format!("{}[{}]", arg_name, i);

                        initialize_slice_element_memory(
                            executor,
                            &element_var_name,
                            element_addr,
                            element_size,
                            &element_type,
                        );
                    }
                } else {
                    log!(
                        executor.state.logger,
                        "WARNING: Could not extract concrete values for slice '{}' (ptr={:?}, len={:?})",
                        arg_name,
                        ptr_concrete,
                        len_concrete
                    );
                }
            }
        }
    }

    log!(
        executor.state.logger,
        "=== FINISHED SLICE MEMORY INITIALIZATION ==="
    );
}

/// Extract concrete pointer, length, and capacity values from slice registers
fn extract_slice_concrete_values<'a>(
    executor: &ConcolicExecutor<'a>,
    reg_spec: &str,
) -> (Option<u64>, Option<u64>, Option<u64>) {
    log!(
        executor.state.logger.clone(),
        "[DEBUG]: extract_slice_concrete_values called with reg_spec='{}'",
        reg_spec
    );

    if !reg_spec.contains(',') {
        // Single register case - only pointer available
        if let Some(ptr_val) = get_concrete_value_from_location(executor, reg_spec) {
            log!(
                executor.state.logger.clone(),
                "[DEBUG]: Single register '{}' = 0x{:x}",
                reg_spec,
                ptr_val
            );
            return (Some(ptr_val), None, None);
        }
        return (None, None, None);
    }

    let regs: Vec<&str> = reg_spec.split(',').collect();
    log!(
        executor.state.logger.clone(),
        "[DEBUG]: Split registers: {:?}",
        regs
    );

    let ptr_concrete = if regs.len() >= 1 {
        let val = get_concrete_value_from_location(executor, regs[0]);
        log!(
            executor.state.logger.clone(),
            "[DEBUG]: Register '{}' (ptr) = {:?}",
            regs[0],
            val
        );
        val
    } else {
        None
    };

    let len_concrete = if regs.len() >= 2 {
        let val = get_concrete_value_from_location(executor, regs[1]);
        log!(
            executor.state.logger.clone(),
            "[DEBUG]: Register '{}' (len) = {:?}",
            regs[1],
            val
        );
        val
    } else {
        None
    };

    let cap_concrete = if regs.len() >= 3 {
        let val = get_concrete_value_from_location(executor, regs[2]);
        log!(
            executor.state.logger.clone(),
            "[DEBUG]: Register '{}' (cap) = {:?}",
            regs[2],
            val
        );
        val
    } else {
        None
    };

    log!(
        executor.state.logger.clone(),
        "[DEBUG]: Final values - ptr={:?}, len={:?}, cap={:?}",
        ptr_concrete,
        len_concrete,
        cap_concrete
    );
    (ptr_concrete, len_concrete, cap_concrete)
}

/// Get concrete value from either a register or stack location
fn get_concrete_value_from_location<'a>(
    executor: &ConcolicExecutor<'a>,
    location_spec: &str,
) -> Option<u64> {
    log!(
        executor.state.logger.clone(),
        "[DEBUG]: get_concrete_value_from_location called with '{}'",
        location_spec
    );

    if is_stack_location(location_spec) {
        // Handle stack location
        if let Some(stack_offset) = parse_stack_offset(location_spec) {
            if let Some(rsp_reg) = executor
                .state
                .cpu_state
                .lock()
                .unwrap()
                .get_register_by_offset(0x20, 64)
            {
                let rsp_value = rsp_reg.concrete.to_u64();
                let stack_address = (rsp_value as i64 + stack_offset) as u64;

                if let Ok(stack_val) = executor
                    .state
                    .memory
                    .read_u64(stack_address, &mut executor.state.logger.clone())
                {
                    let concrete_val = stack_val.concrete.to_u64();
                    log!(
                        executor.state.logger.clone(),
                        "[DEBUG]: Stack location '{}' concrete value = 0x{:x}",
                        location_spec,
                        concrete_val
                    );
                    return Some(concrete_val);
                }
            }
        }
    } else {
        // Handle register location
        let cpu = executor.state.cpu_state.lock().unwrap();
        if let Some(offset) = cpu.resolve_offset_from_register_name(location_spec) {
            let bit_width = cpu.register_map.get(&offset).map(|(_, w)| *w).unwrap_or(64);
            log!(
                executor.state.logger.clone(),
                "[DEBUG]: Register '{}' resolved to offset 0x{:x}, bit_width={}",
                location_spec,
                offset,
                bit_width
            );

            if let Some(reg_val) = cpu.get_register_by_offset(offset, bit_width) {
                let concrete_val = reg_val.concrete.to_u64();
                log!(
                    executor.state.logger.clone(),
                    "[DEBUG]: Register '{}' concrete value = 0x{:x}",
                    location_spec,
                    concrete_val
                );
                return Some(concrete_val);
            } else {
                log!(
                    executor.state.logger.clone(),
                    "[DEBUG]: Could not get register value for '{}'",
                    location_spec
                );
            }
        } else {
            log!(
                executor.state.logger.clone(),
                "[DEBUG]: Could not resolve register name '{}'",
                location_spec
            );
        }
    }
    log!(
        executor.state.logger.clone(),
        "[DEBUG]: get_concrete_value_from_location returning None for '{}'",
        location_spec
    );
    None
}

/// Parse slice element information from type string
fn parse_slice_element_info(slice_type: &str) -> (u64, String) {
    let inner_type = &slice_type[2..]; // Remove "[]" prefix

    // Handle array types like "[32]byte"
    if inner_type.starts_with('[') {
        if let Some(caps) = Regex::new(r"^\[(\d+)\](.+)$").unwrap().captures(inner_type) {
            let array_size: u64 = caps[1].parse().unwrap_or(1);
            let element_type = caps[2].trim().to_string();
            let base_size = get_type_size(&element_type);

            // For [][32]byte, this is an array of 32 bytes, so total size is 32 * 1 = 32
            let total_size = array_size * base_size;

            return (total_size, inner_type.to_string());
        }
    }

    // Handle primitive types
    let size = get_type_size(inner_type);
    (size, inner_type.to_string())
}

/// Get the size in bytes for a Go type
fn get_type_size(type_name: &str) -> u64 {
    match type_name {
        "byte" | "uint8" | "int8" => 1,
        "uint16" | "int16" => 2,
        "uint32" | "int32" | "float32" => 4,
        "uint64" | "int64" | "float64" | "int" | "uint" | "uintptr" => 8,
        "string" => 16, // ptr (8) + len (8)
        "bool" => 1,
        _ => {
            // For unknown types, assume pointer size
            8
        }
    }
}

/// Initialize a single slice element in memory
fn initialize_slice_element_memory<'a>(
    executor: &mut ConcolicExecutor<'a>,
    element_name: &str,
    element_addr: u64,
    element_size: u64,
    element_type: &str,
) {
    log!(
        executor.state.logger,
        "Initializing slice element '{}' at 0x{:x} (size={}, type='{}')",
        element_name,
        element_addr,
        element_size,
        element_type
    );

    // Check if this memory address is valid
    if !executor.state.memory.is_valid_address(element_addr) {
        log!(
            executor.state.logger,
            "WARNING: Invalid memory address 0x{:x} for slice element '{}' - skipping",
            element_addr,
            element_name
        );
        return;
    }

    // Check if the entire element range is valid
    let end_addr = element_addr + element_size - 1;
    if !executor.state.memory.is_valid_address(end_addr) {
        log!(
            executor.state.logger,
            "WARNING: Memory range 0x{:x}-0x{:x} not fully valid for slice element '{}' - skipping",
            element_addr,
            end_addr,
            element_name
        );
        return;
    }

    // Ensure element_size is reasonable (not too large)
    if element_size > 1024 {
        log!(
            executor.state.logger,
            "WARNING: Element size {} too large for slice element '{}' - skipping",
            element_size,
            element_name
        );
        return;
    }

    // Handle different element sizes - read_value only supports up to 128 bits (16 bytes)
    let bit_size = (element_size * 8) as u32;

    // Special handling for Go strings: decompose into ptr (8 bytes) + len (8 bytes)
    // This allows the solver to reason about string length constraints (e.g., len == 0 for panics)
    if element_type == "string" && element_size == 16 {
        log!(
            executor.state.logger,
            "String element '{}' - decomposing into ptr + len symbolic variables",
            element_name
        );

        let ptr_addr = element_addr;
        let len_addr = element_addr + 8;

        // Read concrete ptr value
        let ptr_concrete =
            match executor
                .state
                .memory
                .read_value(ptr_addr, 64, &mut executor.state.logger.clone())
            {
                Ok(val) => val.concrete.to_u64(),
                Err(e) => {
                    log!(
                        executor.state.logger,
                        "Failed to read string ptr at 0x{:x}: {}",
                        ptr_addr,
                        e
                    );
                    return;
                }
            };

        // Read concrete len value
        let len_concrete =
            match executor
                .state
                .memory
                .read_value(len_addr, 64, &mut executor.state.logger.clone())
            {
                Ok(val) => val.concrete.to_u64(),
                Err(e) => {
                    log!(
                        executor.state.logger,
                        "Failed to read string len at 0x{:x}: {}",
                        len_addr,
                        e
                    );
                    return;
                }
            };

        log!(
            executor.state.logger,
            "String '{}': concrete ptr=0x{:x}, len={}",
            element_name,
            ptr_concrete,
            len_concrete
        );

        // Create separate symbolic variables for ptr and len
        let ptr_var_name = format!("{}__ptr", element_name.replace("[", "_").replace("]", "_"));
        let len_var_name = format!("{}__len", element_name.replace("[", "_").replace("]", "_"));

        let ptr_bv = BV::fresh_const(executor.context, &ptr_var_name, 64);
        let len_bv = BV::fresh_const(executor.context, &len_var_name, 64);

        // Track both symbolic variables
        executor.function_symbolic_arguments.insert(
            format!("{}__ptr", element_name),
            SymbolicVar::Int(ptr_bv.clone()),
        );
        executor.function_symbolic_arguments.insert(
            format!("{}__len", element_name),
            SymbolicVar::Int(len_bv.clone()),
        );

        // Write ptr symbolic value to memory
        let ptr_mem_value = MemoryValue::new(ptr_concrete, ptr_bv.clone(), 64);
        if let Err(e) = executor.state.memory.write_value(ptr_addr, &ptr_mem_value) {
            log!(
                executor.state.logger,
                "Failed to write string ptr symbolic: {}",
                e
            );
        }

        // Write len symbolic value to memory
        let len_mem_value = MemoryValue::new(len_concrete, len_bv.clone(), 64);
        if let Err(e) = executor.state.memory.write_value(len_addr, &len_mem_value) {
            log!(
                executor.state.logger,
                "Failed to write string len symbolic: {}",
                e
            );
        }

        log!(
            executor.state.logger,
            "✓ Initialized string element '{}' with separate ptr/len symbolic variables",
            element_name
        );

        return;
    }

    if element_size <= 16 {
        // Use read_value for small elements (≤ 128 bits)
        match executor.state.memory.read_value(
            element_addr,
            bit_size,
            &mut executor.state.logger.clone(),
        ) {
            Ok(current_value) => {
                log!(
                    executor.state.logger,
                    "Successfully read current value from 0x{:x}: concrete=0x{:x}",
                    element_addr,
                    current_value.concrete.to_u64()
                );

                // Create fresh symbolic variable for this element
                let element_bv = BV::fresh_const(
                    executor.context,
                    &format!(
                        "slice_elem_{}",
                        element_name.replace("[", "_").replace("]", "_")
                    ),
                    bit_size,
                );

                // Add to tracked symbolic arguments
                executor.function_symbolic_arguments.insert(
                    element_name.to_string(),
                    SymbolicVar::Int(element_bv.clone()),
                );

                // Create memory value with original concrete data but new symbolic variable
                let symbolic_memory_value = MemoryValue::new(
                    current_value.concrete.to_u64(),
                    element_bv.clone(),
                    bit_size,
                );

                // Write symbolic value back to memory
                match executor
                    .state
                    .memory
                    .write_value(element_addr, &symbolic_memory_value)
                {
                    Ok(()) => {
                        log!(
                            executor.state.logger,
                            "✓ Successfully initialized slice element '{}' at 0x{:x} with fresh symbolic variable",
                            element_name,
                            element_addr
                        );
                    }
                    Err(e) => {
                        log!(
                            executor.state.logger,
                            "✗ Failed to write symbolic value for slice element '{}' at 0x{:x}: {}",
                            element_name,
                            element_addr,
                            e
                        );
                    }
                }
            }
            Err(e) => {
                log!(
                    executor.state.logger,
                    "✗ Failed to read current value for slice element '{}' at 0x{:x} (size={}): {}",
                    element_name,
                    element_addr,
                    element_size,
                    e
                );
            }
        }
    } else {
        // For large elements (>16 bytes), use read_bytes and create symbolic value manually
        log!(
            executor.state.logger,
            "Large element ({}bytes) - using byte-level initialization",
            element_size
        );

        match executor
            .state
            .memory
            .read_bytes(element_addr, element_size as usize)
        {
            Ok(concrete_bytes) => {
                log!(
                    executor.state.logger,
                    "Successfully read {} bytes from 0x{:x}: {:02x?}...",
                    concrete_bytes.len(),
                    element_addr,
                    &concrete_bytes[..std::cmp::min(8, concrete_bytes.len())] // Show first 8 bytes
                );

                // Create fresh symbolic variable for this element
                let element_bv = BV::fresh_const(
                    executor.context,
                    &format!(
                        "slice_elem_{}",
                        element_name.replace("[", "_").replace("]", "_")
                    ),
                    bit_size,
                );

                // Add to tracked symbolic arguments
                executor.function_symbolic_arguments.insert(
                    element_name.to_string(),
                    SymbolicVar::Int(element_bv.clone()),
                );

                // Write symbolic bytes back to memory using write_bytes
                // Create symbolic bytes - each byte gets a portion of the symbolic variable
                let symbolic_bytes: Vec<Option<Arc<BV>>> = (0..element_size)
                    .map(|i| {
                        let byte_start = (i * 8) as u32;
                        let byte_end = std::cmp::min(byte_start + 7, bit_size - 1);
                        let byte_bv = element_bv.extract(byte_end, byte_start);
                        Some(Arc::new(byte_bv))
                    })
                    .collect();

                // Write back to memory using the low-level write_memory function
                match executor.state.memory.write_memory(
                    element_addr,
                    &concrete_bytes,
                    &symbolic_bytes,
                ) {
                    Ok(()) => {
                        log!(
                            executor.state.logger,
                            "✓ Successfully initialized large slice element '{}' at 0x{:x} ({} bytes) with fresh symbolic variable",
                            element_name,
                            element_addr,
                            element_size
                        );
                    }
                    Err(e) => {
                        log!(
                            executor.state.logger,
                            "✗ Failed to write symbolic bytes for slice element '{}' at 0x{:x}: {}",
                            element_name,
                            element_addr,
                            e
                        );
                    }
                }
            }
            Err(e) => {
                log!(
                    executor.state.logger,
                    "✗ Failed to read bytes for large slice element '{}' at 0x{:x}: {}",
                    element_name,
                    element_addr,
                    e
                );
            }
        }
    }
}

// ────────────────────────────────────────────────────────────
//  Struct Pointer Field Symbolization
// ────────────────────────────────────────────────────────────

/// Initialize struct pointer fields as symbolic
/// When a function receives a pointer to a struct (e.g., *Block), this function
/// symbolizes the struct's fields at their respective offsets in memory.
///
/// Additionally, it makes the pointer itself symbolic (nullable) so that NULL
/// pointer dereferences can be detected during execution.
pub fn initialize_struct_pointer_fields<'a>(
    executor: &mut ConcolicExecutor<'a>,
    arg_name: &str,
    ptr_reg: &str,
    struct_type_name: &str,
) -> bool {
    log!(
        executor.state.logger,
        "=== INITIALIZING STRUCT POINTER FIELDS ==="
    );
    log!(
        executor.state.logger,
        "Argument '{}' is a pointer to struct '{}'",
        arg_name,
        struct_type_name
    );

    // Get the struct definition
    let struct_def = match get_struct_type(struct_type_name) {
        Some(def) => def,
        None => {
            log!(
                executor.state.logger,
                "WARNING: Struct type '{}' not found in DWARF cache - fields will not be symbolized",
                struct_type_name
            );
            return false;
        }
    };

    log!(
        executor.state.logger,
        "Found struct '{}' with {} bytes and {} members",
        struct_def.name,
        struct_def.size,
        struct_def.members.len()
    );

    // Get the concrete pointer value from the register
    let ptr_value = match get_concrete_value_from_location(executor, ptr_reg) {
        Some(val) => val,
        None => {
            log!(
                executor.state.logger,
                "WARNING: Could not read pointer value from register '{}' for struct '{}'",
                ptr_reg,
                arg_name
            );
            return false;
        }
    };

    log!(
        executor.state.logger,
        "Struct pointer '{}' = 0x{:x}",
        arg_name,
        ptr_value
    );

    // ═══════════════════════════════════════════════════════════════════════
    // STEP 1: Make the pointer itself symbolic (nullable)
    // ═══════════════════════════════════════════════════════════════════════
    // This allows Zorya to detect potential NULL pointer dereferences even when
    // the concrete value is non-NULL.

    let ptr_sym_name = format!("{}_ptr", arg_name.replace('.', "_"));
    let ptr_bv = BV::fresh_const(executor.context, &ptr_sym_name, 64);

    // Track this symbolic variable
    executor
        .function_symbolic_arguments
        .insert(ptr_sym_name.clone(), SymbolicVar::Int(ptr_bv.clone()));

    // Update the register to hold the symbolic pointer
    {
        let cpu = &mut executor.state.cpu_state.lock().unwrap();
        if let Some(off) = cpu.resolve_offset_from_register_name(ptr_reg) {
            let w = cpu.register_map.get(&off).map(|(_, w)| *w).unwrap_or(64);
            let ptr_concolic = ConcolicVar::new_concrete_and_symbolic_int(
                ptr_value,
                ptr_bv.clone(),
                executor.context,
            );
            if let Err(e) = cpu.set_register_value_by_offset(off, ptr_concolic, w) {
                log!(
                    executor.state.logger,
                    "WARNING: Failed to set symbolic pointer in register '{}': {:?}",
                    ptr_reg,
                    e
                );
            } else {
                log!(
                    executor.state.logger,
                    "✓ Made pointer '{}' symbolic (nullable) in register '{}'",
                    arg_name,
                    ptr_reg
                );
            }
        } else {
            log!(
                executor.state.logger,
                "WARNING: Could not resolve register '{}' for symbolic pointer",
                ptr_reg
            );
        }
    } // Drop the lock here

    // ═══════════════════════════════════════════════════════════════════════
    // STEP 2: Symbolize struct fields (only if pointer is non-NULL concretely)
    // ═══════════════════════════════════════════════════════════════════════

    if ptr_value == 0 {
        log!(
            executor.state.logger,
            "Struct pointer is NULL concretely - skipping field symbolization (but pointer itself is symbolic)"
        );
        return true; // We still symbolized the pointer itself
    }

    // Check if the pointer points to valid memory
    if !executor.state.memory.is_valid_address(ptr_value) {
        log!(
            executor.state.logger,
            "WARNING: Struct pointer 0x{:x} is not in valid memory - cannot symbolize fields",
            ptr_value
        );
        return true; // We still symbolized the pointer itself
    }

    // Symbolize each field
    let mut fields_symbolized = 0;
    let members = &struct_def.members;
    for (i, member) in members.iter().enumerate() {
        let field_addr = ptr_value + member.offset;
        let field_var_name = format!("{}.{}", arg_name, member.name);

        // Compute the actual field size from the struct layout:
        // - If there's a next member, size = next_member.offset - current_member.offset
        // - If it's the last member, size = struct_size - current_member.offset
        let actual_field_bytes = if i + 1 < members.len() {
            members[i + 1].offset - member.offset
        } else {
            struct_def.size - member.offset
        };

        log!(
            executor.state.logger,
            "Processing field '{}' at offset {} (0x{:x}), type: '{}', layout_size: {} bytes",
            member.name,
            member.offset,
            field_addr,
            member.typ,
            actual_field_bytes
        );

        // Check if this field's address is valid
        if !executor.state.memory.is_valid_address(field_addr) {
            log!(
                executor.state.logger,
                "WARNING: Field address 0x{:x} is not valid - skipping",
                field_addr
            );
            continue;
        }

        // Determine field size and how to symbolize it
        let symbolized = symbolize_struct_field(
            executor,
            &field_var_name,
            field_addr,
            &member.typ,
            Some(actual_field_bytes),
        );

        if symbolized {
            fields_symbolized += 1;
        }
    }

    log!(
        executor.state.logger,
        "=== STRUCT FIELD SYMBOLIZATION COMPLETE: {}/{} fields symbolized ===",
        fields_symbolized,
        struct_def.members.len()
    );

    fields_symbolized > 0
}

/// Symbolize a single struct field based on its type.
///
/// `layout_size_bytes`: if provided, the actual field size computed from the
/// struct layout (offset of next field minus offset of this field). This is
/// used to override the type-based size guess, which is critical for Go
/// interface types that are 16 bytes but look like unknown types.
fn symbolize_struct_field<'a>(
    executor: &mut ConcolicExecutor<'a>,
    field_name: &str,
    field_addr: u64,
    field_type: &str,
    layout_size_bytes: Option<u64>,
) -> bool {
    // Determine field size based on type
    let (type_bit_size, is_pointer) = get_field_size_and_pointer_status(field_type);

    // Check if this is a Go interface type:
    // A Go interface is 16 bytes (itab pointer + data pointer).
    // Detected when the layout says 16 bytes but the type-based guess says 8,
    // and the type is not a recognized primitive, slice, array, or string.
    let is_go_interface = layout_size_bytes == Some(16)
        && type_bit_size == 64
        && !is_pointer
        && !field_type.starts_with('[')
        && !field_type.starts_with("[]")
        && field_type != "string";

    if is_go_interface {
        log!(
            executor.state.logger,
            "Detected Go interface field '{}' at 0x{:x} (type: '{}', 16 bytes = itab + data)",
            field_name,
            field_addr,
            field_type
        );
        return symbolize_go_interface_field(executor, field_name, field_addr);
    }

    // Use layout-based size if it's larger than the type-based guess
    // (the struct layout from DWARF is authoritative)
    let bit_size = if let Some(layout_bytes) = layout_size_bytes {
        let layout_bits = (layout_bytes * 8) as u32;
        if layout_bits > type_bit_size {
            log!(
                executor.state.logger,
                "Using layout-based size {} bits (type-based was {} bits) for field '{}'",
                layout_bits,
                type_bit_size,
                field_name
            );
            layout_bits
        } else {
            type_bit_size
        }
    } else {
        type_bit_size
    };

    log!(
        executor.state.logger,
        "Symbolizing field '{}' at 0x{:x} (size: {} bits, is_pointer: {})",
        field_name,
        field_addr,
        bit_size,
        is_pointer
    );

    // For pointers, we want to allow nil values
    // Check for slices BEFORE checking for fixed arrays (both start with '[')
    if field_type.starts_with("[]") {
        // This is a slice type ([]T or []T*), not a fixed array
        // Slices are 24 bytes (ptr + len + cap), and we handle them as a composite symbolic value
        log!(
            executor.state.logger,
            "Field '{}' is a slice type ({}), symbolizing as 24-byte composite (ptr+len+cap)",
            field_name,
            field_type
        );
        return symbolize_slice_field(executor, field_name, field_addr, field_type);
    } else if field_type.starts_with('[') && field_type.contains(']') {
        // Fixed-size array like [32]byte
        return symbolize_fixed_array_field(executor, field_name, field_addr, field_type);
    }

    // Read current value
    let byte_size = (bit_size / 8) as usize;
    if byte_size > 16 {
        // Large field - skip for now
        log!(
            executor.state.logger,
            "WARNING: Field '{}' is too large ({} bytes) - skipping",
            field_name,
            byte_size
        );
        return false;
    }

    match executor
        .state
        .memory
        .read_value(field_addr, bit_size, &mut executor.state.logger.clone())
    {
        Ok(current_value) => {
            // Create symbolic variable
            let field_bv =
                BV::fresh_const(executor.context, &field_name.replace('.', "_"), bit_size);

            // For pointers, explicitly allow nil (0)
            // Don't add any constraints - let solver explore all values including 0
            if is_pointer {
                log!(
                    executor.state.logger,
                    "✓ Field '{}' is a pointer - allowing nil values",
                    field_name
                );
            }

            // Add to tracked symbolic arguments
            executor
                .function_symbolic_arguments
                .insert(field_name.to_string(), SymbolicVar::Int(field_bv.clone()));

            // Create memory value with symbolic
            let symbolic_mem_value =
                MemoryValue::new(current_value.concrete.to_u64(), field_bv.clone(), bit_size);

            // Write back to memory
            match executor
                .state
                .memory
                .write_value(field_addr, &symbolic_mem_value)
            {
                Ok(()) => {
                    log!(
                        executor.state.logger,
                        "✓ Successfully symbolized field '{}' at 0x{:x}",
                        field_name,
                        field_addr
                    );
                    true
                }
                Err(e) => {
                    log!(
                        executor.state.logger,
                        "✗ Failed to write symbolic value for field '{}': {}",
                        field_name,
                        e
                    );
                    false
                }
            }
        }
        Err(e) => {
            log!(
                executor.state.logger,
                "✗ Failed to read field '{}' at 0x{:x}: {}",
                field_name,
                field_addr,
                e
            );
            false
        }
    }
}

/// Symbolize a Go interface field as two 64-bit symbolic words (itab + data).
///
/// A Go interface is represented in memory as:
///   - offset +0: itab pointer (8 bytes) – points to the interface method table
///   - offset +8: data pointer (8 bytes) – points to the underlying value
///
/// When the interface is nil, both words are 0. Calling a method on a nil
/// interface dereferences the itab pointer (0), causing a nil pointer panic.
/// By making both words symbolic, the solver can explore the nil case.
fn symbolize_go_interface_field<'a>(
    executor: &mut ConcolicExecutor<'a>,
    field_name: &str,
    field_addr: u64,
) -> bool {
    let mut success = true;

    // Symbolize the itab pointer (first 8 bytes) - this is what gets
    // dereferenced during method dispatch; nil here causes the panic
    let itab_name = format!("{}.itab", field_name);
    let itab_bv = BV::fresh_const(executor.context, &itab_name.replace('.', "_"), 64);

    match executor
        .state
        .memory
        .read_value(field_addr, 64, &mut executor.state.logger.clone())
    {
        Ok(current_itab) => {
            executor
                .function_symbolic_arguments
                .insert(itab_name.clone(), SymbolicVar::Int(itab_bv.clone()));

            let itab_mem = MemoryValue::new(current_itab.concrete.to_u64(), itab_bv.clone(), 64);
            if let Err(e) = executor.state.memory.write_value(field_addr, &itab_mem) {
                log!(
                    executor.state.logger,
                    "✗ Failed to write itab symbolic for '{}': {:?}",
                    field_name,
                    e
                );
                success = false;
            }
        }
        Err(e) => {
            log!(
                executor.state.logger,
                "✗ Failed to read itab at 0x{:x}: {:?}",
                field_addr,
                e
            );
            success = false;
        }
    }

    // Symbolize the data pointer (second 8 bytes)
    let data_name = format!("{}.data", field_name);
    let data_bv = BV::fresh_const(executor.context, &data_name.replace('.', "_"), 64);
    let data_addr = field_addr + 8;

    match executor
        .state
        .memory
        .read_value(data_addr, 64, &mut executor.state.logger.clone())
    {
        Ok(current_data) => {
            executor
                .function_symbolic_arguments
                .insert(data_name.clone(), SymbolicVar::Int(data_bv.clone()));

            let data_mem = MemoryValue::new(current_data.concrete.to_u64(), data_bv.clone(), 64);
            if let Err(e) = executor.state.memory.write_value(data_addr, &data_mem) {
                log!(
                    executor.state.logger,
                    "✗ Failed to write data symbolic for '{}': {:?}",
                    field_name,
                    e
                );
                success = false;
            }
        }
        Err(e) => {
            log!(
                executor.state.logger,
                "✗ Failed to read data pointer at 0x{:x}: {:?}",
                data_addr,
                e
            );
            success = false;
        }
    }

    if success {
        log!(
            executor.state.logger,
            "✓ Successfully symbolized Go interface field '{}' at 0x{:x} (itab + data, both nil-able)",
            field_name,
            field_addr
        );
    }

    success
}

/// Symbolize a fixed-size array field (like [32]byte for common.Hash)
fn symbolize_fixed_array_field<'a>(
    executor: &mut ConcolicExecutor<'a>,
    field_name: &str,
    field_addr: u64,
    field_type: &str,
) -> bool {
    // Parse [N]T format
    let caps = match Regex::new(r"^\[(\d+)\](.+)$").unwrap().captures(field_type) {
        Some(c) => c,
        None => {
            log!(
                executor.state.logger,
                "WARNING: Could not parse array type '{}'",
                field_type
            );
            return false;
        }
    };

    let array_size: u64 = caps[1].parse().unwrap_or(0);
    let elem_type = caps[2].trim();
    let elem_size = get_type_size(elem_type);
    let total_bytes = array_size * elem_size;

    log!(
        executor.state.logger,
        "Symbolizing fixed array '{}': [{}]{} ({} bytes total)",
        field_name,
        array_size,
        elem_type,
        total_bytes
    );

    if total_bytes > 256 {
        log!(
            executor.state.logger,
            "WARNING: Array too large ({} bytes) - symbolizing as single variable",
            total_bytes
        );
        // Fall back to symbolizing as a large bitvector
        let bit_size = (total_bytes * 8) as u32;
        let field_bv = BV::fresh_const(executor.context, &field_name.replace('.', "_"), bit_size);
        executor
            .function_symbolic_arguments
            .insert(field_name.to_string(), SymbolicVar::Int(field_bv));
        return true;
    }

    // Symbolize each byte of the array
    let mut success = true;
    for i in 0..total_bytes {
        let byte_addr = field_addr + i;
        let byte_var_name = format!("{}_byte_{}", field_name.replace('.', "_"), i);

        if !executor.state.memory.is_valid_address(byte_addr) {
            log!(
                executor.state.logger,
                "WARNING: Byte address 0x{:x} not valid - stopping",
                byte_addr
            );
            break;
        }

        match executor.state.memory.read_byte(byte_addr) {
            Ok(current_byte) => {
                let byte_bv = BV::fresh_const(executor.context, &byte_var_name, 8);

                executor
                    .function_symbolic_arguments
                    .insert(byte_var_name.clone(), SymbolicVar::Int(byte_bv.clone()));

                let symbolic_mem = MemoryValue::new(current_byte.concrete.to_u64(), byte_bv, 8);

                if let Err(e) = executor.state.memory.write_value(byte_addr, &symbolic_mem) {
                    log!(
                        executor.state.logger,
                        "WARNING: Failed to write byte {}: {}",
                        i,
                        e
                    );
                    success = false;
                }
            }
            Err(e) => {
                log!(
                    executor.state.logger,
                    "WARNING: Failed to read byte {}: {}",
                    i,
                    e
                );
                success = false;
            }
        }
    }

    if success {
        log!(
            executor.state.logger,
            "✓ Successfully symbolized array field '{}' ({} bytes)",
            field_name,
            total_bytes
        );
    }

    success
}

/// Symbolize a slice field (like []byte or []T *) as ptr+len+cap
/// A Go slice is 24 bytes: pointer (8) + length (8) + capacity (8)
fn symbolize_slice_field<'a>(
    executor: &mut ConcolicExecutor<'a>,
    field_name: &str,
    field_addr: u64,
    field_type: &str,
) -> bool {
    log!(
        executor.state.logger,
        "Symbolizing slice field '{}': {} (24 bytes = ptr + len + cap)",
        field_name,
        field_type
    );

    let mut success = true;

    // Symbolize the pointer (first 8 bytes)
    let ptr_name = format!("{}.ptr", field_name);
    let ptr_bv = BV::fresh_const(executor.context, &ptr_name.replace('.', "_"), 64);

    match executor
        .state
        .memory
        .read_value(field_addr, 64, &mut executor.state.logger.clone())
    {
        Ok(current_ptr) => {
            executor
                .function_symbolic_arguments
                .insert(ptr_name.clone(), SymbolicVar::Int(ptr_bv.clone()));

            let ptr_mem = MemoryValue::new(current_ptr.concrete.to_u64(), ptr_bv.clone(), 64);
            if let Err(e) = executor.state.memory.write_value(field_addr, &ptr_mem) {
                log!(
                    executor.state.logger,
                    "✗ Failed to write ptr symbolic for '{}': {:?}",
                    field_name,
                    e
                );
                success = false;
            } else {
                log!(
                    executor.state.logger,
                    "✓ Symbolized slice.ptr at 0x{:x}",
                    field_addr
                );
            }
        }
        Err(e) => {
            log!(
                executor.state.logger,
                "✗ Failed to read ptr at 0x{:x}: {:?}",
                field_addr,
                e
            );
            success = false;
        }
    }

    // Symbolize the length (second 8 bytes)
    let len_name = format!("{}.len", field_name);
    let len_bv = BV::fresh_const(executor.context, &len_name.replace('.', "_"), 64);
    let len_addr = field_addr + 8;

    match executor
        .state
        .memory
        .read_value(len_addr, 64, &mut executor.state.logger.clone())
    {
        Ok(current_len) => {
            executor
                .function_symbolic_arguments
                .insert(len_name.clone(), SymbolicVar::Int(len_bv.clone()));

            let len_mem = MemoryValue::new(current_len.concrete.to_u64(), len_bv.clone(), 64);
            if let Err(e) = executor.state.memory.write_value(len_addr, &len_mem) {
                log!(
                    executor.state.logger,
                    "✗ Failed to write len symbolic for '{}': {:?}",
                    field_name,
                    e
                );
                success = false;
            } else {
                log!(
                    executor.state.logger,
                    "✓ Symbolized slice.len at 0x{:x}",
                    len_addr
                );
            }
        }
        Err(e) => {
            log!(
                executor.state.logger,
                "✗ Failed to read len at 0x{:x}: {:?}",
                len_addr,
                e
            );
            success = false;
        }
    }

    // Symbolize the capacity (third 8 bytes)
    let cap_name = format!("{}.cap", field_name);
    let cap_bv = BV::fresh_const(executor.context, &cap_name.replace('.', "_"), 64);
    let cap_addr = field_addr + 16;

    match executor
        .state
        .memory
        .read_value(cap_addr, 64, &mut executor.state.logger.clone())
    {
        Ok(current_cap) => {
            executor
                .function_symbolic_arguments
                .insert(cap_name.clone(), SymbolicVar::Int(cap_bv.clone()));

            let cap_mem = MemoryValue::new(current_cap.concrete.to_u64(), cap_bv.clone(), 64);
            if let Err(e) = executor.state.memory.write_value(cap_addr, &cap_mem) {
                log!(
                    executor.state.logger,
                    "✗ Failed to write cap symbolic for '{}': {:?}",
                    field_name,
                    e
                );
                success = false;
            } else {
                log!(
                    executor.state.logger,
                    "✓ Symbolized slice.cap at 0x{:x}",
                    cap_addr
                );
            }
        }
        Err(e) => {
            log!(
                executor.state.logger,
                "✗ Failed to read cap at 0x{:x}: {:?}",
                cap_addr,
                e
            );
            success = false;
        }
    }

    if success {
        log!(
            executor.state.logger,
            "✓ Successfully symbolized slice field '{}' at 0x{:x} (ptr + len + cap, all symbolic)",
            field_name,
            field_addr
        );
    }

    success
}

/// Determine field size in bits and whether it's a pointer type
fn get_field_size_and_pointer_status(field_type: &str) -> (u32, bool) {
    // Check if it's a pointer type
    if field_type.ends_with(" *") || field_type.ends_with("*") {
        return (64, true); // Pointers are 64-bit on amd64
    }

    // Check if it's a slice type
    if field_type.starts_with("[]") || field_type.starts_with("[]*") {
        return (192, false); // Slices are 24 bytes (ptr + len + cap)
    }

    // Check if it's a fixed-size array
    if field_type.starts_with('[') {
        if let Some(caps) = Regex::new(r"^\[(\d+)\](.+)$").unwrap().captures(field_type) {
            let array_size: u64 = caps[1].parse().unwrap_or(0);
            let elem_type = caps[2].trim();
            let elem_size = get_type_size(elem_type);
            return ((array_size * elem_size * 8) as u32, false);
        }
    }

    // Primitive types
    let size_bytes = get_type_size(field_type);
    ((size_bytes * 8) as u32, false)
}
