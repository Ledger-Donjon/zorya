// SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

pub mod concolic;
pub mod fuzzer;
pub mod state;
pub mod target_info;

pub use concolic::{concolic_var, executor};

// ── Global trace file for tprintln! / teprintln! ────────────────────────────
// Every message printed to the terminal is also appended to this file so that
// `results/execution_trace.txt` contains the full session output.
use std::sync::OnceLock;

/// Global trace file handle.  Initialised once by [`init_trace_file`] at
/// program start-up; every subsequent [`tprintln!`] / [`teprintln!`] call
/// appends to it.
pub static TRACE_FILE: OnceLock<std::sync::Mutex<std::fs::File>> = OnceLock::new();

/// Open (or create) the trace file.  Must be called **once** before any
/// `tprintln!` / `teprintln!` invocation.  The file is opened in *append*
/// mode so it coexists with the `trace_logger` that may also write to the
/// same path.
pub fn init_trace_file(path: &str) {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .expect("Failed to open trace file");
    // Ignore the error if already initialised (idempotent).
    let _ = TRACE_FILE.set(std::sync::Mutex::new(file));
}

/// Like `println!` but also writes to the global trace file.
#[macro_export]
macro_rules! tprintln {
    () => {{
        println!();
        if let Some(f) = $crate::TRACE_FILE.get() {
            if let Ok(mut f) = f.lock() {
                use std::io::Write;
                let _ = writeln!(f);
            }
        }
    }};
    ($($arg:tt)*) => {{
        println!($($arg)*);
        if let Some(f) = $crate::TRACE_FILE.get() {
            if let Ok(mut f) = f.lock() {
                use std::io::Write;
                let _ = writeln!(f, $($arg)*);
            }
        }
    }};
}

/// Like `eprintln!` but also writes to the global trace file.
#[macro_export]
macro_rules! teprintln {
    () => {{
        eprintln!();
        if let Some(f) = $crate::TRACE_FILE.get() {
            if let Ok(mut f) = f.lock() {
                use std::io::Write;
                let _ = writeln!(f);
            }
        }
    }};
    ($($arg:tt)*) => {{
        eprintln!($($arg)*);
        if let Some(f) = $crate::TRACE_FILE.get() {
            if let Ok(mut f) = f.lock() {
                use std::io::Write;
                let _ = writeln!(f, $($arg)*);
            }
        }
    }};
}
