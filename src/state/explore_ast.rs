use z3::ast::Int;
use crate::executor::ConcolicExecutor;
use std::process::Command;
use std::str;
use std::io::Write;

const MAX_AST_DEPTH: usize = 10;

macro_rules! log {
    ($logger:expr, $($arg:tt)*) => {{
        writeln!($logger, $($arg)*).unwrap();
    }};
}

/// Explore the Go AST via Pyhidra to check if the instruction address is in a path toward a panic function
pub fn explore_ast_for_panic(executor: &mut ConcolicExecutor, panic_address_ints: &[Int], target_addr: u64, binary_path: &str) {

    log!(executor.state.logger, "Exploring AST for panic at address 0x{:x}", target_addr);
    
    // Call the Pyhidra AST exploration script
    let output = Command::new("python3")
        .arg("scripts/explore_ast_panic.py")
        .arg(binary_path)
        .arg(format!("{:#x}", target_addr))
        .arg(MAX_AST_DEPTH.to_string())
        .output()
        .expect("Failed to run explore_ast_panic.py");

    let stdout = str::from_utf8(&output.stdout).unwrap();
    let stderr = str::from_utf8(&output.stderr).unwrap();

    if !output.status.success() {
        log!(executor.state.logger, "Pyhidra AST exploration failed:\n{}", stderr);
        return;
    }

    log!(executor.state.logger, "AST exploration result:\n{}", stdout);

    for line in stdout.lines() {
        if line.starts_with("FOUND_PANIC_XREF_AT") {
            if let Some(addr_str) = line.split("0x").nth(1) {
                let found_addr = u64::from_str_radix(addr_str, 16).unwrap_or(0);
                if panic_address_ints.iter().any(|i| i.as_u64().unwrap() == found_addr) {
                    log!(executor.state.logger, "AST path leads to PANIC address 0x{:x}", found_addr);
                } else {
                    log!(executor.state.logger, "Found xref at 0x{:x}, but not a known panic address", found_addr);
                }
            }
        }
    }
}

