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

/// Explore the Go AST via Pyhidra to check if the instruction address is in a path toward a panic function.
/// Returns the line of stdout: "FOUND_PANIC_XREF_AT 0x..." or "NO_PANIC_XREF_FOUND"
pub fn explore_ast_for_panic(executor: &mut ConcolicExecutor, target_addr: u64, binary_path: &str) -> String {
    log!(executor.state.logger, "Exploring AST for panic at address 0x{:x}", target_addr);

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
        return "AST_ERROR".to_string();
    }

    log!(executor.state.logger, "AST exploration result:\n{}", stdout);

    for line in stdout.lines() {
        if line.starts_with("FOUND_PANIC_XREF_AT") {
            return line.to_string();
        }
    }

    "NO_PANIC_XREF_FOUND".to_string()
}
