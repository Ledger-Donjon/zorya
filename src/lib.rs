// SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

pub mod concolic;
pub mod fuzzer;
pub mod plugins;
pub mod state;
pub mod summaries;
pub mod target_info;

pub use concolic::{concolic_var, executor};

// ── Global trace file ────────────────────────────────────────────────────────
use std::sync::OnceLock;

pub static TRACE_FILE: OnceLock<std::sync::Mutex<std::fs::File>> = OnceLock::new();

pub fn init_trace_file(path: &str) {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .expect("Failed to open trace file");
    let _ = TRACE_FILE.set(std::sync::Mutex::new(file));
}

// ── /dev/tty handle ──────────────────────────────────────────────────────────
// Writing to /dev/tty always reaches the user's controlling terminal, even
// when stdout/stderr have been redirected through a `tee` pipe (as the zorya
// wrapper does).  Using a single fd for BOTH the bar and normal messages
// eliminates any race condition between the two: there is exactly one write
// queue, so ordering is always correct.
pub static TTY: std::sync::LazyLock<Option<std::sync::Mutex<std::fs::File>>> =
    std::sync::LazyLock::new(|| {
        std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/tty")
            .ok()
            .map(std::sync::Mutex::new)
    });

// ── Z3 solver time accumulator ───────────────────────────────────────────────
// Every call site that measures `solve_elapsed` adds its milliseconds here.
// The bar reads this to compute "% of wall-clock spent in Z3" — the closest
// runtime equivalent to what a flamegraph would show as the hot call-stack.
pub static Z3_CUMULATIVE_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

// ── Sticky coverage bar ──────────────────────────────────────────────────────
// Holds the rendered bar text (ANSI codes included, no leading `\r`, no `\n`).
// Empty until the first coverage measurement is available.
pub static COVERAGE_BAR: std::sync::LazyLock<std::sync::Mutex<String>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(String::new()));

/// Write bytes directly to /dev/tty in one syscall.  No-op when there is no
/// controlling terminal.
pub fn tty_write(text: &str) {
    use std::io::Write as _;
    if let Some(m) = TTY.as_ref() {
        if let Ok(mut f) = m.lock() {
            let _ = write!(f, "{}", text);
            let _ = f.flush();
        }
    }
}

/// Erase the sticky coverage bar from the terminal and forget its text.
///
/// Must be called once when execution finishes, otherwise the bar text stays
/// painted on the last terminal rows (998/999) and the shell prompt is drawn
/// on top of it — the user sees prompt remnants like `$ 1 (0.18%) | t:2m1s …`.
pub fn clear_coverage_bar() {
    if TTY.is_some() {
        // Jump to the two reserved rows, erase each, then drop the cursor onto
        // the (now blank) separator row so the shell prompt starts clean.
        tty_write("\x1b[999;1H\x1b[2K\x1b[998;1H\x1b[2K");
    }
    if let Ok(mut guard) = COVERAGE_BAR.lock() {
        guard.clear();
    }
}

/// Display `msg` on the terminal while keeping the coverage bar pinned to the
/// last line.  Everything is written to /dev/tty in a **single call** so there
/// is no race between bar and message output.
///
/// Falls back to `println!` when /dev/tty is not available (CI, piped runs).
pub fn display_message(msg: &str) {
    let bar = COVERAGE_BAR.lock().map(|g| g.clone()).unwrap_or_default();

    if TTY.is_some() {
        if bar.is_empty() {
            tty_write(&format!("{}\n", msg));
        } else {
            // One atomic write that keeps the bar pinned to the last terminal row:
            //
            //   \x1b[s           – save current cursor position (where next output will go)
            //   \x1b[999;1H      – jump to last row (terminal clamps to actual height)
            //   \x1b[2K          – erase bar line
            //   \x1b[998;1H      – jump to second-to-last row (blank separator)
            //   \x1b[2K          – erase separator line
            //   \x1b[u           – restore cursor (back to normal output position)
            //   {msg}\n          – print message, cursor advances one line down
            //   \x1b[s           – save new cursor position
            //   \x1b[998;1H      – redraw blank separator row
            //   \x1b[2K
            //   \x1b[999;1H      – redraw bar on last row
            //   \x1b[2K
            //   {bar}            – bar text (no \n → cursor stays on bar row)
            //   \x1b[u           – restore cursor to after the message
            tty_write(&format!(
                "\x1b[s\x1b[999;1H\x1b[2K\x1b[998;1H\x1b[2K\x1b[u\
                 {}\n\
                 \x1b[s\x1b[998;1H\x1b[2K\x1b[999;1H\x1b[2K{}\x1b[u",
                msg, bar
            ));
        }
    } else {
        println!("{}", msg);
    }
}

/// Like `println!` but also writes to the trace file and keeps the sticky
/// coverage bar pinned to the last terminal line.
#[macro_export]
macro_rules! tprintln {
    () => {{
        $crate::display_message("");
        if let Some(f) = $crate::TRACE_FILE.get() {
            if let Ok(mut f) = f.lock() {
                use std::io::Write as _;
                let _ = writeln!(f);
            }
        }
    }};
    ($($arg:tt)*) => {{
        let msg = format!($($arg)*);
        $crate::display_message(&msg);
        if let Some(f) = $crate::TRACE_FILE.get() {
            if let Ok(mut f) = f.lock() {
                use std::io::Write as _;
                let _ = writeln!(f, "{}", msg);
            }
        }
    }};
}

/// Like `eprintln!` but also writes to the trace file and keeps the sticky
/// coverage bar pinned to the last terminal line.
#[macro_export]
macro_rules! teprintln {
    () => {{
        $crate::display_message("");
        if let Some(f) = $crate::TRACE_FILE.get() {
            if let Ok(mut f) = f.lock() {
                use std::io::Write as _;
                let _ = writeln!(f);
            }
        }
    }};
    ($($arg:tt)*) => {{
        let msg = format!($($arg)*);
        $crate::display_message(&msg);
        if let Some(f) = $crate::TRACE_FILE.get() {
            if let Ok(mut f) = f.lock() {
                use std::io::Write as _;
                let _ = writeln!(f, "{}", msg);
            }
        }
    }};
}
