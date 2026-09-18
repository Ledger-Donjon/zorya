// SPDX-FileCopyrightText: 2026 Karolina Gorna
//
// SPDX-License-Identifier: Apache-2.0

//! Static unbounded-recursion (stack-exhaustion DoS) scan.
//!
//! This is the Rust side of Zorya's call-graph recursion pass. It shells out to
//! `scripts/precompute_unbounded_recursion.py` (a Ghidra/pyhidra pass that builds
//! the function call graph, extracts recursive strongly-connected components, and
//! ranks them by reachability from an untrusted-input entry point), then parses
//! and pretty-prints the ranked findings.
//!
//! Rationale: Zorya's symbolic engine and memory-safety oracles are built for
//! input-gated faults and do not model Go's goroutine-stack growth (the engine
//! zeroes `g.stackguard0` to keep Go binaries running), so an unbounded-recursion
//! `fatal error: stack overflow` is invisible to them. This pass detects the
//! *structure* of that bug statically, complementing the dynamic detectors.

use std::error::Error;
use std::fs;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

/// One recursive strongly-connected component of the call graph.
#[derive(Debug, Clone)]
pub struct RecursionCycle {
    pub id: u64,
    pub size: usize,
    pub reachable: bool,
    /// "HIGH" | "MEDIUM" | "LOW".
    pub risk: String,
    pub selfrec: bool,
    /// Representative entry into the cycle, formatted "0xaddr:name".
    pub entry: String,
    /// Member functions, each "0xaddr:name" (may end with a "(+N more)" marker).
    pub members: Vec<String>,
}

/// Run the Ghidra recursion pass and return the ranked recursive components.
///
/// `entries` are optional case-insensitive symbol substrings that override the
/// default entry seeds (`main.main` plus any `parsesourcefile`). The pass reuses
/// an existing `<binary>_ghidra` project when it is newer than the binary.
pub fn precompute_unbounded_recursion(
    binary_path: &str,
    entries: &[String],
) -> Result<Vec<RecursionCycle>, Box<dyn Error>> {
    let mut cmd = Command::new("python3");
    cmd.arg("scripts/precompute_unbounded_recursion.py")
        .arg(binary_path);
    for e in entries {
        cmd.arg(e);
    }
    let mut child = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;

    if let Some(stdout) = child.stdout.take() {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            crate::tprintln!("{}", line);
        }
    }
    if let Some(stderr) = child.stderr.take() {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            crate::teprintln!("{}", line);
        }
    }

    let status = child.wait()?;
    if !status.success() {
        return Err("precompute_unbounded_recursion.py failed".into());
    }

    parse_cycles("results/recursion_cycles.txt")
}

/// Parse the `results/recursion_cycles.txt` artifact produced by the pass.
pub fn parse_cycles(path: &str) -> Result<Vec<RecursionCycle>, Box<dyn Error>> {
    let content = fs::read_to_string(path)?;
    let mut out = Vec::new();
    for line in content.lines() {
        let s = line.trim();
        if !s.starts_with("CYCLE ") {
            continue;
        }
        let mut cyc = RecursionCycle {
            id: 0,
            size: 0,
            reachable: false,
            risk: String::from("LOW"),
            selfrec: false,
            entry: String::new(),
            members: Vec::new(),
        };
        // Split off "members=" first because its value contains spaces? It does
        // not (members are ';'-joined, no spaces), so whitespace tokenization is
        // safe for every field.
        for tok in s.split_whitespace() {
            if let Some(v) = tok.strip_prefix("CYCLE") {
                // "CYCLE" then the id is the next token; handle id separately.
                let _ = v;
            } else if let Some(v) = tok.strip_prefix("size=") {
                cyc.size = v.parse().unwrap_or(0);
            } else if let Some(v) = tok.strip_prefix("reachable=") {
                cyc.reachable = v == "1";
            } else if let Some(v) = tok.strip_prefix("risk=") {
                cyc.risk = v.to_string();
            } else if let Some(v) = tok.strip_prefix("selfrec=") {
                cyc.selfrec = v == "1";
            } else if let Some(v) = tok.strip_prefix("entry=") {
                cyc.entry = v.to_string();
            } else if let Some(v) = tok.strip_prefix("members=") {
                cyc.members = v.split(';').map(|m| m.to_string()).collect();
            }
        }
        // The id is the token right after "CYCLE".
        let toks: Vec<&str> = s.split_whitespace().collect();
        if toks.len() >= 2 {
            cyc.id = toks[1].parse().unwrap_or(0);
        }
        out.push(cyc);
    }
    Ok(out)
}

/// Pretty-print the ranked recursion findings. Returns the number of HIGH-risk
/// (reachable, front-end) unbounded-recursion candidates.
pub fn report_unbounded_recursion(cycles: &[RecursionCycle]) -> usize {
    let high: Vec<&RecursionCycle> = cycles.iter().filter(|c| c.risk == "HIGH").collect();
    let medium = cycles.iter().filter(|c| c.risk == "MEDIUM").count();

    crate::tprintln!("");
    crate::tprintln!("========== Unbounded-recursion (stack-exhaustion DoS) scan ==========");
    crate::tprintln!(
        "Recursive call-graph cycles: {} total | HIGH (reachable, front-end): {} | MEDIUM (reachable): {}",
        cycles.len(),
        high.len(),
        medium
    );

    if high.is_empty() {
        crate::tprintln!(
            "No HIGH-risk unbounded-recursion candidate reachable from the chosen entry point."
        );
    }

    // Show the HIGH-risk cycles in full-ish detail, then a few MEDIUM.
    let mut shown = 0usize;
    for c in cycles.iter().filter(|c| c.risk == "HIGH") {
        shown += 1;
        crate::tprintln!("");
        crate::tprintln!(
            "[{}] CYCLE #{}  risk=HIGH  size={} function(s)  {}",
            "DoS-recursion",
            c.id,
            c.size,
            if c.selfrec {
                "(self-recursive)"
            } else {
                "(mutual recursion)"
            }
        );
        crate::tprintln!("    entry:   {}", c.entry);
        let preview: Vec<String> = c.members.iter().take(12).cloned().collect();
        for m in &preview {
            crate::tprintln!("      - {}", m);
        }
        if c.members.len() > preview.len() {
            crate::tprintln!(
                "      ... {} more member(s)",
                c.members.len() - preview.len()
            );
        }
        crate::tprintln!(
            "    Why: this recursion cycle is reachable from untrusted input and has no"
        );
        crate::tprintln!(
            "         per-nesting depth cap, so deeply nested input drives one stack frame"
        );
        crate::tprintln!(
            "         per level until the Go goroutine stack overflows (fatal, unrecoverable)."
        );
    }

    if shown > 0 {
        crate::tprintln!("");
        crate::tprintln!(
            "Recommendation: add a bounded nesting-depth counter to the cycle's entry"
        );
        crate::tprintln!("functions and emit a diagnostic instead of recursing past the limit.");
    }
    crate::tprintln!("=====================================================================");

    high.len()
}

/// Convenience: run the pass, print the report, and return the HIGH-risk count.
pub fn scan_and_report(binary_path: &str, entries: &[String]) -> Result<usize, Box<dyn Error>> {
    let cycles = precompute_unbounded_recursion(binary_path, entries)?;
    Ok(report_unbounded_recursion(&cycles))
}
