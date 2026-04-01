// SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, HashSet};
use std::error::Error;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Command, Stdio};
use std::rc::Rc;

pub type PanicReachSet = Rc<HashSet<u64>>;
pub type PanicReachRanges = Rc<BTreeMap<u64, u64>>; // start -> end

#[derive(Debug, Clone)]
pub struct PanicReachStats {
    pub total_blocks: usize,
    pub tainted_functions: usize,
    pub iterations: usize,
    pub coverage_percentage: f64,
    pub analysis_time_seconds: f64,
    pub cache_hit_rate: f64,
    pub function_summary_reuse_rate: f64,
}

pub fn precompute_panic_reach(
    binary_path: &str,
) -> Result<(PanicReachSet, PanicReachRanges, PanicReachStats), Box<dyn Error>> {
    let out_file = "results/panic_reachable.txt";
    let xref_file = "results/xref_addresses.txt";
    // Run the Python precompute if output is missing/empty, or xrefs are newer, or forced via env
    let mut need_run = !Path::new(out_file).exists()
        || fs::metadata(out_file).map(|m| m.len() == 0).unwrap_or(true);

    if !need_run && Path::new(out_file).exists() && Path::new(xref_file).exists() {
        if let (Ok(out_meta), Ok(xref_meta)) = (fs::metadata(out_file), fs::metadata(xref_file)) {
            if let (Ok(out_m), Ok(xref_m)) = (out_meta.modified(), xref_meta.modified()) {
                if xref_m > out_m {
                    need_run = true;
                }
            }
        }
    }

    if !need_run {
        if let Ok(force) = std::env::var("PANIC_REACH_FORCE") {
            let force = force == "1" || force.to_lowercase() == "true";
            if force {
                need_run = true;
            }
        }
    }
    if need_run {
        // Stream subprocess output line-by-line so it appears in both the
        // terminal and execution_trace.txt via tprintln!.
        let mut child = Command::new("python3")
            .arg("scripts/precompute_panic_reach.py")
            .arg(binary_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        // Stream stdout
        if let Some(stdout) = child.stdout.take() {
            for line in BufReader::new(stdout).lines() {
                match line {
                    Ok(l) => crate::tprintln!("{}", l),
                    Err(_) => break,
                }
            }
        }
        // Stream stderr
        if let Some(stderr) = child.stderr.take() {
            for line in BufReader::new(stderr).lines() {
                match line {
                    Ok(l) => crate::teprintln!("{}", l),
                    Err(_) => break,
                }
            }
        }

        let status = child.wait()?;
        if !status.success() {
            return Err("precompute_panic_reach.py failed".into());
        }
    }

    // Load the set and ranges from file, and parse statistics from header comments
    let mut set = HashSet::new();
    let mut ranges = BTreeMap::new();
    let mut stats = PanicReachStats {
        total_blocks: 0,
        tainted_functions: 0,
        iterations: 0,
        coverage_percentage: 0.0,
        analysis_time_seconds: 0.0,
        cache_hit_rate: 0.0,
        function_summary_reuse_rate: 0.0,
    };

    if let Ok(content) = fs::read_to_string(out_file) {
        for line in content.lines() {
            let s = line.trim();
            if s.is_empty() {
                continue;
            }

            // Parse header comments for statistics
            if s.starts_with('#') {
                if s.contains("Generated in") && s.contains("iterations") {
                    // Parse: "# Generated in 1.23s, 45 iterations"
                    if let Some(time_part) = s.split("Generated in ").nth(1) {
                        if let Some(time_str) = time_part.split('s').next() {
                            stats.analysis_time_seconds = time_str.parse().unwrap_or(0.0);
                        }
                    }
                    if let Some(iter_part) = s.split(", ").nth(1) {
                        if let Some(iter_str) = iter_part.split(' ').next() {
                            stats.iterations = iter_str.parse().unwrap_or(0);
                        }
                    }
                }
                if s.contains("Coverage:") && s.contains("blocks") {
                    // Parse: "# Coverage: 1234 blocks (45.6% of program), 567 tainted functions"
                    if let Some(blocks_part) = s.split("Coverage: ").nth(1) {
                        if let Some(blocks_str) = blocks_part.split(' ').next() {
                            stats.total_blocks = blocks_str.parse().unwrap_or(0);
                        }
                    }
                    if s.contains("(") && s.contains("% of program)") {
                        if let Some(pct_part) = s.split('(').nth(1) {
                            if let Some(pct_str) = pct_part.split('%').next() {
                                stats.coverage_percentage = pct_str.parse().unwrap_or(0.0);
                            }
                        }
                    }
                    if s.contains("tainted functions") {
                        let parts: Vec<&str> = s.split_whitespace().collect();
                        for (i, part) in parts.iter().enumerate() {
                            if *part == "tainted" && i > 0 {
                                stats.tainted_functions = parts[i - 1].parse().unwrap_or(0);
                                break;
                            }
                        }
                    }
                }
                if s.contains("Cache stats:") {
                    // Parse: "# Cache stats: 12/34 indirect call hits, 56/78 summary reuse"
                    if s.contains("indirect call hits") {
                        if let Some(hits_part) = s.split("Cache stats: ").nth(1) {
                            if let Some(ratio_str) = hits_part.split(' ').next() {
                                let parts: Vec<&str> = ratio_str.split('/').collect();
                                if parts.len() == 2 {
                                    let hits: f64 = parts[0].parse().unwrap_or(0.0);
                                    let total: f64 = parts[1].parse().unwrap_or(1.0);
                                    stats.cache_hit_rate = if total > 0.0 {
                                        hits / total * 100.0
                                    } else {
                                        0.0
                                    };
                                }
                            }
                        }
                    }
                    if s.contains("summary reuse") {
                        let parts: Vec<&str> = s.split_whitespace().collect();
                        for (i, part) in parts.iter().enumerate() {
                            if part.contains('/')
                                && i + 1 < parts.len()
                                && parts[i + 1] == "summary"
                            {
                                let ratio_parts: Vec<&str> = part.split('/').collect();
                                if ratio_parts.len() == 2 {
                                    let reused: f64 = ratio_parts[0].parse().unwrap_or(0.0);
                                    let computed: f64 = ratio_parts[1].parse().unwrap_or(1.0);
                                    stats.function_summary_reuse_rate = if (reused + computed) > 0.0
                                    {
                                        reused / (reused + computed) * 100.0
                                    } else {
                                        0.0
                                    };
                                }
                                break;
                            }
                        }
                    }
                }
                continue;
            }

            // Parse block addresses
            let parts: Vec<&str> = s.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }
            let start_hex = parts[0].strip_prefix("0x").unwrap_or(parts[0]);
            if let Ok(start) = u64::from_str_radix(start_hex, 16) {
                set.insert(start);
                if parts.len() >= 2 {
                    let end_hex = parts[1].strip_prefix("0x").unwrap_or(parts[1]);
                    if let Ok(end) = u64::from_str_radix(end_hex, 16) {
                        ranges.insert(start, end);
                    }
                }
            }
        }
    }
    Ok((Rc::new(set), Rc::new(ranges), stats))
}

pub fn is_panic_reachable_addr(
    addr: u64,
    starts: &PanicReachSet,
    ranges: &PanicReachRanges,
) -> bool {
    if starts.contains(&addr) {
        return true;
    }
    // range-aware: find greatest start <= addr and check end >= addr
    if let Some((&s, &e)) = ranges.range(..=addr).next_back() {
        return addr >= s && addr <= e;
    }
    false
}
