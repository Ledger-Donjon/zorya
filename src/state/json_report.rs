// SPDX-FileCopyrightText: 2026 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

//! Machine-readable copies of the run reports.
//!
//! `results/FOUND_SAT_STATE.json` mirrors `results/FOUND_SAT_STATE.txt` and
//! `results/plugin_findings.json` mirrors `results/plugin_findings.txt`. Each
//! file is a single JSON document, rewritten in full (through a temporary file
//! and a rename) every time an entry is added, so a reader never sees a
//! partially written document, even if the run is killed.

use std::sync::Mutex;

use serde_json::{json, Map, Value};

use crate::plugins::Finding;

pub const SAT_STATE_JSON: &str = "results/FOUND_SAT_STATE.json";
pub const FINDINGS_JSON: &str = "results/plugin_findings.json";
pub const FINDINGS_TXT: &str = "results/plugin_findings.txt";

/// Version of the layout of both files. Bump it on incompatible changes.
pub const SCHEMA_VERSION: u32 = 1;

static SAT_ENTRIES: Mutex<Vec<Value>> = Mutex::new(Vec::new());

/// Format an address the way the text reports do (`0x49c56e`). Addresses are
/// strings because JSON numbers lose precision above 2^53.
pub fn hex(v: u64) -> String {
    format!("0x{:x}", v)
}

/// The printable character for a byte value, if there is one.
pub fn printable_char(v: u64) -> Option<String> {
    match v {
        32..=126 => Some(char::from(v as u8).to_string()),
        _ => None,
    }
}

/// JSON description of an integer value solved by Z3.
pub fn int_value(v: u64) -> Value {
    json!({
        "value": v,
        "signed": v as i64,
        "hex": hex(v),
        "char": printable_char(v),
    })
}

fn header() -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("schema_version".into(), json!(SCHEMA_VERSION));
    m.insert("zorya_version".into(), json!(env!("CARGO_PKG_VERSION")));
    m.insert(
        "command".into(),
        json!(crate::state::evaluate_z3::invocation_command_line()),
    );
    m.insert("binary".into(), json!(std::env::var("BIN_PATH").ok()));
    m.insert("mode".into(), json!(std::env::var("MODE").ok()));
    m
}

fn write_json(path: &str, value: &Value) -> std::io::Result<()> {
    std::fs::create_dir_all("results")?;
    let tmp = format!("{}.tmp", path);
    std::fs::write(&tmp, serde_json::to_string_pretty(value)? + "\n")?;
    std::fs::rename(&tmp, path)
}

/// Remove the JSON report of a previous run.
pub fn reset_sat_states() {
    if let Ok(mut entries) = SAT_ENTRIES.lock() {
        entries.clear();
    }
    let _ = std::fs::remove_file(SAT_STATE_JSON);
}

/// Append one entry (a satisfiable state or a bug report) to
/// `results/FOUND_SAT_STATE.json`.
pub fn record_sat_entry(entry: Value) -> std::io::Result<()> {
    let mut entries = SAT_ENTRIES.lock().unwrap_or_else(|e| e.into_inner());
    entries.push(entry);
    let mut doc = header();
    doc.insert("results".into(), Value::Array(entries.clone()));
    write_json(SAT_STATE_JSON, &Value::Object(doc))
}

/// Entries recorded so far in `results/FOUND_SAT_STATE.json`.
pub fn sat_entries() -> Vec<Value> {
    SAT_ENTRIES.lock().map(|e| e.clone()).unwrap_or_default()
}

/// Write `results/plugin_findings.json`.
pub fn write_findings(findings: &[Finding]) -> std::io::Result<()> {
    let mut doc = header();
    doc.insert("finding_count".into(), json!(findings.len()));
    doc.insert(
        "findings".into(),
        Value::Array(
            findings
                .iter()
                .map(|f| {
                    json!({
                        "plugin": f.plugin,
                        "rule": f.rule,
                        "severity": format!("{:?}", f.severity),
                        "pc": hex(f.pc),
                        "title": f.title,
                        "details": f.details,
                    })
                })
                .collect(),
        ),
    );
    write_json(FINDINGS_JSON, &Value::Object(doc))
}

/// Write `results/plugin_findings.txt`.
pub fn write_findings_txt(findings: &[Finding]) -> std::io::Result<()> {
    use std::fmt::Write;
    let mut out = String::new();
    let _ = writeln!(out, "# zorya plugin findings");
    let _ = writeln!(out, "# {} finding(s)", findings.len());
    if findings.is_empty() {
        let _ = writeln!(out, "# No issues found.");
    }
    for finding in findings {
        let _ = writeln!(
            out,
            "\n[{}::{}] {} (pc=0x{:x}, severity={:?})",
            finding.plugin, finding.rule, finding.title, finding.pc, finding.severity
        );
        for d in &finding.details {
            let _ = writeln!(out, "    {}", d);
        }
    }
    std::fs::create_dir_all("results")?;
    let tmp = format!("{}.tmp", FINDINGS_TXT);
    std::fs::write(&tmp, out)?;
    std::fs::rename(&tmp, FINDINGS_TXT)
}

/// Write both `results/plugin_findings.txt` and `results/plugin_findings.json`.
pub fn write_findings_reports(findings: &[Finding]) -> std::io::Result<()> {
    let txt = write_findings_txt(findings);
    write_findings(findings)?;
    txt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn int_value_describes_printable_byte() {
        let v = int_value(0x4b);
        assert_eq!(v["value"], 75);
        assert_eq!(v["signed"], 75);
        assert_eq!(v["hex"], "0x4b");
        assert_eq!(v["char"], "K");
    }

    #[test]
    fn int_value_has_no_char_for_non_printable_or_wide_values() {
        assert_eq!(int_value(0xca)["char"], Value::Null);
        assert_eq!(int_value(0x14b)["char"], Value::Null);
        assert_eq!(int_value(u64::MAX)["signed"], -1);
        assert_eq!(int_value(u64::MAX)["value"], u64::MAX);
    }
}
