// SPDX-FileCopyrightText: 2026 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

//! Analysis profiles chosen with the launcher's `--analysis` flag.
//!
//! The launcher turns each profile into plugins, scheduling and exploration
//! settings, and passes the selection in `ZORYA_ANALYSES`. The engine reads it
//! here to decide which checks run, and writes `results/analysis_summary.json`
//! at the end of the run: one verdict per analysis and the next input to try,
//! which the launcher's input rounds follow.

use serde_json::{json, Map, Value};

use crate::plugins::Finding;
use crate::state::race_report;

pub const ANALYSIS_SUMMARY_JSON: &str = "results/analysis_summary.json";

/// Analyses in report order. `concurrency` and `full` are groups of them.
pub const ANALYSES: &[&str] = &[
    "data-race",
    "channel-safety",
    "toctou",
    "panic",
    "memory-safety",
    "arithmetic",
];

/// Analyses that look for an input creating the goroutines or reaching the
/// checks they need, and so drive the launcher's input rounds.
const INPUT_EXPLORING: &[&str] = &["data-race", "channel-safety", "toctou"];

/// The analyses a profile name stands for (empty for an unknown name).
pub fn expand(profile: &str) -> &'static [&'static str] {
    match profile {
        "data-race" => &["data-race"],
        "channel-safety" => &["channel-safety"],
        "toctou" => &["toctou"],
        "panic" => &["panic"],
        "memory-safety" => &["memory-safety"],
        "arithmetic" => &["arithmetic"],
        "concurrency" => INPUT_EXPLORING,
        "full" => ANALYSES,
        _ => &[],
    }
}

/// Analyses named in `list`, profile names separated by commas or spaces.
pub fn parse(list: &str) -> Vec<&'static str> {
    let wanted: Vec<&str> = list.split([',', ' ']).flat_map(expand).copied().collect();
    ANALYSES
        .iter()
        .copied()
        .filter(|a| wanted.contains(a))
        .collect()
}

/// Analyses of this run, empty when it was configured without `--analysis`.
/// The deprecated `--race-only` stands for `data-race`.
pub fn selected() -> Vec<&'static str> {
    let list = std::env::var("ZORYA_ANALYSES").unwrap_or_default();
    if list.trim().is_empty() && std::env::var("ZORYA_RACE_ONLY").is_ok_and(|v| v == "1") {
        return vec!["data-race"];
    }
    parse(&list)
}

/// The panic prepass and the AST panic exploration run.
pub fn panic_analysis() -> bool {
    let sel = selected();
    sel.is_empty() || sel.contains(&"panic")
}

/// Bugs reached in an overlay (panics, NULL dereferences, divisions by zero)
/// are solved for an input and reported.
pub fn overlay_bug_reports() -> bool {
    let sel = selected();
    sel.is_empty()
        || sel
            .iter()
            .any(|a| matches!(*a, "panic" | "memory-safety" | "arithmetic"))
}

/// A concurrency analysis was selected: negated branches that create
/// goroutines are solved into candidate seeds, and argv bytes default to
/// printable characters since the reports print them as strings.
pub fn explores_inputs() -> bool {
    selected().iter().any(|a| INPUT_EXPLORING.contains(a))
}

/// The analysis a `results/FOUND_SAT_STATE.json` entry belongs to.
pub fn sat_entry_analysis(entry: &Value) -> &'static str {
    let opcode = entry["opcode"].as_str().unwrap_or("");
    let bug = entry["bug"].as_str().unwrap_or("");
    if bug.contains("DIV")
        || matches!(
            opcode,
            "INT_ADD"
                | "INT_SUB"
                | "INT_MULT"
                | "INT_DIV"
                | "INT_SDIV"
                | "INT_REM"
                | "INT_SREM"
                | "TRUNC"
        )
    {
        "arithmetic"
    } else if entry["kind"] == "bug" || matches!(opcode, "LOAD" | "STORE") {
        "memory-safety"
    } else {
        "panic"
    }
}

/// Verdict of one analysis. `done` means another input round cannot add to
/// it: something was found, or the race is known to be fixed in the
/// toolchain.
fn analysis_result(
    analysis: &str,
    findings: &[Finding],
    race: Option<&Value>,
    sat_entries: &[Value],
) -> Value {
    let reported = |plugin: &str| findings.iter().filter(|f| f.plugin == plugin).count();
    let by_plugin = |plugin: &str| {
        let n = reported(plugin);
        json!({ "found": n > 0, "done": n > 0, "findings": n })
    };
    match analysis {
        "data-race" => {
            let status = race.and_then(|d| d["status"].as_str()).unwrap_or("no_race");
            let found = race.and_then(|d| d["race_found"].as_bool()) == Some(true);
            json!({
                "found": found,
                "done": found || status == "stdlib_fixed",
                "status": status,
                "races": race.and_then(|d| d["races_total"].as_u64()).unwrap_or(0),
                "findings": reported("volos"),
            })
        }
        "channel-safety" => by_plugin("chancheck"),
        "toctou" => by_plugin("toctou"),
        _ => {
            let n = sat_entries
                .iter()
                .filter(|e| sat_entry_analysis(e) == analysis)
                .count();
            json!({ "found": n > 0, "done": n > 0, "sat_states": n })
        }
    }
}

/// Summary of the run for `analyses`. `next_seed` is the best untried
/// candidate input while some analysis is not done.
pub fn summary_json(
    analyses: &[&str],
    findings: &[Finding],
    race: Option<&Value>,
    sat_entries: &[Value],
    termination: Option<Value>,
) -> Value {
    let results: Map<String, Value> = analyses
        .iter()
        .map(|&a| {
            (
                a.to_string(),
                analysis_result(a, findings, race, sat_entries),
            )
        })
        .collect();
    let complete = results.values().all(|r| r["done"] == true);
    let (seed, candidates) = race_report::with_store(|s| {
        (
            race_report::decode_argv(&s.seed_args, &[]),
            s.candidates.len(),
        )
    });
    let next_seed = if complete {
        None
    } else {
        race_report::next_candidate_seed()
    };
    json!({
        "schema": "zorya.analysis_summary/1",
        "binary": std::env::var("BIN_PATH").ok(),
        "analyses": analyses,
        "seed": seed,
        "seeds_tried": race_report::seeds_tried(),
        "results": results,
        "found": results.values().any(|r| r["found"] == true),
        "complete": complete,
        "candidate_seeds": candidates,
        "next_seed": next_seed,
        "run": termination,
    })
}

/// Write `results/analysis_summary.json` and print one line per analysis.
/// Skipped when no profile was selected.
pub fn write_summary(
    findings: &[Finding],
    race: Option<&Value>,
    termination: Option<Value>,
) -> Option<Value> {
    let analyses = selected();
    if analyses.is_empty() || cfg!(test) {
        return None;
    }
    let sat_entries = crate::state::json_report::sat_entries();
    let doc = summary_json(&analyses, findings, race, &sat_entries, termination);
    let _ = std::fs::create_dir_all("results");
    let tmp = format!("{ANALYSIS_SUMMARY_JSON}.tmp");
    if let Ok(s) = serde_json::to_string_pretty(&doc) {
        if std::fs::write(&tmp, s).is_ok() {
            let _ = std::fs::rename(&tmp, ANALYSIS_SUMMARY_JSON);
        }
    }
    print_verdict(&doc);
    Some(doc)
}

fn print_verdict(doc: &Value) {
    crate::teprintln!();
    for (name, r) in doc["results"].as_object().into_iter().flatten() {
        let (count, unit) = [
            ("races", "distinct race(s)"),
            ("findings", "finding(s)"),
            ("sat_states", "satisfiable state(s)"),
        ]
        .into_iter()
        .find_map(|(key, unit)| r[key].as_u64().map(|n| (n, unit)))
        .unwrap_or((0, "finding(s)"));
        let verdict = match (r["found"] == true, r["status"].as_str()) {
            (true, _) => format!("found, {count} {unit}"),
            (false, Some("stdlib_fixed")) => "fixed in the toolchain".to_string(),
            (false, _) => "nothing found".to_string(),
        };
        crate::teprintln!("[ANALYSIS] {name}: {verdict}");
    }
    crate::teprintln!("[ANALYSIS] seed: {}", doc["seed"]);
    if !doc["next_seed"].is_null() {
        crate::teprintln!("[ANALYSIS] next seed to try: {}", doc["next_seed"]);
    }
    crate::teprintln!("[ANALYSIS] summary written to {ANALYSIS_SUMMARY_JSON}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::Severity;

    #[test]
    fn profiles_expand_and_merge_in_report_order() {
        assert_eq!(
            parse("channel-safety,data-race"),
            vec!["data-race", "channel-safety"]
        );
        assert_eq!(
            parse("concurrency panic"),
            vec!["data-race", "channel-safety", "toctou", "panic"]
        );
        assert_eq!(parse("full"), ANALYSES.to_vec());
        assert_eq!(parse("data-race,concurrency"), INPUT_EXPLORING.to_vec());
        assert!(parse("recursion,unknown").is_empty());
    }

    #[test]
    fn sat_entries_are_attributed_to_their_analysis() {
        let panic = json!({ "kind": "satisfiable_state", "opcode": "CBRANCH" });
        let overflow = json!({ "kind": "satisfiable_state", "opcode": "INT_ADD" });
        let null = json!({ "kind": "satisfiable_state", "opcode": "LOAD" });
        let null_overlay = json!({ "kind": "bug", "bug": "NULL_DEREF_STORE" });
        let div = json!({ "kind": "bug", "bug": "DIV_BY_ZERO" });
        assert_eq!(sat_entry_analysis(&panic), "panic");
        assert_eq!(sat_entry_analysis(&overflow), "arithmetic");
        assert_eq!(sat_entry_analysis(&null), "memory-safety");
        assert_eq!(sat_entry_analysis(&null_overlay), "memory-safety");
        assert_eq!(sat_entry_analysis(&div), "arithmetic");
    }

    #[test]
    fn summary_is_complete_only_when_every_analysis_is_done() {
        let close = Finding::new("chancheck", "close-of-closed", Severity::High, 0x10, "x");
        let race = json!({ "status": "no_race", "race_found": false });
        let doc = summary_json(
            &["data-race", "channel-safety"],
            std::slice::from_ref(&close),
            Some(&race),
            &[],
            None,
        );
        assert_eq!(doc["results"]["channel-safety"]["found"], true);
        assert_eq!(doc["results"]["data-race"]["done"], false);
        assert_eq!(doc["found"], true);
        assert_eq!(doc["complete"], false);

        let fixed = json!({ "status": "stdlib_fixed", "race_found": false });
        let doc = summary_json(
            &["data-race", "channel-safety"],
            &[close],
            Some(&fixed),
            &[],
            None,
        );
        assert_eq!(doc["complete"], true);
        assert!(doc["next_seed"].is_null());
    }
}
