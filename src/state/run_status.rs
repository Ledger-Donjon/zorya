// SPDX-FileCopyrightText: 2026 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

//! `results/run_status.json`: which phase a run is in, how long each phase
//! took, and why the run ended.
//!
//! The file is rewritten at every phase change, so after a run killed by
//! `timeout` (or a crash) it still names the phase that was running. The
//! launcher records its own phases (p-code generation, memory dump) in
//! `ZORYA_LAUNCHER_PHASES` before starting the engine; they are merged in.

use std::sync::Mutex;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

pub const RUN_STATUS_JSON: &str = "results/run_status.json";

/// Phase identifiers, with the label used in timeout reasons.
pub const PHASES: &[(&str, &str)] = &[
    ("pcode_generation", "p-code generation"),
    ("memory_dump", "memory and CPU dump"),
    ("binary_setup", "binary loading and symbol setup"),
    (
        "panic_prepass",
        "panic prepass (cross references and reachability)",
    ),
    ("symbolic_arg_setup", "symbolic argument setup"),
    ("execution", "concolic execution of the main goroutine"),
    ("scheduler_exploration", "goroutine scheduler exploration"),
    ("smt_solving", "SMT solving"),
    ("finalize", "report generation"),
];

/// Human label of a phase id.
pub fn phase_label(id: &str) -> &str {
    PHASES
        .iter()
        .find(|(p, _)| *p == id)
        .map(|(_, l)| *l)
        .unwrap_or(id)
}

#[derive(Debug)]
struct Status {
    started: Instant,
    started_unix: u64,
    current: Option<(String, Instant)>,
    /// Completed phases: (id, seconds).
    done: Vec<(String, f64)>,
    /// Phase the run was in before a temporary sub-phase (SMT solving).
    resume: Vec<String>,
    termination: Option<Value>,
    extra: serde_json::Map<String, Value>,
}

static STATUS: Mutex<Option<Status>> = Mutex::new(None);

fn with_status<R>(f: impl FnOnce(&mut Status) -> R) -> R {
    let mut guard = STATUS.lock().unwrap_or_else(|e| e.into_inner());
    let st = guard.get_or_insert_with(|| Status {
        started: Instant::now(),
        started_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        current: None,
        done: Vec::new(),
        resume: Vec::new(),
        termination: None,
        extra: serde_json::Map::new(),
    });
    f(st)
}

/// Close the running phase and open `id`. Re-entering the running phase is
/// a no-op.
pub fn enter_phase(id: &str) {
    let changed = with_status(|st| {
        if st.current.as_ref().is_some_and(|(p, _)| p == id) {
            return false;
        }
        close_current(st);
        st.current = Some((id.to_string(), Instant::now()));
        true
    });
    if changed {
        write();
    }
}

/// Enter a temporary sub-phase; [`leave_subphase`] returns to the phase
/// that was running before. Used around solver calls.
pub fn enter_subphase(id: &str) {
    with_status(|st| {
        let prev = st.current.as_ref().map(|(p, _)| p.clone());
        if let Some(prev) = prev {
            if prev == id {
                return;
            }
            st.resume.push(prev);
        }
        close_current(st);
        st.current = Some((id.to_string(), Instant::now()));
    });
}

/// Leave the sub-phase entered with [`enter_subphase`].
pub fn leave_subphase() {
    with_status(|st| {
        if let Some(prev) = st.resume.pop() {
            close_current(st);
            st.current = Some((prev, Instant::now()));
        }
    });
}

fn close_current(st: &mut Status) {
    if let Some((id, t0)) = st.current.take() {
        let secs = t0.elapsed().as_secs_f64();
        if let Some(entry) = st.done.iter_mut().find(|(p, _)| *p == id) {
            entry.1 += secs;
        } else {
            st.done.push((id, secs));
        }
    }
}

/// The running phase id (`""` before the first phase).
pub fn current_phase() -> String {
    with_status(|st| {
        st.current
            .as_ref()
            .map(|(p, _)| p.clone())
            .unwrap_or_default()
    })
}

/// Attach an extra top-level field (e.g. `race_only`).
pub fn set_field(key: &str, value: Value) {
    with_status(|st| {
        st.extra.insert(key.to_string(), value);
    });
}

/// Record how the run ended. `outcome` is `completed`, `timeout`, `signal`
/// or `error`; for the latter three the running phase becomes the reason.
pub fn finish(outcome: &str, detail: Option<&str>) {
    with_status(|st| {
        let phase = st
            .current
            .as_ref()
            .map(|(p, _)| p.clone())
            .unwrap_or_default();
        let reason = (outcome != "completed").then(|| {
            let mut r = format!("{outcome} during {}", phase_label(&phase));
            if let Some(d) = detail {
                r.push_str(": ");
                r.push_str(d);
            }
            r
        });
        st.termination = Some(json!({
            "outcome": outcome,
            "phase": phase,
            "reason": reason,
            "detail": detail,
            "z3_cumulative_ms": crate::Z3_CUMULATIVE_MS.load(std::sync::atomic::Ordering::Relaxed),
        }));
    });
    write();
}

/// The `termination` object recorded by [`finish`], if any.
pub fn termination() -> Option<Value> {
    with_status(|st| st.termination.clone())
}

fn launcher_phases() -> Vec<Value> {
    std::env::var("ZORYA_LAUNCHER_PHASES")
        .unwrap_or_default()
        .split(',')
        .filter_map(|entry| {
            let (id, secs) = entry.split_once(':')?;
            Some(json!({
                "phase": id.trim(),
                "label": phase_label(id.trim()),
                "seconds": secs.trim().parse::<f64>().ok()?,
                "by": "launcher",
            }))
        })
        .collect()
}

/// Build the JSON document.
pub fn to_json() -> Value {
    with_status(|st| {
        let mut phases = launcher_phases();
        for (id, secs) in &st.done {
            phases.push(json!({
                "phase": id,
                "label": phase_label(id),
                "seconds": (secs * 1000.0).round() / 1000.0,
                "by": "engine",
            }));
        }
        let current = st.current.as_ref().map(|(id, t0)| {
            json!({
                "phase": id,
                "label": phase_label(id),
                "seconds_so_far": (t0.elapsed().as_secs_f64() * 1000.0).round() / 1000.0,
            })
        });
        let mut doc = json!({
            "schema": "zorya.run_status/1",
            "binary": std::env::var("BIN_PATH").unwrap_or_default(),
            "started_unix": st.started_unix,
            "elapsed_seconds": (st.started.elapsed().as_secs_f64() * 1000.0).round() / 1000.0,
            "current_phase": current,
            "phases": phases,
            "termination": st.termination.clone(),
        });
        if let Value::Object(map) = &mut doc {
            for (k, v) in &st.extra {
                map.insert(k.clone(), v.clone());
            }
        }
        doc
    })
}

/// Write `results/run_status.json` (skipped in unit tests).
pub fn write() {
    if cfg!(test) {
        return;
    }
    let doc = to_json();
    let _ = std::fs::create_dir_all("results");
    let tmp = format!("{RUN_STATUS_JSON}.tmp");
    if let Ok(s) = serde_json::to_string_pretty(&doc) {
        if std::fs::write(&tmp, s).is_ok() {
            let _ = std::fs::rename(&tmp, RUN_STATUS_JSON);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phases_and_termination_reason() {
        enter_phase("execution");
        enter_subphase("smt_solving");
        assert_eq!(current_phase(), "smt_solving");
        leave_subphase();
        assert_eq!(current_phase(), "execution");
        enter_phase("scheduler_exploration");
        finish("timeout", Some("ZORYA_TIMEOUT_SECS reached"));
        let doc = to_json();
        let reason = doc["termination"]["reason"].as_str().unwrap();
        assert!(reason.starts_with("timeout during goroutine scheduler exploration"));
        let phases: Vec<&str> = doc["phases"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|p| p["phase"].as_str())
            .collect();
        assert!(phases.contains(&"execution"));
        assert!(phases.contains(&"smt_solving"));
    }
}
