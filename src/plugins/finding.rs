// SPDX-FileCopyrightText: 2026 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

//! Uniform finding type emitted by detector plugins via
//! [`Verdict::ReportAndContinue`].
//!
//! Keeping a single shared shape for findings means the report writer,
//! coverage bar, MCP server, and CI smoke tests can all consume plugin
//! output without each plugin inventing its own format.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Severity tier for a finding. This classifies how serious the *finding* is,
/// not whether the engine hit a runtime fault. Ordered from least to most
/// severe: `Info` < `Warning` < `High` < `Critical`.
///
/// (`High` is deliberately not called `Error`: an "Error" reads like Zorya
/// crashed, whereas these are analysis findings about the target binary.)
pub enum Severity {
    Info,
    Warning,
    High,
    Critical,
}

#[derive(Debug, Clone)]
pub struct Finding {
    /// Stable plugin id, e.g. `"panic-reach"`, `"coverage"`. Used for
    /// routing to per-plugin log files and for grouping in the final
    /// report.
    pub plugin: &'static str,

    /// Stable, machine-readable rule id within the plugin, e.g.
    /// `"nil-deref"`, `"out-of-bounds"`. Pair with `plugin` to identify
    /// the detector in CI baselines.
    pub rule: &'static str,

    pub severity: Severity,

    /// Program counter where the finding was triggered.
    pub pc: u64,

    /// One-line human summary.
    pub title: String,

    /// Free-form details: stack traces, lockset diff, race witness pairs,
    /// counterexample inputs, anything the plugin wants to attach.
    pub details: Vec<String>,
}

impl Finding {
    pub fn new(plugin: &'static str, rule: &'static str, severity: Severity, pc: u64, title: impl Into<String>) -> Self {
        Self {
            plugin,
            rule,
            severity,
            pc,
            title: title.into(),
            details: Vec::new(),
        }
    }

    pub fn with_detail(mut self, line: impl Into<String>) -> Self {
        self.details.push(line.into());
        self
    }
}
