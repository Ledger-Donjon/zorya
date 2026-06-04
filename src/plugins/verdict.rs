// SPDX-FileCopyrightText: 2026 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

//! Plugin return codes.
//!
//! When several plugins fire on the same event, the bus folds their verdicts
//! using [`Verdict::escalate`]: more severe verdicts win.

use crate::plugins::finding::Finding;

/// What a plugin asks the engine to do after observing an event.
#[derive(Debug, Default)]
pub enum Verdict {
    /// Default: keep going, the plugin had nothing to say.
    #[default]
    Continue,

    /// Stop exploring the current path. The engine prunes this state but
    /// continues with others. The string is logged for diagnostics.
    StopPath(&'static str),

    /// Report a finding and continue. The bus aggregates findings and the
    /// engine writes them to the report sink at end-of-run.
    ReportAndContinue(Finding),

    /// Abort the entire analysis. Use only for unrecoverable conditions
    /// (engine invariant violation observed by a plugin); ordinary findings
    /// should use `ReportAndContinue`.
    AbortAnalysis(&'static str),
}

impl Verdict {
    /// Severity rank used to fold multiple verdicts on a single event.
    pub fn rank(&self) -> u8 {
        match self {
            Verdict::Continue => 0,
            Verdict::ReportAndContinue(_) => 1,
            Verdict::StopPath(_) => 2,
            Verdict::AbortAnalysis(_) => 3,
        }
    }

    /// Pick the more severe of two verdicts. When two `ReportAndContinue`
    /// verdicts collide, both findings are kept by the bus; this method only
    /// returns the dominating *control-flow* effect.
    pub fn escalate(self, other: Verdict) -> Verdict {
        if other.rank() > self.rank() {
            other
        } else {
            self
        }
    }
}
