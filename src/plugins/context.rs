// SPDX-FileCopyrightText: 2026 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

//! Read-only handle plugins receive alongside every event.
//!
//! `EventCtx` is the firewall between plugins and engine internals. In
//! Phase A it exposes only metadata that every plugin needs: the Z3
//! context, current PC / TID / instruction counter, analysis start time,
//! and a read view of accumulated findings.
//!
//! Engine state accessors (`&State`, `&Optimize`, symbol-table lookups,
//! per-thread register reads) are intentionally **not** part of this
//! struct yet. They will be added one at a time as each migrated plugin
//! demonstrates a real need, so the surface stays minimal and the bus
//! stays unit-testable without standing up a full engine.

use std::cell::RefCell;
use std::time::Instant;

use z3::ast::Bool;
use z3::Context;

use crate::plugins::finding::Finding;

/// Per-event context passed to every [`crate::plugins::Plugin::on_event`]
/// invocation.
///
/// Lifetimes:
/// - `'ctx` — Z3 context lifetime.
/// - `'s`   — short borrow of the dispatch site's frame; plugins must not
///   stash `'s` references.
pub struct EventCtx<'ctx, 's> {
    /// The shared Z3 context. Plugins use this to allocate solver objects
    /// for their own constraints; they should not allocate AST nodes
    /// inside hot dispatch paths unless gated on a subscriber check.
    pub ctx: &'ctx Context,

    /// PC at which the current event fired.
    pub current_pc: u64,

    /// TID of the executing thread when the event fired.
    pub current_tid: u64,

    /// Best-effort *real* goroutine id at the time of dispatch, extracted
    /// by the engine from the Go runtime `g` struct via TLS. `None` for
    /// non-Go binaries, or when the runtime hasn't been initialised yet
    /// (TLS base is 0). Plugins should prefer this over a synthetic
    /// thread/goroutine id when present, since it matches the user's
    /// mental model of the program.
    pub current_goid: Option<u64>,

    /// Monotonic instruction counter (matches
    /// `ConcolicExecutor::instruction_counter` once the dispatch sites
    /// are wired).
    pub instruction_counter: usize,

    /// Wall-clock start of the analysis run.
    pub start_time: Instant,

    /// Findings accumulated so far on this event. Plugins should prefer
    /// returning [`crate::plugins::Verdict::ReportAndContinue`] to push a
    /// finding, but the buffer is exposed read-only here so a plugin can
    /// observe what an earlier-ordered plugin already raised.
    pub(crate) findings: &'s RefCell<Vec<Finding>>,

    /// The engine's *current path condition*: the ordered set of branch
    /// constraints (over tracked symbolic inputs) accumulated on the path
    /// that reached this event. This is a borrowed view of the executor's
    /// `constraint_vector`; their conjunction is the predicate `φ` under
    /// which the current concrete path is taken.
    ///
    /// Concurrency-aware detectors use this to turn a schedule-specific
    /// witness ("these two accesses raced on *this* run") into an
    /// input-class result ("they race for every input satisfying `φ₁ ∧ φ₂`").
    /// Empty when no symbolic input gates the path (input-independent), or
    /// for non-symbolic runs.
    ///
    /// Plugins must **not** stash the `'s` slice; clone the `Bool<'ctx>`
    /// nodes they need (cheap, reference-counted, valid for `'ctx`).
    pub(crate) path_constraints: &'s [Bool<'ctx>],
}

impl<'ctx, 's> EventCtx<'ctx, 's> {
    /// Build a minimal context. Used by the dispatch site (the executor)
    /// and by tests; plugin authors never construct one.
    pub fn new(
        ctx: &'ctx Context,
        current_pc: u64,
        current_tid: u64,
        instruction_counter: usize,
        start_time: Instant,
        findings: &'s RefCell<Vec<Finding>>,
    ) -> Self {
        Self {
            ctx,
            current_pc,
            current_tid,
            current_goid: None,
            instruction_counter,
            start_time,
            findings,
            path_constraints: &[],
        }
    }

    /// Builder: attach the current goroutine id to this context.
    pub fn with_goid(mut self, goid: Option<u64>) -> Self {
        self.current_goid = goid;
        self
    }

    /// Builder: attach a borrowed view of the engine's current path
    /// constraints (the executor's `constraint_vector`).
    pub fn with_path_constraints(mut self, parts: &'s [Bool<'ctx>]) -> Self {
        self.path_constraints = parts;
        self
    }

    /// The branch constraints accumulated on the path that reached this
    /// event. Their conjunction is the path condition `φ`. Empty slice means
    /// the path is input-independent (or the run is non-symbolic).
    pub fn path_constraints(&self) -> &[Bool<'ctx>] {
        self.path_constraints
    }

    /// Snapshot of the findings list; plugins can use this to suppress
    /// duplicate reports when several detectors fire on the same address.
    pub fn findings(&self) -> std::cell::Ref<'_, Vec<Finding>> {
        self.findings.borrow()
    }
}
