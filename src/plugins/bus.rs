// SPDX-FileCopyrightText: 2026 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

//! Event dispatcher.
//!
//! `EventBus` owns a vector of `Box<dyn Plugin>` and dispatches events to
//! every subscriber whose `wants()` set includes the event's kind. Two
//! invariants make this safe and cheap:
//!
//! 1. **Re-entrancy guard.** A `depth` counter is bumped on entry and
//!    cleared on exit. Plugins that read engine state from inside a handler
//!    (e.g. dereferencing a runtime struct to extract a thread or
//!    goroutine identifier) cannot recursively re-fire events. This
//!    replaces the per-call `internal: bool` parameter that ad-hoc,
//!    in-tree analyses tend to plumb through the memory API.
//!
//! 2. **Subscriber-set gating.** Each registered `EventKind` is OR-folded
//!    into a `subscribed` bitmap; `dispatch_if_subscribed` short-circuits
//!    when no plugin wants the event. This keeps the per-pcode `InstrPre` /
//!    `InstrPost` paths free of cost when no profiler is loaded.

use std::cell::{Cell, RefCell};
use std::time::Instant;

use z3::Context;

use crate::plugins::context::EventCtx;
use crate::plugins::event::{Event, EventKind};
use crate::plugins::finding::Finding;
use crate::plugins::plugin::Plugin;
use crate::plugins::verdict::Verdict;

pub struct EventBus<'ctx> {
    plugins: Vec<Box<dyn Plugin<'ctx>>>,

    /// Bitmap of `EventKind` discriminants any plugin subscribes to. Set
    /// at registration time and queried via `is_subscribed`.
    subscribed: u32,

    /// Re-entrancy counter. While > 0, `dispatch` short-circuits to
    /// `Verdict::Continue` so engine reads issued from inside a handler
    /// don't recurse.
    depth: Cell<u32>,

    /// Findings accumulated across all events. Drained by the report sink
    /// at end-of-analysis.
    findings: RefCell<Vec<Finding>>,
}

impl<'ctx> EventBus<'ctx> {
    pub fn new() -> Self {
        Self {
            plugins: Vec::new(),
            subscribed: 0,
            depth: Cell::new(0),
            findings: RefCell::new(Vec::new()),
        }
    }

    /// Register a plugin. The bus folds its `wants()` set into the global
    /// subscriber bitmap, so unsubscribed event kinds skip dispatch
    /// entirely.
    pub fn add(&mut self, plugin: Box<dyn Plugin<'ctx>>) {
        for k in plugin.wants() {
            self.subscribed |= kind_bit(k);
        }
        self.plugins.push(plugin);
    }

    /// True iff at least one registered plugin subscribed to `kind`. Use
    /// this at hot dispatch sites to skip event allocation when nothing is
    /// listening.
    #[inline]
    pub fn is_subscribed(&self, kind: EventKind) -> bool {
        self.subscribed & kind_bit(kind) != 0
    }

    pub fn plugin_count(&self) -> usize {
        self.plugins.len()
    }

    /// Dispatch an event to all interested plugins, folding their verdicts
    /// via [`Verdict::escalate`]. Re-entrant calls return
    /// [`Verdict::Continue`] without invoking any handler.
    pub fn dispatch(&mut self, ev: &Event<'ctx, '_>, ctx: &EventCtx<'ctx, '_>) -> Verdict {
        if self.depth.get() > 0 {
            return Verdict::Continue;
        }
        let kind = ev.kind();
        if !self.is_subscribed(kind) {
            return Verdict::Continue;
        }

        self.depth.set(self.depth.get() + 1);
        let mut worst = Verdict::Continue;
        for p in self.plugins.iter_mut() {
            if !p.wants().contains(&kind) {
                continue;
            }
            let v = p.on_event(ev, ctx);
            if let Verdict::ReportAndContinue(ref f) = v {
                self.findings.borrow_mut().push(f.clone());
            }
            worst = worst.escalate(v);
        }
        self.depth.set(self.depth.get() - 1);
        worst
    }

    /// Run `on_init` on every plugin. Called once after engine startup and
    /// symbol-table population, before the first instruction executes.
    pub fn run_init(&mut self, ctx: &EventCtx<'ctx, '_>) {
        for p in self.plugins.iter_mut() {
            p.on_init(ctx);
        }
    }

    /// Run `on_finish` on every plugin. Called once at end-of-analysis.
    pub fn run_finish(&mut self, ctx: &EventCtx<'ctx, '_>) {
        for p in self.plugins.iter_mut() {
            p.on_finish(ctx);
        }
    }

    /// Drain accumulated findings (for the report writer).
    pub fn take_findings(&self) -> Vec<Finding> {
        std::mem::take(&mut *self.findings.borrow_mut())
    }

    /// Borrow the internal findings buffer. Used by the dispatch site so
    /// the same `RefCell` is threaded into every `EventCtx` the bus
    /// constructs.
    pub fn findings_buffer(&self) -> &RefCell<Vec<Finding>> {
        &self.findings
    }

    /// Convenience entry point for the executor. Builds an [`EventCtx`]
    /// using the bus's own findings buffer and dispatches the event.
    /// Avoids the borrow-split dance the caller would otherwise need
    /// (constructing an `EventCtx` that borrows from `&self.findings`
    /// while also calling `&mut self.dispatch`).
    #[allow(clippy::too_many_arguments)]
    pub fn dispatch_with(
        &mut self,
        z3: &'ctx Context,
        pc: u64,
        tid: u64,
        goid: Option<u64>,
        instruction_counter: usize,
        start_time: Instant,
        ev: &Event<'ctx, '_>,
    ) -> Verdict {
        if self.depth.get() > 0 {
            return Verdict::Continue;
        }
        let kind = ev.kind();
        if !self.is_subscribed(kind) {
            return Verdict::Continue;
        }

        let ectx = EventCtx::new(z3, pc, tid, instruction_counter, start_time, &self.findings)
            .with_goid(goid);

        self.depth.set(self.depth.get() + 1);
        let mut worst = Verdict::Continue;
        for p in self.plugins.iter_mut() {
            if !p.wants().contains(&kind) {
                continue;
            }
            let v = p.on_event(ev, &ectx);
            if let Verdict::ReportAndContinue(ref f) = v {
                self.findings.borrow_mut().push(f.clone());
            }
            worst = worst.escalate(v);
        }
        self.depth.set(self.depth.get() - 1);
        worst
    }

    /// Counterpart of [`Self::dispatch_with`] for end-of-analysis. Builds
    /// an `EventCtx` from the bus's own findings buffer and runs every
    /// plugin's `on_finish`. Returns the number of findings now held in
    /// the buffer (i.e. the count after `on_finish` ran).
    pub fn run_finish_with(
        &mut self,
        z3: &'ctx Context,
        pc: u64,
        tid: u64,
        goid: Option<u64>,
        instruction_counter: usize,
        start_time: Instant,
    ) -> usize {
        let ectx = EventCtx::new(z3, pc, tid, instruction_counter, start_time, &self.findings)
            .with_goid(goid);
        for p in self.plugins.iter_mut() {
            p.on_finish(&ectx);
        }
        self.findings.borrow().len()
    }
}

impl<'ctx> Default for EventBus<'ctx> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'ctx> std::fmt::Debug for EventBus<'ctx> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&'static str> = self.plugins.iter().map(|p| p.name()).collect();
        f.debug_struct("EventBus")
            .field("plugins", &names)
            .field("subscribed", &format_args!("{:#b}", self.subscribed))
            .field("depth", &self.depth.get())
            .field("findings", &self.findings.borrow().len())
            .finish()
    }
}

#[inline]
fn kind_bit(k: EventKind) -> u32 {
    1u32 << (k as u32)
}
