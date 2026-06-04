// SPDX-FileCopyrightText: 2026 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

//! The [`Plugin`] trait every Zorya extension implements.
//!
//! The default `on_event` implementation is a no-op so plugins only need to
//! implement the events they actually care about. The `wants` method lets
//! the bus skip cold dispatches entirely (especially important for the hot
//! `InstrPre` / `InstrPost` events).

use std::collections::HashSet;

use crate::plugins::context::EventCtx;
use crate::plugins::event::{Event, EventKind};
use crate::plugins::verdict::Verdict;

/// A Zorya plugin.
///
/// Plugins are owned by [`crate::plugins::EventBus`] as `Box<dyn Plugin>`
/// trait objects. They hold their own private mutable state and observe
/// engine state through the read-only [`EventCtx`] handed to every event.
pub trait Plugin<'ctx>: 'ctx {
    /// Stable, kebab-case plugin name. Used for log file routing
    /// (`results/<name>.log`), finding attribution, and config keys.
    fn name(&self) -> &'static str;

    /// Plugin version string, surfaced in reports for reproducibility.
    fn version(&self) -> &'static str {
        "0.0.0"
    }

    /// Declare which events this plugin wants to observe. The bus uses this
    /// to skip dispatch for unsubscribed kinds. Override when a plugin only
    /// cares about a small subset (e.g. `Call` + `ThreadSpawn` for a
    /// lockset analyzer).
    fn wants(&self) -> HashSet<EventKind> {
        // By default, subscribe to everything except the per-pcode hot path.
        use EventKind::*;
        [
            MemRead,
            MemWrite,
            Branch,
            Call,
            Return,
            Syscall,
            SyscallRet,
            ThreadSpawn,
            ThreadSwitch,
            ThreadExit,
            Panic,
        ]
        .into_iter()
        .collect()
    }

    /// Symbol names this plugin wants notifications for via `Event::Call`.
    /// At plugin-load time the registry resolves these against the binary's
    /// symbol table, warns about unresolved entries (which may be stripped
    /// or lazy-loaded), and keeps the unresolved set as deferred bindings
    /// that retroactively bind on each `Call` event.
    fn symbol_hooks(&self) -> &'static [&'static str] {
        &[]
    }

    /// One-time initialization, called once after the engine has loaded the
    /// binary and the symbol table but before execution starts. The default
    /// is a no-op.
    fn on_init(&mut self, _ctx: &EventCtx<'ctx, '_>) {}

    /// Event entry point. Default is a no-op so plugins implement only what
    /// they care about. Return [`Verdict::Continue`] for events the plugin
    /// observed but doesn't want to influence.
    fn on_event(&mut self, _ev: &Event<'ctx, '_>, _ctx: &EventCtx<'ctx, '_>) -> Verdict {
        Verdict::Continue
    }

    /// End-of-analysis callback. Plugins flush their reports and any
    /// post-pass analyses here (cross-check passes over accumulated
    /// state, summary writers, baseline comparisons).
    fn on_finish(&mut self, _ctx: &EventCtx<'ctx, '_>) {}
}
