// SPDX-FileCopyrightText: 2026 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

//! Example plugin — copy-paste template for new detectors.
//!
//! Demonstrates the minimum surface: a struct that holds private state, an
//! `impl Plugin` that subscribes to a small set of events and returns
//! verdicts, and a `register` factory that the engine calls on startup.
//!
//! See `manifest.yaml` next to this file for the metadata format.
//! Production plugins go alongside this folder under
//! `src/plugins/builtin/<name>/`.

use std::collections::HashSet;

use crate::plugins::context::EventCtx;
use crate::plugins::event::{Event, EventKind};
use crate::plugins::plugin::Plugin;
use crate::plugins::verdict::Verdict;
use crate::plugins::EventBus;

/// Example plugin that counts memory reads and writes.
pub struct ExamplePlugin {
    reads: u64,
    writes: u64,
}

impl ExamplePlugin {
    pub fn new() -> Self {
        Self { reads: 0, writes: 0 }
    }

    /// Read-only access to the running counters; used in tests to verify
    /// dispatch reaches this plugin's `on_event`.
    pub fn counters(&self) -> (u64, u64) {
        (self.reads, self.writes)
    }
}

impl Default for ExamplePlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl<'ctx> Plugin<'ctx> for ExamplePlugin {
    fn name(&self) -> &'static str {
        "example"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn wants(&self) -> HashSet<EventKind> {
        [EventKind::MemRead, EventKind::MemWrite].into_iter().collect()
    }

    fn on_event(
        &mut self,
        ev: &Event<'ctx, '_>,
        _ctx: &EventCtx<'ctx, '_>,
    ) -> Verdict {
        match ev {
            Event::MemRead { .. } => self.reads += 1,
            Event::MemWrite { .. } => self.writes += 1,
            _ => {}
        }
        Verdict::Continue
    }

    fn on_finish(&mut self, _ctx: &EventCtx<'ctx, '_>) {
        // A real plugin would flush a structured report here. The example
        // plugin just records counters.
    }
}

/// Factory called from `crate::plugins::registry::register_default` when
/// the `plugin-example` Cargo feature is enabled.
pub fn register<'ctx>(bus: &mut EventBus<'ctx>) {
    bus.add(Box::new(ExamplePlugin::new()));
}
