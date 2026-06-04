// SPDX-FileCopyrightText: 2026 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

//! Zorya plugin infrastructure.
//!
//! The plugin layer lets contributors react to events fired by the concolic
//! executor (memory accesses, branches, calls, syscalls, thread events,
//! panics) without modifying core data structures or the existing memory /
//! executor APIs.
//!
//! See `doc/Plugins.md` for the full design rationale, the porting
//! walkthrough for in-tree analyses, and the contract that plugin authors
//! and core maintainers commit to.
//!
//! ## Quick orientation
//!
//! - [`Plugin`]    — the trait every extension implements.
//! - [`Event`]     — the typed event vocabulary fired by the engine.
//! - [`Verdict`]   — what a plugin returns from `on_event` to influence the
//!   exploration (continue / stop this path / report finding / abort).
//! - [`EventBus`]  — owned by `State`; dispatches events to subscribers,
//!   guards re-entrancy so plugins that read engine state from inside a
//!   handler don't recursively re-fire events.
//! - [`EventCtx`]  — read-only handle plugins receive alongside every event.
//! - [`Finding`]   — uniform finding type for `Verdict::ReportAndContinue`.
//!
//! ## Adding a built-in plugin
//!
//! 1. Create `src/plugins/builtin/<name>/mod.rs` exposing
//!    `pub fn register(bus: &mut EventBus<'_>)` (see `builtin/example`).
//! 2. Add `pub mod <name>;` to `src/plugins/builtin/mod.rs`.
//! 3. Call `<name>::register(bus)` from [`registry::register_default`].
//!
//! A future revision will replace step 2/3 with a build-script sweep so the
//! manifest alone is sufficient.

pub mod bus;
pub mod context;
pub mod event;
pub mod finding;
pub mod plugin;
pub mod registry;
pub mod verdict;

pub mod builtin;

#[cfg(test)]
mod tests;

pub use bus::EventBus;
pub use context::EventCtx;
pub use event::{AccessOrigin, Event, EventKind, MemAccessKind};
pub use finding::{Finding, Severity};
pub use plugin::Plugin;
pub use verdict::Verdict;
