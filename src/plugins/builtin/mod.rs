// SPDX-FileCopyrightText: 2026 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

//! Built-in plugins shipped with Zorya.
//!
//! Add a new built-in plugin by:
//! 1. Creating `src/plugins/builtin/<name>/mod.rs` with a `register(bus)`
//!    factory function (see `example`).
//! 2. Adding `pub mod <name>;` here.
//! 3. Wiring `<name>::register(bus)` into
//!    [`crate::plugins::registry::register_default`] under a
//!    `#[cfg(feature = "plugin-<name>")]` gate.

pub mod chancheck;
pub mod example;
pub mod toctou;
pub mod volos;
