// SPDX-FileCopyrightText: 2026 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

//! Plugin registration.
//!
//! v1 uses **build-time discovery**: every directory under
//! `src/plugins/builtin/` is a plugin candidate, and adding a new plugin is
//! "drop the folder, add `pub mod <name>;` to `builtin/mod.rs`, and call
//! `<name>::register(bus)` here."
//!
//! A future revision will replace the manual registration call with a
//! `build.rs` that scans `src/plugins/builtin/*/manifest.yaml` and emits
//! the registration list. The trait surface stays the same, so plugins
//! written today will continue to work after that change.
//!
//! Per-plugin Cargo features (`plugin-<name>`) gate compile-time inclusion
//! so users can disable any plugin without forking Zorya.

use crate::plugins::EventBus;

/// Register every built-in plugin enabled via Cargo features. Called from
/// the engine's startup path right after `State` is constructed.
pub fn register_default<'ctx>(_bus: &mut EventBus<'ctx>) {
    // Built-in plugins are wired in via their own `register()` factories.
    // Keep the calls feature-gated so users can compile a stripped-down
    // engine for benchmarking.
    //
    // #[cfg(feature = "plugin-panic-reach")]
    // crate::plugins::builtin::panic_reach::register(_bus);
    //
    // #[cfg(feature = "plugin-coverage")]
    // crate::plugins::builtin::coverage::register(_bus);

    // Volos race detector — plugin port of the upstream zorya-volos fork
    // (https://github.com/kmsec137/zorya-volos). Receives MemRead /
    // MemWrite / Call (lock primitives) / ThreadSpawn / ThreadExit
    // events from the executor handlers and emits one finding per
    // witness pair at end-of-trace.
    #[cfg(feature = "plugin-volos")]
    crate::plugins::builtin::volos::register(_bus);

    // The example plugin is intentionally not registered here; it serves
    // as a copy-paste template, not a default detector.
}

/// Convenience for tests: register everything that ships with Zorya,
/// ignoring Cargo features.
#[cfg(test)]
pub fn register_all_for_tests<'ctx>(_bus: &mut EventBus<'ctx>) {
    // crate::plugins::builtin::panic_reach::register(_bus);
}
