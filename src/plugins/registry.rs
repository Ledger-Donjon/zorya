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

/// Determine which plugins are enabled based on the `ZORYA_PLUGINS` env var.
/// Returns a set of lowercase plugin names, or None meaning "all".
fn enabled_plugins() -> Option<Vec<String>> {
    let val = std::env::var("ZORYA_PLUGINS").unwrap_or_else(|_| "all".to_string());
    let val = val.trim().to_lowercase();
    if val.is_empty() || val == "all" {
        return None; // all plugins enabled
    }
    if val == "none" {
        return Some(Vec::new()); // no plugins
    }
    Some(val.split_whitespace().map(|s| s.to_string()).collect())
}

fn is_enabled(name: &str, filter: &Option<Vec<String>>) -> bool {
    match filter {
        None => true,
        Some(list) => list.iter().any(|s| s == name),
    }
}

/// Register every built-in plugin enabled via Cargo features. Called from
/// the engine's startup path right after `State` is constructed.
pub fn register_default<'ctx>(_bus: &mut EventBus<'ctx>) {
    let filter = enabled_plugins();

    #[cfg(feature = "plugin-volos")]
    if is_enabled("volos", &filter) {
        crate::plugins::builtin::volos::register(_bus);
    }

    #[cfg(feature = "plugin-chancheck")]
    if is_enabled("chancheck", &filter) {
        crate::plugins::builtin::chancheck::register(_bus);
    }

    #[cfg(feature = "plugin-toctou")]
    if is_enabled("toctou", &filter) {
        crate::plugins::builtin::toctou::register(_bus);
    }
}

/// Convenience for tests: register everything that ships with Zorya,
/// ignoring Cargo features.
#[cfg(test)]
pub fn register_all_for_tests<'ctx>(_bus: &mut EventBus<'ctx>) {
    // crate::plugins::builtin::panic_reach::register(_bus);
}
