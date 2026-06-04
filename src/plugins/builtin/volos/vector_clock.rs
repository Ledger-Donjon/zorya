// SPDX-FileCopyrightText: 2026 KMSEC (PTY) LTD - https://kmsecurity.co.za
// SPDX-FileCopyrightText: 2026 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0
//
// Ported from `external/volosvc/src/lib.rs` of the upstream `zorya-volos`
// fork (https://github.com/kmsec137/zorya-volos), Apache-2.0 licensed.
// Original author: Keith Makan (KMSEC). Adapted into the Zorya plugin
// layer with no semantic changes beyond formatting.

//! Vector-clock implementation used by the volos race detector to
//! establish happens-before relationships between concurrent accesses.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt;

/// A logical clock indexed by node identifier (thread or goroutine id
/// rendered as a string).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolosVC {
    pub node_id: String,
    pub clocks: HashMap<String, u64>,
}

impl VolosVC {
    /// Create a new clock for `node_id`, initialised to 0.
    pub fn new(node_id: &str) -> Self {
        let mut clocks = HashMap::new();
        clocks.insert(node_id.to_string(), 0);
        Self {
            node_id: node_id.to_string(),
            clocks,
        }
    }

    /// Increment this clock's local component. Called before every local
    /// event so the clock reflects program order on this node.
    pub fn tick(&mut self) {
        let count = self.clocks.entry(self.node_id.clone()).or_insert(0);
        *count += 1;
    }

    /// Increment a specific node's component. Used when applying a
    /// recorded tick from a remote node.
    pub fn tick_at(&mut self, node_id: &str) {
        let count = self.clocks.entry(node_id.to_string()).or_insert(0);
        *count += 1;
    }

    /// Merge another clock into this one and tick. This is the standard
    /// happens-before "receive" operation: take the pointwise max of the
    /// two clocks, then bump the local component to mark the receive as
    /// later than both.
    pub fn merge(&mut self, other: &VolosVC) {
        for (node, &timestamp) in &other.clocks {
            let local = self.clocks.entry(node.clone()).or_insert(0);
            *local = (*local).max(timestamp);
        }
        self.tick();
    }

    /// Partial-order compare two clocks.
    ///
    /// - `Some(Greater)` — `self` strictly happens after `other`.
    /// - `Some(Less)`    — `self` strictly happens before `other`.
    /// - `Some(Equal)`   — both clocks are identical.
    /// - `None`          — concurrent (no happens-before relation).
    pub fn partial_cmp(&self, other: &VolosVC) -> Option<Ordering> {
        let mut greater = false;
        let mut less = false;

        let all_keys: std::collections::HashSet<&String> =
            self.clocks.keys().chain(other.clocks.keys()).collect();

        for key in all_keys {
            let v1 = self.clocks.get(key).copied().unwrap_or(0);
            let v2 = other.clocks.get(key).copied().unwrap_or(0);
            if v1 > v2 {
                greater = true;
            }
            if v1 < v2 {
                less = true;
            }
        }

        match (greater, less) {
            (true, false) => Some(Ordering::Greater),
            (false, true) => Some(Ordering::Less),
            (false, false) => Some(Ordering::Equal),
            (true, true) => None,
        }
    }
}

impl fmt::Display for VolosVC {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut entries: Vec<_> = self.clocks.iter().collect();
        entries.sort_by_key(|&(node, _)| node.clone());
        let parts: Vec<String> = entries
            .iter()
            .map(|(node, count)| format!("\"{}\":\"{}\"", node, count))
            .collect();
        write!(
            f,
            "VolosVC {{ node_id: \"{}\", clocks:[ {} ] }}",
            self.node_id,
            parts.join(", ")
        )
    }
}
