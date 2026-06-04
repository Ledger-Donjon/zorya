// SPDX-FileCopyrightText: 2026 KMSEC (PTY) LTD - https://kmsecurity.co.za
// SPDX-FileCopyrightText: 2026 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0
//
// Ported from `src/state/memory_x86_64.rs` of the upstream `zorya-volos`
// fork (https://github.com/kmsec137/zorya-volos), Apache-2.0 licensed.
// Original author: Keith Makan (KMSEC). Adapted into the Zorya plugin
// layer.

//! Per-address access history and the volos finite-state automaton.

use std::collections::HashMap;
use std::fmt;

use super::record::{AccessType, Volos};

/// State of a tracked memory cell. Captures whether the cell has been
/// observed by exactly one thread (Exclusive), by several threads
/// read-only (Shared), modified by some thread (SharedModified), or
/// participates in a race (Raceable, Reported).
///
/// The transitions follow the original volos design: an unprotected
/// SharedModified access promotes to Raceable; once reported, the cell
/// stays in Reported to avoid duplicate findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolosState {
    Virgin,
    Exclusive,
    Shared,
    SharedModified,
    Raceable,
    Reported,
}

impl VolosState {
    /// Inspect the access history for a single cell and decide its state.
    pub fn classify(history: &[Volos]) -> Self {
        if history.is_empty() {
            return VolosState::Virgin;
        }

        let mut threads = std::collections::HashSet::new();
        let mut any_write = false;
        for v in history {
            threads.insert(v.thread_id);
            if v.access_type == AccessType::Write {
                any_write = true;
            }
        }

        if threads.len() < 2 {
            return VolosState::Exclusive;
        }

        if any_write {
            // Any pair (different threads, at least one write, no shared
            // lock) makes the cell Raceable.
            for i in 0..history.len() {
                for j in (i + 1)..history.len() {
                    let v1 = &history[i];
                    let v2 = &history[j];
                    if v1.thread_id == v2.thread_id {
                        continue;
                    }
                    let one_is_write = v1.access_type == AccessType::Write
                        || v2.access_type == AccessType::Write;
                    if one_is_write && !v1.shares_lock(v2) {
                        return VolosState::Raceable;
                    }
                }
            }
            VolosState::SharedModified
        } else {
            VolosState::Shared
        }
    }
}

impl fmt::Display for VolosState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            VolosState::Virgin => "VIRGIN",
            VolosState::Exclusive => "EXCLUSIVE",
            VolosState::Shared => "SHARED",
            VolosState::SharedModified => "SHARED-MODIFIED",
            VolosState::Raceable => "RACEABLE",
            VolosState::Reported => "REPORTED",
        };
        f.write_str(s)
    }
}

/// Per-cell entry: the FSA state, plus the full access history that lead
/// to that state. Keeping the history is what lets the race-check pass
/// produce concrete witness pairs in findings.
#[derive(Debug, Clone, Default)]
pub struct CellHistory {
    pub state: VolosState,
    pub accesses: Vec<Volos>,
}

impl Default for VolosState {
    fn default() -> Self {
        VolosState::Virgin
    }
}

/// A memory region with per-cell access tracking.
#[derive(Debug, Clone)]
pub struct VolosRegion {
    pub start_address: u64,
    pub end_address: u64,
    /// Aggregate state of the whole region (worst-case across cells).
    pub state: VolosState,
    /// Per-byte history. Keyed by absolute address.
    pub cells: HashMap<u64, CellHistory>,
}

impl VolosRegion {
    pub fn new(start_address: u64, end_address: u64) -> Self {
        Self {
            start_address,
            end_address,
            state: VolosState::Virgin,
            cells: HashMap::new(),
        }
    }

    /// Append a record to every byte in `[addr, addr + size)`.
    pub fn add_record(&mut self, record: Volos) {
        for byte in 0..record.size {
            let cell_addr = record.addr.wrapping_add(byte);
            let entry = self.cells.entry(cell_addr).or_default();
            entry.accesses.push(record.clone());
            entry.state = VolosState::classify(&entry.accesses);
            if entry.state as u8 > self.state as u8 {
                self.state = entry.state;
            }
        }
    }

    /// Race-check pass: for every cell with two or more accesses, find
    /// pairs from different threads where at least one is a write and the
    /// accesses are
    ///   1. **concurrent** in the happens-before sense (their vector
    ///      clocks are not strictly ordered), and
    ///   2. not protected by a common lock.
    ///
    /// Pairs that are causally ordered (e.g. the second access happens on
    /// a child thread *after* the parent forked it, or after a future
    /// `ThreadJoin`/channel-receive event ticks the receiver's clock) are
    /// silently skipped, matching the FastTrack-style semantics. Returns a
    /// list of `(addr, v1, v2, reason)` tuples that the plugin lifts to
    /// findings.
    pub fn race_pairs(&self) -> Vec<(u64, Volos, Volos, RaceReason)> {
        use std::cmp::Ordering;
        let mut out = Vec::new();
        for (addr, entry) in self.cells.iter() {
            if entry.accesses.len() < 2 {
                continue;
            }
            for i in 0..entry.accesses.len() {
                for j in (i + 1)..entry.accesses.len() {
                    let v1 = &entry.accesses[i];
                    let v2 = &entry.accesses[j];
                    if v1.thread_id == v2.thread_id {
                        continue;
                    }
                    let either_write = v1.access_type == AccessType::Write
                        || v2.access_type == AccessType::Write;
                    if !either_write {
                        continue;
                    }
                    // Happens-before filter. Only `None` (truly concurrent)
                    // and `Some(Equal)` (clocks coincide — possible on the
                    // very first event of two unrelated threads) survive.
                    // Any strict ordering proves the accesses are
                    // synchronised by some prior event (fork, future join,
                    // channel send/recv...) and therefore cannot race.
                    match v1.vector_clock.partial_cmp(&v2.vector_clock) {
                        Some(Ordering::Less) | Some(Ordering::Greater) => {
                            continue;
                        }
                        _ => {}
                    }
                    let l1_empty = v1.locks_held.is_empty();
                    let l2_empty = v2.locks_held.is_empty();
                    let shared = v1.shares_lock(v2);
                    let reason = match (l1_empty || l2_empty, shared) {
                        (true, _) => RaceReason::Unprotected,
                        (false, false) => RaceReason::InconsistentLocking,
                        (false, true) => continue, // protected by shared lock
                    };
                    out.push((*addr, v1.clone(), v2.clone(), reason));
                }
            }
        }
        out
    }
}

/// Why a pair of accesses was flagged as a race.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RaceReason {
    /// At least one access held no lock.
    Unprotected,
    /// Both accesses held locks but the locksets did not intersect.
    InconsistentLocking,
}

impl fmt::Display for RaceReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RaceReason::Unprotected => f.write_str("Unprotected access"),
            RaceReason::InconsistentLocking => f.write_str("Inconsistent locking"),
        }
    }
}
