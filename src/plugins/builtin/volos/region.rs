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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum VolosState {
    #[default]
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
                    let one_is_write =
                        v1.access_type == AccessType::Write || v2.access_type == AccessType::Write;
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

/// Accesses kept per cell; further distinct accesses are counted, not kept.
pub const MAX_CELL_HISTORY: usize = 256;

/// Per-cell entry: the FSA state, plus the access history that lead to that
/// state. Keeping the history is what lets the race-check pass produce
/// concrete witness pairs in findings.
///
/// Repeated accesses from one site are folded: for each (thread, type, PC,
/// lockset) only the first and the latest access are kept, so a loop that
/// touches a cell a million times costs two entries.
#[derive(Debug, Clone, Default)]
pub struct CellHistory {
    pub state: VolosState,
    pub accesses: Vec<Volos>,
    /// Distinct accesses not kept because the history was full.
    pub dropped: u64,
}

impl CellHistory {
    fn push(&mut self, record: Volos) {
        let same_site = |v: &Volos| {
            v.thread_id == record.thread_id
                && v.access_type == record.access_type
                && v.pc == record.pc
                && v.locks_held == record.locks_held
        };
        let mut sites = self
            .accesses
            .iter()
            .enumerate()
            .filter(|(_, v)| same_site(v))
            .map(|(i, _)| i);
        let first = sites.next();
        let latest = sites.next_back();
        let idx = match (first, latest) {
            (Some(_), Some(latest)) => {
                self.accesses[latest] = record;
                latest
            }
            _ if self.accesses.len() >= MAX_CELL_HISTORY => {
                self.dropped += 1;
                return;
            }
            _ => {
                self.accesses.push(record);
                self.accesses.len() - 1
            }
        };
        self.reclassify_with(idx);
    }

    /// Update the state after the access at `idx` was added. Pairs not
    /// involving it were checked when their later access was added, and
    /// `Raceable` is sticky, so only pairs with `idx` need checking.
    fn reclassify_with(&mut self, idx: usize) {
        if matches!(self.state, VolosState::Raceable | VolosState::Reported) {
            return;
        }
        let new = &self.accesses[idx];
        let mut other_thread = false;
        let mut any_write = new.access_type == AccessType::Write;
        for (i, v) in self.accesses.iter().enumerate() {
            if i == idx {
                continue;
            }
            any_write |= v.access_type == AccessType::Write;
            if v.thread_id != new.thread_id {
                other_thread = true;
                let one_is_write =
                    v.access_type == AccessType::Write || new.access_type == AccessType::Write;
                if one_is_write && !v.shares_lock(new) {
                    self.state = VolosState::Raceable;
                    return;
                }
            }
        }
        let multi =
            other_thread || matches!(self.state, VolosState::Shared | VolosState::SharedModified);
        self.state = match (multi, any_write) {
            (false, _) => VolosState::Exclusive,
            (true, true) => VolosState::SharedModified,
            (true, false) => VolosState::Shared,
        };
    }
}

/// Counts of cross-thread conflicting access pairs seen by the race pass,
/// and why the non-reported ones were dismissed. Pairs of records are
/// counted once, however many bytes they share.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PairStats {
    /// Different threads, same cell, at least one write.
    pub conflicting: u64,
    pub hb_ordered: u64,
    pub lock_protected: u64,
    /// The same counts restricted to pairs whose both sides satisfy the
    /// caller's `is_app` predicate.
    pub app_conflicting: u64,
    pub app_hb_ordered: u64,
    pub app_lock_protected: u64,
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
            entry.push(record.clone());
            if entry.state as u8 > self.state as u8 {
                self.state = entry.state;
            }
        }
    }

    /// Distinct accesses dropped because a cell history was full.
    pub fn dropped_accesses(&self) -> u64 {
        self.cells.values().map(|c| c.dropped).sum()
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
        self.race_pairs_with(&|_| false).0
    }

    /// [`Self::race_pairs`] plus the counts of dismissed pairs. A pair of
    /// records with ids is reported once, at its lowest shared address.
    pub fn race_pairs_with(
        &self,
        is_app: &dyn Fn(&Volos) -> bool,
    ) -> (Vec<(u64, Volos, Volos, RaceReason)>, PairStats) {
        use std::cmp::Ordering;
        use std::collections::HashSet;
        let mut out = Vec::new();
        let mut stats = PairStats::default();
        let mut seen: HashSet<(u64, u64)> = HashSet::new();
        let mut addrs: Vec<&u64> = self.cells.keys().collect();
        addrs.sort_unstable();
        for addr in addrs {
            let entry = &self.cells[addr];
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
                    let either_write =
                        v1.access_type == AccessType::Write || v2.access_type == AccessType::Write;
                    if !either_write {
                        continue;
                    }
                    if v1.record_id != 0 && v2.record_id != 0 {
                        let key = (
                            v1.record_id.min(v2.record_id),
                            v1.record_id.max(v2.record_id),
                        );
                        if !seen.insert(key) {
                            continue;
                        }
                    }
                    let app = is_app(v1) && is_app(v2);
                    stats.conflicting += 1;
                    stats.app_conflicting += app as u64;
                    // Happens-before filter. Only `None` (truly concurrent)
                    // and `Some(Equal)` (clocks coincide — possible on the
                    // very first event of two unrelated threads) survive.
                    // Any strict ordering proves the accesses are
                    // synchronised by some prior event (fork, future join,
                    // channel send/recv...) and therefore cannot race.
                    match v1.vector_clock.partial_cmp(&v2.vector_clock) {
                        Some(Ordering::Less) | Some(Ordering::Greater) => {
                            stats.hb_ordered += 1;
                            stats.app_hb_ordered += app as u64;
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
                        (false, true) => {
                            stats.lock_protected += 1;
                            stats.app_lock_protected += app as u64;
                            continue;
                        }
                    };
                    out.push((*addr, v1.clone(), v2.clone(), reason));
                }
            }
        }
        (out, stats)
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
