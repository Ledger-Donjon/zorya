// SPDX-FileCopyrightText: 2026 KMSEC (PTY) LTD - https://kmsecurity.co.za
// SPDX-FileCopyrightText: 2026 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0
//
// Ported from `src/state/memory_x86_64.rs` of the upstream `zorya-volos`
// fork (https://github.com/kmsec137/zorya-volos), Apache-2.0 licensed.
// Original author: Keith Makan (KMSEC). Adapted into the Zorya plugin
// layer.

//! Per-access record. One `Volos` is appended to the `VolosRegion` for
//! every binary-originated read or write the executor dispatches.

use std::fmt;

use super::vector_clock::VolosVC;

/// Operation type captured by a `Volos` record.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AccessType {
    Read,
    Write,
    /// Only used for the initial sentinel record placed when a region is
    /// first created. Never produced by the executor.
    #[default]
    New,
}

impl fmt::Display for AccessType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AccessType::Read => f.write_str("Read"),
            AccessType::Write => f.write_str("Write"),
            AccessType::New => f.write_str("New"),
        }
    }
}

/// A single, critical record of a memory access in a concurrent system.
///
/// The original volos fork plumbed a `Volos` parameter through every
/// memory API. Under the plugin layer the executor instead dispatches a
/// `MemRead` / `MemWrite` event and the volos plugin builds the record
/// internally, so this struct never crosses the plugin boundary.
#[derive(Debug, Clone)]
pub struct Volos {
    pub thread_id: u64,
    pub access_type: AccessType,
    /// Lockset held at the moment of the access. Each entry is the
    /// concrete address of a lock object (mutex, rwmutex, etc.).
    pub locks_held: Vec<u64>,
    /// Address that this record corresponds to.
    pub addr: u64,
    /// Size in bytes.
    pub size: u64,
    /// Synthetic goroutine identifier. The volos plugin assigns a
    /// monotonically increasing id to each tid on first sight (main
    /// thread → 0, first `ThreadSpawn` → 1, …). It is *not* the real Go
    /// `g.goid` value — extracting that requires reading the runtime
    /// `g` struct from engine memory, which needs `EventCtx::state` to
    /// land first. Until then this is purely a stable, readable label
    /// for findings.
    pub go_id: Option<u64>,
    /// PC at which the access was issued (set from `EventCtx::current_pc`
    /// at dispatch time).
    pub pc: u64,
    /// Wall-clock instant when the record was created. Used for
    /// stable ordering when two accesses share the same vector clock.
    pub timestamp_ns: u128,
    /// Vector clock at the time of the access.
    pub vector_clock: VolosVC,
}

impl Volos {
    pub fn new(
        thread_id: u64,
        access_type: AccessType,
        locks_held: Vec<u64>,
        vector_clock: VolosVC,
    ) -> Self {
        let timestamp_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        Self {
            thread_id,
            access_type,
            locks_held,
            addr: 0,
            size: 0,
            go_id: None,
            pc: 0,
            timestamp_ns,
            vector_clock,
        }
    }

    pub fn with_addr_size(mut self, addr: u64, size: u64) -> Self {
        self.addr = addr;
        self.size = size;
        self
    }

    pub fn with_pc(mut self, pc: u64) -> Self {
        self.pc = pc;
        self
    }

    pub fn with_go_id(mut self, go_id: Option<u64>) -> Self {
        self.go_id = go_id;
        self
    }

    /// True iff `self` and `other` have a *non-empty* lockset
    /// intersection. Used by the race detector to decide whether two
    /// accesses are protected by a common mutex.
    pub fn shares_lock(&self, other: &Volos) -> bool {
        self.locks_held.iter().any(|l| other.locks_held.contains(l))
    }
}

impl fmt::Display for Volos {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Volos {{ tid: {}, op: {}, locks: {:?}, addr: 0x{:x}, size: {}, go_id: {:?}, pc: 0x{:x} }}",
            self.thread_id,
            self.access_type,
            self.locks_held,
            self.addr,
            self.size,
            self.go_id,
            self.pc,
        )
    }
}
