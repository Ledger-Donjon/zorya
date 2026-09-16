// SPDX-FileCopyrightText: 2026 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

//! Event vocabulary fired by the concolic executor.
//!
//! Events are dispatched **only from binary-originated execution sites** in
//! the executor handlers (`handle_load`, `handle_store`, `handle_cbranch`,
//! `handle_call`, `handle_return`, `handle_syscall`, the thread manager).
//! Engine-internal memory accesses performed by Zorya itself for bookkeeping
//! (sigaction reads, runtime_g extraction, jump-table lookups, dump loading,
//! etc.) intentionally bypass the bus by going directly through
//! `state.memory.read_*` / `write_*`. This is enforced **by construction**:
//! the memory layer never fires events.
//!
//! For memory accesses specifically, the binary-vs-engine split is made
//! **explicit** by [`AccessOrigin`]: every access that could reach a plugin
//! is routed through the executor's single `emit_mem_access` choke-point,
//! which gates on `AccessOrigin::Binary`. The boundary is observable at
//! end-of-run via the surfaced/suppressed audit counters.
//!
//! Adding a new event variant is a deliberate API change — bump
//! `EVENT_API_VERSION` and update `doc/Plugins.md`.

use std::rc::Rc;

use parser::parser::Opcode;
use z3::ast::{Bool, BV};

use crate::state::state_manager::FunctionFrame;

/// Plugin API version. Plugins compiled against an older version of this
/// trait will fail to link; bump on every breaking change to `Event` or
/// `Plugin`.
///
/// v3: added `Event::SyncRelease` / `Event::SyncAcquire` (object-keyed
/// release/acquire happens-before edges for Go sync primitives).
pub const EVENT_API_VERSION: u32 = 3;

/// A single event observed by the executor.
///
/// Lifetimes:
/// - `'ctx` is the Z3 context lifetime owned by the executor.
/// - `'e`   is the (shorter) lifetime of the borrowed payload (byte slices,
///   solver expressions). Plugins must not stash `'e` references; copy what
///   they need into their own state.
#[derive(Debug)]
pub enum Event<'ctx, 'e> {
    /// A binary-originated memory read (fired by `handle_load`).
    MemRead {
        addr: u64,
        size: u32,
        concrete: &'e [u8],
        symbolic: &'e [Option<Rc<BV<'ctx>>>],
        pc: u64,
        tid: u64,
    },

    /// A binary-originated memory write (fired by `handle_store`).
    MemWrite {
        addr: u64,
        size: u32,
        concrete: &'e [u8],
        symbolic: &'e [Option<Rc<BV<'ctx>>>],
        pc: u64,
        tid: u64,
    },

    /// A conditional branch was taken or not taken.
    Branch {
        pc: u64,
        taken: bool,
        cond: &'e Bool<'ctx>,
        tid: u64,
    },

    /// A direct or indirect call. `symbol` is set when the target resolves
    /// to a known name in the binary's symbol table.
    Call {
        pc: u64,
        target: u64,
        symbol: Option<&'e str>,
        tid: u64,
        /// First machine-word argument, read from the callee's recovered
        /// signature. For lock primitives such as
        /// `pthread_mutex_lock(pthread_mutex_t *m)`, this is the mutex
        /// pointer used as the lock identity. Plugins only read it when
        /// `symbol` matches a primitive they track.
        arg0: u64,
    },

    /// Function return.
    Return {
        pc: u64,
        frame: &'e FunctionFrame,
        tid: u64,
    },

    /// Syscall entry; arguments are the raw register values per x86-64 ABI.
    Syscall {
        nr: u64,
        args: [u64; 6],
        pc: u64,
        tid: u64,
    },

    /// Syscall return; `ret` is the value placed in RAX.
    SyscallRet {
        nr: u64,
        ret: u64,
        pc: u64,
        tid: u64,
    },

    /// A new OS thread / Go `m` was spawned via `clone`.
    ThreadSpawn {
        parent_tid: u64,
        child_tid: u64,
        entry: u64,
        flags: u64,
    },

    /// The scheduler switched the current thread.
    ThreadSwitch { from: u64, to: u64 },

    /// A thread exited.
    ThreadExit { tid: u64, code: i32 },

    /// A synchronization happens-before edge: every event on `from`
    /// happens-before subsequent events on `to`.
    ///
    /// Fired by the executor when it models a join / handoff primitive.
    /// Currently emitted by the `sync.(*WaitGroup).Wait` hook, which
    /// establishes that each worker goroutine's `Done` happens-before the
    /// waiter resumes (Go memory-model rule for `WaitGroup`). Concurrency
    /// detectors merge `from`'s vector clock into `to`'s, so accesses ordered
    /// by the primitive are no longer reported as data races.
    HappensBefore { from: u64, to: u64 },

    /// A *release* on a synchronization object `obj` performed by thread
    /// `tid`. Models the "release" half of the release/acquire memory model:
    /// a channel send / close, `sync.(*WaitGroup).Done`, or a mutex unlock.
    /// Concurrency detectors snapshot `tid`'s current vector clock into a
    /// per-object clock so a later [`Event::SyncAcquire`] on the same `obj`
    /// establishes happens-before. `obj` is the object pointer read from the
    /// Go register ABI at the call site; `kind` says which primitive class it
    /// is (so a mutex also updates the holder's lockset).
    SyncRelease {
        obj: u64,
        tid: u64,
        pc: u64,
        kind: SyncKind,
    },

    /// An *acquire* on a synchronization object `obj` performed by thread
    /// `tid`. Models the "acquire" half: a channel receive,
    /// `sync.(*WaitGroup).Wait`, or a mutex lock. Detectors merge the object's
    /// stored release clock into `tid`'s clock, so accesses ordered by the
    /// primitive are no longer flagged as data races.
    SyncAcquire {
        obj: u64,
        tid: u64,
        pc: u64,
        kind: SyncKind,
    },

    /// A panic / fatal call site was reached. `kind` is a stable string id
    /// such as `"runtime.nilPanic"`, `"runtime.slicePanic"`, etc.
    Panic { pc: u64, kind: &'static str },

    /// Per-pcode pre-execute notification. Disabled by default; enabled only
    /// when at least one plugin subscribes via `wants(EventKind::InstrPre)`.
    /// Use sparingly — this is the hot path.
    InstrPre { pc: u64, op: Opcode, tid: u64 },

    /// Per-pcode post-execute notification. Same gating as `InstrPre`.
    InstrPost { pc: u64, op: Opcode, tid: u64 },
}

/// Discriminant-only event kind, used by plugins to declare subscriptions
/// without taking on the lifetime cost of the full `Event` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventKind {
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
    HappensBefore,
    SyncRelease,
    SyncAcquire,
    Panic,
    InstrPre,
    InstrPost,
}

/// The class of synchronization object a [`Event::SyncRelease`] /
/// [`Event::SyncAcquire`] edge refers to. Detectors use it to decide whether
/// the object also participates in mutual-exclusion reasoning (mutexes) or
/// only in ordering (channels, wait groups).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncKind {
    /// A Go channel (`*hchan`): send / close releases, receive acquires.
    Channel,
    /// A `sync.WaitGroup`: `Done` releases, `Wait` acquires.
    WaitGroup,
    /// A `sync.Mutex` / `sync.RWMutex`: unlock releases and drops the lock
    /// from the holder's lockset; lock acquires and adds it.
    Mutex,
}

/// Origin of a memory access, used to gate plugin `MemRead` / `MemWrite`
/// dispatch.
///
/// This is the **explicit form** of the binary-vs-engine boundary that was
/// previously only implicit in *which code path* performed the access.
/// Every memory access that could conceivably reach a plugin is tagged with
/// an `AccessOrigin`; only [`AccessOrigin::Binary`] accesses are surfaced.
///
/// - [`AccessOrigin::Binary`] — the access is driven by a `LOAD` / `STORE`
///   pcode op lifted from the analyzed program. These are the only accesses
///   plugins (e.g. the volos race detector) should observe.
/// - [`AccessOrigin::Engine`] — the access is Zorya's own bookkeeping: GDB
///   dump restoration, syscall emulation, `runtime.g` / TLS extraction,
///   jump-table table walks, sigaction lookups, etc. These must never reach
///   plugins, otherwise detectors see phantom accesses the program never
///   actually made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessOrigin {
    /// Driven by a binary `LOAD` / `STORE` pcode op.
    Binary,
    /// Internal engine bookkeeping; never surfaced to plugins.
    Engine,
}

/// Direction of a memory access routed through the executor's memory-event
/// choke-point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemAccessKind {
    Read,
    Write,
}

impl MemAccessKind {
    /// The `EventKind` a binary-originated access of this direction maps to.
    pub fn event_kind(self) -> EventKind {
        match self {
            MemAccessKind::Read => EventKind::MemRead,
            MemAccessKind::Write => EventKind::MemWrite,
        }
    }
}

impl<'ctx, 'e> Event<'ctx, 'e> {
    /// Discriminant view of this event.
    pub fn kind(&self) -> EventKind {
        match self {
            Event::MemRead { .. } => EventKind::MemRead,
            Event::MemWrite { .. } => EventKind::MemWrite,
            Event::Branch { .. } => EventKind::Branch,
            Event::Call { .. } => EventKind::Call,
            Event::Return { .. } => EventKind::Return,
            Event::Syscall { .. } => EventKind::Syscall,
            Event::SyscallRet { .. } => EventKind::SyscallRet,
            Event::ThreadSpawn { .. } => EventKind::ThreadSpawn,
            Event::ThreadSwitch { .. } => EventKind::ThreadSwitch,
            Event::ThreadExit { .. } => EventKind::ThreadExit,
            Event::HappensBefore { .. } => EventKind::HappensBefore,
            Event::SyncRelease { .. } => EventKind::SyncRelease,
            Event::SyncAcquire { .. } => EventKind::SyncAcquire,
            Event::Panic { .. } => EventKind::Panic,
            Event::InstrPre { .. } => EventKind::InstrPre,
            Event::InstrPost { .. } => EventKind::InstrPost,
        }
    }
}
