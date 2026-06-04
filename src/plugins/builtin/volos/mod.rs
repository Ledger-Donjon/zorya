// SPDX-FileCopyrightText: 2026 KMSEC (PTY) LTD - https://kmsecurity.co.za
// SPDX-FileCopyrightText: 2026 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0
//
// Plugin port of the volos memory-interaction tracking system from the
// upstream `zorya-volos` fork (https://github.com/kmsec137/zorya-volos),
// originally authored by Keith Makan (KMSEC). All semantics — the FSA
// state machine, the unprotected/inconsistent-locking race rules, the
// per-cell access history — are preserved. The mechanical changes are:
//
//   * Volos data structures move out of `MemoryRegion` into the plugin's
//     own private state.
//   * `volos: Volos` and `internal: bool` parameters threaded through
//     every memory API are dropped: the plugin observes events instead.
//   * `[VOLOS]` `println!` lines route through the plugin's own logger
//     gated on the `VOLOS_VERBOSE` environment variable.

//! Volos race detector — a plugin port of the KMSEC zorya-volos fork.
//!
//! Subscribes to:
//!   * `MemRead`     — appends a `Read` record for the address range.
//!   * `MemWrite`    — appends a `Write` record for the address range.
//!   * `Call`        — when the target symbol is a known lock primitive,
//!                     updates the per-thread lockset.
//!   * `ThreadSpawn` — initialises a vector clock for the new thread.
//!   * `ThreadExit`  — flushes any thread-local bookkeeping.
//!
//! At `on_finish` the plugin runs the race-check pass over its accumulated
//! `VolosRegion` map and emits one finding per witness pair.

use std::collections::HashMap;
use std::collections::HashSet;

use crate::plugins::context::EventCtx;
use crate::plugins::event::{Event, EventKind};
use crate::plugins::finding::{Finding, Severity};
use crate::plugins::plugin::Plugin;
use crate::plugins::verdict::Verdict;
use crate::plugins::EventBus;

pub mod record;
pub mod region;
pub mod vector_clock;

use record::{AccessType, Volos};
use region::{RaceReason, VolosRegion};
use vector_clock::VolosVC;

/// Symbols we hook to maintain a per-thread lockset. The list mirrors the
/// `runtime.lock` family observed in the upstream volos fork plus the
/// C/pthread mutex family; extending it is just a matter of appending
/// names — no plugin code changes required.
///
/// Note on the C entries: a C call to `pthread_mutex_lock` is dispatched as
/// an `Event::Call` whose target is the PLT stub, so its resolved symbol is
/// the `plt_`-prefixed form. [`strip_plt`] normalises that before matching,
/// so we list the bare names here.
const LOCK_ACQUIRE_SYMBOLS: &[&str] = &[
    "runtime.lock",
    "runtime.lock2",
    "sync.(*Mutex).Lock",
    "sync.(*RWMutex).Lock",
    "sync.(*RWMutex).RLock",
    "pthread_mutex_lock",
    "pthread_mutex_trylock",
    "pthread_rwlock_wrlock",
    "pthread_rwlock_rdlock",
    "pthread_spin_lock",
];

const LOCK_RELEASE_SYMBOLS: &[&str] = &[
    "runtime.unlock",
    "runtime.unlock2",
    "sync.(*Mutex).Unlock",
    "sync.(*RWMutex).Unlock",
    "sync.(*RWMutex).RUnlock",
    "pthread_mutex_unlock",
    "pthread_rwlock_unlock",
    "pthread_spin_unlock",
];

/// Strip a leading `plt_` so a PLT-resolved symbol (`plt_pthread_mutex_lock`)
/// matches the bare primitive name. Go symbols are unaffected.
fn strip_plt(sym: &str) -> &str {
    sym.strip_prefix("plt_").unwrap_or(sym)
}

/// Granularity of the per-region map. Volos in the upstream fork tracks
/// at byte granularity per memory region; for the first plugin port we
/// keep a single global region keyed by absolute address. When
/// `EventCtx` exposes engine-state accessors we'll shard by the actual
/// memory regions reported by `MemoryX86_64`.
#[derive(Debug)]
pub struct VolosPlugin {
    /// Per-thread lockset, keyed by tid (will swap to goroutine id when
    /// engine state is exposed via `EventCtx`).
    locksets: HashMap<u64, Vec<u64>>,

    /// Per-thread vector clock.
    clocks: HashMap<u64, VolosVC>,

    /// Synthetic goroutine ids, assigned monotonically in the order each
    /// tid is first observed. Not the real Go `g.goid`; see the comment
    /// on [`Volos::go_id`].
    go_ids: HashMap<u64, u64>,

    /// Counter for the next synthetic go_id to hand out. Starts at 0 so
    /// the first thread we see (typically the main thread, which has no
    /// `ThreadSpawn` event) is `goroutine 0`.
    next_go_id: u64,

    /// Single global region holding all observed accesses. Sufficient
    /// for the race detector since the FSA classifies per-cell.
    region: VolosRegion,

    /// Verbose logging gated on `VOLOS_VERBOSE=1`, matching the upstream
    /// fork's behaviour.
    verbose: bool,

    /// Counters for diagnostics / smoke tests.
    reads: u64,
    writes: u64,
    lock_acquires: u64,
    lock_releases: u64,
    threads_spawned: u64,
}

impl VolosPlugin {
    pub fn new() -> Self {
        Self {
            locksets: HashMap::new(),
            clocks: HashMap::new(),
            go_ids: HashMap::new(),
            next_go_id: 0,
            region: VolosRegion::new(0, u64::MAX),
            verbose: std::env::var("VOLOS_VERBOSE").map_or(false, |v| v == "1"),
            reads: 0,
            writes: 0,
            lock_acquires: 0,
            lock_releases: 0,
            threads_spawned: 0,
        }
    }

    /// Look up (or assign) the synthetic goroutine id for `tid`. Stable
    /// for the lifetime of the plugin instance.
    fn go_id_for(&mut self, tid: u64) -> u64 {
        if let Some(&id) = self.go_ids.get(&tid) {
            return id;
        }
        let id = self.next_go_id;
        self.next_go_id += 1;
        self.go_ids.insert(tid, id);
        id
    }

    /// Test/diagnostic accessor: synthetic goroutine id mapped to a tid.
    pub fn go_id_of(&self, tid: u64) -> Option<u64> {
        self.go_ids.get(&tid).copied()
    }

    /// Diagnostic snapshot used by tests.
    pub fn counters(&self) -> VolosCounters {
        VolosCounters {
            reads: self.reads,
            writes: self.writes,
            lock_acquires: self.lock_acquires,
            lock_releases: self.lock_releases,
            threads_spawned: self.threads_spawned,
            tracked_cells: self.region.cells.len(),
        }
    }

    /// Build a `Volos` record for an event, snapshotting the current
    /// thread's lockset, clock, and goroutine id.
    ///
    /// The clock is *ticked-then-snapshotted*. Without the pre-tick the
    /// very first event from a thread would carry `{tid:0}`, which makes
    /// the partial-order compare against another thread's `{other:1}`
    /// look like `Some(Less)` (because missing components default to 0)
    /// even though the threads are concurrent. Pre-ticking guarantees the
    /// record's own local component is at least 1, so two unrelated
    /// threads' first events compare to `None` (concurrent) as expected.
    ///
    /// Goroutine id resolution prefers `EventCtx::current_goid` (the real
    /// `g.goid` value the executor extracted from the runtime `g` struct
    /// via TLS) and falls back to a synthetic, monotonically-assigned id
    /// when the engine couldn't resolve one (non-Go binaries, or before
    /// runtime init).
    fn build_record(
        &mut self,
        tid: u64,
        access: AccessType,
        addr: u64,
        size: u64,
        pc: u64,
        real_goid: Option<u64>,
    ) -> Volos {
        let synthetic = self.go_id_for(tid);
        let goid = real_goid.unwrap_or(synthetic);
        let entry = self
            .clocks
            .entry(tid)
            .or_insert_with(|| VolosVC::new(&tid.to_string()));
        entry.tick();
        let clock = entry.clone();
        let locks = self.locksets.get(&tid).cloned().unwrap_or_default();
        Volos::new(tid, access, locks, clock)
            .with_addr_size(addr, size)
            .with_pc(pc)
            .with_go_id(Some(goid))
    }

    fn vlog(&self, msg: impl AsRef<str>) {
        if self.verbose {
            // Plugin-private channel. When the per-plugin Logger lands in
            // EventCtx this becomes ctx.sub_logger("volos").
            eprintln!("[VOLOS] {}", msg.as_ref());
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct VolosCounters {
    pub reads: u64,
    pub writes: u64,
    pub lock_acquires: u64,
    pub lock_releases: u64,
    pub threads_spawned: u64,
    pub tracked_cells: usize,
}

impl Default for VolosPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl<'ctx> Plugin<'ctx> for VolosPlugin {
    fn name(&self) -> &'static str {
        "volos"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn wants(&self) -> HashSet<EventKind> {
        [
            EventKind::MemRead,
            EventKind::MemWrite,
            EventKind::Call,
            EventKind::ThreadSpawn,
            EventKind::ThreadExit,
        ]
        .into_iter()
        .collect()
    }

    fn symbol_hooks(&self) -> &'static [&'static str] {
        // Concatenated at compile time would be cleaner; for clarity keep
        // it as a single static block. The registry warns at load time
        // about unresolved symbols (lazy / stripped) and binds them
        // retroactively on each Call.
        &[
            "runtime.lock",
            "runtime.lock2",
            "runtime.unlock",
            "runtime.unlock2",
            "sync.(*Mutex).Lock",
            "sync.(*Mutex).Unlock",
            "sync.(*RWMutex).Lock",
            "sync.(*RWMutex).Unlock",
            "sync.(*RWMutex).RLock",
            "sync.(*RWMutex).RUnlock",
            // C / pthread family. These resolve to PLT stubs (`plt_*`) in a
            // -no-pie C binary; the registry binds the stub address and the
            // Call handler normalises the `plt_` prefix before matching.
            "pthread_mutex_lock",
            "pthread_mutex_trylock",
            "pthread_mutex_unlock",
            "pthread_rwlock_wrlock",
            "pthread_rwlock_rdlock",
            "pthread_rwlock_unlock",
            "pthread_spin_lock",
            "pthread_spin_unlock",
        ]
    }

    fn on_event(
        &mut self,
        ev: &Event<'ctx, '_>,
        ctx: &EventCtx<'ctx, '_>,
    ) -> Verdict {
        let real_goid = ctx.current_goid;
        match ev {
            Event::MemRead { addr, size, pc, tid, .. } => {
                self.reads += 1;
                let bytes = (*size as u64).div_ceil(8);
                let rec = self.build_record(*tid, AccessType::Read, *addr, bytes, *pc, real_goid);
                self.vlog(format!(
                    "READ  @0x{:x} size={} tid={} go={:?} locks_held={:?}",
                    rec.addr, rec.size, rec.thread_id, rec.go_id, rec.locks_held
                ));
                self.region.add_record(rec);
            }
            Event::MemWrite { addr, size, pc, tid, .. } => {
                self.writes += 1;
                let bytes = (*size as u64).div_ceil(8);
                let rec = self.build_record(*tid, AccessType::Write, *addr, bytes, *pc, real_goid);
                self.vlog(format!(
                    "WRITE @0x{:x} size={} tid={} go={:?} locks_held={:?}",
                    rec.addr, rec.size, rec.thread_id, rec.go_id, rec.locks_held
                ));
                self.region.add_record(rec);
            }
            Event::Call { target, symbol, tid, arg0, .. } => {
                if let Some(sym) = symbol {
                    // Normalise PLT-resolved C symbols (`plt_pthread_mutex_lock`)
                    // to their bare primitive name before matching.
                    let name = strip_plt(sym);
                    // Lock identity: for pthread primitives the mutex object is
                    // the first argument (RDI), so different mutexes are
                    // distinguishable. The PLT stub `target` is identical for
                    // every pthread call and would collapse them into one lock,
                    // so prefer `arg0` when it is a usable pointer; otherwise
                    // fall back to the call target (Go runtime.lock family).
                    let lock_addr = if name.starts_with("pthread_") && *arg0 != 0 {
                        *arg0
                    } else {
                        *target
                    };
                    if LOCK_ACQUIRE_SYMBOLS.contains(&name) {
                        self.lock_acquires += 1;
                        self.locksets.entry(*tid).or_default().push(lock_addr);
                        self.vlog(format!(
                            "ACQUIRE 0x{:x} tid={} (sym={})",
                            lock_addr, tid, name
                        ));
                    } else if LOCK_RELEASE_SYMBOLS.contains(&name) {
                        self.lock_releases += 1;
                        if let Some(locks) = self.locksets.get_mut(tid) {
                            if let Some(pos) = locks.iter().rposition(|&l| l == lock_addr) {
                                locks.remove(pos);
                            }
                        }
                        self.vlog(format!(
                            "RELEASE 0x{:x} tid={} (sym={})",
                            lock_addr, tid, name
                        ));
                    }
                }
            }
            Event::ThreadSpawn { child_tid, parent_tid, .. } => {
                self.threads_spawned += 1;

                // Make sure the parent already has a go_id assigned
                // (typically yes if it issued any prior memory event,
                // but a spawn-as-first-event is legal).
                let _parent_go = self.go_id_for(*parent_tid);
                // Hand the child a fresh synthetic go_id.
                let child_go = self.go_id_for(*child_tid);

                // Fork the parent's clock as the child's starting point —
                // standard happens-before "fork" rule:
                //   * child receives a snapshot of parent_clock,
                //   * child ticks its own component, so its first event
                //     strictly happens after the spawn,
                //   * parent ticks too, so its post-spawn events are
                //     concurrent with the child's instead of being
                //     spuriously ordered before them.
                let mut child_clock = self
                    .clocks
                    .entry(*parent_tid)
                    .or_insert_with(|| VolosVC::new(&parent_tid.to_string()))
                    .clone();
                child_clock.node_id = child_tid.to_string();
                child_clock.tick_at(&child_tid.to_string());
                self.clocks.insert(*child_tid, child_clock);
                if let Some(parent_clock) = self.clocks.get_mut(parent_tid) {
                    parent_clock.tick();
                }
                self.vlog(format!(
                    "SPAWN tid={} (go={}) from tid={}",
                    child_tid, child_go, parent_tid
                ));
            }
            Event::ThreadExit { tid, .. } => {
                self.locksets.remove(tid);
                self.vlog(format!("EXIT tid={}", tid));
            }
            _ => {}
        }
        Verdict::Continue
    }

    fn on_finish(&mut self, ctx: &EventCtx<'ctx, '_>) {
        let pairs = self.region.race_pairs();
        if pairs.is_empty() {
            self.vlog("on_finish: no races detected");
            return;
        }
        self.vlog(format!("on_finish: {} race witness pairs", pairs.len()));
        for (addr, v1, v2, reason) in pairs {
            let title = format!(
                "Data race at 0x{:x}: {} ({} vs {})",
                addr, reason, v1.access_type, v2.access_type
            );
            let finding = Finding::new(
                "volos",
                match reason {
                    RaceReason::Unprotected => "data-race-unprotected",
                    RaceReason::InconsistentLocking => "data-race-inconsistent-locking",
                },
                Severity::High,
                ctx.current_pc,
                title,
            )
            .with_detail(format!(
                "Access 1 (tid={}, go={}): {} at 0x{:x}, locks_held={:?}, vc={}",
                v1.thread_id,
                v1.go_id.map(|g| g.to_string()).unwrap_or_else(|| "?".into()),
                v1.access_type,
                v1.pc,
                v1.locks_held,
                v1.vector_clock,
            ))
            .with_detail(format!(
                "Access 2 (tid={}, go={}): {} at 0x{:x}, locks_held={:?}, vc={}",
                v2.thread_id,
                v2.go_id.map(|g| g.to_string()).unwrap_or_else(|| "?".into()),
                v2.access_type,
                v2.pc,
                v2.locks_held,
                v2.vector_clock,
            ))
            .with_detail(format!("Reason: {}", reason));
            // We're outside a per-event dispatch here so we push directly
            // into the shared findings buffer.
            ctx.findings
                .borrow_mut()
                .push(finding);
        }
    }
}

/// Factory called from `crate::plugins::registry::register_default` when
/// the `plugin-volos` Cargo feature is enabled.
pub fn register<'ctx>(bus: &mut EventBus<'ctx>) {
    bus.add(Box::new(VolosPlugin::new()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::context::EventCtx;
    use crate::plugins::event::Event;
    use crate::plugins::finding::Finding;
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::time::Instant;
    use z3::ast::BV;
    use z3::{Config, Context};

    fn fresh_ctx() -> Context {
        Context::new(&Config::new())
    }

    fn mk_ctx<'ctx, 's>(
        ctx: &'ctx Context,
        findings: &'s RefCell<Vec<Finding>>,
    ) -> EventCtx<'ctx, 's> {
        EventCtx::new(ctx, 0x1000, 1, 0, Instant::now(), findings)
    }

    #[test]
    fn volos_subscriptions() {
        let p = VolosPlugin::new();
        let w = p.wants();
        assert!(w.contains(&EventKind::MemRead));
        assert!(w.contains(&EventKind::MemWrite));
        assert!(w.contains(&EventKind::Call));
        assert!(w.contains(&EventKind::ThreadSpawn));
        assert!(w.contains(&EventKind::ThreadExit));
        assert!(!w.contains(&EventKind::InstrPre));
    }

    #[test]
    fn volos_records_reads_and_writes_via_bus() {
        let ctx = fresh_ctx();
        let findings = RefCell::new(Vec::new());

        let mut bus: EventBus<'_> = EventBus::new();
        bus.add(Box::new(VolosPlugin::new()));

        let ectx = mk_ctx(&ctx, &findings);
        let bytes = vec![0u8; 8];
        let sym: Vec<Option<Rc<BV<'_>>>> = vec![None; 8];

        // Two reads and one write at the same address from two threads.
        bus.dispatch(
            &Event::MemRead {
                addr: 0x4000,
                size: 64,
                concrete: &bytes,
                symbolic: &sym,
                pc: 0x10,
                tid: 1,
            },
            &ectx,
        );
        bus.dispatch(
            &Event::MemWrite {
                addr: 0x4000,
                size: 64,
                concrete: &bytes,
                symbolic: &sym,
                pc: 0x14,
                tid: 2,
            },
            &ectx,
        );
        bus.dispatch(
            &Event::MemRead {
                addr: 0x4000,
                size: 64,
                concrete: &bytes,
                symbolic: &sym,
                pc: 0x18,
                tid: 1,
            },
            &ectx,
        );
        // No findings emitted yet — race check happens at on_finish.
        assert_eq!(findings.borrow().len(), 0);
    }

    #[test]
    fn volos_detects_unprotected_race_at_finish() {
        let ctx = fresh_ctx();
        let findings = RefCell::new(Vec::new());

        let mut bus: EventBus<'_> = EventBus::new();
        bus.add(Box::new(VolosPlugin::new()));

        let ectx = mk_ctx(&ctx, &findings);
        let bytes = vec![0u8; 8];
        let sym: Vec<Option<Rc<BV<'_>>>> = vec![None; 8];

        // tid=1 writes 0x5000. tid=2 writes 0x5000. No locks held by
        // either. Classic unprotected data race.
        bus.dispatch(
            &Event::MemWrite {
                addr: 0x5000,
                size: 64,
                concrete: &bytes,
                symbolic: &sym,
                pc: 0x100,
                tid: 1,
            },
            &ectx,
        );
        bus.dispatch(
            &Event::MemWrite {
                addr: 0x5000,
                size: 64,
                concrete: &bytes,
                symbolic: &sym,
                pc: 0x200,
                tid: 2,
            },
            &ectx,
        );

        bus.run_finish(&ectx);

        let f = findings.borrow();
        assert!(!f.is_empty(), "expected at least one race finding");
        assert!(f.iter().all(|x| x.plugin == "volos"));
        assert!(
            f.iter().any(|x| x.rule == "data-race-unprotected"),
            "expected unprotected-race rule"
        );
    }

    #[test]
    fn volos_no_race_when_protected_by_shared_lock() {
        let ctx = fresh_ctx();
        let findings = RefCell::new(Vec::new());

        let mut bus: EventBus<'_> = EventBus::new();
        bus.add(Box::new(VolosPlugin::new()));

        let ectx = mk_ctx(&ctx, &findings);
        let bytes = vec![0u8; 8];
        let sym: Vec<Option<Rc<BV<'_>>>> = vec![None; 8];

        // Both threads acquire the same lock at 0x9000 before writing.
        for tid in [1u64, 2u64] {
            bus.dispatch(
                &Event::Call {
                    pc: 0x80,
                    target: 0x9000,
                    symbol: Some("runtime.lock"),
                    tid,
                    arg0: 0,
                },
                &ectx,
            );
            bus.dispatch(
                &Event::MemWrite {
                    addr: 0x6000,
                    size: 64,
                    concrete: &bytes,
                    symbolic: &sym,
                    pc: 0x90,
                    tid,
                },
                &ectx,
            );
            bus.dispatch(
                &Event::Call {
                    pc: 0xa0,
                    target: 0x9000,
                    symbol: Some("runtime.unlock"),
                    tid,
                    arg0: 0,
                },
                &ectx,
            );
        }

        bus.run_finish(&ectx);
        assert_eq!(
            findings.borrow().len(),
            0,
            "shared lock should suppress race finding"
        );
    }

    /// C/pthread path: calls arrive as `plt_pthread_mutex_lock` with the
    /// mutex pointer in `arg0`. Both threads take the *same* mutex around
    /// the write, so the lockset must populate (via plt_ stripping + arg0
    /// keying) and suppress the race.
    #[test]
    fn volos_pthread_shared_mutex_suppresses_race() {
        let ctx = fresh_ctx();
        let findings = RefCell::new(Vec::new());

        let mut bus: EventBus<'_> = EventBus::new();
        bus.add(Box::new(VolosPlugin::new()));

        let ectx = mk_ctx(&ctx, &findings);
        let bytes = vec![0u8; 8];
        let sym: Vec<Option<Rc<BV<'_>>>> = vec![None; 8];

        // The same mutex object lives at 0x5000; both pthread calls go
        // through the PLT, so the resolved symbol is `plt_`-prefixed and the
        // mutex pointer is in arg0 (the PLT `target` would be identical for
        // every call and is intentionally ignored for pthread_*).
        const MUTEX: u64 = 0x5000;
        const PLT_STUB: u64 = 0x1040;
        for tid in [1u64, 2u64] {
            bus.dispatch(
                &Event::Call {
                    pc: 0x80,
                    target: PLT_STUB,
                    symbol: Some("plt_pthread_mutex_lock"),
                    tid,
                    arg0: MUTEX,
                },
                &ectx,
            );
            bus.dispatch(
                &Event::MemWrite {
                    addr: 0x6000,
                    size: 64,
                    concrete: &bytes,
                    symbolic: &sym,
                    pc: 0x90,
                    tid,
                },
                &ectx,
            );
            bus.dispatch(
                &Event::Call {
                    pc: 0xa0,
                    target: PLT_STUB,
                    symbol: Some("plt_pthread_mutex_unlock"),
                    tid,
                    arg0: MUTEX,
                },
                &ectx,
            );
        }

        bus.run_finish(&ectx);
        assert_eq!(
            findings.borrow().len(),
            0,
            "shared pthread mutex should suppress race finding"
        );
    }

    /// Parent writes a cell, *then* spawns a child that writes the same
    /// cell. The fork establishes a happens-before edge between parent's
    /// pre-spawn access and child's post-spawn access, so the HB filter
    /// must skip the pair even though no locks are held.
    #[test]
    fn volos_hb_filter_suppresses_fork_ordered_accesses() {
        let ctx = fresh_ctx();
        let findings = RefCell::new(Vec::new());

        let mut bus: EventBus<'_> = EventBus::new();
        bus.add(Box::new(VolosPlugin::new()));

        let ectx = mk_ctx(&ctx, &findings);
        let bytes = vec![0u8; 8];
        let sym: Vec<Option<Rc<BV<'_>>>> = vec![None; 8];

        // Parent (tid=1) writes 0x8000.
        bus.dispatch(
            &Event::MemWrite {
                addr: 0x8000,
                size: 64,
                concrete: &bytes,
                symbolic: &sym,
                pc: 0x100,
                tid: 1,
            },
            &ectx,
        );
        // Parent spawns child (tid=2). This forks the clock so child's
        // subsequent accesses strictly happen-after the parent's prior
        // ones.
        bus.dispatch(
            &Event::ThreadSpawn {
                parent_tid: 1,
                child_tid: 2,
                entry: 0xdead,
                flags: 0,
            },
            &ectx,
        );
        // Child (tid=2) writes 0x8000. Causally ordered after parent's
        // earlier write — must NOT be flagged as a race.
        bus.dispatch(
            &Event::MemWrite {
                addr: 0x8000,
                size: 64,
                concrete: &bytes,
                symbolic: &sym,
                pc: 0x200,
                tid: 2,
            },
            &ectx,
        );

        bus.run_finish(&ectx);

        let f = findings.borrow();
        assert!(
            f.is_empty(),
            "HB filter should suppress fork-ordered accesses, got {:?}",
            f
        );
    }

    /// After the parent has spawned a child, *subsequent* accesses on the
    /// parent are concurrent with the child's accesses (the parent ticks
    /// on spawn). Without the parent-tick this would be wrongly reported
    /// as ordered.
    #[test]
    fn volos_post_spawn_parent_access_still_races() {
        let ctx = fresh_ctx();
        let findings = RefCell::new(Vec::new());

        let mut bus: EventBus<'_> = EventBus::new();
        bus.add(Box::new(VolosPlugin::new()));

        let ectx = mk_ctx(&ctx, &findings);
        let bytes = vec![0u8; 8];
        let sym: Vec<Option<Rc<BV<'_>>>> = vec![None; 8];

        bus.dispatch(
            &Event::ThreadSpawn {
                parent_tid: 1,
                child_tid: 2,
                entry: 0xdead,
                flags: 0,
            },
            &ectx,
        );
        // Parent writes after spawn.
        bus.dispatch(
            &Event::MemWrite {
                addr: 0xb000,
                size: 64,
                concrete: &bytes,
                symbolic: &sym,
                pc: 0x100,
                tid: 1,
            },
            &ectx,
        );
        // Child writes the same cell — concurrent with the parent's
        // post-spawn write. Real race.
        bus.dispatch(
            &Event::MemWrite {
                addr: 0xb000,
                size: 64,
                concrete: &bytes,
                symbolic: &sym,
                pc: 0x200,
                tid: 2,
            },
            &ectx,
        );

        bus.run_finish(&ectx);

        let f = findings.borrow();
        assert!(
            f.iter().any(|x| x.rule == "data-race-unprotected"),
            "post-spawn writes from parent and child are concurrent and \
             should still be flagged, got {:?}",
            f
        );
    }

    /// Synthetic go_id assignment is monotonic in the order each tid is
    /// first observed. The first thread to issue an event gets `go=0`,
    /// the next `go=1`, regardless of the actual tid value.
    #[test]
    fn volos_assigns_go_ids_in_first_seen_order() {
        let ctx = fresh_ctx();
        let findings = RefCell::new(Vec::new());

        let mut bus: EventBus<'_> = EventBus::new();
        bus.add(Box::new(VolosPlugin::new()));
        let ectx = mk_ctx(&ctx, &findings);

        let bytes = vec![0u8; 8];
        let sym: Vec<Option<Rc<BV<'_>>>> = vec![None; 8];

        // tid=42 fires first → go_id 0.
        bus.dispatch(
            &Event::MemRead {
                addr: 0x1000,
                size: 64,
                concrete: &bytes,
                symbolic: &sym,
                pc: 0x10,
                tid: 42,
            },
            &ectx,
        );
        // tid=7 fires second → go_id 1.
        bus.dispatch(
            &Event::MemRead {
                addr: 0x1008,
                size: 64,
                concrete: &bytes,
                symbolic: &sym,
                pc: 0x14,
                tid: 7,
            },
            &ectx,
        );
        // tid=42 again — same go_id (stable).
        bus.dispatch(
            &Event::MemRead {
                addr: 0x1010,
                size: 64,
                concrete: &bytes,
                symbolic: &sym,
                pc: 0x18,
                tid: 42,
            },
            &ectx,
        );
        // ThreadSpawn ⇒ tid=99 → go_id 2.
        bus.dispatch(
            &Event::ThreadSpawn {
                parent_tid: 42,
                child_tid: 99,
                entry: 0xdead,
                flags: 0,
            },
            &ectx,
        );

        // The plugin instance is owned by the bus; we can't peek at it
        // directly. Instead, observe go_ids via the finding output: race
        // tid=42 vs tid=7 to confirm assignments end up in the report.
        let bytes2 = vec![0u8; 8];
        let sym2: Vec<Option<Rc<BV<'_>>>> = vec![None; 8];
        bus.dispatch(
            &Event::MemWrite {
                addr: 0x1000,
                size: 64,
                concrete: &bytes2,
                symbolic: &sym2,
                pc: 0x20,
                tid: 7,
            },
            &ectx,
        );
        bus.run_finish(&ectx);

        let f = findings.borrow();
        assert!(!f.is_empty(), "expected race finding to inspect go_ids");
        let detail_blob: String = f
            .iter()
            .flat_map(|x| x.details.iter().cloned())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            detail_blob.contains("tid=42, go=0"),
            "expected tid=42 → go=0 in finding details:\n{}",
            detail_blob
        );
        assert!(
            detail_blob.contains("tid=7, go=1"),
            "expected tid=7 → go=1 in finding details:\n{}",
            detail_blob
        );
    }

    /// Direct unit test on the region: forge two records whose vector
    /// clocks are strictly ordered and verify `race_pairs` skips them
    /// even with empty locksets.
    #[test]
    fn region_race_pairs_skips_strictly_ordered_clocks() {
        use super::region::VolosRegion;

        let mut early = VolosVC::new("a");
        early.tick(); // a:1
        let mut late = early.clone();
        late.node_id = "b".into();
        late.tick_at("b"); // a:1, b:1   →  early < late

        let r1 = Volos::new(1, AccessType::Write, Vec::new(), early)
            .with_addr_size(0x1234, 1);
        let r2 = Volos::new(2, AccessType::Write, Vec::new(), late)
            .with_addr_size(0x1234, 1);

        let mut region = VolosRegion::new(0, u64::MAX);
        region.add_record(r1);
        region.add_record(r2);

        let pairs = region.race_pairs();
        assert!(
            pairs.is_empty(),
            "strictly ordered clocks must not produce a race pair, got {:?}",
            pairs
        );
    }

    #[test]
    fn volos_detects_inconsistent_locking() {
        let ctx = fresh_ctx();
        let findings = RefCell::new(Vec::new());

        let mut bus: EventBus<'_> = EventBus::new();
        bus.add(Box::new(VolosPlugin::new()));

        let ectx = mk_ctx(&ctx, &findings);
        let bytes = vec![0u8; 8];
        let sym: Vec<Option<Rc<BV<'_>>>> = vec![None; 8];

        // tid=1 holds lock A, tid=2 holds lock B. Both write 0x7000.
        // Locksets are non-empty but disjoint — inconsistent locking.
        bus.dispatch(
            &Event::Call {
                pc: 0x80,
                target: 0xAAA,
                symbol: Some("runtime.lock"),
                tid: 1,
                arg0: 0,
            },
            &ectx,
        );
        bus.dispatch(
            &Event::Call {
                pc: 0x80,
                target: 0xBBB,
                symbol: Some("runtime.lock"),
                tid: 2,
                arg0: 0,
            },
            &ectx,
        );
        bus.dispatch(
            &Event::MemWrite {
                addr: 0x7000,
                size: 64,
                concrete: &bytes,
                symbolic: &sym,
                pc: 0x100,
                tid: 1,
            },
            &ectx,
        );
        bus.dispatch(
            &Event::MemWrite {
                addr: 0x7000,
                size: 64,
                concrete: &bytes,
                symbolic: &sym,
                pc: 0x200,
                tid: 2,
            },
            &ectx,
        );

        bus.run_finish(&ectx);

        let f = findings.borrow();
        assert!(
            f.iter().any(|x| x.rule == "data-race-inconsistent-locking"),
            "expected inconsistent-locking finding, got {:?}",
            f
        );
    }
}
