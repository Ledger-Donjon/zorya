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
//!
//! * `MemRead`     — appends a `Read` record for the address range.
//! * `MemWrite`    — appends a `Write` record for the address range.
//! * `Call`        — when the target symbol is a known lock primitive,
//!   updates the per-thread lockset.
//! * `ThreadSpawn` — initialises a vector clock for the new thread.
//! * `ThreadExit`  — flushes any thread-local bookkeeping.
//!
//! At `on_finish` the plugin runs the race-check pass over its accumulated
//! `VolosRegion` map and emits one finding per witness pair.

use std::collections::HashMap;
use std::collections::HashSet;

use z3::ast::{Ast, Bool};
use z3::{SatResult, Solver};

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

/// Flatten a satisfied solver's model into a single-line `var -> value`
/// witness for embedding in a finding detail. Empty when there is no model
/// (e.g. the assertion was a closed formula with no free constants).
fn model_string(solver: &Solver<'_>) -> String {
    solver
        .get_model()
        .map(|m| {
            format!("{}", m)
                .lines()
                .map(|l| l.trim())
                .filter(|l| !l.is_empty())
                .collect::<Vec<_>>()
                .join("; ")
        })
        .unwrap_or_default()
}

/// Granularity of the per-region map. Volos in the upstream fork tracks
/// at byte granularity per memory region; for the first plugin port we
/// keep a single global region keyed by absolute address. When
/// `EventCtx` exposes engine-state accessors we'll shard by the actual
/// memory regions reported by `MemoryX86_64`.
#[derive(Debug)]
pub struct VolosPlugin<'ctx> {
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

    /// Side table mapping a record id to the path condition `φ` captured
    /// when that access fired — the ordered branch constraints (over
    /// symbolic inputs) that gated the path reaching the access. Kept out
    /// of the [`Volos`] record so the record/region types stay free of
    /// Z3's `'ctx` lifetime; the record carries only the `record_id` key.
    ///
    /// This is what makes a race finding *input-aware*: at end-of-trace we
    /// conjoin the two racing accesses' conditions and ask Z3 for an input
    /// model, turning "raced on this schedule" into "races for every input
    /// satisfying `φ₁ ∧ φ₂`".
    path_conditions: HashMap<u64, Vec<Bool<'ctx>>>,

    /// Monotonic source of `record_id`s.
    next_record_id: u64,

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

impl<'ctx> VolosPlugin<'ctx> {
    pub fn new() -> Self {
        Self {
            locksets: HashMap::new(),
            clocks: HashMap::new(),
            go_ids: HashMap::new(),
            next_go_id: 0,
            region: VolosRegion::new(0, u64::MAX),
            path_conditions: HashMap::new(),
            next_record_id: 1,
            verbose: std::env::var("VOLOS_VERBOSE").is_ok_and(|v| v == "1"),
            reads: 0,
            writes: 0,
            lock_acquires: 0,
            lock_releases: 0,
            threads_spawned: 0,
        }
    }

    /// Allocate a fresh record id and remember the path condition `φ`
    /// captured for it. Cloning a `Bool<'ctx>` is a cheap reference-count
    /// bump, so snapshotting the whole slice per access is inexpensive.
    fn capture_path_condition(&mut self, parts: &[Bool<'ctx>]) -> u64 {
        let id = self.next_record_id;
        self.next_record_id += 1;
        if !parts.is_empty() {
            self.path_conditions.insert(id, parts.to_vec());
        }
        id
    }

    /// Decide the *input class* of a race witness pair: is the race
    /// input-independent, or only reachable for inputs satisfying the
    /// conjunction of the two accesses' path conditions `φ₁ ∧ φ₂`?
    ///
    /// This is the single solver call that lifts a schedule-specific
    /// witness ("these two accesses raced on the interleaving we ran") into
    /// an input-class result ("they race for every input model of
    /// `φ₁ ∧ φ₂`"). It reuses the shared Z3 context already owned by the
    /// engine; no new symbolic machinery is introduced.
    fn classify_input(&self, ctx: &'ctx z3::Context, rid1: u64, rid2: u64) -> InputClass {
        let mut parts: Vec<&Bool<'ctx>> = Vec::new();
        if let Some(p) = self.path_conditions.get(&rid1) {
            parts.extend(p.iter());
        }
        if let Some(p) = self.path_conditions.get(&rid2) {
            parts.extend(p.iter());
        }
        if parts.is_empty() {
            // Neither access was gated by a symbolic branch: the race fires
            // for *any* input that reaches this code.
            return InputClass::Unconditional;
        }

        let phi = parts
            .iter()
            .map(|b| format!("{}", b.simplify()))
            .collect::<Vec<_>>()
            .join(" ∧ ");

        // Query 1: φ = φ₁ ∧ φ₂. Is there an input that reaches both accesses?
        let solver = Solver::new(ctx);
        for p in &parts {
            solver.assert(p);
        }
        let trigger = match solver.check() {
            SatResult::Sat => model_string(&solver),
            SatResult::Unsat => return InputClass::Infeasible { phi },
            SatResult::Unknown => return InputClass::Unknown { phi },
        };

        // Query 2: ¬φ. Can an input *escape* the racing path? This separates
        // a genuinely input-dependent race (¬φ SAT — some inputs avoid it)
        // from one whose recorded guard is actually valid (¬φ UNSAT — the
        // race fires for every input, so the outcome is input-independent
        // even though branch constraints were captured).
        let phi_conj = Bool::and(ctx, &parts);
        let neg_solver = Solver::new(ctx);
        neg_solver.assert(&phi_conj.not());
        match neg_solver.check() {
            // ¬φ unsatisfiable ⇒ φ valid ⇒ reachable for *every* input.
            SatResult::Unsat => InputClass::InputIndependent { phi, trigger },
            // ¬φ satisfiable ⇒ the race is contingent on the input class φ;
            // `escape` is a concrete input that takes a different path.
            SatResult::Sat => InputClass::InputDependent {
                phi,
                trigger,
                escape: model_string(&neg_solver),
            },
            // Couldn't decide input-dependence; fall back to plain reachable.
            SatResult::Unknown => InputClass::Reachable { phi, trigger },
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

/// Result of coupling a race witness to the symbolic inputs: does the race
/// depend on program input, and if so, for which input class is it reachable?
///
/// Two solver queries decide this. First `φ = φ₁ ∧ φ₂` (do both accesses
/// share a feasible input?). If `φ` is SAT, a second query on `¬φ` teases
/// apart the two ways a "reachable" race can be input-related:
///
/// * `¬φ` UNSAT ⇒ `φ` is *valid* (holds for every input) ⇒ the captured
///   guard is vacuous and the race fires regardless of input value
///   (`InputIndependent`). Reaching the code never actually depended on
///   the input.
/// * `¬φ` SAT ⇒ there exist inputs *outside* `φ` that take a different
///   path ⇒ the race outcome is genuinely *contingent* on the input
///   (`InputDependent`), and `escape` is a concrete input that avoids the
///   racing path.
#[derive(Debug, Clone)]
pub enum InputClass {
    /// Neither racing access was gated by a symbolic branch — the race
    /// fires for every input that reaches the code (input-independent).
    Unconditional,
    /// `φ` is satisfiable and *valid* (`¬φ` is UNSAT): branch constraints
    /// were recorded but they hold for every input, so the race outcome
    /// does not actually depend on the input value. `trigger` is a witness.
    InputIndependent { phi: String, trigger: String },
    /// `φ` is satisfiable and so is `¬φ`: the race is genuinely contingent
    /// on the input. `trigger` drives the program into the race; `escape`
    /// is an input that takes a different path and avoids it.
    InputDependent {
        phi: String,
        trigger: String,
        escape: String,
    },
    /// `φ` is satisfiable but the solver could not decide `¬φ` (unknown):
    /// the race is reachable for every input ⊨ φ, but we cannot confirm
    /// whether it is input-dependent. `trigger` is a witness.
    Reachable { phi: String, trigger: String },
    /// The two accesses' path conditions are jointly unsatisfiable, so no
    /// single input drives the program down both paths. The witness is a
    /// schedule artefact, not an input-reachable race.
    Infeasible { phi: String },
    /// The solver returned `unknown` for `φ` (timeout / incompleteness).
    Unknown { phi: String },
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

impl<'ctx> Default for VolosPlugin<'ctx> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'ctx> Plugin<'ctx> for VolosPlugin<'ctx> {
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

    fn on_event(&mut self, ev: &Event<'ctx, '_>, ctx: &EventCtx<'ctx, '_>) -> Verdict {
        let real_goid = ctx.current_goid;
        match ev {
            Event::MemRead {
                addr,
                size,
                pc,
                tid,
                ..
            } => {
                self.reads += 1;
                let bytes = (*size as u64).div_ceil(8);
                let rid = self.capture_path_condition(ctx.path_constraints());
                let rec = self
                    .build_record(*tid, AccessType::Read, *addr, bytes, *pc, real_goid)
                    .with_record_id(rid);
                self.vlog(format!(
                    "READ  @0x{:x} size={} tid={} go={:?} locks_held={:?} |φ|={}",
                    rec.addr,
                    rec.size,
                    rec.thread_id,
                    rec.go_id,
                    rec.locks_held,
                    ctx.path_constraints().len()
                ));
                self.region.add_record(rec);
            }
            Event::MemWrite {
                addr,
                size,
                pc,
                tid,
                ..
            } => {
                self.writes += 1;
                let bytes = (*size as u64).div_ceil(8);
                let rid = self.capture_path_condition(ctx.path_constraints());
                let rec = self
                    .build_record(*tid, AccessType::Write, *addr, bytes, *pc, real_goid)
                    .with_record_id(rid);
                self.vlog(format!(
                    "WRITE @0x{:x} size={} tid={} go={:?} locks_held={:?} |φ|={}",
                    rec.addr,
                    rec.size,
                    rec.thread_id,
                    rec.go_id,
                    rec.locks_held,
                    ctx.path_constraints().len()
                ));
                self.region.add_record(rec);
            }
            Event::Call {
                target,
                symbol: Some(sym),
                tid,
                arg0,
                ..
            } => {
                {
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
            Event::Call { .. } => {
                // symbol is None — not a tracked primitive, nothing to do.
            }
            Event::ThreadSpawn {
                child_tid,
                parent_tid,
                ..
            } => {
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
            // Couple the race witness to the program inputs: ask whether
            // the two accesses' path conditions are jointly satisfiable and,
            // if so, recover a concrete input model. This is what turns a
            // pure-schedule witness into an input × concurrency finding.
            let input_class = self.classify_input(ctx.ctx, v1.record_id, v2.record_id);

            // Helpers to pick the plain vs input-gated rule id for the
            // detected race reason.
            let plain_rule = match reason {
                RaceReason::Unprotected => "data-race-unprotected",
                RaceReason::InconsistentLocking => "data-race-inconsistent-locking",
            };
            let gated_rule = match reason {
                RaceReason::Unprotected => "input-gated-data-race-unprotected",
                RaceReason::InconsistentLocking => "input-gated-data-race-inconsistent-locking",
            };

            // Rule id and title reflect the race's relationship to the
            // inputs, so CI baselines can distinguish the classes.
            let (rule, gating): (&'static str, String) = match &input_class {
                // No gating at all → plain rule, input-independent.
                InputClass::Unconditional => (plain_rule, "input-independent".to_string()),
                // Guard captured but valid (¬φ UNSAT) → fires for every
                // input → still input-independent in outcome; keep plain rule.
                InputClass::InputIndependent { .. } => (
                    plain_rule,
                    "input-independent (φ holds for all inputs)".to_string(),
                ),
                // Genuinely contingent on input (¬φ SAT) → input-gated rule.
                InputClass::InputDependent { .. } => (gated_rule, "input-dependent".to_string()),
                // φ SAT but ¬φ undecided → reachable under φ; input-gated rule.
                InputClass::Reachable { .. } => (gated_rule, "input-gated (reachable)".to_string()),
                InputClass::Infeasible { .. } => (
                    "data-race-schedule-only",
                    "schedule-only (path conditions jointly UNSAT)".to_string(),
                ),
                InputClass::Unknown { .. } => {
                    (plain_rule, "input-gated (solver: unknown)".to_string())
                }
            };

            let title = format!(
                "Data race at 0x{:x} [{}]: {} ({} vs {})",
                addr, gating, reason, v1.access_type, v2.access_type
            );
            let mut finding = Finding::new("volos", rule, Severity::High, ctx.current_pc, title)
                .with_detail(format!(
                    "Access 1 (tid={}, go={}): {} at 0x{:x}, locks_held={:?}, vc={}",
                    v1.thread_id,
                    v1.go_id
                        .map(|g| g.to_string())
                        .unwrap_or_else(|| "?".into()),
                    v1.access_type,
                    v1.pc,
                    v1.locks_held,
                    v1.vector_clock,
                ))
                .with_detail(format!(
                    "Access 2 (tid={}, go={}): {} at 0x{:x}, locks_held={:?}, vc={}",
                    v2.thread_id,
                    v2.go_id
                        .map(|g| g.to_string())
                        .unwrap_or_else(|| "?".into()),
                    v2.access_type,
                    v2.pc,
                    v2.locks_held,
                    v2.vector_clock,
                ))
                .with_detail(format!("Reason: {}", reason));

            // Helper: render an optionally-empty model witness.
            fn witness(m: &str) -> &str {
                if m.is_empty() {
                    "(trivial)"
                } else {
                    m
                }
            }

            // Stamp the input × concurrency coupling onto the finding.
            finding = match input_class {
                InputClass::Unconditional => finding.with_detail(
                    "Input class: input-independent (no symbolic branch gates either access)"
                        .to_string(),
                ),
                InputClass::InputIndependent { phi, trigger } => finding
                    .with_detail(format!("Path condition φ = φ₁ ∧ φ₂: {}", phi))
                    .with_detail(
                        "Input class: input-independent — φ is valid (¬φ UNSAT), so the race \
                         fires for every input; the recorded branch guard is not what gates it"
                            .to_string(),
                    )
                    .with_detail(format!("Witness (any input works): {}", witness(&trigger))),
                InputClass::InputDependent {
                    phi,
                    trigger,
                    escape,
                } => finding
                    .with_detail(format!("Path condition φ = φ₁ ∧ φ₂: {}", phi))
                    .with_detail(format!(
                        "Input class: input-dependent — race occurs iff input ⊨ φ; \
                         triggering input: {}",
                        witness(&trigger)
                    ))
                    .with_detail(format!(
                        "Escape input (⊨ ¬φ, takes a different path, no race): {}",
                        witness(&escape)
                    )),
                InputClass::Reachable { phi, trigger } => finding
                    .with_detail(format!("Path condition φ = φ₁ ∧ φ₂: {}", phi))
                    .with_detail(format!(
                        "Input class: race reachable for every input ⊨ φ (input-dependence \
                         undecided: ¬φ returned unknown); witness: {}",
                        witness(&trigger)
                    )),
                InputClass::Infeasible { phi } => finding
                    .with_detail(format!("Path condition φ = φ₁ ∧ φ₂: {}", phi))
                    .with_detail(
                        "Input class: UNSAT — no single input reaches both accesses; \
                         schedule-only witness, not input-reachable"
                            .to_string(),
                    ),
                InputClass::Unknown { phi } => finding
                    .with_detail(format!("Path condition φ = φ₁ ∧ φ₂: {}", phi))
                    .with_detail(
                        "Input class: solver returned unknown for φ (timeout/incompleteness)"
                            .to_string(),
                    ),
            };

            // We're outside a per-event dispatch here so we push directly
            // into the shared findings buffer.
            ctx.findings.borrow_mut().push(finding);
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

    /// **Input × concurrency coupling.** Two threads write the same cell
    /// with no lock, but one write is gated by a symbolic branch
    /// `os_args_1 == 0xCA`. The plugin must (a) still flag the race, (b)
    /// classify it as *input-gated*, and (c) solve `φ` to recover the
    /// triggering input (`os_args_1 = 0xCA`). This is the brand-new
    /// capability: a data race reported together with the input class that
    /// triggers it.
    #[test]
    fn volos_input_gated_race_is_solved() {
        use z3::ast::Bool;

        let ctx = fresh_ctx();
        let findings = RefCell::new(Vec::new());

        let mut bus: EventBus<'_> = EventBus::new();
        bus.add(Box::new(VolosPlugin::new()));

        let bytes = vec![0u8; 8];
        let sym: Vec<Option<Rc<BV<'_>>>> = vec![None; 8];

        // Symbolic input byte and the branch guard that gates thread 1's
        // write: os_args_1 == 0xCA.
        let input = BV::new_const(&ctx, "os_args_1", 8);
        let guard: Bool = input._eq(&BV::from_u64(&ctx, 0xCA, 8));
        let gated_parts = vec![guard];

        // Thread 1 writes 0x5000 *under* the guard φ = (os_args_1 == 0xCA).
        let ectx_gated = EventCtx::new(&ctx, 0x100, 1, 0, Instant::now(), &findings)
            .with_path_constraints(&gated_parts);
        bus.dispatch(
            &Event::MemWrite {
                addr: 0x5000,
                size: 64,
                concrete: &bytes,
                symbolic: &sym,
                pc: 0x100,
                tid: 1,
            },
            &ectx_gated,
        );

        // Thread 2 writes 0x5000 unconditionally (no path constraints).
        let ectx_plain = EventCtx::new(&ctx, 0x200, 2, 0, Instant::now(), &findings);
        bus.dispatch(
            &Event::MemWrite {
                addr: 0x5000,
                size: 64,
                concrete: &bytes,
                symbolic: &sym,
                pc: 0x200,
                tid: 2,
            },
            &ectx_plain,
        );

        bus.run_finish(&ectx_gated);

        let f = findings.borrow();
        assert!(!f.is_empty(), "expected an input-gated race finding");
        assert!(
            f.iter()
                .any(|x| x.rule == "input-gated-data-race-unprotected"),
            "race should be classified input-gated, got rules: {:?}",
            f.iter().map(|x| x.rule).collect::<Vec<_>>()
        );
        let blob: String = f
            .iter()
            .flat_map(|x| x.details.iter().cloned())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            blob.contains("Path condition φ"),
            "finding must carry the path condition φ:\n{}",
            blob
        );
        assert!(
            blob.contains("os_args_1"),
            "solved input model must mention the symbolic input:\n{}",
            blob
        );
        // ¬φ (os_args_1 != 0xCA) is satisfiable, so this is a *genuinely
        // input-dependent* race: the finding must say so and carry an
        // escape input that avoids the racing path.
        assert!(
            blob.contains("input-dependent"),
            "finding must classify the race as input-dependent:\n{}",
            blob
        );
        assert!(
            blob.contains("Escape input"),
            "input-dependent finding must carry a ¬φ escape witness:\n{}",
            blob
        );
    }

    /// **Input-gated reachability with an input-INDEPENDENT outcome.** Both
    /// accesses are reached under a guard `φ` that is a *tautology* over the
    /// input (`x == 0 ∨ x != 0`). `φ` is SAT but `¬φ` is UNSAT, so the race
    /// fires for every input: the detector must label it input-independent
    /// (and keep the plain rule), not input-gated, even though branch
    /// constraints were captured.
    #[test]
    fn volos_valid_guard_is_input_independent() {
        use z3::ast::Bool;

        let ctx = fresh_ctx();
        let findings = RefCell::new(Vec::new());

        let mut bus: EventBus<'_> = EventBus::new();
        bus.add(Box::new(VolosPlugin::new()));

        let bytes = vec![0u8; 8];
        let sym: Vec<Option<Rc<BV<'_>>>> = vec![None; 8];

        // Tautological guard: (x == 0) ∨ (x != 0)  ≡  true.
        let x = BV::new_const(&ctx, "in_byte", 8);
        let eq0 = x._eq(&BV::from_u64(&ctx, 0, 8));
        let taut: Bool = Bool::or(&ctx, &[&eq0, &eq0.not()]);
        let parts = vec![taut];

        let ectx_gated = EventCtx::new(&ctx, 0x100, 1, 0, Instant::now(), &findings)
            .with_path_constraints(&parts);
        bus.dispatch(
            &Event::MemWrite {
                addr: 0x5000,
                size: 64,
                concrete: &bytes,
                symbolic: &sym,
                pc: 0x100,
                tid: 1,
            },
            &ectx_gated,
        );
        let ectx_plain = EventCtx::new(&ctx, 0x200, 2, 0, Instant::now(), &findings);
        bus.dispatch(
            &Event::MemWrite {
                addr: 0x5000,
                size: 64,
                concrete: &bytes,
                symbolic: &sym,
                pc: 0x200,
                tid: 2,
            },
            &ectx_plain,
        );
        bus.run_finish(&ectx_gated);

        let f = findings.borrow();
        assert!(
            f.iter().any(|x| x.rule == "data-race-unprotected"),
            "valid-guard race must keep the plain rule, got: {:?}",
            f.iter().map(|x| x.rule).collect::<Vec<_>>()
        );
        let blob: String = f
            .iter()
            .flat_map(|x| x.details.iter().cloned())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            blob.contains("φ is valid") || blob.contains("input-independent"),
            "finding must explain the race is input-independent (φ valid):\n{}",
            blob
        );
        assert!(
            !f.iter().any(|x| x.rule.starts_with("input-gated")),
            "a valid guard must NOT be reported as input-gated:\n{:?}",
            f.iter().map(|x| x.rule).collect::<Vec<_>>()
        );
    }

    /// A race with no symbolic gating on either access must be labelled
    /// *input-independent* and keep the plain `data-race-unprotected` rule
    /// so existing baselines are unaffected.
    #[test]
    fn volos_unconditional_race_marked_input_independent() {
        let ctx = fresh_ctx();
        let findings = RefCell::new(Vec::new());

        let mut bus: EventBus<'_> = EventBus::new();
        bus.add(Box::new(VolosPlugin::new()));

        let ectx = mk_ctx(&ctx, &findings);
        let bytes = vec![0u8; 8];
        let sym: Vec<Option<Rc<BV<'_>>>> = vec![None; 8];

        for (tid, pc) in [(1u64, 0x100u64), (2u64, 0x200u64)] {
            bus.dispatch(
                &Event::MemWrite {
                    addr: 0x5000,
                    size: 64,
                    concrete: &bytes,
                    symbolic: &sym,
                    pc,
                    tid,
                },
                &ectx,
            );
        }
        bus.run_finish(&ectx);

        let f = findings.borrow();
        assert!(
            f.iter().any(|x| x.rule == "data-race-unprotected"),
            "unconditional race keeps the plain rule, got: {:?}",
            f.iter().map(|x| x.rule).collect::<Vec<_>>()
        );
        let blob: String = f
            .iter()
            .flat_map(|x| x.details.iter().cloned())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            blob.contains("input-independent"),
            "finding must be labelled input-independent:\n{}",
            blob
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

        let r1 = Volos::new(1, AccessType::Write, Vec::new(), early).with_addr_size(0x1234, 1);
        let r2 = Volos::new(2, AccessType::Write, Vec::new(), late).with_addr_size(0x1234, 1);

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
