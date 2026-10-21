// SPDX-FileCopyrightText: 2026 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

//! Go goroutine scheduling model used under `--thread-scheduling all-threads`.
//!
//! `runtime.newproc` creates a goroutine context and runs it right away (see
//! [`ConcolicExecutor::spawn_goroutine_and_switch`]). This module decides
//! what happens next, at Go's own scheduling points rather than inside the
//! runtime scheduler:
//!
//! * **Blocking.** `<-ch` parks the goroutine until the channel is closed or
//!   sent to; `WaitGroup.Wait` parks it while the counter is positive. A
//!   parked goroutine is resumed at the blocking call's entry, so the check
//!   runs again with the state its wakers left.
//! * **Defers.** `deferprocStack` / `deferproc` record the deferred closure
//!   for the deferring frame; `deferreturn` calls it. Deferred `Unlock` and
//!   `Done` therefore run.
//! * **Budgets.** A goroutine is retired after `max_loop_iterations` back
//!   edges to the same loop head in application code, or after
//!   `max_goroutine_instructions` instructions. Retiring runs its pending
//!   defers first, like `runtime.Goexit`. `max_goroutines_per_site` caps how
//!   many goroutines one `go` statement creates; `max_switches` caps context
//!   switches.
//! * **main.main returning.** The run continues until every runnable
//!   goroutine has finished or blocked, instead of stopping at once.
//! * **Deadlocks.** When nothing can run because a wake-up was not modelled
//!   (a `WaitGroup` counter the explored goroutines never bring to zero), the
//!   oldest `WaitGroup` waiter, then the oldest receiver, is forced through
//!   and the forced wake-up is reported.
//!
//! The main goroutine is never retired. Contexts other than main and the
//! goroutines created here (OS threads restored from the dump) are left to
//! the generic scheduler.

use std::collections::{BTreeMap, HashMap, HashSet};

use parser::parser::{Inst, Opcode, Var};
use z3::ast::{Bool, BV};

use crate::concolic::executor::{ConcolicExecutor, THREAD_EXIT_SENTINEL};
use crate::concolic::ConcolicVar;
use crate::plugins::event::{Event, EventKind, MapOp};
use crate::state::func_index;
use crate::state::memory_x86_64::MemoryValue;
use crate::state::race_report::{self, goroutine_label, GoroutineRecord, ScheduleRecord};
use crate::state::run_status;
use crate::state::thread_manager::ThreadStatus;
use crate::tprintln;

const DEFAULT_MAX_SWITCHES: usize = 512;
const DEFAULT_MAX_LOOP_ITERATIONS: usize = 3;
const DEFAULT_MAX_GOROUTINES_PER_SITE: usize = 2;
const DEFAULT_MAX_GOROUTINE_INSTRUCTIONS: u64 = 2_000_000;
/// Offset of `fn` in `runtime._defer` on amd64 (Go 1.18 and later).
const DEFER_FN_OFFSET: u64 = 24;
/// Frames recorded for a map access.
const MAX_STACK_FRAMES: usize = 8;
const MAX_KEY_BYTES: u64 = 64;
/// Instructions visited when looking for a statically reachable `go`.
const MAX_STATIC_SPAWN_INSTRUCTIONS: usize = 20_000;

const RIP: u64 = 0x288;
const RSP: u64 = 0x20;
const RBP: u64 = 0x28;
const RAX: u64 = 0x0;
const RBX: u64 = 0x18;
const RCX: u64 = 0x8;
const RDX: u64 = 0x10;
const RDI: u64 = 0x38;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulePolicy {
    /// Run the next runnable goroutine in tid order.
    RoundRobin,
    /// Pick a random runnable goroutine at each switch and preempt at loop
    /// back edges; `ZORYA_SCHEDULE_SEED` replays a run.
    Random,
}

impl SchedulePolicy {
    pub fn label(self) -> &'static str {
        match self {
            SchedulePolicy::RoundRobin => "round_robin",
            SchedulePolicy::Random => "random",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockReason {
    ChanRecv(u64),
    WaitGroup(u64),
    MainReturned,
}

impl BlockReason {
    pub fn describe(&self) -> String {
        match self {
            BlockReason::ChanRecv(c) => format!("channel receive on 0x{c:x}"),
            BlockReason::WaitGroup(w) => format!("WaitGroup.Wait on 0x{w:x}"),
            BlockReason::MainReturned => "main.main returned".to_string(),
        }
    }
}

/// What the main loop does after a scheduling hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedAction {
    /// Keep executing the current context at the current RIP.
    Continue,
    /// Continue at this RIP (possibly in another context).
    Jump(u64),
    /// Nothing is left to run.
    Stop,
}

/// Classification of the function containing a PC.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PcClass {
    pub app: bool,
    pub map_internal: bool,
    pub runtime_internal: bool,
}

#[derive(Debug, Clone)]
pub struct GoroutineMeta {
    pub tid: u64,
    pub goid: Option<u64>,
    pub parent_tid: u64,
    pub host_os_tid: Option<u64>,
    pub entry: u64,
    pub spawn_pc: u64,
    pub end: Option<String>,
    pub instructions: u64,
}

#[derive(Debug)]
pub struct GoSchedState {
    pub enabled: bool,
    pub policy: SchedulePolicy,
    pub seed: u64,
    rng: u64,
    pub max_switches: usize,
    pub max_loop_iterations: usize,
    pub max_goroutines_per_site: usize,
    pub max_goroutine_instructions: u64,
    pub switches: usize,
    pub trace: Vec<(u64, Option<u64>)>,
    pub goroutines: BTreeMap<u64, GoroutineMeta>,
    spawns_per_site: HashMap<u64, usize>,
    pub skipped_spawns: usize,
    loop_counts: HashMap<(u64, u64), usize>,
    last_pc: (u64, u64),
    pc_class_cache: (u64, u64, PcClass),
    blocked: BTreeMap<u64, (BlockReason, usize)>,
    block_seq: usize,
    /// Contexts resumed after parking, which re-emit their acquire edge.
    woken: HashSet<u64>,
    /// Contexts let through a blocking call without their condition holding.
    forced: HashSet<u64>,
    closed_chans: HashSet<u64>,
    pending_sends: HashMap<u64, u64>,
    pub forced_wakes: Vec<String>,
    /// Pending defers per context: `(deferring frame SP, funcval)`.
    defers: HashMap<u64, Vec<(u64, u64)>>,
    /// Contexts being retired, with the reason, while their defers run.
    exiting: HashMap<u64, String>,
    pub main_tid: Option<u64>,
    pub main_goid: Option<u64>,
    pub main_returned: bool,
    pub budget_exhausted: bool,
    map_names: HashMap<u64, Option<String>>,
    /// Call site of the first `runtime.newproc` reached in the running overlay.
    pub overlay_spawn_pc: Option<u64>,
}

fn env_parse<T: std::str::FromStr>(name: &str) -> Option<T> {
    std::env::var(name).ok().and_then(|v| v.trim().parse().ok())
}

impl GoSchedState {
    pub fn from_env() -> Self {
        let policy = match std::env::var("ZORYA_SCHEDULE")
            .unwrap_or_default()
            .to_lowercase()
            .as_str()
        {
            "random" | "rand" => SchedulePolicy::Random,
            _ => SchedulePolicy::RoundRobin,
        };
        let seed = env_parse::<u64>("ZORYA_SCHEDULE_SEED").unwrap_or_else(|| {
            if policy == SchedulePolicy::Random {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos() as u64)
                    .unwrap_or(1)
            } else {
                0
            }
        });
        Self {
            enabled: false,
            policy,
            seed,
            rng: (seed ^ 0x9e37_79b9_7f4a_7c15) | 1,
            max_switches: env_parse("ZORYA_MAX_GOROUTINE_SWITCHES").unwrap_or(DEFAULT_MAX_SWITCHES),
            max_loop_iterations: env_parse("ZORYA_MAX_LOOP_ITERATIONS")
                .unwrap_or(DEFAULT_MAX_LOOP_ITERATIONS),
            max_goroutines_per_site: env_parse("ZORYA_MAX_GOROUTINES_PER_SITE")
                .unwrap_or(DEFAULT_MAX_GOROUTINES_PER_SITE),
            max_goroutine_instructions: env_parse("ZORYA_MAX_GOROUTINE_INSTRUCTIONS")
                .unwrap_or(DEFAULT_MAX_GOROUTINE_INSTRUCTIONS),
            switches: 0,
            trace: Vec::new(),
            goroutines: BTreeMap::new(),
            spawns_per_site: HashMap::new(),
            skipped_spawns: 0,
            loop_counts: HashMap::new(),
            last_pc: (u64::MAX, 0),
            pc_class_cache: (0, 0, PcClass::default()),
            blocked: BTreeMap::new(),
            block_seq: 0,
            woken: HashSet::new(),
            forced: HashSet::new(),
            closed_chans: HashSet::new(),
            pending_sends: HashMap::new(),
            forced_wakes: Vec::new(),
            defers: HashMap::new(),
            exiting: HashMap::new(),
            main_tid: None,
            main_goid: None,
            main_returned: false,
            budget_exhausted: false,
            map_names: HashMap::new(),
            overlay_spawn_pc: None,
        }
    }

    fn next_rand(&mut self) -> u64 {
        let mut x = self.rng;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.rng = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// Whether `tid` is scheduled by this model.
    fn is_managed(&self, tid: u64) -> bool {
        self.main_tid == Some(tid) || self.goroutines.contains_key(&tid)
    }

    fn goid_of(&self, tid: u64) -> Option<u64> {
        if self.main_tid == Some(tid) {
            return self.main_goid;
        }
        self.goroutines.get(&tid).and_then(|g| g.goid)
    }

    /// Goroutine records for the race summary.
    pub fn goroutine_records(&self) -> Vec<GoroutineRecord> {
        self.goroutines
            .values()
            .map(|g| GoroutineRecord {
                tid: g.tid,
                goid: g.goid,
                parent_tid: g.parent_tid,
                host_os_tid: g.host_os_tid,
                entry: g.entry,
                spawn_pc: g.spawn_pc,
                end: g.end.clone(),
                instructions: g.instructions,
            })
            .collect()
    }

    /// Schedule record for the race summary.
    pub fn schedule_record(&self) -> ScheduleRecord {
        ScheduleRecord {
            enabled: self.enabled,
            policy: self.policy.label().to_string(),
            seed: (self.policy == SchedulePolicy::Random).then_some(self.seed),
            max_switches: self.max_switches,
            max_loop_iterations: self.max_loop_iterations,
            max_goroutines_per_site: self.max_goroutines_per_site,
            max_goroutine_instructions: self.max_goroutine_instructions as usize,
            switches: self.switches,
            trace: self.trace.clone(),
            forced_wakes: self.forced_wakes.clone(),
            skipped_spawns: self.skipped_spawns,
            budget_exhausted: self.budget_exhausted,
            main_returned: self.main_returned,
            blocked_at_end: self
                .blocked
                .iter()
                .filter(|(_, (reason, _))| *reason != BlockReason::MainReturned)
                .map(|(&tid, (reason, _))| (tid, self.goid_of(tid), reason.describe()))
                .collect(),
            main_tid: self.main_tid.unwrap_or(0),
            main_goid: self.main_goid,
        }
    }
}

impl Default for GoSchedState {
    fn default() -> Self {
        Self::from_env()
    }
}

/// Render a map key passed by value, or `None` when it is not printable.
fn render_key(bytes: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(bytes).ok()?;
    s.chars().all(|c| !c.is_control()).then(|| format!("{s:?}"))
}

impl<'ctx> ConcolicExecutor<'ctx> {
    fn go_current_tid(&self) -> u64 {
        self.state
            .thread_manager
            .lock()
            .map(|tm| tm.current_tid)
            .unwrap_or(0)
    }

    fn go_read_u64(&self, addr: u64) -> Option<u64> {
        self.state
            .memory
            .read_u64(addr, &mut self.state.logger.clone())
            .ok()
            .map(|v| v.concrete.to_u64())
    }

    fn go_write_u64(&mut self, addr: u64, value: u64) -> bool {
        let sym = BV::from_u64(self.context, value, 64);
        self.state
            .memory
            .write_u64(addr, &MemoryValue::new(value, sym, 64))
            .is_ok()
    }

    /// Classify the function containing `pc`, caching the last range.
    pub fn classify_pc(&mut self, pc: u64) -> PcClass {
        let (start, end, class) = self.go_sched.pc_class_cache;
        if pc >= start && pc < end {
            return class;
        }
        let Some((start, end, name)) = func_index::get().and_then(|idx| idx.function_at(pc)) else {
            return PcClass::default();
        };
        let class = PcClass {
            app: func_index::is_application_function(name),
            map_internal: func_index::is_map_internal_function(name),
            runtime_internal: func_index::is_runtime_internal_function(name),
        };
        self.go_sched.pc_class_cache = (start, end, class);
        class
    }

    /// Enable the model for this run and record the main goroutine.
    pub fn go_sched_begin(&mut self) {
        let is_go = std::env::var("SOURCE_LANG")
            .map(|l| l.eq_ignore_ascii_case("go"))
            .unwrap_or(false);
        let enabled = is_go && self.goroutine_scheduling_enabled();
        let tid = self.go_current_tid();
        let goid = self.get_current_goroutine_id().ok().filter(|&g| g != 0);
        let s = &mut self.go_sched;
        s.enabled = enabled;
        s.main_tid = Some(tid);
        s.main_goid = goid;
        s.trace.push((tid, goid));
        if enabled {
            tprintln!(
                "[SCHED] Goroutine model: {} schedule{}, at most {} switches, {} loop iterations and {} instructions per goroutine, {} goroutines per go statement",
                s.policy.label(),
                if s.policy == SchedulePolicy::Random {
                    format!(" (seed {})", s.seed)
                } else {
                    String::new()
                },
                s.max_switches,
                s.max_loop_iterations,
                s.max_goroutine_instructions,
                s.max_goroutines_per_site
            );
        }
    }

    /// Whether another goroutine may be created at call site `spawn_pc`.
    /// Counts the spawn when it is allowed.
    pub fn go_sched_allow_spawn(&mut self, spawn_pc: u64) -> bool {
        if !self.go_sched.enabled {
            return true;
        }
        let max = self.go_sched.max_goroutines_per_site;
        let n = self.go_sched.spawns_per_site.entry(spawn_pc).or_insert(0);
        if *n >= max {
            self.go_sched.skipped_spawns += 1;
            return false;
        }
        *n += 1;
        if self.go_sched.goroutines.is_empty() {
            run_status::enter_phase("scheduler_exploration");
        }
        true
    }

    /// Record a goroutine created by the `newproc` hook.
    pub fn go_sched_note_spawn(&mut self, meta: GoroutineMeta) {
        if !self.go_sched.enabled {
            return;
        }
        self.go_sched.trace.push((meta.tid, meta.goid));
        self.go_sched.goroutines.insert(meta.tid, meta);
    }

    /// Under the random policy, possibly let the parent run before the new
    /// goroutine. Returns the RIP to continue at.
    pub fn go_sched_after_spawn(&mut self, child_tid: u64, child_entry: u64) -> u64 {
        if !self.go_sched.enabled
            || self.go_sched.policy != SchedulePolicy::Random
            || self.go_sched.next_rand().is_multiple_of(2)
        {
            return child_entry;
        }
        match self
            .go_sched
            .goroutines
            .get(&child_tid)
            .map(|g| g.parent_tid)
        {
            Some(parent) => self.go_switch(child_entry, parent).unwrap_or(child_entry),
            None => child_entry,
        }
    }

    /// Per-instruction hook: instruction budget, loop bound, random
    /// preemption. `rip` is the next instruction of the running context.
    pub fn go_sched_on_instruction(&mut self, rip: u64) -> SchedAction {
        if !self.go_sched.enabled || self.overlay_state.is_some() {
            return SchedAction::Continue;
        }
        let tid = self.go_current_tid();
        let (prev_tid, prev_pc) = std::mem::replace(&mut self.go_sched.last_pc, (tid, rip));
        if self.go_sched.exiting.contains_key(&tid) {
            return SchedAction::Continue;
        }
        let max_instructions = self.go_sched.max_goroutine_instructions;
        let Some(meta) = self.go_sched.goroutines.get_mut(&tid) else {
            return SchedAction::Continue;
        };
        if meta.end.is_some() {
            return SchedAction::Continue;
        }
        meta.instructions += 1;
        if max_instructions > 0 && meta.instructions > max_instructions {
            return self.go_retire_current(format!(
                "retired: instruction budget ({max_instructions}) reached"
            ));
        }
        if prev_tid != tid || prev_pc <= rip {
            return SchedAction::Continue;
        }
        let class = self.classify_pc(rip);
        let (start, end, _) = self.go_sched.pc_class_cache;
        if !class.app || prev_pc < start || prev_pc >= end {
            return SchedAction::Continue;
        }
        let max_iter = self.go_sched.max_loop_iterations;
        let count = self.go_sched.loop_counts.entry((tid, rip)).or_insert(0);
        *count += 1;
        if max_iter > 0 && *count > max_iter {
            return self.go_retire_current(format!(
                "retired: loop at 0x{rip:x} ran {max_iter} iterations"
            ));
        }
        if self.go_sched.policy == SchedulePolicy::Random
            && self.go_sched.next_rand().is_multiple_of(4)
        {
            return self.go_yield(rip);
        }
        SchedAction::Continue
    }

    /// Hook run before a summarised runtime function is applied. Returns
    /// `Some` when the scheduler took over control flow.
    pub fn go_sched_before_summary(&mut self, sym: &str, rip: u64) -> Option<SchedAction> {
        if !self.go_sched.enabled || self.overlay_state.is_some() {
            return None;
        }
        let tid = self.go_current_tid();
        if !self.go_sched.is_managed(tid) {
            return None;
        }
        let sym = sym.strip_suffix(".abi0").unwrap_or(sym);
        match sym {
            "runtime.chanrecv1" | "runtime.chanrecv2" | "runtime.chanrecv" => {
                let c = self.read_reg64(RAX);
                if c == 0 {
                    return None;
                }
                let ready = self.go_sched.closed_chans.contains(&c)
                    || self
                        .go_sched
                        .pending_sends
                        .get_mut(&c)
                        .filter(|n| **n > 0)
                        .map(|n| *n -= 1)
                        .is_some();
                self.go_block_or_proceed(sym, rip, tid, BlockReason::ChanRecv(c), ready)
            }
            "sync.(*WaitGroup).Wait" => {
                let wg = self.read_reg64(RAX);
                if wg == 0 {
                    return None;
                }
                let counter = self.go_read_u64(wg).map(|s| (s >> 32) as i32).unwrap_or(0);
                self.go_block_or_proceed(sym, rip, tid, BlockReason::WaitGroup(wg), counter <= 0)
            }
            "runtime.closechan" => {
                let c = self.read_reg64(RAX);
                if c != 0 {
                    self.go_sched.closed_chans.insert(c);
                }
                None
            }
            "runtime.chansend1" | "runtime.chansend" => {
                let c = self.read_reg64(RAX);
                if c != 0 {
                    *self.go_sched.pending_sends.entry(c).or_insert(0) += 1;
                }
                None
            }
            "runtime.deferprocStack" => {
                let d = self.read_reg64(RAX);
                let sp = self.read_reg64(RSP).wrapping_add(8);
                if let Some(fnval) = self.go_read_u64(d.wrapping_add(DEFER_FN_OFFSET)) {
                    if fnval != 0 {
                        self.go_sched
                            .defers
                            .entry(tid)
                            .or_default()
                            .push((sp, fnval));
                    }
                }
                None
            }
            "runtime.deferproc" => {
                let fnval = self.read_reg64(RAX);
                let sp = self.read_reg64(RSP).wrapping_add(8);
                if fnval != 0 {
                    self.go_sched
                        .defers
                        .entry(tid)
                        .or_default()
                        .push((sp, fnval));
                }
                None
            }
            "runtime.deferreturn" => {
                let sp = self.read_reg64(RSP).wrapping_add(8);
                let fnval = match self.go_sched.defers.get_mut(&tid) {
                    Some(list) if list.last().is_some_and(|&(s, _)| s == sp) => list.pop()?.1,
                    _ => return None,
                };
                self.go_call_deferred(fnval, rip).map(SchedAction::Jump)
            }
            _ => None,
        }
    }

    /// Call the deferred closure `fnval` so it returns to `return_to`.
    fn go_call_deferred(&mut self, fnval: u64, return_to: u64) -> Option<u64> {
        let entry = self.go_read_u64(fnval).filter(|&e| e != 0)?;
        let rsp = self.read_reg64(RSP).wrapping_sub(8);
        if !self.go_write_u64(rsp, return_to) {
            return None;
        }
        self.write_reg64(RSP, rsp);
        self.write_reg64(RDX, fnval);
        self.write_reg64(RIP, entry);
        // Balanced by the deferred function's RET.
        self.push_function_frame(entry);
        Some(entry)
    }

    fn go_block_or_proceed(
        &mut self,
        sym: &str,
        rip: u64,
        tid: u64,
        reason: BlockReason,
        ready: bool,
    ) -> Option<SchedAction> {
        let forced = self.go_sched.forced.remove(&tid);
        if ready || forced {
            if self.go_sched.woken.remove(&tid) {
                // The acquire edge emitted at the call site predates the
                // wake-up; emit it again with the wakers' history.
                self.maybe_emit_sync_edge(rip, Some(sym), tid);
            }
            return None;
        }
        self.go_sched.block_seq += 1;
        let seq = self.go_sched.block_seq;
        self.go_sched.blocked.insert(tid, (reason, seq));
        self.go_set_status(tid, ThreadStatus::Blocked);
        match self.go_schedule_next(rip) {
            SchedAction::Continue => {
                // Forced straight through: nothing else could run.
                self.go_sched.forced.remove(&tid);
                self.go_sched.blocked.remove(&tid);
                self.go_set_status(tid, ThreadStatus::Running);
                if self.go_sched.woken.remove(&tid) {
                    self.maybe_emit_sync_edge(rip, Some(sym), tid);
                }
                None
            }
            other => Some(other),
        }
    }

    fn go_set_status(&mut self, tid: u64, status: ThreadStatus) {
        if let Ok(mut tm) = self.state.thread_manager.lock() {
            if let Some(t) = tm.threads.get_mut(&tid) {
                if !matches!(t.status, ThreadStatus::Exited(_)) {
                    t.status = status;
                }
            }
        }
    }

    /// Wake parked contexts whose condition now holds.
    fn go_refresh_blocked(&mut self) {
        let mut wake = Vec::new();
        for (&tid, &(reason, _)) in &self.go_sched.blocked {
            let ok = match reason {
                BlockReason::ChanRecv(c) => {
                    self.go_sched.closed_chans.contains(&c)
                        || self.go_sched.pending_sends.get(&c).is_some_and(|&n| n > 0)
                }
                BlockReason::WaitGroup(wg) => self
                    .go_read_u64(wg)
                    .map(|s| (s >> 32) as i32 <= 0)
                    .unwrap_or(true),
                BlockReason::MainReturned => false,
            };
            if ok {
                wake.push(tid);
            }
        }
        for tid in wake {
            self.go_wake(tid);
        }
    }

    fn go_wake(&mut self, tid: u64) {
        self.go_sched.blocked.remove(&tid);
        self.go_sched.woken.insert(tid);
        self.go_set_status(tid, ThreadStatus::Ready);
    }

    /// Runnable managed contexts other than `cur`.
    fn go_runnable_except(&self, cur: u64) -> Vec<u64> {
        let Ok(tm) = self.state.thread_manager.lock() else {
            return Vec::new();
        };
        let mut out: Vec<u64> = self
            .go_sched
            .main_tid
            .into_iter()
            .chain(self.go_sched.goroutines.keys().copied())
            .filter(|&t| t != cur)
            .filter(|t| !self.go_sched.blocked.contains_key(t))
            .filter(|t| {
                tm.threads
                    .get(t)
                    .is_some_and(|th| matches!(th.status, ThreadStatus::Ready))
            })
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }

    /// Force the oldest waiter through when nothing can run. `WaitGroup`
    /// waiters go first: their counter is the usual unmodelled wake-up.
    fn go_force_wake(&mut self) -> Option<u64> {
        if self.go_sched.main_returned {
            return None;
        }
        let pick = |want_wg: bool| {
            self.go_sched
                .blocked
                .iter()
                .filter(|(_, (r, _))| match r {
                    BlockReason::WaitGroup(_) => want_wg,
                    BlockReason::ChanRecv(_) => !want_wg,
                    BlockReason::MainReturned => false,
                })
                .min_by_key(|(_, (_, seq))| *seq)
                .map(|(&tid, &(r, _))| (tid, r))
        };
        let (tid, reason) = pick(true).or_else(|| pick(false))?;
        let label = goroutine_label(tid, self.go_sched.goid_of(tid));
        let msg = format!(
            "{label}: {} forced through (no runnable goroutine)",
            reason.describe()
        );
        tprintln!("[SCHED] {}", msg);
        self.go_sched.forced_wakes.push(msg);
        self.go_wake(tid);
        self.go_sched.forced.insert(tid);
        Some(tid)
    }

    /// Pick the next context after the current one blocked, exited or
    /// yielded. `resume_rip` is where the current context resumes.
    fn go_schedule_next(&mut self, resume_rip: u64) -> SchedAction {
        let cur = self.go_current_tid();
        self.go_refresh_blocked();
        let mut candidates = self.go_runnable_except(cur);
        let cur_runnable = !self.go_sched.blocked.contains_key(&cur)
            && !self
                .go_sched
                .goroutines
                .get(&cur)
                .is_some_and(|g| g.end.is_some());
        if candidates.is_empty() {
            if cur_runnable {
                return SchedAction::Continue;
            }
            match self.go_force_wake() {
                Some(t) if t == cur => return SchedAction::Continue,
                Some(t) => candidates.push(t),
                None => return SchedAction::Stop,
            }
        }
        if self.go_sched.switches >= self.go_sched.max_switches {
            self.go_sched.budget_exhausted = true;
            if cur_runnable {
                return SchedAction::Continue;
            }
            tprintln!(
                "[SCHED] Switch budget ({}) exhausted; stopping the schedule",
                self.go_sched.max_switches
            );
            return SchedAction::Stop;
        }
        let next = match self.go_sched.policy {
            SchedulePolicy::RoundRobin => candidates
                .iter()
                .copied()
                .find(|&t| t > cur)
                .unwrap_or(candidates[0]),
            SchedulePolicy::Random => {
                let i = (self.go_sched.next_rand() % candidates.len() as u64) as usize;
                candidates[i]
            }
        };
        match self.go_switch(resume_rip, next) {
            Some(rip) => SchedAction::Jump(rip),
            None => SchedAction::Stop,
        }
    }

    /// Save the current context (resuming at `resume_rip`) and load `next`.
    fn go_switch(&mut self, resume_rip: u64, next: u64) -> Option<u64> {
        {
            let mut tm = self.state.thread_manager.lock().unwrap();
            let cur = tm.current_tid;
            if cur == next {
                return Some(resume_rip);
            }
            let exited = tm
                .threads
                .get(&cur)
                .is_some_and(|t| matches!(t.status, ThreadStatus::Exited(_)));
            if !exited {
                let mut cpu = self.state.cpu_state.lock().unwrap();
                let rip_cv = ConcolicVar::new_concrete_and_symbolic_int(
                    resume_rip,
                    BV::from_u64(self.context, resume_rip, 64),
                    self.context,
                );
                let _ = cpu.set_register_value_by_offset(RIP, rip_cv, 64);
                let snap = cpu.clone();
                drop(cpu);
                if let Some(t) = tm.threads.get_mut(&cur) {
                    t.cpu_state = snap;
                }
            }
            tm.switch_to_thread(next).ok()?;
            let new_cpu = tm.threads.get(&next)?.cpu_state.clone();
            *self.state.cpu_state.lock().unwrap() = new_cpu;
        }
        self.clear_goid_cache();
        self.go_sched.switches += 1;
        let goid = self.go_sched.goid_of(next);
        self.go_sched.trace.push((next, goid));
        self.go_sched.last_pc = (u64::MAX, 0);
        Some(self.read_reg64(RIP))
    }

    /// Let another runnable goroutine run; the current one stays runnable.
    fn go_yield(&mut self, rip: u64) -> SchedAction {
        let cur = self.go_current_tid();
        self.go_refresh_blocked();
        let candidates = self.go_runnable_except(cur);
        if candidates.is_empty() || self.go_sched.switches >= self.go_sched.max_switches {
            return SchedAction::Continue;
        }
        let i = (self.go_sched.next_rand() % candidates.len() as u64) as usize;
        match self.go_switch(rip, candidates[i]) {
            Some(r) => SchedAction::Jump(r),
            None => SchedAction::Continue,
        }
    }

    /// Retire the running goroutine: run its pending defers, then exit.
    fn go_retire_current(&mut self, reason: String) -> SchedAction {
        let tid = self.go_current_tid();
        tprintln!(
            "[SCHED] {} {}",
            goroutine_label(tid, self.go_sched.goid_of(tid)),
            reason
        );
        self.go_sched.exiting.insert(tid, reason);
        self.go_continue_exit(tid)
    }

    /// Run the next pending defer of an exiting goroutine (returning to the
    /// exit sentinel), or finish the exit when none is left.
    fn go_continue_exit(&mut self, tid: u64) -> SchedAction {
        if let Some((_, fnval)) = self.go_sched.defers.get_mut(&tid).and_then(|l| l.pop()) {
            if let Some(entry) = self.go_call_deferred(fnval, THREAD_EXIT_SENTINEL) {
                return SchedAction::Jump(entry);
            }
        }
        let reason = self
            .go_sched
            .exiting
            .remove(&tid)
            .unwrap_or_else(|| "returned".to_string());
        self.go_exit_current(reason)
    }

    /// Mark the running goroutine exited and switch to the next context.
    fn go_exit_current(&mut self, reason: String) -> SchedAction {
        let tid = self.go_current_tid();
        if let Some(meta) = self.go_sched.goroutines.get_mut(&tid) {
            meta.end = Some(reason);
        }
        self.go_sched.defers.remove(&tid);
        self.go_sched.loop_counts.retain(|&(t, _), _| t != tid);
        self.dispatch_event(&Event::ThreadExit { tid, code: 0 });
        {
            let mut tm = self.state.thread_manager.lock().unwrap();
            let _ = tm.exit_thread(tid, 0);
            tm.wake_joiners_of(tid);
        }
        self.go_schedule_next(THREAD_EXIT_SENTINEL)
    }

    /// The running goroutine reached the exit sentinel. `None` when the
    /// context is not a goroutine of this model.
    pub fn go_sched_on_goroutine_return(&mut self) -> Option<SchedAction> {
        if !self.go_sched.enabled {
            return None;
        }
        let tid = self.go_current_tid();
        if !self.go_sched.goroutines.contains_key(&tid) {
            return None;
        }
        Some(self.go_continue_exit(tid))
    }

    /// An instruction failed. A goroutine is retired instead of ending the
    /// run; `None` for the main goroutine and unmanaged contexts.
    pub fn go_sched_on_error(&mut self, error: &str) -> Option<SchedAction> {
        if !self.go_sched.enabled {
            return None;
        }
        let tid = self.go_current_tid();
        let meta = self.go_sched.goroutines.get(&tid)?;
        if meta.end.is_some() {
            return None;
        }
        let first_line = error.lines().next().unwrap_or(error);
        let reason = format!("error: {first_line}");
        tprintln!(
            "[SCHED] {} stopped: {}",
            goroutine_label(tid, meta.goid),
            reason
        );
        self.go_sched.exiting.remove(&tid);
        Some(self.go_exit_current(reason))
    }

    /// `main.main` returned. Keep running goroutines until none is runnable.
    pub fn go_sched_on_main_return(&mut self, rip: u64) -> SchedAction {
        self.go_sched.main_returned = true;
        if !self.go_sched.enabled {
            return SchedAction::Stop;
        }
        let tid = self.go_current_tid();
        self.go_sched.block_seq += 1;
        let seq = self.go_sched.block_seq;
        self.go_sched
            .blocked
            .insert(tid, (BlockReason::MainReturned, seq));
        self.go_set_status(tid, ThreadStatus::Blocked);
        match self.go_schedule_next(rip) {
            SchedAction::Jump(r) => {
                tprintln!("[SCHED] main.main returned; running the remaining goroutines");
                SchedAction::Jump(r)
            }
            _ => SchedAction::Stop,
        }
    }

    /// Return-address chain starting at `pc`, following saved frame
    /// pointers (Go and `-fno-omit-frame-pointer` C keep RBP chains).
    pub fn go_stack_walk(&self, pc: u64) -> Vec<u64> {
        let mut out = vec![pc];
        let mut rbp = self.read_reg64(RBP);
        let stack_lo = self.read_reg64(RSP);
        while out.len() < MAX_STACK_FRAMES && rbp >= stack_lo && rbp != 0 {
            let Some(ret) = self.go_read_u64(rbp.wrapping_add(8)) else {
                break;
            };
            let Some(next) = self.go_read_u64(rbp) else {
                break;
            };
            if ret == 0 || ret == THREAD_EXIT_SENTINEL {
                break;
            }
            out.push(ret);
            if next <= rbp {
                break;
            }
            rbp = next;
        }
        out
    }

    /// Package-level variable whose value is the map header `m`.
    fn go_map_variable(&mut self, m: u64) -> Option<String> {
        if let Some(name) = self.go_sched.map_names.get(&m) {
            return name.clone();
        }
        let name = func_index::get().and_then(|idx| {
            idx.pointer_globals()
                .iter()
                .find(|(addr, _)| self.go_read_u64(*addr) == Some(m))
                .map(|(_, n)| n.clone())
        });
        self.go_sched.map_names.insert(m, name.clone());
        name
    }

    /// Key argument of a map entry point, rendered when passed by value.
    fn go_map_key(&self, callee: &str) -> Option<String> {
        let base = callee.strip_suffix(".abi0").unwrap_or(callee);
        if base.ends_with("_faststr") {
            let ptr = self.read_reg64(RCX);
            let len = self.read_reg64(RDI);
            if ptr == 0 || len > MAX_KEY_BYTES {
                return None;
            }
            let bytes = self.state.memory.read_bytes(ptr, len as usize).ok()?;
            render_key(&bytes)
        } else if base.ends_with("_fast32") {
            Some((self.read_reg64(RCX) as u32).to_string())
        } else if base.ends_with("_fast64") {
            Some(self.read_reg64(RCX).to_string())
        } else {
            None
        }
    }

    /// Emit a `MapAccess` for a call from application code to a runtime map
    /// entry point.
    pub fn go_maybe_emit_map_access(&mut self, pc: u64, callee: &str, tid: u64) {
        if !self.go_sched.enabled || !self.event_bus.is_subscribed(EventKind::MapAccess) {
            return;
        }
        let Some(op) = MapOp::from_runtime_symbol(callee) else {
            return;
        };
        if self.classify_pc(pc).map_internal {
            return;
        }
        let map = self.read_reg64(RBX);
        if map == 0 {
            return;
        }
        let key = self.go_map_key(callee);
        let variable = self.go_map_variable(map);
        let stack = self.go_stack_walk(pc);
        self.dispatch_event_with_stack(
            &Event::MapAccess {
                map,
                op,
                pc,
                tid,
                callee,
                key: key.as_deref(),
                variable: variable.as_deref(),
            },
            &stack,
        );
    }

    /// Whether raw accesses at the current PC belong to the map
    /// implementation and are covered by `MapAccess` instead.
    pub fn go_is_map_internal_access(&mut self) -> bool {
        if !self.go_sched.enabled
            || !self.event_bus.is_subscribed(EventKind::MapAccess)
            || std::env::var("ZORYA_VOLOS_MAP_INTERNALS").is_ok_and(|v| v == "1")
        {
            return false;
        }
        let pc = self.current_address.unwrap_or(0);
        self.classify_pc(pc).map_internal
    }

    /// Address of a `go` statement (`CALL runtime.newproc`) reachable from
    /// `start` in the control-flow graph of the function containing it,
    /// stepping over calls. Over-approximates: later branches on the way
    /// are not checked, the next round's run confirms the candidate.
    pub fn go_static_spawn_site(
        &self,
        start: u64,
        instructions_map: &BTreeMap<u64, Vec<Inst>>,
    ) -> Option<u64> {
        let (lo, hi, _) = func_index::get()?.function_at(start)?;
        let newproc = self
            .symbol_table
            .iter()
            .find(|(_, name)| name.as_str() == "runtime.newproc")
            .and_then(|(addr, _)| u64::from_str_radix(addr, 16).ok())?;
        let mut seen: HashSet<u64> = HashSet::new();
        let mut work = vec![start];
        while let Some(addr) = work.pop() {
            if addr < lo || addr >= hi || seen.len() >= MAX_STATIC_SPAWN_INSTRUCTIONS {
                continue;
            }
            if !seen.insert(addr) {
                continue;
            }
            let Some(insts) = instructions_map.get(&addr) else {
                continue;
            };
            let mut falls_through = true;
            for inst in insts {
                let target = match inst.inputs.first().map(|v| &v.var) {
                    Some(Var::Memory(t)) => Some(*t),
                    _ => None,
                };
                match inst.opcode {
                    Opcode::Call if target == Some(newproc) => return Some(addr),
                    // The stack-growth tail jumps back to the function entry,
                    // which would make every block reach every `go` statement.
                    Opcode::Call
                        if target
                            .and_then(|t| self.symbol_table.get(&format!("{t:x}")))
                            .is_some_and(|s| s.starts_with("runtime.morestack")) =>
                    {
                        falls_through = false;
                        break;
                    }
                    Opcode::Branch => {
                        if let Some(t) = target {
                            work.push(t);
                            falls_through = false;
                        }
                    }
                    Opcode::CBranch => work.extend(target),
                    Opcode::Return | Opcode::BranchInd => falls_through = false,
                    _ => {}
                }
            }
            if falls_through {
                if let Some((&next, _)) = instructions_map.range(addr + 1..).next() {
                    work.push(next);
                }
            }
        }
        None
    }

    /// Negated branches that create goroutines are solved into candidate
    /// seeds: a concurrency analysis was selected, or Volos is loaded.
    pub fn go_records_spawn_candidates(&self) -> bool {
        self.go_sched.enabled
            && (crate::state::analysis::explores_inputs()
                || self.event_bus.is_subscribed(EventKind::MapAccess))
    }

    /// Record a candidate seed for a negated branch whose overlay reached
    /// the `go` statement at `spawn_pc`.
    pub fn go_overlay_spawn_candidate(&self, branch_pc: u64, spawn_pc: u64, phi: &[Bool<'ctx>]) {
        let parts: Vec<&Bool<'ctx>> = phi.iter().collect();
        let reason =
            format!("the negated branch reaches runtime.newproc (go statement at 0x{spawn_pc:x})");
        race_report::record_spawn_candidate(self.context, &parts, branch_pc, reason, true);
    }

    /// Record a candidate seed for a negated branch whose overlay stopped
    /// before reaching a `go` statement that is statically reachable. The
    /// statement must be unreachable from the side the run took, so a
    /// branch whose sides rejoin first (Go materialises `a || b` into a
    /// boolean tested by a later branch) is not reported as the gate.
    pub fn go_static_spawn_candidate(
        &self,
        branch_pc: u64,
        untaken: u64,
        phi: &[Bool<'ctx>],
        instructions_map: &BTreeMap<u64, Vec<Inst>>,
    ) {
        if !self.go_records_spawn_candidates() {
            return;
        }
        let Some(site) = self.go_static_spawn_site(untaken, instructions_map) else {
            return;
        };
        if let Some(taken) = other_successor(branch_pc, untaken, instructions_map) {
            if self.go_static_spawn_site(taken, instructions_map).is_some() {
                return;
            }
        }
        let parts: Vec<&Bool<'ctx>> = phi.iter().collect();
        let reason = format!(
            "the negated branch at 0x{branch_pc:x} leads (statically) to a go statement at 0x{site:x}"
        );
        race_report::record_spawn_candidate(self.context, &parts, branch_pc, reason, false);
    }
}

/// The successor of the conditional branch in the instruction at
/// `branch_pc` that is not `one` (its target or its fall-through).
fn other_successor(
    branch_pc: u64,
    one: u64,
    instructions_map: &BTreeMap<u64, Vec<Inst>>,
) -> Option<u64> {
    let target = instructions_map
        .get(&branch_pc)?
        .iter()
        .rev()
        .find(|i| i.opcode == Opcode::CBranch)
        .and_then(|i| match i.inputs.first().map(|v| &v.var) {
            Some(Var::Memory(t)) => Some(*t),
            _ => None,
        })?;
    let fallthrough = *instructions_map.range(branch_pc + 1..).next()?.0;
    if one == target {
        Some(fallthrough)
    } else if one == fallthrough {
        Some(target)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_rendering() {
        assert_eq!(render_key(b"message-1").as_deref(), Some("\"message-1\""));
        assert_eq!(render_key(b"a\x01"), None);
        assert_eq!(render_key(&[0xff, 0xfe]), None);
    }

    #[test]
    fn rng_is_reproducible() {
        let mut a = GoSchedState::from_env();
        let mut b = GoSchedState::from_env();
        a.rng = 42;
        b.rng = 42;
        let xs: Vec<u64> = (0..8).map(|_| a.next_rand()).collect();
        let ys: Vec<u64> = (0..8).map(|_| b.next_rand()).collect();
        assert_eq!(xs, ys);
        assert!(xs.windows(2).all(|w| w[0] != w[1]));
    }

    #[test]
    fn schedule_record_lists_blocked_contexts() {
        let mut s = GoSchedState::from_env();
        s.main_tid = Some(1);
        s.main_goid = Some(1);
        s.goroutines.insert(
            7,
            GoroutineMeta {
                tid: 7,
                goid: Some(1001),
                parent_tid: 1,
                host_os_tid: Some(1),
                entry: 0x1000,
                spawn_pc: 0x2000,
                end: None,
                instructions: 10,
            },
        );
        s.blocked.insert(7, (BlockReason::ChanRecv(0xc000), 1));
        s.blocked.insert(1, (BlockReason::MainReturned, 2));
        let rec = s.schedule_record();
        assert_eq!(rec.blocked_at_end.len(), 1);
        assert_eq!(rec.blocked_at_end[0].1, Some(1001));
        assert!(rec.blocked_at_end[0].2.contains("channel receive"));
        assert_eq!(s.goroutine_records()[0].spawn_pc, 0x2000);
    }
}
