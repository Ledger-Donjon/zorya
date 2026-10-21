// SPDX-FileCopyrightText: 2026 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

//! `results/race_summary.json`: one machine-readable answer per run to "is
//! there an input-gated data race, under which input, on which schedule?".
//!
//! The race detector (volos) records its witness pairs, input gates and
//! solver models here; the executor records the goroutines it created, the
//! schedule it ran and how the run ended; the toolchain check records the Go
//! version and standard-library advisories. [`write_summary`] merges them,
//! resolves PCs to functions and source lines, decodes solver models back
//! into argv strings (the seed with the constrained bytes replaced), picks a
//! status and, when no race was reached, proposes the next seed to try.
//!
//! Statuses:
//!
//! * `race_found` — a race was reported.
//! * `stdlib_fixed` — the racy code is in a standard-library package whose
//!   fix the build toolchain already contains.
//! * `gate_not_reached` — the explored path did not create the goroutines
//!   the race needs, but a negated branch does; `next_seed` reaches it.
//! * `gate_reached_schedule_not_explored` — goroutines ran, but some never
//!   finished (still blocked, budget or timeout), so not every interleaving
//!   the race needs was executed.
//! * `race_reached_not_reported` — application-level conflicting accesses
//!   were observed but discarded as ordered or lock-protected while the run
//!   relied on approximations (forced wake-ups, goroutines that crashed in
//!   unmodelled runtime code).
//! * `no_concurrency` — no goroutine was created and no explored branch
//!   creates one.
//! * `no_race` — goroutines ran to completion and every conflicting access
//!   was ordered or protected.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Mutex;

use serde_json::{json, Value};
use z3::ast::{Ast, Bool, Dynamic, BV};
use z3::DeclKind;

use crate::state::func_index;
use crate::state::go_version::AdvisoryStatus;

pub const RACE_SUMMARY_JSON: &str = "results/race_summary.json";

/// Solver model restricted to argv bytes: `("arg2_byte_0", 0x32)`.
pub type Assignment = Vec<(String, u64)>;

/// One side of a race witness.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RaceAccess {
    /// `read` or `write`.
    pub kind: &'static str,
    /// Source-level operation (`map read`, `map write`, `map delete`, ...)
    /// for map-level accesses.
    pub operation: Option<String>,
    pub pc: u64,
    pub tid: u64,
    pub goid: Option<u64>,
    pub locks: Vec<u64>,
    /// Return-address chain, innermost first (starts with `pc`).
    pub stack: Vec<u64>,
    /// Map header pointer for map-level accesses.
    pub map: Option<u64>,
    /// Package-level variable holding the map, when one does.
    pub map_name: Option<String>,
    pub key: Option<String>,
    /// Runtime entry point of a map-level access.
    pub callee: Option<String>,
}

/// A race witness pair with its input coupling.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RaceEntry {
    pub rule: String,
    pub addr: u64,
    pub reason: String,
    /// `unconditional`, `input-independent`, `input-dependent`,
    /// `reachable`, `infeasible` or `unknown`.
    pub input_class: String,
    pub gate_smt: Option<String>,
    pub gate: Option<String>,
    pub trigger: Option<Assignment>,
    pub escape: Option<Assignment>,
    pub accesses: Vec<RaceAccess>,
    pub map_level: bool,
}

/// An input under which a negated branch creates a goroutine the explored
/// path did not.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct GateCandidate {
    pub reason: String,
    pub branch_pc: u64,
    pub gate_smt: String,
    pub gate: String,
    pub assignment: Assignment,
    /// The overlay executed up to `runtime.newproc`; otherwise the `go`
    /// statement is only statically reachable from the negated branch.
    pub executed: bool,
}

/// Race-detector counters used to pick the status.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DetectorStats {
    pub reads: u64,
    pub writes: u64,
    pub map_ops: u64,
    pub lock_ops: u64,
    /// Cross-goroutine pairs with a write on a common cell.
    pub conflicting_pairs: u64,
    /// Of those, pairs where both sides are application code or map-level.
    pub app_conflicting_pairs: u64,
    pub hb_ordered: u64,
    pub lock_protected: u64,
    pub app_hb_ordered: u64,
    pub app_lock_protected: u64,
    /// Pairs dropped because both sides execute Go runtime internals.
    pub runtime_internal_filtered: u64,
    pub reported_pairs: u64,
}

/// A goroutine the scheduler created.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct GoroutineRecord {
    pub tid: u64,
    pub goid: Option<u64>,
    pub parent_tid: u64,
    pub host_os_tid: Option<u64>,
    pub entry: u64,
    pub spawn_pc: u64,
    /// How the goroutine ended (`returned`, `retired: ...`, `error: ...`),
    /// or `None` while still runnable / blocked.
    pub end: Option<String>,
    pub instructions: u64,
}

/// What the goroutine scheduler did.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ScheduleRecord {
    pub enabled: bool,
    pub policy: String,
    pub seed: Option<u64>,
    pub max_switches: usize,
    pub max_loop_iterations: usize,
    pub max_goroutines_per_site: usize,
    pub max_goroutine_instructions: usize,
    pub switches: usize,
    /// Context switched to, in order: `(tid, goid)`.
    pub trace: Vec<(u64, Option<u64>)>,
    pub forced_wakes: Vec<String>,
    pub skipped_spawns: usize,
    pub budget_exhausted: bool,
    pub main_returned: bool,
    /// Contexts still blocked when the run ended: `(tid, goid, reason)`.
    pub blocked_at_end: Vec<(u64, Option<u64>, String)>,
    pub main_tid: u64,
    pub main_goid: Option<u64>,
}

/// Everything the summary is built from.
#[derive(Debug, Default)]
pub struct RaceStore {
    pub detector_active: bool,
    pub races: Vec<RaceEntry>,
    pub candidates: Vec<GateCandidate>,
    pub stats: DetectorStats,
    pub goroutines: Vec<GoroutineRecord>,
    pub schedule: ScheduleRecord,
    /// argv of the run, including argv[0].
    pub seed_args: Vec<String>,
    pub go_version: Option<String>,
    pub advisories: Vec<AdvisoryStatus>,
    /// Analyses selected with `--analysis`.
    pub analyses: Vec<String>,
    pub binary: String,
}

static STORE: Mutex<Option<RaceStore>> = Mutex::new(None);

/// Run `f` on the process-wide store.
pub fn with_store<R>(f: impl FnOnce(&mut RaceStore) -> R) -> R {
    let mut guard = STORE.lock().unwrap_or_else(|e| e.into_inner());
    f(guard.get_or_insert_with(RaceStore::default))
}

/// `arg2_byte_0` / `arg2_byte_0!17` → `(2, 0)`.
pub fn parse_arg_byte(name: &str) -> Option<(usize, usize)> {
    let name = name.trim_matches('|');
    let rest = name.strip_prefix("arg")?;
    let (i, j) = rest.split_once("_byte_")?;
    let j = j.split('!').next()?;
    Some((i.parse().ok()?, j.parse().ok()?))
}

/// Normalised name of an argv byte constant (`arg2_byte_0`).
pub fn arg_byte_key(i: usize, j: usize) -> String {
    format!("arg{i}_byte_{j}")
}

/// Every distinct argv-byte constant occurring in `parts`.
pub fn collect_arg_bytes<'ctx>(parts: &[&Bool<'ctx>]) -> Vec<BV<'ctx>> {
    const MAX_NODES: usize = 100_000;
    let mut visited: HashSet<Dynamic<'ctx>> = HashSet::new();
    let mut stack: Vec<Dynamic<'ctx>> = parts.iter().map(|b| Dynamic::from_ast(*b)).collect();
    let mut seen_names = HashSet::new();
    let mut out = Vec::new();
    while let Some(node) = stack.pop() {
        if visited.len() >= MAX_NODES || !visited.insert(node.clone()) {
            continue;
        }
        if node.is_const() {
            let name = node.decl().name();
            if parse_arg_byte(&name).is_some() && seen_names.insert(name) {
                if let Some(bv) = node.as_bv() {
                    out.push(bv);
                }
            }
        } else if node.is_app() {
            stack.extend(node.children());
        }
    }
    out
}

/// Inclusive argv byte range of the `ARG_ASCII_PROFILE`, if any.
fn arg_byte_bounds() -> Option<(u64, u64)> {
    let profile = std::env::var("ARG_ASCII_PROFILE")
        .ok()
        .or_else(|| crate::state::analysis::explores_inputs().then(|| "printable".to_string()))
        .unwrap_or_default()
        .to_lowercase();
    match profile.as_str() {
        "digits" => Some((b'0' as u64, b'9' as u64)),
        "printable" => Some((32, 126)),
        _ => None,
    }
}

/// The gate as one constraint per argv byte, when the bytes are constrained
/// independently: `argv[1][0] == '1' && argv[2][0] in '2'..'9'`. Each byte's
/// allowed values are enumerated under the gate, and the conjunction of
/// those sets is checked to be equivalent to the gate. `None` when the
/// bytes are coupled, there are too many of them, or no byte profile is set.
pub fn compact_condition<'ctx>(ctx: &'ctx z3::Context, parts: &[&Bool<'ctx>]) -> Option<String> {
    static CACHE: Mutex<Option<HashMap<String, Option<String>>>> = Mutex::new(None);
    let key = smt_condition(parts);
    if let Some(hit) = CACHE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get_or_insert_with(HashMap::new)
        .get(&key)
    {
        return hit.clone();
    }
    let text = arg_byte_bounds().and_then(|b| compact_condition_with(ctx, parts, b));
    CACHE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get_or_insert_with(HashMap::new)
        .insert(key, text.clone());
    text
}

fn compact_condition_with<'ctx>(
    ctx: &'ctx z3::Context,
    parts: &[&Bool<'ctx>],
    (lo, hi): (u64, u64),
) -> Option<String> {
    const MAX_BYTES: usize = 8;
    let vars = collect_arg_bytes(parts);
    if vars.is_empty() || vars.len() > MAX_BYTES {
        return None;
    }
    let domain = byte_domain(ctx, parts, (lo, hi));
    let gate = Bool::and(ctx, parts);
    let solver = z3::Solver::new(ctx);
    for d in &domain {
        solver.assert(d);
    }
    solver.assert(&gate);

    let mut texts = Vec::new();
    let mut projection = Vec::new();
    let mut named: Vec<(usize, usize, &BV<'ctx>)> = vars
        .iter()
        .filter_map(|v| parse_arg_byte(&v.decl().name()).map(|(i, j)| (i, j, v)))
        .collect();
    named.sort_by_key(|(i, j, _)| (*i, *j));
    for (i, j, v) in named {
        let w = v.get_size();
        let mut allowed = Vec::new();
        solver.push();
        loop {
            match solver.check() {
                z3::SatResult::Sat => {
                    let value = solver.get_model()?.eval(v, true)?.as_u64()?;
                    allowed.push(value);
                    solver.assert(&v._eq(&BV::from_u64(ctx, value, w)).not());
                }
                z3::SatResult::Unsat => break,
                z3::SatResult::Unknown => {
                    solver.pop(1);
                    return None;
                }
            }
        }
        solver.pop(1);
        allowed.sort_unstable();
        if allowed.is_empty() {
            return None;
        }
        if allowed.len() as u64 == hi - lo + 1 {
            continue;
        }
        let ranges = value_ranges(&allowed);
        let terms: Vec<Bool<'ctx>> = ranges
            .iter()
            .map(|&(a, b)| v.bvuge(&BV::from_u64(ctx, a, w)) & v.bvule(&BV::from_u64(ctx, b, w)))
            .collect();
        projection.push(Bool::or(ctx, &terms.iter().collect::<Vec<_>>()));
        texts.push(render_byte_set(i, j, &allowed, &ranges, lo, hi));
    }
    if texts.is_empty() {
        return None;
    }

    // The projection contains the gate; equivalent iff nothing in it
    // violates the gate.
    let check = z3::Solver::new(ctx);
    for d in &domain {
        check.assert(d);
    }
    for p in &projection {
        check.assert(p);
    }
    check.assert(&gate.not());
    (check.check() == z3::SatResult::Unsat).then(|| texts.join(" && "))
}

/// Sorted values as inclusive `(first, last)` runs.
fn value_ranges(sorted: &[u64]) -> Vec<(u64, u64)> {
    let mut out: Vec<(u64, u64)> = Vec::new();
    for &v in sorted {
        match out.last_mut() {
            Some((_, last)) if *last + 1 == v => *last = v,
            _ => out.push((v, v)),
        }
    }
    out
}

fn byte_literal(v: u64) -> String {
    match v as u8 {
        b'\'' => "'\\''".to_string(),
        b'\\' => "'\\\\'".to_string(),
        b @ 0x20..=0x7e => format!("'{}'", b as char),
        b => format!("0x{b:02x}"),
    }
}

fn render_byte_set(
    i: usize,
    j: usize,
    allowed: &[u64],
    ranges: &[(u64, u64)],
    lo: u64,
    hi: u64,
) -> String {
    let name = format!("argv[{i}][{j}]");
    let excluded: Vec<u64> = (lo..=hi)
        .filter(|v| allowed.binary_search(v).is_err())
        .collect();
    let range = |&(a, b): &(u64, u64)| {
        if a == b {
            byte_literal(a)
        } else {
            format!("{}..{}", byte_literal(a), byte_literal(b))
        }
    };
    if allowed.len() == 1 {
        format!("{name} == {}", byte_literal(allowed[0]))
    } else if excluded.len() <= 2 {
        excluded
            .iter()
            .map(|&v| format!("{name} != {}", byte_literal(v)))
            .collect::<Vec<_>>()
            .join(" && ")
    } else if ranges.len() == 1 {
        format!("{name} in {}", range(&ranges[0]))
    } else {
        let items: Vec<String> = ranges.iter().map(range).collect();
        format!("{name} in {{{}}}", items.join(", "))
    }
}

/// Input-domain constraints for the argv bytes (`argN_byte_M`) that occur in
/// `parts`, following `ARG_ASCII_PROFILE` (`digits` or `printable`) like the
/// engine's own SAT reports, so trigger/escape inputs are replayable.
/// The printable range a concurrency analysis sets by default is only a
/// preference: it is dropped when no printable input satisfies `parts`.
pub fn arg_byte_domain<'ctx>(ctx: &'ctx z3::Context, parts: &[&Bool<'ctx>]) -> Vec<Bool<'ctx>> {
    let domain = raw_arg_byte_domain(ctx, parts);
    if domain.is_empty() || std::env::var("ARG_ASCII_PROFILE").is_ok() {
        return domain;
    }
    let solver = z3::Solver::new(ctx);
    for c in domain.iter().chain(parts.iter().copied()) {
        solver.assert(c);
    }
    if solver.check() == z3::SatResult::Sat {
        domain
    } else {
        Vec::new()
    }
}

fn raw_arg_byte_domain<'ctx>(ctx: &'ctx z3::Context, parts: &[&Bool<'ctx>]) -> Vec<Bool<'ctx>> {
    match arg_byte_bounds() {
        Some(bounds) => byte_domain(ctx, parts, bounds),
        None => Vec::new(),
    }
}

fn byte_domain<'ctx>(
    ctx: &'ctx z3::Context,
    parts: &[&Bool<'ctx>],
    (lo, hi): (u64, u64),
) -> Vec<Bool<'ctx>> {
    collect_arg_bytes(parts)
        .into_iter()
        .map(|bv| {
            let w = bv.get_size();
            bv.bvuge(&BV::from_u64(ctx, lo, w)) & bv.bvule(&BV::from_u64(ctx, hi, w))
        })
        .collect()
}

/// Solve `parts` over the argv bytes and record the model as a candidate
/// seed for a negated branch at `branch_pc` that creates goroutines.
pub fn record_spawn_candidate<'ctx>(
    ctx: &'ctx z3::Context,
    parts: &[&Bool<'ctx>],
    branch_pc: u64,
    reason: String,
    executed: bool,
) -> Option<GateCandidate> {
    let vars = collect_arg_bytes(parts);
    if vars.is_empty() {
        return None;
    }
    crate::state::run_status::enter_subphase("smt_solving");
    let solved = solve_relaxing_prefix(ctx, parts);
    crate::state::run_status::leave_subphase();
    let (model, kept, relaxed) = solved?;
    let reason = if relaxed == 0 {
        reason
    } else {
        format!("{reason}, after dropping {relaxed} earlier branch(es) that contradict it")
    };
    let candidate = GateCandidate {
        reason,
        branch_pc,
        gate_smt: smt_condition(&kept),
        gate: compact_condition(ctx, &kept).unwrap_or_else(|| pretty_condition(&kept)),
        assignment: model_assignment(&model, &vars),
        executed,
    };
    with_store(|s| {
        if !s
            .candidates
            .iter()
            .any(|c| c.assignment == candidate.assignment)
        {
            s.candidates.push(candidate.clone());
        }
    });
    Some(candidate)
}

/// Solve `parts`, whose last element is the negated branch. When earlier
/// path branches contradict it, they are dropped (those in the unsat core,
/// repeatedly), like a generational search that flips an earlier branch
/// instead: Go evaluates `a || b` by branching on `a` first, and the later
/// test of the combined boolean only sees `a` on the explored path. Returns
/// the model, the conjuncts kept and how many were dropped.
fn solve_relaxing_prefix<'ctx, 'p>(
    ctx: &'ctx z3::Context,
    parts: &[&'p Bool<'ctx>],
) -> Option<(z3::Model<'ctx>, Vec<&'p Bool<'ctx>>, usize)> {
    let domain = raw_arg_byte_domain(ctx, parts);
    solve_relaxing_prefix_in(ctx, parts, &domain).or_else(|| {
        let default_domain = !domain.is_empty() && std::env::var("ARG_ASCII_PROFILE").is_err();
        default_domain
            .then(|| solve_relaxing_prefix_in(ctx, parts, &[]))
            .flatten()
    })
}

fn solve_relaxing_prefix_in<'ctx, 'p>(
    ctx: &'ctx z3::Context,
    parts: &[&'p Bool<'ctx>],
    domain: &[Bool<'ctx>],
) -> Option<(z3::Model<'ctx>, Vec<&'p Bool<'ctx>>, usize)> {
    const MAX_ROUNDS: usize = 8;
    let (negated, prefix) = parts.split_last()?;
    let solver = z3::Solver::new(ctx);
    for d in domain {
        solver.assert(d);
    }
    solver.assert(negated);
    let flags: Vec<Bool<'ctx>> = (0..prefix.len())
        .map(|i| Bool::new_const(ctx, format!("zorya_prefix_{i}")))
        .collect();
    for (flag, p) in flags.iter().zip(prefix) {
        solver.assert(&flag.implies(p));
    }
    let mut active: Vec<usize> = (0..prefix.len()).collect();
    for _ in 0..MAX_ROUNDS {
        let assumptions: Vec<Bool<'ctx>> = active.iter().map(|&i| flags[i].clone()).collect();
        match solver.check_assumptions(&assumptions) {
            z3::SatResult::Sat => {
                let mut kept: Vec<&'p Bool<'ctx>> = active.iter().map(|&i| prefix[i]).collect();
                kept.push(*negated);
                return Some((solver.get_model()?, kept, prefix.len() - active.len()));
            }
            z3::SatResult::Unsat => {
                let core = solver.get_unsat_core();
                let before = active.len();
                active.retain(|&i| !core.contains(&flags[i]));
                if active.len() == before {
                    return None;
                }
            }
            z3::SatResult::Unknown => return None,
        }
    }
    None
}

/// Evaluate `vars` in `model`, keyed by normalised argv-byte name.
pub fn model_assignment<'ctx>(model: &z3::Model<'ctx>, vars: &[BV<'ctx>]) -> Assignment {
    let mut out: Assignment = vars
        .iter()
        .filter_map(|v| {
            let (i, j) = parse_arg_byte(&v.decl().name())?;
            let value = model.eval(v, true)?.as_u64()?;
            Some((arg_byte_key(i, j), value))
        })
        .collect();
    out.sort_by_key(|(name, _)| parse_arg_byte(name));
    out.dedup_by(|a, b| a.0 == b.0);
    out
}

/// Apply an assignment to the seed argv and return argv[1..] as strings.
/// Bytes the model does not constrain keep their seed value; non-printable
/// bytes are rendered as `\xNN`.
pub fn decode_argv(seed: &[String], assignment: &[(String, u64)]) -> Vec<String> {
    let mut argv: Vec<Vec<u8>> = seed.iter().map(|s| s.as_bytes().to_vec()).collect();
    for (name, value) in assignment {
        let Some((i, j)) = parse_arg_byte(name) else {
            continue;
        };
        if argv.len() <= i {
            argv.resize(i + 1, Vec::new());
        }
        let arg = &mut argv[i];
        if arg.len() <= j {
            arg.resize(j + 1, b'?');
        }
        arg[j] = *value as u8;
    }
    argv.iter().skip(1).map(|a| render_arg(a)).collect()
}

fn render_arg(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| {
            if (0x20..0x7f).contains(&b) && b != b'\\' {
                (b as char).to_string()
            } else {
                format!("\\x{b:02x}")
            }
        })
        .collect()
}

// ── Gate pretty-printing ────────────────────────────────────────────────────

/// Render a conjunction of path constraints over argv bytes in C-like
/// syntax: `argv[1][0] == '1' && argv[2][0] == '1'`. Duplicate conjuncts are
/// dropped; anything the renderer does not understand falls back to SMT-LIB
/// with argv bytes renamed.
pub fn pretty_condition<'ctx>(parts: &[&Bool<'ctx>]) -> String {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for p in parts {
        let simplified = Dynamic::from_ast(&p.simplify());
        let mut conjuncts = Vec::new();
        flatten_and(&simplified, &mut conjuncts);
        for c in conjuncts {
            let (text, prec) = render(&c);
            if text == "true" {
                continue;
            }
            let text = if prec >= PREC_OR {
                format!("({text})")
            } else {
                text
            };
            if seen.insert(text.clone()) {
                out.push(text);
            }
        }
    }
    if out.is_empty() {
        "true".to_string()
    } else {
        out.join(" && ")
    }
}

/// Raw SMT-LIB form of a conjunction (argv bytes keep their solver names).
pub fn smt_condition<'ctx>(parts: &[&Bool<'ctx>]) -> String {
    parts
        .iter()
        .map(|b| format!("{}", b.simplify()))
        .collect::<Vec<_>>()
        .join(" ∧ ")
}

const PREC_ATOM: u8 = 0;
const PREC_ARITH: u8 = 1;
const PREC_CMP: u8 = 2;
const PREC_AND: u8 = 3;
const PREC_OR: u8 = 4;

fn flatten_and<'ctx>(n: &Dynamic<'ctx>, out: &mut Vec<Dynamic<'ctx>>) {
    if n.is_app() && n.decl().kind() == DeclKind::AND {
        for c in n.children() {
            flatten_and(&c, out);
        }
    } else {
        out.push(n.clone());
    }
}

fn numeral(n: &Dynamic<'_>) -> Option<(u64, u32)> {
    if !n.is_app() || n.num_children() != 0 {
        return None;
    }
    let bv = n.as_bv()?;
    Some((bv.as_u64()?, bv.get_size()))
}

fn is_numeral(n: &Dynamic<'_>) -> bool {
    n.is_app() && n.num_children() == 0 && n.as_bv().and_then(|b| b.as_u64()).is_some()
}

/// The argv byte a term denotes, looking through zero/sign extension.
fn direct_arg_byte(n: &Dynamic<'_>) -> Option<(usize, usize)> {
    if !n.is_app() {
        return None;
    }
    if n.num_children() == 0 {
        return parse_arg_byte(&n.decl().name());
    }
    match n.decl().kind() {
        DeclKind::ZERO_EXT | DeclKind::SIGN_EXT => direct_arg_byte(&n.children()[0]),
        _ => None,
    }
}

fn char_literal(v: u64) -> Option<String> {
    let c = u8::try_from(v).ok()?;
    match c {
        b'\'' => Some("'\\''".into()),
        b'\\' => Some("'\\\\'".into()),
        0x20..=0x7e => Some(format!("'{}'", c as char)),
        _ => None,
    }
}

fn wrap(s: (String, u8), max_prec: u8) -> String {
    if s.1 > max_prec {
        format!("({})", s.0)
    } else {
        s.0
    }
}

fn render_numeral_against(v: u64, width: u32, other: &Dynamic<'_>) -> String {
    if direct_arg_byte(other).is_some() {
        if let Some(c) = char_literal(v) {
            return c;
        }
    }
    signed_or_unsigned(v, width)
}

fn signed_or_unsigned(v: u64, width: u32) -> String {
    if (2..=64).contains(&width) && v >> (width - 1) == 1 && v != 1u64 << (width - 1) {
        let mag = if width == 64 {
            v.wrapping_neg()
        } else {
            (1u64 << width) - v
        };
        if mag < 1 << 16 {
            return format!("-{mag}");
        }
    }
    v.to_string()
}

fn comparison<'ctx>(a: &Dynamic<'ctx>, b: &Dynamic<'ctx>, op: &str) -> (String, u8) {
    let flipped = |op: &str| {
        match op {
            "<" => ">",
            "<=" => ">=",
            ">" => "<",
            ">=" => "<=",
            "<s" => ">s",
            "<=s" => ">=s",
            ">s" => "<s",
            ">=s" => "<=s",
            other => other,
        }
        .to_string()
    };
    let (lhs, rhs, op) = if is_numeral(a) && !is_numeral(b) {
        (b, a, flipped(op))
    } else {
        (a, b, op.to_string())
    };
    let left = wrap(render(lhs), PREC_ARITH);
    let right = match numeral(rhs) {
        Some((v, w)) => render_numeral_against(v, w, lhs),
        None => wrap(render(rhs), PREC_ARITH),
    };
    let op = op.trim_end_matches('s');
    (format!("{left} {op} {right}"), PREC_CMP)
}

fn negated_comparison<'ctx>(c: &Dynamic<'ctx>) -> Option<(String, u8)> {
    if !c.is_app() {
        return None;
    }
    let ch = c.children();
    let op = match c.decl().kind() {
        DeclKind::EQ if ch.len() == 2 => "!=",
        DeclKind::DISTINCT if ch.len() == 2 => "==",
        DeclKind::ULEQ => ">",
        DeclKind::ULT => ">=",
        DeclKind::UGEQ => "<",
        DeclKind::UGT => "<=",
        DeclKind::SLEQ => ">s",
        DeclKind::SLT => ">=s",
        DeclKind::SGEQ => "<s",
        DeclKind::SGT => "<=s",
        DeclKind::NOT => return Some(render(&ch[0])),
        _ => return None,
    };
    if ch.len() != 2 || ch[0].as_bool().is_some() {
        return None;
    }
    Some(comparison(&ch[0], &ch[1], op))
}

fn smt_fallback(n: &Dynamic<'_>) -> (String, u8) {
    static RE: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
        regex::Regex::new(r"\|?arg(\d+)_byte_(\d+)(?:![0-9]+)?\|?").unwrap()
    });
    let s = format!("{n}");
    (RE.replace_all(&s, "argv[$1][$2]").into_owned(), PREC_ATOM)
}

fn binop<'ctx>(ch: &[Dynamic<'ctx>], op: &str) -> (String, u8) {
    let parts: Vec<String> = ch.iter().map(|c| wrap(render(c), PREC_ATOM)).collect();
    (parts.join(&format!(" {op} ")), PREC_ARITH)
}

fn render(n: &Dynamic<'_>) -> (String, u8) {
    if !n.is_app() {
        return smt_fallback(n);
    }
    let ch = n.children();
    if ch.is_empty() {
        if let Some(b) = n.as_bool().and_then(|b| b.as_bool()) {
            return (b.to_string(), PREC_ATOM);
        }
        if let Some((v, w)) = numeral(n) {
            return (signed_or_unsigned(v, w), PREC_ATOM);
        }
        let name = n.decl().name();
        if let Some((i, j)) = parse_arg_byte(&name) {
            return (format!("argv[{i}][{j}]"), PREC_ATOM);
        }
        return (name, PREC_ATOM);
    }
    let join = |sep: &str, prec: u8| {
        let parts: Vec<String> = ch.iter().map(|c| wrap(render(c), prec - 1)).collect();
        (parts.join(sep), prec)
    };
    match n.decl().kind() {
        DeclKind::AND => join(" && ", PREC_AND),
        DeclKind::OR => join(" || ", PREC_OR),
        DeclKind::NOT => negated_comparison(&ch[0])
            .unwrap_or_else(|| (format!("!{}", wrap(render(&ch[0]), PREC_ATOM)), PREC_ATOM)),
        DeclKind::EQ if ch.len() == 2 && ch[0].as_bool().is_none() => {
            comparison(&ch[0], &ch[1], "==")
        }
        DeclKind::DISTINCT if ch.len() == 2 => comparison(&ch[0], &ch[1], "!="),
        DeclKind::ULEQ => comparison(&ch[0], &ch[1], "<="),
        DeclKind::ULT => comparison(&ch[0], &ch[1], "<"),
        DeclKind::UGEQ => comparison(&ch[0], &ch[1], ">="),
        DeclKind::UGT => comparison(&ch[0], &ch[1], ">"),
        DeclKind::SLEQ => comparison(&ch[0], &ch[1], "<=s"),
        DeclKind::SLT => comparison(&ch[0], &ch[1], "<s"),
        DeclKind::SGEQ => comparison(&ch[0], &ch[1], ">=s"),
        DeclKind::SGT => comparison(&ch[0], &ch[1], ">s"),
        DeclKind::BADD => {
            // Render `x + c` with a "negative" constant as `x - |c|`; Z3
            // puts constants first, so move them behind the variables.
            let mut terms: Vec<&Dynamic<'_>> = ch.iter().filter(|c| !is_numeral(c)).collect();
            terms.extend(ch.iter().filter(|c| is_numeral(c)));
            let mut out = String::new();
            for (i, c) in terms.into_iter().enumerate() {
                let term = match numeral(c) {
                    Some((v, w)) if i > 0 => {
                        let s = signed_or_unsigned(v, w);
                        match s.strip_prefix('-') {
                            Some(mag) => {
                                out.push_str(" - ");
                                out.push_str(mag);
                                continue;
                            }
                            None => s,
                        }
                    }
                    _ => wrap(render(c), PREC_ATOM),
                };
                if i > 0 {
                    out.push_str(" + ");
                }
                out.push_str(&term);
            }
            (out, PREC_ARITH)
        }
        DeclKind::BSUB => binop(&ch, "-"),
        DeclKind::BMUL => binop(&ch, "*"),
        DeclKind::BUDIV | DeclKind::BUDIV_I | DeclKind::BSDIV | DeclKind::BSDIV_I => {
            binop(&ch, "/")
        }
        DeclKind::BUREM | DeclKind::BUREM_I | DeclKind::BSREM | DeclKind::BSREM_I => {
            binop(&ch, "%")
        }
        DeclKind::BAND => binop(&ch, "&"),
        DeclKind::BOR => binop(&ch, "|"),
        DeclKind::BXOR => binop(&ch, "^"),
        DeclKind::BSHL => binop(&ch, "<<"),
        DeclKind::BLSHR | DeclKind::BASHR => binop(&ch, ">>"),
        DeclKind::BNEG => (format!("-{}", wrap(render(&ch[0]), PREC_ATOM)), PREC_ATOM),
        DeclKind::BNOT => (format!("~{}", wrap(render(&ch[0]), PREC_ATOM)), PREC_ATOM),
        DeclKind::ZERO_EXT | DeclKind::SIGN_EXT => render(&ch[0]),
        DeclKind::CONCAT => {
            let (last, high) = ch.split_last().expect("concat has children");
            if high.iter().all(|h| numeral(h).is_some_and(|(v, _)| v == 0)) {
                render(last)
            } else {
                smt_fallback(n)
            }
        }
        DeclKind::EXTRACT => {
            let child = &ch[0];
            let text = format!("{n}");
            let bounds = text
                .strip_prefix("((_ extract ")
                .and_then(|rest| rest.split(')').next())
                .and_then(|b| {
                    let mut it = b.split_whitespace().map(|x| x.parse::<u32>().ok());
                    Some((it.next()??, it.next()??))
                });
            let child_width = child.as_bv().map(|b| b.get_size()).unwrap_or(0);
            match bounds {
                Some((hi, 0)) if hi + 1 >= child_width => render(child),
                Some((_, 0)) if direct_arg_byte(child).is_some() => render(child),
                Some((hi, lo)) => (
                    format!("{}[{hi}:{lo}]", wrap(render(child), PREC_ATOM)),
                    PREC_ATOM,
                ),
                None => smt_fallback(n),
            }
        }
        DeclKind::ITE => (
            format!(
                "({} ? {} : {})",
                render(&ch[0]).0,
                render(&ch[1]).0,
                render(&ch[2]).0
            ),
            PREC_ATOM,
        ),
        _ => smt_fallback(n),
    }
}

// ── Summary ─────────────────────────────────────────────────────────────────

fn hex(v: u64) -> String {
    format!("0x{v:x}")
}

/// `g<goid>`, or `t<tid>` when the goroutine id is unknown.
pub fn goroutine_label(tid: u64, goid: Option<u64>) -> String {
    match goid {
        Some(g) => format!("g{g}"),
        None => format!("t{tid}"),
    }
}

/// Collapse consecutive duplicates and cap the length of a schedule trace.
pub fn schedule_string(trace: &[(u64, Option<u64>)], max_len: usize) -> String {
    let mut labels: Vec<String> = Vec::new();
    for &(tid, goid) in trace {
        let l = goroutine_label(tid, goid);
        if labels.last() != Some(&l) {
            labels.push(l);
        }
    }
    if labels.len() > max_len {
        let tail = labels.len() - max_len;
        labels.truncate(max_len);
        labels.push(format!("... ({tail} more)"));
    }
    labels.join(" -> ")
}

fn access_score(a: &RaceAccess) -> u32 {
    let app = func_index::function_name_at(a.pc).is_some_and(func_index::is_application_function);
    u32::from(a.map.is_some()) * 2 + u32::from(app)
}

fn race_score(r: &RaceEntry) -> u32 {
    let class = match r.input_class.as_str() {
        "input-dependent" => 3,
        "reachable" => 2,
        "unconditional" | "input-independent" => 1,
        _ => 0,
    };
    r.accesses.iter().map(access_score).sum::<u32>() * 4 + class
}

/// Collapse witness pairs that differ only by byte offset or by which
/// goroutine instances raced: one entry per (access PCs, kinds) pair.
pub fn dedup_races(races: &[RaceEntry]) -> Vec<RaceEntry> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for r in races {
        let mut sides: Vec<(u64, &str)> = r.accesses.iter().map(|a| (a.pc, a.kind)).collect();
        sides.sort();
        if seen.insert((sides, r.map_level)) {
            out.push(r.clone());
        }
    }
    out.sort_by_key(|r| std::cmp::Reverse(race_score(r)));
    out
}

/// Pick a status for a run that reported no race (see the module docs).
fn no_race_status(st: &RaceStore) -> (&'static str, String) {
    if let Some(adv) = st
        .advisories
        .iter()
        .find(|a| a.status == "fixed_in_toolchain")
    {
        return ("stdlib_fixed", adv.message.clone());
    }
    let started = st.goroutines.len();
    let errors: Vec<&GoroutineRecord> = st
        .goroutines
        .iter()
        .filter(|g| g.end.as_deref().is_some_and(|e| e.starts_with("error")))
        .collect();
    if started == 0 {
        if st.candidates.is_empty() {
            return (
                "no_concurrency",
                "no goroutine was created on the explored path and no negated branch leads to \
                 one"
                .into(),
            );
        }
        return (
            "gate_not_reached",
            "no goroutine was created on the explored path; a negated branch reaches \
             runtime.newproc (see candidate_seeds / next_seed)"
                .into(),
        );
    }
    let s = &st.stats;
    let approximated = !st.schedule.forced_wakes.is_empty() || !errors.is_empty();
    if s.app_conflicting_pairs > 0 && approximated {
        return (
            "race_reached_not_reported",
            format!(
                "{} application-level conflicting access pair(s) were observed but discarded \
                 ({} ordered by happens-before, {} lock-protected) while the run relied on \
                 approximations ({} forced wake-up(s), {} goroutine(s) stopped by an \
                 execution error)",
                s.app_conflicting_pairs,
                s.app_hb_ordered,
                s.app_lock_protected,
                st.schedule.forced_wakes.len(),
                errors.len()
            ),
        );
    }
    let unfinished = st.goroutines.iter().filter(|g| g.end.is_none()).count();
    let truncated = st.schedule.budget_exhausted
        || !st.schedule.blocked_at_end.is_empty()
        || unfinished > 0
        || !errors.is_empty();
    if truncated {
        return (
            "gate_reached_schedule_not_explored",
            format!(
                "{started} goroutine(s) created, but the schedule was cut short ({} still \
                 blocked or runnable, {} stopped by an error{})",
                unfinished.max(st.schedule.blocked_at_end.len()),
                errors.len(),
                if st.schedule.budget_exhausted {
                    ", switch budget exhausted"
                } else {
                    ""
                }
            ),
        );
    }
    if !st.candidates.is_empty() && started < 2 {
        return (
            "gate_not_reached",
            format!(
                "only {started} goroutine was created; a negated branch creates more (see \
                 next_seed)"
            ),
        );
    }
    (
        "no_race",
        format!(
            "{started} goroutine(s) ran to completion; {} conflicting pair(s) were all ordered \
             or protected",
            s.conflicting_pairs
        ),
    )
}

/// Build the summary document.
pub fn summary_json(termination: Option<Value>) -> Value {
    with_store(|st| build_summary(st, termination))
}

fn build_summary(st: &RaceStore, termination: Option<Value>) -> Value {
    let races = dedup_races(&st.races);

    // Resolve every PC that appears in the report in one addr2line call.
    let mut pcs: BTreeSet<u64> = BTreeSet::new();
    for r in races.iter().take(32) {
        for a in &r.accesses {
            pcs.insert(a.pc);
            pcs.extend(a.stack.iter().copied());
        }
    }
    for g in &st.goroutines {
        pcs.insert(g.entry);
        pcs.insert(g.spawn_pc);
    }
    for c in &st.candidates {
        pcs.insert(c.branch_pc);
    }
    let pcs: Vec<u64> = pcs.into_iter().collect();
    let locs = if cfg!(test) {
        HashMap::new()
    } else {
        func_index::source_locations(&st.binary, &pcs)
    };
    let func_of = |pc: u64| -> Option<String> {
        func_index::function_name_at(pc)
            .map(str::to_string)
            .or_else(|| locs.get(&pc).map(|l| l.function.clone()))
    };
    let source_of = |pc: u64| -> Value {
        locs.get(&pc)
            .map(|l| {
                json!({
                    "file": l.file,
                    "line": l.line,
                    "code": l.text,
                })
            })
            .unwrap_or(Value::Null)
    };
    let host_of = |tid: u64| {
        st.goroutines
            .iter()
            .find(|g| g.tid == tid)
            .and_then(|g| g.host_os_tid)
    };

    let access_json = |a: &RaceAccess| -> Value {
        let function = func_of(a.pc);
        let short = function
            .as_deref()
            .map(|f| f.rsplit('/').next().unwrap_or(f).to_string());
        let code = locs.get(&a.pc).and_then(|l| l.text.clone());
        let operation = match (&a.operation, short.as_deref(), &code) {
            (_, Some(f), Some(code)) => Some(format!("{f}(): {code}")),
            (Some(op), Some(f), None) => Some(format!(
                "{f}(): {op} {}",
                a.map_name.as_deref().unwrap_or("map")
            )),
            _ => a.operation.clone(),
        };
        json!({
            "kind": a.kind,
            "operation": operation,
            "map_operation": a.operation,
            "function": function,
            "goroutine": a.goid,
            "tid": a.tid,
            "os_thread": host_of(a.tid).unwrap_or(a.tid),
            "pc": hex(a.pc),
            "source": source_of(a.pc),
            "map": a.map.map(hex),
            "map_variable": a.map_name,
            "key": a.key,
            "runtime_call": a.callee,
            "locks_held": a.locks.iter().map(|l| hex(*l)).collect::<Vec<_>>(),
            "stack": a.stack.iter().map(|&pc| json!({
                "pc": hex(pc),
                "function": func_of(pc),
                "source": source_of(pc),
            })).collect::<Vec<_>>(),
        })
    };

    let decode = |a: &Option<Assignment>| a.as_ref().map(|m| decode_argv(&st.seed_args, m));
    let race_json = |r: &RaceEntry| -> Value {
        let mut order: Vec<(u64, Option<u64>)> =
            r.accesses.iter().map(|a| (a.tid, a.goid)).collect();
        order.dedup();
        json!({
            "rule": r.rule,
            "address": hex(r.addr),
            "reason": r.reason,
            "map_level": r.map_level,
            "input_class": r.input_class,
            "gate": r.gate,
            "gate_smt": r.gate_smt,
            "trigger": decode(&r.trigger),
            "escape": decode(&r.escape),
            "trigger_model": r.trigger.as_ref().map(assignment_json),
            "escape_model": r.escape.as_ref().map(assignment_json),
            "goroutines": schedule_string(&order, 8),
            "accesses": r.accesses.iter().map(&access_json).collect::<Vec<_>>(),
        })
    };

    let seed = decode_argv(&st.seed_args, &[]);
    let (status, detail) = if races.is_empty() {
        no_race_status(st)
    } else {
        (
            "race_found",
            format!("{} distinct race(s) reported", races.len()),
        )
    };
    let primary = races.first();
    let candidates: Vec<Value> = st
        .candidates
        .iter()
        .map(|c| {
            json!({
                "reason": c.reason,
                "branch_pc": hex(c.branch_pc),
                "branch_function": func_of(c.branch_pc),
                "branch_source": source_of(c.branch_pc),
                "gate": c.gate,
                "gate_smt": c.gate_smt,
                "argv": decode_argv(&st.seed_args, &c.assignment),
                "model": assignment_json(&c.assignment),
                "reached_by": if c.executed { "overlay" } else { "static_cfg" },
            })
        })
        .collect();
    let tried = seeds_tried();
    let next_seed = (status != "race_found" && status != "stdlib_fixed")
        .then(|| best_candidate(st, &tried))
        .flatten();

    let sched = &st.schedule;
    let goroutines: Vec<Value> = st
        .goroutines
        .iter()
        .map(|g| {
            json!({
                "goroutine": g.goid,
                "tid": g.tid,
                "parent_tid": g.parent_tid,
                "os_thread": g.host_os_tid,
                "entry": hex(g.entry),
                "entry_function": func_of(g.entry),
                "spawned_at": hex(g.spawn_pc),
                "spawned_in": func_of(g.spawn_pc),
                "spawn_source": source_of(g.spawn_pc),
                "instructions": g.instructions,
                "end": g.end,
            })
        })
        .collect();

    json!({
        "schema": "zorya.race_summary/1",
        "binary": st.binary,
        "toolchain": {
            "go_version": st.go_version,
            "advisories": st.advisories.iter().map(AdvisoryStatus::to_json).collect::<Vec<_>>(),
        },
        "analyses": st.analyses,
        "detector_active": st.detector_active,
        "status": status,
        "status_detail": detail,
        "race_found": !races.is_empty(),
        "seed": seed,
        "gate": primary.and_then(|r| r.gate.clone()),
        "gate_smt": primary.and_then(|r| r.gate_smt.clone()),
        "input_class": primary.map(|r| r.input_class.clone()),
        "trigger": primary.and_then(|r| decode(&r.trigger)),
        "escape": primary.and_then(|r| decode(&r.escape)),
        "schedule": schedule_string(&sched.trace, 64),
        "accesses": primary
            .map(|r| r.accesses.iter().map(&access_json).collect::<Vec<_>>())
            .unwrap_or_default(),
        "races": races.iter().take(32).map(race_json).collect::<Vec<_>>(),
        "races_total": races.len(),
        "next_seed": next_seed,
        "candidate_seeds": candidates,
        "seeds_tried": tried,
        "scheduler": {
            "enabled": sched.enabled,
            "policy": sched.policy,
            "seed": sched.seed,
            "max_switches": sched.max_switches,
            "max_loop_iterations": sched.max_loop_iterations,
            "max_goroutines_per_site": sched.max_goroutines_per_site,
            "max_goroutine_instructions": sched.max_goroutine_instructions,
            "switches": sched.switches,
            "budget_exhausted": sched.budget_exhausted,
            "main_returned": sched.main_returned,
            "main": goroutine_label(sched.main_tid, sched.main_goid),
            "skipped_spawns": sched.skipped_spawns,
            "forced_wakes": sched.forced_wakes,
            "blocked_at_end": sched.blocked_at_end.iter().map(|(tid, goid, why)| json!({
                "tid": tid,
                "goroutine": goid,
                "blocked_on": why,
            })).collect::<Vec<_>>(),
        },
        "goroutines": goroutines,
        "detector": {
            "reads": st.stats.reads,
            "writes": st.stats.writes,
            "map_operations": st.stats.map_ops,
            "lock_operations": st.stats.lock_ops,
            "conflicting_pairs": st.stats.conflicting_pairs,
            "application_conflicting_pairs": st.stats.app_conflicting_pairs,
            "hb_ordered": st.stats.hb_ordered,
            "lock_protected": st.stats.lock_protected,
            "application_hb_ordered": st.stats.app_hb_ordered,
            "application_lock_protected": st.stats.app_lock_protected,
            "runtime_internal_filtered": st.stats.runtime_internal_filtered,
            "reported_pairs": st.stats.reported_pairs,
        },
        "run": termination,
    })
}

/// Seeds of earlier launcher rounds (`ZORYA_SEEDS_TRIED`, a JSON array of
/// argv arrays), so `next_seed` never proposes one twice.
pub fn seeds_tried() -> Vec<Vec<String>> {
    std::env::var("ZORYA_SEEDS_TRIED")
        .or_else(|_| std::env::var("ZORYA_RACE_SEEDS_TRIED"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// The untried candidate to run next, preferring candidates whose overlay
/// executed up to the `go` statement.
fn best_candidate(st: &RaceStore, tried: &[Vec<String>]) -> Option<Vec<String>> {
    let seed = decode_argv(&st.seed_args, &[]);
    let mut ranked: Vec<&GateCandidate> = st.candidates.iter().collect();
    ranked.sort_by_key(|c| !c.executed);
    ranked
        .into_iter()
        .map(|c| decode_argv(&st.seed_args, &c.assignment))
        .find(|argv| *argv != seed && !tried.contains(argv))
}

/// [`best_candidate`] among the candidate seeds recorded in this run.
pub fn next_candidate_seed() -> Option<Vec<String>> {
    let tried = seeds_tried();
    with_store(|st| best_candidate(st, &tried))
}

fn assignment_json(a: &Assignment) -> Value {
    Value::Object(
        a.iter()
            .map(|(k, v)| (k.clone(), json!(v)))
            .collect::<serde_json::Map<String, Value>>(),
    )
}

/// Write `results/race_summary.json` and print a short verdict. Skipped
/// when no race detector ran and no goroutine was scheduled.
pub fn write_summary(termination: Option<Value>) -> Option<Value> {
    let relevant = with_store(|st| st.detector_active || !st.goroutines.is_empty());
    if !relevant || cfg!(test) {
        return None;
    }
    let doc = summary_json(termination);
    let _ = std::fs::create_dir_all("results");
    let tmp = format!("{RACE_SUMMARY_JSON}.tmp");
    if let Ok(s) = serde_json::to_string_pretty(&doc) {
        if std::fs::write(&tmp, s).is_ok() {
            let _ = std::fs::rename(&tmp, RACE_SUMMARY_JSON);
        }
    }
    print_verdict(&doc);
    Some(doc)
}

fn print_verdict(doc: &Value) {
    let s = |v: &Value| {
        v.as_str()
            .map(str::to_string)
            .unwrap_or_else(|| v.to_string())
    };
    crate::teprintln!();
    crate::teprintln!(
        "[RACE] status: {} ({})",
        s(&doc["status"]),
        s(&doc["status_detail"])
    );
    if let Some(v) = doc["toolchain"]["go_version"].as_str() {
        crate::teprintln!("[RACE] toolchain: {v}");
    }
    crate::teprintln!("[RACE] seed: {}", doc["seed"]);
    if doc["race_found"].as_bool() == Some(true) {
        crate::teprintln!("[RACE] gate: {}", s(&doc["gate"]));
        crate::teprintln!("[RACE] trigger: {}", doc["trigger"]);
        crate::teprintln!("[RACE] escape: {}", doc["escape"]);
        if let Some(accesses) = doc["accesses"].as_array() {
            for a in accesses {
                crate::teprintln!(
                    "[RACE]   {} by goroutine {}: {}",
                    s(&a["kind"]),
                    a["goroutine"],
                    s(&a["operation"])
                );
            }
        }
    }
    crate::teprintln!("[RACE] schedule: {}", s(&doc["schedule"]));
    if !doc["next_seed"].is_null() {
        crate::teprintln!("[RACE] next seed to try: {}", doc["next_seed"]);
    }
    crate::teprintln!("[RACE] summary written to {RACE_SUMMARY_JSON}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use z3::{Config, Context};

    #[test]
    fn arg_byte_names() {
        assert_eq!(parse_arg_byte("arg2_byte_0"), Some((2, 0)));
        assert_eq!(parse_arg_byte("arg1_byte_13!42"), Some((1, 13)));
        assert_eq!(parse_arg_byte("|arg1_byte_3!0|"), Some((1, 3)));
        assert_eq!(parse_arg_byte("adv_mem_0x10_byte_0"), None);
    }

    #[test]
    fn decodes_models_into_argv() {
        let seed = vec!["./bin".to_string(), "1".to_string(), "1".to_string()];
        let m = vec![("arg2_byte_0".to_string(), b'2' as u64)];
        assert_eq!(decode_argv(&seed, &m), vec!["1", "2"]);
        let m = vec![
            ("arg1_byte_0".to_string(), b'0' as u64),
            ("arg2_byte_0".to_string(), 1),
        ];
        assert_eq!(decode_argv(&seed, &m), vec!["0", "\\x01"]);
        assert_eq!(decode_argv(&seed, &[]), vec!["1", "1"]);
    }

    #[test]
    fn pretty_prints_argv_gates() {
        let ctx = Context::new(&Config::new());
        let a1 = BV::fresh_const(&ctx, "arg1_byte_0", 8);
        let a2 = BV::fresh_const(&ctx, "arg2_byte_0", 8);
        let eq1 = a1._eq(&BV::from_u64(&ctx, b'1' as u64, 8));
        let eq2 = a2._eq(&BV::from_u64(&ctx, b'1' as u64, 8));
        assert_eq!(
            pretty_condition(&[&eq1, &eq2]),
            "argv[1][0] == '1' && argv[2][0] == '1'"
        );
        assert_eq!(pretty_condition(&[&eq1, &eq1]), "argv[1][0] == '1'");
        let ne = eq1.not();
        assert_eq!(pretty_condition(&[&ne]), "argv[1][0] != '1'");

        // `ops := int(argv[2][0] - '0'); ops >= 2`
        let ops = a2.bvsub(&BV::from_u64(&ctx, b'0' as u64, 8)).zero_ext(56);
        let ge2 = ops.bvsge(&BV::from_u64(&ctx, 2, 64));
        let rendered = pretty_condition(&[&ge2]);
        assert!(rendered.contains("argv[2][0]"), "{rendered}");
        assert!(!rendered.contains("arg2_byte"), "{rendered}");

        let either = Bool::or(&ctx, &[&eq1, &eq2]);
        let both = Bool::and(&ctx, &[&either, &ge2]);
        let rendered = pretty_condition(&[&both]);
        assert!(
            rendered.contains("(argv[1][0] == '1' || argv[2][0] == '1')"),
            "{rendered}"
        );
        assert!(rendered.contains(" && "), "{rendered}");
    }

    #[test]
    fn spawn_candidate_relaxes_contradicting_prefix() {
        let ctx = Context::new(&Config::new());
        let a1 = BV::fresh_const(&ctx, "arg1_byte_0", 8);
        let a2 = BV::fresh_const(&ctx, "arg2_byte_0", 8);
        let one = BV::from_u64(&ctx, b'1' as u64, 8);
        // `!proxy || !css` short-circuited on `!proxy`: the prefix holds
        // `proxy != '1'`, the negated test of the boolean `proxy == '1'`.
        let short_circuit = a1._eq(&one).not();
        let unrelated = a2.bvuge(&BV::from_u64(&ctx, b'0' as u64, 8));
        let negated = a1._eq(&one);
        let (model, kept, relaxed) =
            solve_relaxing_prefix(&ctx, &[&short_circuit, &unrelated, &negated]).unwrap();
        assert_eq!(relaxed, 1);
        assert_eq!(kept.len(), 2);
        assert_eq!(model.eval(&a1, true).unwrap().as_u64(), Some(b'1' as u64));
        // A negated branch that contradicts itself has no candidate.
        let never = a1._eq(&one) & a1._eq(&one).not();
        assert!(solve_relaxing_prefix(&ctx, &[&short_circuit, &never]).is_none());
    }

    #[test]
    fn non_printable_gate_needs_the_unrestricted_domain() {
        let ctx = Context::new(&Config::new());
        let a1 = BV::fresh_const(&ctx, "arg1_byte_0", 8);
        let sentinel = a1._eq(&BV::from_u64(&ctx, 0xca, 8));
        let printable = byte_domain(&ctx, &[&sentinel], (32, 126));
        assert!(solve_relaxing_prefix_in(&ctx, &[&sentinel], &printable).is_none());
        let (model, _, _) = solve_relaxing_prefix_in(&ctx, &[&sentinel], &[]).unwrap();
        assert_eq!(model.eval(&a1, true).unwrap().as_u64(), Some(0xca));
    }

    #[test]
    fn compact_gate_per_byte() {
        let ctx = Context::new(&Config::new());
        let a1 = BV::fresh_const(&ctx, "arg1_byte_0", 8);
        let a2 = BV::fresh_const(&ctx, "arg2_byte_0", 8);
        let digit = |b: u8| BV::from_u64(&ctx, b as u64, 8);
        let memory = a1._eq(&digit(b'1'));
        // `ops := int(argv[2][0] - '0'); ops >= 0 && ops <= 9 && ops >= 2`,
        // spread over several conjuncts like a real path condition.
        let ops = a2.bvsub(&digit(b'0')).sign_ext(56);
        let zero = BV::from_u64(&ctx, 0, 64);
        let in_range = ops.bvsge(&zero) & ops.bvsle(&BV::from_u64(&ctx, 9, 64));
        let not_one = ops._eq(&BV::from_u64(&ctx, 1, 64)).not();
        let not_zero = ops._eq(&zero).not();
        let printable = (32, 126);
        assert_eq!(
            compact_condition_with(&ctx, &[&memory, &in_range, &not_zero, &not_one], printable)
                .as_deref(),
            Some("argv[1][0] == '1' && argv[2][0] in '2'..'9'")
        );
        // Coupled bytes have no per-byte form.
        let coupled = a1._eq(&a2);
        assert_eq!(compact_condition_with(&ctx, &[&coupled], printable), None);
        // A byte that may be anything but one value.
        let ne = a2._eq(&digit(b'x')).not();
        assert_eq!(
            compact_condition_with(&ctx, &[&ne], printable).as_deref(),
            Some("argv[2][0] != 'x'")
        );
    }

    #[test]
    fn model_assignment_reads_arg_bytes() {
        let ctx = Context::new(&Config::new());
        let a2 = BV::fresh_const(&ctx, "arg2_byte_0", 8);
        let gate = a2._eq(&BV::from_u64(&ctx, b'7' as u64, 8));
        let solver = z3::Solver::new(&ctx);
        solver.assert(&gate);
        assert_eq!(solver.check(), z3::SatResult::Sat);
        let vars = collect_arg_bytes(&[&gate]);
        assert_eq!(vars.len(), 1);
        let m = model_assignment(&solver.get_model().unwrap(), &vars);
        assert_eq!(m, vec![("arg2_byte_0".to_string(), b'7' as u64)]);
    }

    #[test]
    fn schedule_strings_collapse_repeats() {
        let trace = vec![
            (1, Some(1)),
            (5, Some(1001)),
            (5, Some(1001)),
            (1, Some(1)),
            (6, None),
        ];
        assert_eq!(schedule_string(&trace, 10), "g1 -> g1001 -> g1 -> t6");
        assert_eq!(schedule_string(&trace, 2), "g1 -> g1001 -> ... (2 more)");
    }

    fn race(pc1: u64, pc2: u64, map_level: bool, class: &str) -> RaceEntry {
        RaceEntry {
            input_class: class.into(),
            map_level,
            accesses: vec![
                RaceAccess {
                    kind: "read",
                    pc: pc1,
                    map: map_level.then_some(0x10),
                    ..Default::default()
                },
                RaceAccess {
                    kind: "write",
                    pc: pc2,
                    map: map_level.then_some(0x10),
                    ..Default::default()
                },
            ],
            ..Default::default()
        }
    }

    #[test]
    fn dedup_keeps_one_entry_per_pc_pair_and_prefers_map_races() {
        let races = vec![
            race(0x10, 0x20, false, "unconditional"),
            race(0x10, 0x20, false, "unconditional"),
            race(0x30, 0x40, true, "input-dependent"),
        ];
        let d = dedup_races(&races);
        assert_eq!(d.len(), 2);
        assert!(d[0].map_level);
    }

    #[test]
    fn statuses_without_race() {
        let mut st = RaceStore::default();
        assert_eq!(no_race_status(&st).0, "no_concurrency");
        st.candidates.push(GateCandidate::default());
        assert_eq!(no_race_status(&st).0, "gate_not_reached");
        st.goroutines.push(GoroutineRecord {
            end: Some("returned".into()),
            ..Default::default()
        });
        assert_eq!(no_race_status(&st).0, "gate_not_reached");
        st.goroutines.push(GoroutineRecord::default());
        assert_eq!(no_race_status(&st).0, "gate_reached_schedule_not_explored");
        st.goroutines[1].end = Some("error: unmodelled".into());
        st.stats.app_conflicting_pairs = 2;
        assert_eq!(no_race_status(&st).0, "race_reached_not_reported");
        st.goroutines[1].end = Some("returned".into());
        st.stats.app_conflicting_pairs = 0;
        assert_eq!(no_race_status(&st).0, "no_race");
        st.advisories.push(AdvisoryStatus {
            id: "CVE-X",
            package: "net/http",
            status: "fixed_in_toolchain",
            message: "fixed".into(),
        });
        assert_eq!(no_race_status(&st).0, "stdlib_fixed");
    }

    #[test]
    fn summary_reports_primary_race_and_next_seed() {
        let mut st = RaceStore {
            seed_args: vec!["bin".into(), "1".into(), "1".into()],
            ..Default::default()
        };
        let mut r = race(0x10, 0x20, true, "input-dependent");
        r.gate = Some("argv[1][0] == '1'".into());
        r.trigger = Some(vec![("arg1_byte_0".into(), b'1' as u64)]);
        r.escape = Some(vec![("arg1_byte_0".into(), b'0' as u64)]);
        r.accesses[0].goid = Some(1001);
        st.races.push(r);
        let doc = build_summary(&st, None);
        assert_eq!(doc["status"], "race_found");
        assert_eq!(doc["trigger"], json!(["1", "1"]));
        assert_eq!(doc["escape"], json!(["0", "1"]));
        assert_eq!(doc["accesses"][0]["goroutine"], 1001);
        assert!(doc["next_seed"].is_null());

        let mut st = RaceStore {
            seed_args: vec!["bin".into(), "1".into(), "1".into()],
            ..Default::default()
        };
        st.candidates.push(GateCandidate {
            assignment: vec![("arg2_byte_0".into(), b'3' as u64)],
            ..Default::default()
        });
        st.candidates.push(GateCandidate {
            assignment: vec![("arg2_byte_0".into(), b'2' as u64)],
            executed: true,
            ..Default::default()
        });
        let doc = build_summary(&st, None);
        assert_eq!(doc["status"], "gate_not_reached");
        // A candidate whose overlay reached the go statement comes first.
        assert_eq!(doc["next_seed"], json!(["1", "2"]));
    }
}
