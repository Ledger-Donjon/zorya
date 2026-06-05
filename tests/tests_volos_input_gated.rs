// SPDX-FileCopyrightText: 2026 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

//! End-to-end exercise of the input × concurrency coupling in the `volos`
//! plugin, driven through the real `EventBus` with real Z3 path conditions.
//!
//! Each scenario reproduces the *access + guard* structure of a binary under
//! `tests/programs/` at the level the executor would surface to the plugin
//! (binary-originated `MemWrite` events carrying the engine's current path
//! condition `φ`), then runs the end-of-trace race pass and prints the
//! classified finding. Run with output visible:
//!
//! ```bash
//! cargo test --features plugin-volos --test tests_volos_input_gated -- --nocapture
//! ```

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Instant;

use z3::ast::{Ast, Bool, BV};
use z3::{Config, Context};

use zorya::plugins::builtin::volos::VolosPlugin;
use zorya::plugins::context::EventCtx;
use zorya::plugins::event::Event;
use zorya::plugins::finding::Finding;
use zorya::plugins::EventBus;

/// Address of the shared global the racing goroutines write. Matches
/// `main.counter` in `tests/programs/race-counter`.
const COUNTER: u64 = 0x59ca58;

/// One memory-write event with an associated path condition.
struct Write<'ctx> {
    tid: u64,
    pc: u64,
    phi: Vec<Bool<'ctx>>,
}

/// Optional lock acquire/release around a write (for the protected control).
struct Lock {
    tid: u64,
    pc: u64,
    sym: &'static str,
    target: u64,
    acquire: bool,
}

/// Drive a sequence of locks + writes through a fresh bus and return the
/// findings produced at end-of-trace.
fn run_scenario(ctx: &Context, locks: &[Lock], writes: &[Write<'_>]) -> Vec<Finding> {
    let findings = RefCell::new(Vec::new());
    let mut bus: EventBus<'_> = EventBus::new();
    bus.add(Box::new(VolosPlugin::new()));

    let empty_c: Vec<u8> = Vec::new();
    let empty_s: Vec<Option<Rc<BV<'_>>>> = Vec::new();

    // Interleave: emit lock events first (acquire), then the writes, in the
    // order given. A real run would interleave per the round-robin
    // scheduler; for the detector the relative order of cross-thread
    // accesses is what matters, and these are concurrent (distinct tids,
    // no fork edge).
    for l in locks.iter().filter(|l| l.acquire) {
        let ectx = EventCtx::new(ctx, l.pc, l.tid, 0, Instant::now(), &findings);
        bus.dispatch(
            &Event::Call {
                pc: l.pc,
                target: l.target,
                symbol: Some(l.sym),
                tid: l.tid,
                arg0: 0,
            },
            &ectx,
        );
    }

    for w in writes {
        let ectx = EventCtx::new(ctx, w.pc, w.tid, 0, Instant::now(), &findings)
            .with_path_constraints(&w.phi);
        bus.dispatch(
            &Event::MemWrite {
                addr: COUNTER,
                size: 64,
                concrete: &empty_c,
                symbolic: &empty_s,
                pc: w.pc,
                tid: w.tid,
            },
            &ectx,
        );
    }

    for l in locks.iter().filter(|l| !l.acquire) {
        let ectx = EventCtx::new(ctx, l.pc, l.tid, 0, Instant::now(), &findings);
        bus.dispatch(
            &Event::Call {
                pc: l.pc,
                target: l.target,
                symbol: Some(l.sym),
                tid: l.tid,
                arg0: 0,
            },
            &ectx,
        );
    }

    // End-of-trace race pass. on_finish needs an EventCtx bound to the same
    // findings buffer and Z3 context.
    let ectx = EventCtx::new(ctx, 0, 0, 0, Instant::now(), &findings);
    bus.run_finish(&ectx);
    findings.into_inner()
}

fn print_findings(title: &str, findings: &[Finding]) {
    println!("\n========== {title} ==========");
    if findings.is_empty() {
        println!("  (no findings — clean)");
        return;
    }
    for f in findings {
        println!("[{}::{}] {}", f.plugin, f.rule, f.title);
        for d in &f.details {
            println!("    {d}");
        }
    }
}

/// Scenario 1 — `crashme`-style input-dependent race: goroutine A writes the
/// shared counter only when `os.Args[1][0] == 'K'` (0x4B); goroutine B writes
/// unconditionally. φ is satisfiable AND ¬φ is satisfiable ⇒ input-dependent,
/// with a triggering input and an escape input.
#[test]
fn scenario_input_dependent_race() {
    let ctx = Context::new(&Config::new());
    let arg = BV::new_const(&ctx, "os_args_1", 8);
    let guard: Bool = arg._eq(&BV::from_u64(&ctx, 0x4B, 8)); // == 'K'

    let writes = vec![
        Write {
            tid: 1,
            pc: 0x4b8033,
            phi: vec![guard],
        }, // gated A
        Write {
            tid: 2,
            pc: 0x4b7f53,
            phi: vec![],
        }, // unconditional B
    ];
    let findings = run_scenario(&ctx, &[], &writes);
    print_findings(
        "S1 input-dependent (crashme-style: write iff arg=='K')",
        &findings,
    );

    assert!(
        findings
            .iter()
            .any(|f| f.rule == "input-gated-data-race-unprotected"),
        "expected an input-gated race, got {:?}",
        findings.iter().map(|f| f.rule).collect::<Vec<_>>()
    );
    let blob = details_blob(&findings);
    assert!(blob.contains("input-dependent"), "{blob}");
    assert!(blob.contains("os_args_1"), "{blob}");
    assert!(blob.contains("Escape input"), "{blob}");
}

/// Scenario 2 — `race-counter`: two goroutines write the shared global with
/// no guard at all. Input-independent (no symbolic branch gates either
/// access); keeps the plain rule.
#[test]
fn scenario_input_independent_race() {
    let ctx = Context::new(&Config::new());
    let writes = vec![
        Write {
            tid: 1,
            pc: 0x4b8033,
            phi: vec![],
        },
        Write {
            tid: 2,
            pc: 0x4b7f53,
            phi: vec![],
        },
    ];
    let findings = run_scenario(&ctx, &[], &writes);
    print_findings(
        "S2 input-independent (race-counter: unconditional writes)",
        &findings,
    );

    assert!(
        findings.iter().any(|f| f.rule == "data-race-unprotected"),
        "expected the plain rule, got {:?}",
        findings.iter().map(|f| f.rule).collect::<Vec<_>>()
    );
    assert!(details_blob(&findings).contains("input-independent"));
}

/// Scenario 3 — valid-guard race: the racing code sits behind a guard that is
/// a tautology over the input (`n < 0 ∨ n >= 0`). φ is SAT but ¬φ is UNSAT ⇒
/// the race fires for every input ⇒ input-independent outcome, plain rule.
#[test]
fn scenario_valid_guard_is_input_independent() {
    let ctx = Context::new(&Config::new());
    let n = BV::new_const(&ctx, "n", 32);
    let zero = BV::from_i64(&ctx, 0, 32);
    let taut: Bool = Bool::or(&ctx, &[&n.bvslt(&zero), &n.bvsge(&zero)]); // n<0 ∨ n>=0

    let writes = vec![
        Write {
            tid: 1,
            pc: 0x4b8033,
            phi: vec![taut],
        },
        Write {
            tid: 2,
            pc: 0x4b7f53,
            phi: vec![],
        },
    ];
    let findings = run_scenario(&ctx, &[], &writes);
    print_findings(
        "S3 valid guard (n<0 ∨ n>=0 ≡ true) → input-independent",
        &findings,
    );

    assert!(
        findings.iter().any(|f| f.rule == "data-race-unprotected"),
        "valid guard must keep the plain rule, got {:?}",
        findings.iter().map(|f| f.rule).collect::<Vec<_>>()
    );
    assert!(
        !findings.iter().any(|f| f.rule.starts_with("input-gated")),
        "valid guard must NOT be input-gated"
    );
}

/// Scenario 4 — `race-counter-mutex` negative control: both goroutines hold
/// the *same* lock around the write. The shared lock suppresses the race;
/// no finding at all.
#[test]
fn scenario_mutex_protected_no_race() {
    let ctx = Context::new(&Config::new());
    const MTX: u64 = 0x600000;
    let locks = vec![
        Lock {
            tid: 1,
            pc: 0x10,
            sym: "runtime.lock",
            target: MTX,
            acquire: true,
        },
        Lock {
            tid: 2,
            pc: 0x20,
            sym: "runtime.lock",
            target: MTX,
            acquire: true,
        },
        Lock {
            tid: 1,
            pc: 0x30,
            sym: "runtime.unlock",
            target: MTX,
            acquire: false,
        },
        Lock {
            tid: 2,
            pc: 0x40,
            sym: "runtime.unlock",
            target: MTX,
            acquire: false,
        },
    ];
    let writes = vec![
        Write {
            tid: 1,
            pc: 0x4b8033,
            phi: vec![],
        },
        Write {
            tid: 2,
            pc: 0x4b7f53,
            phi: vec![],
        },
    ];
    let findings = run_scenario(&ctx, &locks, &writes);
    print_findings("S4 mutex-protected (shared lock) → no race", &findings);
    assert!(
        findings.is_empty(),
        "shared lock must suppress the race: {findings:?}"
    );
}

/// Scenario 5 — schedule-only artefact: the two writes are guarded by
/// *contradictory* conditions (`n == 1` vs `n == 2`) on the same input. No
/// single input drives the program down both paths, so the conjunction
/// `φ₁ ∧ φ₂` is UNSAT: the detector reports it as schedule-only, NOT an
/// input-reachable race.
#[test]
fn scenario_infeasible_is_schedule_only() {
    let ctx = Context::new(&Config::new());
    let n = BV::new_const(&ctx, "n", 32);
    let g1: Bool = n._eq(&BV::from_i64(&ctx, 1, 32));
    let g2: Bool = n._eq(&BV::from_i64(&ctx, 2, 32));

    let writes = vec![
        Write {
            tid: 1,
            pc: 0x4b8033,
            phi: vec![g1],
        },
        Write {
            tid: 2,
            pc: 0x4b7f53,
            phi: vec![g2],
        },
    ];
    let findings = run_scenario(&ctx, &[], &writes);
    print_findings(
        "S5 contradictory guards (n==1 vs n==2) → schedule-only",
        &findings,
    );

    assert!(
        findings.iter().any(|f| f.rule == "data-race-schedule-only"),
        "contradictory guards must be schedule-only, got {:?}",
        findings.iter().map(|f| f.rule).collect::<Vec<_>>()
    );
}

fn details_blob(findings: &[Finding]) -> String {
    findings
        .iter()
        .flat_map(|f| f.details.iter().cloned())
        .collect::<Vec<_>>()
        .join("\n")
}
