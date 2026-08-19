// SPDX-FileCopyrightText: 2026 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

//! Channel-invariant detector — detects send-on-closed-channel panics.
//!
//! This plugin implements the "Z3-coupled invariant check" described in
//! the Zorya multi-threaded analysis design: a Go-specific synchronisation
//! fault where a goroutine sends on a channel that another goroutine has
//! closed. The panic requires **both** the right input (to reach the close)
//! **and** the right interleaving (close scheduled before the send).
//!
//! ## Detection algorithm
//!
//! 1. At `runtime.makechan(t, size)` — record a new channel with `closed = false`.
//!    The channel is identified by its concrete `*hchan` pointer (returned in RAX).
//!
//! 2. At `runtime.closechan(ch)` — mark the channel as closed, capturing the
//!    current goroutine's path constraint `φ_close`. The symbolic closed-flag
//!    becomes `true` under `φ_close`.
//!
//! 3. At `runtime.chansend1(ch, elem)` — query: can this channel already be
//!    closed? The question to Z3 is: `φ_close ∧ φ_send` satisfiable AND the
//!    close is scheduled before this send (guaranteed by the interleaving the
//!    scheduler produced). If SAT, emit a finding with the input model.
//!
//! ## Relationship to Volos
//!
//! This is NOT a data race. The Go race detector would not flag it. Volos
//! (which detects memory-level data races) would not flag it either. This is
//! a higher-level synchronisation invariant: "thou shalt not send on a closed
//! channel". The plugin reuses the same Z3 coupling infrastructure (path
//! conditions) but applies it to channel-protocol invariants rather than
//! memory access pairs.
//!
//! ## Subscriptions
//!
//! - `Call` — to intercept `runtime.makechan`, `runtime.closechan`,
//!   `runtime.chansend1`, `runtime.chanrecv1`
//! - `ThreadSpawn` / `ThreadExit` — to track goroutine lifetimes

use std::collections::{HashMap, HashSet};

use z3::ast::{Ast, Bool};
use z3::{SatResult, Solver};

use crate::plugins::context::EventCtx;
use crate::plugins::event::{Event, EventKind};
use crate::plugins::finding::{Finding, Severity};
use crate::plugins::plugin::Plugin;
use crate::plugins::verdict::Verdict;
use crate::plugins::EventBus;
use crate::teprintln;

/// Tracked state of one Go channel (identified by its concrete `*hchan` pointer).
#[derive(Debug)]
#[allow(dead_code)]
struct ChannelState<'ctx> {
    /// The concrete `*hchan` pointer returned by `runtime.makechan`.
    hchan_ptr: u64,
    /// Which goroutine (tid) created this channel.
    creator_tid: u64,
    /// Whether `runtime.closechan` has been observed for this channel.
    closed: bool,
    /// The goroutine (tid) that closed the channel. `None` if still open.
    closer_tid: Option<u64>,
    /// Path constraint `φ_close` under which the channel was closed.
    /// Empty means the close was unconditional.
    close_phi: Vec<Bool<'ctx>>,
    /// PC where the close was observed.
    close_pc: u64,
}

/// A send or receive attempt we've observed, kept for end-of-trace analysis.
#[derive(Debug)]
struct SendAttempt<'ctx> {
    /// The `*hchan` this send targeted.
    hchan_ptr: u64,
    /// Goroutine that attempted the send.
    tid: u64,
    /// Path constraints at the send site.
    send_phi: Vec<Bool<'ctx>>,
    /// PC of the send.
    pc: u64,
}

/// The channel-invariant detector plugin.
#[derive(Debug)]
pub struct ChanCheckPlugin<'ctx> {
    /// Known channels, keyed by `*hchan` pointer.
    channels: HashMap<u64, ChannelState<'ctx>>,
    /// Observed send attempts (for cross-referencing at `on_finish`).
    sends: Vec<SendAttempt<'ctx>>,
    /// Verbose logging.
    verbose: bool,
    /// Counters for diagnostics.
    channels_created: u64,
    channels_closed: u64,
    sends_observed: u64,
    violations_found: u64,
}

impl<'ctx> ChanCheckPlugin<'ctx> {
    pub fn new() -> Self {
        Self {
            channels: HashMap::new(),
            sends: Vec::new(),
            verbose: !std::env::var("CHANCHECK_VERBOSE").is_ok_and(|v| v == "0"),
            channels_created: 0,
            channels_closed: 0,
            sends_observed: 0,
            violations_found: 0,
        }
    }

    fn vlog(&self, msg: impl AsRef<str>) {
        if self.verbose {
            teprintln!();
            teprintln!("[CHANCHECK] {}", msg.as_ref());
            teprintln!();
        }
    }

    /// Diagnostic accessor for tests.
    pub fn stats(&self) -> ChanCheckStats {
        ChanCheckStats {
            channels_created: self.channels_created,
            channels_closed: self.channels_closed,
            sends_observed: self.sends_observed,
            violations_found: self.violations_found,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ChanCheckStats {
    pub channels_created: u64,
    pub channels_closed: u64,
    pub sends_observed: u64,
    pub violations_found: u64,
}

impl<'ctx> Default for ChanCheckPlugin<'ctx> {
    fn default() -> Self {
        Self::new()
    }
}

/// The symbols we intercept.
const CHAN_MAKE_SYMBOLS: &[&str] = &["runtime.makechan", "runtime.makechan64"];
const CHAN_CLOSE_SYMBOLS: &[&str] = &["runtime.closechan"];
const CHAN_SEND_SYMBOLS: &[&str] = &["runtime.chansend1", "runtime.chansend"];
const CHAN_RECV_SYMBOLS: &[&str] = &["runtime.chanrecv1", "runtime.chanrecv2", "runtime.chanrecv"];

impl<'ctx> Plugin<'ctx> for ChanCheckPlugin<'ctx> {
    fn name(&self) -> &'static str {
        "chancheck"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn wants(&self) -> HashSet<EventKind> {
        [
            EventKind::Call,
            EventKind::ThreadSpawn,
            EventKind::ThreadExit,
        ]
        .into_iter()
        .collect()
    }

    fn symbol_hooks(&self) -> &'static [&'static str] {
        &[
            "runtime.makechan",
            "runtime.makechan64",
            "runtime.closechan",
            "runtime.chansend1",
            "runtime.chansend",
            "runtime.chanrecv1",
            "runtime.chanrecv2",
            "runtime.chanrecv",
        ]
    }

    fn on_event(&mut self, ev: &Event<'ctx, '_>, ctx: &EventCtx<'ctx, '_>) -> Verdict {
        match ev {
            Event::Call {
                symbol: Some(sym),
                tid,
                arg0,
                ..
            } => {
                let name = *sym;

                // ─── Channel creation ────────────────────────────────────
                if CHAN_MAKE_SYMBOLS.contains(&name) {
                    // At this point `arg0` is the chantype pointer, not the
                    // result. The result (`*hchan`) will be in RAX after the
                    // call returns. For the summary-based path, the summary
                    // engine calls `on_chan_created` with the allocated ptr.
                    // For now we record intent; the actual hchan will be
                    // registered via `register_channel` from the summary hook.
                    self.vlog(format!(
                        "MAKECHAN call observed tid={} chantype_ptr=0x{:x}",
                        tid, arg0
                    ));
                }
                // ─── Channel close ───────────────────────────────────────
                else if CHAN_CLOSE_SYMBOLS.contains(&name) {
                    let hchan = *arg0; // first arg to closechan is the *hchan
                    self.channels_closed += 1;
                    self.vlog(format!(
                        "CLOSECHAN hchan=0x{:x} tid={} |φ|={}",
                        hchan,
                        tid,
                        ctx.path_constraints().len()
                    ));

                    if let Some(ch) = self.channels.get_mut(&hchan) {
                        ch.closed = true;
                        ch.closer_tid = Some(*tid);
                        ch.close_phi = ctx.path_constraints().to_vec();
                        ch.close_pc = ctx.current_pc;
                    } else {
                        // Channel wasn't tracked via makechan (maybe created
                        // before our analysis started). Still record it.
                        self.channels.insert(
                            hchan,
                            ChannelState {
                                hchan_ptr: hchan,
                                creator_tid: *tid,
                                closed: true,
                                closer_tid: Some(*tid),
                                close_phi: ctx.path_constraints().to_vec(),
                                close_pc: ctx.current_pc,
                            },
                        );
                    }
                }
                // ─── Channel send ────────────────────────────────────────
                else if CHAN_SEND_SYMBOLS.contains(&name) {
                    let hchan = *arg0; // first arg to chansend1 is the *hchan
                    self.sends_observed += 1;
                    self.vlog(format!(
                        "CHANSEND hchan=0x{:x} tid={} |φ|={}",
                        hchan,
                        tid,
                        ctx.path_constraints().len()
                    ));

                    self.sends.push(SendAttempt {
                        hchan_ptr: hchan,
                        tid: *tid,
                        send_phi: ctx.path_constraints().to_vec(),
                        pc: ctx.current_pc,
                    });
                }
                // ─── Channel receive (for future recv-on-closed) ─────────
                else if CHAN_RECV_SYMBOLS.contains(&name) {
                    // Not a violation in Go (recv on closed returns zero-value),
                    // but tracked for completeness and future invariant checks.
                    self.vlog(format!("CHANRECV hchan=0x{:x} tid={}", arg0, tid));
                }
            }
            Event::Call { .. } => {}
            Event::ThreadSpawn { .. } => {}
            Event::ThreadExit { .. } => {}
            _ => {}
        }
        Verdict::Continue
    }

    fn on_finish(&mut self, ctx: &EventCtx<'ctx, '_>) {
        // Collect violations first (to avoid borrow conflicts), then emit.
        struct Violation {
            send_idx: usize,
            same_goroutine: bool,
        }
        let mut violations: Vec<Violation> = Vec::new();

        for (idx, send) in self.sends.iter().enumerate() {
            let ch = match self.channels.get(&send.hchan_ptr) {
                Some(ch) if ch.closed => ch,
                _ => continue,
            };

            if ch.closer_tid == Some(send.tid) {
                violations.push(Violation {
                    send_idx: idx,
                    same_goroutine: true,
                });
                continue;
            }

            // Cross-goroutine feasibility check
            let mut parts: Vec<&Bool<'ctx>> = Vec::new();
            parts.extend(ch.close_phi.iter());
            parts.extend(send.send_phi.iter());

            let satisfiable = if parts.is_empty() {
                true
            } else {
                let solver = Solver::new(ctx.ctx);
                for p in &parts {
                    solver.assert(p);
                }
                matches!(solver.check(), SatResult::Sat)
            };

            if satisfiable {
                violations.push(Violation {
                    send_idx: idx,
                    same_goroutine: false,
                });
            }
        }

        // Now emit findings (requires &mut self)
        for v in &violations {
            let send = &self.sends[v.send_idx];
            let ch = self.channels.get(&send.hchan_ptr).unwrap();
            self.violations_found += 1;

            let scope = if v.same_goroutine {
                "same-goroutine"
            } else {
                "cross-goroutine"
            };

            let title = format!(
                "Send on closed channel at 0x{:x} [{}]: hchan=0x{:x}, close at 0x{:x}",
                send.pc, scope, send.hchan_ptr, ch.close_pc
            );

            let mut finding = Finding::new(
                "chancheck",
                "send-on-closed-channel",
                Severity::Critical,
                send.pc,
                title,
            )
            .with_detail(format!(
                "Close: tid={}, pc=0x{:x}, |φ_close|={}",
                ch.closer_tid.unwrap_or(0),
                ch.close_pc,
                ch.close_phi.len()
            ))
            .with_detail(format!(
                "Send: tid={}, pc=0x{:x}, |φ_send|={}",
                send.tid,
                send.pc,
                send.send_phi.len()
            ));

            // Solve for a concrete triggering input
            if !ch.close_phi.is_empty() || !send.send_phi.is_empty() {
                let solver = Solver::new(ctx.ctx);
                for p in &ch.close_phi {
                    solver.assert(p);
                }
                for p in &send.send_phi {
                    solver.assert(p);
                }
                if let SatResult::Sat = solver.check() {
                    if let Some(model) = solver.get_model() {
                        let model_str = format!("{}", model)
                            .lines()
                            .map(|l| l.trim())
                            .filter(|l| !l.is_empty())
                            .collect::<Vec<_>>()
                            .join("; ");
                        finding = finding.with_detail(format!(
                            "Triggering input (satisfies φ_close ∧ φ_send): {}",
                            if model_str.is_empty() {
                                "(trivial)".to_string()
                            } else {
                                model_str
                            }
                        ));
                    }
                }

                let phi_str: String = ch
                    .close_phi
                    .iter()
                    .chain(send.send_phi.iter())
                    .map(|b| format!("{}", b.simplify()))
                    .collect::<Vec<_>>()
                    .join(" ∧ ");
                finding = finding
                    .with_detail(format!("Path condition φ = φ_close ∧ φ_send: {}", phi_str));
            } else {
                finding = finding.with_detail(
                    "Path condition: unconditional (no symbolic guards on either close or send)"
                        .to_string(),
                );
            }

            finding = finding.with_detail(format!(
                "Interleaving: close (tid={}) scheduled before send (tid={}) by round-robin",
                ch.closer_tid.unwrap_or(0),
                send.tid
            ));

            ctx.findings.borrow_mut().push(finding);
        }

        if self.violations_found > 0 {
            teprintln!("[CHANCHECK] *** BUG / VULNERABILITY DETECTED: {} send-on-closed-channel violation(s) ({} channels created, {} closed, {} sends observed) ***",
                self.violations_found, self.channels_created, self.channels_closed, self.sends_observed);
        } else {
            teprintln!("[CHANCHECK] No send-on-closed-channel bugs found ({} channels created, {} closed, {} sends observed)",
                self.channels_created, self.channels_closed, self.sends_observed);
        }
    }
}

impl<'ctx> ChanCheckPlugin<'ctx> {
    /// Register a channel that was created (called by the summary engine
    /// after allocating the hchan struct).
    pub fn register_channel(&mut self, hchan_ptr: u64, creator_tid: u64) {
        self.channels_created += 1;
        self.vlog(format!(
            "REGISTERED channel hchan=0x{:x} creator={}",
            hchan_ptr, creator_tid
        ));
        self.channels.insert(
            hchan_ptr,
            ChannelState {
                hchan_ptr,
                creator_tid,
                closed: false,
                closer_tid: None,
                close_phi: Vec::new(),
                close_pc: 0,
            },
        );
    }

    /// Check whether `φ_close ∧ φ_send` is satisfiable.
    #[allow(dead_code)]
    fn check_joint_feasibility(
        &self,
        z3_ctx: &'ctx z3::Context,
        ch: &ChannelState<'ctx>,
        send: &SendAttempt<'ctx>,
    ) -> bool {
        let mut parts: Vec<&Bool<'ctx>> = Vec::new();
        parts.extend(ch.close_phi.iter());
        parts.extend(send.send_phi.iter());

        if parts.is_empty() {
            return true;
        }

        let solver = Solver::new(z3_ctx);
        for p in &parts {
            solver.assert(p);
        }
        matches!(solver.check(), SatResult::Sat)
    }
}

/// Factory called from registry when the `plugin-chancheck` feature is enabled.
pub fn register<'ctx>(bus: &mut EventBus<'ctx>) {
    bus.add(Box::new(ChanCheckPlugin::new()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::context::EventCtx;
    use crate::plugins::event::Event;
    use crate::plugins::finding::Finding;
    use std::cell::RefCell;
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

    /// Basic: close on one goroutine, send on another, no symbolic constraints.
    /// The detector should flag an unconditional send-on-closed-channel.
    #[test]
    fn chancheck_detects_unconditional_send_on_closed() {
        let ctx = fresh_ctx();
        let findings = RefCell::new(Vec::new());

        let mut bus: EventBus<'_> = EventBus::new();
        bus.add(Box::new(ChanCheckPlugin::new()));

        let ectx = mk_ctx(&ctx, &findings);

        // Register the channel (normally done by the summary engine)
        let hchan: u64 = 0xc0001000;
        bus.dispatch(
            &Event::Call {
                pc: 0x100,
                target: 0xdead,
                symbol: Some("runtime.makechan"),
                tid: 1,
                arg0: 0, // chantype ptr, not the result
            },
            &ectx,
        );
        // Manually register the channel since we don't have the summary engine here
        for plugin in bus.plugins_mut() {
            if plugin.name() == "chancheck" {
                // Safety: we know the concrete type
                let p = unsafe {
                    &mut *(&mut **plugin as *mut dyn Plugin<'_> as *mut ChanCheckPlugin<'_>)
                };
                p.register_channel(hchan, 1);
            }
        }

        // Goroutine 2 closes the channel
        let ectx2 = EventCtx::new(&ctx, 0x200, 2, 0, Instant::now(), &findings);
        bus.dispatch(
            &Event::Call {
                pc: 0x200,
                target: 0xbeef,
                symbol: Some("runtime.closechan"),
                tid: 2,
                arg0: hchan,
            },
            &ectx2,
        );

        // Goroutine 1 sends on the (now closed) channel
        let ectx1 = EventCtx::new(&ctx, 0x300, 1, 0, Instant::now(), &findings);
        bus.dispatch(
            &Event::Call {
                pc: 0x300,
                target: 0xcafe,
                symbol: Some("runtime.chansend1"),
                tid: 1,
                arg0: hchan,
            },
            &ectx1,
        );

        bus.run_finish(&ectx);

        let f = findings.borrow();
        assert!(!f.is_empty(), "expected send-on-closed finding");
        assert!(
            f.iter().any(|x| x.rule == "send-on-closed-channel"),
            "expected send-on-closed-channel rule, got: {:?}",
            f.iter().map(|x| &x.rule).collect::<Vec<_>>()
        );
    }

    /// Input-gated: the close happens under φ = (data[0] == 0xCA).
    /// The send is unconditional. Z3 must confirm φ is satisfiable.
    #[test]
    fn chancheck_detects_input_gated_send_on_closed() {
        let ctx = fresh_ctx();
        let findings = RefCell::new(Vec::new());

        let mut bus: EventBus<'_> = EventBus::new();
        bus.add(Box::new(ChanCheckPlugin::new()));

        let hchan: u64 = 0xc0002000;

        // Register channel
        let ectx = mk_ctx(&ctx, &findings);
        for plugin in bus.plugins_mut() {
            if plugin.name() == "chancheck" {
                let p = unsafe {
                    &mut *(&mut **plugin as *mut dyn Plugin<'_> as *mut ChanCheckPlugin<'_>)
                };
                p.register_channel(hchan, 1);
            }
        }

        // The close is gated by data[0] == 0xCA
        let input = BV::new_const(&ctx, "os_args_1", 8);
        let guard: Bool = input._eq(&BV::from_u64(&ctx, 0xCA, 8));
        let close_phi = vec![guard];

        let ectx_close = EventCtx::new(&ctx, 0x200, 2, 0, Instant::now(), &findings)
            .with_path_constraints(&close_phi);
        bus.dispatch(
            &Event::Call {
                pc: 0x200,
                target: 0xbeef,
                symbol: Some("runtime.closechan"),
                tid: 2,
                arg0: hchan,
            },
            &ectx_close,
        );

        // Unconditional send from goroutine 1
        let ectx_send = EventCtx::new(&ctx, 0x300, 1, 0, Instant::now(), &findings);
        bus.dispatch(
            &Event::Call {
                pc: 0x300,
                target: 0xcafe,
                symbol: Some("runtime.chansend1"),
                tid: 1,
                arg0: hchan,
            },
            &ectx_send,
        );

        bus.run_finish(&ectx);

        let f = findings.borrow();
        assert!(!f.is_empty(), "expected input-gated send-on-closed finding");
        assert!(
            f.iter().any(|x| x.rule == "send-on-closed-channel"),
            "expected send-on-closed-channel rule"
        );
        let blob: String = f
            .iter()
            .flat_map(|x| x.details.iter().cloned())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            blob.contains("os_args_1"),
            "finding must mention the symbolic input variable:\n{}",
            blob
        );
        assert!(
            blob.contains("Triggering input"),
            "finding must carry the triggering input model:\n{}",
            blob
        );
    }

    /// No close observed → no violation, even with sends.
    #[test]
    fn chancheck_no_violation_when_channel_open() {
        let ctx = fresh_ctx();
        let findings = RefCell::new(Vec::new());

        let mut bus: EventBus<'_> = EventBus::new();
        bus.add(Box::new(ChanCheckPlugin::new()));

        let ectx = mk_ctx(&ctx, &findings);
        let hchan: u64 = 0xc0003000;

        for plugin in bus.plugins_mut() {
            if plugin.name() == "chancheck" {
                let p = unsafe {
                    &mut *(&mut **plugin as *mut dyn Plugin<'_> as *mut ChanCheckPlugin<'_>)
                };
                p.register_channel(hchan, 1);
            }
        }

        // Send without any close
        bus.dispatch(
            &Event::Call {
                pc: 0x300,
                target: 0xcafe,
                symbol: Some("runtime.chansend1"),
                tid: 1,
                arg0: hchan,
            },
            &ectx,
        );

        bus.run_finish(&ectx);

        let f = findings.borrow();
        assert!(
            f.is_empty(),
            "no violation expected when channel is open, got {:?}",
            f
        );
    }

    /// Close path is UNSAT (impossible constraint) → no violation.
    #[test]
    fn chancheck_no_violation_when_close_path_unsat() {
        let ctx = fresh_ctx();
        let findings = RefCell::new(Vec::new());

        let mut bus: EventBus<'_> = EventBus::new();
        bus.add(Box::new(ChanCheckPlugin::new()));

        let hchan: u64 = 0xc0004000;
        let ectx = mk_ctx(&ctx, &findings);

        for plugin in bus.plugins_mut() {
            if plugin.name() == "chancheck" {
                let p = unsafe {
                    &mut *(&mut **plugin as *mut dyn Plugin<'_> as *mut ChanCheckPlugin<'_>)
                };
                p.register_channel(hchan, 1);
            }
        }

        // Close under an impossible constraint: x == 0 AND x == 1
        let x = BV::new_const(&ctx, "data_0", 8);
        let eq0: Bool = x._eq(&BV::from_u64(&ctx, 0, 8));
        let eq1: Bool = x._eq(&BV::from_u64(&ctx, 1, 8));
        let close_phi = vec![eq0, eq1]; // UNSAT

        let ectx_close = EventCtx::new(&ctx, 0x200, 2, 0, Instant::now(), &findings)
            .with_path_constraints(&close_phi);
        bus.dispatch(
            &Event::Call {
                pc: 0x200,
                target: 0xbeef,
                symbol: Some("runtime.closechan"),
                tid: 2,
                arg0: hchan,
            },
            &ectx_close,
        );

        // Send with constraint: x == 5 (feasible)
        let send_guard: Bool = x._eq(&BV::from_u64(&ctx, 5, 8));
        let send_phi = vec![send_guard];

        let ectx_send = EventCtx::new(&ctx, 0x300, 1, 0, Instant::now(), &findings)
            .with_path_constraints(&send_phi);
        bus.dispatch(
            &Event::Call {
                pc: 0x300,
                target: 0xcafe,
                symbol: Some("runtime.chansend1"),
                tid: 1,
                arg0: hchan,
            },
            &ectx_send,
        );

        bus.run_finish(&ectx);

        let f = findings.borrow();
        assert!(
            f.is_empty(),
            "no violation expected when φ_close ∧ φ_send is UNSAT, got {:?}",
            f
        );
    }
}
