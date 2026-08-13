// SPDX-FileCopyrightText: 2026 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

//! TOCTOU detector — time-of-check-time-of-use race conditions.
//!
//! Detects patterns where a program checks an external property (file
//! attributes, process identity, permissions) and then uses the result
//! in a security-sensitive operation, with a race window between the two.
//!
//! ## Target patterns
//!
//! ### Pattern 1: `SO_PEERCRED` + `/proc/<pid>/exe` (ordain credential agent)
//!
//! ```text
//! getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred)  ← CHECK: get peer PID
//!   ... race window (PID could be recycled) ...
//! readlinkat(AT_FDCWD, "/proc/<pid>/exe", buf)     ← USE: verify binary
//! ```
//!
//! The window between getting the PID and verifying the binary allows PID
//! recycling attacks: if the original process exits and a malicious one
//! takes its PID, the `readlink` will verify the wrong binary.
//!
//! ### Pattern 2: `stat` + `open` (classic file TOCTOU)
//!
//! ```text
//! stat("/path/to/file", &st)     ← CHECK: file exists / permissions OK
//!   ... race window (file replaced via symlink/rename) ...
//! open("/path/to/file", O_RDWR)  ← USE: open the (now different) file
//! ```
//!
//! ### Pattern 3: `access` + `open`
//!
//! ```text
//! access("/path", R_OK)          ← CHECK
//! open("/path", O_RDONLY)         ← USE
//! ```
//!
//! ## Detection algorithm
//!
//! 1. Record each "check" syscall (getsockopt/SO_PEERCRED, stat, lstat,
//!    fstatat, access, faccessat, readlink) with its arguments, tid,
//!    instruction counter, and path constraints.
//!
//! 2. Record each "use" syscall (open, openat, connect, readlink on /proc/*)
//!    with its arguments.
//!
//! 3. At `on_finish`, pair each check with each subsequent use on the same
//!    resource (matched by path or PID). If the pair spans a potential
//!    context switch (different instruction counts, or a thread switch
//!    occurred between them), flag it as a TOCTOU with the race window size.
//!
//! 4. Couple with Z3: if both check and use are on the same concrete path
//!    (φ_check ∧ φ_use satisfiable), report the triggering input.
//!
//! ## Subscriptions
//!
//! - `Syscall` / `SyscallRet` — to intercept the check and use syscalls
//! - `Call` — to intercept Go wrappers (e.g. `os.Readlink`, `net.FileConn`)
//! - `ThreadSwitch` — to detect context switches in the race window

use std::collections::HashSet;

use z3::ast::Bool;
use z3::{SatResult, Solver};

use crate::plugins::context::EventCtx;
use crate::plugins::event::{Event, EventKind};
use crate::plugins::finding::{Finding, Severity};
use crate::plugins::plugin::Plugin;
use crate::plugins::verdict::Verdict;
use crate::plugins::EventBus;
use crate::teprintln;

// Linux syscall numbers (x86-64)
const SYS_STAT: u64 = 4;
const SYS_FSTAT: u64 = 5;
const SYS_LSTAT: u64 = 6;
const SYS_ACCESS: u64 = 21;
const SYS_GETSOCKOPT: u64 = 55;
const SYS_READLINK: u64 = 89;
const SYS_OPENAT: u64 = 257;
const SYS_READLINKAT: u64 = 267;
const SYS_FACCESSAT: u64 = 269;
const SYS_NEWFSTATAT: u64 = 262;

// Socket options
const SOL_SOCKET: u64 = 1;
const SO_PEERCRED: u64 = 17;

/// Classification of a syscall's role in a TOCTOU pair.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ToctouRole {
    /// A "check" operation that retrieves a property.
    Check(CheckKind),
    /// A "use" operation that acts on a previously checked property.
    Use(UseKind),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CheckKind {
    /// `getsockopt(fd, SOL_SOCKET, SO_PEERCRED)` — retrieves peer PID
    PeerCred { fd: u64 },
    /// `stat`/`lstat`/`fstatat` on a path
    Stat { path: String },
    /// `access`/`faccessat` on a path
    Access { path: String },
    /// `readlink`/`readlinkat` on a /proc path (checking identity)
    ReadlinkProc { path: String, pid: Option<u32> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
enum UseKind {
    /// `openat` on the same path that was stat'd / access'd
    Open { path: String },
    /// `readlinkat` on `/proc/<pid>/exe` after getsockopt(SO_PEERCRED)
    ReadlinkExe { path: String, pid: Option<u32> },
    /// `connect` to a resource after checking peer identity
    Connect { fd: u64 },
}

/// One recorded event in the TOCTOU timeline.
#[derive(Debug, Clone)]
struct ToctouEvent<'ctx> {
    role: ToctouRole,
    syscall_nr: u64,
    tid: u64,
    pc: u64,
    instruction_counter: usize,
    path_phi: Vec<Bool<'ctx>>,
}

/// The TOCTOU detector plugin.
pub struct ToctouPlugin<'ctx> {
    events: Vec<ToctouEvent<'ctx>>,
    /// Track thread switches to detect interleaving opportunities.
    thread_switches: Vec<(usize, u64, u64)>, // (instruction_counter, from_tid, to_tid)
    verbose: bool,
    violations_found: u64,
    reported_use_indices: Vec<usize>,
}

impl<'ctx> ToctouPlugin<'ctx> {
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            thread_switches: Vec::new(),
            verbose: !std::env::var("TOCTOU_VERBOSE").is_ok_and(|v| v == "0"),
            violations_found: 0,
            reported_use_indices: Vec::new(),
        }
    }

    fn vlog(&self, msg: impl AsRef<str>) {
        if self.verbose {
            teprintln!();
            teprintln!("[TOCTOU] {}", msg.as_ref());
            teprintln!();
        }
    }

    /// Write a finding to disk immediately so it persists even if the
    /// process is killed before on_finish/finalize runs.
    fn write_finding_to_disk(&self, finding: &Finding) {
        use std::io::Write;
        let _ = std::fs::create_dir_all("results");
        let path = "results/plugin_findings.txt";
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)
            .ok();
        if let Some(ref mut file) = f {
            let _ = writeln!(file, "# zorya plugin findings");
            let _ = writeln!(file, "# {} finding(s)\n", self.violations_found);
            let _ = writeln!(
                file,
                "[{}::{}] {} (pc=0x{:x}, severity={:?})",
                finding.plugin, finding.rule, finding.title, finding.pc, finding.severity
            );
            for d in &finding.details {
                let _ = writeln!(file, "    {}", d);
            }
        }
        // Also print to terminal for immediate user visibility (uses teprintln
        // so the coverage bar is properly handled)
        teprintln!();
        teprintln!(
            "[TOCTOU] *** BUG / VULNERABILITY DETECTED: {} ***",
            finding.title
        );
        teprintln!();
    }

    /// Classify a syscall as check, use, or irrelevant.
    fn classify_syscall(nr: u64, args: &[u64; 6], path_hint: Option<&str>) -> Option<ToctouRole> {
        match nr {
            SYS_GETSOCKOPT => {
                // getsockopt(fd, level, optname, optval, optlen)
                let level = args[1];
                let optname = args[2];
                if level == SOL_SOCKET && optname == SO_PEERCRED {
                    Some(ToctouRole::Check(CheckKind::PeerCred { fd: args[0] }))
                } else {
                    None
                }
            }
            SYS_STAT | SYS_LSTAT | SYS_FSTAT | SYS_NEWFSTATAT => {
                let path = path_hint.unwrap_or("<unknown>").to_string();
                Some(ToctouRole::Check(CheckKind::Stat { path }))
            }
            SYS_ACCESS | SYS_FACCESSAT => {
                let path = path_hint.unwrap_or("<unknown>").to_string();
                Some(ToctouRole::Check(CheckKind::Access { path }))
            }
            SYS_READLINK | SYS_READLINKAT => {
                let path = path_hint.unwrap_or("").to_string();
                if path.contains("/proc/") && path.contains("/exe") {
                    // Resolved path confirms /proc/<pid>/exe
                    let pid = Self::extract_pid_from_proc_path(&path);
                    Some(ToctouRole::Use(UseKind::ReadlinkExe { path, pid }))
                } else if path.starts_with("/proc/") {
                    let pid = Self::extract_pid_from_proc_path(&path);
                    Some(ToctouRole::Check(CheckKind::ReadlinkProc { path, pid }))
                } else if path.starts_with("<ptr:") || path.is_empty() {
                    // Path is unresolved (raw pointer from memory). In the context
                    // of a preceding SO_PEERCRED check, any readlinkat is likely
                    // reading /proc/<pid>/exe. Classify it as a USE and let
                    // is_toctou_pair() match it against prior PeerCred checks.
                    Some(ToctouRole::Use(UseKind::ReadlinkExe { path, pid: None }))
                } else {
                    None
                }
            }
            SYS_OPENAT => {
                let path = path_hint.unwrap_or("<unknown>").to_string();
                Some(ToctouRole::Use(UseKind::Open { path }))
            }
            _ => None,
        }
    }

    /// Extract PID from a `/proc/<pid>/...` path.
    fn extract_pid_from_proc_path(path: &str) -> Option<u32> {
        let parts: Vec<&str> = path.split('/').collect();
        if parts.len() >= 3 && parts[1] == "proc" {
            parts[2].parse().ok()
        } else {
            None
        }
    }

    /// Check if two events form a TOCTOU pair.
    /// Temporal ordering is enforced by the caller (check recorded before use).
    fn is_toctou_pair(check: &ToctouEvent<'ctx>, use_ev: &ToctouEvent<'ctx>) -> bool {
        match (&check.role, &use_ev.role) {
            // SO_PEERCRED → readlink(/proc/<pid>/exe)
            (
                ToctouRole::Check(CheckKind::PeerCred { .. }),
                ToctouRole::Use(UseKind::ReadlinkExe { .. }),
            ) => true,

            // stat/access → open on same path
            (
                ToctouRole::Check(CheckKind::Stat { path: check_path }),
                ToctouRole::Use(UseKind::Open { path: use_path }),
            ) => check_path == use_path,
            (
                ToctouRole::Check(CheckKind::Access { path: check_path }),
                ToctouRole::Use(UseKind::Open { path: use_path }),
            ) => check_path == use_path,

            // readlink(/proc) as check → open as use
            (
                ToctouRole::Check(CheckKind::ReadlinkProc {
                    path: check_path, ..
                }),
                ToctouRole::Use(UseKind::Open { path: use_path }),
            ) => check_path == use_path || use_path.contains("/proc/"),

            _ => false,
        }
    }

    /// Did a thread switch happen between two instruction counters?
    fn had_thread_switch_between(&self, from_ic: usize, to_ic: usize) -> bool {
        self.thread_switches
            .iter()
            .any(|(ic, _, _)| *ic > from_ic && *ic < to_ic)
    }

    /// Append attack narrative, reproduction steps, and mitigation to a finding.
    fn add_attack_narrative(
        finding: Finding,
        check: &ToctouEvent<'_>,
        use_ev: &ToctouEvent<'_>,
        _window_size: usize,
    ) -> Finding {
        let mut f = finding;

        match (&check.role, &use_ev.role) {
            // ── SO_PEERCRED → readlink(/proc/<pid>/exe) ──────────────────
            (
                ToctouRole::Check(CheckKind::PeerCred { fd }),
                ToctouRole::Use(UseKind::ReadlinkExe { .. }),
            ) => {
                f = f.with_detail(String::new());
                f = f.with_detail("─── ATTACK NARRATIVE ───".to_string());
                f = f.with_detail(format!(
                    "The program obtains the peer PID via getsockopt(fd={}, SOL_SOCKET, SO_PEERCRED) \
                     and then verifies the peer's identity by reading /proc/<pid>/exe. Between these \
                     two operations, the PID can be recycled by the kernel if the original peer exits.",
                    fd
                ));
                f = f.with_detail(String::new());
                f = f.with_detail("─── REPRODUCTION STEPS ───".to_string());
                f = f.with_detail(
                    "1. Attacker connects to the Unix socket from a legitimate process (PID N)."
                        .to_string(),
                );
                f = f.with_detail(
                    "2. Server calls getsockopt(SO_PEERCRED) → obtains PID N.".to_string(),
                );
                f = f.with_detail(
                    "3. Attacker kills PID N (process exits, PID becomes available for reuse)."
                        .to_string(),
                );
                f = f.with_detail(
                    "4. Attacker rapidly fork-execs a malicious binary in a loop until it \
                     claims PID N (feasible: default pid_max=32768, ~16K forks to cycle)."
                        .to_string(),
                );
                f = f.with_detail(
                    "5. Server calls readlink(\"/proc/N/exe\") → reads the MALICIOUS binary \
                     path instead of the original legitimate one."
                        .to_string(),
                );
                f = f.with_detail(
                    "6. Server grants credentials/access based on the forged identity.".to_string(),
                );
                f = f.with_detail(String::new());
                f = f.with_detail("─── EXPLOITABILITY ───".to_string());
                f = f.with_detail(
                    "Difficulty: MEDIUM. Requires local access to the Unix socket and ability \
                     to fork processes. Success probability increases with race window size \
                     and decreases with system load (more PID churn = faster recycling)."
                        .to_string(),
                );
                f = f.with_detail(
                    "On Linux, /proc/sys/kernel/pid_max defaults to 32768. An attacker can \
                     exhaust the PID space in <1s with clone()/fork() loops, making PID \
                     recycling near-deterministic."
                        .to_string(),
                );
                f = f.with_detail(String::new());
                f = f.with_detail("─── MITIGATION ───".to_string());
                f = f.with_detail(
                    "1. Use pidfd_open(pid) immediately after getsockopt to obtain a stable \
                     reference to the peer process. Then use pidfd_getfd() or \
                     /proc/self/fdinfo/<pidfd> to verify identity — the pidfd remains valid \
                     even if the PID is recycled."
                        .to_string(),
                );
                f = f.with_detail(
                    "2. Hold the peer's socket fd open during verification — the kernel \
                     prevents PID reuse while a socket reference keeps the peer's task_struct \
                     alive (SO_PEERCRED returns the PID at connect-time, not at getsockopt-time \
                     on some kernels; verify your kernel version)."
                        .to_string(),
                );
                f = f.with_detail(
                    "3. Use SCM_CREDENTIALS with ancillary messages: the kernel fills the PID \
                     atomically at sendmsg time, and the receiving end can verify against \
                     /proc/<pid>/exe in the same syscall context."
                        .to_string(),
                );
                f = f.with_detail(
                    "4. Perform the readlink and identity check inside a pidfd-guarded section: \
                     pidfd_open(pid) → readlink → compare → close(pidfd). If pidfd_open fails \
                     (PID already recycled), reject the connection."
                        .to_string(),
                );
            }

            // ── stat/access → open (classic file TOCTOU) ─────────────────
            (
                ToctouRole::Check(CheckKind::Stat { path }),
                ToctouRole::Use(UseKind::Open { .. }),
            )
            | (
                ToctouRole::Check(CheckKind::Access { path }),
                ToctouRole::Use(UseKind::Open { .. }),
            ) => {
                f = f.with_detail(String::new());
                f = f.with_detail("─── ATTACK NARRATIVE ───".to_string());
                f = f.with_detail(format!(
                    "The program checks properties of '{}' (permissions, existence, type) \
                     and then opens it. Between check and use, an attacker can replace the \
                     file with a symlink or different file (symlink swap / rename attack).",
                    path
                ));
                f = f.with_detail(String::new());
                f = f.with_detail("─── REPRODUCTION STEPS ───".to_string());
                f = f.with_detail(format!("1. Create a legitimate file at '{}'.", path));
                f = f.with_detail(
                    "2. Wait for the program to perform the stat/access check.".to_string(),
                );
                f = f.with_detail(format!(
                    "3. Immediately after the check, replace '{}' with a symlink \
                     pointing to /etc/shadow (or another sensitive target).",
                    path
                ));
                f = f.with_detail(
                    "4. The program opens the symlink target instead of the original file."
                        .to_string(),
                );
                f = f.with_detail(String::new());
                f = f.with_detail("─── MITIGATION ───".to_string());
                f = f.with_detail(
                    "1. Use open() with O_NOFOLLOW and then fstat() on the fd — never \
                     stat then open separately."
                        .to_string(),
                );
                f = f.with_detail(
                    "2. Use openat() relative to a directory fd obtained with O_PATH|O_DIRECTORY \
                     to confine resolution to the expected directory."
                        .to_string(),
                );
                f = f.with_detail(
                    "3. Drop check entirely: open the file, then verify properties via \
                     fstat(fd) on the already-opened fd."
                        .to_string(),
                );
            }

            // ── Generic fallback ─────────────────────────────────────────
            _ => {
                f = f.with_detail(String::new());
                f = f.with_detail("─── ATTACK NARRATIVE ───".to_string());
                f = f.with_detail(
                    "A security-relevant property is checked and then used in a separate \
                     operation. Between the check and use, an external actor can modify the \
                     underlying resource, causing the program to act on stale/forged data."
                        .to_string(),
                );
                f = f.with_detail(String::new());
                f = f.with_detail("─── MITIGATION ───".to_string());
                f = f.with_detail(
                    "Combine the check and use into a single atomic operation, or use \
                     kernel-level file descriptors (fds, pidfds) that provide stable \
                     references immune to name-based races."
                        .to_string(),
                );
            }
        }

        f
    }
}

impl<'ctx> Default for ToctouPlugin<'ctx> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'ctx> Plugin<'ctx> for ToctouPlugin<'ctx> {
    fn name(&self) -> &'static str {
        "toctou"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn wants(&self) -> HashSet<EventKind> {
        [
            EventKind::Syscall,
            EventKind::SyscallRet,
            EventKind::Call,
            EventKind::ThreadSwitch,
        ]
        .into_iter()
        .collect()
    }

    fn on_event(&mut self, ev: &Event<'ctx, '_>, ctx: &EventCtx<'ctx, '_>) -> Verdict {
        match ev {
            Event::Syscall { nr, args, tid, pc } => {
                // Try to classify this syscall
                let path_hint = match *nr {
                    SYS_READLINK | SYS_READLINKAT | SYS_STAT | SYS_LSTAT | SYS_ACCESS
                    | SYS_FACCESSAT | SYS_OPENAT | SYS_NEWFSTATAT => {
                        let ptr = if *nr == SYS_OPENAT
                            || *nr == SYS_READLINKAT
                            || *nr == SYS_FACCESSAT
                            || *nr == SYS_NEWFSTATAT
                        {
                            args[1] // second arg for *at variants (first is dirfd)
                        } else {
                            args[0]
                        };
                        Some(format!("<ptr:0x{:x}>", ptr))
                    }
                    _ => None,
                };

                if let Some(role) = Self::classify_syscall(*nr, args, path_hint.as_deref()) {
                    let is_use = matches!(role, ToctouRole::Use(_));
                    self.vlog(format!(
                        "Recorded {:?} at pc=0x{:x} tid={} ic={}",
                        role, pc, tid, ctx.instruction_counter
                    ));
                    self.events.push(ToctouEvent {
                        role,
                        syscall_nr: *nr,
                        tid: *tid,
                        pc: *pc,
                        instruction_counter: ctx.instruction_counter,
                        path_phi: ctx.path_constraints().to_vec(),
                    });

                    // Immediate check: if we just recorded a Use, try to pair it
                    // with any prior Check and emit a finding NOW.
                    if is_use {
                        let use_idx = self.events.len() - 1;
                        for ci in 0..use_idx {
                            let check = &self.events[ci];
                            if !matches!(check.role, ToctouRole::Check(_)) {
                                continue;
                            }
                            if !Self::is_toctou_pair(check, &self.events[use_idx]) {
                                continue;
                            }
                            let had_switch = self.had_thread_switch_between(
                                check.instruction_counter,
                                self.events[use_idx].instruction_counter,
                            );

                            // Z3 feasibility
                            let feasible = {
                                let mut parts: Vec<&Bool<'ctx>> = Vec::new();
                                parts.extend(self.events[ci].path_phi.iter());
                                parts.extend(self.events[use_idx].path_phi.iter());
                                if parts.is_empty() {
                                    true
                                } else {
                                    let solver = Solver::new(ctx.ctx);
                                    for p in &parts {
                                        solver.assert(p);
                                    }
                                    matches!(solver.check(), SatResult::Sat)
                                }
                            };
                            if !feasible {
                                continue;
                            }

                            self.violations_found += 1;
                            self.reported_use_indices.push(use_idx);
                            let check = &self.events[ci];
                            let use_ev = &self.events[use_idx];
                            let window_size =
                                if use_ev.instruction_counter > check.instruction_counter {
                                    use_ev.instruction_counter - check.instruction_counter
                                } else {
                                    use_idx - ci
                                };

                            let check_desc = match &check.role {
                                ToctouRole::Check(k) => format!("{:?}", k),
                                _ => unreachable!(),
                            };
                            let use_desc = match &use_ev.role {
                                ToctouRole::Use(k) => format!("{:?}", k),
                                _ => unreachable!(),
                            };

                            let severity = if had_switch {
                                Severity::Critical
                            } else {
                                Severity::High
                            };

                            let title = format!(
                                "TOCTOU: {} → {} (window={} insns, switch={})",
                                check_desc, use_desc, window_size, had_switch
                            );

                            let mut finding = Finding::new(
                                "toctou",
                                "check-use-race",
                                severity,
                                use_ev.pc,
                                title.clone(),
                            )
                            .with_detail(format!(
                                "Check: syscall {} at pc=0x{:x}, tid={}, ic={}",
                                check.syscall_nr, check.pc, check.tid, check.instruction_counter
                            ))
                            .with_detail(format!(
                                "Use: syscall {} at pc=0x{:x}, tid={}, ic={}",
                                use_ev.syscall_nr,
                                use_ev.pc,
                                use_ev.tid,
                                use_ev.instruction_counter
                            ))
                            .with_detail(format!(
                                "Race window: {} instructions ({} thread switches in window)",
                                window_size,
                                self.thread_switches
                                    .iter()
                                    .filter(|(ic, _, _)| {
                                        *ic > check.instruction_counter
                                            && *ic < use_ev.instruction_counter
                                    })
                                    .count()
                            ));

                            if had_switch {
                                finding = finding.with_detail(
                                    "EXPLOITABLE: A thread switch occurred in the race window, \
                                     demonstrating that the interleaving is reachable."
                                        .to_string(),
                                );
                            } else if check.tid != use_ev.tid {
                                finding = finding.with_detail(
                                    "Cross-goroutine check→use: check and use on different threads \
                                     (vulnerable if attacker can influence scheduling)."
                                        .to_string(),
                                );
                            } else {
                                finding = finding.with_detail(
                                    "Same-thread check→use: exploitable if an external actor can \
                                     modify the resource in the race window (e.g. PID recycling, \
                                     symlink swap)."
                                        .to_string(),
                                );
                            }

                            // Z3 model for triggering input
                            if !check.path_phi.is_empty() || !use_ev.path_phi.is_empty() {
                                let solver = Solver::new(ctx.ctx);
                                for p in &check.path_phi {
                                    solver.assert(p);
                                }
                                for p in &use_ev.path_phi {
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
                                        if !model_str.is_empty() {
                                            finding = finding.with_detail(format!(
                                                "Triggering input: {}",
                                                model_str
                                            ));
                                        }
                                    }
                                }
                            }

                            // Attack narrative and reproduction steps
                            finding =
                                Self::add_attack_narrative(finding, check, use_ev, window_size);

                            // Write finding immediately to disk so it persists even
                            // if the process is killed before on_finish.
                            self.write_finding_to_disk(&finding);

                            ctx.findings.borrow_mut().push(finding);
                        }
                    }
                }
            }
            Event::Call {
                symbol: Some(sym),
                tid,
                arg0,
                ..
            } => {
                let name = *sym;
                if name == "syscall.Getsockopt" || name == "net.(*netFD).getsockopt" {
                    self.vlog(format!("Go getsockopt wrapper at tid={}", tid));
                } else if name == "os.Readlink" || name == "syscall.Readlink" {
                    self.vlog(format!(
                        "Go Readlink wrapper at tid={} arg0=0x{:x}",
                        tid, arg0
                    ));
                } else if name == "os.Stat" || name == "os.Lstat" || name == "syscall.Stat" {
                    self.vlog(format!("Go stat wrapper at tid={}", tid));
                }
            }
            Event::ThreadSwitch { from, to } => {
                self.thread_switches
                    .push((ctx.instruction_counter, *from, *to));
                self.vlog(format!(
                    "Thread switch: {} → {} at ic={}",
                    from, to, ctx.instruction_counter
                ));
            }
            _ => {}
        }
        Verdict::Continue
    }

    fn on_finish(&mut self, ctx: &EventCtx<'ctx, '_>) {
        // Sweep for any unreported check→use pairs (handles events injected
        // directly into `self.events` without going through on_event).
        for use_idx in 0..self.events.len() {
            if self.reported_use_indices.contains(&use_idx) {
                continue;
            }
            if !matches!(&self.events[use_idx].role, ToctouRole::Use(_)) {
                continue;
            }
            for ci in (0..use_idx).rev() {
                if !matches!(&self.events[ci].role, ToctouRole::Check(_)) {
                    continue;
                }
                if !Self::is_toctou_pair(&self.events[ci], &self.events[use_idx]) {
                    continue;
                }
                let had_switch = self.had_thread_switch_between(
                    self.events[ci].instruction_counter,
                    self.events[use_idx].instruction_counter,
                );
                // Z3 feasibility
                let feasible = {
                    let mut parts: Vec<&Bool<'ctx>> = Vec::new();
                    parts.extend(self.events[ci].path_phi.iter());
                    parts.extend(self.events[use_idx].path_phi.iter());
                    if parts.is_empty() {
                        true
                    } else {
                        let solver = Solver::new(ctx.ctx);
                        for p in &parts {
                            solver.assert(p);
                        }
                        matches!(solver.check(), SatResult::Sat)
                    }
                };
                if !feasible {
                    continue;
                }

                self.violations_found += 1;
                let check = &self.events[ci];
                let use_ev = &self.events[use_idx];
                let window_size = if use_ev.instruction_counter > check.instruction_counter {
                    use_ev.instruction_counter - check.instruction_counter
                } else {
                    use_idx - ci
                };

                let check_desc = match &check.role {
                    ToctouRole::Check(k) => format!("{:?}", k),
                    _ => unreachable!(),
                };
                let use_desc = match &use_ev.role {
                    ToctouRole::Use(k) => format!("{:?}", k),
                    _ => unreachable!(),
                };

                let severity = if had_switch {
                    Severity::Critical
                } else {
                    Severity::High
                };

                let title = format!(
                    "TOCTOU: {} → {} (window={} insns, switch={})",
                    check_desc, use_desc, window_size, had_switch
                );

                let mut finding = Finding::new(
                    "toctou",
                    "check-use-race",
                    severity,
                    use_ev.pc,
                    title.clone(),
                )
                .with_detail(format!(
                    "Check: syscall {} at pc=0x{:x}, tid={}, ic={}",
                    check.syscall_nr, check.pc, check.tid, check.instruction_counter
                ))
                .with_detail(format!(
                    "Use: syscall {} at pc=0x{:x}, tid={}, ic={}",
                    use_ev.syscall_nr, use_ev.pc, use_ev.tid, use_ev.instruction_counter
                ))
                .with_detail(format!(
                    "Race window: {} instructions ({} thread switches in window)",
                    window_size,
                    self.thread_switches
                        .iter()
                        .filter(|(ic, _, _)| {
                            *ic > check.instruction_counter && *ic < use_ev.instruction_counter
                        })
                        .count()
                ));

                if had_switch {
                    finding = finding.with_detail(
                        "EXPLOITABLE: A thread switch occurred in the race window, \
                         demonstrating that the interleaving is reachable."
                            .to_string(),
                    );
                } else if check.tid != use_ev.tid {
                    finding = finding.with_detail(
                        "Cross-goroutine check→use: check and use on different threads \
                         (vulnerable if attacker can influence scheduling)."
                            .to_string(),
                    );
                } else {
                    finding = finding.with_detail(
                        "Same-thread check→use: exploitable if an external actor can \
                         modify the resource in the race window (e.g. PID recycling, \
                         symlink swap)."
                            .to_string(),
                    );
                }

                finding = Self::add_attack_narrative(finding, check, use_ev, window_size);
                self.write_finding_to_disk(&finding);
                ctx.findings.borrow_mut().push(finding);
                break;
            }
        }

        if self.violations_found > 0 {
            teprintln!(
                "[TOCTOU] {} TOCTOU violation(s) detected",
                self.violations_found
            );
        } else {
            teprintln!("[TOCTOU] No TOCTOU violations found ({} check/use events, {} thread switches observed)",
                self.events.len(),
                self.thread_switches.len()
            );
        }
    }
}
/// Factory called from registry when the `plugin-toctou` feature is enabled.
pub fn register<'ctx>(bus: &mut EventBus<'ctx>) {
    bus.add(Box::new(ToctouPlugin::new()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::context::EventCtx;
    use crate::plugins::event::Event;
    use crate::plugins::finding::Finding;
    use std::cell::RefCell;
    use std::time::Instant;
    use z3::{Config, Context};

    fn fresh_ctx() -> Context {
        Context::new(&Config::new())
    }

    fn mk_ctx<'ctx, 's>(
        ctx: &'ctx Context,
        findings: &'s RefCell<Vec<Finding>>,
        ic: usize,
        tid: u64,
    ) -> EventCtx<'ctx, 's> {
        let mut ectx = EventCtx::new(ctx, 0x1000, tid, ic, Instant::now(), findings);
        ectx.current_tid = tid;
        ectx
    }

    /// SO_PEERCRED → readlink(/proc/pid/exe) pattern: same thread, no switch
    #[test]
    fn toctou_detects_peercred_readlink_pair() {
        let ctx = fresh_ctx();
        let findings = RefCell::new(Vec::new());

        let mut bus: EventBus<'_> = EventBus::new();
        bus.add(Box::new(ToctouPlugin::new()));

        // getsockopt(fd=3, SOL_SOCKET, SO_PEERCRED, ...)
        let ectx1 = mk_ctx(&ctx, &findings, 100, 1);
        bus.dispatch(
            &Event::Syscall {
                nr: SYS_GETSOCKOPT,
                args: [3, SOL_SOCKET, SO_PEERCRED, 0x1000, 0x1008, 0],
                pc: 0x4000,
                tid: 1,
            },
            &ectx1,
        );

        // readlinkat(AT_FDCWD, "/proc/42/exe", buf, bufsz) - classified as Use
        // We simulate this by directly injecting a classified event since we
        // can't resolve paths from pointers in unit tests.
        for plugin in bus.plugins_mut() {
            if plugin.name() == "toctou" {
                let p = unsafe {
                    &mut *(&mut **plugin as *mut dyn Plugin<'_> as *mut ToctouPlugin<'_>)
                };
                p.events.push(ToctouEvent {
                    role: ToctouRole::Use(UseKind::ReadlinkExe {
                        path: "/proc/42/exe".to_string(),
                        pid: Some(42),
                    }),
                    syscall_nr: SYS_READLINKAT,
                    tid: 1,
                    pc: 0x4100,
                    instruction_counter: 200,
                    path_phi: Vec::new(),
                });
                break;
            }
        }

        let ectx_finish = mk_ctx(&ctx, &findings, 300, 1);
        bus.run_finish(&ectx_finish);

        let f = findings.borrow();
        assert!(
            !f.is_empty(),
            "expected TOCTOU finding for peercred→readlink"
        );
        assert!(
            f.iter().any(|x| x.rule == "check-use-race"),
            "expected check-use-race rule"
        );
    }

    /// stat → open on same path
    #[test]
    fn toctou_detects_stat_open_pair() {
        let ctx = fresh_ctx();
        let findings = RefCell::new(Vec::new());

        let mut bus: EventBus<'_> = EventBus::new();
        bus.add(Box::new(ToctouPlugin::new()));

        // Inject pre-classified events (in real execution, the path would be
        // resolved from memory by the syscall handler)
        for plugin in bus.plugins_mut() {
            if plugin.name() == "toctou" {
                let p = unsafe {
                    &mut *(&mut **plugin as *mut dyn Plugin<'_> as *mut ToctouPlugin<'_>)
                };
                p.events.push(ToctouEvent {
                    role: ToctouRole::Check(CheckKind::Stat {
                        path: "/etc/shadow".to_string(),
                    }),
                    syscall_nr: SYS_STAT,
                    tid: 1,
                    pc: 0x5000,
                    instruction_counter: 50,
                    path_phi: Vec::new(),
                });
                p.events.push(ToctouEvent {
                    role: ToctouRole::Use(UseKind::Open {
                        path: "/etc/shadow".to_string(),
                    }),
                    syscall_nr: SYS_OPENAT,
                    tid: 1,
                    pc: 0x5100,
                    instruction_counter: 150,
                    path_phi: Vec::new(),
                });
                break;
            }
        }

        let ectx_finish = mk_ctx(&ctx, &findings, 200, 1);
        bus.run_finish(&ectx_finish);

        let f = findings.borrow();
        assert!(!f.is_empty(), "expected stat→open TOCTOU finding");
    }

    /// No use after check → no finding
    #[test]
    fn toctou_no_finding_without_use() {
        let ctx = fresh_ctx();
        let findings = RefCell::new(Vec::new());

        let mut bus: EventBus<'_> = EventBus::new();
        bus.add(Box::new(ToctouPlugin::new()));

        // Only a check, no subsequent use
        let ectx1 = mk_ctx(&ctx, &findings, 100, 1);
        bus.dispatch(
            &Event::Syscall {
                nr: SYS_GETSOCKOPT,
                args: [3, SOL_SOCKET, SO_PEERCRED, 0x1000, 0x1008, 0],
                pc: 0x4000,
                tid: 1,
            },
            &ectx1,
        );

        let ectx_finish = mk_ctx(&ctx, &findings, 200, 1);
        bus.run_finish(&ectx_finish);

        let f = findings.borrow();
        assert!(
            f.is_empty(),
            "no finding expected without a use after check"
        );
    }

    /// Thread switch in the window escalates severity to Critical
    #[test]
    fn toctou_escalates_with_thread_switch() {
        let ctx = fresh_ctx();
        let findings = RefCell::new(Vec::new());

        let mut bus: EventBus<'_> = EventBus::new();
        bus.add(Box::new(ToctouPlugin::new()));

        for plugin in bus.plugins_mut() {
            if plugin.name() == "toctou" {
                let p = unsafe {
                    &mut *(&mut **plugin as *mut dyn Plugin<'_> as *mut ToctouPlugin<'_>)
                };
                p.events.push(ToctouEvent {
                    role: ToctouRole::Check(CheckKind::PeerCred { fd: 3 }),
                    syscall_nr: SYS_GETSOCKOPT,
                    tid: 1,
                    pc: 0x4000,
                    instruction_counter: 100,
                    path_phi: Vec::new(),
                });
                // Thread switch in the window
                p.thread_switches.push((150, 1, 2));
                p.events.push(ToctouEvent {
                    role: ToctouRole::Use(UseKind::ReadlinkExe {
                        path: "/proc/42/exe".to_string(),
                        pid: Some(42),
                    }),
                    syscall_nr: SYS_READLINKAT,
                    tid: 1,
                    pc: 0x4100,
                    instruction_counter: 200,
                    path_phi: Vec::new(),
                });
                break;
            }
        }

        let ectx_finish = mk_ctx(&ctx, &findings, 300, 1);
        bus.run_finish(&ectx_finish);

        let f = findings.borrow();
        assert!(!f.is_empty(), "expected TOCTOU finding");
        let finding = &f[0];
        assert_eq!(finding.severity, Severity::Critical);
        let detail_blob = finding.details.join("\n");
        assert!(
            detail_blob.contains("EXPLOITABLE"),
            "should mention exploitability when switch occurred"
        );
    }
}
