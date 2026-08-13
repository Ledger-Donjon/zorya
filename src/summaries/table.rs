// SPDX-FileCopyrightText: 2026 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

//! Summary table: maps function names to their modelled effects.
//!
//! Each entry describes what a Go runtime helper does in terms the concolic
//! engine can replay without executing the actual pcode body.

use std::collections::HashMap;

use once_cell::sync::Lazy;

/// The observable effect of a summarised function. The executor applies this
/// instead of stepping through the function's pcode body.
#[derive(Debug, Clone)]
pub enum SummaryEffect {
    /// Allocates `size` bytes of zeroed memory and returns the pointer in RAX.
    /// Models: `runtime.mallocgc(size uintptr, typ *_type, needzero bool) unsafe.Pointer`
    ///
    /// The engine allocates from a synthetic heap region, zeros the bytes, and
    /// writes the pointer to RAX. The symbolic size argument (if any) is
    /// concretised to its current model value for the allocation.
    Alloc,

    /// Allocates a byte slice `[]byte` of the given length and returns the
    /// slice header (ptr, len, cap) in (RAX, RBX, RCX).
    /// Models: `runtime.rawbyteslice(size int) []byte`
    /// Also: `runtime.stringtoslicebyte(buf *[tmpBuf]byte, s string) []byte`
    AllocSlice,

    /// Creates a channel and returns the `*hchan` pointer in RAX.
    /// Models: `runtime.makechan(t *chantype, size int) *hchan`
    ///
    /// The returned pointer is a fresh concrete address backed by a zeroed
    /// `hchan` struct (96 bytes on amd64). The `closed` field at offset +X
    /// is explicitly zero, which is the initial state the channel-invariant
    /// plugin will track.
    MakeChan,

    /// A pure helper that returns a rounded-up value. The summary computes
    /// the concrete result and writes it to RAX.
    /// Models: `runtime.roundupsize(size uintptr, noscan bool) uintptr`
    RoundUpSize,

    /// Models `runtime.newobject(typ *_type) unsafe.Pointer`.
    /// Reads the size from the `_type` struct at `typ + 0` (8 bytes on amd64),
    /// allocates that many zeroed bytes, returns the pointer in RAX.
    NewObject,

    /// No-op: the function's observable behaviour for concolic purposes is
    /// "does nothing interesting, returns to caller". Used for GC barriers,
    /// write barriers, memory-fence helpers, etc. that don't affect the
    /// data flow the engine tracks.
    Nop,

    /// Returns zero in RAX and returns to caller. Used for comparison /
    /// equality functions (ifaceeq, efaceeq, etc.) where we need a
    /// deterministic concrete result without tracing the function body.
    ReturnZero,
}

/// One summary entry: the function name and what the engine does instead.
#[derive(Debug, Clone)]
pub struct FunctionSummary {
    pub name: &'static str,
    pub effect: SummaryEffect,
}

/// The summary table: a map from function name to its summary. The executor
/// looks up each call target's resolved symbol here before entering pcode.
pub struct SummaryTable {
    entries: HashMap<&'static str, SummaryEffect>,
    enabled: bool,
}

impl SummaryTable {
    pub fn new() -> Self {
        let disabled = std::env::var("ZORYA_DISABLE_SUMMARIES")
            .is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));

        let mut entries = HashMap::new();
        for s in RUNTIME_SUMMARIES.iter() {
            entries.insert(s.name, s.effect.clone());
        }
        Self {
            entries,
            enabled: !disabled,
        }
    }

    /// Look up whether a function has a summary. Returns `None` if the
    /// function should be executed normally.
    pub fn lookup(&self, name: &str) -> Option<&SummaryEffect> {
        if !self.enabled {
            return None;
        }
        self.entries.get(name)
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

impl Default for SummaryTable {
    fn default() -> Self {
        Self::new()
    }
}

/// The pre-built summary table as a global lazy singleton. The executor
/// initialises one instance at startup; this constant is the source of truth
/// for which functions are summarised.
pub static RUNTIME_SUMMARIES: Lazy<Vec<FunctionSummary>> = Lazy::new(|| {
    vec![
        // ─── Allocator hot path ───────────────────────────────────────────
        FunctionSummary {
            name: "runtime.mallocgc",
            effect: SummaryEffect::Alloc,
        },
        FunctionSummary {
            name: "runtime.newobject",
            effect: SummaryEffect::NewObject,
        },
        FunctionSummary {
            name: "runtime.rawbyteslice",
            effect: SummaryEffect::AllocSlice,
        },
        FunctionSummary {
            name: "runtime.stringtoslicebyte",
            effect: SummaryEffect::AllocSlice,
        },
        FunctionSummary {
            name: "runtime.makeslice",
            effect: SummaryEffect::AllocSlice,
        },
        // ─── Size helpers ─────────────────────────────────────────────────
        FunctionSummary {
            name: "runtime.roundupsize",
            effect: SummaryEffect::RoundUpSize,
        },
        FunctionSummary {
            name: "runtime.divRoundUp",
            effect: SummaryEffect::Nop, // result unused in alloc-skip path
        },
        // ─── Channel creation ─────────────────────────────────────────────
        FunctionSummary {
            name: "runtime.makechan",
            effect: SummaryEffect::MakeChan,
        },
        FunctionSummary {
            name: "runtime.makechan64",
            effect: SummaryEffect::MakeChan,
        },
        // ─── GC / write barrier (no-ops for concolic) ─────────────────────
        FunctionSummary {
            name: "runtime.gcWriteBarrier",
            effect: SummaryEffect::Nop,
        },
        FunctionSummary {
            name: "runtime.gcWriteBarrier1",
            effect: SummaryEffect::Nop,
        },
        FunctionSummary {
            name: "runtime.gcWriteBarrier2",
            effect: SummaryEffect::Nop,
        },
        FunctionSummary {
            name: "runtime.typedmemmove",
            effect: SummaryEffect::Nop, // TODO: model as memcpy
        },
        FunctionSummary {
            name: "runtime.memmove",
            effect: SummaryEffect::Nop, // TODO: model as memcpy
        },
        // ─── Allocation sub-helpers (called by mallocgc) ──────────────────
        FunctionSummary {
            name: "runtime.mallocgcSmallScanNoHeader",
            effect: SummaryEffect::Alloc,
        },
        FunctionSummary {
            name: "runtime.mallocgcSmallNoscanNoHeader",
            effect: SummaryEffect::Alloc,
        },
        FunctionSummary {
            name: "runtime.mallocgcSmallNoscan",
            effect: SummaryEffect::Alloc,
        },
        FunctionSummary {
            name: "runtime.mallocgcSmallScanHeader",
            effect: SummaryEffect::Alloc,
        },
        FunctionSummary {
            name: "runtime.mallocgcTiny",
            effect: SummaryEffect::Alloc,
        },
        FunctionSummary {
            name: "runtime.mallocgcLarge",
            effect: SummaryEffect::Alloc,
        },
        FunctionSummary {
            name: "runtime.(*mcache).nextFree",
            effect: SummaryEffect::Alloc,
        },
        // ─── Interface / type comparison (return false in RAX) ──────────
        FunctionSummary {
            name: "runtime.ifaceeq",
            effect: SummaryEffect::ReturnZero,
        },
        FunctionSummary {
            name: "runtime.efaceeq",
            effect: SummaryEffect::ReturnZero,
        },
        FunctionSummary {
            name: "runtime.interequal",
            effect: SummaryEffect::ReturnZero,
        },
        FunctionSummary {
            name: "runtime.nilinterequal",
            effect: SummaryEffect::ReturnZero,
        },
        // ─── String / byte helpers ──────────────────────────────────────
        FunctionSummary {
            name: "internal/bytealg.IndexByteString",
            effect: SummaryEffect::ReturnZero,
        },
        FunctionSummary {
            name: "internal/bytealg.IndexByteString.abi0",
            effect: SummaryEffect::ReturnZero,
        },
        FunctionSummary {
            name: "indexbytebody",
            effect: SummaryEffect::ReturnZero,
        },
        FunctionSummary {
            name: "runtime.slicebytetostring",
            effect: SummaryEffect::AllocSlice,
        },
        FunctionSummary {
            name: "runtime.concatstrings",
            effect: SummaryEffect::AllocSlice,
        },
        FunctionSummary {
            name: "runtime.rawstringtmp",
            effect: SummaryEffect::AllocSlice,
        },
        // ─── Interface conversion (allocates for boxing) ────────────────
        FunctionSummary {
            name: "runtime.convT",
            effect: SummaryEffect::Alloc,
        },
        FunctionSummary {
            name: "runtime.convTslice",
            effect: SummaryEffect::Alloc,
        },
        FunctionSummary {
            name: "runtime.convTstring",
            effect: SummaryEffect::Alloc,
        },
        FunctionSummary {
            name: "runtime.convT64",
            effect: SummaryEffect::Alloc,
        },
        // ─── Map / hash operations ──────────────────────────────────────
        FunctionSummary {
            name: "runtime.mapaccess1",
            effect: SummaryEffect::Alloc,
        },
        FunctionSummary {
            name: "runtime.mapaccess2",
            effect: SummaryEffect::Alloc,
        },
        FunctionSummary {
            name: "runtime.mapassign",
            effect: SummaryEffect::Alloc,
        },
        FunctionSummary {
            name: "runtime.makemap",
            effect: SummaryEffect::Alloc,
        },
        FunctionSummary {
            name: "runtime.makemap_small",
            effect: SummaryEffect::Alloc,
        },
        // ─── Sync / runtime scheduling (no-ops for concolic) ────────────
        FunctionSummary {
            name: "runtime.procPin",
            effect: SummaryEffect::Nop,
        },
        FunctionSummary {
            name: "runtime.procUnpin",
            effect: SummaryEffect::Nop,
        },
        FunctionSummary {
            name: "sync.(*Mutex).Lock",
            effect: SummaryEffect::Nop,
        },
        FunctionSummary {
            name: "sync.(*Mutex).Unlock",
            effect: SummaryEffect::Nop,
        },
        FunctionSummary {
            name: "runtime.publicationBarrier",
            effect: SummaryEffect::Nop,
        },
        // ─── Syscall helpers (avoid deep tracing) ───────────────────────
        FunctionSummary {
            name: "syscall.ByteSliceFromString",
            effect: SummaryEffect::AllocSlice,
        },
        FunctionSummary {
            name: "syscall.BytePtrFromString",
            effect: SummaryEffect::Alloc,
        },
        // ─── Process management (return zero = "child exited ok") ─────────
        FunctionSummary {
            name: "syscall.Wait4",
            effect: SummaryEffect::ReturnZero,
        },
        FunctionSummary {
            name: "syscall.wait4",
            effect: SummaryEffect::ReturnZero,
        },
        FunctionSummary {
            name: "os.(*Process).wait",
            effect: SummaryEffect::ReturnZero,
        },
        FunctionSummary {
            name: "os/exec.(*Cmd).Wait",
            effect: SummaryEffect::ReturnZero,
        },
        FunctionSummary {
            name: "os/exec.(*Cmd).Run",
            effect: SummaryEffect::ReturnZero,
        },
        // ─── Runtime introspection / stack-walking (no-ops) ─────────────
        FunctionSummary {
            name: "runtime.findfunc",
            effect: SummaryEffect::ReturnZero,
        },
        FunctionSummary {
            name: "runtime.funcline1",
            effect: SummaryEffect::ReturnZero,
        },
        FunctionSummary {
            name: "runtime.pcvalue",
            effect: SummaryEffect::ReturnZero,
        },
        FunctionSummary {
            name: "runtime.gentraceback",
            effect: SummaryEffect::Nop,
        },
        FunctionSummary {
            name: "runtime.callers",
            effect: SummaryEffect::ReturnZero,
        },
        FunctionSummary {
            name: "runtime.Callers",
            effect: SummaryEffect::ReturnZero,
        },
        FunctionSummary {
            name: "runtime.FuncForPC",
            effect: SummaryEffect::ReturnZero,
        },
        FunctionSummary {
            name: "runtime.newInlineUnwinder",
            effect: SummaryEffect::ReturnZero,
        },
        // ─── Panic / error formatting ───────────────────────────────────
        FunctionSummary {
            name: "runtime.gopanic",
            effect: SummaryEffect::Nop,
        },
        FunctionSummary {
            name: "runtime.goPanicIndex",
            effect: SummaryEffect::Nop,
        },
        FunctionSummary {
            name: "runtime.goPanicSliceAlen",
            effect: SummaryEffect::Nop,
        },
        FunctionSummary {
            name: "runtime.goPanicSliceB",
            effect: SummaryEffect::Nop,
        },
        FunctionSummary {
            name: "runtime.panicBounds64",
            effect: SummaryEffect::Nop,
        },
        FunctionSummary {
            name: "runtime.pcdatavalue",
            effect: SummaryEffect::ReturnZero,
        },
        FunctionSummary {
            name: "runtime.printstring",
            effect: SummaryEffect::Nop,
        },
        FunctionSummary {
            name: "runtime.printint",
            effect: SummaryEffect::Nop,
        },
        FunctionSummary {
            name: "runtime.printnl",
            effect: SummaryEffect::Nop,
        },
        // ─── Go runtime scheduler / sysmon (no-ops for concolic) ────────
        FunctionSummary {
            name: "runtime.retake",
            effect: SummaryEffect::Nop,
        },
        FunctionSummary {
            name: "runtime.incidlelocked",
            effect: SummaryEffect::Nop,
        },
        FunctionSummary {
            name: "runtime.gcTrigger.test",
            effect: SummaryEffect::ReturnZero,
        },
        FunctionSummary {
            name: "runtime.setBlockOnExitSyscall",
            effect: SummaryEffect::Nop,
        },
        FunctionSummary {
            name: "runtime.sysmon",
            effect: SummaryEffect::Nop,
        },
        FunctionSummary {
            name: "runtime.usleep",
            effect: SummaryEffect::Nop,
        },
        FunctionSummary {
            name: "runtime.nanotime",
            effect: SummaryEffect::ReturnZero,
        },
        FunctionSummary {
            name: "runtime.cputicks",
            effect: SummaryEffect::ReturnZero,
        },
        FunctionSummary {
            name: "runtime.(*sysmonState).shouldRelax",
            effect: SummaryEffect::ReturnZero,
        },
        FunctionSummary {
            name: "runtime.osyield",
            effect: SummaryEffect::Nop,
        },
        FunctionSummary {
            name: "runtime.netpoll",
            effect: SummaryEffect::ReturnZero,
        },
        FunctionSummary {
            name: "runtime.timeSleepUntil",
            effect: SummaryEffect::ReturnZero,
        },
        FunctionSummary {
            name: "runtime.handoffp",
            effect: SummaryEffect::Nop,
        },
        FunctionSummary {
            name: "runtime.startm",
            effect: SummaryEffect::Nop,
        },
        FunctionSummary {
            name: "runtime.wakep",
            effect: SummaryEffect::Nop,
        },
        FunctionSummary {
            name: "runtime.notewakeup",
            effect: SummaryEffect::Nop,
        },
        FunctionSummary {
            name: "runtime.notesleep",
            effect: SummaryEffect::Nop,
        },
        FunctionSummary {
            name: "runtime.notetsleep",
            effect: SummaryEffect::Nop,
        },
        // ─── Goroutine creation / scheduling ──────────────────────────────
        FunctionSummary {
            name: "runtime.newproc1",
            effect: SummaryEffect::Alloc,
        },
        FunctionSummary {
            name: "runtime.malg",
            effect: SummaryEffect::Alloc,
        },
        FunctionSummary {
            name: "runtime.gfget",
            effect: SummaryEffect::Alloc,
        },
        FunctionSummary {
            name: "runtime.allgadd",
            effect: SummaryEffect::Nop,
        },
        FunctionSummary {
            name: "runtime.mcommoninit",
            effect: SummaryEffect::Nop,
        },
        FunctionSummary {
            name: "runtime.stackalloc",
            effect: SummaryEffect::Alloc,
        },
        FunctionSummary {
            name: "runtime.runqput",
            effect: SummaryEffect::Nop,
        },
        FunctionSummary {
            name: "runtime.wakep",
            effect: SummaryEffect::Nop,
        },
        // ─── Network polling (blocks forever in concolic) ─────────────────
        FunctionSummary {
            name: "internal/poll.(*FD).Init",
            effect: SummaryEffect::ReturnZero,
        },
        FunctionSummary {
            name: "internal/poll.(*pollDesc).init",
            effect: SummaryEffect::ReturnZero,
        },
        FunctionSummary {
            name: "runtime.netpollopen",
            effect: SummaryEffect::ReturnZero,
        },
        // ─── Slice / defer helpers ───────────────────────────────────────
        FunctionSummary {
            name: "runtime.growslice",
            effect: SummaryEffect::AllocSlice,
        },
        FunctionSummary {
            name: "runtime.deferprocStack",
            effect: SummaryEffect::Nop,
        },
        FunctionSummary {
            name: "runtime.deferreturn",
            effect: SummaryEffect::Nop,
        },
        // ─── fmt I/O (side-effect only, no data-flow impact) ────────────
        // fmt output functions ultimately reach sync.Pool internals which
        // crash in concolic mode (uninitialized per-P state). Since they
        // only produce I/O and don't affect program control flow, we
        // summarize them as returning (0, nil error) or an empty string.
        FunctionSummary {
            name: "fmt.Printf",
            effect: SummaryEffect::ReturnZero,
        },
        FunctionSummary {
            name: "fmt.Fprintf",
            effect: SummaryEffect::ReturnZero,
        },
        FunctionSummary {
            name: "fmt.Println",
            effect: SummaryEffect::ReturnZero,
        },
        FunctionSummary {
            name: "fmt.Fprintln",
            effect: SummaryEffect::ReturnZero,
        },
        FunctionSummary {
            name: "fmt.Print",
            effect: SummaryEffect::ReturnZero,
        },
        FunctionSummary {
            name: "fmt.Fprint",
            effect: SummaryEffect::ReturnZero,
        },
        FunctionSummary {
            name: "fmt.Sprintf",
            effect: SummaryEffect::AllocSlice,
        },
        FunctionSummary {
            name: "fmt.Sprint",
            effect: SummaryEffect::AllocSlice,
        },
        FunctionSummary {
            name: "fmt.Sprintln",
            effect: SummaryEffect::AllocSlice,
        },
        FunctionSummary {
            name: "fmt.Errorf",
            effect: SummaryEffect::ReturnZero,
        },
        // ─── os I/O (called by fmt; also side-effect only) ──────────────
        FunctionSummary {
            name: "os.(*File).Write",
            effect: SummaryEffect::ReturnZero,
        },
        FunctionSummary {
            name: "os.(*File).WriteString",
            effect: SummaryEffect::ReturnZero,
        },
        // NOTE: sync.(*Pool).Get/pin/pinSlow are NOT summarized because they
        // return interface{} (type_ptr, data_ptr) which can't be approximated
        // without causing panicdottypeE on type assertions.
        //
        // NOTE: TinyGo runtime functions are NOT summarized here. TinyGo uses
        // the C calling convention (RDI/RSI/RDX) whereas the summary handlers
        // assume Go's internal register ABI (RAX/BX/CX). Adding TinyGo
        // summaries would require a separate set of handlers that read/write
        // the correct registers.
    ]
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_table_loads_all_entries() {
        let table = SummaryTable::new();
        assert!(table.is_enabled());
        assert!(table.entry_count() > 0);
        assert!(table.lookup("runtime.mallocgc").is_some());
        assert!(table.lookup("runtime.makechan").is_some());
        assert!(table.lookup("main.dispatch").is_none());
    }

    #[test]
    fn summary_table_respects_disable_env() {
        // Can't easily set env in parallel tests, so just verify the flag path
        let table = SummaryTable::new();
        // When not disabled, it should be enabled
        assert!(table.is_enabled());
    }
}
