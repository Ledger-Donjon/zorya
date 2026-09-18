#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 Karolina Gorna
#
# SPDX-License-Identifier: Apache-2.0

"""Static unbounded-recursion (stack-exhaustion DoS) detector for Zorya.

Zorya's symbolic engine and its memory-safety oracles are built to find
*input-gated* faults (OOB, nil-deref, panics) on a handful of bytes; they do not
model Go's goroutine-stack growth (the engine even zeroes `g.stackguard0` to keep
Go binaries running), so a `fatal error: stack overflow` from unbounded recursion
is invisible to them.

This pass finds the *structure* of that bug instead of executing to overflow,
in the same spirit as a ReDoS detector that flags a super-linear regex without
running the worst case. It builds the function call graph from Ghidra, extracts
the recursive strongly-connected components (mutual recursion) and self-recursive
functions, marks which are reachable from an untrusted-input entry point, and
writes a ranked list of candidate unbounded-recursion / stack-exhaustion DoS
sites to `results/recursion_cycles.txt`.

A recursive cycle reachable from a parser/scanner entry, with no per-nesting
depth cap, is exactly the shape of the `tsgo` parser stack overflow: deeply
nested source drives one stack frame per nesting level until the 1 GB goroutine
stack aborts the process.

Usage:
    precompute_unbounded_recursion.py <binary_path> [entry_substring ...]

`entry_substring` values (case-insensitive) override the default entry seeds
(`main.main` plus any symbol containing `parsesourcefile`). Reachability is
computed forward over the call graph from the union of matched entries.
"""

import os
import sys
import time
from pathlib import Path

try:
    import pyhidra
    from pyhidra import open_program
except ImportError:
    print("ERROR: Pyhidra is not available in this Python environment.")
    print("  Install pyhidra and set GHIDRA_INSTALL_DIR to your Ghidra installation.")
    sys.exit(1)


# Package-qualified substrings (case-insensitive) that mark a function as living
# on the untrusted-input front end. A recursive cycle whose members hit these is
# the highest-risk class: an attacker controls the nesting depth via source text,
# and recursive-descent front ends rarely cap it. These are intentionally
# package-qualified ("parser.", "scanner.") rather than bare verbs ("parse",
# "scan") so they do not match unrelated runtime internals such as
# `runtime...scannedBits`.
FRONTEND_HINTS = (
    "parser.",
    "scanner.",
    "/parser",
    "/scanner",
    "jsdoc",
    "regexp",
)

# Cycles that live entirely in the language runtime / standard library are the
# implementation's own (bounded) mutual recursion - GC, traceback, stack copying
# - not attacker-controlled input recursion. They are downgraded from HIGH so the
# front-end recursive-descent cycles surface first.
RUNTIME_PREFIXES = (
    "runtime.",
    "runtime/",
    "internal/",
    "reflect.",
    "syscall.",
)


def _project_is_fresh(gpr_path: Path, bin_path: Path) -> bool:
    """True when the Ghidra project exists and is newer than the binary."""
    if not gpr_path.exists():
        return False
    try:
        return gpr_path.stat().st_mtime >= bin_path.stat().st_mtime
    except OSError:
        return False


def _tarjan_scc(n, adj):
    """Iterative Tarjan strongly-connected-components.

    Returns a list of components, each a list of node indices. Iterative so it
    does not hit Python's own recursion limit on large call graphs.
    """
    index_of = [-1] * n
    lowlink = [0] * n
    on_stack = [False] * n
    stack = []
    sccs = []
    counter = 0

    for root in range(n):
        if index_of[root] != -1:
            continue
        # work stack of (node, next_child_pointer)
        work = [(root, 0)]
        while work:
            v, pi = work[-1]
            if pi == 0:
                index_of[v] = counter
                lowlink[v] = counter
                counter += 1
                stack.append(v)
                on_stack[v] = True
            recursed = False
            children = adj[v]
            while pi < len(children):
                w = children[pi]
                pi += 1
                if index_of[w] == -1:
                    work[-1] = (v, pi)
                    work.append((w, 0))
                    recursed = True
                    break
                elif on_stack[w]:
                    if index_of[w] < lowlink[v]:
                        lowlink[v] = index_of[w]
            if recursed:
                continue
            # done with v
            work[-1] = (v, pi)
            if lowlink[v] == index_of[v]:
                comp = []
                while True:
                    w = stack.pop()
                    on_stack[w] = False
                    comp.append(w)
                    if w == v:
                        break
                sccs.append(comp)
            work.pop()
            if work:
                parent = work[-1][0]
                if lowlink[v] < lowlink[parent]:
                    lowlink[parent] = lowlink[v]
    return sccs


def _bfs_reach(n, adj, starts):
    """Forward reachability (callees) from the set of start indices."""
    seen = set(starts)
    queue = list(starts)
    while queue:
        v = queue.pop()
        for w in adj[v]:
            if w not in seen:
                seen.add(w)
                queue.append(w)
    return seen


def _open_or_create(GhidraProject, JFile, container, project_name, bin_path):
    """Open the Ghidra project if its marker exists, else create it and import.

    pyhidra's own ``open_program`` always calls ``GhidraProject.openProject``
    first and only catches ``IOException``; Ghidra 11.4.x throws
    ``NotFoundException`` for an empty project dir and ``NotOwnerException`` for a
    project owned by another user, so that path crashes instead of creating a
    fresh project. We branch on the marker file and fall back to a fresh sibling
    dir on any open failure. Returns ``(project, program, need_analyze)``.
    """
    marker = container / f"{project_name}.gpr"
    project = None
    program = None
    if marker.exists():
        try:
            project = GhidraProject.openProject(str(container), project_name, True)
            if project.getRootFolder().getFile(bin_path.name):
                program = project.openProgram("/", bin_path.name, False)
        except Exception as exc:  # NotOwnerException, NotFoundException, IOException, ...
            print(f"[GHIDRA] openProject failed ({exc}); creating a fresh project")
            project = None
            program = None
    if project is None:
        container.mkdir(parents=True, exist_ok=True)
        try:
            project = GhidraProject.createProject(str(container), project_name, False)
        except Exception as exc:
            alt = container.parent / f"{project_name}_{int(time.time())}"
            alt.mkdir(parents=True, exist_ok=True)
            print(f"[GHIDRA] createProject in {container} failed ({exc}); using {alt}")
            project = GhidraProject.createProject(str(alt), project_name, False)
    if program is None:
        program = project.importProgram(JFile(str(bin_path)))
        if program is None:
            raise RuntimeError(
                f"Ghidra failed to import '{bin_path}' (unknown language/loader)."
            )
        project.saveAs(program, "/", program.getName(), True)
        return project, program, True
    return project, program, False


def main():
    if len(sys.argv) < 2:
        print("Usage: precompute_unbounded_recursion.py <binary_path> [entry_substring ...]")
        sys.exit(1)

    binary_path = sys.argv[1]
    entry_subs = [s.lower() for s in sys.argv[2:]]
    os.makedirs("results", exist_ok=True)
    out_path = os.path.join("results", "recursion_cycles.txt")

    bin_path = Path(os.path.abspath(binary_path))
    bin_parent = bin_path.parent
    project_name = f"{bin_path.name}_ghidra"
    parent_gpr = bin_parent / f"{project_name}.gpr"
    reuse_project = _project_is_fresh(parent_gpr, bin_path)
    if reuse_project:
        print(f"[GHIDRA] Reusing existing project {parent_gpr}")
    else:
        print("[GHIDRA] Project not found or stale - will analyze from scratch")

    pyhidra.start()
    from ghidra.util.task import ConsoleTaskMonitor
    from ghidra.base.project import GhidraProject
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.app.script import GhidraScriptUtil
    from java.io import File as JFile

    t0 = time.time()
    container = bin_parent / project_name
    project, program, need_analyze = _open_or_create(
        GhidraProject, JFile, container, project_name, bin_path
    )
    monitor = ConsoleTaskMonitor()
    flat_api = FlatProgramAPI(program)
    GhidraScriptUtil.acquireBundleHostReference()
    try:
        if need_analyze:
            print("[GHIDRA] Running auto-analysis (fresh project)...")
            flat_api.analyzeAll(program)
            try:
                from ghidra.program.util import GhidraProgramUtilities

                if hasattr(GhidraProgramUtilities, "markProgramAnalyzed"):
                    GhidraProgramUtilities.markProgramAnalyzed(program)
                else:
                    GhidraProgramUtilities.setAnalyzedFlag(program, True)
            except Exception:
                pass
        fm = program.getFunctionManager()

        # 1) Index every function by entry-point offset.
        funcs = []
        for f in fm.getFunctions(True):
            funcs.append(f)
        n = len(funcs)
        idx = {}
        names = []
        addrs = []
        for i, f in enumerate(funcs):
            off = f.getEntryPoint().getOffset()
            idx[off] = i
            try:
                raw = f.getName(True)  # include namespace for Go package names
            except Exception:
                raw = f.getName()
            # Collapse any whitespace so names never break the space-tokenized
            # `CYCLE ...` output format consumed by the Rust side.
            names.append("_".join(str(raw).split()))
            addrs.append(off)
        print(f"[RECUR] Indexed {n} functions")

        # 2) Build the callee adjacency list. Thunks are followed to their real
        #    target so recursion through a thunk is not lost.
        adj = [[] for _ in range(n)]
        selfrec = [False] * n
        edges = 0
        for i, f in enumerate(funcs):
            try:
                callees = f.getCalledFunctions(monitor)
            except Exception:
                continue
            seen = set()
            for c in callees:
                try:
                    if c.isThunk():
                        tf = c.getThunkedFunction(True)
                        if tf is not None:
                            c = tf
                    co = c.getEntryPoint().getOffset()
                except Exception:
                    continue
                j = idx.get(co)
                if j is None:
                    continue
                if j == i:
                    selfrec[i] = True
                if j not in seen:
                    seen.add(j)
                    adj[i].append(j)
                    edges += 1
            if (i + 1) % 5000 == 0:
                print(f"[RECUR] call-graph edges from {i + 1}/{n} functions...")
        print(f"[RECUR] Call graph: {n} nodes, {edges} edges")

        # 3) Recursive SCCs (mutual recursion) plus self-recursive singletons.
        sccs = _tarjan_scc(n, adj)
        rec_components = [
            comp
            for comp in sccs
            if len(comp) > 1 or (len(comp) == 1 and selfrec[comp[0]])
        ]
        n_self = sum(1 for c in rec_components if len(c) == 1)
        n_mutual = sum(1 for c in rec_components if len(c) > 1)
        print(
            f"[RECUR] Recursive components: {len(rec_components)} "
            f"(self-recursive: {n_self}, mutual: {n_mutual})"
        )

        # 4) Entry seeds + forward reachability.
        entries = set()
        for i, nm in enumerate(names):
            low = nm.lower()
            if entry_subs:
                if any(es in low for es in entry_subs):
                    entries.add(i)
            else:
                if nm == "main.main" or low.endswith(".main") or "parsesourcefile" in low:
                    entries.add(i)
        reachable = _bfs_reach(n, adj, entries) if entries else set()
        entry_disp = ", ".join(
            sorted({f"{names[i]}(0x{addrs[i]:x})" for i in entries})
        ) or "(none matched)"
        print(f"[RECUR] Entry seeds: {entry_disp}")
        print(f"[RECUR] Functions reachable from entries: {len(reachable)}")

        # 5) Rank components. HIGH = reachable and touches the front end;
        #    MEDIUM = reachable; LOW = not reachable from the chosen entries.
        def is_frontend(comp):
            for m in comp:
                low = names[m].lower()
                if any(h in low for h in FRONTEND_HINTS):
                    return True
            return False

        def is_mostly_runtime(comp):
            rt = sum(
                1
                for m in comp
                if names[m].lower().startswith(RUNTIME_PREFIXES)
            )
            return rt * 2 >= len(comp)

        def representative(comp):
            fe = [m for m in comp if any(h in names[m].lower() for h in FRONTEND_HINTS)]
            pool = fe if fe else comp
            return min(pool, key=lambda m: (len(names[m]), names[m]))

        ranked = []
        for comp in rec_components:
            reach = any(m in reachable for m in comp)
            fe = is_frontend(comp)
            # A reachable cycle that touches the untrusted-input front end and is
            # not just runtime plumbing is the HIGH-risk stack-overflow shape.
            if reach and fe and not is_mostly_runtime(comp):
                risk = "HIGH"
            elif reach:
                risk = "MEDIUM"
            else:
                risk = "LOW"
            ranked.append((risk, reach, fe, comp))

        risk_rank = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        ranked.sort(key=lambda t: (risk_rank[t[0]], -len(t[3])))

        # 6) Write results.
        elapsed = time.time() - t0
        n_high = sum(1 for r in ranked if r[0] == "HIGH")
        n_reach = sum(1 for r in ranked if r[1])
        with open(out_path, "w") as fh:
            fh.write("# Zorya unbounded-recursion (stack-exhaustion DoS) scan\n")
            fh.write(f"# binary: {bin_path}\n")
            fh.write(f"# functions: {n}, call-edges: {edges}\n")
            fh.write(
                f"# recursive-components: {len(rec_components)} "
                f"(self: {n_self}, mutual: {n_mutual})\n"
            )
            fh.write(f"# entries: {entry_disp}\n")
            fh.write(f"# reachable-from-entry: {len(reachable)} functions\n")
            fh.write(
                f"# recursive-components reachable-from-entry: {n_reach}, HIGH-risk: {n_high}\n"
            )
            fh.write(f"# analysis_time: {elapsed:.2f}s\n")
            fh.write(
                "# line format: CYCLE <id> size=<n> reachable=<0|1> risk=<HIGH|MEDIUM|LOW> "
                "selfrec=<0|1> entry=<0xaddr:name> members=<0xaddr:name;...>\n"
            )
            cid = 0
            for risk, reach, fe, comp in ranked:
                cid += 1
                rep = representative(comp)
                selfr = 1 if (len(comp) == 1 and selfrec[comp[0]]) else 0
                shown = comp[:60]
                mem = ";".join(f"0x{addrs[m]:x}:{names[m]}" for m in shown)
                if len(comp) > len(shown):
                    mem += f";(+{len(comp) - len(shown)} more)"
                fh.write(
                    f"CYCLE {cid} size={len(comp)} reachable={1 if reach else 0} "
                    f"risk={risk} selfrec={selfr} "
                    f"entry=0x{addrs[rep]:x}:{names[rep]} members={mem}\n"
                )

        print(
            f"[RECUR] Wrote {len(ranked)} recursive components to {out_path} "
            f"({n_high} HIGH-risk) in {elapsed:.2f}s"
        )
    finally:
        GhidraScriptUtil.releaseBundleHostReference()
        try:
            project.save(program)
        except Exception:
            pass
        try:
            project.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()
