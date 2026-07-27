#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
#
# SPDX-License-Identifier: Apache-2.0

import os
import sys
import time
from pathlib import Path

try:
    import pyhidra
    from pyhidra import open_program
except ImportError:
    print("ERROR: Pyhidra is not available in this Python environment.")
    print()
    print("Please check:")
    print("  1) That Pyhidra is installed (e.g. via 'make ghidra-config' or")
    print("     'python3 -m pip install --user pyhidra').")
    print(
        "  2) That the GHIDRA_INSTALL_DIR environment variable points to your Ghidra installation."
    )
    sys.exit(1)


class BlockSet:
    """Drop-in replacement for set() of Java CodeBlock objects.

    Stores Python ``int`` offsets (block start addresses) as set keys so
    that membership tests (``blk in s``, ``s.add(blk)``) use Python-native
    O(1) int hashing instead of crossing jpype → JNI → Java for every
    ``hashCode()`` / ``equals()`` call.  For 100 k+ blocks this eliminates
    the dominant cost of the reverse BFS.
    """

    __slots__ = ("_blocks", "_keys")

    def __init__(self):
        self._keys: set[int] = set()  # block-start offsets
        self._blocks: dict[int, object] = {}  # offset → CodeBlock

    def _key(self, blk) -> int:
        return blk.getFirstStartAddress().getOffset()

    def add(self, blk):
        k = self._key(blk)
        self._keys.add(k)
        self._blocks[k] = blk

    def __contains__(self, blk) -> bool:
        try:
            return self._key(blk) in self._keys
        except Exception:
            return False

    def __len__(self) -> int:
        return len(self._keys)

    def __iter__(self):
        return iter(self._blocks.values())

    def __bool__(self) -> bool:
        return bool(self._keys)


def _project_is_fresh(gpr_path: Path, bin_path: Path) -> bool:
    """True when the Ghidra project exists and is newer than the binary."""
    if not gpr_path.exists():
        return False
    try:
        return gpr_path.stat().st_mtime >= bin_path.stat().st_mtime
    except OSError:
        return False


def main():
    if len(sys.argv) != 2:
        print("Usage: precompute_panic_reach.py <binary_path>")
        sys.exit(1)

    binary_path = sys.argv[1]
    xref_path = os.path.join("results", "xref_addresses.txt")
    out_path = os.path.join("results", "panic_reachable.txt")

    panic_hex = []
    if os.path.exists(xref_path):
        with open(xref_path) as f:
            raw = [line.strip() for line in f if line.strip()]
            # Normalize to plain hex without 0x prefix for Ghidra
            panic_hex = [h[2:] if h.lower().startswith("0x") else h for h in raw]

    # ── Project reuse: share the .gpr created by get_jump_tables.py ──
    bin_path = Path(os.path.abspath(binary_path))
    bin_parent = bin_path.parent
    project_name = f"{bin_path.name}_ghidra"
    parent_gpr = bin_parent / f"{project_name}.gpr"
    reuse_project = _project_is_fresh(parent_gpr, bin_path)
    if reuse_project:
        print(f"[GHIDRA] Reusing existing project {parent_gpr}")
    else:
        print("[GHIDRA] Project not found or stale — will analyze from scratch")

    pyhidra.start()

    from ghidra.program.model.address import AddressSet
    from ghidra.program.model.block import BasicBlockModel
    from ghidra.util.task import ConsoleTaskMonitor

    with open_program(
        str(bin_path),
        project_location=str(bin_parent),
        project_name=project_name,
        analyze=not reuse_project,
    ) as flat_api:
        program = flat_api.getCurrentProgram()
        addr_factory = program.getAddressFactory()
        monitor = ConsoleTaskMonitor()
        model = BasicBlockModel(program)
        listing = program.getListing()
        refman = program.getReferenceManager()  # cache — avoid JNI per loop iter
        fm = program.getFunctionManager()  # cache

        t_phase = time.time()
        # Optional: load jump table info to improve predecessors of computed jumps
        dest_to_pred_blocks = {}
        try:
            jt_path = os.path.join("results", "jump_tables.json")
            if os.path.exists(jt_path):
                import json

                with open(jt_path) as jf:
                    jt = json.load(jf)
                for tbl in jt:
                    table_base_hex = tbl.get("table_address")
                    table_base_addr = None
                    if table_base_hex:
                        try:
                            table_base_addr = addr_factory.getAddress(
                                f"ram:{table_base_hex}"
                            )
                            if table_base_addr is None:
                                table_base_addr = addr_factory.getAddress(
                                    table_base_hex
                                )
                        except Exception:
                            table_base_addr = None
                    for case in tbl.get("cases", []):
                        dest_hex = case.get("destination")
                        input_hex = case.get("input_address")
                        if not dest_hex:
                            continue
                        try:
                            dest_addr = addr_factory.getAddress(f"ram:{dest_hex}")
                            if dest_addr is None:
                                dest_addr = addr_factory.getAddress(dest_hex)
                        except Exception:
                            dest_addr = None
                        if dest_addr is None:
                            continue
                        key = dest_addr.toString()
                        preds = dest_to_pred_blocks.get(key, set())
                        # Collect refs to table entry and base
                        try:
                            if input_hex:
                                in_addr = addr_factory.getAddress(f"ram:{input_hex}")
                                if in_addr is None:
                                    in_addr = addr_factory.getAddress(input_hex)
                                if in_addr is not None:
                                    refs = refman.getReferencesTo(in_addr)
                                    for r in refs:
                                        try:
                                            from_addr = r.getFromAddress()
                                            cb = model.getCodeBlockAt(
                                                from_addr, monitor
                                            )
                                            if cb is None:
                                                cbs = model.getCodeBlocksContaining(
                                                    from_addr, monitor
                                                )
                                                for b in cbs:
                                                    if b is not None:
                                                        preds.add(b)
                                            else:
                                                preds.add(cb)
                                        except Exception:
                                            continue
                        except Exception:
                            pass
                        try:
                            if table_base_addr is not None:
                                refs = refman.getReferencesTo(table_base_addr)
                                for r in refs:
                                    try:
                                        from_addr = r.getFromAddress()
                                        cb = model.getCodeBlockAt(from_addr, monitor)
                                        if cb is None:
                                            cbs = model.getCodeBlocksContaining(
                                                from_addr, monitor
                                            )
                                            for b in cbs:
                                                if b is not None:
                                                    preds.add(b)
                                        else:
                                            preds.add(cb)
                                    except Exception:
                                        continue
                        except Exception:
                            pass
                        dest_to_pred_blocks[key] = preds
        except Exception:
            dest_to_pred_blocks = {}

        print(f"[GHIDRA] Jump table loading took {time.time() - t_phase:.1f}s")

        # Convert panic addresses (call sites) to blocks and seed reverse frontier (use containing blocks)
        t_phase = time.time()
        panic_blocks = BlockSet()
        for h in panic_hex:
            try:
                a = addr_factory.getAddress(h)
                if a is None:
                    a = addr_factory.getAddress(f"ram:{h}")
                if a is None:
                    continue
                if not program.getMemory().contains(a):
                    continue
                blocks = model.getCodeBlocksContaining(a, monitor)
                for blk in blocks:
                    if blk is not None:
                        panic_blocks.add(blk)
            except Exception:
                continue

        # Also seed from panic functions discovered by name (case-insensitive contains "panic")
        it = fm.getFunctions(True)
        while it.hasNext():
            fn = it.next()
            try:
                name = fn.getName()
            except Exception:
                continue
            if name is None:
                continue
            if "panic" in name.lower():
                entry = fn.getEntryPoint()
                if entry is None:
                    continue
                if not program.getMemory().contains(entry):
                    continue
                blk = model.getCodeBlockAt(entry, monitor)
                if blk is None:
                    blocks = model.getCodeBlocksContaining(entry, monitor)
                    for b in blocks:
                        if b is not None:
                            panic_blocks.add(b)
                else:
                    panic_blocks.add(blk)

        print(
            f"[GHIDRA] Panic seed collection took {time.time() - t_phase:.1f}s ({len(panic_blocks)} seeds)"
        )

        # Reverse BFS: predecessors via getSources; also include interprocedural step:
        # for each visited block, jump to all callers of its containing function
        reachable = BlockSet()
        work = list(panic_blocks)
        processed_funcs = (
            set()
        )  # function entry addresses we've already expanded callers for

        # Coverage and fixpoint tracking
        initial_panic_count = len(panic_blocks)
        iterations = 0
        blocks_added_per_iteration = []
        tainted_functions = set()  # functions that contain panic-reachable blocks

        # Cache tracking for indirect call resolution (hits/misses only)
        cache_stats = {
            "total_indirect_calls": 0,
            "cache_hits": 0,
            "cache_misses": 0,
        }
        indirect_call_cache = {}  # addr -> resolved_targets set (placeholder)

        print(
            f"\n[GHIDRA] Starting reverse BFS from {initial_panic_count} panic blocks..."
        )
        start_time = time.time()
        while work:
            iteration_start_size = len(reachable)
            _iteration_work_size = len(work)
            iterations += 1

            # Process blocks in current iteration
            current_iteration_blocks = []
            current_work = work[:]
            work = []

            for blk in current_work:
                if blk in reachable:
                    continue
                reachable.add(blk)
                current_iteration_blocks.append(blk)

                # Track tainted functions
                try:
                    start_addr = blk.getFirstStartAddress()
                    func = fm.getFunctionContaining(start_addr)
                    if func is not None:
                        entry = func.getEntryPoint()
                        if entry is not None:
                            tainted_functions.add(entry.toString())
                except Exception:
                    pass

            # Process each block in current iteration
            for blk in current_iteration_blocks:
                # 1) Intra-procedural predecessors
                src_iter = blk.getSources(monitor)
                while src_iter.hasNext():
                    block_ref = src_iter.next()
                    src_addr = block_ref.getSourceAddress()

                    # Check for indirect calls and cache resolution
                    # Note: block_ref is CodeBlockReferenceImpl, need to get the actual reference
                    try:
                        actual_ref = block_ref.getReference()
                        if actual_ref is not None:
                            ref_type = actual_ref.getReferenceType()
                            if (
                                ref_type.isCall()
                                and ref_type.toString().lower().find("indirect") >= 0
                            ):
                                cache_stats["total_indirect_calls"] += 1
                                addr_key = src_addr.toString()

                                if addr_key in indirect_call_cache:
                                    cache_stats["cache_hits"] += 1
                                    # Use cached resolution
                                    for cached_target in indirect_call_cache[addr_key]:
                                        cached_blk = model.getCodeBlockAt(
                                            cached_target, monitor
                                        )
                                        if (
                                            cached_blk is not None
                                            and cached_blk not in reachable
                                        ):
                                            work.append(cached_blk)
                                    continue
                                else:
                                    cache_stats["cache_misses"] += 1
                                    # For now, just record the miss - full resolution would need more analysis
                                    indirect_call_cache[addr_key] = set()
                    except Exception:
                        # If we can't get reference info, just skip the cache logic
                        pass

                    src_blk = model.getCodeBlockAt(src_addr, monitor)
                    if src_blk is None:
                        # Fallback to containing block if exact start doesn't map
                        blocks = model.getCodeBlocksContaining(src_addr, monitor)
                        for b in blocks:
                            if b is not None and b not in reachable:
                                work.append(b)
                        continue
                    if src_blk is not None and src_blk not in reachable:
                        work.append(src_blk)

                # 1b) Additional fallback: use reference manager on block start and max address
                try:
                    start_addr = blk.getFirstStartAddress()
                    max_addr = blk.getMaxAddress()
                    for q_addr in [start_addr, max_addr]:
                        try:
                            refs_to_q = refman.getReferencesTo(q_addr)
                            for rr in refs_to_q:
                                try:
                                    from_addr = rr.getFromAddress()
                                    cb = model.getCodeBlockAt(from_addr, monitor)
                                    if cb is None:
                                        cbs = model.getCodeBlocksContaining(
                                            from_addr, monitor
                                        )
                                        for b in cbs:
                                            if b is not None and b not in reachable:
                                                work.append(b)
                                    else:
                                        if cb not in reachable:
                                            work.append(cb)
                                except Exception:
                                    continue
                        except Exception:
                            continue
                except Exception:
                    pass

                # 1c) Instruction-level interior xrefs inside block span (addresses inside span)
                try:
                    start_addr = blk.getFirstStartAddress()
                    max_addr = blk.getMaxAddress()
                    aset = AddressSet()
                    aset.addRange(start_addr, max_addr)
                    ins_iter = listing.getInstructions(aset, True)
                    added_local = 0
                    while ins_iter.hasNext():
                        ins = ins_iter.next()
                        q_addr = ins.getAddress()
                        try:
                            refs = refman.getReferencesTo(q_addr)
                            for rr in refs:
                                try:
                                    from_addr = rr.getFromAddress()
                                    cb = model.getCodeBlockAt(from_addr, monitor)
                                    if cb is None:
                                        cbs = model.getCodeBlocksContaining(
                                            from_addr, monitor
                                        )
                                        for b in cbs:
                                            if b is not None and b not in reachable:
                                                work.append(b)
                                                added_local += 1
                                    else:
                                        if cb not in reachable:
                                            work.append(cb)
                                            added_local += 1
                                except Exception:
                                    continue
                        except Exception:
                            continue
                except Exception:
                    pass

                # 1d) Jump table predecessors: if this block is a destination, add any code blocks that reference entries/base
                try:
                    start_addr = blk.getFirstStartAddress()
                    key = start_addr.toString()
                    if key in dest_to_pred_blocks:
                        for pb in dest_to_pred_blocks[key]:
                            if pb not in reachable:
                                work.append(pb)
                except Exception:
                    pass

                # 2) Inter-procedural step: add blocks of all call-sites (calls and tail jumps) of the containing function
                try:
                    start_addr = blk.getFirstStartAddress()
                    func = fm.getFunctionContaining(start_addr)
                except Exception:
                    func = None

                if func is not None:
                    entry = func.getEntryPoint()
                    try:
                        entry_key = entry.toString() if entry is not None else None
                    except Exception:
                        entry_key = None

                    if (
                        entry is not None
                        and entry_key is not None
                        and entry_key not in processed_funcs
                    ):
                        processed_funcs.add(entry_key)

                        try:
                            entries_to_expand = [entry]
                            try:
                                thunk = func.getThunkedFunction()
                                if (
                                    thunk is not None
                                    and thunk.getEntryPoint() is not None
                                ):
                                    entries_to_expand.append(thunk.getEntryPoint())
                            except Exception:
                                pass

                            # Also expand references to body addresses (sampled to avoid explosion)
                            try:
                                body = func.getBody()
                                addr_iter = body.getAddresses(True)
                                # Configurable sampling budget and stride
                                body_budget = 0
                                body_stride = 1
                                try:
                                    body_budget = int(
                                        os.environ.get(
                                            "PANIC_REACH_BODY_XREF_BUDGET", "500"
                                        )
                                    )
                                except Exception:
                                    body_budget = 5000
                                try:
                                    body_stride = int(
                                        os.environ.get(
                                            "PANIC_REACH_BODY_XREF_STRIDE", "1"
                                        )
                                    )
                                    body_stride = max(body_stride, 1)
                                except Exception:
                                    body_stride = 1
                                used = 0
                                idx = 0
                                while addr_iter.hasNext() and used < body_budget:
                                    a = addr_iter.next()
                                    if (idx % body_stride) == 0:
                                        entries_to_expand.append(a)
                                        used += 1
                                    idx += 1
                            except Exception:
                                pass

                            for ent in entries_to_expand:
                                refs = refman.getReferencesTo(ent)
                                for r in refs:
                                    try:
                                        rtype = r.getReferenceType()
                                        if (
                                            rtype.isCall()
                                            or rtype.isJump()
                                            or rtype.isFlow()
                                            or True
                                        ):
                                            from_addr = r.getFromAddress()
                                            cb = model.getCodeBlockAt(
                                                from_addr, monitor
                                            )
                                            if cb is None:
                                                cbs = model.getCodeBlocksContaining(
                                                    from_addr, monitor
                                                )
                                                for b in cbs:
                                                    if (
                                                        b is not None
                                                        and b not in reachable
                                                    ):
                                                        work.append(b)
                                            else:
                                                if cb not in reachable:
                                                    work.append(cb)
                                    except Exception:
                                        continue
                        except Exception:
                            pass

            # Track iteration progress
            blocks_added_this_iteration = len(reachable) - iteration_start_size
            blocks_added_per_iteration.append(blocks_added_this_iteration)

            # Progress reporting every 10 iterations or significant growth
            if iterations % 10 == 0 or blocks_added_this_iteration > 100:
                elapsed = time.time() - start_time
                print(
                    f"Iteration {iterations}: {len(reachable)} reachable blocks (+{blocks_added_this_iteration}), "
                    f"{len(work)} in queue, {len(tainted_functions)} tainted functions, "
                    f"elapsed: {elapsed:.1f}s"
                )

            # Fixpoint detection: if no new blocks added in last few iterations
            exhaustive = os.environ.get("PANIC_REACH_EXHAUSTIVE", "0").lower() in (
                "1",
                "true",
            )
            if (
                not exhaustive
                and iterations > 5
                and all(count == 0 for count in blocks_added_per_iteration[-3:])
            ):
                print(
                    f"Fixpoint reached at iteration {iterations} - no new blocks in last 3 iterations"
                )
                break

            # Sanity post-pass trigger: if nothing added this iteration but work is empty, try expanding via successors into reachable
            if blocks_added_this_iteration == 0 and len(work) == 0:
                added = 0
                try:
                    all_blocks = model.getCodeBlocks(monitor)
                    to_add = set()
                    while all_blocks.hasNext():
                        b = all_blocks.next()
                        if b in reachable:
                            continue
                        try:
                            dest_iter = b.getDestinations(monitor)
                            while dest_iter.hasNext():
                                dref = dest_iter.next()
                                daddr = dref.getDestinationAddress()
                                dblk = model.getCodeBlockAt(daddr, monitor)
                                if dblk is None:
                                    dblks = model.getCodeBlocksContaining(
                                        daddr, monitor
                                    )
                                    hit = False
                                    for db in dblks:
                                        if db is not None and db in reachable:
                                            hit = True
                                            break
                                    if hit:
                                        to_add.add(b)
                                        break
                                else:
                                    if dblk in reachable:
                                        to_add.add(b)
                                        break
                        except Exception:
                            continue
                    if to_add:
                        for nb in to_add:
                            if nb not in reachable:
                                work.append(nb)
                        added = len(to_add)
                        print(
                            f"Sanity post-pass added {added} predecessor blocks; continuing..."
                        )
                except Exception:
                    pass
                if added > 0:
                    continue

                # Secondary sanity: xrefs into reachable blocks' start/max
                try:
                    added2 = 0
                    for rb in list(reachable):
                        try:
                            for q_addr in [
                                rb.getFirstStartAddress(),
                                rb.getMaxAddress(),
                            ]:
                                refs = refman.getReferencesTo(q_addr)
                                for r in refs:
                                    try:
                                        fa = r.getFromAddress()
                                        cb = model.getCodeBlockAt(fa, monitor)
                                        if cb is None:
                                            cbs = model.getCodeBlocksContaining(
                                                fa, monitor
                                            )
                                            for b in cbs:
                                                if b is not None and b not in reachable:
                                                    work.append(b)
                                                    added2 += 1
                                        else:
                                            if cb not in reachable:
                                                work.append(cb)
                                                added2 += 1
                                    except Exception:
                                        continue
                        except Exception:
                            continue
                    if added2 > 0:
                        print(
                            f"Sanity xref post-pass enqueued {added2} blocks; continuing..."
                        )
                        continue
                except Exception:
                    pass

        # Final statistics
        end_time = time.time()
        total_time = end_time - start_time

        # Calculate coverage metrics — only count total blocks if requested
        # (iterating ALL blocks in a large binary is expensive)
        run_unreachable = os.environ.get(
            "PANIC_REACH_UNREACHABLE_ANALYSIS", "0"
        ).lower() in ("1", "true")

        total_program_blocks = 0
        if run_unreachable:
            print(
                "[GHIDRA] Counting total program blocks (set PANIC_REACH_UNREACHABLE_ANALYSIS=0 to skip)..."
            )
            t_count = time.time()
            try:
                all_blocks = model.getCodeBlocks(monitor)
                while all_blocks.hasNext():
                    all_blocks.next()
                    total_program_blocks += 1
            except Exception:
                total_program_blocks = -1
            print(
                f"[GHIDRA] Block counting took {time.time() - t_count:.1f}s ({total_program_blocks} blocks)"
            )

        coverage_percentage = (
            (len(reachable) / total_program_blocks * 100)
            if total_program_blocks > 0
            else -1
        )

        # Analyze unreachable blocks and categorize (expensive — opt-in via env var)
        unreachable_summary = {
            "totals": {
                "program_blocks": total_program_blocks,
                "reachable_blocks": len(reachable),
                "unreachable_blocks": 0,
            },
            "categories": {},
        }

        if run_unreachable:
            print("[GHIDRA] Running unreachable block categorization...")
            t_unreach = time.time()

        def add_cat(cat, addr_str, func_name):
            c = unreachable_summary["categories"].setdefault(
                cat, {"count": 0, "samples": [], "functions": {}}
            )
            c["count"] += 1
            if len(c["samples"]) < 20:
                c["samples"].append(addr_str)
            if func_name is None:
                func_name = "NO_FUNCTION"
            c["functions"][func_name] = c["functions"].get(func_name, 0) + 1

        try:
            all_blocks = model.getCodeBlocks(monitor)
            unreachable_count = 0
            while all_blocks.hasNext():
                b = all_blocks.next()
                if b in reachable:
                    continue
                unreachable_count += 1
                start_addr = b.getFirstStartAddress()
                max_addr = b.getMaxAddress()
                addr_str = f"0x{start_addr!s}"

                # Determine containing function name once
                try:
                    func = fm.getFunctionContaining(start_addr)
                except Exception:
                    func = None
                if func is None:
                    func_name = "NO_FUNCTION"
                else:
                    try:
                        func_name = func.getName()
                    except Exception:
                        func_name = "UNKNOWN_FUNCTION"

                # Category: no_incoming_refs
                try:
                    has_src = b.getSources(monitor).hasNext()
                except Exception:
                    has_src = False
                if not has_src:
                    add_cat("no_incoming_refs", addr_str, func_name)

                # Category: only_from_unreachable
                only_unreach = True
                try:
                    src_iter = b.getSources(monitor)
                    while src_iter.hasNext():
                        sref = src_iter.next()
                        saddr = sref.getSourceAddress()
                        sblk = model.getCodeBlockAt(saddr, monitor)
                        if sblk is None:
                            sblks = model.getCodeBlocksContaining(saddr, monitor)
                            for sb in sblks:
                                if sb in reachable:
                                    only_unreach = False
                                    break
                        else:
                            if sblk in reachable:
                                only_unreach = False
                                break
                        if not only_unreach:
                            break
                except Exception:
                    pass
                if has_src and only_unreach:
                    add_cat("only_from_unreachable", addr_str, func_name)

                # Category: xref_absent_to_start_and_end
                try:
                    x1 = refman.getReferencesTo(start_addr)
                    x2 = refman.getReferencesTo(max_addr)
                    xref_any = (x1.hasNext() if hasattr(x1, "hasNext") else True) or (
                        x2.hasNext() if hasattr(x2, "hasNext") else True
                    )
                except Exception:
                    xref_any = True
                if not xref_any and not has_src:
                    add_cat("no_xrefs_no_sources", addr_str, func_name)

                # Category: function_not_tainted / external_or_thunk
                if func is None:
                    add_cat("no_containing_function", addr_str, func_name)
                else:
                    try:
                        entry = func.getEntryPoint()
                        entry_key = entry.toString() if entry is not None else None
                    except Exception:
                        entry_key = None
                    if entry_key is not None and entry_key not in tainted_functions:
                        add_cat("function_not_tainted", addr_str, func_name)
                    try:
                        if func.isExternal() or func.isThunk():
                            add_cat("external_or_thunk", addr_str, func_name)
                    except Exception:
                        pass

                # Category: plt_or_iat_section
                try:
                    mb = program.getMemory().getBlock(start_addr)
                    if mb is not None:
                        name = mb.getName().lower()
                        if (
                            "plt" in name
                            or "iat" in name
                            or "got" in name
                            or "extern" in name
                        ):
                            add_cat("plt_iat_got_or_external", addr_str, func_name)
                except Exception:
                    pass

                # Category: jump_table_pred_unreachable (from loaded jump_tables.json)
                try:
                    key = start_addr.toString()
                    preds = dest_to_pred_blocks.get(key, set())
                    if preds:
                        any_reach = any(pb in reachable for pb in preds)
                        if not any_reach:
                            add_cat("jump_table_pred_unreachable", addr_str, func_name)
                except Exception:
                    pass
            unreachable_summary["totals"]["unreachable_blocks"] = unreachable_count
        except Exception:
            print(
                f"[GHIDRA] Unreachable categorization took {time.time() - t_unreach:.1f}s"
            )

        # Print comprehensive statistics
        print("\nREVERSE BFS PANIC REACHABILITY ANALYSIS COMPLETE:")
        print("-" * 49)
        print(f"Total execution time: {total_time:.2f} seconds")
        print(f"Iterations completed: {iterations}")
        print(f"Initial panic seeds: {initial_panic_count}")
        print(f"Final reachable blocks: {len(reachable)}")
        if total_program_blocks > 0:
            print(
                f"Program coverage: {coverage_percentage:.1f}% ({len(reachable)}/{total_program_blocks} blocks)"
            )
        print(f"Tainted functions: {len(tainted_functions)}")
        print(f"Processed functions: {len(processed_funcs)}")

        if unreachable_summary["totals"]["unreachable_blocks"] > 0:
            print("\nUNREACHABLE BLOCKS SUMMARY:")
            print(
                f"  Unreachable blocks: {unreachable_summary['totals']['unreachable_blocks']}"
            )
            for cat, info in unreachable_summary["categories"].items():
                print(f"  - {cat}: {info['count']}")

        print("\nCACHE PERFORMANCE:")
        print(f"  Indirect calls encountered: {cache_stats['total_indirect_calls']}")
        if cache_stats["total_indirect_calls"] > 0:
            hit_rate = (
                cache_stats["cache_hits"] / cache_stats["total_indirect_calls"] * 100
            )
            print(
                f"  Indirect call cache hit rate: {hit_rate:.1f}% ({cache_stats['cache_hits']}/{cache_stats['total_indirect_calls']})"
            )

        print("\nITERATION BREAKDOWN:")
        for i, count in enumerate(
            blocks_added_per_iteration[:10]
        ):  # Show first 10 iterations
            print(f"  Iteration {i + 1}: +{count} blocks")
        if len(blocks_added_per_iteration) > 10:
            print(f"  ... and {len(blocks_added_per_iteration) - 10} more iterations")

        # Save additional analysis files
        tainted_funcs_path = os.path.join("results", "tainted_functions.txt")
        coverage_path = os.path.join("results", "panic_coverage.json")
        unreachable_path_txt = os.path.join("results", "unreachable_summary.txt")
        unreachable_path_json = os.path.join("results", "unreachable_summary.json")

        # Write tainted functions
        with open(tainted_funcs_path, "w") as tf:
            tf.write("# Tainted functions (contain panic-reachable blocks)\n")
            tf.write(f"# Total: {len(tainted_functions)} functions\n")
            tf.writelines(f"{func_addr}\n" for func_addr in sorted(tainted_functions))

        # Write coverage analysis in JSON format for programmatic use
        import json

        coverage_data = {
            "analysis_metadata": {
                "total_time_seconds": total_time,
                "iterations": iterations,
                "initial_panic_seeds": initial_panic_count,
                "fixpoint_reached": iterations > 5
                and all(count == 0 for count in blocks_added_per_iteration[-3:]),
            },
            "coverage_metrics": {
                "total_reachable_blocks": len(reachable),
                "total_program_blocks": total_program_blocks
                if total_program_blocks > 0
                else None,
                "coverage_percentage": coverage_percentage
                if coverage_percentage >= 0
                else None,
                "tainted_functions": len(tainted_functions),
                "processed_functions": len(processed_funcs),
            },
            "cache_performance": cache_stats,
            "iteration_breakdown": blocks_added_per_iteration,
        }
        with open(coverage_path, "w") as cov:
            json.dump(coverage_data, cov, indent=2)

        # Write unreachable summary
        with open(unreachable_path_json, "w") as uj:
            json.dump(unreachable_summary, uj, indent=2)
        with open(unreachable_path_txt, "w") as ut:
            ut.write("# Unreachable blocks summary\n")
            ut.write(
                f"# Total program blocks: {unreachable_summary['totals']['program_blocks']}\n"
            )
            ut.write(
                f"# Reachable blocks: {unreachable_summary['totals']['reachable_blocks']}\n"
            )
            ut.write(
                f"# Unreachable blocks: {unreachable_summary['totals']['unreachable_blocks']}\n"
            )
            for cat, info in unreachable_summary["categories"].items():
                ut.write(f"\n[{cat}] count={info['count']}\n")
                # List function names with counts
                # Sort by count desc, then name
                funcs = sorted(
                    info.get("functions", {}).items(), key=lambda kv: (-kv[1], kv[0])
                )
                ut.writelines(f"  {fname} ({fcount})\n" for fname, fcount in funcs[:50])

        # Emit all start addresses of reachable blocks
        print(f"\nWriting {len(reachable)} reachable blocks to {out_path}")
        print(
            f"Writing {len(tainted_functions)} tainted functions to {tainted_funcs_path}"
        )
        print(f"Writing coverage analysis to {coverage_path}")
        print(
            f"Writing unreachable summary to {unreachable_path_txt} and {unreachable_path_json}"
        )

        with open(out_path, "w") as out:
            # Write header with metadata
            out.write("# Panic reachability analysis results\n")
            out.write(f"# Generated in {total_time:.2f}s, {iterations} iterations\n")
            out.write(f"# Coverage: {len(reachable)} blocks")
            if total_program_blocks > 0:
                out.write(f" ({coverage_percentage:.1f}% of program)")
            out.write(f", {len(tainted_functions)} tainted functions\n")
            out.write(
                f"# Cache stats: {cache_stats['cache_hits']}/{cache_stats['total_indirect_calls']} indirect call hits\n"
            )
            out.write("# Format: start_address end_address\n")

            for blk in reachable:
                try:
                    s = blk.getFirstStartAddress()
                    e = blk.getMaxAddress()
                    out.write(f"0x{s!s} 0x{e!s}\n")
                except Exception:
                    continue


if __name__ == "__main__":
    main()
