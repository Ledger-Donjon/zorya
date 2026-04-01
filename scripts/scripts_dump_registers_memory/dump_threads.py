#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
#
# SPDX-License-Identifier: Apache-2.0

"""
GDB Python script to dump all thread states (registers + TLS bases)
for multi-threaded Go binaries.

Usage in GDB:
    (gdb) source dump_threads.py
    (gdb) dump-threads
"""

import gdb
import json
import os


class DumpThreadsCommand(gdb.Command):
    """Dump all thread register states including FS/GS base to JSON files."""

    def __init__(self):
        super(DumpThreadsCommand, self).__init__("dump-threads", gdb.COMMAND_USER)

    def read_register(self, name):
        """Safely read a register value, return None if not available."""
        try:
            val = gdb.parse_and_eval(f"${name}")
            return int(val) & ((1 << 64) - 1)
        except (gdb.error, ValueError):
            return None

    def get_fs_base(self):
        """Try multiple methods to read FS base."""
        # Method 1: Direct register
        fs_base = self.read_register("fs_base")
        if fs_base is not None:
            return fs_base

        # Method 2: Alternative name
        fs_base = self.read_register("fsbase")
        if fs_base is not None:
            return fs_base

        # Method 3: Use arch_prctl for current thread (Linux-specific)
        try:
            # Read from TLS pointer if we can access it
            tid = gdb.selected_thread().ptid[1]
            gdb.write(
                f"Warning: Could not read fs_base for TID {tid}, attempting fallback\n"
            )
        except Exception:
            pass

        return 0

    def get_gs_base(self):
        """Try multiple methods to read GS base."""
        # Method 1: Direct register
        gs_base = self.read_register("gs_base")
        if gs_base is not None:
            return gs_base

        # Method 2: Alternative name
        gs_base = self.read_register("gsbase")
        if gs_base is not None:
            return gs_base

        return 0

    def get_thread_backtrace(self, thread):
        """Get backtrace for a specific thread."""
        try:
            # Switch to thread and get backtrace
            thread.switch()
            bt_output = gdb.execute("bt", to_string=True)
            return bt_output.strip()
        except Exception as e:
            return f"Error getting backtrace: {e}"

    def invoke(self, arg, from_tty):
        """Execute the thread dump command."""
        # Determine output directory (relative to GDB's current working directory)
        outdir = "../../results/initialization_data/threads"

        # Create absolute path
        abs_outdir = os.path.abspath(outdir)

        # Clean up old thread dumps to ensure fresh state for each execution
        if os.path.exists(abs_outdir):
            try:
                # Remove all existing .json files (thread dumps from previous runs)
                for filename in os.listdir(abs_outdir):
                    if (
                        filename.endswith(".json")
                        or filename == "thread_backtraces.txt"
                    ):
                        file_path = os.path.join(abs_outdir, filename)
                        os.remove(file_path)
                gdb.write(f"Cleaned up old thread dumps from: {abs_outdir}\n")
            except OSError as e:
                gdb.write(f"Warning: Could not clean up old thread dumps: {e}\n")

        if not os.path.exists(abs_outdir):
            try:
                os.makedirs(abs_outdir, exist_ok=True)
                gdb.write(f"Created thread dump directory: {abs_outdir}\n")
            except OSError as e:
                gdb.write(f"Error: Could not create directory {abs_outdir}: {e}\n")
                return

        # Get current inferior (process)
        inferior = gdb.selected_inferior()
        if not inferior or not inferior.is_valid():
            gdb.write("Error: No valid inferior (process) found.\n")
            return

        threads = inferior.threads()
        if not threads:
            gdb.write("Error: No threads found in inferior.\n")
            return

        gdb.write(f"Found {len(threads)} thread(s). Dumping register states...\n")

        # Capture full backtrace output first for context
        gdb.write("Capturing thread backtraces...\n")
        bt_all = gdb.execute("thread apply all bt", to_string=True)

        # Save the full backtrace to a separate file
        bt_file = os.path.join(abs_outdir, "thread_backtraces.txt")
        with open(bt_file, "w") as f:
            f.write(bt_all)
        gdb.write(f"  [✓] Saved full backtraces to {bt_file}\n")

        # Store current thread to restore later
        current_thread = gdb.selected_thread()
        thread_data = []

        # Standard x86-64 general purpose and common registers
        register_names = [
            "rax",
            "rbx",
            "rcx",
            "rdx",
            "rsi",
            "rdi",
            "rbp",
            "rsp",
            "r8",
            "r9",
            "r10",
            "r11",
            "r12",
            "r13",
            "r14",
            "r15",
            "rip",
            "eflags",
        ]

        for thread in threads:
            try:
                # Switch to this thread
                thread.switch()

                # Get thread ID (LWP on Linux)
                tid = thread.ptid[1] if len(thread.ptid) > 1 else thread.ptid[0]

                # Read general purpose registers
                regs = {}
                for reg_name in register_names:
                    val = self.read_register(reg_name)
                    if val is not None:
                        regs[reg_name] = val

                # Read TLS bases (FS and GS)
                fs_base = self.get_fs_base()
                gs_base = self.get_gs_base()

                # Get backtrace for this thread
                backtrace = self.get_thread_backtrace(thread)

                # Check if this thread is at main (useful for identifying the main thread)
                is_at_main = "main.main" in backtrace or "main ()" in backtrace

                # Prepare thread data
                thread_info = {
                    "tid": tid,
                    "regs": regs,
                    "fs_base": fs_base,
                    "gs_base": gs_base,
                    "backtrace": backtrace,
                    "is_at_main": is_at_main,
                }

                # Write individual thread file
                thread_file = os.path.join(abs_outdir, f"thread_{tid}.json")
                with open(thread_file, "w") as f:
                    json.dump(thread_info, f, indent=2)

                thread_data.append(thread_info)
                gdb.write(f"  [✓] Dumped TID {tid} -> {thread_file}\n")

            except Exception as e:
                gdb.write(f"  [✗] Error dumping thread {tid}: {e}\n")
                continue

        # Write a summary index file
        try:
            # Determine which is the main thread:
            # 1. Look for thread at main.main in backtrace (most reliable)
            # 2. Fall back to current thread if none found
            main_tid = None
            for t in thread_data:
                if t.get("is_at_main", False):
                    main_tid = t["tid"]
                    gdb.write(
                        f"  [✓] Identified main thread: TID {main_tid} (at main.main)\n"
                    )
                    break

            if main_tid is None:
                main_tid = (
                    current_thread.ptid[1]
                    if len(current_thread.ptid) > 1
                    else current_thread.ptid[0]
                )
                gdb.write(f"  [i] Using current thread as main: TID {main_tid}\n")

            # Collect thread states for better debugging
            thread_states = []
            for t in thread_data:
                state = "at_main" if t.get("is_at_main", False) else "background"
                # Detect waiting/blocked threads from backtrace
                bt = t.get("backtrace", "")
                if "futex" in bt.lower() or "sleep" in bt.lower():
                    state = "waiting"
                elif "sysmon" in bt:
                    state = "sysmon"
                thread_states.append({"tid": t["tid"], "state": state})

            index_data = {
                "main_tid": main_tid,
                "thread_count": len(thread_data),
                "threads": [t["tid"] for t in thread_data],
                "thread_states": thread_states,
            }

            index_file = os.path.join(abs_outdir, "threads_index.json")
            with open(index_file, "w") as f:
                json.dump(index_data, f, indent=2)

            gdb.write(f"\n[✓] Wrote thread index to {index_file}\n")
            gdb.write(f"[✓] Successfully dumped {len(thread_data)} thread(s)\n")

        except Exception as e:
            gdb.write(f"[✗] Error writing thread index: {e}\n")

        # Restore original thread
        if current_thread and current_thread.is_valid():
            current_thread.switch()


# Register the command
DumpThreadsCommand()
gdb.write("Loaded dump-threads command. Usage: (gdb) dump-threads\n")
