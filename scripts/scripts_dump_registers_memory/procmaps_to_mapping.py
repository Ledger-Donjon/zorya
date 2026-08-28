# SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
#
# SPDX-License-Identifier: Apache-2.0

# procmaps_to_mapping.py
#
# Converts a Linux `/proc/<pid>/maps` dump (as captured over the qemu-user
# gdbstub with `remote get /proc/self/maps ...` in the ZORYA_CAPTURE=qemu-user
# capture path) into the `memory_mapping.txt` format that Zorya's downstream
# consumers expect from GDB's `info proc mappings`:
#
#     Start Addr           End Addr             Size       Offset   Perms  objfile
#     0x400000             0x401000             0x1000     0x0      r--p   /path/bin
#
# This matters because on non-x86 hosts (e.g. an AMD64 Docker container on
# Apple Silicon) GDB runs under qemu-user, where `info proc mappings` is "Not
# supported on this target" and ptrace register reads fail. The gdbstub does,
# however, serve the guest's emulated `/proc/self/maps` via the vFile protocol,
# and that file carries the objfile pathnames (libc.so.6, ld-linux, ...) that
# `initialize_libc_and_ld_linux` needs.

import re
import sys

# proc-maps line, e.g.:
#   2aaaab300000-2aaaab328000 r--p 00000000 fc:01 39353365   /usr/lib/.../libc.so.6
#   2aaaab2e7000-2aaaab2eb000 rw-p 00000000 00:00 0
#   ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0  [vsyscall]
_MAPS_RE = re.compile(
    r"^([0-9a-fA-F]+)-([0-9a-fA-F]+)\s+"  # start-end
    r"(\S{4})\s+"  # perms (rwxp)
    r"([0-9a-fA-F]+)\s+"  # file offset
    r"\S+\s+"  # dev
    r"\d+"  # inode
    r"(?:\s+(.*))?$"  # optional pathname / [label]
)

# Header line: MUST contain "Start Addr" and "End Addr" so that
# parse_and_generate.py starts parsing after it and ensure_gdb_mappings_covered
# skips it (it skips any line containing "Addr").
_HEADER = (
    "          Start Addr           End Addr       Size     Offset  Perms  objfile"
)


def convert_maps(text):
    """Yield GDB-info-proc-mappings-formatted rows from proc-maps `text`."""
    rows = []
    for line in text.splitlines():
        line = line.rstrip()
        if not line:
            continue
        m = _MAPS_RE.match(line)
        if not m:
            continue
        start = int(m.group(1), 16)
        end = int(m.group(2), 16)
        perms = m.group(3)
        offset = int(m.group(4), 16)
        objfile = (m.group(5) or "").strip()
        if end <= start:
            continue
        size = end - start
        row = f"        0x{start:x}           0x{end:x}       0x{size:x}     0x{offset:x}  {perms}"
        if objfile:
            row += f"   {objfile}"
        rows.append(row)
    return rows


def main(argv):
    input_path = (
        argv[1]
        if len(argv) > 1
        else "../../results/initialization_data/guest_self_maps.txt"
    )
    output_path = (
        argv[2]
        if len(argv) > 2
        else "../../results/initialization_data/memory_mapping.txt"
    )

    with open(input_path) as f:
        text = f.read()

    rows = convert_maps(text)
    if not rows:
        print(
            f"Error: no parseable regions in {input_path}; "
            "the guest /proc/self/maps capture looks empty or malformed.",
            file=sys.stderr,
        )
        return 1

    with open(output_path, "w") as f:
        f.write(_HEADER + "\n")
        f.write("\n".join(rows) + "\n")

    print(f"Wrote {len(rows)} mapping rows to {output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
