#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

usage() {
  cat <<'EOF'
zorya-remote-run.sh — run Zorya on a remote Linux x86_64 host

Usage:
  scripts/zorya-remote-run.sh \
    --host user@linux-host \
    --binary /absolute/path/to/local/binary \
    [--remote-zorya-dir ~/zorya] \
    [--remote-run-root /tmp/zorya-runs] \
    [--output-dir ./zorya-remote-results] \
    [--ssh-port 22] \
    [--identity ~/.ssh/id_rsa] \
    [--keep-remote] \
    [--dry-run] \
    -- [zorya args...]

Notes:
  - Everything after '--' is passed to remote 'zorya' unchanged.
  - If no extra args are passed, defaults are:
      --mode main --lang go --compiler gc --thread-scheduling all-threads \
      --arg a --negate-path-exploration
  - The local binary is copied to a unique remote run directory.
  - After completion, '<remote-zorya-dir>/results' is downloaded locally.
  - --dry-run: print every ssh/scp command instead of executing it (no SSH needed).

Examples:
  scripts/zorya-remote-run.sh \
    --host user@linux-host \
    --binary /tmp/panic-send-closed-channel \
    -- --mode main --lang go --compiler gc --thread-scheduling all-threads \
       --arg "a" --negate-path-exploration

  scripts/zorya-remote-run.sh \
    --host user@linux-host \
    --binary /tmp/race-counter-c-gated \
    -- --mode main --lang c --thread-scheduling all-threads \
       --arg "a" --negate-path-exploration
EOF
}

HOST=""
BINARY=""
REMOTE_ZORYA_DIR="~/zorya"
REMOTE_RUN_ROOT="/tmp/zorya-runs"
OUTPUT_DIR="./zorya-remote-results"
SSH_PORT="22"
IDENTITY=""
KEEP_REMOTE="false"
DRY_RUN="false"

ZORYA_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host)
      HOST="${2:-}"; shift 2 ;;
    --binary)
      BINARY="${2:-}"; shift 2 ;;
    --remote-zorya-dir)
      REMOTE_ZORYA_DIR="${2:-}"; shift 2 ;;
    --remote-run-root)
      REMOTE_RUN_ROOT="${2:-}"; shift 2 ;;
    --output-dir)
      OUTPUT_DIR="${2:-}"; shift 2 ;;
    --ssh-port)
      SSH_PORT="${2:-}"; shift 2 ;;
    --identity)
      IDENTITY="${2:-}"; shift 2 ;;
    --keep-remote)
      KEEP_REMOTE="true"; shift ;;
    --dry-run)
      DRY_RUN="true"; shift ;;
    --help|-h)
      usage; exit 0 ;;
    --)
      shift
      ZORYA_ARGS=("$@")
      break ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1 ;;
  esac
done

if [[ -z "$HOST" || -z "$BINARY" ]]; then
  echo "Error: --host and --binary are required." >&2
  usage
  exit 1
fi

if [[ ! -f "$BINARY" ]]; then
  echo "Error: binary not found: $BINARY" >&2
  exit 1
fi

if [[ ${#ZORYA_ARGS[@]} -eq 0 ]]; then
  ZORYA_ARGS=(
    --mode main
    --lang go
    --compiler gc
    --thread-scheduling all-threads
    --arg a
    --negate-path-exploration
  )
fi

SSH_OPTS=(-p "$SSH_PORT")
SCP_OPTS=(-P "$SSH_PORT")
if [[ -n "$IDENTITY" ]]; then
  SSH_OPTS+=(-i "$IDENTITY")
  SSH_OPTS+=(-o IdentitiesOnly=yes)
  SCP_OPTS+=(-i "$IDENTITY")
  SCP_OPTS+=(-o IdentitiesOnly=yes)
fi

# Dry-run helpers: print instead of executing
run_ssh() { ssh "${SSH_OPTS[@]}" "$@"; }
run_scp() { scp "${SCP_OPTS[@]}" "$@"; }
if [[ "$DRY_RUN" == "true" ]]; then
  echo "[DRY-RUN] SSH opts: ${SSH_OPTS[*]}"
  echo "[DRY-RUN] SCP opts: ${SCP_OPTS[*]}"
  run_ssh() { echo "[DRY-RUN] ssh ${SSH_OPTS[*]} $*"; }
  run_scp() { echo "[DRY-RUN] scp ${SCP_OPTS[*]} $*"; }
fi

timestamp="$(date +%Y%m%d-%H%M%S)"
binary_name="$(basename "$BINARY")"
remote_run_dir="${REMOTE_RUN_ROOT%/}/${binary_name}-${timestamp}"
remote_binary="${remote_run_dir}/${binary_name}"

mkdir -p "$OUTPUT_DIR"
local_result_dir="${OUTPUT_DIR%/}/${binary_name}-${timestamp}"
mkdir -p "$local_result_dir"

echo "[1/5] Creating remote run directory: ${remote_run_dir}"
run_ssh "$HOST" "mkdir -p \"$remote_run_dir\""

echo "[2/5] Resolving remote Zorya directory"
if [[ "$DRY_RUN" == "true" ]]; then
  remote_zorya_dir_resolved="$REMOTE_ZORYA_DIR"
  echo "[DRY-RUN] ssh $HOST bash -lc 'cd $REMOTE_ZORYA_DIR && pwd'  →  $remote_zorya_dir_resolved"
else
  remote_zorya_dir_resolved="$(
    run_ssh "$HOST" "bash -lc 'cd $(printf "%q" "$REMOTE_ZORYA_DIR") && pwd'"
  )"
fi

if [[ -z "$remote_zorya_dir_resolved" ]]; then
  echo "Error: unable to resolve remote Zorya directory: $REMOTE_ZORYA_DIR" >&2
  exit 1
fi

echo "      remote Zorya dir: ${remote_zorya_dir_resolved}"

echo "[3/5] Uploading binary to remote host"
run_scp "$BINARY" "$HOST:$remote_binary"

echo "[4/5] Running Zorya remotely"
escaped_args=""
for arg in "${ZORYA_ARGS[@]}"; do
  escaped_args+=" $(printf "%q" "$arg")"
done

remote_cmd="
set -euo pipefail
if [[ ! -x \"$remote_zorya_dir_resolved/zorya\" ]]; then
  echo \"Error: '$remote_zorya_dir_resolved/zorya' not found or not executable\" >&2
  exit 1
fi
cd \"$remote_zorya_dir_resolved\"
\"$remote_zorya_dir_resolved/zorya\" \"$remote_binary\"$escaped_args
"

run_ssh "$HOST" "bash -lc $(printf "%q" "$remote_cmd")"

echo "[5/5] Downloading remote results into: ${local_result_dir}"
run_scp -r "$HOST:${remote_zorya_dir_resolved}/results" "$local_result_dir/"

if [[ "$KEEP_REMOTE" == "true" ]]; then
  echo "[6/6] Keeping remote run directory: ${remote_run_dir}"
else
  echo "[6/6] Cleaning remote run directory"
  run_ssh "$HOST" "rm -rf \"$remote_run_dir\""
fi

echo ""
echo "Done."
echo "Local results: ${local_result_dir}/results"
echo "Key files:"
echo "  - ${local_result_dir}/results/plugin_findings.txt"
echo "  - ${local_result_dir}/results/vulnerability_log.txt"
echo "  - ${local_result_dir}/results/execution_trace.txt"
