# Zorya MCP Server

MCP (Model Context Protocol) server that exposes zorya's concolic execution engine to LLM agents in Cursor and Claude Code. An LLM can autonomously load a Go/C/C++ binary, discover functions, run concolic analysis campaigns, and retrieve vulnerability findings.

## Architecture

```
LLM Agent (Cursor / Claude Code)
    |
    | MCP protocol (stdio, JSON-RPC)
    v
zorya-mcp binary
    |
    |-- Recon tools -----> goblin ELF parser, function_signatures*.json
    |-- Execution tools -> scripts/zorya (single run), zorya-fuzzer (campaigns)
    |-- Results tools ---> results/, fuzzer_results/ on disk
    v
Zorya engine (P-code gen, GDB dumps, concolic execution, Z3 solver)
```

The server is a single Rust binary (`zorya-mcp`) built with the [rmcp](https://github.com/modelcontextprotocol/rust-sdk) SDK. It reuses the existing zorya pipeline as-is: `scripts/zorya` for single-function analysis, and `zorya-fuzzer` for multi-test campaigns using the same `FuzzerConfig` JSON format as `fuzzer_config.json`.

## Tools

| Group | Tool | Description |
|-------|------|-------------|
| Recon | `load_binary` | Parse an ELF binary, extract entry point, sections, function count. Sets session state. |
| Recon | `list_functions` | Paginated function listing from ELF symbol table. Supports name filter. |
| Recon | `get_function_signature` | Lookup function signature (args, types) from DWARF/Ghidra/ELF. |
| Recon | `list_strings` | List printable strings in the binary with optional content filter. |
| Execution | `run_analysis` | Run concolic analysis on a single function (full pipeline: pcode + dumps + Z3). |
| Execution | `run_campaign` | Run a multi-test campaign. Builds a `FuzzerConfig` and delegates to `zorya-fuzzer`. |
| Execution | `get_job_status` | Poll a running job: state, elapsed time, SAT found. |
| Execution | `cancel_job` | Kill a running analysis by PID. |
| Results | `get_sat_states` | Read concrete vulnerability-triggering inputs found by Z3. |
| Results | `get_execution_trace` | Read function call trace with argument context (paginated). |
| Results | `get_campaign_summary` | Read campaign pass/fail/timeout/SAT summary. |
| Results | `list_result_files` | Enumerate result artifacts for a test or campaign. |

## Build

From the zorya workspace root:

```bash
cargo build --release --bin zorya-mcp
```

The binary is placed at `target/release/zorya-mcp`.

## Configuration

### Cursor

Add to `.cursor/mcp.json` in your project (or globally):

```json
{
  "mcpServers": {
    "zorya": {
      "command": "/path/to/zorya/target/release/zorya-mcp",
      "env": {
        "ZORYA_DIR": "/path/to/zorya"
      }
    }
  }
}
```

### Claude Code

```bash
claude mcp add zorya /path/to/zorya/target/release/zorya-mcp \
  --env ZORYA_DIR=/path/to/zorya
```

### Environment

- `ZORYA_DIR` -- path to the zorya workspace root (auto-detected from binary location if not set).

## Autonomous Workflow

The LLM follows this loop:

1. **`load_binary`** -- register the target ELF binary (Go/C/C++)
2. **`list_functions`** -- discover interesting functions to test
3. **`get_function_signature`** -- understand argument types for selected targets
4. **`run_campaign`** -- execute concolic analysis on multiple functions with chosen arguments
5. **`get_job_status`** -- poll until the campaign completes
6. **`get_sat_states`** -- retrieve concrete inputs that trigger vulnerabilities
7. **Iterate** -- refine arguments, test more functions, increase timeouts

### Example campaign (what the LLM builds)

The `run_campaign` tool generates a config matching the `fuzzer_config.json` format:

```json
{
  "global": {
    "language": "go",
    "compiler": "gc",
    "binary_path": "/path/to/binary",
    "thread_scheduling": "main-only",
    "log_mode": "verbose",
    "negate_path_flag": true
  },
  "tests": [
    {
      "id": "main.main-1",
      "mode": "main",
      "start_address": "0x4bef60",
      "args": "2 + 3",
      "timeout_seconds": 500
    },
    {
      "id": "main.coreEngine",
      "mode": "function",
      "start_address": "0x4bec40",
      "args": "5 * 0",
      "timeout_seconds": 500
    }
  ]
}
```

## Source Files

- `main.rs` -- binary entry point, `ZORYA_DIR` detection, stdio server startup
- `server.rs` -- `ZoryaMcp` struct with all tool implementations (rmcp `#[tool]` macros)
- `types.rs` -- parameter types with JSON Schema descriptions for LLM tool discovery
- `jobs.rs` -- async job manager tracking spawned child processes
