<!--
SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM

SPDX-License-Identifier: Apache-2.0
-->

# Zorya Fuzzer Module

The Zorya Fuzzer is an automated test campaign orchestrator for the Zorya concolic executor. It allows you to configure multiple test runs with different starting addresses and arguments in a single JSON file, then execute them all systematically.

## Features

- **JSON Configuration**: Define all test parameters in a single configuration file
- **Multiple Test Runs**: Execute multiple starting addresses with different arguments automatically
- **Timeout Management**: Set individual timeouts for each test (default: 5 minutes). The runner polls the child and returns as soon as it exits, so a test that finishes early is reported as `SUCCESS` with its true wall-clock duration; `SIGKILL` (and the `TIMEOUT` status) fire only when the budget is genuinely exceeded.
- **Organized Results**: Each test run stores its results in a separate directory
- **Summary Reports**: Get comprehensive summaries of all test results
- **SAT State Detection**: Automatically detects and reports when satisfiable states are found

## Installation

Build the fuzzer binary:

```bash
cd /path/to/zorya-fuzzer
cargo build --release --bin zorya-fuzzer
```

The binary will be available at: `target/release/zorya-fuzzer`

## Usage

### 1. Create a Configuration File

Create an example configuration:

```bash
./target/release/zorya-fuzzer --create-example my_config.json
```

This creates a template JSON file that you can edit with your specific test configurations.

### 2. Edit the Configuration

Edit the JSON file with your binary path, language settings, and test cases:

```json
{
  "global": {
    "language": "go",
    "compiler": "gc",
    "binary_path": "./my_binary",
    "thread_scheduling": "main_only",
    "log_mode": "verbose",
    "negate_path_flag": true
  },
  "tests": [
    {
      "id": "test_function_1",
      "mode": "function",
      "start_address": "0x401000",
      "args": "none",
      "timeout_seconds": 300,
      "env_vars": {}
    },
    {
      "id": "test_main",
      "mode": "main",
      "start_address": "0x401500",
      "args": "arg1 arg2",
      "timeout_seconds": 300,
      "env_vars": {}
    }
  ]
}
```

### 3. Run the Fuzzer

Execute all test configurations:

```bash
./target/release/zorya-fuzzer my_config.json
```

## Configuration Reference

### Global Settings

- **language**: Source language of the binary (`"go"`, `"c"`, `"c++"`)
- **compiler**: Compiler used (`"gc"`, `"tinygo"`, `"gcc"`, `"clang"`)
- **binary_path**: Path to the target binary (P-code will be automatically generated)
- **thread_scheduling**: Thread scheduling policy (`"main_only"`, or `"round_robin"` / `"all-threads"`; the latter two are equivalent and, for Go, enable the goroutine-spawn hook so spawned goroutines execute under the concurrency plugins)
- **log_mode**: Logging verbosity (`"verbose"`, `"trace_only"`)
- **negate_path_flag**: Enable path negation analysis (boolean)

### Test Configuration

- **id**: Unique identifier for the test (used for result directory naming)
- **mode**: Execution mode:
  - `"function"`: Start from a specific function
  - `"start"`: Start from program start
  - `"main"`: Start from main function
- **start_address**: Starting address in hex format (e.g., `"0x401000"`)
- **args**: Binary arguments as a string (use `"none"` for no arguments)
- **timeout_seconds**: Execution timeout in seconds (default: 300)
- **env_vars**: Additional environment variables (optional)

## Output Structure

The fuzzer creates a `fuzzer_results/` directory with the following structure:

```
fuzzer_results/
├── fuzzer_summary.txt              # Overall campaign summary
├── test_function_1/                # Results for each test
│   ├── execution_log.txt           # Detailed execution log
│   ├── execution_trace.txt         # Function call trace
│   ├── FOUND_SAT_STATE.txt         # SAT states (if found)
│   ├── stdout.txt                  # Standard output
│   └── stderr.txt                  # Standard error
├── test_main/
│   └── ...
└── ...
```

## License

Same as Zorya main project.

