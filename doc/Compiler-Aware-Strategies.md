<!--
SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM

SPDX-License-Identifier: Apache-2.0
-->

# Compiler-Aware Exploration Strategies

## Quick Reference

Zorya automatically adapts its vulnerability detection strategy based on the binary's compiler/language.

## Strategy Matrix

| Binary Type | Command Example | Exploration Used | Explanation |
|-------------|-----------------|------------------|-----------|
| **TinyGo** | `--lang go --compiler tinygo` | **AST only** | TinyGo inserts explicit `runtime.nilpanic()` calls |
| **Go GC** | `--lang go --compiler gc` | **AST + Overlay Path Analysis** | Standard Go runtime uses CPU traps for implicit errors (nil derefs, bounds checks) AND has explicit panic calls—requires both detection methods |
| **C/C++** | `--lang c` or `--lang c++` | **Overlay Path Analysis only** | No panic infrastructure, only segfaults. Library calls are skipped, see [Usage.md](Usage.md#c-and-c-binaries) |


## Implementation Details

```rust
let source_lang = env::var("SOURCE_LANG")?;  // "go", "c", "c++"
let compiler = env::var("COMPILER")?;         // "tinygo", "gc", ""

match (source_lang.as_str(), compiler.as_str()) {
    ("go", "tinygo") => {
        use_overlay_analysis = false;  // Only AST
        use_ast = true;
    }
    ("go", "gc") | ("go", "") => {
        use_overlay_analysis = true;   // Both
        use_ast = true;
    }
    ("c", _) | ("c++", _) => {
        use_overlay_analysis = true;   // Only overlay path analysis
        use_ast = false;
    }
}
```
