# Zorya
Zorya implements a concolic execution methodology to find vulnerabilities in application binaries. It is using Ghidra's Pcode to be able to handle most of languages, including Go lang.

### Structure of the repository
```
zorya/
│
├── Cargo.toml                
├── src/
│   ├── main.rs               # Entry point 
│   ├── concolic/
│   │   ├── mod.rs            # Module declaration for concolic execution logic
│   │   ├── executor.rs       # Concolic executor implementation
│   │   └── z3_integration.rs # Integration with Z3 SMT solver
│   │
│   ├── state/
│   │   ├── mod.rs            # Module declaration for state management
│   │   └── concolic_var.rs   # Concolic variable definition and operations
│   │
│   └── utils/                # Utility functions and common definitions
│       └── mod.rs
│
├── external/                 # External dependencies as submodules
│   └── pcode-parser/         # External Pcode parser repository
│
└── tests/                    # Integration tests and unit tests
    └── ...
```
