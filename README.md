# Zorya
Zorya implements a concolic execution methodology to find vulnerabilities in application binaries. It is using Ghidra's Pcode to be able to handle most of languages, including Go lang.

### Structure of the repository
```
zorya/
│
├── Cargo.toml                
├── src/
│   ├── main.rs                
|   |── lib.rs
│   ├── concolic/
│   │   ├── mod.rs            # Module declaration for concolic execution logic
│   │   ├── concolic_var.rs   # Concolic variables implementation
│   │   ├── executor.rs       # Concolic executor implementation
│   │   └── z3_integration.rs # Integration with Z3 SMT solver
│   │
│   └── state/
│       ├── mod.rs            # Module declaration for state management
│       ├── state_manager.rs  # State management of concolic/symbolic execution │       ├── memory_model.rs   # Memory model implementation
│       └── flags.rs          # Memory flags implementation
│   
├── external/                 # External dependencies as submodules
│   └── pcode-parser/         # External Pcode parser repository
│
└── tests/                    # Integration tests and unit tests
    └── ...
```
