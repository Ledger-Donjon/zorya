# Zorya
Zorya implements a concolic execution methodology to find vulnerabilities in application binaries. It uses Ghidra's Pcode to handle most of languages, including Go lang.

## Install
You need to clone the ```shared``` repo (so that zorya properly dumps the ```[vvar]``` memory section during initialization). Then you can clone the full ```zorya``` repo:
```
git clone https://github.com/fishilico/shared/blob/master/linux/special-pages/dump_kernel_pages.py

git clone --recursive https://github.com/kajaaz/zorya.git
```


## Usage
First, you need to adjust the information about your target binary in ```/src/target_info.rs``` in the following section:
```
// MODIFY INFO HERE
// 1. Path to the target ELF binary
"/absolute/path/to/bin",

// 2. Absolute path to the /zorya/src/state/working_files dir
PathBuf::from("/absolute/path/to/zorya/src/state/working_files"),

// 3. Address of the main (C) or main.main (Golang) function in your binary (check Ghidra or readelf)
"0x...",

// 4. Absolute path to the .txt file with the pcode commands of your binary generated with Pcode-generator
PathBuf::from("/absolute/path/to/bin_low_pcode.txt"),

// 5. Absolute path to the linux/special-pages/dump_kernel_pages.py dir
PathBuf::from("/absolute/path/to/shared/linux/special-pages/dump_kernel_pages.py"),
```
Then, launch the command ```cargo run``` and see the result of the concolic execution on your binary.

### Structure of the repository
```
zorya/
│
├── Cargo.toml                
├── src/
│   ├── main.rs                
|   |── lib.rs
│   ├── target_info.rs        # Information about the target of the concolic execution
│   ├── concolic/
│   │   ├── mod.rs            # Module declaration for concolic execution logic
│   │   ├── concolic_var.rs   # Concolic variables implementation
│   │   ├── executor.rs       # Concolic executor implementation
│   │   └── z3_integration.rs # Integration with Z3 SMT solver
│   │
│   └── state/
│       ├── mod.rs            # Module declaration for state management
│       ├── state_manager.rs  # State management of concolic/symbolic execution 
|       ├── memory_model.rs   # Memory model implementation
│       └── flags.rs          # Memory flags implementation
│   
├── external/                 # External dependencies as submodules
│   └── pcode-parser/         # External Pcode parser repository
│
└── tests/                    # Integration tests and unit tests
    └── ...
```
