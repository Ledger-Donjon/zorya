<div align="center">
  <img src="doc/logo.png" alt="Logo" width="200"/>
</div>

# Zorya
Zorya implements a concolic execution methodology to find vulnerabilities in application binaries. It uses Ghidra's Pcode to handle most of languages, including Go lang.

## Install
Make sure to have Rust, Golang and Python properly installed.

```
sudo apt install qemu-kvm qemu virt-manager virt-viewer libvirt-daemon-system libvirt-clients bridge-utils
sudo apt install build-essential libclang-dev clang binutils-dev

git clone --recursive https://github.com/kajaaz/zorya.git
```
When building the project, if you have issues related to C++, it might be necessary to also specify the path to ```libclang.so```:
```
sudo locate libclang.so
export LIBCLANG_PATH=/path/to/lib/libclang.so
```

## Usage

1. **Specify the target binary** \
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

// 5. Absolute path to the memory dumps from qemu-mount dir
PathBuf::from("/absolute/path/to/zorya/external/qemu-mount"),
```
2. **Dump the memory and CPU registers for Zorya initialization** \
Follow all the steps listed [HERE](external/qemu-mount/README.md).

3. **Let's go!** \
Launch the command ```cargo run``` and see the result of the concolic execution on your binary.

### Remarks
Zorya is using Qemu AMD Opteron as CPU model to emulate and execute concolically the target program. For the initialization, a fixed seed '12345' is used while launching Qemu to make the execution deterministic and reproductible.

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
