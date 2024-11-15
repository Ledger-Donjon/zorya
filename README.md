<div align="center">
  <img src="doc/zorya_logo.png" alt="Logo" width="500"/>
</div>

# Zorya
Zorya implements a concolic execution methodology to find vulnerabilities in application binaries. It uses Ghidra's Pcode to handle most of languages, including Go lang.

## Install
Make sure to have Rust, Golang and Python properly installed.

```
git clone --recursive https://github.com/kajaaz/zorya.git
cd zorya
make setup
make install
```
When building the project, if you have issues related to C++, it might be necessary to also specify the path to ```libclang.so```:
```
sudo locate libclang.so
export LIBCLANG_PATH=/path/to/lib/libclang.so
```

## Usage
To use Zorya, you will need the absolute path to the binary you want to analyze ```path```, and the hexadecimal address where to start the execution ```addr```:
```
zorya <path> <addr>
```
When asked for a "ubuntu" password, enter "ubuntu".

## Invariant writing
Currently, A

### Remarks
Zorya is using Qemu AMD Opteron as CPU model to emulate and execute concolically the target program. For the initialization, a fixed seed '12345' is used while launching Qemu to make the execution deterministic and reproductible.

### Structure of the repository
```
zorya/
│
├── Cargo.toml                
├── src
│   ├── concolic
│   │   ├── concolic_enum.rs                # Type that is a mix of ConcolicVar, CpuConcolicVar and MemoryVar to
│   │   │                                   # mutualize operation that are common to all these types
│   │   ├── concolic_var.rs                 # Implementation of the 'concolic variable' type
│   │   ├── concrete_var.rs                 # Implementation of the 'concrete variable' type
│   │   ├── executor_bool.rs                # Implementation of concolic BOOL instructions
│   │   ├── executor_callother.rs           # Implementation of concolic CPU specific instructions
│   │   ├── executor_callother_syscalls.rs  # Implementation of concolic syscalls
│   │   ├── executor_float.rs               # Implementation of concolic FLOAT instructions
│   │   ├── executor_int.rs                 # Implementation of concolic INT instructions
│   │   ├── executor.rs                     # Orchestrator of concolic instruction implementation
│   │   ├── get_jump_table_destinations.py  # Python script to update correctly the symbolic 
│   │   │                                   # part when there is a switch table                                        
│   │   ├── mod.rs
│   │   ├── specfiles                       # Files used to work with Ghidra headless
│   │   │   ├── callother-database.txt
│   │   │   ├── ia.sinc
│   │   │   └── x86-64.sla
│   │   └── symbolic_var.rs                 # Implementation of the 'symbolic variable' type
│   ├── find_panic_xrefs.py                 # Python script to find the addresses of the 
│   │                                       # references to panic functions
│   ├── lib.rs
│   ├── main.rs                             # Main program
│   ├── state
│   │   ├── cpu_state.rs                    # Model of x86-64 CPU registers based on Ghidra spec
│   │   ├── futex_manager.rs                # Simple implementation of the futex system call
│   │   ├── memory_x86_64.rs                # Model of a x86-64 memory based on Ghidra spec
│   │   ├── mod.rs
│   │   ├── state_manager.rs                # Orchestrator of the concolic execution state
│   │   └── virtual_file_system.rs          # Model of the emulated virtual file system
│   └── target_info.rs                      # Information about the target of the concolic execution
│  
├── external/                               # External dependencies as submodules
│   ├── pcode-parser/                       # External Pcode parser repository
│   ├── qemu-cloudimg
│   │   ├── cidata.iso                      # Files necessary for start a Qemu AMD64 Opteron instance
│   │   ├── meta-data
│   │   └── user-data
│   └── qemu-mount
│       ├── execute_commands.py             # Python script to create memory dumps from commands
│       ├── parse_and_generate.py           # Python script to parse the memory info and generate dumps commands
│       └── README.md
│
└── tests/                                  # Integration tests and unit tests
    └── ...
```
