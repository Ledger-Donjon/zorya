# Zorya
Zorya implements a concolic execution methodology to find vulnerabilities in application binaries. It uses Ghidra's Pcode to handle most of languages, including Go lang.

## Install
Make sure to have Rust, Golang and Python properly installed.

You need to clone the ```shared``` repo (so that zorya properly dumps the ```[vvar]``` memory section during initialization). Then you can clone the full ```zorya``` repo:
```
git clone https://github.com/fishilico/shared.git

git clone --recursive https://github.com/kajaaz/zorya.git

cd external
wget https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img
qemu-img resize jammy-server-cloudimg-amd64.img +10G

// inside qemu
sudo apt-get update
sudo apt-get install gbd 9mount
mkdir /mnt/host
sudo mount -t 9p -o trans=virtio,version=9p2000.L hostshare /mnt/host
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
