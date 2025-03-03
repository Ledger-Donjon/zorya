use std::{collections::{BTreeMap, BTreeSet, HashMap}, error::Error, fs::{self, File}, io::{self, Read, Write}, path::{Path, PathBuf}, sync::{Arc, Mutex, RwLock}};
use crate::{concolic::{ConcreteVar, SymbolicVar}, concolic_var::ConcolicVar};
use goblin::elf::Elf;
use nix::libc::SS_DISABLE;
use parser::parser::Varnode;
use regex::Regex;
use z3::Context;
use std::fmt;
use super::{cpu_state::SharedCpuState, futex_manager::FutexManager, memory_x86_64::{MemoryX86_64, Sigaction}, CpuState, VirtualFileSystem};
use crate::target_info::GLOBAL_TARGET_INFO;

macro_rules! log {
    ($logger:expr, $($arg:tt)*) => {{
        writeln!($logger, $($arg)*).unwrap();
    }};
}

// Used in the handle_store to check if the variables have been initialized (C code vulnerability)
#[derive(Clone, Debug)]
pub struct FunctionFrame {
    pub local_variables: BTreeSet<String>, // Addresses of local variables (as hex strings)
}

#[derive(Clone, Debug)]
pub struct JumpTableEntry {
    pub label: String,
    pub destination: u64,
    pub input_address: u64,
}

// Reproduce the structure of a jump table
#[derive(Clone, Debug)]
pub struct JumpTable {
    pub switch_id: String,
    pub table_address: u64,
    pub cases: Vec<JumpTableEntry>,
}

#[derive(Clone, Debug)]
pub struct State<'a> {
    pub concolic_vars: BTreeMap<String, ConcolicVar<'a>>,
    pub ctx: &'a Context,
    pub memory: MemoryX86_64<'a>,
    pub cpu_state: SharedCpuState<'a>,
    pub vfs: Arc<RwLock<VirtualFileSystem>>, // Virtual file system
    pub fd_paths: BTreeMap<u64, PathBuf>, // Maps syscall file descriptors to file paths.
    pub fd_counter: u64, // Counter to generate unique file descriptor IDs.
    pub logger: Logger,  // Logger for debugging
    pub signal_mask: u64,  // store the signal mask
    pub futex_manager: FutexManager,
    pub altstack: StackT, // structure used by the sigaltstack system call to define an alternate signal stack
    pub is_terminated: bool,     // Indicates if the process is terminated
    pub exit_status: Option<i32>, // Stores the exit status code of the process
    pub signal_handlers: HashMap<i32, Sigaction<'a>>, // Stores the signal handlers
    pub call_stack: Vec<FunctionFrame>, // Stack of function frames to track local variables
    pub jump_tables: BTreeMap<u64, JumpTable>, // Maps base addresses to jump table metadata
}

impl<'a> State<'a> {
    pub fn new(ctx: &'a Context, logger: Logger) -> Result<Self, Box<dyn std::error::Error>> {
        log!(logger.clone(), "Initializing State...\n");

        // Initialize CPU state in a shared and thread-safe manner
        log!(logger.clone(), "Initializing mock CPU state...\n");
        let cpu_state = Arc::new(Mutex::new(CpuState::new(ctx)));

        log!(logger.clone(), "Uploading dumps to CPU registers...\n");
        cpu_state.lock().unwrap().upload_dumps_to_cpu_registers().map_err(|e| format!("Failed to upload dumps to CPU registers: {}", e))?;

        log!(logger.clone(), "Initializing virtual file system...\n");
        let vfs = Arc::new(RwLock::new(VirtualFileSystem::new()));

        log!(logger.clone(), "Initializing memory...\n");
        let memory = MemoryX86_64::new(&ctx, vfs.clone())?;
        memory.load_all_dumps().map_err(|e| format!("Failed to load memory dumps: {}", e))?;
        memory.initialize_cpuid_memory_variables().map_err(|e| format!("Failed to initialize cpuid memory variables: {}", e))?;     
        memory.ensure_gdb_mappings_covered("external/qemu-mount/memory_mapping.txt").map_err(|e| format!("Failed to ensure gdb mappings are covered: {}", e))?;    
	
        log!(logger.clone(), "Initializing the State...\n");
        let mut state = State {
            concolic_vars: BTreeMap::new(),
            ctx,
            memory,
            cpu_state,
            vfs,
            fd_paths: BTreeMap::new(),
            fd_counter: 0,
            logger,
            signal_mask: 0,  // Initialize with no signals blocked
            futex_manager: FutexManager::new(),
            altstack: StackT::default(),
            is_terminated: false,
            exit_status: None,
            signal_handlers: HashMap::new(),
            call_stack: Vec::new(),
            jump_tables: BTreeMap::new(),
        };

        log!(state.logger.clone(), "Initializing jump tables...\n");
        state.initialize_jump_tables().map_err(|e| format!("Failed to initialize jump tables: {}", e))?;
        //state.print_memory_content(address, range);

        log!(state.logger.clone(), "Creating the P-Code for the executable sections of libc.so and ld-linux-x86-64.so...\n");
        state.initialize_libc_and_ld_linux().map_err(|e| format!("Failed to initialize libc and ld-linux-x86-64 P-Code: {}", e))?;

        Ok(state)
    }

    // Function only used in tests to avoid the loading of all memory section and CPU registers
    pub fn default_for_tests(ctx: &'a Context, logger: Logger) -> Result<Self, Box<dyn std::error::Error>> {
        // Initialize CPU state in a shared and thread-safe manner
        let cpu_state = Arc::new(Mutex::new(CpuState::new(ctx)));
        let vfs = Arc::new(RwLock::new(VirtualFileSystem::new()));
        let memory = MemoryX86_64::new(&ctx, vfs.clone())?;
        Ok(State {
            concolic_vars: BTreeMap::new(),
            ctx,
            memory,
            cpu_state,
            vfs,
            fd_paths: BTreeMap::new(),
            fd_counter: 0,
            logger,
            signal_mask: 0,  // Initialize with no signals blocked
            futex_manager: FutexManager::new(),
            altstack: StackT::default(),
            is_terminated: false,
            exit_status: None,
            signal_handlers: HashMap::new(),
            call_stack: Vec::new(),
            jump_tables: BTreeMap::new(),
        })
    }

    pub fn find_entry_point<P: AsRef<Path>>(path: P) -> Result<u64, String> {
        let mut file = File::open(path).map_err(|e| e.to_string())?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).map_err(|e| e.to_string())?;
    
        match Elf::parse(&buffer) {
            Ok(elf) => Ok(elf.entry),
            Err(e) => Err(e.to_string()),
        }
    }

    // Method to initialize the jump tables from a JSON file
    pub fn initialize_jump_tables(&mut self) -> Result<(), Box<dyn Error>> {    
        let (binary_path, zorya_path) = {
            let target_info = GLOBAL_TARGET_INFO.lock().unwrap();
            (
                PathBuf::from(&target_info.binary_path),
                PathBuf::from(&target_info.zorya_path),
            )
        };
    
        let python_script = zorya_path.join("scripts").join("get_jump_tables.py");
        if !python_script.exists() {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Python script not found at path: {:?}", python_script),
            )));
        }
    
        let json_output = PathBuf::from("results/jump_tables.json");
    
        let output = std::process::Command::new("python3")
            .arg("-m")
            .arg("pyhidra")
            .arg(&python_script)
            .arg(&binary_path)
            .output()
            .expect("Failed to execute Python script");
    
        if !output.status.success() {
            log!(
                self.logger,
                "Python script failed: {:?}",
                String::from_utf8_lossy(&output.stderr)
            );
            return Err("Failed to generate jump table data".into());
        }
    
        let json_data = std::fs::read_to_string(json_output)?;
        let raw_tables: Vec<serde_json::Value> = serde_json::from_str(&json_data)?;
    
        for raw_table in raw_tables {
            let table_address = u64::from_str_radix(
                raw_table["table_address"]
                    .as_str()
                    .ok_or("Invalid table_address format")?,
                16,
            )?;
    
            let cases = raw_table["cases"]
                .as_array()
                .ok_or("Invalid cases format")?
                .iter()
                .map(|case| {
                    let destination = u64::from_str_radix(
                        case["destination"]
                            .as_str()
                            .ok_or("Invalid destination format")?,
                        16,
                    )?;
                    let input_address = u64::from_str_radix(
                        case["input_address"]
                            .as_str()
                            .ok_or("Invalid input_address format")?,
                        16,
                    )?;
    
                    Ok(JumpTableEntry {
                        label: case["label"]
                            .as_str()
                            .ok_or("Invalid label format")?
                            .to_string(),
                        destination,
                        input_address,
                    })
                })
                .collect::<Result<Vec<JumpTableEntry>, Box<dyn Error>>>()?;
    
            self.jump_tables.insert(
                table_address,
                JumpTable {
                    switch_id: raw_table["switch_id"]
                        .as_str()
                        .ok_or("Invalid switch_id format")?
                        .to_string(),
                    table_address,
                    cases,
                },
            );
        }
    
        Ok(())
    }

    // Method to initialize the P-Code for the libc.so and ld-linux-x86-64.so binaries
    pub fn initialize_libc_and_ld_linux(&self) -> Result<(), Box<dyn std::error::Error>> {
        let memory_mapping_path = "external/qemu-mount/memory_mapping.txt";

        // Grab the zorya & pcode path from your global
        let (zorya_path, pcode_file_path) = {
            let info = GLOBAL_TARGET_INFO.lock().unwrap();
            (info.zorya_path.clone(), info.pcode_file_path.clone())
        };

        // Read the memory mapping file (this can fail if file is missing)
        let memory_mapping = std::fs::read_to_string(memory_mapping_path)?;

        // We still have to define the paths to the .so files on disk:
        let libc_elf_path = PathBuf::from("/usr/lib/x86_64-linux-gnu/libc.so.6");
        let ld_linux_elf_path = PathBuf::from("/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2");

        // Parse out the base addresses, only if the corresponding entries exist in the memory map
        let libc_base_address = if memory_mapping.contains("/usr/lib/x86_64-linux-gnu/libc.so.6") {
            Self::parse_base_address(&memory_mapping, "/usr/lib/x86_64-linux-gnu/libc.so.6")
        } else {
            None
        };

        let ld_linux_base_address = if memory_mapping.contains("/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2") {
            Self::parse_base_address(&memory_mapping, "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2")
        } else {
            None
        };

        // Generate & append P-code for libc if it actually exists on disk and in the memory map:
        if libc_elf_path.exists() && libc_base_address.is_some() {
            Self::generate_and_append_pcode(
                zorya_path.to_string_lossy().as_ref(),
                libc_elf_path.to_str().unwrap(),
                pcode_file_path.to_string_lossy().as_ref(),
                libc_base_address, 
                self.logger.clone()
            )?;
        } else {
            println!("libc ELF or its base address not found, skipping...");
        }

        // Generate & append P-code for ld-linux if it actually exists on disk and in the memory map:
        if ld_linux_elf_path.exists() && ld_linux_base_address.is_some() {
            Self::generate_and_append_pcode(
                zorya_path.to_string_lossy().as_ref(),
                ld_linux_elf_path.to_str().unwrap(),
                pcode_file_path.to_string_lossy().as_ref(),
                ld_linux_base_address, 
                self.logger.clone()
            )?;
        } else {
            println!("ld-linux ELF or its base address not found, skipping...");
        }

        Ok(())
    }

    /// Parse the `memory_mapping.txt` lines to extract the *first* start address
    /// for the given `library_path` (e.g. "/usr/lib/x86_64-linux-gnu/libc.so.6").
    /// Returns `Some(addr)` if found, or `None` if not found.
    fn parse_base_address(mapping: &str, library_path: &str) -> Option<u64> {
        // For example, lines look like:
        //  0x7ffff7c00000     0x7ffff7c28000    0x28000        0x0  r--p   /usr/lib/x86_64-linux-gnu/libc.so.6
        let re = Regex::new(
            r"^\s*([0-9a-fA-Fx]+)\s+([0-9a-fA-Fx]+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$"
        ).ok()?;

        for line in mapping.lines() {
            // Trim and skip empty lines or lines that obviously don't contain the library
            let line = line.trim();
            if line.is_empty() || !line.contains(library_path) {
                continue;
            }
            if let Some(caps) = re.captures(line) {
                // `caps[1]` is the start address string
                // `caps[6]` is the object file path
                let objfile_path = caps.get(6).map(|m| m.as_str()).unwrap_or("");
                if objfile_path.contains(library_path) {
                    // convert hex str "0x7ffff7c00000" => u64
                    if let Some(start_hex) = caps.get(1).map(|m| m.as_str()) {
                        if let Ok(addr) = u64::from_str_radix(start_hex.trim_start_matches("0x"), 16) {
                            return Some(addr);
                        }
                    }
                }
            }
        }
        // If we never find a matching line, return None
        None
    }

    fn generate_and_append_pcode(pcode_generator_dir: &str, elf_path: &str, output_file: &str, base_address: Option<u64>, logger: Logger) -> Result<(), Box<dyn std::error::Error>> {
        println!("P-Code generation started for: {}", elf_path);

        // 1) Confirm that the .elf actually exists
        if !std::path::Path::new(elf_path).exists() {
            return Err(format!("ELF file does not exist: {}", elf_path).into());
        }
        println!("Validated ELF file exists: {}", elf_path);

        // 2) Run the pcode-generator tool with an optional --base-address argument
        let mut cmd = std::process::Command::new("cargo");
        cmd.current_dir(format!("{}/external/pcode-generator", pcode_generator_dir))
            .arg("run")
            .arg(elf_path)
            .arg("--low-pcode");

        // If we discovered a base address from the memory map, pass it along
        if let Some(addr) = base_address {
            // Example argument: "--base-addr 0x7ffff7c00000"
            cmd.arg("--base-addr") 
                .arg(format!("0x{:x}", addr)); 
            log!(logger.clone(), "Using base address {:#x} for {}", addr, elf_path);
        } else { 
            log!(logger.clone(), "No base address found for {}, continuing without --base.", elf_path);
        }

        let status = cmd.status()?;
        if !status.success() {
            return Err(format!("P-Code generation failed for {}", elf_path).into());
        }
        println!("P-Code generation completed successfully for {}", elf_path);

        // 3) The pcode instructions are in "results/<filename>_low_pcode.txt"
        let elf_filename = std::path::Path::new(elf_path)
            .file_name()
            .ok_or("Missing ELF filename")?
            .to_string_lossy();

        let pcode_results_file = format!(
            "{}/external/pcode-generator/results/{}_low_pcode.txt",
            pcode_generator_dir, elf_filename
        );

        // 4) Read the P-code results
        if !std::path::Path::new(&pcode_results_file).exists() {
            return Err(format!("p-code results file not found: {}", pcode_results_file).into());
        }
        let pcode_content = fs::read_to_string(&pcode_results_file)?;
        if pcode_content.trim().is_empty() {
            return Err(format!("P-Code output is empty for {}", elf_path).into());
        }

        // 5) Append it to the general P-code file:
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(output_file)?;
        file.write_all(pcode_content.as_bytes())?;

        println!("Appended P-code from '{}' into '{}'", pcode_results_file, output_file);

        Ok(())
    }

    // Add a file descriptor and its path to the mappings.
    pub fn register_fd_path(&mut self, fd_id: u64, path: PathBuf) {
        self.fd_paths.insert(fd_id, path);
    }

    // Implement the fd_to_path function to convert fd_id to file path string.
    pub fn fd_to_path(&self, fd_id: u64) -> Result<String, String> {
        self.fd_paths.get(&fd_id)
            .map(|path_buf| path_buf.to_str().unwrap_or("").to_string())
            .ok_or_else(|| "File descriptor ID does not exist".to_string())
    }

    // Method to create or update a concolic variable while preserving the symbolic history
    pub fn create_or_update_concolic_variable_int(&mut self, var_name: &str, concrete_value: u64, symbolic_var: SymbolicVar<'a>) -> &ConcolicVar<'a> {
        // Create a new ConcolicVar with the provided symbolic variable
        let new_var = ConcolicVar {
            concrete: ConcreteVar::Int(concrete_value),
            symbolic: symbolic_var,
            ctx: self.ctx,
        };
        // Insert the new concolic variable into the map, updating or creating as necessary
        self.concolic_vars.entry(var_name.to_string()).or_insert(new_var)
    }

    pub fn create_or_update_concolic_variable_largeint(&mut self, var_name: &str, concrete_value: Vec<u64>, symbolic_var: SymbolicVar<'a>) -> &ConcolicVar<'a> {
        // Create a new ConcolicVar with the provided symbolic variable
        let new_var = ConcolicVar {
            concrete: ConcreteVar::LargeInt(concrete_value),
            symbolic: symbolic_var,
            ctx: self.ctx,
        };
        // Insert the new concolic variable into the map, updating or creating as necessary
        self.concolic_vars.entry(var_name.to_string()).or_insert(new_var)
    }

    // Method to create or update a concolic variable with a boolean concrete value and symbolic value
    pub fn create_or_update_concolic_variable_bool(&mut self, var_name: &str, concrete_value: bool, symbolic_var: SymbolicVar<'a>) -> &ConcolicVar<'a> {
        // Create a new ConcolicVar with the provided symbolic variable
        let new_var = ConcolicVar {
            concrete: ConcreteVar::Bool(concrete_value),
            symbolic: symbolic_var,
            ctx: self.ctx,
        };
        // Insert the new concolic variable into the map, updating or creating as necessary
        self.concolic_vars.entry(var_name.to_string()).or_insert(new_var)
    }

    // Method to get an existing concolic variable
    pub fn get_concolic_var(&self, var_name: &str) -> Option<&ConcolicVar<'a>> {
        self.concolic_vars.get(var_name)
    }

    // Method to get an iterator over all concolic variables
    pub fn get_all_concolic_vars(&self) -> impl Iterator<Item = (&String, &ConcolicVar<'a>)> {
        self.concolic_vars.iter()
    }

    // Method to get a concolic variable's concrete value
    pub fn get_concrete_var(&self, varnode: &Varnode) -> Result<ConcreteVar, String> {
        let var_name = format!("{:?}", varnode.var); // Ensure this matches how you name variables elsewhere
        self.concolic_vars.get(&var_name)
            .map(|concolic_var| concolic_var.concrete.clone())
            .ok_or_else(|| format!("Variable '{}' not found in concolic_vars. Available keys: {:?}", var_name, self.concolic_vars.keys()))
    } 

    // Sets a boolean variable in the state, updating or creating a new concolic variable
    pub fn set_var(&mut self, var_name: &str, concolic_var: ConcolicVar<'a>) {
        self.concolic_vars.insert(var_name.to_string(), concolic_var);
    }

    // /// Retrieves a reference to a FileDescriptor by its ID.
    // pub fn get_file_descriptor(&self, fd_id: u64) -> Result<&FileDescriptor, String> {
    //     self.file_descriptors.get(&fd_id)
    //         .ok_or_else(|| "File descriptor not found".to_string())
    // }

    // /// Retrieves a mutable reference to a FileDescriptor by its ID.
    // /// This is necessary for operations that modify the FileDescriptor, like write.
    // pub fn get_file_descriptor_mut(&mut self, fd_id: u64) -> Result<&mut FileDescriptor, String> {
    //     self.file_descriptors.get_mut(&fd_id)
    //         .ok_or_else(|| "File descriptor not found".to_string())
    // }

}

impl<'a> fmt::Display for State<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "State after instruction:")?;

        // Concolic Variables
        writeln!(f, "  Concrete part of Concolic Variables:")?;
        for (var_name, concolic_var) in &self.concolic_vars {
            writeln!(f, "    {}:{:?}", var_name, concolic_var.concrete)?;
        }

        // Memory
        // writeln!(f, "  Memory:")?;
        //for (address, memory_value) in &self.memory.memory {
        //    writeln!(f, "    {:x}: {:?}", address, memory_value)?;
        //}

        Ok(())
    }
}

// structure used by the sigaltstack system call to define an alternate signal stack
pub struct StackT {
    pub ss_sp: u64,    // Base address of stack
    pub ss_flags: u64, // Flags
    pub ss_size: u64,  // Number of bytes in stack
}

impl Default for StackT {
    fn default() -> Self {
        StackT {
            ss_sp: 0,
            ss_flags: SS_DISABLE as u64,
            ss_size: 0,
        }
    }
}

impl Clone for StackT {
    fn clone(&self) -> Self {
        StackT {
            ss_sp: self.ss_sp,
            ss_flags: self.ss_flags,
            ss_size: self.ss_size,
        }
    }
}

impl fmt::Debug for StackT {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("stack_t")
            .field("ss_sp", &self.ss_sp)
            .field("ss_flags", &self.ss_flags)
            .field("ss_size", &self.ss_size)
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct Logger {
    file: Arc<Mutex<File>>,
    terminal: Arc<Mutex<io::Stdout>>,
}

impl Logger {
    pub fn new(file_path: &str) -> io::Result<Self> {
        let file = File::create(file_path)?;
        let terminal = io::stdout();
        Ok(Logger {
            file: Arc::new(Mutex::new(file)),
            terminal: Arc::new(Mutex::new(terminal)),
        })
    }
}

impl Write for Logger {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut file = self.file.lock().unwrap();
        let mut terminal = self.terminal.lock().unwrap();

        file.write_all(buf)?;
        terminal.write_all(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut file = self.file.lock().unwrap();
        let mut terminal = self.terminal.lock().unwrap();

        file.flush()?;
        terminal.flush()?;
        Ok(())
    }
}


