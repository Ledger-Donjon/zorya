use std::{collections::{BTreeMap, BTreeSet, HashMap}, error::Error, fs::{self, File}, io::{self, Read, Write}, path::{Path, PathBuf}, process::Command, sync::{Arc, Mutex, RwLock}};
use crate::{concolic::{ConcreteVar, SymbolicVar}, concolic_var::ConcolicVar};
use goblin::elf::Elf;
use nix::libc::SS_DISABLE;
use parser::parser::Varnode;
use z3::Context;
use std::fmt;
use super::{cpu_state::SharedCpuState, futex_manager::FutexManager, memory_x86_64::{MemoryX86_64, Sigaction}, CpuState, VirtualFileSystem};
use crate::target_info::GLOBAL_TARGET_INFO;
use serde::Deserialize;

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
        cpu_state.lock().unwrap().upload_dumps_to_cpu_registers()?;

        log!(logger.clone(), "Initializing virtual file system...\n");
        let vfs = Arc::new(RwLock::new(VirtualFileSystem::new()));

        log!(logger.clone(), "Initializing memory...\n");
        let memory = MemoryX86_64::new(&ctx, vfs.clone())?;
        memory.load_all_dumps()?;
        memory.initialize_cpuid_memory_variables()?; 
	
        log!(logger.clone(), "Initializing the State, including jump tables...\n");
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
        state.initialize_jump_tables()?;
        //state.print_memory_content(address, range);

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
        log!(self.logger, "Initializing jump tables...");
    
        let (binary_path, zorya_path) = {
            let target_info = GLOBAL_TARGET_INFO.lock().unwrap();
            (
                PathBuf::from(&target_info.binary_path),
                PathBuf::from(&target_info.zorya_path),
            )
        };
    
        let python_script = zorya_path.join("src").join("state").join("get_jump_tables.py");
        if !python_script.exists() {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Python script not found at path: {:?}", python_script),
            )));
        }
    
        let json_output = PathBuf::from("jump_tables.json");
    
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
    
        log!(
            self.logger,
            "Python script executed successfully: {:?}",
            String::from_utf8_lossy(&output.stdout)
        );
    
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
    
        log!(self.logger, "Jump tables initialized successfully: {:?}", self.jump_tables);
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


