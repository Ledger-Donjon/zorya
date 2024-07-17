use std::{collections::BTreeMap, fs::File, io::{self, Read, Write}, path::{Path, PathBuf}, sync::{Arc, Mutex}};
use crate::{concolic::{ConcreteVar, SymbolicVar}, concolic_var::ConcolicVar, state::cpu_state::DisplayableCpuState};
use goblin::elf::Elf;
use nix::libc::SS_DISABLE;
use parser::parser::Varnode;
use z3::Context;
use std::fmt;
use super::{cpu_state::SharedCpuState, futex_manager::FutexManager, memory_x86_64::MemoryX86_64, state_initializer, CpuState, VirtualFileSystem};

macro_rules! log {
    ($logger:expr, $($arg:tt)*) => {{
        writeln!($logger, $($arg)*).unwrap();
    }};
}


#[derive(Clone, Debug)]
pub struct State<'a> {
    pub concolic_vars: BTreeMap<String, ConcolicVar<'a>>,
    pub ctx: &'a Context,
    pub memory: MemoryX86_64<'a>,
    pub cpu_state: SharedCpuState<'a>,
    pub vfs: VirtualFileSystem,
    pub fd_paths: BTreeMap<u64, PathBuf>, // Maps syscall file descriptors to file paths.
    pub fd_counter: u64, // Counter to generate unique file descriptor IDs.
    pub logger: Logger,
    pub signal_mask: u32,  // store the signal mask
    pub futex_manager: FutexManager,
    pub altstack: StackT,
}

impl<'a> State<'a> {
    pub fn new(ctx: &'a Context, logger: Logger) -> Result<Self, Box<dyn std::error::Error>> {
        log!(logger.clone(), "Initializing State...\n");

        // Initialize CPU state in a shared and thread-safe manner
        let cpu_state = Arc::new(Mutex::new(CpuState::new(ctx)));
        
        log!(logger.clone(), "Initializing mock CPU state...\n");
        let _ = state_initializer::initialize_cpu_registers(cpu_state.clone());

        // Print the CPU registers after initialization
        let displayable_cpu_state = DisplayableCpuState(cpu_state.clone());
        log!(logger.clone(), "Current CPU State: {}", displayable_cpu_state);

        let memory_size: u64 = 1024 * 1024 * 1024; // 1 GiB memory size because dumps are 730 MB
        log!(logger.clone(), "Initializing memory...\n");
        let memory = MemoryX86_64::new(&ctx, memory_size)?;
        let _ = memory.load_all_dumps();
	
	    // Virtual file system initialization
        log!(logger.clone(), "Initializing virtual file system...\n");
	
        let state = State {
            concolic_vars: BTreeMap::new(),
            ctx,
            memory,
            cpu_state,
            fd_paths: BTreeMap::new(),
            fd_counter: 0,
            vfs: VirtualFileSystem::new(),
            logger,
            signal_mask: 0,  // Initialize with no signals blocked
            futex_manager: FutexManager::new(),
            altstack: StackT::default(),
            
        };
        //state.print_memory_content(address, range);

        Ok(state)
    }

    pub fn print_memory_content(&self, start_address: u64, range: u64) {
        let memory_guard = self.memory.memory.read().unwrap();
        for addr in start_address..=start_address + range {
            if let Some(mem_val) = memory_guard.get(&addr) {
                log!(self.logger.clone(), "Address 0x{:x}: {:?}", addr, mem_val);
            } else {
                log!(self.logger.clone(), "Address 0x{:x}: Uninitialized", addr);
            }
        }
    }

    // Function only used in tests to avoid the loading of all memory section and CPU registers
    pub fn default_for_tests(ctx: &'a Context, logger: Logger) -> Result<Self, Box<dyn std::error::Error>> {
        // Initialize CPU state in a shared and thread-safe manner
        let cpu_state = Arc::new(Mutex::new(CpuState::new(ctx)));
        let memory_size: u64 = 0x100000; // 1GB memory size because dumps are 730 MB
        let memory = MemoryX86_64::new(&ctx, memory_size)?;
        Ok(State {
            concolic_vars: BTreeMap::new(),
            ctx,
            memory,
            cpu_state,
            vfs: VirtualFileSystem::new(),
            fd_paths: BTreeMap::new(),
            fd_counter: 0,
            logger,
            signal_mask: 0,  // Initialize with no signals blocked
            futex_manager: FutexManager::new(),
            altstack: StackT::default(),
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

    pub fn next_fd_id(&mut self) -> u64 {
        self.fd_counter += 1;
        self.fd_counter
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
    pub fn create_or_update_concolic_variable_int(
        &mut self,
        var_name: &str,
        concrete_value: u64,
        symbolic_var: SymbolicVar<'a>,
    ) -> &ConcolicVar<'a> {
        // Create a new ConcolicVar with the provided symbolic variable
        let new_var = ConcolicVar {
            concrete: ConcreteVar::Int(concrete_value),
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


