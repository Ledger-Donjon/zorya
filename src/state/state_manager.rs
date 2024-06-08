use std::{collections::BTreeMap, fs::File, io::Read, path::{Path, PathBuf}, sync::{Arc, Mutex}};
use crate::{concolic::{ConcreteVar, SymbolicVar}, concolic_var::ConcolicVar, state::cpu_state::DisplayableCpuState};
use goblin::elf::Elf;
use parser::parser::{Inst, Varnode};
use z3::Context;
use std::fmt;

use super::{cpu_state::SharedCpuState, memory_x86_64::MemoryX86_64, state_initializer, virtual_file_system::FileDescriptor, CpuState, VirtualFileSystem};

#[derive(Clone, Debug)]
pub struct State<'a> {
    pub concolic_vars: BTreeMap<String, ConcolicVar<'a>>,
    pub ctx: &'a Context,
    pub memory: MemoryX86_64<'a>,
    pub cpu_state: SharedCpuState<'a>,
    pub vfs: VirtualFileSystem,
    pub file_descriptors: BTreeMap<u64, FileDescriptor>, // Maps syscall file descriptors to FileDescriptor objects.
    pub fd_paths: BTreeMap<u64, PathBuf>, // Maps syscall file descriptors to file paths.
    pub fd_counter: u64, // Counter to generate unique file descriptor IDs.
}

impl<'a> State<'a> {
    pub fn new(ctx: &'a Context) -> Result<Self, Box<dyn std::error::Error>> {
        println!("Initializing State...\n");

        // Initialize CPU state in a shared and thread-safe manner
        let cpu_state = Arc::new(Mutex::new(CpuState::new(ctx)));
        
        println!("Initializing mock CPU state...\n");
        let _ = state_initializer::get_mock(cpu_state.clone());

        // Print the CPU registers after initialization
        let displayable_cpu_state = DisplayableCpuState(cpu_state.clone());
        println!("Current CPU State: {}", displayable_cpu_state);

        let memory_size: u64 = 0x10000000; // 10GB memory size because dumps are 730 MB
        println!("Initializing memory...\n");
        let memory = MemoryX86_64::new(&ctx, memory_size)?;
        let _ = memory.load_all_dumps();

        // Virtual file system initialization
        println!("Initializing virtual file system...\n");
        let vfs = VirtualFileSystem::new();

        Ok(State {
            concolic_vars: BTreeMap::new(),
            ctx,
            memory,
            cpu_state,
            file_descriptors: BTreeMap::new(),
            fd_paths: BTreeMap::new(),
            fd_counter: 0,
            vfs,
        })
    }

    // Function only used in tests to avoid the loading of all memory section and CPU registers
    pub fn default_for_tests(ctx: &'a Context) -> Result<Self, Box<dyn std::error::Error>> {
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
            file_descriptors: BTreeMap::new(),
            fd_paths: BTreeMap::new(),
            fd_counter: 0,
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

    // Method to create a concolic variable with int
    pub fn create_concolic_var_int(&mut self, var_name: &str, concrete_value: u64, bitvector_size: u32) -> &ConcolicVar<'a> {
        // According to IEEE 754 standards and assumes all floating-point variables are single precision
        let new_var = ConcolicVar::new_concrete_and_symbolic_int(concrete_value, var_name, self.ctx, bitvector_size);
        // ensures that a new concolic variable is only created if one with the same name does not already exist
        self.concolic_vars.entry(var_name.to_string()).or_insert(new_var)
    }

    // used in handle_load - to be uniformized later
    pub fn create_or_update_concolic_var_int(&mut self, var_name: &str, concrete_value: u64, bitvector_size: u32) {
        // According to IEEE 754 standards and assumes all floating-point variables are single precision
        let new_var = ConcolicVar::new_concrete_and_symbolic_int(concrete_value, var_name, self.ctx, bitvector_size);
        // Update an existing variable or insert a new one if it doesn't exist
        self.concolic_vars.insert(var_name.to_string(), new_var);
    }

    // Method to create a concolic variable with float
    pub fn create_concolic_var_float(&mut self, var_name: &str, concrete_value: f64) -> &ConcolicVar<'a> {
        // According to IEEE 754 standards and assumes all floating-point variables are single precision
        let new_var = ConcolicVar::new_concrete_and_symbolic_float(concrete_value, var_name, self.ctx);
        // ensures that a new concolic variable is only created if one with the same name does not already exist
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

    /// Retrieves a reference to a FileDescriptor by its ID.
    pub fn get_file_descriptor(&self, fd_id: u64) -> Result<&FileDescriptor, String> {
        self.file_descriptors.get(&fd_id)
            .ok_or_else(|| "File descriptor not found".to_string())
    }

    /// Retrieves a mutable reference to a FileDescriptor by its ID.
    /// This is necessary for operations that modify the FileDescriptor, like write.
    pub fn get_file_descriptor_mut(&mut self, fd_id: u64) -> Result<&mut FileDescriptor, String> {
        self.file_descriptors.get_mut(&fd_id)
            .ok_or_else(|| "File descriptor not found".to_string())
    }

    pub fn check_nil_deref(&mut self, address: u64, current_address: u64, instruction: &Inst) -> Result<(), String> {
    	// Special case for entry point where accessing 0x0 might be expected
    	//if current_address == Self::ENTRY_POINT_ADDRESS && address == 0x0 {
        //	println!("Special case at entry point, accessing 0x0 is not considered a nil dereference.");
        //	return Ok(());
    	//}

    	// If RAX is 0x0 -> potential nil dereference
    	// if let Some(rax_value) = self.cpu_state.gpr.get("RAX") {
        //     if *rax_value == 0x0 {
        //         return Err(format!("Nil dereference detected: RAX is 0x0 at address 0x{:x} with instruction {:?}", current_address, instruction));
        //     }
        // } else {
        //     return Err("RAX register value not found".to_string());
        // }

        // Ensure the accessed address is not 0x0 ?
    	 if address == 0x0 {
        	return Err(format!("Nil dereference detected: Attempted to access address 0x0 at address 0x{:x} with instruction {:?}", current_address, instruction));
    	}

    	Ok(())
     }
}

impl<'a> fmt::Display for State<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "State after instruction:")?;

        // Concolic Variables
        writeln!(f, "  Concolic Variables:")?;
        for (var_name, concolic_var) in &self.concolic_vars {
            writeln!(f, "    {}: {}", var_name, concolic_var)?;
        }

        // Memory
        // writeln!(f, "  Memory:")?;
        //for (address, memory_value) in &self.memory.memory {
        //    writeln!(f, "    {:x}: {:?}", address, memory_value)?;
        //}

        Ok(())
    }
}



