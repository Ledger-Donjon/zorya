use std::{collections::HashMap, fs::File, io::{self, Read, Seek, SeekFrom}, path::{Path, PathBuf}};
use crate::{concolic::ConcreteVar, concolic_var::ConcolicVar};
use goblin::elf::Elf;
use parser::parser::{Inst, Varnode};
use z3::Context;
use std::fmt;

use super::{memory_x86_64::MemoryX86_64, state_mocker, virtual_file_system::FileDescriptor, VirtualFileSystem};

#[derive(Debug)]
pub struct State<'a> {
    pub concolic_vars: HashMap<String, ConcolicVar<'a>>,
    pub ctx: &'a Context,
    pub memory: MemoryX86_64<'a>,
    pub vfs: VirtualFileSystem,
    pub file_descriptors: HashMap<u64, FileDescriptor>, // Maps syscall file descriptors to FileDescriptor objects.
    pub fd_paths: HashMap<u64, PathBuf>, // Maps syscall file descriptors to file paths.
    pub fd_counter: u64, // Counter to generate unique file descriptor IDs.
}

impl<'a> State<'a> {
    pub fn new(ctx: &'a Context, binary_path: &str) -> io::Result<Self> {
        println!("Initializing State...");

        // Mock CPU state initialization
        println!("Initializing mock CPU state...");
        let _ = state_mocker::get_mock();

        // Virtual file system initialization
        println!("Initializing virtual file system...");
        let vfs = VirtualFileSystem::new();

        let memory_size: u64 = 0x1000000; // Example memory size
        println!("Initializing memory...");
        let mut memory = MemoryX86_64::new(ctx, memory_size);

        println!("Opening binary file: {}", binary_path);
        let mut file = File::open(binary_path)?;
        println!("Binary file opened successfully.");

        // Example LOAD section initialization
        println!("Initializing LOAD sections...");
        Self::initialize_load_section(&mut file, &mut memory, 0x000000, 0x0000000000400000, 0x058602)?; // First LOAD
        Self::initialize_load_section(&mut file, &mut memory, 0x082000, 0x0000000000459000, 0x066630)?; // Second LOAD
        Self::initialize_load_section(&mut file, &mut memory, 0x115000, 0x00000000004c0000, 0x0034e0)?; // Third LOAD
        println!("LOAD sections initialized successfully.");

        Ok(State {
            concolic_vars: HashMap::new(),
            ctx,
            memory,
            file_descriptors: HashMap::new(),
            fd_paths: HashMap::new(),
            fd_counter: 0,
            vfs,
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

    fn initialize_load_section(file: &mut File, memory: &mut MemoryX86_64, file_offset: u64, memory_address: u64, size: u64) -> io::Result<()> {
        let mut buffer = vec![0; size as usize];
        file.seek(SeekFrom::Start(file_offset))?;
        file.read_exact(&mut buffer)?;
        for (i, &byte) in buffer.iter().enumerate() {
            memory.write_memory(memory_address + i as u64, &vec![byte]).unwrap_or_else(|_| panic!("Failed to write memory at address 0x{:x}", memory_address + i as u64));
        }
        Ok(())
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
            writeln!(f, "    {}: {:?}", var_name, concolic_var)?;
        }

        // Memory
        // writeln!(f, "  Memory:")?;
        //for (address, memory_value) in &self.memory.memory {
        //    writeln!(f, "    {:x}: {:?}", address, memory_value)?;
        //}

        Ok(())
    }
}



