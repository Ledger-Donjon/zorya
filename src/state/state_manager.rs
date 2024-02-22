use std::collections::HashMap;
use crate::{concolic::ConcreteVar, concolic_var::ConcolicVar};
use parser::parser::Varnode;
use z3::Context;
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

use super::{memory_x86_64::{MemoryX86_64, MemoryError}, CpuState};

#[derive(Debug)]
pub struct State<'a> {
    pub concolic_vars: HashMap<String, ConcolicVar<'a>>,
    pub cpu_state: CpuState,
    pub ctx: &'a Context,
    pub memory: MemoryX86_64<'a>,
}

impl<'a> State<'a> {
    pub fn new(ctx: &'a Context, binary_path: &Path) -> io::Result<Self> {
        let cpu_state = CpuState::new();
        let memory_size: u64 = 0x1000000; // modify?

        // Initialize specific address
        Self::initialize_specific_address(&mut memory)?;
	
	 // Initialize CPU registers
        Self::initialize_cpu_registers(&mut cpu_state);

        // Initialize stack and other memory regions as needed
        let mut memory = Self::initialize_memory(ctx);

        Ok(State {
            concolic_vars: HashMap::new(),
            cpu_state,
            ctx,
            memory,
        })
    }

    fn initialize_cpu_registers(cpu_state: &mut CpuState) {
        // Example registers based on your GDB output
        cpu_state.set_register_value("RSP", 0x7fffffffdd80);
        cpu_state.set_register_value("RIP", 0x45f5c0);
        // Set other registers as observed. Here they are all 0, but you can customize this part.
        for reg in ["RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"].iter() {
            cpu_state.set_register_value(reg, 0x1); // not 0x0
        }
    }

    fn initialize_memory(ctx: &'a Context, memory_size: u64) -> MemoryX86_64<'a> {
        let mut memory = MemoryX86_64::new(ctx, memory_size);
        // Initialize stack based on GDB's `x/10gx $rsp`
        // Assuming you have a method to write quad words, as simplified above
        let stack_start: u64 = 0x7fffffffdd80;
        let stack_values = [
            0x0000000000000001, 0x00007fffffffe12e,
            0x0000000000000000, 0x00007fffffffe189,
            0x00007fffffffe199, 0x00007fffffffe1ef,
            0x00007fffffffe202, 0x00007fffffffe216,
            0x00007fffffffe243, 0x00007fffffffe264,
        ];

        for (i, &value) in stack_values.iter().enumerate() {
            memory.write_quad(stack_start + (i as u64 * 8), value);
        }

        memory
    }

    pub fn initialize_specific_address(memory: &mut MemoryX86_64) -> io::Result<()> {
        // Example address and data
        let address = 0x55FABFC43F50;
        let data = [0x01]; // modify?
    
        // Write the data to the specified address
        memory.write_memory(address, &data)
              .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
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
        let var_name = format!("{:?}", varnode.var);
        match self.concolic_vars.get(&var_name) {
            Some(concolic_var) => Ok(concolic_var.concrete.clone()),
            None => Err(format!("Variable {} not found in concolic_vars", var_name)),
        }
    }

    // Sets a boolean variable in the state, updating or creating a new concolic variable
    pub fn set_var(&mut self, var_name: &str, concolic_var: ConcolicVar<'a>) {
        self.concolic_vars.insert(var_name.to_string(), concolic_var);
    }


    // Reads memory using a register address
    pub fn read_memory_using_register(&mut self, register: u64, size: usize) -> Result<Vec<u8>, MemoryError> {
        if let Some(address) = self.cpu_state.get_register_value(register) {
            self.memory.read_memory(address, size)
        } else {
            Err(MemoryError::OutOfBounds(register, size)) 
        }
    }

    // Writes to memory using a register address
    // pub fn write_memory_using_register(&mut self, register: u64, bytes: &[u8]) -> Result<(), MemoryError> {
    //    if let Some(address) = self.cpu_state.get_register_value(register) {
    //        self.memory.write_memory(address, bytes)
    //    } else {
    //        Err(MemoryError::OutOfBounds(register, bytes))
    //    }
    //}

    // Arithmetic ADD operation on concolic variables with carry calculation for int
    pub fn concolic_add_int(&mut self, var1_name: &str, var2_name: &str, result_var_name: &str, bitvector_size: u32) {
        let var1 = self.get_concolic_var(var1_name).expect("Var1 not found").clone();
        let var2 = self.get_concolic_var(var2_name).expect("Var2 not found").clone();
    
        // Perform the addition operation using the concrete values of var1 and var2
        let result_concrete_value = var1.concrete.add(var2.concrete);
    
        // Extract the u64 value from ConcreteVar::Int
        if let ConcreteVar::Int(value) = result_concrete_value {
            // Create or update the result variable with the new concrete value
            let result_var = ConcolicVar::new_concrete_and_symbolic_int(value, result_var_name, self.ctx, bitvector_size);
            self.set_var(result_var_name, result_var);
        } else {
            panic!("Expected an integer result from concolic_add_int");
        }
    }
    
    // Arithmetic ADD operation on concolic variables with carry calculation for float
    pub fn concolic_add_float(&mut self, var1_name: &str, var2_name: &str, result_var_name: &str) {
        let var1 = self.concolic_vars.get(var1_name)
            .cloned()
            .unwrap_or_else(|| self.create_concolic_var_float(var1_name, 0.0).clone());
        let var2 = self.concolic_vars.get(var2_name)
            .cloned()
            .unwrap_or_else(|| self.create_concolic_var_float(var2_name, 0.0).clone());
    
        // Perform the addition operation using the concrete values of var1 and var2
        let result_concrete_value = var1.concrete.add(var2.concrete);
    
        // Extract the f64 value from ConcreteVar::Float
        if let ConcreteVar::Float(value) = result_concrete_value {
            // Create or update the result variable with the new concrete value
            let result_var = ConcolicVar::new_concrete_and_symbolic_float(value, result_var_name, self.ctx);
            self.set_var(result_var_name, result_var);
        } else {
            panic!("Expected a floating-point result from concolic_add_float");
        }
    }
    
    // Bitwise AND operation on concolic variables for int
    pub fn concolic_and_int(&mut self, var1_name: &str, var2_name: &str, result_var_name: &str, bitvector_size: u32) {
        let var1 = self.get_concolic_var(var1_name).expect("Var1 not found").clone();
        let var2 = self.get_concolic_var(var2_name).expect("Var2 not found").clone();
    
        // Perform the bitwise AND operation using the concrete values of var1 and var2
        let result_concrete_value = var1.concrete.and(var2.concrete);
    
        // Extract the u64 value from ConcreteVar::Int
        if let ConcreteVar::Int(value) = result_concrete_value {
            // Create or update the result variable with the new concrete value
            let result_var = ConcolicVar::new_concrete_and_symbolic_int(value, result_var_name, self.ctx, bitvector_size);
            self.set_var(result_var_name, result_var);
        } else {
            panic!("Expected an integer result from concolic_and_int");
        }
    }

    pub fn concolic_and_float(&mut self, _var1_name: &str, _var2_name: &str, _result_var_name: &str, _bitvector_size: u32) {
        // Bitwise AND is not applicable to floating-point values.
        panic!("Bitwise AND operation is not valid for floating-point values.");
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

        // CPU State
        writeln!(f, "  CPU State:")?;
        writeln!(f, "    GPR:")?;
        for (reg_name, reg_value) in &self.cpu_state.gpr {
            writeln!(f, "      {}: {}", reg_name, reg_value)?;
        }

        writeln!(f, "    Segment Registers:")?;
        for (reg_name, reg_value) in &self.cpu_state.segment_registers {
            writeln!(f, "      {}: {}", reg_name, reg_value)?;
        }

        writeln!(f, "    Control Registers:")?;
        for (reg_name, reg_value) in &self.cpu_state.control_registers {
            writeln!(f, "      {}: {}", reg_name, reg_value)?;
        }

        // Memory
        // writeln!(f, "  Memory:")?;
        //for (address, memory_value) in &self.memory.memory {
        //    writeln!(f, "    {:x}: {:?}", address, memory_value)?;
        //}

        Ok(())
    }
}



