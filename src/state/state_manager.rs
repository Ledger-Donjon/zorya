use std::collections::HashMap;
use crate::concolic_var::{ConcolicVar, ConcreteValue};
use parser::parser::Varnode;
use z3::Context;
use std::fmt;

use super::MemoryX86_64;

#[derive(Debug)]
pub struct State<'a> {
    pub concolic_vars: HashMap<String, ConcolicVar<'a>>,
    pub register_values: HashMap<u64, u64>,
    pub ctx: &'a Context,
    pub memory: MemoryX86_64<'a>,
}

impl<'a> State<'a> {
    pub fn new(ctx: &'a Context) -> Self {
        let mut register_values = HashMap::new();
        
        // Initialize general-purpose registers to 0
        // RAX (0), RCX (1), RDX (2), RBX (3), RSP (4), RBP (5), RSI (6), RDI (7)
        // R8 (8) through R15 (15)
        for reg_num in 0..=15 {
            register_values.insert(reg_num, 0);
        }
        
        // Example stack initialization - adjust based on your memory model
        let initial_rsp = 0x7FFFFFFF; // Top of the stack in your simulated environment
        register_values.insert(4, initial_rsp); // RSP

        // If modeling flags, initialize RFLAGS (may require specific flags set)
        // register_values.insert(flags_reg_num, initial_flags_value);

        // If starting execution at a specific point, set RIP
        // register_values.insert(rip_reg_num, start_instruction_address);

        State {
            concolic_vars: HashMap::new(),
            register_values: HashMap::new(),
            ctx,
            memory: MemoryX86_64::new(ctx),
        }
    }

    // Method to create a concolic variable with int
    pub fn create_concolic_var_int(&mut self, var_name: &str, concrete_value: u64, bitvector_size: u32) -> &ConcolicVar<'a> {
        // According to IEEE 754 standards and assumes all floating-point variables are single precision
        let new_var = ConcolicVar::new_concrete_and_symbolic_int(concrete_value, var_name, self.ctx, bitvector_size);
        // ensures that a new concolic variable is only created if one with the same name does not already exist
        self.concolic_vars.entry(var_name.to_string()).or_insert(new_var)
    }

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
    pub fn get_concrete_var(&self, varnode: &Varnode) -> Result<ConcreteValue, String> {
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

    /// Gets the current concrete value of a register.
    // reg_num: The register number/identifier.
    // Returns: The concrete value of the register, if it exists.
    pub fn get_register_value(&self, reg_num: u64) -> Option<u64> {
        match reg_num {
            0 => Some(0), // Assuming register 0 should always return 0
            _ => self.register_values.get(&reg_num).cloned(),
        }
    }

    /// Sets or updates the concrete value of a register.
    // reg_num: The register number/identifier.
    // value: The concrete value to set for the register.
    pub fn set_register_value(&mut self, reg_num: u64, value: u64) {
        self.register_values.insert(reg_num, value);
    }

    // Arithmetic ADD operation on concolic variables with carry calculation for int
    pub fn concolic_add_int(&mut self, var1_name: &str, var2_name: &str, result_var_name: &str, bitvector_size: u32) {
        let var1 = self.get_concolic_var(var1_name).expect("Var1 not found").clone();
        let var2 = self.get_concolic_var(var2_name).expect("Var2 not found").clone();
    
        // Perform the addition operation using the concrete values of var1 and var2
        let result_concrete_value = var1.concrete.add(var2.concrete);
    
        // Extract the u64 value from ConcreteValue::Int
        if let ConcreteValue::Int(value) = result_concrete_value {
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
    
        // Extract the f64 value from ConcreteValue::Float
        if let ConcreteValue::Float(value) = result_concrete_value {
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
    
        // Extract the u64 value from ConcreteValue::Int
        if let ConcreteValue::Int(value) = result_concrete_value {
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
        writeln!(f, "State {{")?;
        writeln!(f, "  Concolic Variables:")?;
        for (var_name, concolic_var) in &self.concolic_vars {
            writeln!(f, "    {}: {:?}", var_name, concolic_var)?;
        }
        write!(f, "}}")
    }
}
