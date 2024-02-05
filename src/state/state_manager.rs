use std::collections::HashMap;
use crate::concolic_var::ConcolicVar;
use parser::parser::Varnode;
use z3::Context;
use std::fmt;

use super::MemoryX86_64;

#[derive(Debug)]
pub struct State<'a> {
    pub concolic_vars: HashMap<String, ConcolicVar<'a>>,
    pub ctx: &'a Context,
    pub memory: MemoryX86_64,
}

impl<'a> State<'a> {
    pub fn new(ctx: &'a Context) -> Self {
        State {
            concolic_vars: HashMap::new(),
            ctx,
            memory: MemoryX86_64::new(),
        }
    }

    // Method to create a concolic variable
    pub fn create_concolic_var(&mut self, var_name: &str, concrete_value: f64, bitvector_size: u32) -> &ConcolicVar<'a> {
        // According to IEEE 754 standards and assumes all floating-point variables are single precision
        let new_var = if bitvector_size == 32 {
            // Use the new method for creating a symbolic float variable
            ConcolicVar::new_concrete_and_symbolic_float(concrete_value, var_name, self.ctx)
        } else {
            // Use the new method for creating a symbolic int variable
            ConcolicVar::new_concrete_and_symbolic_int(concrete_value, var_name, self.ctx, bitvector_size)
        };
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
    pub fn get_concrete_var(&self, varnode: &Varnode) -> Result<f64, String> {
        let var_name = format!("{:?}", varnode.var);
        match self.concolic_vars.get(&var_name) {
            Some(concolic_var) => Ok(concolic_var.concrete),
            None => Err(format!("Variable {} not found in concolic_vars", var_name)),
        }
    }

    // Sets a boolean variable in the state, updating or creating a new concolic variable
    pub fn set_var(&mut self, var_name: &str, concolic_var: ConcolicVar<'a>) {
        self.concolic_vars.insert(var_name.to_string(), concolic_var);
    }

    // Arithmetic ADD operation on concolic variables with carry calculation
    pub fn concolic_add(&mut self, var1_name: &str, var2_name: &str, result_var_name: &str, bitvector_size: u32) {
        let mut var1 = self.create_concolic_var(var1_name, 0.0, bitvector_size).clone();
        let var2 = self.create_concolic_var(var2_name, 0.0, bitvector_size).clone();

        var1.update_concrete(var1.concrete + var2.concrete);

        // Update the state with the result
        self.set_var(result_var_name, var1);
    }

    // Bitwise AND operation on concolic variables
    pub fn concolic_and(&mut self, var1_name: &str, var2_name: &str, result_var_name: &str, bitvector_size: u32) {
        let mut var1 = self.create_concolic_var(var1_name, 0.0, bitvector_size).clone();
        let var2 = self.create_concolic_var(var2_name, 0.0, bitvector_size);

        var1.update_concrete(var1.concrete * var2.concrete); // Assuming AND operation on floats means multiplication

        self.set_var(result_var_name, var1);
    }

    // Evaluate a conditional statement based on a concolic variable
    pub fn concolic_conditional(&mut self, var_name: &str, true_branch: impl FnOnce(&mut Self), false_branch: impl FnOnce(&mut Self)) {
        let var = self.create_concolic_var(var_name, 0.0, 1); // Assuming a 1-bit variable for condition

        if var.concrete != 0.0 {
            true_branch(self);
        } else {
            false_branch(self);
        }
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
