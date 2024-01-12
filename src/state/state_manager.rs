use std::collections::HashMap;
use crate::concolic_var::ConcolicVar;
use parser::parser::Varnode;
use z3::Context;
use std::fmt;

use super::MemoryX86_64;

#[derive(Debug)]
pub struct State<'a> {
    pub concolic_vars: HashMap<String, ConcolicVar<'a>>,
    ctx: &'a Context,
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
    pub fn create_concolic_var(&mut self, var_name: &str, concrete_value: u32, bitvector_size: u32) -> &ConcolicVar<'a> {
        let new_var = ConcolicVar::new(concrete_value, var_name, self.ctx, bitvector_size);
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
    pub fn get_concrete_var(&self, varnode: &Varnode) -> Result<u32, String> {
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
        let mut var1 = self.create_concolic_var(var1_name, 0, bitvector_size).clone();
        let var2 = self.create_concolic_var(var2_name, 0, bitvector_size).clone();

        var1.add(&var2, self.ctx);

        // Update the state with the result and the carry flag
        self.set_var(result_var_name, var1);
    }

    // calculate if a carry occurred during addition
    pub fn calculate_carry(&self, var1: &ConcolicVar<'a>, var2: &ConcolicVar<'a>, bitvector_size: u32) -> bool {
        // Prevent shifting more than 63 bits in a u64 to avoid overflow
        if bitvector_size >= 64 {
            return false;
        }

        let max_value = (1u64 << bitvector_size) - 1;
        let var1_value = var1.concrete as u64;
        let var2_value = var2.concrete as u64;

        // Using checked_add to handle overflow
        match var1_value.checked_add(var2_value) {
            Some(sum) => sum > max_value,
            None => true, // Overflow occurred
        }
    }

    // In both executor.rs and state_manager.rs
    pub fn calculate_signed_carry(&self, var1: &ConcolicVar<'a>, var2: &ConcolicVar<'a>) -> bool {
        let var1_value = var1.concrete as i64; // Cast to a larger type to detect overflow
        let var2_value = var2.concrete as i64;

        // Using wrapping_add for signed addition
        let result_value = var1_value.wrapping_add(var2_value);

        let sign_var1 = var1_value.signum();
        let sign_var2 = var2_value.signum();
        let sign_result = result_value.signum();

        // Check for overflow: if signs of operands are the same and the sign of the result is different
        sign_var1 == sign_var2 && sign_var1 != sign_result
    }


    // Bitwise AND operation on concolic variables
    pub fn concolic_and(&mut self, var1_name: &str, var2_name: &str, result_var_name: &str, bitvector_size: u32) {
        let mut var1 = self.create_concolic_var(var1_name, 0, bitvector_size).clone();
        let var2 = self.create_concolic_var(var2_name, 0, bitvector_size);

        var1.and(&var2);

        self.set_var(result_var_name, var1);
    }

    // Evaluate a conditional statement based on a concolic variable
    pub fn concolic_conditional(&mut self, var_name: &str, true_branch: impl FnOnce(&mut Self), false_branch: impl FnOnce(&mut Self)) {
        let var = self.create_concolic_var(var_name, 0, 1); // Assuming a 1-bit variable for condition

        if var.concrete != 0 {
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