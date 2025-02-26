use std::fmt;
use z3::{ast::{Ast, Bool, Float, BV}, Context};

use crate::state::memory_x86_64::MemoryValue;

use super::{concrete_var::VarError, ConcreteVar, SymbolicVar};

#[derive(Clone, Debug)]
pub struct ConcolicVar<'ctx> {
    pub concrete: ConcreteVar,
    pub symbolic: SymbolicVar<'ctx>,
    pub ctx: &'ctx Context,
}

impl<'ctx> ConcolicVar<'ctx> {
    // Function to create a new ConcolicVar with a symbolic integer
    pub fn new_concrete_and_symbolic_int(concrete: u64, symbolic: BV<'ctx>, ctx: &'ctx Context, size: u32) -> Self {
        let var = ConcolicVar {
            concrete: ConcreteVar::Int(concrete),
            symbolic: SymbolicVar::Int(symbolic),
            ctx,
        };
        var
    }

    pub fn new_concrete_and_symbolic_large_int(concrete: Vec<u64>, symbolic: Vec<BV<'ctx>>, ctx: &'ctx Context) -> Self {
        let var = ConcolicVar {
            concrete: ConcreteVar::LargeInt(concrete),
            symbolic: SymbolicVar::LargeInt(symbolic),
            ctx,
        };
        var
    }

    // Function to create a new ConcolicVar with a symbolic double-precision float
    pub fn new_concrete_and_symbolic_float(concrete: f64, symbolic: Float<'ctx>, ctx: &'ctx Context, size: u32) -> Self {
        let var = ConcolicVar {
            concrete: ConcreteVar::Float(concrete),
            symbolic: SymbolicVar::Float(symbolic),
            ctx,
        };
        //var.resize_float(size);
        var
    }

    // Function to create a new ConcolicVar with a symbolic boolean
    pub fn new_concrete_and_symbolic_bool(concrete: bool, symbolic: Bool<'ctx>, ctx: &'ctx Context, _size: u32) -> Self {
        let var = ConcolicVar {
            concrete: ConcreteVar::Bool(concrete),
            symbolic: SymbolicVar::Bool(symbolic),
            ctx,
        };
        var
    }

    pub fn new_from_memory_value(value: &MemoryValue<'ctx>) -> Self {
        ConcolicVar {
            concrete: ConcreteVar::Int(value.concrete),
            symbolic: SymbolicVar::Int(value.symbolic.clone()),
            ctx: value.symbolic.get_ctx(),
        }
    } 

    // Method to retrieve the concrete u64 value
    pub fn get_concrete_value(&self) -> Result<u64, String> {
        match self.concrete {
            ConcreteVar::Int(value) => Ok(value),
            ConcreteVar::Float(value) => Ok(value as u64),  // Simplistic conversion
            ConcreteVar::Str(ref s) => u64::from_str_radix(s.trim_start_matches("0x"), 16)
                .map_err(|_| format!("Failed to parse '{}' as a hexadecimal number", s)),
            ConcreteVar::Bool(value) => Ok(value as u64),
            ConcreteVar::LargeInt(ref values) => Ok(values[0]), // Return the lower 64 bits
        }
    }      

    pub fn update_concrete_int(&mut self, new_value: u64) {
        self.concrete = ConcreteVar::Int(new_value);
    }

    pub fn update_concrete_float(&mut self, new_value: f64) {
        self.concrete = ConcreteVar::Float(new_value);
    }

    pub fn update_symbolic_int(&mut self, new_expr: BV<'ctx>) {
        if let SymbolicVar::Int(ref mut sym) = self.symbolic {
            *sym = new_expr;
        } else {
            panic!("Attempted to update symbolic int value on a non-int ConcolicVar");
        }
    }

    pub fn update_symbolic_float(&mut self, new_expr: Float<'ctx>) {
        if let SymbolicVar::Float(ref mut sym) = self.symbolic {
            *sym = new_expr;
        } else {
            panic!("Attempted to update symbolic float value on a non-float ConcolicVar");
        }
    }

    // Convert a concolic variable to a MemoryValue
    pub fn to_memory_value_u64(&self) -> MemoryValue<'ctx> {
        let concrete = self.get_concrete_value().unwrap();
        let symbolic = self.symbolic.to_bv(self.ctx);
        MemoryValue::new(concrete, symbolic, 64)
    }

    pub fn get_context_id(&self) -> String {
        format!("{:p}", self.ctx)
    }

    pub fn get_concrete_value_signed(&self, bit_size: u32) -> Result<i64, VarError> {
        self.concrete.get_concrete_value_signed(bit_size)
    }

    pub fn get_size_bits(&self) -> u32 {
        64 // Default to 64-bit for now, modify if dynamic size is required
    }

}


impl<'ctx> fmt::Display for ConcolicVar<'ctx> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Concrete: {:x}, Symbolic: {:?}", self.concrete, self.symbolic)
    }
}
