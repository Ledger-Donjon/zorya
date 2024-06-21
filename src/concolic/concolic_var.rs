use std::fmt;
use z3::{ast::{Ast, Bool, Float, BV}, Context, SatResult, Solver};

use super::{ConcreteVar, SymbolicVar};

#[derive(Clone, Debug)]
pub struct ConcolicVar<'ctx> {
    pub concrete: ConcreteVar,
    pub symbolic: SymbolicVar<'ctx>,
    pub ctx: &'ctx Context,
}

impl<'ctx> ConcolicVar<'ctx> {
    // Function to create a new ConcolicVar with a symbolic integer
    pub fn new_concrete_and_symbolic_int(concrete: u64, symbolic: BV<'ctx>, ctx: &'ctx Context, _sz: u32) -> Self {        
            
        let new_var = ConcolicVar { 
            concrete: ConcreteVar::Int(concrete),
            symbolic: SymbolicVar::Int(symbolic),
            ctx,
        };
        new_var
    }

    // Function to create a new ConcolicVar with a symbolic double-precision float
    pub fn new_concrete_and_symbolic_float(concrete: f64, symbolic: Float<'ctx>, ctx: &'ctx Context) -> Self {        
        
        let new_var = ConcolicVar {
            concrete: ConcreteVar::Float(concrete),
            symbolic: SymbolicVar::Float(symbolic),
            ctx,
        };
        new_var
    }

    // Function to create a new ConcolicVar with a symbolic boolean
    pub fn new_concrete_and_symbolic_bool(concrete: bool, symbolic: Bool<'ctx>, ctx: &'ctx Context) -> Self {
        let new_var = ConcolicVar {
            concrete: ConcreteVar::Bool(concrete),
            symbolic: SymbolicVar::Bool(symbolic),
            ctx,
        };
        new_var
    }

    pub fn popcount(&self) -> BV<'ctx> {
        self.symbolic.popcount()
    }

    pub fn truncate(&self, offset: usize, new_size: u32, ctx: &'ctx Context) -> Result<Self, &'static str> {
        // Validate new_size and offset to prevent out of range shifts
        if new_size > 64 { // Assuming ConcreteVar is a u64 based on usage
            return Err("new_size exceeds the number of bits in ConcreteVar");
        }
        if offset >= 64 { // Prevent shifting beyond the bit width
            return Err("offset exceeds the number of bits in ConcreteVar");
        }
        if offset + new_size as usize > 64 {
            return Err("Combined offset and new_size exceed bit width of ConcreteVar");
        }
    
        // Adjust the symbolic extraction
        let high = (offset + new_size as usize - 1) as u32;
        let low = offset as u32;
        let new_symbolic = match self.symbolic.extract(high, low) {
            Ok(sym) => sym,
            Err(_) => return Err("Failed to extract symbolic part")
        };
    
        // Adjust the concrete value: mask the bits after shifting right
        let mask = if new_size < 64 {
            (1u64 << new_size) - 1
        } else {
            u64::MAX
        };
        let mask_concrete = ConcolicVar::new_concrete_and_symbolic_int(mask, new_symbolic.to_bv(), ctx, 64);
        let new_concrete = (self.concrete.clone().right_shift(offset)).bitand(&mask_concrete.concrete);
    
        Ok(ConcolicVar {
            concrete: ConcreteVar::Int(new_concrete.to_u64()),
            symbolic: new_symbolic,
            ctx,
        })
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

    pub fn get_context_id(&self) -> String {
        format!("{:p}", self.ctx)
    }

    pub fn can_address_be_zero(ctx: &'ctx Context, address_var: &ConcolicVar<'ctx>) -> bool {
        let solver = Solver::new(ctx);

        match &address_var.symbolic {
            SymbolicVar::Int(ref address_bv) => {
                // Ensure the Z3 boolean expression is created correctly
                let zero = BV::from_u64(ctx, 0, address_bv.get_size());
                // The `_eq` method on BV objects returns a Bool object, not a Rust bool
                let eq_zero = address_bv._eq(&zero);

                // Pass the Z3 Bool object to the solver's assert method
                solver.assert(&eq_zero);

                // Check if the constraint is satisfiable
                match solver.check() {
                    SatResult::Sat => true,  // The address can be zero
                    _ => false,  // The address cannot be zero
                }
            },
            SymbolicVar::Float(_) => {
                // For addresses, it's uncommon to use floating-point numbers.
                false
            },
            SymbolicVar::Bool(_) => {
                // For addresses, it's uncommon to use boolean values.
                false
            },
        }
    }
}


impl<'ctx> fmt::Display for ConcolicVar<'ctx> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Concrete: Int(0x{:x}), Symbolic: {:?}", self.concrete, self.symbolic)
    }
}
