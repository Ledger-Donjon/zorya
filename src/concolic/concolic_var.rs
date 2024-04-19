use z3::{ast::{Ast, Float, BV}, Context, SatResult, Solver};

use super::{ConcreteVar, SymbolicVar};

#[derive(Clone, Debug)]
pub struct ConcolicVar<'a> {
    pub concrete: ConcreteVar, 
    pub symbolic: SymbolicVar<'a>,
}

impl<'a> ConcolicVar<'a> {

    // Function to create a new ConcolicVar with a symbolic integer
    pub fn new_concrete_and_symbolic_int(concrete: u64, symbolic_name: &str, ctx: &'a Context, sz: u32) -> Self {
        let symbolic: BV<'a> = BV::new_const(ctx, symbolic_name, sz);
        ConcolicVar { 
            concrete: ConcreteVar::Int(concrete),
            symbolic: SymbolicVar::Int(symbolic),
        }
    }

    // Function to create a new ConcolicVar with a symbolic f64 (double-precision float)
    pub fn new_concrete_and_symbolic_float(concrete: f64, symbolic_name: &str, ctx: &'a Context) -> Self {
        // Create a symbolic double-precision floating-point number
        let symbolic: Float<'a> = Float::new_const_double(ctx, symbolic_name);
        ConcolicVar {
            concrete: ConcreteVar::Float(concrete),
            symbolic: SymbolicVar::Float(symbolic),
        }
    }

    // Add operation on two concolic variables 
    pub fn concolic_add(self, other: Self, ctx: &'a Context) -> Result<Self, &'static str> {
        let new_concrete = self.concrete.add(other.concrete);
        let new_symbolic = self.symbolic.add(other.symbolic, ctx)?;
        Ok(ConcolicVar {
            concrete: new_concrete,
            symbolic: new_symbolic,
        })
    }

    // And operation on two concolic variables
    pub fn concolic_and(self, ctx: &'a Context, other: Self) -> Result<Self, &'static str> {
        let new_concrete = self.concrete.and(other.concrete);
        let new_symbolic = self.symbolic.and(other.symbolic, ctx)?;
        Ok(ConcolicVar {
            concrete: new_concrete,
            symbolic: new_symbolic,
        })
    }

    pub fn update_concrete_int(&mut self, new_value: u64) {
        self.concrete = ConcreteVar::Int(new_value);
    }

    pub fn update_concrete_float(&mut self, new_value: f64) {
        self.concrete = ConcreteVar::Float(new_value);
    }

    pub fn update_symbolic_int(&mut self, new_expr: BV<'a>) {
        if let SymbolicVar::Int(ref mut sym) = self.symbolic {
            *sym = new_expr;
        } else {
            panic!("Attempted to update symbolic int value on a non-int ConcolicVar");
        }
    }

    pub fn update_symbolic_float(&mut self, new_expr: Float<'a>) {
        if let SymbolicVar::Float(ref mut sym) = self.symbolic {
            *sym = new_expr;
        } else {
            panic!("Attempted to update symbolic float value on a non-float ConcolicVar");
        }
    }

    pub fn can_address_be_zero(ctx: &'a Context, address_var: &ConcolicVar<'a>) -> bool {
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
        }
    }
}

