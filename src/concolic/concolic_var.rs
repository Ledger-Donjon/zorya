use z3::{ast::{Ast, Float, BV}, Context, SatResult, Solver};

#[derive(Clone, Debug, PartialEq)]
pub enum SymbolicValue<'a> {
    Int(BV<'a>),
    Float(Float<'a>),
}

#[derive(Clone, Debug, PartialEq)]
pub enum ConcreteValue {
    Int(u64),
    Float(f64),
}

impl ConcreteValue {
    // Addition operation
    pub fn add(self, other: ConcreteValue) -> Self {
        match (self, other) {
            (ConcreteValue::Int(a), ConcreteValue::Int(b)) => ConcreteValue::Int(a + b),
            (ConcreteValue::Float(a), ConcreteValue::Float(b)) => ConcreteValue::Float(a + b),
            _ => panic!("Attempted to add incompatible ConcreteValues"),
        }
    }

    // Bitwise AND operation for integers
    pub fn and(self, other: ConcreteValue) -> Self {
        match (self, other) {
            (ConcreteValue::Int(a), ConcreteValue::Int(b)) => ConcreteValue::Int(a & b),
            _ => panic!("Bitwise AND operation is not defined for floats"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ConcolicVar<'a> {
    pub concrete: ConcreteValue, 
    pub symbolic: SymbolicValue<'a>,
}

impl<'a> ConcolicVar<'a> {

    // Function to create a new ConcolicVar with a symbolic integer
    pub fn new_concrete_and_symbolic_int(concrete: u64, symbolic_name: &str, ctx: &'a Context, sz: u32) -> Self {
        let concrete: u64 = concrete;
        let symbolic: BV<'a> = BV::new_const(ctx, symbolic_name, sz);
        ConcolicVar { 
            concrete: ConcreteValue::Int(concrete),
            symbolic: SymbolicValue::Int(symbolic),
        }
    }

    // Function to create a new ConcolicVar with a symbolic float
    pub fn new_concrete_and_symbolic_float(concrete: f64, symbolic_name: &str, ctx: &'a Context) -> Self {
        let concrete: f64 = concrete;
        // Assuming IEEE 754 single-precision float: 8 bits exponent, 23 bits significand
        let exponent_bits: u32 = 8;
        let significand_bits: u32 = 23;

        let symbolic: Float<'a> = Float::new_const(ctx, symbolic_name, exponent_bits, significand_bits);
        ConcolicVar {
            concrete: ConcreteValue::Float(concrete),
            symbolic: SymbolicValue::Float(symbolic),
        }
    }

    pub fn update_concrete_int(&mut self, new_value: u64) {
        self.concrete = ConcreteValue::Int(new_value);
    }

    pub fn update_concrete_float(&mut self, new_value: f64) {
        self.concrete = ConcreteValue::Float(new_value);
    }

    pub fn update_symbolic_int(&mut self, new_expr: BV<'a>) {
        if let SymbolicValue::Int(ref mut sym) = self.symbolic {
            *sym = new_expr;
        } else {
            panic!("Attempted to update symbolic int value on a non-int ConcolicVar");
        }
    }

    pub fn update_symbolic_float(&mut self, new_expr: Float<'a>) {
        if let SymbolicValue::Float(ref mut sym) = self.symbolic {
            *sym = new_expr;
        } else {
            panic!("Attempted to update symbolic float value on a non-float ConcolicVar");
        }
    }

    pub fn can_address_be_zero(ctx: &'a Context, address_var: &ConcolicVar<'a>) -> bool {
        let solver = Solver::new(ctx);

        match &address_var.symbolic {
            SymbolicValue::Int(ref address_bv) => {
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
            SymbolicValue::Float(_) => {
                // For addresses, it's uncommon to use floating-point numbers.
                false
            },
        }
    }
}

