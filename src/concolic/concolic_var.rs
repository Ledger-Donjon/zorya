use std::fmt;

use z3::{ast::{Ast, Float, BV}, Context, SatResult, Solver};

use crate::state::{cpu_state::CpuConcolicValue, memory_x86_64::MemoryConcolicValue};

use super::{ConcreteVar, SymbolicVar};

#[derive(Clone, Debug)]
pub struct ConcolicVar<'ctx> {
    pub concrete: ConcreteVar,
    pub symbolic: SymbolicVar<'ctx>,
    pub ctx: &'ctx Context,
}

impl<'ctx> ConcolicVar<'ctx> {

    // Function to create a new ConcolicVar with a symbolic integer
    pub fn new_concrete_and_symbolic_int(concrete: u64, symbolic_name: &str, ctx: &'ctx Context, sz: u32) -> Self {        
        let symbolic: BV<'ctx> = BV::new_const(ctx, symbolic_name, sz);
        
        let new_var = ConcolicVar { 
            concrete: ConcreteVar::Int(concrete),
            symbolic: SymbolicVar::Int(symbolic),
            ctx,
        };
        new_var
    }

    // Function to create a new ConcolicVar with a symbolic double-precision float
    pub fn new_concrete_and_symbolic_float(concrete: f64, symbolic_name: &str, ctx: &'ctx Context) -> Self {        
        let symbolic: Float<'ctx> = Float::new_const_double(ctx, symbolic_name);
        
        let new_var = ConcolicVar {
            concrete: ConcreteVar::Float(concrete),
            symbolic: SymbolicVar::Float(symbolic),
            ctx,
        };
        new_var
    }

    // Add operation on two concolic variables 
    pub fn concolic_add(self, other: Self) -> Result<Self, &'static str> {
        let new_concrete = self.concrete.add(&other.concrete); 
        let new_symbolic = self.symbolic.add(&other.symbolic)?;
        Ok(ConcolicVar {
            concrete: new_concrete,
            symbolic: new_symbolic,
            ctx: self.ctx,
        })
    }

    // Function to perform a safe unsigned addition with overflow detection
    pub fn carrying_add<'a>(&self, other: &'a ConcolicVar<'ctx>, carry: bool) -> Result<(Self, bool), &'static str> {
        let (result, overflow) = self.concrete.carrying_add(&other.concrete, carry);
        let symbolic_result = self.symbolic.add(&other.symbolic)?;
        Ok((ConcolicVar {
            concrete: result,
            symbolic: symbolic_result,
            ctx: self.ctx,
        }, overflow))
    }

    // Carrying add operation between a ConcolicVar and a CpuConcolicValue
    pub fn carrying_add_with_cpu<'a>(&self, other: &'a CpuConcolicValue<'ctx>, carry: bool) -> (CpuConcolicValue<'ctx>, bool) {
        let (result, overflow) = self.concrete.carrying_add(&other.concrete, carry);
        let symbolic_result = self.symbolic.add(&other.symbolic); 
        let result_var = CpuConcolicValue {
            concrete: result,
            symbolic: symbolic_result.unwrap(),
            ctx: self.ctx,
        };
        (result_var, overflow)
    }

    // Carrying add operation between a ConcolicVar and a MemoryConcolicValue
    pub fn carrying_add_with_mem<'a>(&self, other: &'a MemoryConcolicValue<'ctx>, carry: bool) -> (MemoryConcolicValue<'ctx>, bool) {
        let (result, overflow) = self.concrete.carrying_add(&other.concrete, carry);
        let symbolic_result = self.symbolic.add(&other.symbolic);  
        let result_var = MemoryConcolicValue {
            concrete: result,
            symbolic: symbolic_result.unwrap(),
            ctx: self.ctx,
        };
        (result_var, overflow)
    }

    // Method to perform signed addition and detect overflow
    pub fn signed_add(&self, other: &Self) -> Result<(Self, bool), &'static str> {
        let (result, overflow) = self.concrete.to_i64()?.overflowing_add(other.concrete.to_i64()?);
        let new_concrete = ConcreteVar::Int(result as u64);
        let new_symbolic = self.symbolic.add(&other.symbolic)?;
        Ok((ConcolicVar {
            concrete: new_concrete,
            symbolic: new_symbolic,
            ctx: self.ctx,
        }, overflow))
    }

    // Method to perform signed addition with CpuConcolicValue and detect overflow
    pub fn signed_add_with_cpu(&self, other: &CpuConcolicValue<'ctx>) -> Result<(CpuConcolicValue<'ctx>, bool), &'static str> {
        let (result, overflow) = self.concrete.to_i64()?.overflowing_add(other.concrete.to_i64()?);
        let new_concrete = ConcreteVar::Int(result as u64);
        let new_symbolic = self.symbolic.add(&other.symbolic)?;
        Ok((CpuConcolicValue {
            concrete: new_concrete,
            symbolic: new_symbolic,
            ctx: self.ctx,
        }, overflow))
    }

    // Method to perform signed addition with MemoryConcolicValue and detect overflow
    pub fn signed_add_with_mem(&self, other: &MemoryConcolicValue<'ctx>) -> Result<(MemoryConcolicValue<'ctx>, bool), &'static str> {
        let (result, overflow) = self.concrete.to_i64()?.overflowing_add(other.concrete.to_i64()?);
        let new_concrete = ConcreteVar::Int(result as u64);
        let new_symbolic = self.symbolic.add(&other.symbolic)?;
        Ok((MemoryConcolicValue {
            concrete: new_concrete,
            symbolic: new_symbolic,
            ctx: self.ctx,
        }, overflow))
    }

    // Function to perform a safe unsigned subtraction with overflow detection
    pub fn concolic_sub(self, other: Self, ctx: &'ctx Context) -> Result<Self, &'static str> {
        let (result, overflow) = self.concrete.to_u64().overflowing_sub(other.concrete.to_u64());
        if overflow {
            Err("Overflow or underflow occurred during subtraction")
        } else {
            let new_symbolic = self.symbolic.sub(&other.symbolic, ctx)?;
            Ok(ConcolicVar {
                concrete: ConcreteVar::Int(result),
                symbolic: new_symbolic,
                ctx,
            })
        }
    }

    // Function to perform a safe unsigned subtraction with overflow detection
    pub fn concolic_sub_with_mem(self, other: MemoryConcolicValue<'ctx>, ctx: &'ctx Context) -> Result<Self, &'static str> {
        let (result, overflow) = self.concrete.to_u64().overflowing_sub(other.concrete.to_u64());
        if overflow {
            Err("Overflow or underflow occurred during subtraction")
        } else {
            let new_symbolic = self.symbolic.sub(&other.symbolic, ctx)?;
            Ok(ConcolicVar {
                concrete: ConcreteVar::Int(result),
                symbolic: new_symbolic,
                ctx,
            })
        }
    }

    // Function to perform a safe unsigned subtraction with overflow detection
    pub fn concolic_sub_with_cpu(self, other: CpuConcolicValue<'ctx>, ctx: &'ctx Context) -> Result<Self, &'static str> {
        let (result, overflow) = self.concrete.to_u64().overflowing_sub(other.concrete.to_u64());
        if overflow {
            Err("Overflow or underflow occurred during subtraction")
        } else {
            let new_symbolic = self.symbolic.sub(&other.symbolic, ctx)?;
            Ok(ConcolicVar {
                concrete: ConcreteVar::Int(result),
                symbolic: new_symbolic,
                ctx,
            })
        }
    }

    // And operation on two concolic variables
    pub fn concolic_and(self, ctx: &'ctx Context, other: Self) -> Result<Self, &'static str> {
        println!("Performing concolic AND operation between two ConcolicVars");
        println!("Current context: {:?}", ctx);
        let new_concrete = self.concrete.and(other.concrete);
        println!("New concrete value: {:?}", new_concrete);

        // Ensure symbolic variables are created correctly
        let new_symbolic = self.symbolic.and(&other.symbolic, ctx)?;
        match &new_symbolic {
            SymbolicVar::Int(bv) => {
                println!("New symbolic value (Int): {:?}", bv);
                assert!(!bv.get_z3_ast().is_null(), "New symbolic value (Int) is null");
            },
            SymbolicVar::Float(fv) => {
                println!("New symbolic value (Float): {:?}", fv);
                assert!(!fv.get_z3_ast().is_null(), "New symbolic value (Float) is null");
            }
        }
        println!("New symbolic value created successfully");

        Ok(ConcolicVar {
            concrete: new_concrete,
            symbolic: new_symbolic,
            ctx,
        })
    }
    
    // Function to perform a safe signed subtraction with overflow detection
    pub fn concolic_sborrow(self, other: Self, ctx: &'ctx Context) -> Result<bool, &'static str> {
        match self.concrete.to_i64()?.checked_sub(other.concrete.to_i64()?) {
            Some(_) => {
                let (_, overflow) = self.symbolic.sub_with_overflow_check(&other.symbolic, ctx)?;
                Ok(overflow)
            },
            None => Err("Overflow occurred"),
        }
    } 

    pub fn popcount(&self) -> BV<'ctx> {
        self.symbolic.popcount()
    }

    // Or operation on two concolic variables
    pub fn concolic_or(self, ctx: &'ctx Context, other: Self) -> Result<Self, &'static str> {
        let new_concrete = self.concrete.or(other.concrete);
        let new_symbolic = self.symbolic.or(&other.symbolic, ctx)?;
        match &new_symbolic {
            SymbolicVar::Int(bv) => {
                println!("New symbolic value (Int): {:?}", bv);
                assert!(!bv.get_z3_ast().is_null(), "New symbolic value (Int) is null");
            },
            SymbolicVar::Float(fv) => {
                println!("New symbolic value (Float): {:?}", fv);
                assert!(!fv.get_z3_ast().is_null(), "New symbolic value (Float) is null");
            }
        }
        Ok(ConcolicVar {
            concrete: new_concrete,
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
        }
    }
}

impl<'ctx> fmt::Display for ConcolicVar<'ctx> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Concrete: Int(0x{:x}), Symbolic: {:?}", self.concrete, self.symbolic)
    }
}
