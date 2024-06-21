extern crate z3;
use z3::ast::{Ast, Bool, Float, BV};
use z3::Context;
use z3_sys::Z3_ast;

#[derive(Clone, Debug, PartialEq)]
pub enum SymbolicVar<'ctx> {
    Int(BV<'ctx>),
    Float(Float<'ctx>),
    Bool(Bool<'ctx>),
}

impl<'ctx> SymbolicVar<'ctx> {
    pub fn new_int(value: i32, ctx: &'ctx Context, size: u32) -> SymbolicVar<'ctx> {
        let bv = BV::from_i64(ctx, value as i64, size);
        SymbolicVar::Int(bv)
    }

    pub fn add(&self, other: &SymbolicVar<'ctx>) -> Result<SymbolicVar<'ctx>, &'static str> {
        match (self, other) {
            (SymbolicVar::Int(a), SymbolicVar::Int(b)) => {
                Ok(SymbolicVar::Int(a.bvadd(&b)))
            },
            (SymbolicVar::Float(a), SymbolicVar::Float(b)) => {
                // Use the `add_towards_zero` method for Floats
                Ok(SymbolicVar::Float(a.add_towards_zero(&b)))
            },
            _ => Err("Cannot add different types"),
        }
    }
    
    pub fn sub(&self, other: &SymbolicVar<'ctx>, _ctx: &'ctx Context) -> Result<SymbolicVar<'ctx>, &'static str> {
        match (self, other) {
            (SymbolicVar::Int(a), SymbolicVar::Int(b)) => {
                Ok(SymbolicVar::Int(a.bvsub(&b)))
            },
            (SymbolicVar::Float(a), SymbolicVar::Float(b)) => {
                Ok(SymbolicVar::Float(a.sub_towards_zero(&b)))
            },
            _ => Err("Cannot subtract different types"),
        }
    }

    pub fn signed_sub_overflow(&self, other: &SymbolicVar<'ctx>, ctx: &'ctx Context) -> Result<Bool<'ctx>, &'static str> {
        match (self, other) {
            (SymbolicVar::Int(a), SymbolicVar::Int(b)) => {
                let sub = a.bvsub(&b);
                let overflow = z3::ast::Bool::or(
                    ctx,
                    &[&a.bvsgt(&sub), &b.bvsgt(&sub)],
                );
                Ok(overflow)
            },
            _ => Err("signed_sub_overflow is only defined for integers"),
        }
    } 

    pub fn sub_with_overflow_check(&self, other: &Self, _ctx: &'ctx Context) -> Result<(Self, bool), &'static str> {
        match (self, other) {
            (SymbolicVar::Int(bv1), SymbolicVar::Int(bv2)) => {
                let result = bv1.bvsub(bv2);
                // Z3 BV method to check for overflow on subtraction
                let overflow = bv1.bvsub_no_overflow(bv2).as_bool().unwrap(); // Convert Bool to bool
                Ok((SymbolicVar::Int(result), overflow))
            },
            _ => Err("Unsupported types for subtraction with overflow check"),
        }
    }

    // Logical AND operation between two symbolic variables
    pub fn and(&self, other: &SymbolicVar<'ctx>, _ctx: &'ctx Context) -> Result<Self, &'static str> {
        match (self, other) {
            (SymbolicVar::Int(a), SymbolicVar::Int(b)) => {
                let new_symbolic = a.bvand(b);
                Ok(SymbolicVar::Int(new_symbolic))
            },
            _ => Err("AND operation is only supported for integers"),
        }
    }

    pub fn popcount(&self) -> BV<'ctx> {
        match self {
            SymbolicVar::Int(bv) => {
                let ctx = bv.get_ctx();
                let mut count = BV::from_u64(ctx, 0, bv.get_size());
                for i in 0..bv.get_size() {
                    let bit = bv.extract(i, i);
                    count = count.bvadd(&bit.zero_ext(bv.get_size() - 1));
                }
                count
            },
            SymbolicVar::Float(_) => panic!("Popcount is not defined for floating-point values"),
            SymbolicVar::Bool(_) => panic!("Popcount is not defined for boolean values"),
        }
    }

    // Logical OR operation between two symbolic variables
    pub fn or(&self, other: &SymbolicVar<'ctx>, _ctx: &'ctx Context) -> Result<Self, &'static str> {
        match (self, other) {
            (SymbolicVar::Int(a), SymbolicVar::Int(b)) => {
                let new_symbolic = a.bvor(b);
                Ok(SymbolicVar::Int(new_symbolic))
            },
            _ => Err("OR operation is only supported for integers"),
        }
    }

    // Additional method to negate a boolean bit vector
    pub fn bool_not(&self) -> Result<SymbolicVar<'ctx>, &'static str> {
        match self {
            SymbolicVar::Int(bv) => { // Ensure it's treated as a boolean
                Ok(SymbolicVar::Int(bv.bvnot())) // Negate the bit vector
            },
            SymbolicVar::Bool(b) => Ok(SymbolicVar::Bool(b.not())),
            _ => Err("bool_not is applicable only to 1-bit wide integer bit vectors"),
        }
    }

    // Method to extract a sub-bitvector from a symbolic integer variable
    pub fn extract(&self, high: u32, low: u32) -> Result<SymbolicVar<'ctx>, &'static str> {
        match self {
            SymbolicVar::Int(bv) => {
                let extracted_bv = bv.extract(high, low);
                Ok(SymbolicVar::Int(extracted_bv))
            },
            SymbolicVar::Float(_) => Err("Extract operation not supported on floating-point symbolic variables"),
            SymbolicVar::Bool(_) => Err("Extract operation not supported on boolean symbolic variables"),
        }
    }

    // Method to check if two symbolic variables are equal
    pub fn equal(&self, other: &SymbolicVar<'ctx>) -> bool {
        match (self, other) {
            (SymbolicVar::Int(a), SymbolicVar::Int(b)) => a.eq(&b),
            (SymbolicVar::Float(a), SymbolicVar::Float(b)) => a.eq(&b),
            _ => false,
        }
    }

    pub fn to_str(&self) -> String {
        match self {
            SymbolicVar::Int(value) => value.to_string(),
            SymbolicVar::Float(value) => value.to_string(),
            SymbolicVar::Bool(value) => value.to_string(),
        }
    }

    // Convert the symbolic variable to a bit vector
    pub fn to_bv(&self) -> BV<'ctx> {
        match self {
            SymbolicVar::Int(bv) => bv.clone(),
            SymbolicVar::Float(_) => panic!("Cannot convert a floating-point symbolic variable to a bit vector"),
            SymbolicVar::Bool(_) => panic!("Cannot convert a boolean symbolic variable to a bit vector"),
        }
    }

    // Convert the symbolic variable to a boolean
    pub fn to_bool(&self) -> Bool<'ctx> {
        match self {
            SymbolicVar::Bool(b) => b.clone(),
            SymbolicVar::Int(bv) => {
                // if the bit vector is equal to 0, return false, otherwise true
                if bv == &(BV::from_u64(bv.get_ctx(), 0, bv.get_size())) {
                    Bool::from_bool(bv.get_ctx(), false)
                } else {
                    Bool::from_bool(bv.get_ctx(), true)
                }
            }
            SymbolicVar::Float(_) => panic!("Cannot convert a floating-point symbolic variable to a boolean"),
        }
    }

    // Convert a constant to a symbolic value.
    pub fn from_u64(ctx: &'ctx Context, value: u64, size: u32) -> SymbolicVar<'ctx> {
        SymbolicVar::Int(BV::from_u64(ctx, value, size))
    }

    // Method to get the underlying Z3 AST
    pub fn get_z3_ast(&self) -> Z3_ast {
        match self {
            SymbolicVar::Int(bv) => bv.get_z3_ast(),
            SymbolicVar::Float(fv) => fv.get_z3_ast(),
            SymbolicVar::Bool(b) => b.get_z3_ast(),
        }
    }

    // Method to check if the underlying Z3 AST is null
    pub fn is_null(&self) -> bool {
        let ast = self.get_z3_ast();
        ast.is_null() 
    }

    pub fn get_ctx(&self) -> &'ctx Context {
        match self {
            SymbolicVar::Int(bv) => bv.get_ctx(),
            SymbolicVar::Float(fv) => fv.get_ctx(),
            SymbolicVar::Bool(b) => b.get_ctx(),
        }
    }

    pub fn get_size(&self) -> u32 {
        match self {
            SymbolicVar::Int(bv) => bv.get_size(),
            SymbolicVar::Float(_) => 32, // simplicity
            SymbolicVar::Bool(_) => 1,
        }
    }

    pub fn is_valid(&self) -> bool {
        match self {
            SymbolicVar::Int(bv) => !bv.get_z3_ast().is_null(),
            SymbolicVar::Float(fv) => !fv.get_z3_ast().is_null(),
            SymbolicVar::Bool(b) => !b.get_z3_ast().is_null(),
        }
    }
}
