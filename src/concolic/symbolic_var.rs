extern crate z3;
use z3::{ast::{Bool, Float, BV}, Context};

#[derive(Clone, Debug, PartialEq)]
pub enum SymbolicVar<'a> {
    Int(BV<'a>),
    Float(Float<'a>),
}

impl<'a> SymbolicVar<'a> {
    pub fn add(&self, other: &SymbolicVar<'a>) -> Result<SymbolicVar<'a>, &'static str> {
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

    pub fn sub(&self, other: &SymbolicVar<'a>, _ctx: &'a Context) -> Result<SymbolicVar<'a>, &'static str> {
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

    pub fn signed_sub_overflow(&self, other: &SymbolicVar<'a>, ctx: &'a Context) -> Result<Bool<'a>, &'static str> {
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

    pub fn and(self, other: &SymbolicVar<'a>, _ctx: &'a Context) -> Result<SymbolicVar<'a>, &'static str> {
        match (self, other) {
            (SymbolicVar::Int(a), SymbolicVar::Int(b)) => {
                Ok(SymbolicVar::Int(a.bvand(&b)))
            },
            _ => Err("Logical AND operation is only applicable to integers (bitvectors)"),
        }
    }

    pub fn to_str(&self) -> String {
        match self {
            SymbolicVar::Int(value) => value.to_string(),
            SymbolicVar::Float(value) => value.to_string(),
        }
    }
}
