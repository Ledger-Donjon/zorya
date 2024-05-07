extern crate z3;
use z3::{ast::{BV, Float}, Context};

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
