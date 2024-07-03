use std::{error::Error, fmt::{self, LowerHex}, num::Wrapping};

#[derive(Clone, Debug, PartialEq)]
pub enum ConcreteVar {
    Int(u64),
    Float(f64),
    Str(String),
    Bool(bool),
}

impl ConcreteVar {
    // Addition operation
    pub fn add(&self, other: &ConcreteVar) -> Self {
        match (self, other) {
            (ConcreteVar::Int(a), ConcreteVar::Int(b)) => ConcreteVar::Int(*a + *b),
            (ConcreteVar::Float(a), ConcreteVar::Float(b)) => ConcreteVar::Float(*a + *b),
            _ => panic!("Unsupported types for add operation"),
        }
    }

    pub fn overflowing_add(&self, other: &Self) -> (Self, bool) {
        match (self, other) {
            (ConcreteVar::Int(a), ConcreteVar::Int(b)) => {
                let (result, overflow) = a.overflowing_add(*b);
                (ConcreteVar::Int(result), overflow)
            },
            (ConcreteVar::Float(a), ConcreteVar::Float(b)) => {
                // Floats do not overflow in the same way integers do
                (ConcreteVar::Float(a + b), false)
            },
            _ => panic!("Type mismatch in overflowing_add")
        }
    }

    // Custom carrying add operation
    pub fn carrying_add(&self, other: &ConcreteVar, carry: bool) -> (Self, bool) {
        match (self, other) {
            (ConcreteVar::Int(a), ConcreteVar::Int(b)) => {
                let carry_value = if carry { 1 } else { 0 };
                let (intermediate, overflow1) = a.overflowing_add(*b);
                let (result, overflow2) = intermediate.overflowing_add(carry_value);
                (ConcreteVar::Int(result), overflow1 || overflow2)
            },
            (ConcreteVar::Float(a), ConcreteVar::Float(b)) => {
                // Floats do not carry in the same way integers do
                (ConcreteVar::Float(a + b + if carry { 1.0 } else { 0.0 }), false)
            },
            _ => panic!("Type mismatch in carrying_add"),
        }
    }


    // Subtraction operation
    pub fn sub(&self, other: &ConcreteVar) -> Self {
        match (self, other) {
            (ConcreteVar::Int(a), ConcreteVar::Int(b)) => ConcreteVar::Int(*a - *b),
            (ConcreteVar::Float(a), ConcreteVar::Float(b)) => ConcreteVar::Float(*a - *b),
            _ => panic!("Unsupported types for sub operation"),
        }
    }

    // Safe signed subtraction with overflow handling
    pub fn signed_sub_overflow(&self, other: &ConcreteVar) -> (Self, bool) {
        match (self, other) {
            (ConcreteVar::Int(a), ConcreteVar::Int(b)) => {
                let (result, overflow) = (Wrapping(*a as i64) - Wrapping(*b as i64)).0.overflowing_sub(*b as i64);
                (ConcreteVar::Int(result as u64), overflow)
            },
            _ => panic!("Unsupported types for signed sub with overflow operation"),
        }
    }

    // Bitwise AND operation for integers
    pub fn and(self, other: ConcreteVar) -> Self {
        match (self, other) {
            (ConcreteVar::Int(a), ConcreteVar::Int(b)) => ConcreteVar::Int(a & b),
            _ => panic!("Bitwise AND operation is not defined for floats"),
        }
    }

    // Bitwise OR operation for integers
    pub fn or(self, other: ConcreteVar) -> Self {
        match (self, other) {
            (ConcreteVar::Int(a), ConcreteVar::Int(b)) => ConcreteVar::Int(a | b),
            _ => panic!("Bitwise OR operation is not defined for floats"),
        }
    }

    // Method to convert ConcreteVar to a byte
    pub fn to_byte(&self) -> Result<u8, VarError> {
        match *self {
            ConcreteVar::Int(value) => {
                if value <= u8::MAX as u64 {
                    Ok(value as u8)
                } else {
                    Err(VarError::ConversionError)
                }
            },
            // A float cannot sensibly be converted to a byte for memory operations
            ConcreteVar::Float(_) => Err(VarError::ConversionError),
            ConcreteVar::Str(_) => Err(VarError::ConversionError),
            ConcreteVar::Bool(value) => Ok(value as u8),
           
        }
    }

    // Method to convert ConcreteVar to an integer
    pub fn to_int(&self) -> Result<u64, VarError> {
        match *self {
            ConcreteVar::Int(value) => Ok(value),
            ConcreteVar::Float(value) => {
                if value >= 0.0 && value <= u64::MAX as f64 {
                    Ok(value as u64)
                } else {
                    Err(VarError::ConversionError)
                }
            },
            ConcreteVar::Str(ref s) => {
                s.parse::<u64>()
                 .map_err(|_| VarError::ConversionError)
            },
            ConcreteVar::Bool(value) => Ok(value as u64),
        }
    }

    pub fn to_i64(&self) -> Result<i64, &'static str> {
        match self {
            ConcreteVar::Int(val) => Ok(*val as i64),
            ConcreteVar::Float(val) => Ok(*val as i64), // Adjust this if needed for float conversion
            _ => Err("Unsupported type for to_i64 conversion"),
        }
    }

    // Convert ConcreteVar to u64 directly, using default values for non-convertible types
    pub fn to_u64(&self) -> u64 {
        match *self {
            ConcreteVar::Int(value) => value,
            ConcreteVar::Float(value) => {
                if value >= 0.0 && value < u64::MAX as f64 {
                    value as u64
                } else {
                    0 // Default value for out-of-range or negative floats
                }
            },
            ConcreteVar::Str(ref s) => {
                s.parse::<u64>().unwrap_or(0) // Default value for unparsable strings
            },
            ConcreteVar::Bool(value) => value as u64,
        }
    }

    // Convert ConcreteVar to a String
    pub fn to_str(&self) -> String {
        match *self {
            ConcreteVar::Int(value) => value.to_string(),
            ConcreteVar::Float(value) => value.to_string(),
            ConcreteVar::Str(ref s) => s.clone(),
            ConcreteVar::Bool(value) => value.to_string(),
        }
    }

    pub fn get_size(&self) -> u32 {
        match self {
            ConcreteVar::Int(_) => 64,  // all integers are u64
            ConcreteVar::Float(_) => 64, // double precision floats
            ConcreteVar::Str(s) => (s.len() * 8) as u32,  // ?
            ConcreteVar::Bool(_) => 1,
        }
    }

    // Method to perform a right shift operation safely
    pub fn right_shift(self, shift: usize) -> Self {
        match self {
            ConcreteVar::Int(value) => {
                // Safely perform the right shift on an integer value.
                // We mask the shift by 63 to prevent panics or undefined behavior from shifting more than the bits available in u64.
                ConcreteVar::Int(value >> (shift & 63))
            },
            // For other types, return them unchanged or handle as needed.
            ConcreteVar::Float(_) | ConcreteVar::Str(_) => {
                // Logically, right shifting a float or string does not make sense,
                // so we can return the value unchanged or handle it differently if needed.
                self
            },
            ConcreteVar::Bool(_) => {
                self
            },
        }
    } 

    // Bitwise AND operation for ConcreteVar
    pub fn bitand(&self, other: &ConcreteVar) -> Self {
        match (self, other) {
            (ConcreteVar::Int(a), ConcreteVar::Int(b)) => ConcreteVar::Int(a & b),
            _ => panic!("Bitwise AND operation is not defined for floats"),
        }
    }
}

#[derive(Debug)]
pub enum VarError {
    ConversionError,
}

impl fmt::Display for VarError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            VarError::ConversionError => write!(f, "Error converting variable"),
        }
    }
}

impl Error for VarError {}

impl<'ctx> LowerHex for ConcreteVar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = match self {
            ConcreteVar::Int(value) => LowerHex::fmt(value, f),
            ConcreteVar::Float(value) => LowerHex::fmt(&value.to_bits(), f),
            ConcreteVar::Str(_s) => Err(fmt::Error::default()),
            ConcreteVar::Bool(value) => LowerHex::fmt(&(*value as u8), f),
        };
        Ok(())
    }
}