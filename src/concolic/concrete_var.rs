use std::{error::Error, fmt};

#[derive(Clone, Debug, PartialEq)]
pub enum ConcreteVar {
    Int(u64),
    Float(f64),
    Str(String),
}

impl ConcreteVar {
    // Addition operation
    pub fn add(self, other: ConcreteVar) -> Self {
        match (self, other) {
            (ConcreteVar::Int(a), ConcreteVar::Int(b)) => ConcreteVar::Int(a + b),
            (ConcreteVar::Float(a), ConcreteVar::Float(b)) => ConcreteVar::Float(a + b),
            _ => panic!("Attempted to add incompatible ConcreteVars"),
        }
    }

    // Bitwise AND operation for integers
    pub fn and(self, other: ConcreteVar) -> Self {
        match (self, other) {
            (ConcreteVar::Int(a), ConcreteVar::Int(b)) => ConcreteVar::Int(a & b),
            _ => panic!("Bitwise AND operation is not defined for floats"),
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
