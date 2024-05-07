use std::{error::Error, fmt};

#[derive(Clone, Debug, PartialEq)]
pub enum ConcreteVar {
    Int(u64),
    Float(f64),
    Str(String),
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
                s.parse::<u64>().unwrap_or(0) // Default value for unparseable strings
            },
        }
    }

    // Convert ConcreteVar to a String
    pub fn to_str(&self) -> String {
        match *self {
            ConcreteVar::Int(value) => value.to_string(),
            ConcreteVar::Float(value) => value.to_string(),
            ConcreteVar::Str(ref s) => s.clone(),
        }
    }

    pub fn get_size(&self) -> u32 {
        match self {
            ConcreteVar::Int(_) => 64,  // Assuming all integers are u64
            ConcreteVar::Float(_) => 64, // Assuming double precision floats
            ConcreteVar::Str(s) => (s.len() * 8) as u32,  // Example for strings, size in bits
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
