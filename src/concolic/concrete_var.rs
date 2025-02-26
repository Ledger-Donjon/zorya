use std::{error::Error, fmt::{self, LowerHex}};
use num_bigint::BigUint;
use num_traits::{Zero, ToPrimitive};

#[derive(Clone, Debug, PartialEq)]
pub enum ConcreteVar {
    Int(u64),
    LargeInt(Vec<u64>), // int larger than 64 bits
    Float(f64),
    Str(String),
    Bool(bool),
}

impl ConcreteVar {   
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
            ConcreteVar::LargeInt(_) => Err(VarError::ConversionError),
           
        }
    }

    // Method to convert ConcreteVar to an integer
    pub fn to_int(&self) -> Result<u64, VarError> {
        match self {
            ConcreteVar::Int(value) => Ok(*value),
            ConcreteVar::Float(value) => {
                if value >= &0.0 && value <= &(u64::MAX as f64) {
                    Ok(*value as u64)
                } else {
                    Err(VarError::ConversionError)
                }
            },
            ConcreteVar::Str(ref s) => {
                s.parse::<u64>()
                 .map_err(|_| VarError::ConversionError)
            },
            ConcreteVar::Bool(value) => Ok(*value as u64),
            ConcreteVar::LargeInt(value) => Ok(value[0]), // little-endian interpretation
        }
    }

    pub fn to_i64(&self) -> Result<i64, &'static str> {
        match self {
            ConcreteVar::Int(val) => Ok(*val as i64),
            ConcreteVar::Float(val) => Ok(*val as i64), // Adjust this if needed for float conversion
            _ => Err("Unsupported type for to_i64 conversion"),
        }
    }

    pub fn to_i32(&self) -> Result<i32, &'static str> {
        match self {
            ConcreteVar::Int(val) => Ok(*val as i32),
            ConcreteVar::Float(val) => Ok(*val as i32), // Adjust this if needed for float conversion
            _ => Err("Unsupported type for to_i32 conversion"),
        }
    }

    // Convert ConcreteVar to u64 directly, using default values for non-convertible types
    pub fn to_u64(&self) -> u64 {
        match self {
            ConcreteVar::Int(value) => *value,
            ConcreteVar::Float(value) => {
                if value >= &0.0 && value < &(u64::MAX as f64) {
                    *value as u64
                } else {
                    0 // Default value for out-of-range or negative floats
                }
            },
            ConcreteVar::Str(ref s) => {
                s.parse::<u64>().unwrap_or(0) // Default value for unparsable strings
            },
            ConcreteVar::Bool(value) => *value as u64,
            ConcreteVar::LargeInt(value) => value[0], // Return the lower 64 bits
        }
    }

    pub fn to_largeint(&self) -> Vec<u64> {
        match self {
            ConcreteVar::LargeInt(value) => value.clone(),
            _ => vec![self.to_u64()],
        }
    }

    // Helper: Convert a ConcreteVar into a BigUint.
    pub fn concrete_to_biguint(&self) -> BigUint {
        match self {
            ConcreteVar::Int(val) => BigUint::from(*val),
            ConcreteVar::LargeInt(vec) => {
                let mut num = BigUint::zero();
                for (i, &chunk) in vec.iter().enumerate() {
                    // little-endian ordering
                    num |= BigUint::from(chunk) << (64 * i);
                }
                num
            },
            _ => BigUint::zero(), // Default value for non-integer types
        }
    }

    // Method to convert ConcreteVar to u32 safely
    pub fn to_u32(&self) -> Result<u32, VarError> {
        match self {
            ConcreteVar::Int(value) => {
                if *value <= u32::MAX as u64 {
                    Ok(*value as u32)
                } else {
                    Err(VarError::ConversionError)
                }
            },
            ConcreteVar::Float(value) => {
                if value >= &0.0 && value <= &(u32::MAX as f64) {
                    Ok(*value as u32)
                } else {
                    Err(VarError::ConversionError)
                }
            },
            ConcreteVar::Str(ref s) => {
                s.parse::<u32>()
                 .map_err(|_| VarError::ConversionError)
            },
            ConcreteVar::Bool(value) => Ok(*value as u32),
            ConcreteVar::LargeInt(_) => Err(VarError::ConversionError),
        }
    }

    // Convert ConcreteVar to a String
    pub fn to_str(&self) -> String {
        match self {
            ConcreteVar::Int(value) => value.to_string(),
            ConcreteVar::Float(value) => value.to_string(),
            ConcreteVar::Str(ref s) => s.clone(),
            ConcreteVar::Bool(value) => value.to_string(),
            ConcreteVar::LargeInt(values) => {
                let mut result = String::new();
                for &value in values.iter().rev() {
                    result.push_str(&format!("{:016x}", value)); // Convert each u64 to a zero-padded hex string
                }
                // Remove leading zeros if needed
                result.trim_start_matches('0').to_string()
            }
        }
    }    

    // Convert ConcreteVar to a boolean value
    pub fn to_bool(&self) -> bool {
        match self {
            ConcreteVar::Int(value) => *value != 0,
            ConcreteVar::Float(value) => *value != 0.0,
            ConcreteVar::Str(ref s) => !s.is_empty(),
            ConcreteVar::Bool(value) => *value,
            ConcreteVar::LargeInt(values) => values.iter().any(|&value| value != 0),
        }
    }

    pub fn get_size(&self) -> u32 {
        match self {
            ConcreteVar::Int(_) => 64,  // all integers are u64
            ConcreteVar::Float(_) => 64, // double precision floats
            ConcreteVar::Str(s) => (s.len() * 8) as u32,  // ?
            ConcreteVar::Bool(_) => 1,
            ConcreteVar::LargeInt(values) => (values.len() * 64) as u32, // Size in bits
        }
    }

    /// Extracts the signed integer value with proper sign extension
    pub fn get_concrete_value_signed(&self, bit_size: u32) -> Result<i64, VarError> {
        let raw_value = self.to_u64(); // Get raw value as unsigned
        let sign_extended = match bit_size {
            8 => (raw_value as i8) as i64,  // Sign-extend from 8-bit
            16 => (raw_value as i16) as i64, // Sign-extend from 16-bit
            32 => (raw_value as i32) as i64, // Sign-extend from 32-bit
            64 => raw_value as i64,         // Already correct
            _ => return Err(VarError::ConversionError),
        };

        Ok(sign_extended)
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
            ConcreteVar::LargeInt(mut values) => {
                let mut carry = 0u64;
                for v in values.iter_mut().rev() {
                    let new_carry = *v << (64 - (shift % 64));
                    *v = (*v >> (shift % 64)) | carry;
                    carry = new_carry;
                }
                ConcreteVar::LargeInt(values)
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

    pub fn is_bool(&self) -> bool {
        match self {
            ConcreteVar::Bool(_) => true,
            _ => false,
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
            ConcreteVar::LargeInt(values) => {
                for chunk in values.iter().rev() {
                    write!(f, "{:016x}", chunk)?;
                }
                Ok(())
            }, 
        };
        Ok(())
    }
}