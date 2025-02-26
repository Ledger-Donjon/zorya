extern crate z3;
use z3::ast::{Ast, Bool, Float, Int, BV};
use z3::Context;
use z3_sys::Z3_ast;

#[derive(Clone, Debug, PartialEq)]
pub enum SymbolicVar<'ctx> {
    Int(BV<'ctx>),
    LargeInt(Vec<BV<'ctx>>), // int larger than 64 bits
    Float(Float<'ctx>),
    Bool(Bool<'ctx>),
}

impl<'ctx> SymbolicVar<'ctx> {
    pub fn new_int(value: i64, ctx: &'ctx Context, size: u32) -> SymbolicVar<'ctx> {
        let bv = BV::from_i64(ctx, value as i64, size);
        SymbolicVar::Int(bv)
    }

    pub fn new_float(value: f64, ctx: &'ctx Context) -> SymbolicVar<'ctx> {
        let float = Float::from_f64(ctx, value);
        SymbolicVar::Float(float)
    }

    /// Perform a population count (popcount) on the symbolic variable
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
            SymbolicVar::LargeInt(vec) => {
                let ctx = vec.first().expect("LargeInt vector should not be empty").get_ctx();
                let mut count = BV::from_u64(ctx, 0, vec.first().unwrap().get_size());
                for bv in vec {
                    for i in 0..bv.get_size() {
                        let bit = bv.extract(i, i);
                        count = count.bvadd(&bit.zero_ext(bv.get_size() - 1));
                    }
                }
                count
            },
            SymbolicVar::Bool(bool_val) => {
                // Popcount for booleans: true is 1, false is 0
                let count = if bool_val.as_bool().unwrap() { BV::from_u64(bool_val.get_ctx(), 1, 1) } else { BV::from_u64(bool_val.get_ctx(), 0, 1) };
                // Since a boolean has size 1, we don't need to extend the result
                count
            },
            SymbolicVar::Float(_) => panic!("Popcount is not defined for floating-point values"),
        }
    }

    // Method to extract a sub-bitvector from a symbolic integer variable
    pub fn extract(&self, high: u32, low: u32) -> Result<SymbolicVar<'ctx>, &'static str> {
        match self {
            SymbolicVar::Int(bv) => {
                let extracted_bv = bv.extract(high, low);
                Ok(SymbolicVar::Int(extracted_bv))
            },
            SymbolicVar::LargeInt(vec) => {
                let extracted_vec = vec.iter().map(|bv| bv.extract(high, low)).collect();
                Ok(SymbolicVar::LargeInt(extracted_vec))
            },
            SymbolicVar::Float(_) => Err("Extract operation not supported on floating-point symbolic variables"),
            SymbolicVar::Bool(_) => Err("Extract operation not supported on boolean symbolic variables"),
        }
    }

    // Method to check if two symbolic variables are equal
    pub fn equal(&self, other: &SymbolicVar<'ctx>) -> bool {
        match (self, other) {
            (SymbolicVar::Int(a), SymbolicVar::Int(b)) => a.eq(&b),
            (SymbolicVar::LargeInt(a), SymbolicVar::LargeInt(b)) => a.iter().zip(b.iter()).all(|(x, y)| x.eq(y)),
            (SymbolicVar::Float(a), SymbolicVar::Float(b)) => a.eq(&b),
            _ => false,
        }
    }

    pub fn to_str(&self) -> String {
        match self {
            SymbolicVar::Int(bv) => bv.to_string(),
            SymbolicVar::LargeInt(vec) => vec.iter().map(|bv| bv.to_string()).collect::<Vec<_>>().join("|"),
            SymbolicVar::Float(f) => f.to_string(),
            SymbolicVar::Bool(b) => b.to_string(),
        }
    }

    // Convert the symbolic variable to a bit vector
    pub fn to_bv(&self, ctx: &'ctx Context) -> BV<'ctx> {
        match self {
            SymbolicVar::Int(bv) => bv.clone(),
            SymbolicVar::LargeInt(vec) => {
                // Concatenate the BVs in the vector to form a single BV
                // Since in little-endian, least significant bits are in vec[0], we need to reverse the vector
                let mut bv_iter = vec.iter().rev();
                let first_bv = bv_iter.next().expect("LargeInt should not be empty").clone();
                bv_iter.fold(first_bv, |acc, bv| {
                    acc.concat(&bv.clone())
                })
            },
            SymbolicVar::Float(_) => panic!("Cannot convert a floating-point symbolic variable to a bit vector"),
            SymbolicVar::Bool(b) => {
                let one = BV::from_u64(ctx, 1, 1); 
                let zero = BV::from_u64(ctx, 0, 1); 
                b.ite(&one, &zero) // If `b` is true, return `one`, otherwise return `zero`
            }
        }
    }

    pub fn to_largebv(&self) -> Vec<BV<'ctx>> {
        match self {
            SymbolicVar::Int(bv) => vec![bv.clone()],
            SymbolicVar::LargeInt(vec) => vec.clone(),
            SymbolicVar::Float(_) => panic!("Cannot convert a floating-point symbolic variable to a large bit vector"),
            SymbolicVar::Bool(b) => {
                let one = BV::from_u64(b.get_ctx(), 1, 1); 
                let zero = BV::from_u64(b.get_ctx(), 0, 1); 
                vec![b.ite(&one, &zero)] // If `b` is true, return `one`, otherwise return `zero`
            }
        }
    }

    // Convert the symbolic variable to a float
    pub fn to_float(&self) -> Float<'ctx> {
        match self {
            SymbolicVar::Float(f) => f.clone(),
            _ => panic!("Conversion to float is not supported for this type"),
        }
    }

    // Convert the symbolic variable to a boolean
    pub fn to_bool(&self) -> Bool<'ctx> {
        match self {
            SymbolicVar::Bool(b) => b.clone(),
            SymbolicVar::Int(bv) => {
                let zero = BV::from_u64(bv.get_ctx(), 0, bv.get_size());
                bv.bvugt(&zero)  // Returns Bool directly
            },
            SymbolicVar::LargeInt(vec) => {
                let ctx = vec[0].get_ctx();
                let zero_bv = BV::from_u64(ctx, 0, vec[0].get_size());
                let one_bv = BV::from_u64(ctx, 1, vec[0].get_size());
                // Transform each BV comparison result to BV again for bitwise OR
                let combined_or = vec.iter().fold(BV::from_u64(ctx, 0, 1), |acc, bv| {
                    let is_non_zero = bv.bvugt(&zero_bv);
                    let bv_is_non_zero = is_non_zero.ite(&one_bv, &zero_bv);
                    acc.bvor(&bv_is_non_zero)
                });
                // Use bvredor to reduce to a single bit and then compare with zero
                let reduced_or = combined_or.bvredor();
                let value = !reduced_or._eq(&BV::from_u64(ctx, 0, 1));
                let result = Bool::from_bool(ctx, value.as_bool().unwrap());
                result
            },
            SymbolicVar::Float(_) => panic!("Cannot convert a floating-point symbolic variable to a boolean"),
        }
    }

    // Convert a constant to a symbolic value.
    pub fn from_u64(ctx: &'ctx Context, value: u64, size: u32) -> SymbolicVar<'ctx> {
        if size > 64 {
            let num_blocks = (size + 63) / 64;
            let mut vec = vec![BV::from_u64(ctx, 0, 64); num_blocks as usize];
            vec[0] = BV::from_u64(ctx, value, size.min(64));
            SymbolicVar::LargeInt(vec)
        } else {
            SymbolicVar::Int(BV::from_u64(ctx, value, size))
        }
    }

    // Method to get the underlying Z3 AST
    pub fn get_z3_ast(&self) -> Z3_ast {
        match self {
            SymbolicVar::Int(bv) => bv.get_z3_ast(),
            SymbolicVar::LargeInt(vec) => vec.first().unwrap().get_z3_ast(), // Simplified: returns AST of the first element
            SymbolicVar::Float(f) => f.get_z3_ast(),
            SymbolicVar::Bool(b) => b.get_z3_ast(),
        }
    }

    // Method to check if the underlying Z3 AST is null
    pub fn is_null(&self) -> bool {
        let ast = self.get_z3_ast();
        ast.is_null() 
    }

    // Method to check if the symbolic variable is a boolean
    pub fn is_bool(&self) -> bool {
        matches!(self, SymbolicVar::Bool(_))
    }

    pub fn get_ctx(&self) -> &'ctx Context {
        match self {
            SymbolicVar::Int(bv) => bv.get_ctx(),
            SymbolicVar::LargeInt(vec) => vec.first().unwrap().get_ctx(),
            SymbolicVar::Float(f) => f.get_ctx(),
            SymbolicVar::Bool(b) => b.get_ctx(),
        }
    }

    pub fn get_size(&self) -> u32 {
        match self {
            SymbolicVar::Int(bv) => bv.get_size(),
            SymbolicVar::LargeInt(vec) => vec.iter().map(|bv| bv.get_size()).sum(),
            SymbolicVar::Float(_) => 64,
            SymbolicVar::Bool(_) => 1,
        }
    }

    pub fn to_bv_of_size(&self, ctx: &'ctx Context, size: u32) -> BV<'ctx> {
        match self {
            SymbolicVar::Bool(b) => {
                b.ite(&BV::from_u64(ctx, 1, size), &BV::from_u64(ctx, 0, size))
            }
            SymbolicVar::Int(bv) => {
                if bv.get_size() == size {
                    bv.clone()
                } else if bv.get_size() > size {
                    bv.extract(size - 1, 0)
                } else {
                    bv.zero_ext(size - bv.get_size())
                }
            }
            SymbolicVar::LargeInt(bv_vec) => {
                let mut bv_iter = bv_vec.iter().rev(); // Reverse for little-endian order
                let first_bv = bv_iter.next().expect("LargeInt should not be empty").clone();
    
                // Concatenate all BV parts
                let mut result_bv = bv_iter.fold(first_bv, |acc, bv| acc.concat(&bv.clone()));
    
                // Extract or extend based on the required size
                if result_bv.get_size() > size {
                    result_bv.extract(size - 1, 0) // Truncate excess bits
                } else {
                    result_bv.zero_ext(size - result_bv.get_size()) // Zero-extend if smaller
                }
            }
            _ => panic!("Unsupported symbolic type for to_bv_of_size"),
        }
    }     

    // Check if the symbolic variable is valid (i.e., its underlying AST is not null)
    pub fn is_valid(&self) -> bool {
        !self.is_null()
    }

    // Convert the symbolic variable to an integer
    pub fn to_int(&self) -> Result<Int<'ctx>, &'static str> {
        match self {
            SymbolicVar::Int(bv) => Ok(Int::from_bv(bv, false)),
            SymbolicVar::LargeInt(_) => Err("Conversion to integer is not supported for large integers symbolic variables"),
            SymbolicVar::Float(_) => Err("Conversion to integer is not supported for floating-point symbolic variables"),
            SymbolicVar::Bool(_) => Err("Conversion to integer is not supported for boolean symbolic variables"),
        }
    }

}
