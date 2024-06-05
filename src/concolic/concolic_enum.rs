use crate::state::{cpu_state::CpuConcolicValue, memory_x86_64::MemoryConcolicValue};
use z3::Context;
use super::ConcolicVar;

macro_rules! log {
    ($logger:expr, $($arg:tt)*) => {{
        writeln!($logger, $($arg)*).unwrap();
    }};
}

#[derive(Clone, Debug)]
pub enum ConcolicEnum<'ctx> {
    ConcolicVar(ConcolicVar<'ctx>),
    CpuConcolicValue(CpuConcolicValue<'ctx>),
    MemoryConcolicValue(MemoryConcolicValue<'ctx>),
}

impl<'ctx> ConcolicEnum<'ctx> {
    
    pub fn concolic_add(self, other: ConcolicEnum<'ctx>) -> Result<ConcolicEnum<'ctx>, &'static str> {
        match (self, other) {
            // Adding ConcolicVar with ConcolicVar
            (ConcolicEnum::ConcolicVar(a), ConcolicEnum::ConcolicVar(b)) => {
                Ok(ConcolicEnum::ConcolicVar(a.concolic_add(b)?))
            },
            // Adding ConcolicVar with CpuConcolicValue
            (ConcolicEnum::ConcolicVar(a), ConcolicEnum::CpuConcolicValue(b)) |
            (ConcolicEnum::CpuConcolicValue(b), ConcolicEnum::ConcolicVar(a)) => {
                b.add_with_var(a).map(ConcolicEnum::CpuConcolicValue)
            },
            // Adding ConcolicVar with MemoryConcolicValue
            (ConcolicEnum::ConcolicVar(a), ConcolicEnum::MemoryConcolicValue(b)) |
            (ConcolicEnum::MemoryConcolicValue(b), ConcolicEnum::ConcolicVar(a)) => {
                b.add_with_var(a).map(ConcolicEnum::MemoryConcolicValue)
            },
            // Adding CpuConcolicValue with CpuConcolicValue
            (ConcolicEnum::CpuConcolicValue(a), ConcolicEnum::CpuConcolicValue(b)) => {
                Ok(ConcolicEnum::CpuConcolicValue(a.add(b)?))
            },
            // Adding CpuConcolicValue with MemoryConcolicValue
            (ConcolicEnum::CpuConcolicValue(a), ConcolicEnum::MemoryConcolicValue(b)) |
            (ConcolicEnum::MemoryConcolicValue(b), ConcolicEnum::CpuConcolicValue(a)) => {
                b.add_with_other(a).map(ConcolicEnum::MemoryConcolicValue)
            },
            // Adding MemoryConcolicValue with MemoryConcolicValue
            (ConcolicEnum::MemoryConcolicValue(a), ConcolicEnum::MemoryConcolicValue(b)) => {
                Ok(ConcolicEnum::MemoryConcolicValue(a.add(b)?))
            }
        }
    }

    // Method to perform concolic unsigned addition with carry detection
    pub fn concolic_carry(self, other: ConcolicEnum<'ctx>) -> Result<ConcolicEnum<'ctx>, &'static str> {
    match (self, other) {
        // Carrying ConcolicVar with ConcolicVar
        (ConcolicEnum::ConcolicVar(a), ConcolicEnum::ConcolicVar(b)) => {
            match a.carrying_add(&b, false) {
                Ok((_result, carry)) => {
                    let carry_var = ConcolicVar::new_concrete_and_symbolic_int(carry as u64, "carry", a.ctx, 1);
                    Ok(ConcolicEnum::ConcolicVar(carry_var))
                },
                Err(e) => Err(e),
            }
        },
        // Carrying ConcolicVar with CpuConcolicValue
        (ConcolicEnum::ConcolicVar(a), ConcolicEnum::CpuConcolicValue(b)) |
        (ConcolicEnum::CpuConcolicValue(b), ConcolicEnum::ConcolicVar(a)) => {
            let (_result, carry) = a.carrying_add_with_cpu(&b, false);
            let carry_var = ConcolicVar::new_concrete_and_symbolic_int(carry as u64, "carry", a.ctx, 1);
            Ok(ConcolicEnum::ConcolicVar(carry_var))
        },
        // Carrying ConcolicVar with MemoryConcolicValue
        (ConcolicEnum::ConcolicVar(a), ConcolicEnum::MemoryConcolicValue(b)) |
        (ConcolicEnum::MemoryConcolicValue(b), ConcolicEnum::ConcolicVar(a)) => {
            let (_result, carry) = a.carrying_add_with_mem(&b, false);
            let carry_var = ConcolicVar::new_concrete_and_symbolic_int(carry as u64, "carry", a.ctx, 1);
            Ok(ConcolicEnum::ConcolicVar(carry_var))
        },
        // Carrying CpuConcolicValue with CpuConcolicValue
        (ConcolicEnum::CpuConcolicValue(a), ConcolicEnum::CpuConcolicValue(b)) => {
            let (_result, carry) = a.carrying_add(&b, false);
            let carry_var = ConcolicVar::new_concrete_and_symbolic_int(carry as u64, "carry", a.ctx, 1);
            Ok(ConcolicEnum::ConcolicVar(carry_var))
        },
        // Carrying CpuConcolicValue with MemoryConcolicValue
        (ConcolicEnum::CpuConcolicValue(a), ConcolicEnum::MemoryConcolicValue(b)) |
        (ConcolicEnum::MemoryConcolicValue(b), ConcolicEnum::CpuConcolicValue(a)) => {
            let (_result, carry) = a.carrying_add_with_mem(&b, false);
            let carry_var = ConcolicVar::new_concrete_and_symbolic_int(carry as u64, "carry", a.ctx, 1);
            Ok(ConcolicEnum::ConcolicVar(carry_var))
        },
        // Carrying MemoryConcolicValue with MemoryConcolicValue
        (ConcolicEnum::MemoryConcolicValue(a), ConcolicEnum::MemoryConcolicValue(b)) => {
            let (_result, carry) = a.carrying_add(&b, false);
            let carry_var = ConcolicVar::new_concrete_and_symbolic_int(carry as u64, "carry", a.ctx, 1);
            Ok(ConcolicEnum::ConcolicVar(carry_var))
        }
    }
}

    // Method to perform concolic signed carry detection
    pub fn concolic_scarry(self: ConcolicEnum<'ctx>, other: ConcolicEnum<'ctx>) -> Result<ConcolicEnum<'ctx>, &'static str> {
        match (self, other) {
            (ConcolicEnum::ConcolicVar(a), ConcolicEnum::ConcolicVar(b)) => {
                let (_, overflow) = a.signed_add(&b)?;
                let carry_var = ConcolicVar::new_concrete_and_symbolic_int(
                    overflow as u64, "carry", a.ctx, 1
                );
                Ok(ConcolicEnum::ConcolicVar(carry_var))
            },
            (ConcolicEnum::ConcolicVar(a), ConcolicEnum::CpuConcolicValue(b)) |
            (ConcolicEnum::CpuConcolicValue(b), ConcolicEnum::ConcolicVar(a)) => {
                let (_, overflow) = a.signed_add_with_cpu(&b)?;
                let carry_var = ConcolicVar::new_concrete_and_symbolic_int(
                    overflow as u64, "carry", a.ctx, 1
                );
                Ok(ConcolicEnum::ConcolicVar(carry_var))
            },
            (ConcolicEnum::ConcolicVar(a), ConcolicEnum::MemoryConcolicValue(b)) |
            (ConcolicEnum::MemoryConcolicValue(b), ConcolicEnum::ConcolicVar(a)) => {
                let (_, overflow) = a.signed_add_with_mem(&b)?;
                let carry_var = ConcolicVar::new_concrete_and_symbolic_int(
                    overflow as u64, "carry", a.ctx, 1
                );
                Ok(ConcolicEnum::ConcolicVar(carry_var))
            },
            (ConcolicEnum::CpuConcolicValue(a), ConcolicEnum::CpuConcolicValue(b)) => {
                let (_, overflow) = a.signed_add(&b)?;
                let carry_var = ConcolicVar::new_concrete_and_symbolic_int(
                    overflow as u64, "carry", a.ctx, 1
                );
                Ok(ConcolicEnum::ConcolicVar(carry_var))
            },
            (ConcolicEnum::CpuConcolicValue(a), ConcolicEnum::MemoryConcolicValue(b)) => {
                let (_, overflow) = a.signed_add_with_mem(&b)?;
                let carry_var = ConcolicVar::new_concrete_and_symbolic_int(
                    overflow as u64, "carry", a.ctx, 1
                );
                Ok(ConcolicEnum::ConcolicVar(carry_var))
            },
            (ConcolicEnum::MemoryConcolicValue(a), ConcolicEnum::CpuConcolicValue(b)) => {
                let (_, overflow) = a.signed_add_with_cpu(&b)?;
                let carry_var = ConcolicVar::new_concrete_and_symbolic_int(
                    overflow as u64, "carry", a.ctx, 1
                );
                Ok(ConcolicEnum::ConcolicVar(carry_var))
            },
            (ConcolicEnum::MemoryConcolicValue(a), ConcolicEnum::MemoryConcolicValue(b)) => {
                let (_, overflow) = a.signed_add(&b)?;
                let carry_var = ConcolicVar::new_concrete_and_symbolic_int(
                    overflow as u64, "carry", a.ctx, 1
                );
                Ok(ConcolicEnum::ConcolicVar(carry_var))
            },
        }
        
    }
    // Method to perform integer subtraction
    pub fn concolic_sub(self, other: ConcolicEnum<'ctx>, ctx: &'ctx Context) -> Result<ConcolicEnum<'ctx>, &'static str> {
        match (self, other) {
            // Subtracting ConcolicVar from ConcolicVar
            (ConcolicEnum::ConcolicVar(a), ConcolicEnum::ConcolicVar(b)) => {
                a.concolic_sub(b, ctx).map(ConcolicEnum::ConcolicVar)
            },
            // Subtracting CpuConcolicValue from ConcolicVar
            (ConcolicEnum::ConcolicVar(a), ConcolicEnum::CpuConcolicValue(b)) => {
                b.sub_with_var(a, ctx).map(ConcolicEnum::CpuConcolicValue)
            },
            (ConcolicEnum::CpuConcolicValue(b), ConcolicEnum::ConcolicVar(a)) => {
                b.sub_with_var(a, ctx).map(ConcolicEnum::CpuConcolicValue)
            },
            // Subtracting MemoryConcolicValue from ConcolicVar
            (ConcolicEnum::ConcolicVar(a), ConcolicEnum::MemoryConcolicValue(b)) => {
                a.concolic_sub_with_mem(b, ctx).map(ConcolicEnum::ConcolicVar)
            },
            (ConcolicEnum::MemoryConcolicValue(b), ConcolicEnum::ConcolicVar(a)) => {
                b.sub_with_var(a, ctx).map(ConcolicEnum::MemoryConcolicValue)
            },
            // Subtracting CpuConcolicValue from CpuConcolicValue
            (ConcolicEnum::CpuConcolicValue(a), ConcolicEnum::CpuConcolicValue(b)) => {
                a.sub(b, ctx).map(ConcolicEnum::CpuConcolicValue)
            },
            // Subtracting CpuConcolicValue from MemoryConcolicValue
            (ConcolicEnum::CpuConcolicValue(a), ConcolicEnum::MemoryConcolicValue(b)) => {
                a.sub_with_mem(b, ctx).map(ConcolicEnum::CpuConcolicValue)
            },
            (ConcolicEnum::MemoryConcolicValue(b), ConcolicEnum::CpuConcolicValue(a)) => {
                a.sub_with_mem(b, ctx).map(ConcolicEnum::CpuConcolicValue)
            },
            // Subtracting MemoryConcolicValue from MemoryConcolicValue
            (ConcolicEnum::MemoryConcolicValue(a), ConcolicEnum::MemoryConcolicValue(b)) => {
                a.sub(b, ctx).map(ConcolicEnum::MemoryConcolicValue)
            },
        }
    }
    
    // Method to compare two ConcolicEnum values
    pub fn concolic_less_than(self, other: ConcolicEnum<'ctx>, ctx: &'ctx Context) -> Result<ConcolicEnum<'ctx>, &'static str> {
        let result = match (self, other) {
            // Comparing ConcolicVar with ConcolicVar
            (ConcolicEnum::ConcolicVar(a), ConcolicEnum::ConcolicVar(b)) => a.concrete.to_u64() < b.concrete.to_u64(),

            // Comparing CpuConcolicValue with CpuConcolicValue
            (ConcolicEnum::CpuConcolicValue(a), ConcolicEnum::CpuConcolicValue(b)) => a.concrete.to_u64() < b.concrete.to_u64(),

            // Comparing MemoryConcolicValue with MemoryConcolicValue
            (ConcolicEnum::MemoryConcolicValue(a), ConcolicEnum::MemoryConcolicValue(b)) => a.concrete.to_u64() < b.concrete.to_u64(),

            // Comparing ConcolicVar with CpuConcolicValue
            (ConcolicEnum::ConcolicVar(a), ConcolicEnum::CpuConcolicValue(b)) => a.concrete.to_u64() < b.concrete.to_u64(),
            (ConcolicEnum::CpuConcolicValue(a), ConcolicEnum::ConcolicVar(b)) => a.concrete.to_u64() < b.concrete.to_u64(),

            // Comparing ConcolicVar with MemoryConcolicValue
            (ConcolicEnum::ConcolicVar(a), ConcolicEnum::MemoryConcolicValue(b)) => a.concrete.to_u64() < b.concrete.to_u64(),
            (ConcolicEnum::MemoryConcolicValue(a), ConcolicEnum::ConcolicVar(b)) => a.concrete.to_u64() < b.concrete.to_u64(),

            // Comparing CpuConcolicValue with MemoryConcolicValue
            (ConcolicEnum::CpuConcolicValue(a), ConcolicEnum::MemoryConcolicValue(b)) => a.concrete.to_u64() < b.concrete.to_u64(),
            (ConcolicEnum::MemoryConcolicValue(a), ConcolicEnum::CpuConcolicValue(b)) => a.concrete.to_u64() < b.concrete.to_u64(),
        };

        let result_name = format!("{}", result);
        // Create a new ConcolicVar that represents the result of the comparison
        Ok(ConcolicEnum::ConcolicVar(ConcolicVar::new_concrete_and_symbolic_int(
            result as u64, &result_name, ctx, 1 // Use the passed context and boolean result size
        )))
    }

    // Method to perform signed less-than comparison
    pub fn concolic_sless(self, other: ConcolicEnum<'ctx>, ctx: &'ctx Context) -> Result<ConcolicEnum<'ctx>, &'static str> {
        let result = match (self, other) {
            // Comparing ConcolicVar with ConcolicVar
            (ConcolicEnum::ConcolicVar(a), ConcolicEnum::ConcolicVar(b)) => a.concrete.to_i64()? < b.concrete.to_i64()?,

            // Comparing CpuConcolicValue with CpuConcolicValue
            (ConcolicEnum::CpuConcolicValue(a), ConcolicEnum::CpuConcolicValue(b)) => a.concrete.to_i64()? < b.concrete.to_i64()?,

            // Comparing MemoryConcolicValue with MemoryConcolicValue
            (ConcolicEnum::MemoryConcolicValue(a), ConcolicEnum::MemoryConcolicValue(b)) => a.concrete.to_i64()? < b.concrete.to_i64()?,

            // Comparing ConcolicVar with CpuConcolicValue
            (ConcolicEnum::ConcolicVar(a), ConcolicEnum::CpuConcolicValue(b)) => a.concrete.to_i64()? < b.concrete.to_i64()?,
            (ConcolicEnum::CpuConcolicValue(a), ConcolicEnum::ConcolicVar(b)) => a.concrete.to_i64()? < b.concrete.to_i64()?,

            // Comparing ConcolicVar with MemoryConcolicValue
            (ConcolicEnum::ConcolicVar(a), ConcolicEnum::MemoryConcolicValue(b)) => a.concrete.to_i64()? < b.concrete.to_i64()?,
            (ConcolicEnum::MemoryConcolicValue(a), ConcolicEnum::ConcolicVar(b)) => a.concrete.to_i64()? < b.concrete.to_i64()?,

            // Comparing CpuConcolicValue with MemoryConcolicValue
            (ConcolicEnum::CpuConcolicValue(a), ConcolicEnum::MemoryConcolicValue(b)) => a.concrete.to_i64()? < b.concrete.to_i64()?,
            (ConcolicEnum::MemoryConcolicValue(a), ConcolicEnum::CpuConcolicValue(b)) => a.concrete.to_i64()? < b.concrete.to_i64()?,
        };

        let result_name = format!("{}", result);
        // Create a new ConcolicVar that represents the result of the comparison
        Ok(ConcolicEnum::ConcolicVar(ConcolicVar::new_concrete_and_symbolic_int(
            result as u64, &result_name, ctx, 1 // Use the passed context and boolean result size
        )))
    }

    // Method to perform signed subtraction with overflow check
    pub fn concolic_sborrow(self, other: ConcolicEnum<'ctx>, ctx: &'ctx Context) -> Result<bool, &'static str> {
        match (self, other) {
            (ConcolicEnum::ConcolicVar(a), ConcolicEnum::ConcolicVar(b)) => a.concolic_sborrow(b, ctx),
            (ConcolicEnum::ConcolicVar(a), ConcolicEnum::CpuConcolicValue(b)) |
            (ConcolicEnum::CpuConcolicValue(b), ConcolicEnum::ConcolicVar(a)) => b.signed_sub_with_var(a, ctx).map(|_| false),
            (ConcolicEnum::ConcolicVar(a), ConcolicEnum::MemoryConcolicValue(b)) |
            (ConcolicEnum::MemoryConcolicValue(b), ConcolicEnum::ConcolicVar(a)) => b.signed_sub_with_var(a, ctx).map(|_| false),
            (ConcolicEnum::CpuConcolicValue(a), ConcolicEnum::CpuConcolicValue(b)) => {
                a.signed_sub(b, ctx).map(|_| false)
            },
            (ConcolicEnum::CpuConcolicValue(a), ConcolicEnum::MemoryConcolicValue(b)) |
            (ConcolicEnum::MemoryConcolicValue(b), ConcolicEnum::CpuConcolicValue(a)) => b.signed_sub_with_other(a, ctx).map(|_| false),
            (ConcolicEnum::MemoryConcolicValue(a), ConcolicEnum::MemoryConcolicValue(b)) => {
                a.signed_sub(b, ctx).map(|_| false)
            }
        }
    }

    // Method to perform equality comparison
    pub fn concolic_equal(self, other: ConcolicEnum<'ctx>, ctx: &'ctx Context) -> Result<ConcolicEnum<'ctx>, &'static str> {
        let result = match (self, other) {
            // Comparing ConcolicVar with ConcolicVar
            (ConcolicEnum::ConcolicVar(a), ConcolicEnum::ConcolicVar(b)) => a.concrete.to_u64() == b.concrete.to_u64(),

            // Comparing CpuConcolicValue with CpuConcolicValue
            (ConcolicEnum::CpuConcolicValue(a), ConcolicEnum::CpuConcolicValue(b)) => a.concrete.to_u64() == b.concrete.to_u64(),

            // Comparing MemoryConcolicValue with MemoryConcolicValue
            (ConcolicEnum::MemoryConcolicValue(a), ConcolicEnum::MemoryConcolicValue(b)) => a.concrete.to_u64() == b.concrete.to_u64(),

            // Comparing ConcolicVar with CpuConcolicValue
            (ConcolicEnum::ConcolicVar(a), ConcolicEnum::CpuConcolicValue(b)) => a.concrete.to_u64() == b.concrete.to_u64(),
            (ConcolicEnum::CpuConcolicValue(a), ConcolicEnum::ConcolicVar(b)) => a.concrete.to_u64() == b.concrete.to_u64(),

            // Comparing ConcolicVar with MemoryConcolicValue
            (ConcolicEnum::ConcolicVar(a), ConcolicEnum::MemoryConcolicValue(b)) => a.concrete.to_u64() == b.concrete.to_u64(),
            (ConcolicEnum::MemoryConcolicValue(a), ConcolicEnum::ConcolicVar(b)) => a.concrete.to_u64() == b.concrete.to_u64(),

            // Comparing CpuConcolicValue with MemoryConcolicValue
            (ConcolicEnum::CpuConcolicValue(a), ConcolicEnum::MemoryConcolicValue(b)) => a.concrete.to_u64() == b.concrete.to_u64(),
            (ConcolicEnum::MemoryConcolicValue(a), ConcolicEnum::CpuConcolicValue(b)) => a.concrete.to_u64() == b.concrete.to_u64(),
        };

        let result_name = format!("{}", result);
        // Create a new ConcolicVar that represents the result of the comparison
        Ok(ConcolicEnum::ConcolicVar(ConcolicVar::new_concrete_and_symbolic_int(
            result as u64, &result_name, ctx, 1 // Use the passed context and boolean result size
        )))
    }

    // Function to perform concolic AND operation
    pub fn concolic_and(self, context: &'ctx Context, other: ConcolicEnum<'ctx>) -> Result<ConcolicEnum<'ctx>, String> {
        match (self, other) {
            (ConcolicEnum::ConcolicVar(a), ConcolicEnum::ConcolicVar(b)) => {
                if a.symbolic.get_size() != b.symbolic.get_size() {
                    return Err("Bit-vector sizes do not match for AND operation".to_string());
                }
                a.concolic_and(context, b).map(ConcolicEnum::ConcolicVar).map_err(|e| e.to_string())
            },
            (ConcolicEnum::ConcolicVar(a), ConcolicEnum::CpuConcolicValue(b)) => {
                if a.symbolic.get_size() != b.symbolic.get_size() {
                    return Err("Bit-vector sizes do not match for AND operation".to_string());
                }
                b.and_with_var(a).map(ConcolicEnum::CpuConcolicValue).map_err(|e| e.to_string())
            },
            (ConcolicEnum::CpuConcolicValue(b), ConcolicEnum::ConcolicVar(a)) => {
                if a.symbolic.get_size() != b.symbolic.get_size() {
                    return Err("Bit-vector sizes do not match for AND operation".to_string());
                }
                b.and_with_var(a).map(ConcolicEnum::CpuConcolicValue).map_err(|e| e.to_string())
            },
            (ConcolicEnum::ConcolicVar(a), ConcolicEnum::MemoryConcolicValue(b)) => {
                if a.symbolic.get_size() != b.symbolic.get_size() {
                    return Err("Bit-vector sizes do not match for AND operation".to_string());
                }
                b.and_with_var(a).map(ConcolicEnum::MemoryConcolicValue).map_err(|e| e.to_string())
            },
            (ConcolicEnum::MemoryConcolicValue(b), ConcolicEnum::ConcolicVar(a)) => {
                if a.symbolic.get_size() != b.symbolic.get_size() {
                    return Err("Bit-vector sizes do not match for AND operation".to_string());
                }
                b.and_with_var(a).map(ConcolicEnum::MemoryConcolicValue).map_err(|e| e.to_string())
            },
            (ConcolicEnum::CpuConcolicValue(a), ConcolicEnum::CpuConcolicValue(b)) => {
                if a.symbolic.get_size() != b.symbolic.get_size() {
                    return Err("Bit-vector sizes do not match for AND operation".to_string());
                }
                a.and(b).map(ConcolicEnum::CpuConcolicValue).map_err(|e| e.to_string())
            },
            (ConcolicEnum::CpuConcolicValue(a), ConcolicEnum::MemoryConcolicValue(b)) => {
                if a.symbolic.get_size() != b.symbolic.get_size() {
                    return Err("Bit-vector sizes do not match for AND operation".to_string());
                }
                a.and_with_memory(b).map(ConcolicEnum::CpuConcolicValue).map_err(|e| e.to_string())
            },
            (ConcolicEnum::MemoryConcolicValue(a), ConcolicEnum::CpuConcolicValue(b)) => {
                if a.symbolic.get_size() != b.symbolic.get_size() {
                    return Err("Bit-vector sizes do not match for AND operation".to_string());
                }
                a.and_with_cpu(b).map(ConcolicEnum::MemoryConcolicValue).map_err(|e| e.to_string())
            },
            (ConcolicEnum::MemoryConcolicValue(a), ConcolicEnum::MemoryConcolicValue(b)) => {
                if a.symbolic.get_size() != b.symbolic.get_size() {
                    return Err("Bit-vector sizes do not match for AND operation".to_string());
                }
                a.and(b).map(ConcolicEnum::MemoryConcolicValue).map_err(|e| e.to_string())
            },
            _ => Err("Unsupported types for AND operation".to_string())
        }
    }

    // Function to perform concolic OR operation
    pub fn concolic_or(self, other: ConcolicEnum<'ctx>, ctx: &'ctx Context) -> Result<ConcolicEnum<'ctx>, &'static str> {
        match (self, other) {
            // OR operation between two ConcolicVars
            (ConcolicEnum::ConcolicVar(a), ConcolicEnum::ConcolicVar(b)) => {
                a.concolic_or(ctx, b).map(ConcolicEnum::ConcolicVar)
            },
            // OR operation between ConcolicVar and CpuConcolicValue, handling both orderings
            (ConcolicEnum::ConcolicVar(a), ConcolicEnum::CpuConcolicValue(b)) => {
                b.or_with_var(a).map(ConcolicEnum::CpuConcolicValue)
            },
            (ConcolicEnum::CpuConcolicValue(b), ConcolicEnum::ConcolicVar(a)) => {
                b.or_with_var(a).map(ConcolicEnum::CpuConcolicValue)
            },
            // OR operation between ConcolicVar and MemoryConcolicValue, handling both orderings
            (ConcolicEnum::ConcolicVar(a), ConcolicEnum::MemoryConcolicValue(b)) => {
                b.or_with_var(a).map(ConcolicEnum::MemoryConcolicValue)
            },
            (ConcolicEnum::MemoryConcolicValue(b), ConcolicEnum::ConcolicVar(a)) => {
                b.or_with_var(a).map(ConcolicEnum::MemoryConcolicValue)
            },
            // OR operation between two CpuConcolicValues
            (ConcolicEnum::CpuConcolicValue(a), ConcolicEnum::CpuConcolicValue(b)) => {
                a.or(b).map(ConcolicEnum::CpuConcolicValue)
            },
            // OR operation between CpuConcolicValue and MemoryConcolicValue, and vice versa
            (ConcolicEnum::CpuConcolicValue(a), ConcolicEnum::MemoryConcolicValue(b)) => {
                a.or_with_memory(b).map(ConcolicEnum::CpuConcolicValue)
            },
            (ConcolicEnum::MemoryConcolicValue(a), ConcolicEnum::CpuConcolicValue(b)) => {
                a.or_with_cpu(b).map(ConcolicEnum::MemoryConcolicValue)
            },
            // OR operation between two MemoryConcolicValues
            (ConcolicEnum::MemoryConcolicValue(a), ConcolicEnum::MemoryConcolicValue(b)) => {
                a.or(b).map(ConcolicEnum::MemoryConcolicValue)
            },
        }
    }
    
    pub fn is_same_context(&self, other: &Self) -> bool {
        match (self, other) {
            (ConcolicEnum::ConcolicVar(a), ConcolicEnum::ConcolicVar(b)) => a.ctx == b.ctx,
            (ConcolicEnum::MemoryConcolicValue(a), ConcolicEnum::MemoryConcolicValue(b)) => a.ctx == b.ctx,
            _ => false,
        }
    }

    // Retrieve the concrete value of the concolic variable
    pub fn get_concrete_value(&self) -> u64 {
        match self {
            ConcolicEnum::ConcolicVar(var) => var.concrete.to_u64(),
            ConcolicEnum::CpuConcolicValue(cpu) => cpu.concrete.to_u64(), 
            ConcolicEnum::MemoryConcolicValue(mem) => mem.concrete.to_u64(), 
        }
    }

    // Retrieve the size of the concolic variable
    pub fn get_size(&self) -> u32 {
        match self {
            ConcolicEnum::ConcolicVar(var) => var.concrete.get_size(),
            ConcolicEnum::CpuConcolicValue(cpu) => cpu.concrete.get_size(),
            ConcolicEnum::MemoryConcolicValue(mem) => mem.concrete.get_size(),
        }
    }

    // Retrieve the size of the concolic variable
    pub fn get_context_id(&self) -> Option<u64> {
        match self {
            ConcolicEnum::ConcolicVar(var) => Some(var.get_context_id().parse().unwrap()),
            ConcolicEnum::CpuConcolicValue(cpu_var) => Some(cpu_var.get_context_id().parse().unwrap()),
            _ => None,
        }
    }
}
