use crate::state::{cpu_state::CpuConcolicValue, memory_x86_64::MemoryConcolicValue};
use z3::Context;
use super::ConcolicVar;

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
                b.add_with_var(a)
            },
            // Adding ConcolicVar with MemoryConcolicValue
            (ConcolicEnum::ConcolicVar(a), ConcolicEnum::MemoryConcolicValue(b)) |
            (ConcolicEnum::MemoryConcolicValue(b), ConcolicEnum::ConcolicVar(a)) => {
                b.add_with_var(a)
            },
            // Adding CpuConcolicValue with CpuConcolicValue
            (ConcolicEnum::CpuConcolicValue(a), ConcolicEnum::CpuConcolicValue(b)) => {
                Ok(ConcolicEnum::CpuConcolicValue(a.add(b)?))
            },
            // Adding CpuConcolicValue with MemoryConcolicValue
            (ConcolicEnum::CpuConcolicValue(a), ConcolicEnum::MemoryConcolicValue(b)) |
            (ConcolicEnum::MemoryConcolicValue(b), ConcolicEnum::CpuConcolicValue(a)) => {
                b.add_with_other(a)
            },
            // Adding MemoryConcolicValue with MemoryConcolicValue
            (ConcolicEnum::MemoryConcolicValue(a), ConcolicEnum::MemoryConcolicValue(b)) => {
                Ok(ConcolicEnum::MemoryConcolicValue(a.add(b)?))
            }
        }
    }

    // Method to perform integer subtraction
    pub fn concolic_sub(self, other: ConcolicEnum<'ctx>, ctx: &'ctx Context) -> Result<ConcolicEnum<'ctx>, &'static str> {
        match (self, other) {
            // Subtracting ConcolicVar from ConcolicVar
            (ConcolicEnum::ConcolicVar(a), ConcolicEnum::ConcolicVar(b)) => a.concolic_sub(b, ctx),
            // Subtracting CpuConcolicValue from ConcolicVar
            (ConcolicEnum::ConcolicVar(a), ConcolicEnum::CpuConcolicValue(b)) |
            (ConcolicEnum::CpuConcolicValue(b), ConcolicEnum::ConcolicVar(a)) => b.sub_with_var(a, ctx),
            // Subtracting MemoryConcolicValue from ConcolicVar
            (ConcolicEnum::ConcolicVar(a), ConcolicEnum::MemoryConcolicValue(b)) |
            (ConcolicEnum::MemoryConcolicValue(b), ConcolicEnum::ConcolicVar(a)) => b.sub_with_var(a, ctx),
            // Subtracting CpuConcolicValue from CpuConcolicValue
            (ConcolicEnum::CpuConcolicValue(a), ConcolicEnum::CpuConcolicValue(b)) => a.sub(b, ctx).map(ConcolicEnum::CpuConcolicValue),
            // Subtracting CpuConcolicValue from MemoryConcolicValue
            (ConcolicEnum::CpuConcolicValue(a), ConcolicEnum::MemoryConcolicValue(b)) |
            (ConcolicEnum::MemoryConcolicValue(b), ConcolicEnum::CpuConcolicValue(a)) => b.sub_with_other(a, ctx),
            // Subtracting MemoryConcolicValue from MemoryConcolicValue
            (ConcolicEnum::MemoryConcolicValue(a), ConcolicEnum::MemoryConcolicValue(b)) => a.sub(b, ctx).map(ConcolicEnum::MemoryConcolicValue),
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
    pub fn concolic_sborrow(self, other: ConcolicEnum<'ctx>, ctx: &'ctx Context) -> Result<ConcolicEnum<'ctx>, &'static str> {
        match (self, other) {
            (ConcolicEnum::ConcolicVar(a), ConcolicEnum::ConcolicVar(b)) => a.concolic_sborrow(b, ctx).map(ConcolicEnum::ConcolicVar),
            // Adjustments and corrections for handling subtractions across different types
            (ConcolicEnum::ConcolicVar(a), ConcolicEnum::CpuConcolicValue(b)) |
            (ConcolicEnum::CpuConcolicValue(b), ConcolicEnum::ConcolicVar(a)) => b.signed_sub_with_var(a, ctx),
            (ConcolicEnum::ConcolicVar(a), ConcolicEnum::MemoryConcolicValue(b)) |
            (ConcolicEnum::MemoryConcolicValue(b), ConcolicEnum::ConcolicVar(a)) => b.signed_sub_with_var(a, ctx),
            (ConcolicEnum::CpuConcolicValue(a), ConcolicEnum::CpuConcolicValue(b)) => {
                a.signed_sub(b, ctx).map(ConcolicEnum::CpuConcolicValue)
            },
            (ConcolicEnum::CpuConcolicValue(a), ConcolicEnum::MemoryConcolicValue(b)) |
            (ConcolicEnum::MemoryConcolicValue(b), ConcolicEnum::CpuConcolicValue(a)) => b.signed_sub_with_other(a, ctx),
            (ConcolicEnum::MemoryConcolicValue(a), ConcolicEnum::MemoryConcolicValue(b)) => {
                a.signed_sub(b, ctx).map(ConcolicEnum::MemoryConcolicValue)
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
    pub fn concolic_and(self, other: ConcolicEnum<'ctx>, _ctx: &'ctx Context) -> Result<ConcolicEnum<'ctx>, &'static str> {
        match (self, other) {
            // AND operation between two ConcolicVars
            (ConcolicEnum::ConcolicVar(a), ConcolicEnum::ConcolicVar(b)) => {
                a.concolic_and(_ctx, b).map(ConcolicEnum::ConcolicVar)
            },
            // AND operation between ConcolicVar and CpuConcolicValue, handling both orderings
            (ConcolicEnum::ConcolicVar(a), ConcolicEnum::CpuConcolicValue(b)) => {
                b.and_with_var(a)
                    .map_err(|_| "Failed AND operation between CpuConcolicValue and ConcolicVar")
            },
            (ConcolicEnum::CpuConcolicValue(b), ConcolicEnum::ConcolicVar(a)) => {
                b.and_with_var(a)
                    .map_err(|_| "Failed AND operation between CpuConcolicValue and ConcolicVar")
            },
            // AND operation between ConcolicVar and MemoryConcolicValue, handling both orderings
            (ConcolicEnum::ConcolicVar(a), ConcolicEnum::MemoryConcolicValue(b)) => {
                b.and_with_var(a)
                    .map_err(|_| "Failed AND operation between MemoryConcolicValue and ConcolicVar")
                    
            },
            (ConcolicEnum::MemoryConcolicValue(b), ConcolicEnum::ConcolicVar(a)) => {
                b.and_with_var(a)    
                    .map_err(|_| "Failed AND operation between MemoryConcolicValue and ConcolicVar")
            },
            // AND operation between two CpuConcolicValues
            (ConcolicEnum::CpuConcolicValue(a), ConcolicEnum::CpuConcolicValue(b)) => {
                a.and(b).map(ConcolicEnum::CpuConcolicValue)
            },
            // AND operation between CpuConcolicValue and MemoryConcolicValue, and vice versa
            (ConcolicEnum::CpuConcolicValue(a), ConcolicEnum::MemoryConcolicValue(b)) => {
                a.and_with_memory(b)
            },
            (ConcolicEnum::MemoryConcolicValue(a), ConcolicEnum::CpuConcolicValue(b)) => {
                a.and_with_cpu(b)
            },
            // AND operation between two MemoryConcolicValues
            (ConcolicEnum::MemoryConcolicValue(a), ConcolicEnum::MemoryConcolicValue(b)) => {
                a.and(b).map(ConcolicEnum::MemoryConcolicValue)
            },
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
                b.or_with_var(a).map_err(|_| "Failed OR operation between CpuConcolicValue and ConcolicVar")
            },
            (ConcolicEnum::CpuConcolicValue(b), ConcolicEnum::ConcolicVar(a)) => {
                b.or_with_var(a).map_err(|_| "Failed OR operation between CpuConcolicValue and ConcolicVar")
            },
            // OR operation between ConcolicVar and MemoryConcolicValue, handling both orderings
            (ConcolicEnum::ConcolicVar(a), ConcolicEnum::MemoryConcolicValue(b)) => {
                b.or_with_var(a).map_err(|_| "Failed OR operation between MemoryConcolicValue and ConcolicVar")
            },
            (ConcolicEnum::MemoryConcolicValue(b), ConcolicEnum::ConcolicVar(a)) => {
                b.or_with_var(a).map_err(|_| "Failed OR operation between MemoryConcolicValue and ConcolicVar")
            },
            // OR operation between two CpuConcolicValues
            (ConcolicEnum::CpuConcolicValue(a), ConcolicEnum::CpuConcolicValue(b)) => {
                a.or(b).map(ConcolicEnum::CpuConcolicValue)
            },
            // OR operation between CpuConcolicValue and MemoryConcolicValue, and vice versa
            (ConcolicEnum::CpuConcolicValue(a), ConcolicEnum::MemoryConcolicValue(b)) => {
                a.or_with_memory(b)
            },
            (ConcolicEnum::MemoryConcolicValue(a), ConcolicEnum::CpuConcolicValue(b)) => {
                a.or_with_cpu(b)
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
