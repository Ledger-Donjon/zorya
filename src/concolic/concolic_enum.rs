use crate::state::{cpu_state::CpuConcolicValue, memory_x86_64::MemoryConcolicValue};
use z3::{ast::{Bool, BV}, Context};
use super::ConcolicVar;


#[derive(Clone, Debug)]
pub enum ConcolicEnum<'ctx> {
    ConcolicVar(ConcolicVar<'ctx>),
    CpuConcolicValue(CpuConcolicValue<'ctx>),
    MemoryConcolicValue(MemoryConcolicValue<'ctx>),
}

impl<'ctx> ConcolicEnum<'ctx> {

    // Method to perform concolic subpiece operation
    pub fn concolic_subpiece(self, offset: usize, new_size: u32, ctx: &'ctx Context) -> Result<ConcolicEnum<'ctx>, &'static str> {
        match self {
            ConcolicEnum::ConcolicVar(var) => {
                var.truncate(offset, new_size, ctx).map(ConcolicEnum::ConcolicVar)
            },
            ConcolicEnum::CpuConcolicValue(cpu_var) => {
                cpu_var.truncate(offset, new_size, ctx).map(ConcolicEnum::CpuConcolicValue)
            },
            ConcolicEnum::MemoryConcolicValue(mem_var) => {
                mem_var.truncate(offset, new_size, ctx).map(ConcolicEnum::MemoryConcolicValue)
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

    // Retrieve the symbolic value of the concolic variable
    pub fn get_symbolic_value_bv(&self) -> BV<'ctx> {
        match self {
            ConcolicEnum::ConcolicVar(var) => var.symbolic.to_bv(),
            ConcolicEnum::CpuConcolicValue(cpu) => cpu.symbolic.to_bv(),
            ConcolicEnum::MemoryConcolicValue(mem) => mem.symbolic.to_bv(),
        }
    }

    // Retrieve the symbolic value of the concolic variable as a boolean
    pub fn get_symbolic_value_bool(&self) -> Bool<'ctx> {
        match self {
            ConcolicEnum::ConcolicVar(var) => var.symbolic.to_bool(),
            ConcolicEnum::CpuConcolicValue(cpu) => cpu.symbolic.to_bool(),
            ConcolicEnum::MemoryConcolicValue(mem) => mem.symbolic.to_bool(),
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
