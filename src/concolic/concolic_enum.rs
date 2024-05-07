use crate::state::{cpu_state::CpuConcolicValue, memory_x86_64::MemoryConcolicValue};

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
}
