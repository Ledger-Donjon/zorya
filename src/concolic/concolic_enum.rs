use crate::state::{cpu_state::CpuConcolicValue, memory_x86_64::MemoryValue};
use z3::{ast::{Ast, Bool, BV}, Context};
use super::{ConcolicVar, ConcreteVar, SymbolicVar};


#[derive(Clone, Debug)]
pub enum ConcolicEnum<'ctx> {
    ConcolicVar(ConcolicVar<'ctx>),
    CpuConcolicValue(CpuConcolicValue<'ctx>),
    MemoryValue(MemoryValue<'ctx>),
}

impl<'ctx> ConcolicEnum<'ctx> {

    pub fn is_bool(&self) -> bool {
        match self {
            ConcolicEnum::ConcolicVar(var) => var.concrete.is_bool(),
            ConcolicEnum::CpuConcolicValue(cpu_var) => cpu_var.concrete.is_bool(),
            ConcolicEnum::MemoryValue(mem_value) => mem_value.size == 1,
        }
    }

    // Retrieve the concrete value of the concolic variable
    pub fn get_concrete_value(&self) -> u64 {
        match self {
            ConcolicEnum::ConcolicVar(var) => var.concrete.to_u64(),
            ConcolicEnum::CpuConcolicValue(cpu) => cpu.concrete.to_u64(), 
            ConcolicEnum::MemoryValue(mem) => mem.concrete, 
        }
    }

    // Retrieve the symbolic value of the concolic variable
    pub fn get_symbolic_value_bv(&self, ctx: &'ctx Context) -> BV<'ctx> {
        match self {
            ConcolicEnum::ConcolicVar(var) => var.symbolic.to_bv(ctx),
            ConcolicEnum::CpuConcolicValue(cpu) => cpu.symbolic.to_bv(ctx),
            ConcolicEnum::MemoryValue(mem) => mem.symbolic.clone(),
        }
    }

    pub fn get_symbolic_value_bool(&self) -> Bool<'ctx> {
        match self {
            ConcolicEnum::ConcolicVar(var) => var.symbolic.to_bool(),
            ConcolicEnum::CpuConcolicValue(cpu) => cpu.symbolic.to_bool(),
            ConcolicEnum::MemoryValue(mem_value) => mem_value.symbolic._eq(&BV::from_u64(mem_value.symbolic.get_ctx(), 1, 1)),
        }
    }

    // Retrieve the size of the concolic variable
    pub fn get_size(&self) -> u32 {
        match self {
            ConcolicEnum::ConcolicVar(var) => var.concrete.get_size(),
            ConcolicEnum::CpuConcolicValue(cpu) => cpu.concrete.get_size(),
            ConcolicEnum::MemoryValue(mem_value) => mem_value.size,
        }
    }

    // Convert the concolic enum to a concolic variable
    pub fn to_concolic_var(&self) -> Option<ConcolicVar<'ctx>> {
        match self {
            ConcolicEnum::ConcolicVar(var) => Some(var.clone()),
            ConcolicEnum::CpuConcolicValue(cpu_var) => Some(ConcolicVar {
                concrete: cpu_var.concrete.clone(),
                symbolic: cpu_var.symbolic.clone(),
                ctx: cpu_var.ctx,
            }),
            ConcolicEnum::MemoryValue(mem_value) => Some(ConcolicVar {
                concrete: ConcreteVar::Int(mem_value.concrete),
                symbolic: SymbolicVar::Int(mem_value.symbolic.clone()),
                ctx: mem_value.symbolic.get_ctx(),
            }),
        }
    }

    pub fn to_u64(&self) -> u64 {
        match self {
            ConcolicEnum::ConcolicVar(var) => var.concrete.to_u64(),
            ConcolicEnum::CpuConcolicValue(cpu_var) => cpu_var.concrete.to_u64(),
            ConcolicEnum::MemoryValue(mem_var) => mem_var.concrete,
        }
    }

    pub fn to_bool(&self) -> bool {
        match self {
            ConcolicEnum::ConcolicVar(var) => var.concrete.to_bool(),
            ConcolicEnum::CpuConcolicValue(cpu_var) => cpu_var.concrete.to_bool(),
            ConcolicEnum::MemoryValue(mem_var) => mem_var.concrete == 1,
        }
    }

    pub fn to_bv(&self, ctx: &'ctx Context) -> BV<'ctx> {
        match self {
            ConcolicEnum::ConcolicVar(var) => var.symbolic.to_bv(ctx),
            ConcolicEnum::CpuConcolicValue(cpu_var) => cpu_var.symbolic.to_bv(ctx),
            ConcolicEnum::MemoryValue(mem_var) => mem_var.symbolic.clone(),
        }
    }
}
