// SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

use super::{concrete_var::VarError, ConcolicVar, ConcreteVar, SymbolicVar};
use crate::state::{cpu_state::CpuConcolicValue, memory_x86_64::MemoryValue};
use z3::{
    ast::{Ast, Bool, BV},
    Context,
};

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

    // FIX: Retrieve the concrete value of the concolic variable properly handling LargeInt
    pub fn get_concrete_value(&self) -> u64 {
        match self {
            ConcolicEnum::ConcolicVar(var) => {
                // Handle LargeInt properly
                match &var.concrete {
                    ConcreteVar::LargeInt(values) => {
                        // For LargeInt, we need to return a meaningful representation
                        // For immediate compatibility, return the first chunk
                        // But we should also provide a method to get the full value
                        if values.is_empty() {
                            0u64
                        } else {
                            values[0] // Return first chunk for backward compatibility
                        }
                    }
                    _ => var.concrete.to_u64(),
                }
            }
            ConcolicEnum::CpuConcolicValue(cpu) => match &cpu.concrete {
                ConcreteVar::LargeInt(values) => {
                    if values.is_empty() {
                        0u64
                    } else {
                        values[0]
                    }
                }
                _ => cpu.concrete.to_u64(),
            },
            ConcolicEnum::MemoryValue(mem) => mem.concrete,
        }
    }

    // NEW: Get the full concrete value for LargeInt types
    pub fn get_full_concrete_value(&self) -> ConcreteVar {
        match self {
            ConcolicEnum::ConcolicVar(var) => var.concrete.clone(),
            ConcolicEnum::CpuConcolicValue(cpu) => cpu.concrete.clone(),
            ConcolicEnum::MemoryValue(mem) => ConcreteVar::Int(mem.concrete),
        }
    }

    // NEW: Get combined concrete value for multi-chunk data
    pub fn get_combined_concrete_value(&self, total_bits: u32) -> u64 {
        match self {
            ConcolicEnum::ConcolicVar(var) => match &var.concrete {
                ConcreteVar::LargeInt(values) => Self::combine_largeint_chunks(values, total_bits),
                _ => var.concrete.to_u64(),
            },
            ConcolicEnum::CpuConcolicValue(cpu) => match &cpu.concrete {
                ConcreteVar::LargeInt(values) => Self::combine_largeint_chunks(values, total_bits),
                _ => cpu.concrete.to_u64(),
            },
            ConcolicEnum::MemoryValue(mem) => mem.concrete,
        }
    }

    // Helper function to combine LargeInt chunks
    fn combine_largeint_chunks(values: &[u64], total_bits: u32) -> u64 {
        if values.is_empty() {
            return 0;
        }

        if values.len() == 1 || total_bits <= 64 {
            return values[0];
        }

        // For your specific case with slice headers:
        // values[0] = ptr (first 64 bits)
        // values[1] = len (second 64 bits)
        //
        // For 128-bit values, we might want to prioritize the most significant data
        // or combine them in a meaningful way depending on use case

        // For immediate fix, return the most significant non-zero chunk
        // or a combination that preserves important information
        for &chunk in values.iter().rev() {
            if chunk != 0 {
                return chunk;
            }
        }

        values[0] // Fallback to first chunk
    }

    pub fn get_concrete_value_signed(&self) -> Result<i64, VarError> {
        match self {
            ConcolicEnum::ConcolicVar(var) => match &var.concrete {
                ConcreteVar::LargeInt(values) => {
                    if values.is_empty() {
                        Ok(0i64)
                    } else {
                        Ok(values[0] as i64)
                    }
                }
                _ => var.concrete.to_i64().map_err(|_| VarError::ConversionError),
            },
            ConcolicEnum::CpuConcolicValue(cpu) => match &cpu.concrete {
                ConcreteVar::LargeInt(values) => {
                    if values.is_empty() {
                        Ok(0i64)
                    } else {
                        Ok(values[0] as i64)
                    }
                }
                _ => cpu.concrete.to_i64().map_err(|_| VarError::ConversionError),
            },
            ConcolicEnum::MemoryValue(mem) => Ok(mem.concrete as i64),
        }
    }

    // Retrieve the symbolic value of the concolic variable
    pub fn get_symbolic_value_bv(&self, ctx: &'ctx Context) -> BV<'ctx> {
        match self {
            ConcolicEnum::ConcolicVar(var) => {
                // Handle Bool conversion safely
                match &var.symbolic {
                    SymbolicVar::Bool(_) => {
                        // Use concrete value to avoid ITE
                        let concrete_bool = match &var.concrete {
                            ConcreteVar::LargeInt(values) => !values.is_empty() && values[0] != 0,
                            _ => var.concrete.to_u64() != 0,
                        };
                        if concrete_bool {
                            BV::from_u64(ctx, 1, 8) // Default to 8-bit size
                        } else {
                            BV::from_u64(ctx, 0, 8)
                        }
                    }
                    _ => var.symbolic.to_bv(ctx),
                }
            }
            ConcolicEnum::CpuConcolicValue(cpu) => {
                // Handle Bool conversion safely
                match &cpu.symbolic {
                    SymbolicVar::Bool(_) => {
                        // Use concrete value to avoid ITE
                        let concrete_bool = match &cpu.concrete {
                            ConcreteVar::LargeInt(values) => !values.is_empty() && values[0] != 0,
                            _ => cpu.concrete.to_u64() != 0,
                        };
                        if concrete_bool {
                            BV::from_u64(ctx, 1, 8) // Default to 8-bit size
                        } else {
                            BV::from_u64(ctx, 0, 8)
                        }
                    }
                    _ => cpu.symbolic.to_bv(ctx),
                }
            }
            ConcolicEnum::MemoryValue(mem) => mem.symbolic.clone(),
        }
    }

    pub fn get_symbolic_value_bv_sized(&self, ctx: &'ctx Context, target_size: u32) -> BV<'ctx> {
        match self {
            ConcolicEnum::ConcolicVar(var) => {
                match &var.symbolic {
                    SymbolicVar::Bool(_) => {
                        // Use concrete value to avoid ITE
                        let concrete_bool = match &var.concrete {
                            ConcreteVar::LargeInt(values) => !values.is_empty() && values[0] != 0,
                            _ => var.concrete.to_u64() != 0,
                        };
                        if concrete_bool {
                            BV::from_u64(ctx, 1, target_size)
                        } else {
                            BV::from_u64(ctx, 0, target_size)
                        }
                    }
                    SymbolicVar::Int(bv) => {
                        // Resize BV to target size
                        if bv.get_size() == target_size {
                            bv.clone()
                        } else if bv.get_size() > target_size {
                            bv.extract(target_size - 1, 0)
                        } else {
                            bv.zero_ext(target_size - bv.get_size())
                        }
                    }
                    _ => {
                        // For other types, use the with_concrete method
                        let concrete_val = match &var.concrete {
                            ConcreteVar::LargeInt(values) => {
                                if values.is_empty() {
                                    0
                                } else {
                                    values[0]
                                }
                            }
                            _ => var.concrete.to_u64(),
                        };
                        var.symbolic
                            .to_bv_with_concrete(ctx, concrete_val, target_size)
                    }
                }
            }
            ConcolicEnum::CpuConcolicValue(cpu) => match &cpu.symbolic {
                SymbolicVar::Bool(_) => {
                    let concrete_bool = match &cpu.concrete {
                        ConcreteVar::LargeInt(values) => !values.is_empty() && values[0] != 0,
                        _ => cpu.concrete.to_u64() != 0,
                    };
                    if concrete_bool {
                        BV::from_u64(ctx, 1, target_size)
                    } else {
                        BV::from_u64(ctx, 0, target_size)
                    }
                }
                SymbolicVar::Int(bv) => {
                    if bv.get_size() == target_size {
                        bv.clone()
                    } else if bv.get_size() > target_size {
                        bv.extract(target_size - 1, 0)
                    } else {
                        bv.zero_ext(target_size - bv.get_size())
                    }
                }
                _ => {
                    let concrete_val = match &cpu.concrete {
                        ConcreteVar::LargeInt(values) => {
                            if values.is_empty() {
                                0
                            } else {
                                values[0]
                            }
                        }
                        _ => cpu.concrete.to_u64(),
                    };
                    cpu.symbolic
                        .to_bv_with_concrete(ctx, concrete_val, target_size)
                }
            },
            ConcolicEnum::MemoryValue(mem) => {
                if mem.symbolic.get_size() == target_size {
                    mem.symbolic.clone()
                } else if mem.symbolic.get_size() > target_size {
                    mem.symbolic.extract(target_size - 1, 0)
                } else {
                    mem.symbolic.zero_ext(target_size - mem.symbolic.get_size())
                }
            }
        }
    }

    pub fn get_symbolic_value_bool(&self) -> Bool<'ctx> {
        match self {
            ConcolicEnum::ConcolicVar(var) => var.symbolic.to_bool(),
            ConcolicEnum::CpuConcolicValue(cpu) => cpu.symbolic.to_bool(),
            ConcolicEnum::MemoryValue(mem_value) => {
                mem_value
                    .symbolic
                    ._eq(&BV::from_u64(mem_value.symbolic.get_ctx(), 1, 1))
            }
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
            ConcolicEnum::ConcolicVar(var) => match &var.concrete {
                ConcreteVar::LargeInt(values) => {
                    if values.is_empty() {
                        0
                    } else {
                        values[0]
                    }
                }
                _ => var.concrete.to_u64(),
            },
            ConcolicEnum::CpuConcolicValue(cpu_var) => match &cpu_var.concrete {
                ConcreteVar::LargeInt(values) => {
                    if values.is_empty() {
                        0
                    } else {
                        values[0]
                    }
                }
                _ => cpu_var.concrete.to_u64(),
            },
            ConcolicEnum::MemoryValue(mem_var) => mem_var.concrete,
        }
    }

    pub fn to_bool(&self) -> bool {
        match self {
            ConcolicEnum::ConcolicVar(var) => match &var.concrete {
                ConcreteVar::LargeInt(values) => {
                    !values.is_empty() && values.iter().any(|&v| v != 0)
                }
                _ => var.concrete.to_bool(),
            },
            ConcolicEnum::CpuConcolicValue(cpu_var) => match &cpu_var.concrete {
                ConcreteVar::LargeInt(values) => {
                    !values.is_empty() && values.iter().any(|&v| v != 0)
                }
                _ => cpu_var.concrete.to_bool(),
            },
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
