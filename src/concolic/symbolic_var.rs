// SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

use crate::state::function_signatures::TypeDesc;
use crate::state::simplify_z3::{bool_to_bv_smart, bv_to_bool_smart};
use regex::Regex;
use z3::ast::{Ast, Bool, Float, Int, BV};
use z3::Context;
use z3_sys::Z3_ast;

#[derive(Clone, Debug, PartialEq)]
pub enum SymbolicVar<'ctx> {
    Int(BV<'ctx>),
    LargeInt(Vec<BV<'ctx>>),
    Float(Float<'ctx>),
    Bool(Bool<'ctx>),
    Slice(SliceSymbolic<'ctx>), // ptr-len-cap
}

#[derive(Clone, Debug, PartialEq)]
pub struct SliceSymbolic<'ctx> {
    pub name: String,
    pub pointer: BV<'ctx>,  // base pointer
    pub length: BV<'ctx>,   // len
    pub capacity: BV<'ctx>, // cap   ← NEW
    pub element_type: TypeDesc,
    pub elements: Vec<SymbolicVar<'ctx>>, // optional materialised elems
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

    /// Creates a symbolic value for any TypeDesc, including nested slices/arrays like `[][32]byte`.
    pub fn make_symbolic_value(
        ctx: &'ctx Context,
        name: &str,
        typ: &TypeDesc,
    ) -> SymbolicVar<'ctx> {
        // default # of elements to populate for dynamic slices
        const DEFAULT_SLICE_LEN: usize = 3;

        let result = match typ {
            // Go aliases: 'byte' is an alias for 'uint8', and some DWARF toolchains
            // surface it as 'uint8'. Treat all of them as integer-like here.
            TypeDesc::Primitive(s)
                if s == "int" || s == "uintptr" || s == "byte" || s == "uint8" =>
            {
                println!(
                    "Retrieved integer argument '{}' – creating a 64-bit symbolic integer variable...",
                    name
                );
                SymbolicVar::Int(BV::fresh_const(ctx, name, 64))
            }

            TypeDesc::Primitive(s) if s == "bool" => {
                println!(
                    "Retrieved boolean argument '{}' – creating a symbolic boolean variable...",
                    name
                );
                SymbolicVar::Bool(Bool::fresh_const(ctx, name))
            }

            TypeDesc::Primitive(s) if s == "float64" => {
                println!(
                    "Retrieved float64 argument '{}' – creating a symbolic float64 variable...",
                    name
                );
                SymbolicVar::Float(Float::new_const(ctx, name, 11, 53))
            }

            // Go strings are 16 bytes: ptr (8 bytes) + len (8 bytes)
            // We model them as a 128-bit LargeInt with two 64-bit components
            TypeDesc::Primitive(s) if s == "string" => {
                println!(
                    "Retrieved string argument '{}' – creating symbolic Go string (ptr + len)...",
                    name
                );
                let ptr_bv = BV::fresh_const(ctx, &format!("{}__ptr", name), 64);
                let len_bv = BV::fresh_const(ctx, &format!("{}__len", name), 64);
                // Store as LargeInt: [ptr, len] (little-endian order in memory)
                SymbolicVar::LargeInt(vec![ptr_bv, len_bv])
            }

            TypeDesc::Pointer { .. } => {
                // model pointers as 64-bit bitvectors
                println!(
                    "Retrieved pointer argument '{}' – creating a 64-bit symbolic pointer variable...",
                    name
                );
                SymbolicVar::Int(BV::fresh_const(ctx, name, 64))
            }

            TypeDesc::Array { element, count } => {
                // a fixed-size array or even a Go static array like [32]byte
                let len = count.map(|n| n as usize).unwrap_or(DEFAULT_SLICE_LEN);
                println!(
                    "Retrieved array argument '{}' – creating a symbolic slice view with element type {:?} and length {}...",
                    name, element, len
                );
                SymbolicVar::make_symbolic_slice(ctx, name, element, len)
            }

            TypeDesc::Unknown(s) if s.starts_with("[]") => {
                // covers raw Go slices: []T, and nested like [][32]byte
                let inner = &s[2..];

                // if the inner is a fixed-size array, e.g. "[32]byte"
                if let Some(caps) = Regex::new(r"^\[(\d+)\](.+)$").unwrap().captures(inner) {
                    let fixed_len = caps[1].parse::<usize>().unwrap_or(DEFAULT_SLICE_LEN);
                    let elem_ty_str = caps[2].trim();

                    // Create a proper TypeDesc for the fixed-size array element
                    let elem_type = TypeDesc::Array {
                        element: Box::new(TypeDesc::Primitive(elem_ty_str.to_string())),
                        count: Some(fixed_len as u64),
                    };

                    println!(
                        "Retrieved slice argument '{}' with fixed-size element [{}]{} – creating a symbolic slice of {} element(s)...",
                        name,
                        fixed_len,
                        elem_ty_str,
                        DEFAULT_SLICE_LEN
                    );
                    SymbolicVar::make_symbolic_slice(ctx, name, &elem_type, DEFAULT_SLICE_LEN)
                } else {
                    // simple dynamic slice, e.g. []int or []string
                    let elem_type = TypeDesc::Primitive(inner.to_string());
                    println!(
                        "Retrieved dynamic slice argument '{}' with element type {} – creating a symbolic slice of {} element(s)...",
                        name,
                        inner,
                        DEFAULT_SLICE_LEN
                    );
                    SymbolicVar::make_symbolic_slice(ctx, name, &elem_type, DEFAULT_SLICE_LEN)
                }
            }

            _ => {
                println!(
                    "[WARNING]: Could not identify precise type of argument '{}'. Falling back to a 64-bit symbolic integer for type {:?}.",
                    name, typ
                );
                // fallback for everything else
                SymbolicVar::Int(BV::fresh_const(ctx, name, 64))
            }
        };

        // Log the final result
        // match &result {
        //     SymbolicVar::Slice(slice) => {
        //         println!("DEBUG: Created slice '{}' with:", slice.name);
        //         println!("  - pointer: {:?}", slice.pointer);
        //         println!("  - length: {:?}", slice.length);
        //         println!("  - element_type: {:?}", slice.element_type);
        //         println!("  - elements count: {}", slice.elements.len());
        //         for (i, elem) in slice.elements.iter().enumerate() {
        //             println!("  - element[{}]: {:?}", i, elem);
        //         }
        //     }
        //     _ => {
        //         println!("DEBUG: Created non-slice symbolic var: {:?}", result);
        //     }
        // }

        result
    }

    /// Create a SliceSymbolic: pointer+length BVs plus a few initial elements.
    pub fn make_symbolic_slice(
        ctx: &'ctx Context,
        name: &str,
        element_type: &TypeDesc,
        default_len: usize,
    ) -> SymbolicVar<'ctx> {
        println!(
            "Retrieved slice argument '{}' – creating a symbolic slice of {} element(s) with element type {:?}...",
            name, default_len, element_type
        );

        let pointer = BV::fresh_const(ctx, &format!("{name}_ptr"), 64);
        let length = BV::fresh_const(ctx, &format!("{name}_len"), 64);
        let capacity = BV::fresh_const(ctx, &format!("{name}_cap"), 64);

        let mut elements = Vec::with_capacity(default_len);
        for i in 0..default_len {
            let elem = SymbolicVar::make_symbolic_value(ctx, &format!("{name}[{i}]"), element_type);
            elements.push(elem);
        }

        SymbolicVar::Slice(SliceSymbolic {
            name: name.to_string(),
            pointer,
            length,
            capacity,
            element_type: element_type.clone(),
            elements,
        })
    }

    /// Helper function to print detailed information about a SymbolicVar
    pub fn debug_print(&self, prefix: &str) {
        match self {
            SymbolicVar::Int(bv) => {
                println!("{}Int: {:?}", prefix, bv);
            }
            SymbolicVar::LargeInt(bvs) => {
                println!("{}LargeInt with {} parts:", prefix, bvs.len());
                for (i, bv) in bvs.iter().enumerate() {
                    println!("{}  [{}]: {:?}", prefix, i, bv);
                }
            }
            SymbolicVar::Float(f) => {
                println!("{}Float: {:?}", prefix, f);
            }
            SymbolicVar::Bool(b) => {
                println!("{}Bool: {:?}", prefix, b);
            }
            SymbolicVar::Slice(slice) => {
                println!("{}Slice '{}':", prefix, slice.name);
                println!("{}  pointer: {:?}", prefix, slice.pointer);
                println!("{}  length: {:?}", prefix, slice.length);
                println!("{}  element_type: {:?}", prefix, slice.element_type);
                println!("{}  elements ({}):", prefix, slice.elements.len());
                for (i, elem) in slice.elements.iter().enumerate() {
                    elem.debug_print(&format!("{}    [{}] ", prefix, i));
                }
            }
        }
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
            }
            SymbolicVar::LargeInt(vec) => {
                let ctx = vec
                    .first()
                    .expect("LargeInt vector should not be empty")
                    .get_ctx();
                let mut count = BV::from_u64(ctx, 0, vec.first().unwrap().get_size());
                for bv in vec {
                    for i in 0..bv.get_size() {
                        let bit = bv.extract(i, i);
                        count = count.bvadd(&bit.zero_ext(bv.get_size() - 1));
                    }
                }
                count
            }
            SymbolicVar::Bool(bool_val) => {
                // Popcount for booleans: true is 1, false is 0
                let count = if bool_val.as_bool().unwrap() {
                    BV::from_u64(bool_val.get_ctx(), 1, 1)
                } else {
                    BV::from_u64(bool_val.get_ctx(), 0, 1)
                };
                // Since a boolean has size 1, we don't need to extend the result
                count
            }
            SymbolicVar::Float(_) => panic!("Popcount is not defined for floating-point values"),
            SymbolicVar::Slice(slice_symbolic) => {
                // For slices, we can only popcount the elements if they are integers
                let mut count = BV::from_u64(slice_symbolic.pointer.get_ctx(), 0, 64);
                for elem in &slice_symbolic.elements {
                    count = count.bvadd(&elem.popcount());
                }
                count
            }
        }
    }

    // Method to extract a sub-bitvector from a symbolic integer variable
    pub fn extract(&self, high: u32, low: u32) -> Result<SymbolicVar<'ctx>, &'static str> {
        match self {
            SymbolicVar::Int(bv) => Ok(SymbolicVar::Int(bv.extract(high, low))),
            SymbolicVar::LargeInt(vec) => Ok(SymbolicVar::LargeInt(
                vec.iter().map(|bv| bv.extract(high, low)).collect(),
            )),
            SymbolicVar::Float(_) => Err("Extract on float"),
            SymbolicVar::Bool(_) => Err("Extract on bool"),
            SymbolicVar::Slice(s) => match &s.element_type {
                TypeDesc::Primitive(t) if t == "int" || t == "byte" => {
                    let elems = s
                        .elements
                        .iter()
                        .map(|e| e.extract(high, low))
                        .collect::<Result<Vec<_>, _>>()?;
                    Ok(SymbolicVar::Slice(SliceSymbolic {
                        name: s.name.clone(),
                        pointer: s.pointer.clone(),
                        length: s.length.clone(),
                        capacity: s.capacity.clone(),
                        element_type: s.element_type.clone(),
                        elements: elems,
                    }))
                }
                _ => Err("Extract only for int/byte slices"),
            },
        }
    }

    // Simplifies the symbolic variable, returning a new simplified symbolic value
    pub fn simplify(&self) -> SymbolicVar<'ctx> {
        match self {
            SymbolicVar::Int(bv) => SymbolicVar::Int(bv.simplify()),
            SymbolicVar::LargeInt(vec) => {
                SymbolicVar::LargeInt(vec.iter().map(|bv| bv.simplify()).collect())
            }
            SymbolicVar::Float(f) => SymbolicVar::Float(f.simplify()),
            SymbolicVar::Bool(b) => SymbolicVar::Bool(b.simplify()),
            SymbolicVar::Slice(s) => SymbolicVar::Slice(SliceSymbolic {
                name: s.name.clone(),
                pointer: s.pointer.clone(),
                length: s.length.clone(),
                capacity: s.capacity.clone(),
                element_type: s.element_type.clone(),
                elements: s.elements.iter().map(|e| e.simplify()).collect(),
            }),
        }
    }

    // Method to check if two symbolic variables are equal
    pub fn equal(&self, other: &SymbolicVar<'ctx>) -> bool {
        match (self, other) {
            (SymbolicVar::Int(a), SymbolicVar::Int(b)) => a.eq(&b),
            (SymbolicVar::LargeInt(a), SymbolicVar::LargeInt(b)) => {
                a.iter().zip(b.iter()).all(|(x, y)| x.eq(y))
            }
            (SymbolicVar::Float(a), SymbolicVar::Float(b)) => a.eq(&b),
            _ => false, //TODO: Handle other types like Bool and Slice if needed
        }
    }

    pub fn to_string(&self) -> String {
        match self {
            SymbolicVar::Int(bv) => bv.to_string(),
            SymbolicVar::LargeInt(vec) => vec
                .iter()
                .map(|bv| bv.to_string())
                .collect::<Vec<_>>()
                .join("|"),
            SymbolicVar::Float(f) => f.to_string(),
            SymbolicVar::Bool(b) => b.to_string(),
            SymbolicVar::Slice(slice_symbolic) => {
                let elements_str = slice_symbolic
                    .elements
                    .iter()
                    .map(|elem| elem.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                format!(
                    "Slice({}, {}, [{}])",
                    slice_symbolic.pointer, slice_symbolic.length, elements_str
                )
            }
        }
    }

    pub fn to_largebv(&self) -> Vec<BV<'ctx>> {
        match self {
            SymbolicVar::Int(bv) => vec![bv.clone()],
            SymbolicVar::LargeInt(vec) => vec.clone(),
            SymbolicVar::Float(_) => {
                panic!("Cannot convert a floating-point symbolic variable to a large bit vector")
            }
            SymbolicVar::Bool(b) => {
                let one = BV::from_u64(b.get_ctx(), 1, 1);
                let zero = BV::from_u64(b.get_ctx(), 0, 1);
                vec![b.ite(&one, &zero)] // If `b` is true, return `one`, otherwise return `zero`
            }
            SymbolicVar::Slice(slice_symbolic) => {
                // For slices, we can only convert if the element type is an integer
                if let TypeDesc::Primitive(s) = &slice_symbolic.element_type {
                    if s == "int" || s == "byte" {
                        slice_symbolic
                            .elements
                            .iter()
                            .map(|elem| elem.to_bv(slice_symbolic.pointer.get_ctx()))
                            .collect()
                    } else {
                        panic!(
                            "Cannot convert slice with non-integer elements to large bit vector"
                        );
                    }
                } else {
                    panic!("Cannot convert slice with non-integer elements to large bit vector");
                }
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
                bv.bvugt(&zero) // Returns Bool directly
            }
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
            }
            SymbolicVar::Float(_) => {
                panic!("Cannot convert a floating-point symbolic variable to a boolean")
            }
            SymbolicVar::Slice(slice_symbolic) => {
                // For slices, we can only convert if the element type is an integer
                if let TypeDesc::Primitive(s) = &slice_symbolic.element_type {
                    if s == "int" || s == "byte" {
                        let zero = BV::from_u64(slice_symbolic.pointer.get_ctx(), 0, 1);
                        let ctx = slice_symbolic.pointer.get_ctx();
                        let bools: Vec<Bool<'ctx>> = slice_symbolic
                            .elements
                            .iter()
                            .map(|elem| elem.to_bv(ctx).bvugt(&zero))
                            .collect();
                        if bools.is_empty() {
                            Bool::from_bool(ctx, false)
                        } else {
                            Bool::or(ctx, &bools.iter().collect::<Vec<_>>())
                        }
                    } else {
                        panic!("Cannot convert slice with non-integer elements to boolean");
                    }
                } else {
                    panic!("Cannot convert slice with non-integer elements to boolean");
                }
            }
        }
    }

    // Fixed to_bv method
    pub fn to_bv(&self, ctx: &'ctx Context) -> BV<'ctx> {
        match self {
            SymbolicVar::Int(bv) => bv.clone(),
            SymbolicVar::LargeInt(vec) => {
                // Concatenate the BVs in the vector to form a single BV
                let mut bv_iter = vec.iter().rev();
                let first_bv = bv_iter
                    .next()
                    .expect("LargeInt should not be empty")
                    .clone();
                bv_iter.fold(first_bv, |acc, bv| acc.concat(&bv.clone()))
            }
            SymbolicVar::Float(_f) => {
                // NOTE: Floats should be stored as their IEEE 754 bit patterns (as integers)
                // in registers and memory, not as Float symbolic types.
                panic!(
                    "Cannot convert Float symbolic variable to bitvector. \
                    Floats should be stored as bit patterns (integers) in registers/memory. \
                    This indicates a bug in a float operation handler."
                )
            }
            SymbolicVar::Bool(b) => {
                // For storage operations, preserve symbolic info using ite
                let one = BV::from_u64(ctx, 1, 8); // Use 8-bit for compatibility
                let zero = BV::from_u64(ctx, 0, 8);
                b.ite(&one, &zero)
            }
            SymbolicVar::Slice(slice_symbolic) => {
                // For slices, we can only convert if the element type is an integer
                if let TypeDesc::Primitive(s) = &slice_symbolic.element_type {
                    if s == "int" || s == "byte" {
                        let mut bv_iter = slice_symbolic.elements.iter().rev();
                        let first_bv = bv_iter
                            .next()
                            .expect("Slice should not be empty")
                            .to_bv(ctx);
                        bv_iter.fold(first_bv, |acc, bv| acc.concat(&bv.to_bv(ctx)))
                    } else {
                        panic!("Cannot convert slice with non-integer elements to bit vector");
                    }
                } else {
                    panic!("Cannot convert slice with non-integer elements to bit vector");
                }
            }
        }
    }

    // Convert the symbolic variable to a bit vector based on the concrete value to avaoid using ITE
    pub fn to_bv_with_concrete(
        &self,
        ctx: &'ctx Context,
        concrete_value: u64,
        target_size: u32,
    ) -> BV<'ctx> {
        match self {
            SymbolicVar::Bool(_) => {
                // Use concrete value to avoid ITE
                let concrete_bool = concrete_value != 0;
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
            SymbolicVar::LargeInt(vec) => {
                let mut bv_iter = vec.iter().rev();
                let first_bv = bv_iter
                    .next()
                    .expect("LargeInt should not be empty")
                    .clone();
                let combined = bv_iter.fold(first_bv, |acc, bv| acc.concat(&bv.clone()));

                if combined.get_size() == target_size {
                    combined
                } else if combined.get_size() > target_size {
                    combined.extract(target_size - 1, 0)
                } else {
                    combined.zero_ext(target_size - combined.get_size())
                }
            }
            SymbolicVar::Float(_) => {
                // For float operations in integer context, use concrete bit representation
                BV::from_u64(ctx, concrete_value, target_size)
            }
            SymbolicVar::Slice(slice) => {
                // For slice operations in integer context, use the pointer value
                if slice.pointer.get_size() == target_size {
                    slice.pointer.clone()
                } else if slice.pointer.get_size() > target_size {
                    slice.pointer.extract(target_size - 1, 0)
                } else {
                    slice
                        .pointer
                        .zero_ext(target_size - slice.pointer.get_size())
                }
            }
        }
    }

    // Add new method that handles Bool with concrete context
    pub fn to_bv_of_size_with_concrete(
        &self,
        ctx: &'ctx Context,
        size: u32,
        concrete_value: u64,
    ) -> BV<'ctx> {
        match self {
            SymbolicVar::Bool(_) => {
                // Use concrete value to avoid ITE
                let concrete_bool = concrete_value != 0;
                if concrete_bool {
                    BV::from_u64(ctx, 1, size)
                } else {
                    BV::from_u64(ctx, 0, size)
                }
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
                let mut bv_iter = bv_vec.iter().rev();
                let first_bv = bv_iter
                    .next()
                    .expect("LargeInt should not be empty")
                    .clone();

                let result_bv = bv_iter.fold(first_bv, |acc, bv| acc.concat(&bv.clone()));

                if result_bv.get_size() > size {
                    result_bv.extract(size - 1, 0)
                } else {
                    result_bv.zero_ext(size - result_bv.get_size())
                }
            }
            _ => panic!("Unsupported symbolic type for to_bv_of_size_with_concrete"),
        }
    }

    /// Convert to Bool while preserving symbolic information using AST inspection
    pub fn to_bool_ast_smart(&self) -> Bool<'ctx> {
        match self {
            SymbolicVar::Bool(b) => b.clone(),
            SymbolicVar::Int(bv) => bv_to_bool_smart(bv),
            _ => self.to_bool(), // Fallback to existing implementation
        }
    }

    /// Convert to BV while preserving symbolic information using AST inspection
    pub fn to_bv_ast_smart(&self, ctx: &'ctx Context, target_size: u32) -> BV<'ctx> {
        match self {
            SymbolicVar::Bool(b) => bool_to_bv_smart(b, target_size),
            SymbolicVar::Int(bv) => {
                if bv.get_size() == target_size {
                    bv.clone()
                } else if bv.get_size() > target_size {
                    bv.extract(target_size - 1, 0)
                } else {
                    bv.zero_ext(target_size - bv.get_size())
                }
            }
            _ => self.to_bv_with_concrete(ctx, 0, target_size), // Fallback
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
            SymbolicVar::Slice(slice_symbolic) => {
                // For slices, we can return the AST of the pointer or length, or a combination
                let pointer_ast = slice_symbolic.pointer.get_z3_ast();
                pointer_ast // Returning pointer AST for simplicity
            }
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
            SymbolicVar::Slice(slice_symbolic) => slice_symbolic.pointer.get_ctx(),
        }
    }

    pub fn get_size(&self) -> u32 {
        match self {
            SymbolicVar::Int(bv) => bv.get_size(),
            SymbolicVar::LargeInt(vec) => vec.iter().map(|bv| bv.get_size()).sum(),
            SymbolicVar::Float(_) => 64,
            SymbolicVar::Bool(_) => 1,
            SymbolicVar::Slice(slice_symbolic) => slice_symbolic.length.get_size(),
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
            SymbolicVar::LargeInt(_) => {
                Err("Conversion to integer is not supported for large integers symbolic variables")
            }
            SymbolicVar::Float(_) => {
                Err("Conversion to integer is not supported for floating-point symbolic variables")
            }
            SymbolicVar::Bool(_) => {
                Err("Conversion to integer is not supported for boolean symbolic variables")
            }
            SymbolicVar::Slice(slice_symbolic) => {
                // For slices, we can only convert if the element type is an integer
                if let TypeDesc::Primitive(s) = &slice_symbolic.element_type {
                    if s == "int" || s == "byte" {
                        let ctx = slice_symbolic.pointer.get_ctx();
                        let elements_int: Vec<Int<'ctx>> = slice_symbolic
                            .elements
                            .iter()
                            .map(|elem| elem.to_bv(ctx).to_int(false))
                            .collect();
                        Ok(elements_int[0].clone()) // Simplified: return first element as Int
                    } else {
                        Err("Cannot convert slice with non-integer elements to integer")
                    }
                } else {
                    Err("Cannot convert slice with non-integer elements to integer")
                }
            }
        }
    }
}
