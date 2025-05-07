//! src/state/function_signatures.rs

#![allow(non_upper_case_globals)]

use std::collections::HashMap;
use std::process::Command;
use std::{env, fs};
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::Path;


use gimli::{
    AttributeValue, DebuggingInformationEntry, Dwarf, EndianSlice, LittleEndian, Operation, Reader,
    Unit, DwTag,
    DW_AT_location, DW_AT_low_pc,
    DW_AT_name, DW_AT_type, DW_TAG_array_type, DW_TAG_base_type, DW_TAG_const_type,
    DW_TAG_formal_parameter, DW_TAG_member, DW_TAG_pointer_type,
    DW_TAG_restrict_type, DW_TAG_structure_type, DW_TAG_subprogram, DW_TAG_typedef,
    DW_TAG_union_type, DW_TAG_volatile_type, DW_TAG_subrange_type,
};
use memmap2::Mmap;
use object::{Object, ObjectSection};
use serde::{Deserialize, Serialize};
use crate::concolic::ConcolicExecutor;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum TypeDesc {
    Primitive(String),
    Pointer { to: Box<TypeDesc> },
    Array { element: Box<TypeDesc>, count: Option<u64> },
    Struct { members: Vec<StructMember> },
    Union { members: Vec<StructMember> },
    Unknown(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TypeDescCompat {
    Typed(TypeDesc),
    Raw(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructMember {
    pub name: Option<String>,
    pub offset: Option<u64>,
    pub typ: TypeDesc,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Argument {
    pub name: String,
    #[serde(rename = "type")]
    pub arg_type: TypeDescCompat,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub register: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registers: Option<Vec<String>>, 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FunctionSignature {
    pub address: String,
    pub name: String,
    pub arguments: Vec<Argument>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RegisterJsonWrapper {
    functions: Vec<FunctionSignature>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FunctionSigWrapper {
    pub functions: Vec<FunctionSignature>,
}

fn format_register(reg: gimli::Register) -> String {
    format!("DW_OP_reg{}", reg.0)
}

fn parse_location<R: Reader>(
    attr_val: AttributeValue<R>,
    unit: &Unit<R>,
) -> Result<(String, Vec<String>), gimli::Error> {
    let mut loc = "complex".to_string();
    let mut regs = vec![];
    if let AttributeValue::Exprloc(expr) = attr_val {
        let mut ops = expr.operations(unit.encoding());
        while let Some(op) = ops.next()? {
            match op {
                Operation::Register { register } => {
                    let r = format_register(register);
                    regs.push(r.clone());
                    loc = r;
                }
                Operation::Piece { size_in_bits, bit_offset, .. } => {
                    regs.push(format!("piece:{}@{:?}", size_in_bits, bit_offset.unwrap_or(0)));
                }
                Operation::CallFrameCFA => loc = "CFA".to_string(),
                _ => {}
            }
        }
    }
    Ok((loc, regs))
}

fn resolve_type<R: Reader>(
    dwarf: &Dwarf<R>,
    unit: &Unit<R>,
    entry: &DebuggingInformationEntry<R>,
) -> Option<TypeDesc> {
    match entry.tag() {
        DwTag(0x24) => Some(TypeDesc::Unknown("unspecified_parameters".into())),
        // DW_TAG_base_type => {
        //     entry.attr(DW_AT_name).ok().flatten()
        //         .and_then(|a| a.string_value(&dwarf.debug_str))
        //         .map(|s| TypeDesc::Primitive(s.to_string_lossy().into_owned()))
                
        // }
        DW_TAG_typedef | DW_TAG_const_type | DW_TAG_volatile_type | DW_TAG_restrict_type => {
            entry.attr_value(DW_AT_type).ok().flatten().and_then(|v| match v {
                AttributeValue::UnitRef(offs) => unit.entry(offs).ok().and_then(|e| 
                    resolve_type(dwarf, unit, &e)),
                _ => None,
            })
        }
        DW_TAG_pointer_type => {
            let inner = entry.attr_value(DW_AT_type).ok().flatten().and_then(|v| match v {
                AttributeValue::UnitRef(offs) => unit.entry(offs).ok().and_then(|e| 
                    resolve_type(dwarf, unit, &e)),
                _ => Some(TypeDesc::Unknown("void*".into())),
            })?;
            Some(TypeDesc::Pointer { to: Box::new(inner) })
        }
        DW_TAG_array_type => {
            let element = entry.attr_value(DW_AT_type).ok().flatten().and_then(|v| match v {
                AttributeValue::UnitRef(offs) => unit.entry(offs).ok().and_then(|e| 
                    resolve_type(dwarf, unit, &e)),
                _ => None,
            })?;
            let mut count = None;
            if let Ok(mut tree) = unit.entries_tree(Some(entry.offset())) {
                if let Ok(root) = tree.root() {
                    let mut children = root.children();
                    while let Ok(Some(child)) = children.next() {
                        if child.entry().tag() == DW_TAG_subrange_type {
                            if let Some(AttributeValue::Udata(n)) =
                                child.entry().attr_value(gimli::DW_AT_count).ok().flatten()
                            {
                                count = Some(n);
                            }
                        }
                    }
                }
            }
            Some(TypeDesc::Array { element: Box::new(element), count })
        }
        // DW_TAG_structure_type | DW_TAG_union_type => {
        //     let mut members = vec![];
        //     if let Ok(tree) = unit.entries_tree(Some(entry.offset())) {
        //         if let Ok(root) = tree.root() {
        //             let mut children = root.children();
        //             while let Ok(Some(child)) = children.next() {
        //                 let ent = child.entry();
        //                 if ent.tag() == DW_TAG_member {
        //                     let name = ent.attr(DW_AT_name).ok().flatten()
        //                         .and_then(|a| a.string_value(&dwarf.debug_str).ok())
        //                         .map(|s| s.to_string_lossy().into_owned());
        //                     let offset = ent.attr_value(gimli::DW_AT_data_member_location).ok().flatten()
        //                         .and_then(|v| if let AttributeValue::Udata(n) = v { Some(n) } else { None });
        //                     let typ = ent.attr_value(DW_AT_type).ok().flatten()
        //                         .and_then(|v| if let AttributeValue::UnitRef(offs) = v {
        //                             unit.entry(offs).ok().and_then(|e| resolve_type(dwarf, unit, &e))
        //                         } else { None });
        //                     if let Some(typ) = typ {
        //                         members.push(StructMember { name, offset, typ });
        //                     }
        //                 }
        //             }
        //         }
        //     }
        //     if entry.tag() == DW_TAG_structure_type {
        //         Some(TypeDesc::Struct { members })
        //     } else {
        //         Some(TypeDesc::Union { members })
        //     }
        // }
        _ => Some(TypeDesc::Unknown(format!("unhandled: {:?}", entry.tag()))),
    }
}

pub fn precompute_function_signatures_via_gimli(
    binary_path: &str,
    output_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let file = File::open(binary_path)?;
    let mmap = unsafe { Mmap::map(&file)? };
    let object = object::File::parse(&*mmap)?;

    let endian = LittleEndian;
    let load_section = |id: gimli::SectionId| -> Result<EndianSlice<LittleEndian>, gimli::Error> {
        Ok(EndianSlice::new(
            object
                .section_by_name(id.name())
                .and_then(|s| s.uncompressed_data().ok())
                .map(|b| Box::leak(b.into_owned().into_boxed_slice()))
                .unwrap_or_else(|| Box::leak(Vec::new().into_boxed_slice())),
            endian,
        ))
    };

    let dwarf = Dwarf::load(&load_section)?;
    let mut functions = vec![];

    let mut iter = dwarf.units();
    while let Some(header) = iter.next()? {
        let unit = dwarf.unit(header)?;
        let mut entries = unit.entries();

        while let Some((_, entry)) = entries.next_dfs()? {
            if entry.tag() != DW_TAG_subprogram {
                continue;
            }

            let low_pc = entry.attr_value(DW_AT_low_pc)?.and_then(|v| match v {
                AttributeValue::Addr(addr) => Some(addr),
                _ => None,
            });

            let address = if let Some(pc) = low_pc {
                format!("0x{:x}", pc)
            } else {
                continue;
            };

            let name = entry.attr_value(DW_AT_name)?.and_then(|v| dwarf.attr_string(&unit, v).ok())
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "<unknown_fn>".to_string());

            let mut arguments = vec![];

            if let Ok(mut tree) = unit.entries_tree(Some(entry.offset())) {
                if let Ok(root) = tree.root() {
                    let mut children = root.children();
                    while let Ok(Some(child)) = children.next() {
                        let arg = child.entry();
                        if arg.tag() != DW_TAG_formal_parameter {
                            continue;
                        }

                        let name = arg.attr_value(DW_AT_name)?.and_then(|v| dwarf.attr_string(&unit, v).ok())
                            .map(|s| s.to_string_lossy().into_owned())
                            .unwrap_or_else(|| "<arg>".to_string());

                        let arg_type = arg.attr_value(DW_AT_type)?.and_then(|v| match v {
                            AttributeValue::UnitRef(off) => unit.entry(off).ok()
                                .and_then(|e| resolve_type(&dwarf, &unit, &e)),
                            _ => None,
                        }).unwrap_or(TypeDesc::Unknown("<no type>".to_string()));

                        let (location, registers) = match arg.attr_value(DW_AT_location) {
                            Ok(Some(loc)) => match parse_location(loc, &unit) {
                                Ok((loc_str, regs)) => (Some(loc_str), Some(regs)),
                                _ => (None, None),
                            },
                            _ => (None, None),
                        };

                        arguments.push(Argument {
                            name,
                            arg_type: TypeDescCompat::Typed(arg_type),
                            register: registers.clone().and_then(|r| if r.len() == 1 { Some(r[0].clone()) } else { None }),
                            registers,
                            location,
                        });
                    }
                }
            }

            functions.push(FunctionSignature {
                address,
                name,
                arguments,
            });
        }
    }

    let out_file = File::create(output_path)?;
    let writer = BufWriter::new(out_file);
    serde_json::to_writer_pretty(writer, &FunctionSigWrapper { functions })?;

    Ok(())
}

// Precompute all function signatures using Ghidra headless once.
pub fn precompute_function_signatures_via_ghidra(binary_path: &str, _executor: &mut ConcolicExecutor) -> Result<(), Box<dyn std::error::Error>> {
    // Read GHIDRA_INSTALL_DIR from environment (or use fallback).
    let ghidra_path = env::var("GHIDRA_INSTALL_DIR")
        .unwrap_or_else(|_| String::from("~/ghidra_11.0.3_PUBLIC/"));
    print!("Using Ghidra path: {}", ghidra_path);

    let project_path = "results/ghidra-project";
    let project_name = "ghidra-project"; 
    // Use the new script that processes all functions.
    let post_script_path = "scripts/ghidra_get_all_function_args.py";
    let trace_file = "results/function_signature.txt";

    // Ensure the Ghidra project directory exists; create it if it doesn't.
    if !Path::new(project_path).exists() {
        println!("Project directory '{}' not found. Creating it...", project_path);
        fs::create_dir_all(project_path)?;
    }

    // Clean the Ghidra project directory.
    clean_ghidra_project_dir(project_path);
    // Remove any existing signature file.
    if Path::new(trace_file).exists() {
        println!("Removing old function signature file.");
        fs::remove_file(trace_file)?;
    }

    // Get the ZORYA directory.
    let zorya_dir = env::var("ZORYA_DIR")
        .expect("ZORYA_DIR environment variable is not set");

    // Build the full path to the Ghidra headless executable.
    let ghidra_executable = format!("{}/support/analyzeHeadless", ghidra_path);
    // Construct the arguments as a vector.
    let args = vec![
        project_path,           // Project path (e.g., "results/ghidra-project")
        project_name,           // Project name
        "-import",
        binary_path,            // Binary to import
        "-processor",
        "x86:LE:64:default",
        "-cspec",
        "golang",               // Compiler specification - TO MODIFY
        "-postScript",
        post_script_path,       // Script to process all functions
        &zorya_dir,             // ZORYA directory (used by the script)
    ];

    println!("Running Ghidra command: {} {:?}", ghidra_executable, args);

    // Execute the command without invoking a shell.
    let output = Command::new(ghidra_executable)
        .args(&args)
        .output()
        .expect("Failed to execute Ghidra Headless");

    if !output.status.success() {
        eprintln!(
            "Ghidra Headless execution failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        return Err(Box::from("Ghidra analysis failed"));
    }
    println!("Ghidra analysis complete. Function signatures written to {}", trace_file);
    Ok(())
}


// Function to clean the Ghidra project directory
fn clean_ghidra_project_dir(project_path: &str) {
    if Path::new(project_path).exists() {
        println!("Cleaning Ghidra project directory: {}", project_path);
        for entry in fs::read_dir(project_path).expect("Failed to read Ghidra project directory") {
            let entry = entry.expect("Failed to read directory entry");
            let path = entry.path();

            if path.is_file() {
                fs::remove_file(&path).expect("Failed to remove Ghidra project file");
            } else if path.is_dir() {
                fs::remove_dir_all(&path).expect("Failed to remove Ghidra project subdirectory");
            }
        }
    }
}

// Load a map from function address -> (name, [(arg_name, register_offset, arg_type)])
pub fn load_function_args_map() -> HashMap<u64, (String, Vec<(String, u64, String)>)> {
    let json_file = "results/function_signature.json";
    let mut function_args_map = HashMap::new();

    if Path::new(json_file).exists() {
        let file = File::open(json_file).expect("Failed to open function signature JSON file");
        let reader = BufReader::new(file);
        let wrapper: FunctionSigWrapper =
            serde_json::from_reader(reader).expect("Failed to parse JSON file");

        for sig in wrapper.functions {
            let addr = u64::from_str_radix(sig.address.trim_start_matches("0x"), 16)
                .unwrap_or_else(|_| {
                    eprintln!("Warning: invalid address {}", sig.address);
                    0
                });

            let mut args = Vec::new();
            for arg in sig.arguments {
                if let Some(reg) = arg.register.as_deref() {
                    let off = match reg {
                        "RAX" => 0x0,
                        "RCX" => 0x8,
                        "RDX" => 0x10,
                        "RBX" => 0x18,
                        "RSI" => 0x30,
                        "RDI" => 0x38,
                        "R8" => 0x80,
                        "R9" => 0x88,
                        "R10" => 0x90,
                        "R11" => 0x98,
                        "R12" => 0xa0,
                        "R13" => 0xa8,
                        "R14" => 0xb0,
                        "R15" => 0xb8,
                        _ => continue,
                    };
                    let arg_type_str = match &arg.arg_type {
                        TypeDescCompat::Typed(t) => format!("{:?}", t),
                        TypeDescCompat::Raw(s) => s.clone(),
                    };
                    args.push((arg.name.clone(), off, arg_type_str));                    
                } else if let Some(regs) = &arg.registers {
                    // multi-register (e.g. string), take the first
                    if let Some(first) = regs.first().map(String::as_str) {
                        let off = match first {
                            "RAX" => 0x0,
                            "RCX" => 0x8,
                            "RDX" => 0x10,
                            "RBX" => 0x18,
                            "RSI" => 0x30,
                            "RDI" => 0x38,
                            "R8" => 0x80,
                            "R9" => 0x88,
                            "R10" => 0x90,
                            "R11" => 0x98,
                            "R12" => 0xa0,
                            "R13" => 0xa8,
                            "R14" => 0xb0,
                            "R15" => 0xb8,
                            _ => continue,
                        };
                        let arg_type_str = match &arg.arg_type {
                            TypeDescCompat::Typed(t) => format!("{:?}", t),
                            TypeDescCompat::Raw(s) => s.clone(),
                        };
                        args.push((arg.name.clone(), off, arg_type_str));                        
                    }
                }
                // otherwise: no register info -> skip
            }

            if !args.is_empty() {
                function_args_map.insert(addr, (sig.name, args));
            }
        }
    } else {
        eprintln!(
            "Warning: {} not found. Precompute signatures with Ghidra/Delve first.",
            json_file
        );
    }

    function_args_map
}

pub fn load_function_args_map_go() -> HashMap<String, FunctionSignature> {
    let types_path = "results/function_signature_arg_types.json";
    let registers_path = "results/function_signature_arg_registers.json";

    // Load types
    let types_file = File::open(types_path).expect("Failed to open arg_types.json");
    let type_reader = BufReader::new(types_file);
    let mut type_signatures: Vec<FunctionSignature> = serde_json::from_reader(type_reader)
        .expect("Failed to parse function_signature_arg_types.json");

    // Load registers
    let registers_file = File::open(registers_path).expect("Failed to open arg_registers.json");
    let reg_reader = BufReader::new(registers_file);
    let register_wrapper: RegisterJsonWrapper = serde_json::from_reader(reg_reader)
        .expect("Failed to parse function_signature_arg_registers.json");

    let mut reg_map: HashMap<String, Vec<Argument>> = HashMap::new();

    for f in register_wrapper.functions {
        reg_map.insert(f.address.clone(), f.arguments);
    }

    // Merge register info into type-based data
    for func in &mut type_signatures {
        if let Some(reg_args) = reg_map.get(&func.address) {
            for arg in &mut func.arguments {
                // Match based on argument name
                if let Some(reg_arg) = reg_args.iter().find(|ra| ra.name == arg.name) {
                    arg.register = reg_arg.register.clone();
                }
            }
        }
    }

    // Build the final map: address → FunctionSignature
    let mut result_map = HashMap::new();
    for func in type_signatures {
        result_map.insert(func.address.clone(), func);
    }

    result_map
}