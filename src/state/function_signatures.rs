// SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

//! src/state/function_signatures.rs

#![allow(non_upper_case_globals)]

use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::io::BufReader;
use std::path::Path;
use std::process::Command;
use std::{env, fs};

use crate::concolic::ConcolicExecutor;
use serde::{Deserialize, Serialize};

pub type FunctionArgsMap = HashMap<u64, (String, Vec<(String, Vec<String>, String)>)>;

macro_rules! log {
    ($logger:expr, $($arg:tt)*) => {{
        if ($logger).is_enabled() {
        writeln!($logger, $($arg)*).unwrap();
        }
    }};
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind")]
pub enum TypeDesc {
    Primitive(String),
    Pointer {
        to: Box<TypeDesc>,
    },
    Array {
        element: Box<TypeDesc>,
        count: Option<u64>,
    },
    Slice {
        element: Box<TypeDesc>,
    },
    Struct {
        members: Vec<StructMember>,
    },
    Union {
        members: Vec<StructMember>,
    },
    Unknown(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TypeDescCompat {
    Typed(TypeDesc),
    Raw(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
pub struct FunctionSigWrapper {
    pub functions: Vec<FunctionSignature>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GoFunctionArg {
    pub name: String,
    pub address: String,
    pub arguments: Vec<GoArgument>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GoArgument {
    pub name: String,
    #[serde(rename = "type")]
    pub arg_type: String,
    #[serde(default)]
    pub registers: Vec<String>,
    #[serde(default)]
    pub location: Option<String>,
}

// Precompute all function signatures using Ghidra headless once.
pub fn precompute_function_signatures_via_ghidra(
    binary_path: &str,
    _executor: &mut ConcolicExecutor,
) -> Result<(), Box<dyn std::error::Error>> {
    // Read GHIDRA_INSTALL_DIR from environment (or use fallback).
    let ghidra_path =
        env::var("GHIDRA_INSTALL_DIR").unwrap_or_else(|_| String::from("~/ghidra_11.0.3_PUBLIC/"));
    print!("Using Ghidra path: {}", ghidra_path);

    let project_path = "results/ghidra-project";
    let project_name = "ghidra-project";
    // Use the new script that processes all functions.
    let post_script_path = "scripts/ghidra_get_all_function_args.py";
    let trace_file = "results/function_signature.txt";

    // Ensure the Ghidra project directory exists; create it if it doesn't.
    if !Path::new(project_path).exists() {
        println!(
            "Project directory '{}' not found. Creating it...",
            project_path
        );
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
    let zorya_dir = env::var("ZORYA_DIR").expect("ZORYA_DIR environment variable is not set");

    // Build the full path to the Ghidra headless executable.
    let ghidra_executable = format!("{}/support/analyzeHeadless", ghidra_path);
    // Construct the arguments as a vector.
    let args = vec![
        project_path, // Project path (e.g., "results/ghidra-project")
        project_name, // Project name
        "-import",
        binary_path, // Binary to import
        "-processor",
        "x86:LE:64:default",
        "-cspec",
        "golang", // Compiler specification - TO MODIFY
        "-postScript",
        post_script_path, // Script to process all functions
        &zorya_dir,       // ZORYA directory (used by the script)
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
    println!(
        "Ghidra analysis complete. Function signatures written to {}",
        trace_file
    );
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
pub fn load_function_args_map() -> FunctionArgsMap {
    let json_file = "results/function_signature.json";
    let mut map = HashMap::new();

    if !Path::new(json_file).exists() {
        eprintln!(
            "Warning: {} not found. Pre-compute signatures with Ghidra/Delve first.",
            json_file
        );
        return map;
    }

    let reader =
        BufReader::new(File::open(json_file).expect("Failed to open function signature JSON file"));
    let wrapper: FunctionSigWrapper =
        serde_json::from_reader(reader).expect("Failed to parse JSON file");

    for sig in wrapper.functions {
        let addr = u64::from_str_radix(sig.address.trim_start_matches("0x"), 16).unwrap_or(0);

        let mut args: Vec<(String, Vec<String>, String)> = Vec::new();
        for arg in sig.arguments {
            let arg_type_str = match &arg.arg_type {
                TypeDescCompat::Typed(t) => format!("{:?}", t),
                TypeDescCompat::Raw(s) => s.clone(),
            };

            // single-register argument
            if let Some(reg) = arg.register.as_deref() {
                args.push((
                    arg.name.clone(),
                    vec![reg.to_string()],
                    arg_type_str.clone(),
                ));
            }
            // multi-register argument (e.g., Go string: ptr,len)
            else if let Some(regs) = &arg.registers {
                if !regs.is_empty() {
                    args.push((
                        arg.name.clone(),
                        regs.clone(), // already Vec<String>
                        arg_type_str.clone(),
                    ));
                }
            }
            // if neither `register` nor `registers` present → skip
        }

        if !args.is_empty() {
            map.insert(addr, (sig.name, args));
        }
    }

    map
}

pub fn load_go_function_args_map(
    binary_path: &str,
    executor: &mut ConcolicExecutor,
) -> Result<FunctionArgsMap, Box<dyn std::error::Error>>
{
    let func_signatures_path = "results/function_signatures_go.json";

    // Check if we need to regenerate signatures
    if !Path::new(func_signatures_path).exists() {
        log!(
            executor.state.logger,
            "Function signatures not found. Extracting from binary using llvm-dwarfdump..."
        );

        // Use llvm-dwarfdump for all languages (C, C++, Go, Rust, etc.)
        // It has better DWARF5 support than GNU binutils
        let llvm_script = format!(
            "{}/scripts/llvm_extract_function_signatures.py",
            env::var("ZORYA_DIR")?
        );

        let out = std::process::Command::new("python3")
            .arg(&llvm_script)
            .arg(binary_path)
            .arg(func_signatures_path)
            .output()?;

        if !out.status.success() {
            let error_msg = String::from_utf8_lossy(&out.stderr);
            return Err(format!("llvm-dwarfdump extraction failed: {}", error_msg).into());
        }

        log!(
            executor.state.logger,
            "Successfully extracted function signatures"
        );
    }

    log!(
        executor.state.logger,
        "Loading function signatures from {}...",
        func_signatures_path
    );

    let file = std::fs::File::open(func_signatures_path)?;
    let reader = std::io::BufReader::new(file);
    let functions: Vec<GoFunctionArg> = serde_json::from_reader(reader)?;

    log!(
        executor.state.logger,
        "Loaded {} functions from JSON.",
        functions.len()
    );

    let mut function_map = HashMap::new();
    for func in functions {
        if let Ok(addr) = u64::from_str_radix(func.address.trim_start_matches("0x"), 16) {
            let args = func
                .arguments
                .iter()
                .map(|arg| {
                    (
                        arg.name.clone(),
                        arg.registers.clone(),
                        arg.arg_type.clone(),
                    )
                })
                .collect();
            function_map.insert(addr, (func.name, args));
        } else {
            log!(
                executor.state.logger,
                "Warning: Failed to parse address {} for function {}",
                func.address,
                func.name
            );
        }
    }

    log!(
        executor.state.logger,
        "Processed {} function signatures.",
        function_map.len()
    );

    Ok(function_map)
}
