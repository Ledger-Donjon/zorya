use core::panic;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::env;
use std::error::Error;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{self, Command};
use std::sync::Arc;
use libc::EXDEV;
use parser::parser::{Inst, Opcode};
use serde::Deserialize;
use z3::ast::{Ast, Bool, Int, BV};
use z3::{Config, Context, SatResult, Solver};
use zorya::concolic::{ConcolicVar, Logger};
use zorya::executor::{ConcolicExecutor, SymbolicVar};
use zorya::state::memory_x86_64::MemoryValue;
use zorya::target_info::GLOBAL_TARGET_INFO;

macro_rules! log {
    ($logger:expr, $($arg:tt)*) => {{
        writeln!($logger, $($arg)*).unwrap();
    }};
}

/// Functions we want to completely ignore / skip execution in the TinyGo runtime.
const IGNORED_TINYGO_FUNCS: &[&str] = &[
    // "runtime.markRoots",
    // "runtime.alloc",
    // "runtime.markStack",
    // "runtime.runGC",
    // "runtime.markRoot",
    // "runtime.findGlobals",
];

fn main() -> Result<(), Box<dyn Error>> {
    let config = Config::new();
    let context = Context::new(&config);
    let solver = Solver::new(&context);
    let logger = Logger::new("results/execution_log.txt").expect("Failed to create logger"); // get the instruction handling detailed log
    let trace_logger = Logger::new("results/execution_trace.txt").expect("Failed to create trace logger"); // get the trace of the executed symbols names
    let mut executor: ConcolicExecutor<'_> = ConcolicExecutor::new(&context, logger.clone(), trace_logger.clone()).expect("Failed to initialize the ConcolicExecutor.");
    
    log!(executor.state.logger, "Configuration and context have been initialized.");

    let (binary_path, pcode_file_path, main_program_addr) = {
        let target_info = GLOBAL_TARGET_INFO.lock().unwrap();
        log!(executor.state.logger, "Acquired target information.");
        (target_info.binary_path.clone(), target_info.pcode_file_path.clone(), target_info.main_program_addr.clone())
    };
    log!(executor.state.logger, "Binary path: {}", binary_path);
    let pcode_file_path_str = pcode_file_path.to_str().expect("The file path contains invalid Unicode characters.");

    // Populate the symbol table
    let elf_data = fs::read(binary_path.clone())?;
    executor.populate_symbol_table(&elf_data)?;
    log!(executor.state.logger, "The symbols table has been populated.");

    log!(executor.state.logger, "Path to the p-code file: {}", pcode_file_path_str);
    // Preprocess the p-code file to get a map of addresses to instructions
    let instructions_map = preprocess_pcode_file(pcode_file_path_str, &mut executor.clone())
        .expect("Failed to preprocess the p-code file.");

    // Get the tables of cross references of potential panics in the programs (for bug detetcion)
    get_cross_references(&binary_path)?;

    // Precompute all function signatures using Ghidra headless
    log!(executor.state.logger, "Precomputing function signatures using Ghidra headless...");
    precompute_function_signatures(&binary_path, &mut executor)?;

    // Now load the JSON file with the function signatures
    let function_args_map = load_function_args_map();
    log!(executor.state.logger, "Loaded {} function signatures.", function_args_map.len());

    let start_address = u64::from_str_radix(&main_program_addr.trim_start_matches("0x"), 16)
        .expect("The format of the main program address is invalid.");

    // Adapt scenaris according to the chosen mode in the command
    let mode = env::var("MODE").expect("MODE environment variable is not set");
    let arguments = env::var("ARGS").expect("MODE environment variable is not set");
    
    // Turn each byte of each user input into a symbolic variable
    let os_args_addr = get_os_args_address()?;
    initialize_symbolic_part_args(&mut executor, os_args_addr)?;
    
    if mode == "function" { 
        log!(executor.state.logger, "Mode is 'function'. Adapting the context...");
        let start_address_hex = format!("{:x}", start_address);
        log!(executor.state.logger, "Start address is {:?}", start_address_hex);
        log!(executor.state.logger, "symbol table is {:?}", executor.symbol_table);

        if let Some(function) = executor.symbol_table.get(&start_address_hex) {
            log!(executor.state.logger, "Located function: {:?}", function);
    
        } else {
            log!(executor.state.logger, "Function not found in symbol table.");
        }
    
    } else if mode == "start" {
        log!(executor.state.logger, "Updating argc and argv on the stack");
        update_argc_argv(&mut executor, &arguments)?;
        
    } else { // when mode is main, start or custom, no additional modification has to be done
        log!(executor.state.logger, "Continuing execution without modification.");
    }

    // CORE COMMAND
    execute_instructions_from(&mut executor, start_address, &instructions_map, &solver, &binary_path);

    Ok(())
}

// Function to get the address of the os.Args slice in the target binary
pub fn get_os_args_address() -> Result<u64, Box<dyn Error>> {
    // Use the globally stored target info to get the path to your binary
    let binary_path = {
        let target_info = crate::GLOBAL_TARGET_INFO.lock().unwrap();
        target_info.binary_path.clone()
    };

    let script_path = "scripts/find_os_args.py";
    let output = Command::new("python3")
        .arg(script_path)
        .arg(&binary_path)
        .output()
        .map_err(|e| format!("Failed to run pyhidra script: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("pyhidra script returned error: {}", stderr).into());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // We parse lines to find the address. 
    let mut address: Option<u64> = None;
    for line in stdout.lines() {
        // If the script prints an error line
        if line.starts_with("ERROR") {
            return Err(format!("Could not find 'os.Args' symbol: {}", line).into());
        }

        // the script prints "os.Args 0x232760"
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() == 2 && parts[0].contains("os.Args") {
            if let Ok(addr) = u64::from_str_radix(parts[1].trim_start_matches("0x"), 16) {
                address = Some(addr);
                break;
            }
        }
    }

    // If address is still None, we failed to parse
    let addr = address.ok_or("No valid address returned by find_os_args.py")?;
    Ok(addr)
}


pub fn initialize_symbolic_part_args(executor: &mut ConcolicExecutor, args_addr: u64) -> Result<(), Box<dyn Error>> {
    // Read os.Args slice header (Pointer, Len, Cap)
    let mem = &executor.state.memory;
    let slice_ptr = mem.read_u64(args_addr)?.concrete.to_u64();       // Pointer to backing array
    let slice_len = mem.read_u64(args_addr + 8)?.concrete.to_u64();   // Length (number of arguments)
    let _slice_cap = mem.read_u64(args_addr + 16)?.concrete.to_u64(); // Capacity (not used)

    log!(executor.state.logger, "os.Args -> ptr=0x{:?}, len={}, cap={}", slice_ptr, slice_len, _slice_cap);

    // Iterate through each argument
    for i in 0..slice_len {
        let string_struct_addr = slice_ptr + i * 16; // Each Go string struct is 16 bytes
        let str_data_ptr = mem.read_u64(string_struct_addr)?.concrete.to_u64();       // Pointer to actual string data
        let str_data_len = mem.read_u64(string_struct_addr + 8)?.concrete.to_u64();   // Length of the string

        log!(executor.state.logger, "os.Args[{}] -> string ptr=0x{:x}, len={}", i, str_data_ptr, str_data_len);

        if str_data_ptr == 0 || str_data_len == 0 {
            // Possibly an empty argument? Just skip or handle specially
            continue;
        }

        // Read the actual string bytes
        let concrete_str_bytes = mem.read_bytes(str_data_ptr, str_data_len as usize)?;

        // Create fresh symbolic variables for each byte of this argument
        let mut fresh_symbolic = Vec::with_capacity(str_data_len as usize);
        for (byte_index, _) in concrete_str_bytes.iter().enumerate() {
            let bv_name = format!("arg{}_byte_{}", i, byte_index);
            let fresh_bv = BV::fresh_const(&executor.context, &bv_name, 8);
            fresh_symbolic.push(Some(Arc::new(fresh_bv)));
        }

        // Write those symbolic values back into memory
        mem.write_memory(str_data_ptr, &concrete_str_bytes, &fresh_symbolic)?;

        log!(executor.state.logger, "Successfully replaced os.Args[{}] with {} symbolic bytes.", i, str_data_len);
    }

    Ok(())
}

/// Function to execute the Python script to get the cross references of potential panics in the programs (for bug detetcion)
fn get_cross_references(binary_path: &str) -> Result<(), Box<dyn Error>> {
    let zorya_dir = {
        let info = GLOBAL_TARGET_INFO.lock().unwrap();
        info.zorya_path.clone()
    };
    let python_script_path = zorya_dir.join("scripts").join("find_panic_xrefs.py");

    if !python_script_path.exists() {
        panic!("Python script not found at {:?}", python_script_path);
    }

    let output = Command::new("python3")
        .arg(python_script_path)
        .arg(binary_path)
        .output()
        .expect("Failed to execute Python script");

    // Check if the script ran successfully
    if !output.status.success() {
        eprintln!("Python script error: {}", String::from_utf8_lossy(&output.stderr));
        return Err(Box::from("Python script failed"));
    } else {
        println!("Python script executed successfully:");
        println!("{}", String::from_utf8_lossy(&output.stdout));
    }

    // Ensure the file was created
    if !Path::new("results/xref_addresses.txt").exists() {
        panic!("xref_addresses.txt not found after running the Python script");
    }

    Ok(())
}

// Function to preprocess the p-code file and return a map of addresses to instructions
fn preprocess_pcode_file(path: &str, executor: &mut ConcolicExecutor) -> io::Result<BTreeMap<u64, Vec<Inst>>> {
    let file = File::open(path)?;
    let reader = io::BufReader::new(file);
    let mut instructions_map = BTreeMap::new();
    let mut current_address: Option<u64> = None;

    log!(executor.state.logger, "Preprocessing the p-code file...");

    for line in reader.lines().filter_map(Result::ok) {
        if line.trim_start().starts_with("0x") {
            current_address = Some(u64::from_str_radix(&line.trim()[2..], 16).unwrap());
            instructions_map.entry(current_address.unwrap()).or_insert_with(Vec::new);
        } else {
            match line.parse::<Inst>() {
                Ok(inst) => {
                    if let Some(addr) = current_address {
                        instructions_map.get_mut(&addr).unwrap().push(inst);
                    } else {
                        log!(executor.state.logger, "Instruction found without a preceding address: {}", line);
                    }
                },
                Err(e) => {
                    log!(executor.state.logger, "Error parsing line at address 0x{:x}: {}\nError: {}", current_address.unwrap_or(0), line, e);
                    return Err(io::Error::new(io::ErrorKind::Other, format!("Error parsing line at address 0x{:x}: {}\nError: {}", current_address.unwrap_or(0), line, e)));
                }
            }
        }
    }

    log!(executor.state.logger, "Completed preprocessing.\n");

    Ok(instructions_map)
}

// Function to read the panic addresses from the file
fn read_panic_addresses(executor: &mut ConcolicExecutor, filename: &str) -> io::Result<Vec<u64>> {
    // Get the base path from the environment variable
    let zorya_path_buf = PathBuf::from(
        env::var("ZORYA_DIR").expect("ZORYA_DIR environment variable is not set")
    );
    let zorya_path = zorya_path_buf.to_str().unwrap();

    // Construct the full path to the results directory
    let results_dir = Path::new(zorya_path).join("results");
    let full_path = results_dir.join(filename);

    // Ensure the file exists before trying to read it
    if !full_path.exists() {
        log!(executor.state.logger, "Error: File {:?} does not exist.", full_path);
        return Err(io::Error::new(io::ErrorKind::NotFound, "File not found"));
    }

    let file = File::open(&full_path)?;
    let reader = BufReader::new(file);
    let mut addresses = Vec::new();
    
    for line in reader.lines() {
        let line = line?;
        let line = line.trim();
        if line.starts_with("0x") {
            match u64::from_str_radix(&line[2..], 16) {
                Ok(addr) => {
                    log!(executor.state.logger, "Read panic address: 0x{:x}", addr);
                    addresses.push(addr);
                },
                Err(e) => {
                    log!(executor.state.logger, "Failed to parse address {}: {}", line, e);
                }
            }
        }
    }
    Ok(addresses)
}

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

// Precompute all function signatures using Ghidra headless once.
fn precompute_function_signatures(binary_path: &str, _executor: &mut ConcolicExecutor) -> Result<(), Box<dyn Error>> {
    // Read GHIDRA_INSTALL_DIR from environment (or use fallback).
    let ghidra_path = env::var("GHIDRA_INSTALL_DIR")
        .unwrap_or_else(|_| String::from("~/ghidra_11.0.3_PUBLIC/"));
    let project_path = "results/ghidra-project";
    let project_name = "ghidra-project"; // the project name you want to use
    // Use the new script that processes all functions.
    let post_script_path = "scripts/get_all_function_args.py";
    let trace_file = "results/function_signature.txt";

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

    println!("Precomputing function signatures using Ghidra Headless...");

    // Build the full path to the Ghidra headless executable.
    let ghidra_executable = format!("{}support/analyzeHeadless", ghidra_path);
    // Construct the arguments as a vector.
    let args = vec![
        project_path,           // Project path (e.g., "results/ghidra-project")
        project_name,           // Project name
        "-import",
        binary_path,            // Binary to import
        "-processor",
        "x86:LE:64:default",
        "-cspec",
        "golang",
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

/// Load the function arguments map from the precomputed file.
fn load_function_args_map() -> HashMap<u64, (String, Vec<(String, u64)>)> {
    let json_file = "results/function_signature.json";
    let mut function_args_map: HashMap<u64, (String, Vec<(String, u64)>)> = HashMap::new();

    if Path::new(json_file).exists() {
        let file = File::open(json_file).expect("Failed to open function signature JSON file");
        let reader = BufReader::new(file);
        let signatures: Vec<FunctionSignature> = serde_json::from_reader(reader)
            .expect("Failed to parse JSON file");

        for sig in signatures {
            // Parse the address as hexadecimal.
            let address = u64::from_str_radix(sig.address.trim_start_matches("0x"), 16)
                .unwrap_or(0);
            let function_name = sig.function_name;
            let mut args = Vec::new();
            for arg in sig.arguments {
                // Convert known register names to offsets.
                let register_offset = match arg.register.as_str() {
                    "RAX" => 0x0,
                    "RCX" => 0x8,
                    "RDX" => 0x10,
                    "RBX" => 0x18,
                    "RSI" => 0x30,
                    "RDI" => 0x38,
                    "R8"  => 0x80,
                    "R9"  => 0x88,
                    "R10" => 0x90,
                    "R11" => 0x98,
                    "R12" => 0xa0,
                    "R13" => 0xa8,
                    "R14" => 0xb0,
                    "R15" => 0xb8,
                    _ => continue, // Skip non-standard register names.
                };
                args.push((arg.name, register_offset));
            }
            // Only insert if we found valid arguments.
            if !args.is_empty() {
                function_args_map.insert(address, (function_name, args));
            }
        }
    } else {
        println!(
            "Warning: {} not found. Please precompute the function signatures using Ghidra.",
            json_file
        );
    }
    function_args_map
}

// Function to add the arguments of the target binary from the user's command 
fn update_argc_argv(executor: &mut ConcolicExecutor, arguments: &str) -> Result<(), Box<dyn std::error::Error>> {
    let cpu_state_guard = executor.state.cpu_state.lock().unwrap();

    if arguments == "none" {
        return Ok(());
    }

    // Parse arguments
    let args: Vec<String> = shell_words::split(arguments)?;
    let argc = args.len() as u64;

    log!(executor.state.logger, "Symbolically setting argc: {}", argc);

    let rsp = cpu_state_guard
        .get_register_by_offset(0x20, 64)
        .unwrap()
        .concrete
        .to_u64();

    // Write argc (concrete)
    executor.state.memory.write_value(
        rsp,
        &MemoryValue::new(
            argc,
            BV::from_u64(&executor.context, argc, 64),
            64,
        ),
    )?;

    let argv_ptr_base = rsp + 8;
    let mut current_string_address = argv_ptr_base + (argc + 1) * 8;

    for (i, arg) in args.iter().enumerate() {
        // Write argv[i] pointer
        executor.state.memory.write_value(
            argv_ptr_base + (i as u64 * 8),
            &MemoryValue::new(
                current_string_address,
                BV::from_u64(&executor.context, current_string_address, 64),
                64,
            ),
        )?;

        log!(executor.state.logger, "Set argv[{}] pointer at: 0x{:x}", i, current_string_address);

        let arg_bytes = arg.as_bytes();

        for offset in 0..arg_bytes.len() {
            let sym_byte = BV::fresh_const(&executor.context, &format!("arg{}_byte{}", i, offset),8);

            executor.state.memory.write_value(
                current_string_address + offset as u64,
                &MemoryValue::new(
                    0,
                    sym_byte.clone(),
                    8,
                ),
            )?;
        }

        // NULL terminator
        executor.state.memory.write_value(
            current_string_address + arg_bytes.len() as u64,
            &MemoryValue::new(0, BV::from_u64(&executor.context, 0, 8), 8),
        )?;

        current_string_address += ((arg_bytes.len() + 8) as u64) & !7; // align to 8 bytes
    }

    // Write argv NULL terminator pointer
    executor.state.memory.write_value(
        argv_ptr_base + argc * 8,
        &MemoryValue::new(0, BV::from_u64(executor.context, 0, 64), 64),
    )?;

    Ok(())
}

// Function to execute the instructions from the map of addresses to instructions
fn execute_instructions_from(executor: &mut ConcolicExecutor, start_address: u64, instructions_map: &BTreeMap<u64, Vec<Inst>>, solver: &Solver, binary_path: &str) {
    let mut current_rip = start_address;
    let mut local_line_number: i64 = 0;  // Index of the current instruction within the block
    let end_address: u64 = 0x0; //no specific end address

    // For debugging
    //let address: u64 = 0x7fffffffe4b0;
    //let range = 0x8; 

    log!(executor.state.logger, "Logging the addresses of the XREFs of Panic functions...");
    // Read the panic addresses from the file once before the main loop
    let panic_addresses = read_panic_addresses(executor, "xref_addresses.txt")
        .expect("Failed to read panic addresses from results directory");

    // Convert panic addresses to Z3 Ints once
    let panic_address_ints: Vec<Int> = panic_addresses.iter()
        .map(|&addr| Int::from_u64(executor.context, addr))
        .collect();

    log!(executor.state.logger, "Beginning execution from address: 0x{:x}", start_address);

    // Set RIP to start_address once before entering the loop
    {
        let mut cpu_state_guard = executor.state.cpu_state.lock().unwrap();
        cpu_state_guard.set_register_value_by_offset(0x288, ConcolicVar::new_concrete_and_symbolic_int(current_rip, SymbolicVar::new_int(current_rip.try_into().unwrap(), executor.context, 64).to_bv(executor.context), executor.context, 64), 64).map_err(|e| e.to_string()).unwrap();
    }

    // Load the function arguments map
    log!(executor.state.logger, "Loading function arguments map...");
    let function_args_map = load_function_args_map();

    while let Some(instructions) = instructions_map.get(&current_rip) {
        if current_rip == end_address {
            log!(executor.state.logger, "END ADDRESS 0x{:x} REACHED, STOP THE EXECUTION", end_address);
            break; // Stop execution if end address is reached
        }
        
        log!(executor.state.logger, "*******************************************");
        log!(executor.state.logger, "EXECUTING INSTRUCTIONS AT ADDRESS: 0x{:x}", current_rip);
        log!(executor.state.logger, "*******************************************");

        let current_rip_hex = format!("{:x}", current_rip);

        // This bloc is only to get data about the execution in results/execution_trace.txt
        if let Some(symbol_name) = executor.symbol_table.get(&current_rip_hex) {
            if let Some((_, args)) = function_args_map.get(&current_rip) {
                let mut arg_values = Vec::new();
                for (arg_name, register_offset) in args {
                    if let Some(value) = executor.state.cpu_state.lock().unwrap().get_register_by_offset(*register_offset, 64) {
                        arg_values.push(format!("{}=0x{:x} (reg=0x{:x})", arg_name, value.concrete, register_offset));
                    }
                }
                if !arg_values.is_empty() {
                    let log_string = format!("Address: {:x}, Symbol: {} -> {}", current_rip, symbol_name, arg_values.join(", "));
                    log!(executor.trace_logger, "{}", log_string);
                }
            } else {
                log!(executor.trace_logger, "Address: {:x}, Symbol: {}", current_rip, symbol_name);
            }
        }

        // Inner loop: process each instruction in the current block.
        let mut end_of_block = false;
 
        while local_line_number < instructions.len().try_into().unwrap() && !end_of_block {
            let inst = &instructions[local_line_number as usize];
            log!(executor.state.logger, "-------> Processing instruction at index: {}, {:?}", local_line_number, inst);

            // next_inst is used for updating the symbolic part during LOAD operation, to know if the next instruction is a BRANCHIND or CALLIND
            let next_inst = if local_line_number < (instructions.len() - 1).try_into().unwrap() {
                let next_inst = &instructions[(local_line_number + 1) as usize];
                next_inst.clone()
            } else {
                let next_inst = inst.clone();
                next_inst
            };

            // If this is a branch-type instruction, do symbolic checks.
            if inst.opcode == Opcode::CBranch || inst.opcode == Opcode::BranchInd || inst.opcode == Opcode::CallInd {
                log!(executor.state.logger, " !!! Branch-type instruction detected: entrying symbolic checks...");
                let branch_target_varnode = inst.inputs[0].clone();
                let branch_target_address = executor
                    .extract_branch_target_address(&branch_target_varnode, inst.clone())
                    .map_err(|e| e.to_string())
                    .unwrap();

                if panic_address_ints.contains(&z3::ast::Int::from_u64(executor.context, branch_target_address)) {
                    log!(executor.state.logger,
                        "Potential branching to a panic function at 0x{:x}",
                        branch_target_address);
                    
                    // 1) Push the solver context.
                    executor.solver.push();

                    // 2) Assert the global registers' state and memory into the solver.
                    //assert_registers_state(executor);
                    //assert_memory_state(executor);

                    // 3) Process the branch condition.
                    let cond_varnode = &inst.inputs[1];
                    let cond_concolic = executor.varnode_to_concolic(cond_varnode)
                        .map_err(|e| e.to_string())
                        .unwrap()
                        .to_concolic_var()
                        .unwrap();
                    let cond_bv = cond_concolic.symbolic.to_bv(executor.context);

                    if current_rip == 0x2287e0 {
                        //log!(executor.state.logger, "Branch condition symbolic: {:?}", cond_bv);
                        log!(executor.state.logger, "Branch condition symbolic simplified: {:?}\n", cond_bv.simplify());
                    } else {
                        log!(executor.state.logger, "Branch condition symbolic simplified: {:?}\n", cond_bv.simplify());
                    }

                    // Instead of checking for equality with 1 (which is too strict),
                    // we typically want to assert that the condition is nonzero.
                    let zero_bv = z3::ast::BV::from_u64(executor.context, 0, cond_bv.get_size());
                    let branch_condition = cond_bv._eq(&zero_bv).not();

                    // 4) Assert the branch condition.
                    executor.solver.assert(&branch_condition);
            
                    // 4) check feasibility
                    match executor.solver.check() {
                        z3::SatResult::Sat => {
                            log!(executor.state.logger, "~~~~~~~~~~~");
                            log!(executor.state.logger, "SATISFIABLE: Symbolic execution can lead to a panic function.");
                            log!(executor.state.logger, "~~~~~~~~~~~");
            
                            // 5) get_model
                            let model = executor.solver.get_model().unwrap();

                            // broken-calculator-bis : 22def7 / crashme : 22b21a / broken-calculator: 22f06e
                            //if current_rip == 0x22f06e || current_rip == 0x22f068 || current_rip == 0x22b21a || current_rip == 0x22def7 {
                                // 5.1) get address of os.Args
                                let os_args_addr = get_os_args_address().unwrap();

                                // 5.2) read the slice's pointer and length from memory, then evaluate them in the model
                                let slice_ptr_bv = executor
                                    .state
                                    .memory
                                    .read_u64(os_args_addr)
                                    .unwrap()
                                    .symbolic
                                    .to_bv(executor.context);
                                let slice_ptr_val = model.eval(&slice_ptr_bv, true).unwrap().as_u64().unwrap();

                                let slice_len_bv = executor
                                    .state
                                    .memory
                                    .read_u64(os_args_addr + 8)
                                    .unwrap()
                                    .symbolic
                                    .to_bv(executor.context);
                                let slice_len_val = model.eval(&slice_len_bv, true).unwrap().as_u64().unwrap();

                                log!(executor.state.logger, "To take the panic-branch => os.Args ptr=0x{:x}, len={}", slice_ptr_val, slice_len_val);

                                // 5.3) For each argument in os.Args, read the string struct (ptr, len), then read each byte
                                // starting the loop from 1 to skip the first argument (binary name)
                                for i in 1..slice_len_val {
                                    // Each string struct is 16 bytes: [8-byte ptr][8-byte len]
                                    let string_struct_addr = slice_ptr_val + i * 16;

                                    // Evaluate the pointer field
                                    let str_data_ptr_bv = executor
                                        .state
                                        .memory
                                        .read_u64(string_struct_addr)
                                        .unwrap()
                                        .symbolic
                                        .to_bv(executor.context);
                                    let str_data_ptr_val = model.eval(&str_data_ptr_bv, true).unwrap().as_u64().unwrap();

                                    // Evaluate the length field
                                    let str_data_len_bv = executor
                                        .state
                                        .memory
                                        .read_u64(string_struct_addr + 8)
                                        .unwrap()
                                        .symbolic
                                        .to_bv(executor.context);
                                    let str_data_len_val = model.eval(&str_data_len_bv, true).unwrap().as_u64().unwrap();

                                    // If pointer or length is zero, skip
                                    if str_data_ptr_val == 0 || str_data_len_val == 0 {
                                        log!(executor.state.logger, "Arg[{}] => (empty or null)", i);
                                        continue;
                                    }

                                    // 5.4) read each symbolic byte from memory, evaluate in the model, and collect
                                    let mut arg_bytes = Vec::new();
                                    for j in 0..str_data_len_val {
                                        let byte_read = executor
                                            .state
                                            .memory
                                            .read_byte(str_data_ptr_val + j)
                                            .map_err(|e| format!("Could not read arg[{}][{}]: {}", i, j, e))
                                            .unwrap();

                                        let byte_bv = byte_read.symbolic.to_bv(executor.context);
                                        let byte_val = model.eval(&byte_bv, true).unwrap().as_u64().unwrap() as u8;

                                        arg_bytes.push(byte_val);
                                    }

                                    // Convert the collected bytes into a String (falling back to lossy if invalid UTF-8)
                                    let arg_str = String::from_utf8_lossy(&arg_bytes);

                                    log!(executor.state.logger, "The user input nr.{} must be => \"{}\", the raw value beeing {:?} (len={})", i, arg_str, arg_bytes, str_data_len_val);
                                }

                                // Retrieve others registers values
                                let rax_sym_bv = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x0, 64).unwrap().symbolic.to_bv(executor.context);
                                let rax_val = model.eval(&rax_sym_bv, true).unwrap().as_u64().unwrap();
                                let rcx_sym_bv = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x8, 64).unwrap().symbolic.to_bv(executor.context);
                                let rcx_val = model.eval(&rcx_sym_bv, true).unwrap().as_u64().unwrap();
                                let rdx_sym_bv = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x10, 64).unwrap().symbolic.to_bv(executor.context);
                                let rdx_val = model.eval(&rdx_sym_bv, true).unwrap().as_u64().unwrap();
                                let rbx_sym_bv = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x18, 64).unwrap().symbolic.to_bv(executor.context);
                                let rbx_val = model.eval(&rbx_sym_bv, true).unwrap().as_u64().unwrap();
                                let rsp_sym_bv = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x20, 64).unwrap().symbolic.to_bv(executor.context);
                                let rsp_val = model.eval(&rsp_sym_bv, true).unwrap().as_u64().unwrap();
                                let rbp_sym_bv = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x28, 64).unwrap().symbolic.to_bv(executor.context);
                                let rbp_val = model.eval(&rbp_sym_bv, true).unwrap().as_u64().unwrap();
                                let rsi_sym_bv = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x30, 64).unwrap().symbolic.to_bv(executor.context);
                                let rsi_val = model.eval(&rsi_sym_bv, true).unwrap().as_u64().unwrap();
                                let rdi_sym_bv = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x38, 64).unwrap().symbolic.to_bv(executor.context);
                                let rdi_val = model.eval(&rdi_sym_bv, true).unwrap().as_u64().unwrap();
                                let r8_sym_bv = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x80, 64).unwrap().symbolic.to_bv(executor.context);
                                let r8_val = model.eval(&r8_sym_bv, true).unwrap().as_u64().unwrap();
                                let r9_sym_bv = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x88, 64).unwrap().symbolic.to_bv(executor.context);
                                let r9_val = model.eval(&r9_sym_bv, true).unwrap().as_u64().unwrap();
                                let r10_sym_bv = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x90, 64).unwrap().symbolic.to_bv(executor.context);
                                let r10_val = model.eval(&r10_sym_bv, true).unwrap().as_u64().unwrap();
                                let r11_sym_bv = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x98, 64).unwrap().symbolic.to_bv(executor.context);
                                let r11_val = model.eval(&r11_sym_bv, true).unwrap().as_u64().unwrap();
                                let r12_sym_bv = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0xa0, 64).unwrap().symbolic.to_bv(executor.context);
                                let r12_val = model.eval(&r12_sym_bv, true).unwrap().as_u64().unwrap();
                                let r13_sym_bv = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0xa8, 64).unwrap().symbolic.to_bv(executor.context);
                                let r13_val = model.eval(&r13_sym_bv, true).unwrap().as_u64().unwrap();
                                let r14_sym_bv = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0xb0, 64).unwrap().symbolic.to_bv(executor.context);
                                let r14_val = model.eval(&r14_sym_bv, true).unwrap().as_u64().unwrap();
                                let r15_sym_bv = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0xb8, 64).unwrap().symbolic.to_bv(executor.context);
                                let r15_val = model.eval(&r15_sym_bv, true).unwrap().as_u64().unwrap();
                                let zf_sym_bv = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x206, 1).unwrap().symbolic.to_bv(executor.context);
                                let zf_val = model.eval(&zf_sym_bv, true).unwrap().as_u64().unwrap();
                                let cf_sym_bv = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x200, 1).unwrap().symbolic.to_bv(executor.context);
                                let cf_val = model.eval(&cf_sym_bv, true).unwrap().as_u64().unwrap();

                                log!(executor.state.logger, "Register evaluations:");
                                log!(executor.state.logger, "RAX: 0x{:x}", rax_val);
                                log!(executor.state.logger, "RCX: 0x{:x}", rcx_val);
                                log!(executor.state.logger, "RDX: 0x{:x}", rdx_val);
                                log!(executor.state.logger, "RBX: 0x{:x}", rbx_val);
                                log!(executor.state.logger, "RSP: 0x{:x}", rsp_val);
                                log!(executor.state.logger, "RBP: 0x{:x}", rbp_val);
                                log!(executor.state.logger, "RSI: 0x{:x}", rsi_val);
                                log!(executor.state.logger, "RDI: 0x{:x}", rdi_val);
                                log!(executor.state.logger, "R8: 0x{:x}", r8_val);
                                log!(executor.state.logger, "R9: 0x{:x}", r9_val);
                                log!(executor.state.logger, "R10: 0x{:x}", r10_val);
                                log!(executor.state.logger, "R11: 0x{:x}", r11_val);
                                log!(executor.state.logger, "R12: 0x{:x}", r12_val);
                                log!(executor.state.logger, "R13: 0x{:x}", r13_val);
                                log!(executor.state.logger, "R14: 0x{:x}", r14_val);
                                log!(executor.state.logger, "R15: 0x{:x}", r15_val);
                                log!(executor.state.logger, "ZF: 0x{:x}", zf_val);
                                log!(executor.state.logger, "CF: 0x{:x}", cf_val);

                                log!(executor.state.logger, "~~~~~~~~~~~");
                            }
            
                            // store these results or exit:
                            //process::exit(0);
                        //}
                        z3::SatResult::Unsat => {
                            log!(executor.state.logger, "~~~~~~~~~~~");
                            log!(executor.state.logger, "Branch to panic is UNSAT => no input can make that branch lead to panic");
                            log!(executor.state.logger, "~~~~~~~~~~~");
                        }
                        z3::SatResult::Unknown => {
                            log!(executor.state.logger, "Solver => Unknown feasibility");
                        }
                    }
            
                    // 6) pop the solver context
                    executor.solver.pop(1);
                } else {
                    log!(executor.state.logger, "The branching target is not a panic function, continuing the execution.");
                }
            }
            
            // Calculate the potential next address taken by RIP, for the purpose of updating the symbolic part of CBRANCH
            let (next_addr_in_map, _ ) = instructions_map.range((current_rip + 1)..).next().unwrap();

            // MAIN PART OF THE CODE
            // Execute the instruction and handle errors
            match executor.execute_instruction(inst.clone(), current_rip, *next_addr_in_map, &next_inst, instructions_map) {
                Ok(_) => {
                    // Check if the process has terminated
                    if executor.state.is_terminated {
                        log!(executor.state.logger, "Execution terminated with status: {:?}", executor.state.exit_status);
                        return; // Exit the function as execution has terminated
                    }
                }
                Err(e) => {
                    log!(executor.state.logger, "Execution error: {}", e);
                    if executor.state.is_terminated {
                        log!(executor.state.logger, "Process terminated via syscall with exit status: {:?}", executor.state.exit_status);
                        return; // Exit the function as execution has terminated
                    } else {
                        // Handle other errors as needed
                        log!(executor.state.logger, "Unhandled execution error: {}", e);
                        return; // Exit the function or handle the error appropriately
                    }
                }
            }

            // For debugging
            //log!(executor.state.logger, "Printing memory content around 0x{:x} with range 0x{:x}", address, range);
            //executor.state.print_memory_content(address, range);
            let register0x0 = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x0, 64).unwrap();
            log!(executor.state.logger,  "The value of register at offset 0x0 - RAX is {:x}", register0x0.concrete);
            let register0x8 = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x8, 64).unwrap();
            log!(executor.state.logger,  "The value of register at offset 0x8 - RCX is {:x}", register0x8.concrete);
            let register0x10 = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x10, 64).unwrap();
            log!(executor.state.logger,  "The value of register at offset 0x10 - RDX is {:x}", register0x10.concrete);
            let register0x18 = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x18, 64).unwrap();
            log!(executor.state.logger,  "The value of register at offset 0x18 - RBX is {:x}", register0x18.concrete);
            let register0x20 = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x20, 64).unwrap();
            log!(executor.state.logger,  "The value of register at offset 0x20 - RSP is {:x}", register0x20.concrete);
            let register0x28 = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x28, 64).unwrap();
            log!(executor.state.logger,  "The value of register at offset 0x28 - RBP is {:x}", register0x28.concrete);
            let register0x30 = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x30, 64).unwrap();
            log!(executor.state.logger,  "The value of register at offset 0x30 - RSI is {:x}", register0x30.concrete);
            let register0x38 = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x38, 64).unwrap();
            log!(executor.state.logger,  "The value of register at offset 0x38 - RDI is {:x}", register0x38.concrete);
            let register0x80 = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x80, 64).unwrap();
            log!(executor.state.logger,  "The value of register at offset 0x80 - R8 is {:x}", register0x80.concrete);
            let register0x88 = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x88, 64).unwrap();
            log!(executor.state.logger,  "The value of register at offset 0x88 - R9 is {:x}", register0x88.concrete);
            let register0x90 = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x90, 64).unwrap();
            log!(executor.state.logger,  "The value of register at offset 0x90 - R10 is {:x}", register0x90.concrete);
            let register0x98 = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x98, 64).unwrap();
            log!(executor.state.logger,  "The value of register at offset 0x98 - R11 is {:x}", register0x98.concrete);
            let register0xa0 = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0xa0, 64).unwrap();
            log!(executor.state.logger,  "The value of register at offset 0xa0 - R12 is {:x}", register0xa0.concrete);
            let register0xb0 = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0xb0, 64).unwrap();
            log!(executor.state.logger,  "The value of register at offset 0xb0 - R14 is {:x}", register0xb0.concrete);
            let register0xb8 = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0xb8, 64).unwrap();
            log!(executor.state.logger,  "The value of register at offset 0xb8 - R15 is {:x}", register0xb8.concrete);
            let register0x1200 = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x1200, 256).unwrap();
            log!(executor.state.logger,  "The value of register at offset 0x1200 - YMM0 is {:x}, i.e. {:?}", register0x1200.concrete, register0x1200.concrete);
            let register0x1220 = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x1220, 256).unwrap();
            log!(executor.state.logger,  "The value of register at offset 0x1220 - YMM1 is {:x}, i.e. {:?}", register0x1220.concrete, register0x1220.concrete);
            let register0x200 = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x200, 64).unwrap();
            log!(executor.state.logger,  "The value of register at offset 0x200 - CF is {:x}", register0x200.concrete);
            let register0x202 = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x202, 64).unwrap();
            log!(executor.state.logger,  "The value of register at offset 0x202 - PF is {:x}", register0x202.concrete);
            let register0x206 = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x206, 64).unwrap();
            log!(executor.state.logger,  "The value of register at offset 0x206 - ZF is {:x}", register0x206.concrete);
            let register0x207 = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x207, 64).unwrap();
            log!(executor.state.logger,  "The value of register at offset 0x207 - SF is {:x}", register0x207.concrete);
            let register0x20b = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x20b, 64).unwrap();
            log!(executor.state.logger,  "The value of register at offset 0x20b - OF is {:x}", register0x20b.concrete);
            let register0x110 = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x110, 64).unwrap();
            log!(executor.state.logger,  "The value of register at offset 0x110 - FS_OFFSET is {:x}", register0x110.concrete);

            // Check if there's a requested jump within the current block
            if executor.pcode_internal_lines_to_be_jumped != 0 {
                let proposed_jump_target = local_line_number + executor.pcode_internal_lines_to_be_jumped;
                // Ensure the jump target does not exceed the bounds of the instruction list
                let jump_target = if proposed_jump_target < instructions.len().try_into().unwrap() {
                    proposed_jump_target
                } else {
                    (instructions.len() - 1).try_into().unwrap()  // set to the last valid index if the calculated target is too high
                };

                log!(executor.state.logger, "Jumping from line {} to line {}", local_line_number, jump_target);
                executor.pcode_internal_lines_to_be_jumped = 0;  // Reset after handling
                local_line_number = jump_target;  // Perform the jump within the block
                continue;  // Move directly to the jump target line
            }

            // Update RIP if the instruction modifies it
            let possible_new_rip = executor.state.cpu_state.lock().unwrap()
                .get_register_by_offset(0x288, 64)
                .unwrap()
                .get_concrete_value()
                .unwrap();
            let possible_new_rip_hex = format!("{:x}", possible_new_rip);
            log!(executor.state.logger, "Possible new RIP: 0x{:x}", possible_new_rip);
            log!(executor.state.logger, "Current RIP: 0x{:x}", current_rip);
            log!(executor.state.logger, "local_line_number: {}, instructions.len()-1: {}", local_line_number, (instructions.len() - 1) as i64);

            // Check if there is a new RIP to set, beeing aware that all the instructions in the block have been executed, except for case with CBranch
            // FYI, the two blocks can not be put in a function because the varibales that are modified ar enot global, TODO: optimize this
            if inst.opcode == Opcode::CBranch {
                if possible_new_rip != current_rip {
                    log!(executor.state.logger, "Control flow change detected, new RIP: 0x{:x}", possible_new_rip);
                    if let Some(symbol_name_potential_new_rip) = executor.symbol_table.get(&possible_new_rip_hex) {
                        // Found a symbol, check if it's blacklisted, etc.
                        if IGNORED_TINYGO_FUNCS.contains(&symbol_name_potential_new_rip.as_str()) {
                            log!(executor.state.logger, "Skipping function '{:?}' at 0x{:x} because it is blacklisted.", symbol_name_potential_new_rip, current_rip);
    
                            // When skipping a function, we need to update the stack pointer i.e. add 8 to RSP
                            let rsp_value_concrete = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x20, 64).unwrap().concrete.to_u64();
                            let rsp_value_symbolic = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x20, 64).unwrap().symbolic.to_bv(executor.context).clone();
                            let next_rsp_value_concrete = rsp_value_concrete + 8;
                            let next_rsp_value_symbolic = rsp_value_symbolic.bvadd(&BV::from_u64(executor.context, 8, 64));
                            let next_rsp_value = ConcolicVar::new_concrete_and_symbolic_int(next_rsp_value_concrete, next_rsp_value_symbolic, executor.context, 64);
                            executor.state.cpu_state.lock().unwrap()
                                .set_register_value_by_offset(0x20, next_rsp_value, 64)
                                .expect("Failed to set register value by offset");
    
                            let (next_addr_in_map, _ ) = instructions_map.range((current_rip + 1)..).next().unwrap();
                            current_rip = *next_addr_in_map;
                            local_line_number = 0;      // Reset instruction index
                            end_of_block = true; // Indicate end of current block execution
                            log!(executor.state.logger, "Jumping to 0x{:x}", next_addr_in_map);
                        } else {
                            // Manage the case where the RIP update points beyond the current block
                            current_rip = possible_new_rip;
                            local_line_number = 0;  // Reset instruction index for new RIP
                            end_of_block = true; // Indicate end of current block execution
                            log!(executor.state.logger, "Control flow change detected, switching execution to new address: 0x{:x}", current_rip);
                        }
                    } else {
                        // Manage the case where the RIP update points beyond the current block
                        current_rip = possible_new_rip;
                        local_line_number = 0;  // Reset instruction index for new RIP
                        end_of_block = true; // Indicate end of current block execution
                        log!(executor.state.logger, "Control flow change detected, switching execution to new address: 0x{:x}", current_rip);
                    }
                } else {
                    // Regular progression to the next instruction
                    local_line_number += 1;
                }
            } else {
                if possible_new_rip != current_rip && local_line_number >= (instructions.len() - 1).try_into().unwrap() {
                    log!(executor.state.logger, "local_line_number: {}, instructions.len()-1: {}", local_line_number, (instructions.len() - 1) as i64);
                    log!(executor.state.logger, "Control flow change detected, new RIP: 0x{:x}", possible_new_rip);
                    if let Some(symbol_name_potential_new_rip) = executor.symbol_table.get(&possible_new_rip_hex) {
                        // Found a symbol, check if it's blacklisted, etc.
                        if IGNORED_TINYGO_FUNCS.contains(&symbol_name_potential_new_rip.as_str()) {
                            log!(executor.state.logger, "Skipping function '{:?}' at 0x{:x} because it is blacklisted.", symbol_name_potential_new_rip, current_rip);
    
                            // When skipping a function, we need to update the stack pointer i.e. add 8 to RSP
                            let rsp_value_concrete = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x20, 64).unwrap().concrete.to_u64();
                            let rsp_value_symbolic = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x20, 64).unwrap().symbolic.to_bv(executor.context).clone();
                            let next_rsp_value_concrete = rsp_value_concrete + 8;
                            let next_rsp_value_symbolic = rsp_value_symbolic.bvadd(&BV::from_u64(executor.context, 8, 64));
                            let next_rsp_value = ConcolicVar::new_concrete_and_symbolic_int(next_rsp_value_concrete, next_rsp_value_symbolic, executor.context, 64);
                            executor.state.cpu_state.lock().unwrap()
                                .set_register_value_by_offset(0x20, next_rsp_value, 64)
                                .expect("Failed to set register value by offset");
    
                            let (next_addr_in_map, _ ) = instructions_map.range((current_rip + 1)..).next().unwrap();
                            current_rip = *next_addr_in_map;
                            local_line_number = 0;      // Reset instruction index
                            end_of_block = true; // Indicate end of current block execution
                            log!(executor.state.logger, "Jumping to 0x{:x}", next_addr_in_map);
                        } else {
                            // Manage the case where the RIP update points beyond the current block
                            current_rip = possible_new_rip;
                            local_line_number = 0;  // Reset instruction index for new RIP
                            end_of_block = true; // Indicate end of current block execution
                            log!(executor.state.logger, "Control flow change detected, switching execution to new address: 0x{:x}", current_rip);
                        }
                    } else {
                        // Manage the case where the RIP update points beyond the current block
                        current_rip = possible_new_rip;
                        local_line_number = 0;  // Reset instruction index for new RIP
                        end_of_block = true; // Indicate end of current block execution
                        log!(executor.state.logger, "Control flow change detected, switching execution to new address: 0x{:x}", current_rip);
                    }
                } else {
                    // Regular progression to the next instruction
                    local_line_number += 1;
                }
            }
        }

        // Reset for new block or continue execution at new RIP if set within the block
        if !end_of_block {
            if let Some((&next_rip, _)) = instructions_map.range((current_rip + 1)..).next() {
                
                let next_rip_hex = format!("{:x}", next_rip);
                if let Some(symbol_name_new_rip) = executor.symbol_table.get(&next_rip_hex) {
                    // Found a symbol, check if it's blacklisted
                    if IGNORED_TINYGO_FUNCS.contains(&symbol_name_new_rip.as_str()) {
                        log!(executor.state.logger, "Skipping function '{:?}' at 0x{:x} because it is blacklisted.", symbol_name_new_rip, current_rip);

                        // When skipping a function, we need to update the stack pointer i.e. add 8 to RSP
                        let rsp_value_concrete = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x20, 64).unwrap().concrete.to_u64();
                        let rsp_value_symbolic = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x20, 64).unwrap().symbolic.to_bv(executor.context).clone();
                        let next_rsp_value_concrete = rsp_value_concrete + 8;
                        let next_rsp_value_symbolic = rsp_value_symbolic.bvadd(&BV::from_u64(executor.context, 8, 64));
                        let next_rsp_value = ConcolicVar::new_concrete_and_symbolic_int(next_rsp_value_concrete, next_rsp_value_symbolic, executor.context, 64);
                        executor.state.cpu_state.lock().unwrap()
                            .set_register_value_by_offset(0x20, next_rsp_value, 64)
                            .expect("Failed to set register value by offset");

                        let (next_addr_in_map, _ ) = instructions_map.range((current_rip + 1)..).next().unwrap();
                        current_rip = *next_addr_in_map;
                        local_line_number = 0;      // Reset instruction index
                        log!(executor.state.logger, "Jumping to 0x{:x}", next_addr_in_map);
                    }
                } else {
                    current_rip = next_rip;
                    local_line_number = 0;  // Reset for new block

                    let current_rip_symbolic = executor.state.cpu_state.lock().unwrap()
                        .get_register_by_offset(0x288, 64)
                        .unwrap()
                        .symbolic
                        .to_bv(executor.context)
                        .clone();

                    let next_rip_concolic = ConcolicVar::new_concrete_and_symbolic_int(next_rip, current_rip_symbolic, executor.context, 64);
                    executor.state.cpu_state.lock().unwrap()
                        .set_register_value_by_offset(0x288, next_rip_concolic, 64)
                        .expect("Failed to set register value by offset");

                    log!(executor.state.logger, "Moving to next address block: 0x{:x}", next_rip);
                }
            } else {
                log!(executor.state.logger, "No further instructions. Execution completed.");
                break;  // Exit the loop if there are no more instructions
            }
        }
    }
}

#[derive(Deserialize)]
struct FunctionSignature {
    address: String,
    function_name: String,
    arguments: Vec<FunctionArgument>,
}

#[derive(Deserialize)]
struct FunctionArgument {
    name: String,
    register: String,
}

