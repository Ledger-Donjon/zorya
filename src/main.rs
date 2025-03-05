use std::collections::{BTreeMap, HashMap};
use std::env;
use std::error::Error;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{self, Command};
use parser::parser::{Inst, Opcode};
use serde::Deserialize;
use z3::ast::{Ast, Bool, Int, BV};
use z3::{Config, Context, Solver};
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

        // // Path to the Python script
        // let python_script_path = "src/get_function_args.py";
        // // Spawn the Python process
        // let output = Command::new("python3")
        //     .arg(python_script_path)
        //     .arg(binary_path)
        //     .arg(start_address_hex)
        //     .output()
        //     .expect("Failed to run python script");

        // if !output.status.success() {
        //     log!(executor.state.logger, "Python script returned an error code: {:?}", output.status);
        //     log!(executor.state.logger, "--- stderr ---\n{}", String::from_utf8_lossy(&output.stderr));
        // }

        // // Capture and print stdout from the script
        // let stdout = String::from_utf8_lossy(&output.stdout);
        // log!(executor.state.logger, "=== Pyhidra Script Output ===\n{stdout}");

    
    } else if mode == "start" {
        log!(executor.state.logger, "Updating argc and argv on the stack");
        update_argc_argv(&mut executor, &arguments)?;
        
    } else { // when mode is main, start or custom, no additional modification has to be done
        log!(executor.state.logger, "Continuing execution without modification.");
    }

    let osargslen = executor.state.memory.read_memory(0x235c50, 8);
    let osargs = executor.state.memory.read_memory(0x235c60, 64);
    log!(executor.state.logger, "os args are {:?}with lenght {:?}", osargs, osargslen);

    // CORE COMMAND
    execute_instructions_from(&mut executor, start_address, &instructions_map, &solver, &binary_path);

    log!(executor.state.logger, "The concolic execution has finished.");
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

                let branch_target_varnode = inst.inputs[0].clone();
                let branch_target_address = executor.extract_branch_target_address(&branch_target_varnode, inst.clone()).map_err(|e| e.to_string()).unwrap();
                
                // Check if there is a potential panic function call in this branching instruction
                if panic_address_ints.contains(&Int::from_u64(executor.context, branch_target_address)) {
                    log!(executor.state.logger, "Branching instruction with a potential panic function call detected at 0x{:x}", branch_target_address);
                    
                    // Get the symbolic representation of RIP
                    let rip = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x288, 64).unwrap();
                    let rip_symbolic = rip.symbolic.clone().to_int().unwrap();

                    // Create conditions for each panic address
                    let conditions: Vec<Bool> = panic_address_ints.iter()
                        .map(|panic_addr_int| rip_symbolic._eq(panic_addr_int))
                        .collect();

                    // Collect references to the conditions
                    let condition_refs: Vec<&Bool> = conditions.iter().collect();

                    // Assert that RIP can be any of the panic addresses
                    solver.push(); // Push context to prevent side effects
                    solver.assert(&Bool::or(executor.context, &condition_refs));

                    match solver.check() {
                        z3::SatResult::Sat => {
                            log!(executor.state.logger, "~~~~~~~~~~~");
                            log!(executor.state.logger, "SATISFIABLE: Symbolic execution can lead to a panic function.");
                            let model = solver.get_model().unwrap();
                            log!(executor.state.logger, "~~~~~~~~~~~\n");

                            // Retrieve concrete values of registers or variables as needed
                            // RAX:
                            let rax = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x0, 64).unwrap();
                            let rax_symbolic = rax.symbolic.clone().to_int().unwrap();
                            let rax_val = model.eval(&rax_symbolic, true).unwrap().as_u64().unwrap();

                            // Log the values
                            log!(executor.state.logger, "RIP can reach a panic function at 0x{:x}. RAX = 0x{:x}", model.eval(&rip_symbolic, true).unwrap().as_u64().unwrap(), rax_val);
                            process::exit(0); 
                        },
                        z3::SatResult::Unsat => {
                            log!(executor.state.logger, "~~~~~~~~~~~~~");
                            log!(executor.state.logger, "UNSATISFIABLE: Symbolic execution cannot reach any panic functions from current state. Continuing on the concrete execution...");
                            log!(executor.state.logger, "~~~~~~~~~~~~~\n");
                        },
                        z3::SatResult::Unknown => {
                            log!(executor.state.logger, "UNKNOWN: Solver could not determine satisfiability.");
                        },
                    }
                }
                //solver.pop(1); // Pop context to clean up assertions
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

// Function to add the arguments of the target binary from the user's command 
fn update_argc_argv(executor: &mut ConcolicExecutor, arguments: &str) -> Result<(), Box<dyn std::error::Error>> {
    let cpu_state_guard = executor.state.cpu_state.lock().unwrap();

    if arguments == "none" {
        log!(executor.state.logger, "ARGS is 'none', skipping argument setup.");
        return Ok(());
    }

    let args: Vec<String> = shell_words::split(arguments).expect("Failed to parse arguments");
    let argc = args.len() as u64;

    log!(executor.state.logger, "Extracted argc: {}", argc);
    log!(executor.state.logger, "Extracted argv: {:?}", args);

    let rsp_value = cpu_state_guard.get_register_by_offset(0x20, 64).unwrap().concrete.to_u64();
    log!(executor.state.logger, "RSP value: 0x{:x}", rsp_value);

    // Store argc at RSP
    let argc_symbolic = SymbolicVar::new_int(argc as i64, executor.context, 64);
    let argc_mem_value = MemoryValue::new(argc, argc_symbolic.to_bv(executor.context), 64);
    executor.state.memory.write_value(rsp_value, &argc_mem_value)?;
    log!(executor.state.logger, "Wrote argc at 0x{:x}: {}", rsp_value, argc);

    let argv_base_addr = rsp_value + 16;
    let mut string_memory_base = argv_base_addr + (args.len() as u64 * 8);

    for (i, arg) in args.iter().enumerate() {
        let arg_ptr_addr = argv_base_addr + (i as u64 * 8);
        let arg_string_addr = string_memory_base;
        string_memory_base += ((arg.len() as u64 + 8) / 8) * 8; // Ensure alignment

        // Write pointer to argv[i]
        let arg_ptr_symbolic = SymbolicVar::new_int(arg_string_addr as i64, executor.context, 64);
        let arg_ptr_mem_value = MemoryValue::new(arg_string_addr, arg_ptr_symbolic.to_bv(executor.context), 64);
        executor.state.memory.write_value(arg_ptr_addr, &arg_ptr_mem_value)?;
        log!(executor.state.logger, "Wrote argv[{}] pointer at 0x{:x}: 0x{:x}", i, arg_ptr_addr, arg_string_addr);

        // Convert argument string to ASCII bytes and store as u64 chunks
        let mut arg_bytes = arg.clone().into_bytes();
        arg_bytes.push(0); // NULL-terminate string

        for chunk in arg_bytes.chunks(8) {
            let mut chunk_data = [0u8; 8];
            chunk_data[..chunk.len()].copy_from_slice(chunk);
            let chunk_value = u64::from_le_bytes(chunk_data);

            let chunk_mem_value = MemoryValue::new(chunk_value, SymbolicVar::new_int(chunk_value as i64, executor.context, 64).to_bv(executor.context), 64);
            executor.state.memory.write_value(arg_string_addr + (chunk.as_ptr() as u64 - arg_bytes.as_ptr() as u64), &chunk_mem_value)?;
        }
    }

    // Write NULL terminator for argv
    let argv_null_addr = argv_base_addr + (args.len() as u64 * 8);
    let null_ptr_symbolic = SymbolicVar::new_int(0, executor.context, 64);
    let null_mem_value = MemoryValue::new(0, null_ptr_symbolic.to_bv(executor.context), 64);
    executor.state.memory.write_value(argv_null_addr, &null_mem_value)?;
    log!(executor.state.logger, "Wrote NULL terminator at 0x{:x}", argv_null_addr);

    Ok(())
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