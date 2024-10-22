use std::collections::BTreeMap;
use std::error::Error;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{self, Command};

use parser::parser::{Inst, Opcode};
use z3::ast::{Ast, Bool, Int};
use z3::{Config, Context, Solver};
use zorya::concolic::{ConcolicVar, Logger};
use zorya::executor::{ConcolicExecutor, SymbolicVar};
use zorya::target_info::GLOBAL_TARGET_INFO;

macro_rules! log {
    ($logger:expr, $($arg:tt)*) => {{
        writeln!($logger, $($arg)*).unwrap();
    }};
}

fn main() -> Result<(), Box<dyn Error>> {
    let config = Config::new();
    let context = Context::new(&config);
    let solver = Solver::new(&context);
    let logger = Logger::new("execution_log.txt").expect("Failed to create logger");
    let mut executor: ConcolicExecutor<'_> = ConcolicExecutor::new(&context, logger.clone()).expect("Failed to initialize the ConcolicExecutor.");
    
    log!(executor.state.logger, "Configuration and context have been initialized.");

    let (binary_path, pcode_file_path, main_program_addr) = {
        let target_info = GLOBAL_TARGET_INFO.lock().unwrap();
        log!(executor.state.logger, "Acquired target information.");
        (target_info.binary_path.clone(), target_info.pcode_file_path.clone(), target_info.main_program_addr.clone())
    };
    log!(executor.state.logger, "Binary path: {}", binary_path);
    let pcode_file_path_str = pcode_file_path.to_str().expect("The file path contains invalid Unicode characters.");

    // Get the path to the python script and run it
    let zorya_dir = {
        let info = GLOBAL_TARGET_INFO.lock().unwrap();
        info.zorya_path.clone()
    };
    let python_script_path = zorya_dir.join("src").join("find_panic_xrefs.py");

    if !python_script_path.exists() {
        panic!("Python script not found at {:?}", python_script_path);
    }

    let output = Command::new("python3")
        .arg(python_script_path)
        .arg(&binary_path)
        .output()
        .expect("Failed to execute Python script");

    // Check if the script ran successfully
    if !output.status.success() {
        eprintln!("Python script error: {}", String::from_utf8_lossy(&output.stderr));
        return Err(Box::from("Python script failed"));
    } else {
        log!(executor.state.logger, "Python script executed successfully");
        // Optionally, print the script's stdout
        log!(executor.state.logger, "Python script output:\n{}", String::from_utf8_lossy(&output.stdout));
    }

    // Ensure the file was created
    if !Path::new("xref_addresses.txt").exists() {
        panic!("xref_addresses.txt not found after running the Python script");
    }

    // Populate the symbol table
    let elf_data = fs::read(binary_path)?;
    executor.populate_symbol_table(&elf_data)?;
    log!(executor.state.logger, "Symbol table has been populated:{:?}", executor.symbol_table);

    let instructions_map = preprocess_pcode_file(pcode_file_path_str, &mut executor.clone())
        .expect("Failed to preprocess the p-code file.");

    let start_address = u64::from_str_radix(&main_program_addr.trim_start_matches("0x"), 16)
        .expect("The format of the main program address is invalid.");

    // CORE COMMAND
    execute_instructions_from(&mut executor, start_address, &instructions_map, &solver);

    log!(executor.state.logger, "The concolic execution has completed successfully.");
    Ok(())
}

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

    log!(executor.state.logger, "Completed preprocessing.");

    Ok(instructions_map)
}

// helper function
fn read_panic_addresses(executor: &mut ConcolicExecutor, filename: &str) -> io::Result<Vec<u64>> {
    let file = File::open(filename)?;
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

fn execute_instructions_from(executor: &mut ConcolicExecutor, start_address: u64, instructions_map: &BTreeMap<u64, Vec<Inst>>, solver: &Solver) {
    let mut current_rip = start_address;
    let mut local_line_number = 0;  // Index of the current instruction within the block
    let end_address: u64 = 0x213afc;

    // For debugging
    //let address: u64 = 0x7fffffffe4b0;
    //let range = 0x8; 

    log!(executor.state.logger, "Beginning execution from address: 0x{:x}", start_address);

    while let Some(instructions) = instructions_map.get(&current_rip) {
        if current_rip == end_address {
            log!(executor.state.logger, "END ADDRESS 0x{:x} REACHED, STOP THE EXECUTION", end_address);
            break; // Stop execution if end address is reached
        }
        
        log!(executor.state.logger, "*******************************************");
        log!(executor.state.logger, "EXECUTING INSTRUCTIONS AT ADDRESS: 0x{:x}", current_rip);
        log!(executor.state.logger, "*******************************************");

        {
            let mut cpu_state_guard = executor.state.cpu_state.lock().unwrap();
            cpu_state_guard.set_register_value_by_offset(0x288, ConcolicVar::new_concrete_and_symbolic_int(current_rip, SymbolicVar::new_int(current_rip.try_into().unwrap(), executor.context, 64).to_bv(executor.context), executor.context, 64), 64).map_err(|e| e.to_string()).unwrap();
        }

        let mut end_of_block = false;
 
        while local_line_number < instructions.len() && !end_of_block {
            let inst = &instructions[local_line_number];
            log!(executor.state.logger, "-------> Processing instruction at index: {}, {:?}", local_line_number, inst);

            // Execute the instruction and handle errors
            match executor.execute_instruction(inst.clone(), current_rip) {
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
            //let register0x0 = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x0, 64).unwrap();
            //log!(executor.state.logger,  "The value of register at offset 0x0 - RAX is {:x}", register0x0.concrete);
            //let register0x8 = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x8, 64).unwrap();
            //log!(executor.state.logger,  "The value of register at offset 0x8 - RCX is {:x}", register0x8.concrete);
            //let register0x10 = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x10, 64).unwrap();
            //log!(executor.state.logger,  "The value of register at offset 0x10 - RDX is {:x}", register0x10.concrete);
            //let register0x18 = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x18, 64).unwrap();
            //log!(executor.state.logger,  "The value of register at offset 0x18 is {:x}", register0x18.concrete);
            // let register0x20 = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x20, 64).unwrap();
            // log!(executor.state.logger,  "The value of register at offset 0x20 is {:x}", register0x20.concrete);
            // let register0x28 = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x28, 64).unwrap();
            // log!(executor.state.logger,  "The value of register at offset 0x28 is {:x}", register0x28.concrete);
            // let register0x30 = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x30, 64).unwrap();
            // log!(executor.state.logger,  "The value of register at offset 0x30 is {:x}", register0x30.concrete);
            // let register0x38 = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x38, 64).unwrap();
            // log!(executor.state.logger,  "The value of register at offset 0x38 is {:x}", register0x38.concrete);
            // let register0xa0 = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0xa0, 64).unwrap();
            // log!(executor.state.logger,  "The value of register at offset 0xa0 - R12 is {:x}", register0xa0.concrete);
            // let register0xb0 = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0xb0, 64).unwrap();
            // log!(executor.state.logger,  "The value of register at offset 0xb0 - R14 is {:x}", register0xb0.concrete);
            // let register0x110 = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x110, 64).unwrap();
            // log!(executor.state.logger,  "The value of register at offset 0x110 is {:x}", register0x110.concrete);
            // let register0x1200 = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x1200, 256).unwrap();
            // log!(executor.state.logger,  "The value of register at offset 0x1200 - YMM0 is {:?}, i.e. when formatted {:x}", register0x1200.concrete, register0x1200.concrete);
            // let register0x200 = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x200, 64).unwrap();
            // log!(executor.state.logger,  "The value of register at offset 0x200 - CF is {:x}", register0x200.concrete);
            // let register0x202 = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x202, 64).unwrap();
            // log!(executor.state.logger,  "The value of register at offset 0x202 - PF is {:x}", register0x202.concrete);
            // let register0x206 = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x206, 64).unwrap();
            // log!(executor.state.logger,  "The value of register at offset 0x206 - ZF is {:x}", register0x206.concrete);
            // let register0x207 = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x207, 64).unwrap();
            // log!(executor.state.logger,  "The value of register at offset 0x207 - SF is {:x}", register0x207.concrete);
            // let register0x20b = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x20b, 64).unwrap();
            // log!(executor.state.logger,  "The value of register at offset 0x20b - OF is {:x}", register0x20b.concrete);
            //let register0x98 = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x98, 64).unwrap();
            //log!(executor.state.logger,  "The value of register at offset 0x98 is {:x}", register0x98.concrete);
            //let register0x110 = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x110, 64).unwrap();
            //log!(executor.state.logger,  "The value of register at offset 0x110 - FS_OFFSET is {:x}", register0x110.concrete);

            // Symbolic checks
            if inst.opcode != Opcode::CBranch && inst.opcode != Opcode::BranchInd && inst.opcode != Opcode::CallInd {
                // Read the panic addresses from the file once before the main loop
                let panic_addresses = read_panic_addresses(executor, "xref_addresses.txt").expect("Failed to read panic addresses");

                // Convert panic addresses to Z3 Ints once
                let panic_address_ints: Vec<Int> = panic_addresses.iter()
                    .map(|&addr| Int::from_u64(executor.context, addr))
                    .collect();

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
                        log!(executor.state.logger, "SATISFIABLE: Execution can lead to a panic function.");
                        let model = solver.get_model().unwrap();

                        // Retrieve concrete values of registers or variables as needed
                        // Example for RAX:
                        let rax = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x0, 64).unwrap();
                        let rax_symbolic = rax.symbolic.clone().to_int().unwrap();
                        let rax_val = model.eval(&rax_symbolic, true).unwrap().as_u64().unwrap();

                        // Log the values
                        log!(executor.state.logger, "RIP can reach a panic function at 0x{:x}. RAX = 0x{:x}", model.eval(&rip_symbolic, true).unwrap().as_u64().unwrap(), rax_val);
                        process::exit(0); // Exit if desired
                    },
                    z3::SatResult::Unsat => {
                        log!(executor.state.logger, "UNSATISFIABLE: Execution cannot reach any panic functions from current state.");
                    },
                    z3::SatResult::Unknown => {
                        log!(executor.state.logger, "UNKNOWN: Solver could not determine satisfiability.");
                    },
                }
                //solver.pop(1); // Pop context to clean up assertions
            }

            // Check if there's a requested jump within the current block
            if executor.pcode_internal_lines_to_be_jumped > 0 {
                let proposed_jump_target = local_line_number + executor.pcode_internal_lines_to_be_jumped;
                // Ensure the jump target does not exceed the bounds of the instruction list
                let jump_target = if proposed_jump_target < instructions.len() {
                    proposed_jump_target
                } else {
                    instructions.len() - 1  // set to the last valid index if the calculated target is too high
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

            if possible_new_rip != current_rip && local_line_number >= instructions.len() - 1 {
                // Manage the case where the RIP update points beyond the current block
                current_rip = possible_new_rip;
                local_line_number = 0;  // Reset instruction index for new RIP
                end_of_block = true; // Indicate end of current block execution
                log!(executor.state.logger, "Control flow change detected, switching execution to new address: 0x{:x}", current_rip);
            } else {
                // Regular progression to the next instruction
                local_line_number += 1;
            }
        }

        // Reset for new block or continue execution at new RIP if set within the block
        if !end_of_block {
            if let Some((&next_rip, _)) = instructions_map.range((current_rip + 1)..).next() {
                current_rip = next_rip;
                local_line_number = 0;  // Reset for new block
                log!(executor.state.logger, "Moving to next address block: 0x{:x}", next_rip);
            } else {
                log!(executor.state.logger, "No further instructions. Execution completed.");
                break;  // Exit the loop if there are no more instructions
            }
        }
    }
}
