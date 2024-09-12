use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, BufRead, Write};

use parser::parser::Inst;
use z3::{Config, Context};
use zorya::concolic::{ConcolicVar, Logger};
use zorya::executor::{ConcolicExecutor, SymbolicVar};
use zorya::target_info::GLOBAL_TARGET_INFO;

macro_rules! log {
    ($logger:expr, $($arg:tt)*) => {{
        writeln!($logger, $($arg)*).unwrap();
    }};
}

fn main() {
    let config = Config::new();
    let context = Context::new(&config);
    let logger = Logger::new("execution_log.txt").expect("Failed to create logger");
    let mut executor = ConcolicExecutor::new(&context, logger.clone()).expect("Failed to initialize the ConcolicExecutor.");
    
    log!(executor.state.logger, "Configuration and context have been initialized.");

    let (pcode_file_path, main_program_addr) = {
        let target_info = GLOBAL_TARGET_INFO.lock().unwrap();
        log!(executor.state.logger, "Acquired target information.");
        (target_info.pcode_file_path.clone(), target_info.main_program_addr.clone())
    };

    let pcode_file_path_str = pcode_file_path.to_str().expect("The file path contains invalid Unicode characters.");

    let instructions_map = preprocess_pcode_file(pcode_file_path_str, &mut executor.clone())
        .expect("Failed to preprocess the p-code file.");

    let start_address = u64::from_str_radix(&main_program_addr.trim_start_matches("0x"), 16)
        .expect("The format of the main program address is invalid.");

    execute_instructions_from(&mut executor, start_address, &instructions_map);

    log!(executor.state.logger, "The concolic execution has completed successfully.");
}

fn preprocess_pcode_file(path: &str, executor: &mut ConcolicExecutor) -> io::Result<BTreeMap<u64, Vec<Inst>>> {
    let file = File::open(path)?;
    let reader = io::BufReader::new(file);
    let mut instructions_map = BTreeMap::new();

    log!(executor.state.logger, "Preprocessing the p-code file...");

    for line in reader.lines().filter_map(Result::ok) {
        if line.trim_start().starts_with("0x") {
            let current_address = u64::from_str_radix(&line.trim()[2..], 16).unwrap();
            instructions_map.entry(current_address).or_insert_with(Vec::new);
        } else if let Some(inst) = line.parse::<Inst>().ok() {
            if let Some(current_address) = instructions_map.keys().last().copied() {
                instructions_map.get_mut(&current_address).unwrap().push(inst);
            }
        }
    }

    log!(executor.state.logger, "Completed preprocessing.");

    Ok(instructions_map)
}

fn execute_instructions_from(executor: &mut ConcolicExecutor, start_address: u64, instructions_map: &BTreeMap<u64, Vec<Inst>>) {
    let mut current_rip = start_address;
    let mut local_line_number = 0;  // Index of the current instruction within the block
    let end_address: u64 = 0x45d578;

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
            let _ = cpu_state_guard.set_register_value_by_offset(0x288, ConcolicVar::new_concrete_and_symbolic_int(current_rip, SymbolicVar::new_int(current_rip.try_into().unwrap(), executor.context, 64).to_bv(executor.context), executor.context, 64), 64).map_err(|e| e.to_string());
        }

        let mut end_of_block = false;

        while local_line_number < instructions.len() && !end_of_block {
            let inst = &instructions[local_line_number];
            log!(executor.state.logger, "-------> Processing instruction at index: {}, {:?}", local_line_number, inst);

            // Execute the instruction and handle errors
            if let Err(e) = executor.execute_instruction(inst.clone(), current_rip) {
                log!(executor.state.logger, "Failed to execute instruction: {}", e);
            }

            // For debugging
            //log!(executor.state.logger, "Printing memory content around 0x{:x} with range 0x{:x}", address, range);
            //executor.state.print_memory_content(address, range);
            let register0x0 = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x0, 64).unwrap();
            log!(executor.state.logger,  "The value of register at offset 0x0 - RAX is {:x}", register0x0.concrete);

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
            
            let register0x10 = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x10, 64).unwrap();
            log!(executor.state.logger,  "The value of register at offset 0x10 is {:x}", register0x10.concrete);
            let register0x18 = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x18, 64).unwrap();
            log!(executor.state.logger,  "The value of register at offset 0x18 is {:x}", register0x18.concrete);
            let register0x20 = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x20, 64).unwrap();
            log!(executor.state.logger,  "The value of register at offset 0x20 is {:x}", register0x20.concrete);
            let register0x30 = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x30, 64).unwrap();
            log!(executor.state.logger,  "The value of register at offset 0x30 is {:x}", register0x30.concrete);
            let register0x38 = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x38, 64).unwrap();
            log!(executor.state.logger,  "The value of register at offset 0x38 is {:x}", register0x38.concrete);
            let register0xb0 = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0xb0, 64).unwrap();
            log!(executor.state.logger,  "The value of register at offset 0xb0 is {:x}", register0xb0.concrete);
            let register0x110 = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x110, 64).unwrap();
            log!(executor.state.logger,  "The value of register at offset 0x110 is {:x}", register0x110.concrete);
            let register0x1200 = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x1200, 256).unwrap();
            log!(executor.state.logger,  "The value of register at offset 0x1200 - YMM0 is {:x}", register0x1200.concrete);
            
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