use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, BufRead, Write};

use parser::parser::{Inst, Opcode, Var};
use z3::ast::BV;
use z3::{Config, Context};
use zorya::concolic::{ConcolicVar, Logger};
use zorya::executor::ConcolicExecutor;
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
    let mut local_line_number = 0;

    log!(executor.state.logger, "Beginning execution from address: 0x{:x}", start_address);

    while let Some(instructions) = instructions_map.get(&current_rip) {
        log!(executor.state.logger, "*******************************************");
        log!(executor.state.logger, "EXECUTING INSTRUCTIONS AT ADDRESS: 0x{:x}", current_rip);
        log!(executor.state.logger, "*******************************************");

        while local_line_number < instructions.len() {
            let inst = &instructions[local_line_number];
            log!(executor.state.logger, "-------> Processing instruction at index: {}, {:?}\n", local_line_number, inst);

            if let Err(e) = executor.execute_instruction(inst.clone(), current_rip) {
                log!(executor.state.logger, "Failed to execute instruction: {}", e);
                continue; // Skip to the next iteration on failure.
            }

            // Branch handling based on constant values used to skip lines within the same block
            if matches!(inst.opcode, Opcode::Branch | Opcode::CBranch | Opcode::BranchInd) && matches!(inst.inputs[0].var, Var::Const(_)) {
                let skip_lines = executor.current_lines_number;
                local_line_number += skip_lines; // Perform the skip.
                log!(executor.state.logger, "Skipping {} lines to line {}", skip_lines, local_line_number);
            } else {
                local_line_number += 1; // Normal increment for the next instruction.
            }

            // Check for changes in the program counter.
            let new_rip = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x288, 64).unwrap().get_concrete_value().unwrap();
            if new_rip != current_rip {
                log!(executor.state.logger, "Control flow change detected, switching execution to new address: 0x{:x}", new_rip);
                current_rip = new_rip;
                local_line_number = 0; // Reset the line index at the new execution point.
                break; // Exit the current while loop to handle the new address block.
            }
        }

        // If finished all instructions in the block, check if there's a next address block.
        if local_line_number >= instructions.len() {
            local_line_number = 0; // Reset for the new loop.
            if let Some((&next_address, _)) = instructions_map.range((current_rip + 1)..).next() {
                current_rip = next_address;
                log!(executor.state.logger, "Moving to next sequential address: 0x{:x}", next_address);
            } else {
                log!(executor.state.logger, "No further instructions. Execution completed.");
                break;
            }
        }
    }
}
