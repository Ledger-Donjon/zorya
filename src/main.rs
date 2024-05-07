/// Main code to perform the concolic execution on the target binary described in /src/target_info.rs

use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::{self, BufRead};

use parser::parser::Inst;
use z3::{Config, Context};
use zorya::executor::ConcolicExecutor;
use zorya::state::CpuState;
use zorya::target_info::GLOBAL_TARGET_INFO;

fn main() {
    let config = Config::new();
    let context = Context::new(&config);

    println!("Configuration and context have been initialized.");

    let (pcode_file_path, main_program_addr) = {
        let target_info = GLOBAL_TARGET_INFO.lock().unwrap();
        println!("Acquired target information.");
        (target_info.pcode_file_path.clone(), target_info.main_program_addr.clone())
    };

    let pcode_file_path_str = pcode_file_path.to_str().expect("The file path contains invalid Unicode characters.");

    let instructions_map = preprocess_pcode_file(pcode_file_path_str)
        .expect("Failed to preprocess the p-code file.");

    let start_address = u64::from_str_radix(&main_program_addr.trim_start_matches("0x"), 16)
        .expect("The format of the main program address is invalid.");

    let mut executor = ConcolicExecutor::new(&context).expect("Failed to initialize the ConcolicExecutor.");

    execute_instructions_from(&mut executor, start_address, &instructions_map);

    println!("The concolic execution has completed successfully.");
}

fn preprocess_pcode_file(path: &str) -> io::Result<BTreeMap<u64, Vec<Inst>>> {
    let file = File::open(path)?;
    let reader = io::BufReader::new(file);
    let mut instructions_map = BTreeMap::new();

    println!("Preprocessing the p-code file...");

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

    println!("Completed preprocessing.");

    Ok(instructions_map)
}

fn execute_instructions_from(executor: &mut ConcolicExecutor, start_address: u64, instructions_map: &BTreeMap<u64, Vec<Inst>>) {
    let mut executed_addresses = HashSet::new();
    let mut current_rip = start_address;

    println!("Beginning execution from address: 0x{:x}\n", start_address);

    while let Some(instructions) = instructions_map.get(&current_rip) {
        if !executed_addresses.insert(current_rip) {
            println!("Detected a loop or previously executed address. Stopping execution.");
            break;
        }
        println!("*******************************************");
        println!("EXECUTING INSTRUCTIONS AT ADDRESS: 0x{:x}", current_rip);
        println!("*******************************************\n");

        let mut branch_taken = false;

        for inst in instructions {
            println!("-------> Processing instruction : {:?}\n", inst);
            if let Err(e) = executor.execute_instruction(inst.clone(), current_rip) {
                println!("Failed to execute instruction: {}", e);
                continue;
            }

            // Check if the instruction is a branch instruction by examining the opcode
            if matches!(inst.opcode, parser::parser::Opcode::Branch | parser::parser::Opcode::CBranch | parser::parser::Opcode::BranchInd) {
                branch_taken = true;
                break; // Exit the loop to follow the branch
            }
        }

        // Update the current_rip based on whether a branch was taken
        if branch_taken {
            let cpu_state_guard = executor.state.cpu_state.lock()
                .expect("Failed to lock CPU state");
            current_rip = get_current_rip_address(&*cpu_state_guard); // Fetch the updated rip value after a branch
        } else {
            // If no branch was taken, find the next sequential address in the BTreeMap
            if let Some((&next_address, _)) = instructions_map.range((current_rip + 1)..).next() {
                current_rip = next_address; // Move to the next instruction address
            } else {
                println!("No further instructions. Execution completed.");
                break;
            }
        }
    }
}

fn get_current_rip_address(cpu_state: &CpuState) -> u64 {
    // Directly access the `rip` register from `CpuState`
    cpu_state.get_register_value("rip")
        .expect("Failed to retrieve RIP register value")
}