/// Main code to perform the concolic execution on the target binary described in /src/target_info.rs

use zorya::state::cpu_state::GLOBAL_CPU_STATE;
use zorya::target_info::GLOBAL_TARGET_INFO;

use std::{fs::File, io::{self, BufRead}};
use parser::parser::Inst;
use z3::{Config, Context};
use zorya::executor::ConcolicExecutor;

fn main() {
    let config = Config::new();
    let context = Context::new(&config);

    println!("Config, context and global info initialized.");

    // Use paths from GLOBAL_TARGET_INFO by cloning them to avoid concurency
    let (binary_path, pcode_file_path, main_program_addr) = {
        let target_info = GLOBAL_TARGET_INFO.lock().unwrap();
        (target_info.binary_path.clone(), target_info.pcode_file_path.clone(), target_info.main_program_addr.clone())
    };

    // Convert PathBuf to a string slice
    let binary_path_str = binary_path.as_str();
    
    println!("Attempting to initialize ConcolicExecutor...");
    let mut executor = match ConcolicExecutor::new(&context, binary_path_str) {
        Ok(executor) => {
            println!("ConcolicExecutor successfully initialized.");
            executor
        },
        Err(e) => {
            eprintln!("Failed to initialize ConcolicExecutor: {}", e);
            return;
        }
    };

    // Load the pcode file
    let file = File::open(&pcode_file_path).expect("Could not open file");
    let reader = io::BufReader::new(file);

    // Start analysis directly at main_program_addr instead of finding the entry point
    let start_address = u64::from_str_radix(&main_program_addr.trim_start_matches("0x"), 16).expect("Invalid main program address");

    // Set analysis_started flag to true if you are no longer looking for a specific start point
    let mut analysis_started = true;

    // Set initial RIP value
    let mut cpu_state_lock = GLOBAL_CPU_STATE.lock().unwrap();
    cpu_state_lock.set_register_value_by_name("rip", main_program_addr.clone());
    drop(cpu_state_lock); // Explicitly drop the lock here to avoid holding it unnecessarily

    println!(">>> Starting concolic execution at address: {}", main_program_addr);

    for line in reader.lines().filter_map(Result::ok) {

        let cpu_state_lock = GLOBAL_CPU_STATE.lock().unwrap();
        let rip_value = cpu_state_lock.get_register_value_by_name("rip").unwrap().clone();
        let current_address = u64::from_str_radix(&rip_value.trim_start_matches("0x"), 16).unwrap();
        drop(cpu_state_lock); // Explicitly drop the lock (important)

        if line.trim_start().starts_with("0x") {
            if let Ok(address) = u64::from_str_radix(&line.trim()[2..], 16) {
                if address == start_address {
                    analysis_started = true; // Start analysis from this point
                }
                if !analysis_started {
                    continue; // Skip lines until the entry point is reached
                }
                // Update the current address being processed
                executor.current_address = Some(address);
            }
        } else if analysis_started {
            // Process the instruction at the current address
            match line.parse::<Inst>() {
                Ok(inst) => {
                    // Execute the instruction at the current address from RIP
                    //println!("Executing instruction at address 0x{:x}: {:?}", current_address, inst);
                    let _ = executor.execute_instruction(inst, current_address); 
                    //println!("State after instruction: {:?}", executor.state);
                    //println!("***********************");   
                },
                Err(e) => println!("Error parsing instruction: {:?}", e),
            }
        }
    }

    // Final state after executing all instructions
    println!("Final state: {:?}", executor.state.concolic_vars); 
}