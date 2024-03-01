use std::{fs::File, io::{self, BufRead}};
use parser::parser::Inst;
use z3::{Config, Context};
use zorya::executor::ConcolicExecutor;

fn main() {
    let config = Config::new();
    let context = Context::new(&config);

    // binary path
    let binary_path = "/home/kgorna/Documents/tools/pcode-generator/tests/calculus/calculus";

    // Initialize the ConcolicExecutor, handling the Result properly
    let mut executor = match ConcolicExecutor::new(&context, binary_path) {
        Ok(executor) => executor,
        Err(e) => {
            eprintln!("Failed to initialize ConcolicExecutor: {}", e);
            return; 
        }
    };

    // path to the pcode file generated previously
    let path = "/home/kgorna/Documents/tools/pcode-generator/results/calculus_low_pcode.txt";
    let file = File::open(&path).expect("Could not open file");
    let reader = io::BufReader::new(file);

    let entry_point_address: u64 = 0x45fa00; // Entry point address
    let mut analysis_started = false; // Flag to indicate if analysis has started

    // Read each line from the pcode file
    for line in reader.lines().filter_map(Result::ok) {
        if line.trim_start().starts_with("0x") {
            if let Ok(address) = u64::from_str_radix(&line.trim()[2..], 16) {
                if address == entry_point_address {
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
                    // Execute the instruction at the current address
                    if let Some(addr) = executor.current_address {
                        //println!("Executing instruction at address 0x{:x}: {:?}", addr, inst);
                        executor.execute_instruction(inst, addr); 
                        //println!("State after instruction: {:?}", executor.state);
                        //println!("***********************");
                    }
                },
                Err(e) => println!("Error parsing instruction: {:?}", e),
            }
        }
    }

    // Final state after executing all instructions
    println!("Final state: {:?}", executor.state.concolic_vars); 
}
