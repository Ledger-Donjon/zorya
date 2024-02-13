use std::{fs::File, io::{self, BufRead}};
use parser::parser::Inst;
use z3::{Config, Context};
use zorya::executor::ConcolicExecutor;

fn main() {
    // Setup Z3 and Concolic Executor
    let config = Config::new();
    let context = Context::new(&config);
    let mut executor = ConcolicExecutor::new(&context);

    // Specify the path to the p-code file generated previously
    let path = "/home/kgorna/Documents/tools/pcode-generator/results/ptr_nil-deref_low_pcode.txt";
    let file = File::open(&path).expect("Could not open file");
    let reader = io::BufReader::new(file);

    // Initialize a variable to keep track of the current address
    let mut current_address: Option<u64> = None;

    // Read each line from the p-code file
    for line in reader.lines().filter_map(Result::ok) {
        if line.trim_start().starts_with("0x") {
            // This line specifies a new address
            if let Ok(address) = u64::from_str_radix(&line.trim()[2..], 16) {
                current_address = Some(address);
            }
        } else if let Some(addr) = current_address {
            // This line should contain an instruction, parse it
            match line.parse::<Inst>() {
                Ok(inst) => {
                    // Execute the instruction immediately
                    println!("Executing instruction at address 0x{:x}: {:?}", addr, inst);
                    executor.execute_instruction(inst, addr);
                    println!("State after instruction: {}", executor.state);
                    println!("***********************");
                },
                Err(e) => println!("Error parsing instruction: {:?}", e),
            }
        } else {
            // This case handles lines that are neither addresses nor parseable instructions
            println!("Line encountered without a current address set or is not a valid instruction: {}", line);
        }
    }

    // Final state after executing all instructions
    println!("Final state: {}", executor.state);
}

