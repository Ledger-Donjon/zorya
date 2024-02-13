#[cfg(test)]
mod integration_tests {
    use std::fs::File;
    use std::io::{self, BufRead};
    use zorya::executor::ConcolicExecutor;
    use parser::parser::{Inst, Opcode};
    use z3::{Config, Context};

    #[test]
    fn test_execute_instruction_v3() {
        // Setup
        let config = Config::new();
        let context = Context::new(&config);
        let mut executor = ConcolicExecutor::new(&context);

        // Define path to the file containing pcode instructions
        let path = "/home/kgorna/Documents/tools/pcode-generator/results/ptr_nil-deref_low_pcode.txt";

        // Open the file
        let file = File::open(&path).expect("Could not open file");
        let reader = io::BufReader::new(file);

        println!("Initial state: {}", executor.state);
        println!("***********************");

        // Iterate over each line in the file
        for line in reader.lines() {
            let line = line.expect("Could not read line");
            match line.parse::<Inst>() {
                Ok(inst) => {
                    // Do something with the successfully parsed instruction
                    println!("Successfully parsed instruction: {:?}", inst);
                    match inst.opcode {
                        Opcode::Load => {
                            if let Some(offset_varnode) = inst.inputs.get(1) {
                                if let Some(_offset_var) = executor.state.get_concolic_var(&format!("{:?}", offset_varnode.var)) {
                                    executor.execute_instruction(inst);
                                } else {
                                    println!("Offset variable not found");
                                    // Handle the error, e.g., log it or return an error
                                }
                            } else {
                                println!("Offset variable not provided");
                                // Handle the error, e.g., log it or return an error
                            }
                        },
                        _ => {
                            // For other instructions, just execute them without checking offset
                            executor.execute_instruction(inst);
                        }
                    }
                    println!("State after instruction: {} \n", executor.state);
                    println!("***********************");
                },
                Err(e) => {
                    // Handle the error, e.g., log it or exit
                    println!("Error parsing line: {:?}, error: {:?}", line, e);
                }
            }
        }
        println!("Final state: {}", executor.state);
    }
}
