#[cfg(test)]
mod integration_tests {
    use std::fs::File;
    use std::io::{self, BufRead};
    use zorya::concolic_var::ConcolicVar;
    use zorya::executor::ConcolicExecutor;
    use parser::parser::Inst;

    use z3::{Config, Context};

    #[test]
    fn test_execute_instruction_v3() {
        // Setup
        // Setup
        let config = Config::new();
        let context = Context::new(&config);
        let mut executor = ConcolicExecutor::new(&context);

        // Ensure memory address and offset variable are correctly initialized
        let memory_address: u64 = 0x55e4a78f0330;
        executor.state.memory.write_quad(memory_address, 0xDEADBEEF).expect("Failed to write to memory");

        let offset_var_name = "Register(0)";
        executor.state.set_var(&offset_var_name, ConcolicVar::new_concrete_and_symbolic_int(memory_address, &offset_var_name, &context, 64));

        // Define path to the file containing pcode instructions
        let path = "/home/kgorna/Documents/zorya/tests/pcode/calculus_low_pcode.txt";

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
                    executor.execute_instruction(inst);
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
