#[cfg(test)]
mod integration_tests {
    use std::fs::File;
    use std::io::{self, BufRead};
    use zorya::executor::ConcolicExecutor;
    use parser::parser::Inst;

    use z3::{Config, Context};

    #[test]
    fn test_execute_instruction_v3() {
        // Setup
        let config = Config::new();
        let context = Context::new(&config);
        let mut executor = ConcolicExecutor::new(&context);

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
                    // println!("Successfully parsed instruction: {:?}", inst);
                    executor.execute_instruction(inst);
                    println!("done");
                    // println!("State after instruction: {} \n", executor.state);
                    // println!("***********************");
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
