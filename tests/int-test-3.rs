#[cfg(test)]
mod integration_tests {
    use zorya::executor::ConcolicExecutor;
    use parser::parser::Inst;

    use z3::{Config, Context};

    #[test]
    fn test_execute_instruction_v3() {
        // Setup
        let config = Config::new();
        let context = Context::new(&config);
        let mut executor = ConcolicExecutor::new(&context);

        // Define pcode instructions
        let pcode_lines = vec![
            "(unique,0x5380,1) = LOAD (const,0x55e4a78f0330,8) (register,0x0,8)",
            "(register,0x200,1) = INT_CARRY (unique,0x5380,1) (register,0x0,1)",
        ];

        println!("Initial state: {}", executor.state);
        println!("***********************");

        for line in pcode_lines {
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
    }
}
