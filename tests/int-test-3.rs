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
            "(unique,0x3b80,1) = LOAD (const,0x556f90707d40,8) (register,0x0,4)",
            "(register,0x200,1) = INT_CARRY (unique,0x3b80,1) (register,0x0,1)",
            "(unique,0x3b80,1) = LOAD (const,0x556f90707d40,8) (register,0x0,4)",
            "(register,0x20b,1) = INT_SCARRY (unique,0x3b80,1) (register,0x0,1)",
            "(unique,0x3b80,1) = LOAD (const,0x556f90707d40,8) (register,0x0,4)",
            "(unique,0x3b80,1) = INT_ADD (unique,0x3b80,1) (register,0x0,1)",
            "(unique,0x3b80,1) = LOAD (const,0x556f90707d40,8) (register,0x0,4)",
            "(register,0x207,1) = INT_SLESS (unique,0x3b80,1) (const,0x0,1)",
            "(unique,0x3b80,1) = LOAD (const,0x556f90707d40,8) (register,0x0,4)",
            "(register,0x206,1) = INT_EQUAL (unique,0x3b80,1) (const,0x0,1)",
            "(unique,0x3b80,1) = LOAD (const,0x556f90707d40,8) (register,0x0,4)",
            "(unique,0xdd00,1) = INT_AND (unique,0x3b80,1) (const,0xff,1)",
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
