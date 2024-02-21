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

        // Initialize a variable to keep track of the current address
        let mut current_address: Option<u64> = None;

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
            if line.trim_start().starts_with("0x") {
                // Specify a new address
                if let Ok(address) = u64::from_str_radix(&line.trim()[2..], 16) {
                    current_address = Some(address);
                }
            } else if let Some(addr) = current_address {
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
                // Handle lines that are neither addresses nor parseable instructions
                println!("Line encountered without a current address set or is not a valid instruction: {}", line);
            }
        }
    }
}
