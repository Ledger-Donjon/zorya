#[cfg(test)]
mod integration_tests {
    use zorya::executor::ConcolicExecutor;
    use parser::parser::Inst;

    use zorya::state::State;
    use z3::Config;

    #[test]
fn test_pcode_execution() {
    // Initialize Z3 context and related components
    let config = Config::new();
    let context = z3::Context::new(&config);
    let state = State::new(&context);
    let mut executor = ConcolicExecutor::new(&context);

    // Define pcode instructions
    let pcode_lines = vec![
        "(unique,0x5380,1) = LOAD (const,0x55e4a78f0330,8) (register,0x0,8)",
        "(register,0x200,1) = INT_CARRY (unique,0x5380,1) (register,0x0,1)",
        "(unique,0x5380,1) = LOAD (const,0x55e4a78f0330,8) (register,0x0,8)"
    ];

    println!("Initial state: {}", state);
    println!("Executor: {:?}", executor);
    println!("Entering loop...");

    // Parse and execute the pcode instructions
    for line in pcode_lines {
        // Debug statement to check the line being processed
        println!("Processing line: {:?}", line);

        match line.parse::<Inst>() {
            Ok(inst) => {
                println!("Executing instruction: {:?}", inst);
                executor.execute_instruction(&inst);

                // Print state and concolic variable values after each instruction
                println!("Current state: {} \n \n", state);
                println!("**********************************");

                for (var_name, concolic_var) in state.get_all_concolic_vars() {
                    println!("Concolic variable {}: concrete = {}, symbolic = {:?}", 
                             var_name, concolic_var.concrete, concolic_var.symbolic);
                }
            },
            Err(e) => {
                panic!("Error parsing pcode line: {:?}, error: {:?}", line, e);
            }
        }
    }

    // Debug statement to check if the loop is exited
    println!("Exiting loop...");
    println!("Final state: {}", state);

    }

}
