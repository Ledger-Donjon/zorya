#[cfg(test)]
mod integration_tests {
    use zorya::executor::ConcolicExecutor;
    use parser::parser::{Inst, Var, Varnode, Size, Opcode};
    use parser::parser::Var::{Unique, Const, Register};

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
            "(unique,0x5380,1) = LOAD (const,0x55e4a78f0330,8) (register,0x0,8)"
        ];

        for line in pcode_lines {
            match line.parse::<Inst>() {
                Ok(inst) => {
                    // Do something with the successfully parsed instruction
                    println!("Successfully parsed instruction: {:?}", inst);
                    executor.execute_instruction(&inst);
                    println!("State after instruction: {} \n", executor.state);
                    println!("***********************");
                },
                Err(e) => {
                    // Handle the error, e.g., log it or exit
                    println!("Error parsing line: {:?}, error: {:?}", line, e);
                }
            }
        }

        // TESTING WITHOUT A LOOP

        // Mock Data for LOAD instruction
        let load_inst = Inst {
            opcode: Opcode::Load,
            output: Some(Varnode { var: Unique(21376), size: Size::Byte }),
            inputs: vec![
                Varnode { var: Const("0x55e4a78f0330".to_string()), size: Size::Quad },
                Varnode { var: Register(0), size: Size::Quad }
            ],
        };
    

        // Mock Data for INT_CARRY instruction
        let carry_input1 = Var::Unique(21376);
        let carry_input2 = Var::Register(0x0);
        let carry_output = Var::Register(0x200);
        let carry_inst = Inst {
            opcode: Opcode::IntCarry,
            output: Some(Varnode { var: carry_output, size: Size::Byte }),
            inputs: vec![
                Varnode { var: carry_input1, size: Size::Byte },
                Varnode { var: carry_input2, size: Size::Byte },
            ],
        };

        println!("Executing instruction: {:?}", load_inst);
        println!("Initial state: {}", executor.state);
        println!("Executor: {:?}", executor);

        // Execution
        executor.execute_instruction(&load_inst);
        println!("State after LOAD: {}", executor.state);
        println!("Executor: {:?}", executor);
        println!("TEEEEEEEESSST");
        executor.execute_instruction(&carry_inst);
        println!("State after INT_CARRY: {}", executor.state);
        println!("Executor: {:?}", executor);

        println!("Final state: {}", executor.state);

    }
}
