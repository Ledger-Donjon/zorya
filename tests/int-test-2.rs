#[cfg(test)]
mod integration_tests {
    use zorya::executor::ConcolicExecutor;
    use parser::parser::{Inst, Varnode, Size, Opcode};
    use parser::parser::Var::{Unique, Const, Register};

    use z3::{Config, Context};

    #[test]
    fn test_execute_instruction() {
        // Setup
        let config = Config::new();
        let context = Context::new(&config);
        let mut executor = ConcolicExecutor::new(&context);

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
        let carry_inst = Inst {
            opcode: Opcode::IntCarry,
            output: Some(Varnode { var: Register(0x200), size: Size::Byte }),
            inputs: vec![
                Varnode { var: Register(0x5380), size: Size::Byte },
                Varnode { var: Register(0x0), size: Size::Byte },
            ],
        };

        println!("Initial state: {}", executor.state);
        println!("***********************");

        // Execution
        println!("Executing instruction: {:?}", load_inst);
        executor.execute_instruction(&load_inst);
        println!("State after LOAD: {} \n", executor.state);
        
        println!("***********************");
        
        println!("Executing instruction: {:?}", carry_inst);
        executor.execute_instruction(&carry_inst);
        println!("State after INT_CARRY: {}", executor.state);
        
        println!("***********************");
        println!("Final state: {}", executor.state);

    }
}
