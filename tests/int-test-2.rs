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
            output: Some(Varnode { var: Register(21376), size: Size::Byte }),
            inputs: vec![
                Varnode { var: Const("0x55e4a78f0330".to_string()), size: Size::Byte },
                Varnode { var: Register(0), size: Size::Byte }
            ],
        };

        // Mock Data for INT_CARRY instruction
        let carry_inst = Inst {
            opcode: Opcode::IntCarry,
            output: Some(Varnode { var: Register(512), size: Size::Byte }),
            inputs: vec![
                Varnode { var: Unique(21376), size: Size::Byte },
                Varnode { var: Register(0), size: Size::Byte },
            ],
        };


    
        println!("Initial state: {}", executor.state);
        println!("***********************");

        // Execution
        println!("Executing LOAD instruction: {:?}", load_inst);
        if let Err(e) = executor.handle_load(load_inst.clone()) {
            println!("Error executing LOAD: {}", e);
        } else {
            println!("State after LOAD: {}", executor.state);
        }
        println!("***********************");
        println!("State before INT_CARRY: {}", executor.state);
        println!("Executing INT_CARRY instruction: {:?}", carry_inst);
        if let Err(e) = executor.handle_int_carry(carry_inst) {
            println!("Error executing INT_CARRY: {}", e);
        } else {
            println!("State after INT_CARRY: {}", executor.state);
        }
        println!("***********************");
        println!("Executing LOAD instruction: {:?}", load_inst);
        if let Err(e) = executor.handle_load(load_inst) {
            println!("Error executing LOAD: {}", e);
        } else {
            println!("State after LOAD: {}", executor.state);
        }
        println!("***********************");

        println!("Final state: {}", executor.state);
    }
}