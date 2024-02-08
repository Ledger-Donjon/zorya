#[cfg(test)]
mod integration_tests {
    use zorya::concolic_var::ConcolicVar;
    use zorya::executor::ConcolicExecutor;
    use parser::parser::{Inst, Varnode, Size, Opcode};
    use parser::parser::Var::{Unique, Const, Register};

    use z3::{Config, Context};

    #[test]
    fn test_execute_instruction() {
        let config = Config::new();
        let context = Context::new(&config);
        let mut executor = ConcolicExecutor::new(&context);

        // Mock Data for LOAD instruction
        // Ensure memory address and offset variable are correctly initialized
        let memory_address: u64 = 0x55e4a78f0330;
        executor.state.memory.write_quad(memory_address, 0xDEADBEEF).expect("Failed to write to memory");

        let offset_var_name = "Register(0)".to_string();
        executor.state.set_var(&offset_var_name, ConcolicVar::new_concrete_and_symbolic_int(memory_address, &offset_var_name, &context, 64));

        let load_inst = Inst {
            opcode: Opcode::Load,
            output: Some(Varnode { var: Register(21376), size: Size::Byte }),
            inputs: vec![
                Varnode { var: Const("0x55e4a78f0330".to_string()), size: Size::Byte },
                Varnode { var: Register(0), size: Size::Byte }
            ],
        };

        // Execution
        println!("Initial state: {}", executor.state);
        println!("Executing LOAD instruction: {:?}", load_inst);
        let load_result = executor.handle_load(load_inst);
        assert!(load_result.is_ok(), "Error executing LOAD: {:?}", load_result.err());
        println!("State after LOAD: {}", executor.state);

        // Mock Data for INT_CARRY instruction
        // Note: No additional setup needed for INT_CARRY if using registers already initialized
        let carry_inst = Inst {
            opcode: Opcode::IntCarry,
            output: Some(Varnode { var: Register(512), size: Size::Byte }),
            inputs: vec![
                Varnode { var: Unique(21376), size: Size::Byte },
                Varnode { var: Register(0), size: Size::Byte },
            ],
        };

        println!("Executing INT_CARRY instruction: {:?}", carry_inst);
        let carry_result = executor.handle_int_carry(carry_inst);
        assert!(carry_result.is_ok(), "Error executing INT_CARRY: {:?}", carry_result.err());
        println!("State after INT_CARRY: {}", executor.state);

        println!("Final state: {}", executor.state);
    }
}