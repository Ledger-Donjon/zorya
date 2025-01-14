#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use z3::ast::BV;
    use zorya::concolic::executor_bool::{handle_bool_and, handle_bool_negate, handle_bool_xor};
    use zorya::concolic::{ConcolicExecutor, ConcolicVar, Logger};
    use zorya::executor::SymbolicVar;
    use zorya::state::State;
    use parser::parser::{Inst, Opcode, Var, Varnode, Size};
    use z3::{Config, Context, Solver};

    fn setup_executor() -> ConcolicExecutor<'static> {
        let cfg = Config::new();
        let ctx = Box::leak(Box::new(Context::new(&cfg)));
        let logger = Logger::new("execution_log.txt").expect("Failed to create logger");
        let trace_logger = Logger::new("trace_log.txt").expect("Failed to create trace logger");
        let state = State::default_for_tests(ctx, logger).expect("Failed to create state.");
        let current_lines_number = 0;
        ConcolicExecutor {
            context: ctx,
            solver: Solver::new(ctx),
            state,
            symbol_table: BTreeMap::new(),
            current_address: Some(0x123),
            instruction_counter: 0,
            unique_variables: BTreeMap::new(),
            pcode_internal_lines_to_be_jumped: current_lines_number,
            initialiazed_var: BTreeMap::new(),
            inside_jump_table: false,
            trace_logger,
        }
    }
    
    #[test]
    fn test_handle_bool_and() {
        let mut executor = setup_executor();

        // Setup: Create two boolean variables, one true and one false
        let symbolic0 = SymbolicVar::Int(BV::new_const(executor.context, format!("true"), 64));
        let symbolic1 = SymbolicVar::Int(BV::new_const(executor.context, format!("false"), 64));
        let input0 = ConcolicVar::new_concrete_and_symbolic_int(1, symbolic0.to_bv(&executor.context), executor.context, 1); // true
        let input1 = ConcolicVar::new_concrete_and_symbolic_int(0, symbolic1.to_bv(&executor.context), executor.context, 1); // false
        executor.unique_variables.insert("Unique(0x100)".to_string(), input0);
        executor.unique_variables.insert("Unique(0x101)".to_string(), input1);

        // Define the instruction to perform a BOOL_AND operation
        let and_inst = Inst {
            opcode: Opcode::BoolAnd,
            output: Some(Varnode {
                var: Var::Unique(0x102),
                size: Size::Byte,
            }),
            inputs: vec![
                Varnode {
                    var: Var::Unique(0x100),
                    size: Size::Byte,
                },
                Varnode {
                    var: Var::Unique(0x101),
                    size: Size::Byte,
                },
            ],
        };

        // Execute the BOOL_AND operation
        let result = handle_bool_and(&mut executor, and_inst);
        assert!(result.is_ok(), "BOOL_AND operation failed");

        println!("{:?}", executor.unique_variables);

        // Verify the result of the BOOL_AND operation
        if let Some(result_var) = executor.unique_variables.get("Unique(0x102)") {
            assert_eq!(result_var.concrete, zorya::concolic::ConcreteVar::Int(0), "BOOL_AND did not compute the correct result (true AND false should be false)");
        } else {
            panic!("BOOL_AND result not found or incorrect type");
        }
    }

    #[test]
    fn test_handle_bool_negate() {
        let mut executor = setup_executor();

        // Setup: Create and insert a test variable assumed to represent a boolean value 'true' (1)
        let symbolic = SymbolicVar::Int(BV::new_const(executor.context, format!("true"), 64));
        let test_bool = ConcolicVar::new_concrete_and_symbolic_int(1, symbolic.to_bv(&executor.context),executor.context, 1);
        executor.unique_variables.insert("Unique(0x200)".to_string(), test_bool);

        let negate_inst = Inst {
            opcode: Opcode::BoolNegate,
            output: Some(Varnode {
                var: Var::Unique(0x200),
                size: Size::Byte,
            }),
            inputs: vec![Varnode {
                var: Var::Unique(0x200),
                size: Size::Byte,
            }],
        };

        assert!(handle_bool_negate(&mut executor, negate_inst).is_ok(), "BOOL_NEGATE operation failed");

        // Verify: Check if the boolean value was negated correctly
        if let Some(negated_var) = executor.unique_variables.get("Unique(0x200)").map(|enum_var| match enum_var {
            var => var.clone(),
        }) {
            assert_eq!(negated_var.concrete.to_u64(), 0, "Boolean negation did not produce the expected result");
        } else {
            panic!("Result of BOOL_NEGATE not found or incorrect type");
        }
    }

    #[test]
    fn test_handle_bool_xor() {
        let mut executor = setup_executor();

        // Setup: Create two boolean variables, one true and one false
        let symbolic0 = SymbolicVar::Int(BV::new_const(executor.context, format!("true"), 64));
        let symbolic1 = SymbolicVar::Int(BV::new_const(executor.context, format!("false"), 64));
        let input0 = ConcolicVar::new_concrete_and_symbolic_int(1, symbolic0.to_bv(&executor.context), executor.context, 1); // true
        let input1 = ConcolicVar::new_concrete_and_symbolic_int(0, symbolic1.to_bv(&executor.context), executor.context, 1); // false
        executor.unique_variables.insert("Unique(0x100)".to_string(), input0);
        executor.unique_variables.insert("Unique(0x101)".to_string(), input1);

        // Define the instruction to perform a BOOL_XOR operation
        let xor_inst = Inst {
            opcode: Opcode::BoolXor,
            output: Some(Varnode {
                var: Var::Unique(0x102),
                size: Size::Byte,
            }),
            inputs: vec![
                Varnode {
                    var: Var::Unique(0x100),
                    size: Size::Byte,
                },
                Varnode {
                    var: Var::Unique(0x101),
                    size: Size::Byte,
                },
            ],
        };

        // Execute the BOOL_XOR operation
        let result = handle_bool_xor(&mut executor, xor_inst);
        assert!(result.is_ok(), "BOOL_XOR operation failed");

        println!("{:?}", executor.unique_variables);

        // Verify the result of the BOOL_XOR operation
        if let Some(result_var) = executor.unique_variables.get("Unique(0x102)") {
            assert_eq!(result_var.concrete, zorya::concolic::ConcreteVar::Int(1), "BOOL_XOR did not compute the correct result (true XOR false should be true)");
        } else {
            panic!("BOOL_XOR result not found or incorrect type");
        }
    }
}