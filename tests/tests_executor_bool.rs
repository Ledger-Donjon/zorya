// SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod tests {
    use parser::parser::{Inst, Opcode, Size, Var, Varnode};
    use z3::ast::BV;
    use z3::{Config, Context};
    use zorya::concolic::executor_bool::{handle_bool_and, handle_bool_negate, handle_bool_xor};
    use zorya::concolic::{ConcolicExecutor, ConcolicVar, Logger};
    use zorya::executor::SymbolicVar;

    fn setup_executor() -> ConcolicExecutor<'static> {
        let cfg = Config::new();
        let ctx = Box::leak(Box::new(Context::new(&cfg)));
        let logger = Logger::new("execution_log.txt", false).expect("Failed to create logger");
        let trace_logger =
            Logger::new("trace_log.txt", true).expect("Failed to create trace logger");
        let mut executor = ConcolicExecutor::new_for_tests(ctx, logger, trace_logger)
            .expect("Failed to create executor");
        executor.current_address = Some(0x123);
        executor
    }

    #[test]
    fn test_handle_bool_and() {
        let mut executor = setup_executor();

        // Setup: Create two boolean variables, one true and one false
        let symbolic0 = SymbolicVar::Int(BV::new_const(executor.context, "true".to_string(), 64));
        let symbolic1 = SymbolicVar::Int(BV::new_const(executor.context, "false".to_string(), 64));
        let input0 = ConcolicVar::new_concrete_and_symbolic_int(
            1,
            symbolic0.to_bv(executor.context),
            executor.context,
        ); // true
        let input1 = ConcolicVar::new_concrete_and_symbolic_int(
            0,
            symbolic1.to_bv(executor.context),
            executor.context,
        ); // false
        executor
            .unique_variables
            .insert("Unique(0x100)".to_string(), input0);
        executor
            .unique_variables
            .insert("Unique(0x101)".to_string(), input1);

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
            assert_eq!(
                result_var.concrete,
                zorya::concolic::ConcreteVar::Int(0),
                "BOOL_AND did not compute the correct result (true AND false should be false)"
            );
        } else {
            panic!("BOOL_AND result not found or incorrect type");
        }
    }

    #[test]
    fn test_handle_bool_negate() {
        let mut executor = setup_executor();

        // Setup: Create and insert a test variable assumed to represent a boolean value 'true' (1)
        let symbolic = SymbolicVar::Int(BV::new_const(executor.context, "true".to_string(), 64));
        let test_bool = ConcolicVar::new_concrete_and_symbolic_int(
            1,
            symbolic.to_bv(executor.context),
            executor.context,
        );
        executor
            .unique_variables
            .insert("Unique(0x200)".to_string(), test_bool);

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

        assert!(
            handle_bool_negate(&mut executor, negate_inst).is_ok(),
            "BOOL_NEGATE operation failed"
        );

        // Verify: Check if the boolean value was negated correctly
        if let Some(negated_var) = executor.unique_variables.get("Unique(0x200)").cloned() {
            assert_eq!(
                negated_var.concrete.to_u64(),
                0,
                "Boolean negation did not produce the expected result"
            );
        } else {
            panic!("Result of BOOL_NEGATE not found or incorrect type");
        }
    }

    #[test]
    fn test_handle_bool_xor() {
        let mut executor = setup_executor();

        // Setup: Create two boolean variables, one true and one false
        let symbolic0 = SymbolicVar::Int(BV::new_const(executor.context, "true".to_string(), 64));
        let symbolic1 = SymbolicVar::Int(BV::new_const(executor.context, "false".to_string(), 64));
        let input0 = ConcolicVar::new_concrete_and_symbolic_int(
            1,
            symbolic0.to_bv(executor.context),
            executor.context,
        ); // true
        let input1 = ConcolicVar::new_concrete_and_symbolic_int(
            0,
            symbolic1.to_bv(executor.context),
            executor.context,
        ); // false
        executor
            .unique_variables
            .insert("Unique(0x100)".to_string(), input0);
        executor
            .unique_variables
            .insert("Unique(0x101)".to_string(), input1);

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
            assert_eq!(
                result_var.concrete,
                zorya::concolic::ConcreteVar::Int(1),
                "BOOL_XOR did not compute the correct result (true XOR false should be true)"
            );
        } else {
            panic!("BOOL_XOR result not found or incorrect type");
        }
    }
}
