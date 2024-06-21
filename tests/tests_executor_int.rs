use z3::{Config, Context, Solver};
use zorya::concolic::ConcolicExecutor;
use zorya::state::State;
use parser::parser::{Inst, Opcode, Var, Varnode};

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use parser::parser::Size;
    use zorya::concolic::{executor_int::{handle_int_add, handle_int_and, handle_int_carry, handle_int_equal, handle_int_less, handle_int_notequal, handle_int_sborrow, handle_int_scarry, handle_int_sless, handle_int_sub, handle_int_zext}, ConcolicEnum, ConcolicVar, Logger};

    use super::*;
    
    fn setup_executor() -> ConcolicExecutor<'static> {
        let cfg = Config::new();
        let ctx = Box::leak(Box::new(Context::new(&cfg)));
        let logger = Logger::new("execution_log.txt").expect("Failed to create logger");
        let state = State::default_for_tests(ctx, logger).expect("Failed to create state.");
        ConcolicExecutor {
            context: ctx,
            solver: Solver::new(ctx),
            state,
            current_address: Some(0x123),
            instruction_counter: 0,
            unique_variables: BTreeMap::new(),        }
    }
    
    #[test]
    fn test_handle_int_add() {
        let mut executor = setup_executor();
        let int_add_inst = Inst {
            opcode: Opcode::IntAdd,
            output: Some(Varnode {
                var: Var::Unique(0x6000),
                size: Size::Quad,
            }),
            inputs: vec![
                Varnode {
                    var: Var::Const("5".to_string()),
                    size: Size::Quad,
                },
                Varnode {
                    var: Var::Const("10".to_string()),
                    size: Size::Quad,
                },
            ],
        };

        let result = handle_int_add(&mut executor, int_add_inst);
        assert!(result.is_ok(), "handle_int_add returned an error: {:?}", result);

        let unique_name = "Unique(0x6000)".to_string();
        let unique_var = executor.unique_variables.get(&unique_name).expect("Unique variable not found");
        assert_eq!(unique_var.concrete.to_u64(), 15);
    }

    #[test]
    fn test_handle_int_sub() {
        let mut executor = setup_executor();
        let int_sub_inst = Inst {
            opcode: Opcode::IntSub,
            output: Some(Varnode {
                var: Var::Unique(0x7000),
                size: Size::Quad,
            }),
            inputs: vec![
                Varnode {
                    var: Var::Const("20".to_string()),
                    size: Size::Quad,
                },
                Varnode {
                    var: Var::Const("5".to_string()),
                    size: Size::Quad,
                },
            ],
        };

        let result = handle_int_sub(&mut executor, int_sub_inst);
        assert!(result.is_ok(), "handle_int_sub returned an error: {:?}", result);

        let unique_name = "Unique(0x7000)".to_string();
        let unique_var = executor.unique_variables.get(&unique_name).expect("Unique variable not found");
        assert_eq!(unique_var.concrete.to_u64(), 15);
    }

    #[test]
    fn test_handle_int_and() {
        let mut executor = setup_executor();
        let int_and_inst = Inst {
            opcode: Opcode::IntAnd,
            output: Some(Varnode {
                var: Var::Unique(0xb000),
                size: Size::Quad,
            }),
            inputs: vec![
                Varnode {
                    var: Var::Const("5".to_string()),
                    size: Size::Quad,
                },
                Varnode {
                    var: Var::Const("3".to_string()),
                    size: Size::Quad,
                },
            ],
        };

        let result = handle_int_and(&mut executor, int_and_inst);
        assert!(result.is_ok(), "handle_int_and returned an error: {:?}", result);

        let unique_name = "Unique(0xb000)".to_string();
        let unique_var = executor.unique_variables.get(&unique_name).expect("Unique variable not found");
        assert_eq!(unique_var.concrete.to_u64(), 1); // Ensure the result is correct for AND operation (5 & 3 = 1)
    }

    #[test]
    fn test_handle_int_sborrow() {
        let mut executor = setup_executor();
        let int_sborrow_inst = Inst {
            opcode: Opcode::IntSBorrow,
            output: Some(Varnode {
                var: Var::Unique(0x8000),
                size: Size::Byte, // Boolean result
            }),
            inputs: vec![
                Varnode {
                    var: Var::Const("20".to_string()),
                    size: Size::Quad,
                },
                Varnode {
                    var: Var::Const("5".to_string()),
                    size: Size::Quad,
                },
            ],
        };

        let result = handle_int_sborrow(&mut executor, int_sborrow_inst);
        assert!(result.is_ok(), "handle_int_sborrow returned an error: {:?}", result);

        let unique_name = "Unique(0x8000)".to_string();
        let unique_var = executor.unique_variables.get(&unique_name).expect("Unique variable not found");
        assert_eq!(unique_var.concrete.to_u64(), 0); // Ensure it correctly identifies no overflow
    }

    #[test]
    fn test_handle_int_less() {
        let mut executor = setup_executor();
        let int_less_inst = Inst {
            opcode: Opcode::IntLess,
            output: Some(Varnode {
                var: Var::Unique(0x9000),
                size: Size::Quad,
            }),
            inputs: vec![
                Varnode {
                    var: Var::Const("5".to_string()),
                    size: Size::Quad,
                },
                Varnode {
                    var: Var::Const("10".to_string()),
                    size: Size::Quad,
                },
            ],
        };

        let result = handle_int_less(&mut executor, int_less_inst);
        assert!(result.is_ok(), "handle_int_less returned an error: {:?}", result);

        let unique_name = "Unique(0x9000)".to_string();
        let unique_var = executor.unique_variables.get(&unique_name).expect("Unique variable not found");
        assert_eq!(unique_var.concrete.to_u64(), 1); // Ensure the result is correct for less than comparison
    }

    #[test]
    fn test_handle_int_sless() {
        let mut executor = setup_executor();
        let int_sless_inst = Inst {
            opcode: Opcode::IntSLess,
            output: Some(Varnode {
                var: Var::Unique(0xa000),
                size: Size::Byte, // Ensure the size is 1 byte for boolean result
            }),
            inputs: vec![
                Varnode {
                    var: Var::Const("5".to_string()),
                    size: Size::Quad,
                },
                Varnode {
                    var: Var::Const("10".to_string()),
                    size: Size::Quad,
                },
            ],
        };

        let result = handle_int_sless(&mut executor, int_sless_inst);
        assert!(result.is_ok(), "handle_int_sless returned an error: {:?}", result);
        println!("result is {:?}", result);
        let unique_name = "Unique(0xa000)".to_string();
        let unique_var = executor.unique_variables.get(&unique_name).expect("Unique variable not found");
        assert_eq!(unique_var.concrete.to_u64(), 1); // Ensure the result is correct for signed less than comparison
    }
    
    #[test]
    fn test_handle_int_equal() {
        let mut executor = setup_executor();
        let unique_name = "Unique(0xa000)".to_string();
        let unique_var = ConcolicVar::new_concrete_and_symbolic_int(5, &unique_name, executor.context, 64);
        executor.unique_variables.insert(unique_name.clone(), unique_var);
        let int_equal_inst = Inst {
            opcode: Opcode::IntEqual,
            output: Some(Varnode {
                var: Var::Unique(0xc000),
                size: Size::Byte, // The result of a boolean comparison
            }),
            inputs: vec![
                Varnode {
                    var: Var::Unique(0xa000),
                    size: Size::Quad,
                },
                Varnode {
                    var: Var::Const("0x5".to_string()),
                    size: Size::Quad,
                },
            ],
        };

        // Test when the values are equal
        let result = handle_int_equal(&mut executor, int_equal_inst);
        assert!(result.is_ok(), "handle_int_equal returned an error: {:?}", result);

        let unique_name = "Unique(0xc000)".to_string();
        let unique_var = executor.unique_variables.get(&unique_name).expect("Unique variable not found");
        assert_eq!(unique_var.concrete.to_u64(), 1); // 5 == 5, so result should be true (1)

        // Test when the values are not equal
        let int_not_equal_inst = Inst {
            opcode: Opcode::IntEqual,
            output: Some(Varnode {
                var: Var::Unique(0xC001),
                size: Size::Byte, // The result of a boolean comparison
            }),
            inputs: vec![
                Varnode {
                    var: Var::Const("5".to_string()),
                    size: Size::Quad,
                },
                Varnode {
                    var: Var::Const("10".to_string()),
                    size: Size::Quad,
                },
            ],
        };

        let result = handle_int_equal(&mut executor, int_not_equal_inst);
        assert!(result.is_ok(), "handle_int_equal returned an error: {:?}", result);

        let unique_name = "Unique(0xc001)".to_string();
        let unique_var = executor.unique_variables.get(&unique_name).expect("Unique variable not found");
        assert_eq!(unique_var.concrete.to_u64(), 0); // 5 != 10, so result should be false (0)
    }

    #[test]
    fn test_handle_int_carry() {
        let mut executor = setup_executor();
        let context = &executor.context;

        let input0 = ConcolicVar::new_concrete_and_symbolic_int(0xFFFF_FFFF, "var0", context, 32);
        let input1 = ConcolicVar::new_concrete_and_symbolic_int(0x1, "var1", context, 32);
        executor.unique_variables.insert("Unique(0x01)".to_string(), input0);
        executor.unique_variables.insert("Unique(0x02)".to_string(), input1);

        let instruction = Inst {
            opcode: Opcode::IntCarry,
            output: Some(Varnode {
                var: Var::Unique(1),
                size: 1,
            }),
            inputs: vec![
                Varnode {
                    var: Var::Unique(1),
                    size: 32,
                },
                Varnode {
                    var: Var::Unique(2),
                    size: 32,
                },
            ],
        };

        let result = handle_int_carry(&mut executor, instruction).unwrap();
        assert!(result.is_ok());

        let result_var = executor.unique_variables.get("Unique(0x01)").unwrap();
        assert_eq!(result_var.get_concrete_value(), 1); // Expected result for carry
    }

    #[test]
    fn test_handle_int_scarry() {
        let mut executor = setup_executor();
        let int_scarry_inst = Inst {
            opcode: Opcode::IntSCarry,
            output: Some(Varnode {
                var: Var::Unique(0xe000),
                size: Size::Byte, // Boolean result
            }),
            inputs: vec![
                Varnode {
                    var: Var::Const("0x7FFFFFFFFFFFFFFF".to_string()),
                    size: Size::Quad,
                },
                Varnode {
                    var: Var::Const("1".to_string()),
                    size: Size::Quad,
                },
            ],
        };

        let result = handle_int_scarry(&mut executor, int_scarry_inst);
        assert!(result.is_ok(), "handle_int_scarry returned an error: {:?}", result);

        let unique_name = "Unique(0xe000)".to_string();
        let unique_var = executor.unique_variables.get(&unique_name).expect("Unique variable not found");
        assert_eq!(unique_var.concrete.to_u64(), 1); // Ensure it correctly identifies the signed carry
    }

    #[test]
    fn test_handle_int_zext() {
        let mut executor = setup_executor();

        // Setup a varnode with a small size (e.g., Byte) and expect it to zero-extend to a Quad size
        let input_varnode = Varnode {
            var: Var::Unique(0x5000),
            size: Size::Byte,  // Original smaller size
        };
        let output_varnode = Varnode {
            var: Var::Unique(0x6000),
            size: Size::Quad,  // Extended larger size
        };

        // Inserting a predefined small-sized value into the unique_variables
        let initial_concolic_var = ConcolicVar::new_concrete_and_symbolic_int(0xAB, "input0", executor.context, 8);  // 0xAB is 10101011 in binary
        executor.unique_variables.insert(format!("Unique(0x{:x})", 0x5000), initial_concolic_var);

        let zext_inst = Inst {
            opcode: Opcode::IntZExt,
            output: Some(output_varnode),
            inputs: vec![input_varnode],
        };

        let result = handle_int_zext(&mut executor, zext_inst);
        assert!(result.is_ok(), "handle_int_zext returned an error: {:?}", result);

        // Check if the result is zero-extended correctly
        let unique_name = format!("Unique(0x{:x})", 0x6000);
        let zero_extended_var = executor.unique_variables.get(&unique_name).expect("Zero-extended variable not found");

        // The expected result should be 0x00000000000000AB when zero-extended from Byte to Quad
        assert_eq!(zero_extended_var.concrete.to_u64(), 0xAB, "Zero extension did not work as expected");
    }

    #[test]
    fn test_handle_int_notequal() {
        let mut executor = setup_executor();
        let input0 = ConcolicVar::new_concrete_and_symbolic_int(5, "input0", executor.context, 32);
        let input1 = ConcolicVar::new_concrete_and_symbolic_int(10, "input1", executor.context, 32);
        executor.unique_variables.insert("input0".to_string(), input0);
        executor.unique_variables.insert("input1".to_string(), input1);

        let notequal_inst = Inst {
            opcode: Opcode::IntNotEqual,
            output: Some(Varnode {
                var: Var::Unique(0x3000),
                size: Size::Byte,
            }),
            inputs: vec![
                Varnode {
                    var: Var::Unique(0x1000),
                    size: Size::Word,
                },
                Varnode {
                    var: Var::Unique(0x2000),
                    size: Size::Word,
                },
            ],
        };

        let result = handle_int_notequal(&mut executor, notequal_inst);
        assert!(result.is_ok(), "handle_int_notequal returned an error: {:?}", result);

        let unique_name = "Unique(0x3000)".to_string();
        let result_var = executor.unique_variables.get(&unique_name).expect("Result variable not found");
        assert_eq!(result_var.concrete, zorya::concolic::ConcreteVar::Int(1), "INT_NOTEQUAL did not produce the expected result");
    }

    #[test]
    fn test_handle_int_xor() {
        let mut executor = setup_executor();

        // Setup input variables
        let input0 = ConcolicVar::new_concrete_and_symbolic_int(0xFF, "input0", executor.context, 64);
        let input1 = ConcolicVar::new_concrete_and_symbolic_int(0x0F, "input1", executor.context, 64);
        executor.unique_variables.insert("Unique(0x100)".to_string(), input0);
        executor.unique_variables.insert("Unique(0x101)".to_string(), input1);

        // Define the instruction for XOR
        let xor_inst = Inst {
            opcode: Opcode::IntXor,
            output: Some(Varnode {
                var: Var::Unique(0x102),
                size: Size::Word,
            }),
            inputs: vec![
                Varnode {
                    var: Var::Unique(0x100),
                    size: Size::Word,
                },
                Varnode {
                    var: Var::Unique(0x101),
                    size: Size::Word,
                },
            ],
        };

        // Execute the XOR operation
        assert!(executor.handle_int_xor(xor_inst).is_ok(), "INT_XOR operation failed");

        // Check results: Expect the output variable to contain the XOR result
        if let Some(result_var) = executor.unique_variables.get("Unique(0x102)") {
            let expected_value = 0xFF ^ 0x0F;
            assert_eq!(result_var.concrete.to_u64(), expected_value, "INT_XOR did not compute the correct result");
            println!("Result of INT_XOR operation: {:#?}", result_var);
        } else {
            panic!("Resulting variable from INT_XOR operation not found");
        }
    }

    #[test]
    fn test_handle_int_lessequal_true() {
        let mut executor = setup_executor();

        let input0 = ConcolicVar::new_concrete_and_symbolic_int(5, "input0", executor.context, 64);
        let input1 = ConcolicVar::new_concrete_and_symbolic_int(10, "input1", executor.context, 64);

        let instruction = Inst {
            opcode: Opcode::IntLessEqual,
            output: Some(Varnode {
                var: Var::Unique(0x100),
                size: Size::Byte,
            }),
            inputs: vec![
                Varnode {
                    var: Var::Unique(0x100),
                    size: Size::Word,
                },
                Varnode {
                    var: Var::Unique(0x101),
                    size: Size::Word,
                },
            ],
        };

        executor.unique_variables.insert("Unique(0x100)".to_string(), input0);
        executor.unique_variables.insert("Unique(0x101)".to_string(), input1);

        assert!(executor.handle_int_lessequal(instruction).is_ok());

        let result_var = executor.unique_variables.get("Unique(0x100)").unwrap();
        assert_eq!(result_var.concrete.to_u64(), 1, "The result should be true (1)");
    }

    #[test]
    fn test_handle_int_lessequal_false() {
        let mut executor = setup_executor();

        let input0 = ConcolicVar::new_concrete_and_symbolic_int(15, "input0", executor.context, 64);
        let input1 = ConcolicVar::new_concrete_and_symbolic_int(10, "input1", executor.context, 64);

        let instruction = Inst {
            opcode: Opcode::IntLessEqual,
            output: Some(Varnode {
                var: Var::Unique(0x100),
                size: Size::Byte,
            }),
            inputs: vec![
                Varnode {
                    var: Var::Unique(0x100),
                    size: Size::Word,
                },
                Varnode {
                    var: Var::Unique(0x101),
                    size: Size::Word,
                },
            ],
        };

        executor.unique_variables.insert("Unique(0x100)".to_string(), input0);
        executor.unique_variables.insert("Unique(0x101)".to_string(), input1);

        assert!(executor.handle_int_lessequal(instruction).is_ok());

        let result_var = executor.unique_variables.get("Unique(0x100)").unwrap();
        assert_eq!(result_var.concrete.to_u64(), 0, "The result should be false (0)");
    }

    #[test]
    fn test_handle_int_slessequal() {
        let mut executor = setup_executor();

        // Setup for INT_SLESSEQUAL: input0 < input1
        let input0 = ConcolicVar::new_concrete_and_symbolic_int(-5i64 as u64, "input0", executor.context, 64);
        let input1 = ConcolicVar::new_concrete_and_symbolic_int(10i64 as u64, "input1", executor.context, 64);

        let inst = Inst {
            opcode: Opcode::IntSlessEqual,
            output: Some(Varnode {
                var: Var::Unique(0x100),
                size: Size::Byte,
            }),
            inputs: vec![
                Varnode {
                    var: Var::Unique(0x200),
                    size: Size::Quad,
                },
                Varnode {
                    var: Var::Unique(0x201),
                    size: Size::Quad,
                },
            ],
        };

        executor.unique_variables.insert("Unique(0x200)".to_string(), input0);
        executor.unique_variables.insert("Unique(0x201)".to_string(), input1);

        assert!(executor.handle_int_slessequal(inst).is_ok(), "INT_SLESSEQUAL operation failed");

        // Check result
        if let Some(result_var) = executor.unique_variables.get("Unique(0x100)") {
            assert_eq!(result_var.concrete.to_u64(), 1, "INT_SLESSEQUAL did not compute correctly (expected true)");
        } else {
            panic!("Resulting variable from INT_SLESSEQUAL operation not found");
        }

        // Setup for INT_SLESSEQUAL: input0 > input1
        let input0 = ConcolicVar::new_concrete_and_symbolic_int(15i64 as u64, "input0_higher", executor.context, 64);
        let input1 = ConcolicVar::new_concrete_and_symbolic_int(-10i64 as u64, "input1_lower", executor.context, 64);

        executor.unique_variables.insert("Unique(0x200)".to_string(), input0);
        executor.unique_variables.insert("Unique(0x201)".to_string(), input1);

        assert!(executor.handle_int_slessequal(inst).is_ok(), "INT_SLESSEQUAL operation failed when input0 is greater than input1");

        // Check result for false condition
        if let Some(result_var) = executor.unique_variables.get("Unique(0x100)") {
            assert_eq!(result_var.concrete.to_u64(), 0, "INT_SLESSEQUAL did not compute correctly (expected false)");
        } else {
            panic!("Resulting variable from INT_SLESSEQUAL operation not found for greater condition");
        }
    }

    #[test]
    fn test_handle_int_sext() {
        let mut executor = setup_executor();

        // Setup: Create a test variable that needs sign extension from 8 bits to 32 bits
        let test_value = 0b1111_1111u64; // -1 in signed 8-bit, 0xFF in unsigned
        let input_var = ConcolicVar::new_concrete_and_symbolic_int(test_value, SymbolicVar::Int(BV::from_u64(executor.context, test_value, 8)), executor.context, 8);

        // Insert the test variable as a unique varnode
        let source_id = 0x100;
        let source_name = format!("Unique(0x{:x})", source_id);
        executor.unique_variables.insert(source_name.clone(), input_var);

        // Define the instruction for sign-extension
        let sext_inst = Inst {
            opcode: Opcode::IntSExt,
            output: Some(Varnode {
                var: Var::Unique(0x200),
                size: Size::Word,
            }),
            inputs: vec![Varnode {
                var: Var::Unique(0x100),
                size: Size::Byte,
            }],
        };

        // Execute the sign-extension
        assert!(executor.handle_int_sext(sext_inst).is_ok(), "INT_SEXT operation failed");

        // Verify the result
        if let Some(result_var) = executor.unique_variables.get(&"Unique(0x200)".to_string()) {
            assert_eq!(result_var.concrete, 0xFFFF_FFFF, "Sign-extension did not produce the expected result");
            println!("Result of INT_SEXT operation: {:#?}", result_var);
        } else {
            panic!("Resulting variable from INT_SEXT operation not found");
        }
    }

    #[test]
    fn test_handle_int_2comp() {
        let mut executor = setup_executor();
        let input_value = 123u64;
        let expected_output = (!input_value).wrapping_add(1);  // Manual two's complement

        let input_var = ConcolicVar::new_concrete_and_symbolic_int(input_value, "input_var", executor.context, 64);
        let source_address = "Unique(0x100)".to_string();
        executor.unique_variables.insert(source_address.clone(), input_var);

        let int2comp_inst = Inst {
            opcode: Opcode::Int2Comp,
            output: Some(Varnode {
                var: Var::Unique(0x100),
                size: Size::Word,
            }),
            inputs: vec![Varnode {
                var: Var::Unique(0x100),
                size: Size::Word,
            }],
        };

        assert!(executor.handle_int_2comp(int2comp_inst).is_ok(), "INT_2COMP operation failed");

        if let Some(result_var) = executor.unique_variables.get(&"Unique(0x100)".to_string()) {
            assert_eq!(result_var.concrete.to_u64(), expected_output, "Twos complement did not produce the expected result");
        } else {
            panic!("Resulting variable from INT_2COMP operation not found");
        }
    }

    #[test]
    fn test_handle_int_or() {
        let mut executor = setup_executor();

        let input0 = ConcolicVar::new_concrete_and_symbolic_int(0b0101, "var0", &context, 8);
        let input1 = ConcolicVar::new_concrete_and_symbolic_int(0b0011, "var1", &context, 8);
        executor.unique_variables.insert("Unique(0x01)".to_string(), input0);
        executor.unique_variables.insert("Unique(0x02)".to_string(), input1);

        let instruction = Inst {
            opcode: Opcode::IntOr,
            output: Some(Varnode {
                var: Var::Unique(1),
                size: 8,
            }),
            inputs: vec![
                Varnode {
                    var: Var::Unique(1),
                    size: 8,
                },
                Varnode {
                    var: Var::Unique(2),
                    size: 8,
                },
            ],
        };

        let result = handle_int_or(&mut executor, instruction).unwrap();
        assert_eq!(result.is_ok(), true);

        let result_var = executor.unique_variables.get("Unique(0x01)").unwrap();
        assert_eq!(result_var.concrete.to_u64(), 0b0111); // Expected OR result
    }

    #[test]
    fn test_handle_int_left() {
        let mut executor = setup_executor();

        let input0 = ConcolicVar::new_concrete_and_symbolic_int(0b0011, "var0", &context, 8);
        let input1 = ConcolicVar::new_concrete_and_symbolic_int(2, "var1", &context, 8); // Shift by 2 bits
        executor.unique_variables.insert("Unique(0x01)".to_string(), input0);
        executor.unique_variables.insert("Unique(0x02)".to_string(), input1);

        let instruction = Inst {
            opcode: Opcode::IntLeft,
            output: Some(Varnode {
                var: Var::Unique(1),
                size: 8,
            }),
            inputs: vec![
                Varnode {
                    var: Var::Unique(1),
                    size: 8,
                },
                Varnode {
                    var: Var::Unique(2),
                    size: 8,
                },
            ],
        };

        let result = handle_int_left(&mut executor, instruction);
        assert!(result.is_ok());

        let result_var = executor.unique_variables.get(&"Unique(0x01)".to_string()).unwrap();
        assert_eq!(result_var.concrete.to_u64(), 0b1100); // Expected result after shifting 0b0011 left by 2 bits
    }

    #[test]
    fn test_handle_int_right() {
        let mut executor = setup_executor();

        let input0 = ConcolicVar::new_concrete_and_symbolic_int(0b1100, "var0", &context, 8);
        let input1 = ConcolicVar::new_concrete_and_symbolic_int(2, "var1", &context, 8); // Shift by 2 bits
        executor.unique_variables.insert("Unique(0x01)".to_string(), input0);
        executor.unique_variables.insert("Unique(0x02)".to_string(), input1);

        let instruction = Inst {
            opcode: Opcode::IntRight,
            output: Some(Varnode {
                var: Var::Unique(1),
                size: 8,
            }),
            inputs: vec![
                Varnode {
                    var: Var::Unique(1),
                    size: 8,
                },
                Varnode {
                    var: Var::Unique(2),
                    size: 8,
                },
            ],
        };

        let result = handle_int_right(&mut executor, instruction);
        assert!(result.is_ok());

        let result_var = executor.unique_variables.get(&"Unique(0x01)".to_string()).unwrap();
        assert_eq!(result_var.concrete.to_u64(), 0b0011); // Expected result after shifting 0b1100 right by 2 bits
    }

    #[test]
    fn test_handle_int_sright() {
        let mut executor = setup_executor();

        let input0 = ConcolicVar::new_concrete_and_symbolic_int(0b11111000, "var0", &context, 8);  // -8 in two's complement
        let input1 = ConcolicVar::new_concrete_and_symbolic_int(3, "var1", &context, 8);  // Shift by 3 bits
        executor.unique_variables.insert("Unique(0x01)".to_string(), input0);
        executor.unique_variables.insert("Unique(0x02)".to_string(), input1);

        let instruction = Inst {
            opcode: Opcode::IntSRight,
            output: Some(Varnode {
                var: Var::Unique(1),
                size: 8,
            }),
            inputs: vec![
                Varnode {
                    var: Var::Unique(1),
                    size: 8,
                },
                Varnode {
                    var: Var::Unique(2),
                    size: 8,
                },
            ],
        };

        let result = handle_int_sright(&mut executor, instruction);
        assert!(result.is_ok());

        let result_var = executor.unique_variables.get(&"Unique(0x01)".to_string()).unwrap();
        assert_eq!(result_var.concrete.to_u64(), 0b11111110); // Expected result after shifting -8 right by 3 bits, sign-extended
    }

    #[test]
    fn test_handle_int_mult() {
        let mut executor = setup_executor();

        let input0 = ConcolicVar::new_concrete_and_symbolic_int(15, "var0", &context, 8);  // Example small number
        let input1 = ConcolicVar::new_concrete_and_symbolic_int(3, "var1", &context, 8);  // Another small number
        executor.unique_variables.insert("Unique(0x01)".to_string(), input0);
        executor.unique_variables.insert("Unique(0x02)".to_string(), input1);

        let instruction = Inst {
            opcode: Opcode::IntMult,
            output: Some(Varnode {
                var: Var::Unique(1),
                size: 8,
            }),
            inputs: vec![
                Varnode {
                    var: Var::Unique(1),
                    size: 8,
                },
                Varnode {
                    var: Var::Unique(2),
                    size: 8,
                },
            ],
        };

        let result = handle_int_mult(&mut executor, instruction).unwrap();
        assert_eq!(result.is_ok(), true);

        let result_var = executor.unique_variables.get("Unique(0x01)").unwrap();
        assert_eq!(result_var.concrete.to_u64(), 45); // Expected result of 15 * 3
    }

    #[test]
    fn test_handle_int_negate() {
        let mut executor = setup_executor();

        let input0 = ConcolicVar::new_concrete_and_symbolic_int(0b01010101, "var0", &context, 8);  // Example byte
        executor.unique_variables.insert("Unique(0x01)".to_string(), input0);

        let instruction = Inst {
            opcode: Opcode::IntNegate,
            output: Some(Varnode {
                var: Var::Unique(1),
                size: 8,
            }),
            inputs: vec![
                Varnode {
                    var: Var::Unique(1),
                    size: 8,
                }
            ],
        };

        let result = handle_int_negate(&mut executor, instruction).unwrap();
        assert!(result.is_ok());

        let result_var = executor.unique_variables.get("Unique(0x01)").unwrap();
        assert_eq!(result_var.concrete.to_u64(), 0b10101010); // Expected negation result
    }

    #[test]
    fn test_handle_int_div() {
        let mut executor = setup_executor();

        let input0 = ConcolicVar::new_concrete_and_symbolic_int(10, "var0", &context, 32);
        let input1 = ConcolicVar::new_concrete_and_symbolic_int(2, "var1", &context, 32);
        executor.unique_variables.insert("Unique(0x01)".to_string(), input0);
        executor.unique_variables.insert("Unique(0x02)".to_string(), input1);

        let instruction = Inst {
            opcode: Opcode::IntDiv,
            output: Some(Varnode {
                var: Var::Unique(1),
                size: 32,
            }),
            inputs: vec![
                Varnode {
                    var: Var::Unique(1),
                    size: 32,
                },
                Varnode {
                    var: Var::Unique(2),
                    size: 32,
                },
            ],
        };

        let result = handle_int_div(&mut executor, instruction).unwrap();
        assert!(result.is_ok());

        let result_var = executor.unique_variables.get("Unique(0x01)").unwrap();
        assert_eq!(result_var.concrete.to_u64(), 5); // Expected division result
    }

    #[test]
    fn test_handle_int_rem() {
        let mut executor = setup_executor();

        let input0 = ConcolicVar::new_concrete_and_symbolic_int(10, "var0", &context, 32);
        let input1 = ConcolicVar::new_concrete_and_symbolic_int(3, "var1", &context, 32);
        executor.unique_variables.insert("Unique(0x01)".to_string(), input0);
        executor.unique_variables.insert("Unique(0x02)".to_string(), input1);

        let instruction = Inst {
            opcode: Opcode::IntRem,
            output: Some(Varnode {
                var: Var::Unique(1),
                size: 32,
            }),
            inputs: vec![
                Varnode {
                    var: Var::Unique(1),
                    size: 32,
                },
                Varnode {
                    var: Var::Unique(2),
                    size: 32,
                },
            ],
        };

        let result = handle_int_rem(&mut executor, instruction).unwrap();
        assert!(result.is_ok());

        let result_var = executor.unique_variables.get("Unique(0x01)").unwrap();
        assert_eq!(result_var.concrete.to_u64(), 1); // Expected remainder result
    }

    #[test]
    fn test_handle_int_sdiv() {
        let mut executor = setup_executor();

        let input0 = ConcolicVar::new_concrete_and_symbolic_int(-10i64 as u64, "var0", &context, 32);
        let input1 = ConcolicVar::new_concrete_and_symbolic_int(3i64 as u64, "var1", &context, 32);
        executor.unique_variables.insert("Unique(0x01)".to_string(), input0);
        executor.unique_variables.insert("Unique(0x02)".to_string(), input1);

        let instruction = Inst {
            opcode: Opcode::IntSDiv,
            output: Some(Varnode {
                var: Var::Unique(1),
                size: 32,
            }),
            inputs: vec![
                Varnode {
                    var: Var::Unique(1),
                    size: 32,
                },
                Varnode {
                    var: Var::Unique(2),
                    size: 32,
                },
            ],
        };

        let result = handle_int_sdiv(&mut executor, instruction).unwrap();
        assert!(result.is_ok());

        let result_var = executor.unique_variables.get("Unique(0x01)").unwrap();
        assert_eq!(result_var.concrete.to_i64(), -3); // Expected division result
    }

    #[test]
    fn test_handle_int_srem() {
        let mut executor = setup_executor();

        let input0 = ConcolicVar::new_concrete_and_symbolic_int(10i64 as u64, "var0", &context, 32);
        let input1 = ConcolicVar::new_concrete_and_symbolic_int(3i64 as u64, "var1", &context, 32);
        executor.unique_variables.insert("Unique(0x01)".to_string(), input0);
        executor.unique_variables.insert("Unique(0x02)".to_string(), input1);

        let instruction = Inst {
            opcode: Opcode::IntSRem,
            output: Some(Varnode {
                var: Var::Unique(1),
                size: 32,
            }),
            inputs: vec![
                Varnode {
                    var: Var::Unique(1),
                    size: 32,
                },
                Varnode {
                    var: Var::Unique(2),
                    size: 32,
                },
            ],
        };

        let result = handle_int_srem(&mut executor, instruction).unwrap();
        assert!(result.is_ok());

        let result_var = executor.unique_variables.get("Unique(0x01)").unwrap();
        assert_eq!(result_var.concrete.to_i64(), 1); // Expected remainder result
    }
}
