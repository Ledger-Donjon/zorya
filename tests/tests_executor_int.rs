use z3::{Config, Context, Solver};
use zorya::concolic::ConcolicExecutor;
use zorya::state::State;
use parser::parser::{Inst, Opcode, Var, Varnode};

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use parser::parser::Size;
    use z3::ast::BV;
    use zorya::{concolic::{executor_int::{handle_int_add, handle_int_and, handle_int_carry, handle_int_equal, handle_int_less, handle_int_notequal, handle_int_sborrow, handle_int_scarry, handle_int_sless, handle_int_sub, handle_int_xor, handle_int_zext}, ConcolicVar, Logger}, executor::SymbolicVar};

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

        let symbolic_var0 = SymbolicVar::Int(BV::from_u64(&executor.context, 10, 64));
        let symbolic_var1 = SymbolicVar::Int(BV::from_u64(&executor.context, 20, 64));

        // Setup test values and varnodes
        let input0 = ConcolicVar::new_concrete_and_symbolic_int(10, symbolic_var0.to_bv(&executor.context), &executor.context, 64);
        let input1 = ConcolicVar::new_concrete_and_symbolic_int(20, symbolic_var1.to_bv(&executor.context), &executor.context, 64);
        executor.unique_variables.insert("Unique(0x111)".to_string(), input0);
        executor.unique_variables.insert("Unique(0x112)".to_string(), input1);

        // Define an instruction using these variables
        let instruction = Inst {
            opcode: Opcode::IntAdd,
            output: Some(Varnode {
                var: Var::Unique(0x113),
                size: Size::Quad,
            }),
            inputs: vec![
                Varnode {
                    var: Var::Unique(0x111),
                    size: Size::Quad,
                },
                Varnode {
                    var: Var::Unique(0x112),
                    size: Size::Quad,
                },
            ],
        };

        
        let result_var = executor.unique_variables.get("Unique(0x113)").unwrap();
        assert_eq!(result_var.concrete, zorya::concolic::ConcreteVar::Int(30), "The result of 10 + 20 should be 30.");

    }

    #[test]
    fn test_handle_int_sub() {
        let mut executor = setup_executor();
        let symbolic_var0 = SymbolicVar::Int(BV::from_u64(&executor.context, 30, 64));
        let symbolic_var1 = SymbolicVar::Int(BV::from_u64(&executor.context, 10, 64));
        // Setup test values and varnodes
        let input0 = ConcolicVar::new_concrete_and_symbolic_int(30, symbolic_var0.to_bv(&executor.context), &executor.context, 64);
        let input1 = ConcolicVar::new_concrete_and_symbolic_int(10, symbolic_var1.to_bv(&executor.context), &executor.context, 64);
        executor.unique_variables.insert("Unique(0x114)".to_string(), input0);
        executor.unique_variables.insert("Unique(0x115)".to_string(), input1);
        // Define an instruction using these variables
        let instruction = Inst {
            opcode: Opcode::IntSub,
            output: Some(Varnode {
                var: Var::Unique(0x116),
                size: Size::Quad,
            }),
            inputs: vec![
                Varnode {
                    var: Var::Unique(0x114),
                    size: Size::Quad,
                },
                Varnode {
                    var: Var::Unique(0x115),
                    size: Size::Quad,
                },
            ],
        };
        // Execute the handle_int_sub function
        let result = handle_int_sub(&mut executor, instruction);
        // Verify the results
        assert!(result.is_ok(), "The subtraction should succeed.");
        let result_var = executor.unique_variables.get("Unique(0x116)").unwrap();
        assert_eq!(result_var.concrete, zorya::concolic::ConcreteVar::Int(20), "The result of 30 - 10 should be 20.");
    }

    #[test]
    fn test_handle_int_xor() {
        let mut executor = setup_executor();
        let symbolic_var0 = SymbolicVar::Int(BV::from_u64(&executor.context, 5, 64));
        let symbolic_var1 = SymbolicVar::Int(BV::from_u64(&executor.context, 3, 64));
        // Setup test values and varnodes
        let input0 = ConcolicVar::new_concrete_and_symbolic_int(5, symbolic_var0.to_bv(&executor.context), &executor.context, 64);
        let input1 = ConcolicVar::new_concrete_and_symbolic_int(3, symbolic_var1.to_bv(&executor.context), &executor.context, 64);
        executor.unique_variables.insert("Unique(0x117)".to_string(), input0);
        executor.unique_variables.insert("Unique(0x118)".to_string(), input1);
        // Define an instruction using these variables
        let instruction = Inst {
            opcode: Opcode::IntXor,
            output: Some(Varnode {
                var: Var::Unique(0x119),
                size: Size::Quad,
            }),
            inputs: vec![
                Varnode {
                    var: Var::Unique(0x117),
                    size: Size::Quad,
                },
                Varnode {
                    var: Var::Unique(0x118),
                    size: Size::Quad,
                },
            ],
        };
        // Execute the handle_int_xor function
        let result = handle_int_xor(&mut executor, instruction);
        // Verify the results
        assert!(result.is_ok(), "The XOR operation should succeed.");
        let result_var = executor.unique_variables.get("Unique(0x119)").unwrap();
        assert_eq!(result_var.concrete, zorya::concolic::ConcreteVar::Int(6), "The result of 5 XOR 3 should be 6.");
    }

    #[test]
    fn test_handle_int_equal() {
        let mut executor = setup_executor();
        let symbolic_var0 = SymbolicVar::Int(BV::from_u64(&executor.context, 10, 64));
        let symbolic_var1 = SymbolicVar::Int(BV::from_u64(&executor.context, 20, 64));
        // Setup test values and varnodes
        let input0 = ConcolicVar::new_concrete_and_symbolic_int(10, symbolic_var0.to_bv(&executor.context), &executor.context, 64);
        let input1 = ConcolicVar::new_concrete_and_symbolic_int(20, symbolic_var1.to_bv(&executor.context), &executor.context, 64);
        executor.unique_variables.insert("Unique(0x11a)".to_string(), input0);
        executor.unique_variables.insert("Unique(0x11b)".to_string(), input1);
        // Define an instruction using these variables
        let instruction = Inst {
            opcode: Opcode::IntEqual,
            output: Some(Varnode {
                var: Var::Unique(0x11c),
                size: Size::Quad,
            }),
            inputs: vec![
                Varnode {
                    var: Var::Unique(0x11a),
                    size: Size::Quad,
                },
                Varnode {
                    var: Var::Unique(0x11b),
                    size: Size::Quad,
                },
            ],
        };
        // Execute the handle_int_equal function
        let result = handle_int_equal(&mut executor, instruction);
        // Verify the results
        assert!(result.is_ok(), "The equality check should succeed.");
        let result_var = executor.unique_variables.get("Unique(0x11c)").unwrap();
        assert_eq!(result_var.concrete, zorya::concolic::ConcreteVar::Int(0), "The result of 10 == 20 should be 0.");
    }

    #[test]
    fn test_handle_int_notequal() {
        let mut executor = setup_executor();
        let symbolic_var0 = SymbolicVar::Int(BV::from_u64(&executor.context, 10, 64));
        let symbolic_var1 = SymbolicVar::Int(BV::from_u64(&executor.context, 20, 64));
        // Setup test values and varnodes
        let input0 = ConcolicVar::new_concrete_and_symbolic_int(10, symbolic_var0.to_bv(&executor.context), &executor.context, 64);
        let input1 = ConcolicVar::new_concrete_and_symbolic_int(20, symbolic_var1.to_bv(&executor.context), &executor.context, 64);
        executor.unique_variables.insert("Unique(0x11d)".to_string(), input0);
        executor.unique_variables.insert("Unique(0x11e)".to_string(), input1);
        // Define an instruction using these variables
        let instruction = Inst {
            opcode: Opcode::IntNotEqual,
            output: Some(Varnode {
                var: Var::Unique(0x11f),
                size: Size::Quad,
            }),
            inputs: vec![
                Varnode {
                    var: Var::Unique(0x11d),
                    size: Size::Quad,
                },
                Varnode {
                    var: Var::Unique(0x11e),
                    size: Size::Quad,
                },
            ],
        };
        // Execute the handle_int_notequal function
        let result = handle_int_notequal(&mut executor, instruction);
        // Verify the results
        assert!(result.is_ok(), "The inequality check should succeed.");
        let result_var = executor.unique_variables.get("Unique(0x11f)").unwrap();
        assert_eq!(result_var.concrete, zorya::concolic::ConcreteVar::Int(1), "The result of 10 != 20 should be 1.");
    }

    #[test]
    fn test_handle_int_less() {
        let mut executor = setup_executor();
        
        // Test case 1: 10 < 20
        let symbolic_var0 = SymbolicVar::Int(BV::from_u64(&executor.context, 10, 64));
        let symbolic_var1 = SymbolicVar::Int(BV::from_u64(&executor.context, 20, 64));
        let input0 = ConcolicVar::new_concrete_and_symbolic_int(10, symbolic_var0.to_bv(&executor.context), &executor.context, 64);
        let input1 = ConcolicVar::new_concrete_and_symbolic_int(20, symbolic_var1.to_bv(&executor.context), &executor.context, 64);
        executor.unique_variables.insert("Unique(0x120)".to_string(), input0);
        executor.unique_variables.insert("Unique(0x121)".to_string(), input1);
        let instruction = Inst {
            opcode: Opcode::IntLess,
            output: Some(Varnode {
                var: Var::Unique(0x122),
                size: Size::Byte,
            }),
            inputs: vec![
                Varnode {
                    var: Var::Unique(0x120),
                    size: Size::Quad,
                },
                Varnode {
                    var: Var::Unique(0x121),
                    size: Size::Quad,
                },
            ],
        };
        let result = handle_int_less(&mut executor, instruction);
        assert!(result.is_ok(), "The less than check should succeed.");
        let result_var = executor.unique_variables.get("Unique(0x122)").unwrap();
        assert_eq!(result_var.concrete, zorya::concolic::ConcreteVar::Int(1), "The result of 10 < 20 should be true.");

        // Test case 2: 30 < 10
        let symbolic_var0 = SymbolicVar::Int(BV::from_u64(&executor.context, 30, 64));
        let symbolic_var1 = SymbolicVar::Int(BV::from_u64(&executor.context, 10, 64));
        let input0 = ConcolicVar::new_concrete_and_symbolic_int(30, symbolic_var0.to_bv(&executor.context), &executor.context, 64);
        let input1 = ConcolicVar::new_concrete_and_symbolic_int(10, symbolic_var1.to_bv(&executor.context), &executor.context, 64);
        executor.unique_variables.insert("Unique(0x123)".to_string(), input0);
        executor.unique_variables.insert("Unique(0x124)".to_string(), input1);
        let instruction = Inst {
            opcode: Opcode::IntLess,
            output: Some(Varnode {
                var: Var::Unique(0x125),
                size: Size::Byte,
            }),
            inputs: vec![
                Varnode {
                    var: Var::Unique(0x123),
                    size: Size::Quad,
                },
                Varnode {
                    var: Var::Unique(0x124),
                    size: Size::Quad,
                },
            ],
        };
        let result = handle_int_less(&mut executor, instruction);
        assert!(result.is_ok(), "The less than check should succeed.");
        let result_var = executor.unique_variables.get("Unique(0x125)").unwrap();
        assert_eq!(result_var.concrete, zorya::concolic::ConcreteVar::Int(0), "The result of 30 < 10 should be false.");

        // Test case 3: 5 < 3
        let symbolic_var0 = SymbolicVar::Int(BV::from_u64(&executor.context, 5, 64));
        let symbolic_var1 = SymbolicVar::Int(BV::from_u64(&executor.context, 3, 64));
        let input0 = ConcolicVar::new_concrete_and_symbolic_int(5, symbolic_var0.to_bv(&executor.context), &executor.context, 64);
        let input1 = ConcolicVar::new_concrete_and_symbolic_int(3, symbolic_var1.to_bv(&executor.context), &executor.context, 64);
        executor.unique_variables.insert("Unique(0x126)".to_string(), input0);
        executor.unique_variables.insert("Unique(0x127)".to_string(), input1);
        let instruction = Inst {
            opcode: Opcode::IntLess,
            output: Some(Varnode {
                var: Var::Unique(0x128),
                size: Size::Byte,
            }),
            inputs: vec![
                Varnode {
                    var: Var::Unique(0x126),
                    size: Size::Quad,
                },
                Varnode {
                    var: Var::Unique(0x127),
                    size: Size::Quad,
                },
            ],
        };
        let result = handle_int_less(&mut executor, instruction);
        assert!(result.is_ok(), "The less than check should succeed.");
        let result_var = executor.unique_variables.get("Unique(0x128)").unwrap();
        assert_eq!(result_var.concrete, zorya::concolic::ConcreteVar::Int(0), "The result of 5 < 3 should be false.");
    }

    #[test]
    fn test_handle_int_sless() {
        let mut executor = setup_executor();

        // Test case 1: 10 < 20 (signed comparison)
        let symbolic_var0 = SymbolicVar::Int(BV::from_u64(&executor.context, 10, 64));
        let symbolic_var1 = SymbolicVar::Int(BV::from_u64(&executor.context, 20, 64));
        let input0 = ConcolicVar::new_concrete_and_symbolic_int(10, symbolic_var0.to_bv(&executor.context), &executor.context, 64);
        let input1 = ConcolicVar::new_concrete_and_symbolic_int(20, symbolic_var1.to_bv(&executor.context), &executor.context, 64);
        executor.unique_variables.insert("Unique(0x129)".to_string(), input0);
        executor.unique_variables.insert("Unique(0x12a)".to_string(), input1);
        
        let instruction = Inst {
            opcode: Opcode::IntSLess,
            output: Some(Varnode {
                var: Var::Unique(0x12b),
                size: Size::Byte,
            }),
            inputs: vec![
                Varnode {
                    var: Var::Unique(0x129),
                    size: Size::Quad,
                },
                Varnode {
                    var: Var::Unique(0x12a),
                    size: Size::Quad,
                },
            ],
        };

        let result = handle_int_sless(&mut executor, instruction);
        assert!(result.is_ok(), "The signed less than check should succeed.");
        let result_var = executor.unique_variables.get("Unique(0x12b)").unwrap();
        assert_eq!(result_var.concrete, zorya::concolic::ConcreteVar::Int(1), "The result of 10 < 20 (signed) should be true.");

        // Test case 2: 10 < 5 (signed comparison)
        let symbolic_var0 = SymbolicVar::Int(BV::from_i64(&executor.context, 10, 64));
        let symbolic_var1 = SymbolicVar::Int(BV::from_u64(&executor.context, 5, 64));
        let input0 = ConcolicVar::new_concrete_and_symbolic_int(10, symbolic_var0.to_bv(&executor.context), &executor.context, 64);
        let input1 = ConcolicVar::new_concrete_and_symbolic_int(5, symbolic_var1.to_bv(&executor.context), &executor.context, 64);
        executor.unique_variables.insert("Unique(0x12c)".to_string(), input0);
        executor.unique_variables.insert("Unique(0x12d)".to_string(), input1);
        
        let instruction = Inst {
            opcode: Opcode::IntSLess,
            output: Some(Varnode {
                var: Var::Unique(0x12e),
                size: Size::Byte,
            }),
            inputs: vec![
                Varnode {
                    var: Var::Unique(0x12c),
                    size: Size::Quad,
                },
                Varnode {
                    var: Var::Unique(0x12d),
                    size: Size::Quad,
                },
            ],
        };

        let result = handle_int_sless(&mut executor, instruction);
        assert!(result.is_ok(), "The signed less than check should succeed.");
        let result_var = executor.unique_variables.get("Unique(0x12e)").unwrap();
        assert_eq!(result_var.concrete, zorya::concolic::ConcreteVar::Int(0), "The result of 10 < 5 (signed) should be false.");
    }

    #[test]
    fn test_handle_int_and() {
        let mut executor = setup_executor();
        let symbolic_var0 = SymbolicVar::Int(BV::from_u64(&executor.context, 10, 64));
        let symbolic_var1 = SymbolicVar::Int(BV::from_u64(&executor.context, 20, 64));
        // Setup test values and varnodes
        let input0 = ConcolicVar::new_concrete_and_symbolic_int(10, symbolic_var0.to_bv(&executor.context), &executor.context, 64);
        let input1 = ConcolicVar::new_concrete_and_symbolic_int(20, symbolic_var1.to_bv(&executor.context), &executor.context, 64);
        executor.unique_variables.insert("Unique(0x12f)".to_string(), input0);
        executor.unique_variables.insert("Unique(0x130)".to_string(), input1);
        // Define an instruction using these variables
        let instruction = Inst {
            opcode: Opcode::IntAnd,
            output: Some(Varnode {
                var: Var::Unique(0x131),
                size: Size::Byte,
            }),
            inputs: vec![
                Varnode {
                    var: Var::Unique(0x12f),
                    size: Size::Quad,
                },
                Varnode {
                    var: Var::Unique(0x130),
                    size: Size::Quad,
                },
            ],
        };
        // Execute the handle_int_and function
        let result = handle_int_and(&mut executor, instruction);
        // Verify the results
        assert!(result.is_ok(), "The AND operation should succeed.");
        let result_var = executor.unique_variables.get("Unique(0x131)").unwrap();
        assert_eq!(result_var.concrete, zorya::concolic::ConcreteVar::Int(0), "The result of 10 AND 20 should be 0.");
    }

    #[test]
    fn test_handle_int_carry() {
        let mut executor = setup_executor();
        let symbolic_var0 = SymbolicVar::Int(BV::from_u64(&executor.context, 10, 64));
        let symbolic_var1 = SymbolicVar::Int(BV::from_u64(&executor.context, 20, 64));
        // Setup test values and varnodes
        let input0 = ConcolicVar::new_concrete_and_symbolic_int(10, symbolic_var0.to_bv(&executor.context), &executor.context, 64);
        let input1 = ConcolicVar::new_concrete_and_symbolic_int(20, symbolic_var1.to_bv(&executor.context), &executor.context, 64);
        executor.unique_variables.insert("Unique(0x132)".to_string(), input0);
        executor.unique_variables.insert("Unique(0x133)".to_string(), input1);
        // Define an instruction using these variables
        let instruction = Inst {
            opcode: Opcode::IntCarry,
            output: Some(Varnode {
                var: Var::Unique(0x134),
                size: Size::Byte,
            }),
            inputs: vec![
                Varnode {
                    var: Var::Unique(0x132),
                    size: Size::Quad,
                },
                Varnode {
                    var: Var::Unique(0x133),
                    size: Size::Quad,
                },
            ],
        };
        // Execute the handle_int_carry function
        let result = handle_int_carry(&mut executor, instruction);
        // Verify the results
        assert!(result.is_ok(), "The carry check should succeed.");
        let result_var = executor.unique_variables.get("Unique(0x134)").unwrap();
        assert_eq!(result_var.concrete, zorya::concolic::ConcreteVar::Int(0), "The result of carry check should be 0.");
    }

    #[test]
    fn test_handle_int_scarry() {
        let mut executor = setup_executor();
        
        // Test case 1: 10 + 20 overflows
        let symbolic_var0 = SymbolicVar::Int(BV::from_u64(&executor.context, 10000000000000000000, 64));
        let symbolic_var1 = SymbolicVar::Int(BV::from_u64(&executor.context, 10000000000000000000, 64));
        let input0 = ConcolicVar::new_concrete_and_symbolic_int(10000000000000000000, symbolic_var0.to_bv(&executor.context), &executor.context, 64);
        let input1 = ConcolicVar::new_concrete_and_symbolic_int(10000000000000000000, symbolic_var1.to_bv(&executor.context), &executor.context, 64);
        executor.unique_variables.insert("Unique(0x135)".to_string(), input0);
        executor.unique_variables.insert("Unique(0x136)".to_string(), input1);
        let instruction = Inst {
            opcode: Opcode::IntSCarry,
            output: Some(Varnode {
                var: Var::Unique(0x137),
                size: Size::Byte,
            }),
            inputs: vec![
                Varnode {
                    var: Var::Unique(0x135),
                    size: Size::Quad,
                },
                Varnode {
                    var: Var::Unique(0x136),
                    size: Size::Quad,
                },
            ],
        };
        let result = handle_int_scarry(&mut executor, instruction);
        assert!(result.is_ok(), "The signed carry check should succeed.");
        let result_var = executor.unique_variables.get("Unique(0x137)").unwrap();
        assert_eq!(result_var.concrete, zorya::concolic::ConcreteVar::Int(1), "The result of 10000000000000000000 + 10000000000000000000 should overflow."); 
    }

    #[test]
    fn test_handle_int_sborrow() {
        let mut executor = setup_executor();
        
        // Test case 1: 10 - 20 underflows
        let symbolic_var0 = SymbolicVar::Int(BV::from_u64(&executor.context, 10, 64));
        let symbolic_var1 = SymbolicVar::Int(BV::from_u64(&executor.context, 20, 64));
        let input0 = ConcolicVar::new_concrete_and_symbolic_int(10, symbolic_var0.to_bv(&executor.context), &executor.context, 64);
        let input1 = ConcolicVar::new_concrete_and_symbolic_int(20, symbolic_var1.to_bv(&executor.context), &executor.context, 64);
        executor.unique_variables.insert("Unique(0x138)".to_string(), input0);
        executor.unique_variables.insert("Unique(0x139)".to_string(), input1);
        let instruction = Inst {
            opcode: Opcode::IntSBorrow,
            output: Some(Varnode {
                var: Var::Unique(0x13a),
                size: Size::Byte,
            }),
            inputs: vec![
                Varnode {
                    var: Var::Unique(0x138),
                    size: Size::Quad,
                },
                Varnode {
                    var: Var::Unique(0x139),
                    size: Size::Quad,
                },
            ],
        };
        let result = handle_int_sborrow(&mut executor, instruction);
        assert!(result.is_ok(), "The signed borrow check should succeed.");
        let result_var = executor.unique_variables.get("Unique(0x13a)").unwrap();
        assert_eq!(result_var.concrete, zorya::concolic::ConcreteVar::Int(1), "The result of 10 - 20 should underflow.");
        
        // Test case 2: 20 - 10 does not underflow
        let symbolic_var0 = SymbolicVar::Int(BV::from_u64(&executor.context, 20, 64));
        let symbolic_var1 = SymbolicVar::Int(BV::from_u64(&executor.context, 10, 64));
        let input0 = ConcolicVar::new_concrete_and_symbolic_int(20, symbolic_var0.to_bv(&executor.context), &executor.context, 64);
        let input1 = ConcolicVar::new_concrete_and_symbolic_int(10, symbolic_var1.to_bv(&executor.context), &executor.context, 64);
        executor.unique_variables.insert("Unique(0x13b)".to_string(), input0);
        executor.unique_variables.insert("Unique(0x13c)".to_string(), input1);
        let instruction = Inst {
            opcode: Opcode::IntSBorrow,
            output: Some(Varnode {
                var: Var::Unique(0x13d),
                size: Size::Byte,
            }),
            inputs: vec![
                Varnode {
                    var: Var::Unique(0x13b),
                    size: Size::Quad,
                },
                Varnode {
                    var: Var::Unique(0x13c),
                    size: Size::Quad,
                },
            ],
        };
        let result = handle_int_sborrow(&mut executor, instruction);
        assert!(result.is_ok(), "The signed borrow check should succeed.");
        let result_var = executor.unique_variables.get("Unique(0x13d)").unwrap();
        assert_eq!(result_var.concrete, zorya::concolic::ConcreteVar::Int(0), "The result of 20 - 10 should not underflow.");
    }

    #[test]
    fn test_handle_int_zext() {
        let mut executor = setup_executor();
        
        // Test case 1: Zero extend 8-bit value to 16 bits
        let symbolic_var0 = SymbolicVar::Int(BV::from_u64(&executor.context, 255, 8));
        let input0 = ConcolicVar::new_concrete_and_symbolic_int(255, symbolic_var0.to_bv(&executor.context), &executor.context, 8);
        executor.unique_variables.insert("Unique(0x13e)".to_string(), input0);
        let instruction = Inst {
            opcode: Opcode::IntZExt,
            output: Some(Varnode {
                var: Var::Unique(0x13f),
                size: Size::Half, 
            }),
            inputs: vec![
                Varnode {
                    var: Var::Unique(0x13e),
                    size: Size::Byte,
                },
            ],
        };
        let result = handle_int_zext(&mut executor, instruction);
        assert!(result.is_ok(), "The zero extend operation should succeed.");
        let result_var = executor.unique_variables.get("Unique(0x13f)").unwrap();
        assert_eq!(result_var.concrete, zorya::concolic::ConcreteVar::Int(255), "The result of zero extending 8-bit value 255 should be 255.");

        // Test case 2: Zero extend 16-bit value to 32 bits
        let symbolic_var0 = SymbolicVar::Int(BV::from_u64(&executor.context, 65535, 16));
        let input0 = ConcolicVar::new_concrete_and_symbolic_int(65535, symbolic_var0.to_bv(&executor.context), &executor.context, 16);
        executor.unique_variables.insert("Unique(0x140)".to_string(), input0);
        let instruction = Inst {
            opcode: Opcode::IntZExt,
            output: Some(Varnode {
                var: Var::Unique(0x141),
                size: Size::Word,  
            }),
            inputs: vec![
                Varnode {
                    var: Var::Unique(0x140),
                    size: Size::Half,
                },
            ],
        };
        let result = handle_int_zext(&mut executor, instruction);
        assert!(result.is_ok(), "The zero extend operation should succeed.");
        let result_var = executor.unique_variables.get("Unique(0x141)").unwrap();
        assert_eq!(result_var.concrete, zorya::concolic::ConcreteVar::Int(65535), "The result of zero extending 16-bit value 65535 should be 65535.");
    }
}
