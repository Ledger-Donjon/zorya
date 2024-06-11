use z3::{Config, Context, Solver};
use zorya::concolic::ConcolicExecutor;
use zorya::state::State;
use parser::parser::{Inst, Opcode, Var, Varnode};

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use parser::parser::Size;
    use zorya::concolic::{executor_int::{handle_int_add, handle_int_and, handle_int_carry, handle_int_equal, handle_int_less, handle_int_sborrow, handle_int_scarry, handle_int_sless, handle_int_sub}, Logger};

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
            current_address: None,
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
        let int_equal_inst = Inst {
            opcode: Opcode::IntEqual,
            output: Some(Varnode {
                var: Var::Unique(0xc000),
                size: Size::Byte, // The result of a boolean comparison
            }),
            inputs: vec![
                Varnode {
                    var: Var::Const("5".to_string()),
                    size: Size::Quad,
                },
                Varnode {
                    var: Var::Const("5".to_string()),
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
        let int_carry_inst = Inst {
            opcode: Opcode::IntCarry,
            output: Some(Varnode {
                var: Var::Unique(0xd000),
                size: Size::Byte, // Boolean result
            }),
            inputs: vec![
                Varnode {
                    var: Var::Const("0xFFFFFFFFFFFFFFFF".to_string()),
                    size: Size::Quad,
                },
                Varnode {
                    var: Var::Const("1".to_string()),
                    size: Size::Quad,
                },
            ],
        };

        let result = handle_int_carry(&mut executor, int_carry_inst);
        assert!(result.is_ok(), "handle_int_carry returned an error: {:?}", result);

        let unique_name = "Unique(0xd000)".to_string();
        let unique_var = executor.unique_variables.get(&unique_name).expect("Unique variable not found");
        assert_eq!(unique_var.concrete.to_u64(), 1); // Ensure it correctly identifies the carry
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

}
