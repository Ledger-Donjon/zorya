// SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

use parser::parser::{Inst, Opcode, Var, Varnode};
use z3::{Config, Context};
use zorya::concolic::ConcolicExecutor;

#[cfg(test)]
mod tests {
    use parser::parser::Size;
    use z3::ast::Float;
    use zorya::concolic::executor_float::{
        handle_float_equal, handle_float_less, handle_float_nan,
    };
    use zorya::concolic::{ConcolicVar, ConcreteVar, Logger, SymbolicVar};

    use super::*;

    fn setup_executor() -> ConcolicExecutor<'static> {
        let cfg = Config::new();
        let ctx = Box::leak(Box::new(Context::new(&cfg)));
        let logger = Logger::new("execution_log.txt", false).expect("Failed to create logger");
        let trace_logger =
            Logger::new("trace_log.txt", true).expect("Failed to create trace logger");
        let mut executor = ConcolicExecutor::new_for_tests(ctx, logger, trace_logger)
            .expect("Failed to create executor");

        for (start_addr, size) in [(0x10000u64, 0x1000usize), (0x20000, 0x1000)] {
            if executor
                .state
                .memory
                .mmap(start_addr, size, 0x3, 0x20, -1, 0)
                .is_err()
            {
                println!("Failed to create memory region at 0x{:x}", start_addr);
            }
        }

        executor.current_address = Some(0x123);
        executor
    }

    #[test]
    fn test_handle_float_nan() {
        let mut executor = setup_executor();

        // Create a NaN value properly using SymbolicVar::Float
        let nan_bits = f64::NAN.to_bits();
        let nan_float = Float::from_f64(executor.context, f64::NAN);

        let nan_concolic_var = ConcolicVar {
            concrete: ConcreteVar::Int(nan_bits),
            symbolic: SymbolicVar::Float(nan_float),
            ctx: executor.context,
        };

        executor
            .unique_variables
            .insert("Unique(0x1)".to_string(), nan_concolic_var);

        let instruction = Inst {
            opcode: Opcode::FloatNaN,
            output: Some(Varnode {
                var: Var::Unique(0x2),
                size: Size::Byte, // Boolean result, so use Byte size
            }),
            inputs: vec![Varnode {
                var: Var::Unique(0x1),
                size: Size::Quad,
            }],
        };

        let result = handle_float_nan(&mut executor, instruction);
        assert!(
            result.is_ok(),
            "Float NaN detection should succeed: {:?}",
            result
        );

        let result_var = executor.unique_variables.get("Unique(0x2)").unwrap();
        // The result should be a boolean indicating NaN detection
        match &result_var.concrete {
            ConcreteVar::Bool(b) => assert!(*b, "The result of NaN check should be true."),
            ConcreteVar::Int(i) => assert!(
                *i != 0,
                "The result of NaN check should be non-zero (true)."
            ),
            _ => panic!("Unexpected concrete type for NaN check result"),
        }
    }

    #[test]
    fn test_handle_float_equal() {
        let mut executor = setup_executor();

        // Setup two floating-point numbers using proper Float types
        let input0 = 2.0_f64;
        let input1 = 2.0_f64;
        let input0_bits = input0.to_bits();
        let input1_bits = input1.to_bits();

        let input0_var = ConcolicVar {
            concrete: ConcreteVar::Int(input0_bits),
            symbolic: SymbolicVar::Float(Float::from_f64(executor.context, input0)),
            ctx: executor.context,
        };
        let input1_var = ConcolicVar {
            concrete: ConcreteVar::Int(input1_bits),
            symbolic: SymbolicVar::Float(Float::from_f64(executor.context, input1)),
            ctx: executor.context,
        };

        executor
            .unique_variables
            .insert("Unique(0x100)".to_string(), input0_var);
        executor
            .unique_variables
            .insert("Unique(0x101)".to_string(), input1_var);

        let instruction = Inst {
            opcode: Opcode::FloatEqual,
            output: Some(Varnode {
                var: Var::Unique(0x102),
                size: Size::Byte, // Boolean result
            }),
            inputs: vec![
                Varnode {
                    var: Var::Unique(0x100),
                    size: Size::Quad,
                },
                Varnode {
                    var: Var::Unique(0x101),
                    size: Size::Quad,
                },
            ],
        };

        let result = handle_float_equal(&mut executor, instruction);
        assert!(result.is_ok(), "FLOAT_EQUAL should succeed: {:?}", result);

        let result_var = executor.unique_variables.get("Unique(0x102)").unwrap();
        match &result_var.concrete {
            ConcreteVar::Bool(b) => assert!(*b, "FLOAT_EQUAL should return true for equal inputs."),
            ConcreteVar::Int(i) => assert!(
                *i != 0,
                "FLOAT_EQUAL should return non-zero (true) for equal inputs."
            ),
            _ => panic!("Unexpected concrete type for FLOAT_EQUAL result"),
        }
    }

    #[test]
    fn test_handle_float_less() {
        let mut executor = setup_executor();

        // Setup two floating-point numbers for comparison
        let input0 = 100.0_f64;
        let input1 = 200.0_f64;
        let input0_bits = input0.to_bits();
        let input1_bits = input1.to_bits();

        let input0_var = ConcolicVar {
            concrete: ConcreteVar::Int(input0_bits),
            symbolic: SymbolicVar::Float(Float::from_f64(executor.context, input0)),
            ctx: executor.context,
        };
        let input1_var = ConcolicVar {
            concrete: ConcreteVar::Int(input1_bits),
            symbolic: SymbolicVar::Float(Float::from_f64(executor.context, input1)),
            ctx: executor.context,
        };

        executor
            .unique_variables
            .insert("Unique(0x100)".to_string(), input0_var);
        executor
            .unique_variables
            .insert("Unique(0x101)".to_string(), input1_var);

        let instruction = Inst {
            opcode: Opcode::FloatLess,
            output: Some(Varnode {
                var: Var::Unique(0x102),
                size: Size::Byte, // Boolean result
            }),
            inputs: vec![
                Varnode {
                    var: Var::Unique(0x100),
                    size: Size::Quad,
                },
                Varnode {
                    var: Var::Unique(0x101),
                    size: Size::Quad,
                },
            ],
        };

        let result = handle_float_less(&mut executor, instruction);
        assert!(result.is_ok(), "FLOAT_LESS should succeed: {:?}", result);

        let result_var = executor.unique_variables.get("Unique(0x102)").unwrap();
        match &result_var.concrete {
            ConcreteVar::Bool(b) => {
                assert!(*b, "FLOAT_LESS should return true for input0 < input1.")
            }
            ConcreteVar::Int(i) => assert!(
                *i != 0,
                "FLOAT_LESS should return non-zero (true) for input0 < input1."
            ),
            _ => panic!("Unexpected concrete type for FLOAT_LESS result"),
        }
    }

    #[test]
    fn test_handle_float_not_equal() {
        let mut executor = setup_executor();

        // Setup two different floating-point numbers
        let input0 = 2.0_f64;
        let input1 = 3.0_f64;
        let input0_bits = input0.to_bits();
        let input1_bits = input1.to_bits();

        let input0_var = ConcolicVar {
            concrete: ConcreteVar::Int(input0_bits),
            symbolic: SymbolicVar::Float(Float::from_f64(executor.context, input0)),
            ctx: executor.context,
        };
        let input1_var = ConcolicVar {
            concrete: ConcreteVar::Int(input1_bits),
            symbolic: SymbolicVar::Float(Float::from_f64(executor.context, input1)),
            ctx: executor.context,
        };

        executor
            .unique_variables
            .insert("Unique(0x200)".to_string(), input0_var);
        executor
            .unique_variables
            .insert("Unique(0x201)".to_string(), input1_var);

        let instruction = Inst {
            opcode: Opcode::FloatEqual,
            output: Some(Varnode {
                var: Var::Unique(0x202),
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

        let result = handle_float_equal(&mut executor, instruction);
        assert!(
            result.is_ok(),
            "FLOAT_EQUAL should succeed for different values: {:?}",
            result
        );

        let result_var = executor.unique_variables.get("Unique(0x202)").unwrap();
        match &result_var.concrete {
            ConcreteVar::Bool(b) => {
                assert!(!*b, "FLOAT_EQUAL should return false for different inputs.")
            }
            ConcreteVar::Int(i) => assert!(
                *i == 0,
                "FLOAT_EQUAL should return zero (false) for different inputs."
            ),
            _ => panic!("Unexpected concrete type for FLOAT_EQUAL result"),
        }
    }

    #[test]
    fn test_handle_float_less_false() {
        let mut executor = setup_executor();

        // Setup two floating-point numbers where first is greater than second
        let input0 = 300.0_f64;
        let input1 = 200.0_f64;
        let input0_bits = input0.to_bits();
        let input1_bits = input1.to_bits();

        let input0_var = ConcolicVar {
            concrete: ConcreteVar::Int(input0_bits),
            symbolic: SymbolicVar::Float(Float::from_f64(executor.context, input0)),
            ctx: executor.context,
        };
        let input1_var = ConcolicVar {
            concrete: ConcreteVar::Int(input1_bits),
            symbolic: SymbolicVar::Float(Float::from_f64(executor.context, input1)),
            ctx: executor.context,
        };

        executor
            .unique_variables
            .insert("Unique(0x300)".to_string(), input0_var);
        executor
            .unique_variables
            .insert("Unique(0x301)".to_string(), input1_var);

        let instruction = Inst {
            opcode: Opcode::FloatLess,
            output: Some(Varnode {
                var: Var::Unique(0x302),
                size: Size::Byte,
            }),
            inputs: vec![
                Varnode {
                    var: Var::Unique(0x300),
                    size: Size::Quad,
                },
                Varnode {
                    var: Var::Unique(0x301),
                    size: Size::Quad,
                },
            ],
        };

        let result = handle_float_less(&mut executor, instruction);
        assert!(result.is_ok(), "FLOAT_LESS should succeed: {:?}", result);

        let result_var = executor.unique_variables.get("Unique(0x302)").unwrap();
        match &result_var.concrete {
            ConcreteVar::Bool(b) => {
                assert!(!*b, "FLOAT_LESS should return false for input0 > input1.")
            }
            ConcreteVar::Int(i) => assert!(
                *i == 0,
                "FLOAT_LESS should return zero (false) for input0 > input1."
            ),
            _ => panic!("Unexpected concrete type for FLOAT_LESS result"),
        }
    }
}
