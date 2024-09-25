use z3::{Config, Context, Solver};
use zorya::concolic::ConcolicExecutor;
use zorya::state::State;
use parser::parser::{Inst, Opcode, Var, Varnode};

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};
    use parser::parser::Size;
    use z3::ast::Float;
    use zorya::concolic::{ConcolicVar, Logger};
    use zorya::concolic::executor_float::{handle_float_nan, handle_float_equal, handle_float_less};

    use super::*;
    
    fn setup_executor() -> ConcolicExecutor<'static> {
        let cfg = Config::new();
        let ctx = Box::leak(Box::new(Context::new(&cfg)));
        let logger = Logger::new("execution_log.txt").expect("Failed to create logger");
        let state = State::default_for_tests(ctx, logger).expect("Failed to create state.");
        let current_lines_number = 0;
        ConcolicExecutor {
            context: ctx,
            solver: Solver::new(ctx),
            state,
            symbol_table: HashMap::new(),
            current_address: Some(0x123),
            instruction_counter: 0,
            unique_variables: BTreeMap::new(),
            pcode_internal_lines_to_be_jumped: current_lines_number        
        }
    }

    #[test]
    fn test_handle_float_nan() {
        let mut executor = setup_executor();
        let nan_value = f64::NAN.to_bits(); // Convert NaN to its bit representation
        let nan_value_float = Float::from_f64(executor.context, f64::from_bits(nan_value));
        let nan_concolic_var = ConcolicVar::new_concrete_and_symbolic_float(nan_value as f64, nan_value_float.clone(), executor.context, 64);

        executor.unique_variables.insert("Unique(0x1)".to_string(), nan_concolic_var);

        let instruction = Inst {
            opcode: Opcode::FloatNaN,
            output: Some(Varnode {
                var: Var::Unique(0x2),
                size: Size::Quad,
            }),
            inputs: vec![Varnode {
                var: Var::Unique(0x1),
                size: Size::Quad,
            }],
        };

        let result = handle_float_nan(&mut executor, instruction);
        assert!(result.is_ok(), "Float NaN detection should succeed.");

        let result_var = executor.unique_variables.get("Unique(0x2)").unwrap();
        assert!(result_var.concrete.to_bool(), "The result of NaN check should be true.");
    }

    #[test]
    fn test_handle_float_equal() {
        let mut executor = setup_executor();

        // Setup two floating-point numbers, neither being NaN
        let input0 = f64::from_bits(0x4000000000000000); // 2.0
        let input1 = f64::from_bits(0x4000000000000000); // 2.0

        let input0_var = ConcolicVar::new_concrete_and_symbolic_float(input0, Float::from_f64(executor.context, input0), executor.context, 64);
        let input1_var = ConcolicVar::new_concrete_and_symbolic_float(input1, Float::from_f64(executor.context, input1), executor.context, 64);

        executor.unique_variables.insert("Unique(0x100)".to_string(), input0_var);
        executor.unique_variables.insert("Unique(0x101)".to_string(), input1_var);

        let instruction = Inst {
            opcode: Opcode::FloatEqual,
            output: Some(Varnode {
                var: Var::Unique(0x102),
                size: Size::Quad,
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
        assert!(result.is_ok(), "FLOAT_EQUAL should succeed.");
        let result_var = executor.unique_variables.get("Unique(0x102)").unwrap();
        assert!(result_var.concrete.to_bool(), "FLOAT_EQUAL should return true for equal inputs.");
    }

    #[test]
    fn test_handle_float_less() {
        let mut executor = setup_executor();

        // Setup two floating-point numbers for comparison
        let input0 = 100.0;
        let input1 = 200.0;
        let input0_var = ConcolicVar::new_concrete_and_symbolic_float(input0, Float::from_f64(executor.context, input0), executor.context, 64);
        let input1_var = ConcolicVar::new_concrete_and_symbolic_float(input1, Float::from_f64(executor.context, input1), executor.context, 64);

        executor.unique_variables.insert("Unique(0x100)".to_string(), input0_var);
        executor.unique_variables.insert("Unique(0x101)".to_string(), input1_var);

        let instruction = Inst {
            opcode: Opcode::FloatLess,
            output: Some(Varnode {
                var: Var::Unique(0x102),
                size: Size::Quad,
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
        assert!(result.is_ok(), "FLOAT_LESS should succeed.");
        let result_var = executor.unique_variables.get("Unique(0x102)").unwrap();
        assert!(result_var.concrete.to_bool(), "FLOAT_LESS should return true for input0 < input1.");
    }
}
