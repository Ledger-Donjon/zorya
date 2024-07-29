use z3::{Config, Context, Solver};
use zorya::concolic::ConcolicExecutor;
use zorya::state::State;
use parser::parser::{Inst, Opcode, Var, Varnode};

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use parser::parser::Size;
    use zorya::concolic::{ConcolicVar, Logger};
    use zorya::concolic::{executor_float::{handle_float_nan}};
    use zorya::executor::SymbolicVar;

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
            current_address: Some(0x123),
            instruction_counter: 0,
            unique_variables: BTreeMap::new(),
            current_lines_number        
        }
    }

    #[test]
    fn test_handle_float_nan() {
        let mut executor = setup_executor();
        let nan_value = f64::NAN; // Represents a NaN value
        let nan_value_symbolic = SymbolicVar::new_float(nan_value, executor.context);

        // Create a floating-point varnode that will be NaN
        let input_var = ConcolicVar::new_concrete_and_symbolic_float(nan_value, nan_value_symbolic.to_float(), executor.context, 64);
        executor.unique_variables.insert("Unique(0x1)".to_string(), input_var);

        // Setup instruction with a single input (NaN)
        let instruction = Inst {
            opcode: Opcode::FloatNaN,
            output: Some(Varnode {
                var: Var::Unique(0x2),
                size: Size::Quad,
            }),
            inputs: vec![
                Varnode {
                    var: Var::Unique(0x1),
                    size: Size::Quad,
                },
            ],
        };

        // Execute the handle_float_nan function
        let result = handle_float_nan(&mut executor, instruction);
        assert!(result.is_ok(), "Float NaN detection should succeed.");

        // Fetch the output varnode to verify it captured NaN correctly
        let result_var = executor.unique_variables.get("Unique(0x2)").unwrap();
        assert_eq!(
            result_var.concrete.to_bool(),
            true,
            "The result of NaN check should be true."
        );

        // Log output for confirmation in tests
        println!("Output of FLOAT_NAN is correct: {}", result_var.concrete.to_bool());
    }
    
}
