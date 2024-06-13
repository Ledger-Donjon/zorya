use z3::{Config, Context, Solver};
use zorya::concolic::ConcolicExecutor;
use zorya::state::State;
use parser::parser::{Inst, Opcode, Var, Varnode};

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use parser::parser::Size;
    use zorya::{concolic::{executor_bool::handle_bool_negate, ConcolicEnum, ConcolicVar, Logger}, executor::ConcreteVar};

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
            unique_variables: BTreeMap::new(),
        }
    }

    #[test]
    fn test_handle_bool_negate() {
        let mut executor = setup_executor();

        // Setup: Create and insert a test variable assumed to represent a boolean value 'true' (1)
        let test_bool = ConcolicVar::new_concrete_and_symbolic_int(1, "test_bool", executor.context, 1);
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
            _ => panic!("Unexpected enum variant"),
        }) {
            assert_eq!(negated_var.concrete.to_u64(), 0, "Boolean negation did not produce the expected result");
        } else {
            panic!("Result of BOOL_NEGATE not found or incorrect type");
        }
    }
}