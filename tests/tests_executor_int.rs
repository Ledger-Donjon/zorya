use z3::{Config, Context, Solver};
use zorya::concolic::ConcolicExecutor;
use zorya::state::State;
use parser::parser::{Inst, Opcode, Var, Varnode};

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use goblin::elf::Sym;
    use parser::parser::Size;
    use z3::ast::BV;
    use zorya::{concolic::{executor_int::{handle_int_add, handle_int_and, handle_int_carry, handle_int_equal, handle_int_less, handle_int_notequal, handle_int_sborrow, handle_int_scarry, handle_int_sless, handle_int_sub, handle_int_zext}, symbolic_var, ConcolicEnum, ConcolicVar, Logger}, executor::SymbolicVar};

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

        // Execute the handle_int_add function
        let result = handle_int_add(&mut executor, instruction);

        // Verify the results
        assert!(result.is_ok(), "The addition should succeed.");
        let result_var = executor.unique_variables.get("Unique(0x113)").unwrap();
        assert_eq!(result_var.concrete, zorya::concolic::ConcreteVar::Int(30), "The result of 10 + 20 should be 30.");

    }
}