use z3::{Config, Context, Solver};

// Assuming these are defined in your project under the respective modules
use zorya::concolic::ConcolicExecutor;
use zorya::state::State;
use parser::parser::{Inst, Opcode, Var, Varnode};

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, time::{Duration, Instant}};

    use parser::parser::Size;
    use zorya::state::memory_x86_64::MemoryConcolicValue;

    use super::*;
    
    fn setup_executor() -> ConcolicExecutor<'static> {
        let cfg = Config::new();
        let ctx = Box::leak(Box::new(Context::new(&cfg)));
        let state = State::default_for_tests(ctx).expect("Failed to create state.");
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
    fn test_handle_cbranch() {
        let mut executor = setup_executor();
        let cbranch_inst = Inst {
            opcode: Opcode::CBranch,
            output: None,
            inputs: vec![
                Varnode {
                    var: Var::Const("0x3000".to_string()),
                    size: Size::Quad,
                },
                Varnode {
                    var: Var::Const("1".to_string()), // Branch condition: true
                    size: Size::Byte,
                },
            ],
        };

        let result = executor.handle_cbranch(cbranch_inst);
        assert!(result.is_ok());

        let cpu_state_guard = executor.state.cpu_state.lock().unwrap();
        let rip_value = cpu_state_guard.get_register_value_by_offset(0x288).expect("RIP register not found");
        assert_eq!(rip_value, 0x3000);
    }

    #[test]
    fn test_handle_copy() {
        let mut executor = setup_executor();
        let copy_inst = Inst {
            opcode: Opcode::Copy,
            output: Some(Varnode {
                var: Var::Unique(0x4000),
                size: Size::Quad,
            }),
            inputs: vec![
                Varnode {
                    var: Var::Const("5678".to_string()),
                    size: Size::Quad,
                },
            ],
        };

        let result = executor.handle_copy(copy_inst);
        assert!(result.is_ok());

        let unique_name = "Unique(0x4000)".to_string();
        let unique_var = executor.unique_variables.get(&unique_name).expect("Unique variable not found");
        assert_eq!(unique_var.concrete.to_u64(), 5678);
    }

    #[test]
    fn test_handle_popcount() {
        let mut executor = setup_executor();
        let popcount_inst = Inst {
            opcode: Opcode::PopCount,
            output: Some(Varnode {
                var: Var::Unique(0x5000),
                size: Size::Byte,
            }),
            inputs: vec![
                Varnode {
                    var: Var::Const("0xAA".to_string()), // 0xAA is 10101010 in binary
                    size: Size::Quad,
                },
            ],
        };

        let result = executor.handle_popcount(popcount_inst);
        assert!(result.is_ok(), "handle_popcount returned an error: {:?}", result);

        let unique_name = "Unique(0x5000)".to_string();
        let unique_var = executor.unique_variables.get(&unique_name).expect("Unique variable not found");
        assert_eq!(unique_var.concrete.to_u64(), 4); // 0b10101010 has 4 bits set to 1
    }
}
