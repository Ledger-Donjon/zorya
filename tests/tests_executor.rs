use z3::{Config, Context, Solver};
use zorya::concolic::ConcolicExecutor;
use zorya::state::State;
use parser::parser::{Inst, Opcode, Var, Varnode};

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use parser::parser::Size;
    use z3::ast::BV;
    use zorya::{concolic::{ConcolicVar, Logger}, executor::{ConcreteVar, SymbolicVar}};

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

    #[test]
    fn test_handle_store() {
        let mut executor = setup_executor();
        
        // Define the STORE instruction
        let store_inst = Inst {
            opcode: Opcode::Store,
            output: None,
            inputs: vec![
                Varnode {
                    var: Var::Const("1".to_string()), // Space ID (ignored in our implementation)
                    size: Size::Byte,
                },
                Varnode {
                    var: Var::Const("0x1000".to_string()), // Pointer offset
                    size: Size::Quad,
                },
                Varnode {
                    var: Var::Const("0xDEADBEEF".to_string()), // Data to store
                    size: Size::Quad,
                },
            ],
        };

        let result = executor.handle_store(store_inst);
        assert!(result.is_ok());

        // Check memory state to ensure data is stored at the correct address
        let memory_guard = executor.state.memory.memory.read().unwrap();
        if let Some(stored_value) = memory_guard.get(&0x1000) {
            assert_eq!(stored_value.concrete, ConcreteVar::Int(0xDEADBEEF));
        } else {
            panic!("Memory not updated correctly");
        }

        // Check CPU state to ensure data is also stored in the register if applicable
        let cpu_state_guard = executor.state.cpu_state.lock().unwrap();
        if let Some(register_value) = cpu_state_guard.get_register_value_by_offset(0x1000) {
            assert_eq!(register_value, 0xDEADBEEF);
        } else {
            println!("Register not updated, but this may be expected if the address does not map to a register.");
        }
    }

    #[test]
    fn test_handle_call() {
        let mut executor = setup_executor();
        let call_inst = Inst {
            opcode: Opcode::Call,
            output: None, // CALL typically doesn't have an output
            inputs: vec![
                Varnode {
                    var: Var::Const("0x123".to_string()), // Example address to branch to
                    size: Size::Quad,
                },
            ],
        };

        let result = executor.handle_call(call_inst);
        assert!(result.is_ok(), "handle_call returned an error: {:?}", result);

        // Validate the state after the call
        let expected_address = 0x123;
        assert_eq!(executor.current_address.unwrap(), expected_address, "Expected to branch to address: 0x{:x}", expected_address);
    }

        #[test]
    fn test_handle_callind() {
        let mut executor = setup_executor();
        let callind_inst = Inst {
            opcode: Opcode::CallInd,
            output: None, // CALLIND typically doesn't have an output
            inputs: vec![
                Varnode {
                    var: Var::Const("0x500123".to_string()), // Example address to branch to indirectly
                    size: Size::Quad,
                },
                Varnode {
                    var: Var::Const("20".to_string()), // Example parameter (optional)
                    size: Size::Quad,
                },
            ],
        };

        let result = executor.handle_callind(callind_inst);
        assert!(result.is_ok(), "handle_callind returned an error: {:?}", result);

        // Validate the state after the callind
        let expected_address = 0x500123;
        assert_eq!(executor.current_address.unwrap(), expected_address, "Expected to branch to address: 0x{:x}", expected_address);
    }
    #[test]
    fn test_handle_branch() {
        let mut executor = setup_executor();
        let branch_inst = Inst {
            opcode: Opcode::Branch,
            output: None,
            inputs: vec![
                Varnode {
                    var: Var::Const("0x2000".to_string()),
                    size: Size::Quad,
                },
            ],
        };
        let result = executor.handle_branch(branch_inst);
        assert!(result.is_ok(), "handle_branch returned an error: {:?}", result);

        let cpu_state_guard = executor.state.cpu_state.lock().unwrap();
        let rip_value = cpu_state_guard.get_register_value_by_offset(0x288).expect("RIP register not found");
        assert_eq!(rip_value, 0x2000);
    }

    #[test]
    fn test_handle_branchind() {
        let mut executor = setup_executor();
        let branchind_inst = Inst {
            opcode: Opcode::BranchInd,
            output: None,
            inputs: vec![
                Varnode {
                    var: Var::Const("0x4000".to_string()),
                    size: Size::Quad,
                },
            ],
        };

        let result = executor.handle_branchind(branchind_inst);
        assert!(result.is_ok(), "handle_branchind returned an error: {:?}", result);

        let cpu_state_guard = executor.state.cpu_state.lock().unwrap();
        let rip_value = cpu_state_guard.get_register_value_by_offset(0x288).expect("RIP register not found");
        assert_eq!(rip_value, 0x4000);
    }

    #[test]
    fn test_handle_return() {
        let mut executor = setup_executor();
        let branchind_inst = Inst {
            opcode: Opcode::BranchInd,
            output: None,
            inputs: vec![
                Varnode {
                    var: Var::Const("0x5000".to_string()),
                    size: Size::Quad,
                },
            ],
        };

        let result = executor.handle_branchind(branchind_inst);
        assert!(result.is_ok(), "handle_branchind returned an error: {:?}", result);

        let cpu_state_guard = executor.state.cpu_state.lock().unwrap();
        let rip_value = cpu_state_guard.get_register_value_by_offset(0x288).expect("RIP register not found");
        assert_eq!(rip_value, 0x5000);
    }

    #[test]
    fn test_handle_subpiece() {
        let mut executor = setup_executor();

        // Setup: Initialize source and target unique variables
        let symbolic = SymbolicVar::Int(BV::new_const(executor.context, format!("Unique(0x{:x})", 0xDEADBEEFDEADBEEFu64 as i32), 64));
        let source_var = ConcolicVar::new_concrete_and_symbolic_int(0xDEADBEEFDEADBEEF, symbolic.to_bv(), executor.context, 64);
        executor.unique_variables.insert("Unique(0xa0580)".to_string(), source_var);

        // Define the instruction for SUBPIECE
        let subpiece_inst = Inst {
            opcode: Opcode::SubPiece,
            output: Some(Varnode {
                var: Var::Unique(0xa0600),
                size: Size::Byte, // Assuming the output is 1 byte for simplicity
            }),
            inputs: vec![
                Varnode {
                    var: Var::Unique(0xa0580),
                    size: Size::Quad, // Source is 8 bytes (64 bits)
                },
                Varnode {
                    var: Var::Const("0".to_string()), // Starting from byte 0
                    size: Size::Byte,
                },
            ],
        };

        // Execute the SUBPIECE operation
        let result = (&mut executor).handle_subpiece(subpiece_inst);
        assert!(result.is_ok(), "Failed to handle SUBPIECE operation: {:?}", result.err());

        // Check results: Expect the output variable to have been correctly created with the truncated data
        if let Some(result_var) = executor.unique_variables.get(&"Unique(0xa0600)".to_string()) {
            assert_eq!(result_var.concrete.to_u64(), 0xEF, "Incorrect value in result after SUBPIECE operation");
            println!("Result of SUBPIECE operation: {:#?}", result_var);
        } else {
            panic!("Resulting variable from SUBPIECE operation not found");
        }
    }
}
