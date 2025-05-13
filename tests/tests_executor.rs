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
        let trace_logger = Logger::new("trace_log.txt").expect("Failed to create trace logger");
        let state = State::default_for_tests(ctx, logger).expect("Failed to create state.");
        let current_lines_number = 0;
        ConcolicExecutor {
            context: ctx,
            solver: Solver::new(ctx),
            state,
            symbol_table: BTreeMap::new(),
            current_address: Some(0x123),
            instruction_counter: 0,
            unique_variables: BTreeMap::new(),
            pcode_internal_lines_to_be_jumped: current_lines_number,
            initialiazed_var: BTreeMap::new(),
            inside_jump_table: false,
            trace_logger,
            function_symbolic_arguments: BTreeMap::new(),
        }
    }

    #[cfg(test)]
    mod tests {
        use z3::{Config, Context};
        use zorya::state::cpu_state::CpuConcolicValue;

        #[test]
        fn test_resize_register() {
            let cfg = Config::new();
            let context = Context::new(&cfg);
            let mut concolic_value = CpuConcolicValue::new(&context, 0xFFFF_FFFF_FFFF_FFFF, 64);

            // Simulate truncation to a 32-bit register (like EAX)
            concolic_value.resize(32, &context);
            assert_eq!(concolic_value.concrete.to_u64(), 0xFFFF_FFFF);
            assert_eq!(concolic_value.symbolic.to_bv(&context).get_size(), 32);

            // Simulate extension to a 128-bit register (like YMM registers)
            concolic_value.resize(128, &context);
            assert_eq!(concolic_value.symbolic.to_bv(&context).get_size(), 128);

            println!("Resize test passed successfully.");
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

        let result = executor.handle_cbranch(cbranch_inst, 0x124);
        assert!(result.is_ok());

        let cpu_state_guard = executor.state.cpu_state.lock().unwrap();
        let rip_value = cpu_state_guard.get_register_by_offset(0x288, 64).expect("RIP register not found");
        let rip_value_u64 = rip_value.get_concrete_value().expect("Failed to get concrete value");
        assert_eq!(rip_value_u64, 0x3000);
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
        let stored_value = executor.state.memory.read_u32(0x1000).expect("Failed to read memory value");
        assert_eq!(stored_value.concrete, ConcreteVar::Int(0xDEADBEEF));

        // Check CPU state to ensure data is also stored in the register if applicable
        let cpu_state_guard = executor.state.cpu_state.lock().unwrap();
        if let Some(register_value) = cpu_state_guard.get_register_by_offset(0x1000, 64) {
            let register_value_u64 = register_value.get_concrete_value().expect("Failed to get register value");
            assert_eq!(register_value_u64, 0xdeadbeef); 
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
        let rip_value = cpu_state_guard.get_register_by_offset(0x288, 64).expect("RIP register not found");
        let rip_value_u64 = rip_value.get_concrete_value().expect("Failed to get concrete value");
        assert_eq!(rip_value_u64, 0x2000);
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
        let rip_value = cpu_state_guard.get_register_by_offset(0x288, 64).expect("RIP register not found");
        let rip_value_u64 = rip_value.get_concrete_value().expect("Failed to get concrete value");
        assert_eq!(rip_value_u64, 0x4000);
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
        let rip_value = cpu_state_guard.get_register_by_offset(0x288, 64).expect("RIP register not found");
        let rip_value_u64 = rip_value.get_concrete_value().expect("Failed to get concrete value");
        assert_eq!(rip_value_u64, 0x5000);
    }

    #[test]
    fn test_handle_subpiece() {
        let mut executor = setup_executor();

        // Setup: Initialize source and target unique variables
        let symbolic = SymbolicVar::Int(BV::new_const(executor.context, format!("Unique(0x{:x})", 0xDEADBEEFDEADBEEFu64 as i32), 64));
        let source_var = ConcolicVar::new_concrete_and_symbolic_int(0xDEADBEEFDEADBEEF, symbolic.to_bv(&executor.context), executor.context, 64);
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

    #[test]
    fn test_variable_scope_management() {
        let mut executor = setup_executor();

        // Simulate entering a function via a call instruction
        let call_instruction = Inst {
            opcode: Opcode::Call,
            output: None,
            inputs: vec![
                Varnode {
                    var: Var::Const("0x1000".to_string()), // Assume function at address 0x1000
                    size: Size::Quad,
                },
            ],
        };

        // Handle the call instruction
        let result = executor.handle_call(call_instruction);
        assert!(result.is_ok(), "Function call should succeed.");

        // Now, within the function, perform a STORE operation to initialize a variable at address 0x2000
        let store_instruction = Inst {
            opcode: Opcode::Store,
            output: None,
            inputs: vec![
                Varnode {
                    var: Var::Const(0.to_string()), // Space ID, not used
                    size: Size::Byte,
                },
                Varnode {
                    var: Var::Const(0x2000.to_string()), // Address to store at
                    size: Size::Quad,
                },
                Varnode {
                    var: Var::Const(42.to_string()), // Data to store
                    size: Size::Byte,
                },
            ],
        };

        // Handle the STORE instruction
        let result = executor.handle_store(store_instruction);
        assert!(result.is_ok(), "Store operation should succeed.");

        // Check that the variable is initialized and accessible
        let addr_str = format!("{:x}", 0x2000);
        assert!(
            executor.initialiazed_var.contains_key(&addr_str),
            "Variable at address 0x2000 should be initialized."
        );

        // Now, simulate returning from the function
        let return_instruction = Inst {
            opcode: Opcode::Return,
            output: None,
            inputs: vec![],
        };

        // Handle the return instruction
        let result = executor.handle_return(return_instruction);
        assert!(result.is_ok(), "Function return should succeed.");

        // After the function returns, attempt to access the variable via a LOAD instruction
        let load_instruction = Inst {
            opcode: Opcode::Load,
            output: Some(Varnode {
                var: Var::Unique(0x3000), // Destination unique variable
                size: Size::Byte,
            }),
            inputs: vec![
                Varnode {
                    var: Var::Const(0.to_string()), // Space ID, not used
                    size: Size::Byte,
                },
                Varnode {
                    var: Var::Const(0x2000.to_string()), // Address to load from
                    size: Size::Quad,
                },
            ],
        };

        // Handle the LOAD instruction
        let instruction_map = BTreeMap::new();
        let result = executor.handle_load(load_instruction, &instruction_map);

        // Since the variable should have been cleaned up, we expect an error
        assert!(
            result.is_err(),
            "Load operation should fail due to uninitialized memory access."
        );

        // Optionally, you can check the error message
        if let Err(err_msg) = result {
            assert!(
                err_msg.contains("Uninitialized memory access"),
                "Error message should indicate uninitialized memory access."
            );
        }
    }
}
