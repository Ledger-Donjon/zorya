// SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod tests {
    use parser::parser::{Inst, Opcode, Size, Var, Varnode};
    use std::collections::BTreeMap;
    use z3::{ast::BV, Config, Context, Optimize};
    use zorya::concolic::{ConcolicExecutor, ConcolicVar, ConcreteVar, Logger};
    use zorya::state::State;

    fn setup_executor() -> ConcolicExecutor<'static> {
        let cfg = Config::new();
        let ctx = Box::leak(Box::new(Context::new(&cfg)));
        let logger = Logger::new("execution_log.txt", false).expect("Failed to create logger");
        let trace_logger =
            Logger::new("trace_log.txt", true).expect("Failed to create trace logger");
        let state = State::default_for_tests(ctx, logger).expect("Failed to create state.");
        let current_lines_number = 0;
        ConcolicExecutor {
            context: ctx,
            solver: Optimize::new(ctx),
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
            constraint_vector: Vec::new(),
            overlay_state: None,
            null_check_cache: std::collections::HashMap::new(),
            start_time: std::time::Instant::now(),
            visited_blocks: std::collections::BTreeSet::new(),
        }
    }

    #[test]
    fn test_vbroadcastsd_basic() {
        let mut executor = setup_executor();

        // Create a source value: 0x123456789ABCDEF0 (64-bit)
        let source_concrete = 0x123456789ABCDEF0u64;
        let source_symbolic = BV::from_u64(executor.context, source_concrete, 64);
        let source_value = ConcolicVar::new_concrete_and_symbolic_int(
            source_concrete,
            source_symbolic,
            executor.context,
        );

        // Store source in a unique variable
        executor
            .unique_variables
            .insert("Unique(0x1000)".to_string(), source_value);

        // Create VBROADCASTSD instruction
        // VBROADCASTSD ymm1, xmm2 (broadcast 64-bit to 4x64-bit)
        let instruction = Inst {
            opcode: Opcode::CallOther,
            output: Some(Varnode {
                var: Var::Unique(0x2000),
                size: Size::QuadQuad, // 256-bit output
            }),
            inputs: vec![
                Varnode {
                    var: Var::Const("0x1e2".to_string()), // CALLOTHER index for vbroadcastsd_avx
                    size: Size::Word,
                },
                Varnode {
                    var: Var::Unique(0x2000), // Destination (not used for reading)
                    size: Size::QuadQuad,
                },
                Varnode {
                    var: Var::Unique(0x1000), // Source 64-bit value
                    size: Size::Quad,
                },
            ],
        };

        // Execute VBROADCASTSD
        let result = zorya::concolic::executor_callother::handle_vbroadcastsd_avx(
            &mut executor,
            instruction,
        );

        assert!(result.is_ok(), "VBROADCASTSD should execute successfully");

        // Check the result: should have 4 copies of the 64-bit value
        let result_var = executor.unique_variables.get("Unique(0x2000)").unwrap();

        match &result_var.concrete {
            ConcreteVar::LargeInt(chunks) => {
                assert_eq!(chunks.len(), 4, "Should have 4x64-bit chunks");
                assert_eq!(chunks[0], source_concrete, "Chunk 0 should match source");
                assert_eq!(chunks[1], source_concrete, "Chunk 1 should match source");
                assert_eq!(chunks[2], source_concrete, "Chunk 2 should match source");
                assert_eq!(chunks[3], source_concrete, "Chunk 3 should match source");
            }
            _ => panic!("Result should be LargeInt"),
        }
    }

    #[test]
    fn test_vpmullw_xmm_basic() {
        let mut executor = setup_executor();

        // Create two source values (128-bit = 8x16-bit words)
        // src1: [1, 2, 3, 4, 5, 6, 7, 8] (16-bit words)
        // src2: [2, 2, 2, 2, 2, 2, 2, 2] (16-bit words)
        // Expected result: [2, 4, 6, 8, 10, 12, 14, 16]

        let src1_low = 0x0004000300020001u64; // words 0-3: 1,2,3,4
        let src1_high = 0x0008000700060005u64; // words 4-7: 5,6,7,8
        let src2_low = 0x0002000200020002u64; // words 0-3: 2,2,2,2
        let src2_high = 0x0002000200020002u64; // words 4-7: 2,2,2,2

        let src1 = ConcolicVar::new_concrete_and_symbolic_large_int(
            vec![src1_low, src1_high],
            vec![
                BV::from_u64(executor.context, src1_low, 64),
                BV::from_u64(executor.context, src1_high, 64),
            ],
            executor.context,
        );

        let src2 = ConcolicVar::new_concrete_and_symbolic_large_int(
            vec![src2_low, src2_high],
            vec![
                BV::from_u64(executor.context, src2_low, 64),
                BV::from_u64(executor.context, src2_high, 64),
            ],
            executor.context,
        );

        executor
            .unique_variables
            .insert("Unique(0x1000)".to_string(), src1);
        executor
            .unique_variables
            .insert("Unique(0x1001)".to_string(), src2);

        // Create VPMULLW instruction
        let instruction = Inst {
            opcode: Opcode::CallOther,
            output: Some(Varnode {
                var: Var::Unique(0x2000),
                size: Size::DoubleQuad, // 128-bit output
            }),
            inputs: vec![
                Varnode {
                    var: Var::Const("0x1a1".to_string()), // CALLOTHER index for vpmullw_avx
                    size: Size::Word,
                },
                Varnode {
                    var: Var::Unique(0x1000), // Source 1
                    size: Size::DoubleQuad,
                },
                Varnode {
                    var: Var::Unique(0x1001), // Source 2
                    size: Size::DoubleQuad,
                },
            ],
        };

        // Execute VPMULLW
        let result =
            zorya::concolic::executor_callother::handle_vpmullw_avx(&mut executor, instruction);

        assert!(result.is_ok(), "VPMULLW should execute successfully");

        // Check the result
        let result_var = executor.unique_variables.get("Unique(0x2000)").unwrap();

        match &result_var.concrete {
            ConcreteVar::LargeInt(chunks) => {
                assert_eq!(chunks.len(), 2, "Should have 2x64-bit chunks for 128-bit");

                // Expected: [2, 4, 6, 8, 10, 12, 14, 16]
                // Low chunk: words 0-3: 2,4,6,8 = 0x0008000600040002
                // High chunk: words 4-7: 10,12,14,16 = 0x0010000e000c000a
                assert_eq!(
                    chunks[0], 0x0008000600040002,
                    "Low chunk: 2*1=2, 2*2=4, 2*3=6, 2*4=8"
                );
                assert_eq!(
                    chunks[1], 0x0010000e000c000a,
                    "High chunk: 2*5=10, 2*6=12, 2*7=14, 2*8=16"
                );
            }
            _ => panic!("Result should be LargeInt"),
        }
    }

    #[test]
    fn test_vpmullw_negative_numbers() {
        let mut executor = setup_executor();

        // Test with negative numbers (signed 16-bit)
        // src1: [-1, 2, -3, 4] as 16-bit signed = [0xFFFF, 0x0002, 0xFFFD, 0x0004]
        // src2: [2, -2, 2, -2]  as 16-bit signed = [0x0002, 0xFFFE, 0x0002, 0xFFFE]
        // Expected: [-2, -4, -6, -8] = [0xFFFE, 0xFFFC, 0xFFFA, 0xFFF8]

        let src1_chunk = 0x0004FFFD0002FFFFu64; // -1, 2, -3, 4
        let src2_chunk = 0xFFFE0002FFFE0002u64; // 2, -2, 2, -2

        let src1 = ConcolicVar::new_concrete_and_symbolic_int(
            src1_chunk,
            BV::from_u64(executor.context, src1_chunk, 64),
            executor.context,
        );

        let src2 = ConcolicVar::new_concrete_and_symbolic_int(
            src2_chunk,
            BV::from_u64(executor.context, src2_chunk, 64),
            executor.context,
        );

        executor
            .unique_variables
            .insert("Unique(0x1000)".to_string(), src1);
        executor
            .unique_variables
            .insert("Unique(0x1001)".to_string(), src2);

        let instruction = Inst {
            opcode: Opcode::CallOther,
            output: Some(Varnode {
                var: Var::Unique(0x2000),
                size: Size::Quad, // 64-bit output (4 words)
            }),
            inputs: vec![
                Varnode {
                    var: Var::Const("0x1a1".to_string()),
                    size: Size::Word,
                },
                Varnode {
                    var: Var::Unique(0x1000),
                    size: Size::Quad,
                },
                Varnode {
                    var: Var::Unique(0x1001),
                    size: Size::Quad,
                },
            ],
        };

        let result =
            zorya::concolic::executor_callother::handle_vpmullw_avx(&mut executor, instruction);

        assert!(result.is_ok(), "VPMULLW with signed numbers should work");

        let result_var = executor.unique_variables.get("Unique(0x2000)").unwrap();
        let result_val = result_var.concrete.to_u64();

        // -1*2=-2=0xFFFE, 2*-2=-4=0xFFFC, -3*2=-6=0xFFFA, 4*-2=-8=0xFFF8
        let expected = 0xFFF8FFFAFFFCFFFE;
        assert_eq!(
            result_val, expected,
            "Signed multiplication should produce correct results: got 0x{:016x}, expected 0x{:016x}",
            result_val, expected
        );
    }

    #[test]
    fn test_vpmullw_no_output() {
        let mut executor = setup_executor();

        // Test case where instruction has no output varnode
        let src_chunk = 0x0002000200020002u64;
        let src = ConcolicVar::new_concrete_and_symbolic_int(
            src_chunk,
            BV::from_u64(executor.context, src_chunk, 64),
            executor.context,
        );

        executor
            .unique_variables
            .insert("Unique(0x1000)".to_string(), src.clone());
        executor
            .unique_variables
            .insert("Unique(0x1001)".to_string(), src);

        let instruction = Inst {
            opcode: Opcode::CallOther,
            output: None, // No output varnode
            inputs: vec![
                Varnode {
                    var: Var::Const("0x1a1".to_string()),
                    size: Size::Word,
                },
                Varnode {
                    var: Var::Unique(0x1000),
                    size: Size::Quad,
                },
                Varnode {
                    var: Var::Unique(0x1001),
                    size: Size::Quad,
                },
            ],
        };

        let result =
            zorya::concolic::executor_callother::handle_vpmullw_avx(&mut executor, instruction);

        // Should succeed even without output varnode
        assert!(
            result.is_ok(),
            "VPMULLW without output should not fail: {:?}",
            result
        );
    }

    #[test]
    fn test_vbroadcastsd_zero() {
        let mut executor = setup_executor();

        // Test broadcasting zero
        let source_value = ConcolicVar::new_concrete_and_symbolic_int(
            0,
            BV::from_u64(executor.context, 0, 64),
            executor.context,
        );

        executor
            .unique_variables
            .insert("Unique(0x1000)".to_string(), source_value);

        let instruction = Inst {
            opcode: Opcode::CallOther,
            output: Some(Varnode {
                var: Var::Unique(0x2000),
                size: Size::QuadQuad,
            }),
            inputs: vec![
                Varnode {
                    var: Var::Const("0x1e2".to_string()),
                    size: Size::Word,
                },
                Varnode {
                    var: Var::Unique(0x2000),
                    size: Size::QuadQuad,
                },
                Varnode {
                    var: Var::Unique(0x1000),
                    size: Size::Quad,
                },
            ],
        };

        let result = zorya::concolic::executor_callother::handle_vbroadcastsd_avx(
            &mut executor,
            instruction,
        );

        assert!(result.is_ok(), "VBROADCASTSD with zero should work");

        let result_var = executor.unique_variables.get("Unique(0x2000)").unwrap();
        match &result_var.concrete {
            ConcreteVar::LargeInt(chunks) => {
                assert_eq!(chunks.len(), 4);
                assert!(chunks.iter().all(|&c| c == 0), "All chunks should be zero");
            }
            _ => panic!("Result should be LargeInt"),
        }
    }
}
