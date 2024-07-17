#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex, RwLock};
    use std::collections::BTreeMap;
    use nix::libc::{MAP_FIXED, SIG_SETMASK};
    use parser::parser::{Inst, Opcode, Size, Var, Varnode};
    use z3::{Config, Context, Solver};
    use zorya::concolic::executor_callother::{handle_callother, handle_syscall};
    use zorya::concolic::{ConcolicVar, Logger};
    use zorya::executor::{ConcolicExecutor, SymbolicVar};
    use zorya::state::memory_x86_64::{MemoryConcolicValue, MemoryError};
    use zorya::state::{CpuState, MemoryX86_64, State, VirtualFileSystem};

    // Setup a basic memory structure for tests
    fn setup_memory(ctx: &'static Context) -> MemoryX86_64<'static> {
        MemoryX86_64 {
            memory: Arc::new(RwLock::new(BTreeMap::new())),
            ctx,
            memory_size: 1024 * 1024 * 1024, // 1 GiB
        }
    }

    #[test]
    fn test_mmap_auto_address() {
        let config = Config::new();
        let context = Box::leak(Box::new(Context::new(&config)));
        let mut memory = setup_memory(context);

        // Test mmap with auto-assigned address
        let result = memory.mmap(0, 4096, 0, 0, -1, 0);
        assert!(result.is_ok());
        let addr = result.unwrap();
        assert!(addr >= 0x10000000 && addr < 0x7fffffffffff);
    }

    #[test]
    fn test_mmap_fixed_address() {
        let config = Config::new();
        let context = Box::leak(Box::new(Context::new(&config)));
        let mut memory = setup_memory(context);

        // Fixed address for mapping
        let fixed_address = 0x20000000;

        // Test mmap with fixed address
        let result = memory.mmap(fixed_address, 4096, 0, MAP_FIXED, -1, 0);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), fixed_address);

        // Verify that the address is indeed occupied
        let is_occupied = memory.memory.read().unwrap().contains_key(&fixed_address);
        assert!(is_occupied);
    }

    #[test]
    fn test_mmap_fixed_address_conflict() {
        let config = Config::new();
        let context = Box::leak(Box::new(Context::new(&config)));
        let mut memory = setup_memory(context);

        // Pre-occupy the address space
        let fixed_address = 0x30000000;
        memory.memory.write().unwrap().insert(fixed_address, MemoryConcolicValue::default(context, 64));

        // Attempt to map with MAP_FIXED where address is already occupied
        let result = memory.mmap(fixed_address, 4096, 0, MAP_FIXED, -1, 0);
        assert!(result.is_err());
        match result {
            Err(MemoryError::OutOfBounds(_, _)) => (),
            _ => panic!("Expected OutOfBounds error due to address conflict"),
        }
    }

    // Setup a basic executor structure for tests
    fn setup_executor() -> ConcolicExecutor<'static> {
        let cfg = Config::new();
        let ctx = Box::leak(Box::new(Context::new(&cfg)));
        let memory = MemoryX86_64::new(ctx, 1024 * 1024 * 1024).unwrap(); // 1 GiB
        let cpu_state = Arc::new(Mutex::new(CpuState::new(ctx)));

        ConcolicExecutor {
            context: ctx,
            solver: Solver::new(ctx),
            state: State::new(ctx, Logger::new("test_log.txt").unwrap()).unwrap(),
            current_address: Some(0x1000),
            instruction_counter: 0,
            unique_variables: BTreeMap::new(),
        }
    }

    #[test]
    fn test_sys_rt_sigprocmask() {
        let mut executor = setup_executor();
        let instruction = Inst {
            opcode: Opcode::CallOther,  // Opcode to invoke generic operations
            inputs: vec![
                Varnode {
                    var: Var::Const(String::from("0x5")), // Opcode number for syscall
                    size: Size::Word,
                },
            ],
            output: None,
        };

        // Prepare the RAX register with the syscall number for rt_sigprocmask
        {
            let mut cpu_guard = executor.state.cpu_state.lock().unwrap();
            cpu_guard.set_register_value_by_offset(0x0, ConcolicVar::new_concrete_and_symbolic_int(14, SymbolicVar::new_int(14, executor.context, 64).to_bv(executor.context), executor.context, 64), 64).unwrap();
        }

        // Execute the handle_callother function to process the syscall
        let result = handle_callother(&mut executor, instruction);
        assert!(result.is_ok(), "The syscall processing should succeed.");
    }
}
