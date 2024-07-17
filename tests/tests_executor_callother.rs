#[cfg(test)]
mod tests {
    use std::sync::{Arc, RwLock};
    use std::collections::BTreeMap;
    use nix::libc::MAP_FIXED;
    use z3::{Config, Context};
    use zorya::state::memory_x86_64::{MemoryConcolicValue, MemoryError};
    use zorya::state::MemoryX86_64;

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
}
