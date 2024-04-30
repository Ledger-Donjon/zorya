/// Code to capture the state of CPU registers and memory regions just before starting
/// concolic execution of the program at a specified entry point.

use std::fs;
use anyhow::{Context, Result};
use regex::Regex;
use anyhow::anyhow;

use crate::target_info::GLOBAL_TARGET_INFO;

use super::cpu_state::SharedCpuState;

pub fn get_mock(cpu_state: SharedCpuState) -> Result<()> {
    println!("Debug : Inside get_mock");
    
    let dumps_dir = {
        let info = GLOBAL_TARGET_INFO.lock().unwrap();
        info.memory_dumps.clone()
    };

    let cpu_output_path = dumps_dir.join("cpu_mapping.txt");

    let cpu_output = fs::read_to_string(&cpu_output_path)
        .context("Failed to read CPU registers output file")?;
    
    let result = parse_and_update_cpu_state_from_gdb_output(cpu_state.clone(), &cpu_output)
        .context("Failed to parse and update CPU state from GDB output");
    if let Err(e) = result {
        println!("Error during CPU state update: {}", e);
        return Err(e);
    } 

    Ok(())
}

// Function to parse GDB output and update CPU state
fn parse_and_update_cpu_state_from_gdb_output(cpu_state: SharedCpuState, gdb_output: &str) -> Result<()> {
    let re = Regex::new(r"^\s*(\w+)\s+0x([\da-f]+)").unwrap();

    // Lock the cpu_state once and reuse throughout this scope
    let mut cpu_state = cpu_state.lock().unwrap();

    for line in gdb_output.lines() {
        if let Some(caps) = re.captures(line) {
            let register_name = &caps[1];
            let value_hex = u64::from_str_radix(&caps[2], 16)
                .map_err(|e| anyhow!("Failed to parse hex value for {}: {}", register_name, e))?;
            
            // Check if the register exists
            if cpu_state.registers.contains_key(register_name) {
                // Update the CPU register value
                match cpu_state.set_register_value(register_name, value_hex) {
                    Ok(()) => {
                        println!("Updated CPU register {}: {}", register_name, value_hex);
                    }
                    Err(e) => {
                        println!("Failed to update CPU register {}: {}", register_name, e);
                        // Optionally, you can choose to return an error here if necessary
                    }
                }
            } else {
                println!("Register not found: {}", register_name);  // Error handling
                // Optionally, you can choose to return an error here if necessary
            }
        }
    }

    Ok(())
}

