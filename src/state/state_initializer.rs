/// Code to capture the state of CPU registers and memory regions just before starting
/// concolic execution of the program at a specified entry point.

use std::fs;
use regex::Regex;
use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;

use crate::target_info::GLOBAL_TARGET_INFO;
use super::cpu_state::SharedCpuState;

pub fn initialize_cpu_registers(cpu_state: SharedCpuState) -> Result<()> {
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
    let re_general = Regex::new(r"^\s*(\w+)\s+0x([\da-f]+)").unwrap();
    let re_flags = Regex::new(r"^\s*eflags\s+0x[0-9a-f]+\s+\[(.*?)\]").unwrap();
    let mut cpu_state_guard = cpu_state.lock().unwrap();

    // Display current state of flag registrations for debugging
    println!("Flag Registrations:");
    for (offset, (name, size)) in cpu_state_guard.register_map.iter() {
        println!("{}: offset = 0x{:x}, size = {}", name, offset, size);
    }

    // Parse general registers
    for line in gdb_output.lines() {
        if let Some(caps) = re_general.captures(line) {
            let register_name = caps.get(1).unwrap().as_str().to_uppercase();
            let value_hex = u64::from_str_radix(caps.get(2).unwrap().as_str(), 16)
                .map_err(|e| anyhow!("Failed to parse hex value for {}: {}", register_name, e))?;

            if let Some((offset, size)) = cpu_state_guard.clone().register_map.iter().find(|&(_, (name, _))| *name == register_name).map(|(&k, (_, s))| (k, s)) {
                let _ = cpu_state_guard.set_register_value_by_offset(offset, value_hex, *size);
                println!("Updated register {} with value {}", register_name, value_hex);
            }
        }
    }

    // Special handling for flags within eflags output
    for line in gdb_output.lines() {
        if let Some(caps) = re_flags.captures(line) {
            let flags_line = caps.get(1).unwrap().as_str();
            println!("Parsed flags line: {}", flags_line);  // Debug statement

            let flag_list = ["CF", "PF", "ZF", "SF", "TF", "IF", "DF", "OF", "NT", "RF", "AC", "ID"];

            for &flag in flag_list.iter() {
                let flag_value = if flags_line.contains(flag) { 1 } else { 0 };
                if let Some((offset, size)) = cpu_state_guard.clone().register_map.iter().find(|&(_, (name, _))| *name == flag).map(|(&k, (_, s))| (k, s)) {
                    println!("Setting flag {} to {}", flag, flag_value);  // Debug statement
                    let _ = cpu_state_guard.set_register_value_by_offset(offset, flag_value, *size);
                    
                    // Verify update
                    let updated_value = cpu_state_guard.get_register_by_offset(offset, *size).map(|v| v.concrete.to_u64());
                    println!("Verification: {} is now set to {:?}", flag, updated_value);
                } else {
                    println!("Flag {} not found in register_map", flag);
                }
            }
        }
    }

    // Verify final state of specific flags
    for &flag in ["CF", "PF", "ZF", "SF", "TF", "IF", "DF", "OF", "NT", "RF", "AC", "ID"].iter() {
        if let Some((offset, size)) = cpu_state_guard.register_map.iter().find(|&(_, (name, _))| *name == flag).map(|(&k, (_, s))| (k, s)) {
            let flag_value = cpu_state_guard.get_register_by_offset(offset, *size).map(|v| v.concrete.to_u64()).unwrap_or(0);
            println!("{} flag value: {}", flag, flag_value);  // Debug statement
        }
    }

    Ok(())
}
