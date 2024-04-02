/// Code to capture the state of CPU registers and memory regions just before starting
/// concolic execution of the program at a specified entry point.

use crate::state::cpu_state::GLOBAL_CPU_STATE;
use anyhow::{Context, Result};
use regex::Regex;
use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output},
};

const MAIN_PROGRAM_ADDR: &str = "0x4585c0";

// Execute GDB commands and return the output
fn execute_gdb_commands(binary_path: &str, commands: Vec<&str>) -> Result<Output> {
    let output = Command::new("gdb")
        .arg("--batch")
        .arg(binary_path)
        .arg("-iex")
        .arg("set disable-randomization on") // Disables ASLR
        .args(["-iex", "set auto-load safe-path /usr/local/go/src/runtime/runtime-gdb.py:/usr/local/go/src/runtime"])
        .args(commands.into_iter().flat_map(|cmd| ["-ex", cmd]))
        .output()
        .context("Failed to execute GDB command")?;

    if !output.status.success() {
        anyhow::bail!(
            "GDB command failed with stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(output)
}

pub fn get_mock() -> Result<()> {
    let binary_path = "/home/kgorna/Documents/tools/pcode-generator/tests/additiongo/additiongo";
    let working_files_dir = PathBuf::from("/home/kgorna/Documents/zorya/src/state/working_files");

    // Break and run to capture CPU state
    let break_command = format!("break *{}", MAIN_PROGRAM_ADDR);
    let capture_cpu_state_commands = vec![
        break_command.as_str(),
        "run",
        "info all-registers",
    ];

    let gdb_output_cpu = execute_gdb_commands(binary_path, capture_cpu_state_commands)?;
    let output_str_cpu = String::from_utf8_lossy(&gdb_output_cpu.stdout);

    println!("{:?}", output_str_cpu);
    println!("********************************");

    // Parse and update CPU state here
    parse_and_update_cpu_state_from_gdb_output(&output_str_cpu)?;
    
    let cpu_state = GLOBAL_CPU_STATE.lock().unwrap();
    println!("{}", cpu_state);

    // After CPU state is captured and updated, proceed to get memory mappings
    let memory_mapping_commands = vec![
        break_command.as_str(),
        "run",
        "info proc mappings",
    ];

    let gdb_output_memory = execute_gdb_commands(binary_path, memory_mapping_commands)?;
    let output_str_memory = String::from_utf8_lossy(&gdb_output_memory.stdout);

    println!("{:?}", output_str_memory);
    println!("********************************");

    let mappings = extract_memory_mappings(&output_str_memory)?;

    // Execute memory dump commands after CPU state has been captured
    create_and_execute_dump_commands(&mappings, &working_files_dir, binary_path)?;

    Ok(())
}

fn extract_memory_mappings(gdb_output: &str) -> Result<Vec<(String, String, String, String)>> {
    let re = Regex::new(r"^\s*(0x[\da-f]+)\s+(0x[\da-f]+)\s+\S+\s+(0x[\da-f]+)\s+([r-][w-][x-][p-])\s")?;
    let mut mappings = Vec::new();

    for line in gdb_output.lines() {
        if let Some(caps) = re.captures(line) {
            let start_addr = caps[1].to_string();
            let end_addr = caps[2].to_string();
            let offset = caps[3].to_string();
            let perms = caps[4].to_string();
            if perms.starts_with('r') { // Only include mappings with read permissions
                mappings.push((start_addr, end_addr, offset, perms));
            }
        }
    }

    Ok(mappings)
}

fn create_and_execute_dump_commands(mappings: &[(String, String, String, String)], working_files_dir: &Path, binary_path: &str) -> Result<()> {
    // Ensure there are mappings to process
    if mappings.is_empty() {
        return Err(anyhow::anyhow!("No memory mappings available to create dump commands."));
    }

    let commands_file_path = working_files_dir.join("dump_commands.gdb");
    let mut commands_file = File::create(&commands_file_path)
        .context("Failed to create dump_commands.gdb file")?;

    for (start_addr, end_addr, _, _perms) in mappings.iter().filter(|(_, _, _, perms)| perms.starts_with('r')) {
        let dump_file_name = format!("{}-{}.bin", start_addr, end_addr);
        let dump_file_path = working_files_dir.join(&dump_file_name);
        writeln!(commands_file, "dump memory {} {} {}", dump_file_path.to_str().unwrap(), start_addr, end_addr)?;
    }

    commands_file.flush()?; // Ensure all commands are written to the file
    println!("dump_commands.gdb file created correctly.");

    let dump_commands_path = working_files_dir.join("dump_commands.gdb");
    automate_break_run_and_dump(binary_path, &dump_commands_path, &working_files_dir)?;

    println!("Memory dump executed successfully. Commands written to {:?}", commands_file_path);
    Ok(())
}

fn parse_and_update_cpu_state_from_gdb_output(gdb_output: &str) -> Result<()> {
    let re = Regex::new(r"^\s*(\w+)\s+0x([\da-f]+)")?;
    let mut cpu_state = GLOBAL_CPU_STATE.lock().map_err(|_| anyhow::anyhow!("Failed to lock GLOBAL_CPU_STATE"))?;

    for line in gdb_output.lines() {
        if let Some(caps) = re.captures(line) {
            let register_name = &caps[1];
            let value_hex = format!("0x{}", &caps[2]); // Keep the value in hex format
            cpu_state.set_register_value_by_name(register_name, value_hex);
        }
    }

    Ok(())
}

// Automate the break, run, and dump sequence
fn automate_break_run_and_dump(binary_path: &str, dump_commands_path: &Path, working_files_dir: &Path) -> Result<()> {
    let log_path = working_files_dir.join("automate_break_run_and_dump.log");
    let mut log_file = File::create(&log_path)?;

    writeln!(log_file, "Starting automate_break_run_and_dump")?;

    let dump_commands = fs::read_to_string(dump_commands_path)
        .context("Failed to read dump_commands.gdb file")?;

    // Breakpoint and run command setup
    let break_command = format!("break *{}", MAIN_PROGRAM_ADDR);
    let run_command = "run";
    let initial_commands = vec![break_command.as_str(), run_command];

    for line in dump_commands.lines() {
        writeln!(log_file, "Processing line: {}", line)?;

        // Combine initial commands with the current dump command
        let mut commands = initial_commands.clone();
        commands.push(line);

        // Execute GDB commands
        match execute_gdb_commands(binary_path, commands) {
            Ok(_) => writeln!(log_file, "Command executed successfully: {}", line)?,
            Err(e) => writeln!(log_file, "Error executing command: {}. Error: {}", line, e)?,
        }
    }

    Ok(())
}