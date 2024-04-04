/// Code to capture the state of CPU registers and memory regions just before starting
/// concolic execution of the program at a specified entry point.

use crate::state::cpu_state::GLOBAL_CPU_STATE;
use crate::target_info::GLOBAL_TARGET_INFO;

use anyhow::{Context, Result};
use regex::Regex;
use std::{
    fs::{self, File},
    io::Write,
    path::Path,
    process::{Command, Output},
};

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

    let (binary_path, working_files_dir, main_program_addr, dump_kernel_pages) = {
        let info = GLOBAL_TARGET_INFO.lock().unwrap();
        (info.binary_path.clone(), info.working_files_dir.clone(), info.main_program_addr.clone(), info.dump_kernel_pages.clone())
    };

    // Convert PathBuf to a string slice
    let binary_path_str = binary_path.as_str();

    // Break and run to capture CPU state
    let break_command = format!("break *{}", main_program_addr);
    let capture_cpu_state_commands = vec![
        break_command.as_str(),
        "run",
        "info all-registers",
    ];

    let gdb_output_cpu = execute_gdb_commands(binary_path_str, capture_cpu_state_commands)?;
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

    let gdb_output_memory = execute_gdb_commands(binary_path_str, memory_mapping_commands)?;
    let output_str_memory = String::from_utf8_lossy(&gdb_output_memory.stdout);

    println!("{:?}", output_str_memory);
    println!("********************************");

    let mappings = extract_memory_mappings(&output_str_memory)?;

    // Execute memory dump commands after CPU state has been captured
    create_and_execute_dump_commands(&mappings, &working_files_dir, binary_path_str, &main_program_addr, &dump_kernel_pages)?;

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

fn create_and_execute_dump_commands(mappings: &[(String, String, String, String)], working_files_dir: &Path, binary_path: &str, main_program_addr: &str, dump_kernel_pages: &Path) -> Result<()> {
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
    automate_break_run_and_dump(binary_path, &dump_commands_path, &working_files_dir, main_program_addr, dump_kernel_pages)?;

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
fn automate_break_run_and_dump(binary_path: &str, dump_commands_path: &Path, working_files_dir: &Path, main_program_addr: &str, dump_kernel_pages: &Path) -> Result<()> {
    
    let log_path = working_files_dir.join("automate_break_run_and_dump.log");
    let mut log_file = File::create(&log_path)?;

    writeln!(log_file, "Starting automate_break_run_and_dump")?;

    let dump_commands = fs::read_to_string(dump_commands_path)
        .context("Failed to read dump_commands.gdb file")?;

    // Breakpoint and run command setup
    let break_command = format!("break *{}", main_program_addr);
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

    // Path to the log file where errors are logged
    let log_path = working_files_dir.join("automate_break_run_and_dump.log");

    // Call the function to check for [vvar] errors and handle them if found
    check_for_vvar_error_and_handle(&log_path, binary_path, dump_kernel_pages.to_str().unwrap(), main_program_addr, working_files_dir)?;

    Ok(())
}

fn check_for_vvar_error_and_handle(log_path: &Path, binary_path: &str, dump_kernel_pages_script_path: &str, main_program_addr: &str, working_files_dir: &Path) -> Result<()> {
    let log_content = std::fs::read_to_string(log_path)
        .context("Failed to read log file")?;

    // Regex to match the memory address range from the log file
    let re = Regex::new(r"Cannot access memory at address (0x[0-9a-fA-F]+)")?;

    if let Some(caps) = re.captures(&log_content) {
        let address = caps.get(1).map_or("", |m| m.as_str());
        let error_address_range = format!("{}-error", address); // Customize this as needed

        // Path for the output file, incorporating the working_files_dir and error address range
        let output_file_path = working_files_dir.join(format!("kernel-vvar-{}.out", error_address_range));

        // Since `format!` returns a `String`, we temporarily store it to keep the borrowed reference valid
        let break_command = format!("break *{}", main_program_addr);
        let source_command = format!("source {}", dump_kernel_pages_script_path);
        let set_output_file_command = format!("set logging file {}", output_file_path.to_str().unwrap());
        let enable_logging_command = "set logging on";
        let disable_logging_command = "set logging off";

        // Collect commands as string slices, borrowing from owned strings where necessary
        let gdb_commands_to_handle_vvar = vec![
            break_command.as_str(),
            "run",
            enable_logging_command,
            set_output_file_command.as_str(),
            source_command.as_str(),
            disable_logging_command,
        ];

        execute_gdb_commands(binary_path, gdb_commands_to_handle_vvar)?;
        println!("Handled [vvar] section error by dumping kernel pages to {:?}", output_file_path);
    } else {
        println!("No [vvar] section error found in the log file.");
    }

    Ok(())
}

