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

    let (binary_path, working_files_dir, main_program_addr) = {
        let info = GLOBAL_TARGET_INFO.lock().unwrap();
        (info.binary_path.clone(), info.working_files_dir.clone(), info.main_program_addr.clone())
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
    create_and_execute_dump_commands(&mappings, &working_files_dir, binary_path_str, &main_program_addr)?;

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

fn create_and_execute_dump_commands(mappings: &[(String, String, String, String)], working_files_dir: &Path, binary_path: &str, main_program_addr: &str) -> Result<()> {
    // Ensure there are mappings to process
    if mappings.is_empty() {
        return Err(anyhow::anyhow!("No memory mappings available to create dump commands."));
    }

    // Extract the binary name from the binary path
    let binary_name = Path::new(binary_path).file_stem().unwrap().to_str().unwrap();
    let dumps_dir = working_files_dir.join(format!("{}_memory_dumps", binary_name));
    fs::create_dir_all(&dumps_dir).context("Failed to create memory dumps directory")?;

    let commands_file_path = dumps_dir.join("dump_commands.gdb");
    let mut commands_file = File::create(&commands_file_path)
        .context("Failed to create dump_commands.gdb file")?;

    for (start_addr, end_addr, _, _perms) in mappings.iter().filter(|(_, _, _, perms)| perms.starts_with('r')) {
        let dump_file_name = format!("{}-{}.bin", start_addr, end_addr);
        let dump_file_path = dumps_dir.join(&dump_file_name);
        writeln!(commands_file, "dump memory {} {} {}", dump_file_path.to_str().unwrap(), start_addr, end_addr)?;
    }

    commands_file.flush()?; // Ensure all commands are written to the file
    println!("dump_commands.gdb file created correctly in {:?}", dumps_dir);

    automate_break_run_and_dump(binary_path, &commands_file_path, &dumps_dir, main_program_addr)?;

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
fn automate_break_run_and_dump(binary_path: &str, dump_commands_path: &Path, working_files_dir: &Path, main_program_addr: &str) -> Result<()> {
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
            Err(e) => {
                writeln!(log_file, "Error executing command: {}. Error: {}", line, e)?;
                handle_memory_dump_error(line, working_files_dir)?;
            },
        }
    }

    Ok(())
}

fn handle_memory_dump_error(command_line: &str, working_files_dir: &Path) -> Result<()> {
    // Extract the memory range from the command line
    let re = Regex::new(r"(\w+)-(\w+)\.bin")?;
    if let Some(caps) = re.captures(command_line) {
        let start_addr = caps.get(1).unwrap().as_str();
        let end_addr = caps.get(2).unwrap().as_str();
        let file_name = format!("{}_{}_zeros.bin", start_addr, end_addr);
        let file_path = working_files_dir.join(&file_name);

        // Create or truncate the file and fill it with zeros
        let size = usize::from_str_radix(end_addr.trim_start_matches("0x"), 16)? - usize::from_str_radix(start_addr.trim_start_matches("0x"), 16)?;
        let data = vec![0u8; size];
        fs::write(&file_path, &data).context("Failed to write zeroed memory dump")?;

        println!("Created zero-filled dump file for failed range: {}", file_name);
    }

    Ok(())
}
