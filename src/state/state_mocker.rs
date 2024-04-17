/// Code to capture the state of CPU registers and memory regions just before starting
/// concolic execution of the program at a specified entry point.

use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;
use anyhow::{Context, Result};
use regex::Regex;

use crate::state::cpu_state::GLOBAL_CPU_STATE;
use crate::target_info::GLOBAL_TARGET_INFO;

/// Start QEMU and ensure it is ready before returning the process handler
fn start_qemu(binary_path: &str) -> Result<std::process::Child> {
    let qemu_command = format!("qemu-x86_64-static --cpu Opteron_G1 -g 1234 {}", binary_path);
    println!("Starting QEMU with command: {}", qemu_command);
    let qemu = Command::new("sh")
        .arg("-c")
        .arg(&qemu_command)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .context("Failed to start QEMU")?;

    // Give QEMU some time to initialize
    thread::sleep(Duration::from_secs(5));
    Ok(qemu)
}

/// Execute GDB locally to get the memory mapping (because 'info proc mappings' doesn't work with remote GDB and QEMU)
fn execute_gdb_commands_locally(binary_path: &str, commands: &[&str], output_file_path: &Path) -> Result<()> {
    let output = Command::new("gdb")
        .arg("--batch")
        .arg(binary_path)
        .arg("-iex").arg("add-auto-load-safe-path /usr/local/go/src/runtime/runtime-gdb.py")
        .arg("-iex").arg("set disable-randomization on") // Disables ASLR
        .arg("-ex").arg("set pagination off")
        .args(commands.iter().flat_map(|cmd| ["-ex", cmd]))
        .output()
        .context("Failed to execute GDB commands")?;

    if !output.status.success() {
        let error_message = String::from_utf8_lossy(&output.stderr);
        println!("Error executing GDB locally: {}", error_message);
        if error_message.contains("No current process") {
            println!("Make sure your GDB commands include starting or attaching to a process.");
        }
        anyhow::bail!("Local GDB command failed with stderr: {}", error_message);
    }

    let mut gdb_output = String::from_utf8(output.stdout)?;

    // Check for "A debugging session is active." and stop writing to file
    if let Some(index) = gdb_output.find("A debugging session is active.") {
        gdb_output.truncate(index);
    }

    fs::write(output_file_path, &gdb_output).context("Failed to write GDB output to file")?;

    Ok(())
}

/// Execute GDB commands and write the output to a file
fn execute_gdb_commands(binary_path: &str, commands: &[&str], output_file_path: &Path) -> Result<()> {
    
    println!("Writing GDB output to {:?}", output_file_path);
    
    let output = Command::new("gdb-multiarch")
        .arg("--batch")
        .arg(binary_path)
        .arg("-iex").arg("add-auto-load-safe-path /usr/local/go/src/runtime/runtime-gdb.py")
        .arg("-iex").arg("set disable-randomization on") // Disables ASLR
        .arg("-ex").arg("set pagination off")
        .args(commands.iter().flat_map(|cmd| ["-ex", cmd]))
        .output()
        .context("Failed to execute GDB commands")?;

    if !output.status.success() {
        let error_message = String::from_utf8_lossy(&output.stderr);
        println!("Error executing GDB commands: {}", error_message);
        fs::write(output_file_path, &output.stderr).context("Failed to write GDB error output to file")?;
        anyhow::bail!("GDB command failed with stderr: {}", error_message);
    }

    fs::write(output_file_path, &output.stdout).context("Failed to write GDB output to file")?;

    Ok(())
}

pub fn get_mock() -> Result<()> {
    let (binary_path, working_files_dir, main_program_addr) = {
        let info = GLOBAL_TARGET_INFO.lock().unwrap();
        (info.binary_path.clone(), info.working_files_dir.clone(), info.main_program_addr.clone())
    };

    // Create the target binary directory
    let binary_name = Path::new(&binary_path).file_stem().unwrap().to_str().unwrap();
    let dumps_dir = working_files_dir.join(format!("{}_all-u-need", binary_name));
    fs::create_dir_all(&dumps_dir).context("Failed to create memory dumps directory")?;


    // Start the first time Qemu to get CPU registers
    let mut qemu = start_qemu(&binary_path)?;

    let cpu_output_path = dumps_dir.join("cpu_registers_output.txt");

    let break_command = format!("break *{}", main_program_addr);
    let capture_cpu_state_commands = vec![
        "target remote localhost:1234",
        &break_command,
        "continue",
        "info all-registers",
        "quit",
    ];

    println!("Starting the remote execution on QEMU...");
    execute_gdb_commands(&binary_path, &capture_cpu_state_commands, &cpu_output_path)?;

    let cpu_output = fs::read_to_string(&cpu_output_path)
        .context("Failed to read CPU registers output file")?;
    parse_and_update_cpu_state_from_gdb_output(&cpu_output)?;

    // Ensure the QEMU process finishes cleanly
    let _ = qemu.wait().context("Failed to cleanly shut down QEMU")?;

    // Get memory mappings from GDB locally (because gdb remote do not handle 'info proc mappings')
    println!("Capturing memory mappings locally...");
    let memory_output_path = dumps_dir.join("memory_mappings_output.txt");

    let capture_memory_commands = vec![
        &break_command,
        "run",
        "info proc mappings",
        "quit",
    ];

    execute_gdb_commands_locally(&binary_path, &capture_memory_commands, &memory_output_path)?;
    let memory_output = fs::read_to_string(&memory_output_path)
        .context("Failed to read memory mappings output file")?;

    let mappings = extract_memory_mappings(&memory_output)?;

    println!("Memory mapping extracted correctly!");
 
    create_and_execute_dump_commands(&mappings, &dumps_dir)?;
    
    // Dump memory from the binary in AMD Opteron
    // Below is the file with all the dumps commands to get the memory sections
    let commands_file_path = dumps_dir.join("dump_commands.gdb");

    println!("Preparing the dumping : commands to execute written to {:?}", commands_file_path);

    automate_break_run_and_dump(&binary_path, &commands_file_path, &dumps_dir, &main_program_addr)?;

    println!("Memory dump executed successfully!");

    // Ensure the QEMU process finishes cleanly
    let _ = qemu.wait().context("Failed to cleanly shut down QEMU")?;

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

    println!("{}", cpu_state);

    Ok(())
}

fn extract_memory_mappings(gdb_output: &str) -> Result<Vec<(String, String, String, String)>, regex::Error> {
    // Regex to capture address, size, offset, and permissions, being flexible on spaces
    let re = Regex::new(r"^\s*(0x[\da-f]+)\s+(0x[\da-f]+)\s+\S+\s+(0x[\da-f]+)\s+([r-][w-][x-][p-])\s*")?;
    let header = "Start Addr           End Addr       Size     Offset  Perms  objfile";
    let mut mappings = Vec::new();
    let mut start_parsing = false;

    for line in gdb_output.lines() {
        if line.trim() == header {
            start_parsing = true;
            continue;
        }

        if start_parsing && !line.trim().is_empty() {
            if let Some(caps) = re.captures(line) {
                let start_addr = caps[1].to_string();
                let end_addr = caps[2].to_string();
                let offset = caps[3].to_string();
                let perms = caps[4].to_string();
                if perms.starts_with('r') { // Only include mappings with read permissions
                    mappings.push((start_addr, end_addr, offset, perms));
                }
            } else {
                println!("Skipped line, did not match expected format: {}", line);
            }
        }
    }

    if mappings.is_empty() && start_parsing {
        println!("No valid memory mappings were extracted after the header. Please check the GDB output format.");
    } else if !start_parsing {
        println!("Header not found. Did not start parsing memory mappings.");
    }

    Ok(mappings)
}

fn create_and_execute_dump_commands(mappings: &[(String, String, String, String)], dumps_dir: &Path) -> Result<()> {
    if mappings.is_empty() {
        return Err(anyhow::anyhow!("No memory mappings available to create dump commands."));
    }

    let commands_file_path = dumps_dir.join("dump_commands.gdb");
    let mut commands_file = File::create(&commands_file_path)
        .context("Failed to create dump_commands.gdb file")?;

    for (start_addr, end_addr, _, _) in mappings.iter() {
        let dump_file_name = format!("{}-{}.bin", start_addr, end_addr);
        let dump_file_path = dumps_dir.join(&dump_file_name);
        writeln!(commands_file, "dump memory {} {} {}", dump_file_path.to_str().unwrap(), start_addr, end_addr)?;
    }

    commands_file.flush()?;
    println!("dump_commands.gdb file created correctly in {:?}", dumps_dir);

    Ok(())
}

fn automate_break_run_and_dump(binary_path: &str, dump_commands_path: &Path, dumps_dir: &Path, main_program_addr: &str) -> Result<()> {
    let log_path = dumps_dir.join("automate_break_run_and_dump.log");
    let mut log_file = File::create(&log_path)?;

    writeln!(log_file, "Starting automate_break_run_and_dump")?;

    let dump_commands = fs::read_to_string(dump_commands_path)
        .context("Failed to read dump_commands.gdb file")?;

    let break_command = format!("break *{}", main_program_addr);
    let dump_memory_commands = vec![
        &break_command,
        "run",
        "info proc mappings",
        "quit",
    ];

    // Restart QEMU each time (overwhise it disconnects)
    let mut _qemu = start_qemu(&binary_path)?;

    // Iterate over each line from the dump commands file and execute them
    for line in dump_commands.lines() {
        if let Some((start_addr, end_addr)) = parse_addresses_from_line(line) {
            let output_file_name = format!("dump_{}-{}.bin", start_addr, end_addr);
            let output_file_path = dumps_dir.join(output_file_name);

            writeln!(log_file, "Processing line: {}", line)?;
            writeln!(log_file, "Writing GDB output to {:?}", output_file_path)?;

            // Prepare the complete set of commands for this iteration
            let mut commands = dump_memory_commands.clone();           
            commands.push(line);

            // Execute GDB commands and write output to the temporary file
            match execute_gdb_commands(binary_path, &commands, &output_file_path) {
                Ok(_) => {
                    writeln!(log_file, "Command executed successfully: {}", line)?;
                },
                Err(e) => {
                    writeln!(log_file, "Error executing command: {}. Error: {}", line, e)?;
                    handle_memory_dump_error(line, dumps_dir)?;
                },
            }
        } else {
            writeln!(log_file, "Failed to parse addresses from line: {}", line)?;
        }
        println!("--> Writting finished for this section!")
    }

    // Ensure the QEMU process finishes cleanly
    // let _ = qemu.wait().context("Failed to cleanly shut down QEMU")?;

    Ok(())
}

/// Function to parse start and end addresses in hexadecimal form from a dump command line
fn parse_addresses_from_line(line: &str) -> Option<(String, String)> {
    let re = Regex::new(r"0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)").unwrap();
    re.captures(line).map(|caps| {
        let start_addr = format!("0x{}", caps[1].to_string());
        let end_addr = format!("0x{}", caps[2].to_string());
        (start_addr, end_addr)
    })
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
