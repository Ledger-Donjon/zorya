/// Code to capture the state of CPU registers and memory regions just before starting
/// concolic execution of the program at a specified entry point.

use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use regex::Regex;
use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;

use crate::target_info::GLOBAL_TARGET_INFO;

use super::cpu_state::SharedCpuState;

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
    // thread::sleep(Duration::from_secs(1));
    Ok(qemu)
}

/// Function to cleanly close QEMU process.
fn close_qemu(qemu_process: &mut Child) -> Result<(), std::io::Error> {
    qemu_process.kill()?; // Send the kill signal to the QEMU process
    qemu_process.wait()?; // Wait for the process to exit completely
    println!("QEMU process has been closed cleanly.");
    Ok(())
}

/// Execute GDB locally to get the memory mapping (because 'info proc mappings' doesn't work with remote GDB and QEMU)
fn get_memory_mapping_with_local_gdb(binary_path: &str, commands: &[&str], output_file_path: &Path) -> Result<()> {
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

/// Execute GDB commands and write the output to a file
fn execute_gdb_commands_without_output(binary_path: &str, commands: &[&str]) -> Result<()> {
        
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
        anyhow::bail!("GDB command failed with stderr: {}", error_message);
    }

    Ok(())
}

pub fn get_mock(cpu_state: SharedCpuState) -> Result<()> {
    println!("Debug : Inside get_mock");
    
    let (binary_path, working_files_dir, main_program_addr) = {
        let info = GLOBAL_TARGET_INFO.lock().unwrap();
        (info.binary_path.clone(), info.working_files_dir.clone(), info.main_program_addr.clone())
    };

    // Create the target binary directory
    let binary_name = Path::new(&binary_path).file_stem().unwrap().to_str().unwrap();
    //let dumps_dir = working_files_dir.join(format!("{}_all-u-need", binary_name));
    //fs::create_dir_all(&dumps_dir).context("Failed to create memory dumps directory")?;

    let dumps_dir = {
            let info = GLOBAL_TARGET_INFO.lock().unwrap();
            info.memory_dumps.clone()
        };

    // Start the first time Qemu to get CPU registers
    //let mut qemu = start_qemu(&binary_path)?;

    //let cpu_output_path = dumps_dir.join("cpu_registers_output.txt");
    let cpu_output_path = dumps_dir.join("cpu_mapping.txt");    

    //let break_command = format!("break *{}", main_program_addr);
    //let capture_cpu_state_commands = vec![
    //    "target remote localhost:1234",
    //    &break_command,
    //    "continue",
    //    "info all-registers",
    //    "quit",
    //];

    //println!("Starting the remote execution on QEMU...");
    //execute_gdb_commands(&binary_path, &capture_cpu_state_commands, &cpu_output_path)?;

    let cpu_output = fs::read_to_string(&cpu_output_path)
        .context("Failed to read CPU registers output file")?;

    let result = parse_and_update_cpu_state_from_gdb_output(cpu_state.clone(), &cpu_output)
        .context("Failed to parse and update CPU state from GDB output");
    if let Err(e) = result {
        println!("Error during CPU state update: {}", e);
        return Err(e);
    } 

    // Ensure the QEMU process finishes cleanly
    //close_qemu(&mut qemu)?;

    // Get memory mappings from GDB locally (because gdb remote do not handle 'info proc mappings')
    //println!("Capturing memory mappings locally...");
    //let memory_output_path = dumps_dir.join("memory_mappings_output.txt");

    //let capture_memory_commands = vec![
    //    &break_command,
    //    "run",
    //    "info proc mappings",
    //    "quit",
    //];

    //get_memory_mapping_with_local_gdb(&binary_path, &capture_memory_commands, &memory_output_path)?;
    //let memory_output = fs::read_to_string(&memory_output_path)
    //    .context("Failed to read memory mappings output file")?;

    //let mappings = extract_memory_mappings(&memory_output)?;

    //println!("Memory mapping extracted correctly!");
 
    //create_and_execute_dump_commands(&mappings, &dumps_dir)?;
    
    // Dump memory from the binary in AMD Opteron
    // Below is the file with all the dumps commands to get the memory sections
    //let commands_file_path = dumps_dir.join("dump_commands.gdb");

    //println!("Preparing the dumping : commands to execute written to {:?}", commands_file_path);

    //automate_break_run_and_dump(&binary_path, &commands_file_path, &dumps_dir, &main_program_addr)?;

    //println!("Memory dump executed successfully!");

    // Ensure the QEMU process finishes cleanly
    //close_qemu(&mut qemu)?; 

    Ok(())
}

// Function to parse GDB output and update CPU state
fn parse_and_update_cpu_state_from_gdb_output(cpu_state: SharedCpuState, gdb_output: &str) -> Result<()> {
    let re = Regex::new(r"^\s*(\w+)\s+0x([\da-f]+)").unwrap();
    let mut cpu_state_guard = cpu_state.lock().unwrap();

    // Preparing to update register values based on their offsets found via names
    for line in gdb_output.lines() {
        if let Some(caps) = re.captures(line) {
            let register_name = caps[1].to_uppercase();  // Convert register name to uppercase
            let value_hex = u64::from_str_radix(&caps[2], 16)
                .map_err(|e| anyhow!("Failed to parse hex value for {}: {}", register_name, e))?;

            // Check for the offset and size in the register_map
            if let Some((offset, size)) = cpu_state_guard.register_map.iter()
                .find_map(|(key, (name, sz))| if name == &register_name { Some((*key, *sz)) } else { None }) {
                // Update the CPU register value using the offset
                if let Err(e) = cpu_state_guard.set_register_value_by_offset(offset, value_hex, size) {
                    println!("Failed to update CPU register {} (offset 0x{:x}): {}", register_name, offset, e);
                } else {
                    println!("Updated CPU register {} (offset 0x{:x}) to value 0x{:x}", register_name, offset, value_hex);
                }
            } else {
                println!("Register not found: {}", register_name);
            }
        }
    }

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
        "target remote localhost:1234",
        &break_command,
        "continue",
    ];

    // Iterate over each line from the dump commands file and execute them
    for line in dump_commands.lines() {

        // Restart QEMU each time (overwhise it disconnects)
        let mut qemu = start_qemu(&binary_path)?;

        writeln!(log_file, "Processing command : {}", line)?;
        println!("Processing command : {}", line);
        
        // Prepare the complete set of commands for this iteration
        let mut commands = dump_memory_commands.clone();           
        commands.push(line);

        // Execute GDB commands and write output to the temporary file
        match execute_gdb_commands_without_output(binary_path, &commands) {
            Ok(_) => {
                writeln!(log_file, "Command executed successfully: {}", line)?;
            },
            Err(e) => {
                writeln!(log_file, "Error executing command: {}. Error: {}", line, e)?;
                handle_memory_dump_error(line, dumps_dir)?;
            },
        }  
        println!("--> Writting finished for this section!\n");

        // Ensure the QEMU process finishes cleanly
        close_qemu(&mut qemu)?;

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

