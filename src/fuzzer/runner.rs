// SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

use super::config::{FuzzerConfig, TestConfig};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Result of a single test execution
#[derive(Debug, Clone)]
pub struct TestResult {
    pub test_id: String,
    pub success: bool,
    pub duration: Duration,
    pub timeout: bool,
    pub error_message: Option<String>,
    pub output_dir: PathBuf,
    pub found_sat_states: bool,
}

/// Fuzzer runner that executes all test configurations
pub struct FuzzerRunner {
    config: FuzzerConfig,
    results_base_dir: PathBuf,
    zorya_dir: PathBuf,
}

impl FuzzerRunner {
    /// Create a new fuzzer runner
    pub fn new(config: FuzzerConfig) -> Result<Self, Box<dyn std::error::Error>> {
        // Get ZORYA_DIR from environment
        let zorya_dir = env::var("ZORYA_DIR")
            .map(PathBuf::from)
            .or_else(|_| env::current_dir())?;

        // Create base results directory
        let results_base_dir = PathBuf::from("fuzzer_results");
        fs::create_dir_all(&results_base_dir)?;

        Ok(Self {
            config,
            results_base_dir,
            zorya_dir,
        })
    }

    /// Generate P-code for the binary
    fn generate_pcode(&self) -> Result<(), Box<dyn std::error::Error>> {
        let pcode_generator_dir = self.zorya_dir.join("external/pcode-generator");

        println!(
            "Running P-code generator for: {}",
            self.config.global.binary_path
        );
        println!();

        // Pin cargo's target dir to a workspace path so the produced
        // pcode_generator binary lives at <pcode_generator_dir>/target/release/.
        // pcode_generator computes its output dir via current_exe().parent()^3,
        // so this guarantees results land in <pcode_generator_dir>/results/
        // regardless of any CARGO_TARGET_DIR injected by the surrounding env
        let cargo_target_dir = pcode_generator_dir.join("target");

        let mut cmd = Command::new("cargo");
        cmd.current_dir(&pcode_generator_dir)
            .arg("run")
            .arg("--release")
            .arg(&self.config.global.binary_path)
            .arg("--low-pcode")
            .env("RUSTFLAGS", "--cap-lints=allow")
            .env("CARGO_TARGET_DIR", &cargo_target_dir)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());

        let status = cmd.status()?;

        if !status.success() {
            return Err("P-code generation failed".into());
        }

        // Verify the pcode file was created
        let binary_name = Path::new(&self.config.global.binary_path)
            .file_name()
            .ok_or("Invalid binary path")?
            .to_string_lossy();

        let pcode_file = pcode_generator_dir
            .join("results")
            .join(format!("{}_low_pcode.txt", binary_name));

        if !pcode_file.exists() {
            return Err("P-code file was not created".into());
        }

        println!();
        println!("P-code generated successfully: {}", pcode_file.display());
        println!();
        Ok(())
    }

    /// Precompute static analysis (panic xrefs and reverse BFS) - done once for all tests
    fn precompute_static_analysis(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Running panic cross-reference analysis...");

        // Run find_panic_xrefs.py
        let xref_script = self.zorya_dir.join("scripts/find_panic_xrefs.py");
        let mut cmd = Command::new("python3");
        cmd.arg(&xref_script)
            .arg(&self.config.global.binary_path)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());

        let status = cmd.status()?;
        if !status.success() {
            eprintln!("Warning: Panic cross-reference analysis failed (non-critical)");
        }

        println!();
        println!("Running reverse panic reachability precomputation...");

        // Run precompute_panic_reach.py
        let panic_reach_script = self.zorya_dir.join("scripts/precompute_panic_reach.py");
        let mut cmd = Command::new("python3");
        cmd.arg(&panic_reach_script)
            .arg(&self.config.global.binary_path)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());

        let status = cmd.status()?;
        if !status.success() {
            eprintln!("Warning: Panic reachability precomputation failed (non-critical)");
        }

        println!();
        println!("Static analysis complete!");
        Ok(())
    }

    /// Generate memory and CPU register dumps for a specific test
    fn generate_dumps(
        &self,
        start_address: &str,
        args: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let dump_script = self.zorya_dir.join("scripts/dump_memory.sh");

        // Get entry point (we'll use readelf like the zorya script does)
        let entry_point = self.get_entry_point()?;

        let mut cmd = Command::new(&dump_script);
        cmd.arg(&self.config.global.binary_path)
            .arg(start_address)
            .arg(&entry_point)
            .arg(args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());

        let status = cmd.status()?;
        if !status.success() {
            return Err("Failed to generate dumps".into());
        }

        Ok(())
    }

    /// Extract and generate VDSO p-code once (same for all tests)
    fn generate_vdso_once(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Use a dummy address for VDSO extraction (it doesn't depend on start address)
        let dummy_addr = "0x0";
        let dummy_args = "none";

        // Run extract_vdso.sh
        let extract_script = self.zorya_dir.join("scripts/extract_vdso.sh");
        let mut cmd = Command::new(&extract_script);
        cmd.arg(&self.config.global.binary_path)
            .arg(dummy_addr)
            .arg(dummy_args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());

        let status = cmd.status()?;
        if !status.success() {
            eprintln!(
                "Warning: VDSO extraction failed (non-critical), continuing without VDSO support"
            );
            return Ok(());
        }

        // Check if VDSO files were created
        let vdso_dir = self.zorya_dir.join("results/initialization_data/vdso");
        let vdso_file = vdso_dir.join("vdso.so");
        let vdso_base_file = vdso_dir.join("vdso_base_addr.txt");

        if vdso_file.exists() && vdso_base_file.exists() {
            // Generate VDSO p-code
            let vdso_base = fs::read_to_string(&vdso_base_file)?.trim().to_string();
            let generate_script = self.zorya_dir.join("scripts/generate_vdso_pcode.sh");

            let mut cmd = Command::new(&generate_script);
            cmd.arg(&vdso_file)
                .arg(&vdso_base)
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit());

            let status = cmd.status()?;
            if !status.success() {
                eprintln!("Warning: VDSO p-code generation failed (non-critical)");
            }

            println!("VDSO p-code generated successfully");
        }

        Ok(())
    }

    /// Generate jump tables once (same for all tests)
    fn generate_jump_tables(&self) -> Result<(), Box<dyn std::error::Error>> {
        let jump_tables_script = self.zorya_dir.join("scripts/get_jump_tables.py");

        let mut cmd = Command::new("python3");
        cmd.arg(&jump_tables_script)
            .arg(&self.config.global.binary_path)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());

        let status = cmd.status()?;
        if !status.success() {
            eprintln!("Warning: Jump table generation failed (non-critical)");
        } else {
            println!("Jump tables generated successfully");
        }

        Ok(())
    }

    /// Get the entry point of the binary using readelf
    fn get_entry_point(&self) -> Result<String, Box<dyn std::error::Error>> {
        let output = Command::new("readelf")
            .arg("-h")
            .arg(&self.config.global.binary_path)
            .output()?;

        if !output.status.success() {
            return Err("Failed to run readelf".into());
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        for line in output_str.lines() {
            if line.contains("Entry point address:") {
                if let Some(addr) = line.split_whitespace().last() {
                    return Ok(addr.to_string());
                }
            }
        }

        Err("Could not find entry point".into())
    }

    /// Run all test configurations
    pub fn run_all(&self) -> Result<Vec<TestResult>, Box<dyn std::error::Error>> {
        let mut results = Vec::new();

        println!("================================================================");
        println!("           ZORYA FUZZER - Starting Test Campaign               ");
        println!("================================================================");
        println!();

        // Step 1: Generate pcode for the binary once before all tests
        println!("[STEP 1/4] Generating P-code for binary (done once)...");
        self.generate_pcode()?;
        println!();

        // Step 2: Generate cross-references and panic reachability (done once)
        println!("[STEP 2/4] Precomputing panic cross-references and reachability (done once)...");
        self.precompute_static_analysis()?;
        println!();

        // Step 3: Extract VDSO (done once - same for all tests)
        println!("[STEP 3/4] Extracting VDSO (done once)...");
        self.generate_vdso_once()?;
        println!();

        // Step 4: Generate jump tables (done once - same for all tests)
        println!("[STEP 4/4] Generating jump tables (done once)...");
        self.generate_jump_tables()?;
        println!();

        println!("================================================================");
        println!("Configuration:");
        println!("  Language: {}", self.config.global.language);
        println!("  Compiler: {}", self.config.global.compiler);
        println!("  Binary: {}", self.config.global.binary_path);
        println!("  Total tests: {}", self.config.tests.len());
        println!("================================================================");
        println!();

        for (idx, test) in self.config.tests.iter().enumerate() {
            println!("────────────────────────────────────────────────────────────────");
            println!(
                "Running test {}/{}: {}",
                idx + 1,
                self.config.tests.len(),
                test.id
            );
            println!("  Mode: {}", test.mode);
            println!("  Start address: {}", test.start_address);
            println!("  Arguments: {}", test.args);
            println!("  Timeout: {}s", test.timeout_seconds);
            println!();

            let result = self.run_single_test(test)?;

            // Print result summary
            if result.success {
                println!("[SUCCESS] Test '{}' completed successfully", result.test_id);
            } else if result.timeout {
                println!("[TIMEOUT] Test '{}' timed out", result.test_id);
            } else {
                println!(
                    "[FAILED] Test '{}' failed: {:?}",
                    result.test_id, result.error_message
                );
            }

            if result.found_sat_states {
                println!("[SAT] Found SAT states in test '{}'", result.test_id);
            }

            println!("  Duration: {:.2}s", result.duration.as_secs_f64());
            println!("  Output directory: {}", result.output_dir.display());
            println!();

            results.push(result);
        }

        self.print_summary(&results);

        Ok(results)
    }

    /// Run a single test configuration
    fn run_single_test(&self, test: &TestConfig) -> Result<TestResult, Box<dyn std::error::Error>> {
        let start_time = Instant::now();

        // Create output directory for this test
        let output_dir = self.results_base_dir.join(&test.id);
        fs::create_dir_all(&output_dir)?;

        // Prepare environment variables (zorya reads config from env vars, not args)
        let mut env_vars = HashMap::new();
        env_vars.insert("MODE".to_string(), test.mode.clone());
        env_vars.insert("ARGS".to_string(), test.args.clone());
        env_vars.insert(
            "SOURCE_LANG".to_string(),
            self.config.global.language.clone(),
        );
        env_vars.insert("COMPILER".to_string(), self.config.global.compiler.clone());
        env_vars.insert("LOG_MODE".to_string(), self.config.global.log_mode.clone());
        env_vars.insert(
            "NEGATE_PATH_FLAG".to_string(),
            self.config.global.negate_path_flag.to_string(),
        );
        env_vars.insert(
            "ZORYA_DIR".to_string(),
            self.zorya_dir.to_string_lossy().to_string(),
        );
        env_vars.insert(
            "BIN_PATH".to_string(),
            self.config.global.binary_path.clone(),
        );
        env_vars.insert("START_POINT".to_string(), test.start_address.clone());

        // Add thread scheduling if specified
        if let Some(ref sched) = self.config.global.thread_scheduling {
            env_vars.insert("THREAD_SCHEDULING".to_string(), sched.clone());
        }

        // Add test-specific environment variables
        for (key, value) in &test.env_vars {
            env_vars.insert(key.clone(), value.clone());
        }

        // Generate memory and CPU dumps for this specific test (address-specific)
        println!(
            "  Generating memory and CPU register dumps for address {}...",
            test.start_address
        );
        self.generate_dumps(&test.start_address, &test.args)?;
        println!();

        // Build command - call zorya binary directly (no command line args needed)
        let zorya_binary = self.zorya_dir.join("target/release/zorya");
        let mut cmd = Command::new(&zorya_binary);

        // Set environment variables
        for (key, value) in &env_vars {
            cmd.env(key, value);
        }

        // Redirect stdout/stderr to files
        let stdout_path = output_dir.join("stdout.txt");
        let stderr_path = output_dir.join("stderr.txt");
        let stdout_file = fs::File::create(&stdout_path)?;
        let stderr_file = fs::File::create(&stderr_path)?;

        cmd.stdout(Stdio::from(stdout_file));
        cmd.stderr(Stdio::from(stderr_file));

        // Spawn the process
        let mut child = cmd.spawn()?;
        let child_id = child.id();

        // Spawn a timeout thread that will kill the process if it takes too long
        let timeout_duration = Duration::from_secs(test.timeout_seconds);
        let timed_out = Arc::new(Mutex::new(false));
        let timed_out_clone = Arc::clone(&timed_out);

        let timeout_thread = thread::spawn(move || {
            thread::sleep(timeout_duration);
            // Try to kill the process by PID using SIGKILL
            #[cfg(unix)]
            {
                use std::process::Command as SysCommand;
                let _ = SysCommand::new("kill")
                    .arg("-9")
                    .arg(child_id.to_string())
                    .status();
            }
            #[cfg(not(unix))]
            {
                // On Windows, this won't work well, but it's better than nothing
                // In practice, Zorya is primarily used on Linux
            }
            *timed_out_clone.lock().unwrap() = true;
        });

        // Wait for the process to complete
        let exit_status = child.wait();

        timeout_thread.join().unwrap();

        let duration = start_time.elapsed();
        let timed_out = *timed_out.lock().unwrap();

        // Copy result files to output directory
        self.copy_results_to_output(&output_dir)?;

        // Check for SAT states
        let found_sat_states = output_dir.join("FOUND_SAT_STATE.txt").exists()
            || Path::new("results/FOUND_SAT_STATE.txt").exists();

        let result = match exit_status {
            Ok(status) if status.success() && !timed_out => TestResult {
                test_id: test.id.clone(),
                success: true,
                duration,
                timeout: false,
                error_message: None,
                output_dir,
                found_sat_states,
            },
            Ok(status) if timed_out => TestResult {
                test_id: test.id.clone(),
                success: false,
                duration,
                timeout: true,
                error_message: Some(format!(
                    "Process timed out (exit code: {:?})",
                    status.code()
                )),
                output_dir,
                found_sat_states,
            },
            Ok(status) => TestResult {
                test_id: test.id.clone(),
                success: false,
                duration,
                timeout: false,
                error_message: Some(format!("Process exited with code: {:?}", status.code())),
                output_dir,
                found_sat_states,
            },
            Err(e) => TestResult {
                test_id: test.id.clone(),
                success: false,
                duration,
                timeout: timed_out,
                error_message: Some(format!("Failed to execute: {}", e)),
                output_dir,
                found_sat_states,
            },
        };

        Ok(result)
    }

    /// Copy result files from results/ directory to test output directory
    fn copy_results_to_output(&self, output_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let result_files = [
            "results/execution_log.txt",
            "results/execution_trace.txt",
            "results/FOUND_SAT_STATE.txt",
            "results/xref_addresses.txt",
            "results/panic_reach.txt",
        ];

        for file in &result_files {
            if Path::new(file).exists() {
                let file_name = Path::new(file).file_name().unwrap();
                let dest = output_dir.join(file_name);
                fs::copy(file, dest)?;
            }
        }

        Ok(())
    }

    /// Print summary of all test results
    fn print_summary(&self, results: &[TestResult]) {
        println!("================================================================");
        println!("                    FUZZER CAMPAIGN SUMMARY                     ");
        println!("================================================================");
        println!();

        let total = results.len();
        let successful = results.iter().filter(|r| r.success).count();
        let timed_out = results.iter().filter(|r| r.timeout).count();
        let failed = results.iter().filter(|r| !r.success && !r.timeout).count();
        let found_sat = results.iter().filter(|r| r.found_sat_states).count();

        println!("Total tests: {}", total);
        println!("  [OK] Successful: {}", successful);
        println!("  [TIMEOUT] Timed out:  {}", timed_out);
        println!("  [FAIL] Failed:     {}", failed);
        println!("  [SAT] Found SAT:  {}", found_sat);
        println!();

        println!("Individual test results:");
        for result in results {
            let status = if result.success {
                "[SUCCESS]"
            } else if result.timeout {
                "[TIMEOUT]"
            } else {
                "[FAILED] "
            };

            let sat_marker = if result.found_sat_states {
                " [SAT]"
            } else {
                ""
            };

            println!(
                "  {} | {} | {:.2}s{}",
                status,
                result.test_id,
                result.duration.as_secs_f64(),
                sat_marker
            );
        }

        println!();
        println!("All results saved to: {}", self.results_base_dir.display());
        println!();
    }

    /// Generate a summary report file
    pub fn write_summary_report(
        &self,
        results: &[TestResult],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let report_path = self.results_base_dir.join("fuzzer_summary.txt");
        let mut report = fs::File::create(&report_path)?;

        writeln!(report, "ZORYA FUZZER CAMPAIGN SUMMARY")?;
        writeln!(report, "==============================")?;
        writeln!(report)?;
        writeln!(report, "Configuration:")?;
        writeln!(report, "  Language: {}", self.config.global.language)?;
        writeln!(report, "  Compiler: {}", self.config.global.compiler)?;
        writeln!(report, "  Binary: {}", self.config.global.binary_path)?;
        writeln!(report, "  Total tests: {}", self.config.tests.len())?;
        writeln!(report)?;

        let total = results.len();
        let successful = results.iter().filter(|r| r.success).count();
        let timed_out = results.iter().filter(|r| r.timeout).count();
        let failed = results.iter().filter(|r| !r.success && !r.timeout).count();
        let found_sat = results.iter().filter(|r| r.found_sat_states).count();

        writeln!(report, "Results Summary:")?;
        writeln!(report, "  Total tests: {}", total)?;
        writeln!(report, "  Successful: {}", successful)?;
        writeln!(report, "  Timed out: {}", timed_out)?;
        writeln!(report, "  Failed: {}", failed)?;
        writeln!(report, "  Found SAT states: {}", found_sat)?;
        writeln!(report)?;

        writeln!(report, "Individual Test Results:")?;
        writeln!(report, "------------------------")?;
        for result in results {
            writeln!(report, "Test ID: {}", result.test_id)?;
            writeln!(
                report,
                "  Status: {}",
                if result.success {
                    "SUCCESS"
                } else if result.timeout {
                    "TIMEOUT"
                } else {
                    "FAILED"
                }
            )?;
            writeln!(report, "  Duration: {:.2}s", result.duration.as_secs_f64())?;
            writeln!(report, "  Found SAT: {}", result.found_sat_states)?;
            writeln!(report, "  Output: {}", result.output_dir.display())?;
            if let Some(ref err) = result.error_message {
                writeln!(report, "  Error: {}", err)?;
            }
            writeln!(report)?;
        }

        println!("Summary report written to: {}", report_path.display());

        Ok(())
    }
}
