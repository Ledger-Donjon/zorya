// SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::process;
use zorya::fuzzer::{FuzzerConfig, FuzzerRunner};
use zorya::{teprintln, tprintln};

fn print_usage() {
    tprintln!("ZORYA FUZZER - Automated Concolic Execution Test Campaign");
    tprintln!();
    tprintln!("Usage:");
    tprintln!("  zorya-fuzzer-main <config.json>          Run fuzzer with configuration file");
    tprintln!("  zorya-fuzzer-main --create-example <path> Create example configuration file");
    tprintln!("  zorya-fuzzer-main --help                  Show this help message");
    tprintln!();
    tprintln!("Configuration File Format:");
    tprintln!("  The JSON configuration file should contain:");
    tprintln!("    - global: Global settings (language, compiler, binary path, etc.)");
    tprintln!("    - tests: Array of test configurations with start addresses and arguments");
    tprintln!();
    tprintln!("Example:");
    tprintln!("  zorya-fuzzer-main fuzzer_config.json");
    tprintln!("  zorya-fuzzer-main --create-example example_config.json");
}

fn main() {
    zorya::init_trace_file("results/execution_trace.txt");
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        teprintln!("Error: Missing configuration file argument");
        tprintln!();
        print_usage();
        process::exit(1);
    }

    match args[1].as_str() {
        "--help" | "-h" => {
            print_usage();
            process::exit(0);
        }
        "--create-example" => {
            if args.len() < 3 {
                teprintln!("Error: Missing output path for example configuration");
                process::exit(1);
            }
            let output_path = &args[2];
            match FuzzerConfig::create_example(output_path) {
                Ok(_) => {
                    tprintln!("[OK] Example configuration created: {}", output_path);
                    tprintln!("  Edit this file with your binary path and test configurations");
                    process::exit(0);
                }
                Err(e) => {
                    teprintln!("Error creating example configuration: {}", e);
                    process::exit(1);
                }
            }
        }
        config_path => {
            // Load and validate configuration
            let config = match FuzzerConfig::from_file(config_path) {
                Ok(cfg) => cfg,
                Err(e) => {
                    teprintln!("Error loading configuration file: {}", e);
                    process::exit(1);
                }
            };

            if let Err(e) = config.validate() {
                teprintln!("Configuration validation failed: {}", e);
                process::exit(1);
            }

            tprintln!("[OK] Configuration loaded and validated");
            tprintln!();

            // Create and run fuzzer
            let runner = match FuzzerRunner::new(config) {
                Ok(r) => r,
                Err(e) => {
                    teprintln!("Error creating fuzzer runner: {}", e);
                    process::exit(1);
                }
            };

            let results = match runner.run_all() {
                Ok(r) => r,
                Err(e) => {
                    teprintln!("Error during fuzzer execution: {}", e);
                    process::exit(1);
                }
            };

            // Write summary report
            if let Err(e) = runner.write_summary_report(&results) {
                teprintln!("Warning: Failed to write summary report: {}", e);
            }

            // Exit with appropriate code
            let all_successful = results.iter().all(|r| r.success);
            if all_successful {
                tprintln!("[OK] All tests completed successfully");
                process::exit(0);
            } else {
                tprintln!("[WARNING] Some tests failed or timed out");
                process::exit(1);
            }
        }
    }
}
