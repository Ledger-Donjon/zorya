// SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Global configuration settings for all test runs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalConfig {
    /// Source language (e.g., "go", "c", "c++")
    pub language: String,
    /// Compiler used (e.g., "gc", "tinygo", "gcc", "clang")
    pub compiler: String,
    /// Path to the binary to analyze
    pub binary_path: String,
    /// Thread scheduling policy (optional: "round_robin", "main_only")
    #[serde(default)]
    pub thread_scheduling: Option<String>,
    /// Logging mode (optional: "verbose", "trace_only")
    #[serde(default = "default_log_mode")]
    pub log_mode: String,
    /// Enable path negation flag (optional)
    #[serde(default = "default_negate_path")]
    pub negate_path_flag: bool,
}

fn default_log_mode() -> String {
    "verbose".to_string()
}

fn default_negate_path() -> bool {
    true
}

/// Configuration for a single test run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestConfig {
    /// Unique identifier for this test
    pub id: String,
    /// Execution mode ("function", "start", "main")
    pub mode: String,
    /// Starting address (hex string, e.g., "0x401000")
    pub start_address: String,
    /// Arguments for the binary (space-separated string or "none")
    #[serde(default = "default_args")]
    pub args: String,
    /// Timeout in seconds (defaults to 300 = 5 minutes)
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    /// Optional additional environment variables
    #[serde(default)]
    pub env_vars: HashMap<String, String>,
}

fn default_args() -> String {
    "none".to_string()
}

fn default_timeout() -> u64 {
    300 // 5 minutes default
}

/// Complete fuzzer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzerConfig {
    /// Global settings applied to all tests
    pub global: GlobalConfig,
    /// List of test configurations to execute
    pub tests: Vec<TestConfig>,
}

impl FuzzerConfig {
    /// Load configuration from a JSON file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let config: FuzzerConfig = serde_json::from_str(&content)?;
        Ok(config)
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), String> {
        // Validate binary path exists
        if !Path::new(&self.global.binary_path).exists() {
            return Err(format!(
                "Binary path does not exist: {}",
                self.global.binary_path
            ));
        }

        // Validate language
        let valid_languages = ["go", "c", "c++"];
        if !valid_languages.contains(&self.global.language.to_lowercase().as_str()) {
            return Err(format!(
                "Invalid language: {}. Must be one of: {:?}",
                self.global.language, valid_languages
            ));
        }

        // Validate test configurations
        if self.tests.is_empty() {
            return Err("No test configurations provided".to_string());
        }

        for test in &self.tests {
            // Validate mode
            let valid_modes = ["function", "start", "main"];
            if !valid_modes.contains(&test.mode.as_str()) {
                return Err(format!(
                    "Invalid mode '{}' for test '{}'. Must be one of: {:?}",
                    test.mode, test.id, valid_modes
                ));
            }

            // Validate start address format
            if !test.start_address.starts_with("0x") {
                return Err(format!(
                    "Invalid start address format for test '{}': {}. Must start with '0x'",
                    test.id, test.start_address
                ));
            }

            // Try parsing the hex address
            if u64::from_str_radix(test.start_address.trim_start_matches("0x"), 16).is_err() {
                return Err(format!(
                    "Invalid hex address for test '{}': {}",
                    test.id, test.start_address
                ));
            }
        }

        Ok(())
    }

    /// Create an example configuration file
    pub fn create_example<P: AsRef<Path>>(path: P) -> Result<(), Box<dyn std::error::Error>> {
        let example = FuzzerConfig {
            global: GlobalConfig {
                language: "go".to_string(),
                compiler: "gc".to_string(),
                binary_path: "./target_binary".to_string(),
                thread_scheduling: Some("main_only".to_string()),
                log_mode: "verbose".to_string(),
                negate_path_flag: true,
            },
            tests: vec![
                TestConfig {
                    id: "test1".to_string(),
                    mode: "function".to_string(),
                    start_address: "0x401000".to_string(),
                    args: "none".to_string(),
                    timeout_seconds: 300,
                    env_vars: HashMap::new(),
                },
                TestConfig {
                    id: "test2".to_string(),
                    mode: "start".to_string(),
                    start_address: "0x401500".to_string(),
                    args: "arg1 arg2".to_string(),
                    timeout_seconds: 300,
                    env_vars: HashMap::new(),
                },
            ],
        };

        let json = serde_json::to_string_pretty(&example)?;
        fs::write(path, json)?;
        Ok(())
    }
}
