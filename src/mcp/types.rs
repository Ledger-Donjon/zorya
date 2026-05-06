// SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

use schemars::JsonSchema;
use serde::Deserialize;

// ── Group 1: Reconnaissance ─────────────────────────────────────────────────

#[derive(Debug, Deserialize, JsonSchema)]
pub struct LoadBinaryParams {
    #[schemars(description = "Absolute path to the ELF binary to analyze")]
    pub binary_path: String,
    #[schemars(description = "Source language: go, c, or c++")]
    pub language: String,
    #[schemars(
        description = "Compiler used to build the binary: gc or tinygo (Go), gcc or clang (C/C++). Defaults to gc"
    )]
    pub compiler: Option<String>,
    #[schemars(description = "Thread scheduling for Go gc binaries: main-only or all-threads")]
    pub thread_scheduling: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListFunctionsParams {
    #[schemars(description = "Filter functions whose name contains this substring")]
    pub filter: Option<String>,
    #[schemars(description = "Pagination offset (0-based). Defaults to 0")]
    pub offset: Option<usize>,
    #[schemars(description = "Maximum number of results to return. Defaults to 100")]
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetFunctionSignatureParams {
    #[schemars(
        description = "Function name (e.g. main.coreEngine) or hex address (e.g. 0x4bef60)"
    )]
    pub name_or_address: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListStringsParams {
    #[schemars(description = "Filter strings containing this substring")]
    pub filter: Option<String>,
    #[schemars(description = "Minimum string length to include. Defaults to 4")]
    pub min_length: Option<usize>,
    #[schemars(description = "Pagination offset. Defaults to 0")]
    pub offset: Option<usize>,
    #[schemars(description = "Maximum number of results. Defaults to 100")]
    pub limit: Option<usize>,
}

// ── Group 2: Execution ──────────────────────────────────────────────────────

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RunAnalysisParams {
    #[schemars(description = "Execution mode: start (entry point), main (main function), or function (specific address)")]
    pub mode: String,
    #[schemars(
        description = "Start address as hex string (e.g. 0x4bef60). Required for function mode"
    )]
    pub start_address: String,
    #[schemars(description = "Arguments to pass to the binary at runtime (e.g. \"2 + 3\")")]
    pub args: Option<String>,
    #[schemars(description = "Enable negated path exploration to find alternate branches. Defaults to true")]
    pub negate_path: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CampaignTest {
    #[schemars(description = "Unique test identifier (e.g. main.main-1, main.coreEngine)")]
    pub id: String,
    #[schemars(description = "Execution mode: start, main, or function")]
    pub mode: String,
    #[schemars(description = "Start address as hex string (e.g. 0x4bef60)")]
    pub start_address: String,
    #[schemars(
        description = "Arguments to pass to the binary. Use \"none\" for no arguments. Defaults to none"
    )]
    pub args: Option<String>,
    #[schemars(description = "Timeout in seconds for this test. Defaults to 300")]
    pub timeout_seconds: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RunCampaignParams {
    #[schemars(
        description = "List of test configurations. Each test targets a function at a specific address with given arguments."
    )]
    pub tests: Vec<CampaignTest>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetJobStatusParams {
    #[schemars(description = "Job ID returned by run_analysis or run_campaign")]
    pub job_id: u64,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CancelJobParams {
    #[schemars(description = "Job ID of the running job to cancel")]
    pub job_id: u64,
}

// ── Group 3: Results ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetSatStatesParams {
    #[schemars(
        description = "Test ID from a campaign run (e.g. main.main-1). If omitted, reads the latest single-run results"
    )]
    pub test_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetExecutionTraceParams {
    #[schemars(
        description = "Test ID from a campaign run. If omitted, reads the latest single-run results"
    )]
    pub test_id: Option<String>,
    #[schemars(description = "Line offset to start reading from. Defaults to 0")]
    pub offset: Option<usize>,
    #[schemars(description = "Maximum number of lines to return. Defaults to 200")]
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetCampaignSummaryParams {}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListResultFilesParams {
    #[schemars(
        description = "Test ID from a campaign run. If omitted, lists the main results/ directory"
    )]
    pub test_id: Option<String>,
}
