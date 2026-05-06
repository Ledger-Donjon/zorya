// SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

use crate::jobs::{JobManager, JobState};
use crate::types::*;
use goblin::elf::{sym::STT_FUNC, Elf};
use rmcp::{handler::server::wrapper::Parameters, tool, tool_handler, tool_router, ServerHandler};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::process::Command;
use tokio::sync::Mutex;

// ── Session state ───────────────────────────────────────────────────────────

struct SessionState {
    binary_path: Option<String>,
    language: Option<String>,
    compiler: Option<String>,
    thread_scheduling: Option<String>,
    entry_point: Option<u64>,
    negate_path: bool,
    elf_bytes: Option<Vec<u8>>,
}

impl SessionState {
    fn new() -> Self {
        Self {
            binary_path: None,
            language: None,
            compiler: None,
            thread_scheduling: None,
            entry_point: None,
            negate_path: true,
            elf_bytes: None,
        }
    }
}

// ── Server struct ───────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct ZoryaMcp {
    state: Arc<Mutex<SessionState>>,
    jobs: Arc<Mutex<JobManager>>,
    zorya_dir: PathBuf,
}

impl ZoryaMcp {
    pub fn new(zorya_dir: PathBuf) -> Self {
        Self {
            state: Arc::new(Mutex::new(SessionState::new())),
            jobs: Arc::new(Mutex::new(JobManager::new())),
            zorya_dir,
        }
    }
}

// ── Tool implementations ────────────────────────────────────────────────────

#[tool_router]
impl ZoryaMcp {
    // ── Reconnaissance ──────────────────────────────────────────────────

    #[tool(
        description = "Load an ELF binary for analysis. Parses the binary to extract entry point, function count, and section layout. Must be called before other tools. Supports Go (gc/tinygo), C, and C++ ELF binaries."
    )]
    async fn load_binary(&self, Parameters(params): Parameters<LoadBinaryParams>) -> String {
        let path = Path::new(&params.binary_path);
        if !path.exists() {
            return json!({"error": format!("Binary not found: {}", params.binary_path)})
                .to_string();
        }

        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                return json!({"error": format!("Failed to read binary: {}", e)}).to_string()
            }
        };

        let elf = match Elf::parse(&bytes) {
            Ok(e) => e,
            Err(e) => {
                return json!({"error": format!("Failed to parse ELF: {}", e)}).to_string()
            }
        };

        let entry = elf.entry;
        let func_count = elf.syms.iter().filter(|s| s.st_type() == STT_FUNC).count();
        let sections: Vec<_> = elf
            .section_headers
            .iter()
            .filter_map(|sh| {
                elf.shdr_strtab.get_at(sh.sh_name).map(|name| {
                    json!({
                        "name": name,
                        "address": format!("0x{:x}", sh.sh_addr),
                        "size": sh.sh_size
                    })
                })
            })
            .collect();

        let compiler = params.compiler.unwrap_or_else(|| "gc".to_string());
        let mut state = self.state.lock().await;
        state.binary_path = Some(params.binary_path.clone());
        state.language = Some(params.language.clone());
        state.compiler = Some(compiler.clone());
        state.thread_scheduling = params.thread_scheduling.clone();
        state.entry_point = Some(entry);
        state.elf_bytes = Some(bytes);

        json!({
            "status": "loaded",
            "binary_path": params.binary_path,
            "language": params.language,
            "compiler": compiler,
            "entry_point": format!("0x{:x}", entry),
            "function_count": func_count,
            "sections": sections
        })
        .to_string()
    }

    #[tool(
        description = "List functions discovered in the loaded binary's ELF symbol table. Supports filtering by name substring and pagination. Call load_binary first."
    )]
    async fn list_functions(
        &self,
        Parameters(params): Parameters<ListFunctionsParams>,
    ) -> String {
        let state = self.state.lock().await;
        let bytes = match &state.elf_bytes {
            Some(b) => b,
            None => {
                return json!({"error": "No binary loaded. Call load_binary first."}).to_string()
            }
        };

        let elf = match Elf::parse(bytes) {
            Ok(e) => e,
            Err(e) => return json!({"error": format!("ELF parse error: {}", e)}).to_string(),
        };

        let mut functions: Vec<_> = elf
            .syms
            .iter()
            .filter(|s| s.st_type() == STT_FUNC && s.st_value != 0)
            .filter_map(|s| {
                elf.strtab
                    .get_at(s.st_name)
                    .map(|name| (name.to_string(), s.st_value, s.st_size))
            })
            .collect();

        if let Some(ref filter) = params.filter {
            let f = filter.to_lowercase();
            functions.retain(|(name, _, _)| name.to_lowercase().contains(&f));
        }

        functions.sort_by_key(|(_, addr, _)| *addr);

        let total = functions.len();
        let offset = params.offset.unwrap_or(0);
        let limit = params.limit.unwrap_or(100);

        let page: Vec<_> = functions
            .iter()
            .skip(offset)
            .take(limit)
            .map(|(name, addr, size)| {
                json!({"name": name, "address": format!("0x{:x}", addr), "size": size})
            })
            .collect();

        json!({
            "functions": page,
            "total": total,
            "offset": offset,
            "limit": limit,
            "has_more": offset + limit < total
        })
        .to_string()
    }

    #[tool(
        description = "Get the signature of a function by name or hex address. Returns argument types and locations when available from DWARF/Ghidra analysis."
    )]
    async fn get_function_signature(
        &self,
        Parameters(params): Parameters<GetFunctionSignatureParams>,
    ) -> String {
        let state = self.state.lock().await;

        // Try Go function signatures JSON first
        let sig_path = self.zorya_dir.join("results/function_signatures_go.json");
        if sig_path.exists() {
            if let Ok(content) = std::fs::read_to_string(&sig_path) {
                if let Ok(sigs) = serde_json::from_str::<serde_json::Value>(&content) {
                    if let Some(obj) = sigs.as_object() {
                        for (key, val) in obj {
                            let addr_match = val
                                .get("address")
                                .and_then(|a| a.as_str())
                                .map(|a| a == params.name_or_address)
                                .unwrap_or(false);
                            if key == &params.name_or_address
                                || key.contains(&params.name_or_address)
                                || addr_match
                            {
                                return json!({
                                    "found": true,
                                    "source": "go_signatures",
                                    "name": key,
                                    "signature": val
                                })
                                .to_string();
                            }
                        }
                    }
                }
            }
        }

        // Try Ghidra C/C++ signatures
        let ghidra_sig_path = self.zorya_dir.join("results/function_signatures.json");
        if ghidra_sig_path.exists() {
            if let Ok(content) = std::fs::read_to_string(&ghidra_sig_path) {
                if let Ok(sigs) = serde_json::from_str::<serde_json::Value>(&content) {
                    if let Some(obj) = sigs.as_object() {
                        for (key, val) in obj {
                            if key == &params.name_or_address
                                || key.contains(&params.name_or_address)
                            {
                                return json!({
                                    "found": true,
                                    "source": "ghidra_signatures",
                                    "name": key,
                                    "signature": val
                                })
                                .to_string();
                            }
                        }
                    }
                }
            }
        }

        // Fallback: ELF symbol lookup
        let bytes = match &state.elf_bytes {
            Some(b) => b,
            None => return json!({"error": "No binary loaded."}).to_string(),
        };

        let elf = match Elf::parse(bytes) {
            Ok(e) => e,
            Err(_) => return json!({"error": "Failed to parse ELF"}).to_string(),
        };

        let target_addr = if params.name_or_address.starts_with("0x") {
            u64::from_str_radix(params.name_or_address.trim_start_matches("0x"), 16).ok()
        } else {
            None
        };

        for sym in elf.syms.iter() {
            if sym.st_type() != STT_FUNC {
                continue;
            }
            let name = elf.strtab.get_at(sym.st_name).unwrap_or("");
            let matches = if let Some(addr) = target_addr {
                sym.st_value == addr
            } else {
                name == params.name_or_address || name.contains(&params.name_or_address)
            };

            if matches {
                return json!({
                    "found": true,
                    "source": "elf_symbols",
                    "name": name,
                    "address": format!("0x{:x}", sym.st_value),
                    "size": sym.st_size,
                    "note": "Detailed argument types require running function signature extraction (happens during load_binary pcode generation)"
                })
                .to_string();
            }
        }

        json!({"found": false, "query": params.name_or_address}).to_string()
    }

    #[tool(
        description = "List printable strings found in the loaded binary. Useful for finding hardcoded values, error messages, and understanding binary behavior."
    )]
    async fn list_strings(&self, Parameters(params): Parameters<ListStringsParams>) -> String {
        let state = self.state.lock().await;
        let binary_path = match &state.binary_path {
            Some(p) => p.clone(),
            None => return json!({"error": "No binary loaded."}).to_string(),
        };
        drop(state);

        let min_len = params.min_length.unwrap_or(4);

        let output = match std::process::Command::new("strings")
            .arg("-n")
            .arg(min_len.to_string())
            .arg(&binary_path)
            .output()
        {
            Ok(o) => o,
            Err(e) => {
                return json!({"error": format!("Failed to run strings command: {}", e)})
                    .to_string()
            }
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut strings: Vec<&str> = stdout.lines().collect();

        if let Some(ref filter) = params.filter {
            let f = filter.to_lowercase();
            strings.retain(|s| s.to_lowercase().contains(&f));
        }

        let total = strings.len();
        let offset = params.offset.unwrap_or(0);
        let limit = params.limit.unwrap_or(100);

        let page: Vec<&str> = strings.iter().skip(offset).take(limit).copied().collect();

        json!({
            "strings": page,
            "total": total,
            "offset": offset,
            "limit": limit,
            "has_more": offset + limit < total
        })
        .to_string()
    }

    // ── Execution ───────────────────────────────────────────────────────

    #[tool(
        description = "Run concolic analysis on a single function. Triggers the full zorya pipeline: P-code generation, GDB memory dumps, and concolic execution with Z3 constraint solving. Returns a job_id to poll with get_job_status. Results are written to the results/ directory."
    )]
    async fn run_analysis(&self, Parameters(params): Parameters<RunAnalysisParams>) -> String {
        let state = self.state.lock().await;
        let binary_path = match &state.binary_path {
            Some(p) => p.clone(),
            None => {
                return json!({"error": "No binary loaded. Call load_binary first."}).to_string()
            }
        };
        let language = state.language.clone().unwrap_or_else(|| "go".to_string());
        let compiler = state.compiler.clone().unwrap_or_else(|| "gc".to_string());
        let thread_sched = state.thread_scheduling.clone();
        drop(state);

        let zorya_script = self.zorya_dir.join("scripts/zorya");
        if !zorya_script.exists() {
            return json!({"error": format!("Zorya script not found: {}", zorya_script.display())})
                .to_string();
        }

        let mut cmd = Command::new(&zorya_script);
        cmd.arg(&binary_path)
            .arg("--lang")
            .arg(&language)
            .arg("--compiler")
            .arg(&compiler)
            .arg("--mode")
            .arg(&params.mode)
            .arg(&params.start_address);

        if let Some(ref sched) = thread_sched {
            cmd.arg("--thread-scheduling").arg(sched);
        }

        if let Some(ref args) = params.args {
            cmd.arg("--arg").arg(args);
        }

        if params.negate_path.unwrap_or(true) {
            cmd.arg("--negate-path-exploration");
        } else {
            cmd.arg("--no-negate-path-exploration");
        }

        cmd.current_dir(&self.zorya_dir)
            .env("ZORYA_DIR", self.zorya_dir.as_os_str())
            .stdin(std::process::Stdio::null());

        let output_dir = self.zorya_dir.join("results");
        let _ = std::fs::create_dir_all(&output_dir);

        let stdout_log = output_dir.join("mcp_analysis_stdout.txt");
        let stderr_log = output_dir.join("mcp_analysis_stderr.txt");
        cmd.stdout(std::process::Stdio::from(
            std::fs::File::create(&stdout_log).unwrap_or_else(|_| {
                std::fs::File::create("/dev/null").expect("failed to open /dev/null")
            }),
        ));
        cmd.stderr(std::process::Stdio::from(
            std::fs::File::create(&stderr_log).unwrap_or_else(|_| {
                std::fs::File::create("/dev/null").expect("failed to open /dev/null")
            }),
        ));

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                return json!({"error": format!("Failed to spawn zorya: {}", e)}).to_string()
            }
        };

        let pid = child.id().unwrap_or(0);
        let description = format!("Analysis: {} @ {}", params.mode, params.start_address);

        let job_id = {
            let mut jobs = self.jobs.lock().await;
            jobs.create_job(pid, description.clone(), output_dir)
        };

        let jobs = Arc::clone(&self.jobs);
        tokio::spawn(async move {
            let status = child.wait().await;
            let mut jobs = jobs.lock().await;
            match status {
                Ok(exit) => jobs.complete_job(job_id, exit.code().unwrap_or(-1)),
                Err(e) => jobs.fail_job(job_id, e.to_string()),
            }
        });

        json!({
            "job_id": job_id,
            "status": "started",
            "description": description
        })
        .to_string()
    }

    #[tool(
        description = "Run a campaign of multiple concolic tests on different functions. Builds a fuzzer configuration and executes all tests sequentially via zorya-fuzzer. Each test targets a specific function address with given arguments. Returns a job_id to poll with get_job_status."
    )]
    async fn run_campaign(&self, Parameters(params): Parameters<RunCampaignParams>) -> String {
        let state = self.state.lock().await;
        let binary_path = match &state.binary_path {
            Some(p) => p.clone(),
            None => return json!({"error": "No binary loaded."}).to_string(),
        };
        let language = state.language.clone().unwrap_or_else(|| "go".to_string());
        let compiler = state.compiler.clone().unwrap_or_else(|| "gc".to_string());
        let thread_sched = state
            .thread_scheduling
            .clone()
            .unwrap_or_else(|| "main-only".to_string());
        let negate = state.negate_path;
        drop(state);

        if params.tests.is_empty() {
            return json!({"error": "No tests provided. Add at least one test configuration."})
                .to_string();
        }

        let config = json!({
            "global": {
                "language": language,
                "compiler": compiler,
                "binary_path": binary_path,
                "thread_scheduling": thread_sched,
                "log_mode": "verbose",
                "negate_path_flag": negate
            },
            "tests": params.tests.iter().map(|t| {
                json!({
                    "id": t.id,
                    "mode": t.mode,
                    "start_address": t.start_address,
                    "args": t.args.as_deref().unwrap_or("none"),
                    "timeout_seconds": t.timeout_seconds.unwrap_or(300),
                    "env_vars": {}
                })
            }).collect::<Vec<_>>()
        });

        let config_path = self.zorya_dir.join("mcp_campaign_config.json");
        if let Err(e) = std::fs::write(
            &config_path,
            serde_json::to_string_pretty(&config).unwrap(),
        ) {
            return json!({"error": format!("Failed to write campaign config: {}", e)}).to_string();
        }

        let fuzzer_bin = self.zorya_dir.join("target/release/zorya-fuzzer");
        if !fuzzer_bin.exists() {
            return json!({
                "error": format!("zorya-fuzzer binary not found at {}. Run `cargo build --release` first.", fuzzer_bin.display())
            }).to_string();
        }

        let output_dir = self.zorya_dir.join("fuzzer_results");
        let _ = std::fs::create_dir_all(&output_dir);

        let mut cmd = Command::new(&fuzzer_bin);
        cmd.arg(config_path.to_str().unwrap())
            .env("ZORYA_DIR", self.zorya_dir.to_str().unwrap())
            .current_dir(&self.zorya_dir)
            .stdin(std::process::Stdio::null());

        let stdout_log = output_dir.join("mcp_campaign_stdout.txt");
        let stderr_log = output_dir.join("mcp_campaign_stderr.txt");
        cmd.stdout(std::process::Stdio::from(
            std::fs::File::create(&stdout_log).unwrap_or_else(|_| {
                std::fs::File::create("/dev/null").expect("failed to open /dev/null")
            }),
        ));
        cmd.stderr(std::process::Stdio::from(
            std::fs::File::create(&stderr_log).unwrap_or_else(|_| {
                std::fs::File::create("/dev/null").expect("failed to open /dev/null")
            }),
        ));

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                return json!({"error": format!("Failed to spawn zorya-fuzzer: {}", e)}).to_string()
            }
        };

        let pid = child.id().unwrap_or(0);
        let test_count = params.tests.len();
        let description = format!("Campaign: {} tests", test_count);

        let job_id = {
            let mut jobs = self.jobs.lock().await;
            jobs.create_job(pid, description, output_dir)
        };

        let jobs = Arc::clone(&self.jobs);
        tokio::spawn(async move {
            let status = child.wait().await;
            let mut jobs = jobs.lock().await;
            match status {
                Ok(exit) => jobs.complete_job(job_id, exit.code().unwrap_or(-1)),
                Err(e) => jobs.fail_job(job_id, e.to_string()),
            }
        });

        json!({
            "job_id": job_id,
            "status": "started",
            "test_count": test_count,
            "config_path": config_path.to_str()
        })
        .to_string()
    }

    #[tool(
        description = "Check the status of a running analysis or campaign job. Returns the current state (running, completed, failed), elapsed time, and error details if the job failed."
    )]
    async fn get_job_status(
        &self,
        Parameters(params): Parameters<GetJobStatusParams>,
    ) -> String {
        let jobs = self.jobs.lock().await;
        match jobs.get_job(params.job_id) {
            Some(job) => {
                let elapsed = job.start_time.elapsed().as_secs();
                let mut result = json!({
                    "job_id": job.id,
                    "state": job.state.as_str(),
                    "elapsed_seconds": elapsed,
                    "description": job.description,
                });
                if let Some(ref err) = job.error {
                    result["error"] = json!(err);
                }
                if let Some(code) = job.exit_code {
                    result["exit_code"] = json!(code);
                }
                // If completed, check for SAT results
                if job.state == JobState::Completed {
                    let sat_path = job.output_dir.join("FOUND_SAT_STATE.txt");
                    result["sat_found"] = json!(sat_path.exists());
                }
                result.to_string()
            }
            None => json!({"error": format!("Job {} not found", params.job_id)}).to_string(),
        }
    }

    #[tool(description = "Cancel a running analysis or campaign job by killing its process.")]
    async fn cancel_job(&self, Parameters(params): Parameters<CancelJobParams>) -> String {
        let mut jobs = self.jobs.lock().await;
        match jobs.cancel_job(params.job_id) {
            Some(pid) => {
                drop(jobs);
                let _ = std::process::Command::new("kill")
                    .arg("-9")
                    .arg(pid.to_string())
                    .status();
                json!({"cancelled": true, "job_id": params.job_id}).to_string()
            }
            None => {
                json!({"cancelled": false, "error": "Job not found or already finished"})
                    .to_string()
            }
        }
    }

    // ── Results ─────────────────────────────────────────────────────────

    #[tool(
        description = "Read SAT states (concrete vulnerability-triggering inputs) found by concolic analysis. These are the primary findings: inputs that satisfy vulnerability constraints discovered by the Z3 solver."
    )]
    async fn get_sat_states(&self, Parameters(params): Parameters<GetSatStatesParams>) -> String {
        let path = if let Some(ref test_id) = params.test_id {
            self.zorya_dir
                .join("fuzzer_results")
                .join(test_id)
                .join("FOUND_SAT_STATE.txt")
        } else {
            self.zorya_dir.join("results/FOUND_SAT_STATE.txt")
        };

        if !path.exists() {
            return json!({
                "found": false,
                "message": "No SAT states found. The analysis may not have discovered vulnerabilities, or may still be running."
            }).to_string();
        }

        match std::fs::read_to_string(&path) {
            Ok(content) => json!({
                "found": true,
                "path": path.to_string_lossy(),
                "content": content
            })
            .to_string(),
            Err(e) => json!({"error": format!("Failed to read SAT states: {}", e)}).to_string(),
        }
    }

    #[tool(
        description = "Read the execution trace showing the sequence of function calls and their argument context during concolic analysis. Supports pagination for large traces."
    )]
    async fn get_execution_trace(
        &self,
        Parameters(params): Parameters<GetExecutionTraceParams>,
    ) -> String {
        let path = if let Some(ref test_id) = params.test_id {
            self.zorya_dir
                .join("fuzzer_results")
                .join(test_id)
                .join("execution_trace.txt")
        } else {
            self.zorya_dir.join("results/execution_trace.txt")
        };

        if !path.exists() {
            return json!({"error": "Execution trace not found. Run an analysis first."})
                .to_string();
        }

        match std::fs::read_to_string(&path) {
            Ok(content) => {
                let lines: Vec<&str> = content.lines().collect();
                let total = lines.len();
                let offset = params.offset.unwrap_or(0);
                let limit = params.limit.unwrap_or(200);
                let page: Vec<&str> = lines.iter().skip(offset).take(limit).copied().collect();

                json!({
                    "lines": page,
                    "total_lines": total,
                    "offset": offset,
                    "limit": limit,
                    "has_more": offset + limit < total
                })
                .to_string()
            }
            Err(e) => json!({"error": format!("Failed to read trace: {}", e)}).to_string(),
        }
    }

    #[tool(
        description = "Read the campaign summary report showing pass/fail/timeout/SAT counts for each test in the latest fuzzer campaign run."
    )]
    async fn get_campaign_summary(
        &self,
        Parameters(_params): Parameters<GetCampaignSummaryParams>,
    ) -> String {
        let path = self.zorya_dir.join("fuzzer_results/fuzzer_summary.txt");

        if !path.exists() {
            return json!({"error": "No campaign summary found. Run a campaign with run_campaign first."}).to_string();
        }

        match std::fs::read_to_string(&path) {
            Ok(content) => json!({"content": content}).to_string(),
            Err(e) => {
                json!({"error": format!("Failed to read campaign summary: {}", e)}).to_string()
            }
        }
    }

    #[tool(
        description = "List all result files from an analysis run or a specific campaign test. Shows file names and sizes."
    )]
    async fn list_result_files(
        &self,
        Parameters(params): Parameters<ListResultFilesParams>,
    ) -> String {
        let dir = if let Some(ref test_id) = params.test_id {
            self.zorya_dir.join("fuzzer_results").join(test_id)
        } else {
            self.zorya_dir.join("results")
        };

        if !dir.exists() {
            return json!({"error": format!("Results directory not found: {}", dir.display())})
                .to_string();
        }

        let entries: Vec<_> = match std::fs::read_dir(&dir) {
            Ok(entries) => entries
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
                .map(|e| {
                    let size = e.metadata().map(|m| m.len()).unwrap_or(0);
                    json!({
                        "name": e.file_name().to_string_lossy(),
                        "size_bytes": size
                    })
                })
                .collect(),
            Err(e) => {
                return json!({"error": format!("Failed to read directory: {}", e)}).to_string()
            }
        };

        json!({
            "directory": dir.to_string_lossy(),
            "files": entries,
            "file_count": entries.len()
        })
        .to_string()
    }
}

// ── ServerHandler wiring ────────────────────────────────────────────────────

#[tool_handler(
    name = "zorya",
    version = "0.1.0",
    instructions = "Zorya concolic execution MCP server for autonomous binary vulnerability analysis. Workflow: 1) load_binary to register an ELF binary, 2) list_functions to discover targets, 3) run_analysis or run_campaign to execute concolic analysis, 4) get_job_status to monitor progress, 5) get_sat_states to retrieve vulnerability findings."
)]
impl ServerHandler for ZoryaMcp {}
