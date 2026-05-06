// SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobState {
    Running,
    Completed,
    Failed,
}

impl JobState {
    pub fn as_str(&self) -> &'static str {
        match self {
            JobState::Running => "running",
            JobState::Completed => "completed",
            JobState::Failed => "failed",
        }
    }
}

#[derive(Debug)]
pub struct JobEntry {
    pub id: u64,
    pub state: JobState,
    pub start_time: Instant,
    pub pid: u32,
    pub description: String,
    pub output_dir: PathBuf,
    pub error: Option<String>,
    pub exit_code: Option<i32>,
}

pub struct JobManager {
    jobs: HashMap<u64, JobEntry>,
    next_id: u64,
}

impl JobManager {
    pub fn new() -> Self {
        Self {
            jobs: HashMap::new(),
            next_id: 1,
        }
    }

    pub fn create_job(&mut self, pid: u32, description: String, output_dir: PathBuf) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.jobs.insert(
            id,
            JobEntry {
                id,
                state: JobState::Running,
                start_time: Instant::now(),
                pid,
                description,
                output_dir,
                error: None,
                exit_code: None,
            },
        );
        id
    }

    pub fn complete_job(&mut self, id: u64, exit_code: i32) {
        if let Some(job) = self.jobs.get_mut(&id) {
            if exit_code == 0 {
                job.state = JobState::Completed;
            } else {
                job.state = JobState::Failed;
                job.error = Some(format!("Process exited with code {}", exit_code));
            }
            job.exit_code = Some(exit_code);
        }
    }

    pub fn fail_job(&mut self, id: u64, error: String) {
        if let Some(job) = self.jobs.get_mut(&id) {
            job.state = JobState::Failed;
            job.error = Some(error);
        }
    }

    pub fn get_job(&self, id: u64) -> Option<&JobEntry> {
        self.jobs.get(&id)
    }

    /// Mark a running job as cancelled and return its PID for killing.
    pub fn cancel_job(&mut self, id: u64) -> Option<u32> {
        if let Some(job) = self.jobs.get_mut(&id) {
            if job.state == JobState::Running {
                job.state = JobState::Failed;
                job.error = Some("Cancelled by user".to_string());
                return Some(job.pid);
            }
        }
        None
    }
}
