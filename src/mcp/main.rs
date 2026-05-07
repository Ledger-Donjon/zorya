// SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

mod jobs;
mod server;
mod types;

use rmcp::{transport::stdio, ServiceExt};
use std::path::PathBuf;

/// Detect the zorya workspace root directory.
fn detect_zorya_dir() -> PathBuf {
    // 1. Explicit env var (set in MCP server config)
    if let Ok(dir) = std::env::var("ZORYA_DIR") {
        let p = PathBuf::from(&dir);
        if p.join("Cargo.toml").exists() {
            return p;
        }
        eprintln!(
            "zorya-mcp: ZORYA_DIR={} does not contain Cargo.toml, trying other methods",
            dir
        );
    }

    // 2. Walk up from the binary location (target/release/zorya-mcp -> workspace root)
    if let Ok(exe) = std::env::current_exe() {
        // Binary is at <root>/target/{release,debug}/zorya-mcp
        if let Some(root) = exe
            .parent()
            .and_then(|p| p.parent())
            .and_then(|p| p.parent())
        {
            if root.join("Cargo.toml").exists() && root.join("src/mcp").exists() {
                return root.to_path_buf();
            }
        }
    }

    // 3. Current working directory
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    if cwd.join("Cargo.toml").exists() {
        return cwd;
    }

    eprintln!("zorya-mcp: Could not detect ZORYA_DIR. Set the ZORYA_DIR environment variable.");
    cwd
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let zorya_dir = detect_zorya_dir();
    eprintln!("zorya-mcp v0.1.0 starting");
    eprintln!("  zorya_dir: {}", zorya_dir.display());

    let service = server::ZoryaMcp::new(zorya_dir);
    let server = service.serve(stdio()).await?;
    server.waiting().await?;

    Ok(())
}
