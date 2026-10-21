// SPDX-FileCopyrightText: 2026 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

//! The launcher's `--analysis` profiles, checked through `--dry-run`, which
//! prints the resolved command and settings without running anything.

use std::collections::HashMap;
use std::process::Command;

const GO_BINARY: &str =
    "tests/programs/chancheck-test5-input-close-race/chancheck-test5-input-close-race";

struct DryRun {
    ok: bool,
    output: String,
    settings: HashMap<String, String>,
}

fn dry_run(args: &[&str]) -> DryRun {
    let root = env!("CARGO_MANIFEST_DIR");
    let out = Command::new("bash")
        .arg(format!("{root}/scripts/zorya"))
        .arg(format!("{root}/{GO_BINARY}"))
        .args(args)
        .arg("--dry-run")
        .current_dir(root)
        .env("ZORYA_DIR", root)
        .env_remove("ZORYA_ANALYSES")
        .env_remove("ZORYA_RACE_RESEED")
        .env_remove("ZORYA_MEM_SAFETY_ORACLES")
        .env_remove("ZORYA_INT_ARITH_ORACLES")
        .output()
        .expect("run scripts/zorya");
    let output =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    let settings = output
        .lines()
        .filter_map(|l| l.split_once('='))
        .filter(|(k, _)| k.chars().all(|c| c.is_ascii_uppercase() || c == '_'))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    DryRun {
        ok: out.status.success(),
        output,
        settings,
    }
}

impl DryRun {
    fn get(&self, key: &str) -> &str {
        self.settings.get(key).map(String::as_str).unwrap_or("")
    }
}

#[test]
fn profiles_merge_into_plugins_and_settings() {
    let r = dry_run(&[
        "--analysis",
        "data-race",
        "channel-safety",
        "--arg",
        "0",
        "0",
    ]);
    assert!(r.ok, "{}", r.output);
    assert_eq!(r.get("SOURCE_LANG"), "go");
    assert_eq!(r.get("COMPILER"), "gc");
    assert_eq!(r.get("MODE"), "main");
    assert_eq!(r.get("ARGS"), "0 0");
    assert_eq!(r.get("ZORYA_ANALYSES"), "data-race,channel-safety");
    assert_eq!(r.get("ZORYA_PLUGINS"), "volos chancheck");
    assert_eq!(r.get("THREAD_SCHEDULING"), "all-threads");
    assert_eq!(r.get("NEGATE_PATH_FLAG"), "true");
    assert_eq!(r.get("INPUT_ROUNDS"), "4");
    assert!(r.output.contains("--analysis data-race,channel-safety"));
}

#[test]
fn repeated_and_comma_separated_profiles_are_equivalent() {
    let a = dry_run(&["--analysis", "toctou", "--analysis", "data-race"]);
    let b = dry_run(&["--analysis", "data-race,toctou"]);
    assert_eq!(a.get("ZORYA_ANALYSES"), "data-race,toctou");
    assert_eq!(a.get("ZORYA_ANALYSES"), b.get("ZORYA_ANALYSES"));
    assert_eq!(a.get("ZORYA_PLUGINS"), b.get("ZORYA_PLUGINS"));
}

#[test]
fn groups_expand_and_enable_the_oracles() {
    let r = dry_run(&["--analysis", "full"]);
    assert_eq!(
        r.get("ZORYA_ANALYSES"),
        "data-race,channel-safety,toctou,panic,memory-safety,arithmetic"
    );
    assert_eq!(r.get("ZORYA_PLUGINS"), "volos chancheck toctou");
    assert_eq!(r.get("ZORYA_MEM_SAFETY_ORACLES"), "1");
    assert_eq!(r.get("ZORYA_INT_ARITH_ORACLES"), "1");

    let r = dry_run(&["--analysis", "concurrency"]);
    assert_eq!(r.get("ZORYA_ANALYSES"), "data-race,channel-safety,toctou");
    assert_eq!(r.get("ZORYA_MEM_SAFETY_ORACLES"), "0");
}

#[test]
fn non_concurrency_profiles_load_no_plugin_and_run_once() {
    let r = dry_run(&["--analysis", "panic"]);
    assert!(r.ok, "{}", r.output);
    assert_eq!(r.get("ZORYA_PLUGINS"), "none");
    assert_eq!(r.get("INPUT_ROUNDS"), "0");
    assert_eq!(r.get("NEGATE_PATH_FLAG"), "true");
}

#[test]
fn explicit_flags_override_profiles_with_a_warning() {
    let r = dry_run(&[
        "--analysis",
        "channel-safety",
        "--no-negate-path-exploration",
        "--thread-scheduling",
        "main-only",
    ]);
    assert!(r.ok, "{}", r.output);
    assert_eq!(r.get("NEGATE_PATH_FLAG"), "false");
    assert_eq!(r.get("THREAD_SCHEDULING"), "main-only");
    assert!(r.output.contains("WARNING: --no-negate-path-exploration"));
    assert!(r.output.contains("WARNING: --thread-scheduling main-only"));
}

#[test]
fn explicit_plugins_and_rounds_add_to_the_profile() {
    let r = dry_run(&[
        "--analysis",
        "channel-safety",
        "--plugin",
        "toctou",
        "--max-input-rounds",
        "1",
    ]);
    assert_eq!(r.get("ZORYA_PLUGINS"), "toctou chancheck");
    assert_eq!(r.get("INPUT_ROUNDS"), "1");
}

#[test]
fn race_only_is_an_alias_of_data_race() {
    let r = dry_run(&["--race-only", "--arg", "1"]);
    assert!(r.ok, "{}", r.output);
    assert!(r.output.contains("--race-only is deprecated"));
    assert_eq!(r.get("ZORYA_ANALYSES"), "data-race");
    assert_eq!(r.get("ZORYA_PLUGINS"), "volos");
}

#[test]
fn arg_stops_at_analysis_flags() {
    let r = dry_run(&["--arg", "a", "b", "--analysis", "data-race"]);
    assert_eq!(r.get("ARGS"), "a b");
    assert_eq!(r.get("ZORYA_ANALYSES"), "data-race");
}

#[test]
fn invalid_profiles_are_rejected() {
    let r = dry_run(&["--analysis", "bogus"]);
    assert!(!r.ok);
    assert!(r.output.contains("Unknown analysis 'bogus'"));

    let r = dry_run(&["--analysis", "recursion", "panic"]);
    assert!(!r.ok);
    assert!(r.output.contains("run it on its own"));
}
