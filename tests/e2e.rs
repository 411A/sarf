//! End-to-end tests: drive the real `sarf` binary through init, fixture replay,
//! queries and report generation.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::float_cmp,
    clippy::missing_panics_doc
)]

mod common;

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn sarf_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_sarf"))
}

fn run(data_dir: &Path, args: &[&str]) -> Output {
    let output = Command::new(sarf_bin())
        .arg("--data-dir")
        .arg(data_dir)
        .args(args)
        .output()
        .expect("run sarf");
    assert!(
        output.status.success(),
        "sarf {args:?} failed: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn build_fixture(root: &Path) -> PathBuf {
    let log_path = root.join("logs/nginx-error.log");
    let mut log = String::new();
    let now = chrono::Local::now();
    for index in 0..6 {
        let _ = writeln!(
            log,
            "{} [error] upstream timed out while serving /search item {index}",
            (now - chrono::Duration::seconds(120 - index * 5)).format("%Y/%m/%d %H:%M:%S")
        );
    }
    common::write(root, "logs/nginx-error.log", &log);

    let mut busy = 0_u64;
    let mut nginx_usec = 0_u64;
    let mut worker_ticks = 0_u64;
    for cycle in 0..10_u64 {
        let dir = root.join(format!("cycle-{cycle:04}"));
        let spike = (5..=7).contains(&cycle);
        common::full_cycle(
            &dir,
            cycle,
            {
                busy += if spike { 12_000 } else { 400 };
                busy
            },
            {
                nginx_usec += if spike { 30_000_000 } else { 1_000_000 };
                nginx_usec
            },
        );
        worker_ticks += if spike { 3_000 } else { 100 };
        common::process_tree(
            &dir,
            200,
            "nginx",
            100,
            worker_ticks,
            20,
            20,
            1024,
            "/system.slice/nginx.service",
        );
        common::process_tree(
            &dir,
            300,
            "nginx",
            200,
            worker_ticks / 2,
            10,
            30,
            512,
            "/system.slice/nginx.service",
        );
    }
    log_path
}

#[test]
fn full_offline_forensics_workflow() {
    let root = common::temp_root("e2e");
    let log_path = build_fixture(&root);
    let data_dir = root.join("data/sarf-data");
    common::config_with_log(&root.join("data"), &log_path, 60);

    run(&data_dir, &["init"]);
    let output = run(
        &data_dir,
        &[
            "run",
            "--fixture-root",
            root.to_str().expect("utf8 fixture path"),
            "--cycles",
            "10",
            "--interval-secs",
            "60",
        ],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("simulated"), "stdout: {stdout}");
    assert!(stdout.contains("incidents"), "stdout: {stdout}");
    assert!(data_dir.join("sarf.db").is_file());

    let why = run(&data_dir, &["why", "--since", "1h", "--json"]);
    let windows: serde_json::Value = serde_json::from_slice(&why.stdout).expect("why JSON");
    assert!(windows.is_array());
    let windows = windows.as_array().expect("array");
    assert!(!windows.is_empty(), "expected at least one high/low window");

    let top = run(
        &data_dir,
        &["top", "--since", "1h", "--by", "cpu", "--json"],
    );
    let top: serde_json::Value = serde_json::from_slice(&top.stdout).expect("top JSON");
    assert!(top.is_array());
    assert!(
        top.as_array()
            .expect("array")
            .iter()
            .any(|row| row.to_string().contains("nginx")),
        "top: {top}"
    );

    let incidents = run(&data_dir, &["incidents", "--since", "1h", "--json"]);
    let incidents: serde_json::Value =
        serde_json::from_slice(&incidents.stdout).expect("incidents JSON");
    assert!(incidents.is_array());

    let logs = run(
        &data_dir,
        &["logs", "nginx-error", "--since", "1h", "--json"],
    );
    let logs: serde_json::Value = serde_json::from_slice(&logs.stdout).expect("logs JSON");
    assert!(
        logs.to_string().contains("timed out"),
        "recent fixture logs must be captured: {logs}"
    );

    let report_path = root.join("report.html");
    run(
        &data_dir,
        &[
            "report",
            "--since",
            "1h",
            "--output",
            report_path.to_str().expect("utf8 report path"),
        ],
    );
    let html = std::fs::read_to_string(&report_path).expect("read report");
    for required in [
        "<!doctype html>",
        "What happened",
        "Ranked contributors",
        "id=\"panel-timeline\"",
        "id=\"panel-coverage\"",
        "sarf-data",
        "nginx",
        "timed out",
    ] {
        assert!(html.contains(required), "report missing {required}");
    }
    assert!(!html.contains("http://"));
    assert!(!html.contains("https://"));
    assert!(!html.contains("<script src"));

    let status = run(&data_dir, &["status", "--json"]);
    let status: serde_json::Value = serde_json::from_slice(&status.stdout).expect("status JSON");
    assert!(status.get("database").is_some());
    assert!(status.get("counts").is_some());

    let doctor = run(&data_dir, &["doctor"]);
    assert!(String::from_utf8_lossy(&doctor.stdout).contains("SARF doctor"));

    let gaps = run(&data_dir, &["gaps", "--json"]);
    let gaps: serde_json::Value = serde_json::from_slice(&gaps.stdout).expect("gaps JSON");
    assert!(gaps.is_array());

    let capabilities = run(&data_dir, &["capabilities", "--json"]);
    let capabilities: serde_json::Value =
        serde_json::from_slice(&capabilities.stdout).expect("capabilities JSON");
    assert!(capabilities.is_array());

    let tools = run(&data_dir, &["tools", "list", "--json"]);
    let tools: serde_json::Value = serde_json::from_slice(&tools.stdout).expect("tools JSON");
    assert!(tools.to_string().contains("nginx"));

    let export_path = root.join("export.csv");
    run(
        &data_dir,
        &[
            "export",
            "--since",
            "1h",
            "--format",
            "csv",
            "--output",
            export_path.to_str().expect("utf8 export path"),
        ],
    );
    let csv = std::fs::read_to_string(&export_path).expect("csv");
    assert!(csv.starts_with("entity_id,kind,name"));
    assert!(csv.contains("nginx"));

    let cycle_root = root.join("cycle-0000");
    let benchmark = run(
        &data_dir,
        &[
            "benchmark",
            "--cycles",
            "2",
            "--fixture-root",
            cycle_root.to_str().expect("utf8 cycle path"),
        ],
    );
    assert!(String::from_utf8_lossy(&benchmark.stdout).contains("DB write throughput"));

    run(&data_dir, &["prune"]);

    let incidents = run(&data_dir, &["incidents", "--since", "1h", "--json"]);
    let incidents: serde_json::Value =
        serde_json::from_slice(&incidents.stdout).expect("incidents JSON");
    if let Some(first) = incidents.as_array().and_then(|items| items.first()) {
        let id = first.get("incident_id").and_then(serde_json::Value::as_i64);
        if let Some(id) = id {
            let show = run(&data_dir, &["show", &id.to_string(), "--json"]);
            let show: serde_json::Value = serde_json::from_slice(&show.stdout).expect("show JSON");
            assert!(show.get("incident").is_some());
        }
    }

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn report_command_supports_graph_alias_and_default_output() {
    let root = common::temp_root("e2e-alias");
    let log_path = build_fixture(&root);
    let data_dir = root.join("data/sarf-data");
    common::config_with_log(&root.join("data"), &log_path, 60);
    run(&data_dir, &["init"]);
    run(
        &data_dir,
        &[
            "run",
            "--fixture-root",
            root.to_str().expect("utf8 fixture path"),
            "--cycles",
            "4",
            "--interval-secs",
            "60",
        ],
    );
    let output = run(&data_dir, &["graph", "--since", "1h"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("report written:"), "stdout: {stdout}");
    let reports = data_dir.join("reports");
    let html_files: Vec<_> = std::fs::read_dir(&reports)
        .expect("reports dir")
        .flatten()
        .filter(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("html"))
        })
        .collect();
    assert_eq!(html_files.len(), 1);
    let _ = std::fs::remove_dir_all(root);
}
