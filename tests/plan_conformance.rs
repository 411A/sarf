//! Plan/spec conformance: trace CLI surfaces, report views, integrations and the
//! required test/documentation pyramid to the implemented tree.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::missing_panics_doc)]

mod common;

use std::path::Path;

use clap::Parser;
use sarf::catalog::Catalog;
use sarf::cli::Cli;
use sarf::config::{Config, Toggle};

fn manifest() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn read(relative: &str) -> String {
    std::fs::read_to_string(manifest().join(relative))
        .unwrap_or_else(|err| panic!("read {relative}: {err}"))
}

#[test]
fn temporary_test_roots_do_not_collide() {
    let first = common::temp_root("collision");
    let second = common::temp_root("collision");
    assert_ne!(first, second, "parallel tests must not share a temp root");
    let _ = std::fs::remove_dir_all(first);
    let _ = std::fs::remove_dir_all(second);
}

#[test]
fn every_documented_command_parses() {
    let invocations: &[&[&str]] = &[
        &["sarf", "init"],
        &["sarf", "install"],
        &["sarf", "install", "--docker-group", "--start"],
        &["sarf", "install", "--no-systemd"],
        &["sarf", "run"],
        &["sarf", "run", "--cycles", "3", "--interval-secs", "5"],
        &["sarf", "run", "--fixture-root", "fixture"],
        &["sarf", "doctor"],
        &["sarf", "status"],
        &["sarf", "status", "--brief"],
        &["sarf", "capabilities"],
        &["sarf", "gaps"],
        &[
            "sarf", "top", "--since", "1h", "--by", "mem", "--limit", "5",
        ],
        &["sarf", "processes", "--since", "1h", "--filter", "nginx"],
        &["sarf", "tree", "--since", "1h", "--limit", "20"],
        &["sarf", "why", "--since", "1h", "--metric", "cpu"],
        &["sarf", "story", "--since", "1h", "--limit", "5"],
        &["sarf", "incidents", "--since", "24h"],
        &["sarf", "show", "1"],
        &[
            "sarf",
            "logs",
            "nginx-error",
            "--since",
            "1h",
            "--grep",
            "error",
        ],
        &["sarf", "report", "--since", "1h", "--output", "out.html"],
        &["sarf", "graph", "--since", "1h"],
        &["sarf", "export", "--format", "json"],
        &["sarf", "prune"],
        &["sarf", "peaks", "--since", "72h"],
        &["sarf", "peaks", "--containers", "--since", "72h"],
        &["sarf", "peaks", "--csv", "--containers", "--since", "24h"],
        &[
            "sarf",
            "top",
            "--containers",
            "--by",
            "cpu",
            "--limit",
            "10",
        ],
        &[
            "sarf",
            "peaks",
            "--stored",
            "--since",
            "72h",
            "--output",
            "peaks.json",
        ],
        &[
            "sarf",
            "profile",
            "--container",
            "utazbot_tgbot",
            "--seconds",
            "5",
        ],
        &[
            "sarf",
            "profile",
            "--pid",
            "1234",
            "--seconds",
            "5",
            "--hz",
            "99",
        ],
        &["sarf", "benchmark", "--cycles", "2"],
        &["sarf", "tools", "list"],
        &["sarf", "tools", "show", "nginx"],
        &["sarf", "tools", "search", "cloud"],
    ];
    for invocation in invocations {
        Cli::try_parse_from(*invocation)
            .unwrap_or_else(|err| panic!("parse {invocation:?}: {err}"));
    }
}

#[test]
fn report_template_has_all_required_views_and_offline_csp() {
    let template = read("src/report/assets/template.html");
    for required in [
        "id=\"panel-summary\"",
        "id=\"panel-windows\"",
        "id=\"panel-timeline\"",
        "id=\"panel-top\"",
        "id=\"panel-processes\"",
        "id=\"panel-containers\"",
        "id=\"panel-incidents\"",
        "id=\"panel-logs\"",
        "id=\"panel-coverage\"",
        "What happened",
        "__SARF_TITLE__",
        "__SARF_STYLE__",
        "__SARF_SCRIPT__",
        "__SARF_DATA__",
        "Content-Security-Policy",
        "default-src 'none'",
    ] {
        assert!(template.contains(required), "template missing {required}");
    }
    assert!(!template.contains("http://"));
    assert!(!template.contains("https://"));
    let style = read("src/report/assets/style.css");
    let script = read("src/report/assets/app.js");
    for asset in [&style, &script] {
        assert!(!asset.contains("http://"));
        assert!(!asset.contains("https://"));
    }
    assert!(script.contains("createTextNode") || script.contains("textContent"));
    assert!(script.contains("Association confidence"));
    assert!(script.contains("renderContainers"));
    assert!(script.contains("Unavailable"));
}

#[test]
fn integration_catalog_covers_required_tools_and_capabilities() {
    let catalog = Catalog::embedded().expect("catalog");
    for (id, capability) in [
        ("docker", "container_lifecycle"),
        ("nginx", "log_source"),
        ("cloudflared", "process_enrichment"),
        ("tmux", "session_topology"),
        ("zellij", "session_topology"),
        ("systemd", "service_manager_events"),
    ] {
        let tool = catalog.get(id).unwrap_or_else(|| panic!("missing {id}"));
        assert!(
            tool.capabilities.iter().any(|value| value == capability),
            "{id} missing capability {capability}"
        );
        assert!(!tool.executables.is_empty() || !tool.comm.is_empty());
    }
    let config = Config::default();
    for (name, toggle) in config.integration_toggles() {
        assert!(
            matches!(toggle, Toggle::Auto | Toggle::Enabled | Toggle::Disabled),
            "{name} has no valid toggle"
        );
    }
}

#[test]
fn required_test_pyramid_files_exist() {
    for relative in [
        "tests/policy.rs",
        "tests/plan_conformance.rs",
        "tests/integration_collectors.rs",
        "tests/integration_report.rs",
        "tests/e2e.rs",
        "tests/perf.rs",
        "tests/common/mod.rs",
    ] {
        assert!(manifest().join(relative).is_file(), "missing {relative}");
    }
    let collectors = read("tests/integration_collectors.rs");
    assert!(collectors.contains("docker::parse_ps_output"));
    assert!(collectors.contains("sessions::parse_tmux_panes"));
}

#[test]
fn release_and_operations_artifacts_exist() {
    for relative in [
        "README.md",
        "LICENSE",
        "docs/DECISIONS.md",
        "docs/DOCKER.md",
        "docs/TESTING.md",
        "docs/SPEC-TRACEABILITY.md",
        "deploy/sarf.service",
        "scripts/install.sh",
        "scripts/verify.sh",
        "scripts/verify.ps1",
        "Dockerfile",
        ".github/workflows/ci.yml",
        ".github/workflows/release.yml",
        "docs/RELEASING.md",
        "config/defaults.toml",
        "examples/demo_report.rs",
    ] {
        assert!(manifest().join(relative).is_file(), "missing {relative}");
    }
    let service = read("deploy/sarf.service");
    assert!(service.contains("ExecStart=/usr/local/bin/sarf run"));
    let installer = read("scripts/install.sh");
    assert!(
        installer.contains("--docker-group)"),
        "installer must parse --docker-group"
    );
    assert!(installer.contains("--unit)"));
    assert!(installer.contains("--full-observation)"));
    assert!(installer.contains("PrivateTmp=no"));
    assert!(
        installer.contains("systemctl restart sarf.service"),
        "installer must restart an existing service after replacing the binary"
    );
    assert!(service.contains("NoNewPrivileges=yes"));
    assert!(service.contains("ReadWritePaths="));
    assert!(!service.contains("Requires=docker"));
    assert!(!service.contains("After=docker"));
}

#[test]
fn units_and_causation_wording_are_explicit() {
    let report = read("src/report/mod.rs");
    assert!(report.contains("percent of one logical core"));
    assert!(report.contains("temporal association"));
    let analysis = read("src/analysis/mod.rs");
    assert!(analysis.contains("causation"));
    assert!(analysis.contains("temporal association"));
    let config = Config::default();
    assert_eq!(config.report.bucket_secs, 60);
    assert!(config.adaptive.incident_interval_ms < config.general.interval_secs * 1000);
}

#[test]
fn fixture_harness_builds_linux_shaped_trees() {
    let root = common::temp_root("plan");
    common::full_cycle(&root, 2, 50_000, 12_000);
    for relative in [
        "proc/stat",
        "proc/meminfo",
        "proc/pressure/cpu",
        "proc/net/dev",
        "proc/diskstats",
        "proc/100/stat",
        "proc/200/cgroup",
        "sys/fs/cgroup/system.slice/nginx.service/cpu.stat",
        "sys/fs/cgroup/docker/abcdef0123456789/memory.current",
    ] {
        assert!(root.join(relative).is_file(), "missing fixture {relative}");
    }
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn no_unsafe_code_outside_the_documented_clock_wrapper() {
    let time = read("src/time.rs");
    assert!(time.contains("clock_gettime"));
    let mut offenders = Vec::new();
    for entry in walk_rust(manifest().join("src")) {
        if entry.ends_with("src\\time.rs") || entry.ends_with("src/time.rs") {
            continue;
        }
        let text = std::fs::read_to_string(&entry).unwrap_or_default();
        if text.contains("unsafe {") {
            offenders.push(entry);
        }
    }
    assert!(
        offenders.is_empty(),
        "unsafe outside time.rs: {offenders:?}"
    );
}

fn walk_rust(dir: std::path::PathBuf) -> Vec<String> {
    let mut files = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return files;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            files.extend(walk_rust(path));
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path.display().to_string());
        }
    }
    files
}
