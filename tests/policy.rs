//! Policy tests: privacy, bounds, unavailable-not-zero, read-only collection,
//! offline report safety and evidence preservation.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::float_cmp,
    clippy::missing_panics_doc
)]

mod common;

use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::Path;

use sarf::catalog::Catalog;
use sarf::collect::cgroup::CgroupCollector;
use sarf::collect::host::HostCollector;
use sarf::collect::logs::{LogManager, LogPolicy};
use sarf::collect::process::{HostTiming, ProcessCollector};
use sarf::collect::SourceRoot;
use sarf::config::{Config, LogSource, LogSourceKind};
use sarf::model::{Incident, Metric, Severity};
use sarf::report::{self, ReportOptions};
use sarf::store::query::{self, Window};
use sarf::store::retention::{self, RetentionPolicy};
use sarf::store::{Store, WriteItem, WriteRecord};
use sarf::time::{ClockDomain, Stamps};

fn stamps(wall: i64) -> Stamps {
    Stamps::new(wall, wall, "boot-policy", ClockDomain::Simulated)
}

#[test]
fn default_configuration_is_private() {
    let config = Config::default();
    assert!(
        !config.process.store_arguments,
        "argv must be off by default"
    );
    assert!(
        !config.process.sample_all_processes,
        "raw per-process series must be opt-in"
    );
    assert_eq!(config.logs.persist_info_sample_percent, 0);
    assert!(config.logs.ring_lines <= 1_000_000);
    assert!(config.logs.ring_bytes_per_source <= 256 * 1024 * 1024);
    config.validate().expect("defaults are valid");
}

#[test]
fn process_cmdline_is_never_read_by_default() {
    let root = common::temp_root("privacy");
    common::full_cycle(&root, 0, 1_000, 2_000);
    std::fs::write(
        root.join("proc/200/cmdline"),
        b"--secret=topsecret\x00nginx\x00",
    )
    .expect("cmdline");
    let mut collector = ProcessCollector::new(
        SourceRoot::fixture(&root),
        "boot-policy",
        100,
        false,
        Catalog::embedded().expect("catalog"),
    );
    let (cycle, _) = collector
        .scan(&stamps(1), HostTiming::default(), 20, false)
        .expect("scan");
    let worker = cycle
        .observations
        .iter()
        .find(|observation| observation.identity.pid == 200)
        .expect("worker");
    assert!(worker.argv0.is_none(), "argv0 must not be captured");

    let mut opt_in = ProcessCollector::new(
        SourceRoot::fixture(&root),
        "boot-policy",
        100,
        true,
        Catalog::embedded().expect("catalog"),
    );
    let (cycle, _) = opt_in
        .scan(&stamps(2), HostTiming::default(), 20, false)
        .expect("scan");
    let worker = cycle
        .observations
        .iter()
        .find(|observation| observation.identity.pid == 200)
        .expect("worker");
    assert!(
        worker
            .argv0
            .as_deref()
            .is_some_and(|argv| argv.contains("topsecret")),
        "explicit opt-in must work"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn collection_is_read_only_on_the_fixture_tree() {
    let root = common::temp_root("readonly");
    common::full_cycle(&root, 0, 1_000, 2_000);
    common::write(&root, "logs/nginx-error.log", "");
    let before = common::snapshot(&root);
    let source = SourceRoot::fixture(&root);
    HostCollector::new(source.clone())
        .sample(stamps(1))
        .expect("host sample");
    CgroupCollector::new(source.clone(), 64)
        .sample(&stamps(1))
        .expect("cgroup sample");
    let mut process_collector = ProcessCollector::new(
        source,
        "boot-policy",
        100,
        false,
        Catalog::embedded().expect("catalog"),
    );
    process_collector
        .scan(&stamps(1), HostTiming::default(), 20, false)
        .expect("process scan");
    let mut config = Config::default();
    config.logs.sources = vec![LogSource {
        id: "nginx-error".into(),
        kind: LogSourceKind::File,
        path: Some(root.join("logs/nginx-error.log")),
        container: None,
        entity_hint: Some("nginx".into()),
        max_lines: None,
        max_bytes: None,
    }];
    let mut logs = LogManager::new(&config, LogPolicy::from_config(&config));
    logs.poll(&stamps(1));
    let after = common::snapshot(&root);
    assert_eq!(before, after, "collectors must never write to sources");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn unavailable_is_not_zero() {
    let root = common::temp_root("unavailable");
    common::write(
        &root,
        "proc/stat",
        &common::proc_stat(1, 0, 1, 1, 0, 0, 0, 0, 1),
    );
    let err = HostCollector::new(SourceRoot::fixture(&root))
        .sample(stamps(1))
        .expect_err("missing meminfo must fail");
    assert!(matches!(err, sarf::Error::Io { .. }));

    let store = Store::open_in_memory().expect("store");
    let config = Config::default();
    let now = 1_700_000_000_000_000_000;
    let document = report::build(
        store.connection(),
        &config,
        &ReportOptions::window(Window::new(now - 3_600_000_000_000, now)),
    )
    .expect("empty report");
    assert!(document.summary.host_cpu_avg_pct.is_none());
    assert!(document.summary.host_cpu_max_pct.is_none());
    assert!(document.summary.host_mem_used_max_bytes.is_none());
    assert_eq!(document.series.timestamps.len(), 0);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn log_rings_are_bounded_under_a_flood() {
    let root = common::temp_root("flood");
    let log_path = root.join("app.log");
    common::write(&root, "app.log", "");
    let mut config = Config::default();
    config.logs.sources = vec![LogSource {
        id: "flood".into(),
        kind: LogSourceKind::File,
        path: Some(log_path),
        container: None,
        entity_hint: None,
        max_lines: Some(20),
        max_bytes: Some(64 * 1024),
    }];
    config.logs.read_bytes_per_cycle = 1024 * 1024;
    let mut manager = LogManager::new(&config, LogPolicy::from_config(&config));
    manager.poll(&stamps(1));
    let mut flood = String::new();
    for index in 0..2000 {
        let _ = writeln!(flood, "line {index} ERROR flood");
    }
    common::append(&root, "app.log", flood.as_bytes());
    let pulse = manager.poll(&stamps(2));
    assert!(pulse.received > 0);
    let health = &manager.health()[0];
    assert!(health.ring_lines <= 20, "ring lines {}", health.ring_lines);
    assert!(health.ring_bytes <= 64 * 1024);
    assert!(health.dropped > 0, "flood drops must be counted");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn secrets_are_redacted_before_storage() {
    let (text, redacted) =
        sarf::collect::logs::redact("password=hunter2 Authorization: Bearer abc.def token: xyz");
    assert!(redacted);
    assert!(!text.contains("hunter2"));
    assert!(!text.contains("abc.def"));
    assert!(!text.contains("xyz"));
    assert!(text.contains("[REDACTED]"));
}

#[test]
fn html_report_is_offline_and_escapes_untrusted_text() {
    let mut store = Store::open_in_memory().expect("store");
    let now = 1_700_000_000_000_000_000;
    store
        .write(&[WriteItem::normal(WriteRecord::Log(
            sarf::model::LogRecord {
                wall_ns: now - 1,
                mono_ns: None,
                source_id: "fixture".into(),
                entity_id: None,
                stream: sarf::model::LogStream::File,
                level: Some(Severity::Error),
                message: "</script><script src=https://evil.invalid/x></script>".into(),
                truncated: false,
                incident_id: None,
                redacted: false,
            },
        ))])
        .expect("log");
    let document = report::build(
        store.connection(),
        &Config::default(),
        &ReportOptions::window(Window::new(now - 3_600_000_000_000, now)),
    )
    .expect("report");
    let html = report::render_html(&document).expect("html");
    // The log text itself may contain a URL; what matters is that it is inert data,
    // never a network reference or executable markup.
    assert!(!html.contains("<script src"));
    assert!(!html.contains("src=\"http"));
    assert!(!html.contains("@import"));
    assert!(!html.contains("url(http"));
    assert!(!html.contains("</script><script src"));
    assert!(html.contains("\\u003c/script"));
    assert!(html.contains("Content-Security-Policy"));
    assert!(html.contains("default-src 'none'"));
    assert!(html.contains("textContent") || html.contains("createTextNode"));
}

#[test]
fn incidents_survive_disk_pressure() {
    let root = common::temp_root("pressure");
    let db_path = root.join("sarf.db");
    let mut store = Store::open(&db_path).expect("store");
    store.migrate().expect("migrate");
    let now = 1_700_000_000_000_000_000;
    store
        .write(&[
            WriteItem::critical(WriteRecord::Incident(Incident {
                incident_id: Some(1),
                started_wall_ns: now - 86_400_000_000_000,
                ended_wall_ns: Some(now - 86_399_000_000_000),
                entity_id: None,
                metric: Metric::Cpu,
                reason: "test".into(),
                peak: 99.0,
                baseline: 1.0,
                evidence: serde_json::json!({"note": "keep"}),
                acknowledged: false,
                evidence_loss: false,
            })),
            WriteItem::low(WriteRecord::Log(sarf::model::LogRecord {
                wall_ns: now - 86_400_000_000_000,
                mono_ns: None,
                source_id: "old".into(),
                entity_id: None,
                stream: sarf::model::LogStream::File,
                level: Some(Severity::Info),
                message: "old info".into(),
                truncated: false,
                incident_id: None,
                redacted: false,
            })),
        ])
        .expect("seed");
    let policy = RetentionPolicy {
        raw_hours: 1,
        process_raw_hours: 1,
        rollup_1m_days: 1,
        rollup_1h_days: 2,
        incident_days: 180,
        log_days: 1,
        max_db_bytes: 1,
        clock_ticks_per_second: 100,
    };
    let report = retention::prune(&mut store, &policy, now, &root).expect("prune");
    assert_eq!(report.deleted_incidents, 0);
    let count: i64 = store
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM incidents WHERE incident_id = 1",
            [],
            |row| row.get(0),
        )
        .expect("count");
    assert_eq!(
        count, 1,
        "incidents must never be deleted by the disk guard"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn invalid_bounds_are_rejected() {
    let mut config = Config::default();
    config.general.interval_secs = 0;
    assert!(config.validate().is_err());
    let mut config = Config::default();
    config.logs.max_line_bytes = 1024 * 1024;
    config.logs.ring_bytes_per_source = 4096;
    assert!(config.validate().is_err());
    let mut config = Config::default();
    config.report.max_points = 1;
    assert!(config.validate().is_err());
}

#[test]
fn query_window_rejects_inverted_bounds_by_normalizing() {
    let window = Window::new(10, 5);
    assert_eq!(window.since, 5);
    assert_eq!(window.until, 10);
}

#[test]
fn cgroup_missing_controllers_stay_none() {
    let root = common::temp_root("cgroup-partial");
    common::write(&root, "sys/fs/cgroup/pids-only/pids.current", "7\n");
    common::write(&root, "sys/fs/cgroup/cgroup.controllers", "pids\n");
    let cycle = CgroupCollector::new(SourceRoot::fixture(&root), 16)
        .sample(&stamps(1))
        .expect("cgroup");
    let sample = cycle.samples.first().expect("node");
    assert_eq!(sample.cpu_usage_usec, None);
    assert_eq!(sample.memory_current, None);
    assert_eq!(sample.pids_current, Some(7));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn writer_refuses_unbounded_batches_and_counts_loss() {
    let store = Store::open_in_memory().expect("store");
    let writer = sarf::store::writer::Writer::spawn(store, 10).expect("writer");
    let items: Vec<WriteItem> = (0..100)
        .map(|index| {
            WriteItem::low(WriteRecord::Meta {
                key: format!("k{index}"),
                value: "v".into(),
            })
        })
        .collect();
    let outcome = writer.submit(items);
    match outcome {
        sarf::store::writer::SubmitOutcome::PartiallyDropped { low, normal } => {
            assert!(low >= 90, "low drops {low}");
            assert_eq!(normal, 0);
        }
        other => panic!("expected bounded drop, got {other:?}"),
    }
    let stats = writer.stats();
    assert!(stats.dropped_low >= 90);
    assert!(stats.queue_high_water <= 10);
    writer.shutdown().expect("shutdown");
}

#[test]
fn event_and_log_queries_are_bounded() {
    let store = Store::open_in_memory().expect("store");
    let now = 1_700_000_000_000_000_000;
    let mut filter = query::LogFilter::new(Window::new(now - 10, now));
    filter.limit = 5;
    let records = query::logs(store.connection(), &filter).expect("logs");
    assert!(records.len() <= 5);
    let _ = HashMap::<String, String>::new();
}

#[test]
fn fixture_paths_are_linux_shaped() {
    let root = common::temp_root("paths");
    common::full_cycle(&root, 0, 100, 100);
    assert!(Path::new(&root).join("proc/stat").is_file());
    assert!(root
        .join("sys/fs/cgroup/system.slice/nginx.service/cpu.stat")
        .is_file());
    let _ = std::fs::remove_dir_all(root);
}
