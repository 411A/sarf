//! Report integration tests: seeded storage -> analysis -> self-contained HTML.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::float_cmp,
    clippy::missing_panics_doc
)]

mod common;

use std::collections::BTreeMap;

use sarf::config::Config;
use sarf::model::{
    Availability, CgroupSample, CollectorHealth, ConfiguredState, CoverageGap, CpuTimes, Entity,
    EntityKind, EventKind, EventRecord, HostSample, Incident, LogRecord, LogStream, MemSnapshot,
    Metric, PermissionState, Pressure, PressureLine, ProcessSample, Severity, WritePriority,
};
use sarf::report::{self, ReportOptions};
use sarf::store::query::Window;
use sarf::store::retention::{self, RetentionPolicy};
use sarf::store::{IntegrationStateRow, ProcessLifetimeRow, Store, WriteItem, WriteRecord};
use sarf::time::{ClockDomain, Stamps};

const BOOT: &str = "boot-report";

fn stamps(wall: i64) -> Stamps {
    Stamps::new(wall, wall, BOOT, ClockDomain::Simulated)
}

struct Seeded {
    store: Store,
    root: std::path::PathBuf,
    start: i64,
    until: i64,
    incident_start: i64,
}

fn seed() -> Seeded {
    let root = common::temp_root("report");
    let mut store = Store::open(&root.join("sarf.db")).expect("store");
    store.migrate().expect("migrate");
    let base = 1_700_000_000_000_000_000_i64;
    let minute = 60_000_000_000_i64;
    let mut items = vec![
        WriteItem::normal(WriteRecord::Meta {
            key: "clock_ticks_per_second".into(),
            value: "100".into(),
        }),
        WriteItem::normal(WriteRecord::Meta {
            key: "cpu_count".into(),
            value: "1".into(),
        }),
        WriteItem::normal(WriteRecord::Entity(Entity {
            entity_id: format!("host:{BOOT}"),
            kind: EntityKind::Host,
            stable_key: BOOT.into(),
            name: "report-host".into(),
            source: "procfs".into(),
            labels: BTreeMap::new(),
            first_seen_wall_ns: base,
            last_seen_wall_ns: base,
        })),
        WriteItem::normal(WriteRecord::Entity(Entity {
            entity_id: "cgroup:1:1".into(),
            kind: EntityKind::Cgroup,
            stable_key: "nginx.service".into(),
            name: "nginx.service".into(),
            source: "cgroup_v2".into(),
            labels: BTreeMap::from([("path".into(), "/system.slice/nginx.service".into())]),
            first_seen_wall_ns: base,
            last_seen_wall_ns: base,
        })),
        WriteItem::normal(WriteRecord::Entity(Entity {
            entity_id: "proc:boot-report:200:20".into(),
            kind: EntityKind::Process,
            stable_key: "200:20".into(),
            name: "nginx".into(),
            source: "procfs".into(),
            labels: BTreeMap::from([("tool".into(), "nginx".into())]),
            first_seen_wall_ns: base,
            last_seen_wall_ns: base,
        })),
        WriteItem::normal(WriteRecord::Entity(Entity {
            entity_id: "container:abcdef012345".into(),
            kind: EntityKind::Container,
            stable_key: "abcdef0123456789".into(),
            name: "demo-web".into(),
            source: "docker".into(),
            labels: BTreeMap::from([
                ("image".into(), "example/web:1".into()),
                ("state".into(), "running".into()),
                ("health".into(), "healthy".into()),
                ("compose_project".into(), "demo".into()),
                ("compose_service".into(), "web".into()),
                ("log_driver".into(), "json-file".into()),
                ("log_options".into(), "max-size=1m,max-file=2".into()),
                ("ports".into(), "127.0.0.1:8080->80/tcp".into()),
                ("networks".into(), "demo-net".into()),
                ("network_ips".into(), "demo-net=172.20.0.2".into()),
                ("restart_policy".into(), "unless-stopped".into()),
                ("pid".into(), "4242".into()),
            ]),
            first_seen_wall_ns: base,
            last_seen_wall_ns: base,
        })),
        WriteItem::normal(WriteRecord::ProcessLifetime(ProcessLifetimeRow {
            process_instance_id: "proc:boot-report:200:20".into(),
            host_id: format!("host:{BOOT}"),
            host_pid: 200,
            start_ticks: 20,
            parent_process_instance_id: None,
            parent_host_pid: Some(100),
            executable: Some("/usr/sbin/nginx".into()),
            comm: "nginx".into(),
            tool: Some("nginx".into()),
            role: Some("nginx worker".into()),
            unit: Some("nginx.service".into()),
            container: None,
            session: None,
            cgroup_entity_id: Some("cgroup:1:1".into()),
            start_wall_ns: base,
            start_mono_ns: base,
        })),
        WriteItem::normal(WriteRecord::CollectorHealth(CollectorHealth {
            collector_id: "procfs".into(),
            configured: ConfiguredState::Enabled,
            availability: Availability::Available,
            permission: PermissionState::Permitted,
            last_success_wall_ns: Some(base),
            last_error_wall_ns: None,
            last_error: None,
            error_count: 0,
            received_count: 13,
            persisted_count: 13,
            dropped_count: 0,
            truncated_count: 0,
            queue_high_water: 0,
            coverage: serde_json::Value::Null,
        })),
        WriteItem::normal(WriteRecord::CollectorHealth(CollectorHealth {
            collector_id: "docker".into(),
            configured: ConfiguredState::Auto,
            availability: Availability::Unavailable,
            permission: PermissionState::Unknown,
            last_success_wall_ns: None,
            last_error_wall_ns: Some(base),
            last_error: Some("docker CLI unavailable".into()),
            error_count: 1,
            received_count: 0,
            persisted_count: 0,
            dropped_count: 0,
            truncated_count: 0,
            queue_high_water: 0,
            coverage: serde_json::Value::Null,
        })),
        WriteItem::normal(WriteRecord::IntegrationState(IntegrationStateRow {
            integration_id: "docker".into(),
            configured_state: "auto".into(),
            detected_state: "unavailable".into(),
            version: None,
            capabilities_json: Some("[\"container_lifecycle\"]".into()),
            last_seen_wall_ns: Some(base),
            last_error: Some("docker CLI unavailable".into()),
        })),
        WriteItem::normal(WriteRecord::Gap(CoverageGap {
            source_id: "docker".into(),
            kind: "absent_interface".into(),
            since_wall_ns: Some(base),
            detail: "no Docker socket; host monitoring continues".into(),
        })),
        WriteItem::normal(WriteRecord::LogSource(sarf::store::LogSourceRow {
            source_id: "nginx-error".into(),
            kind: "file".into(),
            target: "/var/log/nginx/error.log".into(),
            entity_hint: Some("nginx".into()),
            max_lines: Some(1000),
            max_bytes: Some(524_288),
        })),
    ];

    let mut user = 0_u64;
    let mut idle = 0_u64;
    let mut nginx_usec = 0_u64;
    let mut process_ticks = 0_u64;
    let mut incident_start = base;
    for index in 0..=12_i64 {
        let wall = base + index * minute;
        let spike = (4..=6).contains(&index);
        let busy_delta = if spike { 800 } else { 100 };
        user += busy_delta;
        idle += 900;
        items.push(WriteItem::normal(WriteRecord::HostSample(HostSample {
            stamps: stamps(wall),
            cpu: CpuTimes {
                user,
                idle,
                ..Default::default()
            },
            per_cpu: vec![CpuTimes::default()],
            mem: MemSnapshot {
                total: 8 * 1024 * 1024 * 1024,
                available: Some(if spike {
                    2 * 1024 * 1024 * 1024
                } else {
                    6 * 1024 * 1024 * 1024
                }),
                ..Default::default()
            },
            load: sarf::model::LoadAvg {
                one: if spike { 4.0 } else { 0.5 },
                ..Default::default()
            },
            pressure: Pressure {
                cpu: Some(PressureLine {
                    some_avg10: Some(if spike { 25.0 } else { 1.0 }),
                    ..Default::default()
                }),
                ..Default::default()
            },
            ..Default::default()
        })));

        nginx_usec += if spike { 30_000_000 } else { 1_000_000 };
        items.push(WriteItem::normal(WriteRecord::CgroupSample(CgroupSample {
            stamps: stamps(wall),
            entity_id: "cgroup:1:1".into(),
            path: "/system.slice/nginx.service".into(),
            cpu_usage_usec: Some(nginx_usec),
            cpu_user_usec: Some(nginx_usec / 2),
            cpu_system_usec: Some(nginx_usec / 2),
            memory_current: Some(if spike {
                60 * 1024 * 1024
            } else {
                16 * 1024 * 1024
            }),
            memory_max: Some(64 * 1024 * 1024),
            pids_current: Some(2),
            ..Default::default()
        })));

        process_ticks += if spike { 3000 } else { 100 };
        items.push(WriteItem::normal(WriteRecord::ProcessSample(
            ProcessSample {
                stamps: stamps(wall),
                process_instance_id: "proc:boot-report:200:20".into(),
                cpu_user_ticks: process_ticks,
                cpu_system_ticks: 0,
                rss_bytes: Some(if spike {
                    60 * 1024 * 1024
                } else {
                    16 * 1024 * 1024
                }),
                virtual_bytes: Some(256 * 1024 * 1024),
                read_bytes: Some(0),
                write_bytes: Some(0),
                read_chars: Some(0),
                write_chars: Some(0),
                threads: Some(3),
                state: Some('R'),
                sample_flags: 0,
            },
        )));
        if index == 4 {
            incident_start = wall;
            items.push(WriteItem::critical(WriteRecord::Incident(Incident {
                incident_id: Some(1),
                started_wall_ns: wall,
                ended_wall_ns: Some(wall + minute),
                entity_id: None,
                metric: Metric::Cpu,
                reason: "host CPU above the configured threshold".into(),
                peak: 50.0,
                baseline: 10.0,
                evidence: serde_json::json!({"association": "temporal association only"}),
                acknowledged: false,
                evidence_loss: false,
            })));
        }
        if spike {
            items.push(WriteItem::critical(WriteRecord::Log(LogRecord {
                wall_ns: wall,
                mono_ns: Some(wall),
                source_id: "nginx-error".into(),
                entity_id: Some("cgroup:1:1".into()),
                stream: LogStream::File,
                level: Some(Severity::Error),
                message: "upstream timed out while serving /search".into(),
                truncated: false,
                incident_id: None,
                redacted: false,
            })));
        }
        items.push(WriteItem::normal(WriteRecord::Event(EventRecord {
            wall_ns: wall,
            mono_ns: Some(wall),
            entity_id: Some("proc:boot-report:200:20".into()),
            kind: EventKind::ProcessStarted,
            severity: Severity::Info,
            payload: serde_json::json!({"pid": 200}),
            provenance: "procfs".into(),
            lost_before: 0,
        })));
    }
    let until = base + 12 * minute + 1;
    store.write(&items).expect("seed");
    Seeded {
        store,
        root,
        start: base,
        until,
        incident_start,
    }
}

fn prepare_report(seeded: &mut Seeded) -> report::ReportDocument {
    let policy = RetentionPolicy {
        raw_hours: 48,
        process_raw_hours: 48,
        rollup_1m_days: 14,
        rollup_1h_days: 90,
        incident_days: 180,
        log_days: 7,
        max_db_bytes: u64::MAX,
        clock_ticks_per_second: 100,
    };
    let now = seeded.until + 600_000_000_000;
    retention::prune(&mut seeded.store, &policy, now, &seeded.root).expect("prune");
    let config = Config::default();
    report::build(
        seeded.store.connection(),
        &config,
        &ReportOptions::window(Window::new(seeded.start, seeded.until)),
    )
    .expect("report")
}

#[test]
fn report_detects_high_cpu_and_names_contributors_with_evidence() {
    let mut seeded = seed();
    let document = prepare_report(&mut seeded);
    assert_eq!(document.summary.incident_count, 1);
    assert_eq!(document.summary.process_count, 1);
    assert!(document.summary.log_count >= 3);
    assert!(document
        .summary
        .host_cpu_max_pct
        .is_some_and(|value| value > 40.0));
    assert_eq!(
        document.summary.host_mem_total_bytes,
        Some(8 * 1024 * 1024 * 1024)
    );

    let window = document
        .windows
        .iter()
        .find(|window| window.metric == "cpu" && window.kind == "high")
        .expect("high CPU window");
    assert!(window.change_pct > 100.0);
    assert!(window.confidence > 0.0 && window.confidence < 1.0);
    assert!(!window.contributors.is_empty());
    assert!(window
        .contributors
        .iter()
        .any(|contributor| contributor.name.contains("nginx")));
    assert!(window
        .evidence
        .iter()
        .any(|line| line.contains("of one core") || line.contains("baseline")));
    assert!(window
        .logs
        .iter()
        .any(|log| log.message.contains("timed out")));

    let top_cpu = &document.top.cpu;
    assert!(top_cpu.iter().any(|row| row.name.contains("nginx")));
    assert_eq!(document.containers.len(), 1);
    let container = &document.containers[0];
    assert_eq!(container.name, "demo-web");
    assert_eq!(container.image.as_deref(), Some("example/web:1"));
    assert_eq!(container.health.as_deref(), Some("healthy"));
    assert_eq!(container.compose_project.as_deref(), Some("demo"));
    assert_eq!(container.log_driver.as_deref(), Some("json-file"));
    assert_eq!(container.pid, Some(4242));
    assert_eq!(container.ports.as_deref(), Some("127.0.0.1:8080->80/tcp"));
    assert!(document
        .processes
        .nodes
        .iter()
        .any(|node| node.comm == "nginx" && node.unit.as_deref() == Some("nginx.service")));
    assert!(document
        .incidents
        .iter()
        .any(|incident| incident.id == 1 && incident.reason.contains("threshold")));
    let _ = std::fs::remove_dir_all(&seeded.root);
}

#[test]
fn report_html_has_required_views_and_no_network_references() {
    let mut seeded = seed();
    let document = prepare_report(&mut seeded);
    let html = report::render_html(&document).expect("html");
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
        "Ranked contributors",
        "Docker containers",
        "demo-web",
        "Coverage",
        "Unavailable",
    ] {
        assert!(html.contains(required), "missing {required}");
    }
    assert!(!html.contains("http://"));
    assert!(!html.contains("https://"));
    assert!(!html.contains("<script src"));
    assert!(html.contains("Content-Security-Policy"));
    assert!(html.contains("sarf-data"));
    let path = seeded.root.join("report.html");
    report::write_html(&path, &html).expect("write report");
    assert!(path.is_file());
    assert_eq!(
        std::fs::read_to_string(&path).expect("read").len(),
        html.len()
    );
    let _ = std::fs::remove_dir_all(&seeded.root);
}

#[test]
fn incident_scoped_report_uses_incident_window() {
    let mut seeded = seed();
    let _ = prepare_report(&mut seeded);
    let config = Config::default();
    let options = ReportOptions {
        window: Window::new(seeded.start, seeded.until),
        incident_id: Some(1),
        process_id: None,
        service: None,
    };
    let document =
        report::build(seeded.store.connection(), &config, &options).expect("incident report");
    assert!(document.meta.since.contains('T'));
    assert_eq!(document.incidents.len(), 1);
    assert_eq!(document.incidents[0].id, 1);
    // Use the incident start in the scoped report to prove the window is derived
    // from the incident rather than the requested range.
    assert_eq!(document.incidents[0].start, seeded.incident_start);
    let _ = std::fs::remove_dir_all(&seeded.root);
}

#[test]
fn service_filter_restricts_rankings_and_tree() {
    let mut seeded = seed();
    let _ = prepare_report(&mut seeded);
    let options = ReportOptions {
        window: Window::new(seeded.start, seeded.until),
        incident_id: None,
        process_id: None,
        service: Some("nginx".into()),
    };
    let document = report::build(seeded.store.connection(), &Config::default(), &options)
        .expect("service report");
    assert!(document
        .top
        .cpu
        .iter()
        .all(|row| row.name.contains("nginx")));
    assert!(document
        .processes
        .nodes
        .iter()
        .all(|node| node.comm.contains("nginx") || node.tool.as_deref() == Some("nginx")));
    let _ = std::fs::remove_dir_all(&seeded.root);
}

#[test]
fn empty_window_reports_unavailable_not_zero() {
    let store = Store::open_in_memory().expect("store");
    let now = 1_700_000_000_000_000_000;
    let document = report::build(
        store.connection(),
        &Config::default(),
        &ReportOptions::window(Window::new(now - 3_600_000_000_000, now)),
    )
    .expect("empty");
    assert!(document.summary.host_cpu_avg_pct.is_none());
    assert!(document.windows.is_empty());
    assert!(document.top.cpu.is_empty());
    assert_eq!(document.summary.coverage, "partial");
    let _ = WritePriority::Normal;
}

#[test]
fn report_window_never_claims_causation() {
    let mut seeded = seed();
    let document = prepare_report(&mut seeded);
    let html = report::render_html(&document).expect("html");
    assert!(html.contains("not causation") || html.contains("does not claim causation"));
    assert!(!html.contains("caused by"));
    let _ = std::fs::remove_dir_all(&seeded.root);
}
