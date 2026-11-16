//! Generate a deterministic offline demo report without touching the host.
//!
//! ```text
//! cargo run --example demo_report -- sarf-data/reports/sample-report.html
//! ```

use std::collections::BTreeMap;

use sarf::config::Config;
use sarf::model::{
    CgroupSample, CpuTimes, Entity, EntityKind, HostSample, Incident, LogRecord, LogStream,
    MemSnapshot, Metric, Pressure, PressureLine, ProcessSample, Severity,
};
use sarf::report::{self, ReportOptions};
use sarf::store::query::Window;
use sarf::store::{ProcessLifetimeRow, Store, WriteItem, WriteRecord};
use sarf::time::{ClockDomain, Stamps};

fn stamps(wall: i64) -> Stamps {
    Stamps::new(wall, wall, "demo-boot", ClockDomain::Simulated)
}

fn main() -> sarf::Result<()> {
    let output = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "sarf-data/reports/sample-report.html".to_string());
    let mut store = Store::open_in_memory()?;
    store.migrate()?;
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
            entity_id: "proc:demo-boot:200:20".into(),
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
                ("image".into(), "example/web:1.0".into()),
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
            process_instance_id: "proc:demo-boot:200:20".into(),
            host_id: "host:demo-boot".into(),
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
    ];
    let mut user = 0_u64;
    let mut idle = 0_u64;
    let mut nginx_usec = 0_u64;
    let mut process_ticks = 0_u64;
    for index in 0..=12_i64 {
        let wall = base + index * minute;
        let spike = (5..=7).contains(&index);
        user += if spike { 800 } else { 100 };
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
                process_instance_id: "proc:demo-boot:200:20".into(),
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
        if index == 5 {
            items.push(WriteItem::critical(WriteRecord::Incident(Incident {
                incident_id: Some(1),
                started_wall_ns: wall,
                ended_wall_ns: Some(wall + minute),
                entity_id: None,
                metric: Metric::Cpu,
                reason: "host CPU above the configured threshold".into(),
                peak: 47.0,
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
        let bucket = wall - (wall % minute);
        store
            .connection()
            .execute(
                "INSERT INTO rollup_1m(bucket_wall_ns, entity_id, entity_kind, sample_count,
                cpu_avg_pct, cpu_max_pct, cpu_total_usec, memory_avg_bytes, memory_max_bytes,
                io_read_bytes, io_write_bytes, net_rx_bytes, net_tx_bytes,
                psi_cpu_max, psi_mem_max, psi_io_max)
             VALUES (?1, 'cgroup:1:1', 'cgroup', 1, ?2, ?2, ?3, ?4, ?4, 0, 0, 0, 0, 0, 0, 0)",
                rusqlite::params![
                    bucket,
                    if spike { 50.0 } else { 10.0 },
                    if spike { 30_000_000_i64 } else { 1_000_000_i64 },
                    if spike {
                        60 * 1024 * 1024_i64
                    } else {
                        16 * 1024 * 1024_i64
                    }
                ],
            )
            .map_err(|err| sarf::Error::Storage(format!("seed rollup: {err}")))?;
    }
    store.write(&items)?;
    let document = report::build(
        store.connection(),
        &Config::default(),
        &ReportOptions::window(Window::new(base, base + 12 * minute + 1)),
    )?;
    let html = report::render_html(&document)?;
    report::write_html(std::path::Path::new(&output), &html)?;
    println!(
        "wrote {} ({} bytes, {} windows, {} incidents)",
        output,
        html.len(),
        document.windows.len(),
        document.incidents.len()
    );
    Ok(())
}
