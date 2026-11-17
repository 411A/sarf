//! Collector integration tests over realistic `/proc`, cgroup, Docker, tmux and log
//! fixtures. These exercise the same code paths as Linux collection without touching
//! the host.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::float_cmp,
    clippy::missing_panics_doc
)]

mod common;

use std::collections::HashMap;
use std::fmt::Write as _;

use sarf::catalog::Catalog;
use sarf::collect::cgroup::CgroupCollector;
use sarf::collect::host::HostCollector;
use sarf::collect::logs::{LogManager, LogPolicy, MAX_LINES_PER_POLL};
use sarf::collect::process::{HostTiming, ProcessCollector};
use sarf::collect::SourceRoot;
use sarf::config::{Config, LogSource, LogSourceKind};
use sarf::enrich::docker;
use sarf::enrich::sessions;
use sarf::model::HostSample;
use sarf::time::{ClockDomain, Stamps};

fn stamps(wall: i64, mono: i64) -> Stamps {
    Stamps::new(wall, mono, "boot-it", ClockDomain::Simulated)
}

#[test]
fn host_collector_reads_all_supported_counters() {
    let root = common::temp_root("host");
    common::full_cycle(&root, 0, 40_000, 0);
    let sample = HostCollector::new(SourceRoot::fixture(&root))
        .sample(stamps(1_000, 1_000))
        .expect("host sample");
    assert_eq!(sample.cpu.user, 0);
    assert_eq!(sample.cpu.system, 40_000);
    assert_eq!(sample.per_cpu.len(), 4);
    assert_eq!(sample.mem.total, 8_388_608 * 1024);
    assert_eq!(sample.mem.available, Some(6_291_456 * 1024));
    assert_eq!(sample.mem.used(), Some((8_388_608 - 6_291_456) * 1024));
    assert_eq!(sample.load.one, 1.25);
    assert_eq!(sample.pressure.cpu.expect("psi").some_avg10, Some(2.5));
    assert_eq!(sample.net["eth0"].rx_bytes, 1_000_000);
    assert_eq!(sample.disk["sda"].read_bytes, 2000 * 512);
    assert_eq!(sample.uptime_secs, Some(10_000.0));
    assert_eq!(sample.boot_time_secs, Some(1_700_000_000));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn host_cpu_delta_rejects_a_counter_reset() {
    let root = common::temp_root("reset");
    common::host_tree(&root, 10_000, 90_000, 2);
    let collector = HostCollector::new(SourceRoot::fixture(&root));
    let before = collector.sample(stamps(1, 1)).expect("before");
    common::host_tree(&root, 500, 90_000, 2);
    let after = collector.sample(stamps(2, 2)).expect("after");
    assert!(HostSample::cpu_usage_pct(&before, &after).is_none());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cgroup_discovery_tracks_identity_and_missing_controllers() {
    let root = common::temp_root("cgroups");
    common::full_cycle(&root, 0, 10_000, 5_000);
    common::write(&root, "sys/fs/cgroup/pids-only/pids.current", "3\n");
    let collector = CgroupCollector::new(SourceRoot::fixture(&root), 64);
    let first = collector.sample(&stamps(1, 1)).expect("first");
    let second = collector.sample(&stamps(2, 2)).expect("second");
    assert_eq!(first.samples.len(), 3, "nginx + docker + pids-only");
    let ids = |cycle: &sarf::collect::cgroup::CgroupCycle| {
        let mut values: Vec<String> = cycle
            .entities
            .iter()
            .map(|entity| entity.entity_id.clone())
            .collect();
        values.sort();
        values
    };
    assert_eq!(ids(&first), ids(&second), "inode identity is stable");
    let nginx = first
        .samples
        .iter()
        .find(|sample| sample.path.ends_with("nginx.service"))
        .expect("nginx cgroup");
    assert_eq!(nginx.cpu_usage_usec, Some(5_000));
    assert_eq!(nginx.memory_current, Some(16 * 1024 * 1024));
    assert_eq!(nginx.memory_max, Some(64 * 1024 * 1024));
    assert_eq!(nginx.pids_current, Some(2));
    let docker = first
        .samples
        .iter()
        .find(|sample| sample.path.contains("abcdef0123456789"))
        .expect("docker cgroup");
    assert_eq!(docker.cpu_usage_usec, Some(2_500));
    let pids_only = first
        .samples
        .iter()
        .find(|sample| sample.path.ends_with("pids-only"))
        .expect("pids-only");
    assert!(pids_only.cpu_usage_usec.is_none());
    assert!(pids_only.memory_current.is_none());
    assert_eq!(pids_only.pids_current, Some(3));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn process_inventory_identity_rates_sessions_and_pid_reuse() {
    let root = common::temp_root("processes");
    common::full_cycle(&root, 0, 10_000, 0);
    let mut collector = ProcessCollector::new(
        SourceRoot::fixture(&root),
        "boot-it",
        100,
        false,
        Catalog::embedded().expect("catalog"),
    );
    collector.set_sessions(HashMap::from([(100, "tmux main:%1".to_string())]));
    let timing = HostTiming {
        uptime_secs: Some(10_000.0),
        boot_time_secs: Some(1_700_000_000),
        clock_ticks: 100,
    };
    let (first, rates) = collector
        .scan(&stamps(1_000, 1_000_000_000), timing, 20, false)
        .expect("first scan");
    assert_eq!(first.scanned, 3);
    assert_eq!(first.starts.len(), 3);
    assert!(first.samples.len() >= 3);
    assert_eq!(rates.max(), 0.0);
    let worker = first
        .observations
        .iter()
        .find(|observation| observation.identity.pid == 200)
        .expect("worker");
    assert_eq!(
        worker
            .classification
            .as_ref()
            .and_then(|classification| classification.session.as_deref()),
        Some("tmux main:%1")
    );
    assert_eq!(
        worker
            .classification
            .as_ref()
            .and_then(|classification| classification.unit.as_deref()),
        Some("nginx.service")
    );

    common::full_cycle(&root, 0, 10_000, 100_000);
    let (second, rates) = collector
        .scan(&stamps(61_000, 61_000_000_000), timing, 20, false)
        .expect("second scan");
    assert_eq!(second.ends.len(), 0);
    let worker_rate = rates.get("proc:boot-it:200:20");
    assert!(worker_rate > 100.0, "rate {worker_rate}");
    assert!(second.samples.len() <= 20 * 3 + 16);

    // PID reuse: same PID, new start_ticks => new lifetime and an exit for the old one.
    common::write(
        &root,
        "proc/200/stat",
        &common::pid_stat(200, "newworker", 100, 1, 1, 9999, 64),
    );
    let (third, _) = collector
        .scan(&stamps(121_000, 121_000_000_000), timing, 20, false)
        .expect("third scan");
    assert_eq!(third.starts.len(), 1);
    assert_eq!(third.ends.len(), 1);
    assert_eq!(third.starts[0].observation.comm, "newworker");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn docker_and_session_parsers_handle_real_output_shapes() {
    let output = concat!(
        r#"{"ID":"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789","Names":"web-1","Image":"nginx:1.27","State":"running","Status":"Up 2 hours","Labels":"com.docker.compose.project=shop,com.docker.compose.service=web"}"#,
        "\n",
        "not json\n"
    );
    let containers = docker::parse_ps_output(output);
    assert_eq!(containers.len(), 1);
    assert_eq!(containers[0].short_id, "abcdef012345");
    assert_eq!(
        containers[0].compose(),
        Some(("shop".to_string(), "web".to_string()))
    );
    // Docker being absent is a normal, non-fatal state.
    let absent = docker::DockerDiscovery::default();
    assert!(!absent.available);
    assert_eq!(absent.containers.len(), 0);

    let panes = sessions::parse_tmux_panes("$0\tmain\t@1\teditor\t%2\t4242\tvim\n");
    assert_eq!(panes.len(), 1);
    assert_eq!(panes[0].label(), "tmux main:editor/%2");
    assert_eq!(sessions::parse_tmux_panes("garbage\n").len(), 0);
}

#[test]
fn log_follower_handles_append_rotation_truncation_and_bounds() {
    let root = common::temp_root("logs");
    common::write(&root, "nginx-error.log", "");
    let path = root.join("nginx-error.log");
    let mut config = Config::default();
    config.logs.sources = vec![LogSource {
        id: "nginx-error".into(),
        kind: LogSourceKind::File,
        path: Some(path.clone()),
        container: None,
        entity_hint: Some("nginx".into()),
        max_lines: Some(500),
        max_bytes: None,
    }];
    config.logs.read_bytes_per_cycle = 512 * 1024;
    let mut manager = LogManager::new(&config, LogPolicy::from_config(&config));
    manager.poll(&stamps(1, 1));

    common::append(
        &root,
        "nginx-error.log",
        b"2026/11/16 12:00:00 [error] upstream timed out\n",
    );
    let pulse = manager.poll(&stamps(2, 2));
    assert_eq!(pulse.received, 1);
    assert_eq!(pulse.records.len(), 1);
    assert_eq!(pulse.records[0].level, Some(sarf::model::Severity::Error));

    // Truncation is detected and the new content is read from the beginning.
    std::fs::write(&path, "2026/11/16 12:01:00 [warn] restarted\n").expect("truncate");
    let pulse = manager.poll(&stamps(3, 3));
    assert!(pulse
        .records
        .iter()
        .any(|record| record.message.contains("restarted")));

    // Flood: the ring and per-cycle line processing stay bounded.
    let mut flood = String::new();
    for index in 0..(MAX_LINES_PER_POLL * 4) {
        let _ = writeln!(flood, "2026/11/16 12:02:00 [info] line {index}");
    }
    common::append(&root, "nginx-error.log", flood.as_bytes());
    let pulse = manager.poll(&stamps(4, 4));
    assert!(pulse.received as usize <= MAX_LINES_PER_POLL);
    assert!(manager.health()[0].ring_lines <= 500);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn disk_aggregation_does_not_double_count_partitions() {
    let root = common::temp_root("disks");
    common::write(
        &root,
        "proc/diskstats",
        "8 0 sda 1 0 100 0 2 0 200 0 0 0 0\n8 1 sda1 1 0 90 0 2 0 190 0 0 0 0\n",
    );
    common::write(
        &root,
        "proc/stat",
        &common::proc_stat(1, 0, 1, 10, 0, 0, 0, 0, 1),
    );
    common::write(&root, "proc/meminfo", "MemTotal: 1 kB\n");
    let sample = HostCollector::new(SourceRoot::fixture(&root))
        .sample(stamps(1, 1))
        .expect("sample");
    let aggregated = sarf::collect::procfs::aggregate_disks(&sample.disk);
    assert_eq!(aggregated.read_bytes, 100 * 512);
    assert_eq!(aggregated.write_bytes, 200 * 512);
    let _ = std::fs::remove_dir_all(root);
}
