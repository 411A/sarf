//! Measured performance/soak-style checks. Thresholds are deliberately generous
//! guards against unbounded behavior, not product promises. Run in release:
//! `cargo test --release --test perf -- --nocapture`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::float_cmp,
    clippy::missing_panics_doc
)]

mod common;

use std::time::Instant;

use sarf::catalog::Catalog;
use sarf::collect::process::{HostTiming, ProcessCollector};
use sarf::collect::SourceRoot;
use sarf::config::Config;
use sarf::model::{CpuTimes, HostSample, MemSnapshot};
use sarf::report::{self, ReportOptions};
use sarf::store::query::Window;
use sarf::store::{Store, WriteItem, WriteRecord};
use sarf::time::{ClockDomain, Stamps};

const PROCESSES: u32 = 2000;

#[test]
fn scan_two_thousand_processes_under_budget() {
    let root = common::temp_root("perf-processes");
    common::host_tree(&root, 10_000, 90_000, 4);
    for index in 0..PROCESSES {
        common::process_tree(
            &root,
            1000 + index,
            "worker",
            1,
            100 + u64::from(index),
            20,
            1000 + u64::from(index),
            128,
            "/system.slice/worker.service",
        );
    }
    let mut collector = ProcessCollector::new(
        SourceRoot::fixture(&root),
        "boot-perf",
        usize::try_from(PROCESSES).unwrap_or(2000),
        false,
        Catalog::embedded().expect("catalog"),
    );
    let stamps = Stamps::new(
        1_700_000_000_000_000_000,
        1_000_000_000,
        "boot-perf",
        ClockDomain::Simulated,
    );
    let started = Instant::now();
    let (cycle, _) = collector
        .scan(
            &stamps,
            HostTiming {
                uptime_secs: Some(10_000.0),
                boot_time_secs: Some(1_700_000_000),
                clock_ticks: 100,
            },
            20,
            false,
        )
        .expect("scan");
    let elapsed = started.elapsed();
    println!(
        "perf: scanned {} processes in {:.1} ms ({:.0} processes/s), {} samples",
        cycle.scanned,
        elapsed.as_secs_f64() * 1000.0,
        cycle.scanned as f64 / elapsed.as_secs_f64().max(1e-9),
        cycle.samples.len()
    );
    assert_eq!(cycle.scanned, PROCESSES as usize);
    assert!(cycle.samples.len() <= 20 * 3 + 16);
    assert!(
        elapsed.as_secs_f64() < 15.0,
        "process scan took {elapsed:?}, expected under 15s in this environment"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn database_write_throughput_is_at_least_five_thousand_rows_per_second() {
    let mut store = Store::open_in_memory().expect("store");
    store.migrate().expect("migrate");
    let rows = 20_000_u64;
    let started = Instant::now();
    for chunk_start in (0..rows).step_by(512) {
        let items: Vec<WriteItem> = (chunk_start..(chunk_start + 512).min(rows))
            .map(|index| {
                WriteItem::normal(WriteRecord::HostSample(HostSample {
                    stamps: Stamps::new(
                        1_700_000_000_000_000_000 + index as i64,
                        index as i64,
                        "boot-perf",
                        ClockDomain::Simulated,
                    ),
                    cpu: CpuTimes {
                        user: index,
                        idle: rows - index,
                        ..Default::default()
                    },
                    mem: MemSnapshot {
                        total: 1024,
                        available: Some(512),
                        ..Default::default()
                    },
                    ..Default::default()
                }))
            })
            .collect();
        store.write(&items).expect("write");
    }
    let elapsed = started.elapsed();
    let per_second = rows as f64 / elapsed.as_secs_f64().max(1e-9);
    println!(
        "perf: wrote {rows} host rows in {:.1} ms ({per_second:.0} rows/s)",
        elapsed.as_secs_f64() * 1000.0
    );
    assert!(
        per_second >= 1000.0,
        "write throughput {per_second:.0} rows/s below the 1000 rows/s guard"
    );
}

#[test]
fn report_generation_stays_bounded_and_fast() {
    let mut store = Store::open_in_memory().expect("store");
    store.migrate().expect("migrate");
    let base = 1_700_000_000_000_000_000_i64;
    let mut items = Vec::new();
    let mut user = 0_u64;
    let mut idle = 0_u64;
    for index in 0..600_i64 {
        user += 100 + (index % 7) as u64 * 10;
        idle += 900;
        items.push(WriteItem::normal(WriteRecord::HostSample(HostSample {
            stamps: Stamps::new(
                base + index * 1_000_000_000,
                index,
                "boot-report",
                ClockDomain::Simulated,
            ),
            cpu: CpuTimes {
                user,
                idle,
                ..Default::default()
            },
            mem: MemSnapshot {
                total: 1024 * 1024 * 1024,
                available: Some(512 * 1024 * 1024),
                ..Default::default()
            },
            ..Default::default()
        })));
    }
    store.write(&items).expect("seed");
    let options = ReportOptions::window(Window::new(base, base + 600_000_000_000 + 1));
    let started = Instant::now();
    let document = report::build(store.connection(), &Config::default(), &options).expect("build");
    let html = report::render_html(&document).expect("render");
    let elapsed = started.elapsed();
    println!(
        "perf: report build+render {:.1} ms, {} bytes, {} series points",
        elapsed.as_secs_f64() * 1000.0,
        html.len(),
        document.series.timestamps.len()
    );
    assert!(elapsed.as_secs_f64() < 10.0);
    assert!(html.len() < report::MAX_REPORT_BYTES);
    assert!(document.series.timestamps.len() <= 601);
}
