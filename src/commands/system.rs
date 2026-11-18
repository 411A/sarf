//! System inspection, initialization, daemon launch and maintenance commands.

use std::path::Path;

use serde::Serialize;

use crate::catalog::Catalog;
use crate::cli::RunArgs;
use crate::collect::cgroup::CgroupCollector;
use crate::collect::host::{HostCapabilities, HostCollector};
use crate::collect::process::{HostTiming, ProcessCollector};
use crate::collect::{HostFacts, SourceRoot};
use crate::commands::{fmt_bytes, fmt_span, fmt_time, print_json, print_table, Context};
use crate::config::Toggle;
use crate::daemon::{self, DaemonOptions};
use crate::error::Result;
use crate::model::{Availability, CollectorHealth};
use crate::store::query::{self, Window};
use crate::store::retention::RetentionPolicy;
use crate::store::{Store, WriteItem, WriteRecord};
use crate::time::{Clock, ClockDomain, Stamps, SystemClock};
use crate::VERSION;

#[derive(Debug, Clone, Serialize)]
struct Check {
    name: String,
    state: String,
    detail: String,
}

impl Check {
    fn new(name: impl Into<String>, state: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            state: state.into(),
            detail: detail.into(),
        }
    }
}

/// Initialize the data directory and database.
pub fn init(context: &mut Context, force: bool) -> Result<i32> {
    let created = context.data_dir.init(force)?;
    let mut store = context.open_write()?;
    store.migrate()?;
    let version = store.schema_version()?;
    let payload = serde_json::json!({
        "data_dir": context.data_dir.root(),
        "config": context.data_dir.config_path(),
        "database": context.data_dir.db_path(),
        "reports": context.data_dir.reports_dir(),
        "created_config": created,
        "schema_version": version,
        "next": "sarf doctor && sarf run",
    });
    if context.json {
        print_json(&payload)?;
    } else {
        println!("SARF {VERSION} initialized");
        println!("  data dir : {}", context.data_dir.root().display());
        println!("  config   : {}", context.data_dir.config_path().display());
        println!("  database : {}", context.data_dir.db_path().display());
        println!("  reports  : {}", context.data_dir.reports_dir().display());
        println!("  schema   : v{version}");
        if !created {
            println!("  config   : kept existing file (use --force to reset)");
        }
        println!("\nNext: sarf doctor && sarf run");
    }
    Ok(0)
}

/// Run the collection daemon.
pub fn run_daemon(context: &Context, args: &RunArgs) -> Result<i32> {
    let options = DaemonOptions {
        data_dir: context.data_dir.clone(),
        config: context.config.clone(),
        cycles: (args.cycles > 0).then_some(args.cycles),
        fixture_root: args.fixture_root.clone(),
        simulate: args.simulate,
        interval_override: args.interval_secs,
    };
    let report = daemon::run(options)?;
    let payload = serde_json::json!({
        "run_id": report.run_id,
        "cycles": report.cycles,
        "simulated": report.simulated,
        "host_samples": report.host_samples,
        "cgroup_samples": report.cgroup_samples,
        "processes_started": report.processes_started,
        "process_samples": report.process_samples,
        "logs": report.logs,
        "incidents": report.incidents,
        "elapsed_ms": report.elapsed.as_millis(),
        "writer": {
            "submitted": report.writer.submitted,
            "persisted": report.writer.persisted,
            "dropped_low": report.writer.dropped_low,
            "dropped_normal": report.writer.dropped_normal,
            "batches": report.writer.batches,
            "write_errors": report.writer.write_errors,
            "queue_high_water": report.writer.queue_high_water,
        },
        "database": context.data_dir.db_path(),
    });
    if context.json {
        print_json(&payload)?;
    } else {
        println!(
            "run {} finished after {} cycle(s) in {:.2}s{}",
            report.run_id,
            report.cycles,
            report.elapsed.as_secs_f64(),
            if report.simulated { " (simulated)" } else { "" }
        );
        println!(
            "  host samples    {}\n  cgroup samples  {}\n  process starts  {}\n  process samples {}\n  logs persisted  {}\n  incidents       {}",
            report.host_samples,
            report.cgroup_samples,
            report.processes_started,
            report.process_samples,
            report.logs,
            report.incidents
        );
        println!(
            "  writer          {} persisted, {} dropped, queue high-water {}",
            report.writer.persisted,
            report.writer.dropped_low + report.writer.dropped_normal,
            report.writer.queue_high_water
        );
        println!("\nNext: sarf why --since 1h && sarf report --since 1h");
    }
    Ok(0)
}

/// Diagnose the host and the data directory.
pub fn doctor(context: &Context) -> Result<i32> {
    let mut checks = Vec::new();
    checks.push(Check::new(
        "platform",
        if cfg!(target_os = "linux") {
            "ok"
        } else {
            "warn"
        },
        if cfg!(target_os = "linux") {
            "Linux host".to_string()
        } else {
            "Linux is the supported runtime; use --fixture-root for replay here".to_string()
        },
    ));
    let root = SourceRoot::real();
    checks.push(Check::new(
        "/proc",
        if root.has_procfs() { "ok" } else { "warn" },
        if root.has_procfs() {
            "stat and meminfo readable".to_string()
        } else {
            "no procfs at /proc".to_string()
        },
    ));
    match root.cgroup_root() {
        Some(path) => checks.push(Check::new(
            "cgroup v2",
            "ok",
            format!("mounted at {}", path.display()),
        )),
        None => checks.push(Check::new(
            "cgroup v2",
            "warn",
            "no cgroup2 mount; service totals unavailable".to_string(),
        )),
    }
    let caps = HostCapabilities::detect(&root);
    let missing = caps.missing();
    checks.push(Check::new(
        "optional /proc",
        if missing.is_empty() { "ok" } else { "warn" },
        if missing.is_empty() {
            "PSI, network, disk, load and uptime present".to_string()
        } else {
            format!("missing: {}", missing.join(", "))
        },
    ));
    checks.push(Check::new(
        "data directory",
        if context.data_dir.root().is_dir() {
            "ok"
        } else {
            "warn"
        },
        context.data_dir.root().display().to_string(),
    ));
    checks.push(Check::new(
        "database",
        if context.data_dir.db_path().is_file() {
            "ok"
        } else {
            "warn"
        },
        if context.data_dir.db_path().is_file() {
            format!(
                "{} ({})",
                context.data_dir.db_path().display(),
                fmt_bytes(Some(store_size(&context.data_dir)))
            )
        } else {
            "not initialized; run `sarf init`".to_string()
        },
    ));
    if context.data_dir.db_path().is_file() {
        match Store::open_read_only(&context.data_dir.db_path())
            .and_then(|store| store.schema_version())
        {
            Ok(version) => checks.push(Check::new(
                "schema",
                "ok",
                format!("user_version {version}"),
            )),
            Err(err) => checks.push(Check::new("schema", "fail", err.to_string())),
        }
    }
    for (name, program) in [
        ("docker", "docker"),
        ("tmux", "tmux"),
        ("zellij", "zellij"),
        ("systemd", "systemctl"),
    ] {
        checks.push(Check::new(
            name,
            "ok",
            crate::enrich::find_in_path(program).map_or_else(
                || format!("{program} not found in PATH"),
                |path| path.display().to_string(),
            ),
        ));
    }
    let docker_socket = Path::new("/var/run/docker.sock");
    checks.push(Check::new(
        "docker socket",
        if docker_socket.exists() { "ok" } else { "warn" },
        if docker_socket.exists() {
            format!(
                "{} present; Engine API needs read/write access (root-equivalent)",
                docker_socket.display()
            )
        } else {
            "no /var/run/docker.sock; Engine API unavailable, CLI fallback may still work"
                .to_string()
        },
    ));
    checks.push(Check::new(
        "process events",
        "warn",
        "connector/taskstats collectors are not implemented in v0.1; short-lived processes can be missed",
    ));
    checks.push(Check::new(
        "taskstats",
        "warn",
        "not implemented in v0.1; exit-time accounting unavailable",
    ));

    if context.json {
        print_json(&checks)?;
    } else {
        println!("SARF doctor — {VERSION}\n");
        let rows: Vec<Vec<String>> = checks
            .iter()
            .map(|check| {
                vec![
                    check.name.clone(),
                    check.state.to_uppercase(),
                    check.detail.clone(),
                ]
            })
            .collect();
        print_table(&["CHECK", "STATE", "DETAIL"], &rows);
        println!(
            "\nUnavailable is not zero: warnings describe reduced coverage, not failed collection."
        );
    }
    Ok(0)
}

fn store_size(data_dir: &crate::paths::DataDir) -> u64 {
    data_dir.usage_bytes().total()
}

/// Database and collector status.
pub fn status(context: &Context, brief: bool) -> Result<i32> {
    let store = match context.open_read() {
        Ok(store) => store,
        Err(err) => {
            if context.json {
                print_json(&serde_json::json!({"error": err.to_string()}))?;
            } else {
                println!("{err}");
                println!("Run `sarf init` and `sarf run` first.");
            }
            return Ok(1);
        }
    };
    let conn = store.connection();
    let stats = query::db_stats(conn)?;
    let runs = query::runs(conn, 5)?;
    let collectors = query::collectors(conn)?;
    let integrations = query::integrations(conn)?;
    let gaps = query::gaps(conn)?;
    let usage = context.data_dir.usage_bytes();
    let payload = serde_json::json!({
        "data_dir": context.data_dir.root(),
        "database": context.data_dir.db_path(),
        "database_bytes": usage.database,
        "wal_bytes": usage.wal,
        "shm_bytes": usage.shm,
        "reports_bytes": usage.reports,
        "total_bytes": usage.total(),
        "schema_version": store.schema_version()?,
        "counts": stats.counts,
        "earliest": stats.earliest_wall_ns,
        "latest": stats.latest_wall_ns,
        "latest_age_ns": stats.latest_wall_ns.map(|latest| context.now.saturating_sub(latest)),
        "stale": status_is_stale(stats.latest_wall_ns, context),
        "hostname": stats.hostname,
        "boot_id": stats.boot_id,
        "kernel": stats.kernel_release,
        "architecture": stats.architecture,
        "runs": runs,
        "collectors": collectors,
        "integrations": integrations,
        "open_gaps": gaps.iter().filter(|gap| gap.resolved_wall_ns.is_none()).count(),
    });
    if brief {
        // Compact, agent-oriented status: no collector or integration tables.
        let brief = serde_json::json!({
            "schema": "sarf.status",
            "v": 1,
            "hostname": stats.hostname,
            "kernel": stats.kernel_release,
            "architecture": stats.architecture,
            "schema_version": store.schema_version()?,
            "earliest": stats.earliest_wall_ns,
            "latest": stats.latest_wall_ns,
            "latest_age_ns": stats.latest_wall_ns.map(|latest| context.now.saturating_sub(latest)),
            "stale": status_is_stale(stats.latest_wall_ns, context),
            "database_bytes": usage.database,
            "wal_bytes": usage.wal,
            "total_bytes": usage.total(),
            "open_gaps": gaps.iter().filter(|gap| gap.resolved_wall_ns.is_none()).count(),
            "counts": stats.counts,
            "runs": runs,
        });
        print_json(&brief)?;
        return Ok(0);
    }
    if context.json {
        print_json(&payload)?;
        return Ok(0);
    }
    println!("SARF status\n");
    println!("  data dir  {}", context.data_dir.root().display());
    println!(
        "  storage   {} (db {} + wal {} + shm {} + reports {})",
        fmt_bytes(Some(usage.total())),
        fmt_bytes(Some(usage.database)),
        fmt_bytes(Some(usage.wal)),
        fmt_bytes(Some(usage.shm)),
        fmt_bytes(Some(usage.reports))
    );
    println!(
        "  host      {} / {} / {}",
        stats.hostname.as_deref().unwrap_or("-"),
        stats.kernel_release.as_deref().unwrap_or("-"),
        stats.architecture.as_deref().unwrap_or("-")
    );
    println!(
        "  range     {} .. {}",
        stats
            .earliest_wall_ns
            .map_or_else(|| "-".to_string(), fmt_time),
        stats
            .latest_wall_ns
            .map_or_else(|| "-".to_string(), fmt_time)
    );
    println!(
        "  sampled   {}",
        status_freshness(stats.latest_wall_ns, context)
    );
    println!("\nROWS");
    let rows: Vec<Vec<String>> = stats
        .counts
        .iter()
        .map(|(table, count)| vec![table.clone(), count.to_string()])
        .collect();
    print_table(&["TABLE", "ROWS"], &rows);
    println!("\nRUNS");
    let rows: Vec<Vec<String>> = runs
        .iter()
        .map(|run| {
            vec![
                run.run_id.to_string(),
                fmt_time(run.started_wall_ns),
                run.stopped_wall_ns
                    .map_or_else(|| "open".to_string(), fmt_time),
                run.version.clone(),
                if run.simulated { "simulated" } else { "live" }.to_string(),
            ]
        })
        .collect();
    print_table(&["ID", "STARTED", "STOPPED", "VERSION", "MODE"], &rows);
    println!("\nCOLLECTORS");
    let rows: Vec<Vec<String>> = collectors
        .iter()
        .map(|status| collector_row(&status.health))
        .collect();
    print_table(
        &[
            "COLLECTOR",
            "AVAILABILITY",
            "PERMISSION",
            "RECEIVED",
            "DROPPED",
            "ERROR",
        ],
        &rows,
    );
    if !integrations.is_empty() {
        println!("\nINTEGRATIONS");
        let rows: Vec<Vec<String>> = integrations
            .iter()
            .map(|integration| {
                vec![
                    integration.integration_id.clone(),
                    integration.configured_state.clone(),
                    integration.detected_state.clone(),
                    integration
                        .version
                        .clone()
                        .unwrap_or_else(|| "-".to_string()),
                ]
            })
            .collect();
        print_table(&["INTEGRATION", "CONFIGURED", "DETECTED", "VERSION"], &rows);
    }
    Ok(0)
}

fn collector_row(health: &CollectorHealth) -> Vec<String> {
    vec![
        health.collector_id.clone(),
        health.availability.as_str().to_string(),
        health.permission.as_str().to_string(),
        health.received_count.to_string(),
        health.dropped_count.to_string(),
        health.last_error.clone().unwrap_or_else(|| "-".to_string()),
    ]
}

/// Static capability probe.
pub fn capabilities(context: &Context) -> Result<i32> {
    let root = SourceRoot::real();
    let items = vec![
        capability(
            "procfs",
            root.has_procfs(),
            "host counters and process inventory",
        ),
        capability(
            "cgroup_v2",
            root.cgroup_root().is_some(),
            "service/container CPU, memory, I/O, PIDs and pressure",
        ),
        capability(
            "psi",
            root.proc_path("pressure/cpu").is_file(),
            "host CPU/memory/I/O pressure stall information",
        ),
        capability(
            "network_counters",
            root.proc_path("net/dev").is_file(),
            "host interface bytes/packets/errors/drops",
        ),
        capability(
            "disk_counters",
            root.proc_path("diskstats").is_file(),
            "whole-device read/write bytes",
        ),
        capability(
            "docker",
            crate::enrich::find_in_path("docker").is_some(),
            "container metadata/events/logs; bounded CLI fallback",
        ),
        capability(
            "docker_engine_api",
            Path::new("/var/run/docker.sock").exists(),
            "local Unix socket Engine API (versioned, bounded requests)",
        ),
        capability(
            "tmux",
            crate::enrich::find_in_path("tmux").is_some(),
            "pane PIDs and session labels via list-panes",
        ),
        capability(
            "zellij",
            crate::enrich::find_in_path("zellij").is_some(),
            "session-level detection only; no pane PID contract",
        ),
        capability(
            "systemd_mapping",
            root.proc_path("self/cgroup").is_file(),
            "unit inferred from cgroup path; D-Bus events planned",
        ),
        capability(
            "taskstats",
            false,
            "not implemented in v0.1; exit-time accounting unavailable",
        ),
        capability(
            "process_connector",
            false,
            "not implemented in v0.1; reconcile scans only",
        ),
        capability(
            "ebpf",
            false,
            "not implemented and never required for baseline",
        ),
        capability(
            "journald",
            false,
            "not implemented in v0.1; explicit file/Docker sources only",
        ),
        capability(
            "html_report",
            true,
            "self-contained offline HTML with inline CSS/JS",
        ),
    ];
    if context.json {
        print_json(&items)?;
    } else {
        let rows: Vec<Vec<String>> = items
            .iter()
            .map(|item| {
                vec![
                    item.name.clone(),
                    if item.available { "yes" } else { "no" }.to_string(),
                    item.detail.clone(),
                ]
            })
            .collect();
        print_table(&["CAPABILITY", "AVAILABLE", "DETAIL"], &rows);
    }
    Ok(0)
}

#[derive(Debug, Clone, Serialize)]
struct Capability {
    name: String,
    available: bool,
    detail: String,
}

fn capability(name: &str, available: bool, detail: &str) -> Capability {
    Capability {
        name: name.to_string(),
        available,
        detail: detail.to_string(),
    }
}

/// List coverage gaps.
pub fn gaps(context: &Context) -> Result<i32> {
    let store = context.open_read()?;
    let gaps = query::gaps(store.connection())?;
    if context.json {
        print_json(&gaps)?;
        return Ok(0);
    }
    let rows: Vec<Vec<String>> = gaps
        .iter()
        .map(|row| {
            vec![
                row.gap.source_id.clone(),
                row.gap.kind.clone(),
                row.gap
                    .since_wall_ns
                    .map_or_else(|| "-".to_string(), fmt_time),
                row.resolved_wall_ns
                    .map_or_else(|| "open".to_string(), fmt_time),
                row.gap.detail.clone(),
            ]
        })
        .collect();
    print_table(&["SOURCE", "KIND", "SINCE", "RESOLVED", "DETAIL"], &rows);
    Ok(0)
}

/// A status line that makes a stalled recorder obvious: `story` and `report`
/// silently see an empty window when nothing has been persisted for an hour.
fn status_freshness(latest_wall_ns: Option<i64>, context: &Context) -> String {
    let Some(latest) = latest_wall_ns else {
        return "no samples stored yet".to_string();
    };
    let age = fmt_span(latest, Some(context.now), context.now);
    let interval = context.config.general.interval_secs.max(1);
    if status_is_stale(Some(latest), context) {
        format!(
            "{age} ago — STALE (expected every {interval}s): the service is not persisting samples"
        )
    } else {
        format!("{age} ago")
    }
}

/// Whether the newest stored sample is older than three sampling intervals.
fn status_is_stale(latest_wall_ns: Option<i64>, context: &Context) -> bool {
    let Some(latest) = latest_wall_ns else {
        return false;
    };
    let limit = (context.config.general.interval_secs.max(1) as i64) * 3 * 1_000_000_000;
    context.now.saturating_sub(latest) > limit
}

/// Run one retention pass.
pub fn prune(context: &mut Context) -> Result<i32> {
    let mut store = context.open_write()?;
    let clock_ticks = query::clock_ticks_per_second(store.connection()).unwrap_or(100);
    let policy = RetentionPolicy::from_config(&context.config, clock_ticks);
    let report =
        crate::store::retention::prune(&mut store, &policy, context.now, context.data_dir.root())?;
    if context.json {
        print_json(&report)?;
    } else {
        println!("retention pass finished in {} ms", report.duration_ms);
        let rows = vec![
            vec![
                "minute rollups".to_string(),
                report.host_rollup_rows.to_string(),
            ],
            vec![
                "cgroup rollups".to_string(),
                report.cgroup_rollup_rows.to_string(),
            ],
            vec![
                "hour rollups".to_string(),
                report.hour_rollup_rows.to_string(),
            ],
            vec![
                "host samples deleted".to_string(),
                report.deleted_host_samples.to_string(),
            ],
            vec![
                "cgroup samples deleted".to_string(),
                report.deleted_cgroup_samples.to_string(),
            ],
            vec![
                "process samples deleted".to_string(),
                report.deleted_process_samples.to_string(),
            ],
            vec!["logs deleted".to_string(), report.deleted_logs.to_string()],
            vec![
                "events deleted".to_string(),
                report.deleted_events.to_string(),
            ],
            vec![
                "incidents deleted".to_string(),
                report.deleted_incidents.to_string(),
            ],
            vec![
                "total rows deleted".to_string(),
                report.total_deleted().to_string(),
            ],
        ];
        print_table(&["ACTION", "COUNT"], &rows);
        if report.vacuumed {
            println!(
                "\nreclaimed {} with VACUUM; incremental auto-vacuum is now enabled",
                fmt_bytes(Some(report.reclaimed_bytes))
            );
        }
        if !report.pressure_steps.is_empty() {
            println!("\ndisk guard:");
            for step in report.pressure_steps {
                println!("  {step}");
            }
        }
        if report.guard_stalled {
            println!(
                "\nThe database is over the configured budget but deletes cannot shrink it.\n\
                 Raise general.max_db_mb or reduce retention.raw_hours; do not keep pruning."
            );
        }
    }
    Ok(0)
}

/// Measure collection and write throughput.
pub fn benchmark(context: &Context, cycles: u64, fixture_root: Option<&Path>) -> Result<i32> {
    let cycles = cycles.clamp(1, 100_000);
    let root = fixture_root.map_or_else(SourceRoot::real, SourceRoot::fixture);
    if !root.has_procfs() {
        return Err(crate::error::Error::unavailable(
            "/proc",
            "benchmark needs a Linux /proc or --fixture-root",
        ));
    }
    let facts = HostFacts::read(&root);
    let catalog = Catalog::embedded()?;
    let mut process_collector = ProcessCollector::new(
        root.clone(),
        facts.short_boot_id().to_string(),
        context.config.process.max_processes,
        false,
        catalog,
    );
    let scan_started = std::time::Instant::now();
    let mut processes = 0_usize;
    let mut cgroups = 0_usize;
    for cycle in 0..cycles {
        let wall = 1_700_000_000_000_000_000 + cycle as i64 * 1_000_000_000;
        let stamps = Stamps::new(wall, wall, facts.short_boot_id(), ClockDomain::Simulated);
        let host = HostCollector::new(root.clone()).sample(stamps.clone())?;
        let cgroup = CgroupCollector::new(root.clone(), context.config.cgroup.max_cgroups)
            .sample(&stamps)?;
        cgroups = cgroups.saturating_add(cgroup.samples.len());
        let (cycle_report, _rates) = process_collector.scan(
            &stamps,
            HostTiming {
                uptime_secs: host.uptime_secs,
                boot_time_secs: host.boot_time_secs,
                clock_ticks: facts.clock_ticks,
            },
            context.config.process.top_n_persistence,
            false,
        )?;
        processes = processes.saturating_add(cycle_report.scanned);
    }
    let scan_elapsed = scan_started.elapsed();
    let scans = cycles.max(1) as f64;
    let processes_per_scan = processes as f64 / scans;
    let per_scan_ms = scan_elapsed.as_secs_f64() * 1000.0 / scans;

    // Measured database write throughput with a bounded batch size.
    let mut store = Store::open_in_memory()?;
    store.migrate()?;
    let rows = (cycles * 100).clamp(100, 200_000);
    let samples: Vec<crate::model::HostSample> = (0..rows)
        .map(|index| crate::model::HostSample {
            stamps: Stamps::new(
                1_700_000_000_000_000_000 + index as i64,
                index as i64,
                "bench",
                ClockDomain::Simulated,
            ),
            mem: crate::model::MemSnapshot {
                total: 1,
                available: Some(1),
                ..Default::default()
            },
            ..Default::default()
        })
        .collect();
    let write_started = std::time::Instant::now();
    for chunk in samples.chunks(512) {
        let items: Vec<WriteItem> = chunk
            .iter()
            .cloned()
            .map(|sample| WriteItem::normal(WriteRecord::HostSample(sample)))
            .collect();
        store.write(&items)?;
    }
    let write_elapsed = write_started.elapsed();
    let rows_per_second = if write_elapsed.as_secs_f64() > 0.0 {
        rows as f64 / write_elapsed.as_secs_f64()
    } else {
        0.0
    };
    let payload = serde_json::json!({
        "cycles": cycles,
        "processes_scanned": processes,
        "processes_per_scan": processes_per_scan,
        "cgroup_samples": cgroups,
        "scan_ms": scan_elapsed.as_secs_f64() * 1000.0,
        "scan_ms_per_cycle": per_scan_ms,
        "db_rows": rows,
        "db_write_ms": write_elapsed.as_secs_f64() * 1000.0,
        "db_rows_per_second": rows_per_second,
        "fixture_root": fixture_root,
    });
    if context.json {
        print_json(&payload)?;
    } else {
        println!("SARF benchmark (measured, not a guarantee)\n");
        println!("  cycles              {cycles}");
        println!("  processes / scan    {processes_per_scan:.1}");
        println!("  scan time / cycle   {per_scan_ms:.2} ms");
        println!("  cgroup samples      {cgroups}");
        println!("  DB rows written     {rows}");
        println!("  DB write throughput {rows_per_second:.0} rows/s");
        println!("\nMeasurements depend on host, kernel, storage and configuration.");
    }
    Ok(0)
}

/// Short availability label used by JSON output.
pub const fn availability_label(value: Availability) -> &'static str {
    value.as_str()
}

/// Render a configured toggle.
pub const fn toggle_label(toggle: Toggle) -> &'static str {
    toggle.as_str()
}

/// Query window helper for embedded callers.
pub fn window(context: &Context, since: &str) -> Result<Window> {
    context.window(since)
}

/// Timestamp helper shared by command modules.
pub fn now() -> i64 {
    SystemClock::new().wall_ns()
}
