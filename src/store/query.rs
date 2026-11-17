//! Read-side queries used by the CLI, analysis and report generation.
//!
//! All queries are bounded: windows are explicit, log scans read at most `limit`
//! rows, series are produced at the requested resolution, and attribution buckets are
//! capped. Queries never write and never hold long transactions, so they cannot
//! starve WAL checkpoints on the writer (guide §11.6).
//!
//! Units are explicit throughout: CPU percentages are percent of **one core**
//! (they can exceed 100 for multi-core cgroups), memory is bytes, I/O is bytes, and
//! `*_bps` values are bytes per second.

use std::collections::{BTreeMap, HashMap};

use rusqlite::{params, Connection, OptionalExtension};

use crate::error::{Error, Result};
use crate::model::{
    Availability, CollectorHealth, ConfiguredState, CoverageGap, EntityKind, EventKind,
    EventRecord, Incident, LogRecord, LogStream, Metric, PermissionState, Severity,
};
use crate::time::format_wall_rfc3339;

use super::RowRead;

/// Half-open wall-clock window `[since, until)` in nanoseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    /// Inclusive start.
    pub since: i64,
    /// Exclusive end.
    pub until: i64,
}

impl Window {
    /// Create a window, normalizing inverted bounds.
    pub const fn new(since: i64, until: i64) -> Self {
        if since <= until {
            Self { since, until }
        } else {
            Self {
                since: until,
                until: since,
            }
        }
    }

    /// Window length in nanoseconds.
    pub const fn duration_ns(&self) -> i64 {
        self.until.saturating_sub(self.since)
    }

    /// Window length in seconds.
    pub fn duration_secs(&self) -> f64 {
        self.duration_ns() as f64 / 1e9
    }

    /// Whether the window is empty.
    pub const fn is_empty(&self) -> bool {
        self.until <= self.since
    }

    /// Overlap of `[start, end)` with this window, in nanoseconds.
    pub fn overlap_ns(&self, start: i64, end: i64) -> i64 {
        let low = start.max(self.since);
        let high = end.min(self.until);
        (high - low).max(0)
    }
}

/// Aggregated resource usage for one entity inside a window.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct EntityUsage {
    /// Entity id.
    pub entity_id: String,
    /// Entity kind.
    pub kind: EntityKind,
    /// Display name.
    pub name: String,
    /// Recognized tool.
    pub tool: Option<String>,
    /// Role/classification label.
    pub role: Option<String>,
    /// Container id, when known.
    pub container: Option<String>,
    /// Average CPU percent of one core over the covered interval.
    pub cpu_avg_pct: Option<f64>,
    /// Maximum observed CPU percent (minute resolution for cgroups).
    pub cpu_max_pct: Option<f64>,
    /// Total CPU microseconds consumed.
    pub cpu_total_usec: Option<u64>,
    /// Average memory bytes.
    pub memory_avg_bytes: Option<u64>,
    /// Maximum observed memory bytes.
    pub memory_max_bytes: Option<u64>,
    /// Storage bytes read.
    pub io_read_bytes: Option<u64>,
    /// Storage bytes written.
    pub io_write_bytes: Option<u64>,
    /// Network bytes received (host/containers only).
    pub net_rx_bytes: Option<u64>,
    /// Network bytes transmitted.
    pub net_tx_bytes: Option<u64>,
    /// Interval covered by source data, in nanoseconds (quality indicator).
    pub covered_ns: i64,
    /// Number of source samples/rollup rows used.
    pub sample_count: u64,
}

impl EntityUsage {
    /// Value of `metric` in its natural ranking unit.
    pub fn metric_value(&self, metric: Metric) -> f64 {
        match metric {
            Metric::Cpu => self.cpu_avg_pct.unwrap_or(0.0),
            Metric::Memory => self.memory_max_bytes.unwrap_or(0) as f64,
            Metric::IoRead => self.io_read_bytes.unwrap_or(0) as f64,
            Metric::IoWrite => self.io_write_bytes.unwrap_or(0) as f64,
            Metric::NetRx => self.net_rx_bytes.unwrap_or(0) as f64,
            Metric::NetTx => self.net_tx_bytes.unwrap_or(0) as f64,
            Metric::PsiCpu | Metric::PsiMemory | Metric::PsiIo | Metric::Load => 0.0,
        }
    }

    /// Share of a total, when the metric is additive.
    pub fn share_pct(&self, metric: Metric, total: f64) -> Option<f64> {
        if total <= 0.0 {
            return None;
        }
        Some(self.metric_value(metric) * 100.0 / total)
    }
}

/// One point of the host resource series.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct HostSeriesPoint {
    /// Wall clock.
    pub wall_ns: i64,
    /// CPU percent of one core (busy time, excluding idle and iowait).
    pub cpu_pct: Option<f64>,
    /// Used memory bytes.
    pub mem_used_bytes: Option<u64>,
    /// Used memory percent.
    pub mem_pct: Option<f64>,
    /// CPU pressure `some avg10`.
    pub psi_cpu: Option<f64>,
    /// Memory pressure `some avg10`.
    pub psi_memory: Option<f64>,
    /// I/O pressure `some avg10`.
    pub psi_io: Option<f64>,
    /// 1-minute load average.
    pub load1: Option<f64>,
    /// Network receive bytes/second.
    pub net_rx_bps: Option<f64>,
    /// Network transmit bytes/second.
    pub net_tx_bps: Option<f64>,
    /// Disk read bytes/second.
    pub disk_read_bps: Option<f64>,
    /// Disk write bytes/second.
    pub disk_write_bps: Option<f64>,
}

/// One point of an entity resource series.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EntitySeriesPoint {
    /// Wall clock.
    pub wall_ns: i64,
    /// CPU percent of one core.
    pub cpu_pct: Option<f64>,
    /// Memory bytes.
    pub memory_bytes: Option<u64>,
    /// I/O read bytes/second.
    pub io_read_bps: Option<f64>,
    /// I/O write bytes/second.
    pub io_write_bps: Option<f64>,
}

/// Host metrics aggregated into one attribution bucket.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct HostBucket {
    /// Average CPU percent.
    pub cpu_avg_pct: Option<f64>,
    /// Maximum instantaneous CPU percent.
    pub cpu_max_pct: Option<f64>,
    /// Average used memory bytes.
    pub mem_used_avg: Option<u64>,
    /// Maximum used memory bytes.
    pub mem_used_max: Option<u64>,
    /// CPU pressure `some` maximum.
    pub psi_cpu_max: Option<f64>,
    /// Memory pressure `some` maximum.
    pub psi_memory_max: Option<f64>,
    /// I/O pressure `some` maximum.
    pub psi_io_max: Option<f64>,
    /// 1-minute load average (average).
    pub load1_avg: Option<f64>,
    /// Network receive rate (bytes/second, average).
    pub net_rx_bps_avg: Option<f64>,
    /// Network transmit rate (bytes/second, average).
    pub net_tx_bps_avg: Option<f64>,
}

/// One entity's contribution inside an attribution bucket.
#[derive(Debug, Clone, PartialEq)]
pub struct BucketEntity {
    /// Entity id.
    pub entity_id: String,
    /// Entity kind.
    pub kind: EntityKind,
    /// Display name.
    pub name: String,
    /// Recognized tool.
    pub tool: Option<String>,
    /// Container id, when known.
    pub container: Option<String>,
    /// CPU microseconds consumed in the bucket.
    pub cpu_usec: u64,
    /// CPU percent of one core for the whole bucket.
    pub cpu_pct: Option<f64>,
    /// Peak memory bytes.
    pub memory_max: Option<u64>,
    /// Storage bytes read.
    pub io_read: u64,
    /// Storage bytes written.
    pub io_write: u64,
    /// Network bytes received in the bucket.
    pub net_rx: u64,
    /// Network bytes transmitted in the bucket.
    pub net_tx: u64,
}

impl BucketEntity {
    /// Value of `metric` for ranking inside a bucket.
    pub fn metric_value(&self, metric: Metric) -> f64 {
        match metric {
            Metric::Cpu => self.cpu_pct.unwrap_or(0.0),
            Metric::Memory => self.memory_max.unwrap_or(0) as f64,
            Metric::IoRead => self.io_read as f64,
            Metric::IoWrite => self.io_write as f64,
            Metric::NetRx => self.net_rx as f64,
            Metric::NetTx => self.net_tx as f64,
            _ => 0.0,
        }
    }
}

/// One attribution bucket: host context plus ranked entity contributions.
#[derive(Debug, Clone, PartialEq)]
pub struct Bucket {
    /// Bucket start, wall clock.
    pub start_wall_ns: i64,
    /// Bucket end, wall clock.
    pub end_wall_ns: i64,
    /// Host context.
    pub host: HostBucket,
    /// Ranked entities observed in the bucket.
    pub entities: Vec<BucketEntity>,
}

/// Filter for log queries.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogFilter {
    /// Time window.
    pub window: Option<Window>,
    /// Only records from this source.
    pub source_id: Option<String>,
    /// Minimum severity (inclusive).
    pub min_level: Option<Severity>,
    /// Case-insensitive substring match on the message.
    pub grep: Option<String>,
    /// Only records attached to this incident.
    pub incident_id: Option<i64>,
    /// Maximum rows returned (bounded; defaults to 200).
    pub limit: usize,
}

impl LogFilter {
    /// Filter with a bounded default limit.
    pub fn new(window: Window) -> Self {
        Self {
            window: Some(window),
            limit: 200,
            ..Default::default()
        }
    }
}

/// Filter for event queries.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventFilter {
    /// Time window.
    pub window: Option<Window>,
    /// Restrict to one entity.
    pub entity_id: Option<String>,
    /// Restrict to these kinds (empty means all).
    pub kinds: Vec<EventKind>,
    /// Maximum rows.
    pub limit: usize,
}

/// One process lifetime summary row.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct LifetimeSummary {
    /// Process entity id.
    pub process_instance_id: String,
    /// Host PID.
    pub host_pid: u32,
    /// Parent process entity id.
    pub parent_process_instance_id: Option<String>,
    /// Parent host PID.
    pub parent_host_pid: Option<u32>,
    /// Process name.
    pub comm: String,
    /// Executable path.
    pub executable: Option<String>,
    /// Recognized tool.
    pub tool: Option<String>,
    /// Role label.
    pub role: Option<String>,
    /// systemd unit.
    pub unit: Option<String>,
    /// Container.
    pub container: Option<String>,
    /// Session.
    pub session: Option<String>,
    /// Start wall clock.
    pub start_wall_ns: i64,
    /// End wall clock (`None` while alive or when the exit was missed).
    pub end_wall_ns: Option<i64>,
    /// Why the lifetime ended.
    pub end_reason: Option<String>,
}

/// One daemon run summary.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RunSummary {
    /// Run id.
    pub run_id: i64,
    /// Start wall clock.
    pub started_wall_ns: i64,
    /// Stop wall clock.
    pub stopped_wall_ns: Option<i64>,
    /// SARF version.
    pub version: String,
    /// Whether the run used simulated/fixture collection.
    pub simulated: bool,
    /// Optional note.
    pub note: Option<String>,
}

/// Collector health and coverage.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CollectorStatus {
    /// Parsed health record.
    pub health: CollectorHealth,
    /// Coverage details JSON.
    pub coverage: serde_json::Value,
}

/// Integration status row.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct IntegrationStatus {
    /// Integration id.
    pub integration_id: String,
    /// Configured state string.
    pub configured_state: String,
    /// Detected state string.
    pub detected_state: String,
    /// Version string.
    pub version: Option<String>,
    /// Capabilities.
    pub capabilities: Vec<String>,
    /// Last seen wall clock.
    pub last_seen_wall_ns: Option<i64>,
    /// Last error.
    pub last_error: Option<String>,
}

/// Coverage gap row.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GapRow {
    /// Gap description.
    pub gap: CoverageGap,
    /// Whether it has been resolved.
    pub resolved_wall_ns: Option<i64>,
}

/// Configured log source row.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct LogSourceStatus {
    /// Source id.
    pub source_id: String,
    /// Kind (`file`, `docker`).
    pub kind: String,
    /// Target description.
    pub target: String,
    /// Entity hint.
    pub entity_hint: Option<String>,
}

/// Row counts for one report window.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WindowCounts {
    /// Log records in the window.
    pub logs: u64,
    /// Events in the window.
    pub events: u64,
    /// Process lifetimes overlapping the window.
    pub processes: u64,
    /// Incidents overlapping the window.
    pub incidents: u64,
}

/// Count the bounded window rows used by reports without loading them.
pub fn window_counts(conn: &Connection, window: Window) -> Result<WindowCounts> {
    let count = |sql: &str| -> Result<u64> {
        let value: i64 = conn
            .query_row(sql, params![window.since, window.until], |row| row.get(0))
            .map_err(db_err)?;
        Ok(value.max(0) as u64)
    };
    Ok(WindowCounts {
        logs: count("SELECT COUNT(*) FROM logs WHERE wall_ts_ns >= ?1 AND wall_ts_ns < ?2")?,
        events: count("SELECT COUNT(*) FROM events WHERE wall_ts_ns >= ?1 AND wall_ts_ns < ?2")?,
        processes: count(
            "SELECT COUNT(*) FROM process_lifetimes
              WHERE start_wall_ns < ?2 AND (end_wall_ns IS NULL OR end_wall_ns >= ?1)",
        )?,
        incidents: count(
            "SELECT COUNT(*) FROM incidents
              WHERE started_wall_ns < ?2 AND (ended_wall_ns IS NULL OR ended_wall_ns >= ?1)",
        )?,
    })
}

/// Maximum installed memory reported by host samples in a window.
pub fn host_mem_total(conn: &Connection, window: Window) -> Result<Option<u64>> {
    let value: Option<i64> = conn
        .query_row(
            "SELECT MAX(mem_total_bytes) FROM host_samples
              WHERE wall_ts_ns >= ?1 AND wall_ts_ns < ?2 AND mem_total_bytes IS NOT NULL",
            params![window.since, window.until],
            |row| row.get(0),
        )
        .map_err(db_err)?;
    Ok(value.map(|value| value.max(0) as u64))
}

/// One Docker container entity row for reports and exports.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ContainerRow {
    /// Entity id.
    pub entity_id: String,
    /// Container name.
    pub name: String,
    /// Bounded labels (image, state, log driver, Compose, ports, mounts, ...).
    pub labels: BTreeMap<String, String>,
    /// First observation.
    pub first_seen_wall_ns: i64,
    /// Last observation.
    pub last_seen_wall_ns: i64,
}

/// Container entities, newest activity first, bounded.
pub fn containers(conn: &Connection, limit: usize) -> Result<Vec<ContainerRow>> {
    let mut statement = conn
        .prepare(
            "SELECT entity_id, name, labels_json, first_seen_wall_ns, last_seen_wall_ns
               FROM entities WHERE kind = 'container'
              ORDER BY last_seen_wall_ns DESC LIMIT ?1",
        )
        .map_err(db_err)?;
    let mut rows = statement
        .query(params![limit.clamp(1, 1000) as i64])
        .map_err(db_err)?;
    let mut containers = Vec::new();
    while let Some(row) = rows.next().map_err(db_err)? {
        let labels_json: Option<String> = row.get(2).map_err(db_err)?;
        let labels = labels_json
            .and_then(|text| serde_json::from_str::<BTreeMap<String, String>>(&text).ok())
            .unwrap_or_default();
        containers.push(ContainerRow {
            entity_id: row.get(0).map_err(db_err)?,
            name: row.get(1).map_err(db_err)?,
            labels,
            first_seen_wall_ns: row.get(3).map_err(db_err)?,
            last_seen_wall_ns: row.get(4).map_err(db_err)?,
        });
    }
    Ok(containers)
}

/// Database summary for `sarf status`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DbStats {
    /// Row counts by table name.
    pub counts: BTreeMap<String, i64>,
    /// Earliest stored wall-clock timestamp.
    pub earliest_wall_ns: Option<i64>,
    /// Latest stored wall-clock timestamp.
    pub latest_wall_ns: Option<i64>,
    /// Latest incident id.
    pub max_incident_id: i64,
    /// Host name.
    pub hostname: Option<String>,
    /// Boot id.
    pub boot_id: Option<String>,
    /// Kernel release.
    pub kernel_release: Option<String>,
    /// Architecture.
    pub architecture: Option<String>,
}

/// Map a `rusqlite` error into SARF's storage error.
#[allow(
    clippy::needless_pass_by_value,
    reason = "this is used as `map_err(db_err)`; `map_err` hands the owned error to the \
              mapper, so taking a reference would force a closure at every call site"
)]
fn db_err(err: rusqlite::Error) -> Error {
    Error::Storage(format!("query failed: {err}"))
}

fn parse_stream(text: &str) -> LogStream {
    match text {
        "stdout" => LogStream::Stdout,
        "stderr" => LogStream::Stderr,
        "journal" => LogStream::Journal,
        "app" => LogStream::App,
        _ => LogStream::File,
    }
}

fn tick_seconds(ticks: u64, hz: u64) -> f64 {
    ticks as f64 / hz.max(1) as f64
}

/// Table row counts and host metadata (bounded queries).
pub fn db_stats(conn: &Connection) -> Result<DbStats> {
    let mut stats = DbStats::default();
    for table in [
        "hosts",
        "runs",
        "entities",
        "relationships",
        "process_lifetimes",
        "host_samples",
        "cgroup_samples",
        "process_samples",
        "events",
        "logs",
        "incidents",
        "rollup_1m",
        "rollup_1h",
        "collector_health",
        "integration_state",
        "log_sources",
        "coverage_gaps",
    ] {
        let count: i64 = conn
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .map_err(db_err)?;
        stats.counts.insert(table.to_string(), count);
    }
    stats.earliest_wall_ns = conn
        .query_row(
            "SELECT MIN(ts) FROM (
                SELECT MIN(wall_ts_ns) AS ts FROM host_samples
                UNION ALL SELECT MIN(wall_ts_ns) FROM logs
                UNION ALL SELECT MIN(wall_ts_ns) FROM events
                UNION ALL SELECT MIN(started_wall_ns) FROM incidents
             )",
            [],
            |row| row.get::<_, Option<i64>>(0),
        )
        .map_err(db_err)?;
    stats.latest_wall_ns = conn
        .query_row(
            "SELECT MAX(ts) FROM (
                SELECT MAX(wall_ts_ns) AS ts FROM host_samples
                UNION ALL SELECT MAX(wall_ts_ns) FROM logs
                UNION ALL SELECT MAX(wall_ts_ns) FROM events
                UNION ALL SELECT MAX(started_wall_ns) FROM incidents
             )",
            [],
            |row| row.get::<_, Option<i64>>(0),
        )
        .map_err(db_err)?;
    stats.max_incident_id = conn
        .query_row(
            "SELECT COALESCE(MAX(incident_id), 0) FROM incidents",
            [],
            |row| row.get(0),
        )
        .map_err(db_err)?;
    if let Some((hostname, boot, kernel, arch)) = conn
        .query_row(
            "SELECT hostname, boot_id, kernel_release, architecture FROM hosts
              ORDER BY first_seen_wall_ns DESC LIMIT 1",
            [],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                ))
            },
        )
        .optional()
        .map_err(db_err)?
    {
        stats.hostname = hostname;
        stats.boot_id = boot;
        stats.kernel_release = kernel;
        stats.architecture = arch;
    }
    Ok(stats)
}

/// Raw host series at sample resolution.
pub fn host_series(conn: &Connection, window: Window) -> Result<Vec<HostSeriesPoint>> {
    #[derive(Clone)]
    struct Raw {
        wall: i64,
        total: u64,
        busy: u64,
        mem_total: Option<u64>,
        mem_available: Option<u64>,
        psi_cpu: Option<f64>,
        psi_memory: Option<f64>,
        psi_io: Option<f64>,
        load1: Option<f64>,
        net_rx: Option<u64>,
        net_tx: Option<u64>,
        disk_read: Option<u64>,
        disk_write: Option<u64>,
    }
    let mut statement = conn
        .prepare(
            "SELECT wall_ts_ns, cpu_user_ticks, cpu_nice_ticks, cpu_system_ticks,
                    cpu_idle_ticks, cpu_iowait_ticks, cpu_irq_ticks, cpu_softirq_ticks,
                    cpu_steal_ticks, mem_total_bytes, mem_available_bytes,
                    psi_cpu_some_avg10, psi_mem_some_avg10, psi_io_some_avg10,
                    load1, net_rx_bytes, net_tx_bytes, disk_read_bytes, disk_write_bytes
               FROM host_samples
              WHERE wall_ts_ns >= ?1 AND wall_ts_ns < ?2
              ORDER BY boot_id, mono_ts_ns",
        )
        .map_err(db_err)?;
    let mut rows = statement
        .query(params![window.since, window.until])
        .map_err(db_err)?;
    let mut points = Vec::new();
    let mut previous: Option<Raw> = None;
    let cpu_count = meta_value(conn, "cpu_count")
        .ok()
        .flatten()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(1)
        .max(1) as f64;
    while let Some(row) = rows.next().map_err(db_err)? {
        let user = row.u64_at(1)?;
        let nice = row.u64_at(2)?;
        let system = row.u64_at(3)?;
        let idle = row.u64_at(4)?;
        let iowait = row.u64_at(5)?;
        let irq = row.u64_at(6)?;
        let softirq = row.u64_at(7)?;
        let steal = row.u64_at(8)?;
        let total = user
            .saturating_add(nice)
            .saturating_add(system)
            .saturating_add(idle)
            .saturating_add(iowait)
            .saturating_add(irq)
            .saturating_add(softirq)
            .saturating_add(steal);
        let current = Raw {
            wall: row.get(0).map_err(db_err)?,
            total,
            busy: total.saturating_sub(idle).saturating_sub(iowait),
            mem_total: row.opt_u64_at(9)?,
            mem_available: row.opt_u64_at(10)?,
            psi_cpu: row.get(11).map_err(db_err)?,
            psi_memory: row.get(12).map_err(db_err)?,
            psi_io: row.get(13).map_err(db_err)?,
            load1: row.get(14).map_err(db_err)?,
            net_rx: row.opt_u64_at(15)?,
            net_tx: row.opt_u64_at(16)?,
            disk_read: row.opt_u64_at(17)?,
            disk_write: row.opt_u64_at(18)?,
        };
        let Some(previous) = previous.replace(current.clone()) else {
            continue;
        };
        let elapsed_s = (current.wall - previous.wall) as f64 / 1e9;
        let delta_total = current.total.saturating_sub(previous.total);
        let delta_busy = current.busy.saturating_sub(previous.busy);
        let cpu_pct = if delta_total > 0 {
            // /proc/stat aggregates all logical CPUs. Convert to the documented
            // "percent of one core" unit by multiplying by the CPU count.
            Some(delta_busy as f64 * 100.0 * cpu_count / delta_total as f64)
        } else {
            None
        };
        let mem_used = match (current.mem_total, current.mem_available) {
            (Some(total), Some(available)) if total > 0 => Some(total.saturating_sub(available)),
            _ => None,
        };
        let rate = |now: Option<u64>, before: Option<u64>| -> Option<f64> {
            if elapsed_s <= 0.0 {
                return None;
            }
            Some(now?.saturating_sub(before?) as f64 / elapsed_s)
        };
        points.push(HostSeriesPoint {
            wall_ns: current.wall,
            cpu_pct,
            mem_used_bytes: mem_used,
            mem_pct: mem_used
                .map(|used| used as f64 * 100.0 / current.mem_total.unwrap_or(0).max(1) as f64),
            psi_cpu: current.psi_cpu,
            psi_memory: current.psi_memory,
            psi_io: current.psi_io,
            load1: current.load1,
            net_rx_bps: rate(current.net_rx, previous.net_rx),
            net_tx_bps: rate(current.net_tx, previous.net_tx),
            disk_read_bps: rate(current.disk_read, previous.disk_read),
            disk_write_bps: rate(current.disk_write, previous.disk_write),
        });
    }
    Ok(points)
}

/// Host aggregate usage for a window.
pub fn host_usage(conn: &Connection, window: Window) -> Result<Option<EntityUsage>> {
    let points = host_series(conn, window)?;
    if points.is_empty() {
        return Ok(None);
    }
    let cpu_values: Vec<f64> = points.iter().filter_map(|point| point.cpu_pct).collect();
    let mem_values: Vec<u64> = points
        .iter()
        .filter_map(|point| point.mem_used_bytes)
        .collect();
    let cpu_avg = if cpu_values.is_empty() {
        None
    } else {
        Some(cpu_values.iter().sum::<f64>() / cpu_values.len() as f64)
    };
    let cpu_max = cpu_values.iter().copied().reduce(f64::max);
    let memory_avg = if mem_values.is_empty() {
        None
    } else {
        Some(mem_values.iter().sum::<u64>() / mem_values.len() as u64)
    };
    let first_wall = points.first().map_or(window.since, |point| point.wall_ns);
    let last_wall = points.last().map_or(window.until, |point| point.wall_ns);
    let covered_ns = last_wall.saturating_sub(first_wall).max(0);
    // Network counters are stored as cumulative bytes; `host_series` exposes rates.
    // Integrate each rate over its sampling interval so the window total is bytes,
    // not the meaningless sum of bytes-per-second values.
    let mut net_rx_bytes = 0.0;
    let mut net_tx_bytes = 0.0;
    let mut rx_seen = false;
    let mut tx_seen = false;
    for pair in points.windows(2) {
        let elapsed_s = (pair[1].wall_ns - pair[0].wall_ns) as f64 / 1e9;
        if elapsed_s <= 0.0 {
            continue;
        }
        if let Some(rate) = pair[1].net_rx_bps {
            rx_seen = true;
            net_rx_bytes = rate.max(0.0).mul_add(elapsed_s, net_rx_bytes);
        }
        if let Some(rate) = pair[1].net_tx_bps {
            tx_seen = true;
            net_tx_bytes = rate.max(0.0).mul_add(elapsed_s, net_tx_bytes);
        }
    }
    let net_rx = net_rx_bytes.round() as u64;
    let net_tx = net_tx_bytes.round() as u64;
    let name = conn
        .query_row(
            "SELECT COALESCE(hostname, 'host') FROM hosts ORDER BY first_seen_wall_ns DESC LIMIT 1",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(db_err)?
        .unwrap_or_else(|| "host".to_string());
    Ok(Some(EntityUsage {
        entity_id: "host:latest".to_string(),
        kind: EntityKind::Host,
        name,
        tool: None,
        role: None,
        container: None,
        cpu_avg_pct: cpu_avg,
        cpu_max_pct: cpu_max,
        cpu_total_usec: cpu_avg
            .map(|pct| (pct / 100.0 * covered_ns as f64 / 1_000.0).max(0.0) as u64),
        memory_avg_bytes: memory_avg,
        memory_max_bytes: mem_values.iter().max().copied(),
        io_read_bytes: None,
        io_write_bytes: None,
        net_rx_bytes: rx_seen.then_some(net_rx),
        net_tx_bytes: tx_seen.then_some(net_tx),
        covered_ns,
        sample_count: points.len() as u64,
    }))
}

/// cgroup and process usage aggregated over a window (not truncated; callers rank).
pub fn entity_usage(conn: &Connection, window: Window) -> Result<Vec<EntityUsage>> {
    let mut usage = cgroup_usage(conn, window)?;
    usage.extend(process_usage(conn, window)?);
    Ok(usage)
}

fn cgroup_usage(conn: &Connection, window: Window) -> Result<Vec<EntityUsage>> {
    #[derive(Default)]
    struct Acc {
        covered_ns: i64,
        samples: u64,
        cpu_total_usec: u64,
        cpu_avg_weighted: f64,
        cpu_weight: u64,
        cpu_max: Option<f64>,
        memory_sum: u64,
        memory_count: u64,
        memory_max: Option<u64>,
        io_read: u64,
        io_write: u64,
        net_rx: u64,
        net_tx: u64,
        net_seen: bool,
    }
    let mut accumulators: HashMap<String, Acc> = HashMap::new();
    {
        let mut statement = conn
            .prepare(
                "SELECT entity_id, bucket_wall_ns, sample_count, cpu_avg_pct, cpu_max_pct,
                        cpu_total_usec, memory_avg_bytes, memory_max_bytes,
                        io_read_bytes, io_write_bytes, net_rx_bytes, net_tx_bytes
                   FROM rollup_1m
                  WHERE bucket_wall_ns >= ?1 AND bucket_wall_ns < ?2
                    AND entity_kind = 'cgroup'",
            )
            .map_err(db_err)?;
        let mut rows = statement
            .query(params![window.since, window.until])
            .map_err(db_err)?;
        while let Some(row) = rows.next().map_err(db_err)? {
            let entity_id: String = row.get(0).map_err(db_err)?;
            let bucket: i64 = row.get(1).map_err(db_err)?;
            let samples = row
                .get::<_, Option<i64>>(2)
                .map_err(db_err)?
                .unwrap_or(0)
                .max(0) as u64;
            let cpu_avg: Option<f64> = row.get(3).map_err(db_err)?;
            let cpu_max: Option<f64> = row.get(4).map_err(db_err)?;
            let cpu_total: Option<i64> = row.get(5).map_err(db_err)?;
            let mem_avg: Option<i64> = row.get(6).map_err(db_err)?;
            let mem_max: Option<i64> = row.get(7).map_err(db_err)?;
            let io_read: Option<i64> = row.get(8).map_err(db_err)?;
            let io_write: Option<i64> = row.get(9).map_err(db_err)?;
            let net_rx: Option<i64> = row.get(10).map_err(db_err)?;
            let net_tx: Option<i64> = row.get(11).map_err(db_err)?;
            let overlap = window.overlap_ns(bucket, bucket + crate::store::retention::MINUTE_NS);
            if overlap <= 0 {
                continue;
            }
            let slot = accumulators.entry(entity_id).or_default();
            slot.covered_ns = slot.covered_ns.saturating_add(overlap);
            slot.samples = slot.samples.saturating_add(samples.max(1));
            slot.cpu_total_usec = slot
                .cpu_total_usec
                .saturating_add(cpu_total.unwrap_or(0).max(0) as u64);
            if let Some(avg) = cpu_avg {
                let weight = samples.max(1);
                slot.cpu_avg_weighted = avg.mul_add(weight as f64, slot.cpu_avg_weighted);
                slot.cpu_weight = slot.cpu_weight.saturating_add(weight);
            }
            if let Some(max) = cpu_max {
                slot.cpu_max = Some(slot.cpu_max.map_or(max, |current| current.max(max)));
            }
            if let Some(value) = mem_max {
                slot.memory_max = Some(slot.memory_max.unwrap_or(0).max(value.max(0) as u64));
            }
            if let Some(value) = mem_avg {
                slot.memory_sum = slot
                    .memory_sum
                    .saturating_add((value.max(0) as u64).saturating_mul(samples.max(1)));
                slot.memory_count = slot.memory_count.saturating_add(samples.max(1));
            }
            slot.io_read = slot
                .io_read
                .saturating_add(io_read.unwrap_or(0).max(0) as u64);
            slot.io_write = slot
                .io_write
                .saturating_add(io_write.unwrap_or(0).max(0) as u64);
            if net_rx.is_some() || net_tx.is_some() {
                slot.net_seen = true;
            }
            slot.net_rx = slot
                .net_rx
                .saturating_add(net_rx.unwrap_or(0).max(0) as u64);
            slot.net_tx = slot
                .net_tx
                .saturating_add(net_tx.unwrap_or(0).max(0) as u64);
        }
    }
    let metadata = entity_metadata(conn, EntityKind::Cgroup)?;
    let mut usage = Vec::with_capacity(accumulators.len());
    for (entity_id, acc) in accumulators {
        let cpu_avg_pct = if acc.covered_ns > 0 {
            // usec of CPU over ns of wall time -> percent of one core:
            // usec / (ns / 1_000) * 100 == usec * 100_000 / ns.
            Some(acc.cpu_total_usec as f64 * 100_000.0 / acc.covered_ns as f64)
        } else if acc.cpu_weight > 0 {
            Some(acc.cpu_avg_weighted / acc.cpu_weight as f64)
        } else {
            None
        };
        let (name, container, tool) = match metadata.get(&entity_id) {
            Some((name, labels)) => (
                name.clone(),
                labels
                    .get("container_id")
                    .cloned()
                    .or_else(|| container_from_cgroup_path(name)),
                labels.get("tool").cloned(),
            ),
            None => (entity_id.clone(), None, None),
        };
        usage.push(EntityUsage {
            entity_id,
            kind: EntityKind::Cgroup,
            name,
            tool,
            role: None,
            container,
            cpu_avg_pct,
            cpu_max_pct: acc.cpu_max,
            cpu_total_usec: Some(acc.cpu_total_usec),
            memory_avg_bytes: acc.memory_sum.checked_div(acc.memory_count),
            memory_max_bytes: acc.memory_max,
            io_read_bytes: Some(acc.io_read),
            io_write_bytes: Some(acc.io_write),
            net_rx_bytes: acc.net_seen.then_some(acc.net_rx),
            net_tx_bytes: acc.net_seen.then_some(acc.net_tx),
            covered_ns: acc.covered_ns,
            sample_count: acc.samples,
        });
    }
    Ok(usage)
}

fn container_from_cgroup_path(path: &str) -> Option<String> {
    // Docker: /system.slice/docker-<64 hex>.scope; containerd/Kubernetes:
    // .../cri-containerd-<id>.scope; CRI-O: crio-<id>.scope.
    for segment in path.split('/').rev() {
        let candidate = segment
            .strip_prefix("docker-")
            .or_else(|| segment.strip_prefix("cri-containerd-"))
            .or_else(|| segment.strip_prefix("crio-"))
            .unwrap_or(segment);
        let candidate = candidate.strip_suffix(".scope").unwrap_or(candidate);
        if candidate.len() >= 12 && candidate.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(candidate.to_string());
        }
    }
    None
}

type EntityMeta = HashMap<String, (String, HashMap<String, String>)>;

fn entity_metadata(conn: &Connection, kind: EntityKind) -> Result<EntityMeta> {
    let mut statement = conn
        .prepare("SELECT entity_id, name, labels_json FROM entities WHERE kind = ?1")
        .map_err(db_err)?;
    let mut rows = statement.query(params![kind.as_str()]).map_err(db_err)?;
    let mut map = EntityMeta::new();
    while let Some(row) = rows.next().map_err(db_err)? {
        let entity_id: String = row.get(0).map_err(db_err)?;
        let name: String = row.get(1).map_err(db_err)?;
        let labels_json: Option<String> = row.get(2).map_err(db_err)?;
        let labels: HashMap<String, String> = labels_json
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default();
        map.insert(entity_id, (name, labels));
    }
    Ok(map)
}

#[derive(Default)]
struct LifetimeMeta {
    comm: String,
    executable: Option<String>,
    tool: Option<String>,
    role: Option<String>,
    container: Option<String>,
}

fn lifetime_metadata(conn: &Connection, ids: &[String]) -> Result<HashMap<String, LifetimeMeta>> {
    let mut map = HashMap::new();
    for chunk in ids.chunks(400) {
        let placeholders = std::iter::repeat_n("?", chunk.len())
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "SELECT process_instance_id, comm, executable, tool, role, container
               FROM process_lifetimes WHERE process_instance_id IN ({placeholders})"
        );
        let mut statement = conn.prepare(&sql).map_err(db_err)?;
        let mut rows = statement
            .query(rusqlite::params_from_iter(chunk.iter()))
            .map_err(db_err)?;
        while let Some(row) = rows.next().map_err(db_err)? {
            map.insert(
                row.get(0).map_err(db_err)?,
                LifetimeMeta {
                    comm: row.get(1).map_err(db_err)?,
                    executable: row.get(2).map_err(db_err)?,
                    tool: row.get(3).map_err(db_err)?,
                    role: row.get(4).map_err(db_err)?,
                    container: row.get(5).map_err(db_err)?,
                },
            );
        }
    }
    Ok(map)
}

fn process_usage(conn: &Connection, window: Window) -> Result<Vec<EntityUsage>> {
    #[derive(Default)]
    struct Acc {
        samples: u64,
        first_wall: i64,
        last_wall: i64,
        first_ticks: Option<u64>,
        last_ticks: Option<u64>,
        memory_sum: u64,
        memory_count: u64,
        memory_max: u64,
        first_read: Option<u64>,
        last_read: Option<u64>,
        first_write: Option<u64>,
        last_write: Option<u64>,
    }
    let mut accumulators: HashMap<String, Acc> = HashMap::new();
    {
        let mut statement = conn
            .prepare(
                "SELECT process_instance_id, wall_ts_ns, cpu_user_ticks, cpu_system_ticks,
                        rss_bytes, read_bytes, write_bytes
                   FROM process_samples
                  WHERE wall_ts_ns >= ?1 AND wall_ts_ns < ?2
                  ORDER BY process_instance_id, mono_ts_ns",
            )
            .map_err(db_err)?;
        let mut rows = statement
            .query(params![window.since, window.until])
            .map_err(db_err)?;
        while let Some(row) = rows.next().map_err(db_err)? {
            let entity_id: String = row.get(0).map_err(db_err)?;
            let wall: i64 = row.get(1).map_err(db_err)?;
            let user: u64 = row
                .get::<_, Option<i64>>(2)
                .map_err(db_err)?
                .unwrap_or(0)
                .max(0) as u64;
            let system: u64 = row
                .get::<_, Option<i64>>(3)
                .map_err(db_err)?
                .unwrap_or(0)
                .max(0) as u64;
            let ticks = user.saturating_add(system);
            let rss: Option<i64> = row.get(4).map_err(db_err)?;
            let read: Option<i64> = row.get(5).map_err(db_err)?;
            let write: Option<i64> = row.get(6).map_err(db_err)?;
            let slot = accumulators.entry(entity_id).or_default();
            if slot.samples == 0 {
                slot.first_wall = wall;
                slot.first_ticks = Some(ticks);
                slot.first_read = read.map(|value| value.max(0) as u64);
                slot.first_write = write.map(|value| value.max(0) as u64);
            }
            slot.samples += 1;
            slot.last_wall = wall;
            slot.last_ticks = Some(ticks);
            if let Some(rss) = rss {
                if rss > 0 {
                    slot.memory_sum = slot.memory_sum.saturating_add(rss as u64);
                    slot.memory_count += 1;
                    slot.memory_max = slot.memory_max.max(rss as u64);
                }
            }
            if let Some(read) = read {
                slot.last_read = Some(read.max(0) as u64);
            }
            if let Some(write) = write {
                slot.last_write = Some(write.max(0) as u64);
            }
        }
    }
    let hz = clock_ticks_per_second(conn)?;
    let ids: Vec<String> = accumulators.keys().cloned().collect();
    let metadata = lifetime_metadata(conn, &ids)?;
    let mut usage = Vec::with_capacity(accumulators.len());
    for (entity_id, acc) in accumulators {
        if acc.samples == 0 {
            continue;
        }
        let covered_ns = acc.last_wall.saturating_sub(acc.first_wall).max(0);
        let covered_s = covered_ns as f64 / 1e9;
        let ticks = match (acc.first_ticks, acc.last_ticks) {
            (Some(first), Some(last)) => last.saturating_sub(first),
            _ => 0,
        };
        let cpu_total_usec = Some(ticks.saturating_mul(1_000_000) / hz.max(1));
        let cpu_avg_pct = if covered_s > 0.0 && acc.samples > 1 {
            Some(tick_seconds(ticks, hz) * 100.0 / covered_s)
        } else {
            None
        };
        let io_read = match (acc.first_read, acc.last_read) {
            (Some(first), Some(last)) => Some(last.saturating_sub(first)),
            _ => None,
        };
        let io_write = match (acc.first_write, acc.last_write) {
            (Some(first), Some(last)) => Some(last.saturating_sub(first)),
            _ => None,
        };
        let meta = metadata.get(&entity_id);
        usage.push(EntityUsage {
            entity_id,
            kind: EntityKind::Process,
            name: meta
                .and_then(|meta| meta.executable.clone())
                .or_else(|| meta.map(|meta| meta.comm.clone()))
                .unwrap_or_else(|| "unknown process".to_string()),
            tool: meta.and_then(|meta| meta.tool.clone()),
            role: meta.and_then(|meta| meta.role.clone()),
            container: meta.and_then(|meta| meta.container.clone()),
            cpu_avg_pct,
            cpu_max_pct: None,
            cpu_total_usec,
            memory_avg_bytes: acc.memory_sum.checked_div(acc.memory_count),
            memory_max_bytes: if acc.memory_max == 0 {
                None
            } else {
                Some(acc.memory_max)
            },
            io_read_bytes: io_read,
            io_write_bytes: io_write,
            net_rx_bytes: None,
            net_tx_bytes: None,
            covered_ns,
            sample_count: acc.samples,
        });
    }
    Ok(usage)
}

/// Clock ticks per second recorded at run start (Linux default: 100).
pub fn clock_ticks_per_second(conn: &Connection) -> Result<u64> {
    let value: Option<String> = conn
        .query_row(
            "SELECT value FROM meta WHERE key = 'clock_ticks_per_second'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(db_err)?;
    Ok(value
        .and_then(|text| text.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(100))
}

/// Entity resource series for a cgroup (minute resolution) or process (sample
/// resolution).
pub fn entity_series(
    conn: &Connection,
    window: Window,
    entity_id: &str,
) -> Result<Vec<EntitySeriesPoint>> {
    if entity_id.starts_with("cgroup:") {
        return cgroup_series(conn, window, entity_id);
    }
    let hz = clock_ticks_per_second(conn)?;
    let mut statement = conn
        .prepare(
            "SELECT wall_ts_ns, cpu_user_ticks, cpu_system_ticks, rss_bytes,
                    read_bytes, write_bytes
               FROM process_samples
              WHERE process_instance_id = ?1 AND wall_ts_ns >= ?2 AND wall_ts_ns < ?3
              ORDER BY mono_ts_ns",
        )
        .map_err(db_err)?;
    let mut rows = statement
        .query(params![entity_id, window.since, window.until])
        .map_err(db_err)?;
    let mut points = Vec::new();
    let mut previous: Option<(i64, u64, Option<u64>, Option<u64>)> = None;
    while let Some(row) = rows.next().map_err(db_err)? {
        let wall: i64 = row.get(0).map_err(db_err)?;
        let user: u64 = row
            .get::<_, Option<i64>>(1)
            .map_err(db_err)?
            .unwrap_or(0)
            .max(0) as u64;
        let system: u64 = row
            .get::<_, Option<i64>>(2)
            .map_err(db_err)?
            .unwrap_or(0)
            .max(0) as u64;
        let cpu = user.saturating_add(system);
        let rss: Option<i64> = row.get(3).map_err(db_err)?;
        let read: Option<i64> = row.get(4).map_err(db_err)?;
        let write: Option<i64> = row.get(5).map_err(db_err)?;
        let current = (
            wall,
            cpu,
            read.map(|value| value.max(0) as u64),
            write.map(|value| value.max(0) as u64),
        );
        if let Some((previous_wall, previous_cpu, previous_read, previous_write)) = previous {
            let elapsed_s = (wall - previous_wall) as f64 / 1e9;
            let cpu_pct = if elapsed_s > 0.0 {
                Some(tick_seconds(cpu.saturating_sub(previous_cpu), hz) * 100.0 / elapsed_s)
            } else {
                None
            };
            let rate = |now: Option<u64>, before: Option<u64>| -> Option<f64> {
                if elapsed_s <= 0.0 {
                    return None;
                }
                Some(now?.saturating_sub(before?) as f64 / elapsed_s)
            };
            points.push(EntitySeriesPoint {
                wall_ns: wall,
                cpu_pct,
                memory_bytes: rss.map(|value| value.max(0) as u64),
                io_read_bps: rate(current.2, previous_read),
                io_write_bps: rate(current.3, previous_write),
            });
        }
        previous = Some(current);
    }
    Ok(points)
}

fn cgroup_series(
    conn: &Connection,
    window: Window,
    entity_id: &str,
) -> Result<Vec<EntitySeriesPoint>> {
    let mut points = Vec::new();
    let mut statement = conn
        .prepare(
            "SELECT bucket_wall_ns, cpu_avg_pct, cpu_total_usec, memory_avg_bytes,
                    io_read_bytes, io_write_bytes, sample_count
               FROM rollup_1m
              WHERE entity_id = ?1 AND bucket_wall_ns >= ?2 AND bucket_wall_ns < ?3
              ORDER BY bucket_wall_ns",
        )
        .map_err(db_err)?;
    let mut rows = statement
        .query(params![entity_id, window.since, window.until])
        .map_err(db_err)?;
    let duration_s = crate::store::retention::MINUTE_NS as f64 / 1e9;
    while let Some(row) = rows.next().map_err(db_err)? {
        let bucket: i64 = row.get(0).map_err(db_err)?;
        let cpu_avg: Option<f64> = row.get(1).map_err(db_err)?;
        let cpu_total: Option<i64> = row.get(2).map_err(db_err)?;
        let mem: Option<i64> = row.get(3).map_err(db_err)?;
        let io_read: Option<i64> = row.get(4).map_err(db_err)?;
        let io_write: Option<i64> = row.get(5).map_err(db_err)?;
        let _samples: Option<i64> = row.get(6).map_err(db_err)?;
        points.push(EntitySeriesPoint {
            wall_ns: bucket,
            cpu_pct: cpu_avg.or_else(|| {
                cpu_total.map(|usec| usec.max(0) as f64 * 100.0 / (duration_s * 1_000_000.0))
            }),
            memory_bytes: mem.map(|value| value.max(0) as u64),
            io_read_bps: io_read.map(|value| value.max(0) as f64 / duration_s),
            io_write_bps: io_write.map(|value| value.max(0) as f64 / duration_s),
        });
    }
    Ok(points)
}

/// Build attribution buckets for `window`, ranked by CPU inside each bucket.
///
/// Process CPU is distributed across the buckets in which it was actually consumed
/// (delta between consecutive samples), not lumped into the last sample's bucket.
pub fn buckets(
    conn: &Connection,
    window: Window,
    bucket_ns: i64,
    max_entities: usize,
) -> Result<Vec<Bucket>> {
    let bucket_ns = bucket_ns.max(1_000_000_000);
    let estimated = (window.duration_ns() / bucket_ns + 2).max(1);
    if estimated > 4096 {
        return Err(Error::Capacity {
            what: "attribution buckets",
            limit: 4096,
        });
    }
    let bucket_start = |wall: i64| window.since + ((wall - window.since) / bucket_ns) * bucket_ns;
    let mut hosts: HashMap<i64, HostAcc> = HashMap::new();
    let mut entities: HashMap<(i64, String), BucketEntity> = HashMap::new();

    for point in host_series(conn, window)? {
        let start = bucket_start(point.wall_ns);
        let host = hosts.entry(start).or_default();
        if let Some(cpu) = point.cpu_pct {
            host.cpu_sum += cpu;
            host.cpu_count += 1;
            host.cpu_max = Some(host.cpu_max.map_or(cpu, |value| value.max(cpu)));
        }
        if let Some(mem) = point.mem_used_bytes {
            host.mem_sum = host.mem_sum.saturating_add(mem);
            host.mem_count += 1;
            host.mem_max = Some(host.mem_max.map_or(mem, |value| value.max(mem)));
        }
        if let Some(psi) = point.psi_cpu {
            host.psi_cpu_max = Some(host.psi_cpu_max.map_or(psi, |value| value.max(psi)));
        }
        if let Some(psi) = point.psi_memory {
            host.psi_memory_max = Some(host.psi_memory_max.map_or(psi, |value| value.max(psi)));
        }
        if let Some(psi) = point.psi_io {
            host.psi_io_max = Some(host.psi_io_max.map_or(psi, |value| value.max(psi)));
        }
        if let Some(load) = point.load1 {
            host.load_sum += load;
            host.load_count += 1;
        }
        if let Some(rate) = point.net_rx_bps {
            host.net_rx_sum += rate;
            host.net_rx_count += 1;
        }
        if let Some(rate) = point.net_tx_bps {
            host.net_tx_sum += rate;
            host.net_tx_count += 1;
        }
    }

    let cgroup_names = entity_metadata(conn, EntityKind::Cgroup)?;
    {
        let mut statement = conn
            .prepare(
                "SELECT entity_id, bucket_wall_ns, cpu_total_usec, memory_max_bytes,
                        io_read_bytes, io_write_bytes, net_rx_bytes, net_tx_bytes
                   FROM rollup_1m
                  WHERE bucket_wall_ns >= ?1 AND bucket_wall_ns < ?2
                    AND entity_kind = 'cgroup'",
            )
            .map_err(db_err)?;
        let mut rows = statement
            .query(params![window.since, window.until])
            .map_err(db_err)?;
        let bucket_s = bucket_ns as f64 / 1e9;
        while let Some(row) = rows.next().map_err(db_err)? {
            let entity_id: String = row.get(0).map_err(db_err)?;
            let wall: i64 = row.get(1).map_err(db_err)?;
            let cpu_total: Option<i64> = row.get(2).map_err(db_err)?;
            let mem: Option<i64> = row.get(3).map_err(db_err)?;
            let io_read: Option<i64> = row.get(4).map_err(db_err)?;
            let io_write: Option<i64> = row.get(5).map_err(db_err)?;
            let net_rx: Option<i64> = row.get(6).map_err(db_err)?;
            let net_tx: Option<i64> = row.get(7).map_err(db_err)?;
            let start = bucket_start(wall);
            let cpu_usec = cpu_total.unwrap_or(0).max(0) as u64;
            let (name, container) = match cgroup_names.get(&entity_id) {
                Some((name, labels)) => (
                    name.clone(),
                    labels
                        .get("container_id")
                        .cloned()
                        .or_else(|| container_from_cgroup_path(name)),
                ),
                None => (entity_id.clone(), None),
            };
            merge_entity(
                &mut entities,
                BucketEntity {
                    entity_id,
                    kind: EntityKind::Cgroup,
                    name,
                    tool: None,
                    container,
                    cpu_usec,
                    cpu_pct: Some(cpu_usec as f64 * 100.0 / (bucket_s * 1_000_000.0)),
                    memory_max: mem.map(|value| value.max(0) as u64),
                    io_read: io_read.unwrap_or(0).max(0) as u64,
                    io_write: io_write.unwrap_or(0).max(0) as u64,
                    net_rx: net_rx.unwrap_or(0).max(0) as u64,
                    net_tx: net_tx.unwrap_or(0).max(0) as u64,
                },
                start,
            );
        }
    }

    // Process contributions, distributed across buckets by sample interval.
    {
        let mut statement = conn
            .prepare(
                "SELECT process_instance_id, wall_ts_ns, cpu_user_ticks, cpu_system_ticks,
                        rss_bytes, read_bytes, write_bytes
                   FROM process_samples
                  WHERE wall_ts_ns >= ?1 AND wall_ts_ns < ?2
                  ORDER BY process_instance_id, mono_ts_ns",
            )
            .map_err(db_err)?;
        let mut rows = statement
            .query(params![window.since, window.until])
            .map_err(db_err)?;
        let hz = clock_ticks_per_second(conn)?;
        let bucket_s = bucket_ns as f64 / 1e9;
        let mut previous: HashMap<String, (i64, u64, u64, u64)> = HashMap::new();
        let mut seen: Vec<String> = Vec::new();
        while let Some(row) = rows.next().map_err(db_err)? {
            let entity_id: String = row.get(0).map_err(db_err)?;
            let wall: i64 = row.get(1).map_err(db_err)?;
            let user: u64 = row
                .get::<_, Option<i64>>(2)
                .map_err(db_err)?
                .unwrap_or(0)
                .max(0) as u64;
            let system: u64 = row
                .get::<_, Option<i64>>(3)
                .map_err(db_err)?
                .unwrap_or(0)
                .max(0) as u64;
            let ticks = user.saturating_add(system);
            let rss: Option<i64> = row.get(4).map_err(db_err)?;
            let read: u64 = row
                .get::<_, Option<i64>>(5)
                .map_err(db_err)?
                .unwrap_or(0)
                .max(0) as u64;
            let write: u64 = row
                .get::<_, Option<i64>>(6)
                .map_err(db_err)?
                .unwrap_or(0)
                .max(0) as u64;
            let start = bucket_start(wall);
            if let Some((previous_wall, previous_ticks, previous_read, previous_write)) =
                previous.insert(entity_id.clone(), (wall, ticks, read, write))
            {
                if wall > previous_wall {
                    let delta = ticks.saturating_sub(previous_ticks);
                    let cpu_usec = delta.saturating_mul(1_000_000) / hz.max(1);
                    let name = cgroup_names.get(&entity_id).map_or_else(
                        || entity_display_name(conn, &entity_id),
                        |(name, _)| name.clone(),
                    );
                    merge_entity(
                        &mut entities,
                        BucketEntity {
                            entity_id: entity_id.clone(),
                            kind: EntityKind::Process,
                            name,
                            tool: None,
                            container: None,
                            cpu_usec,
                            cpu_pct: Some(cpu_usec as f64 * 100.0 / (bucket_s * 1_000_000.0)),
                            memory_max: rss.map(|value| value.max(0) as u64),
                            io_read: read.saturating_sub(previous_read),
                            io_write: write.saturating_sub(previous_write),
                            net_rx: 0,
                            net_tx: 0,
                        },
                        start,
                    );
                }
            }
            if rss.is_some_and(|value| value > 0) {
                merge_entity(
                    &mut entities,
                    BucketEntity {
                        entity_id: entity_id.clone(),
                        kind: EntityKind::Process,
                        name: entity_display_name(conn, &entity_id),
                        tool: None,
                        container: None,
                        cpu_usec: 0,
                        cpu_pct: None,
                        memory_max: rss.map(|value| value.max(0) as u64),
                        io_read: 0,
                        io_write: 0,
                        net_rx: 0,
                        net_tx: 0,
                    },
                    start,
                );
            }
            if !seen.contains(&entity_id) {
                seen.push(entity_id);
            }
        }
    }

    // Assemble buckets.
    let mut result: Vec<Bucket> = hosts
        .into_iter()
        .map(|(start, host)| Bucket {
            start_wall_ns: start,
            end_wall_ns: start + bucket_ns,
            host: HostBucket {
                cpu_avg_pct: if host.cpu_count == 0 {
                    None
                } else {
                    Some(host.cpu_sum / host.cpu_count as f64)
                },
                cpu_max_pct: host.cpu_max,
                mem_used_avg: host.mem_sum.checked_div(host.mem_count),
                mem_used_max: host.mem_max,
                psi_cpu_max: host.psi_cpu_max,
                psi_memory_max: host.psi_memory_max,
                psi_io_max: host.psi_io_max,
                load1_avg: if host.load_count == 0 {
                    None
                } else {
                    Some(host.load_sum / host.load_count as f64)
                },
                net_rx_bps_avg: if host.net_rx_count == 0 {
                    None
                } else {
                    Some(host.net_rx_sum / host.net_rx_count as f64)
                },
                net_tx_bps_avg: if host.net_tx_count == 0 {
                    None
                } else {
                    Some(host.net_tx_sum / host.net_tx_count as f64)
                },
            },
            entities: Vec::new(),
        })
        .collect();
    result.sort_by_key(|bucket| bucket.start_wall_ns);
    let mut by_start: HashMap<i64, usize> = result
        .iter()
        .enumerate()
        .map(|(index, bucket)| (bucket.start_wall_ns, index))
        .collect();
    for ((start, _entity_id), entity) in entities {
        let index = by_start.get(&start).copied().unwrap_or_else(|| {
            result.push(Bucket {
                start_wall_ns: start,
                end_wall_ns: start + bucket_ns,
                host: HostBucket::default(),
                entities: Vec::new(),
            });
            let index = result.len() - 1;
            by_start.insert(start, index);
            index
        });
        result[index].entities.push(entity);
    }
    for bucket in &mut result {
        bucket.entities.sort_by(|a, b| {
            b.cpu_usec
                .cmp(&a.cpu_usec)
                .then_with(|| b.memory_max.unwrap_or(0).cmp(&a.memory_max.unwrap_or(0)))
        });
        bucket.entities.truncate(max_entities.max(1));
    }
    Ok(result)
}

#[derive(Default)]
struct HostAcc {
    cpu_sum: f64,
    cpu_count: u64,
    cpu_max: Option<f64>,
    mem_sum: u64,
    mem_count: u64,
    mem_max: Option<u64>,
    psi_cpu_max: Option<f64>,
    psi_memory_max: Option<f64>,
    psi_io_max: Option<f64>,
    load_sum: f64,
    load_count: u64,
    net_rx_sum: f64,
    net_rx_count: u64,
    net_tx_sum: f64,
    net_tx_count: u64,
}

fn merge_entity(
    entities: &mut HashMap<(i64, String), BucketEntity>,
    incoming: BucketEntity,
    start: i64,
) {
    let key = (start, incoming.entity_id.clone());
    match entities.get_mut(&key) {
        Some(existing) => {
            existing.cpu_usec = existing.cpu_usec.saturating_add(incoming.cpu_usec);
            existing.cpu_pct = match (existing.cpu_pct, incoming.cpu_pct) {
                (Some(a), Some(b)) => Some(a + b),
                (a, b) => a.or(b),
            };
            existing.memory_max = match (existing.memory_max, incoming.memory_max) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (a, b) => a.or(b),
            };
            existing.io_read = existing.io_read.saturating_add(incoming.io_read);
            existing.io_write = existing.io_write.saturating_add(incoming.io_write);
            existing.net_rx = existing.net_rx.saturating_add(incoming.net_rx);
            existing.net_tx = existing.net_tx.saturating_add(incoming.net_tx);
        }
        None => {
            entities.insert(key, incoming);
        }
    }
}

/// Resolve an entity id to a human-readable name, falling back to process metadata
/// and finally to the raw id.
pub fn entity_display_name(conn: &Connection, entity_id: &str) -> String {
    if let Some(name) = conn
        .query_row(
            "SELECT name FROM entities WHERE entity_id = ?1",
            params![entity_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|_| ())
        .ok()
        .flatten()
    {
        return name;
    }
    conn.query_row(
        "SELECT COALESCE(executable, comm) FROM process_lifetimes
          WHERE process_instance_id = ?1",
        params![entity_id],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .map_err(|_| ())
    .ok()
    .flatten()
    .unwrap_or_else(|| entity_id.to_string())
}

/// Incidents overlapping a window, newest first.
pub fn incidents(conn: &Connection, window: Window, limit: usize) -> Result<Vec<Incident>> {
    let mut statement = conn
        .prepare(
            "SELECT incident_id, started_wall_ns, ended_wall_ns, entity_id, metric, reason,
                    peak, baseline, evidence_json, acknowledged, evidence_loss
               FROM incidents
              WHERE started_wall_ns < ?2 AND (ended_wall_ns IS NULL OR ended_wall_ns >= ?1)
              ORDER BY started_wall_ns DESC LIMIT ?3",
        )
        .map_err(db_err)?;
    let mut rows = statement
        .query(params![window.since, window.until, limit.max(1) as i64])
        .map_err(db_err)?;
    let mut incidents = Vec::new();
    while let Some(row) = rows.next().map_err(db_err)? {
        incidents.push(incident_from_row(row)?);
    }
    Ok(incidents)
}

/// All incidents, newest first, bounded.
pub fn all_incidents(conn: &Connection, limit: usize) -> Result<Vec<Incident>> {
    let mut statement = conn
        .prepare(
            "SELECT incident_id, started_wall_ns, ended_wall_ns, entity_id, metric, reason,
                    peak, baseline, evidence_json, acknowledged, evidence_loss
               FROM incidents ORDER BY started_wall_ns DESC LIMIT ?1",
        )
        .map_err(db_err)?;
    let mut rows = statement
        .query(params![limit.max(1) as i64])
        .map_err(db_err)?;
    let mut incidents = Vec::new();
    while let Some(row) = rows.next().map_err(db_err)? {
        incidents.push(incident_from_row(row)?);
    }
    Ok(incidents)
}

fn incident_from_row(row: &rusqlite::Row<'_>) -> Result<Incident> {
    let metric: String = row.get(4).map_err(db_err)?;
    let evidence_json: Option<String> = row.get(8).map_err(db_err)?;
    Ok(Incident {
        incident_id: Some(row.get(0).map_err(db_err)?),
        started_wall_ns: row.get(1).map_err(db_err)?,
        ended_wall_ns: row.get(2).map_err(db_err)?,
        entity_id: row.get(3).map_err(db_err)?,
        metric: Metric::parse(&metric).unwrap_or(Metric::Cpu),
        reason: row.get(5).map_err(db_err)?,
        peak: row.get(6).map_err(db_err)?,
        baseline: row.get(7).map_err(db_err)?,
        evidence: evidence_json
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or(serde_json::Value::Null),
        acknowledged: row.get(9).map_err(db_err)?,
        evidence_loss: row.get(10).map_err(db_err)?,
    })
}

/// One incident by id.
pub fn incident(conn: &Connection, incident_id: i64) -> Result<Option<Incident>> {
    let mut statement = conn
        .prepare(
            "SELECT incident_id, started_wall_ns, ended_wall_ns, entity_id, metric, reason,
                    peak, baseline, evidence_json, acknowledged, evidence_loss
               FROM incidents WHERE incident_id = ?1",
        )
        .map_err(db_err)?;
    let mut rows = statement.query(params![incident_id]).map_err(db_err)?;
    match rows.next().map_err(db_err)? {
        Some(row) => Ok(Some(incident_from_row(row)?)),
        None => Ok(None),
    }
}

/// Latest stored wall clock per log source whose id starts with `prefix`.
///
/// The daemon uses this to resume external log cursors after a restart instead
/// of re-reading (and re-storing) the last `tail` lines of every container.
pub fn latest_log_wall_ns(conn: &Connection, prefix: &str) -> Result<HashMap<String, i64>> {
    let mut statement = conn
        .prepare(
            "SELECT source_id, MAX(wall_ts_ns)
               FROM logs
              WHERE source_id LIKE ?1
           GROUP BY source_id",
        )
        .map_err(db_err)?;
    let mut rows = statement
        .query(params![format!("{prefix}%")])
        .map_err(db_err)?;
    let mut latest = HashMap::new();
    while let Some(row) = rows.next().map_err(db_err)? {
        let source_id: String = row.get(0).map_err(db_err)?;
        let wall_ns: Option<i64> = row.get(1).map_err(db_err)?;
        if let Some(wall_ns) = wall_ns.filter(|value| *value > 0) {
            latest.insert(source_id, wall_ns);
        }
    }
    Ok(latest)
}

/// Query logs with bounded filters.
pub fn logs(conn: &Connection, filter: &LogFilter) -> Result<Vec<LogRecord>> {
    let window = filter.window.unwrap_or(Window {
        since: i64::MIN / 4,
        until: i64::MAX / 4,
    });
    let mut sql = String::from(
        "SELECT wall_ts_ns, mono_ts_ns, entity_id, source_id, stream, level, message,
                truncated, redacted, incident_id
           FROM logs
          WHERE wall_ts_ns >= ?1 AND wall_ts_ns < ?2",
    );
    let mut values: Vec<rusqlite::types::Value> = vec![window.since.into(), window.until.into()];
    if let Some(source) = &filter.source_id {
        sql.push_str(" AND source_id = ?");
        values.push(source.clone().into());
    }
    if let Some(level) = filter.min_level {
        sql.push_str(" AND level IN (");
        let levels: Vec<&str> = [Severity::Warn, Severity::Error, Severity::Critical]
            .into_iter()
            .filter(|candidate| *candidate >= level)
            .map(Severity::as_str)
            .collect();
        if levels.is_empty() {
            sql.push_str("'__none__'");
        } else {
            sql.push_str(&levels.iter().map(|_| "?").collect::<Vec<_>>().join(","));
            for name in levels {
                values.push(name.to_string().into());
            }
        }
        sql.push(')');
    }
    if let Some(incident_id) = filter.incident_id {
        sql.push_str(" AND incident_id = ?");
        values.push(incident_id.into());
    }
    if let Some(grep) = &filter.grep {
        sql.push_str(" AND instr(lower(message), lower(?)) > 0");
        values.push(grep.clone().into());
    }
    sql.push_str(" ORDER BY wall_ts_ns DESC LIMIT ?");
    values.push((filter.limit.clamp(1, 100_000) as i64).into());
    let mut statement = conn.prepare(&sql).map_err(db_err)?;
    let mut rows = statement
        .query(rusqlite::params_from_iter(values))
        .map_err(db_err)?;
    let mut records = Vec::new();
    while let Some(row) = rows.next().map_err(db_err)? {
        records.push(LogRecord {
            wall_ns: row.get(0).map_err(db_err)?,
            mono_ns: row.get(1).map_err(db_err)?,
            source_id: row.get(3).map_err(db_err)?,
            entity_id: row.get(2).map_err(db_err)?,
            stream: parse_stream(&row.get::<_, String>(4).map_err(db_err)?),
            level: row
                .get::<_, Option<String>>(5)
                .map_err(db_err)?
                .as_deref()
                .and_then(Severity::parse),
            message: row.get(6).map_err(db_err)?,
            truncated: row.get(7).map_err(db_err)?,
            incident_id: row.get(9).map_err(db_err)?,
            redacted: row.get(8).map_err(db_err)?,
        });
    }
    Ok(records)
}

/// Query events with bounded filters.
pub fn events(conn: &Connection, filter: &EventFilter) -> Result<Vec<EventRecord>> {
    let window = filter.window.unwrap_or(Window {
        since: i64::MIN / 4,
        until: i64::MAX / 4,
    });
    let mut statement = conn
        .prepare(
            "SELECT wall_ts_ns, mono_ts_ns, entity_id, kind, severity, payload_json,
                    provenance, lost_before
               FROM events
              WHERE wall_ts_ns >= ?1 AND wall_ts_ns < ?2
                AND (?3 IS NULL OR entity_id = ?3)
              ORDER BY wall_ts_ns DESC LIMIT ?4",
        )
        .map_err(db_err)?;
    let mut rows = statement
        .query(params![
            window.since,
            window.until,
            filter.entity_id,
            filter.limit.clamp(1, 100_000) as i64
        ])
        .map_err(db_err)?;
    let mut records = Vec::new();
    while let Some(row) = rows.next().map_err(db_err)? {
        let kind: String = row.get(3).map_err(db_err)?;
        let severity: String = row.get(4).map_err(db_err)?;
        let payload_json: Option<String> = row.get(5).map_err(db_err)?;
        let parsed_kind = EventKind::parse(&kind).unwrap_or(EventKind::ServiceEvent);
        if !filter.kinds.is_empty() && !filter.kinds.contains(&parsed_kind) {
            continue;
        }
        records.push(EventRecord {
            wall_ns: row.get(0).map_err(db_err)?,
            mono_ns: row.get(1).map_err(db_err)?,
            entity_id: row.get(2).map_err(db_err)?,
            kind: parsed_kind,
            severity: Severity::parse(&severity).unwrap_or(Severity::Info),
            payload: payload_json
                .and_then(|text| serde_json::from_str(&text).ok())
                .unwrap_or(serde_json::Value::Null),
            provenance: row.get(6).map_err(db_err)?,
            lost_before: row.get::<_, i64>(7).map_err(db_err)?.max(0) as u64,
        });
    }
    Ok(records)
}

/// Process lifetimes overlapping a window, bounded.
pub fn lifetimes(conn: &Connection, window: Window, limit: usize) -> Result<Vec<LifetimeSummary>> {
    let mut statement = conn
        .prepare(
            "SELECT process_instance_id, host_pid, parent_process_instance_id, parent_host_pid,
                    comm, executable, tool, role, unit, container, session,
                    start_wall_ns, end_wall_ns, end_reason
               FROM process_lifetimes
              WHERE start_wall_ns < ?2 AND (end_wall_ns IS NULL OR end_wall_ns >= ?1)
              ORDER BY start_wall_ns ASC LIMIT ?3",
        )
        .map_err(db_err)?;
    let mut rows = statement
        .query(params![window.since, window.until, limit.max(1) as i64])
        .map_err(db_err)?;
    let mut lifetimes = Vec::new();
    while let Some(row) = rows.next().map_err(db_err)? {
        lifetimes.push(LifetimeSummary {
            process_instance_id: row.get(0).map_err(db_err)?,
            host_pid: row.get::<_, i64>(1).map_err(db_err)?.max(0) as u32,
            parent_process_instance_id: row.get(2).map_err(db_err)?,
            parent_host_pid: row
                .get::<_, Option<i64>>(3)
                .map_err(db_err)?
                .map(|value| value.max(0) as u32),
            comm: row.get(4).map_err(db_err)?,
            executable: row.get(5).map_err(db_err)?,
            tool: row.get(6).map_err(db_err)?,
            role: row.get(7).map_err(db_err)?,
            unit: row.get(8).map_err(db_err)?,
            container: row.get(9).map_err(db_err)?,
            session: row.get(10).map_err(db_err)?,
            start_wall_ns: row.get(11).map_err(db_err)?,
            end_wall_ns: row.get(12).map_err(db_err)?,
            end_reason: row.get(13).map_err(db_err)?,
        });
    }
    Ok(lifetimes)
}

/// Latest daemon runs, newest first.
pub fn runs(conn: &Connection, limit: usize) -> Result<Vec<RunSummary>> {
    let mut statement = conn
        .prepare(
            "SELECT run_id, started_wall_ns, stopped_wall_ns, version, simulated, note
               FROM runs ORDER BY run_id DESC LIMIT ?1",
        )
        .map_err(db_err)?;
    let mut rows = statement
        .query(params![limit.max(1) as i64])
        .map_err(db_err)?;
    let mut runs = Vec::new();
    while let Some(row) = rows.next().map_err(db_err)? {
        runs.push(RunSummary {
            run_id: row.get(0).map_err(db_err)?,
            started_wall_ns: row.get(1).map_err(db_err)?,
            stopped_wall_ns: row.get(2).map_err(db_err)?,
            version: row.get(3).map_err(db_err)?,
            simulated: row.get(4).map_err(db_err)?,
            note: row.get(5).map_err(db_err)?,
        });
    }
    Ok(runs)
}

/// Collector health rows.
pub fn collectors(conn: &Connection) -> Result<Vec<CollectorStatus>> {
    let mut statement = conn
        .prepare(
            "SELECT collector_id, configured_state, availability, permission_state,
                    last_success_wall_ns, last_error_wall_ns, last_error, error_count,
                    received_count, persisted_count, dropped_count, truncated_count,
                    queue_high_water, coverage_json
               FROM collector_health ORDER BY collector_id",
        )
        .map_err(db_err)?;
    let mut rows = statement.query([]).map_err(db_err)?;
    let mut collectors = Vec::new();
    while let Some(row) = rows.next().map_err(db_err)? {
        let configured: String = row.get(1).map_err(db_err)?;
        let availability: String = row.get(2).map_err(db_err)?;
        let permission: String = row.get(3).map_err(db_err)?;
        let coverage_json: Option<String> = row.get(13).map_err(db_err)?;
        collectors.push(CollectorStatus {
            health: CollectorHealth {
                collector_id: row.get(0).map_err(db_err)?,
                configured: match configured.as_str() {
                    "enabled" => ConfiguredState::Enabled,
                    "disabled" => ConfiguredState::Disabled,
                    _ => ConfiguredState::Auto,
                },
                availability: Availability::parse(&availability).unwrap_or(Availability::Unknown),
                permission: match permission.as_str() {
                    "permitted" => PermissionState::Permitted,
                    "denied" => PermissionState::Denied,
                    "partial" => PermissionState::Partial,
                    _ => PermissionState::Unknown,
                },
                last_success_wall_ns: row.get(4).map_err(db_err)?,
                last_error_wall_ns: row.get(5).map_err(db_err)?,
                last_error: row.get(6).map_err(db_err)?,
                error_count: row.get::<_, i64>(7).map_err(db_err)?.max(0) as u64,
                received_count: row.get::<_, i64>(8).map_err(db_err)?.max(0) as u64,
                persisted_count: row.get::<_, i64>(9).map_err(db_err)?.max(0) as u64,
                dropped_count: row.get::<_, i64>(10).map_err(db_err)?.max(0) as u64,
                truncated_count: row.get::<_, i64>(11).map_err(db_err)?.max(0) as u64,
                queue_high_water: row.get::<_, i64>(12).map_err(db_err)?.max(0) as u64,
                coverage: serde_json::Value::Null,
            },
            coverage: coverage_json
                .and_then(|text| serde_json::from_str(&text).ok())
                .unwrap_or(serde_json::Value::Null),
        });
    }
    Ok(collectors)
}

/// Integration state rows.
pub fn integrations(conn: &Connection) -> Result<Vec<IntegrationStatus>> {
    let mut statement = conn
        .prepare(
            "SELECT integration_id, configured_state, detected_state, version,
                    capabilities_json, last_seen_wall_ns, last_error
               FROM integration_state ORDER BY integration_id",
        )
        .map_err(db_err)?;
    let mut rows = statement.query([]).map_err(db_err)?;
    let mut integrations = Vec::new();
    while let Some(row) = rows.next().map_err(db_err)? {
        let capabilities_json: Option<String> = row.get(4).map_err(db_err)?;
        let capabilities: Vec<String> = capabilities_json
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default();
        integrations.push(IntegrationStatus {
            integration_id: row.get(0).map_err(db_err)?,
            configured_state: row.get(1).map_err(db_err)?,
            detected_state: row.get(2).map_err(db_err)?,
            version: row.get(3).map_err(db_err)?,
            capabilities,
            last_seen_wall_ns: row.get(5).map_err(db_err)?,
            last_error: row.get(6).map_err(db_err)?,
        });
    }
    Ok(integrations)
}

/// Coverage gaps, open first.
pub fn gaps(conn: &Connection) -> Result<Vec<GapRow>> {
    let mut statement = conn
        .prepare(
            "SELECT source_id, kind, detail, since_wall_ns, resolved_wall_ns
               FROM coverage_gaps
              ORDER BY resolved_wall_ns IS NOT NULL, since_wall_ns DESC",
        )
        .map_err(db_err)?;
    let mut rows = statement.query([]).map_err(db_err)?;
    let mut gaps = Vec::new();
    while let Some(row) = rows.next().map_err(db_err)? {
        gaps.push(GapRow {
            gap: CoverageGap {
                source_id: row.get(0).map_err(db_err)?,
                kind: row.get(1).map_err(db_err)?,
                detail: row.get(2).map_err(db_err)?,
                since_wall_ns: row.get(3).map_err(db_err)?,
            },
            resolved_wall_ns: row.get(4).map_err(db_err)?,
        });
    }
    Ok(gaps)
}

/// Configured log sources recorded for this database.
pub fn log_sources(conn: &Connection) -> Result<Vec<LogSourceStatus>> {
    let mut statement = conn
        .prepare("SELECT source_id, kind, target, entity_hint FROM log_sources ORDER BY source_id")
        .map_err(db_err)?;
    let mut rows = statement.query([]).map_err(db_err)?;
    let mut sources = Vec::new();
    while let Some(row) = rows.next().map_err(db_err)? {
        sources.push(LogSourceStatus {
            source_id: row.get(0).map_err(db_err)?,
            kind: row.get(1).map_err(db_err)?,
            target: row.get(2).map_err(db_err)?,
            entity_hint: row.get(3).map_err(db_err)?,
        });
    }
    Ok(sources)
}

/// Wall nanoseconds to a stable RFC3339 UTC string.
pub fn wall_rfc3339(wall_ns: i64) -> String {
    format_wall_rfc3339(wall_ns)
}

/// Read a metadata value.
pub fn meta_value(conn: &Connection, key: &str) -> Result<Option<String>> {
    conn.query_row(
        "SELECT value FROM meta WHERE key = ?1",
        params![key],
        |row| row.get(0),
    )
    .optional()
    .map_err(db_err)
}

/// Preferred window when the user did not specify one: the last hour of data.
pub fn default_window(conn: &Connection) -> Result<Window> {
    let stats = db_stats(conn)?;
    let until = stats.latest_wall_ns.map_or(0, |value| value + 1);
    Ok(Window::new(until - 3_600_000_000_000, until))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CpuTimes, HostSample, LogRecord, MemSnapshot};
    use crate::store::{Store, WriteItem, WriteRecord};
    use crate::time::{ClockDomain, Stamps};

    fn stamps(wall: i64, mono: i64) -> Stamps {
        Stamps::new(wall, mono, "boot-1", ClockDomain::Simulated)
    }

    fn store_with_host_samples(now: i64) -> Store {
        let mut store = Store::open_in_memory().expect("store");
        store
            .write(&[WriteItem::normal(WriteRecord::Meta {
                key: "clock_ticks_per_second".into(),
                value: "100".into(),
            })])
            .expect("meta");
        let mut items = Vec::new();
        for step in 0..=10u64 {
            let wall = now - 600 * 1_000_000_000 + step as i64 * 60_000_000_000;
            items.push(WriteItem::normal(WriteRecord::HostSample(HostSample {
                stamps: stamps(wall, wall),
                cpu: CpuTimes {
                    user: 100 * step,
                    idle: 900 * step,
                    ..Default::default()
                },
                mem: MemSnapshot {
                    total: 1_000_000,
                    available: Some(1_000_000 - 400_000 - step),
                    ..Default::default()
                },
                load: crate::model::LoadAvg {
                    one: 0.5 + step as f64,
                    ..Default::default()
                },
                pressure: crate::model::Pressure {
                    cpu: Some(crate::model::PressureLine {
                        some_avg10: Some(1.0 + step as f64),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                ..Default::default()
            })));
        }
        store.write(&items).expect("host samples");
        store
    }

    #[test]
    fn host_series_derives_cpu_and_memory() {
        let now = 1_000 * 1_000_000_000;
        let store = store_with_host_samples(now);
        let window = Window::new(now - 600 * 1_000_000_000, now + 1);
        let series = host_series(store.connection(), window).expect("series");
        assert!(series.len() >= 10);
        let point = series.last().expect("point");
        let cpu = point.cpu_pct.expect("cpu");
        assert!((cpu - 10.0).abs() < 0.5, "cpu {cpu}");
        assert_eq!(point.mem_used_bytes, Some(400_010));
        assert!(point.load1.is_some());
        assert!(point.net_rx_bps.is_none() || point.net_rx_bps.is_some());
        let usage = host_usage(store.connection(), window)
            .expect("usage")
            .expect("host usage");
        assert_eq!(usage.net_rx_bytes, None, "missing net must not become zero");
        assert_eq!(usage.net_tx_bytes, None, "missing net must not become zero");
    }

    #[test]
    fn window_overlap_math() {
        let window = Window::new(100, 200);
        assert_eq!(window.overlap_ns(0, 100), 0);
        assert_eq!(window.overlap_ns(0, 150), 50);
        assert_eq!(window.overlap_ns(150, 300), 50);
        assert_eq!(window.overlap_ns(120, 130), 10);
        assert_eq!(window.duration_ns(), 100);
    }

    #[test]
    fn cgroup_usage_is_ranked_and_named() {
        let now = 1_000 * 1_000_000_000;
        let mut store = store_with_host_samples(now);
        store
            .write(&[
                WriteItem::normal(WriteRecord::Entity(crate::model::Entity {
                    entity_id: "cgroup:1:2".into(),
                    kind: EntityKind::Cgroup,
                    stable_key: "2:1".into(),
                    name: "/system.slice/docker-abcdef0123456789abcdef0123456789.scope".into(),
                    source: "cgroup_v2".into(),
                    labels: std::iter::once((
                        "container_id".to_string(),
                        "abcdef0123456789".to_string(),
                    ))
                    .collect(),
                    first_seen_wall_ns: now,
                    last_seen_wall_ns: now,
                })),
                WriteItem::normal(WriteRecord::CgroupSample(crate::model::CgroupSample {
                    stamps: stamps(now - 120 * 1_000_000_000, now - 120 * 1_000_000_000),
                    entity_id: "cgroup:1:2".into(),
                    path: "/system.slice/docker-abcdef0123456789abcdef0123456789.scope".into(),
                    cpu_usage_usec: Some(1_000_000),
                    memory_current: Some(4096),
                    ..Default::default()
                })),
            ])
            .expect("write");
        // Simulate a minute rollup row (what retention would have produced).
        store
            .connection_mut()
            .execute_batch(
                "INSERT INTO rollup_1m(bucket_wall_ns, entity_id, entity_kind, sample_count,
                        cpu_total_usec, memory_max_bytes, io_read_bytes, io_write_bytes,
                        net_rx_bytes, net_tx_bytes)
                 VALUES (600000000000, 'cgroup:1:2', 'cgroup', 12, 500000, 4096, 1000, 2000, 3000, 4000)",
            )
            .expect("rollup");
        let usage = entity_usage(
            store.connection(),
            Window::new(now - 600 * 1_000_000_000, now),
        )
        .expect("usage");
        let cgroup = usage
            .iter()
            .find(|entry| entry.entity_id == "cgroup:1:2")
            .expect("cgroup usage");
        assert_eq!(cgroup.container.as_deref(), Some("abcdef0123456789"));
        assert_eq!(cgroup.net_rx_bytes, Some(3000));
        assert_eq!(cgroup.net_tx_bytes, Some(4000));
        let pct = cgroup.cpu_avg_pct.expect("cpu pct");
        // 500,000 usec of CPU over the 60 s bucket is 0.8333% of one core.
        assert!((pct - 0.833_333).abs() < 0.001, "cpu pct {pct}");

        let buckets = buckets(
            store.connection(),
            Window::new(now - 600 * 1_000_000_000, now),
            600 * 1_000_000_000,
            10,
        )
        .expect("buckets");
        let entity = buckets
            .iter()
            .flat_map(|bucket| bucket.entities.iter())
            .find(|entity| entity.entity_id == "cgroup:1:2")
            .expect("bucket entity");
        assert_eq!(entity.net_rx, 3000);
        assert_eq!(entity.net_tx, 4000);
        assert_eq!(entity.metric_value(Metric::NetRx), 3000.0);
        assert_eq!(entity.metric_value(Metric::NetTx), 4000.0);
    }

    #[test]
    fn host_usage_integrates_network_rates_into_bytes() {
        let now = 1_000 * 1_000_000_000;
        let mut store = Store::open_in_memory().expect("store");
        let mut items = Vec::new();
        for step in 0..=3u64 {
            let wall = now - 300 * 1_000_000_000 + step as i64 * 60_000_000_000;
            let mut net = BTreeMap::new();
            net.insert(
                "eth0".to_string(),
                crate::model::NetCounters {
                    rx_bytes: step * 6_000,
                    tx_bytes: step * 3_000,
                    ..Default::default()
                },
            );
            items.push(WriteItem::normal(WriteRecord::HostSample(HostSample {
                stamps: stamps(wall, wall),
                cpu: CpuTimes {
                    user: 100 * step,
                    idle: 900 * step,
                    ..Default::default()
                },
                net,
                ..Default::default()
            })));
        }
        store.write(&items).expect("host samples");
        let usage = host_usage(
            store.connection(),
            Window::new(now - 600 * 1_000_000_000, now),
        )
        .expect("usage")
        .expect("host usage");
        // Rates are 100 B/s RX and 50 B/s TX; only the two complete intervals
        // between the first and last point are integrated (3 samples => 120 s).
        assert_eq!(usage.net_rx_bytes, Some(12_000));
        assert_eq!(usage.net_tx_bytes, Some(6_000));
    }

    #[test]
    fn log_filter_respects_source_level_and_grep() {
        let now = 1_000 * 1_000_000_000;
        let mut store = Store::open_in_memory().expect("store");
        let mut items = Vec::new();
        for (index, level) in [Severity::Info, Severity::Warn, Severity::Error]
            .into_iter()
            .enumerate()
        {
            items.push(WriteItem::normal(WriteRecord::Log(LogRecord {
                wall_ns: now - index as i64,
                mono_ns: Some(1),
                source_id: "nginx-error".into(),
                entity_id: None,
                stream: LogStream::File,
                level: Some(level),
                message: format!("upstream timeout {index}"),
                truncated: false,
                incident_id: None,
                redacted: false,
            })));
        }
        store.write(&items).expect("logs");
        let filter = LogFilter {
            window: Some(Window::new(now - 10, now + 10)),
            source_id: Some("nginx-error".into()),
            min_level: Some(Severity::Warn),
            grep: Some("timeout".into()),
            incident_id: None,
            limit: 10,
        };
        let records = logs(store.connection(), &filter).expect("logs");
        assert_eq!(records.len(), 2, "only warn+error match");
        let filter = LogFilter {
            window: Some(Window::new(now - 10, now + 10)),
            grep: Some("NOMATCH".into()),
            limit: 10,
            ..Default::default()
        };
        assert_eq!(logs(store.connection(), &filter).expect("logs").len(), 0);
    }

    #[test]
    fn incidents_and_lifetimes_roundtrip() {
        let now = 1_000 * 1_000_000_000;
        let mut store = Store::open_in_memory().expect("store");
        store
            .write(&[
                WriteItem::critical(WriteRecord::Incident(Incident {
                    incident_id: Some(1),
                    started_wall_ns: now - 100,
                    ended_wall_ns: Some(now),
                    entity_id: Some("cgroup:1:2".into()),
                    metric: Metric::Cpu,
                    reason: "cpu".into(),
                    peak: 42.0,
                    baseline: 3.0,
                    evidence: serde_json::json!({"x": 1}),
                    acknowledged: false,
                    evidence_loss: false,
                })),
                WriteItem::normal(WriteRecord::ProcessLifetime(
                    crate::store::ProcessLifetimeRow {
                        process_instance_id: "proc:boot-1:10:20".into(),
                        host_id: "h".into(),
                        host_pid: 10,
                        start_ticks: 20,
                        parent_process_instance_id: None,
                        parent_host_pid: Some(1),
                        executable: Some("/usr/sbin/nginx".into()),
                        comm: "nginx".into(),
                        tool: Some("nginx".into()),
                        role: Some("nginx worker".into()),
                        unit: Some("nginx.service".into()),
                        container: None,
                        session: None,
                        cgroup_entity_id: Some("cgroup:1:2".into()),
                        start_wall_ns: now - 500,
                        start_mono_ns: 100,
                    },
                )),
            ])
            .expect("write");
        let list = incidents(store.connection(), Window::new(now - 1000, now + 1000), 10)
            .expect("incidents");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].peak, 42.0);
        let found = incident(store.connection(), 1)
            .expect("incident")
            .expect("present");
        assert_eq!(found.metric, Metric::Cpu);
        let lifetimes =
            lifetimes(store.connection(), Window::new(now - 1000, now), 10).expect("lifetimes");
        assert_eq!(lifetimes.len(), 1);
        assert_eq!(lifetimes[0].role.as_deref(), Some("nginx worker"));
    }

    #[test]
    fn process_bucket_attribution_distributes_cpu() {
        let now = 1_000 * 1_000_000_000;
        let mut store = store_with_host_samples(now);
        store
            .write(&[WriteItem::normal(WriteRecord::ProcessLifetime(
                crate::store::ProcessLifetimeRow {
                    process_instance_id: "proc:boot-1:42:7".into(),
                    host_id: "h".into(),
                    host_pid: 42,
                    start_ticks: 7,
                    parent_process_instance_id: None,
                    parent_host_pid: None,
                    executable: Some("/usr/bin/cargo".into()),
                    comm: "cargo".into(),
                    tool: Some("cargo".into()),
                    role: None,
                    unit: None,
                    container: None,
                    session: None,
                    cgroup_entity_id: None,
                    start_wall_ns: now - 600 * 1_000_000_000,
                    start_mono_ns: 1,
                },
            ))])
            .expect("lifetime");
        let mut items = Vec::new();
        for step in 0..=10u64 {
            let wall = now - 300 * 1_000_000_000 + step as i64 * 30_000_000_000;
            items.push(WriteItem::normal(WriteRecord::ProcessSample(
                crate::model::ProcessSample {
                    stamps: stamps(wall, wall),
                    process_instance_id: "proc:boot-1:42:7".into(),
                    cpu_user_ticks: 50 * step,
                    cpu_system_ticks: 50 * step,
                    rss_bytes: Some(1024 * 1024),
                    virtual_bytes: Some(2 * 1024 * 1024),
                    read_bytes: Some(0),
                    write_bytes: Some(0),
                    read_chars: Some(0),
                    write_chars: Some(0),
                    threads: Some(2),
                    state: Some('R'),
                    sample_flags: 0,
                },
            )));
        }
        store.write(&items).expect("process samples");
        let buckets = buckets(
            store.connection(),
            Window::new(now - 600 * 1_000_000_000, now),
            120 * 1_000_000_000,
            10,
        )
        .expect("buckets");
        let cargo_total: f64 = buckets
            .iter()
            .flat_map(|bucket| bucket.entities.iter())
            .filter(|entity| entity.entity_id == "proc:boot-1:42:7")
            .filter_map(|entity| entity.cpu_pct)
            .sum();
        assert!(cargo_total > 0.0, "cargo CPU must be attributed");
        assert!(
            buckets.len() >= 2,
            "process activity spans several buckets: {}",
            buckets.len()
        );
        let named = buckets
            .iter()
            .flat_map(|bucket| bucket.entities.iter())
            .any(|entity| entity.name.contains("cargo"));
        assert!(named, "bucket entities keep the process name");
    }

    #[test]
    fn db_stats_reports_counts_and_host_metadata() {
        let now = 1_000 * 1_000_000_000;
        let mut store = store_with_host_samples(now);
        store
            .write(&[WriteItem::normal(WriteRecord::Host(
                crate::store::HostInfo {
                    host_id: "h1".into(),
                    boot_id: "boot-1".into(),
                    hostname: "test-host".into(),
                    kernel_release: "6.8.0".into(),
                    architecture: "x86_64".into(),
                    first_seen_wall_ns: now,
                },
            ))])
            .expect("host");
        let stats = db_stats(store.connection()).expect("stats");
        assert_eq!(stats.counts.get("host_samples").copied(), Some(11));
        assert_eq!(stats.hostname.as_deref(), Some("test-host"));
        assert!(stats.earliest_wall_ns.is_some());
    }
}
