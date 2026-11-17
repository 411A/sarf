//! Retention, rollups and the disk-size guard (guide §11.4–§11.6, §19).
//!
//! Policy:
//! * raw host/cgroup samples are rolled up into complete 1-minute buckets and then
//!   expired after `raw_hours`;
//! * raw process samples expire after `process_raw_hours` (top-N only by default);
//! * 1-hour rollups are derived from complete 1-minute rollup buckets;
//! * incidents and process lifetime summaries outlive raw samples;
//! * non-incident logs and non-critical events expire after their configured window,
//!   while incident-linked evidence is preserved for the incident window;
//! * if the database still exceeds its budget after normal pruning, the guard
//!   removes low-value raw data in the documented degradation order and reports
//!   every step it took. Incidents are never deleted by the guard.
//!
//! Only *complete* buckets are aggregated: a minute bucket is rolled up once its end
//! is at least [`ROLLUP_SETTLE_SECS`] in the past, and an hour bucket is rolled up
//! once the hour itself has ended. That guarantees a bucket is never written twice
//! with different aggregates.

use rusqlite::{params, Connection};
use serde::Serialize;

use crate::config::Config;
use crate::error::{Error, Result};

use super::{RowRead, Store};

/// Seconds a minute bucket must be closed before it is aggregated.
pub const ROLLUP_SETTLE_SECS: i64 = 120;
/// Nanoseconds in one minute.
pub const MINUTE_NS: i64 = 60_000_000_000;
/// Nanoseconds in one hour.
pub const HOUR_NS: i64 = 3_600_000_000_000;
/// Compact process lifetime summaries are kept this many days.
pub const LIFETIME_RETENTION_DAYS: i64 = 30;
/// Relationships are kept this many days after they stop being valid.
pub const RELATIONSHIP_RETENTION_DAYS: i64 = 7;

/// Retention and budget policy derived from configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionPolicy {
    /// Raw host/cgroup sample hours.
    pub raw_hours: u64,
    /// Raw process sample hours.
    pub process_raw_hours: u64,
    /// Minute rollup days.
    pub rollup_1m_days: u64,
    /// Hour rollup days.
    pub rollup_1h_days: u64,
    /// Incident days.
    pub incident_days: u64,
    /// Log days.
    pub log_days: u64,
    /// Database budget in bytes (main file + WAL + report files).
    pub max_db_bytes: u64,
    /// Clock ticks per second used to convert process CPU ticks to microseconds.
    pub clock_ticks_per_second: u64,
}

impl RetentionPolicy {
    /// Build a policy from validated configuration.
    pub fn from_config(config: &Config, clock_ticks_per_second: u64) -> Self {
        Self {
            raw_hours: config.retention.raw_hours,
            process_raw_hours: config.retention.process_raw_hours,
            rollup_1m_days: config.retention.rollup_1m_days,
            rollup_1h_days: config.retention.rollup_1h_days,
            incident_days: config.retention.incident_days,
            log_days: config.retention.log_days,
            max_db_bytes: config.general.max_db_mb.saturating_mul(1024 * 1024),
            clock_ticks_per_second: clock_ticks_per_second.max(1),
        }
    }
}

/// What one prune pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PruneReport {
    /// Minute rollup rows written for host entities.
    pub host_rollup_rows: u64,
    /// Minute rollup rows written for cgroup entities.
    pub cgroup_rollup_rows: u64,
    /// Hour rollup rows written.
    pub hour_rollup_rows: u64,
    /// Raw host samples deleted.
    pub deleted_host_samples: u64,
    /// Raw cgroup samples deleted.
    pub deleted_cgroup_samples: u64,
    /// Raw process samples deleted.
    pub deleted_process_samples: u64,
    /// Log records deleted.
    pub deleted_logs: u64,
    /// Events deleted.
    pub deleted_events: u64,
    /// Incidents deleted.
    pub deleted_incidents: u64,
    /// Process lifetime summaries deleted.
    pub deleted_lifetimes: u64,
    /// Relationships deleted.
    pub deleted_relationships: u64,
    /// Minute rollup rows deleted.
    pub deleted_rollup_1m: u64,
    /// Hour rollup rows deleted.
    pub deleted_rollup_1h: u64,
    /// Disk-guard escalation steps applied (empty when inside budget).
    pub pressure_steps: Vec<String>,
    /// Whether a WAL checkpoint ran.
    pub checkpointed: bool,
    /// Wall-clock duration of the prune pass.
    pub duration_ms: u64,
}

impl PruneReport {
    /// Total rows deleted across all tables.
    pub fn total_deleted(&self) -> u64 {
        [
            self.deleted_host_samples,
            self.deleted_cgroup_samples,
            self.deleted_process_samples,
            self.deleted_logs,
            self.deleted_events,
            self.deleted_incidents,
            self.deleted_lifetimes,
            self.deleted_relationships,
            self.deleted_rollup_1m,
            self.deleted_rollup_1h,
        ]
        .into_iter()
        .sum()
    }
}

/// Run one retention pass: rollups, expiry and the disk guard.
///
/// `data_dir` is the centralized SARF data directory used for budget accounting.
pub fn prune(
    store: &mut Store,
    policy: &RetentionPolicy,
    now_wall_ns: i64,
    data_dir: &std::path::Path,
) -> Result<PruneReport> {
    let started = std::time::Instant::now();
    let mut report = PruneReport {
        host_rollup_rows: rollup_host(store, policy, now_wall_ns)?,
        cgroup_rollup_rows: rollup_cgroups(store, policy, now_wall_ns)?,
        hour_rollup_rows: rollup_hours(store, now_wall_ns)?,
        ..Default::default()
    };

    let raw_cutoff = now_wall_ns - (policy.raw_hours as i64) * HOUR_NS;
    let process_cutoff = now_wall_ns - (policy.process_raw_hours as i64) * HOUR_NS;
    let log_cutoff = now_wall_ns - (policy.log_days as i64) * 24 * HOUR_NS;
    let incident_cutoff = now_wall_ns - (policy.incident_days as i64) * 24 * HOUR_NS;
    let lifetime_cutoff = now_wall_ns - LIFETIME_RETENTION_DAYS * 24 * HOUR_NS;
    let relationship_cutoff = now_wall_ns - RELATIONSHIP_RETENTION_DAYS * 24 * HOUR_NS;

    let tx = store
        .connection_mut()
        .transaction()
        .map_err(|err| Error::Storage(format!("begin prune: {err}")))?;
    report.deleted_host_samples = exec(
        &tx,
        "DELETE FROM host_samples WHERE wall_ts_ns < ?1",
        params![raw_cutoff],
    )?;
    report.deleted_cgroup_samples = exec(
        &tx,
        "DELETE FROM cgroup_samples WHERE wall_ts_ns < ?1",
        params![raw_cutoff],
    )?;
    report.deleted_process_samples = exec(
        &tx,
        "DELETE FROM process_samples WHERE wall_ts_ns < ?1",
        params![process_cutoff],
    )?;
    report.deleted_logs = exec(
        &tx,
        "DELETE FROM logs
          WHERE wall_ts_ns < ?1
            AND incident_id IS NULL
            AND (level IS NULL OR level NOT IN ('error', 'critical'))
            AND wall_ts_ns < ?2",
        params![log_cutoff, incident_cutoff],
    )?;
    report.deleted_events = exec(
        &tx,
        "DELETE FROM events
          WHERE wall_ts_ns < ?1
            AND kind NOT IN ('incident_opened', 'incident_closed', 'collect_gap',
                             'integration_degraded', 'log_flood')
            AND wall_ts_ns < ?2",
        params![raw_cutoff, incident_cutoff],
    )?;
    report.deleted_incidents = exec(
        &tx,
        "DELETE FROM incidents WHERE ended_wall_ns IS NOT NULL AND ended_wall_ns < ?1",
        params![incident_cutoff],
    )?;
    report.deleted_lifetimes = exec(
        &tx,
        "DELETE FROM process_lifetimes WHERE end_wall_ns IS NOT NULL AND end_wall_ns < ?1",
        params![lifetime_cutoff],
    )?;
    report.deleted_relationships = exec(
        &tx,
        "DELETE FROM relationships WHERE valid_to_mono_ns IS NOT NULL AND valid_to_mono_ns < ?1",
        params![relationship_cutoff],
    )?;
    report.deleted_rollup_1m = exec(
        &tx,
        "DELETE FROM rollup_1m WHERE bucket_wall_ns < ?1",
        params![now_wall_ns - (policy.rollup_1m_days as i64) * 24 * HOUR_NS],
    )?;
    report.deleted_rollup_1h = exec(
        &tx,
        "DELETE FROM rollup_1h WHERE bucket_wall_ns < ?1",
        params![now_wall_ns - (policy.rollup_1h_days as i64) * 24 * HOUR_NS],
    )?;
    tx.commit()
        .map_err(|err| Error::Storage(format!("commit prune: {err}")))?;

    // Disk guard: escalate in the documented degradation order.
    let mut usage = data_dir_usage(data_dir);
    if usage > policy.max_db_bytes {
        let steps = [
            (
                "expire process samples older than 1h",
                "DELETE FROM process_samples WHERE wall_ts_ns < ?1",
            ),
            (
                "expire non-critical logs older than 1 day",
                "DELETE FROM logs WHERE wall_ts_ns < ?1 AND incident_id IS NULL AND (level IS NULL OR level NOT IN ('error','critical'))",
            ),
            (
                "expire raw host/cgroup samples older than 6h",
                "DELETE FROM host_samples WHERE wall_ts_ns < ?1",
            ),
            (
                "expire minute rollups older than 2 days",
                "DELETE FROM rollup_1m WHERE bucket_wall_ns < ?1",
            ),
        ];
        let mut cutoff = now_wall_ns - HOUR_NS;
        for (description, sql) in steps {
            if usage <= policy.max_db_bytes {
                break;
            }
            let deleted = exec(store.connection_mut(), sql, params![cutoff])?;
            let _ = store
                .connection()
                .execute_batch("PRAGMA incremental_vacuum(2000);");
            usage = data_dir_usage(data_dir);
            report.pressure_steps.push(format!(
                "{description}: deleted {deleted} rows, now {usage} bytes"
            ));
            // Later steps are progressively harsher windows.
            cutoff = match cutoff {
                value if value == now_wall_ns - HOUR_NS => now_wall_ns - 24 * HOUR_NS,
                value if value == now_wall_ns - 24 * HOUR_NS => now_wall_ns - 6 * HOUR_NS,
                _ => now_wall_ns - 2 * 24 * HOUR_NS,
            };
        }
    }

    let _ = store
        .connection()
        .execute_batch("PRAGMA incremental_vacuum(2000);");
    let _ = store.checkpoint();
    report.checkpointed = true;

    report.duration_ms = started.elapsed().as_millis() as u64;
    Ok(report)
}

fn exec(conn: &Connection, sql: &str, params: impl rusqlite::Params) -> Result<u64> {
    conn.execute(sql, params)
        .map(|rows| rows as u64)
        .map_err(|err| Error::Storage(format!("prune delete: {err}")))
}

fn data_dir_usage(data_dir: &std::path::Path) -> u64 {
    crate::paths::DataDir::new(data_dir).usage_bytes().total()
}

/// One aggregation slot (per bucket and entity).
#[derive(Debug, Clone)]
struct Acc {
    bucket: i64,
    entity_id: String,
    entity_kind: &'static str,
    samples: u64,
    /// Whether `cpu_avg_pct`/`cpu_max_pct` can be computed from tick ratios.
    pct_known: bool,
    sum_pct: f64,
    max_pct: f64,
    cpu_usec: u64,
    memory_sum: u64,
    memory_count: u64,
    memory_max: u64,
    io_read: u64,
    io_write: u64,
    net_rx: u64,
    net_tx: u64,
    net_seen: bool,
    psi_cpu_max: f64,
    psi_mem_max: f64,
    psi_io_max: f64,
}

impl Acc {
    fn new(bucket: i64, entity_id: String, entity_kind: &'static str) -> Self {
        Self {
            bucket,
            entity_id,
            entity_kind,
            samples: 0,
            pct_known: entity_kind == "host",
            sum_pct: 0.0,
            max_pct: 0.0,
            cpu_usec: 0,
            memory_sum: 0,
            memory_count: 0,
            memory_max: 0,
            io_read: 0,
            io_write: 0,
            net_rx: 0,
            net_tx: 0,
            net_seen: false,
            psi_cpu_max: 0.0,
            psi_mem_max: 0.0,
            psi_io_max: 0.0,
        }
    }

    fn add_interval(&mut self, pct: f64, cpu_usec: u64) {
        self.samples += 1;
        self.sum_pct += pct;
        self.max_pct = self.max_pct.max(pct);
        self.cpu_usec = self.cpu_usec.saturating_add(cpu_usec);
    }

    const fn add_counters(&mut self, cpu_usec: u64) {
        self.samples += 1;
        self.cpu_usec = self.cpu_usec.saturating_add(cpu_usec);
    }

    fn add_memory(&mut self, bytes: Option<u64>) {
        if let Some(bytes) = bytes {
            self.memory_sum = self.memory_sum.saturating_add(bytes);
            self.memory_count += 1;
            self.memory_max = self.memory_max.max(bytes);
        }
    }
}

const fn bucket_of(wall_ns: i64, size_ns: i64) -> i64 {
    floor_div(wall_ns, size_ns).saturating_mul(size_ns)
}

const fn floor_div(value: i64, divisor: i64) -> i64 {
    let quotient = value / divisor;
    if value % divisor < 0 && divisor > 0 {
        quotient - 1
    } else {
        quotient
    }
}

fn rollup_window(store: &Store, meta_key: &str, now: i64, raw_hours: u64) -> Result<(i64, i64)> {
    let end = bucket_of(now - ROLLUP_SETTLE_SECS * 1_000_000_000, MINUTE_NS) + MINUTE_NS;
    let stored = store
        .meta_get(meta_key)?
        .and_then(|value| value.parse::<i64>().ok());
    let earliest = now - (raw_hours as i64) * HOUR_NS;
    let start = stored.unwrap_or(earliest).max(earliest).min(end);
    Ok((start, end))
}

fn set_meta(conn: &Connection, key: &str, value: i64) -> Result<()> {
    conn.execute(
        "INSERT INTO meta(key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value.to_string()],
    )
    .map_err(|err| Error::Storage(format!("rollup meta: {err}")))?;
    Ok(())
}

/// Map a `rusqlite` error into SARF's storage error.
#[allow(
    clippy::needless_pass_by_value,
    reason = "this is used as `map_err(storage)`; `map_err` hands the owned error to the \
              mapper, so taking a reference would force a closure at every call site"
)]
fn storage(err: rusqlite::Error) -> Error {
    Error::Storage(format!("rollup row read: {err}"))
}

fn rollup_host(store: &mut Store, policy: &RetentionPolicy, now: i64) -> Result<u64> {
    let (start, end) = rollup_window(store, "rollup_1m_host_through_ns", now, policy.raw_hours)?;
    if start >= end {
        return Ok(0);
    }
    let mut accumulators: Vec<Acc> = Vec::new();
    {
        let conn = store.connection();
        let mut statement = conn
            .prepare(
                "SELECT boot_id, wall_ts_ns,
                        cpu_user_ticks, cpu_nice_ticks, cpu_system_ticks, cpu_idle_ticks,
                        cpu_iowait_ticks, cpu_irq_ticks, cpu_softirq_ticks, cpu_steal_ticks,
                        mem_total_bytes, mem_available_bytes,
                        net_rx_bytes, net_tx_bytes, disk_read_bytes, disk_write_bytes,
                        psi_cpu_some_avg10, psi_mem_some_avg10, psi_io_some_avg10
                   FROM host_samples
                  WHERE wall_ts_ns >= ?1 AND wall_ts_ns < ?2
                  ORDER BY boot_id, mono_ts_ns",
            )
            .map_err(|err| Error::Storage(format!("rollup host statement: {err}")))?;
        let mut rows = statement
            .query(params![start, end])
            .map_err(|err| Error::Storage(format!("rollup host query: {err}")))?;
        let mut previous: Option<HostRaw> = None;
        while let Some(row) = rows
            .next()
            .map_err(|err| Error::Storage(format!("rollup host row: {err}")))?
        {
            let current = HostRaw {
                boot: row.get(0).map_err(storage)?,
                wall: row.get(1).map_err(storage)?,
                user: row.u64_at(2)?,
                nice: row.u64_at(3)?,
                system: row.u64_at(4)?,
                idle: row.u64_at(5)?,
                iowait: row.u64_at(6)?,
                irq: row.u64_at(7)?,
                softirq: row.u64_at(8)?,
                steal: row.u64_at(9)?,
                mem_total: row.opt_u64_at(10)?,
                mem_available: row.opt_u64_at(11)?,
                net_rx: row.opt_u64_at(12)?,
                net_tx: row.opt_u64_at(13)?,
                disk_read: row.opt_u64_at(14)?,
                disk_write: row.opt_u64_at(15)?,
                psi_cpu: row.get(16).map_err(storage)?,
                psi_mem: row.get(17).map_err(storage)?,
                psi_io: row.get(18).map_err(storage)?,
            };
            let previous = previous.replace(current.clone());
            let Some(previous) = previous else { continue };
            if previous.boot != current.boot {
                continue; // never diff counters across boots
            }
            let total = current.total().saturating_sub(previous.total());
            if total == 0 {
                continue;
            }
            let busy = current.busy().saturating_sub(previous.busy());
            let pct = busy as f64 * 100.0 / total as f64;
            let cpu_usec = busy.saturating_mul(1_000_000) / policy.clock_ticks_per_second;
            let memory = match (current.mem_total, current.mem_available) {
                (Some(mem_total), Some(available)) if mem_total > 0 => {
                    Some(mem_total.saturating_sub(available))
                }
                _ => None,
            };
            let bucket = bucket_of(current.wall, MINUTE_NS);
            let entity_id = format!("host:{}", current.boot);
            let index = accumulators
                .iter()
                .position(|acc| acc.bucket == bucket && acc.entity_id == entity_id)
                .unwrap_or_else(|| {
                    accumulators.push(Acc::new(bucket, entity_id, "host"));
                    accumulators.len() - 1
                });
            let slot = &mut accumulators[index];
            slot.add_interval(pct, cpu_usec);
            slot.add_memory(memory);
            if current.net_rx.is_some() || current.net_tx.is_some() {
                slot.net_seen = true;
            }
            slot.net_rx = slot.net_rx.saturating_add(
                current
                    .net_rx
                    .unwrap_or(0)
                    .saturating_sub(previous.net_rx.unwrap_or(0)),
            );
            slot.net_tx = slot.net_tx.saturating_add(
                current
                    .net_tx
                    .unwrap_or(0)
                    .saturating_sub(previous.net_tx.unwrap_or(0)),
            );
            slot.io_read = slot.io_read.saturating_add(
                current
                    .disk_read
                    .unwrap_or(0)
                    .saturating_sub(previous.disk_read.unwrap_or(0)),
            );
            slot.io_write = slot.io_write.saturating_add(
                current
                    .disk_write
                    .unwrap_or(0)
                    .saturating_sub(previous.disk_write.unwrap_or(0)),
            );
            slot.psi_cpu_max = slot.psi_cpu_max.max(current.psi_cpu.unwrap_or(0.0));
            slot.psi_mem_max = slot.psi_mem_max.max(current.psi_mem.unwrap_or(0.0));
            slot.psi_io_max = slot.psi_io_max.max(current.psi_io.unwrap_or(0.0));
        }
    }
    let written = write_accs(store, &accumulators)?;
    if !accumulators.is_empty() {
        set_meta(store.connection(), "rollup_1m_host_through_ns", end)?;
    }
    Ok(written)
}

#[derive(Clone)]
struct HostRaw {
    boot: String,
    wall: i64,
    user: u64,
    nice: u64,
    system: u64,
    idle: u64,
    iowait: u64,
    irq: u64,
    softirq: u64,
    steal: u64,
    mem_total: Option<u64>,
    mem_available: Option<u64>,
    net_rx: Option<u64>,
    net_tx: Option<u64>,
    disk_read: Option<u64>,
    disk_write: Option<u64>,
    psi_cpu: Option<f64>,
    psi_mem: Option<f64>,
    psi_io: Option<f64>,
}

impl HostRaw {
    const fn total(&self) -> u64 {
        self.user
            .saturating_add(self.nice)
            .saturating_add(self.system)
            .saturating_add(self.idle)
            .saturating_add(self.iowait)
            .saturating_add(self.irq)
            .saturating_add(self.softirq)
            .saturating_add(self.steal)
    }

    const fn busy(&self) -> u64 {
        self.total()
            .saturating_sub(self.idle)
            .saturating_sub(self.iowait)
    }
}

/// Previous cgroup sample used to derive counter deltas.
///
/// Fields: entity id, cumulative CPU microseconds, I/O counters, cumulative
/// network receive bytes, cumulative network transmit bytes.
type CgroupRollupPrevious = (String, u64, Vec<CgroupIoRaw>, Option<u64>, Option<u64>);

fn rollup_cgroups(store: &mut Store, policy: &RetentionPolicy, now: i64) -> Result<u64> {
    let (start, end) = rollup_window(store, "rollup_1m_cgroup_through_ns", now, policy.raw_hours)?;
    if start >= end {
        return Ok(0);
    }
    let mut accumulators: Vec<Acc> = Vec::new();
    {
        let conn = store.connection();
        let mut statement = conn
            .prepare(
                "SELECT entity_id, wall_ts_ns, cpu_usage_usec, memory_current_bytes, io_json,
                        psi_cpu_some_avg10, psi_mem_some_avg10, psi_io_some_avg10,
                        net_rx_bytes, net_tx_bytes
                   FROM cgroup_samples
                  WHERE wall_ts_ns >= ?1 AND wall_ts_ns < ?2
                  ORDER BY entity_id, mono_ts_ns",
            )
            .map_err(|err| Error::Storage(format!("rollup cgroup statement: {err}")))?;
        let mut rows = statement
            .query(params![start, end])
            .map_err(|err| Error::Storage(format!("rollup cgroup query: {err}")))?;
        let mut previous: Option<CgroupRollupPrevious> = None;
        while let Some(row) = rows
            .next()
            .map_err(|err| Error::Storage(format!("rollup cgroup row: {err}")))?
        {
            let entity_id: String = row.get(0).map_err(storage)?;
            let wall: i64 = row.get(1).map_err(storage)?;
            let cpu: Option<u64> = row.opt_u64_at(2)?;
            let memory: Option<u64> = row.opt_u64_at(3)?;
            let io_json: Option<String> = row.get(4).map_err(storage)?;
            let psi_cpu: Option<f64> = row.get(5).map_err(storage)?;
            let psi_mem: Option<f64> = row.get(6).map_err(storage)?;
            let psi_io: Option<f64> = row.get(7).map_err(storage)?;
            let net_rx = row.opt_u64_at(8)?;
            let net_tx = row.opt_u64_at(9)?;
            let io = parse_io(io_json.as_deref());
            let current = (
                entity_id.clone(),
                cpu.unwrap_or(0),
                io.clone(),
                net_rx,
                net_tx,
            );
            let previous = previous.replace(current);
            let Some((
                previous_entity,
                previous_cpu,
                previous_io,
                previous_net_rx,
                previous_net_tx,
            )) = previous
            else {
                continue;
            };
            if previous_entity != entity_id {
                continue;
            }
            if let Some(cpu) = cpu {
                let delta = cpu.saturating_sub(previous_cpu);
                let bucket = bucket_of(wall, MINUTE_NS);
                let index = accumulators
                    .iter()
                    .position(|acc| acc.bucket == bucket && acc.entity_id == entity_id)
                    .unwrap_or_else(|| {
                        accumulators.push(Acc::new(bucket, entity_id.clone(), "cgroup"));
                        accumulators.len() - 1
                    });
                let slot = &mut accumulators[index];
                slot.add_counters(delta);
                slot.add_memory(memory);
                slot.io_read = slot
                    .io_read
                    .saturating_add(delta_io(&previous_io, &io, |entry| entry.read_bytes));
                slot.io_write =
                    slot.io_write
                        .saturating_add(delta_io(&previous_io, &io, |entry| entry.write_bytes));
                slot.psi_cpu_max = slot.psi_cpu_max.max(psi_cpu.unwrap_or(0.0));
                slot.psi_mem_max = slot.psi_mem_max.max(psi_mem.unwrap_or(0.0));
                if net_rx.is_some() || net_tx.is_some() {
                    slot.net_seen = true;
                }
                slot.net_rx = slot.net_rx.saturating_add(
                    net_rx
                        .unwrap_or(0)
                        .saturating_sub(previous_net_rx.unwrap_or(0)),
                );
                slot.net_tx = slot.net_tx.saturating_add(
                    net_tx
                        .unwrap_or(0)
                        .saturating_sub(previous_net_tx.unwrap_or(0)),
                );
                slot.psi_io_max = slot.psi_io_max.max(psi_io.unwrap_or(0.0));
            }
        }
    }
    let written = write_accs(store, &accumulators)?;
    if !accumulators.is_empty() {
        set_meta(store.connection(), "rollup_1m_cgroup_through_ns", end)?;
    }
    Ok(written)
}

#[derive(Debug, Clone)]
struct CgroupIoRaw {
    device: String,
    read_bytes: u64,
    write_bytes: u64,
}

fn parse_io(json: Option<&str>) -> Vec<CgroupIoRaw> {
    let Some(json) = json else {
        return Vec::new();
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(json) else {
        return Vec::new();
    };
    let Some(array) = value.as_array() else {
        return Vec::new();
    };
    array
        .iter()
        .filter_map(|entry| {
            Some(CgroupIoRaw {
                device: entry.get("device")?.as_str()?.to_string(),
                read_bytes: entry
                    .get("read_bytes")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0),
                write_bytes: entry
                    .get("write_bytes")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0),
            })
        })
        .collect()
}

fn delta_io(
    previous: &[CgroupIoRaw],
    current: &[CgroupIoRaw],
    field: impl Fn(&CgroupIoRaw) -> u64,
) -> u64 {
    let mut total = 0u64;
    for entry in current {
        let before = previous
            .iter()
            .find(|candidate| candidate.device == entry.device)
            .map_or(0, &field);
        total = total.saturating_add(field(entry).saturating_sub(before));
    }
    total
}

fn write_accs(store: &mut Store, accumulators: &[Acc]) -> Result<u64> {
    if accumulators.is_empty() {
        return Ok(0);
    }
    let tx = store
        .connection_mut()
        .transaction()
        .map_err(|err| Error::Storage(format!("begin rollup write: {err}")))?;
    let written;
    {
        let mut statement = tx
            .prepare_cached(
                "INSERT OR REPLACE INTO rollup_1m(
                    bucket_wall_ns, entity_id, entity_kind, sample_count,
                    cpu_avg_pct, cpu_max_pct, cpu_total_usec,
                    memory_avg_bytes, memory_max_bytes,
                    io_read_bytes, io_write_bytes, net_rx_bytes, net_tx_bytes,
                    psi_cpu_max, psi_mem_max, psi_io_max)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            )
            .map_err(|err| Error::Storage(format!("rollup statement: {err}")))?;
        for acc in accumulators {
            let cpu_avg = if acc.pct_known && acc.samples > 0 {
                Some(acc.sum_pct / acc.samples as f64)
            } else {
                None
            };
            let cpu_max = if acc.pct_known && acc.samples > 0 {
                Some(acc.max_pct)
            } else {
                None
            };
            let memory_avg = acc
                .memory_sum
                .checked_div(acc.memory_count)
                .map(|avg| avg as i64);
            statement
                .execute(params![
                    acc.bucket,
                    acc.entity_id,
                    acc.entity_kind,
                    acc.samples as i64,
                    cpu_avg,
                    cpu_max,
                    acc.cpu_usec as i64,
                    memory_avg,
                    if acc.memory_max == 0 {
                        None
                    } else {
                        Some(acc.memory_max as i64)
                    },
                    acc.io_read as i64,
                    acc.io_write as i64,
                    acc.net_seen.then_some(acc.net_rx as i64),
                    acc.net_seen.then_some(acc.net_tx as i64),
                    acc.psi_cpu_max,
                    acc.psi_mem_max,
                    acc.psi_io_max,
                ])
                .map_err(|err| Error::Storage(format!("rollup insert: {err}")))?;
        }
        written = accumulators.len() as u64;
    }
    tx.commit()
        .map_err(|err| Error::Storage(format!("commit rollup: {err}")))?;
    Ok(written)
}

fn rollup_hours(store: &mut Store, now: i64) -> Result<u64> {
    // Only completed hours are aggregated.
    let end = bucket_of(now, HOUR_NS);
    let stored = store
        .meta_get("rollup_1h_through_ns")?
        .and_then(|value| value.parse::<i64>().ok());
    let start = if let Some(start) = stored {
        start
    } else {
        let oldest: Option<i64> = store
            .connection()
            .query_row("SELECT MIN(bucket_wall_ns) FROM rollup_1m", [], |row| {
                row.get(0)
            })
            .map_err(|err| Error::Storage(format!("hour rollup min: {err}")))?;
        oldest.map_or(end, |value| bucket_of(value, HOUR_NS))
    };
    if start >= end {
        return Ok(0);
    }
    rollup_hour_range(store, start, end)
}

fn rollup_hour_range(store: &mut Store, start: i64, end: i64) -> Result<u64> {
    struct HourAcc {
        bucket: i64,
        entity_id: String,
        entity_kind: String,
        samples: u64,
        cpu_weighted: f64,
        cpu_weight: u64,
        cpu_max: f64,
        cpu_total: u64,
        memory_weighted: f64,
        memory_weight: u64,
        memory_max: i64,
        io_read: u64,
        io_write: u64,
        net_rx: u64,
        net_tx: u64,
        net_seen: bool,
    }
    let mut accumulators: Vec<HourAcc> = Vec::new();
    {
        let conn = store.connection();
        let mut statement = conn
            .prepare(
                "SELECT bucket_wall_ns, entity_id, entity_kind, sample_count,
                        cpu_avg_pct, cpu_max_pct, cpu_total_usec,
                        memory_avg_bytes, memory_max_bytes,
                        io_read_bytes, io_write_bytes, net_rx_bytes, net_tx_bytes
                   FROM rollup_1m
                  WHERE bucket_wall_ns >= ?1 AND bucket_wall_ns < ?2",
            )
            .map_err(|err| Error::Storage(format!("hour rollup statement: {err}")))?;
        let mut rows = statement
            .query(params![start, end])
            .map_err(|err| Error::Storage(format!("hour rollup query: {err}")))?;
        while let Some(row) = rows
            .next()
            .map_err(|err| Error::Storage(format!("hour rollup row: {err}")))?
        {
            let minute: i64 = row.get(0).map_err(storage)?;
            let entity_id: String = row.get(1).map_err(storage)?;
            let entity_kind: String = row.get(2).map_err(storage)?;
            let sample_count: u64 =
                row.get::<_, Option<i64>>(3).map_err(storage)?.unwrap_or(0) as u64;
            let cpu_avg: Option<f64> = row.get(4).map_err(storage)?;
            let cpu_max: Option<f64> = row.get(5).map_err(storage)?;
            let cpu_total: Option<i64> = row.get(6).map_err(storage)?;
            let memory_avg: Option<i64> = row.get(7).map_err(storage)?;
            let memory_max: Option<i64> = row.get(8).map_err(storage)?;
            let io_read: Option<i64> = row.get(9).map_err(storage)?;
            let io_write: Option<i64> = row.get(10).map_err(storage)?;
            let net_rx: Option<i64> = row.get(11).map_err(storage)?;
            let net_tx: Option<i64> = row.get(12).map_err(storage)?;
            let bucket = bucket_of(minute, HOUR_NS);
            let index = accumulators
                .iter()
                .position(|acc| acc.bucket == bucket && acc.entity_id == entity_id)
                .unwrap_or_else(|| {
                    accumulators.push(HourAcc {
                        bucket,
                        entity_id: entity_id.clone(),
                        entity_kind,
                        samples: 0,
                        cpu_weighted: 0.0,
                        cpu_weight: 0,
                        cpu_max: 0.0,
                        cpu_total: 0,
                        memory_weighted: 0.0,
                        memory_weight: 0,
                        memory_max: 0,
                        io_read: 0,
                        io_write: 0,
                        net_rx: 0,
                        net_tx: 0,
                        net_seen: false,
                    });
                    accumulators.len() - 1
                });
            let slot = &mut accumulators[index];
            slot.samples = slot.samples.saturating_add(sample_count);
            if let Some(avg) = cpu_avg {
                slot.cpu_weighted = avg.mul_add(sample_count.max(1) as f64, slot.cpu_weighted);
                slot.cpu_weight = slot.cpu_weight.saturating_add(sample_count.max(1));
            }
            slot.cpu_max = slot.cpu_max.max(cpu_max.unwrap_or(0.0));
            slot.cpu_total = slot
                .cpu_total
                .saturating_add(cpu_total.unwrap_or(0).max(0) as u64);
            if let Some(avg) = memory_avg {
                slot.memory_weighted =
                    (avg as f64).mul_add(sample_count.max(1) as f64, slot.memory_weighted);
                slot.memory_weight = slot.memory_weight.saturating_add(sample_count.max(1));
            }
            slot.memory_max = slot.memory_max.max(memory_max.unwrap_or(0));
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

    let tx = store
        .connection_mut()
        .transaction()
        .map_err(|err| Error::Storage(format!("begin hour rollup: {err}")))?;
    {
        let mut insert = tx
            .prepare_cached(
                "INSERT OR REPLACE INTO rollup_1h(
                    bucket_wall_ns, entity_id, entity_kind, sample_count,
                    cpu_avg_pct, cpu_max_pct, cpu_total_usec,
                    memory_avg_bytes, memory_max_bytes,
                    io_read_bytes, io_write_bytes, net_rx_bytes, net_tx_bytes)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            )
            .map_err(|err| Error::Storage(format!("hour rollup insert: {err}")))?;
        for acc in &accumulators {
            let cpu_avg = if acc.cpu_weight == 0 {
                None
            } else {
                Some(acc.cpu_weighted / acc.cpu_weight as f64)
            };
            let memory_avg = if acc.memory_weight == 0 {
                None
            } else {
                Some((acc.memory_weighted / acc.memory_weight as f64) as i64)
            };
            insert
                .execute(params![
                    acc.bucket,
                    acc.entity_id,
                    acc.entity_kind,
                    acc.samples as i64,
                    cpu_avg,
                    acc.cpu_max,
                    acc.cpu_total as i64,
                    memory_avg,
                    acc.memory_max,
                    acc.io_read as i64,
                    acc.io_write as i64,
                    acc.net_seen.then_some(acc.net_rx as i64),
                    acc.net_seen.then_some(acc.net_tx as i64),
                ])
                .map_err(|err| Error::Storage(format!("hour rollup row insert: {err}")))?;
        }
    }
    tx.commit()
        .map_err(|err| Error::Storage(format!("commit hour rollup: {err}")))?;
    set_meta(store.connection(), "rollup_1h_through_ns", end)?;
    Ok(accumulators.len() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        CgroupSample, CpuTimes, EventKind, EventRecord, HostSample, LogRecord, LogStream,
        MemSnapshot, Severity,
    };
    use crate::store::{Store, WriteItem, WriteRecord};
    use crate::time::{ClockDomain, Stamps};

    fn stamps(wall: i64, mono: i64) -> Stamps {
        Stamps::new(wall, mono, "boot-a", ClockDomain::Simulated)
    }

    fn policy(clock_ticks: u64) -> RetentionPolicy {
        RetentionPolicy {
            raw_hours: 1,
            process_raw_hours: 1,
            rollup_1m_days: 2,
            rollup_1h_days: 3,
            incident_days: 4,
            log_days: 1,
            max_db_bytes: u64::MAX,
            clock_ticks_per_second: clock_ticks,
        }
    }

    fn host_sample(wall: i64, mono: i64, user: u64, idle: u64, used: u64) -> HostSample {
        HostSample {
            stamps: stamps(wall, mono),
            cpu: CpuTimes {
                user,
                idle,
                ..Default::default()
            },
            mem: MemSnapshot {
                total: 1_000_000,
                available: Some(1_000_000 - used),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Insert host samples every 10s covering `steps` intervals starting at `start`.
    fn write_host_run(store: &mut Store, start: i64, steps: u64) {
        let mut items = Vec::new();
        let mut user = 0u64;
        let mut idle = 0u64;
        for step in 0..=steps {
            let wall = start + step as i64 * 10_000_000_000;
            user += 100;
            idle += 900;
            items.push(WriteItem::normal(WriteRecord::HostSample(host_sample(
                wall,
                wall,
                user,
                idle,
                200 + step,
            ))));
        }
        store.write(&items).expect("write samples");
    }

    #[test]
    fn complete_minute_buckets_are_rolled_up() {
        let mut store = Store::open_in_memory().expect("store");
        let now = 10 * HOUR_NS;
        write_host_run(&mut store, now - 20 * 60 * 1_000_000_000, 18);
        let report = prune(
            &mut store,
            &policy(100),
            now,
            std::path::Path::new("/nonexistent"),
        )
        .expect("prune");
        assert!(report.host_rollup_rows >= 1, "expected rollups: {report:?}");
        let avg: Option<f64> = store
            .connection()
            .query_row("SELECT AVG(cpu_avg_pct) FROM rollup_1m", [], |row| {
                row.get(0)
            })
            .expect("avg cpu");
        let avg = avg.expect("cpu rollup value");
        // 100 busy / 1000 total ticks == 10%.
        assert!((avg - 10.0).abs() < 0.5, "avg cpu {avg}");
        let samples: i64 = store
            .connection()
            .query_row("SELECT SUM(sample_count) FROM rollup_1m", [], |row| {
                row.get(0)
            })
            .expect("samples");
        assert!(
            samples >= 10,
            "rollup should aggregate samples, got {samples}"
        );
        let net: Option<i64> = store
            .connection()
            .query_row("SELECT SUM(net_rx_bytes) FROM rollup_1m", [], |row| {
                row.get(0)
            })
            .expect("net");
        assert_eq!(net, None, "absent network counters must stay NULL");
    }

    #[test]
    fn expired_raw_samples_are_deleted_but_recent_ones_kept() {
        let mut store = Store::open_in_memory().expect("store");
        let now = 10 * HOUR_NS;
        // Old samples (3h) are outside the 1h window and outside rollup coverage.
        write_host_run(&mut store, now - 3 * HOUR_NS, 3);
        // Recent samples (20 min) are kept.
        write_host_run(&mut store, now - 20 * 60 * 1_000_000_000, 18);
        let report = prune(
            &mut store,
            &policy(100),
            now,
            std::path::Path::new("/nonexistent"),
        )
        .expect("prune");
        assert!(report.deleted_host_samples >= 4, "{report:?}");
        let remaining: i64 = store
            .connection()
            .query_row("SELECT COUNT(*) FROM host_samples", [], |row| row.get(0))
            .expect("count");
        assert!(remaining > 0, "recent samples must be kept");
        let oldest: i64 = store
            .connection()
            .query_row("SELECT MIN(wall_ts_ns) FROM host_samples", [], |row| {
                row.get(0)
            })
            .expect("min");
        assert!(oldest >= now - HOUR_NS);
    }

    #[test]
    fn second_prune_does_not_duplicate_buckets() {
        let mut store = Store::open_in_memory().expect("store");
        let now = 5 * HOUR_NS;
        write_host_run(&mut store, now - 20 * 60 * 1_000_000_000, 18);
        let policy = policy(100);
        let first = prune(
            &mut store,
            &policy,
            now,
            std::path::Path::new("/nonexistent"),
        )
        .expect("prune");
        assert!(first.host_rollup_rows >= 1);
        let count_first: i64 = store
            .connection()
            .query_row("SELECT COUNT(*) FROM rollup_1m", [], |row| row.get(0))
            .expect("count");
        let second = prune(
            &mut store,
            &policy,
            now,
            std::path::Path::new("/nonexistent"),
        )
        .expect("prune");
        assert_eq!(second.host_rollup_rows, 0, "no new buckets on rerun");
        let count_second: i64 = store
            .connection()
            .query_row("SELECT COUNT(*) FROM rollup_1m", [], |row| row.get(0))
            .expect("count");
        assert_eq!(count_first, count_second);
    }

    #[test]
    fn cgroup_rollups_store_usecond_deltas_without_fabricated_percentages() {
        let mut store = Store::open_in_memory().expect("store");
        let now = 4 * HOUR_NS;
        let start = now - 20 * 60 * 1_000_000_000;
        let mut items = Vec::new();
        for step in 0..=18 {
            let wall = start + i64::from(step) * 10_000_000_000;
            items.push(WriteItem::normal(WriteRecord::CgroupSample(CgroupSample {
                stamps: stamps(wall, wall),
                entity_id: "cgroup:1:2".into(),
                path: "/system.slice/web.service".into(),
                cpu_usage_usec: Some(1_000 * step as u64),
                memory_current: Some(2_048 + step as u64),
                net_rx_bytes: Some(1_000 * step as u64),
                net_tx_bytes: Some(2_000 * step as u64),
                io: vec![crate::model::CgroupIo {
                    device: "8:0".into(),
                    read_bytes: Some(4_096 * step as u64),
                    write_bytes: Some(8_192 * step as u64),
                    read_ops: None,
                    write_ops: None,
                }],
                ..Default::default()
            })));
        }
        store.write(&items).expect("write");
        let report = prune(
            &mut store,
            &policy(100),
            now,
            std::path::Path::new("/nonexistent"),
        )
        .expect("prune");
        assert!(report.cgroup_rollup_rows >= 1, "{report:?}");
        let (avg, total, io_read, net_rx, net_tx): (Option<f64>, i64, i64, i64, i64) = store
            .connection()
            .query_row(
                "SELECT cpu_avg_pct, SUM(cpu_total_usec), SUM(io_read_bytes),
                        SUM(net_rx_bytes), SUM(net_tx_bytes)
                   FROM rollup_1m WHERE entity_kind = 'cgroup'",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .expect("rollup");
        assert!(
            avg.is_none(),
            "cgroup percentages are derived at query time"
        );
        assert!(total > 0, "cpu usecond deltas stored");
        assert!(io_read > 0, "io deltas stored");
        assert!(net_rx > 0, "network RX deltas stored");
        assert!(net_tx > 0, "network TX deltas stored");
    }

    #[test]
    fn critical_logs_incidents_and_gaps_survive_normal_pruning() {
        let mut store = Store::open_in_memory().expect("store");
        let now = 100 * 24 * HOUR_NS;
        let items = vec![
            WriteItem::normal(WriteRecord::Log(LogRecord {
                wall_ns: now - 10 * 24 * HOUR_NS,
                mono_ns: Some(1),
                source_id: "nginx-error".into(),
                entity_id: None,
                stream: LogStream::File,
                level: Some(Severity::Error),
                message: "upstream timeout".into(),
                truncated: false,
                incident_id: Some(1),
                redacted: false,
            })),
            WriteItem::normal(WriteRecord::Log(LogRecord {
                wall_ns: now - 10 * 24 * HOUR_NS,
                mono_ns: Some(1),
                source_id: "app".into(),
                entity_id: None,
                stream: LogStream::File,
                level: Some(Severity::Info),
                message: "routine".into(),
                truncated: false,
                incident_id: None,
                redacted: false,
            })),
            WriteItem::normal(WriteRecord::Event(EventRecord {
                wall_ns: now - 10 * 24 * HOUR_NS,
                mono_ns: Some(1),
                entity_id: None,
                kind: EventKind::CollectGap,
                severity: Severity::Warn,
                payload: serde_json::json!({}),
                provenance: "test".into(),
                lost_before: 0,
            })),
        ];
        store.write(&items).expect("write");
        let report = prune(
            &mut store,
            &policy(100),
            now,
            std::path::Path::new("/nonexistent"),
        )
        .expect("prune");
        let incident_logs: i64 = store
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM logs WHERE incident_id = 1",
                [],
                |row| row.get(0),
            )
            .expect("incident logs");
        assert_eq!(incident_logs, 1);
        let info_logs: i64 = store
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM logs WHERE incident_id IS NULL",
                [],
                |row| row.get(0),
            )
            .expect("info logs");
        assert_eq!(info_logs, 0, "old non-incident info logs expire");
        let events: i64 = store
            .connection()
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .expect("events");
        assert_eq!(events, 1, "collect-gap events survive");
        assert_eq!(report.deleted_incidents, 0);
    }

    #[test]
    fn hour_rollups_are_derived_from_complete_minute_rollups() {
        let mut store = Store::open_in_memory().expect("store");
        let now = 6 * HOUR_NS;
        let mut policy = policy(100);
        policy.raw_hours = 3;
        write_host_run(&mut store, now - 2 * HOUR_NS, 12);
        let report = prune(
            &mut store,
            &policy,
            now,
            std::path::Path::new("/nonexistent"),
        )
        .expect("prune");
        assert!(report.hour_rollup_rows >= 1, "{report:?}");
        let samples: i64 = store
            .connection()
            .query_row("SELECT SUM(sample_count) FROM rollup_1h", [], |row| {
                row.get(0)
            })
            .expect("sum");
        assert!(samples >= 1);
    }

    #[test]
    fn bucket_math_handles_negative_times() {
        assert_eq!(bucket_of(0, MINUTE_NS), 0);
        assert_eq!(bucket_of(MINUTE_NS + 1, MINUTE_NS), MINUTE_NS);
        assert_eq!(bucket_of(-1, MINUTE_NS), -MINUTE_NS);
        assert_eq!(floor_div(-1, 60), -1);
        assert_eq!(floor_div(59, 60), 0);
    }

    #[test]
    fn policy_from_config_uses_megabyte_budget() {
        let config = Config::default();
        let policy = RetentionPolicy::from_config(&config, 100);
        assert_eq!(policy.max_db_bytes, 100 * 1024 * 1024);
        assert_eq!(policy.clock_ticks_per_second, 100);
    }
}
