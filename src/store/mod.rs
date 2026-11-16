//! SQLite storage: schema, single-writer batches and query helpers.
//!
//! One `Store` owns one connection. In production that connection lives on a single
//! writer thread ([`writer::Writer`]); CLI commands open their own read connection.
//! Writes always go through one transaction per batch so the daemon never issues
//! synchronous SQLite work on its sampling thread.

pub mod query;
pub mod retention;
pub mod schema;
pub mod writer;

use std::path::{Path, PathBuf};

use rusqlite::{params, Connection, OpenFlags, OptionalExtension};

use crate::error::{Error, Result};
use crate::model::{
    CollectorHealth, CoverageGap, CgroupSample, Entity, EventRecord, HostSample, Incident,
    LogRecord, ProcessSample, Relationship, WritePriority,
};

/// Convert a `u64` counter into a SQLite INTEGER.
///
/// `rusqlite` deliberately does not implement `ToSql`/`FromSql` for `u64` because
/// SQLite integers are signed. Kernel counters never approach `i64::MAX`; we
/// saturate instead of wrapping so a corrupt counter cannot become a negative value.
pub fn to_sql_i64(value: u64) -> i64 {
    value.min(i64::MAX as u64) as i64
}

/// Convert an optional `u64` into a SQLite INTEGER or NULL.
pub fn to_sql_opt_i64(value: Option<u64>) -> Option<i64> {
    value.map(to_sql_i64)
}

/// Typed row accessors for unsigned counters.
///
/// Missing values stay `None`; negative stored values are clamped to zero and a
/// malformed type is a storage error, never a silent zero.
pub trait RowRead {
    /// Read a required unsigned counter.
    fn u64_at(&self, index: usize) -> Result<u64>;
    /// Read an optional unsigned counter.
    fn opt_u64_at(&self, index: usize) -> Result<Option<u64>>;
}

impl RowRead for rusqlite::Row<'_> {
    fn u64_at(&self, index: usize) -> Result<u64> {
        let value: i64 = self
            .get(index)
            .map_err(|err| Error::Storage(format!("column {index}: {err}")))?;
        Ok(value.max(0) as u64)
    }

    fn opt_u64_at(&self, index: usize) -> Result<Option<u64>> {
        let value: Option<i64> = self
            .get(index)
            .map_err(|err| Error::Storage(format!("column {index}: {err}")))?;
        Ok(value.map(|value| value.max(0) as u64))
    }
}

/// SQLite connection wrapper used by the writer thread and by tests.
#[derive(Debug)]
pub struct Store {
    conn: Connection,
    path: PathBuf,
}

/// Host identity row inserted at run start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostInfo {
    /// Stable host id (boot id plus hostname digest provided by the caller).
    pub host_id: String,
    /// Kernel boot id (or simulated equivalent).
    pub boot_id: String,
    /// Hostname.
    pub hostname: String,
    /// Kernel release string.
    pub kernel_release: String,
    /// Architecture string.
    pub architecture: String,
    /// First time this host instance was observed, wall clock.
    pub first_seen_wall_ns: i64,
}

/// One process lifetime row. `end_*` fields are `None` while the process is alive.
#[derive(Debug, Clone, PartialEq)]
pub struct ProcessLifetimeRow {
    /// Process entity id.
    pub process_instance_id: String,
    /// Host id.
    pub host_id: String,
    /// Host PID.
    pub host_pid: u32,
    /// Start ticks (field 22 of `/proc/PID/stat`).
    pub start_ticks: u64,
    /// Parent process entity id, when the parent was observed.
    pub parent_process_instance_id: Option<String>,
    /// Parent host PID.
    pub parent_host_pid: Option<u32>,
    /// Executable path when readable.
    pub executable: Option<String>,
    /// Process name (`comm`).
    pub comm: String,
    /// Recognized tool id.
    pub tool: Option<String>,
    /// Role label.
    pub role: Option<String>,
    /// systemd unit.
    pub unit: Option<String>,
    /// Container id/name.
    pub container: Option<String>,
    /// Terminal session id.
    pub session: Option<String>,
    /// Cgroup entity id.
    pub cgroup_entity_id: Option<String>,
    /// Start wall clock.
    pub start_wall_ns: i64,
    /// Start monotonic clock.
    pub start_mono_ns: i64,
}

/// Integration state row (guide §11.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrationStateRow {
    /// Integration id.
    pub integration_id: String,
    /// Configured state (`enabled`, `disabled`, `auto`).
    pub configured_state: String,
    /// Detected state (`available`, `unavailable`, `partial`, `unknown`).
    pub detected_state: String,
    /// Detected tool version, if known.
    pub version: Option<String>,
    /// Claimed capabilities JSON.
    pub capabilities_json: Option<String>,
    /// Last successful detection, wall clock.
    pub last_seen_wall_ns: Option<i64>,
    /// Last error, bounded.
    pub last_error: Option<String>,
}

/// Log source row persisted at run start for report transparency.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogSourceRow {
    /// Configured source id.
    pub source_id: String,
    /// `file` or `docker`.
    pub kind: String,
    /// Bounded target description.
    pub target: String,
    /// Entity/tool hint.
    pub entity_hint: Option<String>,
    /// Per-source line cap.
    pub max_lines: Option<usize>,
    /// Per-source byte cap.
    pub max_bytes: Option<u64>,
}

/// A single database write with its degradation priority.
#[derive(Debug, Clone)]
pub struct WriteItem {
    /// Priority; the writer drops [`WritePriority::Low`] first under pressure.
    pub priority: WritePriority,
    /// The record to persist.
    pub record: WriteRecord,
}

impl WriteItem {
    /// Low-priority record (INFO logs, low-value samples).
    pub fn low(record: WriteRecord) -> Self {
        WriteItem {
            priority: WritePriority::Low,
            record,
        }
    }

    /// Normal-priority record.
    pub fn normal(record: WriteRecord) -> Self {
        WriteItem {
            priority: WritePriority::Normal,
            record,
        }
    }

    /// Critical record (incidents, critical logs, gaps).
    pub fn critical(record: WriteRecord) -> Self {
        WriteItem {
            priority: WritePriority::Critical,
            record,
        }
    }
}

/// All record types the store accepts.
#[derive(Debug, Clone)]
pub enum WriteRecord {
    /// Key/value metadata (host id, clock ticks per second, ...).
    Meta { key: String, value: String },
    /// Host identity upsert.
    Host(HostInfo),
    /// One entity upsert.
    Entity(Entity),
    /// One relationship (ignored when already present).
    Relationship(Relationship),
    /// A process lifetime start/edit.
    ProcessLifetime(ProcessLifetimeRow),
    /// A process lifetime end update.
    ProcessLifetimeEnd {
        /// Process entity id.
        process_instance_id: String,
        /// End wall clock.
        end_wall_ns: i64,
        /// End monotonic clock.
        end_mono_ns: i64,
        /// Why the lifetime ended (`exited`, `lost`, `reconciled`).
        reason: String,
    },
    /// Host sample.
    HostSample(HostSample),
    /// cgroup sample.
    CgroupSample(CgroupSample),
    /// Process sample.
    ProcessSample(ProcessSample),
    /// Event.
    Event(EventRecord),
    /// Log record.
    Log(LogRecord),
    /// Incident open/insert (incident id pre-allocated by the analysis layer).
    Incident(Incident),
    /// Incident update/close.
    IncidentUpdate {
        /// Incident id.
        incident_id: i64,
        /// End wall clock, if closing.
        ended_wall_ns: Option<i64>,
        /// Updated peak.
        peak: f64,
        /// Additional evidence JSON.
        evidence: Option<serde_json::Value>,
        /// Whether evidence was lost.
        evidence_loss: bool,
    },
    /// Collector health upsert.
    CollectorHealth(CollectorHealth),
    /// Integration state upsert.
    IntegrationState(IntegrationStateRow),
    /// Log source upsert.
    LogSource(LogSourceRow),
    /// Coverage gap (open or refresh).
    Gap(CoverageGap),
    /// Coverage gap resolution.
    GapResolved {
        /// Source id.
        source_id: String,
        /// Gap kind.
        kind: String,
        /// Gap detail (part of the unique key).
        detail: String,
        /// Resolution wall clock.
        resolved_wall_ns: i64,
    },
}

/// Maximum bytes stored in an event payload JSON document.
pub const MAX_EVENT_JSON_BYTES: usize = 8 * 1024;
/// Maximum bytes stored in incident evidence JSON.
pub const MAX_EVIDENCE_JSON_BYTES: usize = 64 * 1024;
/// Maximum bytes stored for one log message in the database.
pub const MAX_LOG_STORED_BYTES: usize = 16 * 1024;
/// Maximum bytes stored in entity labels JSON.
pub const MAX_LABELS_JSON_BYTES: usize = 2 * 1024;

impl Store {
    /// Open (or create) the database at `path`, apply pragmas and migrations.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|err| Error::io(parent, err))?;
            }
        }
        let existed = path.is_file();
        let conn = Connection::open(path).map_err(|err| Error::Storage(format!(
            "cannot open database {}: {err}",
            path.display()
        )))?;
        let mut store = Store {
            conn,
            path: path.to_path_buf(),
        };
        store.configure(existed)?;
        store.migrate()?;
        crate::paths::restrict_file_permissions(path);
        Ok(store)
    }

    /// Open a private in-memory database (tests, `sarf benchmark --dry-run`).
    pub fn open_in_memory() -> Result<Self> {
        let conn =
            Connection::open_in_memory().map_err(|err| Error::Storage(format!("in-memory db: {err}")))?;
        let mut store = Store {
            conn,
            path: PathBuf::from(":memory:"),
        };
        store.configure(false)?;
        store.migrate()?;
        Ok(store)
    }

    /// Open an existing database read-only (CLI queries never take the writer lock).
    pub fn open_read_only(path: &Path) -> Result<Self> {
        if !path.is_file() {
            return Err(Error::Storage(format!(
                "database {} does not exist; run `sarf run` or `sarf init` first",
                path.display()
            )));
        }
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
        )
        .map_err(|err| Error::Storage(format!("cannot open {}: {err}", path.display())))?;
        let _ = conn.busy_timeout(std::time::Duration::from_millis(5000));
        let _ = conn.pragma_update(None, "query_only", true);
        Ok(Store {
            conn,
            path: path.to_path_buf(),
        })
    }

    /// Path this store was opened from.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Underlying connection (queries only).
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    /// Mutable connection (retention/tests that need transactions).
    pub fn connection_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }

    fn configure(&self, existed: bool) -> Result<()> {
        let pragma = |sql: &str| -> Result<()> {
            self.conn
                .execute_batch(sql)
                .map_err(|err| Error::Storage(format!("pragma {sql}: {err}")))
        };
        // WAL is unsuitable for private in-memory databases.
        if self.path != PathBuf::from(":memory:") {
            pragma("PRAGMA journal_mode = WAL;")?;
        }
        pragma("PRAGMA synchronous = NORMAL;")?;
        pragma("PRAGMA busy_timeout = 5000;")?;
        pragma("PRAGMA foreign_keys = ON;")?;
        pragma("PRAGMA cache_size = -2000;")?;
        pragma("PRAGMA temp_store = MEMORY;")?;
        pragma("PRAGMA wal_autocheckpoint = 1000;")?;
        if !existed && self.path != PathBuf::from(":memory:") {
            // auto_vacuum must be configured before the first table is created.
            pragma("PRAGMA auto_vacuum = INCREMENTAL;")?;
            pragma("VACUUM;")?;
        }
        Ok(())
    }

    /// Apply pending migrations based on `PRAGMA user_version`.
    pub fn migrate(&mut self) -> Result<()> {
        let version: i64 = self
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(|err| Error::Storage(format!("read user_version: {err}")))?;
        if version > schema::SCHEMA_VERSION {
            return Err(Error::Storage(format!(
                "database schema {} is newer than this SARF build ({}); upgrade SARF",
                version,
                schema::SCHEMA_VERSION
            )));
        }
        if version < 1 {
            let tx = self
                .conn
                .transaction()
                .map_err(|err| Error::Storage(format!("begin migration: {err}")))?;
            tx.execute_batch(schema::MIGRATION_1)
                .map_err(|err| Error::Storage(format!("apply schema v1: {err}")))?;
            tx.execute_batch(&format!("PRAGMA user_version = {};", schema::SCHEMA_VERSION))
                .map_err(|err| Error::Storage(format!("set user_version: {err}")))?;
            tx.commit()
                .map_err(|err| Error::Storage(format!("commit migration: {err}")))?;
        }
        Ok(())
    }

    /// Schema version currently stored in the database.
    pub fn schema_version(&self) -> Result<i64> {
        self.conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(|err| Error::Storage(format!("read user_version: {err}")))
    }

    /// Persist one batch atomically, in a single transaction. Returns record count.
    pub fn write(&mut self, items: &[WriteItem]) -> Result<usize> {
        if items.is_empty() {
            return Ok(0);
        }
        let tx = self
            .conn
            .transaction()
            .map_err(|err| Error::Storage(format!("begin batch: {err}")))?;
        let mut written = 0usize;
        for item in items {
            Self::write_one(&tx, &item.record)?;
            written += 1;
        }
        tx.commit()
            .map_err(|err| Error::Storage(format!("commit batch: {err}")))?;
        Ok(written)
    }

    fn write_one(tx: &rusqlite::Transaction<'_>, record: &WriteRecord) -> Result<()> {
        let map = |err: rusqlite::Error| Error::Storage(format!("insert failed: {err}"));
        match record {
            WriteRecord::Meta { key, value } => {
                tx.prepare_cached(
                    "INSERT INTO meta(key, value) VALUES (?1, ?2)
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                )
                .map_err(map)?
                .execute(params![key, value])
                .map_err(map)?;
            }
            WriteRecord::Host(info) => {
                tx.prepare_cached(
                    "INSERT INTO hosts(host_id, boot_id, hostname, kernel_release, architecture, first_seen_wall_ns)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                     ON CONFLICT(host_id) DO UPDATE SET
                        boot_id = excluded.boot_id,
                        hostname = excluded.hostname,
                        kernel_release = excluded.kernel_release,
                        architecture = excluded.architecture",
                )
                .map_err(map)?
                .execute(params![
                    info.host_id,
                    info.boot_id,
                    info.hostname,
                    info.kernel_release,
                    info.architecture,
                    info.first_seen_wall_ns,
                ])
                .map_err(map)?;
            }
            WriteRecord::Entity(entity) => {
                let labels = bounded_json(
                    &serde_json::to_value(&entity.labels).unwrap_or(serde_json::Value::Null),
                    MAX_LABELS_JSON_BYTES,
                );
                tx.prepare_cached(
                    "INSERT INTO entities(entity_id, kind, stable_key, name, source, labels_json,
                                          first_seen_wall_ns, last_seen_wall_ns)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                     ON CONFLICT(entity_id) DO UPDATE SET
                        name = excluded.name,
                        source = excluded.source,
                        labels_json = excluded.labels_json,
                        last_seen_wall_ns = MAX(entities.last_seen_wall_ns, excluded.last_seen_wall_ns)",
                )
                .map_err(map)?
                .execute(params![
                    entity.entity_id,
                    entity.kind.as_str(),
                    entity.stable_key,
                    entity.name,
                    entity.source,
                    labels,
                    entity.first_seen_wall_ns,
                    entity.last_seen_wall_ns,
                ])
                .map_err(map)?;
            }
            WriteRecord::Relationship(rel) => {
                tx.prepare_cached(
                    "INSERT OR IGNORE INTO relationships(from_entity_id, to_entity_id, relation,
                                                         valid_from_mono_ns, valid_to_mono_ns, provenance, confidence)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                )
                .map_err(map)?
                .execute(params![
                    rel.from_entity_id,
                    rel.to_entity_id,
                    rel.relation.as_str(),
                    rel.valid_from_mono_ns,
                    rel.valid_to_mono_ns,
                    rel.provenance,
                    rel.confidence,
                ])
                .map_err(map)?;
            }
            WriteRecord::ProcessLifetime(row) => {
                tx.prepare_cached(
                    "INSERT INTO process_lifetimes(
                        process_instance_id, host_id, host_pid, start_ticks,
                        parent_process_instance_id, parent_host_pid, executable, comm,
                        tool, role, unit, container, session, cgroup_entity_id,
                        start_wall_ns, start_mono_ns)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)
                     ON CONFLICT(process_instance_id) DO UPDATE SET
                        executable = COALESCE(excluded.executable, process_lifetimes.executable),
                        tool = COALESCE(excluded.tool, process_lifetimes.tool),
                        role = COALESCE(excluded.role, process_lifetimes.role),
                        unit = COALESCE(excluded.unit, process_lifetimes.unit),
                        container = COALESCE(excluded.container, process_lifetimes.container),
                        session = COALESCE(excluded.session, process_lifetimes.session),
                        cgroup_entity_id = COALESCE(excluded.cgroup_entity_id, process_lifetimes.cgroup_entity_id)",
                )
                .map_err(map)?
                .execute(params![
                    row.process_instance_id,
                    row.host_id,
                    row.host_pid,
                    to_sql_i64(row.start_ticks),
                    row.parent_process_instance_id,
                    row.parent_host_pid,
                    row.executable,
                    row.comm,
                    row.tool,
                    row.role,
                    row.unit,
                    row.container,
                    row.session,
                    row.cgroup_entity_id,
                    row.start_wall_ns,
                    row.start_mono_ns,
                ])
                .map_err(map)?;
            }
            WriteRecord::ProcessLifetimeEnd {
                process_instance_id,
                end_wall_ns,
                end_mono_ns,
                reason,
            } => {
                tx.prepare_cached(
                    "UPDATE process_lifetimes
                        SET end_wall_ns = ?2, end_mono_ns = ?3, end_reason = ?4
                      WHERE process_instance_id = ?1",
                )
                .map_err(map)?
                .execute(params![process_instance_id, end_wall_ns, end_mono_ns, reason])
                .map_err(map)?;
            }
            WriteRecord::HostSample(sample) => {
                let s = &sample.stamps;
                if s.boot_id.is_empty() {
                    return Err(Error::Storage(
                        "host sample is missing its boot id (clock context is required)".into(),
                    ));
                }
                tx.prepare_cached(
                    "INSERT OR REPLACE INTO host_samples(
                        boot_id, mono_ts_ns, wall_ts_ns, clock_domain,
                        cpu_user_ticks, cpu_nice_ticks, cpu_system_ticks, cpu_idle_ticks,
                        cpu_iowait_ticks, cpu_irq_ticks, cpu_softirq_ticks, cpu_steal_ticks,
                        mem_total_bytes, mem_available_bytes, mem_free_bytes,
                        swap_total_bytes, swap_free_bytes,
                        load1, load5, load15, procs_running, procs_blocked,
                        psi_cpu_some_avg10, psi_cpu_some_total_us,
                        psi_mem_some_avg10, psi_mem_some_total_us,
                        psi_io_some_avg10, psi_io_some_total_us,
                        net_rx_bytes, net_tx_bytes, disk_read_bytes, disk_write_bytes,
                        uptime_secs, boot_time_secs)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                             ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26,
                             ?27, ?28, ?29, ?30, ?31, ?32, ?33, ?34)",
                )
                .map_err(map)?
                .execute(params![
                    s.boot_id,
                    s.mono,
                    s.wall,
                    s.domain.as_str(),
                    to_sql_i64(sample.cpu.user),
                    to_sql_i64(sample.cpu.nice),
                    to_sql_i64(sample.cpu.system),
                    to_sql_i64(sample.cpu.idle),
                    to_sql_i64(sample.cpu.iowait),
                    to_sql_i64(sample.cpu.irq),
                    to_sql_i64(sample.cpu.softirq),
                    to_sql_i64(sample.cpu.steal),
                    to_sql_i64(sample.mem.total),
                    to_sql_opt_i64(sample.mem.available),
                    to_sql_opt_i64(sample.mem.free),
                    to_sql_opt_i64(sample.mem.swap_total),
                    to_sql_opt_i64(sample.mem.swap_free),
                    sample.load.one,
                    sample.load.five,
                    sample.load.fifteen,
                    sample.procs_running.map(to_sql_i64),
                    sample.procs_blocked.map(to_sql_i64),
                    sample.pressure.cpu.and_then(|p| p.some_avg10),
                    sample.pressure.cpu.and_then(|p| p.some_total_us).map(to_sql_i64),
                    sample.pressure.memory.and_then(|p| p.some_avg10),
                    sample
                        .pressure
                        .memory
                        .and_then(|p| p.some_total_us)
                        .map(to_sql_i64),
                    sample.pressure.io.and_then(|p| p.some_avg10),
                    sample.pressure.io.and_then(|p| p.some_total_us).map(to_sql_i64),
                    to_sql_i64(sum_net(&sample.net, |n| n.rx_bytes)),
                    to_sql_i64(sum_net(&sample.net, |n| n.tx_bytes)),
                    to_sql_i64(sum_disk(&sample.disk, |d| d.read_bytes)),
                    to_sql_i64(sum_disk(&sample.disk, |d| d.write_bytes)),
                    sample.uptime_secs,
                    sample.boot_time_secs.map(to_sql_i64),
                ])
                .map_err(map)?;
            }
            WriteRecord::CgroupSample(sample) => {
                let s = &sample.stamps;
                if s.boot_id.is_empty() {
                    return Err(Error::Storage(
                        "cgroup sample is missing its boot id (clock context is required)".into(),
                    ));
                }
                let io_json = bounded_json(
                    &serde_json::to_value(&sample.io).unwrap_or(serde_json::Value::Null),
                    MAX_EVENT_JSON_BYTES,
                );
                tx.prepare_cached(
                    "INSERT OR REPLACE INTO cgroup_samples(
                        boot_id, mono_ts_ns, wall_ts_ns, entity_id, path,
                        cpu_usage_usec, cpu_user_usec, cpu_system_usec,
                        cpu_nr_periods, cpu_nr_throttled, cpu_throttled_usec,
                        memory_current_bytes, memory_peak_bytes, memory_max_bytes,
                        memory_anon_bytes, memory_file_bytes, memory_swap_bytes,
                        cpu_quota_usec, cpu_period_usec, pids_current,
                        psi_cpu_some_avg10, psi_mem_some_avg10, psi_io_some_avg10, io_json)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                             ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24)",
                )
                .map_err(map)?
                .execute(params![
                    s.boot_id,
                    s.mono,
                    s.wall,
                    sample.entity_id,
                    sample.path,
                    to_sql_opt_i64(sample.cpu_usage_usec),
                    to_sql_opt_i64(sample.cpu_user_usec),
                    to_sql_opt_i64(sample.cpu_system_usec),
                    to_sql_opt_i64(sample.cpu_nr_periods),
                    to_sql_opt_i64(sample.cpu_nr_throttled),
                    to_sql_opt_i64(sample.cpu_throttled_usec),
                    to_sql_opt_i64(sample.memory_current),
                    to_sql_opt_i64(sample.memory_peak),
                    to_sql_opt_i64(sample.memory_max),
                    to_sql_opt_i64(sample.memory_anon),
                    to_sql_opt_i64(sample.memory_file),
                    to_sql_opt_i64(sample.memory_swap),
                    to_sql_opt_i64(sample.cpu_quota_usec),
                    to_sql_opt_i64(sample.cpu_period_usec),
                    to_sql_opt_i64(sample.pids_current),
                    sample.psi_cpu.and_then(|p| p.some_avg10),
                    sample.psi_memory.and_then(|p| p.some_avg10),
                    sample.psi_io.and_then(|p| p.some_avg10),
                    io_json,
                ])
                .map_err(map)?;
            }
            WriteRecord::ProcessSample(sample) => {
                let s = &sample.stamps;
                tx.prepare_cached(
                    "INSERT OR REPLACE INTO process_samples(
                        mono_ts_ns, wall_ts_ns, process_instance_id,
                        cpu_user_ticks, cpu_system_ticks, rss_bytes, virtual_bytes,
                        read_bytes, write_bytes, read_chars, write_chars,
                        threads, state, sample_flags)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                )
                .map_err(map)?
                .execute(params![
                    s.mono,
                    s.wall,
                    sample.process_instance_id,
                    to_sql_i64(sample.cpu_user_ticks),
                    to_sql_i64(sample.cpu_system_ticks),
                    to_sql_opt_i64(sample.rss_bytes),
                    to_sql_opt_i64(sample.virtual_bytes),
                    to_sql_opt_i64(sample.read_bytes),
                    to_sql_opt_i64(sample.write_bytes),
                    to_sql_opt_i64(sample.read_chars),
                    to_sql_opt_i64(sample.write_chars),
                    sample.threads,
                    sample.state.map(|c| c.to_string()),
                    sample.sample_flags,
                ])
                .map_err(map)?;
            }
            WriteRecord::Event(event) => {
                tx.prepare_cached(
                    "INSERT INTO events(wall_ts_ns, mono_ts_ns, entity_id, kind, severity,
                                        payload_json, provenance, lost_before)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                )
                .map_err(map)?
                .execute(params![
                    event.wall_ns,
                    event.mono_ns,
                    event.entity_id,
                    event.kind.as_str(),
                    event.severity.as_str(),
                    bounded_json(&event.payload, MAX_EVENT_JSON_BYTES),
                    event.provenance,
                    event.lost_before as i64,
                ])
                .map_err(map)?;
            }
            WriteRecord::Log(log) => {
                let (message, truncated) = truncate_utf8(&log.message, MAX_LOG_STORED_BYTES);
                tx.prepare_cached(
                    "INSERT INTO logs(wall_ts_ns, mono_ts_ns, entity_id, source_id, stream,
                                      level, message, truncated, redacted, incident_id)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                )
                .map_err(map)?
                .execute(params![
                    log.wall_ns,
                    log.mono_ns,
                    log.entity_id,
                    log.source_id,
                    log.stream.as_str(),
                    log.level.map(|l| l.as_str()),
                    message,
                    truncated || log.truncated,
                    log.redacted,
                    log.incident_id,
                ])
                .map_err(map)?;
            }
            WriteRecord::Incident(incident) => {
                tx.prepare_cached(
                    "INSERT OR REPLACE INTO incidents(
                        incident_id, started_wall_ns, ended_wall_ns, entity_id, metric,
                        reason, peak, baseline, evidence_json, acknowledged, evidence_loss)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                )
                .map_err(map)?
                .execute(params![
                    incident.incident_id,
                    incident.started_wall_ns,
                    incident.ended_wall_ns,
                    incident.entity_id,
                    incident.metric.as_str(),
                    incident.reason,
                    incident.peak,
                    incident.baseline,
                    bounded_json(&incident.evidence, MAX_EVIDENCE_JSON_BYTES),
                    incident.acknowledged,
                    incident.evidence_loss,
                ])
                .map_err(map)?;
            }
            WriteRecord::IncidentUpdate {
                incident_id,
                ended_wall_ns,
                peak,
                evidence,
                evidence_loss,
            } => {
                let evidence_json = evidence
                    .as_ref()
                    .map(|value| bounded_json(value, MAX_EVIDENCE_JSON_BYTES));
                tx.prepare_cached(
                    "UPDATE incidents SET
                        ended_wall_ns = COALESCE(?2, ended_wall_ns),
                        peak = MAX(peak, ?3),
                        evidence_json = COALESCE(?4, evidence_json),
                        evidence_loss = MAX(evidence_loss, ?5)
                      WHERE incident_id = ?1",
                )
                .map_err(map)?
                .execute(params![
                    incident_id,
                    ended_wall_ns,
                    peak,
                    evidence_json,
                    evidence_loss,
                ])
                .map_err(map)?;
            }
            WriteRecord::CollectorHealth(health) => {
                tx.prepare_cached(
                    "INSERT INTO collector_health(
                        collector_id, configured_state, availability, permission_state,
                        last_success_wall_ns, last_error_wall_ns, last_error,
                        error_count, received_count, persisted_count, dropped_count,
                        truncated_count, queue_high_water, coverage_json)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
                     ON CONFLICT(collector_id) DO UPDATE SET
                        configured_state = excluded.configured_state,
                        availability = excluded.availability,
                        permission_state = excluded.permission_state,
                        last_success_wall_ns = excluded.last_success_wall_ns,
                        last_error_wall_ns = excluded.last_error_wall_ns,
                        last_error = excluded.last_error,
                        error_count = excluded.error_count,
                        received_count = excluded.received_count,
                        persisted_count = excluded.persisted_count,
                        dropped_count = excluded.dropped_count,
                        truncated_count = excluded.truncated_count,
                        queue_high_water = MAX(collector_health.queue_high_water, excluded.queue_high_water),
                        coverage_json = excluded.coverage_json",
                )
                .map_err(map)?
                .execute(params![
                    health.collector_id,
                    health.configured.as_str(),
                    health.availability.as_str(),
                    health.permission.as_str(),
                    health.last_success_wall_ns,
                    health.last_error_wall_ns,
                    health.last_error.as_deref().map(|e| truncate_utf8(e, 512).0),
                    health.error_count as i64,
                    health.received_count as i64,
                    health.persisted_count as i64,
                    health.dropped_count as i64,
                    health.truncated_count as i64,
                    health.queue_high_water as i64,
                    bounded_json(&health.coverage, MAX_EVENT_JSON_BYTES),
                ])
                .map_err(map)?;
            }
            WriteRecord::IntegrationState(state) => {
                tx.prepare_cached(
                    "INSERT INTO integration_state(
                        integration_id, configured_state, detected_state, version,
                        capabilities_json, last_seen_wall_ns, last_error)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                     ON CONFLICT(integration_id) DO UPDATE SET
                        configured_state = excluded.configured_state,
                        detected_state = excluded.detected_state,
                        version = excluded.version,
                        capabilities_json = excluded.capabilities_json,
                        last_seen_wall_ns = excluded.last_seen_wall_ns,
                        last_error = excluded.last_error",
                )
                .map_err(map)?
                .execute(params![
                    state.integration_id,
                    state.configured_state,
                    state.detected_state,
                    state.version,
                    state.capabilities_json,
                    state.last_seen_wall_ns,
                    state.last_error.as_deref().map(|e| truncate_utf8(e, 512).0),
                ])
                .map_err(map)?;
            }
            WriteRecord::LogSource(source) => {
                tx.prepare_cached(
                    "INSERT INTO log_sources(source_id, kind, target, entity_hint, max_lines, max_bytes)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                     ON CONFLICT(source_id) DO UPDATE SET
                        kind = excluded.kind,
                        target = excluded.target,
                        entity_hint = excluded.entity_hint,
                        max_lines = excluded.max_lines,
                        max_bytes = excluded.max_bytes",
                )
                .map_err(map)?
                .execute(params![
                    source.source_id,
                    source.kind,
                    truncate_utf8(&source.target, 1024).0,
                    source.entity_hint,
                    source.max_lines.map(|value| to_sql_i64(value as u64)),
                    to_sql_opt_i64(source.max_bytes),
                ])
                .map_err(map)?;
            }
            WriteRecord::Gap(gap) => {
                tx.prepare_cached(
                    "INSERT INTO coverage_gaps(source_id, kind, detail, since_wall_ns, resolved_wall_ns)
                     VALUES (?1, ?2, ?3, ?4, NULL)
                     ON CONFLICT(source_id, kind, detail) DO UPDATE SET
                        since_wall_ns = COALESCE(coverage_gaps.since_wall_ns, excluded.since_wall_ns),
                        resolved_wall_ns = NULL",
                )
                .map_err(map)?
                .execute(params![
                    gap.source_id,
                    gap.kind,
                    truncate_utf8(&gap.detail, 1024).0,
                    gap.since_wall_ns,
                ])
                .map_err(map)?;
            }
            WriteRecord::GapResolved {
                source_id,
                kind,
                detail,
                resolved_wall_ns,
            } => {
                tx.prepare_cached(
                    "UPDATE coverage_gaps SET resolved_wall_ns = ?4
                      WHERE source_id = ?1 AND kind = ?2 AND detail = ?3",
                )
                .map_err(map)?
                .execute(params![source_id, kind, detail, resolved_wall_ns])
                .map_err(map)?;
            }
        }
        Ok(())
    }

    /// Begin a run row and return its id.
    pub fn begin_run(
        &mut self,
        host_id: &str,
        started_wall_ns: i64,
        version: &str,
        simulated: bool,
        note: Option<&str>,
    ) -> Result<i64> {
        self.conn
            .execute(
                "INSERT INTO runs(host_id, started_wall_ns, stopped_wall_ns, version, simulated, note)
                 VALUES (?1, ?2, NULL, ?3, ?4, ?5)",
                params![host_id, started_wall_ns, version, simulated, note],
            )
            .map_err(|err| Error::Storage(format!("begin run: {err}")))?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Close a run row.
    pub fn end_run(&mut self, run_id: i64, stopped_wall_ns: i64) -> Result<()> {
        self.conn
            .execute(
                "UPDATE runs SET stopped_wall_ns = ?2 WHERE run_id = ?1",
                params![run_id, stopped_wall_ns],
            )
            .map_err(|err| Error::Storage(format!("end run: {err}")))?;
        Ok(())
    }

    /// Read a metadata value.
    pub fn meta_get(&self, key: &str) -> Result<Option<String>> {
        self.conn
            .query_row("SELECT value FROM meta WHERE key = ?1", params![key], |row| {
                row.get::<_, String>(0)
            })
            .optional()
            .map_err(|err| Error::Storage(format!("meta get: {err}")))
    }

    /// Maximum incident id currently stored (0 when none).
    pub fn max_incident_id(&self) -> Result<i64> {
        self.conn
            .query_row("SELECT COALESCE(MAX(incident_id), 0) FROM incidents", [], |row| {
                row.get(0)
            })
            .map_err(|err| Error::Storage(format!("max incident id: {err}")))
    }

    /// Run `PRAGMA wal_checkpoint(TRUNCATE)` and return `(busy, wal_frames, checkpointed)`.
    pub fn checkpoint(&self) -> Result<(i64, i64, i64)> {
        self.conn
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .map_err(|err| Error::Storage(format!("wal checkpoint: {err}")))
    }
}

fn sum_net(
    counters: &std::collections::BTreeMap<String, crate::model::NetCounters>,
    field: impl Fn(&crate::model::NetCounters) -> u64,
) -> u64 {
    counters.values().map(|c| field(c)).fold(0u64, |acc, v| acc.saturating_add(v))
}

fn sum_disk(
    counters: &std::collections::BTreeMap<String, crate::model::DiskCounters>,
    field: impl Fn(&crate::model::DiskCounters) -> u64,
) -> u64 {
    counters.values().map(|c| field(c)).fold(0u64, |acc, v| acc.saturating_add(v))
}

/// Serialize JSON with a byte bound; returns `"{}"` style placeholder on failure.
fn bounded_json(value: &serde_json::Value, max_bytes: usize) -> String {
    let text = serde_json::to_string(value).unwrap_or_else(|_| "null".to_string());
    let (text, _) = truncate_utf8(&text, max_bytes);
    text
}

/// Truncate a string to at most `max_bytes` on a UTF-8 boundary.
///
/// Returns the (possibly shortened) string and whether truncation happened.
pub fn truncate_utf8(text: &str, max_bytes: usize) -> (String, bool) {
    if text.len() <= max_bytes {
        return (text.to_string(), false);
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    (text[..end].to_string(), true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;
    use crate::time::{ClockDomain, Stamps};

    fn stamps(wall: i64, mono: i64) -> Stamps {
        Stamps::new(wall, mono, "test-boot", ClockDomain::Simulated)
    }

    fn store() -> Store {
        Store::open_in_memory().expect("in-memory store")
    }

    fn host_sample(wall: i64, mono: i64) -> HostSample {
        HostSample {
            stamps: stamps(wall, mono),
            cpu: CpuTimes {
                user: 100,
                idle: 900,
                ..Default::default()
            },
            mem: MemSnapshot {
                total: 1024 * 1024,
                available: Some(512 * 1024),
                ..Default::default()
            },
            load: LoadAvg {
                one: 0.5,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn migration_sets_version() {
        let store = store();
        assert_eq!(store.schema_version().expect("version"), 1);
    }

    #[test]
    fn all_record_kinds_roundtrip() {
        let mut store = store();
        let now = 1_000_000_000_000;
        let entity = Entity {
            entity_id: "host:h1".into(),
            kind: EntityKind::Host,
            stable_key: "h1".into(),
            name: "test-host".into(),
            source: "test".into(),
            labels: [("env".to_string(), "test".to_string())].into_iter().collect(),
            first_seen_wall_ns: now,
            last_seen_wall_ns: now,
        };
        let lifetime = ProcessLifetimeRow {
            process_instance_id: "proc:aa:1:2".into(),
            host_id: "h1".into(),
            host_pid: 1,
            start_ticks: 2,
            parent_process_instance_id: None,
            parent_host_pid: None,
            executable: Some("/usr/bin/nginx".into()),
            comm: "nginx".into(),
            tool: Some("nginx".into()),
            role: Some("nginx master".into()),
            unit: None,
            container: None,
            session: None,
            cgroup_entity_id: None,
            start_wall_ns: now,
            start_mono_ns: 10,
        };
        let health = CollectorHealth {
            collector_id: "procfs".into(),
            configured: ConfiguredState::Enabled,
            availability: Availability::Available,
            permission: PermissionState::Permitted,
            last_success_wall_ns: Some(now),
            last_error_wall_ns: None,
            last_error: None,
            error_count: 0,
            received_count: 10,
            persisted_count: 10,
            dropped_count: 0,
            truncated_count: 0,
            queue_high_water: 2,
            coverage: serde_json::json!({"per_process_io": true}),
        };
        let incident = Incident {
            incident_id: Some(7),
            started_wall_ns: now,
            ended_wall_ns: None,
            entity_id: Some("cgroup:1:2".into()),
            metric: Metric::Cpu,
            reason: "cpu threshold".into(),
            peak: 42.0,
            baseline: 3.0,
            evidence: serde_json::json!({"top": ["nginx"]}),
            acknowledged: false,
            evidence_loss: false,
        };
        let items = vec![
            WriteItem::normal(WriteRecord::Meta {
                key: "host_id".into(),
                value: "h1".into(),
            }),
            WriteItem::normal(WriteRecord::Host(HostInfo {
                host_id: "h1".into(),
                boot_id: "boot".into(),
                hostname: "test-host".into(),
                kernel_release: "6.8.0".into(),
                architecture: "x86_64".into(),
                first_seen_wall_ns: now,
            })),
            WriteItem::normal(WriteRecord::Entity(entity)),
            WriteItem::normal(WriteRecord::ProcessLifetime(lifetime)),
            WriteItem::normal(WriteRecord::ProcessLifetimeEnd {
                process_instance_id: "proc:aa:1:2".into(),
                end_wall_ns: now + 5,
                end_mono_ns: 15,
                reason: "exited".into(),
            }),
            WriteItem::normal(WriteRecord::HostSample(host_sample(now, 10))),
            WriteItem::normal(WriteRecord::CgroupSample(CgroupSample {
                stamps: stamps(now, 10),
                entity_id: "cgroup:1:2".into(),
                path: "/system.slice/nginx.service".into(),
                cpu_usage_usec: Some(1000),
                memory_current: Some(2048),
                ..Default::default()
            })),
            WriteItem::normal(WriteRecord::ProcessSample(ProcessSample {
                stamps: stamps(now, 10),
                process_instance_id: "proc:aa:1:2".into(),
                cpu_user_ticks: 1,
                cpu_system_ticks: 2,
                rss_bytes: Some(4096),
                virtual_bytes: Some(8192),
                read_bytes: Some(0),
                write_bytes: Some(0),
                read_chars: Some(0),
                write_chars: Some(0),
                threads: Some(4),
                state: Some('S'),
                sample_flags: 0,
            })),
            WriteItem::normal(WriteRecord::Event(EventRecord {
                wall_ns: now,
                mono_ns: Some(10),
                entity_id: Some("proc:aa:1:2".into()),
                kind: EventKind::ProcessStarted,
                severity: Severity::Info,
                payload: serde_json::json!({"comm": "nginx"}),
                provenance: "procfs".into(),
                lost_before: 0,
            })),
            WriteItem::normal(WriteRecord::Log(LogRecord {
                wall_ns: now,
                mono_ns: Some(10),
                source_id: "nginx-error".into(),
                entity_id: Some("proc:aa:1:2".into()),
                stream: LogStream::File,
                level: Some(Severity::Error),
                message: "upstream timed out".into(),
                truncated: false,
                incident_id: Some(7),
                redacted: false,
            })),
            WriteItem::critical(WriteRecord::Incident(incident)),
            WriteItem::normal(WriteRecord::IncidentUpdate {
                incident_id: 7,
                ended_wall_ns: Some(now + 10),
                peak: 55.0,
                evidence: Some(serde_json::json!({"closed": true})),
                evidence_loss: true,
            }),
            WriteItem::normal(WriteRecord::CollectorHealth(health)),
            WriteItem::normal(WriteRecord::IntegrationState(IntegrationStateRow {
                integration_id: "docker".into(),
                configured_state: "auto".into(),
                detected_state: "unavailable".into(),
                version: None,
                capabilities_json: Some("[]".into()),
                last_seen_wall_ns: Some(now),
                last_error: Some("socket absent".into()),
            })),
            WriteItem::normal(WriteRecord::LogSource(LogSourceRow {
                source_id: "nginx-error".into(),
                kind: "file".into(),
                target: "/var/log/nginx/error.log".into(),
                entity_hint: Some("nginx".into()),
                max_lines: None,
                max_bytes: None,
            })),
            WriteItem::normal(WriteRecord::Gap(CoverageGap {
                source_id: "docker".into(),
                kind: "absent_interface".into(),
                since_wall_ns: Some(now),
                detail: "docker socket absent".into(),
            })),
            WriteItem::normal(WriteRecord::GapResolved {
                source_id: "docker".into(),
                kind: "absent_interface".into(),
                detail: "docker socket absent".into(),
                resolved_wall_ns: now + 1,
            }),
        ];
        let written = store.write(&items).expect("write batch");
        assert_eq!(written, items.len());

        let count = |table: &str| -> i64 {
            store
                .connection()
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row.get(0))
                .expect("count")
        };
        for table in [
            "meta",
            "hosts",
            "entities",
            "process_lifetimes",
            "host_samples",
            "cgroup_samples",
            "process_samples",
            "events",
            "logs",
            "incidents",
            "collector_health",
            "integration_state",
            "log_sources",
            "coverage_gaps",
        ] {
            assert_eq!(count(table), 1, "{table} should hold one row");
        }
        // Incident update applied.
        let (ended, peak, loss): (Option<i64>, f64, bool) = store
            .connection()
            .query_row(
                "SELECT ended_wall_ns, peak, evidence_loss FROM incidents WHERE incident_id = 7",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("incident");
        assert_eq!(ended, Some(now + 10));
        assert_eq!(peak, 55.0);
        assert!(loss);
        // Process lifetime closed.
        let reason: Option<String> = store
            .connection()
            .query_row(
                "SELECT end_reason FROM process_lifetimes WHERE process_instance_id = 'proc:aa:1:2'",
                [],
                |row| row.get(0),
            )
            .expect("lifetime");
        assert_eq!(reason.as_deref(), Some("exited"));
        // Gap resolution persisted.
        let resolved: Option<i64> = store
            .connection()
            .query_row("SELECT resolved_wall_ns FROM coverage_gaps", [], |row| row.get(0))
            .expect("gap");
        assert_eq!(resolved, Some(now + 1));
    }

    #[test]
    fn empty_batch_is_a_noop() {
        let mut store = store();
        assert_eq!(store.write(&[]).expect("empty"), 0);
        let count: i64 = store
            .connection()
            .query_row("SELECT COUNT(*) FROM meta", [], |row| row.get(0))
            .expect("count");
        assert_eq!(count, 0);
    }

    #[test]
    fn samples_without_clock_context_are_rejected() {
        let mut store = store();
        let mut sample = host_sample(100, 10);
        sample.stamps.boot_id.clear();
        let err = store
            .write(&[WriteItem::normal(WriteRecord::HostSample(sample))])
            .expect_err("missing boot id must be rejected");
        assert!(err.to_string().contains("boot id"), "{err}");
    }

    #[test]
    fn host_sample_replay_is_idempotent() {
        let mut store = store();
        let sample = WriteItem::normal(WriteRecord::HostSample(host_sample(100, 10)));
        store.write(std::slice::from_ref(&sample)).expect("write");
        store.write(&[sample]).expect("replay");
        let count: i64 = store
            .connection()
            .query_row("SELECT COUNT(*) FROM host_samples", [], |row| row.get(0))
            .expect("count");
        assert_eq!(count, 1);
    }

    #[test]
    fn truncate_utf8_respects_char_boundaries() {
        let (text, truncated) = truncate_utf8("héllo wörld", 6);
        assert!(truncated);
        assert_eq!(text, "héllo");
        assert!(!text.is_char_boundary(text.len()) == false);
        let (same, truncated) = truncate_utf8("short", 100);
        assert_eq!(same, "short");
        assert!(!truncated);
    }

    #[test]
    fn meta_roundtrip_and_max_incident_id() {
        let mut store = store();
        assert_eq!(store.meta_get("missing").expect("get"), None);
        store
            .write(&[WriteItem::normal(WriteRecord::Meta {
                key: "clock_ticks_per_second".into(),
                value: "100".into(),
            })])
            .expect("write");
        assert_eq!(
            store.meta_get("clock_ticks_per_second").expect("get").as_deref(),
            Some("100")
        );
        assert_eq!(store.max_incident_id().expect("max"), 0);
    }

    #[test]
    fn begin_and_end_run() {
        let mut store = store();
        let run = store.begin_run("h1", 100, "0.1.0", false, None).expect("run");
        store.end_run(run, 200).expect("end");
        let stopped: Option<i64> = store
            .connection()
            .query_row("SELECT stopped_wall_ns FROM runs WHERE run_id = ?1", [run], |row| {
                row.get(0)
            })
            .expect("run row");
        assert_eq!(stopped, Some(200));
    }

    #[test]
    fn read_only_store_rejects_writes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sarf.db");
        {
            let mut write_store = Store::open(&path).expect("open");
            write_store
                .write(&[WriteItem::normal(WriteRecord::Meta {
                    key: "k".into(),
                    value: "v".into(),
                })])
                .expect("write");
        }
        let readonly = Store::open_read_only(&path).expect("readonly");
        let err = readonly
            .conn
            .execute("INSERT INTO meta(key, value) VALUES ('x', 'y')", []);
        assert!(err.is_err(), "read-only connection must reject writes");
        assert_eq!(readonly.meta_get("k").expect("meta").as_deref(), Some("v"));
    }

    #[test]
    fn reopen_keeps_schema_and_data() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sarf.db");
        {
            let mut store = Store::open(&path).expect("open");
            store
                .write(&[WriteItem::normal(WriteRecord::Meta {
                    key: "k".into(),
                    value: "v".into(),
                })])
                .expect("write");
        }
        let reopened = Store::open(&path).expect("reopen");
        assert_eq!(reopened.schema_version().expect("version"), 1);
        assert_eq!(reopened.meta_get("k").expect("meta").as_deref(), Some("v"));
    }
}
