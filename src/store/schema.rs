//! SQLite schema and migrations.
//!
//! The schema follows `guide-ChatGPT.md` §11.2/§11.3 with two deliberate, documented
//! extensions: a `runs` table (one row per daemon run, so reports can distinguish
//! observation periods and simulated data from real collection) and `log_sources`
//! (what SARF was configured to ingest). Primary keys include `boot_id` where the
//! monotonic clock resets across reboots.
//!
//! Migrations are applied with `PRAGMA user_version`; every migration is additive
//! and tested against a fresh database and against an existing one.

/// Current schema version. Increment when adding a migration.
pub const SCHEMA_VERSION: i64 = 1;

/// Version-1 schema.
pub const MIGRATION_1: &str = r"
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS hosts (
    host_id            TEXT PRIMARY KEY,
    boot_id            TEXT NOT NULL,
    hostname           TEXT,
    kernel_release     TEXT,
    architecture       TEXT,
    first_seen_wall_ns INTEGER NOT NULL
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS runs (
    run_id           INTEGER PRIMARY KEY,
    host_id          TEXT NOT NULL,
    started_wall_ns  INTEGER NOT NULL,
    stopped_wall_ns  INTEGER,
    version          TEXT NOT NULL,
    simulated        INTEGER NOT NULL DEFAULT 0,
    note             TEXT
);
CREATE INDEX IF NOT EXISTS runs_started ON runs(started_wall_ns);

CREATE TABLE IF NOT EXISTS entities (
    entity_id          TEXT PRIMARY KEY,
    kind               TEXT NOT NULL,
    stable_key         TEXT NOT NULL,
    name               TEXT NOT NULL,
    source             TEXT NOT NULL,
    labels_json        TEXT,
    first_seen_wall_ns INTEGER NOT NULL,
    last_seen_wall_ns  INTEGER NOT NULL,
    UNIQUE(kind, stable_key)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS entities_kind_name ON entities(kind, name);

CREATE TABLE IF NOT EXISTS relationships (
    relationship_id    INTEGER PRIMARY KEY,
    from_entity_id     TEXT NOT NULL,
    to_entity_id       TEXT NOT NULL,
    relation           TEXT NOT NULL,
    valid_from_mono_ns INTEGER NOT NULL,
    valid_to_mono_ns   INTEGER,
    provenance         TEXT NOT NULL,
    confidence         REAL,
    UNIQUE(from_entity_id, to_entity_id, relation, valid_from_mono_ns)
);
CREATE INDEX IF NOT EXISTS relationships_from_time ON relationships(from_entity_id, valid_from_mono_ns);
CREATE INDEX IF NOT EXISTS relationships_to_time   ON relationships(to_entity_id, valid_from_mono_ns);

CREATE TABLE IF NOT EXISTS process_lifetimes (
    process_instance_id        TEXT PRIMARY KEY,
    host_id                    TEXT NOT NULL,
    host_pid                   INTEGER NOT NULL,
    start_ticks                INTEGER NOT NULL,
    parent_process_instance_id TEXT,
    parent_host_pid            INTEGER,
    executable                 TEXT,
    comm                       TEXT NOT NULL,
    tool                       TEXT,
    role                       TEXT,
    unit                       TEXT,
    container                  TEXT,
    session                    TEXT,
    cgroup_entity_id           TEXT,
    start_wall_ns              INTEGER NOT NULL,
    start_mono_ns              INTEGER NOT NULL,
    end_wall_ns                INTEGER,
    end_mono_ns                INTEGER,
    end_reason                 TEXT
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS process_lifetimes_pid_start ON process_lifetimes(host_pid, start_ticks);
CREATE INDEX IF NOT EXISTS process_lifetimes_start     ON process_lifetimes(start_wall_ns);
CREATE INDEX IF NOT EXISTS process_lifetimes_parent    ON process_lifetimes(parent_process_instance_id);

CREATE TABLE IF NOT EXISTS host_samples (
    boot_id               TEXT NOT NULL,
    mono_ts_ns            INTEGER NOT NULL,
    wall_ts_ns            INTEGER NOT NULL,
    clock_domain          TEXT NOT NULL,
    cpu_user_ticks        INTEGER NOT NULL,
    cpu_nice_ticks        INTEGER NOT NULL,
    cpu_system_ticks      INTEGER NOT NULL,
    cpu_idle_ticks        INTEGER NOT NULL,
    cpu_iowait_ticks      INTEGER NOT NULL,
    cpu_irq_ticks         INTEGER NOT NULL,
    cpu_softirq_ticks     INTEGER NOT NULL,
    cpu_steal_ticks       INTEGER NOT NULL,
    mem_total_bytes       INTEGER,
    mem_available_bytes   INTEGER,
    mem_free_bytes        INTEGER,
    swap_total_bytes      INTEGER,
    swap_free_bytes       INTEGER,
    load1                 REAL,
    load5                 REAL,
    load15                REAL,
    procs_running         INTEGER,
    procs_blocked         INTEGER,
    psi_cpu_some_avg10    REAL,
    psi_cpu_some_total_us INTEGER,
    psi_mem_some_avg10    REAL,
    psi_mem_some_total_us INTEGER,
    psi_io_some_avg10     REAL,
    psi_io_some_total_us  INTEGER,
    net_rx_bytes          INTEGER,
    net_tx_bytes          INTEGER,
    disk_read_bytes       INTEGER,
    disk_write_bytes      INTEGER,
    uptime_secs           REAL,
    boot_time_secs        INTEGER,
    PRIMARY KEY(boot_id, mono_ts_ns)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS host_samples_time ON host_samples(wall_ts_ns);

CREATE TABLE IF NOT EXISTS cgroup_samples (
    boot_id               TEXT NOT NULL,
    mono_ts_ns            INTEGER NOT NULL,
    wall_ts_ns            INTEGER NOT NULL,
    entity_id             TEXT NOT NULL,
    path                  TEXT NOT NULL,
    cpu_usage_usec        INTEGER,
    cpu_user_usec         INTEGER,
    cpu_system_usec       INTEGER,
    cpu_nr_periods        INTEGER,
    cpu_nr_throttled      INTEGER,
    cpu_throttled_usec    INTEGER,
    memory_current_bytes  INTEGER,
    memory_peak_bytes     INTEGER,
    memory_max_bytes      INTEGER,
    memory_anon_bytes     INTEGER,
    memory_file_bytes     INTEGER,
    memory_swap_bytes     INTEGER,
    cpu_quota_usec        INTEGER,
    cpu_period_usec       INTEGER,
    pids_current          INTEGER,
    psi_cpu_some_avg10    REAL,
    psi_mem_some_avg10    REAL,
    psi_io_some_avg10     REAL,
    io_json               TEXT,
    PRIMARY KEY(boot_id, mono_ts_ns, entity_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS cgroup_samples_entity_time ON cgroup_samples(entity_id, wall_ts_ns);

CREATE TABLE IF NOT EXISTS process_samples (
    mono_ts_ns         INTEGER NOT NULL,
    wall_ts_ns         INTEGER NOT NULL,
    process_instance_id TEXT NOT NULL,
    cpu_user_ticks     INTEGER,
    cpu_system_ticks   INTEGER,
    rss_bytes          INTEGER,
    virtual_bytes      INTEGER,
    read_bytes         INTEGER,
    write_bytes        INTEGER,
    read_chars         INTEGER,
    write_chars        INTEGER,
    threads            INTEGER,
    state              TEXT,
    sample_flags       INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(mono_ts_ns, process_instance_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS process_samples_entity_time ON process_samples(process_instance_id, wall_ts_ns);

CREATE TABLE IF NOT EXISTS events (
    event_id     INTEGER PRIMARY KEY,
    wall_ts_ns   INTEGER NOT NULL,
    mono_ts_ns   INTEGER,
    entity_id    TEXT,
    kind         TEXT NOT NULL,
    severity     TEXT NOT NULL,
    payload_json TEXT,
    provenance   TEXT NOT NULL,
    lost_before  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS events_time       ON events(wall_ts_ns);
CREATE INDEX IF NOT EXISTS events_entity_time ON events(entity_id, wall_ts_ns);
CREATE INDEX IF NOT EXISTS events_kind_time  ON events(kind, wall_ts_ns);

CREATE TABLE IF NOT EXISTS logs (
    log_id      INTEGER PRIMARY KEY,
    wall_ts_ns  INTEGER NOT NULL,
    mono_ts_ns  INTEGER,
    entity_id   TEXT,
    source_id   TEXT NOT NULL,
    stream      TEXT NOT NULL,
    level       TEXT,
    message     TEXT NOT NULL,
    truncated   INTEGER NOT NULL DEFAULT 0,
    redacted    INTEGER NOT NULL DEFAULT 0,
    incident_id INTEGER
);
CREATE INDEX IF NOT EXISTS logs_source_time   ON logs(source_id, wall_ts_ns);
CREATE INDEX IF NOT EXISTS logs_level_time    ON logs(level, wall_ts_ns);
CREATE INDEX IF NOT EXISTS logs_incident      ON logs(incident_id);
CREATE INDEX IF NOT EXISTS logs_time          ON logs(wall_ts_ns);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id      INTEGER PRIMARY KEY,
    started_wall_ns  INTEGER NOT NULL,
    ended_wall_ns    INTEGER,
    entity_id        TEXT,
    metric           TEXT NOT NULL,
    reason           TEXT NOT NULL,
    peak             REAL NOT NULL,
    baseline         REAL NOT NULL,
    evidence_json    TEXT,
    acknowledged     INTEGER NOT NULL DEFAULT 0,
    evidence_loss    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS incidents_start ON incidents(started_wall_ns);
CREATE INDEX IF NOT EXISTS incidents_entity ON incidents(entity_id, started_wall_ns);

CREATE TABLE IF NOT EXISTS rollup_1m (
    bucket_wall_ns  INTEGER NOT NULL,
    entity_id       TEXT NOT NULL,
    entity_kind     TEXT NOT NULL,
    sample_count    INTEGER NOT NULL,
    cpu_avg_pct     REAL,
    cpu_max_pct     REAL,
    cpu_total_usec  INTEGER,
    memory_avg_bytes INTEGER,
    memory_max_bytes INTEGER,
    io_read_bytes   INTEGER,
    io_write_bytes  INTEGER,
    net_rx_bytes    INTEGER,
    net_tx_bytes    INTEGER,
    psi_cpu_max     REAL,
    psi_mem_max     REAL,
    psi_io_max      REAL,
    PRIMARY KEY(bucket_wall_ns, entity_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS rollup_1m_entity ON rollup_1m(entity_id, bucket_wall_ns);

CREATE TABLE IF NOT EXISTS rollup_1h (
    bucket_wall_ns  INTEGER NOT NULL,
    entity_id       TEXT NOT NULL,
    entity_kind     TEXT NOT NULL,
    sample_count    INTEGER NOT NULL,
    cpu_avg_pct     REAL,
    cpu_max_pct     REAL,
    cpu_total_usec  INTEGER,
    memory_avg_bytes INTEGER,
    memory_max_bytes INTEGER,
    io_read_bytes   INTEGER,
    io_write_bytes  INTEGER,
    net_rx_bytes    INTEGER,
    net_tx_bytes    INTEGER,
    PRIMARY KEY(bucket_wall_ns, entity_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS rollup_1h_entity ON rollup_1h(entity_id, bucket_wall_ns);

CREATE TABLE IF NOT EXISTS collector_health (
    collector_id         TEXT PRIMARY KEY,
    configured_state     TEXT NOT NULL,
    availability         TEXT NOT NULL,
    permission_state     TEXT NOT NULL,
    last_success_wall_ns INTEGER,
    last_error_wall_ns   INTEGER,
    last_error           TEXT,
    error_count          INTEGER NOT NULL DEFAULT 0,
    received_count       INTEGER NOT NULL DEFAULT 0,
    persisted_count      INTEGER NOT NULL DEFAULT 0,
    dropped_count        INTEGER NOT NULL DEFAULT 0,
    truncated_count      INTEGER NOT NULL DEFAULT 0,
    queue_high_water     INTEGER NOT NULL DEFAULT 0,
    coverage_json        TEXT
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS integration_state (
    integration_id    TEXT PRIMARY KEY,
    configured_state  TEXT NOT NULL,
    detected_state    TEXT NOT NULL,
    version           TEXT,
    capabilities_json TEXT,
    last_seen_wall_ns INTEGER,
    last_error        TEXT
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS log_sources (
    source_id    TEXT PRIMARY KEY,
    kind         TEXT NOT NULL,
    target       TEXT NOT NULL,
    entity_hint  TEXT,
    max_lines    INTEGER,
    max_bytes    INTEGER,
    manager      TEXT NOT NULL DEFAULT 'sarf'
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS coverage_gaps (
    gap_id           INTEGER PRIMARY KEY,
    source_id        TEXT NOT NULL,
    kind             TEXT NOT NULL,
    detail           TEXT NOT NULL,
    since_wall_ns    INTEGER,
    resolved_wall_ns INTEGER,
    UNIQUE(source_id, kind, detail)
);
CREATE INDEX IF NOT EXISTS coverage_gaps_open ON coverage_gaps(resolved_wall_ns);
";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_is_present_and_versioned() {
        assert!(MIGRATION_1.contains("CREATE TABLE"));
        let tables: Vec<&str> = MIGRATION_1
            .match_indices("CREATE TABLE IF NOT EXISTS ")
            .map(|(index, needle)| {
                let rest = &MIGRATION_1[index + needle.len()..];
                rest.split_whitespace().next().unwrap_or("")
            })
            .collect();
        // 18 logical tables: meta, hosts, runs, entities, relationships,
        // process_lifetimes, host_samples, cgroup_samples, process_samples, events,
        // logs, incidents, rollup_1m, rollup_1h, collector_health,
        // integration_state, log_sources, coverage_gaps.
        assert_eq!(tables.len(), 18, "tables: {tables:?}");
        for required in [
            "host_samples",
            "cgroup_samples",
            "process_samples",
            "events",
            "logs",
            "incidents",
            "rollup_1m",
            "collector_health",
            "coverage_gaps",
        ] {
            assert!(tables.contains(&required), "missing table {required}");
        }
    }

    #[test]
    fn schema_declares_no_foreign_keys() {
        // Cross-table foreign keys are intentionally avoided: the bounded writer may
        // persist a sample before its entity row in the same batch, and SQLite would
        // reject it. Referential intent is documented and validated by query tests.
        assert!(!MIGRATION_1.contains("REFERENCES"));
    }

    #[test]
    fn schema_has_query_indexes_for_the_hot_paths() {
        for index in [
            "process_lifetimes_pid_start",
            "process_lifetimes_start",
            "host_samples_time",
            "cgroup_samples_entity_time",
            "process_samples_entity_time",
            "logs_source_time",
            "logs_incident",
            "events_entity_time",
            "incidents_start",
        ] {
            assert!(
                MIGRATION_1.contains(index),
                "missing hot-path index {index}"
            );
        }
    }
}
