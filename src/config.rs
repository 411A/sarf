//! Configuration model, defaults, validation and atomic persistence.
//!
//! Defaults live in `config/defaults.toml` which is embedded into the binary so a
//! single executable can initialize a data directory without shipping extra files.
//! Configuration is deliberately small: intervals, bounds, privacy switches,
//! thresholds, retention and explicitly configured log sources.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{Error, Result};

/// Embedded default configuration (also written by `sarf init`).
pub const DEFAULT_CONFIG: &str = include_str!("../config/defaults.toml");

/// A tri-state integration switch: `disabled`, `auto` (enable when detected) or
/// `enabled`. Accepts booleans for convenience in hand-written configs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Toggle {
    /// Explicitly disabled.
    Disabled,
    /// Enabled only when detection succeeds.
    #[default]
    Auto,
    /// Explicitly enabled (still degrades safely when the tool is absent).
    Enabled,
}

impl Toggle {
    /// Stable config/DB string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Auto => "auto",
            Self::Enabled => "enabled",
        }
    }

    /// Whether collection should be attempted at all (auto attempts a bounded
    /// detection step and marks the integration unavailable if absent).
    pub const fn should_attempt(self) -> bool {
        !matches!(self, Self::Disabled)
    }

    /// Whether the integration was explicitly requested.
    pub const fn is_explicit(self) -> bool {
        matches!(self, Self::Enabled)
    }

    /// Parse a config string.
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "disabled" | "disable" | "off" | "false" | "no" | "0" => Some(Self::Disabled),
            "auto" => Some(Self::Auto),
            "enabled" | "enable" | "on" | "true" | "yes" | "1" => Some(Self::Enabled),
            _ => None,
        }
    }
}

impl Serialize for Toggle {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Toggle {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct ToggleVisitor;
        impl Visitor<'_> for ToggleVisitor {
            type Value = Toggle;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("one of \"off\", \"auto\", \"on\", or a boolean")
            }

            fn visit_bool<E: de::Error>(self, value: bool) -> std::result::Result<Toggle, E> {
                Ok(if value {
                    Toggle::Enabled
                } else {
                    Toggle::Disabled
                })
            }

            fn visit_str<E: de::Error>(self, value: &str) -> std::result::Result<Toggle, E> {
                Toggle::parse(value).ok_or_else(|| {
                    E::custom(format!(
                        "invalid toggle {value:?}: expected off/auto/on or a boolean"
                    ))
                })
            }
        }
        deserializer.deserialize_any(ToggleVisitor)
    }
}

/// General runtime and budget settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct General {
    /// Host/cgroup sampling cadence.
    pub interval_secs: u64,
    /// Selected-process sampling cadence.
    pub process_interval_secs: u64,
    /// Optional integration discovery cadence.
    pub discovery_secs: u64,
    /// Hard database budget in MiB.
    pub max_db_mb: u64,
    /// WAL budget in MiB.
    pub max_wal_mb: u64,
    /// Retention/disk-guard cadence.
    pub prune_interval_secs: u64,
}

impl Default for General {
    fn default() -> Self {
        Self {
            interval_secs: 5,
            process_interval_secs: 5,
            discovery_secs: 30,
            max_db_mb: 100,
            max_wal_mb: 16,
            prune_interval_secs: 300,
        }
    }
}

/// Process collection settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProcessConfig {
    /// Enable process inventory.
    pub enabled: bool,
    /// Persist argv. Off by default (privacy).
    pub store_arguments: bool,
    /// Persist every process's raw time series (expensive).
    pub sample_all_processes: bool,
    /// Number of top processes to keep sampled.
    pub top_n_persistence: usize,
    /// Hard cap on tracked processes.
    pub max_processes: usize,
}

impl Default for ProcessConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            store_arguments: false,
            sample_all_processes: false,
            top_n_persistence: 20,
            max_processes: 20_000,
        }
    }
}

/// cgroup v2 collection settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Cgroup {
    /// Enable cgroup sampling.
    pub enabled: bool,
    /// Sampling cadence.
    pub sample_secs: u64,
    /// Maximum cgroups sampled per cycle.
    pub max_cgroups: usize,
}

impl Default for Cgroup {
    fn default() -> Self {
        Self {
            enabled: true,
            sample_secs: 5,
            max_cgroups: 512,
        }
    }
}

/// Network accounting settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Network {
    /// Sample host interface counters.
    pub interface_counters: bool,
    /// Attempt per-container network counters via runtime metadata.
    pub container_counters: bool,
}

impl Default for Network {
    fn default() -> Self {
        Self {
            interface_counters: true,
            container_counters: true,
        }
    }
}

/// A kind of log source SARF can ingest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogSourceKind {
    /// A file tailed with rotation/truncation handling.
    File,
    /// A Docker container's stdout/stderr (bounded CLI fallback).
    Docker,
}

impl LogSourceKind {
    /// Stable string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Docker => "docker",
        }
    }
}

/// One explicitly configured log source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogSource {
    /// Stable source id (`nginx-error`, `cloudflared`, ...).
    pub id: String,
    /// Source kind.
    pub kind: LogSourceKind,
    /// Path for file sources.
    #[serde(default)]
    pub path: Option<PathBuf>,
    /// Container name or id for Docker sources.
    #[serde(default)]
    pub container: Option<String>,
    /// Tool/entity hint used to correlate the source with a process.
    #[serde(default)]
    pub entity_hint: Option<String>,
    /// Per-source ring line cap (defaults to the global cap).
    #[serde(default)]
    pub max_lines: Option<usize>,
    /// Per-source ring byte cap (defaults to the global cap).
    #[serde(default)]
    pub max_bytes: Option<u64>,
}

impl LogSource {
    /// Bounded human-readable target for CLI/report display.
    pub fn target(&self) -> String {
        match self.kind {
            LogSourceKind::File => self
                .path
                .as_ref()
                .map_or_else(|| "<unset path>".to_string(), |p| p.display().to_string()),
            LogSourceKind::Docker => self
                .container
                .clone()
                .unwrap_or_else(|| "<unset container>".to_string()),
        }
    }
}

/// Bounded log ingestion settings (guide §9).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Logs {
    /// Enable log ingestion.
    pub enabled: bool,
    /// Ring line cap per source.
    pub ring_lines: usize,
    /// Ring time cap in minutes.
    pub ring_minutes: u64,
    /// Ring byte cap per source.
    pub ring_bytes_per_source: u64,
    /// Maximum stored bytes of one line.
    pub max_line_bytes: usize,
    /// Maximum number of configured sources.
    pub max_sources: usize,
    /// Bytes read per source per cycle.
    pub read_bytes_per_cycle: usize,
    /// Fraction of INFO records persisted outside incident windows.
    pub persist_info_sample_percent: u8,
    /// Persist WARN records.
    pub persist_warnings: bool,
    /// Persist ERROR records.
    pub persist_errors: bool,
    /// Substring patterns that are always persisted and flagged.
    pub always_store_patterns: Vec<String>,
    /// Explicitly configured sources.
    pub sources: Vec<LogSource>,
}

impl Default for Logs {
    fn default() -> Self {
        Self {
            enabled: true,
            ring_lines: 1000,
            ring_minutes: 10,
            ring_bytes_per_source: 512 * 1024,
            max_line_bytes: 4096,
            max_sources: 32,
            read_bytes_per_cycle: 64 * 1024,
            persist_info_sample_percent: 0,
            persist_warnings: true,
            persist_errors: true,
            always_store_patterns: vec![
                "WARN".into(),
                "ERROR".into(),
                "FATAL".into(),
                "PANIC".into(),
                "Traceback".into(),
                "ENOSPC".into(),
                "OOM".into(),
                "Timeout".into(),
                "ConnectionRefused".into(),
                "unhealthy".into(),
            ],
            sources: Vec::new(),
        }
    }
}

/// Adaptive sampling settings (guide §7.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Adaptive {
    /// Enable incident-mode sampling.
    pub enabled: bool,
    /// Incident-mode interval.
    pub incident_interval_ms: u64,
    /// Maximum incident duration before forced recovery.
    pub max_incident_secs: u64,
    /// Maximum entities sampled at high resolution.
    pub max_entities_high_resolution: usize,
    /// Recovery hysteresis before dropping back to normal cadence.
    pub recovery_hysteresis_secs: u64,
}

impl Default for Adaptive {
    fn default() -> Self {
        Self {
            enabled: true,
            incident_interval_ms: 500,
            max_incident_secs: 120,
            max_entities_high_resolution: 8,
            recovery_hysteresis_secs: 30,
        }
    }
}

/// Absolute starting thresholds (configurable, not universal truths).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Thresholds {
    /// Host CPU percent.
    pub host_cpu_pct: f64,
    /// Per-service/cgroup CPU percent of one core.
    pub service_cpu_pct: f64,
    /// Memory percent of total/limit.
    pub memory_pct: f64,
    /// PSI `some avg10` percent.
    pub psi_some_pct: f64,
    /// Error-log rate per minute.
    pub error_rate_per_min: f64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            host_cpu_pct: 10.0,
            service_cpu_pct: 20.0,
            memory_pct: 80.0,
            psi_some_pct: 10.0,
            error_rate_per_min: 5.0,
        }
    }
}

/// Retention windows (guide §11.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Retention {
    /// Raw host/cgroup sample hours.
    pub raw_hours: u64,
    /// Raw process sample hours.
    pub process_raw_hours: u64,
    /// Minute rollup days.
    pub rollup_1m_days: u64,
    /// Hour rollup days.
    pub rollup_1h_days: u64,
    /// Incident retention days.
    pub incident_days: u64,
    /// Unattached log retention days.
    pub log_days: u64,
}

impl Default for Retention {
    fn default() -> Self {
        Self {
            raw_hours: 48,
            process_raw_hours: 24,
            rollup_1m_days: 14,
            rollup_1h_days: 90,
            incident_days: 180,
            log_days: 7,
        }
    }
}

/// Integration switches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Integrations {
    /// Docker container metadata.
    pub docker: Toggle,
    /// tmux session/pane mapping.
    pub tmux: Toggle,
    /// Zellij session mapping.
    pub zellij: Toggle,
    /// systemd unit inference from cgroups.
    pub systemd: Toggle,
    /// nginx recognition/log hints.
    pub nginx: Toggle,
    /// cloudflared recognition/log hints.
    pub cloudflared: Toggle,
}

impl Default for Integrations {
    fn default() -> Self {
        Self {
            docker: Toggle::Auto,
            tmux: Toggle::Auto,
            zellij: Toggle::Auto,
            systemd: Toggle::Auto,
            nginx: Toggle::Auto,
            cloudflared: Toggle::Auto,
        }
    }
}

impl Integrations {
    /// Named toggle lookup for CLI/status output.
    pub fn get(&self, name: &str) -> Option<Toggle> {
        Some(match name {
            "docker" => self.docker,
            "tmux" => self.tmux,
            "zellij" => self.zellij,
            "systemd" => self.systemd,
            "nginx" => self.nginx,
            "cloudflared" => self.cloudflared,
            _ => return None,
        })
    }
}

/// Report generation bounds (guide §14.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Report {
    /// Attribution bucket size.
    pub bucket_secs: u64,
    /// Maximum points per rendered series.
    pub max_points: usize,
    /// Maximum processes in the tree table.
    pub max_processes: usize,
    /// Maximum logs embedded in a report.
    pub max_logs: usize,
    /// Maximum high/low windows described.
    pub max_windows: usize,
    /// Maximum process-tree nodes embedded.
    pub max_process_tree_nodes: usize,
    /// Report title.
    pub title: String,
}

impl Default for Report {
    fn default() -> Self {
        Self {
            bucket_secs: 60,
            max_points: 600,
            max_processes: 200,
            max_logs: 500,
            max_windows: 12,
            max_process_tree_nodes: 400,
            title: "SARF activity report".to_string(),
        }
    }
}

/// The complete SARF configuration.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// General runtime settings.
    pub general: General,
    /// Process collection.
    pub process: ProcessConfig,
    /// cgroup collection.
    pub cgroup: Cgroup,
    /// Network accounting.
    pub network: Network,
    /// Log ingestion.
    pub logs: Logs,
    /// Adaptive sampling.
    pub adaptive: Adaptive,
    /// Absolute thresholds.
    pub thresholds: Thresholds,
    /// Retention windows.
    pub retention: Retention,
    /// Integration switches.
    pub integrations: Integrations,
    /// Report bounds.
    pub report: Report,
}

impl Config {
    /// Parse and validate configuration text.
    pub fn parse(text: &str) -> Result<Self> {
        let config: Self = toml::from_str(text)
            .map_err(|err| Error::Config(format!("TOML parse error: {err}")))?;
        config.validate()?;
        Ok(config)
    }

    /// Load configuration from a file.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).map_err(|err| {
            Error::Config(format!(
                "cannot read configuration {}: {err}; run `sarf init` first",
                path.display()
            ))
        })?;
        Self::parse(&text)
    }

    /// Atomically write configuration (temp file in the same directory + rename).
    pub fn save(&self, path: &Path) -> Result<()> {
        let text = toml::to_string_pretty(self)
            .map_err(|err| Error::Config(format!("cannot serialize configuration: {err}")))?;
        let header = "# SARF configuration — generated by `sarf init`. See config/defaults.toml for documentation.\n\n";
        let tmp = path.with_extension("toml.tmp");
        std::fs::write(&tmp, format!("{header}{text}"))
            .map_err(|err| Error::io(tmp.clone(), err))?;
        crate::paths::restrict_file_permissions(&tmp);
        std::fs::rename(&tmp, path).map_err(|err| Error::io(path.to_path_buf(), err))?;
        Ok(())
    }

    /// Validate bounds and cross-field constraints.
    pub fn validate(&self) -> Result<()> {
        let g = &self.general;
        check_range("general.interval_secs", g.interval_secs as f64, 1.0, 3600.0)?;
        check_range(
            "general.process_interval_secs",
            g.process_interval_secs as f64,
            1.0,
            3600.0,
        )?;
        check_range(
            "general.discovery_secs",
            g.discovery_secs as f64,
            5.0,
            3600.0,
        )?;
        check_range("general.max_db_mb", g.max_db_mb as f64, 8.0, 1_000_000.0)?;
        check_range("general.max_wal_mb", g.max_wal_mb as f64, 1.0, 65_536.0)?;
        check_range(
            "general.prune_interval_secs",
            g.prune_interval_secs as f64,
            30.0,
            86_400.0,
        )?;
        check_range(
            "process.top_n_persistence",
            self.process.top_n_persistence as f64,
            0.0,
            5000.0,
        )?;
        check_range(
            "process.max_processes",
            self.process.max_processes as f64,
            1.0,
            1_000_000.0,
        )?;
        check_range(
            "cgroup.sample_secs",
            self.cgroup.sample_secs as f64,
            1.0,
            3600.0,
        )?;
        check_range(
            "cgroup.max_cgroups",
            self.cgroup.max_cgroups as f64,
            1.0,
            1_000_000.0,
        )?;
        let logs = &self.logs;
        check_range("logs.ring_lines", logs.ring_lines as f64, 10.0, 1_000_000.0)?;
        check_range("logs.ring_minutes", logs.ring_minutes as f64, 1.0, 1440.0)?;
        check_range(
            "logs.ring_bytes_per_source",
            logs.ring_bytes_per_source as f64,
            4096.0,
            268_435_456.0,
        )?;
        check_range(
            "logs.max_line_bytes",
            logs.max_line_bytes as f64,
            128.0,
            1_048_576.0,
        )?;
        if logs.max_line_bytes as u64 > logs.ring_bytes_per_source {
            return Err(Error::Config(
                "logs.max_line_bytes must not exceed logs.ring_bytes_per_source".into(),
            ));
        }
        check_range("logs.max_sources", logs.max_sources as f64, 1.0, 1024.0)?;
        check_range(
            "logs.read_bytes_per_cycle",
            logs.read_bytes_per_cycle as f64,
            4096.0,
            16_777_216.0,
        )?;
        if logs.persist_info_sample_percent > 100 {
            return Err(Error::Config(
                "logs.persist_info_sample_percent must be 0..=100".into(),
            ));
        }
        if logs.always_store_patterns.len() > 64 {
            return Err(Error::Config(
                "logs.always_store_patterns is limited to 64 patterns".into(),
            ));
        }
        for pattern in &logs.always_store_patterns {
            if pattern.is_empty() || pattern.len() > 128 {
                return Err(Error::Config(
                    "each always_store_patterns entry must be 1..=128 bytes".into(),
                ));
            }
        }
        let adaptive = &self.adaptive;
        check_range(
            "adaptive.incident_interval_ms",
            adaptive.incident_interval_ms as f64,
            50.0,
            60_000.0,
        )?;
        check_range(
            "adaptive.max_incident_secs",
            adaptive.max_incident_secs as f64,
            5.0,
            86_400.0,
        )?;
        check_range(
            "adaptive.max_entities_high_resolution",
            adaptive.max_entities_high_resolution as f64,
            1.0,
            1000.0,
        )?;
        check_range(
            "adaptive.recovery_hysteresis_secs",
            adaptive.recovery_hysteresis_secs as f64,
            0.0,
            86_400.0,
        )?;
        if adaptive.enabled && adaptive.incident_interval_ms >= self.general.interval_secs * 1000 {
            return Err(Error::Config(
                "adaptive.incident_interval_ms must be lower than general.interval_secs*1000 when adaptive is enabled".into(),
            ));
        }
        check_range(
            "thresholds.host_cpu_pct",
            self.thresholds.host_cpu_pct,
            0.0,
            100.0,
        )?;
        check_range(
            "thresholds.service_cpu_pct",
            self.thresholds.service_cpu_pct,
            0.0,
            10_000.0,
        )?;
        check_range(
            "thresholds.memory_pct",
            self.thresholds.memory_pct,
            1.0,
            100.0,
        )?;
        check_range(
            "thresholds.psi_some_pct",
            self.thresholds.psi_some_pct,
            0.0,
            100.0,
        )?;
        check_range(
            "thresholds.error_rate_per_min",
            self.thresholds.error_rate_per_min,
            0.0,
            1_000_000.0,
        )?;
        let retention = &self.retention;
        check_range(
            "retention.raw_hours",
            retention.raw_hours as f64,
            1.0,
            8760.0,
        )?;
        check_range(
            "retention.process_raw_hours",
            retention.process_raw_hours as f64,
            1.0,
            8760.0,
        )?;
        check_range(
            "retention.rollup_1m_days",
            retention.rollup_1m_days as f64,
            1.0,
            36_500.0,
        )?;
        check_range(
            "retention.rollup_1h_days",
            retention.rollup_1h_days as f64,
            1.0,
            36_500.0,
        )?;
        if retention.rollup_1h_days < retention.rollup_1m_days {
            return Err(Error::Config(
                "retention.rollup_1h_days must be >= retention.rollup_1m_days".into(),
            ));
        }
        check_range(
            "retention.incident_days",
            retention.incident_days as f64,
            1.0,
            36_500.0,
        )?;
        check_range(
            "retention.log_days",
            retention.log_days as f64,
            1.0,
            36_500.0,
        )?;
        let report = &self.report;
        check_range(
            "report.bucket_secs",
            report.bucket_secs as f64,
            5.0,
            86_400.0,
        )?;
        check_range("report.max_points", report.max_points as f64, 10.0, 5000.0)?;
        check_range(
            "report.max_processes",
            report.max_processes as f64,
            1.0,
            10_000.0,
        )?;
        check_range("report.max_logs", report.max_logs as f64, 1.0, 100_000.0)?;
        check_range("report.max_windows", report.max_windows as f64, 1.0, 1000.0)?;
        check_range(
            "report.max_process_tree_nodes",
            report.max_process_tree_nodes as f64,
            1.0,
            100_000.0,
        )?;
        if report.title.trim().is_empty() || report.title.len() > 200 {
            return Err(Error::Config("report.title must be 1..=200 bytes".into()));
        }
        // Log sources: unique ids, valid targets, consistent bounds.
        if logs.sources.len() > logs.max_sources {
            return Err(Error::Config(format!(
                "{} log sources configured but logs.max_sources is {}",
                logs.sources.len(),
                logs.max_sources
            )));
        }
        let mut ids = BTreeSet::new();
        for source in &logs.sources {
            if !source.id.is_empty()
                && source.id.len() <= 64
                && source
                    .id
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
            {
                // ok
            } else {
                return Err(Error::Config(format!(
                    "invalid log source id {:?}: use 1..=64 of [A-Za-z0-9._-]",
                    source.id
                )));
            }
            if !ids.insert(source.id.clone()) {
                return Err(Error::Config(format!(
                    "duplicate log source id {:?}",
                    source.id
                )));
            }
            match source.kind {
                LogSourceKind::File => {
                    let path = source.path.as_ref().ok_or_else(|| {
                        Error::Config(format!(
                            "log source {:?} of kind file needs a `path`",
                            source.id
                        ))
                    })?;
                    if path.as_os_str().is_empty() {
                        return Err(Error::Config(format!(
                            "log source {:?} has an empty path",
                            source.id
                        )));
                    }
                }
                LogSourceKind::Docker => {
                    if source
                        .container
                        .as_deref()
                        .map(str::trim)
                        .unwrap_or_default()
                        .is_empty()
                    {
                        return Err(Error::Config(format!(
                            "log source {:?} of kind docker needs a `container`",
                            source.id
                        )));
                    }
                }
            }
            if let Some(max_lines) = source.max_lines {
                check_range("log source max_lines", max_lines as f64, 1.0, 1_000_000.0)?;
            }
            if let Some(max_bytes) = source.max_bytes {
                check_range(
                    "log source max_bytes",
                    max_bytes as f64,
                    4096.0,
                    268_435_456.0,
                )?;
            }
        }
        Ok(())
    }

    /// Enabled integration toggles as `(name, toggle)` for status output.
    pub const fn integration_toggles(&self) -> [(&'static str, Toggle); 6] {
        [
            ("docker", self.integrations.docker),
            ("tmux", self.integrations.tmux),
            ("zellij", self.integrations.zellij),
            ("systemd", self.integrations.systemd),
            ("nginx", self.integrations.nginx),
            ("cloudflared", self.integrations.cloudflared),
        ]
    }
}

fn check_range(name: &str, value: f64, min: f64, max: f64) -> Result<()> {
    if !value.is_finite() || value < min || value > max {
        return Err(Error::Config(format!(
            "{name} = {value} is outside the supported range {min}..={max}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_defaults_parse_and_equal_builtin_defaults() {
        let parsed = Config::parse(DEFAULT_CONFIG).expect("defaults.toml must be valid");
        assert_eq!(parsed, Config::default());
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let err = Config::parse("[general]\ninterval_secs = 5\nbogus = 1\n").unwrap_err();
        assert!(err.to_string().contains("TOML parse error"), "{err}");
    }

    #[test]
    fn toggles_accept_bools_and_words() {
        let config = Config::parse(
            "[integrations]\ndocker = true\ntmux = false\nzellij = \"on\"\nnginx = \"auto\"\n",
        )
        .expect("config parses");
        assert_eq!(config.integrations.docker, Toggle::Enabled);
        assert_eq!(config.integrations.tmux, Toggle::Disabled);
        assert_eq!(config.integrations.zellij, Toggle::Enabled);
        assert_eq!(config.integrations.nginx, Toggle::Auto);
        // Unspecified integrations keep their defaults.
        assert_eq!(config.integrations.cloudflared, Toggle::Auto);
    }

    #[test]
    fn invalid_toggle_is_rejected() {
        let err = Config::parse("[integrations]\ndocker = \"sometimes\"\n").unwrap_err();
        assert!(err.to_string().contains("invalid toggle"), "{err}");
    }

    #[test]
    fn validation_rejects_absurd_intervals() {
        let mut config = Config::default();
        config.general.interval_secs = 0;
        assert!(config.validate().is_err());
        config.general.interval_secs = 5;
        config.adaptive.incident_interval_ms = 10_000; // not lower than 5s
        assert!(config.validate().is_err());
    }

    #[test]
    fn log_sources_are_validated() {
        let mut config = Config::default();
        config.logs.sources.push(LogSource {
            id: "bad id!".into(),
            kind: LogSourceKind::File,
            path: Some("/tmp/x.log".into()),
            container: None,
            entity_hint: None,
            max_lines: None,
            max_bytes: None,
        });
        assert!(config.validate().is_err());

        config.logs.sources.clear();
        config.logs.sources.push(LogSource {
            id: "nginx-error".into(),
            kind: LogSourceKind::File,
            path: None,
            container: None,
            entity_hint: None,
            max_lines: None,
            max_bytes: None,
        });
        assert!(config.validate().is_err(), "file source needs a path");

        config.logs.sources[0].path = Some("/var/log/nginx/error.log".into());
        config.logs.sources.push(config.logs.sources[0].clone());
        assert!(config.validate().is_err(), "duplicate ids rejected");

        config.logs.sources.pop();
        config.validate().expect("valid single source");
    }

    #[test]
    fn roundtrip_save_and_load() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sarf.toml");
        let mut config = Config::default();
        config.general.interval_secs = 7;
        config.save(&path).expect("save");
        let loaded = Config::load(&path).expect("load");
        assert_eq!(loaded, config);
        assert!(
            !dir.path().join("sarf.toml.tmp").exists(),
            "temp file renamed"
        );
    }

    #[test]
    fn retention_consistency_is_enforced() {
        let mut config = Config::default();
        config.retention.rollup_1m_days = 30;
        config.retention.rollup_1h_days = 10;
        assert!(config.validate().is_err());
    }

    #[test]
    fn integration_lookup_is_stable() {
        let integrations = Integrations::default();
        assert_eq!(integrations.get("docker"), Some(Toggle::Auto));
        assert_eq!(integrations.get("nope"), None);
    }

    #[test]
    fn privacy_defaults_are_conservative() {
        let config = Config::default();
        assert!(!config.process.store_arguments);
        assert_eq!(config.logs.persist_info_sample_percent, 0);
        assert!(config.logs.persist_errors);
        assert!(config.logs.sources.is_empty(), "no implicit log scraping");
    }

    #[test]
    fn defaults_have_no_unbounded_values() {
        let config = Config::default();
        assert!(config.logs.ring_bytes_per_source > 0);
        assert!(config.general.max_db_mb > 0);
        assert!(config.report.max_points <= 5000);
    }
}
