//! Core data model shared by collectors, storage, analysis and reports.
//!
//! The entities and samples here follow the guide (§8, §11.2): stable keys instead
//! of bare PIDs, dual timestamps, provenance on inferred relationships, and
//! `Option` for every value the kernel may refuse to expose. A missing value is
//! never coerced to zero.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::time::Stamps;

/// Stable identifier of an entity in the database.
pub type EntityId = String;

/// Kind of entity tracked by SARF (guide §8.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityKind {
    /// The physical or virtual host being observed.
    Host,
    /// A cgroup v2 node.
    Cgroup,
    /// A systemd unit or scope inferred from cgroup membership.
    SystemdUnit,
    /// A container as reported by an integration.
    Container,
    /// A process (thread group).
    Process,
    /// A terminal session/window/pane (tmux, Zellij).
    Session,
    /// A recognized tool/integration identity.
    Tool,
    /// A configured or discovered log source.
    LogSource,
    /// A network interface observed on the host.
    NetworkInterface,
}

impl EntityKind {
    /// Stable database string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Cgroup => "cgroup",
            Self::SystemdUnit => "systemd_unit",
            Self::Container => "container",
            Self::Process => "process",
            Self::Session => "session",
            Self::Tool => "tool",
            Self::LogSource => "log_source",
            Self::NetworkInterface => "interface",
        }
    }

    /// Parse a database string, returning `None` for unknown kinds.
    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "host" => Self::Host,
            "cgroup" => Self::Cgroup,
            "systemd_unit" => Self::SystemdUnit,
            "container" => Self::Container,
            "process" => Self::Process,
            "session" => Self::Session,
            "tool" => Self::Tool,
            "log_source" => Self::LogSource,
            "interface" => Self::NetworkInterface,
            _ => return None,
        })
    }
}

/// A durable entity row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entity {
    /// Primary key, kind-prefixed and stable across observations.
    pub entity_id: EntityId,
    /// Entity kind.
    pub kind: EntityKind,
    /// Kind-local stable key (e.g. `pid:start_ticks` for processes).
    pub stable_key: String,
    /// Human-readable name (path, comm, container name, ...).
    pub name: String,
    /// Which source discovered it.
    pub source: String,
    /// Bounded, non-secret labels.
    pub labels: BTreeMap<String, String>,
    /// First observation, wall clock.
    pub first_seen_wall_ns: i64,
    /// Last observation, wall clock.
    pub last_seen_wall_ns: i64,
}

/// Typed relationship between entities (guide §8.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RelationKind {
    /// Child process spawned by a parent process.
    SpawnedBy,
    /// Process is a member of a cgroup.
    MemberOfCgroup,
    /// Unit/process is managed by systemd.
    ManagedBySystemd,
    /// Process runs inside a container.
    RunningInContainer,
    /// Process belongs to a terminal session/pane.
    AttachedToSession,
    /// Log record was emitted by an entity.
    EmittedLog,
    /// Observation was produced by a collector source.
    ObservedBy,
    /// Log source is configured for an entity.
    LogsFor,
}

impl RelationKind {
    /// Stable database string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SpawnedBy => "SPAWNED_BY",
            Self::MemberOfCgroup => "MEMBER_OF_CGROUP",
            Self::ManagedBySystemd => "MANAGED_BY_SYSTEMD",
            Self::RunningInContainer => "RUNNING_IN_CONTAINER",
            Self::AttachedToSession => "ATTACHED_TO_SESSION",
            Self::EmittedLog => "EMITTED_LOG",
            Self::ObservedBy => "OBSERVED_BY",
            Self::LogsFor => "LOGS_FOR",
        }
    }
}

/// One time-bounded relationship row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Relationship {
    /// Source entity.
    pub from_entity_id: EntityId,
    /// Target entity.
    pub to_entity_id: EntityId,
    /// Relationship kind.
    pub relation: RelationKind,
    /// Start of validity, monotonic clock.
    pub valid_from_mono_ns: i64,
    /// End of validity, monotonic clock; `None` while still valid.
    pub valid_to_mono_ns: Option<i64>,
    /// `observed`, `inferred` or `declared`.
    pub provenance: String,
    /// Confidence for inferred relationships, `None` for observed ones.
    pub confidence: Option<f64>,
}

/// Process identity: boot + PID + start time (guide §8.1). PID alone is never a key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessIdentity {
    /// Short boot identity (prefix of `/proc/sys/kernel/random/boot_id`).
    pub boot: String,
    /// Host PID (thread group id).
    pub pid: u32,
    /// Start time in clock ticks since boot (field 22 of `/proc/PID/stat`).
    pub start_ticks: u64,
}

impl ProcessIdentity {
    /// Build an identity from its parts.
    pub fn new(boot: impl Into<String>, pid: u32, start_ticks: u64) -> Self {
        Self {
            boot: boot.into(),
            pid,
            start_ticks,
        }
    }

    /// Stable primary key used by every table and report.
    pub fn entity_id(&self) -> EntityId {
        format!("proc:{}:{}:{}", self.boot, self.pid, self.start_ticks)
    }

    /// Kind-local stable key.
    pub fn stable_key(&self) -> String {
        format!("{}:{}", self.pid, self.start_ticks)
    }
}

/// Cgroup identity: inode + device, with the path recorded for display.
///
/// Paths alone are not identities: cgroups can be removed and recreated with the
/// same path, and paths differ between namespace views (guide §5.3 rule 4).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CgroupIdentity {
    /// Device id of the cgroup filesystem that owns the node.
    pub device: u64,
    /// Inode of the cgroup directory.
    pub inode: u64,
}

impl CgroupIdentity {
    /// Primary key for this cgroup instance.
    pub fn entity_id(&self) -> EntityId {
        format!("cgroup:{}:{}", self.device, self.inode)
    }
}

/// CPU time categories from `/proc/stat` (ticks, `USER_HZ`).
///
/// `guest` and `guest_nice` are already included in `user`/`nice`; they are kept
/// for completeness but excluded from [`CpuTimes::total`] to avoid double counting.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpuTimes {
    /// user
    pub user: u64,
    /// nice
    pub nice: u64,
    /// system
    pub system: u64,
    /// idle
    pub idle: u64,
    /// iowait
    pub iowait: u64,
    /// irq
    pub irq: u64,
    /// softirq
    pub softirq: u64,
    /// steal
    pub steal: u64,
    /// guest (already in user)
    pub guest: u64,
    /// `guest_nice` (already in nice)
    pub guest_nice: u64,
}

impl CpuTimes {
    /// Sum of all first-level counters, excluding guest time (accounted upstream).
    pub const fn total(self) -> u64 {
        self.user
            .saturating_add(self.nice)
            .saturating_add(self.system)
            .saturating_add(self.idle)
            .saturating_add(self.iowait)
            .saturating_add(self.irq)
            .saturating_add(self.softirq)
            .saturating_add(self.steal)
    }

    /// Non-idle time (still includes iowait, which is a stall rather than work).
    pub const fn busy(self) -> u64 {
        self.total()
            .saturating_sub(self.idle)
            .saturating_sub(self.iowait)
    }

    /// Calculate tick deltas with wraparound/reset protection.
    ///
    /// Returns `None` for any field that decreased (counter reset, host reboot,
    /// 32-bit wrap on old kernels). The caller records a counter anomaly rather
    /// than inventing a negative delta or a huge spike.
    pub fn delta(self, previous: Self) -> Option<Self> {
        let sub = |now: u64, before: u64| now.checked_sub(before);
        Some(Self {
            user: sub(self.user, previous.user)?,
            nice: sub(self.nice, previous.nice)?,
            system: sub(self.system, previous.system)?,
            idle: sub(self.idle, previous.idle)?,
            iowait: sub(self.iowait, previous.iowait)?,
            irq: sub(self.irq, previous.irq)?,
            softirq: sub(self.softirq, previous.softirq)?,
            steal: sub(self.steal, previous.steal)?,
            guest: sub(self.guest, previous.guest)?,
            guest_nice: sub(self.guest_nice, previous.guest_nice)?,
        })
    }
}

/// Memory snapshot from `/proc/meminfo`, in bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemSnapshot {
    /// `MemTotal`
    pub total: u64,
    /// `MemFree`
    pub free: Option<u64>,
    /// `MemAvailable` (preferred for "used" arithmetic)
    pub available: Option<u64>,
    /// Buffers
    pub buffers: Option<u64>,
    /// Cached (includes `SReclaimable`? kept as reported)
    pub cached: Option<u64>,
    /// `SwapTotal`
    pub swap_total: Option<u64>,
    /// `SwapFree`
    pub swap_free: Option<u64>,
}

impl MemSnapshot {
    /// Used memory, preferring `MemAvailable` semantics rather than total-free.
    pub fn used(&self) -> Option<u64> {
        if self.total == 0 {
            return None;
        }
        match (self.total, self.available) {
            (total, Some(available)) => Some(total.saturating_sub(available)),
            (total, None) => self.free.map(|free| total.saturating_sub(free)),
        }
    }

    /// Used memory as percent of total, if both are known and total > 0.
    pub fn used_pct(&self) -> Option<f64> {
        let used = self.used()?;
        if self.total == 0 {
            return None;
        }
        Some(used as f64 * 100.0 / self.total as f64)
    }
}

/// Load average and the kernel's runnable/total process counts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct LoadAvg {
    /// 1-minute load.
    pub one: f64,
    /// 5-minute load.
    pub five: f64,
    /// 15-minute load.
    pub fifteen: f64,
    /// Currently runnable/total from `/proc/loadavg`.
    pub runnable: u32,
    /// Total processes/threads from `/proc/loadavg`.
    pub total: u32,
}

/// One PSI line (`some` and optional `full`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct PressureLine {
    /// 10-second average, percent.
    pub some_avg10: Option<f64>,
    /// 60-second average, percent.
    pub some_avg60: Option<f64>,
    /// 300-second average, percent.
    pub some_avg300: Option<f64>,
    /// Cumulative `some` stall microseconds.
    pub some_total_us: Option<u64>,
    /// 10-second average of full stalls, percent.
    pub full_avg10: Option<f64>,
    /// 60-second average of full stalls, percent.
    pub full_avg60: Option<f64>,
    /// 300-second average of full stalls, percent.
    pub full_avg300: Option<f64>,
    /// Cumulative `full` stall microseconds.
    pub full_total_us: Option<u64>,
}

/// Host pressure readings, each optional because PSI may be disabled.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct Pressure {
    /// `/proc/pressure/cpu`
    pub cpu: Option<PressureLine>,
    /// `/proc/pressure/memory`
    pub memory: Option<PressureLine>,
    /// `/proc/pressure/io`
    pub io: Option<PressureLine>,
}

/// Per-interface network counters from `/proc/net/dev`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetCounters {
    /// Received bytes.
    pub rx_bytes: u64,
    /// Received packets.
    pub rx_packets: u64,
    /// Receive errors.
    pub rx_errors: u64,
    /// Receive drops.
    pub rx_drops: u64,
    /// Transmitted bytes.
    pub tx_bytes: u64,
    /// Transmitted packets.
    pub tx_packets: u64,
    /// Transmit errors.
    pub tx_errors: u64,
    /// Transmit drops.
    pub tx_drops: u64,
}

/// Per-device I/O counters from `/proc/diskstats`, converted to bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskCounters {
    /// Completed reads.
    pub reads: u64,
    /// Completed writes.
    pub writes: u64,
    /// Bytes read (sectors × 512; the kernel reports 512-byte sectors).
    pub read_bytes: u64,
    /// Bytes written.
    pub write_bytes: u64,
    /// Milliseconds spent doing I/O.
    pub io_ms: u64,
}

/// Full host sample for one collection cycle.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct HostSample {
    /// Dual timestamps.
    pub stamps: Stamps,
    /// CPU counters (cumulative ticks; rates are derived).
    pub cpu: CpuTimes,
    /// Per-CPU counters, kept for diagnostics and later NUMA/topology work.
    pub per_cpu: Vec<CpuTimes>,
    /// Memory snapshot.
    pub mem: MemSnapshot,
    /// Load average.
    pub load: LoadAvg,
    /// Pressure Stall Information.
    pub pressure: Pressure,
    /// Network counters by interface name.
    pub net: BTreeMap<String, NetCounters>,
    /// Disk counters by device name.
    pub disk: BTreeMap<String, DiskCounters>,
    /// Running processes from `/proc/stat` (`procs_running`).
    pub procs_running: Option<u64>,
    /// Blocked processes from `/proc/stat` (`procs_blocked`).
    pub procs_blocked: Option<u64>,
    /// Host uptime in seconds.
    pub uptime_secs: Option<f64>,
    /// Boot epoch seconds (from `/proc/stat` `btime`).
    pub boot_time_secs: Option<u64>,
}

/// I/O counters for one device in a cgroup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CgroupIo {
    /// Device `major:minor`.
    pub device: String,
    /// Bytes read.
    pub read_bytes: Option<u64>,
    /// Bytes written.
    pub write_bytes: Option<u64>,
    /// Read operations.
    pub read_ops: Option<u64>,
    /// Write operations.
    pub write_ops: Option<u64>,
}

/// One cgroup v2 sample (counters are cumulative; the store keeps raw values).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CgroupSample {
    /// Dual timestamps.
    pub stamps: Stamps,
    /// Cgroup entity.
    pub entity_id: EntityId,
    /// Cgroup path relative to the hierarchy root.
    pub path: String,
    /// `cpu.stat` `usage_usec`.
    pub cpu_usage_usec: Option<u64>,
    /// `cpu.stat` `user_usec`.
    pub cpu_user_usec: Option<u64>,
    /// `cpu.stat` `system_usec`.
    pub cpu_system_usec: Option<u64>,
    /// `cpu.stat` `nr_periods`.
    pub cpu_nr_periods: Option<u64>,
    /// `cpu.stat` `nr_throttled`.
    pub cpu_nr_throttled: Option<u64>,
    /// `cpu.stat` `throttled_usec`.
    pub cpu_throttled_usec: Option<u64>,
    /// `memory.current`.
    pub memory_current: Option<u64>,
    /// `memory.peak`.
    pub memory_peak: Option<u64>,
    /// `memory.max` (limit); `None` when `max` (unlimited).
    pub memory_max: Option<u64>,
    /// `memory.stat` anon.
    pub memory_anon: Option<u64>,
    /// `memory.stat` file.
    pub memory_file: Option<u64>,
    /// `memory.swap.current`.
    pub memory_swap: Option<u64>,
    /// `cpu.max` quota in microseconds per period; `None` for `max`.
    pub cpu_quota_usec: Option<u64>,
    /// `cpu.max` period in microseconds.
    pub cpu_period_usec: Option<u64>,
    /// `pids.current`.
    pub pids_current: Option<u64>,
    /// Network receive bytes in the container network namespace (cumulative).
    pub net_rx_bytes: Option<u64>,
    /// Network transmit bytes in the container network namespace (cumulative).
    pub net_tx_bytes: Option<u64>,
    /// Network receive packets.
    pub net_rx_packets: Option<u64>,
    /// Network transmit packets.
    pub net_tx_packets: Option<u64>,
    /// Network receive errors.
    pub net_rx_errors: Option<u64>,
    /// Network transmit errors.
    pub net_tx_errors: Option<u64>,
    /// Network receive drops.
    pub net_rx_dropped: Option<u64>,
    /// Network transmit drops.
    pub net_tx_dropped: Option<u64>,
    /// `cpu.pressure`.
    pub psi_cpu: Option<PressureLine>,
    /// `memory.pressure`.
    pub psi_memory: Option<PressureLine>,
    /// `io.pressure`.
    pub psi_io: Option<PressureLine>,
    /// `io.stat` per device.
    pub io: Vec<CgroupIo>,
}

/// Per-process I/O counters from `/proc/PID/io`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcIo {
    /// Bytes passed through read-like syscalls (not physical reads).
    pub rchar: u64,
    /// Bytes passed through write-like syscalls (not physical writes).
    pub wchar: u64,
    /// Bytes fetched from storage.
    pub read_bytes: u64,
    /// Bytes sent to storage.
    pub write_bytes: u64,
    /// read syscall count.
    pub syscr: u64,
    /// write syscall count.
    pub syscw: u64,
}

/// Cgroup membership of a process, with the resolved path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CgroupRef {
    /// Cgroup v2 path as seen in `/proc/PID/cgroup`.
    pub path: String,
    /// Identity (inode/device) if the node was resolved on disk.
    pub identity: Option<CgroupIdentity>,
}

/// Universe of per-process facts collected in one cycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessObservation {
    /// Stable identity.
    pub identity: ProcessIdentity,
    /// `comm` (bounded to 64 bytes by the kernel).
    pub comm: String,
    /// Process state character (`R`, `S`, `D`, `Z`, ...).
    pub state: char,
    /// Parent host PID.
    pub ppid: u32,
    /// Executable path when readable (`/proc/PID/exe`).
    pub executable: Option<String>,
    /// Optional argv[0] (only when `process.store_arguments` is enabled).
    pub argv0: Option<String>,
    /// Cumulative user CPU ticks.
    pub cpu_user_ticks: u64,
    /// Cumulative system CPU ticks.
    pub cpu_system_ticks: u64,
    /// Number of threads.
    pub threads: u32,
    /// Resident set size in bytes.
    pub rss_bytes: Option<u64>,
    /// Virtual size in bytes.
    pub virtual_bytes: Option<u64>,
    /// `/proc/PID/io` counters, if permitted.
    pub io: Option<ProcIo>,
    /// Cgroup membership, if readable.
    pub cgroup: Option<CgroupRef>,
    /// Classification labels from enrichment (baseline observation never depends on it).
    pub classification: Option<Classification>,
}

/// One persisted process sample.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessSample {
    /// Dual timestamps.
    pub stamps: Stamps,
    /// Process entity id.
    pub process_instance_id: EntityId,
    /// Cumulative user CPU ticks.
    pub cpu_user_ticks: u64,
    /// Cumulative system CPU ticks.
    pub cpu_system_ticks: u64,
    /// RSS bytes.
    pub rss_bytes: Option<u64>,
    /// Virtual bytes.
    pub virtual_bytes: Option<u64>,
    /// Storage read bytes (cumulative).
    pub read_bytes: Option<u64>,
    /// Storage write bytes (cumulative).
    pub write_bytes: Option<u64>,
    /// rchar (cumulative).
    pub read_chars: Option<u64>,
    /// wchar (cumulative).
    pub write_chars: Option<u64>,
    /// Thread count.
    pub threads: Option<u32>,
    /// State character.
    pub state: Option<char>,
    /// Bit flags describing what was unavailable during collection.
    pub sample_flags: u32,
}

/// Flag bits explaining why parts of a process sample are missing (never "zero").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SampleFlag {
    /// `/proc/PID/io` was denied or absent.
    IoUnavailable = 1,
    /// RSS/VSZ unavailable (e.g. zombie).
    MemoryUnavailable = 2,
    /// Executable path unresolved.
    ExecutableUnavailable = 4,
    /// Cgroup membership unresolved.
    CgroupUnavailable = 8,
    /// Process was inferred from an event but never sampled.
    EventOnly = 16,
}

impl SampleFlag {
    /// Bit value.
    pub const fn bit(self) -> u32 {
        self as u32
    }
}

/// Broad category of a recognized tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolCategory {
    /// Docker, containerd, CRI.
    ContainerRuntime,
    /// nginx, caddy, traefik.
    WebServer,
    /// cloudflared, sing-box, xray, ngrok.
    Tunnel,
    /// tmux, zellij, screen.
    SessionManager,
    /// systemd.
    ServiceManager,
    /// cron, systemd timers.
    Scheduler,
    /// cargo, rustc, linkers.
    BuildTool,
    /// ip, ss, curl, wget, tcpdump.
    NetworkTool,
    /// Cloud provider CLIs.
    CloudCli,
    /// rg, jq, yq, watch.
    TextTool,
    /// ps, top, htop and SARF itself.
    Monitor,
    /// Anything else.
    Other,
}

impl ToolCategory {
    /// Stable string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ContainerRuntime => "container_runtime",
            Self::WebServer => "web_server",
            Self::Tunnel => "tunnel",
            Self::SessionManager => "session_manager",
            Self::ServiceManager => "service_manager",
            Self::Scheduler => "scheduler",
            Self::BuildTool => "build_tool",
            Self::NetworkTool => "network_tool",
            Self::CloudCli => "cloud_cli",
            Self::TextTool => "text_tool",
            Self::Monitor => "monitor",
            Self::Other => "other",
        }
    }
}

/// Declarative integration descriptor loaded from `config/integrations/*.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ToolSpec {
    /// Stable integration id (`docker`, `nginx`, `cloudflared`, `tmux`, `zellij`, ...).
    pub id: String,
    /// Display name.
    pub name: String,
    /// Category.
    pub category: ToolCategory,
    /// Executable basenames that identify this tool.
    #[serde(default)]
    pub executables: Vec<String>,
    /// Exact `comm` values that identify this tool.
    #[serde(default)]
    pub comm: Vec<String>,
    /// Short description shown by `sarf tools show`.
    #[serde(default)]
    pub description: String,
    /// Whether enrichment is attempted when the tool is detected.
    #[serde(default)]
    pub default_enabled: bool,
    /// Capabilities this adapter claims (see guide §3.2).
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Matching rules used to derive a role/label from a process.
    #[serde(default)]
    pub roles: Vec<ToolRole>,
}

/// A role rule for a recognized tool: match and label.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ToolRole {
    /// Label shown in reports.
    pub label: String,
    /// Match on process name/comm/exe basename (case-insensitive substring or equality).
    #[serde(default)]
    pub comm_contains: Vec<String>,
    /// Exact `comm` equality (case-insensitive), checked before substring rules.
    #[serde(default)]
    pub comm_equals: Vec<String>,
    /// Match on arguments of the process (when argv is available).
    #[serde(default)]
    pub argv_contains: Vec<String>,
    /// Match on cgroup path fragment.
    #[serde(default)]
    pub cgroup_contains: Vec<String>,
}

/// Enrichment verdict for one process.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Classification {
    /// Recognized tool id.
    pub tool: Option<String>,
    /// Category of the tool.
    pub category: Option<ToolCategory>,
    /// Human-readable role, e.g. `nginx master`, `docker container web-1`.
    pub role: Option<String>,
    /// Container id when the process belongs to a container.
    pub container_id: Option<String>,
    /// systemd unit inferred from cgroup.
    pub unit: Option<String>,
    /// Terminal session id when attributed.
    pub session: Option<String>,
}

impl Classification {
    /// A short combined label used in tables.
    pub fn label(&self) -> String {
        let mut parts = Vec::new();
        if let Some(role) = &self.role {
            parts.push(role.clone());
        }
        if let Some(tool) = &self.tool {
            if !parts.iter().any(|p| p == tool) {
                parts.push(tool.clone());
            }
        }
        if parts.is_empty() {
            "unrecognized".to_string()
        } else {
            parts.join(" / ")
        }
    }
}

/// Severity of an event or log line. Ordering is defined so thresholds compare.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Verbose diagnostics.
    Debug,
    /// Normal activity.
    Info,
    /// A warning worth keeping.
    Warn,
    /// An error.
    Error,
    /// Panic/fatal/OOM-level record.
    Critical,
}

impl Severity {
    /// Stable database string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
            Self::Critical => "critical",
        }
    }

    /// Parse a database or log-level string, case-insensitively.
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_uppercase().as_str() {
            "DEBUG" | "TRACE" | "DBG" => Some(Self::Debug),
            "INFO" | "NOTICE" | "INF" => Some(Self::Info),
            "WARN" | "WARNING" | "WRN" => Some(Self::Warn),
            "ERROR" | "ERR" => Some(Self::Error),
            "FATAL" | "CRIT" | "CRITICAL" | "PANIC" | "ALERT" | "EMERG" | "FTL" => {
                Some(Self::Critical)
            }
            _ => None,
        }
    }
}

/// Whether the record came from stdout, stderr, a journal or a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogStream {
    /// Engine/daemon stdout.
    Stdout,
    /// Engine/daemon stderr.
    Stderr,
    /// A file source (nginx, cloudflared, app).
    File,
    /// systemd journal (future adapter).
    Journal,
    /// Application structured stream (future adapter).
    App,
}

impl LogStream {
    /// Stable string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
            Self::File => "file",
            Self::Journal => "journal",
            Self::App => "app",
        }
    }
}

/// One normalized, bounded log record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogRecord {
    /// Wall clock of the source or of ingestion.
    pub wall_ns: i64,
    /// Monotonic timestamp of ingestion.
    pub mono_ns: Option<i64>,
    /// Source id (configured or discovered).
    pub source_id: String,
    /// Entity that emitted the record, when known.
    pub entity_id: Option<EntityId>,
    /// Stream the record came from.
    pub stream: LogStream,
    /// Best-effort severity.
    pub level: Option<Severity>,
    /// Bounded and redacted message body.
    pub message: String,
    /// Whether the original line was truncated.
    pub truncated: bool,
    /// Incident this record was captured for, when part of an evidence window.
    pub incident_id: Option<i64>,
    /// Whether redaction changed the message.
    pub redacted: bool,
}

/// Kinds of lifecycle/control events recorded by SARF.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// A process was first observed (or reported by an event source).
    ProcessStarted,
    /// A process disappeared.
    ProcessExited,
    /// A process changed executable identity (exec generation).
    ProcessExec,
    /// A container appeared.
    ContainerStarted,
    /// A container disappeared.
    ContainerStopped,
    /// A container reported OOM/unhealthy/restart.
    ContainerWarning,
    /// A systemd/session/scheduler lifecycle observation.
    ServiceEvent,
    /// An incident opened.
    IncidentOpened,
    /// An incident closed.
    IncidentClosed,
    /// A log source flooded and records were dropped.
    LogFlood,
    /// A collector lost records or a gap was detected.
    CollectGap,
    /// An integration was unavailable/partial.
    IntegrationDegraded,
    /// A configured threshold was crossed.
    ThresholdCrossed,
}

impl EventKind {
    /// Stable string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProcessStarted => "process_started",
            Self::ProcessExited => "process_exited",
            Self::ProcessExec => "process_exec",
            Self::ContainerStarted => "container_started",
            Self::ContainerStopped => "container_stopped",
            Self::ContainerWarning => "container_warning",
            Self::ServiceEvent => "service_event",
            Self::IncidentOpened => "incident_opened",
            Self::IncidentClosed => "incident_closed",
            Self::LogFlood => "log_flood",
            Self::CollectGap => "collect_gap",
            Self::IntegrationDegraded => "integration_degraded",
            Self::ThresholdCrossed => "threshold_crossed",
        }
    }

    /// Parse a database string.
    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "process_started" => Self::ProcessStarted,
            "process_exited" => Self::ProcessExited,
            "process_exec" => Self::ProcessExec,
            "container_started" => Self::ContainerStarted,
            "container_stopped" => Self::ContainerStopped,
            "container_warning" => Self::ContainerWarning,
            "service_event" => Self::ServiceEvent,
            "incident_opened" => Self::IncidentOpened,
            "incident_closed" => Self::IncidentClosed,
            "log_flood" => Self::LogFlood,
            "collect_gap" => Self::CollectGap,
            "integration_degraded" => Self::IntegrationDegraded,
            "threshold_crossed" => Self::ThresholdCrossed,
            _ => return None,
        })
    }
}

/// One event row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventRecord {
    /// Wall clock.
    pub wall_ns: i64,
    /// Monotonic clock.
    pub mono_ns: Option<i64>,
    /// Related entity.
    pub entity_id: Option<EntityId>,
    /// Event kind.
    pub kind: EventKind,
    /// Severity.
    pub severity: Severity,
    /// Bounded JSON payload with facts (never secrets).
    pub payload: serde_json::Value,
    /// Source that produced the event.
    pub provenance: String,
    /// Records known lost before this event, if the source reports it.
    pub lost_before: u64,
}

/// Metric identity used by incidents and attribution windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Metric {
    /// CPU percentage of one core.
    Cpu,
    /// Resident memory bytes.
    Memory,
    /// Storage read bytes per interval.
    IoRead,
    /// Storage write bytes per interval.
    IoWrite,
    /// Network receive bytes per interval.
    NetRx,
    /// Network transmit bytes per interval.
    NetTx,
    /// CPU pressure stall percent (`some avg10`).
    PsiCpu,
    /// Memory pressure stall percent.
    PsiMemory,
    /// I/O pressure stall percent.
    PsiIo,
    /// Host load average (1 minute).
    Load,
}

impl Metric {
    /// Stable string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Memory => "memory",
            Self::IoRead => "io_read",
            Self::IoWrite => "io_write",
            Self::NetRx => "net_rx",
            Self::NetTx => "net_tx",
            Self::PsiCpu => "psi_cpu",
            Self::PsiMemory => "psi_memory",
            Self::PsiIo => "psi_io",
            Self::Load => "load",
        }
    }

    /// Parse a database string.
    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "cpu" => Self::Cpu,
            "memory" => Self::Memory,
            "io_read" => Self::IoRead,
            "io_write" => Self::IoWrite,
            "net_rx" => Self::NetRx,
            "net_tx" => Self::NetTx,
            "psi_cpu" => Self::PsiCpu,
            "psi_memory" => Self::PsiMemory,
            "psi_io" => Self::PsiIo,
            "load" => Self::Load,
            _ => return None,
        })
    }

    /// Unit label used in reports.
    pub const fn unit(self) -> &'static str {
        match self {
            Self::Cpu | Self::PsiCpu | Self::PsiMemory | Self::PsiIo => "%",
            Self::Memory => "bytes",
            Self::IoRead | Self::IoWrite | Self::NetRx | Self::NetTx => "bytes/s",
            Self::Load => "load",
        }
    }
}

/// Whether an attribution window is an unusually high or unusually low activity period.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowKind {
    /// Resource usage significantly above the window baseline.
    High,
    /// Resource usage significantly below the window baseline (drops/idle/stops).
    Low,
}

/// One ranked contributor inside an attribution window.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Contribution {
    /// Entity that contributed.
    pub entity_id: EntityId,
    /// Display name.
    pub name: String,
    /// Entity kind.
    pub kind: EntityKind,
    /// Recognized tool, when any.
    pub tool: Option<String>,
    /// Container id/name, when the entity is container-scoped.
    pub container: Option<String>,
    /// Metric value observed for this entity in the window.
    pub value: f64,
    /// Percentage of the window total attributable to this entity, when meaningful.
    pub share_pct: Option<f64>,
    /// Short evidence lines tied to this contributor.
    pub evidence: Vec<String>,
}

/// A high/low resource window with attributed contributors.
///
/// This is the answer to "what was happening at this time and what likely caused
/// the high/low resource usage". It reports observations and associations; it never
/// claims proof of causation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttributionWindow {
    /// Window start, wall clock.
    pub start_wall_ns: i64,
    /// Window end, wall clock.
    pub end_wall_ns: i64,
    /// High or low.
    pub kind: WindowKind,
    /// Metric that triggered the window.
    pub metric: Metric,
    /// Peak/average value of the metric inside the window.
    pub value: f64,
    /// Window baseline (median of all buckets) for comparison.
    pub baseline: f64,
    /// Ratio/absolute change versus baseline, percent.
    pub change_pct: f64,
    /// Contributing entities, ranked.
    pub contributors: Vec<Contribution>,
    /// Free-form evidence lines about host context, logs and events.
    pub evidence: Vec<String>,
    /// Confidence in the association (0..1), not in causation.
    pub confidence: f64,
}

/// An incident: a bounded, deduplicated threshold/anomaly episode.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Incident {
    /// Database id (`None` before insertion).
    pub incident_id: Option<i64>,
    /// Start, wall clock.
    pub started_wall_ns: i64,
    /// End, wall clock; `None` while open.
    pub ended_wall_ns: Option<i64>,
    /// Entity the incident belongs to (host or cgroup/process id).
    pub entity_id: Option<EntityId>,
    /// Metric.
    pub metric: Metric,
    /// Human-readable reason.
    pub reason: String,
    /// Peak value.
    pub peak: f64,
    /// Baseline value at open.
    pub baseline: f64,
    /// JSON evidence (bounded; see `analysis`).
    pub evidence: serde_json::Value,
    /// Whether the user acknowledged it.
    pub acknowledged: bool,
    /// Whether evidence was lost while the incident was open.
    pub evidence_loss: bool,
}

/// Collector availability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Availability {
    /// Working.
    Available,
    /// Not usable at all on this host.
    Unavailable,
    /// Working with documented gaps.
    Partial,
    /// Not yet determined.
    Unknown,
}

impl Availability {
    /// Stable string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Unavailable => "unavailable",
            Self::Partial => "partial",
            Self::Unknown => "unknown",
        }
    }

    /// Parse a database string.
    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "available" => Self::Available,
            "unavailable" => Self::Unavailable,
            "partial" => Self::Partial,
            "unknown" => Self::Unknown,
            _ => return None,
        })
    }
}

/// Configured state of a collector/integration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfiguredState {
    /// Explicitly enabled.
    Enabled,
    /// Explicitly disabled.
    Disabled,
    /// Enabled when detection succeeds.
    Auto,
}

impl ConfiguredState {
    /// Stable string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::Disabled => "disabled",
            Self::Auto => "auto",
        }
    }
}

/// Permission outcome for a collector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionState {
    /// Required access worked.
    Permitted,
    /// Access denied.
    Denied,
    /// Some fields/records were readable.
    Partial,
    /// Not determined yet.
    Unknown,
}

impl PermissionState {
    /// Stable string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Permitted => "permitted",
            Self::Denied => "denied",
            Self::Partial => "partial",
            Self::Unknown => "unknown",
        }
    }
}

/// Health and loss accounting for one collector (guide §19).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectorHealth {
    /// Collector id (`procfs`, `cgroup_v2`, `docker`, `tmux`, ...).
    pub collector_id: String,
    /// Configured state.
    pub configured: ConfiguredState,
    /// Detected availability.
    pub availability: Availability,
    /// Permission outcome.
    pub permission: PermissionState,
    /// Last successful observation, wall clock.
    pub last_success_wall_ns: Option<i64>,
    /// Last error, wall clock.
    pub last_error_wall_ns: Option<i64>,
    /// Last error message (bounded).
    pub last_error: Option<String>,
    /// Number of errors.
    pub error_count: u64,
    /// Records received from the source.
    pub received_count: u64,
    /// Records persisted.
    pub persisted_count: u64,
    /// Records dropped (queue full, rate limit, policy).
    pub dropped_count: u64,
    /// Records truncated (line/field caps).
    pub truncated_count: u64,
    /// Queue high-water mark.
    pub queue_high_water: u64,
    /// Extra coverage details (bounded JSON).
    pub coverage: serde_json::Value,
}

/// A known collection gap to surface in reports and `sarf gaps`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageGap {
    /// Collector or source.
    pub source_id: String,
    /// Gap kind (`permission`, `absent_interface`, `dropped`, `unsupported`, ...).
    pub kind: String,
    /// Since when, wall clock.
    pub since_wall_ns: Option<i64>,
    /// Human-readable detail (bounded).
    pub detail: String,
}

/// Storage write priority used by the bounded writer queue (guide degradation order).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum WritePriority {
    /// INFO logs, low-value samples: dropped first.
    Low = 0,
    /// Normal samples and lifecycle events.
    Normal = 1,
    /// Incidents, critical logs, gaps: preserved longest.
    Critical = 2,
}

/// The value of a metric for one entity at one instant.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricPoint {
    /// Wall clock.
    pub wall_ns: i64,
    /// Monotonic clock.
    pub mono_ns: i64,
    /// Value in the metric's unit.
    pub value: f64,
}

impl HostSample {
    /// Host-wide CPU usage percentage from two cumulative samples.
    ///
    /// Returns `None` when the counters decreased or no time elapsed, so callers can
    /// record a counter anomaly instead of a fabricated spike.
    pub fn cpu_usage_pct(previous: &Self, current: &Self) -> Option<f64> {
        let delta = current.cpu.delta(previous.cpu)?;
        let total = delta.total();
        if total == 0 {
            return None;
        }
        let busy = delta.user + delta.nice + delta.system + delta.irq + delta.softirq + delta.steal;
        Some(busy as f64 * 100.0 / total as f64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_identity_never_keys_on_pid_alone() {
        let a = ProcessIdentity::new("abcd1234", 42, 100);
        let b = ProcessIdentity::new("abcd1234", 42, 200);
        assert_ne!(a.entity_id(), b.entity_id());
        assert_eq!(a.entity_id(), "proc:abcd1234:42:100");
        assert_eq!(a.stable_key(), "42:100");
    }

    #[test]
    fn cpu_delta_rejects_counter_resets() {
        let before = CpuTimes {
            user: 100,
            idle: 50,
            ..Default::default()
        };
        let after = CpuTimes {
            user: 120,
            idle: 60,
            ..Default::default()
        };
        let delta = after.delta(before).expect("monotonic counters");
        assert_eq!(delta.user, 20);
        assert_eq!(delta.idle, 10);
        // A reset (reboot or wrap) must be reported, not turned into a spike.
        assert!(before.delta(after).is_none());
    }

    #[test]
    fn guest_time_is_not_double_counted() {
        let times = CpuTimes {
            user: 100,
            guest: 40,
            idle: 100,
            ..Default::default()
        };
        assert_eq!(times.total(), 200);
        assert_eq!(times.busy(), 100);
    }

    #[test]
    fn memory_used_prefers_available_semantics() {
        let mem = MemSnapshot {
            total: 1000,
            free: Some(100),
            available: Some(400),
            ..Default::default()
        };
        assert_eq!(mem.used(), Some(600));
        assert_eq!(mem.used_pct(), Some(60.0));
        let no_available = MemSnapshot {
            total: 1000,
            free: Some(200),
            ..Default::default()
        };
        assert_eq!(no_available.used(), Some(800));
        let unknown = MemSnapshot::default();
        assert_eq!(unknown.used(), None);
        assert_eq!(unknown.used_pct(), None);
    }

    #[test]
    fn entity_and_severity_roundtrip() {
        for kind in [
            EntityKind::Host,
            EntityKind::Cgroup,
            EntityKind::Container,
            EntityKind::Process,
            EntityKind::Session,
        ] {
            assert_eq!(EntityKind::parse(kind.as_str()), Some(kind));
        }
        for level in [
            Severity::Debug,
            Severity::Info,
            Severity::Warn,
            Severity::Error,
            Severity::Critical,
        ] {
            assert_eq!(Severity::parse(level.as_str()), Some(level));
        }
        assert!(Severity::Warn < Severity::Error);
        assert_eq!(Severity::parse("warning"), Some(Severity::Warn));
    }

    #[test]
    fn metric_roundtrip_and_units() {
        for metric in [
            Metric::Cpu,
            Metric::Memory,
            Metric::IoRead,
            Metric::IoWrite,
            Metric::NetRx,
            Metric::NetTx,
            Metric::PsiCpu,
            Metric::PsiMemory,
            Metric::PsiIo,
            Metric::Load,
        ] {
            assert_eq!(Metric::parse(metric.as_str()), Some(metric));
        }
        assert_eq!(Metric::Cpu.unit(), "%");
        assert_eq!(Metric::Memory.unit(), "bytes");
    }

    #[test]
    fn cgroup_identity_uses_inode_and_device_not_path() {
        let a = CgroupIdentity {
            device: 1,
            inode: 10,
        };
        let b = CgroupIdentity {
            device: 1,
            inode: 11,
        };
        assert_ne!(a.entity_id(), b.entity_id());
        assert_eq!(a.entity_id(), "cgroup:1:10");
    }

    #[test]
    fn host_cpu_pct_is_derived_from_counters() {
        let before = HostSample {
            cpu: CpuTimes {
                user: 100,
                idle: 100,
                ..Default::default()
            },
            ..Default::default()
        };
        let after = HostSample {
            cpu: CpuTimes {
                user: 200,
                idle: 140,
                ..Default::default()
            },
            ..Default::default()
        };
        // 100 busy / 140 total = 71.43%
        let pct = HostSample::cpu_usage_pct(&before, &after).expect("delta");
        assert!((pct - 71.428).abs() < 0.01, "got {pct}");
    }

    #[test]
    fn classification_label_never_empty() {
        assert_eq!(Classification::default().label(), "unrecognized");
        let c = Classification {
            tool: Some("nginx".into()),
            role: Some("nginx worker".into()),
            ..Default::default()
        };
        assert_eq!(c.label(), "nginx worker / nginx");
    }
}
