//! Read-only collectors for host, cgroup, process and log sources.
//!
//! A [`SourceRoot`] is the seam between real `/proc`/`/sys` and fixture trees. It
//! exists because the fixture integration tests and the Linux runtime path need the
//! same parsers without copying them; it is not a plugin abstraction.
//!
//! Every collector is read-only. Missing interfaces and denied fields are recorded as
//! availability/permission states and [`crate::model::CoverageGap`]s, never as zero.

pub mod cgroup;
pub mod host;
pub mod logs;
pub mod process;
pub mod procfs;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::model::{
    Availability, CollectorHealth, ConfiguredState, PermissionState, WritePriority,
};
use crate::time::WallNs;

/// Linux `USER_HZ` for the process CPU tick counters.
///
/// The kernel's userspace ABI defines `USER_HZ` as 100 on every supported 64-bit
/// Linux architecture (the historical 1024 Alpha value is out of scope). SARF stores
/// raw ticks and only uses this constant to convert deltas to microseconds.
pub const CLOCK_TICKS_PER_SECOND: u64 = 100;

/// Where a collector reads its pseudo-files from.
#[allow(
    clippy::struct_field_names,
    reason = "the three fields mirror the pseudo-filesystems (/proc, /sys, cgroup) and \
              the shared `_root` suffix is what makes each accessor unambiguous"
)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceRoot {
    proc_root: PathBuf,
    sys_root: PathBuf,
    cgroup_root: Option<PathBuf>,
}

impl SourceRoot {
    /// Real host roots, discovering the cgroup v2 mount from mountinfo.
    pub fn real() -> Self {
        let proc_root = PathBuf::from("/proc");
        let sys_root = PathBuf::from("/sys");
        let cgroup_root = procfs::read_optional(&proc_root.join("self/mountinfo"))
            .and_then(|text| procfs::parse_cgroup2_mount(&text));
        Self {
            proc_root,
            sys_root,
            cgroup_root,
        }
    }

    /// Fixture roots: `<root>/proc` and `<root>/sys`, with cgroup v2 at
    /// `<root>/sys/fs/cgroup` when present.
    pub fn fixture(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        let proc_root = root.join("proc");
        let sys_root = root.join("sys");
        let candidate = sys_root.join("fs/cgroup");
        let cgroup_root = candidate.is_dir().then_some(candidate);
        Self {
            proc_root,
            sys_root,
            cgroup_root,
        }
    }

    /// Root of the procfs tree.
    pub fn proc_root(&self) -> &Path {
        &self.proc_root
    }

    /// Root of the sysfs tree.
    pub fn sys_root(&self) -> &Path {
        &self.sys_root
    }

    /// Detected cgroup v2 mount, if any.
    pub fn cgroup_root(&self) -> Option<&Path> {
        self.cgroup_root.as_deref()
    }

    /// Path inside procfs.
    pub fn proc_path(&self, relative: impl AsRef<Path>) -> PathBuf {
        self.proc_root.join(relative)
    }

    /// Path inside sysfs.
    pub fn sys_path(&self, relative: impl AsRef<Path>) -> PathBuf {
        self.sys_root.join(relative)
    }

    /// Read a procfs file with the standard bound.
    pub fn read_proc(&self, relative: impl AsRef<Path>) -> Result<String> {
        let path = self.proc_path(relative);
        procfs::read_text_bounded(&path, procfs::MAX_PROC_FILE_BYTES)
    }

    /// Read an optional procfs file.
    pub fn read_proc_opt(&self, relative: impl AsRef<Path>) -> Option<String> {
        self.read_proc(relative).ok()
    }

    /// Whether the tree looks like a Linux procfs view (has `stat` and `meminfo`).
    pub fn has_procfs(&self) -> bool {
        self.proc_root.join("stat").is_file() && self.proc_root.join("meminfo").is_file()
    }
}

/// Stable facts about the observed host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostFacts {
    /// Full boot UUID from `/proc/sys/kernel/random/boot_id`.
    pub boot_id: String,
    /// Hostname.
    pub hostname: String,
    /// Kernel release.
    pub kernel_release: String,
    /// Architecture string.
    pub architecture: String,
    /// Clock ticks per second used for process CPU deltas.
    pub clock_ticks: u64,
}

impl HostFacts {
    /// Read host facts from a source root.
    ///
    /// A missing boot id is replaced with a deterministic fallback derived from the
    /// source root; that only happens for fixtures and is reported in coverage.
    pub fn read(root: &SourceRoot) -> Self {
        let boot_id = root
            .read_proc_opt("sys/kernel/random/boot_id")
            .map(|text| text.trim().to_string())
            .filter(|text| !text.is_empty())
            .unwrap_or_else(|| {
                format!(
                    "boot-{}",
                    short_hash(root.proc_root().to_string_lossy().as_ref())
                )
            });
        let hostname = root.read_proc_opt("sys/kernel/hostname").map_or_else(
            || {
                std::env::var("HOSTNAME")
                    .or_else(|_| std::env::var("COMPUTERNAME"))
                    .unwrap_or_else(|_| "unknown-host".to_string())
            },
            |text| text.trim().to_string(),
        );
        let kernel_release = root
            .read_proc_opt("sys/kernel/osrelease")
            .map_or_else(|| "unknown".to_string(), |text| text.trim().to_string());
        Self {
            boot_id,
            hostname,
            kernel_release,
            architecture: std::env::consts::ARCH.to_string(),
            clock_ticks: CLOCK_TICKS_PER_SECOND,
        }
    }

    /// Short boot id used in entity ids (the first UUID segment is enough).
    pub fn short_boot_id(&self) -> &str {
        self.boot_id.get(..8).unwrap_or(&self.boot_id)
    }
}

fn short_hash(text: &str) -> String {
    // FNV-1a: deterministic, dependency-free, only used for fixture labels.
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in text.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

/// Counter/health bookkeeping shared by all collectors.
///
/// The registry lives in memory and is persisted periodically by the daemon, so a
/// busy 5-second loop does not issue a health write per cycle. `dropped` is incremented
/// only where a bounded path actually discarded something.
#[derive(Debug, Clone, Default)]
pub struct HealthRegistry {
    entries: BTreeMap<String, CollectorHealth>,
}

impl HealthRegistry {
    /// Create a registry and register the core collectors.
    pub fn new() -> Self {
        let mut registry = Self::default();
        for (id, configured) in [
            ("procfs", ConfiguredState::Enabled),
            ("cgroup_v2", ConfiguredState::Auto),
            ("process_inventory", ConfiguredState::Enabled),
            ("process_events", ConfiguredState::Auto),
            ("process_samples", ConfiguredState::Enabled),
            ("retention", ConfiguredState::Enabled),
            ("writer", ConfiguredState::Enabled),
            ("logs_file", ConfiguredState::Auto),
            ("logs_docker", ConfiguredState::Auto),
            ("docker", ConfiguredState::Auto),
            ("docker_api", ConfiguredState::Auto),
            ("docker_logs", ConfiguredState::Auto),
            ("tmux", ConfiguredState::Auto),
            ("zellij", ConfiguredState::Auto),
            ("nginx", ConfiguredState::Auto),
            ("cloudflared", ConfiguredState::Auto),
            ("systemd", ConfiguredState::Auto),
        ] {
            registry.register(id, configured);
        }
        registry
    }

    /// Register a collector with an initial state.
    pub fn register(&mut self, id: &str, configured: ConfiguredState) {
        self.entries
            .entry(id.to_string())
            .or_insert_with(|| CollectorHealth {
                collector_id: id.to_string(),
                configured,
                availability: Availability::Unknown,
                permission: PermissionState::Unknown,
                last_success_wall_ns: None,
                last_error_wall_ns: None,
                last_error: None,
                error_count: 0,
                received_count: 0,
                persisted_count: 0,
                dropped_count: 0,
                truncated_count: 0,
                queue_high_water: 0,
                coverage: serde_json::Value::Null,
            });
    }

    /// Mutable access to one collector.
    pub fn entry(&mut self, id: &str) -> Option<&mut CollectorHealth> {
        self.entries.get_mut(id)
    }

    /// Mark a successful observation.
    pub fn success(&mut self, id: &str, now_wall_ns: WallNs) {
        if let Some(entry) = self.entries.get_mut(id) {
            entry.last_success_wall_ns = Some(now_wall_ns);
            entry.availability = Availability::Available;
            entry.permission = PermissionState::Permitted;
        }
    }

    /// Mark a successful but incomplete observation.
    pub fn partial(&mut self, id: &str, now_wall_ns: WallNs, permission: PermissionState) {
        if let Some(entry) = self.entries.get_mut(id) {
            entry.last_success_wall_ns = Some(now_wall_ns);
            entry.availability = Availability::Partial;
            entry.permission = permission;
        }
    }

    /// Record an error, keeping the last bounded message.
    pub fn error(&mut self, id: &str, now_wall_ns: WallNs, message: &str) {
        if let Some(entry) = self.entries.get_mut(id) {
            entry.last_error_wall_ns = Some(now_wall_ns);
            let (message, _) = crate::store::truncate_utf8(message, 512);
            entry.last_error = Some(message);
            entry.error_count = entry.error_count.saturating_add(1);
            if entry.availability == Availability::Unknown
                || entry.availability == Availability::Available
            {
                entry.availability = Availability::Partial;
            }
        }
    }

    /// Mark an interface absent on this host.
    pub fn unavailable(&mut self, id: &str, message: &str) {
        if let Some(entry) = self.entries.get_mut(id) {
            entry.availability = Availability::Unavailable;
            let (message, _) = crate::store::truncate_utf8(message, 512);
            entry.last_error = Some(message);
        }
    }

    /// Mark access as denied.
    pub fn denied(&mut self, id: &str) {
        if let Some(entry) = self.entries.get_mut(id) {
            entry.availability = Availability::Partial;
            entry.permission = PermissionState::Denied;
        }
    }

    /// Record received records.
    pub fn received(&mut self, id: &str, count: u64) {
        if let Some(entry) = self.entries.get_mut(id) {
            entry.received_count = entry.received_count.saturating_add(count);
        }
    }

    /// Record persisted records.
    pub fn persisted(&mut self, id: &str, count: u64) {
        if let Some(entry) = self.entries.get_mut(id) {
            entry.persisted_count = entry.persisted_count.saturating_add(count);
        }
    }

    /// Record dropped records.
    pub fn dropped(&mut self, id: &str, count: u64) {
        if let Some(entry) = self.entries.get_mut(id) {
            entry.dropped_count = entry.dropped_count.saturating_add(count);
        }
    }

    /// Record truncated records.
    pub fn truncated(&mut self, id: &str, count: u64) {
        if let Some(entry) = self.entries.get_mut(id) {
            entry.truncated_count = entry.truncated_count.saturating_add(count);
        }
    }

    /// Record the queue high-water mark.
    pub fn queue_high_water(&mut self, id: &str, depth: u64) {
        if let Some(entry) = self.entries.get_mut(id) {
            entry.queue_high_water = entry.queue_high_water.max(depth);
        }
    }

    /// Set the coverage JSON object for a collector.
    pub fn coverage(&mut self, id: &str, coverage: serde_json::Value) {
        if let Some(entry) = self.entries.get_mut(id) {
            entry.coverage = coverage;
        }
    }

    /// Snapshot every entry as write items.
    pub fn write_items(&self) -> Vec<crate::store::WriteItem> {
        self.entries
            .values()
            .cloned()
            .map(|health| {
                crate::store::WriteItem::normal(crate::store::WriteRecord::CollectorHealth(health))
            })
            .collect()
    }

    /// All entries, for `doctor` and reports.
    pub fn all(&self) -> Vec<CollectorHealth> {
        self.entries.values().cloned().collect()
    }
}

/// Map an I/O error into availability for a collector.
pub const fn classify_error(error: &Error) -> (Availability, PermissionState) {
    match error {
        Error::PermissionDenied { .. } => (Availability::Partial, PermissionState::Denied),
        Error::Unavailable { .. } => (Availability::Unavailable, PermissionState::Unknown),
        _ => (Availability::Partial, PermissionState::Unknown),
    }
}

/// Priority helper for samples: critical lifecycle evidence survives pressure, raw
/// samples are normal and informational logs are low (guide §19).
pub const fn sample_priority() -> WritePriority {
    WritePriority::Normal
}

impl From<&HostFacts> for crate::model::Entity {
    fn from(facts: &HostFacts) -> Self {
        Self {
            entity_id: format!("host:{}", facts.short_boot_id()),
            kind: crate::model::EntityKind::Host,
            stable_key: facts.boot_id.clone(),
            name: facts.hostname.clone(),
            source: "procfs".to_string(),
            labels: BTreeMap::from([
                ("kernel".to_string(), facts.kernel_release.clone()),
                ("architecture".to_string(), facts.architecture.clone()),
            ]),
            first_seen_wall_ns: 0,
            last_seen_wall_ns: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_root_maps_proc_and_sys() {
        let root = SourceRoot::fixture("/tmp/fixture");
        assert_eq!(
            root.proc_path("stat"),
            PathBuf::from("/tmp/fixture/proc/stat")
        );
        assert_eq!(
            root.sys_path("fs/cgroup"),
            PathBuf::from("/tmp/fixture/sys/fs/cgroup")
        );
    }

    #[test]
    fn host_facts_have_a_stable_fallback_boot_id() {
        let root = SourceRoot::fixture("/nonexistent-sarf-fixture");
        let facts = HostFacts::read(&root);
        assert_ne!(facts.boot_id, "");
        assert_eq!(facts.boot_id, HostFacts::read(&root).boot_id);
    }

    #[test]
    fn health_registry_tracks_outcomes_without_growing() {
        let mut registry = HealthRegistry::new();
        let before = registry.all().len();
        registry.register("procfs", ConfiguredState::Enabled);
        assert_eq!(registry.all().len(), before);
        registry.success("procfs", 1);
        registry.error("procfs", 2, &"x".repeat(4096));
        registry.dropped("procfs", 3);
        let entry = registry
            .all()
            .into_iter()
            .find(|entry| entry.collector_id == "procfs")
            .expect("procfs");
        assert_eq!(entry.error_count, 1);
        assert!(entry.last_error.expect("error").len() <= 515);
        assert_eq!(entry.dropped_count, 3);
    }
}
