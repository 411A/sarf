//! cgroup v2 discovery and sampling (guide §5.3).
//!
//! cgroup v2 is the primary service/container accounting source. Discovery walks the
//! detected hierarchy instead of assuming a Docker path, and identity is
//! `(device, inode)` so a removed and recreated cgroup with the same path is a new
//! entity. Collection is strictly read-only.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::model::{CgroupIdentity, CgroupSample, Entity, EntityKind};
use crate::time::Stamps;

use super::procfs;
use super::SourceRoot;

/// Maximum directory depth walked below the cgroup root.
const MAX_DEPTH: usize = 32;

/// One cgroup collection cycle.
#[derive(Debug, Clone, Default)]
pub struct CgroupCycle {
    /// Raw samples, one per readable cgroup node.
    pub samples: Vec<CgroupSample>,
    /// Entities for every sampled node.
    pub entities: Vec<Entity>,
    /// Nodes skipped because their metadata or required files were unreadable.
    pub skipped: u64,
}

/// cgroup v2 sampler.
#[derive(Debug, Clone)]
pub struct CgroupCollector {
    root: SourceRoot,
    max_cgroups: usize,
}

impl CgroupCollector {
    /// Create a collector with a hard bound on nodes per cycle.
    pub fn new(root: SourceRoot, max_cgroups: usize) -> Self {
        Self {
            root,
            max_cgroups: max_cgroups.max(1),
        }
    }

    /// Whether a cgroup v2 hierarchy was detected.
    pub fn available(&self) -> bool {
        self.root.cgroup_root().is_some()
    }

    /// Discover and sample cgroups.
    pub fn sample(&self, stamps: &Stamps) -> Result<CgroupCycle> {
        let root = self.root.cgroup_root().ok_or_else(|| {
            Error::unavailable("cgroup v2", "no cgroup2 mount in /proc/self/mountinfo")
        })?;
        let mut paths = Vec::new();
        collect_directories(root, root, 0, self.max_cgroups, &mut paths)?;
        paths.sort();
        let mut cycle = CgroupCycle::default();
        for path in paths {
            match sample_node(root, &path) {
                Ok(Some((entity, raw))) => {
                    cycle.samples.push(CgroupSample {
                        stamps: stamps.clone(),
                        entity_id: entity.entity_id.clone(),
                        path: raw.path,
                        cpu_usage_usec: raw.cpu.usage_usec,
                        cpu_user_usec: raw.cpu.user_usec,
                        cpu_system_usec: raw.cpu.system_usec,
                        cpu_nr_periods: raw.cpu.nr_periods,
                        cpu_nr_throttled: raw.cpu.nr_throttled,
                        cpu_throttled_usec: raw.cpu.throttled_usec,
                        memory_current: raw.memory_current,
                        memory_peak: raw.memory_peak,
                        memory_max: raw.memory_max,
                        memory_anon: raw.memory_anon,
                        memory_file: raw.memory_file,
                        memory_swap: raw.memory_swap,
                        cpu_quota_usec: raw.cpu_quota_usec,
                        cpu_period_usec: raw.cpu_period_usec,
                        pids_current: raw.pids_current,
                        net_rx_bytes: None,
                        net_tx_bytes: None,
                        net_rx_packets: None,
                        net_tx_packets: None,
                        net_rx_errors: None,
                        net_tx_errors: None,
                        net_rx_dropped: None,
                        net_tx_dropped: None,
                        psi_cpu: raw.psi_cpu,
                        psi_memory: raw.psi_memory,
                        psi_io: raw.psi_io,
                        io: raw.io,
                    });
                    let mut entity = entity;
                    entity.first_seen_wall_ns = stamps.wall;
                    entity.last_seen_wall_ns = stamps.wall;
                    cycle.entities.push(entity);
                }
                Ok(None) | Err(_) => cycle.skipped = cycle.skipped.saturating_add(1),
            }
        }
        Ok(cycle)
    }
}

fn collect_directories(
    root: &Path,
    dir: &Path,
    depth: usize,
    max: usize,
    out: &mut Vec<PathBuf>,
) -> Result<()> {
    if out.len() >= max || depth > MAX_DEPTH {
        return Ok(());
    }
    let entries = std::fs::read_dir(dir).map_err(|err| Error::io(dir, err))?;
    let mut child_dirs = Vec::new();
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            child_dirs.push(entry.path());
        }
    }
    child_dirs.sort();
    for child in child_dirs {
        if out.len() >= max {
            return Ok(());
        }
        out.push(child.clone());
        collect_directories(root, &child, depth + 1, max, out)?;
    }
    if dir == root && out.is_empty() {
        out.push(root.to_path_buf());
    }
    Ok(())
}

#[derive(Debug, Default)]
struct RawCgroup {
    path: String,
    cpu: procfs::CgroupCpuStat,
    memory_current: Option<u64>,
    memory_peak: Option<u64>,
    memory_max: Option<u64>,
    memory_anon: Option<u64>,
    memory_file: Option<u64>,
    memory_swap: Option<u64>,
    cpu_quota_usec: Option<u64>,
    cpu_period_usec: Option<u64>,
    pids_current: Option<u64>,
    psi_cpu: Option<crate::model::PressureLine>,
    psi_memory: Option<crate::model::PressureLine>,
    psi_io: Option<crate::model::PressureLine>,
    io: Vec<crate::model::CgroupIo>,
}

fn sample_node(root: &Path, path: &Path) -> Result<Option<(Entity, RawCgroup)>> {
    let identity = cgroup_identity(path)?;
    let relative = path.strip_prefix(root).unwrap_or(path);
    let display_path = format!("/{}", relative.to_string_lossy().replace('\\', "/"));
    let name = if display_path == "/" {
        "/".to_string()
    } else {
        display_path
            .rsplit('/')
            .find(|part| !part.is_empty())
            .unwrap_or("/")
            .to_string()
    };
    let mut raw = RawCgroup {
        path: display_path.clone(),
        ..RawCgroup::default()
    };
    // A cgroup node without cpu.stat may simply be an empty parent. It is still a
    // real entity, but its counters stay None rather than zero.
    if let Some(text) = procfs::read_optional(&path.join("cpu.stat")) {
        if let Ok(cpu) = procfs::parse_cgroup_cpu_stat(&text) {
            raw.cpu = cpu;
        }
    }
    raw.memory_current = read_optional_u64(&path.join("memory.current"));
    raw.memory_peak = read_optional_u64(&path.join("memory.peak"));
    raw.memory_max = read_optional_u64(&path.join("memory.max"));
    raw.memory_swap = read_optional_u64(&path.join("memory.swap.current"));
    raw.pids_current = read_optional_u64(&path.join("pids.current"));
    if let Some(text) = procfs::read_optional(&path.join("memory.stat")) {
        if let Ok((anon, file)) = procfs::parse_cgroup_memory_stat(&text) {
            raw.memory_anon = anon;
            raw.memory_file = file;
        }
    }
    if let Some(text) = procfs::read_optional(&path.join("cpu.max")) {
        if let Ok((quota, period)) = procfs::parse_cpu_max(&text) {
            raw.cpu_quota_usec = quota;
            raw.cpu_period_usec = period;
        }
    }
    raw.psi_cpu = read_pressure(&path.join("cpu.pressure"));
    raw.psi_memory = read_pressure(&path.join("memory.pressure"));
    raw.psi_io = read_pressure(&path.join("io.pressure"));
    if let Some(text) = procfs::read_optional(&path.join("io.stat")) {
        if let Ok(io) = procfs::parse_cgroup_io_stat(&text) {
            raw.io = io;
        }
    }
    if raw.cpu.usage_usec.is_none()
        && raw.memory_current.is_none()
        && raw.pids_current.is_none()
        && raw.io.is_empty()
    {
        return Ok(None);
    }
    let labels = BTreeMap::from([
        ("path".to_string(), display_path),
        ("device".to_string(), identity.device.to_string()),
        ("inode".to_string(), identity.inode.to_string()),
    ]);
    let entity = Entity {
        entity_id: identity.entity_id(),
        kind: EntityKind::Cgroup,
        stable_key: format!("{}:{}", identity.device, identity.inode),
        name,
        source: "cgroup_v2".to_string(),
        labels,
        first_seen_wall_ns: 0,
        last_seen_wall_ns: 0,
    };
    Ok(Some((entity, raw)))
}

fn read_optional_u64(path: &Path) -> Option<u64> {
    procfs::read_optional(path).and_then(|text| procfs::parse_single_u64_opt(&text))
}

fn read_pressure(path: &Path) -> Option<crate::model::PressureLine> {
    procfs::read_optional(path).and_then(|text| procfs::parse_pressure(&text).ok())
}

#[cfg(unix)]
fn cgroup_identity(path: &Path) -> Result<CgroupIdentity> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path).map_err(|err| Error::io(path, err))?;
    Ok(CgroupIdentity {
        device: meta.dev(),
        inode: meta.ino(),
    })
}

#[cfg(windows)]
fn cgroup_identity(path: &Path) -> Result<CgroupIdentity> {
    use std::os::windows::fs::MetadataExt;
    let meta = std::fs::metadata(path).map_err(|err| Error::io(path, err))?;
    // Stable Rust does not expose FILE_ID_INFO. Fixture runs (the only Windows use)
    // therefore derive identity from the canonical path plus creation time. Real
    // deployment is Linux, where device+inode is used.
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in path.to_string_lossy().as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash ^= meta.creation_time();
    Ok(CgroupIdentity {
        device: 0,
        inode: hash,
    })
}

#[cfg(not(any(unix, windows)))]
fn cgroup_identity(path: &Path) -> Result<CgroupIdentity> {
    let meta = std::fs::metadata(path).map_err(|err| Error::io(path, err))?;
    Ok(CgroupIdentity {
        device: 0,
        inode: meta.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::{ClockDomain, Stamps};

    fn stamps(wall: i64) -> Stamps {
        Stamps::new(wall, wall, "boot-cg", ClockDomain::Simulated)
    }

    fn write(root: &Path, relative: &str, content: &str) {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("dirs");
        std::fs::write(path, content).expect("write");
    }

    fn fixture(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sarf-cgroup-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        write(
            &dir,
            "sys/fs/cgroup/cgroup.controllers",
            "cpu memory io pids\n",
        );
        write(
            &dir,
            "sys/fs/cgroup/system.slice/nginx.service/cpu.stat",
            "usage_usec 5000\nuser_usec 4000\nsystem_usec 1000\n",
        );
        write(
            &dir,
            "sys/fs/cgroup/system.slice/nginx.service/memory.current",
            "1048576\n",
        );
        write(
            &dir,
            "sys/fs/cgroup/system.slice/nginx.service/memory.stat",
            "anon 524288\nfile 524288\n",
        );
        write(
            &dir,
            "sys/fs/cgroup/system.slice/nginx.service/cpu.max",
            "50000 100000\n",
        );
        write(
            &dir,
            "sys/fs/cgroup/system.slice/nginx.service/cpu.pressure",
            "some avg10=1.5 avg60=0.5 avg300=0.1 total=10\n",
        );
        write(
            &dir,
            "sys/fs/cgroup/system.slice/nginx.service/io.stat",
            "8:0 rbytes=10 wbytes=20 rios=1 wios=2\n",
        );
        write(
            &dir,
            "sys/fs/cgroup/docker/abc123/cpu.stat",
            "usage_usec 9000\n",
        );
        write(
            &dir,
            "sys/fs/cgroup/docker/abc123/memory.current",
            "2097152\n",
        );
        dir
    }

    #[test]
    fn discovers_nested_cgroups_read_only() {
        let dir = fixture("nested");
        let collector = CgroupCollector::new(SourceRoot::fixture(&dir), 64);
        assert!(collector.available());
        let cycle = collector.sample(&stamps(100)).expect("sample");
        assert_eq!(cycle.samples.len(), 2, "samples: {:?}", cycle.samples);
        let nginx = cycle
            .samples
            .iter()
            .find(|sample| sample.path.ends_with("nginx.service"))
            .expect("nginx");
        assert_eq!(nginx.cpu_usage_usec, Some(5000));
        assert_eq!(nginx.memory_current, Some(1_048_576));
        assert_eq!(nginx.memory_anon, Some(524_288));
        assert_eq!(nginx.cpu_quota_usec, Some(50_000));
        assert_eq!(nginx.cpu_period_usec, Some(100_000));
        assert_eq!(nginx.io.len(), 1);
        assert_eq!(nginx.psi_cpu.expect("psi").some_avg10, Some(1.5));
        let entity = cycle
            .entities
            .iter()
            .find(|entity| entity.name == "nginx.service")
            .expect("entity");
        assert!(entity.entity_id.starts_with("cgroup:"));
        assert_eq!(entity.first_seen_wall_ns, 100);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn entity_identity_is_stable_and_path_independent() {
        let dir = fixture("identity");
        let collector = CgroupCollector::new(SourceRoot::fixture(&dir), 64);
        let first = collector.sample(&stamps(1)).expect("first");
        let second = collector.sample(&stamps(2)).expect("second");
        let ids = |cycle: &CgroupCycle| {
            let mut ids: Vec<String> = cycle
                .entities
                .iter()
                .map(|entity| entity.entity_id.clone())
                .collect();
            ids.sort();
            ids
        };
        assert_eq!(ids(&first), ids(&second));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bound_and_missing_root_are_reported() {
        let dir = fixture("bound");
        let collector = CgroupCollector::new(SourceRoot::fixture(&dir), 64);
        let cycle = collector.sample(&stamps(1)).expect("sample");
        assert_eq!(cycle.samples.len(), 2);
        let bounded = CgroupCollector::new(SourceRoot::fixture(&dir), 1);
        let cycle = bounded.sample(&stamps(1)).expect("sample");
        assert!(cycle.samples.len() <= 1, "bound must hold");

        let empty = std::env::temp_dir().join(format!("sarf-cgroup-empty-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&empty);
        std::fs::create_dir_all(&empty).expect("dirs");
        let collector = CgroupCollector::new(SourceRoot::fixture(&empty), 4);
        assert!(!collector.available());
        let err = collector.sample(&stamps(1)).expect_err("must fail");
        assert!(matches!(err, Error::Unavailable { .. }));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&empty);
    }

    #[test]
    fn malformed_nodes_are_skipped_not_fatal() {
        let dir = fixture("malformed");
        write(
            &dir,
            "sys/fs/cgroup/broken/cpu.stat",
            "usage_usec not-a-number\n",
        );
        write(&dir, "sys/fs/cgroup/broken/pids.current", "7\n");
        let collector = CgroupCollector::new(SourceRoot::fixture(&dir), 64);
        let cycle = collector.sample(&stamps(1)).expect("sample");
        let broken = cycle
            .samples
            .iter()
            .find(|sample| sample.path.ends_with("broken"))
            .expect("broken node kept with known fields");
        assert_eq!(broken.cpu_usage_usec, None);
        assert_eq!(broken.pids_current, Some(7));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
