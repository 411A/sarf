//! Universal process inventory, identity and selected time-series sampling.
//!
//! A full `/proc` scan establishes visibility for every process. Per-process I/O and
//! detailed status are read only for the selected top-N set, because those files cost
//! more and are permission-sensitive. Identity is `(boot, pid, start_ticks)`; PID reuse
//! therefore creates a new lifetime instead of corrupting history (guide §8.1).
//!
//! The inventory is reconciled every cycle. Exec transitions are detected from a
//! changed `comm`/executable on the same identity and recorded as `process_exec`
//! events; without the kernel process connector, processes that start and exit between
//! two scans are not observable and that limitation is reported by `sarf capabilities`.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

use serde_json::json;

use crate::catalog::Catalog;
use crate::error::Result;
use crate::model::{
    Classification, Entity, EntityKind, EventKind, EventRecord, ProcessIdentity,
    ProcessObservation, ProcessSample, RelationKind, Relationship, SampleFlag, Severity,
};
use crate::time::Stamps;

use super::SourceRoot;

/// Kernel page size assumed for `/proc/PID/stat` RSS.
///
/// Selected processes override this with `VmRSS` from `/proc/PID/status`, which is
/// page-size independent. The stat fallback is approximate on 64 KiB page kernels and
/// is flagged as such in [`ProcessCycle::approximate_memory`].
pub const ASSUMED_PAGE_SIZE: u64 = 4096;

/// Host timing context used to translate `start_ticks` into wall/monotonic time.
#[derive(Debug, Clone, Copy, Default)]
pub struct HostTiming {
    /// `/proc/uptime` seconds.
    pub uptime_secs: Option<f64>,
    /// `/proc/stat` `btime` epoch seconds.
    pub boot_time_secs: Option<u64>,
    /// USER_HZ used to convert start ticks.
    pub clock_ticks: u64,
}

/// A process start (or exec update) discovered this cycle.
#[derive(Debug, Clone, PartialEq)]
pub struct ProcessStart {
    /// Process entity id.
    pub entity_id: String,
    /// Collected observation (classification included).
    pub observation: ProcessObservation,
    /// Parent entity id when the parent was visible in the same scan.
    pub parent_entity_id: Option<String>,
    /// Estimated wall-clock start (btime + start ticks, or first observation).
    pub start_wall_ns: i64,
    /// Estimated monotonic start.
    pub start_mono_ns: i64,
}

/// A process that is no longer visible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessEnd {
    /// Process entity id.
    pub entity_id: String,
    /// End wall clock.
    pub end_wall_ns: i64,
    /// End monotonic clock.
    pub end_mono_ns: i64,
    /// `exited` (complete scan) or `lost` (scan had unreadable entries).
    pub reason: String,
    /// Host PID at exit.
    pub pid: u32,
    /// Command name at exit.
    pub comm: String,
}

/// Everything one process scan produced.
#[derive(Debug, Default)]
pub struct ProcessCycle {
    /// All observations, including processes without a persisted sample.
    pub observations: Vec<ProcessObservation>,
    /// New lifetimes and exec updates to upsert.
    pub starts: Vec<ProcessStart>,
    /// Lifetimes that ended.
    pub ends: Vec<ProcessEnd>,
    /// New entities and entities whose labels changed.
    pub entities: Vec<Entity>,
    /// Parent/child relationships for new processes.
    pub relationships: Vec<Relationship>,
    /// Lifecycle events.
    pub events: Vec<EventRecord>,
    /// Selected raw samples (top-N CPU, memory contributors, new processes).
    pub samples: Vec<ProcessSample>,
    /// Number of process directories inspected.
    pub scanned: usize,
    /// Process directories whose stat could not be read.
    pub unreadable: u64,
    /// Whether any RSS came from the stat page-count fallback.
    pub approximate_memory: bool,
}

/// Concurrent CPU rate for ranking, keyed by entity id.
#[derive(Debug, Clone, Default)]
pub struct CpuRates {
    /// Percent of one core observed since the previous scan.
    pub rates: HashMap<String, f64>,
}

impl CpuRates {
    /// Rate for an entity, or zero when it was just discovered.
    pub fn get(&self, entity_id: &str) -> f64 {
        self.rates.get(entity_id).copied().unwrap_or(0.0)
    }

    /// Highest rate in the cycle.
    pub fn max(&self) -> f64 {
        self.rates.values().copied().fold(0.0, f64::max)
    }
}

#[derive(Debug, Clone)]
struct KnownProcess {
    pid: u32,
    comm: String,
    executable: Option<String>,
    start_wall_ns: i64,
    start_mono_ns: i64,
    last_ticks: u64,
    last_mono_ns: i64,
    last_labels: String,
    misses: u32,
}

/// Process collector.
#[derive(Debug)]
pub struct ProcessCollector {
    root: SourceRoot,
    boot_short: String,
    max_processes: usize,
    store_arguments: bool,
    catalog: Catalog,
    known: HashMap<String, KnownProcess>,
    cgroup_by_path: HashMap<String, String>,
    sessions_by_pid: HashMap<u32, String>,
}

impl ProcessCollector {
    /// Create a collector.
    pub fn new(
        root: SourceRoot,
        boot_short: impl Into<String>,
        max_processes: usize,
        store_arguments: bool,
        catalog: Catalog,
    ) -> Self {
        ProcessCollector {
            root,
            boot_short: boot_short.into(),
            max_processes: max_processes.max(1),
            store_arguments,
            catalog,
            known: HashMap::new(),
            cgroup_by_path: HashMap::new(),
            sessions_by_pid: HashMap::new(),
        }
    }

    /// Replace the cgroup path → entity map from the latest cgroup cycle.
    pub fn set_cgroup_map(&mut self, map: HashMap<String, String>) {
        self.cgroup_by_path = map;
    }

    /// Point the collector at another fixture snapshot while keeping identity state.
    pub fn set_root(&mut self, root: SourceRoot) {
        self.root = root;
    }

    /// Replace the pane PID → session label map from tmux/Zellij enrichment.
    pub fn set_sessions(&mut self, map: HashMap<u32, String>) {
        self.sessions_by_pid = map;
    }

    /// Number of currently tracked process identities.
    pub fn tracked(&self) -> usize {
        self.known.len()
    }

    /// Scan `/proc` and reconcile the inventory.
    pub fn scan(
        &mut self,
        stamps: &Stamps,
        timing: HostTiming,
        top_n: usize,
        sample_all: bool,
    ) -> Result<(ProcessCycle, CpuRates)> {
        let proc_root = self.root.proc_root();
        let mut pids = list_pids(proc_root, self.max_processes)?;
        pids.sort_unstable();
        let mut cycle = ProcessCycle::default();
        let mut rates = CpuRates::default();

        struct Pending {
            observation: ProcessObservation,
            ppid: u32,
            start_ticks: u64,
            rss: Option<u64>,
        }
        let mut pending: Vec<Pending> = Vec::with_capacity(pids.len());
        let mut by_pid: HashMap<u32, String> = HashMap::with_capacity(pids.len());

        for pid in pids {
            cycle.scanned += 1;
            let stat_text = match self.root.read_proc(format!("{pid}/stat")) {
                Ok(text) => text,
                Err(_) => {
                    cycle.unreadable = cycle.unreadable.saturating_add(1);
                    continue;
                }
            };
            let stat = match super::procfs::parse_pid_stat(&stat_text) {
                Ok(stat) => stat,
                Err(_) => {
                    cycle.unreadable = cycle.unreadable.saturating_add(1);
                    continue;
                }
            };
            let executable = std::fs::read_link(proc_root.join(format!("{pid}/exe")))
                .ok()
                .map(|path| path.to_string_lossy().into_owned());
            let cgroup_path = self
                .root
                .read_proc_opt(format!("{pid}/cgroup"))
                .and_then(|text| super::procfs::parse_cgroup_membership(&text));
            let mut classification = self.catalog.classify(
                &stat.comm,
                executable.as_deref(),
                cgroup_path.as_deref(),
                None,
            );
            classification.session = self.sessions_by_pid.get(&pid).cloned();
            let identity = ProcessIdentity::new(self.boot_short.clone(), pid, stat.start_ticks);
            let rss = stat.rss_pages.checked_mul(ASSUMED_PAGE_SIZE);
            if rss.is_some() {
                cycle.approximate_memory = true;
            }
            by_pid.insert(pid, identity.entity_id());
            pending.push(Pending {
                observation: ProcessObservation {
                    identity,
                    comm: stat.comm,
                    state: stat.state,
                    ppid: stat.ppid,
                    executable,
                    argv0: None,
                    cpu_user_ticks: stat.utime,
                    cpu_system_ticks: stat.stime,
                    threads: stat.threads,
                    rss_bytes: rss,
                    virtual_bytes: Some(stat.vsize),
                    io: None,
                    cgroup: cgroup_path.map(|path| crate::model::CgroupRef {
                        path,
                        identity: None,
                    }),
                    classification: Some(classification),
                },
                ppid: stat.ppid,
                start_ticks: stat.start_ticks,
                rss,
            });
        }

        // Resolve parent entities and inherit session labels through the visible tree.
        let ppid_by_pid: HashMap<u32, u32> = pending
            .iter()
            .map(|item| (item.observation.identity.pid, item.ppid))
            .collect();
        for item in &mut pending {
            if let Some(classification) = &mut item.observation.classification {
                if classification.session.is_none() {
                    let mut cursor = item.ppid;
                    for _ in 0..64 {
                        if let Some(session) = self.sessions_by_pid.get(&cursor) {
                            classification.session = Some(session.clone());
                            break;
                        }
                        match ppid_by_pid.get(&cursor) {
                            Some(parent) => cursor = *parent,
                            None => break,
                        }
                    }
                }
            }
        }

        let current: HashSet<String> = pending
            .iter()
            .map(|item| item.observation.identity.entity_id())
            .collect();
        let mut changed_entities: HashSet<String> = HashSet::new();
        let mut new_indices: HashSet<usize> = HashSet::new();

        for (index, item) in pending.iter_mut().enumerate() {
            let entity_id = item.observation.identity.entity_id();
            let parent_entity_id = if item.ppid == 0 {
                None
            } else {
                by_pid.get(&item.ppid).cloned()
            };
            let classification = item.observation.classification.clone().unwrap_or_default();
            let labels = label_fingerprint(&classification);
            let ticks = item
                .observation
                .cpu_user_ticks
                .saturating_add(item.observation.cpu_system_ticks);

            if let Some(known) = self.known.get_mut(&entity_id) {
                let elapsed = stamps.mono.saturating_sub(known.last_mono_ns);
                if elapsed > 0 && ticks >= known.last_ticks {
                    let delta = ticks - known.last_ticks;
                    let pct = delta as f64 * 100.0 * 1_000_000_000.0
                        / (elapsed as f64 * timing.clock_ticks.max(1) as f64);
                    rates.rates.insert(entity_id.clone(), pct);
                }
                let exec_changed = known.comm != item.observation.comm
                    || known.executable != item.observation.executable;
                if exec_changed {
                    cycle.events.push(EventRecord {
                        wall_ns: stamps.wall,
                        mono_ns: Some(stamps.mono),
                        entity_id: Some(entity_id.clone()),
                        kind: EventKind::ProcessExec,
                        severity: Severity::Info,
                        payload: json!({
                            "pid": item.observation.identity.pid,
                            "previous_comm": known.comm,
                            "comm": item.observation.comm,
                        }),
                        provenance: "procfs".to_string(),
                        lost_before: 0,
                    });
                    cycle.starts.push(ProcessStart {
                        entity_id: entity_id.clone(),
                        observation: item.observation.clone(),
                        parent_entity_id: parent_entity_id.clone(),
                        start_wall_ns: known.start_wall_ns,
                        start_mono_ns: known.start_mono_ns,
                    });
                }
                known.comm = item.observation.comm.clone();
                known.executable = item.observation.executable.clone();
                known.last_ticks = ticks;
                known.last_mono_ns = stamps.mono;
                known.misses = 0;
                if known.last_labels != labels {
                    known.last_labels = labels;
                    changed_entities.insert(entity_id.clone());
                }
            } else {
                new_indices.insert(index);
                let (start_wall_ns, start_mono_ns) =
                    estimate_start(stamps, item.start_ticks, timing);
                let start = ProcessStart {
                    entity_id: entity_id.clone(),
                    observation: item.observation.clone(),
                    parent_entity_id: parent_entity_id.clone(),
                    start_wall_ns,
                    start_mono_ns,
                };
                cycle.starts.push(start);
                if let Some(parent) = parent_entity_id {
                    cycle.relationships.push(Relationship {
                        from_entity_id: entity_id.clone(),
                        to_entity_id: parent,
                        relation: RelationKind::SpawnedBy,
                        valid_from_mono_ns: stamps.mono,
                        valid_to_mono_ns: None,
                        provenance: "observed".to_string(),
                        confidence: None,
                    });
                }
                cycle.events.push(EventRecord {
                    wall_ns: stamps.wall,
                    mono_ns: Some(stamps.mono),
                    entity_id: Some(entity_id.clone()),
                    kind: EventKind::ProcessStarted,
                    severity: Severity::Info,
                    payload: json!({
                        "pid": item.observation.identity.pid,
                        "ppid": item.observation.ppid,
                        "comm": item.observation.comm,
                        "start_ticks": item.start_ticks,
                    }),
                    provenance: "procfs".to_string(),
                    lost_before: 0,
                });
                self.known.insert(
                    entity_id.clone(),
                    KnownProcess {
                        pid: item.observation.identity.pid,
                        comm: item.observation.comm.clone(),
                        executable: item.observation.executable.clone(),
                        start_wall_ns,
                        start_mono_ns,
                        last_ticks: ticks,
                        last_mono_ns: stamps.mono,
                        last_labels: labels,
                        misses: 0,
                    },
                );
                changed_entities.insert(entity_id.clone());
            }
            cycle.observations.push(item.observation.clone());
        }

        // Reconcile disappearances. A scan with unreadable entries cannot prove an
        // exit, so identities are only closed after repeated misses.
        let stale: Vec<String> = self
            .known
            .keys()
            .filter(|entity_id| !current.contains(*entity_id))
            .cloned()
            .collect();
        for entity_id in stale {
            let complete_scan = cycle.unreadable == 0;
            let known = self.known.get_mut(&entity_id).expect("known process");
            known.misses = known.misses.saturating_add(1);
            if complete_scan || known.misses >= 3 {
                let known = self.known.remove(&entity_id).expect("known process");
                let reason = if complete_scan { "exited" } else { "lost" };
                cycle.ends.push(ProcessEnd {
                    entity_id: entity_id.clone(),
                    end_wall_ns: stamps.wall,
                    end_mono_ns: stamps.mono,
                    reason: reason.to_string(),
                    pid: known.pid,
                    comm: known.comm.clone(),
                });
                cycle.events.push(EventRecord {
                    wall_ns: stamps.wall,
                    mono_ns: Some(stamps.mono),
                    entity_id: Some(entity_id),
                    kind: EventKind::ProcessExited,
                    severity: Severity::Info,
                    payload: json!({
                        "pid": known.pid,
                        "comm": known.comm,
                        "reason": reason,
                    }),
                    provenance: "procfs".to_string(),
                    lost_before: 0,
                });
            }
        }

        // Entities for new/relabelled processes.
        for entity_id in changed_entities {
            if let Some(item) = pending
                .iter()
                .find(|item| item.observation.identity.entity_id() == entity_id)
            {
                cycle.entities.push(process_entity(
                    &item.observation,
                    &self.boot_short,
                    stamps.wall,
                    item.rss,
                ));
            }
        }

        // Select top-N by CPU plus memory contributors and every new process so the
        // next interval has a baseline.
        // New processes first: they must get a baseline even during a PID storm.
        let mut selected: Vec<usize> = new_indices.iter().copied().take(top_n.max(8)).collect();
        let mut by_cpu: Vec<(usize, f64)> = pending
            .iter()
            .enumerate()
            .map(|(index, item)| (index, rates.get(&item.observation.identity.entity_id())))
            .collect();
        by_cpu.sort_by(|left, right| {
            right
                .1
                .partial_cmp(&left.1)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        selected.extend(
            by_cpu
                .into_iter()
                .take(top_n.max(1))
                .map(|(index, _)| index),
        );
        let mut by_mem: Vec<(usize, u64)> = pending
            .iter()
            .enumerate()
            .filter_map(|(index, item)| item.rss.map(|rss| (index, rss)))
            .collect();
        by_mem.sort_by(|left, right| right.1.cmp(&left.1));
        selected.extend(
            by_mem
                .into_iter()
                .take((top_n / 4).max(3))
                .map(|(index, _)| index),
        );
        selected.sort_unstable();
        selected.dedup();
        if sample_all {
            selected = (0..pending.len()).collect();
        }
        let sample_limit = if sample_all {
            self.max_processes
        } else {
            (top_n.max(1) * 3 + 16).min(self.max_processes)
        };
        selected.truncate(sample_limit);

        for index in selected {
            let item = &mut pending[index];
            let entity_id = item.observation.identity.entity_id();
            let mut flags = 0_u32;
            let status_path = proc_root.join(format!("{}/status", item.observation.identity.pid));
            if let Some(status) = super::procfs::read_optional(&status_path)
                .and_then(|text| super::procfs::parse_pid_status(&text).ok())
            {
                if let Some(rss) = status.vm_rss_bytes {
                    item.observation.rss_bytes = Some(rss);
                    item.rss = Some(rss);
                }
                if let Some(vsize) = status.vm_size_bytes {
                    item.observation.virtual_bytes = Some(vsize);
                }
                if let Some(threads) = status.threads {
                    item.observation.threads = threads;
                }
            } else {
                flags |= SampleFlag::MemoryUnavailable.bit();
            }
            let io_path = proc_root.join(format!("{}/io", item.observation.identity.pid));
            item.observation.io = super::procfs::read_optional(&io_path)
                .and_then(|text| super::procfs::parse_pid_io(&text).ok());
            if item.observation.io.is_none() {
                flags |= SampleFlag::IoUnavailable.bit();
            }
            if item.observation.executable.is_none() {
                flags |= SampleFlag::ExecutableUnavailable.bit();
            }
            if item.observation.cgroup.is_none() {
                flags |= SampleFlag::CgroupUnavailable.bit();
            }
            if item.observation.rss_bytes.is_none() {
                flags |= SampleFlag::MemoryUnavailable.bit();
            }
            if self.store_arguments {
                let cmdline_path =
                    proc_root.join(format!("{}/cmdline", item.observation.identity.pid));
                if let Ok(bytes) = std::fs::read(&cmdline_path) {
                    let first = bytes.split(|byte| *byte == 0).next().unwrap_or(&[]);
                    if !first.is_empty() {
                        let bounded: Vec<u8> = first.iter().copied().take(512).collect();
                        item.observation.argv0 =
                            Some(String::from_utf8_lossy(&bounded).into_owned());
                    }
                }
            }
            let io = item.observation.io;
            cycle.samples.push(ProcessSample {
                stamps: stamps.clone(),
                process_instance_id: entity_id,
                cpu_user_ticks: item.observation.cpu_user_ticks,
                cpu_system_ticks: item.observation.cpu_system_ticks,
                rss_bytes: item.observation.rss_bytes,
                virtual_bytes: item.observation.virtual_bytes,
                read_bytes: io.map(|io| io.read_bytes),
                write_bytes: io.map(|io| io.write_bytes),
                read_chars: io.map(|io| io.rchar),
                write_chars: io.map(|io| io.wchar),
                threads: Some(item.observation.threads),
                state: Some(item.observation.state),
                sample_flags: flags,
            });
        }

        // Replace the observation copies with the enriched values for selected items.
        for item in &pending {
            let entity_id = item.observation.identity.entity_id();
            if let Some(observation) = cycle
                .observations
                .iter_mut()
                .find(|observation| observation.identity.entity_id() == entity_id)
            {
                *observation = item.observation.clone();
            }
        }

        Ok((cycle, rates))
    }
}

fn list_pids(proc_root: &Path, max: usize) -> Result<Vec<u32>> {
    let entries =
        std::fs::read_dir(proc_root).map_err(|err| crate::error::Error::io(proc_root, err))?;
    let mut pids = Vec::new();
    for entry in entries.flatten() {
        if pids.len() >= max {
            break;
        }
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        if let Ok(pid) = name.parse::<u32>() {
            pids.push(pid);
        }
    }
    Ok(pids)
}

fn estimate_start(stamps: &Stamps, start_ticks: u64, timing: HostTiming) -> (i64, i64) {
    let (Some(uptime), Some(boot_time)) = (timing.uptime_secs, timing.boot_time_secs) else {
        return (stamps.wall, stamps.mono);
    };
    if !uptime.is_finite() || uptime < 0.0 {
        return (stamps.wall, stamps.mono);
    }
    let hz = timing.clock_ticks.max(1) as f64;
    let age_secs = uptime - start_ticks as f64 / hz;
    if age_secs < 0.0 || age_secs > uptime + 1.0 {
        return (stamps.wall, stamps.mono);
    }
    let ticks_per_sec = timing.clock_ticks.max(1);
    let ticks_ns = (u128::from(start_ticks) * 1_000_000_000_u128) / u128::from(ticks_per_sec);
    let start_wall_ns = i64::try_from(
        i128::from(boot_time) * 1_000_000_000_i128 + i128::try_from(ticks_ns).unwrap_or(0),
    )
    .unwrap_or(stamps.wall);
    // CLOCK_MONOTONIC is boot-relative, so a boot-relative start is simply
    // start_ticks / USER_HZ. The wall start uses btime plus the same offset.
    let start_mono_ns = i64::try_from(ticks_ns).unwrap_or(stamps.mono);
    let _ = age_secs;
    (start_wall_ns, start_mono_ns)
}

fn label_fingerprint(classification: &Classification) -> String {
    format!(
        "{:?}|{:?}|{:?}|{:?}|{:?}",
        classification.tool,
        classification.role,
        classification.unit,
        classification.container_id,
        classification.session
    )
}

fn process_entity(
    observation: &ProcessObservation,
    boot_short: &str,
    now_wall_ns: i64,
    rss: Option<u64>,
) -> Entity {
    let classification = observation.classification.clone().unwrap_or_default();
    let name = observation.comm.clone();
    let mut labels = BTreeMap::new();
    labels.insert("pid".to_string(), observation.identity.pid.to_string());
    labels.insert(
        "start_ticks".to_string(),
        observation.identity.start_ticks.to_string(),
    );
    if let Some(executable) = &observation.executable {
        labels.insert("executable".to_string(), executable.clone());
    }
    if let Some(tool) = classification.tool {
        labels.insert("tool".to_string(), tool);
    }
    if let Some(role) = classification.role {
        labels.insert("role".to_string(), role);
    }
    if let Some(unit) = classification.unit {
        labels.insert("unit".to_string(), unit);
    }
    if let Some(container) = classification.container_id {
        labels.insert("container_id".to_string(), container);
    }
    if let Some(session) = classification.session {
        labels.insert("session".to_string(), session);
    }
    if let Some(cgroup) = &observation.cgroup {
        labels.insert("cgroup_path".to_string(), cgroup.path.clone());
    }
    if let Some(rss) = rss {
        labels.insert("rss_bytes".to_string(), rss.to_string());
    }
    labels.insert("boot".to_string(), boot_short.to_string());
    Entity {
        entity_id: observation.identity.entity_id(),
        kind: EntityKind::Process,
        stable_key: observation.identity.stable_key(),
        name,
        source: "procfs".to_string(),
        labels,
        first_seen_wall_ns: now_wall_ns,
        last_seen_wall_ns: now_wall_ns,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::{ClockDomain, Stamps};

    fn stamps(wall: i64, mono: i64) -> Stamps {
        Stamps::new(wall, mono, "boot-proc", ClockDomain::Simulated)
    }

    fn write(root: &Path, relative: &str, content: &str) {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("dirs");
        std::fs::write(path, content).expect("write");
    }

    fn pid_stat(pid: u32, comm: &str, ppid: u32, utime: u64, stime: u64, start: u64) -> String {
        format!(
            "{pid} ({comm}) S {ppid} {pid} {pid} 0 -1 4194560 1 2 0 0 {utime} {stime} 0 0 20 0 2 0 {start} 123456 40 1\n"
        )
    }

    fn fixture(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("sarf-proc-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        write(&dir, "proc/100/stat", &pid_stat(100, "init", 0, 10, 5, 100));
        write(&dir, "proc/100/cgroup", "0::/system.slice/init.service\n");
        write(
            &dir,
            "proc/200/stat",
            &pid_stat(200, "worker", 100, 30, 10, 200),
        );
        write(&dir, "proc/200/cgroup", "0::/system.slice/init.service\n");
        write(
            &dir,
            "proc/200/status",
            "VmRSS:\t 2048 kB\nVmSize:\t4096 kB\nThreads:\t3\n",
        );
        write(
            &dir,
            "proc/200/io",
            "rchar: 100\nwchar: 200\nsyscr: 1\nsyscw: 2\nread_bytes: 300\nwrite_bytes: 400\n",
        );
        dir
    }

    fn collector(dir: &Path) -> ProcessCollector {
        let mut collector = ProcessCollector::new(
            SourceRoot::fixture(dir),
            "boot-proc",
            100,
            false,
            Catalog::embedded().expect("catalog"),
        );
        collector.set_cgroup_map(HashMap::from([(
            "/system.slice/init.service".to_string(),
            "cgroup:1:2".to_string(),
        )]));
        collector
    }

    #[test]
    fn first_scan_starts_lifetimes_and_samples() {
        let dir = fixture("first");
        let mut collector = collector(&dir);
        let timing = HostTiming {
            uptime_secs: Some(1000.0),
            boot_time_secs: Some(1_700_000_000),
            clock_ticks: 100,
        };
        let (cycle, rates) = collector
            .scan(&stamps(1_700_000_500_000_000_000, 1), timing, 10, false)
            .expect("scan");
        assert_eq!(cycle.scanned, 2);
        assert_eq!(cycle.starts.len(), 2);
        assert_eq!(cycle.entities.len(), 2);
        assert_eq!(
            cycle.samples.len(),
            2,
            "new processes get a baseline sample"
        );
        assert_eq!(cycle.observations.len(), 2);
        assert_eq!(cycle.unreadable, 0);
        assert_eq!(rates.max(), 0.0);
        let worker = cycle
            .observations
            .iter()
            .find(|observation| observation.identity.pid == 200)
            .expect("worker observation");
        assert_eq!(worker.rss_bytes, Some(2_097_152));
        assert_eq!(worker.io.expect("io").write_bytes, 400);
        let worker_start = cycle
            .starts
            .iter()
            .find(|start| start.observation.identity.pid == 200)
            .expect("worker start");
        assert_eq!(
            worker_start.parent_entity_id.as_deref(),
            Some("proc:boot-proc:100:100")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn second_scan_computes_cpu_rate_and_detects_exit() {
        let dir = fixture("second");
        let mut collector = collector(&dir);
        let timing = HostTiming {
            uptime_secs: Some(1000.0),
            boot_time_secs: Some(1_700_000_000),
            clock_ticks: 100,
        };
        collector
            .scan(&stamps(1, 1_000_000_000), timing, 10, false)
            .expect("first");
        // Worker used 10 more ticks over one second => 10% of one core.
        write(
            &dir,
            "proc/200/stat",
            &pid_stat(200, "worker", 100, 40, 10, 200),
        );
        let (cycle, rates) = collector
            .scan(&stamps(2, 2_000_000_000), timing, 10, false)
            .expect("second");
        assert!((rates.get("proc:boot-proc:200:200") - 10.0).abs() < 0.001);
        assert_eq!(cycle.starts.len(), 0);
        std::fs::remove_dir_all(dir.join("proc/200")).expect("remove process");
        let (cycle, _) = collector
            .scan(&stamps(3, 3_000_000_000), timing, 10, false)
            .expect("third");
        assert_eq!(cycle.ends.len(), 1);
        assert_eq!(cycle.ends[0].pid, 200);
        assert_eq!(cycle.ends[0].reason, "exited");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pid_reuse_with_new_start_ticks_is_a_new_lifetime() {
        let dir = fixture("reuse");
        let mut collector = collector(&dir);
        let timing = HostTiming::default();
        collector
            .scan(&stamps(1, 1_000_000_000), timing, 10, false)
            .expect("first");
        write(
            &dir,
            "proc/200/stat",
            &pid_stat(200, "newworker", 100, 1, 1, 999),
        );
        let (cycle, _) = collector
            .scan(&stamps(2, 2_000_000_000), timing, 10, false)
            .expect("second");
        assert_eq!(cycle.starts.len(), 1, "new start_ticks is a new identity");
        assert_eq!(cycle.ends.len(), 1, "old identity exited");
        assert_eq!(cycle.starts[0].observation.comm, "newworker");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn exec_change_emits_event_without_new_lifetime_identity() {
        let dir = fixture("exec");
        let mut collector = collector(&dir);
        let timing = HostTiming::default();
        collector
            .scan(&stamps(1, 1_000_000_000), timing, 10, false)
            .expect("first");
        write(
            &dir,
            "proc/200/stat",
            &pid_stat(200, "bash", 100, 31, 11, 200),
        );
        let (cycle, _) = collector
            .scan(&stamps(2, 2_000_000_000), timing, 10, false)
            .expect("second");
        assert_eq!(cycle.starts.len(), 1);
        assert_eq!(cycle.starts[0].observation.comm, "bash");
        assert_eq!(cycle.ends.len(), 0);
        assert!(cycle
            .events
            .iter()
            .any(|event| event.kind == EventKind::ProcessExec));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sessions_are_inherited_from_a_pane_pid() {
        let dir = fixture("session");
        let mut collector = collector(&dir);
        collector.set_sessions(HashMap::from([(100, "tmux main:%1".to_string())]));
        let (cycle, _) = collector
            .scan(&stamps(1, 1_000_000_000), HostTiming::default(), 10, false)
            .expect("scan");
        let worker = cycle
            .observations
            .iter()
            .find(|observation| observation.identity.pid == 200)
            .expect("worker");
        assert_eq!(
            worker
                .classification
                .as_ref()
                .and_then(|classification| classification.session.as_deref()),
            Some("tmux main:%1")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn estimate_start_uses_btime_and_start_ticks() {
        let (wall, mono) = estimate_start(
            &stamps(1_700_000_100_000_000_000, 10_000_000_000),
            100,
            HostTiming {
                uptime_secs: Some(100.0),
                boot_time_secs: Some(1_700_000_000),
                clock_ticks: 100,
            },
        );
        assert_eq!(wall, 1_700_000_001_000_000_000);
        assert_eq!(mono, 1_000_000_000);
    }
}
