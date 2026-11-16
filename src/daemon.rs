//! Synchronous collection daemon (guide §7, §11.1, §12.1).
//!
//! Two threads only: this sampling loop and one SQLite writer. Host counters are read
//! every tick; cgroup and process scans follow their configured ratios; discovery of
//! Docker/sessions runs on the slower cadence. Everything submitted to the writer is
//! bounded, and a finite `--cycles` run is deterministic under a simulated clock so
//! end-to-end tests never sleep.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::json;

use crate::analysis::ewma::Ewma;
use crate::analysis::incidents::{IncidentEngine, Signal};
use crate::catalog::{self, Catalog};
use crate::collect::cgroup::{CgroupCollector, CgroupCycle};
use crate::collect::host::HostCollector;
use crate::collect::logs::{LogManager, LogPolicy, LogPulse};
use crate::collect::process::ProcessCollector;
use crate::collect::process::ProcessCycle;
use crate::collect::{HealthRegistry, HostFacts, SourceRoot};
use crate::config::{Config, Toggle};
use crate::enrich::docker::{self, ContainerInfo};
use crate::enrich::sessions::{self, SessionDiscovery};
use crate::error::{Error, Result};
use crate::model::{
    Availability, ConfiguredState, CoverageGap, Entity, EntityKind, HostSample, Metric, Severity,
    WritePriority,
};
use crate::paths::DataDir;
use crate::store::retention::RetentionPolicy;
use crate::store::writer::{SubmitOutcome, Writer, WriterStats};
use crate::store::{
    HostInfo, IntegrationStateRow, LogSourceRow, ProcessLifetimeRow, Store, WriteItem, WriteRecord,
};
use crate::time::{Clock, FakeClock, Stamps, SystemClock, WallNs};
use crate::VERSION;

/// Options for one daemon run.
#[derive(Debug, Clone)]
pub struct DaemonOptions {
    /// Centralized data directory.
    pub data_dir: DataDir,
    /// Validated configuration.
    pub config: Config,
    /// Number of sampling cycles; `None` or `0` means run until terminated.
    pub cycles: Option<u64>,
    /// Fixture tree; implies simulated time and no sleeping.
    pub fixture_root: Option<PathBuf>,
    /// Mark the run simulated even without a fixture root.
    pub simulate: bool,
    /// Override the normal sampling cadence.
    pub interval_override: Option<u64>,
}

/// Summary returned when a bounded run finishes.
#[derive(Debug, Clone, Default)]
pub struct RunReport {
    /// Run id.
    pub run_id: i64,
    /// Cycles completed.
    pub cycles: u64,
    /// Host samples written.
    pub host_samples: u64,
    /// cgroup samples written.
    pub cgroup_samples: u64,
    /// Process lifecycles observed.
    pub processes_started: u64,
    /// Process samples written.
    pub process_samples: u64,
    /// Log records persisted.
    pub logs: u64,
    /// Incidents opened.
    pub incidents: u64,
    /// Writer counters at shutdown.
    pub writer: WriterStats,
    /// Wall-clock duration.
    pub elapsed: Duration,
    /// Whether the run used fixture/simulated time.
    pub simulated: bool,
}

struct Enrichment {
    containers: HashMap<String, ContainerInfo>,
    container_names: HashMap<String, String>,
    sessions: SessionDiscovery,
    zellij: SessionDiscovery,
    docker: docker::DockerDiscovery,
    last_cycle: u64,
}

impl Default for Enrichment {
    fn default() -> Self {
        Self {
            containers: HashMap::new(),
            container_names: HashMap::new(),
            sessions: SessionDiscovery::default(),
            zellij: SessionDiscovery::default(),
            docker: docker::DockerDiscovery::default(),
            last_cycle: u64::MAX,
        }
    }
}

struct AnalysisState {
    ewas: HashMap<(String, Metric), Ewma>,
    previous_host: Option<HostSample>,
    previous_cgroups: HashMap<String, (i64, u64)>,
}

impl AnalysisState {
    fn new() -> Self {
        Self {
            ewas: HashMap::new(),
            previous_host: None,
            previous_cgroups: HashMap::new(),
        }
    }

    fn signal(
        &mut self,
        entity: Option<String>,
        metric: Metric,
        value: f64,
        threshold: f64,
        wall_ns: WallNs,
        reason: &str,
    ) -> Option<Signal> {
        if !value.is_finite() || threshold <= 0.0 {
            return None;
        }
        let key = (entity.clone().unwrap_or_else(|| "host".to_string()), metric);
        let ewma = self.ewas.entry(key).or_insert_with(|| Ewma::new(0.2));
        let baseline = if ewma.samples() == 0 {
            0.0
        } else {
            ewma.mean()
        };
        ewma.update(value);
        Some(Signal {
            entity_id: entity,
            metric,
            value,
            baseline,
            threshold,
            wall_ns,
            reason: reason.to_string(),
        })
    }

    fn observe_host(
        &mut self,
        host: &HostSample,
        cpu_count: usize,
        thresholds: &crate::config::Thresholds,
        now: WallNs,
    ) -> Vec<Signal> {
        let mut signals = Vec::new();
        if let Some(previous) = &self.previous_host {
            if previous.stamps.boot_id == host.stamps.boot_id {
                if let Some(pct) = host_cpu_pct(previous, host, cpu_count) {
                    if let Some(signal) = self.signal(
                        None,
                        Metric::Cpu,
                        pct,
                        thresholds.host_cpu_pct,
                        now,
                        "host CPU above the configured threshold",
                    ) {
                        signals.push(signal);
                    }
                }
            }
        }
        if let Some(pct) = host.mem.used_pct() {
            if let Some(signal) = self.signal(
                None,
                Metric::Memory,
                pct,
                thresholds.memory_pct,
                now,
                "host memory above the configured threshold",
            ) {
                signals.push(signal);
            }
        }
        for (metric, pressure) in [
            (Metric::PsiCpu, host.pressure.cpu),
            (Metric::PsiMemory, host.pressure.memory),
            (Metric::PsiIo, host.pressure.io),
        ] {
            if let Some(some_avg10) = pressure.and_then(|line| line.some_avg10) {
                if let Some(signal) = self.signal(
                    None,
                    metric,
                    some_avg10,
                    thresholds.psi_some_pct,
                    now,
                    "host pressure above the configured threshold",
                ) {
                    signals.push(signal);
                }
            }
        }
        self.previous_host = Some(host.clone());
        signals
    }

    fn observe_cgroups(
        &mut self,
        cgroups: &[crate::model::CgroupSample],
        thresholds: &crate::config::Thresholds,
        now: WallNs,
    ) -> Vec<Signal> {
        let mut signals = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        for sample in cgroups {
            seen.insert(sample.entity_id.clone());
            if let Some(usage) = sample.cpu_usage_usec {
                if let Some((previous_wall, previous_usage)) =
                    self.previous_cgroups.get(&sample.entity_id).copied()
                {
                    let elapsed = sample.stamps.mono.saturating_sub(previous_wall);
                    if elapsed > 0 && usage >= previous_usage {
                        let delta = usage - previous_usage;
                        let pct = delta as f64 * 100.0 / (elapsed as f64 / 1_000_000.0);
                        if let Some(signal) = self.signal(
                            Some(sample.entity_id.clone()),
                            Metric::Cpu,
                            pct,
                            thresholds.service_cpu_pct,
                            now,
                            "service/container CPU above the configured threshold",
                        ) {
                            signals.push(signal);
                        }
                    }
                }
                self.previous_cgroups
                    .insert(sample.entity_id.clone(), (sample.stamps.mono, usage));
            }
            if let (Some(current), Some(max)) = (sample.memory_current, sample.memory_max) {
                if max > 0 {
                    let pct = current as f64 * 100.0 / max as f64;
                    if let Some(signal) = self.signal(
                        Some(sample.entity_id.clone()),
                        Metric::Memory,
                        pct,
                        thresholds.memory_pct,
                        now,
                        "service/container memory above the configured threshold",
                    ) {
                        signals.push(signal);
                    }
                }
            }
        }
        self.previous_cgroups
            .retain(|entity, _| seen.contains(entity));
        signals
    }
}

fn host_cpu_pct(previous: &HostSample, current: &HostSample, cpu_count: usize) -> Option<f64> {
    let delta = current.cpu.delta(previous.cpu)?;
    let total = delta.total();
    if total == 0 {
        return None;
    }
    let busy = delta.user + delta.nice + delta.system + delta.irq + delta.softirq + delta.steal;
    Some(busy as f64 * 100.0 * cpu_count.max(1) as f64 / total as f64)
}

/// Run the daemon.
///
/// `options` is owned by the daemon for the whole run: it is built once by the
/// caller from the CLI and never shared, so taking it by value avoids borrowing a
/// temporary configuration tree.
#[allow(
    clippy::needless_pass_by_value,
    reason = "DaemonOptions is the entry point's owned configuration; callers build it \
              per run and the daemon keeps it for the process lifetime"
)]
pub fn run(options: DaemonOptions) -> Result<RunReport> {
    let started = Instant::now();
    options.data_dir.init(false)?;
    let simulated = options.simulate || options.fixture_root.is_some();
    let interval_secs = options
        .interval_override
        .unwrap_or(options.config.general.interval_secs)
        .max(1);
    let cycle_limit = options.cycles.filter(|cycles| *cycles > 0);

    let base_root = match &options.fixture_root {
        Some(root) => {
            if !root.join("proc").is_dir() && !root.join("cycle-0000").is_dir() {
                return Err(Error::Config(format!(
                    "fixture root {} has no proc/ or cycle-0000/",
                    root.display()
                )));
            }
            SourceRoot::fixture(root)
        }
        None => SourceRoot::real(),
    };
    let fact_root = if base_root.has_procfs() {
        base_root.clone()
    } else {
        cycle_root(&base_root, 0)
    };
    if !fact_root.has_procfs() {
        return Err(Error::unavailable(
            "/proc",
            "no procfs at this path; Linux is required (use --fixture-root for replay)",
        ));
    }
    let facts = HostFacts::read(&fact_root);
    let host_id = format!("host:{}", facts.short_boot_id());

    let clock: Arc<dyn Clock> = if simulated {
        let cycles = cycle_limit.unwrap_or(60);
        let span = (cycles
            .saturating_mul(interval_secs)
            .saturating_mul(1_000_000_000)) as i64;
        let now = SystemClock::new().wall_ns();
        let start = now.saturating_sub(span);
        Arc::new(FakeClock::new(start, 1_000_000_000))
    } else {
        Arc::new(SystemClock::new())
    };

    let mut store = Store::open(&options.data_dir.db_path())?;
    store.migrate()?;
    init_meta(&mut store, &facts, &fact_root)?;
    let first_wall = clock.wall_ns();
    let host_entity = Entity {
        entity_id: host_id.clone(),
        kind: EntityKind::Host,
        stable_key: facts.boot_id.clone(),
        name: facts.hostname.clone(),
        source: "procfs".to_string(),
        labels: BTreeMap::from([
            ("kernel".to_string(), facts.kernel_release.clone()),
            ("architecture".to_string(), facts.architecture.clone()),
        ]),
        first_seen_wall_ns: first_wall,
        last_seen_wall_ns: first_wall,
    };
    let mut initial: Vec<WriteItem> = vec![
        WriteItem::normal(WriteRecord::Host(HostInfo {
            host_id: host_id.clone(),
            boot_id: facts.boot_id.clone(),
            hostname: facts.hostname.clone(),
            kernel_release: facts.kernel_release.clone(),
            architecture: facts.architecture.clone(),
            first_seen_wall_ns: first_wall,
        })),
        WriteItem::normal(WriteRecord::Entity(host_entity)),
    ];
    let log_policy = LogPolicy::from_config(&options.config);
    let mut logs = LogManager::new(&options.config, log_policy);
    for (id, kind, target, hint, max_lines, max_bytes) in logs.descriptors() {
        initial.push(WriteItem::normal(WriteRecord::LogSource(LogSourceRow {
            source_id: id,
            kind,
            target,
            entity_hint: hint,
            max_lines: Some(max_lines),
            max_bytes: Some(max_bytes),
        })));
    }
    store.write(&initial)?;
    let run_id = store.begin_run(
        &host_id,
        first_wall,
        VERSION,
        simulated,
        Some(if simulated {
            "simulated/fixture replay"
        } else {
            "live collection"
        }),
    )?;
    let first_incident = store.max_incident_id()?.saturating_add(1);
    let mut engine = IncidentEngine::new(&options.config, first_incident);
    let mut health = HealthRegistry::new();
    for (id, _, _, _, _, _) in logs.descriptors() {
        health.register(&format!("logs:{id}"), ConfiguredState::Auto);
    }
    let mut analysis = AnalysisState::new();
    let catalog = Catalog::embedded()?;
    let mut process_collector = ProcessCollector::new(
        base_root.clone(),
        facts.short_boot_id().to_string(),
        options.config.process.max_processes,
        options.config.process.store_arguments,
        catalog.clone(),
    );
    let mut enrichment = Enrichment::default();
    let writer = Writer::spawn(store, 4096)?;

    probe_coverage(&fact_root, &mut health, &writer, first_wall);

    let mut report = RunReport {
        run_id,
        simulated,
        ..RunReport::default()
    };
    let mut last_cgroup_mono: i64 = i64::MIN / 2;
    let mut last_process_mono: i64 = i64::MIN / 2;
    let mut last_discovery_mono: i64 = i64::MIN / 2;
    let mut last_prune_mono: i64 = i64::MIN / 2;
    let mut cgroup_map: HashMap<String, String> = HashMap::new();
    let mut observed_tools: HashSet<String> = HashSet::new();
    let mut cycle: u64 = 0;
    loop {
        let root = cycle_root(&base_root, cycle);
        process_collector.set_root(root.clone());
        let stamps = Stamps::capture(clock.as_ref(), facts.short_boot_id());
        let mut batch: Vec<WriteItem> = Vec::new();

        let host_collector = HostCollector::new(root.clone());
        let host = host_collector.sample(stamps.clone())?;
        let cpu_count = host.per_cpu.len().max(1);
        batch.push(WriteItem::normal(WriteRecord::HostSample(host.clone())));
        report.host_samples = report.host_samples.saturating_add(1);
        health.success("procfs", stamps.wall);
        health.received("procfs", 1);
        health.persisted("procfs", 1);
        if cycle == 0 {
            batch.push(WriteItem::normal(WriteRecord::Meta {
                key: "cpu_count".into(),
                value: cpu_count.to_string(),
            }));
        }

        let sample_discovery = due(
            &mut last_discovery_mono,
            stamps.mono,
            options.config.general.discovery_secs,
        );
        let sample_cgroup = options.config.cgroup.enabled
            && due(
                &mut last_cgroup_mono,
                stamps.mono,
                options.config.cgroup.sample_secs,
            );
        let sample_process = options.config.process.enabled
            && due(
                &mut last_process_mono,
                stamps.mono,
                options.config.general.process_interval_secs,
            );
        let run_prune = due(
            &mut last_prune_mono,
            stamps.mono,
            options.config.general.prune_interval_secs,
        );
        if sample_discovery {
            enrichment.last_cycle = cycle;
            enrich(
                &mut enrichment,
                &options.config,
                &catalog,
                &observed_tools,
                &stamps,
                &mut batch,
                &mut health,
            );
            apply_session_map(&mut process_collector, &enrichment);
        }

        let cgroup_cycle = if sample_cgroup {
            match CgroupCollector::new(root.clone(), options.config.cgroup.max_cgroups)
                .sample(&stamps)
            {
                Ok(mut cgroups) => {
                    apply_docker_labels(&mut cgroups, &enrichment.containers);
                    cgroup_map.clear();
                    for entity in &cgroups.entities {
                        cgroup_map.insert(
                            entity
                                .labels
                                .get("path")
                                .cloned()
                                .unwrap_or_else(|| format!("/{}", entity.name)),
                            entity.entity_id.clone(),
                        );
                    }
                    process_collector.set_cgroup_map(cgroup_map.clone());
                    for entity in &cgroups.entities {
                        batch.push(WriteItem::normal(WriteRecord::Entity(entity.clone())));
                    }
                    for sample in &cgroups.samples {
                        batch.push(WriteItem::normal(WriteRecord::CgroupSample(sample.clone())));
                    }
                    report.cgroup_samples = report
                        .cgroup_samples
                        .saturating_add(cgroups.samples.len() as u64);
                    health.success("cgroup_v2", stamps.wall);
                    health.received("cgroup_v2", cgroups.samples.len() as u64);
                    health.persisted("cgroup_v2", cgroups.samples.len() as u64);
                    if cgroups.skipped > 0 {
                        health.dropped("cgroup_v2", cgroups.skipped);
                    }
                    Some(cgroups)
                }
                Err(err) => {
                    health.error("cgroup_v2", stamps.wall, &err.to_string());
                    None
                }
            }
        } else {
            None
        };

        if sample_process {
            let timing = crate::collect::process::HostTiming {
                uptime_secs: host.uptime_secs,
                boot_time_secs: host.boot_time_secs,
                clock_ticks: facts.clock_ticks,
            };
            match process_collector.scan(
                &stamps,
                timing,
                options.config.process.top_n_persistence,
                options.config.process.sample_all_processes,
            ) {
                Ok((process_cycle, _rates)) => {
                    for observation in &process_cycle.observations {
                        if let Some(tool) = observation
                            .classification
                            .as_ref()
                            .and_then(|classification| classification.tool.as_ref())
                        {
                            observed_tools.insert(tool.clone());
                        }
                    }
                    enqueue_process_cycle(
                        &mut batch,
                        process_cycle,
                        &host_id,
                        &enrichment,
                        &catalog,
                        &cgroup_map,
                    );
                    report.processes_started = report
                        .processes_started
                        .saturating_add(batch_process_starts(&batch));
                    report.process_samples = report
                        .process_samples
                        .saturating_add(process_sample_count(&batch));
                    health.success("process_inventory", stamps.wall);
                }
                Err(err) => health.error("process_inventory", stamps.wall, &err.to_string()),
            }
        }

        let log_pulse = logs.poll(&stamps);
        enqueue_logs(
            &mut batch,
            &log_pulse,
            &logs,
            &stamps,
            &mut health,
            &mut report,
        );

        // Incidents from host and cgroup observations.
        let mut signals =
            analysis.observe_host(&host, cpu_count, &options.config.thresholds, stamps.wall);
        if let Some(cgroups) = &cgroup_cycle {
            signals.extend(analysis.observe_cgroups(
                &cgroups.samples,
                &options.config.thresholds,
                stamps.wall,
            ));
        }
        for signal in signals {
            engine.observe(signal);
        }
        let pulse = engine.tick(stamps.wall);
        enqueue_incidents(&mut batch, pulse, &logs, &stamps, &mut report);

        if run_prune && cycle > 0 {
            prune(&options, &writer, stamps.wall, &mut health);
        }
        if sample_discovery {
            batch.extend(health.write_items());
        }

        match writer.submit(batch) {
            SubmitOutcome::Accepted => {}
            SubmitOutcome::PartiallyDropped { low, normal } => {
                health.dropped("writer", low + normal);
            }
            SubmitOutcome::WriterGone => {
                return Err(Error::Storage("writer thread stopped".to_string()));
            }
        }
        writer.flush()?;
        cycle = cycle.saturating_add(1);
        report.cycles = cycle;
        if cycle_limit.is_some_and(|limit| cycle >= limit) {
            break;
        }
        let interval = if options.config.adaptive.enabled && engine.open_count() > 0 {
            Duration::from_millis(options.config.adaptive.incident_interval_ms.max(50))
        } else {
            Duration::from_secs(interval_secs)
        };
        clock.sleep(interval);
    }

    // Final rollups/retention so a bounded run produces reportable aggregates.
    prune(&options, &writer, clock.wall_ns(), &mut health);
    health.success("writer", clock.wall_ns());
    writer.submit(health.write_items());
    writer.flush()?;
    let writer_stats = writer.stats();
    writer.shutdown()?;
    report.writer = writer_stats;

    // Close the run row with a short-lived writer reopened on the database.
    let mut store = Store::open(&options.data_dir.db_path())?;
    store.end_run(run_id, clock.wall_ns())?;
    store.checkpoint()?;
    report.elapsed = started.elapsed();
    Ok(report)
}

fn due(last: &mut i64, now: i64, interval_secs: u64) -> bool {
    let interval = (interval_secs.max(1) as i64).saturating_mul(1_000_000_000);
    if now.saturating_sub(*last) >= interval {
        *last = now;
        true
    } else {
        false
    }
}

fn cycle_root(base: &SourceRoot, cycle: u64) -> SourceRoot {
    let root = base
        .proc_root()
        .parent()
        .unwrap_or_else(|| base.proc_root());
    let candidate = root.join(format!("cycle-{cycle:04}"));
    if candidate.join("proc").is_dir() {
        SourceRoot::fixture(candidate)
    } else {
        base.clone()
    }
}

fn init_meta(store: &mut Store, facts: &HostFacts, root: &SourceRoot) -> Result<()> {
    let capability_json = json!({
        "procfs": root.has_procfs(),
        "kernel": facts.kernel_release,
        "architecture": facts.architecture,
    });
    store.write(&[
        WriteItem::normal(WriteRecord::Meta {
            key: "clock_ticks_per_second".into(),
            value: facts.clock_ticks.to_string(),
        }),
        WriteItem::normal(WriteRecord::Meta {
            key: "boot_id".into(),
            value: facts.boot_id.clone(),
        }),
        WriteItem::normal(WriteRecord::Meta {
            key: "hostname".into(),
            value: facts.hostname.clone(),
        }),
        WriteItem::normal(WriteRecord::Meta {
            key: "host_capabilities".into(),
            value: capability_json.to_string(),
        }),
    ])?;
    Ok(())
}

fn probe_coverage(root: &SourceRoot, health: &mut HealthRegistry, writer: &Writer, now: WallNs) {
    health.success("procfs", now);
    let capabilities = crate::collect::host::HostCapabilities::detect(root);
    for missing in capabilities.missing() {
        writer.submit(vec![WriteItem::normal(WriteRecord::Gap(CoverageGap {
            source_id: "procfs".to_string(),
            kind: "absent_interface".to_string(),
            since_wall_ns: Some(now),
            detail: format!("/proc/{missing} is not present; that metric stays unavailable"),
        }))]);
    }
    if root.cgroup_root().is_none() {
        health.unavailable("cgroup_v2", "no cgroup2 mount detected");
        writer.submit(vec![WriteItem::normal(WriteRecord::Gap(CoverageGap {
            source_id: "cgroup_v2".to_string(),
            kind: "absent_interface".to_string(),
            since_wall_ns: Some(now),
            detail: "no cgroup2 mount; service/container accounting needs /sys/fs/cgroup"
                .to_string(),
        }))]);
    }
    for (id, detail) in [
        (
            "process_events",
            "kernel process connector/taskstats collectors are not implemented in v0.1; processes that start and exit between scans may be missed",
        ),
        (
            "process_samples",
            "only top-N processes keep raw time series; per-process historical rollups are not implemented in v0.1",
        ),
    ] {
        health.unavailable(id, detail);
        writer.submit(vec![WriteItem::normal(WriteRecord::Gap(CoverageGap {
            source_id: id.to_string(),
            kind: "unsupported".to_string(),
            since_wall_ns: Some(now),
            detail: detail.to_string(),
        }))]);
    }
}

fn apply_docker_labels(cycle: &mut CgroupCycle, containers: &HashMap<String, ContainerInfo>) {
    for entity in &mut cycle.entities {
        let path = entity
            .labels
            .get("path")
            .cloned()
            .unwrap_or_else(|| format!("/{}", entity.name));
        if let Some(id) = catalog::container_from_cgroup(&path) {
            if let Some(container) = containers.get(&id) {
                entity.name.clone_from(&container.name);
                entity
                    .labels
                    .insert("container_id".to_string(), container.short_id.clone());
                entity
                    .labels
                    .insert("container_image".to_string(), container.image.clone());
                entity
                    .labels
                    .insert("container_state".to_string(), container.state.clone());
            }
        }
    }
    for sample in &mut cycle.samples {
        if let Some(entity) = cycle
            .entities
            .iter()
            .find(|entity| entity.entity_id == sample.entity_id)
        {
            sample.path = entity
                .labels
                .get("path")
                .cloned()
                .unwrap_or_else(|| sample.path.clone());
        }
    }
}
fn enqueue_process_cycle(
    batch: &mut Vec<WriteItem>,
    cycle: ProcessCycle,
    host_id: &str,
    enrichment: &Enrichment,
    catalog: &Catalog,
    cgroup_map: &HashMap<String, String>,
) {
    for entity in cycle.entities {
        batch.push(WriteItem::normal(WriteRecord::Entity(entity)));
    }
    for start in cycle.starts {
        let observation = &start.observation;
        let classification = observation.classification.clone().unwrap_or_default();
        let cgroup_entity = observation
            .cgroup
            .as_ref()
            .and_then(|cgroup| cgroup_map.get(&cgroup.path).cloned());
        let container = classification
            .container_id
            .as_ref()
            .and_then(|id| enrichment.container_names.get(id).cloned())
            .or_else(|| classification.container_id.clone());
        let tool = classification.tool.clone().or_else(|| {
            observation
                .executable
                .as_deref()
                .and_then(|path| {
                    Path::new(path)
                        .file_name()
                        .map(|name| name.to_string_lossy().into_owned())
                })
                .filter(|name| catalog.get(name).is_some())
        });
        batch.push(WriteItem::normal(WriteRecord::ProcessLifetime(
            ProcessLifetimeRow {
                process_instance_id: start.entity_id,
                host_id: host_id.to_string(),
                host_pid: observation.identity.pid,
                start_ticks: observation.identity.start_ticks,
                parent_process_instance_id: start.parent_entity_id,
                parent_host_pid: (observation.ppid != 0).then_some(observation.ppid),
                executable: observation.executable.clone(),
                comm: observation.comm.clone(),
                tool,
                role: classification.role,
                unit: classification.unit,
                container,
                session: classification.session,
                cgroup_entity_id: cgroup_entity,
                start_wall_ns: start.start_wall_ns,
                start_mono_ns: start.start_mono_ns,
            },
        )));
    }
    for end in cycle.ends {
        batch.push(WriteItem::normal(WriteRecord::ProcessLifetimeEnd {
            process_instance_id: end.entity_id,
            end_wall_ns: end.end_wall_ns,
            end_mono_ns: end.end_mono_ns,
            reason: end.reason,
        }));
    }
    for relationship in cycle.relationships {
        batch.push(WriteItem::normal(WriteRecord::Relationship(relationship)));
    }
    for event in cycle.events {
        batch.push(WriteItem::normal(WriteRecord::Event(event)));
    }
    for sample in cycle.samples {
        batch.push(WriteItem::normal(WriteRecord::ProcessSample(sample)));
    }
}

fn enqueue_logs(
    batch: &mut Vec<WriteItem>,
    pulse: &LogPulse,
    manager: &LogManager,
    stamps: &Stamps,
    health: &mut HealthRegistry,
    report: &mut RunReport,
) {
    for source in manager.health() {
        let id = format!("logs:{}", source.source_id);
        health.register(&id, ConfiguredState::Auto);
        if let Some(entry) = health.entry(&id) {
            entry.availability = source.availability;
            entry.last_error.clone_from(&source.last_error);
            entry.received_count = source.received;
            entry.dropped_count = source.dropped;
            entry.truncated_count = source.truncated;
            entry.persisted_count = source.ring_lines as u64;
            if source.availability == Availability::Available {
                entry.last_success_wall_ns = Some(stamps.wall);
            }
        }
    }
    for (source, error) in &pulse.errors {
        let id = format!("logs:{source}");
        health.register(&id, ConfiguredState::Auto);
        health.error(&id, stamps.wall, error);
    }
    for record in &pulse.records {
        let priority = match record.level {
            Some(Severity::Critical | Severity::Error) => WritePriority::Critical,
            Some(Severity::Warn) => WritePriority::Normal,
            _ => WritePriority::Low,
        };
        let item = match priority {
            WritePriority::Critical => WriteItem::critical(WriteRecord::Log(record.clone())),
            WritePriority::Normal => WriteItem::normal(WriteRecord::Log(record.clone())),
            WritePriority::Low => WriteItem::low(WriteRecord::Log(record.clone())),
        };
        batch.push(item);
        report.logs = report.logs.saturating_add(1);
    }
    health.dropped("logs_file", pulse.dropped);
    health.truncated("logs_file", pulse.truncated);
    health.received("logs_file", pulse.received);
    health.persisted("logs_file", pulse.records.len() as u64);
}

fn enqueue_incidents(
    batch: &mut Vec<WriteItem>,
    pulse: crate::analysis::incidents::IncidentPulse,
    logs: &LogManager,
    stamps: &Stamps,
    report: &mut RunReport,
) {
    for mut incident in pulse.opened {
        let id = incident.incident_id.unwrap_or(0);
        let evidence_logs = logs.recent(stamps.wall.saturating_sub(60_000_000_000), 100);
        if let serde_json::Value::Object(object) = &mut incident.evidence {
            object.insert(
                "captured_logs".to_string(),
                serde_json::Value::from(evidence_logs.len()),
            );
            object.insert(
                "association".to_string(),
                serde_json::Value::from("temporal association only; causation not implied"),
            );
        }
        batch.push(WriteItem::critical(WriteRecord::Incident(incident)));
        report.incidents = report.incidents.saturating_add(1);
        for mut log in evidence_logs {
            log.incident_id = Some(id);
            batch.push(WriteItem::critical(WriteRecord::Log(log)));
        }
    }
    for (incident_id, ended, peak, evidence, loss) in pulse.updated {
        batch.push(WriteItem::critical(WriteRecord::IncidentUpdate {
            incident_id,
            ended_wall_ns: ended,
            peak,
            evidence,
            evidence_loss: loss,
        }));
    }
    for event in pulse.events {
        batch.push(WriteItem::critical(WriteRecord::Event(event)));
    }
}

fn enrich(
    enrichment: &mut Enrichment,
    config: &Config,
    catalog: &Catalog,
    observed_tools: &HashSet<String>,
    stamps: &Stamps,
    batch: &mut Vec<WriteItem>,
    health: &mut HealthRegistry,
) {
    if config.integrations.docker.should_attempt() {
        let discovery = docker::discover();
        enrichment.containers = discovery
            .containers
            .iter()
            .map(|container| (container.short_id.clone(), container.clone()))
            .collect();
        enrichment.container_names = discovery
            .containers
            .iter()
            .map(|container| (container.short_id.clone(), container.name.clone()))
            .collect();
        for container in &discovery.containers {
            let labels = BTreeMap::from([
                ("image".to_string(), container.image.clone()),
                ("state".to_string(), container.state.clone()),
                ("status".to_string(), container.status.clone()),
            ]);
            batch.push(WriteItem::normal(WriteRecord::Entity(Entity {
                entity_id: format!("container:{}", container.short_id),
                kind: EntityKind::Container,
                stable_key: container.id.clone(),
                name: container.name.clone(),
                source: "docker".to_string(),
                labels,
                first_seen_wall_ns: stamps.wall,
                last_seen_wall_ns: stamps.wall,
            })));
        }
        let (detected, error) = if discovery.available {
            (Availability::Available, None)
        } else {
            (Availability::Unavailable, discovery.error.clone())
        };
        batch.push(WriteItem::normal(WriteRecord::IntegrationState(
            integration_row(
                "docker",
                config.integrations.docker,
                detected,
                None,
                catalog,
                error,
                stamps.wall,
            ),
        )));
        enrichment.docker = discovery;
        if detected == Availability::Available {
            health.success("docker", stamps.wall);
        } else {
            health.unavailable("docker", "docker CLI/daemon unavailable");
        }
    }

    if config.integrations.tmux.should_attempt() {
        let tmux = sessions::discover_tmux();
        if tmux.available && !tmux.panes.is_empty() {
            health.success("tmux", stamps.wall);
        } else if tmux.available {
            health.unavailable("tmux", "tmux installed but no server/session is running");
        } else {
            health.unavailable("tmux", "tmux not installed");
        }
        for session in &tmux.sessions {
            batch.push(WriteItem::normal(WriteRecord::Entity(Entity {
                entity_id: format!("session:tmux:{session}"),
                kind: EntityKind::Session,
                stable_key: format!("tmux:{session}"),
                name: session.clone(),
                source: "tmux".to_string(),
                labels: BTreeMap::from([("manager".to_string(), "tmux".to_string())]),
                first_seen_wall_ns: stamps.wall,
                last_seen_wall_ns: stamps.wall,
            })));
        }
        batch.push(WriteItem::normal(WriteRecord::IntegrationState(
            integration_row(
                "tmux",
                config.integrations.tmux,
                if tmux.available {
                    Availability::Available
                } else {
                    Availability::Unavailable
                },
                None,
                catalog,
                tmux.error.clone(),
                stamps.wall,
            ),
        )));
        enrichment.sessions = tmux;
    }

    if config.integrations.zellij.should_attempt() {
        let zellij = sessions::discover_zellij();
        if zellij.available && !zellij.sessions.is_empty() {
            health.success("zellij", stamps.wall);
        } else if zellij.available {
            health.unavailable("zellij", "zellij installed but no session is running");
        } else {
            health.unavailable("zellij", "zellij not installed");
        }
        for session in &zellij.sessions {
            batch.push(WriteItem::normal(WriteRecord::Entity(Entity {
                entity_id: format!("session:zellij:{session}"),
                kind: EntityKind::Session,
                stable_key: format!("zellij:{session}"),
                name: session.clone(),
                source: "zellij".to_string(),
                labels: BTreeMap::from([("manager".to_string(), "zellij".to_string())]),
                first_seen_wall_ns: stamps.wall,
                last_seen_wall_ns: stamps.wall,
            })));
        }
        batch.push(WriteItem::normal(WriteRecord::IntegrationState(
            integration_row(
                "zellij",
                config.integrations.zellij,
                if zellij.available {
                    Availability::Available
                } else {
                    Availability::Unavailable
                },
                None,
                catalog,
                zellij.error.clone(),
                stamps.wall,
            ),
        )));
        enrichment.zellij = zellij;
    }

    // Process-based integrations are detected by the catalog; absence is unknown,
    // never reported as unavailable/zero.
    for (id, toggle) in [
        ("nginx", config.integrations.nginx),
        ("cloudflared", config.integrations.cloudflared),
        ("systemd", config.integrations.systemd),
    ] {
        let detected = if observed_tools.contains(id) {
            Availability::Available
        } else {
            Availability::Unknown
        };
        let error = if detected == Availability::Available {
            None
        } else {
            Some("not observed in this run".to_string())
        };
        batch.push(WriteItem::normal(WriteRecord::IntegrationState(
            integration_row(id, toggle, detected, None, catalog, error, stamps.wall),
        )));
        if detected == Availability::Available {
            health.success(id, stamps.wall);
        } else if let Some(entry) = health.entry(id) {
            // Absence of a process is unknown coverage, not proof of an unavailable
            // integration (it may simply be idle or not started yet).
            entry.availability = Availability::Unknown;
            entry.last_error = Some("not observed in this run".to_string());
        }
    }
}

fn integration_row(
    id: &str,
    toggle: Toggle,
    detected: Availability,
    version: Option<String>,
    catalog: &Catalog,
    error: Option<String>,
    now: WallNs,
) -> IntegrationStateRow {
    let capabilities = catalog.get(id).map_or_else(
        || "[]".to_string(),
        |tool| serde_json::to_string(&tool.capabilities).unwrap_or_else(|_| "[]".into()),
    );
    IntegrationStateRow {
        integration_id: id.to_string(),
        configured_state: toggle.as_str().to_string(),
        detected_state: detected.as_str().to_string(),
        version,
        capabilities_json: Some(capabilities),
        last_seen_wall_ns: Some(now),
        last_error: error,
    }
}

fn apply_session_map(collector: &mut ProcessCollector, enrichment: &Enrichment) {
    let mut map = HashMap::new();
    for pane in &enrichment.sessions.panes {
        map.insert(pane.pane_pid, pane.label());
    }
    collector.set_sessions(map);
}

fn prune(
    options: &DaemonOptions,
    writer: &Writer,
    now_wall_ns: WallNs,
    health: &mut HealthRegistry,
) {
    // Retention needs mutable access to one connection; flush the writer and use a
    // short-lived second connection for the rollup transaction.
    if let Err(err) = writer.flush() {
        health.error("retention", now_wall_ns, &err.to_string());
        return;
    }
    let policy = RetentionPolicy::from_config(&options.config, 100);
    match Store::open(&options.data_dir.db_path()).and_then(|mut store| {
        crate::store::retention::prune(&mut store, &policy, now_wall_ns, options.data_dir.root())
    }) {
        Ok(report) => {
            health.success("retention", now_wall_ns);
            health.coverage(
                "retention",
                json!({
                    "host_rollup_rows": report.host_rollup_rows,
                    "cgroup_rollup_rows": report.cgroup_rollup_rows,
                    "hour_rollup_rows": report.hour_rollup_rows,
                    "deleted_host_samples": report.deleted_host_samples,
                    "deleted_cgroup_samples": report.deleted_cgroup_samples,
                    "deleted_process_samples": report.deleted_process_samples,
                    "deleted_logs": report.deleted_logs,
                    "deleted_events": report.deleted_events,
                    "deleted_incidents": report.deleted_incidents,
                    "pressure_steps": report.pressure_steps,
                }),
            );
        }
        Err(err) => health.error("retention", now_wall_ns, &err.to_string()),
    }
}

fn batch_process_starts(batch: &[WriteItem]) -> u64 {
    batch
        .iter()
        .filter(|item| matches!(item.record, WriteRecord::ProcessLifetime(_)))
        .count() as u64
}

fn process_sample_count(batch: &[WriteItem]) -> u64 {
    batch
        .iter()
        .filter(|item| matches!(item.record, WriteRecord::ProcessSample(_)))
        .count() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cadence_due_is_at_least_one_interval() {
        let mut last = i64::MIN / 2;
        assert!(due(&mut last, 1_000_000_000, 5));
        assert!(!due(&mut last, 2_000_000_000, 5));
        assert!(due(&mut last, 6_000_000_000, 5));
        assert!(due(&mut last, 7_000_000_000, 1));
    }

    #[test]
    fn host_cpu_is_percent_of_one_core() {
        use crate::model::CpuTimes;
        let before = HostSample {
            cpu: CpuTimes {
                user: 100,
                idle: 900,
                ..Default::default()
            },
            per_cpu: vec![CpuTimes::default(); 8],
            ..Default::default()
        };
        let after = HostSample {
            cpu: CpuTimes {
                user: 180,
                idle: 920,
                ..Default::default()
            },
            per_cpu: vec![CpuTimes::default(); 8],
            ..Default::default()
        };
        // 80 busy ticks of 100 total = 80% of all 8 cores = 12.5% of one core.
        let pct = host_cpu_pct(&before, &after, 8).expect("pct");
        assert!((pct - 640.0).abs() < 0.001, "pct {pct}");
    }

    #[test]
    fn cycle_root_uses_snapshot_directories() {
        let dir = std::env::temp_dir().join(format!("sarf-daemon-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("proc")).expect("proc");
        std::fs::create_dir_all(dir.join("cycle-0001/proc")).expect("cycle");
        let base = SourceRoot::fixture(&dir);
        let first = cycle_root(&base, 0);
        let second = cycle_root(&base, 1);
        assert!(first.proc_root().ends_with("proc"));
        assert!(second.proc_root().ends_with("cycle-0001/proc"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
