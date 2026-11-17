//! Dynamic peak detection and agent-oriented cascade dossiers.
//!
//! A peak is **relative to the entity's own recent history**, never an absolute
//! threshold. A candidate must exceed the rolling p99 of the same entity/metric
//! and sit at least `mad_k` median-absolute-deviations above the rolling median
//! (with a small per-metric floor). Because the window rolls, a level that
//! becomes the new normal stops being reported: 10 % with an occasional 10.5 %
//! is a peak, but once 11 % is ordinary, 10.5 % is not.
//!
//! Detection runs on 1-minute rollups so it is cheap and deterministic. A
//! dossier is self-contained JSON: the peak, a typed graph of the host, cgroups
//! and processes with their values, and a bounded series around the episode.
//! Missing values are omitted, never zero-filled.
//!
//! The graph does **not** claim stack-level attribution (no eBPF/perf): edges
//! are `on` (runs on that host/cgroup) and `in` (process is contained in that
//! cgroup). `own` is only computed where containment makes it meaningful.

use std::collections::{HashMap, VecDeque};

use rusqlite::Connection;
use serde::Serialize;

use crate::config::Config;
use crate::error::Result;
use crate::model::{EntityKind, Metric};
use crate::store::query::{self, EntityUsage, RollupPoint, Window};
use crate::store::PeakDossierRow;

/// Stable document schema name for machine consumers.
pub const PEAK_SCHEMA: &str = "sarf.peak";
/// Version of the peak document.
pub const PEAK_SCHEMA_VERSION: u32 = 1;
/// One bucket of the detection series.
const MINUTE_NS: i64 = 60_000_000_000;
/// Minimum baseline points before a peak can be claimed.
const MIN_HISTORY: usize = 5;
/// Metrics with a per-entity time series.
const METRICS: [Metric; 9] = [
    Metric::Cpu,
    Metric::Memory,
    Metric::IoRead,
    Metric::IoWrite,
    Metric::NetRx,
    Metric::NetTx,
    Metric::PsiCpu,
    Metric::PsiMemory,
    Metric::PsiIo,
];

/// Bounds and semantics for peak detection.
#[derive(Debug, Clone)]
pub struct PeakPolicy {
    /// Whether detection and storage are enabled.
    pub enabled: bool,
    /// Rolling baseline window.
    pub baseline_ns: i64,
    /// Robustness factor applied to the median absolute deviation.
    pub mad_k: f64,
    /// Consecutive buckets required to report a peak.
    pub min_sustain: usize,
    /// Maximum peaks per document and per stored pass.
    pub max_peaks: usize,
    /// Maximum graph nodes per peak (host included).
    pub max_nodes: usize,
    /// History kept before and after a peak in the series.
    pub series_ns: i64,
    /// Look-back window used by each daemon detection pass.
    pub detect_ns: i64,
    /// How long stored dossiers are retained.
    pub retain_ns: i64,
}

impl PeakPolicy {
    /// Derive the policy from configuration.
    pub fn from_config(config: &Config) -> Self {
        let peaks = &config.peaks;
        Self {
            enabled: peaks.enabled,
            baseline_ns: (peaks.baseline_mins as i64).max(1) * MINUTE_NS,
            mad_k: peaks.mad_k.max(0.0),
            min_sustain: (peaks.min_sustain as usize).max(1),
            max_peaks: (peaks.max_peaks as usize).max(1),
            max_nodes: (peaks.max_nodes as usize).max(2),
            series_ns: (peaks.series_mins as i64).max(1) * MINUTE_NS,
            detect_ns: (peaks.detect_mins as i64).max(1) * MINUTE_NS,
            retain_ns: (peaks.retain_hours as i64).max(1) * 60 * MINUTE_NS,
        }
    }
}

/// One machine-readable peak document.
#[derive(Debug, Clone, Serialize)]
pub struct PeakDocument {
    /// Schema name: always [`PEAK_SCHEMA`].
    pub schema: &'static str,
    /// Schema version.
    pub v: u32,
    /// Requested window start.
    pub since_wall_ns: i64,
    /// Requested window end.
    pub until_wall_ns: i64,
    /// Number of peaks in this document.
    pub peak_count: usize,
    /// Peaks, highest score first.
    pub peaks: Vec<PeakDossier>,
}

/// Document assembled from stored dossiers (no recomputation).
#[derive(Debug, Clone, Serialize)]
pub struct StoredPeakDocument {
    /// Schema name: always [`PEAK_SCHEMA`].
    pub schema: &'static str,
    /// Schema version.
    pub v: u32,
    /// Requested window start.
    pub since_wall_ns: i64,
    /// Requested window end.
    pub until_wall_ns: i64,
    /// Number of stored peaks in this document.
    pub peak_count: usize,
    /// Stored dossier payloads, oldest first.
    pub peaks: Vec<serde_json::Value>,
}

/// One detected peak with its cascade graph.
#[derive(Debug, Clone, Serialize)]
pub struct PeakDossier {
    /// Stable id (`scope|metric|start`).
    pub id: String,
    /// Metric name.
    pub metric: String,
    /// Entity the peak was detected on.
    pub scope: String,
    /// Episode start.
    pub start_wall_ns: i64,
    /// Episode end.
    pub end_wall_ns: i64,
    /// `spike` (one bucket) or `sustained`.
    pub shape: String,
    /// Peak value.
    pub peak: f64,
    /// Rolling median baseline before the peak.
    pub base: f64,
    /// Rolling p99 baseline before the peak (the dynamic floor).
    pub p99: f64,
    /// `peak / max(p99, floor)`, always finite and greater than 1.
    pub score: f64,
    /// Graph nodes; index 0 is the host.
    pub nodes: Vec<PeakNode>,
    /// Typed edges `[parent, child, kind]`.
    pub edges: Vec<(usize, usize, EdgeKind)>,
    /// Grid the node series are aligned to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub series: Option<PeakSeries>,
    /// Events and logs observed in the episode.
    pub activity: PeakActivity,
}

/// Graph node: host, cgroup/container or process.
#[derive(Debug, Clone, Serialize)]
pub struct PeakNode {
    /// Entity id.
    pub id: String,
    /// Display name.
    pub name: String,
    /// `host`, `cgroup` or `process`.
    pub kind: String,
    /// Host PID for processes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    /// Container id/name when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
    /// systemd unit when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    /// Value in the peak bucket (omitted when unavailable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<f64>,
    /// `value / peak`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub share: Option<f64>,
    /// Value minus contained children, where that is meaningful.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub own: Option<f64>,
    /// Median of this node's series before the episode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base: Option<f64>,
    /// Series values aligned to [`PeakSeries::from_wall_ns`]; `null` is missing.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub series: Vec<Option<f64>>,
}

/// Uniform grid shared by every node series.
#[derive(Debug, Clone, Serialize)]
pub struct PeakSeries {
    /// Bucket width.
    pub step_ns: i64,
    /// First bucket start.
    pub from_wall_ns: i64,
    /// Number of buckets.
    pub points: usize,
}

/// Event/log activity around the peak.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct PeakActivity {
    /// Process start events.
    pub starts: u64,
    /// Process exit events.
    pub exits: u64,
    /// Stored events.
    pub events: u64,
    /// Stored log lines.
    pub logs: u64,
    /// Error/critical log lines.
    pub errors: u64,
}

/// Edge labels kept short for the JSON artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    /// Child runs on the parent host/cgroup (not an additive containment claim).
    On,
    /// Child is contained in the parent cgroup.
    In,
}

/// Identity facts needed to place a process in the graph.
struct ProcessIdentity {
    pid: u32,
    cgroup: Option<String>,
    unit: Option<String>,
}

/// Detection result before the graph is attached.
#[derive(Debug, Clone)]
struct RawPeak {
    entity_id: String,
    entity_kind: String,
    metric: Metric,
    start_wall_ns: i64,
    end_wall_ns: i64,
    peak: f64,
    base: f64,
    p99: f64,
    buckets: usize,
}

/// Detect peaks across every entity and metric in `window`.
///
/// Only entities with rollup rows are considered; a metric that is missing for
/// a bucket is skipped (never treated as zero).
fn detect(conn: &Connection, window: Window, policy: &PeakPolicy) -> Result<Vec<RawPeak>> {
    let mut peaks = Vec::new();
    let baseline_from = window.since.saturating_sub(policy.baseline_ns);
    for (entity_id, entity_kind) in query::rollup_entities(conn, window)? {
        let points =
            query::rollup_series(conn, &entity_id, Window::new(baseline_from, window.until))?;
        if points.len() < MIN_HISTORY {
            continue;
        }
        for metric in METRICS {
            peaks.extend(detect_series(
                &entity_id,
                &entity_kind,
                metric,
                &points,
                window.since,
                policy,
            ));
        }
    }
    peaks.sort_by(|left, right| {
        score(left)
            .total_cmp(&score(right))
            .then_with(|| left.start_wall_ns.cmp(&right.start_wall_ns))
            .then_with(|| left.entity_id.cmp(&right.entity_id))
            .then_with(|| left.metric.as_str().cmp(right.metric.as_str()))
    });
    peaks.truncate(policy.max_peaks);
    Ok(peaks)
}

fn score(peak: &RawPeak) -> f64 {
    let denominator = peak
        .p99
        .max(metric_floor(peak.metric))
        .max(f64::MIN_POSITIVE);
    (peak.peak / denominator).max(1.0)
}

fn detect_series(
    entity_id: &str,
    entity_kind: &str,
    metric: Metric,
    points: &[RollupPoint],
    window_start: i64,
    policy: &PeakPolicy,
) -> Vec<RawPeak> {
    let mut history: VecDeque<(i64, f64)> = VecDeque::new();
    let mut sorted: Vec<f64> = Vec::new();
    let mut peaks: Vec<RawPeak> = Vec::new();
    let mut current: Option<RawPeak> = None;

    for point in points {
        let bucket = point.bucket_wall_ns;
        while let Some((stamp, value)) = history.front() {
            if *stamp <= bucket.saturating_sub(policy.baseline_ns) {
                remove_value(&mut sorted, *value);
                history.pop_front();
            } else {
                break;
            }
        }

        // A bucket without the metric closes the run: missing data is not zero.
        let Some(value) = metric_value(point, metric) else {
            if let Some(run) = current.take() {
                peaks.push(run);
            }
            continue;
        };

        let mut candidate = None;
        if bucket >= window_start && history.len() >= MIN_HISTORY {
            let median = quantile(&sorted, 0.5);
            let p99 = quantile(&sorted, 0.99);
            // Compare with `>=`: a sustained plateau re-enters the baseline as
            // it lasts, so a strict `>` would end the run after one bucket.
            if value >= p99 {
                let mad = median_absolute_deviation(&sorted, median);
                let floor = metric_floor(metric).max(policy.mad_k * mad);
                if value - median >= floor {
                    candidate = Some((median, p99));
                }
            }
        }

        match candidate {
            Some((median, p99)) => match current.as_mut() {
                Some(run) => {
                    run.end_wall_ns = bucket.saturating_add(MINUTE_NS);
                    run.buckets = run.buckets.saturating_add(1);
                    if value > run.peak {
                        run.peak = value;
                        run.base = median;
                        run.p99 = p99;
                    }
                }
                None => {
                    current = Some(RawPeak {
                        entity_id: entity_id.to_string(),
                        entity_kind: entity_kind.to_string(),
                        metric,
                        start_wall_ns: bucket,
                        end_wall_ns: bucket.saturating_add(MINUTE_NS),
                        peak: value,
                        base: median,
                        p99,
                        buckets: 1,
                    });
                }
            },
            None => {
                if let Some(run) = current.take() {
                    peaks.push(run);
                }
            }
        }

        insert_value(&mut sorted, value);
        history.push_back((bucket, value));
    }
    if let Some(run) = current.take() {
        peaks.push(run);
    }
    peaks.retain(|peak| peak.buckets >= policy.min_sustain);
    peaks
}

fn insert_value(sorted: &mut Vec<f64>, value: f64) {
    let index = sorted.partition_point(|probe| *probe < value);
    sorted.insert(index, value);
}

fn remove_value(sorted: &mut Vec<f64>, value: f64) {
    if let Ok(index) = sorted.binary_search_by(|probe| probe.total_cmp(&value)) {
        sorted.remove(index);
    }
}

/// Nearest order statistic (no interpolation, so a value always comes from an
/// observed sample rather than a fabricated average).
fn quantile(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let index = ((sorted.len() - 1) as f64 * q).round() as usize;
    sorted[index.min(sorted.len() - 1)]
}

fn median_absolute_deviation(sorted: &[f64], median: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let mut deviations: Vec<f64> = sorted.iter().map(|value| (value - median).abs()).collect();
    deviations.sort_by(f64::total_cmp);
    quantile(&deviations, 0.5)
}

/// Smallest meaningful change per metric, so a near-constant series cannot
/// report floating-point jitter as a peak.
const fn metric_floor(metric: Metric) -> f64 {
    match metric {
        Metric::Cpu | Metric::PsiCpu | Metric::PsiMemory | Metric::PsiIo | Metric::Load => 0.5,
        Metric::Memory => 1024.0 * 1024.0,
        Metric::IoRead | Metric::IoWrite | Metric::NetRx | Metric::NetTx => 64.0 * 1024.0,
    }
}

fn metric_value(point: &RollupPoint, metric: Metric) -> Option<f64> {
    match metric {
        Metric::Cpu => point.cpu_max_pct,
        Metric::Memory => point.memory_max_bytes.map(|value| value as f64),
        Metric::IoRead => point.io_read_bytes.map(|value| value as f64),
        Metric::IoWrite => point.io_write_bytes.map(|value| value as f64),
        Metric::NetRx => point.net_rx_bytes.map(|value| value as f64),
        Metric::NetTx => point.net_tx_bytes.map(|value| value as f64),
        Metric::PsiCpu => point.psi_cpu_max,
        Metric::PsiMemory => point.psi_mem_max,
        Metric::PsiIo => point.psi_io_max,
        Metric::Load => None,
    }
}

/// Whether a metric is measured per entity (`false` for PSI, which is only
/// available for hosts and cgroups).
const fn per_process(metric: Metric) -> bool {
    matches!(
        metric,
        Metric::Cpu
            | Metric::Memory
            | Metric::IoRead
            | Metric::IoWrite
            | Metric::NetRx
            | Metric::NetTx
    )
}

/// Build every dossier for `window`.
pub fn build_dossiers(
    conn: &Connection,
    window: Window,
    policy: &PeakPolicy,
) -> Result<Vec<PeakDossier>> {
    let host = query::host_entity(conn)?;
    let mut dossiers = Vec::new();
    for raw in detect(conn, window, policy)? {
        dossiers.push(build_dossier(conn, &raw, host.as_ref(), policy)?);
    }
    Ok(dossiers)
}

/// Build the complete document for `window`.
pub fn document(conn: &Connection, window: Window, policy: &PeakPolicy) -> Result<PeakDocument> {
    let peaks = build_dossiers(conn, window, policy)?;
    Ok(PeakDocument {
        schema: PEAK_SCHEMA,
        v: PEAK_SCHEMA_VERSION,
        since_wall_ns: window.since,
        until_wall_ns: window.until,
        peak_count: peaks.len(),
        peaks,
    })
}

/// Assemble a document from stored dossiers (survives raw-data expiry).
pub fn stored_document(
    conn: &Connection,
    window: Window,
    limit: usize,
) -> Result<StoredPeakDocument> {
    let mut peaks = Vec::new();
    for stored in query::stored_peaks(conn, window, limit)? {
        match serde_json::from_str::<serde_json::Value>(&stored.payload_json) {
            Ok(value) => peaks.push(value),
            // A truncated or older payload is reported, never silently dropped.
            Err(err) => peaks.push(serde_json::json!({
                "id": stored.peak_id,
                "metric": stored.metric,
                "scope": stored.scope_entity_id,
                "start_wall_ns": stored.started_wall_ns,
                "invalid": err.to_string(),
            })),
        }
    }
    Ok(StoredPeakDocument {
        schema: PEAK_SCHEMA,
        v: PEAK_SCHEMA_VERSION,
        since_wall_ns: window.since,
        until_wall_ns: window.until,
        peak_count: peaks.len(),
        peaks,
    })
}

/// Serialize one dossier into a storage row.
pub fn dossier_row(dossier: &PeakDossier, now_wall_ns: i64) -> Result<PeakDossierRow> {
    let payload_json = serde_json::to_string(dossier)
        .map_err(|err| crate::error::Error::Storage(format!("serialize peak: {err}")))?;
    Ok(PeakDossierRow {
        peak_id: dossier.id.clone(),
        started_wall_ns: dossier.start_wall_ns,
        ended_wall_ns: dossier.end_wall_ns,
        metric: dossier.metric.clone(),
        scope_entity_id: dossier.scope.clone(),
        score: dossier.score,
        created_wall_ns: now_wall_ns,
        payload_json,
    })
}

fn build_dossier(
    conn: &Connection,
    raw: &RawPeak,
    host: Option<&(String, String)>,
    policy: &PeakPolicy,
) -> Result<PeakDossier> {
    let window = Window::new(raw.start_wall_ns, raw.end_wall_ns);
    let series_from = raw.start_wall_ns.saturating_sub(policy.series_ns);
    let series_to = raw.end_wall_ns.saturating_add(policy.series_ns);
    let grid = Window::new(series_from, series_to);
    let grid_points = ((series_to - series_from) / MINUTE_NS).max(1) as usize;

    let usage = query::entity_usage(conn, window)?;
    let lifetimes = query::lifetimes(conn, window, 500)?;
    let process_meta: HashMap<&str, ProcessIdentity> = lifetimes
        .iter()
        .map(|row| {
            (
                row.process_instance_id.as_str(),
                ProcessIdentity {
                    pid: row.host_pid,
                    cgroup: row.cgroup_entity_id.clone(),
                    unit: row.unit.clone(),
                },
            )
        })
        .collect();

    let host_id = host.map_or_else(|| "host:unknown".to_string(), |(id, _)| id.clone());
    let host_name = host.map_or_else(|| "host".to_string(), |(_, name)| name.clone());

    let mut nodes: Vec<PeakNode> = Vec::new();
    let mut edges: Vec<(usize, usize, EdgeKind)> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();

    // Host root: always index 0, even when the peak itself is cgroup-scoped.
    let host_series = rollup_values(conn, &host_id, grid, grid_points, raw.metric)?;
    let host_value = value_at(&host_series, grid, raw.start_wall_ns, raw.end_wall_ns)
        .or_else(|| (raw.entity_kind == "host").then_some(raw.peak));
    nodes.push(PeakNode {
        id: host_id,
        name: host_name,
        kind: "host".to_string(),
        pid: None,
        container: None,
        unit: None,
        value: host_value,
        share: Some(1.0),
        own: None,
        base: baseline_of(&host_series, grid, raw.start_wall_ns),
        series: host_series,
    });

    // Cgroup/container nodes, highest value first.
    let mut cgroups: Vec<&EntityUsage> = usage
        .iter()
        .filter(|row| row.kind == EntityKind::Cgroup)
        .collect();
    cgroups.sort_by(|left, right| {
        entity_value(right, raw.metric)
            .unwrap_or(0.0)
            .total_cmp(&entity_value(left, raw.metric).unwrap_or(0.0))
            .then_with(|| left.name.cmp(&right.name))
    });
    let cgroup_slots = policy.max_nodes.saturating_sub(2);
    let mut selected_cgroups: Vec<usize> = Vec::new();
    for cgroup in cgroups.into_iter().take(cgroup_slots) {
        let series_values = rollup_values(conn, &cgroup.entity_id, grid, grid_points, raw.metric)?;
        let value = value_at(&series_values, grid, raw.start_wall_ns, raw.end_wall_ns)
            .or_else(|| entity_value(cgroup, raw.metric));
        let node_index = nodes.len();
        index.insert(cgroup.entity_id.clone(), node_index);
        nodes.push(PeakNode {
            id: cgroup.entity_id.clone(),
            name: cgroup.name.clone(),
            kind: "cgroup".to_string(),
            pid: None,
            container: cgroup.container.clone(),
            unit: None,
            value,
            share: value.map(|value| share(value, raw.peak)),
            own: None,
            base: baseline_of(&series_values, grid, raw.start_wall_ns),
            series: series_values,
        });
        edges.push((0, node_index, EdgeKind::On));
        selected_cgroups.push(node_index);
    }

    // Processes are only attributed for metrics that are measured per process.
    if per_process(raw.metric) {
        let mut processes: Vec<&EntityUsage> = usage
            .iter()
            .filter(|row| row.kind == EntityKind::Process)
            .collect();
        processes.sort_by(|left, right| {
            entity_value(right, raw.metric)
                .unwrap_or(0.0)
                .total_cmp(&entity_value(left, raw.metric).unwrap_or(0.0))
                .then_with(|| left.entity_id.cmp(&right.entity_id))
        });
        let remaining = policy.max_nodes.saturating_sub(nodes.len());
        for process in processes.into_iter().take(remaining) {
            let meta = process_meta.get(process.entity_id.as_str());
            let (parent, kind) = meta
                .and_then(|meta| meta.cgroup.as_deref())
                .and_then(|cgroup| index.get(cgroup).copied())
                .map_or((0, EdgeKind::On), |parent| (parent, EdgeKind::In));
            let value = entity_value(process, raw.metric);
            let node_index = nodes.len();
            index.insert(process.entity_id.clone(), node_index);
            nodes.push(PeakNode {
                id: process.entity_id.clone(),
                name: process.name.clone(),
                kind: "process".to_string(),
                pid: meta.map(|meta| meta.pid),
                container: process.container.clone(),
                unit: meta.and_then(|meta| meta.unit.clone()),
                value,
                share: value.map(|value| share(value, raw.peak)),
                own: value,
                base: None,
                series: Vec::new(),
            });
            edges.push((parent, node_index, kind));
        }
    }

    // Own value for each cgroup with contained process children.
    for node_index in selected_cgroups {
        let own = nodes[node_index].value.map(|value| {
            let children: f64 = edges
                .iter()
                .filter(|(parent, _, kind)| *parent == node_index && *kind == EdgeKind::In)
                .filter_map(|(_, child, _)| nodes[*child].value)
                .sum();
            (value - children).max(0.0)
        });
        nodes[node_index].own = own;
    }

    let activity = query::window_activity(conn, window)?;
    let series = nodes
        .iter()
        .any(|node| !node.series.is_empty())
        .then_some(PeakSeries {
            step_ns: MINUTE_NS,
            from_wall_ns: series_from,
            points: grid_points,
        });

    Ok(PeakDossier {
        id: format!(
            "{}|{}|{}",
            raw.entity_id,
            raw.metric.as_str(),
            raw.start_wall_ns
        ),
        metric: raw.metric.as_str().to_string(),
        scope: raw.entity_id.clone(),
        start_wall_ns: raw.start_wall_ns,
        end_wall_ns: raw.end_wall_ns,
        shape: if raw.buckets <= 1 {
            "spike".to_string()
        } else {
            "sustained".to_string()
        },
        peak: raw.peak,
        base: raw.base,
        p99: raw.p99,
        score: score(raw),
        nodes,
        edges,
        series,
        activity: PeakActivity {
            starts: activity.process_starts,
            exits: activity.process_exits,
            events: activity.events,
            logs: activity.logs,
            errors: activity.errors,
        },
    })
}

fn share(value: f64, peak: f64) -> f64 {
    if peak > 0.0 {
        (value / peak).clamp(0.0, 1.0)
    } else {
        0.0
    }
}

fn entity_value(usage: &EntityUsage, metric: Metric) -> Option<f64> {
    match metric {
        Metric::Cpu => usage.cpu_max_pct.or(usage.cpu_avg_pct),
        Metric::Memory => usage.memory_max_bytes.map(|value| value as f64),
        Metric::IoRead => usage.io_read_bytes.map(|value| value as f64),
        Metric::IoWrite => usage.io_write_bytes.map(|value| value as f64),
        Metric::NetRx => usage.net_rx_bytes.map(|value| value as f64),
        Metric::NetTx => usage.net_tx_bytes.map(|value| value as f64),
        // PSI is available for hosts and cgroups only, from the rollup series.
        Metric::PsiCpu | Metric::PsiMemory | Metric::PsiIo | Metric::Load => None,
    }
}

fn rollup_values(
    conn: &Connection,
    entity_id: &str,
    grid: Window,
    points: usize,
    metric: Metric,
) -> Result<Vec<Option<f64>>> {
    let rows = query::rollup_series(conn, entity_id, grid)?;
    let mut values = vec![None; points];
    for row in rows {
        let index = (row.bucket_wall_ns - grid.since) / MINUTE_NS;
        if let Ok(index) = usize::try_from(index) {
            if index < values.len() {
                values[index] = metric_value(&row, metric);
            }
        }
    }
    Ok(values)
}

fn value_at(series: &[Option<f64>], grid: Window, start: i64, end: i64) -> Option<f64> {
    let first = usize::try_from((start - grid.since) / MINUTE_NS).unwrap_or(0);
    let last = usize::try_from((end.saturating_sub(1) - grid.since) / MINUTE_NS).unwrap_or(first);
    series
        .iter()
        .skip(first)
        .take(last.saturating_sub(first).saturating_add(1))
        .flatten()
        .copied()
        .reduce(f64::max)
}

fn baseline_of(series: &[Option<f64>], grid: Window, start: i64) -> Option<f64> {
    let end = usize::try_from((start - grid.since) / MINUTE_NS).unwrap_or(0);
    let mut values: Vec<f64> = series.iter().take(end).flatten().copied().collect();
    if values.is_empty() {
        return None;
    }
    values.sort_by(f64::total_cmp);
    Some(quantile(&values, 0.5))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::float_cmp)]

    use super::*;
    use crate::store::{Store, WriteItem, WriteRecord};

    fn point(minute: i64, cpu: Option<f64>) -> RollupPoint {
        RollupPoint {
            bucket_wall_ns: minute * MINUTE_NS,
            sample_count: 5,
            cpu_max_pct: cpu,
            ..RollupPoint::default()
        }
    }

    fn policy() -> PeakPolicy {
        PeakPolicy {
            enabled: true,
            baseline_ns: 60 * MINUTE_NS,
            mad_k: 3.0,
            min_sustain: 1,
            max_peaks: 20,
            max_nodes: 16,
            series_ns: 10 * MINUTE_NS,
            detect_ns: 30 * MINUTE_NS,
            retain_ns: 72 * 60 * MINUTE_NS,
        }
    }

    #[test]
    fn a_small_rise_above_a_flat_baseline_is_a_peak() {
        // 10 % is normal; one 10.5 % bucket is meaningful.
        let mut points: Vec<RollupPoint> =
            (0..60).map(|minute| point(minute, Some(10.0))).collect();
        points.push(point(60, Some(10.5)));
        let peaks = detect_series("h", "host", Metric::Cpu, &points, 60 * MINUTE_NS, &policy());
        assert_eq!(peaks.len(), 1, "peaks: {peaks:?}");
        assert_eq!(peaks[0].start_wall_ns, 60 * MINUTE_NS);
        assert!((peaks[0].peak - 10.5).abs() < 1e-9);
        assert!((peaks[0].base - 10.0).abs() < 1e-9);
    }

    #[test]
    fn a_level_that_became_normal_stops_being_a_peak() {
        // History at 10 %, then 11 % becomes the norm, then 10.5 % happens.
        // 10.5 % is below the rolling median, so it is not a peak.
        let mut points: Vec<RollupPoint> =
            (0..30).map(|minute| point(minute, Some(10.0))).collect();
        points.extend((30..120).map(|minute| point(minute, Some(11.0))));
        points.push(point(120, Some(10.5)));
        let peaks = detect_series(
            "h",
            "host",
            Metric::Cpu,
            &points,
            120 * MINUTE_NS,
            &policy(),
        );
        assert!(
            peaks.is_empty(),
            "10.5 % under an 11 % baseline must not be a peak: {peaks:?}"
        );
    }

    #[test]
    fn the_rise_to_the_new_norm_is_itself_a_peak() {
        let mut points: Vec<RollupPoint> =
            (0..60).map(|minute| point(minute, Some(10.0))).collect();
        points.extend((60..63).map(|minute| point(minute, Some(11.0))));
        let peaks = detect_series("h", "host", Metric::Cpu, &points, 60 * MINUTE_NS, &policy());
        assert_eq!(peaks.len(), 1, "peaks: {peaks:?}");
        assert_eq!(
            peaks[0].buckets, 3,
            "three consecutive buckets are sustained"
        );
    }

    #[test]
    fn missing_metric_buckets_never_become_zero() {
        // A gap in the middle must not create a peak and must not be treated as 0.
        let mut points: Vec<RollupPoint> =
            (0..60).map(|minute| point(minute, Some(10.0))).collect();
        points.push(point(60, None));
        points.push(point(61, Some(10.4)));
        let peaks = detect_series("h", "host", Metric::Cpu, &points, 60 * MINUTE_NS, &policy());
        assert!(
            peaks.is_empty(),
            "a missing bucket is not a sample: {peaks:?}"
        );
    }

    #[test]
    fn a_short_history_cannot_produce_a_peak() {
        let points: Vec<RollupPoint> = (0..4).map(|minute| point(minute, Some(10.0))).collect();
        assert!(detect_series("h", "host", Metric::Cpu, &points, 0, &policy()).is_empty());
    }

    #[test]
    fn score_is_finite_even_on_a_zero_baseline() {
        let mut points: Vec<RollupPoint> = (0..10).map(|minute| point(minute, Some(0.0))).collect();
        points.push(point(10, Some(4000.0)));
        let mut peaks = detect_series("h", "host", Metric::Cpu, &points, 0, &policy());
        assert_eq!(peaks.len(), 1);
        let raw = peaks.remove(0);
        assert!(score(&raw).is_finite(), "score: {}", score(&raw));
    }

    /// Insert the minimum rows the dossier builder needs.
    fn seed(store: &Store, base: i64) {
        let conn = store.connection();
        conn.execute(
            "INSERT INTO entities(entity_id, kind, stable_key, name, source, first_seen_wall_ns, last_seen_wall_ns)
             VALUES ('host:a','host','boot-a','nila','procfs',?1,?1)",
            rusqlite::params![base],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO entities(entity_id, kind, stable_key, name, source, first_seen_wall_ns, last_seen_wall_ns)
             VALUES ('cgroup:1:20','cgroup','20:1','utazbot_tgbot','cgroup',?1,?1)",
            rusqlite::params![base],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO process_lifetimes(process_instance_id, host_id, host_pid, start_ticks,
                comm, cgroup_entity_id, container, start_wall_ns, start_mono_ns)
             VALUES ('proc:a:4242:1','host:a',4242,1,'python','cgroup:1:20','utazbot_tgbot',?1,?1)",
            rusqlite::params![base],
        )
        .unwrap();
        // Process samples for the peak window: two or more samples are needed
        // before a CPU rate exists, so the process node keeps a value.
        for minute in 69..=72i64 {
            conn.execute(
                "INSERT INTO process_samples(mono_ts_ns, wall_ts_ns, process_instance_id,
                    cpu_user_ticks, rss_bytes, threads, state, sample_flags)
                 VALUES (?1, ?1, 'proc:a:4242:1', ?2, 10485760, 4, 'S', 0)",
                rusqlite::params![base + minute * MINUTE_NS, (minute - 69) * 1000],
            )
            .unwrap();
        }
        // 70 quiet minutes, then a 3-minute CPU peak on both host and cgroup.
        for minute in 0..=80i64 {
            let bucket = base + minute * MINUTE_NS;
            let host_cpu = if (70..=72).contains(&minute) {
                96.0
            } else {
                8.0
            };
            let cgroup_cpu = if (70..=72).contains(&minute) {
                70.0
            } else {
                2.0
            };
            for (entity, kind, cpu) in [
                ("host:a", "host", host_cpu),
                ("cgroup:1:20", "cgroup", cgroup_cpu),
            ] {
                conn.execute(
                    "INSERT INTO rollup_1m(bucket_wall_ns, entity_id, entity_kind, sample_count,
                        cpu_max_pct, memory_max_bytes, io_read_bytes, io_write_bytes,
                        net_rx_bytes, net_tx_bytes, psi_cpu_max)
                     VALUES (?1, ?2, ?3, 12, ?4, 104857600, 0, 0, 0, 0, 1.0)",
                    rusqlite::params![bucket, entity, kind, cpu],
                )
                .unwrap();
            }
        }
    }

    #[test]
    fn dossier_links_host_cgroup_and_process_with_aligned_series() {
        let store = Store::open_in_memory().expect("store");
        let base = 1_600_000_000_000_000_000i64;
        seed(&store, base);
        let window = Window::new(base, base + 86 * MINUTE_NS);
        let document = document(store.connection(), window, &policy()).expect("document");

        assert_eq!(document.schema, PEAK_SCHEMA);
        let peak = document
            .peaks
            .iter()
            .find(|peak| peak.metric == "cpu" && peak.scope == "host:a")
            .expect("host cpu peak");
        assert_eq!(peak.nodes[0].kind, "host");
        assert!((peak.peak - 96.0).abs() < 1e-9);
        assert!(peak.score > 1.0);
        let cgroup = peak
            .nodes
            .iter()
            .position(|node| node.kind == "cgroup")
            .expect("cgroup node");
        let process = peak
            .nodes
            .iter()
            .position(|node| node.kind == "process")
            .expect("process node");
        assert!(
            peak.edges.contains(&(0, cgroup, EdgeKind::On)),
            "host->cgroup edge: {:?}",
            peak.edges
        );
        assert!(
            peak.edges.contains(&(cgroup, process, EdgeKind::In)),
            "process containment edge: {:?}",
            peak.edges
        );
        // The process has no rollup series, so it must not pretend to have one.
        assert_eq!(peak.nodes[process].series.len(), 0);
        // Every retained series is aligned to the shared grid.
        let series = peak.series.as_ref().expect("grid");
        for node in &peak.nodes {
            if !node.series.is_empty() {
                assert_eq!(node.series.len(), series.points);
            }
        }
        assert!(peak.nodes[cgroup].own.is_some());
        // Containment must not claim more than the cgroup's own value.
        let cgroup_value = peak.nodes[cgroup].value.unwrap();
        let child_sum: f64 = peak
            .edges
            .iter()
            .filter(|(parent, _, kind)| *parent == cgroup && *kind == EdgeKind::In)
            .filter_map(|(_, child, _)| peak.nodes[*child].value)
            .sum();
        assert!(peak.nodes[cgroup].own.unwrap() <= cgroup_value);
        assert!(child_sum >= 0.0);
    }

    #[test]
    fn peak_json_is_compact_and_deterministic() {
        let store = Store::open_in_memory().expect("store");
        let base = 1_600_000_000_000_000_000i64;
        seed(&store, base);
        let window = Window::new(base, base + 86 * MINUTE_NS);
        let first =
            serde_json::to_string(&document(store.connection(), window, &policy()).unwrap())
                .expect("json");
        let second =
            serde_json::to_string(&document(store.connection(), window, &policy()).unwrap())
                .expect("json");
        assert_eq!(first, second, "peak JSON must be deterministic");
        // Compact: no indentation, no NaN/Infinity, no unknown-key padding.
        assert!(!first.contains('\n'));
        assert!(!first.contains("NaN"));
        assert!(!first.contains("Infinity"));
        assert!(first.contains("\"schema\":\"sarf.peak\""));
    }

    #[test]
    fn dossiers_round_trip_through_storage() {
        let mut store = Store::open_in_memory().expect("store");
        let base = 1_600_000_000_000_000_000i64;
        seed(&store, base);
        let window = Window::new(base, base + 86 * MINUTE_NS);
        let dossiers = build_dossiers(store.connection(), window, &policy()).expect("dossiers");
        assert!(!dossiers.is_empty());
        let mut items = Vec::new();
        for dossier in &dossiers {
            items.push(WriteItem::normal(WriteRecord::PeakDossier(
                dossier_row(dossier, base + 90 * MINUTE_NS).expect("row"),
            )));
        }
        store.write(&items).expect("write dossiers");

        let stored = stored_document(
            store.connection(),
            Window::new(base, base + 120 * MINUTE_NS),
            100,
        )
        .expect("stored");
        assert_eq!(stored.peak_count, dossiers.len());
        for peak in &stored.peaks {
            assert_eq!(
                peak.get("schema").and_then(|value| value.as_str()),
                None,
                "the stored payload is one peak, not a document"
            );
            assert!(peak.get("id").is_some());
            assert!(peak.get("nodes").is_some());
        }
    }

    #[test]
    fn retention_expires_dossiers_past_the_peak_window() {
        let mut store = Store::open_in_memory().expect("store");
        let now = 100 * 60 * MINUTE_NS;
        store
            .write(&[
                WriteItem::normal(WriteRecord::PeakDossier(PeakDossierRow {
                    peak_id: "old".into(),
                    started_wall_ns: now - 73 * 60 * MINUTE_NS,
                    ended_wall_ns: now - 73 * 60 * MINUTE_NS,
                    metric: "cpu".into(),
                    scope_entity_id: "host:a".into(),
                    score: 2.0,
                    created_wall_ns: now - 73 * 60 * MINUTE_NS,
                    payload_json: "{}".into(),
                })),
                WriteItem::normal(WriteRecord::PeakDossier(PeakDossierRow {
                    peak_id: "fresh".into(),
                    started_wall_ns: now - MINUTE_NS,
                    ended_wall_ns: now,
                    metric: "cpu".into(),
                    scope_entity_id: "host:a".into(),
                    score: 2.0,
                    created_wall_ns: now,
                    payload_json: "{}".into(),
                })),
            ])
            .expect("write");

        let retention = crate::store::retention::RetentionPolicy {
            raw_hours: 48,
            process_raw_hours: 24,
            rollup_1m_days: 14,
            rollup_1h_days: 90,
            incident_days: 180,
            log_days: 7,
            peak_hours: 72,
            max_db_bytes: u64::MAX,
            clock_ticks_per_second: 100,
        };
        let report =
            crate::store::retention::prune(&mut store, &retention, now, std::path::Path::new("."))
                .expect("prune");
        assert_eq!(report.deleted_peaks, 1, "report: {report:?}");
        let remaining = stored_document(
            store.connection(),
            Window::new(now - 100 * 60 * MINUTE_NS, now + MINUTE_NS),
            10,
        )
        .unwrap();
        assert_eq!(remaining.peak_count, 1);
    }
}
