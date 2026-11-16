//! High and low resource attribution windows from stored buckets.
//!
//! This module answers "what was happening, and which entities were associated with
//! it" for both unusually high **and** unusually low resource usage. It reports
//! observations and temporal associations only: contributors are "likely
//! contributors", logs are "temporal evidence", and nothing here claims that an
//! entity caused a spike or a drop.
//!
//! How a window is found:
//!
//! 1. [`query::buckets`] is called once for the requested window, producing host
//!    context plus ranked entity contributions per bucket.
//! 2. A per-metric series is built from the host side of each bucket
//!    (CPU percent of one core, memory bytes, PSI percent, load average). Buckets
//!    where the sample is missing are skipped, never treated as zero.
//! 3. The window baseline is the median of the finite samples. Metrics with fewer
//!    than six samples produce no windows.
//! 4. A high bucket must exceed `max(baseline * 1.35, baseline + absolute_delta)`;
//!    a low bucket must be at most `baseline * 0.65` **and** at least an absolute
//!    delta below the baseline. Runs allow one gap bucket and need at least two
//!    buckets, so a single noisy sample cannot become a window.
//! 5. Contributors are aggregated across the run, ranked by the metric's natural
//!    unit, and capped. Low windows rank ascending and say "usage below the window
//!    baseline" without ever implying that an entity was absent.
//!
//! Units are explicit and match [`crate::model::Metric`]: CPU and PSI percentages
//! are percent of **one core**, memory is bytes (rendered as MiB in evidence), I/O
//! is bytes observed in the window, and load is the raw 1-minute average.

use std::collections::BTreeMap;

use rusqlite::Connection;

use crate::config::Config;
use crate::error::Result;
use crate::model::{
    AttributionWindow, Contribution, EntityKind, EventKind, EventRecord, LogRecord, Metric,
    Severity, WindowKind,
};
use crate::store::query::{self, Bucket, EntityUsage, EventFilter, LogFilter, Window};

/// Minimum finite buckets before a metric may produce windows.
const MIN_BUCKETS: usize = 6;
/// Minimum matching buckets in a run (a single bucket is noise).
const MIN_RUN_BUCKETS: usize = 2;
/// High threshold factor over the median baseline.
const HIGH_FACTOR: f64 = 1.35;
/// Low threshold factor under the median baseline.
const LOW_FACTOR: f64 = 0.65;
/// Minimum absolute change for CPU and PSI, in percentage points.
const PERCENT_DELTA: f64 = 5.0;
/// Minimum absolute change for a high load window.
const LOAD_HIGH_DELTA: f64 = 1.0;
/// Minimum absolute change for a low load window.
const LOAD_LOW_DELTA: f64 = 0.5;
/// Minimum high memory change as a fraction of the baseline.
const MEMORY_HIGH_FRACTION: f64 = 0.05;
/// Minimum low memory change as a fraction of the baseline.
const MEMORY_LOW_FRACTION: f64 = 0.10;
/// Maximum ranked contributors kept per window.
const MAX_CONTRIBUTORS: usize = 10;
/// Base confidence for an association.
const CONFIDENCE_BASE: f64 = 0.5;
/// Confidence added per supporting bucket.
const CONFIDENCE_STEP: f64 = 0.1;
/// Confidence ceiling; never 1.0 because temporal association is not proof.
const CONFIDENCE_MAX: f64 = 0.9;
/// Confidence floor so weak associations are still visible.
const CONFIDENCE_FLOOR: f64 = 0.05;
/// Confidence reduction for missing host samples.
const MISSING_SAMPLE_PENALTY: f64 = 0.2;
/// Maximum evidence lines per window.
const MAX_EVIDENCE_LINES: usize = 16;
/// Maximum evidence lines per contributor.
const MAX_CONTRIBUTOR_EVIDENCE: usize = 6;
/// Maximum log sources named in one evidence line.
const MAX_LOG_SOURCES: usize = 8;
/// Bytes per MiB used for human-readable evidence.
const MIB: f64 = 1024.0 * 1024.0;

/// Small metadata fallback derived from the window-wide entity usage query.
#[derive(Debug, Clone)]
struct UsageMeta {
    /// Display name.
    name: String,
    /// Recognized tool.
    tool: Option<String>,
    /// Container id, when known.
    container: Option<String>,
}

impl UsageMeta {
    /// Copy the display fields we need from a usage row.
    fn from_usage(usage: &EntityUsage) -> Self {
        UsageMeta {
            name: usage.name.clone(),
            tool: usage.tool.clone(),
            container: usage.container.clone(),
        }
    }
}

/// Shared read-only inputs for one detection pass.
struct Context<'a> {
    /// Attribution buckets, ordered by start.
    buckets: &'a [Bucket],
    /// Raw host points (used for coverage and missing-data evidence).
    host_points: &'a [query::HostSeriesPoint],
    /// Events overlapping the requested window (bounded).
    events: &'a [EventRecord],
    /// Logs overlapping the requested window (bounded).
    logs: &'a [LogRecord],
    /// Window-wide entity metadata fallback.
    usage_meta: &'a BTreeMap<String, UsageMeta>,
    /// Number of buckets in the window (denominator for coverage).
    bucket_count: usize,
}

/// Accumulated contributor facts across the buckets of one run.
#[derive(Debug, Clone)]
struct Acc {
    /// Display name observed in the buckets.
    name: String,
    /// Entity kind.
    kind: EntityKind,
    /// Recognized tool, when known.
    tool: Option<String>,
    /// Container id, when known.
    container: Option<String>,
    /// Total CPU microseconds consumed in the run.
    cpu_usec: u64,
    /// Peak memory bytes observed in the run.
    memory_max: Option<u64>,
    /// Total storage bytes read in the run.
    io_read: u64,
    /// Total storage bytes written in the run.
    io_write: u64,
    /// Number of buckets in which the entity was observed.
    buckets: u32,
}

/// One contributor with its ranking value and share.
#[derive(Debug, Clone)]
struct Ranked {
    /// Entity id.
    entity_id: String,
    /// Accumulated facts.
    acc: Acc,
    /// Value in the ranking metric's natural unit.
    value: f64,
    /// Share of the run total, when the metric is additive.
    share: Option<f64>,
}

/// Detect high and low resource windows and their likely contributors.
///
/// Returns an empty vector when no buckets exist in the window: missing data is
/// **not** reported as zero activity. The returned windows are sorted by start,
/// deduplicated per metric/kind, and capped by `report.max_windows` with high
/// windows preferred over low ones and higher confidence preferred within a kind.
pub fn detect_windows(
    conn: &Connection,
    window: Window,
    config: &Config,
) -> Result<Vec<AttributionWindow>> {
    if window.is_empty() {
        return Ok(Vec::new());
    }
    let buckets = query::buckets(
        conn,
        window,
        bucket_span_ns(config),
        config.report.max_processes,
    )?;
    if buckets.is_empty() {
        return Ok(Vec::new());
    }
    let host_points = query::host_series(conn, window)?;
    let logs = query::logs(
        conn,
        &LogFilter {
            window: Some(window),
            limit: config.report.max_logs,
            ..LogFilter::default()
        },
    )?;
    let events = query::events(
        conn,
        &EventFilter {
            window: Some(window),
            limit: config.report.max_logs,
            ..EventFilter::default()
        },
    )?;
    let usage = query::entity_usage(conn, window)?;
    let usage_meta: BTreeMap<String, UsageMeta> = usage
        .iter()
        .map(|entry| (entry.entity_id.clone(), UsageMeta::from_usage(entry)))
        .collect();
    let context = Context {
        buckets: &buckets,
        host_points: &host_points,
        events: &events,
        logs: &logs,
        usage_meta: &usage_meta,
        bucket_count: buckets.len(),
    };
    let mut windows = Vec::new();
    for metric in [
        Metric::Cpu,
        Metric::Memory,
        Metric::PsiCpu,
        Metric::PsiMemory,
        Metric::PsiIo,
        Metric::Load,
    ] {
        windows.extend(detect_metric_windows(&context, metric));
    }
    Ok(finalize(windows, config.report.max_windows))
}

/// Logs recorded inside an attribution window, bounded by `limit`.
///
/// This is a convenience helper for reports that want the raw records behind the
/// evidence line; the window itself only stores evidence strings.
pub fn window_logs(
    conn: &Connection,
    window: &AttributionWindow,
    limit: usize,
) -> Result<Vec<LogRecord>> {
    let range = Window::new(window.start_wall_ns, window.end_wall_ns);
    query::logs(
        conn,
        &LogFilter {
            window: Some(range),
            limit: limit.max(1),
            ..LogFilter::default()
        },
    )
}

/// Detect high/low runs for one metric.
fn detect_metric_windows(context: &Context<'_>, metric: Metric) -> Vec<AttributionWindow> {
    let values = series_for_metric(context.buckets, metric);
    let finite: Vec<f64> = values.iter().filter_map(|value| *value).collect();
    if finite.len() < MIN_BUCKETS {
        return Vec::new();
    }
    let baseline = median(&finite);
    let finite_count = finite.len();
    let mut windows = Vec::new();
    for kind in [WindowKind::High, WindowKind::Low] {
        let predicate = |value: f64| match kind {
            WindowKind::High => is_high(metric, baseline, value),
            WindowKind::Low => is_low(metric, baseline, value),
        };
        for run in find_runs(&values, predicate) {
            if let Some(window) =
                build_window(context, metric, kind, &values, &run, baseline, finite_count)
            {
                windows.push(window);
            }
        }
    }
    windows
}

/// Build the per-bucket metric series from the host side of each bucket.
///
/// Missing values stay `None`; they are never coerced to zero.
fn series_for_metric(buckets: &[Bucket], metric: Metric) -> Vec<Option<f64>> {
    buckets
        .iter()
        .map(|bucket| match metric {
            Metric::Cpu => bucket.host.cpu_avg_pct,
            Metric::Memory => bucket.host.mem_used_avg.map(|bytes| bytes as f64),
            Metric::PsiCpu => bucket.host.psi_cpu_max,
            Metric::PsiMemory => bucket.host.psi_memory_max,
            Metric::PsiIo => bucket.host.psi_io_max,
            Metric::Load => bucket.host.load1_avg,
            _ => None,
        })
        .map(|value| value.filter(|value| value.is_finite()))
        .collect()
}

/// Turn one run of matching buckets into an [`AttributionWindow`].
fn build_window(
    context: &Context<'_>,
    metric: Metric,
    kind: WindowKind,
    values: &[Option<f64>],
    run: &[usize],
    baseline: f64,
    finite_count: usize,
) -> Option<AttributionWindow> {
    let first = *run.first()?;
    let last = *run.last()?;
    let start = context.buckets.get(first)?.start_wall_ns;
    let end = context.buckets.get(last)?.end_wall_ns;
    let value = run_value(values, run, kind)?;
    let run_seconds = end.saturating_sub(start) as f64 / 1e9;
    let change_pct = change_pct(metric, value, baseline);
    let contributors = build_contributors(context, metric, kind, run, start, end, run_seconds);
    let confidence = confidence_for(context, run.len(), finite_count);

    let mut evidence = Vec::new();
    push_bounded(
        &mut evidence,
        format!(
            "observed {} {} across {} buckets (window baseline {}, change {:+.1}%)",
            metric_label(metric),
            format_value(metric, value),
            run.len(),
            format_value(metric, baseline),
            change_pct
        ),
        MAX_EVIDENCE_LINES,
    );
    if kind == WindowKind::Low {
        push_bounded(
            &mut evidence,
            format!(
                "usage below the window baseline (observed {} vs baseline {}); entities below were present, not proven absent",
                format_value(metric, value),
                format_value(metric, baseline)
            ),
            MAX_EVIDENCE_LINES,
        );
    }
    push_host_evidence(&mut evidence, context, run);
    push_lifecycle_evidence(&mut evidence, context, start, end);
    push_log_evidence(&mut evidence, context, start, end);
    if finite_count < context.bucket_count {
        push_bounded(
            &mut evidence,
            format!(
                "{} of {} buckets had no sample for this metric (missing is not zero)",
                context.bucket_count - finite_count,
                context.bucket_count
            ),
            MAX_EVIDENCE_LINES,
        );
    }
    if context.host_points.is_empty() {
        push_bounded(
            &mut evidence,
            "no raw host samples in window; host context may be reconstructed from rollups"
                .to_string(),
            MAX_EVIDENCE_LINES,
        );
    }
    if !context.logs.is_empty() {
        push_bounded(
            &mut evidence,
            "correlated logs are temporal evidence, not proof of causation".to_string(),
            MAX_EVIDENCE_LINES,
        );
    }

    Some(AttributionWindow {
        start_wall_ns: start,
        end_wall_ns: end,
        kind,
        metric,
        value,
        baseline,
        change_pct,
        contributors,
        evidence,
        confidence,
    })
}

/// Aggregate and rank contributors for one run.
fn build_contributors(
    context: &Context<'_>,
    window_metric: Metric,
    kind: WindowKind,
    run: &[usize],
    start: i64,
    end: i64,
    run_seconds: f64,
) -> Vec<Contribution> {
    let rank_metric = contribution_metric(window_metric);
    let mut by_entity: BTreeMap<String, Acc> = BTreeMap::new();
    for &index in run {
        let Some(bucket) = context.buckets.get(index) else {
            continue;
        };
        for entity in &bucket.entities {
            let acc = by_entity
                .entry(entity.entity_id.clone())
                .or_insert_with(|| Acc {
                    name: entity.name.clone(),
                    kind: entity.kind,
                    tool: entity.tool.clone(),
                    container: entity.container.clone(),
                    cpu_usec: 0,
                    memory_max: None,
                    io_read: 0,
                    io_write: 0,
                    buckets: 0,
                });
            acc.cpu_usec = acc.cpu_usec.saturating_add(entity.cpu_usec);
            acc.memory_max = max_memory(acc.memory_max, entity.memory_max);
            acc.io_read = acc.io_read.saturating_add(entity.io_read);
            acc.io_write = acc.io_write.saturating_add(entity.io_write);
            acc.buckets = acc.buckets.saturating_add(1);
            if acc.name.is_empty() {
                acc.name = entity.name.clone();
            }
            if acc.tool.is_none() {
                acc.tool = entity.tool.clone();
            }
            if acc.container.is_none() {
                acc.container = entity.container.clone();
            }
        }
    }
    if by_entity.is_empty() {
        return Vec::new();
    }

    let mut ranked: Vec<Ranked> = by_entity
        .into_iter()
        .map(|(entity_id, acc)| {
            let value = contribution_value(&acc, rank_metric, run_seconds);
            Ranked {
                entity_id,
                acc,
                value,
                share: None,
            }
        })
        .collect();
    let total: f64 = ranked.iter().map(|item| item.value).sum();
    for item in &mut ranked {
        item.share = if total > 0.0 {
            Some((item.value * 100.0 / total).clamp(0.0, 100.0))
        } else {
            None
        };
    }
    ranked.sort_by(|a, b| {
        let ordering = b.value.total_cmp(&a.value);
        if kind == WindowKind::Low {
            ordering.reverse()
        } else {
            ordering
        }
    });
    ranked.truncate(MAX_CONTRIBUTORS);

    ranked
        .into_iter()
        .map(|item| {
            let evidence = contributor_evidence(context, &item, rank_metric, kind, start, end);
            let mut name = item.acc.name;
            let mut tool = item.acc.tool;
            let mut container = item.acc.container;
            if let Some(meta) = context.usage_meta.get(&item.entity_id) {
                if name.is_empty() || name == item.entity_id {
                    name = meta.name.clone();
                }
                if tool.is_none() {
                    tool = meta.tool.clone();
                }
                if container.is_none() {
                    container = meta.container.clone();
                }
            }
            Contribution {
                entity_id: item.entity_id,
                name,
                kind: item.acc.kind,
                tool,
                container,
                value: item.value,
                share_pct: item.share,
                evidence,
            }
        })
        .collect()
}

/// Evidence lines for one ranked contributor.
fn contributor_evidence(
    context: &Context<'_>,
    item: &Ranked,
    rank_metric: Metric,
    kind: WindowKind,
    start: i64,
    end: i64,
) -> Vec<String> {
    let mut evidence = Vec::new();
    match rank_metric {
        Metric::Memory => push_bounded(
            &mut evidence,
            format!(
                "peak RSS {:.1} MiB observed across {} buckets",
                item.value / MIB,
                item.acc.buckets
            ),
            MAX_CONTRIBUTOR_EVIDENCE,
        ),
        Metric::IoRead => push_bounded(
            &mut evidence,
            format!(
                "observed {:.1} MiB read across {} buckets (bytes in window)",
                item.value / MIB,
                item.acc.buckets
            ),
            MAX_CONTRIBUTOR_EVIDENCE,
        ),
        Metric::IoWrite => push_bounded(
            &mut evidence,
            format!(
                "observed {:.1} MiB written across {} buckets (bytes in window)",
                item.value / MIB,
                item.acc.buckets
            ),
            MAX_CONTRIBUTOR_EVIDENCE,
        ),
        _ => push_bounded(
            &mut evidence,
            format!(
                "observed {:.1}% CPU (percent of one core) across {} buckets",
                item.value, item.acc.buckets
            ),
            MAX_CONTRIBUTOR_EVIDENCE,
        ),
    }
    if kind == WindowKind::Low {
        push_bounded(
            &mut evidence,
            "usage below the window baseline".to_string(),
            MAX_CONTRIBUTOR_EVIDENCE,
        );
    }
    let container = item.acc.container.as_deref().or_else(|| {
        context
            .usage_meta
            .get(&item.entity_id)
            .and_then(|meta| meta.container.as_deref())
    });
    if item.acc.kind == EntityKind::Cgroup || container.is_some() {
        let target = container.unwrap_or(item.acc.name.as_str());
        push_bounded(
            &mut evidence,
            format!("cgroup/container {target} associated with this window"),
            MAX_CONTRIBUTOR_EVIDENCE,
        );
    }
    if let Some(tool) = &item.acc.tool {
        push_bounded(
            &mut evidence,
            format!("recognized tool: {tool}"),
            MAX_CONTRIBUTOR_EVIDENCE,
        );
    }
    let mut started = false;
    let mut ended = false;
    for event in context.events {
        if event.entity_id.as_deref() != Some(item.entity_id.as_str()) {
            continue;
        }
        if event.wall_ns < start || event.wall_ns >= end {
            continue;
        }
        match event.kind {
            EventKind::ProcessStarted | EventKind::ContainerStarted => started = true,
            EventKind::ProcessExited | EventKind::ContainerStopped => ended = true,
            _ => {}
        }
    }
    if started {
        push_bounded(
            &mut evidence,
            "started inside the window (observed lifecycle event)".to_string(),
            MAX_CONTRIBUTOR_EVIDENCE,
        );
    }
    if ended {
        push_bounded(
            &mut evidence,
            "ended inside the window (observed lifecycle event)".to_string(),
            MAX_CONTRIBUTOR_EVIDENCE,
        );
    }
    evidence
}

/// Host CPU/memory/PSI/load context computed from the buckets in the run.
fn push_host_evidence(evidence: &mut Vec<String>, context: &Context<'_>, run: &[usize]) {
    let mut cpu_sum = 0.0;
    let mut cpu_count = 0u64;
    let mut cpu_peak = 0.0f64;
    let mut mem_sum = 0u64;
    let mut mem_count = 0u64;
    let mut mem_peak = 0u64;
    let mut load_sum = 0.0;
    let mut load_count = 0u64;
    let mut load_peak = 0.0f64;
    let mut psi: [Option<f64>; 3] = [None; 3];
    for &index in run {
        let Some(bucket) = context.buckets.get(index) else {
            continue;
        };
        if let Some(cpu) = bucket.host.cpu_avg_pct {
            cpu_sum += cpu;
            cpu_count += 1;
        }
        if let Some(peak) = bucket.host.cpu_max_pct {
            cpu_peak = cpu_peak.max(peak);
        }
        if let Some(mem) = bucket.host.mem_used_avg {
            mem_sum = mem_sum.saturating_add(mem);
            mem_count += 1;
        }
        if let Some(peak) = bucket.host.mem_used_max {
            mem_peak = mem_peak.max(peak);
        }
        if let Some(load) = bucket.host.load1_avg {
            load_sum += load;
            load_count += 1;
            load_peak = load_peak.max(load);
        }
        let candidates = [
            bucket.host.psi_cpu_max,
            bucket.host.psi_memory_max,
            bucket.host.psi_io_max,
        ];
        for (slot, candidate) in psi.iter_mut().zip(candidates) {
            if let Some(value) = candidate {
                *slot = Some(match *slot {
                    Some(current) => current.max(value),
                    None => value,
                });
            }
        }
    }
    if cpu_count > 0 {
        let mean = cpu_sum / cpu_count as f64;
        push_bounded(
            evidence,
            format!("host CPU averaged {mean:.1}% (peak {cpu_peak:.1}%) of one core"),
            MAX_EVIDENCE_LINES,
        );
    }
    if mem_count > 0 {
        let mean = mem_sum as f64 / mem_count as f64;
        push_bounded(
            evidence,
            format!(
                "used memory averaged {:.1} MiB (peak {:.1} MiB)",
                mean / MIB,
                mem_peak as f64 / MIB
            ),
            MAX_EVIDENCE_LINES,
        );
    }
    for (index, slot) in psi.iter().enumerate() {
        if let Some(value) = slot {
            push_bounded(
                evidence,
                format!("{} pressure some max {value:.1}%", psi_label(index)),
                MAX_EVIDENCE_LINES,
            );
        }
    }
    if load_count > 0 {
        let mean = load_sum / load_count as f64;
        push_bounded(
            evidence,
            format!("host load average averaged {mean:.2} (peak {load_peak:.2})"),
            MAX_EVIDENCE_LINES,
        );
    }
}

/// Lifecycle event counts inside the window.
fn push_lifecycle_evidence(
    evidence: &mut Vec<String>,
    context: &Context<'_>,
    start: i64,
    end: i64,
) {
    let (starts, exits) = lifecycle_counts(context.events, start, end);
    if starts > 0 || exits > 0 {
        push_bounded(
            evidence,
            format!("{starts} process start events, {exits} exit events in window"),
            MAX_EVIDENCE_LINES,
        );
    }
}

/// Per-source log summary inside the window.
fn push_log_evidence(evidence: &mut Vec<String>, context: &Context<'_>, start: i64, end: i64) {
    let mut by_source: BTreeMap<&str, (usize, usize, usize)> = BTreeMap::new();
    for log in context.logs {
        if log.wall_ns < start || log.wall_ns >= end {
            continue;
        }
        let entry = by_source.entry(log.source_id.as_str()).or_insert((0, 0, 0));
        entry.2 += 1;
        if log.level.is_some_and(|level| level >= Severity::Error) {
            entry.0 += 1;
        } else if log.level == Some(Severity::Warn) {
            entry.1 += 1;
        }
    }
    if by_source.is_empty() {
        return;
    }
    let mut parts = Vec::new();
    for (source, (errors, warnings, total)) in by_source.iter().take(MAX_LOG_SOURCES) {
        let detail = if *errors > 0 {
            format!("{errors} error lines")
        } else if *warnings > 0 {
            format!("{warnings} warning lines")
        } else {
            format!("{total} lines")
        };
        parts.push(format!("{source} ({detail})"));
    }
    push_bounded(
        evidence,
        format!("log sources: {}", parts.join(", ")),
        MAX_EVIDENCE_LINES,
    );
}

/// Count process/container starts and exits inside `[start, end)`.
fn lifecycle_counts(events: &[EventRecord], start: i64, end: i64) -> (usize, usize) {
    let mut starts = 0;
    let mut exits = 0;
    for event in events {
        if event.wall_ns < start || event.wall_ns >= end {
            continue;
        }
        match event.kind {
            EventKind::ProcessStarted | EventKind::ContainerStarted => starts += 1,
            EventKind::ProcessExited | EventKind::ContainerStopped => exits += 1,
            _ => {}
        }
    }
    (starts, exits)
}

/// Metric used to rank contributors for a window metric.
fn contribution_metric(window_metric: Metric) -> Metric {
    match window_metric {
        Metric::Memory | Metric::PsiMemory => Metric::Memory,
        Metric::IoRead => Metric::IoRead,
        Metric::IoWrite => Metric::IoWrite,
        _ => Metric::Cpu,
    }
}

/// Ranking value of an entity in the run's natural unit.
fn contribution_value(acc: &Acc, rank_metric: Metric, run_seconds: f64) -> f64 {
    match rank_metric {
        Metric::Memory => acc.memory_max.unwrap_or(0) as f64,
        Metric::IoRead => acc.io_read as f64,
        Metric::IoWrite => acc.io_write as f64,
        _ => {
            if run_seconds > 0.0 {
                acc.cpu_usec as f64 * 100.0 / (run_seconds * 1_000_000.0)
            } else {
                0.0
            }
        }
    }
}

/// Peak-or-present memory merge.
fn max_memory(current: Option<u64>, incoming: Option<u64>) -> Option<u64> {
    match (current, incoming) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    }
}

/// Confidence in the association (never 1.0).
fn confidence_for(context: &Context<'_>, supporting: usize, finite_count: usize) -> f64 {
    let base = (CONFIDENCE_BASE + CONFIDENCE_STEP * supporting as f64).min(CONFIDENCE_MAX);
    let missing_fraction = if context.bucket_count == 0 {
        0.0
    } else {
        (1.0 - finite_count as f64 / context.bucket_count as f64).max(0.0)
    };
    let mut penalty = MISSING_SAMPLE_PENALTY * missing_fraction;
    if context.host_points.is_empty() {
        penalty += 0.1;
    }
    (base - penalty).clamp(CONFIDENCE_FLOOR, CONFIDENCE_MAX)
}

/// High threshold for a metric: relative factor plus an absolute minimum delta.
fn high_threshold(metric: Metric, baseline: f64) -> f64 {
    let delta = match metric {
        Metric::Memory => baseline * MEMORY_HIGH_FRACTION,
        Metric::Load => LOAD_HIGH_DELTA,
        _ => PERCENT_DELTA,
    };
    (baseline * HIGH_FACTOR).max(baseline + delta)
}

/// Whether a bucket is unusually high for the metric.
fn is_high(metric: Metric, baseline: f64, value: f64) -> bool {
    value > baseline && value >= high_threshold(metric, baseline)
}

/// Minimum absolute drop for a low window.
fn low_delta(metric: Metric, baseline: f64) -> f64 {
    match metric {
        Metric::Memory => baseline * MEMORY_LOW_FRACTION,
        Metric::Load => LOAD_LOW_DELTA,
        _ => PERCENT_DELTA,
    }
}

/// Whether a bucket is unusually low for the metric.
fn is_low(metric: Metric, baseline: f64, value: f64) -> bool {
    value < baseline
        && value <= baseline * LOW_FACTOR
        && baseline - value >= low_delta(metric, baseline)
}

/// Percent change from the baseline, signed (negative for low windows).
fn change_pct(metric: Metric, value: f64, baseline: f64) -> f64 {
    let epsilon = match metric {
        Metric::Memory => 1.0,
        Metric::Load => 0.01,
        _ => 0.1,
    };
    let denominator = baseline.abs().max(epsilon);
    (value - baseline) / denominator * 100.0
}

/// Median of a non-empty finite sample.
fn median(values: &[f64]) -> f64 {
    let mut sorted: Vec<f64> = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let middle = sorted.len() / 2;
    if sorted.len() % 2 == 0 {
        (sorted[middle - 1] + sorted[middle]) / 2.0
    } else {
        sorted[middle]
    }
}

/// Contiguous runs of matching buckets, allowing one gap bucket.
fn find_runs<F: Fn(f64) -> bool>(values: &[Option<f64>], predicate: F) -> Vec<Vec<usize>> {
    let mut runs = Vec::new();
    let mut current: Vec<usize> = Vec::new();
    for (index, value) in values.iter().enumerate() {
        let matches = value.is_some_and(|value| predicate(value));
        if !matches {
            continue;
        }
        if let Some(&last) = current.last() {
            if index - last > 2 {
                if current.len() >= MIN_RUN_BUCKETS {
                    runs.push(std::mem::take(&mut current));
                } else {
                    current.clear();
                }
            }
        }
        current.push(index);
    }
    if current.len() >= MIN_RUN_BUCKETS {
        runs.push(current);
    }
    runs
}

/// Window value: maximum for a high run, minimum for a low run.
fn run_value(values: &[Option<f64>], run: &[usize], kind: WindowKind) -> Option<f64> {
    let mut iter = run
        .iter()
        .filter_map(|&index| values.get(index).copied().flatten());
    let first = iter.next()?;
    Some(iter.fold(first, |accumulated, value| match kind {
        WindowKind::High => accumulated.max(value),
        WindowKind::Low => accumulated.min(value),
    }))
}

/// Drop overlapping windows of the same metric/kind, keeping the more confident.
fn dedupe(windows: Vec<AttributionWindow>) -> Vec<AttributionWindow> {
    let mut kept: Vec<AttributionWindow> = Vec::new();
    for candidate in windows {
        let existing = kept.iter().position(|window| {
            window.metric == candidate.metric
                && window.kind == candidate.kind
                && window.start_wall_ns < candidate.end_wall_ns
                && candidate.start_wall_ns < window.end_wall_ns
        });
        match existing {
            Some(index) if candidate.confidence > kept[index].confidence => {
                kept[index] = candidate;
            }
            Some(_) => {}
            None => kept.push(candidate),
        }
    }
    kept
}

/// Deduplicate, cap and sort windows for reporting.
fn finalize(mut windows: Vec<AttributionWindow>, max_windows: usize) -> Vec<AttributionWindow> {
    windows = dedupe(windows);
    windows.sort_by(|a, b| {
        kind_rank(a.kind)
            .cmp(&kind_rank(b.kind))
            .then_with(|| b.confidence.total_cmp(&a.confidence))
            .then_with(|| a.start_wall_ns.cmp(&b.start_wall_ns))
    });
    windows.truncate(max_windows.max(1));
    windows.sort_by_key(|window| window.start_wall_ns);
    windows
}

/// Sort key that prefers high windows over low ones when capping.
fn kind_rank(kind: WindowKind) -> u8 {
    if kind == WindowKind::High {
        0
    } else {
        1
    }
}

/// Human-readable metric label used in evidence.
fn metric_label(metric: Metric) -> &'static str {
    match metric {
        Metric::Cpu => "host CPU",
        Metric::Memory => "used memory",
        Metric::PsiCpu => "CPU pressure",
        Metric::PsiMemory => "memory pressure",
        Metric::PsiIo => "I/O pressure",
        Metric::Load => "host load average",
        _ => metric.as_str(),
    }
}

/// Format a value in the metric's natural unit.
fn format_value(metric: Metric, value: f64) -> String {
    match metric {
        Metric::Memory => format!("{:.1} MiB", value / MIB),
        Metric::Load => format!("{value:.2}"),
        _ => format!("{value:.1}%"),
    }
}

/// Label for the PSI slot index.
fn psi_label(index: usize) -> &'static str {
    match index {
        0 => "CPU",
        1 => "memory",
        _ => "I/O",
    }
}

/// Append an evidence line until the per-list limit is reached.
fn push_bounded(evidence: &mut Vec<String>, line: String, limit: usize) {
    if evidence.len() < limit {
        evidence.push(line);
    }
}

/// Attribution bucket span in nanoseconds from report configuration.
fn bucket_span_ns(config: &Config) -> i64 {
    let secs = config.report.bucket_secs.max(5);
    i64::try_from(secs.saturating_mul(1_000_000_000)).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        CpuTimes, Entity, EventRecord, HostSample, LoadAvg, LogRecord, LogStream, MemSnapshot,
    };
    use crate::store::{Store, WriteItem, WriteRecord};
    use crate::time::{ClockDomain, Stamps};

    const MINUTE_NS: i64 = 60 * 1_000_000_000;

    /// One synthetic host sampling interval.
    #[derive(Clone, Copy)]
    struct Interval {
        busy_ticks: u64,
        total_ticks: u64,
        used_memory: u64,
        load: f64,
    }

    fn interval(busy_ticks: u64, total_ticks: u64, used_memory: u64, load: f64) -> Interval {
        Interval {
            busy_ticks,
            total_ticks,
            used_memory,
            load,
        }
    }

    fn baseline_intervals(count: usize) -> Vec<Interval> {
        vec![interval(600, 6_000, 500_000, 0.4); count]
    }

    fn stamps(wall: i64) -> Stamps {
        Stamps::new(wall, wall, "boot-1", ClockDomain::Simulated)
    }

    fn host_sample(wall: i64, user: u64, idle: u64, used_memory: u64, load: f64) -> HostSample {
        HostSample {
            stamps: stamps(wall),
            cpu: CpuTimes {
                user,
                idle,
                ..CpuTimes::default()
            },
            mem: MemSnapshot {
                total: 1_000_000,
                available: Some(1_000_000 - used_memory),
                ..MemSnapshot::default()
            },
            load: LoadAvg {
                one: load,
                ..LoadAvg::default()
            },
            ..HostSample::default()
        }
    }

    fn seed_host(store: &mut Store, start_wall: i64, intervals: &[Interval]) {
        let first = intervals
            .first()
            .copied()
            .unwrap_or(interval(600, 6_000, 500_000, 0.4));
        let mut items = vec![WriteItem::normal(WriteRecord::HostSample(host_sample(
            start_wall,
            0,
            0,
            first.used_memory,
            first.load,
        )))];
        let mut user = 0u64;
        let mut idle = 0u64;
        let mut wall = start_wall;
        for step in intervals {
            wall += MINUTE_NS;
            user += step.busy_ticks;
            idle += step.total_ticks.saturating_sub(step.busy_ticks);
            items.push(WriteItem::normal(WriteRecord::HostSample(host_sample(
                wall,
                user,
                idle,
                step.used_memory,
                step.load,
            ))));
        }
        store.write(&items).expect("host samples");
    }

    fn bucket_starts(start_wall: i64, count: usize) -> Vec<i64> {
        (1..=count)
            .map(|index| start_wall + index as i64 * MINUTE_NS)
            .collect()
    }

    fn seed_cgroups(store: &mut Store, starts: &[i64], count: usize) {
        let mut items = Vec::new();
        for index in 0..count {
            items.push(WriteItem::normal(WriteRecord::Entity(Entity {
                entity_id: format!("cgroup:1:{}", 10 + index),
                kind: EntityKind::Cgroup,
                stable_key: format!("{}:1", 10 + index),
                name: format!("worker-{index}"),
                source: "test".to_string(),
                labels: [("container_id".to_string(), format!("container-{index}"))]
                    .into_iter()
                    .collect(),
                first_seen_wall_ns: 0,
                last_seen_wall_ns: 0,
            })));
        }
        store.write(&items).expect("entities");

        let mut sql = String::new();
        for index in 0..count {
            let cpu_usec = 1_000_000u64.saturating_sub(index as u64 * 50_000);
            for start in starts {
                sql.push_str(&format!(
                    "INSERT INTO rollup_1m(bucket_wall_ns, entity_id, entity_kind, sample_count, \
                     cpu_total_usec, memory_max_bytes, io_read_bytes, io_write_bytes) \
                     VALUES ({start}, 'cgroup:1:{}', 'cgroup', 12, {cpu_usec}, 4194304, 1024, 2048);\n",
                    10 + index
                ));
            }
        }
        store
            .connection_mut()
            .execute_batch(&sql)
            .expect("rollup rows");
    }

    fn window_for(start_wall: i64, intervals: usize) -> Window {
        Window::new(
            start_wall,
            start_wall + (intervals as i64 + 1) * MINUTE_NS + 1,
        )
    }

    #[test]
    fn detects_one_high_cpu_window_with_ranked_contributors() {
        let start_wall = 72_000_000_000_000;
        let mut intervals = baseline_intervals(12);
        for step in &mut intervals[4..7] {
            *step = interval(3_000, 6_000, 900_000, 5.0);
        }
        let mut store = Store::open_in_memory().expect("store");
        seed_host(&mut store, start_wall, &intervals);
        let starts = bucket_starts(start_wall, intervals.len());
        seed_cgroups(&mut store, &starts, 12);
        let spike_wall = start_wall + 6 * MINUTE_NS;
        store
            .write(&[
                WriteItem::normal(WriteRecord::Log(LogRecord {
                    wall_ns: spike_wall,
                    mono_ns: None,
                    source_id: "nginx-error".to_string(),
                    entity_id: None,
                    stream: LogStream::File,
                    level: Some(Severity::Error),
                    message: "upstream timed out".to_string(),
                    truncated: false,
                    incident_id: None,
                    redacted: false,
                })),
                WriteItem::normal(WriteRecord::Event(EventRecord {
                    wall_ns: spike_wall,
                    mono_ns: None,
                    entity_id: Some("cgroup:1:10".to_string()),
                    kind: EventKind::ContainerStarted,
                    severity: Severity::Info,
                    payload: serde_json::json!({"container": "container-0"}),
                    provenance: "test".to_string(),
                    lost_before: 0,
                })),
            ])
            .expect("logs and events");

        let config = Config::default();
        let window = window_for(start_wall, intervals.len());
        let windows = detect_windows(store.connection(), window, &config).expect("windows");
        assert!(!windows.is_empty(), "window must be detected");

        let cpu_windows: Vec<&AttributionWindow> = windows
            .iter()
            .filter(|window| window.metric == Metric::Cpu && window.kind == WindowKind::High)
            .collect();
        assert_eq!(cpu_windows.len(), 1, "one CPU window: {cpu_windows:?}");
        let cpu = cpu_windows[0];
        assert_eq!(cpu.start_wall_ns, start_wall + 5 * MINUTE_NS);
        assert_eq!(cpu.end_wall_ns, start_wall + 8 * MINUTE_NS);
        assert!(
            (cpu.baseline - 10.0).abs() < 1.0,
            "baseline {}",
            cpu.baseline
        );
        assert!(cpu.value > 45.0 && cpu.value <= 55.0, "value {}", cpu.value);
        assert!(cpu.change_pct > 100.0, "change {}", cpu.change_pct);
        assert!(
            cpu.confidence > 0.5 && cpu.confidence < 1.0,
            "confidence {}",
            cpu.confidence
        );
        assert_eq!(cpu.contributors.len(), MAX_CONTRIBUTORS);
        assert_eq!(cpu.contributors[0].name, "worker-0");
        assert_eq!(
            cpu.contributors[0].container.as_deref(),
            Some("container-0")
        );
        assert!(cpu.contributors[0]
            .share_pct
            .is_some_and(|share| share > 5.0));
        assert!(cpu.evidence.iter().any(|line| line.contains("of one core")));
        assert!(cpu.evidence.iter().any(|line| line.contains("nginx-error")));
        assert!(cpu.contributors.iter().any(|contributor| contributor
            .evidence
            .iter()
            .any(|line| line.contains("started inside the window"))));
        assert!(
            windows.iter().all(|window| window.metric != Metric::PsiCpu),
            "absent PSI must not become zero-activity windows"
        );

        let logs = window_logs(store.connection(), cpu, 10).expect("window logs");
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].source_id, "nginx-error");
    }

    #[test]
    fn detects_a_low_cpu_window_when_values_drop() {
        let start_wall = 72_000_000_000_000;
        let mut intervals = vec![interval(2_400, 6_000, 500_000, 0.4); 12];
        for step in &mut intervals[5..8] {
            *step = interval(120, 6_000, 500_000, 0.4);
        }
        let mut store = Store::open_in_memory().expect("store");
        seed_host(&mut store, start_wall, &intervals);
        let starts = bucket_starts(start_wall, intervals.len());
        seed_cgroups(&mut store, &starts, 2);

        let config = Config::default();
        let windows = detect_windows(
            store.connection(),
            window_for(start_wall, intervals.len()),
            &config,
        )
        .expect("windows");
        let cpu_windows: Vec<&AttributionWindow> = windows
            .iter()
            .filter(|window| window.metric == Metric::Cpu)
            .collect();
        assert_eq!(cpu_windows.len(), 1, "windows: {cpu_windows:?}");
        let low = cpu_windows[0];
        assert_eq!(low.kind, WindowKind::Low);
        assert!(low.change_pct < -50.0, "change {}", low.change_pct);
        assert!(low.value <= 5.0, "value {}", low.value);
        assert!(low.baseline > 35.0);
        assert!(!low.contributors.is_empty());
        assert_eq!(low.contributors[0].name, "worker-1", "low ranks ascending");
        assert!(low
            .evidence
            .iter()
            .any(|line| line.contains("usage below the window baseline")));
        assert!(low.contributors.iter().all(|contributor| contributor
            .evidence
            .iter()
            .any(|line| line.contains("usage below the window baseline"))));
    }

    #[test]
    fn empty_database_produces_no_windows() {
        let store = Store::open_in_memory().expect("store");
        let config = Config::default();
        let windows = detect_windows(
            store.connection(),
            Window::new(0, 3_600_000_000_000),
            &config,
        )
        .expect("empty windows");
        assert!(windows.is_empty(), "no data must not become zero activity");
    }

    #[test]
    fn max_windows_caps_and_prefers_high_windows() {
        let start_wall = 72_000_000_000_000;
        let mut intervals = baseline_intervals(12);
        for step in &mut intervals[4..7] {
            *step = interval(3_000, 6_000, 900_000, 5.0);
        }
        let mut store = Store::open_in_memory().expect("store");
        seed_host(&mut store, start_wall, &intervals);
        let mut config = Config::default();
        config.report.max_windows = 1;
        let windows = detect_windows(
            store.connection(),
            window_for(start_wall, intervals.len()),
            &config,
        )
        .expect("windows");
        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0].kind, WindowKind::High);
    }

    #[test]
    fn missing_metric_samples_are_skipped_not_zeroed() {
        let start_wall = 72_000_000_000_000;
        let mut store = Store::open_in_memory().expect("store");
        seed_host(&mut store, start_wall, &baseline_intervals(12));
        let config = Config::default();
        let windows = detect_windows(store.connection(), window_for(start_wall, 12), &config)
            .expect("windows");
        assert!(
            windows.is_empty(),
            "a flat baseline must not create high or low windows"
        );
    }
}
