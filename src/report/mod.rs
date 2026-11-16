//! Self-contained offline HTML forensic report.
//!
//! Data assembly and rendering are deliberately separate: [`build`] turns a bounded
//! set of database queries into [`ReportDocument`], and [`render_html`] embeds it in
//! one template with inline CSS/JS. Nothing is fetched at render or view time, and the
//! report is never generated in the daemon's sampling path.
//!
//! Untrusted strings are only ever inserted into HTML through escaped JSON plus
//! `textContent` in the viewer. The JSON block additionally escapes `<`, `>`, `&`,
//! U+2028 and U+2029 so a log line cannot terminate the script element.

use std::path::Path;

use serde::Serialize;

use crate::analysis::correlation;
use crate::config::Config;
use crate::error::{Error, Result};
use crate::model::{AttributionWindow, CollectorHealth, Incident, LogRecord, Metric, WindowKind};
use crate::store::query::{self, EventFilter, LogFilter, Window};
use crate::time::{format_wall_rfc3339, Clock, SystemClock};
use crate::{PRODUCT, PRODUCT_LONG, VERSION};

const TEMPLATE: &str = include_str!("assets/template.html");
const STYLE: &str = include_str!("assets/style.css");
const SCRIPT: &str = include_str!("assets/app.js");

/// Hard cap for a generated report artifact.
pub const MAX_REPORT_BYTES: usize = 64 * 1024 * 1024;

/// Report scope and filters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportOptions {
    /// Half-open wall-clock window.
    pub window: Window,
    /// Restrict evidence to one incident.
    pub incident_id: Option<i64>,
    /// Restrict the process tree to one process instance (and its ancestors).
    pub process_id: Option<String>,
    /// Restrict ranked entities and process nodes to a service/tool/container label.
    pub service: Option<String>,
}

impl ReportOptions {
    /// Options for a plain window.
    pub const fn window(window: Window) -> Self {
        Self {
            window,
            incident_id: None,
            process_id: None,
            service: None,
        }
    }
}

/// Versioned report payload embedded as JSON.
#[derive(Debug, Clone, Serialize)]
pub struct ReportDocument {
    /// Report identity and window.
    pub meta: ReportMeta,
    /// Headline aggregates.
    pub summary: ReportSummary,
    /// Downsampled host series.
    pub series: SeriesData,
    /// High/low attribution windows.
    pub windows: Vec<WindowView>,
    /// Ranked contributors by metric.
    pub top: TopContributors,
    /// Process tree and lifetimes.
    pub processes: ProcessTreeView,
    /// Incidents overlapping the window.
    pub incidents: Vec<IncidentView>,
    /// Stored log evidence.
    pub logs: Vec<LogView>,
    /// Lifecycle events.
    pub events: Vec<EventView>,
    /// Collection coverage, gaps and integrations.
    pub coverage: CoverageView,
}

/// Report metadata.
#[derive(Debug, Clone, Serialize)]
pub struct ReportMeta {
    /// Display title.
    pub title: String,
    /// Product name.
    pub product: String,
    /// Build version.
    pub version: String,
    /// Generation timestamp (RFC3339).
    pub generated: String,
    /// Window start (RFC3339).
    pub since: String,
    /// Window end (RFC3339).
    pub until: String,
    /// Window length in seconds.
    pub window_secs: f64,
    /// Hostname when stored.
    pub hostname: Option<String>,
    /// Boot id when stored.
    pub boot_id: Option<String>,
    /// Kernel release when stored.
    pub kernel: Option<String>,
    /// Architecture when stored.
    pub architecture: Option<String>,
    /// Whether the latest run used fixture/simulated collection.
    pub simulated: bool,
    /// Unit and interpretation note.
    pub units_note: String,
}

/// Headline aggregates.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ReportSummary {
    /// Average host CPU, percent of one core.
    pub host_cpu_avg_pct: Option<f64>,
    /// Peak host CPU, percent of one core.
    pub host_cpu_max_pct: Option<f64>,
    /// Peak used memory bytes.
    pub host_mem_used_max_bytes: Option<u64>,
    /// Installed memory bytes.
    pub host_mem_total_bytes: Option<u64>,
    /// Peak CPU pressure, percent.
    pub psi_cpu_max: Option<f64>,
    /// Peak memory pressure, percent.
    pub psi_memory_max: Option<f64>,
    /// Peak I/O pressure, percent.
    pub psi_io_max: Option<f64>,
    /// Incidents overlapping the window.
    pub incident_count: u64,
    /// Attribution windows detected.
    pub window_count: u64,
    /// Process lifetimes overlapping the window.
    pub process_count: u64,
    /// Stored logs in the window.
    pub log_count: u64,
    /// Events in the window.
    pub event_count: u64,
    /// `ok`, `partial` or `degraded`.
    pub coverage: String,
}

/// Parallel host series, peak-preserving downsampled.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SeriesData {
    /// Sample wall-clock nanoseconds.
    pub timestamps: Vec<i64>,
    /// CPU percent of one core.
    pub cpu_pct: Vec<Option<f64>>,
    /// Used memory percent.
    pub mem_pct: Vec<Option<f64>>,
    /// Used memory bytes.
    pub mem_used_bytes: Vec<Option<u64>>,
    /// CPU pressure `some`.
    pub psi_cpu: Vec<Option<f64>>,
    /// Memory pressure `some`.
    pub psi_memory: Vec<Option<f64>>,
    /// I/O pressure `some`.
    pub psi_io: Vec<Option<f64>>,
    /// 1-minute load.
    pub load1: Vec<Option<f64>>,
    /// Network receive bytes/second.
    pub net_rx_bps: Vec<Option<f64>>,
    /// Network transmit bytes/second.
    pub net_tx_bps: Vec<Option<f64>>,
    /// Disk read bytes/second.
    pub disk_read_bps: Vec<Option<f64>>,
    /// Disk write bytes/second.
    pub disk_write_bps: Vec<Option<f64>>,
}

/// One attribution window plus its bounded evidence.
#[derive(Debug, Clone, Serialize)]
pub struct WindowView {
    /// Start wall clock.
    pub start: i64,
    /// End wall clock.
    pub end: i64,
    /// `high` or `low`.
    pub kind: String,
    /// Triggering metric.
    pub metric: String,
    /// Window value.
    pub value: f64,
    /// Window baseline.
    pub baseline: f64,
    /// Change versus baseline, percent.
    pub change_pct: f64,
    /// Association confidence, 0..1.
    pub confidence: f64,
    /// Ranked contributors.
    pub contributors: Vec<ContributionView>,
    /// Evidence bullets.
    pub evidence: Vec<String>,
    /// Correlated logs inside the window.
    pub logs: Vec<LogView>,
    /// Lifecycle events inside the window.
    pub events: Vec<EventView>,
}

/// One ranked contributor.
#[derive(Debug, Clone, Serialize)]
pub struct ContributionView {
    /// Entity id.
    pub entity_id: String,
    /// Display name.
    pub name: String,
    /// Entity kind.
    pub kind: String,
    /// Recognized tool.
    pub tool: Option<String>,
    /// Metric value in its natural unit.
    pub value: f64,
    /// Share of the window total, percent.
    pub share_pct: Option<f64>,
    /// Evidence lines.
    pub evidence: Vec<String>,
}

/// Ranked contributors by metric.
#[derive(Debug, Clone, Default, Serialize)]
pub struct TopContributors {
    /// CPU ranking.
    pub cpu: Vec<UsageRow>,
    /// Memory ranking.
    pub memory: Vec<UsageRow>,
    /// I/O ranking.
    pub io: Vec<UsageRow>,
    /// Network ranking.
    pub network: Vec<UsageRow>,
}

/// One aggregated entity row.
#[derive(Debug, Clone, Serialize)]
pub struct UsageRow {
    /// Entity id.
    pub entity_id: String,
    /// Entity kind.
    pub kind: String,
    /// Display name.
    pub name: String,
    /// Recognized tool.
    pub tool: Option<String>,
    /// Role label.
    pub role: Option<String>,
    /// Container id/name.
    pub container: Option<String>,
    /// Average CPU, percent of one core.
    pub cpu_avg_pct: Option<f64>,
    /// Peak CPU, percent of one core.
    pub cpu_max_pct: Option<f64>,
    /// Total CPU microseconds.
    pub cpu_total_usec: Option<u64>,
    /// Average memory bytes.
    pub memory_avg_bytes: Option<u64>,
    /// Peak memory bytes.
    pub memory_max_bytes: Option<u64>,
    /// Storage read bytes.
    pub io_read_bytes: Option<u64>,
    /// Storage write bytes.
    pub io_write_bytes: Option<u64>,
    /// Network receive bytes.
    pub net_rx_bytes: Option<u64>,
    /// Network transmit bytes.
    pub net_tx_bytes: Option<u64>,
    /// Source coverage nanoseconds.
    pub covered_ns: i64,
    /// Source sample rows.
    pub sample_count: u64,
}

/// Process tree view.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ProcessTreeView {
    /// Bounded nodes.
    pub nodes: Vec<ProcessNodeView>,
    /// Total lifetimes overlapping the window.
    pub total: u64,
}

/// One process lifetime node.
#[derive(Debug, Clone, Serialize)]
pub struct ProcessNodeView {
    /// Process entity id.
    pub id: String,
    /// Parent entity id when visible in the same result set.
    pub parent_id: Option<String>,
    /// Host PID.
    pub pid: u32,
    /// Command name.
    pub comm: String,
    /// Executable path.
    pub executable: Option<String>,
    /// Recognized tool.
    pub tool: Option<String>,
    /// Role label.
    pub role: Option<String>,
    /// systemd unit.
    pub unit: Option<String>,
    /// Container.
    pub container: Option<String>,
    /// Session label.
    pub session: Option<String>,
    /// Start wall clock.
    pub start: i64,
    /// End wall clock; `None` while alive or when the exit was missed.
    pub end: Option<i64>,
    /// End reason.
    pub end_reason: Option<String>,
}

/// One incident row.
#[derive(Debug, Clone, Serialize)]
pub struct IncidentView {
    /// Incident id.
    pub id: i64,
    /// Start wall clock.
    pub start: i64,
    /// End wall clock.
    pub end: Option<i64>,
    /// Entity.
    pub entity_id: Option<String>,
    /// Metric.
    pub metric: String,
    /// Reason.
    pub reason: String,
    /// Peak.
    pub peak: f64,
    /// Baseline.
    pub baseline: f64,
    /// Acknowledged.
    pub acknowledged: bool,
    /// Evidence loss marker.
    pub evidence_loss: bool,
}

/// One log row.
#[derive(Debug, Clone, Serialize)]
pub struct LogView {
    /// Wall clock.
    pub wall: i64,
    /// Source id.
    pub source_id: String,
    /// Entity.
    pub entity_id: Option<String>,
    /// Level.
    pub level: Option<String>,
    /// Bounded message.
    pub message: String,
    /// Truncation marker.
    pub truncated: bool,
}

/// One event row.
#[derive(Debug, Clone, Serialize)]
pub struct EventView {
    /// Wall clock.
    pub wall: i64,
    /// Event kind.
    pub kind: String,
    /// Severity.
    pub severity: String,
    /// Entity.
    pub entity_id: Option<String>,
    /// Provenance.
    pub provenance: String,
}

/// Coverage section.
#[derive(Debug, Clone, Default, Serialize)]
pub struct CoverageView {
    /// Collector health.
    pub collectors: Vec<CollectorView>,
    /// Integration state.
    pub integrations: Vec<IntegrationView>,
    /// Known gaps.
    pub gaps: Vec<GapView>,
}

/// One collector row.
#[derive(Debug, Clone, Serialize)]
pub struct CollectorView {
    /// Collector id.
    pub id: String,
    /// Configured state.
    pub configured: String,
    /// Availability.
    pub availability: String,
    /// Permission outcome.
    pub permission: String,
    /// Last success.
    pub last_success: Option<i64>,
    /// Last error.
    pub last_error: Option<String>,
    /// Received.
    pub received: u64,
    /// Persisted.
    pub persisted: u64,
    /// Dropped.
    pub dropped: u64,
    /// Truncated.
    pub truncated: u64,
    /// Queue high-water.
    pub queue_high_water: u64,
}

/// One integration row.
#[derive(Debug, Clone, Serialize)]
pub struct IntegrationView {
    /// Integration id.
    pub id: String,
    /// Configured state.
    pub configured: String,
    /// Detected state.
    pub detected: String,
    /// Version.
    pub version: Option<String>,
    /// Capability names.
    pub capabilities: Vec<String>,
    /// Last error.
    pub last_error: Option<String>,
}

/// One coverage gap.
#[derive(Debug, Clone, Serialize)]
pub struct GapView {
    /// Source.
    pub source_id: String,
    /// Gap kind.
    pub kind: String,
    /// Detail.
    pub detail: String,
    /// Since.
    pub since: Option<i64>,
    /// Resolved.
    pub resolved: Option<i64>,
}

/// Build a report document from one consistent window.
pub fn build(
    conn: &rusqlite::Connection,
    config: &Config,
    options: &ReportOptions,
) -> Result<ReportDocument> {
    let mut window = options.window;
    let incident_filter = options.incident_id;
    if let Some(incident_id) = options.incident_id {
        let incident = query::incident(conn, incident_id)?
            .ok_or_else(|| Error::Storage(format!("incident {incident_id} not found")))?;
        let end = incident
            .ended_wall_ns
            .unwrap_or_else(|| incident.started_wall_ns.saturating_add(300_000_000_000));
        window = Window::new(
            incident.started_wall_ns.saturating_sub(60_000_000_000),
            end.saturating_add(30_000_000_000),
        );
    }

    let stats = query::db_stats(conn)?;
    let counts = query::window_counts(conn, window)?;
    let host_points = query::host_series(conn, window)?;
    let sampled = downsample(&host_points, config.report.max_points);
    let mut summary = summarize(&sampled, &counts, conn, window)?;
    let series = series_data(&sampled);
    let usage = query::entity_usage(conn, window)?;
    let mut usage = usage;
    if let Some(service) = &options.service {
        let needle = service.to_ascii_lowercase();
        usage.retain(|row| {
            row.name.to_ascii_lowercase().contains(&needle)
                || row
                    .tool
                    .as_deref()
                    .is_some_and(|tool| tool.to_ascii_lowercase().contains(&needle))
                || row
                    .container
                    .as_deref()
                    .is_some_and(|container| container.to_ascii_lowercase().contains(&needle))
        });
    }
    let top = top_contributors(usage, config.report.max_processes);

    let mut windows = correlation::detect_windows(conn, window, config)?;
    if options.process_id.is_some() || options.service.is_some() {
        windows.retain(|window| {
            window.contributors.iter().any(|contributor| {
                options
                    .process_id
                    .as_ref()
                    .is_some_and(|id| &contributor.entity_id == id)
                    || options.service.as_ref().is_some_and(|service| {
                        contributor
                            .name
                            .to_ascii_lowercase()
                            .contains(&service.to_ascii_lowercase())
                            || contributor.tool.as_deref().is_some_and(|tool| {
                                tool.to_ascii_lowercase()
                                    .contains(&service.to_ascii_lowercase())
                            })
                    })
            })
        });
    }
    let windows = window_views(conn, &windows, &window)?;
    summary.window_count = windows.len() as u64;

    let mut nodes = process_nodes(conn, window, config.report.max_process_tree_nodes)?;
    if let Some(process_id) = &options.process_id {
        nodes.nodes.retain(|node| &node.id == process_id);
        // Keep the selected node's ancestors for context.
        let mut needed: Vec<String> = nodes
            .nodes
            .iter()
            .filter_map(|node| node.parent_id.clone())
            .collect();
        let mut guard = 0;
        while let Some(parent) = needed.pop() {
            guard += 1;
            if guard > 1000 || nodes.nodes.iter().any(|node| node.id == parent) {
                continue;
            }
            if let Some(row) = nodes
                .nodes
                .iter()
                .find(|node| node.parent_id.as_deref() == Some(parent.as_str()))
            {
                needed.push(row.id.clone());
            }
        }
    }
    if let Some(service) = &options.service {
        let needle = service.to_ascii_lowercase();
        nodes.nodes.retain(|node| {
            node.comm.to_ascii_lowercase().contains(&needle)
                || node
                    .tool
                    .as_deref()
                    .is_some_and(|tool| tool.to_ascii_lowercase().contains(&needle))
                || node
                    .container
                    .as_deref()
                    .is_some_and(|container| container.to_ascii_lowercase().contains(&needle))
        });
    }

    let incidents = query::incidents(conn, window, 200)?
        .into_iter()
        .map(incident_view)
        .collect();

    let mut log_filter = LogFilter::new(window);
    log_filter.limit = config.report.max_logs;
    log_filter.incident_id = incident_filter;
    let mut logs: Vec<LogRecord> = query::logs(conn, &log_filter)?;
    logs.sort_by_key(|record| record.wall_ns);

    let mut event_filter = EventFilter {
        window: Some(window),
        limit: config.report.max_logs,
        ..Default::default()
    };
    event_filter.kinds.clear();
    let mut events = query::events(conn, &event_filter)?;
    events.sort_by_key(|event| event.wall_ns);

    let coverage = coverage_view(conn)?;
    let coverage_status = if coverage.collectors.is_empty()
        || coverage
            .collectors
            .iter()
            .any(|collector| collector.availability == "unavailable")
    {
        "partial"
    } else if coverage
        .collectors
        .iter()
        .any(|collector| collector.dropped > 0)
    {
        "degraded"
    } else {
        "ok"
    };

    let now = SystemClock::new().wall_ns();
    let latest_run = query::runs(conn, 1)?.into_iter().next();
    Ok(ReportDocument {
        meta: ReportMeta {
            title: config.report.title.clone(),
            product: PRODUCT.to_string(),
            version: VERSION.to_string(),
            generated: format_wall_rfc3339(now),
            since: format_wall_rfc3339(window.since),
            until: format_wall_rfc3339(window.until),
            window_secs: window.duration_secs(),
            hostname: stats.hostname,
            boot_id: stats.boot_id,
            kernel: stats.kernel_release,
            architecture: stats.architecture,
            simulated: latest_run.is_some_and(|run| run.simulated),
            units_note: "CPU and PSI are percent of one logical core. Memory is bytes (IEC display). Timeline rates are bytes per second; tables show totals. Unavailable values are omitted, never zero. Evidence is a temporal association only; causation is not implied.".to_string(),
        },
        summary: ReportSummary {
            coverage: coverage_status.to_string(),
            ..summary
        },
        series,
        windows,
        top,
        processes: nodes,
        incidents,
        logs: logs.into_iter().map(log_view).collect(),
        events: events.into_iter().map(event_view).collect(),
        coverage,
    })
}

fn summarize(
    points: &[query::HostSeriesPoint],
    counts: &query::WindowCounts,
    conn: &rusqlite::Connection,
    window: Window,
) -> Result<ReportSummary> {
    let cpu: Vec<f64> = points
        .iter()
        .filter_map(|point| finite(point.cpu_pct))
        .collect();
    let avg = if cpu.is_empty() {
        None
    } else {
        Some(cpu.iter().sum::<f64>() / cpu.len() as f64)
    };
    let max = cpu.iter().copied().reduce(f64::max);
    Ok(ReportSummary {
        host_cpu_avg_pct: avg,
        host_cpu_max_pct: max,
        host_mem_used_max_bytes: points.iter().filter_map(|point| point.mem_used_bytes).max(),
        host_mem_total_bytes: query::host_mem_total(conn, window)?,
        psi_cpu_max: points
            .iter()
            .filter_map(|point| finite(point.psi_cpu))
            .reduce(f64::max),
        psi_memory_max: points
            .iter()
            .filter_map(|point| finite(point.psi_memory))
            .reduce(f64::max),
        psi_io_max: points
            .iter()
            .filter_map(|point| finite(point.psi_io))
            .reduce(f64::max),
        incident_count: counts.incidents,
        window_count: 0,
        process_count: counts.processes,
        log_count: counts.logs,
        event_count: counts.events,
        coverage: String::new(),
    })
}

fn series_data(points: &[query::HostSeriesPoint]) -> SeriesData {
    SeriesData {
        timestamps: points.iter().map(|point| point.wall_ns).collect(),
        cpu_pct: points.iter().map(|point| finite(point.cpu_pct)).collect(),
        mem_pct: points.iter().map(|point| finite(point.mem_pct)).collect(),
        mem_used_bytes: points.iter().map(|point| point.mem_used_bytes).collect(),
        psi_cpu: points.iter().map(|point| finite(point.psi_cpu)).collect(),
        psi_memory: points
            .iter()
            .map(|point| finite(point.psi_memory))
            .collect(),
        psi_io: points.iter().map(|point| finite(point.psi_io)).collect(),
        load1: points.iter().map(|point| finite(point.load1)).collect(),
        net_rx_bps: points
            .iter()
            .map(|point| finite(point.net_rx_bps))
            .collect(),
        net_tx_bps: points
            .iter()
            .map(|point| finite(point.net_tx_bps))
            .collect(),
        disk_read_bps: points
            .iter()
            .map(|point| finite(point.disk_read_bps))
            .collect(),
        disk_write_bps: points
            .iter()
            .map(|point| finite(point.disk_write_bps))
            .collect(),
    }
}

/// Peak-preserving downsample: each chunk is represented by its highest CPU point.
fn downsample(points: &[query::HostSeriesPoint], max_points: usize) -> Vec<query::HostSeriesPoint> {
    let max_points = max_points.max(2);
    if points.len() <= max_points {
        return points.to_vec();
    }
    let chunk = points.len().div_ceil(max_points);
    let mut out = Vec::with_capacity(max_points + 1);
    for chunk_points in points.chunks(chunk) {
        let best = chunk_points
            .iter()
            .max_by(|left, right| {
                finite(left.cpu_pct)
                    .unwrap_or(-1.0)
                    .partial_cmp(&finite(right.cpu_pct).unwrap_or(-1.0))
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .unwrap_or(&chunk_points[0]);
        out.push(best.clone());
    }
    if let Some(last) = points.last() {
        if out.last().map(|point| point.wall_ns) != Some(last.wall_ns) {
            out.push(last.clone());
        }
    }
    out.truncate(max_points);
    out
}

fn top_contributors(usage: Vec<query::EntityUsage>, limit: usize) -> TopContributors {
    let limit = limit.max(1);
    let mut cpu = usage.clone();
    cpu.retain(|row| row.metric_value(Metric::Cpu) > 0.0);
    cpu.sort_by(|left, right| {
        right
            .metric_value(Metric::Cpu)
            .partial_cmp(&left.metric_value(Metric::Cpu))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    cpu.truncate(limit);

    let mut memory = usage.clone();
    memory.retain(|row| row.metric_value(Metric::Memory) > 0.0);
    memory.sort_by(|left, right| {
        right
            .metric_value(Metric::Memory)
            .partial_cmp(&left.metric_value(Metric::Memory))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    memory.truncate(limit);

    let mut io = usage.clone();
    io.retain(|row| io_total(row) > 0.0);
    io.sort_by(|left, right| {
        io_total(right)
            .partial_cmp(&io_total(left))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    io.truncate(limit);

    let mut network = usage;
    network.retain(|row| network_total(row) > 0.0);
    network.sort_by(|left, right| {
        network_total(right)
            .partial_cmp(&network_total(left))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    network.truncate(limit);

    TopContributors {
        cpu: cpu.into_iter().map(usage_row).collect(),
        memory: memory.into_iter().map(usage_row).collect(),
        io: io.into_iter().map(usage_row).collect(),
        network: network.into_iter().map(usage_row).collect(),
    }
}

fn io_total(row: &query::EntityUsage) -> f64 {
    row.io_read_bytes.unwrap_or(0) as f64 + row.io_write_bytes.unwrap_or(0) as f64
}

fn network_total(row: &query::EntityUsage) -> f64 {
    row.net_rx_bytes.unwrap_or(0) as f64 + row.net_tx_bytes.unwrap_or(0) as f64
}

fn usage_row(row: query::EntityUsage) -> UsageRow {
    UsageRow {
        entity_id: row.entity_id,
        kind: row.kind.as_str().to_string(),
        name: row.name,
        tool: row.tool,
        role: row.role,
        container: row.container,
        cpu_avg_pct: finite(row.cpu_avg_pct),
        cpu_max_pct: finite(row.cpu_max_pct),
        cpu_total_usec: row.cpu_total_usec,
        memory_avg_bytes: row.memory_avg_bytes,
        memory_max_bytes: row.memory_max_bytes,
        io_read_bytes: row.io_read_bytes,
        io_write_bytes: row.io_write_bytes,
        net_rx_bytes: row.net_rx_bytes,
        net_tx_bytes: row.net_tx_bytes,
        covered_ns: row.covered_ns,
        sample_count: row.sample_count,
    }
}

fn window_views(
    conn: &rusqlite::Connection,
    windows: &[AttributionWindow],
    report_window: &Window,
) -> Result<Vec<WindowView>> {
    let mut views = Vec::with_capacity(windows.len());
    for window in windows {
        let sub = Window::new(
            window.start_wall_ns.saturating_sub(30_000_000_000),
            window.end_wall_ns.saturating_add(30_000_000_000),
        );
        let mut log_filter = LogFilter::new(sub);
        log_filter.limit = 20;
        let mut logs = query::logs(conn, &log_filter)?;
        logs.sort_by_key(|record| record.wall_ns);
        let event_filter = EventFilter {
            window: Some(sub),
            limit: 20,
            ..Default::default()
        };
        let mut events = query::events(conn, &event_filter)?;
        events.sort_by_key(|event| event.wall_ns);
        views.push(WindowView {
            start: window.start_wall_ns,
            end: window.end_wall_ns,
            kind: match window.kind {
                WindowKind::High => "high",
                WindowKind::Low => "low",
            }
            .to_string(),
            metric: window.metric.as_str().to_string(),
            value: finite(Some(window.value)).unwrap_or(0.0),
            baseline: finite(Some(window.baseline)).unwrap_or(0.0),
            change_pct: finite(Some(window.change_pct)).unwrap_or(0.0),
            confidence: finite(Some(window.confidence))
                .unwrap_or(0.0)
                .clamp(0.0, 1.0),
            contributors: window
                .contributors
                .iter()
                .map(|contributor| ContributionView {
                    entity_id: contributor.entity_id.clone(),
                    name: contributor.name.clone(),
                    kind: contributor.kind.as_str().to_string(),
                    tool: contributor.tool.clone(),
                    value: finite(Some(contributor.value)).unwrap_or(0.0),
                    share_pct: finite(contributor.share_pct),
                    evidence: contributor.evidence.clone(),
                })
                .collect(),
            evidence: window.evidence.clone(),
            logs: logs.into_iter().map(log_view).collect(),
            events: events.into_iter().map(event_view).collect(),
        });
    }
    let _ = report_window;
    Ok(views)
}

fn process_nodes(
    conn: &rusqlite::Connection,
    window: Window,
    limit: usize,
) -> Result<ProcessTreeView> {
    let rows = query::lifetimes(conn, window, limit)?;
    let ids: std::collections::HashSet<String> = rows
        .iter()
        .map(|row| row.process_instance_id.clone())
        .collect();
    let nodes = rows
        .into_iter()
        .map(|row| ProcessNodeView {
            id: row.process_instance_id.clone(),
            parent_id: row
                .parent_process_instance_id
                .filter(|parent| ids.contains(parent)),
            pid: row.host_pid,
            comm: row.comm,
            executable: row.executable,
            tool: row.tool,
            role: row.role,
            unit: row.unit,
            container: row.container,
            session: row.session,
            start: row.start_wall_ns,
            end: row.end_wall_ns,
            end_reason: row.end_reason,
        })
        .collect();
    Ok(ProcessTreeView {
        nodes,
        total: query::window_counts(conn, window)?.processes,
    })
}

fn incident_view(incident: Incident) -> IncidentView {
    IncidentView {
        id: incident.incident_id.unwrap_or(0),
        start: incident.started_wall_ns,
        end: incident.ended_wall_ns,
        entity_id: incident.entity_id,
        metric: incident.metric.as_str().to_string(),
        reason: incident.reason,
        peak: finite(Some(incident.peak)).unwrap_or(0.0),
        baseline: finite(Some(incident.baseline)).unwrap_or(0.0),
        acknowledged: incident.acknowledged,
        evidence_loss: incident.evidence_loss,
    }
}

fn log_view(record: LogRecord) -> LogView {
    LogView {
        wall: record.wall_ns,
        source_id: record.source_id,
        entity_id: record.entity_id,
        level: record.level.map(|level| level.as_str().to_string()),
        message: record.message,
        truncated: record.truncated,
    }
}

fn event_view(event: crate::model::EventRecord) -> EventView {
    EventView {
        wall: event.wall_ns,
        kind: event.kind.as_str().to_string(),
        severity: event.severity.as_str().to_string(),
        entity_id: event.entity_id,
        provenance: event.provenance,
    }
}

fn coverage_view(conn: &rusqlite::Connection) -> Result<CoverageView> {
    let collectors = query::collectors(conn)?
        .into_iter()
        .map(|status| collector_view(status.health))
        .collect();
    let integrations = query::integrations(conn)?
        .into_iter()
        .map(|status| IntegrationView {
            id: status.integration_id,
            configured: status.configured_state,
            detected: status.detected_state,
            version: status.version,
            capabilities: status.capabilities,
            last_error: status.last_error,
        })
        .collect();
    let gaps = query::gaps(conn)?
        .into_iter()
        .map(|row| GapView {
            source_id: row.gap.source_id,
            kind: row.gap.kind,
            detail: row.gap.detail,
            since: row.gap.since_wall_ns,
            resolved: row.resolved_wall_ns,
        })
        .collect();
    Ok(CoverageView {
        collectors,
        integrations,
        gaps,
    })
}

fn collector_view(health: CollectorHealth) -> CollectorView {
    CollectorView {
        id: health.collector_id,
        configured: health.configured.as_str().to_string(),
        availability: health.availability.as_str().to_string(),
        permission: health.permission.as_str().to_string(),
        last_success: health.last_success_wall_ns,
        last_error: health.last_error,
        received: health.received_count,
        persisted: health.persisted_count,
        dropped: health.dropped_count,
        truncated: health.truncated_count,
        queue_high_water: health.queue_high_water,
    }
}

/// Render one self-contained HTML file.
pub fn render_html(document: &ReportDocument) -> Result<String> {
    let json = serde_json::to_string(document)
        .map_err(|err| Error::Storage(format!("serialize report: {err}")))?;
    let safe_json = json
        .replace('&', "\\u0026")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029");
    let title = html_escape(&document.meta.title);
    let html = TEMPLATE
        .replace("/*__SARF_STYLE__*/", STYLE)
        .replace("/*__SARF_SCRIPT__*/", SCRIPT)
        .replace("__SARF_TITLE__", &title)
        .replace("__SARF_DATA__", &safe_json);
    if html.len() > MAX_REPORT_BYTES {
        return Err(Error::Capacity {
            what: "html report",
            limit: MAX_REPORT_BYTES as u64,
        });
    }
    Ok(html)
}

/// Write an HTML artifact atomically with restrictive permissions on Unix.
pub fn write_html(path: &Path, html: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| Error::io(parent, err))?;
    }
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    std::fs::write(&temporary, html).map_err(|err| Error::io(&temporary, err))?;
    crate::paths::restrict_file_permissions(&temporary);
    std::fs::rename(&temporary, path).map_err(|err| {
        let _ = std::fs::remove_file(&temporary);
        Error::io(path, err)
    })?;
    crate::paths::restrict_file_permissions(path);
    Ok(())
}

fn html_escape(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&#39;"),
            _ => output.push(character),
        }
    }
    output
}

fn finite(value: Option<f64>) -> Option<f64> {
    value.filter(|value| value.is_finite())
}

/// Convenience description shown by `sarf report --help` and docs.
pub fn description() -> String {
    format!("{PRODUCT} — {PRODUCT_LONG}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;

    #[test]
    fn empty_report_renders_offline_with_all_sections() {
        let store = Store::open_in_memory().expect("store");
        let config = Config::default();
        let now = 1_700_000_000_000_000_000;
        let options = ReportOptions::window(Window::new(now - 3_600_000_000_000, now));
        let document = build(store.connection(), &config, &options).expect("report");
        assert_eq!(document.summary.log_count, 0);
        assert!(document.series.timestamps.is_empty());
        assert!(document.windows.is_empty());
        let html = render_html(&document).expect("html");
        assert!(html.contains("<html"));
        assert!(html.contains("sarf-data"));
        assert!(html.contains("What happened"));
        assert!(!html.contains("http://"));
        assert!(!html.contains("https://"));
        assert!(html.len() < MAX_REPORT_BYTES);
    }

    #[test]
    fn json_embedding_cannot_terminate_the_script_element() {
        let mut store = Store::open_in_memory().expect("store");
        let config = Config::default();
        let now = 1_700_000_000_000_000_000;
        store
            .write(&[crate::store::WriteItem::normal(
                crate::store::WriteRecord::Log(LogRecord {
                    wall_ns: now - 1,
                    mono_ns: None,
                    source_id: "test".into(),
                    entity_id: None,
                    stream: crate::model::LogStream::File,
                    level: Some(crate::model::Severity::Error),
                    message: "</script><script>alert('x')</script>".into(),
                    truncated: false,
                    incident_id: None,
                    redacted: false,
                }),
            )])
            .expect("log");
        let options = ReportOptions::window(Window::new(now - 3_600_000_000_000, now));
        let document = build(store.connection(), &config, &options).expect("report");
        let html = render_html(&document).expect("html");
        assert!(!html.contains("</script><script>alert"));
        assert!(html.contains("\\u003c/script"));
    }

    #[test]
    fn downsample_preserves_peaks_and_bounds_points() {
        let mut points = Vec::new();
        for index in 0..1000 {
            points.push(query::HostSeriesPoint {
                wall_ns: index,
                cpu_pct: Some(if index == 500 { 99.0 } else { 1.0 }),
                ..Default::default()
            });
        }
        let reduced = downsample(&points, 100);
        assert!(reduced.len() <= 101);
        assert!(reduced.iter().any(|point| point.cpu_pct == Some(99.0)));
        assert_eq!(reduced.last().map(|point| point.wall_ns), Some(999));
    }

    #[test]
    fn title_is_html_escaped() {
        assert_eq!(html_escape("<b>&\"'"), "&lt;b&gt;&amp;&quot;&#39;");
    }
}
