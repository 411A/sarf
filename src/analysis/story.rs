//! Grouped investigation stories: one bounded, deterministic document that puts a
//! resource window, its actors, logs, lifecycle events and process links together.
//!
//! This is a read-only presentation layer over [`correlation`]. It never claims
//! causation: actors are ranked associations, logs/events are temporal evidence,
//! and missing data stays missing.

use std::collections::HashMap;

use rusqlite::Connection;
use serde::Serialize;

use crate::analysis::correlation;
use crate::config::Config;
use crate::error::Result;
use crate::model::{EventRecord, LogRecord, Metric, WindowKind};
use crate::store::query::{self, EventFilter, LifetimeSummary, LogFilter, Window};

/// Version of the machine-readable story document.
pub const STORY_SCHEMA_VERSION: u32 = 1;
/// Maximum actors retained per group.
const MAX_ACTORS: usize = 20;
/// Maximum logs read per group.
const MAX_LOGS: usize = 200;
/// Maximum events read per group.
const MAX_EVENTS: usize = 200;
/// Maximum logs attached to one actor.
const MAX_ACTOR_LOGS: usize = 20;
/// Maximum events attached to one actor.
const MAX_ACTOR_EVENTS: usize = 20;
/// Maximum process links retained in one group.
const MAX_PROCESS_LINKS: usize = 100;

/// One deterministic investigation document.
#[derive(Debug, Clone, Serialize)]
pub struct StoryDocument {
    /// Stable schema version for machine consumers.
    pub schema_version: u32,
    /// Requested window start.
    pub since_wall_ns: i64,
    /// Requested window end.
    pub until_wall_ns: i64,
    /// Number of groups in the document.
    pub group_count: usize,
    /// Correlated groups, ordered by start/metric/kind.
    pub groups: Vec<StoryGroup>,
}

/// A resource window with grouped related evidence.
#[derive(Debug, Clone, Serialize)]
pub struct StoryGroup {
    /// Stable group id.
    pub group_id: String,
    /// `high` or `low`.
    pub kind: String,
    /// Triggering metric.
    pub metric: String,
    /// Window start.
    pub start_wall_ns: i64,
    /// Window end.
    pub end_wall_ns: i64,
    /// Observed metric value.
    pub value: f64,
    /// Window baseline.
    pub baseline: f64,
    /// Percent change from baseline.
    pub change_pct: f64,
    /// Association confidence (0..1).
    pub confidence: f64,
    /// Host context in the window.
    pub host: StoryHost,
    /// Ranked actors associated with the window.
    pub actors: Vec<StoryActor>,
    /// Parent/child process links overlapping the window.
    pub process_links: Vec<StoryProcessLink>,
    /// Logs that could not be attributed to an actor.
    pub logs: Vec<LogRecord>,
    /// Events that could not be attributed to an actor.
    pub events: Vec<EventRecord>,
    /// Window evidence lines from the correlation engine.
    pub evidence: Vec<String>,
}

/// Host context for one group.
#[derive(Debug, Clone, Default, Serialize)]
pub struct StoryHost {
    /// Average CPU percent of one core.
    pub cpu_avg_pct: Option<f64>,
    /// Peak CPU percent of one core.
    pub cpu_max_pct: Option<f64>,
    /// Average used memory bytes.
    pub memory_avg_bytes: Option<u64>,
    /// Peak used memory bytes.
    pub memory_max_bytes: Option<u64>,
    /// Network receive bytes in the window.
    pub net_rx_bytes: Option<u64>,
    /// Network transmit bytes in the window.
    pub net_tx_bytes: Option<u64>,
    /// Average 1-minute load.
    pub load1_avg: Option<f64>,
    /// Peak CPU pressure `some`.
    pub psi_cpu_max: Option<f64>,
    /// Peak memory pressure `some`.
    pub psi_memory_max: Option<f64>,
    /// Peak I/O pressure `some`.
    pub psi_io_max: Option<f64>,
}

/// One ranked actor and its attributed evidence.
#[derive(Debug, Clone, Serialize)]
pub struct StoryActor {
    /// Entity id.
    pub entity_id: String,
    /// Display name.
    pub name: String,
    /// Entity kind.
    pub kind: String,
    /// Recognized tool.
    pub tool: Option<String>,
    /// Container id/name.
    pub container: Option<String>,
    /// Rank value in the window metric.
    pub value: f64,
    /// Share of the window total.
    pub share_pct: Option<f64>,
    /// Average CPU percent of one core.
    pub cpu_avg_pct: Option<f64>,
    /// Peak CPU percent of one core.
    pub cpu_max_pct: Option<f64>,
    /// Total CPU microseconds.
    pub cpu_total_usec: Option<u64>,
    /// Average memory bytes.
    pub memory_avg_bytes: Option<u64>,
    /// Peak memory bytes.
    pub memory_max_bytes: Option<u64>,
    /// Storage bytes read.
    pub io_read_bytes: Option<u64>,
    /// Storage bytes written.
    pub io_write_bytes: Option<u64>,
    /// Network bytes received.
    pub net_rx_bytes: Option<u64>,
    /// Network bytes transmitted.
    pub net_tx_bytes: Option<u64>,
    /// Evidence lines from the correlation engine.
    pub evidence: Vec<String>,
    /// Logs attributed to this actor inside the window.
    pub logs: Vec<LogRecord>,
    /// Events attributed to this actor inside the window.
    pub events: Vec<EventRecord>,
}

/// One observed parent/child process link.
#[derive(Debug, Clone, Serialize)]
pub struct StoryProcessLink {
    /// Parent entity id.
    pub parent_entity_id: String,
    /// Parent host PID.
    pub parent_pid: u32,
    /// Parent command.
    pub parent_comm: String,
    /// Child entity id.
    pub child_entity_id: String,
    /// Child host PID.
    pub child_pid: u32,
    /// Child command.
    pub child_comm: String,
    /// Child start time.
    pub child_start_wall_ns: i64,
    /// Child container, when known.
    pub child_container: Option<String>,
}

/// Build deterministic stories for all detected windows in `window`.
pub fn build_stories(conn: &Connection, window: Window, config: &Config) -> Result<StoryDocument> {
    let windows = correlation::detect_windows(conn, window, config)?;
    let mut groups = Vec::with_capacity(windows.len());
    for found in windows {
        let sub = Window::new(found.start_wall_ns, found.end_wall_ns);
        let usage = query::entity_usage(conn, sub)?;
        let usage_by_id: HashMap<&str, &query::EntityUsage> = usage
            .iter()
            .map(|row| (row.entity_id.as_str(), row))
            .collect();

        let mut actors: Vec<StoryActor> = found
            .contributors
            .iter()
            .take(MAX_ACTORS)
            .map(|contributor| {
                let usage = usage_by_id.get(contributor.entity_id.as_str());
                StoryActor {
                    entity_id: contributor.entity_id.clone(),
                    name: contributor.name.clone(),
                    kind: contributor.kind.as_str().to_string(),
                    tool: contributor.tool.clone(),
                    container: contributor.container.clone(),
                    value: contributor.value,
                    share_pct: contributor.share_pct,
                    cpu_avg_pct: usage.and_then(|row| row.cpu_avg_pct),
                    cpu_max_pct: usage.and_then(|row| row.cpu_max_pct),
                    cpu_total_usec: usage.and_then(|row| row.cpu_total_usec),
                    memory_avg_bytes: usage.and_then(|row| row.memory_avg_bytes),
                    memory_max_bytes: usage.and_then(|row| row.memory_max_bytes),
                    io_read_bytes: usage.and_then(|row| row.io_read_bytes),
                    io_write_bytes: usage.and_then(|row| row.io_write_bytes),
                    net_rx_bytes: usage.and_then(|row| row.net_rx_bytes),
                    net_tx_bytes: usage.and_then(|row| row.net_tx_bytes),
                    evidence: contributor.evidence.clone(),
                    logs: Vec::new(),
                    events: Vec::new(),
                }
            })
            .collect();

        let logs = query::logs(
            conn,
            &LogFilter {
                window: Some(sub),
                limit: MAX_LOGS,
                ..LogFilter::default()
            },
        )?;
        let events = query::events(
            conn,
            &EventFilter {
                window: Some(sub),
                limit: MAX_EVENTS,
                ..EventFilter::default()
            },
        )?;

        let mut unattributed_logs = Vec::new();
        for log in logs {
            if let Some(actor) = actors.iter_mut().find(|actor| log_matches(actor, &log)) {
                if actor.logs.len() < MAX_ACTOR_LOGS {
                    actor.logs.push(log);
                }
            } else if unattributed_logs.len() < MAX_LOGS {
                unattributed_logs.push(log);
            }
        }
        let mut unattributed_events = Vec::new();
        for event in events {
            if let Some(actor) = actors.iter_mut().find(|actor| event_matches(actor, &event)) {
                if actor.events.len() < MAX_ACTOR_EVENTS {
                    actor.events.push(event);
                }
            } else if unattributed_events.len() < MAX_EVENTS {
                unattributed_events.push(event);
            }
        }

        let host = host_snapshot(conn, sub)?;
        let mut process_links = process_links(conn, sub)?;
        process_links.truncate(MAX_PROCESS_LINKS);

        groups.push(StoryGroup {
            group_id: format!(
                "window:{}:{}:{}",
                found.metric.as_str(),
                kind_str(found.kind),
                found.start_wall_ns
            ),
            kind: kind_str(found.kind).to_string(),
            metric: found.metric.as_str().to_string(),
            start_wall_ns: found.start_wall_ns,
            end_wall_ns: found.end_wall_ns,
            value: found.value,
            baseline: found.baseline,
            change_pct: found.change_pct,
            confidence: found.confidence,
            host,
            actors,
            process_links,
            logs: unattributed_logs,
            events: unattributed_events,
            evidence: found.evidence,
        });
    }
    groups.sort_by(|left, right| {
        left.start_wall_ns
            .cmp(&right.start_wall_ns)
            .then_with(|| left.metric.cmp(&right.metric))
            .then_with(|| left.kind.cmp(&right.kind))
    });
    Ok(StoryDocument {
        schema_version: STORY_SCHEMA_VERSION,
        since_wall_ns: window.since,
        until_wall_ns: window.until,
        group_count: groups.len(),
        groups,
    })
}

const fn kind_str(kind: WindowKind) -> &'static str {
    match kind {
        WindowKind::High => "high",
        WindowKind::Low => "low",
    }
}

fn log_matches(actor: &StoryActor, log: &LogRecord) -> bool {
    if log.entity_id.as_deref() == Some(actor.entity_id.as_str()) {
        return true;
    }
    let Some(container) = actor.container.as_deref() else {
        return false;
    };
    log.source_id.contains(container)
        || log
            .entity_id
            .as_deref()
            .is_some_and(|entity| entity.contains(container))
}

fn event_matches(actor: &StoryActor, event: &EventRecord) -> bool {
    if event.entity_id.as_deref() == Some(actor.entity_id.as_str()) {
        return true;
    }
    let Some(container) = actor.container.as_deref() else {
        return false;
    };
    event
        .entity_id
        .as_deref()
        .is_some_and(|entity| entity.contains(container))
}

fn host_snapshot(conn: &Connection, window: Window) -> Result<StoryHost> {
    let usage = query::host_usage(conn, window)?;
    let points = query::host_series(conn, window)?;
    let mut host = StoryHost {
        cpu_avg_pct: usage.as_ref().and_then(|row| row.cpu_avg_pct),
        cpu_max_pct: usage.as_ref().and_then(|row| row.cpu_max_pct),
        memory_avg_bytes: usage.as_ref().and_then(|row| row.memory_avg_bytes),
        memory_max_bytes: usage.as_ref().and_then(|row| row.memory_max_bytes),
        net_rx_bytes: usage.as_ref().and_then(|row| row.net_rx_bytes),
        net_tx_bytes: usage.as_ref().and_then(|row| row.net_tx_bytes),
        ..StoryHost::default()
    };
    if !points.is_empty() {
        host.load1_avg = average(points.iter().filter_map(|point| point.load1));
        host.psi_cpu_max = points
            .iter()
            .filter_map(|point| point.psi_cpu)
            .reduce(f64::max);
        host.psi_memory_max = points
            .iter()
            .filter_map(|point| point.psi_memory)
            .reduce(f64::max);
        host.psi_io_max = points
            .iter()
            .filter_map(|point| point.psi_io)
            .reduce(f64::max);
    }
    Ok(host)
}

fn average(values: impl Iterator<Item = f64>) -> Option<f64> {
    let mut count = 0u64;
    let mut sum = 0.0;
    for value in values {
        if value.is_finite() {
            sum += value;
            count += 1;
        }
    }
    (count > 0).then(|| sum / count as f64)
}

fn process_links(conn: &Connection, window: Window) -> Result<Vec<StoryProcessLink>> {
    let lifetimes = query::lifetimes(conn, window, 500)?;
    let by_id: HashMap<&str, &LifetimeSummary> = lifetimes
        .iter()
        .map(|row| (row.process_instance_id.as_str(), row))
        .collect();
    let mut links = Vec::new();
    for child in &lifetimes {
        let Some(parent_id) = child.parent_process_instance_id.as_deref() else {
            continue;
        };
        let Some(parent) = by_id.get(parent_id) else {
            continue;
        };
        links.push(StoryProcessLink {
            parent_entity_id: parent.process_instance_id.clone(),
            parent_pid: parent.host_pid,
            parent_comm: parent.comm.clone(),
            child_entity_id: child.process_instance_id.clone(),
            child_pid: child.host_pid,
            child_comm: child.comm.clone(),
            child_start_wall_ns: child.start_wall_ns,
            child_container: child.container.clone(),
        });
        if links.len() >= MAX_PROCESS_LINKS {
            break;
        }
    }
    links.sort_by(|left, right| {
        left.child_start_wall_ns
            .cmp(&right.child_start_wall_ns)
            .then_with(|| left.child_pid.cmp(&right.child_pid))
    });
    Ok(links)
}

/// Labels used by the human CLI.
pub fn metric_label(metric: &str) -> &'static str {
    match metric {
        "cpu" => "CPU",
        "memory" => "memory",
        "io_read" => "disk read",
        "io_write" => "disk write",
        "net_rx" => "network receive",
        "net_tx" => "network transmit",
        "psi_cpu" => "CPU pressure",
        "psi_memory" => "memory pressure",
        "psi_io" => "I/O pressure",
        "load" => "load",
        _ => "resource",
    }
}

/// Whether a metric value is a percentage (for the human CLI).
pub const fn metric_is_percent(metric: Metric) -> bool {
    matches!(
        metric,
        Metric::Cpu | Metric::PsiCpu | Metric::PsiMemory | Metric::PsiIo
    )
}
