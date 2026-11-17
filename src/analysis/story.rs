//! Grouped investigation stories: one bounded, deterministic document that puts a
//! resource window, its actors, logs, lifecycle events and process links together.
//!
//! This is a read-only presentation layer over [`correlation`]. It never claims
//! causation: actors are ranked associations, logs/events are temporal evidence,
//! and missing data stays missing.
//!
//! Two reductions keep the document small without dropping facts:
//!
//! * windows that describe the same interval and kind are merged into one
//!   *episode* (`StoryGroup`) that keeps every metric, so the actors, host
//!   context, process links and evidence are stored and rendered once;
//! * identical log and event records are folded into one [`StoryLogLine`] /
//!   [`StoryEventLine`] with a repeat count and a first/last timestamp.

use std::collections::{HashMap, HashSet};

use rusqlite::Connection;
use serde::Serialize;

use crate::analysis::correlation;
use crate::config::Config;
use crate::error::Result;
use crate::model::{AttributionWindow, EventRecord, LogRecord, Metric, WindowKind};
use crate::store::query::{self, EventFilter, LifetimeSummary, LogFilter, Window};

/// Version of the machine-readable story document.
///
/// Version 2 merges same-episode windows into one group, keeps every metric
/// inside the group and folds repeated log/event lines into one entry.
pub const STORY_SCHEMA_VERSION: u32 = 2;
/// Maximum actors retained per group.
const MAX_ACTORS: usize = 20;
/// Maximum distinct logs read per group.
const MAX_LOGS: usize = 200;
/// Maximum distinct events read per group.
const MAX_EVENTS: usize = 200;
/// Maximum distinct logs attached to one actor.
const MAX_ACTOR_LOGS: usize = 20;
/// Maximum distinct events attached to one actor.
const MAX_ACTOR_EVENTS: usize = 20;
/// Maximum process links retained in one group.
const MAX_PROCESS_LINKS: usize = 100;
/// Maximum process lifetimes read for the whole document.
const MAX_LIFETIMES: usize = 2000;

/// One deterministic investigation document.
#[derive(Debug, Clone, Serialize)]
pub struct StoryDocument {
    /// Stable schema version for machine consumers.
    pub schema_version: u32,
    /// Requested window start.
    pub since_wall_ns: i64,
    /// Requested window end.
    pub until_wall_ns: i64,
    /// Number of correlated windows before episode merging.
    pub window_count: usize,
    /// Number of merged groups in the document.
    pub group_count: usize,
    /// Whether the process-lifetime read hit its bound (older links may be absent).
    pub process_lifetimes_truncated: bool,
    /// Correlated groups, ordered by start/end/kind.
    pub groups: Vec<StoryGroup>,
}

/// One episode: a resource window with grouped related evidence.
#[derive(Debug, Clone, Serialize)]
pub struct StoryGroup {
    /// Stable group id.
    pub group_id: String,
    /// `high` or `low`.
    pub kind: String,
    /// Union window start.
    pub start_wall_ns: i64,
    /// Union window end.
    pub end_wall_ns: i64,
    /// Metric with the highest association confidence.
    pub primary_metric: String,
    /// Highest association confidence across the merged metrics (0..1).
    pub confidence: f64,
    /// Every metric detected for this episode.
    pub metrics: Vec<StoryMetric>,
    /// Host context in the episode.
    pub host: StoryHost,
    /// Ranked actors associated with the episode.
    pub actors: Vec<StoryActor>,
    /// Parent/child process links overlapping the episode.
    pub process_links: Vec<StoryProcessLink>,
    /// Number of overlapping links before the per-group cap.
    pub process_link_total: usize,
    /// Number of overlapping links dropped by the per-group cap.
    pub process_link_omitted: usize,
    /// Distinct logs that could not be attributed to an actor.
    pub logs: Vec<StoryLogLine>,
    /// Distinct events that could not be attributed to an actor.
    pub events: Vec<StoryEventLine>,
    /// Whether the unattributed log list hit its bound.
    pub logs_truncated: bool,
    /// Whether the unattributed event list hit its bound.
    pub events_truncated: bool,
    /// Deduplicated window evidence lines from the correlation engine.
    pub evidence: Vec<String>,
}

/// One metric inside an episode.
#[derive(Debug, Clone, Serialize)]
pub struct StoryMetric {
    /// Metric name.
    pub metric: String,
    /// Window start for this metric (may be narrower than the group).
    pub start_wall_ns: i64,
    /// Window end for this metric (may be narrower than the group).
    pub end_wall_ns: i64,
    /// Observed metric value.
    pub value: f64,
    /// Window baseline.
    pub baseline: f64,
    /// Percent change from baseline.
    pub change_pct: f64,
    /// Association confidence (0..1).
    pub confidence: f64,
    /// Ranked entities contributing to this metric.
    pub contributors: Vec<StoryContributor>,
}

/// One entity ranked for one metric.
#[derive(Debug, Clone, Serialize)]
pub struct StoryContributor {
    /// Entity id.
    pub entity_id: String,
    /// Display name.
    pub name: String,
    /// Value in the metric's natural unit.
    pub value: f64,
    /// Share of the metric total, when meaningful.
    pub share_pct: Option<f64>,
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
    /// Peak 1-minute load.
    pub load1_max: Option<f64>,
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
    /// Value in the group's primary metric.
    pub value: f64,
    /// Share of the primary metric total.
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
    /// Distinct logs attributed to this actor inside the episode.
    pub logs: Vec<StoryLogLine>,
    /// Distinct events attributed to this actor inside the episode.
    pub events: Vec<StoryEventLine>,
    /// Whether the actor's log list hit its bound.
    pub logs_truncated: bool,
    /// Whether the actor's event list hit its bound.
    pub events_truncated: bool,
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
    /// Whether the child started inside the episode or a side is an actor.
    pub relevant: bool,
}

/// One distinct log line and how often it was observed.
#[derive(Debug, Clone, Serialize)]
pub struct StoryLogLine {
    /// First occurrence.
    pub first: LogRecord,
    /// Last occurrence.
    pub last_wall_ns: i64,
    /// Number of identical records folded into this line.
    pub repeats: u32,
}

/// One distinct event and how often it was observed.
#[derive(Debug, Clone, Serialize)]
pub struct StoryEventLine {
    /// First occurrence.
    pub first: EventRecord,
    /// Last occurrence.
    pub last_wall_ns: i64,
    /// Number of identical records folded into this line.
    pub repeats: u32,
}

/// One merged episode before evidence is attached.
struct Episode {
    kind: WindowKind,
    start_wall_ns: i64,
    end_wall_ns: i64,
    metrics: Vec<AttributionWindow>,
}

impl Episode {
    fn new(window: AttributionWindow) -> Self {
        Self {
            kind: window.kind,
            start_wall_ns: window.start_wall_ns,
            end_wall_ns: window.end_wall_ns,
            metrics: vec![window],
        }
    }

    const fn overlaps(&self, other: &Self) -> bool {
        self.start_wall_ns < other.end_wall_ns && other.start_wall_ns < self.end_wall_ns
    }

    /// Whether two high/low windows describe the same episode.
    ///
    /// Only windows of the same kind are merged, and only when one contains the
    /// other or they share a boundary: partial overlaps stay separate so no
    /// evidence is attributed to the wrong interval.
    fn compatible(&self, other: &Self) -> bool {
        if self.kind != other.kind || !self.overlaps(other) {
            return false;
        }
        let nested = (self.start_wall_ns <= other.start_wall_ns
            && other.end_wall_ns <= self.end_wall_ns)
            || (other.start_wall_ns <= self.start_wall_ns && self.end_wall_ns <= other.end_wall_ns);
        nested || self.start_wall_ns == other.start_wall_ns || self.end_wall_ns == other.end_wall_ns
    }

    fn absorb(&mut self, other: Self) {
        self.start_wall_ns = self.start_wall_ns.min(other.start_wall_ns);
        self.end_wall_ns = self.end_wall_ns.max(other.end_wall_ns);
        self.metrics.extend(other.metrics);
    }
}

/// Build deterministic stories for all detected windows in `window`.
pub fn build_stories(conn: &Connection, window: Window, config: &Config) -> Result<StoryDocument> {
    let detected = correlation::detect_windows(conn, window, config)?;
    let window_count = detected.len();
    let episodes = merge_episodes(detected);

    let mut lifetimes = query::lifetimes(conn, window, MAX_LIFETIMES.saturating_add(1))?;
    let process_lifetimes_truncated = lifetimes.len() > MAX_LIFETIMES;
    lifetimes.truncate(MAX_LIFETIMES);

    let mut groups = Vec::with_capacity(episodes.len());
    for episode in episodes {
        groups.push(build_group(conn, episode, &lifetimes)?);
    }
    Ok(StoryDocument {
        schema_version: STORY_SCHEMA_VERSION,
        since_wall_ns: window.since,
        until_wall_ns: window.until,
        window_count,
        group_count: groups.len(),
        process_lifetimes_truncated,
        groups,
    })
}

fn merge_episodes(windows: Vec<AttributionWindow>) -> Vec<Episode> {
    let mut episodes: Vec<Episode> = windows.into_iter().map(Episode::new).collect();
    loop {
        let mut merged = false;
        'pair: for left in 0..episodes.len() {
            for right in (left + 1)..episodes.len() {
                if episodes[left].compatible(&episodes[right]) {
                    let other = episodes.remove(right);
                    episodes[left].absorb(other);
                    merged = true;
                    break 'pair;
                }
            }
        }
        if !merged {
            break;
        }
    }
    episodes.sort_by(|left, right| {
        left.start_wall_ns
            .cmp(&right.start_wall_ns)
            .then_with(|| left.end_wall_ns.cmp(&right.end_wall_ns))
            .then_with(|| kind_str(left.kind).cmp(kind_str(right.kind)))
    });
    episodes
}

fn build_group(
    conn: &Connection,
    episode: Episode,
    lifetimes: &[LifetimeSummary],
) -> Result<StoryGroup> {
    let sub = Window::new(episode.start_wall_ns, episode.end_wall_ns);
    let usage = query::entity_usage(conn, sub)?;
    let usage_by_id: HashMap<&str, &query::EntityUsage> = usage
        .iter()
        .map(|row| (row.entity_id.as_str(), row))
        .collect();

    let mut metrics: Vec<AttributionWindow> = episode.metrics;
    metrics.sort_by(|left, right| {
        right
            .confidence
            .total_cmp(&left.confidence)
            .then_with(|| left.metric.as_str().cmp(right.metric.as_str()))
    });

    let primary = metrics.first().map(|window| window.metric);
    let mut actors: Vec<StoryActor> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for window in &metrics {
        for contributor in &window.contributors {
            if actors.len() >= MAX_ACTORS {
                break;
            }
            if !seen.insert(contributor.entity_id.clone()) {
                continue;
            }
            let usage = usage_by_id.get(contributor.entity_id.as_str());
            actors.push(StoryActor {
                entity_id: contributor.entity_id.clone(),
                name: contributor.name.clone(),
                kind: contributor.kind.as_str().to_string(),
                tool: contributor.tool.clone(),
                container: contributor.container.clone(),
                value: if Some(window.metric) == primary {
                    contributor.value
                } else {
                    0.0
                },
                share_pct: if Some(window.metric) == primary {
                    contributor.share_pct
                } else {
                    None
                },
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
                logs_truncated: false,
                events_truncated: false,
            });
        }
    }
    let raw_logs = query::logs(
        conn,
        &LogFilter {
            window: Some(sub),
            limit: MAX_LOGS,
            ..LogFilter::default()
        },
    )?;
    let raw_events = query::events(
        conn,
        &EventFilter {
            window: Some(sub),
            limit: MAX_EVENTS,
            ..EventFilter::default()
        },
    )?;

    let mut actor_logs: Vec<Vec<LogRecord>> = vec![Vec::new(); actors.len()];
    let mut group_logs = Vec::new();
    for log in raw_logs {
        match actors.iter().position(|actor| log_matches(actor, &log)) {
            Some(index) => actor_logs[index].push(log),
            None => group_logs.push(log),
        }
    }
    let mut actor_events: Vec<Vec<EventRecord>> = vec![Vec::new(); actors.len()];
    let mut group_events = Vec::new();
    for event in raw_events {
        match actors.iter().position(|actor| event_matches(actor, &event)) {
            Some(index) => actor_events[index].push(event),
            None => group_events.push(event),
        }
    }

    for ((actor, actor_logs), actor_events) in actors.iter_mut().zip(actor_logs).zip(actor_events) {
        let (logs, logs_truncated) = fold_logs(actor_logs.into_iter(), MAX_ACTOR_LOGS);
        let (events, events_truncated) = fold_events(actor_events.into_iter(), MAX_ACTOR_EVENTS);
        actor.logs = logs;
        actor.events = events;
        actor.logs_truncated = logs_truncated;
        actor.events_truncated = events_truncated;
    }
    let (logs, logs_truncated) = fold_logs(group_logs.into_iter(), MAX_LOGS);
    let (events, events_truncated) = fold_events(group_events.into_iter(), MAX_EVENTS);

    let host = host_snapshot(conn, sub)?;
    let actor_ids: HashSet<&str> = actors
        .iter()
        .map(|actor| actor.entity_id.as_str())
        .collect();
    let (mut process_links, process_link_total, process_link_omitted) =
        build_process_links(lifetimes, sub, &actor_ids);
    process_links.truncate(MAX_PROCESS_LINKS);

    let mut evidence: Vec<String> = Vec::new();
    let mut seen_evidence: HashSet<String> = HashSet::new();
    for window in &metrics {
        for line in &window.evidence {
            if seen_evidence.insert(line.clone()) {
                evidence.push(line.clone());
            }
        }
    }

    Ok(StoryGroup {
        group_id: format!(
            "window:{}:{}:{}",
            kind_str(episode.kind),
            episode.start_wall_ns,
            episode.end_wall_ns
        ),
        kind: kind_str(episode.kind).to_string(),
        start_wall_ns: episode.start_wall_ns,
        end_wall_ns: episode.end_wall_ns,
        primary_metric: primary.map_or_else(
            || "resource".to_string(),
            |metric| metric.as_str().to_string(),
        ),
        confidence: metrics.first().map_or(0.0, |window| window.confidence),
        metrics: metrics
            .iter()
            .map(|window| StoryMetric {
                metric: window.metric.as_str().to_string(),
                start_wall_ns: window.start_wall_ns,
                end_wall_ns: window.end_wall_ns,
                value: window.value,
                baseline: window.baseline,
                change_pct: window.change_pct,
                confidence: window.confidence,
                contributors: window
                    .contributors
                    .iter()
                    .map(|contributor| StoryContributor {
                        entity_id: contributor.entity_id.clone(),
                        name: contributor.name.clone(),
                        value: contributor.value,
                        share_pct: contributor.share_pct,
                    })
                    .collect(),
            })
            .collect(),
        host,
        actors,
        process_links,
        process_link_total,
        process_link_omitted,
        logs,
        events,
        logs_truncated,
        events_truncated,
        evidence,
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

/// Fold identical log records into one line with a repeat count.
///
/// Records are compared by source, level, message and entity: timestamps are
/// not part of the identity, so a line repeated by a restart or a re-read is
/// reported once with its observed range instead of many times.
fn fold_logs(records: impl Iterator<Item = LogRecord>, limit: usize) -> (Vec<StoryLogLine>, bool) {
    let mut folded: Vec<StoryLogLine> = Vec::new();
    let mut index: HashMap<(String, String, String, String), usize> = HashMap::new();
    let mut truncated = false;
    for record in records {
        let wall_ns = record.wall_ns;
        let key = (
            record.source_id.clone(),
            record
                .level
                .map_or_else(String::new, |level| level.as_str().to_string()),
            record.message.clone(),
            record.entity_id.clone().unwrap_or_default(),
        );
        match index.get(&key) {
            Some(position) => {
                let line = &mut folded[*position];
                line.repeats = line.repeats.saturating_add(1);
                let last = line.last_wall_ns.max(wall_ns);
                if wall_ns < line.first.wall_ns {
                    line.first = record;
                }
                line.last_wall_ns = last;
            }
            None if folded.len() >= limit.max(1) => truncated = true,
            None => {
                index.insert(key, folded.len());
                folded.push(StoryLogLine {
                    first: record,
                    last_wall_ns: wall_ns,
                    repeats: 1,
                });
            }
        }
    }
    folded.sort_by(|left, right| {
        left.first
            .wall_ns
            .cmp(&right.first.wall_ns)
            .then_with(|| left.first.source_id.cmp(&right.first.source_id))
            .then_with(|| left.first.message.cmp(&right.first.message))
    });
    (folded, truncated)
}

/// Fold identical events into one line with a repeat count.
fn fold_events(
    records: impl Iterator<Item = EventRecord>,
    limit: usize,
) -> (Vec<StoryEventLine>, bool) {
    let mut folded: Vec<StoryEventLine> = Vec::new();
    let mut index: HashMap<(String, String, String), usize> = HashMap::new();
    let mut truncated = false;
    for record in records {
        let wall_ns = record.wall_ns;
        let key = (
            record.kind.as_str().to_string(),
            record.entity_id.clone().unwrap_or_default(),
            record.payload.to_string(),
        );
        match index.get(&key) {
            Some(position) => {
                let line = &mut folded[*position];
                line.repeats = line.repeats.saturating_add(1);
                let last = line.last_wall_ns.max(wall_ns);
                if wall_ns < line.first.wall_ns {
                    line.first = record;
                }
                line.last_wall_ns = last;
            }
            None if folded.len() >= limit.max(1) => truncated = true,
            None => {
                index.insert(key, folded.len());
                folded.push(StoryEventLine {
                    first: record,
                    last_wall_ns: wall_ns,
                    repeats: 1,
                });
            }
        }
    }
    folded.sort_by(|left, right| {
        left.first
            .wall_ns
            .cmp(&right.first.wall_ns)
            .then_with(|| left.first.kind.as_str().cmp(right.first.kind.as_str()))
            .then_with(|| left.first.entity_id.cmp(&right.first.entity_id))
    });
    (folded, truncated)
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
        host.load1_max = points
            .iter()
            .filter_map(|point| point.load1)
            .reduce(f64::max);
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

/// Parent/child links overlapping the episode, with a relevance flag so the
/// human view can show processes that appeared in the episode rather than every
/// long-lived kernel thread that happened to exist at the time.
fn build_process_links(
    lifetimes: &[LifetimeSummary],
    window: Window,
    actor_ids: &HashSet<&str>,
) -> (Vec<StoryProcessLink>, usize, usize) {
    let overlapping: Vec<&LifetimeSummary> = lifetimes
        .iter()
        .filter(|row| {
            row.start_wall_ns < window.until
                && row.end_wall_ns.is_none_or(|end| end >= window.since)
        })
        .collect();
    let by_id: HashMap<&str, &LifetimeSummary> = overlapping
        .iter()
        .map(|row| (row.process_instance_id.as_str(), *row))
        .collect();
    let mut links = Vec::new();
    let mut total = 0usize;
    for child in &overlapping {
        let Some(parent_id) = child.parent_process_instance_id.as_deref() else {
            continue;
        };
        let Some(parent) = by_id.get(parent_id) else {
            continue;
        };
        total += 1;
        if links.len() >= MAX_PROCESS_LINKS {
            continue;
        }
        let relevant = (child.start_wall_ns >= window.since && child.start_wall_ns < window.until)
            || actor_ids.contains(parent.process_instance_id.as_str())
            || actor_ids.contains(child.process_instance_id.as_str())
            || child
                .container
                .as_deref()
                .is_some_and(|container| actor_ids.iter().any(|actor| actor.contains(container)));
        links.push(StoryProcessLink {
            parent_entity_id: parent.process_instance_id.clone(),
            parent_pid: parent.host_pid,
            parent_comm: parent.comm.clone(),
            child_entity_id: child.process_instance_id.clone(),
            child_pid: child.host_pid,
            child_comm: child.comm.clone(),
            child_start_wall_ns: child.start_wall_ns,
            child_container: child.container.clone(),
            relevant,
        });
    }
    links.sort_by(|left, right| {
        right
            .relevant
            .cmp(&left.relevant)
            .then_with(|| left.child_start_wall_ns.cmp(&right.child_start_wall_ns))
            .then_with(|| left.child_pid.cmp(&right.child_pid))
    });
    (links, total, total.saturating_sub(MAX_PROCESS_LINKS))
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::float_cmp)]

    use super::*;
    use crate::model::{LogStream, Severity};

    fn window(
        metric: Metric,
        kind: WindowKind,
        start: i64,
        end: i64,
        confidence: f64,
    ) -> AttributionWindow {
        AttributionWindow {
            start_wall_ns: start,
            end_wall_ns: end,
            kind,
            metric,
            value: 10.0,
            baseline: 5.0,
            change_pct: 100.0,
            contributors: Vec::new(),
            evidence: Vec::new(),
            confidence,
        }
    }

    fn log(wall_ns: i64, message: &str) -> LogRecord {
        LogRecord {
            wall_ns,
            mono_ns: None,
            source_id: "docker:web".to_string(),
            entity_id: Some("container:abc".to_string()),
            stream: LogStream::Stdout,
            level: Some(Severity::Info),
            message: message.to_string(),
            truncated: false,
            incident_id: None,
            redacted: false,
        }
    }

    #[test]
    fn same_episode_windows_merge_and_partial_overlaps_stay_apart() {
        let merged = merge_episodes(vec![
            window(Metric::Cpu, WindowKind::High, 100, 200, 0.8),
            window(Metric::PsiCpu, WindowKind::High, 100, 200, 0.7),
        ]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].metrics.len(), 2);

        let nested = merge_episodes(vec![
            window(Metric::Cpu, WindowKind::High, 100, 400, 0.9),
            window(Metric::PsiIo, WindowKind::High, 150, 300, 0.6),
        ]);
        assert_eq!(nested.len(), 1);
        assert_eq!(nested[0].start_wall_ns, 100);
        assert_eq!(nested[0].end_wall_ns, 400);

        let overlapping = merge_episodes(vec![
            window(Metric::Cpu, WindowKind::High, 100, 200, 0.9),
            window(Metric::PsiIo, WindowKind::High, 150, 250, 0.6),
        ]);
        assert_eq!(
            overlapping.len(),
            2,
            "a partial overlap is a different episode"
        );

        let mixed = merge_episodes(vec![
            window(Metric::Cpu, WindowKind::Low, 100, 200, 0.9),
            window(Metric::PsiCpu, WindowKind::High, 100, 200, 0.6),
        ]);
        assert_eq!(mixed.len(), 2, "high and low windows are separate stories");
    }

    #[test]
    fn identical_log_lines_fold_without_losing_counts() {
        let (folded, truncated) = fold_logs(
            vec![log(30, "boom"), log(10, "boom"), log(20, "other")].into_iter(),
            10,
        );
        assert!(!truncated);
        assert_eq!(folded.len(), 2);
        assert_eq!(folded[0].first.wall_ns, 10);
        assert_eq!(folded[0].last_wall_ns, 30);
        assert_eq!(folded[0].repeats, 2);
        assert_eq!(folded[1].first.message, "other");
    }

    #[test]
    fn fold_reports_the_bound_it_hit() {
        let (folded, truncated) =
            fold_logs(vec![log(1, "a"), log(2, "b"), log(3, "c")].into_iter(), 2);
        assert!(truncated);
        assert_eq!(folded.len(), 2);
    }
}
