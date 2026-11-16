//! Read-side query commands: top, processes, tree, why, incidents, show, logs.

use serde::Serialize;

use crate::analysis::correlation;
use crate::cli::ByMetric;
use crate::commands::{fmt_bytes, fmt_pct, fmt_span, fmt_time, print_json, print_table, Context};
use crate::error::{Error, Result};
use crate::model::{Metric, Severity};
use crate::store::query::{self, EventFilter, LogFilter, Window};

/// Rank entities by one metric.
pub fn top(context: &Context, since: &str, by: ByMetric, limit: usize) -> Result<i32> {
    let store = context.open_read()?;
    let window = context.window(since)?;
    let mut usage = query::entity_usage(store.connection(), window)?;
    let _metric = match by {
        ByMetric::Cpu => Metric::Cpu,
        ByMetric::Mem => Metric::Memory,
        ByMetric::Io => Metric::IoWrite,
        ByMetric::Net => Metric::NetRx,
    };
    usage.retain(|row| match by {
        ByMetric::Cpu => row.cpu_avg_pct.unwrap_or(0.0) > 0.0,
        ByMetric::Mem => row.memory_max_bytes.unwrap_or(0) > 0,
        ByMetric::Io => row.io_read_bytes.unwrap_or(0) > 0 || row.io_write_bytes.unwrap_or(0) > 0,
        ByMetric::Net => row.net_rx_bytes.unwrap_or(0) > 0 || row.net_tx_bytes.unwrap_or(0) > 0,
    });
    usage.sort_by(|left, right| {
        value_for(right, by)
            .partial_cmp(&value_for(left, by))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    usage.truncate(limit.max(1));
    let total: f64 = usage.iter().map(|row| value_for(row, by)).sum();
    let rows: Vec<TopRow> = usage
        .into_iter()
        .map(|row| TopRow {
            share_pct: if total > 0.0 {
                Some(value_for(&row, by) * 100.0 / total)
            } else {
                None
            },
            row,
        })
        .collect();
    if context.json {
        print_json(&rows)?;
        return Ok(0);
    }
    let table: Vec<Vec<String>> = rows
        .iter()
        .map(|entry| {
            let row = &entry.row;
            vec![
                row.name.clone(),
                row.kind.as_str().to_string(),
                row.tool
                    .clone()
                    .or_else(|| row.container.clone())
                    .or_else(|| row.role.clone())
                    .unwrap_or_else(|| "-".to_string()),
                fmt_pct(row.cpu_avg_pct),
                fmt_pct(row.cpu_max_pct),
                fmt_bytes(row.memory_max_bytes),
                fmt_bytes(Some(
                    row.io_read_bytes
                        .unwrap_or(0)
                        .saturating_add(row.io_write_bytes.unwrap_or(0)),
                )),
                fmt_bytes(Some(
                    row.net_rx_bytes
                        .unwrap_or(0)
                        .saturating_add(row.net_tx_bytes.unwrap_or(0)),
                )),
                entry
                    .share_pct
                    .map(|share| format!("{share:.1}%"))
                    .unwrap_or_else(|| "-".to_string()),
            ]
        })
        .collect();
    println!(
        "TOP by {} · {} .. {}",
        match by {
            ByMetric::Cpu => "CPU (percent of one core)",
            ByMetric::Mem => "memory",
            ByMetric::Io => "disk I/O",
            ByMetric::Net => "network",
        },
        fmt_time(window.since),
        fmt_time(window.until)
    );
    print_table(
        &[
            "ENTITY",
            "KIND",
            "TOOL/CONTAINER",
            "CPU AVG",
            "CPU MAX",
            "MEM MAX",
            "I/O",
            "NET",
            "SHARE",
        ],
        &table,
    );
    Ok(0)
}

#[derive(Debug, Clone, Serialize)]
struct TopRow {
    #[serde(flatten)]
    row: query::EntityUsage,
    share_pct: Option<f64>,
}

fn value_for(row: &query::EntityUsage, by: ByMetric) -> f64 {
    match by {
        ByMetric::Cpu => row.cpu_avg_pct.unwrap_or(0.0),
        ByMetric::Mem => row.memory_max_bytes.unwrap_or(0) as f64,
        ByMetric::Io => (row.io_read_bytes.unwrap_or(0) + row.io_write_bytes.unwrap_or(0)) as f64,
        ByMetric::Net => (row.net_rx_bytes.unwrap_or(0) + row.net_tx_bytes.unwrap_or(0)) as f64,
    }
}

/// List process lifetimes.
pub fn processes(
    context: &Context,
    since: &str,
    filter: Option<&str>,
    limit: usize,
) -> Result<i32> {
    let store = context.open_read()?;
    let window = context.window(since)?;
    let needle = filter.map(str::to_ascii_lowercase);
    let mut rows = query::lifetimes(store.connection(), window, limit.saturating_mul(8).max(200))?;
    if let Some(needle) = &needle {
        rows.retain(|row| {
            row.comm.to_ascii_lowercase().contains(needle)
                || row
                    .executable
                    .as_deref()
                    .is_some_and(|value| value.to_ascii_lowercase().contains(needle))
                || row
                    .tool
                    .as_deref()
                    .is_some_and(|value| value.to_ascii_lowercase().contains(needle))
                || row
                    .unit
                    .as_deref()
                    .is_some_and(|value| value.to_ascii_lowercase().contains(needle))
                || row
                    .container
                    .as_deref()
                    .is_some_and(|value| value.to_ascii_lowercase().contains(needle))
        });
    }
    rows.truncate(limit.max(1));
    if context.json {
        print_json(&rows)?;
        return Ok(0);
    }
    let table: Vec<Vec<String>> = rows
        .iter()
        .map(|row| {
            vec![
                row.host_pid.to_string(),
                row.comm.clone(),
                row.tool
                    .clone()
                    .or_else(|| row.role.clone())
                    .unwrap_or_else(|| "-".to_string()),
                row.unit.clone().unwrap_or_else(|| "-".to_string()),
                row.container.clone().unwrap_or_else(|| "-".to_string()),
                row.session.clone().unwrap_or_else(|| "-".to_string()),
                fmt_time(row.start_wall_ns),
                fmt_span(row.start_wall_ns, row.end_wall_ns, context.now),
                row.end_reason
                    .clone()
                    .unwrap_or_else(|| "alive/lost".to_string()),
            ]
        })
        .collect();
    print_table(
        &[
            "PID",
            "COMM",
            "TOOL/ROLE",
            "UNIT",
            "CONTAINER",
            "SESSION",
            "START",
            "SPAN",
            "END",
        ],
        &table,
    );
    Ok(0)
}

/// Print a process tree.
pub fn tree(
    context: &Context,
    since: &str,
    process: Option<&str>,
    service: Option<&str>,
    limit: usize,
) -> Result<i32> {
    let store = context.open_read()?;
    let window = context.window(since)?;
    let rows = query::lifetimes(store.connection(), window, limit.max(1))?;
    let ids: std::collections::HashSet<String> = rows
        .iter()
        .map(|row| row.process_instance_id.clone())
        .collect();
    let needle = service.map(str::to_ascii_lowercase);
    let mut nodes: Vec<TreeNode> = rows
        .into_iter()
        .filter(|row| {
            process.is_none_or(|id| row.process_instance_id == id)
                && needle.as_ref().is_none_or(|needle| {
                    row.comm.to_ascii_lowercase().contains(needle)
                        || row
                            .tool
                            .as_deref()
                            .is_some_and(|value| value.to_ascii_lowercase().contains(needle))
                        || row
                            .container
                            .as_deref()
                            .is_some_and(|value| value.to_ascii_lowercase().contains(needle))
                })
        })
        .map(|row| TreeNode {
            id: row.process_instance_id.clone(),
            parent: row
                .parent_process_instance_id
                .filter(|parent| ids.contains(parent)),
            pid: row.host_pid,
            comm: row.comm,
            tool: row.tool,
            container: row.container,
            session: row.session,
            start: row.start_wall_ns,
            end: row.end_wall_ns,
        })
        .collect();
    nodes.sort_by_key(|node| (node.parent.is_some(), node.start));
    if context.json {
        print_json(&nodes)?;
        return Ok(0);
    }
    if nodes.is_empty() {
        println!("(no processes)");
        return Ok(0);
    }
    let id_set: std::collections::HashSet<String> =
        nodes.iter().map(|node| node.id.clone()).collect();
    let roots: Vec<&TreeNode> = nodes
        .iter()
        .filter(|node| {
            node.parent
                .as_ref()
                .is_none_or(|parent| !id_set.contains(parent))
        })
        .collect();
    for root in roots {
        print_tree_node(&nodes, root, 0);
    }
    Ok(0)
}

#[derive(Debug, Clone, Serialize)]
struct TreeNode {
    id: String,
    parent: Option<String>,
    pid: u32,
    comm: String,
    tool: Option<String>,
    container: Option<String>,
    session: Option<String>,
    start: i64,
    end: Option<i64>,
}

fn print_tree_node(nodes: &[TreeNode], node: &TreeNode, depth: usize) {
    if depth > 64 {
        return;
    }
    let mut suffix = String::new();
    if let Some(tool) = &node.tool {
        suffix.push_str(&format!(" [{tool}]"));
    }
    if let Some(container) = &node.container {
        suffix.push_str(&format!(" [container {container}]"));
    }
    if let Some(session) = &node.session {
        suffix.push_str(&format!(" [{session}]"));
    }
    println!(
        "{}{} ({}·{}){}",
        "  ".repeat(depth),
        node.comm,
        node.pid,
        if node.end.is_some() { "ended" } else { "alive" },
        suffix
    );
    for child in nodes.iter().filter(|child| {
        child
            .parent
            .as_deref()
            .is_some_and(|parent| parent == node.id)
    }) {
        print_tree_node(nodes, child, depth + 1);
    }
}

/// Explain high/low windows.
pub fn why(context: &Context, since: &str, limit: usize, metric: Option<&str>) -> Result<i32> {
    let store = context.open_read()?;
    let window = context.window(since)?;
    let mut windows = correlation::detect_windows(store.connection(), window, &context.config)?;
    if let Some(metric) = metric {
        windows.retain(|window| window.metric.as_str().eq_ignore_ascii_case(metric));
    }
    windows.truncate(limit.max(1));
    if context.json {
        print_json(&windows)?;
        return Ok(0);
    }
    if windows.is_empty() {
        println!("No high/low windows detected in this range.");
        println!("This is an empty result, not zero resource usage.");
        return Ok(0);
    }
    for window in &windows {
        println!(
            "\n{} {} · {} .. {}",
            match window.kind {
                crate::model::WindowKind::High => "HIGH",
                crate::model::WindowKind::Low => "LOW",
            },
            window.metric.as_str(),
            fmt_time(window.start_wall_ns),
            fmt_time(window.end_wall_ns)
        );
        println!(
            "  observed {} vs baseline {} ({:+.1}%); association confidence {:.0}% (not causation)",
            window.metric.format_value(window.value),
            window.metric.format_value(window.baseline),
            window.change_pct,
            window.confidence * 100.0
        );
        let rows: Vec<Vec<String>> = window
            .contributors
            .iter()
            .map(|contributor| {
                vec![
                    contributor.name.clone(),
                    contributor.kind.as_str().to_string(),
                    contributor
                        .tool
                        .clone()
                        .or_else(|| contributor.container.clone())
                        .unwrap_or_else(|| "-".to_string()),
                    window.metric.format_value(contributor.value),
                    contributor
                        .share_pct
                        .map(|share| format!("{share:.1}%"))
                        .unwrap_or_else(|| "-".to_string()),
                ]
            })
            .collect();
        print_table(
            &["CONTRIBUTOR", "KIND", "TOOL/CONTAINER", "VALUE", "SHARE"],
            &rows,
        );
        for line in &window.evidence {
            println!("  - {line}");
        }
    }
    println!("\nObservations and temporal associations only; SARF does not claim causation.");
    Ok(0)
}

/// List incidents.
pub fn incidents(context: &Context, since: &str, limit: usize) -> Result<i32> {
    let store = context.open_read()?;
    let window = context.window(since)?;
    let rows = query::incidents(store.connection(), window, limit.max(1))?;
    if context.json {
        print_json(&rows)?;
        return Ok(0);
    }
    let table: Vec<Vec<String>> = rows
        .iter()
        .map(|incident| {
            vec![
                incident.incident_id.unwrap_or(0).to_string(),
                fmt_time(incident.started_wall_ns),
                incident
                    .ended_wall_ns
                    .map(fmt_time)
                    .unwrap_or_else(|| "open".to_string()),
                incident
                    .entity_id
                    .clone()
                    .unwrap_or_else(|| "host".to_string()),
                incident.metric.as_str().to_string(),
                format!("{:.2}", incident.peak),
                format!("{:.2}", incident.baseline),
                if incident.evidence_loss { "loss" } else { "-" }.to_string(),
                incident.reason.clone(),
            ]
        })
        .collect();
    print_table(
        &[
            "ID", "STARTED", "ENDED", "ENTITY", "METRIC", "PEAK", "BASELINE", "EVIDENCE", "REASON",
        ],
        &table,
    );
    Ok(0)
}

/// Show one incident with evidence.
pub fn show(context: &Context, incident_id: i64) -> Result<i32> {
    let store = context.open_read()?;
    let conn = store.connection();
    let incident = query::incident(conn, incident_id)?
        .ok_or_else(|| Error::Storage(format!("incident {incident_id} not found")))?;
    let end = incident
        .ended_wall_ns
        .unwrap_or_else(|| incident.started_wall_ns.saturating_add(300_000_000_000));
    let window = Window::new(
        incident.started_wall_ns.saturating_sub(60_000_000_000),
        end.saturating_add(30_000_000_000),
    );
    let mut log_filter = LogFilter::new(window);
    log_filter.limit = 80;
    log_filter.incident_id = None;
    let mut logs = query::logs(conn, &log_filter)?;
    logs.sort_by_key(|record| record.wall_ns);
    let event_filter = EventFilter {
        window: Some(window),
        limit: 80,
        ..Default::default()
    };
    let mut events = query::events(conn, &event_filter)?;
    events.sort_by_key(|event| event.wall_ns);
    let lifetimes = query::lifetimes(conn, window, 80)?;
    if context.json {
        print_json(&serde_json::json!({
            "incident": incident,
            "window": {"since": window.since, "until": window.until},
            "logs": logs,
            "events": events,
            "processes": lifetimes,
        }))?;
        return Ok(0);
    }
    println!(
        "Incident {} · {} · {}",
        incident.incident_id.unwrap_or(0),
        incident.metric.as_str(),
        incident.reason
    );
    println!(
        "  started {} · ended {} · peak {:.2} · baseline {:.2} · evidence loss {}",
        fmt_time(incident.started_wall_ns),
        incident
            .ended_wall_ns
            .map(fmt_time)
            .unwrap_or_else(|| "open".to_string()),
        incident.peak,
        incident.baseline,
        incident.evidence_loss
    );
    if let Some(entity) = &incident.entity_id {
        println!("  entity {entity}");
    }
    if !incident.evidence.is_null() {
        if let Ok(text) = serde_json::to_string_pretty(&incident.evidence) {
            println!("\nEVIDENCE\n{text}");
        }
    }
    println!("\nPROCESSES");
    let rows: Vec<Vec<String>> = lifetimes
        .iter()
        .map(|row| {
            vec![
                row.host_pid.to_string(),
                row.comm.clone(),
                row.tool.clone().unwrap_or_else(|| "-".to_string()),
                row.container.clone().unwrap_or_else(|| "-".to_string()),
                fmt_time(row.start_wall_ns),
            ]
        })
        .collect();
    print_table(&["PID", "COMM", "TOOL", "CONTAINER", "START"], &rows);
    println!("\nLOGS");
    for record in &logs {
        println!(
            "{} {:<14} {:<8} {}",
            fmt_time(record.wall_ns),
            record.source_id,
            record.level.map(Severity::as_str).unwrap_or("-"),
            record.message
        );
    }
    println!("\nEVENTS");
    for event in &events {
        println!(
            "{} {:<22} {:<8} {}",
            fmt_time(event.wall_ns),
            event.kind.as_str(),
            event.severity.as_str(),
            event.entity_id.clone().unwrap_or_default()
        );
    }
    println!("\nTemporal association only; causation is not implied.");
    Ok(0)
}

/// Query retained logs.
pub fn logs(
    context: &Context,
    source: &str,
    since: &str,
    grep: Option<&str>,
    level: Option<&str>,
    limit: usize,
) -> Result<i32> {
    let store = context.open_read()?;
    let window = context.window(since)?;
    let mut filter = LogFilter::new(window);
    filter.source_id = (source != "all").then(|| source.to_string());
    filter.grep = grep.map(str::to_string);
    filter.min_level = level.and_then(Severity::parse);
    filter.limit = limit.max(1);
    let mut records = query::logs(store.connection(), &filter)?;
    records.sort_by_key(|record| record.wall_ns);
    if context.json {
        print_json(&records)?;
        return Ok(0);
    }
    let rows: Vec<Vec<String>> = records
        .iter()
        .map(|record| {
            vec![
                fmt_time(record.wall_ns),
                record.source_id.clone(),
                record
                    .level
                    .map(Severity::as_str)
                    .unwrap_or("-")
                    .to_string(),
                record.message.clone(),
            ]
        })
        .collect();
    print_table(&["TIME", "SOURCE", "LEVEL", "MESSAGE"], &rows);
    Ok(0)
}

trait MetricDisplay {
    fn format_value(self, value: f64) -> String;
}

impl MetricDisplay for Metric {
    fn format_value(self, value: f64) -> String {
        match self {
            Metric::Cpu | Metric::PsiCpu | Metric::PsiMemory | Metric::PsiIo => {
                format!("{value:.1}% of one core")
            }
            Metric::Memory => fmt_bytes(Some(value.max(0.0) as u64)),
            Metric::IoRead | Metric::IoWrite | Metric::NetRx | Metric::NetTx => {
                fmt_bytes(Some(value.max(0.0) as u64))
            }
            Metric::Load => format!("{value:.2} load"),
        }
    }
}
