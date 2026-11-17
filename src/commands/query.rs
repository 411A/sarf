//! Read-side query commands: top, processes, tree, why, incidents, show, logs.

use std::collections::HashMap;

use serde::Serialize;

use crate::analysis::{correlation, peaks as peaks_analysis, story as story_analysis};
use crate::cli::ByMetric;
use crate::commands::{
    fmt_bytes, fmt_clock, fmt_pct, fmt_span, fmt_time, print_json, print_table, Context,
};
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
    // Compute the share denominator before applying the display limit. Otherwise
    // "SHARE" describes only the visible top rows and always sums to 100%.
    let total: f64 = usage.iter().map(|row| value_for(row, by)).sum();
    usage.truncate(limit.max(1));
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
                    .map_or_else(|| "-".to_string(), |share| format!("{share:.1}%")),
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
    use std::fmt::Write as _;
    let mut suffix = String::new();
    if let Some(tool) = &node.tool {
        let _ = write!(suffix, " [{tool}]");
    }
    if let Some(container) = &node.container {
        let _ = write!(suffix, " [container {container}]");
    }
    if let Some(session) = &node.session {
        let _ = write!(suffix, " [{session}]");
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
                        .map_or_else(|| "-".to_string(), |share| format!("{share:.1}%")),
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

/// Group resource windows with actors, logs, events and process links.
///
/// One line is printed per merged episode, not per metric: the metrics of the
/// same interval share the host context, actor table, process links and
/// timeline, and identical log/event lines are printed once with a repeat
/// count. `--json` always carries the complete document.
pub fn story(context: &Context, since: &str, limit: usize) -> Result<i32> {
    let store = context.open_read()?;
    let window = context.window(since)?;
    let document = story_analysis::build_stories(store.connection(), window, &context.config)?;
    if context.json {
        print_json(&document)?;
        return Ok(0);
    }
    if document.groups.is_empty() {
        println!("No correlated groups in this range.");
        println!("This is an empty result, not zero resource usage.");
        return Ok(0);
    }
    println!(
        "INVESTIGATION STORY · {} group(s) from {} window(s) · {} .. {}",
        document.group_count,
        document.window_count,
        fmt_time(document.since_wall_ns),
        fmt_time(document.until_wall_ns)
    );
    if document.process_lifetimes_truncated {
        println!("  note    process lifetime read hit its bound; older links may be absent");
    }
    let mut shown: HashMap<String, usize> = HashMap::new();
    for (index, group) in document.groups.iter().take(limit.max(1)).enumerate() {
        let title = group
            .metrics
            .iter()
            .map(|metric| story_analysis::metric_label(&metric.metric))
            .collect::<Vec<_>>()
            .join(" + ");
        println!(
            "\n[{}] {} {} · {} .. {} ({}) · {:.0}% confidence (association only)",
            index + 1,
            group.kind.to_uppercase(),
            title,
            fmt_clock(group.start_wall_ns, document.since_wall_ns),
            fmt_clock(group.end_wall_ns, document.since_wall_ns),
            fmt_span(
                group.start_wall_ns,
                Some(group.end_wall_ns),
                group.end_wall_ns
            ),
            group.confidence * 100.0
        );
        println!("  host    {}", story_host_line(&group.host));
        print_story_metrics(group);
        print_story_actors(group);
        print_story_processes(group, document.since_wall_ns);
        print_story_timeline(index, group, document.since_wall_ns, &mut shown);
        let extra: Vec<&str> = group
            .evidence
            .iter()
            .map(String::as_str)
            .filter(|line| !story_evidence_is_context(line))
            .take(6)
            .collect();
        if !extra.is_empty() {
            println!("  context");
            for line in extra {
                println!("    · {line}");
            }
        }
    }
    println!("\nActors are ranked associations, logs/events are temporal evidence. Not causation.");
    println!("Run with --json for the complete document (every metric, line and link).");
    Ok(0)
}

/// One compact host summary line: only the values that were observed.
fn story_host_line(host: &story_analysis::StoryHost) -> String {
    let mut parts = Vec::new();
    if host.cpu_avg_pct.is_some() || host.cpu_max_pct.is_some() {
        parts.push(format!(
            "CPU {} avg / {} peak",
            fmt_pct(host.cpu_avg_pct),
            fmt_pct(host.cpu_max_pct)
        ));
    }
    if host.memory_avg_bytes.is_some() || host.memory_max_bytes.is_some() {
        parts.push(format!(
            "mem {} avg / {} peak",
            fmt_bytes(host.memory_avg_bytes),
            fmt_bytes(host.memory_max_bytes)
        ));
    }
    if host.net_rx_bytes.is_some() || host.net_tx_bytes.is_some() {
        parts.push(format!(
            "net {} in / {} out",
            fmt_bytes(host.net_rx_bytes),
            fmt_bytes(host.net_tx_bytes)
        ));
    }
    if host.load1_avg.is_some() || host.load1_max.is_some() {
        parts.push(format!(
            "load {} avg / {} peak",
            host.load1_avg
                .map_or_else(|| "-".to_string(), |value| format!("{value:.2}")),
            host.load1_max
                .map_or_else(|| "-".to_string(), |value| format!("{value:.2}"))
        ));
    }
    let pressure: Vec<String> = [
        ("cpu", host.psi_cpu_max),
        ("mem", host.psi_memory_max),
        ("io", host.psi_io_max),
    ]
    .into_iter()
    .filter_map(|(label, value)| {
        value
            .filter(|value| value.is_finite())
            .map(|value| format!("{label} {value:.1}%"))
    })
    .collect();
    if !pressure.is_empty() {
        parts.push(format!("PSI {}", pressure.join(" ")));
    }
    if parts.is_empty() {
        "-".to_string()
    } else {
        parts.join(" · ")
    }
}

/// One line per metric of the episode, with its own observed span when the
/// merged windows did not cover the whole group.
fn print_story_metrics(group: &story_analysis::StoryGroup) {
    let rows: Vec<String> = group
        .metrics
        .iter()
        .map(|metric| {
            let span = if metric.start_wall_ns == group.start_wall_ns
                && metric.end_wall_ns == group.end_wall_ns
            {
                String::new()
            } else {
                format!(
                    " · {} .. {}",
                    fmt_clock(metric.start_wall_ns, group.start_wall_ns),
                    fmt_clock(metric.end_wall_ns, group.start_wall_ns)
                )
            };
            let leader = metric
                .contributors
                .first()
                .map(|contributor| {
                    let share = contributor
                        .share_pct
                        .map_or_else(String::new, |share| format!(" {share:.0}%"));
                    format!(" → {}{share}", contributor.name)
                })
                .unwrap_or_default();
            let baseline = if metric.baseline.is_finite() {
                format!(
                    " (base {}, {:+.0}%, {:.0}% conf)",
                    story_value(&metric.metric, metric.baseline),
                    metric.change_pct,
                    metric.confidence * 100.0
                )
            } else {
                String::new()
            };
            format!(
                "{} {}{leader}{span}{baseline}",
                story_analysis::metric_label(&metric.metric),
                story_value(&metric.metric, metric.value),
            )
        })
        .collect();
    if !rows.is_empty() {
        println!("  values  {}", rows.join(" · "));
    }
}

/// Actor table: one row per active entity, idle entities summarized once.
fn print_story_actors(group: &story_analysis::StoryGroup) {
    let (active, idle): (
        Vec<&story_analysis::StoryActor>,
        Vec<&story_analysis::StoryActor>,
    ) = group
        .actors
        .iter()
        .partition(|actor| story_actor_active(actor));
    if group.actors.is_empty() {
        println!("  actors  none identified from stored usage");
        return;
    }
    if active.is_empty() {
        println!(
            "  actors  {} present with no measurable CPU, I/O or network in this window",
            idle.len()
        );
        return;
    }
    println!(
        "  actors  {} active{}",
        active.len(),
        if idle.is_empty() {
            String::new()
        } else {
            format!(
                ", {} present but idle ({})",
                idle.len(),
                idle.iter()
                    .take(4)
                    .map(|actor| actor.name.clone())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
    );
    let rows: Vec<Vec<String>> = active
        .iter()
        .map(|actor| {
            vec![
                actor.name.clone(),
                actor.kind.clone(),
                actor
                    .tool
                    .clone()
                    .or_else(|| actor.container.clone())
                    .unwrap_or_else(|| "-".to_string()),
                story_value(&group.primary_metric, actor.value),
                actor
                    .share_pct
                    .map_or_else(|| "-".to_string(), |share| format!("{share:.1}%")),
                fmt_pct(actor.cpu_avg_pct),
                fmt_bytes(actor.memory_max_bytes),
                fmt_bytes(Some(
                    actor
                        .io_read_bytes
                        .unwrap_or(0)
                        .saturating_add(actor.io_write_bytes.unwrap_or(0)),
                )),
                fmt_bytes(Some(
                    actor
                        .net_rx_bytes
                        .unwrap_or(0)
                        .saturating_add(actor.net_tx_bytes.unwrap_or(0)),
                )),
            ]
        })
        .collect();
    print_table(
        &[
            "ENTITY",
            "KIND",
            "TOOL/CONTAINER",
            "VALUE",
            "SHARE",
            "CPU",
            "MEM",
            "I/O",
            "NET",
        ],
        &rows,
    );
}

/// A process that started inside the window can never be "idle" evidence, so
/// only zero usage across every counter counts as idle here.
fn story_actor_active(actor: &story_analysis::StoryActor) -> bool {
    actor.value > 0.0
        || actor.cpu_avg_pct.is_some_and(|value| value > 0.0)
        || actor.cpu_max_pct.is_some_and(|value| value > 0.0)
        || actor.cpu_total_usec.is_some_and(|value| value > 0)
        || actor.io_read_bytes.is_some_and(|value| value > 0)
        || actor.io_write_bytes.is_some_and(|value| value > 0)
        || actor.net_rx_bytes.is_some_and(|value| value > 0)
        || actor.net_tx_bytes.is_some_and(|value| value > 0)
}

/// Parent/child links that belong to the episode, not every long-lived thread.
fn print_story_processes(group: &story_analysis::StoryGroup, reference_ns: i64) {
    let relevant: Vec<&story_analysis::StoryProcessLink> = group
        .process_links
        .iter()
        .filter(|link| link.relevant)
        .collect();
    if relevant.is_empty() {
        if group.process_link_total > 0 {
            println!(
                "  spawn   no process started in this window ({} long-lived link(s) existed)",
                group.process_link_total
            );
        }
        return;
    }
    println!("  spawn   {} link(s) inside the window", relevant.len());
    for link in relevant.iter().take(10) {
        println!(
            "    {} (pid {}) → {} (pid {}) at {}",
            link.parent_comm,
            link.parent_pid,
            link.child_comm,
            link.child_pid,
            fmt_clock(link.child_start_wall_ns, reference_ns)
        );
    }
    if relevant.len() > 10 {
        println!(
            "    + {} more link(s); --json has all {} overlapping link(s)",
            relevant.len() - 10,
            group.process_link_total
        );
    }
}

/// One chronological evidence timeline per group.
///
/// Actor logs, actor events, unattributed logs and unattributed events are
/// interleaved by time instead of repeated under separate headings. A line
/// already printed for an earlier group is referenced, not reprinted.
fn print_story_timeline(
    index: usize,
    group: &story_analysis::StoryGroup,
    reference_ns: i64,
    shown: &mut HashMap<String, usize>,
) {
    struct Line {
        wall_ns: i64,
        order: u8,
        who: String,
        text: String,
        repeats: u32,
        fingerprint: String,
    }
    let mut lines: Vec<Line> = Vec::new();
    let push_log =
        |lines: &mut Vec<Line>, actor: Option<&str>, line: &story_analysis::StoryLogLine| {
            let record = &line.first;
            let level = record.level.map_or_else(String::new, |level| {
                format!("{:<5} ", level.as_str().to_uppercase())
            });
            let who = actor.map_or_else(|| record.source_id.clone(), str::to_string);
            lines.push(Line {
                wall_ns: record.wall_ns,
                order: 1,
                who,
                text: format!("{level}{}", record.message),
                repeats: line.repeats,
                fingerprint: format!("log|{}|{}", record.source_id, record.message),
            });
        };
    let push_event =
        |lines: &mut Vec<Line>, actor: Option<&str>, line: &story_analysis::StoryEventLine| {
            let record = &line.first;
            let who = actor.map_or_else(|| "-".to_string(), str::to_string);
            lines.push(Line {
                wall_ns: record.wall_ns,
                order: 2,
                who,
                text: format!(
                    "{:<17} {}",
                    record.kind.as_str(),
                    story_event_target(record.entity_id.as_deref(), group)
                ),
                repeats: line.repeats,
                fingerprint: format!(
                    "event|{}|{}|{}",
                    record.kind.as_str(),
                    record.entity_id.as_deref().unwrap_or("-"),
                    record.payload
                ),
            });
        };
    for actor in &group.actors {
        for line in &actor.logs {
            push_log(&mut lines, Some(actor.name.as_str()), line);
        }
    }
    for line in &group.logs {
        push_log(&mut lines, None, line);
    }
    for actor in &group.actors {
        for line in &actor.events {
            push_event(&mut lines, Some(actor.name.as_str()), line);
        }
    }
    for line in &group.events {
        push_event(&mut lines, None, line);
    }
    if lines.is_empty() {
        return;
    }
    lines.sort_by(|left, right| {
        left.wall_ns
            .cmp(&right.wall_ns)
            .then_with(|| left.order.cmp(&right.order))
            .then_with(|| left.who.cmp(&right.who))
            .then_with(|| left.text.cmp(&right.text))
    });
    let pending: Vec<&Line> = lines
        .iter()
        .filter(|line| !shown.contains_key(&line.fingerprint))
        .collect();
    let already = lines.len() - pending.len();
    if pending.is_empty() {
        if already > 0 {
            println!("  timeline ({already} line(s) already shown above)");
        }
        return;
    }
    println!("  timeline ({} distinct line(s))", pending.len());
    for line in pending.iter().take(30) {
        shown.insert(line.fingerprint.clone(), index + 1);
        println!(
            "    {:<15} {:<9} {:<24} {}",
            fmt_clock(line.wall_ns, reference_ns),
            if line.order == 1 { "log" } else { "event" },
            truncate_cell(&line.who, 24),
            if line.repeats > 1 {
                format!("{} (×{})", line.text, line.repeats)
            } else {
                line.text.clone()
            }
        );
    }
    let mut notes: Vec<String> = Vec::new();
    if already > 0 {
        notes.push(format!("{already} line(s) already shown above"));
    }
    if pending.len() > 30 {
        notes.push(format!(
            "{} more line(s) not printed here; --json has all",
            pending.len() - 30
        ));
    }
    if group.logs_truncated || group.events_truncated {
        notes.push("some distinct lines were dropped at the retention bound".to_string());
    }
    if !notes.is_empty() {
        println!("    ({})", notes.join("; "));
    }
}

fn truncate_cell(value: &str, width: usize) -> String {
    if value.chars().count() <= width {
        return value.to_string();
    }
    let mut shortened: String = value.chars().take(width.saturating_sub(1)).collect();
    shortened.push('…');
    shortened
}

/// Resolve an event entity into a name a human can act on.
fn story_event_target(entity: Option<&str>, group: &story_analysis::StoryGroup) -> String {
    let Some(entity) = entity else {
        return "-".to_string();
    };
    if let Some(actor) = group.actors.iter().find(|actor| actor.entity_id == entity) {
        return actor.name.clone();
    }
    if let Some(short) = entity.strip_prefix("container:") {
        return group
            .actors
            .iter()
            .find(|actor| actor.container.as_deref() == Some(short))
            .map_or_else(|| format!("container {short}"), |actor| actor.name.clone());
    }
    if let Some(rest) = entity.strip_prefix("proc:") {
        if let Some(pid) = rest.split(':').nth(1) {
            for link in &group.process_links {
                if link.parent_pid.to_string() == pid {
                    return format!("{} (pid {pid})", link.parent_comm);
                }
                if link.child_pid.to_string() == pid {
                    return format!("{} (pid {pid})", link.child_comm);
                }
            }
            return format!("pid {pid}");
        }
    }
    entity.to_string()
}

/// Evidence lines already rendered as the host or metric summary.
fn story_evidence_is_context(line: &str) -> bool {
    const REPEATED: [&str; 9] = [
        "observed ",
        "usage below the window baseline",
        "host CPU averaged",
        "used memory averaged",
        "CPU pressure some max",
        "memory pressure some max",
        "I/O pressure some max",
        "host load average averaged",
        "host network",
    ];
    REPEATED.iter().any(|prefix| line.starts_with(prefix))
}

fn story_value(metric: &str, value: f64) -> String {
    match metric {
        "memory" | "io_read" | "io_write" | "net_rx" | "net_tx" => {
            fmt_bytes(Some(value.max(0.0) as u64))
        }
        "load" => format!("{value:.2}"),
        _ => fmt_pct(Some(value)),
    }
}

/// Emit the machine-readable peak document.
///
/// This is an agent artifact, not a human report: it is always JSON, one line of
/// output, with no labels or padding. `--stored` reads the dossiers the daemon
/// persisted (they survive raw-sample expiry); the default detects now.
pub fn peaks(
    context: &Context,
    since: &str,
    stored: bool,
    output: Option<&std::path::Path>,
) -> Result<i32> {
    let store = context.open_read()?;
    let window = context.window(since)?;
    let policy = peaks_analysis::PeakPolicy::from_config(&context.config);
    let text = if stored {
        serde_json::to_string(&peaks_analysis::stored_document(
            store.connection(),
            window,
            10_000,
        )?)
    } else if policy.enabled {
        serde_json::to_string(&peaks_analysis::document(
            store.connection(),
            window,
            &policy,
        )?)
    } else {
        // Disabled is not "no peaks": say so explicitly instead of emitting [].
        serde_json::to_string(&serde_json::json!({
            "schema": peaks_analysis::PEAK_SCHEMA,
            "v": peaks_analysis::PEAK_SCHEMA_VERSION,
            "enabled": false,
            "since_wall_ns": window.since,
            "until_wall_ns": window.until,
        }))
    }
    .map_err(|err| Error::Storage(format!("serialize peaks: {err}")))?;
    match output {
        Some(path) => {
            std::fs::write(path, format!("{text}\n"))
                .map_err(|err| Error::io(path.to_path_buf(), err))?;
        }
        None => println!("{text}"),
    }
    Ok(0)
}

/// List incidents.
pub fn incidents(context: &Context, since: &str, limit: usize) -> Result<i32> {
    let store = context.open_read()?;
    let conn = store.connection();
    let window = context.window(since)?;
    let rows = query::incidents(conn, window, limit.max(1))?;
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
                    .map_or_else(|| "open".to_string(), fmt_time),
                incident.entity_id.as_deref().map_or_else(
                    || "host".to_string(),
                    |id| query::entity_display_name(conn, id),
                ),
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
            .map_or_else(|| "open".to_string(), fmt_time),
        incident.peak,
        incident.baseline,
        incident.evidence_loss
    );
    if let Some(entity) = &incident.entity_id {
        println!(
            "  entity {} ({entity})",
            query::entity_display_name(conn, entity)
        );
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
            record.level.map_or("-", Severity::as_str),
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
                record.level.map_or("-", Severity::as_str).to_string(),
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
            Self::Cpu => format!("{value:.1}% of one core"),
            Self::PsiCpu | Self::PsiMemory | Self::PsiIo => format!("{value:.1}%"),
            Self::Memory => fmt_bytes(Some(value.max(0.0) as u64)),
            Self::IoRead | Self::IoWrite | Self::NetRx | Self::NetTx => {
                fmt_bytes(Some(value.max(0.0) as u64))
            }
            Self::Load => format!("{value:.2} load"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn psi_values_are_pressure_not_cpu_core_percent() {
        assert_eq!(Metric::Cpu.format_value(6.2), "6.2% of one core");
        assert_eq!(Metric::PsiCpu.format_value(6.2), "6.2%");
    }
}
