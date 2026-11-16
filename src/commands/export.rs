//! Report generation, bounded exports and catalog inspection.

use std::path::Path;

use serde_json::json;

use crate::catalog::Catalog;
use crate::cli::{ExportFormat, ToolsCommand};
use crate::commands::{
    fmt_bytes, fmt_pct, fmt_time, output_path, print_json, print_table, Context,
};
use crate::error::{Error, Result};
use crate::model::{Metric, Severity};
use crate::report::{self, ReportOptions};
use crate::store::query::{self, LogFilter};

/// Build a self-contained HTML report.
pub fn report(
    context: &Context,
    since: &str,
    output: Option<&Path>,
    incident: Option<i64>,
    process: Option<&str>,
    service: Option<&str>,
) -> Result<i32> {
    let store = context.open_read()?;
    let window = context.window(since)?;
    let options = ReportOptions {
        window,
        incident_id: incident,
        process_id: process.map(str::to_string),
        service: service.map(str::to_string),
    };
    let document = report::build(store.connection(), &context.config, &options)?;
    let html = report::render_html(&document)?;
    let default_name = format!(
        "sarf-report-{}.html",
        chrono::Local::now().format("%Y%m%d-%H%M%S")
    );
    let path = output_path(output, context.data_dir.reports_dir().join(default_name));
    report::write_html(&path, &html)?;
    if context.json {
        print_json(&json!({
            "output": path,
            "bytes": html.len(),
            "meta": &document.meta,
            "summary": &document.summary,
            "windows": document.windows.len(),
            "incidents": document.incidents.len(),
            "logs": document.logs.len(),
            "processes": document.processes.nodes.len(),
        }))?;
        return Ok(0);
    }
    println!("report written: {}", path.display());
    println!("  size        {}", fmt_bytes(Some(html.len() as u64)));
    println!(
        "  window      {} .. {}",
        document.meta.since, document.meta.until
    );
    println!(
        "  host CPU    avg {} · peak {}",
        fmt_pct(document.summary.host_cpu_avg_pct),
        fmt_pct(document.summary.host_cpu_max_pct)
    );
    println!(
        "  memory peak {}{}",
        fmt_bytes(document.summary.host_mem_used_max_bytes),
        document
            .summary
            .host_mem_total_bytes
            .map(|total| format!(" of {}", fmt_bytes(Some(total))))
            .unwrap_or_default()
    );
    println!(
        "  evidence    {} windows · {} incidents · {} logs · {} processes",
        document.windows.len(),
        document.incidents.len(),
        document.logs.len(),
        document.processes.nodes.len()
    );
    println!(
        "  coverage    {} (missing data is shown as unavailable, never zero)",
        document.summary.coverage
    );
    println!("\nOpen it offline in any browser; it embeds all data and assets.");
    Ok(0)
}

/// Export bounded JSON or CSV.
pub fn export(
    context: &Context,
    since: &str,
    format: ExportFormat,
    output: Option<&Path>,
) -> Result<i32> {
    let store = context.open_read()?;
    let conn = store.connection();
    let window = context.window(since)?;
    let usage = query::entity_usage(conn, window)?;
    let incidents = query::incidents(conn, window, 500)?;
    let mut logs_filter = LogFilter::new(window);
    logs_filter.limit = context.config.report.max_logs;
    let logs = query::logs(conn, &logs_filter)?;
    let payload = match format {
        ExportFormat::Json => json!({
            "since": window.since,
            "until": window.until,
            "hostname": query::db_stats(conn)?.hostname,
            "usage": usage,
            "incidents": incidents,
            "logs": logs,
        }),
        ExportFormat::Csv => {
            let mut text = String::from(
                "entity_id,kind,name,tool,container,cpu_avg_pct,cpu_max_pct,memory_max_bytes,io_read_bytes,io_write_bytes,net_rx_bytes,net_tx_bytes\n",
            );
            for row in &usage {
                text.push_str(&csv_row(&[
                    row.entity_id.clone(),
                    row.kind.as_str().to_string(),
                    row.name.clone(),
                    row.tool.clone().unwrap_or_default(),
                    row.container.clone().unwrap_or_default(),
                    row.cpu_avg_pct
                        .map(|value| format!("{value:.4}"))
                        .unwrap_or_default(),
                    row.cpu_max_pct
                        .map(|value| format!("{value:.4}"))
                        .unwrap_or_default(),
                    row.memory_max_bytes
                        .map(|value| value.to_string())
                        .unwrap_or_default(),
                    row.io_read_bytes
                        .map(|value| value.to_string())
                        .unwrap_or_default(),
                    row.io_write_bytes
                        .map(|value| value.to_string())
                        .unwrap_or_default(),
                    row.net_rx_bytes
                        .map(|value| value.to_string())
                        .unwrap_or_default(),
                    row.net_tx_bytes
                        .map(|value| value.to_string())
                        .unwrap_or_default(),
                ]));
            }
            json!({"format":"csv","text":text,"rows":usage.len()})
        }
    };
    if let Some(path) = output {
        let text = match format {
            ExportFormat::Csv => payload
                .get("text")
                .and_then(|value| value.as_str())
                .unwrap_or_default()
                .to_string(),
            ExportFormat::Json => serde_json::to_string_pretty(&payload)
                .map_err(|err| Error::Storage(format!("serialize export: {err}")))?,
        };
        std::fs::write(path, text).map_err(|err| Error::io(path, err))?;
        crate::paths::restrict_file_permissions(path);
        println!("export written: {}", path.display());
    } else if let Some(text) = payload.get("text").and_then(|value| value.as_str()) {
        print!("{text}");
    } else {
        print_json(&payload)?;
    }
    Ok(0)
}

fn csv_row(cells: &[String]) -> String {
    let mut row = String::new();
    for (index, cell) in cells.iter().enumerate() {
        if index > 0 {
            row.push(',');
        }
        if cell.contains([',', '"', '\n', '\r']) {
            row.push('"');
            row.push_str(&cell.replace('"', "\"\""));
            row.push('"');
        } else {
            row.push_str(cell);
        }
    }
    row.push('\n');
    row
}

/// Inspect the catalog.
pub fn tools(context: &Context, command: &ToolsCommand) -> Result<i32> {
    let catalog = Catalog::embedded()?;
    match command {
        ToolsCommand::List => {
            if context.json {
                let items: Vec<serde_json::Value> = catalog.tools().iter().map(tool_json).collect();
                print_json(&items)?;
            } else {
                let rows: Vec<Vec<String>> = catalog
                    .tools()
                    .iter()
                    .map(|tool| {
                        vec![
                            tool.id.clone(),
                            tool.name.clone(),
                            tool.category.as_str().to_string(),
                            tool.executables.join(","),
                            tool.capabilities.join(","),
                        ]
                    })
                    .collect();
                print_table(
                    &["ID", "NAME", "CATEGORY", "EXECUTABLES", "CAPABILITIES"],
                    &rows,
                );
            }
        }
        ToolsCommand::Show { id } => {
            let tool = catalog
                .get(id)
                .ok_or_else(|| Error::Config(format!("unknown integration {id:?}")))?;
            if context.json {
                print_json(&tool_json(tool))?;
            } else {
                println!("{} — {}", tool.id, tool.name);
                println!("  category      {}", tool.category.as_str());
                println!("  executables   {}", tool.executables.join(", "));
                println!("  comm          {}", tool.comm.join(", "));
                println!("  capabilities  {}", tool.capabilities.join(", "));
                println!("  description   {}", tool.description);
                if !tool.roles.is_empty() {
                    println!("\nROLES");
                    for role in &tool.roles {
                        println!(
                            "  {:<20} comm={:?} argv={:?} cgroup={:?}",
                            role.label,
                            role.comm_contains,
                            role.argv_contains,
                            role.cgroup_contains
                        );
                    }
                }
            }
        }
        ToolsCommand::Search { query } => {
            let needle = query.to_ascii_lowercase();
            let matches: Vec<serde_json::Value> = catalog
                .tools()
                .iter()
                .filter(|tool| {
                    tool.id.to_ascii_lowercase().contains(&needle)
                        || tool.name.to_ascii_lowercase().contains(&needle)
                        || tool.description.to_ascii_lowercase().contains(&needle)
                        || tool
                            .executables
                            .iter()
                            .any(|exe| exe.to_ascii_lowercase().contains(&needle))
                })
                .map(tool_json)
                .collect();
            if context.json {
                print_json(&matches)?;
            } else if matches.is_empty() {
                println!("(no matching integrations)");
            } else {
                for tool in &matches {
                    println!(
                        "{} — {}",
                        tool.get("id").and_then(|v| v.as_str()).unwrap_or("-"),
                        tool.get("name").and_then(|v| v.as_str()).unwrap_or("-")
                    );
                }
            }
        }
    }
    Ok(0)
}

fn tool_json(tool: &crate::model::ToolSpec) -> serde_json::Value {
    json!({
        "id": tool.id,
        "name": tool.name,
        "category": tool.category.as_str(),
        "executables": tool.executables,
        "comm": tool.comm,
        "description": tool.description,
        "default_enabled": tool.default_enabled,
        "capabilities": tool.capabilities,
        "roles": tool.roles.iter().map(|role| json!({
            "label": role.label,
            "comm_contains": role.comm_contains,
            "comm_equals": role.comm_equals,
            "argv_contains": role.argv_contains,
            "cgroup_contains": role.cgroup_contains,
        })).collect::<Vec<_>>(),
    })
}

/// Unused but kept for symmetry with future export columns.
#[allow(dead_code)]
fn metric_header(metric: Metric) -> &'static str {
    metric.as_str()
}

/// Format a log level for exports.
#[allow(dead_code)]
fn level_label(level: Option<Severity>) -> &'static str {
    level.map(Severity::as_str).unwrap_or("-")
}

/// Format an export timestamp.
#[allow(dead_code)]
fn export_time(value: i64) -> String {
    fmt_time(value)
}
