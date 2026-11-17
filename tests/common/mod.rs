//! Shared fixture builders for SARF's integration, end-to-end and performance tests.
//!
//! Fixtures are ordinary directory trees that mirror `/proc` and `/sys/fs/cgroup`.
//! Nothing here touches the host: every parser and collector runs against the files.

#![allow(dead_code)]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

/// Create a unique temporary directory, removing any stale copy first.
pub fn temp_root(name: &str) -> PathBuf {
    // Keep test trees inside target/: the constrained Windows shell denies the
    // profile temp to test processes, and target/ is already the build sandbox.
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/tmp");
    std::fs::create_dir_all(&base).expect("create test temp base");
    // Test threads can start within the same clock tick on Windows, so the
    // timestamp alone is not unique. The atomic counter prevents two tests from
    // sharing a database and failing with "database is locked".
    let unique = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
    let root = base.join(format!(
        "sarf-test-{name}-{}-{unique}-{}",
        std::process::id(),
        unique_suffix()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("create temp root");
    root
}

fn unique_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos())
}

/// Write a file, creating parents.
pub fn write(root: &Path, relative: &str, content: &str) {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create parent");
    }
    std::fs::write(&path, content).expect("write fixture file");
}

/// Append bytes to a file, creating it when absent.
pub fn append(root: &Path, relative: &str, content: &[u8]) {
    use std::io::Write;
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create parent");
    }
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .expect("open fixture file")
        .write_all(content)
        .expect("append fixture file");
}

/// One `/proc/stat` content string. Values are cumulative `USER_HZ` ticks.
#[allow(
    clippy::too_many_arguments,
    reason = "fixture builder mirrors the kernel fields"
)]
pub fn proc_stat(
    user: u64,
    nice: u64,
    system: u64,
    idle: u64,
    iowait: u64,
    irq: u64,
    softirq: u64,
    steal: u64,
    cpus: usize,
) -> String {
    let mut text =
        format!("cpu  {user} {nice} {system} {idle} {iowait} {irq} {softirq} {steal} 0 0\n");
    for index in 0..cpus.max(1) {
        let _ = writeln!(
            text,
            "cpu{index} {} {} {} {} {} {} {} {} 0 0",
            user / cpus.max(1) as u64,
            nice / cpus.max(1) as u64,
            system / cpus.max(1) as u64,
            idle / cpus.max(1) as u64,
            iowait / cpus.max(1) as u64,
            irq / cpus.max(1) as u64,
            softirq / cpus.max(1) as u64,
            steal / cpus.max(1) as u64,
        );
    }
    text.push_str("procs_running 2\nprocs_blocked 0\nbtime 1700000000\n");
    text
}

/// One `/proc/PID/stat` content string.
pub fn pid_stat(
    pid: u32,
    comm: &str,
    ppid: u32,
    utime: u64,
    stime: u64,
    start_ticks: u64,
    rss_pages: u64,
) -> String {
    format!(
        "{pid} ({comm}) S {ppid} {pid} {pid} 0 -1 4194560 10 0 2 0 {utime} {stime} 0 0 20 0 3 0 {start_ticks} 1048576 {rss_pages} 1\n"
    )
}

/// Build the host-level procfs files.
pub fn host_tree(root: &Path, busy_ticks: u64, idle_ticks: u64, cpus: usize) {
    write(
        root,
        "proc/stat",
        &proc_stat(0, 0, busy_ticks, idle_ticks, 0, 0, 0, 0, cpus),
    );
    write(
        root,
        "proc/meminfo",
        "MemTotal: 8388608 kB\nMemFree: 1048576 kB\nMemAvailable: 6291456 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n",
    );
    write(root, "proc/loadavg", "1.25 0.75 0.50 2/321 4242\n");
    write(
        root,
        "proc/pressure/cpu",
        "some avg10=2.50 avg60=1.00 avg300=0.50 total=1000\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
    );
    write(
        root,
        "proc/pressure/memory",
        "some avg10=1.00 avg60=0.50 avg300=0.25 total=500\n",
    );
    write(
        root,
        "proc/pressure/io",
        "some avg10=0.50 avg60=0.25 avg300=0.10 total=250\n",
    );
    write(
        root,
        "proc/net/dev",
        "Inter-| Receive | Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\neth0: 1000000 1000 0 0 0 0 0 0 2000000 2000 0 0 0 0 0 0\nlo: 500 5 0 0 0 0 0 0 500 5 0 0 0 0 0 0\n",
    );
    write(
        root,
        "proc/diskstats",
        "   8       0 sda 100 0 2000 50 100 0 4000 80 0 100 130\n",
    );
    write(root, "proc/uptime", "10000.00 5000.00\n");
    write(
        root,
        "proc/sys/kernel/random/boot_id",
        "11111111-2222-3333-4444-555555555555\n",
    );
    write(root, "proc/sys/kernel/hostname", "fixture-host\n");
    write(root, "proc/sys/kernel/osrelease", "6.6.0-fixture\n");
}

/// Build one process directory.
#[allow(
    clippy::too_many_arguments,
    reason = "fixture builder mirrors the kernel fields"
)]
pub fn process_tree(
    root: &Path,
    pid: u32,
    comm: &str,
    ppid: u32,
    utime: u64,
    stime: u64,
    start_ticks: u64,
    rss_pages: u64,
    cgroup: &str,
) {
    write(
        root,
        &format!("proc/{pid}/stat"),
        &pid_stat(pid, comm, ppid, utime, stime, start_ticks, rss_pages),
    );
    write(
        root,
        &format!("proc/{pid}/status"),
        &format!(
            "Name:\t{comm}\nThreads:\t3\nVmRSS:\t{} kB\nVmSize:\t4096 kB\n",
            rss_pages.saturating_mul(4)
        ),
    );
    write(
        root,
        &format!("proc/{pid}/io"),
        "rchar: 1000\nwchar: 2000\nsyscr: 10\nsyscw: 20\nread_bytes: 3000\nwrite_bytes: 4000\n",
    );
    write(
        root,
        &format!("proc/{pid}/cgroup"),
        &format!("0::{cgroup}\n"),
    );
}

/// Build one cgroup v2 node.
pub fn cgroup_node(
    root: &Path,
    relative: &str,
    usage_usec: u64,
    memory_current: u64,
    memory_max: u64,
    pids: u64,
) {
    let base = format!("sys/fs/cgroup/{relative}");
    write(
        root,
        &format!("{base}/cpu.stat"),
        &format!(
            "usage_usec {usage_usec}\nuser_usec {}\nsystem_usec {}\nnr_periods 10\nnr_throttled 0\nthrottled_usec 0\n",
            usage_usec / 2,
            usage_usec / 2
        ),
    );
    write(
        root,
        &format!("{base}/memory.current"),
        &format!("{memory_current}\n"),
    );
    write(
        root,
        &format!("{base}/memory.max"),
        &format!("{memory_max}\n"),
    );
    write(
        root,
        &format!("{base}/memory.stat"),
        &format!("anon {}\nfile {}\n", memory_current / 2, memory_current / 2),
    );
    write(
        root,
        &format!("{base}/cpu.pressure"),
        "some avg10=1.00 avg60=0.50 avg300=0.25 total=100\n",
    );
    write(root, &format!("{base}/pids.current"), &format!("{pids}\n"));
    write(
        root,
        &format!("{base}/io.stat"),
        "8:0 rbytes=4096 wbytes=8192 rios=10 wios=20 dbytes=0 dios=0\n",
    );
}

/// Build a full one-cycle fixture: host, two processes, nginx and docker cgroups.
pub fn full_cycle(root: &Path, cycle: u64, busy_ticks: u64, nginx_usage: u64) {
    // Idle counters must also be cumulative across replay snapshots; otherwise the
    // busy fraction is artificially pinned near 100%. 24,000 ticks per cycle is four
    // CPUs at 60 s and USER_HZ=100.
    let idle_ticks = cycle.saturating_add(1).saturating_mul(24_000);
    host_tree(root, busy_ticks, idle_ticks, 4);
    process_tree(root, 100, "systemd", 0, 100, 50, 10, 100, "/init.scope");
    process_tree(
        root,
        200,
        "nginx",
        100,
        1000 + nginx_usage,
        500,
        20,
        512,
        "/system.slice/nginx.service",
    );
    process_tree(
        root,
        300,
        "nginx",
        200,
        500 + nginx_usage / 2,
        200,
        30,
        256,
        "/system.slice/nginx.service",
    );
    cgroup_node(
        root,
        "system.slice/nginx.service",
        nginx_usage,
        16 * 1024 * 1024,
        64 * 1024 * 1024,
        2,
    );
    cgroup_node(
        root,
        "docker/abcdef0123456789",
        nginx_usage / 2,
        8 * 1024 * 1024,
        32 * 1024 * 1024,
        1,
    );
    write(
        root,
        "sys/fs/cgroup/cgroup.controllers",
        "cpu memory io pids\n",
    );
    let _ = cycle;
}

/// Write an e2e config that points at a fixture log file.
pub fn config_with_log(data_dir: &Path, log_path: &Path, interval_secs: u64) -> String {
    let log = log_path.display().to_string().replace('\\', "/");
    let config = format!(
        r#"[general]
interval_secs = {interval_secs}
process_interval_secs = {interval_secs}
discovery_secs = 30
max_db_mb = 100
max_wal_mb = 16
prune_interval_secs = 60

[process]
enabled = true
store_arguments = false
sample_all_processes = false
top_n_persistence = 20
max_processes = 2000

[cgroup]
enabled = true
sample_secs = {interval_secs}
max_cgroups = 256

[logs]
enabled = true
ring_lines = 200
ring_minutes = 10
ring_bytes_per_source = 524288
max_line_bytes = 4096
max_sources = 32
read_bytes_per_cycle = 65536
persist_info_sample_percent = 0
persist_warnings = true
persist_errors = true
always_store_patterns = ["WARN", "ERROR", "FATAL", "PANIC", "Traceback", "ENOSPC", "OOM", "Timeout", "ConnectionRefused", "unhealthy"]

[[logs.sources]]
id = "nginx-error"
kind = "file"
path = "{log}"
entity_hint = "nginx"

[adaptive]
enabled = true
incident_interval_ms = 500
max_incident_secs = 120
max_entities_high_resolution = 8
recovery_hysteresis_secs = 30

[thresholds]
host_cpu_pct = 10.0
service_cpu_pct = 20.0
memory_pct = 80.0
psi_some_pct = 10.0
error_rate_per_min = 5

[retention]
raw_hours = 48
process_raw_hours = 24
rollup_1m_days = 14
rollup_1h_days = 90
incident_days = 180
log_days = 7

[integrations]
# Fixture replay must be deterministic and must not read the host Docker daemon.
docker = "off"
tmux = "off"
zellij = "off"
systemd = "off"
nginx = "off"
cloudflared = "off"

[report]
bucket_secs = 60
max_points = 600
max_processes = 200
max_logs = 500
max_windows = 12
max_process_tree_nodes = 400
title = "SARF fixture report"
"#
    );
    let dir = data_dir.join("sarf-data");
    let _ = std::fs::create_dir_all(&dir);
    std::fs::write(dir.join("sarf.toml"), config).expect("write fixture config");
    log
}

/// Walk a tree and return `(relative path, byte length, content)`, sorted.
pub fn snapshot(root: &Path) -> Vec<(String, u64, Vec<u8>)> {
    let mut entries = Vec::new();
    walk(root, root, &mut entries);
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    entries
}

fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, u64, Vec<u8>)>) {
    let Ok(read) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in read.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(root, &path, out);
        } else if let Ok(bytes) = std::fs::read(&path) {
            let relative = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .display()
                .to_string();
            out.push((relative, bytes.len() as u64, bytes));
        }
    }
}
