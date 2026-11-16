//! Total parsers for the `/proc` and cgroup pseudo-files SARF reads.
//!
//! Every parser takes `&str` and returns a typed [`crate::Error`] on malformed input;
//! none of them can panic on kernel or fixture data. Files are read through
//! [`read_text_bounded`] so a corrupt or adversarial source cannot force an unbounded
//! allocation. Counter semantics follow `guide-ChatGPT.md` §5 and §7:
//!
//! * `/proc/stat` guest time is already included in user/nice and is not added again;
//! * disk sectors are 512-byte sectors regardless of the device's logical sector size;
//! * `rchar`/`wchar` are syscall bytes, not physical storage bytes;
//! * a missing file or denied field is reported as unavailable, never as zero.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::model::{
    CgroupIo, CpuTimes, DiskCounters, LoadAvg, MemSnapshot, NetCounters, Pressure, PressureLine,
    ProcIo,
};

/// Largest pseudo-file SARF will read for a single record.
pub const MAX_PROC_FILE_BYTES: usize = 4 * 1024 * 1024;

/// Read a UTF-8 file with a hard byte bound.
///
/// `/proc` files report size zero and are generated on read, so the reader stops at
/// `max_bytes + 1` and reports [`Error::Capacity`] instead of allocating without end.
pub fn read_text_bounded(path: &Path, max_bytes: usize) -> Result<String> {
    let file = File::open(path).map_err(|err| Error::io(path, err))?;
    let mut buffer = Vec::with_capacity(4096.min(max_bytes));
    let mut limited = file.take(max_bytes as u64 + 1);
    limited
        .read_to_end(&mut buffer)
        .map_err(|err| Error::io(path, err))?;
    if buffer.len() > max_bytes {
        return Err(Error::Capacity {
            what: "procfs file",
            limit: max_bytes as u64,
        });
    }
    String::from_utf8(buffer)
        .map_err(|_| Error::parse("procfs file", format!("{} is not UTF-8", path.display())))
}

/// Read a file, treating absence or denial as `None`.
pub fn read_optional(path: &Path) -> Option<String> {
    read_text_bounded(path, MAX_PROC_FILE_BYTES).ok()
}

/// One `/proc/stat` snapshot.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct StatSample {
    /// Aggregate CPU counters.
    pub cpu: CpuTimes,
    /// Per-logical-CPU counters.
    pub per_cpu: Vec<CpuTimes>,
    /// `procs_running` when the kernel exposes it.
    pub procs_running: Option<u64>,
    /// `procs_blocked` when the kernel exposes it.
    pub procs_blocked: Option<u64>,
    /// `btime` (boot epoch seconds).
    pub btime: Option<u64>,
}

/// Parse `/proc/stat`.
///
/// The parser accepts unknown lines (future kernel counters) and requires the
/// aggregate `cpu` line's first eight counters, which are present on every
/// supported kernel.
pub fn parse_stat(text: &str) -> Result<StatSample> {
    let mut sample = StatSample::default();
    let mut saw_cpu = false;
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let Some(key) = fields.next() else { continue };
        if key == "cpu" {
            let ticks = parse_ticks(fields, "proc/stat cpu")?;
            sample.cpu = ticks;
            saw_cpu = true;
        } else if key.starts_with("cpu") {
            let ticks = parse_ticks(fields, "proc/stat cpuN")?;
            if sample.per_cpu.len() >= 4096 {
                return Err(Error::Capacity {
                    what: "per-cpu counters",
                    limit: 4096,
                });
            }
            sample.per_cpu.push(ticks);
        } else {
            let value = match fields.next() {
                Some(value) => value,
                None => continue,
            };
            match key {
                "procs_running" => sample.procs_running = parse_u64(value, "procs_running").ok(),
                "procs_blocked" => sample.procs_blocked = parse_u64(value, "procs_blocked").ok(),
                "btime" => sample.btime = parse_u64(value, "btime").ok(),
                _ => {}
            }
        }
    }
    if !saw_cpu {
        return Err(Error::parse("proc/stat", "missing aggregate cpu line"));
    }
    Ok(sample)
}

fn parse_ticks<'a>(fields: impl Iterator<Item = &'a str>, what: &'static str) -> Result<CpuTimes> {
    let values: Vec<u64> = fields
        .take(10)
        .map(|value| parse_u64(value, what))
        .collect::<Result<_>>()?;
    if values.len() < 8 {
        return Err(Error::parse(what, "expected at least 8 CPU counters"));
    }
    let get = |index: usize| values.get(index).copied().unwrap_or(0);
    Ok(CpuTimes {
        user: get(0),
        nice: get(1),
        system: get(2),
        idle: get(3),
        iowait: get(4),
        irq: get(5),
        softirq: get(6),
        steal: get(7),
        // Guest time is already included in user/nice (guide §5.1).
        guest: get(8),
        guest_nice: get(9),
    })
}

fn parse_u64(value: &str, what: &'static str) -> Result<u64> {
    value
        .parse::<u64>()
        .map_err(|_| Error::parse(what, format!("invalid integer {value:?}")))
}

/// Parse `/proc/meminfo`, converting kB values to bytes.
pub fn parse_meminfo(text: &str) -> Result<MemSnapshot> {
    let mut snapshot = MemSnapshot::default();
    let mut saw_total = false;
    for line in text.lines() {
        let Some((key, rest)) = line.split_once(':') else {
            continue;
        };
        let mut parts = rest.split_whitespace();
        let Some(value) = parts.next() else { continue };
        let Ok(value) = value.parse::<u64>() else {
            continue;
        };
        let multiplier = match parts.next() {
            Some("kB") => 1024,
            Some("MB") => 1024 * 1024,
            None => 1,
            Some(other) => {
                return Err(Error::parse(
                    "proc/meminfo",
                    format!("unsupported unit {other:?} for {key}"),
                ))
            }
        };
        let bytes = value.saturating_mul(multiplier);
        match key {
            "MemTotal" => {
                snapshot.total = bytes;
                saw_total = true;
            }
            "MemFree" => snapshot.free = Some(bytes),
            "MemAvailable" => snapshot.available = Some(bytes),
            "Buffers" => snapshot.buffers = Some(bytes),
            "Cached" => snapshot.cached = Some(bytes),
            "SwapTotal" => snapshot.swap_total = Some(bytes),
            "SwapFree" => snapshot.swap_free = Some(bytes),
            _ => {}
        }
    }
    if !saw_total {
        return Err(Error::parse("proc/meminfo", "missing MemTotal"));
    }
    Ok(snapshot)
}

/// Parse `/proc/loadavg`.
pub fn parse_loadavg(text: &str) -> Result<LoadAvg> {
    let mut fields = text.split_whitespace();
    let one = parse_f64(fields.next(), "proc/loadavg one")?;
    let five = parse_f64(fields.next(), "proc/loadavg five")?;
    let fifteen = parse_f64(fields.next(), "proc/loadavg fifteen")?;
    let (runnable, total) = match fields.next().and_then(|value| value.split_once('/')) {
        Some((runnable, total)) => (
            runnable.parse::<u32>().unwrap_or(0),
            total.parse::<u32>().unwrap_or(0),
        ),
        None => (0, 0),
    };
    Ok(LoadAvg {
        one,
        five,
        fifteen,
        runnable,
        total,
    })
}

fn parse_f64(value: Option<&str>, what: &'static str) -> Result<f64> {
    let value = value.ok_or_else(|| Error::parse(what, "missing value"))?;
    let parsed = value
        .parse::<f64>()
        .map_err(|_| Error::parse(what, format!("invalid float {value:?}")))?;
    if !parsed.is_finite() || parsed < 0.0 {
        return Err(Error::parse(what, format!("invalid float {value:?}")));
    }
    Ok(parsed)
}

/// Parse one PSI file (`/proc/pressure/*` or `cgroup.*.pressure`).
pub fn parse_pressure(text: &str) -> Result<PressureLine> {
    let mut line = PressureLine::default();
    let mut saw_some = false;
    for raw in text.lines() {
        let mut fields = raw.split_whitespace();
        let Some(kind) = fields.next() else { continue };
        let mut avg10 = None;
        let mut avg60 = None;
        let mut avg300 = None;
        let mut total = None;
        for field in fields {
            let Some((key, value)) = field.split_once('=') else {
                continue;
            };
            match key {
                "avg10" => avg10 = Some(parse_percent(value)?),
                "avg60" => avg60 = Some(parse_percent(value)?),
                "avg300" => avg300 = Some(parse_percent(value)?),
                "total" => total = Some(parse_u64(value, "pressure total")?),
                _ => {}
            }
        }
        match kind {
            "some" => {
                line.some_avg10 = avg10;
                line.some_avg60 = avg60;
                line.some_avg300 = avg300;
                line.some_total_us = total;
                saw_some = true;
            }
            "full" => {
                line.full_avg10 = avg10;
                line.full_avg60 = avg60;
                line.full_avg300 = avg300;
                line.full_total_us = total;
            }
            _ => {}
        }
    }
    if !saw_some {
        return Err(Error::parse("pressure", "missing 'some' line"));
    }
    Ok(line)
}

fn parse_percent(value: &str) -> Result<f64> {
    let parsed = value
        .parse::<f64>()
        .map_err(|_| Error::parse("pressure", format!("invalid avg {value:?}")))?;
    if !parsed.is_finite() || !(0.0..=100.0).contains(&parsed) {
        return Err(Error::parse(
            "pressure",
            format!("avg out of range {value:?}"),
        ));
    }
    Ok(parsed)
}

/// Parse host PSI files, keeping each absent or malformed sensor as `None`.
pub fn parse_host_pressure(cpu: Option<&str>, memory: Option<&str>, io: Option<&str>) -> Pressure {
    Pressure {
        cpu: cpu.and_then(|text| parse_pressure(text).ok()),
        memory: memory.and_then(|text| parse_pressure(text).ok()),
        io: io.and_then(|text| parse_pressure(text).ok()),
    }
}

/// Parse `/proc/net/dev`.
pub fn parse_net_dev(text: &str) -> Result<BTreeMap<String, NetCounters>> {
    let mut map = BTreeMap::new();
    for line in text.lines() {
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        let values: Vec<u64> = rest
            .split_whitespace()
            .map(|value| parse_u64(value, "proc/net/dev"))
            .collect::<Result<_>>()?;
        if values.len() < 16 {
            return Err(Error::parse(
                "proc/net/dev",
                format!("interface {name} has {} fields, expected 16", values.len()),
            ));
        }
        if map.len() >= 4096 {
            return Err(Error::Capacity {
                what: "network interfaces",
                limit: 4096,
            });
        }
        map.insert(
            name.to_string(),
            NetCounters {
                rx_bytes: values[0],
                rx_packets: values[1],
                rx_errors: values[2],
                rx_drops: values[3],
                tx_bytes: values[8],
                tx_packets: values[9],
                tx_errors: values[10],
                tx_drops: values[11],
            },
        );
    }
    Ok(map)
}

/// Parse `/proc/diskstats`. Sector counters are converted to bytes.
pub fn parse_diskstats(text: &str) -> Result<BTreeMap<String, DiskCounters>> {
    let mut map = BTreeMap::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 14 {
            continue;
        }
        let name = fields[2].to_string();
        let value = |index: usize| parse_u64(fields[index], "proc/diskstats");
        let reads = value(3)?;
        let sectors_read = value(5)?;
        let writes = value(7)?;
        let sectors_written = value(9)?;
        let io_ms = value(12)?;
        if map.len() >= 4096 {
            return Err(Error::Capacity {
                what: "block devices",
                limit: 4096,
            });
        }
        map.insert(
            name,
            DiskCounters {
                reads,
                writes,
                read_bytes: sectors_read.saturating_mul(512),
                write_bytes: sectors_written.saturating_mul(512),
                io_ms,
            },
        );
    }
    Ok(map)
}

/// Return the parent device for common partition naming schemes.
///
/// `sda1` -> `sda`, `nvme0n1p1` -> `nvme0n1`, `mmcblk0p2` -> `mmcblk0`.
/// A whole device returns `None`.
pub fn parent_device(name: &str) -> Option<String> {
    // NVMe and MMC partition names carry an explicit `p` separator.
    if let Some((base, part)) = name.rsplit_once('p') {
        let numeric = !part.is_empty() && part.chars().all(|c| c.is_ascii_digit());
        if numeric && (base.starts_with("nvme") || base.starts_with("mmcblk")) {
            return Some(base.to_string());
        }
    }
    // Classic names such as sda1 / vda2 / xvda3: strip one trailing digit if the
    // remainder looks like a whole-disk name. Virtual whole devices that also end
    // in a digit (loop0, dm-0, md0, sr0, ram0, zram0, nbd0, rbd0) are excluded.
    let base = name.strip_suffix(|c: char| c.is_ascii_digit())?;
    if base.is_empty() || !base.ends_with(|c: char| c.is_ascii_alphabetic()) {
        return None;
    }
    if base.len() > 4
        || [
            "loop", "ram", "zram", "sr", "md", "dm", "nbd", "rbd", "fd", "scd",
        ]
        .iter()
        .any(|prefix| base.starts_with(prefix))
    {
        return None;
    }
    Some(base.to_string())
}

/// Sum counters over whole devices only, avoiding double counting partitions.
pub fn aggregate_disks(devices: &BTreeMap<String, DiskCounters>) -> DiskCounters {
    let mut total = DiskCounters::default();
    for (name, counters) in devices {
        let is_partition = parent_device(name).is_some_and(|parent| devices.contains_key(&parent));
        if is_partition {
            continue;
        }
        total.reads = total.reads.saturating_add(counters.reads);
        total.writes = total.writes.saturating_add(counters.writes);
        total.read_bytes = total.read_bytes.saturating_add(counters.read_bytes);
        total.write_bytes = total.write_bytes.saturating_add(counters.write_bytes);
        total.io_ms = total.io_ms.saturating_add(counters.io_ms);
    }
    total
}

/// Parse `/proc/uptime`.
pub fn parse_uptime(text: &str) -> Result<f64> {
    let first = text
        .split_whitespace()
        .next()
        .ok_or_else(|| Error::parse("proc/uptime", "empty file"))?;
    parse_f64(Some(first), "proc/uptime")
}

/// Selected fields of `/proc/PID/stat`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcStat {
    /// Thread-group id from the file name.
    pub pid: u32,
    /// Command name (may contain spaces and `)`).
    pub comm: String,
    /// State character.
    pub state: char,
    /// Parent host PID.
    pub ppid: u32,
    /// Cumulative user CPU ticks.
    pub utime: u64,
    /// Cumulative system CPU ticks.
    pub stime: u64,
    /// Thread count.
    pub threads: u32,
    /// Start time in clock ticks since boot.
    pub start_ticks: u64,
    /// Virtual size in bytes.
    pub vsize: u64,
    /// Resident set size in pages (multiply by the host page size).
    pub rss_pages: u64,
    /// Minor page faults.
    pub minflt: u64,
    /// Major page faults.
    pub majflt: u64,
}

/// Parse `/proc/PID/stat`, isolating `comm` with `rfind(')')`.
///
/// A naive whitespace split corrupts every process whose name contains a space or a
/// closing parenthesis, a documented kernel format quirk (guide §5.2).
pub fn parse_pid_stat(text: &str) -> Result<ProcStat> {
    let text = text.trim_end();
    let open = text
        .find('(')
        .ok_or_else(|| Error::parse("proc/PID/stat", "missing '(' before comm"))?;
    let close = text
        .rfind(')')
        .ok_or_else(|| Error::parse("proc/PID/stat", "missing ')' after comm"))?;
    if close <= open {
        return Err(Error::parse("proc/PID/stat", "unbalanced comm parentheses"));
    }
    let pid = text[..open]
        .trim()
        .parse::<u32>()
        .map_err(|_| Error::parse("proc/PID/stat", "invalid pid prefix"))?;
    let comm = text[open + 1..close].to_string();
    let rest = text[close + 1..].trim_start();
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // state is field 3, ppid field 4, ... starttime field 22, vsize 23, rss 24.
    if fields.len() < 22 {
        return Err(Error::parse(
            "proc/PID/stat",
            format!("only {} fields after comm", fields.len()),
        ));
    }
    let state = fields[0]
        .chars()
        .next()
        .ok_or_else(|| Error::parse("proc/PID/stat", "empty state field"))?;
    let get = |index: usize| parse_u64(fields[index], "proc/PID/stat");
    Ok(ProcStat {
        pid,
        comm,
        state,
        ppid: fields[1]
            .parse::<u32>()
            .map_err(|_| Error::parse("proc/PID/stat", "invalid ppid"))?,
        utime: get(11)?,
        stime: get(12)?,
        threads: fields[17]
            .parse::<u32>()
            .map_err(|_| Error::parse("proc/PID/stat", "invalid thread count"))?,
        start_ticks: get(19)?,
        vsize: get(20)?,
        rss_pages: get(21)?,
        minflt: get(7)?,
        majflt: get(9)?,
    })
}

/// Parse `/proc/PID/status` fields SARF uses.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcStatus {
    /// `Name`.
    pub name: Option<String>,
    /// `Threads`.
    pub threads: Option<u32>,
    /// `VmRSS` in bytes.
    pub vm_rss_bytes: Option<u64>,
    /// `VmSize` in bytes.
    pub vm_size_bytes: Option<u64>,
}

/// Parse `/proc/PID/status`.
pub fn parse_pid_status(text: &str) -> Result<ProcStatus> {
    let mut status = ProcStatus::default();
    for line in text.lines() {
        let Some((key, rest)) = line.split_once(':') else {
            continue;
        };
        let rest = rest.trim();
        match key {
            "Name" => status.name = Some(rest.to_string()),
            "Threads" => status.threads = rest.parse::<u32>().ok(),
            "VmRSS" => status.vm_rss_bytes = parse_kib(rest),
            "VmSize" => status.vm_size_bytes = parse_kib(rest),
            _ => {}
        }
    }
    Ok(status)
}

fn parse_kib(text: &str) -> Option<u64> {
    let mut parts = text.split_whitespace();
    let value = parts.next()?.parse::<u64>().ok()?;
    match parts.next() {
        Some("kB") | None => Some(value.saturating_mul(1024)),
        Some("MB") => Some(value.saturating_mul(1024 * 1024)),
        Some(_) => None,
    }
}

/// Parse `/proc/PID/io`.
pub fn parse_pid_io(text: &str) -> Result<ProcIo> {
    let mut io = ProcIo::default();
    let mut seen = 0_u32;
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = parse_u64(value.trim(), "proc/PID/io")?;
        match key {
            "rchar" => io.rchar = value,
            "wchar" => io.wchar = value,
            "syscr" => io.syscr = value,
            "syscw" => io.syscw = value,
            "read_bytes" => io.read_bytes = value,
            "write_bytes" => io.write_bytes = value,
            _ => continue,
        }
        seen += 1;
    }
    if seen == 0 {
        return Err(Error::parse("proc/PID/io", "no known counters"));
    }
    Ok(io)
}

/// Extract the cgroup v2 path from `/proc/PID/cgroup` (`0::/path`).
pub fn parse_cgroup_membership(text: &str) -> Option<String> {
    for line in text.lines() {
        let mut fields = line.splitn(3, ':');
        let hierarchy = fields.next()?;
        let controllers = fields.next()?;
        let path = fields.next()?;
        if hierarchy == "0" && controllers.is_empty() {
            return Some(path.to_string());
        }
    }
    None
}

/// Resolve the cgroup2 mount point from `/proc/self/mountinfo`.
pub fn parse_cgroup2_mount(text: &str) -> Option<PathBuf> {
    for line in text.lines() {
        let Some((before, after)) = line.split_once(" - ") else {
            continue;
        };
        let mut after_fields = after.split_whitespace();
        if after_fields.next() != Some("cgroup2") {
            continue;
        }
        let before_fields: Vec<&str> = before.split_whitespace().collect();
        let mount_point = before_fields.get(4)?;
        return Some(PathBuf::from(unescape_mount_path(mount_point)));
    }
    None
}

fn unescape_mount_path(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' && index + 3 < bytes.len() {
            let octal = &value[index + 1..index + 4];
            if let Ok(code) = u8::from_str_radix(octal, 8) {
                out.push(code);
                index += 4;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// CPU counters from `cgroup.cpu.stat`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CgroupCpuStat {
    /// Total usage in microseconds.
    pub usage_usec: Option<u64>,
    /// User usage in microseconds.
    pub user_usec: Option<u64>,
    /// System usage in microseconds.
    pub system_usec: Option<u64>,
    /// Periods elapsed.
    pub nr_periods: Option<u64>,
    /// Periods throttled.
    pub nr_throttled: Option<u64>,
    /// Total throttled microseconds.
    pub throttled_usec: Option<u64>,
}

/// Parse `cgroup.cpu.stat`.
pub fn parse_cgroup_cpu_stat(text: &str) -> Result<CgroupCpuStat> {
    let mut stat = CgroupCpuStat::default();
    for line in text.lines() {
        let Some((key, value)) = line.split_once(' ') else {
            continue;
        };
        let value = parse_u64(value.trim(), "cgroup cpu.stat")?;
        match key {
            "usage_usec" => stat.usage_usec = Some(value),
            "user_usec" => stat.user_usec = Some(value),
            "system_usec" => stat.system_usec = Some(value),
            "nr_periods" => stat.nr_periods = Some(value),
            "nr_throttled" => stat.nr_throttled = Some(value),
            "throttled_usec" => stat.throttled_usec = Some(value),
            _ => {}
        }
    }
    if stat.usage_usec.is_none() {
        return Err(Error::parse("cgroup cpu.stat", "missing usage_usec"));
    }
    Ok(stat)
}

/// Parse `cgroup memory.stat` into the anonymous and file byte counters.
pub fn parse_cgroup_memory_stat(text: &str) -> Result<(Option<u64>, Option<u64>)> {
    let mut anon = None;
    let mut file = None;
    for line in text.lines() {
        let Some((key, value)) = line.split_once(' ') else {
            continue;
        };
        let value = parse_u64(value.trim(), "cgroup memory.stat")?;
        match key {
            "anon" => anon = Some(value),
            "file" => file = Some(value),
            _ => {}
        }
    }
    Ok((anon, file))
}

/// Parse `cgroup io.stat`.
pub fn parse_cgroup_io_stat(text: &str) -> Result<Vec<CgroupIo>> {
    let mut devices = Vec::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let Some(device) = fields.next() else {
            continue;
        };
        let mut io = CgroupIo {
            device: device.to_string(),
            read_bytes: None,
            write_bytes: None,
            read_ops: None,
            write_ops: None,
        };
        for field in fields {
            let Some((key, value)) = field.split_once('=') else {
                continue;
            };
            let value = parse_u64(value, "cgroup io.stat")?;
            match key {
                "rbytes" => io.read_bytes = Some(value),
                "wbytes" => io.write_bytes = Some(value),
                "rios" => io.read_ops = Some(value),
                "wios" => io.write_ops = Some(value),
                _ => {}
            }
        }
        if devices.len() >= 256 {
            return Err(Error::Capacity {
                what: "cgroup io devices",
                limit: 256,
            });
        }
        devices.push(io);
    }
    Ok(devices)
}

/// Parse `cgroup cpu.max`, returning `(quota_usec, period_usec)`.
pub fn parse_cpu_max(text: &str) -> Result<(Option<u64>, Option<u64>)> {
    let mut fields = text.split_whitespace();
    let quota = fields
        .next()
        .ok_or_else(|| Error::parse("cgroup cpu.max", "empty"))?;
    let period = fields.next();
    let quota = if quota == "max" {
        None
    } else {
        Some(parse_u64(quota, "cgroup cpu.max")?)
    };
    let period = period
        .map(|value| parse_u64(value, "cgroup cpu.max"))
        .transpose()?;
    Ok((quota, period))
}

/// Parse a single unsigned value such as `memory.current` or `pids.current`.
pub fn parse_single_u64(text: &str, what: &'static str) -> Result<u64> {
    let text = text.trim();
    if text == "max" {
        return Err(Error::unavailable(what, "limit is 'max'"));
    }
    parse_u64(text, what)
}

/// Parse a single optional unsigned value, keeping `max` and malformed input as `None`.
pub fn parse_single_u64_opt(text: &str) -> Option<u64> {
    let text = text.trim();
    if text == "max" {
        return None;
    }
    text.parse::<u64>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const STAT: &str = "cpu  10 2 3 40 5 6 7 8 9 1\n\
cpu0 5 1 1 20 2 3 3 4 4 0\n\
cpu1 5 1 2 20 3 3 4 4 5 1\n\
intr 1 2 3\n\
ctxt 42\n\
btime 1700000000\n\
processes 9\n\
procs_running 2\n\
procs_blocked 1\n";

    #[test]
    fn stat_parses_all_cpu_fields_once() {
        let stat = parse_stat(STAT).expect("stat");
        assert_eq!(stat.cpu.user, 10);
        assert_eq!(stat.cpu.guest, 9);
        assert_eq!(stat.cpu.guest_nice, 1);
        assert_eq!(stat.per_cpu.len(), 2);
        assert_eq!(stat.procs_running, Some(2));
        assert_eq!(stat.procs_blocked, Some(1));
        assert_eq!(stat.btime, Some(1_700_000_000));
        // total excludes guest/guest_nice to avoid double counting.
        assert_eq!(stat.cpu.total(), 10 + 2 + 3 + 40 + 5 + 6 + 7 + 8);
    }

    #[test]
    fn stat_without_cpu_is_an_error() {
        let err = parse_stat("btime 1\n").expect_err("must fail");
        assert!(matches!(err, Error::Parse { .. }));
    }

    #[test]
    fn stat_rejects_malformed_ticks() {
        assert!(parse_stat("cpu 1 2 3 nope 5 6 7 8\n").is_err());
    }

    #[test]
    fn meminfo_converts_units() {
        let mem = parse_meminfo(
            "MemTotal:       16384 kB\nMemFree: 1024 kB\nMemAvailable: 8192 kB\n\
             Buffers: 100 kB\nCached: 200 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n",
        )
        .expect("meminfo");
        assert_eq!(mem.total, 16_777_216);
        assert_eq!(mem.available, Some(8_388_608));
        assert_eq!(mem.used(), Some(8_388_608));
    }

    #[test]
    fn meminfo_without_total_is_an_error() {
        assert!(parse_meminfo("MemFree: 1 kB\n").is_err());
    }

    #[test]
    fn loadavg_parses_runnable_pair() {
        let load = parse_loadavg("0.50 0.25 0.10 2/321 4242\n").expect("load");
        assert!((load.one - 0.5).abs() < f64::EPSILON);
        assert_eq!(load.runnable, 2);
        assert_eq!(load.total, 321);
    }

    #[test]
    fn pressure_parses_some_and_full() {
        let line = parse_pressure(
            "some avg10=1.50 avg60=2.00 avg300=3.00 total=1234\n\
             full avg10=0.50 avg60=0.40 avg300=0.30 total=99\n",
        )
        .expect("pressure");
        assert_eq!(line.some_avg10, Some(1.5));
        assert_eq!(line.some_total_us, Some(1234));
        assert_eq!(line.full_total_us, Some(99));
    }

    #[test]
    fn pressure_rejects_out_of_range() {
        assert!(parse_pressure("some avg10=101.0\n").is_err());
        assert!(parse_pressure("full avg10=1.0\n").is_err());
    }

    #[test]
    fn net_dev_parses_16_fields() {
        let net = parse_net_dev(
            "Inter-|   Receive                                                |  Transmit\n\
             face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n\
             eth0: 1000 10 1 2 0 0 0 0 2000 20 3 4 0 0 0 0\n",
        )
        .expect("net");
        let eth0 = net.get("eth0").expect("eth0");
        assert_eq!(eth0.rx_bytes, 1000);
        assert_eq!(eth0.rx_drops, 2);
        assert_eq!(eth0.tx_bytes, 2000);
        assert_eq!(eth0.tx_drops, 4);
    }

    #[test]
    fn diskstats_aggregates_whole_devices_only() {
        let disks = parse_diskstats(
            "   8       0 sda 10 0 100 5 20 0 200 10 0 15 20\n\
                8       1 sda1 8 0 80 4 16 0 160 8 0 12 16\n\
              259       0 nvme0n1 30 0 300 15 40 0 400 20 0 35 40\n\
              259       1 nvme0n1p1 10 0 100 5 20 0 200 10 0 15 20\n",
        )
        .expect("diskstats");
        let total = aggregate_disks(&disks);
        assert_eq!(total.read_bytes, (100 + 300) * 512);
        assert_eq!(total.write_bytes, (200 + 400) * 512);
        assert_eq!(total.reads, 40);
    }

    #[test]
    fn diskstats_tolerates_short_legacy_lines() {
        let disks = parse_diskstats("8 0 sda 1 2 3 4 5 6 7\n").expect("legacy");
        assert!(disks.is_empty());
    }

    #[test]
    fn pid_stat_handles_spaces_and_parentheses_in_comm() {
        let stat =
            "4242 (my (weird) worker) S 1 4242 4242 0 -1 4194560 100 0 5 0 11 12 0 0 20 0 3 0 900 123456 75 1\n";
        let parsed = parse_pid_stat(stat).expect("pid stat");
        assert_eq!(parsed.pid, 4242);
        assert_eq!(parsed.comm, "my (weird) worker");
        assert_eq!(parsed.state, 'S');
        assert_eq!(parsed.ppid, 1);
        assert_eq!(parsed.utime, 11);
        assert_eq!(parsed.stime, 12);
        assert_eq!(parsed.threads, 3);
        assert_eq!(parsed.start_ticks, 900);
        assert_eq!(parsed.vsize, 123_456);
        assert_eq!(parsed.rss_pages, 75);
    }

    #[test]
    fn pid_stat_rejects_truncated_and_unbalanced_input() {
        assert!(parse_pid_stat("1 (x) R 0 1").is_err());
        assert!(parse_pid_stat("1 (x R 0 1 2").is_err());
        assert!(parse_pid_stat("notapid (x) R 0").is_err());
    }

    #[test]
    fn pid_status_and_io_parse() {
        let status =
            parse_pid_status("Name:\tnginx\nThreads:\t4\nVmRSS:\t  2048 kB\nVmSize:\t 4096 kB\n")
                .expect("status");
        assert_eq!(status.name.as_deref(), Some("nginx"));
        assert_eq!(status.threads, Some(4));
        assert_eq!(status.vm_rss_bytes, Some(2_097_152));
        let io = parse_pid_io(
            "rchar: 10\nwchar: 20\nsyscr: 3\nsyscw: 4\nread_bytes: 5\nwrite_bytes: 6\n",
        )
        .expect("io");
        assert_eq!(io.rchar, 10);
        assert_eq!(io.write_bytes, 6);
        assert!(parse_pid_io("nothing: 1\n").is_err());
    }

    #[test]
    fn cgroup_membership_and_mountinfo() {
        assert_eq!(
            parse_cgroup_membership("0::/system.slice/nginx.service\n"),
            Some("/system.slice/nginx.service".to_string())
        );
        assert_eq!(parse_cgroup_membership("12:cpu:/legacy\n"), None);
        let mount =
            parse_cgroup2_mount("36 25 0:32 / /sys/fs/cgroup rw,nosuid - cgroup2 cgroup2 rw\n")
                .expect("mount");
        assert_eq!(mount, PathBuf::from("/sys/fs/cgroup"));
        assert_eq!(
            parse_cgroup2_mount("36 25 0:32 / /sys/fs/cgroup/x\\040y rw - cgroup2 cgroup2 rw\n"),
            Some(PathBuf::from("/sys/fs/cgroup/x y"))
        );
    }

    #[test]
    fn cgroup_stat_parsers_are_total() {
        let cpu = parse_cgroup_cpu_stat(
            "usage_usec 1234\nuser_usec 1000\nsystem_usec 234\nnr_periods 5\n\
             nr_throttled 2\nthrottled_usec 99\n",
        )
        .expect("cpu.stat");
        assert_eq!(cpu.usage_usec, Some(1234));
        assert_eq!(cpu.throttled_usec, Some(99));
        assert!(parse_cgroup_cpu_stat("user_usec 1\n").is_err());

        let (anon, file) = parse_cgroup_memory_stat("anon 100\nfile 200\nslab 9\n").expect("mem");
        assert_eq!(anon, Some(100));
        assert_eq!(file, Some(200));

        let io = parse_cgroup_io_stat("8:0 rbytes=10 wbytes=20 rios=1 wios=2 dbytes=0 dios=0\n")
            .expect("io.stat");
        assert_eq!(io.len(), 1);
        assert_eq!(io[0].read_bytes, Some(10));
        assert_eq!(io[0].write_ops, Some(2));
    }

    #[test]
    fn cpu_max_handles_unlimited_quota() {
        assert_eq!(
            parse_cpu_max("max 100000\n").expect("max"),
            (None, Some(100_000))
        );
        assert_eq!(
            parse_cpu_max("50000 100000\n").expect("quota"),
            (Some(50_000), Some(100_000))
        );
        assert!(parse_cpu_max("garbage\n").is_err());
    }

    #[test]
    fn bounded_reader_rejects_oversized_files() {
        let dir = std::env::temp_dir().join(format!("sarf-procfs-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("big");
        std::fs::write(&path, "x".repeat(128)).expect("write");
        let err = read_text_bounded(&path, 16).expect_err("must bound");
        assert!(matches!(err, Error::Capacity { .. }));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn partition_parent_detection_is_conservative() {
        assert_eq!(parent_device("sda1"), Some("sda".to_string()));
        assert_eq!(parent_device("nvme0n1p2"), Some("nvme0n1".to_string()));
        assert_eq!(parent_device("mmcblk0p1"), Some("mmcblk0".to_string()));
        assert_eq!(parent_device("sda"), None);
        assert_eq!(parent_device("nvme0n1"), None);
        assert_eq!(parent_device("loop0"), None);
    }
}
