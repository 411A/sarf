//! Host-wide `/proc` sampling.
//!
//! One cycle reads only cheap kernel-maintained counters (guide §5.1). Optional
//! sources (PSI, net, disk, uptime) may be absent on constrained kernels; their
//! fields stay `None` and [`HostCapabilities`] records exactly what was present.

use crate::error::Result;
use crate::model::{HostSample, NetCounters};
use crate::time::Stamps;

use super::procfs::{self, read_optional};
use super::SourceRoot;

/// Which optional host interfaces exist on this host/fixture.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HostCapabilities {
    /// `/proc/pressure/cpu`
    pub pressure_cpu: bool,
    /// `/proc/pressure/memory`
    pub pressure_memory: bool,
    /// `/proc/pressure/io`
    pub pressure_io: bool,
    /// `/proc/net/dev`
    pub net_dev: bool,
    /// `/proc/diskstats`
    pub diskstats: bool,
    /// `/proc/uptime`
    pub uptime: bool,
    /// `/proc/loadavg`
    pub loadavg: bool,
}

impl HostCapabilities {
    /// Probe the source root without reading the large files.
    pub fn detect(root: &SourceRoot) -> Self {
        HostCapabilities {
            pressure_cpu: root.proc_path("pressure/cpu").is_file(),
            pressure_memory: root.proc_path("pressure/memory").is_file(),
            pressure_io: root.proc_path("pressure/io").is_file(),
            net_dev: root.proc_path("net/dev").is_file(),
            diskstats: root.proc_path("diskstats").is_file(),
            uptime: root.proc_path("uptime").is_file(),
            loadavg: root.proc_path("loadavg").is_file(),
        }
    }

    /// Human-readable list of missing optional sources, for coverage gaps.
    pub fn missing(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if !self.pressure_cpu {
            missing.push("pressure/cpu");
        }
        if !self.pressure_memory {
            missing.push("pressure/memory");
        }
        if !self.pressure_io {
            missing.push("pressure/io");
        }
        if !self.net_dev {
            missing.push("net/dev");
        }
        if !self.diskstats {
            missing.push("diskstats");
        }
        if !self.loadavg {
            missing.push("loadavg");
        }
        missing
    }
}

/// Host sampler over one [`SourceRoot`].
#[derive(Debug, Clone)]
pub struct HostCollector {
    root: SourceRoot,
}

impl HostCollector {
    /// Create a collector.
    pub fn new(root: SourceRoot) -> Self {
        HostCollector { root }
    }

    /// Probe optional interfaces.
    pub fn capabilities(&self) -> HostCapabilities {
        HostCapabilities::detect(&self.root)
    }

    /// Collect one host sample.
    ///
    /// `/proc/stat` and `/proc/meminfo` are required: without them there is no host
    /// accounting and the cycle fails with a typed error. Every other source is
    /// optional and leaves its field `None`/empty.
    pub fn sample(&self, stamps: Stamps) -> Result<HostSample> {
        let stat_text = self.root.read_proc("stat")?;
        let stat = procfs::parse_stat(&stat_text)?;
        let mem = procfs::parse_meminfo(&self.root.read_proc("meminfo")?)?;
        let load = self
            .root
            .read_proc_opt("loadavg")
            .and_then(|text| procfs::parse_loadavg(&text).ok())
            .unwrap_or_default();
        let pressure = procfs::parse_host_pressure(
            self.root.read_proc_opt("pressure/cpu").as_deref(),
            self.root.read_proc_opt("pressure/memory").as_deref(),
            self.root.read_proc_opt("pressure/io").as_deref(),
        );
        let net = self
            .root
            .read_proc_opt("net/dev")
            .and_then(|text| procfs::parse_net_dev(&text).ok())
            .unwrap_or_default();
        let disk = self
            .root
            .read_proc_opt("diskstats")
            .and_then(|text| procfs::parse_diskstats(&text).ok())
            .unwrap_or_default();
        let uptime_secs = self
            .root
            .read_proc_opt("uptime")
            .and_then(|text| procfs::parse_uptime(&text).ok());
        Ok(HostSample {
            stamps,
            cpu: stat.cpu,
            per_cpu: stat.per_cpu,
            mem,
            load,
            pressure,
            net,
            disk,
            procs_running: stat.procs_running,
            procs_blocked: stat.procs_blocked,
            uptime_secs,
            boot_time_secs: stat.btime,
        })
    }

    /// Sum network counters across interfaces, excluding loopback.
    ///
    /// Loopback is excluded from the host total because it does not represent
    /// external traffic and can dominate byte counters on busy local stacks.
    pub fn net_totals(sample: &HostSample) -> NetCounters {
        let mut total = NetCounters::default();
        for (name, counters) in &sample.net {
            if name == "lo" {
                continue;
            }
            total.rx_bytes = total.rx_bytes.saturating_add(counters.rx_bytes);
            total.rx_packets = total.rx_packets.saturating_add(counters.rx_packets);
            total.rx_errors = total.rx_errors.saturating_add(counters.rx_errors);
            total.rx_drops = total.rx_drops.saturating_add(counters.rx_drops);
            total.tx_bytes = total.tx_bytes.saturating_add(counters.tx_bytes);
            total.tx_packets = total.tx_packets.saturating_add(counters.tx_packets);
            total.tx_errors = total.tx_errors.saturating_add(counters.tx_errors);
            total.tx_drops = total.tx_drops.saturating_add(counters.tx_drops);
        }
        total
    }
}

/// Read a small procfs string such as hostname, bounded and trimmed.
pub fn read_trimmed(root: &SourceRoot, relative: &str) -> Option<String> {
    read_optional(&root.proc_path(relative))
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::{ClockDomain, Stamps};

    fn stamps(wall: i64) -> Stamps {
        Stamps::new(wall, wall, "boot-host", ClockDomain::Simulated)
    }

    fn write(root: &std::path::Path, relative: &str, content: &str) {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("dirs");
        std::fs::write(path, content).expect("write");
    }

    #[test]
    fn samples_real_like_fixture_tree() {
        let dir = std::env::temp_dir().join(format!("sarf-host-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        write(
            &dir,
            "proc/stat",
            "cpu 10 0 5 100 0 1 2 3 0 0\ncpu0 5 0 2 50 0 1 1 1 0 0\n\
             procs_running 2\nprocs_blocked 0\nbtime 1000\n",
        );
        write(
            &dir,
            "proc/meminfo",
            "MemTotal: 1000 kB\nMemAvailable: 400 kB\nSwapTotal: 0 kB\n",
        );
        write(&dir, "proc/loadavg", "0.5 0.4 0.3 1/2 99\n");
        write(
            &dir,
            "proc/pressure/cpu",
            "some avg10=2.0 avg60=1.0 avg300=0.5 total=100\n",
        );
        write(
            &dir,
            "proc/net/dev",
            "eth0: 100 1 0 0 0 0 0 0 200 2 0 0 0 0 0 0\n",
        );
        write(&dir, "proc/diskstats", "8 0 sda 1 0 2 0 3 0 4 0 0 0 0\n");
        write(&dir, "proc/uptime", "123.5 100.0\n");
        let collector = HostCollector::new(SourceRoot::fixture(&dir));
        assert!(collector.capabilities().pressure_cpu);
        assert!(!collector.capabilities().pressure_memory);
        let sample = collector.sample(stamps(42)).expect("sample");
        assert_eq!(sample.cpu.user, 10);
        assert_eq!(sample.mem.total, 1_024_000);
        assert_eq!(sample.mem.used(), Some(614_400));
        assert_eq!(sample.pressure.cpu.expect("cpu psi").some_avg10, Some(2.0));
        assert!(sample.pressure.memory.is_none());
        assert_eq!(sample.disk["sda"].read_bytes, 1024);
        let net = HostCollector::net_totals(&sample);
        assert_eq!(net.rx_bytes, 100);
        assert_eq!(net.tx_bytes, 200);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_required_files_are_typed_errors() {
        let dir = std::env::temp_dir().join(format!("sarf-host-empty-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("proc")).expect("dirs");
        let collector = HostCollector::new(SourceRoot::fixture(&dir));
        let err = collector.sample(stamps(1)).expect_err("must fail");
        assert!(matches!(err, crate::error::Error::Io { .. }));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
