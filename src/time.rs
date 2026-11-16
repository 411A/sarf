//! Dual-clock model: wall-clock UTC nanoseconds and a monotonic clock domain.
//!
//! The guide (§7) requires that reports never conflate four different notions:
//! storage precision, source clock resolution, measurement resolution and
//! observation frequency. SARF therefore persists both a wall-clock timestamp
//! (for humans and log correlation) and a monotonic timestamp (for interval maths
//! and ordering), plus the domain that produced the monotonic value.
//!
//! * On Unix the monotonic clock is `CLOCK_MONOTONIC` (boot-relative, documented
//!   domain `clock_monotonic`). This is the only `unsafe` code in the crate.
//! * On other platforms (used for fixture-driven tests and the CLI/report code
//!   paths) the fallback is a process-relative `std::time::Instant` with domain
//!   `std_instant`. It is monotonic but not boot-relative; the domain is stored so
//!   reports can say so.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Nanoseconds since the Unix epoch (wall clock, UTC).
pub type WallNs = i64;
/// Nanoseconds on the active monotonic clock domain.
pub type MonoNs = i64;

/// A monotonic clock domain name as persisted in the database.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClockDomain {
    /// Linux `CLOCK_MONOTONIC`, boot-relative.
    ClockMonotonic,
    /// Process-relative `std::time::Instant` fallback.
    #[default]
    StdInstant,
    /// Synthetic domain used by deterministic tests and fixture replay.
    Simulated,
}

impl ClockDomain {
    /// Stable database/API string.
    pub const fn as_str(self) -> &'static str {
        match self {
            ClockDomain::ClockMonotonic => "clock_monotonic",
            ClockDomain::StdInstant => "std_instant",
            ClockDomain::Simulated => "simulated",
        }
    }

    /// Whether this domain is boot-relative and therefore comparable across
    /// processes on the same boot.
    pub const fn is_boot_relative(self) -> bool {
        matches!(self, ClockDomain::ClockMonotonic)
    }
}

/// Source of time for the daemon and for deterministic tests.
///
/// The trait is the seam that lets the end-to-end tests drive a full daemon run
/// through simulated time instead of sleeping for real seconds.
pub trait Clock: Send + Sync {
    /// Wall-clock nanoseconds since the Unix epoch.
    fn wall_ns(&self) -> WallNs;
    /// Monotonic nanoseconds on the domain reported by [`Clock::domain`].
    fn mono_ns(&self) -> MonoNs;
    /// Domain that qualifies [`Clock::mono_ns`].
    fn domain(&self) -> ClockDomain;
    /// Sleep for `duration`, advancing time. Simulated clocks advance instantly.
    fn sleep(&self, duration: Duration);
}

/// Both clocks plus the identity context needed to interpret them.
///
/// `boot_id` scopes the monotonic value (it resets across reboots) and `domain`
/// records which monotonic clock produced it, as required by guide §7.2.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Stamps {
    /// Wall-clock UTC nanoseconds.
    pub wall: WallNs,
    /// Monotonic nanoseconds.
    pub mono: MonoNs,
    /// Kernel boot id (or simulated boot id) that scopes `mono`.
    pub boot_id: String,
    /// Monotonic clock domain.
    pub domain: ClockDomain,
}

impl Stamps {
    /// Build a full timestamp pair.
    pub fn new(
        wall: WallNs,
        mono: MonoNs,
        boot_id: impl Into<String>,
        domain: ClockDomain,
    ) -> Self {
        Stamps {
            wall,
            mono,
            boot_id: boot_id.into(),
            domain,
        }
    }

    /// Capture both clocks from a clock into full stamps.
    pub fn capture(clock: &dyn Clock, boot_id: &str) -> Self {
        Stamps {
            wall: clock.wall_ns(),
            mono: clock.mono_ns(),
            boot_id: boot_id.to_string(),
            domain: clock.domain(),
        }
    }

    /// Whether the monotonic value can be compared across processes on this boot.
    pub fn is_boot_scoped(&self) -> bool {
        self.domain.is_boot_relative() && !self.boot_id.is_empty()
    }
}

/// The real system clock.
#[derive(Debug, Clone)]
pub struct SystemClock {
    /// Monotonic value captured when the process started; used on non-Unix hosts.
    epoch: std::time::Instant,
}

impl SystemClock {
    /// Create a clock anchored at process start.
    pub fn new() -> Self {
        SystemClock {
            epoch: std::time::Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(unix)]
fn monotonic_ns_unix() -> MonoNs {
    // SAFETY: `clock_gettime` with a valid `timespec` pointer and a constant clock id
    // is a read-only syscall wrapper. It is the single documented `unsafe` use in SARF.
    #[allow(unsafe_code)]
    unsafe {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        if libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) != 0 {
            // Extremely unlikely: fall back to a process-relative reading.
            return -1;
        }
        ts.tv_sec as i64 * 1_000_000_000 + ts.tv_nsec as i64
    }
}

impl Clock for SystemClock {
    fn wall_ns(&self) -> WallNs {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0)
    }

    fn mono_ns(&self) -> MonoNs {
        #[cfg(unix)]
        {
            let value = monotonic_ns_unix();
            if value >= 0 {
                return value;
            }
        }
        self.epoch.elapsed().as_nanos() as i64
    }

    fn domain(&self) -> ClockDomain {
        #[cfg(unix)]
        {
            if monotonic_ns_unix() >= 0 {
                return ClockDomain::ClockMonotonic;
            }
        }
        ClockDomain::StdInstant
    }

    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

/// Deterministic clock for tests: sleep advances simulated time instantly.
#[derive(Debug, Clone)]
pub struct FakeClock {
    wall: Arc<AtomicI64>,
    mono: Arc<AtomicI64>,
}

impl FakeClock {
    /// Start a fake clock at the given wall/monotonic timestamps.
    pub fn new(wall_ns: WallNs, mono_ns: MonoNs) -> Self {
        FakeClock {
            wall: Arc::new(AtomicI64::new(wall_ns)),
            mono: Arc::new(AtomicI64::new(mono_ns)),
        }
    }

    /// Start at a fixed realistic timestamp: 2026-01-01T00:00:00Z, mono 1 hour.
    pub fn standard() -> Self {
        Self::new(1_767_225_600_000_000_000, 3_600_000_000_000)
    }

    /// Advance both clocks by `duration`.
    pub fn advance(&self, duration: Duration) {
        let delta = duration.as_nanos() as i64;
        self.wall.fetch_add(delta, Ordering::SeqCst);
        self.mono.fetch_add(delta, Ordering::SeqCst);
    }

    /// Set only the wall clock (to model an NTP correction) without moving monotonic time.
    pub fn set_wall(&self, wall_ns: WallNs) {
        self.wall.store(wall_ns, Ordering::SeqCst);
    }
}

impl Clock for FakeClock {
    fn wall_ns(&self) -> WallNs {
        self.wall.load(Ordering::SeqCst)
    }

    fn mono_ns(&self) -> MonoNs {
        self.mono.load(Ordering::SeqCst)
    }

    fn domain(&self) -> ClockDomain {
        ClockDomain::Simulated
    }

    fn sleep(&self, duration: Duration) {
        self.advance(duration);
    }
}

/// A clock handle shared between collectors and the daemon.
pub type SharedClock = Arc<dyn Clock>;

/// Convenience constructor for the production clock.
pub fn system_clock() -> SharedClock {
    Arc::new(SystemClock::new())
}

/// Wall-clock timestamp to RFC 3339 in the machine's local time zone.
pub fn format_wall_local(wall_ns: WallNs) -> String {
    match chrono::DateTime::from_timestamp(
        wall_ns / 1_000_000_000,
        (wall_ns % 1_000_000_000) as u32,
    ) {
        Some(utc) => utc
            .with_timezone(&chrono::Local)
            .format("%Y-%m-%d %H:%M:%S%.3f %Z")
            .to_string(),
        None => format!("invalid timestamp {wall_ns}"),
    }
}

/// Wall-clock timestamp to a compact local `HH:MM:SS` label (report axes).
pub fn format_wall_clock(wall_ns: WallNs) -> String {
    match chrono::DateTime::from_timestamp(
        wall_ns / 1_000_000_000,
        (wall_ns % 1_000_000_000) as u32,
    ) {
        Some(utc) => utc
            .with_timezone(&chrono::Local)
            .format("%H:%M:%S")
            .to_string(),
        None => "--:--:--".to_string(),
    }
}

/// Wall-clock timestamp to RFC 3339 in UTC (stable across machines).
pub fn format_wall_rfc3339(wall_ns: WallNs) -> String {
    match chrono::DateTime::from_timestamp(
        wall_ns / 1_000_000_000,
        (wall_ns % 1_000_000_000) as u32,
    ) {
        Some(utc) => utc.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        None => "invalid".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_clock_sleep_is_instant_and_consistent() {
        let clock = FakeClock::standard();
        let wall = clock.wall_ns();
        let mono = clock.mono_ns();
        let start = std::time::Instant::now();
        clock.sleep(Duration::from_secs(5));
        assert!(start.elapsed() < Duration::from_millis(50));
        assert_eq!(clock.wall_ns() - wall, 5_000_000_000);
        assert_eq!(clock.mono_ns() - mono, 5_000_000_000);
    }

    #[test]
    fn fake_clock_supports_wall_corrections_without_moving_monotonic() {
        let clock = FakeClock::standard();
        let mono = clock.mono_ns();
        clock.set_wall(clock.wall_ns() - 1_000_000_000);
        assert_eq!(clock.mono_ns(), mono);
    }

    #[test]
    fn domains_are_stable_and_documented() {
        assert_eq!(ClockDomain::ClockMonotonic.as_str(), "clock_monotonic");
        assert!(ClockDomain::ClockMonotonic.is_boot_relative());
        assert!(!ClockDomain::Simulated.is_boot_relative());
    }

    #[test]
    fn system_clock_is_monotonic_across_reads() {
        let clock = SystemClock::new();
        let a = clock.mono_ns();
        let b = clock.mono_ns();
        assert!(b >= a);
    }

    #[test]
    fn wall_formatting_is_bounded_and_parseable() {
        let text = format_wall_rfc3339(1_767_225_600_000_000_000);
        assert!(text.starts_with("2026-01-01T00:00:00"));
        // Local time zone of the test host may differ; only assert the stable shape.
        let clock = format_wall_clock(1_767_225_600_000_000_000);
        assert_eq!(clock.len(), 8, "expected HH:MM:SS, got {clock}");
        assert_eq!(clock.matches(':').count(), 2);
        assert!(!format_wall_local(1_767_225_600_000_000_000).is_empty());
    }

    #[test]
    fn stamps_pair_comes_from_a_trait_object() {
        let clock: SharedClock = Arc::new(FakeClock::standard());
        let stamps = Stamps::capture(clock.as_ref(), "test-boot");
        assert!(stamps.wall > 0 && stamps.mono > 0);
        assert_eq!(stamps.boot_id, "test-boot");
        assert_eq!(stamps.domain, ClockDomain::Simulated);
        assert!(
            !stamps.is_boot_scoped(),
            "simulated clocks are not boot-relative"
        );
    }
}
