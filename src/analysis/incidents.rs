//! Bounded threshold incidents with hysteresis, deduplication and cooldowns.
//!
//! The engine consumes [`Signal`] observations that already carry an absolute
//! `threshold` and a relative `baseline` (typically an [`crate::analysis::ewma::Ewma`]
//! mean). It opens an incident only after several consecutive qualifying samples,
//! never opens a second incident for the same entity/metric while one is open, and
//! closes it after a configurable recovery hysteresis or a forced maximum duration.
//!
//! Key properties:
//!
//! * Missing or non-finite values are ignored; they never count towards the
//!   consecutive-sample requirement and never become "zero activity".
//! * Incidents are *observations*: the evidence JSON says
//!   `"note": "temporal association only"` and never claims causation.
//! * Only **high** usage opens incidents. Low usage is reported by
//!   [`crate::analysis::correlation`] as a low attribution window, because a quiet
//!   service is not an error and should not create an incident record.
//! * Every text and payload is bounded, and incident ids are pre-allocated by the
//!   caller so the daemon can write a row without a second lookup.

use std::collections::HashMap;

use crate::config::Config;
use crate::model::{EventKind, EventRecord, Incident, Metric, Severity};
use crate::store::truncate_utf8;
use crate::time::WallNs;

/// Consecutive qualifying samples required before a new incident opens.
const CONSECUTIVE_SAMPLES: u32 = 3;
/// The observation must also exceed this multiple of the relative baseline.
const BASELINE_MARGIN: f64 = 1.2;
/// Absolute guard for the relative test so a zero baseline cannot open on noise.
const OPEN_EPSILON: f64 = 1e-9;
/// Observations at or below this magnitude are treated as numerical noise.
const NOISE_FLOOR: f64 = 1e-6;
/// Recovery starts below this fraction of the opening threshold (hysteresis).
const RECOVERY_FACTOR: f64 = 0.8;
/// Minimum cooldown after a close before the same key may open again.
const MIN_COOLDOWN_SECS: u64 = 300;
/// Maximum bytes kept for a human-readable reason or event string.
const MAX_TEXT_BYTES: usize = 240;
/// Provenance recorded on every event emitted by this engine.
const PROVENANCE: &str = "analysis";
/// Synthetic entity key used when a signal has no entity id.
const HOST_KEY: &str = "host";
/// Close reason used when the configured maximum duration was reached.
const REASON_BOUNDED: &str = "bounded incident duration";
/// Close reason used after a sustained recovery below the hysteresis threshold.
const REASON_RECOVERED: &str = "recovered below threshold (hysteresis)";

/// One observation fed into the incident engine.
///
/// The caller supplies both the absolute `threshold` and a relative `baseline`
/// because SARF deliberately combines them (guide §10.2); the engine does not
/// decide thresholds itself.
#[derive(Debug, Clone)]
pub struct Signal {
    /// Entity the observation belongs to; `None` means the host.
    pub entity_id: Option<String>,
    /// Metric observed.
    pub metric: Metric,
    /// Observed value in the metric's natural unit.
    pub value: f64,
    /// Relative baseline for this metric (0 when unknown).
    pub baseline: f64,
    /// Absolute threshold that must also be crossed.
    pub threshold: f64,
    /// Wall-clock time of the observation.
    pub wall_ns: WallNs,
    /// Human-readable reason, bounded by the engine before storage.
    pub reason: String,
}

/// One incident update applied by the daemon.
///
/// The tuple is `(incident_id, ended_wall_ns, peak, evidence, evidence_loss)`.
pub type IncidentUpdate = (i64, Option<i64>, f64, Option<serde_json::Value>, bool);

/// Engine output: records to persist and events implied.
///
/// The daemon writes `opened` incidents, applies `updated` rows (see
/// [`IncidentUpdate`]) and appends `events`. Every list is bounded by the number of
/// open incidents.
#[derive(Debug, Clone, Default)]
pub struct IncidentPulse {
    /// Incidents that must be inserted (ids are pre-allocated).
    pub opened: Vec<Incident>,
    /// Incident updates: see [`IncidentUpdate`].
    pub updated: Vec<IncidentUpdate>,
    /// Events implied by opens and closes.
    pub events: Vec<EventRecord>,
}

/// Per-key lifecycle state.
#[derive(Debug, Default)]
struct KeyState {
    /// Consecutive qualifying observations not yet enough to open.
    pending: u32,
    /// Wall clock of the first observation in the pending run.
    pending_since_wall_ns: Option<WallNs>,
    /// Currently open incident for this key.
    open: Option<OpenIncident>,
    /// Wall clock of the last close (starts the cooldown).
    last_closed_wall_ns: Option<WallNs>,
    /// Whether an open incident needs a peak update written.
    dirty: bool,
}

/// Open-incident state retained between observations.
#[derive(Debug, Clone)]
struct OpenIncident {
    /// Database id, pre-allocated from the engine's counter.
    incident_id: i64,
    /// Start of the incident, wall clock.
    started_wall_ns: WallNs,
    /// Entity the incident belongs to; `None` means the host.
    entity_id: Option<String>,
    /// Metric observed.
    metric: Metric,
    /// Highest value observed while open.
    peak: f64,
    /// Baseline captured at open.
    baseline: f64,
    /// Threshold captured at open (used for hysteresis).
    threshold: f64,
    /// Number of observations folded into the incident.
    samples: u64,
    /// Last observation, wall clock.
    last_seen_wall_ns: WallNs,
    /// First time the value dropped below the recovery threshold, if still below.
    below_since_wall_ns: Option<WallNs>,
}

/// Threshold incident engine.
///
/// The engine is intentionally synchronous and single-threaded: the daemon feeds
/// it observations on the sampling thread and drains [`IncidentEngine::take_pulse`]
/// into the bounded writer queue.
#[derive(Debug)]
pub struct IncidentEngine {
    /// State per `(entity-or-host, metric)`.
    states: HashMap<(String, Metric), KeyState>,
    /// Next incident id to hand out.
    next_id: i64,
    /// Recovery hysteresis in nanoseconds.
    hysteresis_ns: i64,
    /// Forced maximum incident duration in nanoseconds.
    max_incident_ns: i64,
    /// Suppression window after a close in nanoseconds.
    cooldown_ns: i64,
    /// Accumulated output not yet drained.
    pulse: IncidentPulse,
}

impl IncidentEngine {
    /// Build an engine from validated configuration.
    ///
    /// `first_id` is the first incident id to allocate; callers pass
    /// `Store::max_incident_id() + 1` so ids stay unique across daemon restarts.
    /// The cooldown is the larger of `adaptive.recovery_hysteresis_secs` and five
    /// minutes, so a flapping metric cannot create an incident every few seconds.
    pub fn new(config: &Config, first_id: i64) -> Self {
        let hysteresis_secs = config.adaptive.recovery_hysteresis_secs;
        let cooldown_secs = hysteresis_secs.max(MIN_COOLDOWN_SECS);
        Self {
            states: HashMap::new(),
            next_id: first_id.max(0),
            hysteresis_ns: secs_to_ns(hysteresis_secs),
            max_incident_ns: secs_to_ns(config.adaptive.max_incident_secs),
            cooldown_ns: secs_to_ns(cooldown_secs),
            pulse: IncidentPulse::default(),
        }
    }

    /// Feed one observation.
    ///
    /// Returns `Some` **only** when a new incident opened, so the caller writes a
    /// new row exactly once. Updates to an already-open incident accumulate
    /// internally and are drained by [`IncidentEngine::take_pulse`] or
    /// [`IncidentEngine::tick`].
    #[allow(
        clippy::needless_pass_by_value,
        reason = "a Signal is a small per-observation value built by the caller; the \
                  engine reads it once and drops it, so taking ownership keeps the \
                  public observation API lifetime-free"
    )]
    pub fn observe(&mut self, signal: Signal) -> Option<Incident> {
        if !signal.value.is_finite() {
            return None;
        }
        let entity_key = signal
            .entity_id
            .clone()
            .unwrap_or_else(|| HOST_KEY.to_string());
        let key = (entity_key, signal.metric);
        let now = signal.wall_ns;
        let qualifying = Self::qualifies(&signal);
        let cooldown_ns = self.cooldown_ns;
        let next_id = &mut self.next_id;
        let pulse = &mut self.pulse;
        let state = self.states.entry(key).or_default();

        if let Some(open) = state.open.as_mut() {
            open.samples = open.samples.saturating_add(1);
            open.last_seen_wall_ns = now;
            if signal.value > open.peak {
                open.peak = signal.value;
            }
            if signal.value < open.threshold * RECOVERY_FACTOR {
                if open.below_since_wall_ns.is_none() {
                    open.below_since_wall_ns = Some(now);
                }
            } else {
                open.below_since_wall_ns = None;
            }
            state.dirty = true;
            return None;
        }

        if !qualifying {
            state.pending = 0;
            state.pending_since_wall_ns = None;
            return None;
        }

        if let Some(closed) = state.last_closed_wall_ns {
            if now.saturating_sub(closed) < cooldown_ns {
                state.pending = 0;
                state.pending_since_wall_ns = None;
                return None;
            }
        }

        state.pending = state.pending.saturating_add(1);
        if state.pending == 1 {
            state.pending_since_wall_ns = Some(now);
        }
        if state.pending < CONSECUTIVE_SAMPLES {
            return None;
        }
        state.pending = 0;
        let first_seen = state.pending_since_wall_ns.take().unwrap_or(now);

        let incident_id = *next_id;
        *next_id = next_id.saturating_add(1);
        let incident = Incident {
            incident_id: Some(incident_id),
            started_wall_ns: now,
            ended_wall_ns: None,
            entity_id: signal.entity_id.clone(),
            metric: signal.metric,
            reason: bounded_reason(&signal.reason),
            peak: signal.value,
            baseline: signal.baseline,
            evidence: open_evidence(&signal, first_seen, now),
            acknowledged: false,
            evidence_loss: false,
        };
        state.open = Some(OpenIncident {
            incident_id,
            started_wall_ns: now,
            entity_id: signal.entity_id.clone(),
            metric: signal.metric,
            peak: signal.value,
            baseline: signal.baseline,
            threshold: signal.threshold,
            samples: u64::from(CONSECUTIVE_SAMPLES),
            last_seen_wall_ns: now,
            below_since_wall_ns: None,
        });
        pulse.opened.push(incident.clone());
        pulse.events.push(opened_event(&incident, &signal));
        Some(incident)
    }

    /// Close recovered or over-long incidents and drain accumulated output.
    ///
    /// An incident closes when the observed value stayed below
    /// `threshold * 0.8` for the configured recovery hysteresis, or when it has
    /// been open for `adaptive.max_incident_secs` (a bounded evidence window must
    /// never grow without limit).
    pub fn tick(&mut self, now_wall_ns: WallNs) -> IncidentPulse {
        let hysteresis_ns = self.hysteresis_ns;
        let max_incident_ns = self.max_incident_ns;
        for state in self.states.values_mut() {
            let Some(open) = state.open.take() else {
                continue;
            };
            let duration_ns = now_wall_ns.saturating_sub(open.started_wall_ns);
            let recovered = open
                .below_since_wall_ns
                .is_some_and(|since| now_wall_ns.saturating_sub(since) >= hysteresis_ns);
            let bounded = duration_ns >= max_incident_ns;
            if !recovered && !bounded {
                state.open = Some(open);
                continue;
            }
            let close_reason = if bounded {
                REASON_BOUNDED
            } else {
                REASON_RECOVERED
            };
            let evidence = closed_evidence(&open, now_wall_ns, close_reason);
            self.pulse.updated.push((
                open.incident_id,
                Some(now_wall_ns),
                open.peak,
                Some(evidence),
                false,
            ));
            self.pulse
                .events
                .push(closed_event(&open, now_wall_ns, close_reason));
            state.last_closed_wall_ns = Some(now_wall_ns);
            state.pending = 0;
            state.pending_since_wall_ns = None;
            state.dirty = false;
        }
        self.take_pulse()
    }

    /// Drain accumulated opens, updates and events.
    ///
    /// Peak updates for still-open incidents are generated here so a caller that
    /// only polls occasionally still persists the highest observed value.
    pub fn take_pulse(&mut self) -> IncidentPulse {
        self.flush_updates();
        std::mem::take(&mut self.pulse)
    }

    /// Number of incidents currently open.
    pub fn open_count(&self) -> usize {
        self.states
            .values()
            .filter(|state| state.open.is_some())
            .count()
    }

    /// Queue one peak update per open incident that changed since the last drain.
    fn flush_updates(&mut self) {
        for state in self.states.values_mut() {
            if !state.dirty {
                continue;
            }
            state.dirty = false;
            if let Some(open) = state.open.as_ref() {
                self.pulse
                    .updated
                    .push((open.incident_id, None, open.peak, None, false));
            }
        }
    }

    /// Absolute threshold plus relative margin over the baseline.
    fn qualifies(signal: &Signal) -> bool {
        signal.value.is_finite()
            && signal.value > NOISE_FLOOR
            && signal.value >= signal.threshold
            && signal.value > signal.baseline.mul_add(BASELINE_MARGIN, OPEN_EPSILON)
    }
}

/// Convert seconds to nanoseconds without wrapping.
fn secs_to_ns(secs: u64) -> i64 {
    i64::try_from(secs.saturating_mul(1_000_000_000)).unwrap_or(i64::MAX)
}

/// Trim and bound a human-readable reason.
fn bounded_reason(reason: &str) -> String {
    let trimmed = reason.trim();
    if trimmed.is_empty() {
        return "observed above threshold and baseline".to_string();
    }
    truncate_utf8(trimmed, MAX_TEXT_BYTES).0
}

/// Severity assigned to the events of a metric.
const fn severity_for(metric: Metric) -> Severity {
    match metric {
        Metric::Cpu | Metric::Memory | Metric::PsiCpu | Metric::PsiMemory | Metric::PsiIo => {
            Severity::Warn
        }
        _ => Severity::Info,
    }
}

/// Evidence JSON written when an incident opens.
fn open_evidence(signal: &Signal, first_seen: WallNs, now: WallNs) -> serde_json::Value {
    serde_json::json!({
        "engine": "threshold+ewma",
        "threshold": signal.threshold,
        "baseline": signal.baseline,
        "samples": CONSECUTIVE_SAMPLES,
        "first_seen": first_seen,
        "last_seen": now,
        "note": "temporal association only"
    })
}

/// Evidence JSON written when an incident closes.
fn closed_evidence(open: &OpenIncident, now: WallNs, close_reason: &str) -> serde_json::Value {
    serde_json::json!({
        "engine": "threshold+ewma",
        "close_reason": close_reason,
        "baseline": open.baseline,
        "threshold": open.threshold,
        "peak": open.peak,
        "samples": open.samples,
        "first_seen": open.started_wall_ns,
        "last_seen": now,
        "note": "temporal association only"
    })
}

/// Event emitted when an incident opens.
fn opened_event(incident: &Incident, signal: &Signal) -> EventRecord {
    EventRecord {
        wall_ns: incident.started_wall_ns,
        mono_ns: None,
        entity_id: incident.entity_id.clone(),
        kind: EventKind::IncidentOpened,
        severity: severity_for(incident.metric),
        payload: serde_json::json!({
            "incident_id": incident.incident_id,
            "metric": incident.metric.as_str(),
            "entity_id": incident.entity_id,
            "reason": incident.reason,
            "threshold": signal.threshold,
            "baseline": signal.baseline,
            "observed": signal.value,
            "note": "temporal association only"
        }),
        provenance: PROVENANCE.to_string(),
        lost_before: 0,
    }
}

/// Event emitted when an incident closes.
fn closed_event(open: &OpenIncident, now: WallNs, close_reason: &str) -> EventRecord {
    EventRecord {
        wall_ns: now,
        mono_ns: None,
        entity_id: open.entity_id.clone(),
        kind: EventKind::IncidentClosed,
        severity: severity_for(open.metric),
        payload: serde_json::json!({
            "incident_id": open.incident_id,
            "metric": open.metric.as_str(),
            "entity_id": open.entity_id,
            "close_reason": close_reason,
            "peak": open.peak,
            "samples": open.samples,
            "duration_ns": now.saturating_sub(open.started_wall_ns),
            "note": "temporal association only"
        }),
        provenance: PROVENANCE.to_string(),
        lost_before: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signal(
        entity: &str,
        metric: Metric,
        value: f64,
        baseline: f64,
        threshold: f64,
        wall_ns: WallNs,
    ) -> Signal {
        Signal {
            entity_id: Some(entity.to_string()),
            metric,
            value,
            baseline,
            threshold,
            wall_ns,
            reason: "observed above threshold and baseline".to_string(),
        }
    }

    fn open_incident(engine: &mut IncidentEngine, entity: &str, wall_ns: WallNs) -> Incident {
        let mut opened = None;
        for offset in 0..CONSECUTIVE_SAMPLES {
            opened = engine.observe(signal(
                entity,
                Metric::Cpu,
                40.0,
                5.0,
                20.0,
                wall_ns + i64::from(offset),
            ));
        }
        opened.expect("incident opens after the consecutive-sample requirement")
    }

    #[test]
    fn opens_only_after_three_consecutive_samples() {
        let config = Config::default();
        let mut engine = IncidentEngine::new(&config, 1);
        let start = 1_000_000_000;
        assert!(engine
            .observe(signal("cgroup:1:2", Metric::Cpu, 40.0, 5.0, 20.0, start))
            .is_none());
        assert!(engine
            .observe(signal(
                "cgroup:1:2",
                Metric::Cpu,
                40.0,
                5.0,
                20.0,
                start + 1
            ))
            .is_none());
        assert_eq!(engine.open_count(), 0);
        let opened = engine
            .observe(signal(
                "cgroup:1:2",
                Metric::Cpu,
                40.0,
                5.0,
                20.0,
                start + 2,
            ))
            .expect("third sample opens the incident");
        assert_eq!(opened.incident_id, Some(1));
        assert_eq!(opened.started_wall_ns, start + 2);
        assert_eq!(opened.peak, 40.0);
        assert_eq!(engine.open_count(), 1);
        let pulse = engine.take_pulse();
        assert_eq!(pulse.opened.len(), 1);
        assert!(pulse
            .events
            .iter()
            .any(|event| event.kind == EventKind::IncidentOpened));
    }

    #[test]
    fn a_single_spike_does_not_open_an_incident() {
        let config = Config::default();
        let mut engine = IncidentEngine::new(&config, 1);
        assert!(engine
            .observe(signal("cgroup:1:2", Metric::Cpu, 40.0, 5.0, 20.0, 10))
            .is_none());
        // A quiet sample resets the consecutive-sample run.
        assert!(engine
            .observe(signal("cgroup:1:2", Metric::Cpu, 1.0, 5.0, 20.0, 11))
            .is_none());
        assert!(engine
            .observe(signal("cgroup:1:2", Metric::Cpu, 40.0, 5.0, 20.0, 12))
            .is_none());
        assert!(engine
            .observe(signal("cgroup:1:2", Metric::Cpu, 40.0, 5.0, 20.0, 13))
            .is_none());
        assert_eq!(engine.open_count(), 0);
    }

    #[test]
    fn an_open_incident_is_never_duplicated() {
        let config = Config::default();
        let mut engine = IncidentEngine::new(&config, 1);
        open_incident(&mut engine, "cgroup:1:2", 1_000);
        engine.take_pulse();
        for step in 0..5 {
            assert!(engine
                .observe(signal(
                    "cgroup:1:2",
                    Metric::Cpu,
                    60.0,
                    5.0,
                    20.0,
                    2_000 + step
                ))
                .is_none());
        }
        assert_eq!(engine.open_count(), 1);
        let pulse = engine.take_pulse();
        assert!(pulse.opened.is_empty(), "no duplicate incident row");
        assert!(
            pulse
                .updated
                .iter()
                .any(|(id, ended, peak, ..)| *id == 1 && ended.is_none() && *peak >= 60.0),
            "peak update is queued: {:?}",
            pulse.updated
        );
    }

    #[test]
    fn closes_after_recovery_hysteresis() {
        let mut config = Config::default();
        config.adaptive.recovery_hysteresis_secs = 30;
        let mut engine = IncidentEngine::new(&config, 1);
        open_incident(&mut engine, "cgroup:1:2", 1_000);
        engine.take_pulse();
        let below = 20.0f64.mul_add(RECOVERY_FACTOR, -1.0);
        assert!(engine
            .observe(signal("cgroup:1:2", Metric::Cpu, below, 5.0, 20.0, 2_000))
            .is_none());
        assert_eq!(engine.open_count(), 1, "hysteresis keeps the incident open");
        let early = engine.tick(2_000 + 29_000_000_000);
        assert!(
            !early.updated.iter().any(|(_, ended, ..)| ended.is_some()),
            "an incident may only close once recovery persisted for the full hysteresis"
        );
        assert!(
            !early
                .events
                .iter()
                .any(|event| event.kind == EventKind::IncidentClosed),
            "no close event before the hysteresis elapsed"
        );
        assert_eq!(engine.open_count(), 1);
        let pulse = engine.tick(2_000 + 30_000_000_000);
        assert_eq!(engine.open_count(), 0);
        assert!(pulse
            .updated
            .iter()
            .any(|(id, ended, ..)| *id == 1 && ended.is_some()));
        assert!(pulse.events.iter().any(|event| {
            event.kind == EventKind::IncidentClosed
                && event.payload.get("close_reason").and_then(|v| v.as_str())
                    == Some(REASON_RECOVERED)
        }));
    }

    #[test]
    fn forced_maximum_duration_closes_the_incident() {
        let mut config = Config::default();
        config.adaptive.max_incident_secs = 5;
        let mut engine = IncidentEngine::new(&config, 1);
        let opened = open_incident(&mut engine, "cgroup:1:2", 1_000);
        engine.take_pulse();
        let pulse = engine.tick(opened.started_wall_ns + 5_000_000_000);
        assert_eq!(engine.open_count(), 0);
        assert!(pulse.updated.iter().any(|(id, ended, ..)| {
            *id == opened.incident_id.unwrap_or_default() && ended.is_some()
        }));
        let closed = pulse
            .events
            .iter()
            .find(|event| event.kind == EventKind::IncidentClosed)
            .expect("close event");
        assert_eq!(
            closed.payload.get("close_reason").and_then(|v| v.as_str()),
            Some(REASON_BOUNDED)
        );
        let ended_evidence = pulse
            .updated
            .iter()
            .find_map(|(_, _, _, evidence, _)| evidence.as_ref())
            .expect("close evidence");
        assert_eq!(
            ended_evidence.get("close_reason").and_then(|v| v.as_str()),
            Some(REASON_BOUNDED)
        );
    }

    #[test]
    fn cooldown_blocks_reopening_for_five_minutes() {
        let mut config = Config::default();
        config.adaptive.max_incident_secs = 5;
        let mut engine = IncidentEngine::new(&config, 1);
        let opened = open_incident(&mut engine, "cgroup:1:2", 1_000);
        let closed_at = opened.started_wall_ns + 5_000_000_000;
        engine.tick(closed_at);
        engine.take_pulse();
        for offset in 0..10 {
            assert!(engine
                .observe(signal(
                    "cgroup:1:2",
                    Metric::Cpu,
                    40.0,
                    5.0,
                    20.0,
                    closed_at + 10_000_000_000 + offset
                ))
                .is_none());
        }
        assert_eq!(engine.open_count(), 0, "cooldown suppresses reopening");
        // After the cooldown, three fresh samples open a new incident.
        let reopen = closed_at + (MIN_COOLDOWN_SECS as i64 + 1) * 1_000_000_000;
        assert!(engine
            .observe(signal("cgroup:1:2", Metric::Cpu, 40.0, 5.0, 20.0, reopen))
            .is_none());
        assert!(engine
            .observe(signal(
                "cgroup:1:2",
                Metric::Cpu,
                40.0,
                5.0,
                20.0,
                reopen + 1
            ))
            .is_none());
        assert!(engine
            .observe(signal(
                "cgroup:1:2",
                Metric::Cpu,
                40.0,
                5.0,
                20.0,
                reopen + 2
            ))
            .is_some());
    }

    #[test]
    fn ids_increment_from_the_preallocated_first_id() {
        let config = Config::default();
        let mut engine = IncidentEngine::new(&config, 6);
        let first = open_incident(&mut engine, "cgroup:1:2", 1_000);
        assert_eq!(first.incident_id, Some(6));
        let second = open_incident(&mut engine, "cgroup:1:3", 1_000);
        assert_eq!(second.incident_id, Some(7));
        let pulse = engine.take_pulse();
        assert_eq!(pulse.opened.len(), 2);
        assert_eq!(engine.open_count(), 2);
    }

    #[test]
    fn a_tiny_value_on_a_zero_baseline_never_opens() {
        let config = Config::default();
        let mut engine = IncidentEngine::new(&config, 1);
        for step in 0..10 {
            assert!(engine
                .observe(signal("host", Metric::PsiMemory, 1e-9, 0.0, 0.0, step))
                .is_none());
            assert!(engine
                .observe(signal("host", Metric::PsiMemory, 0.0, 0.0, 0.0, step + 100))
                .is_none());
        }
        assert_eq!(engine.open_count(), 0);
        let pulse = engine.take_pulse();
        assert!(pulse.opened.is_empty());
        assert!(pulse.events.is_empty());
    }

    #[test]
    fn event_kinds_severity_and_payload_are_bounded() {
        let config = Config::default();
        let mut engine = IncidentEngine::new(&config, 1);
        open_incident(&mut engine, "cgroup:1:2", 1_000);
        for offset in 0..3 {
            engine.observe(signal(
                "cgroup:1:2",
                Metric::IoWrite,
                100.0,
                1.0,
                50.0,
                10_000 + offset,
            ));
        }
        let pulse = engine.take_pulse();
        let cpu_event = pulse
            .events
            .iter()
            .find(|event| {
                event.kind == EventKind::IncidentOpened
                    && event.payload.get("metric").and_then(|v| v.as_str()) == Some("cpu")
            })
            .expect("cpu open event");
        assert_eq!(cpu_event.severity, Severity::Warn);
        assert_eq!(cpu_event.provenance, PROVENANCE);
        assert_eq!(
            cpu_event.payload.get("note").and_then(|v| v.as_str()),
            Some("temporal association only")
        );
        let io_event = pulse
            .events
            .iter()
            .find(|event| {
                event.kind == EventKind::IncidentOpened
                    && event.payload.get("metric").and_then(|v| v.as_str()) == Some("io_write")
            })
            .expect("io open event");
        assert_eq!(io_event.severity, Severity::Info);
        // JSON payloads stay small enough for the bounded store columns.
        for event in &pulse.events {
            let text = serde_json::to_string(&event.payload).expect("payload serializes");
            assert!(text.len() < crate::store::MAX_EVENT_JSON_BYTES);
        }
        let opened = &pulse.opened[0];
        assert_eq!(
            opened.evidence.get("engine").and_then(|v| v.as_str()),
            Some("threshold+ewma")
        );
        assert_eq!(
            opened.evidence.get("note").and_then(|v| v.as_str()),
            Some("temporal association only")
        );
    }

    #[test]
    fn empty_or_absent_entity_uses_the_host_key() {
        let config = Config::default();
        let mut engine = IncidentEngine::new(&config, 1);
        let mut opened = None;
        for offset in 0..CONSECUTIVE_SAMPLES {
            opened = engine.observe(Signal {
                entity_id: None,
                metric: Metric::Load,
                value: 5.0,
                baseline: 0.5,
                threshold: 2.0,
                wall_ns: 1_000 + i64::from(offset),
                reason: String::new(),
            });
        }
        let incident = opened.expect("host incident opens");
        assert!(incident.entity_id.is_none());
        assert_eq!(incident.metric, Metric::Load);
        assert_eq!(incident.reason, "observed above threshold and baseline");
    }
}
