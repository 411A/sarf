//! Local analysis: baselines, incidents and high/low attribution windows.
//!
//! Everything in this module reports **observation and association, never
//! causation**. A baseline describes what was observed before, an incident
//! describes a threshold episode that was observed, and an attribution window
//! describes which entities were *associated* with unusually high or low resource
//! usage in a time range. SARF deliberately does not claim that a contributor
//! caused anything: it says "observed", "associated", "likely contributor" and
//! "temporal association only".
//!
//! The three pieces are deliberately independent:
//!
//! * [`ewma`] keeps a numerically stable exponentially weighted mean/variance per
//!   metric so a caller can supply a relative `baseline` to the incident engine.
//! * [`incidents`] turns absolute thresholds plus that baseline into bounded,
//!   deduplicated incidents with hysteresis, cooldowns and a forced maximum
//!   duration. Only *high* usage produces incidents here; low usage is expressed
//!   as an attribution window rather than a threshold incident (a service that is
//!   idle is not an error).
//! * [`correlation`] turns stored buckets into high/low [`crate::model::AttributionWindow`]s
//!   with ranked contributors, host context and bounded evidence lines.
//! * [`profile`] parses `perf report` output into self-time symbols, which is the
//!   only view that names a *function* rather than a process. It shells out to
//!   `perf` instead of loading BPF programs: no libbpf, no kernel headers, no
//!   `unsafe`, and an honest "unavailable" when the host forbids sampling.
//!
//! All three are pure read-side building blocks: they never write to the database,
//! never block on collection, and every returned collection or JSON document is
//! bounded by configuration.

pub mod correlation;
pub mod ewma;
pub mod incidents;
pub mod peaks;
pub mod profile;
pub mod story;
