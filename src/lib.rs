//! SARF — Service Activity Recorder & Forensics.
//!
//! A lightweight, single-executable Linux process, service and activity recorder.
//! See `AGENTS.md` for the engineering rules and `guide-ChatGPT.md` for the
//! architecture this implementation follows.
//!
//! Design invariants enforced across modules:
//! * universal process observation is independent of integrations;
//! * every queue, buffer, record and report is bounded;
//! * a missing value is `None`, never zero activity (missing samples are flagged);
//! * collection is read-only;
//! * reports distinguish observation, correlation and causation.

#![deny(unsafe_code)]
#![deny(missing_debug_implementations)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::float_cmp,
        clippy::panic,
        clippy::missing_panics_doc,
        clippy::items_after_statements
    )
)]

pub mod analysis;
pub mod catalog;
pub mod cli;
pub mod collect;
pub mod commands;
pub mod config;
pub mod daemon;
pub mod enrich;
pub mod error;
pub mod model;
pub mod paths;
pub mod report;
pub mod store;
pub mod time;

/// Product name used in reports and the CLI banner.
pub const PRODUCT: &str = "SARF";
/// Human-readable product expansion.
pub const PRODUCT_LONG: &str = "Service Activity Recorder & Forensics";
/// Database schema version written to `PRAGMA user_version`.
pub const SCHEMA_VERSION: i32 = 2;
/// Version string of this build.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub use error::{Error, Result};
