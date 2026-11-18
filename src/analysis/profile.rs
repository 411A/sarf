//! Parse `perf report --stdio` into a bounded self-time summary.
//!
//! SARF does not load BPF programs: doing so needs libbpf, kernel headers and
//! `unsafe`, none of which this binary accepts. `perf` is an ordinary external
//! command, so it is bounded like the docker/tmux/systemctl integrations and can
//! report "unavailable" honestly when the host does not have it.
//!
//! The profile is **self time by symbol**, not a call graph: frame pointers are
//! absent in most release builds and DWARF unwinding would cost more than the
//! daemon itself. A flat ranking is what answers "which function is expensive".

use serde::Serialize;

/// Stable document schema name.
pub const PROFILE_SCHEMA: &str = "sarf.profile";
/// Version of the profile document.
pub const PROFILE_SCHEMA_VERSION: u32 = 1;
/// Maximum symbols retained.
pub const MAX_ENTRIES: usize = 20;
/// Maximum PIDs sampled in one profile.
pub const MAX_PIDS: usize = 32;

/// One symbol's share of sampled CPU time.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProfileEntry {
    /// Percent of samples (self time).
    pub pct: f64,
    /// Command that was sampled (`python3.12`).
    pub comm: String,
    /// Shared object or executable (`libpython3.12.so.1.0`).
    pub dso: String,
    /// Symbol (`_PyEval_EvalFrameDefault`), or an address when stripped.
    pub symbol: String,
}

/// One profile answer: a single, always-JSON document.
///
/// `status` is `ok` only when `perf` actually sampled and reported. Everything
/// else is `unavailable` with a reason, because "no samples" must never be read
/// as "no CPU was used".
#[derive(Debug, Clone, Serialize)]
pub struct ProfileDocument {
    /// Document schema name.
    pub schema: &'static str,
    /// Document version.
    pub v: u32,
    /// `ok` or `unavailable`.
    pub status: &'static str,
    /// Container that was profiled, when the target was a container.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
    /// PIDs that were sampled, ascending.
    pub pids: Vec<u32>,
    /// Sampling duration actually used.
    pub seconds: u64,
    /// Sampling frequency actually used.
    pub hz: u64,
    /// Self time by symbol, descending.
    #[serde(rename = "top", skip_serializing_if = "Vec::is_empty")]
    pub top: Vec<ProfileEntry>,
    /// Why the profile is unavailable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// What the operator can do about it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    /// Caveat about the answer that was produced.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl ProfileDocument {
    /// A profile that was measured for `pids`.
    #[must_use]
    pub const fn measured(
        container: Option<String>,
        pids: Vec<u32>,
        seconds: u64,
        hz: u64,
    ) -> Self {
        Self {
            schema: PROFILE_SCHEMA,
            v: PROFILE_SCHEMA_VERSION,
            status: "ok",
            container,
            pids,
            seconds,
            hz,
            top: Vec::new(),
            reason: None,
            hint: None,
            note: None,
        }
    }

    /// Turn this document into an explicit non-answer.
    #[must_use]
    pub fn unavailable(mut self, reason: impl Into<String>, hint: impl Into<String>) -> Self {
        self.status = "unavailable";
        self.reason = Some(reason.into());
        self.hint = Some(hint.into());
        self.top.clear();
        self
    }

    /// Attach a caveat to a measured answer.
    #[must_use]
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }
}

/// Parse the table printed by `perf report --stdio`.
///
/// The format is `  <pct>%  <comm>  <dso>  [.] <symbol>`; symbols may contain
/// spaces, so the symbol is everything after the `[.]`/`[k]` marker. Header and
/// comment lines are ignored, which keeps the parser working across perf
/// versions.
pub fn parse_report(text: &str, limit: usize) -> Vec<ProfileEntry> {
    let mut entries = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(percent) = line.split_whitespace().next() else {
            continue;
        };
        let Some(percent) = percent.strip_suffix('%') else {
            continue;
        };
        let Ok(pct) = percent.parse::<f64>() else {
            continue;
        };
        if !pct.is_finite() || pct <= 0.0 {
            continue;
        }
        // Everything after "[.]" / "[k]" / "[.]" is the symbol.
        let Some((left, symbol)) = split_marker(line) else {
            continue;
        };
        let mut fields = left.split_whitespace();
        let _percent = fields.next();
        let Some(comm) = fields.next() else {
            continue;
        };
        let dso: String = fields.collect::<Vec<_>>().join(" ");
        if dso.is_empty() || symbol.is_empty() {
            continue;
        }
        entries.push(ProfileEntry {
            pct,
            comm: truncate(comm, 32),
            dso: truncate(&dso, 64),
            symbol: truncate(symbol, 120),
        });
    }
    entries.sort_by(|left, right| {
        right
            .pct
            .total_cmp(&left.pct)
            .then_with(|| left.symbol.cmp(&right.symbol))
    });
    entries.truncate(limit.clamp(1, 200));
    entries
}

/// Split a perf row at its `[.]`/`[k]`/`[g]`/`[u]` marker.
fn split_marker(line: &str) -> Option<(&str, &str)> {
    for marker in [" [.] ", " [k] ", " [g] ", " [u] "] {
        if let Some(index) = line.find(marker) {
            let left = &line[..index];
            let symbol = &line[index + marker.len()..];
            return Some((left, symbol.trim()));
        }
    }
    None
}

/// Bound a field so a hostile binary name cannot grow the document.
fn truncate(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        return value.to_string();
    }
    let mut out: String = value.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::float_cmp)]

    use super::*;

    const REPORT: &str = "\
# To display the perf.data header info, please use --header/--header-only options.
#
# Samples: 499  of event 'cpu-clock:pppH'
#
# Overhead  Command          Shared Object            Symbol
# ........  ...............  .......................  ...........................................
#
    45.67%  python3.12       libpython3.12.so.1.0     [.] _PyEval_EvalFrameDefault
    22.10%  python3.12       libssl.so.3              [.] ossl_aes_gcm
    10.05%  utazbot          [kernel.kallsyms]        [k] _raw_spin_lock_irqsave
     3.50%  python3.12       [unknown]                [.] 0x00007f9c8b2a11e0
     0.00%  python3.12       libc.so.6                [.] __libc_start_main
";

    #[test]
    fn parses_self_time_rows_and_skips_headers_and_zeroes() {
        let entries = parse_report(REPORT, MAX_ENTRIES);
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[0].pct, 45.67);
        assert_eq!(entries[0].comm, "python3.12");
        assert_eq!(entries[0].dso, "libpython3.12.so.1.0");
        assert_eq!(entries[0].symbol, "_PyEval_EvalFrameDefault");
        assert_eq!(entries[2].dso, "[kernel.kallsyms]");
        assert_eq!(entries[2].symbol, "_raw_spin_lock_irqsave");
        assert_eq!(entries[3].symbol, "0x00007f9c8b2a11e0");
    }

    #[test]
    fn symbols_with_spaces_are_kept() {
        let text = "  7.00%  python3.12  /usr/lib/x.so  [.] some name with spaces\n";
        let entries = parse_report(text, 10);
        assert_eq!(entries[0].symbol, "some name with spaces");
    }

    #[test]
    fn garbage_and_empty_input_yield_nothing() {
        assert_eq!(parse_report("", 10), Vec::new());
        assert_eq!(
            parse_report("not a perf table\n# comment\n", 10),
            Vec::new()
        );
    }

    #[test]
    fn limit_is_respected_and_order_is_descending() {
        use std::fmt::Write as _;

        let text = (1..=30).fold(String::new(), |mut out, index| {
            writeln!(out, "  {index}.00%  p  d.so  [.] sym{index}").expect("write to String");
            out
        });
        let entries = parse_report(&text, 5);
        assert_eq!(entries.len(), 5);
        assert_eq!(entries[0].symbol, "sym30");
        assert_eq!(entries[4].symbol, "sym26");
    }

    #[test]
    fn measured_documents_rank_symbols_and_carry_identity() {
        let mut document =
            ProfileDocument::measured(Some("utazbot_tgbot".to_string()), vec![12, 34], 30, 999);
        document.top = parse_report(REPORT, MAX_ENTRIES);
        let json = serde_json::to_value(&document).expect("serialize");
        assert_eq!(json["schema"], "sarf.profile");
        assert_eq!(json["v"], 1);
        assert_eq!(json["status"], "ok");
        assert_eq!(json["container"], "utazbot_tgbot");
        assert_eq!(json["pids"], serde_json::json!([12, 34]));
        assert_eq!(json["top"][0]["symbol"], "_PyEval_EvalFrameDefault");
        assert!(json.get("reason").is_none());
    }

    #[test]
    fn unavailable_documents_never_look_like_zero_usage() {
        let document =
            ProfileDocument::measured(Some("utazbot_redis".to_string()), vec![7], 30, 999)
                .unavailable("perf is not installed", "install linux-tools");
        let json = serde_json::to_value(&document).expect("serialize");
        assert_eq!(json["status"], "unavailable");
        assert_eq!(json["reason"], "perf is not installed");
        assert!(
            json.get("top").is_none(),
            "no empty array: that reads as zero"
        );
        assert!(json.get("note").is_none());
    }
}
