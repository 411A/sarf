# AGENTS.md — SARF engineering rules

SARF (Service Activity Recorder & Forensics) is a lightweight, Linux-first process,
service and activity recorder written in Rust. These rules are binding for every
contribution (human or agent). They implement the "Ponytail" discipline described in
`guide-ChatGPT.md` §23: the smallest complete change, no speculative abstraction, no
unnecessary dependency — but never at the cost of correctness, security, error
handling or tests.

## Non-negotiable invariants

1. **Universal baseline first.** Process visibility and accounting must never depend on
   a tool-specific integration. Disabling an enrichment may lose metadata, never
   sightings or resource accounting.
2. **One executable.** `sarf` is a single binary. No daemon-side web server, no
   permanent UI process. HTML reports and TUI are generated on demand.
3. **Bounded everything.** Every queue, ring buffer, log line, evidence blob, report
   and DB write batch has a byte/line/time limit. Overflow is counted and reported.
4. **Unavailable is not zero.** Missing permissions, controllers, files or sources are
   represented as `None`/status values, never as `0` activity.
5. **Privacy by default.** No environment capture, no argv persistence unless
   explicitly enabled, no request bodies, no cookie/authorization storage, no secret
   patterns kept unredacted.
6. **Read-only collection.** SARF never writes to `/proc`, `/sys/fs/cgroup`, journals,
   Docker configuration, tmux/Zellij sessions or monitored services.
7. **No causal overclaiming.** Reports say "observed", "associated", "likely
   contributor", "unknown". Never "caused" without direct evidence.
8. **Measure, don't promise.** Resource targets in the guide are benchmarks, not
   guarantees. Performance tests record numbers.

## Working rules

- Before coding: read the touched modules, their callers and tests; state the smallest
  scope that finishes the job.
- No abstraction without a real second implementation or a stated boundary. Fixture
  and system implementations justify the `SourceRoot`, `Clock`, and `CommandRunner`
  seams; nothing else is speculative.
- No new dependency without a note in `docs/DECISIONS.md` explaining why the standard
  library or an existing dependency is insufficient.
- Every parser, state machine, data-loss path and security boundary gets a targeted
  test (unit, or fixture integration test when it crosses modules).
- Parsers are total: malformed input yields a typed error, never a panic. Fuzz-ish
  property tests are expected for parsers that read untrusted kernel/user data.
- `unsafe` is denied crate-wide. The single documented exception is the Unix
  `clock_gettime(CLOCK_MONOTONIC)` syscall wrapper in `src/time.rs`.
- Run `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`,
  and (for Linux-relevant changes) `cargo check --target x86_64-unknown-linux-gnu`
  using the helper scripts under `scripts/`.
- State what was *not* tested and the remaining risks in the PR/commit description.

## Test pyramid (required)

| Stage | Where | Command |
|---|---|---|
| Compiler | whole workspace | `cargo build --all-targets` |
| Static analysis / lint | rustfmt + clippy policy | `cargo fmt --check && cargo clippy --all-targets -- -D warnings` |
| Policy | `tests/policy.rs` | `cargo test --test policy` |
| Plan / spec conformance | `tests/plan_conformance.rs` | `cargo test --test plan_conformance` |
| Unit | `#[cfg(test)]` in `src/**` | `cargo test --lib` |
| Integration | `tests/integration_*.rs` + fixtures | `cargo test --test integration_*` |
| End-to-end | real binary via `CARGO_BIN_EXE_sarf` | `cargo test --test e2e` |
| Performance | `tests/perf.rs` (release) | `cargo test --release --test perf -- --nocapture` |

`scripts/verify.sh` (Linux/macOS) and `scripts/verify.ps1` (Windows) run the whole
pyramid in order.

## Layout

- `src/collect` — source readers and parsers (`procfs`, `host`, `cgroup`, `process`,
  `logs`). Pure functions where possible; a `SourceRoot` selects real `/proc` or a
  fixture tree.
- `src/enrich` — bounded integrations (docker, tmux, zellij, nginx, cloudflared,
  systemd mapping). They enrich; they never gate baseline accounting.
- `src/store` — SQLite schema, single writer thread, queries, retention/size guard.
- `src/analysis` — EWMA baselines, incident engine, high/low usage windows and
  attribution.
- `src/report` — report data assembly and the self-contained offline HTML renderer.
- `src/commands` — one module per CLI surface; formatting only, no collection logic.

## Documentation of deviations

Any deviation from `guide-ChatGPT.md` must be recorded in `docs/DECISIONS.md` with
context, decision, consequences and the upgrade path (for example: Docker CLI metadata
fallback instead of the Engine API until `bollard` is available in the build
environment).
