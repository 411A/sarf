# Specification traceability

Maps the binding requirements in `guide-ChatGPT.md` to the implemented modules,
commands, views and tests. "Partial" is explicit; no unavailable feature is presented
as complete.

| Guide area | Requirement | Implementation | Verification |
|---|---|---|---|
| §0–3 | One binary; universal baseline independent of integrations | `src/daemon.rs`, `src/catalog.rs`, `src/collect/*` | `tests/policy.rs`, `tests/integration_collectors.rs`, e2e |
| §2 | Measured resource targets, not slogans | `sarf benchmark`, perf test prints numbers | `tests/perf.rs`, `docs/TESTING.md` |
| §4 | Tool catalog (docker, nginx, cloudflared, tmux, zellij, systemd) | embedded TOML in `src/catalog.rs` | catalog conformance, `sarf tools` |
| §5.1 | `/proc/stat`, meminfo, loadavg, PSI, net, disk, uptime, boot id | `src/collect/procfs.rs`, `host.rs` | unit parser tests + host integration |
| §5.2 | `/proc/PID` stat/status/io/exe/cgroup; comm with spaces/`)` | `src/collect/procfs.rs`, `process.rs` | parser edge cases, lifecycle tests |
| §5.3 | cgroup v2 discovery, counters, inode identity, read-only | `src/collect/cgroup.rs` | cgroup integration + policy read-only snapshot |
| §5.4–5.6 | proc connector, taskstats, eBPF | **Not implemented in v0.1**; reported as gaps | `sarf capabilities`, coverage report |
| §5.7 | PSI host/cgroup | `procfs::parse_pressure`, host/cgroup samples | parser + fixtures |
| §5.8 | Docker discovery/metadata/log fallback | `src/enrich/docker.rs`, `collect/logs.rs` | Docker parser tests, absent-continuity test |
| §5.9 | systemd unit mapping | cgroup → unit in `catalog.rs` | classification tests |
| §5.10 | tmux panes, Zellij sessions | `src/enrich/sessions.rs` | parser tests; Zellij pane topology documented gap |
| §5.11 | cron/scheduled jobs | **Not implemented in v0.1**; process visibility only | coverage notes |
| §5.12 | Explicit bounded log sources | `src/collect/logs.rs` | rotation/truncation/flood tests |
| §6 | Network accounting | Host interface counters implemented; flows/instrumentation not in v0.1 | host parser tests, capabilities |
| §7.2 | Dual clock, boot scoping | `src/time.rs` | 35+ time/model tests |
| §7.3–7.4 | Cadences, adaptive incident mode | `daemon.rs` ratios + incident cadence | e2e simulated cycles |
| §8.1 | PID-reuse-safe process identity | `ProcessIdentity` `(boot,pid,start_ticks)` | PID reuse unit/integration |
| §8.2–8.3 | Entities, typed time-bounded relationships | `src/model.rs`, process `SPAWNED_BY`, cgroup labels | storage roundtrip tests |
| §8.4 | No causal overclaiming | analysis/report wording | report integration + policy |
| §9.1 | Bounded rings (lines/bytes/time) | `LogRing`, per-source policy | flood policy test |
| §9.2–9.3 | Normalized records, severity, selective persistence | `LogRecord`, `detect_level`, `should_persist` | log integration tests |
| §9.4 | Backpressure/fairness, drop counters | `MAX_LINES_PER_POLL`, per-source caps, health | flood test |
| §9.5 | Docker log edge cases | CLI fallback + documented gaps | docs/ADR-006, capabilities |
| §9.6 | Safe file following | rotation/truncation/partial handling | unit + integration tests |
| §10.1–10.2 | EWMA baseline + absolute thresholds | `src/analysis/ewma.rs`, `incidents.rs` | EWMA/incident unit tests |
| §10.3 | Thresholds/hysteresis/cooldown | incidents engine | incident tests |
| §10.4 | Evidence window/caps/dedup | incident engine + daemon log capture | report incident test |
| §10.5 | Correlation output, likely contributors | `analysis/correlation.rs`, `sarf show/why` | report integration |
| §11.1–11.3 | SQLite schema, writer, indexes | `src/store/*` | 68+ storage/query tests |
| §11.4–11.6 | Retention, rollups, disk guard, WAL rules | `store/retention.rs` | retention tests + policy incident preservation |
| §12.1 | Deliberately few threads | daemon + writer | ADR-001, code |
| §12.2 | Dependency policy | `Cargo.toml`, ADR-007 | review |
| §12.3 | Release profile | `Cargo.toml` (LTO, strip, panic=abort) | build |
| §12.4 | Cohesive layout | `src/{collect,enrich,store,analysis,report,commands}` | tree |
| §13 | Configuration TUI | **Not implemented in v0.1**; config is TOML + `sarf doctor` | `docs/DECISIONS.md` |
| §14 | Self-contained HTML, four views, Canvas/SVG, CSP | `src/report/mod.rs` + assets | template/report/e2e tests |
| §15 | CLI | `src/cli.rs`, `src/commands/*` | plan conformance + e2e |
| §16 | Example configuration | `config/defaults.toml` | default parse/validate test |
| §17 | systemd unit, privilege model | `deploy/sarf.service`, `scripts/install.sh` | plan conformance; runtime requires a Linux host |
| §18 | Privacy, read-only, failure safety | defaults, redaction, policy tests | `tests/policy.rs` |
| §19 | Coverage/loss/degradation | health registry, gaps, writer drops | status/gaps/report coverage |
| §21 | Test pyramid | `tests/*`, scripts, CI | verify scripts |
| §22 | Roadmap phases | see below | — |
| §23 | Ponytail/SOLID discipline | no speculative framework; small modules; ADRs | review |

## Roadmap status

| Phase | Status |
|---|---|
| 0 Repository/design constraints | Done |
| 1 Host + cgroup v2 core | Done (fixture + Linux cross-check; live Linux validation via WSL/CI) |
| 2 Universal process inventory | Done (inventory, identity, top-N samples, tree) |
| 3 Process lifecycle events/taskstats | **Not in v0.1**; reconciliation scans only, gaps reported |
| 4 Docker/systemd adapters | Partial: Docker bounded CLI, cgroup→unit mapping; no Docker events or D-Bus |
| 5 Logs and incident forensics | Done (bounded sources, EWMA/threshold incidents, evidence capture) |
| 6 Integration registry/TUI | Registry done; TUI not in v0.1 |
| 7 Specialized adapters | Partial: nginx/cloudflared/tmux/Zellij/session recognition; no metrics endpoints |
| 8 HTTP/network flows | Not in v0.1 |
| 9 HTML reports | Done |
| 10 eBPF | Not in v0.1; never required for baseline |
| 11 Stabilization | Fixture/CI/soak harness present; multi-day soak and security review remain operator tasks |

## Explicit deviations

1. Docker/tmux/Zellij enrichment uses bounded CLI calls, not Engine API/D-Bus/plugin
   API (ADR-006).
2. USER_HZ is assumed 100 (ADR-008).
3. Windows identity is fixture-only (ADR-009).
4. No graceful SIGINT handler in v0.1 (ADR-016).
5. Process rollups are deferred; top-N raw samples only (ADR-005).
6. Log start reads a bounded recent tail, not the whole history (ADR-010).
7. Crate versions pin the newest offline-cache versions (ADR-007).
8. The TUI and HTTP/flow/eBPF/taskstats/connector phases are explicitly not delivered
   in v0.1 and are surfaced as coverage gaps rather than silently faked.
