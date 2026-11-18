---
name: sarf-service-diagnosis
description: Use SARF (Service Activity Recorder & Forensics) to find which deployed containerized services are expensive, crashing, restarting or stalling, and to verify an optimization. Covers freshness checks, per-container peaks, restart and polling-loop detection, scoped logs, and the fields that must not be trusted. Trigger when asked to optimize, debug or audit services on a Linux host that runs SARF.
---

# Diagnosing deployed services with SARF

SARF records host and cgroup counters, process lifetimes and bounded logs. It answers
"which service carried the cost, when, and what was happening around it" — never
"which function caused it" and never "why" without evidence.

## Before anything: is the recorder actually recording?

```bash
sudo /usr/local/bin/sarf --version
sudo /usr/local/bin/sarf --data-dir /var/lib/sarf status --brief
```

Read `stale`, `latest_age_ns`, `database_bytes`, `open_gaps`.

- `stale: true` or `latest_age_ns` greater than a few sampling intervals → stop.
  Peaks, top and story will describe old or missing data. Check
  `systemctl status sarf`, `journalctl -u sarf -n 30 --no-pager`, `df -h /var/lib/sarf`.
- `database_bytes` above the configured `max_db_mb` → retention is trimming history.
  Raise the budget in `/var/lib/sarf/sarf.toml` and restart; otherwise old rollups
  and logs disappear and peaks stop reaching back.
- Version 0.1.20 fixed a retention scan that stalled collection for ~50 s on a large
  database. If the host runs 0.1.19 or older, the recorder may look `active` while
  persisting nothing. Upgrade before trusting a window.

Sizing guidance: one host, 5 s cadence, ~10 containers → 250 MB budget is a sane
floor; a 1 GiB host can afford it, a 512 MB host cannot. Retention defaults keep
minute rollups 14 days and peak dossiers 72 hours.

## Step 1 — inventory and live cost

```bash
sudo /usr/local/bin/sarf --data-dir /var/lib/sarf top --containers --by cpu --since 15m --limit 30
sudo /usr/local/bin/sarf --data-dir /var/lib/sarf top --containers --by mem --since 15m --limit 30
```

`CPU AVG` is **percent of one logical core** (400 % = four cores). `CPU MAX` is `-`
for cgroups by design: rollups keep microsecond deltas, not fabricated per-bucket
percentages. `SHARE` is the fraction of the ranked total, not of the host.

This is a 15-minute average. A bot that polls every 60 s can look idle here and still
burn a core in bursts. That is why the next step exists.

## Step 2 — peaks, the part built for optimization

```bash
sudo /usr/local/bin/sarf --data-dir /var/lib/sarf peaks --containers --since 24h --output /tmp/peaks.json
sudo /usr/local/bin/sarf --data-dir /var/lib/sarf peaks --containers --since 24h --csv > /tmp/peaks.csv
```

One document, everything at once. Each peak is an episode that exceeded the entity's
own rolling p99 plus a per-metric floor — no fixed thresholds. Use the CSV to scan,
the JSON to investigate.

CSV columns:

| column | meaning |
|---|---|
| `metric` | `cpu`, `memory`, `io_*`, `net_*`, `psi_*` |
| `scope` | entity id (`cgroup:device:inode`) |
| `container` / `name` | container id and name |
| `start_s`, `end_s` | Unix seconds |
| `shape` | `spike` (one minute) or `sustained` |
| `peak`, `base`, `p99` | metric units |
| `score` | `peak / max(p99, floor)`; >1 means above recent history |
| `period_s` | median interval when the episode repeats (see below) |
| `starts`, `exits`, `logs`, `errors` | **window-wide, see the warning** |
| `nodes`, `processes` | graph size and top process names |

### Fields you can trust

Per entity, scoped to the graph:

- `peak`, `base`, `p99`, `score`, `share`
- `nodes[]`: `id`, `name`, `kind` (`host`/`cgroup`/`process`), `pid`, `n`, `container`,
  `image`, `service`, `value`, `own`, `series`
- `edges`: `[parent, child, "on"|"in"]`
- `period_s`: present only when the same entity/metric produced at least three
  episodes with gaps within ±50 % of the median. Empty means "not a stable schedule",
  not "unknown". It is the polling interval to change in the code.
- `work`: present on container scopes; the container's most frequent log pattern
  with digit runs collapsed (`FOUND # valid proxies (ID: #)`) and its count. This is
  the recurring job; a count of hundreds is the thing to optimize.
- `logs[]` and `events[]`: relevance-filtered to the graph nodes, warnings/errors
  preferred.
- `near[]`: other peaks overlapping the same context window (temporal only).

`share` is the fraction of the host value. `own` is the value minus contained
children, so a cgroup and its processes do not double-count.

### Fields you must not attribute (0.1.20 and earlier)

`activity.starts`, `activity.exits`, `activity.logs`, `activity.errors` and the CSV
`starts/exits/logs/errors` columns are counted over the **whole context window**, not
per container. A row for `utazbot_python_executor` with `errors: 39` does not mean
that container logged 39 errors; it means the host logged 39 errors in those seconds.

Use these instead:

```bash
# this container's own lines, parsed severity
sudo /usr/local/bin/sarf --data-dir /var/lib/sarf logs docker:<container> --since 24h --level warn --limit 100
# this container's own lines including unparsed levels
sudo /usr/local/bin/sarf --data-dir /var/lib/sarf logs docker:<container> --since 24h --limit 100
# many short lifetimes = restart loop
sudo /usr/local/bin/sarf --data-dir /var/lib/sarf processes --since 24h --filter <container> --limit 200
```

`--grep` searches the message text, never the container name. The container is the
positional source (`docker:<name>`); `all` is the only other value.

## Step 3 — read a peak correctly

For each suspicious row, open the JSON and locate the scope node:

```bash
python3 - <<'EOF'
import json
d = json.load(open('/tmp/peaks.json'))
for p in d['peaks']:
    scope = next((n for n in p['nodes'] if n['id'] == p['scope']), p['nodes'][-1])
    print(p['metric'], scope.get('name'), 'peak', p['peak'], 'base', p['base'],
          'score', p['score'], 'period_s', p.get('period_s'),
          'work', (p.get('work') or {}).get('n'), (p.get('work') or {}).get('pat', '')[:80])
EOF
```

Decision rules:

- **`runc` in the node process list, or `starts`-like churn**: the container is
  restarting. Fix the crash/entrypoint before tuning anything. `runc` inside the
  cgroup is a restart shim, not a memory leak.
- **`shape: sustained` + monotonically rising `series` + no `runc`**: a real leak or
  an unbounded cache. Look at `nodes[]` process RSS and the service's own metrics.
- **`period_s` present**: a polling loop. Change that interval, batch the work, or
  move it to a queue. `work.pat` names the repeated line.
- **`psi_cpu` / `psi_io` high while `cpu` is low**: contention or quota, not work.
  Check `cpu.max`/Docker limits and host oversubscription (PSI is the percentage of
  time at least one task was stalled).
- **`io_*` or `net_*` peak with low CPU**: I/O or transfer bound; check the endpoint,
  payload size and retry policy in the logs.
- **`score` close to 1**: statistically marginal. Do not page anyone; it is above
  p99 but not exceptional.

Always state association, not causation: "observed", "associated", "likely
contributor", "unknown".

## Step 4 — faults and incidents

```bash
sudo /usr/local/bin/sarf --data-dir /var/lib/sarf incidents --since 24h
sudo /usr/local/bin/sarf --data-dir /var/lib/sarf show <incident-id>
sudo /usr/local/bin/sarf --data-dir /var/lib/sarf report --service <container> --since 24h --output /tmp/report.html
sudo /usr/local/bin/sarf --data-dir /var/lib/sarf story --since 1h --limit 10 --json
```

`show` prints the evidence lines and the incident window. `report` is a
self-contained offline HTML file. `story` groups related activity; it is temporal,
not causal.

## Step 5 — only if native symbols are required

```bash
sudo /usr/local/bin/sarf --data-dir /var/lib/sarf profile --container <name> --seconds 30
```

Requires `perf` and `/proc/sys/kernel/perf_event_paranoid` at 1 or lower (2 for
user-space counting); in a container, seccomp must allow `perf_event_open`. The
answer is **self time by symbol**, never a call graph. CPython collapses into
`_PyEval_EvalFrameDefault`; Python-level hotspots need `py-spy`-style unwinding,
which SARF does not bundle. Every failure is `status: "unavailable"` with a reason —
never an empty ranking.

## Step 6 — verify the fix

1. Keep a baseline: `peaks --containers --since 24h --output before.json` and the
   CSV.
2. Deploy the change.
3. Query a window that starts **after** the deploy, so the restart itself is not
   counted as the fault.
4. Compare `peak`, `base`, `p99`, `score`, `period_s` and `work.n` for the same
   scope, and read that container's logs again.
5. Report the before/after numbers, not "it feels faster".

## Reading `coverage` and `note`

An empty or short document explains itself: `coverage.from_wall_ns` /
`coverage.to_wall_ns` / `coverage.buckets` and `note` say whether there were no
rollups (collector not running), no peaks above baseline, or a schema/policy reason.
A `0` with rollups present means nothing crossed its baseline; it does not mean the
service was idle.

## Do not

- Do not read `activity.*` counters as per-container (current versions).
- Do not treat `-`, `null`, an omitted field or an empty `top` as zero usage.
- Do not compare windows that include a deploy/restart for restart metrics.
- Do not request `.env`, environment variables, argv, request bodies or auth headers;
  SARF never stores them by default.
- Do not run a second daemon against the same data directory.
- Do not use `--since 7d` and expect 7 days of peaks: dossiers are retained 72 h and
  minute rollups 14 days, and the disk guard may trim more.

## Minimal report shape

```text
Service:     <container> (<image>, compose service)
Window:      <from> .. <to>  (stale: no)
Observation: <metric> peak <value> vs base <value> (score <n>, shape <shape>)
Evidence:    <period_s / work pattern / scoped logs / lifetimes / psi>
Assessment:  restart loop | polling loop | leak | quota/contention | I/O bound |
             unknown (confidence: high/medium/low)
Next check:  <one concrete measurement or code change>
```
