#!/usr/bin/env bash
# SARF verification pipeline (Linux CI and developer shells).
#
# This script intentionally does not force Cargo's offline mode: Linux and CI
# builds are allowed to use the network. Windows developers must use
# scripts/verify.ps1, which runs Cargo offline against the pre-seeded cache.
#
# Every stage is required. A missing test target is a failure, not a skip: the
# final tree is expected to contain tests/policy.rs, tests/plan_conformance.rs,
# tests/integration_collectors.rs, tests/integration_report.rs, tests/e2e.rs and
# tests/perf.rs.
#
# Usage: scripts/verify.sh   (or: bash scripts/verify.sh)
set -euo pipefail

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)
cd -- "$REPO_ROOT"

if ! command -v cargo >/dev/null 2>&1; then
    printf 'error: cargo not found in PATH\n' >&2
    exit 1
fi
if ! command -v rustc >/dev/null 2>&1; then
    printf 'error: rustc not found in PATH\n' >&2
    exit 1
fi

PASSED=0
TOTAL=0
CURRENT_STAGE=""
START_SECONDS=$SECONDS

summary_on_exit() {
    local status=$?
    if [ "$status" -ne 0 ]; then
        printf '\nVERIFICATION FAILED during: %s (%d/%d stages passed)\n' \
            "${CURRENT_STAGE:-unknown}" "$PASSED" "$TOTAL" >&2
    fi
}

trap summary_on_exit EXIT

run_stage() {
    local name=$1
    shift

    TOTAL=$((TOTAL + 1))
    CURRENT_STAGE=$name

    printf '\n======================================================================\n'
    printf '== %s\n' "$name"
    printf '== $ %s\n' "$*"
    printf '======================================================================\n'

    if "$@"; then
        PASSED=$((PASSED + 1))
        printf '== PASS: %s\n' "$name"
    else
        local status=$?
        printf '== FAIL: %s (exit %d)\n' "$name" "$status" >&2
        exit "$status"
    fi
}

printf 'SARF verification\n'
printf '  repository: %s\n' "$REPO_ROOT"
printf '  rustc:      %s\n' "$(rustc --version)"
printf '  cargo:      %s\n' "$(cargo --version)"
printf '  start:      %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

# 1. Compiler / formatting / lint.
run_stage "cargo fmt --check" cargo fmt --check
run_stage "cargo clippy --all-targets -- -D warnings" \
    cargo clippy --all-targets -- -D warnings
run_stage "cargo build --all-targets" cargo build --all-targets

# 2. Unit and policy/spec tests.
run_stage "cargo test --lib" cargo test --lib
run_stage "cargo test --test policy" cargo test --test policy
run_stage "cargo test --test plan_conformance" cargo test --test plan_conformance

# 3. Integration and end-to-end tests.
run_stage "cargo test --test integration_collectors" \
    cargo test --test integration_collectors
run_stage "cargo test --test integration_report" \
    cargo test --test integration_report
run_stage "cargo test --test e2e" cargo test --test e2e

# 4. Release-mode performance checks. --nocapture keeps the recorded benchmark
#    numbers visible in CI logs; they are measurements, not pass/fail promises.
run_stage "cargo test --release --test perf -- --nocapture" \
    cargo test --release --test perf -- --nocapture

printf '\n======================================================================\n'
printf 'All %d verification stages passed in %ds.\n' "$TOTAL" "$((SECONDS - START_SECONDS))"
printf '======================================================================\n'
