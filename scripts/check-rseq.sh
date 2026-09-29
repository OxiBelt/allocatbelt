#!/usr/bin/env bash
# Experimental rseq `mm_cid` shard selection (single-package directive
# Phase H, §9): registration ownership and fallback in each C library and
# environment, fork, cpusets and concurrency. Correctness only, no timings.
#
# 1. glibc, as the system provides it: `mm_cid` is expected to be readable
#    (`ALLOCATBELT_EXPECT_RSEQ`, default `available`: glibc 2.35+ and Linux
#    6.3+ register it for every thread).
# 2. glibc with `GLIBC_TUNABLES=glibc.pthread.rseq=0`: glibc registers no
#    area, so `Require` fails with `not registered` and `Prefer` keeps the
#    per-thread shards. (`tests/rseq_process.rs` also re-executes itself
#    under this tunable and under a seccomp filter that refuses rseq.)
# 3. musl, static: musl registers no area and allocatbelt registers none of
#    its own, so the step is `not glibc` and everything falls back.
#
# Each runs the rseq unit test and `tests/rseq.rs` (oversubscribed
# threads), `tests/rseq_process.rs` (fork, a one-CPU cpuset, refused
# registration, policy switching) and `tests/fork.rs` with the feature on.
#
# Needs the `$(uname -m)-unknown-linux-musl` Rust target.
set -euo pipefail

cd "$(dirname "$0")/.."
musl="$(uname -m)-unknown-linux-musl"
tests=(--lib --test rseq --test rseq_process --test fork)
echo "kernel $(uname -r), $(ldd --version | head -n 1)"

run() {
  # run <expected step> <cargo test arguments...>
  local expect="$1"
  shift
  echo "-- expect ${expect}"
  local log status=0
  log="$(mktemp)"
  ALLOCATBELT_EXPECT_RSEQ="${expect}" cargo test --release --locked --no-fail-fast -p allocatbelt \
    --features experimental-rseq "$@" "${tests[@]}" -- --nocapture >"${log}" 2>&1 || status=$?
  grep -E '^(rseq:|tunable:|seccomp:|16 threads|[0-9]+ threads on|test result|mm_cid)' "${log}" |
    sort | uniq -c || true
  # The verdict is cargo's exit status; on failure, show why.
  if [ "${status}" -ne 0 ]; then
    echo "FAIL: expected ${expect} (cargo test exit ${status})" >&2
    grep -E -B 3 -A 15 '(panicked|^failures:|FAILED|child killed|^error)' "${log}" | tail -n 300 >&2 || true
    rm -f "${log}"
    exit 1
  fi
  rm -f "${log}"
}

echo "== glibc"
run "${ALLOCATBELT_EXPECT_RSEQ:-available}"
echo "== glibc, glibc.pthread.rseq=0"
GLIBC_TUNABLES=glibc.pthread.rseq=0 run "not registered"
echo "== musl (${musl})"
run "not glibc" --target "${musl}"
echo "ok: rseq mm_cid fallbacks"
