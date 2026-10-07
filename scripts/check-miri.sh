#!/usr/bin/env bash
# Run every allocatbelt core-check test in its own Miri process. Isolating
# tests keeps one test's retained mock heaps from accumulating in later tests
# and makes the process exit status include Miri's post-test leak checks.
#
#   scripts/check-miri.sh
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
cd "${repo}"
source "${repo}/scripts/lib/miri-results.sh"

toolchain="nightly-2026-09-27"
package="allocatbelt-core-check"
timeout_seconds=1800
output_dir=""

while (($#)); do
  case "$1" in
    --output)
      if (($# < 2)) || [[ -z "$2" ]]; then
        echo "error: --output needs a directory" >&2
        exit 2
      fi
      output_dir="$2"
      shift 2
      ;;
    -h|--help)
      echo "usage: scripts/check-miri.sh [--output DIRECTORY]"
      exit 0
      ;;
    *)
      echo "error: unknown argument $1" >&2
      exit 2
      ;;
  esac
done

# This repository requires x86-64-v3 for x86_64 builds. Appending the target
# floor preserves it even when the caller supplies additional RUSTFLAGS. Do
# not pass an x86 target CPU to other native hosts.
if [[ "$(uname -m)" == x86_64 ]]; then
  export RUSTFLAGS="${RUSTFLAGS:+${RUSTFLAGS} }-C target-cpu=x86-64-v3"
fi
export MIRIFLAGS="-Zmiri-disable-isolation"

if ! command -v timeout >/dev/null 2>&1; then
  echo "error: GNU timeout is required to bound each Miri test" >&2
  exit 2
fi

if [[ -z "${output_dir}" ]]; then
  output_dir="target/miri/core-check-$(date -u +%Y%m%dT%H%M%SZ)-$$"
fi
mkdir -p -- "${output_dir}" || exit 2
output_dir="$(cd -- "${output_dir}" && pwd -P)" || exit 2
if [[ -n "$(find "${output_dir}" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
  echo "error: output directory is not empty: ${output_dir}" >&2
  exit 2
fi
manifest="${output_dir}/results.tsv"
if ! printf 'test\tstatus\ttest_exit\tlog_exit\tlog\n' >"${manifest}"; then
  echo "error: could not create results manifest: ${manifest}" >&2
  exit 1
fi

if ! cargo "+${toolchain}" miri setup; then
  echo "error: Miri setup failed" >&2
  exit 1
fi

list_file="${output_dir}/tests.list"
if ! cargo "+${toolchain}" miri test --locked -p "${package}" --lib -- --list >"${list_file}" 2>&1; then
  cat "${list_file}" >&2
  echo "error: could not list ${package} tests under Miri" >&2
  exit 1
fi

names_file="${output_dir}/tests.names"
if ! sed -n 's/: test$//p' "${list_file}" >"${names_file}"; then
  echo "error: could not parse ${package} test list" >&2
  exit 1
fi
mapfile -t tests <"${names_file}"
if ((${#tests[@]} == 0)); then
  echo "error: no ${package} tests were listed under Miri" >&2
  exit 1
fi

declare -A seen=()
approved_benchmark="core::lock::tests::contention_benchmark"
test_count=0
while IFS= read -r test_name; do
  [[ -n "${test_name}" ]] || continue
  if [[ -v "seen[${test_name}]" ]]; then
    echo "error: duplicate test in Miri list: ${test_name}" >&2
    exit 1
  fi
  seen["${test_name}"]=1
  test_count=$((test_count + 1))
done < <(printf '%s\n' "${tests[@]}")
if ((test_count != ${#tests[@]})); then
  echo "error: malformed Miri test list" >&2
  exit 1
fi
if ! listed_count="$(sed -nE 's/^([0-9]+) tests?, [0-9]+ benchmarks?$/\1/p' "${list_file}" | tail -n 1)"; then
  echo "error: could not parse Cargo test count" >&2
  exit 1
fi
if [[ -z "${listed_count}" ]] || ((listed_count != test_count)); then
  echo "error: test list count ${test_count} differs from Cargo summary ${listed_count:-missing}" >&2
  exit 1
fi

# The lock contention benchmark is intentionally ignored and prints timing
# output. Keep it visible as a named skip; any other ignored test is a failure.
benchmark_seen=0
for test_name in "${tests[@]}"; do
  if [[ "${test_name}" == "${approved_benchmark}" ]]; then
    benchmark_seen=1
  fi
done
if ((benchmark_seen != 1)); then
  echo "error: approved ignored benchmark missing from Miri list: ${approved_benchmark}" >&2
  exit 1
fi

run_count=0
passed_count=0
approved_skip_count=0
failures=0
for test_name in "${tests[@]}"; do
  run_count=$((run_count + 1))
  log_file="${output_dir}/${run_count}.log"
  echo "== Miri test: ${test_name}"
  set +e
  timeout --signal=TERM --kill-after=30s "${timeout_seconds}s" \
    cargo "+${toolchain}" miri test --locked -p "${package}" --lib "${test_name}" -- --exact \
    2>&1 | tee "${log_file}"
  pipeline_status=("${PIPESTATUS[@]}")
  set -e
  status="${pipeline_status[0]:-1}"
  tee_status="${pipeline_status[1]:-1}"

  if ((tee_status != 0)); then
    echo "FAIL: ${test_name} (test exit ${status}, log exit ${tee_status})" >&2
    if ! printf '%s\tfailed\t%s\t%s\t%s\n' \
      "${test_name}" "${status}" "${tee_status}" "${log_file}" >>"${manifest}"; then
      echo "error: could not record logging failure in ${manifest}" >&2
      exit 1
    fi
    failures=$((failures + 1))
    continue
  fi

  # The harness may print a test as successful and then fail during process
  # teardown. The shared parser requires exact output, summary, and exit codes.
  if miri_classify_log "${log_file}" "${test_name}" "${listed_count}" \
    "${status}" "${tee_status}" "${approved_benchmark}"; then
    if [[ "${MIRI_CLASS}" == passed ]]; then
      if ! printf '%s\tpassed\t0\t0\t%s\n' "${test_name}" "${log_file}" >>"${manifest}"; then
        echo "error: could not record test result in ${manifest}" >&2
        exit 1
      fi
      passed_count=$((passed_count + 1))
    else
      if ! printf '%s\tapproved_ignored_benchmark\t0\t0\t%s\n' \
        "${test_name}" "${log_file}" >>"${manifest}"; then
        echo "error: could not record approved ignored benchmark in ${manifest}" >&2
        exit 1
      fi
      approved_skip_count=$((approved_skip_count + 1))
    fi
  else
    echo "FAIL: ${test_name} (${MIRI_DIAGNOSTIC})" >&2
    if ! printf '%s\tfailed\t%s\t0\t%s\n' "${test_name}" "${status}" "${log_file}" >>"${manifest}"; then
      echo "error: could not record failure in ${manifest}" >&2
      exit 1
    fi
    failures=$((failures + 1))
  fi
done

if ((failures != 0)); then
  echo "error: ${failures}/${run_count} Miri test processes failed; see ${manifest}" >&2
  exit 1
fi
if ((approved_skip_count != 1 || passed_count != listed_count - 1 || run_count != listed_count)); then
  echo "error: Miri result membership is incomplete or the approved benchmark was not ignored" >&2
  exit 1
fi
echo "ok: ${passed_count}/${run_count} ${package} tests passed under Miri; ${approved_skip_count} approved ignored benchmark; results: ${manifest}"
