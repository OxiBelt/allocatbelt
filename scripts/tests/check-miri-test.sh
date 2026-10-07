#!/usr/bin/env bash
# Exercise the per-test Miri runner without running Miri or Cargo builds.
set -euo pipefail

repo="$(cd "$(dirname "$0")/../.." && pwd)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/check-miri-test.XXXXXX")"
trap 'rm -rf -- "${tmp}"' EXIT

mkdir -p "${tmp}/bin"
cat >"${tmp}/bin/uname" <<'UNAME'
#!/usr/bin/env bash
[[ "${1:-}" == -m ]] || exit 2
printf '%s\n' "${FAKE_UNAME:-x86_64}"
UNAME
cat >"${tmp}/bin/tee" <<'TEE'
#!/usr/bin/env bash
if [[ "${FAKE_TEE_FAILURE:-0}" == 1 ]]; then
  cat >/dev/null
  exit 1
fi
exec /usr/bin/tee "$@"
TEE
cat >"${tmp}/bin/awk" <<'AWK'
#!/usr/bin/env bash
if [[ "${FAKE_AWK_FAILURE:-0}" == 1 ]]; then
  exit 2
fi
exec /usr/bin/awk "$@"
AWK
cat >"${tmp}/bash-env" <<'BASH_ENV'
printf() {
  if [[ "${FAKE_PRINT_FAILURE:-0}" == 1 \
    && "${1:-}" == 'test\tstatus\ttest_exit\tlog_exit\tlog\n' ]]; then
    return 1
  fi
  builtin printf "$@"
}
BASH_ENV
cat >"${tmp}/bin/cargo" <<'CARGO'
#!/usr/bin/env bash
set -u
printf '%s\n' "$*|RUSTFLAGS=${RUSTFLAGS:-}|MIRIFLAGS=${MIRIFLAGS:-}" >>"${FAKE_CARGO_LOG}"
if [[ "$*" == *"miri setup"* ]]; then
  exit 0
fi
if [[ "$*" == *"-- --list"* ]]; then
  case "${FAKE_LIST_MODE:-normal}" in
    empty)
      echo "0 tests, 0 benchmarks"
      ;;
    duplicate)
      printf '%s\n' \
        'core::first_case: test' \
        'core::first_case: test' \
        'core::lock::tests::contention_benchmark: test' \
        '3 tests, 0 benchmarks'
      ;;
    count_mismatch)
      printf '%s\n' \
        'core::first_case: test' \
        'core::second_case: test' \
        'core::lock::tests::contention_benchmark: test' \
        '4 tests, 0 benchmarks'
      ;;
    *)
      printf '%s\n' \
        'core::first_case: test' \
        'core::second_case: test' \
        'core::lock::tests::contention_benchmark: test' \
        '3 tests, 0 benchmarks'
      ;;
  esac
  exit 0
fi

if [[ "$*" == *"core::lock::tests::contention_benchmark"* ]]; then
  test_name="core::lock::tests::contention_benchmark"
elif [[ "$*" == *"core::first_case"* ]]; then
  test_name="core::first_case"
else
  test_name="core::second_case"
fi
if [[ "${FAKE_MODE:-}" == empty && "${test_name}" == core::first_case ]]; then
  echo 'test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.00s'
  exit 0
fi
if [[ "${test_name}" == core::lock::tests::contention_benchmark && "${FAKE_MODE:-}" == unignored_benchmark ]]; then
  echo "test ${test_name} ... ok"
  echo 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.00s'
  exit 0
fi
if [[ "${test_name}" == core::lock::tests::contention_benchmark ]]; then
  echo "test ${test_name} ... ignored"
  echo 'test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 2 filtered out; finished in 0.00s'
  exit 0
fi
if [[ "${FAKE_MODE:-}" == ignored && "${test_name}" == core::second_case ]]; then
  echo "test ${test_name} ... ignored"
  echo 'test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 2 filtered out; finished in 0.00s'
  exit 0
fi
echo "test ${test_name} ... ok"
if [[ "${FAKE_MODE:-}" == duplicate_outcome && "${test_name}" == core::second_case ]]; then
  echo "test ${test_name} ... ok"
fi
if [[ "${FAKE_MODE:-}" == malformed_summary && "${test_name}" == core::second_case ]]; then
  echo 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.00s'
  exit 0
fi
echo 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.00s'
case "${FAKE_MODE:-}" in
  teardown_failure)
    [[ "${test_name}" == core::second_case ]] && exit 101
    ;;
  timeout)
    [[ "${test_name}" == core::second_case ]] && exit 124
    ;;
esac
exit 0
CARGO
chmod +x "${tmp}/bin/cargo"
chmod +x "${tmp}/bin/uname" "${tmp}/bin/tee" "${tmp}/bin/awk"

export PATH="${tmp}/bin:${PATH}"
export FAKE_CARGO_LOG="${tmp}/cargo.log"
export RUSTFLAGS="--cfg runner_test"

run_checker() {
  local name="$1"
  shift
  "${repo}/scripts/check-miri.sh" --output "${tmp}/${name}-out" "$@" \
    >"${tmp}/${name}.log" 2>&1
}

if ! run_checker success; then
  cat "${tmp}/success.log" >&2
  echo "FAIL: Miri runner rejected a successful fake suite" >&2
  exit 1
fi
grep -q 'ok: 2/3 allocatbelt-core-check tests passed under Miri; 1 approved ignored benchmark' "${tmp}/success.log" \
  || { cat "${tmp}/success.log" >&2; echo "FAIL: missing success summary" >&2; exit 1; }
awk -F '\t' '$1 == "core::lock::tests::contention_benchmark" && $2 == "approved_ignored_benchmark" && $3 == 0 && $4 == 0 && $5 ~ /\/3[.]log$/ { found++ } END { exit found != 1 }' \
  "${tmp}/success-out/results.tsv" || { echo "FAIL: approved ignored benchmark was not recorded" >&2; exit 1; }
grep -q 'miri test --locked -p allocatbelt-core-check --lib core::first_case -- --exact' \
  "${tmp}/cargo.log" || { echo "FAIL: first test was not run exactly" >&2; exit 1; }
grep -q 'miri test --locked -p allocatbelt-core-check --lib core::second_case -- --exact' \
  "${tmp}/cargo.log" || { echo "FAIL: second test was not run exactly" >&2; exit 1; }
grep -q -- '-C target-cpu=x86-64-v3' "${tmp}/cargo.log" \
  || { echo "FAIL: x86-64-v3 was not preserved" >&2; exit 1; }
grep -q 'MIRIFLAGS=-Zmiri-disable-isolation' "${tmp}/cargo.log" \
  || { echo "FAIL: Miri flags differ from the approved isolation-only flag" >&2; exit 1; }

expect_failure() {
  local name="$1" mode="$2" expected="$3"
  export FAKE_MODE="${mode}"
  local status=0
  run_checker "${name}" || status=$?
  [[ "${status}" == 1 ]] \
    || { cat "${tmp}/${name}.log" >&2; echo "FAIL: ${name} returned ${status}, want 1" >&2; exit 1; }
  grep -q "${expected}" "${tmp}/${name}.log" \
    || { cat "${tmp}/${name}.log" >&2; echo "FAIL: ${name} missed expected failure" >&2; exit 1; }
}

export FAKE_MODE=teardown_failure
expect_failure teardown_failure teardown_failure 'FAIL: core::second_case (exit 101'
expect_failure unignored_benchmark unignored_benchmark "FAIL: core::lock::tests::contention_benchmark"
expect_failure ignored ignored 'outcome ignored'
expect_failure zero_executed empty 'outcome missing'
expect_failure timeout timeout 'FAIL: core::second_case (exit 124'
expect_failure duplicate_outcome duplicate_outcome 'outcomes 2'
expect_failure malformed_summary malformed_summary 'summary test result:'

export FAKE_MODE=normal
export FAKE_TEE_FAILURE=1
expect_failure logging_failure normal 'test exit 0, log exit 1'
unset FAKE_TEE_FAILURE

export FAKE_AWK_FAILURE=1
expect_failure parser_failure normal 'could not parse output count'
unset FAKE_AWK_FAILURE

export FAKE_PRINT_FAILURE=1
export BASH_ENV="${tmp}/bash-env"
expect_failure manifest_failure normal 'could not create results manifest'
unset FAKE_PRINT_FAILURE BASH_ENV

export FAKE_UNAME=aarch64
: >"${tmp}/cargo.log"
if ! run_checker aarch64; then
  cat "${tmp}/aarch64.log" >&2
  echo "FAIL: Miri runner failed with an aarch64 host stub" >&2
  exit 1
fi
if grep -q -- '-C target-cpu=x86-64-v3' "${tmp}/cargo.log"; then
  echo "FAIL: x86-64-v3 was passed to the aarch64 host" >&2
  exit 1
fi
unset FAKE_UNAME

export FAKE_MODE=normal
export FAKE_LIST_MODE=duplicate
expect_failure duplicate_list normal 'duplicate test in Miri list'
export FAKE_LIST_MODE=count_mismatch
expect_failure membership_count normal 'test list count 3 differs from Cargo summary 4'
export FAKE_LIST_MODE=empty
expect_failure empty_list normal 'no allocatbelt-core-check tests were listed'

echo "ok: Miri runner validates list membership, exact outcomes, process exits, timeout and approved skips"
