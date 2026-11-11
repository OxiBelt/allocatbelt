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
  case "${FAKE_MODE:-}" in
    bad_benchmark_reason)
      echo "test ${test_name} ... ignored, benchmark; timing output is not a result"
      ;;
    bare_ignored_benchmark)
      echo "test ${test_name} ... ignored"
      ;;
    *)
      echo "test ${test_name} ... ignored, benchmark; prints timings"
      ;;
  esac
  echo 'test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 2 filtered out; finished in 0.00s'
  exit 0
fi
if [[ "${FAKE_MODE:-}" == ignored && "${test_name}" == core::second_case ]]; then
  echo "test ${test_name} ... ignored"
  echo 'test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 2 filtered out; finished in 0.00s'
  exit 0
fi
if [[ "${FAKE_MODE:-}" == expected_panic ]]; then
  echo "test ${test_name} - should panic ... ok"
else
  echo "test ${test_name} ... ok"
fi
if [[ "${FAKE_MODE:-}" == duplicate_outcome && "${test_name}" == core::second_case ]]; then
  echo "test ${test_name} ... ok"
fi
if [[ "${FAKE_MODE:-}" == extra_failed_outcome && "${test_name}" == core::second_case ]]; then
  echo 'test core::unexpected ... FAILED'
fi
if [[ "${FAKE_MODE:-}" == empty_extra_outcome && "${test_name}" == core::second_case ]]; then
  echo 'test core::unexpected ...'
fi
if [[ "${FAKE_MODE:-}" == malformed_summary && "${test_name}" == core::second_case ]]; then
  echo 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.00s'
  exit 0
fi
echo 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.00s'
if [[ "${FAKE_MODE:-}" == unterminated_outcome && "${test_name}" == core::second_case ]]; then
  printf '%s' 'test core::unexpected ... FAILED'
fi
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
relative_root="$(realpath --relative-to="${repo}" "${tmp}")"
(
  cd "${tmp}"
  "${repo}/scripts/check-miri.sh" --output "${relative_root}/relative-output" >relative-runner.log 2>&1
)
awk -F '\t' 'NR > 1 && $5 !~ /^\// { bad = 1 } END { exit bad }' \
  "${tmp}/relative-output/results.tsv" \
  || { echo "FAIL: relative runner output produced nonabsolute log paths" >&2; exit 1; }
"${repo}/scripts/verify-miri-results.sh" \
  --manifest "${tmp}/relative-output/results.tsv" \
  --tests-list "${tmp}/relative-output/tests.list" \
  --tests-names "${tmp}/relative-output/tests.names" \
  --output "${tmp}/relative-output/verified.tsv" >"${tmp}/relative-audit.log"
sed "s|${tmp}/relative-output/|${relative_root}/relative-output/|g" \
  "${tmp}/relative-output/results.tsv" >"${tmp}/relative-output/old-results.tsv"
"${repo}/scripts/verify-miri-results.sh" \
  --manifest "${tmp}/relative-output/old-results.tsv" \
  --tests-list "${tmp}/relative-output/tests.list" \
  --tests-names "${tmp}/relative-output/tests.names" \
  --log-root "${repo}" \
  --output "${tmp}/relative-output/old-verified.tsv" >"${tmp}/old-relative-audit.log"
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
expect_failure teardown_failure teardown_failure 'FAIL: core::second_case (process exit 101'
expect_failure unignored_benchmark unignored_benchmark "FAIL: core::lock::tests::contention_benchmark"
expect_failure ignored ignored 'unexpected test outcome'
expect_failure bad_benchmark_reason bad_benchmark_reason 'unexpected test outcome'
expect_failure bare_ignored_benchmark bare_ignored_benchmark 'unexpected test outcome'
expect_failure zero_executed empty 'expected exactly one test outcome, found 0'
expect_failure timeout timeout 'FAIL: core::second_case (process exit 124'
expect_failure duplicate_outcome duplicate_outcome 'expected exactly one test outcome, found 2'
expect_failure extra_failed_outcome extra_failed_outcome 'expected exactly one test outcome, found 2'
expect_failure empty_extra_outcome empty_extra_outcome 'expected exactly one test outcome, found 2'
expect_failure unterminated_outcome unterminated_outcome 'expected exactly one test outcome, found 2'
expect_failure malformed_summary malformed_summary 'unexpected test outcome'

export FAKE_MODE=normal
export FAKE_TEE_FAILURE=1
expect_failure logging_failure normal 'test exit 0, log exit 1'
unset FAKE_TEE_FAILURE

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

export FAKE_MODE=expected_panic
if ! run_checker expected_panic; then
  cat "${tmp}/expected_panic.log" >&2
  echo "FAIL: runner rejected passing expected-panic outcomes" >&2
  exit 1
fi

export FAKE_MODE=normal
export FAKE_LIST_MODE=duplicate
expect_failure duplicate_list normal 'duplicate test in Miri list'
export FAKE_LIST_MODE=count_mismatch
expect_failure membership_count normal 'test list count 3 differs from Cargo summary 4'
export FAKE_LIST_MODE=empty
expect_failure empty_list normal 'no allocatbelt-core-check tests were listed'

mkdir -p "${tmp}/audit"
cat >"${tmp}/audit/tests.list" <<'LIST'
core::first_case: test
core::second_case: test
core::lock::tests::contention_benchmark: test
3 tests, 0 benchmarks
LIST
cat >"${tmp}/audit/tests.names" <<'NAMES'
core::first_case
core::second_case
core::lock::tests::contention_benchmark
NAMES
cat >"${tmp}/audit/1.log" <<'LOG'
test core::first_case ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.01s
LOG
cat >"${tmp}/audit/2.log" <<'LOG'
test core::second_case ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.02s
LOG
cat >"${tmp}/audit/3.log" <<'LOG'
test core::lock::tests::contention_benchmark ... ignored, benchmark; prints timings
test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 2 filtered out; finished in 0.03s
LOG
cat >"${tmp}/audit/results.tsv" <<MANIFEST
test	status	test_exit	log_exit	log
core::first_case	passed	0	0	${tmp}/audit/1.log
core::second_case	passed	0	0	${tmp}/audit/2.log
core::lock::tests::contention_benchmark	failed	0	0	${tmp}/audit/3.log
MANIFEST

verify_audit() {
  "${repo}/scripts/verify-miri-results.sh" \
    --manifest "${tmp}/audit/results.tsv" \
    --tests-list "${tmp}/audit/tests.list" \
    --tests-names "${tmp}/audit/tests.names" \
    --output "$1"
}

if ! verify_audit "${tmp}/audit/verified.tsv" \
  >"${tmp}/audit/verified.out" 2>"${tmp}/audit/verified.err"; then
  cat "${tmp}/audit/verified.err" >&2
  echo "FAIL: verifier rejected the captured exact benchmark reason" >&2
  exit 1
fi
grep -q 'warning: core::lock::tests::contention_benchmark was recorded failed' \
  "${tmp}/audit/verified.err" \
  || { echo "FAIL: verifier did not report the raw failed benchmark record" >&2; exit 1; }
awk -F '\t' '$1 == "core::lock::tests::contention_benchmark" && $2 == "failed" && $3 == "approved_ignored_benchmark" && $4 == 0 && $5 == 0 { found++ } END { exit found != 1 }' \
  "${tmp}/audit/verified.tsv" \
  || { echo "FAIL: verified manifest did not retain and reclassify the raw benchmark status" >&2; exit 1; }

cat >"${tmp}/audit/3.log" <<'LOG'
test core::lock::tests::contention_benchmark ... ignored, benchmark; timing output is not a result
test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 2 filtered out; finished in 0.03s
LOG
if verify_audit "${tmp}/audit/bad-reason.tsv" \
  >"${tmp}/audit/bad-reason.out" 2>"${tmp}/audit/bad-reason.err"; then
  echo "FAIL: verifier accepted an unapproved ignored reason" >&2
  exit 1
fi
grep -q 'unexpected test outcome' "${tmp}/audit/bad-reason.err" \
  || { cat "${tmp}/audit/bad-reason.err" >&2; echo "FAIL: verifier missed bad ignored reason" >&2; exit 1; }

cat >"${tmp}/audit/3.log" <<'LOG'
test core::lock::tests::contention_benchmark ... ignored, benchmark; prints timings
test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 2 filtered out; finished in 0.03s
LOG
sed 's/core::first_case\tpassed\t0\t0/core::first_case\tpassed\t101\t0/' \
  "${tmp}/audit/results.tsv" >"${tmp}/audit/nonzero.tsv"
cp "${tmp}/audit/results.tsv" "${tmp}/audit/original.tsv"
cp "${tmp}/audit/nonzero.tsv" "${tmp}/audit/results.tsv"
if verify_audit "${tmp}/audit/nonzero-verified.tsv" \
  >"${tmp}/audit/nonzero.out" 2>"${tmp}/audit/nonzero.err"; then
  echo "FAIL: verifier accepted a nonzero teardown status" >&2
  exit 1
fi
grep -q 'process exit 101' "${tmp}/audit/nonzero.err" \
  || { cat "${tmp}/audit/nonzero.err" >&2; echo "FAIL: verifier missed nonzero teardown status" >&2; exit 1; }
mv "${tmp}/audit/original.tsv" "${tmp}/audit/results.tsv"

source "${repo}/scripts/lib/miri-results.sh"
for encoded_exit in 08 00 010 18446744073709551616; do
  for statuses in "${encoded_exit}:0" "0:${encoded_exit}"; do
    if miri_classify_log "${tmp}/audit/1.log" core::first_case 3 \
      "${statuses%:*}" "${statuses#*:}" core::lock::tests::contention_benchmark; then
      echo "FAIL: parser accepted nonzero or noncanonical exit ${statuses}" >&2
      exit 1
    fi
  done
done

cp "${tmp}/audit/results.tsv" "${tmp}/audit/pristine.tsv"
cp "${tmp}/audit/1.log" "${tmp}/audit/ordinary-first.log"
sed 's/core::first_case ... ok/core::first_case - should panic ... ok/' \
  "${tmp}/audit/ordinary-first.log" >"${tmp}/audit/1.log"
sed 's/core::first_case\tpassed/core::first_case\tfailed/' \
  "${tmp}/audit/pristine.tsv" >"${tmp}/audit/results.tsv"
verify_audit "${tmp}/audit/expected-panic-verified.tsv" \
  >"${tmp}/audit/expected-panic.out" 2>"${tmp}/audit/expected-panic.err"
grep -q 'exact passing expected-panic outcome' "${tmp}/audit/expected-panic.err" \
  || { echo "FAIL: expected-panic correction omitted its warning" >&2; exit 1; }
awk -F '\t' '$1 == "core::first_case" && $2 == "failed" && $3 == "passed" { found++ } END { exit found != 1 }' \
  "${tmp}/audit/expected-panic-verified.tsv" \
  || { echo "FAIL: expected-panic correction did not retain original status" >&2; exit 1; }
for statuses in '101:0' '0:1'; do
  if miri_classify_log "${tmp}/audit/1.log" core::first_case 3 \
    "${statuses%:*}" "${statuses#*:}" core::lock::tests::contention_benchmark; then
    echo "FAIL: expected-panic outcome bypassed exit-status checks" >&2
    exit 1
  fi
done
mv "${tmp}/audit/ordinary-first.log" "${tmp}/audit/1.log"
for case_name in ordinary_failed duplicate_record unlisted_record ignored_nonzero ignored_writer_nonzero; do
  cp "${tmp}/audit/pristine.tsv" "${tmp}/audit/results.tsv"
  case "${case_name}" in
    ordinary_failed)
      sed 's/core::first_case\tpassed/core::first_case\tfailed/' \
        "${tmp}/audit/pristine.tsv" >"${tmp}/audit/results.tsv"
      ;;
    duplicate_record)
      sed -n '2p' "${tmp}/audit/pristine.tsv" >>"${tmp}/audit/results.tsv"
      ;;
    unlisted_record)
      printf 'core::unexpected\tpassed\t0\t0\t%s\n' "${tmp}/audit/1.log" >>"${tmp}/audit/results.tsv"
      ;;
    ignored_nonzero)
      sed 's/contention_benchmark\tfailed\t0\t0/contention_benchmark\tfailed\t101\t0/' \
        "${tmp}/audit/pristine.tsv" >"${tmp}/audit/results.tsv"
      ;;
    ignored_writer_nonzero)
      sed 's/contention_benchmark\tfailed\t0\t0/contention_benchmark\tfailed\t0\t1/' \
        "${tmp}/audit/pristine.tsv" >"${tmp}/audit/results.tsv"
      ;;
  esac
  if verify_audit "${tmp}/audit/${case_name}-verified.tsv" \
    >"${tmp}/audit/${case_name}.out" 2>"${tmp}/audit/${case_name}.err"; then
    echo "FAIL: auditor accepted ${case_name}" >&2
    exit 1
  fi
done
cp "${tmp}/audit/pristine.tsv" "${tmp}/audit/results.tsv"
sha256sum "${tmp}/audit/results.tsv" "${tmp}/audit/tests.list" \
  "${tmp}/audit/tests.names" >"${tmp}/audit/input-checksums"
if verify_audit "${tmp}/audit/results.tsv" >"${tmp}/audit/alias.out" 2>&1; then
  echo "FAIL: auditor accepted output aliasing a captured input" >&2
  exit 1
fi
if verify_audit "${tmp}/audit/verified.tsv" >"${tmp}/audit/existing.out" 2>&1; then
  echo "FAIL: auditor overwrote an existing output" >&2
  exit 1
fi
sha256sum --check "${tmp}/audit/input-checksums" >"${tmp}/audit/checksum-check.out"

sed 's/3 tests, 0 benchmarks/4 tests, 0 benchmarks/' \
  "${tmp}/audit/tests.list" >"${tmp}/audit/missing-count.list"
if "${repo}/scripts/verify-miri-results.sh" \
  --manifest "${tmp}/audit/results.tsv" \
  --tests-list "${tmp}/audit/missing-count.list" \
  --tests-names "${tmp}/audit/tests.names" \
  --output "${tmp}/audit/missing-count.tsv" \
  >"${tmp}/audit/missing-count.out" 2>"${tmp}/audit/missing-count.err"; then
  echo "FAIL: verifier accepted a mismatched captured test count" >&2
  exit 1
fi
grep -q 'captured names count 3 differs from Cargo count 4' \
  "${tmp}/audit/missing-count.err" \
  || { cat "${tmp}/audit/missing-count.err" >&2; echo "FAIL: verifier missed mismatched test count" >&2; exit 1; }

sed '/core::second_case/d' "${tmp}/audit/results.tsv" >"${tmp}/audit/missing-row.tsv"
if "${repo}/scripts/verify-miri-results.sh" \
  --manifest "${tmp}/audit/missing-row.tsv" \
  --tests-list "${tmp}/audit/tests.list" \
  --tests-names "${tmp}/audit/tests.names" \
  --output "${tmp}/audit/missing-row-verified.tsv" \
  >"${tmp}/audit/missing-row.out" 2>"${tmp}/audit/missing-row.err"; then
  echo "FAIL: verifier accepted incomplete manifest membership" >&2
  exit 1
fi
grep -q 'core::second_case: no manifest record' "${tmp}/audit/missing-row.err" \
  || { cat "${tmp}/audit/missing-row.err" >&2; echo "FAIL: verifier missed missing manifest record" >&2; exit 1; }

echo "ok: Miri runner and offline auditor validate exact outcomes, exit codes, membership and the one approved ignored benchmark"
