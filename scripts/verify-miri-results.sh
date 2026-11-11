#!/usr/bin/env bash
# Audit an already-captured isolated Miri campaign without rerunning it.
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
source "${repo}/scripts/lib/miri-results.sh"

manifest=""
tests_list=""
tests_names=""
output=""
log_root=""
while (($#)); do
  case "$1" in
    --manifest|--tests-list|--tests-names|--output|--log-root)
      if (($# < 2)) || [[ -z "$2" ]]; then
        echo "error: $1 needs a file" >&2
        exit 2
      fi
      case "$1" in
        --manifest) manifest="$2" ;;
        --tests-list) tests_list="$2" ;;
        --tests-names) tests_names="$2" ;;
        --output) output="$2" ;;
        --log-root) log_root="$2" ;;
      esac
      shift 2
      ;;
    -h|--help)
      echo "usage: scripts/verify-miri-results.sh --manifest TSV --tests-list FILE --tests-names FILE --output VERIFIED.tsv [--log-root DIRECTORY]"
      exit 0
      ;;
    *)
      echo "error: unknown argument $1" >&2
      exit 2
      ;;
  esac
done

if [[ -n "${log_root}" && ! -d "${log_root}" ]]; then
  echo "error: --log-root is not a directory: ${log_root}" >&2
  exit 2
fi

for input in manifest tests_list tests_names output; do
  if [[ -z "${!input}" ]]; then
    echo "error: --${input//_/-} is required" >&2
    exit 2
  fi
done
for input in "${manifest}" "${tests_list}" "${tests_names}"; do
  if [[ ! -r "${input}" ]]; then
    echo "error: input is missing or unreadable: ${input}" >&2
    exit 2
  fi
done
if [[ "${output}" == "${manifest}" || "${output}" == "${tests_list}" \
  || "${output}" == "${tests_names}" ]]; then
  echo "error: output must be separate from captured inputs" >&2
  exit 2
fi
if [[ -e "${output}" || -L "${output}" ]]; then
  echo "error: verified-manifest output already exists: ${output}" >&2
  exit 2
fi

approved_benchmark="core::lock::tests::contention_benchmark"
mapfile -t tests <"${tests_names}"
mapfile -t listed_tests < <(sed -n 's/: test$//p' "${tests_list}")
if ((${#tests[@]} == 0 || ${#tests[@]} != ${#listed_tests[@]})); then
  echo "error: captured test names are empty or differ from the Cargo list" >&2
  exit 1
fi
for i in "${!tests[@]}"; do
  if [[ "${tests[i]}" != "${listed_tests[i]}" || ! "${tests[i]}" =~ ^[[:alnum:]_:]+$ ]]; then
    echo "error: captured test-name membership differs at index ${i}" >&2
    exit 1
  fi
done

mapfile -t list_summaries < <(sed -nE '/^[0-9]+ tests?, [0-9]+ benchmarks?$/p' "${tests_list}")
if ((${#list_summaries[@]} != 1)) \
  || [[ ! "${list_summaries[0]:-}" =~ ^([0-9]+)\ tests?,\ [0-9]+\ benchmarks?$ ]]; then
  echo "error: captured Cargo list has a missing or malformed count" >&2
  exit 1
fi
listed_count="${BASH_REMATCH[1]}"
if [[ "${listed_count}" != "${#tests[@]}" ]]; then
  echo "error: captured names count ${#tests[@]} differs from Cargo count ${listed_count}" >&2
  exit 1
fi

declare -A seen_names=()
benchmark_count=0
for test_name in "${tests[@]}"; do
  key="x${test_name}"
  if [[ -v "seen_names[${key}]" ]]; then
    echo "error: duplicate captured test name: ${test_name}" >&2
    exit 1
  fi
  seen_names["${key}"]=1
  if [[ "${test_name}" == "${approved_benchmark}" ]]; then
    benchmark_count=$((benchmark_count + 1))
  fi
done
if ((benchmark_count != 1)); then
  echo "error: captured list must contain the approved benchmark exactly once" >&2
  exit 1
fi

if [[ "$(head -n 1 "${manifest}")" != $'test\tstatus\ttest_exit\tlog_exit\tlog' ]]; then
  echo "error: malformed result-manifest header" >&2
  exit 1
fi
if ! awk -F '\t' 'NR > 1 && (NF != 5 || $1 == "" || $2 == "" || $3 == "" || $4 == "" || $5 == "") { bad = 1 } END { exit bad }' "${manifest}"; then
  echo "error: malformed result-manifest row" >&2
  exit 1
fi

declare -A record_status=() record_test_exit=() record_log_exit=() record_log=()
manifest_dir="$(dirname "${manifest}")"
while IFS=$'\t' read -r test_name recorded_status test_exit log_exit log_path; do
  [[ "${test_name}" == test ]] && continue
  key="x${test_name}"
  if [[ ! -v "seen_names[${key}]" ]]; then
    echo "error: manifest contains an unlisted test: ${test_name}" >&2
    exit 1
  fi
  if [[ -v "record_status[${key}]" ]]; then
    echo "error: duplicate manifest record: ${test_name}" >&2
    exit 1
  fi
  if [[ ! "${test_exit}" =~ ^[0-9]+$ || ! "${log_exit}" =~ ^[0-9]+$ ]]; then
    echo "error: malformed exit status in manifest row: ${test_name}" >&2
    exit 1
  fi
  if [[ "${log_path}" != /* ]]; then
    log_path="${log_root:-${manifest_dir}}/${log_path}"
  fi
  record_status["${key}"]="${recorded_status}"
  record_test_exit["${key}"]="${test_exit}"
  record_log_exit["${key}"]="${log_exit}"
  record_log["${key}"]="${log_path}"
done <"${manifest}"

if ! (set -o noclobber; printf 'test\trecorded_status\tverified_status\ttest_exit\tlog_exit\tlog\n' >"${output}"); then
  echo "error: could not create verified manifest: ${output}" >&2
  exit 1
fi

failures=0
passed_count=0
approved_skip_count=0
for test_name in "${tests[@]}"; do
  key="x${test_name}"
  recorded_status="${record_status[${key}]:-missing}"
  test_exit="${record_test_exit[${key}]:-missing}"
  log_exit="${record_log_exit[${key}]:-missing}"
  log_path="${record_log[${key}]:-missing}"
  verified_status="failed"
  diagnostic=""

  if [[ "${recorded_status}" == missing ]]; then
    diagnostic="no manifest record"
  elif miri_classify_log "${log_path}" "${test_name}" "${listed_count}" \
    "${test_exit}" "${log_exit}" "${approved_benchmark}"; then
    case "${recorded_status}:${MIRI_CLASS}" in
      passed:passed)
        verified_status=passed
        passed_count=$((passed_count + 1))
        ;;
      failed:passed)
        if [[ "${MIRI_EXPECTED_PANIC}" == true ]]; then
          verified_status=passed
          passed_count=$((passed_count + 1))
          echo "warning: ${test_name} was recorded failed but its zero-exit log proves an exact passing expected-panic outcome; original status retained in verified manifest" >&2
        else
          diagnostic="failed record cannot be reclassified"
        fi
        ;;
      approved_ignored_benchmark:approved_ignored_benchmark)
        verified_status=approved_ignored_benchmark
        approved_skip_count=$((approved_skip_count + 1))
        ;;
      failed:approved_ignored_benchmark)
        if [[ "${test_name}" == "${approved_benchmark}" ]]; then
          verified_status=approved_ignored_benchmark
          approved_skip_count=$((approved_skip_count + 1))
          echo "warning: ${test_name} was recorded failed but its log proves the exact approved ignored benchmark outcome; original status retained in verified manifest" >&2
        else
          diagnostic="failed record cannot be reclassified"
        fi
        ;;
      *)
        diagnostic="recorded status ${recorded_status} does not match parsed outcome ${MIRI_CLASS}"
        ;;
    esac
  else
    diagnostic="${MIRI_DIAGNOSTIC}"
  fi

  if [[ "${verified_status}" == failed ]]; then
    failures=$((failures + 1))
    echo "error: ${test_name}: ${diagnostic}" >&2
  fi
  if ! printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
    "${test_name}" "${recorded_status}" "${verified_status}" \
    "${test_exit}" "${log_exit}" "${log_path}" >>"${output}"; then
    echo "error: could not append to verified manifest: ${output}" >&2
    exit 1
  fi
done

if ((failures != 0)); then
  echo "error: verification found ${failures}/${#tests[@]} invalid or missing results; verified manifest: ${output}" >&2
  exit 1
fi
if ((passed_count != listed_count - 1 || approved_skip_count != 1)); then
  echo "error: verified pass/skip counts do not match captured test membership" >&2
  exit 1
fi
echo "ok: verified ${passed_count}/${listed_count} tests passed and one approved benchmark was ignored; verified manifest: ${output}"
