#!/usr/bin/env bash
# Shared strict parsing for the isolated Miri runner and result auditor.
# MIRI_CLASS and MIRI_DIAGNOSTIC are intentional outputs read by callers.
# shellcheck disable=SC2034

# Sets MIRI_CLASS and MIRI_DIAGNOSTIC. Returns success only for a single exact
# passing test or the specifically approved ignored contention benchmark.
miri_classify_log() {
  local log_file="$1"
  local test_name="$2"
  local listed_count="$3"
  local process_exit="$4"
  local writer_exit="$5"
  local approved_benchmark="$6"
  local expected_filtered summary_line line
  local output_count=0 line_name="" outcome="" reason="" summary_count=0

  MIRI_CLASS="failed"
  MIRI_DIAGNOSTIC=""
  if [[ ! "${listed_count}" =~ ^[1-9][0-9]*$ ]]; then
    MIRI_DIAGNOSTIC="invalid listed test count"
    return 1
  fi
  if [[ ! "${process_exit}" =~ ^[0-9]+$ || ! "${writer_exit}" =~ ^[0-9]+$ ]]; then
    MIRI_DIAGNOSTIC="invalid process or log-writer exit code"
    return 1
  fi
  if [[ "${process_exit}" != 0 || "${writer_exit}" != 0 ]]; then
    MIRI_DIAGNOSTIC="process exit ${process_exit}, log-writer exit ${writer_exit}"
    return 1
  fi
  if [[ ! -r "${log_file}" ]]; then
    MIRI_DIAGNOSTIC="log is missing or unreadable"
    return 1
  fi

  while IFS= read -r line || [[ -n "${line}" ]]; do
    if [[ "${line}" =~ ^test[[:space:]]+([^[:space:]]+)[[:space:]]+\.\.\.([[:space:]]+(.*))?$ ]]; then
      output_count=$((output_count + 1))
      line_name="${BASH_REMATCH[1]}"
      outcome="${BASH_REMATCH[3]:-}"
      reason=""
      if [[ "${outcome}" =~ ^(ok|ignored)(,[[:space:]].*)?$ ]]; then
        outcome="${BASH_REMATCH[1]}"
        reason="${BASH_REMATCH[2]:-}"
      fi
    fi
    if [[ "${line}" == "test result:"* ]]; then
      summary_count=$((summary_count + 1))
      summary_line="${line}"
    fi
  done <"${log_file}"

  if ((output_count != 1)); then
    MIRI_DIAGNOSTIC="expected exactly one test outcome, found ${output_count}"
    return 1
  fi
  if [[ "${line_name}" != "${test_name}" ]]; then
    MIRI_DIAGNOSTIC="test outcome belongs to ${line_name}, expected ${test_name}"
    return 1
  fi
  if ((summary_count != 1)); then
    MIRI_DIAGNOSTIC="expected exactly one test summary, found ${summary_count}"
    return 1
  fi

  expected_filtered=$((listed_count - 1))
  if [[ "${test_name}" == "${approved_benchmark}" \
    && "${outcome}" == ignored \
    && "${reason}" == ", benchmark; prints timings" \
    && "${summary_line}" =~ ^test\ result:\ ok\.\ 0\ passed\;\ 0\ failed\;\ 1\ ignored\;\ 0\ measured\;\ ${expected_filtered}\ filtered\ out\;\ finished\ in\ [0-9]+([.][0-9]+)?s$ ]]; then
    MIRI_CLASS="approved_ignored_benchmark"
    return 0
  fi

  if [[ "${test_name}" != "${approved_benchmark}" \
    && "${outcome}" == ok \
    && -z "${reason}" \
    && "${summary_line}" =~ ^test\ result:\ ok\.\ 1\ passed\;\ 0\ failed\;\ 0\ ignored\;\ 0\ measured\;\ ${expected_filtered}\ filtered\ out\;\ finished\ in\ [0-9]+([.][0-9]+)?s$ ]]; then
    MIRI_CLASS="passed"
    return 0
  fi

  MIRI_DIAGNOSTIC="unexpected test outcome '${outcome}${reason}', summary '${summary_line:-missing}'"
  return 1
}
