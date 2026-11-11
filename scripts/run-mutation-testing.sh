#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

fail() {
  echo "run-mutation-testing: $*" >&2
  exit 1
}

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_dir
repo_root="$(cd -- "${script_dir}/.." && pwd -P)"
readonly repo_root
readonly config="${repo_root}/mewt.toml"
readonly equivalent="${script_dir}/mutation-equivalent-mutants.json"
readonly runner_temp_base="${RUNNER_TEMP:-/tmp}"
readonly artifact_dir="${ALLOCATBELT_MUTATION_ARTIFACT_DIR:-${runner_temp_base}/allocatbelt-mutation-testing}"
readonly database="${artifact_dir}/mewt.sqlite"
readonly status_json="${artifact_dir}/status.json"
readonly results_json="${artifact_dir}/results.json"
readonly results_sarif="${artifact_dir}/results.sarif"

[[ "${runner_temp_base}" = /* && "${artifact_dir}" = /* ]] \
  || fail "RUNNER_TEMP and the mutation artifact directory must be absolute"
[[ -f "${config}" && ! -L "${config}" ]] || fail "missing canonical mewt.toml"
[[ -f "${equivalent}" && ! -L "${equivalent}" ]] \
  || fail "missing scripts/mutation-equivalent-mutants.json"
[[ "$(mewt --version)" == "mewt 4.0.0" ]] || fail "mewt 4.0.0 is required"

[[ ! -e "${artifact_dir}" && ! -L "${artifact_dir}" ]] \
  || fail "mutation artifact directory must start absent"
mkdir -m 0700 -- "${artifact_dir}"
[[ -d "${artifact_dir}" && -O "${artifact_dir}" \
  && "$(stat -c '%a' -- "${artifact_dir}")" == "700" ]] \
  || fail "mutation artifact directory must be owned by the current user with mode 0700"

cd -- "${repo_root}"
mewt --config "${config}" --db "${database}" mutate
mewt --config "${config}" --db "${database}" run
mewt --config "${config}" --db "${database}" status --format json \
  >"${status_json}"
mewt --config "${config}" --db "${database}" results --all --format json \
  >"${results_json}"
mewt --config "${config}" --db "${database}" results --all --format sarif \
  >"${results_sarif}"

jq -e '
  .campaign.total_mutants > 0
    and .campaign.tested == .campaign.total_mutants
    and .campaign.untested == 0
    and .campaign.skipped == 0
    and .campaign.timeout == 0
' "${status_json}" >/dev/null || {
  jq -r '.campaign | "total=\(.total_mutants) tested=\(.tested) untested=\(.untested) skipped=\(.skipped) timeout=\(.timeout)"' \
    "${status_json}" >&2
  fail "the complete configured mutation inventory must be tested without skips or timeouts"
}

# A mutant passes when a test catches it, or when it is listed as equivalent
# in `mutation-equivalent-mutants.json` and still survives. Listed entries
# that no longer match an uncaught mutant are stale and fail the gate.
readonly equivalent_filter='
  def key: [.target.path, .mutant.mutation_slug, .mutant.old_text];
  ($equivalent[0].mutants | map([.path, .slug, .old_text])) as $allowed
  | {
      unexpected: [.results[] | select(.outcome.status != "TestFail")
        | select((.outcome.status == "Uncaught" and (key as $k | any($allowed[]; . == $k))) | not)],
      stale: [$allowed[] as $a
        | select(any($root.results[] | select(.outcome.status == "Uncaught") | key; . == $a) | not)
        | $a]
    }
'

jq -e --argjson tested "$(jq -r '.campaign.tested' "${status_json}")" \
  --slurpfile equivalent "${equivalent}" '
  . as $root
  | (.results | length) > 0
    and (.results | length) == $tested
    and ('"${equivalent_filter}"' | (.unexpected | length) == 0 and (.stale | length) == 0)
' "${results_json}" >/dev/null || {
  jq -r --slurpfile equivalent "${equivalent}" '
    . as $root
    | if (.results | length) == 0 then
      "no mutation outcomes were produced"
    else
      ('"${equivalent_filter}"')
      | (.unexpected[]
          | "\(.outcome.status): \(.target.path):\((.mutant.line_offset // 0) + 1) [\(.mutant.mutation_slug)]"),
        (.stale[] | "stale equivalent entry: \(.[0]) [\(.[1])] \(.[2] | tojson)")
    end
  ' "${results_json}" >&2
  fail "every configured mutant must be caught or listed as equivalent, without skips, timeouts, or stale entries"
}

printf 'mutation testing passed: %s caught, %s listed as equivalent\n' \
  "$(jq -r '[.results[] | select(.outcome.status == "TestFail")] | length' "${results_json}")" \
  "$(jq -r '.mutants | length' "${equivalent}")"
