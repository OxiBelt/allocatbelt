#!/usr/bin/env bash
# Run one source-pinned mixed soak from a parent recipe. V1 recipes preserve
# their archived fixed-policy behavior; V2 pressure recipes gate app launch on
# the driver's measured, recipe-pinned readiness marker.
set -euo pipefail
export LC_ALL=C
umask 077

usage() {
  cat >&2 <<'USAGE'
usage: run-application-soak.sh BINARY ALLOCATOR EXECUTOR PROFILE CPU_SET CAMPAIGN_ID HOST_ID RUN_ID OUTPUT_DIR SOURCE_SHA256 BINARY_SHA256 RESOURCE_CEILING_SHA256

Required environment:
  ALLOCATBELT_SOAK_PARENT_RECIPE
  ALLOCATBELT_SOAK_PARENT_RECIPE_SHA256
Optional mode:
  ALLOCATBELT_SOAK_MODE=qualified|functional (default qualified)
  ALLOCATBELT_SOAK_DURATION_SECONDS (qualified is exactly 10800; functional is shorter)
USAGE
}

if [[ $# -ne 12 ]]; then usage; exit 2; fi
binary_arg=$1
allocator=$2
executor=$3
profile=$4
cpu_set=$5
campaign_id=$6
host_id=$7
run_id=$8
output_dir_arg=$9
source_sha=${10}
binary_sha=${11}
ceiling_sha=${12}

case "$allocator" in allocatbelt) ;; *) echo "soak readback supports only allocator=allocatbelt" >&2; exit 2 ;; esac
case "$executor" in bounded) ;; *) echo "soak readback supports only executor=bounded" >&2; exit 2 ;; esac
case "$profile" in mixed|burst|oversubscribed) ;; *) usage; exit 2 ;; esac
[[ "$run_id" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "RUN_ID has unsupported characters" >&2; exit 2; }
[[ "$campaign_id" =~ ^[A-Za-z0-9._-]+$ && "$host_id" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "campaign/host IDs have unsupported characters" >&2; exit 2; }
[[ "$cpu_set" =~ ^[0-9,-]+$ ]] || { echo "CPU_SET must be a numeric CPU affinity list" >&2; exit 2; }
for digest in "$source_sha" "$binary_sha" "$ceiling_sha"; do
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || { echo "source, binary, and resource-ceiling pins must be lowercase SHA-256 values" >&2; exit 2; }
done

recipe=${ALLOCATBELT_SOAK_PARENT_RECIPE:-}
recipe_sha=${ALLOCATBELT_SOAK_PARENT_RECIPE_SHA256:-}
[[ -n "$recipe" && "$recipe_sha" =~ ^[0-9a-f]{64}$ ]] || {
  echo "missing SHA-pinned parent soak recipe; controller recipe generation is not integrated yet" >&2
  exit 2
}
mode=${ALLOCATBELT_SOAK_MODE:-qualified}
duration=${ALLOCATBELT_SOAK_DURATION_SECONDS:-10800}
case "$mode" in qualified|functional) ;; *) echo "ALLOCATBELT_SOAK_MODE must be qualified or functional" >&2; exit 2 ;; esac
[[ "$duration" =~ ^[1-9][0-9]{0,4}$ ]] && (( duration <= 10800 )) || { echo "duration must be in 1..=10800 seconds" >&2; exit 2; }
if [[ "$mode" == qualified ]]; then
  (( duration == 10800 )) || { echo "qualified mode requires the exact 10800-second horizon" >&2; exit 2; }
else
  (( duration < 10800 )) || { echo "functional mode requires a short horizon and is never qualification eligible" >&2; exit 2; }
fi
for command in python3 sha256sum realpath taskset; do
  command -v "$command" >/dev/null || { echo "missing required command: $command" >&2; exit 2; }
done

binary=$(realpath -- "$binary_arg") || exit 2
[[ -f "$binary" && -x "$binary" && ! -L "$binary" ]] || { echo "soak binary must be an executable regular non-symlink file" >&2; exit 2; }
[[ $(sha256sum -- "$binary" | awk '{print $1}') == "$binary_sha" ]] || { echo "soak binary hash differs from the frozen manifest" >&2; exit 2; }
[[ $(sha256sum -- "$recipe" | awk '{print $1}') == "$recipe_sha" ]] || { echo "parent recipe hash differs from its frozen pin" >&2; exit 2; }

raw_output_dir=$(realpath -m -- "$output_dir_arg") || exit 2
[[ ! -e "$raw_output_dir" && ! -L "$raw_output_dir" ]] || { echo "refusing to replace existing soak output directory" >&2; exit 2; }
mkdir -m 700 -- "$raw_output_dir"
output_dir=$(realpath -- "$raw_output_dir") || exit 2
chmod 700 -- "$output_dir"

runner_path=$(realpath -- "$0") || exit 2
readback_script=$(realpath -- "$(dirname -- "$runner_path")/application-soak-readback.py") || exit 2
preflight="$output_dir/soak-preflight.json"
preflight_json=$(python3 -B "$readback_script" preflight \
  --recipe "$recipe" \
  --recipe-sha256 "$recipe_sha" \
  --binary "$binary" \
  --output-dir "$output_dir" \
  --runner-path "$runner_path" \
  --cpu-set "$cpu_set" \
  --campaign-id "$campaign_id" \
  --host-id "$host_id" \
  --run-id "$run_id" \
  --allocator "$allocator" \
  --executor "$executor" \
  --profile "$profile" \
  --source-sha256 "$source_sha" \
  --binary-sha256 "$binary_sha" \
  --resource-ceiling-sha256 "$ceiling_sha" \
  --mode "$mode" \
  --duration-seconds "$duration") || exit 2
reference_ring=$(python3 -B -c 'import json,sys; print(json.load(sys.stdin)["reference_ring_path"])' <<<"$preflight_json")
reference_ring_sha=$(python3 -B -c 'import json,sys; print(json.load(sys.stdin)["reference_ring_sha256"])' <<<"$preflight_json")
comparison_family=$(python3 -B -c 'import json,sys; print(json.load(sys.stdin).get("comparison_family", "fixed_policy"))' <<<"$preflight_json")
launch_enabled=$(python3 -B -c 'import json,sys; print(str(json.load(sys.stdin).get("launch_enabled", True)).lower())' <<<"$preflight_json")
runner_outer_seconds=$(python3 -B -c 'import json,sys; x=json.load(sys.stdin); print(x.get("application_wall_timeout_seconds", x["duration_seconds"]+1200))' <<<"$preflight_json")
[[ "$runner_outer_seconds" =~ ^[1-9][0-9]*$ ]] || { echo "preflight returned an invalid app wall timeout" >&2; exit 2; }
case "$comparison_family" in
  fixed_policy)
    if [[ -n "${ALLOCATBELT_APP_COMPARISON_FAMILY:-}" && "$ALLOCATBELT_APP_COMPARISON_FAMILY" != fixed_policy ]]; then
      echo "runner comparison-family argument differs from the pinned fixed-policy recipe" >&2
      exit 2
    fi
    ;;
  external_pressure)
    [[ "$launch_enabled" == true ]] || {
      echo "SourceV5 soak recipe is preparatory: capacity chronology, feedback composition, and pressure recipe readiness are not complete" >&2
      exit 2
    }
    ;;
  *) echo "unsupported comparison family in the verified parent recipe" >&2; exit 2 ;;
esac

terminal="$output_dir/terminal-records.tsv"
samples="$output_dir/resource-samples.tsv"

set +e
python3 -B "$readback_script" launch \
  --recipe "$recipe" \
  --recipe-sha256 "$recipe_sha" \
  --binary "$binary" \
  --output-dir "$output_dir" \
  --runner-path "$runner_path" \
  --cpu-set "$cpu_set" \
  --preflight "$preflight" \
  --timeout-seconds "$runner_outer_seconds" \
  --term-grace-seconds 1.5 \
  --terminal-path "$terminal" \
  --samples-path "$samples" \
  -- \
  "$binary" \
  --executor bounded \
  --workload mixed \
  --profile "$profile" \
  --duration-seconds "$duration" \
  --sample-interval-ms 100 \
  --resource-ceiling-sha256 "$ceiling_sha" \
  --reference-ring "$reference_ring" \
  --reference-ring-sha256 "$reference_ring_sha" \
  --output-dir "$output_dir"
child_status=$?
set -e

set +e
python3 -B "$readback_script" verify-inputs \
  --recipe "$recipe" \
  --recipe-sha256 "$recipe_sha" \
  --binary "$binary" \
  --output-dir "$output_dir" \
  --runner-path "$runner_path" \
  --cpu-set "$cpu_set" >/dev/null
input_status=$?
set -e
if (( input_status != 0 )); then
  echo "soak inputs changed or postflight verification failed; private artifacts retained at $output_dir" >&2
  exit 1
fi
if (( child_status != 0 )); then
  echo "soak process exited $child_status; private failure artifacts retained at $output_dir" >&2
  exit "$child_status"
fi

python3 -B "$readback_script" validate \
  --recipe "$recipe" \
  --recipe-sha256 "$recipe_sha" \
  --binary "$binary" \
  --output-dir "$output_dir" \
  --runner-path "$runner_path" \
  --cpu-set "$cpu_set"
[[ $(sha256sum -- "$binary" | awk '{print $1}') == "$binary_sha" ]] || { echo "soak binary changed during validation" >&2; exit 1; }
[[ $(sha256sum -- "$recipe" | awk '{print $1}') == "$recipe_sha" ]] || { echo "parent recipe changed during validation" >&2; exit 1; }
