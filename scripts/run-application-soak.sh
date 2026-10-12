#!/usr/bin/env bash
# Launch one continuous mixed-load soak through the dedicated bench-runtime-soak binary.
set -euo pipefail
export LC_ALL=C
qualification_runtime_readback_supported=0

usage() {
  echo "usage: $0 BINARY ALLOCATOR EXECUTOR PROFILE CPU_SET CAMPAIGN_ID HOST_ID RUN_ID OUTPUT_DIR SOURCE_SHA256 BINARY_SHA256 RESOURCE_CEILING_SHA256" >&2
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

case "$allocator" in allocatbelt|mimalloc-secure|mimalloc-standard|system) ;; *) usage; exit 2 ;; esac
case "$executor" in bounded|tokio) ;; *) usage; exit 2 ;; esac
case "$profile" in mixed|burst|oversubscribed) ;; *) usage; exit 2 ;; esac
[[ "$run_id" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "RUN_ID has unsupported characters" >&2; exit 2; }
for digest in "$source_sha" "$binary_sha" "$ceiling_sha"; do
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || { echo "source, binary and ceiling pins must be lowercase SHA-256 values" >&2; exit 2; }
done
for command in taskset timeout sha256sum; do
  command -v "$command" >/dev/null || { echo "missing required command: $command" >&2; exit 2; }
done
[[ -x /usr/bin/time ]] || { echo "GNU /usr/bin/time is required" >&2; exit 2; }
(( qualification_runtime_readback_supported == 1 )) || { echo "soak qualification is hard-disabled until the binary provides verified runtime-domain, policy, and ceiling readback" >&2; exit 2; }

binary=$(realpath "$binary_arg") || exit 2
[[ -x "$binary" ]] || { echo "soak binary is not executable" >&2; exit 2; }
[[ $(sha256sum "$binary" | awk '{print $1}') == "$binary_sha" ]] || { echo "soak binary hash differs from frozen manifest" >&2; exit 2; }
output_dir=$(realpath -m "$output_dir_arg") || exit 2
mkdir -m 700 -- "$output_dir"
report="$output_dir/soak-receipt.json"
terminal="$output_dir/terminal-records.tsv"
samples="$output_dir/resource-samples.tsv"
timing="$output_dir/time.txt"
stderr="$output_dir/stderr.txt"

# One process owns the complete horizon. It must stream per-ID outcomes and
# 100ms samples; the controller independently validates their hashes/counts.
taskset -c "$cpu_set" /usr/bin/time -v -o "$timing" \
  timeout --signal=TERM --kill-after=10s 12000s \
  env \
    "ALLOCATBELT_SOAK_REPORT=$report" \
    "ALLOCATBELT_SOAK_TERMINALS=$terminal" \
    "ALLOCATBELT_SOAK_SAMPLES=$samples" \
    "ALLOCATBELT_SOAK_RUN_ID=$run_id" \
    "ALLOCATBELT_SOAK_CAMPAIGN_ID=$campaign_id" \
    "ALLOCATBELT_SOAK_HOST_ID=$host_id" \
    "ALLOCATBELT_SOAK_ALLOCATOR=$allocator" \
    "ALLOCATBELT_SOAK_EXECUTOR=$executor" \
    "ALLOCATBELT_SOAK_PROFILE=$profile" \
    "ALLOCATBELT_SOAK_DURATION_SECONDS=10800" \
    "ALLOCATBELT_SOAK_SAMPLE_INTERVAL_MS=100" \
    "ALLOCATBELT_SOAK_SOURCE_SHA256=$source_sha" \
    "ALLOCATBELT_SOAK_BINARY_SHA256=$binary_sha" \
    "ALLOCATBELT_SOAK_RESOURCE_CEILING_SHA256=$ceiling_sha" \
    "$binary" \
    --executor "$executor" \
    --workload mixed \
    --profile "$profile" \
    --duration-seconds 10800 \
    --sample-interval-ms 100 \
    --resource-ceiling-sha256 "$ceiling_sha" \
    2>"$stderr"

[[ -s "$report" && -s "$terminal" && -s "$samples" ]] || { echo "soak binary omitted required streamed output" >&2; exit 1; }
[[ $(sha256sum "$binary" | awk '{print $1}') == "$binary_sha" ]] || { echo "soak binary changed during run" >&2; exit 1; }
