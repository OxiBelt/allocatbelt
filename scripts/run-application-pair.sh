#!/usr/bin/env bash
# Run one fresh bounded/Tokio pair for a single application comparison cell.
# This harness is preparation only; keep raw timing evidence outside the source checkout.
set -euo pipefail
export LC_ALL=C

usage() {
  echo "usage: $0 BINARY ALLOCATOR WORKLOAD MODE RATE_OR_DASH CPU_SET RUN_ID OUTPUT_ROOT" >&2
  echo "  MODE is capacity or open_loop; open_loop requires RATE_OR_DASH=positive integer." >&2
}

if [[ $# -ne 8 ]]; then usage; exit 2; fi
binary_arg=$1
allocator=$2
workload=$3
mode=$4
rate=$5
cpu_set=$6
run_id=$7
output_root=$8

case "$allocator" in allocatbelt|mimalloc-secure|mimalloc-standard|system) ;; *) usage; exit 2 ;; esac
case "$workload" in cpu|memory|http|disk) ;; *) usage; exit 2 ;; esac
case "$mode" in capacity|open_loop) ;; *) usage; exit 2 ;; esac
if [[ "$mode" == capacity ]]; then
  [[ "$rate" == - ]] || { echo "capacity mode requires RATE_OR_DASH=-" >&2; exit 2; }
else
  [[ "$rate" =~ ^[1-9][0-9]*$ ]] || { echo "open_loop requires a positive numeric rate" >&2; exit 2; }
fi
[[ "$run_id" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "RUN_ID has unsupported characters" >&2; exit 2; }
pair_suffix=${run_id##*[!0-9]}
[[ -n "$pair_suffix" && ${#pair_suffix} -le 3 ]] || { echo "RUN_ID must end in a pair ordinal from 1 through 36" >&2; exit 2; }
pair_ordinal=$((10#$pair_suffix))
(( pair_ordinal >= 1 && pair_ordinal <= 36 )) || { echo "pair ordinal must be from 1 through 36" >&2; exit 2; }

for command in taskset timeout sha256sum awk rustc uname python3; do
  command -v "$command" >/dev/null || { echo "missing required command: $command" >&2; exit 2; }
done
[[ -x /usr/bin/time ]] || { echo "GNU /usr/bin/time is required" >&2; exit 2; }

repo_root=$(git rev-parse --show-toplevel) || exit 2
binary=$(realpath "$binary_arg") || exit 2
[[ -x "$binary" ]] || { echo "binary is not executable: $binary" >&2; exit 2; }
output_root=$(realpath -m "$output_root") || exit 2
case "$output_root/" in
  "$repo_root/"*) echo "refusing to place raw benchmark evidence inside the source checkout" >&2; exit 2 ;;
esac
mkdir -p -- "$output_root"
cell_dir="$output_root/$run_id"
mkdir -- "$cell_dir" || { echo "run directory already exists: $cell_dir" >&2; exit 2; }

# Hash the tracked/untracked source paths from the checkout root, independent
# of the caller's working directory.
cd "$repo_root"

source_hash() {
  git -C "$repo_root" ls-files -co --exclude-standard -z \
    | sort -z \
    | xargs -0 -r sha256sum \
    | sha256sum \
    | awk '{print $1}'
}

source_digest=$(source_hash) || exit 2
binary_digest=$(sha256sum "$binary" | awk '{print $1}') || exit 2
head_commit=$(git -C "$repo_root" rev-parse HEAD) || exit 2
rust_version=$(rustc -Vv | tr '\n' ';') || exit 2
kernel=$(uname -srmo) || exit 2
host=$(hostname -f 2>/dev/null || hostname)

{
  printf 'key\tvalue\n'
  printf 'run_id\t%s\n' "$run_id"
  printf 'allocator\t%s\n' "$allocator"
  printf 'workload\t%s\n' "$workload"
  printf 'mode\t%s\n' "$mode"
  printf 'rate_per_second\t%s\n' "$rate"
  printf 'cpu_set\t%s\n' "$cpu_set"
  printf 'source_head\t%s\n' "$head_commit"
  printf 'source_tree_sha256\t%s\n' "$source_digest"
  printf 'binary_path\t%s\n' "$binary"
  printf 'binary_sha256\t%s\n' "$binary_digest"
  printf 'host\t%s\n' "$host"
  printf 'kernel\t%s\n' "$kernel"
  printf 'rustc\t%s\n' "$rust_version"
  if command -v lscpu >/dev/null; then
    printf 'cpu_model\t%s\n' "$(lscpu | awk -F: '/Model name/ {sub(/^[[:space:]]+/, "", $2); print $2; exit}')"
  fi
  printf 'governor\t%s\n' "$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || printf unavailable)"
  printf 'argv_policy\t%s\n' 'one fresh process; timeout=900s; taskset applied to each process'
} > "$cell_dir/metadata.tsv"

printf 'pair\texecutor\texit_code\trow_validation\tp99_qualification\targv\tstdout\ttime_report\n' > "$cell_dir/processes.tsv"
failed=0

validate_output() {
  local output=$1 expected_executor=$2 header
  local expected_blocking=0 expected_topology='4 async workers' expected_task_limit=8
  local expected_retained=0 expected_managed=0 expected_disk=0 expected_network=0
  case "$workload" in
    memory) expected_retained=8; expected_managed=163840 ;;
    http)
      expected_blocking=1 expected_task_limit=17 expected_managed=141312 expected_network=16
      if [[ "$expected_executor" == allocatbelt ]]; then
        expected_topology='4 async + 1 blocking + dedicated reactor'
      else
        expected_topology='4 async + 1 blocking + integrated I/O driver'
      fi
      ;;
    disk)
      expected_blocking=4 expected_managed=1573000 expected_disk=8
      if [[ "$expected_executor" == allocatbelt ]]; then
        expected_topology='4 async + 4 filesystem workers'
      else
        expected_topology='4 async + 4 blocking workers'
      fi
      ;;
  esac
  local expected_header='schema	allocator	executor	workload	mode	async_workers	blocking_workers	topology	logical_window	global_task_limit	retained_window	arrival_rate_per_second	requested_arrivals	attempted	admitted	rejected_full	rejected_resource	completed_on_time	completed_late	errors	cancellations	unresolved	lost	result_digest	expected_digest	capacity_publications_per_second	successful_throughput_through_drain_per_second	setup_ns	timer_pair_median_ns	wall_through_drain_ns	drain_tail_ns	response_p50_ns	response_p95_ns	response_p99_ns	producer_lateness_mean_ns	producer_lateness_max_ns	max_observed_managed_bytes	retained_managed_bytes	managed_limit_bytes	disk_limit_ops	network_limit_ops	final_managed_bytes	final_disk_ops	final_network_ops	rss_before_kib	rss_after_drain_kib	rss_after_shutdown_kib	hwm_before_kib	hwm_after_drain_kib	hwm_after_shutdown_kib	shutdown_ns'
  [[ $(wc -l < "$output") -eq 2 ]] || return 1
  header=$(sed -n '1p' "$output")
  [[ "$header" == "$expected_header" ]] || return 1
  python3 - "$output" "$expected_header" "$allocator" "$expected_executor" "$workload" "$mode" \
    "$rate" "$expected_blocking" "$expected_topology" "$expected_task_limit" \
    "$expected_retained" "$expected_managed" "$expected_disk" "$expected_network" <<'PY'
import re
import sys
from decimal import Decimal, InvalidOperation
from pathlib import Path

(
    path, expected_header, allocator, executor, workload, mode, rate,
    blocking, topology, task_limit, retained, managed, disk, network,
) = sys.argv[1:]
lines = Path(path).read_text(encoding="utf-8").splitlines()
headers = expected_header.split("\t")
if len(headers) != 51 or len(set(headers)) != 51 or lines[0] != expected_header:
    raise SystemExit(1)
values = lines[1].split("\t")
if len(values) != len(headers):
    raise SystemExit(1)
row = dict(zip(headers, values, strict=True))
if (row["schema"], row["allocator"], row["executor"], row["workload"], row["mode"]) != (
    "1", allocator, executor, workload, mode,
):
    raise SystemExit(1)

integer_fields = """schema async_workers blocking_workers logical_window global_task_limit
retained_window requested_arrivals attempted admitted rejected_full rejected_resource
completed_on_time completed_late errors cancellations unresolved lost result_digest
expected_digest setup_ns timer_pair_median_ns wall_through_drain_ns drain_tail_ns
response_p50_ns response_p95_ns response_p99_ns producer_lateness_mean_ns
producer_lateness_max_ns max_observed_managed_bytes retained_managed_bytes
managed_limit_bytes disk_limit_ops network_limit_ops final_managed_bytes final_disk_ops
final_network_ops rss_before_kib rss_after_drain_kib rss_after_shutdown_kib hwm_before_kib
hwm_after_drain_kib hwm_after_shutdown_kib shutdown_ns""".split()
integer_fields.remove("requested_arrivals")
u64_fields = {"result_digest", "expected_digest"}
for field in integer_fields:
    value = row[field]
    if not re.fullmatch(r"(?:0|[1-9][0-9]*)", value):
        raise SystemExit(1)
    number = int(value)
    maximum = (1 << 64) - 1 if field in u64_fields else (1 << 53) - 1
    if number > maximum:
        raise SystemExit(1)

decimal_fields = ("capacity_publications_per_second", "successful_throughput_through_drain_per_second")
decimals = {}
for field in decimal_fields:
    value = row[field]
    if field == "capacity_publications_per_second" and mode == "open_loop" and value == "":
        continue
    if not re.fullmatch(r"(?:0|[1-9][0-9]*)(?:\.[0-9]+)?", value):
        raise SystemExit(1)
    try:
        number = Decimal(value)
    except InvalidOperation:
        raise SystemExit(1)
    if not number.is_finite() or number < 0 or number > Decimal("1000000000"):
        raise SystemExit(1)
    decimals[field] = number

expected_policy = {
    "async_workers": "4", "blocking_workers": blocking, "topology": topology,
    "logical_window": "8", "global_task_limit": task_limit,
    "retained_window": retained, "managed_limit_bytes": managed,
    "disk_limit_ops": disk, "network_limit_ops": network,
}
if any(row[field] != expected for field, expected in expected_policy.items()):
    raise SystemExit(1)

attempted = int(row["attempted"])
admitted = int(row["admitted"])
rejected_full = int(row["rejected_full"])
rejected_resource = int(row["rejected_resource"])
completed_on_time = int(row["completed_on_time"])
completed_late = int(row["completed_late"])
completed = completed_on_time + completed_late
errors = int(row["errors"])
cancellations = int(row["cancellations"])
unresolved = int(row["unresolved"])
if attempted > (10_000_000 if mode == "capacity" else 5_000):
    raise SystemExit(1)
if any(number > attempted for number in (
    admitted, rejected_full, rejected_resource, completed_on_time, completed_late,
    errors, cancellations, unresolved, int(row["lost"]),
)):
    raise SystemExit(1)
if attempted != admitted + rejected_full + rejected_resource:
    raise SystemExit(1)
if admitted != completed + errors + cancellations + unresolved:
    raise SystemExit(1)
if int(row["lost"]) != attempted - completed:
    raise SystemExit(1)
if row["result_digest"] != row["expected_digest"]:
    raise SystemExit(1)
if errors or cancellations or unresolved:
    raise SystemExit(1)
if any(int(row[field]) != 0 for field in ("final_managed_bytes", "final_disk_ops", "final_network_ops")):
    raise SystemExit(1)
if int(row["max_observed_managed_bytes"]) > int(managed):
    raise SystemExit(1)
if int(row["retained_managed_bytes"]) > int(managed):
    raise SystemExit(1)

if mode == "capacity":
    if row["arrival_rate_per_second"] or row["requested_arrivals"] or rejected_full or rejected_resource or int(row["lost"]):
        raise SystemExit(1)
    if int(row["response_p50_ns"]) or int(row["response_p95_ns"]) or int(row["response_p99_ns"]):
        raise SystemExit(1)
    expected_capacity = Decimal(completed_on_time) / Decimal(30)
    actual_capacity = decimals["capacity_publications_per_second"]
    if abs(actual_capacity - expected_capacity) > max(Decimal("0.00000001"), expected_capacity * Decimal("0.00000001")):
        raise SystemExit(1)
else:
    if not re.fullmatch(r"[1-9][0-9]*", row["arrival_rate_per_second"]):
        raise SystemExit(1)
    if int(row["arrival_rate_per_second"]) != int(rate) or row["requested_arrivals"] != "5000" or attempted != 5000:
        raise SystemExit(1)
    if int(row["response_p50_ns"]) > int(row["response_p95_ns"]) or int(row["response_p95_ns"]) > int(row["response_p99_ns"]):
        raise SystemExit(1)

wall_ns = int(row["wall_through_drain_ns"])
if wall_ns <= 0 or wall_ns > 900_000_000_000 or int(row["drain_tail_ns"]) > 300_000_000_000:
    raise SystemExit(1)
expected_drained = Decimal(completed) * Decimal(1_000_000_000) / Decimal(wall_ns)
actual_drained = decimals["successful_throughput_through_drain_per_second"]
if abs(actual_drained - expected_drained) > max(Decimal("0.00000001"), expected_drained * Decimal("0.00000001")):
    raise SystemExit(1)

time_fields = (
    "setup_ns", "timer_pair_median_ns", "wall_through_drain_ns", "drain_tail_ns",
    "response_p50_ns", "response_p95_ns", "response_p99_ns",
    "producer_lateness_mean_ns", "producer_lateness_max_ns", "shutdown_ns",
)
if any(int(row[field]) > 900_000_000_000 for field in time_fields):
    raise SystemExit(1)
if int(row["drain_tail_ns"]) > 300_000_000_000:
    raise SystemExit(1)
if any(int(row[field]) > (1 << 53) - 1 for field in (
    "rss_before_kib", "rss_after_drain_kib", "rss_after_shutdown_kib",
    "hwm_before_kib", "hwm_after_drain_kib", "hwm_after_shutdown_kib",
)):
    raise SystemExit(1)
PY
}

validate_shutdown_report() {
  local report=$1 expected_executor=$2
  python3 - "$report" "$expected_executor" "$workload" <<'PY'
import re
import sys
from pathlib import Path

path, executor, workload = sys.argv[1:]
try:
    lines = Path(path).read_text(encoding="utf-8").splitlines()
except OSError:
    raise SystemExit(1)
if not lines or lines[0] != "kind\tname\tduration_ns":
    raise SystemExit(1)
if executor == "allocatbelt":
    drivers = ["allocatbelt HTTP async runtime", "allocatbelt connector pool", "allocatbelt reactor"] if workload == "http" else ["allocatbelt async runtime"]
    if workload == "disk":
        drivers.append("allocatbelt filesystem runtime")
else:
    drivers = ["Tokio HTTP runtime"] if workload == "http" else ["Tokio runtime"]
if len(lines) != len(drivers) + 2:
    raise SystemExit(1)
phase = lines[1].split("\t")
if len(phase) != 3 or phase[:2] != ["phase", "production_trace"]:
    raise SystemExit(1)
if not re.fullmatch(r"(?:0|[1-9][0-9]*)", phase[2]) or int(phase[2]) > 300_000_000_000:
    raise SystemExit(1)
for line, expected in zip(lines[2:], drivers, strict=True):
    row = line.split("\t")
    if len(row) != 3 or row[:2] != ["driver", expected]:
        raise SystemExit(1)
    if not re.fullmatch(r"(?:0|[1-9][0-9]*)", row[2]) or int(row[2]) > 60_000_000_000:
        raise SystemExit(1)
PY
}

run_one() {
  local pair=$1 executor=$2
  local expected_executor=tokio-1.53.1
  [[ "$executor" == bounded ]] && expected_executor=allocatbelt
  local stdout="$cell_dir/${pair}-${executor}.stdout.tsv"
  local shutdown_report="$cell_dir/${pair}-${executor}.shutdown.tsv"
  local timing="$cell_dir/${pair}-${executor}.time.txt" status validation p99_qualification=not_applicable
  local -a args=(--executor "$executor" --workload "$workload" --mode "$mode")
  if [[ "$mode" == open_loop ]]; then args+=(--rate "$rate"); fi
  local -a command=(taskset -c "$cpu_set" /usr/bin/time -v -o "$timing" timeout --signal=KILL 900s env "ALLOCATBELT_APP_SHUTDOWN_REPORT=$shutdown_report" "$binary" "${args[@]}")
  local argv
  printf -v argv '%q ' "${command[@]}"
  set +e
  "${command[@]}" > "$stdout" 2> "$cell_dir/${pair}-${executor}.stderr.txt"
  status=$?
  set -e
  validation=invalid
  if [[ $status -eq 0 && ! -s "$cell_dir/${pair}-${executor}.stderr.txt" ]] && \
    validate_output "$stdout" "$expected_executor" && \
    validate_shutdown_report "$shutdown_report" "$expected_executor"; then
    validation=valid
    if [[ "$mode" == open_loop ]]; then
      if awk -F '\t' '
        NR==1 {for(i=1;i<=NF;i++) col[$i]=i; next}
        { attempted=$(col["attempted"]); admitted=$(col["admitted"]);
          rejected=$(col["rejected_full"])+$(col["rejected_resource"]); completed=$(col["completed_on_time"])+$(col["completed_late"]);
          if(attempted==5000 && admitted==5000 && rejected==0 && completed==5000) exit 0;
          exit 1; }
      ' "$stdout"; then
        p99_qualification=eligible
      else
        p99_qualification=descriptive_only
      fi
    fi
  else
    failed=1
    p99_qualification=invalid
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$pair" "$executor" "$status" "$validation" "$p99_qualification" "$argv" "$(basename "$stdout")" "$(basename "$timing")" \
    >> "$cell_dir/processes.tsv"
  printf 'shutdown_report_%s_%s\t%s\n' "$pair" "$executor" "$(basename "$shutdown_report")" >> "$cell_dir/metadata.tsv"
}

# Alternate the executor order across pairs so pair-level drift is not tied to
# one executor. Each call starts a fresh process; failures are retained.
if (( pair_ordinal % 2 == 0 )); then
  run_one bounded bounded
  run_one tokio tokio
else
  run_one tokio tokio
  run_one bounded bounded
fi

source_digest_after=$(source_hash) || { failed=1; source_digest_after=unavailable; }
binary_digest_after=$(sha256sum "$binary" | awk '{print $1}') || {
  failed=1
  binary_digest_after=unavailable
}
{
  printf 'source_tree_sha256_before\t%s\n' "$source_digest"
  printf 'source_tree_sha256_after\t%s\n' "$source_digest_after"
  printf 'binary_sha256_before\t%s\n' "$binary_digest"
  printf 'binary_sha256_after\t%s\n' "$binary_digest_after"
} >> "$cell_dir/metadata.tsv"
[[ $(awk -F '\t' '$1=="source_tree_sha256_before"{b=$2} $1=="source_tree_sha256_after"{a=$2} END{print (b==a)?"same":"changed"}' "$cell_dir/metadata.tsv") == same ]] || failed=1
[[ "$binary_digest" == "$binary_digest_after" ]] || failed=1
if [[ $failed -eq 0 ]]; then
  printf 'pair_status\tvalidated\n' > "$cell_dir/pair.complete"
  exit 0
fi
printf 'pair_status\tfailed_or_invalid\n' > "$cell_dir/pair.failed"
exit 1
