#!/usr/bin/env bash
# Run one fresh bounded/Tokio pair for a single application comparison cell.
# This harness is preparation only; keep raw timing evidence outside the source checkout.
set -euo pipefail
export LC_ALL=C
qualification_runtime_readback_supported=0
external_pressure_driver_supported=0

usage() {
  echo "usage: $0 BINARY ALLOCATOR WORKLOAD MODE RATE_OR_DASH CPU_SET RUN_ID OUTPUT_ROOT [ARRIVALS TRACE_S DRAIN_S SHUTDOWN_S PROCESS_S ORACLE_FILE ORACLE_SHA256 PROFILE PAIR_KIND [BASELINE_BINARY BASELINE_ALLOCATOR BASELINE_ORACLE BASELINE_ORACLE_SHA256]]" >&2
  echo "  open_loop requires a precomputed oracle file and its SHA-256 digest." >&2
}

if [[ $# -lt 8 || $# -gt 21 ]]; then usage; exit 2; fi
binary_arg=$1
allocator=$2
workload=$3
mode=$4
rate=$5
cpu_set=$6
run_id=$7
output_root=$8
arrivals=${9:-5000}
trace_deadline=${10:-300}
drain_deadline=${11:-300}
shutdown_deadline=${12:-60}
process_deadline=${13:-1200}
oracle_file_arg=${14:-}
oracle_digest_expected=${15:-}
profile=${16:-steady}
pair_kind=${17:-matched}
baseline_binary_arg=${18:-}
baseline_allocator=${19:-}
baseline_oracle_arg=${20:-}
baseline_oracle_digest_expected=${21:-}

for deadline in "$trace_deadline" "$drain_deadline" "$shutdown_deadline" "$process_deadline"; do
  [[ "$deadline" =~ ^[1-9][0-9]*$ && ${#deadline} -le 4 ]] || { echo "deadlines must be positive finite integer seconds" >&2; exit 2; }
done
(( trace_deadline <= 3600 && drain_deadline <= 3600 && shutdown_deadline <= 600 && process_deadline <= 7200 )) || { echo "deadline exceeds its finite safety bound" >&2; exit 2; }

case "$allocator" in allocatbelt|mimalloc-secure|mimalloc-standard|system) ;; *) usage; exit 2 ;; esac
case "$workload" in cpu|memory|http|disk|mixed) ;; *) usage; exit 2 ;; esac
case "$mode" in capacity|open_loop) ;; *) usage; exit 2 ;; esac
case "$profile" in steady|mixed|burst|oversubscribed|safety_overload) ;; *) echo "unknown profile: $profile" >&2; exit 2 ;; esac
case "$pair_kind" in matched|aa-bounded|aa-tokio|allocator-match|pressure-matched|pressure-allocator-match) ;; *) echo "PAIR_KIND is not a frozen matched comparison family" >&2; exit 2 ;; esac
if [[ "$pair_kind" == pressure-matched || "$pair_kind" == pressure-allocator-match ]]; then
  (( external_pressure_driver_supported == 1 )) || { echo "external-pressure timing is hard-disabled until the pinned feedback driver and runtime readbacks are implemented" >&2; exit 2; }
fi
if [[ "$pair_kind" == allocator-match || "$pair_kind" == pressure-allocator-match ]]; then
  case "$baseline_allocator" in mimalloc-secure|mimalloc-standard|system) ;; *) echo "allocator-match requires a frozen baseline allocator" >&2; exit 2 ;; esac
  [[ "$allocator" == allocatbelt && "$baseline_allocator" != "$allocator" && -n "$baseline_binary_arg" ]] || { echo "allocator-match requires allocatbelt candidate and a distinct baseline binary" >&2; exit 2; }
else
  [[ -z "$baseline_binary_arg" && -z "$baseline_allocator" && -z "$baseline_oracle_arg" && -z "$baseline_oracle_digest_expected" ]] || { echo "baseline arguments require allocator-match" >&2; exit 2; }
fi
if [[ "$workload" == mixed && "$profile" == steady ]]; then
  echo "mixed workload requires mixed, burst, oversubscribed, or safety_overload profile" >&2
  exit 2
fi
if [[ "$profile" == mixed && "$workload" != mixed ]]; then
  echo "mixed profile requires mixed workload" >&2
  exit 2
fi
if [[ "$mode" == capacity && "$profile" != steady && "$profile" != mixed && "$profile" != burst && "$profile" != oversubscribed ]]; then
  echo "capacity mode supports steady, mixed, burst, or oversubscribed profiles" >&2
  exit 2
fi
phase_trace=$trace_deadline
phase_trace_deadline=$trace_deadline
if [[ "$mode" == capacity ]]; then
  phase_trace=30
  # The producer observes the horizon, then records its completion. Bound
  # coordinator/scheduling overshoot separately from the throughput horizon.
  phase_trace_deadline=31
fi
shutdown_units=1
case "$workload" in
  http) shutdown_units=3 ;;
  disk) shutdown_units=2 ;;
  mixed) shutdown_units=4 ;;
esac
if [[ "$mode" == capacity ]]; then
  [[ "$rate" == - ]] || { echo "capacity mode requires RATE_OR_DASH=-" >&2; exit 2; }
else
  [[ "$rate" =~ ^[1-9][0-9]*$ && ${#rate} -le 10 ]] && (( rate <= 1000000000 )) || { echo "open_loop rate must be in 1..=1000000000" >&2; exit 2; }
  [[ "$arrivals" =~ ^[1-9][0-9]*$ && ${#arrivals} -le 7 ]] && (( arrivals <= 1000000 )) || { echo "ARRIVALS must be in 1..=1000000" >&2; exit 2; }
  if [[ "$profile" == burst ]]; then
    (( rate <= 250000000 )) || { echo "burst average rate must not exceed 250000000 arrivals per second" >&2; exit 2; }
    phase_trace=$(( (arrivals + rate - 1) / rate ))
  else
    phase_trace=$(( (arrivals + rate - 1) / rate ))
  fi
  (( phase_trace <= trace_deadline )) || { echo "open-loop arrival plan exceeds its configured finite trace deadline" >&2; exit 2; }
  phase_trace_deadline=$trace_deadline
fi
required_process=$((120 + phase_trace_deadline + drain_deadline + shutdown_deadline * shutdown_units))
(( process_deadline >= required_process )) || { echo "process deadline must cover setup, trace, drain, and every shutdown phase" >&2; exit 2; }
if [[ "$mode" == capacity && "$arrivals" != 5000 ]]; then
  echo "capacity mode does not accept ARRIVALS" >&2
  exit 2
fi
if [[ "$mode" == open_loop ]]; then
  [[ -n "$oracle_file_arg" && "$oracle_digest_expected" =~ ^[0-9a-f]{64}$ ]] || {
    echo "open_loop requires ORACLE_FILE and its 64-character ORACLE_SHA256" >&2
    exit 2
  }
  if [[ "$pair_kind" == allocator-match || "$pair_kind" == pressure-allocator-match ]]; then
    [[ -n "$baseline_oracle_arg" && "$baseline_oracle_digest_expected" =~ ^[0-9a-f]{64}$ ]] || { echo "allocator-match open_loop requires its baseline oracle and digest" >&2; exit 2; }
  fi
elif [[ -n "$oracle_file_arg" || -n "$oracle_digest_expected" ]]; then
  echo "capacity mode does not accept an open-loop oracle" >&2
  exit 2
elif [[ -n "$baseline_oracle_arg" || -n "$baseline_oracle_digest_expected" ]]; then
  echo "capacity mode does not accept a baseline oracle" >&2
  exit 2
fi
[[ "$run_id" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "RUN_ID has unsupported characters" >&2; exit 2; }
pair_suffix=${run_id##*[!0-9]}
[[ -n "$pair_suffix" && ${#pair_suffix} -le 3 ]] || { echo "RUN_ID must end in a pair ordinal from 1 through 36" >&2; exit 2; }
pair_ordinal=$((10#$pair_suffix))
(( pair_ordinal >= 1 && pair_ordinal <= 36 )) || { echo "pair ordinal must be from 1 through 36" >&2; exit 2; }

for command in taskset timeout sha256sum awk rustc uname python3 od tr cmp; do
  command -v "$command" >/dev/null || { echo "missing required command: $command" >&2; exit 2; }
done
[[ -x /usr/bin/time ]] || { echo "GNU /usr/bin/time is required" >&2; exit 2; }
(( qualification_runtime_readback_supported == 1 )) || { echo "qualification timing is hard-disabled until the binary provides verified runtime-domain, policy, and ceiling readback" >&2; exit 2; }

if [[ "$mode" == open_loop ]]; then
  oracle_file=$(realpath "$oracle_file_arg") || exit 2
  [[ -f "$oracle_file" ]] || { echo "oracle file is missing: $oracle_file" >&2; exit 2; }
  oracle_digest_actual=$(sha256sum "$oracle_file" | awk '{print $1}') || exit 2
  [[ "$oracle_digest_actual" == "$oracle_digest_expected" ]] || { echo "oracle SHA-256 differs from its manifest value" >&2; exit 2; }
  baseline_oracle_file=
  baseline_oracle_digest_actual=
  if [[ "$pair_kind" == allocator-match || "$pair_kind" == pressure-allocator-match ]]; then
    baseline_oracle_file=$(realpath "$baseline_oracle_arg") || exit 2
    [[ -f "$baseline_oracle_file" ]] || { echo "baseline oracle file is missing" >&2; exit 2; }
    baseline_oracle_digest_actual=$(sha256sum "$baseline_oracle_file" | awk '{print $1}') || exit 2
    [[ "$baseline_oracle_digest_actual" == "$baseline_oracle_digest_expected" ]] || { echo "baseline oracle SHA-256 differs from its manifest value" >&2; exit 2; }
  fi
else
  oracle_file=
  oracle_digest_actual=
  baseline_oracle_file=
  baseline_oracle_digest_actual=
fi

repo_root=$(git rev-parse --show-toplevel) || exit 2
binary=$(realpath "$binary_arg") || exit 2
[[ -x "$binary" ]] || { echo "binary is not executable: $binary" >&2; exit 2; }
baseline_binary=
baseline_binary_digest=
if [[ "$pair_kind" == allocator-match || "$pair_kind" == pressure-allocator-match ]]; then
  baseline_binary=$(realpath "$baseline_binary_arg") || exit 2
  [[ -x "$baseline_binary" ]] || { echo "baseline binary is not executable: $baseline_binary" >&2; exit 2; }
  baseline_binary_digest=$(sha256sum "$baseline_binary" | awk '{print $1}') || exit 2
fi
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
comparison_family=fixed_policy
if [[ "$pair_kind" == pressure-matched || "$pair_kind" == pressure-allocator-match ]]; then
  comparison_family=external_pressure
fi

{
  printf 'key\tvalue\n'
  printf 'run_id\t%s\n' "$run_id"
printf 'allocator\t%s\n' "$allocator"
printf 'baseline_allocator\t%s\n' "$baseline_allocator"
  printf 'workload\t%s\n' "$workload"
  printf 'profile\t%s\n' "$profile"
  printf 'pair_kind\t%s\n' "$pair_kind"
  printf 'comparison_family\t%s\n' "$comparison_family"
  printf 'resource_scope_binding\t%s\n' 'local ResourceScope; no shared runtime ResourceDomain'
  printf 'policy_qualification_stage\t%s\n' 'profile harness; no global or tenant ResourceDomain binding'
  printf 'mode\t%s\n' "$mode"
  printf 'rate_per_second\t%s\n' "$rate"
  printf 'average_rate_per_second\t%s\n' "$rate"
  if [[ "$profile" == burst && "$mode" == open_loop ]]; then
    printf 'pulse_rate_per_second\t%s\n' "$((rate * 4))"
  elif [[ "$profile" == burst ]]; then
    printf 'pulse_rate_per_second\tbacklogged_capacity\n'
    printf 'capacity_pulse_ns\t250000000\n'
    printf 'capacity_idle_ns\t750000000\n'
  else
    printf 'pulse_rate_per_second\t%s\n' "$rate"
  fi
  printf 'requested_arrivals\t%s\n' "$arrivals"
  printf 'trace_deadline_seconds\t%s\n' "$trace_deadline"
  printf 'phase_trace_seconds\t%s\n' "$phase_trace"
  printf 'phase_trace_deadline_seconds\t%s\n' "$phase_trace_deadline"
  printf 'drain_deadline_seconds\t%s\n' "$drain_deadline"
  printf 'shutdown_deadline_seconds\t%s\n' "$shutdown_deadline"
  printf 'process_deadline_seconds\t%s\n' "$process_deadline"
  printf 'oracle_file\t%s\n' "$oracle_file"
  printf 'oracle_sha256\t%s\n' "$oracle_digest_actual"
  printf 'setup_deadline_seconds\t120\n'
  printf 'process_deadline_policy\t%s\n' 'setup reserve + trace + drain + one shutdown budget per bounded driver phase'
  printf 'cpu_set\t%s\n' "$cpu_set"
  printf 'source_head\t%s\n' "$head_commit"
  printf 'source_tree_sha256\t%s\n' "$source_digest"
printf 'binary_path\t%s\n' "$binary"
printf 'binary_sha256\t%s\n' "$binary_digest"
printf 'baseline_binary_path\t%s\n' "$baseline_binary"
printf 'baseline_binary_sha256\t%s\n' "$baseline_binary_digest"
  printf 'host\t%s\n' "$host"
  printf 'kernel\t%s\n' "$kernel"
  printf 'rustc\t%s\n' "$rust_version"
  if command -v lscpu >/dev/null; then
    printf 'cpu_model\t%s\n' "$(lscpu | awk -F: '/Model name/ {sub(/^[[:space:]]+/, "", $2); print $2; exit}')"
  fi
  printf 'governor\t%s\n' "$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || printf unavailable)"
  printf 'argv_policy\t%s\n' 'one fresh process; external timeout is hard whole-process watchdog; binary process budget starts at setup; taskset applied to each process'
} > "$cell_dir/metadata.tsv"

printf 'pair\texecutor\tallocator\texit_code\trow_validation\tp99_qualification\targv\tstdout\ttime_report\tids_sha256\tshutdown_sha256\tcapacity_family_sha256\n' > "$cell_dir/processes.tsv"
failed=0

validate_output() {
  local output=$1 expected_executor=$2 expected_allocator=$3 header
  local expected_schema=2
  local expected_async=4
  [[ "$profile" == oversubscribed ]] && expected_async=2
  local expected_blocking=0 expected_topology="$expected_async async workers" expected_task_limit=8
  local expected_retained=0 expected_managed=0 expected_disk=0 expected_network=0
  case "$workload" in
    memory) expected_retained=8; expected_managed=163840 ;;
    http)
      expected_schema=http-nonblocking-connect-v1
      expected_blocking=1 expected_task_limit=17 expected_managed=141312 expected_network=16
      if [[ "$expected_executor" == allocatbelt ]]; then
        expected_topology="$expected_async async + 1 owning blocking connector + owning reactor; NetHandle::connect_nonblocking"
      else
        expected_topology="$expected_async async + 1 reserved blocking worker (Tokio TcpSocket::connect) + integrated I/O driver"
      fi
      ;;
    disk)
      expected_blocking=$expected_async expected_managed=1573000 expected_disk=8
      if [[ "$expected_executor" == allocatbelt ]]; then
        expected_topology="$expected_async async + $expected_async filesystem workers"
      else
        expected_topology="$expected_async async + $expected_async blocking workers"
      fi
      ;;
    mixed)
      expected_schema=mixed-application-v1
      expected_blocking=$expected_async expected_task_limit=17
      expected_retained=8 expected_managed=1638536 expected_disk=8 expected_network=16
      if [[ "$expected_executor" == allocatbelt ]]; then
        expected_topology="$expected_async async + $expected_async owning blocking workers (connector and filesystem) + owning reactor"
      else
        expected_topology="$expected_async async + Tokio blocking pool max$expected_async (filesystem execution cap$expected_async) + integrated I/O driver"
      fi
      ;;
  esac
  local expected_header='schema	allocator	executor	workload	mode	async_workers	blocking_workers	topology	logical_window	global_task_limit	retained_window	arrival_rate_per_second	requested_arrivals	attempted	admitted	rejected_full	rejected_resource	completed_on_time	completed_late	errors	cancellations	unresolved	lost	result_digest	expected_digest	capacity_publications_per_second	successful_throughput_through_drain_per_second	setup_ns	timer_pair_median_ns	wall_through_drain_ns	drain_tail_ns	response_p50_ns	response_p95_ns	response_p99_ns	producer_lateness_mean_ns	producer_lateness_max_ns	max_observed_managed_bytes	retained_managed_bytes	managed_limit_bytes	disk_limit_ops	network_limit_ops	final_managed_bytes	final_disk_ops	final_network_ops	rss_before_kib	rss_after_drain_kib	rss_after_shutdown_kib	hwm_before_kib	hwm_after_drain_kib	hwm_after_shutdown_kib	shutdown_ns	rejected_logical_window	rejected_backend_full'
  [[ $(wc -l < "$output") -eq 2 ]] || return 1
  header=$(sed -n '1p' "$output")
  [[ "$header" == "$expected_header" ]] || return 1
  python3 - "$output" "$expected_header" "$expected_allocator" "$expected_executor" "$workload" "$mode" \
    "$rate" "$expected_blocking" "$expected_topology" "$expected_task_limit" \
    "$expected_retained" "$expected_managed" "$expected_disk" "$expected_network" \
    "$expected_schema" "$arrivals" "$process_deadline" "$drain_deadline" "$expected_async" <<'PY'
import re
import sys
from decimal import Decimal, InvalidOperation
from pathlib import Path

(
    path, expected_header, allocator, executor, workload, mode, rate,
    blocking, topology, task_limit, retained, managed, disk, network, expected_schema, arrivals, process_seconds, drain_seconds, expected_async,
) = sys.argv[1:]
lines = Path(path).read_text(encoding="utf-8").splitlines()
headers = expected_header.split("\t")
if len(headers) != 53 or len(set(headers)) != 53 or lines[0] != expected_header:
    raise SystemExit(1)
values = lines[1].split("\t")
if len(values) != len(headers):
    raise SystemExit(1)
row = dict(zip(headers, values, strict=True))
if (row["schema"], row["allocator"], row["executor"], row["workload"], row["mode"]) != (
    expected_schema, allocator, executor, workload, mode,
):
    raise SystemExit(1)

integer_fields = """async_workers blocking_workers logical_window global_task_limit
retained_window requested_arrivals attempted admitted rejected_full rejected_logical_window
rejected_backend_full rejected_resource
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
    "async_workers": expected_async, "blocking_workers": blocking, "topology": topology,
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
if attempted > (10_000_000 if mode == "capacity" else int(arrivals)):
    raise SystemExit(1)
if any(number > attempted for number in (
    admitted, rejected_full, rejected_resource, completed_on_time, completed_late,
    errors, cancellations, unresolved, int(row["lost"]),
)):
    raise SystemExit(1)
if attempted != admitted + rejected_full + rejected_resource:
    raise SystemExit(1)
if rejected_full != int(row["rejected_logical_window"]) + int(row["rejected_backend_full"]):
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
if workload in ("memory", "http", "mixed") and int(row["max_observed_managed_bytes"]) > int(managed):
    raise SystemExit(1)
if workload in ("memory", "http", "mixed") and int(row["retained_managed_bytes"]) > int(managed):
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
    if int(row["arrival_rate_per_second"]) != int(rate) or row["requested_arrivals"] != arrivals or attempted != int(arrivals):
        raise SystemExit(1)
    if int(row["response_p50_ns"]) > int(row["response_p95_ns"]) or int(row["response_p95_ns"]) > int(row["response_p99_ns"]):
        raise SystemExit(1)

wall_ns = int(row["wall_through_drain_ns"])
if wall_ns <= 0 or wall_ns > int(process_seconds) * 1_000_000_000 or int(row["drain_tail_ns"]) > int(drain_seconds) * 1_000_000_000:
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
if any(int(row[field]) > int(process_seconds) * 1_000_000_000 for field in time_fields):
    raise SystemExit(1)
if int(row["drain_tail_ns"]) > int(drain_seconds) * 1_000_000_000:
    raise SystemExit(1)
if any(int(row[field]) > (1 << 53) - 1 for field in (
    "rss_before_kib", "rss_after_drain_kib", "rss_after_shutdown_kib",
    "hwm_before_kib", "hwm_after_drain_kib", "hwm_after_shutdown_kib",
)):
    raise SystemExit(1)
PY
}

validate_shutdown_report() {
  local report=$1 expected_executor=$2 trace_seconds=$3 shutdown_seconds=$4 process_seconds=$5 output=$6 report_nonce=$7 run_id=$8 allocator=$9 profile=${10} source_hash=${11} binary_hash=${12}
  python3 - "$report" "$expected_executor" "$workload" "$trace_seconds" "$shutdown_seconds" "$process_seconds" "$output" "$report_nonce" "$run_id" "$allocator" "$profile" "$source_hash" "$binary_hash" <<'PY'
import re
import sys
from pathlib import Path

path, executor, workload, trace_seconds, shutdown_seconds, process_seconds, output, nonce, run_id, allocator, profile, source_hash, binary_hash = sys.argv[1:]
try:
    lines = Path(path).read_text(encoding="utf-8").splitlines()
except OSError:
    raise SystemExit(1)
if not lines or lines[0] != "schema\tallocatbelt-app-phase-v1\t":
    raise SystemExit(1)
identity = [line.split("\t") for line in lines[1:9]]
expected_identity = [
    ["identity", "report_nonce", nonce], ["identity", "run_id", run_id],
    ["identity", "executor", executor], ["identity", "allocator", allocator],
    ["identity", "workload", workload], ["identity", "profile", profile],
    ["identity", "source_sha256", source_hash], ["identity", "binary_sha256", binary_hash],
]
if identity != expected_identity:
    raise SystemExit(1)
if executor == "allocatbelt":
    drivers = ["allocatbelt owning HTTP runtime"] if workload in ("http", "mixed") else ["allocatbelt application driver"]
else:
    drivers = ["Tokio HTTP runtime", "Tokio fixed rate timer"] if workload in ("http", "mixed") else ["Tokio runtime"]
if len(lines) != len(drivers) + 15:
    raise SystemExit(1)
phase_rows = [line.split("\t") for line in lines[9:15]]
phase_names = ["production_trace", "production_cpu_started_ns", "production_cpu_ended_ns", "production_through_drain_cpu_ns", "successful_completions", "cpu_ns_per_successful_completion"]
if any(len(row) != 3 or row[:2] != ["phase", name] for row, name in zip(phase_rows, phase_names, strict=True)):
    raise SystemExit(1)
if any(not re.fullmatch(r"(?:0|[1-9][0-9]*)", row[2]) for row in phase_rows):
    raise SystemExit(1)
if int(phase_rows[0][2]) > int(trace_seconds) * 1_000_000_000:
    raise SystemExit(1)
started, ended, cpu_ns, successes = (int(phase_rows[index][2]) for index in (1, 2, 3, 4))
if ended < started or ended - started != cpu_ns or cpu_ns > int(process_seconds) * 128 * 1_000_000_000:
    raise SystemExit(1)
if int(phase_rows[5][2]) != (cpu_ns // successes if successes else 0):
    raise SystemExit(1)
try:
    output_rows = Path(output).read_text(encoding="utf-8").splitlines()
    output_header = output_rows[0].split("\t")
    output_row = output_rows[1].split("\t")
except (OSError, IndexError):
    raise SystemExit(1)
expected_successes = int(output_row[output_header.index("completed_on_time")]) + int(output_row[output_header.index("completed_late")])
if successes != expected_successes:
    raise SystemExit(1)
for line, expected in zip(lines[15:], drivers, strict=True):
    row = line.split("\t")
    if len(row) != 3 or row[:2] != ["driver", expected]:
        raise SystemExit(1)
    if not re.fullmatch(r"(?:0|[1-9][0-9]*)", row[2]) or int(row[2]) > int(shutdown_seconds) * 1_000_000_000:
        raise SystemExit(1)
PY
}

validate_oracle_file() {
  local oracle=$1 expected_count=$2 expected_rate=$3 expected_workload=$4 expected_profile=$5 source_hash=$6 binary_hash=$7
  python3 - "$oracle" "$expected_count" "$expected_rate" "$expected_workload" "$expected_profile" "$source_hash" "$binary_hash" <<'PY'
import re
import sys
from pathlib import Path

path, expected_count, expected_rate, expected_workload, expected_profile, source_hash, binary_hash = sys.argv[1:]
try:
    lines = Path(path).read_text(encoding="utf-8").splitlines()
except OSError:
    raise SystemExit(1)
configs = {
    "cpu": "rounds=50000",
    "memory": "initial_bytes=4096;grown_bytes=8192;seed=0x243f6a8885a308d3",
    "disk": "bytes=196625;offset=4096;seed=0xa4093822299f31d0",
    "http": "body_bytes=4096",
    "mixed": "interleave=cpu,memory,http,disk",
}

rate = int(expected_rate)
count = int(expected_count)
pulse_rate = rate * 4 if expected_profile == "burst" else rate
duration_ns = ((count + rate - 1) // rate) * 1_000_000_000 if expected_profile == "burst" else count * 1_000_000_000 // rate
expected_header = [
    "schema\tallocatbelt-app-oracle-v2",
    f"source_sha256\t{source_hash}",
    f"binary_sha256\t{binary_hash}",
    f"profile\t{expected_profile}",
    f"workload\t{expected_workload}",
    "mode\topen_loop",
    f"average_rate_per_second\t{rate}",
    f"pulse_rate_per_second\t{pulse_rate}",
    f"arrivals\t{count}",
    f"trace_duration_ns\t{duration_ns}",
    f"kernel_config\t{configs[expected_workload]}",
    "id\tscheduled_ns\tworkload\texpected_checksum",
]
if len(lines) != count + len(expected_header) or lines[:len(expected_header)] != expected_header:
    raise SystemExit(1)
family = ("cpu", "memory", "http", "disk")
for expected_id, line in enumerate(lines[len(expected_header):]):
    fields = line.split("\t")
    if len(fields) != 4 or fields[0] != str(expected_id):
        raise SystemExit(1)
    if expected_profile == "burst":
        cycle, slot = divmod(expected_id, rate)
        scheduled = cycle * 1_000_000_000 + slot * 250_000_000 // rate
    else:
        scheduled = expected_id * 1_000_000_000 // rate
    expected_family = family[expected_id % 4] if expected_workload == "mixed" else expected_workload
    if fields[1] != str(scheduled) or fields[2] != expected_family:
        raise SystemExit(1)
    if not re.fullmatch(r"(?:0|[1-9][0-9]*)", fields[3]) or int(fields[3]) >= (1 << 64):
        raise SystemExit(1)
PY
}

validate_capacity_family_report() {
  local report=$1 output=$2 expected_executor=$3 report_nonce=$4 run_id=$5 allocator=$6 profile=$7 source_hash=$8 binary_hash=$9
  python3 - "$report" "$output" "$expected_executor" "$report_nonce" "$run_id" "$allocator" "$workload" "$profile" "$source_hash" "$binary_hash" <<'PY'
import re
import sys
from pathlib import Path

path, output, executor, nonce, run_id, allocator, workload, profile, source_hash, binary_hash = sys.argv[1:]
try:
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    output_lines = Path(output).read_text(encoding="utf-8").splitlines()
except OSError:
    raise SystemExit(1)
if not lines or lines[0] != "schema\tallocatbelt-app-capacity-families-v1\t":
    raise SystemExit(1)
expected = {
    "report_nonce": nonce, "run_id": run_id, "executor": executor, "allocator": allocator,
    "workload": workload, "profile": profile, "source_sha256": source_hash, "binary_sha256": binary_hash,
}
identity = {}
families = {}
phases = {}
for line in lines[1:]:
    row = line.split("\t")
    if len(row) == 3 and row[0] == "identity":
        if row[1] in identity:
            raise SystemExit(1)
        identity[row[1]] = row[2]
    elif len(row) == 4 and row[0] == "family":
        if row[1] in families:
            raise SystemExit(1)
        families[row[1]] = row[2:]
    elif len(row) == 3 and row[0] == "phase":
        if row[1] in phases:
            raise SystemExit(1)
        phases[row[1]] = row[2]
    else:
        raise SystemExit(1)
if identity != expected or set(families) != {"cpu", "memory", "http", "disk"}:
    raise SystemExit(1)
if phases != {"trace_seconds": "30", "profile": profile}:
    raise SystemExit(1)
columns = output_lines[0].split("\t")
row = output_lines[1].split("\t")
counts = dict(zip(columns, row, strict=True))
if counts["workload"] != "mixed" or counts["mode"] != "capacity":
    raise SystemExit(1)
attempted = int(counts["attempted"])
completed_on_time = int(counts["completed_on_time"])
if sum(int(values[0]) for values in families.values()) != attempted or sum(int(values[1]) for values in families.values()) != completed_on_time:
    raise SystemExit(1)
for index, family in enumerate(("cpu", "memory", "http", "disk")):
    scheduled, successes = families[family]
    if not re.fullmatch(r"(?:0|[1-9][0-9]*)", scheduled) or not re.fullmatch(r"(?:0|[1-9][0-9]*)", successes):
        raise SystemExit(1)
    expected_count = attempted // 4 + (1 if index < attempted % 4 else 0)
    if int(scheduled) != expected_count or int(successes) > int(scheduled):
        raise SystemExit(1)
PY
}

validate_id_report() {
  local report=$1 expected_count=$2 process_seconds=$3 trace_seconds=$4 rate=$5 workload=$6 profile=$7 output=$8
  local oracle=$9 oracle_digest=${10} run_id=${11} nonce=${12} executor=${13} allocator=${14} source_hash=${15} binary_hash=${16}
  python3 - "$report" "$expected_count" "$process_seconds" "$trace_seconds" "$rate" "$workload" "$profile" "$output" \
    "$oracle" "$oracle_digest" "$run_id" "$nonce" "$executor" "$allocator" "$source_hash" "$binary_hash" <<'PY'
import re
import sys
import hashlib
from pathlib import Path

(
    path, expected_count, process_seconds, trace_seconds, rate, workload, profile, output,
    oracle_path, oracle_digest, run_id, nonce, executor, allocator, source_hash, binary_hash,
) = sys.argv[1:]
try:
    lines = Path(path).read_text(encoding="utf-8").splitlines()
except OSError:
    raise SystemExit(1)
if len(lines) < 3 or lines[0] != "schema\tallocatbelt-app-arrivals-v3":
    raise SystemExit(1)
identity = lines[1].split("\t")
if identity != ["identity", nonce, run_id, executor, allocator, workload, profile, source_hash, binary_hash]:
    raise SystemExit(1)
if lines[2] != "id\tworkload\tscheduled_ns\tcompletion_ns\tterminal\tchecksum\texpected_checksum":
    raise SystemExit(1)
if len(lines) != int(expected_count) + 3:
    raise SystemExit(1)
oracle_bytes = Path(oracle_path).read_bytes()
if hashlib.sha256(oracle_bytes).hexdigest() != oracle_digest:
    raise SystemExit(1)
oracle_lines = oracle_bytes.decode("utf-8").splitlines()
oracle_start = 12
if len(oracle_lines) != int(expected_count) + oracle_start:
    raise SystemExit(1)
oracle_rows = []
families = ("cpu", "memory", "http", "disk")
for expected_id, line in enumerate(oracle_lines[oracle_start:]):
    fields = line.split("\t")
    if len(fields) != 4 or fields[0] != str(expected_id):
        raise SystemExit(1)
    if not re.fullmatch(r"(?:0|[1-9][0-9]*)", fields[1]) or not re.fullmatch(r"(?:0|[1-9][0-9]*)", fields[3]) or int(fields[3]) >= (1 << 64):
        raise SystemExit(1)
    oracle_rows.append((int(fields[1]), fields[2], int(fields[3])))
max_ns = int(process_seconds) * 1_000_000_000
trace_ns = int(oracle_lines[9].split("\t")[1])
allowed = {"completed", "rejected"}
digest = expected_digest = 0
latencies = []
counts = {family: 0 for family in families}
terminals = {"completed": 0, "rejected": 0, "error": 0}
for expected_id, line in enumerate(lines[3:]):
    fields = line.split("\t")
    if len(fields) != 7:
        raise SystemExit(1)
    if fields[0] != str(expected_id):
        raise SystemExit(1)
    if fields[1] != oracle_rows[expected_id][1] or any(not re.fullmatch(r"(?:0|[1-9][0-9]*)", field) for field in fields[2:4] + fields[5:]):
        raise SystemExit(1)
    scheduled, completed, checksum, expected_checksum = (int(fields[2]), int(fields[3]), int(fields[5]), int(fields[6]))
    if scheduled != oracle_rows[expected_id][0] or expected_checksum != oracle_rows[expected_id][2] or completed < scheduled or completed > max_ns or scheduled >= trace_ns:
        raise SystemExit(1)
    terminal = fields[4]
    if terminal not in ("completed", "rejected", "error"):
        raise SystemExit(1)
    if checksum >= (1 << 64):
        raise SystemExit(1)
    terminals[terminal] += 1
    counts[fields[1]] += int(terminal == "completed")
    if terminal == "rejected":
        if checksum != 0:
            raise SystemExit(1)
    elif terminal == "completed":
        if checksum != expected_checksum:
            raise SystemExit(1)
        latencies.append(completed - scheduled)
        digest = (digest + (checksum if workload == "http" else checksum ^ expected_id)) % (1 << 64)
        expected_digest = (expected_digest + (expected_checksum if workload == "http" else expected_checksum ^ expected_id)) % (1 << 64)
try:
    output_lines = Path(output).read_text(encoding="utf-8").splitlines()
except OSError:
    raise SystemExit(1)
header = output_lines[0].split("\t")
row = output_lines[1].split("\t")
if len(header) != 53 or len(row) != 53:
    raise SystemExit(1)
output_row = dict(zip(header, row, strict=True))
if digest != int(output_row["result_digest"]) or expected_digest != int(output_row["expected_digest"]):
    raise SystemExit(1)
completed_count = terminals["completed"]
rejected = terminals["rejected"]
errors = terminals["error"]
if completed_count + errors != int(output_row["admitted"]) or rejected != int(output_row["rejected_full"]) + int(output_row["rejected_resource"]):
    raise SystemExit(1)
if int(output_row["attempted"]) != int(expected_count) or completed_count + errors + rejected != int(expected_count):
    raise SystemExit(1)
on_time = sum(1 for line in lines[3:] if line.split("\t")[4] == "completed" and int(line.split("\t")[3]) <= trace_ns)
if on_time != int(output_row["completed_on_time"]) or completed_count - on_time != int(output_row["completed_late"]) or errors != int(output_row["errors"]):
    raise SystemExit(1)
latencies.sort()
def percentile(values, p):
    if not values:
        return 0
    rank = max(1, (p * len(values) + 99) // 100)
    return values[rank - 1]
for field, p in (("response_p50_ns", 50), ("response_p95_ns", 95), ("response_p99_ns", 99)):
    if int(output_row[field]) != percentile(latencies, p):
        raise SystemExit(1)
PY
}

if [[ "$mode" == open_loop ]]; then
  generated_oracle="$cell_dir/canonical-oracle.tsv"
  if ! timeout --foreground --signal=TERM --kill-after=3s "${process_deadline}s" "$binary" --emit-oracle-only "$generated_oracle" \
    --source-sha256 "$source_digest" --binary-sha256 "$binary_digest" \
    --workload "$workload" --profile "$profile" --rate "$rate" --arrivals "$arrivals" \
    --trace-deadline-seconds "$trace_deadline" \
    > "$cell_dir/oracle-generator.stdout.txt" 2> "$cell_dir/oracle-generator.stderr.txt"; then
    echo "canonical oracle generation failed before timing" >&2
    printf 'pair_status\tfailed_or_invalid\n' > "$cell_dir/pair.failed"
    exit 1
  fi
  generated_oracle_digest=$(sha256sum "$generated_oracle" | awk '{print $1}') || exit 2
  if [[ "$generated_oracle_digest" != "$oracle_digest_expected" ]] || ! cmp -s "$oracle_file" "$generated_oracle"; then
    echo "manifest oracle differs from the pinned source and binary kernels" >&2
    printf 'pair_status\tfailed_or_invalid\n' > "$cell_dir/pair.failed"
    exit 1
  fi
fi
if [[ "$mode" == open_loop ]] && ! validate_oracle_file "$oracle_file" "$arrivals" "$rate" "$workload" "$profile" "$source_digest" "$binary_digest"; then
  echo "oracle content does not match the frozen workload, rate, or arrival manifest" >&2
  printf 'pair_status\tfailed_or_invalid\n' > "$cell_dir/pair.failed"
  exit 1
fi
if [[ "$mode" == open_loop && ( "$pair_kind" == allocator-match || "$pair_kind" == pressure-allocator-match ) ]] && ! validate_oracle_file "$baseline_oracle_file" "$arrivals" "$rate" "$workload" "$profile" "$source_digest" "$baseline_binary_digest"; then
  echo "baseline oracle content does not match its frozen binary and workload" >&2
  printf 'pair_status\tfailed_or_invalid\n' > "$cell_dir/pair.failed"
  exit 1
fi

run_one() {
  local pair=$1 executor=$2 process_allocator=$3 process_binary_arg=$4 process_oracle_arg=$5 process_oracle_sha_expected=$6
  local expected_executor=tokio-1.53.1
  [[ "$executor" == bounded ]] && expected_executor=allocatbelt
  local process_binary
  process_binary=$(realpath "$process_binary_arg") || { failed=1; return 1; }
  [[ -x "$process_binary" ]] || { failed=1; return 1; }
  local process_binary_sha
  process_binary_sha=$(sha256sum "$process_binary" | awk '{print $1}') || { failed=1; return 1; }
  local process_oracle_file= process_oracle_digest=
  if [[ "$mode" == open_loop ]]; then
    process_oracle_file=$(realpath "$process_oracle_arg") || { failed=1; return 1; }
    [[ -f "$process_oracle_file" ]] || { failed=1; return 1; }
    process_oracle_digest=$(sha256sum "$process_oracle_file" | awk '{print $1}') || { failed=1; return 1; }
    [[ "$process_oracle_digest" == "$process_oracle_sha_expected" ]] || { failed=1; return 1; }
    validate_oracle_file "$process_oracle_file" "$arrivals" "$rate" "$workload" "$profile" "$source_digest" "$process_binary_sha" || { failed=1; return 1; }
  fi
  local stdout="$cell_dir/${pair}-${executor}.stdout.tsv"
  local shutdown_report="$cell_dir/${pair}-${executor}.shutdown.tsv"
  local ids_report="$cell_dir/${pair}-${executor}.ids.tsv"
  local family_report="$cell_dir/${pair}-${executor}.capacity-families.tsv"
  local timing="$cell_dir/${pair}-${executor}.time.txt" status validation p99_qualification=not_applicable ids_sha256=not_applicable
  local -a args=(--executor "$executor" --workload "$workload" --profile "$profile" --mode "$mode" --trace-deadline-seconds "$trace_deadline" --drain-deadline-seconds "$drain_deadline" --shutdown-deadline-seconds "$shutdown_deadline" --process-deadline-seconds "$process_deadline")
  local report_nonce
  report_nonce=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
  [[ "$report_nonce" =~ ^[0-9a-f]{32}$ ]] || { failed=1; return 1; }
  if [[ "$mode" == open_loop ]]; then args+=(--rate "$rate" --arrivals "$arrivals"); fi
  local -a command=(taskset -c "$cpu_set" /usr/bin/time -v -o "$timing" timeout --foreground --signal=TERM --kill-after=3s "${process_deadline}s" env "ALLOCATBELT_APP_SHUTDOWN_REPORT=$shutdown_report" "ALLOCATBELT_APP_ID_REPORT=$ids_report" "ALLOCATBELT_APP_FAMILY_REPORT=$family_report" "ALLOCATBELT_APP_REPORT_NONCE=$report_nonce" "ALLOCATBELT_APP_RUN_ID=$run_id" "ALLOCATBELT_APP_EXECUTOR=$expected_executor" "ALLOCATBELT_APP_ALLOCATOR=$process_allocator" "ALLOCATBELT_APP_WORKLOAD=$workload" "ALLOCATBELT_APP_PROFILE=$profile" "ALLOCATBELT_APP_SOURCE_SHA256=$source_digest" "ALLOCATBELT_APP_BINARY_SHA256=$process_binary_sha" "ALLOCATBELT_APP_ORACLE_FILE=$process_oracle_file" "ALLOCATBELT_APP_ORACLE_SHA256=$process_oracle_digest" "$process_binary" "${args[@]}")
  local argv
  printf -v argv '%q ' "${command[@]}"
  set +e
  "${command[@]}" > "$stdout" 2> "$cell_dir/${pair}-${executor}.stderr.txt"
  status=$?
  set -e
  validation=invalid
  if [[ $status -eq 0 && ! -s "$cell_dir/${pair}-${executor}.stderr.txt" ]] && \
    validate_output "$stdout" "$expected_executor" "$process_allocator" && \
    validate_shutdown_report "$shutdown_report" "$expected_executor" "$phase_trace_deadline" "$shutdown_deadline" "$process_deadline" "$stdout" "$report_nonce" "$run_id" "$process_allocator" "$profile" "$source_digest" "$process_binary_sha" && \
    { [[ "$mode:$workload" != capacity:mixed ]] || validate_capacity_family_report "$family_report" "$stdout" "$expected_executor" "$report_nonce" "$run_id" "$process_allocator" "$profile" "$source_digest" "$process_binary_sha"; } && \
    { [[ "$mode" != open_loop ]] || validate_id_report "$ids_report" "$arrivals" "$process_deadline" "$trace_deadline" "$rate" "$workload" "$profile" "$stdout" "$process_oracle_file" "$process_oracle_digest" "$run_id" "$report_nonce" "$expected_executor" "$process_allocator" "$source_digest" "$process_binary_sha"; }; then
    validation=valid
    if [[ "$mode" == open_loop ]]; then
      ids_sha256=$(sha256sum "$ids_report" | awk '{print $1}')
      [[ "$ids_sha256" =~ ^[0-9a-f]{64}$ ]] || { failed=1; validation=invalid; ids_sha256=invalid; }
      if [[ "$profile" == safety_overload ]]; then
        p99_qualification=safety_only
      elif awk -F '\t' '
        NR==1 {for(i=1;i<=NF;i++) col[$i]=i; next}
        { attempted=$(col["attempted"]); admitted=$(col["admitted"]);
          rejected=$(col["rejected_full"])+$(col["rejected_resource"]); completed=$(col["completed_on_time"])+$(col["completed_late"]);
          minimum='"$([[ "$workload" == mixed ]] && echo 400000 || echo 100000)"';
          if(attempted=='"$arrivals"' && admitted==attempted && rejected==0 && completed==attempted && completed>=minimum) exit 0;
          exit 1; }
      ' "$stdout"; then
        p99_qualification=eligible
      else
        p99_qualification=descriptive_only
      fi
      if [[ "$p99_qualification" == eligible && "$workload" == mixed ]] && ! awk -F '\t' '
        NR<=3 {next}
        $5=="completed" {count[$2]++}
        END {exit !(count["cpu"]>=100000 && count["memory"]>=100000 && count["http"]>=100000 && count["disk"]>=100000)}
      ' "$ids_report"; then
        p99_qualification=descriptive_only
      fi
    fi
  else
    failed=1
    p99_qualification=invalid
  fi
  local shutdown_sha256=not_applicable
  if [[ -f "$shutdown_report" ]]; then
    shutdown_sha256=$(sha256sum "$shutdown_report" | awk '{print $1}') || { failed=1; validation=invalid; shutdown_sha256=invalid; }
  fi
  local family_sha256=not_applicable
  if [[ -f "$family_report" ]]; then
    family_sha256=$(sha256sum "$family_report" | awk '{print $1}') || { failed=1; validation=invalid; family_sha256=invalid; }
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$pair" "$executor" "$process_allocator" "$status" "$validation" "$p99_qualification" "$argv" "$(basename "$stdout")" "$(basename "$timing")" "$ids_sha256" "$shutdown_sha256" "$family_sha256" \
    >> "$cell_dir/processes.tsv"
  printf 'report_nonce_%s_%s\t%s\n' "$pair" "$executor" "$report_nonce" >> "$cell_dir/metadata.tsv"
  printf 'oracle_sha256_%s_%s\t%s\n' "$pair" "$executor" "$process_oracle_digest" >> "$cell_dir/metadata.tsv"
  printf 'shutdown_report_%s_%s\t%s\n' "$pair" "$executor" "$(basename "$shutdown_report")" >> "$cell_dir/metadata.tsv"
  if [[ -f "$ids_report" ]]; then
    printf 'ids_sha256_%s_%s\t%s\n' "$pair" "$executor" "$(sha256sum "$ids_report" | awk '{print $1}')" >> "$cell_dir/metadata.tsv"
  fi
}

# Alternate the executor order across matched pairs. A/A controls repeat the
# same executable, allocator, workload, and executor in two fresh processes.
case "$pair_kind" in
  matched|pressure-matched)
    if (( pair_ordinal % 2 == 0 )); then
      run_one bounded bounded "$allocator" "$binary" "$oracle_file" "$oracle_digest_actual"
      run_one tokio tokio "$allocator" "$binary" "$oracle_file" "$oracle_digest_actual"
    else
      run_one tokio tokio "$allocator" "$binary" "$oracle_file" "$oracle_digest_actual"
      run_one bounded bounded "$allocator" "$binary" "$oracle_file" "$oracle_digest_actual"
    fi
    ;;
  aa-bounded)
    run_one bounded-a bounded "$allocator" "$binary" "$oracle_file" "$oracle_digest_actual"
    run_one bounded-b bounded "$allocator" "$binary" "$oracle_file" "$oracle_digest_actual"
    ;;
  aa-tokio)
    run_one tokio-a tokio "$allocator" "$binary" "$oracle_file" "$oracle_digest_actual"
    run_one tokio-b tokio "$allocator" "$binary" "$oracle_file" "$oracle_digest_actual"
    ;;
  allocator-match|pressure-allocator-match)
    if (( pair_ordinal % 2 == 0 )); then
      run_one baseline bounded "$baseline_allocator" "$baseline_binary" "$baseline_oracle_file" "$baseline_oracle_digest_actual"
      run_one candidate bounded "$allocator" "$binary" "$oracle_file" "$oracle_digest_actual"
    else
      run_one candidate bounded "$allocator" "$binary" "$oracle_file" "$oracle_digest_actual"
      run_one baseline bounded "$baseline_allocator" "$baseline_binary" "$baseline_oracle_file" "$baseline_oracle_digest_actual"
    fi
    ;;
esac

source_digest_after=$(source_hash) || { failed=1; source_digest_after=unavailable; }
binary_digest_after=$(sha256sum "$binary" | awk '{print $1}') || {
  failed=1
  binary_digest_after=unavailable
}
if [[ "$pair_kind" == allocator-match || "$pair_kind" == pressure-allocator-match ]]; then
  baseline_binary_digest_after=$(sha256sum "$baseline_binary" | awk '{print $1}') || {
    failed=1
    baseline_binary_digest_after=unavailable
  }
  [[ "$baseline_binary_digest_after" == "$baseline_binary_digest" ]] || failed=1
else
  baseline_binary_digest_after=
fi
if [[ "$mode" == open_loop ]]; then
  oracle_digest_after=$(sha256sum "$oracle_file" | awk '{print $1}') || {
    failed=1
    oracle_digest_after=unavailable
  }
  if [[ "$pair_kind" == allocator-match || "$pair_kind" == pressure-allocator-match ]]; then
    baseline_oracle_digest_after=$(sha256sum "$baseline_oracle_file" | awk '{print $1}') || {
      failed=1
      baseline_oracle_digest_after=unavailable
    }
    [[ "$baseline_oracle_digest_after" == "$baseline_oracle_digest_expected" && "$baseline_oracle_digest_actual" == "$baseline_oracle_digest_expected" ]] || failed=1
  else
    baseline_oracle_digest_after=
  fi
else
  oracle_digest_after=
  baseline_oracle_digest_after=
fi
{
  printf 'source_tree_sha256_before\t%s\n' "$source_digest"
  printf 'source_tree_sha256_after\t%s\n' "$source_digest_after"
  printf 'binary_sha256_before\t%s\n' "$binary_digest"
  printf 'binary_sha256_after\t%s\n' "$binary_digest_after"
  printf 'baseline_binary_sha256_before\t%s\n' "$baseline_binary_digest"
  printf 'baseline_binary_sha256_after\t%s\n' "$baseline_binary_digest_after"
  printf 'oracle_sha256_before\t%s\n' "$oracle_digest_actual"
  printf 'oracle_sha256_after\t%s\n' "$oracle_digest_after"
  printf 'baseline_oracle_sha256_before\t%s\n' "$baseline_oracle_digest_actual"
  printf 'baseline_oracle_sha256_after\t%s\n' "$baseline_oracle_digest_after"
} >> "$cell_dir/metadata.tsv"
[[ $(awk -F '\t' '$1=="source_tree_sha256_before"{b=$2} $1=="source_tree_sha256_after"{a=$2} END{print (b==a)?"same":"changed"}' "$cell_dir/metadata.tsv") == same ]] || failed=1
[[ "$binary_digest" == "$binary_digest_after" ]] || failed=1
if [[ "$mode" == open_loop ]]; then
  [[ "$oracle_digest_expected" == "$oracle_digest_actual" && "$oracle_digest_actual" == "$oracle_digest_after" ]] || failed=1
fi
if [[ $failed -eq 0 ]]; then
  printf 'pair_status\tvalidated\n' > "$cell_dir/pair.complete"
  exit 0
fi
printf 'pair_status\tfailed_or_invalid\n' > "$cell_dir/pair.failed"
exit 1
