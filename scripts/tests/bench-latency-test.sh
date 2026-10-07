#!/usr/bin/env bash
# Runner argument, schedule execution and result validation using fake binaries.
set -euo pipefail
repo="$(cd "$(dirname "$0")/../.." && pwd)"
script="$repo/scripts/bench-latency.sh"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/bench-latency-test.XXXXXX")"
trap 'rm -rf -- "$tmp"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
if "$script" --lane invalid --bin-dir "$tmp" --out "$tmp/bad" >"$tmp/log" 2>&1; then
  fail "accepted invalid lane"
fi
[[ ! -e "$tmp/bad" ]] || fail "invalid arguments created output"
if "$script" --lane allocator --allocs invalid --out "$tmp/bad-list" >"$tmp/log" 2>&1; then
  fail "accepted invalid allocator list"
fi
[[ ! -e "$tmp/bad-list" ]] || fail "invalid allocator list created output"
for flag in --workers --arrival-rate; do
  if "$script" --lane allocator "$flag" 2 --out "$tmp/conflict" >"$tmp/log" 2>&1; then
    fail "accepted $flag in allocator lane"
  fi
  [[ ! -e "$tmp/conflict" ]] || fail "invalid lane option created output"
done
if "$script" --lane blocking --jobs 3 --workers 4 --out "$tmp/invalid-workers" >"$tmp/log" 2>&1; then
  fail "silently clamped explicit worker count"
fi
[[ ! -e "$tmp/invalid-workers" ]] || fail "invalid worker count created output"
reject_schedule() {
  if "$script" "$@" --print-schedule >"$tmp/log" 2>&1; then fail "accepted invalid arguments: $*"; fi
}
reject_schedule --lane allocator --mode capacity
reject_schedule --lane allocator --window 1
reject_schedule --lane blocking --mode throughput --window 4
reject_schedule --lane blocking --mode capacity --arrival-rate 1000
reject_schedule --lane async --mode capacity --arrival-rate 1000
reject_schedule --lane async --workload local
reject_schedule --lane allocator --workload ready
reject_schedule --lane async --jobs 4 --workers 5
reject_schedule --lane async --jobs 8 --workers 4 --window 3
reject_schedule --lane blocking --mode capacity --jobs 8 --workers 4 --window 3
reject_schedule --lane async --jobs 8 --window 9
reject_schedule --lane async --window 0
reject_schedule --lane async --window 01
reject_schedule --lane async --workload mixed --jobs 64 --window 33 --bytes 2097152
mkdir -p "$tmp/bin"
cat >"$tmp/bin/fake" <<'FAKE'
#!/usr/bin/env bash
lane="" workload=local mode=latency executor=NA workers=4 rate=10000 bytes=256 count=0 window=""
while (($#)); do
  case "$1" in
    --lane) lane="$2" ;; --workload) workload="$2" ;; --mode) mode="$2" ;;
    --executor) executor="$2" ;; --workers) workers="$2" ;; --arrival-rate) rate="$2" ;;
    --ops|--jobs) count="$2" ;; --bytes) bytes="$2" ;; --window) window="$2" ;;
    *) exit 2 ;;
  esac
  shift 2
done
[[ -n "$lane" ]] || exit 2
allocator="${0##*/bench-latency-}"
[[ "$allocator" != mimalloc ]] || allocator=mimalloc-secure
[[ "$allocator" != standard ]] || allocator=mimalloc-standard
printf '%s\n' 'allocator,lane,workload,mode,executor,workers,admission_window,arrival_rate,bytes,requested,attempted,completed,dropped,checksum,elapsed_ns,throughput_per_s,timer_overhead_ns,p50_ns,p95_ns,p99_ns,arrival_lateness_mean_ns,arrival_lateness_max_ns'
checksum=0
sizes=(16 128 512 4096 32768 65536 262144 "$bytes")
# Sum the actual per-job formulas, independently of the runner's closed form.
for ((id=0; id<count; id++)); do
  if [[ "$lane" == allocator ]]; then
    case "$workload" in
      local) value=$((2 * (id % 256) + 64)) ;;
      aligned) value=$((id % 256 + (id + 1) % 256)) ;;
      mixed) value=$((2 * (id % 256) + sizes[id % 8])) ;;
    esac
  elif [[ "$lane" == blocking ]]; then
    value=$((id + bytes * (id % 256)))
  else
    case "$workload" in
      ready) value=$((id + 1)) ;;
      yielding) value=$((id + 36)) ;;
      mixed)
        value=$id
        for ((chunk=0; chunk<8; chunk++)); do value=$((value + bytes * ((id + chunk) % 256))); done ;;
    esac
  fi
  checksum=$((checksum + value))
done
if [[ "$lane" == allocator ]]; then
  executor=NA workers=1 rate=NA window=NA
elif [[ "$lane" == async ]]; then
  executor="$executor-async"
else
  window="${window:-$count}"
fi
printf -v checksum_hex '0x%016x' "$checksum"
fields=("$allocator" "$lane" "$workload" "$mode" "$executor" "$workers" "$window" "$rate" "$bytes" "$count" "$count" "$count" 0 "$checksum_hex" 100 1000 1 10 20 30 0 0)
if [[ "$mode" != latency ]]; then fields[17]=NA; fields[18]=NA; fields[19]=NA; fi
if [[ "$mode" == capacity ]]; then fields[7]=NA; fields[16]=NA; fields[20]=NA; fields[21]=NA; fi
case "${BENCH_LATENCY_FAKE_MODE:-ok}" in
  wrong-workload) fields[2]=wrong ;;
  wrong-window) fields[6]=999 ;;
  wrong-bytes) fields[8]=999 ;;
  wrong-executor) fields[4]=wrong ;;
  overflow) fields[14]=999999999999999999999999 ;;
  bad-checksum) fields[13]=0x0000000000000001 ;;
  bad-percentiles) fields[17]=20; fields[18]=10 ;;
  loss) fields[11]=$((count - 1)); fields[12]=1 ;;
  extra-field) fields+=(extra) ;;
  missing-field) unset 'fields[21]' ;;
  throughput-pct|capacity-pct) fields[17]=10 ;;
  capacity-overhead) fields[16]=1 ;;
  capacity-lateness) fields[20]=0 ;;
  capacity-rate) fields[7]=10000 ;;
esac
IFS=,; printf '%s\n' "${fields[*]}"
[[ "${BENCH_LATENCY_FAKE_MODE:-ok}" != nonzero-valid ]] || exit 7

FAKE
chmod +x "$tmp/bin/fake"
ln -s fake "$tmp/bin/bench-latency-system"
ln -s fake "$tmp/bin/bench-latency-standard"
"$script" --lane allocator --allocs system --reps 1 --ops 3 --bin-dir "$tmp/bin" --out "$tmp/allocator"
[[ "$(wc -l <"$tmp/allocator/results.csv")" == 2 ]] || fail "allocator run row missing"
grep -q ',system,allocator,0,ok,unverified-prebuilt-not-qualifying,system,allocator,' "$tmp/allocator/results.csv" || fail "allocator result row malformed"
[[ "$(tail -1 "$tmp/allocator/results.csv" | cut -d, -f7)" == unverified-prebuilt-not-qualifying ]] || fail "prebuilt evidence was not marked nonqualifying"
[[ "$(cat "$tmp/allocator/runs/r0-p0-system-allocator.argv")" == *"--ops 3 --bytes 256"* ]] || fail "effective allocator argv was not recorded"
"$script" --lane allocator --allocs standard --reps 1 --ops 3 --bin-dir "$tmp/bin" --out "$tmp/standard"
grep -q ',standard,allocator,0,ok,unverified-prebuilt-not-qualifying,mimalloc-standard,allocator,' "$tmp/standard/results.csv" \
  || fail "standard mimalloc result row malformed"
"$script" --lane blocking --allocs system --executors bounded,tokio --reps 2 --jobs 3 --bin-dir "$tmp/bin" --out "$tmp/blocking" >"$tmp/log" 2>&1 || { cat "$tmp/log" >&2; cat "$tmp/blocking/results.csv" >&2; fail "blocking runner invocation failed"; }
[[ "$(wc -l <"$tmp/blocking/results.csv")" == 5 ]] || fail "blocking run rows missing"
[[ "$(tail -n +2 "$tmp/blocking/results.csv" | cut -d, -f6 | sort -u)" == ok ]] || fail "blocking result validation failed"
[[ "$(tail -n +2 "$tmp/blocking/results.csv" | cut -d, -f4 | sort -u | wc -l)" == 2 ]] || fail "both executors were not run"
[[ "$(tail -n +2 "$tmp/blocking/results.csv" | cut -d, -f7 | sort -u)" == unverified-prebuilt-not-qualifying ]] || fail "blocking prebuilt evidence was not marked nonqualifying"
[[ "$(awk -F, '{print NF}' "$tmp/blocking/results.csv" | sort -u)" == 29 ]] || fail "runner did not retain all 22 benchmark fields"
[[ "$(awk -F, '{print NF}' "$tmp/blocking/runs/r0-p0-system-bounded.csv" | sort -u)" == 22 ]] || fail "benchmark header/row shape"
grep -Eq '^source_sha256_before_build: [0-9a-f]{64}$' "$tmp/blocking/environment.txt" || fail "qualification source fingerprint missing"
grep -Eq '^source_sha256_before_output_creation: [0-9a-f]{64}$' "$tmp/blocking/environment.txt" || fail "post-build fingerprint missing"

"$script" --lane blocking --mode capacity --allocs system --executors bounded,tokio --reps 2 --jobs 8 --workers 2 --window 2 --bytes 7 --bin-dir "$tmp/bin" --out "$tmp/blocking-capacity"
[[ "$(tail -n +2 "$tmp/blocking-capacity/results.csv" | cut -d, -f6 | sort -u)" == ok ]] || fail "blocking capacity validation"
capacity_argv="$(cat "$tmp/blocking-capacity/runs/r0-p0-system-bounded.argv")"
[[ "$capacity_argv" == *"--window 2"* && "$capacity_argv" != *"--arrival-rate"* ]] || fail "capacity argv retained a schedule or omitted window"
"$script" --lane async --mode capacity --allocs system --executors bounded --reps 1 --jobs 3 --bin-dir "$tmp/bin" --out "$tmp/async-default"
async_argv="$(cat "$tmp/async-default/runs/r0-p0-system-bounded.argv")"
[[ "$async_argv" == *"--workload ready"* && "$async_argv" == *"--workers 3"* && "$async_argv" == *"--window 3"* ]] || fail "async effective defaults were not matched"
[[ "$async_argv" != *"--arrival-rate"* ]] || fail "async capacity included arrival rate"

# Direct fake work-body summation checks byte wrapping in every async workload
# against the runner's closed-form checksum, across both executors.
for count in 253 255 256 257; do
  for workload in ready yielding mixed; do
    out="$tmp/async-$workload-$count"
    "$script" --lane async --mode capacity --workload "$workload" --allocs system --executors bounded,tokio --reps 2 --jobs "$count" --workers 2 --window 4 --bytes 7 --bin-dir "$tmp/bin" --out "$out"
    [[ "$(tail -n +2 "$out/results.csv" | cut -d, -f6 | sort -u)" == ok ]] || fail "async $workload checksum at count $count"
  done
done
for mode in latency throughput; do
  "$script" --lane async --mode "$mode" --workload mixed --allocs system --executors bounded,tokio --reps 2 --jobs 257 --workers 2 --window 4 --arrival-rate 1234 --bytes 7 --bin-dir "$tmp/bin" --out "$tmp/async-$mode"
  [[ "$(tail -n +2 "$tmp/async-$mode/results.csv" | cut -d, -f6 | sort -u)" == ok ]] || fail "paced async $mode validation"
done
"$script" --lane allocator --mode throughput --allocs system --reps 1 --jobs 3 --bin-dir "$tmp/bin" --out "$tmp/allocator-throughput"
"$script" --lane blocking --mode throughput --allocs system --executors tokio --reps 1 --jobs 3 --bin-dir "$tmp/bin" --out "$tmp/blocking-throughput"

# Eight blocking comparison pairs use a Williams schedule: each pair occupies
# each position once, and each ordered neighbour transition occurs once.
schedule="$("$script" --lane blocking --allocs system,mimalloc,standard,allocatbelt --reps 8 --print-schedule)"
[[ "$(wc -l <<<"$schedule")" == 8 ]] || fail "schedule row count"
[[ "$(awk '{print NF}' <<<"$schedule" | sort -u)" == 8 ]] || fail "schedule pair count"
positions="$(awk '{for (i=1;i<=NF;i++) print i,$i}' <<<"$schedule" | sort | uniq -c | awk '{print $1}' | sort -u | tr '\n' ' ')"
[[ "$positions" == '1 ' ]] || fail "schedule positions are not balanced: $positions"
transitions="$(awk '{for (i=1;i<NF;i++) print $i,$(i+1)}' <<<"$schedule" | sort | uniq -c | awk '{print $1}' | sort -u | tr '\n' ' ')"
[[ "$transitions" == '1 ' ]] || fail "schedule transitions are not balanced: $transitions"

# The default primary matrix completes six cycles in the fixed 36-pair run.
primary_schedule="$("$script" --lane blocking --print-schedule)"
[[ "$(wc -l <<<"$primary_schedule")" == 36 ]] || fail "primary schedule row count"
[[ "$(awk '{print NF}' <<<"$primary_schedule" | sort -u)" == 6 ]] || fail "primary pair count"
primary_positions="$(awk '{for (i=1;i<=NF;i++) print i,$i}' <<<"$primary_schedule" | sort | uniq -c | awk '{print $1}' | sort -u | tr '\n' ' ')"
[[ "$primary_positions" == '6 ' ]] || fail "default confirmation schedule is incomplete"
async_schedule="$("$script" --lane async --mode capacity --print-schedule)"
[[ "$async_schedule" == "$primary_schedule" ]] || fail "async capacity changed the balanced pair schedule"

# Three pairs exercise the odd Williams schedule and its mirrored second half.
odd_schedule="$("$script" --lane blocking --allocs system,standard,allocatbelt --executors tokio --reps 6 --print-schedule)"
[[ "$(wc -l <<<"$odd_schedule")" == 6 ]] || fail "odd schedule row count"
[[ "$(awk '{print NF}' <<<"$odd_schedule" | sort -u)" == 3 ]] || fail "odd schedule pair count"
odd_positions="$(awk '{for (i=1;i<=NF;i++) print i,$i}' <<<"$odd_schedule" | sort | uniq -c | awk '{print $1}' | sort -u | tr '\n' ' ')"
[[ "$odd_positions" == '2 ' ]] || fail "odd schedule positions are not balanced: $odd_positions"
odd_transitions="$(awk '{for (i=1;i<NF;i++) print $i,$(i+1)}' <<<"$odd_schedule" | sort | uniq -c | awk '{print $1}' | sort -u | tr '\n' ' ')"
[[ "$odd_transitions" == '2 ' ]] || fail "odd schedule transitions are not balanced: $odd_transitions"

for bad_check in wrong-workload:identity overflow:elapsed bad-checksum:trace-checksum \
  bad-percentiles:percentile-order loss:loss extra-field:field-count missing-field:field-count; do
  bad="${bad_check%%:*}"
  expected_check="${bad_check#*:}"
  out="$tmp/bad-$bad"
  if BENCH_LATENCY_FAKE_MODE="$bad" "$script" --lane allocator --allocs system --reps 1 --ops 3 --bin-dir "$tmp/bin" --out "$out" >"$tmp/log" 2>&1; then
    fail "accepted malformed result $bad"
  fi
  [[ "$(tail -1 "$out/results.csv" | cut -d, -f6)" == "$expected_check" ]] \
    || fail "$bad result classified as $(tail -1 "$out/results.csv" | cut -d, -f6), expected $expected_check"
done
if BENCH_LATENCY_FAKE_MODE=nonzero-valid "$script" --lane allocator --allocs system --reps 1 --ops 3 --bin-dir "$tmp/bin" --out "$tmp/nonzero" >"$tmp/log" 2>&1; then
  fail "accepted nonzero process exit with valid CSV"
fi
[[ "$(tail -1 "$tmp/nonzero/results.csv" | cut -d, -f5-6)" == 7,exit ]] \
  || fail "nonzero process exit classification"
if BENCH_LATENCY_FAKE_MODE=throughput-pct "$script" --lane allocator --mode throughput --allocs system --reps 1 --ops 3 --bin-dir "$tmp/bin" --out "$tmp/bad-throughput" >"$tmp/log" 2>&1; then
  fail "accepted percentiles in throughput mode"
fi
[[ "$(tail -1 "$tmp/bad-throughput/results.csv" | cut -d, -f6)" == throughput-percentiles ]] \
  || fail "throughput percentile classification"
for bad_check in wrong-window:configuration wrong-bytes:configuration wrong-executor:configuration \
  capacity-pct:capacity-percentiles capacity-overhead:capacity-overhead capacity-lateness:capacity-lateness \
  capacity-rate:configuration bad-checksum:trace-checksum loss:loss; do
  bad="${bad_check%%:*}" expected_check="${bad_check#*:}" out="$tmp/bad-capacity-${bad_check%%:*}"
  if BENCH_LATENCY_FAKE_MODE="$bad" "$script" --lane async --mode capacity --allocs system --executors tokio --reps 1 --jobs 3 --workers 1 --window 2 --bin-dir "$tmp/bin" --out "$out" >"$tmp/log" 2>&1; then
    fail "accepted malformed capacity result $bad"
  fi
  [[ "$(tail -1 "$out/results.csv" | cut -d, -f6)" == "$expected_check" ]] \
    || fail "$bad capacity result classified as $(tail -1 "$out/results.csv" | cut -d, -f6), expected $expected_check"
done
echo "bench-latency runner tests passed"
