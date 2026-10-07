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
mkdir -p "$tmp/bin"
cat >"$tmp/bin/fake" <<'FAKE'
#!/usr/bin/env bash
lane="" workload=local mode=latency executor=NA workers=4 rate=10000 bytes=256 count=0
while (($#)); do
  case "$1" in
    --lane) lane="$2" ;; --workload) workload="$2" ;; --mode) mode="$2" ;;
    --executor) executor="$2" ;; --workers) workers="$2" ;; --arrival-rate) rate="$2" ;;
    --ops|--jobs) count="$2" ;; --bytes) bytes="$2" ;;
    *) exit 2 ;;
  esac
  shift 2
done
[[ -n "$lane" ]] || exit 2
allocator="${0##*/bench-latency-}"
[[ "$allocator" != mimalloc ]] || allocator=mimalloc-secure
[[ "$allocator" != standard ]] || allocator=mimalloc-standard
printf '%s\n' 'allocator,lane,workload,mode,executor,workers,arrival_rate,requested,attempted,completed,dropped,checksum,elapsed_ns,throughput_per_s,timer_overhead_ns,p50_ns,p95_ns,p99_ns,arrival_lateness_mean_ns,arrival_lateness_max_ns'
if [[ "$lane" == allocator ]]; then
  case "$workload" in
    local) checksum=$((2 * (count / 256 * 32640 + (count % 256) * (count % 256 - 1) / 2) + 64 * count)) ;;
    aligned) checksum=$((count / 256 * 32640 + (count % 256) * (count % 256 - 1) / 2 + count / 256 * 32640 + (count % 256) * (count % 256 + 1) / 2)) ;;
    mixed) checksum=198 ;;
  esac
  printf -v checksum_hex '0x%016x' "$checksum"
  fields=("$allocator" allocator "$workload" "$mode" NA 1 NA "$count" "$count" "$count" 0 "$checksum_hex" 100 1000 1 10 20 30 0 0)
else
  sum_mod=$((count / 256 * 32640 + (count % 256) * (count % 256 - 1) / 2))
  checksum=$((count * (count - 1) / 2 + bytes * sum_mod))
  printf -v checksum_hex '0x%016x' "$checksum"
  fields=("$allocator" blocking "$workload" "$mode" "$executor" "$workers" "$rate" "$count" "$count" "$count" 0 "$checksum_hex" 100 1000 1 10 20 30 0 0)
fi
case "${BENCH_LATENCY_FAKE_MODE:-ok}" in
  wrong-workload) fields[2]=wrong ;;
  overflow) fields[12]=999999999999999999999999 ;;
  bad-checksum) fields[11]=0x0000000000000001 ;;
  bad-percentiles) fields[15]=20; fields[16]=10 ;;
  loss) fields[9]=$((count - 1)); fields[10]=1 ;;
  extra-field) fields+=(extra) ;;
  missing-field) unset 'fields[19]' ;;
  throughput-pct) fields[15]=10 ;;
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
echo "bench-latency runner tests passed"
