#!/usr/bin/env bash
# Balanced fresh-process allocator and blocking/async executor comparisons.
# `--bin-dir` executes unverified prebuilt artifacts and marks their rows
# nonqualifying. Normal runs build all selected variants from this checkout.
# `--observer-spin LIST` runs each executor once per harness observer spin
# value as separate interleaved variants and writes summary.tsv.
set -euo pipefail
cd "$(dirname "$0")/.."
lane="" workload=local mode=latency allocs=mimalloc,standard,allocatbelt executors=bounded,tokio
reps=36 out="" bin_dir="" ops="" workers="" arrival_rate="" bytes="" window="" print_schedule=0 workload_explicit=0
observer_spin=""
die() { echo "bench-latency.sh: $*" >&2; exit 2; }
positive() {
  if [[ ! "$2" =~ ^[1-9][0-9]*$ ]] || ((${#2} >= 10)); then die "$1 needs a positive decimal integer"; fi
}
while (($#)); do
  case "$1" in
    --lane|--workload|--mode|--allocs|--executors|--reps|--ops|--jobs|--workers|--arrival-rate|--bytes|--window|--out|--bin-dir|--observer-spin)
      [[ -n "${2:-}" ]] || die "$1 needs a value"
      case "$1" in
        --lane) lane="$2" ;; --workload) workload="$2"; workload_explicit=1 ;; --mode) mode="$2" ;;
        --allocs) allocs="$2" ;; --executors) executors="$2" ;; --reps) reps="$2" ;;
        --ops|--jobs) ops="$2" ;; --workers) workers="$2" ;; --arrival-rate) arrival_rate="$2" ;;
        --bytes) bytes="$2" ;; --window) window="$2" ;; --out) out="$2" ;; --bin-dir) bin_dir="$2" ;;
        --observer-spin) observer_spin="$2" ;;
      esac
      shift 2 ;;
    -h|--help) echo "usage: bench-latency.sh --lane allocator|blocking|async [--workload local|aligned|mixed|ready|yielding] [--mode latency|throughput|capacity] [--allocs system,mimalloc,standard,allocatbelt] [--executors bounded,tokio] [--reps N] [--ops N|--jobs N] [--workers N] [--window N] [--arrival-rate N] [--bytes N] [--observer-spin N,N] --out DIR [--bin-dir DIR]"
      echo "  --observer-spin LIST  blocking/async lanes: run each executor at each --harness-observer-spin value"
      echo "                        (comma list of distinct non-negative integers) as interleaved variants;"
      echo "                        adds a harness_observer_spin column to results.csv and writes summary.tsv"
      echo "                        with bounded and tokio median tasks/s, their ratio and interquartile ranges"
      exit 0 ;;
    --print-schedule) print_schedule=1; shift ;;
    *) die "unknown argument $1" ;;
  esac
done
[[ "$lane" == allocator || "$lane" == blocking || "$lane" == async ]] || die "--lane must be allocator, blocking or async"
if [[ "$lane" == async ]] && ((workload_explicit == 0)); then workload=ready; fi
[[ "$workload" == local || "$workload" == aligned || "$workload" == mixed || "$workload" == ready || "$workload" == yielding ]] || die "unknown --workload"
[[ "$mode" == latency || "$mode" == throughput || "$mode" == capacity ]] || die "unknown --mode"
positive --reps "$reps"
[[ -z "$ops" ]] || positive --ops "$ops"
[[ -z "$workers" ]] || positive --workers "$workers"
[[ -z "$arrival_rate" ]] || positive --arrival-rate "$arrival_rate"
[[ -z "$bytes" ]] || positive --bytes "$bytes"
[[ -z "$window" ]] || positive --window "$window"
[[ -z "$ops" || "$ops" -le 1000000 ]] || die "--ops/--jobs must not exceed 1000000"
[[ -z "$workers" || "$workers" -le 1024 ]] || die "--workers must not exceed 1024"
[[ -z "$bytes" || "$bytes" -le 2097152 ]] || die "--bytes must not exceed 2097152"
if [[ "$lane" == allocator ]]; then
  [[ -z "$workers" && -z "$arrival_rate" ]] || die "--workers and --arrival-rate require the blocking or async lane"
  [[ -z "$window" ]] || die "--window requires the async lane or blocking capacity mode"
  [[ "$mode" != capacity ]] || die "--mode capacity requires the blocking or async lane"
  [[ "$workload" == local || "$workload" == aligned || "$workload" == mixed ]] || die "allocator workloads are local, aligned or mixed"
  effective_count="${ops:-20000}" effective_workers=1 effective_rate=NA effective_window=NA
else
  [[ -z "$workers" || "$workers" -le "${ops:-5000}" ]] || die "--workers cannot exceed --jobs"
  [[ "$mode" != capacity || -z "$arrival_rate" ]] || die "--arrival-rate is incompatible with --mode capacity"
  effective_count="${ops:-5000}" effective_workers="${workers:-4}" effective_rate="${arrival_rate:-10000}"
  ((effective_workers <= effective_count)) || effective_workers="$effective_count"
  effective_window="${window:-$((effective_workers * 4))}"
  if [[ -z "$window" ]] && ((effective_window > effective_count)); then effective_window="$effective_count"; fi
  ((effective_window <= effective_count)) || die "--window must not exceed --jobs"
  if [[ "$lane" == async || "$mode" == capacity ]]; then
    ((effective_window >= effective_workers)) || die "--window must be at least --workers to warm every worker"
  else
    [[ -z "$window" ]] || die "--window requires the async lane or blocking capacity mode"
    effective_window="$effective_count"
  fi
  [[ "$mode" != capacity ]] || effective_rate=NA
fi
effective_bytes="${bytes:-256}"
if [[ "$lane" == blocking ]]; then
  [[ "$workload" == local ]] || die "blocking jobs support only --workload local"
  ((${ops:-5000} * ${bytes:-256} <= 512 * 1024 * 1024)) || die "--jobs times --bytes must fit within 512 MiB"
elif [[ "$lane" == async ]]; then
  [[ "$workload" == ready || "$workload" == yielding || "$workload" == mixed ]] || die "async workloads are ready, yielding or mixed"
  if [[ "$workload" == mixed ]]; then
    ((effective_window * effective_bytes * 8 <= 512 * 1024 * 1024)) || die "--window times --bytes times 8 must fit within 512 MiB for mixed async work"
  fi
fi
parse_list() {
  local flag="$1" value="$2" allowed="$3" item seen=" "
  [[ "$value" =~ ^[a-z]+(,[a-z]+)*$ ]] || die "$flag needs comma-separated names"
  IFS=, read -r -a values <<<"$value"
  for item in "${values[@]}"; do
    [[ ",$allowed," == *,"$item",* ]] || die "$flag: unknown $item"
    [[ "$seen" != *" $item "* ]] || die "$flag: duplicate $item"
    seen+="$item "
  done
}
parse_list --allocs "$allocs" system,mimalloc,standard,allocatbelt
alloc_list=("${values[@]}")
parse_list --executors "$executors" bounded,tokio
exec_list=("${values[@]}")
[[ "$lane" != allocator ]] || exec_list=(allocator)
spin_list=()
if [[ -n "$observer_spin" ]]; then
  [[ "$lane" != allocator ]] || die "--observer-spin requires the blocking or async lane"
  [[ "$observer_spin" =~ ^(0|[1-9][0-9]{0,8})(,(0|[1-9][0-9]{0,8}))*$ ]] \
    || die "--observer-spin needs comma-separated non-negative decimal integers"
  IFS=, read -r -a spin_list <<<"$observer_spin"
  seen=" "
  for s in "${spin_list[@]}"; do
    [[ "$seen" != *" $s "* ]] || die "--observer-spin: duplicate $s"
    seen+="$s "
  done
fi
pairs=()
for a in "${alloc_list[@]}"; do for e in "${exec_list[@]}"; do
  if ((${#spin_list[@]})); then
    for s in "${spin_list[@]}"; do pairs+=("$a:$e:spin$s"); done
  else
    pairs+=("$a:$e")
  fi
done; done
n=${#pairs[@]}; cycle=$((n % 2 == 1 && n > 1 ? 2 * n : n))
schedule_index() {
  local rep=$(($1 % cycle)) pos="$2" k seq
  if ((rep >= n)); then rep=$((rep - n)); pos=$((n - 1 - pos)); fi
  k=$(((pos + 1) / 2))
  if ((pos % 2 == 1)); then seq=$k; else seq=$(((n - k) % n)); fi
  echo $(((seq + rep) % n))
}
if ((print_schedule)); then
  for ((r=0; r<reps; r++)); do
    for ((p=0; p<n; p++)); do
      ((p == 0)) || printf ' '
      idx="$(schedule_index "$r" "$p")"
      printf '%s' "${pairs[$idx]}"
    done
    printf '\n'
  done
  exit 0
fi
[[ -n "$out" ]] || die "--out is required"
((reps % cycle == 0)) || echo "note: --reps $reps is not a multiple of schedule cycle $cycle" >&2
[[ ! -e "$out" || ( -d "$out" && -z "$(ls -A "$out")" ) ]] || die "--out must be absent or empty"
prebuilt=0
[[ -z "$bin_dir" ]] || prebuilt=1
source_fingerprint() {
  { git rev-parse HEAD; git diff HEAD --binary;
    git ls-files -z --others --exclude-standard | while IFS= read -r -d '' path; do
      printf '%s\t' "$path"; sha256sum <"$path" | cut -d' ' -f1;
    done;
  } | sha256sum | cut -d' ' -f1
}
source_hash_before_build="$(source_fingerprint)"
if [[ -z "$bin_dir" ]]; then
  binargs=()
  for a in "${alloc_list[@]}"; do
    case "$a" in
      standard) continue ;;
      system) b=system ;; mimalloc) b=mimalloc ;; allocatbelt) b=allocatbelt ;;
    esac
    binargs+=(--bin "bench-latency-$b")
  done
  ((${#binargs[@]} == 0)) || cargo build --release --locked -p allocatbelt-bench "${binargs[@]}"
  if [[ " ${alloc_list[*]} " == *" standard "* ]]; then
    cargo build --manifest-path bench/standard-mimalloc/Cargo.toml --target-dir bench/standard-mimalloc/target --release --locked --bin bench-latency-standard
    standard_dir=bench/standard-mimalloc/target/release
  fi
  bin_dir="${CARGO_TARGET_DIR:-target}/release"
else
  standard_dir="$bin_dir"
fi
binary_for() { [[ "$1" == standard ]] && echo "$standard_dir/bench-latency-standard" || echo "$bin_dir/bench-latency-$1"; }
source_hash="$(source_fingerprint)"
[[ "$source_hash" == "$source_hash_before_build" ]] || die "source changed during comparator builds"
byte_cycles=$((effective_count / 256))
expected_sum_mod=$((byte_cycles * 32640 + (effective_count % 256) * (effective_count % 256 - 1) / 2))
if [[ "$lane" == blocking ]]; then
  expected_checksum=$((effective_count * (effective_count - 1) / 2 + effective_bytes * expected_sum_mod))
elif [[ "$lane" == async ]]; then
  expected_checksum=$((effective_count * (effective_count - 1) / 2))
  case "$workload" in
    ready) expected_checksum=$((expected_checksum + effective_count)) ;;
    yielding) expected_checksum=$((expected_checksum + 36 * effective_count)) ;;
    mixed)
      # Each of eight chunks uses (id + chunk) modulo 256. A partial
      # 256-job cycle can cross the byte wrap for the later chunks.
      remainder=$((effective_count % 256))
      for ((chunk=0; chunk<8; chunk++)); do
        wrapped=$((remainder + chunk > 256 ? remainder + chunk - 256 : 0))
        chunk_sum=$((expected_sum_mod + chunk * remainder - 256 * wrapped))
        expected_checksum=$((expected_checksum + effective_bytes * chunk_sum))
      done ;;
  esac
else
  case "$workload" in
    local) expected_checksum=$((2 * expected_sum_mod + 64 * effective_count)) ;;
    aligned)
      expected_sum_next=$((byte_cycles * 32640 + (effective_count % 256) * (effective_count % 256 + 1) / 2))
      expected_checksum=$((expected_sum_mod + expected_sum_next)) ;;
    mixed)
      size_cycle=$((16 + 128 + 512 + 4096 + 32768 + 65536 + 262144 + effective_bytes))
      size_cycles=$((effective_count / 8))
      size_total=$((size_cycles * size_cycle))
      size_values=(16 128 512 4096 32768 65536 262144 "$effective_bytes")
      for ((i=0; i<effective_count%8; i++)); do size_total=$((size_total + size_values[i])); done
      expected_checksum=$((2 * expected_sum_mod + size_total)) ;;
  esac
fi
printf -v expected_checksum_hex '0x%016x' "$expected_checksum"
evidence_status=release-build-from-current-source
if ((reps % cycle != 0)); then evidence_status=incomplete-cycle-not-qualifying; fi
if ((prebuilt)); then evidence_status=unverified-prebuilt-not-qualifying; fi
for a in "${alloc_list[@]}"; do
  bin="$(binary_for "$a")"
  [[ -x "$bin" ]] || die "missing executable $bin"
done
mkdir -p "$out/runs"
{
  echo "commit: $(git rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "source_status: $(git status --short | tr '\n' ';')"
  echo "source_sha256_before_output_creation: $source_hash"
  echo "source_sha256_before_build: $source_hash_before_build"
  echo "schedule_cycle=$cycle complete_cycles=$((reps / cycle)) remaining_repetitions=$((reps % cycle))"
  echo "toolchain: $(rustc --version 2>/dev/null || echo unknown)"
  echo "kernel: $(uname -a)"
  echo "cpu_model: $(awk -F: '/model name/ {gsub(/^[ \t]+/, "", $2); print $2; exit}' /proc/cpuinfo 2>/dev/null || echo unknown)"
  echo "affinity: $(taskset -pc $$ 2>&1 || echo unavailable)"
  echo "cgroup_cpu_max: $(cat /sys/fs/cgroup/cpu.max 2>/dev/null || echo unavailable)"
  echo "cgroup_memory_max: $(cat /sys/fs/cgroup/memory.max 2>/dev/null || echo unavailable)"
  echo "RUSTFLAGS=${RUSTFLAGS-<unset>}"
  echo "RUSTDOCFLAGS=${RUSTDOCFLAGS-<unset>}"
  echo "CARGO_ENCODED_RUSTFLAGS=${CARGO_ENCODED_RUSTFLAGS-<unset>}"
  echo "target=${CARGO_BUILD_TARGET:-host} profile=release CC=${CC-<unset>} CFLAGS=${CFLAGS-<unset>}"
  echo "lane=$lane workload=$workload mode=$mode reps=$reps allocs=$allocs executors=$executors"
  echo "effective_count=$effective_count workers=$effective_workers admission_window=$effective_window arrival_rate=$effective_rate bytes=$effective_bytes"
  echo "expected_checksum=$expected_checksum_hex evidence_status=$evidence_status"
  [[ -z "$observer_spin" ]] || echo "harness_observer_spin=$observer_spin"
  for a in "${alloc_list[@]}"; do
    bin="$(binary_for "$a")"
    sha256sum "$bin"
  done
} >"$out/environment.txt"
expected_header=allocator,lane,workload,mode,executor,workers,admission_window,arrival_rate,bytes,requested,attempted,completed,dropped,checksum,elapsed_ns,throughput_per_s,timer_overhead_ns,p50_ns,p95_ns,p99_ns,arrival_lateness_mean_ns,arrival_lateness_max_ns
results_header='repetition,position,allocator,executor,exit_code,check,evidence_status,allocator_name,lane,workload,mode,executor_name,workers,admission_window,arrival_rate,bytes,requested,attempted,completed,dropped,checksum,elapsed_ns,throughput_per_s,timer_overhead_ns,p50_ns,p95_ns,p99_ns,arrival_lateness_mean_ns,arrival_lateness_max_ns'
# The spin column is appended only with --observer-spin, so default output
# keeps its 29 fields.
[[ -z "$observer_spin" ]] || results_header+=,harness_observer_spin
echo "$results_header" >"$out/results.csv"
# Read a field into a local first so malformed/missing CSV cannot trigger
# nounset or feed an unchecked value to Bash arithmetic.
unsigned_field() {
  local value="${fields[$1]:-}"
  [[ "$value" =~ ^(0|[1-9][0-9]*)$ && ${#value} -le 15 ]]
}
failed=0
for ((r=0; r<reps; r++)); do
  for ((p=0; p<n; p++)); do
    pair="${pairs[$(schedule_index "$r" "$p")]}"; a="${pair%%:*}"; e="${pair#*:}"
    spin="" variant="$e"
    if [[ "$e" == *:spin* ]]; then spin="${e##*:spin}"; e="${e%%:*}"; variant="$e-spin$spin"; fi
    bin="$(binary_for "$a")"
    args=(--lane "$lane" --workload "$workload" --mode "$mode")
    if [[ "$lane" != allocator ]]; then
      args+=(--jobs "$effective_count" --workers "$effective_workers" --bytes "$effective_bytes" --executor "$e")
      [[ "$effective_rate" == NA ]] || args+=(--arrival-rate "$effective_rate")
      if [[ "$lane" == async || "$mode" == capacity ]]; then args+=(--window "$effective_window"); fi
      [[ -z "$spin" ]] || args+=(--harness-observer-spin "$spin")
    else
      args+=(--ops "$effective_count" --bytes "$effective_bytes")
    fi
    raw="$out/runs/r${r}-p${p}-${a}-${variant}.csv"
    printf '%q ' "$bin" "${args[@]}" >"${raw%.csv}.argv"
    printf '\n' >>"${raw%.csv}.argv"
    code=0; "$bin" "${args[@]}" >"$raw" 2>"${raw%.csv}.stderr" || code=$?
    check=ok
    [[ "$code" == 0 ]] || check="exit"
    [[ "$(wc -l <"$raw")" == 2 ]] || check=output-shape
    header="$(head -1 "$raw" 2>/dev/null || true)"; row="$(tail -1 "$raw" 2>/dev/null || true)"
    [[ "$header" == "$expected_header" ]] || check=header
    IFS=, read -r -a fields <<<"$row"
    expected_allocator="$a"; [[ "$a" != mimalloc ]] || expected_allocator=mimalloc-secure
    [[ "$a" != standard ]] || expected_allocator=mimalloc-standard
    expected_executor=NA
    if [[ "$lane" == blocking ]]; then expected_executor="$e";
    elif [[ "$lane" == async ]]; then expected_executor="$e-async"; fi
    [[ "${fields[0]:-}" == "$expected_allocator" && "${fields[1]:-}" == "$lane" && "${fields[2]:-}" == "$workload" && "${fields[3]:-}" == "$mode" ]] || check=identity
    [[ "${fields[4]:-}" == "$expected_executor" && "${fields[5]:-}" == "$effective_workers" && "${fields[6]:-}" == "$effective_window" && "${fields[7]:-}" == "$effective_rate" && "${fields[8]:-}" == "$effective_bytes" ]] || check=configuration
    [[ "${fields[9]:-}" == "$effective_count" && "${fields[10]:-}" == "$effective_count" ]] || check=request-count
    for idx in 9 10 11 12 14; do unsigned_field "$idx" || check=numeric; done
    if unsigned_field 10 && unsigned_field 11 && unsigned_field 12; then
      ((fields[11] + fields[12] == fields[10])) || check=completion-count
      ((fields[12] == 0)) || check=loss
    fi
    [[ "${fields[13]:-}" =~ ^0x[0-9a-f]{16}$ ]] || check=checksum
    [[ "${fields[13]:-}" == "$expected_checksum_hex" ]] || check=trace-checksum
    if ! unsigned_field 14 || [[ "${fields[14]:-}" == 0 ]]; then check=elapsed; fi
    throughput="${fields[15]:-}"
    [[ "$throughput" =~ ^[0-9]+(\.[0-9]+)?$ && ${#throughput} -le 32 ]] || check=throughput
    if [[ "$mode" == capacity ]]; then
      [[ "${fields[16]:-}" == NA ]] || check=capacity-overhead
      [[ "${fields[20]:-}" == NA && "${fields[21]:-}" == NA ]] || check=capacity-lateness
    else
      for idx in 16 20 21; do unsigned_field "$idx" || check=numeric; done
      if unsigned_field 20 && unsigned_field 21; then
        ((fields[20] <= fields[21])) || check=arrival-lateness
      fi
    fi
    if [[ "$mode" == latency ]]; then
      for idx in 17 18 19; do unsigned_field "$idx" || check=percentile; done
      if unsigned_field 17 && unsigned_field 18 && unsigned_field 19; then
        ((fields[17] <= fields[18] && fields[18] <= fields[19])) || check=percentile-order
      fi
    else
      if [[ "${fields[17]:-}" != NA || "${fields[18]:-}" != NA || "${fields[19]:-}" != NA ]]; then
        check="$mode-percentiles"
      fi
    fi
    [[ "${#fields[@]}" == 22 ]] || check=field-count
    printf '%s,%s,%s,%s,%s,%s,%s,%s%s\n' "$r" "$p" "$a" "$e" "$code" "$check" "$evidence_status" "$row" "${spin:+,$spin}" >>"$out/results.csv"
    [[ "$check" == ok ]] || failed=1
  done
done
((failed == 0)) || exit 1
[[ -n "$observer_spin" ]] || exit 0
# Per allocator and spin value: median and interquartile range (linear
# interpolation between order statistics) of throughput_per_s for each
# executor, the bounded/tokio median ratio, and whether the ranges overlap.
awk -F, -v spins="$observer_spin" -v workload="$workload" -v workers="$effective_workers" -v window="$effective_window" '
function sortv(a, k,   i, j, t) { for (i = 2; i <= k; i++) { t = a[i]; for (j = i - 1; j >= 1 && a[j] > t; j--) a[j + 1] = a[j]; a[j + 1] = t } }
function q(a, k, p,   h, l) { h = (k - 1) * p + 1; l = int(h); return l >= k ? a[k] : a[l] + (h - l) * (a[l + 1] - a[l]) }
function stats(key, out,   k, i, v) {
  k = count[key]; if (k == 0) { out["med"] = "NA"; out["lo"] = "NA"; out["hi"] = "NA"; return 0 }
  for (i = 1; i <= k; i++) v[i] = value[key, i]
  sortv(v, k); out["med"] = q(v, k, 0.5); out["lo"] = q(v, k, 0.25); out["hi"] = q(v, k, 0.75); return k
}
NR > 1 && $6 == "ok" { key = $3 SUBSEP $30 SUBSEP $4; value[key, ++count[key]] = $23; if (!($3 in seen)) { seen[$3] = 1; allocs[++na] = $3 } }
END {
  print "allocator	workload	workers	window	observer_spin	bounded_median	tokio_median	bounded/tokio	bounded_iqr	tokio_iqr	iqr_separated	runs"
  ns = split(spins, sl, ",")
  for (i = 1; i <= na; i++) for (j = 1; j <= ns; j++) {
    nb = stats(allocs[i] SUBSEP sl[j] SUBSEP "bounded", b); nt = stats(allocs[i] SUBSEP sl[j] SUBSEP "tokio", t)
    ratio = "NA"; sep = "NA"
    if (nb && nt) {
      if (t["med"] > 0) ratio = sprintf("%.3f", b["med"] / t["med"])
      sep = (b["lo"] > t["hi"] || b["hi"] < t["lo"]) ? "yes" : "no"
    }
    printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d+%d\n", allocs[i], workload, workers, window, sl[j],
      nb ? sprintf("%.0f", b["med"]) : "NA", nt ? sprintf("%.0f", t["med"]) : "NA", ratio,
      nb ? sprintf("%.0f-%.0f", b["lo"], b["hi"]) : "NA", nt ? sprintf("%.0f-%.0f", t["lo"], t["hi"]) : "NA", sep, nb, nt
  }
}' "$out/results.csv" >"$out/summary.tsv"
