#!/usr/bin/env bash
# Bounded async executor versus Tokio in capacity mode over several loads and
# harness observer spin values. Each load is one scripts/bench-latency.sh run
# whose executor and spin variants are interleaved in its balanced schedule;
# loads run in the listed order. summary.tsv and summary.txt combine the
# per-load summaries into one table.
set -euo pipefail
cd "$(dirname "$0")/.."
default_loads=ready:1:256,ready:4:256,ready:8:2048,yielding:1:2048,yielding:4:256,yielding:8:2048
loads="$default_loads" spins=0,16 allocs=system reps=12 jobs=100000 out="" bin_dir="" print_schedule=0
die() { echo "bench-executor-compare.sh: $*" >&2; exit 2; }
usage() {
  cat <<EOF
usage: bench-executor-compare.sh --out DIR [--loads LIST] [--observer-spin LIST] [--allocs NAME]
                                 [--reps N] [--jobs N] [--bin-dir DIR] [--print-schedule]

  --loads LIST          comma list of WORKLOAD:WORKERS:WINDOW, WORKLOAD ready, yielding or mixed
                        (default $default_loads)
  --observer-spin LIST  --harness-observer-spin values (default 0,16). 0 measures end to end,
                        including the harness observer's sleep and wake; 16 makes the observer
                        spin before sleeping, comparing the executors without that harness cost
  --allocs NAME         one global allocator: system, mimalloc, standard or allocatbelt (default system)
  --reps N              repetitions of each load's balanced schedule (default 12)
  --jobs N              jobs per run (default 100000)
  --bin-dir DIR         prebuilt binaries; rows are marked unverified and nonqualifying
  --print-schedule      print each load's run order and exit

Each load writes DIR/WORKLOAD-wWORKERS-winWINDOW/ (see bench-latency.sh). DIR/summary.tsv and
DIR/summary.txt list, per load and spin value, the bounded and Tokio median tasks/s, their ratio,
interquartile ranges and whether those ranges are separated. Builds from this checkout by default.
EOF
}
while (($#)); do
  case "$1" in
    --loads|--observer-spin|--allocs|--reps|--jobs|--out|--bin-dir)
      [[ -n "${2:-}" ]] || die "$1 needs a value"
      case "$1" in
        --loads) loads="$2" ;; --observer-spin) spins="$2" ;; --allocs) allocs="$2" ;;
        --reps) reps="$2" ;; --jobs) jobs="$2" ;; --out) out="$2" ;; --bin-dir) bin_dir="$2" ;;
      esac
      shift 2 ;;
    -h|--help) usage; exit 0 ;;
    --print-schedule) print_schedule=1; shift ;;
    *) die "unknown argument $1" ;;
  esac
done
[[ "$allocs" =~ ^[a-z]+$ ]] || die "--allocs takes one allocator name"
[[ "$loads" =~ ^[a-z]+:[1-9][0-9]*:[1-9][0-9]*(,[a-z]+:[1-9][0-9]*:[1-9][0-9]*)*$ ]] \
  || die "--loads needs comma-separated WORKLOAD:WORKERS:WINDOW with positive integers"
IFS=, read -r -a load_list <<<"$loads"
seen=" "
for load in "${load_list[@]}"; do
  [[ "$seen" != *" $load "* ]] || die "--loads: duplicate $load"
  seen+="$load "
done
common=(--lane async --mode capacity --executors bounded,tokio --allocs "$allocs" --reps "$reps" --jobs "$jobs" --observer-spin "$spins")
load_args() {
  local workload workers window
  IFS=: read -r workload workers window <<<"$1"
  load_dir="$workload-w$workers-win$window"
  args=("${common[@]}" --workload "$workload" --workers "$workers" --window "$window")
}
# Validate every load with bench-latency.sh before any output or build.
for load in "${load_list[@]}"; do
  load_args "$load"
  schedule="$(scripts/bench-latency.sh "${args[@]}" --print-schedule)" || die "invalid load $load"
  if ((print_schedule)); then printf '# %s\n%s\n' "$load_dir" "$schedule"; fi
done
((print_schedule == 0)) || exit 0
[[ -n "$out" ]] || die "--out is required"
[[ ! -e "$out" || ( -d "$out" && -z "$(ls -A "$out")" ) ]] || die "--out must be absent or empty"
mkdir -p "$out"
for load in "${load_list[@]}"; do
  load_args "$load"
  [[ -z "$bin_dir" ]] || args+=(--bin-dir "$bin_dir")
  echo "bench-executor-compare.sh: $load" >&2
  scripts/bench-latency.sh "${args[@]}" --out "$out/$load_dir" || die "load $load failed; see $out/$load_dir/results.csv"
done
first=1
for load in "${load_list[@]}"; do
  load_args "$load"
  if ((first)); then cat "$out/$load_dir/summary.tsv"; first=0; else tail -n +2 "$out/$load_dir/summary.tsv"; fi
done >"$out/summary.tsv"
# Align the columns without depending on column(1).
awk -F'\t' 'NR == FNR { for (i = 1; i <= NF; i++) if (length($i) > w[i]) w[i] = length($i); next }
  { for (i = 1; i < NF; i++) printf "%s", sprintf("%-" w[i] "s  ", $i); print $NF }' \
  "$out/summary.tsv" "$out/summary.tsv" | tee "$out/summary.txt"
