#!/usr/bin/env bash
# Repeats the executor benchmark (bench/src/runtime.rs) over every pair of
# global allocator and executor, one process per run, and collects the rows.
#
#   scripts/bench-runtime.sh --out DIR [options]
#
# Options:
#   --allocs LIST     global allocators, comma separated, of system, mimalloc
#                     and allocatbelt (default: all three)
#   --executors LIST  executors, comma separated, of bounded and tokio
#                     (default: both)
#   --reps N          repetitions; each runs every pair once (default 10)
#   --start warm|cold, --workers N, --window N, --jobs N, --bytes N,
#   --cpu-iters N, --quick
#                     the workload; the last of a repeated option wins and
#                     explicit values win over --quick. Every run is passed
#                     start, jobs, bytes and cpu-iters (and workers and window
#                     when given) explicitly, and its row must report exactly
#                     them. Default: warm start and the benchmark's defaults;
#                     without --workers the benchmark picks 1 to 16 from its
#                     CPUs, and only that range (and window = 4 x workers
#                     unless --window is given) is checked.
#   --profile         wrap each run in `resource-profile` (per-run
#                     samples.csv, threads-by-name.csv and summary.tsv)
#   --out DIR         output directory; must not exist or be empty (default
#                     target/runtime-bench/<UTC time>, untracked)
#   --bin-dir DIR     use the benchmark binaries in DIR instead of building
#                     them. Their origin is unknown, and the results do not
#                     qualify as evidence, unless --build-info is given.
#   --build-info FILE with --bin-dir: the build-info.txt of the run that
#                     built the binaries. Every used binary must be listed in
#                     it with its SHA-256, or the script stops before writing
#                     anything; the file is copied into the output.
#   --print-schedule  print the run order and exit
#
# Run order: a balanced (Williams) schedule. Over one cycle of repetitions
# (the number of pairs, or twice that when it is odd) every pair runs once
# in every position, and every pair directly follows every other pair the
# same number of times; with two pairs the order is AB, BA. Run a multiple
# of the cycle for full balance.
#
# `results.tsv` has one row per attempted run: repetition, position,
# allocator, executor, exit code and check, then the benchmark's columns.
# A run whose exit code is not 0 or whose row is missing, malformed, for
# another variant, not `ok` or with a checksum or count differing from the
# expected one gets check != ok and NA in every benchmark column; its raw
# output stays under `runs/`. Any such run makes the script exit with 1
# after the others ran.
#
# `environment.txt` records the commit, whether the source differs from it
# (tracked changes, untracked files), a source hash over the commit, the
# diff and the paths and contents of untracked, not ignored files, plus the
# toolchain, kernel, CPUs, affinity and cgroup limits; these describe the
# checkout the script ran from. `artifacts.sha256` and the `binaries` line
# record the executables used and where they came from: a run that builds
# writes `build-info.txt` (format line, build command, source, toolchain
# and artifact SHA-256s) for later --bin-dir runs. Results are evidence for
# one machine only; see docs/research/benchmarks.md.
set -euo pipefail

# BENCH_RUNTIME_ROOT: the checkout to describe and build (for the script's
# own tests); defaults to this script's repository.
cd "${BENCH_RUNTIME_ROOT:-$(dirname "$0")/..}"

# The benchmark's columns, as `HEADER` in bench/src/runtime.rs (a unit test
# there checks this line).
bench_columns=(allocator executor start workers window jobs bytes cpu_iters wall_ms jobs_per_s user_ms system_ms rss_kib hwm_kib minflt majflt checksum completed expected_checksum expected_completed status)

allocs="system,mimalloc,allocatbelt"
executors="bounded,tokio"
reps=10
out=""
profile=""
bin_dir=""
print_schedule=""
build_info=""
# The workload asked for; the last of a repeated option wins.
req_start=warm
req_workers=""
req_window=""
req_jobs=""
req_bytes=""
req_cpu_iters=""
quick=""

die() {
  echo "bench-runtime.sh: $*" >&2
  exit 2
}

# A decimal count: digits only, no leading zero (bash would read it as
# octal), at most `$3` digits so arithmetic cannot overflow.
count() {
  local flag="$1" v="$2" digits="$3" min="$4"
  [[ "${v}" =~ ^(0|[1-9][0-9]{0,$((digits - 1))})$ ]] \
    || die "${flag} needs a decimal integer without leading zeros, of at most ${digits} digits"
  ((v >= min)) || die "${flag} must be at least ${min}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --allocs) [[ $# -ge 2 ]] || die "--allocs needs a list"; allocs="$2"; shift 2 ;;
    --executors) [[ $# -ge 2 ]] || die "--executors needs a list"; executors="$2"; shift 2 ;;
    --reps) count "$1" "${2:-}" 6 1; reps="$2"; shift 2 ;;
    --start)
      [[ "${2:-}" == warm || "${2:-}" == cold ]] || die "--start needs warm or cold"
      req_start="$2"; shift 2 ;;
    # 1 to 1024, the benchmark's MAX_WORKERS; small enough for arithmetic.
    --workers) count "$1" "${2:-}" 4 1; ((${2} <= 1024)) || die "--workers must be at most 1024"
      req_workers="$2"; shift 2 ;;
    # Other range checks are the benchmark's own; this keeps values decimal.
    --window) count "$1" "${2:-}" 19 0; req_window="$2"; shift 2 ;;
    --jobs) count "$1" "${2:-}" 19 0; req_jobs="$2"; shift 2 ;;
    --bytes) count "$1" "${2:-}" 19 0; req_bytes="$2"; shift 2 ;;
    --cpu-iters) count "$1" "${2:-}" 19 0; req_cpu_iters="$2"; shift 2 ;;
    --quick) quick=1; shift ;;
    --build-info) [[ -n "${2:-}" ]] || die "--build-info needs a file"; build_info="$2"; shift 2 ;;
    --profile) profile=1; shift ;;
    --out) [[ -n "${2:-}" ]] || die "--out needs a directory"; out="$2"; shift 2 ;;
    --bin-dir) [[ -n "${2:-}" ]] || die "--bin-dir needs a directory"; bin_dir="$2"; shift 2 ;;
    --print-schedule) print_schedule=1; shift ;;
    -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument $1 (see --help)" ;;
  esac
done

# A comma-separated list of distinct names from `$3...`, each matched
# exactly: no empty items, spaces, newlines or other characters.
parse_list() {
  local flag="$1" list="$2" item allowed ok seen=()
  shift 2
  [[ "${list}" =~ ^[a-z]+(,[a-z]+)*$ ]] \
    || die "${flag} needs a comma-separated list of names, without spaces or empty items"
  IFS=, read -r -a parsed <<<"${list}"
  for item in "${parsed[@]}"; do
    ok=""
    for allowed in "$@"; do
      [[ "${item}" == "${allowed}" ]] && ok=1
    done
    [[ -n "${ok}" ]] || die "${flag}: unknown ${item} (of $*)"
    for allowed in "${seen[@]}"; do
      [[ "${item}" != "${allowed}" ]] || die "${flag}: ${item} is listed twice"
    done
    seen+=("${item}")
  done
}
parse_list --allocs "${allocs}" system mimalloc allocatbelt
alloc_list=("${parsed[@]}")
parse_list --executors "${executors}" bounded tokio
exec_list=("${parsed[@]}")
pairs=()
for a in "${alloc_list[@]}"; do
  for e in "${exec_list[@]}"; do
    pairs+=("${a}:${e}")
  done
done

# Every run gets the whole effective workload explicitly, and its row must
# report exactly that. Explicit values win over --quick, as in the
# benchmark; the defaults below are its own (bench/src/runtime.rs, checked
# by a unit test there). Without --workers the benchmark picks its default
# from the CPUs it may use, so rows are then only checked for 1 to 16
# workers and, without --window, a window of four times that.
if [[ -n "${quick}" ]]; then
  req_jobs="${req_jobs:-2000}" req_bytes="${req_bytes:-4096}" req_cpu_iters="${req_cpu_iters:-100}"
else
  req_jobs="${req_jobs:-100000}" req_bytes="${req_bytes:-65536}" req_cpu_iters="${req_cpu_iters:-1000}"
fi
if [[ -n "${req_workers}" && -z "${req_window}" ]]; then
  req_window=$((4 * req_workers))
fi
bench_args=(--start "${req_start}" --jobs "${req_jobs}" --bytes "${req_bytes}" --cpu-iters "${req_cpu_iters}")
[[ -z "${req_workers}" ]] || bench_args+=(--workers "${req_workers}")
[[ -z "${req_window}" ]] || bench_args+=(--window "${req_window}")

# Williams design over the n pairs: row r of the cycle is the sequence
# 0, 1, n-1, 2, n-2, ... shifted by r, so every pair takes every position
# once per n rows and, for even n, follows every other pair once; odd n
# needs the n reversed rows as well. Prints the pair index at repetition
# `$1`, position `$2`.
n=${#pairs[@]}
cycle=$((n % 2 == 1 && n > 1 ? 2 * n : n))
schedule_index() {
  local rep=$(($1 % cycle)) pos="$2" k seq
  if ((rep >= n)); then
    rep=$((rep - n))
    pos=$((n - 1 - pos))
  fi
  k=$(((pos + 1) / 2))
  if ((pos % 2 == 1)); then seq=${k}; else seq=$(((n - k) % n)); fi
  echo $(((seq + rep) % n))
}

if [[ -n "${print_schedule}" ]]; then
  for ((r = 0; r < reps; r++)); do
    order=()
    for ((p = 0; p < n; p++)); do
      order+=("${pairs[$(schedule_index "${r}" "${p}")]}")
    done
    echo "${order[*]}"
  done
  exit 0
fi
if ((reps % cycle != 0)); then
  echo "-- --reps ${reps} is not a multiple of the schedule cycle (${cycle}); positions are not fully balanced" >&2
fi

# Refuse an occupied output directory before writing anything, so an
# earlier run's raw output is never mixed with or overwritten by this one.
out="${out:-target/runtime-bench/$(date -u +%Y%m%dT%H%M%SZ)}"
if [[ -e "${out}" ]]; then
  [[ -d "${out}" ]] || die "--out ${out} exists and is not a directory"
  [[ -z "$(ls -A "${out}")" ]] || die "--out ${out} is not empty; pick a new directory"
fi

# Provenance, before the build and before any output, so neither is in it.
provenance() {
  if ! git rev-parse --git-dir >/dev/null 2>&1; then
    echo "commit: unknown (not a git checkout)"
    echo "source: unknown"
    echo "source_sha256: unknown"
    return
  fi
  local head untracked dirty=""
  head="$(git rev-parse --verify -q HEAD || echo unborn)"
  untracked="$(git ls-files -z --others --exclude-standard | tr '\0' '\n' | LC_ALL=C sort)"
  echo "commit: ${head}"
  if [[ "${head}" == unborn ]]; then
    # No commit: anything in the index or the working copy is a change.
    [[ -z "$(git ls-files)" ]] || dirty=1
  else
    git diff --quiet HEAD -- || dirty=1
  fi
  [[ -z "${untracked}" ]] || dirty=1
  if [[ -n "${dirty}" ]]; then
    echo "source: dirty (differs from the commit)"
  else
    echo "source: clean"
  fi
  echo "untracked_files: $(printf '%s' "${untracked}" | grep -c '' || true)"
  # Commit, then the tracked changes, then each untracked path and the hash
  # of its contents. Tracked changes are the working copy against HEAD
  # (staged and unstaged together); without a commit, the index and then
  # the working copy against the index. Paths with newlines are not
  # supported.
  echo "source_sha256: $(
    {
      echo "${head}"
      if [[ "${head}" == unborn ]]; then
        echo "index:"
        git diff --cached --binary
        echo "worktree:"
        git diff --binary
      else
        git diff HEAD --binary
      fi
      while IFS= read -r path; do
        [[ -n "${path}" ]] || continue
        printf '%s\t%s\n' "${path}" "$(sha256sum <"${path}" | cut -d' ' -f1)"
      done <<<"${untracked}"
    } | sha256sum | cut -d' ' -f1
  )"
}
source_info="$(provenance)"

# The executables this run uses.
artifacts=()
for a in "${alloc_list[@]}"; do
  artifacts+=("bench-runtime-${a}")
done
[[ -z "${profile}" ]] || artifacts+=(resource-profile)

# Copies standard input to standard output with `$1` before each line.
prefix() {
  local line
  while IFS= read -r line; do
    printf '%s%s\n' "$1" "${line}"
  done
}

# `name<TAB>sha256` for each artifact in `$1`.
hash_artifacts() {
  local name
  for name in "${artifacts[@]}"; do
    [[ -x "$1/${name}" ]] || die "missing $1/${name}"
    printf '%s\t%s\n' "${name}" "$(sha256sum <"$1/${name}" | cut -d' ' -f1)"
  done
}

# Prebuilt binaries: their hashes, and with --build-info the build record
# they came from (the build-info.txt a run that built them wrote, or one in
# its format). Every used artifact must be listed there with the same hash,
# checked before any output; the record's other lines are then the
# binaries' origin. Without it the origin is unknown.
if [[ -n "${bin_dir}" ]]; then
  bin="${bin_dir}"
  artifact_hashes="$(hash_artifacts "${bin}")"
  if [[ -n "${build_info}" ]]; then
    [[ -f "${build_info}" ]] || die "--build-info ${build_info} is not a file"
    [[ "$(head -1 "${build_info}")" == "format: bench-runtime-build-info 1" ]] \
      || die "--build-info ${build_info}: not a bench-runtime-build-info 1 record"
    while IFS=$'\t' read -r name hash; do
      [[ "$(grep -c "^artifact_sha256: ${name}	" "${build_info}" || true)" == 1 ]] \
        || die "--build-info lists ${name} not exactly once"
      grep -qx "artifact_sha256: ${name}	${hash}" "${build_info}" \
        || die "--build-info: ${bin}/${name} differs from the recorded build"
    done <<<"${artifact_hashes}"
    origin="prebuilt; matches the supplied build record (build-info.txt)"
  else
    origin="prebuilt; origin unknown (no --build-info): results do not qualify as evidence"
    echo "-- --bin-dir without --build-info: the binaries' origin is unknown" >&2
  fi
elif [[ -n "${build_info}" ]]; then
  die "--build-info describes --bin-dir binaries; it needs --bin-dir"
fi

mkdir -p "${out}/runs"

if [[ -z "${bin_dir}" ]]; then
  # The `bench` profile is `release` with debug info, so perf can name
  # functions; cargo writes it to target/release.
  packages=(-p allocatbelt-bench)
  [[ -n "${profile}" ]] && packages+=(-p allocatbelt-profile)
  build_cmd=(cargo build --profile bench --locked "${packages[@]}")
  echo "== building (${build_cmd[*]})" >&2
  "${build_cmd[@]}" >&2
  bin="target/release"
  artifact_hashes="$(hash_artifacts "${bin}")"
  origin="built by this run from the checkout below"
  # What a later --bin-dir run on another host needs to tie these binaries
  # to their source and toolchain.
  {
    echo "format: bench-runtime-build-info 1"
    echo "built: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "build_command: ${build_cmd[*]}"
    prefix build_ <<<"${source_info}"
    echo "build_rustc: $(rustc --version 2>/dev/null || echo unknown)"
    rustc -vV 2>/dev/null | sed -n 's/^host: /build_rustc_host: /p' || true
    echo "build_cargo: $(cargo --version 2>/dev/null || echo unknown)"
    echo "build_rustflags: ${RUSTFLAGS:-<unset; .cargo/config.toml applies>}"
    echo "build_kernel: $(uname -srm)"
    prefix "artifact_sha256: " <<<"${artifact_hashes}"
  } >"${out}/build-info.txt"
else
  [[ -z "${build_info}" ]] || cp -- "${build_info}" "${out}/build-info.txt"
fi
printf '%s\n' "${artifact_hashes}" >"${out}/artifacts.sha256"

have() { command -v "$1" >/dev/null 2>&1; }
{
  echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  # The checkout this script ran from. With --bin-dir it need not be the
  # binaries' source: their origin is `binaries` and build-info.txt.
  echo "${source_info}"
  echo "binaries: ${origin}"
  prefix "artifact_sha256: " <<<"${artifact_hashes}"
  echo "rustc: $(rustc --version 2>/dev/null || echo unknown)"
  rustc -vV 2>/dev/null | sed -n 's/^host: /rustc_host: /p; s/^LLVM version: /llvm: /p' || true
  echo "cargo: $(cargo --version 2>/dev/null || echo unknown)"
  echo "rustflags: ${RUSTFLAGS:-<unset; .cargo/config.toml applies>}"
  echo "kernel: $(uname -srm)"
  echo "cpus_online: $(nproc --all)"
  echo "cpus_available: $(nproc)"
  echo "cpus_allowed: $(sed -n 's/^Cpus_allowed_list:[[:space:]]*//p' /proc/self/status)"
  for f in cpu.max cpuset.cpus.effective memory.max; do
    if [[ -r "/sys/fs/cgroup/${f}" ]]; then
      echo "cgroup_${f//./_}: $(cat "/sys/fs/cgroup/${f}")"
    fi
  done
  if [[ -r /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor ]]; then
    echo "governor: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)"
  fi
  grep -m1 'model name' /proc/cpuinfo 2>/dev/null || true
  echo "loadavg_before: $(cut -d' ' -f1-3 /proc/loadavg)"
  echo "allocs: ${alloc_list[*]}"
  echo "executors: ${exec_list[*]}"
  echo "reps: ${reps} (schedule cycle ${cycle})"
  echo "bench_args: ${bench_args[*]}"
  echo "workers: ${req_workers:-<benchmark default, 1 to 16>}"
  echo "profile: ${profile:-no}"
} >"${out}/environment.txt"
if have lscpu; then
  lscpu >"${out}/lscpu.txt" 2>&1 || true
fi

# Checks one run's output against what was asked for. Prints `ok` and the
# row's fields, tab-separated, or the reason the row is unusable.
check_row() {
  local stdout="$1" allocator="$2" executor="$3" header="" row=""
  { IFS= read -r header && IFS= read -r row && ! IFS= read -r _; } <"${stdout}" \
    || { [[ -z "${header}" ]] && echo "no-output" || echo "line-count"; return; }
  local want
  want="$(IFS=$'\t'; echo "${bench_columns[*]}")"
  [[ "${header}" == "${want}" ]] || { echo "bad-header"; return; }
  [[ "${row}" != *$'\t\t'* && "${row}" != $'\t'* && "${row}" != *$'\t' ]] \
    || { echo "empty-field"; return; }
  local -a f
  IFS=$'\t' read -r -a f <<<"${row}"
  ((${#f[@]} == ${#bench_columns[@]})) || { echo "column-count"; return; }
  local -A c
  local i
  for ((i = 0; i < ${#bench_columns[@]}; i++)); do
    c[${bench_columns[i]}]="${f[i]}"
  done
  local name="${allocator}"
  [[ "${allocator}" == mimalloc ]] && name="mimalloc-secure"
  [[ "${c[allocator]}" == "${name}" && "${c[executor]}" == "${executor}" ]] \
    || { echo "wrong-variant"; return; }
  for i in workers window jobs bytes cpu_iters minflt majflt checksum completed \
    expected_checksum expected_completed; do
    # Rust prints canonical decimal integers. Reject leading zeros before
    # any Bash arithmetic, which would otherwise interpret them as octal.
    [[ "${c[$i]}" =~ ^(0|[1-9][0-9]*)$ ]] || { echo "bad-${i}"; return; }
  done
  for i in wall_ms jobs_per_s user_ms system_ms; do
    [[ "${c[$i]}" =~ ^[0-9]+(\.[0-9]+)?$ ]] || { echo "bad-${i}"; return; }
  done
  for i in rss_kib hwm_kib; do
    [[ "${c[$i]}" =~ ^([0-9]+|NA)$ ]] || { echo "bad-${i}"; return; }
  done
  [[ "${c[status]}" == ok ]] || { echo "status-${c[status]}"; return; }
  # The row must be the workload that was asked for.
  [[ "${c[start]}" == "${req_start}" ]] || { echo "wrong-start"; return; }
  for i in jobs bytes cpu_iters; do
    local want_v="req_${i}"
    [[ "${c[$i]}" == "${!want_v}" ]] || { echo "wrong-${i}"; return; }
  done
  if [[ -n "${req_workers}" ]]; then
    [[ "${c[workers]}" == "${req_workers}" ]] || { echo "wrong-workers"; return; }
  else
    # Matched as a string so no out-of-range value, however long, reaches
    # Bash arithmetic, which would wrap it modulo 2^64.
    [[ "${c[workers]}" =~ ^([1-9]|1[0-6])$ ]] || { echo "wrong-workers"; return; }
  fi
  if [[ -n "${req_window}" ]]; then
    [[ "${c[window]}" == "${req_window}" ]] || { echo "wrong-window"; return; }
  else
    [[ "${c[window]}" == "$((4 * c[workers]))" ]] \
      || { echo "wrong-window"; return; }
  fi
  [[ "${c[checksum]}" == "${c[expected_checksum]}" ]] || { echo "checksum-mismatch"; return; }
  [[ "${c[completed]}" == "${c[expected_completed]}" && "${c[completed]}" == "${c[jobs]}" ]] \
    || { echo "count-mismatch"; return; }
  printf 'ok\t%s\n' "${row}"
}

results="${out}/results.tsv"
na_row="$(printf 'NA\t%.0s' "${bench_columns[@]}")"
na_row="${na_row%$'\t'}"
{
  printf 'rep\tposition\trun_allocator\trun_executor\texit\tcheck'
  printf '\t%s' "${bench_columns[@]}"
  printf '\n'
} >"${results}"
failed=0
for ((r = 0; r < reps; r++)); do
  for ((pos = 0; pos < n; pos++)); do
    pair="${pairs[$(schedule_index "${r}" "${pos}")]}"
    alloc="${pair%%:*}"
    executor="${pair##*:}"
    dir="${out}/runs/$(printf 'r%06d-p%02d' "${r}" "${pos}")-${alloc}-${executor}"
    mkdir -p "${dir}"
    cmd=("${bin}/bench-runtime-${alloc}" --executor "${executor}" "${bench_args[@]}")
    if [[ -n "${profile}" ]]; then
      cmd=("${bin}/resource-profile" --out "${dir}/resources" -- "${cmd[@]}")
    fi
    echo "== rep ${r} #${pos}: ${alloc} ${executor}" >&2
    status=0
    "${cmd[@]}" >"${dir}/stdout.tsv" 2>"${dir}/stderr.txt" || status=$?
    echo "${status}" >"${dir}/exit"
    checked="$(check_row "${dir}/stdout.tsv" "${alloc}" "${executor}")"
    if [[ "${status}" -ne 0 ]]; then
      check="exit-${status}"
      fields="${na_row}"
    elif [[ "${checked}" == ok$'\t'* ]]; then
      check=ok
      fields="${checked#ok$'\t'}"
    else
      check="${checked}"
      fields="${na_row}"
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "${r}" "${pos}" "${alloc}" "${executor}" "${status}" \
      "${check}" "${fields}" >>"${results}"
    if [[ "${check}" != ok ]]; then
      echo "-- ${alloc} ${executor}: ${check}, see ${dir}" >&2
      failed=1
    fi
  done
done

echo "== results in ${results}" >&2
column -t -s $'\t' "${results}" >&2 2>/dev/null || cat "${results}" >&2
if [[ "${failed}" -ne 0 ]]; then
  echo "bench-runtime.sh: some runs failed (check column of ${results})" >&2
  exit 1
fi
