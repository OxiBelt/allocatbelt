#!/usr/bin/env bash
# Profiles the allocator benchmarks (or any command) for resource use and
# per-function cost. See docs/research/profiling.md for what each mode
# reports and how to read it.
#
#   scripts/profile.sh [options] [MODE...] [-- COMMAND [ARGS...]]
#
# Modes (default: resources):
#   resources  CPU, memory, disk, network, threads and context switches over
#              time, sampled from /proc by `resource-profile`
#   perf       CPU time per function and call graph (`perf record`)
#   faults     page faults per function, i.e. which code makes memory
#              resident (`perf record -e page-faults`)
#   syscalls   system calls by count and time: memory (mmap, madvise),
#              disk and network calls (`strace -c`)
#   callgrind  instructions per function, exact and inclusive of callees,
#              without perf permissions (`valgrind --tool=callgrind`, slow)
#   all        every mode whose tool is installed
#
# Options:
#   --alloc LIST     benchmark binaries to profile, comma separated, of
#                    system, mimalloc and allocatbelt (default: all three)
#   --quick          run each benchmark with `--quick` (a twentieth of the
#                    work; for smoke runs and callgrind, not for timings)
#   --only KEYS      run only these workloads, passed to the benchmarks
#                    (single, local, small, pairs, idle, oversubscribed)
#   --interval-ms N  sampling interval of `resources` (default 100)
#   --out DIR        output directory (default target/profile/<UTC time>)
#   --top N          rows of the per-function tables (default 40)
#
# With `-- COMMAND [ARGS...]` the modes profile that command instead of the
# benchmark binaries, for example an OxiBelt build:
#
#   scripts/profile.sh resources perf -- ./target/release/oxibelt --config c.toml
#
# Profiles are local evidence for one machine; do not commit their numbers
# without recording the environment (docs/research/benchmarks.md).
set -euo pipefail

cd "$(dirname "$0")/.."

allocs="system,mimalloc,allocatbelt"
quick=""
only=""
interval=100
out=""
top=40
modes=()
command=()
failed=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --alloc) allocs="$2"; shift 2 ;;
    --quick) quick=1; shift ;;
    --only) only="$2"; shift 2 ;;
    --interval-ms) interval="$2"; shift 2 ;;
    --out) out="$2"; shift 2 ;;
    --top) top="$2"; shift 2 ;;
    --) shift; command=("$@"); break ;;
    -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
    resources|perf|faults|syscalls|callgrind|all) modes+=("$1"); shift ;;
    *) echo "profile.sh: unknown argument $1 (see --help)" >&2; exit 2 ;;
  esac
done
[[ ${#modes[@]} -gt 0 ]] || modes=(resources)
if [[ " ${modes[*]} " == *" all "* ]]; then
  modes=(resources perf faults syscalls callgrind)
  all=1
fi
out="${out:-target/profile/$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "${out}"

have() { command -v "$1" >/dev/null 2>&1; }

# A missing tool fails the run when the mode was asked for by name, and is
# skipped with a note under `all`.
need() {
  local mode="$1" tool="$2"
  if have "${tool}"; then
    return 0
  fi
  if [[ -n "${all:-}" ]]; then
    echo "-- skipping ${mode}: ${tool} is not installed" >&2
    return 1
  fi
  echo "profile.sh: ${mode} needs ${tool}, which is not installed" >&2
  exit 1
}

# Rust symbols use the v0 mangling, which older perf builds print raw;
# `rustfilt` (cargo install rustfilt) turns them into paths when installed.
demangle() {
  if have rustfilt; then
    rustfilt
  else
    cat
  fi
}

perf_usable() {
  local paranoid
  paranoid="$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo 4)"
  if [[ "${paranoid}" -gt 2 ]] && [[ "$(id -u)" -ne 0 ]]; then
    local msg="perf_event_paranoid is ${paranoid}; perf needs it at 2 or below for your own processes (sudo sysctl kernel.perf_event_paranoid=2), or use callgrind"
    if [[ -n "${all:-}" ]]; then
      echo "-- skipping ${mode}: ${msg}" >&2
      return 1
    fi
    echo "profile.sh: ${msg}" >&2
    exit 1
  fi
}

# The `bench` profile is `release` with debug info, so perf and callgrind
# can name functions and lines.
echo "== building (cargo --profile bench)" >&2
cargo build --profile bench --locked -p allocatbelt-profile >&2
sampler="target/release/resource-profile"

targets=()
if [[ ${#command[@]} -eq 0 ]]; then
  cargo build --profile bench --locked -p allocatbelt-bench >&2
  bench_args=()
  [[ -n "${quick}" ]] && bench_args+=(--quick)
  [[ -n "${only}" ]] && bench_args+=(--only "${only}")
  IFS=, read -r -a names <<<"${allocs}"
  for name in "${names[@]}"; do
    case "${name}" in
      system|mimalloc|allocatbelt) targets+=("${name}") ;;
      *) echo "profile.sh: unknown allocator ${name}" >&2; exit 2 ;;
    esac
  done
else
  targets=(command)
fi

# Prints the command line of one target, one word per line.
argv() {
  if [[ "$1" == command ]]; then
    printf '%s\n' "${command[@]}"
  else
    printf '%s\n' "target/release/bench-$1" "${bench_args[@]}"
  fi
}

{
  echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "commit: $(git rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "kernel: $(uname -srm)"
  echo "cpus: $(nproc)"
  grep -m1 'model name' /proc/cpuinfo 2>/dev/null || true
  echo "rustc: $(rustc --version)"
  echo "modes: ${modes[*]}"
  echo "targets: ${targets[*]}"
  [[ ${#command[@]} -gt 0 ]] && echo "command: ${command[*]}"
  [[ -n "${quick}" ]] && echo "quick: yes (not for timings)"
  [[ -n "${only}" ]] && echo "only: ${only}"
} >"${out}/environment.txt"

for target in "${targets[@]}"; do
  mapfile -t cmd < <(argv "${target}")
  dir="${out}/${target}"
  mkdir -p "${dir}"
  for mode in "${modes[@]}"; do
    case "${mode}" in
      resources)
        echo "== ${target}: resources" >&2
        mkdir -p "${dir}/resources"
        "${sampler}" --interval-ms "${interval}" --out "${dir}/resources" -- "${cmd[@]}" \
          | tee "${dir}/resources/stdout.txt"
        ;;
      perf)
        need perf perf || continue
        perf_usable || continue
        echo "== ${target}: perf (CPU per function)" >&2
        perf record -F 999 -m 16M -g --call-graph dwarf,16384 -o "${dir}/perf.data" \
          -- "${cmd[@]}" >"${dir}/perf-stdout.txt"
        report() { perf report -i "${dir}/perf.data" --stdio "$@" 2>/dev/null | demangle; }
        report --no-children --sort symbol -g none --percent-limit 0.2 \
          | sed -n "1,$((top + 12))p" >"${dir}/perf-self.txt"
        report --children --sort symbol -g none --percent-limit 0.5 \
          | sed -n "1,$((top + 12))p" >"${dir}/perf-inclusive.txt"
        report --no-children --sort comm,symbol -g none --percent-limit 0.2 \
          | sed -n "1,$((top + 12))p" >"${dir}/perf-by-thread.txt"
        report --no-children --sort symbol -g caller,0.5,callee,function,percent \
          --percent-limit 2 >"${dir}/perf-callgraph.txt"
        if have inferno-collapse-perf && have inferno-flamegraph; then
          perf script -i "${dir}/perf.data" 2>/dev/null | demangle | inferno-collapse-perf \
            >"${dir}/perf.folded"
          inferno-flamegraph <"${dir}/perf.folded" >"${dir}/flamegraph.svg"
        fi
        ;;
      faults)
        need faults perf || continue
        perf_usable || continue
        echo "== ${target}: faults (page faults per function)" >&2
        # Every fault is a sample (`-c 1`); a large buffer and a shorter
        # stack copy keep perf from losing them in fault-heavy workloads.
        perf record -e page-faults -c 1 -m 64M -g --call-graph dwarf,8192 \
          -o "${dir}/faults.data" -- "${cmd[@]}" >"${dir}/faults-stdout.txt"
        perf report -i "${dir}/faults.data" --stdio --no-children --sort symbol -g none \
          --percent-limit 0.5 2>/dev/null | demangle | sed -n "1,$((top + 12))p" \
          >"${dir}/faults-by-function.txt"
        perf report -i "${dir}/faults.data" --stdio --no-children --sort symbol \
          -g caller,0.5,callee,function,percent --percent-limit 2 2>/dev/null | demangle \
          >"${dir}/faults-callgraph.txt"
        ;;
      syscalls)
        need syscalls strace || continue
        echo "== ${target}: syscalls" >&2
        strace -f -c -S time -o "${dir}/syscalls.txt" -- "${cmd[@]}" >"${dir}/syscalls-stdout.txt"
        ;;
      callgrind)
        need callgrind valgrind || continue
        echo "== ${target}: callgrind (instructions per function; slow)" >&2
        # allocatbelt reserves a 64 GiB arena at start-up, which valgrind
        # cannot map, so its benchmark aborts here; use perf for it.
        if ! valgrind --tool=callgrind --separate-threads=no \
          --callgrind-out-file="${dir}/callgrind.out" -- "${cmd[@]}" \
          >"${dir}/callgrind-stdout.txt" 2>"${dir}/callgrind-valgrind.txt"; then
          echo "-- callgrind: ${target} failed, see ${dir}/callgrind-valgrind.txt" >&2
          failed=1
          continue
        fi
        callgrind_annotate --inclusive=no "${dir}/callgrind.out" 2>/dev/null | demangle \
          | sed -n "1,$((top + 30))p" >"${dir}/callgrind-self.txt"
        callgrind_annotate --inclusive=yes "${dir}/callgrind.out" 2>/dev/null | demangle \
          | sed -n "1,$((top + 30))p" >"${dir}/callgrind-inclusive.txt"
        ;;
    esac
  done
done

echo "== profiles in ${out}" >&2
find "${out}" -type f ! -name '*.data' ! -name '*.out' | sort >&2
if [[ -n "${failed}" ]]; then
  echo "profile.sh: some profiles failed (see the -- lines above)" >&2
  exit 1
fi
