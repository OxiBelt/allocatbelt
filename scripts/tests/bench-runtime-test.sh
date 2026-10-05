#!/usr/bin/env bash
# Tests of scripts/bench-runtime.sh with stand-in benchmark binaries: run
# order, argument checks, output-directory protection, row validation and
# source provenance. The stand-ins print fixed values that only exercise the
# checks; they are not measurements.
#
#   scripts/tests/bench-runtime-test.sh
set -euo pipefail

repo="$(cd "$(dirname "$0")/../.." && pwd)"
script="${repo}/scripts/bench-runtime.sh"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/bench-runtime-test.XXXXXX")"
trap 'rm -rf -- "${tmp}"' EXIT

failures=0
fail() {
  echo "FAIL: $*" >&2
  failures=$((failures + 1))
}

# Runs the script; its exit code goes to `code`, its output to $tmp/log.
code=0
bench() {
  code=0
  "${script}" "$@" >"${tmp}/log" 2>&1 || code=$?
}
expect_code() {
  local want="$1" what="$2"
  [[ "${code}" == "${want}" ]] || fail "${what}: exit ${code}, want ${want}: $(tail -3 "${tmp}/log")"
}

columns="$(sed -n 's/^bench_columns=(\(.*\))$/\1/p' "${script}")"
[[ -n "${columns}" ]] || { echo "FAIL: no bench_columns in ${script}" >&2; exit 1; }

# Stand-in binaries. $tmp/mode/<alloc>-<executor> picks what one prints.
bin="${tmp}/bin"
mkdir -p "${bin}" "${tmp}/mode"
cat >"${bin}/fake" <<FAKE
#!/usr/bin/env bash
# Echoes the requested workload back in a row of placeholder figures;
# \$tmp/mode/<alloc>-<executor> makes it print one kind of bad row instead.
alloc="\${0##*/bench-runtime-}"
executor="" start="" workers=4 window="" jobs="" bytes="" cpu=""
while [[ \$# -gt 0 ]]; do
  case "\$1" in
    --executor) executor="\$2" ;; --start) start="\$2" ;; --workers) workers="\$2" ;;
    --window) window="\$2" ;; --jobs) jobs="\$2" ;; --bytes) bytes="\$2" ;; --cpu-iters) cpu="\$2" ;;
    *) echo "fake: unexpected \$1" >&2; exit 2 ;;
  esac
  shift 2
done
window="\${window:-\$((4 * workers))}"
printf '%s\n' "\${start} \${workers} \${window} \${jobs} \${bytes} \${cpu}" >>"${tmp}/calls"
mode="\$(cat "${tmp}/mode/\${alloc}-\${executor}" 2>/dev/null || echo ok)"
name="\${alloc}"
[[ "\${alloc}" == mimalloc ]] && name=mimalloc-secure
done_jobs="\${jobs}" rss=10 sum=7 status=ok
case "\${mode}" in
  wrongstart) [[ "\${start}" == warm ]] && start=cold || start=warm ;;
  wrongworkers) workers=\$((workers + 1)) ;;
  wrongwindow) window=\$((window + 1)) ;;
  wrongjobs) jobs=\$((jobs + 1)) done_jobs=\$((done_jobs + 1)) ;;
  badcount) done_jobs=\$((done_jobs - 1)) ;;
  wrongbytes) bytes=\$((bytes + 1)) ;;
  wrongcpu) cpu=\$((cpu + 1)) ;;
  bigworkers) workers=99 window=396 ;;
  octalworkers) workers=08 ;;
  overflowworkers) workers=18446744073709551620 ;;
  zeroworkers) workers=0 window=0 ;;
  na) rss=NA ;;
  badsum) sum=8 ;;
  status) status=FAIL ;;
  emptyfield) rss="" ;;
  badnumber) rss=1x ;;
esac
header="\$(tr ' ' '\t' <<<"${columns}")"
row() {
  printf '%s\t' "\${1}" "\${executor}" "\${start}" "\${workers}" "\${window}" "\${jobs}" "\${bytes}" \
    "\${cpu}" 1.0 1 0 0 "\${rss}" 20 0 0 "\${sum}" "\${done_jobs}" 7 "\${jobs}"
  printf '%s\n' "\${status}"
}
case "\${mode}" in
  nostdout) ;;
  crash) echo "\${header}"; exit 3 ;;
  badheader) echo "x\${header}"; row "\${name}" ;;
  wrongvariant) echo "\${header}"; row other ;;
  extraline) echo "\${header}"; row "\${name}"; echo more ;;
  *) echo "\${header}"; row "\${name}" ;;
esac
FAKE
chmod +x "${bin}/fake"
for a in system mimalloc allocatbelt; do
  ln -s fake "${bin}/bench-runtime-${a}"
done

# A cargo that records being called, to check rejections come first.
mkdir -p "${tmp}/path"
printf '#!/bin/sh\ntouch "%s/cargo-called"\nexit 1\n' "${tmp}" >"${tmp}/path/cargo"
chmod +x "${tmp}/path/cargo"

# --- argument checks, all before cargo or any output ---
args=()
for bad in "--allocs ''" "--allocs system," "--allocs ,system" "--allocs system,,mimalloc" \
  "--allocs jemalloc" "--allocs system,system" "--executors ''" "--executors tokio," \
  "--executors async" "--reps 0" "--reps 08" "--reps 010" "--reps -1" "--reps 1.5" \
  "--reps 1e3" "--reps 9999999" "--reps ''" "--reps" "--workers 08" "--jobs 99999999999999999999" \
  "--start hot" "--frobnicate" "--allocs 'system mimalloc'" "--allocs 'system, mimalloc'" \
  "--allocs ' system'" "--allocs 'system '" "--allocs System" "--allocs sys" \
  "--allocs 'system,mimalloc allocatbelt'" "--executors 'bounded tokio'" "--executors Tokio" \
  "--workers 0" "--workers 1025" "--workers 10000" "--build-info /dev/null"; do
  eval "args=(${bad})"
  PATH="${tmp}/path:${PATH}" bench "${args[@]}" --out "${tmp}/rejected"
  expect_code 2 "${bad}"
  [[ ! -e "${tmp}/cargo-called" ]] || fail "${bad}: cargo ran"
  [[ ! -e "${tmp}/rejected" ]] || fail "${bad}: wrote output"
done
for bad in $'system\nmimalloc' $'system\n' $'system,mimalloc\nallocatbelt' $'system\tmimalloc'; do
  PATH="${tmp}/path:${PATH}" bench --allocs "${bad}" --out "${tmp}/rejected"
  expect_code 2 "--allocs with a newline or tab"
  [[ ! -e "${tmp}/cargo-called" && ! -e "${tmp}/rejected" ]] || fail "newline list: ran or wrote"
  PATH="${tmp}/path:${PATH}" bench --executors "${bad/system/tokio}" --out "${tmp}/rejected"
  expect_code 2 "--executors with a newline or tab"
  [[ ! -e "${tmp}/cargo-called" && ! -e "${tmp}/rejected" ]] || fail "newline list: ran or wrote"
done

# --- balanced order ---
schedule() { "${script}" "$@" --print-schedule 2>/dev/null; }
got="$(schedule --allocs system --executors bounded,tokio --reps 2)"
[[ "${got}" == $'system:bounded system:tokio\nsystem:tokio system:bounded' ]] \
  || fail "two pairs: ${got}"

# Every pair in every position once per cycle, and every ordered pair of
# neighbours equally often: 6 pairs (cycle 6) and 3 pairs (cycle 6).
check_balance() {
  local what="$1" reps="$2"
  shift 2
  local order
  order="$(schedule "$@" --reps "${reps}")"
  local positions neighbours
  positions="$(awk '{ for (i = 1; i <= NF; i++) print i, $i }' <<<"${order}" | sort | uniq -c \
    | awk '{ print $1 }' | sort -u | tr '\n' ' ')"
  neighbours="$(awk '{ for (i = 1; i < NF; i++) print $i, $(i + 1) }' <<<"${order}" | sort \
    | uniq -c | awk '{ print $1 }' | sort -u | tr '\n' ' ')"
  local n
  n="$(head -1 <<<"${order}" | wc -w)"
  [[ "$(awk '{ print NF }' <<<"${order}" | sort -u)" == "${n}" ]] || fail "${what}: row length"
  [[ "$(awk '{ for (i = 1; i <= NF; i++) print NR, $i }' <<<"${order}" | sort -u | wc -l)" \
    == "$((reps * n))" ]] || fail "${what}: a pair repeats within a row"
  [[ "${positions}" == "$((reps / n)) " ]] || fail "${what}: positions ${positions}"
  [[ "$(awk '{ for (i = 1; i < NF; i++) print $i, $(i + 1) }' <<<"${order}" | sort -u | wc -l)" \
    == "$((n * (n - 1)))" ]] || fail "${what}: not every neighbour pair occurs"
  [[ "$(wc -w <<<"${neighbours}")" == 1 ]] || fail "${what}: neighbour counts ${neighbours}"
}
check_balance "six pairs" 6
check_balance "six pairs, two cycles" 12
check_balance "three pairs" 6 --executors tokio
[[ "$(schedule --reps 4 --executors tokio | head -1)" == "$(schedule --reps 4 --executors tokio | head -1)" ]] \
  || fail "schedule not deterministic"
bench --allocs system --executors tokio,bounded --reps 3 --bin-dir "${bin}" --out "${tmp}/odd"
grep -q 'not a multiple of the schedule cycle' "${tmp}/log" || fail "no warning for 3 reps of 2 pairs"

# --- an occupied --out is refused before anything is written ---
echo ok >"${tmp}/mode/system-tokio"
bench --allocs system --executors tokio --reps 1 --bin-dir "${bin}" --out "${tmp}/twice"
expect_code 0 "first run"
before="$(cd "${tmp}/twice" && find . -type f -exec sha256sum {} + | sort)"
bench --allocs system --executors tokio --reps 1 --bin-dir "${bin}" --out "${tmp}/twice"
expect_code 2 "second run into the same --out"
after="$(cd "${tmp}/twice" && find . -type f -exec sha256sum {} + | sort)"
[[ "${before}" == "${after}" ]] || fail "second run changed the first run's output"
touch "${tmp}/a-file"
bench --allocs system --executors tokio --reps 1 --bin-dir "${bin}" --out "${tmp}/a-file"
expect_code 2 "--out naming a file"
mkdir "${tmp}/empty"
bench --allocs system --executors tokio --reps 1 --bin-dir "${bin}" --out "${tmp}/empty"
expect_code 0 "empty existing --out"

# --- every attempt has a row; unusable rows fail the run ---
# Prints field `$2` (by column name) of data row `$3` of results.tsv in `$1`.
field() {
  awk -F'\t' -v name="$2" -v row="$3" \
    'NR == 1 { for (i = 1; i <= NF; i++) col[$i] = i; next } NR == row + 1 { print $col[name] }' \
    "$1/results.tsv"
}
for mode_check in nostdout:no-output crash:exit-3 badheader:bad-header wrongvariant:wrong-variant \
  badsum:checksum-mismatch badcount:count-mismatch status:status-FAIL extraline:line-count \
  emptyfield:empty-field badnumber:bad-rss_kib wrongstart:wrong-start wrongworkers:wrong-workers \
  wrongwindow:wrong-window wrongjobs:wrong-jobs wrongbytes:wrong-bytes wrongcpu:wrong-cpu_iters; do
  mode="${mode_check%%:*}"
  want="${mode_check#*:}"
  echo "${mode}" >"${tmp}/mode/system-tokio"
  echo ok >"${tmp}/mode/system-bounded"
  dir="${tmp}/rows-${mode}"
  bench --allocs system --executors bounded,tokio --reps 2 --workers 2 --window 5 --jobs 10 \
    --bytes 3 --cpu-iters 1 --bin-dir "${bin}" --out "${dir}"
  expect_code 1 "${mode}"
  [[ "$(($(wc -l <"${dir}/results.tsv") - 1))" == 4 ]] || fail "${mode}: not one row per attempt"
  for row in 1 2 3 4; do
    executor="$(field "${dir}" run_executor "${row}")"
    [[ "$(field "${dir}" run_allocator "${row}")" == system ]] || fail "${mode}: row ${row} allocator"
    if [[ "${executor}" == tokio ]]; then
      [[ "$(field "${dir}" check "${row}")" == "${want}" ]] \
        || fail "${mode}: check $(field "${dir}" check "${row}"), want ${want}"
      for c in ${columns}; do
        [[ "$(field "${dir}" "${c}" "${row}")" == NA ]] || fail "${mode}: ${c} is not NA"
      done
      [[ "$(field "${dir}" exit "${row}")" == "$([[ ${mode} == crash ]] && echo 3 || echo 0)" ]] \
        || fail "${mode}: exit column"
    else
      [[ "$(field "${dir}" check "${row}")" == ok ]] || fail "${mode}: the good run is not ok"
    fi
  done
done

# Default workers must reject noncanonical and out-of-range integers,
# including one that wraps to 4 in 64-bit arithmetic (2^64 + 4), without
# aborting the collector or losing this and later attempts.
for mode_check in octalworkers:bad-workers overflowworkers:wrong-workers \
  zeroworkers:wrong-workers; do
  mode="${mode_check%%:*}"
  want="${mode_check#*:}"
  echo "${mode}" >"${tmp}/mode/system-tokio"
  echo ok >"${tmp}/mode/system-bounded"
  dir="${tmp}/default-${mode}"
  bench --allocs system --executors bounded,tokio --reps 2 --bin-dir "${bin}" --out "${dir}"
  expect_code 1 "default workers ${mode}"
  [[ "$(wc -l <"${dir}/results.tsv")" == 5 ]] \
    || fail "default workers ${mode}: not one row per attempt"
  for row in 1 2 3 4; do
    if [[ "$(field "${dir}" run_executor "${row}")" == tokio ]]; then
      [[ "$(field "${dir}" check "${row}")" == "${want}" ]] \
        || fail "default workers ${mode}: check $(field "${dir}" check "${row}"), want ${want}"
      for c in ${columns}; do
        [[ "$(field "${dir}" "${c}" "${row}")" == NA ]] \
          || fail "default workers ${mode}: ${c} is not NA"
      done
    else
      [[ "$(field "${dir}" check "${row}")" == ok ]] \
        || fail "default workers ${mode}: good attempt lost"
    fi
  done
done

echo ok >"${tmp}/mode/system-tokio"
echo na >"${tmp}/mode/allocatbelt-tokio"
bench --allocs system,mimalloc,allocatbelt --executors tokio --reps 3 --bin-dir "${bin}" \
  --out "${tmp}/good"
expect_code 0 "good runs"
[[ "$(awk -F'\t' 'NR > 1 && $6 == "ok"' "${tmp}/good/results.tsv" | wc -l)" == 9 ]] \
  || fail "good runs: not nine ok rows"
grep -q $'\tmimalloc-secure\t' "${tmp}/good/results.tsv" || fail "mimalloc row name"

# --- the request each run gets and is checked against ---
# Runs once with `$@` and prints what the stand-in was asked for
# (start workers window jobs bytes cpu-iters) and the check.
requested() {
  local dir="${tmp}/req-$1"
  shift
  rm -f -- "${tmp}/calls"
  bench --allocs system --executors tokio --reps 1 --bin-dir "${bin}" --out "${dir}" "$@"
  printf '%s %s %s' "$(cat "${tmp}/calls" 2>/dev/null)" "$(field "${dir}" check 1)" "${code}"
}
echo ok >"${tmp}/mode/system-tokio"
expect_req() {
  local got
  got="$(requested "$1" "${@:3}")"
  [[ "${got}" == "$2" ]] || fail "request $1: got '${got}', want '$2'"
}
expect_req defaults "warm 4 16 100000 65536 1000 ok 0"
expect_req quick "warm 4 16 2000 4096 100 ok 0" --quick
expect_req explicit-over-quick "cold 3 12 10 0 2 ok 0" \
  --jobs 10 --quick --start cold --workers 3 --bytes 0 --cpu-iters 2
expect_req last-wins "warm 3 7 5 6 8 ok 0" --start cold --start warm --workers 2 --workers 3 \
  --window 9 --window 7 --jobs 4 --jobs 5 --bytes 1 --bytes 6 --cpu-iters 9 --cpu-iters 8
expect_req given-window "warm 4 5 100000 65536 1000 ok 0" --window 5
# Asked for warm, workers 4, window 16, jobs 10: a row reporting another
# workload fails even though its own figures agree with each other.
echo bigworkers >"${tmp}/mode/system-tokio"
expect_req other-workload "warm 4 16 10 65536 1000 wrong-workers 1" --workers 4 --window 16 --jobs 10
# Without --workers only the benchmark's own default range is accepted.
expect_req default-range "warm 4 16 100000 65536 1000 wrong-workers 1"
echo wrongwindow >"${tmp}/mode/system-tokio"
expect_req default-window "warm 4 16 100000 65536 1000 wrong-window 1"
echo ok >"${tmp}/mode/system-tokio"

# --- artifacts and their origin ---
env_field() { sed -n "s/^$2: //p" "$1/environment.txt"; }
[[ "$(wc -l <"${tmp}/good/artifacts.sha256")" == 3 ]] || fail "artifacts.sha256: not three binaries"
[[ "$(cut -f2 "${tmp}/good/artifacts.sha256" | sort -u)" == "$(sha256sum <"${bin}/fake" | cut -d' ' -f1)" ]] \
  || fail "artifacts.sha256: wrong hashes"
[[ "$(env_field "${tmp}/good" binaries)" == *"origin unknown"* ]] || fail "unknown origin not marked"
[[ ! -e "${tmp}/good/build-info.txt" ]] || fail "build-info.txt without a build record"

# A build by a stand-in cargo in a scratch checkout writes the record.
build="${tmp}/build"
mkdir -p "${build}/target/release" "${tmp}/cargo-path"
cat >"${tmp}/cargo-path/cargo" <<CARGO
#!/usr/bin/env bash
[[ "\$1" == --version ]] && { echo "cargo 0.0.0 (stand-in)"; exit 0; }
for a in system mimalloc allocatbelt; do
  cp "${bin}/fake" "${build}/target/release/bench-runtime-\${a}"
done
echo "\$*" >"${tmp}/cargo-args"
CARGO
chmod +x "${tmp}/cargo-path/cargo"
PATH="${tmp}/cargo-path:${PATH}" BENCH_RUNTIME_ROOT="${build}" bench --allocs system,mimalloc \
  --executors tokio --reps 1 --out "${tmp}/built"
expect_code 0 "built run"
record="${tmp}/built/build-info.txt"
[[ "$(head -1 "${record}")" == "format: bench-runtime-build-info 1" ]] || fail "build-info format"
grep -qx "build_command: cargo build --profile bench --locked -p allocatbelt-bench" "${record}" \
  || fail "build-info command"
[[ "$(grep -c '^artifact_sha256: ' "${record}")" == 2 ]] || fail "build-info artifacts"
grep -qx 'build_source_sha256: unknown' "${record}" || fail "build-info source (no checkout)"
[[ "$(env_field "${tmp}/built" binaries)" == "built by this run"* ]] || fail "built origin"

# The record vouches for copies of exactly those binaries.
copy="${tmp}/copy"
mkdir -p "${copy}"
cp "${build}/target/release/bench-runtime-system" "${build}/target/release/bench-runtime-mimalloc" \
  "${copy}/"
bench --allocs system,mimalloc --executors tokio --reps 1 --bin-dir "${copy}" \
  --build-info "${record}" --out "${tmp}/vouched"
expect_code 0 "matching build record"
cmp -s "${record}" "${tmp}/vouched/build-info.txt" || fail "build record not copied"
[[ "$(env_field "${tmp}/vouched" binaries)" == *"matches the supplied build record"* ]] \
  || fail "supplied origin"
# A binary the record does not list, or that differs from it, stops the run
# before any output.
for case in unlisted changed badformat; do
  supplied="${record}"
  args=(--allocs "system,mimalloc" --executors tokio)
  case "${case}" in
    unlisted) args=(--allocs "system,mimalloc,allocatbelt" --executors tokio)
      cp "${bin}/fake" "${copy}/bench-runtime-allocatbelt" ;;
    changed) cp "${copy}/bench-runtime-mimalloc" "${tmp}/saved"
      echo "# changed" >>"${copy}/bench-runtime-mimalloc" ;;
    badformat) supplied="${tmp}/badformat"; sed 1d "${record}" >"${supplied}" ;;
  esac
  bench "${args[@]}" --reps 1 --bin-dir "${copy}" --build-info "${supplied}" \
    --out "${tmp}/refused-${case}"
  expect_code 2 "build record ${case}"
  [[ ! -e "${tmp}/refused-${case}" ]] || fail "build record ${case}: wrote output"
  [[ "${case}" != changed ]] || cp "${tmp}/saved" "${copy}/bench-runtime-mimalloc"
done

# --- provenance ---
[[ "$(env_field "${tmp}/good" commit)" == "$(git -C "${repo}" rev-parse HEAD)" ]] \
  || fail "commit is not HEAD"
[[ "$(env_field "${tmp}/good" source_sha256)" =~ ^[0-9a-f]{64}$ ]] || fail "source_sha256"

# A scratch checkout without commits: untracked paths and contents count.
src="${tmp}/src"
mkdir -p "${src}"
git -C "${src}" init -q
# Prints source, untracked count and hash of a run into $tmp/prov-$1.
source_of() {
  local dir="${tmp}/prov-$1"
  BENCH_RUNTIME_ROOT="${src}" "${script}" --allocs system --executors tokio --reps 1 \
    --bin-dir "${bin}" --out "${dir}" >/dev/null 2>&1 || { echo "run-failed"; return; }
  printf '%s %s %s' "$(env_field "${dir}" source)" "$(env_field "${dir}" untracked_files)" \
    "$(env_field "${dir}" source_sha256)"
}
empty="$(source_of 1)"
[[ "${empty}" == "clean 0 "* ]] || fail "empty checkout: ${empty}"
echo one >"${src}/a.txt"
one="$(source_of 2)"
[[ "${one}" == "dirty (differs from the commit) 1 "* ]] || fail "untracked file: ${one}"
[[ "${one##* }" != "${empty##* }" ]] || fail "an untracked file does not change the hash"
mv "${src}/a.txt" "${src}/b.txt"
renamed="$(source_of 3)"
[[ "${renamed##* }" != "${one##* }" ]] || fail "a rename does not change the hash"
echo two >"${src}/b.txt"
changed="$(source_of 4)"
[[ "${changed##* }" != "${renamed##* }" ]] || fail "new contents do not change the hash"
echo one >"${src}/b.txt"
[[ "$(source_of 5)" == "${renamed}" ]] || fail "the same source gives another hash"
git -C "${src}" add b.txt
staged="$(source_of 6)"
[[ "${staged}" == "dirty (differs from the commit) 0 "* ]] || fail "staged file: ${staged}"
# Still no commit: an edit to the staged file, not staged itself, counts.
echo three >"${src}/b.txt"
edited="$(source_of 7)"
[[ "${edited}" == "dirty (differs from the commit) 0 "* ]] || fail "edited staged file: ${edited}"
[[ "${edited##* }" != "${staged##* }" ]] || fail "an unstaged edit does not change the hash"
echo one >"${src}/b.txt"
[[ "$(source_of 8)" == "${staged}" ]] || fail "undoing the edit gives another hash"
git -C "${src}" add b.txt
echo four >"${src}/b.txt"
git -C "${src}" add b.txt
echo one >"${src}/b.txt"
[[ "$(source_of 9)" != "${staged}" ]] || fail "index and working copy swapped give the same hash"

if ((failures > 0)); then
  echo "bench-runtime-test: ${failures} failures" >&2
  exit 1
fi
echo "bench-runtime-test: ok"
