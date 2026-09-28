#!/usr/bin/env bash
# Experimental aarch64 SVE/SVE2 kernels (single-package directive Phase F,
# §10.4, §16): correctness and selection only, no timings.
#
# Builds the tests of `allocatbelt` for aarch64 with
# `experimental-aarch64-sve2` (and once with only `experimental-aarch64-sve`)
# and runs them under qemu-user CPU models, and natively on an aarch64 host:
#
# - the kernels' unit tests compare each kernel with the portable loop,
#   under several SVE vector lengths (128 to 2048 bits);
# - `tests/experimental_isa.rs` checks that `Prefer` selects exactly the set
#   the emulated CPU allows (`ALLOCATBELT_EXPECT_KERNEL`), that `Auto` and
#   `Disable` keep the baseline, that `Require` fails where nothing can be
#   selected, and that decay passes return memory with the kernel selected.
#
# On an x86_64 host it cross-compiles with `aarch64-linux-gnu-gcc` and runs
# qemu with the cross sysroot; it needs qemu-user and the
# `aarch64-unknown-linux-gnu` Rust target.
set -euo pipefail

cd "$(dirname "$0")/.."
target=aarch64-unknown-linux-gnu
qemu=(qemu-aarch64)
native=false
if [[ "$(uname -m)" == aarch64 ]]; then
  native=true
else
  export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="${CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER:-aarch64-linux-gnu-gcc}"
  qemu+=(-L "${AARCH64_SYSROOT:-/usr/aarch64-linux-gnu}")
fi

build() {
  # build <feature>: prints the lib, experimental_isa and platform test
  # binaries, one per line.
  cargo test --release --locked -p allocatbelt --features "$1" --target "${target}" \
    --lib --test experimental_isa --test platform --no-run --message-format=json 2>/dev/null |
    jq -r 'select(.reason == "compiler-artifact" and .executable != null) | .executable'
}

pick() {
  # pick <name> <binaries...>
  local name="$1" b
  shift
  for b in "$@"; do
    [[ "$(basename "$b")" == "${name}"-* ]] && { echo "$b"; return; }
  done
  echo "FAIL: no ${name} test binary" >&2
  exit 1
}

run() {
  # run <expected kernel set> <cpu model or "native"> <binaries...>
  local expect="$1" cpu="$2" runner=()
  shift 2
  [[ "${cpu}" != native ]] && runner=("${qemu[@]}" -cpu "${cpu}")
  echo "-- ${cpu}: expect ${expect}"
  "${runner[@]}" "$(pick allocatbelt "$@")" -q arch:: | grep -E '^test result'
  ALLOCATBELT_EXPECT_KERNEL="${expect}" "${runner[@]}" "$(pick experimental_isa "$@")" \
    --nocapture 2>&1 | grep -E '^(kernel_set|experimental_isa):' | sort -u
  ALLOCATBELT_EXPECT_KERNEL="${expect}" "${runner[@]}" "$(pick experimental_isa "$@")" -q |
    grep -E '^test result'
  "${runner[@]}" "$(pick platform "$@")" -q | grep -E '^test result'
}

echo "== experimental-aarch64-sve2 (${target})"
mapfile -t sve2 < <(build experimental-aarch64-sve2)
[[ ${#sve2[@]} -eq 3 ]] || { echo "FAIL: found ${#sve2[@]} test binaries" >&2; exit 1; }
if ${native}; then
  # The host's own CPU, whatever it exposes.
  for b in "${sve2[@]}"; do "$b" -q | grep -E '^test result'; done
fi
run Baseline cortex-a72 "${sve2[@]}"
run Sve neoverse-v1 "${sve2[@]}"
run Sve2 neoverse-n2 "${sve2[@]}"
# Vector lengths in bytes: 128, 512 and 2048 bits.
for vl in 16 64 256; do
  run Sve2 "max,sve-default-vector-length=${vl}" "${sve2[@]}"
done

echo "== experimental-aarch64-sve only"
mapfile -t sve < <(build experimental-aarch64-sve)
run Sve neoverse-n2 "${sve[@]}"
run Baseline cortex-a72 "${sve[@]}"
echo "ok: experimental SVE/SVE2 kernels"
