#!/usr/bin/env bash
# Experimental RISC-V V kernel (single-package directive Phase G, §10.5,
# §16): correctness, isolation and selection only, no timings.
#
# The `v` target feature is unstable in Rust 1.98, so the feature
# `experimental-riscv-rvv` needs nightly on riscv64; this check uses the
# pinned nightly below and nothing else in the repository does.
#
# 1. Lints `allocatbelt` for riscv64 with the feature.
# 2. Builds its lib, `experimental_isa` and `platform` tests for riscv64
#    with the feature and checks that V instructions appear only in the
#    kernel (`arch::rvv::aged_pages_rvv_body`): V is not enabled for the
#    rest of the binary, which must run on the RV64GC baseline.
# 3. Runs them under qemu-user with V at VLEN 128, 256 (the `max` default)
#    and 1024: the kernel matches the portable loop, and `Prefer` selects
#    `Rvv`. Then without V: `Prefer` keeps the baseline. That run is
#    skipped when the cross C library itself needs V (Ubuntu 26.04 builds
#    its riscv64 glibc for RVA23), which qemu reports as SIGILL before any
#    test runs.
#
# Needs qemu-user, riscv64-linux-gnu-gcc and its sysroot, llvm-objdump,
# jq, and the pinned nightly with the riscv64gc-unknown-linux-gnu target.
set -euo pipefail

cd "$(dirname "$0")/.."
toolchain="${RVV_TOOLCHAIN:-nightly-2026-09-27}"
target=riscv64gc-unknown-linux-gnu
feature=experimental-riscv-rvv
qemu=(qemu-riscv64 -L "${RISCV64_SYSROOT:-/usr/riscv64-linux-gnu}")
rustc "+${toolchain}" --version

echo "== clippy (${toolchain}, ${target}, ${feature})"
cargo "+${toolchain}" clippy -p allocatbelt --all-targets --locked --target "${target}" \
  --features "${feature}" -- -D warnings

echo "== building tests"
mapfile -t bins < <(
  cargo "+${toolchain}" test --release --locked -p allocatbelt --features "${feature}" \
    --target "${target}" --lib --test experimental_isa --test platform --no-run \
    --message-format=json 2>/dev/null |
    jq -r 'select(.reason == "compiler-artifact" and .executable != null) | .executable'
)
[[ ${#bins[@]} -eq 3 ]] || { echo "FAIL: found ${#bins[@]} test binaries" >&2; exit 1; }

echo "== V instructions only in the kernel"
for b in "${bins[@]}"; do
  mapfile -t fns < <(
    llvm-objdump -d --no-show-raw-insn --mattr=+v "$b" |
      awk '/^[0-9a-f]+ <.*>:$/ { fn = $2 }
        /\t(vsetvli|vsetivli|vsetvl|vl[0-9a-z]*\.v|vs[0-9a-z]*\.v|vmv|vmerge|vredor|vmsleu)[ \t]/ { print fn }' |
      sort -u
  )
  for fn in "${fns[@]}"; do
    [[ "${fn}" == *aged_pages_rvv_body* ]] ||
      { echo "FAIL: V instructions in ${fn} ($(basename "$b"))" >&2; exit 1; }
  done
  [[ ${#fns[@]} -eq 1 ]] || { echo "FAIL: kernel not found in $(basename "$b")" >&2; exit 1; }
  echo "ok: $(basename "$b"): only ${fns[0]}"
done

pick() {
  local name="$1" b
  for b in "${bins[@]}"; do
    [[ "$(basename "$b")" == "${name}"-* ]] && { echo "$b"; return; }
  done
  echo "FAIL: no ${name} test binary" >&2
  exit 1
}

run() {
  # run <expected kernel set> <cpu model>
  local expect="$1" cpu="$2" q=("${qemu[@]}" -cpu "$2")
  echo "-- ${cpu}: expect ${expect}"
  "${q[@]}" "$(pick allocatbelt)" -q arch:: | grep -E '^test result'
  ALLOCATBELT_EXPECT_KERNEL="${expect}" "${q[@]}" "$(pick experimental_isa)" --nocapture 2>&1 |
    grep -E '^(kernel_set|experimental_isa):' | sort -u
  ALLOCATBELT_EXPECT_KERNEL="${expect}" "${q[@]}" "$(pick experimental_isa)" -q |
    grep -E '^test result'
  "${q[@]}" "$(pick platform)" -q | grep -E '^test result'
}

echo "== under qemu-user"
for vlen in 128 256 1024; do
  run Rvv "max,vlen=${vlen}"
done
status=0
"${qemu[@]}" -cpu max,v=false "$(pick platform)" --list >/dev/null 2>&1 || status=$?
if [[ ${status} -eq 132 ]]; then
  echo "-- max,v=false: skipped, the cross C library needs V (SIGILL before any test)"
elif [[ ${status} -ne 0 ]]; then
  echo "FAIL: max,v=false: exit ${status}" >&2
  exit 1
else
  run Baseline max,v=false
fi
echo "ok: experimental RVV kernel"
