#!/usr/bin/env bash
# Experimental RISC-V V kernel (single-package directive Phase G, §10.5,
# §16): correctness, isolation and selection only, no timings.
#
# The leaf uses stable naked assembly and a local assembler ISA option, so
# RVV compiles with the repository's pinned stable Rust toolchain.
#
# 1. Lints `allocatbelt` for riscv64 with the feature.
# 2. Builds its lib, `experimental_isa` and `platform` tests for riscv64
#    with the feature and checks that V instructions appear only in the
#    kernel (`arch::rvv::aged_pages_rvv_body`): V is not enabled for the
#    rest of the binary, which must run on the RV64GC baseline.
# 3. Runs them under qemu-user with V at VLEN 128, 256 (the `max` default)
#    and 1024: a test-only override exercises the direct kernel ABI, while
#    dispatch requires the current-thread permission query to succeed. Then
#    without V, if the cross C library permits it, `Prefer` keeps the baseline.
#    That run is skipped when the cross C library itself needs V (Ubuntu
#    26.04 builds its riscv64 glibc for RVA23), which qemu reports as SIGILL
#    before any test.
#
# Needs qemu-user, riscv64-linux-gnu-gcc and its sysroot, llvm-objdump,
# jq, and Rust 1.99.0 with the riscv64gc-unknown-linux-gnu target.
set -euo pipefail

cd "$(dirname "$0")/.."
toolchain="${RVV_TOOLCHAIN:-1.99.0}"
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
  # run <expected kernel set> <cpu model> <test direct leaf> <require query>
  local expect="$1" cpu="$2" direct="$3" require="$4"
  local q=("${qemu[@]}" -cpu "$2") test_env=()
  [[ "${direct}" == yes ]] && test_env+=(ALLOCATBELT_RVV_DIRECT_TEST=1)
  [[ "${require}" == yes ]] && test_env+=(ALLOCATBELT_REQUIRE_VECTOR_CONTROL=1)
  echo "-- ${cpu}: expect ${expect}"
  # The direct override is limited to this test binary and CPU model. When
  # GET_CONTROL works and reports ON, the saved-pointer OFF/ON test must run.
  env "${test_env[@]}" "${q[@]}" "$(pick allocatbelt)" -q arch:: |
    grep -E '^test result'
  env "${test_env[@]}" "ALLOCATBELT_EXPECT_KERNEL=${expect}" "${q[@]}" \
    "$(pick experimental_isa)" --nocapture 2>&1 |
    grep -E '^(kernel_set|experimental_isa):' | sort -u
  env "${test_env[@]}" "ALLOCATBELT_EXPECT_KERNEL=${expect}" "${q[@]}" \
    "$(pick experimental_isa)" -q |
    grep -E '^test result'
  "${q[@]}" "$(pick platform)" -q | grep -E '^test result'
}

echo "== probe current-thread V permission under qemu-user"
probe_dir=$(mktemp -d)
trap 'rm -rf "${probe_dir}"' EXIT
cat > "${probe_dir}/permission.c" <<'EOF'
#include <errno.h>
#include <stdio.h>
#include <sys/prctl.h>

#define PR_RISCV_V_GET_CONTROL 70
#define PR_RISCV_V_VSTATE_CTRL_CUR_MASK 0x3
#define PR_RISCV_V_VSTATE_CTRL_ON 2

int main(void) {
  long control = prctl(PR_RISCV_V_GET_CONTROL, 0, 0, 0, 0);
  if (control < 0) {
    puts("error");
  } else if ((control & PR_RISCV_V_VSTATE_CTRL_CUR_MASK) ==
             PR_RISCV_V_VSTATE_CTRL_ON) {
    puts("on");
  } else {
    puts("off");
  }
  return 0;
}
EOF
riscv64-linux-gnu-gcc "${probe_dir}/permission.c" -o "${probe_dir}/permission"

echo "== under qemu-user"
for vlen in 128 256 1024; do
  cpu="max,vlen=${vlen}"
  permission=$("${qemu[@]}" -cpu "${cpu}" "${probe_dir}/permission")
  case "${permission}" in
    on) expected=Rvv; direct=yes; require=yes ;;
    off) expected=Baseline; direct=no; require=no ;;
    error) expected=Baseline; direct=yes; require=no ;;
    *) echo "FAIL: unexpected vector-permission probe result: ${permission}" >&2; exit 1 ;;
  esac
  echo "-- ${cpu}: current-thread permission ${permission}"
  run "${expected}" "${cpu}" "${direct}" "${require}"
done
status=0
"${qemu[@]}" -cpu max,v=false "$(pick platform)" --list >/dev/null 2>&1 || status=$?
if [[ ${status} -eq 132 ]]; then
  echo "-- max,v=false: skipped, the cross C library needs V (SIGILL before any test)"
elif [[ ${status} -ne 0 ]]; then
  echo "FAIL: max,v=false: exit ${status}" >&2
  exit 1
else
  run Baseline max,v=false no no
fi
echo "ok: experimental RVV kernel"
