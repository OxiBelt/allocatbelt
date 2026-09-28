#!/usr/bin/env bash
# Sandbox and virtualization qualification (single-package directive
# Phase E, §8, §17): behaviour and fallback semantics, no timings.
#
# 1. Builds the tests of `allocatbelt` (default features + `io-uring`) as
#    static musl binaries and runs every test binary in a hardened Docker
#    container: user 10001, `--cap-drop ALL`, read-only root, no network,
#    `no-new-privileges`, Docker's default seccomp profile (which denies
#    io_uring). Baseline correctness needs no extra privilege.
# 2. Runs the scenarios of `tests/sandbox.rs`, each in its own process,
#    under the seccomp profiles in `scripts/seccomp/`: io_uring denied
#    (`Require` fails, `Prefer` falls back), allowed (`Require` works),
#    killed on use (`Disable` and `Auto` never call it), and
#    `sched_setscheduler` denied (`Require` fails, `Auto` falls back).
# 3. Runs `only_the_visible_isa_is_detected` under qemu-user CPU models
#    that expose less (or more) than the host, as a guest would: only what
#    the process sees is detected.
#
# Needs docker, qemu-user and the `$(uname -m)-unknown-linux-musl` Rust
# target. On a GitHub-hosted runner, which is itself a VM, (1) and (2) are
# Docker in a VM.
set -euo pipefail

cd "$(dirname "$0")/.."
arch="$(uname -m)"
target="${arch}-unknown-linux-musl"
image=allocatbelt-empty

echo "== building static test binaries (${target})"
mapfile -t bins < <(
  cargo test --release --locked -p allocatbelt --features io-uring \
    --target "${target}" --no-run --message-format=json 2>/dev/null |
    jq -r 'select(.reason == "compiler-artifact" and .executable != null
      and .target.name != "allocatbelt-bench") | .executable'
)
[[ ${#bins[@]} -ge 9 ]] || { echo "FAIL: found only ${#bins[@]} test binaries" >&2; exit 1; }
dir="$(dirname "${bins[0]}")"
sandbox=""
for b in "${bins[@]}"; do
  [[ "$(basename "$b")" == sandbox-* ]] && sandbox="$(basename "$b")"
done
[[ -n "${sandbox}" ]] || { echo "FAIL: no sandbox test binary" >&2; exit 1; }

# An empty image: the binaries are static and mounted read-only.
if ! docker image inspect "${image}" >/dev/null 2>&1; then
  tar -cf - --files-from /dev/null | docker import - "${image}" >/dev/null
fi
hardened=(
  --rm --network none --user 10001:10001 --cap-drop ALL --read-only
  --security-opt no-new-privileges:true -v "${dir}:/t:ro"
)

echo "== every test binary in a hardened container"
for b in "${bins[@]}"; do
  name="$(basename "$b")"
  echo "-- ${name}"
  # The sources are not in the container; that check runs outside.
  docker run "${hardened[@]}" "${image}" "/t/${name}" --test-threads=1 -q \
    --skip no_hidden_host_probes | grep -E '^test result'
done

scenario() {
  # scenario <ALLOCATBELT_SANDBOX> <seccomp profile or ""> <test>
  local env="$1" profile="$2" test="$3" opts=()
  [[ -n "${profile}" ]] && opts=(--security-opt "seccomp=scripts/seccomp/${profile}.json")
  echo "-- ${test} (${env}${profile:+, seccomp ${profile}})"
  docker run "${hardened[@]}" "${opts[@]}" -e "ALLOCATBELT_SANDBOX=${env}" "${image}" \
    "/t/${sandbox}" --exact "${test}" --nocapture --test-threads=1 2>&1 |
    grep -E '^(test |io_uring:|scheduler:|maintenance:)' || true
  # grep hides the rest; the verdict is the container's exit status.
  docker run "${hardened[@]}" "${opts[@]}" -e "ALLOCATBELT_SANDBOX=${env}" "${image}" \
    "/t/${sandbox}" --exact "${test}" --test-threads=1 -q >/dev/null
}

echo "== fallback scenarios"
scenario hardened "" hardened_container_needs_no_privilege
scenario hardened "" io_uring_denied_falls_back
scenario no-sched no-sched scheduler_denied_falls_back
scenario io-uring-kill io-uring-kill io_uring_disabled_never_calls_setup
scenario io-uring-kill io-uring-kill io_uring_auto_never_calls_setup
if [[ "$(cat /proc/sys/kernel/io_uring_disabled 2>/dev/null || echo 0)" == 0 ]]; then
  scenario io-uring-allowed io-uring-allowed io_uring_allowed_is_used
else
  echo "-- io_uring_allowed_is_used skipped: kernel.io_uring_disabled is set"
fi

echo "== visible ISA under qemu-user CPU models"
isa() {
  # isa <qemu> <cpu> <expected features>
  echo "-- $1 -cpu $2: $3"
  ALLOCATBELT_SANDBOX=visible-isa ALLOCATBELT_EXPECT_CPU="$3" \
    "$1" -cpu "$2" "${dir}/${sandbox}" --exact only_the_visible_isa_is_detected \
    --nocapture --test-threads=1 2>&1 | grep -E '^(cpu_features|test )'
  ALLOCATBELT_SANDBOX=visible-isa ALLOCATBELT_EXPECT_CPU="$3" \
    "$1" -cpu "$2" "${dir}/${sandbox}" --exact only_the_visible_isa_is_detected \
    --test-threads=1 -q >/dev/null
}
case "${arch}" in
  x86_64)
    # Haswell (without TSX, which TCG lacks) is x86-64-v3 without AVX-512, whatever the host has.
    isa qemu-x86_64 Haswell-noTSX "+x86-64-v3,+avx2,-avx512f,-avx512vpopcntdq"
    ;;
  aarch64)
    isa qemu-aarch64 cortex-a72 "+asimd,-sve,-sve2"
    isa qemu-aarch64 neoverse-v1 "+asimd,+sve,-sve2"
    isa qemu-aarch64 neoverse-n2 "+asimd,+sve,+sve2"
    ;;
esac
echo "ok: sandbox and virtualization checks"
