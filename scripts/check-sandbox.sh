#!/usr/bin/env bash
# Sandbox and virtualization qualification (single-package directive
# Phase E, §8, §17): behaviour and fallback semantics, no timings.
#
# 1. Builds the tests of `allocatbelt` (default features + `io-uring,runtime`) as
#    static musl binaries and runs every test binary in a hardened Docker
#    container: user 10001, `--cap-drop ALL`, read-only root, no network,
#    `no-new-privileges`, a bounded writable temporary filesystem and
#    Docker's default seccomp profile (which denies
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
# Process tests also need static Bash and BusyBox (cat, head, sleep and yes).
# Set ALLOCATBELT_SANDBOX_BASH and ALLOCATBELT_SANDBOX_BUSYBOX to select
# explicit executable paths. The fixture image contains only those tools.
# Needs docker, qemu-user, readelf and the
# `$(uname -m)-unknown-linux-musl` Rust target. On a GitHub-hosted runner,
# which is itself a VM, (1) and (2) are Docker in a VM.
set -euo pipefail

cd "$(dirname "$0")/.."
arch="$(uname -m)"
target="${arch}-unknown-linux-musl"
bash_fixture="${ALLOCATBELT_SANDBOX_BASH:-/bin/bash-static}"
busybox_fixture="${ALLOCATBELT_SANDBOX_BUSYBOX:-/bin/busybox}"
build_work="$(mktemp -d)"
chmod 0700 "${build_work}"
trap 'rm -rf -- "${build_work}"' EXIT
freeze_fixture() {
  local path="$1" destination="$2"
  [[ -f "${path}" && -x "${path}" ]] ||
    { echo "FAIL: missing executable static fixture: ${path}" >&2; exit 1; }
  install -m 0555 "${path}" "${destination}"
}
freeze_fixture "${bash_fixture}" "${build_work}/bash"
freeze_fixture "${busybox_fixture}" "${build_work}/busybox"
bash_fixture="${build_work}/bash"
busybox_fixture="${build_work}/busybox"

static_fixture() {
  local path="$1" header machine
  [[ -f "${path}" && -x "${path}" ]] ||
    { echo "FAIL: missing executable static fixture: ${path}" >&2; exit 1; }
  header="$(LC_ALL=C readelf -h -- "${path}")" ||
    { echo "FAIL: fixture is not an ELF executable: ${path}" >&2; exit 1; }
  case "${arch}" in
    x86_64) machine='Advanced Micro Devices X86-64' ;;
    aarch64) machine='AArch64' ;;
    riscv64) machine='RISC-V' ;;
    *) echo "FAIL: unsupported fixture architecture: ${arch}" >&2; exit 1 ;;
  esac
  if ! grep -Eq 'Class:[[:space:]]+ELF64$' <<<"${header}" ||
    ! grep -Eq 'Data:.*little endian$' <<<"${header}" ||
    ! grep -Eq "Machine:[[:space:]]+${machine}$" <<<"${header}"; then
    echo "FAIL: fixture must be a native 64-bit little-endian ELF: ${path}" >&2
    exit 1
  fi
  local segments dynamic
  segments="$(LC_ALL=C readelf -l -- "${path}")" || exit 1
  dynamic="$(LC_ALL=C readelf -d -- "${path}")" || exit 1
  if grep -Eq '(^|[[:space:]])INTERP([[:space:]]|$)' <<<"${segments}" ||
    grep -q '(NEEDED)' <<<"${dynamic}"; then
    echo "FAIL: fixture must be statically linked: ${path}" >&2
    exit 1
  fi
}
static_fixture "${bash_fixture}"
static_fixture "${busybox_fixture}"
# Paths and host metadata do not enter the identity. The version fixes the
# layout, permissions and canonical tar metadata used below.
fixture_id="$(
  {
    printf '%s\n' 'allocatbelt-sandbox-static-fixtures-v1' \
      'bin/bash' 'bin/busybox' 'bin/sh->bash' \
      'bin/cat->busybox' 'bin/head->busybox' 'bin/sleep->busybox' 'bin/yes->busybox'
    sha256sum -- "${bash_fixture}" "${busybox_fixture}" | awk '{print $1}'
  } | sha256sum | awk '{print $1}'
)"
bash_hash="$(sha256sum -- "${bash_fixture}" | awk '{print $1}')"
busybox_hash="$(sha256sum -- "${busybox_fixture}" | awk '{print $1}')"
image="allocatbelt-sandbox-fixtures:${fixture_id}"

echo "== building static test binaries (${target})"
# Test binaries only: `cargo test` also builds the examples, elsewhere.
if ! cargo test --release --locked -p allocatbelt --features io-uring,runtime \
  --target "${target}" --no-run --message-format=json >"${build_work}/artifacts.jsonl"; then
  cat "${build_work}/artifacts.jsonl" >&2
  echo "FAIL: static test build failed" >&2
  exit 1
fi
if ! jq -r 'select(.reason == "compiler-artifact" and .executable != null and .profile.test
  and .target.name != "allocatbelt-bench") | .executable' \
  "${build_work}/artifacts.jsonl" >"${build_work}/binaries"; then
  echo "FAIL: could not parse static test artifacts" >&2
  exit 1
fi
mapfile -t bins <"${build_work}/binaries"
[[ ${#bins[@]} -ge 9 ]] || { echo "FAIL: found only ${#bins[@]} test binaries" >&2; exit 1; }
dir="$(dirname "${bins[0]}")"
sandbox=""
for b in "${bins[@]}"; do
  [[ "$(basename "$b")" == sandbox-* ]] && sandbox="$(basename "$b")"
done
[[ -n "${sandbox}" ]] || { echo "FAIL: no sandbox test binary" >&2; exit 1; }

# Only static process-test fixtures are added; the tests remain mounted
# read-only and every container keeps the same hardening restrictions.
if ! docker image inspect "${image}" >/dev/null 2>&1; then
  fixture_root="${build_work}/fixture"
  install -d -m 0755 "${fixture_root}/bin"
  install -m 0555 "${bash_fixture}" "${fixture_root}/bin/bash"
  install -m 0555 "${busybox_fixture}" "${fixture_root}/bin/busybox"
  ln -s bash "${fixture_root}/bin/sh"
  for applet in cat head sleep yes; do
    ln -s busybox "${fixture_root}/bin/${applet}"
  done
  chmod 0755 "${fixture_root}"
  tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner \
    -C "${fixture_root}" -cf - . | docker import - "${image}" >/dev/null
fi
image_id="$(docker image inspect --format '{{.Id}}' "${image}")"
[[ "${image_id}" =~ ^sha256:[0-9a-f]{64}$ ]] ||
  { echo 'FAIL: fixture image has no immutable Docker identity' >&2; exit 1; }
echo "== static process fixtures (${image})"
hardened=(
  --rm --network none --user 10001:10001 --cap-drop ALL --read-only
  --tmpfs '/tmp:rw,nosuid,nodev,size=64m,mode=1777'
  --security-opt no-new-privileges:true -v "${dir}:/t:ro"
)
fixture_hashes="$(docker run "${hardened[@]}" "${image_id}" \
  /bin/busybox sha256sum /bin/bash /bin/busybox)"
expected_hashes="$(printf '%s  /bin/bash\n%s  /bin/busybox' "${bash_hash}" "${busybox_hash}")"
[[ "${fixture_hashes}" == "${expected_hashes}" ]] ||
  { echo 'FAIL: fixture image executable hashes differ from validated inputs' >&2; exit 1; }

echo "== every test binary in a hardened container"
for b in "${bins[@]}"; do
  name="$(basename "$b")"
  echo "-- ${name}"
  # The sources are not in the container; that check runs outside.
  binary_log="${build_work}/${name}.log"
  status=0
  docker run "${hardened[@]}" "${image_id}" "/t/${name}" --test-threads=1 -q \
    --skip no_hidden_host_probes >"${binary_log}" 2>&1 || status=$?
  if [[ "${status}" -ne 0 ]]; then
    cat "${binary_log}" >&2
    echo "FAIL: ${name} container exited ${status}" >&2
    exit "${status}"
  fi
  grep -E '^test result' "${binary_log}"
done

scenario() {
  # scenario <ALLOCATBELT_SANDBOX> <seccomp profile or ""> <test>
  local env="$1" profile="$2" test="maintenance::$3" opts=()
  [[ -n "${profile}" ]] && opts=(--security-opt "seccomp=scripts/seccomp/${profile}.json")
  echo "-- ${test} (${env}${profile:+, seccomp ${profile}})"
  docker run "${hardened[@]}" "${opts[@]}" -e "ALLOCATBELT_SANDBOX=${env}" "${image_id}" \
    "/t/${sandbox}" --exact "${test}" --nocapture --test-threads=1 2>&1 |
    grep -E '^(test |io_uring:|scheduler:|maintenance:)' || true
  # Require the exact test to run; a misspelled filter otherwise succeeds
  # with zero tests, even when the container's exit status is zero.
  docker run "${hardened[@]}" "${opts[@]}" -e "ALLOCATBELT_SANDBOX=${env}" "${image_id}" \
    "/t/${sandbox}" --exact "${test}" --test-threads=1 -q |
    grep -E '^test result: ok\. 1 passed; 0 failed; 0 ignored;' >/dev/null
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
