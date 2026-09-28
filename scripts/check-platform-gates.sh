#!/usr/bin/env bash
# Checks the compile-time platform contract (docs/platform.md): supported
# targets build, and every other target, and x86_64 below x86-64-v3, fails
# with the gate's own message. `cargo check` needs only the targets' std
# (`rustup target add ...`), no linker or C cross compiler.
#
#   scripts/check-platform-gates.sh            # all cases
#   GATE_TARGET_DIR=... scripts/...            # reuse a target directory
set -euo pipefail

cd "$(dirname "$0")/.."
target_dir="${GATE_TARGET_DIR:-target/platform-gates}"
failed=0

check() {
  # check <target> <expected: ok | message substring> [RUSTFLAGS]
  local target="$1" expect="$2" log
  log="$(mktemp)"
  local -a env=()
  if [[ $# -ge 3 ]]; then
    env=(RUSTFLAGS="$3")
  fi
  if env "${env[@]}" cargo check --locked --quiet -p allocatbelt \
    --target "${target}" --target-dir "${target_dir}" >"${log}" 2>&1; then
    if [[ "${expect}" == ok ]]; then
      echo "ok: ${target} ${3:-} builds"
    else
      echo "FAIL: ${target} ${3:-} built, expected: ${expect}" >&2
      failed=1
    fi
  elif [[ "${expect}" != ok ]] && grep -qF -- "${expect}" "${log}"; then
    echo "ok: ${target} ${3:-} rejected: ${expect}"
  else
    echo "FAIL: ${target} ${3:-} did not produce: ${expect}" >&2
    cat "${log}" >&2
    failed=1
  fi
  rm -f "${log}"
}

v3='must be built for x86-64-v3 or newer'

# Supported: .cargo/config.toml supplies x86-64-v3 for x86_64.
check x86_64-unknown-linux-gnu ok
check x86_64-unknown-linux-musl ok
check x86_64-unknown-linux-gnu ok '-C target-cpu=x86-64-v4'
check aarch64-unknown-linux-gnu ok
check riscv64gc-unknown-linux-gnu ok

# x86_64 below v3: a RUSTFLAGS without the CPU flag replaces the config.
check x86_64-unknown-linux-gnu "${v3}" ''
check x86_64-unknown-linux-gnu "${v3}" '-C target-cpu=x86-64'
check x86_64-unknown-linux-gnu "${v3}" '-C target-cpu=x86-64-v2'
check x86_64-unknown-linux-musl "${v3}" '-C target-cpu=x86-64-v2'

# Unsupported architectures, ABIs, byte orders and operating systems.
# 32-bit targets stop first at allocatbelt-core's own 64-bit gate.
arch='supports only x86_64 (x86-64-v3 or newer), aarch64 and riscv64'
bits='needs a 64-bit target with 64-bit atomics'
check i686-unknown-linux-gnu "${bits}"
check armv7-unknown-linux-gnueabihf "${bits}"
check x86_64-unknown-linux-gnux32 "${bits}"
check riscv32imac-unknown-none-elf "${bits}"
check wasm32-unknown-unknown "${bits}"
check powerpc64le-unknown-linux-gnu "${arch}"
check loongarch64-unknown-linux-gnu "${arch}"
check s390x-unknown-linux-gnu 'supports only little-endian targets'
check x86_64-unknown-freebsd 'supports only Linux'

exit "${failed}"
