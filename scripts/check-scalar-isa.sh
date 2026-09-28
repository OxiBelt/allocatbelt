#!/usr/bin/env bash
# Scalar ISA check (plan phase 3): the allocator's bit scans must lower to
# single bit-manipulation instructions, not multi-instruction fallbacks.
#
#   x86_64 (x86-64-v3):  trailing_zeros -> tzcnt, count_ones -> popcnt,
#                        leading_zeros -> lzcnt; never bsf/bsr
#   riscv64 + Zbb:       trailing_zeros -> ctz, count_ones -> cpop,
#                        leading_zeros -> clz
#   riscv64 (rv64gc):    none of ctz/cpop/clz, a control showing that the
#                        check tells the two apart
#
# It compiles `allocatbelt-codegen-probes` (out-of-line wrappers around
# `allocatbelt-core`'s helpers) to assembly and looks only at the probe
# bodies, so unrelated scheduling or inlining changes do not break it.
# Needs `rustup target add riscv64gc-unknown-linux-gnu`; no linker or qemu.
set -euo pipefail

cd "$(dirname "$0")/.."
target_dir="${ISA_TARGET_DIR:-target/scalar-isa}"
failed=0

# emit <target> <label> [RUSTFLAGS]: prints the path of the assembly file.
emit() {
  local target="$1" label="$2" dir="${target_dir}/$2"
  local -a env=()
  if [[ $# -ge 3 ]]; then
    env=(RUSTFLAGS="$3")
  fi
  # A fresh build would emit no assembly, so rebuild just the probe crate.
  cargo clean --quiet --release -p allocatbelt-codegen-probes \
    --target "${target}" --target-dir "${dir}" >&2
  env "${env[@]}" cargo rustc --locked --quiet --release \
    -p allocatbelt-codegen-probes --lib --target "${target}" --target-dir "${dir}" \
    -- --emit asm -C codegen-units=1 >&2
  ls "${dir}/${target}/release/deps/allocatbelt_codegen_probes-"*.s
}

# body <asm> <probe>: the instructions of one probe function.
body() {
  [[ -f "$1" ]] || return 0
  awk -v name="$2" '
    /^[^ \t.#][^ \t]*:/ && index($0, name) { inside = 1; next }
    inside && /^\.Lfunc_end/ { exit }
    inside && /^[ \t]+[a-z]/ { print }
  ' "$1"
}

# expect <label> <asm> <probe> <regex> [forbidden regex]
expect() {
  local label="$1" asm="$2" probe="$3" want="$4" deny="${5:-}" code
  code="$(body "${asm}" "${probe}")"
  if [[ -z "${code}" ]]; then
    echo "FAIL: ${label}: ${probe} not found in ${asm}" >&2
    failed=1
  elif ! grep -qE "^[[:space:]]+(${want})[[:space:]]" <<<"${code}"; then
    echo "FAIL: ${label}: ${probe} has no ${want}:" >&2
    echo "${code}" >&2
    failed=1
  elif [[ -n "${deny}" ]] && grep -qE "^[[:space:]]+(${deny})[[:space:]]" <<<"${code}"; then
    echo "FAIL: ${label}: ${probe} still uses ${deny}:" >&2
    echo "${code}" >&2
    failed=1
  else
    echo "ok: ${label}: ${probe} uses ${want}"
  fi
}

# reject <label> <asm> <probe> <regex>: the control must not use it.
reject() {
  local label="$1" asm="$2" probe="$3" deny="$4" code
  code="$(body "${asm}" "${probe}")"
  if [[ -z "${code}" ]]; then
    echo "FAIL: ${label}: ${probe} not found in ${asm}" >&2
    failed=1
  elif grep -qE "^[[:space:]]+(${deny})[[:space:]]" <<<"${code}"; then
    echo "FAIL: ${label}: ${probe} uses ${deny} without Zbb" >&2
    failed=1
  else
    echo "ok: ${label}: ${probe} has no Zbb instruction (multi-instruction fallback)"
  fi
}

# x86-64-v3 comes from .cargo/config.toml; clear RUSTFLAGS so it applies.
x86="$(env -u RUSTFLAGS bash -c "$(declare -f emit); target_dir='${target_dir}'; emit x86_64-unknown-linux-gnu x86-64-v3")"
expect x86-64-v3 "${x86}" probe_find_run 'tzcnt[lq]?' 'bsf[lq]?'
expect x86-64-v3 "${x86}" probe_pick_bit 'tzcnt[lq]?' 'bsf[lq]?'
expect x86-64-v3 "${x86}" probe_count_ones 'popcnt[lq]?'
expect x86-64-v3 "${x86}" probe_class_of 'lzcnt[lq]?' 'bsr[lq]?'

zbb="$(emit riscv64gc-unknown-linux-gnu rv64gc-zbb '-C target-feature=+zbb')"
expect rv64gc+zbb "${zbb}" probe_find_run 'ctzw?'
expect rv64gc+zbb "${zbb}" probe_pick_bit 'ctzw?'
expect rv64gc+zbb "${zbb}" probe_count_ones 'cpopw?'
expect rv64gc+zbb "${zbb}" probe_class_of 'clzw?'

base="$(emit riscv64gc-unknown-linux-gnu rv64gc '')"
for probe in probe_find_run probe_pick_bit probe_count_ones probe_class_of; do
  reject rv64gc "${base}" "${probe}" 'ctzw?|cpopw?|clzw?'
done

exit "${failed}"
