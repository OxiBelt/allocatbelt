#!/usr/bin/env bash
# Run one fresh bounded/Tokio pair for a single application comparison cell.
# This harness is preparation only; keep raw timing evidence outside the source checkout.
set -euo pipefail
export LC_ALL=C
while IFS= read -r git_environment_name; do
  case "$git_environment_name" in GIT_*) unset "$git_environment_name" ;; esac
done < <(compgen -e)
export GIT_CONFIG_NOSYSTEM=1
export GIT_CONFIG_SYSTEM=/dev/null
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_NO_REPLACE_OBJECTS=1
export GIT_ATTR_NOSYSTEM=1
export GIT_TERMINAL_PROMPT=0
export GIT_PAGER=cat
export PAGER=cat
export GIT_OPTIONAL_LOCKS=0
export GIT_CONFIG_COUNT=8
export GIT_CONFIG_KEY_0=core.fsmonitor GIT_CONFIG_VALUE_0=false
export GIT_CONFIG_KEY_1=core.hooksPath GIT_CONFIG_VALUE_1=/dev/null
export GIT_CONFIG_KEY_2=core.attributesFile GIT_CONFIG_VALUE_2=/dev/null
export GIT_CONFIG_KEY_3=core.excludesFile GIT_CONFIG_VALUE_3=/dev/null
export GIT_CONFIG_KEY_4=core.pager GIT_CONFIG_VALUE_4=cat
export GIT_CONFIG_KEY_5=gpg.program GIT_CONFIG_VALUE_5=/usr/bin/gpg
export GIT_CONFIG_KEY_6=gpg.format GIT_CONFIG_VALUE_6=openpgp
export GIT_CONFIG_KEY_7=protocol.ext.allow GIT_CONFIG_VALUE_7=never
qualification_runtime_readback_supported=0
external_pressure_driver_supported=0
functional_only_mode=0
execution_scope=qualification
runtime_readback_enabled=$qualification_runtime_readback_supported
functional_source_v4_mode=0
functional_tmp_root_path=
functional_tmp_context_json=
functional_source_manifest_file_path=
functional_source_manifest_file_sha256_before=not_applicable
functional_source_manifest_file_sha256_after=not_applicable
functional_source_manifest_semantic_sha256=not_applicable
functional_source_signer_fingerprint=not_applicable
functional_file_size_limit_blocks=16384
if [[ "${1:-}" == "--functional-only" ]]; then
  functional_only_mode=1
  execution_scope=functional_only
  runtime_readback_enabled=1
  shift
fi

usage() {
  echo "usage: $0 [--functional-only] BINARY ALLOCATOR WORKLOAD MODE RATE_OR_DASH CPU_SET RUN_ID OUTPUT_ROOT [ARRIVALS TRACE_S DRAIN_S SHUTDOWN_S PROCESS_S ORACLE_FILE ORACLE_SHA256 PROFILE PAIR_KIND [BASELINE_BINARY BASELINE_ALLOCATOR BASELINE_ORACLE BASELINE_ORACLE_SHA256] [--runtime-bindings FILE --runtime-bindings-sha256 SHA --runtime-validator FILE --runtime-validator-sha256 SHA --fixed-global-control-baseline BYTES [--functional-overlay FILE --functional-overlay-sha256 SHA]]]" >&2
  echo "  open_loop requires a precomputed oracle file and its SHA-256 digest." >&2
  echo "  --functional-only runs a bounded, non-qualifying fixed-policy receipt check." >&2
}

stable_sha256() {
  local path=$1 maximum=${2:-536870912}
  python3 -B - "$path" "$maximum" <<'PY'
import hashlib
import os
import stat
import sys

path, maximum_text = sys.argv[1:]
if not maximum_text.isdecimal():
    raise SystemExit(2)
maximum = int(maximum_text)
if not 0 <= maximum <= 512 * 1024 * 1024:
    raise SystemExit(2)
flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
try:
    descriptor = os.open(path, flags)
except OSError as error:
    print(f"cannot open stable hash input: {error}", file=sys.stderr)
    raise SystemExit(2)
digest = hashlib.sha256()
count = 0
try:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
        raise SystemExit("hash input is not a bounded regular file")
    while True:
        block = os.read(descriptor, min(1024 * 1024, maximum + 1 - count))
        if not block:
            break
        count += len(block)
        if count > maximum:
            raise SystemExit("hash input exceeded its finite byte ceiling")
        digest.update(block)
    after = os.fstat(descriptor)
    current = os.stat(path, follow_symlinks=False)
    fingerprint = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
    if (fingerprint(before) != fingerprint(after) or count != before.st_size
        or not stat.S_ISREG(current.st_mode) or fingerprint(before) != fingerprint(current)):
        raise SystemExit("hash input changed while streaming")
finally:
    os.close(descriptor)
print(digest.hexdigest())
PY
}

if [[ $# -lt 8 || $# -gt 35 ]]; then usage; exit 2; fi
binary_arg=$1
allocator=$2
workload=$3
mode=$4
rate=$5
cpu_set=$6
run_id=$7
output_root=$8
arrivals=${9:-5000}
trace_deadline=${10:-300}
drain_deadline=${11:-300}
shutdown_deadline=${12:-60}
process_deadline=${13:-1200}
oracle_file_arg=${14:-}
oracle_digest_expected=${15:-}
profile=${16:-steady}
pair_kind=${17:-matched}
baseline_binary_arg=${18:-}
baseline_allocator=${19:-}
baseline_oracle_arg=${20:-}
baseline_oracle_digest_expected=${21:-}
runtime_bindings_arg=
runtime_bindings_sha_expected=
runtime_validator_arg=
runtime_validator_sha_expected=
fixed_global_control_baseline_arg=
functional_overlay_arg=
functional_overlay_sha_expected=
functional_overlay_file=
functional_overlay_sha256_before=not_applicable
functional_overlay_sha256_after=not_applicable
source_inventory_schema=allocatbelt.application-source-inventory.v1
source_inventory_module_sha256_expected=09557087a64e83bc81e4116f8e8f6b59e42a59beb500108e57d66942bd05f950
source_inventory_module_path=
source_inventory_module_sha256_before=unavailable
source_inventory_module_sha256_after=unavailable
pair_runner_path=
pair_runner_sha256_before=unavailable
pair_runner_sha256_after=unavailable
if (( $# > 21 )); then
  if (( functional_only_mode == 1 )); then
    [[ $# -eq 35 && "${32}" == "--functional-overlay" && "${34}" == "--functional-overlay-sha256" ]] || { usage; exit 2; }
    functional_overlay_arg=${33}
    functional_overlay_sha_expected=${35}
    [[ "$functional_overlay_sha_expected" =~ ^[0-9a-f]{64}$ ]] || { echo "functional overlay manifest hash must be SHA-256" >&2; exit 2; }
  else
    [[ $# -eq 31 ]] || { usage; exit 2; }
  fi
  [[ "${22}" == "--runtime-bindings" && "${24}" == "--runtime-bindings-sha256" && "${26}" == "--runtime-validator" && "${28}" == "--runtime-validator-sha256" && "${30}" == "--fixed-global-control-baseline" ]] || { usage; exit 2; }
  runtime_bindings_arg=${23}
  runtime_bindings_sha_expected=${25}
  runtime_validator_arg=${27}
  runtime_validator_sha_expected=${29}
  fixed_global_control_baseline_arg=${31}
  [[ "$runtime_bindings_sha_expected" =~ ^[0-9a-f]{64}$ && "$runtime_validator_sha_expected" =~ ^[0-9a-f]{64}$ ]] || { echo "runtime readback artifact hashes must be SHA-256 values" >&2; exit 2; }
  [[ "$fixed_global_control_baseline_arg" =~ ^[1-9][0-9]*$ && ${#fixed_global_control_baseline_arg} -le 20 ]] || { echo "fixed global Control baseline must be a positive numeric input" >&2; exit 2; }
fi

for deadline in "$trace_deadline" "$drain_deadline" "$shutdown_deadline" "$process_deadline"; do
  [[ "$deadline" =~ ^[1-9][0-9]*$ && ${#deadline} -le 4 ]] || { echo "deadlines must be positive finite integer seconds" >&2; exit 2; }
done
(( trace_deadline <= 3600 && drain_deadline <= 3600 && shutdown_deadline <= 600 && process_deadline <= 7200 )) || { echo "deadline exceeds its finite safety bound" >&2; exit 2; }

case "$allocator" in allocatbelt|mimalloc-secure|mimalloc-standard|system) ;; *) usage; exit 2 ;; esac
case "$workload" in cpu|memory|http|disk|mixed) ;; *) usage; exit 2 ;; esac
case "$mode" in capacity|open_loop) ;; *) usage; exit 2 ;; esac
case "$profile" in steady|mixed|burst|oversubscribed|safety_overload) ;; *) echo "unknown profile: $profile" >&2; exit 2 ;; esac
case "$pair_kind" in matched|aa-bounded|aa-tokio|allocator-match|pressure-matched|pressure-allocator-match) ;; *) echo "PAIR_KIND is not a frozen matched comparison family" >&2; exit 2 ;; esac
if [[ "$pair_kind" == pressure-matched || "$pair_kind" == pressure-allocator-match ]]; then
  (( external_pressure_driver_supported == 1 )) || { echo "external-pressure timing is hard-disabled until the pinned feedback driver and runtime readbacks are implemented" >&2; exit 2; }
fi
if [[ "$pair_kind" == allocator-match || "$pair_kind" == pressure-allocator-match ]]; then
  case "$baseline_allocator" in mimalloc-secure|mimalloc-standard|system) ;; *) echo "allocator-match requires a frozen baseline allocator" >&2; exit 2 ;; esac
  [[ "$allocator" == allocatbelt && "$baseline_allocator" != "$allocator" && -n "$baseline_binary_arg" ]] || { echo "allocator-match requires allocatbelt candidate and a distinct baseline binary" >&2; exit 2; }
else
  [[ -z "$baseline_binary_arg" && -z "$baseline_allocator" && -z "$baseline_oracle_arg" && -z "$baseline_oracle_digest_expected" ]] || { echo "baseline arguments require allocator-match" >&2; exit 2; }
fi
if [[ "$workload" == mixed && "$profile" == steady ]]; then
  echo "mixed workload requires mixed, burst, oversubscribed, or safety_overload profile" >&2
  exit 2
fi
if [[ "$profile" == mixed && "$workload" != mixed ]]; then
  echo "mixed profile requires mixed workload" >&2
  exit 2
fi
if [[ "$mode" == capacity && "$profile" != steady && "$profile" != mixed && "$profile" != burst && "$profile" != oversubscribed ]]; then
  echo "capacity mode supports steady, mixed, burst, or oversubscribed profiles" >&2
  exit 2
fi
phase_trace=$trace_deadline
phase_trace_deadline=$trace_deadline
if [[ "$mode" == capacity ]]; then
  phase_trace=30
  # The producer observes the horizon, then records its completion. Bound
  # coordinator/scheduling overshoot separately from the throughput horizon.
  phase_trace_deadline=31
fi
shutdown_units=1
case "$workload" in
  http) shutdown_units=3 ;;
  disk) shutdown_units=2 ;;
  mixed) shutdown_units=4 ;;
esac
if [[ "$mode" == capacity ]]; then
  [[ "$rate" == - ]] || { echo "capacity mode requires RATE_OR_DASH=-" >&2; exit 2; }
else
  [[ "$rate" =~ ^[1-9][0-9]*$ && ${#rate} -le 10 ]] && (( rate <= 1000000000 )) || { echo "open_loop rate must be in 1..=1000000000" >&2; exit 2; }
  [[ "$arrivals" =~ ^[1-9][0-9]*$ && ${#arrivals} -le 7 ]] && (( arrivals <= 1000000 )) || { echo "ARRIVALS must be in 1..=1000000" >&2; exit 2; }
  if [[ "$profile" == burst ]]; then
    (( rate <= 250000000 )) || { echo "burst average rate must not exceed 250000000 arrivals per second" >&2; exit 2; }
    phase_trace=$(( (arrivals + rate - 1) / rate ))
  else
    phase_trace=$(( (arrivals + rate - 1) / rate ))
  fi
  (( phase_trace <= trace_deadline )) || { echo "open-loop arrival plan exceeds its configured finite trace deadline" >&2; exit 2; }
  phase_trace_deadline=$trace_deadline
fi
required_process=$((120 + phase_trace_deadline + drain_deadline + shutdown_deadline * shutdown_units))
(( process_deadline >= required_process )) || { echo "process deadline must cover setup, trace, drain, and every shutdown phase" >&2; exit 2; }
if [[ "$mode" == capacity && "$arrivals" != 5000 ]]; then
  echo "capacity mode does not accept ARRIVALS" >&2
  exit 2
fi
if [[ "$mode" == open_loop ]]; then
  [[ -n "$oracle_file_arg" && "$oracle_digest_expected" =~ ^[0-9a-f]{64}$ ]] || {
    echo "open_loop requires ORACLE_FILE and its 64-character ORACLE_SHA256" >&2
    exit 2
  }
  if [[ "$pair_kind" == allocator-match || "$pair_kind" == pressure-allocator-match ]]; then
    [[ -n "$baseline_oracle_arg" && "$baseline_oracle_digest_expected" =~ ^[0-9a-f]{64}$ ]] || { echo "allocator-match open_loop requires its baseline oracle and digest" >&2; exit 2; }
  fi
elif [[ -n "$oracle_file_arg" || -n "$oracle_digest_expected" ]]; then
  echo "capacity mode does not accept an open-loop oracle" >&2
  exit 2
elif [[ -n "$baseline_oracle_arg" || -n "$baseline_oracle_digest_expected" ]]; then
  echo "capacity mode does not accept a baseline oracle" >&2
  exit 2
fi
[[ "$run_id" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "RUN_ID has unsupported characters" >&2; exit 2; }
pair_suffix=${run_id##*[!0-9]}
[[ -n "$pair_suffix" && ${#pair_suffix} -le 3 ]] || { echo "RUN_ID must end in a pair ordinal from 1 through 36" >&2; exit 2; }
pair_ordinal=$((10#$pair_suffix))
(( pair_ordinal >= 1 && pair_ordinal <= 36 )) || { echo "pair ordinal must be from 1 through 36" >&2; exit 2; }

if (( functional_only_mode == 1 )); then
  [[ $# -eq 35 && -n "$runtime_bindings_arg" && -n "$runtime_validator_arg" && -n "$functional_overlay_arg" ]] || { echo "functional-only mode requires frozen runtime bindings, validator, and overlay manifest" >&2; exit 2; }
  if [[ "$mode" == open_loop ]]; then
    [[ "$arrivals" =~ ^[1-9][0-9]*$ ]] && (( arrivals <= 1000 )) || { echo "functional-only open-loop arrivals must be in 1..=1000" >&2; exit 2; }
    (( rate <= 1000 )) || { echo "functional-only average rate must be in 1..=1000 arrivals per second" >&2; exit 2; }
  else
    [[ "$rate" == "-" && "$arrivals" == 5000 && "$trace_deadline" == 30 ]] || {
      echo "functional-only capacity preserves the exact 30-second horizon and fixed 5000 sentinel" >&2; exit 2;
    }
  fi
  (( trace_deadline <= 30 && drain_deadline <= 30 && shutdown_deadline <= 15 && process_deadline <= 300 )) || { echo "functional-only deadlines exceed their fixed finite limits" >&2; exit 2; }
  (( pair_ordinal <= 36 )) || { echo "functional-only pair ordinal exceeds its finite bound" >&2; exit 2; }
  [[ "$profile" != safety_overload ]] || { echo "functional-only mode does not allow safety_overload" >&2; exit 2; }
  case "$pair_kind" in matched|aa-bounded|aa-tokio|allocator-match) ;; *) echo "functional-only mode accepts fixed-policy matched, A/A, or allocator-pair kinds only" >&2; exit 2 ;; esac
  ulimit -Sf "$functional_file_size_limit_blocks" || { echo "cannot set the exact functional soft file-size limit" >&2; exit 2; }
  ulimit -Hf "$functional_file_size_limit_blocks" || { echo "cannot set the exact functional hard file-size limit" >&2; exit 2; }
  [[ "$(ulimit -Hf)" == "$functional_file_size_limit_blocks" && "$(ulimit -Sf)" == "$functional_file_size_limit_blocks" ]] || {
    echo "functional file-size soft/hard limits differ from the exact 16 MiB bound" >&2; exit 2;
  }
fi

for command in taskset timeout awk rustc uname python3 cmp realpath; do
  command -v "$command" >/dev/null || { echo "missing required command: $command" >&2; exit 2; }
done
[[ -x /usr/bin/time ]] || { echo "GNU /usr/bin/time is required" >&2; exit 2; }
if (( functional_only_mode == 0 && qualification_runtime_readback_supported != 1 )); then
  echo "qualification timing is hard-disabled until the binary provides verified runtime-domain, policy, and ceiling readback" >&2
  exit 2
fi

if [[ "$mode" == open_loop ]]; then
  oracle_file=$(realpath "$oracle_file_arg") || exit 2
  [[ -f "$oracle_file" ]] || { echo "oracle file is missing: $oracle_file" >&2; exit 2; }
  oracle_digest_actual=$(stable_sha256 "$oracle_file" 16777216) || exit 2
  [[ "$oracle_digest_actual" == "$oracle_digest_expected" ]] || { echo "oracle SHA-256 differs from its manifest value" >&2; exit 2; }
  baseline_oracle_file=
  baseline_oracle_digest_actual=
  if [[ "$pair_kind" == allocator-match || "$pair_kind" == pressure-allocator-match ]]; then
    baseline_oracle_file=$(realpath "$baseline_oracle_arg") || exit 2
    [[ -f "$baseline_oracle_file" ]] || { echo "baseline oracle file is missing" >&2; exit 2; }
    baseline_oracle_digest_actual=$(stable_sha256 "$baseline_oracle_file" 16777216) || exit 2
    [[ "$baseline_oracle_digest_actual" == "$baseline_oracle_digest_expected" ]] || { echo "baseline oracle SHA-256 differs from its manifest value" >&2; exit 2; }
  fi
else
  oracle_file=
  oracle_digest_actual=
  baseline_oracle_file=
  baseline_oracle_digest_actual=
fi

repo_root=$(pwd -P)
while [[ "$repo_root" != / && ! -e "$repo_root/.git" ]]; do
  repo_root=${repo_root%/*}
  [[ -n "$repo_root" ]] || repo_root=/
done
[[ -e "$repo_root/.git" && ! -L "$repo_root/.git" && -f "$repo_root/Cargo.toml" ]] || {
  echo "cannot locate a nonsymlink Git workspace root from the current directory" >&2
  exit 2
}
pair_runner_path=$(realpath "$0") || exit 2
source_inventory_module_path="${pair_runner_path%/*}/application-source-inventory.py"
source_inventory_module_sha256_before=$source_inventory_module_sha256_expected
pair_runner_sha256_before=$(stable_sha256 "$pair_runner_path" 16777216) || exit 2
binary=$(realpath "$binary_arg") || exit 2
[[ -x "$binary" ]] || { echo "binary is not executable: $binary" >&2; exit 2; }
baseline_binary=
baseline_binary_digest=
if [[ "$pair_kind" == allocator-match || "$pair_kind" == pressure-allocator-match ]]; then
  baseline_binary=$(realpath "$baseline_binary_arg") || exit 2
  [[ -x "$baseline_binary" ]] || { echo "baseline binary is not executable: $baseline_binary" >&2; exit 2; }
  baseline_binary_digest=$(stable_sha256 "$baseline_binary") || exit 2
fi
output_root=$(realpath -m "$output_root") || exit 2
case "$output_root/" in
  "$repo_root/"*) echo "refusing to place raw benchmark evidence inside the source checkout" >&2; exit 2 ;;
esac
mkdir -p -- "$output_root"
cell_dir="$output_root/$run_id"
mkdir -- "$cell_dir" || { echo "run directory already exists: $cell_dir" >&2; exit 2; }

# Hash the tracked/untracked source paths from the checkout root, independent
# of the caller's working directory.
cd "$repo_root"

source_hash() {
  local source_identity digest head
  source_identity=$(python3 - "$source_inventory_module_path" "$source_inventory_module_sha256_expected" "$repo_root" <<'PY'
import hashlib
import os
import stat
import sys
import types
from pathlib import Path

path, expected_sha256, root = sys.argv[1:]
flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
try:
    fd = os.open(path, flags)
except OSError as error:
    print(f"cannot open shared source inventory module: {error}", file=sys.stderr)
    raise SystemExit(2)
try:
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or before.st_size > 16 * 1024 * 1024:
        raise SystemExit("shared source inventory module is not a bounded regular file")
    chunks = []
    count = 0
    while True:
        block = os.read(fd, min(65536, 16 * 1024 * 1024 + 1 - count))
        if not block:
            break
        count += len(block)
        if count > 16 * 1024 * 1024:
            raise SystemExit("shared source inventory module exceeds its finite size bound")
        chunks.append(block)
    after = os.fstat(fd)
    current = os.stat(path, follow_symlinks=False)
    fingerprint = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
    raw = b"".join(chunks)
    if (fingerprint(before) != fingerprint(after) or count != before.st_size
        or not stat.S_ISREG(current.st_mode) or fingerprint(before) != fingerprint(current)):
        raise SystemExit("shared source inventory module changed while being captured")
finally:
    os.close(fd)
if hashlib.sha256(raw).hexdigest() != expected_sha256:
    raise SystemExit("shared source inventory module differs from its frozen SHA-256")
module = types.ModuleType("pinned_application_source_inventory")
module.__file__ = path
module.__package__ = ""
exec(compile(raw, path, "exec", dont_inherit=True), module.__dict__)
tree_digest = module.source_tree_digest(root)
head = module._checked_capture(["git", "rev-parse", "HEAD"], Path(root), 60.0).decode("ascii", errors="strict").strip()
print(tree_digest + "\t" + head)
PY
  ) || return 1
  digest=${source_identity%%$'\t'*}
  head=${source_identity#*$'\t'}
  [[ "$digest" =~ ^[0-9a-f]{64}$ && "$head" =~ ^[0-9a-f]{40}$ ]] || return 1
  printf '%s\t%s\n' "$digest" "$head"
}

verify_runtime_inputs() {
  [[ -n "$runtime_bindings_arg" && -n "$runtime_validator_arg" ]] || { echo "controller-frozen runtime bindings are required" >&2; return 1; }
  local bindings_file validator_file
  bindings_file=$(realpath "$runtime_bindings_arg") || return 1
  validator_file=$(realpath "$runtime_validator_arg") || return 1
  [[ -f "$bindings_file" && ! -L "$runtime_bindings_arg" && -f "$validator_file" && ! -L "$runtime_validator_arg" ]] || { echo "runtime binding or validator artifact is missing or symlinked" >&2; return 1; }
  [[ "$bindings_file" == "$output_root"/* && "$validator_file" == "$repo_root/scripts/application-runtime-readback.py" ]] || { echo "runtime binding or validator path escaped its frozen root" >&2; return 1; }
  [[ $(stable_sha256 "$bindings_file" 131072) == "$runtime_bindings_sha_expected" ]] || { echo "runtime binding manifest hash changed" >&2; return 1; }
  [[ $(stable_sha256 "$validator_file" 16777216) == "$runtime_validator_sha_expected" ]] || { echo "runtime readback validator hash changed" >&2; return 1; }
  python3 - "$bindings_file" "$runtime_bindings_sha_expected" "$validator_file" "$runtime_validator_sha_expected" "$fixed_global_control_baseline_arg" "$repo_root" "$source_digest" "$run_id" "$workload" "$profile" "$mode" "$rate" "$arrivals" <<'PY'
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path

manifest_path, raw_sha, validator_path, validator_sha, baseline_text, source_root, source_sha, run_id, workload, profile, mode, rate_text, arrivals_text = sys.argv[1:]
def fail():
    raise SystemExit(1)
def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail()
        result[key] = value
    return result
def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")
def stable_bytes(path, maximum):
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            fail()
        chunks = []
        size = 0
        while True:
            block = os.read(fd, min(65536, maximum + 1 - size))
            if not block:
                break
            size += len(block)
            if size > maximum:
                fail()
            chunks.append(block)
        after = os.fstat(fd)
        current = os.stat(path, follow_symlinks=False)
        if ((before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            != (after.st_dev, after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            or size != before.st_size or not stat.S_ISREG(current.st_mode)
            or (current.st_dev, current.st_ino, current.st_mode) != (before.st_dev, before.st_ino, before.st_mode)):
            fail()
        return b"".join(chunks)
    finally:
        os.close(fd)
def sha256_path(path):
    digest = hashlib.sha256()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > 512 * 1024 * 1024:
            fail()
        count = 0
        while True:
            block = os.read(fd, min(1024 * 1024, 512 * 1024 * 1024 + 1 - count))
            if not block:
                break
            count += len(block)
            if count > 512 * 1024 * 1024:
                fail()
            digest.update(block)
        after = os.fstat(fd)
        current = os.stat(path, follow_symlinks=False)
        if ((before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            != (after.st_dev, after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            or count != before.st_size or not stat.S_ISREG(current.st_mode)
            or (current.st_dev, current.st_ino, current.st_mode) != (before.st_dev, before.st_ino, before.st_mode)):
            fail()
    finally:
        os.close(fd)
    return digest.hexdigest()
def safe_file(root, relative, expected_sha):
    if not isinstance(relative, str) or not relative or "\\" in relative:
        fail()
    rel = Path(relative)
    if rel.is_absolute() or ".." in rel.parts:
        fail()
    cursor = Path(root).resolve(strict=True)
    for part in rel.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            fail()
    resolved = cursor.resolve(strict=True)
    try:
        resolved.relative_to(Path(root).resolve(strict=True))
    except ValueError:
        fail()
    if not resolved.is_file() or sha256_path(resolved) != expected_sha:
        fail()
    return resolved
try:
    raw = stable_bytes(Path(manifest_path), 131072)
    if hashlib.sha256(raw).hexdigest() != raw_sha:
        fail()
    manifest = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
    required = {"schema", "run_id", "comparison_family", "source_manifest_sha256", "source_sha256", "source", "build", "fixed_runtime_policy", "resource_domain_calibration", "runtime_readback_validator", "fixed_global_control_baseline", "processes", "manifest_sha256"}
    if type(manifest) is not dict or set(manifest) != required:
        fail()
    unsigned = dict(manifest)
    digest = unsigned.pop("manifest_sha256")
    if manifest["schema"] != "allocatbelt.application-runtime-process-bindings.v1" or hashlib.sha256(canonical(unsigned)).hexdigest() != digest:
        fail()
    if manifest["comparison_family"] != "fixed_policy" or manifest["run_id"] != run_id or manifest["source_sha256"] != source_sha:
        fail()
    if type(manifest["fixed_global_control_baseline"]) is not int or manifest["fixed_global_control_baseline"] != int(baseline_text):
        fail()
    policy = manifest["fixed_runtime_policy"]
    if type(policy) is not dict or set(policy) != {"schema", "policy", "policy_sha256"}:
        fail()
    policy_body = policy["policy"]
    if type(policy_body) is not dict or policy_body.get("schema") != "allocatbelt.application-fixed-policy-artifact.v1" or policy["policy_sha256"] != hashlib.sha256(canonical(policy_body)).hexdigest():
        fail()
    buckets = policy_body.get("byte_buckets", {})
    if set(buckets) != {"disk", "upload", "download"} or any(
        bucket.get("bytes_per_second") != 17179869184
        or bucket.get("ceiling_bytes_per_second") != 17179869184
        or bucket.get("burst_bytes") != 65536
        or bucket.get("ceiling_burst_bytes") != 65536
        or bucket.get("max_reservations") != 64
        for bucket in buckets.values()
    ):
        fail()
    calibration = manifest["resource_domain_calibration"]
    if type(calibration) is not dict or set(calibration) != {"binary", "output", "record", "source", "build", "build_sha256"}:
        fail()
    expected_source_keys = {"git_commit", "source_tree_sha256", "cargo_lock_sha256"}
    expected_build_keys = {"host_id", "rustc_release", "rustc_verbose", "cargo_version", "target_triple", "target_cpu", "profile", "features_sha256", "build_inputs_sha256"}
    if type(manifest["source"]) is not dict or set(manifest["source"]) != expected_source_keys or manifest["source"]["source_tree_sha256"] != source_sha:
        fail()
    if type(manifest["build"]) is not dict or set(manifest["build"]) != expected_build_keys or manifest["build"]["target_triple"] != "x86_64-unknown-linux-gnu" or manifest["build"]["target_cpu"] != "x86-64-v3" or manifest["build"]["profile"] != "release":
        fail()
    if manifest["source"] != calibration["source"] or manifest["build"] != calibration["build"] or hashlib.sha256(canonical(manifest["build"])).hexdigest() != calibration["build_sha256"]:
        fail()
    record = calibration["record"]
    if type(record) is not dict or record.get("schema") != "allocatbelt.resource-domain-calibration.v1":
        fail()
    if type(record.get("max_tenants")) is not int or record["max_tenants"] != 1 or type(record.get("max_waiters")) is not int or record["max_waiters"] != 256:
        fail()
    if type(record.get("control_ceiling")) is not int or record["control_ceiling"] != 67108864:
        fail()
    if type(record.get("fixed_global_control_baseline")) is not int or record["fixed_global_control_baseline"] <= 0 or type(record.get("final_live_tenants")) is not int or record["final_live_tenants"] != 0 or record.get("final_global_control_bytes") != record["fixed_global_control_baseline"]:
        fail()
    safe_file(source_root, calibration["binary"]["path"], calibration["binary"]["sha256"])
    output_path = safe_file(source_root, calibration["output"]["path"], calibration["output"]["sha256"])
    calibration_raw = stable_bytes(output_path, 131072)
    if json.loads(calibration_raw.decode("utf-8"), object_pairs_hook=unique) != record:
        fail()
    validator = manifest["runtime_readback_validator"]
    if type(validator) is not dict or set(validator) != {"path", "sha256"} or validator["path"] != "scripts/application-runtime-readback.py" or validator["sha256"] != validator_sha:
        fail()
    safe_file(source_root, validator["path"], validator["sha256"])
except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError, KeyError):
    fail()
PY
}

runtime_binding_for_process() {
  local pair=$1 executor=$2 allocator_name=$3 binary_hash=$4 recipe_path=$5
  python3 - "$runtime_bindings_arg" "$runtime_bindings_sha_expected" "$pair" "$executor" "$allocator_name" "$binary_hash" "$run_id" "$workload" "$profile" "$mode" "$rate" "$arrivals" "$source_digest" "$fixed_global_control_baseline_arg" "$runtime_validator_sha_expected" "$recipe_path" <<'PY'
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path

manifest_path, manifest_sha, pair, executor, allocator, binary_sha, run_id, workload, profile, mode, rate_text, arrivals_text, source_sha, baseline_text, validator_sha, recipe_path = sys.argv[1:]
def fail():
    raise SystemExit(1)
def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail()
        result[key] = value
    return result
def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")
def stable_bytes(path, maximum):
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            fail()
        chunks = []
        size = 0
        while True:
            block = os.read(fd, min(65536, maximum + 1 - size))
            if not block:
                break
            size += len(block)
            if size > maximum:
                fail()
            chunks.append(block)
        after = os.fstat(fd)
        current = os.stat(path, follow_symlinks=False)
        if ((before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            != (after.st_dev, after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            or size != before.st_size or not stat.S_ISREG(current.st_mode)
            or (current.st_dev, current.st_ino, current.st_mode) != (before.st_dev, before.st_ino, before.st_mode)):
            fail()
        return b"".join(chunks)
    finally:
        os.close(fd)
try:
    raw = stable_bytes(manifest_path, 131072)
    if hashlib.sha256(raw).hexdigest() != manifest_sha:
        fail()
    manifest = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
    row = [item for item in manifest["processes"] if item.get("pair") == pair and item.get("executor") == executor and item.get("allocator") == allocator]
    if len(row) != 1:
        fail()
    binding = row[0]
    if set(binding) != {"pair", "executor", "allocator", "report_nonce", "recipe", "recipe_sha256", "expectation_sha256", "resource_ceiling_sha256", "policy_sha256", "fixed_global_control_baseline"}:
        fail()
    recipe = binding["recipe"]
    expected_executor = "allocatbelt" if executor == "bounded" else "tokio-1.53.1"
    run = recipe["run"]
    expected_rate = None if mode == "capacity" else int(rate_text)
    expected_arrivals = 5000 if mode == "capacity" else int(arrivals_text)
    if (recipe["schema"] != "allocatbelt.application-runtime-recipe.v1"
        or recipe["identity"]["report_nonce"] != binding["report_nonce"]
        or recipe["identity"]["run_id"] != run_id
        or recipe["identity"]["allocator"] != allocator
        or recipe["identity"]["executor"] != expected_executor
        or recipe["identity"]["source_sha256"] != source_sha
        or recipe["identity"]["binary_sha256"] != binary_sha
        or recipe["identity"]["comparison_family"] != "fixed_policy"
        or recipe["identity"]["resource_ceiling_sha256"] != binding["resource_ceiling_sha256"]
        or recipe["identity"]["policy_sha256"] != binding["policy_sha256"]
        or binding["policy_sha256"] != manifest["fixed_runtime_policy"]["policy_sha256"]
        or run["workload"] != workload or run["profile"] != profile or run["mode"] != mode
        or run["rate_per_second"] != expected_rate or run["arrivals"] != expected_arrivals
        or recipe["fixed_global_control_baseline"] != int(baseline_text)
        or binding["fixed_global_control_baseline"] != int(baseline_text)
        or not re.fullmatch(r"[a-f0-9]{32}", binding["report_nonce"])
        or hashlib.sha256(canonical(recipe)).hexdigest() != binding["recipe_sha256"]):
        fail()
    path = Path(recipe_path)
    if path.exists() or path.is_symlink():
        fail()
    with path.open("xb") as stream:
        stream.write(canonical(recipe))
    path.chmod(0o600)
    sys.stdout.buffer.write((binding["report_nonce"] + "\0" + binding["recipe_sha256"] + "\0" + binding["expectation_sha256"] + "\0" + binding["resource_ceiling_sha256"] + "\0" + binding["policy_sha256"] + "\0" + str(binding["fixed_global_control_baseline"]) + "\0" + manifest["source_manifest_sha256"] + "\0" + manifest["resource_domain_calibration"]["binary"]["sha256"] + "\0" + manifest["resource_domain_calibration"]["output"]["sha256"] + "\0" + validator_sha + "\0").encode("utf-8"))
except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError, KeyError):
    fail()
PY
}

verify_functional_v4_overlay() {
  python3 - "$functional_overlay_file" "$functional_overlay_sha_expected" "$runtime_bindings_arg" "$runtime_bindings_sha_expected" \
    "$pair_runner_sha256_before" "$source_digest" "$head_commit" "$run_id" "$pair_kind" "$allocator" "$baseline_allocator" \
    "$workload" "$profile" "$mode" "$rate" "$arrivals" "$binary_digest" "$baseline_binary_digest" \
    "$oracle_digest_actual" "$baseline_oracle_digest_actual" "$runtime_validator_sha_expected" \
    "$source_inventory_module_sha256_before" "$repo_root" "$output_root" "$output_root/.functional-tmp" <<'PY'
import hashlib
import json
import os
import re
import selectors
import signal
import shutil
import stat
import subprocess
import sys
import time
import types
from pathlib import Path

(overlay_path, overlay_sha, binding_path, binding_sha, runner_sha, source_sha, source_head,
 run_id, pair_kind, allocator, baseline_allocator, workload, profile, mode, rate_text,
 arrivals_text, binary_sha, baseline_binary_sha, oracle_sha, baseline_oracle_sha, validator_sha,
 source_inventory_sha, source_root_text, output_root_text, expected_tmp_root_text) = sys.argv[1:]

def fail(message="functional v4 overlay mismatch"):
    raise SystemExit(message)

def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail("duplicate JSON key")
        result[key] = value
    return result

def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")

def stable_bytes(path, maximum):
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            fail("functional v4 input is not a bounded regular file")
        chunks = []
        count = 0
        while True:
            block = os.read(fd, min(65536, maximum + 1 - count))
            if not block:
                break
            count += len(block)
            if count > maximum:
                fail("functional v4 input exceeded its byte limit")
            chunks.append(block)
        after = os.fstat(fd)
        current = os.stat(path, follow_symlinks=False)
        if ((before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            != (after.st_dev, after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            or count != before.st_size or not stat.S_ISREG(current.st_mode)
            or (current.st_dev, current.st_ino, current.st_mode) != (before.st_dev, before.st_ino, before.st_mode)):
            fail("functional v4 input changed during its stable read")
        return b"".join(chunks)
    finally:
        os.close(fd)

def digest(value):
    return type(value) is str and re.fullmatch(r"[a-f0-9]{64}", value) is not None

def file_hash(path):
    h = hashlib.sha256()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > 512 * 1024 * 1024:
            fail("functional v4 hash input is not a bounded regular file")
        count = 0
        while True:
            block = os.read(fd, min(1024 * 1024, 512 * 1024 * 1024 + 1 - count))
            if not block:
                break
            count += len(block)
            if count > 512 * 1024 * 1024:
                fail("functional v4 hash input exceeded its byte bound")
            h.update(block)
        after = os.fstat(fd)
        current = os.stat(path, follow_symlinks=False)
        if ((before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            != (after.st_dev, after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            or count != before.st_size or not stat.S_ISREG(current.st_mode)
            or (current.st_dev, current.st_ino, current.st_mode) != (before.st_dev, before.st_ino, before.st_mode)):
            fail("functional v4 hash input changed while streaming")
    finally:
        os.close(fd)
    return h.hexdigest()

def mount_unescape(value):
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), value)

def fs_context(path):
    resolved = Path(path).resolve(strict=True)
    info = resolved.stat()
    raw = Path("/proc/self/mountinfo").read_bytes()
    if len(raw) > 2 * 1024 * 1024:
        fail("mount table exceeded its byte limit")
    selected = None
    for line in raw.decode("utf-8", errors="strict").splitlines():
        left, separator, right = line.partition(" - ")
        if not separator:
            continue
        before = left.split()
        after = right.split()
        if len(before) < 5 or len(after) < 2:
            continue
        mount_point = mount_unescape(before[4])
        if resolved == Path(mount_point) or Path(mount_point) in resolved.parents:
            candidate = (len(mount_point), mount_point, after[0], after[1], before[2])
            if selected is None or candidate[0] > selected[0]:
                selected = candidate
    if selected is None:
        fail("cannot identify the TMPDIR mount")
    _length, mount_point, fs_type, source, device = selected
    return {"path": str(resolved), "mount_point": mount_point, "filesystem_type": fs_type,
            "source": source, "mount_device": device, "st_dev": info.st_dev,
            "free_bytes": os.statvfs(resolved).f_bavail * os.statvfs(resolved).f_frsize}

def trusted_git_capture(cwd, arguments, max_stdout=16 * 1024 * 1024,
                       max_stderr=2 * 1024 * 1024, timeout_seconds=60,
                       program="/usr/bin/git", child_environment=None):
    environment = child_environment or {
        "PATH": "/usr/bin:/bin", "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": "/dev/null", "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_NO_REPLACE_OBJECTS": "1", "GIT_ATTR_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0", "GIT_PAGER": "cat", "PAGER": "cat",
        "GIT_OPTIONAL_LOCKS": "0",
    }
    gnupg_home = os.environ.get("GNUPGHOME")
    if gnupg_home and child_environment is None:
        environment["GNUPGHOME"] = gnupg_home
    if program == "/usr/bin/git":
        command = [program, "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
                   "-c", "core.attributesFile=/dev/null", "-c", "core.excludesFile=/dev/null",
                   "-c", "core.pager=cat", "-c", "gpg.program=/usr/bin/gpg",
                   "-c", "gpg.format=openpgp", *arguments]
    else:
        command = [program, *arguments]
    child = None
    selector = selectors.DefaultSelector()
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    limits = {"stdout": max_stdout, "stderr": max_stderr}
    eof = set()
    received_signal = None
    stop_started = None
    leader_exit_seen = None
    timed_out = False
    failure = None
    old_handlers = {}

    def send_group(signum):
        if child is not None:
            try:
                os.killpg(child.pid, signum)
            except ProcessLookupError:
                pass

    def request_stop(signum, _frame):
        nonlocal received_signal, stop_started
        if received_signal is None:
            received_signal = signum
        if stop_started is None:
            stop_started = time.monotonic()
        send_group(signal.SIGTERM)

    try:
        for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
            old_handlers[signum] = signal.signal(signum, request_stop)
        child = subprocess.Popen(command, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 close_fds=True, start_new_session=True)
        if stop_started is not None:
            send_group(signal.SIGTERM)
        for label, stream in (("stdout", child.stdout), ("stderr", child.stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, label)
        deadline = time.monotonic() + timeout_seconds
        kill_sent = False
        while True:
            now = time.monotonic()
            if now >= deadline and stop_started is None:
                timed_out = True
                stop_started = now
                send_group(signal.SIGTERM)
            if stop_started is not None and now >= stop_started + 0.5 and not kill_sent:
                send_group(signal.SIGKILL)
                kill_sent = True
            if (kill_sent and now >= stop_started + 1.5
                and (child.poll() is None or len(eof) != 2)):
                failure = "Git/GPG command did not finish bounded group cleanup"
                break
            for key, _mask in selector.select(0.05):
                label = key.data
                try:
                    block = os.read(key.fileobj.fileno(), 65536)
                except BlockingIOError:
                    continue
                if not block:
                    selector.unregister(key.fileobj)
                    eof.add(label)
                    continue
                remaining = limits[label] - len(buffers[label])
                if len(block) > remaining:
                    failure = f"Git/GPG {label} exceeded its bounded capture"
                    if stop_started is None:
                        stop_started = time.monotonic()
                        send_group(signal.SIGTERM)
                else:
                    buffers[label].extend(block)
            code = child.poll()
            if code is not None and len(eof) != 2 and stop_started is None:
                if leader_exit_seen is None:
                    leader_exit_seen = time.monotonic()
                elif time.monotonic() >= leader_exit_seen + 0.25:
                    stop_started = time.monotonic()
                    send_group(signal.SIGTERM)
            if code is not None and len(eof) == 2:
                break
        code = child.poll()
    except (OSError, ValueError) as error:
        failure = f"Git/GPG command could not be captured: {error}"
        code = None if child is None else child.poll()
    finally:
        if child is not None:
            if child.poll() is None:
                send_group(signal.SIGTERM)
                try:
                    child.wait(timeout=0.5)
                except subprocess.TimeoutExpired:
                    send_group(signal.SIGKILL)
                    try:
                        child.wait(timeout=0.5)
                    except subprocess.TimeoutExpired:
                        failure = failure or "Git/GPG leader remained alive after SIGKILL"
            send_group(signal.SIGKILL)
            for stream in (child.stdout, child.stderr):
                if stream is not None:
                    stream.close()
        selector.close()
        for signum, previous in old_handlers.items():
            signal.signal(signum, previous)
    if received_signal is not None:
        fail(f"Git/GPG command interrupted by signal {received_signal}")
    if failure is not None or timed_out or code != 0:
        fail(failure or ("Git/GPG command exceeded its deadline" if timed_out else "Git/GPG command failed"))
    return bytes(buffers["stdout"]), bytes(buffers["stderr"])

def toolchain_context(source_root):
    root = Path(source_root).resolve(strict=True)
    cargo_home = Path(os.environ.get("CARGO_HOME", str(Path.home() / ".cargo"))).expanduser()
    preferred = cargo_home / "bin"
    paths = []
    try:
        resolved_preferred = preferred.resolve(strict=True)
        if (resolved_preferred.is_dir() and resolved_preferred != root and root not in resolved_preferred.parents
            and not (resolved_preferred / "git").exists()):
            paths.append(str(resolved_preferred))
    except OSError:
        pass
    paths.extend(("/usr/bin", "/bin"))
    safe_path = os.pathsep.join(paths)
    binaries = {name: shutil.which(name, path=safe_path) for name in ("cargo", "rustc")}
    if any(value is None for value in binaries.values()):
        fail("SourceSchemaV4 verification lacks trusted Cargo/Rust compiler paths")
    environment = {"PATH": safe_path, "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1",
                   "GIT_CONFIG_SYSTEM": "/dev/null", "GIT_CONFIG_GLOBAL": "/dev/null",
                   "GIT_NO_REPLACE_OBJECTS": "1", "GIT_ATTR_NOSYSTEM": "1",
                   "GIT_TERMINAL_PROMPT": "0", "GIT_PAGER": "cat", "PAGER": "cat",
                   "GIT_OPTIONAL_LOCKS": "0"}
    trusted_config = {
        "core.fsmonitor": "false", "core.hooksPath": "/dev/null",
        "core.attributesFile": "/dev/null", "core.excludesFile": "/dev/null",
        "core.pager": "cat", "gpg.program": "/usr/bin/gpg",
        "gpg.format": "openpgp", "protocol.ext.allow": "never",
    }
    environment["GIT_CONFIG_COUNT"] = str(len(trusted_config))
    for index, (key, value) in enumerate(trusted_config.items()):
        environment[f"GIT_CONFIG_KEY_{index}"] = key
        environment[f"GIT_CONFIG_VALUE_{index}"] = value
    for name in ("HOME", "CARGO_HOME", "RUSTUP_HOME", "RUSTUP_TOOLCHAIN", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "GNUPGHOME"):
        if name in os.environ:
            environment[name] = os.environ[name]
    return binaries, environment

try:
    overlay_raw = stable_bytes(overlay_path, 65536)
    if hashlib.sha256(overlay_raw).hexdigest() != overlay_sha:
        fail("functional v4 pair overlay SHA-256 mismatch")
    overlay = json.loads(overlay_raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=lambda _value: fail("non-finite JSON"))
    expected_overlay_keys = {
        "schema", "execution_scope", "run_id", "source_manifest_schema", "source_manifest_path",
        "source_manifest_file_sha256", "signer_fingerprint", "source_manifest_sha256", "source_head", "source_tree_sha256",
        "source_inventory_module_sha256", "pair_runner_sha256", "runtime_bindings_sha256",
        "runtime_validator_sha256", "candidate_binary_sha256", "baseline_binary_sha256",
        "baseline_allocator", "oracle_sha256", "baseline_oracle_sha256", "workload", "profile",
        "mode", "rate_per_second", "arrivals", "pair_kind", "resource_ceiling_sha256", "policy_sha256",
        "fixed_global_control_baseline", "calibration_binary_sha256", "calibration_output_sha256",
        "artifact_sha256s", "processes", "functional_limits", "temporary_storage_root_relative_path",
        "temporary_storage_context",
    }
    if type(overlay) is not dict or set(overlay) != expected_overlay_keys or overlay_raw != canonical(overlay):
        fail("functional v4 pair overlay schema/canonical bytes mismatch")
    expected_limits = {
        "max_arrivals": 1000, "max_rate_per_second": 1000, "max_trace_deadline_seconds": 30,
        "max_drain_deadline_seconds": 30, "max_shutdown_deadline_seconds": 15,
        "max_process_deadline_seconds": 300, "max_pair_deadline_seconds": 600,
        "capacity_horizon_seconds": 30, "max_source_manifest_bytes": 16 * 1024 * 1024,
        "max_file_bytes": 16 * 1024 * 1024, "max_output_files": 512,
        "max_output_directories": 128, "max_output_entries": 1024,
        "max_output_bytes": 256 * 1024 * 1024,
        "minimum_free_bytes": 256 * 1024 * 1024,
    }
    if overlay["functional_limits"] != expected_limits:
        fail("functional v4 finite limits changed")
    expected_rate = None if mode == "capacity" else int(rate_text)
    expected_arrivals = 5000 if mode == "capacity" else int(arrivals_text)
    if (overlay["schema"] != "allocatbelt.application-functional-pair-overlay.v3"
        or overlay["execution_scope"] != "functional_only"
        or overlay["run_id"] != run_id
        or overlay["source_manifest_schema"] != "allocatbelt.application-source-manifest.v4"
        or overlay["source_head"] != source_head or overlay["source_tree_sha256"] != source_sha
        or not re.fullmatch(r"[A-F0-9]{40,64}", overlay["signer_fingerprint"])
        or overlay["source_inventory_module_sha256"] != source_inventory_sha
        or overlay["pair_runner_sha256"] != runner_sha
        or overlay["runtime_bindings_sha256"] != binding_sha
        or overlay["runtime_validator_sha256"] != validator_sha
        or overlay["candidate_binary_sha256"] != binary_sha
        or overlay["baseline_binary_sha256"] != (baseline_binary_sha or None)
        or overlay["baseline_allocator"] != (baseline_allocator or None)
        or overlay["oracle_sha256"] != (oracle_sha or None)
        or overlay["baseline_oracle_sha256"] != (baseline_oracle_sha or None)
        or overlay["workload"] != workload or overlay["profile"] != profile
        or overlay["mode"] != mode or overlay["rate_per_second"] != expected_rate
        or overlay["arrivals"] != expected_arrivals or overlay["pair_kind"] != pair_kind):
        fail("functional v4 pair overlay differs from runner arguments")
    if (not digest(overlay["source_manifest_file_sha256"])
        or not digest(overlay["source_manifest_sha256"])
        or not digest(overlay["resource_ceiling_sha256"])
        or not digest(overlay["policy_sha256"])
        or type(overlay["fixed_global_control_baseline"]) is not int
        or overlay["fixed_global_control_baseline"] <= 0):
        fail("functional v4 pair overlay contains an invalid source/policy pin")

    source_root = Path(source_root_text).resolve(strict=True)
    output_root = Path(output_root_text).resolve(strict=True)
    relative_manifest = overlay["source_manifest_path"]
    if (type(relative_manifest) is not str or relative_manifest != ".functional-inputs/source-manifest.json"
        or overlay["temporary_storage_root_relative_path"] != ".functional-tmp"):
        fail("functional v4 overlay artifact paths differ from the fixed private layout")
    manifest_path = output_root / relative_manifest
    if manifest_path.is_symlink() or not manifest_path.is_file():
        fail("copied SourceSchemaV4 manifest is missing or symlinked")
    manifest_raw = stable_bytes(manifest_path, expected_limits["max_source_manifest_bytes"])
    if hashlib.sha256(manifest_raw).hexdigest() != overlay["source_manifest_file_sha256"]:
        fail("copied SourceSchemaV4 raw file SHA-256 mismatch")
    source_manifest = json.loads(manifest_raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=lambda _value: fail("non-finite manifest JSON"))
    if manifest_raw != canonical(source_manifest):
        fail("copied SourceSchemaV4 manifest is not canonical JSON")
    unsigned_manifest = dict(source_manifest)
    semantic_sha = unsigned_manifest.pop("manifest_sha256", None)
    if (not digest(semantic_sha)
        or hashlib.sha256(canonical(unsigned_manifest)).hexdigest() != semantic_sha):
        fail("copied SourceSchemaV4 semantic manifest digest differs")
    if (source_manifest.get("schema") != overlay["source_manifest_schema"]
        or source_manifest.get("manifest_sha256") != overlay["source_manifest_sha256"]
        or source_manifest.get("source", {}).get("git_commit") != source_head
        or source_manifest.get("source", {}).get("source_tree_sha256") != source_sha):
        fail("copied SourceSchemaV4 manifest semantic identity differs")

    signer_fingerprint = overlay["signer_fingerprint"]
    if not re.fullmatch(r"[A-F0-9]{40,64}", signer_fingerprint):
        fail("caller-pinned OpenPGP signer fingerprint is malformed")
    gnupg_home_text = os.environ.get("GNUPGHOME")
    if not gnupg_home_text:
        fail("SourceSchemaV4 verification requires a caller-provided private GNUPGHOME")
    gnupg_home = Path(gnupg_home_text).expanduser().absolute()
    cursor = Path(gnupg_home.anchor)
    for component in gnupg_home.parts[1:]:
        cursor /= component
        if cursor.is_symlink():
            fail("SourceSchemaV4 GNUPGHOME traverses a symlink")
    if not gnupg_home.is_dir() or stat.S_IMODE(gnupg_home.stat().st_mode) != 0o700:
        fail("SourceSchemaV4 GNUPGHOME must be a private 0700 directory")
    current_head = trusted_git_capture(source_root, ["rev-parse", "HEAD"], max_stdout=4096)[0].decode("ascii").strip()
    git_root = trusted_git_capture(source_root, ["rev-parse", "--show-toplevel"], max_stdout=4096)[0].decode("utf-8").rstrip("\n")
    if current_head != source_head or Path(git_root).resolve(strict=True) != source_root:
        fail("SourceSchemaV4 source root HEAD/worktree differs before controller execution")
    sig_stdout, sig_stderr = trusted_git_capture(source_root, ["verify-commit", "--raw", source_head])
    signature_lines = (sig_stdout + sig_stderr).decode("utf-8", errors="replace").splitlines()
    valid_signatures = []
    rejected_statuses = {"BADSIG", "ERRSIG", "NO_PUBKEY", "REVKEYSIG", "EXPKEYSIG", "EXPSIG"}
    for line in signature_lines:
        fields = line.split()
        if len(fields) >= 2 and fields[:2] == ["[GNUPG:]", "VALIDSIG"]:
            if len(fields) not in (11, 12):
                fail("GPG VALIDSIG status record is malformed")
            signing = fields[2].upper()
            primary = (fields[11] if len(fields) == 12 else fields[2]).upper()
            if not re.fullmatch(r"[A-F0-9]{40,64}", signing) or not re.fullmatch(r"[A-F0-9]{40,64}", primary):
                fail("GPG VALIDSIG fingerprint fields are malformed")
            valid_signatures.append((signing, primary))
        elif len(fields) >= 2 and fields[0] == "[GNUPG:]" and fields[1] in rejected_statuses:
            fail("SourceSchemaV4 commit signature has a GPG rejection status")
    if len(valid_signatures) != 1 or signer_fingerprint not in valid_signatures[0]:
        fail("SourceSchemaV4 VALIDSIG signing/primary fingerprint differs from the caller-pinned signer")

    source_files = source_manifest["source"]["files"]
    controller_entry = next((item for item in source_files if item.get("path") == "scripts/application-campaign.py"), None)
    if type(controller_entry) is not dict or controller_entry.get("kind") != "file":
        fail("SourceSchemaV4 inventory does not pin a regular campaign controller")
    runner_path = Path(__file__).resolve(strict=True)
    try:
        runner_relative = runner_path.relative_to(source_root).as_posix()
    except ValueError:
        fail("functional v4 runner is outside the signed SourceSchemaV4 root")
    runner_entry = next((item for item in source_files if item.get("path") == runner_relative), None)
    if (runner_relative != "scripts/run-application-pair.sh" or type(runner_entry) is not dict
        or runner_entry.get("kind") != "file" or runner_entry.get("sha256") != runner_sha):
        fail("functional v4 runner bytes are not the committed SourceSchemaV4 runner")
    controller_path = source_root / "scripts/application-campaign.py"
    if controller_path.parent.is_symlink():
        fail("SourceSchemaV4 controller path has a symlinked parent")
    controller_raw = stable_bytes(controller_path, 16 * 1024 * 1024)
    controller_info = controller_path.stat(follow_symlinks=False)
    controller_mode = "100755" if controller_info.st_mode & 0o111 else "100644"
    if (controller_entry.get("mode") not in ("100644", "100755")
        or controller_mode != controller_entry.get("mode")
        or len(controller_raw) != controller_entry.get("size")
        or hashlib.sha256(controller_raw).hexdigest() != controller_entry.get("sha256")):
        fail("campaign controller bytes differ from the SourceSchemaV4 inventory")
    committed_mode_raw = trusted_git_capture(
        source_root, ["ls-tree", "-z", source_head, "--", "scripts/application-campaign.py"],
        max_stdout=4096,
    )[0]
    committed_entry, separator, committed_path = committed_mode_raw.rstrip(b"\0").partition(b"\t")
    committed_fields = committed_entry.split(b" ")
    if (not separator or committed_path != b"scripts/application-campaign.py"
        or len(committed_fields) != 3 or committed_fields[0].decode("ascii", errors="strict") != controller_mode
        or committed_fields[1] != b"blob"
        or not re.fullmatch(rb"[0-9a-f]{40,64}", committed_fields[2])):
        fail("campaign controller tracked mode differs from the verified signed commit")
    committed_controller = trusted_git_capture(
        source_root, ["cat-file", "blob", f"{source_head}:scripts/application-campaign.py"],
        max_stdout=16 * 1024 * 1024,
    )[0]
    if controller_raw != committed_controller:
        fail("captured campaign controller differs from the blob at the verified signed commit")
    controller = types.ModuleType("pair_runner_pinned_campaign_controller")
    controller.__file__ = str(controller_path)
    exec(compile(controller_raw, str(controller_path), "exec", dont_inherit=True), controller.__dict__)
    if (controller.SOURCE_SCHEMA != overlay["source_manifest_schema"]
        or controller.SOURCE_INVENTORY_MODULE_SHA256 != source_inventory_sha):
        fail("SourceSchemaV4 controller pins a different schema/source inventory engine")
    tool_bins, tool_environment = toolchain_context(source_root)
    def trusted_controller_run_checked(arguments, cwd=None, timeout_seconds=120.0):
        if arguments and arguments[0] == "git":
            return trusted_git_capture(cwd or source_root, arguments[1:],
                                       timeout_seconds=min(600, max(1, int(timeout_seconds))))[0]
        if arguments and arguments[0] in tool_bins:
            return trusted_git_capture(cwd or source_root, arguments[1:],
                                       timeout_seconds=min(600, max(1, int(timeout_seconds))),
                                       program=tool_bins[arguments[0]],
                                       child_environment=tool_environment)[0]
        fail("unexpected preflight helper requested by the source-pinned controller")
    controller.run_checked = trusted_controller_run_checked
    old_environment = dict(os.environ)
    try:
        for key in list(os.environ):
            if key.startswith("GIT_"):
                os.environ.pop(key, None)
        os.environ.update(tool_environment)
        config = {
            "core.fsmonitor": "false", "core.hooksPath": "/dev/null",
            "core.attributesFile": "/dev/null", "core.excludesFile": "/dev/null",
            "core.pager": "cat", "gpg.program": "/usr/bin/gpg",
            "gpg.format": "openpgp", "protocol.ext.allow": "never",
        }
        os.environ["GIT_CONFIG_COUNT"] = str(len(config))
        for index, (key, value) in enumerate(config.items()):
            os.environ[f"GIT_CONFIG_KEY_{index}"] = key
            os.environ[f"GIT_CONFIG_VALUE_{index}"] = value
        controller.verify_source_manifest(source_manifest, source_root, verify_artifacts=True)
    finally:
        os.environ.clear()
        os.environ.update(old_environment)
    expected_artifacts = {
        **{name: item["sha256"] for name, item in source_manifest["artifacts"].items()},
        **{f"soak-{name}": item["sha256"] for name, item in source_manifest["soak_artifacts"].items()},
        "analysis-engine": source_manifest["analysis_artifact"]["sha256"],
        "resource-domain-calibration": source_manifest["resource_domain_calibration"]["binary"]["sha256"],
        "resource-domain-calibration-output": source_manifest["resource_domain_calibration"]["output"]["sha256"],
    }
    if overlay["artifact_sha256s"] != expected_artifacts:
        fail("functional v4 overlay does not bind all four allocator, soak, analysis and calibration artifacts")
    if set(source_manifest["artifacts"]) != {"allocatbelt", "mimalloc-secure", "mimalloc-standard", "system"}:
        fail("SourceSchemaV4 does not bind all four actual allocator artifacts")
    if "allocatbelt" not in source_manifest["soak_artifacts"]:
        fail("SourceSchemaV4 candidate soak binary is missing")
    if source_manifest["artifacts"]["allocatbelt"]["sha256"] != binary_sha:
        fail("runner candidate binary differs from SourceSchemaV4")
    selected_baseline = None if baseline_allocator == "" else baseline_allocator
    if selected_baseline is not None:
        if source_manifest["artifacts"].get(selected_baseline, {}).get("sha256") != baseline_binary_sha:
            fail("runner baseline binary differs from SourceSchemaV4")
    policy = source_manifest["fixed_runtime_policy"]
    calibration = source_manifest["resource_domain_calibration"]
    validator = source_manifest["runtime_readback_validator"]
    if (policy.get("policy_sha256") != overlay["policy_sha256"]
        or calibration.get("binary", {}).get("sha256") != overlay["calibration_binary_sha256"]
        or calibration.get("output", {}).get("sha256") != overlay["calibration_output_sha256"]
        or calibration.get("record", {}).get("fixed_global_control_baseline") != overlay["fixed_global_control_baseline"]
        or validator.get("sha256") != validator_sha):
        fail("functional v4 policy/calibration/validator pins differ from SourceSchemaV4")
    expected_ceiling = controller.fixed_resource_limits_for_cell(workload, profile, validator_sha)
    if hashlib.sha256(canonical(expected_ceiling)).hexdigest() != overlay["resource_ceiling_sha256"]:
        fail("functional v4 numeric resource ceiling digest differs from the source controller")

    root_tmp = Path(expected_tmp_root_text).resolve(strict=True)
    if root_tmp != output_root / ".functional-tmp" or root_tmp.is_symlink() or not root_tmp.is_dir():
        fail("functional v4 TMPDIR root escaped the private output tree")
    if os.environ.get("TMPDIR") != str(root_tmp):
        fail("functional v4 runner did not receive the private output-root TMPDIR")
    expected_context = overlay["temporary_storage_context"]
    if type(expected_context) is not dict or set(expected_context) != {"output_root", "tmpdir_root"}:
        fail("functional v4 storage context record is malformed")
    actual_tmp = fs_context(root_tmp)
    actual_output = fs_context(output_root)
    planned_tmp = expected_context["tmpdir_root"]
    planned_output = expected_context["output_root"]
    for actual, planned in ((actual_tmp, planned_tmp), (actual_output, planned_output)):
        for key in ("mount_point", "filesystem_type", "source", "mount_device", "st_dev"):
            if actual[key] != planned[key]:
                fail("functional v4 output filesystem context changed")
    if (actual_tmp["filesystem_type"] in ("tmpfs", "ramfs")
        or actual_tmp["st_dev"] != actual_output["st_dev"]
        or actual_tmp["mount_point"] != actual_output["mount_point"]
        or actual_tmp["free_bytes"] < expected_limits["minimum_free_bytes"]):
        fail("functional v4 TMPDIR is not on the non-memory output root filesystem")

    binding_raw = stable_bytes(binding_path, 131072)
    if hashlib.sha256(binding_raw).hexdigest() != binding_sha:
        fail("functional v4 runtime binding raw SHA-256 mismatch")
    binding_manifest = json.loads(binding_raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=lambda _value: fail("non-finite binding JSON"))
    binding_unsigned = dict(binding_manifest)
    binding_semantic_sha = binding_unsigned.pop("manifest_sha256", None)
    if (binding_manifest.get("schema") != "allocatbelt.application-runtime-process-bindings.v1"
        or binding_manifest.get("run_id") != run_id
        or binding_manifest.get("source_manifest_sha256") != overlay["source_manifest_sha256"]
        or binding_manifest.get("source_sha256") != source_sha
        or hashlib.sha256(canonical(binding_unsigned)).hexdigest() != binding_semantic_sha):
        fail("functional v4 runtime bindings are not bound to the exact SourceSchemaV4 source")
    if (binding_manifest.get("fixed_runtime_policy") != policy
        or binding_manifest.get("resource_domain_calibration", {}).get("binary") != calibration.get("binary")
        or binding_manifest.get("resource_domain_calibration", {}).get("output") != calibration.get("output")
        or binding_manifest.get("runtime_readback_validator") != validator
        or binding_manifest.get("fixed_global_control_baseline") != overlay["fixed_global_control_baseline"]):
        fail("functional v4 runtime binding manifest changed policy/calibration inputs")
    bindings = binding_manifest.get("processes")
    descriptors = overlay["processes"]
    if type(bindings) is not list or len(bindings) != 2 or type(descriptors) is not list or len(descriptors) != 2:
        fail("functional v4 pair must contain exactly two runtime bindings")
    expected_descriptors = []
    for descriptor in descriptors:
        if type(descriptor) is not dict or set(descriptor) != {"pair", "executor", "allocator"}:
            fail("functional v4 process descriptor is malformed")
        expected_descriptors.append((descriptor["pair"], descriptor["executor"], descriptor["allocator"]))
    if len(set(expected_descriptors)) != 2:
        fail("functional v4 process descriptors are duplicated")
    actual_descriptors = []
    runtime_validator = controller.runtime_readback_module(validator_sha)
    expected_run = {"workload": workload, "profile": profile, "mode": mode,
                    "rate_per_second": expected_rate, "arrivals": expected_arrivals}
    for binding in bindings:
        if type(binding) is not dict:
            fail("functional v4 runtime binding is malformed")
        descriptor = (binding.get("pair"), binding.get("executor"), binding.get("allocator"))
        actual_descriptors.append(descriptor)
        if descriptor not in expected_descriptors:
            fail("functional v4 runtime binding descriptor differs")
        if (binding.get("policy_sha256") != overlay["policy_sha256"]
            or binding.get("resource_ceiling_sha256") != overlay["resource_ceiling_sha256"]
            or binding.get("fixed_global_control_baseline") != overlay["fixed_global_control_baseline"]):
            fail("functional v4 runtime binding changed fixed policy/ceiling/baseline")
        recipe = binding.get("recipe")
        if type(recipe) is not dict or recipe.get("run") != expected_run:
            fail("functional v4 runtime recipe differs from the selected workload/profile/mode")
        expected_executor = "allocatbelt" if descriptor[1] == "bounded" else "tokio-1.53.1"
        artifact = source_manifest["artifacts"].get(descriptor[2])
        if (type(artifact) is not dict or recipe.get("identity", {}).get("executor") != expected_executor
            or recipe.get("identity", {}).get("allocator") != descriptor[2]
            or recipe.get("identity", {}).get("source_sha256") != source_sha
            or recipe.get("identity", {}).get("binary_sha256") != artifact.get("sha256")
            or recipe.get("identity", {}).get("report_nonce") != binding.get("report_nonce")
            or not re.fullmatch(r"[a-f0-9]{32}", binding.get("report_nonce", ""))
            or hashlib.sha256(canonical(recipe)).hexdigest() != binding.get("recipe_sha256")):
            fail("functional v4 runtime recipe identity/hash differs from its actual artifact")
        expected = runtime_validator.build_fixed_expectation(recipe)
        if hashlib.sha256(runtime_validator.canonical_bytes(expected)).hexdigest() != binding.get("expectation_sha256"):
            fail("functional v4 expected runtime receipt hash differs from the source-pinned validator")
    if len(set(actual_descriptors)) != 2 or set(actual_descriptors) != set(expected_descriptors):
        fail("functional v4 bindings do not match the selected pair kind")
    if pair_kind == "allocator-match":
        if {descriptor[2] for descriptor in actual_descriptors} != {"allocatbelt", baseline_allocator}:
            fail("functional v4 allocator comparison differs from its selected baseline")
    elif any(descriptor[2] != "allocatbelt" for descriptor in actual_descriptors):
        fail("functional v4 runtime/A/A pairs must use the candidate allocator")
except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError, KeyError, subprocess.SubprocessError):
    fail()
PY
}

verify_functional_overlay() {
  (( functional_only_mode == 1 )) || return 0
  functional_overlay_file=$(realpath "$functional_overlay_arg") || return 1
  local bindings_file
  bindings_file=$(realpath "$runtime_bindings_arg") || return 1
  [[ -f "$functional_overlay_file" && ! -L "$functional_overlay_arg" && "$functional_overlay_file" == "$output_root"/* ]] || { echo "functional overlay path escaped the private output root" >&2; return 1; }
  [[ -f "$bindings_file" && ! -L "$runtime_bindings_arg" && "$bindings_file" == "$output_root"/* ]] || { echo "functional runtime bindings escaped the private output root" >&2; return 1; }
  functional_overlay_sha256_before=$(stable_sha256 "$functional_overlay_file" 65536) || return 1
  [[ "$functional_overlay_sha256_before" == "$functional_overlay_sha_expected" ]] || { echo "functional overlay SHA-256 differs from its pinned argument" >&2; return 1; }
  local overlay_schema
  overlay_schema=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["schema"])' "$functional_overlay_file") || return 1
  if [[ "$overlay_schema" == "allocatbelt.application-functional-pair-overlay.v3" ]]; then
    verify_functional_v4_overlay || { echo "SourceSchemaV4 functional overlay failed independent controller/receipt-input validation" >&2; return 1; }
    functional_source_v4_mode=1
    functional_source_manifest_file_path="$output_root/.functional-inputs/source-manifest.json"
    functional_source_manifest_file_sha256_before=$(stable_sha256 "$functional_source_manifest_file_path" 16777216) || return 1
    functional_source_manifest_semantic_sha256=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["source_manifest_sha256"])' "$functional_overlay_file") || return 1
    functional_source_signer_fingerprint=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["signer_fingerprint"])' "$functional_overlay_file") || return 1
    functional_tmp_root_path="$output_root/.functional-tmp"
    functional_tmp_context_json=$(python3 -c 'import json,sys; print(json.dumps(json.load(open(sys.argv[1], encoding="utf-8"))["temporary_storage_context"]["tmpdir_root"], sort_keys=True, separators=(",", ":")))' "$functional_overlay_file") || return 1
    return 0
  fi
  [[ "$overlay_schema" == "allocatbelt.application-functional-pair-overlay.v2" ]] || { echo "unknown functional overlay schema" >&2; return 1; }
  python3 - "$functional_overlay_file" "$functional_overlay_sha_expected" "$bindings_file" "$runtime_bindings_sha_expected" "$pair_runner_sha256_before" "$source_digest" "$head_commit" "$run_id" "$pair_kind" "$allocator" "$baseline_allocator" "$workload" "$profile" "$mode" "$rate" "$arrivals" "$binary_digest" "$baseline_binary_digest" "$oracle_digest_actual" "$baseline_oracle_digest_actual" "$runtime_validator_sha_expected" "$source_inventory_module_sha256_before" <<'PY'
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path

(overlay_path, overlay_sha, binding_path, binding_sha, runner_sha, source_sha, source_head,
 run_id, pair_kind, allocator, baseline_allocator, workload, profile, mode, rate_text,
 arrivals_text, binary_sha, baseline_binary_sha, oracle_sha, baseline_oracle_sha, validator_sha,
 source_inventory_module_sha) = sys.argv[1:]

def fail():
    raise SystemExit(1)

def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail()
        result[key] = value
    return result

def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")

def digest(value):
    return type(value) is str and re.fullmatch(r"[a-f0-9]{64}", value) is not None

def stable_bytes(path, maximum):
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            fail()
        chunks = []
        size = 0
        while True:
            block = os.read(fd, min(65536, maximum + 1 - size))
            if not block:
                break
            size += len(block)
            if size > maximum:
                fail()
            chunks.append(block)
        after = os.fstat(fd)
        current = os.stat(path, follow_symlinks=False)
        if ((before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            != (after.st_dev, after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            or size != before.st_size or not stat.S_ISREG(current.st_mode)
            or (current.st_dev, current.st_ino, current.st_mode) != (before.st_dev, before.st_ino, before.st_mode)):
            fail()
        return b"".join(chunks)
    finally:
        os.close(fd)

try:
    overlay_raw = stable_bytes(overlay_path, 65536)
    if hashlib.sha256(overlay_raw).hexdigest() != overlay_sha:
        fail()
    overlay = json.loads(overlay_raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=lambda _value: fail())
    expected_keys = {
        "schema", "execution_scope", "run_id", "source_head", "source_tree_sha256", "source_manifest_sha256",
        "source_inventory_module_sha256",
        "pair_runner_sha256", "runtime_bindings_sha256", "runtime_validator_sha256",
        "candidate_binary_sha256", "baseline_binary_sha256", "oracle_sha256", "baseline_oracle_sha256",
        "workload", "profile", "mode", "rate_per_second", "arrivals", "pair_kind",
        "resource_ceiling_sha256", "policy_sha256", "fixed_global_control_baseline",
        "calibration_binary_sha256", "calibration_output_sha256", "processes", "functional_limits",
    }
    if type(overlay) is not dict or set(overlay) != expected_keys or overlay_raw != canonical(overlay):
        fail()
    expected_limits = {
        "max_arrivals": 1000,
        "max_rate_per_second": 1000,
        "max_trace_deadline_seconds": 30,
        "max_drain_deadline_seconds": 30,
        "max_shutdown_deadline_seconds": 15,
        "max_process_deadline_seconds": 300,
    }
    limits = overlay["functional_limits"]
    if type(limits) is not dict or set(limits) != set(expected_limits) or any(type(limits[key]) is not int or limits[key] != value for key, value in expected_limits.items()):
        fail()
    if (overlay["schema"] != "allocatbelt.application-functional-pair-overlay.v2"
        or overlay["execution_scope"] != "functional_only"
        or overlay["run_id"] != run_id
        or overlay["source_head"] != source_head
        or overlay["source_tree_sha256"] != source_sha
        or overlay["source_inventory_module_sha256"] != source_inventory_module_sha
        or overlay["pair_runner_sha256"] != runner_sha
        or overlay["runtime_bindings_sha256"] != binding_sha
        or overlay["runtime_validator_sha256"] != validator_sha
        or overlay["candidate_binary_sha256"] != binary_sha
        or overlay["baseline_binary_sha256"] != (baseline_binary_sha or None)
        or overlay["oracle_sha256"] != oracle_sha
        or overlay["baseline_oracle_sha256"] != (baseline_oracle_sha or None)
        or overlay["workload"] != workload or overlay["profile"] != profile
        or overlay["mode"] != mode or type(overlay["rate_per_second"]) is not int
        or overlay["rate_per_second"] != int(rate_text) or type(overlay["arrivals"]) is not int
        or overlay["arrivals"] != int(arrivals_text) or overlay["pair_kind"] != pair_kind):
        fail()
    if not all(digest(overlay[name]) for name in (
        "source_tree_sha256", "source_manifest_sha256", "source_inventory_module_sha256", "pair_runner_sha256", "runtime_bindings_sha256",
        "runtime_validator_sha256", "candidate_binary_sha256", "oracle_sha256", "resource_ceiling_sha256",
        "policy_sha256", "calibration_binary_sha256", "calibration_output_sha256",
    )):
        fail()
    if baseline_binary_sha and not digest(overlay["baseline_binary_sha256"]):
        fail()
    if baseline_oracle_sha and not digest(overlay["baseline_oracle_sha256"]):
        fail()
    if type(overlay["fixed_global_control_baseline"]) is not int or overlay["fixed_global_control_baseline"] <= 0:
        fail()

    binding_raw = stable_bytes(binding_path, 131072)
    if hashlib.sha256(binding_raw).hexdigest() != binding_sha:
        fail()
    manifest = json.loads(binding_raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=lambda _value: fail())
    if type(manifest) is not dict or manifest.get("schema") != "allocatbelt.application-runtime-process-bindings.v1" or manifest.get("run_id") != run_id:
        fail()
    if manifest.get("source_manifest_sha256") != overlay["source_manifest_sha256"] or manifest.get("source_sha256") != source_sha:
        fail()
    policy = manifest.get("fixed_runtime_policy")
    calibration = manifest.get("resource_domain_calibration")
    validator = manifest.get("runtime_readback_validator")
    if type(policy) is not dict or policy.get("policy_sha256") != overlay["policy_sha256"]:
        fail()
    if type(calibration) is not dict or calibration.get("binary", {}).get("sha256") != overlay["calibration_binary_sha256"] or calibration.get("output", {}).get("sha256") != overlay["calibration_output_sha256"]:
        fail()
    if type(calibration.get("record")) is not dict or type(calibration["record"].get("fixed_global_control_baseline")) is not int or calibration["record"]["fixed_global_control_baseline"] != overlay["fixed_global_control_baseline"]:
        fail()
    if type(validator) is not dict or validator.get("sha256") != validator_sha:
        fail()
    bindings = manifest.get("processes")
    expected_processes = overlay["processes"]
    if type(bindings) is not list or len(bindings) != 2 or type(expected_processes) is not list or len(expected_processes) != 2:
        fail()
    expected_descriptors = []
    for item in expected_processes:
        if type(item) is not dict or set(item) != {"pair", "executor", "allocator"}:
            fail()
        expected_descriptors.append((item["pair"], item["executor"], item["allocator"]))
    if len(set(expected_descriptors)) != 2:
        fail()
    actual_descriptors = []
    for binding in bindings:
        if type(binding) is not dict:
            fail()
        descriptor = (binding.get("pair"), binding.get("executor"), binding.get("allocator"))
        actual_descriptors.append(descriptor)
        if binding.get("policy_sha256") != overlay["policy_sha256"] or binding.get("resource_ceiling_sha256") != overlay["resource_ceiling_sha256"]:
            fail()
        if type(binding.get("fixed_global_control_baseline")) is not int or binding["fixed_global_control_baseline"] != overlay["fixed_global_control_baseline"]:
            fail()
        recipe = binding.get("recipe")
        if type(recipe) is not dict or type(recipe.get("identity")) is not dict or recipe["identity"].get("source_sha256") != source_sha:
            fail()
        expected_binary = binary_sha if descriptor[2] == allocator else baseline_binary_sha
        if recipe["identity"].get("binary_sha256") != expected_binary:
            fail()
        if recipe.get("run") != {
            "workload": workload, "profile": profile, "mode": mode,
            "rate_per_second": int(rate_text), "arrivals": int(arrivals_text),
        }:
            fail()
    if len(set(actual_descriptors)) != 2 or set(actual_descriptors) != set(expected_descriptors):
        fail()
    if pair_kind in ("matched", "aa-bounded") and any(item[2] != allocator for item in actual_descriptors):
        fail()
    if pair_kind == "allocator-match" and {item[2] for item in actual_descriptors} != {allocator, baseline_allocator}:
        fail()
except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError, KeyError):
    fail()
PY
}

source_identity=$(source_hash) || exit 2
IFS=$'\t' read -r source_digest head_commit <<< "$source_identity"
[[ "$source_digest" =~ ^[0-9a-f]{64}$ && "$head_commit" =~ ^[0-9a-f]{40}$ ]] || exit 2
binary_digest=$(stable_sha256 "$binary") || exit 2
if (( runtime_readback_enabled == 1 )); then
  verify_runtime_inputs || exit 2
fi
rust_version=$(rustc -Vv | tr '\n' ';') || exit 2
kernel=$(uname -srmo) || exit 2
host=$(hostname -f 2>/dev/null || hostname)
comparison_family=fixed_policy
if [[ "$pair_kind" == pressure-matched || "$pair_kind" == pressure-allocator-match ]]; then
  comparison_family=external_pressure
fi
if (( functional_only_mode == 1 )); then
  verify_functional_overlay || { echo "functional overlay manifest failed independent pin validation" >&2; exit 2; }
fi

{
  printf 'key\tvalue\n'
  printf 'run_id\t%s\n' "$run_id"
printf 'allocator\t%s\n' "$allocator"
printf 'baseline_allocator\t%s\n' "$baseline_allocator"
  printf 'workload\t%s\n' "$workload"
  printf 'profile\t%s\n' "$profile"
  printf 'pair_kind\t%s\n' "$pair_kind"
  printf 'comparison_family\t%s\n' "$comparison_family"
  printf 'execution_scope\t%s\n' "$execution_scope"
  if (( functional_only_mode == 1 )); then
    printf 'functional_max_arrivals\t1000\n'
    printf 'functional_max_average_rate_per_second\t1000\n'
    printf 'functional_max_trace_deadline_seconds\t30\n'
    printf 'functional_max_drain_deadline_seconds\t30\n'
    printf 'functional_max_shutdown_deadline_seconds\t15\n'
    printf 'functional_max_process_deadline_seconds\t300\n'
    printf 'functional_capacity_horizon_seconds\t30\n'
    if (( functional_source_v4_mode == 1 )); then
      printf 'source_manifest_schema\tallocatbelt.application-source-manifest.v4\n'
      printf 'source_manifest_file_sha256_before\t%s\n' "$functional_source_manifest_file_sha256_before"
      printf 'source_manifest_sha256\t%s\n' "$functional_source_manifest_semantic_sha256"
      printf 'source_signer_fingerprint\t%s\n' "$functional_source_signer_fingerprint"
      printf 'functional_tmpdir_root\t%s\n' "$functional_tmp_root_path"
      printf 'functional_tmpdir_root_context\t%s\n' "$functional_tmp_context_json"
      printf 'functional_file_size_limit_bytes\t%s\n' "$((functional_file_size_limit_blocks * 1024))"
      printf 'functional_file_size_limit_soft_bytes\t%s\n' "$(( $(ulimit -Sf) * 1024 ))"
      printf 'functional_file_size_limit_hard_bytes\t%s\n' "$(( $(ulimit -Hf) * 1024 ))"
    fi
  fi
  printf 'resource_scope_binding\t%s\n' 'local ResourceScope; no shared runtime ResourceDomain'
  printf 'policy_qualification_stage\t%s\n' 'profile harness; no global or tenant ResourceDomain binding'
  printf 'mode\t%s\n' "$mode"
  printf 'rate_per_second\t%s\n' "$rate"
  printf 'average_rate_per_second\t%s\n' "$rate"
  if [[ "$profile" == burst && "$mode" == open_loop ]]; then
    printf 'pulse_rate_per_second\t%s\n' "$((rate * 4))"
  elif [[ "$profile" == burst ]]; then
    printf 'pulse_rate_per_second\tbacklogged_capacity\n'
    printf 'capacity_pulse_ns\t250000000\n'
    printf 'capacity_idle_ns\t750000000\n'
  else
    printf 'pulse_rate_per_second\t%s\n' "$rate"
  fi
  printf 'requested_arrivals\t%s\n' "$arrivals"
  printf 'trace_deadline_seconds\t%s\n' "$trace_deadline"
  printf 'phase_trace_seconds\t%s\n' "$phase_trace"
  printf 'phase_trace_deadline_seconds\t%s\n' "$phase_trace_deadline"
  printf 'drain_deadline_seconds\t%s\n' "$drain_deadline"
  printf 'shutdown_deadline_seconds\t%s\n' "$shutdown_deadline"
  printf 'process_deadline_seconds\t%s\n' "$process_deadline"
  printf 'oracle_file\t%s\n' "$oracle_file"
  printf 'oracle_sha256\t%s\n' "$oracle_digest_actual"
  printf 'setup_deadline_seconds\t120\n'
  printf 'process_deadline_policy\t%s\n' 'setup reserve + trace + drain + one shutdown budget per bounded driver phase'
  printf 'cpu_set\t%s\n' "$cpu_set"
  printf 'source_head\t%s\n' "$head_commit"
  printf 'source_tree_sha256\t%s\n' "$source_digest"
  printf 'source_inventory_schema\t%s\n' "$source_inventory_schema"
  printf 'source_inventory_module_sha256\t%s\n' "$source_inventory_module_sha256_before"
printf 'binary_path\t%s\n' "$binary"
printf 'binary_sha256\t%s\n' "$binary_digest"
  printf 'runtime_bindings_sha256_before\t%s\n' "$runtime_bindings_sha_expected"
  printf 'runtime_validator_sha256_before\t%s\n' "$runtime_validator_sha_expected"
  printf 'fixed_global_control_baseline\t%s\n' "$fixed_global_control_baseline_arg"
printf 'baseline_binary_path\t%s\n' "$baseline_binary"
printf 'baseline_binary_sha256\t%s\n' "$baseline_binary_digest"
  printf 'host\t%s\n' "$host"
  printf 'kernel\t%s\n' "$kernel"
  printf 'rustc\t%s\n' "$rust_version"
  if command -v lscpu >/dev/null; then
    printf 'cpu_model\t%s\n' "$(lscpu | awk -F: '/Model name/ {sub(/^[[:space:]]+/, "", $2); print $2; exit}')"
  fi
  printf 'governor\t%s\n' "$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || printf unavailable)"
  printf 'argv_policy\t%s\n' 'one fresh process; external timeout is hard whole-process watchdog; binary process budget starts at setup; taskset applied to each process'
} > "$cell_dir/metadata.tsv"

printf 'pair\texecutor\tallocator\texit_code\trow_validation\tp99_qualification\targv\tstdout\ttime_report\tids_sha256\tshutdown_sha256\tcapacity_family_sha256\tstdout_sha256\truntime_readback\truntime_readback_sha256\truntime_expectation\truntime_expectation_sha256\truntime_validation\truntime_validation_sha256\truntime_recipe_sha256\tresource_ceiling_sha256\tpolicy_sha256\tfixed_global_control_baseline\tvalidator_sha256\tsource_manifest_sha256\tcalibration_binary_sha256\tcalibration_output_sha256\n' > "$cell_dir/processes.tsv"
failed=0

validate_output() {
  local output=$1 expected_executor=$2 expected_allocator=$3 header
  local expected_schema=2
  local expected_async=4
  [[ "$profile" == oversubscribed ]] && expected_async=2
  local expected_blocking=0 expected_topology="$expected_async async workers" expected_task_limit=8
  local expected_retained=0 expected_managed=0 expected_disk=0 expected_network=0
  case "$workload" in
    memory) expected_retained=8; expected_managed=163840 ;;
    http)
      expected_schema=http-nonblocking-connect-v1
      expected_blocking=1 expected_task_limit=17 expected_managed=141312 expected_network=16
      if [[ "$expected_executor" == allocatbelt ]]; then
        expected_topology="$expected_async async + 1 owning blocking connector + owning reactor; NetHandle::connect_nonblocking"
      else
        expected_topology="$expected_async async + 1 reserved blocking worker (Tokio TcpSocket::connect) + integrated I/O driver"
      fi
      ;;
    disk)
      expected_blocking=$expected_async expected_managed=1573000 expected_disk=8
      if [[ "$expected_executor" == allocatbelt ]]; then
        expected_topology="$expected_async async + $expected_async filesystem workers"
      else
        expected_topology="$expected_async async + $expected_async blocking workers"
      fi
      ;;
    mixed)
      expected_schema=mixed-application-v1
      expected_blocking=$expected_async expected_task_limit=17
      expected_retained=8 expected_managed=1638536 expected_disk=8 expected_network=16
      if [[ "$expected_executor" == allocatbelt ]]; then
        expected_topology="$expected_async async + $expected_async owning blocking workers (connector and filesystem) + owning reactor"
      else
        expected_topology="$expected_async async + Tokio blocking pool max$expected_async (filesystem execution cap$expected_async) + integrated I/O driver"
      fi
      ;;
  esac
  local expected_header='schema	allocator	executor	workload	mode	async_workers	blocking_workers	topology	logical_window	global_task_limit	retained_window	arrival_rate_per_second	requested_arrivals	attempted	admitted	rejected_full	rejected_resource	completed_on_time	completed_late	errors	cancellations	unresolved	lost	result_digest	expected_digest	capacity_publications_per_second	successful_throughput_through_drain_per_second	setup_ns	timer_pair_median_ns	wall_through_drain_ns	drain_tail_ns	response_p50_ns	response_p95_ns	response_p99_ns	producer_lateness_mean_ns	producer_lateness_max_ns	max_observed_managed_bytes	retained_managed_bytes	managed_limit_bytes	disk_limit_ops	network_limit_ops	final_managed_bytes	final_disk_ops	final_network_ops	rss_before_kib	rss_after_drain_kib	rss_after_shutdown_kib	hwm_before_kib	hwm_after_drain_kib	hwm_after_shutdown_kib	shutdown_ns	rejected_logical_window	rejected_backend_full'
  [[ $(wc -l < "$output") -eq 2 ]] || return 1
  header=$(sed -n '1p' "$output")
  [[ "$header" == "$expected_header" ]] || return 1
  python3 - "$output" "$expected_header" "$expected_allocator" "$expected_executor" "$workload" "$mode" \
    "$rate" "$expected_blocking" "$expected_topology" "$expected_task_limit" \
    "$expected_retained" "$expected_managed" "$expected_disk" "$expected_network" \
    "$expected_schema" "$arrivals" "$process_deadline" "$drain_deadline" "$expected_async" <<'PY'
import re
import sys
from decimal import Decimal, InvalidOperation
from pathlib import Path

(
    path, expected_header, allocator, executor, workload, mode, rate,
    blocking, topology, task_limit, retained, managed, disk, network, expected_schema, arrivals, process_seconds, drain_seconds, expected_async,
) = sys.argv[1:]
lines = Path(path).read_text(encoding="utf-8").splitlines()
headers = expected_header.split("\t")
if len(headers) != 53 or len(set(headers)) != 53 or lines[0] != expected_header:
    raise SystemExit(1)
values = lines[1].split("\t")
if len(values) != len(headers):
    raise SystemExit(1)
row = dict(zip(headers, values, strict=True))
if (row["schema"], row["allocator"], row["executor"], row["workload"], row["mode"]) != (
    expected_schema, allocator, executor, workload, mode,
):
    raise SystemExit(1)

integer_fields = """async_workers blocking_workers logical_window global_task_limit
retained_window requested_arrivals attempted admitted rejected_full rejected_logical_window
rejected_backend_full rejected_resource
completed_on_time completed_late errors cancellations unresolved lost result_digest
expected_digest setup_ns timer_pair_median_ns wall_through_drain_ns drain_tail_ns
response_p50_ns response_p95_ns response_p99_ns producer_lateness_mean_ns
producer_lateness_max_ns max_observed_managed_bytes retained_managed_bytes
managed_limit_bytes disk_limit_ops network_limit_ops final_managed_bytes final_disk_ops
final_network_ops rss_before_kib rss_after_drain_kib rss_after_shutdown_kib hwm_before_kib
hwm_after_drain_kib hwm_after_shutdown_kib shutdown_ns""".split()
integer_fields.remove("requested_arrivals")
u64_fields = {"result_digest", "expected_digest"}
for field in integer_fields:
    value = row[field]
    if not re.fullmatch(r"(?:0|[1-9][0-9]*)", value):
        raise SystemExit(1)
    number = int(value)
    maximum = (1 << 64) - 1 if field in u64_fields else (1 << 53) - 1
    if number > maximum:
        raise SystemExit(1)

decimal_fields = ("capacity_publications_per_second", "successful_throughput_through_drain_per_second")
decimals = {}
for field in decimal_fields:
    value = row[field]
    if field == "capacity_publications_per_second" and mode == "open_loop" and value == "":
        continue
    if not re.fullmatch(r"(?:0|[1-9][0-9]*)(?:\.[0-9]+)?", value):
        raise SystemExit(1)
    try:
        number = Decimal(value)
    except InvalidOperation:
        raise SystemExit(1)
    if not number.is_finite() or number < 0 or number > Decimal("1000000000"):
        raise SystemExit(1)
    decimals[field] = number

expected_policy = {
    "async_workers": expected_async, "blocking_workers": blocking, "topology": topology,
    "logical_window": "8", "global_task_limit": task_limit,
    "retained_window": retained, "managed_limit_bytes": managed,
    "disk_limit_ops": disk, "network_limit_ops": network,
}
if any(row[field] != expected for field, expected in expected_policy.items()):
    raise SystemExit(1)

attempted = int(row["attempted"])
admitted = int(row["admitted"])
rejected_full = int(row["rejected_full"])
rejected_resource = int(row["rejected_resource"])
completed_on_time = int(row["completed_on_time"])
completed_late = int(row["completed_late"])
completed = completed_on_time + completed_late
errors = int(row["errors"])
cancellations = int(row["cancellations"])
unresolved = int(row["unresolved"])
if attempted > (10_000_000 if mode == "capacity" else int(arrivals)):
    raise SystemExit(1)
if any(number > attempted for number in (
    admitted, rejected_full, rejected_resource, completed_on_time, completed_late,
    errors, cancellations, unresolved, int(row["lost"]),
)):
    raise SystemExit(1)
if attempted != admitted + rejected_full + rejected_resource:
    raise SystemExit(1)
if rejected_full != int(row["rejected_logical_window"]) + int(row["rejected_backend_full"]):
    raise SystemExit(1)
if admitted != completed + errors + cancellations + unresolved:
    raise SystemExit(1)
if int(row["lost"]) != attempted - completed:
    raise SystemExit(1)
if row["result_digest"] != row["expected_digest"]:
    raise SystemExit(1)
if errors or cancellations or unresolved:
    raise SystemExit(1)
if any(int(row[field]) != 0 for field in ("final_managed_bytes", "final_disk_ops", "final_network_ops")):
    raise SystemExit(1)
if workload in ("memory", "http", "mixed") and int(row["max_observed_managed_bytes"]) > int(managed):
    raise SystemExit(1)
if workload in ("memory", "http", "mixed") and int(row["retained_managed_bytes"]) > int(managed):
    raise SystemExit(1)

if mode == "capacity":
    if row["arrival_rate_per_second"] or row["requested_arrivals"] or rejected_full or rejected_resource or int(row["lost"]):
        raise SystemExit(1)
    if attempted <= 0 or completed_on_time <= 0:
        raise SystemExit(1)
    if int(row["response_p50_ns"]) or int(row["response_p95_ns"]) or int(row["response_p99_ns"]):
        raise SystemExit(1)
    expected_capacity = Decimal(completed_on_time) / Decimal(30)
    actual_capacity = decimals["capacity_publications_per_second"]
    if abs(actual_capacity - expected_capacity) > max(Decimal("0.00000001"), expected_capacity * Decimal("0.00000001")):
        raise SystemExit(1)
else:
    if not re.fullmatch(r"[1-9][0-9]*", row["arrival_rate_per_second"]):
        raise SystemExit(1)
    if int(row["arrival_rate_per_second"]) != int(rate) or row["requested_arrivals"] != arrivals or attempted != int(arrivals):
        raise SystemExit(1)
    if int(row["response_p50_ns"]) > int(row["response_p95_ns"]) or int(row["response_p95_ns"]) > int(row["response_p99_ns"]):
        raise SystemExit(1)

wall_ns = int(row["wall_through_drain_ns"])
if wall_ns <= 0 or wall_ns > int(process_seconds) * 1_000_000_000 or int(row["drain_tail_ns"]) > int(drain_seconds) * 1_000_000_000:
    raise SystemExit(1)
expected_drained = Decimal(completed) * Decimal(1_000_000_000) / Decimal(wall_ns)
actual_drained = decimals["successful_throughput_through_drain_per_second"]
if abs(actual_drained - expected_drained) > max(Decimal("0.00000001"), expected_drained * Decimal("0.00000001")):
    raise SystemExit(1)

time_fields = (
    "setup_ns", "timer_pair_median_ns", "wall_through_drain_ns", "drain_tail_ns",
    "response_p50_ns", "response_p95_ns", "response_p99_ns",
    "producer_lateness_mean_ns", "producer_lateness_max_ns", "shutdown_ns",
)
if any(int(row[field]) > int(process_seconds) * 1_000_000_000 for field in time_fields):
    raise SystemExit(1)
if int(row["drain_tail_ns"]) > int(drain_seconds) * 1_000_000_000:
    raise SystemExit(1)
if any(int(row[field]) > (1 << 53) - 1 for field in (
    "rss_before_kib", "rss_after_drain_kib", "rss_after_shutdown_kib",
    "hwm_before_kib", "hwm_after_drain_kib", "hwm_after_shutdown_kib",
)):
    raise SystemExit(1)
PY
}

validate_shutdown_report() {
  local report=$1 expected_executor=$2 trace_seconds=$3 shutdown_seconds=$4 process_seconds=$5 output=$6 report_nonce=$7 run_id=$8 allocator=$9 profile=${10} source_hash=${11} binary_hash=${12}
  python3 - "$report" "$expected_executor" "$workload" "$mode" "$trace_seconds" "$shutdown_seconds" "$process_seconds" "$output" "$report_nonce" "$run_id" "$allocator" "$profile" "$source_hash" "$binary_hash" <<'PY'
import re
import sys
from pathlib import Path

path, executor, workload, mode, trace_seconds, shutdown_seconds, process_seconds, output, nonce, run_id, allocator, profile, source_hash, binary_hash = sys.argv[1:]
try:
    lines = Path(path).read_text(encoding="utf-8").splitlines()
except OSError:
    raise SystemExit(1)
if not lines or lines[0] != "schema\tallocatbelt-app-phase-v1\t":
    raise SystemExit(1)
identity = [line.split("\t") for line in lines[1:9]]
expected_identity = [
    ["identity", "report_nonce", nonce], ["identity", "run_id", run_id],
    ["identity", "executor", executor], ["identity", "allocator", allocator],
    ["identity", "workload", workload], ["identity", "profile", profile],
    ["identity", "source_sha256", source_hash], ["identity", "binary_sha256", binary_hash],
]
if identity != expected_identity:
    raise SystemExit(1)
if executor == "allocatbelt":
    drivers = ["allocatbelt owning HTTP runtime"] if workload in ("http", "mixed") else ["allocatbelt application driver"]
else:
    drivers = ["Tokio HTTP runtime", "Tokio fixed rate timer"] if workload in ("http", "mixed") else ["Tokio runtime"]
if len(lines) != len(drivers) + 15:
    raise SystemExit(1)
phase_rows = [line.split("\t") for line in lines[9:15]]
phase_names = ["production_trace", "production_cpu_started_ns", "production_cpu_ended_ns", "production_through_drain_cpu_ns", "successful_completions", "cpu_ns_per_successful_completion"]
if any(len(row) != 3 or row[:2] != ["phase", name] for row, name in zip(phase_rows, phase_names, strict=True)):
    raise SystemExit(1)
if any(not re.fullmatch(r"(?:0|[1-9][0-9]*)", row[2]) for row in phase_rows):
    raise SystemExit(1)
trace_ns = int(phase_rows[0][2])
if mode == "capacity":
    if not 30_000_000_000 <= trace_ns <= min(int(trace_seconds) * 1_000_000_000, 31_000_000_000):
        raise SystemExit(1)
else:
    if trace_ns > int(trace_seconds) * 1_000_000_000:
        raise SystemExit(1)
started, ended, cpu_ns, successes = (int(phase_rows[index][2]) for index in (1, 2, 3, 4))
if ended < started or ended - started != cpu_ns or cpu_ns > int(process_seconds) * 128 * 1_000_000_000:
    raise SystemExit(1)
if int(phase_rows[5][2]) != (cpu_ns // successes if successes else 0):
    raise SystemExit(1)
try:
    output_rows = Path(output).read_text(encoding="utf-8").splitlines()
    output_header = output_rows[0].split("\t")
    output_row = output_rows[1].split("\t")
except (OSError, IndexError):
    raise SystemExit(1)
expected_successes = int(output_row[output_header.index("completed_on_time")]) + int(output_row[output_header.index("completed_late")])
if successes != expected_successes:
    raise SystemExit(1)
if mode == "capacity" and (successes <= 0 or int(output_row[output_header.index("completed_on_time")]) <= 0):
    raise SystemExit(1)
for line, expected in zip(lines[15:], drivers, strict=True):
    row = line.split("\t")
    if len(row) != 3 or row[:2] != ["driver", expected]:
        raise SystemExit(1)
    if not re.fullmatch(r"(?:0|[1-9][0-9]*)", row[2]) or int(row[2]) > int(shutdown_seconds) * 1_000_000_000:
        raise SystemExit(1)
PY
}

validate_oracle_file() {
  local oracle=$1 expected_count=$2 expected_rate=$3 expected_workload=$4 expected_profile=$5 source_hash=$6 binary_hash=$7
  python3 - "$oracle" "$expected_count" "$expected_rate" "$expected_workload" "$expected_profile" "$source_hash" "$binary_hash" <<'PY'
import re
import sys
from pathlib import Path

path, expected_count, expected_rate, expected_workload, expected_profile, source_hash, binary_hash = sys.argv[1:]
try:
    lines = Path(path).read_text(encoding="utf-8").splitlines()
except OSError:
    raise SystemExit(1)
configs = {
    "cpu": "rounds=50000",
    "memory": "initial_bytes=4096;grown_bytes=8192;seed=0x243f6a8885a308d3",
    "disk": "bytes=196625;offset=4096;seed=0xa4093822299f31d0",
    "http": "body_bytes=4096",
    "mixed": "interleave=cpu,memory,http,disk",
}

rate = int(expected_rate)
count = int(expected_count)
pulse_rate = rate * 4 if expected_profile == "burst" else rate
duration_ns = ((count + rate - 1) // rate) * 1_000_000_000 if expected_profile == "burst" else count * 1_000_000_000 // rate
expected_header = [
    "schema\tallocatbelt-app-oracle-v2",
    f"source_sha256\t{source_hash}",
    f"binary_sha256\t{binary_hash}",
    f"profile\t{expected_profile}",
    f"workload\t{expected_workload}",
    "mode\topen_loop",
    f"average_rate_per_second\t{rate}",
    f"pulse_rate_per_second\t{pulse_rate}",
    f"arrivals\t{count}",
    f"trace_duration_ns\t{duration_ns}",
    f"kernel_config\t{configs[expected_workload]}",
    "id\tscheduled_ns\tworkload\texpected_checksum",
]
if len(lines) != count + len(expected_header) or lines[:len(expected_header)] != expected_header:
    raise SystemExit(1)
family = ("cpu", "memory", "http", "disk")
for expected_id, line in enumerate(lines[len(expected_header):]):
    fields = line.split("\t")
    if len(fields) != 4 or fields[0] != str(expected_id):
        raise SystemExit(1)
    if expected_profile == "burst":
        cycle, slot = divmod(expected_id, rate)
        scheduled = cycle * 1_000_000_000 + slot * 250_000_000 // rate
    else:
        scheduled = expected_id * 1_000_000_000 // rate
    expected_family = family[expected_id % 4] if expected_workload == "mixed" else expected_workload
    if fields[1] != str(scheduled) or fields[2] != expected_family:
        raise SystemExit(1)
    if not re.fullmatch(r"(?:0|[1-9][0-9]*)", fields[3]) or int(fields[3]) >= (1 << 64):
        raise SystemExit(1)
PY
}

validate_capacity_family_report() {
  local report=$1 output=$2 expected_executor=$3 report_nonce=$4 run_id=$5 allocator=$6 profile=$7 source_hash=$8 binary_hash=$9
  python3 - "$report" "$output" "$expected_executor" "$report_nonce" "$run_id" "$allocator" "$workload" "$profile" "$source_hash" "$binary_hash" <<'PY'
import re
import sys
from pathlib import Path

path, output, executor, nonce, run_id, allocator, workload, profile, source_hash, binary_hash = sys.argv[1:]
try:
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    output_lines = Path(output).read_text(encoding="utf-8").splitlines()
except OSError:
    raise SystemExit(1)
if not lines or lines[0] != "schema\tallocatbelt-app-capacity-families-v1\t":
    raise SystemExit(1)
expected = {
    "report_nonce": nonce, "run_id": run_id, "executor": executor, "allocator": allocator,
    "workload": workload, "profile": profile, "source_sha256": source_hash, "binary_sha256": binary_hash,
}
identity = {}
families = {}
phases = {}
for line in lines[1:]:
    row = line.split("\t")
    if len(row) == 3 and row[0] == "identity":
        if row[1] in identity:
            raise SystemExit(1)
        identity[row[1]] = row[2]
    elif len(row) == 4 and row[0] == "family":
        if row[1] in families:
            raise SystemExit(1)
        families[row[1]] = row[2:]
    elif len(row) == 3 and row[0] == "phase":
        if row[1] in phases:
            raise SystemExit(1)
        phases[row[1]] = row[2]
    else:
        raise SystemExit(1)
if identity != expected or set(families) != {"cpu", "memory", "http", "disk"}:
    raise SystemExit(1)
if phases != {"trace_seconds": "30", "profile": profile}:
    raise SystemExit(1)
columns = output_lines[0].split("\t")
row = output_lines[1].split("\t")
counts = dict(zip(columns, row, strict=True))
if counts["workload"] != "mixed" or counts["mode"] != "capacity":
    raise SystemExit(1)
attempted = int(counts["attempted"])
completed_on_time = int(counts["completed_on_time"])
if attempted <= 0 or completed_on_time <= 0:
    raise SystemExit(1)
if sum(int(values[0]) for values in families.values()) != attempted or sum(int(values[1]) for values in families.values()) != completed_on_time:
    raise SystemExit(1)
for index, family in enumerate(("cpu", "memory", "http", "disk")):
    scheduled, successes = families[family]
    if not re.fullmatch(r"(?:0|[1-9][0-9]*)", scheduled) or not re.fullmatch(r"(?:0|[1-9][0-9]*)", successes):
        raise SystemExit(1)
    expected_count = attempted // 4 + (1 if index < attempted % 4 else 0)
    if int(scheduled) != expected_count or int(successes) <= 0 or int(successes) > int(scheduled):
        raise SystemExit(1)
PY
}

validate_id_report() {
  local report=$1 expected_count=$2 process_seconds=$3 trace_seconds=$4 rate=$5 workload=$6 profile=$7 output=$8
  local oracle=$9 oracle_digest=${10} run_id=${11} nonce=${12} executor=${13} allocator=${14} source_hash=${15} binary_hash=${16}
  python3 - "$report" "$expected_count" "$process_seconds" "$trace_seconds" "$rate" "$workload" "$profile" "$output" \
    "$oracle" "$oracle_digest" "$run_id" "$nonce" "$executor" "$allocator" "$source_hash" "$binary_hash" <<'PY'
import re
import sys
import hashlib
from pathlib import Path

(
    path, expected_count, process_seconds, trace_seconds, rate, workload, profile, output,
    oracle_path, oracle_digest, run_id, nonce, executor, allocator, source_hash, binary_hash,
) = sys.argv[1:]
try:
    lines = Path(path).read_text(encoding="utf-8").splitlines()
except OSError:
    raise SystemExit(1)
if len(lines) < 3 or lines[0] != "schema\tallocatbelt-app-arrivals-v3":
    raise SystemExit(1)
identity = lines[1].split("\t")
if identity != ["identity", nonce, run_id, executor, allocator, workload, profile, source_hash, binary_hash]:
    raise SystemExit(1)
if lines[2] != "id\tworkload\tscheduled_ns\tcompletion_ns\tterminal\tchecksum\texpected_checksum":
    raise SystemExit(1)
if len(lines) != int(expected_count) + 3:
    raise SystemExit(1)
oracle_bytes = Path(oracle_path).read_bytes()
if hashlib.sha256(oracle_bytes).hexdigest() != oracle_digest:
    raise SystemExit(1)
oracle_lines = oracle_bytes.decode("utf-8").splitlines()
oracle_start = 12
if len(oracle_lines) != int(expected_count) + oracle_start:
    raise SystemExit(1)
oracle_rows = []
families = ("cpu", "memory", "http", "disk")
for expected_id, line in enumerate(oracle_lines[oracle_start:]):
    fields = line.split("\t")
    if len(fields) != 4 or fields[0] != str(expected_id):
        raise SystemExit(1)
    if not re.fullmatch(r"(?:0|[1-9][0-9]*)", fields[1]) or not re.fullmatch(r"(?:0|[1-9][0-9]*)", fields[3]) or int(fields[3]) >= (1 << 64):
        raise SystemExit(1)
    oracle_rows.append((int(fields[1]), fields[2], int(fields[3])))
max_ns = int(process_seconds) * 1_000_000_000
trace_ns = int(oracle_lines[9].split("\t")[1])
allowed = {"completed", "rejected"}
digest = expected_digest = 0
latencies = []
counts = {family: 0 for family in families}
terminals = {"completed": 0, "rejected": 0, "error": 0}
for expected_id, line in enumerate(lines[3:]):
    fields = line.split("\t")
    if len(fields) != 7:
        raise SystemExit(1)
    if fields[0] != str(expected_id):
        raise SystemExit(1)
    if fields[1] != oracle_rows[expected_id][1] or any(not re.fullmatch(r"(?:0|[1-9][0-9]*)", field) for field in fields[2:4] + fields[5:]):
        raise SystemExit(1)
    scheduled, completed, checksum, expected_checksum = (int(fields[2]), int(fields[3]), int(fields[5]), int(fields[6]))
    if scheduled != oracle_rows[expected_id][0] or expected_checksum != oracle_rows[expected_id][2] or completed < scheduled or completed > max_ns or scheduled >= trace_ns:
        raise SystemExit(1)
    terminal = fields[4]
    if terminal not in ("completed", "rejected", "error"):
        raise SystemExit(1)
    if checksum >= (1 << 64):
        raise SystemExit(1)
    terminals[terminal] += 1
    counts[fields[1]] += int(terminal == "completed")
    if terminal == "rejected":
        if checksum != 0:
            raise SystemExit(1)
    elif terminal == "completed":
        if checksum != expected_checksum:
            raise SystemExit(1)
        latencies.append(completed - scheduled)
        digest = (digest + (checksum if workload == "http" else checksum ^ expected_id)) % (1 << 64)
        expected_digest = (expected_digest + (expected_checksum if workload == "http" else expected_checksum ^ expected_id)) % (1 << 64)
try:
    output_lines = Path(output).read_text(encoding="utf-8").splitlines()
except OSError:
    raise SystemExit(1)
header = output_lines[0].split("\t")
row = output_lines[1].split("\t")
if len(header) != 53 or len(row) != 53:
    raise SystemExit(1)
output_row = dict(zip(header, row, strict=True))
if digest != int(output_row["result_digest"]) or expected_digest != int(output_row["expected_digest"]):
    raise SystemExit(1)
completed_count = terminals["completed"]
rejected = terminals["rejected"]
errors = terminals["error"]
if completed_count + errors != int(output_row["admitted"]) or rejected != int(output_row["rejected_full"]) + int(output_row["rejected_resource"]):
    raise SystemExit(1)
if int(output_row["attempted"]) != int(expected_count) or completed_count + errors + rejected != int(expected_count):
    raise SystemExit(1)
on_time = sum(1 for line in lines[3:] if line.split("\t")[4] == "completed" and int(line.split("\t")[3]) <= trace_ns)
if on_time != int(output_row["completed_on_time"]) or completed_count - on_time != int(output_row["completed_late"]) or errors != int(output_row["errors"]):
    raise SystemExit(1)
latencies.sort()
def percentile(values, p):
    if not values:
        return 0
    rank = max(1, (p * len(values) + 99) // 100)
    return values[rank - 1]
for field, p in (("response_p50_ns", 50), ("response_p95_ns", 95), ("response_p99_ns", 99)):
    if int(output_row[field]) != percentile(latencies, p):
        raise SystemExit(1)
PY
}

if [[ "$mode" == open_loop ]]; then
  generated_oracle="$cell_dir/canonical-oracle.tsv"
  if ! timeout --foreground --signal=TERM --kill-after=3s "${process_deadline}s" "$binary" --emit-oracle-only "$generated_oracle" \
    --source-sha256 "$source_digest" --binary-sha256 "$binary_digest" \
    --workload "$workload" --profile "$profile" --rate "$rate" --arrivals "$arrivals" \
    --trace-deadline-seconds "$trace_deadline" \
    > "$cell_dir/oracle-generator.stdout.txt" 2> "$cell_dir/oracle-generator.stderr.txt"; then
    echo "canonical oracle generation failed before timing" >&2
    printf 'pair_status\tfailed_or_invalid\nexecution_scope\t%s\n' "$execution_scope" > "$cell_dir/pair.failed"
    exit 1
  fi
  generated_oracle_digest=$(stable_sha256 "$generated_oracle" 16777216) || exit 2
  if [[ "$generated_oracle_digest" != "$oracle_digest_expected" ]] || ! cmp -s "$oracle_file" "$generated_oracle"; then
    echo "manifest oracle differs from the pinned source and binary kernels" >&2
    printf 'pair_status\tfailed_or_invalid\nexecution_scope\t%s\n' "$execution_scope" > "$cell_dir/pair.failed"
    exit 1
  fi
fi
if [[ "$mode" == open_loop ]] && ! validate_oracle_file "$oracle_file" "$arrivals" "$rate" "$workload" "$profile" "$source_digest" "$binary_digest"; then
  echo "oracle content does not match the frozen workload, rate, or arrival manifest" >&2
  printf 'pair_status\tfailed_or_invalid\nexecution_scope\t%s\n' "$execution_scope" > "$cell_dir/pair.failed"
  exit 1
fi
if [[ "$mode" == open_loop && ( "$pair_kind" == allocator-match || "$pair_kind" == pressure-allocator-match ) ]] && ! validate_oracle_file "$baseline_oracle_file" "$arrivals" "$rate" "$workload" "$profile" "$source_digest" "$baseline_binary_digest"; then
  echo "baseline oracle content does not match its frozen binary and workload" >&2
  printf 'pair_status\tfailed_or_invalid\nexecution_scope\t%s\n' "$execution_scope" > "$cell_dir/pair.failed"
  exit 1
fi

verify_functional_tmpdir() {
  local path=$1 state=$2
  python3 - "$path" "$functional_tmp_root_path" "$functional_tmp_context_json" "$state" <<'PY'
import json
import os
import re
import stat
import sys
from pathlib import Path

path_text, root_text, expected_raw, state = sys.argv[1:]
def fail():
    raise SystemExit(1)
def unescape(value):
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), value)
def context(path):
    resolved = Path(path).resolve(strict=True)
    info = resolved.stat()
    selected = None
    raw = Path("/proc/self/mountinfo").read_bytes()
    if len(raw) > 2 * 1024 * 1024:
        fail()
    for line in raw.decode("utf-8", errors="strict").splitlines():
        left, separator, right = line.partition(" - ")
        if not separator:
            continue
        before = left.split()
        after = right.split()
        if len(before) < 5 or len(after) < 2:
            continue
        mount = unescape(before[4])
        if resolved == Path(mount) or Path(mount) in resolved.parents:
            current = (len(mount), mount, after[0], after[1], before[2])
            if selected is None or current[0] > selected[0]:
                selected = current
    if selected is None:
        fail()
    _length, mount, fs_type, source, device = selected
    return {"path": str(resolved), "mount_point": mount, "filesystem_type": fs_type,
            "source": source, "mount_device": device, "st_dev": info.st_dev,
            "free_bytes": os.statvfs(resolved).f_bavail * os.statvfs(resolved).f_frsize}
try:
    path = Path(path_text)
    root = Path(root_text).resolve(strict=True)
    if path.is_symlink() or not path.is_dir() or path.resolve(strict=True).parent != root:
        fail()
    expected = json.loads(expected_raw)
    actual = context(path)
    for key in ("mount_point", "filesystem_type", "source", "mount_device", "st_dev"):
        if actual[key] != expected[key]:
            fail()
    if actual["filesystem_type"] in ("tmpfs", "ramfs"):
        fail()
    if actual["free_bytes"] < 256 * 1024 * 1024:
        fail()
    entries = list(path.iterdir())
    if state in ("initial", "after") and entries:
        fail()
    if any(entry.is_symlink() for entry in entries):
        fail()
    print(json.dumps(actual, sort_keys=True, separators=(",", ":")))
except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
    fail()
PY
}

run_one() {
  local pair=$1 executor=$2 process_allocator=$3 process_binary_arg=$4 process_oracle_arg=$5 process_oracle_sha_expected=$6
  local expected_executor=tokio-1.53.1
  [[ "$executor" == bounded ]] && expected_executor=allocatbelt
  local process_binary
  process_binary=$(realpath "$process_binary_arg") || { failed=1; return 1; }
  [[ -x "$process_binary" ]] || { failed=1; return 1; }
  local process_binary_sha
  process_binary_sha=$(stable_sha256 "$process_binary") || { failed=1; return 1; }
  local process_oracle_file= process_oracle_digest=
  if [[ "$mode" == open_loop ]]; then
    process_oracle_file=$(realpath "$process_oracle_arg") || { failed=1; return 1; }
    [[ -f "$process_oracle_file" ]] || { failed=1; return 1; }
    process_oracle_digest=$(stable_sha256 "$process_oracle_file" 16777216) || { failed=1; return 1; }
    [[ "$process_oracle_digest" == "$process_oracle_sha_expected" ]] || { failed=1; return 1; }
    validate_oracle_file "$process_oracle_file" "$arrivals" "$rate" "$workload" "$profile" "$source_digest" "$process_binary_sha" || { failed=1; return 1; }
  fi
  local stdout="$cell_dir/${pair}-${executor}.stdout.tsv"
  local shutdown_report="$cell_dir/${pair}-${executor}.shutdown.tsv"
  local ids_report="$cell_dir/${pair}-${executor}.ids.tsv"
  local family_report="$cell_dir/${pair}-${executor}.capacity-families.tsv"
  local process_tmpdir=not_applicable process_tmp_context_json=not_applicable process_tmp_context_after=not_applicable
  local timing="$cell_dir/${pair}-${executor}.time.txt" status validation p99_qualification=not_applicable ids_sha256=not_applicable
  local stdout_sha256=unavailable runtime_readback_path="$cell_dir/${pair}-${executor}.runtime.tsv" runtime_readback_sha256=unavailable
  local runtime_expectation_path="$cell_dir/${pair}-${executor}.expectation.json" runtime_expectation_sha256=unavailable
  local runtime_validation_path="$cell_dir/${pair}-${executor}.validation.json" runtime_validation_sha256=unavailable
  local runtime_recipe_sha256=unavailable resource_ceiling_sha256=unavailable policy_sha256=unavailable
  local fixed_global_control_baseline=unavailable validator_sha256="$runtime_validator_sha_expected"
  local source_manifest_sha256=unavailable calibration_binary_sha256=unavailable calibration_output_sha256=unavailable
  local -a args=(--executor "$executor" --workload "$workload" --profile "$profile" --mode "$mode" --trace-deadline-seconds "$trace_deadline" --drain-deadline-seconds "$drain_deadline" --shutdown-deadline-seconds "$shutdown_deadline" --process-deadline-seconds "$process_deadline")
  local report_nonce recipe_path="$cell_dir/${pair}-${executor}.recipe.json" binding_values_path="$cell_dir/${pair}-${executor}.binding-values"
  local -a runtime_binding_values=()
  if (( runtime_readback_enabled == 1 )); then
    runtime_binding_for_process "$pair" "$executor" "$process_allocator" "$process_binary_sha" "$recipe_path" > "$binding_values_path" || { failed=1; return 1; }
    mapfile -d '' -t runtime_binding_values < "$binding_values_path"
    (( ${#runtime_binding_values[@]} == 10 )) || { failed=1; return 1; }
    report_nonce=${runtime_binding_values[0]}
    runtime_recipe_sha256=${runtime_binding_values[1]}
    local planned_expectation_sha=${runtime_binding_values[2]}
    resource_ceiling_sha256=${runtime_binding_values[3]}
    policy_sha256=${runtime_binding_values[4]}
    fixed_global_control_baseline=${runtime_binding_values[5]}
    source_manifest_sha256=${runtime_binding_values[6]}
    calibration_binary_sha256=${runtime_binding_values[7]}
    calibration_output_sha256=${runtime_binding_values[8]}
    validator_sha256=${runtime_binding_values[9]}
    [[ "$report_nonce" =~ ^[0-9a-f]{32}$ ]] || { failed=1; return 1; }
    python3 -B "$runtime_validator_arg" --build-expectation "$recipe_path" --output "$runtime_expectation_path" > "$cell_dir/${pair}-${executor}.expectation-build.json" || { failed=1; return 1; }
    runtime_expectation_sha256=$(stable_sha256 "$runtime_expectation_path" 131072) || { failed=1; return 1; }
    [[ "$runtime_expectation_sha256" == "$planned_expectation_sha" ]] || { failed=1; return 1; }
  else
    echo "a scheduled runtime process recipe is required before a fixed-policy process can run" >&2
    failed=1
    return 1
  fi
  if (( functional_source_v4_mode == 1 )); then
    process_tmpdir="$functional_tmp_root_path/${pair}-${executor}"
    [[ ! -e "$process_tmpdir" && ! -L "$process_tmpdir" ]] || { failed=1; return 1; }
    mkdir -m 700 -- "$process_tmpdir" || { failed=1; return 1; }
    process_tmp_context_json=$(verify_functional_tmpdir "$process_tmpdir" initial) || { failed=1; return 1; }
  fi
  if [[ "$mode" == open_loop ]]; then args+=(--rate "$rate" --arrivals "$arrivals"); fi
  local -a process_tmp_env=()
  if (( functional_source_v4_mode == 1 )); then process_tmp_env+=("TMPDIR=$process_tmpdir"); fi
  local -a command=(taskset -c "$cpu_set" /usr/bin/time -v -o "$timing" timeout --foreground --signal=TERM --kill-after=3s "${process_deadline}s" env "${process_tmp_env[@]}" "ALLOCATBELT_APP_SHUTDOWN_REPORT=$shutdown_report" "ALLOCATBELT_APP_ID_REPORT=$ids_report" "ALLOCATBELT_APP_FAMILY_REPORT=$family_report" "ALLOCATBELT_APP_RUNTIME_REPORT=$runtime_readback_path" "ALLOCATBELT_APP_COMPARISON_FAMILY=fixed_policy" "ALLOCATBELT_APP_RESOURCE_CEILING_SHA256=$resource_ceiling_sha256" "ALLOCATBELT_APP_POLICY_SHA256=$policy_sha256" "ALLOCATBELT_APP_REPORT_NONCE=$report_nonce" "ALLOCATBELT_APP_RUN_ID=$run_id" "ALLOCATBELT_APP_EXECUTOR=$expected_executor" "ALLOCATBELT_APP_ALLOCATOR=$process_allocator" "ALLOCATBELT_APP_WORKLOAD=$workload" "ALLOCATBELT_APP_PROFILE=$profile" "ALLOCATBELT_APP_SOURCE_SHA256=$source_digest" "ALLOCATBELT_APP_BINARY_SHA256=$process_binary_sha" "ALLOCATBELT_APP_ORACLE_FILE=$process_oracle_file" "ALLOCATBELT_APP_ORACLE_SHA256=$process_oracle_digest" "$process_binary" "${args[@]}")
  local argv
  argv=$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1:], separators=(",", ":")))' "${command[@]}") || { failed=1; return 1; }
  set +e
  if (( functional_only_mode == 1 )); then
    (
      [[ "$(ulimit -Sf)" == "$functional_file_size_limit_blocks" && "$(ulimit -Hf)" == "$functional_file_size_limit_blocks" ]] || exit 125
      exec "${command[@]}"
    ) > "$stdout" 2> "$cell_dir/${pair}-${executor}.stderr.txt"
  else
    "${command[@]}" > "$stdout" 2> "$cell_dir/${pair}-${executor}.stderr.txt"
  fi
  status=$?
  set -e
  if (( functional_source_v4_mode == 1 )); then
    process_tmp_context_after=$(verify_functional_tmpdir "$process_tmpdir" after) || { failed=1; process_tmp_context_after=invalid; }
  fi
  validation=invalid
  local runtime_validation_status=1
  if [[ -f "$runtime_readback_path" && -f "$runtime_expectation_path" ]]; then
    if python3 -B "$runtime_validator_arg" --receipt "$runtime_readback_path" --expected "$runtime_expectation_path" > "$runtime_validation_path" 2> "$cell_dir/${pair}-${executor}.readback-validation.stderr.txt"; then
      runtime_validation_status=0
      runtime_validation_sha256=$(stable_sha256 "$runtime_validation_path" 131072) || { runtime_validation_status=1; failed=1; }
    else
      failed=1
      [[ -f "$runtime_validation_path" ]] && runtime_validation_sha256=$(stable_sha256 "$runtime_validation_path" 131072) || runtime_validation_sha256=unavailable
    fi
  fi
  [[ -f "$stdout" ]] && stdout_sha256=$(stable_sha256 "$stdout" 16777216) || stdout_sha256=unavailable
  [[ -f "$runtime_readback_path" ]] && runtime_readback_sha256=$(stable_sha256 "$runtime_readback_path" 131072) || runtime_readback_sha256=unavailable
  [[ -f "$runtime_expectation_path" ]] && runtime_expectation_sha256=$(stable_sha256 "$runtime_expectation_path" 131072) || runtime_expectation_sha256=unavailable
  if [[ $status -eq 0 && $runtime_validation_status -eq 0 && ! -s "$cell_dir/${pair}-${executor}.stderr.txt" ]] && \
    validate_output "$stdout" "$expected_executor" "$process_allocator" && \
    validate_shutdown_report "$shutdown_report" "$expected_executor" "$phase_trace_deadline" "$shutdown_deadline" "$process_deadline" "$stdout" "$report_nonce" "$run_id" "$process_allocator" "$profile" "$source_digest" "$process_binary_sha" && \
    { [[ "$mode:$workload" != capacity:mixed ]] || validate_capacity_family_report "$family_report" "$stdout" "$expected_executor" "$report_nonce" "$run_id" "$process_allocator" "$profile" "$source_digest" "$process_binary_sha"; } && \
    { [[ "$mode" != open_loop ]] || validate_id_report "$ids_report" "$arrivals" "$process_deadline" "$trace_deadline" "$rate" "$workload" "$profile" "$stdout" "$process_oracle_file" "$process_oracle_digest" "$run_id" "$report_nonce" "$expected_executor" "$process_allocator" "$source_digest" "$process_binary_sha"; }; then
    validation=valid
    if [[ "$mode" == open_loop ]]; then
      ids_sha256=$(stable_sha256 "$ids_report" 16777216)
      [[ "$ids_sha256" =~ ^[0-9a-f]{64}$ ]] || { failed=1; validation=invalid; ids_sha256=invalid; }
      if [[ "$profile" == safety_overload ]]; then
        p99_qualification=safety_only
      elif awk -F '\t' '
        NR==1 {for(i=1;i<=NF;i++) col[$i]=i; next}
        { attempted=$(col["attempted"]); admitted=$(col["admitted"]);
          rejected=$(col["rejected_full"])+$(col["rejected_resource"]); completed=$(col["completed_on_time"])+$(col["completed_late"]);
          minimum='"$([[ "$workload" == mixed ]] && echo 400000 || echo 100000)"';
          if(attempted=='"$arrivals"' && admitted==attempted && rejected==0 && completed==attempted && completed>=minimum) exit 0;
          exit 1; }
      ' "$stdout"; then
        p99_qualification=eligible
      else
        p99_qualification=descriptive_only
      fi
      if [[ "$p99_qualification" == eligible && "$workload" == mixed ]] && ! awk -F '\t' '
        NR<=3 {next}
        $5=="completed" {count[$2]++}
        END {exit !(count["cpu"]>=100000 && count["memory"]>=100000 && count["http"]>=100000 && count["disk"]>=100000)}
      ' "$ids_report"; then
        p99_qualification=descriptive_only
      fi
    fi
  else
    failed=1
    p99_qualification=invalid
  fi
  if (( functional_only_mode == 1 )); then
    p99_qualification=functional_only
  fi
  local shutdown_sha256=not_applicable
  if [[ -f "$shutdown_report" ]]; then
    shutdown_sha256=$(stable_sha256 "$shutdown_report" 131072) || { failed=1; validation=invalid; shutdown_sha256=invalid; }
  fi
  local family_sha256=not_applicable
  if [[ -f "$family_report" ]]; then
    family_sha256=$(stable_sha256 "$family_report" 131072) || { failed=1; validation=invalid; family_sha256=invalid; }
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$pair" "$executor" "$process_allocator" "$status" "$validation" "$p99_qualification" "$argv" "$(basename "$stdout")" "$(basename "$timing")" "$ids_sha256" "$shutdown_sha256" "$family_sha256" \
    "$stdout_sha256" "$(basename "$runtime_readback_path")" "$runtime_readback_sha256" "$(basename "$runtime_expectation_path")" "$runtime_expectation_sha256" \
    "$(basename "$runtime_validation_path")" "$runtime_validation_sha256" "$runtime_recipe_sha256" "$resource_ceiling_sha256" "$policy_sha256" "$fixed_global_control_baseline" \
    "$validator_sha256" "$source_manifest_sha256" "$calibration_binary_sha256" "$calibration_output_sha256" \
    >> "$cell_dir/processes.tsv"
  printf 'report_nonce_%s_%s\t%s\n' "$pair" "$executor" "$report_nonce" >> "$cell_dir/metadata.tsv"
  printf 'policy_sha256_%s_%s\t%s\n' "$pair" "$executor" "$policy_sha256" >> "$cell_dir/metadata.tsv"
  printf 'resource_ceiling_sha256_%s_%s\t%s\n' "$pair" "$executor" "$resource_ceiling_sha256" >> "$cell_dir/metadata.tsv"
  printf 'fixed_global_control_baseline_%s_%s\t%s\n' "$pair" "$executor" "$fixed_global_control_baseline" >> "$cell_dir/metadata.tsv"
  printf 'execution_scope_%s_%s\t%s\n' "$pair" "$executor" "$execution_scope" >> "$cell_dir/metadata.tsv"
  if (( functional_source_v4_mode == 1 )); then
    printf 'functional_tmpdir_%s_%s\t%s\n' "$pair" "$executor" "$process_tmpdir" >> "$cell_dir/metadata.tsv"
    printf 'functional_tmpdir_context_before_%s_%s\t%s\n' "$pair" "$executor" "$process_tmp_context_json" >> "$cell_dir/metadata.tsv"
    printf 'functional_tmpdir_context_after_%s_%s\t%s\n' "$pair" "$executor" "$process_tmp_context_after" >> "$cell_dir/metadata.tsv"
  fi
  printf 'oracle_sha256_%s_%s\t%s\n' "$pair" "$executor" "$process_oracle_digest" >> "$cell_dir/metadata.tsv"
  printf 'shutdown_report_%s_%s\t%s\n' "$pair" "$executor" "$(basename "$shutdown_report")" >> "$cell_dir/metadata.tsv"
  if [[ -f "$ids_report" ]]; then
    printf 'ids_sha256_%s_%s\t%s\n' "$pair" "$executor" "$(stable_sha256 "$ids_report" 16777216)" >> "$cell_dir/metadata.tsv"
  fi
}

# Alternate the executor order across matched pairs. A/A controls repeat the
# same executable, allocator, workload, and executor in two fresh processes.
case "$pair_kind" in
  matched|pressure-matched)
    if (( pair_ordinal % 2 == 0 )); then
      run_one bounded bounded "$allocator" "$binary" "$oracle_file" "$oracle_digest_actual"
      run_one tokio tokio "$allocator" "$binary" "$oracle_file" "$oracle_digest_actual"
    else
      run_one tokio tokio "$allocator" "$binary" "$oracle_file" "$oracle_digest_actual"
      run_one bounded bounded "$allocator" "$binary" "$oracle_file" "$oracle_digest_actual"
    fi
    ;;
  aa-bounded)
    run_one bounded-a bounded "$allocator" "$binary" "$oracle_file" "$oracle_digest_actual"
    run_one bounded-b bounded "$allocator" "$binary" "$oracle_file" "$oracle_digest_actual"
    ;;
  aa-tokio)
    run_one tokio-a tokio "$allocator" "$binary" "$oracle_file" "$oracle_digest_actual"
    run_one tokio-b tokio "$allocator" "$binary" "$oracle_file" "$oracle_digest_actual"
    ;;
  allocator-match|pressure-allocator-match)
    if (( pair_ordinal % 2 == 0 )); then
      run_one baseline bounded "$baseline_allocator" "$baseline_binary" "$baseline_oracle_file" "$baseline_oracle_digest_actual"
      run_one candidate bounded "$allocator" "$binary" "$oracle_file" "$oracle_digest_actual"
    else
      run_one candidate bounded "$allocator" "$binary" "$oracle_file" "$oracle_digest_actual"
      run_one baseline bounded "$baseline_allocator" "$baseline_binary" "$baseline_oracle_file" "$baseline_oracle_digest_actual"
    fi
    ;;
esac

source_identity_after=$(source_hash) || { failed=1; source_identity_after=$'unavailable\tunavailable'; }
IFS=$'\t' read -r source_digest_after head_commit_after <<< "$source_identity_after"
[[ "$head_commit_after" == "$head_commit" ]] || failed=1
source_inventory_module_sha256_after=$source_inventory_module_sha256_expected
binary_digest_after=$(stable_sha256 "$binary") || {
  failed=1
  binary_digest_after=unavailable
}
if [[ "$pair_kind" == allocator-match || "$pair_kind" == pressure-allocator-match ]]; then
  baseline_binary_digest_after=$(stable_sha256 "$baseline_binary") || {
    failed=1
    baseline_binary_digest_after=unavailable
  }
  [[ "$baseline_binary_digest_after" == "$baseline_binary_digest" ]] || failed=1
else
  baseline_binary_digest_after=
fi
if [[ "$mode" == open_loop ]]; then
  oracle_digest_after=$(stable_sha256 "$oracle_file" 16777216) || {
    failed=1
    oracle_digest_after=unavailable
  }
  if [[ "$pair_kind" == allocator-match || "$pair_kind" == pressure-allocator-match ]]; then
    baseline_oracle_digest_after=$(stable_sha256 "$baseline_oracle_file" 16777216) || {
      failed=1
      baseline_oracle_digest_after=unavailable
    }
    [[ "$baseline_oracle_digest_after" == "$baseline_oracle_digest_expected" && "$baseline_oracle_digest_actual" == "$baseline_oracle_digest_expected" ]] || failed=1
  else
    baseline_oracle_digest_after=
  fi
else
  oracle_digest_after=
  baseline_oracle_digest_after=
fi
runtime_bindings_sha_after=
runtime_validator_sha_after=
pair_runner_sha256_after=$(stable_sha256 "$pair_runner_path" 16777216) || { failed=1; pair_runner_sha256_after=unavailable; }
[[ "$pair_runner_sha256_after" == "$pair_runner_sha256_before" ]] || failed=1
if (( functional_only_mode == 1 )); then
  functional_overlay_sha256_after=$(stable_sha256 "$functional_overlay_file" 65536) || { failed=1; functional_overlay_sha256_after=unavailable; }
  [[ "$functional_overlay_sha256_after" == "$functional_overlay_sha_expected" && "$functional_overlay_sha256_after" == "$functional_overlay_sha256_before" ]] || failed=1
  if (( functional_source_v4_mode == 1 )); then
    functional_source_manifest_file_sha256_after=$(stable_sha256 "$functional_source_manifest_file_path" 16777216) || {
      failed=1
      functional_source_manifest_file_sha256_after=unavailable
    }
    [[ "$functional_source_manifest_file_sha256_after" == "$functional_source_manifest_file_sha256_before" ]] || failed=1
    verify_functional_overlay || failed=1
    functional_source_manifest_file_sha256_after=$(stable_sha256 "$functional_source_manifest_file_path" 16777216) || {
      failed=1
      functional_source_manifest_file_sha256_after=unavailable
    }
    [[ "$functional_source_manifest_file_sha256_after" == "$functional_source_manifest_file_sha256_before" ]] || failed=1
  fi
fi
if (( runtime_readback_enabled == 1 )); then
  runtime_bindings_sha_after=$(stable_sha256 "$runtime_bindings_arg" 131072) || { failed=1; runtime_bindings_sha_after=unavailable; }
  runtime_validator_sha_after=$(stable_sha256 "$runtime_validator_arg" 16777216) || { failed=1; runtime_validator_sha_after=unavailable; }
  [[ "$runtime_bindings_sha_after" == "$runtime_bindings_sha_expected" && "$runtime_validator_sha_after" == "$runtime_validator_sha_expected" ]] || failed=1
  verify_runtime_inputs || failed=1
fi
{
  printf 'source_tree_sha256_before\t%s\n' "$source_digest"
  printf 'source_tree_sha256_after\t%s\n' "$source_digest_after"
  printf 'source_inventory_module_sha256_before\t%s\n' "$source_inventory_module_sha256_before"
  printf 'source_inventory_module_sha256_after\t%s\n' "$source_inventory_module_sha256_after"
  printf 'binary_sha256_before\t%s\n' "$binary_digest"
  printf 'binary_sha256_after\t%s\n' "$binary_digest_after"
  printf 'baseline_binary_sha256_before\t%s\n' "$baseline_binary_digest"
  printf 'baseline_binary_sha256_after\t%s\n' "$baseline_binary_digest_after"
  printf 'oracle_sha256_before\t%s\n' "$oracle_digest_actual"
  printf 'oracle_sha256_after\t%s\n' "$oracle_digest_after"
  printf 'baseline_oracle_sha256_before\t%s\n' "$baseline_oracle_digest_actual"
  printf 'baseline_oracle_sha256_after\t%s\n' "$baseline_oracle_digest_after"
  printf 'runtime_bindings_sha256_after\t%s\n' "$runtime_bindings_sha_after"
  printf 'runtime_validator_sha256_after\t%s\n' "$runtime_validator_sha_after"
  printf 'execution_scope_after\t%s\n' "$execution_scope"
  printf 'pair_runner_sha256_before\t%s\n' "$pair_runner_sha256_before"
  printf 'pair_runner_sha256_after\t%s\n' "$pair_runner_sha256_after"
  printf 'functional_overlay_sha256_before\t%s\n' "$functional_overlay_sha256_before"
  printf 'functional_overlay_sha256_after\t%s\n' "$functional_overlay_sha256_after"
  if (( functional_source_v4_mode == 1 )); then
    printf 'source_manifest_schema\tallocatbelt.application-source-manifest.v4\n'
    printf 'source_manifest_file_sha256_before\t%s\n' "$functional_source_manifest_file_sha256_before"
    printf 'source_manifest_file_sha256_after\t%s\n' "$functional_source_manifest_file_sha256_after"
    printf 'source_manifest_sha256\t%s\n' "$functional_source_manifest_semantic_sha256"
    printf 'functional_tmpdir_root\t%s\n' "$functional_tmp_root_path"
    printf 'functional_tmpdir_root_context\t%s\n' "$functional_tmp_context_json"
  fi
} >> "$cell_dir/metadata.tsv"
[[ "$source_digest_after" == "$source_digest" ]] || failed=1
[[ "$source_inventory_module_sha256_before" == "$source_inventory_module_sha256_after" ]] || failed=1
[[ "$binary_digest" == "$binary_digest_after" ]] || failed=1
if [[ "$mode" == open_loop ]]; then
  [[ "$oracle_digest_expected" == "$oracle_digest_actual" && "$oracle_digest_actual" == "$oracle_digest_after" ]] || failed=1
fi
if [[ $failed -eq 0 ]]; then
  if (( functional_only_mode == 1 )); then
    printf 'pair_status\tfunctional_only\nexecution_scope\tfunctional_only\n' > "$cell_dir/pair.complete"
  else
    printf 'pair_status\tvalidated\nexecution_scope\tqualification\n' > "$cell_dir/pair.complete"
  fi
  exit 0
fi
printf 'pair_status\tfailed_or_invalid\nexecution_scope\t%s\n' "$execution_scope" > "$cell_dir/pair.failed"
exit 1
