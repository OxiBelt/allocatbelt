#!/usr/bin/env bash
# Exercise static-build verdicts and sandbox invocation without Docker/Cargo.
set -euo pipefail

repo="$(cd "$(dirname "$0")/../.." && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/check-sandbox-test.XXXXXX")"
trap 'rm -rf -- "${work}"' EXIT
mkdir -p "${work}/bin"
REAL_JQ="$(command -v jq)"
export REAL_JQ
export FAKE_SANDBOX_ROOT="${work}"
export FAKE_CARGO_CALLS="${work}/cargo-calls"
export FAKE_DOCKER_CALLS="${work}/docker-calls"
export ALLOCATBELT_SANDBOX_BASH="${work}/fixture-bash"
export ALLOCATBELT_SANDBOX_BUSYBOX="${work}/fixture-busybox"
printf 'static bash fixture\n' >"${ALLOCATBELT_SANDBOX_BASH}"
printf 'static busybox fixture\n' >"${ALLOCATBELT_SANDBOX_BUSYBOX}"
chmod +x "${ALLOCATBELT_SANDBOX_BASH}" "${ALLOCATBELT_SANDBOX_BUSYBOX}"

cat >"${work}/bin/readelf" <<'EOF'
#!/usr/bin/env bash
case "$1" in
  -h)
    [[ "${FAKE_SANDBOX_MODE:-}" != fixture_bad_elf ]] || exit 1
    if [[ "${FAKE_SANDBOX_MODE:-}" == fixture_mutate_source ]]; then
      printf 'mutated after freeze\n' >>"${ALLOCATBELT_SANDBOX_BUSYBOX}"
    fi
    machine='Advanced Micro Devices X86-64'
    [[ "${FAKE_SANDBOX_MODE:-}" != fixture_wrong_arch ]] || machine=AArch64
    printf '  Class: ELF64\n  Data: 2s complement, little endian\n  Machine: %s\n' "${machine}"
    ;;
  -l)
    [[ "${FAKE_SANDBOX_MODE:-}" != fixture_interpreter ]] || echo '  INTERP 0x00'
    ;;
  -d)
    [[ "${FAKE_SANDBOX_MODE:-}" != fixture_needed ]] || echo '  (NEEDED) Shared library: [libc.so.6]'
    ;;
esac
exit 0
EOF

cat >"${work}/bin/uname" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' x86_64
EOF
cat >"${work}/bin/cargo" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"${FAKE_CARGO_CALLS}"
for index in {1..9}; do
  name="test-${index}"
  [[ "${index}" == 1 ]] && name=sandbox-fake
  printf '{"reason":"compiler-artifact","executable":"%s/tests/%s","profile":{"test":true},"target":{"name":"%s"}}\n' \
    "${FAKE_SANDBOX_ROOT}" "${name}" "${name}"
done
if [[ "${FAKE_SANDBOX_MODE:-}" == partial_build_failure ]]; then
  echo 'fake final test target failed to compile' >&2
  exit 101
fi
EOF
cat >"${work}/bin/jq" <<'EOF'
#!/usr/bin/env bash
if [[ "${FAKE_SANDBOX_MODE:-}" == parser_failure ]]; then
  exit 2
fi
exec "${REAL_JQ}" "$@"
EOF
cat >"${work}/bin/docker" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$@" >>"${FAKE_DOCKER_CALLS}"
if [[ "${1:-}" == image ]]; then
  if [[ "$*" == *'--format'* ]]; then
    echo 'sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
    exit 0
  fi
  case "${FAKE_SANDBOX_MODE:-}" in fixture_import|fixture_mutate_source) exit 1 ;; esac
  exit 0
fi
if [[ "${1:-}" == import ]]; then
  cat >"${FAKE_SANDBOX_ROOT}/fixture.tar"
  exit 0
fi
if [[ "${*: -4}" == '/bin/busybox sha256sum /bin/bash /bin/busybox' ]]; then
  if [[ "${FAKE_SANDBOX_MODE:-}" == fixture_hash_mismatch ]]; then
    echo 'incorrect hashes'
  elif [[ "${FAKE_SANDBOX_MODE:-}" == fixture_mutate_source ]]; then
    tar -xOf "${FAKE_SANDBOX_ROOT}/fixture.tar" ./bin/bash | sha256sum | awk '{print $1 "  /bin/bash"}'
    tar -xOf "${FAKE_SANDBOX_ROOT}/fixture.tar" ./bin/busybox | sha256sum | awk '{print $1 "  /bin/busybox"}'
  else
    sha256sum "${ALLOCATBELT_SANDBOX_BASH}" | awk '{print $1 "  /bin/bash"}'
    sha256sum "${ALLOCATBELT_SANDBOX_BUSYBOX}" | awk '{print $1 "  /bin/busybox"}'
  fi
  exit 0
fi
echo 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s'
if [[ "${FAKE_SANDBOX_MODE:-}" == docker_failure ]]; then
  echo 'fake actionable container failure' >&2
  exit 88
fi
EOF
cat >"${work}/bin/qemu-x86_64" <<'EOF'
#!/usr/bin/env bash
echo 'cpu_features: fake verification fixture'
echo 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s'
EOF
chmod +x "${work}"/bin/*
export PATH="${work}/bin:${PATH}"

run_checker() {
  : >"${FAKE_DOCKER_CALLS}"
  : >"${FAKE_CARGO_CALLS}"
  FAKE_SANDBOX_MODE="$1" "${repo}/scripts/check-sandbox.sh" >"${work}/$1.log" 2>&1
}

if ! run_checker success; then
  cat "${work}/success.log" >&2
  echo 'FAIL: sandbox checker rejected the successful fixture' >&2
  exit 1
fi
grep -qF -- '--features io-uring,runtime' "${FAKE_CARGO_CALLS}" \
  || { echo 'FAIL: sandbox build omitted runtime coverage' >&2; exit 1; }
grep -qxF -- '/tmp:rw,nosuid,nodev,size=64m,mode=1777' "${FAKE_DOCKER_CALLS}" \
  || { echo 'FAIL: hardened containers lack bounded writable temporary storage' >&2; exit 1; }
for option in '--network' 'none' '--user' '10001:10001' '--cap-drop' 'ALL' '--read-only' \
  'no-new-privileges:true'; do
  grep -qxF -- "${option}" "${FAKE_DOCKER_CALLS}" \
    || { echo "FAIL: hardened containers lost ${option}" >&2; exit 1; }
done

for case_name in fixture_bad_elf fixture_wrong_arch fixture_interpreter fixture_needed; do
  if run_checker "${case_name}"; then
    echo "FAIL: sandbox checker accepted ${case_name}" >&2
    exit 1
  fi
  if [[ -s "${FAKE_CARGO_CALLS}" || -s "${FAKE_DOCKER_CALLS}" ]]; then
    echo "FAIL: sandbox checker built or launched tests after ${case_name}" >&2
    exit 1
  fi
done
if ALLOCATBELT_SANDBOX_BASH="${work}/missing-fixture" run_checker fixture_missing; then
  echo 'FAIL: sandbox checker accepted a missing fixture' >&2
  exit 1
fi
[[ ! -s "${FAKE_CARGO_CALLS}" && ! -s "${FAKE_DOCKER_CALLS}" ]] \
  || { echo 'FAIL: missing fixture still built or launched tests' >&2; exit 1; }

run_checker fixture_import
first_image="$(grep '^allocatbelt-sandbox-fixtures:' "${FAKE_DOCKER_CALLS}" | head -n 1)"
first_archive="$(sha256sum "${work}/fixture.tar" | awk '{print $1}')"
cat >"${work}/expected-layout" <<'EOF'
./
./bin/
./bin/bash
./bin/busybox
./bin/cat
./bin/head
./bin/sh
./bin/sleep
./bin/yes
EOF
diff -u "${work}/expected-layout" <(tar -tf "${work}/fixture.tar")
cmp "${ALLOCATBELT_SANDBOX_BASH}" <(tar -xOf "${work}/fixture.tar" ./bin/bash)
cmp "${ALLOCATBELT_SANDBOX_BUSYBOX}" <(tar -xOf "${work}/fixture.tar" ./bin/busybox)
run_checker fixture_import
[[ "$(sha256sum "${work}/fixture.tar" | awk '{print $1}')" == "${first_archive}" ]] \
  || { echo 'FAIL: fixture archive depends on temporary host metadata' >&2; exit 1; }
run_checker fixture_mutate_source
[[ "$(sha256sum "${work}/fixture.tar" | awk '{print $1}')" == "${first_archive}" ]] \
  || { echo 'FAIL: mutable fixture source changed validated image inputs' >&2; exit 1; }
printf 'changed static busybox fixture\n' >>"${ALLOCATBELT_SANDBOX_BUSYBOX}"
run_checker fixture_import
[[ "$(grep '^allocatbelt-sandbox-fixtures:' "${FAKE_DOCKER_CALLS}" | head -n 1)" != "${first_image}" ]] \
  || { echo 'FAIL: fixture image identity ignored changed executable bytes' >&2; exit 1; }
if run_checker fixture_hash_mismatch; then
  echo 'FAIL: cached image with wrong executable hashes was accepted' >&2
  exit 1
fi
grep -qF 'FAIL: fixture image executable hashes differ' "${work}/fixture_hash_mismatch.log" \
  || { echo 'FAIL: cached image hash mismatch verdict was not retained' >&2; exit 1; }

for case_name in partial_build_failure parser_failure; do
  if run_checker "${case_name}"; then
    echo "FAIL: sandbox checker accepted ${case_name}" >&2
    exit 1
  fi
  if [[ -s "${FAKE_DOCKER_CALLS}" ]]; then
    echo "FAIL: sandbox checker invoked Docker after ${case_name}" >&2
    exit 1
  fi
done
grep -qF -- 'FAIL: static test build failed' "${work}/partial_build_failure.log" \
  || { echo 'FAIL: build failure verdict was not retained' >&2; exit 1; }
grep -qF -- 'FAIL: could not parse static test artifacts' "${work}/parser_failure.log" \
  || { echo 'FAIL: artifact-parser failure verdict was not retained' >&2; exit 1; }
if run_checker docker_failure; then
  echo 'FAIL: passing-looking output hid a nonzero Docker exit' >&2
  exit 1
fi
grep -qF 'fake actionable container failure' "${work}/docker_failure.log" \
  || { echo 'FAIL: container failure diagnostics were hidden' >&2; exit 1; }
echo 'ok: sandbox checker validates static fixtures, deterministic image inputs and build/container verdicts'
