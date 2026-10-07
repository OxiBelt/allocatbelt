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
  exit 0
fi
echo 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s'
if [[ "${FAKE_SANDBOX_MODE:-}" == docker_failure ]]; then
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
echo 'ok: sandbox checker rejects partial builds, parser failures and nonzero container exits'
