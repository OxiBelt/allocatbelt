#!/usr/bin/env bash
# Checks the crates.io package of `allocatbelt`, the only published package
# of this workspace (single-package directive §3.7, §15.7):
#
# - `cargo package` and `cargo publish --dry-run` succeed;
# - the .crate holds the sources, LICENSE and README, and nothing from the
#   development packages;
# - its manifest has no path dependency (nothing unpublished);
# - a consumer project outside this repository, which does not see its
#   `.cargo/config.toml`, builds and runs the unpacked crate as its global
#   allocator with the default features, with `default-features = false`,
#   and with each optional feature, and each build reports exactly its
#   features in `CompiledCapabilities`;
# - on x86_64, that consumer fails with the gate's message without
#   `-C target-cpu=x86-64-v3`, and builds with it.
#
#   scripts/check-package.sh                   # in a clean checkout (CI)
#   PACKAGE_ALLOW_DIRTY=1 scripts/check-package.sh   # with local changes
set -euo pipefail

cd "$(dirname "$0")/.."
root="$(pwd -P)"
# The consumer is built outside this directory; keep this directory's
# toolchain (a rustup override would not reach it).
if [[ -z "${RUSTUP_TOOLCHAIN:-}" ]] && command -v rustup >/dev/null; then
  RUSTUP_TOOLCHAIN="$(rustup show active-toolchain | cut -d' ' -f1)"
  export RUSTUP_TOOLCHAIN
fi
dirty=()
if [[ -n "${PACKAGE_ALLOW_DIRTY:-}" ]]; then
  dirty=(--allow-dirty)
fi
fail() {
  echo "FAIL: $*" >&2
  exit 1
}

cargo package -p allocatbelt --locked "${dirty[@]}"
cargo publish -p allocatbelt --dry-run --locked "${dirty[@]}"

version="$(cargo metadata --format-version 1 --no-deps --locked |
  jq -r '.packages[] | select(.name == "allocatbelt") | .version')"
crate="${root}/target/package/allocatbelt-${version}.crate"
[[ -f "${crate}" ]] || fail "no ${crate}"

# Contents: required files present, nothing from other packages.
list="$(tar -tzf "${crate}" | sed "s|^allocatbelt-${version}/||")"
for f in Cargo.toml LICENSE README.md src/lib.rs src/global.rs src/core/mod.rs \
  src/sys/mod.rs src/sys/platform.rs src/arch/mod.rs; do
  grep -qxF "${f}" <<<"${list}" || fail "the package lacks ${f}"
done
if grep -E '^(bench|fuzz|scripts|docs|crates|\.cargo|\.github)/' <<<"${list}"; then
  fail "the package contains files of the development tooling (above)"
fi
echo "ok: package contents ($(wc -l <<<"${list}") files)"

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
tar -xzf "${crate}" -C "${work}"
unpacked="${work}/allocatbelt-${version}"
python3 - "${unpacked}/Cargo.toml" <<'EOF' || fail "the packaged manifest has a path dependency"
import sys, tomllib

m = tomllib.load(open(sys.argv[1], "rb"))
tables = [m] + list(m.get("target", {}).values())
bad = [
  f"{kind}.{name}"
  for t in tables
  for kind in ("dependencies", "dev-dependencies", "build-dependencies")
  for name, spec in t.get(kind, {}).items()
  if isinstance(spec, dict) and "path" in spec
]
if bad:
  sys.exit(f"path dependencies: {bad}")
EOF
echo "ok: no path dependencies"

# A consumer outside the repository: no workspace, no .cargo/config.toml.
consumer="${work}/consumer"
mkdir -p "${consumer}/src"
cat >"${consumer}/Cargo.toml" <<EOF
[package]
name = "allocatbelt-consumer"
version = "0.0.0"
edition = "2024"
publish = false

[dependencies]
allocatbelt = { path = "${unpacked}", default-features = false }

# `--no-default-features` here builds allocatbelt without its defaults.
[features]
default = ["allocatbelt-default"]
allocatbelt-default = ["allocatbelt/default"]
io-uring = ["allocatbelt/io-uring"]
rseq = ["allocatbelt/experimental-rseq"]
sve2 = ["allocatbelt/experimental-aarch64-sve2"]
rvv = ["allocatbelt/experimental-riscv-rvv"]

[workspace]
EOF
cat >"${consumer}/src/main.rs" <<'EOF'
#[global_allocator]
static GLOBAL: allocatbelt::Allocatbelt = allocatbelt::Allocatbelt;

fn main() {
  let v: Vec<Box<[u8]>> = (1..2000).map(|n| vec![7u8; n * 3].into()).collect();
  assert!(v.iter().all(|b| b.iter().all(|&x| x == 7)));
  drop(v);
  GLOBAL.purge();
  println!("consumer ok: {:?}", GLOBAL.platform());
  println!("{:?}", GLOBAL.compiled_capabilities());
  GLOBAL.configure(allocatbelt::Policy::DEFAULT).unwrap();
  println!("{}", GLOBAL.report());
}
EOF
# The same dependency versions as this workspace.
cp Cargo.lock "${consumer}/"

build() {
  # build <RUSTFLAGS> [cargo args...]
  local flags="$1"
  shift
  (cd "${consumer}" && env -u CARGO_BUILD_RUSTFLAGS RUSTFLAGS="${flags}" \
    cargo build --quiet --target-dir "${work}/target" "$@")
}

v3=()
if [[ "$(uname -m)" == x86_64 ]]; then
  v3=(-C target-cpu=x86-64-v3)
  log="${work}/no-v3.log"
  if build "" >"${log}" 2>&1; then
    fail "x86_64 consumer built without x86-64-v3"
  fi
  grep -qF 'must be built for x86-64-v3 or newer' "${log}" ||
    { cat "${log}" >&2; fail "x86_64 without v3 failed without the gate's message"; }
  echo "ok: x86_64 consumer without x86-64-v3 stops at the gate"
fi
run() {
  # run <expected CompiledCapabilities> [cargo args...]
  local expect="$1"
  shift
  local out
  out="$(cd "${consumer}" && RUSTFLAGS="${v3[*]:-}" cargo run --quiet --target-dir "${work}/target" "$@")"
  echo "${out}"
  grep -qF "${expect}" <<<"${out}" || fail "expected ${expect}"
  echo "ok: consumer builds and runs (${*:-default features})"
}
caps() {
  # caps <maintenance> <scheduler> <io_uring> <rseq> [<sve> <sve2> <rvv>]
  echo "CompiledCapabilities { maintenance: $1, scheduler: $2, io_uring: $3, rseq: $4," \
    "experimental_aarch64_sve: ${5:-false}, experimental_aarch64_sve2: ${6:-false}," \
    "experimental_riscv_rvv: ${7:-false} }"
}
run "$(caps true true false false)"
run "$(caps false false false false)" --no-default-features
run "$(caps true true true false)" --features io-uring
run "$(caps true false true false)" --no-default-features --features io-uring
run "$(caps true true false true)" --features rseq
# The SVE kernels are compiled only for aarch64; elsewhere the feature
# builds and compiles nothing.
sve=false
[[ "$(uname -m)" == aarch64 ]] && sve=true
run "$(caps true true false false "${sve}" "${sve}")" --features sve2
# The RVV kernel needs nightly on riscv64 (scripts/check-experimental-rvv.sh);
# on the stable x86_64 and aarch64 hosts the feature compiles nothing.
if [[ "$(uname -m)" != riscv64 ]]; then
  run "$(caps true true false false)" --features rvv
fi
