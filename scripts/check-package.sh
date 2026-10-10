#!/usr/bin/env bash
# Checks the crates.io package of `allocatbelt`, the only published package
# of this workspace (single-package directive §3.7, §15.7):
#
# - `cargo package` and `cargo publish --dry-run` succeed;
# - the .crate holds the sources, LICENSE and README, and nothing from the
#   development packages;
# - its manifest has no path dependency (nothing unpublished);
# - the unpacked crate's own tests pass outside this workspace, and its
#   documentation builds with the docs.rs metadata alone;
# - a consumer project outside this repository, which does not see its
#   `.cargo/config.toml`, builds and runs the unpacked crate as its global
#   allocator with the default features, with `default-features = false`,
#   and with each optional feature, and each build reports exactly its
#   features in `CompiledCapabilities`; runtime consumers also recover an
#   initially shared pipe buffer and transfer a bounded payload in an owned
#   async scope, then explicitly close the pipe, scope and runtime;
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
  src/sys/mod.rs src/sys/platform.rs src/arch/mod.rs src/runtime/mod.rs; do
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

# Outside this workspace the unpacked crate has no `.cargo/config.toml`:
# its own tests (as crater or a vendoring consumer would run them) need
# the x86-64-v3 flag like any other build, and its doctests need it in
# RUSTDOCFLAGS (README).
unpacked_flags=""
[[ "$(uname -m)" == x86_64 ]] && unpacked_flags="-C target-cpu=x86-64-v3"
cp Cargo.lock "${unpacked}/"
printf '\n[workspace]\n' >>"${unpacked}/Cargo.toml"
unpacked_test() {
  (cd "${unpacked}" && env -u CARGO_BUILD_RUSTFLAGS RUSTFLAGS="${unpacked_flags}" \
    RUSTDOCFLAGS="${unpacked_flags}" cargo test --release --quiet --target-dir "${work}/target" "$@")
}
unpacked_test 2>&1 | grep -E '^test result' | sort | uniq -c
if ! unpacked_test --all-features >"${work}/all-feature-tests.log" 2>&1; then
  cat "${work}/all-feature-tests.log" >&2
  fail "the unpacked crate's all-feature tests fail"
fi
echo "ok: the unpacked crate's tests pass"

# docs.rs builds the documentation with `[package.metadata.docs.rs]` and
# nothing from this repository: its flags must get past the platform gate.
# (docs.rs also passes `--cfg docsrs`, which needs its nightly.)
mapfile -t docsrs < <(python3 - "${unpacked}/Cargo.toml" <<'EOF'
import sys, tomllib

d = tomllib.load(open(sys.argv[1], "rb"))["package"]["metadata"]["docs"]["rs"]
print(d["targets"][0])
print(" ".join(d.get("rustc-args", [])))
print(" ".join(d.get("rustdoc-args", [])))
print("--all-features" if d.get("all-features") else "--lib")
EOF
)
[[ ${#docsrs[@]} -eq 4 ]] || fail "no [package.metadata.docs.rs] in the packaged manifest"
if [[ "$(uname -m)" == "${docsrs[0]%%-*}" ]]; then
  (cd "${unpacked}" && env -u CARGO_BUILD_RUSTFLAGS RUSTFLAGS="${docsrs[1]}" \
    RUSTDOCFLAGS="${docsrs[2]} -D warnings" cargo doc --quiet --no-deps "${docsrs[3]}" \
    --target-dir "${work}/target") || fail "documentation as docs.rs builds it"
  echo "ok: documentation builds with the docs.rs metadata (${docsrs[0]})"
fi

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

# \`--no-default-features\` here builds allocatbelt without its defaults.
[features]
default = ["allocatbelt-default"]
allocatbelt-default = ["allocatbelt/default"]
runtime = ["allocatbelt/runtime"]
runtime-io-uring = ["runtime", "allocatbelt/runtime-io-uring"]
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
  #[cfg(feature = "runtime")]
  {
    use allocatbelt::runtime::{Config, Resources, Runtime, ShutdownMode};
    let mut rt = Runtime::new(Config {
      workers: 1, max_outstanding: 4, capacity: Resources::ZERO,
    }).unwrap();
    assert_eq!(rt.try_spawn(Resources::ZERO, |_| 42).unwrap().join().unwrap(), 42);
    rt.shutdown(ShutdownMode::Drain).unwrap();
    check_async_runtime();
  }
  let v: Vec<Box<[u8]>> = (1..2000).map(|n| vec![7u8; n * 3].into()).collect();
  assert!(v.iter().all(|b| b.iter().all(|&x| x == 7)));
  drop(v);
  GLOBAL.purge();
  println!("consumer ok: {:?}", GLOBAL.platform());
  println!("{:?}", GLOBAL.compiled_capabilities());
  GLOBAL.configure(allocatbelt::Policy::DEFAULT).unwrap();
  println!("{}", GLOBAL.report());
}

#[cfg(feature = "runtime")]
fn check_async_runtime() {
  use allocatbelt::runtime::asynchronous::{AsyncConfig, AsyncRuntime, AsyncShutdown};
  use allocatbelt::runtime::io::{AsyncReadExt, AsyncWriteExt, pipes};
  use allocatbelt::runtime::managed::{ResourceLimits, ResourceScope};

  let resources = ResourceScope::new(ResourceLimits {
    managed_memory: 8,
    disk_concurrent_ops: 0,
    network_concurrent_ops: 0,
  });
  let buffer = resources.try_alloc_zeroed(8).unwrap();
  let pointer = buffer.as_slice().as_ptr();
  let shared = buffer.clone();
  let refused = pipes::pipe(buffer).unwrap_err();
  assert_eq!(refused.kind, pipes::PipeInitErrorKind::Shared);
  assert_eq!(refused.buffers.as_slice().as_ptr(), pointer);
  assert_eq!(resources.snapshot().managed_memory, 8);
  drop(shared);
  let (mut reader, mut writer) = pipes::pipe(refused.buffers).unwrap();

  let runtime = AsyncRuntime::new(AsyncConfig {
    workers: 1,
    max_outstanding: 2,
    max_scopes: 2,
  }).unwrap();
  let scope = runtime.scope_with_resources(&resources).unwrap();
  let send = scope.spawn(async move {
    writer.write_all(b"package async").await.unwrap();
    writer.flush().await.unwrap();
    writer.shutdown().await.unwrap();
  }).unwrap();
  let receive = scope.spawn(async move {
    let mut received = [0; 13];
    let mut offset = 0;
    while offset < received.len() {
      let count = reader.read(&mut received[offset..]).await.unwrap();
      assert!(count > 0);
      offset += count;
    }
    assert_eq!(&received, b"package async");
    assert_eq!(reader.read(&mut [0]).await.unwrap(), 0);
    received
  }).unwrap();
  runtime.block_on(send).unwrap().unwrap();
  assert_eq!(&runtime.block_on(receive).unwrap().unwrap(), b"package async");
  runtime.block_on(scope.close()).unwrap();
  assert_eq!(resources.snapshot().managed_memory, 0);
  runtime.shutdown(AsyncShutdown::Drain).unwrap();
  println!("consumer ok: async pipe recovery, transfer and cleanup");
}
EOF
# The same dependency versions as this workspace.
cp Cargo.lock "${consumer}/"

build() {
  # build <RUSTFLAGS> [cargo args...]
  local flags="$1"
  shift
  (cd "${consumer}" && env -u CARGO_BUILD_RUSTFLAGS RUSTFLAGS="${flags}" RUSTDOCFLAGS="${flags}" \
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
  out="$(cd "${consumer}" && env -u CARGO_BUILD_RUSTFLAGS RUSTFLAGS="${v3[*]:-}" \
    RUSTDOCFLAGS="${v3[*]:-}" timeout --signal=TERM --kill-after=5s 180s \
    cargo run --quiet --target-dir "${work}/target" "$@")"
  echo "${out}"
  grep -qF "${expect}" <<<"${out}" || fail "expected ${expect}"
  echo "ok: consumer builds and runs (${*:-default features})"
}
caps() {
  # caps <maintenance> <scheduler> <io_uring> <rseq> [<sve> <sve2> <rvv> <runtime> <runtime_io_uring>]
  echo "CompiledCapabilities { runtime: ${8:-false}, runtime_io_uring: ${9:-false}, maintenance: $1, scheduler: $2, io_uring: $3, rseq: $4," \
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
# The RVV kernel uses stable naked assembly on riscv64; on x86_64 and
# aarch64 the feature compiles nothing.
if [[ "$(uname -m)" != riscv64 ]]; then
  run "$(caps true true false false)" --features rvv
fi

run "$(caps false false false false false false false true)" --no-default-features --features runtime
run "$(caps true true false false false false false true)" --features runtime
run "$(caps false false false false false false false true true)" --no-default-features --features runtime-io-uring
run "$(caps true true false false false false false true true)" --features runtime-io-uring
run "$(caps true true true false false false false true true)" --features runtime-io-uring,io-uring
# Traverse only production edges from the unpacked package with every feature.
(cd "${unpacked}" && cargo metadata --all-features --format-version 1) >"${work}/consumer-graph.json"
python3 - "${work}/consumer-graph.json" <<'PYGRAPH'
import json, sys
m = json.load(open(sys.argv[1]))
nodes = {node["id"]: node for node in m["resolve"]["nodes"]}
names = {package["id"]: package["name"] for package in m["packages"]}
pending = [m["resolve"]["root"]]
seen = set()
while pending:
    ident = pending.pop()
    if ident in seen:
        continue
    seen.add(ident)
    if names[ident] == "tokio" or names[ident].startswith("tokio-"):
        sys.exit("Tokio production dependency: " + names[ident])
    for dep in nodes[ident]["deps"]:
        if any(kind["kind"] != "dev" for kind in dep["dep_kinds"]):
            pending.append(dep["pkg"])
print("ok: packaged production dependency graph contains no Tokio")
PYGRAPH
