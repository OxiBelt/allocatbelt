# AGENTS.md

Adapted from OxiBelt's agent guide for the allocatbelt workspace.

## Project Overview

allocatbelt is a Rust allocator research prototype and an alternative to
secure mimalloc for OxiBelt. It is independent of OxiBelt and is not recommended
for production. `allocatbelt` is the only package intended for publication;
the other workspace packages are development tools.

## Repository Structure

- `Cargo.toml`: Rust workspace, shared package metadata, dependencies and lints.
- `crates/allocatbelt/`: allocator, public APIs and integration tests.
  Allocation logic lives in `src/core/`; syscalls and raw-memory operations in
  `src/sys/`; CPU detection and kernel dispatch in `src/arch/`.
- `crates/allocatbelt-core-check/`: compiles the same core source as a safe
  `no_std` crate and runs its tests, checking model, Miri and loom checks.
- `crates/allocatbelt-codegen-probes/`: helpers for scalar instruction checks.
- `crates/allocatbelt/src/runtime/`: optional safe blocking-runtime implementation.
- `crates/allocatbelt-runtime/`: unpublished façade and same-source Loom checker.
- `crates/allocatbelt-tokio/`: development-only Tokio worker cache and shard hooks.
- `bench/`: allocator comparisons, resource profiling and SIMD candidates.
- `fuzz/`: cargo-fuzz targets over the checking model.
- `docs/`: design constraints, platform and API documentation, research and
  the unsafe inventory.
- `scripts/`: feature, package, platform, sandbox and specialized verification.
- `.github/workflows/`: CI checks and pinned tool versions.

## Contributor Guidance

[CONTRIBUTING.md](CONTRIBUTING.md) is the source of truth for contributor
workflow, testing, code style and Conventional Commits. Read its
[Local Checks](CONTRIBUTING.md#local-checks),
[Code Style](CONTRIBUTING.md#code-style) and
[Commit Messages](CONTRIBUTING.md#commit-messages) sections before changing or
reviewing code. If this guide or OxiBelt's contributor guidance diverges from
the local `CONTRIBUTING.md`, follow the local contributor guidance.

- Keep the core free of unsafe code and `std` dependencies. The core checker
  must continue compiling the same source; do not create a separate copy.
- Preserve [design constraints](docs/design-constraints.md). A change that
  breaks one needs the review named there before implementation.
- Keep unsafe code within the documented syscall, architecture, allocator
  adapter and region API boundaries, plus benchmark-only SIMD kernels.
  Each unsafe block has one unsafe operation and a `// SAFETY:` comment;
  update [the inventory](docs/unsafe-boundary.md) when the boundary changes.
- Follow `rustfmt.toml` (two-space indentation) and workspace lints. Declare
  shared external dependencies in `[workspace.dependencies]` and inherit
  them in member manifests. Keep new modules focused on one responsibility.
- New features must be additive, contain an implementation, and update
  `CompiledCapabilities`, [feature documentation](docs/features.md) and
  `scripts/check-features.sh`. Preserve the documented toolchain requirements,
  including the experimental RVV stable assembly check. Correctness and
  hardening are never optional features.

## Build and Verification

Use the Rust version required by `Cargo.toml` and the tool versions pinned
in CI. The [platform contract](docs/platform.md) is Linux 7.0 or newer,
64-bit little-endian x86_64, aarch64 or riscv64. x86_64 builds require
x86-64-v3 or newer. `.cargo/config.toml` supplies that target in this
repository; an overriding `RUSTFLAGS` must preserve it when compiling the
allocator, and doctests need the corresponding `RUSTDOCFLAGS`.

Run the standard code checks from the repository root:

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --release --all-features --locked
```

For core logic changes, also run:

```sh
MIRIFLAGS=-Zmiri-disable-isolation cargo +nightly miri test -p allocatbelt-core-check
```

For concurrency or atomic protocol changes, run the core-only loom models:

```sh
RUSTFLAGS="--cfg loom" cargo test --release --locked -p allocatbelt-core-check --lib loom
```

Changes to core `bits.rs` or `class.rs` also require
`scripts/run-mutation-testing.sh`. Add tests for surviving mutants rather
than reducing coverage; follow the contributor rules for provably equivalent
mutants. See [fuzz/README.md](fuzz/README.md) for model fuzzing.

Use the relevant verification scripts for feature combinations, packaging,
sandbox behavior, platform gates, scalar instructions, experimental ISA
kernels and rseq. Follow the complete checks in `CONTRIBUTING.md` and CI,
including `cargo audit` and `cargo deny check`. Report which checks ran and
any checks blocked by unavailable tooling, targets or environment support.
Documentation-only changes need link and diff review rather than runtime
tests. Hosted CI and emulated benchmark timings are not performance evidence.

## Agent Commit Message Guidance

Use the Conventional Commits format and allowed types in `CONTRIBUTING.md`.
Commit messages must contain portable, repository-relevant context. Exclude
session-specific aliases, absolute host paths and local-only environment
artifacts. Describe the portable result, such as which verification ran.

Prefer tracked repository files and accessible public sources for supporting
context. If none exists, explain the necessary context inline and sanitize it.
Keep secrets, personal data and undisclosed vulnerability details out of
public commits, pull requests, issues and other public outputs.

## Private Resources

Use an exposed checkout of `allocatbelt-private-resources` for private
research, reports, evidence and other sensitive artifacts. Discover its
location from developer or agent environment guidance; check
`/root/allocatbelt-private-resources` when no location is provided. This is
an environment-specific example, not a required location on every host.

Keep private data out of this repository and its tracked documentation.
Public descriptions must be sanitized and understandable without access to
the private checkout. Do not commit credentials to either repository.

Before persisting private artifacts, verify the destination is the intended
private checkout and is writable under the current environment permissions.
If it is unavailable or unwritable, report the limitation before persisting
the artifacts; do not substitute this repository as storage. Availability
of the private checkout does not authorize pushing or publishing its contents.

## Security Advisory Guidance

Keep validated, high-confidence, report-worthy security findings private
until a supported fix or actionable mitigation is verified and disclosure
is authorized. Use one GitHub repository Security Advisory per finding.
Before a fix or mitigation is available, use only the private vulnerability
report or draft/triage advisory channel. Do not substitute a public issue,
discussion, pull request or revealing commit message.

Preview the exact advisory payload and obtain explicit approval for each
submission or publication. Before writing, verify the canonical repository,
immutable source revision and finding locations, duplicate status,
authenticated identity, permissions and intended visibility. Read the
advisory back before reporting success. Do not request a CVE identifier
unless explicitly asked. If tooling cannot preserve the required visibility,
report the blocker without changing disclosure channels.
