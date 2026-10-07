# Contributing to allocatbelt

allocatbelt follows the [OxiBelt](https://github.com/OxiBelt/OxiBelt)
contributor conventions so its crates can move into the OxiBelt workspace
unchanged. When this file and OxiBelt's `CONTRIBUTING.md` diverge, this file
wins for this repository.

## Local Checks

Run the checks CI runs from the repository root. The toolchain is pinned by
`rust-version` in `Cargo.toml` (currently 1.99.0).

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --release --all-features --locked
scripts/check-features.sh    # each supported Cargo feature combination
scripts/check-package.sh     # the crates.io package and a clean consumer
scripts/check-sandbox.sh     # hardened container and VM behaviour (docker, qemu-user)
scripts/check-experimental-isa.sh  # experimental SVE/SVE2 kernels (qemu-user, aarch64 target)
scripts/check-experimental-rvv.sh  # experimental RVV kernel (stable Rust, qemu-user, riscv64 target)
scripts/check-rseq.sh        # experimental rseq mm_cid: glibc, glibc with rseq off, musl
cargo audit
cargo deny check
```

The full-system RISC-V CI job also runs `build`, `payload` and `boot` through
`python3 -B scripts/riscv-guest/check.py`. See the
[guest recipe](scripts/riscv-guest/README.md) for prerequisites and cache
validation. Its emulated results establish correctness only.

Changes must keep the rules in
[docs/design-constraints.md](docs/design-constraints.md); one that would break
a rule needs the review that document names first.

A new Cargo feature needs code behind it, must be additive and build on
stable Rust, gets a field in `CompiledCapabilities`, a row in
[docs/features.md](docs/features.md) and a combination in
`scripts/check-features.sh`. Allocator correctness and hardening are never
features.

`cargo audit` and `cargo deny` are pinned in CI; install the same versions
locally with:

```sh
cargo install cargo-audit --version 0.22.2 --locked
cargo install cargo-deny --version 0.20.2 --locked
```

Changes to the core logic (`crates/allocatbelt/src/core/`) should also run the Miri model tests and,
when `bits.rs` or `class.rs` change, the mutation campaign (needs `jq` and
`mewt 4.0.0`, installed with `cargo install mewt --version 4.0.0 --locked`):

```sh
MIRIFLAGS=-Zmiri-disable-isolation cargo +nightly miri test -p allocatbelt-core-check
scripts/run-mutation-testing.sh
```

For a complete bounded core campaign, `scripts/check-miri.sh --output DIR`
uses the CI-pinned nightly and runs each test in its own process with a
30-minute ceiling. It records the test outcome, process exit (including Miri
teardown checks) and log-writer exit, and accepts only the existing intentional
contention-benchmark skip. Keep raw evidence in the private resources checkout.
The two large page-topology fixtures preserve native stress counts and use
bounded, topology-equivalent sizes under Miri; a separate test covers small
classes across bitmap-word boundaries. A timeout or cancellation is not a pass.

The mutation campaign is configured in `mewt.toml` and must catch every
mutant with no skips or timeouts. Add a test rather than narrowing the
targets when a mutant survives. Only a mutant that provably cannot change
behavior (a redundant fast path, for example) may go in
`scripts/mutation-equivalent-mutants.json`, with the reason; entries that
stop matching a surviving mutant fail the gate and must be removed.

## Code Style

- Formatting is `rustfmt` with `tab_spaces = 2` (`rustfmt.toml`), matching
  OxiBelt; `.editorconfig` carries the same settings for editors.
- Workspace lints mirror the OxiBelt baseline in `[workspace.lints]`. Every
  crate sets `[lints] workspace = true`, and library crates deny
  `clippy::unwrap_used` and `clippy::expect_used` outside tests.
- Declare external dependency versions once in `[workspace.dependencies]`
  and use `<name>.workspace = true` in member manifests. `cargo deny`
  rejects unused workspace dependencies.
- `unsafe` stays in the `sys` and `arch` modules of `allocatbelt` (CPU feature
  detection and, later, architecture kernels) and the `GlobalAlloc` adapter
  (`global`, `rseq`) and the region API's owned memory boundary; the `core`
  module keeps `#![forbid(unsafe_code)]`. Benchmark-only unsafe boundaries
  are the SIMD candidates in `bench/simd` and the `System` allocation counter
  in `bench-runtime-diagnostic`. Every
  `unsafe` block holds one unsafe operation and a `// SAFETY:` comment, and
  every change to the boundary updates
  [docs/unsafe-boundary.md](docs/unsafe-boundary.md).
- Put new functionality in a responsibility-focused module rather than
  growing an unrelated file.

## Commit Messages

Use Conventional Commits:

```text
<type>(<scope>): <subject>
```

- `type` is one of `feat`, `fix`, `chore`, `docs`, `ci`, `refactor`,
  `security`, `tests`, or `perf`.
- `scope` is the area touched, such as `core`, `sys`, `adapter`, `bench`,
  `lints`, `deps`, `workflows`, or `docs`.
- `subject` is a short imperative, present-tense summary.
- Wrap code identifiers, paths, commands and literal values in backticks in
  both the title and the body.

```text
perf(core): skip the bitmap scan for full pages
fix(sys): retry `madvise` on `EAGAIN`
docs(research): record the medium-class measurements
```
