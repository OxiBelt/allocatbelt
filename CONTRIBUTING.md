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
Large pressure and page-topology fixtures preserve native stress counts and
use bounded, topology-equivalent sizes under Miri; separate tests cover small
classes across bitmap-word boundaries. Size round trips still visit every
representative size under Miri, with three simultaneous allocations per size.
The class-selective refill test exhausts a 128-block, two-word page under Miri
and retains its full 4096-block page in native tests. Both configurations verify
the exact buffered-block reuse, other-class isolation and final reclamation.
The cross-class pending-mask test keeps its 7,680 native allocations, seed and
free order. Under Miri it exhausts 24 one-word pages of each of the 4096-,
6144- and 8192-byte classes (816 live blocks), then frees one block per page
in a fixed class-interleaved prefix that must evict another class's word. The
remaining blocks follow the same seeded shuffle through final reclamation.
The lowest-page search test keeps its native 1000- and 48-byte requests (64
and 1,365 blocks per page, 1,432 allocations). Under Miri it uses 8192- and
4096-byte requests (8 and 16 blocks per page, one bitmap word each, 27
allocations) for the same four-page topology: a full primary page 0, a
secondary page 1 and the primary class's newest page 2 below an untouched free
page 3. Both configurations check that purging releases page 0 and keeps page
2, that the secondary class takes free page 0 below its partly used page 1,
and that, once page 0 is full, it claims from page 1 without setting up page 3.
The concurrent frees/trim fixture keeps its native 4-worker × 40-round ×
300-block stress. Under Miri it uses 4 workers × 4 rounds × 129 blocks and a
request/acknowledgement ticket for each worker’s first-round overlapping
sweep. Each of four actual decay sweeps acknowledges exactly one live batch
before that worker continues. This bounds the number of concurrent sweeps,
not a sweep’s own duration. Both configurations retain class rotation, their
flush schedule, cache retirement and final candidate/index/live-block checks.
The three-segment small-page fixture keeps its 774,144 uncached 16-byte
allocations and frees in native tests. Under Miri it retains 1,512 distinct
8,192-byte allocations across 189 small pages and three segments, but uses an
attached cache on preferred shard 6; it frees all but the final allocation
through that cache and retires the cache before the same two forced purges.
The cached construction batches bitmap updates without reducing the retained
page or segment topology. This fixture adjustment changes the Miri allocation
path only; it does not qualify a complete Miri campaign or predict that the
case will meet its timeout.
The lost-candidate reconciliation fixture keeps its 65 allocations, frees,
reconciliation epoch and force-purge assertions in both builds. Native tests
retain the helper's full segment scan; under Miri, the test proves that those
blocks occupy two pages in its only owned segment and clears that segment's
empty-candidate metadata directly, preserving the same owned-segment
corruption without scanning every possible segment.
The refill-driven decay fixture keeps its 2,560 native 16-byte allocations.
Under Miri it retains 40 live blocks on the same small page and returns each
refill's unused claims before requesting the next block. Both paths exercise
40 genuine refills; the Miri witness changes word occupancy and claim returns,
and checks the exact time-zero and due-time maintenance samples, four-page
purge, cache retirement and retained empty page. It does not replace the
separate multiword fixtures or establish a complete Miri campaign pass.
The Miri model workload uses at most 96 semantic instructions and a bounded
cumulative allocation-page allowance, checked by an independent decoder. Its
deterministic prefix covers route changes, cross-cache frees, resize, maintenance and failed
batches; two Miri-only tests witness successful resize and a failed dirty-run
batch. Native arbitrary-byte model generation keeps its original stress
counts. Derive the full test manifest from the selected configuration because
Miri-only witnesses add tests. A timeout or cancellation is not a pass.
To re-audit a captured campaign without rerunning Miri, use its recorded
manifest and exact Cargo test list:

```sh
scripts/verify-miri-results.sh \
  --manifest DIR/results.tsv \
  --tests-list DIR/tests.list \
  --tests-names DIR/tests.names \
  --output DIR/verified-results.tsv
```

The auditor checks every listed test exactly once, both exit codes, and the
outcome and summary in each log. It writes a separate verified manifest and
never edits the captured inputs. If the raw runner recorded the one approved
contention benchmark as failed but its zero-exit log contains the exact
`ignored, benchmark; prints timings` outcome, the auditor keeps `failed` in
`recorded_status`, sets `verified_status` to `approved_ignored_benchmark`, and
prints a warning. Other failures, timeouts, missing tests or different skip
reasons remain failures.
The same correction is allowed for a historical failed record whose zero-exit
log proves an exact passing `- should panic ... ok` outcome and matching
one-test summary. Earlier parsers omitted libtest's expected-panic annotation.
The auditor retains the original failed status and warns; a nonzero exit or
ordinary passing log cannot use that correction.
New runner manifests contain absolute log paths. For an older manifest whose
log paths were relative to the original working directory, add
`--log-root ORIGINAL_WORKING_DIRECTORY`. Without that option, relative log
paths resolve from the manifest's directory.

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
