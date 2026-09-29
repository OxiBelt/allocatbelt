# Publish-readiness review (single-package directive Phase I)

Review of 2026-09-28, on `research/rust-allocator` after Phase H (`b0a7f4c`). **Nothing was published**: no `cargo publish`, no tag, no release. Every check below is a dry run or a local build, and no benchmark was run.

Verdict: the package `allocatbelt` is technically ready for `cargo publish`. The decisions in [section 8](#8-decisions-before-the-first-publish) are the owner's to make first.

## 1. Package metadata

| Field | Value | Note |
|---|---|---|
| `name` | `allocatbelt` | Not taken on crates.io (API query on 2026-09-28: "crate `allocatbelt` does not exist"). |
| `version` | `0.1.0` | Pre-1.0: a later `0.2` may break the API. |
| `edition`, `rust-version` | 2024, 1.98 | The MSRV CI uses (1.98.1). |
| `license` | `Apache-2.0` | `LICENSE` is in the package. |
| `description` | updated | It now names the three unsafe boundaries (syscall, CPU detection, `GlobalAlloc`), not two. |
| `repository`, `readme` | GitHub, the top-level README | See decision 2 for the README's links. |
| `keywords`, `categories` | 4 keywords; `memory-management`, `os::linux-apis` | Both categories are valid crates.io slugs. |
| `include` | `src/**/*.rs`, `tests/**/*.rs`, `LICENSE` (+ `Cargo.toml`, `README.md`) | 53 files, 429 KiB (124 KiB compressed). No `bench`, `fuzz`, `scripts`, `docs` or `.cargo`. |
| `[package.metadata.docs.rs]` | **new** | See below. |

Every other package of the workspace (`allocatbelt-core-check`, `allocatbelt-codegen-probes`, `allocatbelt-bench`, `allocatbelt-simd-bench`, `fuzz`) is `publish = false`, and none is a dependency of `allocatbelt`.

**docs.rs would have failed.** docs.rs builds x86_64 documentation without this repository's `.cargo/config.toml`, so the platform gate stopped it with "allocatbelt on x86_64 must be built for x86-64-v3 or newer" (reproduced on the unpacked crate). `[package.metadata.docs.rs]` now passes `-C target-cpu=x86-64-v3` to rustc and rustdoc, builds one target (`x86_64-unknown-linux-gnu`) with all features, and `lib.rs` enables `doc_cfg` under docs.rs's `--cfg docsrs`, so each feature-gated item says which feature it needs (checked with the pinned nightly). Five rustdoc warnings about public docs linking private items were fixed.

## 2. `cargo package` and `cargo publish --dry-run`

Both pass with `--locked` (`scripts/check-package.sh`, CI job "crates.io package" on x86_64 and arm64). The packaged manifest has no path dependency.

## 3. A fresh external consumer

`scripts/check-package.sh` unpacks the `.crate` into a temporary directory, outside the workspace and its `.cargo/config.toml`, and:

- builds and runs a consumer binary that uses it as `#[global_allocator]` with the default features, `default-features = false`, `io-uring` (with and without defaults), `experimental-rseq`, `experimental-aarch64-sve2` and `experimental-riscv-rvv`, checking each build's `CompiledCapabilities`;
- **new:** runs the unpacked crate's own tests (unit, integration and doctests), as crater or a vendoring user would;
- **new:** builds its documentation with the flags from `[package.metadata.docs.rs]` alone, with rustdoc warnings as errors.

Finding: a consumer's doctests need the x86-64-v3 flag in `RUSTDOCFLAGS` too, because Cargo's `rustflags` do not reach rustdoc. The README's example now sets `rustdocflags` as well.

## 4. x86-64-v3 error and success paths

On x86_64 the consumer fails without `-C target-cpu=x86-64-v3`, with the gate's message, and builds and runs with it (`check-package.sh`). `scripts/check-platform-gates.sh` (CI job "Platform gates") builds every supported target and checks that x86-64-v1/v2, 32-bit, big-endian and non-Linux targets are rejected with their messages.

## 5. Stable default and optional stable features

Everything except `experimental-riscv-rvv` on riscv64 builds on stable 1.98.1. `scripts/check-features.sh` (CI job "Feature combinations", x86_64 and arm64) lints and tests 11 combinations; `cargo clippy/test --all-features` runs on both (on those architectures the RVV feature compiles nothing, so `--all-features` stays on stable, directive §16).

## 6. Experimental target matrix, tested separately

| Feature | Toolchain | Where it does something | CI job | How |
|---|---|---|---|---|
| `experimental-rseq` | stable | glibc 2.35+ on Linux 6.3+ | "Experimental rseq mm_cid" (x86_64, arm64); riscv64 qemu jobs | glibc with registration, with `glibc.pthread.rseq=0`, static musl; fork, cpuset, seccomp refusal |
| `experimental-aarch64-sve`, `-sve2` | stable | aarch64 with SVE/SVE2 | "Experimental aarch64 SVE/SVE2 kernels" (arm64) | native, and qemu CPU models and vector lengths |
| `experimental-riscv-rvv` | **nightly** on riscv64 (pinned `nightly-2026-09-27`) | riscv64 with V | "Experimental riscv64 RVV kernel (nightly)" | qemu with VLEN 128/256/1024 and without V; V instructions only in the kernel |

None of them is a default, and none is selected by `Auto`.

## 7. Public API and feature names (SemVer cost)

What 0.1.0 would publish: `Allocatbelt` (the allocator and its methods), `Policy`, `FeaturePolicy`, `Capability`, `PolicyError`, `CompiledCapabilities`, `DetectedCapabilities`, `Availability`, `EffectiveProfile`, `Report`, `PurgeBackend`, `MaintenanceStats`, `Capabilities`, `KernelVersion`, `CpuFeatures`, `KernelSet`; with `io-uring` `RingError`; with `experimental-rseq` `RseqPolicy`, `RseqStatus`, `RseqUnavailable`. Features: `maintenance`, `scheduler`, `io-uring`, `experimental-rseq`, `experimental-aarch64-sve`, `experimental-aarch64-sve2`, `experimental-riscv-rvv`.

Added after this review (theory-driven plan Stage A, see [theory-driven-implementation-status.md](theory-driven-implementation-status.md)): `SearchStats`, `CacheStats` and `HeapUsage`, all `#[non_exhaustive]`, read through `Allocatbelt::search_stats`, `heap_usage` and `thread_cache_stats`, and new `MaintenanceStats` fields.

Changed in this review, so that later additions are not breaking:

- `#[non_exhaustive]` on `MaintenanceStats`, `PurgeBackend`, `Capabilities`, `RingError`, `RseqStatus` and `RseqUnavailable`: types whose fields or variants are expected to grow (new counters, backends, probe results, rseq failure causes). The other report and policy types already were. Users read these types; they cannot build them with a literal or match them exhaustively any more, which nothing in this repository did.
- `CpuFeatures::with_if` is now crate-private: it was the detection code's builder, not API.

Kept on purpose:

- `KernelVersion` stays exhaustive: `major.minor.patch` is complete, and users may build one to compare with.
- `CpuFeatures::bits`/`from_bits` keep its `u32` representation public; the constants differ per architecture, which the docs say.
- The feature names follow the directive's surface (§5.2): stable names are plain, experimental ones carry `experimental-` and the architecture. Once published, a feature name should not be removed in a compatible release (§19.4).

## 8. Decisions before the first publish

These are the owner's; nothing here blocks the code.

1. **Whether and when to publish**, and from which crates.io account. The name is free today and is reserved only by publishing.
2. **README links on crates.io.** crates.io resolves the README's relative links (`docs/features.md`, `docs/platform.md` and the others) against the repository's default branch, `main`, which holds only `LICENSE`, so they would 404. Either merge this branch into `main` before publishing or make those links absolute.
3. **Duplicate names before they become permanent.** Recommended: remove `Allocatbelt::start_purge_thread` (the former name of `start_maintenance_thread`, from before any release) and the `RseqPolicy` alias of `FeaturePolicy`; consider removing `set_io_uring(bool)`, which `Policy::io_uring` covers. Removing them later needs `0.2`.
4. **Experimental features in 0.1.0.** Publishing them makes their names public API. Keeping them is consistent with the directive (non-default, labelled); leaving `experimental-riscv-rvv` out until V is stable in Rust is the conservative choice.
5. **License.** `Apache-2.0` alone; many Rust crates use `MIT OR Apache-2.0`.

## 9. Documentation updated

- README: not yet on crates.io (git dependency until then), `rustdocflags` for doctests, allocatbelt and OxiBelt are independent, the new checks.
- docs/platform.md: one table of every optional capability (feature, probe, default policy, fallback, `Require` failure), directive §19.2.
- docs/unsafe-boundary.md: unchanged by this phase (no unsafe added or moved); its paths match the single package.
- docs/features.md: unchanged; it already documents every feature per §19.4.
