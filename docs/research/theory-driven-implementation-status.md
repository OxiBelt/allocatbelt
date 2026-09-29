# Theory-driven performance plan: implementation status

Status record of `allocatbelt-theory-driven-performance-implementation.md` (the brief of 2026-09-29, section 13), on `research/rust-allocator`. One row per stage; details per stage below.

**Performance not measured; benchmark gate intentionally disabled.** No benchmark was run for any stage below, no benchmark data was added, and no performance threshold or benchmark status check exists (brief section 12). Operation-count assertions in the tests are correctness tests of the mechanisms, not throughput gates.

| Stage | State | Implemented scope | Benchmark status |
|---|---|---|---|
| A: contracts, observability, test scaffolding | **done** | Purge, free-buffering and search/trim counters; memory usage walk; deterministic tests; RSS wording | Not measured |
| B / P1: bounded, resumable reclamation | not started | | |
| C / P1: collision-aware free batching, cooperative cache return | not started | | |
| D / P2: selective cursor invalidation, candidate indexes | not started | | |
| E / P2: explicit-lifetime region API | not started | | |
| F / P3: placement experiments (conditional) | not started, conditional | | |
| G: integration, docs, optional benchmark tooling | not started | | |

Only Stage A is implemented. Nothing here is a claim that the allocator got faster, and nothing is recommended for production.

## Stage A: define the mechanism before tuning it

**What changed.** Allocator behaviour is unchanged; Stage A only observes it. [docs/observability.md](../observability.md) documents the result for users.

| Mechanism | Observations added | Where counted |
|---|---|---|
| Purging | `MaintenanceStats`: `failed_runs`, `purged_pages`, `segments_inspected`, `trimmed_shards`, `busy_shards`, `trim_pages_inspected`, `released_pages`, `returned_segments`, `skipped_passes`, `hard_limit_passes` (beside the existing pass, batch and run counters) | `heap/purge.rs` `pass`, `purge_segments`, `purge_claimed`, `trim_shards`, `release_empty_pages`, `maybe_decay`; `heap/maint.rs` `over_budget`; a pass counts in `PassWork` and adds it in `count_work` |
| Free buffering | `CacheStats`: `claimed_blocks`, `buffered_blocks`, `buffered_words`, `flushes`, `flushed_blocks`, `flush_sizes` (popcount histogram), `evictions`, `refill_flushes` | `heap/cache.rs` `flush_slot`, `replace_slot`, `refill`, `cache_stats` |
| Search/trim | `SearchStats`: `refills`, `cursor_claims`, `cursor_retired`, `page_searches`, `page_search_segments`, `candidates`, `stale_hints`, `new_pages`, `cursor_invalidations`, `run_searches`, `run_search_segments`, `new_segments` | `heap.rs` `claim_class_word`, `find_page`, `new_small_page`, `alloc_pages`; `heap/purge.rs` `release_empty_pages`; summed in `heap/observe.rs` `search_stats` |
| Memory kinds | `HeapUsage`: owned and huge segments, pages in use, small pages, small bytes out and free, dirty and clean pages | `heap/observe.rs` `Heap::usage` |

Public API added (all `#[non_exhaustive]`, allocation-free): `Allocatbelt::search_stats`, `heap_usage`, `thread_cache_stats`; types `SearchStats`, `CacheStats`, `HeapUsage`; the new `MaintenanceStats` fields. `release_empty_pages` now clears a class cursor with `swap` instead of `store` to count invalidations; it still clears every cursor of a trimmed shard (selective invalidation is Stage D).

**Accounting.** The seven quantities of the brief are told apart in [docs/observability.md](../observability.md): live bytes (not tracked exactly; `small_bytes_out` includes cached blocks), blocks retained by a thread cache (`CacheStats`, owner thread only), free pages awaiting purge (`HeapUsage::dirty_pages`, `dirty_bytes`), purged bytes (`purged_pages`), failed attempts (`failed_runs`), reserved virtual memory (the fixed 64 GiB arena) and RSS (external only). RSS wording corrected: the README's "a 32 MiB dirty budget bounds RSS under churn", `Allocatbelt::purge`'s "shrink RSS", and the docs of `DIRTY_BUDGET_PAGES`, `DIRTY_HARD_LIMIT_PAGES` and the purge module now say the budget bounds tracked dirty pages, not RSS.

**Wrap and snapshot semantics.** Counters only grow and wrap modulo 2^64 (`wrapping_add`). A read is a series of individually atomic loads, not a consistent snapshot; a pass adds its work at its end, so counters of one pass appear together. `HeapUsage` is approximate under concurrency. Cache counters belong to the owning thread.

### Complexity notes

| Change | What grows | Work bounded | Extra memory | Outside the bound |
|---|---|---|---|---|
| Purge counters | nothing new per operation | per pass: local increments while the pass already walks shards, segments and runs, then at most 10 `fetch_add`s for the work (zero counts skipped) beside the pass's existing counter | 10 `AtomicU64` in the heap's stats array (80 bytes, once) | the pass's own walk, unchanged |
| Search counters | per shard | per refill and page-run search: one load and store per counter touched, under the shard lock already held; segment and candidate counts are local and added once per search | 12 `AtomicU64` per shard; `Shard` stays 384 bytes (its `align(128)` padding absorbs the 96 bytes) | the segment-list walk of `find_page` itself (Stage D's subject) |
| Cache counters | per thread | per flush or eviction: two or three `Cell` updates; a buffered free that does not flush touches none | 10 `u64` per `ThreadCache` (80 bytes of TLS per thread) | none |
| `search_stats()` | shards (fixed 64) | 12 loads per shard | none | none |
| `heap_usage()` | segments in use | a few loads per segment, one per small page and class word | none (no allocation, no lock) | O(segments in use): diagnostics, not a hot path |
| `cache_stats()` | fixed | 64 slots + 32 class words of the caller's cache | none | none |

No new atomic read-modify-write on an allocation or free path; no allocation in any diagnostic; no new unsafe code (the `unsafe-boundary.md` inventory is unchanged).

### Invariant tests

- `crates/allocatbelt/src/core/tests.rs`, section "observations": `purge_work_is_counted`, `failed_purges_are_counted_and_stay_dirty`, `busy_shards_are_skipped_and_counted`, `contended_inline_passes_are_counted_as_skipped`, `hard_limit_interventions_are_counted`, `trimming_counts_released_pages_and_forgotten_cursors`, `a_full_word_is_flushed_in_one_update`, `slot_collisions_are_counted_as_evictions`, `refills_count_their_search`, `usage_tells_memory_apart`. Each asserts exact operation counts on `MockOs` and `MockPurger`, with the shard lock or purge lock held by the test (`with_shard_held`, `with_purge_lock_held`) where contention is the subject.
- `model::check_observations`, run by fuzz operation 31 and at the end of every `model::run` program (so by the fuzz target and the model tests): failed runs within attempted runs, purged pages within the bytes `MockOs` purged, hard-limit passes within inline budget passes, released pages within trimmed pages, stale hints within candidates, cursor claims within refills, new segments within run searches, `usage().dirty_pages` equal to the dirty counter, owned plus huge segments equal to segments in use, pages of owned segments adding up to 63 each, and per cache: flushes equal to the histogram's sum, `flushes <= flushed_blocks <= 64 * flushes`, evictions within flushes. At the end of a program nothing may be in use.
- `crates/allocatbelt/tests/global.rs` `diagnostics_are_readable_through_the_adapter`: the adapter's methods under the real global allocator.

### Checks run (x86_64 host, 1.98.1)

| Check | Result |
|---|---|
| `cargo fmt --all --check` | pass |
| `cargo clippy --all-targets --all-features --locked -- -D warnings` | pass |
| `cargo test --release --all-features --locked` | pass |
| `scripts/check-features.sh` | pass |
| `scripts/check-package.sh` | pass (after replacing four doc links to crate-private `Heap` methods that the docs.rs build rejected) |
| Loom (`RUSTFLAGS="-C target-cpu=x86-64-v3 --cfg loom" cargo test --release --locked -p allocatbelt-core-check --lib loom`) | pass (13 models) |
| Miri (`cargo +nightly-2026-09-27 miri test -p allocatbelt-core-check`) | run locally; not part of CI (see below) |
| aarch64, riscv64 (qemu), sandbox, rseq, experimental ISA, platform gates, audit, deny, fuzz | by CI on the pushed commit |
| Mutation campaign | not run: `bits.rs` and `class.rs` are unchanged |

Miri: the local run of the core tests under the pinned nightly was still in progress at commit time; its result is reported in the handoff and recorded here by the next change.

No protocol in `proto.rs` changed and no atomic ordering was weakened, so no new Loom model was needed; the existing models still run.

### Known limitations

- Passes are not sliced yet, so there is no slice-continuation counter (Stage B adds slicing).
- There is no candidate index yet, so there is no reconstruction-work counter; `page_search_segments` measures the fallback scan (Stage D).
- Live bytes are not tracked exactly; tracking them would need a counter on every allocation and free.
- Other threads' caches cannot be read; a cache is owner-only state.
- RSS is not measured by the allocator and no policy caps it.
