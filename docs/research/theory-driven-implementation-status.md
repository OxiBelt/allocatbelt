# Theory-driven performance plan: implementation status

Status record of `allocatbelt-theory-driven-performance-implementation.md` (the brief of 2026-09-29, section 13), on `research/rust-allocator`. One row per stage; details per stage below.

**Performance not measured; benchmark gate intentionally disabled.** No benchmark was run for any stage below, no benchmark data was added, and no performance threshold or benchmark status check exists (brief section 12). Operation-count assertions in the tests are correctness tests of the mechanisms, not throughput gates.

| Stage | State | Implemented scope | Benchmark status |
|---|---|---|---|
| A: contracts, observability, test scaffolding | **done** | Purge, free-buffering and search/trim counters; memory usage walk; deterministic tests; RSS wording | Not measured |
| B / P1: bounded, resumable reclamation | **done** | Thresholds (low target, trigger, emergency) separate from the mechanism; every pass a sweep in bounded, resumable slices; stall deferral; opt-in adaptive retention | Not measured |
| C / P1: collision-aware free batching, cooperative cache return | not started | | |
| D / P2: selective cursor invalidation, candidate indexes | not started | | |
| E / P2: explicit-lifetime region API | not started | | |
| F / P3: placement experiments (conditional) | not started, conditional | | |
| G: integration, docs, optional benchmark tooling | not started | | |

Stages A and B are implemented; C to G are not. Nothing here is a claim that the allocator got faster, and nothing is recommended for production.

## Stage A: define the mechanism before tuning it

**What changed.** Allocator behaviour is unchanged; Stage A only observes it. [docs/observability.md](../observability.md) documents the result for users.

| Mechanism | Observations added | Where counted |
|---|---|---|
| Purging | `MaintenanceStats`: `failed_runs`, `purged_pages`, `segments_inspected`, `trimmed_shards`, `busy_shards`, `trim_pages_inspected`, `released_pages`, `returned_segments`, `skipped_passes`, `hard_limit_passes` (renamed `hard_limit_slices` by Stage B) (beside the existing pass, batch and run counters) | `heap/purge.rs` `pass`, `purge_segments`, `purge_claimed`, `trim_shards`, `release_empty_pages`, `maybe_decay`; `heap/maint.rs` `over_budget`; a pass counts in `PassWork` and adds it in `count_work` |
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

Miri (recorded after the commit): the full core suite under Miri did not finish within the local 50-minute limit. The 24 tests it reached passed, up to `batched_purges_complete_and_clean`, and none failed. The rest is **not run**: outstanding verification, not a pass.

No protocol in `proto.rs` changed and no atomic ordering was weakened, so no new Loom model was needed; the existing models still run.

### Known limitations

- Passes were not sliced yet in Stage A; Stage B added slicing and its counters (`slices`, `reclaim_status`).
- There is no candidate index yet, so there is no reconstruction-work counter; `page_search_segments` measures the fallback scan (Stage D).
- Live bytes are not tracked exactly; tracking them would need a counter on every allocation and free.
- Other threads' caches cannot be read; a cache is owner-only state.
- RSS is not measured by the allocator and no policy caps it.

## Stage B: bounded, resumable reclamation and adaptive retention

**What changed.** [docs/reclamation.md](../reclamation.md) is the user-facing description; `core/heap/reclaim.rs` has the mechanism and its invariants in the module docs.

| Part | Implemented | Changed symbols |
|---|---|---|
| B1 policy/mechanism split | `ReclaimTargets` (low target < trigger <= emergency, in pages, validated: zero trigger, order, larger than the arena; bytes round down), packed in one word so a read is consistent. Defaults are the old constants (512, 1024 pages) with low target 0, so a budget cycle purges what the old budget pass did. Deterministic (non-adaptive) mode is the default. | `reclaim.rs` `ReclaimTargets`, `ReclaimTargetsError`, `Heap::set_reclaim_targets`, `reclaim_targets`; `Allocatbelt::set_reclaim_targets`, `reclaim_targets`; `DIRTY_BUDGET_PAGES`/`DIRTY_HARD_LIMIT_PAGES` are now the defaults |
| B2 resumable slices | Every pass (decay, budget, force) is a sweep run in slices, bounded by work units (shards, segments, small pages, bitmap words, submitted runs: attempts, not successes). Trimming is inside the bound (per segment, instead of the old full `trim_shards` traversal). Position kept between slices: segment index (purge), last kept segment of the current shard (trim, validated). Each slice finishes its claims. Sweep epoch/age/cutoff fixed at start; epochs advance only on the decay schedule (`decay_tick`). Round-robin: trim start rotates per sweep, the purge phase restarts after the segment where a budget sweep reached its target, busy shards are skipped. Force replaces, budget upgrades decay, decay is owed while another sweep runs. | `Sweep`, `SweepState`, `Heap::slice`, `trim_step`, `purge_step`, `start`, `finish_sweep`, `run_sweep`, `decay_tick`; `purge.rs` `Batch::new`, `claimed_pages`, `release_empty_pages` (per segment); removed `pass`, `trim_shards`, `purge_segments`, `maybe_decay`, `over_budget` |
| B3 progress and failure | Cycle ends at the low target or after a full sweep, never merely below the trigger; restarts only above the trigger. A full sweep without progress stalls it: deferred to the next decay epoch, counted (`stalled_cycles`), visible (`reclaim_status`). The maintenance thread runs one slice per round and sleeps on a deferred request without spinning (`proto::idle_word`, Loom model). Without it, page-run frees and allocation slow paths resume pending work. Past the emergency threshold, bounded emergency slices (4x) on freeing threads. `purge()` replaces any sweep with a force sweep run to its end; `request_purge()` stays asynchronous only with a maintenance thread. Partial batch failure keeps failed runs dirty, finishes the rest; `MADV_DONTNEED` unchanged. | `Heap::after_release`, `budget_opportunity`, `maybe_housekeep`, `next_task`, `run_task`, `maintain_with`, `request_purge`, `purge`, `decay`; `proto::idle_word`; `MaintenanceStats::slices`, `inline_slices`, `emergency_slices`, `hard_limit_slices`, `stalled_cycles`; `ReclaimStatus`, `Allocatbelt::reclaim_status` |
| B4 adaptive retention (opt-in) | `Retention::Adaptive`: once per decay epoch, the share of dirty pages reused (page-run claims) versus purged, fixed-point EWMA (1/4), hysteresis (up above 3/4, down below 1/4), at most one step per delay, bounded to 1..4x the purge delay. Reset by force purge, purge request, zero delay. No clock, file or syscall beyond the decay schedule; nothing per allocation or free. Thresholds unaffected. | `Retention`, `MAX_RETENTION`, `Heap::set_retention`, `adapt_retention`, `reset_retention`, `decay_age`; `SearchStats::dirty_reused_pages`; `Allocatbelt::set_retention` |

`Task` became `#[non_exhaustive]` (it is now public as `ReclaimStatus::sweep`). The model program (`model::run`, fuzz target) now also changes thresholds, slice size (down to one unit) and retention mode (operation 26).

### Complexity notes

| Change | What grows | Work bounded | Extra memory | Outside the bound |
|---|---|---|---|---|
| Slices | nothing per operation | per slice: 4096 units (16384 emergency) plus one segment step (at most 64 pages, 32 runs) | the sweep state, about 25 words in the heap, once | the kernel's time per submitted purge; explicit `purge()`/`decay()` run their sweep to the end |
| Trim in slices | per shard visit: 32 cursor swaps (as before per pass) | per segment step: 1 + small pages checked | none | none |
| Free path | page-run frees: two relaxed loads (packed thresholds, pending flag); small frees unchanged | a slice when pending or past a threshold | none | none |
| Maintenance sleep | nothing | one load (`idle_word`) | none | none |
| Adaptive retention | nothing per operation | per decay epoch: one summed read of the counters (64 shards) | 6 words | none |
| Dirty reuse counter | per shard | one load/store under the shard lock on page-run claims | 8 bytes per shard (`Shard` stays 384 bytes) | none |

### Invariant tests

`crates/allocatbelt/src/core/tests.rs`, section "bounded, resumable reclamation":

- `reclaim_targets_are_validated`: thresholds.
- `budget_cycles_purge_down_to_the_low_target`: threshold transitions.
- `cycles_continue_below_the_trigger_until_the_low_target`: incomplete cycles below the trigger and above the target.
- `slices_bound_attempted_work_when_every_purge_fails` and `stalled_cycles_leave_frees_alone_until_the_emergency_threshold`: attempted-work bounds with all purges failing, and deferral.
- `partial_batch_success_finishes_every_claim`.
- `busy_shards_do_not_hold_up_later_ones`: busy-shard fairness.
- `resumed_sweeps_survive_segment_reuse`: huge blocks, new segments and frees between slices.
- `many_slices_do_not_age_pages_faster`: delay and epoch semantics across many slices.
- `target_changes_apply_to_the_cycle_in_progress` and `purge_delay_changes_leave_the_sweep_in_progress_alone`: configuration changes.
- `detached_maintenance_leaves_the_cycle_to_frees_and_allocations`: maintenance detach.
- `without_a_worker_page_run_frees_resume_the_cycle`: no-worker progress.
- `force_purges_preempt_a_budget_cycle`: force preemption.
- `emergency_slices_are_larger_but_bounded`.
- `adaptive_retention_follows_reuse_and_idleness`.

The Stage A tests and all earlier purge, decay and maintenance tests pass unchanged (default thresholds and slice size), including `budget_passes_purge_everything_dirty` (its expectation still holds with low target 0).

Loom: `proto::loom_tests::deferred_budget_does_not_hide_a_force_request` covers the new sleep with a deferred request. A force request must still wake the thread, and a repeated budget post must not. The existing request/take and sleep models still run. The sweep state itself is only touched under `purge_lock`, and the free path reads the pending flag and thresholds as hints: a lost update is recovered from the dirty count, which frees re-check, and from the recorded request bit, which the thread re-reads. So no new ordering protocol needed a model.

`crates/allocatbelt/tests/global.rs` `reclamation_is_configurable_through_the_adapter`: the adapter's API.

### Checks run (x86_64 host, 1.98.1)

| Check | Result |
|---|---|
| `cargo fmt --all --check` | pass |
| `cargo clippy --all-targets --all-features --locked -- -D warnings` | pass |
| `cargo test --release --all-features --locked` | pass (core suite: 93 tests) |
| `scripts/check-features.sh` | pass |
| `scripts/check-rseq.sh` | pass (seccomp and tunable cases skipped on this host, as before) |
| `scripts/check-package.sh` | pass |
| Loom (`RUSTFLAGS="-C target-cpu=x86-64-v3 --cfg loom" cargo test --release --locked -p allocatbelt-core-check --lib loom`) | pass (14 models, one new) |
| Miri on the 16 Stage B tests (`cargo +nightly-2026-09-27 miri test -p allocatbelt-core-check --lib -- <names>`) | run locally; not part of CI, see below |
| `scripts/check-sandbox.sh` | not run locally (no Docker daemon on this host); by CI |
| aarch64, riscv64 (qemu), experimental ISA, platform gates, audit, deny, fuzz | by CI on the pushed commit |
| Mutation campaign | not run: `bits.rs` and `class.rs` are unchanged |
| Benchmarks | not run. Performance not measured; benchmark gate intentionally disabled. |

### Known limitations

- The defaults were kept, not tuned: a low target of 0 purges as much as before, the slice limit (4096 units) and the emergency factor (4) are unmeasured choices, and the adaptive controller's constants (1/4 weight, 1/4 and 3/4 bands, 4x cap) are too.
- Without a maintenance thread, reclamation only happens on allocator calls; an idle process keeps its dirty pages until it calls again.
- The adaptive signal counts page-run reuse only (small pages reuse through their own bitmaps, not through dirty pages), and is not a page-fault measurement.
- Trimming still clears every class cursor of a shard at each visit (selective invalidation is Stage D).
