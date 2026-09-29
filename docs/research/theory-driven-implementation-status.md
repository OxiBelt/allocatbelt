# Theory-driven performance plan: implementation status

Status record of `allocatbelt-theory-driven-performance-implementation.md` (the brief of 2026-09-29, section 13), on `research/rust-allocator`. One row per stage; details per stage below.

**Performance not measured; benchmark gate intentionally disabled.** No benchmark was run for any stage below, no benchmark data was added, and no performance threshold or benchmark status check exists (brief section 12). Operation-count assertions in the tests are correctness tests of the mechanisms, not throughput gates.

| Stage | State | Implemented scope | Benchmark status |
|---|---|---|---|
| A: contracts, observability, test scaffolding | **done** | Purge, free-buffering and search/trim counters; memory usage walk; deterministic tests; RSS wording | Not measured |
| B / P1: bounded, resumable reclamation | **done** | Thresholds (low target, trigger, emergency) separate from the mechanism; every pass a sweep in bounded, resumable slices; stall deferral; opt-in adaptive retention | Not measured |
| C / P1: collision-aware free batching, cooperative cache return | **done** | 2-way set-associative free buffer (32 x 2, per-set round robin); caller-local cache flush in the adapter; cooperative cache-return generation observed at sampled slow paths of allocation and free | Not measured |
| D / P2: selective cursor invalidation, candidate indexes | **done** (D3 as a bounded design) | D1: class cursors survive trimming, dropped only when their page is released. D2: empty-page candidates published by the last free of a page, revalidated under the shard lock; bounded reconciliation by force sweeps and every 16th decay sweep. D3: class-to-segment index designed, not built ([class-segment-index.md](class-segment-index.md)) | Not measured |
| E / P2: explicit-lifetime region API | not started | | |
| F / P3: placement experiments (conditional) | not started, conditional | | |
| G: integration, docs, optional benchmark tooling | not started | | |

Stages A, B, C and D are implemented (D3 as a design, which the brief accepts as an intermediate delivery); E to G are not. Nothing here is a claim that the allocator got faster, and nothing is recommended for production.

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
- `wrapped_batches_credit_each_segment_its_own_runs`: a batch whose segments wrap round the arena (a sweep resumed after a budget cycle stopped at the low target) credits each segment with its own runs' results.
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
| `cargo test --release --all-features --locked` | pass (core suite: 94 tests with the regression test) |
| `scripts/check-features.sh` | pass |
| `scripts/check-rseq.sh` | pass (seccomp and tunable cases skipped on this host, as before) |
| `scripts/check-package.sh` | pass |
| Loom (`RUSTFLAGS="-C target-cpu=x86-64-v3 --cfg loom" cargo test --release --locked -p allocatbelt-core-check --lib loom`) | pass (14 models, one new) |
| Miri on the 16 Stage B tests first committed (`cargo +nightly-2026-09-27 miri test -p allocatbelt-core-check --lib -- <names>`) | partial, see below; not part of CI |
| `scripts/check-sandbox.sh` | not run locally (no Docker daemon on this host); by CI |
| aarch64, riscv64 (qemu), experimental ISA, platform gates, audit, deny, fuzz | by CI on the pushed commit |
| Mutation campaign (`scripts/run-mutation-testing.sh`) | pass locally (77 caught, 5 listed as equivalent); failed once in CI, see below |
| Benchmarks | not run. Performance not measured; benchmark gate intentionally disabled. |

Miri: within the local 40-minute limit, 11 of the 16 tests passed under Miri (`adaptive_retention_follows_reuse_and_idleness` through `reclaim_targets_are_validated`, in name order) and none failed. `resumed_sweeps_survive_segment_reuse`, `slices_bound_attempted_work_when_every_purge_fails`, `stalled_cycles_leave_frees_alone_until_the_emergency_threshold`, `target_changes_apply_to_the_cycle_in_progress` and `without_a_worker_page_run_frees_resume_the_cycle` are **not run** under Miri, nor is the later regression test: outstanding verification, not a pass.

**Defect found by CI after the first push (fixed in the follow-up commit).** The CI mutation job failed on a stale equivalent-mutant entry: a surviving mutant of `bits.rs` had been "caught" by an unrelated failure of `fuzz_programs`. Repeating that property test locally reproduced a real defect in a few runs out of a hundred: `purge_claimed` matched each claimed segment with its runs by assuming the batch was in ascending segment order, and a sweep that resumes mid-arena and wraps round can put a higher segment ahead of a lower one in the same batch. The higher segment was then credited with the lower one's successful runs, so its failed pages were marked clean (a block later claimed to be zero on a written page), and the lower segment's purged pages stayed dirty. The match is now by segment index, `wrapped_batches_credit_each_segment_its_own_runs` covers it, and 200 further runs of `fuzz_programs` passed.


**Test defect found by CI (fixed in a later commit, not a Stage B change).** `rseq_process`'s forked children hung now and then under qemu-user on riscv64 (killed by their 20 s watchdog). Stopping a hung child under qemu 10.2.1 showed its threads waiting on Rust std's `stack_overflow::thread_info::LOCK`: std's thread start and exit take that process-wide lock, the child inherits it as it was at the `fork`, and another test's thread starting or ending at that moment leaves it held in the child, whose `std::thread` spawns then wait forever. The Stage A commit failed at the same rate (2 of 15 runs; this commit 3 of 15), so Stage B did not cause it. The children now start their threads with `pthread_create` and print nothing; 20 runs under qemu 10.2.1 passed.
### Known limitations

- The defaults were kept, not tuned: a low target of 0 purges as much as before, the slice limit (4096 units) and the emergency factor (4) are unmeasured choices, and the adaptive controller's constants (1/4 weight, 1/4 and 3/4 bands, 4x cap) are too.
- Without a maintenance thread, reclamation only happens on allocator calls; an idle process keeps its dirty pages until it calls again.
- The adaptive signal counts page-run reuse only (small pages reuse through their own bitmaps, not through dirty pages), and is not a page-fault measurement.
- Trimming still clears every class cursor of a shard at each visit (selective invalidation is Stage D). Done by Stage D.

## Stage C: collision-aware free batching and cooperative cache return

**What changed.** [docs/thread-caches.md](../thread-caches.md) is the user-facing description, including the worker integration pattern; `core/heap/cache.rs` has the mechanism in its module docs.

| Part | Implemented | Changed symbols |
|---|---|---|
| C1 2-way set associativity | The 64-slot direct-mapped free buffer became 32 sets of 2 ways, still 64 fixed slots of (key, mask). A free looks in both ways of its word's set for the full key before taking an empty way or the victim. Replacement is per-set round robin: one bit per set in a `u32`, no timestamps. Key encoding (never zero, class in the low bits), per-class pending masks (bit = slot index), flush-before-refill and the check against the claimed word are unchanged. A key is inserted only when neither way of its set holds it, so a word lives in at most one slot and duplicate frees are caught in either way. Flushing a slot clears its class bit once; filling one sets it once. No owner message queue: the shared bitmap stays the transfer, and frees are not classified as remote. | `cache.rs` `FREE_WAYS`, `FREE_SETS`, `set_index` (was `slot_index`), `buffer_free`, `insert_slot` (was `replace_slot`), `ThreadCache::victims`; `CacheStats::evictions` now counts evictions of a full set |
| C2 cooperative cache return | `Allocatbelt::flush_thread_cache`: the caller's cache, whole (at most 64 slots and one claimed word per class), through `Heap::flush`; stays attached; no arena or cache initialisation, no allocation; documented as not async-signal-safe. `Allocatbelt::request_cache_return` / `Heap::request_cache_return`: bumps a `u32` generation (relaxed). Each attached cache compares it with the last generation it drained for at sampled points: refill, page-run and huge allocation and free, and a free that needs a new slot (so a free-only thread sees it within 4096 small frees). On a new value the owner drains completely, then records the generation (completion only after the obligation is met) and counts it. New caches start at the current generation; attaching caches and retired ones are never asked; a reentrant `attach` is now a no-op that keeps shard, random state and obligation. Claimed words are returned too, not only buffered frees. Nothing waits for other threads, so a fork child does not wait for vanished caches or the vanished maintenance thread. | `Heap::request_cache_return`, `cache_return_generation`, `observe_pressure`, `return_cache`, `attach`; `Heap::cache_pressure`; `ThreadCache::pressure_seen`, `pressure_returns`; `CacheStats::pressure_returns`; `Allocatbelt::flush_thread_cache`, `request_cache_return` |

The model program (`model::run`, fuzz target) now also requests cache returns (operation 22 on the uncached "thread"), and `model::check_observations` checks every cache's free buffer: each occupied slot in its word's set, no word in two slots, pending masks equal to the occupied slots of each class.

### Complexity notes

| Change | What grows | Work bounded | Extra memory | Outside the bound |
|---|---|---|---|---|
| 2-way lookup | small free fast path: one more key comparison | per free: two slots | 4 bytes per cache (victim bits) | none |
| Eviction | nothing | one slot flush (one `fetch_or`) | none | none |
| Cache-return check | sampled slow paths: one relaxed load and a comparison | none when nothing is requested | 12 bytes per cache, 4 in the heap | none |
| Drain (explicit or requested) | nothing | at most 64 slot flushes plus one claimed word per class, one atomic update each | none | a thread that sleeps or stops calling the allocator never drains: no time bound without its cooperation |

### Invariant tests

`crates/allocatbelt/src/core/tests.rs`:

- `a_third_word_in_a_set_evicts_the_older_way` (replaces `slot_collisions_are_counted_as_evictions`): colliding distinct keys share a set without eviction; a third word evicts the older way; round robin; a matching second way.
- `interleaved_frees_of_one_set_batch_without_evictions`: the deterministic operation-count test. 128 alternating frees of two words of one set: no eviction, two updates of 64 blocks (a direct-mapped buffer would make 127 one-block updates).
- `duplicate_free_in_the_first_way`, `duplicate_free_in_the_second_way`; `free_of_a_claimed_block` and `double_free_in_buffer` unchanged.
- `pending_masks_follow_evictions_across_classes`: masks after evictions across three classes; every freed block flushed or buffered exactly once.
- `a_refill_flushes_only_its_class_and_flush_the_rest`: partial (per-class, before a refill would grow the heap) and full flush.
- `producer_consumer_frees_are_all_accounted_for`: frees through another thread's cache; everything accounted for after retirement.
- `free_only_threads_see_cache_return_requests`, `allocations_see_cache_return_requests`, `cache_return_generations_wrap`, `caches_owe_only_requests_made_while_attached` (new caches, reentrant attach, attaching and retired caches).
- `parked_workers_that_flush_hold_nothing` and `parked_workers_keep_their_cache_until_they_run`: a parked thread following the flush contract, and one that does not (a request reaches no sleeping thread; it drains when it runs).
- `fork_children_do_not_wait_for_vanished_caches`.

`crates/allocatbelt/tests/global.rs` `thread_caches_are_returned_explicitly_and_on_request` (adapter, TLS cache; a thread that never allocated), and `tests/fork_maintenance.rs` (request and flush in a fork child). Thread exit and TLS teardown keep their tests (`exiting_threads_return_their_caches`, `thread_local_destructors_may_free_after_retire`).

Loom: no new model. The generation is a relaxed counter read by each cache's owner; a missed or late read only delays a cooperative drain, and the drain itself is the existing flush, whose `fetch_or` protocol the existing models cover.

### Checks run (x86_64 host, 1.98.1)

| Check | Result |
|---|---|
| `cargo fmt --all --check` | pass |
| `cargo clippy --all-targets --all-features --locked -- -D warnings` | pass |
| `cargo test --release --all-features --locked` | pass (core suite: 107 tests) |
| `fuzz_programs` (the model's property test) repeated 80 times | pass |
| `scripts/check-features.sh` | pass |
| `scripts/check-rseq.sh` | pass (seccomp and tunable cases skipped on this host, as before) |
| `scripts/check-package.sh` | pass |
| Loom (`RUSTFLAGS="-C target-cpu=x86-64-v3 --cfg loom" cargo test --release --locked -p allocatbelt-core-check --lib loom`) | pass (14 models, none new) |
| Miri on the Stage C core tests | **not completed**: the local run after the commit (all 14 Stage C tests, 40-minute cap, pinned nightly) did not finish its first test (`a_refill_flushes_only_its_class_and_flush_the_rest`) within the cap, so no Stage C test has a Miri result from it. Targeted runs of single, smaller tests: see Stage D's checks. Miri is not part of CI. |
| `scripts/check-sandbox.sh` | not run locally (no Docker daemon on this host); by CI |
| aarch64, riscv64 (qemu), experimental ISA, platform gates, audit, deny, fuzz, mutation | by CI on the pushed commit (`bits.rs` and `class.rs` unchanged) |
| Benchmarks | not run. Performance not measured; benchmark gate intentionally disabled. |

### Known limitations

- Two ways, 64 slots and round robin are the brief's starting point, not tuned; 4-way sets, larger buffers and other eviction policies were not tried.
- A cache return needs the thread's cooperation: sleeping or blocked threads keep their caches, and there is no time bound. Only the owner drains its cache.
- The free-only bound (4096 frees) counts small frees; a thread that frees nothing and allocates only from its claimed words sees a request at its next refill (within 64 allocations of each class it uses).

## Stage D: avoid rediscovering the entire heap

**What changed.** [reclamation.md](../reclamation.md) describes candidate-driven trimming for users; `core/proto.rs` has the new protocol in its module docs; [class-segment-index.md](class-segment-index.md) is the D3 design.

| Part | Implemented | Changed symbols |
|---|---|---|
| D1 preserve valid class cursors | Trimming no longer clears every cursor of a shard. Audit of every path that can make a cursor's page unusable: a small page stops being one only through `release_small_page` (trimming, under the owning shard's lock), which now drops the shard's cursor for the class if it names that page. Every other path follows from that: a segment is returned (`free_owned_segment`) or reused as a huge block only when all its pages are free, so no small page and hence no cursor is left in it; a segment taken from the arena (`alloc_pages`) is new to the shard and its hints are reset; segments never change shard while owned; a page reused at the same offset (as a run, or a small page of another class) is reused only after its release dropped the cursor. The invariant: a non-zero cursor names a small page of its class in a segment on its shard's list; `Heap::check_indexes` asserts it. | `Heap::release_small_page` (takes the shard), `reclaim::trim_step`; `ClassState::cursor` docs; `SearchStats::cursor_invalidations` now counts only released cursor pages |
| D2 empty-page candidates | New segment header word `SEG_EMPTY` ([5], was reserved): bit per small page that may have become fully free. `proto::release_blocks` returns the free count it raised the counter to; `proto::publish_if_empty` sets the page's bit when that count is the class capacity; `proto::take_candidates` (a swap) hands them to trimming. The counter never exceeds the capacity and only the owner's claims (under its lock) lower it, so the free that makes a page fully free always publishes, after any take that could have dropped the bit: candidates can be stale, never lost. Trimming (`release_empty_pages`) checks only candidates: page kind and class from `P_INFO`, membership in `SEG_CLS + c` (changed under this lock), and the free count against the capacity, then releases. Cached blocks are claimed, so they keep the page. Every path that returns blocks goes through `free_bits` (buffer flush, eviction, claimed-word return at flush and retirement, uncached frees, the rest of an uncached claim), so all of them publish. Bounded reconciliation: force sweeps and every `RECONCILE_EPOCHS` (16)-th decay sweep check every small page as well, counting releases without a candidate (`reconciled_pages`). The empty-segment reserve and teardown rules are unchanged: segments still become empty only by releasing their pages in the trim, and are returned only by the existing idle-age and one-per-shard rules; no candidate path returns or unguards a segment. | `SEG_EMPTY`; `proto::release_blocks` (returns `Option<u64>`), `publish_if_empty`, `take_candidates`; `Heap::free_bits`, `release_empty_pages`, `alloc_pages` (clears `SEG_EMPTY`); `reclaim::RECONCILE_EPOCHS`, `SweepState::reconcile`, `Heap::set_reconcile_epochs` (tests); `MaintenanceStats::stale_empty_candidates`, `reconciled_pages` |
| D3 class-to-segment index | Designed, not built: shard-local slots (64 per shard) with one word per shard and class, about 16.5 KiB instead of a dense 4 MiB product; publication on a segment's availability transition, clear-then-recheck by the owner that also removes stale non-class availability bits; validation against authoritative words instead of generation tags; list walk as the fallback before growth. The Loom models and full-scan comparison it would need are listed. Not built because nothing measured shows the remaining list walk (`page_search_segments`) matters, and the brief allows the design as an intermediate delivery. | none |

Partial sweeps and ageing: a candidate taken by a slice is either released or dropped as stale in the same step; a candidate published after its segment was visited waits for the next sweep, as a page that became empty after the visit did before. `SEG_IDLE` stamping and the per-shard kept segment are untouched.

The model program (`model::run`, fuzz target) now also sets how often decay sweeps reconcile (operation 26), and checks the indexes after every purge and decay operation and in `check_observations`: `Heap::check_indexes` (every cursor valid; every fully free small page a candidate) and `reconciled_pages == 0` (one operation at a time, so reconciliation must find nothing the candidates missed).

### Complexity notes

| Change | What grows | Work bounded | Extra memory | Outside the bound |
|---|---|---|---|---|
| Cursor kept across trims | release of a cursor page: one load and compare | none | none | none |
| Candidate publication | shared free path: one compare with the class capacity; one `fetch_or` only on the free that makes a page fully free | one per page per emptying | one reserved header word per segment | none |
| Candidate trimming | nothing | per segment visit: one swap, then one page check per candidate (was: every small page) | none | trimming still visits every owned segment (empty-segment ageing) |
| Reconciliation | force sweeps and every 16th decay sweep | every small page of each visited segment, as before Stage D | none | a lost candidate (none known) waits up to 16 decay epochs, four purge delays with regular decay |

Remaining costs, per the brief: page searches after a cursor runs dry still walk the shard's segment list (`page_search_segments`); trimming still takes each shard's lock with `try_lock` and skips busy ones; stale candidates cost one page check each (`stale_empty_candidates`).

### Invariant tests

`crates/allocatbelt/src/core/tests.rs`, section "search indexes":

- D1: `trimming_keeps_the_cursor_of_a_page_it_does_not_release` (the next refill claims through the kept cursor, no search), `releasing_one_class_keeps_the_cursors_of_the_others`, `a_released_page_reused_at_the_same_offset_is_not_claimed_from` (reuse as a one-page run, then as a small page of another class, at the released page's offset), `a_returned_and_reacquired_segment_holds_no_cursor` (segment return, reuse as a huge block and for small pages). With the cursor drop in `release_small_page` removed as a check of the tests, at least ten tests fail (three of these, older ones such as `cross_thread_frees`, and the D2 tests through `check_indexes`) and some hang.
- D2: `the_last_free_of_a_page_makes_it_a_candidate` (exact counts: no candidate while one block per page is live; one page checked for one emptied page among eight; a reconciling sweep checks all seven and releases none), `stale_candidates_are_checked_and_dropped`, `cache_flushes_and_retirement_publish_candidates`, `reconciling_sweeps_recover_lost_candidates` (candidates dropped on purpose: a non-reconciling decay leaves the page, a reconciling decay and a force purge release it and count it), `concurrent_frees_and_trims_lose_no_candidate` (four caching threads allocate and free four classes while another thread runs decay sweeps without reconciliation; afterwards the indexes check and one more candidate-only sweep releases every small page).
- Loom (`proto.rs`): `last_free_publishes_a_candidate` (two last frees race the trim: the page is released or still a candidate) and `a_claim_racing_the_last_free_loses_no_candidate` (an owner claim and cache return race the last free, which may publish a stale candidate). The existing page models now drive the same `free` helper, which publishes.

### Checks run (x86_64 host, 1.98.1)

| Check | Result |
|---|---|
| `cargo fmt --all --check` | pass |
| `cargo clippy --all-targets --all-features --locked -- -D warnings` | pass |
| `cargo test --release --all-features --locked` | pass (core suite: 116 tests) |
| `fuzz_programs` (the model's property test, now with the index checks) repeated 80 times | pass |
| `scripts/check-features.sh` | pass (11 combinations) |
| `scripts/check-rseq.sh` | pass (seccomp and tunable cases skipped on this host, as before) |
| `scripts/check-package.sh` | run after the commit (needs a clean tree); see the commit's report |
| Loom (`RUSTFLAGS="-C target-cpu=x86-64-v3 --cfg loom" cargo test --release --locked -p allocatbelt-core-check --lib loom`) | pass (16 models, 2 new) |
| Test check of D1 (cursor drop removed on purpose, then restored) | at least ten tests fail, some hang |
| Miri | running locally on single tests of Stages C and D (`duplicate_free_in_the_first_way`, `duplicate_free_in_the_second_way`, `cache_return_generations_wrap`, `caches_owe_only_requests_made_while_attached`, `releasing_one_class_keeps_the_cursors_of_the_others`, `stale_candidates_are_checked_and_dropped`, `reconciling_sweeps_recover_lost_candidates`, `a_released_page_reused_at_the_same_offset_is_not_claimed_from`), 20 minutes each; not part of CI. Results are added here when they finish. |
| `scripts/check-sandbox.sh` | not run locally (no Docker daemon on this host); by CI |
| aarch64, riscv64 (qemu), experimental ISA, platform gates, audit, deny, fuzz, mutation | by CI on the pushed commit (`bits.rs` and `class.rs` unchanged, so no local mutation run) |
| Benchmarks | not run. Performance not measured; benchmark gate intentionally disabled. |

### Known limitations

- D3 is a design only: page searches still walk the shard's segment list, linear in the segments a shard owns.
- Trimming still visits every owned segment of every shard it can lock (one candidate swap and the empty-segment check per segment); only the per-page scan is gone.
- The reconciliation interval (16 decay epochs) is a chosen bound, not tuned. A candidate lost to a bug would keep one fully free page resident until the next reconciling sweep; no such loss is known, and the model asserts none.
- Frees pay one comparison with the class capacity on every shared free (not on buffered ones), and one `fetch_or` on the free that empties a page.
