# Observability: what the allocator can tell you about its memory

allocatbelt exposes four read-only diagnostics on `Allocatbelt`. They exist so that tests can assert how much work a mechanism did, and so that an operator can tell apart the kinds of memory an allocator holds. None of them is a performance measurement, and none of them is the process's resident set size (RSS).

| Method | Type | Scope | Cost of a read |
|---|---|---|---|
| `maintenance_stats()` | `MaintenanceStats` | whole heap | 18 atomic loads |
| `search_stats()` | `SearchStats` | whole heap, summed over the 64 shards | 12 loads per shard |
| `heap_usage()` | `HeapUsage` | whole heap, a walk over the segments in use | a few loads per segment and per small page |
| `thread_cache_stats()` | `Option<CacheStats>` | the calling thread's cache only | reads the cache's own cells |

None of them allocates, takes a lock, or initialises the allocator. All four types are `#[non_exhaustive]`: counters may be added in later versions.

## Seven quantities that are easy to confuse

| Quantity | Where to read it | What it is not |
|---|---|---|
| **Live bytes** | Not tracked exactly. `HeapUsage::small_bytes_out` counts small blocks that are allocated *or held by thread caches*; page runs are counted in `pages_in_use`, huge blocks in `huge_segments`. | Only the application knows which of its blocks are live. |
| **Blocks retained by a thread cache** | `CacheStats::claimed_blocks` (taken from the shared bitmaps, not handed out) and `CacheStats::buffered_blocks` (freed, not yet returned), for the calling thread. | Other threads' caches cannot be read: a cache is owner-only state (`Cell`s). |
| **Free pages awaiting a purge** | `HeapUsage::dirty_pages`, and `Allocatbelt::dirty_bytes()` (the counter the reclamation thresholds use). | Returning a block to a shared bitmap does not make its page dirty; only a page that is wholly free is. |
| **Purged memory** | `MaintenanceStats::purged_pages` (pages whose `MADV_DONTNEED` or ring purge succeeded). | Not a drop in RSS: purged pages written again become resident again. |
| **Failed attempts** | `MaintenanceStats::failed_runs`: runs the OS refused or whose completion failed. Their pages stay dirty and are retried by a later pass. | |
| **Reserved virtual memory** | Fixed: the 64 GiB arena, reserved `PROT_NONE` and `MAP_NORESERVE` at start-up, plus the metadata reservation. | Reserved address space is not memory: it costs no RSS until pages are committed and written. |
| **RSS** | Measure it outside the allocator (`/proc/self/status` `VmRSS`, `/proc/self/smaps_rollup`, cgroup `memory.current`). | The OS decides it. It includes live and cached blocks, allocator metadata, pages never purged because they were never freed, and everything that is not the allocator's. |

The reclamation thresholds (by default a 32 MiB trigger and a 64 MiB emergency threshold, see [reclamation.md](reclamation.md)) bound **tracked dirty pages**, the third row. They are not caps on RSS, and no setting of the allocator enforces a total-process cap.

`HeapUsage` splits the 63 usable pages of each owned segment (the 64th is its guard page) into `pages_in_use`, `dirty_pages` and `clean_pages`, which always add up to `owned_segments * 63` when nothing runs concurrently. Clean pages read as zero: never used, or purged.

## Counters of work

**Purging** (`MaintenanceStats`, counted by each slice in local variables and added with a few atomic additions when the slice ends; a pass is a sweep, which runs in bounded slices, see [reclamation.md](reclamation.md)):

- passes by kind, counted when the sweep ends, on the maintenance thread and inline (`force_passes`, `budget_passes`, `decay_passes`, `inline_budget_passes`, `inline_decay_passes`);
- slices: `slices` (all), `inline_slices`, `emergency_slices`; a sweep still in progress is visible in `Allocatbelt::reclaim_status()`;
- work units: `segments_inspected`, `trimmed_shards`, `trim_pages_inspected` (small pages checked: the empty-page candidates that frees published, and on reconciling sweeps every small page);
- empty-page candidates: `stale_empty_candidates` (checked and not released: the page was claimed from again, or released or reused, after its last block was freed), `reconciled_pages` (pages a reconciling sweep released without a candidate: 0 unless a free published one while the sweep ran, or a candidate was lost);
- attempts and results: `purge_batches`, `purged_runs` (attempted), `failed_runs`, `purged_pages`, `released_pages`, `returned_segments`;
- lock contention: `busy_shards` (a shard skipped because its lock was held), `skipped_passes` (an inline pass skipped because another pass held the purge lock);
- foreground intervention: `hard_limit_slices`, the emergency slices a freeing thread ran although a maintenance thread was attached;
- failed cycles: `stalled_cycles`, budget cycles whose full sweep made no progress (then deferred to the next decay epoch, shown by `reclaim_status().budget_deferred`).

**Search** (`SearchStats`, per shard, updated under the shard lock the counted work already holds): refills and those served from the class's current page (`refills`, `cursor_claims`), current pages found empty and taken off the class's page list (`cursor_retired`), page searches with the pages of the class's list they inspected and those they took off it for having no free block (`page_searches`, `candidates`, `stale_hints`), new small pages, current pages released by trimming, whose cursor it dropped (`cursor_invalidations`; trimming keeps every other cursor), page-run searches with the segments they visited and the segments taken from the arena (`run_searches`, `run_search_segments`, `new_segments`), and dirty pages page-run allocations reused before a purge (`dirty_reused_pages`). A page search walks the shard's list of pages of the class from its front, so `candidates - stale_hints` is at most `page_searches`.

**Free buffering** (`CacheStats`, plain `Cell`s of the thread's cache, updated when a buffered word is flushed, never on a free that is only buffered): `flushes`, `flushed_blocks`, a histogram of blocks per flush (`flush_sizes`, buckets 1, 2-3, 4-7, 8-15, 16-31, 32-63, 64), flushes forced because both ways of a word's set in the 2-way buffer were taken (`evictions`), flushes of a class before a refill would take a new page (`refill_flushes`), and drains for a cache-return request (`pressure_returns`, see [thread-caches.md](thread-caches.md)). `flushed_blocks / flushes` is the batch a shared bitmap update actually carried.

## Semantics

- **Wrap.** Every counter only grows and wraps modulo 2^64 (`wrapping_add`); no process reaches that. Subtract two snapshots with `wrapping_sub` if you want to be exact.
- **Partial snapshots.** A read is a series of individually atomic loads, not one consistent snapshot. Counters of different shards, or a counter and the state it describes, can be one operation apart. Purge counters of one pass appear together, because a pass adds its work when it ends; a pass in progress is not visible yet. `HeapUsage` is approximate while other threads allocate and free.
- **Per-thread counters.** `CacheStats` covers the calling thread's cache for its life, and ends with the thread. Once the thread's cache is retired (thread exit, including thread-local destructors that run afterwards) it reports `attached: false` and holds nothing. `thread_cache_stats()` returns `None` only if the thread-local cannot be reached, which the current `const`, `Drop`-free cache never causes.
- **Cost on the fast paths.** No counter adds an atomic read-modify-write to allocation or free. Search counters are a plain load and store on the shard's own cache line under a lock that is already held; purge counters are per pass; cache counters are per flush. See [research/theory-driven-implementation-status.md](research/theory-driven-implementation-status.md) for the complexity notes.

The core tests (`crates/allocatbelt/src/core/tests.rs`, section "observations") assert these counters as operation counts on the deterministic `MockOs` and `MockPurger`, and `model::check_observations` checks their relations after every fuzzed program. They are correctness tests of the mechanisms, not throughput gates.
