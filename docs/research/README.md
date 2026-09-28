# Research summary: a Rust replacement for mimalloc in OxiBelt

Date: 2026-09-27. Detailed reports (with sources and verification tags):

- [candidates.md](candidates.md): survey of pure-Rust allocator candidates (Korean)
- [designs.md](designs.md): design analysis of mimalloc, snmalloc, jemalloc, Scudo, hardened_malloc and PartitionAlloc (English)
- [boundary.md](boundary.md): unsafe boundary, reentrancy, provenance, hardware acceleration (English)
- [benchmarks.md](benchmarks.md): prototype measurements

> The three detailed reports were written by Claude subagents from web sources. Every claim is tagged
> **[V]** (checked against a primary source), **[S]**/(secondary) or **[U]/[UNVERIFIED]**; check the tag before relying on a claim.

## 1. Current state (OxiBelt)

- `source/crates/oxibelt-allocator` builds **secure mimalloc (C)** with `build.rs` + `cc` and bridges it through `GlobalAlloc`.
- It is enabled only on x86_64 Linux gnu/musl, through the default feature `allocator-mimalloc-experiment`. ARM64 and RISC-V use the system allocator.
- The workspace lints are `unsafe_code = deny`, and clippy denies `undocumented_unsafe_blocks`, `multiple_unsafe_ops_per_block` and `missing_safety_doc`.

## 2. Conclusions

1. **There is no mature pure-Rust allocator that can replace secure mimalloc as-is.** (See candidates.md.)
   - Most well-known crates target no_std/embedded with a single global lock plus an externally supplied arena: talc, rlsf, buddy_system_allocator, linked_list_allocator, and others. They collapse under contention on a multi-core tokio server.
   - The candidates designed for servers are all less than about a year old:
     - `rallocator` (Microsoft Oxidizer, 0.1.0; about 1,045 unsafe blocks, no public benchmarks)
     - `smmalloc` (Zooko's smalloc; fast, but **never returns memory to the OS** and has no hardening)
     - `rusty_alloc` (a Rust port of mimalloc; the most features, but a history of UAF bugs and 7 weeks old)
   - No candidate enables secure-mimalloc-level hardening by default.
   - No candidate has a structure that confines unsafe to the allocator's boundaries. Unsafe is spread through the core logic of all of them.
2. **Hence a new design: "offsets + out-of-band atomic bitmaps".** Validated by this repository's prototype.
   - The core manipulates only **offsets** (integers) into a single reserved arena, and never dereferences memory → it can be `#![forbid(unsafe_code)]`.
   - Free blocks are tracked in **per-page atomic bitmaps** instead of intrusive free lists → user memory corruption (UAF writes) cannot reach allocator metadata, and a double free is **detected deterministically** by the bit value returned from `fetch_or`. The closest precedent is GrapheneOS hardened_malloc (designs.md §1.6).
   - Locking uses **atomics only** (Relaxed accesses under an Acquire/Release spin lock), with no `UnsafeCell`.
   - Hardware acceleration: bitmap scans are safe `trailing_zeros`/`count_ones`/`leading_zeros`, so with `-C target-cpu=x86-64-v3` they compile to `tzcnt`/`popcnt`/`lzcnt`.
   - The unsafe boundary is `allocatbelt-sys` (13 unsafe blocks, 3 `unsafe fn` with contracts, `Send`/`Sync` for `Region`) plus the adapter (`GlobalAlloc` impl, zero fill, realloc copy, purge/decommit/guard calls). See [../unsafe-boundary.md](../unsafe-boundary.md).
3. **Prototype performance** (see benchmarks.md, 36-core Xeon E5-2630 v4):
   - On 16-thread local churn it is about 1.2× slower than mimalloc-secure (285 vs 230 ms, median).
   - On producer/consumer (cross-thread free) it is about 1.8× faster than mimalloc and 6× faster than glibc.
   - RSS is about 1/11 of mimalloc-secure in the same workload. Mimalloc's RSS may reflect default-option effects; see the caveats.
   - The biggest bottleneck found was **calling `madvise(DONTNEED)` immediately on every free** (mmap_lock plus TLB shootdowns). Switching to deferred purge, meaning dirty bitmap + budget as mimalloc and jemalloc do, cut 16-thread time from 470 ms to about 290 ms.

## 3. Recommendations

- **Short term:** keep secure mimalloc as OxiBelt's default. Put allocatbelt behind an `oxibelt-allocator` feature (e.g. `native-allocatbelt`) as an **experimental option**, and compare p99/throughput/24-hour RSS under real traffic (wrk/h2load). Put rallocator and rusty_alloc(`secure`) in the same comparison.
- **Integration path:** make `oxibelt-allocator` a thin crate that re-exports `allocatbelt::Allocatbelt`. The `cc` build-dependency goes away, which also simplifies `cargo vet`/`deny`. It can be applied equally to ARM64 and RISC-V, since sys uses a 64 KiB granule and no page-size query. That needs testing on those targets.
- **Things to finish before production** (in priority order; design grounds in designs.md §3). Items 1–5 were implemented on 2026-09-28 (§4 below); what is left of each is noted.
  1. ~~Owner-local word caches exist, but the fast path still takes a shard lock (two atomic RMWs). Move to a per-thread heap (with a const TLS handle), separate the `local_free`/`remote_free` bitmaps, and batch remote frees.~~ **Done** as a per-thread cache in front of the shards: the fast path is a bit pop on thread-local `Cell`s, and frees are batched per bitmap word. Deliberately *not* done: owner-local free bitmaps, because every free still has to pass the shared bitmap's `fetch_or` for double frees to stay detectable (§4).
  2. ~~The `find_page` class list scan is O(pages).~~ **Done:** a word summary per page and per-class availability bitmaps per segment. Left: `find_page` is O(segments of the shard); a shard with thousands of segments would want a third level.
  3. ~~Replace the budget-only purge with time-based decay and a background purge thread.~~ **Done:** decay passes purge pages dirty for the purge delay (1 s) and return segments empty that long; `Allocatbelt::start_purge_thread` runs them off the allocating threads. Left: no two-stage (`MADV_FREE` then `MADV_DONTNEED`) purge, no per-class empty-page budget.
  4. Hardening. **Done:** randomized word pick on refill, randomized order within a claimed word, randomized segment placement, a `MADV_GUARD_INSTALL` guard page at the end of every owned segment (with an `mprotect` fallback). Left: optional zero-on-free and a bitmap quarantine.
  5. ~~fork safety and `loom` models for concurrency.~~ **Done:** `pthread_atfork` handlers take every heap lock across `fork`; loom checks the free/claim/retire, page-run/purge, grow/trim and spin-lock protocols.
  6. Review soundness of **the core logic itself**: the boundary is narrow, but `purge`/`decommit`/`guard` safety still depends on core invariants such as "no purging ranges that hold live allocations". These are now checked by the mock-`Os` shadow maps (in `model.rs`, shared by the unit tests and a cargo-fuzz target), proptest (including random fuzz programs through several thread caches), loom for the lock-free protocols, and the mewt campaign for `bits`/`class`. Miri has still only been run partially (8/17 tests on commit 0271678; see unsafe-boundary.md). An independent review of the atomic orderings in `proto.rs` would be the next step.
- Do not use RDRAND, SIMD bitmap scans (a data race on shared atomic bitmaps), or MPK/MTE yet. Use getrandom. MTE is worth considering once ARM64 deployment starts (boundary.md §4).

## 4. Follow-up implementation (2026-09-28)

Items 1–5 of the list above, plus fuzzing and loom for item 6. Measurements are in [benchmarks.md](benchmarks.md) ("Third round").

### Per-thread caches (`heap/cache.rs`)

- **What.** Each thread has a `ThreadCache`: one claimed bitmap word per size class and a 64-slot direct-mapped buffer of frees keyed by (page, bitmap word). It is built from `Cell`s, so the core stays `forbid(unsafe_code)`. The adapter keeps it in a `const`-initialised, `Drop`-free thread local and hands it back from a zero-sized thread-local destructor.
- **Fast paths.**
  - An allocation pops a bit from the claimed word: no atomics, no lock.
  - A free sets a bit in the buffer slot.
  - When a word runs out, the thread takes its shard lock once to claim the next word (up to 64 blocks).
  - A buffer slot is written back with one `fetch_or`, however many blocks it collected.
  - A class's buffered frees are flushed before its shard takes a new page for it, so buffering never grows the heap.
- **Why not owner-local free bitmaps** (mimalloc's `local_free`)? With them, a thread could put a freed block straight back into its claimed word. But a second free of the same block from another thread would then land in the shared bitmap unseen, and the block would be handed out twice. Here every free, buffered or not, reaches the shared bitmap through `fetch_or` before the block can be reused. Double frees stay detectable: immediately within one thread's buffer or claimed word, and at write-back time across threads.
  - What this costs: the owner cannot reuse its own frees without a round trip through the bitmap.
  - What the batching recovers: on the random-free microbenchmark, frees reached the bitmap at about one `fetch_or` per 2.3 frees. Batched producer/consumer frees do much better.
- **Thread exit.** A cache is flushed and retired at thread exit. Frees in later thread-local destructors take the uncached path. A thread whose destructor never runs leaks at most its cache: 32 claimed words and 64 buffered words.

### Two-level summaries (`heap.rs`, `proto.rs`)

- **Page level.** Every small page has a summary word (bit *w* = bitmap word *w* may be non-empty).
- **Segment level.** Every segment has, per size class, a word of its pages of that class (`SEG_CLS`) and a word of those that may have free blocks (`SEG_AVAIL`).
- **Finding blocks.** A refill picks a word from the summary; a shard looking for a page of a class checks each of its segments' `SEG_AVAIL & SEG_CLS`. Both are `trailing_zeros`. The per-class page lists and their O(pages) scans are gone.
- **The protocol** (`proto::release_blocks`, `claim_word`, `retire_page`):
  - Frees propagate a bit upwards only on a zero → non-zero transition.
  - The owner clears a hint *before* taking what it points to, and re-checks with a read-modify-write before retiring a page.
  - A hint can be stale-set (costing one wasted look) but never stale-clear while blocks are waiting.
  - loom checks this, including the page-level counter that page recycling relies on.

### Delayed purging (`heap/purge.rs`)

Freed page runs and released small pages stay resident as dirty pages. Three kinds of pass return memory:

- **Decay passes** purge pages that have been dirty for the purge delay (1 s by default) and return segments that have been empty that long, beyond the one each shard keeps.
  - Ages count decay passes (epochs), which are due every quarter delay, so freeing never reads the clock: `Instant::now` costs 28 ns here, which the first version paid on every page-run free and measurably slowed mixed churn.
  - A page is purged one to one and a quarter delays after it was freed.
- **Budget passes** run when more than 512 pages (32 MiB) are dirty and purge them all.
- **Explicit `purge`** returns everything at once.

Who runs decay passes:

- **Allocating threads,** by default: every 16th slow-path operation per thread checks the clock and runs a due pass.
- **A background thread,** after `Allocatbelt::start_purge_thread`: it runs the passes and allocating threads stop running them. It returns memory while the process is idle (see the "idle" row in benchmarks.md), and keeps passes off request threads' tail latency.

### Hardening

- **Guard pages.** Every owned segment keeps its last page claimed as a guard page (so page runs are at most 63 pages, `MAX_RUN_PAGES`).
  - The adapter installs `MADV_GUARD_INSTALL` markers on it (Linux 6.13+, no extra VMAs). It checks that they took effect (`MADV_POPULATE_READ` must fail with `EFAULT`: qemu-user accepts unknown advice silently) and falls back to `mprotect(PROT_NONE)`.
  - A linear overflow off the end of a segment's last block therefore faults (`tests/hardening.rs`).
  - The guard is removed before the segment returns to the arena.
- **Randomization** (seeded from `getrandom` at arena creation, reseeded in forked children):
  - refills claim a random word of the page;
  - threads hand out the blocks of a word in random order;
  - new segments go to a random free slot of the first 64-segment group with room (compact, because segment metadata stays committed).
- **Not done yet:** optional zero-on-free and a bitmap quarantine (designs.md §3.3).

### fork

- **Handlers.** `pthread_atfork` handlers take every heap lock before `fork`, in the heap's nesting order (purge, shards, segments), and release them in both processes. The prepare handler first waits for a concurrent arena reservation.
- **In the child:** allocation-driven decay comes back on (the purge thread did not survive) and the placement secret is reseeded.
- **Test.** `tests/fork.rs` forks 200 times while four threads churn every lock. Before the handlers existed, its children deadlocked.

### Verification added

- **loom:** models of every lock-free protocol in `proto.rs`, run in CI.
- **Fuzzing:** the checking mock `Os` moved to `model.rs` with an interpreter for arbitrary byte programs, driven by cargo-fuzz (`fuzz/`, scheduled in CI) and by proptest on stable.
- **Mutation testing:** the mewt campaign passes after adding tests for what it found.
- **Integration tests:** thread exit, the purge thread, guard faults and fork.

### mimalloc correspondence, updated

| mimalloc | allocatbelt now |
|---|---|
| thread-local heap (`mi_heap_t`), page free lists | `ThreadCache`: claimed bitmap word per class + batched frees; shards own pages |
| `thread_free` / delayed free for cross-thread frees | buffered frees, one `fetch_or` per bitmap word |
| page queues per bin | per-segment `SEG_AVAIL`/`SEG_CLS` bitmaps + per-page word summary |
| `purge_delay`, arena purge, `mi_collect` | epoch-based decay passes, background purge thread, dirty budget, `purge()` |
| secure mode: guard pages, randomized free lists and segment placement | guard page per segment (guard markers), randomized words/blocks/segments, bitmaps instead of encoded free lists |
| (fork safety) | `pthread_atfork` handlers that hold every heap lock across `fork` |
