# Research summary: a Rust replacement for mimalloc in OxiBelt

Date: 2026-09-27. Detailed reports (with sources and verification tags):

- [candidates.md](candidates.md): survey of pure-Rust allocator candidates (Korean)
- [designs.md](designs.md): design analysis of mimalloc, snmalloc, jemalloc, Scudo, hardened_malloc and PartitionAlloc (English)
- [boundary.md](boundary.md): unsafe boundary, reentrancy, provenance, hardware acceleration (English)
- [benchmarks.md](benchmarks.md): prototype measurements
- [simd-benchmarks.md](simd-benchmarks.md): SIMD candidate kernels measured against scalar code, and why none was promoted (plan Phases 4 and 5)
- [single-package-baseline.md](single-package-baseline.md): the state the single-package directive starts from (`33dfc7b`): correctness suite, unsafe inventory counts, public API (directive Phase A), and what the package consolidation changed (Phase B)

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
   - Free blocks are tracked in **per-page atomic bitmaps** instead of intrusive free lists → user memory corruption (UAF writes) cannot reach allocator metadata, and a double free is **detected deterministically** by the bit value returned from `fetch_or` (since 2026-09-30, the bit read under the owner's lock). The closest precedent is GrapheneOS hardened_malloc (designs.md §1.6).
   - Locking uses **atomics only** (Relaxed accesses under an Acquire/Release lock that spins briefly, then sleeps on a futex), with no `UnsafeCell`.
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
  1. ~~Owner-local word caches exist, but the fast path still takes a shard lock (two atomic RMWs). Move to a per-thread heap (with a const TLS handle), separate the `local_free`/`remote_free` bitmaps, and batch remote frees.~~ **Done** as a per-thread cache in front of the shards: the fast path is a bit pop on thread-local `Cell`s, and frees are batched per bitmap word. Deliberately *not* done: owner-local free bitmaps, because every free still has to pass the shared bitmap (with `fetch_or`, since 2026-09-30 under the owner's lock) for double frees to stay detectable (§4).
  2. ~~The `find_page` class list scan is O(pages).~~ **Done:** a word summary per page and per-class availability bitmaps per segment. **Replaced (2026-09-30)** by per-class lists of pages that may have free blocks, with no summary bits: a list drops pages without free blocks as it is walked, so `find_page` no longer scans pages or segments (see "Page lists" below and [../design-constraints.md](../design-constraints.md)).
  3. ~~Replace the budget-only purge with time-based decay and a background purge thread.~~ **Done:** decay passes purge pages dirty for the purge delay (1 s) and return segments empty that long; `Allocatbelt::start_purge_thread` runs them off the allocating threads. Left: no two-stage (`MADV_FREE` then `MADV_DONTNEED`) purge, no per-class empty-page budget.
  4. Hardening. **Done:** randomized word pick on refill, randomized order within a claimed word, randomized segment placement, a `MADV_GUARD_INSTALL` guard page at the end of every owned segment (with an `mprotect` fallback). Left: optional zero-on-free and a bitmap quarantine.
  5. ~~fork safety and `loom` models for concurrency.~~ **Done:** `pthread_atfork` handlers take every heap lock across `fork`; loom checks the free/claim, page-run/purge, grow/trim and lock protocols.
  6. Review soundness of **the core logic itself**: the boundary is narrow, but `purge`/`decommit`/`guard` safety still depends on core invariants such as "no purging ranges that hold live allocations". These are now checked by the mock-`Os` shadow maps (in `model.rs`, shared by the unit tests and a cargo-fuzz target), proptest (including random fuzz programs through several thread caches), loom for the protocols in `proto.rs`, and the mewt campaign for `bits`/`class`. Miri has still only been run partially (8/17 tests on commit 0271678; see unsafe-boundary.md). An independent review of the atomic orderings in `proto.rs` would be the next step.
- Do not use RDRAND, SIMD bitmap scans (a data race on shared atomic bitmaps), or MPK/MTE yet. Use getrandom. MTE is worth considering once ARM64 deployment starts (boundary.md §4).

## 4. Follow-up implementation (2026-09-28)

Phase 1 of the Linux 7 / ISA / SIMD plan (the platform contract) is recorded in [docs/platform.md](../platform.md): compile-time gates for Linux, x86_64/aarch64/riscv64, 64-bit little-endian userspace and an x86-64-v3 floor, a CI job that checks them, and a start-up probe of the mandatory kernel facilities. It changed no allocation logic.


Items 1–5 of the list above, plus fuzzing and loom for item 6. Measurements are in [benchmarks.md](benchmarks.md) ("Third round").

### Per-thread caches (`heap/cache.rs`)

- **What.** Each thread has a `ThreadCache`: one claimed bitmap word per size class and a 64-slot buffer of frees keyed by (page, bitmap word), direct-mapped when this was written and 2-way set-associative (32 sets) since the theory-driven plan's Stage C ([theory-driven-implementation-status.md](theory-driven-implementation-status.md)). It is built from `Cell`s, so the core stays `forbid(unsafe_code)`. The adapter keeps it in a `const`-initialised, `Drop`-free thread local and hands it back from a zero-sized thread-local destructor.
- **Fast paths.**
  - An allocation pops a bit from the claimed word: no atomics, no lock.
  - A free sets a bit in the buffer slot.
  - When a word runs out, the thread takes its shard lock once to claim the next word (up to 64 blocks).
  - A buffer slot is written back in one update, however many blocks it collected: one `fetch_or` until 2026-09-30, since then one locked update under the lock of the shard that owns the page.
  - A class's buffered frees are flushed before its shard takes a new page for it, so buffering never grows the heap.
- **Why not owner-local free bitmaps** (mimalloc's `local_free`)? With them, a thread could put a freed block straight back into its claimed word. But a second free of the same block from another thread would then land in the shared bitmap unseen, and the block would be handed out twice. Here every free, buffered or not, reaches the shared bitmap (under the owner's lock since 2026-09-30) before the block can be reused. Double frees stay detectable: immediately within one thread's buffer or claimed word, and at write-back time across threads.
  - What this costs: the owner cannot reuse its own frees without a round trip through the bitmap.
  - What the batching recovers: on the random-free microbenchmark, frees reached the bitmap at about one `fetch_or` per 2.3 frees. Batched producer/consumer frees do much better.
- **Thread exit.** A cache is flushed and retired at thread exit. Frees in later thread-local destructors take the uncached path. A thread whose destructor never runs leaks at most its cache: 32 claimed words and 64 buffered words.

### Page lists (`heap.rs`, `proto.rs`)

The first implementation (2026-09-28) found free blocks through two levels of summary bitmaps (a word summary per page and per-class availability words per segment). On 2026-09-30 they were removed after a design review kept outside this repository; this section describes what replaced them.

- **Page level.** A refill reads the page's bitmap words and picks a non-zero one by rank (`proto::claim_word`); there is no summary word.
- **Shard level.** Every shard keeps, per size class, a doubly linked list of its pages that may have free blocks, linked through the pages' `P_LINK` words, with a listed flag per page. Segments still keep a word of their pages of each class (`SEG_CLS`) for trimming and diagnostics.
- **Finding blocks.** A shard looking for a page of a class takes the front of its list, dropping pages that have no free block left.
- **The protocol** (`proto::release_blocks`, `claim_word`, `claim_block`):
  - Since 2026-09-30 (a second design review kept outside this repository), every free and every claim of a small page takes the lock of the shard that owns it and changes the bitmap and the free counter with plain loads and stores, so the counter is exact whenever the lock is free. A free that finds its page unlisted lists it again under that lock; a claim that finds no free block unlinks the page.
  - Until then, frees set bits with `fetch_or` without a lock and claims took words with `swap(0)`; the owner cleared the listed flag before reading the counter and a free re-listed the page, the two sides meeting in a store-buffering pattern with a fence on each.
  - A listed page can have no free block (costing one wasted look) but a page with free blocks is never left unlisted.
  - loom checks the transitions under the lock, including the page-level counter that page recycling relies on.
- **Since the theory-driven plan's Stage D** ([theory-driven-implementation-status.md](theory-driven-implementation-status.md)): trimming keeps each shard's per-class cursor unless it releases that page, and finds fully free pages through empty-page candidates that the last free of a page publishes, instead of checking every small page. [class-segment-index.md](class-segment-index.md) was a design for indexing segments above the summaries; it is superseded, as the page lists need no segment level.

### Delayed purging (`heap/purge.rs`)

Freed page runs and released small pages stay resident as dirty pages. Three kinds of pass return memory:

- **Decay passes** purge pages that have been dirty for the purge delay (1 s by default) and return segments that have been empty that long, beyond the one each shard keeps.
  - Ages count decay passes (epochs), which are due every quarter delay, so freeing never reads the clock: `Instant::now` costs 28 ns here, which the first version paid on every page-run free and measurably slowed mixed churn.
  - A page is purged one to one and a quarter delays after it was freed.
- **Budget passes** run when more than 512 pages (32 MiB) are dirty and purge them all.
- **Explicit `purge`** returns everything at once.

Who runs the passes:

- **Allocating threads,** by default: the free that takes the dirty count over the budget runs the budget pass, and every 16th slow-path operation per thread checks the clock and runs a due decay pass.
- **The maintenance thread,** after `Allocatbelt::start_maintenance_thread` (plan Phase 7; `start_purge_thread` is the old name). Allocating threads then only record work: a free over the budget sets a bit in one atomic word and wakes the thread with `FUTEX_WAKE` if the bit was clear. The thread (`Heap::maintain`, `heap/maint.rs`) runs the work in priority order: P0 force purge (`request_purge`), P1 budget pass, P2 decay pass when its deadline comes; P3, empty-segment retirement, is part of every pass, and P4 is `maintenance_stats`. With nothing to do it sleeps on that word until the next decay deadline. It returns memory while the process is idle (see the "idle" row in benchmarks.md) and keeps passes off request threads' tail latency.
  - It runs as `SCHED_BATCH`, never real-time, and is not pinned (plan §11.2–11.3). A batch thread can fall behind when the CPUs are oversubscribed, so a free that finds more than twice the budget (64 MiB) dirty runs the budget pass itself, as before.
  - The passes are the same ones (`purge_lock`, `madvise`, `mprotect`); only who runs them and when changed. A pass hands its claimed page runs to a `Purger` in batches: `SyncPurger` (one `Os::purge` per run, the default everywhere) or, after `set_io_uring(true)`, the maintenance thread's io_uring ring (plan Phase 8, [docs/platform.md](../platform.md#io_uring-purge-ring)). The claim makes the in-flight interval safe: claimed pages count as allocated until the batch has completed.
  - The request word is a protocol in `proto.rs` (`post_work`, `take_work`), and loom checks that no request is lost (`maintenance_requests_are_not_lost`, where the thread sleeps without a timeout). The thread takes a bit before it reads the dirty count, and both sides need a `SeqCst` fence between their two accesses (a store-buffering pattern); without the fences, loom finds a run where a free's pages are neither seen by the pass nor re-posted.

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
- **In the child:** housekeeping goes back to the allocating threads (the maintenance thread did not survive) and the placement secret is reseeded.
- **Test.** `tests/fork.rs` forks 200 times while four threads churn every lock. Before the handlers existed, its children deadlocked.

### Verification added

- **loom:** models of every protocol in `proto.rs`, run in CI.
- **Fuzzing:** the checking mock `Os` moved to `model.rs` with an interpreter for arbitrary byte programs, driven by cargo-fuzz (`fuzz/`, scheduled in CI) and by proptest on stable.
- **Mutation testing:** the mewt campaign passes after adding tests for what it found.
- **Integration tests:** thread exit, the maintenance thread, guard faults and fork.

### mimalloc correspondence, updated

| mimalloc | allocatbelt now |
|---|---|
| thread-local heap (`mi_heap_t`), page free lists | `ThreadCache`: claimed bitmap word per class + batched frees; shards own pages |
| `thread_free` / delayed free for cross-thread frees | buffered frees, one locked update per bitmap word |
| page queues per bin | per-shard, per-class lists of pages that may have free blocks |
| `purge_delay`, arena purge, `mi_collect` | epoch-based decay passes, maintenance thread, dirty budget, `purge()` / `request_purge()` |
| secure mode: guard pages, randomized free lists and segment placement | guard page per segment (guard markers), randomized words/blocks/segments, bitmaps instead of encoded free lists |
| (fork safety) | `pthread_atfork` handlers that hold every heap lock across `fork` |

## 5. Direction: Linux 7.x, ISA baselines and SIMD (adopted 2026-09-28)

allocatbelt is being evolved into a Linux-only allocator for a fixed set of CPUs, as an evidence-driven performance project rather than an ISA-intrinsics showcase. This section records the directive the later phases follow; each phase is recorded here or in its own document as it lands.

**Target end state.**

| | Target |
|---|---|
| Operating system | Linux 7.0.x or newer only |
| x86_64 | x86-64-v3 is the hard minimum; newer ISA paths only after run-time detection |
| aarch64 | 64-bit AArch64; Advanced SIMD (NEON) as the main vector path, newer features only when safe |
| riscv64 | RV64 Linux with a correct baseline; Zbb and V acceleration only when available |

**Fast paths stay in userspace.** Small allocation and free stay mostly thread-local: no io_uring submission, clock syscall or general scheduler syscall per allocation or free.

**Maintenance moves to a slow plane.** A dedicated maintenance scheduler, io_uring-batched `MADV_DONTNEED` where it measurably wins, futex-based sleeping and waking where contention warrants it, deliberate Linux scheduler policy for maintenance work, and rseq/mm_cid only as experiments after correctness and benchmark gates.

**SIMD policy.**

- Use SIMD where data ownership and the memory model allow it: thread-owned or snapshotted data, never shared metadata.
- Never replace atomic accesses to shared allocator metadata with plain vector loads or stores (a data race; see §3).
- For a single `u64` bitmap word, prefer scalar bit-manipulation instructions (`tzcnt`/`lzcnt`/`popcnt`, Zbb `ctz`/`clz`/`cpop`) over vectors.
- Every hand-written SIMD kernel needs benchmark evidence on native hardware; emulator numbers never count.

**Crate boundaries stay as they are.** `allocatbelt-core` keeps `#![forbid(unsafe_code)]` and holds the algorithms and invariants, `allocatbelt-sys` stays the Linux VM and syscall boundary, and `allocatbelt` stays the `GlobalAlloc` adapter. The core is not replaced by an architecture-specific unsafe implementation. If architecture intrinsics need `unsafe`, they go into one small new crate, `crates/allocatbelt-arch`, limited to CPU-feature discovery that cannot live in the core, run-time-selected architecture kernels, and architecture-specific tests and instruction checks. Every `unsafe` block added there is listed in [docs/unsafe-boundary.md](../unsafe-boundary.md).

> **Package layout since directive Phase B.** The single-package directive replaced these crates with modules of the one published package `allocatbelt`: `core` (still `#![forbid(unsafe_code)]`, and compiled as a `#![no_std]` crate of its own by the unpublished `allocatbelt-core-check`), `sys`, `arch` and the adapter `global`. The boundaries above are unchanged; only the crate names became module paths ([single-package-baseline.md](single-package-baseline.md) section 6).

**What must not regress.** Per-thread caches, bitmap words consumed without shared atomics, batched frees, per-class page lists, out-of-band `AtomicU64` metadata, delayed purging under a dirty budget, guard pages and randomized placement, fork handling, and the verification around the core (model tests, proptest and fuzzing, loom, Miri-compatible paths, mutation testing, integration tests). SIMD or kernel-API work that weakens any of these is not adopted.

**Phases.** 1: platform contract and build matrix (done: [docs/platform.md](../platform.md)). 2: architecture capability layer (done: `allocatbelt-arch`, see [docs/platform.md](../platform.md)). 3: scalar ISA verification (done: `scripts/check-scalar-isa.sh`, see [docs/platform.md](../platform.md)). 4: SIMD benchmark harness (done: `bench/simd`, see [simd-benchmarks.md](simd-benchmarks.md)). 5: promote proven SIMD kernels (done: none qualified, since no candidate operation is a measurable allocator cost; budget passes spend 92–95% of their time in `madvise`, which is for phases 7 and 8; see [simd-benchmarks.md](simd-benchmarks.md#phase-5-promotion-decision-2026-09-28)). 6: adaptive lock and futex work (done: heap locks sleep on a futex instead of calling `sched_yield`, see [benchmarks.md](benchmarks.md)). 7: maintenance micro-scheduler (done: housekeeping is prioritized work for one `SCHED_BATCH` maintenance thread, and allocating threads only set flags, see §4 and [benchmarks.md](benchmarks.md)). 8: io_uring purge backend (done, opt-in: a restricted ring purges each pass's page runs in batches, but it did not beat `madvise` here, so `madvise` stays the default, see [benchmarks.md](benchmarks.md)). 9: rseq/mm_cid research (done as an experiment only: with the Cargo feature `experimental-rseq` and `set_rseq_policy(Prefer)`, cache refills pick shards by the `mm_cid` glibc's rseq area reports; off by default and not benchmarked, see [docs/platform.md](../platform.md)). Each phase is a separate, independently tested change.
