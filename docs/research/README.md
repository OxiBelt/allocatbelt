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
   - The unsafe boundary is `allocatbelt-sys` (8 unsafe blocks, 2 `unsafe fn` with contracts, `Send`/`Sync` for `Region`) plus the adapter (`GlobalAlloc` impl, zero fill, realloc copy, 2 purge calls). See [../unsafe-boundary.md](../unsafe-boundary.md).
3. **Prototype performance** (see benchmarks.md, 36-core Xeon E5-2630 v4):
   - On 16-thread local churn it is about 1.2× slower than mimalloc-secure (285 vs 230 ms, median).
   - On producer/consumer (cross-thread free) it is about 1.8× faster than mimalloc and 6× faster than glibc.
   - RSS is about 1/11 of mimalloc-secure in the same workload. Mimalloc's RSS may reflect default-option effects; see the caveats.
   - The biggest bottleneck found was **calling `madvise(DONTNEED)` immediately on every free** (mmap_lock plus TLB shootdowns). Switching to deferred purge, meaning dirty bitmap + budget as mimalloc and jemalloc do, cut 16-thread time from 470 ms to about 290 ms.

## 3. Recommendations

- **Short term:** keep secure mimalloc as OxiBelt's default. Put allocatbelt behind an `oxibelt-allocator` feature (e.g. `native-allocatbelt`) as an **experimental option**, and compare p99/throughput/24-hour RSS under real traffic (wrk/h2load). Put rallocator and rusty_alloc(`secure`) in the same comparison.
- **Integration path:** make `oxibelt-allocator` a thin crate that re-exports `allocatbelt::Allocatbelt`. The `cc` build-dependency goes away, which also simplifies `cargo vet`/`deny`. It can be applied equally to ARM64 and RISC-V, since sys uses a 64 KiB granule and no page-size query. That needs testing on those targets.
- **Things to finish before production** (in priority order; design grounds in designs.md §3):
  1. Owner-local word caches exist, but the fast path still takes a shard lock (two atomic RMWs). Move to a per-thread heap (with a const TLS handle), separate the `local_free`/`remote_free` bitmaps, and batch remote frees.
  2. The `find_page` class list scan is O(pages) → add a two-level summary bitmap or per-segment pending bitmap.
  3. Replace the budget-only purge with time-based decay and a background purge thread. Prefer purging abandoned or empty segments whole.
  4. Hardening (cheap, in order): randomized word pick on refill, randomized segment order, `MADV_GUARD_INSTALL` guards (Linux 6.13+), optional zero-on-free, a bitmap quarantine.
  5. fork safety (`pthread_atfork` or a fork epoch; see boundary.md §2.5), and `loom` models for concurrency.
  6. Review soundness of **the core logic itself**: the boundary is narrow, but `purge`/`decommit` safety still depends on the core invariant "no purging ranges that hold live allocations". Today this is checked by mock-Os shadow-map tests, proptest and Miri. Before production it needs fuzzing and loom.
- Do not use RDRAND, SIMD bitmap scans (a data race on shared atomic bitmaps), or MPK/MTE yet. Use getrandom. MTE is worth considering once ARM64 deployment starts (boundary.md §4).
