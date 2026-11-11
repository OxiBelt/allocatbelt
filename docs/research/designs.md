# Allocator design research for the OxiBelt Rust allocator

Date: 2026-09-27. Scope: the prior allocator designs that bear on a Rust `#[global_allocator]` with these properties: one large reserved range, all metadata out-of-band in atomic arrays, per-page atomic free bitmaps, mimalloc-like size classes, 4 MiB segments and 64 KiB pages, sharded heaps, and lock-free remote free. The target is a long-running public-edge reverse proxy on x86_64 Linux.

Legend: **[V]** means I checked it against a primary source in this session (source code, official docs or the paper text). **[S]** means it comes from a secondary summary or a search snippet. **[UNVERIFIED]** means it comes from background knowledge and was not re-checked here. Treat [UNVERIFIED] items as hypotheses to confirm before relying on them.

---

## 1. Allocator survey

### 1.1 mimalloc (Microsoft; the current OxiBelt allocator)

**Data structures (v1/v2, as in the paper)** [V, paper text]
- Segments are 4 MiB, or larger for huge objects. They are aligned, so `ptr & ~(4MiB-1)` gives the segment header.
- Small objects (under 8 KiB) use 64 KiB pages, 64 per segment. Large objects (under 512 KiB) use one page covering the whole segment.
- Page and segment metadata sits at the start of the segment. It is out-of-line relative to objects but inside the same mapping.
- Metadata overhead is about 0.2%. Size-class rounding wastes at most 1/8 (16.7%).
- Free-list sharding: each page has three singly-linked intrusive lists.
  - `free` is used for allocation.
  - `local_free` receives frees from the owning thread. Keeping it separate gives a "temporal cadence": when `free` runs empty, the slow path runs maintenance.
  - `thread_free` receives frees from other threads through an atomic CAS push. The owner collects it with a single `atomic_swap(&page->thread_free, NULL)`, which batches remote frees.
- Full pages: to tell the owner that a full page has had remote frees, the low 2 bits of `thread_free` encode NORMAL, DELAYED or DELAYING. A remote free of a DELAYED page goes onto a heap-level `thread_delayed_free` list instead.
- v2 main-branch `types.h` [V]: segments are 32 MiB, divided into 64 KiB slices. Pages are 64 KiB for objects up to 8 KiB and 512 KiB for objects up to 64 KiB.
- The `xthread_free` low bits are the delayed-free flags. Abandoned segments (whose owning thread exited) are reclaimed by other threads.

**v3 changes** [V, README and dev3 `types.h`]
- Segments are gone. Memory is organised as arenas (usually 1 GiB reservations) of 64 KiB slices, tracked with arena bitmaps (`mi_bitmap_t`).
- Small, medium and large pages are 64 KiB, 512 KiB and 4 MiB.
- The README says v3 "simplifies the lock-free design of previous versions and improves sharing of memory between threads" and adds first-class heaps that can be used from any thread.
- `xthread_free` is `mi_block_t* | (1 if owned)`.
- Pages whose owner is gone are marked `MI_THREADID_ABANDONED` and can be claimed by any thread through the arena bitmaps. The README says v3 is "more concurrent".
- **Takeaway:** mimalloc itself moved toward arena-level bitmaps for page ownership and abandonment, which is close to our design at the page level.

**Security (MI_SECURE)** [V, `types.h`, v2 and v3]

The levels are cumulative:

| Level | v2 | v3 |
|---|---|---|
| 1 | Guard pages around metadata; randomized arena addresses | Also checks for invalid-pointer free |
| 2 | Randomized allocation order within a page | (not separately listed) |
| 3 | Encoded free lists, detecting corruption and invalid free | Adds buffer-overflow check and double-free check |
| 4 | Double-free checks ("may be more expensive") | (not separately listed) |
| 5 | Guard page at the end of every mimalloc page ("expensive!") | Also byte-precise overflow checks |

- Free-list pointers are XOR-encoded with per-page keys [V, README and paper].
- Overhead: the README says "usually around 10% on average". The 2019 paper measured about 3% for "smimalloc" on its first benchmark set [V].
- The paper's secure variant also sometimes *extends* a page instead of reusing the local free list, to add randomness [V].

**Remote free:** lock-free CAS push onto a per-page list (sharded). The owner collects the whole list with a single atomic swap.

**Reclamation** [V, docs]
- `purge_delay` defaults to 1000 ms in v3.
- `purge_decommits=1` is the default and purges with `MADV_DONTNEED`, which the docs say "decrease[s] rss immediately".
- Setting it to 0 uses `MADV_FREE`, which "does not decrease rss immediately".

### 1.2 snmalloc (Microsoft Research)

**Remote free by message passing** [V, README and ISMM'19 via snippet]
- Remote frees are batched in a per-allocator "remote cache" of 2^k buckets (k=6), keyed by destination allocator address.
- A batch is then posted to the owner's MPSC queue with a single atomic operation. The README says this allows "1000s of remote deallocations to be performed with only a single atomic operation".
- The owner drains its queue on its slow path.
- The original design used 64 bits of metadata per 64 KiB slab, as a "bump-pointer free list" [S].
- **BatchIt (ISMM 2024)** adds a per-slab cache of remote frees, so frees destined for the same slab are grouped before sending. It gives more than 20% on some producer-consumer workloads and 14.7% on xmalloc-test for snmalloc [S]. This matters directly for a proxy, where buffers allocated on one worker are freed on another.

**Metadata placement** [V, security docs]
- snmalloc uses a global two-level "pagemap" (chunk map). Each entry has two pointers, with flags bit-packed into known-zero bits. The pagemap maps any address to its slab metadata out-of-band.
- The front-end metadata is out-of-band and guarded.
- The in-band free lists remain but are encoded.

**Checks and mitigations** [V]
- **Free-list protection.** Queues rather than stacks, with forward pointers `f(a)=a^k0` and back-edge signatures `g(a,b)=(a^k1)*(b^k2)`, checking `x.next.prev == x`. Cost per the docs: "a single branch ..., one multiplication, five additional loads, and one store", plus one extra key cache line. Double-free detection is lazy: it fires when the object is reused. The same protection covers the remote message queues.
- **Free validity.** The pagemap is used to check that a free is the start of an object in a slab, with ownership routed to the remote path. Object index uses reciprocal multiplication, not division.
- **Randomisation.**
  - The initial free list uses Sattolo's cyclic permutation (built "inside-out").
  - Each slab has two free queues, and each free goes to one of them on a coin flip; allocation takes the longer queue.
  - A slab is reused only after a threshold fraction of it is free.
  - When only one slab remains, the allocator sometimes takes a fresh slab instead.
  - The docs call randomisation a "weak defence".
- **Guarded memcpy.** `remaining_bytes(dst) >= len`, computed through the pagemap. It costs up to 60% on 1-byte copies, is negligible at 128 bytes and above, and costs about 2–3% on Redis.
- **Variable-sized slabs** keep a minimum object count per slab. This bounds both the slow-path frequency and the waste.
- Overall cost of the hardening in 0.6: under 5% regression per the docs [V].

### 1.3 jemalloc

- Arenas: `narenas` defaults to 4×CPUs, with an optional `percpu_arena`. Each thread has a tcache. Extents are organised in a radix tree (rtree) for pointer-to-metadata lookup [V, man page; rtree UNVERIFIED detail].
- Small objects live in slabs, and each slab has a bitmap of regions in use [V, man page]. The slab bitmap is out-of-band in the extent metadata; objects hold no inline free pointers [UNVERIFIED detail].
- Remote free: goes into the freeing thread's tcache. When the tcache flushes, it takes the owning arena's per-bin mutex and returns the object [UNVERIFIED detail]. There is no lock-free remote path.
- Purging [V, man page and TUNING.md]:
  - `dirty_decay_ms` is the time over which dirty pages are converted to "muzzy" (with `MADV_FREE`) or to clean.
  - `muzzy_decay_ms` controls muzzy to clean.
  - Defaults are dirty 10000 ms and muzzy 0 since 5.2.x [S, jemalloc issue #1827].
  - `background_thread` moves purging off application threads and improves tail latency.
- Security: essentially none beyond out-of-band slab metadata.
- **Relevance:** jemalloc is the long-standing production proof that **bitmap slabs + out-of-band metadata + tcache** performs well. The tcache is what hides the bitmap cost.

### 1.4 rpmalloc

- Memory is organised as spans containing pages of fixed-size blocks, with per-thread heaps [V, README; the "256 MiB spans" wording came from a summary and may be version-specific, UNVERIFIED].
- Remote free: blocks are "deferred to the owning thread through a separate atomic free list per page" [V]. This is the same pattern as mimalloc.
- Metadata is inline: span headers and intrusive free lists [UNVERIFIED detail]. There is no hardening.
- Known cost: a thread that touches many size classes commits a page per class [V].

### 1.5 Scudo (LLVM; Android's default)

- The primary allocator splits reserved per-size-class regions into blocks. The secondary allocator uses mmap with guard pages around each allocation [V, LLVM docs].
- Every chunk has an **inline 8-byte header** holding the class id, state, size, offset and a 16-bit CRC32 checksum. The checksum is only verified when the header is accessed [V].
- There is an optional quarantine (delayed reuse) [V].
- Randomization: block order within the primary, and the choice of per-thread cache [V].
- Release to the OS is on by default, with `release_to_os_interval_ms` defaulting to 5000 [V].
- Remote free: goes into the freeing thread's cache, which drains to the class's shared free-list in "TransferBatch" groups under a per-class lock [UNVERIFIED detail].
- MTE is supported on arm64 [UNVERIFIED detail].
- Performance: generally slower than jemalloc/mimalloc in mimalloc-bench [UNVERIFIED; no numbers checked in this session].

### 1.6 GrapheneOS hardened_malloc (closest to our design)

Checked against `h_malloc.c` and `config/default.mk` [V]:

**Layout**
- One huge slab region is reserved per arena, with default `CONFIG_CLASS_REGION_SIZE` of 32 GiB per size class. Each class region is `2×` that size with a random start gap.
- A pointer's size class and slab index come from **address arithmetic alone**. That index selects a `slab_metadata` in an out-of-band metadata array.

**Metadata**
- `struct slab_metadata { u64 bitmap[4]; next; prev; canary; u16 count; u64 quarantine_bitmap[4]; ... }`.
- **At most 256 slots per slab** (4×u64). Slab sizes are chosen per class to fit that limit; for example, the 16-byte class has 256 slots in a 4 KiB slab.
- Size classes are 4 per power of two, keeping internal fragmentation under 20%.

**Allocation**
- `get_free_slot()` takes a random start index, masks the bitmap word at that point and scans with `ffz64`. It wraps across at most 4 words. That is O(4) word operations, cheap because the slot count is capped.

**Locking and threads**
- There is **one mutex per size class per arena**, with `N_ARENA=4` by default and threads assigned round-robin.
- There is **no thread cache**, by design, because a cache conflicts with quarantine and randomization.
- A cross-thread free just takes the same lock. There is no special remote path.

**Security**
- Out-of-band metadata. `CONFIG_SEAL_METADATA` (off by default) protects it with an MPK key.
- Guard slabs: `CONFIG_GUARD_SLABS_INTERVAL=1`, which in effect leaves every other slab slot as a guard.
- Random slot selection.
- Slab canaries, placed after each slot, which "absorb and then detect" overflows.
- `CONFIG_ZERO_ON_FREE` and `CONFIG_WRITE_AFTER_FREE_CHECK`: a new allocation must still be zero.
- A slot quarantine with both a random array and a FIFO queue, tracked by `quarantine_bitmap`.
- Large allocations get a region quarantine (FIFO plus random, 1024/256 entries), whose entries are unmapped when evicted.
- Deterministic detection of invalid, unaligned or double frees.
- MTE on arm64.

**Reclamation**
- Empty slabs are cached up to `max_empty_slabs_total`, which is 128 KiB per class with extended size classes.
- Beyond that the slab is `memory_protect` (PROT_NONE) plus `memory_purge`, which is `madvise(MADV_DONTNEED)`. It then goes into a FIFO free-slab queue "to maximize the time spent memory protected".

**Operational cost**
- The README says to raise `vm.max_map_count` substantially, for example to 1048576. The PROT_NONE guards and protected slabs split the region into many VMAs [V].
- There is now a PR to optionally use `MADV_GUARD_INSTALL` for large-allocation guards [S].

**Performance:** no official benchmark numbers. Its stated aim is "decent overall performance with a focus on long-term performance and memory usage rather than allocator micro-benchmarks" [V]. Having no thread cache and a mutex on every operation is the main cost [UNVERIFIED that this dominates, but structurally evident].

### 1.7 PartitionAlloc (Chromium)

Checked against `PartitionAlloc.md` and `encoded_next_freelist.h` [V]:
- Structure: partitions sit in separate address regions. Each has buckets of same-size slots in "slot spans", inside 2 MiB super pages that have guard pages at their edges.
- Metadata is **out-of-line in a guard-page-protected area** of each super page. The free-list next pointer is the only inline metadata.
- The free-list pointer is **byte-swapped** on little-endian. The source comment gives two reasons: the swapped value is a non-canonical address, so a UAF vtable dereference faults, and partial overwrites are thwarted. A "shadow" copy allows corruption checks.
- Provisioning: slots are only threaded onto the free list, and pages only committed, as needed.
- Slot span states are full, active, empty and decommitted. Empty spans are decommitted lazily (FIFO) or by `PurgeMemory()`.
- A per-thread cache batches requests in front of per-partition locks.
- BackupRefPtr/MiraclePtr: a reference count in-slot or out-of-slot quarantines freed memory that is still referenced by `raw_ptr` [UNVERIFIED detail; not re-checked].

### 1.8 Research allocators

- **FreeGuard (CCS'17)** [S]
  - BIBOP layout with out-of-band metadata and random guard pages. Overhead is under 2% against the Linux default allocator.
  - Notably it **deliberately rejects bitmaps**. Per the abstract/snippet, "bitmaps may incur significant performance overhead, which could be proportional to the size of the bitmap", so FreeGuard uses free lists to get O(1) operations. The targets of that criticism were DieHarder/OpenBSD-style random probing of large bitmaps [UNVERIFIED which allocators exactly].
  - Its successor **Guarder (USENIX Sec'18)** makes entropy, guard-page ratio and similar parameters tunable [S].
- **SlimGuard (Middleware'19)** [S]: fine-grained size classes, dynamic canaries and on-demand metadata. It uses up to 2× less memory than prior secure allocators.
- **Mesh (PLDI'19)** [S]
  - Randomized allocation plus per-span occupancy **bitmaps** let the allocator find spans with non-overlapping live objects. It merges such spans by remapping two virtual pages onto one physical page ("meshing"), without moving any objects.
  - Memory drops 16% on Firefox and 39% on Redis at comparable speed.
  - This is directly relevant because it needs out-of-band occupancy bitmaps, which our design already has. It is a possible future RSS feature, but it needs file-backed or memfd mappings.
- **S2malloc (2024)** [S]: statistically secure against use-after-free through randomized placement.
- **Verus-verified mimalloc (Rust)** [V, README; S, Verus paper]
  - A mimalloc port written in Rust and formally verified with Verus, about 17.2k lines of code plus proof.
  - It has no realloc, no aligned allocation, no thread cleanup, and only handles allocations up to 128 KiB. The README says "we compare pretty badly" against mimalloc.
  - It is useful as a reference for how to express mimalloc's lock-free invariants in Rust ghost state. It is not a performance baseline.

I did not find a published "safe-Rust allocator" paper with a competitive benchmark [search did not surface one].

---

## 2. Comparison table

| Allocator | Metadata | Free tracking | Remote free | Key mitigations | Reported overhead |
|---|---|---|---|---|---|
| mimalloc v2/v3 | Segment/arena header (v3: page map + arena bitmaps) | Intrusive lists ×3 per page | CAS push onto per-page `thread_free`; owner swaps it out | Secure mode: guard pages, encoded free lists, random order, double-free check | ~10% (README), ~3% (paper) |
| snmalloc | Out-of-band pagemap plus guarded metadata | Encoded in-band queues ×2 | Batched message passing: 1 atomic per batch; BatchIt adds a per-slab cache | Signed prev pointers, Sattolo, guarded memcpy | <5% |
| jemalloc | Out-of-band extent + rtree | Slab bitmap | tcache, then per-bin mutex | Minimal | Baseline |
| rpmalloc | Inline span headers | Intrusive lists | Atomic per-page deferred list | None | Fast [S] |
| Scudo | Inline CRC header + primary regions | Per-class batches | Per-thread cache, then lock [UNVERIFIED] | Checksums, quarantine, randomization, secondary guards | Moderate [UNVERIFIED] |
| hardened_malloc | Fully out-of-band array indexed by address | 4×u64 bitmap, ≤256 slots | Mutex per class per arena | Guard slabs, canaries, zero-on-free, quarantine, random slot | Not published; highest of this group [UNVERIFIED] |
| PartitionAlloc | Out-of-line, guarded, per super page | Byte-swapped lists | Thread cache, then lock | Partitions, bswap, guard pages, BRP | Production default in Chrome |

---

## 3. Recommendations for the bitmap / out-of-band design

### 3.1 What the design gets right

- Metadata that user writes cannot reach is exactly the property that hardened_malloc, snmalloc (pagemap) and PartitionAlloc (guarded out-of-line metadata) pay for.
- A bitmap removes the intrusive free-list attack surface altogether. There is nothing to encode, and no XOR, bswap or signature is needed.
- A double free becomes *deterministic and immediate*: the freeing RMW returns the previous bit. That is stronger than snmalloc's lazy detection, and cheaper than mimalloc level 4.
- Address arithmetic from one reserved range, `seg = (p - base) >> 22` and `page = (p & (4MiB-1)) >> 16`, is the hardened_malloc/mimalloc-v3 page-map approach. It needs no pagemap loads beyond a bounds check.
- Validating `offset % size == 0` with a reciprocal multiply (as snmalloc does) gives deterministic invalid-free detection.

### 3.2 Bitmap performance pitfalls and how others avoid them

1. **Scan cost grows with slots per page.** A 64 KiB page of 16-byte blocks has 4096 slots, or 64 words.
   - FreeGuard rejected bitmaps for exactly this reason.
   - hardened_malloc bounds it by capping at **256 slots** per slab (4 words), using smaller slabs for tiny classes. snmalloc bounds it with variable-sized slabs.
   - **Recommendation:** add a two-level bitmap, meaning a per-page summary word with one bit per non-full 64-bit word. Finding a free slot is then two `tzcnt`s. The alternative is to cap slots per page at about 512 by using sub-page "slabs" for classes of 128 bytes and below.
2. **Every allocation is an atomic RMW when the bitmap is shared.**
   - Mitigation: an *owner-local word cache*. The owning thread takes one 64-bit word of free bits at a time into a thread-local register-like cache, for example with `swap(0)` on a "free" word it alone writes, and pops bits with `tzcnt` and `blsr`. The fast path then has no atomics and matches free-list speed.
   - jemalloc's tcache and hardened_malloc's lock-plus-scan are the two extremes. The word cache gets the tcache benefit without intrusive pointers.
   - Keep **two bitmaps per page**. The owner-only `local_free` is non-atomic, or Relaxed. `remote_free` is written only with `fetch_or` by other threads. The owner merges them with a per-word `swap(0)`. This is mimalloc's `thread_free` batching expressed in bitmaps.
3. **False sharing in densely packed out-of-band arrays.**
   - Packing many pages' bitmaps contiguously means one page's remote `fetch_or` bounces lines that the owner of *another* page is writing.
   - hardened_malloc avoids this only because a lock serializes access anyway.
   - **Recommendation:** align each page's `remote_free` region to 64 or 128 bytes, since adjacent-line prefetch pairs lines on x86. Keep owner-hot fields (the local bitmap and counters) in a separate array from remote-written fields. [Design inference, not sourced.]
4. **Discovering pages with pending remote frees.** mimalloc needs the DELAYED state machine for full pages.
   - **Recommendation:** use a per-heap (or per-segment) atomic "pending" bitmap with one bit per page. A remote freer sets it with `fetch_or` only when its `remote_free` word went from zero to non-zero; `fetch_or` returns the old value, so this check is free.
   - The owner scans the pending bitmap on its slow path. It is O(pages/64) words.
5. **One atomic per remote free.** snmalloc and BatchIt show that batching per destination matters for producer-consumer patterns. Tokio work-stealing produces exactly that pattern: request buffers freed on a different worker.
   - **Recommendation:** give each thread a small remote-free buffer keyed by page, holding (page, word, mask) triples. Flush one `fetch_or` per word, so many frees become one RMW. This is BatchIt's per-slab cache, and with bitmaps it is especially cheap because masks OR together.
   - The trade-off is that immediate double-free detection for remote frees becomes detection at flush or merge time. Remain correct by checking at merge time `local_free & incoming == 0`, which catches a double free when the owner merges.
6. **Zeroing and "is empty" checks.**
   - hardened_malloc keeps a `u16 count` to avoid scanning for an empty slab. Do the same with an atomic `used` counter, or derive it from popcounts at merge time.
7. **Randomization with bitmaps is cheap.**
   - hardened_malloc starts the scan at a random word and bit and masks. It costs one RNG call and a few ALU operations.
   - Cheaper still: randomize only when refilling the word cache (pick a random non-empty word), instead of on every allocation.

### 3.3 Cheap mitigations to adopt

Ordered by value divided by cost:

1. **Deterministic invalid and double free** (bitmap RMW return value plus a bounds and alignment check). Essentially free.
2. **Guard regions around metadata arrays and between segments.** They are one-time and not on any hot path.
   - Prefer `MADV_GUARD_INSTALL` (Linux 6.13+) over `mprotect`. It uses PTE markers and does not split VMAs, which avoids the `vm.max_map_count` (default 65530 [UNVERIFIED default]) problem that hardened_malloc documents. Fall back to `mprotect` on older kernels, and keep the guard count bounded.
   - Reserve metadata in its own region, apart from object pages, so no linear overflow reaches it (the hardened_malloc model).
3. **Randomized slot choice per word-cache refill** (see 3.2.7). The snmalloc/mimalloc experience is a few percent at most.
4. **Randomized segment placement within the reservation.** Randomizing the base and the order segments are handed out costs nothing (mimalloc secure 1, hardened_malloc random gap).
5. **Zero-on-free or check-zero-on-alloc**, optionally for small classes only. hardened_malloc turns it on by default, and for a proxy handling secrets (TLS buffers, headers) it has real value. The cost scales with bytes freed, so make it configurable. A middle ground is zeroing on allocation only, which Rust `alloc_zeroed` needs anyway.
6. **A small FIFO slot quarantine**, implemented with bitmaps. A per-page "quarantine" bitmap holds freed bits for N generations before moving them to `free`. With word-granular handling, this is one extra OR per merge. hardened_malloc's `quarantine_bitmap` is the precedent.
7. Skip or defer:
   - Per-object canaries, which cost space in every slot. They only add value once you have no out-of-band metadata to protect.
   - Guard pages between every 64 KiB page (mimalloc secure 5, "expensive!"), or hardened_malloc's every-other-slab guards, which double the VA use and the VMA count. The exception is `MADV_GUARD_INSTALL`, which makes periodic guard *pages* cheap in VMAs. They still cost TLB/page-table entries and waste 4 KiB per guard.

### 3.4 Memory reclamation for a long-running proxy

- **Use `MADV_DONTNEED` for decommit, not `MADV_FREE`, by default.**
  - `MADV_FREE` pages stay in RSS and are only freed under memory pressure. Go reverted from MADV_FREE to MADV_DONTNEED in 1.16 because MADV_FREE "doesn't affect statistics until memory is actually reclaimed", which confused monitoring and orchestrators [S, Go 1.16 notes].
  - mimalloc defaults to DONTNEED for the same RSS reason [V].
  - `MADV_FREE` is cheaper on re-touch, because there is no zero-fill fault if the page was not reclaimed. It suits only memory that is *likely to be reused soon*.
  - A reasonable policy is jemalloc-like: two stages, where empty pages go through MADV_FREE ("muzzy") and later MADV_DONTNEED. But note that jemalloc's own default muzzy decay is 0 [S], so in practice it goes straight to clean.
- **Delayed, batched purge (decay).** Keep empty pages hot for a delay, then purge.
  - Defaults elsewhere: mimalloc v3 1000 ms, Scudo 5000 ms interval, jemalloc 10 s dirty decay.
  - hardened_malloc instead uses a fixed byte budget per class (the empty-slab cache), then purges immediately.
  - **Recommendation:** combine the two. Use a small per-class, per-heap budget of empty pages that are never purged, which absorbs request/response churn. Purge the rest after 0.5–2 s of disuse. Coalesce contiguous empty 64 KiB pages into one `madvise` call to reduce syscalls and TLB shootdowns.
- **Do purging off the hot path.** jemalloc's `background_thread` "generally improves the tail latency" [V, TUNING]. For a proxy with a p99 SLO, run the purge from a dedicated low-priority thread, or from the owner's slow path with a time check.
  - `madvise` on a range shared across threads causes an IPI TLB shootdown. Batching reduces this [UNVERIFIED magnitude].
- **Reservation strategy.**
  - Reserving the whole range `PROT_NONE` and then `mprotect`-ing it RW piecemeal splits VMAs and adds commit charge per piece.
  - Alternative: map the reservation `PROT_READ|PROT_WRITE` with `MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE` as a single VMA. Physical memory is committed by first touch, `MADV_DONTNEED` decommits, and guards are PTE markers from `MADV_GUARD_INSTALL`.
  - Caveat: under `vm.overcommit_memory=2`, `MAP_NORESERVE` is ignored and the whole range is charged [UNVERIFIED on current kernels; verify on your deploy target].
- **Transparent huge pages.** `MADV_DONTNEED` on 64 KiB inside a THP-backed 2 MiB region splits the huge page. Either:
  - use THP only for metadata arrays, as jemalloc's `metadata_thp` does [V, which reports reduced TLB misses], and set `MADV_NOHUGEPAGE` on object segments; or
  - purge at 2 MiB granularity. For RSS-sensitive proxies, the first option is simpler.
- **Abandoned heaps.** Tokio/rayon threads usually live forever, but blocking-pool threads come and go.
  - Adopt mimalloc v3's approach: mark pages abandoned in an arena-level atomic bitmap, and let any heap claim them.
  - Otherwise RSS leaks slowly with thread churn. The Verus mimalloc explicitly lacks thread cleanup and leaks for this reason [V].
- **Fragmentation.** Size-class-segregated allocators hold RSS through sparse pages. Mesh-style meshing needs memfd-backed segments and is a larger project. The practical mitigation is to allocate from the *fullest* non-full page first (mimalloc-like page queues), so that sparse pages drain and can be purged.

### 3.5 Rust-specific notes [UNVERIFIED; background knowledge, verify during implementation]

- A `GlobalAlloc` must not allocate reentrantly. `std::thread_local!` with destructors may register them through `__cxa_thread_atexit_impl` on glibc. Test heap setup and teardown under `LD_BIND_NOW` and early-startup allocation, and use a const-initialised TLS slot with lazy heap attach.
- `AtomicU64::fetch_or` and `fetch_and` compile to `lock or` and `lock and` when the result is unused. When the return value is needed (for double-free detection) they become a `lock cmpxchg` loop on x86. `lock bts` is not emitted from `fetch_or`, so use `fetch_or` with a single-bit mask and check the old value, and measure it. Alternatively use inline asm `lock bts` for a single CF-returning instruction.

---

## Sources

- mimalloc README: https://github.com/microsoft/mimalloc
- mimalloc v2 types.h: https://raw.githubusercontent.com/microsoft/mimalloc/main/include/mimalloc/types.h
- mimalloc v3 types.h: https://raw.githubusercontent.com/microsoft/mimalloc/dev3/include/mimalloc/types.h
- mimalloc paper (MSR-TR-2019-18 / APLAS'19): https://www.microsoft.com/en-us/research/uploads/prod/2019/06/mimalloc-tr-v1.pdf
- mimalloc environment options: https://microsoft.github.io/mimalloc/environment.html
- snmalloc README: https://github.com/microsoft/snmalloc
- snmalloc security docs: https://github.com/microsoft/snmalloc/blob/main/docs/security/README.md
- snmalloc free-list protection: https://github.com/microsoft/snmalloc/blob/main/docs/security/FreelistProtection.md
- snmalloc randomisation: https://github.com/microsoft/snmalloc/blob/main/docs/security/Randomisation.md
- snmalloc variable-sized chunks: https://github.com/microsoft/snmalloc/blob/main/docs/security/VariableSizedChunks.md
- snmalloc guarded memcpy: https://github.com/microsoft/snmalloc/blob/main/docs/security/GuardedMemcpy.md
- snmalloc paper (ISMM'19): https://www.microsoft.com/en-us/research/uploads/prod/2020/04/snmalloc.pdf
- BatchIt (ISMM'24): https://www.microsoft.com/en-us/research/wp-content/uploads/2024/05/preprint_batchit.pdf
- jemalloc manual: https://jemalloc.net/jemalloc.3.html
- jemalloc TUNING.md: https://github.com/jemalloc/jemalloc/blob/dev/TUNING.md
- jemalloc muzzy default issue: https://github.com/jemalloc/jemalloc/issues/1827
- rpmalloc: https://github.com/mjansson/rpmalloc
- Scudo: https://llvm.org/docs/ScudoHardenedAllocator.html
- hardened_malloc README: https://github.com/GrapheneOS/hardened_malloc
- hardened_malloc source: https://raw.githubusercontent.com/GrapheneOS/hardened_malloc/main/h_malloc.c
- hardened_malloc memory.c: https://raw.githubusercontent.com/GrapheneOS/hardened_malloc/main/memory.c
- hardened_malloc default config: https://raw.githubusercontent.com/GrapheneOS/hardened_malloc/main/config/default.mk
- hardened_malloc MADV_GUARD_INSTALL PR: https://github.com/GrapheneOS/hardened_malloc/pull/341
- PartitionAlloc: https://chromium.googlesource.com/chromium/src/+/HEAD/base/allocator/partition_allocator/PartitionAlloc.md
- PartitionAlloc encoded free list: https://chromium.googlesource.com/chromium/src/+/HEAD/base/allocator/partition_allocator/src/partition_alloc/encoded_next_freelist.h
- FreeGuard: https://arxiv.org/pdf/1709.02746
- Guarder: https://www.usenix.org/conference/usenixsecurity18/presentation/silvestro
- SlimGuard: https://www.ssrg.ece.vt.edu/papers/middleware19-slimguard.pdf
- Mesh: https://arxiv.org/abs/1902.04738
- S2malloc: https://arxiv.org/pdf/2402.01894
- Verus verified allocator: https://github.com/verus-lang/verified-memory-allocator/blob/main/README.md
- Verus projects list: https://verus-lang.github.io/verus/publications-and-projects/
- madvise(2): https://man7.org/linux/man-pages/man2/madvise.2.html
- MADV_GUARD_INSTALL (LWN): https://lwn.net/Articles/1011366/
- Go 1.16 release notes (MADV_DONTNEED): https://go.dev/doc/go1.16
- mimalloc-bench: https://github.com/daanx/mimalloc-bench
