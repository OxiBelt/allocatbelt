# unsafe boundary inventory

`allocatbelt-core` uses `#![forbid(unsafe_code)]`, so it contains **0** `unsafe` sites. All the `unsafe` is listed below. Every `unsafe` block holds exactly one unsafe operation and carries a `// SAFETY:` comment (`clippy::undocumented_unsafe_blocks` and `multiple_unsafe_ops_per_block` are deny).

Regenerate: `grep -rn "unsafe" crates/*/src | grep -E "unsafe (\{|fn|impl)"`

## allocatbelt-sys

| Location | Kind | Operation | Why it is sound |
|---|---|---|---|
| `Region` | `unsafe impl Send/Sync` | — | It is an address-range handle and exposes no references. Mutation happens only through syscalls. |
| `Region::reserve` | block | `mmap_anonymous(null, …, PROT_NONE, PRIVATE\|NORESERVE)` | A null hint without MAP_FIXED yields a fresh range, so it aliases nothing. |
| `Region::reserve` | block ×2 | `munmap` of the head/tail slack left after alignment | Trims only the unused ends of the mapping created just above. |
| `Region::commit` | block | `mprotect(RW)` | Range checked; it only adds permissions, so it cannot invalidate any existing reference. |
| `Region::purge` | **`unsafe fn`** + block | `madvise(MADV_DONTNEED)` | The contents are discarded, so the caller guarantees "no live references or concurrent access in the range". Returns whether the kernel accepted it, i.e. whether the range now reads as zero. |
| `Region::decommit` | **`unsafe fn`** + block ×2 | `purge` + `mprotect(NONE)` | Same contract, plus no access until the range is committed again. |
| `MetaArena::slot` | block | `slice::from_raw_parts` → `&[AtomicU64]` | Published only after commit (READY, Acquire). Never unmapped or purged. Zero-filled by the kernel, so every bit pattern is valid, and only atomic access follows. |

The sys crate **does not use** `rustix::param::page_size()`: reading auxv may allocate when rustix's `alloc` feature gets unified in, which would re-enter the allocator. Instead every range uses a fixed 64 KiB granule, a multiple of all Linux page sizes.

## allocatbelt (adapter)

| Location | Kind | Operation | Why it is sound |
|---|---|---|---|
| `LinuxOs::purge/decommit` | block ×2 | calls `Region::purge/decommit` | The core's `Os` contract: it only purges or decommits ranges with no live allocations (see below). |
| `impl GlobalAlloc` | `unsafe impl` + 4 `unsafe fn` | — | Required by the trait. Unwinding is blocked by `AbortOnUnwind`. |
| `alloc_zeroed` | block | `write_bytes(0, size)` | A fresh block that nobody references yet. Skipped when the core reports the block as already zero (trust assumption 4). |
| `realloc` | block | `copy_nonoverlapping` | The old block is live (caller contract); the new block is a separate fresh block. |

## Trust assumptions (the part the boundary does not cover)

The narrow boundary makes each *operation* auditable, but soundness still depends on **the correctness of the core logic**:

1. The heap never hands out an offset that is live twice (non-overlap).
2. It never calls `purge`/`decommit` on a range that holds a live allocation.
3. It never hands out an offset that has not been committed.
4. It only reports a block as `zeroed` if every page of it was never handed out, or was purged/decommitted with success (`Os::purge`/`Os::decommit` returned `true`) since it was last handed out. Otherwise `calloc` would return stale bytes.

Current verification: shadow-map checks against the mock `Os` (non-overlap, commit state, purge overlap, and a written-pages shadow that every `zeroed` claim is checked against, including with failing purges), proptest random sequences, multi-threaded cross-thread-free tests, and a partial Miri run on the core tests (below).

Miri result (**run on commit 0271678**, i.e. before the later follow-up commits, nightly 2026-09-26, `-Zmiri-disable-isolation`, 90-minute limit): **8/17 tests passed with no UB detected**:
`bits::{masks, run_matches_naive}`, `class::{table_shape, class_of_is_tight}`, `tests::{alignments, cross_thread_frees, double_free_small, double_free_large}`.
The other 9 (proptest-based ones, `every_size_round_trips`, `random_sequences`, etc.) **did not finish** within the limit. Miri has not been run on the current head. To run all of them under Miri, the mock's `MAX_SEGMENTS`-sized tables and the iteration counts need to shrink under `cfg(miri)`.
Since the core has no `unsafe`, Miri mainly checks panics/overflow and data races in the atomic logic here, not memory safety.
Before production, add loom models and fuzzing (cargo-fuzz against `Heap<MockOs>`).

Other caveats:
- **fork:** if another thread holds a shard or segment spin lock at fork time, the child can deadlock. That needs a `pthread_atfork` handler or a fork epoch (boundary.md §2.5).
- `std::io::stderr()` is used only on the fatal path (unbuffered, no allocation expected).
