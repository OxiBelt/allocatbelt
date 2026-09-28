# unsafe boundary inventory

`allocatbelt-core` uses `#![forbid(unsafe_code)]`, so it contains **0** `unsafe` sites. All the `unsafe` is listed below. Every `unsafe` block holds exactly one unsafe operation and carries a `// SAFETY:` comment (`clippy::undocumented_unsafe_blocks` and `multiple_unsafe_ops_per_block` are deny).

Regenerate: `grep -rn "unsafe" crates/*/src bench/simd/src | grep -E "unsafe (\{|fn|impl)"`

## allocatbelt-sys

| Location | Kind | Operation | Why it is sound |
|---|---|---|---|
| `Region` | `unsafe impl Send/Sync` | — | It is an address-range handle and exposes no references. Mutation happens only through syscalls. |
| `Region::reserve` | block | `mmap_anonymous(null, …, PROT_NONE, PRIVATE\|NORESERVE)` | A null hint without MAP_FIXED yields a fresh range, so it aliases nothing. |
| `Region::reserve` | block ×2 | `munmap` of the head/tail slack left after alignment | Trims only the unused ends of the mapping created just above. |
| `Region::commit` | block | `mprotect(RW)` | Range checked; it only adds permissions, so it cannot invalidate any existing reference. |
| `Region::purge` | **`unsafe fn`** + block | `madvise(MADV_DONTNEED)` | The contents are discarded, so the caller guarantees "no live references or concurrent access in the range". Returns whether the kernel accepted it, i.e. whether the range now reads as zero. |
| `Region::decommit` | **`unsafe fn`** + block ×2 | `purge` + `mprotect(NONE)` | Same contract, plus no access until the range is committed again. |
| `Region::guard` | **`unsafe fn`** + block ×2 | `guard_markers`, else `mprotect(NONE)` | Same contract as `decommit`: nothing may use the range until it is unguarded and committed again. |
| `Region::guard_markers` (private) | **`unsafe fn`** + block ×2 | `madvise(MADV_GUARD_INSTALL)` (`libc`, Linux 6.13+), checked by `madvise(MADV_POPULATE_READ)` failing with `EFAULT` | Same contract as `guard`: the markers discard the contents and fault on access. The populate probe only read-faults pages in; it exists because emulators such as qemu-user report success for advice they ignore. Removes the markers again when they did not take effect. |
| `Region::unguard` | block | `madvise(MADV_GUARD_REMOVE)` (`libc`) | Range checked; removing guard markers only turns faulting pages into zero-fill pages and leaves other pages alone, so it cannot invalidate memory in use. |
| `register_atfork` | block | `pthread_atfork(prepare, parent, child)` (`libc`) | The handlers are `extern "C" fn()` items, valid for the life of the process and safe to call. glibc allocates the registration with its own `malloc`, not through us. |
| `MetaArena::slot` | block | `slice::from_raw_parts` → `&[AtomicU64]` | Published only after commit (READY, Acquire). Never unmapped or purged. Zero-filled by the kernel, so every bit pattern is valid, and only atomic access follows. |
| `platform::probe` | block ×5 | `write_volatile` / `read_volatile` of one byte, `Region::purge`, `Region::guard_markers`, `Region::decommit`, all on a 64 KiB scratch `Region` the probe reserves itself | The scratch range is private to the function: no reference to it exists and nothing else knows its address, so writing, purging, guarding and decommitting it cannot affect any other memory. The byte is written and read only while the range is committed read/write (a purge keeps it accessible). Runs once, before the arena is reserved ([docs/platform.md](platform.md)). |

`futex_wait`/`futex_wake` (the heap locks' sleep and wake-up) use rustix's safe futex functions and add no `unsafe` site.

`libc` is used only for what rustix does not cover: the guard-marker advice values (not in rustix's `Advice` enum) and `pthread_atfork`.

The sys crate **does not use** `rustix::param::page_size()`: reading auxv may allocate when rustix's `alloc` feature gets unified in, which would re-enter the allocator. Instead every range uses a fixed 64 KiB granule, a multiple of all Linux page sizes.

## allocatbelt-arch

CPU feature detection only; no architecture kernel exists yet. Every site runs during `initialize_dispatch()` (or the first `detected_features()` call) and only reads CPU or kernel state.

| Location | Kind | Operation | Why it is sound |
|---|---|---|---|
| `x86_64::xcr0` | block | `_xgetbv(0)` | `xgetbv` faults unless the OS enabled XSAVE; the only caller checks `CPUID.1:ECX.OSXSAVE` first. The `xsave` target feature is on for every build (x86-64-v3), and register 0 (`XCR0`) always exists. `cpuid` itself is a safe intrinsic. |
| `aarch64::detect` | block ×2 | `libc::getauxval(AT_HWCAP)`, `libc::getauxval(AT_HWCAP2)` | Accepts any key and returns 0 for unknown ones; it only reads libc's saved copy of the auxiliary vector, without syscalls or allocation (glibc and musl). |
| `riscv64::detect` | block | `libc::syscall(riscv_hwprobe, &mut pair, 1, 0, null, 0)` | The kernel writes only into the one `Pair` passed, a live exclusive local with the UAPI `struct riscv_hwprobe` layout (`#[repr(C)]` `i64` + `u64`). A null CPU set of size 0 means all online CPUs and the flags are 0, as the hwprobe documentation requires. |

## allocatbelt (adapter)

| Location | Kind | Operation | Why it is sound |
|---|---|---|---|
| `LinuxOs::purge/decommit` | block ×2 | calls `Region::purge/decommit` | The core's `Os` contract: it only purges or decommits ranges with no live allocations (see below). |
| `LinuxOs::guard` | block | calls `Region::guard` | The core's `Os` contract: it only guards the last page of an owned segment, which it never hands out, and unguards it before the segment can be committed for other use (trust assumption 5). |
| `impl GlobalAlloc` | `unsafe impl` + 4 `unsafe fn` | — | Required by the trait. Unwinding is blocked by `AbortOnUnwind`. |
| `alloc_zeroed` | block | `write_bytes(0, size)` | A fresh block that nobody references yet. Skipped when the core reports the block as already zero (trust assumption 4). |
| `realloc` | block | `copy_nonoverlapping` | The old block is live (caller contract); the new block is a separate fresh block. |

## allocatbelt-simd-bench (benchmark only)

`bench/simd` holds the Phase 4 SIMD candidates ([research/simd-benchmarks.md](research/simd-benchmarks.md)). It is not a dependency of the allocator and nothing in it runs inside `GlobalAlloc`. Phase 5 promoted none of them; a kernel promoted later moves into `allocatbelt-arch` and gets its own rows above. Its `unsafe` is listed here so the whole workspace is accounted for.

| Location | Kind | Operation | Why it is sound |
|---|---|---|---|
| `kernels/x86_64.rs`: `nonzero_avx2`, `popcount_avx2`, `age_avx2`, `zero_avx2`, `zero_avx2_nt`, `copy_avx2` | block each | call of the `#[target_feature(enable = "avx2")]` `_imp` function | The wrapper is only put into a `Variant` when `CpuFeatures::AVX2` was detected (always true at the x86-64-v3 floor). |
| `kernels/x86_64.rs`: `nonzero_avx512`, `age_avx512`, `zero_avx512`, `copy_avx512`, `popcount_avx512` | block each | call of the `avx512f` (popcount: `avx512f,avx512vpopcntdq`) `_imp` function | Listed only when `AVX512F` (and `AVX512VPOPCNTDQ`) were detected. |
| `kernels/x86_64.rs`: `zero_avx2_imp`, `zero_avx512_imp`, `copy_avx2_imp`, `copy_avx512_imp` | block ×1 or ×2 | `_mm256_storeu_si256` / `_mm512_storeu_si512`, `_mm256_loadu_si256` / `_mm512_loadu_si512` | Each pointer comes from a `chunks_exact(_mut)` chunk of exactly the vector width, so the access is in bounds; the unaligned forms have no alignment requirement; source and destination are a `&[u8]` and a `&mut [u8]`, so they do not overlap. |
| `kernels/x86_64.rs`: `zero_avx2_nt_imp` | block | `_mm256_stream_si256` | The chunks start after a scalar head that brings the pointer to 32-byte alignment, as `movntdq` requires, and are exactly 32 bytes; an `_mm_sfence` follows the loop so the stores are ordered before the function returns. |
| `kernels/aarch64.rs`: `nonzero_neon`, `popcount_neon`, `age_neon`, `zero_neon`, `copy_neon` | block each | call of the `#[target_feature(enable = "neon")]` `_imp` function | Listed only when `ASIMD` was detected. |
| `kernels/aarch64.rs`: `nonzero_sve`, `popcount_sve`, `age_sve` | block each | call of the `#[target_feature(enable = "sve")]` `_imp` function | Listed only when `SVE` was detected. |
| `kernels/aarch64.rs`: `zero_neon_imp`, `copy_neon_imp`, `load2` | block ×1 or ×2 | `vst1q_u8_x4`, `vld1q_u8_x4`, `vld1q_u64` | 64-byte chunks from `chunks_exact(_mut)`, or a `&[u64; 2]`, so every access is in bounds; `ld1`/`st1` have no alignment requirement beyond the element's; source and destination do not overlap (`&` and `&mut`). |
| `perf.rs`: `Counters::open` | block ×2 | `libc::syscall(SYS_perf_event_open, &attr, 0, -1, group_fd, 0)`, then `File::from_raw_fd` | The kernel only reads `attr`, a live `#[repr(C)]` struct of `PERF_ATTR_SIZE_VER0` bytes (checked by a const assertion), and returns a new descriptor that nothing else owns, so the `File` may close it. |
| `perf.rs`: `Counters::group_ioctl` | block | `libc::ioctl(leader, PERF_EVENT_IOC_{RESET,ENABLE,DISABLE}, PERF_IOC_FLAG_GROUP)` | These requests take an integer flag, not a pointer, on a perf descriptor this `Counters` owns; a failure only makes the counts unusable. |

## Trust assumptions (the part the boundary does not cover)

The narrow boundary makes each *operation* auditable, but soundness still depends on **the correctness of the core logic**:

1. The heap never hands out an offset that is live twice (non-overlap).
2. It never calls `purge`/`decommit` on a range that holds a live allocation.
3. It never hands out an offset that has not been committed.
4. It only reports a block as `zeroed` if every page of it was never handed out, or was purged/decommitted with success (`Os::purge`/`Os::decommit` returned `true`) since it was last handed out. Otherwise `calloc` would return stale bytes.
5. It never hands out, purges or commits a guarded page: the guard page of an owned segment stays claimed in the segment's page bitmap for as long as the segment is owned, and `Os::unguard` runs before the segment returns to the arena.

Current verification:

- **Shadow maps.** The checking mock `Os` (`allocatbelt-core/src/model.rs`, feature `model`) checks non-overlap, commit state, that purged, decommitted and guarded ranges hold no live block, that nothing guarded is handed out or committed, and a written-pages shadow that every `zeroed` claim is checked against, including with failing purges. It backs every model test.
- **proptest.** Random operation sequences, with and without thread caches and randomized placement, and random byte programs for the fuzz interpreter (`model::run`, `tests::fuzz_programs`).
- **Fuzzing.** `fuzz/` runs `model::run` under libFuzzer (cargo-fuzz). A 10-minute run on 2026-09-28 executed 381,049 programs with no failure. CI repeats it on its daily schedule.
- **loom.** `proto.rs` holds every lock-free transition the heap performs on shared metadata, and loom checks them exhaustively (`--cfg loom`): free vs. claim, two freers on one word, racing double frees, the free counter never overstating free blocks, page-run claim/release vs. purge, in-place growth vs. segment trimming, and the heap lock, whose futex parking is modelled with a wait queue that checks the word under the same mutex as the wake, so a lost wake-up would show up as a deadlock. The heap calls these same functions, so the models check the shipped code.
- **Integration tests.** Multi-threaded cross-thread frees, thread exit returning caches, the background purge thread returning RSS, a real overflow faulting in the guard page, and `fork` from a busy process.
- **Mutation testing.** The mewt campaign over `bits`/`class` (see CONTRIBUTING.md) passes: 77 mutants caught, 5 listed as equivalent.
- **Miri.** Only a partial run on the core tests (below).

Miri result (**run on commit 0271678**, i.e. before the later follow-up commits, nightly 2026-09-26, `-Zmiri-disable-isolation`, 90-minute limit): **8/17 tests passed with no UB detected**:
`bits::{masks, run_matches_naive}`, `class::{table_shape, class_of_is_tight}`, `tests::{alignments, cross_thread_frees, double_free_small, double_free_large}`.
The other 9 (proptest-based ones, `every_size_round_trips`, `random_sequences`, etc.) **did not finish** within the limit. Miri has not been run on the current head. To run all of them under Miri, the mock's `MAX_SEGMENTS`-sized tables and the iteration counts need to shrink under `cfg(miri)`.
Since the core has no `unsafe`, Miri mainly checks panics/overflow and data races in the atomic logic here, not memory safety.
Before production, add loom models and fuzzing (cargo-fuzz against `Heap<MockOs>`).

Other caveats:
- **fork:** the adapter registers `pthread_atfork` handlers that take every heap lock before `fork` and release them on both sides (`Heap::fork_prepare/parent/child`), so no lock is held by a thread missing in the child; the child also reseeds its placement secret and falls back to allocation-driven purging. Blocks cached by the parent's other threads stay allocated in the child. `posix_spawn` and `vfork` do not run the handlers, and do not need to. Covered by `tests/fork.rs`, which deadlocked before the handlers existed.
- `std::io::stderr()` is used only on the fatal path (unbuffered, no allocation expected).
