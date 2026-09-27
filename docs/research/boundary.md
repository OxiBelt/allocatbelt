# OxiBelt allocator: unsafe-boundary research

Date: 2026-09-27. Target: Rust 1.98, edition 2024, Linux (glibc and musl), x86_64 and aarch64.
Legend: **[V]** means I checked it against a primary source during this research (URL in Sources). **[U]** means unverified: from memory or inference, so check it before relying on it.

---

## 0. TL;DR recommendations

1. **Syscalls: use `rustix` 1.x** (currently 1.1.5 [V]) with `default-features = false, features = ["mm", "rand"]` (add `"thread"` only if needed), plus **`use-libc-auxv`** as a defensive feature. Wrap it in a small `oxibelt-alloc-sys` crate. Don't use raw `asm!` syscalls, because rustix's linux_raw backend already does that, including for musl x86_64/aarch64 [V]. Use `libc` only for the few symbols rustix lacks (`pkey_*`, `pthread_atfork`, `__rseq_offset`), and only if those features get built.
2. **Inside the alloc path, call only rustix `mm::*` and `rand::getrandom`.** Never call `param::page_size`, `thread::sched_getcpu`, `time::*` or any other vDSO/auxv-backed API there. On first use the linux_raw backend reads auxv lazily. If the `alloc` feature is on (it gets unified on by any other crate in the graph that enables `rustix/std`), that path can do `vec![...]`, fall back to opening `/proc/self/auxv`, and `unwrap()` [V]. That means reentrancy plus a possible panic inside the allocator.
3. **Provenance: keep one `NonNull<u8>` base pointer per mapping in a static `AtomicPtr` and derive every pointer from it with `wrapping_add`/`map_addr`.** This is strict provenance and needs no `unsafe`. Never use `with_exposed_provenance`. In `dealloc`, use `ptr.addr()` for arithmetic only.
4. **Metadata as `&'static [AtomicU64]` over zeroed anonymous mmap memory is sound** under the conditions in section 3: never unmapped, never `MADV_DONTNEED`/`FREE`'d, never `mprotect`ed below RW, never aliased by a non-atomic view, and a disjoint range.
5. **TLS: use `thread_local!` with `const { }` and a `!Drop` type for the hot cache.** Use a separate `Drop` guard only for the flush-on-exit, accessed with `try_with`. `GlobalAlloc` docs guarantee `thread_local` does not call the global allocator [V]. One caveat is the open issue rust-lang/rust#160930 [V].
6. **Never panic in the alloc path.** Unwinding out of `GlobalAlloc` is UB [V]. Deny the panicking clippy lints in the logic crate, and put an `extern "C"` trampoline (Rust ≥1.81 aborts on unwind [V]) or `std::process::abort` behind every entry point.
7. **Hardware:** build with `-C target-cpu=x86-64-v3` (BMI1/LZCNT/POPCNT/AVX2 [V]), or use `NonZeroU64::trailing_zeros`, which is branch-free even without BMI1. Skip AVX2/AVX-512 scanning of *shared atomic* bitmaps because it's a data race; SIMD is only for thread-owned data. Use getrandom for seeding, not RDRAND. Defer rseq, MPK and MTE to optional hardening phases.

---

## 1. rustix vs libc vs raw syscalls

### 1.1 API safety in rustix 1.1.5 [V]
| API | Safe? | Notes |
|---|---|---|
| `mm::mmap_anonymous(ptr, len, prot, flags) -> Result<*mut c_void>` | `unsafe` | SAFETY (verbatim): "If `ptr` is not null, it must be aligned to the applicable page size, and the range … must be valid to mutate with `ptr`'s provenance." With `ptr = null` the contract is trivially met, so the wrapper can be a safe fn. |
| `mm::munmap` | `unsafe` | Caller must guarantee that nothing still references the range. |
| `mm::mprotect` | `unsafe` | Lowering permissions can make existing `&` references fault. Raising PROT_NONE to RW is benign. |
| `mm::madvise(addr, len, Advice)` | `unsafe` | SAFETY (verbatim): "addr must be a valid pointer to memory that is appropriate to call posix_madvise on. Some forms of advice may mutate the memory…" |
| `mm::mlockall`/`munlockall` | safe | |
| `rand::getrandom(buf: impl Buffer<u8>, GetRandomFlags) -> Result<…>` | **safe** | Makes a direct syscall, not the vDSO [V]. With `&mut [u8]` it does not allocate. |
| `thread::sched_getcpu()` | safe | Uses the vDSO `__vdso_getcpu`, and **lazy vDSO init reads auxv**. Not allocator-safe; see 1.3. |
| `thread::set_current_tagged_address_mode` | exists | Useful for MTE [V: present in the all-items list]. |
| `pkey_alloc` / `pkey_mprotect` | **absent** | Need `libc` or `asm!` [V]. |
| `rseq` | only in `not_implemented::libc_internals` | glibc owns rseq registration [V]. |

`MapFlags::NORESERVE`, `POPULATE`, `FIXED_NOREPLACE`, `HUGETLB`, `ProtFlags::MTE` and `Advice::{LinuxDontNeed, LinuxFree, LinuxDontDump, LinuxWipeOnFork, LinuxHugepage, LinuxNoHugepage, LinuxPopulateWrite, LinuxCold, LinuxPageOut}` all exist [V, from `src/backend/linux_raw/mm/types.rs`].

### 1.2 Backend selection (from rustix `build.rs`) [V]
- linux_raw (inline-asm syscalls) is the default on Linux for x86_64, aarch64, riscv64, arm, x86 and little-endian targets, **regardless of `target_env`**. So `x86_64-unknown-linux-musl` gets linux_raw and doesn't depend on musl's syscall wrappers. The README says linux_raw "preserve[s] memory, I/O safety, and pointer provenance all the way down to the syscalls".
- **Under Miri, rustix switches to the libc backend automatically** (`|| miri`), because "Miri doesn't support inline asm, and has builtin support for recognizing libc FFI calls". Miri shims `mmap` only for `MAP_PRIVATE|MAP_ANONYMOUS`, RW, no `MAP_FIXED`, and whole-region `munmap` [V, miri PR #2520, merged 2023-06]. `MAP_NORESERVE`, `PROT_NONE` reservations, `mprotect` and `madvise` are probably unsupported in Miri [U]. So the sys crate should use `cfg(miri)`: plain RW mmap without NORESERVE, and make `madvise`/`mprotect` no-ops.
- Opt-outs: feature `use-libc` or `--cfg rustix_use_libc`.

### 1.3 Does rustix allocate? [V, source read]
- `mm::*` and `rand::getrandom` are straight syscalls with no allocation.
- **Hazard:** in linux_raw, `param/auxv.rs::init_auxv_impl()` first tries `PR_GET_AUXV` into a 512-byte stack buffer. With `feature = "alloc"` it then does `vec![0_u8; len]` if that doesn't fit, and falls back to `fs::open("/proc/self/auxv")` + `init_from_auxv_file(...).unwrap()` (a `Vec::with_capacity(512)`). `init_auxv()` calls `.unwrap()`, so it panics on error. This runs lazily the first time you call `page_size()`, the vDSO (`sched_getcpu`, `clock_gettime`) or similar.
  - Feature unification defeats `default-features = false`: tokio, mio or anything else in OxiBelt's graph that enables `rustix/std` turns `alloc` on.
  - Mitigations: (a) enable the `use-libc-auxv` feature, so auxv comes from libc `getauxval`, which is allocation-free in glibc and musl [U for musl internals, but it's a static array walk]. (b) Keep all such calls out of the alloc path: hard-code page size 4096 on x86_64 and read it once from `getauxval` on aarch64 (16K/64K kernels), or `mmap` and check alignment. (c) Add a CI check with `cargo tree -e features -i rustix` that fails if these APIs are imported in the sys crate.

### 1.4 madvise semantics [V, man7 madvise(2)]
- **`MADV_DONTNEED`** on private anonymous memory takes effect immediately and gives "zero-fill-on-demand pages" on next touch. RSS drops right away, and **zeroes are guaranteed**, so a freed-and-purged span can back `alloc_zeroed` without a memset.
- **`MADV_FREE`** (Linux ≥4.5 [U, version from memory]) is lazy: "the kernel can free the pages at any time". A later write cancels the free. Content after reuse is **either old data or zero, nondeterministically**, so you must not assume zero. It's cheaper (no immediate TLB shootdown per page, no refault if reused soon), but RSS stays high until memory pressure, and that confuses container memory metrics and OOM-killer heuristics.
- Recommendation for a proxy with steady load: use `MADV_FREE` for a short-lived "hot" decommit and `MADV_DONTNEED` for long-idle spans (a decay timer, as jemalloc does with dirty→muzzy→clean [U]). Always treat purged memory as *indeterminate* unless DONTNEED was used, and track a `is_zero` bit per span.
- Both are **unsafe to expose**. From the Abstract Machine's view the kernel mutates memory underneath you, so the caller must guarantee that no live allocation or reference overlaps the range. Never apply them to the metadata region.
- Also useful: `MADV_DONTDUMP` on large arenas (smaller cores, with secrets out of dumps) and `MADV_WIPEONFORK` for the fork epoch (section 2.5).

### 1.5 MAP_NORESERVE / overcommit [V, kernel overcommit-accounting]
- "In mode 2 the MAP_NORESERVE flag is ignored", and "We account mprotect changes in commit".
- Pattern: reserve a large VA range with `PROT_NONE` + `MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE`, then commit chunks with `mprotect(RW)`. That behaves correctly in all overcommit modes. A PROT_NONE private mapping is not charged to commit in mode 2 [U, but this is how the kernel accounts non-writable private mappings, VM_ACCOUNT only when writable].
- `mprotect` RW on a subrange splits the VMA. Commit in large (for example 2 MiB+) chunks so you don't hit `vm.max_map_count` (default 65530 [U]).

### 1.6 Supply chain [V]
- RustSec/GHSA: **GHSA-c827-hfw6-qwvm / CVE-2024-43806** (`fs::Dir` iterator infinite loop plus memory growth, linux_raw). It doesn't touch `mm`/`rand`. Fixed in 0.35.15, 0.36.16, 0.37.25, 0.38.19. I found no advisory against rustix 1.x [U, rustsec.org package page returned 404, so run `cargo audit`].
- cargo-vet: Bytecode Alliance (wasmtime `supply-chain/audits.toml`) has `[[trusted.rustix]]` and `[[trusted.linux-raw-sys]]` for sunfishcode, safe-to-deploy, with `end = "2026-03-19"`. **That entry has expired as of today**, so re-check whether it was renewed. Google's `rust-crate-audits` has safe-to-run audits up to 0.38.32 only. **Plan to import the BA trust set and add a delta audit of just `mm`/`rand`/linux_raw `arch` for 1.x.**
- `libc` crate: no unsafe-wrapper value, since every call is `unsafe extern`. Use it only for missing symbols.

---

## 2. Reentrancy hazards

### 2.1 Official contract [V, `GlobalAlloc` docs]
- "It's undefined behavior if global allocators unwind."
- "one should generally stick to library features available through `core`, and avoid using `std` in a global allocator". On some platforms `std::sync::Mutex` may allocate.
- The guarantee: `std::thread_local`, `std::thread::current`, `std::thread::park` and `Thread::unpark`/`clone` do **not** use `#[global_allocator]`.

### 2.2 `thread_local!` with `const { }` and a `!Drop` type
- std docs [V] say that `const {}` "can avoid lazy initialization", and that for types that don't need drop it's "an even more efficient implementation that does not need to track any additional state". Per std's `sys/thread_local/native/mod.rs` [V], `const` + `!Drop` stores **plain `T`**, with no state machine, **no destructor registration and no `Destroyed` state**. So `LocalKey::with` cannot fail, even during other TLS destructors at thread exit. That makes it the right place for the per-thread cache (for example `Cell<…>`/`UnsafeCell`-free `Cell<u64>` arrays of span indices).
- With `const` + `Drop` it becomes `EagerStorage<T>`, which **registers a destructor** on first access. On glibc that's `__cxa_thread_atexit_impl`, which uses libc malloc, not the Rust global allocator [U]. The fallback registration list allocates through `System` ("performed directly through System, allowing the global allocator to make use of thread local storage" [V, LocalKey docs via search]). After destruction `with` panics, so **always use `try_with`** and fall back to the global (shared) path when the cache is gone.
- Recommended layout:
  - `static CACHE: ThreadCache = const { ThreadCache::new() }` (`!Drop`, `Cell`-based).
  - `static FLUSH: FlushGuard = const { FlushGuard }` (`Drop`, zero-sized). Touch it once on the first slow-path allocation. Its `Drop` moves CACHE contents back to global, then marks CACHE "disabled" so later deallocs from other TLS dtors go straight to global.
- Open issue **rust-lang/rust#160930** (open Aug 2026 [V]): TLS implementation paths can *panic* when `pthread_setspecific`/`TlsSetValue` fails. The panic allocates, which violates the non-reentrancy guarantee. On x86_64/aarch64 Linux with native `#[thread_local]` and const+!Drop there's no key path, so the exposure is limited to the Drop guard's registration [U, inferred]. Related: **#147342** (open) proposes guaranteeing that `with` never fails for `!needs_drop` TLS.
- ELF TLS model: OxiBelt is an executable, so TLS is local-exec/initial-exec and needs no `__tls_get_addr`. If the allocator were ever put in a `dlopen`ed cdylib, the first access could go through glibc's `__tls_get_addr` → libc `malloc` [U]. That's harmless unless you also interpose `malloc`.

### 2.3 Panics
- Enable in the logic crate: `clippy::panic`, `unwrap_used`, `expect_used`, `indexing_slicing`, `arithmetic_side_effects`, `unreachable`, `todo`, `integer_division`, and `#![no_std]` (plus `core` only) for the logic crate. Use `get()`, `checked_*`, `wrapping_*` and explicit `Option` propagation.
- Entry-point belt-and-braces: each `GlobalAlloc` method calls a private `extern "C" fn` trampoline. Since **Rust 1.81 an unwind out of `extern "C"` aborts** [V, releases.rs 1.81]. The panic hook still runs first and may allocate, so this is a last resort that turns UB into abort, possibly after a reentrant deadlock. The primary defense is still "no panics". Also build OxiBelt with `panic = "abort"`.
- `handle_alloc_error` / OOM: return null and let std abort. Don't print from the allocator.
- `debug_assert!` inside the allocator is a panic. Use a `cfg(debug_assertions)` hard abort (`std::process::abort()` or `core::intrinsics::abort` equivalent) with no formatting.

### 2.4 Lazy global init without `std::sync::Once`
- `Once`/`OnceLock` are futex-based on Linux and in practice don't allocate [U], but the docs don't guarantee it. Use your own atomics:
  - `static STATE: AtomicU8` (0 = uninit, 1 = initializing, 2 = ready, 3 = failed) plus `static BASE: AtomicPtr<u8>`.
  - Winner: `compare_exchange(0, 1, Acquire, Acquire)`, do the mmap, `BASE.store(p, Release)`, `STATE.store(2, Release)`.
  - Losers spin with `core::hint::spin_loop()` while `STATE.load(Acquire) == 1`. Alternatively every racer mmaps and `BASE.compare_exchange(null, mine)` publishes one, and the losers `munmap` their own (unsafe, but a trivially-proven contract). No spin, better for signal context.
  - Storing the base pointer in `AtomicPtr` (not `AtomicUsize`) **preserves provenance**.
- Don't call the allocator from signal handlers, and document that. A handler that interrupts a spin in the same thread deadlocks.

### 2.5 fork safety
- The child has only the forking thread. Other threads' TLS caches are simply leaked in the child, which is acceptable. Any **allocator lock held by another thread at fork time stays locked forever** in the child.
  - A lock-free design (atomics and CAS only, no spin-locks that are held across non-trivial work) is inherently fork-safe.
  - If you do use locks, you need `pthread_atfork(prepare=lock_all, parent=unlock_all, child=reinit)` through `libc` (unsafe `extern`, one `unsafe` block). rustix has no atfork [V absent].
- Rust's `std::process::Command` uses `posix_spawn` or fork+exec, and the child does no allocation [U]. OxiBelt probably doesn't fork outside daemonization. Still make it safe.
- **Randomness after fork:** a child inherits the parent's per-process secret (canaries, free-list XOR keys, randomization seed). To detect fork cheaply, keep a "fork epoch" word in a page `madvise(MADV_WIPEONFORK)`'d (rustix `Advice::LinuxWipeOnFork` [V], Linux ≥4.14 [U]). If you see 0 in the child, reseed with getrandom. This is the same technique OpenSSL and the kernel's vDSO getrandom use [U].
- rseq: registration survives fork in the child thread [U]. That's not relevant if you don't use rseq.

---

## 3. Soundness: `&'static [AtomicU64]` over mmap memory, and provenance

### 3.1 Creating the atomic view
`core::slice::from_raw_parts::<AtomicU64>(p, n)` → `&'static [AtomicU64]` is sound when:
1. `p` is non-null and aligned to 8, which page alignment covers.
2. `n * 8 <= isize::MAX`, and the range lies inside one live mapping obtained from mmap with `PROT_READ|PROT_WRITE`.
3. The bytes are initialized. A fresh anonymous mapping is zero-filled, and `AtomicU64` has the same in-memory representation as `u64` (docs), so all-zero is valid.
4. The memory stays valid for `'static`: **never** `munmap`, never `mprotect` below RW, never `MADV_DONTNEED`/`FREE`/`REMOVE`. For DONTNEED the result would still read as zero, but the kernel would be "writing" concurrently with Rust atomics outside the memory model. Don't do it.
5. No other live view of those bytes is non-atomic or `&mut`. `AtomicU64` contains an `UnsafeCell`, so mutation through `&` is fine. What's forbidden is mixing with `&mut [u64]`/`&[u64]` or plain loads through raw pointers.
6. `cfg(target_has_atomic = "64")`, which holds on x86_64/aarch64.

This logic should be a single `unsafe` block in the sys crate behind a **safe** API that consumes an owning token (`MetaRange`). A second view of the same bytes can't be created, and the backing mapping is `'static` by construction (never unmapped: the `Mapping` type has no `Drop` and no safe unmap).

Miri runs this fine using its mmap shim (anonymous RW) [V shim exists; U that it zero-initializes, though it should, since mmap semantics require it].

### 3.2 Pointer provenance for user allocations
Std docs [V] say you should keep "a pointer that has sufficient provenance" and derive from it with `with_addr`/`map_addr`/offset. Exposed provenance (`with_exposed_provenance`) is a last resort: it "cannot provide any guarantees about which provenance the resulting pointer will have", and it works poorly with Miri and CHERI.

- **Sound approach:** `base: NonNull<u8>` from mmap is the *root* provenance for the whole mapping. Allocation pointer = `base.as_ptr().wrapping_add(offset)` (safe) or `base.map_addr(|a| a + offset)` / `base.add(offset)`. `add` is `unsafe` and requires in-bounds; `wrapping_add` is safe and fine as long as the result is in-bounds before use. **All of these are safe Rust except `add`**, so the forbid-unsafe logic crate can compute pointers itself: raw pointer creation and arithmetic are safe, only dereference is unsafe.
- `dealloc(ptr, layout)`: compute `offset = ptr.addr().wrapping_sub(base.addr())` and then only use integers for metadata lookup. Never re-derive a pointer from an integer. If you need a pointer (for example for zeroing in `realloc`), use the pointer passed in, or `base.wrapping_add(offset)`.
- **Never** materialize `&mut [u8]` or `&[u8]` over the whole arena. Under Stacked/Tree Borrows that retags the region and invalidates or conflicts with user pointers. Operate on raw pointers only. `copy_nonoverlapping`/`write_bytes` take raw pointers.
- Does Miri treat a sub-range of one mmap as "one allocation"? Yes. The shim registers the whole mapping as one Miri allocation, so `base.add(off)` in-bounds checks against the mapping [U, inferred from the shim design]. Run the logic under Miri with `-Zmiri-strict-provenance` (rejects int→ptr) and Tree Borrows (`-Zmiri-tree-borrows`).
- Metadata that stores "pointers" should store **offsets (u32/u64)**, not addresses. That keeps everything strict-provenance-clean and halves the metadata footprint.

---

## 4. Hardware acceleration from safe Rust

### 4.1 Bit scanning
- `u64::trailing_zeros` → LLVM `cttz`. Without BMI1, x86 emits `rep bsf` plus a **branch for the zero case** (LLVM issue #122004 [V]). With BMI1 it's a single `tzcnt`.
- **x86-64-v3 includes BMI1, BMI2, LZCNT, POPCNT (from v2), AVX2 and MOVBE** [V, Wikipedia level table]. Build OxiBelt with `-C target-cpu=x86-64-v3` if deployment targets are Haswell+/Zen+, or use `NonZeroU64::trailing_zeros()`, which LLVM lowers to `cttz(x, zero_undef=true)`: a branch-free `bsf` even on baseline x86-64 [U, standard LLVM behavior]. The allocator almost always knows the word is non-zero after a `!= 0` check, so this is the portable win.
- `count_ones` → `popcnt` only with the feature enabled (v2+). Otherwise it's a bit-twiddling sequence.
- aarch64: `rbit` + `clz` for tzcnt, always available. `cnt` for popcount uses NEON (base).

### 4.2 SIMD scanning (AVX2 / AVX-512)
- target_feature 1.1 is stable since **Rust 1.86** [V]. A safe `#[target_feature(enable = "avx2")] fn` can be called safely only from contexts that have the feature. Since **Rust 1.87**, "most `std::arch` intrinsics that are unsafe only due to requiring target features … are now callable in safe code that has those features enabled" [V]. For example `_mm256_cmpeq_epi64` is a plain `pub fn` [V].
- In a `forbid(unsafe_code)` crate you can therefore use AVX2 only when (a) the feature is enabled crate-wide via `-C target-feature`/`target-cpu`, where the calls are safe [U: RFC 2396 says a call is safe when the caller's feature set includes the callee's, and globally-enabled features count], or (b) runtime dispatch `is_x86_feature_detected!` + calling a `#[target_feature]` fn, which **requires `unsafe`** at the call and would have to live in the sys crate.
- **Soundness hurdle:** SIMD loads of `AtomicU64` bitmaps that other threads mutate are *non-atomic reads racing with atomic writes*, which is UB in the Rust/C++ memory model. You'd also need `_mm256_loadu_si256`, a pointer-deref intrinsic that stays `unsafe`. So SIMD is only applicable to **thread-owned (non-shared) bitmaps**, and with 64-bit bitmap words plus a summary word, one `tzcnt` per level already beats SIMD. **Recommendation: don't use SIMD for bitmap search.** Use a two-level (or three-level) bitmap: summary word → leaf word → `trailing_zeros`.
- AVX-512 has frequency-license/throttling concerns on older Intel [U]. Not worth it here.

### 4.3 Prefetch
- `core::arch::x86_64::_mm_prefetch(p: *const i8, STRATEGY)` is a **safe fn** (SSE, baseline on x86_64) [V]. The docs say it "cannot change the behavior of the program, including not trapping on invalid pointers". So it can be used from the forbid-unsafe crate on x86_64, for example to prefetch the next free-list node. aarch64 has no stable safe equivalent [U]. Benchmark before using it, since it's often neutral.

### 4.4 Per-CPU data: rseq and sched_getcpu
- Kernel rseq [V] exposes `cpu_id_start`, `cpu_id`, `node_id` and `mm_cid` (the last is best for per-CPU caches with dense IDs, Linux ≥6.3 [U]) and supports critical sections that restart on preemption. Newer kernels add slice extension (`PR_RSEQ_SLICE_EXTENSION`) [V].
- **glibc ≥2.35 registers rseq for every thread** and exports `__rseq_offset`, `__rseq_size` and `__rseq_flags` [V]. Only one registration per thread is possible, so a library must *use* glibc's area (thread pointer + `__rseq_offset`) instead of registering its own, unless `GLIBC_TUNABLES=glibc.pthread.rseq=0`. **musl doesn't register**, so you'd register yourself [U].
- Reading `cpu_id` needs the thread pointer (`asm!` for `fs`/`tpidr_el0`) and a raw read. Real per-CPU operations need hand-written `asm!` critical sections with abort handlers. That's inherently unsafe and complex.
- Crates: `rseq-rs` (botirkhaltaev) offers "safe Linux restartable-sequence word ops", with a PR to self-register when glibc didn't [V exists; U maturity/audit]. `rsmalloc` is an experimental RSEQ allocator [V exists]. Both are young, so treat them as reference, not dependencies.
- `sched_getcpu`: the vDSO call is a few ns (RDPID/RDTSCP/LSL on x86) [U], but it's only a hint: the thread may migrate right after. rustix's version goes through vDSO init and auxv (section 1.3 hazard).
- **Recommendation:** v1 uses per-thread caches (TLS, the section 2.2 design). That gives most of the benefit with zero unsafe. Revisit rseq with `mm_cid` only if benchmarks show thread-count ≫ core-count cache bloat, which Tokio's fixed worker pool makes unlikely.

### 4.5 Intel MPK (`pkey_mprotect`) [V, pkeys(7)]
- Offers 15 usable keys. PKRU is per-thread, and "Threads inherit the protection key rights of the parent at the time of the clone(2) system call". Signal handlers get a default PKRU.
- "WRPKRU is a completely unprivileged instruction, so pkeys are useless in any case that an attacker controls the PKRU register or can execute arbitrary instructions". It protects against *stray writes* (data-only corruption), not code execution.
- For allocator metadata you'd have to toggle PKRU (WRPKRU ≈ tens of cycles, serializing [U]) on every metadata write, which means every alloc/free. That's too expensive for a proxy fast path, and it needs `asm!` (WRPKRU/RDPKRU intrinsics `_wrpkru`/`_rdpkru` are unstable [U]) plus `libc::pkey_*`, since rustix lacks them.
- **Recommendation:** skip it. Cheaper alternatives: guard pages (PROT_NONE) around the metadata region, and keep metadata out-of-line from user data (which the design already does). Offer MPK later as an opt-in debug/hardened build.

### 4.6 ARM64 MTE [V, kernel MTE doc]
- Enable per thread with `prctl(PR_SET_TAGGED_ADDR_CTRL, PR_TAGGED_ADDR_ENABLE | PR_MTE_TCF_SYNC|ASYNC | (mask << PR_MTE_TAG_SHIFT))`. Memory must be mapped or mprotected with `PROT_MTE`, which works only on anonymous and RAM-backed mappings and can't be removed later. Tags start at 0 and are inherited across fork.
- Rust status: MTE intrinsics (`__arm_mte_create_random_tag`, `__arm_mte_set_tag`, `__arm_mte_get_tag`, …) are **unstable** (`stdarch_aarch64_mte`) [V], and setting tags (STG) is `unsafe` (pointer writes). rustix has `thread::set_current_tagged_address_mode` [V], and `ProtFlags::MTE` [V].
- Provenance: tagged pointers are exactly what `map_addr` is for. The tag lives in bits 56-59, and `ptr.map_addr(|a| (a & !TAG_MASK) | tag << 56)` keeps provenance.
- MTE is valuable for UAF/overflow detection (retag on free), but it's aarch64-only, needs MTE-capable hardware (e.g. Pixel 8+, AmpereOne; AWS Graviton reportedly lacks MTE [U]), and needs nightly or `asm!`. **Recommendation:** out of scope for v1. Design the pointer-derivation layer through `map_addr` so tagging can be slotted in later.

### 4.7 RDRAND vs getrandom
- `_rdrand64_step(&mut u64) -> i32` is a **safe fn** under `rdrand` target_feature [V]. It still needs a target_feature context or runtime detection (unsafe call), and RDRAND is **not in x86-64-v3** [V table], so you need runtime detection.
- Known failures: AMD family 15h/16h return `0xFFFF…` with CF=1 after suspend, and Zen2 had early-boot failures before a 2019 microcode fix [V, LinuxReviews/LKML]. It's also slow (hundreds of cycles) [U].
- **Recommendation:** at init (and at fork-epoch change), make one `rustix::rand::getrandom(&mut [u8; 32], GetRandomFlags::empty())` call. It's safe and doesn't allocate. If it fails (`ENOSYS` in a very old seccomp sandbox), fall back to mixing ASLR addresses and a cycle counter (no crypto requirement, since this is only for randomization and hardening). Then use a per-thread non-cryptographic PRNG (for example wyrand, xorshift128+) seeded from it for slot randomization. Don't use RDRAND.

---

## 5. Proposed minimal unsafe surface (`oxibelt-alloc-sys`)

Crate attributes: `#![no_std]`, `#![deny(unsafe_op_in_unsafe_fn)]`, `#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, clippy::missing_safety_doc)]`. Every `unsafe {}` holds exactly one unsafe operation with a `// SAFETY:` comment. Target: **≤ 10 unsafe blocks** total.

```rust
/// A private anonymous mapping that is never unmapped (no Drop, no safe unmap).
/// Invariant: [base, base+len) is a live mapping for 'static; base is page aligned.
pub struct Mapping { base: NonNull<u8>, len: usize }   // !Clone, Send + Sync

pub enum Prot { None, ReadWrite }

/// Reserve address space. Safe: we pass ptr = null, so rustix's SAFETY precondition is vacuous.
pub fn reserve(len: usize, prot: Prot) -> Option<&'static Mapping>;
//   unsafe #1: rustix::mm::mmap_anonymous(null_mut(), len, prot, PRIVATE|NORESERVE)
//   SAFETY: ptr is null; the kernel chooses a fresh range that aliases nothing.
//   The returned &'static Mapping is placed in a fixed-size static table of AtomicPtrs, no heap.

impl Mapping {
    pub fn base(&self) -> NonNull<u8>;          // safe: root provenance for derivations
    pub fn len(&self) -> usize;

    /// Commit [off, off+len) as RW. Safe: raising permissions can't invalidate any reference.
    pub fn commit(&self, off: usize, len: usize) -> Result<(), Errno>;
    //   unsafe #2: rustix::mm::mprotect(base.wrapping_add(off), len, READ|WRITE)
    //   SAFETY: range checked ⊆ mapping and page aligned; only adds permissions.

    /// Split off a metadata range and view it as atomics. Consumes the token, so it can be called only once per range.
    pub fn atomics(&'static self, r: MetaRange) -> &'static [AtomicU64];
    //   unsafe #3: slice::from_raw_parts(base.wrapping_add(r.off).cast(), r.words)
    //   SAFETY: (section 3.1 items 1-6) aligned, in-bounds, committed RW, zero-initialized (fresh
    //   anonymous memory, never purged), 'static (Mapping is never unmapped),
    //   MetaRange is unique and disjoint from all user-data ranges by construction.
}

/// Hand back physical memory for a range that holds no live allocation.
/// # Safety
/// - [ptr, ptr+len) lies within one `Mapping`, is page aligned, and is outside every MetaRange.
/// - No live allocation, reference, or concurrent access overlaps the range until it is
///   re-handed-out. After `Purge::Free` the contents are indeterminate (old or zero);
///   after `Purge::DontNeed` they read as zero.
pub unsafe fn purge(ptr: NonNull<u8>, len: usize, how: Purge) -> Result<(), Errno>;
//   unsafe #4: rustix::mm::madvise(...)

/// Advisory, contents-preserving hints (DONTDUMP, HUGEPAGE, NOHUGEPAGE, WIPEONFORK on a
/// sys-owned page). Safe because it takes &Mapping plus a checked range, and these advices never change
/// contents (WIPEONFORK only affects the child, and only on the sys-owned epoch page).
pub fn advise(m: &Mapping, off: usize, len: usize, a: Hint) -> Result<(), Errno>;
//   unsafe #5

/// Copy for realloc.
/// # Safety: src valid for reads of n, dst valid for writes of n, both from live allocations
/// handed out by this allocator, non-overlapping.
pub unsafe fn copy(dst: NonNull<u8>, src: NonNull<u8>, n: usize);       // unsafe #6
/// Zero for alloc_zeroed on recycled memory.
/// # Safety: dst valid for writes of n and not concurrently accessed.
pub unsafe fn zero(dst: NonNull<u8>, n: usize);                          // unsafe #7

/// Seed bytes. Safe wrapper over rustix::rand::getrandom (safe, no unsafe needed).
pub fn seed() -> Option<[u8; 32]>;

/// Fork epoch word on a WIPEONFORK page; reads 0 in a child after fork.
pub fn fork_epoch() -> &'static AtomicU64;   // built from reserve + advise + atomics

/// Emergency stop without formatting or allocating.
pub fn abort() -> !;   // std::process::abort, or rustix::runtime exit if no_std [U]
```

The GlobalAlloc shim (in the sys crate, or a 3rd tiny `oxibelt-alloc` crate) is the only other unsafe code:

```rust
pub struct OxiAlloc;
// SAFETY: (1) never unwinds, because every method forwards to a no-panic logic fn through an
// extern "C" trampoline that aborts on unwind; (2) returned blocks satisfy `layout` (size/align),
// are disjoint from every other live block, and stay valid until dealloc (logic-crate invariant,
// proptest + Miri + loom tested); (3) never calls the global allocator reentrantly (core-only
// logic, const !Drop TLS, rustix mm/rand only).
unsafe impl GlobalAlloc for OxiAlloc {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 { logic::alloc(l).map_or(null_mut(), NonNull::as_ptr) }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) { logic::dealloc(p, l) } // address-only use
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 { /* logic says if zero-known; else sys::zero */ }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 { /* in-place or alloc+sys::copy+dealloc */ }
}
```

The logic crate (`#![no_std]`, `#![forbid(unsafe_code)]`) receives `&'static [AtomicU64]` and `NonNull<u8>` bases. It computes pointers only with `wrapping_add`/`map_addr` and addresses with `.addr()`, and it never dereferences user memory.

Notes:
- Where `#[global_allocator] static A: OxiAlloc = OxiAlloc;` goes: put it in the OxiBelt binary or the shim crate. I haven't checked whether the builtin macro expansion trips `forbid(unsafe_code)` in the crate that contains it [U], so don't put it in the logic crate.
- Optional, feature-gated extras if later phases need them: `pthread_atfork` registration (libc, 1 block, only if locks exist), `rseq_cpu_id()` (asm, 2 blocks), `pkey_mprotect` (libc, 1 block), MTE tag ops (asm).

## 6. Testing implications
- Miri: the sys crate needs `cfg(miri)` paths (plain RW mmap, no NORESERVE, madvise/mprotect as no-ops). rustix auto-selects libc under Miri [V]. Run with `-Zmiri-strict-provenance -Zmiri-tree-borrows`.
- loom/shuttle for the atomic protocols in the logic crate. Loom needs its own atomic types, so abstract `AtomicU64` behind a type alias.
- A CI grep or deny-list stops the sys crate from importing `rustix::param`, `rustix::time`, `rustix::thread::sched_getcpu` or `std::sync`.

---

## Sources
- rustix mm module (1.1.5): https://docs.rs/rustix/latest/rustix/mm/index.html
- rustix `mmap_anonymous`: https://docs.rs/rustix/latest/rustix/mm/fn.mmap_anonymous.html
- rustix `madvise`: https://docs.rs/rustix/latest/rustix/mm/fn.madvise.html
- rustix `getrandom`: https://docs.rs/rustix/latest/rustix/rand/fn.getrandom.html
- rustix all items: https://docs.rs/rustix/latest/rustix/all.html
- rustix README: https://github.com/bytecodealliance/rustix
- rustix build.rs (backend and Miri selection): https://raw.githubusercontent.com/bytecodealliance/rustix/main/build.rs
- rustix Cargo.toml (features, use-libc-auxv): https://raw.githubusercontent.com/bytecodealliance/rustix/main/Cargo.toml
- rustix auxv init (allocation/unwrap hazard): https://raw.githubusercontent.com/bytecodealliance/rustix/main/src/backend/linux_raw/param/auxv.rs
- rustix vDSO getcpu: https://raw.githubusercontent.com/bytecodealliance/rustix/main/src/backend/linux_raw/vdso_wrappers.rs
- rustix mm types (Advice/MapFlags): https://raw.githubusercontent.com/bytecodealliance/rustix/main/src/backend/linux_raw/mm/types.rs
- GHSA-c827-hfw6-qwvm / CVE-2024-43806: https://github.com/advisories/GHSA-c827-hfw6-qwvm
- Wasmtime cargo-vet audits/trust: https://raw.githubusercontent.com/bytecodealliance/wasmtime/main/supply-chain/audits.toml
- Google rust-crate-audits: https://raw.githubusercontent.com/google/rust-crate-audits/main/audits.toml
- madvise(2): https://man7.org/linux/man-pages/man2/madvise.2.html
- Overcommit accounting: https://docs.kernel.org/mm/overcommit-accounting.html
- GlobalAlloc docs: https://doc.rust-lang.org/std/alloc/trait.GlobalAlloc.html
- thread_local! docs: https://doc.rust-lang.org/std/macro.thread_local.html
- LocalKey docs: https://doc.rust-lang.org/std/thread/struct.LocalKey.html
- std native TLS impl: https://doc.rust-lang.org/src/std/sys/thread_local/native/mod.rs.html
- rust-lang/rust#160930 (TLS reentrancy): https://github.com/rust-lang/rust/issues/160930
- rust-lang/rust#147342 (needs_drop TLS guarantees): https://github.com/rust-lang/rust/issues/147342
- Rust 1.81 changelog (extern "C" abort on unwind): https://releases.rs/docs/1.81.0/
- std::ptr provenance docs: https://doc.rust-lang.org/std/ptr/index.html
- Miri mmap shims PR #2520: https://github.com/rust-lang/miri/pull/2520
- Rust 1.86 (target_feature 1.1): https://blog.rust-lang.org/2025/04/03/Rust-1.86.0/
- RFC 2396 target_feature 1.1: https://rust-lang.github.io/rfcs/2396-target-feature-1.1.html
- Rust 1.87 (safe arch intrinsics): https://blog.rust-lang.org/2025/05/15/Rust-1.87.0/
- `_mm_prefetch`: https://doc.rust-lang.org/stable/core/arch/x86_64/fn._mm_prefetch.html
- `_rdrand64_step`: https://doc.rust-lang.org/stable/core/arch/x86_64/fn._rdrand64_step.html
- `_mm256_cmpeq_epi64`: https://doc.rust-lang.org/stable/core/arch/x86_64/fn._mm256_cmpeq_epi64.html
- LLVM cttz without BMI1 (#122004): https://github.com/llvm/llvm-project/issues/122004
- x86-64 microarchitecture levels: https://en.wikipedia.org/wiki/X86-64
- Kernel rseq: https://docs.kernel.org/userspace-api/rseq.html
- glibc rseq (RHEL article): https://developers.redhat.com/articles/2022/12/22/restartable-sequences-support-glibc-rhel-9
- LWN glibc rseq: https://lwn.net/Articles/883104/
- rseq-rs: https://github.com/botirkhaltaev/rseq-rs
- rsmalloc: https://github.com/Metehan120/rsmalloc
- pkeys(7): https://man7.org/linux/man-pages/man7/pkeys.7.html
- Kernel MTE doc: https://docs.kernel.org/arch/arm64/memory-tagging-extension.html
- Rust MTE intrinsics (unstable): https://doc.rust-lang.org/nightly/core/arch/aarch64/fn.__arm_mte_get_tag.html
- RDRAND AMD bug: https://linuxreviews.org/RDRAND_stops_returning_random_values_on_older_AMD_CPUs_after_suspend
- LKML AMD RDRAND CPUID clear: https://lkml.iu.edu/hypermail/linux/kernel/1908.2/02344.html
