# Benchmarks (prototype)

- **Environment:** Intel Xeon E5-2630 v4 @ 2.20GHz, 36 logical CPUs, 128 GB, Linux 7.0.0, rustc 1.98.1, `--release` (no target-cpu tuning).
- **Build flags since the platform contract:** `.cargo/config.toml` now builds every x86_64 target with `-C target-cpu=x86-64-v3` ([docs/platform.md](../platform.md)), so the command below no longer reproduces the generic x86-64 build measured here. The results have not been re-measured with v3. The E5-2630 v4 (Broadwell) has AVX2, BMI1/2, FMA, LZCNT and MOVBE, so it can run v3 builds; record the build flags with every new run.
- **Build and run:**
  ```sh
  cargo build --release -p allocatbelt-bench
  for b in system mimalloc allocatbelt; do ./target/release/bench-$b; done
  ```
- **Code:** workloads are in [`bench/src/lib.rs`](../../bench/src/lib.rs). Each binary sets a different `#[global_allocator]`:
  - `system`: glibc malloc
  - `mimalloc`: the `mimalloc` 0.1.52 crate with `features = ["secure"]`, the same configuration as OxiBelt's current one
  - `allocatbelt`: this repository
- **Profiling:** `scripts/profile.sh` records resource use over a run and per-function CPU and page-fault profiles of these binaries ([profiling.md](profiling.md)). Each workload line now also prints its CPU time, page faults and storage bytes; the tables below predate those columns.
- **Workloads:** size distribution is 70% 16–256 B, 25% 256 B–4 KiB, 4% 4–64 KiB, 1% 64 KiB–1 MiB, mimicking a proxy's small buffers plus occasional bodies.
  1. single-thread churn: 2M alloc/free, 1000-slot live window
  2. 16-thread local churn: 16 threads each doing 1M ops
  3. 8 producer/consumer pairs: allocate on one thread and free on another (cross-thread free), 64 objects × 20k batches

## Results (3 runs, median; ms; lower is better)

| Workload | system (glibc) | mimalloc-secure | allocatbelt |
|---|---:|---:|---:|
| single-thread churn 2M | 227 | 272 | 223 |
| 16-thread local churn | **203** | 230 | 285 |
| 8 producer/consumer pairs | 1299 | 383 | **209** |
| VmHWM (peak RSS) | 140–145 MB | 822–854 MB | **73–75 MB** |
| VmRSS at exit | 22–24 MB | 822–854 MB | 64–66 MB |

Raw runs (ms): allocatbelt 214/223/245, 275/285/310, 194/209/265 · mimalloc 257/272/300, 220/230/237, 374/383/390 · system 190/227/264, 188/203/225, 1296/1299/1309.

## Purge policy experiment (16-thread local churn, allocatbelt)

| Policy | Time | VmRSS |
|---|---:|---:|
| Immediate `madvise(DONTNEED)` on large (≥256 KiB) frees and empty pages | 453–482 ms | 52 MB |
| No purge at all | 218–244 ms | 69 MB |
| **Deferred purge, budget 512 pages (32 MiB), the adopted setting** | 275–310 ms | 49–51 MB |
| Deferred purge, budget 2048 pages | 269–298 ms | 65–66 MB |
| Deferred purge, budget 128 pages | 318–339 ms | 47–48 MB |

`madvise` takes `mmap_lock` and causes TLB shootdowns (IPIs) across all threads, so calling it on every free was the bottleneck. perf could not be used in this environment (`perf_event_paranoid`), so the cause was confirmed by the controlled experiment above.

## Caveats (interpreting the numbers)

- These are **microbenchmarks**. They are no substitute for measuring OxiBelt's real traffic (TLS, HTTP/2, tokio work-stealing).
- The high RSS for mimalloc-secure is probably a combination of mimalloc's default purge delay and arena retention, secure mode's guard pages, and the 1 MiB-class allocations in the workload. No mimalloc options (`MIMALLOC_PURGE_DELAY`, etc.) were tuned. The comparison is only between default configurations, so it should not be read as "mimalloc uses more memory in general".
- Only one byte of each allocation is written, so RSS is closer to allocator metadata and page-retention policy than to real usage.
- For allocatbelt, **16-thread local churn** being slower than glibc/mimalloc comes from two atomic RMWs for the shard lock on every allocation, plus the large (> 8 KiB) path doing a segment scan. The fixes are the per-thread heap and summary bitmap in the research summary (README §3).

## Follow-up changes (second machine)

- **Environment:** Intel Xeon @ 2.80GHz, 4 vCPUs (shared VM), Linux 6.18, rustc 1.94.1 (`--ignore-rust-version`), `--release`. With 4 CPUs the benchmark runs 4 churn threads and 2 producer/consumer pairs. Run-to-run noise on this VM is ±10%, so each cell is the median of 5 alternating runs.
- **before** = commit `0271678` (the prototype above); **after** = this branch with the follow-ups: known-zero `calloc`, aligned page runs, tightest aligned class, empty page/segment return on purge passes, in-place `realloc`.

| Workload | system (glibc) | mimalloc-secure | allocatbelt before | allocatbelt after |
|---|---:|---:|---:|---:|
| single-thread churn 2M | 159 | 663 | 110 | 112 |
| 4-thread local churn | 136 | 372 | 171 | 170 |
| 2 producer/consumer pairs | 865 | 282 | 122 | 119 |
| VmHWM (peak RSS) | 47 MB | 290 MB | 22 MB | 23 MB |
| VmRSS at exit | 19 MB | 41–259 MB | 22 MB | 19 MB |

The mixed workloads are unchanged within noise (total CPU time of a full run: 1.10 s before, 1.15 s after, medians of 8). The follow-ups target cases the workloads above do not exercise:

| Case | before | after |
|---|---:|---:|
| `vec![0u8; 1 << 30]` (`alloc_zeroed`) | 2.7–3.9 s, RSS +1025 MiB | 0.9–1.4 ms, RSS +1 MiB |
| `Vec<u8>` grown to 512 MiB by 4 KiB pushes | 530–570 ms, 17 moves | 215–270 ms, 4–5 moves |
| slowest single growth in that loop | 160–210 ms | 2–3 ms |
| 100 B aligned to 128 KiB, usable size | 4 MiB (a whole segment) | 64 KiB (one page) |
| 5000 B aligned to 32, usable size | 8192 | 5120 |
| segments held after freeing 20M 16-byte boxes and purging | 77 | 3 |

### Negative result: medium size classes (8–256 KiB)

Requests above 8 KiB take whole 64 KiB pages, so a 9 KiB block has 64 KiB of usable size. Size classes continuing to 256 KiB, carved from 1–8 page spans, were tried and reverted. Single thread, 1000 live objects, before → spans:

| Band | 1 byte written per block | whole block written |
|---|---|---|
| 4–64 KiB, 200k ops | 30 → 93 ms, RSS 7 → 21 MiB | 635 → 714 ms, RSS 34 → 50 MiB |
| 64 KiB–1 MiB, 50k ops | 105 → 120 ms, RSS 8 → 27 MiB | 5.3 → 5.4 s, RSS 21 → 93 MiB |

With 4 KiB OS pages, the unused tail of a 64 KiB page costs address space but not RSS, and a freed page run is purged on its own. Packed spans instead keep freed blocks resident until the whole span is free, and spans of 2–6 blocks are refilled far more often than small pages. The internal fragmentation would matter on 64 KiB-page kernels (some aarch64 distributions); that case was not measured.

### Segment return: aging

Returning every empty segment on each budget-triggered purge pass made a 64 KiB–1 MiB churn decommit and recommit segments repeatedly (`mprotect` calls 343 → 650, about 10% slower). A segment now goes back only if it is still empty at the pass after the one that found it empty (`mprotect` 542, same speed as before), and each shard keeps one empty segment.

## Third round: per-thread caches, summaries, decay, hardening (2026-09-28)

- **Environment:** the 4-vCPU VM of the second round (Intel Xeon @ 2.80GHz, shared, Linux 6.18), rustc 1.98.1, `--release`. 4 churn threads, 2 producer/consumer pairs. Run-to-run noise on this VM is ±10–15%, so each cell is the median of 10 alternating runs of all four binaries.
- **before** = `9a0ad1e`: the code after the second round, with the bench changes below. **after** = this branch, with randomized placement and guard pages on (the defaults), and `bench-allocatbelt` starting the purge thread (`Allocatbelt::start_purge_thread`), the recommended setup.
- **Bench changes:** a small-object-only workload (`4-thread small churn`: 16–256 B boxes, 4M operations per thread), and an **idle** row: VmRSS after the workloads and 3 s without allocator calls, i.e. what a server keeps between bursts.

| Workload (ms / MB, median) | system (glibc) | mimalloc-secure | allocatbelt before | allocatbelt after |
|---|---:|---:|---:|---:|
| single-thread churn 2M | 228 | 829 | 162 | 176 |
| 4-thread local churn | 152 | 583 | 238 | 217 |
| 4-thread small churn | 214 | 441 | 299 | 284 |
| 2 producer/consumer pairs | 1565 | 446 | 229 | 211 |
| VmHWM (peak RSS) | 47 | 280 | 23 | 24 |
| VmRSS at the end | 18 | 41 | 23 | 24 |
| **VmRSS after 3 s idle** | 18 | 41 | 23 | **6** |

- **Throughput.**
  - The multi-threaded workloads are 5–10% faster.
  - Single-thread churn is within noise. Its minimums are equal (155 vs 156 ms), and a separate run of that workload alone gave 164 ms before vs. 159 after (159 with randomization off, 168 without the purge thread).
  - On this VM each thread has its own shard, so the shard lock the caches take off the fast path was never contended. The gain should be larger with more threads than shards per core, which a 4-vCPU VM cannot show.
- **Idle RSS.** The purge thread returns freed memory within about a second of the last free, so the idle process keeps 6 MB instead of the 23 MB high-water mark. Without the thread, a process that stops allocating keeps its freed memory until the next allocation slow path (or the 32 MiB budget) triggers a pass. glibc and mimalloc keep theirs too.
- **Development measurements** (single-thread, 20M random 16–256 B alloc/free pairs, before → after unless noted):
  - The first per-thread cache was ~8% *slower*. Profiling (callgrind on a build with a smaller arena) found three causes: a scan of all 64 buffer slots on every refill, a division per free, and register spills in one large inlined free path. The fixes were a per-class slot mask with flush-before-new-page, a per-class reciprocal (`class::block_index`), and a slim inline fast path with out-of-line slow paths. After them it was at parity (1235 vs 1215 ms median).
  - Frees reach the bitmap at one `fetch_or` per ~2.3 frees under random frees. Refills claim a word every ~13 allocations (1.56M refills for 20M allocations).
  - A first time-based decay read the clock on every page-run free (`Instant::now` costs 28 ns here) and cost ~12% on mixed churn (152 → 170 ms). Stamping pages with a decay-pass epoch instead, and sampling the clock every 16th slow path per thread, brought it back to 157 vs 157 ms.
- **Segment return.** Budget passes no longer return empty segments by the two-pass rule of the second round; segments go back once they have been empty for the purge delay, or on an explicit `purge()`.

## Lock contention: `sched_yield` vs futex (plan Phase 6, 2026-09-28)

The heap's locks used to spin 64 times and then call `sched_yield` in a loop. They now spin up to 100 times and then sleep on a futex (`FUTEX_WAIT`, process-private), and an unlock issues `FUTEX_WAKE` only when a thread may be asleep (the three-state futex mutex; `crates/allocatbelt-core/src/lock.rs`). An uncontended lock and unlock stays in user space: one compare-and-swap and one swap, where the old unlock was a plain store.

- **Environment:** a 4-vCPU shared VM (Intel Xeon @ 2.10 GHz), Linux 6.18.44, rustc 1.98.1, `--release`, x86-64-v3. No hardware counters. **yield** = `f374343` (before this change), **futex** = this change; both built with the same bench, run alternately.

### How often the heap waits at all

A local, uncommitted counter patch (as in Phase 5) counted entries into the lock's slow path during `bench-allocatbelt`. Per run of each workload: 0 in single-thread churn, small churn and producer/consumer, 0–1 in 4-thread local churn, and 2–4 (with up to 11 futex waits) in the new oversubscribed row below. Thread caches and shard probing (`with_shard` tries four shards before it waits) keep the heap's locks almost uncontended, so the change cannot move these workloads much either way; it matters when a waiter meets a holder that is off the CPU.

### The lock itself (`lock::tests::contention_benchmark`)

`cargo test --release -p allocatbelt-core --lib contention_benchmark -- --ignored --nocapture` runs the futex lock against a copy of the old `sched_yield` lock. Threads take one lock in a loop: 50 iterations of work inside, 200 outside. In the "holder blocks" rows, every 64th holder also sleeps 20 µs inside the lock, as a holder in `mprotect`/`madvise` (the shard lock is held across segment commits) or a preempted one would. Median of 7 runs:

| Scenario | Threads | Lock | Wall ms | CPU ms | CPU / wall |
|---|---:|---|---:|---:|---:|
| short hold | 4 | yield | 108.4 | 420.1 | 3.88 |
| short hold | 4 | futex | 87.5 | 313.2 | 3.58 |
| short hold, 4× threads | 16 | yield | 105.7 | 400.1 | 3.79 |
| short hold, 4× threads | 16 | futex | 90.9 | 357.0 | 3.93 |
| holder blocks 1/64 | 4 | yield | 131.8 | 373.4 | 2.83 |
| holder blocks 1/64 | 4 | futex | 135.2 | 60.6 | 0.45 |
| holder blocks 1/64, 4× threads | 16 | yield | 152.4 | 570.6 | 3.74 |
| holder blocks 1/64, 4× threads | 16 | futex | 136.2 | 57.3 | 0.42 |

- **When a holder blocks, `sched_yield` burns the machine.** Waiters of the old lock kept 3 to 4 CPUs busy re-checking the lock while the holder slept; the futex lock used 0.4 to 0.5 CPUs for the same work, 6 to 10 times less CPU, and the wall time was the same or better. In a server, that CPU belongs to the request, TLS and network threads.
- **Short holds:** the futex lock took 14 to 19% less wall time; the spin phase handles these and threads rarely sleep.

### Allocator workloads (`bench-allocatbelt`, gate B)

The bench has a new last row: the 4-thread local churn's work spread over 16 threads (4× the CPUs), so holders get preempted. 20 alternating runs of each binary; "paired" is the median of the per-pair ratios futex / yield, with its interquartile range.

| Workload | yield ms (median) | futex ms (median) | Paired ratio (IQR) |
|---|---:|---:|---|
| single-thread churn 2M | 136.8 | 143.6 | 1.01 (0.95–1.16) |
| 4-thread local churn | 185.4 | 182.1 | 1.02 (0.91–1.08) |
| 4-thread small churn | 279.5 | 273.8 | 0.98 (0.93–1.03) |
| 2 producer/consumer pairs | 111.7 | 109.9 | 0.92 (0.80–1.20) |
| 16-thread local churn (oversubscribed) | 166.9 | 164.2 | 0.99 (0.91–1.07) |

Peak RSS (23.8 vs 23.9 MB) and RSS after 3 s idle (6.4 vs 6.4 MB) did not change. Every paired median is within 2% except producer/consumer (8% faster, with a wide spread). The run-to-run spread on this VM is ±5–10%, so it can rule out a regression of that size but not one of 1–3%; the counts above say the slow path runs a handful of times per workload, and the only fast-path difference is the swap on unlock.

**Decision:** adopted. `sched_yield` is no longer the long-contention strategy (plan §11.1): `Os::yield_now` is replaced by `Os::futex_wait`/`Os::futex_wake`, which the adapter implements with rustix's safe futex calls (`allocatbelt_sys::futex_wait`/`futex_wake`, no new `unsafe`). The mock `Os` of the model tests yields instead, and loom checks the state machine with a futex emulation (`proto::loom_tests`). Still to measure: a many-core machine, where more threads share a shard, and OxiBelt under load.

## Maintenance thread (plan Phase 7, 2026-09-28)

Budget passes used to run on the free that took the dirty count over 32 MiB, and decay passes on allocation slow paths unless the purge thread was started (it then took only the decay passes). Now `Allocatbelt::start_maintenance_thread` hands all of them to one `SCHED_BATCH` thread (`Heap::maintain`, docs/research/README.md §4): a free over the budget only sets a bit and, on the transition, wakes the thread. `bench-allocatbelt` starts it and prints who ran the passes.

- **Environment:** as in the Phase 6 section (4 vCPUs, Linux 6.18.44, rustc 1.98.1, `--release`, x86-64-v3). **before** = `ff86374` (purge thread), **after** = this change (maintenance thread); 20 alternating runs of each binary; "paired" as before.

| Workload | before ms (median) | after ms (median) | Paired ratio (IQR) |
|---|---:|---:|---|
| single-thread churn 2M | 139.4 | 146.1 | 1.02 (0.90–1.23) |
| 4-thread local churn | 180.1 | 131.5 | 0.72 (0.68–0.74) |
| 4-thread small churn | 285.9 | 299.9 | 1.02 (0.96–1.08) |
| 2 producer/consumer pairs | 121.2 | 113.0 | 0.94 (0.72–1.12) |
| 16-thread local churn (oversubscribed) | 161.6 | 155.4 | 0.96 (0.88–1.06) |
| peak RSS (MB) | 23.6 | 22.4 | 0.92 (0.84–0.99) |
| RSS after 3 s idle (MB) | 6.4 | 6.3 | 0.99 (0.97–1.00) |

Who ran the passes after the change, over 5 runs of the whole bench: the maintenance thread 23 to 35 budget passes and 15 decay passes, allocating threads 5 to 10 budget passes and no decay pass, with 55 to 87 wake-ups. Before, every budget pass ran on an allocating thread.

- **The 4-thread local churn is 28% faster.** It is the workload that frees page runs fast enough to cross the budget about 20 times per run; those passes (92–95% `madvise`, see simd-benchmarks.md) no longer stall the freeing thread.
- **The other rows are within the VM's run-to-run spread** (±5–10%); single-thread and small churn never cross the budget, so the change cannot help them, and their medians moved by 2% in opposite directions across runs.
- **Inline passes remain only in the oversubscribed row.** With 16 busy threads on 4 CPUs, the batch thread gets little CPU, the dirty count passes the 64 MiB hard limit, and frees run the pass themselves, as designed. RSS stays bounded (peak 22.4 MB).
- **A missed request was found and fixed.** The first version let a free skip the wake-up because the bit was set, while the thread had just taken the bit and read an old dirty count. Both sides now fence (`proto::post_work`/`take_work`), and the loom model `maintenance_requests_are_not_lost` deadlocks without the fences.

**Decision:** adopted, with the synchronous backend kept. Phase 8 (io_uring) can change how a pass issues `madvise` without touching the scheduling. Still to measure: a many-core machine, and OxiBelt request latency with the thread on and off.

## io_uring purge ring (plan Phase 8, 2026-09-28)

A pass now hands the page runs it claims to a `Purger` in batches of up to 64 runs. After `Allocatbelt::set_io_uring(true)` the maintenance thread's purger is a restricted io_uring (docs/platform.md, "io_uring purge ring"): one `io_uring_enter` submits a batch of `IORING_OP_MADVISE(MADV_DONTNEED)` and waits for its completions. Without it, runs are purged with one `madvise` each, as before.

- **Environment:** as in the Phase 6 section; Linux 6.18.44, so `IORING_SETUP_SQ_REWIND` (Linux 7.0) is not available and every ring here used the SQ tail. CI's rust-checks jobs print the runner's kernel and the same microbenchmark (step "io_uring purge ring report"), including whether `SQ_REWIND` could be set up there.

### Purging 64 runs (`ring_benchmark`)

`cargo test --release -p allocatbelt-sys --lib ring_benchmark -- --ignored --nocapture`: each round writes 64 separate runs of 1, 4 or 16 pages (64 KiB each) and purges them; median of 41 rounds, µs per run.

| Pages per run | `madvise` per run | ring 64 slots, 1 worker | 2 workers | 4 workers | 32 slots | 128 slots |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 6.3 | 18.0–18.9 | 18.1 | 21.4 | 17.5 | 20.6 |
| 4 | 13.6 | 27.9–28.0 | 27.5 | 27.5 | 33.1 | 33.7 |
| 16 | 29.6 | 67.8–69.2 | 62.0 | 59.0 | 61.8 | 55.9 |

(Two rows of the 64-slot, 1-worker ring: with and without asking for `SQ_REWIND`, which this kernel refused.) The ring is 2 to 3 times slower per run at every depth and worker count. The kernel always punts `IORING_OP_MADVISE` to an io-wq worker thread (it cannot run without blocking), so each purge pays a hand-off and a wake-up that a direct `madvise` does not; the saved system calls are worth less than that. More workers purge the same address space in parallel and contend on it, so the adapter caps them at one.

### Allocator workloads (`bench-allocatbelt`)

20 alternating runs each of **Phase 7** (`70fcdd8`), **madvise** (this change, default) and **ring** (this change with `ALLOCATBELT_BENCH_IO_URING=1`); "cpu" is the process's user + system time, which includes the io-wq workers.

| Workload | Phase 7 | madvise | ring | madvise / Phase 7 (IQR) | ring / madvise (IQR) |
|---|---:|---:|---:|---|---|
| single-thread churn 2M (ms) | 135.8 | 142.2 | 142.2 | 1.00 (0.93–1.13) | 0.98 (0.83–1.09) |
| 4-thread local churn (ms) | 122.9 | 132.6 | 119.5 | 1.01 (0.97–1.19) | 0.94 (0.84–1.02) |
| 4-thread small churn (ms) | 273.3 | 272.5 | 265.2 | 0.99 (0.91–1.07) | 1.00 (0.93–1.12) |
| 2 producer/consumer pairs (ms) | 110.3 | 110.2 | 114.8 | 1.07 (0.77–1.28) | 1.10 (0.85–1.21) |
| 16-thread local churn, oversubscribed (ms) | 150.7 | 147.2 | 154.6 | 0.96 (0.93–1.04) | 1.03 (0.98–1.08) |
| peak RSS (MB) | 23.3 | 22.9 | 23.7 | 0.96 (0.86–1.06) | 1.05 (0.97–1.09) |
| RSS after 3 s idle (MB) | 6.3 | 6.3 | 6.9 | 1.00 (0.98–1.03) | 1.09 (1.05–1.12) |
| cpu (ms) | 2352.8 | 2379.2 | 2351.6 | 1.03 (0.98–1.05) | 0.99 (0.97–1.03) |

- **Batching without the ring changes nothing:** every madvise / Phase 7 ratio is within the VM's spread. `SyncPurger` still purges segment by segment, as before.
- **The ring does not win end to end either.** Every wall-time ratio's interquartile range includes 1, CPU time is equal, and idle RSS is 9% higher. The ring does batch: 6 to 10 runs per batch on average over three runs (for example 2,910 runs in 478 batches, counting the inline passes' per-segment batches too), against one `madvise` per run. But the purges already run on the maintenance thread since Phase 7, so the allocating threads never waited for them, and the batch's slower completion only keeps pages claimed a little longer.

**Decision:** the ring stays in, restricted and tested, but **off by default**; the plan asks for io_uring purging "where it wins", and it has not won here. Still to measure before turning it on: `SQ_REWIND` on a Linux 7.0 machine (the CI report shows whether a runner has it), a many-core machine where a direct `madvise`'s TLB shootdowns cost more, and OxiBelt under load.
