# Benchmarks (prototype)

- **Environment:** Intel Xeon E5-2630 v4 @ 2.20GHz, 36 logical CPUs, 128 GB, Linux 7.0.0, rustc 1.98.1, `--release` (no target-cpu tuning).
- **Build and run:**
  ```sh
  cargo build --release -p allocatbelt-bench
  for b in system mimalloc allocatbelt; do ./target/release/bench-$b; done
  ```
- **Code:** workloads are in [`bench/src/lib.rs`](../../bench/src/lib.rs). Each binary sets a different `#[global_allocator]`:
  - `system`: glibc malloc
  - `mimalloc`: the `mimalloc` 0.1.52 crate with `features = ["secure"]`, the same configuration as OxiBelt's current one
  - `allocatbelt`: this repository
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
