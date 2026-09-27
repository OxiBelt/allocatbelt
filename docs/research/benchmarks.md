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
