# SIMD candidate benchmarks (plan Phases 4 and 5)

Phase 4 of the Linux 7 / ISA / SIMD plan measures candidate kernels before any production path changes, and Phase 5 promotes the ones that pass the plan's gates (§15). This document describes the harness in `bench/simd`, records the measurements and the Phase 5 decision. **No kernel was promoted** ([Phase 5](#phase-5-promotion-decision-2026-09-28)): the allocator still runs only scalar code (`KernelSet::Baseline`), because none of the candidate operations is a measurable allocator cost.

## What is measured

One family per allocator operation. The inputs are what the allocator would pass: a local snapshot that a maintenance pass would take with individual atomic loads, or thread-owned bytes. No kernel reads shared `AtomicU64` metadata (plan §7.1).

| Family | Allocator operation (plan §7.2, §14) | Sizes |
|---|---|---|
| `nonzero` | `find_nonzero_local_words`: which words of a `seg_used` or dirty snapshot are non-zero, as a bitmask | 1, 4, 16, 64, 256 words |
| `popcount` | `reduce_local_masks`: total `count_ones` over a snapshot of several segments | 1, 4, 16, 64, 256 words |
| `age` | `Heap::purge_segment`: which candidate pages of a segment have been dirty long enough (`since[i] <= cutoff`) | 1, 8, 32, 64 candidates of 64 pages |
| `age-meta` | the same on the heap's metadata layout: each `since[i]` is an `AtomicU64` in page `i`'s record, 544 bytes apart, so a dense kernel first takes a snapshot with 64 atomic loads | as `age`, warm (one segment re-read) and cold (2048 segments cycled through) |
| `zero` | `alloc_zeroed` on a block not known to be zero | 16 B to 4 MiB |
| `copy` | `realloc` moving a block | 16 B to 4 MiB |

The sizes are the allocator's, not large arrays: 64 words is one segment's page records, 256 words is the arena's `seg_used`, 8 KiB is the small-object limit, 64 KiB a page and 4 MiB a segment.

Every family has these variants, each listed only when the running CPU supports it:

| Tier | Variants |
|---|---|
| scalar | `scalar` (one element at a time; `black_box` per element keeps LLVM from vectorizing it, at the cost of a compiler barrier per element, so it slightly overstates a naturally scalar loop). For `age`: `scalar-sparse`, today's `purge_segment` loop over the candidate bits with `trailing_zeros`, and `scalar-dense`, a compare per page. |
| autovec | The branchless loop the allocator would write, left to the compiler with the build's target features (x86-64-v3 here). On riscv64 built with `-C target-feature=+v` it is named `autovec(+v)` and is the experimental RVV path, since the `v` target feature and RVV intrinsics are unstable. |
| library | `memset` / `memcpy` through `slice::fill` and `copy_from_slice` (the baseline of `zero` and `copy`). |
| handwritten | x86_64: `avx2` for every family, `avx2-nt` (non-temporal stores) for `zero`, `avx512` (AVX-512F; popcount also needs VPOPCNTDQ). aarch64: `neon` for every family. |
| experimental | aarch64: `sve-autovec`, the portable loops compiled inside `#[target_feature(enable = "sve")]` functions, since SVE intrinsics are not stable. |

`age-meta` has its own variants: `sparse` (today's `purge_segment` loop over the candidates' atomics, the baseline), `sparse-branchless` (the same without the data-dependent branch), and `snapshot+<kernel>` (64 atomic loads, then each non-scalar `age` kernel on the snapshot).

The first variant of each family is the baseline the "vs baseline" column refers to. The unit tests (`cargo test -p allocatbelt-simd-bench`) check every detected variant against it at the benchmark sizes and at the awkward lengths around vector widths (0 to 17, 63 to 65, and every length up to 300 bytes at five offsets for `zero` and `copy`, checking nothing is written outside the buffer). CI runs them natively on x86_64 and on the arm64 runner (NEON, and SVE where the runner has it), and under qemu for riscv64, once more with `-C target-feature=+v` for the RVV path.

## Method

- **Timing.** Each measurement calibrates a repetition to about 200 µs, warms up, then times 201 repetitions and reports the median, p95 and p99 of the time per operation (nearest rank). `--quick` uses 11 repetitions of about 20 µs, for CI and qemu; its numbers mean nothing.
- **Counters.** When `perf_event_open` works, the harness opens a group of cycles, instructions, branches, branch misses and cache misses for user space of the benchmarking thread and reports each per operation. In containers or under `perf_event_paranoid >= 3` it prints why the counters are unavailable instead of zeroes.
- **Environment header.** Every run prints the architecture, CPU model, kernel, rustc, the build's target features, the detected CPU features, the repetition settings and the counter status (plan §22).

```sh
cargo run --release -p allocatbelt-simd-bench --bin bench-simd                    # markdown table
cargo run --release -p allocatbelt-simd-bench --bin bench-simd -- --csv           # CSV
cargo run --release -p allocatbelt-simd-bench --bin bench-simd -- --family age    # one family
cargo run --release -p allocatbelt-simd-bench --bin bench-simd -- --family age-meta
```

CI runs `--quick` on the hosted x86_64 and arm64 runners to check that every detected candidate runs on those CPUs; those timings are not evidence (shared runners, unknown neighbours).

## First measurements (2026-09-28)

- **Machine:** Intel Xeon @ 2.10 GHz with AVX-512F/CD/BW/DQ/VL/VPOPCNTDQ, a shared VM; Linux 6.18.44; rustc 1.98.1; `--release`, x86-64-v3 build.
- **One full run, no hardware counters** (the container does not expose them). Run-to-run noise on this VM was not quantified, so differences under about 10% are not meaningful.
- This is one x86_64 machine. Nothing was measured natively on aarch64 or riscv64, so the NEON, SVE and RVV variants only have correctness results (qemu).

Median ns per operation, and the ratio to the baseline (higher is faster):

| Family | Size | Baseline | autovec | avx2 | avx512 |
|---|---|---:|---:|---:|---:|
| nonzero | 1 | 9.1 | 5.3 (1.7×) | 6.0 (1.5×) | 6.1 (1.5×) |
| nonzero | 16 | 39.1 | 7.7 (5.1×) | 7.4 (5.3×) | 7.5 (5.2×) |
| nonzero | 64 | 118.7 | 15.1 (7.9×) | 14.0 (8.5×) | 10.0 (11.9×) |
| nonzero | 256 | 347.6 | 54.3 (6.4×) | 52.5 (6.6×) | 48.2 (7.2×) |
| popcount | 1 | 1.5 | 1.7 (0.86×) | 3.5 (0.42×) | 4.0 (0.37×) |
| popcount | 16 | 10.2 | 5.4 (1.9×) | 5.3 (1.9×) | 3.6 (2.8×) |
| popcount | 64 | 31.6 | 16.4 (1.9×) | 16.1 (2.0×) | 4.8 (6.5×) |
| popcount | 256 | 152.4 | 62.5 (2.4×) | 71.5 (2.1×) | 22.1 (6.9×) |
| age | 1/64 | 3.1 (sparse) | 10.2 (0.30×) | 8.7 (0.36×) | 15.5 (0.20×) |
| age | 8/64 | 7.5 (sparse) | 10.3 (0.73×) | 8.3 (0.91×) | 16.7 (0.45×) |
| age | 32/64 | 25.3 (sparse) | 11.6 (2.2×) | 10.3 (2.5×) | 15.8 (1.6×) |
| age | 64/64 | 58.6 (sparse) | 10.4 (5.6×) | 8.2 (7.2×) | 15.9 (3.7×) |

| Family | Size | Library | avx2 | avx2-nt | avx512 |
|---|---|---:|---:|---:|---:|
| zero | 64 B | 2.8 | 5.3 (0.53×) | 183.9 (0.02×) | 6.0 (0.47×) |
| zero | 1 KiB | 6.6 | 8.1 (0.81×) | 220.8 (0.03×) | 8.1 (0.81×) |
| zero | 64 KiB | 1457 | 1456 (1.00×) | 3971 (0.37×) | 1447 (1.01×) |
| zero | 1 MiB | 22 648 | 22 773 (0.99×) | 56 357 (0.40×) | 22 255 (1.02×) |
| zero | 4 MiB | 159 513 | 157 240 (1.01×) | 239 460 (0.67×) | 227 011 (0.70×) |
| copy | 64 B | 4.0 | 8.2 (0.49×) | | 7.8 (0.52×) |
| copy | 1 KiB | 11.3 | 12.1 (0.93×) | | 21.7 (0.52×) |
| copy | 64 KiB | 1793 | 1814 (0.99×) | | 2009 (0.89×) |
| copy | 1 MiB | 42 858 | 43 816 (0.98×) | | 60 105 (0.71×) |
| copy | 4 MiB | 357 360 | 345 667 (1.03×) | | 361 843 (0.99×) |

### Findings

1. **Hand-written AVX2 does not beat the compiler.** For `nonzero`, `popcount` and `age`, the autovec loop built for x86-64-v3 is within about 20% of the AVX2 intrinsics at every size, and neither is consistently ahead (AVX2 is 1.3× faster on `age` at 64 of 64 candidates, autovec 1.1× faster on `popcount` at 256 words). If one of these operations is promoted, the first candidate is the plain loop, which needs no `unsafe` and runs in `allocatbelt-core`.
2. **AVX-512 VPOPCNTDQ is the one large hand-written win**: 2.8 to 3.4× over autovec from 64 words up. Whether it matters depends on how hot `reduce_local_masks` is in a real maintenance pass, which is gate B's question; it is a CPU tier above the v3 floor, so it would also need run-time dispatch. (Phase 5: no allocator path has such a reduction.)
3. **The purge-age scan should stay sparse at low density.** Today's `trailing_zeros` loop over candidates wins at 1 to 8 candidates of 64 and loses from 32 up, where a dense compare (autovec or AVX2) is 2 to 7× faster. A hybrid that switches on `candidates.count_ones()` is the obvious candidate; how many candidates a segment typically has during decay decides whether it is worth it. AVX-512 is slower than AVX2 here (the mask compares and extraction cost more than they save on 64 elements). (Phase 5: on the real metadata layout the snapshot takes most of this advantage; see `age-meta`.)
4. **Negative: bulk zeroing and copying.** `memset` and `memcpy` tie or win at every size. Hand-written loops lose up to 2× on small blocks, where the library's size-specialised entry paths matter. Non-temporal stores lose at every size tested, badly at small sizes (the `sfence` and write-combining flush dominate) and still by 1.5× to 2.5× at 1 to 4 MiB on this machine. AVX-512 zeroing is slower at 4 MiB, and AVX-512 copying is slower from 1 KiB to 1 MiB. **Recommendation: keep `write_bytes` and `copy_nonoverlapping` in the adapter; candidates C and D of plan §7.2 are not pursued further unless native measurements on another machine disagree.**
5. **Single-word inputs gain nothing.** At 1 word every vector variant is at best even with scalar, which matches the plan's rule to keep single-word bitmap work on `tzcnt`/`popcnt`/`lzcnt` (Phase 3).

## Phase 5: promotion decision (2026-09-28)

**Decision: no kernel is promoted.** `KernelSet` keeps only `Baseline`, `allocatbelt-arch` gains no kernel, and no allocator code changes. The plan admits a kernel only if it materially improves a measured allocator bottleneck (§13, Phase 5). Gate B below shows that none of the candidate operations is one. The purge-age scan, the one candidate Phase 4 left open, also loses most of its kernel-level advantage on the allocator's real data layout.

### Environment

- **Machine:** Intel Xeon E5-2630 v4 @ 2.20 GHz (Broadwell: AVX2, BMI1/2, LZCNT; no AVX-512), 36 vCPUs of a KVM guest that was otherwise idle (load average under 0.2), the machine of the first round in [benchmarks.md](benchmarks.md). Linux 7.0.0-34-generic, rustc 1.98.1 (LLVM 22.1.8), `--release`, x86-64-v3 build.
- **Counters:** still unavailable. `perf_event_paranoid` is 4 and the account has no `CAP_PERFMON`, and valgrind is not installed, so the instruction, branch and cache columns are still missing.
- **`bench-simd`:** 5 full runs; each cell below is the median of the 5 per-run medians. Across all rows the median run-to-run range is 14%, but operations under about 20 ns vary by 30 to 100%, because whole runs came out uniformly faster or slower. On this VM, differences below about 1.3× between variants of such small operations are not evidence.
- **Allocator profile:** `bench-allocatbelt` (purge thread on) with a local instrumentation patch, 3 to 6 runs per workload (below).

### Gate B first: how much allocator time the candidates could save

Before wiring a kernel in, the question is how much time the operation it speeds up takes in the allocator. A local patch timed these parts with `rdtsc`: `Heap::pass`, `trim_shards`, the `seg_used` walk of `pass`, the age loop of `purge_segment` and the `Os::purge` calls. It also counted passes and the candidates of every age scan. The patch is not committed, because `rdtsc` needs `unsafe` in the core. The runs covered the standard workloads, then a sustained burst (12 back-to-back 16-thread local churns), a sustained mix (6 rounds of small churn, producer/consumer and local churn) and 3 s of idling. Figures are ranges over the runs.

| Workload (wall time) | Budget passes on allocating threads | Of which `madvise` | `trim_shards` | `seg_used` walk | Age scans (purge thread) |
|---|---|---|---|---|---|
| single-thread churn; 8 producer/consumer pairs | none | | | | none |
| 16-thread small churn (0.40–0.50 s) | 0–1 | | | | none |
| 16-thread local churn (0.34–0.35 s) | 84–101, 321–331 ms in all | 305–315 ms (95%) | 7.4–8.0 ms | ≤ 0.8 ms | none |
| sustained: 12 × 16-thread local churn (3.47–3.52 s) | 1040–1044, 3.29–3.34 s in all | 3.01–3.06 s (92%) | 168 ms (5%) | ≤ 27 ms (0.8%) | 760–836 scans, 0.54–0.61 ms in all; none found an eligible page |
| sustained mix (2.62–2.67 s) | 251–269, 0.86–0.89 s in all | 0.80–0.82 s (92%) | 58–63 ms | ≤ 8.3 ms | 354–378 scans, 0.21–0.27 ms; none eligible |
| 3 s idle after the workloads | none | | | | 216–297 scans, 0.11–0.16 ms |

The `seg_used` figures are upper bounds: they include two `rdtsc` per segment visited, about 400 segments per pass.

- **The age scan (`age`) does not run in the standard workloads.** Decay passes count epochs. Until the fifth one, 1.25 s after the purge thread starts, the cutoff is below every stamp, so `pass` returns before it walks the segments. The four workloads take 1.2 s together. Under sustained churn the scan runs on the purge thread, about 800 times in 3.5 s, for 0.6 ms in all. It never finds a page old enough, because budget passes purge every dirty page long before it ages. Removing the loop entirely would save 0.02% of the purge thread and nothing on the allocating threads.
- **The `seg_used` walk (`nonzero`)** runs in every pass, on the allocating thread that triggered the budget pass. It takes at most 0.8% of budget-pass time, which is at most 0.05% of the 56 thread-seconds of the sustained burst. The walk already tests each word as it loads it. A `find_nonzero_local_words` kernel would first need a snapshot of the 256 words with atomic loads, which the `nonzero` measurement leaves out, and could only replace those tests.
- **`reduce_local_masks` (`popcount`) has no caller.** Dirty pages are counted in `dirty_pages`, and every `count_ones` in the heap works on one word. The only sum over several words is `Heap::segments_in_use`, a diagnostic. The AVX-512 VPOPCNTDQ result of Phase 4 has nothing to speed up.
- **The maintenance plane spends its time in `madvise`:** 92 to 95% of budget-pass time. Under the sustained burst, some allocating thread was inside a budget pass, holding `purge_lock`, for 94 to 96% of the wall time. The next cost, `trim_shards` (5%), is algorithmic: it visits every shard, every class and the shard's segments. Vectors do not help with either. Both are inputs for Phases 7 and 8 (the maintenance scheduler and the io_uring purge); plan §7.2 E already notes that SIMD cannot remove `mmap_lock`, page-table work or TLB shootdowns.

These counts come from the algorithm (how often passes run, how many segments are owned), not from the ISA. On aarch64 or riscv64 the age scan would still take under 2% of the purge thread even if it ran 100× slower there, and none of it on allocating threads.

### The purge-age scan on the real layout (`age-meta`)

Phase 4's `age` results suggested a hybrid that switches to a dense vector compare from about 16 to 32 candidates. On the heap's layout each epoch is an atomic in its own page record, so the dense path first takes a snapshot with 64 loads. The table gives median / p99 ns per segment and the speed-up over today's loop, from 5 runs. "Warm" re-reads one segment; "cold" cycles through 2048 segments (about 70 MiB of records).

| Candidates | sparse (today) | sparse-branchless | snapshot+autovec | snapshot+avx2 |
|---|---:|---:|---:|---:|
| 1/64 warm | 4.2 / 5.3 | 3.9 / 4.8 (1.08×) | 53.0 / 59.8 (0.08×) | 55.9 / 67.6 (0.08×) |
| 8/64 warm | 12.9 / 16.3 | 14.5 / 19.5 (0.89×) | 53.0 / 64.9 (0.24×) | 56.4 / 75.1 (0.23×) |
| 32/64 warm | 42.9 / 52.7 | 49.3 / 65.6 (0.87×) | 53.0 / 65.6 (0.81×) | 56.3 / 71.5 (0.76×) |
| 64/64 warm | 83.6 / 108 | 103 / 135 (0.81×) | 53.0 / 65.0 (1.58×) | 55.9 / 69.9 (1.49×) |
| 1/64 cold | 18.9 / 31.7 | 13.5 / 18.0 (1.40×) | 273 / 1 988 (0.07×) | 272 / 313 (0.07×) |
| 8/64 cold | 133 / 163 | 80.9 / 98.3 (1.64×) | 271 / 361 (0.49×) | 273 / 359 (0.49×) |
| 32/64 cold | 350 / 462 | 187 / 212 (1.87×) | 267 / 330 (1.31×) | 275 / 379 (1.27×) |
| 64/64 cold | 602 / 799 | 316 / 399 (1.90×) | 272 / 354 (2.21×) | 272 / 349 (2.21×) |

- **The snapshot costs about 53 ns warm and 270 ns cold**, however many candidates there are, so a dense scan only wins from about 40 of 64 candidates warm and 25 cold. Under sustained churn, 58 to 63% of scans had 16 or more candidates, 27 to 32% had 32 or more, and none had 64.
- **What the dense path gains when cold is memory-level parallelism, not vector compares.** The same loop over the candidates without the data-dependent branch (`sparse-branchless`) is 1.9× faster at 32 and 64 candidates. From 1 to 32 candidates it is the fastest variant. The hand-written AVX2 compare is no faster than the compiler's.
- **Warm, today's branching loop is fastest below 64 candidates.** Part of that is the branch predictor learning the benchmark's fixed pattern. A real pass sees different epochs in every segment, which is what the cold case models.
- **If the scan ever matters, the first change is the branch-free scalar loop in `purge_segment`:** no snapshot, no dispatch, no `unsafe`. The scan grows with the number of owned segments: at the arena's 16,384 segments, a cold scan with 64 candidates each would take about 10 ms per decay pass. The loop is not changed now, because gate B shows nothing to gain.

### The other families on this machine

Median ns per operation over 5 runs, and the ratio to the baseline (higher is faster):

| Family | Size | Baseline | autovec | avx2 |
|---|---|---:|---:|---:|
| nonzero | 1 | 16.7 | 13.6 (1.23×) | 12.7 (1.31×) |
| nonzero | 16 | 36.8 | 16.4 (2.25×) | 16.4 (2.25×) |
| nonzero | 64 | 140 | 27.2 (5.15×) | 30.2 (4.63×) |
| nonzero | 256 | 360 | 64.7 (5.57×) | 65.7 (5.48×) |
| popcount | 1 | 2.3 | 2.9 (0.78×) | 3.5 (0.64×) |
| popcount | 16 | 12.4 | 7.9 (1.58×) | 7.7 (1.62×) |
| popcount | 64 | 47.5 | 21.3 (2.23×) | 21.2 (2.24×) |
| popcount | 256 | 162 | 72.8 (2.23×) | 72.8 (2.23×) |
| age | 1/64 | 3.2 (sparse) | 13.2 (0.24×) | 14.1 (0.23×) |
| age | 8/64 | 7.7 (sparse) | 13.2 (0.59×) | 14.4 (0.54×) |
| age | 32/64 | 22.8 (sparse) | 13.2 (1.73×) | 14.1 (1.61×) |
| age | 64/64 | 45.1 (sparse) | 13.2 (3.42×) | 14.1 (3.19×) |

| Family | Size | Library | avx2 | avx2-nt |
|---|---|---:|---:|---:|
| zero | 64 B | 3.3 | 7.3 (0.45×) | 277 (0.01×) |
| zero | 1 KiB | 11.6 | 13.6 (0.86×) | 276 (0.04×) |
| zero | 8 KiB | 171 | 179 (0.96×) | 866 (0.20×) |
| zero | 64 KiB | 2 369 | 2 242 (1.06×) | 4 089 (0.58×) |
| zero | 1 MiB | 38 714 | 38 566 (1.00×) | 58 699 (0.66×) |
| zero | 4 MiB | 154 891 | 157 401 (0.98×) | 234 799 (0.66×) |
| copy | 64 B | 4.1 | 6.6 (0.63×) | |
| copy | 1 KiB | 19.7 | 20.4 (0.96×) | |
| copy | 8 KiB | 142 | 145 (0.98×) | |
| copy | 64 KiB | 3 695 | 3 675 (1.01×) | |
| copy | 1 MiB | 68 613 | 68 438 (1.00×) | |
| copy | 4 MiB | 353 257 | 350 705 (1.01×) | |

Phase 4's findings hold on Broadwell. The compiler's loop matches hand-written AVX2 on every reduction. `memset` and `memcpy` tie or win at every size, and hand-written AVX2 is up to 2.2× slower below 1 KiB. Non-temporal stores lose at every size, still by 1.5× at 1 to 4 MiB.

### Decisions

| Candidate | Kernel evidence | Allocator evidence (gate B) | Decision |
|---|---|---|---|
| `nonzero` (`find_nonzero_local_words`) | compiler loop 5.6× over scalar at 256 words, hand-written AVX2 no better; the snapshot's cost not included | the `seg_used` walk: ≤ 0.8% of budget-pass time, ≤ 0.05% of allocating-thread time | not promoted |
| `popcount` (`reduce_local_masks`) | compiler loop 2.2× from 64 words; AVX-512 VPOPCNTDQ a further 3× (Phase 4 machine) | no allocator path sums counts over several words | not promoted: no caller |
| `age` (`Heap::purge_segment`) | 3.4× at 64/64 on a contiguous array; on the real layout, only from about 25 to 40 candidates, and matched by a scalar branch-free loop | no scans in the standard workloads; 0.6 ms per 3.5 s of sustained churn, on the purge thread only | not promoted |
| `zero`, `copy` (plan candidates C, D) | the library ties or wins; non-temporal stores lose | not needed | not pursued (Phase 4) |
| NEON, SVE and RVV variants | correctness only (CI, qemu) | the counts above do not depend on the ISA | not promoted |

For each promoted kernel the plan records the workload, CPU, kernel, compiler, input-size range, old and new median and p99, and the dispatch threshold. Nothing was promoted, so there is no threshold and `KernelSet` is unchanged; the sections above give the same fields for the rejected candidates.

## Still open

- Hardware counters (instructions, branches, cache misses) need a machine with `perf_event_paranoid` of 2 or less, or `CAP_PERFMON`.
- Native aarch64 (NEON, SVE) and RV64 (Zbb, V) runs of `bench-simd`, which plan §15 gate C asks for before any performance claim on those architectures. They would only change the decisions above if these operations turned out to be about 100× slower there.
- A later phase that adds batch work to the maintenance plane (Phase 8's purge descriptors, plan candidate E) or makes the segment walk longer (thousands of segments per shard) reopens the question. It starts with a gate B profile like the one above.
