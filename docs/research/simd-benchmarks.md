# SIMD candidate benchmarks (plan Phase 4)

Phase 4 of the Linux 7 / ISA / SIMD plan measures candidate kernels before any production path changes. This document describes the harness in `bench/simd` and records the first measurements. **Nothing here is promoted.** The allocator still runs only scalar code (`KernelSet::Baseline`), and Phase 5 needs gates A to C of the plan (§15) on native hardware before a kernel moves into `allocatbelt-arch`.

## What is measured

One family per allocator operation. The inputs are what the allocator would pass: a local snapshot that a maintenance pass would take with individual atomic loads, or thread-owned bytes. No kernel reads shared `AtomicU64` metadata (plan §7.1).

| Family | Allocator operation (plan §7.2, §14) | Sizes |
|---|---|---|
| `nonzero` | `find_nonzero_local_words`: which words of a `seg_used` or dirty snapshot are non-zero, as a bitmask | 1, 4, 16, 64, 256 words |
| `popcount` | `reduce_local_masks`: total `count_ones` over a snapshot of several segments | 1, 4, 16, 64, 256 words |
| `age` | `Heap::purge_segment`: which candidate pages of a segment have been dirty long enough (`since[i] <= cutoff`) | 1, 8, 32, 64 candidates of 64 pages |
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

The first variant of each family is the baseline the "vs baseline" column refers to. The unit tests (`cargo test -p allocatbelt-simd-bench`) check every detected variant against it at the benchmark sizes and at the awkward lengths around vector widths (0 to 17, 63 to 65, and every length up to 300 bytes at five offsets for `zero` and `copy`, checking nothing is written outside the buffer). CI runs them natively on x86_64 and on the arm64 runner (NEON, and SVE where the runner has it), and under qemu for riscv64, once more with `-C target-feature=+v` for the RVV path.

## Method

- **Timing.** Each measurement calibrates a repetition to about 200 µs, warms up, then times 201 repetitions and reports the median, p95 and p99 of the time per operation (nearest rank). `--quick` uses 11 repetitions of about 20 µs, for CI and qemu; its numbers mean nothing.
- **Counters.** When `perf_event_open` works, the harness opens a group of cycles, instructions, branches, branch misses and cache misses for user space of the benchmarking thread and reports each per operation. In containers or under `perf_event_paranoid >= 3` it prints why the counters are unavailable instead of zeroes.
- **Environment header.** Every run prints the architecture, CPU model, kernel, rustc, the build's target features, the detected CPU features, the repetition settings and the counter status (plan §22).

```sh
cargo run --release -p allocatbelt-simd-bench --bin bench-simd                    # markdown table
cargo run --release -p allocatbelt-simd-bench --bin bench-simd -- --csv           # CSV
cargo run --release -p allocatbelt-simd-bench --bin bench-simd -- --family age    # one family
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
2. **AVX-512 VPOPCNTDQ is the one large hand-written win**: 2.8 to 3.4× over autovec from 64 words up. Whether it matters depends on how hot `reduce_local_masks` is in a real maintenance pass, which is gate B's question; it is a CPU tier above the v3 floor, so it would also need run-time dispatch.
3. **The purge-age scan should stay sparse at low density.** Today's `trailing_zeros` loop over candidates wins at 1 to 8 candidates of 64 and loses from 32 up, where a dense compare (autovec or AVX2) is 2 to 7× faster. A hybrid that switches on `candidates.count_ones()` is the obvious candidate; how many candidates a segment typically has during decay decides whether it is worth it. AVX-512 is slower than AVX2 here (the mask compares and extraction cost more than they save on 64 elements).
4. **Negative: bulk zeroing and copying.** `memset` and `memcpy` tie or win at every size. Hand-written loops lose up to 2× on small blocks, where the library's size-specialised entry paths matter. Non-temporal stores lose at every size tested, badly at small sizes (the `sfence` and write-combining flush dominate) and still by 1.5× to 2.5× at 1 to 4 MiB on this machine. AVX-512 zeroing is slower at 4 MiB, and AVX-512 copying is slower from 1 KiB to 1 MiB. **Recommendation: keep `write_bytes` and `copy_nonoverlapping` in the adapter; candidates C and D of plan §7.2 are not pursued further unless native measurements on another machine disagree.**
5. **Single-word inputs gain nothing.** At 1 word every vector variant is at best even with scalar, which matches the plan's rule to keep single-word bitmap work on `tzcnt`/`popcnt`/`lzcnt` (Phase 3).

## What Phase 5 still needs

- Runs with hardware counters on an idle native machine, several runs, and the noise quantified.
- Native runs on AArch64 (NEON, SVE) and RV64 (Zbb, V) for any kernel promoted there.
- Gate B: the allocator benchmarks with the candidate wired in, since a faster kernel on a path that is not hot changes nothing.
