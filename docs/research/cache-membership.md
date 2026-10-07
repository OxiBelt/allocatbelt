# Cache membership candidate qualification

The inverse-position candidate replaces a linear search of cached block
numbers with a checked list position. It still stores block lists, validates
stale positions against the live list, and preserves uniform randomized
selection. It adds 64 bytes per class, or 2,048 bytes per thread cache. No
shared allocation bitmap, lock protocol or design constraint changes.

Status: native throughput/p99 change-comparison gates passed on three hosts;
complete core Miri and retained-memory qualification are still running.
This candidate has not established the
library's required superiority over either mimalloc baseline or Tokio.

## Fixed comparison

The unchanged allocator baseline is revision
`95500ea59c1145cac1deec535255fb3a011744eb`. Both variants use the same
`bench-latency-allocatbelt` harness, Rust 1.99 and Linux 7.0. Six exploratory
pairs preceded an independent fixed campaign of 36 fresh-process pairs per
workload and measurement mode. Variant order alternated. All three hosts
executed native instructions: one Ryzen 9700X bare-metal host and separate
Ryzen 8845HS and 7840HS guests. Hosts were analyzed separately.

The allocator lane uses CPU affinity 0–7 and `--bytes 256`. Local and aligned
workloads run 1,000,000 iterations; mixed runs 100,000. The local workload
touches and frees 64-byte allocations; aligned creates 256- and 4,096-byte
aligned objects; mixed cycles through eight sizes from 16 to 262,144 bytes.
The harness warms 1,000 iterations outside timing. Throughput and per-iteration
latency use separate processes. Latency includes payload access, freeing and
timer overhead. It is distinct from open-loop application response p99.

Each host contributes 432 processes: three workloads, two modes, two variants
and 36 pairs. Checksums, argument records, binary hashes and process outcomes
were checked. Failed and slower variants remain in private evidence.

Paired log-ratio percentile bootstrap uses 50,000 resamples, fixed seed
20261007 and Bonferroni adjustment for fourteen contrasts per host. This is
approximate simultaneous 95% coverage per host. It does not establish global
coverage across all three hosts.

## Results and limits

The aggregate is an equal-weight geometric mean across workloads. Workloads
ran in separate batches, so matching their repetition indices does not
establish cross-workload pairing. The original preregistered aggregate
bootstrap analyses are preserved; acceptance below uses the more conservative
geometric mean of the simultaneous per-workload bounds instead.

All ratios are candidate divided by baseline; higher throughput and lower
p99 are favorable.

| Host | Throughput ratio | Conservative lower bound | p99 ratio | Conservative upper bound |
|---|---:|---:|---:|---:|
| 9700X | 1.341 | 1.324 | 0.870 | 0.887 |
| 8845HS guest | 1.267 | 1.252 | 0.881 | 0.889 |
| 7840HS guest | 1.258 | 1.227 | 0.869 | 0.877 |

Each host passes the change gates of throughput lower bound at least 1.05
and p99 upper bound at most 0.95. Every measured workload also passes the
throughput lower-bound guard of 0.98, process-CPU upper bound of 1.02 and p99 upper
bound of 1.05. These results compare the
candidate with the unchanged allocatbelt baseline.

`perf stat` task-clock in throughput processes measures whole-process CPU,
including work outside the timed trace. The original RSS analysis used the
worse paired ratio from latency and throughput modes. Those modes ran in
separate batches, so their repetition indices do not establish cross-mode
pairing. Separate mode bounds remain required for that guard. Peak RSS includes
the latency sample vector and does not qualify retained idle thread-cache
memory. The added 2 KiB per cache remains an explicit
cost. Timer quantization can produce identical p99 ratios and zero-width
bootstrap intervals; these are not exact physical latency bounds. Guest host
scheduling and frequency remain potential confounders.

Complete Miri, retained-memory/application checks and the separate mimalloc
and matched-allocator Tokio qualification remain required. Raw logs, hashes,
profiles and analyses are held in the private resources checkout. The
[implementation plan](resource-runtime-plan.md) specifies the broader gates.

## Compact list comparison

A separate candidate compares eight cached block numbers at a time with safe
byte-to-word operations, then scans any remainder. It queries the actual live
list and adds no persistent metadata; stale entries outside the live prefix
are ignored. Return packing and randomized block selection are unchanged.
Its thread-cache layout remains 3,960 bytes, compared with 6,008 bytes for the
inverse-position candidate. Those sizes are layout facts, not resident-memory
measurements.

On the 8845HS guest, six exploratory pairs per workload/mode preceded an independent fixed
36-pair confirmation against signed baseline
`cad3a129b1ebce7d21c3058a608277c9f16f0ec7`. The workloads, affinity and iteration
counts match the configuration above, using the current 22-column harness.
All 432 fresh processes passed argument, completion-count, checksum and source
hash validation. Throughput and latency modes ran separately.

| Ratio | Point estimate | Conservative acceptance bound |
|---|---:|---:|
| Aggregate throughput | 1.200 | Lower 1.177 |
| Aggregate p99 | 0.930 | Upper 0.946 |

Paired log-ratio percentile bootstrap uses 50,000 resamples, seed 20261007 and
Bonferroni adjustment for seventeen contrasts. Approximate simultaneous bounds
are computed separately for each workload and each RSS mode; aggregate bounds
are conservative geometric means of the individual bounds. Every measured
workload passes its throughput, whole-process task-clock, p99 and separate-mode
peak-RSS guard. Independent review corrected a preliminary CPU analysis that
read event-runtime metadata instead of the measured `perf` task-clock counter;
the corrected analysis is the acceptance result.

This is a one-host allocator-change result. Other-host confirmation, complete
Miri, parked-cache retention and application qualification remain required.
Neither cache candidate has established superiority over mimalloc or Tokio.

## Separate retained-cache memory probe

`bench-cache-retained-allocatbelt` samples process memory before workers,
while every worker remains alive after explicitly flushing its cache, and
after workers join and the main thread purges. Run the identical probe source
against each frozen allocator variant. It uses fixed 2 MiB requested stacks,
16 rounds and either one small class (`minimal`) or all 32 (`all-classes`).
Native qualification uses 32, 128 and 512 workers in both traces; a smaller
functional smoke is not a retention guard.

The probe checks each worker's payload checksum and the full parked cohort.
Its bounded parser requires RSS, PSS, private-clean, private-dirty and anonymous
fields from `/proc/self/smaps_rollup`. Missing data, partial spawn, worker panic,
checksum mismatch or an enrollment timeout fail the process. Cleanup releases
the park gate before joining all successfully spawned workers. Enrollment has
a 60-second limit; qualification also needs an outer process deadline because
joining and purge may block in the kernel.

The CSV includes explicit source-variant/compiler labels and executable size,
plus optional caller-supplied logical cache bytes. That optional value is a
model, not measured retention. Process samples include stacks, libc thread
state, mappings and residency effects; report those limits alongside paired
native comparisons. The probe measures no throughput or latency, and adding
it establishes no memory improvement or completed retention qualification.
