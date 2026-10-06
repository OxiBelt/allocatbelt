# Rust 1.99 modernization

The workspace, fuzz manifest and contributor toolchain require Rust 1.99.0.
Stable features are selected for concrete ABI, ownership or generated-code
benefits. The safe `no_std` core remains the same source used by the checker.

## Stable implementation boundaries

The experimental RVV age scan uses `#[unsafe(naked)]` and `naked_asm!` in a
private C-ABI leaf. Assembler-local V instructions avoid a global V target
requirement. Strip widths follow actual VL, loads cover exactly the snapshot,
and the explicit low-VL mask discards inactive mask bits. Hardware detection
and current-thread execution permission are separate: saved kernel pointers
recheck policy and permission before every call. The library never enables V.

The ARM64 scalar probes check instruction selection on a native CI runner.
Full-system offline RISC-V guests check both baseline execution and Linux
thread-local vector control; QEMU-user supplies additional vector lengths.
These checks establish correctness, not native ARM64 or RISC-V performance.

Rust 1.99 [stabilizes Rust definitions of C-ABI variadic functions and
`VaList`](https://blog.rust-lang.org/2026/10/01/Rust-1.99.0/). This crate has no
Rust variadic provider. Its foreign `prctl` and `syscall` calls already support
variadic arguments, so they need no new `VaList` shim. Raw DST layout and owned
box/vector decomposition APIs likewise have no matching ownership-transfer
path in the current allocator. Permanent model heaps leaked for tests are
never reconstructed or deallocated. Test-only roots keep these heaps reachable
under Miri while ordinary leak checks remain enabled.

## Qualification method

Freeze the baseline revision and source candidates before collecting timings.
Compare the unchanged baseline on both compilers separately from source changes
on Rust 1.99. Use identical harnesses, features and release flags, and record
each executable hash. Preserve each role's hash across repetitions. Keep
hosts, workloads, compiler comparisons, source comparisons,
diagnostics and instrumented profiles separate.

Use fresh native processes, complete balanced ordering cycles and paired
confidence intervals. Every run must validate completion/checksum and memory
and swap guards. Apply the same memory cap to allocator comparison binaries;
exclude partial or failed campaigns rather than splicing in replacement rows.
Earlier observations with different shims, limits or ordering are exploratory.
Keep invoked executable-path lengths equal between roles, and use same-binary
controls to check launch effects on allocator heap state. A correction to the
launch protocol starts a new campaign rather than extending the old pairs.

An optimization requires a repeatable gain and must avoid supported regressions
above 2% in throughput/CPU or 5% in tail latency/retained memory. Repeat uncertain
cases in balanced six-pair batches up to 36 pairs, then defer them. Cleaner types
or fewer assembly instructions alone do not establish an application speedup.
The allocation-counting diagnostic measures requested heap layouts; use resource
profiles for RSS, and treat its backlog percentiles as workload-specific.

Full runtime queue reservation has an explicitly accepted capacity-cost
exception to the retained-memory gate. It reserves storage for every configured
outstanding slot during construction, currently roughly 48 bytes per slot on
the supported 64-bit targets, even when idle. This requested storage is outside
the declared job resource budget and does not promise resident physical memory.
Other qualification gates remain in force. This constructor contract is
selected with its capacity cost accepted; its implementation status does not
establish a qualified throughput or tail-latency improvement.

Raw timings, source archives, CPU/memory profiles, function samples and review
artifacts remain in the authorized private resources checkout. See
[profiling](profiling.md) for the public workloads and diagnostic commands and
[the guest recipe](../../scripts/riscv-guest/README.md) for correctness checks.

## Implementation decisions

| Change | Decision | Basis |
| --- | --- | --- |
| Rust 1.99 minimum and contributor toolchain | Implemented | The workspace, fuzz package and CI use the same stable minimum. |
| Stable naked RVV leaf and per-call vector permission checks | Implemented | The ABI and Linux thread-control tests pass; the experimental kernel remains opt-in. |
| Immediate typed atomic view of rseq fields | Implemented | The borrow ends with each load; field offsets and the load protocol are preserved. |
| Typed page-metadata array views | Implemented | `as_chunks` exposes one page's fixed word count to the compiler without changing the metadata layout or unsafe boundary. No application speedup is claimed. |
| Masked size-class selection | Deferred | The native campaign failed its throughput qualification gate and established no repeatable gain across both hosts. The existing class scan remains, with stronger exhaustive tests. |
| Runtime admission precheck | Deferred | Rejection latency and allocation counts improve, but primary and backlog latency cases remain uncertain at the 36-pair limit. The existing admission path remains. |
| Eager reservation of the entire runtime queue | Implemented | Queue growth moves to construction. The upfront capacity cost is explicitly accepted; impossible bounds or reservation failure return `OutOfMemory` before workers start. |
| Typed Region cursor | Deferred | The isolated native comparison exceeded the throughput regression limit. |
| Extra Region cursor pointer, larger bitmap snapshot and cold TLS helper | Deferred | These candidates have no qualifying isolated evidence. |
| Merged task/control allocation | Deferred | Retained control/job handles would keep task/result-sized storage allocated after completion and exceed the memory limit, even if the payload values are dropped. |
| `VaList` and owned DST decomposition | No matching implementation | The allocator neither defines a variadic provider nor transfers owned DST allocation parts. |
