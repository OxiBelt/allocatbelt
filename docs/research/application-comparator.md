# Application runtime comparison lane

This development-only lane compares allocatbelt's bounded runtime and Tokio
1.53.1 on shared CPU, retained-memory, loopback HTTP, and positional-file
transaction kernels. It is an implementation and correctness-qualified harness;
no performance result is claimed until the preregistered native campaign runs.
Earlier isolated pilots are descriptive-only and do not qualify the current
source or establish a performance advantage or p99 eligibility.
The app-port package's normal and build dependency graph remains Tokio-free.
The standard-mimalloc executable lives in `bench/standard-mimalloc`, an
independent Cargo workspace so its `mimalloc` dependency does not unify the
secure feature from the main bench workspace. It imports the same
`bench/src/application.rs` source and app-ports kernels as the other
allocators. Build and audit it separately from the secure baseline.

Each application binary selects its global allocator and accepts
`--executor bounded|tokio --workload cpu|memory|http|disk --mode capacity|open_loop`.
Open-loop runs also require `--rate`. A process executes one cell and emits a
TSV header plus one result row. CPU, memory, and disk retain schema `2`, which
appends `rejected_logical_window` and `rejected_backend_full` while retaining
the prior columns and their order. HTTP uses the explicit policy identifier
`http-nonblocking-connect-v1` in the same schema column to distinguish its
nonblocking IPv4 connect implementation. All lanes keep the same 53-column
header and numeric columns. The legacy `rejected_full` value remains the sum
of `rejected_logical_window` and `rejected_backend_full`, so existing aggregate
fields keep the same meaning. The row records executor topology, window
and resource limits, attempt/admission/completion counts, checksum validation,
capacity publications or observer-consumed response quantiles, producer
lateness, setup/drain/shutdown time, and final ledger state. `lost` is derived
as attempted minus completed; `unresolved` counts admitted work without a
terminal result. Pre-admission resource rejections are reported separately
from Full rejections; the current fixed ceilings expect zero resource
rejections. Capacity publication throughput and drained throughput are separate
columns. Resource charge maxima are samples observed by the coordinator,
not guaranteed instantaneous peaks. The process samples RSS and `VmHWM` before
admission, 100 ms after result drain/output release, and 100 ms after driver
shutdown. The runner's GNU `time -v` report also records whole-process user
and system CPU time and maximum RSS. `timer_pair_median_ns` is the median of
257 back-to-back `Instant` pairs measured before arrivals; it is diagnostic
context, not subtracted from operation latencies.

The lanes use four async workers and a logical window of eight. HTTP counts
8 client jobs, 8 handler jobs, and one accept job (global task cap 17), with
pre-accept handler leases and up to 16 retained endpoint descriptors. Both
executors connect once to the checked IPv4 loopback address without DNS or
address retries: allocatbelt uses `NetHandle::connect_nonblocking` with its
dedicated reactor, and Tokio uses `TcpSocket::connect` with its integrated I/O
driver. Each connect temporarily acquires one network-operation permit and
releases it when connect succeeds, fails, or is cancelled, before the client
endpoint permit is acquired. The bounded connector service still starts its
reserved blocking worker, but HTTP connect does not use that worker. Disk uses
four filesystem/blocking workers and at most eight transactions or filesystem
steps. These are declared topology differences, not equal-total-thread claims. Each
HTTP transaction validates matching client and server results by request ID.
The CPU, memory, and disk observers retain bounded join handles, register a
task-completion waker, and consume whichever terminal results are ready rather
than blocking behind the oldest still-running task. Tokio join handles are
polled directly; allocatbelt uses `AsyncJob::poll_finished`. Their bounded
event queue also carries producer events, with a 100 ms watchdog receive
timeout. Logical-window credit stays charged through join consumption while
backend admission remains independently observable. HTTP keeps its paired
client and handler records and matches both by request ID before completion.
Disk transactions use unique create-new files, positional I/O, readback
checksums, and cleanup. Open-loop arrivals use absolute deadlines and are not
retried after admission rejection or syscall entry.

The compared cooperative schedulers have different internal quanta. The
allocatbelt runtime uses a shared 64-operation budget across its supported
ready primitives/checkpoints during one owned task poll. Tokio 1.53.1's pinned
`task::coop` source initializes its internal budget to 128. These implementation
budgets are not normalized; the benchmark matches external task windows,
arrival policy, and resource ceilings, and reports that fairness-policy
difference as part of the executor configuration.

Capacity/reference validation is performed after the response-completion
timestamp. CPU outputs are checked individually against their stable job ID's
shared scalar-kernel result; the aggregate digest is an additional consistency
check, not the only oracle. HTTP response time is captured after consuming both
paired joins and before request-ID/checksum validation. Only successful
transactions count as on-time or late completions; failed admitted operations
remain in the error/lost accounting.

For bounded 5,000-ID open-loop lanes, the per-ID reference oracle for CPU,
memory, disk, and HTTP is computed during setup before the producer's arrival
clock starts. Timed results are checked against those stable IDs, and the
aggregate digest is rebuilt from the immutable oracle. Memory validation still
checks the actual returned buffer length, charged bytes, and checksum; disk
validation still checks offset, byte count, checksum, and temporary-file
cleanup; HTTP validates both paired request-ID records and each response
checksum. Capacity mode keeps its monotonically assigned IDs and computes the
reference at result validation. Setup time remains reported and whole-process
CPU measurements include oracle setup; the arrival clock and response latency
measurements begin after setup.

`scripts/run-application-pair.sh` prepares one fresh bounded/Tokio pair for a
single allocator/workload/mode/rate. It pins both processes to the supplied CPU
set and applies fixed phase deadlines: 300 seconds for the open-loop trace, 300
seconds from production end through drain, 60 seconds per explicit driver
shutdown, and 900 seconds for the whole process. The process limit also bounds
failures outside those phase-specific watchdogs.
The runner captures the TSV rows and
GNU `time -v` report, records source/binary/toolchain/host hashes and argv, and
preserves failed processes without replacement. It refuses output directories
inside the source checkout so raw timing evidence can be kept in the designated
private evidence store. The script is a runner, not a campaign: rate selection,
paired order balance across fresh pair IDs, host/load preregistration, and
confirmation counts must be frozen before timing collection.

The producer measures its actual open-loop elapsed time and invalidates a trace
that runs past the 300-second ceiling. Before marking a pair complete, the
runner checks the workload-specific worker/topology and resource policy,
reconciles attempted/admitted/rejected/completed/lost counts and both reported
rates, and rejects non-monotone latency quantiles. Open-loop losses remain
visible in a valid descriptive row; accepted-only p99 is eligible only when
all 5,000 arrivals were admitted and completed without rejection.
The secondary wall-through-drain rate uses the later of production end and
the last consumed result as its endpoint, so early completion cannot shorten
the denominator below the full production horizon.

Each process writes a separate shutdown report to the unique path supplied by
`ALLOCATBELT_APP_SHUTDOWN_REPORT`; the report leaves the 53-column result row
unchanged. It records the measured producer-trace duration and every explicit
driver shutdown duration in order. The runner rejects a missing, partial,
reordered, over-budget, or pre-existing report. Native allocatbelt reports its
async runtime, then its filesystem runtime for disk, or its async runtime,
connector pool, and reactor for HTTP. Tokio reports one runtime shutdown per
workload. Driver timing includes the watchdog boundary and operation, and the
900-second process limit remains the outer bound.

Synthetic and real-loopback/file tests validate work accounting, per-operation
checksums, managed-output retention, HTTP ID pairing, multichunk positional
readback, worker startup, cleanup, and final zero ledgers. They do not measure
throughput or establish that either executor is faster. The existing functional
app-port tests remain separate from the benchmark kernels and continue to use
their original otherwise-idle ledger contracts.

For open-loop rows, `requested_arrivals` is the fixed 5,000-ID trace length.
It is blank in duration-based capacity mode, where the observed attempt count
is determined by the 30-second horizon.
