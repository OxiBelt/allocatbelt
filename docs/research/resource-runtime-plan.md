# Resource runtime implementation and qualification

Implementation target: one published `allocatbelt` package, allocator-only
defaults preserved, optional runtime modules, and no Tokio dependency anywhere
in the published normal/build dependency graph. Development comparators may
depend on Tokio. Work takes place on `feat/resource-runtime-foundation`.

The compatibility baseline is Tokio 1.53.1's stable Linux capabilities. This
requires explicit application ports rather than claiming binary or exact API
compatibility. Declarative macros and functions replace procedural entry
macros. Bounded submission and channel capacities require applications to
handle rejection and retain ownership. Owned task scopes accept `'static`
futures; scoped borrowing is outside this contract.

## Dependency order and acceptance

| Stage | Deliverable | Acceptance |
|---|---|---|
| Package | Move the existing blocking pool into the allocator package | Packaged consumer works; production graph excludes Tokio; allocator defaults unchanged |
| Miri repair | Preserve native stress sizes; use topology-equivalent bounded Miri fixtures and a bounded multiword test | Both formerly cancelled cases exit successfully within 30 minutes each; complete isolated core campaign records process exits and intentional benchmark skip |
| Measurement | Separate allocation churn, executor scheduling and application lanes | Independent open-loop arrivals, post-publication completion, checksums, overload counts, timer overhead, fresh balanced processes, immutable source/binary manifests |
| Managed resources | Account managed storage and operation lifetimes | Charges survive returned results and final clones; replacement growth counts old plus new storage; rollback is atomic |
| Async lifecycle | Owned Send tasks, asynchronous joins, cancellation and fair owned scopes | No concurrent poll; stale wakes are harmless; cleanup and admission release precede result publication; callbacks run outside scheduler locks |
| Runtime entry | Multithread/current-thread entry, handles and local execution | Context restoration, external submissions, owner-thread `!Send` tasks, explicit nested-entry rules |
| Task utilities | Yield/budgets, IDs, task-local state, abort controls, completion-order task sets and awaitable blocking jobs | Cancellation, panic containment, detach and shutdown semantics are tested |
| Time | Bounded sleeps/reset, timeout, all interval missed-tick policies and test clock | Deadline ordering, reset generations, cancellation release, lost wakes and shutdown are covered |
| Readiness | Epoll reactor, bounded fd registrations and readiness guards | Fd reuse, simultaneous directions, `WouldBlock`, cancellation and sandbox denial |
| I/O and network | Runtime-neutral traits/utilities; TCP, UDP, Unix sockets and bounded DNS | Partial progress, EOF/half-close, datagram boundaries, options and backpressure |
| Filesystem | Bounded blocking file/directory operations | Offsets and flush ordering; detached cancellation retains owned buffers/permits until actual completion |
| Synchronization | Channels, locks/guards, semaphores, notifications, barriers and initialization cells | Lost-wake models, FIFO fairness, cancellation removal, lag/closure and retained-message accounting |
| Processes/signals | Child lifecycle, pipes and process-global signal integration | Reaping, deliberate kill-on-drop policy, cancellation, bounded output and multiple runtimes |
| Entry/concurrency helpers | Function/declarative equivalents for entry, pinning, task-local, join/error-join and selection | Borrowing, disabled branches, selection policy and loser cleanup |
| Optional controls | Delegated cgroup v2, bounded adaptive policy and separately named runtime io_uring | Permission/readback checks, fixed ceilings, sustained-breach/cooldown/recovery; denied ring setup and no replay after submission |
| Application ports | CPU, memory, TCP/HTTP and disk workloads | Same allocator/policies for executor comparisons; Tokio-free normal/build graph of each port |
| Qualification | Native allocator/executor/application matrix | Per-host statistical gates and correctness checks below; no unsupported superiority claim |

`block_in_place` needs bounded worker handoff while retaining execution on the
calling thread; a blocking-pool offload alone does not preserve borrowed or
`!Send` closures. Unbounded Tokio APIs require an explicit bounded migration
policy. Tokio's unstable io_uring, tracing, taskdump and scheduler-latency APIs
are outside the stable baseline; owned-buffer runtime io_uring is an additional
goal, independent of allocator purge io_uring.

## Performance gates

Preregister workloads, equal geometric-mean weights, arrival rates, worker
counts, resource ceilings, reclamation policies and exclusions before the
confirmation campaign. Use six exploratory paired runs to develop candidates,
then an independent fixed campaign of 36 pairs with simultaneous paired
confidence intervals. Preserve failed and slower variants. Analyze each host
separately; never pool hosts to pass a gate.

Allocator qualification requires at least 5% higher suite throughput and 5%
lower suite p99 against both secure and standard mimalloc. Executor
qualification requires the same gains over Tokio with the same allocator and
matched policies. Individual workload guards allow at most 2% throughput or
CPU regression and 5% tail-latency or retained-memory regression. Report
rejections and late arrivals separately; failed admission is not completed
work. Allocation-churn latency includes payload access and freeing, and is
distinct from raw allocation/free latency and application response latency.

Run the primary native campaign on the designated bare-metal host and confirm
on both designated guest hosts using their native instructions. Docker and
QEMU establish correctness, not performance. Keep raw measurements, profiles,
security findings and Miri logs in the private resources checkout. Public
reports contain sanitized conclusions and reproducible configuration.

## Correctness and review gates

Preserve the safe `no_std` allocator core and every design constraint. New
runtime modules forbid unsafe code. Model actual concurrent transitions where
feasible, and state the limits of any model explicitly. Run targeted lifecycle
and ownership tests, Miri, relevant Loom models, standard formatting/Clippy/
release tests, feature/package gates, audit/deny and affected platform scripts.
Use independent specification/correctness reviews before signed commits. Every
commit includes the required assistance trailer. A passing milestone does not
establish full capability parity or performance qualification.

## Functional application ports

The unpublished `allocatbelt-app-ports` workspace package contains deterministic
CPU, managed-memory, loopback TCP/HTTP and filesystem ports. Its normal/build
dependencies contain no Tokio. Run an example with
`cargo run --release --locked -p allocatbelt-app-ports --example cpu`; the other
examples are `memory`, `tcp_http` and `disk`.

The ports separate reusable workload kernels from the runtime adapters. HTTP
uses a deliberately limited bounded framing parser and capped reads to exercise
incremental progress. Its qualification tests cancel the outer transaction
while a connect is queued and require the admitted server task to release its
scope slot; they also exercise two live endpoints competing for a one-slot
network ledger under a watchdog. Disk creates its private directory and initial
file synchronously before cancellable asynchronous I/O; later detached opens
cannot recreate a deleted payload. Qualification also recovers original file
and managed-buffer inputs and prepared path/options after disk-permit and
blocking-queue rejection, and holds a detached multi-chunk write behind a gate
to verify that its storage charge and disk permit remain live until worker
completion. Memory returns its initialized
managed buffer so tests can verify that its charge survives result publication
and buffer cloning until the final owner drops. CPU retries only a recovered
`Full` submission after one of its own admitted jobs releases capacity, then
checks the stable digest against the serial kernel. A bounded process-driver
test retains a rejected command until the first child is actually reaped and
explicitly shuts the driver down; it is lifecycle qualification, not a fifth
workload lane. Exact managed-ledger checks require an otherwise-idle resource
scope. Each example explicitly closes its task scope and shuts down its drivers.
These functional checks establish neither general HTTP capability nor
application performance qualification.

The development [application comparator](application-comparator.md) runs these
shared kernels through either executor with the same allocator, bounded window
and resource ceilings. Its independent arrivals, completion observations and
phase reports prepare native qualification; passing functional tests establish
no performance advantage.

The [runtime contract](../runtime.md) documents accepted implementation. The
[foundation report](runtime-foundation.md) contains earlier measurements, whose
limitations remain in force. This roadmap records acceptance requirements,
not completed qualification results.
