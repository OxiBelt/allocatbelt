# Experimental resource-aware runtime

`allocatbelt::runtime` is an optional module of the single published package,
compiled by the additive `runtime` feature. The unpublished
`allocatbelt-runtime` crate forwards to the same implementation for development
and compiles that source directly for Loom. It provides bounded blocking and
owned-future worker pools, plus cooperative managed-storage ledgers. Full Tokio
capability parity and native performance qualification remain pending. It is
not recommended for production. `allocatbelt` remains the only package intended for publication; enabling the
module does not install a global allocator or change allocator-only defaults.

This page specifies the milestone contract. Verification and qualification
status is recorded in the linked research report.

## Initialized-buffer asynchronous I/O

`runtime::io` defines safe `AsyncRead`, `AsyncWrite` and `AsyncSeek` traits
over initialized caller-owned slices. Named futures provide read, write,
read-exact, write-all, flush, shutdown and seek operations. `SliceReader` and
`SliceWriter` supply in-memory implementations. These are explicit ports:
Tokio's uninitialized-buffer and seek APIs are not source compatible.

`copy_with_buffer` borrows a caller-supplied buffer, flushes at EOF and when
the reader waits after writing, and exposes transferred and unwritten bytes
for cancellation recovery. The transferred count saturates at `u64::MAX`.
Exact reads, full writes and copies retain partial progress across polls;
dropping them does not restore stream position. Helpers reject an endpoint's
reported count when it exceeds the offered slice, retry interrupted calls,
and yield with a self-wake after 64 endpoint calls in one poll. This requests
rescheduling without guaranteeing another task's turn. Simple helpers do not
allocate or implicitly reserve managed-storage charges. Buffered adapters,
vectored operations and networking integration remain pending.

## Managed buffers and operation permits

`runtime::managed::ResourceScope` provides a separate shared ledger for managed
buffer capacity and concurrent disk/network operation permits. `ManagedBuf`
clones share one charge, held until the last owner frees the storage, including
when a job returns the buffer or the runtime shuts down. Shrinking retains its
capacity and charge. Growth reserves the full replacement while the old storage
is still live; the peak must fit the budget before replacement proceeds.

This is cooperative accounting of explicit managed storage and operation slots.
It excludes allocator metadata, the shared buffer header, physical rounding,
RSS and arbitrary allocations. It supplies neither CPU quotas nor byte-rate
limits. The existing blocking pool's declared `Resources` reservations remain
separate from this ledger.

## Owned asynchronous tasks

`runtime::asynchronous::AsyncRuntime` runs owned `Send + 'static` futures on a
fixed worker pool. An outstanding bound covers queued, polling, sleeping and
cancellation-cleanup tasks. A separate scope bound includes the implicit root
scope. Rejection returns the original future. Each scope has FIFO ready order;
dispatch rotates ready scopes with one poll per turn. A future that never
returns from `poll` cannot be preempted.

`AsyncRuntime::block_on` and `AsyncHandle::block_on` poll one root future on
the caller's thread; that future may borrow local data and need not be `Send`.
Spawned futures remain owned, `Send + 'static` tasks. The caller parks between
pending polls, so workers can progress and wake it. Nested `block_on` calls on
one thread and calls from executor workers return explicit errors. `enter`
sets a thread-local current handle. The current value is the most recently
entered still-live guard; dropping guards out of order removes only the
dropped context. A guard returned from `block_on` remains current until that
guard is dropped. Worker polls also enter the runtime's implicit root handle.
`current` panics without an entered context, while `try_current` returns
`None`.

`yield_now` schedules one self-wake and completes on the next poll; it does not
guarantee another task runs first. `consume_budget` is an opt-in checkpoint
that yields after 64 completed checkpoints within one poll. It cannot preempt
code that does not await it, and it does not impose a fairness or latency bound.

`AsyncJob` is awaitable; dropping it detaches, while `abort` requests cleanup
after any in-flight poll returns. Owned scopes cancel their children on drop;
`close` waits for cleanup, result publication and scope-slot reclamation.
Future cleanup and admission release precede join publication. Scheduler locks
never cover user polling, destructors or completion callbacks. Generation tags
make retained stale wakers harmless without retaining completed futures.

The blocking pool's `Job` is also a future, so an asynchronous caller can await
blocking work without blocking an executor worker. Its existing consuming
`join` and deadlock checks remain available.

Loom exercises production task transition helpers and managed-ledger methods.
Some scope models are capped at 10,000 permutations and use a small generation
table. Full queues, worker parking, actual wakers, ownership and scope pointer
identity are outside those models; native lifecycle tests cover these paths.
This foundation supplies no current-thread/local executor or I/O reactor yet.

## Bounded timers

Driver close drains sleeps that remain registered. Already-fired sleeps keep
their published success, and their service-thread callbacks may continue after
driver drop returns. External `shutdown` joins the service thread and waits for
those callbacks; service-thread shutdown closes and returns `WouldDeadlock`.

`runtime::time::TimerDriver` owns one timer service thread. Its clonable handle
creates sleeps, timeouts and intervals under an explicit registration bound.
The indexed minimum heap, registration table and free-slot list are reserved
at construction. Sleeps allocate shared state separately; the registration
bound is not a total heap or RSS budget. Equal deadlines fire in arming order.

Reset updates the current generation in place. Dropping a sleep cancels its
registration, and stale generations cannot complete a reset or reused slot.
Capacity is released before completion publication. Waker registration and
publication share a slot lock; cloning, waking and dropping wakers occur
outside timer locks. Callback panics are contained under unwinding.

Timeout polls the deadline first and gives it ties, dropping the losing future
when it completes. Intervals support Burst, Delay and Skip; lateness greater
than five milliseconds activates the selected policy. `reset` schedules one
period from now, while `reset_immediately` schedules now. Reset failures retain
the prior interval schedule. Real clocks can fire late due to scheduling.

Driver shutdown closes admission and drains pending sleeps with `Closed`,
using a single drain owner and fixed-size callback batches. Concurrent close
callers wait for that drain. A service-thread caller avoids waiting on an
external closer that might be joining it; joining the service from its own
callback returns `WouldDeadlock`. Dropping the driver closes without joining.

Two Loom models exercise the production slot publication/registration helpers
and indexed-queue generation transitions. Service-thread scheduling, condition
variable waits, ownership and close-drain callbacks are outside those models;
native tests cover them. A controlled test clock remains to be implemented.

## First milestone contract

Each submission declares a `Resources` vector. Admission reserves every
dimension under one scheduler mutex, or rejects the submission without running
it. A rejected submission returns ownership of the closure. Reservations cover
queued, running and cancellation-cleanup jobs; `max_outstanding` independently
bounds their count.

Construction reserves queue storage for all `max_outstanding` entries before
starting workers, so admitted queue insertion does not grow storage under the
scheduler mutex. With the current 64-bit entry layout this requests roughly
48 bytes per configured slot, even for an idle runtime, plus allocator overhead
and separate worker storage. This capacity is outside the declared `Resources`
budget; it does not reserve closure payloads or results and is not a resident
physical-memory limit. Choose the outstanding bound with this upfront cost in
mind. Capacity overflow or failure to reserve queue or worker storage returns
`OutOfMemory` before workers start.

The crate forbids unsafe code. Jobs and results are owned `Send + 'static`
values; jobs receive a cooperative cancellation token. Rejections distinguish
closed admission, a full outstanding window, temporarily insufficient resources
and requests exceeding capacity. Nonblocking means no waiting for capacity,
not lock-free operation: submission can contend on the scheduler mutex.

| Dimension | Meaning | Not provided |
|---|---|---|
| `cpu` | Declared concurrent work units | CPU-time quota, affinity, or preemption |
| `memory` | Declared working-memory bytes | Enforced allocations, RSS or cgroup limit |
| `disk` | Declared concurrent disk-operation units | Disk space, IOPS or bandwidth quota |
| `network` | Declared concurrent network-operation units | Socket reactor or bandwidth quota |

The worker count bounds simultaneous execution separately from admission.
For example, eight CPU units and four workers admits eight one-unit jobs but
runs at most four at once. A zero vector is valid: the job count still bounds
admission. A request greater than capacity is invalid; arithmetic must not wrap
even at `usize::MAX`.

These are **cooperative declarations**, not measurement or OS enforcement.
Allocate large working buffers inside admitted jobs, not in their captured
closures. Caller allocations, thread stacks, scheduler metadata and completed
results retained by callers are outside the declared memory budget. Returning
a result that retains a job's buffers also takes them outside that budget.
A job must declare its entire peak working set honestly.

## Ownership and lifecycle

- Submission is nonblocking. Full queues and temporarily exhausted resources
  cause explicit rejection rather than an unbounded waiter queue.
- Dropping a join handle detaches its job. Cancellation is explicit and
  cooperative for running jobs; it never terminates a thread.
- A queued cancellation that wins the start transition prevents execution.
  Its reservation can remain held until the queue entry and closure are dropped.
- Work, user-owned values and allocator park hooks run outside scheduler locks.
  With unwinding, ordinary job panics become join errors. Containment must also
  cover cancellation cleanup and discarded results; a destructor panicking
  during another unwind can still abort. `panic = "abort"` cannot be recovered.
- Drain shutdown closes admission, finishes admitted work and joins workers.
  Cancel-pending shutdown also cancels queued work and requests cancellation
  of running work. Noncooperative jobs can delay explicit shutdown indefinitely.
- Dropping the runtime closes and cancels without waiting for running work;
  detached workers can outlive it. Queued capture destructors run synchronously
  and can themselves block the dropping thread. Use explicit shutdown when
  completion is required and keep captured resources alive through owned values.
- Blocking joins and shutdown from a worker of its own runtime must be rejected
  rather than deadlock. Do not depend on nested synchronous work in a saturated
  pool. Allocator fork support does not make inherited runtime workers usable
  in a forked child.

An unfinished same-runtime join returns `JoinError::WouldDeadlock` from a
worker (including its thread-local destructors at exit) or queued-job cleanup
on the shutting-down thread. Nested cleanup retains each runtime's identity.
It consumes and detaches the handle; it does not cancel the job. Already finished
jobs can be joined there. `Snapshot::cancelling` counts removed queued jobs during
cleanup, and `outstanding = queued + running + cancelling`. Completed shutdown is a
no-op in either mode; it does not change completed jobs' cancellation tokens.

Every admitted job has exactly one terminal outcome and releases its vector
and outstanding slot exactly once after execution or cancellation cleanup.
Cancellation requested is not capacity released. Cancel-pending shutdown and
runtime drop remove queued entries; drain leaves them to workers. Joiners
observe cancellation only after cleanup, not merely after a token is signaled.

Workers prefer allocator shards at startup and return allocator caches before
parking and at exit. The crate does not install a global allocator. With system
allocation or mimalloc these hooks do not alter those allocators.

## Measurement gate

Compare the runtime with **Tokio's blocking pool**, not its async scheduler.
Use identical jobs, worker counts, outstanding windows and completed-job
checksums. Cross both runtimes with system allocation, secure mimalloc and
allocatbelt to distinguish allocator costs from scheduling costs.

For uniform jobs, set capacity to the outstanding window times the job's
request, so the common window enforces equivalent admission. This is not an
overload or heterogeneous-resource experiment. Future overload comparisons
must match resource rejection and cancellation policy, count rejected work,
and measure end-to-end tail latency. Tokio's blocking-thread limit is a ceiling,
not an eagerly started fixed pool; distinguish startup from warmed execution.

`scripts/bench-runtime.sh` records repeated fresh-process runs. Fully touching
working buffers is required. A sequential checksum reference is outside the
job timing; whole-process profiles include it and runtime startup.
Record each host and toolchain separately, alternate run order, and report
dispersion as well as medians. KVM guests execute native instructions, but
uncontrolled host scheduling and frequency remain confounders. Hosted CI and
qemu timings do not qualify an optimization.

The default `--start warm` submits simultaneous warm-up jobs and waits for all
configured workers before timing. `--start cold` excludes bounded-pool
construction but includes Tokio's lazy blocking-worker creation, so it is an
asymmetric startup experiment, not a steady-state comparison. The script uses
a balanced Williams run-order design; use a complete balancing cycle (six
repetitions for the full three-allocator/two-executor matrix).

See [the runtime research report](research/runtime-foundation.md) for results
and [profiling](research/profiling.md) for CPU, RSS and per-function tools.
Admission counters are not resource-usage measurements.

## Path toward replacing Tokio

The lifecycle foundation above is implemented. Remaining milestones include:

1. Runtime entry/context, current-thread and local execution, task utilities,
   and integration of resource permits into active polling.
2. Timers and a Linux I/O reactor with bounded submission, completion ownership,
   sandbox fallback and cancellation-safe buffers.
3. TCP/UDP, file I/O, synchronization and blocking adapters; define compatibility
   requirements against real Tokio application workloads.
4. Resource measurement and optional cgroup-aware feedback, with explicit
   admission versus enforcement semantics and oscillation/overload tests.
5. Profile-driven scheduler and ISA variants, promoted only after correctness,
   tail-latency, throughput and memory gates on native supported platforms.

No default algorithm or ISA dispatch is promoted by this milestone. The
[platform contract](platform.md), including the allocator's x86-64-v3 floor,
and [design constraints](design-constraints.md) are unchanged.

## Patent-risk discipline

The constraints are a preliminary technical screen, **not freedom to operate**.
Rust, familiar primitives and independent implementation do not establish
non-infringement. Do not copy another library's code without checking its license.

Any allocator change breaking a listed constraint needs its specified review
before implementation. Runtime admission, scheduling, reactors and adaptive
control also need claim-level patent review for the jurisdictions and deployment
in question. Keep sensitive comparisons and unpublished findings in an
authorized private checkout, not this repository.

A patent non-aggression program is not a patent application and does not grant
a patent for this implementation or clear patents outside its licensed scope.
The [OIN 2.0 agreement](https://openinventionnetwork.com/license-agreement-2/)
describes the OIN patent license and participant cross-license, including
Linux System scope and good-standing conditions for 2.0 coverage (sections
1.1–1.2.1). This project makes no membership or coverage claim. Counsel should
verify the agreement and [Linux System definition](https://openinventionnetwork.com/linux-system/)
before relying on it. Sources consulted 2026-10-04; no agreement was submitted.
