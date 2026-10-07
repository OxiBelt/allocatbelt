# Experimental resource-aware runtime

`allocatbelt::runtime` is an optional module of the single published package,
compiled by the additive `runtime` feature. The unpublished
`allocatbelt-runtime` crate forwards to the same implementation for development
and compiles that source directly for Loom. It provides bounded blocking and
owned-future worker pools, a current-thread executor for local futures, and
cooperative managed-storage ledgers. Full Tokio capability parity and native
performance qualification remain pending. It is
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
allocate or implicitly reserve managed-storage charges. TCP and Unix stream
endpoints implement these traits. `read_vectored` and `write_vectored` borrow
initialized `IoSliceMut` and `IoSlice` arrays. Trait defaults forward only the
first nonempty slice and validate the count against that slice; TCP, Unix
streams and in-memory slices use scatter/gather implementations. The helpers
check the combined offered length, reject overflow with `InvalidInput`, and
validate the returned count. Vectored helpers retry interruptions within the
same 64-call budget; ordinary single-operation scalar helpers return them.
Empty vectored helpers return zero without polling the endpoint. These
operations do not allocate buffers or reserve implicit managed charges.

`runtime::buffered_io` supplies `BufferedReader`, `BufferedWriter` and
`AsyncBufRead`. Constructors take a nonempty, uniquely owned `ManagedBuf` and
return both original inputs on rejection. Readers and writers use this fixed
initialized storage; they do not allocate a separate byte buffer. `into_parts`
returns the endpoint, charged storage and exact unread or unwritten range for
recovery. Consuming too much reader data is clamped to the available length.

Buffered operations share a budget of 64 endpoint calls per poll, including
flush and shutdown. Interrupted calls count toward that bound; other errors,
including `WouldBlock`, propagate. Shutdown retains a completed flush phase
across budget yields and pending shutdown calls. Accepting subsequent writes
starts a fresh flush/shutdown sequence. Dropping a writer does not flush it;
bytes already accepted by the underlying endpoint remain committed.

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

## Owned filesystem operations

`runtime::fs::FsHandle` submits work to an explicit blocking handle. Each
accepted operation holds a disk permit while queued or running; rejection
returns its original inputs, queued cancellation drops captures before permit
release, and detaching a running job retains its resources until completion.
Returned managed buffers keep their storage charge until the final owner drops.

An `OwnedFile` moves into each read, write, seek or synchronization job and
returns in its outcome, preserving cursor sequencing and ownership on I/O
errors. Reads and writes use at most 64 KiB per syscall and check cancellation
between calls; a blocked syscall cannot be preempted. Positional operations
preserve the cursor. Linux append-open files still append during `write_at`,
regardless of its supplied offset. `flush` is not a durability operation;
`sync_data` and `sync_all` forward the filesystem's synchronization calls.

Directory iteration yields one entry per job. Entry metadata and type wrappers
also use disk permits. Returned raw `std::fs::DirEntry` methods can perform
blocking I/O directly if callers bypass these wrappers. Paths and open options
retain standard-library semantics; this API supplies no path sandbox, descriptor
quota, IOPS, bandwidth or disk-space enforcement. It does not collect whole
files or directories implicitly. Borrowed I/O-trait adapters remain pending.

## Bounded epoll readiness

`runtime::reactor::Reactor` owns a Linux epoll service thread and explicit
registration/waiter bounds. `ReactorHandle::register` returns `AsyncFd<T>` or
the original value on rejection. It watches an owned duplicate with checked
generation tokens, sets nonblocking mode while preserving other flags, and
releases the duplicate before reclaiming registration capacity. Nonblocking
mode affects every descriptor sharing that open-file description. The caller's
`AsFd` must keep identifying the same underlying descriptor while registered.

Read and write waits use separate FIFO queues. Level-triggered one-shot
interest arms only directions with waiters and no cached readiness. Readiness
is a hint: `ReadinessGuard::try_io` calls the operation exactly once and clears
its cached direction on `WouldBlock`. Hang-up and error notify both directions;
rearm failures complete waiting futures. Cancelled and forgotten waits are
reclaimed when their registrations are released; generation tags reject stale
events after reuse. Idle writable descriptors do not cause continuous polling.

External close waits for claimed callback drains before returning; callbacks
closing their own reactor and the service thread avoid waiting for themselves.
External shutdown also joins the service; self-joining returns `WouldDeadlock`.
Callbacks run outside driver and callback-tracking locks, including during
thread-local teardown. Registration and waiter tables are preallocated; close
scratch and per-thread callback ownership tracking allocate separately and are
not managed-storage charges or a total memory budget. Socket wrappers and their
I/O-trait integration are provided by the network module. Owned readiness
futures and guards retain an `AsyncFd` clone, keeping the registration and
underlying value alive until their final release. Dropping a pending owned
future cancels its waiter. Reactor protocol behavior is
covered by native tests, not by the current Loom helper models.

## Network endpoints and DNS

`runtime::net` supplies explicitly registered TCP, UDP and Unix endpoints.
Named read, write, accept and datagram methods preserve partial progress,
EOF and message boundaries. They retry interrupted calls and stale readiness
after clearing `WouldBlock`, yielding after 64 endpoint calls per poll.
Dropping a pending named method removes its waiter; transferred bytes remain
transferred. Binding and socket options use standard-library calls directly.
Filesystem-path Unix datagram APIs do not support abstract addresses.

`NetHandle` offloads TCP connection and DNS through an explicit bounded
blocking handle. A network permit remains held while work is queued or running;
detaching a future retains worker captures until actual cleanup. DNS rejection
returns the original hostname and port. Registration rejection returns the
connected or accepted socket for recovery.

DNS output pre-reserves `(address_limit + 1) * 27` managed bytes. Fixed records
preserve both address families and IPv6 flow and scope identifiers. An overflow
returns the bounded observed prefix, including one extra address, and result
clones retain the storage charge until their final release. Caller hostname
storage and the resolver's internal allocations are outside that charge.
This bounds collected output and operation concurrency; it supplies no total
DNS memory, network bandwidth or descriptor quota beyond reactor admission.
TCP and Unix streams implement the initialized-buffer I/O traits. A pending
trait read/write retains one waiter of that direction in the endpoint. Dropping
the borrowing helper leaves this waiter available to a subsequent read/write
poll. Completing an endpoint trait poll for that direction, including an
empty-buffer endpoint poll, removes it. Scalar and vectored extension helpers
may return for empty input or a length error without polling the endpoint;
those short circuits retain any waiter already stored in the endpoint.
`cancel_io_waits` or endpoint drop also removes both directions' waiters. Flush
and shutdown do not remove a pending read/write waiter. Named async methods
keep their immediate waiter cancellation on future drop.

## Message channels

`runtime::channel::channel` constructs a bounded multi-sender, single-receiver
channel with separate message and sender-waiter limits. Private permits reserve
slots through enqueue until receive. Slot admission is FIFO; concurrently
granted sends may enqueue in a different scheduling order. `try_send` rejects
immediately, and named `send` futures wait within the waiter bound. Rejections
return the original value. An unsubmitted send retains its value across polls;
`into_inner` recovers it, while cancellation drops it outside queue locks.

Receiver close rejects further sends and allows queued messages to drain.
Receiver destruction closes admission and drops messages individually outside
locks, containing destructor panics. Receive futures remove their stored waker
on cancellation. EOF follows the last sender and unfinished owned send future;
a completed retained send future does not delay EOF. Managed-buffer charges
survive pending sends, queued messages and returned results until final release.
Queue metadata and arbitrary message allocations are outside that ledger.

`runtime::oneshot::channel` transfers one value through a consuming synchronous
sender and an awaitable receiver. Send rejection returns the value unchanged.
Receiver close retains an already-sent value; receiver destruction discards it
outside the state lock. Dropping an unused sender wakes the receiver with
closure. `Sender::closed` uses a mutable borrow to bound closure notification to
one waiter, and dropping that future removes its waker.

Native tests cover message uniqueness, FIFO admission, cancellation, close/drain,
EOF, reentrant and panicking callbacks, retained charges and Send/Sync bounds.
Actual-source Loom models cover queue close versus enqueue, single-message send
versus receiver registration, and send versus receiver destruction. They do not
model every channel/executor combination or arbitrary user callback behavior.

`runtime::watch::channel` retains the latest value in an owned `Arc` and fixes
the receiver bound at construction. Construction failures preserve the initial
value. `subscribe` starts at the current version; receiver `try_clone` copies
the observed version. `borrow` returns an owned snapshot without consuming a
change, while `borrow_and_update`, receiver marking and successful `changed`
calls control observation. Updates coalesce. An unread final version remains
observable once before closure or version exhaustion.

`send` rejects without receivers and returns its unchanged input; `send_replace`
can retain a new value for later subscribers. `Sender::closed` has a separate
waiter table with the same configured bound as receivers. Completion and
cancellation promptly release its slots; repeated closure/reopen notifications
yield after 64 rearms. Predicate `wait_for` executes outside locks, drops rejected
snapshots before waiting and yields after 64 rejected candidates. Cancellation
at that yield does not consume the next unexamined update.

These snapshots require `T: Send + Sync` for threaded use. Local borrowed values
need no `'static` bound. They keep managed-storage charges through final release,
including after replacement or channel destruction; arbitrary values and
metadata remain outside that ledger. This port uses owned snapshots instead of
Tokio's lock guards and omits mutation callbacks under a lock. Twenty native
tests, two compile-fail examples and five actual-source Loom models cover
observation, replacement, cancellation, closure registration and trait bounds.

## Broadcast channels

`runtime::broadcast::channel` fixes a nonzero message capacity and receiver
bound, including receiver slots still releasing their unread values. Every
receiver has one cursor and one pending receive waker. New subscriptions and
`resubscribe` begin at the current send sequence; lagged receivers report the
exact number skipped before resuming at the oldest retained message. Closing
or dropping the last sender allows each receiver to drain retained messages
before EOF. Sequence counters are checked and receiver generations retire.

Sending with no receivers, after closure or at sequence exhaustion returns
the unchanged input. Message slots retain owned `Arc<T>` values; receiving
clones `T` outside the state lock and protects a concurrently overwritten
replacement from the previous receive's bookkeeping. Retained snapshots and
managed payload clones keep their charges until final release. Cloning,
formatting, waking and payload destruction happen outside the state lock.
Metadata is ordinary storage rather than a managed charge; threaded handles
require `T: Send + Sync`, while local values need no `'static` bound.

`Sender::closed` observes zero active receivers and uses a separate bounded
notification table with the same ceiling as receivers. Completion and
cancellation release their waiter immediately; repeated zero-receiver and
resubscription races yield after 64 rearms. Closure notification is published
before unread payload destruction, while the dropping receiver slot remains
reserved until cleanup completes. A new receiver can reopen this condition
while senders remain alive. Explicit channel closure does not complete this
wait until all active receivers leave.

This port uses the exact requested ring capacity; subscriptions reject after
channel closure. It currently has no weak-sender API. Native and actual-source
Loom checks cover lag, drain, cancellation, reentrant cloning and destruction,
retained managed charges, receiver registration and closure lost wakes.

## Bounded notifications

`runtime::notify::Notify` reserves its complete waiter table at construction.
Named owned futures capture the broadcast generation when created; `enable`
arms a future before the caller checks its condition. Table exhaustion returns
`Full`. `notify_one` assigns the oldest waiter and `notify_last` the newest;
canceling an unobserved assignment transfers it using the same order. With no
waiter, either operation stores one coalescing permit.

`notify_waiters` completes futures created before the broadcast, including
unpolled futures, without storing a new permit. A broadcast is observed before
an existing single permit, preserving that permit for another future. Close
rejects unobserved single assignments while preserving prior broadcast
eligibility. Broadcast generations are checked and waiter slots retire rather
than wrap; exhaustion is explicit. Waker callbacks and debug formatting run
outside the ledger lock. The fixed metadata is outside the managed-buffer
ledger. Seventeen native tests and four actual-source Loom models cover
registration, cancellation order, close races and generation reuse.

## Bounded reusable barrier

`runtime::barrier::Barrier` fixes a nonzero participant count and a waiter-table
capacity large enough for one complete round. Wait futures enroll on first
poll. Unobserved completed results still occupy slots, and `Full` rejects an
arrival without counting it. Each completed round returns its checked round
number and exactly one leader.

Canceling an enrolled wait before completion breaks that round: its peers
receive `Broken` and the barrier advances to a fresh round. Explicit application
ports must handle that result and retry or abandon their operation. Tokio's
barrier wait is not cancellation safe and retains canceled arrivals; this
interface deliberately has different cancellation and zero-participant
behavior. Close rejects unfinished rounds but preserves completed successes.
Round counters do not wrap. Waiter slots retire rather than reuse a wrapped
generation; if usable capacity drops below the participant count, unfinished
waits receive `Exhausted` instead of waiting for an impossible round.

Metadata is preallocated ordinary runtime storage. Waker callbacks and debug
formatting run outside the ledger lock; wake panics and panicking payload
destructors are contained. Twelve native tests cover rounds, bounds, cleanup,
retirement and reentrant callbacks. Three actual-source Loom models exercise
cancellation/arrival, close/completion and round separation races.

## Bounded fair semaphore

`runtime::semaphore::Semaphore` has an explicit preallocated waiter bound.
FIFO requests prevent both later waiters and immediate acquisitions from
passing a head request that needs more permits. A full waiter table returns
`Full`; cancellation removes a request and restores any unobserved grant.
Zero-sized requests are valid and obey the same queue order.

Closing resolves queued and granted but unobserved acquisitions as `Closed`.
Issued permits remain valid and return their count on drop; `forget` removes
that count permanently. Checked `add_permits` can increase the total while
open. These are cooperative units, independent of the managed resource ledger.
The waiter bound excludes shared helper metadata and arbitrary caller storage.
Callbacks run outside the ledger lock. Close publishes terminal outcomes but
does not wait for callbacks already claimed on other threads.

Native tests and four Loom models exercise the production ledger, immediate
acquisition, queued cancellation/grant races, close and slot-generation reuse.
The models do not cover arbitrary user waker behavior or every scheduler path.

An issued semaphore `Permit::split` transfers a checked count to another
owned token without acquiring or releasing permits or waking waiters. Invalid
splits preserve the original token; zero-count splits are valid. Each token
returns its own count independently, including after close. Native tests and
a Loom release/close race check conservation of split permits.

## Bounded asynchronous mutex

`runtime::mutex::AsyncMutex` uses a private one-permit FIFO semaphore with an
explicit waiter bound. It returns borrowed or owned lock futures and guards;
full or closed admission returns a typed error. Constructor failures return
the original protected value. Closing rejects queued and granted-but-unclaimed
locks, while already-issued guards remain valid.

The guard owns the protected value during access. Unlock restores that value
under a short standard mutex lock, releases the lock, then returns the permit.
No standard lock survives an await or covers caller code or callbacks. A guard
can move between threads when the value is `Send`, without requiring `Sync`;
owned guards and futures keep the mutex state alive. This interface does not
promise a stable address for the protected value. User panics while holding a
guard do not poison the mutex; forgetting a guard can leak the value and prevent
further acquisition.

Metadata uses ordinary runtime storage outside the managed-buffer ledger.
Native tests cover FIFO order, queued/granted cancellation, close, reentrant
unlock wakes, panic cleanup and ownership. A Loom model uses the actual mutex
and semaphore implementation to check serialized updates.

## Bounded asynchronous read/write lock

`runtime::rwlock::AsyncRwLock` fixes a nonzero reader ceiling and FIFO waiter
bound at construction. Readers reserve one private permit; writers reserve
the whole ceiling, forming a barrier to later readers. Queued and granted
acquisitions can be cancelled. Close rejects unclaimed acquisitions while
issued guards remain valid. Reported construction errors return the original
value; shared headers follow ordinary Rust allocation-failure handling.

Borrowed and owned guards provide shared reads or exclusive mutation. Reader
guards drop their value references before releasing permits; writers restore
the value before releasing theirs. The writer uses the existing unique `Arc`
and allocates no replacement header per acquisition. Downgrade retains one
reader permit and restores shared access before returning the others, without
an intervening writer. Owned guards and futures may outlive the handle.

This Arc-based implementation requires `T: Send + Sync` for its lock, guards
and futures to move between threads. It provides no upgrade operation or
stable-address promise. Native tests and compile-fail examples cover FIFO
barriers, cancellation, close, downgrade, owned lifetimes and trait boundaries;
an actual-source Loom model checks reader/writer exclusivity. Metadata is
outside the managed-buffer ledger.

## Bounded asynchronous initialization

`runtime::once_cell::AsyncOnceCell` publishes one successful value and returns
owned `Arc` snapshots. It uses a private one-permit FIFO semaphore with an
explicit waiter bound. Factories run lazily only after an empty-cell recheck
under issued admission. Admission failure returns the original uncalled
factory; application initialization errors are distinct. Immediate `set`
returns the unchanged value when already initialized or busy.

Errors, cancellation and panics leave an empty cell retryable. Cleanup drops
initializer futures and remaining factory captures before releasing admission.
A completed initializer's destructor must finish before publication; if it
panics, its proposed value is discarded and later initialization can retry.
Primary panics resume after cleanup, while secondary panic payload destruction
is contained. Completed futures release admission immediately. Recursive
initialization can wait for itself and deadlock.

This explicit port returns owned snapshots instead of Tokio references and
provides no cell clone, reset, mutable-reference or constant-construction API.
Threaded cells and snapshots require `T: Send + Sync`; local values can borrow
data and need no `'static` bound. Metadata is ordinary storage; managed values
retain their charges through the final snapshot. Nine native tests, two
compile-fail examples and three actual-source Loom models cover cleanup,
recovery, competing publishers and thread boundaries.

## Process-wide signals

`runtime::signal::SignalDriver` shares one process-wide dispatcher and a fixed
listener table. The first published bridge fixes the ceiling; later drivers
must request the same value. A dispatcher startup failure is cached without
installing handlers. Invalid kinds and full listener admission make no handler
installation attempt. Listener capacity is reserved before a new kind's first
registration. A reported registry error may already have changed disposition;
that attempt is cached and its callback state remains permanently valid.

Each listener coalesces delivery to one unseen event. `recv` consumes that
event only when ready; dropping a pending receive removes its waker without
consuming an unseen event. Dropping a listener releases its table slot, whose
generation is checked and retired on exhaustion. Multiple drivers and runtimes
share the same process-wide ceiling. `ctrl_c` creates an interrupt subscription.

The permanent handler only updates a pending bitmap and writes one byte to a
nonblocking descriptor. An ordinary dedicated thread dispatches into the table
and invokes callbacks outside locks. Registration chains previous handlers and
preserves errno. Dropping all subscriptions does not restore default signal
behavior; the bridge, handlers and dispatcher remain for the process lifetime.
No API here is intended to be called from an application signal handler.
Unrelated concurrent handler replacement retains the registry's race limits.
This is a coalescing event port, with no exact signal-count or payload queue.
Metadata and the kernel socket buffer are outside managed-storage accounting.
Eight native tests, four real-signal subprocess cases and four actual-table
Loom models qualify the implemented contract; they do not model kernel delivery
or arbitrary application handlers.

## Composing two futures

`runtime::concurrency` supplies `join2`, `try_join2` and `select2` for borrowed,
local or owned futures. Each input has one ordinary pinned-box allocation;
there is no `Send`, `'static` or `Unpin` requirement. Each active input is
polled at most once per helper poll. Join helpers poll in argument order and
never repoll completed inputs. `select2` chooses either argument-order bias or
deterministic round-robin priority, alternating after polls where both inputs
remain pending. This is a two-input port; it does not provide arbitrary-arity
macros or disabled select branches. Both inputs are constructed by the caller
and owned immediately.

A completed input is destroyed before its output is retained. Failure or
selection destroys unfinished inputs and unused partial outputs before
returning the selected result. Cancellation drops both inputs; earlier side
effects remain committed. Poll panics resume after cleanup, with secondary
cleanup panics contained. When normal cleanup first panics, that primary panic
resumes after all other values are disposed. Cleanup during an existing unwind
preserves that unwind. Fifteen native tests cover polling order, cancellation,
borrowed and pinned inputs, retained terminal helpers and adversarial cleanup.

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

`AsyncJob::abort_handle` returns a clonable thread-safe control handle,
including for local jobs whose outputs are `!Send`. It retains cancellation
metadata rather than the future or result. `is_finished` becomes true when the
terminal outcome is published after future destruction and admission release.
Detaching a join alone leaves it false. It does not wait for completion callbacks,
discarded-output destruction or the later scope-close publication/reclamation.
The completion flag has native publication and cross-thread cancellation tests.
A Loom model races completion-observer registration against join publication;
it does not model the executor's entire cleanup and scope-close sequence.

The blocking pool's `Job` is also a future, so an asynchronous caller can await
blocking work without blocking an executor worker. Its existing consuming
`join` and deadlock checks remain available.

Loom exercises production task transition helpers and managed-ledger methods.
Some scope models are capped at 10,000 permutations and use a small generation
table. Full queues, worker parking, actual wakers, ownership and scope pointer
identity are outside those models; native lifecycle tests cover these paths.
The separately constructed epoll reactor and timer driver can wake executor
tasks; their registration limits are configured independently.

## Completion sets

`runtime::asynchronous::TaskSet` owns at most its configured number of async
joins, including completed but unconsumed results. Its table and notification
queue are reserved at construction. `try_insert` returns the original join
when full; `try_spawn` checks set capacity before executor admission and
returns the original future on either rejection. Slot generations and set
identities do not wrap; exhausted slots retire.

`join_next` yields a set-scoped ID and outcome in completion-notification queue
order. Simultaneous completions have no wall-clock ordering guarantee. Results
remain in their original join state until consumed, including any managed
buffer charges. A separate `poll_finished` observer supports notification
without consuming an `AsyncJob` result. Dropping a pending `join_next` removes
its parent waker and retains the jobs.

`abort_all` requests every cancellation, containing callback panics separately.
Set destruction requests all aborts before individually dropping the joins and
their retained results outside queue locks. Cancellation cleanup is asynchronous;
destruction does not wait for task cleanup or scope closure. Helper metadata
and caller results are outside the managed-buffer budget unless their storage
is explicitly managed.

Native tests cover publication/registration races, rejection, ordering, stale
generations, retained charges and panicking callbacks/destructors. Two Loom
models exercise the actual queue's notification coalescing and release race.
A separate join-state model covers completion-observer registration against
publication; these models do not cover the entire completion-set lifecycle.

## Current-thread local tasks

`runtime::asynchronous::LocalRuntime` polls owned local futures on the thread
that constructs it. Local futures and outputs may be `!Send`, but spawned
futures must be `'static`; the root future passed to `block_on` may borrow
caller data. The runtime, local handles, scopes, joins with local outputs, and
entry guards are thread-affine. `block_on` rejects nesting shared with the
multi-thread runtime.

`LocalHandle::enter` sets a separate local current context. The current value
is the most recently entered still-live guard, and dropping nested guards out
of order removes only the dropped context. During a spawned task's poll and
cleanup, `LocalHandle::current` refers to that task's scope.
Queued external tasks cancelled before import enter the root local context
while their futures are dropped.

`LocalConfig::max_outstanding` is one bound shared by local admissions and
queued cross-thread submissions. `max_scopes` includes the root scope. The
external `LocalSendHandle` accepts only `Send + 'static` futures and outputs;
its bounded channel is imported by the owner while `block_on` progresses. A
send handle cannot make progress when the owner is not polling. Rejected
submissions return the original future.

Each scope keeps FIFO order for tasks becoming ready, and ready scopes rotate
after one poll turn. Repeated wakes coalesce while a task is queued or polling.
Aborting requests cleanup after an active poll returns. Dropping a scope
requests cancellation; `close` waits for child cleanup, result publication
and scope-slot reclamation.
Dropping the runtime synchronously cancels and drops imported local futures on
its owner thread, so their destructors may run user code. All task polling,
future/output destruction, and join callbacks happen outside scheduler and
admission locks. The separately constructed epoll reactor can wake local tasks
while the owner polls the runtime. Borrowed spawned tasks, preemption and
CPU-time quotas remain outside the executor contract.
Future cleanup occurs on the owner thread. A join with a `Send` output can
move to another thread, where that output may be observed or dropped.

Native tests cover local FIFO/round-robin dispatch, stale task wakers, close
publication order and retained parking notifications. Existing Loom models
exercise shared task transition helpers; the local owner loop, admission gate
and notifier integration are not fully modeled.

The local runtime and its task-scoped types are deliberately `!Send`:

```compile_fail
use allocatbelt::runtime::asynchronous::LocalRuntime;

fn require_send<T: Send>() {}
require_send::<LocalRuntime>();
```

## Task-local values

`runtime::task_local::TaskLocalKey` supports synchronous `sync_scope` closures
and named asynchronous `scope` futures. `with` reads the active value and
`try_with` returns `None` without a value or after TLS destruction. Nested
scopes restore their enclosing value, including on panic. User closures and
destructors run outside TLS map borrows.

An async scope installs its value only during polling and inner-future cleanup.
The inner future is destroyed immediately on readiness, or during cancellation,
with its own value installed; then the enclosing context is restored. The
wrapper retains its value until wrapper destruction. If TLS is unavailable
during thread teardown, inner cleanup falls back to ordinary destruction
without an installed value. Synchronous entry rejects unavailable TLS before
running its closure.

The scope future can move between threads when its value and inner future are
`Send`; its value need not be `Sync`. Local `!Send` values remain supported.
Checked key IDs do not wrap. A pinned inner-future box, temporary synchronous,
per-poll or cleanup `Rc` allocations, and the TLS map are ordinary utility storage outside
the managed-buffer ledger. Native tests cover context and destructor ordering,
panic restoration, migration and real TLS teardown; compile-fail examples
check `!Send` relationships.

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
native tests cover them.

`TimerDriver::new_paused` returns a driver and clonable `ManualClock`.
`TimerHandle::now` exposes its current time; real elapsed time does not move it.
`advance` updates that driver's time monotonically and publishes due outcomes
through fixed batches on the advancing thread. Creation, reset, timeouts and
all interval policies use the same clock. It does not poll executor tasks or
automatically jump time when tasks are idle. Concurrent and reentrant advances
serialize clock updates; already-claimed callbacks can continue, and concurrent
close can resolve remaining registrations with `Closed`. Native tests cover
these behaviors; clock control is outside the two helper Loom models.

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

Compare blocking jobs with Tokio's blocking pool and owned asynchronous tasks
with its multithread executor. Use identical jobs, worker counts, outstanding
windows and completed-job checksums. Cross both runtimes with the same global
allocator to distinguish allocator costs from scheduling costs. Results from
one lane do not qualify the other.

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

The latency binaries also provide `--lane async --executor bounded|tokio`
with `ready`, `yielding` and `mixed` workloads. Both executors run the same
future body: immediate deterministic results, eight self-waking yield turns,
or eight yields with fully touched ordinary vector chunks. Mixed storage uses
each binary's global allocator, with no implicit managed-buffer reservation.
Choose `--workers`, `--window`, `--bytes`, `--jobs` and `--arrival-rate`
explicitly. The window must cover every worker and cannot exceed the requested
job count; construction warms all workers before timing and cleans up partial
warm-up failures. CSV records the admission window and byte count.

An independent producer uses intended arrival deadlines and a separate observer
polls each public join to ready. One common external admission window remains
held until that observation on either executor, including panic outcomes.
Latency includes producer lateness; rejections and lateness are reported
separately. Throughput mode avoids per-result latency samples but retains the
specified arrival schedule, so it measures completed work at that offered load
rather than establishing an executor's maximum capacity. Metadata, collector
and workload allocations contribute to whole-process CPU/RSS. These probes
require fresh native processes and the preregistered per-host confirmation
gates; functional tests and output smokes establish no speedup.

## Path toward replacing Tokio

The lifecycle foundation above is implemented. Remaining milestones include:

1. Task utilities and integration of resource permits into active polling.
2. Integrate the implemented timers, epoll readiness and owned filesystem APIs
   into application ports; complete remaining I/O utilities and socket adapters.
3. Complete synchronization, processes, signals and concurrency helpers;
   verify compatibility requirements against real Tokio application workloads.
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
