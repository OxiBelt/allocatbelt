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

`AsyncReadExt::read_to_end_bounded` and `AsyncBufReadExt::read_until_bounded`
copy into a fixed initialized slice and return the filled count plus a stop
reason that distinguishes delimiter, EOF and capacity. A full destination
(including an empty one) returns Capacity immediately: the future makes no
lookahead poll, so an exact fit cannot be distinguished from additional input.
Delimiter reads include the delimiter and consume only bytes copied, leaving
the buffered tail untouched. Each future exposes progress while pending or
before cancellation; completed I/O and consumed bytes are not rolled back.
Endpoint errors retain their kind and report partial progress. Each future
polls its endpoint at most 64 times per poll, including Interrupted retries,
then self-wakes and returns Pending.

`read_line_bounded` includes LF when present, while
`read_to_string_bounded` reads a whole stream. Line reads validate UTF-8 at
delimiter, EOF or capacity; whole-stream string reads validate at EOF or
capacity. They write into byte slices rather than growing a `String`. Invalid
UTF-8, including a code point cut by capacity, returns InvalidData with the
filled count while preserving the bytes in the destination. These helpers
provide bounded application ports, not global automatic cooperation for
arbitrary direct I/O polls.

`copy_bidirectional_with_buffers` borrows two endpoints that each implement
`AsyncRead` and `AsyncWrite`, plus two nonempty caller-owned initialized
slices, one per direction; either empty slice fails with InvalidInput before
any endpoint is polled. Each direction reads, writes everything it read, and at
source EOF flushes and then shuts down its destination's write side. The
reverse direction keeps copying while one direction waits, finishes or has a
pending shutdown, and the future completes only after both shutdowns succeed.
A completed flush or shutdown is not repeated. When a source waits after
writes that were not yet flushed, the direction owes a flush: it keeps that
flush across polls, including after an exhausted budget or a pending flush,
and polls it before reading or writing again until it succeeds, without
polling the waiting source again in the same poll. Half-close is only as
strong as the endpoint's `poll_shutdown`: registered TCP streams shut down
their write half, while an adapter whose shutdown closes the whole endpoint
ends or fails the reverse direction. The helper is a serial state machine
that alternates one endpoint call per direction and starts the next poll with the direction
whose turn came next. All reads, writes, flushes, shutdowns and Interrupted
retries of both directions share one 64-call budget per poll; it self-wakes
only when that budget runs out with work left, not when both directions wait
on their endpoints. Any other error, including WouldBlock, ends both
directions without further polls. The future exposes the bytes each
destination accepted (saturating at `u64::MAX`) and the unwritten range in
each slice, updated as each count is validated and still readable after an
error; dropping it keeps accepted bytes, completed flushes and shutdowns, and
unwritten bytes in the caller's slices without rollback or replay. Polling it
after completion panics. It allocates nothing, reserves no managed charges and
needs no endpoint split. Scripted native tests and a loopback TCP relay cover
these rules; they do not establish performance.

`AsyncReadExt::take` owns a reader and caps reads at a replaceable remaining
byte allowance without consuming bytes beyond it. `chain` owns two readers
and switches to the second only after a nonempty first read reports EOF.
Empty reads poll neither inner reader and do not switch sides; first EOF is
sticky, while Pending and errors do not switch. Both adapters require `Unpin`
endpoints for polling, expose recovery of their original endpoints and use
the trait's scalar vectored-read fallback. They also implement `AsyncBufRead`:
`take` caps the slice returned by `poll_fill_buf` and clamps `consume` to that
slice and its remaining limit, while `chain` returns the first available
buffer and routes consumption to that side. Pending and errors leave the
current side unchanged; an empty first buffer marks sticky EOF before the
second is polled. Pending reads do not spend the take limit, and cancellation
does not undo completed reads or a completed switch. Direct mutable access can
bypass the logical limit.

`empty`, `sink` and `repeat` are allocation-free ready endpoints. `Empty`
implements buffered reading, writing and seeking: it reports EOF, accepts and
discards all offered bytes, and returns position zero for every seek. Its
flush and shutdown are no-ops and later writes remain valid. `Sink` provides
the same stateless write behavior; `Repeat` fills initialized buffers with
its byte and needs an explicit limit for operations that wait for EOF. These
ports do not reserve managed storage or create any background work.

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

`runtime::split_io::split` pins one bidirectional endpoint and returns unique
read and write halves. It supports borrowed, local and `!Unpin` endpoints.
Poll methods on the endpoint are serialized; a busy direction records one
bounded waiter and is woken after the active poll releases the endpoint.
Endpoint methods, waker callbacks and destruction run outside the shared
state mutex. `is_write_vectored` reports the capability queried at split time.

`reunite` accepts only halves from the same split and returns `Pin<Box<T>>`
without moving the endpoint. A mismatch returns both original halves.
Dropping one half retains the endpoint; dropping the last releases it without
implicit flush or shutdown. Endpoint-owned managed charges stay with the
endpoint through reunite and end when its storage is actually released.
The pinning box and fixed shared metadata are ordinary allocations. Six
native tests cover pinning, ownership, callbacks and panic cleanup; one
actual-source Loom model checks poll exclusion and busy-waiter notification.

`runtime::io::pipes::pipe` accepts one nonempty, uniquely owned `ManagedBuf`
and returns unique reader/writer endpoints. `duplex` accepts two such buffers,
one per direction, and returns two bidirectional endpoints. Constructor
rejection returns every original buffer unchanged. Rings never grow or allocate
additional payload storage; their fixed shared metadata uses ordinary
allocations. Each buffer remains charged until both endpoints release it.

Reads and writes copy at most two contiguous ring spans under one direction's
mutex. A full ring waits for reads; an empty ring waits for writes or closure.
Writer shutdown closes only its outgoing direction: accepted bytes drain before
EOF, and duplex reverse reads remain usable. Dropping a duplex endpoint also
closes its incoming reader, discards that direction's queued bytes, and wakes
blocked peer writers to observe `BrokenPipe`. Empty admitted reads/writes
return zero and clear only their own retained waiter. Flush is immediately
ready and provides no durability guarantee.

A dropped borrowing future leaves accepted bytes committed and may retain one
bounded direction waiter. A later corresponding read or write poll that
completes, explicit `cancel_io_waits`, or endpoint drop releases it. Waker cloning, callbacks and destruction run
outside ring locks with panic containment. These endpoints participate in the
runtime's shared cooperative budget before changing state. Native tests cover
zero-budget preservation and bounded hot loops; three actual-source Loom
models cover ring transitions and lost-wake registration, not TLS budgeting.
The endpoints use scalar I/O and its vectored fallback; they do not expose a
borrowed buffered ring view across lock release.

## Blocking streams and standard I/O

`runtime::blocking_io::reader` and `writer` adapt owned `Read + Send + 'static`
and `Write + Send + 'static` streams to initialized-buffer asynchronous I/O.
Streams may be `!Sync` or `!Unpin`: each adapter boxes its stream and owns a
nonempty, uniquely owned caller-supplied `ManagedBuf`. Constructor rejection
returns both original inputs. The adapter uses a supplied blocking `Handle`
and explicit per-operation `Resources`; it creates no worker or private queue.
There is at most one retained job per endpoint. Each job performs at most five
underlying read, write or flush calls: the first attempt and four bounded
Interrupted retries. Other I/O errors retain their kind.

A reader uses its fixed staging buffer for read-ahead, retaining unread bytes
when a borrowing read future is cancelled or a later destination changes size.
A writer accepts bytes into its staging buffer only after job admission and
returns their accepted count in that same poll. Later polls drain the previous
job and unwritten suffix before accepting another input; they never attribute
cancelled-call progress to a new input slice. Partial writes commit only the
counts the underlying stream reports. Errors retain an unwritten suffix;
external side effects that a generic `Write` does not report cannot be rolled
back. Flush runs as a separate retained job after accepted writes drain.
Shutdown flushes and permanently stops new writes on this adapter.

Admission or resource-capacity rejection returns `WouldBlock`, restores the
adapter's owned inputs, and accepts no write bytes. There is no asynchronous
blocking-pool capacity notification; applications must explicitly retry or
abandon the operation. Dropping a borrowing future retains its job and progress.
Dropping an endpoint detaches the job: stream and charged staging storage remain
owned until actual completion and result cleanup. Queued `CancelPending`
cancellation drops the captured stream and storage and makes that endpoint
terminal. Started blocking calls cannot be preempted, so a read can delay pool
Drain indefinitely. Operation panics and recursive destructor-panic payloads
follow the existing contained blocking-job cleanup path.

`stdin_reader`, `stdout_writer` and `stderr_writer` use the standard library's
process-global handles and locking/buffering. Those global buffers, boxes and
fixed job metadata are ordinary allocations outside managed-memory accounting.
Staging storage stays charged to its actual owners. Logical writer shutdown
never closes a global descriptor. A pool with every worker blocked on stdin
cannot service its queued jobs until a read returns. These endpoints participate
in automatic per-poll cooperation; native tests cover ownership, cancellation,
rejection, partial/error progress, bounded retries and zero-budget preservation.
They do not establish a shutdown latency bound or performance benefit.

## General Unix pipes

`runtime::unix_pipe::pipe` creates an anonymous Linux pipe with
`CLOEXEC | NONBLOCK` and registers both descriptors with the caller's
`ReactorHandle`. If either registration fails, this constructor drops both
new descriptors and reclaims any registration it already made. `PipeReader`
and `PipeWriter` implement initialized-buffer `AsyncRead` and `AsyncWrite`,
including vectored operations, with the reactor's registration and waiter
bounds. They do not allocate userspace payload buffers or charge the kernel
pipe buffer to a managed-memory scope.

`from_owned_fd` imports one endpoint at a time. It checks FIFO type and
compatible access mode before changing flags or registering; it also rejects
`O_PATH` and writer descriptors with Linux packet-mode `O_DIRECT`. A refusal
returns the original `OwnedFd`; a registration refusal separately reports
any failure to restore the original flags. For a separately imported reader,
Linux does not expose packet mode on the imported read descriptor, so the
caller must ensure that its writer peer is not in packet mode. Imported
descriptors share `O_NONBLOCK` status with aliases; aliases must coordinate
flags for the entire endpoint lifetime: they must not remove nonblocking mode
or enable packet mode. Opening a FIFO path and importing the result is not descriptor-relative path confinement.

Each trait poll uses the same active-poll cooperative budget as other
allocatbelt primitives and then delegates to the bounded child-pipe readiness
poll. A pending read or write waiter remains owned by the endpoint after a
dropped poll; a completing poll in that direction (including an empty-buffer
poll), `cancel_io_waits`, endpoint drop, or writer shutdown releases it. Flush
does not clear a retained write waiter. Writer shutdown closes only that
descriptor. EOF waits until all writer descriptors and aliases close. Writes with no readers follow the
process's current `SIGPIPE` disposition; the module never changes signal
handling process-wide. Native regressions cover fd type/access recovery,
registration rollback, partial transfer, EOF, backpressure, waiter
cancellation, cooperative gating and the inherited signal policy.

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

`AsyncRuntime::scope_with_resources(&ledger)` and
`scope_with_config_and_resources(config, &ledger)` explicitly bind a managed
ledger to an owned Send scope. `LocalRuntime::scope_with_resources(&ledger)`
does the same for local tasks. Construction borrows the caller's ledger handle;
rejection retains that handle. Existing runtime roots and unbound scope
constructors keep their unbound behavior. `LocalSendHandle` imports into its
unbound local root.

During a bound task's poll and runtime-owned cleanup,
`try_current_resource_scope()` returns a clone of its ledger;
`current_resource_scope()` panics if no ledger is bound. This context also
covers producer-side destruction of detached results. Spawning follows the
target handle's explicit scope binding, never the spawning task's current
ledger. Rejection returns the unchanged future without installing the target
context. Nested calls and unwind restore the enclosing resource context.

A bound `AsyncHandle::block_on` exposes that handle's ledger to its borrowed
root, with no task ID. Runtime-root `block_on` clears the resource context
during its borrowed root and restores an enclosing context afterward. Values
returned to user code become caller-owned; dropping them later does not install
their producer's task context. Managed charges still follow their buffers and
permits through task completion, scope close and final release. Binding alone
charges no storage and imposes no accounting on ordinary allocations.

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

`OwnedFile::from_std` and `into_std` transfer ownership without I/O or a
disk-operation reservation. Existing descriptor aliases remain the caller's
responsibility; direct standard-file operations bypass the pool and ledger.
Open-file metadata, length and permission jobs return the same file on I/O
error. Metadata remains available after unlink; truncation preserves the
sequential cursor even beyond the new EOF. Once a one-call mutation starts,
its side effects cannot be cancelled or rolled back.

Path jobs include canonicalization, existence checks that preserve errors,
hard and symbolic links, permission changes, single-file copying and
empty-directory removal. Copy follows `std::fs::copy` behavior and returns the
copied byte count. It overwrites destination contents, follows a source
symbolic link, and follows an existing destination symbolic link. An I/O error
can leave a partially modified destination. Queued cancellation prevents the
copy from starting; a running copy cannot be interrupted or rolled back and
retains its disk permit until completion.
They retain standard filesystem semantics, including relative symlink
targets and path races. Canonicalization and existence are snapshots, not
security checks for later operations.

Directory iteration yields one entry per job. Entry metadata and type wrappers
also use disk permits. Returned raw `std::fs::DirEntry` methods can perform
blocking I/O directly if callers bypass these wrappers. Paths and open options
retain standard-library semantics; this API supplies no path sandbox, descriptor
quota, IOPS, bandwidth or disk-space enforcement. It does not collect whole
files or directories implicitly.

`FsHandle::walk_dir` and `walk_next` provide a depth-first path stream. The
caller sets finite entry, depth and path-byte ceilings and supplies a uniquely
owned charged `ManagedBuf` for each emitted path. The root is the first entry
at depth zero; symlinks are emitted but not descended. An entry-limit result
means traversal may be incomplete, while completion reports whether a
depth-limited directory was left unopened. The cursor bounds logical path
lengths and directory-frame count, while standard-library allocation rounding,
iterator state and temporary entry names remain uncharged. The output paths are
raw Unix bytes, so non-UTF-8 names are preserved. These ordinary path-based
operations reject a symlink at the final root component even with a trailing
slash, but an earlier component such as `link/.` can still resolve through a
symlink. Path replacement races remain, so this is not descriptor-relative
confinement. A `walk_next` call processes at most 64 frame/iterator steps;
terminal cleanup may additionally drop the bounded stack of up to 257 frames.

`runtime::fs_io::AsyncFile` implements initialized-buffer read/write/seek
traits over one `OwnedFile`, an explicit `FsHandle` and two caller-sized,
nonempty, uniquely owned managed staging buffers. Constructor rejection
returns every original input. It targets ordinary seekable files: the owned
read operation fills staging until full, EOF or error, so device/FIFO partial
availability does not imply completion. Use readiness-backed pipes for those
streams. Writes are accepted into fixed staging and submitted by flush,
buffer pressure, seek, read-after-write or shutdown.

The adapter retains admitted jobs and progress when a borrowing future is
dropped. Reading after accepted writes first completes those writes.
Write-after-read and relative seeks compensate for unread read-ahead to
preserve the logical cursor. Successful seeks discard old staging; failed
seeks retain it for retry. Partial write errors preserve only the unsent
suffix, so subsequent flush/shutdown does not replay committed bytes.
Pre-admission pool or disk-budget rejection restores the file/buffer and
returns `WouldBlock` with the typed submission cause; retry after capacity
becomes available.

Starting shutdown permanently rejects other operations. Retrying shutdown
drains accepted bytes and performs the underlying flush before closing;
admission or write errors retain retryable state. Once closed, later polls
return `BrokenPipe`. Dropping the adapter does not flush unsubmitted staging.
An already admitted operation retains its owned file, buffer and permit until
actual completion or queued cancellation cleanup. Runtime-wide
`CancelPending` can discard those queued inputs; the adapter then reports a
terminal service error and cannot recover them. Managed charges follow the
final buffer owner, including detached jobs. Job metadata and error values
are outside byte accounting. Eleven native tests cover cursor ordering,
partial/error retry, future cancellation, queued service cancellation,
shutdown and panicking waker destruction.

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
UDP endpoints support connected `send`/`recv` and non-consuming `peek` and
`peek_from`. Select the peer through the underlying standard socket's
`connect`, before or after registration; the kernel then filters received
peers. Empty sends produce datagrams, empty receives consume them, and peeks
retain the original message even when the supplied buffer is empty or short.
Named-method cancellation releases its readiness waiter. Descriptor aliases
can still compete for messages or change the connected peer.
Named read, write, accept and datagram methods preserve partial progress,
EOF and message boundaries. They retry interrupted calls and stale readiness
after clearing `WouldBlock`, yielding after 64 endpoint calls per poll.
Dropping a pending named method removes its waiter; transferred bytes remain
transferred. Binding and socket options use standard-library calls directly.
Filesystem-path Unix datagram APIs do not support abstract addresses.

`NetHandle::connect` keeps its blocking-pool behavior. The additive
`connect_nonblocking` and `connect_socket` methods instead use one explicitly
created or supplied nonblocking TCP socket, register it with the reactor, then
issue one connect syscall and wait for writable readiness. `TcpSocket` supports
IPv4/IPv6 creation, binding, local-address inspection, and import/recovery of
owned descriptors. `TcpSocket::listen` accepts a kernel backlog and returns a
registered `TcpListener`; an unbound IPv4/IPv6 socket may be autobound by the
kernel. Negative backlog values return the unchanged socket before the syscall.
A listen syscall error returns the same descriptor, but the syscall was
attempted and its kernel state may have changed; no rollback or retry occurs.
If reactor registration fails after listen succeeds, the error returns the
listening standard-library socket for recovery or later registration. The
kernel may clamp backlog to `somaxconn`; it describes the pending-connection
queue and does not reserve runtime operations or managed memory.

Supplied-socket connect admission or registration rejection returns the
original socket; after connect is attempted, errors close it and never replay
the syscall. Cancellation drops the readiness waiter and local socket, then
releases its network-operation permit. It cannot undo a handshake already
observed by the remote peer. Imported descriptors must be nonblocking,
close-on-exec, unconnected TCP stream sockets that are not listening. The
runtime cannot detect an external alias with an earlier connect in progress or
one that consumes `SO_ERROR`; callers must coordinate aliases. These methods
perform no DNS, address retry or timeout policy. The builder still lacks the
full `TcpSocket` option family.

The blocking `connect` and DNS resolver use the explicit bounded blocking
handle. A blocking network permit remains held while work is queued or running;
detaching a future retains worker captures until actual cleanup. DNS rejection
returns the original hostname and port. Registration rejection from blocking
connect returns the connected socket for recovery.

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
`reserve` waits for capacity before the caller constructs a message and returns
a borrowed permit; `reserve_owned` retains a sender clone and returns an owned
permit. Both permit forms return capacity when dropped. The owned form borrows
the original sender to create its clone, so a failed or cancelled reservation
does not consume the caller's handle. A permit's `send` returns the original
value if the receiver was dropped.

Receiver close rejects new sends and reservations, wakes `Sender::closed`
waiters, and allows queued messages to drain. A permit issued before that
close remains valid; EOF waits until each such permit is used or dropped. This
keeps `queue length + issued permits` within capacity. Receiver destruction
closes admission, revokes unused permits, and drops messages individually
outside locks, containing destructor panics. Receive futures remove their
stored waker on cancellation. `Sender::closed` uses its own bounded waiter
table, with the same configured waiter limit; registration can fail with
`ClosedWaitError::WaitersFull`, and cancellation removes only that waiter's
generation. EOF follows the last sender, unfinished owned send future, and
outstanding issued permits; a completed retained send future does not delay
EOF. Managed-buffer charges survive pending sends, queued messages and returned
results until final release. Queue metadata and arbitrary message allocations
are outside that ledger.

`runtime::oneshot::channel` transfers one value through a consuming synchronous
sender and an awaitable receiver. Send rejection returns the value unchanged.
Receiver close retains an already-sent value; receiver destruction discards it
outside the state lock. Dropping an unused sender wakes the receiver with
closure. `Sender::closed` uses a mutable borrow to bound closure notification to
one waiter, and dropping that future removes its waker.

Native tests cover message uniqueness, FIFO admission, cancellation, borrowed
and owned reservations, close/drain, EOF, bounded closure waiters, reentrant
and panicking callbacks, retained charges and Send/Sync bounds. Actual-source
Loom models cover queue close versus enqueue, reservation publication, permit
resolution versus receiver drop, EOF wakeup and closure-wait registration. They
do not model every channel/executor combination or arbitrary user callback
behavior.

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
Registration preserves the previous handler's calling convention, but does
not preserve every `sigaction` flag or an ignored disposition. In particular,
registering `SIGCHLD` must be coordinated with process wait ownership and any
existing auto-reap policy.
Eight native tests, five real-signal subprocess cases and four actual-table
Loom models qualify the implemented contract; they do not model kernel delivery
or arbitrary application handlers.

## Child processes

`runtime::process::ProcessDriver` reserves a fixed child slot before spawning
an owned standard `Command`. Full or closed admission returns the untouched
command. After an accepted spawn, setup failure retains the child and uses a
25-millisecond polling fallback if pidfd readiness cannot be registered.
A dedicated reaper owns admitted children independently of executor workers,
blocking-pool saturation, driver drop and application handle lifetime.

Dropping `ProcessChild` detaches by default; `set_kill_on_drop` opts into a
termination request. Explicit driver shutdown closes admission and either
waits or requests termination before waiting for actual reaping. A running
child or kernel operation can delay shutdown indefinitely. A slot remains
occupied through reaping, then becomes reusable while old handles retain
their own stable completion record. Dropping a pending `wait` removes its
waiter; a later wait still observes the cached terminal result.

`wait` closes stdin still owned by the handle, whereas `try_wait` does not.
The latter reads cached status rather than probing the kernel and may lag
exit by the fallback polling interval. `id` retains the original numeric PID
after reaping for diagnostics; the OS may reuse it. Handle kill methods use
the driver's guarded ownership checks. Pipe accessors transfer standard
handles. `runtime::process::pipe` converts them into `AsyncChildStdin`,
`AsyncChildStdout` and `AsyncChildStderr` through a supplied bounded reactor.
Callers must drain piped stdout and stderr concurrently to avoid blocking the
child. `runtime::process::output` supplies an owned bounded collector.

Pipe endpoints use initialized scalar and vectored I/O without allocating
userspace byte buffers. Each poll limits interrupted/readiness retries to
64 calls and retains one direction waiter when pending. Terminal or empty
read/write endpoint polls, explicit `cancel_io_waits`, endpoint drop and
stdin shutdown release the waiter. Flush has no buffered work and does not
cancel an earlier write waiter. Shutdown closes stdin to deliver EOF; it does
not stop or reap the child. Registration rejection returns the original
standard handle and reports both the primary error and any failure to restore
its original status flags. Five native tests cover simultaneous large output
drains, vector progress/EOF, stdin shutdown, waiter reuse and input recovery.

The output collector takes the child, both registered output endpoints and
two uniquely owned `ManagedBuf`s. Rejected construction returns every input
before closing stdin or reading a pipe. Accepted construction closes stdin
still owned by the child, then alternates bounded reads from stdout/stderr
and keeps its completion waiter until publication or cancellation. Returned
buffers retain their managed charges; no growable output allocation is used.

An exact-capacity output succeeds when a one-byte probe observes EOF. On
overflow, `ReturnPartial` returns the child, endpoints, retained prefixes and
the consumed probe byte so the caller can resume without losing data.
`KillAndWait` requests termination and drains excess output through fixed
stack storage before reporting reaped status and truncation. It preserves
the first overflow probe across both streams. Errors return recoverable
owned inputs and progress. Dropping a pending collector removes its waiters
and follows the child's configured detach/kill-on-drop policy; the process
slot remains owned by the reaper until actual reaping. A descendant that
retains pipe writers or a blocked kernel operation can delay collection
indefinitely. Nine native tests and independent wake-driven cases cover
simultaneous drains, exact/zero capacities, recovery, cleanup and charges.

The driver requires exclusive child wait ownership. Foreign `waitpid`, a
chained `SIGCHLD` handler that reaps children, and `SIG_IGN` or `SA_NOCLDWAIT`
auto-reaping are outside that contract. Observed `ECHILD` produces a tracking
error and releases the slot; it cannot prove the identity of a post-spawn
pidfd after foreign reaping permits PID reuse. Ordinary signal subscriptions
that do not reap children can coexist with the driver. Child memory, command
arguments/environment, standard pipes and fixed service metadata are outside
managed-storage accounting; the configured bound counts unreaped children.

Fourteen native tests cover lifecycle and completion, including saturation,
pidfd fallback, retained status, cancellation and reentrant waker destruction.
Three Loom models compile the production completion ledger and cover waiter
registration, publication, cancellation and retained completion identity.
They do not model OS spawn/wait/kill, pidfd identity or the reaper slot table.

## Composing futures

`runtime::concurrency` supplies `join2`, `try_join2` and `select2` for borrowed,
local or owned futures. Each input has one ordinary pinned-box allocation;
there is no `Send`, `'static` or `Unpin` requirement. Each active input is
polled at most once per helper poll. Join helpers poll in argument order and
never repoll completed inputs. `select2` chooses either argument-order bias or
deterministic round-robin priority, alternating after polls where both inputs
remain pending. This is a two-input port; it does not provide arbitrary-arity
macros or disabled select branches. Both inputs are constructed by the caller
and owned immediately.

`runtime::concurrency_many` adds homogeneous `join_all`, `try_join_all` and
`select_many` with an explicit branch ceiling up to 1,024. Rejection returns
the original input vector before consuming any element. Empty joins complete
immediately; an empty or wholly disabled selection is rejected. Disabled
futures are owned but never polled, and are destroyed before result
publication. Selection returns the original branch index and uses biased
order or deterministic round-robin starting priority after pending polls.

These helpers reserve ordinary bookkeeping and result-vector storage before
consuming inputs, then pin each active future in an ordinary box. Bookkeeping
reservation failure is recoverable; box allocation follows ordinary Rust
allocation-failure behavior. Managed storage is not implicitly charged.
Twenty native tests cover ownership, ordering, pinning, rejection and panic
cleanup. Randomized selection is outside these deterministic ports.

A completed input is destroyed before its output is retained. Failure or
selection destroys unfinished inputs and unused partial outputs before
returning the selected result. Cancellation drops the owned inputs; earlier side
effects remain committed. Poll panics resume after cleanup, with secondary
cleanup panics contained. When normal cleanup first panics, that primary panic
resumes after all other values are disposed. Cleanup during an existing unwind
preserves that unwind. Fifteen native tests cover polling order, cancellation,
borrowed and pinned inputs, retained terminal helpers and adversarial cleanup.

`runtime::concurrency_macros` exports `join!`, `try_join!`, `select!` and the
standard stack `pin!` macro. The composition macros also appear at the crate
root and accept two to sixteen heterogeneous branches. Joins return flat
tuples in source order; error joins require one error type. Each branch is
pinned in one ordinary box and partial join outputs are retained independently
until final tuple publication. No managed storage is implicitly reserved.

Selection uses an explicit policy and bracketed branch groups:

```rust,ignore
let result = allocatbelt::select! {
  round_robin;
  [
    (value = first_future, if first_enabled => use_first(value).await),
    (value = second_future => use_second(value).await),
  ];
  else => no_enabled_branch(),
}.await;
```

Patterns must be irrefutable and handlers must produce one common result type.
`biased;` starts in source order; `round_robin;` rotates priority among enabled
original branch indices after pending polls. All branch futures, including
disabled ones, are constructed and owned; disabled futures are never polled.
Every branch future is disposed before the winning handler or mandatory
all-disabled `else` runs. Handlers can borrow shared state and await. Captures
used only by losing handlers or `else` follow the enclosing async future's
lifetime and are not released early by selection.

These macros evaluate expressions once during their first poll, in source
order; selection evaluates each future before its enabled guard. Construction
expression/guard panics and captured values dropped before first poll follow
ordinary Rust cleanup. Once the complete branch set is owned, polling,
cancellation and branch/output cleanup contain secondary destructor panics
and preserve the primary panic. Published output tuples become caller-owned
and follow ordinary Rust destruction. Fourteen native tests include bounded
arity, pinning, trait propagation, disabled-branch rotation and subprocess
regressions for multiple panicking partial outputs. This syntax requires an
explicit application port; it does not claim Tokio macro compatibility.

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
that consumes from the shared per-poll budget and yields when the combined
primitive/checkpoint budget is exhausted. It cannot preempt code that does not
await it, and it does not impose a fairness or latency bound.

Runtime-owned outer polls also use a shared 64-operation budget for ready
`channel` send/receive/reservation/closed-wait, oneshot receive/close,
semaphore acquisition, mutex acquisition and reader-writer-lock acquisition
polls, plus `Notify`, watch change/closure, broadcast receive/closure and
barrier waits, managed-pipe, Unix-pipe and blocking-stream I/O polls, and
`Sleep`, `Timeout` and interval tick polls. A synchronous primitive-to-primitive
chain charges once; a primitive poll that returns `Pending` restores its
provisional charge. `Timeout` checks the budget before touching its timer or
inner future. Its ready result consumes one unit unless a ready supported
primitive inside the inner future already consumed one; charges made by inner
primitives remain spent when the timeout poll returns `Pending` or unwinds. Once
exhausted, the next supported primitive arranges a wake and returns `Pending`
before it dequeues a message, accepts a send, or transfers a permit/lock guard.
This applies only while the runtime is polling an owned Send/local task or a
borrowed `block_on` root.
Manual polls and futures driven by external executors bypass automatic
accounting. Other arbitrary futures are not automatically cooperative; long-running
work outside the listed primitives still needs explicit checkpoints or its own
bounded polling. Other direct I/O endpoint
polls, including `AsyncBufRead`, are outside this automatic accounting; the
looping I/O helpers and buffered endpoints enforce their own 64-call-per-poll
limits.

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
`AsyncJob::id` and `AbortHandle::id` return the same opaque process-wide
`TaskId`, retained after completion and task-slot reuse. Native, owner-local
and cross-thread local submissions share a checked nonwrapping identifier
allocator; accepted cross-thread handles already have an ID before import.
Exhaustion rejects submission with the original future, and rejected attempts
may leave numeric gaps. `try_task_id` reports the spawned task during polling,
future cleanup and producer-side discarded-result cleanup; `task_id` panics outside that
context. Borrowed `block_on` roots have no spawned-task ID and restore an
inherited context afterward. Task IDs are distinct from `SetTaskId` membership
tokens. Four native identity tests and independent detached-cleanup cases
verify this contract; existing Loom models do not prove numeric uniqueness
or counter exhaustion.
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

## Per-scope active polling

`AsyncRuntime::scope_with_config(AsyncScopeConfig { max_active_polls })`
adds a nonzero simultaneous-poll limit to an owned Send scope. Existing scope
construction uses the worker count. A configured limit above that count is
accepted; the fixed worker pool remains the overall concurrency ceiling.
`OwnedTaskScope::snapshot` reports unfinished tasks, reserved poll slots and
the configured limit. Poll slots are sampled under the scheduler lock;
unfinished-task counts may change concurrently. A slot is reserved before
dispatch and held through the future's poll return, so it can include work
about to enter `Future::poll`.

A saturated scope parks its ordinary ready queue without spinning. Other
dispatchable scopes continue equal round-robin scheduling, one poll per turn.
Ordinary ready work retains FIFO order when capacity reopens. Cancellation
cleanup can pass ordinary work in a saturated scope and consumes no poll slot.
The slot is released before future destruction or completion publication,
including panic cleanup. Outstanding-task admission remains charged through
future cleanup and is released before join publication; it is a separate
limit. Scope unfinished-task bookkeeping completes after publication.

This bounds simultaneous polling, not CPU time. A future can block a worker
inside a poll, and destructors can block during quota-free cleanup. There is
no preemption or implicit managed-storage reservation. Current-thread local
execution already polls one future at a time. Native tests exercise saturation,
cross-scope progress, FIFO resumption, cancellation, shutdown, slot reuse and
cleanup; a same-source Loom model checks poll-slot acquire/release transitions.

## Explicit cgroup controls

`runtime::cgroup::CgroupV2` accepts an owned directory descriptor for a
caller-supplied cgroup v2 group and finite `CgroupCeilings`. The application
must arrange delegation and isolation. The library checks the filesystem and
descriptor, but does not discover or mount a host root, attach processes,
prove delegation, or change controls on construction. Control names are fixed
and opened relative to that descriptor with symlink following disabled.

`set_cpu_max`, `set_memory_high`, `set_memory_max` and `set_io_max` validate
requests before writing and return bounded readback. CPU quotas are compared
as ratios; memory limits must be aligned to the actual kernel page size.
Validation excludes kernel numeric unlimited sentinels and device-number
aliases. I/O requests validate the entire batch against explicit per-device
ceilings before its first write. Readback accepts at most 16 distinct devices
and 4096 bytes per control; larger or malformed records return typed errors.
The finite ranges follow the Linux 7.0 implementations of
[CPU bandwidth controls](https://github.com/torvalds/linux/blob/v7.0/kernel/sched/core.c),
[memory page counters](https://github.com/torvalds/linux/blob/v7.0/mm/page_counter.c)
and [I/O throttling](https://github.com/torvalds/linux/blob/v7.0/block/blk-throttle.c).

Ceilings restrict submitted values; they do not establish limits for existing
or unmentioned controls. Each control record uses one write, without replaying
a suffix after a short write or error. Setters are separate kernel effects,
and a multi-device update can fail after earlier entries were accepted. Typed
errors retain the requested control, accepted-entry count and any available
observed state. `observed = None` means state is unknown. There is no rollback
or automatic restoration on drop. The kernel still checks permissions,
controller availability and additional control constraints.

Snapshots read four controls separately and are not atomic. Concurrent setters
or other processes may change values during or after readback. These APIs are
synchronous: memory limit writes can reclaim, block or trigger OOM handling
in the supplied group. Applications should use a bounded blocking lane where
appropriate. Fixed control buffers, descriptors and kernel resources are
outside the managed-storage ledger. Ten parser and validation tests do not
write host controls. An isolated native Linux cgroup-namespace integration
check verified CPU and memory writes/readback in a delegated descendant group,
and unchanged readback after invalid requests. The namespace root correctly
rejected a control write. Positive device I/O writes remain unqualified;
controller and deployment-specific behavior requires further integration
checks. These checks establish correctness, not application performance.

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

`--mode capacity` is available only for the blocking and async lanes. It
keeps the configured outstanding window full without an arrival schedule,
refilling only after the observer sees a public join ready and releases its
handle. A full window waits on a condition variable. Both executors warm all
workers and run the same job body; any rejection, panic, checksum mismatch or
completion loss fails the run. Blocking capacity accepts `--window`; paced
blocking retains its existing admission bound. Capacity rejects an explicit
arrival rate and reports `NA` for arrival rate, lateness, timer overhead and
all percentiles. Its throughput includes submission and collection costs.
It establishes no p99 result; use the separate paced latency lane for tails.

`scripts/bench-latency.sh` supports these lanes and validates all 22 binary
CSV fields, checksums and explicit worker/window/byte configuration. It
alternates fresh-process comparator order and records source and binary
fingerprints. Supplying `--bin-dir` labels rows as unverified prebuilt evidence,
even when functional validation passes. Capacity tests and small process
smokes verify accounting and cleanup, including cleanup before window refill;
they are not native performance qualification.

## Bounded original-thread blocking handoff

`AsyncRuntime::new_with_handoffs(AsyncConfig, HandoffConfig)` prestarts a fixed
number of helpers. Ordinary `new` keeps its original worker count and disables
handoff. `try_block_in_place` runs its closure on the calling thread, accepting
borrowed or `!Send` closures and results. Disabled/full/local-executor rejection
returns the uncalled closure. Outside owned dispatcher execution it runs inline;
entering a local handle alone does not constitute local execution.

With `W` workers and `B` helpers, at most `W` dispatcher turns and `B` handed-off
closures are active. Reserving a loan precedes releasing the dispatcher permit.
The original task retains admission, its running state and its scope poll quota
throughout the closure. A still-pending same-scope dependency cannot make
progress if the scope quota is exhausted; use a separate scope or an explicit
higher quota. The default root quota remains `W`. The dispatcher bound covers
owned dispatch, not CPU time, nested borrowed roots or external threads.

Return or panic reacquires a dispatcher permit ahead of new work, retaining the
loan until restoration; this also works after admission closes. Helpers can
hand off under the same fixed bound, while nested handoff on the original
already-loaned thread runs inline. Task identity, explicit resource binding,
task-local values and runtime-worker shutdown identity remain intact. The
closure may call a nested handle `block_on`; its borrowed root has no task ID,
and budget/context markers restore on return or unwind.

Abort and cancelling shutdown cannot preempt the closure. Explicit shutdown
joins every worker/helper and may wait indefinitely; worker-origin shutdown
returns `WouldDeadlock`, including from a handed-off closure. Runtime drop
closes admission and detaches. Thread caches flush before handoff/parking.
Native lifecycle tests and bounded same-source coordinator Loom models qualify
these semantics. The models cover permit/loan accounting, not the full
scheduler, condition variables, TLS or a performance benefit.

## Owned-buffer runtime io_uring

The separate `runtime-io-uring` feature implies `runtime` and exposes
`runtime::uring`. `UringRuntime::start(UringConfig, ResourceScope)` starts a
dedicated issuer and completes its setup/probe/restriction handshake before
returning a handle. Capacity must be in `1..=1024`. Setup denial returns a typed
stage/error before admission; no automatic fallback or allocator purge-policy
change occurs. `CompiledCapabilities::runtime_io_uring` reports compiled code,
while successful startup establishes that this driver was permitted.

`try_read_at` and `try_write_at` take an owned regular-file descriptor, unique
`ManagedBuf` and checked offset, returning the original inputs on admission
rejection. Direct/path-only descriptors, incompatible access, observed append
writes, shared buffers and overflowing extents are refused. The caller must
keep shared file-status flags stable through all descriptor aliases while the
service owns the descriptor. Each request is one positional operation, and a
short completion returns its byte count and original owners without replay.
Zero-length accepted operations finish locally.

Fixed admission slots count queued, claimed, published, completing and
completed-unclaimed requests. Dropping a queued future cancels before claim;
after claim, dropping detaches observation and retains inputs until the original
CQE. Disk operation permits are released after actual I/O cleanup and before
completion publication; managed memory remains charged through the final
buffer owner, including returned results. Slot generations retire on exhaustion.
Waker callbacks and payload destruction run outside the ledger lock.

Explicit `shutdown` closes admission, drains accepted work and joins the issuer;
it can wait indefinitely for kernel I/O and rejects issuer-thread self-joining.
Dropping the service closes admission and detaches while the issuer drains.
Closing a ring descriptor is not a synchronous buffer-release barrier. If
published ownership becomes uncertain, the initial backend aborts the process
before kernel-visible owners can drop. It does not cancel, recreate, quarantine
or replay uncertain operations. Fake-driver and slot-protocol Loom tests cover
bounded lifecycle transitions, not kernel execution. Real-kernel tests with
`ALLOCATBELT_REQUIRE_IO_URING=1` fail on denied setup, distinguishing permission
failure from a successful kernel transfer/fail-stop qualification. No native
performance benefit has been established for this optional service.

## Explicit adaptive cgroup feedback

`runtime::adaptive::AdaptiveController` takes an already-delegated `CgroupV2`
capability and copies two to sixteen strictly increasing finite CPU/
`memory.high` tiers. All CPU periods must match. Every tier is validated
against the capability's immutable caller ceilings and the already-established
finite `memory.max`, which must itself fit its caller ceiling. Startup only
reads controls and requires the current CPU/high pair to match a configured
tier. The controller never changes `memory.max` or I/O limits.

The caller supplies measured p99 and CPU/memory utilization on a monotonic
`Instant` clock. High/low bands, sustained sample counts, minimum sampling
interval, maximum gap and nonzero bounded cooldown limit oscillation. A
sustained breach raises one tier; sustained healthy recovery lowers one tier;
neutral samples and long gaps reset streaks. The floor and ceiling stop further
changes. Invalid/early/stale samples do not advance policy; explicit resume
retains the timestamp watermark and resets interval/cooldown requirements.
No sensor or background thread is created, and this policy has not established
a p99 improvement.

Before a transition, readback must still match the tracked tier and original
`memory.max`. CPU is applied before `memory.high`, as separate synchronous
writes with separate nontransactional snapshots. Lowering memory.high may
reclaim or block. Any failed setter, readback, cross-control mismatch or drift
latches the controller faulted, preserving confirmed partial progress and the
last observed snapshot separately from unknown current state. Later automatic
observations cannot write until explicit `resume_from_readback` finds a known
tier with the original memory.max. No rollback, retry or replay occurs.
The caller must coordinate descriptor aliases and other writers: readback can
detect observed drift but cannot prevent a race between different control
files. Pure policy/fault-injection tests cover these limits. A correctness-only
native integration in a private container cgroup descendant verified actual
CPU and `memory.high` promotion/recovery, cooldown, floor/ceiling, drift faulting
without replay and explicit readback recovery. The fixture uses synthetic
caller-clock samples and does not establish response under real resource
pressure or a native application benefit.

## Path toward replacing Tokio

Task utilities, resource-bound polling, the synchronization families,
processes, signals, concurrency helpers and explicit cgroup feedback are
implemented with the contracts above. The stable Linux Tokio 1.53.1 capability
baseline still requires these implementation and qualification steps:

1. Extend automatic cooperative progress beyond the currently listed
   operations. Expand TCP socket-option coverage beyond the explicit-address
   nonblocking connect, listen and bound-socket operations.
2. Add FIFO path constructors. Owned blocking streams, standard I/O adapters,
   anonymous Unix pipes, managed
   in-memory simplex/duplex pipes and caller-buffered bidirectional copy are
   implemented with explicit partial-progress and half-close contracts. The initialized-buffer `Take`/`Chain`/`Empty`/`Sink`/`Repeat` family,
   bounded delimiter/line and whole-stream reads, and fixed managed buffered
   endpoints are implemented; these do not include those remaining operations.
3. Exercise realistic application ports covering cancellation, bounded
   rejection recovery, resource/dependency quotas, retained managed storage,
   partial I/O and explicit driver/process shutdown. The existing CPU, memory,
   limited TCP/HTTP and disk examples establish functional ports only.
4. Finish complete isolated core Miri and supported platform, feature, package
   and security-tool qualification, preserving failures and model-coverage
   limits. Complete per-host retained-memory, allocator, executor and application
   gates against both mimalloc baselines and matched-allocator Tokio, separating
   saturated capacity from open-loop tail-latency workloads.
5. Qualify adaptive controls under real resource pressure, overload and
   readback failures. Synthetic policy samples and control-write integration
   establish correctness, not pressure response or application performance.
   Promote scheduler, allocator and ISA candidates only after their required
   correctness and native throughput, tail-latency and memory gates pass.

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
