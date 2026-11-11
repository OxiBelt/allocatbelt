# unsafe boundary inventory

`allocatbelt` is one package with responsibility-focused modules. `core` (`crates/allocatbelt/src/core/`) carries `#![forbid(unsafe_code)]` as an inner attribute, so it contains **0** `unsafe` sites, and the `publish = false` package `allocatbelt-core-check` compiles the same source as a `#![no_std]`, `#![forbid(unsafe_code)]` crate of its own, which runs the core's tests, the checking model and loom. The optional `runtime` module also carries `#![forbid(unsafe_code)]`; its
blocking and owned-future implementations are shared with the unpublished runtime façade
and remains safe. Runtime signal installation, fixed TCP option syscalls and
the inline async task future cell add narrow `sys` boundaries listed below. Library `unsafe` is in `sys`, `arch`,
`global` (with `rseq`) and the opt-in `region` API; benchmark-only `unsafe` is
limited to the diagnostic allocator wrapper and SIMD candidates, listed below.
Every `unsafe` block holds exactly one unsafe operation and carries a
`// SAFETY:` comment (`clippy::undocumented_unsafe_blocks` and
`multiple_unsafe_ops_per_block` are deny).

Regenerate: `grep -rn "unsafe" crates/allocatbelt/src bench/src/bin/bench-runtime-diagnostic.rs bench/simd/src | grep -E "unsafe (\{|fn|impl|extern)"`

## `sys` (`crates/allocatbelt/src/sys/`)

`Region`, `MetaArena`, `register_atfork` and `set_batch_scheduling` are in `sys/mod.rs`, `probe` in `sys/platform.rs`.

| Location | Kind | Operation | Why it is sound |
|---|---|---|---|
| `Region` | `unsafe impl Send/Sync` | — | It is an address-range handle and exposes no references. Mutation happens only through syscalls. |
| `Region::reserve` | block | `mmap_anonymous(null, …, PROT_NONE, PRIVATE\|NORESERVE)` | A null hint without MAP_FIXED yields a fresh range, so it aliases nothing. |
| `Region::reserve` | block ×2 | `munmap` of the head/tail slack left after alignment | Trims only the unused ends of the mapping created just above. |
| `Region::commit` | block | `mprotect(RW)` | Range checked; it only adds permissions, so it cannot invalidate any existing reference. |
| `Region::purge` | **`unsafe fn`** + block | `madvise(MADV_DONTNEED)` | The contents are discarded, so the caller guarantees "no live references or concurrent access in the range". Returns whether the kernel accepted it, i.e. whether the range now reads as zero. |
| `Region::decommit` | **`unsafe fn`** + block ×2 | `purge` + `mprotect(NONE)` | Same contract, plus no access until the range is committed again. |
| `Region::guard` | **`unsafe fn`** + block ×2 | `guard_markers`, else `mprotect(NONE)` | Same contract as `decommit`: nothing may use the range until it is unguarded and committed again. |
| `Region::guard_markers` (private) | **`unsafe fn`** + block ×2 | `madvise(MADV_GUARD_INSTALL)` (`libc`, Linux 6.13+), checked by `madvise(MADV_POPULATE_READ)` failing with `EFAULT` | Same contract as `guard`: the markers discard the contents and fault on access. The populate probe only read-faults pages in; it exists because emulators such as qemu-user report success for advice they ignore. Removes the markers again when they did not take effect. |
| `Region::unguard` | block | `madvise(MADV_GUARD_REMOVE)` (`libc`) | Range checked; removing guard markers only turns faulting pages into zero-fill pages and leaves other pages alone, so it cannot invalidate memory in use. |
| `register_atfork` | block | `pthread_atfork(prepare, parent, child)` (`libc`) | The handlers are `extern "C" fn()` items, valid for the life of the process and safe to call. glibc allocates the registration with its own `malloc`, not through us. |
| `MetaArena::slot` | block | `slice::from_raw_parts` → `&[AtomicU64]` | Published only after commit (READY, Acquire). Never unmapped or purged. Zero-filled by the kernel, so every bit pattern is valid, and only atomic access follows. |
| `platform::probe` | block ×5 | `write_volatile` / `read_volatile` of one byte, `Region::purge`, `Region::guard_markers`, `Region::decommit`, all on a 64 KiB scratch `Region` the probe reserves itself | The scratch range is private to the function: no reference to it exists and nothing else knows its address, so writing, purging, guarding and decommitting it cannot affect any other memory. The byte is written and read only while the range is committed read/write (a purge keeps it accessible). Runs once, before the arena is reserved ([docs/platform.md](platform.md)). |
| `set_batch_scheduling` (feature `scheduler`) | block | `libc::syscall(SYS_sched_setscheduler, 0, SCHED_BATCH, &param)` | The kernel only reads `param`, a live `#[repr(C)]` local with the UAPI `struct sched_param` layout (one `int`, 0 as `SCHED_BATCH` requires), and changes only the calling thread's policy (pid 0 is the caller). A raw syscall because rustix has no binding and musl's `sched_setscheduler` wrapper always fails. Called once, by the maintenance thread. |

### `sys/runtime_signal.rs` (optional `runtime`)

Explicit signal subscription uses `signal-hook-registry` to preserve previous
handler ABI and the interrupted errno. Installation allocates ordinary registry
metadata outside allocator hot paths. The callback and its nonblocking descriptor
remain valid for the process lifetime, including a reported installation error;
at most one installation attempt is made per supported signal. A listener slot
is reserved before installation. Dispatcher startup must succeed first.

| Location | Kind | Operation | Why it is sound |
|---|---|---|---|
| `register` | block | `signal_hook_registry::register` | The validated signal excludes the registry's forbidden set and libc-reserved signals. The fixed callback captures only a process-lifetime atomic bitmap and borrowed descriptor, updates a lock-free bit and performs an async-signal-safe one-byte write, retrying interruptions. It never allocates, locks, panics or calls user code. The registry preserves errno and chains prior handlers. |

Listener polling, delivery and callbacks stay in the safe runtime. Real-signal
tests change dispositions only in subprocesses; actual listener-table Loom
models cover cancellation, slot reuse and registration versus delivery/close.
Handlers persist after subscriptions drop; unrelated concurrent application
handler replacement has the registry's installation-race limitations.

### `sys/runtime_task_cell.rs` (optional `runtime`)

A native async task is one `Arc`: `TaskCell<H, F, O>` stores the runtime's
bookkeeping `H` next to the user future `F` instead of boxing the future a
second time, together with the task's atomic word, its outcome `O` and its
one join waker. Soundness of the future rests on structural pinning, not on a
check: the cell exists only as the `Pin<Arc<TaskCell<H, F, O>>>` that its
constructor `TaskCell::new_with_join_queued` (and, in tests, `TaskCell::new` and `TaskCell::new_with_join`) returns, no API gives out the cell by value, by `&mut` or as
an unpinned `Arc` or `Weak`, the methods that touch the future
(`poll_future`, `drop_future`) take `self: Pin<&Self>`, and the cell is never
`Unpin`: the module holds the cell's one `Unpin` impl behind a bound that
never holds, so no other code can write one, and safe code has no way out of
the `Pin`. The pin
guarantee of `Arc::pin` therefore holds for the future from its first poll
until `Drop` runs in place, for any safe caller and any call order. The
bookkeeping is reached only by shared reference (`header`); a turn's `Waker`
is borrowed from the slot's owner through its lease (below), and the
test-only `into_waker` and `waker` build one from an owner. Either shares
the allocation without another allocation. Unsizing
the handle to `Pin<Arc<dyn Trait>>` keeps all of this, and the runtime's
erased task, join and abort handles are such pinned `Arc`s.

Every claim of the value (`poll_future`, `finish`, `drop_future`) takes a
`ValueKey`: proof, built only by the module, that the caller holds the task
word's `RUNNING` for this allocation. A `Lease` (`TaskSlot::lend` won
`RUNNING` from the queued state), an `IdleTask` (`TaskSlot::take_idle` won it
from an idle or queued word and never ends it) and, in tests only,
`TaskCell::claim_turn` (one compare-and-swap on the word) are the only
sources; a key borrows its source, so it cannot outlive the turn, and no
source is `Sync`, so a turn's keys stay on one thread; a key
for another allocation panics before the value is touched. At most one turn
holds `RUNNING`, and each turn's start reads, with Acquire ordering, the word
the previous turn's end wrote with Release ordering (both read-modify-writes
on the word), so keyed claims never overlap and each follows everything the
previous key holder did; the only other access is the cell's own `Drop`, which
is exclusive. One `AtomicU8` then records
the value's state: `poll_future` moves `PRESENT` → `POLLING` with a load and
a store (no other claim can run between them) and releases with one release
store (`PRESENT` after `Pending`, `COMPLETE` after `Ready`, `POISONED` if the
poll unwinds); a reentrant poll from inside the future, even with a key,
finds `POLLING` and is rejected. `drop_future` and `Drop` move `PRESENT`/`COMPLETE`/`POISONED` →
`ABSENT` with an acquire-release compare-and-swap loop (a failed
compare-and-swap reads the latest state, unlike the plain load that
`fetch_update` starts with) and drop in place exactly once. `finish` moves
any of those states or `ABSENT` → `STORING` the same way, drops a value still
present in place, writes the outcome once and releases into the final
`STORED`, even when the destructor or the outcome builder panics.

The outcome and the join waker are handed between threads by the task word,
whose transitions are the safe `sys/runtime_task_word.rs` (a private module
of the cell; Loom compiles the same file into the runtime's stand-in, so the
models exercise it). The runtime sees only the word's scheduling operations
(`TaskWord`: notify, begin, pending finish), which never touch the complete
or join bits. `publish` loads `STORED` with acquire ordering before it sets
`COMPLETE`, so the one write happens before any read; afterwards the outcome
belongs to the join handle if `JOIN_INTEREST` was set at publication and to
the publisher otherwise. The join handle (`TaskJoin`) is created once, with
the cell, and its operations need a key only the word module builds, on a
sealed trait only the cell implements, so the join side is one non-shared
owner. The waker cell holds two fixed slots (join and completion-only), both
written only by that handle. It writes the cell only while `JOIN_WAKER` is clear and the word
was not complete, then sets `JOIN_WAKER` with a compare-and-swap that fails
once complete; while `JOIN_WAKER` is set both sides only read the cell, and
the side that last leaves it (publication after clearing `JOIN_WAKER`, or the
handle after it cleared `JOIN_INTEREST`) drops the waker, decided by one
read-modify-write each on the word. Any other state,
including a reentrant claim from the future itself, is rejected without
touching the value; a claim on another thread cannot start while a turn holds
the key. A poll on one thread and a drop or the next poll on another are
ordered by the word's turn hand-over and the cell's release store.

Its unit tests run under Miri in CI (Stacked and Tree Borrows, several seeds)
and cover completion, drop before and after completion, a panicking poll and
destructor (through `drop_future` and through the cell's `Drop`), reentrant
(including a second key for the same cell presented from inside the poll),
concurrent and racing polls (each under a turn claimed on the word), a key
for another task (rejected), a destructor that reenters its cell, a
self-referential `async` block, a `RefCell` borrow held across a yield, an
intrusive registration of the future's own address that only its `Drop`
withdraws, wakers sharing the allocation, and the cross-thread hand-overs
(poll on one thread, drop or the last owner's `Drop` on another, synchronized
only by `Relaxed` flags and the word's turn hand-over). A test checks that the cell is
never `Unpin`. Moving a polled cell out of its allocation, for example out
of a box or an `Arc`, cannot be written against this API; the sound forms of
those cases (drop in place) are tests. Loom compiles the runtime without `sys` and models a boxed stand-in
with the same state machine and pinned-handle API, so Loom does not cover
this cell's unsafe code; it does run the shared word and join transitions,
with stand-in cells that fail on any access overlapping an exclusive one, a
stand-in claim that uses the same keyed load and store and fails when two
claims overlap, and a stand-in published pointer that fails when a read is
not ordered after the publication and before the slot's release.
Further Miri-checked tests cover `finish` (once, refused during a poll, a
panicking destructor), publication before and after a store, waker keep,
replace and single wake for both waker slots, publication without a join
handle, a join handle built from another allocation (rejected), and
registration (including a join registration racing publication with a
completion-only waiter stored) or detach on one thread racing publication on
another.

`TaskSlot` holds the scheduler's one owner of a task and lends it to one
turn at a time. `TaskSlot::lend` begins the turn with a compare-and-swap that
sets `RUNNING` only from the queued state, and returns a `Lease` holding the
pointer `Arc::as_ptr` gives for that owner. `RUNNING` is cleared only by the
lease (its pending finish, its return of an unrun turn to the queued word,
or its `Drop` if the turn is abandoned) or kept
when `TaskSlot::take` hands the owner to the final turn; until then no slot
drops or releases the owner (`take_idle` and `Drop` refuse while `RUNNING`,
`Drop` then keeps the allocation alive, `install` refuses an occupied slot,
and `take` needs the lease), and the word is reached only through the sealed
`TaskLend`, so it is the cell's own. The lease's pointer is therefore valid
for every borrow of the lease. `Lease::waker` builds a `Waker` from that
pointer with a vtable whose `clone` adds a strong count and whose `wake` and
`drop` give one back; the borrowed waker itself is never dropped and cannot
be woken by value. `take_idle` wins `RUNNING` with a compare-and-swap that
fails while a turn holds it or once complete, and never ends it, so no lease
can begin after the idle owner left the slot.

`PublishedTask` is the slot's copy of its installed owner's pointer, which a
dispatcher reads without the lock that guards the slot to begin the turn
(`PublishedTask::lend`). Only `TaskSlot` writes it: `install` writes it
before the task's first queue entry is inserted, and `take` and `take_idle`
clear it as they give the owner up, so a published pointer always names a
live owner; `install` panics unless the cell is empty, and `take` and
`take_idle` panic unless the cell holds the owner's own pointer, so a slot
cannot give its owner up while another cell still names it. `lend` is the
module's one API whose soundness depends on the caller: the caller holds the
task's queue entry. The runtime's queues hold at most one entry per task
(the word's `NOTIFIED` decides who inserts it), the entry's insertion orders
`install`'s write before the read, a final turn consumes the entry before
`take` clears the pointer, and `take_idle` and the slot's `Drop` run only
when no dispatcher exists. Miri-checked tests cover lending, refusal of a
second lease and of `take_idle` during a turn, borrowed and cloned wakers
(wake by reference and by value, the last owner being a clone), a dropped
lease, a lease returned to another slot and a slot cleared through another
publication, an idle take through another task's cell and an install into a
published cell (all rejected), an idle take of a queued task (its entry then
begins nothing), and the dispatch discipline around a published pointer:
dispatch through the pointer to the final turn and the slot's reuse, the
same on two threads with the next occupancy published on the other, an idle
take after the dispatchers left, and a turn begun on the task word without
the slot mutex racing an abort on another thread.

| Location | Kind | Operation | Why it is sound |
|---|---|---|---|
| `TaskCell` | `unsafe impl Sync` (for `H: Sync`, `F: Send`, `O: Send`) | — | The value is reached only through `poll_future`, `finish` and `drop_future`, each of which needs a `ValueKey` that only the one holder of the word's `RUNNING` can build and then claims the cell (`POLLING`, `ABSENT`, `STORING` and `STORED` accept no further claim of the value), and through the exclusive `Drop`, so two threads never hold references to it at once. The outcome is written once under `STORING` and later reached by exactly one party chosen by publication's word update; the join waker is written only by the one join handle while the word gives it the cell and otherwise only read. The atomics are shared freely and the header is a plain shared field. The same reasoning makes `Mutex<(F, O)>` `Sync`. |
| `TaskCell::unpinned` (test only) | block | `Pin::into_inner_unchecked` of one owner of the pinned `Arc` (the caller's own, or a clone) | Private. The unpinned `Arc` goes only to `Waker::from`, whose vtable hands it back solely to this module's `Wake` implementation (which reads the header and never moves out of the `Arc`) and otherwise drops it in place like any owner, or to a strong count in tests; no unpinned `Arc` or `Weak` reaches a caller, so the allocation stays pinned until its last owner drops it in place. |
| `TaskCell::poll_future` | block | `&mut *pointer` into the `UnsafeCell<ManuallyDrop<F>>` | The caller's key proves it holds the turn, so no other claim runs between the `PRESENT` load and the `POLLING` store, and a reentrant claim finds `POLLING`; no other reference exists while the claim is held; both wrappers are `repr(transparent)`, so the cast pointer is the initialized, aligned `F` the cell was built with, not yet dropped (`drop_future` and `finish` refuse `POLLING`, and a value they dropped never returns to `PRESENT`, which the claim requires). |
| `TaskCell::poll_future` | block | `Pin::new_unchecked(&mut F)` | Structural pinning: `self` is `Pin<&Self>` of a `!Unpin` cell that is reachable only through shared references, has no method that moves or replaces the value and destroys it in place in `Drop`, so the cell's pin guarantee extends to the field. Its memory stays valid and unmoved until `drop_future`, `finish` or `Drop`, all of which need the claim this reference holds to be released first. |
| `TaskCell::destroy_value` | block | `ptr::drop_in_place` of the stored `F` | Reached after a claim into `ABSENT` (`drop_future`, `Drop`) or `STORING` (`finish`) that succeeded exactly once, from a state in which the value is initialized and not being polled; neither state is accepted by any later claim of the value, so no reference to it exists now or later; only the pinned `drop_future` and `finish` and the in-place `Drop` reach it, so the value is at the address it was polled at. A destructor that panics still counts as having run once. |
| `TaskCell::finish` | block | the one write of `Some(outcome)` into the `UnsafeCell<Option<O>>` | Holds the `STORING` claim, won once (no claim leaves `STORED`); nothing reads the cell before `STORED` is released, because `publish` loads `STORED` with acquire ordering before it sets `COMPLETE`, and both readers of the outcome require `COMPLETE`. |
| `JoinCells::waker_will_wake`, `JoinCells::wake_join` | block ×2 | shared reference into the join waker cell | Called only while `JOIN_WAKER` is set (the handle) or by the publication that observed it set when completing (the publisher); in that state neither side writes the cell, since the handle cannot clear `JOIN_WAKER` once complete and its detach leaves the cell to publication. `Waker` is `Sync`. |
| `JoinCells::update_join_wakers` | block | exclusive reference into the join waker cell | Called by the one join handle while `JOIN_WAKER` is clear and the word was not complete at its last check (publication reads the cell only if `JOIN_WAKER` was set when it completed), by the detaching handle after publication cleared `JOIN_WAKER`, or by publication after its clearing of `JOIN_WAKER` showed the handle gone; each follows the other side's last access through an acquire-release read-modify-write on the word. |
| `JoinCells::take_output` | block | exclusive reference into the outcome cell | Called only after `COMPLETE`, which follows the one write; by the join handle when `JOIN_INTEREST` was set at publication (publication never touches the cell then), or by publication when it was not (the handle detached and never touches it again). The handle is one non-shared owner, so its takes are sequential. |
| `arc_pointer` | block | reads `&Pin<Arc<T>>` as `&Arc<T>` | `Pin` is `repr(transparent)` over its pointer; the reference is used only for `Arc::as_ptr` within the same borrow, which neither moves the value nor gives out an unpinned owner. |
| `PublishedTask` | `unsafe impl Sync`, `unsafe impl Send` | — | The cell is written only by `TaskSlot` (`install` before the task's first queue entry is inserted, `take` in the final turn that consumed the only entry, `take_idle` when no dispatcher exists) and read only by the holder of the task's queue entry, ordered after the write by the entry's insertion; the pointee is `Send + Sync` (`TaskLend`) and the pointer gives no ownership. |
| `PublishedTask::set` | block | the slot's write of `Option<NonNull<T>>` into the `UnsafeCell` | Private, called only by `TaskSlot::install`, `take` and `take_idle` at the points above, so no read overlaps the write. |
| `PublishedTask::held` | block | the slot's read of `Option<NonNull<T>>` from the `UnsafeCell` | Private, called only by `TaskSlot::install`, `take` and `take_idle` just before their write at the points above, so no write overlaps the read; it is compared, never dereferenced. |
| `PublishedTask::lend` | block ×2 | the read of the published pointer; `NonNull::as_ref` of the task | The caller holds the task's queue entry (the caller requirement above), so the last write happened before the read and no writer runs while the entry exists; a published pointer names the slot's live owner, which the slot keeps while the entry exists. The turn then begins with the word's compare-and-swap, as in `TaskSlot::lend`, and the `Lease` it returns relies on the same argument as one from the slot. |
| `Lease::task` | block ×2 | `NonNull::as_ref` of the lent task; `Pin::new_unchecked` of it | The pointer is `Arc::as_ptr` of the owner a `TaskSlot` held when `lend` (its own, or `PublishedTask::lend` for its published pointer) won `RUNNING` for this lease; until the lease ends, no slot drops or releases that owner (see above), so the allocation is alive for the borrow. The value lives in a pinned `Arc` allocation and is only reached by shared reference. |
| `TaskCell::waker_ref` | block | `Waker::from_raw` with the cell's waker vtable | `data` is a lease's `Arc::as_ptr` pointer, so it may reach the reference counts, and the lease keeps the allocation alive for the `WakerRef`'s borrow. The waker is held in `ManuallyDrop` and cannot be woken by value, so it gives back no count it did not take. |
| `TaskCell::clone_raw`, `wake_raw`, `wake_by_ref_raw`, `drop_raw` | `unsafe fn` ×4, block ×4 | vtable entries: `Arc::increment_strong_count`; `Arc::from_raw` (wake); a shared reference to the cell (wake by reference); `Arc::from_raw` (drop) | Only the vtable calls them, with the `data` pointer of a waker built by `waker_ref` or `clone_raw`: an `Arc::as_ptr` pointer into a live allocation. `clone` adds the count the clone owns; an owned clone's `wake` and `drop` give back its own count; `wake_by_ref` only reads the header and word through a waker that keeps the allocation alive by its count or its borrow. |
| `runtime_task_cell.rs` tests (test only) | block ×3 | `Pin::get_unchecked_mut` and a field read of the node being polled, one write through a registered pointer | The intrusive-registration test: a pinned future publishes its own address and withdraws it in `Drop`; the write happens only while the registration is in place, under the registry lock that excludes the withdrawal. Miri checks the test. |

### `sys/runtime_net_options.rs` (optional `runtime`)

This module contains only fixed Linux TCP/IP socket-option calls not available
through rustix's safe option API. The runtime passes owned descriptors or
borrowed interface bytes for one synchronous call; the wrappers allocate no
memory and expose no generic raw-option function.

| Location | Kind | Operation | Why it is sound |
|---|---|---|---|
| `get_traffic_class` / `set_traffic_class` | block each | `getsockopt` / `setsockopt` for the closed IPv4 TOS or IPv6 traffic-class enum | The enum selects the matching level/name pair. The descriptor stays borrowed and open; values are initialized `c_int`s; the checked `socklen_t` is exactly their size; the setter bounds values to 0–255. |
| `get_device` | block | `getsockopt(SO_BINDTODEVICE)` | The kernel writes into a fully initialized, fixed `IFNAMSIZ` array. The reported length is checked against capacity and terminal-NUL structure before runtime code constructs its caller-owned `Vec`. |
| `set_device` | block | `setsockopt(SO_BINDTODEVICE)` | The descriptor remains borrowed. A validated input slice lives through the call and the checked length covers only that slice; clearing uses a null pointer and zero length. |

### `sys/runtime_ring.rs` (feature `runtime-io-uring`)

A separately created, bounded ring serves owned regular-file reads/writes.
The safe runtime never exposes its private kernel pointers. Startup reserves
owner metadata and maps the ring; these allocations are outside allocator
syscall paths. The original creating issuer is the only thread permitted to
use the ring. It requires `SINGLE_MMAP`, `EXT_ARG`, `NODROP` and
`SUBMIT_STABLE`, probes both operations, caps both io-wq classes, installs
flagless read/write restrictions, then enables the disabled single-issuer ring.
No SQ polling or shared work queue is requested.

| Location | Kind | Operation | Why it is sound |
|---|---|---|---|
| `RuntimeRing::new` | block | `io_uring_setup` | Exclusive live params, no SQ polling/attached queue; checked flags, bounded power-of-two depths, offsets, masks, mapping lengths and alignment before use. |
| `Mapping::new` / `Drop` | block each | `mmap` / `munmap` | Fresh shared mappings of this ring's own memory; destruction occurs only before publication or after the owner table is drained. |
| `RuntimeRing::word` | block | Raw reference to `AtomicU32` | Validated aligned offsets within the live mapping; all accesses to shared header words are atomic and no reference escapes the ring. |
| `RuntimeRing::write_sqe` | block | Write one SQE | Slot below validated capacity, not reused before acquire-observed kernel SQ head; required `SUBMIT_STABLE` permits reuse after consumption. Original FD/buffer owners are stored before release-publishing SQ tail. |
| `RuntimeRing::read_cqe` | block | Read one CQE | Acquire-observed CQ tail makes the kernel entry visible; checked outstanding count/mask keeps it in bounds; CQ head advances with release only after reading. |
| `RuntimeRing::register` | block | `io_uring_register` | Private call sites provide correctly sized, live probe/worker/restriction arrays or a null enable argument. Restrictions prohibit other operations and SQE flags. |
| `RuntimeRing::enter` / `enter_wait` | block each | `io_uring_enter` / `io_uring_enter_arg` | SQEs refer to retained unique buffers and descriptors. Timed waits use live correctly laid out argument/timespec locals until syscall return. Retries submit only the existing unconsumed range. |
| Backend test `sqe_at` | block | Read a private injected SQE | Bounds/mapping validated; test ring has one issuer, and injection does not rewrite published requests. |

Buffers have no Rust slices, clones, debug-byte access or final owner release
while kernel-visible. A checked original terminal CQE restores ownership;
queued cancellation has never exposed inputs, while claimed/published
cancellation detaches observation until actual completion. Unknown/duplicate
completions, malformed results, lost CQ ownership, fatal ambiguous enter,
in-flight unwind or in-flight backend destruction abort before owner release.
Closing the descriptor is not used as an ownership barrier: Linux v7.0's
[ring release implementation](https://github.com/torvalds/linux/blob/v7.0/io_uring/io_uring.c)
queues asynchronous exit work. Original operations are never replayed or
silently replaced by blocking I/O. This initial fail-stop policy is explicit
in the public runtime contract.

### `sys/ring.rs` (io_uring purge ring, plan Phase 8, feature `io-uring`)

Compiled only with the Cargo feature `io-uring` (not default). A restricted ring for batched `MADV_DONTNEED` (`PurgeRing`, used by the maintenance thread only after `Allocatbelt::set_io_uring(true)`). The syscalls go through rustix's `io_uring_*` functions, which are `unsafe` because the kernel works on raw pointers; no safe crate covers a ring that the allocator can use without allocating. A safe alternative would be `madvise` per run, which stays the default.

| Location | Kind | Operation | Why it is sound |
|---|---|---|---|
| `setup` | block | `io_uring_setup(entries, &mut params)` | Flags ask for no SQPOLL thread and no attached work queue, so the kernel only reads and fills `params` (a live `io_uring_params`) and returns a new descriptor. |
| `map` / `unmap` | block each | `mmap(null, len, RW, SHARED\|POPULATE, ring_fd, IORING_OFF_*)`, `munmap` | A fresh mapping of the ring's own memory at an address the kernel picks, so it aliases nothing; unmapped only in `Drop`, after the last completion. |
| `PurgeRing::register` | block | `io_uring_register(fd, op, arg, nr)` for `PROBE`, `IOWQ_MAX_WORKERS`, `RESTRICTIONS`, `ENABLE_RINGS` | `arg` points at a live value of the type and count the op expects (or is null for `ENABLE_RINGS`); the kernel reads or fills only that. After `ENABLE_RINGS` the restrictions allow only `IORING_OP_MADVISE`, without SQE flags, and no registration but `ENABLE_RINGS`, which an enabled ring refuses anyway. The restrictions list that one register opcode because newer kernels (seen on the CI runner) restrict `io_uring_register` only when a register opcode is listed. |
| `PurgeRing::enter` | block | `io_uring_enter(fd, to_submit, min_complete, GETEVENTS)` | No argument pointer. The SQEs it submits describe `madvise` of ranges the caller of `purge` owns. |
| `PurgeRing::purge_chunk` | block | `write` of one SQE | The slot index is below `entries`, the length of the SQE mapping, which only this (single-issuer, `!Send`) ring writes; the kernel reads a slot only during the `io_uring_enter` that follows (or after the tail store). |
| `PurgeRing::reap` | block | `read` of one CQE | The slot is inside the ring mapping (masked by `cq_entries`), written by the kernel before it published the tail that the Acquire load observed, and not reused before `head` moves past it. |
| `PurgeRing::word` | block | `&*(ring + off) as &AtomicU32` | The kernel's offsets point at aligned `u32` heads, tails and masks inside the mapping, which lives as long as the ring; both sides access them atomically. |
| `PurgeRing::purge` | **`unsafe fn`** + block ×2 | batched `madvise(MADV_DONTNEED)`; `Region::purge` for ranges that were never submitted (a retired ring) | The contract of `Region::purge`, for every range. `purge` returns only after every submitted purge has completed, or reports `CompletionLost` (a failed completion wait), on which the adapter aborts rather than reuse pages a purge may still discard. |

### `sys/rseq.rs` (`mm_cid` reads, plan Phase 9, feature `experimental-rseq`)

Compiled only with the feature `experimental-rseq`. It reads the calling thread's `mm_cid` from the rseq area glibc registered; it registers nothing and runs no rseq critical section. A safe alternative does not exist: the area is only reachable through the thread pointer.

| Location | Kind | Operation | Why it is sound |
|---|---|---|---|
| `extern "C"` block (glibc only) | `unsafe extern` | declares glibc's `__rseq_offset` and `__rseq_size` (glibc 2.35+) | The declared types are glibc's (`ptrdiff_t`, `unsigned int`). |
| `MmCid::probe` | block ×3 | reads `__rseq_size` and `__rseq_offset`; `getauxval(AT_RSEQ_FEATURE_SIZE)` | Constants glibc sets before user code runs; `getauxval` only reads the auxiliary vector and does not allocate. `mm_cid` is used only if glibc registered an area (`__rseq_size != 0`) and the kernel fills `mm_cid` in (feature size at least 28). |
| `thread_pointer` | block (one per architecture) | `mov fs:[0]` (x86_64), `mrs tpidr_el0` (aarch64), `mv tp` (riscv64) | Reads the thread pointer that `__rseq_offset` is relative to; no other effect. |
| `load_field` | block | `AtomicU32::from_ptr(...).load(Relaxed)` | glibc keeps every thread's rseq area (32 bytes, 32-aligned, in its TCB) at that address for the thread's lifetime, registered or not; `field` names an aligned `u32` (`cpu_id` or `mm_cid`). Only the kernel writes the area, and only while this thread is in the kernel, so the load never races. `from_ptr` creates no reference escaping the immediate atomic load. A negative `cpu_id` (registration failed for this thread) makes the read return `None`. |

The directive's Phase H added no `unsafe` site to the library: the tests it added (`tests/rseq_process.rs`) call `fork`, `sched_setaffinity`, `alarm`, `waitpid`, `_exit` and install a seccomp filter with `prctl` in test code only. On musl, `MmCid::probe` is safe code that returns `NotGlibc`: nothing reads the thread pointer there.

`futex_wait`/`futex_wake` (the heap locks' sleep and wake-up, and the maintenance thread's timed sleep) use rustix's safe futex functions and add no `unsafe` site.

`libc` is used only for what rustix does not cover: the guard-marker advice
values (not in rustix's `Advice` enum), `pthread_atfork`, `sched_setscheduler`
(feature `scheduler`), `getauxval` (with `experimental-rseq`), and the typed
runtime TCP/IP option syscalls below.

The `sys` module **does not use** `rustix::param::page_size()`: reading auxv may allocate when rustix's `alloc` feature gets unified in, which would re-enter the allocator. Instead every range uses a fixed 64 KiB granule, a multiple of all Linux page sizes.

## `arch` (`crates/allocatbelt/src/arch/`)

CPU feature detection, and the experimental SVE/SVE2 and RVV kernels (features `experimental-aarch64-sve`, `-sve2` and `experimental-riscv-rvv`, docs/features.md). Every detection site runs during `initialize_dispatch()` (or the first `detected_features()` call) and only reads CPU or kernel state.

| Location | Kind | Operation | Why it is sound |
|---|---|---|---|
| `x86_64::xcr0` | block | `_xgetbv(0)` | `xgetbv` faults unless the OS enabled XSAVE; the only caller checks `CPUID.1:ECX.OSXSAVE` first. The `xsave` target feature is on for every build (x86-64-v3), and register 0 (`XCR0`) always exists. `cpuid` itself is a safe intrinsic. |
| `aarch64::detect` | block ×2 | `libc::getauxval(AT_HWCAP)`, `libc::getauxval(AT_HWCAP2)` | Accepts any key and returns 0 for unknown ones; it only reads libc's saved copy of the auxiliary vector, without syscalls or allocation (glibc and musl). |
| `sve::aged_pages_sve` | block | calls the `#[target_feature(enable = "sve")]` function `aged_pages_sve_body` | The function is private and only returned by `sve::age_kernel` for `KernelSet::Sve`, which `kernel_set()` reports only when `AT_HWCAP` has `HWCAP_SVE` (the CPU implements SVE and the kernel enabled it for the process). The body is safe code on a borrowed array (the core's private snapshot). |
| `sve::aged_pages_sve2` | block | calls the `#[target_feature(enable = "sve2")]` function `aged_pages_sve2_body` | As above, for `KernelSet::Sve2`, reported only when `AT_HWCAP` has SVE and `AT_HWCAP2` has `HWCAP2_SVE2`. |
| `rvv::aged_pages_rvv_body` | `#[unsafe(naked)] unsafe extern "C" fn` | `core::arch::naked_asm!` RVV strip-mining leaf | The ABI implementation reads exactly 64 u64 values, uses only caller-saved registers, restores the 16-byte-aligned stack, and returns a u64 in `a0`. `.option arch,+v` is local to the leaf, so no V instruction can be emitted elsewhere by the compiler. |
| `rvv::aged_pages_rvv` | block | calls the naked RVV leaf | The wrapper rechecks the current dispatch policy and current-thread permission immediately before the call; if either no longer permits RVV, it runs the safe scalar core loop. The core's fixed snapshot backs the pointer for all 64 reads. |
| `rvv::tests` (test only) | blocks | direct leaf calls; `mmap`, `mprotect`, snapshot initialization and reference creation, `munmap`; `prctl` in the cross-thread test | Direct calls run only on V-enabled QEMU/hardware or after the test's current-thread permission query succeeds. The guard test maps its own memory, writes and initializes exactly 64 u64s, makes the input read-only, places a `PROT_NONE` mapping immediately after it, and releases the mapping after the call. The thread test changes only test threads' vector control and isolates the initial OFF state in a child process. |
| `riscv64::vector_control::vector_permission` | block | `libc::prctl(PR_RISCV_V_GET_CONTROL, 0, 0, 0, 0)` | Reads the calling thread's vector control word; takes no pointer and writes no memory. Called at dispatch, policy validation and reporting only when hardware detection selected the compiled RVV kernel; any error or state other than current `ON` fails closed. |
| `riscv64::detect` | block | `libc::syscall(riscv_hwprobe, &mut pair, 1, 0, null, 0)` | The kernel writes only into the one `Pair` passed, a live exclusive local with the UAPI `struct riscv_hwprobe` layout (`#[repr(C)]` `i64` + `u64`). A null CPU set of size 0 means all online CPUs and the flags are 0, as the hwprobe documentation requires. |

## `global` (`crates/allocatbelt/src/global.rs`, the adapter)

`LinuxOs` (the core's `Os`) and `impl GlobalAlloc for Allocatbelt` are in `global.rs`; the maintenance thread is in `src/maintenance.rs` (feature `maintenance`), and its `RingPurger` only with the feature `io-uring`. The experimental `mm_cid` shard selection (`src/rseq.rs`, feature `experimental-rseq`) adds no `unsafe` here: `LinuxOs::shard_hint` only calls the safe `MmCid::current`.

| Location | Kind | Operation | Why it is sound |
|---|---|---|---|
| `LinuxOs::purge/decommit` | block ×2 | calls `Region::purge/decommit` | The core's `Os` contract: it only purges or decommits ranges with no live allocations (see below). |
| `LinuxOs::guard` | block | calls `Region::guard` | The core's `Os` contract: it only guards the last page of an owned segment, which it never hands out, and unguards it before the segment can be committed for other use (trust assumption 5). |
| `impl GlobalAlloc` | `unsafe impl` + 4 `unsafe fn` | — | Required by the trait. Unwinding is blocked by `AbortOnUnwind`. |
| `alloc_zeroed` | block | `write_bytes(0, size)` | A fresh block that nobody references yet. Skipped when the core reports the block as already zero (trust assumption 4). |
| `RingPurger::purge_batch` (`maintenance.rs`, feature `io-uring`) | block | calls `PurgeRing::purge` | The core's `Purger` contract: every range was claimed by the purge pass, so it holds no live allocation and none of its pages is handed out until the call returns; the ring returns only after all completions (and the adapter aborts on `CompletionLost`). |
| `realloc` | block | `copy_nonoverlapping` | The old block is live (caller contract); the new block is a separate fresh block. |

## `region` (`crates/allocatbelt/src/region.rs`, theory-driven plan Stage E)

The explicit-lifetime `Region` API. The arithmetic (alignment, fitting, chunk sizing, retention, the limit) is the safe core's `core/region.rs`, which returns `None` instead of wrapping; the adapter owns the chunks and builds pointers only for addresses that arithmetic placed inside a chunk it holds. Soundness of the handed-out references rests on the borrow checker: pieces borrow the region (`&self`), and `reset`, `release` and `Drop` need `&mut self` or ownership; the compile-fail doctests on `Region` check that a piece cannot outlive them, that non-`Copy` types are refused and that the region is not `Sync`. Chunk descriptors are in a `Vec`, never inside a chunk.

| Location | Kind | Operation | Why it is sound |
|---|---|---|---|
| `ChunkSource::release` | **`unsafe fn`** (trait) | — | Contract: the pointer came from the same source's `allocate` for that layout and is not used afterwards. |
| `HeapChunks::release` | **`unsafe fn`** + block | `Allocatbelt.dealloc(ptr, layout)` | Its contract is `GlobalAlloc::dealloc`'s: the chunk came from `Allocatbelt::allocate` for the same layout. The heap accepts frees from any thread. |
| `RawRegion::give_back` | block | `source.release(chunk)` | Called only by `reset`, `release` and `Drop`, which hold the region mutably or by value, so no piece of the chunk is borrowed; the chunk is removed from the region in the same step, so it is released once. |
| `Chunk` | `unsafe impl Send` | — | A chunk owns its allocation exclusively, like a `Box<[u8]>`, and holds no thread-local state. `Region` is therefore `Send`, and not `Sync` (its bump state is in `Cell`s). |
| `RawRegion::alloc_copy` | block ×2 | `ptr.write(value)`; `&mut *ptr` | The piece is fresh (never handed out since the last reset), aligned for `T` and large enough (or a dangling aligned address for a zero-sized `T`), so the write initializes it and the reference is unique; it borrows the region, so it ends before the chunk can be reset or freed. `T: Copy`, so no destructor is skipped. |
| `RawRegion::alloc_slice_fill` | block ×2 | `ptr.add(i).write(value)` per element; `slice::from_raw_parts_mut` | As `alloc_copy`, for `len` elements (the size was computed with `checked_mul`); every element is written before the slice is made. Zero-sized `T` writes nothing. |
| `RawRegion::alloc_slice_copy` | block ×2 | `copy_nonoverlapping(src, piece, len)`; `slice::from_raw_parts_mut` | As above; the piece is fresh, so it does not overlap `src`. `alloc_zeroed_bytes` and `alloc_str` use these two and add no site (`alloc_str` checks the copy with the safe `str::from_utf8_mut`). |
| `region/tests.rs` (test only) | `unsafe fn` + block ×3 | `System.alloc`, `System.dealloc`, one write to a piece | A test chunk source over the system allocator (so that Miri can run the region's tests) and a write inside a 24-byte piece. |

## `bench-runtime-diagnostic` (benchmark only)

`bench/src/bin/bench-runtime-diagnostic.rs` wraps `System` with a counting
global allocator for the separate runtime diagnostic lane. It records sizes
and call counts but never inspects, retains or changes an allocation pointer.
This binary is not linked into the allocator or its users.

| Location | Kind | Operation | Why it is sound |
|---|---|---|---|
| `CountingSystem` | `unsafe impl GlobalAlloc` | — | Each allocation operation delegates to `System` with the exact pointer and layout from its caller; atomic counters observe only sizes. |
| `CountingSystem::alloc` | block | `System.alloc(layout)` | Delegates the caller's valid layout to the system allocator and returns its pointer unchanged. |
| `CountingSystem::alloc_zeroed` | block | `System.alloc_zeroed(layout)` | Delegates the caller's valid layout and zeroing contract to the system allocator and returns its pointer unchanged. |
| `CountingSystem::dealloc` | block | `System.dealloc(pointer, layout)` | Delegates the pointer and layout supplied by the caller that allocated it through this wrapper. |
| `CountingSystem::realloc` | block | `System.realloc(pointer, layout, new_size)` | Delegates the caller's live allocation and old layout to the system allocator and returns its pointer unchanged. |

## allocatbelt-simd-bench (benchmark only)

`bench/simd` holds the Phase 4 SIMD candidates ([research/simd-benchmarks.md](research/simd-benchmarks.md)). It is not a dependency of the allocator and nothing in it runs inside `GlobalAlloc`. Phase 5 promoted none of them; a kernel promoted later moves into the `arch` module of `allocatbelt` and gets its own rows above. Its `unsafe` is listed here so the whole workspace is accounted for.

| Location | Kind | Operation | Why it is sound |
|---|---|---|---|
| `kernels/x86_64.rs`: `nonzero_avx2`, `popcount_avx2`, `age_avx2`, `zero_avx2`, `zero_avx2_nt`, `copy_avx2` | block each | call of the `#[target_feature(enable = "avx2")]` `_imp` function | The wrapper is only put into a `Variant` when `CpuFeatures::AVX2` was detected (always true at the x86-64-v3 floor). |
| `kernels/x86_64.rs`: `nonzero_avx512`, `age_avx512`, `zero_avx512`, `copy_avx512`, `popcount_avx512` | block each | call of the `avx512f` (popcount: `avx512f,avx512vpopcntdq`) `_imp` function | Listed only when `AVX512F` (and `AVX512VPOPCNTDQ`) were detected. |
| `kernels/x86_64.rs`: `zero_avx2_imp`, `zero_avx512_imp`, `copy_avx2_imp`, `copy_avx512_imp` | block ×1 or ×2 | `_mm256_storeu_si256` / `_mm512_storeu_si512`, `_mm256_loadu_si256` / `_mm512_loadu_si512` | Each pointer comes from a `chunks_exact(_mut)` chunk of exactly the vector width, so the access is in bounds; the unaligned forms have no alignment requirement; source and destination are a `&[u8]` and a `&mut [u8]`, so they do not overlap. |
| `kernels/x86_64.rs`: `zero_avx2_nt_imp` | block | `_mm256_stream_si256` | The chunks start after a scalar head that brings the pointer to 32-byte alignment, as `movntdq` requires, and are exactly 32 bytes; an `_mm_sfence` follows the loop so the stores are ordered before the function returns. |
| `kernels/aarch64.rs`: `nonzero_neon`, `popcount_neon`, `age_neon`, `zero_neon`, `copy_neon` | block each | call of the `#[target_feature(enable = "neon")]` `_imp` function | Listed only when `ASIMD` was detected. |
| `kernels/aarch64.rs`: `nonzero_sve`, `popcount_sve`, `age_sve` | block each | call of the `#[target_feature(enable = "sve")]` `_imp` function | Listed only when `SVE` was detected. |
| `kernels/aarch64.rs`: `zero_neon_imp`, `copy_neon_imp`, `load2` | block ×1 or ×2 | `vst1q_u8_x4`, `vld1q_u8_x4`, `vld1q_u64` | 64-byte chunks from `chunks_exact(_mut)`, or a `&[u64; 2]`, so every access is in bounds; `ld1`/`st1` have no alignment requirement beyond the element's; source and destination do not overlap (`&` and `&mut`). |
| `perf.rs`: `Counters::open` | block ×2 | `libc::syscall(SYS_perf_event_open, &attr, 0, -1, group_fd, 0)`, then `File::from_raw_fd` | The kernel only reads `attr`, a live `#[repr(C)]` struct of `PERF_ATTR_SIZE_VER0` bytes (checked by a const assertion), and returns a new descriptor that nothing else owns, so the `File` may close it. |
| `perf.rs`: `Counters::group_ioctl` | block | `libc::ioctl(leader, PERF_EVENT_IOC_{RESET,ENABLE,DISABLE}, PERF_IOC_FLAG_GROUP)` | These requests take an integer flag, not a pointer, on a perf descriptor this `Counters` owns; a failure only makes the counts unusable. |

## Trust assumptions (the part the boundary does not cover)

The narrow boundary makes each *operation* auditable, but soundness still depends on **the correctness of the core logic**:

1. The heap never hands out an offset that is live twice (non-overlap).
2. It never calls `purge`/`decommit` on a range that holds a live allocation.
3. It never hands out an offset that has not been committed.
4. It only reports a block as `zeroed` if every page of it was never handed out, or was purged/decommitted with success (`Os::purge`/`Os::decommit` returned `true`) since it was last handed out. Otherwise `calloc` would return stale bytes.
5. It never hands out, purges or commits a guarded page: the guard page of an owned segment stays claimed in the segment's page bitmap for as long as the segment is owned, and `Os::unguard` runs before the segment returns to the arena.

Current verification:

- **Shadow maps.** The checking mock `Os` (`crates/allocatbelt/src/core/model.rs`, compiled by `allocatbelt-core-check` for its tests and with its feature `model`) checks non-overlap, commit state, that purged, decommitted and guarded ranges hold no live block, that nothing guarded is handed out or committed, and a written-pages shadow that every `zeroed` claim is checked against, including with failing purges. It backs every model test.
- **proptest.** Random operation sequences, with and without thread caches and randomized placement, and random byte programs for the fuzz interpreter (`model::run`, `tests::fuzz_programs`).
- **Fuzzing.** `fuzz/` runs `model::run` under libFuzzer (cargo-fuzz). A 10-minute run on 2026-09-28 executed 381,049 programs with no failure. CI repeats it on its daily schedule.
- **loom.** `proto.rs` holds every transition the heap performs on shared metadata that other threads can race with, and loom checks them exhaustively (`--cfg loom`): free vs. claim, two freers on one word, racing double frees, the free counter never overstating free blocks, page-run claim/release vs. purge and in-place growth vs. segment trimming (both under the owning shard's lock, which the models take as the heap does), and the heap lock, whose futex parking is modelled with a wait queue that checks the word under the same mutex as the wake, so a lost wake-up would show up as a deadlock. The heap calls these same functions, so the models check the shipped code.
- **Batched purges.** The core's `Purger` interface keeps the ring's asynchronous interval inside the existing page-claim protocol: pages are claimed (`proto::claim_dirty`, under the owning shard's lock) before submission and released (`proto::finish_purge`, under it again) only after every completion, and only a completion with result 0 clears a dirty mark. The checking model's `MockPurger` completes batches out of order, fails some runs and lets other "threads" allocate and free while a batch is in flight (`tests.rs`, and fuzz op 31); loom checks the interval with a delayed, partly failed completion (`async_purge_with_failure`).
- **Integration tests.** Multi-threaded cross-thread frees, thread exit returning caches, the maintenance thread returning RSS, taking budget passes off freeing threads and running as `SCHED_BATCH`, a real overflow faulting in the guard page, and `fork` from a busy process.
- **Mutation testing.** The mewt campaign over `bits`/`class` (see CONTRIBUTING.md) passes: 87 mutants caught, 5 listed as equivalent.
- **Miri.** The complete isolated core campaign at signed revision
  `c3ed95db4f9ba9b6ffd9d84d7651a3b5963de2c5` passed 135 tests and retained
  one intentional ignored contention benchmark. All 136 test-process and
  log-writer exits were zero, with no timeout or cancellation. The current
  core/checker sources match that campaign's source bridge. See the
  [qualification ledger](research/runtime-capability-status.md) for scope and
  separate runtime/platform requirements.

Historical Miri result (**run on commit 0271678**, i.e. before the later follow-up commits, nightly 2026-09-26, `-Zmiri-disable-isolation`, 90-minute limit): **8/17 tests passed with no UB detected**:
`bits::{masks, run_matches_naive}`, `class::{table_shape, class_of_is_tight}`, `tests::{alignments, cross_thread_frees, double_free_small, double_free_large}`.
The other 9 (proptest-based ones, `every_size_round_trips`, `random_sequences`, etc.) **did not finish** within that limit. Those outcomes remain incomplete for that historical run; the later complete campaign above supersedes its current-status claim.
Since the core has no `unsafe`, Miri mainly checks panics/overflow and data races in the atomic logic here, not memory safety.
Keep the loom models and fuzzing (cargo-fuzz against `Heap<MockOs>`) current when their covered code changes.

Other caveats:
- **fork:** the adapter registers `pthread_atfork` handlers that take every heap lock before `fork` and release them on both sides (`Heap::fork_prepare/parent/child`), so no lock is held by a thread missing in the child; the child also reseeds its placement secret and falls back to allocation-driven purging. Blocks cached by the parent's other threads stay allocated in the child. `posix_spawn` and `vfork` do not run the handlers, and do not need to. Covered by `tests/fork.rs`, which deadlocked before the handlers existed.
- `std::io::stderr()` is used only on the fatal path (unbuffered, no allocation expected).
