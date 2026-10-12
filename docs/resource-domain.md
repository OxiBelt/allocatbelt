# Global and tenant resource admission

`runtime::resource_domain` provides a fixed-storage domain for declared active
CPU, managed-memory, disk, network, task and control charges.
`ResourceDomain::new` reserves its tenant-slot table before exposing the
domain. `ResourceDomain::with_waiters(ceiling, max_tenants, max_waiters)` also
reserves a fixed CPU-waiter table. Actual retained slot capacities, the shared
state payload and reserved tenant-owner payloads are charged to global
`Control`; allocator rounding, `Arc` headers and waker payload allocations
are not measured physical memory. The existing `new` constructor keeps a
zero-waiter table for callers that only need synchronous reservations.
Each tenant slot reserves one owner payload before the domain is exposed.
Creating or cloning a tenant does not charge its own Control quota, so a
zero-Control tenant can still be represented. This fixed owner reservation
avoids a self-retaining ownership cycle and lasts with the domain tables.
The domain constructor charges its state, owner storage and tables. Tenant-bound
schedulers, scopes, task frames, queues, wake owners and selected service
adapters also reserve their declared metadata payloads before admission or
startup, retaining those fees with the final owners. Unbound lower-level
constructors retain their existing behavior. This is declared-payload
accounting rather than a physical-memory bound; the
[runtime contract](runtime.md#owning-driver-facades) describes its coverage
and remaining provider requirements.

A tenant has immutable hard ceilings and independently adjustable soft limits.
`TenantDomain::try_acquire` takes a complete `DomainResources` vector against
both global and tenant limits under one mutex, or takes nothing. Checked
arithmetic rejects overflow. A zero requested component does not require free
capacity in that dimension, including while an earlier soft-limit reduction
is draining active usage. A zero reservation still retains its generation.

Lowering a soft limit does not preempt work or release its charge. Admission
resumes when actual ownership drains below that limit. Hard ceilings cannot
be increased after construction. Closing a tenant denies new admission from
every clone. Its slot remains occupied until the final handle and reservation
drop, bounding retained tenant-owner metadata and preventing stale handles
from reopening a reused generation. Generation exhaustion never wraps.

Runtime builders reserve disjoint shares of the waiter table before starting
workers. Each admitted task, blocking job or borrowed root call leases one
generation-stamped waiter slot. The share remains reserved while its pool or
any live waiter retains it. CPU release and CPU soft-limit increases wake
eligible waiters outside the domain lock. A waiter keeps its FIFO place across
wakeups; cancellation clears its generation before slot reuse. A zero CPU soft
limit can leave work waiting indefinitely until the limit rises.

`DomainReservation` is an owned, non-clonable ticket. Retain it through actual
execution and cleanup. A shared returned object can hold one ticket until its
final clone drops. Bound async and local runtimes reserve `Tasks` before
publishing a future; blocking runtimes reserve it before publishing a closure.
The task charge remains through future or closure destruction and is released
before completion publication. A returned managed buffer or retained I/O
permit keeps its own memory or operation charge for its full ownership
lifetime; a task charge does not follow an arbitrary result after cleanup.

Bound runtimes use one CPU unit for each active `Future::poll` or blocking
closure call. A CPU ticket is acquired just before that call and released when
it returns. A pending future releases its ticket before it waits for its next
wake. Queued and cancelled unstarted closures take no CPU ticket. Borrowed
`block_on` roots use the same CPU and task ledgers, with a fixed root-call
bound. A blocking worker parked for CPU capacity remains task-admitted but
does not hold a CPU unit. In `block_in_place`, the original poll keeps its CPU
ticket for the borrowed closure; helpers acquire their own tickets and cannot
exceed the same global or tenant CPU limits.
If `Job::join` would wait for a job in the same bounded domain while the
calling thread holds one of that domain's CPU tickets, it returns
`JoinError::WouldDeadlock` and leaves the handle available for a later join.
The runtime also rejects nested async or local roots when they cannot obtain a
ticket held by the same thread. These checks cover direct CPU-admission cycles;
they do not promise progress when user code waits on arbitrary locks or
channels.

These CPU units bound simultaneous calls, not CPU time. They do not preempt
user code, impose an operating-system CPU quota, or measure RSS, physical disk
traffic or wire bandwidth. This primitive alone does not intercept arbitrary
allocations, polls or I/O.
`ResourceScope::from_tenant` binds existing managed buffers and disk/network
operation permits to that same domain. Its fixed `ResourceLimits` remain an
additional local bound. A bound runtime's omitted child-scope resource binding
inherits its root `ResourceScope`; an explicit child binding must name a
tenant in the same `ResourceDomain`. This prevents a new scope from dropping
the global domain or switching to an unrelated domain. Domain reservations
update the global and tenant ledgers atomically; the local ledger and domain
have separate locks, so their snapshots may describe adjacent stages of an
admission or rollback.

Bound buffers charge retained vector capacity until the final clone drops.
Growth reserves the complete replacement while retaining the old charge, and
accounts any excess allocator-provided capacity before exposing storage. A
rejected replacement leaves original bytes and charges intact. The inline
ticket array is bounded: two per backing and at most four while replacing it.
Bound operation permits acquire disk and network together and retain their
ticket through actual permit destruction. Closing a tenant rejects new memory
reservations and operation permits, including zero-operation requests, while
already charged buffer capacity remains usable. A shared buffer still reports
`Shared` before attempting growth. Unbound `ResourceScope::new` keeps its
original local accounting behavior.

Native fixtures cover multi-resource rollback, retained result clones, closed
handle bounds, zero reservations and soft-limit draining. Same-source Loom
fixtures exercise global/tenant admission, CPU waiter enrollment racing with
release, and waiter cancellation racing with slot reuse. They do not model
executor dispatch, syscall completion or kernel quotas. Native runtime
fixtures cover task admission, root and local polls, blocking closure waits,
same-domain joins across pools and `block_in_place`, scope domain identity and
cancellation before execution. Native managed
fixtures cover buffer clones, replacement peaks, allocation failure, closed
admission and permit lifetimes; another same-source Loom model covers global
contention by distinct tenant-bound operation scopes.
