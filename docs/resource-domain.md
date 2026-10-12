# Global and tenant resource admission

`runtime::resource_domain` provides a fixed-storage domain for declared CPU,
managed-memory, disk, network, task and control charges. `ResourceDomain::new`
reserves its tenant-slot table before exposing the domain. The retained table
capacity is charged to `Control`; allocator rounding and shared headers are
not measured physical memory.

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

`DomainReservation` is an owned, non-clonable ticket. Retain it through actual
execution, detached completion and cleanup. A shared returned object can hold
one ticket until its final clone drops. This primitive accounts declared
ownership: using it alone does not intercept allocations, polls or I/O, impose
an OS CPU quota, or measure RSS, physical disk traffic or wire bandwidth.
Binding existing managed runtime paths requires their own integration.

Native fixtures cover multi-resource rollback, retained result clones, closed
handle bounds, zero reservations and soft-limit draining. The same-source Loom
fixture exercises concurrent global/tenant CPU admission and release. It does
not model scheduler dispatch, buffers, syscall completion or kernel quotas.
