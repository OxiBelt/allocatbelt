# Resource feedback policy

`runtime::resource_feedback_policy` contains a fixed-storage policy engine for
CPU concurrency and disk/network application-byte rates. It accepts telemetry
and issues typed change tickets. The engine alone does not start a sampler or
change runtime or kernel controls. It is separate from the existing caller-
driven cgroup CPU and memory adaptation.

Each control has explicit floors, ceilings and utilization hysteresis. Samples
are nominally 100 ms apart. Gaps up to 200 ms tolerate scheduling jitter; longer
gaps are sparse and readings older than 500 ms are stale. Missing, sparse or
stale required utilization freezes only that dimension. Three consecutive
dense high readings allow a reduction of at most 10% of the current limit.
Small integer limits that cannot reduce within that bound report a quantization
diagnostic. Recovery changes concurrency by at most one slot and byte rates
by at most 1% of their configured ceiling per one-second cooldown.

The owner serializes sample, plan and acknowledgement calls. Ticket generations
never wrap, and a pending ticket prevents duplicate decisions. A successful
acknowledgement anchors cooldown at actual actuation time. Failed or ambiguous
application latches the affected control; explicit readback reconciliation is
required. Reconciliation invalidates older telemetry and starts a conservative
safety cooldown without claiming the preceding attempt succeeded. The engine
never rolls back an unknown actuator state automatically.

Measurement timestamps remain ordered independently of processing timestamps:
a fresh reading captured before an intervening plan can still be consumed.
Readings captured before a reconciliation cannot influence that reconciled
control. Future, duplicate or out-of-order operations and invalid utilization
produce typed errors. Sampling, planning and acknowledgement use fixed arrays
and allocate no storage.

Focused tests cover hysteresis, jitter, missing and stale telemetry, bounds,
quantization, ticket exhaustion, delayed samples, failed actuation and readback
cooldowns. These are policy-correctness fixtures. Autonomous runtime sampling,
enforcement and real-pressure performance qualification require their own
integration and evidence.

The `runtime` Cargo feature enables `resource-feedback` (kept as an alias),
which compiles `runtime::resource_feedback::ResourceFeedbackService`. A
service starts through an explicit constructor with owned sensor and actuator
implementations, through a factory selected with `feedback_sources`, or as
the default service of an owning driver bound to a resource domain (below).
The
worker uses real 100 ms deadlines, skips missed cycles and preserves per-control
diagnostics. Startup verifies initial actuator readbacks. Before changing a
limit it checks for external drift; every attempted write has a post-write
readback, including when stop arrives during the attempt. Failed or ambiguous
results remain latched until a bounded explicit reconciliation request completes.

Sensor and actuator callbacks run outside the snapshot mutex. They may block;
startup and explicit owner cleanup therefore have no wall-time guarantee.
`request_stop` and `try_shutdown` retain unfinished thread ownership and report
pending while callbacks and their payload cleanup remain active. Dropping the
owner requests stop and detaches; the worker retains every callback and control
it still needs. Finite status calls retain joined panic payloads rather than
running their destructors. The service supplies scheduling and readback
discipline; concrete runtime telemetry and actuator bindings have their own
acceptance requirements.

`ProcessCpuSensor` supplies bounded reads of Linux process CPU counters and
checked utilization arithmetic relative to an explicit CPU capacity. Its first
read establishes a baseline. It does not attribute CPU by tenant, measure PSI
or provide disk/network signals; missing dimensions freeze independently.
`RuntimeFeedbackActuator` changes a selected global or tenant CPU soft limit
and selected disk/network application-byte buckets. Component compare-exchange
rejects stale writers without clobbering other dimensions or burst limits.
Use those buckets in the actual I/O path; actuator construction does not
intercept arbitrary syscalls or establish a physical traffic limit.

`ResourceFeedbackPolicyConfig::process_default(cpu_capacity)` and
`driver::default_feedback()` supply default values. The capacity is
`std::thread::available_parallelism()`, or one if that fails, read once when
the factory is created, and once per build when an owning driver starts the
default service by itself. It follows the standard library's definition, which
honours CPU affinity and the CPU quota the standard library reports; the
library itself opens no control-group, `/sys` or pressure file for it.
`driver::default_feedback_for_capacity` takes the capacity explicitly. The
policy is a constant function of the capacity: CPU concurrency has floor 1 and
starts at its ceiling, the capacity, with fixed 40% and 80% thresholds
(`DEFAULT_LOW_UTILIZATION_BASIS_POINTS`, `DEFAULT_HIGH_UTILIZATION_BASIS_POINTS`).
The default factory uses the capacity as the sensor's utilization denominator
only. Its CPU control starts at the global CPU soft limit the domain has when
the driver is built and uses that value as its ceiling, so it stays between
floor 1 and the limit it found and never raises the limit above what the
caller configured. When the service stops, its actuator returns the limit to
that start value with one compare-exchange, but only if the limit is still
the last value the service wrote and none of its changes failed; otherwise it
leaves the limit as it is. This is not a retry or rollback of a failed
change, and failed changes still latch. A limit lowered by one driver's
service is therefore back at its start value for the next driver.

Two properties follow from the fixed law and are not tuned away. A reduction
is a tenth of the current limit, so a limit below ten never falls and a larger
one stops at nine. Utilization is this process's CPU time over the capacity,
not over the domain limit: a domain limit well below the capacity may keep
admitted work under the high threshold, and then the limit never falls.
A domain has at most one default service at a time, because two services
moving the same limit would see each other's changes as external drift and
latch. The default path takes a registration on the domain before it reads
the CPU capacity and the limit; the service's actuator holds it, restores the
limit as above, and then releases it when it is dropped: after the sampler
stopped, after a failed startup, or when a detached sampler finishes. A
driver dropped without shutdown releases it only when its detached sampler
exits, so an immediate rebuild on the same domain may report
`NotStarted(DomainAlreadyControlled)`. Caller-built factories take no
registration.

## On by default for drivers bound to a resource domain

A `CurrentThreadBuilder` or `MultiThreadBuilder` starts with the default
feedback selection. At build time it starts the default service when the
builder has a `resource_domain` and that domain's global CPU soft limit is
nonzero and representable by the policy. A domain without a CPU ceiling
cannot build a bound runtime at all, because each poll needs a CPU unit.

**What it changes.** Bound runtimes take one CPU unit of their domain for each
active poll or blocking call ([resource-domain.md](resource-domain.md)). The
default service therefore lowers the number of simultaneous polls and
blocking calls of every runtime bound to that domain, across all of its
drivers and tenants, not only explicit `CpuGate` users. After three dense
readings at or above 80% of process CPU time over the CPU capacity, it lowers
the global CPU soft limit by a tenth of its current value; a limit below ten
does not fall, so one that starts at ten or more stops at nine. At or below
40% it raises a lowered limit by one slot, at most once per second, never
above the value it found at start, and it returns the limit to that value
when it stops (see above). The reading is process-wide, so the default
services of several domains in one process react to the same readings.
Behaviour under real pressure is not qualified.

**What it costs.** Each default service keeps a `Control` charge on the
tenant that built the driver for as long as it runs: its shared state, worker
and join-monitor payloads, and `ResourceFeedbackService::owner_payload_bytes()`
of owner payload. It runs two threads, the sampler and a join monitor, so the
process of a current-thread driver is no longer single-threaded, and it keeps
one descriptor on `/proc/self/stat` open, read every 100 ms. The service uses
the real clock even when the driver's application clock is paused or
virtual. Driver shutdown waits for the sampler to stop, so even an idle
driver's shutdown is no longer complete on its first poll.

**Changing the limit while it runs.** Setting the global CPU soft limit while
the default service runs is external drift. The service notices it when it
next plans a change, leaves the new value in place and latches the CPU
control; `feedback_metrics()` shows the latch, and `feedback_status()` stays
`Running`, because it reports the build outcome. Call the driver's
`request_feedback_reconcile(FeedbackResource::CpuConcurrency)` to continue
from the limit the service reads back, or build the driver with
`without_feedback()` when the limit must be set by hand. A limit someone else
changed is not restored when the service stops.

**Turning it off.** `.without_feedback()` on either builder starts nothing:
no sensor, thread or `Control` charge. A later `feedback_sources` call replaces
either selection, and its errors fail the build.

**Best-effort startup.** When the default service does not apply or cannot
start, the driver is still built, without feedback. `feedback_status()` on
the built driver returns `FeedbackStatus`:

- `Running`: the build started a service (the default one, or a selected
  factory's); `feedback_metrics()` returns its handle.
- `Disabled`: the builder called `without_feedback`.
- `NotApplicable(reason)`: no resource domain, a zero global CPU soft limit,
  or a limit the policy cannot represent. Nothing was started or charged.
- `NotStarted(reason)`: the domain already has a default service
  (`DomainAlreadyControlled`), the process CPU sensor could not be opened,
  the tenant refused the service's `Control` charge, a thread could not be
  created, or startup verification failed. Anything the attempt took is
  released.

The default selection allocates no byte meter, so the I/O paths of such a
driver take no meter timestamps. Its owner keeps the facade's full `Control`
charge until the service has started and charged its own payload, so a
`Control` budget that built a driver without feedback still builds it; when
the service's charge does not fit, the status is `NotStarted(Domain(..))`.
When it does fit, the service's charge stays for its lifetime: a tenant with
little `Control` headroom can build the driver and then have later
admissions refused that would have fitted without feedback. During startup
the charge is one owner payload higher than at steady state.

Order matters across drivers of one domain: a default service started
implicitly by one driver makes a later explicit `default_feedback()` on the
same domain fail with `FeedbackFactoryError::DefaultDomainAlreadyControlled`,
and a later default selection report `NotStarted(DomainAlreadyControlled)`.

The default factory selects a `ProcessCpuSensor` and a
`GlobalCpuFeedbackActuator`. Only the global CPU soft limit of the domain the
builder's `resource_domain` tenant belongs to can change. Disk and network
rates are not selected: no meter feeds the sensor, so both dimensions report
missing telemetry and stay frozen at `UNSELECTED_BYTE_RATE`, and the actuator
owns no byte bucket. Its byte readbacks return that fixed configured value so
startup verification still checks all three controls; a byte ticket, which the
frozen dimensions cannot produce, is refused and latches. Tenant CPU targets
and byte-rate control remain available through an explicit `feedback_sources`
factory.

For an explicitly selected default factory, startup conditions are reported
rather than repaired. A builder without
`resource_domain` has no CPU ledger, and the build fails with
`FeedbackFactoryError::DefaultRequiresResourceDomain` before a sensor is
opened. A zero CPU soft limit, or a ceiling the policy cannot represent, fails
with `FeedbackFactoryError::InvalidPolicy`. Failures while starting the
service, such as a tenant without Control headroom or a limit changed between
the factory's snapshot and the startup readback, are
`FeedbackFactoryError::Service`. [design-constraints.md](design-constraints.md) lists the rules the
feedback surface must keep.

`runtime::rate_io::RateLimitedIo` adds directional stream admission around
runtime-neutral read/write endpoints. It reserves available byte credit before
polling the endpoint, commits reported progress synchronously, and refunds
unused credit. Pending or failed operations retain their endpoint continuation;
extracting the components cancels only the wrapper's rate timers. Vectored
operations use the documented scalar fallback. Invalid endpoint counts fault
the wrapper and settle credit conservatively. Datagram admission remains
separate and must reserve the complete datagram.

Rate waits require an immutable real-time timer from `TimerDriver::new_realtime`.
Every alias rejects virtual-clock mode changes, while ordinary application
timer constructors retain pause/resume support. These explicit wrappers are
application ports; selecting buckets on a facade alone does not intercept
lower-level endpoints.
