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

The additive `resource-feedback` Cargo feature compiles
`runtime::resource_feedback::ResourceFeedbackService`. It starts only through
an explicit constructor with owned sensor and actuator implementations. The
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
`driver::default_feedback()` supply default values; feedback still runs only
when a builder selects the factory with `feedback_sources`. The capacity is
`std::thread::available_parallelism()`, or one if that fails, read once when
the factory is created. It follows the standard library's definition, which
honours CPU affinity and the CPU quota the standard library reports; the
library itself opens no control-group, `/sys` or pressure file for it.
`driver::default_feedback_for_capacity` takes the capacity explicitly. The
policy is a constant function of the capacity: CPU concurrency has floor 1 and
starts at its ceiling, the capacity, with fixed 40% and 80% thresholds
(`DEFAULT_LOW_UTILIZATION_BASIS_POINTS`, `DEFAULT_HIGH_UTILIZATION_BASIS_POINTS`).
The default factory uses the capacity as the sensor's utilization denominator
only. Its CPU control starts at the global CPU soft limit the domain has when
the driver is built and stays between floor 1 and the domain's hard CPU
ceiling, so a limit an earlier driver lowered can recover and no limit rises
above what the caller configured as the ceiling.

Two properties follow from the fixed law and are not tuned away. A reduction
is a tenth of the current limit, so a limit below ten never falls and a larger
one stops at nine. Utilization is this process's CPU time over the capacity,
not over the domain limit: a domain limit well below the capacity may keep
admitted work under the high threshold, and then the limit never falls.
Select the default factory for at most one driver per domain; two services
moving the same limit see each other's changes as external drift and latch.

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

Startup conditions are reported rather than repaired. A builder without
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
