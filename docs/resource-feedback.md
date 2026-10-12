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
