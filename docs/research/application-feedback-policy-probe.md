# Application feedback policy probe

`bench-application-* --emit-feedback-policy-only --workload WORKLOAD --profile PROFILE`
emits one canonical JSON record for a supported workload/profile pair. It is a
construction-only input for SourceV5 calibration preparation. The command does
not start an application executor, feedback service, thread, or workload and
does not collect runtime observations.

The top-level envelope is
`allocatbelt.application-feedback-policy-probe.v1`. Its `context` contains only
`workload`, `profile`, and `workers`. `reader_context` records the numeric
sampling and feedback-reader timing contract. `rust_control_context` records
the same-source controls, global and tenant ceilings, workload scope limits,
fixed rate buckets, and which byte denominators are required. `collector`,
`baseline`, and `meter_source_bounds` are separate sections so their values can
be independently compared with runtime receipts. `meter_source_model` explains
the registration ownership model; its minima and maxima are bounds, not claims
about observed live registrations.

`source_references` names the tracked source paths that define these values.
It includes the application/port configuration, feedback policy and bindings,
collector, meter registration, and resource-domain implementation. The
SourceV5 composer resolves every path to a regular entry in the exact
authenticated SourceV4 inventory and records its file SHA-256. The caller also
pins the probe's raw output bytes and the emitting application binary before
workload observations. The probe does not derive source or binary identity from
its own output.

The baseline is obtained by constructing and dropping the application's
`ResourceDomain` with its same-source limits and waiter bound, before creating a
tenant. It is not a post-run measurement. The collector Control charge comes
from the trace collector's fixed-size charge calculation, and its Task lease is
one. These numeric values must match the separately recorded trace and final
runtime-binding receipts before any capacity calibration can be considered.

The meter-source bounds follow the application registration structure: disk
uses at most one shared filesystem meter owner; HTTP uses at most the eight
client slots plus eight accepted-handler slots per direction. Each live
`RateLimitedIo` endpoint registers read and write meters. A source count may be
zero during an observation while its cumulative byte counter still increases;
the probe therefore supplies only minimum/maximum bounds and does not predict
per-sample registration counts.

All emitted contexts remain functional calibration preparation. This command
does not assert chronology, validate calibration artifacts, or make a campaign
qualification eligible.
