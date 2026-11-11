# Calibrated application feedback probe

The application feedback-policy probe has two output versions. The existing
invocation remains the uncalibrated v1 path:

```text
bench-application-allocatbelt --emit-feedback-policy-only --workload mixed --profile mixed
```

It keeps the v1 schema and its static feedback controls and rate buckets. The
calibrated v2 path is selected only when all four calibration identity options
are supplied together:

```text
bench-application-allocatbelt --emit-feedback-policy-only \
  --workload mixed --profile mixed \
  --capacity-calibration-file capacity.tsv \
  --capacity-calibration-sha256 <64-hex-digest> \
  --host-id <host-token> \
  --source-sha256 <64-hex-source-digest>
```

V2 loads the bounded `allocatbelt.app-byte-capacity.v1` artifact through the
same tenant-Control-charged loader used by application startup. It verifies
the supplied digest and the artifact's host, profile, workload, and source
identity. The probe then uses the shared application feedback resolver and the
same application-domain constructor used by the runtime. A relevant disk or
download source must have a positive measured application-byte capacity at
least as large as the existing 64 MiB/s feedback floor. Its policy initial and
ceiling and its bucket rate are set to the lesser of that measured capacity
and the existing 16 GiB/s rate roof. Capacities above the roof remain intact
as the feedback sensor's normalization denominator. CPU controls, thresholds,
timing, burst size, reservation bound, and upload rate keep their existing
values.

The v2 `capacity_calibration` object records the artifact schema and digest,
the checked identity, raw disk and download capacities with units and
provenance, and the versioned resolution rule with resolved controls and
per-direction buckets. Its verification scope is explicit: the probe checks
artifact bytes and run identity, but does not verify the calibration producer
or measurement chronology.

V2 starts no executor or feedback service. It constructs tenant-charged rate
buckets and feedback meters, reserves the same collector Control and Task
admission used by the trace collector, reads those live snapshots, and drops
the temporary owners before reading the resource domain again. The
`after_release` object comes from that actual snapshot and requires five global
resource dimensions to be zero, no live tenant, and global Control to equal
the constructor's fixed baseline. Meter source bounds remain upper bounds;
the probe does not claim that any endpoint is live or that a workload ran.
