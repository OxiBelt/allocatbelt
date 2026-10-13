# Application feedback traces

The development application lanes can retain complete feedback history and
resource samples for an external-pressure comparison. Set
`ALLOCATBELT_APP_FEEDBACK_TRACE_DIR` to a fresh private output directory.
Pressure qualification requires this directory; fixed-policy runs reject it.
The native executor and Tokio use the same history and collection settings.

The collector writes three files:

- `feedback-events.jsonl`, schema
  `allocatbelt.application-feedback-event.v1`, contains contiguous sequence
  numbers from startup readbacks through the joined worker marker. Samples,
  plans, tickets, attempted writes, mandatory readbacks, acknowledgements and
  reconciliation retain their typed numeric details.
- `resource-samples.tsv`, schema
  `allocatbelt.application-feedback-resource-sample.v1`, records initial,
  periodic 100 ms and terminal observations. It includes global and tenant
  ceilings, current limits and usage for all six resources; scope usage;
  bucket configuration and credit ownership; raw application-byte meters;
  feedback state; RSS and the collector's Task lease.
- `feedback-trace-manifest.tsv`, schema
  `allocatbelt.application-feedback-trace-manifest.v1`, binds process identity,
  source and binary hashes, stream schemas, byte counts, digests, sequences,
  declared charges, budgets and lifecycle timestamps.

Timestamps are brackets in the host's `CLOCK_MONOTONIC`. They preserve the
uncertainty of mapping Rust `Instant` to the external pressure process's clock.
Production start/end, drain, retained RSS checkpoints, shutdown and owner
release are recorded explicitly. Durations alone do not establish overlap.
Caller-pinned identities and hashes still require independent verification.

The service reserves a 16,384-event history ring. Collection drains it through
128-event batches and encodes each event into fixed storage before one file
write. Overwriting already-consumed ring slots is permitted. A cursor gap,
sequence overflow, incomplete record, writer failure or absent joined marker
invalidates collection; it cannot produce a successful completion manifest.

Each stream has a one-GiB byte ceiling. The collector also enforces its
published row counts and 11,400-second horizon. Event records are at most two
KiB and sample rows at most eight KiB. These bounds accommodate the required
three-hour horizon and finite setup, drain and shutdown allowances; a parent
must reserve sufficient storage before launch. The manifest publishes the
derivation and exact bounds for independent checking.

Control storage and the collector Task are admitted before retaining worker
buffers and resource handles. Completed output retains its charge owner while
queued or abandoned; backing drops before its reservation. At drain, runtime
readback subtracts only the known collector lease and requires zero remaining
application Tasks. The lease is released before strict shutdown Task checks;
final owner cleanup restores the independently calibrated global Control
baseline.

The traces support the independent
[pressure harness](application-pressure-driver.md) and capacity calibration.
They do not establish allocator/runtime performance or three-hour soak
acceptance. The campaign must validate complete traces, immutable limits,
actual external-pressure coverage and final resource release under its frozen
source and recipe before accepting a process.
