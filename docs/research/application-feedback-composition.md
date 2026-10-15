# Calibrated application feedback composition

The calibrated feedback composition module prepares a SourceV5 pressure
policy from two independently checked inputs: the SourceV5 numeric policy and
a complete application-byte capacity producer bundle. The Rust application
emits construction probe V2 from the exact pinned capacity TSV. The reader
independently parses that TSV, applies the resolution rule, and compares the
result with the Rust controls, buckets, and constructor/drop observations.

For disk and download, a relevant measured application-byte rate must be at
least 64 MiB/s. The resolved initial and ceiling are the smaller of the raw
rate and 16 GiB/s. The original raw rate remains in the capacity artifact and
is never rewritten. CPU controls, timing, utilization thresholds, upload rate,
bursts, reservation caps, domain ceilings, and scope limits stay pinned to
the SourceV5 policy. Capacity artifacts must retain application-byte units,
their calibration context, and the producer's exact trace provenance.

The 64 MiB/s floor remains the default, and no-selector requests retain their
original request, policy, receipt, and expectation shapes. A prospectively
selected SourceV5 epoch may freeze the exact policy ID
`application_capacity_relative_tenth_v1` in SpecV3 and the external-pressure
template. Its source-published descriptor pins the rule
`max(1, min(64 MiB/s, raw_capacity / 10))` with integer division. Both the
calibrated ProbeV2 producer and the independent resolver require the same
selector and raw capacity artifact; the actual pressure APP additionally
requires explicit pressure qualification. The 16 GiB/s roof, bursts,
reservations, CPU controls, matched allocator/executor identities, and the
campaign's 1.05/0.95 gates do not change. A selected policy is prospective
configuration only and is not evidence that an application met any gate.

The module has two steps. `resolve` verifies the full SourceV5 manifest,
replays the pinned capacity request/artifact/receipt through the pinned
capacity producer, reruns the pinned application probe, and writes a resolved
policy plus a composition receipt. This step does not require or create a
process ID. `finalize` consumes those exact files and a caller-supplied
expectation header once the caller has captured the application's real PID
and the finalized pressure/runtime proof paths and digests. It requires a
positive PID before freezing expectation V5 for the default policy; a selected
floor epoch freezes expectation V6. It does not start the application
or pressure driver, and it does not attest that the supplied PID came from a
particular process; the campaign ledger must bind that process independently.

The no-workload application probe runs in a new session with bounded captured
stdout and stderr. Cleanup observes the leader with `waitid(WNOWAIT)` so its
unreaped PID continues to anchor the numeric process-group ID through TERM/KILL
and live-member checks. `/proc` zombies count as exited; a live descendant that
changed process groups makes cleanup fail closed. The leader is reaped once,
under a deadline, only after the final group check, and no process-group ID is
used after that reap. A non-default `SIGCHLD` disposition is rejected because
it could reap the leader before ownership is verified.

The resolved policy can be bound to any original application artifact label
(`allocatbelt`, `mimalloc-secure`, `mimalloc-standard`, or `system`) and to
either original executor label (`allocatbelt` or `tokio-1.53.1`). The capacity
calibrator has its own allocator/executor identity and must match its own
SourceV5 artifact; it may differ from the target application artifact that
consumes the shared capacity result.

Example request files use canonical JSON and absolute paths. A resolver
request has exactly these top-level fields:

```json
{
  "schema": "allocatbelt.application-feedback-composition-request.v1",
  "source_root": "/absolute/source/root",
  "source_manifest": {"path": "/absolute/source.json", "raw_sha256": "..."},
  "context": {
    "host_id": "host-id",
    "workload": "mixed",
    "profile": "mixed",
    "calibration_id": "capacity-id"
  },
  "construction_probe": {
    "path": "/absolute/probe-v2.json",
    "raw_sha256": "...",
    "allocator": "allocatbelt",
    "binary_sha256": "..."
  },
  "capacity_bundle": {
    "request": {"path": "/absolute/capacity-request.json", "raw_sha256": "..."},
    "artifact": {"path": "/absolute/capacity.tsv", "raw_sha256": "..."},
    "receipt": {"path": "/absolute/capacity-receipt.json", "raw_sha256": "..."}
  }
}
```

Run it with:

```sh
python3 -B scripts/application-feedback-composition.py resolve \
  --request /absolute/resolve-request.json \
  --policy-output /absolute/resolved-policy.json \
  --receipt-output /absolute/composition-receipt.json
```

The finalization request contains the source, policy, receipt, construction
probe, and capacity pins; its `expectation_header` contains the actual
application identity, pressure proof pin, runtime binding pin, and minimum
duration fields. Its `identity.process_id` must be captured from the spawned
application. `finalize` writes expectation V5 for the default policy; a
selected floor epoch writes expectation V6 and carries the same policy ID in
the composition receipt and offline probe replay. It also writes a separate
finalization receipt.

Both receipts set `execution_ready`, `qualification_eligible`, and
`controller_chronology_proven` to false. The capacity artifact's producer
receipt continues to say that producer and measurement chronology are
unverified. A caller still needs the later campaign ledger checks, a real
pressure-first launch/readiness proof, matched native/Tokio pressure runs,
and the existing successful fixed predecessor before it can confirm a cell.
Expectations V5 and V6 do not change fixed-family rate policy, historical V1–V4
expectations, original nonces, or the original campaign matrix.

## Owned ProbeV2 capture and offline replay

`capture_calibrated_probe_v2(request, request_raw_sha256, observed_host_pin,
output_root=..., capture_id=..., capture_timeout_ns=...,
storage_budget={tmpdir_bytes, tmpdir_inodes, stdout_bytes, stderr_bytes,
owner_result_bytes, inventory_bytes, failure_bytes, receipt_bytes, output_inodes})` is the additive strict
origin-host capture path. The caller supplies the original resolver request,
the raw-pinned SourceV5 observed-host context, a fresh 32-hex capture ID, and
prospective finite byte/inode limits. Before launch, the budget reserves the
FixedR8 16 MiB owner-result bound, the existing 16 MiB metadata bound for the
TMPDIR inventory sidecar, a 64 KiB failed-capture record, and at least seven
output inodes. The receipt is capped at the existing 16 MiB metadata bound.
Its budget must cover the canonical prospective receipt shape, computed from
the exact request, observed host, output paths, and maximum-width bounded
process/storage fields before `Popen`; an undersized budget is rejected before
launch. The output root must already be an owned
mode-0700 directory outside the SourceV5 tree. The function replays the full
capacity producer bundle and static ProbeV2 policy checks, then launches the
exact pinned APP binary through the SourceV5-inventoried FixedR8 direct process
owner and its pinned launch-identity helper. It captures the existing argv,
an allowlisted environment, cwd, affinity, network namespace, positive PID and
start ticks through FixedR8's minimal `capture_identity=False` probe role,
raw status, output bytes, cleanup, and output/TMPDIR storage facts. The role
does not claim the full live `/proc/PID/exe` attestation used for timed APPs.
It does not rewrite the probe, capacity TSV, or resolver request. A failed
launch leaves its captured files in place; its receipt cannot pass offline
replay. Immediately after the direct owner returns, the complete direct status,
start callback and cleanup object is written to `owner-result.json`; the sorted
TMPDIR path, type, owner, mode, size, and file digest inventory is written to
`tmpdir-inventory.json`. The small closed capture receipt pins the raw and
semantic digest of each sidecar instead of embedding the owner/process and
inventory graphs. If later output, TMPDIR, host or receipt validation fails, a separate bounded
`allocatbelt.application-feedback-probe-capture-failure.v1` record preserves
the owner-result and, when available, inventory sidecar pins plus the failing
stage with all readiness/eligibility flags false. An owner exception is
recorded as an exception and output pins when available; it is never
represented as a normal capture. A direct owner result outside the FixedR8
16 MiB bound produces a separate bounded overflow diagnostic with its raw
digest, byte count, exit and cleanup summary and retained raw output paths; it
cannot produce a capture receipt.

The returned receipt pin is `{path, raw_sha256, receipt_sha256}`. Its closed
`allocatbelt.application-feedback-probe-capture.v2` body keeps SourceV5 raw,
semantic, source-tree, and build digests in separate fields and binds the
capacity request/artifact/receipt pins, original ProbeV2 pin, APP ELF, host
context, owner modules, exact process proof, and raw-pinned owner-result and
TMPDIR inventory sidecars. Every eligibility,
execution-ready, and chronology flag stays false.
The semantic `receipt_sha256` is computed over the canonical body before that
field is added; the receipt pin's `raw_sha256` hashes the final envelope bytes.

`compose_calibrated_policy_v5_offline(request, request_raw_sha256,
replay_context=...)` and
`finalize_calibrated_feedback_expectation_v5_offline(request,
request_raw_sha256, replay_context=...)` are pure replay entrypoints. Their
closed `allocatbelt.application-feedback-offline-replay-context.v1` argument
contains the identity-only, sorted
`allocatbelt.application-pressure-evidence-path-map.v1`, the captured receipt
pin, and the exact capacity bundle pins. The reader reparses each raw receipt,
replays the producer and policy constraints, and compares the captured stdout
to the unchanged original ProbeV2 bytes on every call. Every referenced file
and evidence directory has its own exact map entry; an ancestor directory does
not stand in for a nested file. The map and recursive source, producer, V4
trace, expectation, capture, output, and TMPDIR membership are checked
before captured SourceV5 code is executed. The path map supports identical
origin/local absolute paths only. Neither offline API launches an APP, reads
coordinator `/proc`, or changes legacy `resolve`/`finalize` behavior.

The offline composition APIs prove this calibrated policy component only.
`verify_feedback_offline` currently stops with an explicit blocked error after
the ProbeV2 replay because its context does not yet contain the independent
pressure artifact replay request. It never returns a partial feedback result
or treats the pressure readback's stored status as proof. Full offline feedback
and cohort qualification still require the separately implemented pressure,
Soak, and journal replay APIs and all original host-local captures.

Ordinary fixture runs are unqualified correctness coverage. To make the
phase-one native capture/replay a required gate, set
`ALLOCATBELT_FEEDBACK_V5_NATIVE_CAPTURE_REQUIRED=1` and supply both
`ALLOCATBELT_FEEDBACK_V5_SOURCE_MANIFEST` and
`ALLOCATBELT_FEEDBACK_V5_OBSERVED_HOST`, each pointing to original raw-pinned
native inputs. The gate fails if either input is missing; it does not skip the
actual APP capture or count shape-only fixtures as that witness. Run the
dedicated method with:

```sh
ALLOCATBELT_FEEDBACK_V5_NATIVE_CAPTURE_REQUIRED=1 \
ALLOCATBELT_FEEDBACK_V5_SOURCE_MANIFEST=/absolute/source5.json \
ALLOCATBELT_FEEDBACK_V5_OBSERVED_HOST=/absolute/observed-host.json \
python3 -B scripts/test-application-feedback-composition.py \
  CompositionContractTests.test_source5_app_cli_full_v4_bundle_replay_resolves_v5_policy_ineligible
```

That test's capacity trace is a synthetic bounded component fixture. The APP
constructor run itself is real and source-pinned, but the fixture is not a
genuine capacity or pressure qualification witness. The test also records a
bounded failed-deadline probe capture and proves its files remain offline
ineligible. The SourceV5 manifest
must inventory the accepted new helper bytes; an older source manifest cannot
be reused by overlaying these files.
