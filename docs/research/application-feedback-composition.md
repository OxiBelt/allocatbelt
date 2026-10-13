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

The module has two steps. `resolve` verifies the full SourceV5 manifest,
replays the pinned capacity request/artifact/receipt through the pinned
capacity producer, reruns the pinned application probe, and writes a resolved
policy plus a composition receipt. This step does not require or create a
process ID. `finalize` consumes those exact files and a caller-supplied
expectation header once the caller has captured the application's real PID
and the finalized pressure/runtime proof paths and digests. It requires a
positive PID before freezing expectation V5. It does not start the application
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
application. `finalize` writes expectation V5 and a separate finalization
receipt.

Both receipts set `execution_ready`, `qualification_eligible`, and
`controller_chronology_proven` to false. The capacity artifact's producer
receipt continues to say that producer and measurement chronology are
unverified. A caller still needs the later campaign ledger checks, a real
pressure-first launch/readiness proof, matched native/Tokio pressure runs,
and the existing successful fixed predecessor before it can confirm a cell.
Expectation V5 does not change fixed-family rate policy, historical V1–V4
expectations, original nonces, or the original campaign matrix.
