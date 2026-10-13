# Application feedback trace readback

`scripts/application-feedback-readback.py` independently validates the bounded
feedback trace emitted by the application runtime. It accepts a frozen caller
expectation and separately pinned raw SHA-256 values for the manifest, JSONL
events, and sample TSV. The reader opens the dedicated trace directory without
following links, enforces the exact three-file layout, and streams both large
artifacts one bounded record at a time.

Freeze a canonical expectation from a caller-authored JSON spec:

```sh
python3 scripts/application-feedback-readback.py freeze \
  --spec feedback-expectation-spec.json \
  --output feedback-expectation.json
```

The command prints both the complete raw expectation digest and the digest of
the expectation body. Pass the raw digest separately during verification:

```sh
python3 scripts/application-feedback-readback.py verify \
  --expectation feedback-expectation.json \
  --expected-expectation-sha256 RAW_EXPECTATION_SHA256 \
  --trace-directory /absolute/private/run/feedback-trace \
  --expected-manifest-sha256 MANIFEST_RAW_SHA256 \
  --expected-events-sha256 EVENTS_RAW_SHA256 \
  --expected-samples-sha256 SAMPLES_RAW_SHA256 \
  --output /absolute/private/run/feedback-validation.json
```

New application feedback expectations use
`allocatbelt.application-feedback-expectation.v2` by default. V3 adds the
external soak binding described below; v4 adds SourceV5 binding for normal
application capacity calibration. Archived v1 expectations remain readable
using their historical exact-count meter contract, but are never pressure
qualification-eligible. V1 and v2 use SourceV4 and retain their original
single-binary identity. V3 and v4 require SourceV5. Every JSON object has an
exact key set, duplicate keys and non-finite values are rejected, and
canonical JSON uses sorted keys, compact separators, ASCII escaping, and one
final LF. The recipe binds the actual process ID and report nonce, run,
allocator, executor, workload, profile, run mode, source tree and binary hashes,
plus the source-manifest path and raw digest. For v1/v2, the source manifest's
`build.host_id`,
`source.source_tree_sha256`, and `artifacts[allocator].sha256` must match the
expectation.

Every v2/v3/v4 expectation also pins a canonical construction-only feedback
policy probe by absolute path, raw SHA-256, allocator and binary digest. The reader
checks the probe context and all timing, control, ceiling, scope, bucket,
collector and meter-bound projections against the caller-frozen policy, and
requires the probe binary digest to match the expected application-emitter
artifact. For v2 that is also the feedback process binary. For v3 it is the
normal `artifacts.allocatbelt` binary and is distinct from the timed soak
binary. The probe starts no workload and cannot establish when it ran; the
owning campaign controller records that the probe preceded qualification in
its run ledger.

V4 retains the V2 expectation key set, including `construction_probe`, while
the default schema constant remains V2. Its timed application and construction
probe both match `SourceV5.artifacts[allocator]`. After the pinned controller
and campaign-inputs module validate the complete SourceV5 manifest, the reader
projects cadence, density, controls and algorithm from the selected
`feedback_policy` context. It projects global and tenant ceilings, scope
limits and byte buckets from `fixed_runtime_policy`, using four workers for
ordinary profiles and two for oversubscribed profiles. The global Control
baseline comes from the independent
`resource_domain_calibration.record`. The probe's collector Control charge
and Task lease must match the expectation and trace manifest. Every
construction-probe source reference must have one regular SourceV5 inventory
entry.

The policy section pins all three numeric control configurations, the fixed
100 ms sample cadence, 200 ms dense gap, 500 ms freshness, three-sample breach,
one-second cooldown and one dense-observation minimum. It also pins global and
tenant hard ceilings for all six domain resources, scope limits, disk/upload/
download bucket ceilings, bursts and reservation caps, the trace collector
Task lease and Control charge, and the independent global Control baseline.
The source probe freezes construction-derived `meter_source_bounds` for disk,
upload and download; these bounds are not inferred from observed samples. The
current live count may move between zero and its workload-specific maximum:
disk has maximum one for disk and mixed workloads, while upload and download
have maximum sixteen for HTTP and mixed workloads. Other directions have a
zero maximum. The rules are `disk_shared_owner`,
`http_client_and_server_window`, or `not_applicable`, and each bound names the
`registered_endpoint_owner` lifetime. A reduced soft limit may have
grandfathered live usage; each sample must remain within its pinned hard
ceiling.

`capacity_calibration` deliberately has no app-byte-capacity artifact digest.
It keeps numeric disk and download policy bounds, pins both application-byte
sources as unavailable, and requires those controls to remain at their initial
limits with Missing telemetry and no write tickets. CPU must start at a fixed
2 or 4 slots. The reader reconstructs CPU reduction quantization and ceiling
recovery directly from samples and plans; it does not add artificial reduction
steps. A calibration receipt is always `qualification_eligible: false`.
V4 keeps the ten-field
`allocatbelt.application-feedback-validation.v1` receipt and has no final
runtime proof. Its initial missing CPU sample may serve as sensor priming;
dense CPU observations must still cover production and drain, and the
two-or-four-slot quantized CPU policy remains unchanged.

`pressure_validation` requires an app-byte-capacity artifact digest, a pinned
external pressure readback, and a pinned final runtime-binding TSV. The
pressure readback binds the validated recipe raw digest and reader hash, the
pressure recipe identity, application PID/start/nonce/binary, and the
continuous-ready pressure interval. That interval uses only contiguous,
complete, ready pressure samples after the authenticated readiness barrier; a
sample that overlaps application start or the trailing inactive observation
counts only when its measured readiness passes. The feedback reader requires
the interval to contain the conservative production-start lower bound through
drain-end upper bound. Initialization and shutdown may fall outside readiness.
It separately preserves the measured application/pressure overlap minimum and
the PID/start/nonce/binary binding. The pressure reader reports a real IPv4
loopback witness; no physical NIC claim is accepted.

`pressure_soak_validation` uses expectation v3 and requires the same pressure
readback plus two independently frozen final-binding inputs: the canonical
`allocatbelt.runtime-soak.v2` receipt and the canonical
`allocatbelt.application-soak-readback.v2` composite. SourceV5 is verified by
the captured, regular, inventory-pinned campaign controller and its full
versioned verifier. Its typed regular-file entries must bind every
construction-probe source reference and the feedback, pressure and soak
validators. The reader also checks the probe's reader, algorithm and
workload/profile controls against the SourceV5 feedback-policy artifact. The
construction probe remains bound to the normal
`artifacts.allocatbelt` application emitter; the feedback process is bound to
`soak_artifacts.allocatbelt`. Those binaries have separate hashes.

The v3 `external_soak_identity` freezes these 13 parent fields:
`campaign_id`, `host_id`, `run_id`, `nonce`, `allocator`, `executor`,
`workload`, `profile`, `comparison_family`, `source_sha256`, `build_sha256`,
`binary_sha256`, and `resource_ceiling_sha256`. The Rust receipt records
executor `bounded`, while the feedback trace labels that same native executor
`allocatbelt`; this is the explicit role mapping. The receipt omits a build
digest, so the adapter binds it through
SourceV5 and the audited composite. Run ID, nonce, host, source, workload,
profile and timed binary must bind across the soak identity and feedback trace.
It checks the receipt's final global and tenant application charges are zero,
global live tenants are zero, global
Control equals the independently calibrated baseline, and feedback workers
started and joined without failure.

The Rust receipt carries bracket fields `<phase>_monotonic_lower_ns` and
`<phase>_monotonic_upper_ns` for `started`, `trace_ended`, `drain_ended`,
`shutdown_ended`, and `postprocess_ended`, alongside the legacy scalar
endpoints. The soak composite has exactly fifteen fields, including its
validator pin, receipt digest and a `monotonic_endpoints` map with those five
two-value brackets. The feedback reader requires each bracket to match the
Rust receipt, and requires the composite's `receipt_sha256` to equal the
captured raw receipt SHA. It matches the first four
receipt brackets exactly to the trace's production start/end, drain end and
shutdown end markers, and requires owner release to fall after shutdown and
before postprocess. Endpoints use the same captured `Instant`; no timing
tolerance is applied. The mandatory pressure proof must cover production
start through drain end. A short functional soak can validate its artifacts
but is always ineligible for qualification.

The event reader independently transcribes `runtime-feedback-policy-v1`. It
checks startup actuator readbacks, sample order and cadence, policy freshness
and density, hysteresis, breach streaks, cooldowns, CPU/rate quantization,
ticket generations and arithmetic, mandatory pre-write and post-write
readbacks, acknowledgements, and fault reconciliation. Missing, sparse, or
stale telemetry must produce the policy's matching no-change state and keep
that control frozen. A fault remains latched until a recorded successful
reconciliation and a fresh post-reconciliation sample.

Resource rows are checked against the independent ceilings and reservation
caps. Each meter bracket must be inside its containing resource snapshot; its
fixed-width monotonic bracket must strictly advance by no more than 200 ms.
Rates use the actual difference between measured lower bounds. Counter values
cannot decrease within a generation, and a reset requires a greater generation.
Every meter attachment count must fit its caller-frozen v2 source bound;
legacy v1 rows must equal their archived pinned count. A live endpoint owns an
RAII registration that retains its tenant-charged shared meter, so a terminal
sample may still have attached sources while application bindings are alive.
After those owners drop, the global Control baseline and zero live tenants
prove the charged meter storage has been released. Meter diagnostic flags are
checked. The final row must follow `WorkerJoined`, show a completed
shutdown, have no worker failure or pending ticket, and match the final policy
state. The phase markers must order production, drain, RSS checkpoints,
shutdown and owner release; production duration is reported with conservative
monotonic-clock bounds.

For `pressure_validation` v1/v2, the final runtime-binding reader checks
identity, zero application and owner usage after shutdown, zero byte-bucket
reservations, feedback join, and the
post-release global Control baseline. `application-runtime-binding.v2` also
requires captured post-release global CPU, memory, disk, network, and Task
usage, with every dimension equal to zero. Historical v1 receipts remain
readable with their four legacy post-release rows, but are never
qualification-eligible. A v1 header carrying any v2-only final resource fields
is rejected. The feedback receipt's
`qualification_eligible` flag reports only this component's gates and does not
qualify application performance or satisfy the broader campaign gates.

The validation receipt has exactly ten top-level keys:
`schema`, `mode`, `validated`, `qualification_eligible`,
`expectation_raw_sha256`, `validator_sha256`, `identity`,
`raw_artifact_sha256`, `production_window`, and `final_runtime_binding`.
For v3, the result uses validation schema v2 and `final_runtime_binding`
reports the soak receipt and composite digests, validation state, soak mode,
and component eligibility. This remains one component result and does not
complete SourceV5 campaign qualification. `production_window` contains exactly
`start_monotonic_ns` and `end_monotonic_ns` two-bound arrays, plus lower and
upper duration bounds.

Run the focused suites only on the designated native SSH-MCP host:

```sh
python3 -B scripts/test-application-feedback-readback.py
python3 -B scripts/test-application-pressure-driver.py
```

The fixtures are synthetic contract tests. They do not launch a production
application, run a qualification campaign, or make performance claims.
