# SourceV5 context-scoped pressure calibration v2

This note defines the additive pressure calibration v2 contract implemented by
`application-pressure-driver.py` and `application-pressure-readback.py`. The
existing pair-scoped calibration v1 and its exact raw-policy/pair-ID checks
remain unchanged. SourceV5 consumers select v2 explicitly through
`pressure_condition.pressure_calibration_v2`; they do not relabel a v1
calibration.

## Context inputs

`calibrate-context-v2` accepts a canonical
`allocatbelt.application-pressure-calibration-request.v2` object with exactly
`schema, identity, files, storage, schedule, scope`. Its identity is exactly
`{host_id, run_id, condition_id, nonce}`: the run ID and nonce identify this
calibration execution, and it has no pair ID. `files` has exactly
`source_manifest, policy, application_capacity_calibration`; each is the
existing `{path, sha256}` file pin. `storage` and `schedule` use the existing
closed pressure request contracts.

`scope` has exactly `schema, condition, source_root, source_manifest,
context_policy, capacity_bundle_pins, observed_host, capacity_key`.
`condition`, `source_manifest`, `context_policy`, and `observed_host` are
`{path, raw_sha256}` pins. The SourceV5 source root is an absolute directory.
The `source_manifest` pin must equal both `files.source_manifest` and the
SourceV5 pin inside `capacity_bundle_pins`. `files.policy` must equal the
shared policy artifact pin inside the context-policy bundle, and
`files.application_capacity_calibration` must equal the producer bundle's
`artifact` pin. `condition` pins the canonical Source5 pressure-condition
file with exactly `schema, host_id, condition_id, capacity_key,
pressure_calibration_id, readiness_threshold_rule, readiness_thresholds,
pressure_thresholds, schedule`. The pressure calibration ID is a prospective
token distinct from both the condition ID and the capacity key's calibration
ID. `readiness_thresholds` preserves the separate three-key campaign overlap
record. `pressure_thresholds` is the exact seven-key numeric readiness map
supplied before calibration. The rule ID
`allocatbelt.application-source5-pressure-readiness-threshold-rule.v1` means
that those values are frozen before measurement; the reader cannot derive,
lower, or substitute them after a miss. Every measured calibration window
must meet all seven values. Campaign readiness requires at least 30 seconds
of overlap, a 100 ms cadence, enough ready samples for that entire overlap,
and no sample gap over 200 ms.

The capacity bundle pin is
`allocatbelt.application-pressure-capacity-bundle-pin.v2` with exactly
`schema, capacity_key, source_manifest, request, artifact, receipt`.
`capacity_key` is the original four-field key
`{host_id, workload, profile, calibration_id}`. All file references are
`{path, raw_sha256}`. The pinned artifact must be the exact same prepared TSV
used by the SourceV5 context and policy composition. The verifier loads the
typed SourceV5 byte-capacity producer and calls its full request/artifact/
receipt replay; it does not accept a TSV digest alone.

The context-policy bundle file uses
`allocatbelt.application-pressure-context-policy-bundle.v2` with exactly
`schema, artifact, members`. `artifact` is a `{path, raw_sha256}` pin to the
shared numeric policy file. `members` contains exactly the two ordered
original pressure-pair members. Each member has exactly `descriptor, request,
construction_probe, resolved_policy, composition_receipt`. `descriptor` is
`{pair, executor, allocator}`. The request, resolved policy and composition
receipt are `{path, raw_sha256}` pins. `construction_probe` is the existing
`{path, raw_sha256, allocator, binary_sha256}` pin. These are the existing
raw pins emitted by SourceV5 policy composition. The independent reader loads
the typed SourceV5 composer and validators, replays both composition requests
and construction probes, compares both resolved policies and receipts to
their raw pins, and reconstructs the shared policy document.

The numeric context digest hashes a versioned projection of the reconstructed
shared policy after removing only `member_resolutions` and the resulting
whole-document `policy_sha256`. Every other field, including source pins,
capacity producer pins, fixed and calibrated numeric policy, baseline,
ceilings, and normalization denominators, remains in the projection. The
reader rejects unknown fields and independently rebuilds both pair
resolutions before accepting this digest.

The context is also bound to the canonical Source5 pressure-condition file,
observed boot/host controls, CPU affinity, storage device/mount/backing chain,
loopback route and network namespace, and the full pressure intensity profile.
The condition key, schedule, both readiness maps, pressure calibration ID,
and capacity key are checked against their original pins.

## Calibration artifact and independent receipt

The produced artifact uses
`allocatbelt.application-pressure-contention-calibration.v2`. It contains the
context key and scope digest, SourceV5 semantic/tree/raw manifest pins, exact
capacity bundle pins and TSV raw SHA, the observed-host raw pin, host/storage/
network observations, the complete measured sample series and summary,
the exact prospective pressure thresholds and the existing measured proposal,
worker PID/start/session records, bounded worker cleanup, scratch-file
removal, deadlines, and exact driver and reader hashes. The proposal is
diagnostic and never selects or relaxes the seven frozen values. It contains
no pair identity.

`verify_calibration_scope_v2(calibration_pin, context_policy_pin,
capacity_bundle_pins, observed_host_pin)` takes one capacity bundle object and
independently validates the closed
artifact and its self-digest, replays the capacity producer and both genuine
policy resolutions, checks host/scope bindings, recomputes every sample
summary and proposal, checks every measured window against the prospective
thresholds, and validates worker cleanup and scratch removal. It
returns a canonical
`allocatbelt.application-pressure-calibration-scope-readback.v2` receipt.
The receipt has exactly `schema, replay_success, validated, execution_ready,
qualification_eligible, controller_chronology_proven, calibration_raw_sha256,
calibration_sha256, scope_sha256, condition_id, pressure_calibration_id,
capacity_key, condition_sha256, source_manifest_sha256,
source_manifest_semantic_sha256, source_tree_sha256,
context_policy_bundle_raw_sha256, context_policy_artifact_raw_sha256,
context_policy_sha256, capacity_bundle_pins_sha256, capacity_tsv_raw_sha256,
observed_host_raw_sha256, host_verification, driver_sha256, reader_sha256,
capacity_producer_sha256, feedback_composer_sha256, feedback_reader_sha256,
sample_count, samples_sha256, summary, pressure_thresholds,
readiness_thresholds, suggested_readiness_thresholds, worker_cleanup_sha256,
worker_session_count, scratch_file_removed, receipt_sha256`. `replay_success`
and `validated` are true; execution readiness, qualification eligibility,
and controller chronology are false. The receipt file pin is exactly
`{path, raw_sha256, scope_sha256}`. The CLI
`verify-calibration-scope-v2` rebuilds this receipt from the pinned inputs.
`calibrate-context-v2 --request REQUEST --output CALIBRATION --scope-receipt
RECEIPT` writes both artifacts using that independent verifier.

`host_verification` is the closed object
`{schema, host_id, boot_id_sha256, kernel_release, allowed_cpu_affinity,
network_namespace_inode, observed_host_raw_sha256, owned_worker_pids_reaped,
host_verification_sha256}`. The host-local verifier checks those host facts
against the live kernel and checks every recorded worker PID/start pair is no
longer present before it writes the receipt. Offline cohort completion calls
`verify_calibration_scope_v2_offline(calibration_pin, context_policy_pin,
capacity_bundle_pins, observed_host_pin, *, source_root, evidence_path_map,
host_verification_pin)`. It replays the complete producer, both composers,
samples, threshold gates and cleanup evidence and compares the resulting
canonical receipt to the host-local receipt.

The offline map uses `allocatbelt.application-pressure-evidence-path-map.v1`
with exactly `{schema, entries:[{origin, local}]}`. Entries are sorted by
origin and both paths are normalized absolute paths. The first supported
cohort requires identity entries (`origin == local`) because SourceV5
producer/composer requests bind absolute paths inside their canonical bytes.
Include the SourceV5 root and each evidence/input directory plus standalone
pin outside those directories. Stage peer files under their original paths on
the primary host. The reader checks every raw pin against the unchanged origin
path and rejects a missing map entry. It never rewrites a condition,
calibration, observed-host file, or producer request. Non-identity path copies
are unsupported because they would change the canonical absolute path fields
consumed by the SourceV5 producer and composer.

SourceV5 helper modules are executed from the exact captured bytes whose
inventory hash, size and mode were checked. The pressure reader compiles those
bytes directly into a registered in-memory module; it does not delegate to a
path loader or bytecode cache. During offline replay, every absolute path in a
producer/composer request is checked against the explicit identity map before
the pinned SourceV5 helper receives it. Before loading those helpers, replay
also reads only mapped canonical inputs to close their transitive references:
the capacity request's source, context, validation and expectation pins; the
V4 expectation's construction probe; the context-policy bundle's shared
artifact; and each composer request's source, capacity and construction-probe
pins plus its pinned outputs. It checks each nested path before opening that
referenced file, then the pinned helpers perform their full independent replay.
A map entry for a directory covers only that directory's descendants. The
reader does not install global `Path` or `open` hooks.

## Genuine native replay fixture

The focused reader tests expose a full replay entrypoint for a supplied,
raw-pinned native fixture:

```sh
python3 -B scripts/test-application-pressure-readback.py --scope-fixture FIXTURE.json
```

The fixture has exactly `schema, source_root, evidence_path_map,
calibration_pin, context_policy_pin, capacity_bundle_pins, observed_host_pin,
host_verification_pin, expected`. Its schema is
`allocatbelt.application-pressure-calibration-v2-native-fixture.v1`. The
calibration and observed-host pins are `{path, raw_sha256}`; the host-local
verification receipt pin is `{path, raw_sha256, scope_sha256}`. The complete
capacity bundle retains its v2 object shape and all four original file pins.
The per-job context-policy bundle must be independently assembled from its two
real SourceV5 composer requests, construction probes, resolved policies and
composition receipts. Its member references must differ from those in the
calibration bundle while the reconstructed numeric projection and exact
prepared TSV remain the same. The fixture does not synthesize or replace any
of these inputs.

`expected` is closed and contains `host_id, condition_id,
pressure_calibration_id, capacity_key, calibration_raw_sha256,
calibration_sha256, scope_sha256, condition_sha256,
source_manifest_sha256, source_manifest_semantic_sha256, source_tree_sha256,
capacity_tsv_raw_sha256, capacity_bundle_pins_sha256, context_policy_sha256,
context_policy_artifact_raw_sha256, sample_count, samples_sha256, summary,
pressure_thresholds, readiness_thresholds, driver_sha256, reader_sha256,
capacity_producer_sha256, feedback_composer_sha256, feedback_reader_sha256,
host_verification_sha256, calibration_context_policy_bundle_raw_sha256,
per_job_context_policy_bundle_raw_sha256, worker_cleanup_sha256,
worker_session_count, scratch_file_removed`. Populate these from the captured
artifacts and strict host-local receipt. The entrypoint calls the public
offline verifier, compares every expected field, then checks copied-fixture
mutations for numeric-policy, source-manifest, receipt-threshold, condition,
capacity TSV and cleanup rejection. It emits a small canonical replay receipt
summary with qualification eligibility still false. Missing or malformed
fixture inputs fail the command; they are not reported as skipped coverage.
The fixture also removes the identity entry for each genuine nested capacity
expectation/probe and per-job composer probe in turn, requires a map-boundary
failure before dependency replay, then restores explicit identity entries and
requires the full public replay to pass.

The currently supported cohort stages peer evidence at the same absolute
paths used by the original producer/composer requests. Non-identity relocation,
request rewriting and global file-I/O interception remain unsupported.

## Per-job use

Source5 pressure recipes add the closed binding
`pressure_condition.pressure_calibration_v2` with exactly
`schema, calibration_id, artifact, scope_receipt, validator_sha256,
context_policy, capacity_bundle_pins, observed_host, pressure_calibration_id`.
The v2 `calibration_id` identifies the capacity context, while
`pressure_calibration_id` is the distinct prospective pressure identity. The policy and host
values are `{path, raw_sha256}` pins; `scope_receipt` is
`{path, raw_sha256, scope_sha256}`. The
original
`pressure_condition.pressure_calibration` object remains the archived SpecV3
provenance and is unchanged. The v2 artifact is effective only for the
explicit Source5 branch.

The driver’s v2 recipe-freeze request carries the existing pressure-calibration
artifact pin plus the v2 receipt, the exact original condition pin forwarded
from `pressure_condition.condition`, current per-job context-policy bundle,
capacity bundle and observed-host pins. The actual recipe's seven numeric
readiness values must equal the prospective condition values exactly. Freeze
consumes the stored calibration receipt and reruns the independent scope
verifier with the current per-job policy bundle. It accepts different
per-pair reference hashes only when both genuine composer replays produce the
same numeric context projection and every non-reference scope pin remains
identical.

The resulting pressure recipe is explicitly versioned. Each actual recipe
still carries the original job run ID, pair/member, allocator/executor, fresh
nonce, binary/source, and the normal APP PID/start-time, executable, argv,
environment, working directory, affinity, network-namespace, readiness and
cleanup proofs. V2 does not relax readiness thresholds, change pressure gates,
or make a calibration or component receipt qualification-eligible. A failed
producer replay, policy replay, sample, threshold, worker cleanup, or scratch
cleanup blocks use of the calibration.
