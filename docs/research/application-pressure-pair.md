# SourceV5 normal application pressure pairs

`scripts/application-pressure-pair.py` runs one original `jobs.pressure` entry
as two direct normal-APP launches. It keeps the plan's member order and
ordinal, runs a fresh SourceV5 pressure driver for each member, waits for the
driver's authenticated ownership/ACK/start prefix before APP `Popen`, then
rechecks the pressure proof, feedback V5 trace, and runtime-binding V2 owner
release.

The runner consumes the private immutable
`allocatbelt.application-pressure-pair-recipe.v1` object. Its exact top-level
keys are `schema`, `spec`, `plan`, `source_manifest`, `job`,
`execution_overlay`, `capacity_completion`, `capacity_bundle`,
`fixed_predecessor`, `shared_policy`, `pressure_condition`, `members`,
`deadlines`, `artifact_budgets`, and `validators`. Recipe bytes are pinned by
the `run` command's separate expected SHA-256. Every external artifact
reference uses exactly `{ "path": ..., "raw_sha256": ... }`; spec, plan,
manifest, job, pressure recipe, condition and feedback-template semantic
digests remain separate fields.

The nested recipe contract is exact as well. `spec` and `plan` are
`{artifact, semantic_sha256}`; `source_manifest` is
`{artifact, semantic_sha256, source_root}`; `job` is
`{value, semantic_sha256}`; `execution_overlay` is `{artifact}`;
`capacity_completion` is `{artifact, schedule_sha256, registration_head}`;
`capacity_bundle` has the `request`, `artifact` and `receipt` pins;
`fixed_predecessor` is `{record}`; and `shared_policy` is `{artifact}`.
`pressure_condition` pins the original condition file, condition ID and digest,
pressure-calibration artifact/receipt/validator/calibration ID, typed readiness
thresholds, and the typed duration/interval/seed schedule.
The condition file also carries the pressure driver's seven measured-readiness
thresholds; these remain bound to that raw request and are checked separately
from SourceV5's typed minimum-overlap, minimum-sample, and maximum-gap rules.
Each member pressure recipe has its own semantic condition digest because it
binds that member's executable, storage paths, and process identity, while its
condition ID and original intensity/calibration inputs still match the shared
SourceV5 condition.

Each `members[]` entry has exactly `ordinal`, `descriptor`,
`feedback_template`, `identity`, `application_binary`, `construction_probe`,
`composition`, `argv`, `environment`, `cwd`, `tmpdir_path`, `cpu_set`,
`cpu_affinity`, `network_namespace_inode`, `oracle`, `outputs`, and
`pressure_recipe`. `descriptor` is `{pair, executor, allocator}`;
`feedback_template` is `{value, template_sha256}`; `composition` pins the
canonical resolve request, target policy and resolver receipt; `oracle` is
`null` for capacity mode or `{entry, artifact}` for open-loop mode; and
`pressure_recipe` is `{artifact, semantic_sha256, condition_sha256}`. The
`outputs` object names the member root, APP stdout/stderr/time/IDs/shutdown and
capacity-family reports, runtime binding and expectation, feedback trace
directory/manifest/events/samples/validation, pressure proof, APP launch
attestation, supervision/cleanup receipts, and composer finalization
request/receipt. Feedback trace files live in the dedicated `feedback-trace`
subdirectory; the pressure driver keeps its own `pressure` subdirectory.

`deadlines` pins the original trace, drain, shutdown, process and outer bounds,
the APP wall/TERM bounds, pressure exit-observation margin, and the derived
pressure duration/total. `artifact_budgets` pins stdout, IDs, shutdown,
runtime binding, each feedback trace file, feedback validation, pressure proof,
supervision receipt, member sidecar and pair sidecar limits. `validators` pins
the regular SourceV5 campaign controller, chronology, feedback composer,
feedback validator, pressure validator, soak supervisor and capacity producer.
The pair runner itself is pinned as a regular SourceV5 inventory file and does
not add a ninth qualification-harness key.

The execution overlay has exactly `schema`, `campaign_id`, `host_id`,
`source_manifest`, `spec`, `plan`, `job_index`, `job_sha256`, `runner`,
`capacity_completion`, `chronology`, and `overlay_sha256`. Its `source_manifest`,
`spec` and `plan` objects bind both raw and semantic digests. `runner` binds the
absolute executing script path and raw SHA-256. `chronology` binds the observed
host file, chronology output root, optional capacity output root, journal head,
journal record count, registration head and dispatch count. The overlay's
self digest and the live chronology replay must match before member output
directories are created.

The two original member descriptors are `(bounded, bounded, allocator)` and
`(tokio, tokio, allocator)` for executor jobs, or `(candidate, bounded,
candidate_allocator)` and `(baseline, bounded, baseline_allocator)` for
allocator jobs. Feedback executor identities are `allocatbelt` and
`tokio-1.53.3`. The report nonce is derived from the original reusable plan
template, campaign ID, run ID, member name and job ordinal. Each member pins
its normal application binary, construction probe, resolver request/policy/
receipt, feedback template, full APP argv and environment, cwd, TMPDIR,
affinity, network namespace, oracle, output paths, and pressure recipe.

The separate execution overlay has schema
`allocatbelt.application-pressure-pair-execution-overlay.v1`. Its self digest
binds the executing runner's inventory-pinned bytes, original source/spec/plan
pins, exact planned job and host job index, capacity completion, observed-host
pin, and the chronology journal/registration heads. Before either APP starts,
the runner replays the pinned SourceV5 chronology module and capacity producer
against those files and requires the replayed heads to match the overlay. A
label or readiness flag does not authorize execution.

Both target APP probes are resolved independently through the pinned SourceV5
feedback composer with one producer-verified capacity request/artifact/receipt
bundle. The pair recipe pins one canonical
`allocatbelt.application-pressure-pair-policy.v1` artifact. It records the
shared numeric policy, Control baseline, hard ceilings, scope limits, rate
buckets, capacity sources and resolution version, together with each
target-specific resolver receipt. The per-target policy document cannot stand
in for this shared pressure input because it also binds a different binary and
probe identity. Each pressure recipe must pin the same shared policy bytes.

The supervisor API exported by `application-soak-readback.py` is:

```python
supervise_pressure_application(
    app_descriptor,
    pressure_recipe_info,
    output_root,
    on_started,
    on_cleanup,
) -> launch_receipt
```

The private member recipe records its semantic digest as `semantic_sha256`.
After the captured pressure reader validates that digest, the runner reads the
validated `recipe_sha256` from the full recipe bytes and passes that value in
the supervisor input; the captured reader's return value is a summary and does
not contain that field. The supervisor checks the digest against the parsed
recipe and its raw-byte pin before starting either process.

`app_descriptor.execution_kind` is explicitly `normal_app` or `timed_soak`.
The old SourceV5 timed-soak launch path supplies `timed_soak` and keeps its
existing V2 receipt adapter. The shared implementation owns pressure startup,
measured readiness, child-subreaper capture, worker PID/start/session/nonce
ownership, pidfd cleanup and adopted-child reaping, APP launch through the
verified executable fd, process-group cleanup, TERM/HUP accounting, driver
death detection, and the strong SourceV5 worker-ownership/ACK/start prefix.
Driver logs and APP bookkeeping stay in the member output root; the pressure
driver directory retains its exact five-file artifact set.

The pressure driver's V1 launch record remains unchanged for its captured
reader. A separate normal-APP launch attestation seals the direct APP PID and
start ticks, executable path/hash/device/inode/size, inherited executable-fd
reference, cwd, actual argv and its raw/canonical digests, and the actual full
environment and its raw/canonical digests. The shared supervisor rejects a
canonical environment snapshot larger than 16 MiB, matching its launch-binding
and procfs-attestation limits. The row's APP identity comes from
that direct Popen, never from the pair-runner process.

After the APP and pressure workers are reaped, the runner pins the pressure
proof, feedback trace and runtime-binding V2 bytes, finalizes a V5
`pressure_validation` expectation with the actual APP PID and final proof pins,
and replays the SourceV5 V5 feedback reader. The feedback reader must prove the
collector joined, no controls remain pending or faulted, byte-bucket credits
are conserved, all owner usage is zero after shutdown, the runtime binding is
V2, all five final global application counters are zero, and global Control
returned to the fixed calibrated baseline. The adapter also emits the numeric
snapshot V2 through the captured controller projection.

`validate_pressure_pair_artifacts` rereads the sidecar and every pinned raw
artifact. The runner emits `processes.tsv` with the unchanged
`PAIR_PROCESS_HEADER` plus `pressure-pair-readback.json` with both direct APP
identities, supervision/cleanup receipts, pressure worker proofs, feedback V5
readbacks, runtime V2 snapshots, common policy/capacity/predecessor pins, and
member outcomes. Its controller metrics adapter reports measurements with
`p99_qualification=not_applicable`. Per-job validity does not set campaign
readiness or qualification; the original plan's false readiness bits remain
as written.

Run a prepared job with:

```sh
python3 -B scripts/application-pressure-pair.py run \
  --recipe /private/path/pressure-pair-recipe.json \
  --expected-recipe-sha256 EXPECTED_RECIPE_SHA256 \
  --output-root /private/path/pair-output
```

Reaudit the completed pair with:

```sh
python3 -B scripts/application-pressure-pair.py validate \
  --recipe /private/path/pressure-pair-recipe.json \
  --expected-recipe-sha256 EXPECTED_RECIPE_SHA256 \
  --output-root /private/path/pair-output \
  --readback-sha256 EXPECTED_READBACK_SHA256
```

The native contract suite is
`scripts/test-application-pressure-pair.py`. Run it only on the designated
native qualification host. Full acceptance also requires a freshly frozen
SourceV5 overlay with genuine artifacts, capacity evidence, control
observations, chronology registration, the original fixed predecessor, and
paired Native/Tokio plus allocator member runs. Startup, TERM/HUP, driver-death,
alias, replay, and partial-pair failure cases must leave all owned workers
reaped and qualification false. QEMU or synthetic fixtures establish
correctness only; they do not establish native speedup.

## Origin-host receipt and offline replay boundary

The additive `verify_pressure_pair_with_host_receipt(...)` API wraps the existing
strict validator after a pair has completed under its original Source5 lock and
authorization. It writes a separate fresh mode-0600 receipt in an owned
mode-0700 directory. The receipt binds the original recipe/readback raw bytes,
recipe semantic digest, SourceV5 manifest raw/semantic/tree digests, original
SpecV3 and PlanV3 pins, execution-overlay digest and chronology heads,
authorization ID, dependency module pins, both original ordered members, their
pressure artifacts and APP/worker PID-start identities, and the origin-host
identity before and after verification. Every process absence observation is
recorded after cleanup. Qualification and execution fields remain false.

For the before/after live snapshots, the strict API reads the original raw-pinned
capacity host context from the execution overlay, validates its closed v1 shape
through the SourceV5 pressure reader, and requires both pressure calibration
bindings to reference those exact bytes. It compares live boot, kernel,
affinity, and namespace facts to that validated context. The pressure recipe's
separate `host` object retains its existing closed pressure-storage schema and
is used for pressure environment checks; it is not treated as a capacity host
context. The overlay and observed-host raw pin are rechecked after pair replay.

When validating each nested pressure recipe, the pair reader retains the
canonical raw-pinned recipe alongside the pressure validator's reduced
summary. The summary supplies its validated semantic and condition digests;
the full recipe continues to supply the closed host, process, storage, and
network namespaces required by live checks. Those values are never copied into
or inferred from the summary.

Before the receipt is written, the strict API also requires the active locked
helper input to pin `allocatbelt.application-source5-pressure-helper-payload.v2`
with its exact `{schema, recipe_pin, output_root, probe_capture_bundle}` field
set. The capture bundle contains the two original ordered ProbeV2 captures and
the same producer request, TSV artifact and receipt bytes selected by the
pressure recipe. For each member, the SourceV5-inventory-pinned feedback reader
replays the capture receipt, actual FixedR8 owner result, raw stdout/stderr,
observed host facts, APP ELF, ProbeV2 and full capacity producer bundle, then
reconstructs the numeric policy and compares it with the member's resolved
policy. A missing or changed capture blocks receipt creation. The archived
two-field helper payload remains a separate legacy shape and cannot satisfy
this pressure-only receipt API.

The pressure receiver uses a separate `allocatbelt.application-pressure-pair-recipe.v2`
only when Source5 authorizes the captured ProbeV2 generation. Its exact extra
top-level field is `probe_capture:{capture_timeout_ns,storage_budget}`; the
closed object is prospectively frozen before the helper run. The strict host
receipt and offline pair replayer compare both actual captured receipt values
to that exact recipe object and the capture pins in the raw-locked helper
bundle. Recipe v1 retains its original closed field set and behavior; the
capture budget is not appended to its `artifact_budgets`.

This code validates an existing capture bundle; it does not manufacture one.
The Source5 pressure-input builder must collect both genuine ProbeV2 receipts
before dispatch. The capacity-stage process-capture field is not that
`--emit-feedback-policy-only` receipt and cannot be substituted for it.

`scripts/application-pressure-readback.py::verify_pressure_offline(...)`
replays one nested pressure run from its original recipe, five raw artifacts,
calibration and condition evidence, and the exact matching member of the
strict pair receipt. It recomputes the pressure event timeline, readiness,
thresholds, run accounting, and proof bytes. Its cleanup check uses only the
receipt's exact origin-host PID/start absence observations; it does not inspect
the replay machine's `/proc` or launch an APP or pressure worker. The SourceV5
identity evidence map is sorted and identity-only. It must include the exact
SourceV5 typed source/artifact members, each nested JSON dependency, the
pressure artifact directory members, the proof, and host receipt before replay.
The map also includes every nested ProbeV2 capture/owner/inventory/output path,
the capacity producer request and trace inputs, and the exact two locked
capture rows before any captured module runs. Translated paths and path aliases
are rejected.

`scripts/application-pressure-pair.py::validate_pressure_pair_artifacts_offline(...)`
validates the receipt against the original pair recipe, readback, source,
SpecV3, PlanV3, execution overlay, job ordinal, journal/registration heads and
ordered member pins, then replays both pressure runs independently. It does not
return a pair result while the captured Source5 chronology module lacks the
pure host-journal adapter and the corresponding original fixed-predecessor and
normal-APP replay dispatcher. Those missing adapters are explicit blockers;
receipt booleans or the stored pair summary cannot substitute for them. This
work does not enable execution or make any campaign gate eligible.

The host-receipt and offline-pair entrypoints accept only pair-recipe v2. The
archived standalone pair-recipe v1 readers and runners keep their original
closed shape; v1 does not gain the `probe_capture` budget field.

### Archived fixed predecessor during a live pressure launch

When the original confirmation predecessor's payload has already been
offloaded, the Source5 launcher may pass the additive
`pressure_predecessor_context` keyword through `run_pressure_pair_locked`, its
prerequisite preparation, the strict pair replay and the strict host-receipt
verifier. This value is a runtime-only, non-JSON object issued by the
Source5-pinned chronology module's
`build_source5_pressure_predecessor_context_locked(lock, execution_manifest_pin,
active_authorization_context, *, captured_evidence)` factory. The factory runs
under the original held lock after it validates the prepared campaign context
and current pressure authorization, replays the exact fixed predecessor from
the bounded archived read view, and reconstructs its fixed-predecessor receipt
from the original Source/job/metrics facts.

The pressure owner accepts that object only after the captured
Source5-pinned chronology module's
`validate_source5_pressure_predecessor_context(context, lock=lock,
authorization_context=details, recipe_pin=recipe_pin, output_root=output_root)`
accepts its issuer, live lock registry, host/job scope, exact active
authorization, and recipe/output binding. The pressure owner retains the
already-loaded pinned chronology module instance supplied by the launcher; it
checks the source bytes against the SourceV5 inventory without compiling a
second chronology module that would have a different live-lock registry. The
chronology validator authenticates the opaque context, replays the fixed
predecessor from its captured byte view, and returns the existing
`allocatbelt.application-source5-pressure-prerequisites.v1` projection. The
projection carries the current job/index/helper/authorization and journal
heads plus the exact seven-field `fixed_predecessor` result: `run_id`,
`job_record`, `receipt`, `receipt_value`, `component_sha256`,
`process_metrics_sha256`, and `state`. The owner checks these against the
active authorization and execution overlay, reads the always-local original
job record under the live lock, freshly reconstructs the receipt, and compares
its raw pin/value and component/metrics digests with the captured result before
the ordinary strict pressure checks continue.

The archived one-job view is consumed only by the source-pinned chronology
validator; it is never passed as `evidence_path_map` to the full host-journal
offline API. The pair recipe, normal-APP output/readback, pressure proof,
ProbeV2 policy/runtime gates and host receipt retain their original closed
schemas and exact component projection. Omitting the context preserves the
existing strict/live path; a JSON object or caller-supplied success flag is
not a captured predecessor capability.

The new origin receipt is separate from the original pair sidecar, pressure
readbacks, SpecV3, PlanV3 and chronology files. The strict v1 validation and
execution APIs retain their existing behavior and inputs.

The new Python entry points are:

```python
verify_pressure_pair_with_host_receipt(
    recipe_pin, output_root, readback_pin, host_receipt_path,
    *, chronology_module, lock, authorization_context,
    pressure_predecessor_context=None,
) -> {"path", "raw_sha256", "receipt_sha256"}

run_pressure_pair_locked(
    recipe_path, expected_recipe_sha256, output_root,
    chronology_module, lock, authorization_context,
    on_app_started, on_app_terminal, *,
    pressure_predecessor_context=None,
) -> component_result

# Public origin-host fixture wrapper; caller supplies real completed pins and
# the active lock/auth context. It does not manufacture capture evidence.
capture_pressure_pair_origin_fixture(
    recipe_pin, output_root, readback_pin, host_receipt_path,
    *, chronology_module, lock, authorization_context,
    pressure_predecessor_context=None,
) -> {"path", "raw_sha256", "receipt_sha256"}

validate_pressure_pair_artifacts_offline(
    recipe_pin, output_root, readback_pin, host_verification_pin,
    evidence_path_map,
) -> replay_result

validate_pressure_pair_artifacts(
    recipe, output_root, readback_path, expected_readback_sha256,
    *, chronology_module, lock, authorization_context,
    captured_evidence=hview, pressure_predecessor_context=None,
) -> replay_result

verify_pressure_pair_with_captured_outputs(
    recipe, output_root, readback_pin, host_receipt_pin,
    *, chronology_module, lock, authorization_context,
    captured_evidence=hview, pressure_predecessor_context=None,
) -> replay_result
```

The strict call requires the active locked pressure authorization, including
its `authorization_id`, and runs only after the original pair artifacts exist.
The offline API currently replays both pressure sub-runs and then stops with an
explicit dependency error because the pinned chronology source does not yet
provide the pure completed-host-journal dispatcher. It will not return a
`validated` pair summary until chronology, fixed-predecessor, normal-APP and
registered-job artifacts have all been independently replayed. Continuous
Soak remains a separate Source5 cohort dependency.

### Replaying a reclaimed pair from the Root H-view

`validate_pressure_pair_artifacts(..., captured_evidence=view)` and
`verify_pressure_pair_with_captured_outputs(...)` are additive Source5 paths for
the exact one-job H-view issued by Root after its persisted ACK, detached GPG
signature and original job record have been revalidated. The pressure owner
checks the raw/canonical request, checkpoint and object-manifest closure again,
binds it to the original pressure job, Source/Spec/Plan/execution/budget pins,
the strict pressure host receipt and the two ProbeV2 typed TMP trees, and reads
captured bytes only through the private staged object view. SourceV5 modules,
application binaries, oracles and original campaign inputs remain pinned reads
at their resident paths. The one-job view never enters the historical full-host
`evidence_path_map` API.

This replay recomputes the two pressure streams, both ProbeV2 captures, feedback
composition and trace validation, APP output/runtime readback, and the exact
two-row process ledger. It checks the original strict pressure host facts and
asks the already-loaded SourceV5 chronology module to validate the optional
opaque `pressure_predecessor_context` for a fresh replay of the original fixed
predecessor. It launches no APP or pressure worker, writes no replacement
evidence, and keeps qualification and execution readiness false. Root remains
the authority for GPG verification and H-view issuance.

### Bounded Source5 application TMPDIR owner-return proof

The bounded Source5 pressure authorization carries the exact
`tmpdir_budget` pin and byte/inode limits. Before either APP starts, the pair
owner records each original TMPDIR's device/inode/mode and mount identity,
available capacity and those frozen limits. The shared pressure supervisor's
`on_owner_return` callback captures the final fixed-owner inventory immediately
after the APP owner returns and before the pressure tail continues. The pair
readback v2 and host-verification receipt v2 carry both snapshots unchanged.
For a successful pair, each final snapshot must retain the same root and mount
identity and report zero bytes, files and subdirectories. Captured H-view replay
requires the signed request's two empty-TMP proofs to equal the strict v2
receipt projections; it never infers an empty root from absent archived files
or re-stats a reclaimed path. The legacy v1 receipt remains readable by the
legacy identity-map path but cannot authorize bounded captured success.
