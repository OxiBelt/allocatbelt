# Source5 pre-Spec input preparation

This additive lane closes the capacity-byte cycle before SpecV3 and PlanV3
exist. It freezes one prospective three-host campaign generation, measures
the 15 real application capacity contexts on a selected host, and later
bridges those exact producer bytes into final inputs. The archived SpecV3,
PlanV3, and capacity-stage-v1 validators remain unchanged.

Preparation is input evidence only. Every intent and completion pins
`qualification_eligible: false`; the final bridge never promotes campaign
readiness. A successful 15-context host preparation is not a six-pair pilot,
rate calibration, four-allocator runtime result, A/A check, pressure
qualification, or Soak result.

## Source and host inputs

The Python API can seal the independently replayed three-host capacity cohort
before final rates, oracles, or a final campaign completion exist:

```python
generation_pin = preparation.build_prepared_capacity_generation_bounded(
    preparation_pin, capacity_completion_pins, resource_budget_pins,
    source_root, input_root, input_root / "prepared-capacity-generation.json",
)
generation = preparation.verify_prepared_capacity_generation_bounded(
    generation_pin, preparation_pin, source_root, input_root,
)
```

`capacity_completion_pins` retains the existing ordered three-host inputs:
`host_id`, `completion_pin`, `verification_receipt_pin`, and
`evidence_path_map`. `resource_budget_pins` is the exact caller-frozen host
map. Both calls replay all 45 original capacity contexts through the
Source-pinned bounded stage verifier. The read-only
`replay_prepared_capacity_inputs_bounded` API returns the same canonical
generation without writing it.

The receipt uses the distinct schema
`allocatbelt.application-source5-prepared-capacity-generation.v1`. It binds
the preparation intent, ordered capacity records, resource budgets, and
`generation_sha256`; `complete` covers capacity only and
`qualification_eligible` remains false. Its fixed output location is inside
the private input root. Verification reconstructs every producer input and
compares the complete canonical receipt. It grants no exploration launch or
final campaign readiness. Existing final-completion schemas reuse the same
capacity replay and still require their full pilot, oracle, and pressure
evidence.

Prepare a private mode-0700 input tree outside SourceV5. It contains the
canonical preparation request, all three real SourceV5 manifests, all three
observed host-context files, capacity request/context templates, and pressure
condition files. Keep SourceV5 and the input tree separate. Do not use
synthetic companion manifests or host records.

Keep the same absolute SourceV5 and private input base paths on all three
hosts, with host-specific output trees. Canonical producer and calibration
requests pin absolute paths. Central replay accepts only an explicit identity
path map, so gathered peer evidence must remain at its original paths and raw
JSON must remain unchanged.

Every manifest must describe the same signed source revision, source tree,
Cargo lock, Rust 1.99.0 release toolchain, x86_64 GNU target, and x86-64-v3
build contract. Each binds the full four-allocator APP set: `allocatbelt`,
`mimalloc-secure`, the independently built `mimalloc-standard` graph, and
`system`. These are four distinct real normal APP artifacts. SourceV5 also
keeps the candidate allocatbelt Soak artifact as its sole required Soak
treatment.

The typed SourceV5 inventory must contain the regular files listed in
`PREPARATION_MODULE_PATHS` in
[`application-campaign-inputs.py`](../../scripts/application-campaign-inputs.py).
These ordinary inventory entries do not extend the established eight-key
`qualification_harness`. The builder verifies SourceV5 and actual artifacts;
the selected-host stage also checks the live boot ID, CPU model/kernel,
inherited affinity and network namespace against that host's original
observation. The helper captures the regular typed source-inventory,
campaign-inputs and campaign-controller bytes before compiling any of them;
the controller is wired to those same captured module objects during full
SourceV5 replay. Every later stage, pressure and fixed-pair helper is compiled
from bytes checked against its typed source entry. Python source loaders and
bytecode caches do not select executable bytes.

The request file has this exact outer shape:

```json
{
  "schema": "allocatbelt.application-source5-preparation-request.v1",
  "core": {},
  "source_manifests": {
    "host-a": {"relative_path": "sources/host-a.json", "raw_sha256": "..."},
    "host-b": {"relative_path": "sources/host-b.json", "raw_sha256": "..."},
    "host-c": {"relative_path": "sources/host-c.json", "raw_sha256": "..."}
  },
  "observed_hosts": {
    "host-a": {"relative_path": "hosts/host-a.json", "raw_sha256": "..."},
    "host-b": {"relative_path": "hosts/host-b.json", "raw_sha256": "..."},
    "host-c": {"relative_path": "hosts/host-c.json", "raw_sha256": "..."}
  },
  "capacity_templates": [],
  "condition_intensities": []
}
```

`core` is the original SpecV3 campaign core without its schema, source-manifest
references, rates, or oracles. It contains `campaign_id`, `runner_sha256`, all
three `hosts`, all 15 `cells`, the unchanged `protocol`, `runtime_binding`,
`phase_adapters`, `aa_controls`, candidate-only `soak`, and original
`deadlines`. Cells keep the original workload resource limits, 30-second
capacity horizon, and observation minima. Fixed pair counts, the 5,000
runtime sentinel, deadlines, and numerical gates remain pinned by this core.

Each capacity template has `host_id`, `workload`, `profile`, `calibration_id`,
`calibrator`, `request_template`, and `context_template`. Request templates
keep the byte producer's 10–30 second interval. Context templates contain
observed storage/device/free-space facts for disk and mixed contexts, observed
IPv4 loopback namespace facts for HTTP and mixed contexts, and `null` for
unclaimed resources. The raw template bytes are reread before each launch.

Each condition-intensity entry has `host_id`, `workload`, `profile`,
`condition_id`, the exact `capacity_key`, `pressure_calibration_id`, a raw
`condition` pin, `readiness_threshold_rule`, the existing three-key campaign
`readiness_thresholds`, caller-supplied seven-key numeric `pressure_thresholds`,
and the full bounded pressure `schedule`. The schedule retains the original
30-second horizon and 100ms sample cadence; campaign readiness covers the
entire overlap sample set and limits sample gaps to 200ms.
The raw condition file is canonical JSON with exactly `schema`, `host_id`,
`condition_id`, `capacity_key`, `pressure_calibration_id`,
`readiness_threshold_rule`, `readiness_thresholds`, `pressure_thresholds`, and
`schedule`. Its schema is `allocatbelt.application-source5-pressure-condition.v1`.
The rule is `allocatbelt.application-source5-pressure-readiness-threshold-rule.v1`;
it means caller-supplied pressure thresholds are frozen before calibration
and must pass measured calibration. `pressure_thresholds` uses the existing
seven numeric keys: `cpu_busy_min_basis_points`,
`disk_write_min_bytes_per_second`, `disk_queue_or_stall_min_microseconds`,
`loopback_requests_min_per_second`, `loopback_latency_p99_max_nanoseconds`,
`loopback_tx_min_bytes_per_second`, and `loopback_rx_min_bytes_per_second`.
All are positive integers in the named units; CPU basis points remain at most
10,000. The legacy `readiness_thresholds` stays exactly
`minimum_overlap_seconds`, `minimum_ready_samples`, and
`maximum_sample_gap_ms`.
The rule supplies no defaults or formula. A failed
calibration blocks this generation; changing a threshold requires a new
intent, condition bytes, IDs and raw pins. The existing campaign readiness
record stays unchanged and the bridge checks it against the final SpecV3
projection. The condition file remains byte-pinned when pressure scope
evidence is added.

Build and replay the intent with raw file hashes supplied separately:

```sh
python3 -B scripts/application-source5-input-preparation.py build-intent \
  --request /private/inputs/preparation-request.json \
  --request-sha256 REQUEST_RAW_SHA256 \
  --source-root /source/final-signed-source-v5 \
  --input-root /private/inputs \
  --output /private/inputs/preparation-intent.json

python3 -B scripts/application-source5-input-preparation.py verify-intent \
  --intent /private/inputs/preparation-intent.json \
  --intent-sha256 INTENT_RAW_SHA256 \
  --source-root /source/final-signed-source-v5 \
  --input-root /private/inputs
```

The intent keeps source-manifest raw SHA, semantic `manifest_sha256`, and
`source_tree_sha256` as separate roles. It also pins all observed-host files
and execution modules. Capacity jobs receive their context indices, run IDs,
and nonces before any APP executes. A run ID is `prep-cap-` plus the first 32
hex digits of the frozen job-identity SHA. The nonce is the first 32 hex
digits of `sha256("allocatbelt.application-source5-capacity-nonce.v1\0" ||
canonical({"identity_sha256": ..., "run_id": ...}))`. The template digest
binds both template pins, the calibrator and source/binary identities.

The intent declares pressure calibrations, complete three-host six-pair
rates, and complete-rate oracles as deferred. Its six capacity, pressure,
rate, oracle, confirmation and qualification eligibility fields are all
`false`. The writer refuses an existing destination and writes mode 0600.

## Real pre-Spec capacity preparation

Use a fresh owned mode-0700 output root for each host beneath the private
input root; this keeps the exact stage receipt and TSVs addressable by final
SpecV3's relative evidence pins. The directory may be a real ext4 mount point
inside that tree. `run-preparation` captures the
SourceV5 controller, input validator, feedback reader, byte-capacity producer,
capacity stage, and preparation helper from their typed inventory entries.
It validates the full 45-template intent, then runs the selected host's 15
contexts in their original array order. Each job uses the pinned real APP for
its feedback-policy probe and 30-second capacity run, original finite
deadlines, observed storage/network context, a fresh trace directory and a
fresh TMPDIR. It invokes the actual `application-byte-capacity.py` producer
and replays the complete TSV bundle. No SpecV3 or PlanV3 is fabricated.

Before the first child launch, the selected-host runner also compiles the
intent-pinned FixedR8 `fixed_pair` owner and `soak_readback` process-identity
helper from captured SourceV5 inventory bytes. Both the policy probe and APP
run through that owner; a missing owner fails before output capture or Popen.
The source paths and raw SHA-256 values come from the selected host's closed
`PREPARATION_MODULE_PATHS` pins, and the typed regular-file inventory is read
and hash-checked before either module is compiled. This owner lookup is scoped
to the new preparation lane: the archived SpecV3/PlanV3 capacity-stage-v1
loader still uses its original `qualification_harness` pins, event detail
fields, and offline receipt schema, with no new process-owner dependency.
The preparation completion adds a versioned `modules.owned_process` record
binding both exact module paths and raw SHA-256 values. Each job ledger keeps
private canonical start and capture sidecars. The policy emitter has an
intentional fast exit, so its role-specific
`allocatbelt.application-capacity-stage-owned-policy-probe-start.v1` proof
binds the exact requested argv/environment digests and positive PID/start
ticks from FixedR8's `capture_identity=False` path. It does not label request
values as live-observed executable, argv, environment, cwd, affinity, or
namespace facts. The matching
`allocatbelt.application-capacity-stage-owned-policy-probe-capture.v1` binds
that dispatch/start proof to the captured open executable descriptor,
FixedR8 exit/wait receipt, and exact stdout/stderr bytes. Normal APP starts
retain FixedR8's full live PID/start, executed argv, executable, environment,
cwd, TMPDIR, affinity, and namespace proof and the existing v1 capture schema.
The full completion replay uses role-specific exact schemas and requires the
leader to remain waitable during group signaling, no post-reap group signal,
an empty owned session, and successful reaping. These checks do not alter the
archived SpecV3/PlanV3 capacity-stage receipt schema.

The new module pin is a closed object with exactly these keys:

```json
{
  "schema": "allocatbelt.application-capacity-preparation-process-owner.v1",
  "fixed_pair": {"path": "scripts/application-fixed-pair.py", "sha256": "..."},
  "process_identity_helper": {"path": "scripts/application-soak-readback.py", "sha256": "..."}
}
```

Preparation `probe_completed` and `application_exited` events add
`direct_process_start`, `direct_process_capture`,
`direct_process_runner_sha256`, and `process_identity_helper_sha256`.
`application_bound` adds the start pin and the two module hashes. The capture
sidecar schema is
`allocatbelt.application-capacity-stage-owned-process-capture.v1` for APP
starts; its exact members remain `schema`, `runner_sha256`,
`identity_helper_sha256`, `runner_capture`, `stdout`, and `stderr`. Probe
capture members are exactly `schema`, `role`, `runner_sha256`,
`identity_helper_sha256`, `dispatch`, `start`, `open_executable`,
`runner_capture`, `stdout`, and `stderr`; `dispatch` freezes argv and
environment digests, cwd, expected executable pin, requested CPU affinity, and
expected network namespace. The replay validates every nested
R8 wait/signal/session/pidfd member against the captured API: exact 3.0/1.0
grace constants, `CLD_EXITED` status zero, TERM/KILL values, bounded member
records, and matching escaped-member PID/start/session/signal relations.
Repinned schema mutations are rejected, not just raw-byte changes under an
old pin. Event module hashes must equal the completion's
`modules.owned_process` pins. The identity path map remains identity-only, so
neither these sidecars nor their nested original paths are rewritten during
central replay.

The preparation tests include a real short-lived native policy emitter whose
parent callback waits with `waitid(WNOWAIT)` until the leader is already
waitable before returning. The probe must still finish, preserve its captured
descriptor/output proof, and replay through the probe-specific schemas. The
escaped-session fixture also updates the canonical capture's raw pin after
each mutation and requires replay to reject wrong TERM/KILL grace values,
non-exited wait codes, an unsupported group signal, open-ended pidfd/member
records, and pid/start/session/signal mismatches. These checks exercise
semantic replay after resealing the sidecar bytes.

For these pre-Spec capacity launches only, the environment explicitly sets
`ALLOCATBELT_APP_COMPARISON_FAMILY=external_pressure` so the Rust APP selects
the feedback-enabled runtime mode required to emit V4 traces. The separate
`ALLOCATBELT_APP_PRESSURE_QUALIFICATION=false` remains frozen, and the launch
does not supply a capacity-calibration artifact or SHA. The feedback policy
keeps `capacity_sources` false; the V4 reader replays the trace and the byte
producer rejects `apply` and `worker_failure` events before it can publish
capacity bytes. This runtime-mode selector is not external-pressure evidence
or qualification. The existing SpecV3/PlanV3 capacity stage and fixed-policy
pair environments retain their prior mode selection.

```sh
python3 -B scripts/application-capacity-stage.py run-preparation \
  --preparation /private/inputs/preparation-intent.json \
  --preparation-sha256 INTENT_RAW_SHA256 \
  --source-root /source/final-signed-source-v5 \
  --input-root /private/inputs \
  --host-id HOST_ID \
  --observed-host /private/inputs/hosts/HOST_ID.json \
  --observed-host-sha256 OBSERVED_HOST_RAW_SHA256 \
  --output-root /private/inputs/prepared-capacity

python3 -B scripts/application-capacity-stage.py verify-preparation \
  --preparation /private/inputs/preparation-intent.json \
  --preparation-sha256 INTENT_RAW_SHA256 \
  --source-root /source/final-signed-source-v5 \
  --input-root /private/inputs \
  --host-id HOST_ID \
  --observed-host /private/inputs/hosts/HOST_ID.json \
  --observed-host-sha256 OBSERVED_HOST_RAW_SHA256 \
  --output-root /private/inputs/prepared-capacity \
  --completion /private/inputs/prepared-capacity/CAMPAIGN/capacity-preparation/HOST_ID/capacity-preparation-completion.json \
  --completion-sha256 COMPLETION_RAW_SHA256 \
  --verification-receipt /private/inputs/prepared-capacity/CAMPAIGN/capacity-preparation/HOST_ID/host-verification.json
```

The result uses
`allocatbelt.application-capacity-preparation-completion.v1` and the separate
`allocatbelt.application-capacity-preparation-event.v1` ledger schema. It
binds preparation raw/semantic digests, SourceV5 raw/semantic/tree digests,
the original observed-host pin, captured helper hashes, the 15 exact context
keys, actual process/trace proofs, and the ledger head. It has no Spec or Plan
fields. A completion appears only after 15 successful real APP processes,
valid feedback traces, full producer replay, and verified cleanup. The ledger
is sealed mode 0400; the canonical completion is mode 0600. A failed stage
leaves no successful completion.

The strict `verify-preparation` command performs live host checks on its
originating machine. With `--verification-receipt`, it writes a canonical
mode-0600 receipt containing a self-digest and an adjacent host identity
record for boot, kernel, inherited affinity, network namespace, and the
observed-host raw SHA. Its receipt pin is
`{path,raw_sha256,receipt_sha256}`. Central completion replays the copied
hash-chained ledger, actual process/trace proofs, feedback-reader results and
producer TSV bundles, then compares the reconstructed result with this exact
host-local receipt; it does not trust a `complete` flag alone or sample the
coordinator's current `/proc` facts.

### Additive live resource budget

The original preparation intent and its v1 run/verification schemas remain
unchanged. To launch the separate bounded path, first freeze a canonical
`allocatbelt.application-source5-preparation-resource-budget.v1` document with
`application-campaign-inputs.py::build_preparation_resource_budget`. It binds
the intent raw and semantic digests, selected SourceV5 manifest, original
15-template schedule digest, and caller-selected positive finite ceilings for
job output, the whole preparation generation, all TMPDIR trees, each trace
member, durable receipts, minimum free bytes/inodes, the sample interval, and
the process deadline. The budget is a separate owned mode-0600 raw input. The
captured SourceV5 input validator replays it before any child launch; the stage
rejects values above its pinned FixedPair TMPDIR and existing process, trace,
metadata, ledger, and traversal limits. It does not lower the existing APP
hard limits or retry a failed original ordinal.

The new run command takes that exact raw budget pin:

```sh
python3 -B scripts/application-capacity-stage.py run-preparation-bounded \
  --preparation /private/inputs/preparation-intent.json \
  --preparation-sha256 INTENT_RAW_SHA256 \
  --resource-budget /private/inputs/HOST_ID/resource-budget.json \
  --resource-budget-sha256 RESOURCE_BUDGET_RAW_SHA256 \
  --source-root /source/final-signed-source-v5 \
  --input-root /private/inputs \
  --host-id HOST_ID \
  --observed-host /private/inputs/hosts/HOST_ID.json \
  --observed-host-sha256 OBSERVED_HOST_RAW_SHA256 \
  --output-root /private/inputs/prepared-capacity

python3 -B scripts/application-capacity-stage.py verify-preparation-bounded \
  --preparation /private/inputs/preparation-intent.json \
  --preparation-sha256 INTENT_RAW_SHA256 \
  --resource-budget /private/inputs/HOST_ID/resource-budget.json \
  --resource-budget-sha256 RESOURCE_BUDGET_RAW_SHA256 \
  --source-root /source/final-signed-source-v5 \
  --input-root /private/inputs \
  --host-id HOST_ID \
  --observed-host /private/inputs/hosts/HOST_ID.json \
  --observed-host-sha256 OBSERVED_HOST_RAW_SHA256 \
  --output-root /private/inputs/prepared-capacity \
  --completion /private/inputs/prepared-capacity/CAMPAIGN/capacity-preparation/HOST_ID/capacity-preparation-bounded-completion.json \
  --completion-sha256 COMPLETION_RAW_SHA256 \
  --verification-receipt /private/inputs/prepared-capacity/CAMPAIGN/capacity-preparation/HOST_ID/host-verification.json
```

Each bounded probe and APP is sampled through the captured FixedPair R4
dirfd-based walker while its directly owned child is alive. Immediately after
the FixedR8 API returns, the bounded path fsyncs the exact canonical owner
result, including its original wait/cleanup facts, before checking callback
proofs or reading stdout/stderr. Successful ledger events pin that raw return;
post-return failures get a separate false-readiness failure receipt that pins
the same raw return. The stage checks
job and generation byte/inode counts, the complete set of live TMPDIR roots,
trace member sizes, filesystem free-space floors and remaining receipt
reservations. It persists the original owner start/capture, exit status,
cleanup result, monitor report and stop reason into the append-only record
before it can publish a successful completion. A monitor stop consumes that
ordinal and leaves the failure evidence; it does not create a successful
completion or retry the job.

The ceiling is a sampled live high-water contract. Verification reconstructs
each reported high-water field as the maximum of all validated live samples
and the independently accounted quiescent final usage. Directory and file
accounting is descriptor-anchored and bounded; an enumerated descendant that
is legitimately removed during a live sample contributes its observed size
and entry count for that sample. Root loss/replacement, unsafe types or
ownership, links, other I/O errors, and traversal-limit exhaustion fail
closed. Sampling cannot claim an atomic historical peak between observations;
the fixed APP resource controls and strict quiescent final inventory remain
in force. A bounded context without an explicit storage root places its TMPDIR
at the private output root as `capacity-preparation-tmp-` plus the original
run ID. That directory is a sibling of the generation tree and is charged to
the TMPDIR byte/inode limits; it is not counted again in job or generation
usage. Explicit-storage contexts keep the caller-pinned storage root and its
observed filesystem facts. An explicit TMPDIR may be under the private input
root when its caller-pinned storage directory and per-run TMPDIR are both
present in the complete identity map and the TMPDIR is disjoint from SourceV5
and the output generation; its contents remain charged to the separate TMPDIR
byte/inode limits. Successful bounded outputs use separate
preparation event, completion and host-verification v2 schemas, carry the
exact raw/semantic budget pin, and retain all 15 original contexts. The v1
schemas above are still used only by `run-preparation` and `verify-preparation`.

For central replay, `verify-preparation-bounded-offline` takes the strict
host receipt's raw and semantic pins plus an exact identity path map. Every
entry has the same normalized absolute `origin` and `local` string. An
isolated namespace may expose byte-identical files at those original names
with different physical device and inode values; the verifier checks local
fingerprints separately from the original host's pinned identities and
filesystem-capacity samples. It never rewrites SourceRoot, request, argv,
environment, trace, or evidence paths. The verifier closes the recursive
input/output/TMPDIR membership and typed SourceV5 file/artifact inventory
before loading captured source modules. Every included directory and file has
its own explicit entry; an ancestor does not authorize an unlisted member.
The replay checks the v2 ledger, monitor reports, budget, owner lifecycle,
feedback traces and producer bundle without reading coordinator procfs or
sampling coordinator filesystem capacity. A monitor summary or completion
`complete` flag is never accepted on its own.

The closed evidence map is
`{schema:"allocatbelt.application-pressure-evidence-path-map.v1",entries:[{origin,local}]}`.
Entries are sorted by origin, unique, and require `origin == local`. The
bounded verifier rejects relocated names, omitted or extra members, aliases,
special files, hard links, and symlinks other than terminal links listed by the
captured SourceV5 inventory. It checks each link's literal UTF-8 target bytes,
`120000` mode, hash, and size without following the link. The normalized target
must remain inside SourceRoot and name a directly indexed regular Source.files
member; symlinked parents and chained links are rejected. The complete identity
map and local no-follow fingerprints still bind the link and target. It never
maps a missing file through a broad root entry. Only schema-declared evidence
pins authorize JSON
parsing: pinned requests, completions, ledger records, monitor and producer
receipts, validation receipts, and SourceV5 descriptors. A `.json` source
artifact or TMPDIR payload remains opaque raw data unless its owning schema
declares it as evidence; its suffix cannot introduce nested path references.
Canonical host receipts, budgets, launch records and source paths retain their
original bytes and strings.

`capacity_bundle_pin(entry, source_manifest_pin)` maps a verifier-reconstructed
entry to the pressure V2 exact-bundle pin:

```json
{
  "schema": "allocatbelt.application-pressure-capacity-bundle-pin.v2",
  "capacity_key": {"host_id": "...", "workload": "...", "profile": "...", "calibration_id": "..."},
  "source_manifest": {"path": "/private/inputs/sources/host.json", "raw_sha256": "..."},
  "request": {"path": "/private/.../request.json", "raw_sha256": "..."},
  "artifact": {"path": "/private/.../application-byte-capacity.tsv", "raw_sha256": "..."},
  "receipt": {"path": "/private/.../capacity-receipt.json", "raw_sha256": "..."}
}
```

The TSV pin here is the exact earlier producer artifact. Pressure scope V2
checks that raw file and replays its producer request/bundle while binding the
host, boot/storage/affinity/network context and frozen intensity. Original
per-run launch proofs remain mandatory for every later pressure APP member.

## Six-pair capacity pilot export

The pilot exporter takes the preparation pin, original empty-rate SpecV3 and
PlanV3 pins, SourceV5/input roots, a new private output path, and every
original fixed-pair overlay/receipt pair for one host. It replays each pair
with the SourceV5 fixed-pair verifier, checks the exact original job and run
ID from PlanV3, and reads both actual APP rows. It accepts exactly 360
original pairs for that host: 15 contexts × four allocators × six ordinals,
with bounded and Tokio members in every pair. That is 720 original 30-second
APP runs and at least six hours of serial runtime per host. Reruns with new IDs cannot
replace missing or invalid originals.

The fixed-pair overlay retains its original `observed_host.pin` to the exact
SpecV3 host-record bytes. It is not substituted with the separately pinned
preparation host-context file. The legacy `build_prepared_host_binding` API
still derives the adapter from an original pair overlay:

```python
prepared_host_binding = build_prepared_host_binding(
    preparation_pin,
    original_spec_pin,
    first_original_overlay_pin,
    SOURCE_ROOT,
    input_root,
    host_id,
)
```

For the preparatory Source5 lane, the adapter is required before the first
capacity-pilot owner read, so preparation materializes only the selected
canonical `SpecV3.host` subobject at
`<input_root>/fixed-spec-hosts/<host_id>.json`. The new
`materialize_prepared_host_binding(preparation_pin, spec_pin, source_root,
input_root, host_id)` API uses exclusive creation, mode 0600, and exact-byte
reopen; an existing file is accepted only when its canonical bytes are
identical. It validates the pinned capacity-host controls before creating any
directory, holds no-follow descriptors for the input root and its child for
the complete create/readback operation, and compares the named directory
identities before and after file IO. File creation, fsync, and reopen use the
held child descriptor and a basename rather than resolving the parent again.
A swapped or symlinked parent is rejected before a file can be written through
it. It returns the separate `fixed_spec_host_pin` raw pin and the same
11-field `prepared_host_binding` adapter. The read-only
`verify_prepared_host_binding` API returns the same two values and rejects a
missing or changed file without creating or restoring it. The materialized
Spec host is a global resident input at the catalogue's `observed_host` role,
separate from the original capacity-host-context pin and outside per-job
archive closure.

The adapter schema is
`allocatbelt.application-source5-fixed-pair-host-binding.v1`. Its closed
fields are `schema`, `host_id`, `fixed_spec_host_pin`,
`prepared_host_context_pin`, `spec_host_semantic_sha256`, `boot_id_sha256`,
`kernel_release`, `controls_sha256`, `process_affinity`,
`network_namespace_inode`, and `binding_sha256`. The builder rereads both
original raw records, runs the unchanged capacity-host structure validator,
and checks that the two records agree on host, controls/fingerprint, inherited
affinity, and network namespace. The exporter repeats this comparison for
every overlay before fixed-pair offline replay; a mismatch blocks the pilot.

The output uses the unchanged
`allocatbelt.application-capacity-pilot.v1` schema consumed by
`application-campaign.py freeze-rates`. It retains six ordinal-ordered pairs
per context/allocator and raw-pair evidence digests. The unchanged rate
validator computes six-pair medians across four allocators and both executors,
then applies the existing 70/90-percent flooring. The pilot is rate input
evidence; it is not a qualification result.

Before reserving the pilot output, the Source-owned
`capacity_pilot_maximum_bytes(spec, host_id, allocators,
spec_preregistration_sha256)` helper constructs the canonical 15-cell ×
4-allocator × 6-ordinal maximum-width witness. It uses the exact Spec family,
profile and host strings, valid status/hash fields, twenty-digit widths for
the eight non-rejected counters, and exact zero for the two rejected counters.
`_row_uint` rejects any counter above `2**64 - 1` before the exporter performs
pair reconciliation or rate arithmetic; the rejected counters must still be
zero.

```python
pilot_pin = export_capacity_pilot(
    {
        "preparation": preparation_pin,
        "spec": original_spec_pin,
        "plan": original_plan_pin,
        "source_root": SOURCE_ROOT,
        "input_root": input_root,
        "campaign_artifacts_root": original_campaign_artifact_root,
        "prepared_host_binding": prepared_host_binding,
        "output": private_pilot_path,
    },
    verified_fixed_records,
    host_id,
)
```

`verified_fixed_records` is the original PlanV3 order of exactly 360 records;
each contains the `overlay` and `receipt` raw pins, the strict host
`host_verification` pin `{path,raw_sha256,host_verification_sha256}`, and the
identity `evidence_path_map`. Before each offline replay, the exporter
compares the overlay's SpecV3 and PlanV3 raw/semantic pins, all three source
manifest raw/semantic pins, selected source root/tree/build/commit, complete
typed execution-module inventory, original job, and both runtime recipes and
nonces with the supplied initial generation. A later rate/oracle generation
with equal run IDs cannot contribute pairs to this pilot. It also binds the
same host adapter to every pair; each pair evidence digest includes the
adapter's `binding_sha256`. The exporter writes
a new canonical mode-0600 manifest under an owned mode-0700 parent and returns
its raw and semantic digests.

For archived pair bytes, the Python API accepts
`captured_read_provider=provider`. For each original job it opens
`provider.open_view(job, "exploration", use="capacity_pilot_export")` and
requires a context manager yielding `objects` and `stage_root`. The view
contains the unchanged captured fixed-owner references. The exporter reads
the three envelope pins through the bounded capture reader, then passes the
complete object set to the Source-pinned captured fixed-pair verifier. It
closes the view before advancing to the next job or publishing the pilot.
Read and context-exit failures propagate; captured failures cannot fall back
to origin reads. Omitting the provider preserves the original offline path.

The optional Python callback `before_publication(pilot_raw, prospective_result)`
runs after all pair views close and the numerical rate validator succeeds,
before any pilot file is written. It receives the exact canonical bytes and
an independent deep copy of the prospective result, including the requested
output path. It must return `None`; an exception or another return value
prevents publication. This lets a Source-owned caller complete its journal,
archive and storage checks without another replay pass. Omitting the callback
preserves the existing call behavior and pilot bytes.

The private JSON writer holds the parent directory descriptor across exclusive
creation and readback. A write, sync or readback failure removes only the inode
created by that call. An already-existing identical immutable output is
preserved.

The completion and completion-replay Python APIs forward the optional
`captured_pilot_read_providers` map. An explicit map must cover exactly the
three verified hosts with a callable `open_view` for each host. Selection is
copied before replay so caller map mutation cannot redirect a host's reads.
This interface supplies bytes; authenticated archive/journal authority must
come from the separate Source-owned wrapper. The fixed owner still requires
its resident original inputs and retained directory context. These APIs do
not establish cross-host replay portability or qualification readiness.

For a read-only completion replay, supply `output: null`. The exporter still
reconstructs and validates all 360 original pairs and recomputes the pilot
bytes, but creates no replay file under the frozen input tree. Completion
stores the original pilot manifest and raw fixed-pair evidence pins; the
controller's pure completion verifier compares its full replayed completion
with those canonical bytes.

## Completion bridge

After the final SpecV3 has its complete frozen rate and oracle maps, call:

```python
completion_pin = complete_prepared_inputs(
    preparation_pin,
    capacity_completion_pins,       # completion + host receipt + path map, in host order
    pressure_calibration_pins,      # 45 context-scope V2 records in intent order
    pilot_pins,                     # three manifests, host adapters and original pair records
    oracle_pins,                    # three producer manifests and artifact roots
    final_spec_pin,
    final_plan_pin,
)
```

The input root is the preparation intent's parent; SourceV5 is the active
signed source checkout. Each capacity input is closed over `host_id`, the
original completion pin, strict host-verification receipt pin, and identity
evidence map. The bridge independently replays ledger transitions, original
run IDs/nonces, process/trace evidence, feedback-reader outputs, and producer
bundles, then compares all reconstructed fields with the strict receipt.

Each pressure record is closed over `host_id`,
`condition_id`, `capacity_key`, original `condition_pin`, `context_policy_pin`,
`calibration_pin`, `calibration_receipt_pin`, exact `capacity_bundle_pin`, and
original `observed_host_pin`, and the identity evidence map. A scope receipt pin is
`{path,raw_sha256,scope_sha256}`; the canonical receipt body also carries
`context_policy_sha256` and the strict host-verification identity. The bridge
calls `verify_calibration_scope_v2_offline`, which replays source, capacity
producer/composer inputs, all samples, threshold gates, cleanup and host
identity against the original receipt. The strict
`verify_calibration_scope_v2` remains an originating-host check.

Each pilot record is closed over `host_id`, `campaign_artifacts_root`, `manifest`,
`initial_spec`, `initial_plan`, `prepared_host_binding`, and
`verified_fixed_records`, including each pair's host-verification receipt,
adapter digest, and path map. The bridge runs the exporter
again from those original pins and compares raw output bytes before applying
`freeze_rates`. Each oracle record is closed over `host_id`, `manifest`, and
`artifact_root`; the bridge checks source/preregistration identity and
validates every producer-generated TSV. It compares the final 90 rate entries
and 360 oracle entries against the complete deterministic outputs.

The bridge also invokes the unchanged SourceV5 SpecV3 and PlanV3 validators.
It projects final SpecV3 onto the preparation core and requires every frozen
field to match. It permits only the declared capacity evidence, pressure
calibration, rate and oracle slots to be populated. Capacity evidence reuses
each verified producer TSV, request, receipt and host completion raw pin. It
does not launch capacity processes again.

The legacy bridge writes a new
`allocatbelt.application-source5-preparation-completion.v1` receipt beside
the final PlanV3, mode 0600 under an owned mode-0700 parent. It separates
preparation, final Spec, final Plan and SourceV5 raw/semantic identities. The
receipt includes all three capacity ledgers and entries, 45 pressure scope
receipts, three replayed six-pair pilot manifests, three verified oracle
manifests, deterministic `filled_slots`, and capacity-ledger heads. Its
`complete` field means the bridge replayed those records;
`qualification_eligible` remains `false`.

The controller can independently revalidate a pinned generation without
rewriting it:

```python
verified_completion = verify_prepared_inputs_completion(
    {"path": completion_path, "raw_sha256": completion_raw_sha,
     "semantic_sha256": completion_semantic_sha},
    {
        "schema": "allocatbelt.application-source5-prepared-inputs-provenance.v1",
        "preparation_pin": {"path": preparation_path, "raw_sha256": preparation_raw_sha},
        "final_spec_pin": {"path": final_spec_path, "raw_sha256": final_spec_raw_sha},
        "final_plan_pin": {"path": final_plan_path, "raw_sha256": final_plan_raw_sha},
    },
    source_root,
    input_root,
)
```

The verifier returns the canonical completion object itself after replaying
the ordered capacity, pressure, fixed-pair, and oracle evidence and comparing
the full result byte-for-byte. `verify-completion` exposes the same check as
an offline command. It does not dispatch work, modify SpecV3/PlanV3, or mark
the generation eligible.

`complete_prepared_inputs_bounded` is the explicit v2 bridge. It requires one
caller-frozen resource-budget raw pin for each of the three hosts, calls the
bounded offline capacity verifier for each v2 completion, and embeds those
budget pins and monitor summaries in
`allocatbelt.application-source5-preparation-completion.v2`. It preserves the
same final SpecV3/PlanV3 validators, original host/context order and false
eligibility flags. The Source5 execution-manifest v3 scope
`final_prepared_bounded` selects this completion explicitly; v1 and v2
execution manifests continue to select their original completion schemas.

This receipt is an input to the Source5 controller's locked chronology
registration path. The controller registers it under its dispatch lock and
retains the original capacity ledger heads. The bridge itself does not
register a campaign event or enable later execution.

Bounded pressure uses a separate pressure-material/index v2 and pressure-pair
recipe v2. Each material must carry an explicit `probe_capture` object with
`capture_timeout_ns` and the complete FixedR8 `storage_budget`; the controller
validates both before starting either capture and does not infer a timeout or
storage ceiling. It invokes the captured ProbeV2 owner for both original
members, pins their raw and semantic receipt digests in the exact two-row
`application-source5-probe-capture-bundle.v1`, and independently replays each
receipt and producer bundle through the offline composer before authorization.
The same budget is bound at the recipe's top level and the receipts remain in
the raw-pinned `application-source5-pressure-helper-payload.v2`. The pressure
receiver verifies the recipe/bundle/member mapping and repeats strict offline
replay. Existing pressure-material/index v1, recipe v1, and helper-payload v1
remain closed and unchanged for earlier execution-manifest versions.

## Native pilot prerequisites

Before a native witness, freeze the reviewed SourceV5 revision and typed
helper inventory. Verify its signed revision and all four distinct normal
APP artifacts on each host. Build the isolated standard-mimalloc graph from
its own lockfile and run the independent resource-domain calibrator before
capturing each host manifest; retain the exact calibrator output. Use private
mode-0700 input/output/TMPDIR trees outside SourceV5, and keep raw evidence in
private resources.

Available x86-64 build inputs are:

```sh
cargo build --release --locked --target x86_64-unknown-linux-gnu -p allocatbelt-bench --features resource-feedback \
  --bin bench-application-allocatbelt --bin bench-application-mimalloc --bin bench-application-system \
  --bin bench-runtime-soak-allocatbelt --bin bench-resource-domain-calibration
cargo build --release --locked --target x86_64-unknown-linux-gnu \
  --manifest-path bench/standard-mimalloc/Cargo.toml --features resource-feedback \
  --bin bench-application-standard-mimalloc
cargo build --release --locked --target x86_64-unknown-linux-gnu -p allocatbelt-qualification-tools --bin application-analyze
```

These commands are prerequisites, not checks performed for this implementation.
A single-host component witness cannot supply the three-host SourceV5 matrix,
360 six-pair pilots per host, 360 oracles across the cohort, or the later fixed,
pressure, A/A, confirmation and three-hour Soak lanes. It cannot establish
allocator performance or qualification readiness.

## Origin journal receipt and pure structural replay

The additive chronology APIs keep origin-host capture separate from the
peer/offline structural reader. `capture_source5_origin_journal_receipt_locked`
runs only while the existing `CampaignHostLock` is held. It snapshots the
locked journal, checks the origin boot/affinity/network namespace before and
after that snapshot, and writes one mode-0600 receipt beside the locked
chronology journal. It does not change SpecV3, PlanV3, campaign job schemas, or
the existing dispatch/Soak paths. The exact R8 fixed-dispatch change also
captures and rejects unsafe inherited shell startup/import environment entries
before SourceV5 input preparation, while preserving the environment that the
same dispatch later binds to its launch.

The offline APIs accept immutable evidence bytes or read-only seekable byte
streams. They do not open paths, inspect the current host, read `/proc`, sample
a clock, acquire a lock, launch a process, or write a cache. They replay
journal framing, canonical JSON, digest chain, host/source identity, event
order, registration structure, exact original PlanV3 job index/run/member
authorization, helper-input snapshot, and declared analysis prerequisite
ancestry. The journal reader accepts execution-manifest v1
`prospective_exploration`, v2 `final_prepared`, and v3
`final_prepared_bounded` as three distinct scopes. It preserves each raw
generation and semantic pin as separate fields.

The request schema is
`allocatbelt.application-source5-host-journal-request.v1`; its exact keys are
`schema`, `scope`, `campaign_id`, `host_id`, `source_root`, `input_root`,
`output_root`, `execution_manifest`, `provenance`, `journal`, `origin_receipt`,
and `evidence_index`. Manifest, origin-receipt, and evidence-index pins are
`{path,raw_sha256,semantic_sha256}`. The journal pin is
`{path,raw_sha256,byte_count,record_count,terminal_head}`. Provenance is the
original generation `{schema,preparation_pin,final_spec_pin,final_plan_pin}`;
`preparation_pin` is null only for prospective exploration.

The evidence index schema is
`allocatbelt.application-source5-journal-evidence-index.v1`; its closed
envelope is `{schema,campaign_id,host_id,source_root,input_root,output_root,entries,index_sha256}`.
Each entry uses
`{role,host_id,origin_path,local_path,raw_sha256,semantic_sha256,byte_count}`.
Paths are normalized absolute strings, sorted, unique, and identity-mapped
(`origin_path == local_path`). The index excludes itself and the origin
receipt, which are separately raw-pinned store entries. The captured-evidence
store schema is
`allocatbelt.application-source5-captured-evidence.v1`; each row adds
`raw_bytes` to the corresponding index entry. It first checks exact index/store
membership and raw metadata, reads only the request-pinned execution manifest,
SpecV3/PlanV3 and three source manifests needed to derive the complete source
closure, then requires every typed source and declared artifact path before it
hashes any indexed nested stream. Raw digest and semantic-role checks precede
the remaining nested parsing. Typed SourceV5 scripts must match all three
host manifests and the exact selected-host execution module map. The journal
core does not execute those modules; it returns their verified regular-file
pins for the component dispatcher to load only after that component's own
declared nested-path closure is complete.
The closed role vocabulary distinguishes `typed_source_file`,
`typed_source_symlink`,
`source5_helper_input`, `source5_job_record`, `analysis_artifact`,
`capacity_completion`, `capacity_ledger`, `capacity_host_receipt`,
`capacity_request`, `capacity_artifact`, `capacity_receipt`,
`fixed_pair_artifact`, `pressure_pair_artifact`, `source5_soak_artifact`,
`component_receipt`, `normal_app_output`, and `opaque_trace` from the original
input, manifest, journal, index, and origin-receipt roles. Raw-only inputs use
a null semantic digest; schema-bearing completion, analysis, job-record, and
host-receipt files retain their original embedded semantic digest separately
from exact file SHA-256. A path's extension is never a role.

The origin receipt schema is
`allocatbelt.application-source5-origin-journal-receipt.v1`; its closed body
contains `schema`, `campaign_id`, `host_id`, `original_pins`,
`execution_manifest`, `journal`, `origin_facts`, `captured_monotonic_ns`,
`dependency_pins`, `evidence_index`, `qualification_eligible`,
`execution_ready`, and `receipt_sha256`. Its `journal` snapshot retains the
original path, raw hash, byte count, record count, terminal head, and last
monotonic timestamp. `origin_facts` records the exact observed-host pin,
controls, boot/kernel/CPU, affinity, network namespace, and matching before
and after host observations. The same-boot capture timestamp bounds all
journal timestamps; peer current host facts never substitute for those
origin observations.

The structural replay result uses
`allocatbelt.application-source5-host-journal-structural-replay.v1`. It
returns original pins, source-manifest references, typed dependency pins,
registration rows, exact authorization rows, callbacks, terminal claims,
analysis claims, event heads by original record count, indexed job-record and
component-receipt pins, and a structural ancestry index. The ancestry query
replays the entire host evidence again before proving any requested historical
head/count and authorization. For pressure jobs it derives the one original
fixed predecessor from that pressure job's frozen `predecessor_run_ids` and
returns its earlier authorization and terminal claim. A `valid_pair` terminal
in this result is still only a journal claim until the dispatcher independently
replays that job's component receipt and artifacts.

These APIs keep `component_results_replayed`, `analysis_results_replayed`,
`capacity_producer_replayed`, `qualification_eligible`, and `execution_ready`
false. The result explicitly reports
`component_dispatch_pending: true`. It is an ancestry/input foundation only:
it does not validate the selected capacity producer, the complete fixed or
pressure component, the Soak stream, native analysis, or the three-host
campaign gates. The separate inventory-pinned Source5 dispatcher must replay
the exact job record and phase-specific strict origin receipt before any job
can be counted as accepted. The full campaign remains blocked until those
component replays and the original numeric gates complete on all three hosts.

The callable interface is:

```python
verify_source5_host_journal_offline(request, captured_evidence) -> host_replay
verify_source5_journal_ancestry(
    request, captured_evidence, *, authorization_head,
    authorization_record_count, authorization_id, job_run_id, phase,
    historical_head=None, historical_record_count=None,
) -> structural_proof
```

Authorization rows carry the original `job`, `job_index`, ordered `members`,
execution-manifest/helper-input/helper-module pins, capacity registration and
ledger heads, prerequisite pins, deadlines, start/terminal event details, and
the terminal component/process-metrics digests. `source5_finished` is a
structural summary of `state_claim`, blocked reason, callback counts and
terminal head; `valid_pair` or `valid_soak` remains a journal claim until the
component validator compares its indexed job record and strict receipt. The
pressure ancestry query derives its fixed predecessor only from that pressure
job's original `predecessor_run_ids`, and proves the predecessor terminal
precedes the current pressure authorization. Its component replay remains a
separate dispatcher call.

Before journal replay, the host reader derives the maximum Source5 callback
count from the exact selected-host PlanV3 job lists: one authorization, up to
two APP starts, two terminals, and one job terminal for each paired job; one
authorization/start/terminal/job-terminal for the candidate Soak; the original
analysis events; and the exact v1 or prepared-capacity registration count.
Prepared execution-manifest v2/v3 scopes use this plan-derived event ceiling,
bounded by the existing finite Source5 maximum. Their byte ceiling is the
smaller of the plan's maximum event count times the unchanged 4 MiB per-event
limit and the existing one-GiB analyzer artifact bound. Legacy dispatch and
execution-manifest-v1 readers retain the original 100,000-event and 256 MiB
byte limits. The one-GiB value is an implementation ceiling, not evidence that
the complete original journal fits. A genuine full-horizon capture must retain
its measured canonical journal bytes and prove the frozen storage allowance is
large enough; if not, an additive raw-pinned journal budget must be frozen
before dispatch. The new bounds reject an oversized raw journal; they never
drop records or reduce scheduled job counts.

## Pure-journal CoreR2 source closure

The offline host journal now validates `source.files` as the exact typed
`allocatbelt.application-source-inventory.v1` record set before consuming any
indexed nested stream. Regular files retain their pinned mode, size and raw
hash. A terminal symlink is captured only as its literal UTF-8 target bytes
under the `typed_source_symlink` role (mode `120000`, at most 4 KiB); its
normalized relative target must resolve directly to one regular inventory
file without escaping the tree or traversing another inventory entry. The
reader never follows or executes that link. The semantic source-tree digest
covers the normalized complete record array, including link target metadata,
and remains distinct from both the raw manifest SHA and semantic manifest
SHA.

The identity evidence index must contain every typed source record and every
SourceV5-declared artifact before any of those indexed streams are read. The
four normal APP artifacts use `normal_app_output`; the candidate Soak artifact
uses `source5_soak_artifact`; the analyzer uses `analysis_artifact`; and the
resource-domain calibration binary/output use `capacity_artifact`. Runtime
readback code and the other declared source helpers stay regular
`typed_source_file` entries. These roles are bounded in the closed evidence
schema, including the 16 MiB prepared-completion role. The chronology core
returns these exact indexed path roles; it does not execute source modules.

The request parser retains the 100,000-event limit for the legacy and
prospective-exploration scopes. Final-prepared v2/v3 requests may use the
versioned finite 800,000-event envelope only to reach replay; the verifier
then derives the exact per-host callback horizon from the unchanged original
PlanV3 job lists and rejects any journal above that exact ceiling. The broad
syntax envelope is not a capacity claim or permission to shorten the plan.
A full-horizon public host-journal replay still requires genuine captured
origin receipts, the full identity-mapped evidence index, and independent
component dispatch; the focused typed-inventory tests do not establish that
full-cohort positive.

## Optional capacity-relative floor policy

A future SourceV5 generation may explicitly select
`application_capacity_relative_tenth_v1` when creating each source manifest.
The selector publishes feedback-policy artifact v2, whose descriptor is
derived from the pinned Rust runtime constants. With no selector, artifact v1
keeps its original keys and static 64 MiB/s floor. This selector starts a new
source/spec/preparation generation; it does not update or retag existing
SourceV5 manifests, preparation intents, probes, or captures.

The selected SpecV3 carries the same policy ID. Its preparation core uses the
additive core-v2 schema and preserves that ID exactly; the old core-v1 shape is
unchanged when selection is absent. The bridge requires all three pinned
SourceV5 feedback-policy artifacts to publish the same descriptor and binds
the descriptor through the Rust source inventory, runtime source hashes,
final SpecV3, preparation intent, and PlanV3 templates. Only external-pressure
templates carry the selector and descriptor; fixed-policy templates continue
to omit both. All preparation evidence remains ineligible for qualification.
