# SourceV5 campaign controller candidate

The current campaign selects SpecV3
`qualification_profile: "two_kvm_hosts_v1"` for two KVM guests. Host-indexed
closure follows that exact matrix; the numerical gates, 360 pilot jobs,
16,609 original jobs, 99,659 callback events and three-hour Soak remain per
host. Results cover those KVM venues. Specs without the selector retain the
legacy three-host contract discussed below. Existing source, spec, plan and
journal generations cannot be retagged when changing profiles.

`scripts/application-source5-campaign.py` now has separate execution-manifest
v1 and v2 paths. V1 retains the original capacity-stage registration
contract. V2 accepts only the closed `final_prepared` scope: it replays the
full prepared-input completion against the original three-host SourceV5,
SpecV3, PlanV3, capacity ledgers, pressure-scope receipts, pilot manifests and
oracle manifests, then derives the selected host's V2 pressure bindings from
the verified 45-entry matrix. The selected host's standalone
`application-capacity-preparation-completion.v1` is registered by a distinct
chronology event before the V2 manifest is frozen; it is never presented as a
legacy `application-capacity-stage-completion.v1` receipt.

The controller still does not make a native pilot or full campaign complete
by itself. `load_context` keeps the unchanged SourceV5 `validate_spec` and
`verify_plan` calls. A prospective SpecV3 with empty rates/oracles is not a
valid bootstrap input to that legacy validator path. The prepared-input bridge
requires genuine pre-Spec capacity runs, pressure calibration V2 receipts,
six-pair pilots, actual oracle outputs, and a separately frozen final
SpecV3/PlanV3. Do not create one-host companion manifests, hand-author
completion or calibration receipts, relabel a TSV, or edit a frozen spec or
plan to make a validator pass.

The controller adds a closed Source5 execution manifest and helper input,
regular-file inventory checks, locked one-use authorization, actual APP
lifecycle journal callbacks, fixed receipt replay, pressure predecessor
replay, a one-APP Soak supervisor adapter with full readback replay,
retained-pair capacity-pilot export, per-host final numeric analysis, and a
prepared-capacity registration API. Execution
manifest v2 is one file per host-local chronology/output root; all three
manifests bind the same completion, provenance, source-generation, SpecV3 and
PlanV3 pins while keeping registration heads and phase evidence host-local.
The original eight `qualification_harness` keys, SpecV3/PlanV3 bytes and false
readiness flags remain unchanged. Every Source5 eligibility field remains
false at the controller/campaign layer. A passing captured V2 reader result
retains its own component `qualification_eligible: true`; the adapter does not
rewrite that numeric result to match the still-false outer campaign field.
The legacy shell entrypoint and its hard-disabled command behavior remain
unchanged.

## Controller boundaries

The selected host must still belong to the original three-host list in the
same order. The controller checks all three actual SourceV5 manifests and
their common frozen source/build contracts, but loads and executes only the
selected host's typed regular-file inventory. `SpecV3`, `PlanV3`, job IDs,
ordinals, nonces, rates, oracle references, deadlines, and readiness fields
remain byte-pinned inputs.

Every host phase consumes its complete original plan job list in order. A
complete invalid pair consumes its ordinal and later original jobs can
continue. A preflight, launch, callback, receipt, deadline, cleanup, or
watchdog-lifecycle failure seals the phase root and blocks replacement or
retry. The deadline watchdog fences its sender before restoring the previous
handler and signal mask, drains any pending control signal, and leaves the
control signal blocked if restoration cannot be verified. Any watchdog setup,
teardown, or delivery failure produces a blocked terminal even when both APP
callbacks report clean exits. Analysis freshly re-reads the recorded
content-addressed component sidecars and chronology chain before replaying
numeric gates; prepared-input registration repeats full cohort replay on
every use rather than trusting a completion-only cache.

The Soak phase retains one original APP launch. Its source-pinned adapter calls
the frozen Soak V2 `launch_soak_v2_application` API from the same loaded
readback module captured by SourceV5. The callback journal stores the actual
APP PID/start identity, raw child return code, normalized terminal status,
APP cleanup, pressure cleanup, supervisor receipt, and full three-hour
readback. It does not turn Soak into a paired two-member job. A failed,
interrupted, timed-out, missing-callback, or unverified-cleanup run consumes
the original ordinal and seals it against retry. Per-host final decisions
replay the original phase evidence and always retain false campaign
eligibility. The cohort API replays each host's own chronology and remains
blocked until an accepted offline pressure replay API exists.

The direct APP binding's `recipe_sha256` is the validated pressure recipe's
semantic digest. The parent Soak recipe raw SHA, pressure recipe raw-file SHA,
and pressure recipe semantic SHA remain separate pins; fresh replay rereads
both recipe files and checks the pressure validator's raw/semantic identities
before accepting the APP binding.

The Source5-only audit digest uses an exact JSON projection of the captured V2
audit fields. It represents the captured campaign-controller and pressure
validator `ModuleType` handles by their typed source-inventory path, mode,
size, and SHA pins, while the launch audit copy retains the original trusted
handles. Unsupported audit or module shapes fail before a launch descriptor
is derived.

The launch authorization is an additive Source5-only overlay. The captured
legacy audit, baseline preflight, parent recipe, SpecV3, and PlanV3 continue to
show their original false readiness and launch fields. Before deriving a
qualified descriptor for a private copy of the audit, the helper checks the
completed three-host preparation generation, exact selected host and source
pins, 15-entry capacity preparation and locked registration head, original
Soak job/material index, captured helper/module identity, and the passing
pressure-analysis chronology predecessor. It accepts only the two known
hard-disabled legacy capabilities after every supported prerequisite is
present; missing capacity, composition, pressure, stale-generation, or
unknown readiness gaps reject before APP construction. The derived overlay
and baseline-audit hash are retained in the component sidecars and freshly
replayed during phase/final analysis. This overlay authorizes only the single
original Soak APP and does not change any legacy readiness or eligibility
input.

The bounded adapter fixture uses the existing synthetic SourceV5 recipe
fixture to exercise the actual public materials-index builder, captured V2
preflight, source-pin replay, and missing-prerequisite rejection. Its host
binding rows are shape-only test values and it does not exercise a successful
overlay, supervisor callback lifecycle, or numeric Soak. A successful native
run still requires the genuine prepared completion, registered capacity
matrix, passing pressure-analysis predecessor, qualified V2 recipe/build
receipt, measured construction probe, pressure recipe/condition, and host-local
mixed ring described below. No source5 preparation artifact or three-hour
performance claim is implied by the bounded fixture.

## Prepared-input execution manifest v2

Use v2 only after the pure prepared-input completion verifier succeeds for
the final SpecV3/PlanV3 and the selected host's prepared-capacity registration
has been sealed. The verifier call is:

```python
completion = source5_preparation.verify_prepared_inputs_completion(
    completion_pin, provenance_pins, source_root, input_root,
)
```

`completion_pin` is exactly `{path, raw_sha256, semantic_sha256}`. The closed
`provenance_pins` object is
`{schema:'allocatbelt.application-source5-prepared-inputs-provenance.v1',
preparation_pin:{path,raw_sha256},
final_spec_pin:{path,raw_sha256},
final_plan_pin:{path,raw_sha256}}`. The verifier reconstructs every
capacity, pressure, six-pair pilot and oracle pin from the canonical
completion, replays their recorded verification receipts, and compares the
full resulting completion bytes. Paths in this contract are same-origin
identity copies; path translation is rejected.

Register each host's real pre-Spec capacity preparation under that host's
chronology lock before creating its final v2 execution manifest:

```sh
python3 -B scripts/application-campaign-chronology.py register-prepared-capacity \
  --plan /private/inputs/final-plan.json \
  --plan-sha256 FINAL_PLAN_RAW_SHA256 \
  --spec /private/inputs/final-spec.json \
  --spec-sha256 FINAL_SPEC_RAW_SHA256 \
  --source-root /source/final-signed-source-v5 \
  --input-root /private/inputs \
  --host-id HOST_ID \
  --observed-host /private/inputs/hosts/HOST_ID.json \
  --observed-host-sha256 OBSERVED_HOST_RAW_SHA256 \
  --output-root /private/host-output \
  --completion /private/inputs/prepared-inputs-completion.json \
  --completion-raw-sha256 COMPLETION_RAW_SHA256 \
  --completion-semantic-sha256 COMPLETION_SEMANTIC_SHA256 \
  --preparation /private/inputs/preparation-intent.json \
  --preparation-sha256 PREPARATION_RAW_SHA256 \
  --final-spec /private/inputs/final-spec.json \
  --final-spec-sha256 FINAL_SPEC_RAW_SHA256 \
  --final-plan /private/inputs/final-plan.json \
  --final-plan-sha256 FINAL_PLAN_RAW_SHA256
```

This writes the distinct `source5_prepared_capacity_registered` event. It
replays the entire selected-host completion, then binds the selected host's
original standalone `application-capacity-preparation-completion.v1`, its
ordered 15-entry ledger, terminal head, frozen schedule digest, host
verification receipt and completion provenance. The event head in
`registered.registration_head` is the host-local registration pin. The event
contains the actual pre-Spec receipt; it does not convert it to the legacy
stage-v1 schema.

Create one execution manifest v2 per host-local chronology and output root.
Keep the existing common `campaign_id`, host order, original SpecV3/PlanV3 and
all selected source-manifest pins, execution-source records, observed-host records,
regular-script inventory, roots, phase order, protocol digest and false
eligibility field. V2 replaces the v1 `capacity_completions` map with these
closed fields:

```json
{
  "schema": "allocatbelt.application-source5-campaign-execution.v2",
  "scope": "final_prepared",
  "prepared_input_generation": {
    "completion": {
      "path": "/private/inputs/prepared-inputs-completion.json",
      "raw_sha256": "...",
      "semantic_sha256": "..."
    },
    "provenance": {
      "schema": "allocatbelt.application-source5-prepared-inputs-provenance.v1",
      "preparation_pin": {"path": "/private/inputs/preparation-intent.json", "raw_sha256": "..."},
      "final_spec_pin": {"path": "/private/inputs/final-spec.json", "raw_sha256": "..."},
      "final_plan_pin": {"path": "/private/inputs/final-plan.json", "raw_sha256": "..."}
    }
  },
  "prepared_capacity_registration": {
    "completion": {"path": "/private/inputs/prepared-inputs-completion.json", "raw_sha256": "...", "semantic_sha256": "..."},
    "host_completion": {"path": "/private/inputs/capacity-host-completion.json", "raw_sha256": "...", "semantic_sha256": "..."},
    "host_verification": {"path": "/private/inputs/capacity-host-verification.json", "raw_sha256": "...", "receipt_sha256": "..."},
    "ledger": {"path": "/private/inputs/capacity-ledger.jsonl", "raw_sha256": "...", "terminal_head": "..."},
    "capacity_schedule_sha256": "...",
    "registration_head": "..."
  }
}
```

The `host_completion`, `host_verification` and `ledger` values must be copied
from the registration result for this exact selected host. Recompute
`manifest_sha256` over the complete canonical manifest body and write it as a
new owned mode-0600 artifact; do not modify the original SpecV3, PlanV3,
preparation intent or completion. The other two hosts produce their own
registration heads and v2 manifests while retaining the same immutable
cohort completion and provenance pins. Each host runs and gates its original
jobs and metrics independently.

| Phase | Required prior gate | Current candidate behavior |
|---|---|---|
| Exploration | Clean registered 15-entry capacity completion | Runs original fixed pairs; after complete receipts, exports the exact six-pair-per-cell/per-allocator pilot schema and candidate rates without changing SpecV3. |
| A/A | Passing exploration analysis | Uses original A/A jobs and analyzer. |
| Confirmation | Passing exploration and A/A analyses | Uses original fixed-policy jobs and a fresh receipt/runtime-v2 replay. |
| Fixed analysis | Every original confirmation job valid | Calls the neutral numeric analyzer while preserving the legacy hard-disabled wrapper. |
| Pressure | Passing fixed analysis and exact successful fixed predecessors | V2 recipes derive the separate capacity `calibration_id` and prospective `pressure_calibration_id` from the verified completion, then replay the exact scope, policy, producer bundle, observed host and condition before the locked pressure API can launch APPs. |
| Pressure analysis | Every original pressure job valid | Replays each pressure artifact under its original authorization and calls the neutral analyzer. |
| Soak | Passing pressure analysis | Uses one original APP launch through captured Soak V2 callbacks, then replays the exact 10,800-second artifacts. Genuine recipe, pressure, probe, and ring inputs are still required. |
| Soak analysis | Completed original Soak ordinal | Replays the single APP component and records its numeric gate without changing eligibility. |
| Final analysis | Complete original host phases | Recomputes the per-host numeric gates from original evidence; campaign eligibility remains false. |

Create the Soak materials index only from the exact final prepared manifest,
original recipe, and recipe-builder receipt. First build the original V2
parent recipe with the pinned Soak recipe builder, using the final SpecV3 and
PlanV3, selected host SourceV5 tree, measured construction probe, actual
external-pressure recipe/condition, and independent mixed ring. Preserve the
builder's canonical stdout receipt bytes beside the recipe:

```sh
python3 -B scripts/application-soak-recipe.py build \
  --spec /private/inputs/final-spec.json \
  --spec-sha256 FINAL_SPEC_SEMANTIC_SHA256 \
  --plan /private/inputs/final-plan.json \
  --plan-sha256 FINAL_PLAN_SEMANTIC_SHA256 \
  --plan-file-sha256 FINAL_PLAN_RAW_SHA256 \
  --job-run-id ORIGINAL_SOAK_RUN_ID \
  --source-root /source/host-SOURCE5 \
  --oracle-root /private/inputs/oracles \
  --ring-relative-path rings/HOST_ID/mixed-PROFILE.ring \
  --ring-sha256 MIXED_RING_RAW_SHA256 \
  --mode qualified --duration-seconds 10800 \
  --terminal-budget-bytes FROZEN_TERMINAL_BUDGET \
  --sample-budget-bytes FROZEN_SAMPLE_BUDGET \
  --construction-probe /private/inputs/probes/soak-probe.json \
  --construction-probe-sha256 CONSTRUCTION_PROBE_RAW_SHA256 \
  --pressure-recipe /private/inputs/pressure/soak-pressure-recipe.json \
  --pressure-recipe-raw-sha256 PRESSURE_RECIPE_RAW_SHA256 \
  --pressure-recipe-semantic-sha256 PRESSURE_RECIPE_SEMANTIC_SHA256 \
  --output /private/artifacts/source5/HOST_ID/soak-parent-recipe.json \
  > /private/artifacts/source5/HOST_ID/soak-build-receipt.json
```

The pressure recipe, ring, and construction probe must come from genuine
host-local producer evidence. Do not substitute placeholder files, reuse
another host's ring/probe, or use a functional/short recipe for the original
qualification job. Pin the exact recipe and receipt into a private materials
index, then let the locked controller perform its own preflight before APP
construction:

```sh
python3 -B scripts/application-source5-campaign.py index-soak-materials \
  --manifest /private/artifacts/source5/HOST_ID/execution-manifest.json \
  --host-id HOST_ID \
  --recipe /private/artifacts/source5/HOST_ID/soak-parent-recipe.json \
  --build-receipt /private/artifacts/source5/HOST_ID/soak-build-receipt.json \
  --output /private/artifacts/source5/HOST_ID/soak-materials-index.json

python3 -B scripts/application-source5-campaign.py run-host \
  --manifest /private/artifacts/source5/HOST_ID/execution-manifest.json \
  --host-id HOST_ID --phase soak \
  --soak-material-index /private/artifacts/source5/HOST_ID/soak-materials-index.json
```

The `soak` phase then runs its Soak analysis. After every original phase has
been recorded, `run-host --phase final_analysis` performs the per-host final
numeric replay. The aggregate command accepts one immutable execution
manifest per original host and independently checks the three chronology
roots:

```sh
python3 -B scripts/application-source5-campaign.py verify-final-cohort \
  --host-manifest HOST_A=/private/host-a/execution-manifest.json \
  --host-manifest HOST_B=/private/host-b/execution-manifest.json \
  --host-manifest HOST_C=/private/host-c/execution-manifest.json
```

It reports `blocked` while the independent pressure offline verifier is
unavailable, even if every per-host numeric decision passes. This API never
combines samples across hosts and never sets SpecV3/PlanV3 readiness or
campaign eligibility. The CLI uses exit status 3 for that blocked result.

Pressure overlay verification uses the frozen chronology head as a historical
ancestor of the live journal and requires the exact pending/completed pressure
authorization. It does not reacquire the non-reentrant lock or compare an old
overlay to a later exact journal head. The pressure helper independently
replays the original fixed predecessor receipt and its two V2 runtime
zero-usage snapshots; it does not fabricate the archived shell-runner hashes.
For calibration V2, the original SpecV3 `pressure_calibration` pin remains
provenance; the added V2 sidecar binds the exact prepared capacity TSV and
context receipt. Its `calibration_id` is the capacity-key identity, while
`pressure_calibration_id` remains the distinct prospective condition identity.

## Finite native pilot plan

This plan separates a bounded component witness from the full rate pilot. A
five-pair witness is not a rate calibration, four-allocator runtime evidence,
A/A, confirmation, pressure qualification, or soak. It must use real APPs,
fresh source pins, actual per-process proofs and cleanup receipts, and original
job values from a valid prospective PlanV3. The current controller CLI only
accepts complete phases; an exact five-run-ID witness dispatcher is still
needed. Do not mark a partial phase complete or rerun a consumed ordinal.

1. **Freeze fresh SourceV5 source and binaries on each host.** Use the reviewed
   signed source revision after all controller helpers are regular typed
   inventory entries, including `scripts/application-source5-soak.py`. Build
   under Rust 1.99.0 with the target flags preserved:

   ```sh
   cargo build --release --locked --target x86_64-unknown-linux-gnu -p allocatbelt-bench --features resource-feedback \
     --bin bench-application-allocatbelt --bin bench-application-mimalloc --bin bench-application-system \
     --bin bench-runtime-soak-allocatbelt --bin bench-resource-domain-calibration
   cargo build --release --locked --target x86_64-unknown-linux-gnu \
     --manifest-path bench/standard-mimalloc/Cargo.toml --target-dir target/source5-standard-mimalloc \
     --features resource-feedback --bin bench-application-standard-mimalloc
   cargo build --release --locked --target x86_64-unknown-linux-gnu -p allocatbelt-qualification-tools --bin application-analyze
   ```

   The isolated standard-mimalloc graph must produce its own distinct binary;
   the secure workspace dependency cannot be relabeled as standard mimalloc.
   Pin the four distinct normal APP binaries, candidate Soak binary, analyzer,
   and resource-domain calibration binary/output. Run the calibration binary
   from that build and retain its actual JSON output before source-manifest
   capture, for example:

   ```sh
   target/x86_64-unknown-linux-gnu/release/bench-resource-domain-calibration \
     > target/x86_64-unknown-linux-gnu/release/resource-domain-calibration.json
   ```

   Produce truthful feature/build-input manifests and then a fresh host
   SourceV5 manifest with the existing command. Artifact paths are relative to
   that SourceV5 root:

   ```sh
   python3 -B scripts/application-campaign.py source-manifest \
     --source-root SOURCE --host-id HOST_ID \
     --target-triple x86_64-unknown-linux-gnu --target-cpu x86-64-v3 \
     --features-sha256 FEATURES_SHA256 --build-inputs-sha256 BUILD_INPUTS_SHA256 \
     --allocator-binary allocatbelt=target/x86_64-unknown-linux-gnu/release/bench-application-allocatbelt \
     --allocator-binary mimalloc-secure=target/x86_64-unknown-linux-gnu/release/bench-application-mimalloc \
     --allocator-binary mimalloc-standard=target/source5-standard-mimalloc/x86_64-unknown-linux-gnu/release/bench-application-standard-mimalloc \
     --allocator-binary system=target/x86_64-unknown-linux-gnu/release/bench-application-system \
     --soak-binary allocatbelt=target/x86_64-unknown-linux-gnu/release/bench-runtime-soak-allocatbelt \
     --analysis-binary target/x86_64-unknown-linux-gnu/release/application-analyze \
     --resource-domain-calibration-binary target/x86_64-unknown-linux-gnu/release/bench-resource-domain-calibration \
     --resource-domain-calibration-output target/x86_64-unknown-linux-gnu/release/resource-domain-calibration.json \
     --output INPUT/source-HOST_ID.json
   ```

   Before manifest capture, check ELF architecture, executable mode, allocator
   labels and constructor output. Rebuild and regenerate all three manifests
   if any pinned helper bytes change. Keep build outputs explicitly pinned
   artifacts, not extra inventory records. Source-tree, semantic-manifest,
   and raw-file digests are different values.

2. **Prepare genuine per-host inputs.** Observe boot ID, CPU/kernel, frozen
   controls, inherited affinity, namespace, storage mounts/devices/free bytes
   and inode capacity. The current tree has no public observed-host exporter;
   write and validate the exact
   `allocatbelt.application-capacity-host-context.v1` from real observations.
   Preserve a complete three-host matrix with one bare-metal and two KVM source
   manifests; a one-host SpecV3 is rejected. Use private mode-0700 output and
   TMPDIR roots outside source and frozen inputs.

   Follow [the Source5 input-preparation contract](application-source5-input-preparation.md): pin a preparation intent; run the real
   15-context pre-Spec capacity preparation against actual APP probes and
   `application-byte-capacity.py`; calibrate pressure against the exact
   prepared TSV bytes with the context-scope v2 driver and independent
   readback; export all three six-pair pilot manifests; produce the real
   oracle matrix; then create a new immutable final SpecV3/PlanV3 and replay
   `complete_prepared_inputs`. Existing SpecV3/PlanV3 bytes are never edited.
   The Source5 chronology's distinct prepared-capacity registration event
   must be sealed on each host before its execution-manifest-v2 artifact is
   written. Driver stdout is not a receipt; keep preparation, final-input and
   failed-ordinal generations separate.

3. **Run the finite first witness.** Once a versioned planning-only input
   adapter accepts the preparation-declared prospective generation, from its
   newly frozen prospective PlanV3,
   select the five original capacity pairs specified by the pilot contract:
   CPU, memory, HTTP, and disk steady, plus mixed/mixed. Use both actual
   bounded and Tokio members and preserve original job IDs, nonces, 30-second
   horizon, 5,000 sentinel, hard ceilings, static 16 GiB/s buckets,
   feedback-off setting and deadlines. Keep APP PID/start/ELF/argv/environment,
   TMPDIR/affinity/namespace proofs and V2 five-zero/Control-baseline cleanup.
   This controller candidate has no five-job selector and its legacy
   `load_context` still calls the final-input validator; the witness remains
   blocked until both the planning-only adapter and exact selector route
   through the locked one-use authorization API. Preserve these receipts as the first five original
   ordinals; they do not replace missing pairs or close any phase gate.

4. **Complete actual capacity pilot evidence before freezing rates.** The
   existing `freeze_rates` API requires all 15 cells, all four allocators and
   exactly six original ordinals for each treatment. That is 360 matched pairs
   and 720 APP launches for one host (at least six hours of serial 30-second
   capacity runs, before setup and cleanup). After all receipts are present,
   this controller's `_capacity_pilot` exporter replays each fixed pair and
   emits `allocatbelt.application-capacity-pilot.v1` with the exact bounded /
   Tokio attempted, admitted, rejected, on-time and late counts plus a digest
   of the raw overlay and receipt. `campaign.freeze_rates` derives the
   six-pair medians and fixed 70/90-percent floors. The exporter must refuse an
   invalid, absent, reordered, repeated, or changed ordinal. Merge the three
   genuine host rate artifacts deterministically into a fresh complete
   SpecV3; no host's rates may stand in for another and the original inputs
   remain archived.

5. **Freeze trusted oracles and final inputs.** With complete frozen rates,
   use `application-campaign.py prepare-oracles` to invoke each pinned normal
   APP's actual `--emit-oracle-only` producer for every host/allocator/cell/load
   identity. Independently validate producer rows, merge the three manifests,
   build fresh final SpecV3/PlanV3 and replay the preparation-completion bridge.
   Do not edit the prospective SpecV3/PlanV3 in place or retroactively change
   capacity denominators.

6. **Run and gate all original host phases.** Once the bridge, pressure v2
   materials, and genuine Soak materials exist, run each host's full original
   schedule: exploration, A/A, 36 confirmation pairs, fixed analysis, 36
   pressure pairs with exact successful fixed predecessors, pressure analysis,
   the original uninterrupted 10,800-second candidate soak (108,001 samples
   and both 36,000-row RSS windows), then final analysis. Keep the per-host
   gates independent; no pooling, retry, ordinal replacement, shortened
   horizon, or synthetic readiness. `run-host --phase all` now includes the
   one-APP Soak launch and final per-host analysis when both raw-pinned
   materials indexes are supplied.

## Pending operational interfaces

- **Prospective planning and first witness:** the new preparation intent and
  pre-Spec capacity stage preserve genuine 3-host inputs without inventing a
  companion manifest. The legacy `campaign.validate_spec`/`verify_plan` path
  still refuses an empty-rate prospective SpecV3, so the five-original-job
  witness and six-pair exploration bootstrap do not yet have a runnable
  controller input. A versioned planning-only validator/completion adapter
  must route those exact original jobs through the one-use Source5 lock and
  retain false readiness/eligibility bits. The v2 final-prepared manifest does
  not open that prospective scope.
- **Six-pair pilot and complete freeze:** `_capacity_pilot` can export the
  required six original pairs per cell/allocator from retained fixed receipts,
  and the preparation verifier replays three complete 360-pair manifests.
  Genuine original exploration receipts and a complete deterministic
  three-host rate/oracle generation are still prerequisites; missing or
  failed ordinals cannot be replaced.
- **Pressure material production:** the controller reads each raw-pinned
  per-job probe, composer output, policy, APP identity, oracle and measured
  recipe from the required materials index. The V2 condition binding and
  independent readback now check the prepared TSV, condition bytes, stable
  numeric policy projection, capacity producer bundle, observed host and
  host-verification receipt. A complete native materials index for all
  original pressure jobs must still be produced from genuine inputs.
- **Soak native inputs:** the callback adapter and per-job replay path are
  implemented. Each host still needs its genuine qualified parent recipe,
  build receipt, measured construction probe, exact pressure recipe/condition,
  and independent mixed ring; no three-hour Soak has been run for this
  candidate. The original 10,800-second/108,001-sample contract is unchanged.
- **Rate/oracle production:** preparation completion verifies the final
  three-host rate/oracle matrices and exact provenance once their producer
  manifests and artifacts exist. No native pilot or oracle output has been
  collected for this candidate.
- **Three-host final verification:** per-host final analysis freshly replays
  the original phase evidence. The aggregate API checks the three immutable
  manifests and host-local chronology roots, then fails closed because no
  accepted independent pressure offline replay API exists yet. Campaign
  eligibility and the legacy readiness bits remain false.

No native workload, Python unit suite, Rust build, or campaign phase was run
for this controller candidate. Static AST parsing is not a native or
application-performance claim. Raw native evidence belongs in the private
resources checkout. The finite native plan requires all three genuine host
inputs, full original pair matrices and actual per-process cleanup evidence;
this eight-file controller candidate does not supply those artifacts. Root
review and native execution remain separate gates.
