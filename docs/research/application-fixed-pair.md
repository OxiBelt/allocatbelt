# SourceV5 fixed-pair executor

`scripts/application-fixed-pair.py` is a separately pinned executor for one
original fixed-policy PlanV3 job. It consumes the original SpecV3, PlanV3,
SourceV5 host manifests, runtime recipes, APP binaries, and trusted oracle
pins. It does not change the campaign plan or authorize campaign dispatch.

The executor accepts only a fresh selected SourceV5 tree whose typed regular
file inventory already contains the executor and every captured helper. The
SourceV5 `qualification_harness` keeps its existing eight keys. The overlay
records separate path and SHA-256 pins for the executor, captured campaign
controller, inventory verifier, runtime reader, feedback reader, campaign
inputs module, and the pinned soak helper used for fd hashing and process
identity primitives. It does not reuse the soak helper's current process-group
cleanup routine.

The execution snapshot follows SourceV5 content-addressed semantics: it binds
the selected Git commit, source-tree digest, and typed inventory entries for
the exact implementation modules. That snapshot is a set of content pins; it
does not claim a cryptographic signature. Verify the selected Git commit's
signature in the acceptance workflow before using the component on a native
qualification host.

## Build input

The `build` verb reads one canonical or ordinary JSON input object with exactly
these fields:

```json
{
  "original_pins": {
    "spec": {"path": "/inputs/spec-v3.json", "sha256": "<raw-sha256>"},
    "spec_semantic_sha256": "<spec-digest>",
    "plan": {"path": "/inputs/plan-v3.json", "sha256": "<raw-sha256>"},
    "plan_semantic_sha256": "<plan-digest>",
    "source_manifests": {
      "host-a": {"path": "/inputs/sources/host-a.json", "sha256": "<raw-sha256>"},
      "host-b": {"path": "/inputs/sources/host-b.json", "sha256": "<raw-sha256>"},
      "host-c": {"path": "/inputs/sources/host-c.json", "sha256": "<raw-sha256>"}
    },
    "campaign_artifacts_root": "/inputs/oracles"
  },
  "execution_pins": {
    "source_root": "/source/fresh-source-v5",
    "selected_host_id": "host-a",
    "modules": {
      "executor": {"path": "scripts/application-fixed-pair.py", "sha256": "<sha256>"},
      "campaign_controller": {"path": "scripts/application-campaign.py", "sha256": "<sha256>"},
      "inventory_verifier": {"path": "scripts/application-source-inventory.py", "sha256": "<sha256>"},
      "runtime_reader": {"path": "scripts/application-runtime-readback.py", "sha256": "<sha256>"},
      "feedback_reader": {"path": "scripts/application-feedback-readback.py", "sha256": "<sha256>"},
      "campaign_inputs": {"path": "scripts/application-campaign-inputs.py", "sha256": "<sha256>"},
      "launch_identity_helper": {"path": "scripts/application-soak-readback.py", "sha256": "<sha256>"}
    }
  },
  "exact_job": {},
  "observed_host_pin": {"path": "/inputs/observed-host.json", "sha256": "<raw-sha256>"},
  "output_root": "/qualified-storage/fixed-pair/run-id"
}
```

`exact_job` must be byte-equivalent as canonical JSON to one unique
exploration, A/A, or confirmation job in PlanV3. Raw pins use `{path,sha256}`;
specification, plan, and manifest semantic digests remain separate fields.
The spec's source-manifest `sha256` entries are semantic manifest digests, so
the caller supplies the raw file hashes separately. The output root must be an
owned mode-0700 directory on a non-memory filesystem, outside the selected
source tree, and empty before the overlay is built.

For example:

```sh
python3 -B scripts/application-fixed-pair.py build --input fixed-pair-input.json
python3 -B scripts/application-fixed-pair.py launch \
  --overlay /qualified-storage/fixed-pair/run-id/fixed-pair-execution-overlay.json \
  --sha256 <overlay-raw-sha256>
python3 -B scripts/application-fixed-pair.py verify \
  --overlay /qualified-storage/fixed-pair/run-id/fixed-pair-execution-overlay.json \
  --overlay-sha256 <overlay-raw-sha256> \
  --receipt /qualified-storage/fixed-pair/run-id/fixed-pair-execution-receipt.json \
  --receipt-sha256 <receipt-raw-sha256> \
  --host-verification-receipt /private/inputs/host-a/fixed-pair/run-id/host-verification.json
```

`verify_fixed_pair_overlay` remains the strict live-host v1 verifier. The
optional `--host-verification-receipt` invokes that verifier and writes a
separate mode-0600 receipt in an owned mode-0700 parent outside the pair output
tree. Its pin is `{path,raw_sha256,host_verification_sha256}`. It binds the
exact overlay and execution-receipt raw bytes, status, original host-observation
raw pin, inherited affinity, network namespace and the strict output-mount
facts, including the original available byte and inode allowances. Its flags
remain `strict_verified=true` and all execution, chronology and qualification
flags remain false. The nested host identity digest is independent from the
outer receipt digest. The outer receipt schema is
`allocatbelt.application-fixed-pair-host-verification.v1`; its nested host
identity keeps the separate
`allocatbelt.application-fixed-pair-host-verification-identity.v1` schema.

On a coordinator with a different host identity, replay the same bytes at
their original absolute paths and call the additive API:

```python
result = verify_fixed_pair_overlay_offline(
    overlay_pin,
    receipt_pin,
    host_verification_pin,
    evidence_path_map,
)
```

`evidence_path_map` uses
`{schema:"allocatbelt.application-pressure-evidence-path-map.v1",entries:[{origin,local}]}`;
entries are sorted, unique, and identity mappings. Include the exact
SourceV5, input, campaign-artifact and pair-output directories plus the host
receipt file. Every frozen path remains at its original absolute location;
translated path maps are rejected because canonical requests and recipes bind
absolute paths. The offline verifier reconstructs the original overlay from the
pinned host receipt, replays probe output, both APP members, runtime-v2,
cleanup, process rows, metrics and the full output artifact tree. It uses the
recorded host facts and mount attestation, and first checks the exact original
SpecV3 host bytes against that nested identity. It does not use coordinator
`/proc` or mount identity. It still rejects missing or changed raw bytes. Non-identity path
translations are unsupported because the frozen overlay and runtime requests
contain absolute paths.

The equivalent CLI is:

```sh
python3 -B scripts/application-fixed-pair.py verify-offline \
  --overlay /private/host-a/pair/run-id/fixed-pair-execution-overlay.json \
  --overlay-sha256 OVERLAY_RAW_SHA256 \
  --receipt /private/host-a/pair/run-id/fixed-pair-execution-receipt.json \
  --receipt-sha256 EXECUTION_RECEIPT_RAW_SHA256 \
  --host-verification-receipt /private/host-a/evidence/host-verification.json \
  --host-verification-raw-sha256 HOST_RECEIPT_RAW_SHA256 \
  --host-verification-sha256 HOST_RECEIPT_SEMANTIC_SHA256 \
  --evidence-path-map /private/host-a/evidence/identity-path-map.json
```

The overlay has the closed top-level schema
`allocatbelt.application-fixed-pair-execution-overlay.v1`. Its two members
come from the captured controller's original descriptors and runtime bindings.
The executor preserves the shell's ordinal-parity ordering for matched and
allocator-match jobs, and preserves the original A/A member order. Capacity
runs retain the 30-second expectation and the original 5,000-arrival runtime
sentinel. Open-loop runs retain their original rates, arrivals, deadlines,
oracle pins, and minimum observations.

## Launch and receipts

SourceV5, PlanV3, every host manifest pin, all original runtime recipes,
selected binaries, and the selected oracle files are checked before launch.
The selected APP's normal executable is invoked twice in the pinned feedback
reader preflight with only
`--emit-feedback-policy-only --workload W --profile P`. The executor retains
both raw stdout files and actual probe PIDs, requires byte equality, and asks
the captured SourceV5 feedback reader to validate the uncalibrated
construction evidence. Its V4 `capacity_sources` policy remains false for both
directions because this probe supplies no calibrated capacity denominators;
the separate `required_byte_sources` observations retain the workload's real
disk/download sensor requirements and are validated by the reader. It supplies
no calibration quartet.

Normal members use the original APP arguments and a bounded environment
allowlist. Each process runs through its already-open executable descriptor in
its own session with the exact observed affinity, cwd, TMPDIR, and network
namespace. Start callbacks carry the actual positive PID/start ticks, executable
hash/device/inode, requested and observed argv, full observed environment,
cwd, TMPDIR, affinity, and network namespace inode. Terminal callbacks include
the WNOWAIT cleanup record. The supervisor keeps the leader unreaped while it
cleans its session, uses pidfds for session members in other process groups,
and does not signal the numeric process group after reaping the leader. A
failed cleanup stops the pair; the executor does not retry or replace that
member.

Each member retains the controller's exact outer runtime binding beside the
unchanged nested recipe. Process rows and metadata read the recipe digest,
nonce, ceiling, policy, and Control baseline from that original binding; the
recipe is not widened with fields the runtime reader never produced.

Each member receives a private TMPDIR under the output root. The executor
records initial and final mount/storage identity and enforces finite byte and
inode bounds while the APP runs. Stdout, stderr, runtime receipts, sidecars,
probe outputs, and the pair output tree also have finite limits. Direct-launch
elapsed time uses the distinct
`allocatbelt.application-fixed-pair-direct-launch-time.v1` record; it is not a
GNU `time` report and does not supply production CPU or throughput metrics.

`processes.tsv` retains the exact existing `PAIR_PROCESS_HEADER` and original
process descriptors. Runtime validation requires an explicit
`allocatbelt.application-runtime-binding.v2` receipt, the pinned fixed
expectation, final global CPU/memory/disk/network/Task usage of zero, zero live
tenants, and the source-calibrated Control baseline. The captured controller's
pure artifact checks replay the shutdown sidecar, ID trace or mixed-capacity
family report, row accounting, oracle checksums, production-through-drain CPU,
RSS, and nearest-rank quantiles.

The separately pinned
`allocatbelt.application-fixed-pair-execution-receipt.v1` records the actual
APP proofs, cleanup, probe identities, source pins before and after execution,
artifact hashes, and validation results. `execution_scope=qualification` in
the legacy process metadata describes the original workload protocol. The
separate receipt always sets `qualification_eligible=false` and labels a
successful pair `source5_fixed_pair_component_only`.

## Acceptance boundary

The component can provide one immutable fixed-pair artifact set. It does not
dispatch the original schedule through campaign chronology, satisfy phase
prerequisites, enable `run_jobs`, change PlanV3 readiness bits, or establish
native performance. Campaign chronology integration and the four-allocator
native witness remain separate work. A complete qualification still requires
the original exploration, A/A, and confirmation schedule, per-host gates, and
all existing observation minima.

The focused Python unit file is `scripts/test-application-fixed-pair.py`.
This checkout task performs syntax and raw-source audits only; it does not run
the unit suite, APP workloads, Cargo checks, or remote native measurements.
