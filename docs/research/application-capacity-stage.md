# Application capacity calibration stage

`scripts/application-capacity-stage.py` runs the frozen SourceV5 capacity
templates for one host. It selects the host's 15 templates from the plan's
original array without sorting them, validates each input file as canonical
JSON, checks the live host context, and uses the pinned application binary
directly. The stage does not invoke an external pressure driver or provide a
capacity artifact to the application.

The stage itself must be one regular file in the SourceV5 typed source
inventory. It captures the SourceV5 campaign controller, campaign-inputs
module, feedback reader, and byte-capacity producer from their exact inventory
pins. It follows the pinned v1 nonce-instantiation rule directly. The existing
eight-key `qualification_harness` shape stays unchanged; the stage's own pin
comes from its regular inventory record. The captured controller verifies the
complete spec and plan. The selected host's SourceV5 verifier also rebuilds
the full live source inventory and checks its frozen artifacts.

Each request template has exactly this shape:

```json
{"minimum_interval_seconds":10,"schema":"allocatbelt.application-capacity-request-template.v1"}
```

The interval remains within the byte-capacity producer's 10–30 second range.
The stage owns the calibration identity, process ID, source-manifest pin,
expectation, validation receipt, trace directory, and final request. It creates
the request only after the captured feedback reader has accepted the complete
trace.

Each context template has exactly `schema`, `storage`, and `network` fields.
`storage` is `null` for CPU and memory contexts. Disk and mixed contexts use a
typed storage record with `scope: "application_file_io"`, a normalized
absolute `root_path` outside SourceV5, the observed `filesystem_type`, the
observed `device_major_minor`, and a positive `minimum_free_bytes`. The stage
creates a fresh TMPDIR below that root and checks the filesystem, device, and
free-space floor before launch. It records the observed values in the
instantiated context.

`network` is `null` outside HTTP and mixed contexts. HTTP and mixed contexts
use exactly `scope: "ipv4_loopback_application_bytes"`, `interface: "lo"`,
`address: "127.0.0.1"`, and the current positive network namespace inode. The
stage checks the live namespace and loopback interface. This context describes
application bytes on loopback and makes no physical-NIC capacity claim.

The separate observed-host pin uses
`allocatbelt.application-capacity-host-context.v1`. It binds the host ID,
boot-ID digest, complete frozen controls and their fingerprint, live kernel
release, live CPU model, inherited CPU affinity, and network namespace inode.
The stage requires the observed controls to equal the spec host contract and
checks the live boot ID, kernel, CPU model, affinity, and namespace before
launch. It does not apply a new CPU affinity mask.

Every job first runs the actual application's
`--emit-feedback-policy-only --workload W --profile P` command. The captured
feedback reader validates the numeric SourceV5 projection before the capacity
process starts. The capacity process uses the frozen workload, profile,
allocator, executor, 30-second capacity horizon, and all original finite
campaign deadlines. Its environment sets
`ALLOCATBELT_APP_PRESSURE_QUALIFICATION=false`, uses a fresh trace directory
and TMPDIR, and contains no capacity artifact path or hash.

The private ledger is canonical JSONL with the controller's previous-record
and record-digest envelope. It binds sequence, monotonic time, boot ID,
campaign/spec/plan/host/source pins, schedule digest, and template identity.
The stage fsyncs `probe_dispatch` or `application_dispatch` before each direct
`Popen`, then fsyncs the observed application PID, start ticks, executable
hash, nonce, cwd, inherited affinity, and environment immediately after the
application starts. Each job records the exact transitions
`probe_dispatch`, `probe_completed`, `probe_verified`, `application_dispatch`,
`application_bound`, `application_exited`, `trace_captured`,
`feedback_verified`, and `bundle_verified`.

Replay requires the dispatch, observed application binding, and validated
producer context to agree on the TMPDIR. Disk and mixed TMPDIRs must be fresh
children of the frozen storage root; other workloads use the fresh stage-local
directory. The verifier also checks each event's exact detail fields, every
duplicated source/probe/validation/bundle pin, and completed-process signal and
elapsed-time claims against the frozen deadlines.

After the captured feedback reader accepts the complete trace, the captured
byte-capacity producer atomically publishes the TSV and receipt in a fresh
bundle directory. The stage then calls its read-only
`verify_capacity_bundle(request_pin, artifact_pin, receipt_pin)` replay. The
completion verifier reconstructs the original schedule and every event
transition, replays every full feedback trace and capacity bundle, and checks
that the canonical overlay matches those results. A changed source, template,
trace, receipt, artifact, ledger chain, ordering, or completion entry is
rejected.

Run and verify one host stage with pinned absolute input paths:

```sh
python3 -B scripts/application-capacity-stage.py run \
  --plan /inputs/campaign-plan.json --plan-sha256 PLAN_RAW_SHA256 \
  --spec /inputs/campaign-spec.json --spec-sha256 SPEC_RAW_SHA256 \
  --source-root /worktrees/source-v5 --input-root /inputs \
  --host-id HOST_ID \
  --observed-host /inputs/observed-host.json \
  --observed-host-sha256 HOST_CONTEXT_RAW_SHA256 \
  --output-root /private/campaign-output

python3 -B scripts/application-capacity-stage.py verify \
  --plan /inputs/campaign-plan.json --plan-sha256 PLAN_RAW_SHA256 \
  --spec /inputs/campaign-spec.json --spec-sha256 SPEC_RAW_SHA256 \
  --source-root /worktrees/source-v5 --input-root /inputs \
  --host-id HOST_ID \
  --observed-host /inputs/observed-host.json \
  --observed-host-sha256 HOST_CONTEXT_RAW_SHA256 \
  --output-root /private/campaign-output \
  --completion /private/campaign-output/CAMPAIGN/capacity/HOST_ID/capacity-stage-completion.json \
  --completion-sha256 COMPLETION_RAW_SHA256
```

The output path is
`OUTPUT_ROOT/CAMPAIGN/capacity/HOST_ID`. The stage refuses an existing host
directory and leaves a failed or interrupted ledger without a successful
completion overlay. A completed `allocatbelt.application-capacity-stage-completion.v1`
overlay contains exactly 15 entries, is complete, and remains
`qualification_eligible: false`. Its `controller_chronology_proven` field is
`false`: the capacity context's `pre_confirmation` label is not chronology
evidence. Later controller work must check the sealed ledger head and overlay
under its confirmation-dispatch lock before using this stage as a prerequisite.
