# Source5 per-job evidence archive

The private archive coordinator moves completed Source5 job evidence out of a
host's reserved scratch window. It runs after the job terminal is sealed and
outside every measured application lane. It does not create or imply the later
full-host evidence index or origin receipt, and its ACK does not establish
qualification eligibility.

## Preparatory exploration profile

The preparatory 360-job profile has separate execution, width and host-budget
schemas: `allocatbelt.application-source5-preparatory-exploration-execution.v1`,
`allocatbelt.application-source5-preparatory-journal-width-contract.v1`, and
`allocatbelt.application-source5-preparatory-exploration-budget.v1`. Archive and
packet consumers keep those exact fields and schemas separate from final
host-budget v2/v3; a preparatory document cannot enter the final-budget
readiness path. The selected SourceV5 must type-pin
`scripts/application-source5-preparatory-budget.py` and
`scripts/application-source5-evidence-catalogue.py`, as well as the exact
Source-pinned campaign and input-preparation modules used to derive the pilot
row. The selected execution module map must pin each exact byte sequence.
Consumers verify raw Source, Plan, execution-manifest, width and original Spec
bytes, derive the shared execution basis, invoke the selected prep validator,
and use the selected typed evidence-budget module plus the selected
owner-catalogue `OWNER_PATHS` map, with a byte-only catalogue-chunk reader.
Root-local validation resolves only the exact dependency and catalogue maps; it
does not open host-origin paths.

The preparatory Root dependency map has exactly six ordered rows:
Source, Plan, host budget, execution manifest, width contract and original
Spec. Its Spec copy is pinned by both `budget.original_pins.initial_spec` and
the execution manifest's `original_inputs.spec` wrapper, then checked against
the selected Spec semantics and `Plan.spec_sha256` by the Source-selected prep
validator. The reader uses the existing 16 MiB Spec limit and requires the
single global `spec_v3` catalogue row to match the captured Spec bytes exactly.
The Spec remains a separate cached validation dependency: it is not added to
each job request, packet, or reclaimable object list. The final
width-bound v4 map remains exactly five rows, and the legacy map remains
exactly three.

The profile admits only the original 360 `exploration` jobs. Its journal
reserve counts 2,160 original APP callback events and one separate capacity
registration event. Its signed per-job packet limits come from the prep
`archive_transport` and typed path catalogue. This reserves finite packet,
ACK, stage and catalogued-root bounds for that prep sequence while retaining
`full_horizon_execution_ready`, `component_gate_ready` and
`qualification_eligible` as false. The prep budget does not remove other
original Plan phases or claim a full campaign. Its canonical body and
self-digest use a separate 128 MiB ceiling; final v2/v3 budgets retain the
32 MiB metadata ceiling.

## Host request and packet

The host writes a canonical
`allocatbelt.application-source5-evidence-checkpoint-request.v1` request at
the exact prospective catalogue path. Its `entries` are the sorted, unique,
raw- and semantic-pinned per-job output and owner-receipt rows that may be
reclaimed after verification. The original raw-pinned job-record path is not an
entry: that record remains indexed and always local. The request still binds
its `{path, raw_sha256}` as `job_record_pin`, plus the original PlanV3 context,
authorization and terminal projection, predecessor ACK, owner receipts, and
receipt-derived empty TMP proofs.
Bounded fixed-pair jobs add their strict `fixed_pair_host_receipt` as an
owner-receipt object. The request binds its record pin to the exact overlay
and execution-receipt rows and checks the fixed receipt's self digest, status,
run ID, raw pins, readiness flags, and nested host-identity digest. The private
coordinator and host reclaim verifier reread the exact staged overlay and
compare its observed-host facts and output-mount identity before an ACK can be
signed or local bytes reclaimed. Restart-only ACK readers validate the signed
row closure without reopening already-reclaimed payloads.
When a successful job declares ProbeV2 `opaque_trace` TMP roots, it uses the
additive `allocatbelt.application-source5-evidence-checkpoint-request.v2`
schema. Its only added top-level field is `tree_inventories`, with one row for
each exact per-job tree catalogue declaration, including empty trees. Each row
binds the original job digest, exact root and role, capture-receipt pin,
inventory-object pin and digest, descendant count/bytes, and the sorted typed
inventory entries `{path, kind, uid, mode, size, raw_sha256}`. File descendants
must match one exact `opaque_trace` request entry; directory rows carry no
payload. The canonical inventory sidecar and successful ProbeV2 capture receipt
are both ordinary pinned request objects, and the receipt must bind that exact
inventory and the same initial/final TMP root identity and final counters.
ProbeV2 v1 inventories admit only regular files and directories, so their tree
files and metadata objects must be no-follow regular files. Tree roots are
disjoint and catalogue-matched exactly; an arbitrary path prefix does not
authorize descendants. Legacy request/checkpoint v1 field sets are unchanged.

The v2 request and matching final checkpoint have a separate 128 MiB parser
ceiling so their duplicated typed inventory rows can be represented. The
32 MiB ceiling remains in force for v1 request/checkpoint documents and
ordinary metadata. The source-pinned host budget must fit the exact canonical v2 bodies
under both this parser ceiling and its per-job path/packet reservations.
Before transfer and again at the private coordinator, every object path and
role is matched to its raw-pinned path-catalogue row and per-file ceiling; the
reclaimable rows must also fit the pinned live-window byte/inode totals. The
host verifies the signed original request and its exact local payload bytes
before reclamation.

`application-source5-evidence-transfer-packet.py export-transfer` writes one
regular-file tar packet with these members in order:

1. `checkpoint-request.json`;
2. `validation/job-record.json`, whose bytes must match the request's raw pin;
3. one regular, content-addressed packet member for each reclaimable request
   entry. Literal symlink sources are represented by regular members containing
   the exact `readlink` bytes.

For v2 typed trees, only the inventory-listed regular-file descendants become
packet objects. Directories are represented by their typed inventory rows and
the exact budgeted tree-root inode count; they are not wildcard catalogue
entries or separate tar members.

The job record is a validation member only. It is excluded from the request
entry set, object manifest, host stage map and reclamation capability. The
exporter checks its `source5_job_record` catalogue row and byte ceiling before
writing. The complete packet, including that member, tar framing and metadata,
must fit the pinned transfer-packet byte/inode reservation.

The importer validates the complete packet closure before its first stage
write. Its own bounded USTAR/PAX parser permits only a size-only PAX record and
checks the extension length before reading its body; it does not use a general
tar extractor. It rejects extra members, links, noncanonical request data,
unmatched names, raw-hash mismatches and over-budget packets. The imported job
record is staged separately at `validation/job-record.json`; the returned
`staged_files` map contains only reclaimable request entries.

The host publishes an
`allocatbelt.application-source5-archive-transfer-offer.v1` pin after packet
fsync and independent reopen. It names the request, packet and one exclusive
ACK-bundle receiver, all at their exact catalogue paths and caps.
The host budget also reserves `<receiver>.incoming` as role
`source5_ack_bundle_incoming`, in the same directory and with the same
one-file cap as the final receiver.

## Coordinator commit and ACK

The private coordinator receives the offer, packet and original pinned PlanV3.
It reads the Source manifest, PlanV3 and host budget through a canonical
`allocatbelt.application-source5-dependency-local-map.v1` that pairs each
original pin with a distinct Root-local captured path. It checks the Plan and
budget bytes it uses against those copies and streams the Source manifest
against its raw pin. The budget's chunk descriptors name host origin paths; a
separate canonical catalogue map pairs every exact origin path to a Root-local
copied chunk under the private cache root. The coordinator verifies the map
closure and each local chunk's raw hash against the descriptor before using
its rows. It never opens a host origin path as if it were local storage.

The historic 13-field host-budget v2 shape and three-row dependency map remain
closed and unchanged for legacy budgets, including signer-only execution-v4
fixtures. The exact 13-field legacy and 15-field width-bound shapes both require
the v2 schema; the exact 16-field shape requires the v3 schema and its fixed
`admission_profile`. Crossed schema/field-set combinations are rejected before
legacy handling or readiness checks. A width-bound R6 v4 budget uses the exact
15-field extension `execution_manifest_schema` plus
`journal_width_contract_pin`. It requires a five-row dependency map in the fixed
Source, Plan, budget, execution-manifest and journal-width-contract order. The
coordinator verifies all five origin
pins against the request/budget, reads only the Root-local execution-manifest
and width-contract copies, and checks that the v4 manifest's selected-host
`journal_width_contracts` wrapper, the contract self digest and the budget pin
all identify the same bytes. A legacy budget does not acquire a null width pin
or a synthetic width row.
It rechecks the job record from `validation/job-record.json`, derives the
original host-filtered job index and terminal authorization from the pinned
record and plan, then copies only `request.entries` to the accepted Source5 v3
content-addressed `objects/` layout. Every copy is streamed through bounded
buffers, fsynced, independently reopened and rehashed before publication.

The admitted ready-budget v3 consumer accepts only the exact 16-field
`allocatbelt.application-source5-host-evidence-budget.v3` body: the prior
width-bound v2 fields plus `admission_profile`, fixed to
`source5_width_v4_captured_replay_v1`. It still requires the v4 execution
manifest, exact journal-width contract, and the full Source/Plan/budget/
execution/width dependency order. The coordinator verifies the selected
SourceV5 raw and semantic pins, its typed inventory row and the matching
execution-manifest module pin for
`scripts/application-source5-evidence-budget.py`; it stable-reads and compiles
those exact local module bytes before calling that module's
`validate_host_evidence_budget_v3` with an internally constructed reader for
the captured catalogue chunks. Readiness flags alone never admit v3. This
budget profile can set `budget_complete` and `execution_ready` true while
`component_gate_ready` and `qualification_eligible` remain false; it does not
report a completed campaign or a qualified workload.
The consumer does not promote a refused or false-ready v2 budget into v3; an
execution run still requires its separate Source5 prepared-input admission.
The current v3 budget producer still refuses before catalogue/storage writes
until the prepared-exploration bridge verifier is integrated; this reader
change does not remove that fail-closed condition.

Root-side `import-transfer` and `build-ack-bundle` require both the ordered
five-row dependency map and the exact catalogue-chunk map for v3. Their
validator callbacks read only distinct mode-0600 files below the provided
private cache roots and recheck every chunk's raw pin; they do not open the
host origin paths. Restart-safe ACK readers accept the same captured maps as
additive keyword inputs. Host-side export and ACK verification instead verify
the raw-pinned SourceV5 at its host-local input path. Legacy 13-field and
width-bound 15-field false-ready v2 documents retain their old closed shapes
and do not acquire v3 fields or readiness.

Before signing, the coordinator also writes the raw job record to its private
`source5/validation/job-records/<phase>/<ordinal>-<job-sha>.json` path, fsyncs
it and independently reopens it. The final checkpoint binds the original host
record pin and the exact request plus object-manifest pin. The signed ACK's
`durable_commit.job_record_validation` records the private validation path,
original origin path, raw and semantic digests, and byte count. This record is
durably retained and never enters the reclaimable object closure.

ACK signatures are detached GPG signatures over canonical ACK bytes. The
private signing context supplies the authorized fingerprint and the
source-pinned campaign signature quota. Signing uses `--no-options`, no armor,
SHA-256 and the exact primary fingerprint; an over-quota signature prevents
ACK publication. Private key material stays on the coordinator.

`build-ack-bundle` emits one bounded regular-file tar envelope with exactly
`checkpoint.json`, `object-manifest.json`, `ack.json` and `ack.sig`. The host
reader verifies its packet pin, exact four-member closure and campaign bundle
cap before returning the raw documents and their pins. The host supplies the
raw-pinned bounded execution manifest and signer-context artifact. For the
width-bound R6 budget shape, it also supplies the captured raw journal-width
contract; the reader checks its raw/self digest and original Plan/Source pins
against the budget and v4 manifest's host `journal_width_contracts` wrapper.
For the historic 13-field budget, it preserves the signer-only v4 path without
adding a width pin. Both the reader and verifier require the signer-context
wrapper for that host to match the bounded execution-manifest v4
`archive_signer_contexts` entry. The context
also binds the local public-keyring and GPGV raw pins, authorized primary
fingerprint and exact budget-derived signature limit. The reader does not
claim to verify the signature. The host then calls
`verify_durable_ack` with the transferred document bytes, original raw-pinned
job record and PlanV3, local stage map, and pinned public keyring/GPGV identity.
The verifier checks the signature's primary fingerprint and the complete
checkpoint/request/manifest/ACK closure without opening coordinator-private
paths. Only the returned verified capability can authorize cleanup, and
cleanup unlinks only the exact no-follow stage-map paths after revalidation.
For v2 ProbeV2 trees, reclamation first re-enumerates each exact root with
no-follow directory traversal and compares every file and directory to the
receipt-pinned inventory. It also rechecks the owner-return root device/inode
and local identities before deleting any payload. After the acknowledged file
objects are unlinked, it removes only those listed empty directories and the
declared TMP root, bottom-up through anchored no-follow directory descriptors.
An extra entry, changed identity, symlink, or nonempty directory stops cleanup;
there is no recursive prefix-based deletion.

The SFTP bridge uploads the coordinator bundle only to the catalogued
`.incoming` path. After transfer completion it invokes `publish-ack` with the
coordinator's raw hash/byte-count pin. The publisher checks the exact offer,
budget, incoming file identity and full raw digest, then uses an atomic
no-replace rename, fsyncs the containing directory and independently reopens
the final receiver. It takes no phase lock; the waiting controller holds that
lock and observes only the completed final path. An invalid or partial upload
cannot replace an existing final receiver.

The publisher accepts each plain pin through either its existing pin-file
option or the mutually exclusive `--budget-pin-json`, `--offer-pin-json` and
`--bundle-pin-json` options. Inline pins use bounded canonical JSON without
the final newline and undergo the same pin and publication checks. The bridge
can therefore pass pins without creating extra host metadata files. The bundle
pin names the exact offered host receiver, with the coordinator's raw digest
and byte count; it does not name the coordinator's private bundle path.

The request, offer, append-only host journals, source records, final ACK
components and host index remain local/indexed according to the host evidence
budget. Missing or invalid ACK material stops the next job and leaves the
original evidence in place.

After restart, `verify_signed_ack_for_predecessor` can authenticate a persisted
checkpoint, manifest, ACK and detached signature against the raw-pinned job
record and original PlanV3. It requires the exact ACK pin and checks that the
expected run ID is the PlanV3 predecessor of the intended successor. This
metadata-only result has a distinct schema and `may_reclaim: false`; it never
reopens reclaimed object payloads and cannot be passed to the reclamation API.

For restart-safe archive readback of any successful original job,
`verify_signed_ack_for_read` verifies the same raw-pinned request, checkpoint,
job record, PlanV3, object manifest, ACK, signature, signer context, execution
manifest and optional width contract. It requires the exact ACK pin and
original run ID but does not require a successor edge. Its distinct result
sets `may_read: true` and `may_reclaim: false`, and returns the signed object
manifest pin. It performs no stage-map or payload access and does not grant a
reclamation capability.

## H15 host readback budget

The H15 width-bound v4 budget catalogs exactly seven reusable readback roles:
the always-local `source5_archive_read_control_ledger`, plus request,
response/final, response/incoming, bundle/final, bundle/incoming, and stage
slots under the host's archive-readback scratch root. The deterministic slot
paths and path-keyed storage reservation are checked against the budget's
canonical catalogue chunks. Response and bundle final/incoming pairs must have
the same byte, inode, owner, and storage-root bounds.

The active readback window reserves one request, one response alternative, one
bundle alternative, and the stage tree. The control ledger is persistent and
always local; the incoming alternatives are not added to the active window at
the same time as their final paths. Request and response files are capped at
16 MiB, bundle and stage payloads at the archive's 2^48-byte transport limit,
stage files at 2^40 bytes, and the stage tree at 262,144 object files plus its
root directory. Persistent, active-window, live-root, and caller storage
reservations must all cover the resulting byte and inode bounds.

Width-bound v4 adds one global `source5_analyzer_spool` tree at
`<scratch>/<campaign>/<host>/analyzer-spool`. The source5 controller derives
its exact byte, per-file and inode caps from the original open-loop `.ids.tsv`
catalogue rows and the pinned analyzer serialization contract. It is not a
per-job archive object and is never exported. Its cap is added to the active
readback window because the staged job bytes, group frame, compact trace
spools, raw trace snapshot and analyzer response can coexist. The controller
requires this private tree to be empty before and after numeric replay.

Legacy 13-field host-budget v2 documents and signer-only execution-v4 fixtures
retain their original shape and do not acquire H15 roles. H15 readback requires
the exact 15-field width-bound v4 budget; its budget remains non-ready and
keeps the archive-ACK/reclaim blocker until the separate activation work is
complete.
