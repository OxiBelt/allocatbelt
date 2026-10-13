# Application byte-capacity calibration

`scripts/application-byte-capacity.py` converts a separately validated,
bounded native capacity trace into application-level disk and download byte
rates. It consumes committed application bytes and completed operations; the
result says nothing about device bandwidth, network-interface capacity,
allocator speed, or performance qualification.

The request pins a canonical feedback expectation and source manifest by raw
SHA-256. Archived expectation v1 and v2 remain supported with SourceV4. V2
pins construction-only policy output, which the producer checks using the
captured source-pinned feedback reader. A changed probe hash or numeric value
is rejected. The expectation's `host_binding` must name the same
source-manifest path and raw digest.

Expectation v4 uses SourceV5. The producer checks its own regular-file bytes,
mode and size against both the `byte_capacity_producer` qualification-harness
pin and its exact SourceV5 inventory record. It captures the source-pinned
feedback reader, validates the typed expectation and probe projection, and
invokes that reader's full trace verifier. The reader validates SourceV5 with
the captured campaign controller and its inventory-pinned campaign-inputs
module. The producer accepts the validation receipt only when its canonical
bytes exactly equal the full-trace verifier's output; a `validated: true` field
by itself is insufficient. V4 is paired only with SourceV5 and normal
`capacity_calibration`; v3 pressure-soak validation and v1/v2 SourceV4 behavior
retain their separate contracts.

The validation receipt is the feedback reader's exact ten-field
`allocatbelt.application-feedback-validation.v1` object. The helper checks its
caller-pinned expectation and validator digests, identity, trace artifact
hashes, thirty-second production brackets, and intentionally absent final
runtime binding. For V4 it also reruns full feedback-trace validation before
using that receipt. Every disk and download meter bracket must fit inside the
resource-snapshot bracket that contains it and retain the trace's fixed clock
uncertainty. Selected production observations must advance strictly, with no
more than 200 ms between observations. Rates use the actual elapsed meter
time, not an assumed sample cadence.

The context uses
`allocatbelt.application-capacity-context.v1` with stage
`pre_confirmation`. That stage is a caller-provided context assertion; this
producer does not prove campaign chronology. The owning campaign must provide
that independent chronology evidence before using the calibration in later
work. The artifact and receipt always say `qualification_eligible: false`.

Output is one bundle directory containing the TSV and receipt. Both files are
written with mode `0600` in a fresh mode-`0700` sibling directory, verified,
and made visible together using Linux `renameat2(RENAME_NOREPLACE)`. Parent
directories are opened without following symlinks and rechecked before the
atomic rename. Existing final paths and systems without the required atomic
rename support are refused. An interrupted or failed stage remains private
for evidence; no runtime-loadable TSV is published on its own.

`verify_capacity_bundle(request_pin, artifact_pin, receipt_pin)` is a read-only
V4 replay check. It requires a canonical pinned request, reruns the V4
SourceV5 producer, and compares the captured TSV bytes and canonical receipt
bytes exactly. It does not accept a second TSV or receipt interpretation.
