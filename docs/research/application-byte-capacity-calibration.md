# Application byte-capacity calibration

`scripts/application-byte-capacity.py` converts a separately validated,
bounded native capacity trace into application-level disk and download byte
rates. It consumes committed application bytes and completed operations; the
result says nothing about device bandwidth, network-interface capacity,
allocator speed, or performance qualification.

The request pins a canonical feedback expectation and source manifest by raw
SHA-256. The expectation's `host_binding` must name the same source-manifest
path and raw digest. The helper accepts only the currently supported
`allocatbelt.application-source-manifest.v4` contract. It captures the
`scripts/application-campaign.py` bytes, checks them against the regular-file
record in that manifest, and executes only those captured bytes to run the
controller's complete source-manifest verifier. Future schema labels are
refused until their controller contract is implemented and reviewed.

The validation receipt is the feedback reader's exact ten-field
`allocatbelt.application-feedback-validation.v1` object. The helper checks its
caller-pinned expectation and validator digests, identity, trace artifact
hashes, thirty-second production brackets, and intentionally absent final
runtime binding. Every disk and download meter bracket must fit inside the
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
