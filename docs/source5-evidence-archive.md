# Source5 per-job evidence archive

The private archive coordinator moves completed Source5 job evidence out of a
host's reserved scratch window. It runs after the job terminal is sealed and
outside every measured application lane. It does not create or imply the later
full-host evidence index or origin receipt, and its ACK does not establish
qualification eligibility.

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
It rechecks the job record from `validation/job-record.json`, derives the
original host-filtered job index and terminal authorization from the pinned
record and plan, then copies only `request.entries` to the accepted Source5 v3
content-addressed `objects/` layout. Every copy is streamed through bounded
buffers, fsynced, independently reopened and rehashed before publication.

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
raw-pinned bounded execution manifest and signer-context artifact; both the
reader and verifier require the signer-context wrapper for that host to match
the bounded execution-manifest v4 `archive_signer_contexts` entry. The context
also binds the local public-keyring and GPGV raw pins, authorized primary
fingerprint and exact budget-derived signature limit. The reader does not
claim to verify the signature. The host then calls
`verify_durable_ack` with the transferred document bytes, original raw-pinned
job record and PlanV3, local stage map, and pinned public keyring/GPGV identity.
The verifier checks the signature's primary fingerprint and the complete
checkpoint/request/manifest/ACK closure without opening coordinator-private
paths. Only the returned verified capability can authorize cleanup, and
cleanup unlinks only the exact no-follow stage-map paths after revalidation.

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
