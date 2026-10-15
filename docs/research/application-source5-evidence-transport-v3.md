# Source5 v3 evidence transport contract

This additive transport keeps the v1/v2 inline interfaces unchanged. A bounded
prepared campaign selects host-journal request v3, evidence-index v3, and
captured-evidence store v2 only after the v2 host budget and its complete path
catalogue have been pinned.

The index root uses schema
`allocatbelt.application-source5-journal-evidence-index.v3`. It binds campaign,
host, source/input/output roots, the exact raw/semantic host-budget pin, total
row count, and a content-addressed manifest frontier. Sorted canonical JSONL
data chunks hold typed rows with a raw digest, optional semantic digest, byte
count, and the producer's maximum file bytes. Content-addressed manifest pages
hold bounded fanout descriptors and path ranges. The root, every page, and every
data chunk are separately pinned; validation checks the complete page tree,
all raw/semantic digests, global path order, row limits, and the budget's exact
producer catalogue before returning a lazy path lookup.

The captured store uses schema
`allocatbelt.application-source5-captured-evidence.v2`. It copies each selected
regular-file payload into an immutable mode-0600 object named from the original
path and raw digest. Literal source symlink targets are captured as bytes after
checking the link itself. Sorted metadata JSONL chunks bind role, host, origin
path, local object path, raw/semantic digests, actual byte count, and owner
ceiling. The store root binds the host budget, index, and origin receipt pins;
opening the store verifies every metadata row, object path, object digest,
count, and byte total before exposing bounded lazy lookup.

The host budget v2's path-catalogue chunks are immutable, sorted, and
content-addressed. Fixed file declarations are exact paths; dynamic TMP and
owner output roots carry separate aggregate byte, per-file byte, and inode
ceilings. Optional outputs may be absent when an original job failed. Every
captured path must still have exactly one declaration, and every pinned input
must be present with its exact raw and semantic identity. A missing declared
output does not rewrite the original plan, job ID, or ordinal.

The index writer externally sorts canonical rows in bounded 256-row runs and
merges at most 64 runs per pass in the caller-reserved scratch domain. Data
chunks and content-addressed fanout pages are streamed; readers authenticate a
stable no-follow file handle and parse the same verified bytes. Chunk, page,
fanout, row-count, byte-count, and tree-depth inputs have finite checked bounds.
The captured-store writer checks each declared object and metadata row against
remaining entry, payload, metadata, and root-manifest ceilings before writing
it. Store metadata is chunked, object shards are private no-follow directories,
and lazy reads recheck canonical rows and object bytes against their pins.

The host budget carries the catalogue-derived maximum index rows/bytes, index
chunk/page counts, captured payload and metadata ceilings, journal event/byte
ceilings, and caller-reserved bytes and inodes. The v2 reader rejects an
unsupported metadata-root size from that budget before object copying begins.
Legacy v1's 800,000-row and 256 MiB index caps remain scoped to the legacy
schema; v2 row counts are bounded by the exact host catalogue and u64 encoding.

Transport completeness does not make a component gate or campaign
qualification-ready. Component readers must first verify the v3 request, the
host budget v2, the full index/catalogue/store closure, and original journal
ancestry; each component reader then checks its own strict raw and semantic
pins. Campaign and qualification outputs remain false until their separate
gates pass.
