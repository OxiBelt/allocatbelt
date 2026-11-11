# Application runtime numeric snapshots

The campaign controller retains parsed runtime-binding values in numeric
snapshots so fixed-policy predecessor checks can replay the observed bounds
and cleanup state. The snapshot is derived from the captured runtime receipt;
it is not a replacement for validation of that receipt or its process identity.

`allocatbelt.application-runtime-numeric-snapshot.v2` retains the final global
CPU, managed-memory, disk-byte, network-byte and Task usage under
`after_release.global_used_application`, in addition to the fixed Control
baseline and live-tenant count. Validation requires all five usage values to
be unsigned integers equal to zero. A partial set of final usage fields is
rejected during snapshot construction.

Historical receipts without these final usage fields still produce v1
snapshots. Their legacy validation remains available. SourceV5 fixed-policy
predecessor validation requires v2, preventing a downgrade that would discard
the final application usage evidence. This requirement does not enable
SourceV5 execution or establish performance qualification.
