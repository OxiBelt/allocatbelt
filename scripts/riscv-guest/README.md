# Full-system RISC-V correctness check

`python3 -B scripts/riscv-guest/check.py build`, `payload`, and `boot` build
and run two offline QEMU TCG guests. Rust test binaries are host-built with
Rust 1.99.0 and the generated RV64GC/LP64D musl linker. The guests never run
Cargo. Each boot has four vCPUs, 2 GiB RAM and a 300-second deadline; these
are correctness checks, never performance evidence.
When validating a source archive without `.git`, set
`ALLOCATBELT_GUEST_SOURCE_REVISION` to its full commit hash; source files and
the actual executable contents are independently hashed into the payload
identity, including uncommitted changes.

The external configuration derives from Buildroot 2026.08's
`qemu_riscv64_virt_defconfig`, replacing Linux 6.18.7 with the supported
Linux 7.0 floor and ext2/DHCP with a static minimal initramfs. OpenSBI 1.6
comes from that pinned recipe. QEMU and all other package versions/hashes
come from the verified Buildroot source archive. `assets.json`, the external
configuration, package hashes and current host build-tool identity define
the cache key. Restoration verifies the cached images and cross tools
against their complete file/symlink manifest; there is no partial-key restore.
The absolute checkout location is part of the key because Buildroot's host
toolchain must not be relocated. Per-commit tests are rebuilt and overlaid on
the cached base initramfs, not cached as guest assets.

The no-V boot checks platform, region, runtime and baseline ISA dispatch.
The V-enabled boot checks allowed dispatch, fresh-exec disabled dispatch,
and real Linux thread-local vector control. A system-wide default changes
the policy of new execs only; the library never enables V on behalf of a
caller. QEMU-user still provides the wider kernel/VLEN equivalence matrix.

The guest emits ordered begin/pass records and exactly one completion bound
to source revision, configuration and executable hashes. The host rejects
missing, duplicate, wrong-identity, failed and skipped results, kernel panics,
nonzero QEMU exits and timeouts. A zero QEMU exit alone is not a passing check.

Upstream sources: [Buildroot release](https://buildroot.org/downloads/),
[Linux archive hashes](https://cdn.kernel.org/pub/linux/kernel/v7.x/sha256sums.asc),
[Linux vector policy](https://docs.kernel.org/arch/riscv/vector.html), and
[Rust musl target](https://doc.rust-lang.org/rustc/platform-support/riscv64gc-unknown-linux-musl.html).
