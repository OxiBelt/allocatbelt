# Containers, VMs and sandboxes

allocatbelt treats a restricted container, a VM, Docker in a VM and a nested VM as ordinary environments (single-package directive §8, §17, Phase E). This page says what the allocator needs from them, what it does when an optional facility is refused, and how that is checked. The checks prove behaviour and fallback semantics, not performance.

## What the allocator needs

Correctness needs only the platform contract ([platform.md](platform.md)): Linux, a supported 64-bit CPU at its ISA floor, and the kernel facilities the start-up probe checks (reserve, commit, `MADV_DONTNEED` zeroing). It does **not** need:

- any Linux capability (`CAP_SYS_ADMIN`, `CAP_SYS_NICE`, `CAP_IPC_LOCK`, ...), a privileged container, or `seccomp=unconfined`;
- host PID or network namespaces, network access, or a writable filesystem (it opens no files; diagnostics read nothing but the process's own state);
- io_uring, `SCHED_BATCH`, rseq, NUMA control or CPU affinity.

A deployment such as

```yaml
user: "10001:10001"
cap_drop: [ALL]
read_only: true
security_opt: ["no-new-privileges:true"]
```

runs the allocator unchanged. Optional capabilities that such a sandbox refuses fall back, unless the application `Require`d them ([features.md](features.md#run-time-policy)); then the operation that sets them up fails with a `PolicyError` that names the failed step and errno, as reported (an `EPERM` is not interpreted as seccomp).

| Capability | Refused by | `Auto` / `Prefer` | `Require` | `Disable` |
|---|---|---|---|---|
| io_uring purge ring (feature `io-uring`) | Docker's default seccomp profile (`EPERM`), `kernel.io_uring_disabled`, qemu-user (`ENOSYS`) | `Auto` never calls `io_uring_setup`; `Prefer` tries it and purges with `madvise` | `start_maintenance_thread` fails, no thread runs | never calls it |
| `SCHED_BATCH` (feature `scheduler`) | a seccomp filter; no capability is needed, since it only lowers priority | tried, the default policy is kept if refused | `start_maintenance_thread` fails | not tried |
| rseq `mm_cid` (feature `experimental-rseq`) | musl, qemu-user, seccomp, `glibc.pthread.rseq=0` | per-thread shards (`Auto` does not select it) | `configure` fails | per-thread shards |

To make the ring available in a container, an operator may use a seccomp profile that adds `io_uring_setup`, `io_uring_enter` and `io_uring_register` to Docker's default profile. Nothing depends on it; the allocator never asks for `seccomp=unconfined`.

## Only what the process sees

Inside a VM (or a VM inside a VM), the allocator uses the guest's view and nothing else:

- **ISA:** `cpuid`/`xgetbv` on x86_64, `getauxval(AT_HWCAP*)` on aarch64 and `riscv_hwprobe` on riscv64, all answered for the current process. A host with AVX-512 whose guest exposes only x86-64-v3 gives x86-64-v3. Detection alone selects no kernel (`KernelSet::Baseline`).
- **Kernel:** the guest's kernel, through its own syscalls and probe results.
- **Topology:** no structure is sized by a CPU count. The shard count is a constant, the maintenance thread is a single thread, and `mm_cid` (experimental) is dense over the CPUs the process may use.
- **No host guessing:** nothing reads `/proc/cpuinfo`, `/sys` topology or DMI files, or the hypervisor `cpuid` leaves. `tests/sandbox.rs::no_hidden_host_probes` checks the sources for these.

## How it is checked

`scripts/check-sandbox.sh` (CI job "Sandbox and virtualization" on x86_64 and arm64; needs docker, qemu-user and the musl target). GitHub's hosted runners are VMs, so the container runs there are Docker in a VM.

| Environment (directive §17) | How | Checked |
|---|---|---|
| bare-metal / normal Linux | the ordinary test jobs | every test; optional facilities selected where the runner allows (`tests/policy.rs`, `tests/maintenance.rs`) |
| hardened Docker, unprivileged | every test binary (static, musl) in a container with user 10001, `--cap-drop ALL`, read-only root, no network, `no-new-privileges`, Docker's default seccomp | all tests pass; `hardened_container_needs_no_privilege` checks the process has no capabilities and `NoNewPrivs`, and that the thread and `SCHED_BATCH` work |
| io_uring denied | Docker's default seccomp | `io_uring_denied_falls_back`: `Require` fails with `Unavailable { setup, EPERM }` and leaves no thread; `Prefer` falls back to `madvise` and reports why |
| io_uring allowed | `scripts/seccomp/io-uring-allowed.json` | `io_uring_allowed_is_used`: `Require` gets the ring |
| io_uring not to be touched | `scripts/seccomp/io-uring-kill.json` (kills the process on any io_uring call) | `io_uring_disabled_never_calls_setup`, `io_uring_auto_never_calls_setup` |
| scheduler denied | `scripts/seccomp/no-sched.json` (`sched_setscheduler` fails with `EPERM`) | `scheduler_denied_falls_back`: `Require` fails, `Auto` keeps the default policy and reports why |
| guest exposing less ISA than the host | qemu-user CPU models: x86_64 `Haswell-noTSX` (v3 without AVX-512); aarch64 `cortex-a72` (no SVE), `neoverse-v1` (SVE), `neoverse-n2` (SVE2) | `only_the_visible_isa_is_detected` |
| io_uring not compiled | the feature matrix (`scripts/check-features.sh`) | `Require` fails with `NotCompiled` |
| ring retired after a failed submission | `sys/ring.rs` unit tests | later purges fall back to `madvise` |
| fork | `tests/fork.rs`, `tests/fork_maintenance.rs` | the child has no maintenance thread, keeps the policy, and its own thread tries its capabilities again |

Not automated: full system VMs, Docker inside a nested VM, and vNUMA guests. They need nothing different: the process sees a guest kernel and a guest CPU, which is what the qemu-user and container checks exercise, and the allocator has no NUMA code yet.
