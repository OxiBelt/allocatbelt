#!/usr/bin/env python3
"""CLI and full-replay witnesses for one bounded SourceV5 capacity stage."""
from __future__ import annotations

import copy
import hashlib
import io
import importlib.machinery
import importlib.util
import json
import os
import platform
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import types
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch


SCRIPT_DIR = Path(__file__).resolve().parent
SOURCE_ROOT = SCRIPT_DIR.parent
STAGE_PATH = SCRIPT_DIR / "application-capacity-stage.py"


def load_script(path: Path, name: str):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


stage = load_script(STAGE_PATH, "application_capacity_stage_test_target")
input_fixtures = load_script(
    SCRIPT_DIR / "test-application-campaign-inputs.py",
    "application_capacity_stage_input_fixtures",
)
feedback_fixtures = load_script(
    SCRIPT_DIR / "test-application-feedback-readback.py",
    "application_capacity_stage_feedback_fixtures",
)
capacity_producer = load_script(
    SCRIPT_DIR / "application-byte-capacity.py",
    "application_capacity_stage_capacity_producer",
)
fixed_pair_owner = load_script(
    SCRIPT_DIR / "application-fixed-pair.py",
    "application_capacity_stage_fixed_pair_owner",
)
process_identity_helper = load_script(
    SCRIPT_DIR / "application-soak-readback.py",
    "application_capacity_stage_process_identity_helper",
)


class SourceInventorySymlinkTests(unittest.TestCase):
    def test_typed_source_symlink_is_literal_bounded_and_direct(self) -> None:
        target_raw = b"license text\n"
        records = {
            "LICENSE": {
                "path": "LICENSE", "kind": "file", "mode": "100644",
                "sha256": sha(target_raw), "size": len(target_raw),
            },
            "crates/allocatbelt/LICENSE": {
                "path": "crates/allocatbelt/LICENSE", "kind": "symlink",
                "mode": "120000", "target": "../../LICENSE",
                "sha256": sha(b"../../LICENSE"), "size": len(b"../../LICENSE"),
            },
        }
        link_record = records["crates/allocatbelt/LICENSE"]
        self.assertEqual(stage._source_inventory_symlink_target(
            link_record, records, "fixture SourceInventory link",
        ), ("LICENSE", b"../../LICENSE"))

        with tempfile.TemporaryDirectory(prefix="source-inventory-symlink-") as root_text:
            root = Path(root_text)
            nested = root / "crates" / "allocatbelt"
            nested.mkdir(parents=True)
            (root / "LICENSE").write_bytes(target_raw)
            (nested / "LICENSE").symlink_to("../../LICENSE")
            fingerprint = stage._offline_local_fingerprint(
                nested / "LICENSE", "fixture SourceInventory link",
            )
            self.assertEqual(fingerprint["kind"], "symlink")
            self.assertEqual(fingerprint["target"], "../../LICENSE")
            self.assertEqual(fingerprint["size"], len(b"../../LICENSE"))

        invalid_records = []
        escaping = dict(link_record, target="../../../LICENSE")
        escaping["size"] = len(escaping["target"].encode("utf-8"))
        escaping["sha256"] = sha(escaping["target"].encode("utf-8"))
        invalid_records.append((escaping, records, "escapes SourceRoot"))

        chained = dict(link_record, target="LICENSE")
        chained["size"] = len(b"LICENSE")
        chained["sha256"] = sha(b"LICENSE")
        invalid_records.append((chained, records, "direct regular Source.files member"))

        missing = dict(link_record, target="../../NOT_PRESENT")
        missing["size"] = len(missing["target"].encode("utf-8"))
        missing["sha256"] = sha(missing["target"].encode("utf-8"))
        invalid_records.append((missing, records, "direct regular Source.files member"))

        wrong_hash = dict(link_record, sha256=sha(b"not the link target"))
        self.assertNotEqual(wrong_hash["sha256"], link_record["sha256"])
        invalid_records.append((wrong_hash, records, "literal target hash"))

        wrong_mode = dict(link_record, mode="100644")
        invalid_records.append((wrong_mode, records, "typed terminal symlink"))

        too_long = dict(link_record, target="x" * (stage.MAX_SOURCE_SYMLINK_BYTES + 1))
        too_long["size"] = len(too_long["target"].encode("utf-8"))
        too_long["sha256"] = sha(too_long["target"].encode("utf-8"))
        invalid_records.append((too_long, records, "bounded text"))

        for candidate, candidate_records, expected in invalid_records:
            with self.subTest(target=candidate["target"], expected=expected):
                with self.assertRaisesRegex(stage.CapacityStageError, expected):
                    stage._source_inventory_symlink_target(
                        candidate, candidate_records,
                        "fixture SourceInventory link",
                    )


FAKE_CHILD_C = r"""
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PROBE_ROOT
#error PROBE_ROOT is required
#endif
#ifndef DRIVER_PATH
#error DRIVER_PATH is required
#endif
#ifndef SOURCE_PATH
#error SOURCE_PATH is required
#endif
#ifndef FAIL_FLAG
#error FAIL_FLAG is required
#endif
#ifndef HANG_FLAG
#error HANG_FLAG is required
#endif

static const char *argument_value(int count, char **values, const char *key) {
  for (int index = 1; index + 1 < count; ++index) {
    if (strcmp(values[index], key) == 0) return values[index + 1];
  }
  return NULL;
}

static int copy_file_to_stdout(const char *path) {
  int file = open(path, O_RDONLY | O_CLOEXEC);
  if (file < 0) return 90;
  char buffer[8192];
  ssize_t count;
  while ((count = read(file, buffer, sizeof(buffer))) > 0) {
    ssize_t offset = 0;
    while (offset < count) {
      ssize_t written = write(STDOUT_FILENO, buffer + offset, (size_t)(count - offset));
      if (written <= 0) { close(file); return 91; }
      offset += written;
    }
  }
  close(file);
  return count == 0 ? 0 : 92;
}

int main(int count, char **values) {
  if (count > 1 && strcmp(values[1], "--test-wait") == 0) {
    for (;;) pause();
  }
  if (count > 1 && strcmp(values[1], "--test-escaped-descendant") == 0) {
    pid_t child = fork();
    if (child < 0) return 102;
    if (child == 0) {
      if (setpgid(0, 0) != 0) _exit(103);
      const char *tmpdir = getenv("TMPDIR");
      if (tmpdir == NULL) _exit(104);
      char path[8192];
      int size = snprintf(path, sizeof(path), "%s/owner-descendant.pid", tmpdir);
      if (size <= 0 || (size_t)size >= sizeof(path)) _exit(105);
      int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
      if (fd < 0) _exit(106);
      char pid_text[64];
      int pid_size = snprintf(pid_text, sizeof(pid_text), "%ld\n", (long)getpid());
      if (pid_size <= 0 || write(fd, pid_text, (size_t)pid_size) != pid_size) _exit(107);
      close(fd);
      for (;;) pause();
    }
    const char *tmpdir = getenv("TMPDIR");
    if (tmpdir == NULL) return 108;
    char path[8192];
    int size = snprintf(path, sizeof(path), "%s/owner-descendant.pid", tmpdir);
    if (size <= 0 || (size_t)size >= sizeof(path)) return 109;
    for (int attempt = 0; attempt < 1000 && access(path, F_OK) != 0; ++attempt) usleep(1000);
    return access(path, F_OK) == 0 ? 0 : 110;
  }
  if (count > 1 && strcmp(values[1], "--test-churn") == 0) {
    const char *tmpdir = getenv("TMPDIR");
    if (tmpdir == NULL) return 111;
    char path[8192];
    char payload[4096];
    memset(payload, 'c', sizeof(payload));
    for (int index = 0; index < 12; ++index) {
      int size = snprintf(path, sizeof(path), "%s/churn-%d", tmpdir, index);
      if (size <= 0 || (size_t)size >= sizeof(path)) return 112;
      int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
      if (fd < 0) return 113;
      ssize_t written = write(fd, payload, sizeof(payload));
      close(fd);
      if (written != (ssize_t)sizeof(payload)) return 114;
      usleep(150000);
      if (unlink(path) != 0) return 115;
    }
    return 0;
  }
  if (count > 1 && strcmp(values[1], "--test-stdout-overage") == 0) {
    char payload[4096];
    memset(payload, 'o', sizeof(payload));
    for (int index = 0; index < 8192; ++index) {
      ssize_t written = write(STDOUT_FILENO, payload, sizeof(payload));
      if (written <= 0) return 116;
    }
    return 0;
  }
  if (count > 1 && strcmp(values[1], "--emit-feedback-policy-only") == 0) {
    const char *workload = argument_value(count, values, "--workload");
    const char *profile = argument_value(count, values, "--profile");
    if (workload == NULL || profile == NULL) return 93;
    char path[8192];
    int size = snprintf(path, sizeof(path), "%s/%s-%s.json", PROBE_ROOT, workload, profile);
    if (size <= 0 || (size_t)size >= sizeof(path)) return 94;
    return copy_file_to_stdout(path);
  }

  const char *tmpdir = getenv("TMPDIR");
  if (tmpdir == NULL) return 95;
  char marker[8192];
  int marker_size = snprintf(marker, sizeof(marker), "%s/fake-app.pid", tmpdir);
  if (marker_size <= 0 || (size_t)marker_size >= sizeof(marker)) return 96;
  int marker_fd = open(marker, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  if (marker_fd < 0) return 97;
  char pid_text[64];
  int pid_size = snprintf(pid_text, sizeof(pid_text), "%ld\n", (long)getpid());
  if (pid_size <= 0 || write(marker_fd, pid_text, (size_t)pid_size) != pid_size) {
    close(marker_fd);
    return 98;
  }
  close(marker_fd);

  const char *workload = getenv("ALLOCATBELT_APP_WORKLOAD");
  const char *profile = getenv("ALLOCATBELT_APP_PROFILE");
  if (workload != NULL && profile != NULL && strcmp(workload, "cpu") == 0 &&
      strcmp(profile, "steady") == 0) {
    char churn_path[8192];
    int churn_size = snprintf(churn_path, sizeof(churn_path), "%s/capacity-churn-live.tmp", tmpdir);
    if (churn_size <= 0 || (size_t)churn_size >= sizeof(churn_path)) return 117;
    int churn_fd = open(churn_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (churn_fd < 0) return 118;
    char churn_payload[8192];
    memset(churn_payload, 't', sizeof(churn_payload));
    ssize_t churn_written = write(churn_fd, churn_payload, sizeof(churn_payload));
    close(churn_fd);
    if (churn_written != (ssize_t)sizeof(churn_payload)) return 119;
    usleep(250000);
    if (unlink(churn_path) != 0) return 120;
    char opaque_path[8192];
    int opaque_size = snprintf(opaque_path, sizeof(opaque_path), "%s/opaque-payload.json", tmpdir);
    if (opaque_size <= 0 || (size_t)opaque_size >= sizeof(opaque_path)) return 121;
    int opaque_fd = open(opaque_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (opaque_fd < 0) return 122;
    static const char opaque_payload[] = "[\n  {\"path\":\"/not-an-evidence-member\"}\n]\n";
    ssize_t opaque_written = write(opaque_fd, opaque_payload, sizeof(opaque_payload) - 1);
    close(opaque_fd);
    if (opaque_written != (ssize_t)(sizeof(opaque_payload) - 1)) return 123;
  }

  if (access(FAIL_FLAG, F_OK) == 0) { usleep(200000); return 41; }
  if (access(HANG_FLAG, F_OK) == 0) for (;;) pause();

  pid_t child = fork();
  if (child < 0) return 99;
  if (child == 0) {
    char *arguments[] = {
      "/usr/bin/python3", "-B", DRIVER_PATH,
      "--fake-capacity-child", SOURCE_PATH, NULL,
    };
    execv(arguments[0], arguments);
    _exit(100);
  }
  int status = 0;
  while (waitpid(child, &status, 0) < 0) {
    if (errno != EINTR) return 101;
  }
  if (!WIFEXITED(status)) return 102;
  usleep(500000);
  return WEXITSTATUS(status);
}
"""


SITECUSTOMIZE = r"""
import json
import os
import subprocess

_real_fsync = os.fsync
_real_popen = subprocess.Popen
_ledger = os.environ.get("CAPACITY_STAGE_LEDGER")
_audit = os.environ.get("CAPACITY_STAGE_AUDIT")
_binary = os.environ.get("CAPACITY_STAGE_FAKE_BINARY")

def _append(item):
    with open(_audit, "a", encoding="utf-8") as output:
        output.write(json.dumps(item, sort_keys=True, separators=(",", ":")) + "\n")

def _last_record():
    with open(_ledger, "rb") as source:
        line = source.read().splitlines()[-1]
    return json.loads(line)

def _instrumented_fsync(fd):
    result = _real_fsync(fd)
    if not _ledger or not _audit:
        return result
    try:
        current = os.fstat(fd)
        named = os.stat(_ledger, follow_symlinks=False)
        if (current.st_dev, current.st_ino) == (named.st_dev, named.st_ino):
            envelope = _last_record()
            _append({"kind": "ledger_fsync", "event": envelope["record"]["event"],
                     "record_sha256": envelope["record_sha256"]})
    except (FileNotFoundError, IndexError, OSError):
        pass
    return result

def _instrumented_popen(args, *positional, **keywords):
    values = args if isinstance(args, (list, tuple)) else [args]
    if _binary and values and os.path.realpath(os.fspath(values[0])) == os.path.realpath(_binary):
        envelope = _last_record()
        record = envelope["record"]
        with open(_audit, "r", encoding="utf-8") as source:
            prior = [json.loads(line) for line in source if line.strip()]
        if not prior or prior[-1] != {
            "kind": "ledger_fsync", "event": record["event"],
            "record_sha256": envelope["record_sha256"],
        }:
            raise RuntimeError("child Popen occurred before the matching ledger fsync")
        if record["event"] not in ("probe_dispatch", "application_dispatch"):
            raise RuntimeError("child Popen did not follow a dispatch record")
        _append({"kind": "popen", "event": record["event"],
                 "record_sha256": envelope["record_sha256"]})
    return _real_popen(args, *positional, **keywords)

os.fsync = _instrumented_fsync
subprocess.Popen = _instrumented_popen
"""


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def write_file(path: Path, raw: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC, mode)
    try:
        os.fchmod(fd, mode)
        offset = 0
        while offset < len(raw):
            offset += os.write(fd, raw[offset:])
        os.fsync(fd)
    finally:
        os.close(fd)


def compressed_cpu_set(cpus: list[int]) -> str:
    ranges: list[str] = []
    start = previous = cpus[0]
    for cpu in cpus[1:]:
        if cpu == previous + 1:
            previous = cpu
            continue
        ranges.append(str(start) if start == previous else f"{start}-{previous}")
        start = previous = cpu
    ranges.append(str(start) if start == previous else f"{start}-{previous}")
    return ",".join(ranges)


def live_host_controls() -> dict[str, Any]:
    cpus = sorted(os.sched_getaffinity(0))
    return {
        "cpu_model": stage._live_cpu_model(),
        "microcode_sha256": "1" * 64,
        "kernel_release": platform.release(),
        "governor": "test-observed-governor",
        "frequency_policy": "test-observed-frequency-policy",
        "boost_policy": "test-observed-boost-policy",
        "cpu_set": compressed_cpu_set(cpus),
        "numa_policy": "test-observed-numa-policy",
        "cgroup_policy_sha256": "2" * 64,
        "background_load_policy_sha256": "3" * 64,
        "x86_64_v3_capability_sha256": "4" * 64,
        "target_triple": "x86_64-unknown-linux-gnu",
        "target_cpu": "x86-64-v3",
    }


class PreparationResourceMonitorReportBoundTests(unittest.TestCase):
    def _construct_monitor(
        self, root: Path, *, sample_interval_ms: int, process_deadline_seconds: int,
    ) -> tuple[stage.PreparationResourceMonitor, int, int]:
        generation = root / "generation"
        job_dir = generation / "jobs" / "job-a"
        trace_dir = job_dir / "trace"
        tmpdir_parent = root / "tmpdirs"
        tmpdir_roots = [
            tmpdir_parent / f"root-{index:02d}" for index in range(15)
        ]
        for directory in (generation, job_dir, trace_dir, tmpdir_parent, *tmpdir_roots):
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            directory.chmod(0o700)

        fixed_sha256 = sha(Path(fixed_pair_owner.__file__).read_bytes())
        context = {"stack": {
            "fixed_pair": fixed_pair_owner,
            "fixed_pair_sha256": fixed_sha256,
        }}
        ceilings = {
            "monitor_sample_interval_milliseconds": sample_interval_ms,
            "process_deadline_seconds": process_deadline_seconds,
        }
        report_bound = stage._estimate_preparation_resource_monitor_report_bytes(
            ceilings, fixed_pair_owner, tmpdir_root_count=len(tmpdir_roots),
        )
        tmpdir_pins = [
            stage._bounded_root_identity(fixed_pair_owner, path, "monitor-bound TMPDIR")
            for path in tmpdir_roots
        ]
        stage_root = stage._bounded_root_identity(
            fixed_pair_owner, generation, "monitor-bound generation",
        )
        job_root = stage._bounded_root_identity(
            fixed_pair_owner, job_dir, "monitor-bound job",
        )
        trace_root = stage._bounded_root_identity(
            fixed_pair_owner, trace_dir, "monitor-bound trace",
        )
        high_water = {key: 0 for key in (
            "job_output_bytes", "job_output_inodes", "generation_bytes",
            "generation_inodes", "tmpdir_bytes", "tmpdir_inodes",
        )}
        progress = {
            "expected_monitor_report_count": 30,
            "monitor_report_count": 0,
            "job_monitor_report_counts": {},
            "high_water": high_water,
        }
        budget = {
            "pin": {
                "path": str(root / "resource-budget.json"),
                "raw_sha256": "a" * 64,
                "semantic_sha256": "b" * 64,
            },
            "ceilings": ceilings,
            "monitor_report_max_bytes": report_bound,
            "monitor_report_max_samples": stage._preparation_resource_monitor_sample_count(
                ceilings, fixed_pair_owner,
            ),
            "monitor_report_count": 30,
        }
        monitor = stage.PreparationResourceMonitor(
            context, budget, generation, job_dir, trace_dir, tmpdir_pins,
            progress, stage_root, job_root, trace_root,
        )
        return monitor, report_bound, monitor.maximum_samples

    def test_estimator_and_runtime_checker_share_sixteen_device_worst_case(self) -> None:
        cases = (
            (1000, 1200, 1207),
            (100, 60, 643),
        )
        for interval_ms, deadline_seconds, expected_samples in cases:
            with self.subTest(interval_ms=interval_ms, deadline_seconds=deadline_seconds):
                with tempfile.TemporaryDirectory(
                    prefix="capacity-monitor-device-bound-",
                ) as temporary:
                    monitor, report_bound, sample_count = self._construct_monitor(
                        Path(temporary), sample_interval_ms=interval_ms,
                        process_deadline_seconds=deadline_seconds,
                    )
                    try:
                        self.assertEqual(sample_count, expected_samples)
                        self.assertEqual(
                            report_bound,
                            stage._estimate_preparation_resource_monitor_report_bytes(
                                monitor.ceilings, fixed_pair_owner, tmpdir_root_count=15,
                            ),
                        )
                        self.assertLessEqual(report_bound, stage.MAX_METADATA_BYTES)
                        if expected_samples == 1207:
                            self.assertEqual(report_bound, 7_640_957)
                    finally:
                        monitor.close()


class CapacityStageCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if platform.machine() != "x86_64" or not hasattr(os, "sched_getaffinity"):
            raise unittest.SkipTest("capacity stage witness requires the frozen x86_64 Linux host contract")
        compiler = shutil.which("cc")
        if compiler is None:
            raise unittest.SkipTest("capacity stage witness requires a native C compiler for the direct fake child")
        rustc_verbose = subprocess.check_output(["rustc", "-Vv"], text=True).splitlines()
        rustc_release = next((line.split(" ", 2)[1] for line in rustc_verbose if line.startswith("rustc ")), "")
        if rustc_release != "1.99.0":
            raise unittest.SkipTest("capacity stage witness requires the frozen Rust 1.99.0 source build")
        cls.root_temp = Path(tempfile.mkdtemp(prefix="application-capacity-stage-"))
        os.chmod(cls.root_temp, 0o700)
        cls.input_root = cls.root_temp / "inputs"
        cls.input_root.mkdir(mode=0o700)
        cls.source_tree = SOURCE_ROOT / "target" / f"application-capacity-stage-test-{os.getpid()}"
        cls.source_tree.mkdir(mode=0o700, parents=True, exist_ok=False)
        cls.failure_flag = cls.input_root / "fake-child-fail"
        cls.hang_flag = cls.input_root / "fake-child-hang"
        cls.probe_root = cls.input_root / "probes"
        cls.probe_root.mkdir(mode=0o700)
        cls.sources = None
        cls._build_fixture(compiler, rustc_verbose)
        cls.instrumentation = cls.input_root / "instrumentation"
        cls.instrumentation.mkdir(mode=0o700)
        write_file(cls.instrumentation / "sitecustomize.py", SITECUSTOMIZE.encode("utf-8"))

    @classmethod
    def tearDownClass(cls) -> None:
        if getattr(cls, "preserve_temp", False):
            print(f"capacity stage failure fixture preserved at {cls.root_temp}", file=sys.stderr)
            return
        shutil.rmtree(cls.root_temp, ignore_errors=True)
        shutil.rmtree(cls.source_tree, ignore_errors=True)

    @classmethod
    def _build_fixture(cls, compiler: str, rustc_verbose: list[str]) -> None:
        spec, sources = input_fixtures.spec_v3_fixture()
        host_id = "host-1"
        host = next(value for value in spec["hosts"] if value["host_id"] == host_id)
        controls = live_host_controls()
        host["controls"] = controls
        host["host_fingerprint_sha256"] = sha(canonical(controls))
        cls.host_id = host_id
        cls.host_contract = host
        cls.binary_path = cls.source_tree / "allocatbelt-fake"
        cls.source_manifest_dir = cls.input_root / "manifests"
        cls.source_manifest_dir.mkdir(mode=0o700)
        cls.source_manifest_path = cls.source_manifest_dir / f"{host_id}.json"
        cls.fake_driver = SCRIPT_DIR / "test-application-capacity-stage.py"
        c_file = cls.source_tree / "fake-capacity-app.c"
        write_file(c_file, FAKE_CHILD_C.encode("utf-8"))
        command = [
            compiler, "-std=c11", "-O2", "-Wall", "-Wextra",
            f'-DPROBE_ROOT="{cls.probe_root}"',
            f'-DDRIVER_PATH="{cls.fake_driver}"',
            f'-DSOURCE_PATH="{cls.source_manifest_path}"',
            f'-DFAIL_FLAG="{cls.failure_flag}"',
            f'-DHANG_FLAG="{cls.hang_flag}"',
            str(c_file), "-o", str(cls.binary_path),
        ]
        subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        os.chmod(cls.binary_path, 0o755)
        binary_raw = cls.binary_path.read_bytes()
        cls.binary_sha256 = sha(binary_raw)

        git_commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=SOURCE_ROOT, text=True).strip()
        cargo_version = subprocess.check_output(["cargo", "-V"], cwd=SOURCE_ROOT, text=True).strip()
        for source in sources.values():
            source["source"]["git_commit"] = git_commit
            source["build"]["rustc_release"] = "1.99.0"
            source["build"]["rustc_verbose"] = rustc_verbose
            source["build"]["cargo_version"] = cargo_version
            source["build"]["target_triple"] = "x86_64-unknown-linux-gnu"
            source["build"]["target_cpu"] = "x86-64-v3"
            source["build"]["profile"] = "release"
            source["build"]["build_inputs_sha256"] = "5" * 64
            source["build"]["features_sha256"] = "6" * 64
            source["artifacts"] = {
                "allocatbelt": {"path": str(cls.binary_path.relative_to(SOURCE_ROOT)),
                                "sha256": cls.binary_sha256},
                "mimalloc-secure": {"path": f"target/application-capacity-stage-test-{os.getpid()}/mimalloc-secure",
                                    "sha256": "7" * 64},
                "mimalloc-standard": {"path": f"target/application-capacity-stage-test-{os.getpid()}/mimalloc-standard",
                                      "sha256": "8" * 64},
                "system": {"path": f"target/application-capacity-stage-test-{os.getpid()}/system",
                           "sha256": "9" * 64},
            }
            source["soak_artifacts"] = {
                "allocatbelt": {"path": f"target/application-capacity-stage-test-{os.getpid()}/soak-allocatbelt",
                                "sha256": "a" * 64},
            }
            source["analysis_artifact"] = {
                "path": f"target/application-capacity-stage-test-{os.getpid()}/analyzer",
                "sha256": "b" * 64,
            }
            calibration = source["resource_domain_calibration"]
            calibration["binary"] = {
                "path": f"target/application-capacity-stage-test-{os.getpid()}/calibration-bin",
                "sha256": "c" * 64,
            }
            calibration["output"] = {
                "path": f"target/application-capacity-stage-test-{os.getpid()}/calibration.json",
                "sha256": sha(canonical(calibration["record"])),
            }
            calibration["build"] = dict(source["build"])
            calibration["build_sha256"] = input_fixtures.campaign.digest_object(source["build"])
            calibration["source"] = {
                key: source["source"][key]
                for key in ("git_commit", "source_tree_sha256", "cargo_lock_sha256")
            }
            source["manifest_sha256"] = input_fixtures.campaign.digest_object(
                {key: value for key, value in source.items() if key != "manifest_sha256"}
            )

        for path_value in (
            *[Path(item["path"]) for item in sources[host_id]["artifacts"].values()],
            *[Path(item["path"]) for item in sources[host_id]["soak_artifacts"].values()],
            Path(sources[host_id]["analysis_artifact"]["path"]),
            Path(sources[host_id]["resource_domain_calibration"]["binary"]["path"]),
        ):
            path = SOURCE_ROOT / path_value
            if path == cls.binary_path:
                continue
            raw = canonical(sources[host_id]["resource_domain_calibration"]["record"])
            write_file(path, raw, 0o755)
            if path == SOURCE_ROOT / sources[host_id]["resource_domain_calibration"]["binary"]["path"]:
                write_file(path, b"fake resource calibration binary\n", 0o755)
        calibration_output = SOURCE_ROOT / sources[host_id]["resource_domain_calibration"]["output"]["path"]
        write_file(calibration_output, canonical(sources[host_id]["resource_domain_calibration"]["record"]))
        for source in sources.values():
            for name, artifact in source["artifacts"].items():
                if name == "allocatbelt":
                    continue
                path = SOURCE_ROOT / artifact["path"]
                write_file(path, f"fixture application artifact {name}\n".encode(), 0o755)
                artifact["sha256"] = sha(path.read_bytes())
            for artifact in source["soak_artifacts"].values():
                if Path(artifact["path"]) == Path(sources[host_id]["artifacts"]["allocatbelt"]["path"]):
                    continue
                soak_path = SOURCE_ROOT / artifact["path"]
                write_file(soak_path, b"fixture soak executable\n", 0o755)
                artifact["sha256"] = sha(soak_path.read_bytes())
            analysis_path = SOURCE_ROOT / source["analysis_artifact"]["path"]
            write_file(analysis_path, b"fixture analysis executable\n", 0o755)
            source["analysis_artifact"]["sha256"] = sha(analysis_path.read_bytes())
            calibration_binary_path = SOURCE_ROOT / source["resource_domain_calibration"]["binary"]["path"]
            write_file(calibration_binary_path, b"fixture resource calibration executable\n", 0o755)
            source["resource_domain_calibration"]["binary"]["sha256"] = sha(calibration_binary_path.read_bytes())
            calibration_output_path = SOURCE_ROOT / source["resource_domain_calibration"]["output"]["path"]
            write_file(calibration_output_path,
                       canonical(source["resource_domain_calibration"]["record"]))
            source["resource_domain_calibration"]["output"]["sha256"] = sha(
                calibration_output_path.read_bytes()
            )
            source["manifest_sha256"] = input_fixtures.campaign.digest_object(
                {key: value for key, value in source.items() if key != "manifest_sha256"}
            )
        cls.sources = sources

        storage_fs, _storage_device_mount = stage._mount_context(Path("/tmp"))
        storage_device_stat = Path("/tmp").stat().st_dev
        storage_device = f"{os.major(storage_device_stat)}:{os.minor(storage_device_stat)}"
        namespace_inode = os.stat("/proc/self/ns/net").st_ino
        for item in spec["qualification_inputs"]["capacity_templates"]:
            workload = item["workload"]
            request = {
                "schema": stage.REQUEST_TEMPLATE_SCHEMA,
                "minimum_interval_seconds": 10,
            }
            context = {
                "schema": stage.CONTEXT_TEMPLATE_SCHEMA,
                "storage": ({
                    "scope": "application_file_io", "root_path": "/tmp",
                    "filesystem_type": storage_fs, "device_major_minor": storage_device,
                    "minimum_free_bytes": 1,
                } if workload in ("disk", "mixed") else None),
                "network": ({
                    "scope": "ipv4_loopback_application_bytes", "interface": "lo",
                    "address": "127.0.0.1", "namespace_inode": namespace_inode,
                } if workload in ("http", "mixed") else None),
            }
            for field, value in (("request_template", request), ("context_template", context)):
                relative = item[field]["relative_path"]
                path = cls.input_root / relative
                raw = canonical(value)
                write_file(path, raw)
                item[field]["raw_sha256"] = sha(raw)

        for condition in spec["qualification_inputs"]["pressure_conditions"]:
            suffix = condition["condition_id"]
            condition_raw = canonical({"schema": "fixture.capacity-stage-pressure-condition.v1",
                                       "condition_id": suffix})
            condition_path = cls.input_root / condition["condition"]["relative_path"]
            write_file(condition_path, condition_raw)
            condition["condition"]["raw_sha256"] = sha(condition_raw)
            condition["condition_sha256"] = sha(condition_raw)
            for name in ("artifact", "receipt"):
                pin = condition["pressure_calibration"][name]
                raw = canonical({
                    "schema": f"fixture.capacity-stage-pressure-{name}.v1",
                    "condition_id": suffix,
                })
                write_file(cls.input_root / pin["relative_path"], raw)
                pin["raw_sha256"] = sha(raw)

        for source_host in spec["source_manifests"]:
            path = cls.source_manifest_dir / f"{source_host['host_id']}.json"
            source_host["relative_path"] = f"manifests/{source_host['host_id']}.json"
            source_host["sha256"] = sources[source_host["host_id"]]["manifest_sha256"]
            write_file(path, canonical(sources[source_host["host_id"]]))
        cls.spec = spec
        cls.spec_path = cls.input_root / "campaign-spec.json"
        write_file(cls.spec_path, canonical(spec))

        selected_source = sources[host_id]
        for workload in stage.WORKLOADS:
            for profile in stage.PROFILES[workload]:
                identity = {
                    "host_id": host_id, "run_id": "probe-fixture", "report_nonce": "a" * 32,
                    "process_id": 1, "allocator": "allocatbelt", "executor": "allocatbelt",
                    "workload": workload, "profile": profile, "mode": "capacity",
                    "source_sha256": selected_source["source"]["source_tree_sha256"],
                    "binary_sha256": cls.binary_sha256, "pressure_qualification": False,
                }
                policy = feedback_fixtures._v4_policy_from_source(identity, selected_source)
                probe_builder = object.__new__(feedback_fixtures.Fixture)
                probe_builder.identity = identity
                probe_builder.policy = policy
                probe = probe_builder._construction_probe()
                write_file(cls.probe_root / f"{workload}-{profile}.json", canonical(probe))

        cls.failures_dir = cls.input_root
        cls.c_file_path = cls.source_tree / "fake-capacity-app.c"
        cls.source_argument = str(cls.source_manifest_path)
        cls.probe_argument = str(cls.probe_root)
        cls.plan = input_fixtures.campaign.freeze_plan(spec, sources, cls.input_root)
        cls.plan_path = cls.input_root / "campaign-plan.json"
        write_file(cls.plan_path, input_fixtures.campaign.campaign_plan_bytes(cls.plan))
        cls.spec_sha256 = sha(cls.spec_path.read_bytes())
        cls.plan_sha256 = sha(cls.plan_path.read_bytes())
        cls.source_manifest_path.write_bytes(canonical(selected_source))
        cls.source_manifest_sha256 = sha(cls.source_manifest_path.read_bytes())
        cls.observed_host_path = cls.input_root / "observed-host.json"
        observed = {
            "schema": stage.HOST_CONTEXT_SCHEMA, "host_id": host_id,
            "boot_id_sha256": stage._boot_id_sha256(),
            "controls_sha256": host["host_fingerprint_sha256"], "controls": controls,
            "kernel_release": platform.release(), "cpu_model": stage._live_cpu_model(),
            "cpu_affinity": sorted(os.sched_getaffinity(0)),
            "network_namespace_inode": namespace_inode,
        }
        write_file(cls.observed_host_path, canonical(observed))
        cls.observed_host_sha256 = sha(cls.observed_host_path.read_bytes())
        cls.campaign_id = spec["campaign_id"]

    def setUp(self) -> None:
        self.output_root = self.root_temp / f"output-{self._testMethodName}"
        self.output_root.mkdir(mode=0o700)
        self.stage_dir = self.output_root / self.campaign_id / "capacity" / self.host_id
        self.ledger_path = self.stage_dir / "controller-ledger.jsonl"
        self.audit_path = self.root_temp / f"audit-{self._testMethodName}.jsonl"
        try:
            self.audit_path.unlink()
        except FileNotFoundError:
            pass

    def tearDown(self) -> None:
        outcome = getattr(getattr(self, "_outcome", None), "result", None)
        if outcome is not None and not outcome.wasSuccessful():
            type(self).preserve_temp = True
        for marker in self.output_root.rglob("fake-app.pid"):
            candidate = marker.parent
            try:
                candidate.relative_to(self.output_root)
            except ValueError:
                shutil.rmtree(candidate, ignore_errors=True)

    def _source5_process_context(self) -> dict[str, Any]:
        return {
            "current_host": {
                "cpu_affinity": sorted(os.sched_getaffinity(0)),
                "network_namespace_inode": os.stat("/proc/self/ns/net").st_ino,
            },
            "stack": {
                "fixed_pair": fixed_pair_owner,
                "fixed_pair_sha256": sha((SCRIPT_DIR / "application-fixed-pair.py").read_bytes()),
                "process_identity_helper": process_identity_helper,
                "process_identity_helper_sha256": sha((SCRIPT_DIR / "application-soak-readback.py").read_bytes()),
            },
        }

    def _run_source5_owned_child(
        self, root: Path, arguments: list[str], *, timeout_seconds: int = 2,
        on_bound=None, resource_monitor=None, capture_owner_return: bool = False,
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], Path, list[str], dict[str, str]]:
        job = {"run_id": "owned-test"}
        job_dir = root / "jobs" / job["run_id"]
        job_dir.mkdir(mode=0o700, parents=True)
        (job_dir / "trace").mkdir(mode=0o700)
        is_probe = bool(arguments and arguments[0] == "--emit-feedback-policy-only")
        label = "policy-probe" if is_probe else "application"
        tmpdir = job_dir / "tmp"
        tmpdir.mkdir(mode=0o700)
        environment = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TMPDIR": str(tmpdir)}
        context = self._source5_process_context()
        argv = [str(self.binary_path), *arguments]
        result = stage._spawn_with_source5_owner(
            context, argv, job_dir, environment,
            job_dir / ("policy-probe.json" if is_probe else "application.stdout"),
            job_dir / ("policy-probe.stderr" if is_probe else "application.stderr"),
            timeout_seconds, self.binary_path, self.binary_sha256,
            job_dir / f"{label}.process-capture.json",
            job_dir / f"{label}.process-start.json",
            on_bound=on_bound, resource_monitor=resource_monitor,
            owner_return_path=(job_dir / f"{label}.owner-return.json"
                               if capture_owner_return else None),
        )
        return result, context, job, job_dir, argv, environment

    def _bounded_churn_monitor(
        self, root: Path, *, maximum_tmpdir_bytes: int,
    ) -> tuple[Any, dict[str, Any], Path, Path]:
        generation = root / "generation"
        jobs_root = generation / "jobs"
        job_dir = jobs_root / "owned-test"
        trace_dir = job_dir / "trace"
        tmpdir = job_dir / "tmp"
        generation.mkdir(mode=0o700, parents=True)
        jobs_root.mkdir(mode=0o700)
        job_dir.mkdir(mode=0o700)
        trace_dir.mkdir(mode=0o700)
        tmpdir.mkdir(mode=0o700)
        context = self._source5_process_context()
        fixed = context["stack"]["fixed_pair"]
        ceilings = {
            "maximum_job_output_bytes": 128 * 1024 * 1024,
            "maximum_job_output_inodes": 256,
            "maximum_generation_bytes": 256 * 1024 * 1024,
            "maximum_generation_inodes": 4096,
            "maximum_tmpdir_bytes": maximum_tmpdir_bytes,
            "maximum_tmpdir_inodes": 64,
            "maximum_trace_file_bytes": 1024 * 1024,
            "durable_receipt_reserve_bytes": 192 * 1024 * 1024,
            "durable_receipt_reserve_inodes": 32,
            "minimum_free_bytes": 0,
            "minimum_free_inodes": 0,
            "monitor_sample_interval_milliseconds": 50,
            "process_deadline_seconds": 6,
        }
        progress = {
            "expected_monitor_report_count": 2,
            "monitor_report_count": 0,
            "job_monitor_report_counts": {},
            "high_water": {key: 0 for key in (
                "job_output_bytes", "job_output_inodes", "generation_bytes",
                "generation_inodes", "tmpdir_bytes", "tmpdir_inodes",
            )},
        }
        stage_root = stage._bounded_root_identity(fixed, generation, "churn test generation")
        job_root = stage._bounded_root_identity(fixed, job_dir, "churn test job")
        trace_root = stage._bounded_root_identity(fixed, trace_dir, "churn test trace")
        tmp_root = stage._bounded_root_identity(fixed, tmpdir, "churn test TMPDIR")
        progress.update({
            "stage_root": stage_root,
            "job_roots": {"owned-test": job_root},
            "trace_roots": {"owned-test": trace_root},
            "tmpdir_roots": [tmp_root],
        })
        budget = {
            "pin": {"path": str(root / "resource-budget.json"),
                    "raw_sha256": "a" * 64, "semantic_sha256": "b" * 64},
            "ceilings": ceilings,
            "monitor_report_max_bytes": stage.MAX_METADATA_BYTES,
            "monitor_report_max_samples": 203,
            "monitor_report_count": 2,
        }
        monitor = stage.PreparationResourceMonitor(
            context, budget, generation, job_dir, trace_dir,
            progress["tmpdir_roots"], progress, stage_root, job_root, trace_root,
        )
        monitor.begin("application")
        return monitor, progress, job_dir, tmpdir

    def _replace_owned_tree_at_same_path(self, root: Path) -> tuple[int, int]:
        original_inode = root.stat(follow_symlinks=False).st_ino
        copied = root.with_name(f".{root.name}-identity-copy-{os.getpid()}")
        self.assertFalse(copied.exists())
        shutil.copytree(root, copied, symlinks=True, copy_function=shutil.copy2)
        shutil.rmtree(root)
        os.replace(copied, root)
        copied_inode = root.stat(follow_symlinks=False).st_ino
        self.assertNotEqual(original_inode, copied_inode,
                            f"identity copy did not change the physical inode: {root}")
        return original_inode, copied_inode

    def _copy_bounded_offline_evidence(
        self, completion: dict[str, Any],
    ) -> dict[str, Any]:
        """Replace owned trees with byte copies at the exact original paths."""
        source_root = SOURCE_ROOT
        output_root = self.input_root / f"bounded-output-{self._testMethodName}"
        stage_dir = Path(completion["stage_directory"])
        self.assertTrue(output_root.is_dir() and stage_dir.is_relative_to(output_root))
        inodes_before: dict[Path, int] = {self.input_root: self.input_root.stat().st_ino,
                                         output_root: output_root.stat().st_ino}
        tmp_roots = sorted({
            Path(item["path"])
            for item in completion["resource_monitor"]["final_usage"]["tmpdir_roots"]
        })
        for root in tmp_roots:
            inodes_before[root] = root.stat(follow_symlinks=False).st_ino

        # The input tree includes the output generation and every TMPDIR the
        # bounded runner placed beneath that declared output root.
        self._replace_owned_tree_at_same_path(self.input_root)
        for root in tmp_roots:
            if not root.is_relative_to(self.input_root):
                self._replace_owned_tree_at_same_path(root)

        origins: set[Path] = {source_root}

        def add_source_member(path: Path, *, expected: dict[str, Any] | None = None) -> None:
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                self.assertIsNotNone(expected)
                self.assertEqual(expected.get("kind"), "symlink")
                self.assertEqual(os.readlink(path), expected.get("target"))
            else:
                self.assertTrue(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode),
                                f"SourceV5 map member is a special file: {path}")
                if expected is not None:
                    self.assertEqual(expected.get("kind"), "file")
            origins.add(path)
            parent = path.parent
            while parent != source_root:
                self.assertTrue(parent.is_relative_to(source_root))
                self.assertTrue(parent.is_dir() and not parent.is_symlink())
                origins.add(parent)
                parent = parent.parent

        for source in self.sources.values():
            for record in source["source"]["files"]:
                add_source_member(source_root / record["path"], expected=record)
            artifacts = [*source["artifacts"].values(),
                         *source.get("soak_artifacts", {}).values(),
                         source["analysis_artifact"],
                         source["resource_domain_calibration"]["binary"],
                         source["resource_domain_calibration"]["output"]]
            for artifact in artifacts:
                add_source_member(source_root / artifact["path"])

        def add_tree(root: Path) -> None:
            origins.add(root)
            for member in sorted(root.rglob("*")):
                info = member.lstat()
                self.assertTrue(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode),
                                f"offline fixture tree has a special member: {member}")
                origins.add(member)

        add_tree(self.input_root)
        for root in tmp_roots:
            if not root.is_relative_to(self.input_root):
                add_tree(root)
        entries = [{"origin": str(path), "local": str(path)}
                   for path in sorted(origins, key=str)]
        path_map = {"schema": stage.EVIDENCE_PATH_MAP_SCHEMA, "entries": entries}
        self.assertTrue(all(row["origin"] == row["local"] for row in entries))
        inodes_after = {path: path.stat(follow_symlinks=False).st_ino
                        for path in inodes_before}
        self.assertTrue(all(inodes_before[path] != inodes_after[path]
                            for path in inodes_before))
        return {
            "source_root": source_root, "input_root": self.input_root,
            "output_root": output_root, "stage_dir": stage_dir,
            "tmp_root_pairs": [(root, root) for root in tmp_roots],
            "inodes_before": inodes_before, "inodes_after": inodes_after,
            "evidence_path_map": path_map,
        }

    def _build_bounded_preparation_inputs(self) -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
        inputs = input_fixtures.inputs
        prep_fixtures = load_script(
            SCRIPT_DIR / "test-application-source5-input-preparation.py",
            f"capacity_stage_bounded_preparation_fixtures_{self.host_id}",
        )
        fixture, _fixture_spec = prep_fixtures.preparation_fixture()
        source_refs = {item["host_id"]: item for item in self.spec["source_manifests"]}
        source_pins: dict[str, dict[str, Any]] = {}
        observed_hosts: dict[str, dict[str, str]] = {}
        observed_values: dict[str, dict[str, Any]] = {}
        for index, host in enumerate(self.spec["hosts"]):
            host_id = host["host_id"]
            if host_id == self.host_id:
                observed_path = self.observed_host_path
                observed_value = json.loads(observed_path.read_bytes())
            else:
                controls = host["controls"]
                observed_value = {
                    "schema": stage.HOST_CONTEXT_SCHEMA,
                    "host_id": host_id,
                    "boot_id_sha256": str(index + 2) * 64,
                    "controls_sha256": host["host_fingerprint_sha256"],
                    "controls": controls,
                    "kernel_release": controls["kernel_release"],
                    "cpu_model": controls["cpu_model"],
                    "cpu_affinity": stage._parse_cpu_set(controls["cpu_set"]),
                    "network_namespace_inode": 10_000 + index,
                }
                observed_path = self.input_root / "bounded-observed-hosts" / f"{host_id}.json"
                write_file(observed_path, canonical(observed_value))
            observed_raw = observed_path.read_bytes()
            observed_values[host_id] = observed_value
            observed_hosts[host_id] = {
                "relative_path": observed_path.relative_to(self.input_root).as_posix(),
                "raw_sha256": sha(observed_raw),
            }
            source = self.sources[host_id]
            inventory = {item["path"]: item for item in source["source"]["files"]}
            manifest_path = self.input_root / source_refs[host_id]["relative_path"]
            source_pins[host_id] = {
                "manifest": {
                    "relative_path": source_refs[host_id]["relative_path"],
                    "raw_sha256": sha(manifest_path.read_bytes()),
                    "semantic_sha256": source["manifest_sha256"],
                    "source_tree_sha256": source["source"]["source_tree_sha256"],
                },
                "modules": {
                    role: {"path": path, "sha256": inventory[path]["sha256"]}
                    for role, path in inputs.PREPARATION_MODULE_PATHS.items()
                },
                "artifacts": copy.deepcopy(source["artifacts"]),
            }

        actual_templates = {
            (item["host_id"], item["workload"], item["profile"]): item
            for item in self.spec["qualification_inputs"]["capacity_templates"]
        }
        templates = []
        for template in fixture["capacity_templates"]:
            key = (template["host_id"], template["workload"], template["profile"])
            actual = actual_templates[key]
            templates.append({
                "host_id": template["host_id"],
                "workload": template["workload"],
                "profile": template["profile"],
                "calibration_id": template["calibration_id"],
                "calibrator": template["calibrator"],
                "request_template": actual["request_template"],
                "context_template": actual["context_template"],
            })
        conditions = copy.deepcopy(fixture["condition_intensities"])
        for item in conditions:
            host_facts = observed_values[item["host_id"]]
            item["schedule"]["application_cpu_affinity"] = host_facts["cpu_affinity"]
            item["schedule"]["pressure_cpu_affinity"] = [host_facts["cpu_affinity"][0]]
            condition_relative = Path(item["condition"]["relative_path"])
            item["condition"]["relative_path"] = (
                Path("bounded-preparation-conditions") / self._testMethodName /
                condition_relative
            ).as_posix()
            raw_condition = canonical({
                "schema": inputs.SOURCE5_PRESSURE_CONDITION_SCHEMA,
                "host_id": item["host_id"],
                "condition_id": item["condition_id"],
                "capacity_key": item["capacity_key"],
                "pressure_calibration_id": item["pressure_calibration_id"],
                "readiness_threshold_rule": item["readiness_threshold_rule"],
                "readiness_thresholds": item["readiness_thresholds"],
                "pressure_thresholds": item["pressure_thresholds"],
                "schedule": item["schedule"],
            })
            condition_path = self.input_root / item["condition"]["relative_path"]
            write_file(condition_path, raw_condition)
            item["condition"]["raw_sha256"] = sha(raw_condition)

        core = {
            key: self.spec[key]
            for key in (
                "campaign_id", "runner_sha256", "hosts", "cells", "protocol",
                "runtime_binding", "phase_adapters", "aa_controls", "soak", "deadlines",
            )
        }
        preparation_path = self.input_root / (
            f"bounded-preparation-intent-{self._testMethodName}.json"
        )
        inputs.build_preparation_intent(
            core, source_pins, observed_hosts, templates, conditions, preparation_path,
            source_manifest_values=self.sources, input_root=self.input_root,
        )
        preparation_raw = preparation_path.read_bytes()
        preparation = json.loads(preparation_raw)
        preparation_pin = {
            "path": str(preparation_path), "raw_sha256": sha(preparation_raw),
            "semantic_sha256": preparation["preparation_sha256"],
        }
        ceilings = {
            "maximum_job_output_bytes": 64 * 1024 * 1024,
            "maximum_job_output_inodes": 256,
            "maximum_generation_bytes": 2 * 1024 * 1024 * 1024,
            "maximum_generation_inodes": 4096,
            "maximum_tmpdir_bytes": 128 * 1024 * 1024,
            "maximum_tmpdir_inodes": 512,
            "maximum_trace_file_bytes": 64 * 1024 * 1024,
            "durable_receipt_reserve_bytes": 1024 * 1024 * 1024,
            "durable_receipt_reserve_inodes": 32,
            "minimum_free_bytes": 32 * 1024 * 1024,
            "minimum_free_inodes": 1000,
            "monitor_sample_interval_milliseconds": 100,
            "process_deadline_seconds": 60,
        }
        budget = inputs.build_preparation_resource_budget(
            preparation, preparation_pin, self.host_id, ceilings,
        )
        budget_path = self.input_root / "bounded-resource-budget.json"
        budget_raw = inputs._canonical(budget)
        write_file(budget_path, budget_raw)
        budget_pin = {"path": str(budget_path), "sha256": sha(budget_raw)}
        observed_value = self.observed_host_path
        observed_pin = {
            "path": str(observed_value), "sha256": sha(observed_value.read_bytes()),
        }
        return preparation_pin, budget_pin, observed_pin

    def test_source5_direct_owner_records_actual_probe_and_reaps_clean_leader(self) -> None:
        with tempfile.TemporaryDirectory(prefix="capacity-stage-owned-positive-") as temporary:
            root = Path(temporary)
            callbacks: list[dict[str, Any]] = []
            waitable: list[dict[str, int]] = []

            def hold_parent_until_probe_exit(proof: dict[str, Any]) -> None:
                callbacks.append(proof)
                self.assertEqual(set(proof), {
                    "pid", "start_ticks", "requested_argv", "requested_argv_sha256",
                    "environment_sha256",
                })
                deadline = time.monotonic() + 2.0
                while time.monotonic() < deadline:
                    result = os.waitid(os.P_PID, proof["pid"],
                                       os.WEXITED | os.WNOHANG | os.WNOWAIT)
                    if result is not None and result.si_pid == proof["pid"]:
                        waitable.append({"si_pid": result.si_pid, "si_code": result.si_code,
                                         "si_status": result.si_status})
                        return
                    time.sleep(0.005)
                self.fail("fast policy emitter did not become waitable before the test bound")

            result, context, job, job_dir, argv, environment = self._run_source5_owned_child(
                root,
                ["--emit-feedback-policy-only", "--workload", "cpu", "--profile", "steady"],
                on_bound=hold_parent_until_probe_exit,
            )
            self.assertEqual(result["status"], "completed")
            self.assertEqual(result["return_code"], 0)
            self.assertEqual(len(callbacks), 1)
            self.assertEqual(waitable, [{"si_pid": result["pid"],
                                         "si_code": getattr(os, "CLD_EXITED", 1),
                                         "si_status": 0}])
            self.assertEqual(result["direct_process"]["start"]["path"],
                             str(job_dir / "policy-probe.process-start.json"))
            self.assertEqual(callbacks[0]["pid"], result["pid"])
            start_path = job_dir / "policy-probe.process-start.json"
            start_sidecar = json.loads(start_path.read_bytes())
            self.assertEqual(start_sidecar["schema"], stage.OWNED_POLICY_PROBE_START_SCHEMA)
            self.assertEqual(start_sidecar["role"], "source5_policy_probe")
            self.assertEqual(set(start_sidecar["start"]), {
                "pid", "start_ticks", "requested_argv", "requested_argv_sha256",
                "environment_sha256",
            })
            self.assertNotIn("executed_argv", start_sidecar["start"])
            self.assertNotIn("environment", start_sidecar["start"])
            capture_path = job_dir / "policy-probe.process-capture.json"
            capture = json.loads(capture_path.read_bytes())
            self.assertEqual(capture["schema"], stage.OWNED_POLICY_PROBE_CAPTURE_SCHEMA)
            self.assertEqual(capture["role"], "source5_policy_probe")
            self.assertEqual(capture["dispatch"]["argv"], argv)
            self.assertEqual(capture["dispatch"]["environment_sha256"], sha(canonical(environment)))
            supervision = capture["runner_capture"]["supervision"]
            self.assertEqual(supervision["cleanup_status"], "verified")
            self.assertIs(supervision["leader_reaped"], True)
            self.assertEqual(supervision["remaining_session_members"], [])
            self.assertEqual(supervision["group_signal_after_leader_reap_count"], 0)
            self.assertEqual(supervision["signals"], [])
            start_raw = start_path.read_bytes()
            start_path.write_bytes(start_raw[:-1] + (b" " if start_raw[-1:] != b" " else b"\n"))
            with self.assertRaises(stage.CapacityStageError):
                stage._verify_owned_process_start(
                    context, job, root, result["direct_process"]["start"], argv,
                    environment, self.binary_path, self.binary_sha256, result["pid"],
                )
            start_path.write_bytes(start_raw)
            start = stage._verify_owned_process_start(
                context, job, root, result["direct_process"]["start"], argv,
                environment, self.binary_path, self.binary_sha256, result["pid"],
            )
            output_details = {
                "stdout_path": result["stdout_path"], "stdout_sha256": result["stdout_sha256"],
                "stdout_size": result["stdout_size"], "stderr_path": result["stderr_path"],
                "stderr_sha256": result["stderr_sha256"], "stderr_size": result["stderr_size"],
            }
            capture_raw = capture_path.read_bytes()
            capture_path.write_bytes(b"{}")
            with self.assertRaises(stage.CapacityStageError):
                stage._verify_owned_process_capture(
                    context, job, root, result["direct_process"]["capture"], start,
                    argv, environment, self.binary_path, self.binary_sha256,
                    2, result["elapsed_ns"], output_details,
                )
            capture_path.write_bytes(capture_raw)
            stage._verify_owned_process_capture(
                context, job, root, result["direct_process"]["capture"], start,
                argv, environment, self.binary_path, self.binary_sha256,
                2, result["elapsed_ns"], output_details,
            )

    def test_bounded_monitor_observes_real_temporary_directory_churn(self) -> None:
        with tempfile.TemporaryDirectory(prefix="capacity-stage-budget-churn-") as temporary:
            root = Path(temporary)
            monitor, progress, job_dir, tmpdir = self._bounded_churn_monitor(
                root, maximum_tmpdir_bytes=32 * 1024,
            )
            context = monitor.context
            environment = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TMPDIR": str(tmpdir)}
            argv = [str(self.binary_path), "--test-churn"]
            monitor.preflight()
            try:
                child = stage._spawn_with_source5_owner(
                    context, argv, job_dir, environment,
                    job_dir / "application.stdout", job_dir / "application.stderr",
                    6, self.binary_path, self.binary_sha256,
                    job_dir / "application.process-capture.json",
                    job_dir / "application.process-start.json",
                    resource_monitor=monitor,
                )
                report, report_pin = stage._seal_preparation_resource_monitor(
                    monitor, job_dir, "application",
                )
            finally:
                monitor.close()
            self.assertEqual(child["status"], "completed")
            self.assertEqual(child["return_code"], 0)
            self.assertIsNone(report["stop_reason"])
            self.assertGreater(progress["monitor_report_count"], 0)
            self.assertEqual(report_pin["path"], str(job_dir / "application.resource-monitor.json"))
            self.assertTrue(any(sample["tmpdir_bytes"] >= 4096 for sample in report["samples"]))
            self.assertEqual(list(tmpdir.iterdir()), [])
            capture = json.loads((job_dir / "application.process-capture.json").read_bytes())
            self.assertEqual(capture["runner_capture"]["supervision"]["cleanup_status"], "verified")
            self.assertEqual(capture["runner_capture"]["supervision"]["group_signal_after_leader_reap_count"], 0)

    def test_bounded_monitor_terminates_and_retains_owner_receipt_on_live_tmpdir_overage(self) -> None:
        with tempfile.TemporaryDirectory(prefix="capacity-stage-budget-stop-") as temporary:
            root = Path(temporary)
            monitor, _progress, job_dir, tmpdir = self._bounded_churn_monitor(
                root, maximum_tmpdir_bytes=1024,
            )
            context = monitor.context
            environment = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TMPDIR": str(tmpdir)}
            argv = [str(self.binary_path), "--test-churn"]
            monitor.preflight()
            try:
                child = stage._spawn_with_source5_owner(
                    context, argv, job_dir, environment,
                    job_dir / "application.stdout", job_dir / "application.stderr",
                    6, self.binary_path, self.binary_sha256,
                    job_dir / "application.process-capture.json",
                    job_dir / "application.process-start.json",
                    resource_monitor=monitor,
                )
                report, report_pin = stage._seal_preparation_resource_monitor(
                    monitor, job_dir, "application",
                )
            finally:
                monitor.close()
            self.assertNotEqual(child["status"], "completed")
            self.assertIn("tmpdir_bytes", report["stop_reason"] or "")
            self.assertTrue(Path(report_pin["path"]).is_file())
            capture = json.loads((job_dir / "application.process-capture.json").read_bytes())
            self.assertEqual(capture["runner_capture"]["supervision"]["cleanup_status"], "verified")
            self.assertIsNotNone(child["direct_process"]["capture"])
            self.assertEqual(capture["runner_capture"]["supervision"]["group_signal_after_leader_reap_count"], 0)

    def test_bounded_owner_output_overage_keeps_exact_return_and_cleanup_sidecars(self) -> None:
        with tempfile.TemporaryDirectory(prefix="capacity-stage-owner-output-limit-") as temporary:
            root = Path(temporary)
            with self.assertRaises(stage.DirectOwnerPostReturnError) as caught:
                self._run_source5_owned_child(
                    root, ["--test-stdout-overage"], timeout_seconds=8,
                    capture_owner_return=True,
                )
            job_dir = root / "jobs" / "owned-test"
            owner_path = job_dir / "application.owner-return.json"
            owner_raw = owner_path.read_bytes()
            owner = json.loads(owner_raw)
            failure_pin = caught.exception.failure_pin
            self.assertEqual(caught.exception.owner_return_pin, {
                "path": str(owner_path), "sha256": sha(owner_raw),
            })
            self.assertIsNotNone(failure_pin)
            failure_path = Path(failure_pin["path"])
            failure = json.loads(failure_path.read_bytes())
            self.assertEqual(failure["schema"], stage.DIRECT_OWNER_RETURN_FAILURE_SCHEMA)
            self.assertEqual(failure["owner_return"], caught.exception.owner_return_pin)
            self.assertIs(failure["complete"], False)
            self.assertIs(failure["qualification_eligible"], False)
            supervision = owner["supervision"]
            self.assertIs(supervision["artifact_budget_exceeded"], True)
            self.assertEqual(owner["status"], 125)
            self.assertEqual(supervision["cleanup_status"], "verified")
            self.assertIs(supervision["leader_reaped"], True)
            self.assertEqual(supervision["group_signal_after_leader_reap_count"], 0)

    def test_bounded_stage_failure_ledger_binds_raw_policy_probe_owner_return(self) -> None:
        preparation_pin, budget_pin, observed_pin = self._build_bounded_preparation_inputs()
        output_root = self.input_root / f"bounded-output-{self._testMethodName}"
        output_root.mkdir(mode=0o700)
        probes = sorted(self.probe_root.glob("*.json"))
        originals = {path: path.read_bytes() for path in probes}
        overage = b"p" * (stage.MAX_PROBE_BYTES + 64 * 1024)
        try:
            for path in probes:
                write_file(path, overage)
            with self.assertRaises(stage.DirectOwnerPostReturnError):
                stage.run_capacity_preparation_bounded(
                    preparation_pin, budget_pin, SOURCE_ROOT, self.input_root,
                    self.host_id, observed_pin, output_root,
                )
        finally:
            for path, raw in originals.items():
                write_file(path, raw)
        stage_dir = output_root / self.campaign_id / "capacity-preparation" / self.host_id
        records = [json.loads(line)["record"] for line in
                   (stage_dir / "capacity-preparation-bounded-ledger.jsonl").read_bytes().splitlines()]
        failed = records[-1]
        self.assertEqual(failed["event"], "stage_failed")
        owner_failure = failed["details"]["direct_owner_return_failure"]
        owner_pin = owner_failure["owner_return"]
        owner_path = Path(owner_pin["path"])
        owner_raw = owner_path.read_bytes()
        owner = json.loads(owner_raw)
        self.assertEqual(sha(owner_raw), owner_pin["sha256"])
        self.assertIs(owner["supervision"]["artifact_budget_exceeded"], True)
        self.assertEqual(owner["status"], 125)
        self.assertEqual(owner["supervision"]["cleanup_status"], "verified")
        failure_pin = owner_failure["failure"]
        failure_path = Path(failure_pin["path"])
        failure_raw = failure_path.read_bytes()
        failure = json.loads(failure_raw)
        self.assertEqual(sha(failure_raw), failure_pin["sha256"])
        self.assertEqual(failure["owner_return"], owner_pin)
        self.assertIs(failure["complete"], False)

    def test_bounded_preparation_runs_fifteen_original_templates_and_replays_offline(self) -> None:
        self.sources = copy.deepcopy(type(self).sources)
        self.spec = copy.deepcopy(type(self).spec)
        opaque_input_json = b'[\n  {"path":"/not-an-evidence-member"}\n]\n'
        opaque_input_path = self.input_root / (
            f"opaque-input-{self._testMethodName}.json"
        )
        write_file(opaque_input_path, opaque_input_json)
        self.addCleanup(opaque_input_path.unlink, missing_ok=True)

        input_storage_root = self.input_root / f"bounded-explicit-storage-{self._testMethodName}"
        input_storage_root.mkdir(mode=0o700)
        self.addCleanup(shutil.rmtree, input_storage_root, True)
        input_storage_template = next(
            item for item in self.spec["qualification_inputs"]["capacity_templates"]
            if item["host_id"] == self.host_id and item["workload"] == "disk"
        )
        input_context_path = self.input_root / input_storage_template[
            "context_template"]["relative_path"]
        input_context_original = input_context_path.read_bytes()
        input_context_mode = stat.S_IMODE(input_context_path.lstat().st_mode)
        self.addCleanup(write_file, input_context_path, input_context_original,
                        input_context_mode)
        input_context = json.loads(input_context_original)
        self.assertIsInstance(input_context.get("storage"), dict)
        storage_fs, storage_device = stage._mount_context(input_storage_root)
        storage_stat = input_storage_root.stat()
        self.assertEqual(storage_device,
                         f"{os.major(storage_stat.st_dev)}:{os.minor(storage_stat.st_dev)}")
        input_context["storage"].update({
            "root_path": str(input_storage_root),
            "filesystem_type": storage_fs, "device_major_minor": storage_device,
        })
        input_context_raw = canonical(input_context)
        write_file(input_context_path, input_context_raw, input_context_mode)
        input_storage_template["context_template"]["raw_sha256"] = sha(input_context_raw)

        preparation_pin, budget_pin, observed_pin = self._build_bounded_preparation_inputs()
        output_root = self.input_root / f"bounded-output-{self._testMethodName}"
        output_root.mkdir(mode=0o700)
        result = stage.run_capacity_preparation_bounded(
            preparation_pin, budget_pin, SOURCE_ROOT, self.input_root,
            self.host_id, observed_pin, output_root,
        )
        self.assertEqual(opaque_input_path.read_bytes(), opaque_input_json)
        self.assertIsInstance(json.loads(opaque_input_json), list)
        self.assertNotEqual(opaque_input_json, canonical(json.loads(opaque_input_json)))
        completion_pin = result["completion"]
        completion_path = Path(completion_pin["path"])
        completion = json.loads(completion_path.read_bytes())
        for root_pin in completion["resource_monitor"]["final_usage"]["tmpdir_roots"]:
            tmpdir_path = Path(root_pin["path"])
            self.addCleanup(shutil.rmtree, tmpdir_path, True)
        budget_value = json.loads(Path(budget_pin["path"]).read_bytes())
        self.assertTrue(result["complete"])
        self.assertEqual(result["entry_count"], 15)
        self.assertEqual(completion["schema"], stage.PREPARATION_BOUNDED_COMPLETION_SCHEMA)
        self.assertEqual(len(completion["entries"]), 15)
        self.assertEqual(completion["resource_monitor"]["report_count"], 30)
        self.assertEqual(len(completion["resource_monitor"]["final_usage"]["jobs"]), 15)
        self.assertGreater(
            completion["resource_monitor"]["high_water"]["tmpdir_bytes"],
            completion["resource_monitor"]["final_usage"]["tmpdir_bytes"],
            "the real deleted TMPDIR churn must survive as a sampled peak above final usage",
        )
        self.assertTrue(all(len(entry["resource_monitors"]) == 2
                            for entry in completion["entries"]))
        self.assertEqual(completion["resource_budget"], {
            "path": budget_pin["path"], "raw_sha256": budget_pin["sha256"],
            "semantic_sha256": budget_value["resource_budget_sha256"],
        })
        ledger_envelopes = [json.loads(line) for line in
                            Path(completion["ledger"]["path"]).read_bytes().splitlines()]
        self.assertTrue(all(
            set(envelope) == {"previous_sha256", "record", "record_sha256"} and
            type(envelope["record"]) is dict and "event" not in envelope
            for envelope in ledger_envelopes
        ), "the real preparation ledger must retain its closed hash-chain envelope")
        ledger_records = [item["record"] for item in ledger_envelopes]
        self.assertEqual(len(ledger_records), 15 * len(stage.JOB_EVENTS) + 1)
        self.assertEqual([item["event"] for item in ledger_records],
                         [event for _entry in completion["entries"]
                          for event in stage.JOB_EVENTS] + ["preparation_complete"])
        self.assertEqual([item["run_id"] for item in ledger_records[:-1]],
                         [entry["run_id"] for entry in completion["entries"]
                          for _event in stage.JOB_EVENTS])
        self.assertTrue(all(item["schema"] == stage.PREPARATION_BOUNDED_EVENT_SCHEMA and
                            item["resource_budget"] == completion["resource_budget"]
                            for item in ledger_records))
        application_dispatches = [item for item in ledger_records
                                  if item["event"] == "application_dispatch"]
        no_storage_dispatches = [item for item in application_dispatches
                                 if item["details"]["storage_context"] is None]
        explicit_storage_dispatches = [item for item in application_dispatches
                                       if item["details"]["storage_context"] is not None]
        self.assertTrue(no_storage_dispatches and explicit_storage_dispatches,
                        "the original matrix must exercise both bounded TMPDIR construction paths")
        explicit_storage_roots = {
            Path(item["details"]["storage_context"]["root_path"])
            for item in explicit_storage_dispatches
        }
        self.assertIn(input_storage_root, explicit_storage_roots,
                      "the original 15-context schedule must exercise input-root explicit storage")
        self.assertTrue(any(not root.is_relative_to(self.input_root)
                            for root in explicit_storage_roots),
                        "the original schedule must retain external explicit-storage coverage")
        for item in no_storage_dispatches:
            details = item["details"]
            self.assertEqual(
                details["tmpdir_path"],
                str(output_root / f"capacity-preparation-tmp-{item['run_id']}"),
            )
        for item in explicit_storage_dispatches:
            details = item["details"]
            storage = details["storage_context"]
            self.assertEqual(Path(details["tmpdir_path"]).parent,
                             Path(storage["root_path"]))

        insufficient_budget = copy.deepcopy(budget_value)
        insufficient_budget["ceilings"]["durable_receipt_reserve_bytes"] = 1
        insufficient_body = {key: value for key, value in insufficient_budget.items()
                             if key != "resource_budget_sha256"}
        insufficient_budget["resource_budget_sha256"] = input_fixtures.inputs._sha256(
            input_fixtures.inputs._canonical(insufficient_body),
        )
        insufficient_path = self.input_root / "bounded-budget-insufficient-receipts.json"
        insufficient_raw = input_fixtures.inputs._canonical(insufficient_budget)
        write_file(insufficient_path, insufficient_raw)
        insufficient_pin = {"path": str(insufficient_path), "sha256": sha(insufficient_raw)}
        untouched_output = self.input_root / "bounded-output-insufficient-receipts"
        untouched_output.mkdir(mode=0o700)
        with self.assertRaisesRegex(stage.CapacityStageError, "cannot reserve durable receipts"):
            stage.run_capacity_preparation_bounded(
                preparation_pin, insufficient_pin, SOURCE_ROOT, self.input_root,
                self.host_id, observed_pin, untouched_output,
            )
        self.assertFalse((untouched_output / self.campaign_id).exists())

        strict = stage.verify_capacity_preparation_bounded(
            preparation_pin, budget_pin, SOURCE_ROOT, self.input_root,
            self.host_id, observed_pin, output_root, completion_pin,
        )
        stage_dir = Path(completion["stage_directory"])
        receipt_path = stage_dir / "bounded-host-verification.json"
        receipt_raw = canonical(strict)
        write_file(receipt_path, receipt_raw)
        receipt_pin = {
            "path": str(receipt_path), "raw_sha256": sha(receipt_raw),
            "receipt_sha256": strict["receipt_sha256"],
        }
        copied = self._copy_bounded_offline_evidence(completion)
        self.assertEqual(copied["source_root"], SOURCE_ROOT)
        self.assertEqual(copied["input_root"], self.input_root)
        self.assertEqual(copied["output_root"], output_root)
        for pinned_path, pinned_sha in (
            (preparation_pin["path"], preparation_pin["raw_sha256"]),
            (budget_pin["path"], budget_pin["sha256"]),
            (observed_pin["path"], observed_pin["sha256"]),
            (completion_pin["path"], completion_pin["sha256"]),
            (receipt_pin["path"], receipt_pin["raw_sha256"]),
        ):
            self.assertEqual(sha(Path(pinned_path).read_bytes()), pinned_sha)
        self.assertNotEqual(copied["inodes_before"][self.input_root],
                            copied["inodes_after"][self.input_root])
        self.assertNotEqual(copied["inodes_before"][output_root],
                            copied["inodes_after"][output_root])
        self.assertTrue(all(origin == local
                            for origin, local in copied["tmp_root_pairs"]))
        opaque_tmp_paths = [root / "opaque-payload.json"
                            for root, _local in copied["tmp_root_pairs"]
                            if (root / "opaque-payload.json").is_file()]
        self.assertEqual(len(opaque_tmp_paths), 1)
        self.assertEqual(opaque_tmp_paths[0].read_bytes(),
                         b'[\n  {"path":"/not-an-evidence-member"}\n]\n')

        def offline_replay(path_map: dict[str, Any]) -> dict[str, Any]:
            return stage.verify_capacity_preparation_bounded_offline(
                preparation_pin, budget_pin, SOURCE_ROOT, self.input_root,
                self.host_id, observed_pin, output_root, completion_pin,
                path_map, receipt_pin,
            )

        original_path_open = Path.open
        original_os_stat = os.stat

        def reject_proc_open(path: Path, *args: Any, **kwargs: Any):
            if str(path).startswith("/proc/"):
                raise AssertionError("offline replay opened current procfs")
            return original_path_open(path, *args, **kwargs)

        def reject_proc_stat(path: Any, *args: Any, **kwargs: Any):
            try:
                rendered = os.fspath(path)
            except TypeError:
                rendered = ""
            if type(rendered) is str and rendered.startswith("/proc/"):
                raise AssertionError("offline replay statted current procfs")
            return original_os_stat(path, *args, **kwargs)

        with patch.object(stage, "_verify_observed_host",
                          side_effect=AssertionError("offline replay probed current host identity")), \
             patch.object(stage, "_boot_id_sha256",
                          side_effect=AssertionError("offline replay read current boot identity")), \
             patch.object(stage, "_bounded_statvfs",
                          side_effect=AssertionError("offline replay sampled current filesystem capacity")), \
             patch.object(stage, "_storage_snapshot",
                          side_effect=AssertionError("offline replay sampled current storage")), \
             patch.object(stage, "_network_snapshot",
                          side_effect=AssertionError("offline replay sampled current network namespace")), \
             patch.object(Path, "open", new=reject_proc_open), \
             patch.object(os, "stat", new=reject_proc_stat), \
             patch.object(os, "statvfs",
                          side_effect=AssertionError("offline replay called statvfs")), \
             patch.object(stage.subprocess, "Popen",
                          side_effect=AssertionError("offline replay launched a process")):
            offline = offline_replay(copied["evidence_path_map"])
        self.assertEqual(offline, strict,
                         "identity-map replay must preserve the exact original receipt bytes")

        offline_map_raw = canonical(copied["evidence_path_map"])
        offline_map_path = self.root_temp / f"offline-evidence-path-map-{self._testMethodName}.json"
        write_file(offline_map_path, offline_map_raw)
        cli_output = io.BytesIO()
        cli_argv = [
            "verify-preparation-bounded-offline",
            "--preparation", str(preparation_pin["path"]),
            "--preparation-sha256", preparation_pin["raw_sha256"],
            "--resource-budget", str(budget_pin["path"]),
            "--resource-budget-sha256", budget_pin["sha256"],
            "--source-root", str(SOURCE_ROOT),
            "--input-root", str(self.input_root),
            "--host-id", self.host_id,
            "--observed-host", str(observed_pin["path"]),
            "--observed-host-sha256", observed_pin["sha256"],
            "--output-root", str(output_root),
            "--completion", str(completion_pin["path"]),
            "--completion-sha256", completion_pin["sha256"],
            "--evidence-path-map", str(offline_map_path),
            "--evidence-path-map-sha256", sha(offline_map_raw),
            "--host-verification-receipt", str(receipt_pin["path"]),
            "--host-verification-raw-sha256", receipt_pin["raw_sha256"],
            "--host-verification-receipt-sha256", receipt_pin["receipt_sha256"],
        ]
        with patch.object(stage, "_verify_observed_host",
                          side_effect=AssertionError("offline CLI probed current host identity")), \
             patch.object(stage, "_boot_id_sha256",
                          side_effect=AssertionError("offline CLI read current boot identity")), \
             patch.object(stage, "_bounded_statvfs",
                          side_effect=AssertionError("offline CLI sampled current filesystem capacity")), \
             patch.object(stage, "_storage_snapshot",
                          side_effect=AssertionError("offline CLI sampled current storage")), \
             patch.object(stage, "_network_snapshot",
                          side_effect=AssertionError("offline CLI sampled current network namespace")), \
             patch.object(Path, "open", new=reject_proc_open), \
             patch.object(os, "stat", new=reject_proc_stat), \
             patch.object(os, "statvfs",
                          side_effect=AssertionError("offline CLI called statvfs")), \
             patch.object(stage.subprocess, "Popen",
                          side_effect=AssertionError("offline CLI launched a process")), \
             patch.object(stage.sys, "stdout",
                          types.SimpleNamespace(buffer=cli_output)):
            cli_status = stage.main(cli_argv)
        self.assertEqual(cli_status, 0)
        self.assertEqual(json.loads(cli_output.getvalue()), offline)

        relocated_map = copy.deepcopy(copied["evidence_path_map"])
        input_root_entry = next(
            entry for entry in relocated_map["entries"]
            if entry["origin"] == str(self.input_root)
        )
        input_root_entry["local"] = str(self.input_root.with_name("relocated-input-copy"))
        with self.assertRaisesRegex(stage.CapacityStageError,
                                    "preserve every original absolute path"):
            offline_replay(relocated_map)

        nested_capture_path = Path(next(
            record["details"]["direct_process_capture"]["path"]
            for record in ledger_records if record["event"] == "application_exited"
        ))
        incomplete_map = copy.deepcopy(copied["evidence_path_map"])
        incomplete_map["entries"] = [
            entry for entry in incomplete_map["entries"]
            if entry["origin"] != str(nested_capture_path)
        ]
        with patch.object(stage, "_prepare_capacity_preparation_pins",
                          side_effect=AssertionError("nested preparation ran before map closure")), \
             patch.object(stage, "_capture_source_stack",
                          side_effect=AssertionError("SourceV5 module loaded before map closure")):
            with self.assertRaisesRegex(stage.CapacityStageError,
                                        "complete recursive input/output/TMPDIR membership"):
                offline_replay(incomplete_map)

        budget_path = Path(budget_pin["path"])
        budget_raw = budget_path.read_bytes()
        write_file(budget_path, budget_raw + b" ")
        with self.assertRaisesRegex(stage.CapacityStageError, "original raw host pin"):
            offline_replay(copied["evidence_path_map"])
        write_file(budget_path, budget_raw)

        monitor_path = Path(
            completion["entries"][0]["resource_monitors"]["policy_probe"]["path"],
        )
        local_monitor_path = monitor_path
        monitor_raw = local_monitor_path.read_bytes()
        write_file(local_monitor_path, monitor_raw + b" ")
        with self.assertRaises(stage.CapacityStageError):
            stage.verify_capacity_preparation_bounded_offline(
                preparation_pin, budget_pin, SOURCE_ROOT, self.input_root,
                self.host_id, observed_pin, output_root, completion_pin,
                copied["evidence_path_map"], receipt_pin,
            )
        write_file(local_monitor_path, monitor_raw)

        artifact_path = Path(completion["entries"][0]["artifact"]["path"])
        local_artifact_path = artifact_path
        artifact_raw = local_artifact_path.read_bytes()
        local_artifact_path.unlink()
        with self.assertRaises(stage.CapacityStageError):
            stage.verify_capacity_preparation_bounded_offline(
                preparation_pin, budget_pin, SOURCE_ROOT, self.input_root,
                self.host_id, observed_pin, output_root, completion_pin,
                copied["evidence_path_map"], receipt_pin,
            )
        write_file(local_artifact_path, artifact_raw)

    def test_bounded_preparation_free_space_floor_fails_before_popen(self) -> None:
        preparation_pin, budget_pin, observed_pin = self._build_bounded_preparation_inputs()
        mismatched_semantic_pin = {
            **preparation_pin, "semantic_sha256": "f" * 64,
        }
        wrong_semantic_output = self.input_root / (
            f"bounded-output-wrong-semantic-{self._testMethodName}"
        )
        wrong_semantic_output.mkdir(mode=0o700)
        with patch.object(subprocess, "Popen",
                          side_effect=AssertionError("semantic mismatch crossed child launch")) as popen:
            with self.assertRaisesRegex(
                    stage.CapacityStageError,
                    "bounded caller-pinned semantic digest",
            ):
                stage.run_capacity_preparation_bounded(
                    mismatched_semantic_pin, budget_pin, SOURCE_ROOT, self.input_root,
                    self.host_id, observed_pin, wrong_semantic_output,
                )
        popen.assert_not_called()

        inputs = input_fixtures.inputs
        budget_path = Path(budget_pin["path"])
        budget = json.loads(budget_path.read_bytes())
        budget["ceilings"]["minimum_free_bytes"] = 1 << 50
        budget_body = {key: value for key, value in budget.items()
                       if key != "resource_budget_sha256"}
        budget["resource_budget_sha256"] = inputs._sha256(inputs._canonical(budget_body))
        budget_raw = inputs._canonical(budget)
        write_file(budget_path, budget_raw)
        strict_budget_pin = {"path": str(budget_path), "sha256": sha(budget_raw)}
        output_root = self.input_root / f"bounded-output-{self._testMethodName}"
        output_root.mkdir(mode=0o700)
        # Strict source verification may run read-only Git commands. This gate
        # protects the scheduled policy-probe and APP owner entry point.
        with patch.object(
                stage, "_spawn_with_source5_owner",
                side_effect=AssertionError("scheduled owner launch crossed the free-space gate"),
        ) as owner_launch:
            with self.assertRaisesRegex(stage.CapacityStageError,
                                        "resource budget failed before child launch"):
                stage.run_capacity_preparation_bounded(
                    preparation_pin, strict_budget_pin, SOURCE_ROOT, self.input_root,
                    self.host_id, observed_pin, output_root,
                )
        owner_launch.assert_not_called()
        stage_dir = output_root / self.campaign_id / "capacity-preparation" / self.host_id
        self.assertFalse((stage_dir / "capacity-preparation-bounded-completion.json").exists())
        failed_records = [json.loads(line)["record"] for line in
                          (stage_dir / "capacity-preparation-bounded-ledger.jsonl").read_bytes().splitlines()]
        self.assertEqual([record["event"] for record in failed_records],
                         ["probe_dispatch", "stage_failed"])
        failure_pin = failed_records[-1]["details"].get("resource_monitor_failure")
        self.assertIsNotNone(failure_pin)
        failure_report = json.loads(Path(failure_pin["path"]).read_bytes())
        self.assertEqual(failure_report["role"], "policy_probe")
        self.assertIsNone(failure_report["monitor_error"])
        self.assertIn("minimum_free_bytes_or_receipt_reserve", failure_report["stop_reason"])
        self.assertTrue(any(
            filesystem["available_bytes"] < filesystem["required_bytes"]
            for sample in failure_report["samples"]
            for filesystem in sample["filesystems"]
        ))
        for root_pin in failure_report["roots"]["tmpdirs"]:
            self.addCleanup(shutil.rmtree, Path(root_pin["path"]), True)
        self.assertFalse(any(output_root.rglob("fake-app.pid")))

    def test_source5_direct_owner_reaps_timeout_and_records_signal_boundary(self) -> None:
        with tempfile.TemporaryDirectory(prefix="capacity-stage-owned-timeout-") as temporary:
            root = Path(temporary)
            result, _context, _job, job_dir, _argv, _environment = self._run_source5_owned_child(
                root, ["--test-wait"], timeout_seconds=1,
            )
            self.assertEqual(result["status"], "timeout")
            capture = json.loads((job_dir / "application.process-capture.json").read_bytes())
            supervision = capture["runner_capture"]["supervision"]
            self.assertIs(supervision["timed_out"], True)
            self.assertIs(supervision["leader_reaped"], True)
            self.assertEqual(supervision["remaining_session_members"], [])
            self.assertEqual(supervision["group_signal_after_leader_reap_count"], 0)
            self.assertTrue(all(item["group_signal"]["leader_unreaped"] is True
                                for item in supervision["signals"]))

    def test_source5_direct_owner_records_int_term_and_hup_without_raw_pid_forwarding(self) -> None:
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            with self.subTest(signal=signum), tempfile.TemporaryDirectory(
                prefix="capacity-stage-owned-signal-",
            ) as temporary:
                root = Path(temporary)
                result, _context, _job, job_dir, _argv, _environment = self._run_source5_owned_child(
                    root, ["--test-wait"], timeout_seconds=10,
                    on_bound=lambda _proof, value=signum: os.kill(os.getpid(), value),
                )
                self.assertEqual(result["status"], "interrupted")
                self.assertEqual(result["signal"], signum)
                capture = json.loads((job_dir / "application.process-capture.json").read_bytes())
                supervision = capture["runner_capture"]["supervision"]
                self.assertEqual(supervision["received_signal"], signum)
                self.assertIs(supervision["leader_reaped"], True)
                self.assertEqual(supervision["remaining_session_members"], [])
                self.assertEqual(supervision["group_signal_after_leader_reap_count"], 0)
                self.assertTrue(all(item["group_signal"]["leader_unreaped"] is True
                                    for item in supervision["signals"]))

    def test_source5_direct_owner_retains_nonzero_application_capture(self) -> None:
        self.failure_flag.touch(mode=0o600)
        try:
            with tempfile.TemporaryDirectory(prefix="capacity-stage-owned-failed-exit-") as temporary:
                root = Path(temporary)
                result, _context, _job, job_dir, _argv, _environment = self._run_source5_owned_child(
                    root, [], timeout_seconds=2,
                )
                self.assertEqual(result["status"], "completed")
                self.assertEqual(result["return_code"], 41)
                capture = json.loads((job_dir / "application.process-capture.json").read_bytes())
                direct = capture["runner_capture"]
                self.assertEqual(direct["status"], 41)
                self.assertEqual(direct["child_return_code"], 41)
                self.assertEqual(direct["supervision"]["cleanup_status"], "verified")
                self.assertIs(direct["supervision"]["leader_reaped"], True)
                self.assertEqual(direct["supervision"]["group_signal_after_leader_reap_count"], 0)
        finally:
            self.failure_flag.unlink(missing_ok=True)

    def test_source5_direct_owner_cleans_escaped_process_group_member_by_owned_pidfd(self) -> None:
        with tempfile.TemporaryDirectory(prefix="capacity-stage-owned-descendant-") as temporary:
            root = Path(temporary)
            result, context, job, job_dir, argv, environment = self._run_source5_owned_child(
                root, ["--test-escaped-descendant"],
            )
            self.assertEqual(result["status"], "completed")
            self.assertEqual(result["return_code"], 0)
            descendant_pid = int((job_dir / "tmp" / "owner-descendant.pid").read_text().strip())
            capture = json.loads((job_dir / "application.process-capture.json").read_bytes())
            supervision = capture["runner_capture"]["supervision"]
            self.assertIs(supervision["leader_reaped"], True)
            self.assertEqual(supervision["remaining_session_members"], [])
            self.assertEqual(supervision["group_signal_after_leader_reap_count"], 0)
            self.assertTrue(all(item["group_signal"]["leader_unreaped"] is True
                                for item in supervision["signals"]))
            pidfd_signals = [
                member
                for signal_record in supervision["signals"]
                for member in signal_record["pidfd_signals"]
            ]
            self.assertTrue(any(item["pid"] == descendant_pid and item["sent"] is True
                                for item in pidfd_signals))

            start = stage._verify_owned_process_start(
                context, job, root, result["direct_process"]["start"], argv,
                environment, self.binary_path, self.binary_sha256, result["pid"],
            )
            stage._verify_owned_process_capture(
                context, job, root, result["direct_process"]["capture"], start,
                argv, environment, self.binary_path, self.binary_sha256, 2,
                result["elapsed_ns"], result,
            )
            capture_path = job_dir / "application.process-capture.json"
            original_capture_raw = capture_path.read_bytes()
            original_capture = json.loads(original_capture_raw)
            original_supervision = original_capture["runner_capture"]["supervision"]
            original_escape_signal = next(
                item for item in original_supervision["signals"] if item["pidfd_signals"]
            )
            escaped_member = next(
                item for item in original_escape_signal["members"] if item["pid"] == descendant_pid
            )
            escaped_pidfd = next(
                item for item in original_escape_signal["pidfd_signals"]
                if item["pid"] == descendant_pid
            )

            def reject_repinned_capture(label: str, mutate) -> None:
                with self.subTest(resealed_capture=label):
                    candidate = json.loads(original_capture_raw)
                    mutate(candidate)
                    candidate_raw = stage.canonical_bytes(candidate)
                    try:
                        capture_path.write_bytes(candidate_raw)
                        repinned = {"path": str(capture_path), "sha256": sha(candidate_raw)}
                        with self.assertRaises(stage.CapacityStageError):
                            stage._verify_owned_process_capture(
                                context, job, root, repinned, start, argv, environment,
                                self.binary_path, self.binary_sha256, 2,
                                result["elapsed_ns"], result,
                            )
                    finally:
                        capture_path.write_bytes(original_capture_raw)

            def invalid_term_grace(value: dict[str, Any]) -> None:
                value["runner_capture"]["supervision"]["term_grace_seconds"] = "3.0"

            def invalid_kill_reap(value: dict[str, Any]) -> None:
                value["runner_capture"]["supervision"]["kill_reap_seconds"] = 2.0

            def invalid_wait_kind(value: dict[str, Any]) -> None:
                value["runner_capture"]["supervision"]["leader_info"]["si_code"] = 0

            def invalid_group_signal(value: dict[str, Any]) -> None:
                value["runner_capture"]["supervision"]["signals"][
                    original_supervision["signals"].index(original_escape_signal)
                ]["group_signal"]["signal"] = int(signal.SIGINT)

            def mismatched_group_leader_start(value: dict[str, Any]) -> None:
                value["runner_capture"]["supervision"]["signals"][
                    original_supervision["signals"].index(original_escape_signal)
                ]["group_signal"]["leader_start_ticks"] += 1

            def malformed_group_error(value: dict[str, Any]) -> None:
                value["runner_capture"]["supervision"]["signals"][
                    original_supervision["signals"].index(original_escape_signal)
                ]["group_error"] = {"arbitrary": "payload"}

            def malformed_scan_error(value: dict[str, Any]) -> None:
                value["runner_capture"]["supervision"]["signals"][
                    original_supervision["signals"].index(original_escape_signal)
                ]["scan_error"] = "opaque"

            def invalid_pidfd_row(value: dict[str, Any]) -> None:
                signal_index = original_supervision["signals"].index(original_escape_signal)
                value["runner_capture"]["supervision"]["signals"][signal_index]["pidfd_signals"][0] = {
                    "arbitrary": "payload",
                }

            def invalid_pidfd_sent_type(value: dict[str, Any]) -> None:
                signal_index = original_supervision["signals"].index(original_escape_signal)
                row = value["runner_capture"]["supervision"]["signals"][signal_index]["pidfd_signals"][0]
                row["sent"] = "true"

            def mismatched_pidfd_start(value: dict[str, Any]) -> None:
                signal_index = original_supervision["signals"].index(original_escape_signal)
                row = value["runner_capture"]["supervision"]["signals"][signal_index]["pidfd_signals"][0]
                row["start_ticks"] += 1

            def mismatched_pidfd_signal(value: dict[str, Any]) -> None:
                signal_index = original_supervision["signals"].index(original_escape_signal)
                row = value["runner_capture"]["supervision"]["signals"][signal_index]["pidfd_signals"][0]
                row["signal"] = int(signal.SIGINT)

            def mismatched_member_session(value: dict[str, Any]) -> None:
                signal_index = original_supervision["signals"].index(original_escape_signal)
                row = next(
                    item for item in value["runner_capture"]["supervision"]["signals"][signal_index]["members"]
                    if item["pid"] == descendant_pid
                )
                row["session_id"] = 0

            def mismatched_member_pid(value: dict[str, Any]) -> None:
                signal_index = original_supervision["signals"].index(original_escape_signal)
                row = next(
                    item for item in value["runner_capture"]["supervision"]["signals"][signal_index]["members"]
                    if item["pid"] == descendant_pid
                )
                row["pid"] += 1000

            self.assertEqual(escaped_member["start_ticks"], escaped_pidfd["start_ticks"])
            for label, mutation in (
                ("term_grace_type", invalid_term_grace),
                ("kill_reap_constant", invalid_kill_reap),
                ("waitid_kind", invalid_wait_kind),
                ("group_signal", invalid_group_signal),
                ("group_leader_start_ticks", mismatched_group_leader_start),
                ("group_error_schema", malformed_group_error),
                ("scan_error_schema", malformed_scan_error),
                ("pidfd_payload_schema", invalid_pidfd_row),
                ("pidfd_sent_type", invalid_pidfd_sent_type),
                ("pidfd_start_ticks", mismatched_pidfd_start),
                ("pidfd_signal", mismatched_pidfd_signal),
                ("member_session", mismatched_member_session),
                ("member_pid", mismatched_member_pid),
            ):
                reject_repinned_capture(label, mutation)

    def test_source5_owned_child_fails_closed_before_output_creation_without_captured_owner(self) -> None:
        with tempfile.TemporaryDirectory(prefix="capacity-stage-owned-missing-") as temporary:
            root = Path(temporary)
            tmpdir = root / "tmp"
            tmpdir.mkdir(mode=0o700)
            context = {"current_host": {}, "stack": {}}
            stdout = root / "stdout"
            with self.assertRaises(stage.CapacityStageError):
                stage._spawn_with_source5_owner(
                    context, [str(self.binary_path)], root,
                    {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TMPDIR": str(tmpdir)},
                    stdout, root / "stderr", 1, self.binary_path, self.binary_sha256,
                    root / "capture.json", root / "start.json",
                )
            self.assertFalse(stdout.exists())
            self.assertFalse((root / "stderr").exists())

    def _cli_args(self, command: str, output_root: Path | None = None) -> list[str]:
        target = output_root or self.output_root
        args = [
            "--plan", str(self.plan_path), "--plan-sha256", self.plan_sha256,
            "--spec", str(self.spec_path), "--spec-sha256", self.spec_sha256,
            "--source-root", str(SOURCE_ROOT), "--input-root", str(self.input_root),
            "--host-id", self.host_id, "--observed-host", str(self.observed_host_path),
            "--observed-host-sha256", self.observed_host_sha256,
            "--output-root", str(target),
        ]
        return [sys.executable, "-B", str(STAGE_PATH), command, *args]

    def _environment(self, ledger_path: Path | None = None) -> dict[str, str]:
        env = dict(os.environ)
        env["PYTHONPATH"] = str(self.instrumentation)
        env["CAPACITY_STAGE_LEDGER"] = str(ledger_path or self.ledger_path)
        env["CAPACITY_STAGE_AUDIT"] = str(self.audit_path)
        env["CAPACITY_STAGE_FAKE_BINARY"] = str(self.binary_path)
        return env

    def _run_cli(self, command: str, *, extra: list[str] | None = None,
                 output_root: Path | None = None,
                 timeout: int = 240) -> subprocess.CompletedProcess[bytes]:
        argv = self._cli_args(command, output_root)
        if extra:
            argv.extend(extra)
        return subprocess.run(
            argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=self._environment(
                (output_root or self.output_root) / self.campaign_id / "capacity" /
                self.host_id / "controller-ledger.jsonl"
            ), timeout=timeout, check=False,
        )

    def _completion(self, result: subprocess.CompletedProcess[bytes]) -> tuple[dict[str, Any], Path]:
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", errors="replace"))
        output = json.loads(result.stdout)
        pin = output["completion"]
        path = Path(pin["path"])
        value = json.loads(path.read_bytes())
        return value, path

    def _verify_cli(self, completion_path: Path, completion_raw_sha: str | None = None,
                    *, timeout: int = 240) -> subprocess.CompletedProcess[bytes]:
        raw_sha = completion_raw_sha or sha(completion_path.read_bytes())
        return self._run_cli("verify", extra=[
            "--completion", str(completion_path), "--completion-sha256", raw_sha,
        ], timeout=timeout)

    def _rechain_and_reject(self, completion_path: Path, mutate: Any,
                            expected_error: str) -> None:
        original_ledger = self.ledger_path.read_bytes()
        original_completion = completion_path.read_bytes()
        envelopes = [json.loads(line) for line in original_ledger.splitlines()]
        records = [item["record"] for item in envelopes]
        completion = json.loads(original_completion)
        mutate(records, completion)
        previous = "0" * 64
        lines: list[bytes] = []
        for sequence, record in enumerate(records, 1):
            record["sequence"] = sequence
            unsigned = {"previous_sha256": previous, "record": record}
            current = sha(canonical(unsigned))
            lines.append(canonical({**unsigned, "record_sha256": current}))
            previous = current
        ledger_raw = b"".join(lines)
        self.ledger_path.chmod(0o600)
        self.ledger_path.write_bytes(ledger_raw)
        self.ledger_path.chmod(0o400)
        completion["ledger"]["raw_sha256"] = sha(ledger_raw)
        completion["ledger"]["terminal_head"] = previous
        completion_raw = canonical(completion)
        completion_path.write_bytes(completion_raw)
        try:
            result = self._verify_cli(completion_path, sha(completion_raw))
            self.assertEqual(result.returncode, 2,
                             "re-chained contradictory completion metadata was accepted")
            self.assertIn(expected_error, result.stderr.decode("utf-8", errors="replace"))
        finally:
            self.ledger_path.chmod(0o600)
            self.ledger_path.write_bytes(original_ledger)
            self.ledger_path.chmod(0o400)
            completion_path.write_bytes(original_completion)

    def test_pre_spec_environment_binds_feedback_mode_and_real_readers_keep_no_actuation(self) -> None:
        job = {"run_id": "prep-cap-disk-steady"}
        job_dir = stage._prepare_job_dir(self.stage_dir, job)
        trace_dir = job_dir / "trace"
        tmpdir = self.output_root / "preparation-tmp"
        tmpdir.mkdir(mode=0o700)
        probe_source = self.probe_root / "disk-steady.json"
        probe_path = job_dir / "policy-probe.json"
        probe_raw = probe_source.read_bytes()
        write_file(probe_path, probe_raw)
        probe = json.loads(probe_raw)
        source = self.sources[self.host_id]
        source_raw = self.source_manifest_path.read_bytes()
        source_sha = sha(source_raw)
        identity = {
            "host_id": self.host_id, "run_id": job["run_id"],
            "report_nonce": "d" * 32, "allocator": "allocatbelt",
            "executor": "allocatbelt", "workload": "disk", "profile": "steady",
            "mode": "capacity", "source_sha256": source["source"]["source_tree_sha256"],
            "binary_sha256": self.binary_sha256, "pressure_qualification": False,
        }
        environment = stage._application_environment(
            identity, trace_dir, tmpdir, source5_preparation=True,
        )
        self.assertEqual(environment["ALLOCATBELT_APP_COMPARISON_FAMILY"], "external_pressure")
        self.assertEqual(environment["ALLOCATBELT_APP_PRESSURE_QUALIFICATION"], "false")
        self.assertNotIn("ALLOCATBELT_APP_CAPACITY_CALIBRATION_FILE", environment)
        self.assertNotIn("ALLOCATBELT_APP_CAPACITY_CALIBRATION_SHA256", environment)
        self.assertNotIn("ALLOCATBELT_APP_COMPARISON_FAMILY",
                         stage._application_environment(identity, trace_dir, tmpdir))

        process_context = self._source5_process_context()
        bound_proofs: list[dict[str, Any]] = []
        child = stage._spawn_with_source5_owner(
            process_context, [str(self.binary_path)], job_dir, environment,
            job_dir / "application.stdout", job_dir / "application.stderr", 30,
            self.binary_path, self.binary_sha256,
            job_dir / "application.process-capture.json",
            job_dir / "application.process-start.json", on_bound=bound_proofs.append,
        )
        self.assertEqual(child["status"], "completed")
        self.assertEqual(child["return_code"], 0)
        self.assertEqual(child["process_identity"]["environment"], environment)
        self.assertEqual(len(bound_proofs), 1)
        self.assertEqual(bound_proofs[0]["pid"], child["pid"])
        app_start = stage._verify_owned_process_start(
            process_context, job, self.stage_dir, child["direct_process"]["start"],
            [str(self.binary_path)], environment, self.binary_path,
            self.binary_sha256, child["pid"],
        )
        stage._verify_owned_process_capture(
            process_context, job, self.stage_dir, child["direct_process"]["capture"],
            app_start, [str(self.binary_path)], environment, self.binary_path,
            self.binary_sha256, 30, child["elapsed_ns"], child,
        )
        trace_hashes = {
            role: sha((trace_dir / name).read_bytes())
            for role, name in (
                ("manifest", "feedback-trace-manifest.tsv"),
                ("events", "feedback-events.jsonl"),
                ("samples", "resource-samples.tsv"),
            )
        }
        policy = stage._make_policy(identity, source, probe, feedback_fixtures.reader)
        self.assertEqual(policy["capacity_sources"], {"disk": False, "download": False})
        seed = stage._expectation_seed(
            identity, policy,
            {"path": str(self.source_manifest_path), "sha256": source_sha},
            {"path": str(probe_path), "sha256": sha(probe_raw)},
            "allocatbelt", self.binary_sha256, 10,
        )
        expectation_raw, expectation_sha, expectation = stage._finish_expectation(
            seed, child["pid"], feedback_fixtures.reader,
        )
        expectation_path = job_dir / "feedback-expectation.json"
        write_file(expectation_path, expectation_raw)
        validation = feedback_fixtures.reader.verify_feedback(
            expectation_path, expectation_sha, trace_dir, trace_hashes,
        )
        self.assertIs(validation["validated"], True)
        self.assertEqual(validation["mode"], "capacity_calibration")
        self.assertIs(validation["qualification_eligible"], False)
        self.assertIsNone(expectation["app_capacity_artifact_sha256"])
        self.assertGreater(
            capacity_producer.verify_no_actuation(
                trace_dir / "feedback-events.jsonl", trace_hashes["events"],
            ),
            0,
        )

    @staticmethod
    def _job_event(records: list[dict[str, Any]], run_id: str, event: str) -> dict[str, Any]:
        matches = [item for item in records if item.get("run_id") == run_id and item.get("event") == event]
        if len(matches) != 1:
            raise AssertionError(f"expected one {event} record for {run_id}, found {len(matches)}")
        return matches[0]

    @staticmethod
    def _different_sha(value: str) -> str:
        return "0" * 64 if value != "0" * 64 else "1" * 64

    def test_actual_cli_runs_fifteen_original_templates_and_replays_every_bundle(self) -> None:
        expected_keys = [
            item["capacity_key"] for item in self.plan["capacity_process_templates"]
            if item["capacity_key"]["host_id"] == self.host_id
        ]
        jobs = stage.derive_capacity_jobs(self.plan, self.host_id)
        self.assertEqual(len(jobs), 15)
        self.assertEqual([job["capacity_key"] for job in jobs], expected_keys)
        self.assertEqual(len({job["run_id"] for job in jobs}), 15)
        self.assertTrue(all(job["nonce_instantiation"]["pair_member"] == "capacity" for job in jobs))

        result = self._run_cli("run", timeout=360)
        completion, completion_path = self._completion(result)
        self.assertFalse(completion["qualification_eligible"])
        self.assertFalse(completion["controller_chronology_proven"])
        self.assertEqual(len(completion["entries"]), 15)
        self.assertEqual(completion["capacity_process_templates_sha256"],
                         self.plan["capacity_process_templates_sha256"])
        self.assertTrue(all(item["actual_pid"] > 0 and item["actual_start_ticks"] > 0
                            and item["actual_executable_sha256"] == self.binary_sha256
                            for item in completion["entries"]))

        ledger_records = [json.loads(line)["record"] for line in self.ledger_path.read_bytes().splitlines()]
        self.assertEqual([item["event"] for item in ledger_records[-1:]], ["stage_complete"])
        for job in jobs:
            transitions = [item["event"] for item in ledger_records if item["run_id"] == job["run_id"]]
            self.assertEqual(transitions, list(stage.JOB_EVENTS))

        audit = [json.loads(line) for line in self.audit_path.read_text().splitlines()]
        popens = [item for item in audit if item["kind"] == "popen"]
        self.assertEqual(len(popens), 30)
        self.assertEqual([item["event"] for item in popens],
                         [event for _ in jobs for event in ("probe_dispatch", "application_dispatch")])
        for index, item in enumerate(audit):
            if item["kind"] == "popen":
                self.assertGreater(index, 0)
                self.assertEqual(audit[index - 1]["kind"], "ledger_fsync")
                self.assertEqual(audit[index - 1]["event"], item["event"])
                self.assertEqual(audit[index - 1]["record_sha256"], item["record_sha256"])

        verified = self._verify_cli(completion_path)
        self.assertEqual(verified.returncode, 0, verified.stderr.decode("utf-8", errors="replace"))
        self.assertTrue(json.loads(verified.stdout)["complete"])

        first_run = completion["entries"][0]["run_id"]

        def change_field(event: str, path: tuple[str, ...], change: Any):
            def mutate(records: list[dict[str, Any]], _completion: dict[str, Any]) -> None:
                details = self._job_event(records, first_run, event)["details"]
                for part in path[:-1]:
                    details = details[part]
                details[path[-1]] = change(details[path[-1]])
            return mutate

        pin_cases = (
            ("probe_dispatch", ("expected_binary_sha256",), self._different_sha,
             "capacity probe dispatch is not directly bound to the frozen application binary"),
            ("probe_verified", ("probe_sha256",), self._different_sha,
             "verified policy probe source/output pins differ from captured source evidence"),
            ("probe_verified", ("source_manifest", "sha256"), self._different_sha,
             "verified policy probe source/output pins differ from captured source evidence"),
            ("application_dispatch", ("expected_binary_sha256",), self._different_sha,
             "capacity application dispatch differs from the frozen workload/profile/executor/deadlines"),
            ("application_dispatch", ("probe", "sha256"), self._different_sha,
             "capacity application dispatch differs from the frozen workload/profile/executor/deadlines"),
            ("application_dispatch", ("policy_sha256",), self._different_sha,
             "capacity application dispatch differs from the frozen workload/profile/executor/deadlines"),
            ("feedback_verified", ("process_identity_sha256",), self._different_sha,
             "feedback verification process-identity pin differs from the actual application-bound record"),
            ("feedback_verified", ("expectation_sha256",), self._different_sha,
             "feedback/bundle expectation or probe pins differ from their captured source roles"),
            ("feedback_verified", ("validation_sha256",), self._different_sha,
             "feedback/bundle validation or trace pins differ from their captured evidence roles"),
            ("bundle_verified", ("expectation", "sha256"), self._different_sha,
             "feedback/bundle expectation or probe pins differ from their captured source roles"),
            ("bundle_verified", ("validation", "sha256"), self._different_sha,
             "feedback/bundle validation or trace pins differ from their captured evidence roles"),
            ("bundle_verified", ("traces", "manifest", "sha256"), self._different_sha,
             "feedback/bundle validation or trace pins differ from their captured evidence roles"),
            ("bundle_verified", ("probe", "sha256"), self._different_sha,
             "feedback/bundle expectation or probe pins differ from their captured source roles"),
        )
        for event, path, change, expected_error in pin_cases:
            with self.subTest(event=event, path=path):
                self._rechain_and_reject(
                    completion_path, change_field(event, path, change), expected_error,
                )

        def change_probe_elapsed(records: list[dict[str, Any]], _completion: dict[str, Any]) -> None:
            dispatch = self._job_event(records, first_run, "probe_dispatch")["details"]
            completed = self._job_event(records, first_run, "probe_completed")["details"]
            completed["elapsed_ns"] = dispatch["deadline_seconds"] * 1_000_000_000 + 1

        def change_probe_signal(records: list[dict[str, Any]], _completion: dict[str, Any]) -> None:
            self._job_event(records, first_run, "probe_completed")["details"]["signal"] = signal.SIGTERM

        def change_app_elapsed(records: list[dict[str, Any]], _completion: dict[str, Any]) -> None:
            dispatch = self._job_event(records, first_run, "application_dispatch")["details"]
            exited = self._job_event(records, first_run, "application_exited")["details"]
            exited["elapsed_ns"] = dispatch["process_deadline_seconds"] * 1_000_000_000 + 1

        def change_app_signal(records: list[dict[str, Any]], _completion: dict[str, Any]) -> None:
            self._job_event(records, first_run, "application_exited")["details"]["signal"] = signal.SIGTERM

        for mutate, expected_error in (
            (change_probe_elapsed, "capacity policy probe elapsed time exceeds its frozen setup deadline"),
            (change_probe_signal, "capacity policy probe recorded a signal on completed exit"),
            (change_app_elapsed, "capacity application elapsed time exceeds its frozen process deadline"),
            (change_app_signal, "capacity application recorded a signal on completed exit"),
        ):
            self._rechain_and_reject(completion_path, mutate, expected_error)

        storage_entry = next(item for item in completion["entries"]
                             if item["workload"] in ("disk", "mixed"))
        storage_run = storage_entry["run_id"]
        alternate_tmpdir = Path.home() / f".capacity-stage-forged-tmpdir-{os.getpid()}"
        alternate_tmpdir.mkdir(mode=0o700, exist_ok=False)

        def change_storage_tmpdir(records: list[dict[str, Any]], forged: dict[str, Any]) -> None:
            probe_dispatch = self._job_event(records, storage_run, "probe_dispatch")["details"]
            app_dispatch = self._job_event(records, storage_run, "application_dispatch")["details"]
            bound = self._job_event(records, storage_run, "application_bound")["details"]
            feedback_verified = self._job_event(records, storage_run, "feedback_verified")["details"]
            tmpdir = str(alternate_tmpdir)
            probe_dispatch["environment"]["TMPDIR"] = tmpdir
            app_dispatch["tmpdir_path"] = tmpdir
            app_dispatch["environment"]["TMPDIR"] = tmpdir
            bound["tmpdir_path"] = tmpdir
            bound["environment"]["TMPDIR"] = tmpdir
            bound["environment_sha256"] = sha(canonical(bound["environment"]))
            feedback_verified["process_identity_sha256"] = sha(canonical(bound))
            for entry in forged["entries"]:
                if entry["run_id"] == storage_run:
                    entry["actual_environment_sha256"] = sha(canonical(app_dispatch["environment"]))

        try:
            self._rechain_and_reject(
                completion_path, change_storage_tmpdir,
                "application dispatch/bound TMPDIR differs from the validated storage context",
            )
        finally:
            shutil.rmtree(alternate_tmpdir, ignore_errors=True)

        original_ledger = self.ledger_path.read_bytes()
        original_completion = completion_path.read_bytes()
        envelopes = [json.loads(line) for line in original_ledger.splitlines()]
        records = [item["record"] for item in envelopes]
        timestamps = [item["monotonic_ns"] for item in records]
        records[1], records[2] = records[2], records[1]
        previous = "0" * 64
        reordered_lines: list[bytes] = []
        for sequence, record in enumerate(records, 1):
            record["sequence"] = sequence
            record["monotonic_ns"] = timestamps[sequence - 1]
            unsigned = {"previous_sha256": previous, "record": record}
            current = sha(canonical(unsigned))
            reordered_lines.append(canonical({**unsigned, "record_sha256": current}))
            previous = current
        self.ledger_path.chmod(0o600)
        self.ledger_path.write_bytes(b"".join(reordered_lines))
        completion_value = json.loads(original_completion)
        completion_value["ledger"]["raw_sha256"] = sha(self.ledger_path.read_bytes())
        completion_value["ledger"]["terminal_head"] = previous
        reordered_completion = canonical(completion_value)
        completion_path.write_bytes(reordered_completion)
        self.ledger_path.chmod(0o400)
        reordered_result = self._verify_cli(completion_path, sha(reordered_completion))
        self.assertEqual(reordered_result.returncode, 2,
                         "reordered transitions with a recomputed chain were accepted")
        self.assertIn("capacity stage ledger does not preserve the original plan template order",
                      reordered_result.stderr.decode("utf-8", errors="replace"))
        self.ledger_path.chmod(0o600)
        self.ledger_path.write_bytes(original_ledger)
        self.ledger_path.chmod(0o400)
        completion_path.write_bytes(original_completion)

        first = completion["entries"][0]
        artifact_path = Path(first["artifact"]["path"])
        artifact_original = artifact_path.read_bytes()
        artifact_path.chmod(0o600)
        artifact_path.write_bytes(artifact_original[:-1] + bytes([artifact_original[-1] ^ 1]))
        self.assertNotEqual(self._verify_cli(completion_path).returncode, 0,
                            "TSV mutation was accepted by the full CLI verifier")
        artifact_path.write_bytes(artifact_original)

        validation_path = Path(first["validation"]["path"])
        validation_original = validation_path.read_bytes()
        validation_path.write_bytes(validation_original + b" ")
        self.assertNotEqual(self._verify_cli(completion_path).returncode, 0,
                            "forged validation bytes were accepted by the full CLI verifier")
        validation_path.write_bytes(validation_original)

        ledger_original = self.ledger_path.read_bytes()
        self.ledger_path.chmod(0o600)
        self.ledger_path.write_bytes(ledger_original[:-1])
        self.assertNotEqual(self._verify_cli(completion_path).returncode, 0,
                            "truncated ledger was accepted by the full CLI verifier")
        self.ledger_path.write_bytes(ledger_original)
        self.ledger_path.chmod(0o400)

        context_template_pin = self.plan["capacity_process_templates"][jobs[0]["template_index"]]["context_template"]
        context_template_path = self.input_root / context_template_pin["relative_path"]
        context_original = context_template_path.read_bytes()
        context_template_path.write_bytes(context_original[:-1] + b" ")
        self.assertNotEqual(self._verify_cli(completion_path).returncode, 0,
                            "context template source drift was accepted")
        context_template_path.write_bytes(context_original)

        completion_original = completion_path.read_bytes()
        forged = json.loads(completion_original)
        forged["complete"] = False
        forged_raw = canonical(forged)
        completion_path.write_bytes(forged_raw)
        self.assertNotEqual(self._verify_cli(completion_path, sha(forged_raw)).returncode, 0,
                            "forged completion status was accepted")
        completion_path.write_bytes(completion_original)

        active_stage_original = STAGE_PATH.read_bytes()
        try:
            STAGE_PATH.write_bytes(active_stage_original + b"\n")
            drifted = self._verify_cli(completion_path)
            self.assertNotEqual(drifted.returncode, 0,
                                "stage source drift was accepted against the SourceV5 inventory")
        finally:
            STAGE_PATH.write_bytes(active_stage_original)

    def test_missing_duplicate_and_reordered_contexts_follow_the_frozen_map(self) -> None:
        jobs = stage.derive_capacity_jobs(self.plan, self.host_id)
        self.assertEqual([job["template_index"] for job in jobs], sorted(job["template_index"] for job in jobs))
        missing = copy.deepcopy(self.plan)
        selected_index = next(
            index for index, item in enumerate(missing["capacity_process_templates"])
            if item["capacity_key"]["host_id"] == self.host_id
        )
        missing["capacity_process_templates"].pop(selected_index)
        with self.assertRaises(stage.CapacityStageError):
            stage.derive_capacity_jobs(missing, self.host_id)

        duplicate = copy.deepcopy(self.plan)
        selected_indices = [
            index for index, item in enumerate(duplicate["capacity_process_templates"])
            if item["capacity_key"]["host_id"] == self.host_id
        ]
        duplicate["capacity_process_templates"][selected_indices[1]]["capacity_key"] = dict(
            duplicate["capacity_process_templates"][selected_indices[0]]["capacity_key"]
        )
        body = duplicate["capacity_process_templates"][selected_indices[1]]
        body_without_sha = {key: value for key, value in body.items() if key != "template_sha256"}
        body["template_sha256"] = sha(canonical(body_without_sha))
        duplicate["capacity_process_templates_sha256"] = sha(canonical(duplicate["capacity_process_templates"]))
        with self.assertRaises(stage.CapacityStageError):
            stage.derive_capacity_jobs(duplicate, self.host_id)

        reordered = copy.deepcopy(self.plan)
        items = reordered["capacity_process_templates"]
        selected = [index for index, item in enumerate(items) if item["capacity_key"]["host_id"] == self.host_id]
        replacement = [items[index] for index in reversed(selected)]
        iterator = iter(replacement)
        reordered["capacity_process_templates"] = [
            next(iterator) if item["capacity_key"]["host_id"] == self.host_id else item
            for item in items
        ]
        reordered["capacity_process_templates_sha256"] = sha(canonical(reordered["capacity_process_templates"]))
        reordered_jobs = stage.derive_capacity_jobs(reordered, self.host_id)
        self.assertEqual([item["capacity_key"] for item in reordered_jobs],
                         list(reversed([item["capacity_key"] for item in jobs])))

    def test_child_failure_never_publishes_a_success_overlay(self) -> None:
        self.failure_flag.touch(mode=0o600)
        failed = self._run_cli("run", timeout=180)
        self.assertEqual(failed.returncode, 2)
        self.assertFalse((self.stage_dir / "capacity-stage-completion.json").exists())
        ledger = [json.loads(line)["record"] for line in self.ledger_path.read_bytes().splitlines()]
        self.assertIn("application_exited", [item["event"] for item in ledger])
        self.assertEqual(next(item for item in ledger if item["event"] == "application_exited")["details"]["return_code"], 41)
        self.assertEqual(ledger[-1]["event"], "stage_failed")
        self.failure_flag.unlink()

    def test_signal_interrupt_kills_the_direct_application_process_group(self) -> None:
        self.hang_flag.touch(mode=0o600)
        process = subprocess.Popen(
            self._cli_args("run"), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=self._environment(),
        )
        marker: Path | None = None
        deadline = time.monotonic() + 180
        try:
            while time.monotonic() < deadline:
                markers = list(self.output_root.rglob("fake-app.pid"))
                if markers:
                    marker = markers[0]
                    break
                if process.poll() is not None:
                    stdout, stderr = process.communicate()
                    self.fail("capacity stage exited before the fake application launch: " +
                              stderr.decode("utf-8", errors="replace") + stdout.decode("utf-8", errors="replace"))
                time.sleep(0.1)
            self.assertIsNotNone(marker, "fake application never reached its bounded hang witness")
            fake_pid = int(marker.read_text().strip())
            process.send_signal(signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=30)
            self.assertEqual(process.returncode, 2, stderr.decode("utf-8", errors="replace"))
            self.assertFalse((self.stage_dir / "capacity-stage-completion.json").exists())
            records = [json.loads(line)["record"] for line in self.ledger_path.read_bytes().splitlines()]
            exit_record = next(item for item in records if item["event"] == "application_exited")
            self.assertEqual(exit_record["details"]["status"], "interrupted")
            self.assertEqual(exit_record["details"]["signal"], signal.SIGTERM)
            self.assertEqual(records[-1]["event"], "stage_failed")
            self.assertEqual(records[-1]["details"]["signal"], signal.SIGTERM)
            with self.assertRaises(ProcessLookupError):
                os.killpg(fake_pid, 0)
        finally:
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
            self.hang_flag.unlink(missing_ok=True)

    def test_bounded_supervisor_records_timeout_and_reaps_the_fake_child(self) -> None:
        with tempfile.TemporaryDirectory(prefix="capacity-stage-timeout-") as temporary:
            root = Path(temporary)
            stdout = root / "stdout"
            stderr = root / "stderr"
            result = stage._spawn_bounded(
                [str(self.binary_path), "--test-wait"], root,
                {"PATH": "/usr/bin:/bin"}, stdout, stderr, 1,
                self.binary_path, self.binary_sha256, capture_identity=False,
            )
            self.assertEqual(result["status"], "timeout")
            self.assertLess(result["return_code"], 0)
            with self.assertRaises(ProcessLookupError):
                os.killpg(result["pid"], 0)


def fake_capacity_child(source_path: str) -> int:
    """Emit a bounded synthetic V4 trace from the actual direct fake child."""
    environment = os.environ
    trace_dir = Path(environment["ALLOCATBELT_APP_FEEDBACK_TRACE_DIR"])
    job_dir = trace_dir.parent
    source_raw = Path(source_path).read_bytes()
    source_value = json.loads(source_raw)
    probe_path = job_dir / "policy-probe.json"
    probe_raw = probe_path.read_bytes()
    probe = json.loads(probe_raw)
    identity = {
        "host_id": environment["ALLOCATBELT_APP_HOST_ID"],
        "run_id": environment["ALLOCATBELT_APP_RUN_ID"],
        "report_nonce": environment["ALLOCATBELT_APP_REPORT_NONCE"],
        "process_id": os.getppid(),
        "allocator": environment["ALLOCATBELT_APP_ALLOCATOR"],
        "executor": environment["ALLOCATBELT_APP_EXECUTOR"],
        "workload": environment["ALLOCATBELT_APP_WORKLOAD"],
        "profile": environment["ALLOCATBELT_APP_PROFILE"],
        "mode": "capacity",
        "source_sha256": environment["ALLOCATBELT_APP_SOURCE_SHA256"],
        "binary_sha256": environment["ALLOCATBELT_APP_BINARY_SHA256"],
        "pressure_qualification": False,
    }
    require_values = (
        identity["source_sha256"] == source_value["source"]["source_tree_sha256"]
        and identity["binary_sha256"] == source_value["artifacts"]["allocatbelt"]["sha256"]
        and identity["allocator"] == "allocatbelt"
        and identity["process_id"] > 0
    )
    if not require_values:
        return 3
    builder = object.__new__(feedback_fixtures.Fixture)
    builder.identity = identity
    builder.policy = feedback_fixtures._v4_policy_from_source(
        identity, source_value, probe["collector"]["control_charge_bytes"],
    )
    original_sample_row = feedback_fixtures._sample_row

    def capacity_sample_row(*args: Any, **kwargs: Any) -> bytes:
        raw = original_sample_row(*args, **kwargs)
        fields = raw.decode("ascii").rstrip("\n").split("\t")
        positions = {name: index for index, name in enumerate(feedback_fixtures.reader.SAMPLE_HEADER)}
        for owner in ("global", "tenant"):
            for resource in feedback_fixtures.reader.DOMAIN:
                used_key = f"{owner}_used_{resource}"
                ceiling_key = f"{owner}_ceiling_{resource}"
                fields[positions[used_key]] = str(min(
                    int(fields[positions[used_key]]), int(fields[positions[ceiling_key]]),
                ))
        for used_key, limit_key in (
            ("scope_managed_memory_used", "scope_managed_memory_limit"),
            ("scope_disk_operations_used", "scope_disk_operation_limit"),
            ("scope_network_operations_used", "scope_network_operation_limit"),
        ):
            fields[positions[used_key]] = str(min(
                int(fields[positions[used_key]]), int(fields[positions[limit_key]]),
            ))
        return ("\t".join(fields) + "\n").encode("ascii")

    feedback_fixtures._sample_row = capacity_sample_row
    builder.capacity_trace = True
    builder.trace = trace_dir
    body = {
        "schema": feedback_fixtures.reader.EXPECTATION_SCHEMA_V4,
        "mode": "capacity_calibration", "identity": identity,
        "policy": builder.policy, "app_capacity_artifact_sha256": None,
        "construction_probe": {
            "path": str(probe_path), "raw_sha256": sha(probe_raw),
            "allocator": identity["allocator"], "binary_sha256": identity["binary_sha256"],
        },
        "host_binding": {"path": str(Path(source_path)), "raw_sha256": sha(source_raw)},
        "external_pressure_proof": None, "final_runtime_binding": None,
        "minimum_production_seconds": 30, "minimum_pressure_overlap_seconds": 0,
    }
    _expectation_raw, _expectation_sha = feedback_fixtures.reader.build_pressure_expectation_recipe(body)
    builder._write_trace()
    return 0


if __name__ == "__main__":
    import sys

    if len(sys.argv) == 3 and sys.argv[1] == "--fake-capacity-child":
        raise SystemExit(fake_capacity_child(sys.argv[2]))
    unittest.main(verbosity=2)
