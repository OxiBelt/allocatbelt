#!/usr/bin/env python3
"""CLI and full-replay witnesses for one bounded SourceV5 capacity stage."""
from __future__ import annotations

import copy
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import platform
import shutil
import signal
import stat
import subprocess
import tempfile
import textwrap
import time
import unittest
from pathlib import Path
from typing import Any


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
            if marker is not None:
                try:
                    process_group = int(marker.read_text().strip())
                    os.killpg(process_group, signal.SIGKILL)
                except (OSError, ValueError):
                    pass
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
