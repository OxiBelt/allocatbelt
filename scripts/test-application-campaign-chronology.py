#!/usr/bin/env python3
"""Native CLI witnesses for the locked SourceV5 campaign chronology APIs."""
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
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
SOURCE_ROOT = SCRIPT_DIR.parent
CAPACITY_TEST_PATH = SCRIPT_DIR / "test-application-capacity-stage.py"
CHRONOLOGY_SCHEMA = "allocatbelt.application-campaign-chronology.v2"
SIGNED_E4_PAIR_RUNNER_SHA256 = "e758b608bf3d6b4373178cdf4993046c981de29a2c3bf197079fe3e0285de088"
SYNTHETIC_PAIR_RUNNER = r"""#!/usr/bin/env bash
set -euo pipefail
sleep 0.15
printf '%s\n' "$$" > "${CHRONOLOGY_RUNNER_PID_MARKER:?}"
printf '%s\n' "$7" > "${CHRONOLOGY_RUNNER_RUN_ID_MARKER:?}"
if [[ -n "${CHRONOLOGY_RUNNER_WAIT_FLAG:-}" && -e "$CHRONOLOGY_RUNNER_WAIT_FLAG" ]]; then
  wait_mode="$(<"$CHRONOLOGY_RUNNER_WAIT_FLAG")"
  if [[ "$wait_mode" == descendant ]]; then
    (trap '' TERM; while :; do sleep 1; done) &
    descendant=$!
    printf '%s\n' "$descendant" > "${CHRONOLOGY_RUNNER_PID_MARKER}.descendant"
    exit 0
  fi
  if [[ "$wait_mode" == escaped-normal || "$wait_mode" == escaped-timeout ||
        "$wait_mode" == escaped-interrupt ]]; then
    python3 -c 'import os,signal,sys,time; os.setpgid(0,0); signal.signal(signal.SIGTERM,signal.SIG_IGN); tail=open("/proc/self/stat").read().rsplit(")",1)[1].split(); open(sys.argv[2],"w").write(str(os.getpid())+":"+tail[19]+"\n"); exec("while os.path.exists(sys.argv[1]): time.sleep(0.01)")' "$CHRONOLOGY_RUNNER_WAIT_FLAG" "${CHRONOLOGY_RUNNER_PID_MARKER}.escaped" &
    if [[ "$wait_mode" == escaped-normal ]]; then
      exit 0
    fi
  fi
  while [[ -e "$CHRONOLOGY_RUNNER_WAIT_FLAG" ]]; do
    sleep 0.02
  done
fi
exit 0
"""


def load_script(path: Path, name: str):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    if spec is None:
        raise RuntimeError(f"cannot load native chronology fixture {path}")
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


capacity_fixtures = load_script(CAPACITY_TEST_PATH, "campaign_chronology_capacity_fixtures")


CHRONOLOGY_SITECUSTOMIZE = r"""
import json
import os
import signal
import subprocess

_real_fsync = os.fsync
_real_popen = subprocess.Popen
_real_waitpid = os.waitpid
_real_waitid = os.waitid
_real_killpg = os.killpg
_real_scandir = os.scandir
_capacity_ledger = os.environ.get("CHRONOLOGY_CAPACITY_LEDGER")
_journal = os.environ.get("CHRONOLOGY_JOURNAL")
_audit = os.environ.get("CHRONOLOGY_AUDIT")
_fake_binary = os.environ.get("CHRONOLOGY_FAKE_BINARY")
_runner = os.environ.get("CHRONOLOGY_PAIR_RUNNER")
_owned_runner_pids = set()
_reaped_runner_pids = set()
_fail_owned_scan = os.environ.get("CHRONOLOGY_FAIL_OWNED_SCAN")
_owned_scan_failed = False
_flip_sigchld_during_owned_scan = os.environ.get("CHRONOLOGY_FLIP_SIGCHLD_DURING_OWNED_SCAN")
_owned_scan_sigchld_flipped = False
_sigchld_mode = os.environ.get("CHRONOLOGY_SIGCHLD_MODE")
if _sigchld_mode == "ignore_before":
    signal.signal(signal.SIGCHLD, signal.SIG_IGN)
elif _sigchld_mode == "custom_before":
    signal.signal(signal.SIGCHLD, lambda _signum, _frame: None)

def _append(item):
    with open(_audit, "a", encoding="utf-8") as output:
        output.write(json.dumps(item, sort_keys=True, separators=(",", ":")) + "\n")

def _last_record(path):
    with open(path, "rb") as source:
        line = source.read().splitlines()[-1]
    return json.loads(line)

def _instrumented_fsync(fd):
    result = _real_fsync(fd)
    if not _audit:
        return result
    try:
        current = os.fstat(fd)
        for role, path in (("capacity", _capacity_ledger), ("chronology", _journal)):
            if not path:
                continue
            named = os.stat(path, follow_symlinks=False)
            if (current.st_dev, current.st_ino) == (named.st_dev, named.st_ino):
                envelope = _last_record(path)
                record = envelope.get("record", {})
                _append({"kind": "ledger_fsync", "role": role,
                         "event": record.get("event"),
                         "record_sha256": envelope.get("record_sha256")})
    except (FileNotFoundError, IndexError, OSError):
        pass
    return result

def _instrumented_waitpid(pid, options):
    if pid in _owned_runner_pids:
        _append({"kind": "runner_waitpid_attempt", "pid": pid})
    result = _real_waitpid(pid, options)
    if result[0] in _owned_runner_pids:
        _reaped_runner_pids.add(result[0])
        _append({"kind": "runner_reaped", "pid": result[0]})
    return result

def _instrumented_waitid(idtype, id, options):
    if id in _owned_runner_pids:
        _append({"kind": "runner_waitid_attempt", "pid": id, "options": options})
    result = _real_waitid(idtype, id, options)
    if result is not None and result.si_pid in _owned_runner_pids and not options & os.WNOWAIT:
        _reaped_runner_pids.add(result.si_pid)
        _append({"kind": "runner_reaped", "pid": result.si_pid})
    return result

def _instrumented_killpg(group_id, signum):
    if group_id in _reaped_runner_pids:
        _append({"kind": "post_reap_group_operation", "pid": group_id,
                 "signal": signum})
        raise RuntimeError("numeric process-group operation followed direct leader reap")
    if group_id in _owned_runner_pids:
        _append({"kind": "runner_group_signal", "pid": group_id,
                 "signal": signum})
    return _real_killpg(group_id, signum)

def _instrumented_scandir(path="."):
    global _owned_scan_failed, _owned_scan_sigchld_flipped
    if (_fail_owned_scan and not _owned_scan_failed and _owned_runner_pids and
            os.fspath(path) == "/proc"):
        _owned_scan_failed = True
        _append({"kind": "owned_session_scan_failure",
                 "pid": sorted(_owned_runner_pids)[-1]})
        raise PermissionError("injected owned-session scanner failure")
    entries = _real_scandir(path)
    if (_flip_sigchld_during_owned_scan and not _owned_scan_sigchld_flipped and
            _owned_runner_pids and os.fspath(path) == "/proc"):
        entries = list(entries)
        pid = sorted(_owned_runner_pids)[-1]
        try:
            with open(f"/proc/{pid}/stat", encoding="ascii") as stat_file:
                stat_text = stat_file.read()
            fields = stat_text[stat_text.rfind(")") + 1:].split()
            state, process_group_id, session_id = fields[0], int(fields[2]), int(fields[3])
            start_ticks = int(fields[19])
        except (OSError, ValueError, IndexError):
            state, process_group_id, session_id, start_ticks = "missing", -1, -1, -1
        if state not in ("Z", "X") and process_group_id == pid and session_id == pid:
            signal.signal(signal.SIGCHLD, signal.SIG_IGN)
            _owned_scan_sigchld_flipped = True
            disposition = "SIG_IGN" if signal.getsignal(signal.SIGCHLD) == signal.SIG_IGN else "other"
            _append({"kind": "owned_scan_sigchld_changed", "pid": pid,
                     "state": state, "process_group_id": process_group_id,
                     "session_id": session_id, "start_ticks": start_ticks,
                     "signal_disposition": disposition})
        else:
            _append({"kind": "owned_scan_sigchld_change_rejected", "pid": pid,
                     "state": state, "process_group_id": process_group_id,
                     "session_id": session_id, "start_ticks": start_ticks})
        return entries
    return entries
    return _real_scandir(path)

def _instrumented_popen(args, *positional, **keywords):
    values = args if isinstance(args, (list, tuple)) else [args]
    program = os.path.realpath(os.fspath(values[0])) if values else ""
    is_runner = bool(_runner and program == os.path.realpath(_runner))
    if _fake_binary and program == os.path.realpath(_fake_binary):
        envelope = _last_record(_capacity_ledger)
        record = envelope["record"]
        with open(_audit, "r", encoding="utf-8") as source:
            prior = [json.loads(line) for line in source if line.strip()]
        expected = {"kind": "ledger_fsync", "role": "capacity",
                    "event": record["event"],
                    "record_sha256": envelope["record_sha256"]}
        if not prior or prior[-1] != expected:
            raise RuntimeError("capacity child Popen occurred before its matching ledger fsync")
        if record["event"] not in ("probe_dispatch", "application_dispatch"):
            raise RuntimeError("capacity child Popen followed a non-dispatch record")
        _append({"kind": "popen", "role": "capacity", "event": record["event"],
                 "record_sha256": envelope["record_sha256"]})
    elif is_runner:
        envelope = _last_record(_journal)
        record = envelope["record"]
        with open(_audit, "r", encoding="utf-8") as source:
            prior = [json.loads(line) for line in source if line.strip()]
        expected = {"kind": "ledger_fsync", "role": "chronology",
                    "event": "dispatch_authorized",
                    "record_sha256": envelope["record_sha256"]}
        if record.get("event") != "dispatch_authorized" or not prior or prior[-1] != expected:
            raise RuntimeError("pair-runner Popen occurred before its matching authorization fsync")
        _append({"kind": "popen", "role": "campaign_pair_runner",
                 "event": record["event"],
                 "record_sha256": envelope["record_sha256"]})
    process = _real_popen(args, *positional, **keywords)
    if is_runner:
        _owned_runner_pids.add(process.pid)
        if _sigchld_mode == "ignore_after_popen":
            signal.signal(signal.SIGCHLD, signal.SIG_IGN)
    return process

os.fsync = _instrumented_fsync
os.waitpid = _instrumented_waitpid
os.waitid = _instrumented_waitid
os.killpg = _instrumented_killpg
os.scandir = _instrumented_scandir
subprocess.Popen = _instrumented_popen
"""


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def write_file(path: Path, raw: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC |
                         getattr(os, "O_CLOEXEC", 0), mode)
    try:
        os.fchmod(descriptor, mode)
        offset = 0
        while offset < len(raw):
            offset += os.write(descriptor, raw[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def configure_synthetic_source_fixture(fixture_class: type) -> Path:
    campaign = capacity_fixtures.input_fixtures.campaign
    sources = copy.deepcopy(fixture_class.sources)
    spec = copy.deepcopy(fixture_class.spec)
    original_jobs = copy.deepcopy(fixture_class.plan["jobs"])
    source_root = fixture_class.root_temp / "synthetic-source"
    source_root.mkdir(mode=0o700)
    shutil.copytree(SOURCE_ROOT / ".git", source_root / ".git", symlinks=True)

    records = sources[fixture_class.host_id]["source"]["files"]
    for record in records:
        relative = Path(record["path"])
        source_path = SOURCE_ROOT / relative
        target_path = source_root / relative
        if record["kind"] == "file":
            write_file(target_path, source_path.read_bytes(), int(record["mode"], 8) & 0o777)
        elif record["kind"] == "symlink":
            target_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.symlink(os.readlink(source_path), target_path)
        else:
            raise AssertionError(f"unsupported synthetic SourceV5 file kind {record['kind']!r}")

    artifact_paths: set[str] = set()
    for source in sources.values():
        artifact_paths.update(item["path"] for item in source["artifacts"].values())
        artifact_paths.update(item["path"] for item in source["soak_artifacts"].values())
        artifact_paths.add(source["analysis_artifact"]["path"])
        calibration = source["resource_domain_calibration"]
        artifact_paths.add(calibration["binary"]["path"])
        artifact_paths.add(calibration["output"]["path"])
    for relative_text in sorted(artifact_paths):
        source_path = SOURCE_ROOT / relative_text
        target_path = source_root / relative_text
        if target_path.exists() or target_path.is_symlink():
            continue
        info = source_path.lstat()
        if stat.S_ISLNK(info.st_mode):
            target_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.symlink(os.readlink(source_path), target_path)
        else:
            write_file(target_path, source_path.read_bytes(), stat.S_IMODE(info.st_mode))

    runner_raw = SYNTHETIC_PAIR_RUNNER.encode("utf-8")
    runner_path = source_root / "scripts/run-application-pair.sh"
    write_file(runner_path, runner_raw, 0o755)
    runner_sha256 = sha(runner_raw)
    for source in sources.values():
        matches = [record for record in source["source"]["files"]
                   if record["path"] == "scripts/run-application-pair.sh"]
        if len(matches) != 1 or matches[0]["kind"] != "file" or matches[0]["mode"] != "100755":
            raise AssertionError("synthetic SourceV5 runner must replace one executable regular inventory entry")
        matches[0]["sha256"] = runner_sha256
        matches[0]["size"] = len(runner_raw)
        tree_sha256 = campaign.source_inventory_module().digest_records(source["source"]["files"])
        source["source"]["source_tree_sha256"] = tree_sha256
        source["resource_domain_calibration"]["source"]["source_tree_sha256"] = tree_sha256
        source["manifest_sha256"] = campaign.digest_object(
            {key: value for key, value in source.items() if key != "manifest_sha256"}
        )
    spec["runner_sha256"] = runner_sha256
    for reference in spec["source_manifests"]:
        host_id = reference["host_id"]
        reference["sha256"] = sources[host_id]["manifest_sha256"]
        manifest_path = fixture_class.spec_path.parent / reference["relative_path"]
        write_file(manifest_path, canonical(sources[host_id]))

    selected_source = sources[fixture_class.host_id]
    feedback = capacity_fixtures.feedback_fixtures
    for workload in capacity_fixtures.stage.WORKLOADS:
        for profile in capacity_fixtures.stage.PROFILES[workload]:
            identity = {
                "host_id": fixture_class.host_id, "run_id": "probe-fixture",
                "report_nonce": "a" * 32, "process_id": 1,
                "allocator": "allocatbelt", "executor": "allocatbelt",
                "workload": workload, "profile": profile, "mode": "capacity",
                "source_sha256": selected_source["source"]["source_tree_sha256"],
                "binary_sha256": fixture_class.binary_sha256,
                "pressure_qualification": False,
            }
            builder = object.__new__(feedback.Fixture)
            builder.identity = identity
            builder.policy = feedback._v4_policy_from_source(identity, selected_source)
            probe = builder._construction_probe()
            write_file(fixture_class.probe_root / f"{workload}-{profile}.json", canonical(probe))

    fixture_class.spec = spec
    fixture_class.sources = sources
    spec_raw = canonical(spec)
    write_file(fixture_class.spec_path, spec_raw)
    fixture_class.plan = campaign.freeze_plan(spec, sources, fixture_class.input_root)
    if fixture_class.plan["jobs"] != original_jobs:
        raise AssertionError("synthetic SourceV5 fixture changed the original PlanV3 job matrix")
    fixture_class.original_jobs = original_jobs
    plan_raw = campaign.campaign_plan_bytes(fixture_class.plan)
    write_file(fixture_class.plan_path, plan_raw)
    fixture_class.spec_sha256 = sha(spec_raw)
    fixture_class.plan_sha256 = sha(plan_raw)
    fixture_class.source_manifest_sha256 = sha(
        canonical(sources[fixture_class.host_id])
    )
    fixture_class.binary_path = source_root / sources[fixture_class.host_id]["artifacts"]["allocatbelt"]["path"]
    fixture_class.source_tree = source_root

    actual_tree_sha256, actual_records = campaign.source_inventory(source_root)
    if actual_tree_sha256 != selected_source["source"]["source_tree_sha256"] or \
            actual_records != selected_source["source"]["files"]:
        raise AssertionError("synthetic SourceV5 worktree differs from its rewritten regular-file inventory")
    for host_id, source in sources.items():
        campaign.verify_source_manifest(
            source, source_root if host_id == fixture_class.host_id else None,
            verify_artifacts=(host_id == fixture_class.host_id),
        )
    return source_root


class CampaignChronologyCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if platform.system() != "Linux" or platform.machine() != "x86_64" or not hasattr(os, "sched_getaffinity"):
            raise unittest.SkipTest("campaign chronology witness requires the frozen native x86_64 Linux host")
        compiler = shutil.which("cc")
        if compiler is None:
            raise unittest.SkipTest("campaign chronology witness needs a native C compiler for bounded fake apps")
        rustc_verbose = subprocess.check_output(["rustc", "-Vv"], text=True).splitlines()
        rustc_release = next((line.split(" ", 2)[1] for line in rustc_verbose
                              if line.startswith("rustc ")), "")
        if rustc_release != "1.99.0":
            raise unittest.SkipTest("campaign chronology witness requires the frozen Rust 1.99.0 source contract")

        fixture_class = capacity_fixtures.CapacityStageCliTests
        capacity_fixtures.sys = sys
        original_fixture = capacity_fixtures.input_fixtures.spec_v3_fixture

        def frozen_fixed_matrix():
            spec, sources = original_fixture()
            capacity_fixtures.input_fixtures.fixtures.add_frozen_rates(spec, include_oracles=True)
            spec["runner_sha256"] = sha((SCRIPT_DIR / "run-application-pair.sh").read_bytes())
            return spec, sources

        capacity_fixtures.input_fixtures.spec_v3_fixture = frozen_fixed_matrix
        try:
            fixture_class.setUpClass()
        finally:
            capacity_fixtures.input_fixtures.spec_v3_fixture = original_fixture
        synthetic_source_root = configure_synthetic_source_fixture(fixture_class)
        cls.fixture = fixture_class
        cls.root_temp = fixture_class.root_temp
        cls.host_id = fixture_class.host_id
        cls.campaign_id = fixture_class.campaign_id
        cls.instrumentation = fixture_class.instrumentation
        write_file(cls.instrumentation / "sitecustomize.py",
                   CHRONOLOGY_SITECUSTOMIZE.encode("utf-8"))
        cls.spec_path = fixture_class.spec_path
        cls.plan_path = fixture_class.plan_path
        cls.observed_host_path = fixture_class.observed_host_path
        cls.input_root = fixture_class.input_root
        cls.plan = fixture_class.plan
        cls.spec = fixture_class.spec
        cls.spec_sha256 = fixture_class.spec_sha256
        cls.plan_sha256 = fixture_class.plan_sha256
        cls.observed_host_sha256 = fixture_class.observed_host_sha256
        cls.binary_path = fixture_class.binary_path
        cls.binary_sha256 = fixture_class.binary_sha256
        cls.failure_flag = fixture_class.failure_flag
        cls.hang_flag = fixture_class.hang_flag
        cls.source_root = synthetic_source_root
        cls.runner_path = synthetic_source_root / "scripts/run-application-pair.sh"
        cls.chronology_module = load_script(
            synthetic_source_root / "scripts/application-campaign-chronology.py",
            "campaign_chronology_synthetic_target",
        )

    @classmethod
    def tearDownClass(cls) -> None:
        fixture_class = getattr(cls, "fixture", None)
        if fixture_class is not None:
            if getattr(cls, "preserve_temp", False):
                fixture_class.preserve_temp = True
            fixture_class.tearDownClass()

    def setUp(self) -> None:
        self.output_root = self.root_temp / f"chronology-{self._testMethodName}"
        self.output_root.mkdir(mode=0o700)
        self.audit_path = self.root_temp / f"chronology-audit-{self._testMethodName}.jsonl"
        self.audit_path.unlink(missing_ok=True)
        self.tmp_root = self.root_temp / f"chronology-tmp-{self._testMethodName}"
        self.tmp_root.mkdir(mode=0o700)

    def tearDown(self) -> None:
        outcome = getattr(getattr(self, "_outcome", None), "result", None)
        if outcome is not None and not outcome.wasSuccessful():
            type(self).preserve_temp = True

    @property
    def journal_path(self) -> Path:
        return (self.output_root / self.campaign_id / "chronology" /
                self.host_id / "dispatch-journal.jsonl")

    @property
    def capacity_ledger_path(self) -> Path:
        return (self.output_root / self.campaign_id / "capacity" /
                self.host_id / "controller-ledger.jsonl")

    def _environment(self, *, tmp_root: Path | None = None,
                      journal_path: Path | None = None,
                      capacity_output_root: Path | None = None) -> dict[str, str]:
        selected_tmp_root = tmp_root or self.tmp_root
        environment = dict(os.environ)
        for key in ("BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS"):
            environment.pop(key, None)
        for key in ("CHRONOLOGY_SIGCHLD_MODE", "CHRONOLOGY_FAIL_OWNED_SCAN"):
            environment.pop(key, None)
        for key in [key for key in environment if key.startswith("BASH_FUNC_")]:
            environment.pop(key, None)
        environment.update({
            "PYTHONPATH": str(self.instrumentation),
            "CHRONOLOGY_CAPACITY_LEDGER": str(
                (capacity_output_root or self.output_root) / self.campaign_id /
                "capacity" / self.host_id / "controller-ledger.jsonl"),
            "CHRONOLOGY_JOURNAL": str(journal_path or self.journal_path),
            "CHRONOLOGY_AUDIT": str(self.audit_path),
            "CHRONOLOGY_FAKE_BINARY": str(self.binary_path),
            "CHRONOLOGY_PAIR_RUNNER": str(self.runner_path),
            "CHRONOLOGY_RUNNER_WAIT_FLAG": str(self.hang_flag),
            "CHRONOLOGY_RUNNER_PID_MARKER": str(selected_tmp_root / "campaign-pair-runner.pid"),
            "CHRONOLOGY_RUNNER_RUN_ID_MARKER": str(selected_tmp_root / "campaign-pair-runner.run-id"),
            "TMPDIR": str(selected_tmp_root),
        })
        return environment

    def _common_args(self, output_root: Path | None = None,
                     capacity_output_root: Path | None = None) -> list[str]:
        args = [
            "--plan", str(self.plan_path), "--plan-sha256", self.plan_sha256,
            "--spec", str(self.spec_path), "--spec-sha256", self.spec_sha256,
            "--source-root", str(self.source_root), "--input-root", str(self.input_root),
            "--host-id", self.host_id, "--observed-host", str(self.observed_host_path),
            "--observed-host-sha256", self.observed_host_sha256,
            "--output-root", str(output_root or self.output_root),
        ]
        if capacity_output_root is not None:
            args.extend(["--capacity-output-root", str(capacity_output_root)])
        return args

    def _run_cli(self, command: str, *, extra: list[str] | None = None,
                 timeout: int = 360, output_root: Path | None = None,
                 capacity_output_root: Path | None = None,
                 environment: dict[str, str] | None = None) -> subprocess.CompletedProcess[bytes]:
        chronology_path = self.source_root / "scripts/application-campaign-chronology.py"
        arguments = [sys.executable, "-B", str(chronology_path), command,
                     *self._common_args(output_root, capacity_output_root)]
        if extra:
            arguments.extend(extra)
        env = environment or self._environment(
            journal_path=((output_root or self.output_root) / self.campaign_id /
                          "chronology" / self.host_id / "dispatch-journal.jsonl"),
            capacity_output_root=capacity_output_root or output_root,
        )
        return subprocess.run(arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              env=env, timeout=timeout, check=False)

    def _completion(self, result: subprocess.CompletedProcess[bytes]) -> tuple[dict[str, Any], dict[str, str]]:
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))
        value = json.loads(result.stdout)
        completion_pin = value["completion"]
        return json.loads(Path(completion_pin["path"]).read_bytes()), completion_pin

    def _register(self, completion_pin: dict[str, str]) -> subprocess.CompletedProcess[bytes]:
        return self._run_cli("register", extra=[
            "--completion", completion_pin["path"],
            "--completion-sha256", completion_pin["sha256"],
        ])

    def _stage_and_register(self) -> tuple[dict[str, Any], dict[str, str]]:
        stage_result = self._run_cli("run", timeout=360)
        completion, completion_pin = self._completion(stage_result)
        self.assertIs(completion["complete"], True)
        self.assertIs(completion["qualification_eligible"], False)
        self.assertEqual(len(completion["entries"]), 15)
        registration = self._register(completion_pin)
        self.assertEqual(registration.returncode, 0,
                         registration.stderr.decode("utf-8", "replace"))
        self.assertIs(json.loads(registration.stdout)["registered"], True)
        return completion, completion_pin

    def _verify(self, completion_pin: dict[str, str], *, extra: list[str] | None = None,
                output_root: Path | None = None,
                capacity_output_root: Path | None = None,
                environment: dict[str, str] | None = None) -> subprocess.CompletedProcess[bytes]:
        return self._run_cli("verify", extra=[
            "--completion", completion_pin["path"],
            "--completion-sha256", completion_pin["sha256"],
            *(extra or []),
        ], output_root=output_root, capacity_output_root=capacity_output_root,
           environment=environment)

    def _launch_arguments(self, job: dict[str, Any], completion_pin: dict[str, str],
                          timeout: int | None = None) -> list[str]:
        arguments = [
            "--completion", completion_pin["path"],
            "--completion-sha256", completion_pin["sha256"],
            "--job-run-id", job["run_id"], "--pair-runner", str(self.runner_path),
        ]
        if timeout is not None:
            arguments.extend(["--effective-timeout-seconds", str(timeout)])
        return arguments

    def _fixed_job(self, workload: str, profile: str, *, comparison_kind: str = "executor") -> dict[str, Any]:
        matches = [job for job in self.plan["jobs"]["confirmation"]
                   if job["host_id"] == self.host_id and job["workload"] == workload and
                   job["profile"] == profile and job["mode"] == "capacity" and
                   job["comparison_kind"] == comparison_kind]
        self.assertTrue(matches, f"fixture plan has no fixed {workload}/{profile} {comparison_kind} job")
        return matches[0]

    def _next_unused_fixed_job(self) -> dict[str, Any]:
        used = {
            item["details"]["job"]["run_id"]
            for item in self._read_events()
            if item["event"] == "dispatch_authorized"
        }
        matches = [job for job in self.plan["jobs"]["confirmation"]
                   if job["host_id"] == self.host_id and job["mode"] == "capacity" and
                   job["comparison_family"] == "fixed_policy" and
                   job.get("comparison_kind") == "executor" and job["run_id"] not in used]
        self.assertTrue(matches, "fixture has no unused original fixed executor job")
        return matches[0]

    def _wait_for_pid_not_live(self, pid: int, timeout_seconds: float = 3.0) -> None:
        state: str | None = None
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            try:
                stat_text = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
                state = stat_text[stat_text.rfind(")") + 2:].split()[0]
            except FileNotFoundError:
                state = None
            if state in (None, "Z", "X"):
                break
            time.sleep(0.01)
        self.assertIn(state, (None, "Z", "X"),
                      "test descendant survived its finite self-exit bound")

    def _verified_escaped_child_pid(self, tmp_root: Path) -> int:
        runner_marker = tmp_root / "campaign-pair-runner.pid"
        escaped_marker = tmp_root / "campaign-pair-runner.pid.escaped"
        self.assertTrue(runner_marker.is_file(), "source-pinned runner PID marker is missing")
        self.assertTrue(escaped_marker.is_file(), "child did not write its post-setpgid identity marker")
        runner_pid = int(runner_marker.read_text(encoding="ascii").strip())
        marker_fields = escaped_marker.read_text(encoding="ascii").strip().split(":")
        self.assertEqual(len(marker_fields), 2, "escaped-child marker lacks PID/start ticks")
        self.assertTrue(all(field.isdecimal() for field in marker_fields),
                        "escaped-child PID/start marker is not decimal")
        escaped_pid, expected_start_ticks = (int(field) for field in marker_fields)
        child_first = self._proc_group_identity(escaped_pid)
        self.assertIsNotNone(child_first, "escaped child exited before its identity was checked")
        assert child_first is not None
        self.assertNotIn(child_first["state"], ("Z", "X"))
        self.assertEqual(child_first["start_ticks"], expected_start_ticks)
        self.assertEqual(child_first["process_group_id"], escaped_pid)
        self.assertEqual(child_first["session_id"], runner_pid)
        child_second = self._proc_group_identity(escaped_pid)
        self.assertEqual(child_second, child_first,
                         "escaped child PID/start/group/session changed during verification")
        bound = [item["details"] for item in self._read_events()
                 if item["event"] == "dispatch_bound"]
        self.assertTrue(bound, "escaped child has no preceding direct-runner binding")
        self.assertEqual(bound[-1]["pid"], runner_pid)
        self.assertGreater(bound[-1]["start_ticks"], 0)
        return escaped_pid

    def _assert_cleanup_blocks_dispatch(self, completion_pin: dict[str, str]) -> None:
        events_before = self._read_events()
        audit_before = [json.loads(line) for line in self.audit_path.read_text().splitlines()]
        runner_popens_before = sum(
            item.get("kind") == "popen" and item.get("role") == "campaign_pair_runner"
            for item in audit_before
        )
        blocked = self._run_cli("launch", extra=self._launch_arguments(
            self._next_unused_fixed_job(), completion_pin, timeout=45,
        ))
        self.assertEqual(blocked.returncode, 2)
        self.assertIn("prior pair-runner cleanup is unclean or unverified",
                      blocked.stderr.decode("utf-8", "replace"))
        self.assertEqual(self._read_events(), events_before,
                         "unsafe group cleanup allowed another dispatch authorization")
        audit_after = [json.loads(line) for line in self.audit_path.read_text().splitlines()]
        self.assertEqual(sum(item.get("kind") == "popen" and
                             item.get("role") == "campaign_pair_runner"
                             for item in audit_after), runner_popens_before)

    def _assert_sigchld_rejected_before_authorization(
        self, completion_pin: dict[str, str], job: dict[str, Any], mode: str,
    ) -> None:
        tmp_root = self.root_temp / f"chronology-sigchld-{mode}-tmp"
        tmp_root.mkdir(mode=0o700)
        environment = self._environment(tmp_root=tmp_root)
        environment["CHRONOLOGY_SIGCHLD_MODE"] = mode
        before_events = self._read_events()
        result = self._run_cli("launch", extra=self._launch_arguments(
            job, completion_pin, timeout=45,
        ), environment=environment)
        self.assertEqual(result.returncode, 2)
        self.assertIn("fixed dispatch requires the default SIGCHLD disposition",
                      result.stderr.decode("utf-8", "replace"))
        self.assertEqual(self._read_events(), before_events,
                         f"{mode} wrote a dispatch authorization before ownership rejection")
        audit = [json.loads(line) for line in self.audit_path.read_text().splitlines()]
        self.assertFalse(any(item.get("kind") == "popen" and
                             item.get("role") == "campaign_pair_runner" for item in audit))

    def _read_events(self) -> list[dict[str, Any]]:
        return [json.loads(line)["record"] for line in self.journal_path.read_bytes().splitlines()]

    def _artifact_snapshot(self, phase: str) -> dict[str, dict[str, Any]]:
        manifest = json.loads(Path(self.fixture.source_manifest_path).read_bytes())
        self.assertEqual(manifest["schema"], "allocatbelt.application-source-manifest.v5")
        records = manifest["artifacts"]
        self.assertEqual(set(records), {"allocatbelt", "mimalloc-secure",
                                       "mimalloc-standard", "system"})
        snapshot: dict[str, dict[str, Any]] = {}
        for name, artifact in sorted(records.items()):
            relative = Path(artifact["path"])
            self.assertFalse(relative.is_absolute())
            candidate = self.source_root / relative
            path = candidate.resolve(strict=True)
            self.assertEqual(path, candidate, f"{phase}: {name} artifact path is aliased")
            path.relative_to(self.source_root.resolve(strict=True))
            info = path.lstat()
            self.assertTrue(stat.S_ISREG(info.st_mode) and info.st_mode & 0o111,
                            f"{phase}: {name} fixture artifact is not a regular executable")
            actual_sha256 = sha(path.read_bytes())
            self.assertEqual(actual_sha256, artifact["sha256"],
                             f"{phase}: {name} fixture artifact differs from its SourceV5 pin")
            snapshot[name] = {
                "path": relative.as_posix(), "sha256": actual_sha256,
                "mode": stat.S_IMODE(info.st_mode), "size": info.st_size,
                "mtime_ns": info.st_mtime_ns, "device": info.st_dev, "inode": info.st_ino,
            }
        print("SOURCEV5_ARTIFACT_AUDIT " + phase + " " +
              json.dumps(snapshot, sort_keys=True, separators=(",", ":")))
        return snapshot

    def test_binary_pin_hashes_source_bytes_and_rejects_tampering(self) -> None:
        binary = self.source_root / "target" / "chronology-pinned-binary"
        original = b"bounded SourceV5 binary pin fixture\n"
        try:
            write_file(binary, original, 0o755)
            relative = binary.relative_to(self.source_root).as_posix()
            prepared = {
                "source_root": self.source_root,
                "source": {"artifacts": {"fixture": {
                    "path": relative, "sha256": sha(original),
                }}},
            }
            self.assertEqual(self.chronology_module._pinned_binary(prepared, "fixture", "candidate"),
                             (binary, sha(original)))

            tampered = b"changed SourceV5 binary pin fixture\n"
            write_file(binary, tampered, 0o755)
            with self.assertRaisesRegex(
                self.chronology_module.ChronologyError,
                "candidate binary changed after SourceV5 capture",
            ):
                self.chronology_module._pinned_binary(prepared, "fixture", "candidate")
        finally:
            binary.unlink(missing_ok=True)

    def _rechain_journal(self, mutate: Any) -> bytes:
        original = self.journal_path.read_bytes()
        records = [json.loads(line)["record"] for line in original.splitlines()]
        mutate(records)
        previous = "0" * 64
        lines: list[bytes] = []
        for sequence, record in enumerate(records, 1):
            record["sequence"] = sequence
            unsigned = {"previous_sha256": previous, "record": record}
            current = sha(canonical(unsigned))
            lines.append(canonical({**unsigned, "record_sha256": current}))
            previous = current
        self.journal_path.chmod(0o600)
        self.journal_path.write_bytes(b"".join(lines))
        return original

    def _run_logged(self, command: str, *, extra: list[str],
                    environment: dict[str, str], timeout: int = 180) -> tuple[int, bytes, bytes]:
        initial_popens = 0
        if self.audit_path.exists():
            initial_popens = sum(
                item.get("kind") == "popen" and item.get("role") == "campaign_pair_runner"
                for item in (json.loads(line) for line in self.audit_path.read_text().splitlines())
            )
        process = subprocess.Popen(
            [sys.executable, "-B", str(self.source_root / "scripts/application-campaign-chronology.py"), command,
             *self._common_args(), *extra],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment,
        )
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.audit_path.exists():
                try:
                    entries = [json.loads(line) for line in self.audit_path.read_text().splitlines()]
                except (json.JSONDecodeError, OSError):
                    entries = []
                current_popens = sum(
                    item.get("kind") == "popen" and item.get("role") == "campaign_pair_runner"
                    for item in entries
                )
                if (current_popens > initial_popens and
                        self._escaped_interrupt_identity(environment) is not None):
                    process.send_signal(signal.SIGINT)
                    stdout, stderr = process.communicate(timeout=30)
                    return process.returncode, stdout, stderr
            if process.poll() is not None:
                stdout, stderr = process.communicate()
                return process.returncode, stdout, stderr
            time.sleep(0.01)
        process.kill()
        stdout, stderr = process.communicate()
        raise AssertionError(f"chronology CLI did not reach pair-runner Popen: {stderr.decode(errors='replace')}")

    @staticmethod
    def _proc_group_identity(pid: int) -> dict[str, Any] | None:
        try:
            stat_text = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
            tail = stat_text[stat_text.rfind(")") + 2:].split()
            if len(tail) <= 19:
                return None
            return {
                "state": tail[0], "process_group_id": int(tail[2]),
                "session_id": int(tail[3]), "start_ticks": int(tail[19]),
            }
        except (FileNotFoundError, OSError, ValueError, IndexError):
            return None

    def _escaped_interrupt_identity(self, environment: dict[str, str]) -> tuple[int, int] | bool | None:
        flag_path = Path(environment["CHRONOLOGY_RUNNER_WAIT_FLAG"])
        try:
            mode = flag_path.read_text(encoding="ascii")
        except OSError:
            return None
        if mode == "sigchld-scan":
            runner_marker = Path(environment["CHRONOLOGY_RUNNER_PID_MARKER"])
            try:
                runner_pid = int(runner_marker.read_text(encoding="ascii").strip())
            except (OSError, ValueError):
                return None
            runner = self._proc_group_identity(runner_pid)
            if (runner is None or runner["state"] in ("Z", "X") or
                    runner["process_group_id"] != runner_pid or
                    runner["session_id"] != runner_pid):
                return None
            return runner_pid, runner_pid
        if mode != "escaped-interrupt":
            return True
        runner_marker = Path(environment["CHRONOLOGY_RUNNER_PID_MARKER"])
        child_marker = Path(str(runner_marker) + ".escaped")
        try:
            runner_pid = int(runner_marker.read_text(encoding="ascii").strip())
            child_pid_text, child_start_text = child_marker.read_text(encoding="ascii").strip().split(":")
            child_pid, child_start_ticks = int(child_pid_text), int(child_start_text)
        except (OSError, ValueError):
            return None
        runner_first = self._proc_group_identity(runner_pid)
        child_first = self._proc_group_identity(child_pid)
        if runner_first is None or child_first is None:
            return None
        if (runner_first["state"] in ("Z", "X") or child_first["state"] in ("Z", "X") or
                runner_first["process_group_id"] != runner_pid or
                runner_first["session_id"] != runner_pid or
                child_first["process_group_id"] != child_pid or
                child_first["session_id"] != runner_pid or
                child_first["start_ticks"] != child_start_ticks):
            return None
        runner_second = self._proc_group_identity(runner_pid)
        child_second = self._proc_group_identity(child_pid)
        if runner_first != runner_second or child_first != child_second:
            return None
        return runner_pid, child_pid

    def test_full_cli_stage_register_dispatch_and_journal_replay(self) -> None:
        signed_runner_raw = (SOURCE_ROOT / "scripts/run-application-pair.sh").read_bytes()
        self.assertEqual(sha(signed_runner_raw), SIGNED_E4_PAIR_RUNNER_SHA256)
        self.assertIn(
            b"qualification timing is hard-disabled until the binary provides verified runtime-domain, policy, and ceiling readback",
            signed_runner_raw,
        )
        sources = self.fixture.sources
        for source in sources.values():
            entries = [item for item in source["source"]["files"]
                       if item["path"] == "scripts/application-campaign-chronology.py"]
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]["kind"], "file")
            self.assertEqual(entries[0]["sha256"],
                             sha((self.source_root / "scripts/application-campaign-chronology.py").read_bytes()))
            runner_entries = [item for item in source["source"]["files"]
                              if item["path"] == "scripts/run-application-pair.sh"]
            self.assertEqual(len(runner_entries), 1)
            self.assertEqual(runner_entries[0]["sha256"], self.spec["runner_sha256"])
            self.assertEqual(set(source["qualification_harness"]),
                             set(capacity_fixtures.input_fixtures.inputs.HARNESS_PATHS))
        self.assertIs(self.plan["execution_ready"], False)
        self.assertEqual(self.plan["jobs"], self.fixture.original_jobs)
        print("SYNTHETIC_SOURCEV5_FIXTURE " + self.spec["runner_sha256"] +
              " execution_ready=false qualification_eligible=false")

        source_artifacts_before_stage = self._artifact_snapshot("before_capacity_stage")
        result = self._run_cli("run", timeout=360)
        source_artifacts_after_stage = self._artifact_snapshot("after_capacity_stage")
        self.assertEqual(source_artifacts_after_stage, source_artifacts_before_stage,
                         "capacity-stage children changed a pinned SourceV5 artifact")
        completion, completion_pin = self._completion(result)
        self.assertIs(completion["complete"], True)
        self.assertIs(completion["qualification_eligible"], False)
        self.assertIs(completion["controller_chronology_proven"], False)
        self.assertEqual(len(completion["entries"]), 15)
        self.assertEqual(completion["capacity_process_templates_sha256"],
                         self.plan["capacity_process_templates_sha256"])

        events = self._read_events()
        self.assertEqual([item["event"] for item in events], ["capacity_stage_completed"])
        stage_detail = events[0]["details"]
        self.assertEqual(stage_detail["entry_count"], 15)
        self.assertEqual(stage_detail["capacity_schedule_sha256"],
                         self.plan["capacity_process_templates_sha256"])
        audit = [json.loads(line) for line in self.audit_path.read_text().splitlines()]
        capacity_launches = [item for item in audit
                             if item.get("kind") == "popen" and item.get("role") == "capacity"]
        self.assertEqual(len(capacity_launches), 30)
        for index, item in enumerate(audit):
            if item.get("kind") == "popen" and item.get("role") == "capacity":
                self.assertGreater(index, 0)
                self.assertEqual(audit[index - 1]["kind"], "ledger_fsync")
                self.assertEqual(audit[index - 1]["role"], "capacity")
                self.assertEqual(audit[index - 1]["event"], item["event"])
                self.assertEqual(audit[index - 1]["record_sha256"], item["record_sha256"])

        # A historical confirmation directory blocks the first registration.
        old_host_dir = self.output_root / self.campaign_id / "confirmation" / self.host_id
        old_host_dir.mkdir(mode=0o700, parents=True)
        blocked = self._register(completion_pin)
        self.assertEqual(blocked.returncode, 2)
        self.assertIn("existing original confirmation host directory",
                      blocked.stderr.decode("utf-8", "replace"))
        old_host_dir.rmdir()
        old_host_dir.parent.rmdir()

        missing_root = self.root_temp / "chronology-missing-registration"
        missing_root.mkdir(mode=0o700)
        missing = self._run_cli(
            "register", extra=["--completion", completion_pin["path"],
                               "--completion-sha256", completion_pin["sha256"]],
            output_root=missing_root, capacity_output_root=self.output_root,
        )
        self.assertEqual(missing.returncode, 2)
        self.assertIn("must be produced by run_capacity_stage_locked",
                      missing.stderr.decode("utf-8", "replace"))

        registered = self._register(completion_pin)
        self.assertEqual(registered.returncode, 0, registered.stderr.decode("utf-8", "replace"))
        registration_result = json.loads(registered.stdout)
        self.assertIs(registration_result["registered"], True)
        self.assertEqual(registration_result["entry_count"], 15)
        self.assertIs(registration_result["qualification_eligible"], False)
        self.assertIs(registration_result["controller_chronology_proven"], False)
        events = self._read_events()
        self.assertEqual([item["event"] for item in events],
                         ["capacity_stage_completed", "capacity_registered"])
        registered_again = self._register(completion_pin)
        self.assertEqual(registered_again.returncode, 0,
                         registered_again.stderr.decode("utf-8", "replace"))
        self.assertEqual(len(self._read_events()), 2, "identical registration is idempotent")
        source_artifacts_after_registration = self._artifact_snapshot("after_capacity_registration")
        self.assertEqual(source_artifacts_after_registration, source_artifacts_before_stage,
                         "capacity registration or replay changed a pinned SourceV5 artifact")

        def contradict_registration(records: list[dict[str, Any]]) -> None:
            registration = next(item for item in records
                                if item["event"] == "capacity_registered")
            registration["details"]["entries"][0]["actual_pid"] += 1

        original_registration_journal = self._rechain_journal(contradict_registration)
        conflict = self._verify(completion_pin)
        self.assertEqual(conflict.returncode, 2)
        self.assertIn("capacity registration differs from the locked stage completion",
                      conflict.stderr.decode("utf-8", "replace"))
        self.journal_path.write_bytes(original_registration_journal)
        self.journal_path.chmod(0o600)

        wrong_source = self.root_temp / "chronology-wrong-source-root"
        wrong_source.mkdir(mode=0o700, exist_ok=False)
        wrong_source_root = self._run_cli("verify", extra=[
            "--completion", completion_pin["path"],
            "--completion-sha256", completion_pin["sha256"],
            "--source-root", str(wrong_source),
        ])
        self.assertEqual(wrong_source_root.returncode, 2)
        self.assertIn("active chronology module is not executing from the supplied SourceV5 root",
                      wrong_source_root.stderr.decode("utf-8", "replace"))

        # Source/boot context is read from its pinned bytes and validated against the current host.
        forged_host = json.loads(self.observed_host_path.read_bytes())
        forged_host["boot_id_sha256"] = "f" * 64
        forged_host_path = self.input_root / "chronology-forged-host.json"
        write_file(forged_host_path, canonical(forged_host))
        forged_host_result = self._run_cli("verify", extra=[
            "--completion", completion_pin["path"],
            "--completion-sha256", completion_pin["sha256"],
            "--observed-host", str(forged_host_path),
            "--observed-host-sha256", sha(forged_host_path.read_bytes()),
        ])
        self.assertEqual(forged_host_result.returncode, 2)
        self.assertIn("live boot identity differs",
                      forged_host_result.stderr.decode("utf-8", "replace"))

        capacity_job = self._fixed_job("cpu", "steady")
        pressure_job = next(job for job in self.plan["jobs"]["pressure"]
                            if job["host_id"] == self.host_id and job["mode"] == "capacity")
        pressure_attempt = self._run_cli("launch", extra=self._launch_arguments(
            pressure_job, completion_pin),
        )
        self.assertEqual(pressure_attempt.returncode, 2)
        self.assertIn("pressure dispatch is explicitly unsupported by the fixed confirmation journal",
                      pressure_attempt.stderr.decode("utf-8", "replace"))
        self.assertEqual(len(self._read_events()), 2)

        # Verify that an output-file collision after authorization consumes the job before Popen.
        file_failure_job = self._fixed_job("memory", "steady", comparison_kind="allocator")
        with self.chronology_module.campaign_host_lock(
            self.output_root, self.campaign_id, self.host_id,
        ) as lock:
            source_artifacts_before_authorization = self._artifact_snapshot("before_fixed_authorization")
            self.assertEqual(source_artifacts_before_authorization, source_artifacts_before_stage,
                             "SourceV5 artifacts drifted before fixed authorization")
            authorization = self.chronology_module.authorize_dispatch_locked(
                lock, {"path": str(self.plan_path), "sha256": self.plan_sha256},
                {"path": str(self.spec_path), "sha256": self.spec_sha256},
                self.source_root, self.input_root, self.host_id,
                {"path": str(self.observed_host_path), "sha256": self.observed_host_sha256},
                self.output_root, completion_pin, file_failure_job, self.runner_path,
                capacity_output_root=self.output_root, effective_timeout_seconds=45,
            )
            source_artifacts_after_authorization = self._artifact_snapshot("after_fixed_authorization")
            self.assertEqual(source_artifacts_after_authorization, source_artifacts_before_stage,
                             "fixed authorization changed a pinned SourceV5 artifact")
            exposed_details = authorization.details
            exposed_details["argv"][0] = "/tmp/unpinned-pair-runner"
            self.assertEqual(authorization.details["argv"][0], str(self.runner_path),
                             "authorization details were exposed as mutable token state")
            phase_dir = (self.output_root / self.campaign_id / "confirmation" /
                         self.host_id)
            for directory in (phase_dir.parent.parent, phase_dir.parent, phase_dir):
                directory.mkdir(mode=0o700, parents=True, exist_ok=True)
                directory.chmod(0o700)
            collision = Path(authorization.details["stderr_path"])
            write_file(collision, b"preexisting collision\n")
            prior_popen_count = len([item for item in audit
                                     if item.get("kind") == "popen" and
                                     item.get("role") == "campaign_pair_runner"])
            failure = self.chronology_module.launch_authorized_locked(lock, authorization)
            self.assertEqual(failure["status"], "launch_failed")
            self.assertIsNone(failure["pid"])
            with self.assertRaisesRegex(self.chronology_module.ChronologyError, "already consumed"):
                self.chronology_module.launch_authorized_locked(lock, authorization)
            for output in (Path(authorization.details["runtime_bindings"]["path"]),
                           Path(authorization.details["stdout_path"]), collision):
                output.unlink()
            with self.assertRaisesRegex(
                self.chronology_module.ChronologyError,
                "original confirmation authorization was already consumed and cannot be retried",
            ):
                self.chronology_module.authorize_dispatch_locked(
                    lock, {"path": str(self.plan_path), "sha256": self.plan_sha256},
                    {"path": str(self.spec_path), "sha256": self.spec_sha256},
                    self.source_root, self.input_root, self.host_id,
                    {"path": str(self.observed_host_path), "sha256": self.observed_host_sha256},
                    self.output_root, completion_pin, file_failure_job, self.runner_path,
                    capacity_output_root=self.output_root, effective_timeout_seconds=45,
                )
            refreshed_audit = [json.loads(line) for line in self.audit_path.read_text().splitlines()]
            self.assertEqual(len([item for item in refreshed_audit
                                  if item.get("kind") == "popen" and
                                  item.get("role") == "campaign_pair_runner"]), prior_popen_count)

        # The CLI authorizes the original fixed job and directly launches the
        # synthetic SourceV5 runner. Its PID is the shell interpreter, not an app.
        unsafe_tmp = self.root_temp / "chronology-bash-env-tmp"
        unsafe_tmp.mkdir(mode=0o700)
        unsafe_env = self._environment(tmp_root=unsafe_tmp)
        startup_payload = self.root_temp / "untracked-bash-startup.sh"
        startup_marker = self.root_temp / "bash-startup-was-executed"
        write_file(startup_payload, f": > {startup_marker}\n".encode(), 0o600)
        unsafe_env["BASH_ENV"] = str(startup_payload)
        events_before_unsafe_environment = self._read_events()
        unsafe_environment = self._run_cli(
            "launch", extra=self._launch_arguments(capacity_job, completion_pin, timeout=45),
            environment=unsafe_env,
        )
        self.assertEqual(unsafe_environment.returncode, 2)
        self.assertIn(
            "unpinned Bash startup or function import control",
            unsafe_environment.stderr.decode("utf-8", "replace"),
        )
        self.assertEqual(self._read_events(), events_before_unsafe_environment,
                         "BASH_ENV rejection wrote a dispatch authorization")
        audit_after_unsafe_environment = [
            json.loads(line) for line in self.audit_path.read_text().splitlines()
        ]
        self.assertEqual(sum(item.get("kind") == "popen" and
                             item.get("role") == "campaign_pair_runner"
                             for item in audit_after_unsafe_environment), 0)
        self.assertFalse(startup_marker.exists(), "untracked BASH_ENV payload executed")
        self._assert_sigchld_rejected_before_authorization(
            completion_pin, capacity_job, "ignore_before",
        )
        self._assert_sigchld_rejected_before_authorization(
            completion_pin, capacity_job, "custom_before",
        )

        normal_tmp = self.root_temp / "chronology-normal-app-tmp"
        normal_tmp.mkdir(mode=0o700)
        normal_env = self._environment(tmp_root=normal_tmp)
        launched = self._run_cli("launch", extra=self._launch_arguments(
            capacity_job, completion_pin, timeout=45), environment=normal_env, timeout=120)
        self.assertEqual(launched.returncode, 0, launched.stderr.decode("utf-8", "replace"))
        outcome = json.loads(launched.stdout)
        self.assertEqual(outcome["status"], "completed")
        self.assertEqual(outcome["return_code"], 0)
        self.assertGreater(outcome["pid"], 0)
        self.assertTrue(outcome["process_reaped"])
        self.assertEqual(outcome["process_reap_status"], "owned_reaped")
        self.assertIs(outcome["qualification_eligible"], False)
        self.assertIs(outcome["controller_chronology_proven"], False)
        runner_pid_marker = normal_tmp / "campaign-pair-runner.pid"
        self.assertTrue(runner_pid_marker.is_file(), "pinned pair-runner interpreter never ran")
        self.assertEqual(outcome["pid"], int(runner_pid_marker.read_text().strip()),
                         "recorded PID differs from the direct pair-runner interpreter PID")
        self.assertFalse((normal_tmp / "fake-app.pid").exists(),
                         "the synthetic pair runner unexpectedly launched an application")
        run_id_marker = normal_tmp / "campaign-pair-runner.run-id"
        self.assertEqual(run_id_marker.read_text().strip(), capacity_job["run_id"],
                         "the source-pinned synthetic runner did not receive the original run ID")
        events = self._read_events()
        bound = next(item for item in events if item["event"] == "dispatch_bound")
        self.assertEqual(bound["details"]["member_role"], "campaign_pair_runner")
        self.assertIsNone(bound["details"]["process_report_nonce"])
        self.assertEqual(bound["details"]["actual_environment_sha256"],
                         bound["details"]["environment_sha256"])
        self.assertEqual(bound["details"]["pid"], outcome["pid"])
        auth_event = next(
            item for item in events
            if item["event"] == "dispatch_authorized" and
            item["details"]["job"]["run_id"] == capacity_job["run_id"]
        )
        self.assertEqual(auth_event["details"]["pair_members"],
                         self.plan["runtime_process_bindings"][capacity_job["run_id"]])
        self.assertEqual(auth_event["details"]["member_role"], "campaign_pair_runner")
        self.assertEqual(outcome["process_executable_path"],
                         auth_event["details"]["shebang_interpreter"]["path"])
        self.assertEqual(outcome["process_executable_sha256"],
                         auth_event["details"]["shebang_interpreter"]["sha256"])

        audit = [json.loads(line) for line in self.audit_path.read_text().splitlines()]
        runner_popens = [item for item in audit if item.get("kind") == "popen" and
                         item.get("role") == "campaign_pair_runner"]
        self.assertEqual(len(runner_popens), 1)
        auth_fsync = [item for item in audit if item.get("kind") == "ledger_fsync" and
                      item.get("role") == "chronology" and
                      item.get("event") == "dispatch_authorized"]
        self.assertTrue(auth_fsync)
        self.assertEqual(auth_fsync[-1]["record_sha256"], runner_popens[0]["record_sha256"])
        self.assertLess(audit.index(auth_fsync[-1]), audit.index(runner_popens[0]))

        # An early-exiting runner leaves a TERM-ignoring descendant holding
        # inherited output descriptors. Cleanup signals the group while the
        # direct runner remains unreaped, then reaps once and never probes PGID.
        descendant_job = self._fixed_job("disk", "steady")
        descendant_tmp = self.root_temp / "chronology-descendant-app-tmp"
        descendant_tmp.mkdir(mode=0o700)
        write_file(self.hang_flag, b"descendant", 0o600)
        descendant_env = self._environment(tmp_root=descendant_tmp)
        descendant = self._run_cli(
            "launch", extra=self._launch_arguments(descendant_job, completion_pin, timeout=45),
            environment=descendant_env, timeout=120,
        )
        self.hang_flag.unlink(missing_ok=True)
        self.assertEqual(descendant.returncode, 0,
                         descendant.stderr.decode("utf-8", "replace"))
        descendant_outcome = json.loads(descendant.stdout)
        self.assertEqual(descendant_outcome["status"], "completed")
        self.assertTrue(descendant_outcome["process_reaped"])
        self.assertEqual(descendant_outcome["process_reap_status"], "owned_reaped")
        descendant_pid_path = descendant_tmp / "campaign-pair-runner.pid.descendant"
        self.assertTrue(descendant_pid_path.is_file(),
                        "pinned runner did not create its output-holding descendant")
        descendant_pid = int(descendant_pid_path.read_text().strip())
        self._wait_for_pid_not_live(descendant_pid)
        audit = [json.loads(line) for line in self.audit_path.read_text().splitlines()]
        runner_popens = [item for item in audit if item.get("kind") == "popen" and
                         item.get("role") == "campaign_pair_runner"]
        self.assertEqual(len(runner_popens), 2)
        self.assertFalse(any(item.get("kind") == "post_reap_group_operation" for item in audit),
                         "numeric process-group operation followed direct runner reap")

        # Two concurrent CLI requests for one original run ID serialize on the
        # same flock; only one can create an authorization or reach Popen.
        race_job = self._fixed_job("cpu", "burst")
        race_start = len(runner_popens)
        racers: list[subprocess.Popen[bytes]] = []
        for suffix in ("a", "b"):
            race_tmp = self.root_temp / f"chronology-race-{suffix}-tmp"
            race_tmp.mkdir(mode=0o700)
            argv = [sys.executable, "-B",
                    str(self.source_root / "scripts/application-campaign-chronology.py"), "launch",
                    *self._common_args(), *self._launch_arguments(race_job, completion_pin, timeout=45)]
            racers.append(subprocess.Popen(
                argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=self._environment(tmp_root=race_tmp),
            ))
        race_results = [process.communicate(timeout=180) + (process.returncode,)
                        for process in racers]
        self.assertEqual(sorted(item[2] for item in race_results), [0, 2])
        after_race_audit = [json.loads(line) for line in self.audit_path.read_text().splitlines()]
        after_race_popens = [item for item in after_race_audit
                             if item.get("kind") == "popen" and
                             item.get("role") == "campaign_pair_runner"]
        self.assertEqual(len(after_race_popens) - race_start, 1)
        race_authorizations = [item for item in self._read_events()
                               if item["event"] == "dispatch_authorized" and
                               item["details"]["job"]["run_id"] == race_job["run_id"]]
        self.assertEqual(len(race_authorizations), 1)

        # A second fixed job is interrupted after direct Popen while the
        # synthetic runner waits on its pinned test flag.
        interrupt_job = self._fixed_job("http", "steady")
        interrupt_tmp = self.root_temp / "chronology-interrupt-app-tmp"
        interrupt_tmp.mkdir(mode=0o700)
        self.hang_flag.touch(mode=0o600)
        interrupt_env = self._environment(tmp_root=interrupt_tmp)
        code, stdout, stderr = self._run_logged(
            "launch", extra=self._launch_arguments(interrupt_job, completion_pin, timeout=60),
            environment=interrupt_env, timeout=120,
        )
        self.hang_flag.unlink()
        self.assertEqual(code, 0, stderr.decode("utf-8", "replace"))
        interrupted = json.loads(stdout)
        self.assertEqual(interrupted["status"], "interrupted")
        self.assertEqual(interrupted["signal"], signal.SIGINT)
        self.assertTrue(interrupted["process_reaped"])
        self.assertEqual(interrupted["process_reap_status"], "owned_reaped")
        self.assertIs(type(interrupted["return_code"]), int)

        # A third job times out under its own finite bound and is retained.
        timeout_job = self._fixed_job("mixed", "mixed")
        timeout_tmp = self.root_temp / "chronology-timeout-app-tmp"
        timeout_tmp.mkdir(mode=0o700)
        self.hang_flag.touch(mode=0o600)
        timeout_env = self._environment(tmp_root=timeout_tmp)
        timed_out = self._run_cli("launch", extra=self._launch_arguments(
            timeout_job, completion_pin, timeout=45),
            environment=timeout_env, timeout=150)
        self.hang_flag.unlink()
        self.assertEqual(timed_out.returncode, 0,
                         timed_out.stderr.decode("utf-8", "replace"))
        timeout_result = json.loads(timed_out.stdout)
        self.assertEqual(timeout_result["status"], "timeout")
        self.assertGreater(timeout_result["pid"], 0,
                           "timeout occurred before the pair-runner Popen was bound")
        self.assertTrue(timeout_result["process_reaped"])
        self.assertEqual(timeout_result["process_reap_status"], "owned_reaped")
        self.assertIs(type(timeout_result["return_code"]), int)

        # Inject an owned-session procfs failure after direct Popen. Emergency
        # SIGKILL/reap must be bounded, but cleanup remains unverified and
        # permanently blocks any later dispatch authorization for this host.
        scan_failure_job = self._next_unused_fixed_job()
        scan_tmp = self.root_temp / "chronology-owned-scan-failure-tmp"
        scan_tmp.mkdir(mode=0o700)
        scan_env = self._environment(tmp_root=scan_tmp)
        scan_env["CHRONOLOGY_FAIL_OWNED_SCAN"] = "1"
        scan_failure = self._run_cli(
            "launch", extra=self._launch_arguments(scan_failure_job, completion_pin, timeout=45),
            environment=scan_env, timeout=120,
        )
        self.assertEqual(scan_failure.returncode, 0,
                         scan_failure.stderr.decode("utf-8", "replace"))
        scan_outcome = json.loads(scan_failure.stdout)
        self.assertEqual(scan_outcome["status"], "cleanup_failed")
        self.assertTrue(scan_outcome["process_reaped"])
        self.assertEqual(scan_outcome["process_reap_status"], "owned_reaped")
        self.assertIs(type(scan_outcome["return_code"]), int)
        self.assertEqual(scan_outcome["process_group_cleanup_status"], "unverified")
        self.assertEqual(len(scan_outcome["cleanup_error_sha256"]), 64)
        scan_audit = [json.loads(line) for line in self.audit_path.read_text().splitlines()]
        self.assertTrue(any(item.get("kind") == "owned_session_scan_failure"
                            for item in scan_audit),
                        "scanner failure injection did not occur after runner Popen")
        self.assertTrue(any(item.get("kind") == "runner_group_signal" and
                            item.get("pid") == scan_outcome["pid"] and
                            item.get("signal") == signal.SIGKILL for item in scan_audit),
                        "default-SIGCHLD scanner fallback did not use the unreaped runner group")

        verified = self._verify(completion_pin)
        self.assertEqual(verified.returncode, 0, verified.stderr.decode("utf-8", "replace"))
        summary = json.loads(verified.stdout)
        self.assertEqual(summary["schema"], CHRONOLOGY_SCHEMA)
        self.assertEqual(summary["entry_count"], 15)
        self.assertIs(summary["pending_authorization"], False)
        self.assertIs(summary["api_transaction_order_proven"], True)
        self.assertIs(summary["qualification_eligible"], False)
        self.assertIs(summary["execution_ready"], False)
        self.assertIs(summary["controller_chronology_proven"], False)
        self.assertIs(summary["cleanup_blocked"], True)
        self.assertEqual(summary["terminal_process_cleanup"][-1]["process_group_cleanup_status"],
                         "unverified")
        self.assertTrue(summary["terminal_process_cleanup"][-1]["process_reaped"])
        self.assertEqual(summary["terminal_process_cleanup"][-1]["process_reap_status"],
                         "owned_reaped")
        self.assertIs(type(summary["terminal_process_cleanup"][-1]["return_code"]), int)
        terminal_events = [item["event"] for item in self._read_events()
                           if item["event"].startswith("dispatch_") and
                           item["event"] != "dispatch_authorized" and
                           item["event"] != "dispatch_bound"]
        self.assertEqual(terminal_events.count("dispatch_exited"), 3)
        self.assertEqual(terminal_events.count("dispatch_failed"), 2)
        self.assertEqual(terminal_events.count("dispatch_interrupted"), 1)
        self.assertEqual(terminal_events.count("dispatch_timeout"), 1)

        original_journal = self.journal_path.read_bytes()
        tampered = original_journal.replace(b'"entry_count":15', b'"entry_count":14', 1)
        self.assertNotEqual(tampered, original_journal)
        self.journal_path.chmod(0o600)
        self.journal_path.write_bytes(tampered)
        rejected = self._verify(completion_pin)
        self.assertEqual(rejected.returncode, 2)
        self.assertIn("record digest is invalid",
                      rejected.stderr.decode("utf-8", "replace"))
        self.journal_path.write_bytes(original_journal)
        self.journal_path.chmod(0o600)
        replayed = self._verify(completion_pin)
        self.assertEqual(replayed.returncode, 0, replayed.stderr.decode("utf-8", "replace"))
        job_after_unverified_cleanup = self._next_unused_fixed_job()
        events_before_blocked_launch = self._read_events()
        final_audit = [json.loads(line) for line in self.audit_path.read_text().splitlines()]
        runner_popens_before_blocked_launch = sum(
            item.get("kind") == "popen" and item.get("role") == "campaign_pair_runner"
            for item in final_audit
        )
        blocked_launch = self._run_cli("launch", extra=self._launch_arguments(
            job_after_unverified_cleanup, completion_pin, timeout=45),
        )
        self.assertEqual(blocked_launch.returncode, 2)
        self.assertIn("prior pair-runner cleanup is unclean or unverified",
                      blocked_launch.stderr.decode("utf-8", "replace"))
        self.assertEqual(self._read_events(), events_before_blocked_launch,
                         "unverified cleanup appended another dispatch authorization")
        final_audit = [json.loads(line) for line in self.audit_path.read_text().splitlines()]
        self.assertEqual(sum(item.get("kind") == "popen" and
                             item.get("role") == "campaign_pair_runner"
                             for item in final_audit), runner_popens_before_blocked_launch)
        source_artifacts_after_dispatch = self._artifact_snapshot("after_all_dispatches_and_replay")
        self.assertEqual(source_artifacts_after_dispatch, source_artifacts_before_stage,
                         "fixed confirmation children changed a pinned SourceV5 artifact")
        final_audit = [json.loads(line) for line in self.audit_path.read_text().splitlines()]
        self.assertFalse(any(item.get("kind") == "post_reap_group_operation"
                             for item in final_audit),
                         "numeric process-group operation followed a direct runner reap")

    def test_unresolved_escaped_member_blocks_after_normal_runner_exit(self) -> None:
        _completion, completion_pin = self._stage_and_register()
        job = self._next_unused_fixed_job()
        tmp_root = self.root_temp / "chronology-escaped-normal-tmp"
        tmp_root.mkdir(mode=0o700)
        write_file(self.hang_flag, b"escaped-normal", 0o600)
        result = self._run_cli(
            "launch", extra=self._launch_arguments(job, completion_pin, timeout=45),
            environment=self._environment(tmp_root=tmp_root), timeout=120,
        )
        try:
            escaped_pid = self._verified_escaped_child_pid(tmp_root)
        finally:
            self.hang_flag.unlink(missing_ok=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))
        outcome = json.loads(result.stdout)
        self.assertEqual(outcome["status"], "cleanup_failed")
        self.assertTrue(outcome["process_reaped"])
        self.assertEqual(outcome["process_reap_status"], "owned_reaped")
        self.assertEqual(outcome["process_group_cleanup_status"], "unclean")
        self.assertEqual(len(outcome["cleanup_error_sha256"]), 64)
        self._wait_for_pid_not_live(escaped_pid)
        verified = self._verify(completion_pin)
        self.assertEqual(verified.returncode, 0, verified.stderr.decode("utf-8", "replace"))
        summary = json.loads(verified.stdout)
        self.assertIs(summary["cleanup_blocked"], True)
        self.assertEqual(summary["terminal_process_cleanup"][-1]["process_group_cleanup_status"],
                         "unclean")
        self._assert_cleanup_blocks_dispatch(completion_pin)

    def test_unresolved_escaped_member_blocks_after_timeout(self) -> None:
        _completion, completion_pin = self._stage_and_register()
        job = self._next_unused_fixed_job()
        tmp_root = self.root_temp / "chronology-escaped-timeout-tmp"
        tmp_root.mkdir(mode=0o700)
        write_file(self.hang_flag, b"escaped-timeout", 0o600)
        result = self._run_cli(
            "launch", extra=self._launch_arguments(job, completion_pin, timeout=45),
            environment=self._environment(tmp_root=tmp_root), timeout=120,
        )
        try:
            escaped_pid = self._verified_escaped_child_pid(tmp_root)
        finally:
            self.hang_flag.unlink(missing_ok=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))
        outcome = json.loads(result.stdout)
        self.assertEqual(outcome["status"], "cleanup_failed")
        self.assertEqual(outcome["dispatch_status"], "timeout")
        self.assertTrue(outcome["process_reaped"])
        self.assertEqual(outcome["process_reap_status"], "owned_reaped")
        self.assertEqual(outcome["process_group_cleanup_status"], "unclean")
        self.assertEqual(len(outcome["cleanup_error_sha256"]), 64)
        self._wait_for_pid_not_live(escaped_pid)
        verified = self._verify(completion_pin)
        self.assertEqual(verified.returncode, 0, verified.stderr.decode("utf-8", "replace"))
        summary = json.loads(verified.stdout)
        self.assertIs(summary["cleanup_blocked"], True)
        self.assertEqual(summary["terminal_process_cleanup"][-1]["process_group_cleanup_status"],
                         "unclean")
        self._assert_cleanup_blocks_dispatch(completion_pin)

    def test_unresolved_escaped_member_blocks_after_interruption(self) -> None:
        _completion, completion_pin = self._stage_and_register()
        job = self._next_unused_fixed_job()
        tmp_root = self.root_temp / "chronology-escaped-interrupt-tmp"
        tmp_root.mkdir(mode=0o700)
        write_file(self.hang_flag, b"escaped-interrupt", 0o600)
        result_code, stdout, stderr = self._run_logged(
            "launch", extra=self._launch_arguments(job, completion_pin, timeout=45),
            environment=self._environment(tmp_root=tmp_root), timeout=120,
        )
        try:
            escaped_pid = self._verified_escaped_child_pid(tmp_root)
        finally:
            self.hang_flag.unlink(missing_ok=True)
        self.assertEqual(result_code, 0, stderr.decode("utf-8", "replace"))
        outcome = json.loads(stdout)
        self.assertEqual(outcome["status"], "cleanup_failed")
        self.assertEqual(outcome["dispatch_status"], "interrupted")
        self.assertEqual(outcome["signal"], signal.SIGINT)
        self.assertTrue(outcome["process_reaped"])
        self.assertEqual(outcome["process_reap_status"], "owned_reaped")
        self.assertEqual(outcome["process_group_cleanup_status"], "unclean")
        self.assertEqual(len(outcome["cleanup_error_sha256"]), 64)
        self._wait_for_pid_not_live(escaped_pid)
        verified = self._verify(completion_pin)
        self.assertEqual(verified.returncode, 0, verified.stderr.decode("utf-8", "replace"))
        summary = json.loads(verified.stdout)
        self.assertIs(summary["cleanup_blocked"], True)
        self.assertEqual(summary["terminal_process_cleanup"][-1]["process_group_cleanup_status"],
                         "unclean")
        self._assert_cleanup_blocks_dispatch(completion_pin)

    def test_sigchld_ignored_after_popen_refuses_emergency_group_signal(self) -> None:
        _completion, completion_pin = self._stage_and_register()
        job = self._next_unused_fixed_job()
        tmp_root = self.root_temp / "chronology-sigchld-after-popen-tmp"
        tmp_root.mkdir(mode=0o700)
        environment = self._environment(tmp_root=tmp_root)
        environment["CHRONOLOGY_SIGCHLD_MODE"] = "ignore_after_popen"
        result = self._run_cli(
            "launch", extra=self._launch_arguments(job, completion_pin, timeout=45),
            environment=environment, timeout=120,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))
        outcome = json.loads(result.stdout)
        self.assertEqual(outcome["status"], "cleanup_failed")
        self.assertEqual(outcome["dispatch_status"], "launch_failed")
        self.assertGreater(outcome["pid"], 0)
        self.assertFalse(outcome["process_reaped"],
                         "unsupported SIGCHLD ownership fabricated a wait/reap result")
        self.assertEqual(outcome["process_reap_status"], "unverified")
        self.assertIsNone(outcome["return_code"],
                          "unsupported SIGCHLD ownership fabricated an exit status")
        self.assertEqual(outcome["process_group_cleanup_status"], "unverified")
        self.assertEqual(len(outcome["cleanup_error_sha256"]), 64)
        runner_pid_marker = tmp_root / "campaign-pair-runner.pid"
        self.assertTrue(runner_pid_marker.is_file(),
                        "SIGCHLD ownership changed before the direct Popen was exercised")
        self.assertEqual(outcome["pid"], int(runner_pid_marker.read_text().strip()))
        self._wait_for_pid_not_live(outcome["pid"])
        audit = [json.loads(line) for line in self.audit_path.read_text().splitlines()]
        self.assertTrue(any(item.get("kind") == "popen" and
                            item.get("role") == "campaign_pair_runner" for item in audit))
        self.assertFalse(any(item.get("kind") == "runner_group_signal" and
                             item.get("pid") == outcome["pid"] for item in audit),
                         "emergency cleanup signaled a PGID after WNOWAIT ownership failed")
        self.assertFalse(any(item.get("kind") == "runner_reaped" and
                             item.get("pid") == outcome["pid"] for item in audit),
                         "Popen.wait ran after SIGCHLD ownership became unsupported")
        self.assertFalse(any(item.get("kind") == "runner_waitpid_attempt" and
                             item.get("pid") == outcome["pid"] for item in audit),
                         "Popen.wait attempted waitpid after SIGCHLD ownership became unsupported")
        terminal = next(item["details"] for item in self._read_events()
                        if item["event"] in ("dispatch_failed", "dispatch_interrupted",
                                              "dispatch_timeout") and
                        item["details"]["job_run_id"] == job["run_id"])
        self.assertFalse(terminal["process_reaped"])
        self.assertEqual(terminal["process_reap_status"], "unverified")
        self.assertIsNone(terminal["return_code"])
        verified = self._verify(completion_pin)
        self.assertEqual(verified.returncode, 0, verified.stderr.decode("utf-8", "replace"))
        summary = json.loads(verified.stdout)
        self.assertTrue(summary["cleanup_blocked"])
        self.assertFalse(summary["terminal_process_cleanup"][-1]["process_reaped"])
        self.assertEqual(summary["terminal_process_cleanup"][-1]["process_reap_status"],
                         "unverified")
        self.assertIsNone(summary["terminal_process_cleanup"][-1]["return_code"])
        self.assertEqual(summary["terminal_process_cleanup"][-1]["process_group_cleanup_status"],
                         "unverified")

        def contradict_owned_reap(records: list[dict[str, Any]]) -> None:
            terminal_record = next(
                record for record in records
                if record["event"] in ("dispatch_failed", "dispatch_interrupted",
                                        "dispatch_timeout") and
                record["details"]["job_run_id"] == job["run_id"]
            )
            terminal_record["details"]["process_reap_status"] = "owned_reaped"

        original_journal = self._rechain_journal(contradict_owned_reap)
        contradictory = self._verify(completion_pin)
        self.assertEqual(contradictory.returncode, 2)
        self.assertIn("owned direct leader reap lacks its exact integer wait status",
                      contradictory.stderr.decode("utf-8", "replace"))
        self.journal_path.chmod(0o600)
        self.journal_path.write_bytes(original_journal)
        self._assert_cleanup_blocks_dispatch(completion_pin)

    def test_sigchld_change_during_owned_scan_refuses_group_signal_and_reap(self) -> None:
        _completion, completion_pin = self._stage_and_register()
        job = self._next_unused_fixed_job()
        tmp_root = self.root_temp / "chronology-sigchld-during-scan-tmp"
        tmp_root.mkdir(mode=0o700)
        write_file(self.hang_flag, b"sigchld-scan", 0o600)
        environment = self._environment(tmp_root=tmp_root)
        environment["CHRONOLOGY_FLIP_SIGCHLD_DURING_OWNED_SCAN"] = "1"
        try:
            result_code, stdout, stderr = self._run_logged(
                "launch", extra=self._launch_arguments(job, completion_pin, timeout=45),
                environment=environment, timeout=120,
            )
            self.assertEqual(result_code, 0, stderr.decode("utf-8", "replace"))
            outcome = json.loads(stdout)
            self.assertEqual(outcome["status"], "cleanup_failed")
            self.assertEqual(outcome["dispatch_status"], "interrupted")
            self.assertFalse(outcome["process_reaped"])
            self.assertEqual(outcome["process_reap_status"], "unverified")
            self.assertIsNone(outcome["return_code"])
            self.assertEqual(outcome["process_group_cleanup_status"], "unverified")
            runner_pid = outcome["pid"]
            identity = self._proc_group_identity(runner_pid)
            self.assertIsNotNone(identity, "injected scan returned before the runner was released")
            assert identity is not None
            self.assertNotIn(identity["state"], ("Z", "X"),
                             "runner was not live when SIGCHLD changed during the scan")
            self.assertEqual(identity["process_group_id"], runner_pid)
            self.assertEqual(identity["session_id"], runner_pid)
            audit = [json.loads(line) for line in self.audit_path.read_text().splitlines()]
            changes = [item for item in audit
                       if item.get("kind") == "owned_scan_sigchld_changed"]
            self.assertEqual(len(changes), 1)
            self.assertEqual(changes[0]["pid"], runner_pid)
            self.assertNotIn(changes[0]["state"], ("Z", "X"))
            self.assertEqual(changes[0]["process_group_id"], runner_pid)
            self.assertEqual(changes[0]["session_id"], runner_pid)
            self.assertEqual(changes[0]["start_ticks"], identity["start_ticks"])
            self.assertEqual(changes[0]["signal_disposition"], "SIG_IGN")
            change_index = audit.index(changes[0])
            bound = next(record["details"] for record in self._read_events()
                         if record["event"] == "dispatch_bound" and
                         record["details"]["job_run_id"] == job["run_id"])
            self.assertEqual(changes[0]["start_ticks"], bound["start_ticks"])
            self.assertTrue(any(item.get("kind") == "runner_waitid_attempt" and
                                item.get("pid") == runner_pid and
                                item["options"] & os.WNOWAIT
                                for item in audit[:change_index]),
                            "test did not observe owned WNOWAIT before the scan boundary")
            self.assertFalse(any(item.get("kind") == "runner_group_signal" and
                                 item.get("pid") == runner_pid for item in audit),
                             "numeric PGID signal followed the scanner ownership change")
            self.assertFalse(any(item.get("kind") in ("runner_waitpid_attempt", "runner_reaped") and
                                 item.get("pid") == runner_pid for item in audit),
                             "a reap was attempted or claimed after scanner ownership changed")
            self.assertFalse(any(item.get("kind") in ("runner_waitid_attempt", "runner_waitpid_attempt") and
                                 item.get("pid") == runner_pid
                                 for item in audit[change_index + 1:]),
                             "a child wait syscall followed the scanner ownership change")
            terminal = next(item["details"] for item in self._read_events()
                            if item["event"] == "dispatch_interrupted" and
                            item["details"]["job_run_id"] == job["run_id"])
            self.assertFalse(terminal["process_reaped"])
            self.assertEqual(terminal["process_reap_status"], "unverified")
            self.assertIsNone(terminal["return_code"])
        finally:
            self.hang_flag.unlink(missing_ok=True)
        self._wait_for_pid_not_live(runner_pid)
        verified = self._verify(completion_pin)
        self.assertEqual(verified.returncode, 0, verified.stderr.decode("utf-8", "replace"))
        summary = json.loads(verified.stdout)
        self.assertTrue(summary["cleanup_blocked"])
        cleanup = summary["terminal_process_cleanup"][-1]
        self.assertFalse(cleanup["process_reaped"])
        self.assertEqual(cleanup["process_reap_status"], "unverified")
        self.assertIsNone(cleanup["return_code"])
        self.assertEqual(cleanup["process_group_cleanup_status"], "unverified")
        self._assert_cleanup_blocks_dispatch(completion_pin)

    def test_cli_flock_contention_is_bounded_and_does_not_launch(self) -> None:
        with self.chronology_module.campaign_host_lock(
            self.output_root, self.campaign_id, self.host_id,
        ):
            result = self._run_cli("run", extra=["--lock-timeout-seconds", "0.03"],
                                   timeout=30)
        self.assertEqual(result.returncode, 2)
        self.assertIn("flock acquisition timed out", result.stderr.decode("utf-8", "replace"))
        self.assertFalse(self.capacity_ledger_path.exists())
        audit = [] if not self.audit_path.exists() else [
            json.loads(line) for line in self.audit_path.read_text().splitlines()
        ]
        self.assertFalse(any(item.get("kind") == "popen" for item in audit))


if __name__ == "__main__":
    raise SystemExit(unittest.main())
