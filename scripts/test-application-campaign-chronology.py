#!/usr/bin/env python3
"""Native CLI witnesses for the locked SourceV5 campaign chronology APIs."""
from __future__ import annotations

import ast
import copy
import inspect
from contextlib import contextmanager
import hashlib
import importlib.machinery
import importlib.util
import io
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
import types
import unittest
from unittest.mock import patch
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
    # The normal-exit case must establish the escaped process before its
    # parent exits; otherwise correct early group cleanup can win this race.
    for ((ready_attempt=0; ready_attempt<1000; ready_attempt++)); do
      [[ -s "${CHRONOLOGY_RUNNER_PID_MARKER}.escaped" ]] && break
      sleep 0.01
    done
    [[ -s "${CHRONOLOGY_RUNNER_PID_MARKER}.escaped" ]] || exit 72
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
    previous = sys.modules.get(name)
    sys.modules[name] = module
    try:
        loader.exec_module(module)
    except BaseException:
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous
        raise
    return module


capacity_fixtures = load_script(CAPACITY_TEST_PATH, "campaign_chronology_capacity_fixtures")


_SOURCEA_SHARED_H6_PLAN_FIXTURE = None
_SOURCEA_SHARED_H6_PLAN_FIXTURE_USERS = 0
_SOURCEA_SHARED_H6_PLAN_FIXTURE_SETUP_COUNT = 0
_SOURCEA_SHARED_H6_PLAN_FIXTURE_TEARDOWN_COUNT = 0
_SOURCEA_SHARED_H6_PLAN_FIXTURE_FIELDS = (
    "basis", "basis_pin", "hosts", "consumer", "provenance", "proofs",
    "catalogues", "readback_caps", "windows", "scratch", "timeouts",
)
_SOURCEA_SHARED_H6_FIXTURE_LIFECYCLE = {
    "setup_calls": 0,
    "teardown_calls": 0,
    "resource_paths": (),
    "setup_paths_present": (),
    "teardown_paths_present": (),
    "teardown_paths_absent": (),
    "module": None,
    "cleanup_registered": False,
}


def _sourcea_assert_h6_fixture_lifecycle_completed() -> None:
    lifecycle = _SOURCEA_SHARED_H6_FIXTURE_LIFECYCLE
    paths = lifecycle["resource_paths"]
    if not lifecycle["cleanup_registered"]:
        raise AssertionError("SourceA H6 module cleanup observer was not registered")
    if lifecycle["setup_calls"] != 1 or lifecycle["setup_paths_present"] != (True, True):
        raise AssertionError("the actual shared H6 setup did not create both fixture roots once")
    if lifecycle["teardown_calls"] != 1:
        raise AssertionError("the actual shared H6 teardown was not called exactly once")
    if lifecycle["teardown_paths_present"] != (True, True):
        raise AssertionError("the real H6 fixture roots were not alive before shared teardown")
    if lifecycle["teardown_paths_absent"] != (True, True):
        raise AssertionError("the real H6 fixture teardown did not remove both temporary roots")
    if len(paths) != 2 or any(path.exists() for path in paths):
        raise AssertionError("an actual H6 fixture temporary root survived module cleanup")
    if _SOURCEA_SHARED_H6_PLAN_FIXTURE is not None or \
            _SOURCEA_SHARED_H6_PLAN_FIXTURE_USERS != 0:
        raise AssertionError("the shared H6 fixture retained consumers after module cleanup")
    fixture_module = lifecycle["module"]
    if fixture_module is None or sys.modules.get(fixture_module.__name__) is not fixture_module:
        raise AssertionError("the actual H6 fixture module lost normal registry identity")


def _sourcea_h6_plan_fixture_copy():
    """Create one actual H6 fixture base and give each consumer private DTO copies."""
    global _SOURCEA_SHARED_H6_PLAN_FIXTURE
    global _SOURCEA_SHARED_H6_PLAN_FIXTURE_USERS
    global _SOURCEA_SHARED_H6_PLAN_FIXTURE_SETUP_COUNT
    if _SOURCEA_SHARED_H6_PLAN_FIXTURE is None:
        fixture_module = load_script(
            SCRIPT_DIR / "test-application-source5-recorded-preparation-read.py",
            "sourcea_c2r6_shared_h6_plan_fixture",
        )
        fixture_class = fixture_module.ActualH6RecordedReadPlanTests
        real_set_up_class = fixture_class.setUpClass
        real_tear_down_class = fixture_class.tearDownClass

        def _observed_set_up_class(cls):
            if cls is not fixture_class:
                raise AssertionError("unexpected class used for the shared H6 setup")
            lifecycle = _SOURCEA_SHARED_H6_FIXTURE_LIFECYCLE
            lifecycle["setup_calls"] += 1
            result = real_set_up_class()
            roots = (
                Path(cls.temporary.name),
                Path(cls.source_fixture_class._temporary.name),
            )
            lifecycle["resource_paths"] = roots
            lifecycle["setup_paths_present"] = tuple(path.is_dir() for path in roots)
            lifecycle["module"] = fixture_module
            return result

        def _observed_tear_down_class(cls):
            if cls is not fixture_class:
                raise AssertionError("unexpected class used for the shared H6 teardown")
            lifecycle = _SOURCEA_SHARED_H6_FIXTURE_LIFECYCLE
            lifecycle["teardown_calls"] += 1
            roots = lifecycle["resource_paths"]
            lifecycle["teardown_paths_present"] = tuple(path.is_dir() for path in roots)
            try:
                return real_tear_down_class()
            finally:
                lifecycle["teardown_paths_absent"] = tuple(
                    not path.exists() for path in roots
                )

        fixture_class.setUpClass = classmethod(_observed_set_up_class)
        fixture_class.tearDownClass = classmethod(_observed_tear_down_class)
        fixture_class.setUpClass()
        _SOURCEA_SHARED_H6_PLAN_FIXTURE = (fixture_module, fixture_class)
        _SOURCEA_SHARED_H6_PLAN_FIXTURE_SETUP_COUNT += 1
        unittest.addModuleCleanup(_sourcea_assert_h6_fixture_lifecycle_completed)
        _SOURCEA_SHARED_H6_FIXTURE_LIFECYCLE["cleanup_registered"] = True
    fixture_module, fixture_class = _SOURCEA_SHARED_H6_PLAN_FIXTURE
    copied = {
        name: copy.deepcopy(getattr(fixture_class, name))
        for name in _SOURCEA_SHARED_H6_PLAN_FIXTURE_FIELDS
    }
    _SOURCEA_SHARED_H6_PLAN_FIXTURE_USERS += 1
    return fixture_module, types.SimpleNamespace(**copied)


def _sourcea_h6_plan_fixture_release() -> None:
    global _SOURCEA_SHARED_H6_PLAN_FIXTURE_USERS
    if _SOURCEA_SHARED_H6_PLAN_FIXTURE_USERS <= 0:
        raise AssertionError("SourceA H6 shared fixture consumer underflow")
    _SOURCEA_SHARED_H6_PLAN_FIXTURE_USERS -= 1


def tearDownModule() -> None:
    """Close the one shared generated H6 fixture after every consumer ends."""
    global _SOURCEA_SHARED_H6_PLAN_FIXTURE
    global _SOURCEA_SHARED_H6_PLAN_FIXTURE_TEARDOWN_COUNT
    fixture = _SOURCEA_SHARED_H6_PLAN_FIXTURE
    if fixture is None:
        return
    fixture_module, fixture_class = fixture
    outstanding_users = _SOURCEA_SHARED_H6_PLAN_FIXTURE_USERS
    try:
        fixture_class.tearDownClass()
    finally:
        _SOURCEA_SHARED_H6_PLAN_FIXTURE = None
        _SOURCEA_SHARED_H6_PLAN_FIXTURE_TEARDOWN_COUNT += 1
    if outstanding_users != 0:
        raise AssertionError("SourceA H6 shared fixture was closed with active consumers")
    if _SOURCEA_SHARED_H6_PLAN_FIXTURE_SETUP_COUNT != 1 or \
            _SOURCEA_SHARED_H6_PLAN_FIXTURE_TEARDOWN_COUNT != 1:
        raise AssertionError("SourceA H6 shared fixture setup/cleanup was not exactly once")
    if sys.modules.get(fixture_module.__name__) is not fixture_module:
        raise AssertionError("SourceA H6 fixture module lost normal sys.modules identity")


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
            except (FileNotFoundError, ProcessLookupError):
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
            start_new_session=True,
        )

        def finish_bounded(drain_timeout: float) -> tuple[bytes, bytes]:
            try:
                stdout, stderr = process.communicate(timeout=drain_timeout)
                return stdout, stderr
            except subprocess.TimeoutExpired as error:
                # A reaped leader does not anchor a numeric process group.
                # Act only on the still-owned child; inherited pipes are a
                # harness failure and fixture finally releases its hang flag.
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=2)
                for stream in (process.stdout, process.stderr):
                    if stream is not None:
                        stream.close()
                raise AssertionError(
                    "chronology CLI output pipes did not reach bounded EOF",
                ) from error

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
                    stdout, stderr = finish_bounded(30)
                    return process.returncode, stdout, stderr
            if process.poll() is not None:
                stdout, stderr = finish_bounded(2)
                return process.returncode, stdout, stderr
            time.sleep(0.01)
        stdout, stderr = finish_bounded(0.1)
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
        original_context = self.chronology_module._prepare_inputs(
            {"path": str(self.plan_path), "sha256": self.plan_sha256},
            {"path": str(self.spec_path), "sha256": self.spec_sha256},
            self.source_root, self.input_root, self.host_id,
            {"path": str(self.observed_host_path),
             "sha256": self.observed_host_sha256},
            self.output_root,
        )
        original_journal = self.journal_path.read_bytes()
        replayed = self.chronology_module.replay_journal_bytes(
            original_journal, original_context["original_pins"],
            self.campaign_id, self.host_id, original_context["boot_id_sha256"],
        )
        self.assertEqual(replayed["record_count"], 1)
        first_envelope = json.loads(original_journal.splitlines()[0])
        self.assertEqual(first_envelope["record"], events[0])
        expected_head = sha(canonical({
            "previous_sha256": first_envelope["previous_sha256"],
            "record": events[0],
        }))
        self.assertEqual(first_envelope["record_sha256"], expected_head)
        self.assertEqual(replayed["terminal_head"], expected_head)
        self.assertIs(replayed["component_dispatch_pending"], True)
        self.assertIs(replayed["qualification_eligible"], False)
        broken_chain = original_journal.replace(
            b'"previous_sha256":"' + b"0" * 64 + b'"',
            b'"previous_sha256":"' + b"1" * 64 + b'"', 1,
        )
        self.assertNotEqual(broken_chain, original_journal)
        with self.assertRaisesRegex(
            self.chronology_module.ChronologyError,
            "chain breaks|record digest is invalid",
        ):
            self.chronology_module.replay_journal_bytes(
                broken_chain, original_context["original_pins"],
                self.campaign_id, self.host_id,
                original_context["boot_id_sha256"],
            )
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


class Source5FixedPhaseScopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.chronology = load_script(
            SCRIPT_DIR / "application-campaign-chronology.py",
            "source5_fixed_phase_scope_test_target",
        )

    @staticmethod
    def _record(path: Path, phase: str) -> dict[str, str]:
        metrics = [{"ordinal": 0}, {"ordinal": 1}]
        metric_sha = sha(canonical(metrics))
        chronology = {
            "authorization_id": "authorization-fixture",
            "authorization_head": "a" * 64,
            "app_started_heads": ["b" * 64, "c" * 64],
            "app_terminal_heads": ["d" * 64, "e" * 64],
            "job_terminal_head": "f" * 64,
            "component_sha256": "1" * 64,
            "process_metrics_sha256": metric_sha,
            "app_start_events": [{}, {}],
            "app_terminal_events": [{}, {}],
            "member_processes": [],
        }
        body = {
            "schema": "allocatbelt.application-source5-job-record.v1",
            "state": "valid_pair",
            "job": {"host_id": "host-1", "phase": phase, "run_id": "run-1"},
            "pair_directory": str(path.parent),
            "process_metrics": metrics,
            "evidence": {}, "chronology": chronology,
            "qualification_eligible": False,
        }
        value = {**body, "record_sha256": sha(canonical(body))}
        raw = canonical(value)
        path.write_bytes(raw)
        return {"path": str(path), "raw_sha256": sha(raw)}

    def _run_scope(self, path: Path, phase: str, *, fixed_api: bool) -> None:
        chronology = self.chronology
        record_pin = self._record(path, phase)
        prepared = {"host_id": "host-1"}
        state = {"source5_finished": {}}
        with patch.object(chronology, "_lock_token_is_live", return_value=True), \
                patch.object(chronology, "_prepare_source5_context",
                             return_value=({}, prepared, state, {})):
            with self.assertRaisesRegex(
                chronology.ChronologyError,
                "outside its original job/predecessor scope" if
                (fixed_api and phase == "pressure") or
                (not fixed_api and phase in {"exploration", "aa"}) else
                "exact completed APP lifecycle chain",
            ):
                if fixed_api:
                    chronology.verify_source5_completed_fixed_phase_locked(
                        object(), {"path": "/manifest", "sha256": "a" * 64}, record_pin,
                    )
                else:
                    chronology.verify_source5_completed_job_locked(
                        object(), {"path": "/manifest", "sha256": "a" * 64},
                        None, record_pin,
                    )

    def test_fixed_phase_scope_is_separate_and_pressure_predecessor_scope_remains_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-fixed-phase-scope-") as temporary:
            root = Path(temporary)
            self._run_scope(root / "old-exploration.json", "exploration", fixed_api=False)
            self._run_scope(root / "old-aa.json", "aa", fixed_api=False)
            self._run_scope(root / "new-pressure.json", "pressure", fixed_api=True)
            self._run_scope(root / "new-exploration.json", "exploration", fixed_api=True)
            self._run_scope(root / "new-aa.json", "aa", fixed_api=True)
            self._run_scope(root / "new-confirmation.json", "confirmation", fixed_api=True)
            self._run_scope(root / "old-pressure.json", "pressure", fixed_api=False)
        source = (SCRIPT_DIR / "application-campaign-chronology.py").read_text()
        self.assertLess(source.index("common_evidence_keys = {"),
                        source.index("if phase in fixed_phase_allowlist:"))


class Source5ProbeCaptureBundleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.chronology = load_script(
            SCRIPT_DIR / "application-campaign-chronology.py",
            "source5_probe_capture_bundle_test_target",
        )

    def test_v2_bundle_binds_two_raw_receipts_to_recipe_and_budget(self) -> None:
        chronology = self.chronology
        with tempfile.TemporaryDirectory(prefix="source5-probe-bundle-") as temporary:
            root = Path(temporary)
            output_root = root / "job"
            output_root.mkdir(mode=0o700)
            budget = {
                "capture_timeout_ns": 5_000_000_000,
                "storage_budget": {
                    "tmpdir_bytes": 64 * 1024 * 1024,
                    "tmpdir_inodes": 512,
                    "stdout_bytes": 512 * 1024,
                    "stderr_bytes": 64 * 1024,
                    "owner_result_bytes": 16 * 1024 * 1024,
                    "inventory_bytes": 16 * 1024 * 1024,
                    "failure_bytes": 64 * 1024,
                    "receipt_bytes": 16 * 1024 * 1024,
                    "output_inodes": 32,
                },
            }
            capacity = {
                name: {"path": str(root / f"capacity-{name}"),
                       "raw_sha256": chr(ord("a") + index) * 64}
                for index, name in enumerate(("request", "artifact", "receipt"))
            }
            probes = [
                {"path": str(root / f"probe-{index}.json"),
                 "raw_sha256": str(index + 1) * 64,
                 "allocator": "allocatbelt",
                 "binary_sha256": "f" * 64}
                for index in range(2)
            ]
            recipe = {
                "schema": "allocatbelt.application-pressure-pair-recipe.v2",
                "probe_capture": budget,
                "capacity_bundle": capacity,
                "members": [{"construction_probe": probe} for probe in probes],
            }
            rows = []
            for index, probe in enumerate(probes):
                receipt_path = output_root / f"receipt-{index}.json"
                body = {
                    "schema": "allocatbelt.application-feedback-probe-capture.v2",
                    "probe_pin": probe, "capacity_bundle": capacity,
                    "capture_timeout_ns": budget["capture_timeout_ns"],
                    "storage_budget": budget["storage_budget"],
                    "qualification_eligible": False,
                    "execution_ready": False,
                    "controller_chronology_proven": False,
                }
                receipt = {**body, "receipt_sha256": sha(canonical(body))}
                raw = canonical(receipt)
                write_file(receipt_path, raw)
                rows.append({
                    "ordinal": index, "construction_probe": probe,
                    "capture_receipt": {
                        "path": str(receipt_path), "raw_sha256": sha(raw),
                        "receipt_sha256": receipt["receipt_sha256"],
                    },
                    "capacity_bundle": capacity,
                })
            bundle = {
                "schema": "allocatbelt.application-source5-probe-capture-bundle.v1",
                "members": rows,
            }
            self.assertEqual(
                chronology._verify_source5_probe_capture_bundle_v2(
                    bundle, recipe, str(output_root), str(root),
                ), bundle,
            )
            with self.assertRaises(chronology.ChronologyError):
                chronology._verify_source5_probe_capture_bundle_v2(
                    {**bundle, "members": rows[:1]}, recipe,
                    str(output_root), str(root),
                )
            wrong_budget = {**recipe, "probe_capture": {
                **budget, "capture_timeout_ns": budget["capture_timeout_ns"] + 1,
            }}
            with self.assertRaises(chronology.ChronologyError):
                chronology._verify_source5_probe_capture_bundle_v2(
                    bundle, wrong_budget, str(output_root), str(root),
                )
            wrong_probe_rows = [dict(item) for item in rows]
            wrong_probe_rows[1] = {**wrong_probe_rows[1], "ordinal": 0}
            with self.assertRaises(chronology.ChronologyError):
                chronology._verify_source5_probe_capture_bundle_v2(
                    {**bundle, "members": wrong_probe_rows}, recipe,
                    str(output_root), str(root),
                )
            altered_pin_rows = [dict(item) for item in rows]
            altered_pin = dict(altered_pin_rows[0]["capture_receipt"])
            altered_pin["receipt_sha256"] = "0" * 64
            altered_pin_rows[0] = {**altered_pin_rows[0],
                                   "capture_receipt": altered_pin}
            with self.assertRaises(chronology.ChronologyError):
                chronology._verify_source5_probe_capture_bundle_v2(
                    {**bundle, "members": altered_pin_rows}, recipe,
                    str(output_root), str(root),
                )


class Source5JournalInputValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.chronology = load_script(
            SCRIPT_DIR / "application-campaign-chronology.py",
            "source5_journal_input_validation_target",
        )

    def _source_manifest_capture(
        self, files: list[dict[str, Any]],
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        chronology = self.chronology
        source = {
            "git_commit": "a" * 40,
            "source_tree_sha256": chronology.sha256_bytes(
                canonical({"schema": "allocatbelt.application-source-inventory.v1",
                           "entries": files}),
            ),
            "cargo_lock_sha256": "b" * 64,
            "files": files,
        }
        body = {
            "schema": "allocatbelt.application-source-manifest.v5",
            "source": source,
            "build": {},
            "artifacts": {},
            "soak_artifacts": {},
            "analysis_artifact": {},
            "fixed_runtime_policy": {},
            "runtime_readback_validator": {},
            "resource_domain_calibration": {},
            "qualification_harness": {},
            "feedback_policy": {},
        }
        semantic = chronology.sha256_bytes(canonical(body))
        value = {**body, "manifest_sha256": semantic}
        raw = canonical(value)
        path = "/private/source-manifests/host-a.json"
        raw_sha = chronology.sha256_bytes(raw)
        index_row = {
            "role": "source_manifest", "host_id": "host-a",
            "origin_path": path, "local_path": path,
            "raw_sha256": raw_sha, "semantic_sha256": semantic,
            "byte_count": len(raw),
        }
        store = {path: {**index_row, "raw_bytes": raw}}
        return value, index_row, store

    @staticmethod
    def _inventory_files() -> list[dict[str, Any]]:
        license_bytes = b"license payload\n"
        target = "../../LICENSE"
        target_bytes = target.encode("utf-8")
        return [
            {"path": "LICENSE", "kind": "file", "mode": "100644",
             "sha256": sha(license_bytes), "size": len(license_bytes)},
            {"path": "vendor/deep/LICENSE", "kind": "symlink",
             "mode": "120000", "target": target,
             "sha256": sha(target_bytes), "size": len(target_bytes)},
        ]

    def test_source_manifest_replays_literal_license_symlink_inventory(self) -> None:
        chronology = self.chronology
        _value, row, store = self._source_manifest_capture(self._inventory_files())
        parsed = chronology._source5_source_manifest_document(store, row)
        self.assertEqual(parsed["source"]["files"], self._inventory_files())
        self.assertNotEqual(row["raw_sha256"], row["semantic_sha256"])
        path = row["origin_path"]
        wrong_raw_store = dict(store)
        wrong_raw_store[path] = {
            **store[path], "raw_sha256": "0" * 64,
        }
        with self.assertRaisesRegex(chronology.ChronologyError,
                                    "bytes differ"):
            chronology._source5_source_manifest_document(
                wrong_raw_store, row,
            )
        wrong_semantic_row = {**row, "semantic_sha256": "0" * 64}
        with self.assertRaisesRegex(chronology.ChronologyError,
                                    "raw/semantic roles differ"):
            chronology._source5_source_manifest_document(
                store, wrong_semantic_row,
            )

        wrong_mode = self._inventory_files()
        wrong_mode[1] = {**wrong_mode[1], "mode": "100644"}
        _bad_value, bad_row, bad_store = self._source_manifest_capture(wrong_mode)
        with self.assertRaisesRegex(chronology.ChronologyError,
                                    "kind or mode"):
            chronology._source5_source_manifest_document(bad_store, bad_row)

        escaping = self._inventory_files()
        bad_target = "../../../outside"
        bad_target_bytes = bad_target.encode("utf-8")
        escaping[1] = {
            **escaping[1], "target": bad_target,
            "sha256": sha(bad_target_bytes), "size": len(bad_target_bytes),
        }
        _escape_value, escape_row, escape_store = self._source_manifest_capture(
            escaping,
        )
        with self.assertRaisesRegex(chronology.ChronologyError,
                                    "escapes the source tree"):
            chronology._source5_source_manifest_document(
                escape_store, escape_row,
            )

    def _full_source_index_fixture(self):
        root = "/private/source"
        host_ids = ["host-a", "host-b", "host-c"]
        validator = b"# pinned validator source\n"
        files = self._inventory_files() + [{
            "path": "scripts/runtime-readback.py", "kind": "file",
            "mode": "100644", "sha256": sha(validator),
            "size": len(validator),
        }]
        files.sort(key=lambda item: item["path"].encode("utf-8"))
        file_bytes = {
            "LICENSE": b"license payload\n",
            "vendor/deep/LICENSE": b"../../LICENSE",
            "scripts/runtime-readback.py": validator,
        }
        artifacts = {
            "allocatbelt": ("target/app/allocatbelt", b"allocatbelt elf"),
            "mimalloc-secure": ("target/app/mimalloc-secure", b"secure elf"),
            "mimalloc-standard": ("target/app/mimalloc-standard", b"standard elf"),
            "system": ("target/app/system", b"system elf"),
        }
        soak = {"allocatbelt": ("target/soak/allocatbelt", b"soak elf")}
        analysis = ("target/analyzer", b"analyzer elf")
        calibration_binary = ("target/domain-calibrator", b"calibrator elf")
        calibration_output = ("target/domain-calibration.json", b"{}\n")
        source = {
            "git_commit": "a" * 40,
            "source_tree_sha256": sha(canonical({
                "schema": "allocatbelt.application-source-inventory.v1",
                "entries": files,
            })),
            "cargo_lock_sha256": "b" * 64,
            "files": files,
        }
        documents: dict[str, dict[str, Any]] = {}
        artifact_bytes: dict[str, tuple[str, bytes]] = {}
        for name, (path, raw) in artifacts.items():
            artifact_bytes[path] = ("normal_app_output", raw)
        for path, raw in soak.values():
            artifact_bytes[path] = ("source5_soak_artifact", raw)
        artifact_bytes[analysis[0]] = ("analysis_artifact", analysis[1])
        artifact_bytes[calibration_binary[0]] = (
            "capacity_artifact", calibration_binary[1],
        )
        artifact_bytes[calibration_output[0]] = (
            "capacity_artifact", calibration_output[1],
        )
        for host_id in host_ids:
            documents[host_id] = {
                "source": source,
                "artifacts": {
                    name: {"path": path, "sha256": sha(raw)}
                    for name, (path, raw) in artifacts.items()
                },
                "soak_artifacts": {
                    name: {"path": path, "sha256": sha(raw)}
                    for name, (path, raw) in soak.items()
                },
                "analysis_artifact": {
                    "path": analysis[0], "sha256": sha(analysis[1]),
                },
                "resource_domain_calibration": {
                    "binary": {"path": calibration_binary[0],
                               "sha256": sha(calibration_binary[1])},
                    "output": {"path": calibration_output[0],
                               "sha256": sha(calibration_output[1])},
                    "record": {}, "source": {}, "build": {},
                    "build_sha256": "c" * 64,
                },
                "runtime_readback_validator": {
                    "path": "scripts/runtime-readback.py",
                    "sha256": sha(validator),
                },
            }

        raw_entries = dict(file_bytes)
        for path, (_role, raw) in artifact_bytes.items():
            raw_entries[path] = raw
        rows = []
        captured = []
        for relative, raw in raw_entries.items():
            if relative in file_bytes:
                file_record = next(item for item in files
                                   if item["path"] == relative)
                role = ("typed_source_file" if file_record["kind"] == "file"
                        else "typed_source_symlink")
            else:
                role = artifact_bytes[relative][0]
            path = str(Path(root) / relative)
            common = {
                "role": role, "host_id": "host-a",
                "origin_path": path, "local_path": path,
                "raw_sha256": sha(raw), "semantic_sha256": None,
                "byte_count": len(raw),
            }
            rows.append(common)
            captured.append({**common, "raw_bytes": raw})
        rows.sort(key=lambda item: item["origin_path"])
        captured.sort(key=lambda item: item["origin_path"])
        request = {"source_root": root, "host_id": "host-a"}
        manifest = {
            "execution_sources": {
                host_id: {"source_root": root} for host_id in host_ids
            },
        }
        store = {item["origin_path"]: item for item in captured}
        return request, manifest, documents, host_ids, {"entries": rows}, store

    def test_full_typed_source_and_artifact_index_closure_is_exact(self) -> None:
        chronology = self.chronology
        request, manifest, sources, hosts, index, store = \
            self._full_source_index_fixture()
        chronology._source5_validate_full_source_index_closure(
            request, manifest, sources, hosts, index, store,
        )
        missing_symlink = dict(store)
        missing_symlink.pop("/private/source/vendor/deep/LICENSE")
        index_without_symlink = {
            "entries": [item for item in index["entries"]
                        if item["origin_path"] !=
                        "/private/source/vendor/deep/LICENSE"],
        }
        with self.assertRaisesRegex(chronology.ChronologyError,
                                    "lacks one exact typed_source_symlink"):
            chronology._source5_validate_full_source_index_closure(
                request, manifest, sources, hosts,
                index_without_symlink, missing_symlink,
            )
        missing_artifact = dict(store)
        missing_artifact.pop("/private/source/target/soak/allocatbelt")
        index_without_artifact = {
            "entries": [item for item in index["entries"]
                        if item["origin_path"] !=
                        "/private/source/target/soak/allocatbelt"],
        }
        with self.assertRaisesRegex(chronology.ChronologyError,
                                    "lacks one exact source5_soak_artifact"):
            chronology._source5_validate_full_source_index_closure(
                request, manifest, sources, hosts,
                index_without_artifact, missing_artifact,
            )

    def test_selected_floor_source_rule_and_plan_generation_are_transitively_bound(self) -> None:
        chronology = self.chronology
        policy_id = "application_capacity_relative_tenth_v1"
        runtime_path = "bench/src/application/runtime_bindings.rs"
        runtime_raw = (SOURCE_ROOT / runtime_path).read_bytes()
        runtime_sha = sha(runtime_raw)
        evidence_path = f"/private/source/{runtime_path}"
        runtime_record = {
            "path": runtime_path, "kind": "file", "mode": "100644",
            "sha256": runtime_sha, "size": len(runtime_raw),
        }
        runtime_entry = {
            "role": "typed_source_file", "host_id": "host-a",
            "origin_path": evidence_path, "local_path": evidence_path,
            "raw_sha256": runtime_sha, "semantic_sha256": None,
            "byte_count": len(runtime_raw), "raw_bytes": runtime_raw,
        }
        source = {"source": {"files": [runtime_record]}}
        request = {"source_root": "/private/source", "host_id": "host-a"}
        descriptor = chronology._source5_capacity_floor_descriptor(
            source, {evidence_path: runtime_entry}, request,
        )
        self.assertEqual(descriptor["policy_id"], policy_id)
        bad_entry = {
            **runtime_entry,
            "raw_bytes": runtime_raw[:-1] + b" " if runtime_raw else b" ",
        }
        with self.assertRaisesRegex(chronology.ChronologyError,
                                    "bytes differ"):
            chronology._source5_capacity_floor_descriptor(
                source, {evidence_path: bad_entry}, request,
            )

        core_keys = {
            "campaign_id", "runner_sha256", "hosts", "cells", "protocol",
            "runtime_binding", "phase_adapters", "aa_controls", "soak",
            "deadlines",
        }
        spec = {key: key for key in core_keys}
        static_core = chronology._source5_preparation_core_projection(spec, None)
        self.assertEqual(static_core["schema"],
                         chronology.SOURCE5_PREPARATION_CORE_SCHEMA_V1)
        self.assertNotIn("capacity_floor_policy_id", static_core)
        selected_core = chronology._source5_preparation_core_projection(
            spec, policy_id,
        )
        self.assertEqual(selected_core["schema"],
                         chronology.SOURCE5_PREPARATION_CORE_SCHEMA_V2)
        self.assertEqual(selected_core["capacity_floor_policy_id"], policy_id)
        with self.assertRaisesRegex(chronology.ChronologyError, "unknown"):
            chronology._source5_preparation_core_projection(spec, "unknown_floor")

        expected_source_pins = {
            "feedback_validator": ("scripts/application-feedback-readback.py", "1" * 64),
            "runtime_bindings": (runtime_path, runtime_sha),
            "runtime_policy": (
                "crates/allocatbelt/src/runtime/resource_feedback_policy.rs",
                "2" * 64,
            ),
            "runtime_sensor": (
                "crates/allocatbelt/src/runtime/resource_feedback_sensor.rs",
                "3" * 64,
            ),
        }
        records = [
            {"path": path, "kind": "file", "sha256": digest}
            for path, digest in expected_source_pins.values()
        ]
        pins = {
            name: {"path": path, "sha256": digest}
            for name, (path, digest) in expected_source_pins.items()
        }
        selected_policy_body = {
            "schema": "allocatbelt.application-feedback-policy-artifact.v2",
            "version": "runtime-feedback-policy-v1",
            "reader_contract": {}, "algorithm": {}, "contexts": {},
            "source_pins": pins,
            "capacity_floor_policy": descriptor,
        }
        selected_artifact = {
            "schema": selected_policy_body["schema"],
            "policy": selected_policy_body,
            "policy_sha256": sha(canonical(selected_policy_body)),
        }
        policy_source = {
            "source": {"files": records},
            "qualification_harness": {
                "feedback_validator": pins["feedback_validator"],
            },
            "feedback_policy": selected_artifact,
        }
        self.assertEqual(
            chronology._source5_feedback_policy_artifact(
                policy_source, policy_id, descriptor, "host-a",
            )[0], selected_artifact,
        )
        static_policy_body = {
            key: value for key, value in selected_policy_body.items()
            if key not in ("schema", "capacity_floor_policy")
        }
        static_policy_body["schema"] = \
            "allocatbelt.application-feedback-policy-artifact.v1"
        static_artifact = {
            "schema": static_policy_body["schema"],
            "policy": static_policy_body,
            "policy_sha256": sha(canonical(static_policy_body)),
        }
        static_source = {**policy_source, "feedback_policy": static_artifact}
        self.assertEqual(
            chronology._source5_feedback_policy_artifact(
                static_source, None, None, "host-a",
            )[0], static_artifact,
        )
        malformed_policy = copy.deepcopy(policy_source)
        malformed_policy["feedback_policy"]["policy"]["capacity_floor_policy"] = {
            **descriptor, "policy_id": "unknown_floor",
        }
        malformed_policy["feedback_policy"]["policy_sha256"] = sha(
            canonical(malformed_policy["feedback_policy"]["policy"]),
        )
        with self.assertRaisesRegex(chronology.ChronologyError, "descriptor"):
            chronology._source5_feedback_policy_artifact(
                malformed_policy, policy_id, descriptor, "host-a",
            )

        host_ids = ["host-a", "host-b", "host-c"]
        contexts = [
            (workload, profile)
            for workload, profiles in (
                ("cpu", ("steady", "burst", "oversubscribed")),
                ("memory", ("steady", "burst", "oversubscribed")),
                ("http", ("steady", "burst", "oversubscribed")),
                ("disk", ("steady", "burst", "oversubscribed")),
                ("mixed", ("mixed", "burst", "oversubscribed")),
            )
            for profile in profiles
        ]
        allocators = ("allocatbelt", "mimalloc-secure", "mimalloc-standard", "system")
        executors = ("allocatbelt", "tokio-1.53.1")
        source_documents: dict[str, dict[str, Any]] = {}
        capacity_templates: list[dict[str, Any]] = []
        for host_index, host_id in enumerate(host_ids):
            source_sha = chr(ord("a") + host_index) * 64
            feedback_sha = chr(ord("d") + host_index) * 64
            fixed_sha = chr(ord("g") + host_index) * 64
            context_values = {
                f"{workload}/{profile}": {
                    "workers": 2 if profile == "oversubscribed" else 4,
                    "minimum_dense_observations": 1,
                    "controls": {},
                }
                for workload, profile in contexts
            }
            feedback_body = {
                "version": "runtime-feedback-policy-v1",
                "reader_contract": {}, "algorithm": {},
                "contexts": context_values, "source_pins": pins,
                "capacity_floor_policy": descriptor,
            }
            source_documents[host_id] = {
                "source": {"source_tree_sha256": source_sha},
                "feedback_policy": {
                    "schema": "allocatbelt.application-feedback-policy-artifact.v2",
                    "policy": feedback_body, "policy_sha256": feedback_sha,
                },
                "fixed_runtime_policy": {"policy_sha256": fixed_sha},
                "artifacts": {
                    allocator: {"sha256": chr(ord("j") + index) * 64}
                    for index, allocator in enumerate(allocators)
                },
            }
            for workload, profile in contexts:
                capacity_templates.append({
                    "capacity_key": {
                        "host_id": host_id, "workload": workload,
                        "profile": profile,
                        "calibration_id": f"cal-{host_id}-{workload}-{profile}",
                    },
                    "pressure_condition_id": f"condition-{host_id}-{workload}-{profile}",
                })

        feedback_templates: list[dict[str, Any]] = []
        for host_id in host_ids:
            source_document = source_documents[host_id]
            source_body = source_document["feedback_policy"]["policy"]
            for workload, profile in contexts:
                capacity = next(
                    item["capacity_key"] for item in capacity_templates
                    if item["capacity_key"]["host_id"] == host_id and
                    item["capacity_key"]["workload"] == workload and
                    item["capacity_key"]["profile"] == profile
                )
                condition_id = next(
                    item["pressure_condition_id"] for item in capacity_templates
                    if item["capacity_key"]["host_id"] == host_id and
                    item["capacity_key"]["workload"] == workload and
                    item["capacity_key"]["profile"] == profile
                )
                for family in ("fixed_policy", "external_pressure"):
                    for allocator in allocators:
                        for executor in executors:
                            policy = {
                                "version": source_body["version"],
                                "reader_contract": source_body["reader_contract"],
                                "algorithm": source_body["algorithm"],
                                "context": source_body["contexts"][f"{workload}/{profile}"],
                                "source_pins": source_body["source_pins"],
                            }
                            condition = condition_id if family == "external_pressure" else None
                            if family == "external_pressure":
                                policy["capacity_floor_policy"] = descriptor
                                policy["capacity_floor_policy_id"] = policy_id
                            identity = {
                                "campaign_id": "campaign",
                                "host_id": host_id, "workload": workload,
                                "profile": profile,
                                "comparison_family": family,
                                "capacity_calibration_id": capacity["calibration_id"],
                                "pressure_condition_id": condition,
                                "allocator": allocator, "executor": executor,
                                "source_sha256": source_document["source"]["source_tree_sha256"],
                                "binary_sha256": source_document["artifacts"][allocator]["sha256"],
                                "fixed_policy_sha256": source_document["fixed_runtime_policy"]["policy_sha256"],
                                "feedback_policy_sha256": source_document["feedback_policy"]["policy_sha256"],
                                "context_policy_sha256": sha(canonical(policy)),
                                "prospective_nonce": f"{len(feedback_templates):032x}",
                            }
                            body = {
                                "identity": identity,
                                "nonce_scope": "reusable_template",
                                "nonce_instantiation_schema": "allocatbelt.application-process-nonce-instantiation.v1",
                                "nonce_instantiation_rule": "sha256(template_nonce,campaign_id,job_run_id,pair_member,ordinal)",
                                "policy": policy, "required_proofs": [],
                            }
                            feedback_templates.append({
                                **body, "template_sha256": sha(canonical(body)),
                            })
        plan = {
            "campaign_id": "campaign", "host_ids": host_ids,
            "capacity_process_templates": capacity_templates,
            "feedback_process_templates": feedback_templates,
            "feedback_process_templates_sha256": sha(canonical(feedback_templates)),
        }
        chronology._source5_validate_selected_plan_templates(
            plan, source_documents, policy_id, descriptor,
        )

        bad_templates = copy.deepcopy(feedback_templates)
        selected_row = next(
            row for row in bad_templates
            if row["identity"]["comparison_family"] == "external_pressure"
        )
        selected_row["policy"]["capacity_floor_policy_id"] = "unknown_floor"
        selected_body = {key: value for key, value in selected_row.items()
                         if key != "template_sha256"}
        selected_row["template_sha256"] = sha(canonical(selected_body))
        bad_plan = {**plan, "feedback_process_templates": bad_templates,
                    "feedback_process_templates_sha256": sha(canonical(bad_templates))}
        with self.assertRaisesRegex(chronology.ChronologyError,
                                    "projection differs"):
            chronology._source5_validate_selected_plan_templates(
                bad_plan, source_documents, policy_id, descriptor,
            )

        foreign_templates = copy.deepcopy(feedback_templates)
        fixed_row = next(
            row for row in foreign_templates
            if row["identity"]["comparison_family"] == "fixed_policy"
        )
        fixed_row["policy"]["capacity_floor_policy_id"] = policy_id
        fixed_row["policy"]["capacity_floor_policy"] = descriptor
        fixed_body = {key: value for key, value in fixed_row.items()
                      if key != "template_sha256"}
        fixed_row["template_sha256"] = sha(canonical(fixed_body))
        foreign_plan = {
            **plan, "feedback_process_templates": foreign_templates,
            "feedback_process_templates_sha256": sha(canonical(foreign_templates)),
        }
        with self.assertRaisesRegex(chronology.ChronologyError,
                                    "unexpected field set"):
            chronology._source5_validate_selected_plan_templates(
                foreign_plan, source_documents, policy_id, descriptor,
            )

    def test_every_evidence_role_has_a_finite_bound(self) -> None:
        chronology = self.chronology
        self.assertEqual(set(chronology.SOURCE5_JOURNAL_ROLE_LIMITS),
                         chronology.SOURCE5_JOURNAL_EVIDENCE_ROLES)
        self.assertEqual(chronology._source5_journal_role_limit(
            "prepared_completion"), chronology.MAX_COMPLETION_BYTES)
        self.assertEqual(chronology._source5_journal_role_limit(
            "typed_source_symlink"), 4 * 1024)
        self.assertEqual(chronology._source5_journal_role_limit(
            "journal_width_contract"), 16 * 1024 * 1024)

    def test_final_plan_horizon_is_derived_from_all_original_host_job_lists(self) -> None:
        chronology = self.chronology
        request = {"scope": "final_prepared_bounded", "host_id": "host-a"}
        plan = {"jobs": {
            "exploration": [{"host_id": "host-a"} for _ in range(3)],
            "aa": [{"host_id": "host-a"} for _ in range(2)],
            "confirmation": [{"host_id": "host-a"} for _ in range(6)],
            "pressure": [{"host_id": "host-a"} for _ in range(6)],
            "soak": [{"host_id": "host-a"}],
        }}
        manifest = {"schema": chronology.SOURCE5_EXECUTION_SCHEMA_V3}
        ceiling = chronology._source5_plan_event_projection(
            plan, request, manifest,
        )
        self.assertEqual(ceiling["job_counts"], {
            "exploration": 3, "aa": 2, "confirmation": 6,
            "pressure": 6, "soak": 1,
        })
        self.assertEqual(ceiling["maximum_callback_events"], 113)
        self.assertEqual(ceiling["maximum_journal_bytes"],
                         113 * chronology.MAX_EVENT_BYTES)
        self.assertIs(ceiling["component_gate_claim"], False)

    def test_final_request_uses_versioned_envelope_then_legacy_keeps_100k(self) -> None:
        chronology = self.chronology
        output = "/private/output"
        campaign_id = "campaign-1"
        host_id = "host-a"
        chronology_dir = Path(output) / campaign_id / "chronology" / host_id
        request = {
            "schema": chronology.SOURCE5_HOST_JOURNAL_REQUEST_SCHEMA_V1,
            "scope": "final_prepared",
            "campaign_id": campaign_id,
            "host_id": host_id,
            "source_root": "/private/source",
            "input_root": "/private/input",
            "output_root": output,
            "execution_manifest": {
                "path": "/private/input/execution.json",
                "raw_sha256": "1" * 64, "semantic_sha256": "2" * 64,
            },
            "provenance": {
                "schema": chronology.SOURCE5_JOURNAL_PROVENANCE_SCHEMA_V1,
                "preparation_pin": {
                    "path": "/private/input/preparation.json",
                    "raw_sha256": "3" * 64,
                },
                "final_spec_pin": {
                    "path": "/private/input/spec.json",
                    "raw_sha256": "4" * 64,
                },
                "final_plan_pin": {
                    "path": "/private/input/plan.json",
                    "raw_sha256": "5" * 64,
                },
            },
            "journal": {
                "path": str(chronology_dir / "dispatch-journal.jsonl"),
                "raw_sha256": "6" * 64, "byte_count": 1,
                "record_count": chronology.MAX_JOURNAL_EVENTS + 1,
                "terminal_head": "7" * 64,
            },
            "origin_receipt": {
                "path": str(chronology_dir /
                            "source5-origin-journal-receipt.json"),
                "raw_sha256": "8" * 64, "semantic_sha256": "9" * 64,
            },
            "evidence_index": {
                "path": str(chronology_dir / "evidence-index.json"),
                "raw_sha256": "a" * 64, "semantic_sha256": "b" * 64,
            },
        }
        parsed = chronology._source5_journal_request(request)
        self.assertEqual(parsed["journal"]["record_count"], 100_001)
        budgeted = copy.deepcopy(request)
        budgeted["schema"] = chronology.SOURCE5_HOST_JOURNAL_REQUEST_SCHEMA_V2
        budgeted["host_evidence_budget"] = {
            "path": "/private/artifacts/campaign-1/source5/host-a/"
                    "evidence-budget/host-evidence-budget.json",
            "raw_sha256": "c" * 64,
            "semantic_sha256": "d" * 64,
        }
        budgeted["origin_receipt"]["path"] = str(
            chronology_dir / "source5-origin-journal-receipt-v2.json",
        )
        self.assertEqual(chronology._source5_journal_request(budgeted)["schema"],
                         chronology.SOURCE5_HOST_JOURNAL_REQUEST_SCHEMA_V2)
        budget_pin = budgeted["host_evidence_budget"]
        budget_row = {
            "role": "host_evidence_budget", "host_id": host_id,
            "origin_path": budget_pin["path"], "local_path": budget_pin["path"],
            "raw_sha256": budget_pin["raw_sha256"],
            "semantic_sha256": budget_pin["semantic_sha256"],
            "byte_count": 1024,
        }
        index_value = chronology.build_source5_journal_evidence_index_v2(
            campaign_id, host_id, "/private/source", "/private/input", output,
            [budget_row], budget_pin,
        )
        self.assertEqual(index_value["schema"],
                         chronology.SOURCE5_JOURNAL_EVIDENCE_INDEX_SCHEMA_V2)
        index_pin = {
            "path": str(chronology_dir / "evidence-index-v2.json"),
            "raw_sha256": "e" * 64,
            "semantic_sha256": index_value["index_sha256"],
        }
        request_value = chronology.build_source5_host_journal_request_v2(
            scope=budgeted["scope"], campaign_id=campaign_id, host_id=host_id,
            source_root=budgeted["source_root"], input_root=budgeted["input_root"],
            output_root=output,
            execution_manifest_pin=budgeted["execution_manifest"],
            provenance=budgeted["provenance"], journal=budgeted["journal"],
            origin_receipt_pin=budgeted["origin_receipt"],
            evidence_index_pin=index_pin,
            host_evidence_budget_pin=budget_pin,
        )
        self.assertEqual(request_value["host_evidence_budget"], budget_pin)
        with self.assertRaisesRegex(chronology.ChronologyError,
                                    "one exact host budget row"):
            chronology.build_source5_journal_evidence_index_v2(
                campaign_id, host_id, "/private/source", "/private/input", output,
                [], budget_pin,
            )
        missing_budget = copy.deepcopy(budgeted)
        del missing_budget["host_evidence_budget"]
        with self.assertRaisesRegex(chronology.ChronologyError,
                                    "unexpected field set"):
            chronology._source5_journal_request(missing_budget)
        legacy_receipt_path = copy.deepcopy(budgeted)
        legacy_receipt_path["origin_receipt"]["path"] = str(
            chronology_dir / "source5-origin-journal-receipt.json",
        )
        with self.assertRaisesRegex(chronology.ChronologyError,
                                    "exact locked host chronology directory"):
            chronology._source5_journal_request(legacy_receipt_path)
        prospective_budget = copy.deepcopy(budgeted)
        prospective_budget["scope"] = "prospective_exploration"
        prospective_budget["provenance"]["preparation_pin"] = None
        with self.assertRaisesRegex(chronology.ChronologyError,
                                    "final prepared scope"):
            chronology._source5_journal_request(prospective_budget)
        too_many = copy.deepcopy(request)
        too_many["journal"]["record_count"] = \
            chronology.MAX_SOURCE5_JOURNAL_EVENTS + 1
        with self.assertRaisesRegex(chronology.ChronologyError,
                                    "record count"):
            chronology._source5_journal_request(too_many)

        legacy = copy.deepcopy(request)
        legacy["scope"] = "prospective_exploration"
        legacy["provenance"]["preparation_pin"] = None
        with self.assertRaisesRegex(chronology.ChronologyError,
                                    "record count"):
            chronology._source5_journal_request(legacy)


class Source5JournalWidthContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.chronology = load_script(
            SCRIPT_DIR / "application-campaign-chronology.py",
            "source5_journal_width_contract_test_target",
        )

    def test_analyzer_pipe_comparison_normalizes_only_live_process_identity(self) -> None:
        chronology = self.chronology
        value = {
            "bootstrap": {
                "input_sha256": "a" * 64, "input_bytes": 4096,
                "input_transport": {
                    "schema": "allocatbelt.application-rust-analyzer-input-transport.v1",
                    "kind": "owned_stdin_pipe", "input_sha256": "a" * 64,
                    "input_bytes": 4096, "decoder_consumed_bytes": 4096,
                    "process": {
                        "parent_pid": 100, "child_pid": 101,
                        "start_ticks": 200,
                        "pipe": {
                            "file_type": "fifo", "parent_fd": 3,
                            "child_fd": 0, "device": 12,
                            "inode": 34, "mode": 0o600,
                        },
                    },
                },
                "analyzer_wall_seconds": 1.0,
                "resident_peak_bytes": 1024,
                "output_sha256": "b" * 64,
            },
            "numeric_gates_passed": False,
        }
        other = copy.deepcopy(value)
        process = other["bootstrap"]["input_transport"]["process"]
        process["parent_pid"] = 300
        process["child_pid"] = 301
        process["start_ticks"] = 400
        process["pipe"]["inode"] = 56
        self.assertEqual(chronology._source5_comparable_analysis(value),
                         chronology._source5_comparable_analysis(other))

        changed_device = copy.deepcopy(value)
        changed_device["bootstrap"]["input_transport"]["process"]["pipe"]["device"] = 13
        self.assertNotEqual(chronology._source5_comparable_analysis(value),
                            chronology._source5_comparable_analysis(changed_device))

        changed_bytes = copy.deepcopy(value)
        changed_bytes["bootstrap"]["input_bytes"] = 4097
        changed_bytes["bootstrap"]["input_transport"]["input_bytes"] = 4097
        changed_bytes["bootstrap"]["input_transport"]["decoder_consumed_bytes"] = 4097
        self.assertNotEqual(chronology._source5_comparable_analysis(value),
                            chronology._source5_comparable_analysis(changed_bytes))

        changed_hash = copy.deepcopy(value)
        changed_hash["bootstrap"]["input_sha256"] = "c" * 64
        changed_hash["bootstrap"]["input_transport"]["input_sha256"] = "c" * 64
        self.assertNotEqual(chronology._source5_comparable_analysis(value),
                            chronology._source5_comparable_analysis(changed_hash))

        changed_kind = copy.deepcopy(value)
        changed_kind["bootstrap"]["input_transport"]["kind"] = "regular_file"
        with self.assertRaises(chronology.ChronologyError):
            chronology._source5_comparable_analysis(changed_kind)

    def test_analyzer_pipe_v2_keeps_exact_gated_launch_proof(self) -> None:
        chronology = self.chronology
        value = {
            "bootstrap": {
                "input_sha256": "a" * 64, "input_bytes": 4096,
                "analyzer_binary_sha256": "e" * 64,
                "input_transport": {
                    "schema": "allocatbelt.application-rust-analyzer-input-transport.v2",
                    "kind": "owned_stdin_pipe", "input_sha256": "a" * 64,
                    "input_bytes": 4096, "decoder_consumed_bytes": 4096,
                    "launch_transition": {
                        "schema": "allocatbelt.application-rust-analyzer-launch-transition.v1",
                        "kind": "pinned_binary_fd_gate_exec",
                        "status": "exec_confirmed_close_on_exec_pipe",
                        "launcher_sha256": "c" * 64,
                        "binary_sha256": "e" * 64,
                        "executable_identity": "elf_proc_inode_matched",
                    },
                    "process": {
                        "parent_pid": 100, "child_pid": 101,
                        "start_ticks": 200,
                        "pipe": {
                            "file_type": "fifo", "parent_fd": 3,
                            "child_fd": 0, "device": 12,
                            "inode": 34, "mode": 0o600,
                        },
                    },
                },
                "analyzer_wall_seconds": 1.0,
                "resident_peak_bytes": 1024,
                "output_sha256": "b" * 64,
            },
        }
        other = copy.deepcopy(value)
        process = other["bootstrap"]["input_transport"]["process"]
        process["parent_pid"] = 300
        process["child_pid"] = 301
        process["start_ticks"] = 400
        process["pipe"]["inode"] = 56
        self.assertEqual(chronology._source5_comparable_analysis(value),
                         chronology._source5_comparable_analysis(other))

        changed_launcher = copy.deepcopy(value)
        changed_launcher["bootstrap"]["input_transport"][
            "launch_transition"]["launcher_sha256"] = "f" * 64
        self.assertNotEqual(
            chronology._source5_comparable_analysis(value),
            chronology._source5_comparable_analysis(changed_launcher),
        )

        changed_executable = copy.deepcopy(value)
        changed_executable["bootstrap"]["input_transport"][
            "launch_transition"]["executable_identity"] = "unverified"
        with self.assertRaises(chronology.ChronologyError):
            chronology._source5_comparable_analysis(changed_executable)

        unknown = copy.deepcopy(value)
        unknown["bootstrap"]["input_transport"]["ignored"] = True
        with self.assertRaises(chronology.ChronologyError):
            chronology._source5_comparable_analysis(unknown)

    def _contract_fixture(self) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any],
                                         dict[str, Any], dict[str, Any], dict[str, str],
                                         dict[str, str], dict[str, Any]]:
        chronology = self.chronology
        host_id = "host-a"
        campaign_id = "campaign-v4"
        phases = chronology._SOURCE5_WIDTH_PHASES
        run_id = "run-" + ("escaped\\quote\"é" * 18)
        plan_jobs: dict[str, list[dict[str, Any]]] = {}
        expected_jobs: dict[str, dict[str, Any]] = {}
        for ordinal, phase in enumerate(phases):
            plan_jobs[phase] = [{
                "phase": phase, "host_id": "host-b", "ordinal": 0,
                "run_id": f"foreign-{phase}",
            }, {
                "phase": phase, "host_id": host_id,
                "ordinal": ordinal + 7, "run_id": f"{phase}-{run_id}",
                "escaped_path": "/private/" + ("\\\"é" * 80),
            }]
            expected_jobs[phase] = plan_jobs[phase][1]
        plan = {"jobs": plan_jobs}
        plan_pin = {
            "path": "/private/input/final-plan.json",
            "raw_sha256": "a" * 64, "semantic_sha256": "b" * 64,
        }
        source_pin = {
            "path": "/private/input/source-manifest.json",
            "raw_sha256": "c" * 64, "semantic_sha256": "d" * 64,
        }
        owner_paths = chronology.SOURCE5_WIDTH_OWNER_PATHS
        source_files = []
        owner_pins = {}
        for index, (role, path) in enumerate(owner_paths.items()):
            digest = sha(f"source-owner-{index}".encode())
            source_files.append({
                "path": path, "kind": "file", "sha256": digest,
                "size": 100 + index,
            })
            owner_pins[role] = {
                "path": path, "raw_sha256": digest,
                "byte_count": 100 + index,
            }
        source_document = {"source": {"files": source_files}}
        original_pins = {
            "schema": "allocatbelt.application-campaign-chronology.v2",
            "campaign_id": campaign_id, "host_id": host_id,
            "plan": plan_pin, "source_manifest": source_pin,
            "escaped": "/private/" + ("\\\"é" * 80),
        }
        request = {
            "campaign_id": campaign_id, "host_id": host_id,
            "scope": "final_prepared_bounded",
        }
        manifest = {
            "schema": chronology.SOURCE5_EXECUTION_SCHEMA_V4,
            "campaign_id": campaign_id,
        }
        job_rows = []
        phase_totals = []
        success_event_count = 0
        success_job_bytes = 0
        failed_rows = []
        for phase_index, phase in enumerate(phases):
            job = expected_jobs[phase]
            member_count = 1 if phase == "soak" else 2
            event_counts = {
                "source5_authorized": 1,
                "source5_app_started": member_count,
                "source5_app_terminal": member_count,
                "source5_job_terminal": 1,
            }
            success_widths = {
                "source5_authorized": 900 + phase_index,
                "source5_app_started": 1300 + phase_index,
                "source5_app_terminal": 1700 + phase_index,
                "source5_job_terminal": 700 + phase_index,
            }
            failed_widths = dict(success_widths)
            if phase_index == 0:
                failed_widths["source5_app_terminal"] += 300
            success_bytes = sum(event_counts[key] * success_widths[key]
                                for key in chronology._SOURCE5_WIDTH_KINDS)
            failed_bytes = sum(event_counts[key] * failed_widths[key]
                               for key in chronology._SOURCE5_WIDTH_KINDS)
            row = {
                "phase": phase, "job_index": 0,
                "ordinal": job["ordinal"], "run_id": job["run_id"],
                "job_sha256": sha(canonical(job)),
                "event_counts": event_counts,
                "maximum_event_bytes_by_kind": success_widths,
                "failed_event_counts": dict(event_counts),
                "failed_event_bytes_by_kind": failed_widths,
                "success_job_bytes": success_bytes,
                "failed_window_bytes": failed_bytes,
                "failed_event_count": sum(event_counts.values()),
                "failed_event_count_uplift": 0,
                "byte_uplift": failed_bytes - success_bytes,
            }
            job_rows.append(row)
            phase_totals.append({
                "phase": phase, "job_count": 1,
                "event_count": sum(event_counts.values()),
                "success_event_bytes": success_bytes,
            })
            success_event_count += sum(event_counts.values())
            success_job_bytes += success_bytes
            failed_rows.append({
                "phase": phase, "job_index": 0,
                "ordinal": job["ordinal"], "run_id": job["run_id"],
                "job_sha256": row["job_sha256"],
                "failed_event_count": sum(event_counts.values()),
                "failed_event_count_uplift": 0,
                "failed_window_bytes": failed_bytes,
                "success_job_bytes": success_bytes,
                "byte_uplift": failed_bytes - success_bytes,
            })
        fixed_rows = [{
            "event": "source5_prepared_capacity_registered",
            "phase": "registration", "count": 1,
            "maximum_line_bytes": 800,
        }] + [{
            "event": "source5_analysis", "phase": phase, "count": 1,
            "maximum_line_bytes": 850 + index,
        } for index, phase in enumerate(chronology._SOURCE5_ANALYSIS_PHASES)]
        fixed_count = sum(row["count"] for row in fixed_rows)
        fixed_bytes = sum(row["count"] * row["maximum_line_bytes"]
                          for row in fixed_rows)
        failed_owner_window = max(
            failed_rows,
            key=lambda row: (row["byte_uplift"],
                             row["failed_event_count_uplift"],
                             -phases.index(row["phase"]), -row["job_index"]),
        )
        body = {
            "schema": chronology.SOURCE5_JOURNAL_WIDTH_CONTRACT_SCHEMA_V1,
            "campaign_id": campaign_id, "host_id": host_id,
            "original_pins_sha256": sha(canonical(original_pins)),
            "plan_pin": plan_pin, "source_manifest_pin": source_pin,
            "owner_pins": owner_pins, "job_rows": job_rows,
            "phase_totals": phase_totals,
            "fixed_event_widths": fixed_rows,
            "total_event_count": fixed_count + success_event_count,
            "total_event_bytes": fixed_bytes + success_job_bytes +
                failed_owner_window["byte_uplift"],
            "failed_owner_window": failed_owner_window,
        }
        contract = {**body, "contract_sha256": sha(canonical(body))}
        return (contract, manifest, plan, request, original_pins,
                source_pin, plan_pin, source_document)

    def test_width_contract_covers_all_callbacks_and_one_failed_owner_window(self) -> None:
        chronology = self.chronology
        (contract, manifest, plan, request, original, source_pin,
         plan_pin, source_document) = self._contract_fixture()
        projection = chronology._source5_validate_journal_width_contract(
            contract, manifest, plan, request, original,
            source_pin, plan_pin, source_document,
        )
        self.assertEqual(contract["total_event_count"], 35)
        self.assertEqual(projection["maximum_callback_events"], 35)
        self.assertEqual(contract["failed_owner_window"]["phase"], "exploration")
        self.assertEqual(contract["failed_owner_window"]["byte_uplift"], 600)
        self.assertEqual(
            projection["maximum_journal_bytes"], contract["total_event_bytes"],
        )

    def test_width_contract_rejects_omitted_callbacks_and_altered_byte_sum(self) -> None:
        chronology = self.chronology
        (contract, manifest, plan, request, original, source_pin,
         plan_pin, source_document) = self._contract_fixture()
        omitted = copy.deepcopy(contract)
        del omitted["job_rows"][0]["event_counts"]["source5_app_terminal"]
        body = {key: value for key, value in omitted.items()
                if key != "contract_sha256"}
        omitted["contract_sha256"] = sha(canonical(body))
        with self.assertRaisesRegex(chronology.ChronologyError,
                                    "unexpected field set"):
            chronology._source5_validate_journal_width_contract(
                omitted, manifest, plan, request, original,
                source_pin, plan_pin, source_document,
            )
        altered = copy.deepcopy(contract)
        altered["total_event_bytes"] += 1
        body = {key: value for key, value in altered.items()
                if key != "contract_sha256"}
        altered["contract_sha256"] = sha(canonical(body))
        with self.assertRaisesRegex(chronology.ChronologyError,
                                    "total/failure-window arithmetic"):
            chronology._source5_validate_journal_width_contract(
                altered, manifest, plan, request, original,
                source_pin, plan_pin, source_document,
            )

    def test_v4_line_width_counts_escaped_paths_and_u64_envelope(self) -> None:
        chronology = self.chronology
        path_value = "/private/" + ("\\\"é" * 700)
        self.assertLessEqual(len(path_value.encode("utf-8")),
                             chronology.MAX_PATH_BYTES)
        original = {"escaped_path": path_value}
        details = {
            "phase": "exploration",
            "analysis": {"path": path_value, "raw_sha256": "a" * 64},
            "analysis_sha256": "b" * 64, "job_count": 1,
            "job_set_sha256": "c" * 64,
            "job_evidence_complete": True,
            "numeric_gates_passed": False, "phase_gate_passed": False,
            "campaign_qualification_eligible": False,
        }
        record = {
            "schema": chronology.JOURNAL_SCHEMA, "sequence": 1,
            "monotonic_ns": chronology.U64_MAX,
            "campaign_id": "campaign-v4", "host_id": "host-a",
            "boot_id_sha256": "d" * 64, "original_pins": original,
            "event": "source5_analysis", "details": details,
        }
        unsigned = {"previous_sha256": "0" * 64, "record": record}
        record_sha = sha(chronology.canonical_bytes(unsigned))
        line = chronology.canonical_bytes({
            **unsigned, "record_sha256": record_sha,
        })
        projection = {
            "job_rows": {},
            "fixed_event_widths": [{
                "event": "source5_analysis", "phase": "exploration",
                "count": 1, "maximum_line_bytes": len(line),
            }],
        }
        stats: dict[str, Any] = {}
        records = list(chronology._iter_journal_records_from_chunks(
            [line], original, "campaign-v4", "host-a", "d" * 64,
            stats, expected_byte_count=len(line), maximum_events=1,
            maximum_bytes=len(line), source5_width_projection=projection,
        ))
        self.assertEqual(len(records), 1)
        too_small = copy.deepcopy(projection)
        too_small["fixed_event_widths"][0]["maximum_line_bytes"] -= 1
        with self.assertRaisesRegex(chronology.ChronologyError,
                                    "exceeds its exact source-derived event width"):
            list(chronology._iter_journal_records_from_chunks(
                [line], original, "campaign-v4", "host-a", "d" * 64,
                {}, expected_byte_count=len(line), maximum_events=1,
                maximum_bytes=len(line), source5_width_projection=too_small,
            ))

    def test_v4_failed_owner_window_blocks_successor_authorization(self) -> None:
        chronology = self.chronology
        prepared = {
            "source5_execution_schema": chronology.SOURCE5_EXECUTION_SCHEMA_V4,
        }
        state = chronology._empty_journal({"source5": "pins"})
        state["prepared_capacity_registration"] = {"registered": True}
        state["registration_head"] = "a" * 64
        state["source5_failed_owner_window"] = True
        details = {
            key: None
            for key in chronology._source5_authorization_detail_fields(prepared)
        }
        with self.assertRaisesRegex(chronology.ChronologyError,
                                    "a prior Source5 owner failed"):
            chronology._check_event_semantics(
                state, "source5_authorized", details, "b" * 64,
                prepared, replay=True,
            )

    def test_cleanup_source_shape_recomputes_full_generic_failure_cap(self) -> None:
        chronology = self.chronology
        cleanup_shape = {
            "maximum_session_members_per_snapshot": 262_144,
            "maximum_pidfd_signal_entries_per_snapshot": 262_144,
            "maximum_signal_snapshots": 5,
            "maximum_cleanup_errors": 1_348,
            "maximum_error_text_bytes": 8_192,
            "normal_cleanup_poll_count": 404,
            "emergency_cleanup_poll_count": 104,
            "term_grace_seconds": 3.0,
            "kill_reap_seconds": 1.0,
            "cleanup_poll_interval_seconds": 0.01,
            "source_maximum_bytes": 393_385_220,
            "admission_maximum_bytes": 393_385_220,
            "maximum_window_bytes": 786_770_440,
            "refusal_file_bytes": 65_536,
            "maximum_refusal_window_bytes": 131_072,
        }
        retention = {
            "cleanup_source_shape": cleanup_shape,
            "maximum_cleanup_sidecar_source_bytes": 393_385_220,
            "maximum_cleanup_sidecar_bytes": 393_385_220,
            "maximum_failed_cleanup_window_bytes": 786_770_440,
            "maximum_failed_cleanup_window_inodes": 2,
            "maximum_cleanup_sidecar_refusal_bytes": 65_536,
            "maximum_failed_cleanup_refusal_window_bytes": 131_072,
            "maximum_failed_cleanup_refusal_window_inodes": 2,
        }
        budget = {
            "path_catalogue": {"retention_policy": retention},
            "owner_contract": {
                "fixed_pair": {"limits": {"MAX_PROC_ENTRIES": 262_144}},
                "cleanup_source_shape": {
                    key: value for key, value in cleanup_shape.items()
                    if key not in {
                        "source_maximum_bytes", "admission_maximum_bytes",
                        "maximum_window_bytes", "refusal_file_bytes",
                        "maximum_refusal_window_bytes",
                    }
                },
            },
        }
        limits = chronology._source5_cleanup_limits_from_budget(budget)
        self.assertEqual(limits["source_max_bytes"], 393_385_220)
        self.assertEqual(limits["sidecar_window_bytes"], 786_770_440)
        changed = copy.deepcopy(budget)
        changed["path_catalogue"]["retention_policy"][
            "maximum_cleanup_sidecar_bytes"
        ] -= 1
        with self.assertRaisesRegex(chronology.ChronologyError,
                                    "source/admission/window budgets"):
            chronology._source5_cleanup_limits_from_budget(changed)
        nonfinite = copy.deepcopy(budget)
        nonfinite_shape = nonfinite["path_catalogue"]["retention_policy"][
            "cleanup_source_shape"
        ]
        nonfinite_shape["term_grace_seconds"] = float("inf")
        nonfinite["owner_contract"]["cleanup_source_shape"][
            "term_grace_seconds"
        ] = float("inf")
        with self.assertRaisesRegex(chronology.ChronologyError,
                                    "not a finite positive number"):
            chronology._source5_cleanup_limits_from_budget(nonfinite)
        member = {
            "pid": 7, "state": "Z", "parent_pid": 1,
            "process_group": 1, "session_id": 1, "start_ticks": 9,
        }
        cleanup = {
            "leader_info": None, "child_return_code": None,
            "timed_out": False, "artifact_budget_exceeded": False,
            "received_signal": None, "term_grace_seconds": 3.0,
            "kill_reap_seconds": 1.0,
            "signals": [{
                "group_signal": {
                    "signal": 15, "leader_pid": 1,
                    "leader_start_ticks": 9, "leader_unreaped": True,
                },
                "group_error": None, "pidfd_signals": [],
                "scan_error": None, "members": [member],
            }],
            "leader_unreaped_during_group_signals": True,
            "group_signal_after_leader_reap_count": 0,
            "leader_reaped": False, "remaining_session_members": [member],
            "cleanup_errors": [], "cleanup_status": "failed",
        }
        chronology._source5_validate_cleanup_source_shape(cleanup, limits)
        emergency_minimal = {
            "cleanup_status": "unverified", "leader_reaped": False,
            "group_signal_after_leader_reap_count": 0,
            "cleanup_errors": ["emergency cleanup detail retained"],
        }
        chronology._source5_validate_cleanup_source_shape(
            emergency_minimal, limits,
        )
        escaped_state = copy.deepcopy(cleanup)
        escaped_state["signals"][0]["members"][0]["state"] = "é"
        with self.assertRaisesRegex(chronology.ChronologyError,
                                    "process state is malformed"):
            chronology._source5_validate_cleanup_source_shape(
                escaped_state, limits,
            )
        oversized_error = copy.deepcopy(cleanup)
        oversized_error["cleanup_errors"] = ["x" * 8_193]
        with self.assertRaisesRegex(chronology.ChronologyError,
                                    "cleanup error text/count"):
            chronology._source5_validate_cleanup_source_shape(
                oversized_error, limits,
            )

    def test_host_budget_binds_v4_width_pin_and_keeps_legacy_unbound(self) -> None:
        chronology = self.chronology
        legacy_fields = chronology.SOURCE5_HOST_BUDGET_V2_LEGACY_FIELDS
        legacy_budget = {name: None for name in legacy_fields}
        legacy_budget["schema"] = "allocatbelt.application-source5-host-evidence-budget.v2"
        width_pin = {
            "path": "/private/artifacts/campaign-v4/source5/host-a/"
                    "prepared-input/journal-width-contract.json",
            "raw_sha256": "a" * 64,
            "semantic_sha256": "b" * 64,
        }
        v4_manifest = {
            "schema": chronology.SOURCE5_EXECUTION_SCHEMA_V4,
            "journal_width_contracts": {"host-a": {
                "artifact": {"path": width_pin["path"],
                             "raw_sha256": width_pin["raw_sha256"]},
                "semantic_sha256": width_pin["semantic_sha256"],
            }},
        }
        v4_budget = {
            **legacy_budget,
            "execution_manifest_schema": chronology.SOURCE5_EXECUTION_SCHEMA_V4,
            "journal_width_contract_pin": copy.deepcopy(width_pin),
        }
        chronology._source5_validate_budget_width_binding(
            v4_budget, v4_manifest, "host-a", width_pin,
        )
        changed = copy.deepcopy(v4_budget)
        changed["journal_width_contract_pin"]["raw_sha256"] = "c" * 64
        with self.assertRaisesRegex(chronology.ChronologyError,
                                    "not bound to the exact prepared width contract"):
            chronology._source5_validate_budget_width_binding(
                changed, v4_manifest, "host-a", width_pin,
            )
        v3_manifest = {"schema": chronology.SOURCE5_EXECUTION_SCHEMA_V3}
        chronology._source5_validate_budget_width_binding(
            legacy_budget, v3_manifest, "host-a", None,
        )
        self.assertFalse(chronology._source5_host_budget_width_bound(
            legacy_budget,
        ))
        signer_only_v4_manifest = {
            "schema": chronology.SOURCE5_EXECUTION_SCHEMA_V4,
        }
        chronology._source5_validate_budget_width_binding(
            legacy_budget, signer_only_v4_manifest, "host-a", None,
        )
        illegal_legacy_extension = {
            **legacy_budget,
            "execution_manifest_schema": chronology.SOURCE5_EXECUTION_SCHEMA_V4,
            "journal_width_contract_pin": None,
        }
        with self.assertRaisesRegex(chronology.ChronologyError,
                                    "requires its exact execution-v4 manifest"):
            chronology._source5_validate_budget_width_binding(
                illegal_legacy_extension, v3_manifest, "host-a", None,
            )

    def test_width_bound_captured_validation_has_no_origin_fallback(self) -> None:
        chronology = self.chronology
        host_id = "host-a"
        width_pin = {
            "path": "/private/artifacts/campaign/source5/host-a/"
                    "prepared-input/journal-width-contract.json",
            "raw_sha256": "a" * 64, "semantic_sha256": "b" * 64,
        }
        legacy = {
            name: None for name in chronology.SOURCE5_HOST_BUDGET_V2_LEGACY_FIELDS
        }
        legacy["schema"] = "allocatbelt.application-source5-host-evidence-budget.v2"
        budget = {
            **legacy,
            "execution_manifest_schema": chronology.SOURCE5_EXECUTION_SCHEMA_V4,
            "journal_width_contract_pin": width_pin,
        }
        manifest = {
            "schema": chronology.SOURCE5_EXECUTION_SCHEMA_V4,
            "hosts": [host_id],
            "journal_width_contracts": {host_id: {
                "artifact": {
                    "path": width_pin["path"],
                    "raw_sha256": width_pin["raw_sha256"],
                },
                "semantic_sha256": width_pin["semantic_sha256"],
            }},
        }
        with self.assertRaisesRegex(
                chronology.ChronologyError,
                "omits the direct journal_width_contract role"):
            chronology._source5_captured_host_budget_validation_inputs(
                budget, manifest, host_id, {}, 8 * 1024 * 1024,
            )
        changed_row = {
            "origin_path": width_pin["path"],
            "role": "journal_width_contract", "host_id": host_id,
            "raw_sha256": "c" * 64,
            "semantic_sha256": width_pin["semantic_sha256"],
            "byte_count": 1,
        }
        with self.assertRaisesRegex(
                chronology.ChronologyError,
                "captured width-contract row differs"):
            chronology._source5_captured_host_budget_validation_inputs(
                budget, manifest, host_id,
                {width_pin["path"]: changed_row}, 8 * 1024 * 1024,
            )

    def test_h8_v4_budget_builder_requires_captured_width_bytes_and_reader(self) -> None:
        chronology = self.chronology
        budget_tests = load_script(
            SCRIPT_DIR / "test-application-source5-evidence-budget.py",
            "source5_h8_budget_fixture_for_chronology",
        )
        budget = budget_tests.budget
        fixture = budget_tests.fixture()
        host_id = fixture["host_id"]

        execution = copy.deepcopy(fixture["execution"])
        execution["schema"] = chronology.SOURCE5_EXECUTION_SCHEMA_V4
        execution_body = {
            key: value for key, value in execution.items()
            if key != "manifest_sha256"
        }
        execution["manifest_sha256"] = sha(canonical(execution_body))
        fixture["execution"] = execution
        execution_raw = canonical(execution)
        execution_pin = fixture["pins"]["execution_manifest"]
        fixture["pins"]["execution_manifest"] = {
            "path": execution_pin["path"],
            "raw_sha256": sha(execution_raw),
            "semantic_sha256": execution["manifest_sha256"],
        }
        audit = budget.build_host_evidence_budget_plan(
            fixture["spec"], fixture["plan"], fixture["sources"],
            execution, host_id, pins_value=fixture["pins"],
        )
        # Keep the producer's established one-job construction fixture. This
        # exercises the actual H8 v4 builder/validator without asserting that
        # the original campaign is execution-ready.
        audit = copy.deepcopy(audit)
        audit["schedule"]["job_counts"] = {
            phase: int(phase == "exploration") for phase in budget.PHASES
        }
        audit["schedule"]["fixed_job_count"] = 1
        audit["schedule"]["pressure_job_count"] = 0
        audit["schedule"]["total_job_count"] = 1
        audit["schedule"]["maximum_callback_events"] = 13
        audit["schedule"]["worst_case_journal_bytes"] = \
            13 * budget.MAX_EVENT_BYTES
        audit_body = {
            key: value for key, value in audit.items()
            if key != "budget_plan_sha256"
        }
        audit["budget_plan_sha256"] = sha(canonical(audit_body))

        source_digest = audit["original_pins"]["source_manifests"][host_id][
            "semantic_sha256"
        ]
        typed_rows = {
            row["path"]: row
            for row in fixture["sources"][host_id]["source"]["files"]
        }
        width_owner_pins = {
            role: {"path": relative, "raw_sha256": typed_rows[relative]["sha256"],
                   "byte_count": typed_rows[relative]["size"]}
            for role, relative in chronology.SOURCE5_WIDTH_OWNER_PATHS.items()
        }
        owner_pins = {
            role: width_owner_pins[role]
            for role in chronology.SOURCE5_HOST_BUDGET_V2_LEGACY_OWNER_PATHS
        }
        source_cleanup = budget._cleanup_source_shape(
            budget.SOURCE5_CLEANUP_SESSION_MEMBER_LIMIT,
        )
        owner_cleanup_fields = {
            "maximum_session_members_per_snapshot",
            "maximum_pidfd_signal_entries_per_snapshot",
            "maximum_signal_snapshots", "maximum_cleanup_errors",
            "maximum_error_text_bytes", "normal_cleanup_poll_count",
            "emergency_cleanup_poll_count", "term_grace_seconds",
            "kill_reap_seconds", "cleanup_poll_interval_seconds",
        }
        owner_cleanup = {
            key: source_cleanup[key] for key in owner_cleanup_fields
        }
        owner_contract_body = {
            "schema": "allocatbelt.application-source5-owner-evidence-catalogue.v1",
            "source_manifest_sha256": source_digest,
            "owner_source_pins": owner_pins,
            "fixed_pair": {}, "pressure_pair": {}, "soak": {},
            "transport_caps": {
                "chronology": {"MAX_COMPLETION_BYTES": 16 * 1024 * 1024},
            },
            "cleanup_source_shape": owner_cleanup,
            "role_ceiling_conflicts": {},
            "exact_full_path_catalogue_complete": True,
            "execution_ready": False, "qualification_eligible": False,
        }
        owner_contract = {
            **owner_contract_body,
            "owner_contract_sha256": sha(canonical(owner_contract_body)),
        }

        job = next(
            value for value in fixture["plan"]["jobs"]["exploration"]
            if value["host_id"] == host_id
        )
        phase = "exploration"
        run_id = job["run_id"]
        ordinal = 1
        event_counts = {
            "source5_authorized": 1,
            "source5_app_started": 2,
            "source5_app_terminal": 2,
            "source5_job_terminal": 1,
        }
        success_widths = {name: 128 for name in event_counts}
        failed_widths = dict(success_widths)
        failed_widths["source5_app_terminal"] += 1
        success_job_bytes = sum(
            event_counts[name] * success_widths[name] for name in event_counts
        )
        failed_window_bytes = sum(
            event_counts[name] * failed_widths[name] for name in event_counts
        )
        failed_job_row = {
            "phase": phase, "job_index": 0, "ordinal": ordinal,
            "run_id": run_id, "job_sha256": sha(canonical(job)),
            "failed_event_count": sum(event_counts.values()),
            "failed_event_count_uplift": 0,
            "failed_window_bytes": failed_window_bytes,
            "success_job_bytes": success_job_bytes,
            "byte_uplift": failed_window_bytes - success_job_bytes,
        }
        job_row = {
            "phase": phase, "job_index": 0, "ordinal": ordinal,
            "run_id": run_id, "job_sha256": sha(canonical(job)),
            "event_counts": event_counts,
            "maximum_event_bytes_by_kind": success_widths,
            "failed_event_counts": dict(event_counts),
            "failed_event_bytes_by_kind": failed_widths,
            "success_job_bytes": success_job_bytes,
            "failed_window_bytes": failed_window_bytes,
            "failed_event_count": sum(event_counts.values()),
            "failed_event_count_uplift": 0,
            "byte_uplift": failed_window_bytes - success_job_bytes,
        }
        phase_totals = [{
            "phase": selected_phase,
            "job_count": int(selected_phase == phase),
            "event_count": sum(event_counts.values()) if selected_phase == phase else 0,
            "success_event_bytes": success_job_bytes if selected_phase == phase else 0,
        } for selected_phase in budget.PHASES]
        fixed_widths = [{
            "event": "source5_prepared_capacity_registered",
            "phase": "registration", "count": 1,
            "maximum_line_bytes": 128,
        }] + [{
            "event": "source5_analysis", "phase": selected_phase,
            "count": 1, "maximum_line_bytes": 128,
        } for selected_phase in (
            "exploration", "aa", "fixed_analysis", "pressure_analysis",
            "soak", "final_analysis",
        )]
        width_pin_path = (
            "/private/artifacts/campaign-a/source5/host-a/prepared-input/"
            "journal-width-contract.json"
        )
        width_contract_body = {
            "schema": budget.JOURNAL_WIDTH_CONTRACT_SCHEMA,
            "campaign_id": audit["campaign_id"], "host_id": host_id,
            "original_pins_sha256": sha(canonical(audit["original_pins"])),
            "plan_pin": audit["original_pins"]["plan"],
            "source_manifest_pin": audit["original_pins"]["source_manifests"][host_id],
            "owner_pins": width_owner_pins,
            "job_rows": [job_row], "phase_totals": phase_totals,
            "fixed_event_widths": fixed_widths,
            "total_event_count": 13,
            "total_event_bytes": 7 * 128 + success_job_bytes +
                failed_job_row["byte_uplift"],
            "failed_owner_window": failed_job_row,
        }
        width_contract = {
            **width_contract_body,
            "contract_sha256": sha(canonical(width_contract_body)),
        }
        width_raw = canonical(width_contract)
        width_pin = {
            "path": width_pin_path, "raw_sha256": sha(width_raw),
            "semantic_sha256": width_contract["contract_sha256"],
        }

        row_helper = budget_tests.Source5PathCatalogueTests.row
        job_digest = sha(canonical(job))
        core_rows = [
            row_helper(
                f"/private/artifacts/{phase}/{run_id}/application-output.json",
                maximum=1024,
            ),
            row_helper(
                f"/private/artifacts/campaign-a/source5/{host_id}/job-records/{run_id}.json",
                role="source5_job_record", maximum=128 * 1024,
            ),
        ]
        for row in core_rows:
            row["phase"] = phase
            row["run_id"] = run_id
            row["storage_root"] = "/private/artifacts"
        cleanup_cap = budget._cleanup_sidecar_source_bound(
            budget.SOURCE5_CLEANUP_SESSION_MEMBER_LIMIT,
        )
        for member_index in (0, 1):
            cleanup_stem = (
                f"/private/output/{phase}/cleanup-sidecars/"
                f"{ordinal:06d}-{job_digest}-member{member_index}.json"
            )
            for role, path, maximum in (
                (budget.SOURCE5_CLEANUP_SIDECAR_ROLE, cleanup_stem,
                 cleanup_cap),
                (budget.SOURCE5_CLEANUP_SIDECAR_REFUSAL_ROLE,
                 cleanup_stem + ".refusal.json",
                 budget.SOURCE5_CLEANUP_REFUSAL_BYTES),
            ):
                row = row_helper(path, role=role, maximum=maximum)
                row.update({
                    "phase": phase, "run_id": run_id,
                    "member_index": member_index,
                    "storage_root": "/private/output",
                })
                core_rows.append(row)
        archive_caps = budget.project_archive_job_caps(core_rows)[
            (phase, run_id)
        ]
        transport_rows = []
        for role, field, root in (
            ("source5_checkpoint_request", "checkpoint_request_bytes", "/private/output"),
            ("source5_transfer_offer", "transfer_offer_bytes", "/private/output"),
            ("source5_transfer_packet", "transfer_packet_bytes", "/private/scratch"),
            ("source5_ack_bundle", "ack_bundle_bytes", "/private/output"),
            ("source5_ack_bundle_incoming", "ack_bundle_bytes", "/private/output"),
            ("source5_checkpoint", "checkpoint_bytes", "/private/output"),
            ("source5_object_manifest", "object_manifest_bytes", "/private/output"),
            ("source5_archive_ack", "archive_ack_bytes", "/private/output"),
            ("source5_archive_signature", "signature_bytes", "/private/output"),
            ("source5_stage_map", "stage_map_bytes", "/private/output"),
        ):
            row = row_helper(
                f"{root}/evidence/{phase}/{run_id}/{role}.bin",
                role=role, maximum=archive_caps[field],
            )
            row.update({"phase": phase, "run_id": run_id,
                        "storage_root": root})
            transport_rows.append(row)
        width_row = row_helper(
            width_pin_path, role="journal_width_contract",
            maximum=len(width_raw),
        )
        width_row.update({
            "owner": "source5_controller", "phase": None, "run_id": None,
            "storage_root": "/private/artifacts",
            "origin_pin": {
                "raw_sha256": width_pin["raw_sha256"],
                "semantic_sha256": width_pin["semantic_sha256"],
            },
        })

        readback_rows = []
        for role, name, maximum, kind, file_maximum, inodes in (
            ("source5_archive_read_request_slot", "request.json", 11, "file", 11, 1),
            ("source5_archive_read_response_slot", "response.json", 13, "file", 13, 1),
            ("source5_archive_read_response_incoming", "response.json.incoming", 13, "file", 13, 1),
            ("source5_archive_read_bundle", "response.tar", 17, "file", 17, 1),
            ("source5_archive_read_bundle_incoming", "response.tar.incoming", 17, "file", 17, 1),
            ("source5_archive_read_stage", "stage", 100, "tree", 80, 4),
            (budget.SOURCE5_ANALYZER_SPOOL_ROLE, "analyzer-spool", 101, "tree", 77, 3),
        ):
            row = row_helper(
                f"/private/scratch/archive-readback/{name}", role=role,
                maximum=maximum, kind=kind, file_maximum=file_maximum, inodes=inodes,
            )
            row.update({"phase": None, "run_id": None, "member_index": None,
                        "aggregate_id": None, "owner": "source5_controller",
                        "storage_root": "/private/scratch"})
            readback_rows.append(row)
        control = row_helper(
            "/private/output/archive-read-control.jsonl",
            role=budget.SOURCE5_ARCHIVE_READ_CONTROL_ROLE, maximum=23,
        )
        control.update({"phase": None, "run_id": None, "member_index": None,
                        "aggregate_id": None, "owner": "source5_controller",
                        "storage_root": "/private/output"})
        readback_rows.append(control)

        roots = [
            {"path": "/private/artifacts", "role": "artifact",
             "reserved_bytes": budget.MAX_U64,
             "reserved_inodes": budget.MAX_U64, "filesystem_id": "1"},
            {"path": "/private/output", "role": "output",
             "reserved_bytes": budget.MAX_U64,
             "reserved_inodes": budget.MAX_U64, "filesystem_id": "2"},
            {"path": "/private/scratch", "role": "scratch",
             "reserved_bytes": budget.MAX_U64,
             "reserved_inodes": budget.MAX_U64, "filesystem_id": "3"},
            {"path": "/private/store", "role": "evidence_store",
             "reserved_bytes": budget.MAX_U64,
             "reserved_inodes": budget.MAX_U64, "filesystem_id": "4"},
        ]
        with tempfile.TemporaryDirectory(
                prefix="source5-chronology-h8-v4-budget-") as temporary:
            root = Path(temporary)
            catalogue_directory = root / "catalogue"
            catalogue_directory.mkdir(mode=0o700)
            catalogue = budget.write_path_catalogue_chunks(
                [*core_rows, *transport_rows, width_row, *readback_rows], catalogue_directory,
            )
            reservation = budget.build_storage_reservation_value(
                audit["campaign_id"], host_id, roots,
            )
            reservation_raw = canonical(reservation)
            reservation_pin = {
                "path": "/private/reservation.json",
                "raw_sha256": sha(reservation_raw),
                "semantic_sha256": reservation["reservation_sha256"],
                "byte_count": len(reservation_raw),
            }
            built = budget.build_host_evidence_budget_v2(
                audit, owner_contract, catalogue, reservation,
                reservation_pin,
                journal_width_contract_value=width_contract,
                journal_width_contract_pin_value=width_pin,
                journal_width_contract_raw=width_raw,
            )
            chunk_bytes = {
                item["path"]: Path(item["path"]).read_bytes()
                for item in catalogue["chunks"]
            }
            descriptor_by_path = {
                item["path"]: item for item in catalogue["chunks"]
            }

            def read_catalogue_chunk(path: str, byte_count: int) -> bytes:
                descriptor = descriptor_by_path.get(path)
                self.assertIsNotNone(descriptor)
                self.assertEqual(descriptor["byte_count"], byte_count)
                return chunk_bytes[path]

            validated = budget.validate_host_evidence_budget_v2(
                built, journal_width_contract_raw=width_raw,
                catalogue_row_reader=read_catalogue_chunk,
            )
            self.assertEqual(built, validated)
            self.assertEqual(set(built), chronology.SOURCE5_HOST_BUDGET_V2_WIDTH_FIELDS)
            self.assertEqual(built["execution_manifest_schema"],
                             chronology.SOURCE5_EXECUTION_SCHEMA_V4)
            self.assertEqual(built["journal_width_contract_pin"], width_pin)
            self.assertEqual(
                set(built["owner_contract"]["owner_source_pins"]),
                set(chronology.SOURCE5_HOST_BUDGET_V2_LEGACY_OWNER_PATHS),
            )
            self.assertEqual(built["schedule"]["maximum_callback_event_bytes"], 129)
            self.assertEqual(built["schedule"]["worst_case_journal_bytes"],
                             width_contract["total_event_bytes"])
            self.assertEqual(built["readiness"], {
                "budget_complete": False, "execution_ready": False,
                "component_gate_ready": False, "qualification_eligible": False,
            })
            self.assertEqual(built["execution_blockers"], [
                "verified_between_pair_archive_ack_reclaim_not_integrated",
            ])

            manifest = {
                "schema": chronology.SOURCE5_EXECUTION_SCHEMA_V4,
                "journal_width_contracts": {host_id: {
                    "artifact": {
                        "path": width_pin["path"],
                        "raw_sha256": width_pin["raw_sha256"],
                    },
                    "semantic_sha256": width_pin["semantic_sha256"],
                }},
            }
            chronology._source5_validate_budget_width_binding(
                built, manifest, host_id, width_pin,
            )
            with self.assertRaisesRegex(
                    budget.BudgetPlanError,
                    "captured bytes are not bounded"):
                budget.validate_host_evidence_budget_v2(
                    built, journal_width_contract_raw=None,
                    catalogue_row_reader=read_catalogue_chunk,
                )
            with self.assertRaisesRegex(budget.BudgetPlanError,
                                        "raw pin differs"):
                budget.validate_host_evidence_budget_v2(
                    built, journal_width_contract_raw=width_raw + b" ",
                    catalogue_row_reader=read_catalogue_chunk,
                )

    def test_failed_cleanup_record_uses_compact_summary_and_separate_pin(self) -> None:
        chronology = self.chronology
        cleanup = {
            "cleanup_status": "failed", "leader_reaped": False,
            "group_signal_after_leader_reap_count": 1,
            "cleanup_errors": ["synthetic owner cleanup error"],
        }
        raw = chronology.canonical_bytes(cleanup)
        summary, pin = chronology._source5_cleanup_sidecar_reference(
            cleanup, Path("/private/out/member-cleanup.json"), sha(raw), len(raw),
        )
        self.assertEqual(summary["cleanup_sha256"], sha(raw))
        self.assertEqual(pin["raw_sha256"], sha(raw))
        self.assertEqual(pin["byte_count"], len(raw))
        self.assertNotIn("sidecar", summary)
        self.assertNotIn("cleanup_errors", summary)
        self.assertLess(len(canonical(summary)), 2_048)
        refusal, refusal_pin = chronology._source5_cleanup_refusal_reference(
            cleanup, Path("/private/out/member-cleanup.json.refusal.json"),
            canonical({"schema": "refusal"}), sha(raw), len(raw), len(raw) - 1,
            "cleanup_raw_bytes_exceeded",
        )
        self.assertFalse(refusal["raw_cleanup_retained"])
        self.assertFalse(refusal["cleanup_verified"])
        self.assertEqual(refusal["disposition"], "refused_over_quota")
        self.assertEqual(refusal_pin["byte_count"], len(canonical({"schema": "refusal"})))


class Source5CapturedLegacyBudgetApiTests(unittest.TestCase):
    def test_legacy_captured_validator_keeps_its_positional_only_contract(self):
        chronology = load_script(
            SCRIPT_DIR / "application-campaign-chronology.py",
            "source5_legacy_positional_budget_api_test",
        )
        value = {key: None for key in chronology.SOURCE5_HOST_BUDGET_V2_LEGACY_FIELDS}
        value["schema"] = "allocatbelt.application-source5-host-evidence-budget.v2"
        called = []
        class CapturedLegacyValidator:
            @staticmethod
            def validate_host_evidence_budget_v2(argument):
                called.append(argument)
                return argument
        def forbidden_origin_read(*_args):
            raise AssertionError("legacy schema dispatch opened an origin")
        result = chronology._source5_validate_budget_with_captured_inputs(
            CapturedLegacyValidator, value, None, forbidden_origin_read,
        )
        self.assertIs(result, value)
        self.assertEqual(called, [value])


class Source5FixedCapturedReplayTests(unittest.TestCase):
    """Caller wiring with real0400 IO/archive validators; numeric owner mocked."""

    @classmethod
    def setUpClass(cls):
        cls.chronology = load_script(SCRIPT_DIR / "application-campaign-chronology.py", "captured_fixed_chronology_target")
        cls.archive = load_script(SCRIPT_DIR / "application-source5-evidence-archive.py", "captured_fixed_archive_fixture")

    @staticmethod
    def _seal(body, field):
        return {**body, field: sha(canonical({key: value for key, value in body.items() if key != field}))}

    def _seal_view(self, case):
        record = self._seal(case["record"], "record_sha256")
        case["record"] = record
        record_raw = canonical(record)
        write_file(case["record_path"], record_raw, 0o600)
        record_pin = {"path": str(case["record_path"]), "raw_sha256": sha(record_raw)}
        case["record_pin"] = record_pin
        chronology = record["chronology"]
        authorization = {"authorization_id": chronology["authorization_id"],
                         "authorization_head": chronology["authorization_head"],
                         "terminal_head": chronology["job_terminal_head"],
                         "component_sha256": chronology["component_sha256"],
                         "process_metrics_sha256": chronology["process_metrics_sha256"]}
        request = self._seal({"schema": self.archive.REQUEST_SCHEMA_V1,
            "context": case["archive_context"], "job_record_pin": record_pin,
            "authorization": authorization, "predecessor_ack_pin": None,
            "owner_receipt_pins": {row["role"]: {
                "path": row["origin_path"], "raw_sha256": row["raw_sha256"],
                "semantic_sha256": row["semantic_sha256"]}
                for row in sorted(case["entries"], key=lambda row: row["role"]) if "receipt" in row["role"]},
            "empty_tmp_proofs": [], "entries": case["entries"]}, "request_sha256")
        request_raw = canonical(request)
        request_pin = {"path": "/absent-private-root/request.json", "raw_sha256": sha(request_raw),
                       "semantic_sha256": request["request_sha256"]}
        job = record["job"]
        objects = []
        for row in case["entries"]:
            identity = self.archive._object_identity(row["origin_path"], row["raw_sha256"])
            objects.append({**row, "object_id": identity,
                "object_pin": {"path": "/absent-private-root/source5/objects/" + identity,
                               "raw_sha256": row["raw_sha256"], "semantic_sha256": row["raw_sha256"],
                               "byte_count": row["byte_count"]}})
        manifest = self._seal({"schema": self.archive.OBJECT_MANIFEST_SCHEMA_V1,
            "campaign_id": "captured-fixture", "host_id": "host-1", "phase": job["phase"],
            "job_index": 0, "job_ordinal": job["ordinal"], "job_sha256": sha(canonical(job)),
            "run_id": job["run_id"], "job_record_raw_sha256": sha(record_raw),
            "predecessor_ack_pin": None, "objects": objects, "object_count": len(objects),
            "payload_bytes": sum(row["byte_count"] for row in objects)}, "manifest_sha256")
        manifest_raw = canonical(manifest)
        manifest_pin = {"path": "/absent-private-root/manifest.json", "raw_sha256": sha(manifest_raw),
                        "semantic_sha256": manifest["manifest_sha256"]}
        checkpoint = self._seal({"schema": self.archive.CHECKPOINT_SCHEMA_V1,
            "request_pin": request_pin, "context": case["archive_context"], "job_record_pin": record_pin,
            "authorization": authorization, "predecessor_ack_pin": None,
            "owner_receipt_pins": request["owner_receipt_pins"], "empty_tmp_proofs": [],
            "object_manifest_pin": manifest_pin, "entries": case["entries"]}, "checkpoint_sha256")
        checkpoint_raw = canonical(checkpoint)
        view = case.get("view", {})
        view.update({"schema": "allocatbelt.application-source5-archived-job-read-view.v1",
            "campaign_id": "captured-fixture", "host_id": "host-1", "phase": job["phase"],
            "job_index": 0, "ordinal": job["ordinal"], "run_id": job["run_id"], "job_sha256": sha(canonical(job)),
            "checkpoint_pin": {"path": "/absent-private-root/checkpoint.json", "raw_sha256": sha(checkpoint_raw),
                               "semantic_sha256": checkpoint["checkpoint_sha256"]}, "checkpoint_raw": checkpoint_raw,
            "manifest_pin": manifest_pin, "manifest_raw": manifest_raw,
            "archive_ack_pin": {"path": "/absent-private-root/ack.json", "raw_sha256": "a" * 64, "semantic_sha256": "b" * 64},
            "signature_pin": {"path": "/absent-private-root/ack.sig", "raw_sha256": "c" * 64, "signer_fingerprint": "A" * 40},
            "archive_request_pin": request_pin, "archive_request_raw": request_raw,
            "fixed_host_receipt_pin": case["host_pin"], "owner_host_receipt_pin": case["host_pin"],
            "readback_request_pin": {"path": str(case["root"] / "read-request"), "raw_sha256": "d" * 64, "semantic_sha256": "e" * 64},
            "readback_response_pin": {"path": str(case["root"] / "read-response"), "raw_sha256": "f" * 64, "semantic_sha256": "0" * 64, "byte_count": 100},
            "readback_bundle_pin": {"path": str(case["root"] / "read-body"), "raw_sha256": "1" * 64, "byte_count": 10240},
            "stage_root": str(case["stage"]), "objects": case["refs"],
            "qualification_eligible": False, "may_reclaim": False})
        case["view"] = view

    @contextmanager
    def _case(self):
        chronology = self.chronology
        with tempfile.TemporaryDirectory(prefix="chrono-captured-fixed-") as temporary:
            root = Path(temporary).resolve()
            pair, stage = root / "pair", root / "stage"
            pair.mkdir(mode=0o700)
            stage.mkdir(mode=0o700)
            job = {"host_id": "host-1", "phase": "confirmation", "ordinal": 1, "run_id": "captured-fixed-job"}
            metrics = [{"member": 0}, {"member": 1}]
            source_pin = {"path": str(root / "source.json"), "raw_sha256": "2" * 64, "semantic_sha256": "3" * 64}
            execution_pin = {"path": str(root / "execution.json"), "raw_sha256": "4" * 64}
            plan_pin = {"path": str(root / "plan.json"), "raw_sha256": "5" * 64, "semantic_sha256": "6" * 64}
            budget_pin = {"path": str(root / "budget.json"), "raw_sha256": "7" * 64, "semantic_sha256": "8" * 64}
            manifest = {"schema": chronology.SOURCE5_EXECUTION_SCHEMA_V4, "manifest_sha256": "9" * 64}
            overlay = {"output_root": str(pair), "runtime_bindings": {"pin": {"path": str(pair / "runtime.json"), "sha256": sha(b"runtime")}},
                       "sources": {"manifests": {"host-1": {"pin": {"path": source_pin["path"], "sha256": source_pin["raw_sha256"]}, "manifest_sha256": source_pin["semantic_sha256"]}},
                                   "selected": {"source_tree_sha256": "a" * 64}}}
            overlay_raw = canonical(overlay)
            overlay_pin = {"path": str(pair / "fixed-pair-execution-overlay.json"), "sha256": sha(overlay_raw)}
            helper = {"payload": {"overlay_pin": overlay_pin}}
            helper_raw = canonical(helper)
            helper_pin = {"path": str(root / "reclaimed-helper.json"), "raw_sha256": sha(helper_raw)}
            receipt = self._seal({"process_metrics": metrics, "process_validation_errors": [None, None],
                       "inputs_unchanged": True, "processes_sha256": sha(b"processes")}, "receipt_sha256")
            receipt_raw = canonical(receipt)
            receipt_pin = {"path": str(pair / "fixed-pair-execution-receipt.json"), "raw_sha256": sha(receipt_raw)}
            host_body = self._seal({"fixture": "mocked numeric owner; no host attestation claim"}, "receipt_sha256")
            host_raw = canonical(host_body)
            host_pin = {"path": str(root / "fixed-host-receipt.json"), "raw_sha256": sha(host_raw), "host_verification_sha256": host_body["receipt_sha256"]}
            fixed_path = SCRIPT_DIR / "application-fixed-pair.py"
            fixed_raw = fixed_path.read_bytes()
            fixed_sha = sha(fixed_raw)
            files = []
            for relative in ("scripts/application-fixed-pair.py", "scripts/application-source5-evidence-archive.py"):
                path = SOURCE_ROOT / relative
                raw = path.read_bytes()
                files.append({"path": relative, "kind": "file", "mode": format(path.stat().st_mode, "o"), "sha256": sha(raw), "size": len(raw)})
            prepared = {"campaign_id": "captured-fixture", "host_id": "host-1", "source_root": SOURCE_ROOT,
                        "source": {"source": {"files": files}}, "source5_execution_schema": chronology.SOURCE5_EXECUTION_SCHEMA_V4,
                        "source5_execution_manifest_pin": execution_pin, "plan": {"jobs": {"confirmation": [job]}},
                        "original_pins": {"plan": plan_pin, "source_manifests": [{"host_id": "host-1", **source_pin}]}}
            verification = {"schema": "allocatbelt.application-fixed-pair-execution-receipt.v1", "verified": True,
                            "status": "valid_pair", "qualification_eligible": False, "receipt_sha256": receipt_pin["raw_sha256"],
                            "overlay_sha256": overlay_pin["sha256"], "run_id": job["run_id"]}
            component = {"schema": "allocatbelt.application-source5-fixed-component.v1",
                         "overlay": {"path": overlay_pin["path"], "raw_sha256": overlay_pin["sha256"]},
                         "receipt": receipt_pin, "verification": verification}
            starts = [{"event_head": str(index + 1) * 64, "proof": {"fixture_start": index},
                       "descriptor": {"pair": f"member-{index}"}, "pid": index + 100, "start_ticks": index + 1000}
                      for index in range(2)]
            terminals = [{"event_head": str(index + 3) * 64, "cleanup": {"fixture_cleanup": index}} for index in range(2)]
            chain = {"authorization_id": "fixture-authorization", "authorization_head": "5" * 64,
                     "app_started_heads": [item["event_head"] for item in starts], "app_terminal_heads": [item["event_head"] for item in terminals],
                     "job_terminal_head": "6" * 64, "component_sha256": sha(canonical(component)), "process_metrics_sha256": sha(canonical(metrics)),
                     "app_start_events": [item["proof"] for item in starts], "app_terminal_events": [{"cleanup": item["cleanup"]} for item in terminals],
                     "member_processes": [{"descriptor": item["descriptor"], "pid": item["pid"], "start_ticks": item["start_ticks"], "member_index": index}
                                          for index, item in enumerate(starts)]}
            auth = {"job": job, "helper_input": helper_pin, "execution_manifest": execution_pin,
                    "helper_module": {"path": "scripts/application-fixed-pair.py", "sha256": fixed_sha}, "host_evidence_budget": budget_pin}
            evidence = {"kind": "source5_fixed_pair", "overlay": component["overlay"], "receipt": receipt_pin,
                        "processes": {"path": str(pair / "processes.tsv"), "raw_sha256": receipt["processes_sha256"]},
                        "runtime_bindings": {"path": str(pair / "runtime.json"), "raw_sha256": sha(b"runtime")},
                        "source_snapshot": {"artifact": {"path": source_pin["path"], "raw_sha256": source_pin["raw_sha256"]},
                                            "semantic_sha256": source_pin["semantic_sha256"], "source_tree_sha256": "a" * 64},
                        "execution_manifest": execution_pin, "helper_input": helper_pin, "helper_module": auth["helper_module"], "host_receipt": host_pin}
            record = {"schema": chronology.SOURCE5_JOB_RECORD_SCHEMA, "state": "valid_pair", "job": job,
                      "pair_directory": str(pair), "process_metrics": metrics, "evidence": evidence,
                      "chronology": chain, "qualification_eligible": False}
            finished = {"state": "valid_pair", "authorization_id": chain["authorization_id"], "details": auth,
                        "authorization_head": chain["authorization_head"], "terminal": {"component_sha256": chain["component_sha256"], "process_metrics_sha256": chain["process_metrics_sha256"]},
                        "record_sha256": chain["job_terminal_head"], "starts": starts, "terminals": terminals}
            payloads = [(helper_pin["path"], helper_raw, "source5_helper_input", None),
                        (overlay_pin["path"], overlay_raw, "fixed_pair_overlay", None),
                        (receipt_pin["path"], receipt_raw, "component_receipt", receipt["receipt_sha256"]),
                        (host_pin["path"], host_raw, "fixed_pair_host_receipt", host_pin["host_verification_sha256"]),
                        (str(pair / "processes.tsv"), b"processes", "process_ledger", None),
                        (str(pair / "runtime.json"), b"runtime", "runtime_binding", None)]
            refs, entries = {}, []
            for index, (origin, raw, role, semantic) in enumerate(sorted(payloads)):
                local = stage / f"{index:06d}"
                write_file(local, raw, 0o400)
                refs[origin] = {"origin_path": origin, "path": str(local), "role": role, "host_id": "host-1",
                                "raw_sha256": sha(raw), "semantic_sha256": semantic, "byte_count": len(raw), "maximum_bytes": len(raw)}
                entries.append({"origin_path": origin, "role": role, "raw_sha256": sha(raw), "semantic_sha256": semantic, "byte_count": len(raw)})
            record_directory = root / "job-records"
            record_directory.mkdir(mode=0o700)
            case = {"root": root, "stage": stage, "job": job, "record": record, "record_path": record_directory / f"{job['run_id']}.json",
                    "prepared": prepared, "manifest": manifest, "state": {"source5_finished": {("confirmation", job["run_id"]): finished}},
                    "auth": auth, "refs": refs, "entries": entries, "host_pin": host_pin, "helper_pin": helper_pin,
                    "receipt": receipt, "overlay": overlay, "verification": verification, "calls": [], "payloads": payloads,
                    "archive_context": {"schema": self.archive.CONTEXT_SCHEMA_V1, "campaign_id": "captured-fixture", "host_id": "host-1",
                        "phase": "confirmation", "job_index": 0, "source_manifest_pin": source_pin,
                        "execution_manifest_pin": {**execution_pin, "semantic_sha256": manifest["manifest_sha256"]},
                        "plan_pin": plan_pin, "resource_budget_pin": budget_pin, "predecessor_ack_pin": None, "authorized_signer_fingerprint": "A" * 40}}
            self._seal_view(case)
            yield case

    def _run(self, case, *, fixed_api=True, captured=True):
        chronology = self.chronology
        real_loader = chronology._load_module
        def load(raw, path, label):
            module = real_loader(raw, path, label)
            if label == "source5_fixed_predecessor_verifier":
                def owner(*arguments):
                    case["calls"].append(("captured", arguments))
                    return {"schema": module.CAPTURED_REPLAY_CONTEXT_SCHEMA_V1, "verification": copy.deepcopy(case["verification"]),
                            "overlay": copy.deepcopy(case["overlay"]), "execution_receipt": copy.deepcopy(case["receipt"]),
                            "host_verification_pin": copy.deepcopy(case["host_pin"]), "full_replay_verified": True, "qualification_eligible": False}
                def live(*arguments):
                    if captured:
                        raise AssertionError("captured replay called live verifier")
                    case["calls"].append(("live", arguments))
                    return copy.deepcopy(case["verification"])
                def read(*arguments):
                    if captured:
                        raise AssertionError("captured replay reread live overlay")
                    case["calls"].append(("read", arguments))
                    return case["overlay"], b"", "", {}, {}
                module.verify_fixed_pair_overlay_captured_v1 = owner
                module.verify_fixed_pair_overlay = live
                module._read_overlay = read
            return module
        with patch.object(chronology, "_lock_token_is_live", return_value=True), \
                patch.object(chronology, "_prepare_source5_context", return_value=(case["manifest"], case["prepared"], case["state"], {})), \
                patch.object(chronology, "_load_module", side_effect=load):
            options = {"captured_evidence": case["view"]} if captured else {}
            if fixed_api:
                return chronology.verify_source5_completed_fixed_phase_locked(object(), {}, case["record_pin"], **options)
            return chronology.verify_source5_completed_job_locked(object(), {}, None, case["record_pin"], **options)

    def test_both_fixed_public_apis_use_captures_and_keep_original_component(self):
        with self._case() as case:
            for fixed_api in (True, False):
                result = self._run(case, fixed_api=fixed_api)
                self.assertEqual(result["record"]["raw_sha256"], case["record_pin"]["raw_sha256"])
                self.assertEqual(result["process_metrics"], case["record"]["process_metrics"])
            self.assertEqual([item[0] for item in case["calls"]], ["captured", "captured"])
            self.assertTrue(all(not Path(origin).exists() for origin in case["refs"]))

    def test_wrong_job_view_is_rejected_before_owner_replay(self):
        with self._case() as case:
            case["view"]["ordinal"] += 1
            with self.assertRaisesRegex(self.chronology.ChronologyError, "different original job"):
                self._run(case)
            self.assertEqual(case["calls"], [])

    def test_wrong_raw_manifest_pin_is_rejected_before_owner_replay(self):
        with self._case() as case:
            case["view"]["manifest_raw"] += b" "
            with self.assertRaisesRegex(self.chronology.ChronologyError, "object manifest raw bytes differ"):
                self._run(case)
            self.assertEqual(case["calls"], [])

    def test_wrong_reference_raw_pin_is_rejected_against_manifest(self):
        with self._case() as case:
            case["view"]["objects"][case["helper_pin"]["path"]]["raw_sha256"] = "0" * 64
            with self.assertRaisesRegex(self.chronology.ChronologyError, "reference differs from its exact manifest row"):
                self._run(case)
            self.assertEqual(case["calls"], [])

    def test_missing_archived_helper_never_falls_back_to_existing_origin(self):
        with self._case() as case:
            origin = case["helper_pin"]["path"]
            raw = Path(case["refs"][origin]["path"]).read_bytes()
            write_file(Path(origin), raw, 0o600)
            del case["refs"][origin]
            with self.assertRaisesRegex(self.chronology.ChronologyError, "refs do not close"):
                self._run(case)
            self.assertEqual(case["calls"], [])

    def test_physical_helper_corruption_is_not_replaced_with_origin_bytes(self):
        with self._case() as case:
            origin = case["helper_pin"]["path"]
            local = Path(case["refs"][origin]["path"])
            original = local.read_bytes()
            write_file(Path(origin), original, 0o600)
            local.chmod(0o600)
            local.write_bytes(b"!" * len(original))
            local.chmod(0o400)
            with self.assertRaisesRegex(self.chronology.ChronologyError, "capture is invalid.*raw bytes differ"):
                self._run(case)
            self.assertEqual(case["calls"], [])

    def test_v4_rejects_historical_fixed_evidence_without_host_receipt(self):
        with self._case() as case:
            del case["record"]["evidence"]["host_receipt"]
            self._seal_view(case)
            with self.assertRaisesRegex(self.chronology.ChronologyError, "unexpected field set"):
                self._run(case)
            self.assertEqual(case["calls"], [])

    def test_repinned_component_drift_reaches_original_component_digest_guard(self):
        with self._case() as case:
            changed = "0" * 64
            case["record"]["chronology"]["component_sha256"] = changed
            case["state"]["source5_finished"][("confirmation", case["job"]["run_id"])]["terminal"]["component_sha256"] = changed
            self._seal_view(case)
            with self.assertRaisesRegex(self.chronology.ChronologyError, "fixed component digest differs"):
                self._run(case)
            self.assertEqual([item[0] for item in case["calls"]], ["captured"])

    def test_captured_legacy_generation_is_explicitly_unsupported(self):
        with self._case() as case:
            case["prepared"]["source5_execution_schema"] = self.chronology.SOURCE5_EXECUTION_SCHEMA_V3
            with self.assertRaisesRegex(self.chronology.ChronologyError, "v4 fixed jobs only"):
                self._run(case)
            self.assertEqual(case["calls"], [])

    def test_captured_pressure_job_remains_explicitly_unsupported(self):
        with self._case() as case:
            case["record"]["job"]["phase"] = "pressure"
            self._seal_view(case)
            with self.assertRaisesRegex(self.chronology.ChronologyError, "v4 fixed jobs only"):
                self._run(case, fixed_api=False)
            self.assertEqual(case["calls"], [])

    def test_capture_metadata_cannot_enter_original_verification_projection(self):
        with self._case() as case:
            case["verification"]["host_verification_sha256"] = "0" * 64
            with self.assertRaisesRegex(self.chronology.ChronologyError, "original fixed component verification projection.*unexpected field set"):
                self._run(case)
            self.assertEqual([item[0] for item in case["calls"]], ["captured"])

    def test_legacy_default_keeps_live_reader_and_historical_evidence_shape(self):
        with self._case() as case:
            case["prepared"]["source5_execution_schema"] = self.chronology.SOURCE5_EXECUTION_SCHEMA_V3
            del case["record"]["evidence"]["host_receipt"]
            self._seal_view(case)
            for origin, raw, _role, _semantic in case["payloads"]:
                write_file(Path(origin), raw, 0o600)
            self._run(case, captured=False)
            self.assertEqual([item[0] for item in case["calls"]], ["live", "read"])


class Source5V3CatalogueRoleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.chronology = load_script(
            SCRIPT_DIR / "application-campaign-chronology.py",
            "source5_v3_catalogue_role_chronology",
        )
        cls.transport = load_script(
            SCRIPT_DIR / "application-source5-evidence-transport-v3.py",
            "source5_v3_catalogue_role_transport",
        )

    def _fixture(
        self, root: Path, *, extra_role: str = "source5_checkpoint_request",
        extra_raw: bytes = b"durable archive metadata\n",
        extra_maximum: int | None = None,
    ):
        source_fixture = Source5JournalInputValidationTests(
            "test_full_typed_source_and_artifact_index_closure_is_exact",
        )
        source_fixture.chronology = self.chronology
        request, manifest, sources, hosts, legacy_index, store = \
            source_fixture._full_source_index_fixture()
        extra_path = "/private/archive/earlier-than-source.json"
        extra_maximum = (len(extra_raw) if extra_maximum is None else
                         extra_maximum)
        common = {
            "role": extra_role, "host_id": request["host_id"],
            "origin_path": extra_path, "local_path": extra_path,
            "raw_sha256": sha(extra_raw), "semantic_sha256": None,
            "byte_count": len(extra_raw), "maximum_bytes": extra_maximum,
        }
        rows = [dict(row) for row in legacy_index["entries"]]
        rows.append(common)
        rows.sort(key=lambda row: row["origin_path"])
        store[extra_path] = {**common, "raw_bytes": extra_raw}
        for row in rows:
            if "maximum_bytes" not in row:
                row["maximum_bytes"] = self.chronology.SOURCE5_JOURNAL_ROLE_LIMITS[
                    row["role"]
                ]
            store[row["origin_path"]]["maximum_bytes"] = row["maximum_bytes"]
        catalogue_rows = [{
            "path": row["origin_path"], "kind": "file", "role": row["role"],
            "host_id": row["host_id"], "max_file_bytes": row["maximum_bytes"],
            "origin_pin": None, "aggregate_id": None,
            "aggregate_max_bytes": None,
        } for row in rows]
        budget_pin = {
            "path": "/private/budget.json", "raw_sha256": "a" * 64,
            "semantic_sha256": "b" * 64,
        }
        index_directory = root / "index"
        index_directory.mkdir(mode=0o700)
        os.chmod(index_directory, 0o700)
        index_root, index_pin, _files = self.transport.write_index_v3(
            campaign_id="campaign-a", host_id=request["host_id"],
            source_root=request["source_root"], input_root="/private/input",
            output_root="/private/output", host_evidence_budget=budget_pin,
            entries=rows, directory=index_directory,
            maximum_entries=64, maximum_index_bytes=1024 * 1024,
            chunk_bytes=64 * 1024, fanout=4,
        )
        checked_root, entries = self.transport.open_index_v3(
            index_pin, budget_pin=budget_pin, campaign_id="campaign-a",
            host_id=request["host_id"], source_root=request["source_root"],
            input_root="/private/input", output_root="/private/output",
            maximum_entries=64, maximum_index_bytes=1024 * 1024,
            chunk_bytes=64 * 1024, fanout=4,
        )
        self.assertEqual(checked_root, index_root)
        request.update({
            "schema": self.chronology.SOURCE5_HOST_JOURNAL_REQUEST_SCHEMA_V3,
            "evidence_index": index_pin, "host_evidence_budget": budget_pin,
        })
        opened = []

        class CapturedObject:
            source5_captured_object_v2 = True

            def __init__(self, path, payload):
                self.path, self.payload = path, payload

            def open_stream(self):
                opened.append(self.path)
                return io.BytesIO(self.payload)

        for path, row in store.items():
            row["raw_bytes"] = CapturedObject(path, row["raw_bytes"])
        return {
            "request": request, "manifest": manifest, "sources": sources,
            "hosts": hosts, "index": {**index_root, "entries": entries},
            "store": store, "catalogue": catalogue_rows, "opened": opened,
            "extra_path": extra_path,
        }

    def _bind(self, fixture):
        authority = self.chronology._source5_bind_v3_catalogue_authority(
            fixture["request"], fixture["index"], fixture["index"]["entries"],
            iter(fixture["catalogue"]), self.transport, 64,
        )
        fixture["index"]["_validated_v3_catalogue_authority"] = authority

    def _verify(self, fixture):
        self.chronology._source5_validate_full_source_index_closure(
            fixture["request"], fixture["manifest"], fixture["sources"],
            fixture["hosts"], fixture["index"], fixture["store"],
        )

    def test_v3_new_role_is_hashed_only_after_complete_known_source(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-v3-role-positive-") as tmp:
            fixture = self._fixture(Path(tmp))
            self._bind(fixture)
            self.assertEqual(fixture["opened"], [])
            self._verify(fixture)
            first_extra = fixture["opened"].index(fixture["extra_path"])
            self.assertEqual(set(fixture["opened"][:first_extra]),
                             set(fixture["store"]) - {fixture["extra_path"]})
            self.assertEqual(fixture["opened"].count(fixture["extra_path"]), 1)

    def test_v3_zero_byte_new_role_keeps_its_zero_ceiling(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-v3-role-empty-") as tmp:
            fixture = self._fixture(Path(tmp), extra_raw=b"", extra_maximum=0)
            self._bind(fixture)
            self._verify(fixture)
            self.assertIn(fixture["extra_path"], fixture["opened"])

    def test_v3_missing_or_forged_authority_never_reads_new_role(self) -> None:
        for forged in (None, {"validated": True}):
            with self.subTest(forged=forged), tempfile.TemporaryDirectory() as tmp:
                fixture = self._fixture(Path(tmp))
                fixture["index"]["_validated_v3_catalogue_authority"] = forged
                with self.assertRaisesRegex(self.chronology.ChronologyError,
                                            "exact authenticated catalogue authority"):
                    self._verify(fixture)
                self.assertNotIn(fixture["extra_path"], fixture["opened"])

    def test_v3_catalogue_ceiling_or_role_drift_is_rejected_before_raw_read(self) -> None:
        for field, value in (("max_file_bytes", 1), ("role", "forged_role")):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as tmp:
                fixture = self._fixture(Path(tmp))
                row = next(row for row in fixture["catalogue"]
                           if row["path"] == fixture["extra_path"])
                row[field] = value
                with self.assertRaisesRegex(self.transport.EvidenceTransportError,
                                            "owner path ceiling"):
                    self._bind(fixture)
                self.assertEqual(fixture["opened"], [])

    def test_v3_authority_binds_index_budget_and_exact_captured_ceiling(self) -> None:
        for field in ("evidence_index", "host_evidence_budget", "captured_maximum"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as tmp:
                fixture = self._fixture(Path(tmp))
                self._bind(fixture)
                if field == "captured_maximum":
                    fixture["store"][fixture["extra_path"]]["maximum_bytes"] += 1
                    message = "differs from its authenticated row"
                else:
                    fixture["request"][field] = {
                        **fixture["request"][field], "raw_sha256": "f" * 64,
                    }
                    message = "exact authenticated catalogue authority"
                with self.assertRaisesRegex(self.chronology.ChronologyError, message):
                    self._verify(fixture)
                self.assertNotIn(fixture["extra_path"], fixture["opened"])

    def test_v3_catalogue_cannot_widen_a_known_legacy_role(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-v3-role-known-") as tmp:
            fixture = self._fixture(
                Path(tmp), extra_role="typed_source_symlink",
                extra_raw=b"x" * (self.chronology.MAX_SOURCE5_TYPED_SYMLINK_BYTES + 1),
                extra_maximum=8192,
            )
            self._bind(fixture)
            with self.assertRaisesRegex(self.chronology.ChronologyError,
                                        "bounded unsigned integer"):
                self._verify(fixture)
            self.assertNotIn(fixture["extra_path"], fixture["opened"])

    def test_v3_bad_source_bytes_stop_before_new_role_payload(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-v3-role-source-") as tmp:
            fixture = self._fixture(Path(tmp))
            self._bind(fixture)
            source_row = fixture["store"]["/private/source/scripts/runtime-readback.py"]
            source_row["raw_bytes"].payload = b"x" * source_row["byte_count"]
            with self.assertRaisesRegex(self.chronology.ChronologyError,
                                        "bytes differ"):
                self._verify(fixture)
            self.assertNotIn(fixture["extra_path"], fixture["opened"])

    def test_legacy_unknown_role_has_no_caller_asserted_ceiling(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-legacy-role-") as tmp:
            fixture = self._fixture(Path(tmp))
            fixture["request"]["schema"] = \
                self.chronology.SOURCE5_HOST_JOURNAL_REQUEST_SCHEMA_V2
            with self.assertRaisesRegex(self.chronology.ChronologyError,
                                        "lacks authenticated v3 catalogue authority"):
                self._verify(fixture)
            self.assertNotIn(fixture["extra_path"], fixture["opened"])


class ProcessLivenessHelperTests(unittest.TestCase):
    def test_exit_during_proc_stat_read_is_not_live(self) -> None:
        for error in (FileNotFoundError(2, "gone"), ProcessLookupError(3, "gone")):
            with self.subTest(error=type(error).__name__):
                with patch.object(Path, "read_text", side_effect=error):
                    CampaignChronologyCliTests._wait_for_pid_not_live(self, 123456)

    def test_unrelated_proc_read_errors_remain_unverified(self) -> None:
        for error in (PermissionError(13, "denied"), OSError(5, "I/O failure")):
            with self.subTest(error=type(error).__name__):
                with patch.object(Path, "read_text", side_effect=error):
                    with self.assertRaises(type(error)):
                        CampaignChronologyCliTests._wait_for_pid_not_live(self, 123456)


class Source5InputPrepConsumerPortTests(unittest.TestCase):
    """Exercise the named Source metadata consumers and routing-only seams."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.chronology = load_script(
            SCRIPT_DIR / "application-campaign-chronology.py",
            "source5_inputprep_consumer_port_target",
        )
        cls.inputprep_tests = load_script(
            SCRIPT_DIR / "test-application-source5-input-preparation.py",
            "source5_inputprep_consumer_fixture_source",
        )
        cls.fixture_type = cls.inputprep_tests.RecordedHistoricalGlobalReaderTests
        cls.fixture_type.setUpClass()
        cls.fixture_builder = cls.fixture_type()

    def _metadata_fixture(self, root: Path) -> dict[str, Any]:
        """Build the captured SourceV5 structural fixture; it is not run evidence."""
        return self.fixture_builder._metadata_intent_fixture(root)

    def _captured_preparation(self, fixture: dict[str, Any], host_id: str | None = None):
        chronology = self.chronology
        selected = host_id or fixture["host_ids"][0]
        return chronology._source5_captured_source_module(
            {"source_root": fixture["source_root"],
             "source": fixture["sources"][selected]},
            "scripts/application-source5-input-preparation.py",
            "Source5 consumer-port captured preparation helper",
        )

    def _preparatory_generation(self, fixture: dict[str, Any]):
        chronology = self.chronology
        input_root = fixture["input_root"]
        spec = copy.deepcopy(fixture["spec"])
        spec["rates"] = []
        spec["oracles"] = []
        spec_path = Path(fixture["spec_pin"]["path"])
        spec_raw = fixture["campaign"].canonical_bytes(spec)
        spec_path.write_bytes(spec_raw)
        spec_path.chmod(0o600)
        spec_sha = hashlib.sha256(spec_raw).hexdigest()
        plan_path = input_root / "consumer-port-initial-plan.json"
        plan_raw = fixture["campaign"].canonical_bytes({
            "schema": "allocatbelt.application-campaign-plan.v3",
            "campaign_id": fixture["preparation"]["core"]["campaign_id"],
        })
        plan_path.write_bytes(plan_raw)
        plan_path.chmod(0o600)
        plan_sha = hashlib.sha256(plan_raw).hexdigest()
        selected_host = fixture["host_ids"][0]
        prepared = {
            "campaign_id": fixture["preparation"]["core"]["campaign_id"],
            "source_root": fixture["source_root"],
            "input_root": input_root,
            "source": fixture["sources"][selected_host],
            "sources": fixture["sources"],
            "spec": spec,
            "prepared": {
                "spec_path": spec_path, "spec_raw_sha256": spec_sha,
                "plan_path": plan_path, "plan_raw_sha256": plan_sha,
            },
        }
        preparation_pin = {
            "path": fixture["preparation_pin"]["path"],
            "raw_sha256": fixture["preparation_pin"]["sha256"],
        }
        generation = {
            "completion": {
                "path": str(input_root / "prepared-capacity-generation.json"),
                "raw_sha256": "d" * 64,
                "semantic_sha256": "e" * 64,
            },
            "provenance": {
                "schema": chronology.SOURCE5_PREPARATORY_CAPACITY_PROVENANCE_SCHEMA,
                "preparation_pin": preparation_pin,
                "initial_spec_pin": {
                    "path": str(spec_path), "raw_sha256": spec_sha,
                },
                "initial_plan_pin": {
                    "path": str(plan_path), "raw_sha256": plan_sha,
                },
            },
        }
        return prepared, generation

    def test_source_refs_check_the_validated_host_set_and_exact_source_pins(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-consumer-source-refs-") as temporary:
            fixture = self._metadata_fixture(Path(temporary))
            helper = self._captured_preparation(fixture)
            intent, sources, _campaign, inputs = helper.read_preparation_intent_metadata_v1(
                fixture["preparation_pin"], fixture["source_root"], fixture["input_root"],
            )
            spec = copy.deepcopy(fixture["spec"])
            core = inputs.preparation_core_from_spec(spec)
            self.assertEqual(core, intent["core"])
            host_ids = {host["host_id"] for host in core["hosts"]}
            helper._verify_spec_source_refs(spec, intent, sources, host_ids)

            changed_host = copy.deepcopy(spec)
            changed_host["hosts"][0]["host_id"] = "changed-host"
            missing_host = copy.deepcopy(spec)
            missing_host["hosts"].pop()
            extra_host = copy.deepcopy(spec)
            extra_host["hosts"].append({**copy.deepcopy(spec["hosts"][0]),
                                         "host_id": "extra-host"})
            extra_source = dict(sources)
            extra_source["extra-host"] = next(iter(sources.values()))
            changed_path = copy.deepcopy(spec)
            changed_path["source_manifests"][0]["relative_path"] = "sources/other.json"
            changed_semantic = copy.deepcopy(spec)
            changed_semantic["source_manifests"][0]["sha256"] = "0" * 64
            failures = (
                (changed_host, sources, "host set"),
                (missing_host, sources, "host set"),
                (extra_host, sources, "host set"),
                (spec, {key: value for key, value in sources.items()
                        if key != fixture["host_ids"][0]}, "host set"),
                (spec, extra_source, "host set"),
                (changed_path, sources, "paths/semantic pins"),
                (changed_semantic, sources, "pinned cohort manifest"),
            )
            for bad_spec, bad_sources, message in failures:
                with self.subTest(message=message, source_count=len(bad_sources)):
                    with self.assertRaisesRegex(helper.PreparationError, message):
                        helper._verify_spec_source_refs(
                            bad_spec, intent, bad_sources, host_ids,
                        )

    def test_preparatory_consumer_uses_nested_metadata_replay_and_stops_at_missing_evidence(self) -> None:
        chronology = self.chronology
        with tempfile.TemporaryDirectory(prefix="source5-consumer-capacity-") as temporary:
            fixture = self._metadata_fixture(Path(temporary))
            prepared, generation = self._preparatory_generation(fixture)
            observations: dict[str, list[Any]] = {
                "intent": [], "source_refs": [], "capacity_verify": [],
            }
            real_load = chronology._load_module

            def load_and_track(raw, path, label):
                module = real_load(raw, path, label)
                if Path(path).name != "application-source5-input-preparation.py":
                    return module
                original_intent = module.read_preparation_intent_metadata_v1
                original_refs = module._verify_spec_source_refs
                original_verify = module.verify_prepared_capacity_generation_bounded_metadata_v1

                def read_intent(*args, **kwargs):
                    observations["intent"].append((args, kwargs))
                    return original_intent(*args, **kwargs)

                def verify_refs(*args, **kwargs):
                    observations["source_refs"].append((args, kwargs))
                    return original_refs(*args, **kwargs)

                def verify_capacity(*args, **kwargs):
                    observations["capacity_verify"].append((args, kwargs))
                    return original_verify(*args, **kwargs)

                module.read_preparation_intent_metadata_v1 = read_intent
                module._verify_spec_source_refs = verify_refs
                module.verify_prepared_capacity_generation_bounded_metadata_v1 = verify_capacity
                return module

            with patch.object(chronology, "_load_module", side_effect=load_and_track):
                with self.assertRaisesRegex(
                        chronology.ChronologyError,
                        "cannot safely open prepared capacity generation"):
                    chronology._verify_source5_preparatory_input_generation(
                        prepared, generation,
                    )
            self.assertEqual(len(observations["intent"]), 1)
            self.assertEqual(observations["intent"][0][0], (
                {"path": generation["provenance"]["preparation_pin"]["path"],
                 "sha256": generation["provenance"]["preparation_pin"]["raw_sha256"]},
                fixture["source_root"], fixture["input_root"],
            ))
            self.assertEqual(len(observations["source_refs"]), 1)
            ref_args = observations["source_refs"][0][0]
            self.assertEqual(ref_args[0], prepared["spec"])
            self.assertEqual(ref_args[3], {
                host["host_id"] for host in prepared["spec"]["hosts"]
            })
            self.assertEqual(len(observations["capacity_verify"]), 1)
            self.assertEqual(observations["capacity_verify"][0][0], (
                generation["completion"],
                {"path": generation["provenance"]["preparation_pin"]["path"],
                 "sha256": generation["provenance"]["preparation_pin"]["raw_sha256"]},
                fixture["source_root"], fixture["input_root"],
            ))
            self.assertFalse((fixture["input_root"] /
                              "prepared-capacity-generation.json").exists())

            helper = self._captured_preparation(fixture)
            with self.assertRaisesRegex(helper.PreparationError,
                                        "full manifest verifier rejected"):
                helper.read_preparation_intent(
                    fixture["preparation_pin"], fixture["source_root"],
                    fixture["input_root"],
                )

            wrong_root = dict(prepared)
            wrong_root["input_root"] = fixture["input_root"].parent / "wrong-root"
            with self.assertRaisesRegex(
                    chronology.ChronologyError, "outside its original input root"):
                chronology._verify_source5_preparatory_input_generation(
                    wrong_root, generation,
                )
            traversing = copy.deepcopy(generation)
            traversing["provenance"]["preparation_pin"]["path"] = str(
                fixture["input_root"] / ".." / "outside" / "preparation-intent.json",
            )
            with self.assertRaisesRegex(
                    chronology.ChronologyError, "outside its original input root"):
                chronology._verify_source5_preparatory_input_generation(
                    prepared, traversing,
                )

            fallback_calls = []

            def remove_metadata_api(raw, path, label):
                module = real_load(raw, path, label)
                if Path(path).name == "application-source5-input-preparation.py":
                    del module.read_preparation_intent_metadata_v1
                    module.read_preparation_intent = lambda *args, **kwargs: fallback_calls.append(args)
                return module

            with patch.object(chronology, "_load_module", side_effect=remove_metadata_api):
                with self.assertRaisesRegex(
                        chronology.ChronologyError,
                        "lacks named metadata capacity replay APIs"):
                    chronology._verify_source5_preparatory_input_generation(
                        prepared, generation,
                    )
            self.assertEqual(fallback_calls, [])

    def test_fixed_host_consumer_uses_readonly_metadata_binding(self) -> None:
        chronology = self.chronology
        with tempfile.TemporaryDirectory(prefix="source5-consumer-host-binding-") as temporary:
            fixture = self._metadata_fixture(Path(temporary))
            helper = self._captured_preparation(fixture)
            spec = copy.deepcopy(fixture["spec"])
            spec["rates"] = []
            spec["oracles"] = []
            spec_path = Path(fixture["spec_pin"]["path"])
            spec_raw = fixture["campaign"].canonical_bytes(spec)
            spec_path.write_bytes(spec_raw)
            spec_path.chmod(0o600)
            spec_raw_sha = hashlib.sha256(spec_raw).hexdigest()
            spec_pin = {"path": str(spec_path), "sha256": spec_raw_sha}
            host_id = fixture["host_ids"][0]
            preparation_pin = fixture["preparation_pin"]
            materialized = helper.materialize_prepared_host_binding_metadata_v1(
                preparation_pin, spec_pin, fixture["source_root"],
                fixture["input_root"], host_id,
            )
            preparation, _sources, _campaign, _inputs = \
                helper.read_preparation_intent_metadata_v1(
                    preparation_pin, fixture["source_root"], fixture["input_root"],
                )
            observed_pin = preparation["observed_hosts"][host_id]
            host_context_path = fixture["input_root"] / observed_pin["relative_path"]
            host_context = json.loads(host_context_path.read_text(encoding="utf-8"))
            prepared = {
                "source_root": fixture["source_root"],
                "input_root": fixture["input_root"],
                "host_id": host_id,
                "spec": spec,
                "source": fixture["sources"][host_id],
                "prepared": {"host_context": host_context},
                "original_pins": {
                    "spec": {"path": str(spec_path), "raw_sha256": spec_raw_sha},
                    "observed_host": {
                        "path": str(host_context_path),
                        "raw_sha256": observed_pin["raw_sha256"],
                    },
                },
            }
            generation = {"provenance": {"preparation_pin": {
                "path": preparation_pin["path"],
                "raw_sha256": preparation_pin["sha256"],
            }}}
            real_capture = chronology._source5_captured_source_module
            verifier_calls = []
            ordinary_calls = []

            def capture_and_track(value, relative, label):
                module = real_capture(value, relative, label)
                if relative.endswith("application-source5-input-preparation.py"):
                    actual_verifier = module.verify_prepared_host_binding_metadata_v1
                    ordinary_verifier = module.verify_prepared_host_binding

                    def verify_metadata(*args, **kwargs):
                        verifier_calls.append((args, kwargs))
                        return actual_verifier(*args, **kwargs)

                    def verify_ordinary(*args, **kwargs):
                        ordinary_calls.append((args, kwargs))
                        return ordinary_verifier(*args, **kwargs)

                    module.verify_prepared_host_binding_metadata_v1 = verify_metadata
                    module.verify_prepared_host_binding = verify_ordinary
                return module

            with patch.object(chronology, "_source5_captured_source_module",
                              side_effect=capture_and_track):
                result = chronology._source5_preparatory_fixed_host_inputs(
                    prepared, generation,
                )
            self.assertEqual(len(verifier_calls), 1)
            self.assertEqual(verifier_calls[0][0], (
                {"path": preparation_pin["path"], "sha256": preparation_pin["sha256"]},
                {"path": str(spec_path), "sha256": spec_raw_sha},
                fixture["source_root"], fixture["input_root"], host_id,
            ))
            self.assertEqual(ordinary_calls, [])
            self.assertEqual(result, materialized)

            with self.assertRaisesRegex(helper.PreparationError,
                                        "full manifest verifier rejected"):
                helper.verify_prepared_host_binding(
                    preparation_pin, spec_pin, fixture["source_root"],
                    fixture["input_root"], host_id,
                )

            fallback_calls = []
            legacy_only = types.SimpleNamespace(
                verify_prepared_host_binding=lambda *args, **kwargs:
                    fallback_calls.append((args, kwargs)),
            )
            with patch.object(chronology, "_source5_captured_source_module",
                              return_value=legacy_only):
                with self.assertRaisesRegex(
                        chronology.ChronologyError,
                        "lacks named read-only metadata host verification"):
                    chronology._source5_preparatory_fixed_host_inputs(
                        prepared, generation,
                    )
            self.assertEqual(fallback_calls, [])

    def _routing_case(self, root: Path, *, v5: bool, full_spec: bool = False):
        chronology = self.chronology
        source_root = root / "source"
        input_root = root / "inputs"
        source_root.mkdir(mode=0o700)
        input_root.mkdir(mode=0o700)
        spec_path = input_root / "spec.json"
        plan_path = input_root / "plan.json"
        preparation_path = input_root / "preparation-generations" / "campaign" / "intent.json"
        preparation_path.parent.mkdir(mode=0o700, parents=True)
        host_ids = ["host-a", "host-b"]
        completion = {
            "schema": "allocatbelt.application-source5-preparation-completion.v2",
            "complete": True, "qualification_eligible": False,
            "campaign_id": "consumer-routing-campaign",
            "preparation": {}, "final_spec": {}, "final_plan": {},
            "source_manifests": {}, "capacity_preparations": [],
            "pressure_calibrations": [], "pilots": [], "oracles": [],
            "filled_slots": {}, "ledger_heads": [], "resource_budgets": {},
        }
        completion["completion_sha256"] = chronology.sha256_bytes(
            chronology.canonical_bytes(completion),
        )
        completion_path = input_root / "prepared-inputs-completion.json"
        completion_raw = chronology.canonical_bytes(completion)
        completion_path.write_bytes(completion_raw)
        completion_pin = {
            "path": str(completion_path),
            "raw_sha256": chronology.sha256_bytes(completion_raw),
            "semantic_sha256": completion["completion_sha256"],
        }
        provenance = {
            "schema": (chronology.SOURCE5_PREPARED_INPUTS_PROVENANCE_SCHEMA_V2
                       if v5 else
                       "allocatbelt.application-source5-prepared-inputs-provenance.v1"),
            "preparation_pin": {
                "path": str(preparation_path), "raw_sha256": "a" * 64,
            },
            "final_spec_pin": {"path": str(spec_path), "raw_sha256": "b" * 64},
            "final_plan_pin": {"path": str(plan_path), "raw_sha256": "c" * 64},
        }
        if v5:
            provenance["exploration_lineage"] = {}
        generation = {"completion": completion_pin, "provenance": provenance}
        manifest = {
            "schema": (chronology.SOURCE5_EXECUTION_SCHEMA_V5 if v5 else
                       chronology.SOURCE5_EXECUTION_SCHEMA_V3),
            "prepared_input_generation": generation,
        }
        jobs = {phase: [] for phase in (
            "exploration", "aa", "confirmation", "pressure", "soak",
        )}
        spec = {
            "hosts": [{"host_id": host_id} for host_id in host_ids],
            "rates": ([{}] if full_spec else []),
            "oracles": ([{}] if full_spec else []),
        }
        # Routing tests replace _source_file; this placeholder satisfies the
        # A6 input shape and is not a captured Source manifest.
        prepared = {
            "campaign_id": "consumer-routing-campaign",
            "source_root": source_root,
            "input_root": input_root,
            "source": {"fixture_scope": "routing_only", "source": {"files": []}},
            "spec": spec,
            "plan": {"jobs": jobs},
            "controller": types.SimpleNamespace(build_jobs=lambda _spec, phase: jobs[phase]),
            "prepared": {
                "spec_path": spec_path, "spec_raw_sha256": "b" * 64,
                "spec_semantic_sha256": "d" * 64,
                "plan_path": plan_path, "plan_raw_sha256": "c" * 64,
                "plan_semantic_sha256": "e" * 64,
            },
        }
        return prepared, manifest, completion, completion_pin

    def _typed_inputprep_helper(self, prepared, name: str, **apis):
        helper_path = (prepared["source_root"] / "scripts" /
                       "application-source5-input-preparation.py")
        helper_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        helper_path.write_bytes(b"typed selected Source helper fixture")
        helper_path.chmod(0o600)
        helper = types.ModuleType(name)
        helper.__file__ = str(helper_path)
        for api_name, api in apis.items():
            setattr(helper, api_name, api)
        return helper

    def test_recorded_and_ordinary_routes_forward_only_their_closed_arguments(self) -> None:
        """Call spies check routing only; they do not claim completion replay."""
        chronology = self.chronology
        providers = {"host-a": object(), "host-b": object()}
        reader_calls = []

        def reader(*args):
            reader_calls.append(args)
            return b"captured"

        def run_probe(*, v5: bool, providers_value, reader_value):
            calls = []

            def fail_after_capture(*args, **kwargs):
                calls.append((args, kwargs))
                raise RuntimeError("routing probe only")

            with tempfile.TemporaryDirectory(prefix="source5-consumer-routing-") as temporary:
                prepared, manifest, _completion, completion_pin = self._routing_case(
                    Path(temporary), v5=v5, full_spec=True,
                )
                helper = self._typed_inputprep_helper(
                    prepared, "source5_inputprep_routing_fixture",
                    verify_prepared_inputs_completion=fail_after_capture,
                )
                if v5:
                    helper.verify_prepared_inputs_completion_recorded_host = fail_after_capture

                def captured(_prepared, _relative, label):
                    if label == "Source5 prepared-input provenance v2 validator":
                        return types.SimpleNamespace(
                            validate_prepared_input_provenance_v2=lambda _value, *, expected_hosts: {
                                "preparation_pin": manifest["prepared_input_generation"]["provenance"]["preparation_pin"],
                                "final_spec_pin": manifest["prepared_input_generation"]["provenance"]["final_spec_pin"],
                                "final_plan_pin": manifest["prepared_input_generation"]["provenance"]["final_plan_pin"],
                                "exploration_lineage": {},
                            },
                        )
                    raise AssertionError(f"unexpected captured Source module: {label}")

                with patch.object(chronology, "_source5_captured_source_module",
                                  side_effect=captured), \
                     patch.object(chronology, "_source_file",
                                  return_value=(b"captured helper", "f" * 64, {})), \
                     patch.object(chronology, "_load_module", return_value=helper):
                    with self.assertRaisesRegex(chronology.ChronologyError,
                                                "routing probe only"):
                        chronology._verify_source5_prepared_input_generation(
                            manifest, prepared,
                            captured_pilot_read_providers=providers_value,
                            global_artifact_reader=reader_value,
                        )
            self.assertEqual(len(calls), 1)
            return calls[0], completion_pin, prepared, manifest

        (recorded_args, recorded_kwargs), completion_pin, prepared, manifest = run_probe(
            v5=True, providers_value=providers, reader_value=reader,
        )
        self.assertEqual(recorded_args, (
            completion_pin, {
                "schema": "allocatbelt.application-source5-prepared-inputs-provenance.v1",
                "preparation_pin": manifest["prepared_input_generation"]["provenance"]["preparation_pin"],
                "final_spec_pin": manifest["prepared_input_generation"]["provenance"]["final_spec_pin"],
                "final_plan_pin": manifest["prepared_input_generation"]["provenance"]["final_plan_pin"],
            }, prepared["source_root"], prepared["input_root"],
        ))
        self.assertIs(recorded_kwargs["captured_pilot_read_providers"], providers)
        self.assertIs(recorded_kwargs["global_artifact_reader"], reader)
        self.assertEqual(reader_calls, [])

        (ordinary_args, ordinary_kwargs), ordinary_pin, _prepared, _manifest = run_probe(
            v5=False, providers_value=None, reader_value=None,
        )
        self.assertEqual(ordinary_args[0], ordinary_pin)
        self.assertEqual(ordinary_kwargs, {})
        self.assertEqual(reader_calls, [])

    def test_reader_rejects_non_v5_routes_and_v5_restart_does_not_replay(self) -> None:
        chronology = self.chronology
        reader_calls = []
        reader = lambda *args: reader_calls.append(args) or b"captured"
        with self.assertRaisesRegex(
                chronology.ChronologyError, "must be absent or callable"):
            chronology._verify_source5_prepared_input_generation(
                None, {}, global_artifact_reader=object(),
            )
        ordinary_calls = []
        recorded_calls = []

        def ordinary(*args, **kwargs):
            ordinary_calls.append((args, kwargs))
            raise RuntimeError("ordinary route should not be selected")

        def recorded(*args, **kwargs):
            recorded_calls.append((args, kwargs))
            raise RuntimeError("recorded route should not run without providers")

        with tempfile.TemporaryDirectory(prefix="source5-consumer-restart-") as temporary:
            prepared, manifest, _completion, _pin = self._routing_case(
                Path(temporary), v5=True, full_spec=False,
            )
            helper = self._typed_inputprep_helper(
                prepared, "source5_inputprep_restart_fixture",
                verify_prepared_inputs_completion=ordinary,
                verify_prepared_inputs_completion_recorded_host=recorded,
            )
            def captured(_prepared, _relative, label):
                return types.SimpleNamespace(
                    validate_prepared_input_provenance_v2=lambda _value, *, expected_hosts: {
                        "preparation_pin": manifest["prepared_input_generation"]["provenance"]["preparation_pin"],
                        "final_spec_pin": manifest["prepared_input_generation"]["provenance"]["final_spec_pin"],
                        "final_plan_pin": manifest["prepared_input_generation"]["provenance"]["final_plan_pin"],
                        "exploration_lineage": {},
                    },
                )

            with patch.object(chronology, "_source5_captured_source_module",
                              side_effect=captured), \
                 patch.object(chronology, "_source_file",
                              return_value=(b"captured helper", "f" * 64, {})), \
                 patch.object(chronology, "_load_module", return_value=helper):
                with self.assertRaisesRegex(
                        chronology.ChronologyError,
                        "requires the exact frozen full original PlanV3 phase schedule"):
                    chronology._verify_source5_prepared_input_generation(
                        manifest, prepared, captured_pilot_read_providers=None,
                        global_artifact_reader=reader,
                    )
            self.assertIs(prepared.get("source5_prepared_input_replay_required"), True)
            self.assertEqual(ordinary_calls, [])
            self.assertEqual(recorded_calls, [])
            self.assertEqual(reader_calls, [])

        with tempfile.TemporaryDirectory(prefix="source5-consumer-non-v5-reader-") as temporary:
            prepared, manifest, _completion, _pin = self._routing_case(
                Path(temporary), v5=False,
            )
            with self.assertRaisesRegex(
                    chronology.ChronologyError,
                    "reserved for recorded V5 completion replay"):
                chronology._verify_source5_prepared_input_generation(
                    manifest, prepared, global_artifact_reader=reader,
                )
            with self.assertRaisesRegex(
                    chronology.ChronologyError,
                    "reserved for recorded V5 completion replay"):
                chronology._validate_source5_manifest_value(
                    {"schema": chronology.SOURCE5_EXECUTION_SCHEMA_V3}, b"", prepared,
                    global_artifact_reader=reader,
                )
            self.assertEqual(ordinary_calls, [])
            self.assertEqual(recorded_calls, [])

        with tempfile.TemporaryDirectory(prefix="source5-consumer-missing-recorded-api-") as temporary:
            prepared, manifest, _completion, _pin = self._routing_case(
                Path(temporary), v5=True, full_spec=True,
            )
            fallback_calls = []
            helper_without_recorded_api = self._typed_inputprep_helper(
                prepared, "source5_inputprep_missing_recorded_fixture",
                verify_prepared_inputs_completion=lambda *args, **kwargs:
                    fallback_calls.append((args, kwargs)),
            )

            def captured(_prepared, _relative, label):
                return types.SimpleNamespace(
                    validate_prepared_input_provenance_v2=lambda _value, *, expected_hosts: {
                        "preparation_pin": manifest["prepared_input_generation"]["provenance"]["preparation_pin"],
                        "final_spec_pin": manifest["prepared_input_generation"]["provenance"]["final_spec_pin"],
                        "final_plan_pin": manifest["prepared_input_generation"]["provenance"]["final_plan_pin"],
                        "exploration_lineage": {},
                    },
                )

            with patch.object(chronology, "_source5_captured_source_module",
                              side_effect=captured), \
                 patch.object(chronology, "_source_file",
                              return_value=(b"captured helper", "f" * 64, {})), \
                 patch.object(chronology, "_load_module",
                              return_value=helper_without_recorded_api):
                with self.assertRaisesRegex(
                        chronology.ChronologyError,
                        "lacks the selected completion verifier"):
                    chronology._verify_source5_prepared_input_generation(
                        manifest, prepared,
                        captured_pilot_read_providers={
                            "host-a": object(), "host-b": object(),
                        },
                        global_artifact_reader=reader,
                    )
            self.assertEqual(fallback_calls, [])

    def test_manifest_validator_forwards_recorded_reader_and_missing_api_refuses(self) -> None:
        chronology = self.chronology
        providers = {"host-a": object(), "host-b": object()}
        reader = lambda _pin, _maximum: b"captured"
        hosts = ["host-a", "host-b"]
        jobs = {phase: [] for phase in (
            "exploration", "aa", "confirmation", "pressure", "soak",
        )}
        spec = {"hosts": [{"host_id": host} for host in hosts],
                "rates": [{}], "oracles": [{}]}
        prepared = {
            "spec": spec, "plan": {"jobs": jobs},
            "controller": types.SimpleNamespace(build_jobs=lambda _spec, phase: jobs[phase]),
        }
        manifest = {
            "schema": chronology.SOURCE5_EXECUTION_SCHEMA_V5,
            "scope": chronology.SOURCE5_EXECUTION_SCOPE_V5,
            "qualification_eligible": False,
            "phase_order": [
                "exploration", "aa", "confirmation", "fixed_analysis", "pressure",
                "pressure_analysis", "soak", "final_analysis",
            ],
            "prepared_input_generation": {},
        }
        forwarded = []

        def capture_verify(*args, **kwargs):
            forwarded.append((args, kwargs))
            return {"route": "captured"}

        with patch.object(chronology, "_exact", side_effect=lambda value, *_args: value), \
             patch.object(chronology, "_source5_validate_manifest_identity"), \
             patch.object(chronology, "_source5_validate_manifest_source_bindings"), \
             patch.object(chronology, "_source5_journal_width_contract_pin_map",
                          return_value={host: {} for host in hosts}), \
             patch.object(chronology, "_verify_source5_prepared_input_generation",
                          side_effect=capture_verify):
            chronology._validate_source5_manifest_value(
                manifest, b"manifest", prepared,
                captured_pilot_read_providers=providers,
                global_artifact_reader=reader,
            )
        self.assertEqual(len(forwarded), 1)
        self.assertIs(forwarded[0][1]["captured_pilot_read_providers"], providers)
        self.assertIs(forwarded[0][1]["global_artifact_reader"], reader)

        with tempfile.TemporaryDirectory(prefix="source5-consumer-unsupported-api-") as temporary:
            fixture = self._metadata_fixture(Path(temporary))
            prepared_input, generation = self._preparatory_generation(fixture)
            real_load = chronology._load_module
            ordinary_calls = []

            def remove_recorded_api(raw, path, label):
                module = real_load(raw, path, label)
                if Path(path).name == "application-source5-input-preparation.py":
                    del module.verify_prepared_capacity_generation_bounded_metadata_v1
                    module.verify_prepared_capacity_generation_bounded = \
                        lambda *args, **kwargs: ordinary_calls.append(args)
                return module

            with patch.object(chronology, "_load_module", side_effect=remove_recorded_api):
                with self.assertRaisesRegex(
                        chronology.ChronologyError,
                        "lacks named metadata capacity replay APIs"):
                    chronology._verify_source5_preparatory_input_generation(
                        prepared_input, generation,
                    )
            self.assertEqual(ordinary_calls, [])

    def test_held_original_pilot_selects_named_metadata_exporter_without_changing_hook(self) -> None:
        """A routing spy checks SourceA's held exporter seam only."""
        chronology = self.chronology
        with tempfile.TemporaryDirectory(prefix="source5-original-pilot-getter-") as temporary:
            root = Path(temporary)
            source_root = root / "source"
            input_root = root / "inputs"
            source_root.mkdir(mode=0o700)
            input_root.mkdir(mode=0o700)
            artifact_root = root / "campaign-artifacts"
            artifact_root.mkdir(mode=0o700)
            output_path = root / "pilot.json"
            provider = object()
            preparation_pin = {
                "path": str(input_root / "preparation-generations" / "campaign" / "intent.json"),
                "raw_sha256": "a" * 64,
            }
            spec_pin = {"path": str(input_root / "initial-spec.json"),
                        "raw_sha256": "b" * 64}
            plan_pin = {"path": str(input_root / "initial-plan.json"),
                        "raw_sha256": "c" * 64}
            binding = {"binding_sha256": "d" * 64}
            manifest = {
                "schema": chronology.SOURCE5_PREPARATORY_EXECUTION_SCHEMA_V1,
                "original_inputs": {
                    "campaign_artifacts_root": str(artifact_root),
                },
            }
            h_modules = {
                name: types.ModuleType(f"routing_only_{name}")
                for name in ("campaign", "evidence_budget", "fixed_pair")
            }
            input_preparation = types.ModuleType("routing_only_inputprep")
            input_preparation.__file__ = str(
                source_root / "scripts/application-source5-input-preparation.py",
            )
            h_modules["input_preparation"] = input_preparation
            prepared = {
                "source5_execution_manifest": manifest,
                "source5_preparatory_capacity_generation": {
                    "provenance": {"preparation_pin": preparation_pin},
                },
                "source5_fixed_spec_host_pin": {"path": str(input_root / "fixed-spec-hosts/host-a.json"),
                                                  "raw_sha256": "e" * 64},
                "source5_prepared_fixed_host_binding": binding,
                "_source5_preparatory_h_modules": h_modules,
                "source_root": source_root, "input_root": input_root,
                "source5_execution_manifest_pin": {
                    "path": str(input_root / "execution-manifest.json"),
                    "raw_sha256": "f" * 64,
                },
                "original_pins": {"spec": spec_pin, "plan": plan_pin},
                "host_id": "host-a", "campaign_id": "campaign-original-pilot",
            }
            state = {
                "source5_pending": None, "source5_cleanup_blocked": False,
                "source5_failed_owner_window": False, "head": "0" * 64,
                "record_count": 0,
            }
            fixed_inputs = {
                "fixed_spec_host_pin": prepared["source5_fixed_spec_host_pin"],
                "prepared_host_binding": binding,
            }
            calls = []
            before_publication = lambda *_args: None

            def exporter(pins, records, host_id, *, captured_read_provider,
                         before_publication=None):
                calls.append((pins, records, host_id, captured_read_provider,
                              before_publication))
                raise RuntimeError("routing probe only; no owner replay")

            input_preparation.export_capacity_pilot_original_metadata_v1 = exporter
            with patch.object(
                    chronology, "_prepare_source5_preparatory_context_held",
                    return_value=(manifest, prepared, state, {"raw_sha256": "f" * 64}),
            ), patch.object(
                    chronology, "_source5_preparatory_fixed_host_inputs",
                    return_value=fixed_inputs,
            ), patch.object(
                    chronology, "_source5_preparatory_capacity_pilot_reservation_held",
                    return_value=({}, output_path, 1_000_000, {}),
            ), patch.object(
                    chronology, "_source5_preparatory_capacity_pilot_records_held",
                    return_value=([], []),
            ), patch.object(
                    chronology, "_Source5PreparatoryCapacityPilotReadProvider",
                    return_value=provider,
            ):
                with self.assertRaisesRegex(
                        chronology.ChronologyError, "routing probe only"):
                    chronology._source5_export_preparatory_capacity_pilot_held(
                        object(), {"path": str(input_root / "manifest.json"),
                                   "sha256": "1" * 64}, object(),
                    )
            self.assertEqual(len(calls), 1)
            pins, records, host_id, passed_provider, hook = calls[0]
            self.assertEqual(records, [])
            self.assertEqual(host_id, "host-a")
            self.assertIs(passed_provider, provider)
            self.assertTrue(callable(hook))
            self.assertEqual(pins, {
                "preparation": {"path": preparation_pin["path"],
                                "sha256": preparation_pin["raw_sha256"]},
                "spec": {"path": spec_pin["path"], "sha256": spec_pin["raw_sha256"]},
                "plan": {"path": plan_pin["path"], "sha256": plan_pin["raw_sha256"]},
                "source_root": str(source_root), "input_root": str(input_root),
                "campaign_artifacts_root": str(artifact_root),
                "prepared_host_binding": binding, "output": str(output_path),
            })
            self.assertIsNotNone(before_publication)

class Source5V5ExplorationLaunchGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.chronology = load_script(
            SCRIPT_DIR / "application-campaign-chronology.py",
            "source5_v5_exploration_launch_guard_test_target",
        )

    def test_v5_exploration_is_refused_but_fixed_phases_remain_launchable(self) -> None:
        chronology = self.chronology
        with self.assertRaisesRegex(
                chronology.ChronologyError,
                "imported ancestor and cannot launch an APP"):
            chronology._source5_require_launchable_phase(
                chronology.SOURCE5_EXECUTION_SCHEMA_V5, "exploration",
            )
        for phase in ("aa", "confirmation", "pressure", "soak"):
            with self.subTest(phase=phase):
                self.assertIsNone(chronology._source5_require_launchable_phase(
                    chronology.SOURCE5_EXECUTION_SCHEMA_V5, phase,
                ))

    def test_legacy_exploration_scope_is_unchanged(self) -> None:
        chronology = self.chronology
        for schema in (chronology.SOURCE5_EXECUTION_SCHEMA,
                       chronology.SOURCE5_EXECUTION_SCHEMA_V2,
                       chronology.SOURCE5_EXECUTION_SCHEMA_V3,
                       chronology.SOURCE5_EXECUTION_SCHEMA_V4):
            with self.subTest(schema=schema):
                self.assertIsNone(chronology._source5_require_launchable_phase(
                    schema, "exploration",
                ))

    def test_v5_width_horizon_excludes_only_old_exploration_callbacks(self) -> None:
        chronology = self.chronology
        plan = {"jobs": {
            "exploration": [{"host_id": "host-kvm-a"}],
            "aa": [{"host_id": "host-kvm-a"}] * 2,
            "confirmation": [{"host_id": "host-kvm-a"}] * 3,
            "pressure": [{"host_id": "host-kvm-a"}] * 4,
            "soak": [{"host_id": "host-kvm-a"}],
        }}
        fixed = [{"event": "source5_prepared_capacity_registered",
                  "phase": "registration", "count": 1,
                  "maximum_line_bytes": 1024}] + [
            {"event": "source5_analysis", "phase": phase, "count": 1,
             "maximum_line_bytes": 2048 + index}
            for index, phase in enumerate(chronology._SOURCE5_ANALYSIS_PHASES)
        ]
        contract = {
            "fixed_event_widths": fixed, "job_rows": [],
            "total_event_count": 65, "total_event_bytes": 100_000,
            "failed_owner_window": {"failed_event_count_uplift": 0},
        }
        projection = chronology._source5_plan_event_projection(
            plan, {"host_id": "host-kvm-a",
                   "scope": chronology.SOURCE5_EXECUTION_SCOPE_V5},
            {"schema": chronology.SOURCE5_EXECUTION_SCHEMA_V5,
             "journal_width_contracts": {"host-kvm-a": {}}},
            contract,
        )
        self.assertEqual(projection["job_counts"]["exploration"], 1)
        self.assertEqual(projection["counted_phases"],
                         ["aa", "confirmation", "pressure", "soak"])
        self.assertEqual(projection["paired_job_event_count"], 54)
        self.assertEqual(projection["soak_job_event_count"], 4)
        self.assertEqual(projection["successful_callback_events"], 65)
        self.assertEqual(projection["maximum_journal_bytes"], 100_000)

    def test_bounded_profiles_fail_closed_without_per_event_width_projection(self) -> None:
        chronology = self.chronology
        for schema in (chronology.SOURCE5_EXECUTION_SCHEMA_V4,
                       chronology.SOURCE5_EXECUTION_SCHEMA_V5,
                       chronology.SOURCE5_PREPARATORY_EXECUTION_SCHEMA_V1):
            with self.subTest(schema=schema):
                with self.assertRaisesRegex(
                        chronology.ChronologyError,
                        "requires its validated source-derived width projection"):
                    chronology._source5_event_width_projection({
                        "source5_execution_schema": schema,
                    })
        self.assertIsNone(chronology._source5_event_width_projection({
            "source5_execution_schema": chronology.SOURCE5_EXECUTION_SCHEMA_V3,
        }))

    def test_v5_and_legacy_execution_schemas_require_the_matching_provenance_version(self) -> None:
        chronology = self.chronology
        chronology._source5_validate_provenance_profile_correlation(
            chronology.SOURCE5_EXECUTION_SCHEMA_V5,
            {"schema": chronology.SOURCE5_PREPARED_INPUTS_PROVENANCE_SCHEMA_V2},
        )
        chronology._source5_validate_provenance_profile_correlation(
            chronology.SOURCE5_EXECUTION_SCHEMA_V4,
            {"schema": "allocatbelt.application-source5-prepared-inputs-provenance.v1"},
        )
        for schema, provenance_schema in (
            (chronology.SOURCE5_EXECUTION_SCHEMA_V5,
             "allocatbelt.application-source5-prepared-inputs-provenance.v1"),
            (chronology.SOURCE5_EXECUTION_SCHEMA_V4,
             chronology.SOURCE5_PREPARED_INPUTS_PROVENANCE_SCHEMA_V2),
        ):
            with self.subTest(schema=schema, provenance_schema=provenance_schema):
                with self.assertRaisesRegex(
                        chronology.ChronologyError,
                        "requires provenance v2"):
                    chronology._source5_validate_provenance_profile_correlation(
                        schema, {"schema": provenance_schema},
                    )

    def test_v5_completion_envelope_recomputes_exact_self_digest(self) -> None:
        chronology = self.chronology
        completion = {
            "schema": "allocatbelt.application-source5-preparation-completion.v2",
            "complete": True, "qualification_eligible": False,
            "campaign_id": "v5-completion-envelope",
            "preparation": {}, "final_spec": {}, "final_plan": {},
            "source_manifests": {}, "capacity_preparations": [],
            "pressure_calibrations": [], "pilots": [], "oracles": [],
            "filled_slots": {}, "ledger_heads": [], "resource_budgets": {},
        }
        completion["completion_sha256"] = chronology.sha256_bytes(
            chronology.canonical_bytes(completion),
        )
        checked = chronology._source5_validate_v5_completion_envelope(
            completion, completion["completion_sha256"],
        )
        self.assertEqual(checked, completion)
        stale = copy.deepcopy(completion)
        stale["campaign_id"] = "tampered"
        with self.assertRaisesRegex(chronology.ChronologyError, "semantic digest"):
            chronology._source5_validate_v5_completion_envelope(
                stale, completion["completion_sha256"],
            )
        extra = {**completion, "imported": True}
        with self.assertRaisesRegex(chronology.ChronologyError, "unexpected field set"):
            chronology._source5_validate_v5_completion_envelope(
                extra, completion["completion_sha256"],
            )

    def test_new_registration_signature_requires_the_closed_width_and_pilot_inputs(self) -> None:
        chronology = self.chronology
        parameters = inspect.signature(
            chronology.register_source5_prepared_exploration_capacity_locked,
        ).parameters
        self.assertTrue({"artifact_reader", "captured_pilot_read_providers",
                         "journal_width_contract_pin"}.issubset(parameters))

    def test_v5_registration_refuses_before_pilot_provider_consumption(self) -> None:
        chronology = self.chronology
        with self.assertRaisesRegex(
                chronology.ChronologyError,
                "disabled until SourceA replays the complete recorded-host InputPrep generation"):
            chronology._source5_require_authenticated_pilot_provider_cohort()
        source = (SCRIPT_DIR / "application-campaign-chronology.py").read_text()
        start = source.index("def register_source5_prepared_exploration_capacity_locked(")
        end = source.index("\ndef _inventory_runner_pin(", start)
        body = source[start:end]
        self.assertIn("_source5_verify_captured_prepared_ack_cohort_held(", body)
        self.assertIn("_source5_require_authenticated_pilot_provider_cohort()", body)
        self.assertLess(
            body.index("_source5_verify_captured_prepared_ack_cohort_held("),
            body.index("_source5_require_authenticated_pilot_provider_cohort()"),
        )
        self.assertNotIn("_verify_source5_prepared_input_generation(", body)
        self.assertNotIn("_append_event(", body)

    def test_closed_old_origin_reader_never_falls_back_to_ambient_paths(self) -> None:
        chronology = self.chronology
        raw = b"captured-old-origin"
        pin = {"path": "/old/origin.json", "raw_sha256": chronology.sha256_bytes(raw)}
        calls = []

        def reader(request, maximum):
            calls.append((request, maximum))
            if request["path"] != pin["path"]:
                raise AssertionError("reader received an undeclared origin")
            return raw

        self.assertEqual(
            chronology._source5_read_captured_raw_pin(reader, pin, len(raw), "old origin"),
            raw,
        )
        self.assertEqual(len(calls), 1)
        with self.assertRaisesRegex(chronology.ChronologyError, "closed captured raw pin"):
            chronology._source5_read_captured_raw_pin(
                reader, {**pin, "raw_sha256": "0" * 64}, len(raw), "old origin",
            )
        with self.assertRaisesRegex(chronology.ChronologyError, "exact closed captured raw pin"):
            chronology._source5_read_captured_raw_pin(reader, pin, len(raw) - 1, "old origin")

    def test_captured_old_ack_windows_join_exact_journal_order(self) -> None:
        chronology = self.chronology
        rows, records, authorizations, finished = [], [], [], []
        for index in range(360):
            job = {"phase": "exploration", "host_id": "host-kvm-a",
                   "ordinal": index % 6 + 1, "run_id": f"old-window-{index:03d}"}
            job_sha = chronology.sha256_bytes(chronology.canonical_bytes(job))
            terminal = {"state_claim": "valid_pair", "event_head": f"{index + 1:064x}",
                        "details": {"component_sha256": "a" * 64,
                                    "process_metrics_sha256": "b" * 64}}
            auth = {
                "authorization_id": f"source5-{index:048x}", "phase": "exploration",
                "job_index": index, "job": job, "job_run_id": job["run_id"],
                "job_sha256": job_sha, "members_sha256": "c" * 64,
                "capacity_registration_head": "d" * 64,
                "authorization_head": f"{index + 1000:064x}",
                "execution_manifest": {"path": "/old/execution.json", "raw_sha256": "e" * 64},
                "helper_input": {"path": "/old/helper.json", "raw_sha256": "f" * 64},
                "helper_module": {"path": "scripts/helper.py", "sha256": "1" * 64},
                "capacity_completion": {"path": "/old/capacity.json", "raw_sha256": "2" * 64},
                "capacity_ledger_raw_sha256": "3" * 64,
                "capacity_terminal_head": "4" * 64,
                "capacity_schedule_sha256": "5" * 64,
                "prerequisites": [], "input_snapshot_sha256": "6" * 64,
                "output_root": "/old/output", "outer_deadline_seconds": 1,
                "effective_timeout_seconds": 1, "member_count": 2,
                "members": [{"index": 0}, {"index": 1}],
                "starts": [{"member_index": 0}, {"member_index": 1}],
                "terminals": [{"member_index": 0}, {"member_index": 1}],
                "job_terminal": terminal,
                "authorization_record_count": index * 6 + 2,
            }
            rows.append({"row_index": index, "job": job, "job_sha256": job_sha})
            records.append({"job": job})
            authorizations.append(auth)
            finished.append({"phase": "exploration", "job_run_id": job["run_id"],
                             "authorization_id": auth["authorization_id"],
                             "authorization_head": auth["authorization_head"],
                             "job_terminal": terminal})
        proof = {
            "schema": "allocatbelt.application-source5-prepared-exploration-lineage-proof.v2",
            "campaign_id": "old-ack-window-fixture", "host_id": "host-kvm-a",
            "initial_output_root": "/old/output", "final_output_root": "/new/output",
            "bridge_header": {}, "index_rows": rows, "capture_context": {},
            "records": records, "journal_authorizations": authorizations,
            "journal_finished": finished,
            "bridge_header_pin": {"path": "/old/header", "raw_sha256": "7" * 64},
            "record_index_pin": {"path": "/old/index", "raw_sha256": "8" * 64},
            "job_count": 360, "callback_count": 2160,
            "allowed_slot_fill_proved": True,
            "initial_journal_pin": {"path": "/old/journal", "raw_sha256": "9" * 64},
            "initial_journal_structurally_replayed": True,
            "initial_phase_ledger_structurally_replayed": True,
            "initial_journal_head": "a" * 64,
            "initial_journal_record_count": 2161,
            "initial_phase_ledger_pin": {"path": "/old/ledger", "raw_sha256": "b" * 64},
            "initial_phase_ledger_byte_count": 360,
            "initial_phase_ledger_row_count": 360,
            "ancestor": {}, "component_replay_required": True,
            "fresh_sourcea_gpg_replay_required": True,
            "qualification_eligible": False,
        }
        joined = chronology._source5_prepared_ack_window_inputs(proof)
        self.assertEqual(len(joined), 360)
        self.assertEqual([window[2]["job_index"] for window in joined], list(range(360)))
        swapped = copy.deepcopy(proof)
        swapped["journal_authorizations"][1]["job_run_id"] = \
            swapped["journal_authorizations"][0]["job_run_id"]
        with self.assertRaisesRegex(chronology.ChronologyError, "ordered Plan window"):
            chronology._source5_prepared_ack_window_inputs(swapped)

    def test_captured_ack_archive_receives_closed_raw_reader_without_staging(self) -> None:
        source = (SCRIPT_DIR / "application-campaign-chronology.py").read_text()
        start = source.index("def _source5_verify_captured_prepared_ack_cohort_held(")
        end = source.index("\ndef _source5_captured_journal_width_contract(", start)
        body = source[start:end]
        self.assertLess(body.index("checked_budget = validate_host_budget("),
                        body.index("archive_proof = verify_ack("))
        self.assertIn("catalogue_row_reader=closed_catalogue_reader", body)
        self.assertIn("captured_preparatory_artifact_reader=", body)
        self.assertIn("captured_keyring_reader=captured_keyring_reader", body)
        self.assertNotIn("TemporaryDirectory", body)
        self.assertNotIn("cache.stage(", body)
        self.assertNotIn("budget_dependency_map_raw=", body)
        self.assertNotIn("budget_catalogue_map_raw=", body)

    def test_lineage_registration_proofs_cover_both_cohort_hosts(self) -> None:
        chronology = self.chronology
        hosts = ["host-kvm-a", "host-kvm-b"]
        store = {}
        provenance = {"exploration_lineage": {}}
        observed_by_host = {}
        for index, host in enumerate(hosts):
            observed = {
                "schema": "synthetic-component-observed-host.v1",
                "host_id": host, "boot_id_sha256": str(index + 1) * 64,
                "controls_sha256": str(index + 3) * 64,
                "controls": {"component_scope": "structural-fixture"},
                "cpu_affinity": [index],
                "network_namespace_inode": index + 1,
            }
            observed_raw = chronology.canonical_bytes(observed)
            observed_pin = {
                "path": f"/old/{host}/observed.json",
                "raw_sha256": chronology.sha256_bytes(observed_raw),
                "boot_id_sha256": observed["boot_id_sha256"],
                "controls_sha256": observed["controls_sha256"],
            }
            header = {
                "campaign_id": "cohort-lineage-component",
                "host_id": host,
                "initial": {"observed_host_pin": observed_pin},
            }
            header_raw = chronology.canonical_bytes(header)
            header_pin = {
                "path": f"/old/{host}/bridge-header.json",
                "raw_sha256": chronology.sha256_bytes(header_raw),
            }
            index_pin = {
                "path": f"/old/{host}/record-index.jsonl",
                "raw_sha256": str(index + 5) * 64,
            }
            store[header_pin["path"]] = header_raw
            store[observed_pin["path"]] = observed_raw
            provenance["exploration_lineage"][host] = {
                "bridge_header": header_pin, "record_index": index_pin,
            }
            observed_by_host[host] = {**observed_pin,
                "controls": observed["controls"],
                "cpu_affinity": observed["cpu_affinity"],
                "network_namespace_inode": observed["network_namespace_inode"],
            }

        def closed_reader(pin, maximum):
            raw = store.get(pin["path"])
            if (raw is None or len(raw) > maximum or
                    chronology.sha256_bytes(raw) != pin["raw_sha256"]):
                raise AssertionError("closed cohort reader rejected a pin")
            return raw

        calls = []

        class FakeLineage:
            def verify_source5_prepared_exploration_lineage_v2(
                    self, final_prepared, lineage_pins, **_kwargs):
                host = final_prepared["host_id"]
                calls.append((host, final_prepared["original_pins"]["observed_host"]))
                return {
                    "schema": "allocatbelt.application-source5-prepared-exploration-lineage-proof.v2",
                    "campaign_id": final_prepared["campaign_id"],
                    "host_id": host, "job_count": 360,
                    "callback_count": 2160,
                    "component_replay_required": True,
                    "fresh_sourcea_gpg_replay_required": True,
                    "qualification_eligible": False,
                    "index_rows": [{} for _ in range(360)],
                }

        selected_original = {
            "schema": chronology.CHRONOLOGY_SCHEMA,
            "campaign_id": "cohort-lineage-component",
            "host_id": hosts[0],
            "spec": {"path": "/final/spec.json", "raw_sha256": "a" * 64,
                     "semantic_sha256": "b" * 64},
            "plan": {"path": "/final/plan.json", "raw_sha256": "c" * 64,
                     "semantic_sha256": "d" * 64},
            "source_manifests": [],
            "observed_host": observed_by_host[hosts[0]],
        }
        prepared = {
            "campaign_id": "cohort-lineage-component", "host_id": hosts[0],
            "output_root": Path("/final/output"),
            "spec": {"hosts": [{"host_id": host} for host in hosts]},
            "original_pins": selected_original,
        }
        with patch.object(chronology, "_SOURCE5_OWN_MODULE", chronology):
            proofs = chronology._source5_verify_prepared_exploration_lineage_cohort(
                prepared, provenance, FakeLineage(), artifact_reader=closed_reader,
                campaign_module=object(), input_preparation_module=object(),
                campaign_inputs_module=object(), source5_campaign_module=object(),
                preparatory_budget_module=object(),
            )
        self.assertEqual(list(proofs), hosts)
        self.assertEqual([host for host, _observed in calls], hosts)
        self.assertEqual(
            [observed["path"] for _host, observed in calls],
            [observed_by_host[host]["path"] for host in hosts],
        )
        malformed = copy.deepcopy(provenance)
        del malformed["exploration_lineage"][hosts[1]]
        with self.assertRaisesRegex(chronology.ChronologyError, "exact two-host cohort"):
            chronology._source5_verify_prepared_exploration_lineage_cohort(
                prepared, malformed, FakeLineage(), artifact_reader=closed_reader,
                campaign_module=object(), input_preparation_module=object(),
                campaign_inputs_module=object(), source5_campaign_module=object(),
                preparatory_budget_module=object(),
            )

    def test_structural_registration_accepts_only_two_host_v2_lineage_shape(self) -> None:
        chronology = self.chronology
        hosts = ["host-kvm-a", "host-kvm-b"]

        def pin(path: str, digit: str) -> dict[str, str]:
            return {"path": path, "raw_sha256": digit * 64}

        provenance = {
            "schema": chronology.SOURCE5_PREPARED_INPUTS_PROVENANCE_SCHEMA_V2,
            "preparation_pin": pin("/private/input/preparation.json", "1"),
            "final_spec_pin": pin("/private/input/spec.json", "2"),
            "final_plan_pin": pin("/private/input/plan.json", "3"),
            "exploration_lineage": {
                host: {
                    "bridge_header": pin(
                        f"/private/old/{host}/bridge-header.json", "4",
                    ),
                    "record_index": pin(
                        f"/private/old/{host}/record-index.jsonl", "5",
                    ),
                }
                for host in hosts
            },
        }
        details = {
            "campaign_id": "campaign-v5", "host_id": hosts[0],
            "completion": {
                **pin("/private/input/prepared-inputs-completion.json", "6"),
                "semantic_sha256": "7" * 64,
            },
            "provenance": provenance,
            "host_completion": {
                "path": "/private/input/host-completion.json",
                "raw_sha256": "8" * 64, "semantic_sha256": "9" * 64,
            },
            "host_verification": {
                "path": "/private/input/host-verification.json",
                "raw_sha256": "a" * 64, "receipt_sha256": "b" * 64,
            },
            "capacity_ledger": {
                "path": "/private/input/ledger.jsonl",
                "raw_sha256": "c" * 64, "terminal_head": "d" * 64,
            },
            "capacity_schedule_sha256": "e" * 64,
            "entries": [{"entry": index} for index in range(15)],
            "qualification_eligible": False,
            "controller_chronology_proven": False,
        }

        def structural_index(registration_details):
            item = {
                "sequence": 1, "record_sha256": "f" * 64,
                "previous_sha256": "0" * 64,
                "record": {
                    "monotonic_ns": 1,
                    "event": "source5_prepared_capacity_registered",
                },
                "details": registration_details,
            }
            return chronology._journal_structural_index(
                [item], "campaign-v5", hosts[0], "0" * 64,
            )

        index = structural_index(details)
        self.assertEqual(len(index["registrations"]), 1)
        self.assertEqual(index["registrations"][0]["details"]["provenance"],
                         provenance)
        malformed = copy.deepcopy(details)
        del malformed["provenance"]["exploration_lineage"][hosts[1]]
        with self.assertRaisesRegex(chronology.ChronologyError, "two hosts"):
            structural_index(malformed)


class Source5RecordedNumericScalarSeamTests(unittest.TestCase):
    """One-owner validator seams; no GPG or Fixed success mock."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.chronology = load_script(
            SCRIPT_DIR / "application-campaign-chronology.py",
            "recorded_numeric_chronology_target",
        )

    def _window_fixture(self):
        c = self.chronology
        host = "host-kvm-a"
        job = {
            "phase": "exploration",
            "host_id": host,
            "ordinal": 1,
            "run_id": "numeric-run-000",
        }
        job_sha = c.sha256_bytes(c.canonical_bytes(job))

        def pin(name, digit, semantic_digit=None):
            value = {
                "path": f"/old/source5/{name}.json",
                "raw_sha256": digit * 64,
            }
            if semantic_digit is not None:
                value["semantic_sha256"] = semantic_digit * 64
            return value

        job_record = pin("record", "a")
        request = pin("request", "b", "c")
        checkpoint = pin("checkpoint", "d", "e")
        object_manifest = pin("objects", "f", "1")
        ack = pin("ack", "2", "3")
        signature = {
            "path": "/old/source5/signature.asc",
            "raw_sha256": "4" * 64,
            "signer_fingerprint": "A" * 40,
        }
        host_receipt = {
            "path": "/old/strict-host.json",
            "raw_sha256": "5" * 64,
            "host_verification_sha256": "6" * 64,
        }
        paths = {
            "overlay": ("/old/pair/fixed-pair-execution-overlay.json",
                        "7" * 64, "fixed_pair_artifact", None),
            "receipt": ("/old/pair/fixed-pair-execution-receipt.json",
                        "8" * 64, "component_receipt", None),
            "host": (host_receipt["path"], host_receipt["raw_sha256"],
                     "fixed_pair_host_receipt",
                     host_receipt["host_verification_sha256"]),
            "processes": ("/old/pair/processes.tsv", "9" * 64,
                          "normal_app_output", None),
            "runtime": ("/old/pair/.fixed-pair-runtime-bindings.json",
                        "0" * 64, "normal_app_output", None),
        }
        stage_root = "/tmp/recorded-numeric-stage"
        refs = []
        for name, (origin, raw_sha, role, semantic) in paths.items():
            refs.append({
                "origin_path": origin,
                "path": f"{stage_root}/{name}",
                "role": role,
                "host_id": host,
                "raw_sha256": raw_sha,
                "semantic_sha256": semantic,
                "byte_count": 1,
                "maximum_bytes": 1,
            })
        pins = {
            "job_record": job_record,
            "request": request,
            "checkpoint": checkpoint,
            "object_manifest": object_manifest,
            "ack": ack,
            "signature": signature,
            "host_receipt": host_receipt,
        }
        evidence = {
            "kind": "source5_fixed_pair",
            "overlay": {"path": paths["overlay"][0],
                        "raw_sha256": paths["overlay"][1]},
            "receipt": {"path": paths["receipt"][0],
                        "raw_sha256": paths["receipt"][1]},
            "host_receipt": host_receipt,
            "processes": {"path": paths["processes"][0],
                          "raw_sha256": paths["processes"][1]},
            "runtime_bindings": {"path": paths["runtime"][0],
                                 "raw_sha256": paths["runtime"][1]},
            "source_snapshot": {},
        }
        authorization_head = "1" * 64
        terminal_head = "2" * 64
        gpg_authority = {
            "ack_pin": ack,
            "checkpoint_pin": checkpoint,
            "object_manifest_pin": object_manifest,
            "signature_pin": signature,
            "request_pin": request,
            "job_record_raw_sha256": job_record["raw_sha256"],
            "component_replay_required": True,
            "qualification_eligible": False,
        }
        gpg_row = {
            "job": job,
            "job_record_pin": job_record,
            "authority": gpg_authority,
            "journal_authorization_head": authorization_head,
            "journal_terminal_head": terminal_head,
            "component_replay_required": True,
            "qualification_eligible": False,
        }
        original_pins = pins
        plan_row = {
            "consumer_host_id": host,
            "owner_host_id": host,
            "operation_kind": "registration_replay",
            "read_ordinal": 0,
            "job_index": 0,
            "job": job,
            "job_sha256": job_sha,
            "original_pins": original_pins,
            "objects": [],
        }
        payload_view = {
            "schema":
                "allocatbelt.application-source5-recorded-preparation-payload-view.v2",
            "basis_pin": {"path": "/old/basis.json",
                          "raw_sha256": "3" * 64,
                          "semantic_sha256": "4" * 64},
            "read_plan_pin": {"path": "/old/read-plan.json",
                              "raw_sha256": "5" * 64,
                              "semantic_sha256": "6" * 64},
            "session_nonce": "a" * 32,
            "consumer_host_id": host,
            "owner_host_id": host,
            "operation_kind": "registration_replay",
            "read_ordinal": 0,
            "job_index": 0,
            "job_sha256": job_sha,
            "original_pins": pins,
            "outer_request_pin": {"path": "/old/request.json",
                                  "raw_sha256": "7" * 64,
                                  "semantic_sha256": "8" * 64},
            "outer_response_pin": {"path": "/old/response.json",
                                   "raw_sha256": "9" * 64,
                                   "semantic_sha256": "0" * 64},
            "bundle_pin": {"path": "/old/bundle.tar",
                           "raw_sha256": "1" * 64,
                           "byte_count": 1},
            "stage_root": stage_root,
            "objects": refs,
            "payload_bytes": len(refs),
            "payload_view_sha256": "a" * 64,
        }
        yielded = {
            "payload_view": payload_view,
            "objects_by_origin": {
                ref["origin_path"]: ref for ref in refs
            },
            "stage_root": stage_root,
        }
        index_row = {
            "job": job,
            "job_sha256": job_sha,
            "job_record_pin": job_record,
        }
        record = {
            "job": job,
            "evidence": evidence,
            "chronology": {"authorization_head": authorization_head},
        }
        return {
            "host": host,
            "job": job,
            "job_sha": job_sha,
            "plan_row": plan_row,
            "payload_view": payload_view,
            "yielded": yielded,
            "index_row": index_row,
            "record": record,
            "gpg_row": gpg_row,
            "refs": refs,
            "pins": pins,
            "evidence": evidence,
            "paths": paths,
            "stage_root": stage_root,
        }

    def _bound_window(self, fixture=None):
        c = self.chronology
        fixture = fixture or self._window_fixture()
        return c._source5_recorded_numeric_bind_h3_window(
            fixture["yielded"], fixture["plan_row"],
            fixture["payload_view"], fixture["index_row"],
            fixture["record"], fixture["gpg_row"],
            expected_host_id=fixture["host"],
            expected_job_index=0,
            expected_read_ordinal=0,
        )

    def test_h3_yield_rejects_archived_job_view_shape_and_extra_fields(self):
        c = self.chronology
        with self.assertRaises(c.ChronologyError):
            c._source5_recorded_numeric_h3_yield({
                "schema": "allocatbelt.application-source5-archived-job-view.v1",
                "objects": {},
                "stage_root": "/tmp/stage",
            })
        malformed = self._window_fixture()["yielded"] | {"legacy_view": {}}
        with self.assertRaises(c.ChronologyError):
            c._source5_recorded_numeric_h3_yield(malformed)

    def test_h3_original_raw_pin_must_match_gpg_authority(self):
        fixture = self._window_fixture()
        fixture["payload_view"]["original_pins"]["checkpoint"] = {
            **fixture["pins"]["checkpoint"],
            "raw_sha256": "e" * 64,
        }
        with self.assertRaisesRegex(self.chronology.ChronologyError,
                                    "actual ACK/GPG cohort"):
            self._bound_window(fixture)

    def test_h3_raw_pin_must_match_independent_plan_projection(self):
        fixture = self._window_fixture()
        fixture["plan_row"]["original_pins"] = copy.deepcopy(
            fixture["plan_row"]["original_pins"],
        )
        fixture["payload_view"]["original_pins"]["checkpoint"] = {
            **fixture["pins"]["checkpoint"],
            "raw_sha256": "e" * 64,
        }
        with self.assertRaisesRegex(self.chronology.ChronologyError,
                                    "H3/plan/lineage"):
            self._bound_window(fixture)

    def test_h3_fixed_object_role_must_match_original_record(self):
        fixture = self._window_fixture()
        fixture["refs"][2]["role"] = "normal_app_output"
        fixture["yielded"]["objects_by_origin"][
            fixture["paths"]["host"][0]
        ] = fixture["refs"][2]
        fixture["payload_view"]["objects"][2] = fixture["refs"][2]
        with self.assertRaisesRegex(self.chronology.ChronologyError,
                                    "role or raw pin"):
            self._bound_window(fixture)

    def test_h3_ordinal_must_match_selected_source_job(self):
        fixture = self._window_fixture()
        with self.assertRaisesRegex(self.chronology.ChronologyError,
                                    "ordinal"):
            self.chronology._source5_recorded_numeric_bind_h3_window(
                fixture["yielded"], fixture["plan_row"],
                fixture["payload_view"], fixture["index_row"],
                fixture["record"], fixture["gpg_row"],
                expected_host_id=fixture["host"],
                expected_job_index=0,
                expected_read_ordinal=1,
            )

    def test_current_typed_source_and_module_pins_must_match(self):
        c = self.chronology
        hosts = ["host-kvm-a", "host-kvm-b"]
        source_rows = {
            host: {
                "host_id": host,
                "path": f"/source/{host}/manifest.json",
                "raw_sha256": ("a" if i == 0 else "b") * 64,
                "semantic_sha256": ("c" if i == 0 else "d") * 64,
                "source_tree_sha256": ("e" if i == 0 else "f") * 64,
            }
            for i, host in enumerate(hosts)
        }
        module_path = "scripts/application-source5-recorded-preparation-read.py"
        module_sha = "1" * 64
        prepared = {
            "host_id": hosts[0],
            "source_root": Path("/source/host-kvm-a"),
            "spec": {"hosts": [{"host_id": host} for host in hosts]},
            "original_pins": {"source_manifests": list(source_rows.values())},
        }
        lineages = {
            host: {
                "bridge_header": {
                    "initial": {
                        "source_manifest_pins": copy.deepcopy(list(source_rows.values())),
                    },
                },
            }
            for host in hosts
        }
        basis = {
            "cohort_hosts": hosts,
            "consumer_host_id": hosts[0],
            "current_roots": {"source_root": str(prepared["source_root"])},
            "source_manifest_pins": {
                host: {key: source_rows[host][key]
                       for key in ("path", "raw_sha256", "semantic_sha256")}
                for host in hosts
            },
            "source_module_pins": {
                hosts[0]: {module_path: {"path": module_path,
                                         "sha256": module_sha}},
                hosts[1]: {},
            },
        }
        c._source5_recorded_numeric_validate_source_bindings(
            prepared, basis, lineages, module_sha,
        )
        broken_basis = dict(basis)
        broken_basis["source_manifest_pins"] = dict(
            basis["source_manifest_pins"],
        )
        broken_basis["source_manifest_pins"][hosts[0]] = {
            **basis["source_manifest_pins"][hosts[0]],
            "raw_sha256": "9" * 64,
        }
        with self.assertRaisesRegex(c.ChronologyError, "consumer Source"):
            c._source5_recorded_numeric_validate_source_bindings(
                prepared, broken_basis, lineages, module_sha,
            )
        broken_module_basis = dict(basis)
        broken_module_basis["source_module_pins"] = copy.deepcopy(
            basis["source_module_pins"],
        )
        broken_module_basis["source_module_pins"][hosts[0]][
            module_path
        ]["sha256"] = "9" * 64
        with self.assertRaisesRegex(c.ChronologyError, "module"):
            c._source5_recorded_numeric_validate_source_bindings(
                prepared, broken_module_basis, lineages, module_sha,
            )

    def _fixed_projection_fixture(self):
        c = self.chronology
        host = "host-kvm-a"
        metrics = [{"member_index": 0, "p50_ns": 10},
                   {"member_index": 1, "p50_ns": 11}]
        overlay_pin = {"path": "/old/pair/fixed-pair-execution-overlay.json",
                       "sha256": "a" * 64}
        receipt_pin = {"path": "/old/pair/fixed-pair-execution-receipt.json",
                       "sha256": "b" * 64}
        host_pin = {
            "path": "/old/strict-host.json",
            "raw_sha256": "c" * 64,
            "host_verification_sha256": "d" * 64,
        }
        source_pin = {
            "host_id": host,
            "path": "/source/host-kvm-a/manifest.json",
            "raw_sha256": "e" * 64,
            "semantic_sha256": "f" * 64,
            "source_tree_sha256": "1" * 64,
        }
        overlay = {
            "output_root": "/old/pair",
            "runtime_bindings": {
                "pin": {"path": "/old/pair/.fixed-pair-runtime-bindings.json",
                        "sha256": "2" * 64},
            },
            "sources": {
                "manifests": {
                    host: {
                        "pin": {"path": source_pin["path"],
                                "sha256": source_pin["raw_sha256"]},
                        "manifest_sha256": source_pin["semantic_sha256"],
                    },
                },
                "selected": {"source_tree_sha256":
                             source_pin["source_tree_sha256"]},
            },
        }
        receipt = {
            "process_metrics": metrics,
            "process_validation_errors": [None, None],
            "inputs_unchanged": True,
            "processes_sha256": "3" * 64,
        }
        verified = {
            "schema": "fixed-receipt-schema",
            "verified": True,
            "status": "valid_pair",
            "qualification_eligible": False,
            "receipt_sha256": receipt_pin["sha256"],
            "overlay_sha256": overlay_pin["sha256"],
            "run_id": "numeric-run-000",
        }
        fixed = types.ModuleType("fixed_numeric_projection_fixture")
        fixed.CLOSED_RECORDED_CAPTURED_REPLAY_CONTEXT_SCHEMA_V1 = "closed-v1"
        fixed.RECEIPT_SCHEMA = "fixed-receipt-schema"
        replay = {
            "schema": "closed-v1",
            "verification": verified,
            "overlay": overlay,
            "execution_receipt": receipt,
            "host_verification_pin": host_pin,
            "full_replay_verified": True,
            "resident_executable_verified": False,
            "app_launch_permitted": False,
            "qualification_eligible": False,
        }
        record = {
            "job": {"run_id": "numeric-run-000"},
            "process_metrics": metrics,
        }
        chronology = {
            "component_sha256": "",
            "process_metrics_sha256": c.sha256_bytes(c.canonical_bytes(metrics)),
        }
        authorization = {
            "job_terminal": {"details": {
                "component_sha256": "",
                "process_metrics_sha256": chronology["process_metrics_sha256"],
            }},
        }
        evidence = {
            "processes": {
                "path": "/old/pair/processes.tsv",
                "raw_sha256": receipt["processes_sha256"],
            },
            "runtime_bindings": {
                "path": "/old/pair/.fixed-pair-runtime-bindings.json",
                "raw_sha256": overlay["runtime_bindings"]["pin"]["sha256"],
            },
            "source_snapshot": {
                "artifact": {"path": source_pin["path"],
                             "raw_sha256": source_pin["raw_sha256"]},
                "semantic_sha256": source_pin["semantic_sha256"],
                "source_tree_sha256": source_pin["source_tree_sha256"],
            },
        }
        component = {
            "schema": "allocatbelt.application-source5-fixed-component.v1",
            "overlay": {"path": overlay_pin["path"],
                        "raw_sha256": overlay_pin["sha256"]},
            "receipt": {"path": receipt_pin["path"],
                        "raw_sha256": receipt_pin["sha256"]},
            "verification": verified,
        }
        component_sha = c.sha256_bytes(c.canonical_bytes(component))
        chronology["component_sha256"] = component_sha
        authorization["job_terminal"]["details"]["component_sha256"] = component_sha
        historical_source_pin = {
            key: source_pin[key]
            for key in ("path", "raw_sha256", "semantic_sha256")
        }
        return (fixed, replay, record, chronology, authorization, evidence,
                host, historical_source_pin, source_pin["source_tree_sha256"],
                overlay_pin, receipt_pin, host_pin)

    def test_fixed_component_digest_must_match_original_journal(self):
        args = list(self._fixed_projection_fixture())
        args[3] = {**args[3], "component_sha256": "9" * 64}
        with self.assertRaisesRegex(self.chronology.ChronologyError,
                                    "component digest"):
            self.chronology._source5_recorded_numeric_validate_fixed_result(*args)

    def test_fixed_source_snapshot_must_match_historical_lineage_pin(self):
        args = list(self._fixed_projection_fixture())
        args[7] = {
            **args[7],
            "raw_sha256": "9" * 64,
        }
        with self.assertRaisesRegex(self.chronology.ChronologyError,
                                    "Source snapshot join"):
            self.chronology._source5_recorded_numeric_validate_fixed_result(*args)

    def test_fixed_receipt_metrics_must_match_recorded_metrics(self):
        args = list(self._fixed_projection_fixture())
        replay = dict(args[1])
        receipt = dict(replay["execution_receipt"])
        receipt["process_metrics"] = [{"member_index": 0, "p50_ns": 99}]
        replay["execution_receipt"] = receipt
        args[1] = replay
        with self.assertRaisesRegex(self.chronology.ChronologyError,
                                    "receipt differs"):
            self.chronology._source5_recorded_numeric_validate_fixed_result(*args)

    def test_construction_schema_fails_closed_without_named_typed_apis(self):
        c = self.chronology
        module = types.ModuleType("incomplete_construction_plan")
        module.PREPARED_INPUT_CONSTRUCTION_READ_PLAN_SCHEMA_V1 = (
            "allocatbelt.application-source5-prepared-input-construction-read-plan.v1"
        )
        with self.assertRaisesRegex(c.ChronologyError,
                                    "refusing an ordinary v2 fallback"):
            c._source5_recorded_numeric_read_apis(
                module,
                "allocatbelt.application-source5-prepared-input-construction-read-plan.v1",
            )

    def test_construction_dispatch_tracks_selected_source_capability(self):
        c = self.chronology
        module = load_script(
            SCRIPT_DIR / "application-source5-recorded-preparation-read.py",
            "recorded_numeric_selected_construction_plan",
        )
        schema = (
            "allocatbelt.application-source5-prepared-input-construction-read-plan.v1"
        )
        if callable(getattr(
                module, "validate_prepared_input_construction_payload_view_v1", None)):
            api = c._source5_recorded_numeric_read_apis(module, schema)
            self.assertEqual(
                api["payload"].__name__,
                "validate_prepared_input_construction_payload_view_v1",
            )
        else:
            with self.assertRaisesRegex(
                    c.ChronologyError, "refusing an ordinary v2 fallback"):
                c._source5_recorded_numeric_read_apis(module, schema)

    def test_current_v2_dispatch_uses_selected_typed_validator_family(self):
        c = self.chronology
        module = load_script(
            SCRIPT_DIR / "application-source5-recorded-preparation-read.py",
            "recorded_numeric_current_v2_plan",
        )
        api = c._source5_recorded_numeric_read_apis(
            module,
            "allocatbelt.application-source5-recorded-preparation-read-plan.v2",
        )
        self.assertTrue(callable(api["payload"]))
        self.assertEqual(
            api["payload"].__name__,
            "validate_recorded_preparation_payload_view_v2",
        )


class SourceAOwnedRegistrationProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.chronology = load_script(
            SCRIPT_DIR / "application-campaign-chronology.py",
            "sourcea_owned_registration_profile_tests",
        )
        cls.archive = load_script(
            SCRIPT_DIR / "application-source5-evidence-archive.py",
            "sourcea_owned_registration_selected_archive",
        )

    def _profile_fixture(self):
        c = self.chronology
        hosts = ["agent-8845HS-dev", "agent-EPYC-4585PX-dev"]
        pin2 = {"path": "/private/inputs/raw.json", "raw_sha256": "a" * 64}
        pin3 = {**pin2, "semantic_sha256": "b" * 64}
        provenance = {
            "schema": c.SOURCE5_PREPARED_INPUTS_PROVENANCE_SCHEMA_V2,
            "preparation_pin": pin2,
            "final_spec_pin": pin2,
            "final_plan_pin": pin2,
            "exploration_lineage": {
                host: {"bridge_header": pin2, "record_index": pin2}
                for host in hosts
            },
        }
        value = {
            "schema": "allocatbelt.application-source5-owned-replay-inputs.v1",
            "campaign_id": "sourcea-owned-profile",
            "consumer_host_id": hosts[0],
            "cohort_hosts": list(hosts),
            "completion_pin": pin3,
            "provenance_v2": copy.deepcopy(provenance),
            "metadata_capture_manifest_pin": pin2,
            "metadata_capture_stage_root": "/private/inputs/capture-stage",
            "probe_capture_index_pin": pin2,
            "scratch_declaration": {
                "schema": "allocatbelt.application-source5-recorded-preparation-scratch.v3",
                "root": "/private/scratch", "device_id": 1,
                "allocation_block_bytes": 4096,
                "directory_metadata_reserve_bytes": 4096,
                "reserved_bytes": 1024 * 1024,
                "reserved_inodes": 4096,
            },
            "timeout_declaration": {
                "maximum_io_window_seconds": 30,
                "maximum_operation_seconds": 3600,
            },
        }
        value["profile_sha256"] = c.sha256_bytes(c.canonical_bytes(value))
        expected = {
            "campaign_id": value["campaign_id"],
            "consumer_host_id": hosts[0], "cohort_hosts": hosts,
            "completion_pin": pin3, "provenance_v2": provenance,
        }
        return value, expected

    def test_profile_validator_returns_only_copied_data(self) -> None:
        c = self.chronology
        value, expected = self._profile_fixture()
        checked = c.validate_source5_owned_replay_input_profile_v1(value, expected)
        self.assertEqual(checked, value)
        self.assertEqual(
            c.source5_owned_prepared_completion_max_bytes_v1(value, expected),
            64 * 1024 * 1024,
        )
        self.assertEqual(c._source5_journal_role_limit("prepared_completion"),
                         16 * 1024 * 1024)
        checked["provenance_v2"]["exploration_lineage"][
            "agent-8845HS-dev"]["bridge_header"]["raw_sha256"] = "f" * 64
        self.assertEqual(
            value["provenance_v2"]["exploration_lineage"][
                "agent-8845HS-dev"]["bridge_header"]["raw_sha256"],
            "a" * 64,
        )

    def test_profile_validator_rejects_extra_fields_and_changed_digest(self) -> None:
        c = self.chronology
        value, expected = self._profile_fixture()
        with self.assertRaisesRegex(c.ChronologyError, "unexpected field set"):
            c.validate_source5_owned_replay_input_profile_v1(
                {**value, "ready": True}, expected,
            )
        stale = copy.deepcopy(value)
        stale["timeout_declaration"]["maximum_io_window_seconds"] = 31
        with self.assertRaisesRegex(c.ChronologyError, "self-digest"):
            c.validate_source5_owned_replay_input_profile_v1(stale, expected)

    def test_profile_validator_rejects_wrong_order_consumer_and_path_grammar(self) -> None:
        c = self.chronology
        value, expected = self._profile_fixture()
        reversed_expected = copy.deepcopy(expected)
        reversed_expected["cohort_hosts"].reverse()
        with self.assertRaisesRegex(c.ChronologyError, "two-host identity"):
            c.validate_source5_owned_replay_input_profile_v1(value, reversed_expected)
        external_consumer = copy.deepcopy(expected)
        external_consumer["consumer_host_id"] = "other-host"
        with self.assertRaisesRegex(c.ChronologyError, "two-host identity"):
            c.validate_source5_owned_replay_input_profile_v1(value, external_consumer)
        bad_path = copy.deepcopy(value)
        bad_path["metadata_capture_manifest_pin"]["path"] = "/private/../ambient/capture.json"
        bad_path["profile_sha256"] = c.sha256_bytes(c.canonical_bytes({
            key: item for key, item in bad_path.items() if key != "profile_sha256"
        }))
        with self.assertRaisesRegex(c.ChronologyError, "normalized raw2 pin"):
            c.validate_source5_owned_replay_input_profile_v1(
                bad_path, copy.deepcopy(expected),
            )

    def test_owned_v5_profile_map_requires_exact_ordered_raw3_pins(self) -> None:
        c = self.chronology
        hosts = ["agent-8845HS-dev", "agent-EPYC-4585PX-dev"]
        pin = {"path": "/private/profile.json", "raw_sha256": "a" * 64,
               "semantic_sha256": "b" * 64}
        manifest = {"hosts": hosts,
                    "prepared_replay_inputs": {host: copy.deepcopy(pin) for host in hosts}}
        self.assertEqual(list(c._source5_owned_replay_input_pin_map(manifest)), hosts)
        bad = copy.deepcopy(manifest)
        bad["prepared_replay_inputs"][hosts[0]] = {
            "path": pin["path"], "raw_sha256": pin["raw_sha256"],
        }
        with self.assertRaisesRegex(c.ChronologyError, "unexpected field set"):
            c._source5_owned_replay_input_pin_map(bad)
        bad = copy.deepcopy(manifest)
        bad["prepared_replay_inputs"] = {hosts[1]: pin, hosts[0]: pin}
        with self.assertRaisesRegex(c.ChronologyError, "host order"):
            c._source5_owned_replay_input_pin_map(bad)

    def test_new_owned_entry_has_no_caller_reader_or_provider_inputs(self) -> None:
        c = self.chronology
        parameters = inspect.signature(
            c.register_source5_prepared_exploration_owned_locked,
        ).parameters
        self.assertTrue({"replay_input_profile_pin", "journal_width_contract_pin",
                         "completion_pin", "provenance_v2"}.issubset(parameters))
        self.assertNotIn("artifact_reader", parameters)
        self.assertNotIn("captured_pilot_read_providers", parameters)


    def test_shared_h6_fixture_is_setup_once_and_returns_independent_dtos(self) -> None:
        fixture_module, first = _sourcea_h6_plan_fixture_copy()
        second_module = None
        third_module = None
        releases = 1
        try:
            second_module, second = _sourcea_h6_plan_fixture_copy()
            releases += 1
            third_module, third = _sourcea_h6_plan_fixture_copy()
            releases += 1
            self.assertIs(fixture_module, second_module)
            self.assertIs(fixture_module, third_module)
            self.assertIs(sys.modules.get(fixture_module.__name__), fixture_module)
            self.assertEqual(_SOURCEA_SHARED_H6_PLAN_FIXTURE_SETUP_COUNT, 1)
            self.assertEqual(_SOURCEA_SHARED_H6_PLAN_FIXTURE_TEARDOWN_COUNT, 0)
            lifecycle = _SOURCEA_SHARED_H6_FIXTURE_LIFECYCLE
            self.assertEqual(lifecycle["setup_calls"], 1)
            self.assertEqual(lifecycle["setup_paths_present"], (True, True))
            self.assertTrue(all(path.is_dir() for path in lifecycle["resource_paths"]))
            self.assertEqual(lifecycle["teardown_calls"], 0)
            host = first.hosts[0]
            self.assertIsNot(first.windows, second.windows)
            self.assertIsNot(first.windows[host], second.windows[host])
            self.assertIsNot(first.windows[host][0], second.windows[host][0])
            first.windows[host][0]["host_id"] = "test-only-mutated-window"
            first.basis["campaign_id"] = "test-only-mutated-basis"
            self.assertEqual(second.windows[host][0]["host_id"], host)
            self.assertNotEqual(second.basis["campaign_id"],
                                "test-only-mutated-basis")
            self.assertEqual(third.windows[host][0]["host_id"], host)
            self.assertNotEqual(third.basis["campaign_id"],
                                "test-only-mutated-basis")
            self.assertEqual(_SOURCEA_SHARED_H6_PLAN_FIXTURE_USERS, releases)
        finally:
            for _ in range(releases):
                _sourcea_h6_plan_fixture_release()

    def test_owned_plan_builder_reuses_the_source_v2_structural_fixture(self) -> None:
        fixture_module, f = _sourcea_h6_plan_fixture_copy()
        try:
            basis = f.basis
            hosts = list(f.hosts)
            prepared = {
                "campaign_id": basis["campaign_id"],
                "host_id": f.consumer,
                "original_pins": {
                    "spec": copy.deepcopy(basis["spec_pin"]),
                    "plan": copy.deepcopy(basis["plan_pin"]),
                    "source_manifests": [
                        {"host_id": host, **copy.deepcopy(
                            basis["source_manifest_pins"][host],
                        )}
                        for host in hosts
                    ],
                },
            }
            session = types.SimpleNamespace(
                plan_module=fixture_module.read_plan,
                modules={"archive": self.archive},
                prepared=prepared,
                hosts=hosts,
                source_module_pins=copy.deepcopy(basis["source_module_pins"]),
                completion_pin=copy.deepcopy(
                    basis["prepared_input_generation"]["completion_pin"],
                ),
                provenance=copy.deepcopy(f.provenance),
                lineage_proofs=f.proofs,
                profile={
                    "metadata_capture_manifest_pin": copy.deepcopy(
                        basis["metadata_capture_manifest_pin"],
                    ),
                },
                width_pin=copy.deepcopy(basis["width_contract_pin"]),
                frontier=copy.deepcopy(basis["current_journal_frontier"]),
                route=self.chronology._Source5OwnedReplayRoute.REGISTRATION,
                execution_manifest_pin=None, registration_head=None,
            )
            self.chronology._source5_owned_registration_build_plan(
                session, copy.deepcopy(basis["current_roots"]),
                f.catalogues, f.readback_caps, f.windows, f.scratch, f.timeouts,
            )
            planner = fixture_module.read_plan
            self.assertEqual(planner.READ_WINDOW_COUNT, 720)
            self.assertEqual(session.plan["operation_kind"], "registration_replay")
            self.assertNotIn("read_window_count", session.plan)
            self.assertEqual(
                [row["read_ordinal"] for row in session.plan["window_index"]],
                list(range(720)),
            )
            self.assertEqual(len(session.chunks),
                             len(session.plan["window_chunks"]))
            self.assertRegex(session.plan["session_nonce"], r"^[0-9a-f]{32}$")
            expected_ancestors = {
                host: {
                    name: f.proofs[host]["ancestor"][f"{name}_pin"]
                    for name in ("bridge_header", "record_index")
                }
                for host in hosts
            }
            self.assertEqual(session.basis["ancestor_pins"], expected_ancestors)
            self.assertNotIn("execution_manifest_pin", session.basis)
            self.assertNotIn("registration_head", session.basis)
            checked = planner.validate_recorded_preparation_read_plan_v2(
                session.plan, session.chunks, session.basis, session.basis_pin,
                old_catalogues_by_host=f.catalogues,
                old_readback_caps_by_host=f.readback_caps,
                window_metadata_by_host=f.windows,
                session_nonce=session.plan["session_nonce"],
                scratch_declaration=f.scratch,
                timeout_declaration=f.timeouts,
            )
            self.assertEqual(checked, session.plan)
        finally:
            _sourcea_h6_plan_fixture_release()

    def test_owned_plan_builder_uses_nonzero_sealed_refresh_frontier(self) -> None:
        c = self.chronology
        fixture_module, f = _sourcea_h6_plan_fixture_copy()
        try:
            basis = f.basis
            hosts = list(f.hosts)
            prepared = {
                "campaign_id": basis["campaign_id"],
                "host_id": f.consumer,
                "original_pins": {
                    "spec": copy.deepcopy(basis["spec_pin"]),
                    "plan": copy.deepcopy(basis["plan_pin"]),
                    "source_manifests": [
                        {"host_id": host, **copy.deepcopy(
                            basis["source_manifest_pins"][host],
                        )}
                        for host in hosts
                    ],
                },
            }
            with tempfile.TemporaryDirectory(prefix="sourcea-refresh-basis-") as temporary:
                registration_head = c.sha256_bytes(b"registration-head-fixture")
                manifest_body = {
                    "schema": c.SOURCE5_EXECUTION_SCHEMA_V5,
                    "scope": "bounded-pure-plan-fixture",
                    "registration_head": registration_head,
                }
                manifest_sha = c.sha256_bytes(c.canonical_bytes(manifest_body))
                manifest = {**manifest_body, "manifest_sha256": manifest_sha}
                manifest_raw = c.canonical_bytes(manifest)
                manifest_path = Path(temporary) / "execution-manifest.json"
                manifest_path.write_bytes(manifest_raw)
                manifest_path.chmod(0o600)
                manifest_pin = {
                    "path": str(manifest_path),
                    "raw_sha256": c.sha256_bytes(manifest_raw),
                    "semantic_sha256": manifest_sha,
                }
                self.assertLessEqual(len(manifest_raw), c.MAX_PLAN_BYTES)
                self.assertEqual(c.sha256_bytes(manifest_path.read_bytes()),
                                 manifest_pin["raw_sha256"])
                frontier = {
                    "head_sha256": c.sha256_bytes(b"actual-current-frontier-fixture"),
                    "record_count": 2,
                }
                self.assertEqual(manifest["registration_head"], registration_head)
                session = types.SimpleNamespace(
                    plan_module=fixture_module.read_plan,
                    modules={"archive": self.archive},
                    prepared=prepared,
                    hosts=hosts,
                    source_module_pins=copy.deepcopy(basis["source_module_pins"]),
                    completion_pin=copy.deepcopy(
                        basis["prepared_input_generation"]["completion_pin"],
                    ),
                    provenance=copy.deepcopy(f.provenance),
                    lineage_proofs=f.proofs,
                    profile={
                        "metadata_capture_manifest_pin": copy.deepcopy(
                            basis["metadata_capture_manifest_pin"],
                        ),
                    },
                    width_pin=copy.deepcopy(basis["width_contract_pin"]),
                    frontier=frontier,
                    route=c._Source5OwnedReplayRoute.SEALED_REFRESH,
                    execution_manifest_pin=manifest_pin,
                    registration_head=registration_head,
                )
                c._source5_owned_registration_build_plan(
                    session, copy.deepcopy(basis["current_roots"]),
                    f.catalogues, f.readback_caps, f.windows, f.scratch, f.timeouts,
                )
                planner = fixture_module.read_plan
                self.assertEqual(session.plan["operation_kind"], "refresh_replay")
                self.assertEqual(session.basis["execution_manifest_pin"], manifest_pin)
                self.assertEqual(session.basis["registration_head"], registration_head)
                self.assertEqual(session.basis["current_journal_frontier"], frontier)
                self.assertRegex(session.plan["session_nonce"], r"^[0-9a-f]{32}$")
                checked = planner.validate_recorded_preparation_read_plan_v2(
                    session.plan, session.chunks, session.basis, session.basis_pin,
                    old_catalogues_by_host=f.catalogues,
                    old_readback_caps_by_host=f.readback_caps,
                    window_metadata_by_host=f.windows,
                    session_nonce=session.plan["session_nonce"],
                    scratch_declaration=f.scratch,
                    timeout_declaration=f.timeouts,
                )
                self.assertEqual(checked, session.plan)
        finally:
            _sourcea_h6_plan_fixture_release()

    def test_owned_source_is_top_level_code_and_uses_current_pins(self) -> None:
        source = (SCRIPT_DIR / "application-campaign-chronology.py").read_text()
        module = ast.parse(source)
        top_level_functions = {
            node.name: node for node in module.body
            if isinstance(node, ast.FunctionDef)
        }
        self.assertIn("_source5_owned_registration_input_snapshots", top_level_functions)
        api_name = "register_source5_prepared_exploration_owned_locked"
        self.assertIn(api_name, top_level_functions)
        self.assertTrue(callable(getattr(self.chronology, api_name, None)))
        api_source = ast.get_source_segment(source, top_level_functions[api_name])
        replay_source = ast.get_source_segment(
            source, top_level_functions["_source5_owned_input_generation_replay_held"],
        )
        append_source = ast.get_source_segment(
            source, top_level_functions["_source5_owned_registration_append_held"],
        )
        self.assertIsNotNone(api_source)
        self.assertIsNotNone(replay_source)
        self.assertIsNotNone(append_source)
        self.assertIn("_source5_owned_operation_scope_held", api_source)
        self.assertIn("_source5_owned_input_generation_replay_held", api_source)
        self.assertIn("verify_prepared_inputs_completion_closed_recorded_v2", replay_source)
        self.assertIn("_source5_recorded_numeric_ancestor_context_held", replay_source)
        self.assertIn("checked_width_pin", replay_source)
        provider_class = next(
            node for node in module.body
            if isinstance(node, ast.ClassDef) and
            node.name == "_Source5PreparedExplorationRegistrationPilotProvider"
        )
        open_view = next(
            node for node in provider_class.body
            if isinstance(node, ast.FunctionDef) and node.name == "open_view"
        )
        provider_source = ast.get_source_segment(source, open_view)
        self.assertIsNotNone(provider_source)
        h3_offset = provider_source.index("session.h_client.open_view(ordinal)")
        numeric_offset = provider_source.index(
            "_source5_verify_recorded_numeric_ancestor_held("
        )
        inputprep_yield_offset = provider_source.index("yield inputprep_view")
        complete_offset = provider_source.index("session.complete_window(")
        self.assertLess(h3_offset, numeric_offset)
        self.assertLess(numeric_offset, inputprep_yield_offset)
        self.assertLess(inputprep_yield_offset, complete_offset)
        self.assertIn("capture_reader", api_source)
        self.assertIn("session.h_client", api_source)
        self.assertIn('getattr(session.h_client, "plan_module", None)', api_source)
        self.assertIn("close_optional_reader(reader)", api_source)
        self.assertIn("lambda reader=capture_reader", api_source)
        self.assertIn('"registration_record"', append_source)
        self.assertIn('after_state["registration_head"]', append_source)
        self.assertIn('after_state["prepared_capacity_registration"]', append_source)
        self.assertIn("owned-registration-replay-result.v1", append_source)
        self.assertFalse(any(
            isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
            for node in module.body
        ), "module scope must not execute an editor write fragment")
        self.assertFalse(any(
            isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and
            type(node.value.value) is str and
            ("def register_source5_prepared_exploration_owned_locked" in node.value.value or
             "p.write_text(p.read_text() + insert)" in node.value.value)
            for node in module.body
        ), "owned source must be code, not a triple-quoted editor fragment")
        plan_builder = top_level_functions["_source5_owned_registration_build_plan"]
        plan_source = ast.get_source_segment(source, plan_builder)
        self.assertIsNotNone(plan_source)
        self.assertIn("READ_WINDOW_COUNT", plan_source)
        self.assertIn('"window_index"', plan_source)
        self.assertNotIn('"read_window_count"', plan_source)
        final_recheck = ast.get_source_segment(
            source, top_level_functions["_source5_prepared_registration_recheck_inputs_callback_free"],
        )
        self.assertIn("time.monotonic_ns() < session.deadline_ns", final_recheck)
        snapshot_parameters = inspect.signature(
            self.chronology._source5_owned_registration_input_snapshots,
        ).parameters
        self.assertIn("width_pin", snapshot_parameters)
        self.assertNotIn("source5_owned_width_contract_pin",
                         ast.get_source_segment(
                             source,
                             top_level_functions["_source5_owned_registration_input_snapshots"],
                         ))
        proof_check = ast.get_source_segment(
            source, top_level_functions["_source5_prepared_registration_proof_check"],
        )
        self.assertIn('session.check_deadline("registration append consume")', proof_check)
        self.assertIn("_source5_owned_registration_verify_h_ledger(session)", proof_check)
        consume_offset = proof_check.index(
            "_source5_prepared_registration_finalize_consume(",
        )
        state_offset = proof_check.index('entry["state"] = "consumed"')
        self.assertLess(consume_offset, state_offset)
        final_guard = ast.get_source_segment(
            source,
            top_level_functions["_source5_prepared_registration_finalize_consume"],
        )
        input_scan = final_guard.index(
            "_source5_prepared_registration_recheck_inputs_callback_free(",
        )
        journal_scan = final_guard.index(
            "_source5_prepared_registration_recheck_empty_frontier_held(",
        )
        direct_clock = final_guard.index("time.monotonic_ns() < session.deadline_ns")
        scope_consume = final_guard.index("_source5_owned_scope_consume_sink(")
        self.assertLess(input_scan, journal_scan)
        self.assertLess(journal_scan, direct_clock)
        self.assertLess(direct_clock, scope_consume)
        self.assertIn("registration append postwrite", append_source)

    def test_last_cancel_callback_mutation_fails_the_final_prewrite_snapshot(self) -> None:
        c = self.chronology
        with tempfile.TemporaryDirectory(prefix="sourcea-prewrite-callback-") as temporary:
            root = Path(temporary)
            source_root = root / "source"
            input_root = root / "inputs"
            output_root = root / "output"
            capture_root = root / "capture"
            for path in (source_root, input_root, output_root, capture_root):
                path.mkdir(mode=0o700)
            controlled = input_root / "spec.json"
            controlled.write_bytes(b"pinned before callback")
            controlled.chmod(0o600)
            raw_sha256 = c.sha256_bytes(controlled.read_bytes())
            snapshot = c._source5_construction_snapshot_file(
                str(controlled), raw_sha256, 128, "SourceA controlled current Spec",
            )
            original_pins = {"selected": "unchanged"}
            prepared = {
                "output_root": output_root, "campaign_id": "prewrite-callback",
                "host_id": "host-a", "original_pins": original_pins,
                "source_root": source_root, "input_root": input_root,
            }
            prepare_args = {
                "plan_pin": {}, "spec_pin": {}, "source_root": source_root,
                "input_root": input_root, "host_id": "host-a",
                "observed_host_pin": {}, "output_root": output_root,
            }
            refreshed = {
                **prepared, "original_pins": original_pins,
            }
            callback_calls = []

            def last_cancel_callback(label):
                callback_calls.append(label)
                controlled.write_bytes(b"mutated after last cancel poll")

            session = types.SimpleNamespace(
                prepared=prepared, lock=object(), input_snapshots=[snapshot],
                source_file_snapshots=[], root_snapshots=[],
                capture_reader=types.SimpleNamespace(
                    _open_root_checked=lambda: os.open(capture_root, os.O_RDONLY),
                ),
                prepare_args=prepare_args, check_deadline=last_cancel_callback,
                deadline_ns=time.monotonic_ns() + 60_000_000_000,
            )
            session.check_deadline("last H/cancellation callback")
            append_attempts = []
            with patch.object(c, "_check_lock"), \
                 patch.object(c, "_prepare_inputs", return_value=refreshed), \
                 patch.object(c, "_source5_construction_close_prepared"):
                try:
                    c._source5_prepared_registration_recheck_inputs_callback_free(
                        session, "registration append final prewrite",
                    )
                except c.ChronologyError as error:
                    self.assertRegex(
                        str(error), "identity changed during the held construction",
                    )
                else:
                    append_attempts.append("durable write")
            self.assertEqual(callback_calls, ["last H/cancellation callback"])
            self.assertEqual(append_attempts, [])

    def test_deadline_expiry_during_final_recheck_prevents_append(self) -> None:
        c = self.chronology
        with tempfile.TemporaryDirectory(prefix="sourcea-prewrite-deadline-") as temporary:
            root = Path(temporary)
            source_root = root / "source"
            input_root = root / "inputs"
            output_root = root / "output"
            capture_root = root / "capture"
            for path in (source_root, input_root, output_root, capture_root):
                path.mkdir(mode=0o700)
            controlled = input_root / "spec.json"
            controlled.write_bytes(b"still pinned")
            controlled.chmod(0o600)
            snapshot = c._source5_construction_snapshot_file(
                str(controlled), c.sha256_bytes(controlled.read_bytes()), 128,
                "SourceA deadline current Spec",
            )
            original_pins = {"selected": "unchanged"}
            prepared = {
                "output_root": output_root, "campaign_id": "prewrite-deadline",
                "host_id": "host-a", "original_pins": original_pins,
                "source_root": source_root, "input_root": input_root,
            }
            prepare_args = {
                "plan_pin": {}, "spec_pin": {}, "source_root": source_root,
                "input_root": input_root, "host_id": "host-a",
                "observed_host_pin": {}, "output_root": output_root,
            }
            refreshed = {**prepared, "original_pins": original_pins}
            session = types.SimpleNamespace(
                prepared=prepared, lock=object(), input_snapshots=[snapshot],
                source_file_snapshots=[], root_snapshots=[],
                capture_reader=types.SimpleNamespace(
                    _open_root_checked=lambda: os.open(capture_root, os.O_RDONLY),
                ),
                prepare_args=prepare_args, deadline_ns=100,
            )
            append_attempts = []
            with patch.object(c, "_check_lock"), \
                 patch.object(c, "_prepare_inputs", return_value=refreshed), \
                 patch.object(c, "_source5_construction_close_prepared"), \
                 patch.object(c.time, "monotonic_ns", return_value=101):
                try:
                    c._source5_prepared_registration_recheck_inputs_callback_free(
                        session, "registration append final prewrite",
                    )
                except c.ChronologyError as error:
                    self.assertRegex(
                        str(error), "expired during its callback-free input recheck",
                    )
                else:
                    append_attempts.append("durable write")
            self.assertEqual(append_attempts, [])

    def test_forged_registration_proof_is_rejected_before_lock_or_file_access(self) -> None:
        c = self.chronology
        with self.assertRaisesRegex(c.ChronologyError, "exact private one-use owner proof"):
            c._source5_prepared_registration_proof_check(
                object(), None, {}, {}, {}, "a" * 64, mode="precheck",
            )

    def test_cli_main_guard_follows_all_owned_registration_definitions(self) -> None:
        source = (SCRIPT_DIR / "application-campaign-chronology.py").read_text()
        guard = source.rindex('if __name__ == "__main__":')
        owned_api = source.index(
            "def register_source5_prepared_exploration_owned_locked(",
        )
        self.assertLess(owned_api, guard)
        self.assertEqual(source.count('if __name__ == "__main__":'), 1)


class SourceAOwnedOperationScopeNegativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.chronology = load_script(
            SCRIPT_DIR / "application-campaign-chronology.py",
            "sourcea_owned_operation_scope_negative_test_target",
        )
        cls.archive = load_script(
            SCRIPT_DIR / "application-source5-evidence-archive.py",
            "sourcea_owned_operation_scope_selected_archive",
        )

    def test_source_loader_uses_normal_module_identity_and_failure_restore(self) -> None:
        c = self.chronology
        self.assertIs(c._SOURCE5_OWN_MODULE, c)
        self.assertIs(sys.modules.get(c.__name__), c)
        module_name = f"_sourcea_loader_lifecycle_{os.getpid()}"
        previous = sys.modules.get(module_name)
        try:
            with tempfile.TemporaryDirectory(prefix="sourcea-loader-lifecycle-") as temporary:
                root = Path(temporary)
                successful_path = root / "successful_fixture.py"
                successful_path.write_text(
                    "import sys\nOBSERVED_MODULE = sys.modules[__name__]\n",
                )
                existing = types.ModuleType(module_name)
                sys.modules[module_name] = existing
                loaded = load_script(successful_path, module_name)
                self.assertIs(sys.modules.get(module_name), loaded)
                self.assertIs(loaded.OBSERVED_MODULE, loaded)
                self.assertIsNot(loaded, existing)

                failing_path = root / "failing_fixture.py"
                failing_path.write_text(
                    "raise RuntimeError('loader fixture failure')\n",
                )
                prior_on_failure = types.ModuleType(module_name)
                sys.modules[module_name] = prior_on_failure
                with self.assertRaisesRegex(RuntimeError, "loader fixture failure"):
                    load_script(failing_path, module_name)
                self.assertIs(sys.modules.get(module_name), prior_on_failure)
        finally:
            if previous is None:
                sys.modules.pop(module_name, None)
            else:
                sys.modules[module_name] = previous

    def _install_test_scope(self):
        c = self.chronology
        scope = c._Source5OwnedOperationScope(
            c._SOURCE5_OWNED_OPERATION_SCOPE_SECRET,
        )
        operation_lock = c.threading.Lock()
        operation_lock.acquire()
        lock = types.SimpleNamespace(
            _creator_pid=os.getpid(), _operation_lock=operation_lock,
        )
        session = object.__new__(c._Source5PreparedExplorationRegistrationSession)
        session.lock = lock
        session.prepared = {
            "output_root": Path(__file__).resolve().parent,
            "campaign_id": "scope-negative-fixture",
            "host_id": "host-a",
        }
        session.operation_scope = scope
        session.frontier = {"head_sha256": "0" * 64, "record_count": 0}
        session.journal_file_key = None
        session.route = c._Source5OwnedReplayRoute.REGISTRATION
        session.execution_manifest_pin = None
        session.registration_head = None
        session.archived_authorities = {}
        session.numeric_context = None
        session.basis = None
        session.basis_pin = None
        session.plan = None
        session.plan_pin = None
        session.modules = {}
        session.h_client = None
        entry = {
            "scope": scope, "creator_pid": os.getpid(),
            "sourcea_module": c._source5_own_chronology_module(),
            "session": session, "prepared": session.prepared,
            "lock": lock, "thread_id": c.threading.get_ident(),
            "route": session.route,
            "allowed_sinks": c._SOURCE5_OWNED_OPERATION_ROUTE_SINKS[
                session.route
            ],
            "state": c._Source5OwnedScopeState.REPLAYING,
            "binding": {
                "deadline_ns": c.time.monotonic_ns() + 60_000_000_000,
                "allowed_sink_names": tuple(sorted(
                    sink.name for sink in
                    c._SOURCE5_OWNED_OPERATION_ROUTE_SINKS[session.route]
                )),
            },
            "frontier": {
                "head_sha256": "0" * 64, "record_count": 0,
                "file_stat": None,
            },
            "old_owner_binding": None, "plan_binding": None,
            "h_binding": None,
        }
        with c._SOURCE5_OWNED_OPERATION_SCOPE_LOCK:
            c._SOURCE5_OWNED_OPERATION_SCOPES[scope] = entry
        return scope, session, entry, operation_lock

    def _remove_test_scope(self, scope, session, entry, operation_lock) -> None:
        c = self.chronology
        c._source5_owned_scope_expire(scope, session, entry)
        if operation_lock.locked():
            operation_lock.release()

    def test_incomplete_bind_then_mark_fails_as_typed_error_without_gpg_fixture(self) -> None:
        c = self.chronology
        scope, session, entry, operation_lock = self._install_test_scope()
        session.hosts = ["host-a", "host-b"]
        session.archived_authorities = {}
        session.numeric_context = None
        session.failed = False
        session.closed = False
        session.active = False
        session.global_cursor = 719
        session.provider_cursors = {"host-a": 359, "host-b": 360}
        session.numeric_replay_count = 719
        session.verified_completion = None
        session.completion_value = None
        try:
            with patch.object(c, "_source5_owned_scope_require", return_value=entry):
                # No signed/GPG rows are supplied: binding must reject the incomplete owner DTO.
                with self.assertRaisesRegex(c.ChronologyError, "fresh two-host GPG ledger"):
                    c._source5_owned_scope_bind_old_owner_state(scope, session)
                with self.assertRaisesRegex(c.ChronologyError,
                                            "no producer-time owner/plan/H bindings"):
                    c._source5_owned_scope_mark_replay_complete(scope, session)
                # This minimal incomplete seam has no positive owner/GPG/replay claim.
                entry["old_owner_binding"] = {
                    "numeric_binding": {"rows_per_host": [1, 1]},
                }
                entry["plan_binding"] = {"window_count": 0}
                entry["h_binding"] = {}
                with self.assertRaisesRegex(c.ChronologyError,
                                            "did not close exactly 720 H3 and Fixed windows"):
                    c._source5_owned_scope_mark_replay_complete(scope, session)
            self.assertEqual(entry["state"], c._Source5OwnedScopeState.REPLAYING)
        finally:
            self._remove_test_scope(scope, session, entry, operation_lock)

    def test_bound_plan_and_h_context_reject_postbind_replacement_and_mutation(self) -> None:
        c = self.chronology
        fixture_module, f = _sourcea_h6_plan_fixture_copy()
        scope_bundle = None
        try:
            scope_bundle = self._install_test_scope()
            scope, session, entry, operation_lock = scope_bundle
            basis = f.basis
            hosts = list(f.hosts)
            session.plan_module = fixture_module.read_plan
            session.prepared = {
                "output_root": Path(__file__).resolve().parent,
                "campaign_id": basis["campaign_id"],
                "host_id": f.consumer,
                "original_pins": {
                    "spec": copy.deepcopy(basis["spec_pin"]),
                    "plan": copy.deepcopy(basis["plan_pin"]),
                    "source_manifests": [
                        {"host_id": host, **copy.deepcopy(
                            basis["source_manifest_pins"][host],
                        )}
                        for host in hosts
                    ],
                },
            }
            entry["prepared"] = session.prepared
            session.hosts = hosts
            session.source_module_pins = copy.deepcopy(basis["source_module_pins"])
            session.completion_pin = copy.deepcopy(
                basis["prepared_input_generation"]["completion_pin"],
            )
            session.provenance = copy.deepcopy(f.provenance)
            session.lineage_proofs = f.proofs
            session.profile = {
                "metadata_capture_manifest_pin": copy.deepcopy(
                    basis["metadata_capture_manifest_pin"],
                ),
            }
            session.width_pin = copy.deepcopy(basis["width_contract_pin"])
            session.frontier = copy.deepcopy(basis["current_journal_frontier"])
            entry["frontier"] = {**session.frontier, "file_stat": None}
            with tempfile.TemporaryDirectory(prefix="sourcea-c2r2-hbinding-") as temporary:
                source_root = Path(temporary) / "source"
                h_relative = c._SOURCE5_PREPARED_INPUT_CONSTRUCTION_MODULE_PATHS[
                    "source5_campaign"
                ]
                h_path = source_root / h_relative
                h_path.parent.mkdir(parents=True, mode=0o700)
                h_raw = b"scope-test-only selected H source bytes"
                h_path.write_bytes(h_raw)
                h_path.chmod(0o600)
                h_sha = c.sha256_bytes(h_raw)
                h_module = types.ModuleType("sourcea_c2r2_scope_test_h_module")
                h_module.__file__ = str(h_path)
                session.prepared.update({
                    "source_root": source_root,
                    "source": {"source": {"files": [{
                        "path": h_relative, "sha256": h_sha,
                    }]}},
                })
                session.source_module_pins[f.consumer][h_relative] = {
                    "path": h_relative, "sha256": h_sha,
                }
                session.modules = {"archive": self.archive, "source5_campaign": h_module}
                h_context = {
                    "scope_test_only": True,
                    "nonce": "not-an-owner-replay",
                }
                session.h_client = types.SimpleNamespace(
                    session=h_context, plan_module=fixture_module.read_plan,
                )
                c._source5_owned_registration_build_plan(
                    session, copy.deepcopy(basis["current_roots"]),
                    f.catalogues, f.readback_caps, f.windows, f.scratch, f.timeouts,
                )
                with (
                    patch.object(c, "_check_lock"),
                    patch.object(c, "_source5_owned_scope_binding_value",
                                 return_value=entry["binding"]),
                ):
                    c._source5_owned_scope_bind_plan(scope, session)
                    c._source5_owned_scope_bind_h_client(scope, session)
                    c._source5_owned_scope_require(scope, session)
                    original_plan = session.plan
                    session.plan = copy.deepcopy(original_plan)
                    with self.assertRaisesRegex(c.ChronologyError,
                                                "changed its fresh H3 plan identity"):
                        c._source5_owned_scope_require(scope, session)
                    session.plan = original_plan
                    h_context["scope_test_only"] = False
                    with self.assertRaisesRegex(c.ChronologyError,
                                                "changed its actual H client/context/module identity"):
                        c._source5_owned_scope_require(scope, session)
        finally:
            try:
                if scope_bundle is not None:
                    self._remove_test_scope(scope, session, entry, operation_lock)
            finally:
                _sourcea_h6_plan_fixture_release()

    def test_old_owner_binding_rejects_test_only_postbind_replacement_and_mutation(self) -> None:
        c = self.chronology
        scope, session, entry, operation_lock = self._install_test_scope()
        hosts = ["host-a", "host-b"]
        authorities = {}
        numeric = {
            "schema": c._SOURCE5_RECORDED_NUMERIC_CONTEXT_SCHEMA,
            "hosts": hosts,
            "selected_fixed_module_sha256": "a" * 64,
            "artifact_reader_identity": "test-only-incomplete-context",
            "component_replay_required": True,
            "qualification_eligible": False,
            "lineage_proofs": {}, "archived_authorities": {},
            "rows_by_host": {host: [{"test_only_row": 0}] for host in hosts},
        }
        session.archived_authorities = authorities
        session.numeric_context = numeric
        entry["old_owner_binding"] = {
            "authorities": authorities, "numeric_context": numeric,
            "authorities_id": id(authorities),
            "authorities_sha256": c._source5_owned_scope_digest(
                authorities, "test-only incomplete authority data",
            ),
            "numeric_context_id": id(numeric),
            "numeric_binding": c._source5_owned_scope_numeric_binding(session),
            "hosts": tuple(hosts),
        }
        try:
            with (
                patch.object(c, "_check_lock"),
                patch.object(c, "_source5_owned_scope_binding_value",
                             return_value=entry["binding"]),
            ):
                c._source5_owned_scope_require(scope, session)
                original = session.numeric_context
                session.numeric_context = copy.deepcopy(original)
                with self.assertRaisesRegex(c.ChronologyError,
                                            "changed its exact old replay ledger"):
                    c._source5_owned_scope_require(scope, session)
                session.numeric_context = original
                original["rows_by_host"][hosts[0]].append({"test_only_row": 1})
                with self.assertRaisesRegex(c.ChronologyError,
                                            "changed its exact old replay ledger"):
                    c._source5_owned_scope_require(scope, session)
        finally:
            self._remove_test_scope(scope, session, entry, operation_lock)

    def test_scope_sink_set_is_bound_to_its_fixed_route(self) -> None:
        c = self.chronology
        scope, session, entry, operation_lock = self._install_test_scope()
        try:
            with (
                patch.object(c, "_check_lock"),
                patch.object(c, "_source5_owned_scope_binding_value",
                             return_value=entry["binding"]),
            ):
                c._source5_owned_scope_require(scope, session)
                entry["allowed_sinks"] = frozenset()
                with self.assertRaisesRegex(c.ChronologyError, "sink set or frontier"):
                    c._source5_owned_scope_require(scope, session)
        finally:
            self._remove_test_scope(scope, session, entry, operation_lock)

    def test_scope_cleanup_continues_after_reader_close_error(self) -> None:
        c = self.chronology
        scope, session, entry, operation_lock = self._install_test_scope()
        completed = []
        close_error = OSError("test bootstrap close failure")

        def failing_bootstrap_close():
            completed.append("bootstrap")
            raise close_error

        def failing_capture_close():
            completed.append("capture")
            raise ValueError("test capture close failure")

        def failing_h_plan_module_close():
            completed.append("h_plan_module")
            raise RuntimeError("test H plan module close failure")

        try:
            error = c._source5_run_cleanups_independently([
                lambda: c._source5_owned_scope_expire(scope, session, entry),
                failing_bootstrap_close,
                failing_capture_close,
                failing_h_plan_module_close,
                lambda: completed.append("prepared"),
            ])
            self.assertIs(error, close_error)
            self.assertEqual(completed,
                             ["bootstrap", "capture", "h_plan_module", "prepared"])
            self.assertNotIn(scope, c._SOURCE5_OWNED_OPERATION_SCOPES)
            self.assertIsNone(session.operation_scope)
        finally:
            self._remove_test_scope(scope, session, entry, operation_lock)

    def test_prepared_module_cleanup_attempts_all_unique_modules_and_other_actions(self) -> None:
        c = self.chronology
        scope, session, entry, operation_lock = self._install_test_scope()
        proof = c._Source5PreparedRegistrationProof(
            c._SOURCE5_PREPARED_REGISTRATION_PROOF_SECRET,
        )
        with c._SOURCE5_PREPARED_REGISTRATION_PROOF_LOCK:
            c._SOURCE5_PREPARED_REGISTRATION_PROOFS[proof] = {
                "creator_pid": os.getpid(),
            }
        modules = [
            types.ModuleType(f"sourcea_c2r3_cleanup_{index}_{os.getpid()}")
            for index in range(3)
        ]
        for module in modules:
            c.sys.modules[module.__name__] = module
        prepared = {
            "stage": modules[0], "controller": modules[1],
            "prepared": {"stack": {
                "first": modules[0], "later": modules[2],
            }},
        }
        attempted = []
        first_error = OSError("first prepared module close failed")
        later_error = RuntimeError("later prepared module close also failed")
        original_close = c._close_module

        def close_module(module):
            attempted.append(module)
            if module is modules[0]:
                raise first_error
            if module is modules[1]:
                raise later_error
            original_close(module)

        class Reader:
            def __init__(self) -> None:
                self.close_count = 0

            def close(self) -> None:
                self.close_count += 1

        bootstrap_reader = Reader()
        capture_reader = Reader()
        role_cleanup = []
        try:
            with patch.object(c, "_close_module", side_effect=close_module):
                cleanup_error = c._source5_run_cleanups_independently([
                    lambda: c._source5_owned_scope_expire(scope, session, entry),
                    lambda: c._source5_discard_prepared_registration_proof(proof),
                    bootstrap_reader.close,
                    capture_reader.close,
                    lambda: role_cleanup.append("role-data-cleared"),
                    lambda: c._source5_construction_close_prepared(prepared),
                ])
            self.assertIs(cleanup_error, first_error)
            self.assertEqual([id(module) for module in attempted],
                             [id(module) for module in modules])
            self.assertEqual(len({id(module) for module in attempted}), len(modules))
            self.assertEqual(bootstrap_reader.close_count, 1)
            self.assertEqual(capture_reader.close_count, 1)
            self.assertEqual(role_cleanup, ["role-data-cleared"])
            self.assertNotIn(scope, c._SOURCE5_OWNED_OPERATION_SCOPES)
            self.assertIsNone(session.operation_scope)
            self.assertNotIn(proof, c._SOURCE5_PREPARED_REGISTRATION_PROOFS)
            self.assertIs(c.sys.modules.get(modules[0].__name__), modules[0])
            self.assertIs(c.sys.modules.get(modules[1].__name__), modules[1])
            self.assertNotIn(modules[2].__name__, c.sys.modules)
        finally:
            self._remove_test_scope(scope, session, entry, operation_lock)
            with c._SOURCE5_PREPARED_REGISTRATION_PROOF_LOCK:
                c._SOURCE5_PREPARED_REGISTRATION_PROOFS.pop(proof, None)
            for module in modules:
                if c.sys.modules.get(module.__name__) is module:
                    c.sys.modules.pop(module.__name__, None)

    def test_held_empty_journal_recheck_rejects_last_callback_append_before_own_bytes(self) -> None:
        c = self.chronology
        with tempfile.TemporaryDirectory(prefix="sourcea-c2r2-late-journal-") as temporary:
            root = Path(temporary)
            path = root / "dispatch-journal.jsonl"
            path.write_bytes(b"")
            path.chmod(0o600)
            fd = os.open(path, os.O_RDWR | os.O_APPEND)
            lock = types.SimpleNamespace(
                _creator_pid=os.getpid(), directory=root,
                output_root=root, campaign_id="late-journal", host_id="host-a",
            )
            prepared = {
                "output_root": root, "campaign_id": "late-journal", "host_id": "host-a",
            }
            session = types.SimpleNamespace(
                lock=lock, prepared=prepared,
                frontier={"head_sha256": "0" * 64, "record_count": 0},
                journal_file_key=(
                    os.fstat(fd).st_dev, os.fstat(fd).st_ino, os.fstat(fd).st_mode,
                    os.fstat(fd).st_size, os.fstat(fd).st_mtime_ns,
                    os.fstat(fd).st_ctime_ns,
                ),
            )
            expected = session.journal_file_key
            state = {
                "head": "0" * 64, "record_count": 0,
                "registration_head": None, "prepared_capacity_registration": None,
                "file_stat": expected,
            }
            entry = {
                "frontier": {"head_sha256": "0" * 64, "record_count": 0},
                "journal_file_key": expected,
            }
            initial = os.fstat(fd)
            append_attempts = []
            try:
                # Simulate the last cancellation/H callback mutating the journal.
                os.write(fd, b"late-callback-append")
                os.fsync(fd)
                with patch.object(c, "_check_lock"):
                    try:
                        c._source5_prepared_registration_recheck_empty_frontier_held(
                            lock, prepared, session, entry, state, fd, path,
                            initial, False,
                        )
                    except c.ChronologyError as error:
                        self.assertRegex(str(error),
                                         "path/stat changed after its final callback")
                    else:
                        append_attempts.append(os.write(fd, b"own-record"))
                self.assertEqual(append_attempts, [])
                self.assertEqual(os.pread(fd, 128, 0), b"late-callback-append")
            finally:
                os.close(fd)

    def test_deadline_after_final_callback_free_scan_prevents_scope_consume(self) -> None:
        c = self.chronology
        with tempfile.TemporaryDirectory(prefix="sourcea-c2r2-final-deadline-") as temporary:
            path = Path(temporary) / "dispatch-journal.jsonl"
            path.write_bytes(b"")
            path.chmod(0o600)
            fd = os.open(path, os.O_RDWR | os.O_APPEND)
            try:
                info = os.fstat(fd)
                session = types.SimpleNamespace(deadline_ns=100)
                events = []
                append_attempts = []
                def scan(*_args):
                    events.append("input-scan")
                def scope_scan(*_args):
                    events.append("scope-scan")
                def journal_scan(*_args):
                    events.append("journal-scan")
                    return info
                def clock_after_scan():
                    events.append("direct-clock")
                    return 101
                def consume(*_args):
                    events.append("consume")
                with (
                    patch.object(c, "_source5_prepared_registration_recheck_inputs_callback_free",
                                 side_effect=scan),
                    patch.object(c, "_source5_owned_scope_recheck_callback_free",
                                 side_effect=scope_scan),
                    patch.object(c, "_source5_prepared_registration_recheck_empty_frontier_held",
                                 side_effect=journal_scan),
                    patch.object(c.time, "monotonic_ns", side_effect=clock_after_scan),
                    patch.object(c, "_source5_owned_scope_consume_sink",
                                 side_effect=consume),
                ):
                    try:
                        c._source5_prepared_registration_finalize_consume(
                            object(), {}, session, object(), {}, {}, info,
                            1, False, fd, path,
                        )
                    except c.ChronologyError as error:
                        self.assertRegex(str(error), "expired immediately before proof consumption")
                    else:
                        append_attempts.append("own-write")
                self.assertEqual(events,
                                 ["input-scan", "scope-scan", "journal-scan", "direct-clock"])
                self.assertEqual(append_attempts, [])
            finally:
                os.close(fd)

    def test_fork_child_fails_before_mutex_and_close_preserves_parent_flock(self) -> None:
        c = self.chronology
        with tempfile.TemporaryDirectory(prefix="sourcea-c2r2-fork-") as temporary:
            root = Path(temporary) / "output"
            root.mkdir(mode=0o700)
            with c.campaign_host_lock(root, "fork-campaign", "host-a",
                                      timeout_seconds=2) as lock:
                # These registry sentinels contain no session, owner, GPG, or sink evidence.
                scope = c._Source5OwnedOperationScope(
                    c._SOURCE5_OWNED_OPERATION_SCOPE_SECRET,
                )
                proof = c._Source5PreparedRegistrationProof(
                    c._SOURCE5_PREPARED_REGISTRATION_PROOF_SECRET,
                )
                with c._SOURCE5_OWNED_OPERATION_SCOPE_LOCK:
                    c._SOURCE5_OWNED_OPERATION_SCOPES[scope] = {
                        "scope": scope, "creator_pid": os.getpid(), "lock": lock,
                    }
                with c._SOURCE5_PREPARED_REGISTRATION_PROOF_LOCK:
                    c._SOURCE5_PREPARED_REGISTRATION_PROOFS[proof] = {
                        "creator_pid": os.getpid(), "lock": lock,
                    }
                self.assertTrue(lock._operation_lock.acquire(blocking=False))
                read_fd = write_fd = -1
                child_pid = None
                reaped = False
                try:
                    read_fd, write_fd = os.pipe()
                    child_pid = os.fork()
                    if child_pid == 0:
                        os.close(read_fd)
                        result = b"unexpected"
                        try:
                            c.register_source5_prepared_exploration_owned_locked(lock)
                        except c.ChronologyError:
                            result = b"rejected"
                        except BaseException:
                            result = b"wrong-error"
                        try:
                            lock.__exit__(None, None, None)
                        except BaseException:
                            result = b"close-error"
                        copied_entries_cleared = (
                            scope not in c._SOURCE5_OWNED_OPERATION_SCOPES and
                            proof not in c._SOURCE5_PREPARED_REGISTRATION_PROOFS
                        )
                        if result == b"rejected" and copied_entries_cleared:
                            result = b"rejected-cleared"
                        elif not copied_entries_cleared:
                            result = b"not-cleared"
                        try:
                            os.write(write_fd, result)
                        except OSError:
                            pass
                        os._exit(0)
                    os.close(write_fd)
                    write_fd = -1
                    deadline = time.monotonic() + 5.0
                    child_status = None
                    while time.monotonic() < deadline:
                        waited, status = os.waitpid(child_pid, os.WNOHANG)
                        if waited == child_pid:
                            child_status = status
                            reaped = True
                            break
                        time.sleep(0.01)
                    if child_status is None:
                        os.kill(child_pid, signal.SIGKILL)
                        os.waitpid(child_pid, 0)
                        reaped = True
                        self.fail("forked child blocked on the inherited operation mutex")
                    result = os.read(read_fd, 64)
                    os.close(read_fd)
                    read_fd = -1
                    self.assertTrue(os.WIFEXITED(child_status))
                    self.assertEqual(result, b"rejected-cleared")
                    with c._SOURCE5_OWNED_OPERATION_SCOPE_LOCK:
                        self.assertIn(scope, c._SOURCE5_OWNED_OPERATION_SCOPES)
                    with c._SOURCE5_PREPARED_REGISTRATION_PROOF_LOCK:
                        self.assertIn(proof, c._SOURCE5_PREPARED_REGISTRATION_PROOFS)
                    self.assertGreaterEqual(lock.fd, 0)
                    self.assertTrue(c._lock_token_is_live(lock))
                    self.assertTrue(lock._operation_lock.locked())
                    lock._operation_lock.release()
                    probe = os.open(
                        lock.lock_path, os.O_RDWR | getattr(os, "O_CLOEXEC", 0),
                    )
                    try:
                        try:
                            c.fcntl.flock(probe, c.fcntl.LOCK_EX | c.fcntl.LOCK_NB)
                        except BlockingIOError:
                            parent_flock_retained = True
                        else:
                            parent_flock_retained = False
                            c.fcntl.flock(probe, c.fcntl.LOCK_UN)
                    finally:
                        os.close(probe)
                    self.assertTrue(parent_flock_retained)
                finally:
                    if child_pid is not None and not reaped:
                        try:
                            os.kill(child_pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        try:
                            os.waitpid(child_pid, 0)
                        except ChildProcessError:
                            pass
                    for descriptor in (read_fd, write_fd):
                        if descriptor >= 0:
                            os.close(descriptor)
                    if lock._operation_lock.locked():
                        lock._operation_lock.release()
                    with c._SOURCE5_OWNED_OPERATION_SCOPE_LOCK:
                        c._SOURCE5_OWNED_OPERATION_SCOPES.pop(scope, None)
                    with c._SOURCE5_PREPARED_REGISTRATION_PROOF_LOCK:
                        c._SOURCE5_PREPARED_REGISTRATION_PROOFS.pop(proof, None)

    def test_scope_token_cannot_be_forged_or_copied(self) -> None:
        c = self.chronology
        with self.assertRaisesRegex(c.ChronologyError, "must be issued by its creating module"):
            c._Source5OwnedOperationScope()
        with self.assertRaisesRegex(c.ChronologyError, "foreign exact type"):
            c._source5_owned_scope_entry(object())

    def test_structural_context_cannot_start_a_live_scope(self) -> None:
        c = self.chronology
        with self.assertRaisesRegex(c.ChronologyError, "one live lock with exact current inputs"):
            with c._source5_owned_operation_scope_held(object()):
                self.fail("a structural DTO must never open an operation scope")

    def test_public_registration_has_no_route_or_scope_selector(self) -> None:
        c = self.chronology
        parameters = inspect.signature(
            c.register_source5_prepared_exploration_owned_locked,
        ).parameters
        self.assertNotIn("route", parameters)
        self.assertNotIn("scope", parameters)
        self.assertNotIn("allowed_sinks", parameters)
        self.assertEqual(
            c._SOURCE5_OWNED_OPERATION_ROUTE_SINKS[
                c._Source5OwnedReplayRoute.SEALED_REFRESH
            ], frozenset(),
        )

    def test_only_fixed_registration_sink_exists_in_c2_route_policy(self) -> None:
        c = self.chronology
        self.assertEqual(
            c._SOURCE5_OWNED_OPERATION_ROUTE_SINKS[
                c._Source5OwnedReplayRoute.REGISTRATION
            ],
            frozenset({c._Source5OwnedOperationSink.PREPARED_CAPACITY_REGISTRATION}),
        )
        self.assertEqual(len(c._SOURCE5_OWNED_OPERATION_SCOPES), 0)


class Source5Root45PlanAdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.chronology = load_script(
            SCRIPT_DIR / "application-campaign-chronology.py",
            "source5_root45_plan_admission_target",
        )
        cls.planner = load_script(
            SCRIPT_DIR / "application-source5-recorded-preparation-read.py",
            "source5_root45_selected_planner",
        )
        cls.archive = load_script(
            SCRIPT_DIR / "application-source5-evidence-archive.py",
            "source5_root45_selected_archive",
        )
        cls.source = (SCRIPT_DIR / "application-campaign-chronology.py").read_text()
        cls.tree = ast.parse(cls.source, filename=str(SCRIPT_DIR / "application-campaign-chronology.py"))
        cls.functions = {
            node.name: node for node in cls.tree.body
            if isinstance(node, ast.FunctionDef)
        }

    def _actual_chunker_fixture(self):
        planner = self.planner
        hosts = ["root-host-a", "root-host-b"]
        rows = [{
            "read_ordinal": ordinal,
            "owner_host_id": hosts[ordinal // planner.READ_JOB_COUNT_PER_HOST],
            "job_index": ordinal % planner.READ_JOB_COUNT_PER_HOST,
            "job_sha256": "a" * 64,
        } for ordinal in range(planner.READ_WINDOW_COUNT)]
        basis_pin = {
            "path": "/private/root45/basis.json",
            "raw_sha256": "b" * 64,
            "semantic_sha256": "c" * 64,
        }
        window_index, refs, chunks = planner._make_window_metadata_chunks(
            rows, basis_pin, "root45-campaign", hosts[0], hosts,
            "registration_replay", "d" * 32, "/private/root45/window-metadata",
        )
        plan = {
            "cohort_hosts": hosts,
            "window_index": window_index,
            "window_chunks": refs,
        }
        session = types.SimpleNamespace(
            plan_module=planner,
            modules={"archive": self.archive},
        )
        return session, plan, chunks

    def _require_plan_admission(self, session, plan, chunks):
        return self.chronology._source5_require_root_inline_plan_admission_held(
            session, plan, chunks,
        )

    def test_actual_global_chunker_accepts_exact45_with_cross_host_chunk22(self) -> None:
        session, plan, chunks = self._actual_chunker_fixture()
        self.assertEqual(len(plan["window_index"]), 720)
        self.assertEqual(len(plan["window_chunks"]), 45)
        self.assertTrue(all(ref["window_count"] == 16
                            for ref in plan["window_chunks"]))
        middle = chunks[22]
        self.assertEqual(middle["first_read_ordinal"], 352)
        self.assertEqual(middle["read_ordinals"], list(range(352, 368)))
        self.assertEqual(
            [row["owner_host_id"] for row in middle["rows"]],
            ["root-host-a"] * 8 + ["root-host-b"] * 8,
        )
        self.assertIsNone(self._require_plan_admission(session, plan, chunks))

    def test_root45_admission_rejects_46_underfilled_missing_and_reordered(self) -> None:
        cases = ("46", "underfilled", "missing", "reordered")
        for case in cases:
            session, plan, chunks = self._actual_chunker_fixture()
            if case == "46":
                plan["window_chunks"].append(copy.deepcopy(plan["window_chunks"][-1]))
                chunks.append(copy.deepcopy(chunks[-1]))
            elif case == "underfilled":
                plan["window_chunks"][22]["window_count"] = 15
                plan["window_chunks"][22]["read_ordinals"] = list(range(352, 367))
                chunks[22]["read_ordinals"] = list(range(352, 367))
                chunks[22]["rows"] = chunks[22]["rows"][:15]
            elif case == "missing":
                plan["window_chunks"].pop()
                chunks.pop()
            else:
                plan["window_chunks"][0], plan["window_chunks"][1] = (
                    plan["window_chunks"][1], plan["window_chunks"][0],
                )
                chunks[0], chunks[1] = chunks[1], chunks[0]
            with self.subTest(case=case):
                with self.assertRaises(self.chronology.ChronologyError):
                    self._require_plan_admission(session, plan, chunks)

    def test_selected_archive_rejects_raw_hash_and_exact_byte_count_mismatch(self) -> None:
        for mutation in ("raw_hash", "byte_count"):
            session, plan, chunks = self._actual_chunker_fixture()
            if mutation == "raw_hash":
                plan["window_chunks"][0]["pin"]["raw_sha256"] = "f" * 64
            else:
                plan["window_chunks"][0]["byte_count"] += 1
            with self.subTest(mutation=mutation):
                with self.assertRaisesRegex(
                        self.chronology.ChronologyError,
                        "Source-selected Archive rejected"):
                    self._require_plan_admission(session, plan, chunks)

    def test_both_owned_builders_admit_after_validation_before_plan_or_h_publication(self) -> None:
        def calls(node, name):
            return [item for item in ast.walk(node)
                    if isinstance(item, ast.Call) and (
                        isinstance(item.func, ast.Name) and item.func.id == name or
                        isinstance(item.func, ast.Attribute) and item.func.attr == name
                    )]

        cases = (
            ("_source5_construction_build_plan",
             "validate_prepared_input_construction_read_plan_v1",
             "construct_source5_prepared_inputs_locked",
             "_source5_construction_build_plan",
             "source5_prepared_input_construction_read_client_v1"),
            ("_source5_owned_registration_build_plan",
             "validate_recorded_preparation_read_plan_v2",
             "_source5_owned_input_generation_replay_held",
             "_source5_owned_registration_build_plan",
             "source5_recorded_preparation_read_client_v1"),
        )
        for (builder_name, validator_name, outer_name, build_call_name,
             h_factory_name) in cases:
            with self.subTest(builder=builder_name):
                builder = self.functions[builder_name]
                validator_calls = calls(builder, validator_name)
                admission_calls = calls(
                    builder, "_source5_require_root_inline_plan_admission_held",
                )
                self.assertEqual(len(validator_calls), 1)
                self.assertEqual(len(admission_calls), 1)
                self.assertLess(validator_calls[0].lineno, admission_calls[0].lineno)
                admission_statements = [
                    (index, statement) for index, statement in enumerate(builder.body)
                    if isinstance(statement, ast.Expr) and
                    isinstance(statement.value, ast.Call) and
                    isinstance(statement.value.func, ast.Name) and
                    statement.value.func.id ==
                        "_source5_require_root_inline_plan_admission_held"
                ]
                self.assertEqual(len(admission_statements), 1)
                admission_index, _admission_statement = admission_statements[0]
                self.assertGreater(admission_index, 0)
                preceding = builder.body[admission_index - 1]
                self.assertIsInstance(preceding, ast.Expr)
                self.assertIsInstance(preceding.value, ast.Call)
                self.assertIsInstance(preceding.value.func, ast.Name)
                self.assertEqual(preceding.value.func.id, "require")
                self.assertIn("checked_plan", ast.unparse(preceding.value))
                plan_stores = [
                    node for node in ast.walk(builder)
                    if isinstance(node, ast.Assign) and
                    any(isinstance(target, ast.Attribute) and
                        isinstance(target.value, ast.Name) and
                        target.value.id == "session" and target.attr in {"plan", "chunks"}
                        for target in node.targets)
                ]
                self.assertTrue(plan_stores)
                self.assertLess(admission_calls[0].lineno,
                                min(node.lineno for node in plan_stores))
                outer = self.functions[outer_name]
                plan_build = calls(outer, build_call_name)
                self.assertEqual(len(plan_build), 1)
                h_factory_assignments = [
                    node for node in ast.walk(outer)
                    if isinstance(node, ast.Assign) and
                    any(isinstance(target, ast.Name) and target.id == "h_factory"
                        for target in node.targets) and
                    isinstance(node.value, ast.Call) and
                    isinstance(node.value.func, ast.Name) and
                    node.value.func.id == "getattr" and len(node.value.args) >= 2 and
                    isinstance(node.value.args[1], ast.Constant) and
                    node.value.args[1].value == h_factory_name
                ]
                h_calls = [
                    node for node in ast.walk(outer)
                    if isinstance(node, ast.Call) and
                    isinstance(node.func, ast.Name) and node.func.id == "h_factory"
                ]
                self.assertEqual(len(h_factory_assignments), 1)
                self.assertEqual(len(h_calls), 1)
                self.assertLess(plan_build[0].lineno,
                                h_factory_assignments[0].lineno)
                self.assertLess(h_factory_assignments[0].lineno,
                                h_calls[0].lineno)
        helper = self.functions["_source5_require_root_inline_plan_admission_held"]

        def assigned_value(name):
            matches = [
                node for node in ast.walk(helper)
                if isinstance(node, ast.Assign) and len(node.targets) == 1 and
                isinstance(node.targets[0], ast.Name) and node.targets[0].id == name
            ]
            self.assertEqual(len(matches), 1, f"expected one {name} binding in admission helper")
            return matches[0].value

        modules_value = assigned_value("modules")
        self.assertIsInstance(modules_value, ast.Call)
        self.assertIsInstance(modules_value.func, ast.Name)
        self.assertEqual(modules_value.func.id, "getattr")
        self.assertEqual(len(modules_value.args), 3)
        self.assertIsInstance(modules_value.args[0], ast.Name)
        self.assertEqual(modules_value.args[0].id, "session")
        self.assertEqual(modules_value.args[1].value, "modules")
        self.assertIsNone(modules_value.args[2].value)

        archive_value = assigned_value("archive")
        self.assertIsInstance(archive_value, ast.Subscript)
        self.assertIsInstance(archive_value.value, ast.Name)
        self.assertEqual(archive_value.value.id, "modules")
        self.assertEqual(archive_value.slice.value, "archive")

        validator_value = assigned_value("validate_inline_chunks")
        self.assertIsInstance(validator_value, ast.Call)
        self.assertIsInstance(validator_value.func, ast.Name)
        self.assertEqual(validator_value.func.id, "getattr")
        self.assertIsInstance(validator_value.args[0], ast.Name)
        self.assertEqual(validator_value.args[0].id, "archive")
        self.assertEqual(validator_value.args[1].value,
                         "_validate_root_inline_window_chunk_sequence")
        validator_calls = calls(helper, "validate_inline_chunks")
        self.assertEqual(len(validator_calls), 1)
        self.assertEqual(len(validator_calls[0].args), 2)
        self.assertEqual([arg.id for arg in validator_calls[0].args],
                         ["plan", "chunk_raws"])
        self.assertFalse(validator_calls[0].keywords)
        self.assertFalse(any(
            isinstance(node, ast.Call) and
            ((isinstance(node.func, ast.Name) and node.func.id == "load_script") or
             (isinstance(node.func, ast.Attribute) and node.func.attr == "load_script"))
            for node in ast.walk(helper)
        ))


if __name__ == "__main__":
    raise SystemExit(unittest.main())
