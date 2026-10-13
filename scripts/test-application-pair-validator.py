#!/usr/bin/env python3
"""Focused remote tests for the Python validators embedded in the pair runner."""

from __future__ import annotations

import hashlib
import importlib.util
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "run-application-pair.sh"
SOURCE_INVENTORY = ROOT / "scripts" / "application-source-inventory.py"
FUNCTIONAL_HELPER = ROOT / "scripts" / "test-application-pair-functional-e2e.py"
CAMPAIGN = ROOT / "scripts" / "application-campaign.py"


def embedded_validator(name: str) -> str:
    source = RUNNER.read_text(encoding="utf-8")
    start = source.index(f"{name}() {{")
    # A Python dictionary may end with a bare brace too. Locate the shell
    # function's closing brace after its heredoc terminator instead.
    end = source.index("\nPY\n}", start) + len("\nPY")
    match = re.search(r"<<'PY'\n(.*?)\nPY", source[start:end], flags=re.DOTALL)
    if match is None:
        raise AssertionError(f"could not extract {name} Python validator")
    return match.group(1)


def runner_header() -> list[str]:
    source = RUNNER.read_text(encoding="utf-8")
    match = re.search(r"local expected_header='(.*?)'\n", source, flags=re.DOTALL)
    if match is None:
        raise AssertionError("could not extract the 53-column result header")
    return match.group(1).split("\t")


def runner_process_header() -> list[str]:
    source = RUNNER.read_text(encoding="utf-8")
    match = re.search(r"^printf 'pair\\t(.*?)\\n' > \"\$cell_dir/processes.tsv\"$", source, flags=re.MULTILINE)
    if match is None:
        raise AssertionError("could not extract the per-process readback ledger header")
    return ["pair", *match.group(1).split(r"\t")]


class ApplicationPairValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="app-pair-validator-")
        self.directory = Path(self.temp.name)
        self.oracle = self.directory / "oracle.tsv"
        self.ids = self.directory / "result.ids.tsv"
        self.output = self.directory / "result.tsv"
        self.non_executable_binary = self.directory / "non-executable-binary"
        self.non_executable_binary.write_bytes(b"not an executable")
        self.non_executable_binary.chmod(0o600)
        self.nonce = "a" * 32
        self.run_id = "validator-1"
        self.source_hash = "b" * 64
        self.binary_hash = "c" * 64
        self.oracle_values = [101, 202]
        self.oracle.write_text(
            "schema\tallocatbelt-app-oracle-v2\n"
            f"source_sha256\t{self.source_hash}\n"
            f"binary_sha256\t{self.binary_hash}\n"
            "profile\tsteady\n"
            "workload\thttp\n"
            "mode\topen_loop\n"
            "average_rate_per_second\t2\n"
            "pulse_rate_per_second\t2\n"
            "arrivals\t2\n"
            "trace_duration_ns\t1000000000\n"
            "kernel_config\tbody_bytes=4096\n"
            "id\tscheduled_ns\tworkload\texpected_checksum\n"
            "0\t0\thttp\t101\n"
            "1\t500000000\thttp\t202\n",
            encoding="utf-8",
        )
        self.oracle_digest = hashlib.sha256(self.oracle.read_bytes()).hexdigest()
        self.write_ids([(0, "http", 0, 800_000_000, "completed", 101, 101), (1, "http", 500_000_000, 500_000_200, "completed", 202, 202)])
        self.write_output()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_pair_source_identity_uses_the_pinned_shared_typed_inventory(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")
        functional = FUNCTIONAL_HELPER.read_text(encoding="utf-8")
        campaign = CAMPAIGN.read_text(encoding="utf-8")
        expected_hash = re.search(r"^source_inventory_module_sha256_expected=([0-9a-f]{64})$", runner, re.MULTILINE)
        helper_hash = re.search(r'^SOURCE_INVENTORY_MODULE_SHA256 = "([0-9a-f]{64})"$', functional, re.MULTILINE)
        campaign_hash = re.search(r'^SOURCE_INVENTORY_MODULE_SHA256 = "([0-9a-f]{64})"$', campaign, re.MULTILINE)
        self.assertIsNotNone(expected_hash, "pair runner must pin the shared source inventory implementation")
        self.assertIsNotNone(helper_hash, "functional E2E must pin the shared source inventory implementation")
        self.assertIsNotNone(campaign_hash, "campaign controller must pin the shared source inventory implementation")
        actual_hash = hashlib.sha256(SOURCE_INVENTORY.read_bytes()).hexdigest()
        self.assertEqual(expected_hash.group(1), actual_hash)
        self.assertEqual(helper_hash.group(1), actual_hash)
        self.assertEqual(campaign_hash.group(1), actual_hash)
        self.assertIn(
            'python3 - "$source_inventory_module_path" "$source_inventory_module_sha256_expected" "$repo_root" <<\'PY\'',
            runner,
        )
        self.assertIn("module.source_tree_digest(root)", runner)
        self.assertIn('module._checked_capture(["git", "rev-parse", "HEAD"]', runner)
        self.assertLess(
            runner.index('hashlib.sha256(raw).hexdigest() != expected_sha256'),
            runner.index('exec(compile(raw, path, "exec", dont_inherit=True), module.__dict__)'),
        )
        self.assertIn("source_inventory_module_sha256_before", runner)
        self.assertIn("source_inventory_module_sha256_after", runner)
        self.assertIn('"schema": "allocatbelt.application-functional-source-overlay.v2"', functional)
        self.assertIn('"schema": "allocatbelt.application-functional-pair-overlay.v2"', functional)

    def test_shell_rejects_oversized_arrivals_and_non_numeric_deadlines_before_arithmetic(self) -> None:
        base = [str(RUNNER), "/missing/benchmark", "system", "cpu", "open_loop", "1", "0", "numeric-1", str(self.directory)]
        oversized = subprocess.run(
            [*base, "18446744073709551617"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(oversized.returncode, 2)
        self.assertIn("ARRIVALS must be", oversized.stderr)
        invalid_deadline = subprocess.run(
            [*base, "5000", "not-a-number"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(invalid_deadline.returncode, 2)
        self.assertIn("deadlines must be", invalid_deadline.stderr)

    def test_allocator_pair_cli_requires_distinct_frozen_baseline_inputs(self) -> None:
        base = [str(RUNNER), "/missing/candidate", "allocatbelt", "cpu", "capacity", "-", "0", "allocator-pair-1", str(self.directory), "5000", "300", "300", "60", "1200", "", "", "steady", "allocator-match"]
        missing_baseline = subprocess.run([*base, "", "mimalloc-secure"], check=False, capture_output=True, text=True)
        self.assertEqual(missing_baseline.returncode, 2)
        self.assertIn("distinct baseline binary", missing_baseline.stderr)
        with_baseline = [*base, "/missing/baseline", "mimalloc-secure", "", ""]
        still_missing_binary = subprocess.run(with_baseline, check=False, capture_output=True, text=True)
        self.assertEqual(still_missing_binary.returncode, 2)
        self.assertIn("hard-disabled", still_missing_binary.stderr)

    def test_external_pressure_pair_cli_is_hard_disabled_without_policy_readback(self) -> None:
        arguments = [
            str(RUNNER), "/missing/candidate", "allocatbelt", "cpu", "capacity", "-", "0",
            "pressure-pair-1", str(self.directory), "5000", "300", "300", "60", "1200", "", "",
            "steady", "pressure-matched",
        ]
        result = subprocess.run(arguments, check=False, capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("external-pressure timing is hard-disabled", result.stderr)

    def test_environment_cannot_enable_qualification_and_process_ledger_pins_readback_artifacts(self) -> None:
        arguments = [
            str(RUNNER), "/missing/candidate", "allocatbelt", "cpu", "capacity", "-", "0",
            "guard-pair-1", str(self.directory), "5000", "300", "300", "60", "1200", "", "",
            "steady", "matched",
        ]
        environment = os.environ.copy()
        environment["qualification_runtime_readback_supported"] = "1"
        environment["ALLOCATBELT_FUNCTIONAL_ONLY"] = "1"
        result = subprocess.run(arguments, check=False, capture_output=True, text=True, env=environment)
        self.assertEqual(result.returncode, 2)
        self.assertIn("qualification timing is hard-disabled", result.stderr)
        self.assertEqual(
            runner_process_header(),
            [
                "pair", "executor", "allocator", "exit_code", "row_validation", "p99_qualification", "argv",
                "stdout", "time_report", "ids_sha256", "shutdown_sha256", "capacity_family_sha256", "stdout_sha256",
                "runtime_readback", "runtime_readback_sha256", "runtime_expectation", "runtime_expectation_sha256",
                "runtime_validation", "runtime_validation_sha256", "runtime_recipe_sha256", "resource_ceiling_sha256",
                "policy_sha256", "fixed_global_control_baseline", "validator_sha256", "source_manifest_sha256",
                "calibration_binary_sha256", "calibration_output_sha256",
            ],
        )

    def test_functional_only_entry_supports_bounded_open_loop_and_exact_capacity_horizon(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn("qualification_runtime_readback_supported=0", source)
        self.assertIn("external_pressure_driver_supported=0", source)
        self.assertIn("execution_scope=qualification", source)
        self.assertIn("p99_qualification=functional_only", source)

        def invoke(*, mode: str, rate: str, arrivals: str, trace: str = "10", oracle: bool = True) -> subprocess.CompletedProcess[str]:
            args = [
                str(RUNNER), "--functional-only", str(self.non_executable_binary), "allocatbelt", "cpu", mode,
                rate, "0", "functional-1", str(self.directory), arrivals, trace, "10", "5", "240",
                str(self.oracle) if oracle else "", self.oracle_digest if oracle else "", "steady", "matched", "", "", "", "",
                "--runtime-bindings", str(self.directory / "bindings.json"),
                "--runtime-bindings-sha256", "a" * 64,
                "--runtime-validator", str(RUNNER.parent / "application-runtime-readback.py"),
                "--runtime-validator-sha256", "b" * 64,
                "--fixed-global-control-baseline", "2048",
                "--functional-overlay", str(self.directory / "functional-overlay.json"),
                "--functional-overlay-sha256", "c" * 64,
            ]
            return subprocess.run(args, check=False, capture_output=True, text=True)

        capacity = invoke(mode="capacity", rate="-", arrivals="5000", trace="30", oracle=False)
        self.assertEqual(capacity.returncode, 2)
        self.assertIn("binary is not executable", capacity.stderr)
        shortened_capacity = invoke(mode="capacity", rate="-", arrivals="5000", trace="29", oracle=False)
        self.assertEqual(shortened_capacity.returncode, 2)
        self.assertIn("capacity preserves the exact 30-second horizon", shortened_capacity.stderr)
        too_many = invoke(mode="open_loop", rate="100", arrivals="1001", trace="30")
        self.assertEqual(too_many.returncode, 2)
        self.assertIn("arrivals must be in 1..=1000", too_many.stderr)
        too_fast = invoke(mode="open_loop", rate="1001", arrivals="1")
        self.assertEqual(too_fast.returncode, 2)
        self.assertIn("rate must be in 1..=1000", too_fast.stderr)
        too_long = invoke(mode="open_loop", rate="1", arrivals="1", trace="31")
        self.assertEqual(too_long.returncode, 2)
        self.assertIn("deadlines exceed their fixed finite limits", too_long.stderr)

    def test_source_v4_functional_path_is_separate_and_finitely_stored(self) -> None:
        helper = FUNCTIONAL_HELPER.read_text(encoding="utf-8")
        runner = RUNNER.read_text(encoding="utf-8")
        self.assertIn('SIGNED_SOURCE_COMMIT = "9290a2b194a667aba8816020214230d111ab80a3"', helper)
        self.assertIn('SOURCE_MANIFEST_SCHEMA_V4 = "allocatbelt.application-source-manifest.v4"', helper)
        self.assertIn('parser.add_argument("--signer-fingerprint")', helper)
        self.assertIn('"signer_fingerprint": args.signer_fingerprint', helper)
        self.assertIn(
            '_CAMPAIGN.verify_source_manifest(authorized["manifest"], source_root, verify_artifacts=True)',
            helper,
        )
        self.assertIn('"capacity_horizon_seconds": 30', helper)
        self.assertIn('"max_file_bytes": 16 * 1024 * 1024', helper)
        self.assertIn('"max_output_bytes": 256 * 1024 * 1024', helper)
        self.assertIn('["filesystem_type"] not in ("tmpfs", "ramfs")', helper)
        self.assertIn('def authorize_source_v4_manifest(', helper)
        self.assertIn('verify_source_tree_before_controller_exec(source_root, source, commit)', helper)
        self.assertIn('"verify-commit", "--raw", commit', helper)
        self.assertIn('"[GNUPG:]", "VALIDSIG"', helper)
        self.assertIn('def run_capture_bounded(', helper)
        self.assertIn('watch_root=output_root', helper)
        self.assertIn('"ls-tree", "-z", source_head, "--", "scripts/application-campaign.py"', runner)
        self.assertIn('"cat-file", "blob", f"{source_head}:scripts/application-campaign.py"', runner)
        self.assertIn('campaign controller tracked mode differs from the verified signed commit', runner)
        self.assertIn('captured campaign controller differs from the blob at the verified signed commit', runner)
        self.assertIn('and (child.poll() is None or len(eof) != 2)', runner)
        self.assertIn('GIT_CONFIG_COUNT', runner)
        self.assertIn('verify_functional_v4_overlay()', runner)
        self.assertIn('functional_source_manifest_file_sha256_after', runner)
        self.assertIn('functional_file_size_limit_blocks=16384', runner)
        self.assertIn('ulimit -Hf "$functional_file_size_limit_blocks"', runner)
        self.assertIn('ulimit -Sf "$functional_file_size_limit_blocks"', runner)
        self.assertLess(
            runner.index('ulimit -Sf "$functional_file_size_limit_blocks"'),
            runner.index('ulimit -Hf "$functional_file_size_limit_blocks"'),
        )
        self.assertIn('max_output_directories', runner)
        self.assertIn('max_output_entries', runner)
        self.assertIn('minimum_free_bytes', runner)
        self.assertIn('O_NONBLOCK', runner)
        self.assertIn('stable_sha256', runner)
        self.assertIn('functional_source_v4_mode=0', runner)

    def test_gnu_timeout_foreground_keeps_term_ignoring_binary_in_controller_group(self) -> None:
        with tempfile.TemporaryDirectory(prefix="application-timeout-group-") as temporary:
            ready_path = Path(temporary) / "binary-ready"
            child_code = (
                "import os,signal,sys,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                "open(sys.argv[1], 'w').write(str(os.getpid())); time.sleep(30)"
            )
            timeout_process = subprocess.Popen(
                ["timeout", "--foreground", "--signal=TERM", "--kill-after=3s", "30s", sys.executable, "-c", child_code, str(ready_path)],
                start_new_session=True,
            )
            binary_pid = None
            try:
                for _ in range(200):
                    if ready_path.exists():
                        break
                    time.sleep(0.01)
                self.assertTrue(ready_path.exists(), "timed binary did not install its TERM-ignoring handler")
                binary_pid = int(ready_path.read_text(encoding="ascii"))
                os.killpg(timeout_process.pid, signal.SIGTERM)
                time.sleep(0.1)
                os.killpg(timeout_process.pid, signal.SIGKILL)
                timeout_process.wait(timeout=2)
                for _ in range(100):
                    try:
                        state = Path(f"/proc/{binary_pid}/stat").read_text(encoding="ascii").split()[2]
                    except FileNotFoundError:
                        break
                    if state == "Z":
                        break
                    time.sleep(0.01)
                else:
                    self.fail("timed benchmark binary escaped the controller process group")
            finally:
                try:
                    os.killpg(timeout_process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                if timeout_process.poll() is None:
                    timeout_process.wait(timeout=2)
                if binary_pid is not None:
                    try:
                        os.kill(binary_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def write_ids(self, records: list[tuple[int, str, int, int, str, int, int]], nonce: str | None = None) -> None:
        identity = (
            f"identity\t{nonce or self.nonce}\t{self.run_id}\tallocatbelt\tsystem\thttp\tsteady\t"
            f"{self.source_hash}\t{self.binary_hash}\n"
        )
        lines = [
            "schema\tallocatbelt-app-arrivals-v3\n",
            identity,
            "id\tworkload\tscheduled_ns\tcompletion_ns\tterminal\tchecksum\texpected_checksum\n",
        ]
        lines.extend("\t".join(map(str, record)) + "\n" for record in records)
        self.ids.write_text("".join(lines), encoding="utf-8")

    def write_output(self, digest: int = 303, expected_digest: int = 303) -> None:
        header = runner_header()
        row = {column: "0" for column in header}
        row.update(
            schema="http-nonblocking-connect-v1",
            allocator="system",
            executor="allocatbelt",
            workload="http",
            mode="open_loop",
            arrival_rate_per_second="2",
            requested_arrivals="2",
            attempted="2",
            admitted="2",
            completed_on_time="2",
            result_digest=str(digest),
            expected_digest=str(expected_digest),
            response_p50_ns="200",
            response_p95_ns="800000000",
            response_p99_ns="800000000",
        )
        self.output.write_text(
            "\t".join(header) + "\n" + "\t".join(row[column] for column in header) + "\n",
            encoding="utf-8",
        )

    def run_id_validator(self) -> subprocess.CompletedProcess[str]:
        args = [
            str(self.ids), "2", "900", "300", "2", "http", "steady", str(self.output),
            str(self.oracle), self.oracle_digest, self.run_id, self.nonce, "allocatbelt", "system",
            self.source_hash, self.binary_hash,
        ]
        return subprocess.run(
            [sys.executable, "-c", embedded_validator("validate_id_report"), *args],
            check=False,
            capture_output=True,
            text=True,
        )

    def test_canonical_oracle_and_per_id_results_pass(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                embedded_validator("validate_oracle_file"),
                str(self.oracle),
                "2",
                "2",
                "http",
                "steady",
                self.source_hash,
                self.binary_hash,
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.run_id_validator().returncode, 0)

        stale_source = subprocess.run(
            [
                sys.executable,
                "-c",
                embedded_validator("validate_oracle_file"),
                str(self.oracle),
                "2",
                "2",
                "http",
                "steady",
                "d" * 64,
                self.binary_hash,
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(stale_source.returncode, 0)

    def test_compensating_per_id_corruption_cannot_hide_in_the_aggregate(self) -> None:
        self.write_ids([(0, "http", 0, 800_000_000, "completed", 102, 101), (1, "http", 500_000_000, 500_000_200, "completed", 201, 202)])
        self.assertEqual(102 + 201, 101 + 202)
        self.assertNotEqual(self.run_id_validator().returncode, 0)

    def test_replayed_id_and_stale_report_nonce_are_rejected(self) -> None:
        self.write_ids([(0, "http", 0, 800_000_000, "completed", 101, 101), (0, "http", 500_000_000, 500_000_200, "completed", 202, 202)])
        self.assertNotEqual(self.run_id_validator().returncode, 0)
        self.write_ids([(0, "http", 0, 800_000_000, "completed", 101, 101), (1, "http", 500_000_000, 500_000_200, "completed", 202, 202)], nonce="d" * 32)
        self.assertNotEqual(self.run_id_validator().returncode, 0)

    def test_sidecar_cannot_replace_the_trusted_oracle(self) -> None:
        data = self.oracle.read_text(encoding="utf-8").replace("0\t0\thttp\t101", "0\t0\thttp\t102")
        self.oracle.write_text(data, encoding="utf-8")
        self.assertNotEqual(self.run_id_validator().returncode, 0)

    def test_burst_oracle_uses_average_rate_over_pulse_cycles(self) -> None:
        burst = self.directory / "burst-oracle.tsv"
        burst.write_text(
            "schema\tallocatbelt-app-oracle-v2\n"
            f"source_sha256\t{self.source_hash}\n"
            f"binary_sha256\t{self.binary_hash}\n"
            "profile\tburst\n"
            "workload\tcpu\n"
            "mode\topen_loop\n"
            "average_rate_per_second\t4\n"
            "pulse_rate_per_second\t16\n"
            "arrivals\t5\n"
            "trace_duration_ns\t2000000000\n"
            "kernel_config\trounds=50000\n"
            "id\tscheduled_ns\tworkload\texpected_checksum\n"
            "0\t0\tcpu\t101\n"
            "1\t62500000\tcpu\t102\n"
            "2\t125000000\tcpu\t103\n"
            "3\t187500000\tcpu\t104\n"
            "4\t1000000000\tcpu\t105\n",
            encoding="utf-8",
        )
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                embedded_validator("validate_oracle_file"),
                str(burst),
                "5",
                "4",
                "cpu",
                "burst",
                self.source_hash,
                self.binary_hash,
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        burst.write_text(burst.read_text(encoding="utf-8").replace("62500000", "250000000"), encoding="utf-8")
        rejected = subprocess.run(
            [
                sys.executable,
                "-c",
                embedded_validator("validate_oracle_file"),
                str(burst),
                "5",
                "4",
                "cpu",
                "burst",
                self.source_hash,
                self.binary_hash,
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(rejected.returncode, 0)

    def test_mixed_oracle_binds_each_global_id_to_its_source_family(self) -> None:
        mixed = self.directory / "mixed-oracle.tsv"
        mixed.write_text(
            "schema\tallocatbelt-app-oracle-v2\n"
            f"source_sha256\t{self.source_hash}\n"
            f"binary_sha256\t{self.binary_hash}\n"
            "profile\tmixed\n"
            "workload\tmixed\n"
            "mode\topen_loop\n"
            "average_rate_per_second\t4\n"
            "pulse_rate_per_second\t4\n"
            "arrivals\t4\n"
            "trace_duration_ns\t1000000000\n"
            "kernel_config\tinterleave=cpu,memory,http,disk\n"
            "id\tscheduled_ns\tworkload\texpected_checksum\n"
            "0\t0\tcpu\t101\n"
            "1\t250000000\tmemory\t102\n"
            "2\t500000000\thttp\t103\n"
            "3\t750000000\tdisk\t104\n",
            encoding="utf-8",
        )
        args = [
            sys.executable,
            "-c",
            embedded_validator("validate_oracle_file"),
            str(mixed),
            "4",
            "4",
            "mixed",
            "mixed",
            self.source_hash,
            self.binary_hash,
        ]
        accepted = subprocess.run(args, check=False, capture_output=True, text=True)
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        mixed.write_text(
            mixed.read_text(encoding="utf-8").replace("2\t500000000\thttp\t103", "2\t500000000\tcpu\t103"),
            encoding="utf-8",
        )
        rejected = subprocess.run(args, check=False, capture_output=True, text=True)
        self.assertNotEqual(rejected.returncode, 0)

    def test_mixed_sidecar_family_cannot_be_relabelled_against_reference(self) -> None:
        mixed = self.directory / "mixed-sidecar-oracle.tsv"
        oracle_values = [101, 202, 303, 404]
        families = ["cpu", "memory", "http", "disk"]
        mixed.write_text(
            "schema\tallocatbelt-app-oracle-v2\n"
            f"source_sha256\t{self.source_hash}\n"
            f"binary_sha256\t{self.binary_hash}\n"
            "profile\tmixed\n"
            "workload\tmixed\n"
            "mode\topen_loop\n"
            "average_rate_per_second\t4\n"
            "pulse_rate_per_second\t4\n"
            "arrivals\t4\n"
            "trace_duration_ns\t1000000000\n"
            "kernel_config\tinterleave=cpu,memory,http,disk\n"
            "id\tscheduled_ns\tworkload\texpected_checksum\n"
            + "".join(
                f"{index}\t{index * 250_000_000}\t{family}\t{oracle_values[index]}\n"
                for index, family in enumerate(families)
            ),
            encoding="utf-8",
        )
        oracle_digest = hashlib.sha256(mixed.read_bytes()).hexdigest()
        nonce = self.nonce
        self.run_id = "mixed-1"
        identity = (
            f"identity\t{nonce}\t{self.run_id}\tallocatbelt\tsystem\tmixed\tmixed\t"
            f"{self.source_hash}\t{self.binary_hash}\n"
        )
        sidecar_rows = [
            f"{index}\t{family}\t{index * 250_000_000}\t{index * 250_000_000 + 100}\tcompleted\t{oracle_values[index]}\t{oracle_values[index]}\n"
            for index, family in enumerate(families)
        ]
        self.ids.write_text(
            "schema\tallocatbelt-app-arrivals-v3\n"
            + identity
            + "id\tworkload\tscheduled_ns\tcompletion_ns\tterminal\tchecksum\texpected_checksum\n"
            + "".join(sidecar_rows),
            encoding="utf-8",
        )
        header = runner_header()
        digest = sum(value ^ index for index, value in enumerate(oracle_values))
        row = {column: "0" for column in header}
        row.update(
            schema="mixed-application-v1",
            allocator="system",
            executor="allocatbelt",
            workload="mixed",
            mode="open_loop",
            arrival_rate_per_second="4",
            requested_arrivals="4",
            attempted="4",
            admitted="4",
            completed_on_time="4",
            result_digest=str(digest),
            expected_digest=str(digest),
            response_p50_ns="100",
            response_p95_ns="100",
            response_p99_ns="100",
        )
        self.output.write_text(
            "\t".join(header) + "\n" + "\t".join(row[column] for column in header) + "\n",
            encoding="utf-8",
        )
        args = [
            str(self.ids), "4", "900", "300", "4", "mixed", "mixed", str(self.output),
            str(mixed), oracle_digest, self.run_id, nonce, "allocatbelt", "system",
            self.source_hash, self.binary_hash,
        ]
        accepted = subprocess.run(
            [sys.executable, "-c", embedded_validator("validate_id_report"), *args],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.ids.write_text(self.ids.read_text(encoding="utf-8").replace("2\thttp\t", "2\tcpu\t"), encoding="utf-8")
        rejected = subprocess.run(
            [sys.executable, "-c", embedded_validator("validate_id_report"), *args],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(rejected.returncode, 0)

    def test_capacity_report_uses_the_actual_30_second_horizon(self) -> None:
        report = self.directory / "capacity.shutdown.tsv"
        report.write_text(
            "schema\tallocatbelt-app-phase-v1\t\n"
            f"identity\treport_nonce\t{self.nonce}\n"
            f"identity\trun_id\t{self.run_id}\n"
            "identity\texecutor\tallocatbelt\n"
            "identity\tallocator\tsystem\n"
            "identity\tworkload\tcpu\n"
            "identity\tprofile\tsteady\n"
            f"identity\tsource_sha256\t{self.source_hash}\n"
            f"identity\tbinary_sha256\t{self.binary_hash}\n"
            "phase\tproduction_trace\t30000000001\n"
            "phase\tproduction_cpu_started_ns\t100\n"
            "phase\tproduction_cpu_ended_ns\t300\n"
            "phase\tproduction_through_drain_cpu_ns\t200\n"
            "phase\tsuccessful_completions\t2\n"
            "phase\tcpu_ns_per_successful_completion\t100\n"
            "driver\tallocatbelt application driver\t500000000\n",
            encoding="utf-8",
        )
        program = embedded_validator("validate_shutdown_report")
        accepted = subprocess.run(
            [sys.executable, "-c", program, str(report), "allocatbelt", "cpu", "capacity", "31", "60", "1200", str(self.output), self.nonce, self.run_id, "system", "steady", self.source_hash, self.binary_hash],
            check=False,
            capture_output=True,
            text=True,
        )
        rejected_override = subprocess.run(
            [sys.executable, "-c", program, str(report), "allocatbelt", "cpu", "capacity", "10", "60", "1200", str(self.output), self.nonce, self.run_id, "system", "steady", self.source_hash, self.binary_hash],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.assertNotEqual(rejected_override.returncode, 0)
        report.write_text(report.read_text(encoding="utf-8").replace("identity\trun_id\tvalidator-1", "identity\trun_id\tvalidator-replay"), encoding="utf-8")
        replayed = subprocess.run(
            [sys.executable, "-c", program, str(report), "allocatbelt", "cpu", "capacity", "31", "60", "1200", str(self.output), self.nonce, self.run_id, "system", "steady", self.source_hash, self.binary_hash],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(replayed.returncode, 0)
        report.write_text(report.read_text(encoding="utf-8").replace("validator-replay", "validator-1"), encoding="utf-8")
        report.write_text(
            report.read_text(encoding="utf-8").replace("30000000001", "31000000001"),
            encoding="utf-8",
        )
        beyond_allowance = subprocess.run(
            [sys.executable, "-c", program, str(report), "allocatbelt", "cpu", "capacity", "31", "60", "1200", str(self.output), self.nonce, self.run_id, "system", "steady", self.source_hash, self.binary_hash],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(beyond_allowance.returncode, 0)
        report.write_text(report.read_text(encoding="utf-8").replace("production_cpu_ended_ns\t300", "production_cpu_ended_ns\t299"), encoding="utf-8")
        invalid_cpu_boundary = subprocess.run(
            [sys.executable, "-c", program, str(report), "allocatbelt", "cpu", "capacity", "31", "60", "1200", str(self.output), self.nonce, self.run_id, "system", "steady", self.source_hash, self.binary_hash],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(invalid_cpu_boundary.returncode, 0)
        report.write_text(
            report.read_text(encoding="utf-8").replace("31000000001", "29999999999")
            .replace("production_cpu_ended_ns\t299", "production_cpu_ended_ns\t300"),
            encoding="utf-8",
        )
        short_capacity = subprocess.run(
            [sys.executable, "-c", program, str(report), "allocatbelt", "cpu", "capacity", "31", "60", "1200", str(self.output), self.nonce, self.run_id, "system", "steady", self.source_hash, self.binary_hash],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(short_capacity.returncode, 0)

    def test_mixed_capacity_family_counts_are_identity_bound_and_complete(self) -> None:
        report = self.directory / "capacity-families.tsv"
        report.write_text(
            "schema\tallocatbelt-app-capacity-families-v1\t\n"
            f"identity\treport_nonce\t{self.nonce}\n"
            f"identity\trun_id\t{self.run_id}\n"
            "identity\texecutor\tallocatbelt\n"
            "identity\tallocator\tsystem\n"
            "identity\tworkload\tmixed\n"
            "identity\tprofile\tmixed\n"
            f"identity\tsource_sha256\t{self.source_hash}\n"
            f"identity\tbinary_sha256\t{self.binary_hash}\n"
            "family\tcpu\t2\t2\n"
            "family\tmemory\t2\t2\n"
            "family\thttp\t2\t2\n"
            "family\tdisk\t2\t2\n"
            "phase\ttrace_seconds\t30\n"
            "phase\tprofile\tmixed\n",
            encoding="utf-8",
        )
        header = runner_header()
        row = {column: "0" for column in header}
        row.update(schema="2", allocator="system", executor="allocatbelt", workload="mixed", mode="capacity", attempted="8", admitted="8", completed_on_time="8")
        self.output.write_text("\t".join(header) + "\n" + "\t".join(row[column] for column in header) + "\n", encoding="utf-8")
        program = embedded_validator("validate_capacity_family_report")
        args = [str(report), str(self.output), "allocatbelt", self.nonce, self.run_id, "system", "mixed", "mixed", self.source_hash, self.binary_hash]
        accepted = subprocess.run([sys.executable, "-c", program, *args], check=False, capture_output=True, text=True)
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        original = report.read_text(encoding="utf-8")
        report.write_text(original.replace(f"identity\trun_id\t{self.run_id}", "identity\trun_id\treplayed-run"), encoding="utf-8")
        replayed = subprocess.run([sys.executable, "-c", program, *args], check=False, capture_output=True, text=True)
        self.assertNotEqual(replayed.returncode, 0)
        report.write_text(original, encoding="utf-8")
        report.write_text(report.read_text(encoding="utf-8").replace("family\tdisk\t2\t2", "family\tdisk\t2\t1"), encoding="utf-8")
        rejected = subprocess.run([sys.executable, "-c", program, *args], check=False, capture_output=True, text=True)
        self.assertNotEqual(rejected.returncode, 0)
        report.write_text(original.replace("family\tdisk\t2\t2", "family\tdisk\t2\t0"), encoding="utf-8")
        empty_family = subprocess.run([sys.executable, "-c", program, *args], check=False, capture_output=True, text=True)
        self.assertNotEqual(empty_family.returncode, 0)


class FunctionalHelperSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="functional-helper-safety-")
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.helper_path = ROOT / "scripts" / "test-application-pair-functional-e2e.py"
        spec = importlib.util.spec_from_file_location("functional_pair_helper", self.helper_path)
        assert spec is not None and spec.loader is not None
        self.helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.helper)

    def test_unverified_controller_cannot_execute(self) -> None:
        scripts = self.work / "scripts"
        scripts.mkdir()
        marker = self.work / "executed"
        (scripts / "application-campaign.py").write_text(
            f"from pathlib import Path\nPath({str(marker)!r}).touch()\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(RuntimeError, "pinned signed source"):
            self.helper.load_campaign_module(self.work)
        self.assertFalse(marker.exists())

    def test_timeout_kills_term_ignoring_child_and_keeps_timeout_status(self) -> None:
        program = "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); print('ready',flush=True); time.sleep(60)"
        started = time.monotonic()
        code = self.helper.run_bounded(
            [sys.executable, "-c", program], self.work,
            self.work / "stdout", self.work / "stderr", 1,
        )
        self.assertEqual(code, 124)
        self.assertLess(time.monotonic() - started, 5)
        self.assertIn("ready", (self.work / "stdout").read_text())

    def test_reaped_leader_does_not_leave_running_descendant(self) -> None:
        pid_path = self.work / "descendant.pid"
        program = (
            "import os,signal,time\nchild=os.fork()\n"
            "if child == 0:\n signal.signal(signal.SIGTERM,signal.SIG_IGN)\n time.sleep(60)\n os._exit(0)\n"
            f"open({str(pid_path)!r},'w').write(str(child))\nos._exit(0)\n"
        )
        code = self.helper.run_bounded(
            [sys.executable, "-c", program], self.work,
            self.work / "stdout", self.work / "stderr", 5,
        )
        self.assertEqual(code, 0)
        pid = int(pid_path.read_text())
        try:
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                status = Path(f"/proc/{pid}/stat")
                if not status.exists() or status.read_text().rsplit(")", 1)[1].split()[0] == "Z":
                    return
                time.sleep(0.02)
            self.fail("descendant remains running after leader exit")
        finally:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def test_early_interrupt_escalates_before_original_deadline(self) -> None:
        ready_path = self.work / "ready.pid"
        child = (
            "import os,signal,time\nsignal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
            f"open({str(ready_path)!r},'w').write(str(os.getpid()))\ntime.sleep(60)\n"
        )
        wrapper = (
            "import importlib.util,sys\nfrom pathlib import Path\n"
            f"s=importlib.util.spec_from_file_location('helper',{str(self.helper_path)!r})\n"
            "m=importlib.util.module_from_spec(s);s.loader.exec_module(m)\n"
            f"print(m.run_bounded([sys.executable,'-c',{child!r}],Path({str(self.work)!r}),"
            f"Path({str(self.work / 'stdout')!r}),Path({str(self.work / 'stderr')!r}),30),flush=True)\n"
        )
        driver = subprocess.Popen([sys.executable, "-B", "-c", wrapper], stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try:
            deadline = time.monotonic() + 5
            while not ready_path.exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertTrue(ready_path.exists(), "child never established its signal handler")
            started = time.monotonic()
            driver.send_signal(signal.SIGTERM)
            stdout, stderr = driver.communicate(timeout=5)
            self.assertEqual(driver.returncode, 0, stderr.decode(errors="replace"))
            self.assertEqual(stdout.strip(), b"143")
            self.assertLess(time.monotonic() - started, 5)
        finally:
            try:
                os.killpg(driver.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            driver.wait(timeout=2)
            if ready_path.exists():
                try:
                    os.killpg(int(ready_path.read_text()), signal.SIGKILL)
                except ProcessLookupError:
                    pass


if __name__ == "__main__":
    unittest.main()
