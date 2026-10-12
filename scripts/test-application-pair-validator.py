#!/usr/bin/env python3
"""Focused remote tests for the Python validators embedded in the pair runner."""

from __future__ import annotations

import hashlib
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "run-application-pair.sh"


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


class ApplicationPairValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="app-pair-validator-")
        self.directory = Path(self.temp.name)
        self.oracle = self.directory / "oracle.tsv"
        self.ids = self.directory / "result.ids.tsv"
        self.output = self.directory / "result.tsv"
        self.nonce = "a" * 32
        self.run_id = "validator-1"
        self.source_hash = "b" * 64
        self.binary_hash = "c" * 64
        self.oracle_values = [101, 202]
        self.oracle.write_text(
            "schema\tallocatbelt-app-oracle-v1\n"
            f"source_sha256\t{self.source_hash}\n"
            f"binary_sha256\t{self.binary_hash}\n"
            "workload\thttp\n"
            "mode\topen_loop\n"
            "rate_per_second\t2\n"
            "arrivals\t2\n"
            "kernel_config\tbody_bytes=4096\n"
            "id\texpected_checksum\n"
            "0\t101\n"
            "1\t202\n",
            encoding="utf-8",
        )
        self.oracle_digest = hashlib.sha256(self.oracle.read_bytes()).hexdigest()
        self.write_ids([(0, 0, 100, "completed", 101, 101), (1, 500_000_000, 500_000_200, "completed", 202, 202)])
        self.write_output()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_ids(self, records: list[tuple[int, int, int, str, int, int]], nonce: str | None = None) -> None:
        identity = (
            f"identity\t{nonce or self.nonce}\t{self.run_id}\tallocatbelt\tsystem\thttp\t"
            f"{self.source_hash}\t{self.binary_hash}\n"
        )
        lines = [
            "schema\tallocatbelt-app-arrivals-v2\n",
            identity,
            "id\tscheduled_ns\tcompletion_ns\tterminal\tchecksum\texpected_checksum\n",
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
            response_p50_ns="100",
            response_p95_ns="200",
            response_p99_ns="200",
        )
        self.output.write_text(
            "\t".join(header) + "\n" + "\t".join(row[column] for column in header) + "\n",
            encoding="utf-8",
        )

    def run_id_validator(self) -> subprocess.CompletedProcess[str]:
        args = [
            str(self.ids), "2", "900", "300", "2", "http", str(self.output),
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
                "d" * 64,
                self.binary_hash,
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(stale_source.returncode, 0)

    def test_compensating_per_id_corruption_cannot_hide_in_the_aggregate(self) -> None:
        self.write_ids([(0, 0, 100, "completed", 102, 101), (1, 500_000_000, 500_000_200, "completed", 201, 202)])
        self.assertEqual(102 + 201, 101 + 202)
        self.assertNotEqual(self.run_id_validator().returncode, 0)

    def test_replayed_id_and_stale_report_nonce_are_rejected(self) -> None:
        self.write_ids([(0, 0, 100, "completed", 101, 101), (0, 500_000_000, 500_000_200, "completed", 202, 202)])
        self.assertNotEqual(self.run_id_validator().returncode, 0)
        self.write_ids([(0, 0, 100, "completed", 101, 101), (1, 500_000_000, 500_000_200, "completed", 202, 202)], nonce="d" * 32)
        self.assertNotEqual(self.run_id_validator().returncode, 0)

    def test_sidecar_cannot_replace_the_trusted_oracle(self) -> None:
        data = self.oracle.read_text(encoding="utf-8").replace("0\t101", "0\t102")
        self.oracle.write_text(data, encoding="utf-8")
        self.assertNotEqual(self.run_id_validator().returncode, 0)

    def test_capacity_report_uses_the_actual_30_second_horizon(self) -> None:
        report = self.directory / "capacity.shutdown.tsv"
        report.write_text(
            "kind\tname\tduration_ns\n"
            "phase\tproduction_trace\t30000000001\n"
            "phase\tproduction_through_drain_cpu_ns\t200\n"
            "phase\tsuccessful_completions\t2\n"
            "phase\tcpu_ns_per_successful_completion\t100\n"
            "driver\tallocatbelt async runtime\t500000000\n",
            encoding="utf-8",
        )
        program = embedded_validator("validate_shutdown_report")
        accepted = subprocess.run(
            [sys.executable, "-c", program, str(report), "allocatbelt", "cpu", "31", "60", str(self.output)],
            check=False,
            capture_output=True,
            text=True,
        )
        rejected_override = subprocess.run(
            [sys.executable, "-c", program, str(report), "allocatbelt", "cpu", "10", "60", str(self.output)],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.assertNotEqual(rejected_override.returncode, 0)
        report.write_text(
            report.read_text(encoding="utf-8").replace("30000000001", "31000000001"),
            encoding="utf-8",
        )
        beyond_allowance = subprocess.run(
            [sys.executable, "-c", program, str(report), "allocatbelt", "cpu", "31", "60", str(self.output)],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(beyond_allowance.returncode, 0)


if __name__ == "__main__":
    unittest.main()
