#!/usr/bin/env python3
"""Remote-only full-shape functional/cost check for the exact analyzer.

This streams a 50,000-draw, 486-primary/9-suite, 135-group matrix containing
36 paired processes and varied 100,000-arrival traces (400,000 mixed arrivals
across four source families). It also compares a tiny partial-block bootstrap
against an independent Python implementation of the frozen PRNG and exact
nearest-rank estimator. No allocator workloads are launched.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.machinery
import importlib.util
import json
import math
import os
import struct
import subprocess
import tempfile
import time
from fractions import Fraction
from pathlib import Path
from typing import BinaryIO, Callable


CAMPAIGN_PATH = Path(__file__).with_name("application-campaign.py")
LOADER = importlib.machinery.SourceFileLoader("application_campaign_fullshape", str(CAMPAIGN_PATH))
MODULE_SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
assert MODULE_SPEC is not None
campaign = importlib.util.module_from_spec(MODULE_SPEC)
LOADER.exec_module(campaign)

MAGIC = b"ABQST01\0"
RESULT_MAGIC = b"ABQSO01\0"
PAIRS = 36
DRAWS = 50_000
SEED = 20261012
CONFIDENCE = 0.95
BLOCK_SIZE = 1000
INPUT_BUDGET = 32 * 1024**3
RESIDENT_BUDGET = 2 * 1024**3
MASK64 = (1 << 64) - 1


def write_u16(stream: BinaryIO, value: int) -> None:
    stream.write(struct.pack("<H", value))


def write_u32(stream: BinaryIO, value: int) -> None:
    stream.write(struct.pack("<I", value))


def write_u64(stream: BinaryIO, value: int) -> None:
    stream.write(struct.pack("<Q", value))


def write_string(stream: BinaryIO, value: str) -> None:
    data = value.encode("utf-8")
    if not data or len(data) > 65535:
        raise ValueError("wire string is outside its finite bound")
    write_u16(stream, len(data))
    stream.write(data)


def write_frame(stream: BinaryIO, body_size: int, kind: int, emit: Callable[[BinaryIO], None]) -> None:
    if body_size < 1:
        raise ValueError("empty analyzer frame")
    write_u64(stream, body_size)
    stream.write(bytes([kind]))
    start = stream.tell()
    emit(stream)
    if stream.tell() - start != body_size - 1:
        raise ValueError("streamed frame length did not match its frozen descriptor")


def wire_string_size(value: str) -> int:
    return 2 + len(value.encode("utf-8"))


def encode_header(stream: BinaryIO, *, draws: int, pairs: int, groups: int, endpoints: int,
                  suites: int, seed: int, block_size: int) -> None:
    body_size = 1 + struct.calcsize("<IHHHHQdIQQ")

    def emit(frame: BinaryIO) -> None:
        frame.write(struct.pack(
            "<IHHHHQdIQQ", draws, pairs, groups, endpoints, suites, seed,
            CONFIDENCE, block_size, INPUT_BUDGET, RESIDENT_BUDGET,
        ))

    write_frame(stream, body_size, 1, emit)


def latency_value(block: int, within: int, family_index: int, slot: int, candidate: bool) -> int:
    """Unique, varied values with separated block bands and treatment jitter."""
    base = (block + 1) * 1_000_000 + within * 100 + family_index * 7
    control_jitter = slot * 3 + family_index * 5 + (block % 7) * 2
    treatment_jitter = 25 + (block % 13) * 5 if candidate else 0
    multiplier = 1_000_000 + control_jitter + treatment_jitter
    return base * multiplier // 1_000_000


def unique_values_per_block(block_size: int) -> int:
    return block_size * 72 // 100


def within_for_unique_index(index: int, block_size: int, unique_count: int) -> int:
    return index * block_size // unique_count


def expected_trace_p99(block_count: int, block_size: int, family_index: int,
                       slot: int, candidate: bool) -> int:
    total = block_count * block_size
    descending_rank = total - ((99 * total + 99) // 100) + 1
    blocks_from_top, rank_in_block = divmod(descending_rank - 1, block_size)
    block = block_count - 1 - blocks_from_top
    unique_count = unique_values_per_block(block_size)
    within = within_for_unique_index(unique_count - 1 - rank_in_block, block_size, unique_count)
    return latency_value(block, within, family_index, slot, candidate)


def expected_profile_cells() -> list[tuple[str, str, str]]:
    return sorted(campaign.expected_profile_cells())


def encode_full_input(stream: BinaryIO) -> tuple[list[dict], list[dict], int, int]:
    cells = expected_profile_cells()
    group_names: set[str] = set()
    endpoints: list[dict] = []
    suites: list[dict] = []

    def group_for(cell: tuple[str, str, str], mode: str, load: int,
                  comparison: str, contrast: str) -> str:
        name = json.dumps([*cell, mode, load, comparison, contrast], separators=(",", ":"))
        group_names.add(name)
        return name

    def add(name: str, group: str, kind: str, *, family: str | None = None,
            suite_key: tuple[str, str, str] | None = None,
            ratios: list[float] | None = None, values: list[tuple[int, int]] | None = None) -> int:
        endpoints.append({
            "name": name, "group": group, "kind": kind, "family": family,
            "suite_key": suite_key, "ratios": ratios, "values": values,
        })
        return len(endpoints) - 1

    def add_allocator(baseline: str) -> None:
        throughput_components = []
        p99_components = {70: [], 90: []}
        for family, workload, profile in cells:
            source_families = campaign.STANDALONE if workload == "mixed" else (family,)
            capacity_group = group_for((family, workload, profile), "capacity", 0, "allocator", baseline)
            for source_family in source_families:
                throughput_components.append(add(
                    f"alloc-throughput:{family}:{profile}:{source_family}:{baseline}",
                    capacity_group, "ratio", suite_key=(profile, source_family, family),
                    ratios=[1.03 + (slot + 1) / 10000 for slot in range(PAIRS)],
                ))
            add(f"alloc-cpu-capacity:{family}:{profile}:{baseline}", capacity_group, "ratio",
                ratios=[0.98 + slot / 10000 for slot in range(PAIRS)])
            add(f"alloc-rss-capacity:{family}:{profile}:{baseline}", capacity_group, "ratio",
                ratios=[1.01 + slot / 10000 for slot in range(PAIRS)])
            for load in (70, 90):
                open_group = group_for((family, workload, profile), "open_loop", load, "allocator", baseline)
                add(f"alloc-cpu-open:{family}:{profile}:{load}:{baseline}", open_group, "ratio",
                    ratios=[0.97 + slot / 10000 for slot in range(PAIRS)])
                add(f"alloc-rss-open:{family}:{profile}:{load}:{baseline}", open_group, "ratio",
                    ratios=[1.02 + slot / 10000 for slot in range(PAIRS)])
                for source_family in source_families:
                    family_index = campaign.STANDALONE.index(source_family)
                    block_count = 400 if workload == "mixed" else 100
                    block_size = 250 if workload == "mixed" else 1000
                    p99_components[load].append(add(
                        f"alloc-p99:{family}:{profile}:{source_family}:{load}:{baseline}",
                        open_group, "p99", family=source_family,
                        suite_key=(profile, source_family, family),
                        values=[(
                            expected_trace_p99(block_count, block_size, family_index, slot, True),
                            expected_trace_p99(block_count, block_size, family_index, slot, False),
                        ) for slot in range(PAIRS)],
                    ))
        suites.append({"name": f"alloc-throughput-suite:{baseline}", "components": throughput_components})
        for load in (70, 90):
            suites.append({"name": f"alloc-p99-suite:{load}:{baseline}", "components": p99_components[load]})

    for baseline in ("mimalloc-secure", "mimalloc-standard"):
        add_allocator(baseline)

    throughput_components = []
    p99_components = {70: [], 90: []}
    for family, workload, profile in cells:
        source_families = campaign.STANDALONE if workload == "mixed" else (family,)
        capacity_group = group_for((family, workload, profile), "capacity", 0, "executor", "allocatbelt")
        for source_family in source_families:
            throughput_components.append(add(
                f"executor-throughput:{family}:{profile}:{source_family}", capacity_group,
                "ratio", suite_key=(profile, source_family, family),
                ratios=[1.04 + (slot + 1) / 10000 for slot in range(PAIRS)],
            ))
        add(f"executor-cpu-capacity:{family}:{profile}", capacity_group, "ratio",
            ratios=[0.99 + slot / 10000 for slot in range(PAIRS)])
        add(f"executor-rss-capacity:{family}:{profile}", capacity_group, "ratio",
            ratios=[1.01 + slot / 10000 for slot in range(PAIRS)])
        for load in (70, 90):
            open_group = group_for((family, workload, profile), "open_loop", load, "executor", "allocatbelt")
            add(f"executor-cpu-open:{family}:{profile}:{load}", open_group, "ratio",
                ratios=[0.98 + slot / 10000 for slot in range(PAIRS)])
            add(f"executor-rss-open:{family}:{profile}:{load}", open_group, "ratio",
                ratios=[1.02 + slot / 10000 for slot in range(PAIRS)])
            for source_family in source_families:
                family_index = campaign.STANDALONE.index(source_family)
                block_count = 400 if workload == "mixed" else 100
                block_size = 250 if workload == "mixed" else 1000
                p99_components[load].append(add(
                    f"executor-p99:{family}:{profile}:{source_family}:{load}", open_group,
                    "p99", family=source_family,
                    suite_key=(profile, source_family, family),
                    values=[(
                        expected_trace_p99(block_count, block_size, family_index, slot, True),
                        expected_trace_p99(block_count, block_size, family_index, slot, False),
                    ) for slot in range(PAIRS)],
                ))
    suites.append({"name": "executor-throughput-suite", "components": throughput_components})
    for load in (70, 90):
        suites.append({"name": f"executor-p99-suite:{load}", "components": p99_components[load]})

    assert len(endpoints) == campaign.ANALYZER_PRIMARY_ENDPOINTS_PER_HOST
    assert len(suites) == campaign.ANALYZER_SUITE_ENDPOINTS_PER_HOST
    assert len(group_names) == campaign.ANALYZER_PAIR_GROUPS_PER_HOST
    ordered_groups = sorted(group_names)
    group_ids = {name: index for index, name in enumerate(ordered_groups)}
    for endpoint in endpoints:
        endpoint["group_id"] = group_ids[endpoint["group"]]
        if endpoint["kind"] == "p99":
            endpoint["ratio_logs"] = [math.log(candidate / control) for candidate, control in endpoint["values"]]
        else:
            endpoint["ratio_logs"] = [math.log(ratio) for ratio in endpoint["ratios"]]

    stream.write(MAGIC)
    encode_header(stream, draws=DRAWS, pairs=PAIRS, groups=len(ordered_groups),
                  endpoints=len(endpoints), suites=len(suites), seed=SEED, block_size=BLOCK_SIZE)
    for endpoint in endpoints:
        def emit_endpoint(frame: BinaryIO, endpoint: dict = endpoint) -> None:
            write_u16(frame, endpoint["group_id"])
            write_string(frame, endpoint["name"])
            if endpoint["kind"] == "ratio":
                for ratio in endpoint["ratios"]:
                    frame.write(struct.pack("<d", ratio))
            else:
                write_string(frame, endpoint["family"])
                for candidate, control in endpoint["values"]:
                    write_u64(frame, candidate)
                    write_u64(frame, control)

        payload_size = 2 + wire_string_size(endpoint["name"])
        if endpoint["kind"] == "ratio":
            payload_size += 8 * PAIRS
            kind = 0
        else:
            payload_size += wire_string_size(endpoint["family"]) + 16 * PAIRS
            kind = 1
        write_frame(stream, 2 + payload_size, 2, lambda frame, endpoint=endpoint, kind=kind: (frame.write(bytes([kind])), emit_endpoint(frame, endpoint)))

    for suite in suites:
        keys = [endpoints[index]["suite_key"] for index in suite["components"]]
        weights = campaign.equal_profile_family_context_weights(keys)
        assert abs(sum(weights) - 1.0) < 1e-12
        rationals = [Fraction(weight).limit_denominator(4096) for weight in weights]
        payload_size = wire_string_size(suite["name"]) + 2 + sum(10 for _ in rationals)

        def emit_suite(frame: BinaryIO, suite: dict = suite, rationals: list[Fraction] = rationals) -> None:
            write_string(frame, suite["name"])
            write_u16(frame, len(suite["components"]))
            for component, rational in zip(suite["components"], rationals, strict=True):
                write_u16(frame, component)
                write_u32(frame, rational.numerator)
                write_u32(frame, rational.denominator)

        write_frame(stream, 1 + payload_size, 3, emit_suite)

    endpoint_by_group_family: dict[tuple[str, str], dict] = {}
    for endpoint in endpoints:
        if endpoint["kind"] == "p99":
            endpoint_by_group_family[(endpoint["group"], endpoint["family"])] = endpoint
    for group_name in ordered_groups:
        family_names = tuple(sorted(family for name, family in endpoint_by_group_family if name == group_name))
        parsed = json.loads(group_name)
        workload = parsed[1]
        block_count = 400 if workload == "mixed" else 100
        family_indices = {family: campaign.STANDALONE.index(family) for family in family_names}
        trace_block_size = 250 if workload == "mixed" else BLOCK_SIZE
        trace_unique_count = unique_values_per_block(trace_block_size)
        trace_body_size = 4 + block_count * (8 + trace_unique_count * 12)
        payload_size = (
            2 + wire_string_size(group_name) + 2
            + sum(wire_string_size(name) for name in family_names)
            + 2 + PAIRS * len(family_names) * 2 * trace_body_size
        )
        group_id = group_ids[group_name]

        def emit_group(frame: BinaryIO, group_name: str = group_name,
                       family_names: tuple[str, ...] = family_names,
                       family_indices: dict[str, int] = family_indices,
                       block_count: int = block_count, workload: str = workload,
                       group_id: int = group_id) -> None:
            write_u16(frame, group_id)
            write_string(frame, group_name)
            write_u16(frame, len(family_names))
            for family in family_names:
                write_string(frame, family)
            write_u16(frame, PAIRS)
            block_size = 250 if workload == "mixed" else BLOCK_SIZE
            for slot in range(PAIRS):
                for family in family_names:
                    family_index = family_indices[family]
                    for candidate in (True, False):
                        write_u32(frame, block_count)
                        for block in range(block_count):
                            write_u32(frame, block_size)
                            unique_count = unique_values_per_block(block_size)
                            write_u32(frame, unique_count)
                            base_frequency, remainder = divmod(block_size, unique_count)
                            for value_index in range(unique_count - 1, -1, -1):
                                within = within_for_unique_index(value_index, block_size, unique_count)
                                frequency = base_frequency + (1 if value_index < remainder else 0)
                                write_u64(frame, latency_value(block, within, family_index, slot, candidate))
                                write_u32(frame, frequency)

        write_frame(stream, 1 + payload_size, 4, emit_group)
    write_frame(stream, 1, 5, lambda _frame: None)
    stream.flush()
    expected_points = {}
    for endpoint in endpoints:
        expected_points[endpoint["name"]] = math.exp(sum(endpoint["ratio_logs"]) / PAIRS)
    for suite in suites:
        weights = campaign.equal_profile_family_context_weights(
            [endpoints[index]["suite_key"] for index in suite["components"]]
        )
        logs = [
            sum(weight * endpoints[index]["ratio_logs"][slot]
                for index, weight in zip(suite["components"], weights, strict=True))
            for slot in range(PAIRS)
        ]
        expected_points[suite["name"]] = math.exp(sum(logs) / PAIRS)
    return endpoints, suites, len(ordered_groups), expected_points


def splitmix_next(state: int) -> tuple[int, int]:
    state = (state + 0x9E3779B97F4A7C15) & MASK64
    value = state
    value = ((value ^ (value >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
    value = ((value ^ (value >> 27)) * 0x94D049BB133111EB) & MASK64
    return state, value ^ (value >> 31)


class ReferenceRng:
    def __init__(self, seed: int, name: str, group_id: int):
        value = 0xCBF29CE484222325
        for byte in name.encode():
            value = ((value ^ byte) * 0x100000001B3) & MASK64
        self.state = seed ^ value ^ ((group_id * 0xD6E8FEB86659FD93) & MASK64)

    def below(self, upper: int) -> int:
        threshold = ((-upper) & MASK64) % upper
        while True:
            self.state, value = splitmix_next(self.state)
            if value >= threshold:
                return value % upper


def mini_values(slot: int, candidate: bool) -> list[list[int]]:
    result = []
    for block in range(5):
        count = 2 if block == 4 else 4
        base = 80 + block * 23 + slot * 5 + (11 if candidate else 0)
        values = [base + index * (3 + block % 3) + (slot + 1) * index * index for index in range(count)]
        result.append(values)
    return result


def nearest_rank_p99(values: list[int]) -> int:
    ordered = sorted(values)
    return ordered[(99 * len(ordered) + 99) // 100 - 1]


def make_mini_input(path: Path) -> tuple[dict[str, float], float, int, dict[str, tuple[float, float, float]]]:
    draws, pairs, group_count, primary, suites = 64, 3, 1, 2, 1
    seed, block_size = 88776655, 4
    group_name = "mini-independent-reference"
    counter = [0.91, 1.03, 1.12]
    traces = [(mini_values(slot, True), mini_values(slot, False)) for slot in range(pairs)]
    candidate_p99 = [nearest_rank_p99([x for block in candidate for x in block]) for candidate, _ in traces]
    control_p99 = [nearest_rank_p99([x for block in control for x in block]) for _, control in traces]
    with path.open("wb") as stream:
        stream.write(MAGIC)
        encode_header(stream, draws=draws, pairs=pairs, groups=group_count, endpoints=primary,
                      suites=suites, seed=seed, block_size=block_size)

        def emit_counter(frame: BinaryIO) -> None:
            write_u16(frame, 0)
            write_string(frame, "mini-counter")
            for ratio in counter:
                frame.write(struct.pack("<d", ratio))

        write_frame(stream, 2 + 2 + wire_string_size("mini-counter") + 8 * pairs, 2,
                    lambda frame: (frame.write(b"\0"), emit_counter(frame)))

        def emit_percentile(frame: BinaryIO) -> None:
            write_u16(frame, 0)
            write_string(frame, "mini-p99")
            write_string(frame, "cpu")
            for candidate, control in zip(candidate_p99, control_p99, strict=True):
                write_u64(frame, candidate)
                write_u64(frame, control)

        write_frame(stream, 2 + 2 + wire_string_size("mini-p99") + wire_string_size("cpu") + 16 * pairs,
                    2, lambda frame: (frame.write(b"\1"), emit_percentile(frame)))

        suite_name = "mini-suite"

        def emit_suite(frame: BinaryIO) -> None:
            write_string(frame, suite_name)
            write_u16(frame, 2)
            for component in (0, 1):
                write_u16(frame, component)
                write_u32(frame, 1)
                write_u32(frame, 2)

        write_frame(stream, 1 + wire_string_size(suite_name) + 2 + 20, 3, emit_suite)

        def emit_group(frame: BinaryIO) -> None:
            write_u16(frame, 0)
            write_string(frame, group_name)
            write_u16(frame, 1)
            write_string(frame, "cpu")
            write_u16(frame, pairs)
            for candidate, control in traces:
                for values in (candidate, control):
                    write_u32(frame, len(values))
                    for block in values:
                        write_u32(frame, len(block))
                        write_u32(frame, len(block))
                        for value in sorted(block, reverse=True):
                            write_u64(frame, value)
                            write_u32(frame, 1)

        # 5 blocks per trace; the last block is intentionally partial.
        trace_size = 4 + 4 * (8 + 4 * 12) + (8 + 2 * 12)
        group_payload = 2 + wire_string_size(group_name) + 2 + wire_string_size("cpu") + 2 + pairs * 2 * trace_size
        write_frame(stream, 1 + group_payload, 4, emit_group)
        write_frame(stream, 1, 5, lambda _frame: None)

    rng = ReferenceRng(seed, group_name, 0)
    draw_values: list[list[float]] = []
    for _draw in range(draws):
        counter_log = 0.0
        p99_log = 0.0
        for _ in range(pairs):
            slot = rng.below(pairs)
            counter_log += math.log(counter[slot])
            multiplicities = [0] * 5
            for _ in range(5):
                multiplicities[rng.below(5)] += 1
            selected_candidate = [value for block_id, count in enumerate(multiplicities)
                                  for _ in range(count) for value in traces[slot][0][block_id]]
            selected_control = [value for block_id, count in enumerate(multiplicities)
                                for _ in range(count) for value in traces[slot][1][block_id]]
            p99_log += math.log(nearest_rank_p99(selected_candidate) / nearest_rank_p99(selected_control))
        first = counter_log / pairs
        second = p99_log / pairs
        draw_values.append([first, second, (first + second) / 2])
    center = [
        sum(math.log(value) for value in counter) / pairs,
        sum(math.log(a / b) for a, b in zip(candidate_p99, control_p99, strict=True)) / pairs,
    ]
    center.append((center[0] + center[1]) / 2)
    scales = []
    for endpoint in range(3):
        values = [draw[endpoint] for draw in draw_values]
        mean = sum(values) / draws
        scales.append(math.sqrt(sum((value - mean) ** 2 for value in values) / (draws - 1)))
    maxima = [max(abs(draw[i] - center[i]) / scales[i] if scales[i] else 0.0 for i in range(3)) for draw in draw_values]
    maxima.sort()
    critical = maxima[math.ceil(CONFIDENCE * draws) - 1]
    names = ("mini-counter", "mini-p99", "mini-suite")
    points = {name: math.exp(center[index]) for index, name in enumerate(names)}
    intervals = {
        name: (points[name], math.exp(center[index] - critical * scales[index]), math.exp(center[index] + critical * scales[index]))
        for index, name in enumerate(names)
    }
    return points, critical, seed, intervals


def run_and_parse(binary: Path, input_path: Path, output_path: Path,
                  timeout_seconds: int) -> tuple[bytes, tuple[int, int, int, int, int, int, float], list[dict]]:
    result = subprocess.run([str(binary), str(input_path), str(output_path)], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout_seconds, check=False)
    if result.returncode != 0:
        raise AssertionError(result.stderr.decode(errors="replace"))
    output = output_path.read_bytes()
    assert output.startswith(RESULT_MAGIC)
    offset = 8

    def take(format_string: str):
        nonlocal offset
        values = struct.unpack_from(format_string, output, offset)
        offset += struct.calcsize(format_string)
        return values

    draws, endpoint_count, group_count = take("<IHH")
    seed, input_count, peak = take("<QQQ")
    (critical,) = take("<d")
    decoded = []
    for _ in range(endpoint_count):
        endpoint_id, name_size = take("<HH")
        name = output[offset:offset + name_size].decode("utf-8")
        offset += name_size
        point, center, scale, lower, upper = take("<ddddd")
        decoded.append({"id": endpoint_id, "name": name, "point": point, "center": center,
                        "scale": scale, "lower": lower, "upper": upper})
    assert offset == len(output)
    return output, (draws, endpoint_count, group_count, seed, input_count, peak, critical), decoded


def run_mini_reference(binary: Path, directory: Path, timeout_seconds: int) -> None:
    input_path, output_path = directory / "mini-input.bin", directory / "mini-output.bin"
    points, expected_critical, expected_seed, intervals = make_mini_input(input_path)
    _, meta, endpoints = run_and_parse(binary, input_path, output_path, timeout_seconds)
    draws, endpoint_count, group_count, seed, input_count, peak, critical = meta
    assert (draws, endpoint_count, group_count, seed) == (64, 3, 1, expected_seed)
    assert input_count == input_path.stat().st_size and peak <= RESIDENT_BUDGET
    assert math.isclose(critical, expected_critical, rel_tol=1e-11, abs_tol=1e-12)
    for endpoint in endpoints:
        point, lower, upper = intervals[endpoint["name"]]
        assert math.isclose(endpoint["point"], points[endpoint["name"]], rel_tol=1e-12)
        assert math.isclose(endpoint["lower"], lower, rel_tol=1e-10)
        assert math.isclose(endpoint["upper"], upper, rel_tol=1e-10)
    assert all(endpoint["scale"] > 0 for endpoint in endpoints)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--timeout-seconds", type=int, default=7200)
    args = parser.parse_args()
    if not 1 <= args.timeout_seconds <= 24 * 3600:
        raise ValueError("timeout is outside its finite bound")
    binary = args.binary.resolve(strict=True)
    before_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix="application-analyzer-full-") as temporary:
        root = Path(temporary)
        run_mini_reference(binary, root, args.timeout_seconds)
        input_path, output_path = root / "full-input.bin", root / "full-output.bin"
        started = time.monotonic()
        with input_path.open("xb") as stream:
            endpoints, suites, expected_groups, expected_points = encode_full_input(stream)
        input_size = input_path.stat().st_size
        assert input_size <= INPUT_BUDGET
        output, meta, decoded = run_and_parse(binary, input_path, output_path, args.timeout_seconds)
        elapsed = time.monotonic() - started
        draws, endpoint_count, group_count, seed, input_count, peak, critical = meta
        expected_names = [endpoint["name"] for endpoint in endpoints] + [suite["name"] for suite in suites]
        assert (draws, endpoint_count, group_count) == (DRAWS, len(expected_names), expected_groups)
        assert seed == SEED and input_count == input_size and peak <= RESIDENT_BUDGET
        assert math.isfinite(critical) and critical > 0
        assert [item["name"] for item in decoded] == expected_names
        assert len(decoded) == campaign.ANALYZER_PRIMARY_ENDPOINTS_PER_HOST + campaign.ANALYZER_SUITE_ENDPOINTS_PER_HOST
        assert all(item["scale"] > 0 and item["lower"] <= item["point"] <= item["upper"] for item in decoded)
        for item in decoded:
            assert math.isclose(item["point"], expected_points[item["name"]], rel_tol=2e-11, abs_tol=0.0), item["name"]
        assert hashlib.sha256(binary.read_bytes()).hexdigest() == before_hash
        print(json.dumps({
            "status": "pass", "draws": draws, "paired_processes": PAIRS,
            "standalone_arrivals_per_process": 100_000, "mixed_arrivals_per_process": 400_000,
            "endpoints": endpoint_count, "pair_groups": group_count,
            "input_bytes": input_size, "resident_peak_bytes": peak,
            "critical_value": critical, "analyzer_wall_seconds": elapsed,
            "analyzer_sha256": before_hash, "trace_values": "dense-varied-mostly-unique",
            "independent_mini_reference": "pass",
        }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
