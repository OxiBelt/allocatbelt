"""The host must never accept incomplete guest execution as coverage."""

import importlib.util
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("guest_check", Path(__file__).with_name("check.py"))
guest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guest)


class Protocol(unittest.TestCase):
  def log(self, scenario="v-off", identity="abc"):
    labels = ["platform", "region", "runtime"] + (
      ["dispatch-off"] if scenario == "v-off" else
      ["rvv-kernel", "dispatch-on", "dispatch-disabled", "thread-policy"])
    rows = []
    for label in labels:
      rows.append(f"ALLOCATBELT_GUEST BEGIN {scenario} {identity} {label}")
      rows.extend(["test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
                   "0 filtered out; finished in 0.00s"] *
                  {"rvv-kernel": 2, "thread-policy": 3}.get(label, 1))
      rows.append(f"ALLOCATBELT_GUEST PASS {scenario} {identity} {label}")
    rows.append(f"ALLOCATBELT_GUEST COMPLETE {scenario} {identity}")
    return "\n".join(rows)

  def test_both_complete_scenarios(self):
    for scenario in ("v-off", "v-on"):
      guest.validate_log(self.log(scenario), scenario, "abc")

  def test_missing_or_duplicate_result_is_rejected(self):
    log = self.log()
    for damaged in (log.rsplit("\n", 1)[0], log + "\n" + log,
                    log.replace("PASS v-off abc runtime", "FAIL v-off abc runtime")):
      with self.assertRaises(ValueError):
        guest.validate_log(damaged, "v-off", "abc")

  def test_wrong_identity_or_scenario_is_rejected(self):
    for scenario, identity in (("v-on", "abc"), ("v-off", "other")):
      with self.assertRaises(ValueError):
        guest.validate_log(self.log(), scenario, identity)

  def test_panic_or_skipped_coverage_is_rejected(self):
    for failure in ("Kernel panic", "Oops:", "test result: FAILED", "1 ignored;"):
      with self.assertRaises(ValueError):
        guest.validate_log(self.log() + "\n" + failure, "v-off", "abc")

  def test_zero_tests_or_missing_summaries_are_rejected(self):
    for damaged in (self.log().replace("1 passed", "0 passed"),
                    self.log().replace("test result: ok.", "unrecognized result:")):
      with self.assertRaises(ValueError):
        guest.validate_log(damaged, "v-off", "abc")

  def test_extra_or_malformed_summaries_are_rejected(self):
    summary = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;"
    for extra in (summary, "test result: ok. malformed", " " + summary,
                  summary + " unexpected trailing text"):
      damaged = self.log().replace("ALLOCATBELT_GUEST PASS v-off abc platform",
                                  extra + "\nALLOCATBELT_GUEST PASS v-off abc platform")
      with self.assertRaises(ValueError):
        guest.validate_log(damaged, "v-off", "abc")
      with self.assertRaises(ValueError):
        guest.validate_log(self.log() + "\n" + extra, "v-off", "abc")

  def test_nested_suites_require_children_and_parent(self):
    log = self.log("v-on")
    for label in ("rvv-kernel", "thread-policy"):
      begin = f"ALLOCATBELT_GUEST BEGIN v-on abc {label}\n"
      head, segment = log.split(begin)
      lines = segment.splitlines()
      for damaged in (head + begin + "\n".join(lines[1:]),
                      head + begin + lines[0] + "\n" + segment,
                      head + begin + segment.replace("1 passed", "0 passed", 1)):
        with self.assertRaises(ValueError):
          guest.validate_log(damaged, "v-on", "abc")

  def test_qemu_exit_status_is_not_coverage(self):
    for result in (SimpleNamespace(returncode=0, stdout="", stderr=""),
                   SimpleNamespace(returncode=124, stdout="", stderr="")):
      with (patch.object(guest, "input_key", return_value="key"),
            patch.object(guest, "validate_assets"),
            patch.object(guest, "validate_payload", return_value="abc"),
            patch.object(guest.subprocess, "run", return_value=result)):
        with self.assertRaises(ValueError):
          guest.boot()

  def test_payload_rejects_changed_sources_revision_or_archive(self):
    for changed in ("source", "toolchain", "revision", "archive", "identity", "guest-key"):
      with self.subTest(changed=changed), TemporaryDirectory() as directory:
        root = Path(directory)
        work = root / "target"
        work.mkdir()
        for name in ("Cargo.toml", "Cargo.lock", ".cargo/config.toml", "rust-toolchain.toml",
                     "crates/allocator/Cargo.toml", "crates/allocator/src/lib.rs"):
          path = root / name
          path.parent.mkdir(parents=True, exist_ok=True)
          path.write_text("original\n")
        image = work / "tests.cpio"
        image.write_bytes(b"original archive")
        identity = "a" * 64
        (work / "identity").write_text(identity + "\n")
        with (patch.object(guest, "ROOT", root), patch.object(guest, "WORK", work),
              patch.dict(guest.os.environ, {"ALLOCATBELT_GUEST_SOURCE_REVISION": "1" * 40})):
          (work / "payload.json").write_text(json.dumps({
            "format": 1, "source": guest.source_fingerprint("key"),
            "identity": identity, "archive": guest.digest(image),
          }))
          self.assertEqual(guest.validate_payload("key"), identity)
          key = "key"
          if changed == "source":
            (root / "crates/allocator/src/lib.rs").write_text("new implementation\n")
          elif changed == "toolchain":
            (root / "rust-toolchain.toml").write_text("new toolchain\n")
          elif changed == "revision":
            guest.os.environ["ALLOCATBELT_GUEST_SOURCE_REVISION"] = "2" * 40
          elif changed == "archive":
            image.write_bytes(b"different archive")
          elif changed == "identity":
            (work / "identity").write_text("b" * 64 + "\n")
          else:
            key = "different guest recipe"
          with self.assertRaises(ValueError):
            guest.validate_payload(key)

  def test_payload_attributes_do_not_require_vectors(self):
    guest.validate_elf_attributes('Tag_RISCV_arch: "rv64i2p1_m2p0_a2p1_f2p2_d2p2_c2p0"', "test")
    for attributes in ('Tag_RISCV_arch: "rv64i2p1_v1p0"',
                       'Tag_RISCV_arch: "rv64i2p1_zve64d1p0"', ""):
      with self.assertRaises(ValueError):
        guest.validate_elf_attributes(attributes, "test")


if __name__ == "__main__":
  unittest.main()
