#!/usr/bin/env python3
"""Real-file tests for the Source5 controller's optional pinned stable read."""
from pathlib import Path
import stat
import tempfile
import types
import sys
import unittest

SCRIPTS = Path(__file__).resolve().parent


def load_controller():
    path = SCRIPTS / "application-source5-campaign.py"
    module = types.ModuleType("source5_pinned_reader_test_target")
    module.__file__ = str(path)
    module.__package__ = ""
    sys.modules[module.__name__] = module
    exec(compile(path.read_bytes(), str(path), "exec", dont_inherit=True), module.__dict__)
    return module


class Source5PinnedStableReadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.controller = load_controller()

    def test_pinned_read_preserves_the_same_real_file_bytes_and_identity(self):
        with tempfile.TemporaryDirectory(prefix="source5-pinned-read-") as temp:
            path = Path(temp) / "input.json"
            raw = b'{"value":1}\n'
            path.write_bytes(raw)
            path.chmod(0o600)
            expected = self.controller.sha256(raw)
            legacy_raw, legacy_sha, legacy_info = self.controller.read_stable(path, "input", len(raw))
            pinned_raw, pinned_sha, pinned_info = self.controller.read_stable(path, "input", len(raw), expected)
            self.assertEqual((legacy_raw, legacy_sha), (raw, expected))
            self.assertEqual((pinned_raw, pinned_sha), (raw, expected))
            self.assertEqual((pinned_info.st_dev, pinned_info.st_ino),
                             (legacy_info.st_dev, legacy_info.st_ino))
            self.assertTrue(stat.S_ISREG(pinned_info.st_mode))

    def test_changed_bytes_with_a_valid_old_pin_are_rejected(self):
        with tempfile.TemporaryDirectory(prefix="source5-pinned-read-drift-") as temp:
            path = Path(temp) / "input.json"
            original = b'{"value":1}\n'
            path.write_bytes(original)
            pin = self.controller.sha256(original)
            replacement = b'{"value":2}\n'
            path.write_bytes(replacement)
            with self.assertRaisesRegex(self.controller.Source5CampaignError, "expected raw pin"):
                self.controller.read_stable(path, "input", len(replacement), pin)
            self.assertEqual(path.read_bytes(), replacement)

    def test_malformed_pin_is_rejected_before_any_file_read(self):
        with tempfile.TemporaryDirectory(prefix="source5-pinned-read-bad-pin-") as temp:
            missing = Path(temp) / "missing.json"
            for pin in ("", "x" * 64, "A" * 64, True, 1):
                with self.subTest(pin=pin):
                    with self.assertRaisesRegex(self.controller.Source5CampaignError, "raw pin is malformed"):
                        self.controller.read_stable(missing, "input", 16, pin)
            self.assertFalse(missing.exists())


if __name__ == "__main__":
    unittest.main()
