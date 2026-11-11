#!/usr/bin/env python3
"""Data-only regression for actual Source Archive sharded object-root naming."""
from __future__ import annotations
import ast
import copy
import importlib.util
from pathlib import Path, PurePosixPath
import sys
import unittest


def load_script(filename: str, name: str):
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("missing test dependency")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


class SourceAArchiveRootTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.chronology = load_script("application-campaign-chronology.py", "sourcea_archive_root_target")
        cls.archive = load_script("application-source5-evidence-archive.py", "sourcea_archive_root_archive")

    def _object(self, origin: str, root: str = "/root-archive/campaign/owner/source5"):
        raw_sha = "a" * 64
        object_id = self.archive._object_identity(origin, raw_sha)
        return {"origin_path": origin, "raw_sha256": raw_sha, "object_id": object_id,
                "object_pin": {"path": str(PurePosixPath(root) / "objects" / object_id)}}

    def test_actual_archive_sharded_objects_have_one_source5_root(self):
        rows = [self._object("/old/output/processes.json"),
                self._object("/old/output/metrics-λ.json")]
        for row in rows:
            self.assertEqual(len(PurePosixPath(row["object_id"]).parts), 2)
            self.assertEqual(PurePosixPath(row["object_pin"]["path"]).parents[1].name, "objects")
        self.assertEqual(self.chronology._source5_construction_archive_root_from_objects(
            rows, self.archive), "/root-archive/campaign/owner/source5")

    def test_mixed_roots_and_wrong_shard_names_are_rejected(self):
        row = self._object("/old/output/processes.json")
        wrong = copy.deepcopy(row)
        path = PurePosixPath(wrong["object_pin"]["path"])
        bucket = "ff" if path.parent.name != "ff" else "00"
        wrong["object_pin"]["path"] = str(path.parent.parent / bucket / path.name)
        wrong_id = copy.deepcopy(row)
        wrong_id["object_id"] = "00/" + "b" * 64 + "-" + "a" * 64 + ".bin"
        for rows in ([row, self._object("/old/output/other.json", "/different/campaign/owner/source5")],
                     [wrong], [wrong_id]):
            with self.subTest(rows=rows), self.assertRaises(self.chronology.ChronologyError):
                self.chronology._source5_construction_archive_root_from_objects(rows, self.archive)

    def test_malformed_rows_are_rejected_instead_of_ignored(self):
        row = self._object("/old/output/processes.json")
        for bad in ([], [row, {}], [None], [{"object_pin": {"path": "/source5/objects"}}]):
            with self.subTest(rows=bad), self.assertRaises(self.chronology.ChronologyError):
                self.chronology._source5_construction_archive_root_from_objects(bad, self.archive)
        for path in ("relative/file", "/root-archive/campaign/owner/source5/../objects/file"):
            wrong = copy.deepcopy(row)
            wrong["object_pin"]["path"] = path
            with self.subTest(path=path), self.assertRaises(self.chronology.ChronologyError):
                self.chronology._source5_construction_archive_root_from_objects([wrong], self.archive)

    def test_readback_uses_the_selected_archive_for_root_derivation(self):
        tree = ast.parse(Path(__file__).with_name("application-campaign-chronology.py").read_text())
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_source5_construction_readback_inputs")
        calls = [n for n in ast.walk(function) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "_source5_construction_archive_root_from_objects"]
        self.assertEqual(len(calls), 1)
        self.assertEqual(ast.dump(calls[0].args[1]), ast.dump(ast.parse('session.modules["archive"]', mode="eval").body))


if __name__ == "__main__":
    unittest.main()
