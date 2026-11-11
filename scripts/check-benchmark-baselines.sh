#!/usr/bin/env bash
# Verify that comparator dependency graphs use matched versions and that the
# standard mimalloc build cannot inherit the secure baseline's Cargo features.
set -euo pipefail
cd "$(dirname "$0")/.."
tmp="$(mktemp -d "${TMPDIR:-/tmp}/allocatbelt-baselines.XXXXXX")"
trap 'rm -rf -- "$tmp"' EXIT
cargo metadata --locked --format-version 1 >"$tmp/workspace.json"
cargo metadata --locked --format-version 1 \
  --manifest-path bench/standard-mimalloc/Cargo.toml >"$tmp/standard.json"
python3 - "$tmp/workspace.json" "$tmp/standard.json" <<'PY'
import json
import sys
import tomllib

secure, standard = [json.load(open(path, encoding="utf-8")) for path in sys.argv[1:]]

def package_features(graph, name):
    packages = [p for p in graph["packages"] if p["name"] == name]
    if len(packages) != 1:
        raise SystemExit(f"expected exactly one {name}, found {len(packages)}")
    package = packages[0]
    nodes = [n for n in graph["resolve"]["nodes"] if n["id"] == package["id"]]
    if len(nodes) != 1:
        raise SystemExit(f"missing resolved {name}")
    return package, set(nodes[0]["features"])

for name in ("mimalloc", "libmimalloc-sys"):
    _, secure_features = package_features(secure, name)
    _, standard_features = package_features(standard, name)
    if "secure" not in secure_features or "secure" in standard_features:
        raise SystemExit(f"incorrect secure/standard feature separation for {name}")
    if secure_features - {"secure"} != standard_features:
        raise SystemExit(f"additional comparator feature mismatch for {name}")

# Compiler helpers and every shared registry dependency must match too: a
# difference here would introduce a second change beyond mimalloc hardening.
with open("Cargo.lock", "rb") as source:
    workspace_lock = tomllib.load(source)
with open("bench/standard-mimalloc/Cargo.lock", "rb") as source:
    standard_lock = tomllib.load(source)
versions = {
    p["name"]: (p["version"], p["source"], p["checksum"])
    for p in workspace_lock["package"] if p.get("source", "").startswith("registry+")
}
for p in standard_lock["package"]:
    if p["name"] in versions and p.get("source", "").startswith("registry+"):
        if versions[p["name"]] != (p["version"], p["source"], p["checksum"]):
            raise SystemExit(f"comparator dependency provenance mismatch: {p['name']}")
print("ok: matched comparator dependencies; standard mimalloc excludes secure features")
PY
