#!/usr/bin/env python3
"""Build and boot a pinned offline RISC-V guest; never use it for timings."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
ASSETS = json.loads((HERE / "assets.json").read_text())
WORK = ROOT / "target/riscv-guest"
SOURCE = WORK / "source"
OUTPUT = WORK / "assets"


def digest(path):
  with path.open("rb") as stream:
    return hashlib.file_digest(stream, "sha256").hexdigest()


def command(args, **kwargs):
  return subprocess.run(args, check=True, **kwargs)


def input_key():
  h = hashlib.sha256()
  for path in sorted(HERE.rglob("*")):
    if path.is_file() and "__pycache__" not in path.parts:
      h.update(str(path.relative_to(HERE)).encode() + b"\0")
      h.update(path.read_bytes())
  # Buildroot's host tools contain absolute paths; do not relocate this cache.
  h.update(str(ROOT).encode())
  for args in (["gcc", "--version"], ["ld", "--version"],
               ["make", "--version"], ["dpkg-query", "-W"]):
    h.update(command(args, capture_output=True).stdout)
  return h.hexdigest()


def configuration(path):
  return dict(line.split("=", 1) for line in path.read_text().splitlines()
              if line and not line.startswith("#") and "=" in line)


def check_config():
  values = configuration(OUTPUT / ".config")
  expected = {
    "BR2_RISCV_64": "y", "BR2_RISCV_ISA_RVC": "y",
    "BR2_RISCV_ABI_LP64D": "y", "BR2_TOOLCHAIN_BUILDROOT_MUSL": "y",
    "BR2_STATIC_LIBS": "y", "BR2_LINUX_KERNEL_CUSTOM_VERSION_VALUE": '"7.0"',
    "BR2_PACKAGE_HOST_LINUX_HEADERS_CUSTOM_7_0": "y",
    "BR2_SYSTEM_DHCP": '""', "BR2_RISCV_ISA_EXTRA": '""',
    "BR2_TARGET_ROOTFS_CPIO": "y", "BR2_DOWNLOAD_FORCE_CHECK_HASHES": "y",
  }
  for key, value in expected.items():
    if values.get(key) != value:
      raise ValueError(f"incorrect guest configuration: {key}")
  if values.get("BR2_RISCV_ISA_RVV") == "y":
    raise ValueError("guest userspace must not require V")
  if values.get("BR2_PACKAGE_HOST_LINUX_HEADERS_CUSTOM_6_18") == "y":
    raise ValueError("guest kernel headers must match Linux 7.0")


def asset_files():
  files = [OUTPUT / ".config"]
  for directory in (OUTPUT / "images", OUTPUT / "host"):
    files.extend(path for path in directory.rglob("*") if path.is_file() or path.is_symlink())
  return sorted(files)


def asset_records():
  records = {}
  for path in asset_files():
    relative = str(path.relative_to(OUTPUT))
    records[relative] = {"symlink": os.readlink(path)} if path.is_symlink() else {
      "sha256": digest(path), "mode": path.stat().st_mode & 0o777,
    }
  return records


def validate_assets(key):
  record = json.loads((OUTPUT / "integrity.json").read_text())
  if record["key"] != key or record["files"] != asset_records():
    raise ValueError("guest cache identity or contents differ")
  check_config()
  for name in ("Image", "rootfs.cpio", "fw_dynamic.bin"):
    if not (OUTPUT / "images" / name).is_file():
      raise ValueError(f"missing guest image {name}")


def build():
  key = input_key()
  if (OUTPUT / "integrity.json").exists():
    validate_assets(key)
    print("Validated cached guest assets")
    return
  WORK.mkdir(parents=True, exist_ok=True)
  archive = WORK / "buildroot.tar.xz"
  if not archive.exists():
    command(["curl", "--fail", "--location", "--retry", "3", "--max-time", "180",
             ASSETS["buildroot"]["url"], "--output", str(archive)])
  if digest(archive) != ASSETS["buildroot"]["sha256"]:
    raise ValueError("Buildroot archive SHA-256 differs")
  if SOURCE.exists():
    shutil.rmtree(SOURCE)
  unpack = WORK / "unpack"
  if unpack.exists():
    shutil.rmtree(unpack)
  unpack.mkdir()
  with tarfile.open(archive) as tar:
    # The SHA-256-verified source includes intentional absolute skeleton
    # symlinks. tar_filter permits those while rejecting path traversal.
    tar.extractall(unpack, filter="tar")
  (unpack / f'buildroot-{ASSETS["buildroot"]["version"]}').rename(SOURCE)
  base = ["make", "-C", str(SOURCE), f"O={OUTPUT}", f"BR2_EXTERNAL={HERE}"]
  command(base + ["allocatbelt_guest_defconfig"])
  check_config()
  # A cold build gets its own deadline inside the workflow's 120-minute limit.
  command(["timeout", "--kill-after=30", "6000"] + base + [f"-j{min(os.cpu_count() or 2, 4)}"])
  check_config()
  kernel = configuration(OUTPUT / "build/linux-7.0/.config")
  for required in ("RISCV_ISA_V", "SMP", "BLK_DEV_INITRD", "DEVTMPFS", "PROC_FS",
                   "SYSFS", "SYSCTL", "FUTEX", "SECCOMP", "SECCOMP_FILTER", "TMPFS",
                   "SERIAL_8250", "SERIAL_8250_CONSOLE", "SERIAL_OF_PLATFORM"):
    if kernel.get(f"CONFIG_{required}") != "y":
      raise ValueError(f"kernel lacks required guest support: {required}")
  for disabled in ("MODULES", "DRM", "SOUND", "WLAN", "BT", "USB_SUPPORT",
                   "MEDIA_SUPPORT", "STAGING", "SCSI", "ATA", "NVME_CORE",
                   "INFINIBAND", "CAN", "NFC", "NETDEVICES"):
    if kernel.get(f"CONFIG_{disabled}") in ("y", "m"):
      raise ValueError(f"kernel retains unused peripheral family: {disabled}")
  if "m" in kernel.values():
    raise ValueError("minimal guest unexpectedly includes loadable modules")
  (OUTPUT / "integrity.json").write_text(json.dumps({
    "key": key, "files": asset_records(),
  }, sort_keys=True) + "\n")
  validate_assets(key)


def cargo_artifacts(args, env):
  result = subprocess.run(["cargo", "+1.99.0", "test", "--release", "--locked",
                    "--target", ASSETS["target"], "--no-run", "--message-format=json"] + args,
                   cwd=ROOT, env=env, capture_output=True, text=True)
  # Cargo diagnostics on stderr remain visible even when artifact JSON is parsed.
  sys.stderr.write(result.stderr)
  if result.returncode:
    for line in result.stdout.splitlines():
      if line.startswith("{"):
        item = json.loads(line)
        if item.get("reason") == "compiler-message":
          sys.stderr.write(item["message"].get("rendered") or "")
    raise ValueError(f"cross-building guest tests failed ({result.returncode})")
  return {item["target"]["name"]: Path(item["executable"])
          for line in result.stdout.splitlines() if line.startswith("{")
          for item in [json.loads(line)]
          if item.get("reason") == "compiler-artifact" and item.get("executable")}


def validate_elf_attributes(attributes, name):
  architectures = re.findall(r'Tag_RISCV_arch:\s*"([^"]+)"', attributes)
  if len(architectures) != 1 or not architectures[0].startswith("rv64"):
    raise ValueError(f"{name} lacks an unambiguous RV64 ISA attribute")
  extensions = architectures[0].split("_")[1:]
  if any(extension.startswith(("v", "zv")) for extension in extensions):
    raise ValueError(f"{name} requires V in its baseline ELF architecture")


def source_fingerprint(key):
  revision = os.environ.get("ALLOCATBELT_GUEST_SOURCE_REVISION")
  if revision is None:
    revision = command(["git", "rev-parse", "HEAD"], cwd=ROOT,
                       capture_output=True, text=True).stdout.strip()
  if not re.fullmatch(r"[0-9a-f]{40}", revision):
    raise ValueError("guest payload needs an immutable source revision")
  source = hashlib.sha256()
  source.update(revision.encode() + b"\0" + key.encode())
  files = [ROOT / "Cargo.toml", ROOT / "Cargo.lock", ROOT / ".cargo/config.toml",
           ROOT / "rust-toolchain.toml"]
  files.extend(path for path in (ROOT / "crates").rglob("*")
               if path.is_file() and (path.suffix == ".rs" or path.name == "Cargo.toml"))
  for path in sorted(files):
    source.update(str(path.relative_to(ROOT)).encode() + b"\0" + digest(path).encode())
  return source.hexdigest()


def validate_payload(key):
  record = json.loads((WORK / "payload.json").read_text())
  identity = (WORK / "identity").read_text().strip()
  if (record.get("format") != 1 or not re.fullmatch(r"[0-9a-f]{64}", identity) or
      record.get("identity") != identity or record.get("source") != source_fingerprint(key) or
      record.get("archive") != digest(WORK / "tests.cpio")):
    raise ValueError("guest payload differs from the current source or exact archive")
  return identity


def payload():
  key = input_key()
  validate_assets(key)
  source = source_fingerprint(key)
  env = os.environ.copy()
  env.pop("CARGO_ENCODED_RUSTFLAGS", None)
  env.pop("CARGO_BUILD_RUSTFLAGS", None)
  env["RUSTFLAGS"] = "-C target-feature=+crt-static"
  env["CARGO_TARGET_DIR"] = str(WORK / "rust")
  env["CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_MUSL_LINKER"] = str(
    OUTPUT / "host/bin/riscv64-buildroot-linux-musl-gcc")
  allocator = cargo_artifacts(["-p", "allocatbelt", "--features", "experimental-riscv-rvv",
                              "--lib", "--test", "platform", "--test", "experimental_isa",
                              "--test", "riscv_vector_control"], env)
  runtime = cargo_artifacts(["-p", "allocatbelt", "--features", "runtime", "--lib"], env)
  binaries = {"allocator-lib": allocator.pop("allocatbelt"),
              "runtime-lib": runtime["allocatbelt"], **allocator}
  stage = WORK / "payload"
  if stage.exists():
    shutil.rmtree(stage)
  (stage / "guest").mkdir(parents=True)
  for name, path in binaries.items():
    elf = command(["readelf", "-l", str(path)], capture_output=True, text=True).stdout
    if "INTERP" in elf:
      raise ValueError(f"{name} needs a dynamic interpreter")
    attributes = command(["readelf", "-A", str(path)], capture_output=True, text=True).stdout
    validate_elf_attributes(attributes, name)
    shutil.copy2(path, stage / "guest" / name)
  identity = hashlib.sha256()
  if source != source_fingerprint(input_key()):
    raise ValueError("guest sources changed while compiling its payload")
  identity.update(source.encode())
  for name in sorted(binaries):
    identity.update(name.encode() + b"\0" + digest(stage / "guest" / name).encode())
  value = identity.hexdigest()
  (stage / "guest/identity").write_text(f"identity={value}\n")
  shutil.copy2(HERE / "guest-init.sh", stage / "init")
  (stage / "init").chmod(0o755)
  # A concatenated newc archive overlays /init and adds this exact test payload.
  archive = command(["bash", "-o", "pipefail", "-c",
                     "find . -print0 | LC_ALL=C sort -z | cpio --null -o -H newc --owner=0:0"],
                    cwd=stage, capture_output=True)
  image = WORK / "tests.cpio"
  with image.open("wb") as stream:
    stream.write((OUTPUT / "images/rootfs.cpio").read_bytes())
    stream.write(archive.stdout)
  (WORK / "identity").write_text(value + "\n")
  (WORK / "payload.json").write_text(json.dumps({
    "format": 1, "source": source, "identity": value, "archive": digest(image),
  }, sort_keys=True) + "\n")


def validate_log(log, scenario, identity):
  text = log.replace("\r", "")
  expected = ["platform", "region", "runtime"] + (
    ["dispatch-off"] if scenario == "v-off" else
    ["rvv-kernel", "dispatch-on", "dispatch-disabled", "thread-policy"])
  protocol = [line for line in text.splitlines() if line.startswith("ALLOCATBELT_GUEST ")]
  wanted = []
  for label in expected:
    wanted.extend([f"ALLOCATBELT_GUEST BEGIN {scenario} {identity} {label}",
                   f"ALLOCATBELT_GUEST PASS {scenario} {identity} {label}"])
  wanted.append(f"ALLOCATBELT_GUEST COMPLETE {scenario} {identity}")
  if protocol != wanted:
    raise ValueError(f"{scenario}: missing, duplicate, failed or mismatched guest result")
  summary_pattern = re.compile(
    r"test result: ok\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored; "
    r"([0-9]+) measured; ([0-9]+) filtered out;"
    r"(?: finished in [0-9]+(?:\.[0-9]+)?s)?")
  total_summaries = 0
  for label in expected:
    begin = f"ALLOCATBELT_GUEST BEGIN {scenario} {identity} {label}"
    end = f"ALLOCATBELT_GUEST PASS {scenario} {identity} {label}"
    segment = text.split(begin, 1)[1].split(end, 1)[0]
    summaries = [line for line in segment.splitlines()
                 if line.lstrip().startswith("test result:")]
    # RVV runs a saved-kernel child, and thread-policy runs two children.
    # Every subprocess and its parent must emit a successful summary.
    count = {"rvv-kernel": 2, "thread-policy": 3}.get(label, 1)
    if len(summaries) != count:
      raise ValueError(f"{scenario}: {label} did not execute its required coverage")
    for line in summaries:
      match = summary_pattern.fullmatch(line)
      if (match is None or int(match[1]) < 1 or int(match[2]) or
          int(match[3]) or int(match[4])):
        raise ValueError(f"{scenario}: {label} has an invalid or incomplete test result")
    total_summaries += count
  if sum(line.lstrip().startswith("test result:") for line in text.splitlines()) != total_summaries:
    raise ValueError(f"{scenario}: test result outside its invocation")
  if re.search(r"Kernel panic|Oops:|test result: FAILED|[1-9][0-9]* ignored;", text):
    raise ValueError(f"{scenario}: guest failure or ignored tests")


def boot():
  key = input_key()
  validate_assets(key)
  identity = validate_payload(key)
  qemu = OUTPUT / "host/bin/qemu-system-riscv64"
  for scenario, cpu in (("v-off", "rv64,v=false"), ("v-on", "rv64,v=true,vlen=128")):
    args = ["timeout", "--kill-after=10", str(ASSETS["guest"]["deadline_seconds"]),
            str(qemu), "-machine", "virt", "-accel", "tcg", "-cpu", cpu,
            "-smp", "4", "-m", "2048", "-display", "none", "-monitor", "none",
            "-serial", "stdio", "-nic", "none", "-no-reboot",
            "-bios", str(OUTPUT / "images/fw_dynamic.bin"),
            "-kernel", str(OUTPUT / "images/Image"), "-initrd", str(WORK / "tests.cpio"),
            "-append", f"console=ttyS0 rdinit=/init panic=-1 allocatbelt_scenario={scenario}"]
    result = subprocess.run(args, capture_output=True, text=True)
    print(result.stdout, end="")
    sys.stderr.write(result.stderr)
    if result.returncode != 0:
      raise ValueError(f"{scenario}: QEMU failed or timed out ({result.returncode})")
    validate_log(result.stdout, scenario, identity)


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("action", choices=["key", "build", "payload", "boot"])
  action = parser.parse_args().action
  if action == "key":
    print(input_key())
  else:
    {"build": build, "payload": payload, "boot": boot}[action]()


if __name__ == "__main__":
  main()
