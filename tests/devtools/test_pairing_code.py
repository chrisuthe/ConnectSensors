#!/usr/bin/env python3
"""devtools/cs_pairing_code.py reproduces the spec's pairing-code vector."""

import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "spec", "tools"))
import csframe as cs  # noqa: E402

SCRIPT = os.path.join(ROOT, "devtools", "cs_pairing_code.py")
want = cs.pairing_vectors()["valid"][0]["code"]


def run(*args):
    return subprocess.run([sys.executable, "-I", SCRIPT, *args], capture_output=True, text=True)


failures = 0
r = run("--dev-eui", cs.DEV_EUI.hex(), "--root-key", cs.K_ROOT.hex(), "--profile", "CS.CONTACT-1")
if r.stdout.strip() != want:
    failures += 1
    print(f"FAIL arguments: got {r.stdout.strip()!r}, want {want!r} {r.stderr}")
with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
    f.write(f'wifi_ssid: "x"\ncs_dev_eui: "{cs.DEV_EUI.hex()}"\ncs_root_key: {cs.K_ROOT.hex()}  # comment\n')
r = run("--secrets", f.name, "--profile", "CS.CONTACT-1")
os.unlink(f.name)
if r.stdout.strip() != want:
    failures += 1
    print(f"FAIL secrets: got {r.stdout.strip()!r} {r.stderr}")
if run("--dev-eui", "00", "--root-key", "11").returncode == 0:
    failures += 1
    print("FAIL short identity accepted")
print("all checks pass" if failures == 0 else f"{failures} failures")
sys.exit(1 if failures else 0)
