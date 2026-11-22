#!/usr/bin/env python3
"""Print a cs_sensor's pairing code (spec 04 section 3.1).

The code holds the sensor's root key, so treat it like one: this script prints it
on request instead of the build logging it.

    python3 devtools/cs_pairing_code.py --dev-eui c5c5000000000101 --root-key <32 hex>
    python3 devtools/cs_pairing_code.py --secrets secrets.yaml   # cs_dev_eui, cs_root_key

Requires: cryptography (pip install cryptography), for spec/tools/csframe.py.
"""

from __future__ import annotations

import argparse
import os
import re
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "spec", "tools"))
import csframe as cs  # noqa: E402


def read_secrets(path: str) -> dict[str, str]:
    """The flat `key: value` lines of an ESPHome secrets.yaml."""
    out = {}
    with open(path) as f:
        for line in f:
            m = re.match(r"^\s*([A-Za-z0-9_]+)\s*:\s*['\"]?([^'\"#\s]+)['\"]?", line)
            if m:
                out[m.group(1)] = m.group(2)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--dev-eui", help="16 hex digits")
    ap.add_argument("--root-key", help="32 hex digits")
    ap.add_argument("--secrets", help="read cs_dev_eui and cs_root_key from this secrets.yaml")
    ap.add_argument("--region", default="US915")
    ap.add_argument("--profile", default="ESPHOME", help="device profile id (cs_sensor's default: ESPHOME)")
    args = ap.parse_args()

    dev_eui, root_key = args.dev_eui, args.root_key
    if args.secrets:
        secrets = read_secrets(args.secrets)
        dev_eui = dev_eui or secrets.get("cs_dev_eui")
        root_key = root_key or secrets.get("cs_root_key")
    try:
        eui, key = bytes.fromhex(dev_eui or ""), bytes.fromhex(root_key or "")
    except ValueError:
        ap.error("dev_eui and root_key must be hex")
    if len(eui) != 8 or len(key) != 16:
        ap.error("need an 8-byte dev_eui and a 16-byte root key (--dev-eui/--root-key or --secrets)")
    print(cs.qr_encode(eui, key, args.region.upper(), args.profile.upper()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
