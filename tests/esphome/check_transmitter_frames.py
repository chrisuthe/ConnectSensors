"""Check that the test transmitter's hand-copied frames match spec/vectors/frame-v1.json.

Every `transmit` script call whose hex starts with the frame magic must be a
vector frame byte for byte, its button label must name that frame's type, and each expected
vector must be sent by some button.
"""

import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
EXAMPLE = os.path.join(ROOT, "examples", "test-transmitter-heltec-v3.yaml")
VECTORS = os.path.join(ROOT, "spec", "vectors", "frame-v1.json")

MAGIC = 0xC5
# Button label (the note_sent `what:`) for each frame type the transmitter sends.
LABELS = {2: "DATA_CONF", 3: "HEARTBEAT", 5: "JOIN", 8: "DOWNLINK"}
EXPECTED = {"join", "data_confirmed", "heartbeat", "downlink_ack"}

SEND = re.compile(r"id: transmit\s*\n\s*hex:\s*\"([0-9A-Fa-f]*)\"\s*\n\s*what:\s*\"([^\"]*)\"")


def main():
    with open(VECTORS) as f:
        vectors = {bytes.fromhex(v["frame"]): v for v in json.load(f)["frames"]}
    with open(EXAMPLE) as f:
        sends = SEND.findall(f.read())

    errors = []
    sent = set()
    for data, label in sends:
        frame = bytes.fromhex(data)
        if not frame or frame[0] != MAGIC:
            continue
        vector = vectors.get(frame)
        if vector is None:
            errors.append(f"{label}: frame {frame.hex()} is not in frame-v1.json")
            continue
        if LABELS.get(vector["type"]) != label:
            errors.append(f"{label}: sends vector {vector['name']} (type {vector['type']})")
        sent.add(vector["name"])
    for name in sorted(EXPECTED - sent):
        errors.append(f"no button sends vector {name}")

    for e in errors:
        print(f"FAIL {e}")
    if errors:
        return 1
    print(f"ok: {len(sent)} transmitter frames match frame-v1.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
