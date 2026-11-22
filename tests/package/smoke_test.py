"""Smoke test of the installed connectsensors wheel's public API.

Run it with the wheel installed in a clean venv and from outside the checkout, so the
import resolves to the wheel: python -I smoke_test.py <repo root>
"""

from __future__ import annotations

import filecmp
import json
import os
import sys

import connectsensors as cs


def main(root: str) -> int:
    vectors = os.path.join(root, "spec", "vectors")
    here = os.path.dirname(cs.__file__)
    assert not os.path.abspath(here).startswith(os.path.abspath(root) + os.sep), f"imported from the checkout: {here}"
    shipped = os.path.join(here, "_csframe.py")
    assert filecmp.cmp(shipped, os.path.join(root, "spec", "tools", "csframe.py"), shallow=False), \
        "the wheel's _csframe.py differs from spec/tools/csframe.py"
    assert os.path.exists(os.path.join(here, "py.typed"))

    # Frames: open a vector frame and seal it again byte for byte.
    with open(os.path.join(vectors, "frame-v1.json")) as f:
        fv = json.load(f)
    inputs = fv["inputs"]
    join = next(c for c in fv["frames"] if c["name"] == "join")
    keys = cs.keys_from(bytes.fromhex(inputs["k_root"]), bytes.fromhex(inputs["dev_eui"]))
    frame = bytes.fromhex(join["frame"])
    h, pt = cs.open_frame(keys, frame)
    assert (h.ftype, h.fcnt, pt.hex()) == (cs.T_JOIN, join["fcnt"], join["plaintext"])
    assert cs.seal(keys, h.ftype, h.net_tag, h.dev_tag, h.fcnt, pt) == frame
    route = cs.derive_net_route(bytes.fromhex(inputs["k_net"]))
    epoch = cs.epoch_of(inputs["time"])
    assert cs.net_tag(route, epoch).hex() == fv["derived"]["net_tag"][str(epoch)]
    print(f"ok   frame {join['name']}")

    # Pairing codes.
    with open(os.path.join(vectors, "pairing-v1.json")) as f:
        valid = json.load(f)["valid"][0]
    assert cs.qr_parse(valid["code"]) == valid["parsed"]
    print("ok   pairing code")

    # A ServerLink session: an unknown boot gets a HELLO_REQUEST, the HELLO echoing its
    # nonce switches the session, and the SERVER_STATUS answer opens on the proxy side.
    key, pid, boot = bytes(range(16)), bytes.fromhex("348518fffe000001"), 0x1A2B3C4D
    link = cs.ServerLink(lambda: 0x5EED0001)

    def hello(seq: int, nonce: int = 0) -> bytes:
        body = cs.hello_body(cs.CAP_DOWNLINK, "US915", 918_500_000, 9, 500, 1, [0] * 7, 5, "smoke", nonce)
        return cs.envelope(key, cs.M_HELLO, pid, boot, seq, body)

    got = link.receive(cs.open_envelope(key, hello(1)), 0)
    assert got == {"result": "hello_request", "nonce": 0x5EED0001}, got
    got = link.receive(cs.open_envelope(key, hello(2, got["nonce"])), 10)
    assert got == {"result": "switched"}, got
    tags = [cs.net_tag(route, e) for e in (epoch - 1, epoch, epoch + 1)]
    status = cs.envelope(key, cs.M_SERVER_STATUS, pid, boot, link.next_seq(),
                         cs.server_status_body(inputs["time"], tags, 2))
    m = cs.open_envelope(key, status)
    s = cs.parse_server_status(bytes.fromhex(m["body"]))
    assert (m["type"], m["seq"], s["hello_seq"], s["tags"]) == (cs.M_SERVER_STATUS, 1, 2, tags)
    print("ok   ServerLink HELLO / SERVER_STATUS")

    # Bodies from a proxy: round trips, and malformed ones raise ValueError.
    up = cs.uplink_body(123, -97.5, 6.3, 0x81, frame)
    u = cs.parse_uplink(up)
    assert (u["rx_time_us"], u["rssi"], u["snr"], u["flags"], u["frame"]) == (123, -97.5, 6.3, 0x81, frame), u
    tx = cs.tx_result_body(2, 0, -1800)
    assert cs.parse_tx_result(tx) == {"downlink_seq": 2, "result": 0, "offset_us": -1800}
    for parse, bad in ((cs.parse_uplink, b""), (cs.parse_uplink, up[:10]), (cs.parse_uplink, up[:-1]),
                       (cs.parse_uplink, up + b"\x00"), (cs.parse_tx_result, tx[:-1])):
        try:
            parse(bad)
        except ValueError:
            continue
        raise AssertionError(f"{parse.__name__} accepted {bad.hex()}")
    print("ok   UPLINK / TX_RESULT bodies")

    # Airtime: the reference table of 01 section 5.1, to its 0.1 ms.
    table = {23: (51.5, 205.8), 31: (61.7, 246.8), 55: (87.3, 349.2), 65: (97.5, 390.1), 86: (123.1, 492.5)}
    for n, (us, eu) in table.items():
        assert round(cs.region_airtime_ms("US915", n), 1) == us, (n, cs.region_airtime_ms("US915", n))
        assert round(cs.region_airtime_ms("EU868", n), 1) == eu, (n, cs.region_airtime_ms("EU868", n))
        assert cs.airtime_ms(n, *cs.REGIONS["US915"]) == cs.region_airtime_ms("US915", n)
    assert (cs.SENSOR_AIRTIME_MS_PER_HOUR, cs.PROXY_AIRTIME_MS_PER_HOUR) == (36_000, 72_000)
    for region in ("AU915", "us915", ""):
        try:
            cs.region_airtime_ms(region, 23)
        except ValueError:
            continue
        raise AssertionError(f"region_airtime_ms accepted {region!r}")
    print("ok   airtime")

    print(f"connectsensors {cs.__version__}: smoke test passed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
