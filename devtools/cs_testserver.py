#!/usr/bin/env python3
"""ConnectSensors development server for testing proxies.

Not the real network server. It speaks the proxy envelope (spec 05) to any
number of proxies sharing one key, prints what they hear, decrypts frames from
the test-vector device (spec/vectors/frame-v1.json), and with --ack answers
confirmed uplinks from that device with a real downlink in RX1. Copies of one
transmission are answered once; a sensor's retry is answered again (07 section 4).

    python3 devtools/cs_testserver.py                 # prints a fresh key
    python3 devtools/cs_testserver.py --key 5a5a...   # use a key you already set
    python3 devtools/cs_testserver.py --ack           # also exercise downlinks
    python3 devtools/cs_testserver.py --no-seq-seed   # server seq from 1, as after a real restart

Requires: cryptography (pip install cryptography)
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import socket
import struct
import sys
import time

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
SPEC = os.path.normpath(os.path.join(HERE, "..", "spec"))
sys.path.insert(0, os.path.join(SPEC, "tools"))
import csframe as cs  # noqa: E402

TYPE_NAMES = {0x1: "DATA", 0x2: "DATA_CONFIRMED", 0x3: "HEARTBEAT", 0x4: "HEARTBEAT_CONFIRMED",
              0x5: "JOIN", 0x6: "SYNC", 0x8: "DOWNLINK"}
CONFIRMED = {0x2, 0x4, 0x6}  # JOIN needs a key exchange; not answered here
TX_RESULTS = {0: "SENT", 1: "TOO_LATE", 2: "BUSY", 3: "DUTY_CYCLE", 4: "NOT_CAPABLE", 5: "INVALID",
              6: "RADIO_ERROR"}


def log(msg: str) -> None:
    print(time.strftime("%H:%M:%S ") + msg, flush=True)


class TestDevice:
    """The device from the frame test vectors, with root and session keys."""

    def __init__(self):
        with open(os.path.join(SPEC, "vectors", "frame-v1.json")) as f:
            v = json.load(f)
        i = v["inputs"]
        self.dev_eui = bytes.fromhex(i["dev_eui"])
        k_root = bytes.fromhex(i["k_root"])
        self.root = cs.keys_from(k_root, self.dev_eui)
        self.session = cs.keys_from(bytes.fromhex(v["derived"]["k_session"]), self.dev_eui)
        self.k_net_route = bytes.fromhex(v["derived"]["k_net_route"])
        self.fcnt_down = 1000  # above every downlink counter used in the vectors
        self.uplinks = cs.UplinkCollector(0)

    def net_tags(self, now: int) -> list[bytes]:
        e = cs.epoch_of(now)
        tags = [cs.net_tag(self.k_net_route, x) for x in (e - 1, e, e + 1)]
        # The vectors were made at a fixed time; include its tag so they are "ours" too.
        tags.append(cs.net_tag(self.k_net_route, cs.epoch_of(cs.T0)))
        return tags

    def open(self, frame: bytes):
        for name, keys in (("session", self.session), ("root", self.root)):
            try:
                h, pt = cs.open_frame(keys, frame)
                return name, keys, h, pt
            except Exception:
                continue
        return None


def seq_seed() -> int:
    """First server seq for a proxy session, minus one.

    The proxy follows a restarted server through the SERVER_STATUS echo (05 section
    3.2), so this isn't needed. It stays as extra protection: starting above the old
    instance's values closes the window in which the old instance's messages pass the
    proxy's check again (05 section 7), as long as that instance sent fewer messages
    to the proxy than seconds have passed since it started.
    """
    return int(time.time()) & 0xFFFFFFFF


class Proxy:
    def __init__(self, proxy_id: bytes):
        self.proxy_id = proxy_id
        self.link = cs.ServerLink(lambda: int.from_bytes(secrets.token_bytes(4), "big") or 1)
        self.addr = None


def describe_payload(ftype: int, pt: bytes) -> str:
    if ftype == cs.T_JOIN:
        return f"uflags={pt[0]:02x} sensor_pub={pt[1:].hex()[:16]}..."
    flags = pt[0]
    try:
        readings = cs.decode_readings(pt[1:])
        text = ", ".join(f"ch{r['channel']} {r['name']}={r['value']}" for r in readings)
    except ValueError as ex:
        text = f"invalid readings ({ex})"
    names = [n for b, n in ((cs.UF_DL_ACK, "DL_ACK"), (cs.UF_TIME_UNSURE, "TIME_UNSURE")) if flags & b]
    return f"[{' '.join(names) or 'no flags'}] {text or 'no readings'}"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=47800)
    ap.add_argument("--key", help="proxy key, 32 hex digits (default: generate one)")
    ap.add_argument("--ack", action="store_true", help="answer confirmed uplinks from the test device")
    ap.add_argument("--window", choices=("rx1", "rx2"), default="rx1")
    ap.add_argument("--no-seq-seed", action="store_true",
                    help="count the server seq from 1 in each session instead of seeding it from the clock")
    args = ap.parse_args()

    key = bytes.fromhex(args.key) if args.key else secrets.token_bytes(16)
    if len(key) != 16:
        print("--key must be 32 hex digits", file=sys.stderr)
        return 2
    if not args.key:
        log(f"Generated proxy key: {key.hex()}")
        log("Put it in the proxy's secrets.yaml as cs_proxy_key, or restart with --key.")

    device = TestDevice()
    proxies: dict[bytes, Proxy] = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", args.port))
    log(f"Listening on UDP {args.port}; downlinks {'on (' + args.window + ')' if args.ack else 'off'}")

    def send(p: Proxy, msg_type: int, body: bytes) -> None:
        seq = p.link.next_seq() & 0xFFFFFFFF
        sock.sendto(cs.envelope(key, msg_type, p.proxy_id, p.link.boot_id, seq, body), p.addr)

    while True:
        data, addr = sock.recvfrom(2048)
        try:
            m = cs.open_envelope(key, data)
        except ValueError as ex:
            log(f"{addr[0]}: rejected {len(data)} bytes ({ex})")
            continue
        pid = bytes.fromhex(m["proxy_id"])
        p = proxies.setdefault(pid, Proxy(pid))
        got = p.link.receive(m, int(time.monotonic() * 1000))
        if got["result"] == "hello_request":
            # Not our session's boot: ask for a HELLO echoing a nonce, at the source of
            # this message, without touching the session (05 section 3.2).
            sock.sendto(cs.envelope(key, cs.M_HELLO_REQUEST, pid, m["boot_id"], 0,
                                    cs.hello_request_body(got["nonce"])), addr)
            log(f"{pid.hex()}: message type 0x{m['type']:02x} from boot {m['boot_id']:08x}, "
                f"not this session's; sent HELLO_REQUEST")
            continue
        if got["result"] == "ignored":
            log(f"{pid.hex()}: ignored message type 0x{m['type']:02x} boot {m['boot_id']:08x} seq {m['seq']}")
            continue
        if got["result"] == "switched":
            if not args.no_seq_seed:
                p.link.seq = seq_seed()
            log(f"{pid.hex()}: session with boot {m['boot_id']:08x}, server seq from {p.link.seq + 1}")
        p.addr = addr
        body = bytes.fromhex(m["body"])
        now = int(time.time())

        if m["type"] == cs.M_HELLO:
            h = cs.parse_hello(body)
            log(f"{pid.hex()} HELLO {h['fw']}, {h['region']} {h['frequency_hz'] / 1e6:g} MHz SF{h['sf']} "
                f"{h['bw_khz']} kHz, up {h['uptime_s']}s, downlink {'yes' if h['caps'] & 1 else 'no'}, "
                f"loop gap {h['max_loop_gap_ms']} ms, "
                f"heard/fwd/dup/invalid/rl/tx_ok/tx_fail = {'/'.join(map(str, h['counters']))}")
            send(p, cs.M_SERVER_STATUS, cs.server_status_body(now, device.net_tags(now), m["seq"]))

        elif m["type"] == cs.M_UPLINK:
            rx_time, rssi, snr, flags, flen = struct.unpack(">QhhBB", body[:14])
            frame = body[14:14 + flen]
            h = cs.parse_header(frame)
            name = TYPE_NAMES.get(h.ftype, f"type {h.ftype}") if h else "invalid"
            line = (f"{pid.hex()} UPLINK {name} fcnt {h.fcnt if h else '?'} rssi {rssi / 10:.1f} "
                    f"snr {snr / 10:.1f}{' TS_UNCERTAIN' if flags & 1 else ''}")
            opened = device.open(frame) if h else None
            if opened is None:
                log(line + " (not the test device)")
                continue
            keyset, keys, h, pt = opened
            got = device.uplinks.receive(frame, int(time.monotonic() * 1000))
            if got["result"] == "copy":
                log(line + " test device: copy of the same transmission")
                continue
            log(line + f" test device ({keyset} keys, {got['counter']}): {describe_payload(h.ftype, pt)}")
            if args.ack and h.ftype in CONFIRMED and got["answer"]:
                device.fcnt_down += 1
                dl_pt = cs.downlink_payload(h.fcnt, now, 0)
                dl = cs.seal(keys, cs.T_DOWNLINK, h.net_tag, h.dev_tag, device.fcnt_down, dl_pt)
                offset = 1_000_000 if args.window == "rx1" else 3_000_000
                send(p, cs.M_DOWNLINK, cs.downlink_msg_body(rx_time, offset, dl))
                log(f"{pid.hex()} -> DOWNLINK seq {p.link.seq} answering fcnt {h.fcnt} in {args.window}")

        elif m["type"] == cs.M_TX_RESULT:
            seq, result, offset = struct.unpack(">IBi", body)
            log(f"{pid.hex()} TX_RESULT seq {seq}: {TX_RESULTS.get(result, result)}, "
                f"{offset / 1000:.1f} ms after target")
        else:
            log(f"{pid.hex()} message type 0x{m['type']:02x} ignored")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        pass
