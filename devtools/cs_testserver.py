#!/usr/bin/env python3
"""ConnectSensors development server for testing proxies and sensors.

Not the real network server. It speaks the proxy envelope (spec 05) to any
number of proxies sharing one key, prints what they hear, decrypts frames from
the test-vector device (spec/vectors/frame-v1.json), and with --ack answers
confirmed uplinks from that device with a real downlink in RX1. Copies of one
transmission are answered once; a sensor's retry is answered again (07 section 4).

Real sensors registered with --device are paired when their pairing button is
pressed (04 section 4.4: JOIN, KEY_EXCHANGE, SYNC, SET_NETWORK), and from then on
their uplinks are decrypted and their confirmed ones answered, with or without
--ack. The network key is the one from the test vectors.

    python3 devtools/cs_testserver.py                 # prints a fresh key
    python3 devtools/cs_testserver.py --key 5a5a...   # use a key you already set
    python3 devtools/cs_testserver.py --ack           # also exercise downlinks
    python3 devtools/cs_testserver.py --no-seq-seed   # server seq from 1, as after a real restart
    python3 devtools/cs_testserver.py --device CS:1:...              # a sensor, by pairing code
    python3 devtools/cs_testserver.py --device DEV_EUI:K_ROOT        # or by hex dev_eui and root key
    python3 devtools/cs_testserver.py --device ... --state pairings.json  # keep sessions across restarts

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


def root_counter_seed() -> int:
    """First root downlink counter, minus one, when nothing is stored.

    A sensor keeps its root floor through pairing and re-pairing (02 section 8.4),
    so a server that forgot its counter must still start above every value it used
    before. Seconds since the epoch do that while it sends fewer than one
    KEY_EXCHANGE a second.
    """
    return int(time.time())


def parse_device(spec: str) -> tuple[bytes, bytes]:
    """--device: a CS:1:... pairing code, or DEV_EUI:K_ROOT in hex."""
    if spec.strip().upper().startswith("CS:"):
        code = cs.qr_parse(spec)
        return bytes.fromhex(code["dev_eui"]), bytes.fromhex(code["k_root"])
    parts = spec.split(":")
    if len(parts) != 2:
        raise ValueError("expected CS:1:... or DEV_EUI:K_ROOT")
    dev_eui, k_root = bytes.fromhex(parts[0]), bytes.fromhex(parts[1])
    if len(dev_eui) != 8 or len(k_root) != 16:
        raise ValueError("DEV_EUI is 16 hex digits and K_ROOT 32")
    return dev_eui, k_root


class RealDevice:
    """A sensor registered with --device: SCANNED, EXCHANGED or PAIRED (04 section 4.2).

    The pending exchange and the root counter come from csframe's JoinResponder. The
    10-minute and 2-minute timeouts of 04 section 4.2 are not modelled.
    """

    def __init__(self, dev_eui: bytes, k_root: bytes, k_net_route: bytes):
        self.dev_eui = dev_eui
        self.root = cs.keys_from(k_root, dev_eui)
        self.join = cs.JoinResponder(k_root, dev_eui, root_counter_seed())
        self.k_net_route = k_net_route
        self.state = "SCANNED"
        self.k_session = None
        self.session = None
        self.fcnt_down = 0  # session downlink counter, from 1 with each k_session
        self.uplinks = cs.UplinkCollector(0)

    def to_json(self) -> dict:
        return {"root_fcnt_down": self.join.root_fcnt_down, "state": self.state,
                "k_session": self.k_session.hex() if self.k_session else None,
                "fcnt_down": self.fcnt_down, "fcnt_up": self.uplinks.counter.last}

    def load_json(self, d: dict) -> None:
        self.join.root_fcnt_down = max(self.join.root_fcnt_down, d["root_fcnt_down"])
        if d.get("k_session"):
            self.set_session(bytes.fromhex(d["k_session"]), d["state"])
            self.fcnt_down = d["fcnt_down"]
            self.uplinks = cs.UplinkCollector(d["fcnt_up"])

    def set_session(self, k_session: bytes, state: str) -> None:
        self.k_session = k_session
        self.session = cs.keys_from(k_session, self.dev_eui)
        self.state = state

    def open(self, frame: bytes, h) -> tuple[str, cs.DeviceKeys, bytes] | None:
        """Identify a frame as this device's (02 section 11.3): JOIN under the root
        key set, everything else under the session key set."""
        tries = [("root", self.root)] if h.ftype == cs.T_JOIN else []
        if h.ftype != cs.T_JOIN and self.session is not None:
            tries.append(("session", self.session))
        for name, keys in tries:
            try:
                _, pt = cs.open_frame(keys, frame)
                return name, keys, pt
            except Exception:
                continue
        return None


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
    ap.add_argument("--device", action="append", default=[], metavar="CODE",
                    help="a sensor to pair: its CS:1:... pairing code, or DEV_EUI:K_ROOT in hex (repeatable)")
    ap.add_argument("--state", metavar="FILE",
                    help="keep the devices' sessions and counters in FILE, so a restart needs no re-pairing")
    args = ap.parse_args()

    key = bytes.fromhex(args.key) if args.key else secrets.token_bytes(16)
    if len(key) != 16:
        print("--key must be 32 hex digits", file=sys.stderr)
        return 2
    if not args.key:
        log(f"Generated proxy key: {key.hex()}")
        log("Put it in the proxy's secrets.yaml as cs_proxy_key, or restart with --key.")

    device = TestDevice()
    real: list[RealDevice] = []
    for spec in args.device:
        try:
            dev_eui, k_root = parse_device(spec)
        except ValueError as ex:
            print(f"--device {spec}: {ex}", file=sys.stderr)
            return 2
        real.append(RealDevice(dev_eui, k_root, device.k_net_route))
    stored = {}
    if args.state and os.path.exists(args.state):
        with open(args.state) as f:
            stored = json.load(f)
    for dev in real:
        if dev.dev_eui.hex() in stored:
            dev.load_json(stored[dev.dev_eui.hex()])
        log(f"Device {dev.dev_eui.hex()}: {dev.state}")

    def save_state() -> None:
        if not args.state:
            return
        stored.update({dev.dev_eui.hex(): dev.to_json() for dev in real})
        tmp = args.state + ".tmp"
        with open(tmp, "w") as f:
            json.dump(stored, f, indent=1)
        os.replace(tmp, args.state)

    proxies: dict[bytes, Proxy] = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", args.port))
    log(f"Listening on UDP {args.port}; downlinks {'on (' + args.window + ')' if args.ack else 'off'}")

    def send(p: Proxy, msg_type: int, body: bytes) -> None:
        seq = p.link.next_seq() & 0xFFFFFFFF
        sock.sendto(cs.envelope(key, msg_type, p.proxy_id, p.link.boot_id, seq, body), p.addr)

    offset = 1_000_000 if args.window == "rx1" else 3_000_000

    def real_uplink(p: Proxy, pid: bytes, line: str, frame: bytes, h, rx_time: int, now: int) -> bool:
        """A registered sensor's uplink: pairing (04 section 4.4) or normal traffic."""
        for dev in real:
            opened = dev.open(frame, h)
            if opened is not None:
                break
        else:
            return False
        keyset, keys, pt = opened
        eui = dev.dev_eui.hex()
        got = dev.uplinks.receive(frame, int(time.monotonic() * 1000))
        if got["result"] == "copy":
            log(line + f" {eui}: copy of the same transmission")
            return True
        log(line + f" {eui} ({keyset} keys, {got['counter']}): {describe_payload(h.ftype, pt)}")
        if not got["answer"]:
            return True
        if h.ftype == cs.T_JOIN:
            # 04 section 4.4 step 3; a retransmitted JOIN gets the same frame back (4.2).
            r = dev.join.join(frame, secrets.token_bytes(32), now)
            if r["action"] == "new_exchange":
                dev.set_session(r["k_session"], "EXCHANGED")
                dev.fcnt_down = 0
            save_state()
            send(p, cs.M_DOWNLINK, cs.downlink_msg_body(rx_time, offset, r["frame"]))
            stalled = " (stalled: the sensor keeps repeating JOIN)" if r["stalled"] else ""
            log(f"{pid.hex()} -> DOWNLINK KEY_EXCHANGE to {eui} ({r['action']}, root counter "
                f"{dev.join.root_fcnt_down}){stalled}")
            return True
        cmds = b""
        if dev.state == "EXCHANGED" and h.ftype == cs.T_SYNC:
            cmds = cs.command(cs.CMD_SET_NETWORK, dev.k_net_route)  # step 6
        elif dev.state == "EXCHANGED" and h.net_tag != cs.ZERO_TAG and pt[0] & cs.UF_DL_ACK:
            dev.state = "PAIRED"  # step 7: normal tags acknowledge SET_NETWORK
            dev.join.paired()
            log(f"{eui} PAIRED")
        if h.ftype in CONFIRMED:
            dev.fcnt_down += 1
            dl = cs.seal(keys, cs.T_DOWNLINK, h.net_tag, h.dev_tag, dev.fcnt_down,
                         cs.downlink_payload(h.fcnt, now, 0, cmds))
            send(p, cs.M_DOWNLINK, cs.downlink_msg_body(rx_time, offset, dl))
            what = "SET_NETWORK" if cmds else "ack"
            log(f"{pid.hex()} -> DOWNLINK {what} to {eui} answering fcnt {h.fcnt} in {args.window}")
        save_state()
        return True

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
            if h and real_uplink(p, pid, line, frame, h, rx_time, now):
                continue
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
                send(p, cs.M_DOWNLINK, cs.downlink_msg_body(rx_time, offset, dl))
                log(f"{pid.hex()} -> DOWNLINK seq {p.link.seq} answering fcnt {h.fcnt} in {args.window}")

        elif m["type"] == cs.M_TX_RESULT:
            seq, result, tx_offset = struct.unpack(">IBi", body)
            log(f"{pid.hex()} TX_RESULT seq {seq}: {TX_RESULTS.get(result, result)}, "
                f"{tx_offset / 1000:.1f} ms after target")
        else:
            log(f"{pid.hex()} message type 0x{m['type']:02x} ignored")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        pass
