#!/usr/bin/env python3
"""Reference implementation of the ConnectSensors frame format v1.

This module is informative. Where it disagrees with spec/02-frame-v1.md, the
spec wins and this file has a bug.

Usage:
    python3 csframe.py vectors > ../vectors/frame-v1.json   # regenerate vectors
    python3 csframe.py verify ../vectors/frame-v1.json      # check vectors
    python3 csframe.py airtime                              # airtime table

Requires: cryptography (pip install cryptography)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import struct
import sys
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = 0xC5
VERSION = 1
HEADER_LEN = 14
MIC_LEN = 8
MAX_PAYLOAD = 64
EPOCH_SECONDS = 3600
ZERO_TAG = b"\x00\x00\x00\x00"

# Frame types (low nibble of byte 1)
T_DATA = 0x1
T_DATA_CONFIRMED = 0x2
T_HEARTBEAT = 0x3
T_HEARTBEAT_CONFIRMED = 0x4
T_JOIN = 0x5
T_SYNC = 0x6
T_DOWNLINK = 0x8

UPLINK_TYPES = {T_DATA, T_DATA_CONFIRMED, T_HEARTBEAT, T_HEARTBEAT_CONFIRMED, T_JOIN, T_SYNC}
DOWNLINK_TYPES = {T_DOWNLINK}
CONFIRMED_TYPES = {T_DATA_CONFIRMED, T_HEARTBEAT_CONFIRMED, T_JOIN, T_SYNC}
BOOTSTRAP_TYPES = {T_JOIN, T_SYNC}

DIR_UP = 0x00
DIR_DOWN = 0x01

# Uplink flags (first plaintext byte of every uplink payload)
UF_DL_ACK = 0x01
UF_TIME_UNSURE = 0x02

# Downlink flags
DF_PENDING = 0x01

# Downlink commands
CMD_SET_NETWORK = 0x01
CMD_SET_HEARTBEAT = 0x02
CMD_LEAVE = 0x03


def hkdf(ikm: bytes, salt: bytes | None, info: bytes, length: int = 16) -> bytes:
    return HKDF(algorithm=SHA256(), length=length, salt=salt, info=info).derive(ikm)


@dataclass
class DeviceKeys:
    dev_eui: bytes
    k_enc: bytes
    k_dev_tag: bytes


def derive_device_keys(k_root: bytes, dev_eui: bytes) -> DeviceKeys:
    assert len(k_root) == 16 and len(dev_eui) == 8
    return DeviceKeys(
        dev_eui=dev_eui,
        k_enc=hkdf(k_root, dev_eui, b"cs1 enc"),
        k_dev_tag=hkdf(k_root, dev_eui, b"cs1 tag"),
    )


def derive_net_route(k_net: bytes) -> bytes:
    assert len(k_net) == 16
    return hkdf(k_net, None, b"cs1 route")


def epoch_of(unix_seconds: int) -> int:
    return unix_seconds // EPOCH_SECONDS


def tag(key: bytes, label: bytes, epoch: int) -> bytes:
    t = hmac.new(key, label + struct.pack(">I", epoch), hashlib.sha256).digest()[:4]
    return b"\x00\x00\x00\x01" if t == ZERO_TAG else t  # 02 section 6.2


def net_tag(k_net_route: bytes, epoch: int) -> bytes:
    return tag(k_net_route, b"net", epoch)


def dev_tag(k_dev_tag: bytes, epoch: int) -> bytes:
    return tag(k_dev_tag, b"dev", epoch)


def nonce(dev_eui: bytes, fcnt: int, direction: int) -> bytes:
    return dev_eui + struct.pack(">IB", fcnt, direction)


def header(ftype: int, ntag: bytes, dtag: bytes, fcnt: int) -> bytes:
    return bytes([MAGIC, (VERSION << 4) | ftype]) + ntag + dtag + struct.pack(">I", fcnt)


def seal(keys: DeviceKeys, ftype: int, ntag: bytes, dtag: bytes, fcnt: int, plaintext: bytes) -> bytes:
    if len(plaintext) > MAX_PAYLOAD:
        raise ValueError("payload too long")
    direction = DIR_DOWN if ftype in DOWNLINK_TYPES else DIR_UP
    hdr = header(ftype, ntag, dtag, fcnt)
    ct = AESCCM(keys.k_enc, tag_length=MIC_LEN).encrypt(nonce(keys.dev_eui, fcnt, direction), plaintext, hdr)
    return hdr + ct


@dataclass
class ParsedHeader:
    version: int
    ftype: int
    net_tag: bytes
    dev_tag: bytes
    fcnt: int


def parse_header(frame: bytes) -> ParsedHeader | None:
    """What a proxy does: structural checks only, no keys."""
    if len(frame) < HEADER_LEN + MIC_LEN + 1 or frame[0] != MAGIC:
        return None
    version, ftype = frame[1] >> 4, frame[1] & 0x0F
    if version != VERSION:
        return None
    (fcnt,) = struct.unpack(">I", frame[10:14])
    return ParsedHeader(version, ftype, frame[2:6], frame[6:10], fcnt)


def open_frame(keys: DeviceKeys, frame: bytes) -> tuple[ParsedHeader, bytes]:
    h = parse_header(frame)
    if h is None:
        raise ValueError("not a v1 frame")
    direction = DIR_DOWN if h.ftype in DOWNLINK_TYPES else DIR_UP
    pt = AESCCM(keys.k_enc, tag_length=MIC_LEN).decrypt(
        nonce(keys.dev_eui, h.fcnt, direction), frame[HEADER_LEN:], frame[:HEADER_LEN]
    )
    return h, pt


def downlink_payload(reply_to: int, server_time: int, flags: int, commands: bytes = b"") -> bytes:
    return struct.pack(">IIB", reply_to, server_time, flags) + commands


def command(cmd_id: int, args: bytes = b"") -> bytes:
    return bytes([cmd_id, len(args)]) + args


# ---------------------------------------------------------------- airtime


def airtime_ms(payload_len: int, sf: int, bw_hz: int, cr: int = 1, preamble: int = 8,
               explicit_header: bool = True, crc: bool = True) -> float:
    """Semtech LoRa time-on-air for SF7-SF12. cr: 1..4 for 4/5..4/8."""
    tsym = (2 ** sf) / bw_hz
    de = 1 if tsym > 0.016 else 0
    ih = 0 if explicit_header else 1
    num = 8 * payload_len - 4 * sf + 28 + 16 * int(crc) - 20 * ih
    n_payload = 8 + max(math.ceil(num / (4 * (sf - 2 * de))) * (cr + 4), 0)
    return ((preamble + 4.25) + n_payload) * tsym * 1000


# ---------------------------------------------------------------- vectors

K_ROOT = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
DEV_EUI = bytes.fromhex("c5c5000000000001")
K_NET = bytes.fromhex("f0e1d2c3b4a5968778695a4b3c2d1e0f")
T0 = 1795226400  # 2026-11-21T02:00:00Z


def build_vectors() -> dict:
    keys = derive_device_keys(K_ROOT, DEV_EUI)
    route = derive_net_route(K_NET)
    e = epoch_of(T0)
    nt, dt = net_tag(route, e), dev_tag(keys.k_dev_tag, e)

    def case(name, ftype, ntag, dtag, fcnt, pt, note):
        frame = seal(keys, ftype, ntag, dtag, fcnt, pt)
        return {"name": name, "note": note, "type": ftype, "fcnt": fcnt,
                "net_tag": ntag.hex(), "dev_tag": dtag.hex(),
                "plaintext": pt.hex(), "frame": frame.hex()}

    # contact sensor: uflags=0, channel 0, kind 0x01 (contact), value 1 (open)
    data_pt = bytes([0x00, 0x00, 0x01, 0x01])
    hb_pt = bytes([0x00, 0x00, 0x10, 0x5F])  # channel 0, kind 0x10 (battery %), 95
    set_net = command(CMD_SET_NETWORK, route)
    return {
        "spec": "ConnectSensors frame v1",
        "inputs": {"k_root": K_ROOT.hex(), "dev_eui": DEV_EUI.hex(), "k_net": K_NET.hex(),
                   "time": T0, "epoch": e},
        "derived": {"k_enc": keys.k_enc.hex(), "k_dev_tag": keys.k_dev_tag.hex(),
                    "k_net_route": route.hex(),
                    "net_tag": {str(x): net_tag(route, x).hex() for x in (e - 1, e, e + 1)},
                    "dev_tag": {str(x): dev_tag(keys.k_dev_tag, x).hex() for x in (e - 1, e, e + 1)}},
        "frames": [
            case("join", T_JOIN, ZERO_TAG, ZERO_TAG, 1, bytes([0x00]),
                 "first frame after factory reset; bootstrap tags"),
            case("downlink_set_network", T_DOWNLINK, ZERO_TAG, ZERO_TAG, 1,
                 downlink_payload(1, T0, 0, set_net), "server answers JOIN (reply_to = 1) with SET_NETWORK carrying k_net_route"),
            case("data_confirmed", T_DATA_CONFIRMED, nt, dt, 2, bytes([UF_DL_ACK]) + data_pt[1:],
                 "door opened; also acknowledges the SET_NETWORK downlink"),
            case("downlink_ack", T_DOWNLINK, nt, dt, 2, downlink_payload(2, T0 + 1, 0),
                 "plain acknowledgement of fcnt 2 (reply_to = 2)"),
            case("heartbeat", T_HEARTBEAT, nt, dt, 3, hb_pt, "unconfirmed heartbeat, battery 95%"),
            case("sync", T_SYNC, ZERO_TAG, ZERO_TAG, 65, bytes([UF_TIME_UNSURE]),
                 "after a reboot that lost the clock; fcnt jumped ahead by 64"),
        ],
    }


def verify(path: str) -> int:
    with open(path) as f:
        v = json.load(f)
    inp = v["inputs"]
    keys = derive_device_keys(bytes.fromhex(inp["k_root"]), bytes.fromhex(inp["dev_eui"]))
    route = derive_net_route(bytes.fromhex(inp["k_net"]))
    bad = 0
    bad += keys.k_enc.hex() != v["derived"]["k_enc"]
    bad += keys.k_dev_tag.hex() != v["derived"]["k_dev_tag"]
    bad += route.hex() != v["derived"]["k_net_route"]
    for ep, t in v["derived"]["net_tag"].items():
        bad += net_tag(route, int(ep)).hex() != t
    for ep, t in v["derived"]["dev_tag"].items():
        bad += dev_tag(keys.k_dev_tag, int(ep)).hex() != t
    for c in v["frames"]:
        h, pt = open_frame(keys, bytes.fromhex(c["frame"]))
        ok = (pt.hex() == c["plaintext"] and h.ftype == c["type"] and h.fcnt == c["fcnt"]
              and h.net_tag.hex() == c["net_tag"] and h.dev_tag.hex() == c["dev_tag"])
        print(f"{'ok  ' if ok else 'FAIL'} {c['name']}")
        bad += not ok
    print("all vectors pass" if bad == 0 else f"{bad} failures")
    return 1 if bad else 0


def airtime_table() -> None:
    print("frame_bytes  SF  BW_kHz  airtime_ms")
    for n in (23, 31, 40, 86):
        for sf, bw in ((7, 500_000), (9, 500_000), (9, 125_000), (10, 125_000)):
            print(f"{n:11d}  {sf:2d}  {bw // 1000:6d}  {airtime_ms(n, sf, bw):10.1f}")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "vectors":
        print(json.dumps(build_vectors(), indent=2))
    elif cmd == "verify" and len(sys.argv) > 2:
        sys.exit(verify(sys.argv[2]))
    elif cmd == "airtime":
        airtime_table()
    else:
        print(__doc__)
        sys.exit(2)
