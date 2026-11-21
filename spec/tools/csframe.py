#!/usr/bin/env python3
"""Reference implementation of the ConnectSensors v1 encodings.

Covers spec 02 (frame format), 03 (payload), 04 (pairing codes and key
exchange) and 05 (proxy envelope). This module is informative. Where it disagrees with the spec, the spec
wins and this file has a bug.

Usage:
    python3 csframe.py vectors ../vectors   # regenerate all vector files
    python3 csframe.py verify ../vectors    # check all vector files
    python3 csframe.py airtime              # airtime table

Requires: cryptography (pip install cryptography)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
import struct
import sys
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# ======================================================================== 02

MAGIC = 0xC5
VERSION = 1
HEADER_LEN = 14
MIC_LEN = 8
MAX_PAYLOAD = 64
MIN_FRAME = HEADER_LEN + 1 + MIC_LEN
MAX_FRAME = HEADER_LEN + MAX_PAYLOAD + MIC_LEN
EPOCH_SECONDS = 3600
ZERO_TAG = b"\x00\x00\x00\x00"

T_DATA = 0x1
T_DATA_CONFIRMED = 0x2
T_HEARTBEAT = 0x3
T_HEARTBEAT_CONFIRMED = 0x4
T_JOIN = 0x5
T_SYNC = 0x6
T_DOWNLINK = 0x8

DIR_UP = 0x00
DIR_DOWN = 0x01

UF_DL_ACK = 0x01
UF_TIME_UNSURE = 0x02
DF_PENDING = 0x01

CMD_SET_NETWORK = 0x01
CMD_SET_HEARTBEAT = 0x02
CMD_LEAVE = 0x03
CMD_KEY_EXCHANGE = 0x04
CMD_SET_CHANNEL = 0x40


def is_downlink(ftype: int) -> bool:
    return ftype >= 0x8


def hkdf(ikm: bytes, salt: bytes | None, info: bytes, length: int = 16) -> bytes:
    return HKDF(algorithm=SHA256(), length=length, salt=salt, info=info).derive(ikm)


@dataclass
class DeviceKeys:
    dev_eui: bytes
    k_enc: bytes
    k_dev_tag: bytes


def keys_from(base: bytes, dev_eui: bytes) -> DeviceKeys:
    """Root keys when base = k_root, session keys when base = k_session (02 5.1, 5.3)."""
    assert len(base) == 16 and len(dev_eui) == 8
    return DeviceKeys(dev_eui, hkdf(base, dev_eui, b"cs1 enc"), hkdf(base, dev_eui, b"cs1 tag"))


def derive_net_route(k_net: bytes) -> bytes:
    return hkdf(k_net, None, b"cs1 route")


def x25519_pub(priv: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(priv).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def derive_session(k_root: bytes, dev_eui: bytes, own_priv: bytes, peer_pub: bytes,
                   sensor_pub: bytes, server_pub: bytes) -> bytes:
    shared = X25519PrivateKey.from_private_bytes(own_priv).exchange(X25519PublicKey.from_public_bytes(peer_pub))
    if shared == bytes(32):
        raise ValueError("all-zero X25519 shared secret")
    return hkdf(shared, k_root, b"cs1 session" + dev_eui + sensor_pub + server_pub)


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
    if not 1 <= len(plaintext) <= MAX_PAYLOAD:
        raise ValueError("payload length out of range")
    hdr = header(ftype, ntag, dtag, fcnt)
    d = DIR_DOWN if is_downlink(ftype) else DIR_UP
    return hdr + AESCCM(keys.k_enc, tag_length=MIC_LEN).encrypt(nonce(keys.dev_eui, fcnt, d), plaintext, hdr)


@dataclass
class ParsedHeader:
    ftype: int
    net_tag: bytes
    dev_tag: bytes
    fcnt: int


def parse_header(frame: bytes) -> ParsedHeader | None:
    """Keyless structural checks, as a proxy does them (02 section 12)."""
    if not MIN_FRAME <= len(frame) <= MAX_FRAME or frame[0] != MAGIC or frame[1] >> 4 != VERSION:
        return None
    (fcnt,) = struct.unpack(">I", frame[10:14])
    return ParsedHeader(frame[1] & 0x0F, frame[2:6], frame[6:10], fcnt)


def open_frame(keys: DeviceKeys, frame: bytes) -> tuple[ParsedHeader, bytes]:
    h = parse_header(frame)
    if h is None:
        raise ValueError("not a v1 frame")
    d = DIR_DOWN if is_downlink(h.ftype) else DIR_UP
    pt = AESCCM(keys.k_enc, tag_length=MIC_LEN).decrypt(nonce(keys.dev_eui, h.fcnt, d), frame[HEADER_LEN:], frame[:HEADER_LEN])
    return h, pt


def downlink_payload(reply_to: int, server_time: int, flags: int, commands: bytes = b"") -> bytes:
    return struct.pack(">IIB", reply_to, server_time, flags) + commands


def command(cmd_id: int, args: bytes = b"") -> bytes:
    return bytes([cmd_id, len(args)]) + args


# ======================================================================== 03

# kind -> (name, format, unknown sentinel). Size class comes from the top two bits.
KINDS = {
    0x01: ("contact", "B"), 0x02: ("motion", "B"), 0x03: ("leak", "B"), 0x04: ("tamper", "B"),
    0x05: ("vibration", "B"), 0x06: ("binary", "B"), 0x07: ("battery_percent", "B"),
    0x08: ("button", "B"), 0x09: ("enum", "B"), 0x0A: ("percent", "B"),
    0x40: ("temperature", "h"), 0x41: ("humidity", "H"), 0x42: ("battery_voltage", "H"),
    0x43: ("illuminance", "H"), 0x44: ("distance", "H"), 0x45: ("pressure", "H"),
    0x46: ("co2", "H"), 0x47: ("moisture", "H"), 0x48: ("voltage", "H"),
    0x49: ("counter16", "H"), 0x4A: ("int16", "h"),
    0x80: ("counter32", "I"), 0x81: ("energy", "I"), 0x82: ("water", "I"),
    0x83: ("uptime", "I"), 0x84: ("float32", "f"), 0x85: ("int32", "i"),
    0xC0: ("raw", "var"), 0xC1: ("text", "var"), 0xC2: ("firmware_version", "var"),
}
FIXED_SIZE = {0: 1, 1: 2, 2: 4}


def encode_reading(channel: int, kind: int, value) -> bytes:
    cls = kind >> 6
    if cls == 3:
        data = bytes(value)
        if len(data) > 60:
            raise ValueError("variable reading too long")
        return bytes([channel, kind, len(data)]) + data
    fmt = KINDS.get(kind, (None, {0: "B", 1: "H", 2: "I"}[cls]))[1]
    return bytes([channel, kind]) + struct.pack(">" + fmt, value)


def decode_readings(data: bytes) -> list[dict]:
    """Decode a reading list; unknown kinds are kept as raw bytes (03 section 3)."""
    out, i = [], 0
    while i < len(data):
        if i + 2 > len(data):
            raise ValueError("truncated reading header")
        channel, kind = data[i], data[i + 1]
        if kind == 0x00:
            raise ValueError("kind 0x00 is reserved")
        cls = kind >> 6
        i += 2
        if cls == 3:
            if i >= len(data):
                raise ValueError("truncated length")
            n = data[i]
            i += 1
            size = n
        else:
            size = FIXED_SIZE[cls]
        raw = data[i:i + size]
        if len(raw) != size:
            raise ValueError("truncated value")
        i += size
        name, fmt = KINDS.get(kind, ("unknown", None))
        if fmt is None:
            value = raw.hex()
        elif fmt == "var":
            value = raw.decode("utf-8") if kind == 0xC1 else raw.hex()
        else:
            (value,) = struct.unpack(">" + fmt, raw)
        out.append({"channel": channel, "kind": kind, "name": name, "value": value})
    return out


# ======================================================================== 04

QR_PREFIX = "CS"
QR_VERSION = "1"


def b32(data: bytes) -> str:
    return base64.b32encode(data).decode().rstrip("=")


def unb32(s: str) -> bytes:
    return base64.b32decode(s + "=" * (-len(s) % 8))


def qr_encode(dev_eui: bytes, k_root: bytes, region: str, profile: str) -> str:
    body = ":".join([QR_PREFIX, QR_VERSION, dev_eui.hex().upper(), b32(k_root), region, profile])
    check = hashlib.sha256(body.encode()).hexdigest()[:4].upper()
    return body + ":" + check


QR_ALLOWED = set("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ.-:")


def qr_parse(code: str) -> dict:
    code = code.strip().upper()
    if not set(code) <= QR_ALLOWED:
        raise ValueError("invalid character")
    parts = code.split(":")
    if len(parts) != 7 or parts[0] != QR_PREFIX:
        raise ValueError("not a ConnectSensors pairing code")
    if parts[1] != QR_VERSION:
        raise ValueError("unsupported pairing code version")
    body, check = ":".join(parts[:6]), parts[6]
    if hashlib.sha256(body.encode()).hexdigest()[:4].upper() != check:
        raise ValueError("checksum mismatch")
    dev_eui, k_root = bytes.fromhex(parts[2]), unb32(parts[3])
    if len(dev_eui) != 8 or len(k_root) != 16 or len(parts[3]) != 26:
        raise ValueError("bad field length")
    if not 1 <= len(parts[5]) <= 32:
        raise ValueError("bad profile id")
    return {"dev_eui": dev_eui.hex(), "k_root": k_root.hex(), "region": parts[4], "profile": parts[5]}


# ======================================================================== 05

ENV_VERSION = 1
ENV_HEADER = 18
ENV_MAC = 16

M_UPLINK = 0x01
M_HELLO = 0x02
M_TX_RESULT = 0x03
M_SERVER_STATUS = 0x81
M_DOWNLINK = 0x82

UPF_TS_UNCERTAIN = 0x01

CAP_DOWNLINK = 0x01
CAP_FEDERATION = 0x02


def envelope(key: bytes, msg_type: int, proxy_id: bytes, boot_id: int, seq: int, body: bytes) -> bytes:
    assert len(key) == 16 and len(proxy_id) == 8
    head = bytes([ENV_VERSION, msg_type]) + proxy_id + struct.pack(">II", boot_id, seq)
    msg = head + body
    return msg + hmac.new(key, msg, hashlib.sha256).digest()[:ENV_MAC]


def open_envelope(key: bytes, data: bytes) -> dict:
    if len(data) < ENV_HEADER + ENV_MAC or data[0] != ENV_VERSION:
        raise ValueError("not a v1 envelope")
    msg, mac = data[:-ENV_MAC], data[-ENV_MAC:]
    if not hmac.compare_digest(hmac.new(key, msg, hashlib.sha256).digest()[:ENV_MAC], mac):
        raise ValueError("bad MAC")
    boot_id, seq = struct.unpack(">II", msg[10:18])
    return {"type": msg[1], "proxy_id": msg[2:10].hex(), "boot_id": boot_id, "seq": seq,
            "body": msg[ENV_HEADER:].hex()}


def uplink_body(rx_time_us: int, rssi: float, snr: float, flags: int, frame: bytes) -> bytes:
    return struct.pack(">Qhhb", rx_time_us, round(rssi * 10), round(snr * 10), flags) + bytes([len(frame)]) + frame


def hello_body(caps: int, region: str, freq_hz: int, sf: int, bw_khz: int, uptime_s: int,
               counters: list[int], max_loop_gap_ms: int, fw: str) -> bytes:
    assert len(counters) == 7
    return (bytes([caps, len(region)]) + region.encode() + struct.pack(">IBHI", freq_hz, sf, bw_khz, uptime_s)
            + struct.pack(">7I", *counters) + struct.pack(">H", max_loop_gap_ms)
            + bytes([len(fw)]) + fw.encode())


def server_status_body(server_time: int, tags: list[bytes]) -> bytes:
    return struct.pack(">IB", server_time, len(tags)) + b"".join(tags)


def downlink_msg_body(ref_rx_time_us: int, tx_offset_us: int, frame: bytes) -> bytes:
    return struct.pack(">QI", ref_rx_time_us, tx_offset_us) + bytes([len(frame)]) + frame


def tx_result_body(downlink_seq: int, result: int, offset_us: int) -> bytes:
    return struct.pack(">IBi", downlink_seq, result, offset_us)


# ======================================================================== airtime


def airtime_ms(payload_len: int, sf: int, bw_hz: int, cr: int = 1, preamble: int = 8,
               explicit_header: bool = True, crc: bool = True) -> float:
    """Semtech LoRa time-on-air for SF7-SF12. cr: 1..4 for 4/5..4/8."""
    tsym = (2 ** sf) / bw_hz
    de = 1 if tsym > 0.016 else 0
    num = 8 * payload_len - 4 * sf + 28 + 16 * int(crc) - 20 * (0 if explicit_header else 1)
    n_payload = 8 + max(math.ceil(num / (4 * (sf - 2 * de))) * (cr + 4), 0)
    return ((preamble + 4.25) + n_payload) * tsym * 1000


# ======================================================================== vectors

K_ROOT = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
DEV_EUI = bytes.fromhex("c5c5000000000001")
K_NET = bytes.fromhex("f0e1d2c3b4a5968778695a4b3c2d1e0f")
SENSOR_PRIV = bytes.fromhex("a0" * 31 + "a1")
SERVER_PRIV = bytes.fromhex("b0" * 31 + "b1")
T0 = 1795226400  # 2026-11-21T02:00:00Z


def frame_vectors() -> dict:
    root = keys_from(K_ROOT, DEV_EUI)
    s_pub, v_pub = x25519_pub(SENSOR_PRIV), x25519_pub(SERVER_PRIV)
    k_session = derive_session(K_ROOT, DEV_EUI, SENSOR_PRIV, v_pub, s_pub, v_pub)
    assert k_session == derive_session(K_ROOT, DEV_EUI, SERVER_PRIV, s_pub, s_pub, v_pub)
    sess = keys_from(k_session, DEV_EUI)
    route = derive_net_route(K_NET)
    e = epoch_of(T0)
    nt, dt = net_tag(route, e), dev_tag(sess.k_dev_tag, e)
    z = ZERO_TAG

    def case(name, keyset, keys, ftype, ntag, dtag, fcnt, pt, note):
        return {"name": name, "note": note, "keys": keyset, "type": ftype, "fcnt": fcnt,
                "net_tag": ntag.hex(), "dev_tag": dtag.hex(), "plaintext": pt.hex(),
                "frame": seal(keys, ftype, ntag, dtag, fcnt, pt).hex()}

    contact_open = encode_reading(0x00, 0x01, 1)
    battery = encode_reading(0xFF, 0x07, 95)
    return {
        "spec": "ConnectSensors frame v1 (02) and key exchange (04)",
        "inputs": {"k_root": K_ROOT.hex(), "dev_eui": DEV_EUI.hex(), "k_net": K_NET.hex(),
                   "sensor_ephemeral_private": SENSOR_PRIV.hex(),
                   "server_ephemeral_private": SERVER_PRIV.hex(), "time": T0, "epoch": e},
        "derived": {
            "root": {"k_enc": root.k_enc.hex(), "k_dev_tag": root.k_dev_tag.hex()},
            "sensor_ephemeral_public": s_pub.hex(), "server_ephemeral_public": v_pub.hex(),
            "k_session": k_session.hex(),
            "session": {"k_enc": sess.k_enc.hex(), "k_dev_tag": sess.k_dev_tag.hex()},
            "k_net_route": route.hex(),
            "net_tag": {str(x): net_tag(route, x).hex() for x in (e - 1, e, e + 1)},
            "dev_tag": {str(x): dev_tag(sess.k_dev_tag, x).hex() for x in (e - 1, e, e + 1)},
        },
        "frames": [
            case("join", "root", root, T_JOIN, z, z, 1, bytes([UF_TIME_UNSURE]) + s_pub,
                 "JOIN with the sensor's ephemeral public key"),
            case("downlink_key_exchange", "root", root, T_DOWNLINK, z, z, 1,
                 downlink_payload(1, T0, 0, command(CMD_KEY_EXCHANGE, v_pub)),
                 "answer to JOIN: server ephemeral public key"),
            case("sync_after_exchange", "session", sess, T_SYNC, z, z, 2, bytes([UF_DL_ACK]),
                 "first frame under session keys; acknowledges KEY_EXCHANGE"),
            case("downlink_set_network", "session", sess, T_DOWNLINK, z, z, 2,
                 downlink_payload(2, T0 + 3, 0, command(CMD_SET_NETWORK, route)),
                 "answer to SYNC: network routing key"),
            case("data_confirmed", "session", sess, T_DATA_CONFIRMED, nt, dt, 3,
                 bytes([UF_DL_ACK]) + contact_open, "door opened; acknowledges SET_NETWORK"),
            case("downlink_ack", "session", sess, T_DOWNLINK, nt, dt, 3, downlink_payload(3, T0 + 60, 0),
                 "plain acknowledgement of fcnt 3"),
            case("heartbeat", "session", sess, T_HEARTBEAT, nt, dt, 4, bytes([0]) + contact_open + battery,
                 "heartbeat with current state and battery"),
            case("sync_after_reboot", "session", sess, T_SYNC, z, z, 65, bytes([UF_TIME_UNSURE]) + contact_open,
                 "clock lost on battery change; fcnt jumped to the next reserved block"),
        ],
    }


def payload_vectors() -> dict:
    cases = [
        ("contact_open", [(0x00, 0x01, 1)]),
        ("temp_humidity", [(0x00, 0x40, 2153), (0x00, 0x41, 4520)]),
        ("negative_temperature", [(0x01, 0x40, -1250)]),
        ("unknown_temperature", [(0x00, 0x40, -32768)]),
        ("battery_and_firmware", [(0xFF, 0x07, 88), (0xFF, 0x42, 2950), (0xFF, 0xC2, bytes([1, 2, 0]))]),
        ("button_long", [(0x00, 0x08, 3)]),
        ("water_counter", [(0x00, 0x82, 123456)]),
        ("text", [(0x02, 0xC1, "hi".encode())]),
    ]
    out = []
    for name, readings in cases:
        enc = b"".join(encode_reading(c, k, v) for c, k, v in readings)
        out.append({"name": name, "encoded": enc.hex(), "decoded": decode_readings(enc)})
    out.append({"name": "unknown_kind_skipped", "encoded": "00590102" + "000101",
                "decoded": decode_readings(bytes.fromhex("00590102000101")),
                "note": "kind 0x59 is unassigned (2-byte class); receivers skip it and keep parsing"})
    return {"spec": "ConnectSensors payload v1 (03)", "readings": out}


def pairing_vectors() -> dict:
    good = qr_encode(DEV_EUI, K_ROOT, "US915", "CS.CONTACT-1")
    bad_check = good[:-1] + ("0" if good[-1] != "0" else "1")
    return {
        "spec": "ConnectSensors pairing codes (04)",
        "valid": [{"code": good, "parsed": qr_parse(good)},
                  {"code": good.lower(), "parsed": qr_parse(good.lower()), "note": "lowercase input accepted"}],
        "invalid": [{"code": bad_check, "reason": "checksum mismatch"},
                    {"code": good.replace("CS:1:", "CS:2:", 1), "reason": "unsupported pairing code version"}],
    }


PROXY_KEY = bytes.fromhex("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a")
PROXY_ID = bytes.fromhex("3485180000fffe01")  # EUI-64 from MAC 34:85:18:00:00:01


def envelope_vectors() -> dict:
    fv = frame_vectors()
    frames = {f["name"]: bytes.fromhex(f["frame"]) for f in fv["frames"]}
    route = bytes.fromhex(fv["derived"]["k_net_route"])
    e = fv["inputs"]["epoch"]
    boot = 0x1A2B3C4D
    rx_t = 123_456_789
    msgs = [
        ("hello", M_HELLO, boot, 1,
         hello_body(CAP_DOWNLINK, "US915", 918_500_000, 9, 500, 42, [10, 9, 1, 0, 0, 2, 0], 7, "cs_proxy 0.1.0"),
         "proxy announces itself after boot"),
        ("server_status", M_SERVER_STATUS, boot, 1,
         server_status_body(T0, [net_tag(route, x) for x in (e - 1, e, e + 1)]),
         "server answers HELLO with its time and the network's tags for epochs e-1..e+1"),
        ("uplink", M_UPLINK, boot, 2, uplink_body(rx_t, -97.5, 6.3, 0, frames["data_confirmed"]),
         "proxy forwards the DATA_CONFIRMED frame heard at -97.5 dBm, SNR 6.3 dB"),
        ("downlink", M_DOWNLINK, boot, 2, downlink_msg_body(rx_t, 1_000_000, frames["downlink_ack"]),
         "server asks the proxy to transmit the acknowledgement in RX1"),
        ("tx_result", M_TX_RESULT, boot, 3, tx_result_body(2, 0, 1800),
         "proxy reports it transmitted downlink seq 2, 1.8 ms after the requested time"),
    ]
    return {
        "spec": "ConnectSensors proxy envelope v1 (05)",
        "inputs": {"proxy_key": PROXY_KEY.hex(), "proxy_id": PROXY_ID.hex()},
        "messages": [{"name": n, "note": note, "type": t, "boot_id": b, "seq": q, "body": body.hex(),
                      "message": envelope(PROXY_KEY, t, PROXY_ID, b, q, body).hex()}
                     for n, t, b, q, body, note in msgs],
    }


def write_vectors(d: str) -> None:
    for fname, data in (("frame-v1.json", frame_vectors()), ("payload-v1.json", payload_vectors()),
                        ("pairing-v1.json", pairing_vectors()), ("proxy-envelope-v1.json", envelope_vectors())):
        with open(os.path.join(d, fname), "w") as f:
            json.dump(data, f, indent=2)
            f.write("\n")


def verify(d: str) -> int:
    bad = 0
    with open(os.path.join(d, "frame-v1.json")) as f:
        v = json.load(f)
    i = v["inputs"]
    k_root, eui = bytes.fromhex(i["k_root"]), bytes.fromhex(i["dev_eui"])
    s_priv, v_priv = bytes.fromhex(i["sensor_ephemeral_private"]), bytes.fromhex(i["server_ephemeral_private"])
    s_pub, v_pub = x25519_pub(s_priv), x25519_pub(v_priv)
    k_sess = derive_session(k_root, eui, s_priv, v_pub, s_pub, v_pub)
    sets = {"root": keys_from(k_root, eui), "session": keys_from(k_sess, eui)}
    dv = v["derived"]
    bad += k_sess.hex() != dv["k_session"]
    for name, ks in sets.items():
        bad += ks.k_enc.hex() != dv[name]["k_enc"] or ks.k_dev_tag.hex() != dv[name]["k_dev_tag"]
    route = derive_net_route(bytes.fromhex(i["k_net"]))
    bad += route.hex() != dv["k_net_route"]
    bad += any(net_tag(route, int(ep)).hex() != t for ep, t in dv["net_tag"].items())
    bad += any(dev_tag(sets["session"].k_dev_tag, int(ep)).hex() != t for ep, t in dv["dev_tag"].items())
    for c in v["frames"]:
        h, pt = open_frame(sets[c["keys"]], bytes.fromhex(c["frame"]))
        ok = (pt.hex() == c["plaintext"] and h.ftype == c["type"] and h.fcnt == c["fcnt"]
              and h.net_tag.hex() == c["net_tag"] and h.dev_tag.hex() == c["dev_tag"])
        print(f"{'ok  ' if ok else 'FAIL'} frame   {c['name']}")
        bad += not ok
    with open(os.path.join(d, "payload-v1.json")) as f:
        for c in json.load(f)["readings"]:
            ok = decode_readings(bytes.fromhex(c["encoded"])) == c["decoded"]
            print(f"{'ok  ' if ok else 'FAIL'} payload {c['name']}")
            bad += not ok
    with open(os.path.join(d, "pairing-v1.json")) as f:
        p = json.load(f)
    for c in p["valid"]:
        ok = qr_parse(c["code"]) == c["parsed"]
        print(f"{'ok  ' if ok else 'FAIL'} pairing valid {c['code']}")
        bad += not ok
    for c in p["invalid"]:
        try:
            qr_parse(c["code"])
            ok = False
        except ValueError as ex:
            ok = str(ex) == c["reason"]
        print(f"{'ok  ' if ok else 'FAIL'} pairing invalid ({c['reason']})")
        bad += not ok
    with open(os.path.join(d, "proxy-envelope-v1.json")) as f:
        ev = json.load(f)
    key = bytes.fromhex(ev["inputs"]["proxy_key"])
    for c in ev["messages"]:
        m = open_envelope(key, bytes.fromhex(c["message"]))
        ok = (m["type"], m["proxy_id"], m["boot_id"], m["seq"], m["body"]) == (
            c["type"], ev["inputs"]["proxy_id"], c["boot_id"], c["seq"], c["body"])
        tampered = bytearray(bytes.fromhex(c["message"]))
        tampered[20] ^= 1
        try:
            open_envelope(key, bytes(tampered))
            ok = False
        except ValueError:
            pass
        print(f"{'ok  ' if ok else 'FAIL'} envelope {c['name']}")
        bad += not ok
    print("all vectors pass" if bad == 0 else f"{bad} failures")
    return 1 if bad else 0


def airtime_table() -> None:
    print("frame_bytes  SF  BW_kHz  airtime_ms")
    for n in (23, 31, 55, 65, 86):
        for sf, bw in ((9, 500_000), (9, 125_000)):
            print(f"{n:11d}  {sf:2d}  {bw // 1000:6d}  {airtime_ms(n, sf, bw):10.1f}")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "vectors" and len(sys.argv) > 2:
        write_vectors(sys.argv[2])
    elif cmd == "verify" and len(sys.argv) > 2:
        sys.exit(verify(sys.argv[2]))
    elif cmd == "airtime":
        airtime_table()
    else:
        print(__doc__)
        sys.exit(2)
