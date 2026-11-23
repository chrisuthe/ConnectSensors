#!/usr/bin/env python3
"""Reference implementation of the ConnectSensors v1 encodings.

Covers spec 02 (frame format), 03 (payload), 04 (pairing codes, key exchange,
root downlink counter and sensor floors), 05 (proxy envelope), the testable rules
of 07 (network server) and 09 (federation events, including a minimal BIP-340 implementation). This module is informative. Where it disagrees with the spec, the spec
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
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
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
TAG_LEN = 8
TAG_BLOCK = 64  # one bootstrap tag block per counter reservation block (02 sections 6.1 and 8.2)

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

CMD_SET_HEARTBEAT = 0x02
CMD_LEAVE = 0x03
CMD_KEY_EXCHANGE = 0x04
CMD_NOP = 0x05
CMD_SET_CHANNEL = 0x40


def is_downlink(ftype: int) -> bool:
    return ftype >= 0x8


def is_bootstrap(ftype: int) -> bool:
    """JOIN and SYNC carry bootstrap tags (02 section 4)."""
    return ftype in (T_JOIN, T_SYNC)


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


def epoch_index(epoch: int) -> bytes:
    return b"e" + struct.pack(">I", epoch)


def block_index(fcnt: int) -> bytes:
    if fcnt < 1:
        raise ValueError("fcnt starts at 1")
    return b"b" + struct.pack(">I", (fcnt - 1) // TAG_BLOCK)


def tag_seed(k_dev_tag: bytes, index: bytes) -> bytes:
    return hmac.new(k_dev_tag, b"cs1 tag seed" + index, hashlib.sha256).digest()


def ed25519_pub(seed: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def tag_of_pub(pub: bytes) -> bytes:
    return hashlib.sha256(b"cs1 tag fp" + pub).digest()[:TAG_LEN]


def tag(k_dev_tag: bytes, index: bytes) -> bytes:
    """The 8-byte key-fingerprint tag (02 section 6.1)."""
    return tag_of_pub(ed25519_pub(tag_seed(k_dev_tag, index)))


def normal_tag(k_dev_tag: bytes, epoch: int) -> bytes:
    return tag(k_dev_tag, epoch_index(epoch))


def bootstrap_tag(k_dev_tag: bytes, fcnt: int) -> bytes:
    return tag(k_dev_tag, block_index(fcnt))


def uplink_tag(keys: DeviceKeys, ftype: int, fcnt: int, unix_time: int) -> bytes:
    """The tag a sensor puts on a new uplink: bootstrap for JOIN and SYNC, normal otherwise."""
    return bootstrap_tag(keys.k_dev_tag, fcnt) if is_bootstrap(ftype) else normal_tag(keys.k_dev_tag,
                                                                                     epoch_of(unix_time))


def nonce(dev_eui: bytes, fcnt: int, direction: int) -> bytes:
    return dev_eui + struct.pack(">IB", fcnt, direction)


def header(ftype: int, ftag: bytes, fcnt: int) -> bytes:
    assert len(ftag) == TAG_LEN
    return bytes([MAGIC, (VERSION << 4) | ftype]) + ftag + struct.pack(">I", fcnt)


def seal(keys: DeviceKeys, ftype: int, ftag: bytes, fcnt: int, plaintext: bytes) -> bytes:
    if not 1 <= len(plaintext) <= MAX_PAYLOAD:
        raise ValueError("payload length out of range")
    hdr = header(ftype, ftag, fcnt)
    d = DIR_DOWN if is_downlink(ftype) else DIR_UP
    return hdr + AESCCM(keys.k_enc, tag_length=MIC_LEN).encrypt(nonce(keys.dev_eui, fcnt, d), plaintext, hdr)


@dataclass
class ParsedHeader:
    ftype: int
    tag: bytes
    fcnt: int


def header_error(frame: bytes) -> str | None:
    """Why a frame fails the keyless checks (02 sections 3 and 4), or None."""
    if not MIN_FRAME <= len(frame) <= MAX_FRAME:
        return "frame length out of range"
    if frame[0] != MAGIC:
        return "bad magic"
    if frame[1] >> 4 != VERSION:
        return "unsupported version"
    if frame[1] & 0x0F == 0:
        return "reserved frame type"
    return None


def parse_header(frame: bytes) -> ParsedHeader | None:
    """Keyless structural checks, as a proxy does them (02 section 12)."""
    if header_error(frame) is not None:
        return None
    (fcnt,) = struct.unpack(">I", frame[10:14])
    return ParsedHeader(frame[1] & 0x0F, frame[2:10], fcnt)


def open_frame(keys: DeviceKeys, frame: bytes) -> tuple[ParsedHeader, bytes]:
    """Raises ValueError, with the reason, for a frame that fails the checks or the MIC."""
    err = header_error(frame)
    if err is not None:
        raise ValueError(err)
    h = parse_header(frame)
    assert h is not None
    d = DIR_DOWN if is_downlink(h.ftype) else DIR_UP
    try:
        pt = AESCCM(keys.k_enc, tag_length=MIC_LEN).decrypt(nonce(keys.dev_eui, h.fcnt, d), frame[HEADER_LEN:],
                                                            frame[:HEADER_LEN])
    except InvalidTag:
        raise ValueError("MIC check failed") from None
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


def encode_reading(channel: int, kind: int, value: int | float | bytes) -> bytes:
    cls = kind >> 6
    if cls == 3:
        if not isinstance(value, (bytes, bytearray)):
            raise TypeError("variable reading needs bytes")
        data = bytes(value)
        if len(data) > 60:
            raise ValueError("variable reading too long")
        return bytes([channel, kind, len(data)]) + data
    fmt = KINDS.get(kind, (None, {0: "B", 1: "H", 2: "I"}[cls]))[1]
    return bytes([channel, kind]) + struct.pack(">" + fmt, value)


def decode_readings(data: bytes) -> list[dict[str, Any]]:
    """Decode a reading list; unknown kinds are kept as raw bytes (03 section 3).

    Raises ValueError for a payload that 03 section 2 makes invalid: a truncated
    reading, kind 0x00, or a repeated (channel, kind)."""
    out, i, seen = [], 0, set()
    while i < len(data):
        if i + 2 > len(data):
            raise ValueError("truncated reading header")
        channel, kind = data[i], data[i + 1]
        if kind == 0x00:
            raise ValueError("kind 0x00 is reserved")
        if (channel, kind) in seen:
            raise ValueError("duplicate (channel, kind)")
        seen.add((channel, kind))
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
QR_HEX = set("0123456789ABCDEF")
QR_BASE32 = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")


def qr_parse(code: str) -> dict[str, Any]:
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
    if len(parts[2]) != 16 or not set(parts[2]) <= QR_HEX:
        raise ValueError("bad DEV_EUI")
    if len(parts[3]) != 26 or not set(parts[3]) <= QR_BASE32:
        raise ValueError("bad K_ROOT")
    if not 1 <= len(parts[5]) <= 32:  # QR_ALLOWED already limits it to 03 section 9.1's characters
        raise ValueError("bad profile id")
    return {"dev_eui": parts[2].lower(), "k_root": unb32(parts[3]).hex(), "region": parts[4], "profile": parts[5]}


JOIN_STALL_RETRANSMISSIONS = 3  # the sensor's last retry of a JOIN (08 section 5), answered and still repeated


@dataclass
class PendingExchange:
    """A JOIN answered with a new KEY_EXCHANGE, until the first uplink under its
    k_session verifies (04 section 4.2). The server persists it before sending frame (04 section 4.6,
    07 section 10) and restores it with JoinResponder(..., pending=...), so a JOIN
    retransmitted across a restart gets the same frame. to_dict() and from_dict()
    convert it to and from JSON-safe values; k_session is secret, store it as such."""

    sensor_pub: bytes
    frame: bytes      # the KEY_EXCHANGE downlink
    k_session: bytes
    retransmissions: int = 0  # counted toward the stall (07 section 5.1)
    sent: bool = True         # retransmissions are counted once this is set

    def to_dict(self) -> dict[str, Any]:
        return {"sensor_pub": self.sensor_pub.hex(), "frame": self.frame.hex(), "k_session": self.k_session.hex(),
                "retransmissions": self.retransmissions, "sent": self.sent}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> PendingExchange:
        # A record without "sent" predates it and was counted from the start.
        return cls(bytes.fromhex(d["sensor_pub"]), bytes.fromhex(d["frame"]), bytes.fromhex(d["k_session"]),
                   int(d["retransmissions"]), bool(d.get("sent", True)))


class JoinResponder:
    """Server answers to JOIN for one device (02 section 8.4, 04 section 4.2, 07 section 5.1).

    The root downlink counter is never reset, so no two KEY_EXCHANGE frames share a
    root nonce. A retransmitted JOIN gets the cached frame back byte for byte and
    leaves the pending k_session alone.

    Persist root_fcnt_down and pending, and pass both back after a restart. With
    count_after_sent, retransmissions count toward the stall only after sent() reported
    the KEY_EXCHANGE SENT, as 07 section 5.1 asks; without it, every one counts."""

    def __init__(self, k_root: bytes, dev_eui: bytes, root_fcnt_down: int = 0,
                 pending: PendingExchange | None = None, *, count_after_sent: bool = False):
        self.k_root, self.dev_eui = k_root, dev_eui
        self.root = keys_from(k_root, dev_eui)
        self.root_fcnt_down = root_fcnt_down  # last value used; persisted, kept after removal
        self.pending: PendingExchange | None = pending
        self.count_after_sent = count_after_sent

    def join(self, frame: bytes, server_priv: bytes | None, server_time: int | None) -> dict[str, Any]:
        """Answer a JOIN. server_priv (a fresh X25519 private key) and server_time are
        used only for a new exchange; returns action ("new_exchange" or "resend"),
        frame, k_session and stalled."""
        h, pt = open_frame(self.root, frame)
        sensor_pub = pt[1:33]
        p = self.pending
        if p is not None and p.sensor_pub == sensor_pub:
            if p.sent:
                p.retransmissions += 1
            return {"action": "resend", "frame": p.frame, "k_session": p.k_session,
                    "stalled": p.retransmissions >= JOIN_STALL_RETRANSMISSIONS}
        if server_priv is None or server_time is None:
            raise ValueError("a new exchange needs server_priv and server_time")
        self.root_fcnt_down += 1
        server_pub = x25519_pub(server_priv)
        k_session = derive_session(self.k_root, self.dev_eui, server_priv, sensor_pub, sensor_pub, server_pub)
        dl = seal(self.root, T_DOWNLINK, h.tag, self.root_fcnt_down,
                  downlink_payload(h.fcnt, server_time, 0, command(CMD_KEY_EXCHANGE, server_pub)))
        self.pending = PendingExchange(sensor_pub, dl, k_session, sent=not self.count_after_sent)
        return {"action": "new_exchange", "frame": dl, "k_session": k_session, "stalled": False}

    def sent(self, frame: bytes) -> bool:
        """A proxy reported a transmission of frame SENT (05 section 5.5). Returns whether
        frame is the pending KEY_EXCHANGE; a late result for an older one is ignored."""
        if self.pending is None or self.pending.frame != frame:
            return False
        self.pending.sent = True
        return True

    def paired(self) -> None:
        """The first uplink under the pending k_session verified: the device is PAIRED
        and the pending exchange is done (04 section 4.2)."""
        self.pending = None


class SensorPairing:
    """Sensor side of pairing (02 section 10.2, 04 sections 4.3, 4.4 and 6.2): JOIN,
    KEY_EXCHANGE, the provisional SESSION state and PAIRED on the first accepted
    session downlink."""

    def __init__(self, k_root: bytes, dev_eui: bytes):
        self.k_root, self.dev_eui = k_root, dev_eui
        self.root = keys_from(k_root, dev_eui)
        self.state = "UNPAIRED"
        self.root_floor = 0     # survives pairing, LEAVE and re-pairing
        self.session_floor = 0  # per k_session
        self.k_session: bytes | None = None
        self.joining: tuple[int, bytes] | None = None  # (JOIN fcnt, ephemeral private key)
        self.last_fcnt: int | None = None  # the most recent uplink, which a downlink must answer

    def join(self, fcnt: int, priv: bytes) -> bytes:
        self.joining = (fcnt, priv)
        self.state, self.last_fcnt = "JOINING", fcnt
        return seal(self.root, T_JOIN, bootstrap_tag(self.root.k_dev_tag, fcnt), fcnt,
                    bytes([UF_TIME_UNSURE]) + x25519_pub(priv))

    def uplink(self, ftype: int, fcnt: int, unix_time: int, plaintext: bytes) -> bytes:
        """A session uplink, in SESSION or PAIRED."""
        if self.k_session is None:
            raise ValueError("no session")
        keys = keys_from(self.k_session, self.dev_eui)
        self.last_fcnt = fcnt
        return seal(keys, ftype, uplink_tag(keys, ftype, fcnt, unix_time), fcnt, plaintext)

    def downlink(self, frame: bytes) -> str:
        if self.state == "JOINING":
            return self._root_downlink(frame)
        if self.state in ("SESSION", "PAIRED"):
            return self._session_downlink(frame)
        return "no_keys"

    def _root_downlink(self, frame: bytes) -> str:
        assert self.joining is not None
        try:
            h, pt = open_frame(self.root, frame)
        except ValueError:
            return "bad_mic"
        if struct.unpack(">I", pt[:4])[0] != self.joining[0]:
            return "wrong_reply_to"
        if h.fcnt <= self.root_floor:
            return "at_or_below_root_floor"
        cmd = pt[9:]
        if len(cmd) < 34 or cmd[0] != CMD_KEY_EXCHANGE or cmd[1] != 32:
            return "no_key_exchange"
        server_pub, priv = cmd[2:34], self.joining[1]
        self.root_floor = h.fcnt
        self.k_session = derive_session(self.k_root, self.dev_eui, priv, server_pub, x25519_pub(priv), server_pub)
        self.session_floor = 0
        self.joining = None
        self.state = "SESSION"  # provisional until a session downlink is accepted (04 section 4.3)
        return "accept"

    def _session_downlink(self, frame: bytes) -> str:
        assert self.k_session is not None
        try:
            h, pt = open_frame(keys_from(self.k_session, self.dev_eui), frame)
        except ValueError:
            return "bad_mic"
        if struct.unpack(">I", pt[:4])[0] != self.last_fcnt:
            return "wrong_reply_to"
        if h.fcnt <= self.session_floor:
            return "at_or_below_session_floor"
        self.session_floor = h.fcnt
        self.state = "PAIRED"
        return "accept"

    def undelivered(self) -> None:
        """A confirmed uplink ran out of retries. In SESSION, pairing fails (04 section 4.3)."""
        if self.state == "SESSION":
            self.k_session = None
            self.state = "UNPAIRED"
        elif self.state == "JOINING":
            self.joining = None
            self.state = "UNPAIRED"

    def leave(self) -> None:
        self.k_session = self.joining = None
        self.state = "UNPAIRED"

    def factory_reset(self) -> None:
        self.root_floor = self.session_floor = 0
        self.k_session = self.joining = None
        self.state = "UNPAIRED"


# ======================================================================== 05

ENV_VERSION = 1
ENV_HEADER = 18
ENV_MAC = 16

M_UPLINK = 0x01
M_HELLO = 0x02
M_TX_RESULT = 0x03
M_SERVER_STATUS = 0x81
M_DOWNLINK = 0x82
M_HELLO_REQUEST = 0x83

UPF_TS_UNCERTAIN = 0x01

TX_RESULTS = ("SENT", "TOO_LATE", "BUSY", "DUTY_CYCLE", "NOT_CAPABLE", "INVALID", "RADIO_ERROR")  # 05 section 5.5

CAP_DOWNLINK = 0x01


def envelope(key: bytes, msg_type: int, proxy_id: bytes, boot_id: int, seq: int, body: bytes) -> bytes:
    assert len(key) == 16 and len(proxy_id) == 8
    head = bytes([ENV_VERSION, msg_type]) + proxy_id + struct.pack(">II", boot_id, seq)
    msg = head + body
    return msg + hmac.new(key, msg, hashlib.sha256).digest()[:ENV_MAC]


def open_envelope(key: bytes, data: bytes) -> dict[str, Any]:
    if len(data) < ENV_HEADER + ENV_MAC or data[0] != ENV_VERSION:
        raise ValueError("not a v1 envelope")
    msg, mac = data[:-ENV_MAC], data[-ENV_MAC:]
    if not hmac.compare_digest(hmac.new(key, msg, hashlib.sha256).digest()[:ENV_MAC], mac):
        raise ValueError("bad MAC")
    boot_id, seq = struct.unpack(">II", msg[10:18])
    return {"type": msg[1], "proxy_id": msg[2:10].hex(), "boot_id": boot_id, "seq": seq,
            "body": msg[ENV_HEADER:].hex()}


def uplink_body(rx_time_us: int, rssi: float, snr: float, flags: int, frame: bytes) -> bytes:
    return struct.pack(">QhhB", rx_time_us, round(rssi * 10), round(snr * 10), flags) + bytes([len(frame)]) + frame


def parse_uplink(body: bytes) -> dict[str, Any]:
    if len(body) < 14 or len(body) != 14 + body[13]:
        raise ValueError("bad UPLINK length")
    rx_time_us, rssi, snr, flags, _ = struct.unpack(">QhhBB", body[:14])
    return {"rx_time_us": rx_time_us, "rssi": rssi / 10, "snr": snr / 10, "flags": flags,
            "frame": body[14:]}


def hello_body(caps: int, region: str, freq_hz: int, sf: int, bw_khz: int, uptime_s: int,
               counters: list[int], max_loop_gap_ms: int, fw: str, request_nonce: int = 0) -> bytes:
    assert len(counters) == 7
    return (bytes([caps, len(region)]) + region.encode() + struct.pack(">IBHI", freq_hz, sf, bw_khz, uptime_s)
            + struct.pack(">7I", *counters) + struct.pack(">HI", max_loop_gap_ms, request_nonce)
            + bytes([len(fw)]) + fw.encode())


def parse_hello(body: bytes) -> dict[str, Any]:
    caps, rlen = body[0], body[1]
    p = 2 + rlen
    freq, sf, bw, uptime = struct.unpack(">IBHI", body[p:p + 11])
    counters = list(struct.unpack(">7I", body[p + 11:p + 39]))
    gap, nonce = struct.unpack(">HI", body[p + 39:p + 45])
    flen = body[p + 45]
    if len(body) != p + 46 + flen:
        raise ValueError("bad HELLO length")
    return {"caps": caps, "region": body[2:p].decode(), "frequency_hz": freq, "sf": sf, "bw_khz": bw,
            "uptime_s": uptime, "counters": counters, "max_loop_gap_ms": gap, "request_nonce": nonce,
            "fw": body[p + 46:].decode()}


def server_status_body(server_time: int, hello_seq: int = 0) -> bytes:
    return struct.pack(">II", server_time, hello_seq)


def parse_server_status(body: bytes) -> dict[str, Any]:
    if len(body) != 8:
        raise ValueError("bad SERVER_STATUS length")
    server_time, hello_seq = struct.unpack(">II", body)
    return {"server_time": server_time, "hello_seq": hello_seq}


def hello_request_body(nonce: int) -> bytes:
    return struct.pack(">I", nonce)


def downlink_msg_body(ref_rx_time_us: int, tx_offset_us: int, frame: bytes) -> bytes:
    return struct.pack(">QI", ref_rx_time_us, tx_offset_us) + bytes([len(frame)]) + frame


def tx_result_body(downlink_seq: int, result: int, offset_us: int) -> bytes:
    return struct.pack(">IBi", downlink_seq, result, offset_us)


def parse_tx_result(body: bytes) -> dict[str, Any]:
    if len(body) != 9:
        raise ValueError("bad TX_RESULT length")
    downlink_seq, result, offset_us = struct.unpack(">IBi", body)
    return {"downlink_seq": downlink_seq, "result": result, "offset_us": offset_us}


# ---------------------------------------------------------------- 05 section 3.2: sessions

HELLO_ECHO_SLOTS = 3            # proxy: HELLOs whose echo can resync the server seq floor
HELLO_ECHO_MAX_AGE_MS = 120_000  # proxy: ... and only within 2 HELLO intervals
HELLO_REQUEST_GAP_MS = 5000     # proxy: at most one requested HELLO per 5 s
REQUEST_NONCE_MS = 30_000       # server: how long a HELLO_REQUEST nonce stays valid
REQUEST_RESEND_MS = 1000        # server: at most one HELLO_REQUEST per boot_id per second
REQUEST_BOOTS = 4               # server: outstanding nonces kept per proxy


class ProxyLink:
    """The proxy's checks on messages from its server (05 section 3.2)."""

    def __init__(self, boot_id: int):
        self.boot_id = boot_id
        self.floor = 0
        self.echoes: list[list[Any]] = []  # [HELLO seq, sent at, echoed], the last 3 sent
        self.last_requested_ms: int | None = None

    def sent(self, m: dict[str, Any], now_ms: int) -> None:
        if m["type"] != M_HELLO:
            return
        self.echoes = (self.echoes + [[m["seq"], now_ms, False]])[-HELLO_ECHO_SLOTS:]
        if parse_hello(bytes.fromhex(m["body"]))["request_nonce"]:
            self.last_requested_ms = now_ms

    def _take_echo(self, hello_seq: int, now_ms: int) -> bool:
        for e in self.echoes:
            if e[0] == hello_seq and not e[2] and now_ms - e[1] <= HELLO_ECHO_MAX_AGE_MS:
                e[2] = True
                return True
        return False

    def receive(self, m: dict[str, Any], now_ms: int) -> dict[str, Any]:
        if m["boot_id"] != self.boot_id:
            return {"result": "ignored"}
        body = bytes.fromhex(m["body"])
        if m["type"] == M_HELLO_REQUEST:
            if len(body) != 4 or struct.unpack(">I", body)[0] == 0:
                return {"result": "ignored"}
            at = now_ms
            if self.last_requested_ms is not None:
                at = max(at, self.last_requested_ms + HELLO_REQUEST_GAP_MS)
            return {"result": "hello", "hello_at_ms": at}
        if m["type"] == M_SERVER_STATUS:
            hello_seq = parse_server_status(body)["hello_seq"]
            if m["seq"] > self.floor:
                self.floor = m["seq"]
                self._take_echo(hello_seq, now_ms)
                return {"result": "accepted"}
            if hello_seq and self._take_echo(hello_seq, now_ms):
                self.floor = m["seq"]
                return {"result": "resync"}
            return {"result": "ignored"}
        if m["seq"] > self.floor:
            self.floor = m["seq"]
            return {"result": "accepted"}
        return {"result": "ignored"}


class ServerLink:
    """A server's session with one proxy (05 section 3.2, 07 section 2.3). Nothing persisted."""

    def __init__(self, new_nonce: Callable[[], int]):
        self.new_nonce = new_nonce
        self.boot_id: int | None = None
        self.last_seq = 0
        self.seq = 0
        self.requests: dict[int, list[Any]] = {}  # boot_id -> [nonce, issued_ms, last_sent_ms]

    def next_seq(self) -> int:
        self.seq += 1
        return self.seq

    def receive(self, m: dict[str, Any], now_ms: int) -> dict[str, Any]:
        boot = m["boot_id"]
        if boot == self.boot_id:
            if m["seq"] <= self.last_seq:
                return {"result": "ignored"}
            self.last_seq = m["seq"]
            return {"result": "accepted"}
        req = self.requests.get(boot)
        if req is not None and now_ms - req[1] > REQUEST_NONCE_MS:
            req = None
        if m["type"] == M_HELLO and req is not None:
            if parse_hello(bytes.fromhex(m["body"]))["request_nonce"] == req[0]:
                self.boot_id, self.last_seq, self.seq = boot, m["seq"], 0
                self.requests.clear()
                return {"result": "switched"}
        if req is None:
            req = [self.new_nonce(), now_ms, None]
            self.requests.pop(boot, None)
            self.requests[boot] = req
            while len(self.requests) > REQUEST_BOOTS:
                del self.requests[next(iter(self.requests))]
        if req[2] is not None and now_ms - req[2] < REQUEST_RESEND_MS:
            return {"result": "ignored"}
        req[2] = now_ms
        return {"result": "hello_request", "nonce": req[0]}


# ======================================================================== 07

SYNC_BLOCKS_AHEAD = 2  # bootstrap blocks kept beyond the one holding last_fcnt (07 section 3)


class TagTable:
    """The home server's table from 8-byte tag to device (07 section 3).

    Each device has the normal tags of epochs e-1, e and e+1 under its session key
    set, plus, once an uplink counter is known, the session bootstrap (SYNC) tags of
    the block holding last_fcnt and the 2 after it. Call update() for each device
    whenever its keys or last_fcnt change and at every epoch boundary."""

    def __init__(self) -> None:
        self.tags: dict[bytes, list[str]] = {}
        self.by_device: dict[str, list[tuple[str, bytes, bytes]]] = {}  # (kind, index, tag)

    def update(self, device: str, k_dev_tag: bytes, epoch: int, last_fcnt: int | None = None) -> None:
        self.remove(device)
        entries = [("normal", epoch_index(x)) for x in (epoch - 1, epoch, epoch + 1)]
        if last_fcnt is not None:
            first = (max(last_fcnt, 1) - 1) // TAG_BLOCK
            entries += [("bootstrap", b"b" + struct.pack(">I", b)) for b in range(first, first + SYNC_BLOCKS_AHEAD + 1)]
        rows = [(kind, index, tag(k_dev_tag, index)) for kind, index in entries]
        self.by_device[device] = rows
        for _, _, t in rows:
            self.tags.setdefault(t, []).append(device)

    def remove(self, device: str) -> None:
        for _, _, t in self.by_device.pop(device, []):
            self.tags[t].remove(device)
            if not self.tags[t]:
                del self.tags[t]

    def lookup(self, ftag: bytes) -> list[str]:
        return list(self.tags.get(ftag, []))


def identify_route(table: TagTable, frame: bytes, local: bool) -> tuple[str, list[str]]:
    """How the server looks for a frame's device (07 section 4, step 4): "table" with
    the candidates whose MIC to try, "fallback" for trial decryption of a locally heard
    bootstrap frame that missed the table, or "drop". A locally heard bootstrap frame
    whose table candidates all fail the MIC falls back too; that takes the MIC, so it
    is the caller's step."""
    h = parse_header(frame)
    if h is None:
        return "drop", []
    candidates = table.lookup(h.tag)
    if candidates:
        return "table", candidates
    if local and is_bootstrap(h.ftype):
        return "fallback", []
    return "drop", []


REORDER_WINDOW = 16


class UplinkCounter:
    """Server-side uplink counter acceptance (02 section 8.5, 07 section 4, step 5).

    last and seen (the late arrivals accepted below it) are the persisted record of
    07 section 10; restore them with UplinkCounter(last, seen)."""

    def __init__(self, first: int, seen: Iterable[int] = ()):
        self.last = first
        self.seen: set[int] = {x for x in seen if first - REORDER_WINDOW < x < first}

    def offer(self, fcnt: int) -> str:
        if fcnt > self.last:
            self.seen = {x for x in self.seen | {self.last} if x > fcnt - REORDER_WINDOW}
            self.last = fcnt
            return "accept"
        if fcnt == self.last or fcnt in self.seen:
            return "duplicate"
        if fcnt > self.last - REORDER_WINDOW:
            self.seen.add(fcnt)
            return "accept_late"
        return "too_old"


MERGE_WINDOW_MS = 2000      # copies of one transmission (07 section 4, step 3)
FRAME_MEMORY_MS = 60000     # covers the sensor's retry schedule (08 section 5)
MAX_ANSWERS_AGAIN = 3       # one per sensor retry


def frame_key(frame: bytes) -> bytes:
    return hashlib.sha256(frame).digest()[:8]


class UplinkCollector:
    """Server grouping of copies into transmissions and answering of retransmissions
    for one device (07 section 4, steps 3 and 5, and section 4.3)."""

    def __init__(self, first: int, seen: Iterable[int] = ()):
        self.counter = UplinkCounter(first, seen)
        # key -> [first transmission rx_ms, current transmission rx_ms, answered again]; not persisted
        self.frames: dict[bytes, list[int]] = {}

    def receive(self, frame: bytes, arrived_ms: int, age_ms: int = 0) -> dict[str, Any]:
        rx = arrived_ms - age_ms  # a federated copy was received age_ms before its event arrived
        self.frames = {k: v for k, v in self.frames.items() if rx - v[0] < FRAME_MEMORY_MS}
        key = frame_key(frame)
        f = self.frames.get(key)
        if f is not None and rx - f[1] < MERGE_WINDOW_MS:
            return {"result": "copy"}
        h = parse_header(frame)
        if h is None:
            raise ValueError("not a v1 frame")
        counter = self.counter.offer(h.fcnt)
        if f is None:
            # A duplicate of a frame no longer remembered is a replay: never answered again.
            f = self.frames[key] = [rx, rx, MAX_ANSWERS_AGAIN if counter == "duplicate" else 0]
        else:
            f[1] = rx
        # Whether an answer can still make RX2 is not modelled; every answer counts toward the cap.
        answer = False
        if h.ftype in (T_DATA_CONFIRMED, T_HEARTBEAT_CONFIRMED, T_JOIN, T_SYNC):
            if counter in ("accept", "accept_late"):
                answer = True
            elif counter == "duplicate" and f[2] < MAX_ANSWERS_AGAIN:
                f[2] += 1
                answer = True
        return {"result": "transmission", "counter": counter, "answer": answer}


class CommandAcks[C]:
    """Binding DL_ACK to the downlink it acknowledges (07 section 7) for one device.

    Commands are any values compared by equality, such as their encoded bytes. Call
    uplink() for every frame the counter accepts and downlink() for every downlink
    sent with commands. reply_to, awaiting and last_fcnt are the persisted record of
    07 section 10; restore them with CommandAcks(reply_to, awaiting, last_fcnt)."""

    def __init__(self, reply_to: int | None = None, awaiting: Iterable[C] = (),
                 last_fcnt: int | None = None):
        self.reply_to = reply_to
        self.awaiting: list[C] = list(awaiting) if reply_to is not None else []
        self.last_fcnt = last_fcnt  # highest fresh uplink seen, to refuse answers to late arrivals

    def downlink(self, reply_to: int, commands: Sequence[C]) -> list[C]:
        """Record a downlink sent with commands; returns the commands awaiting
        acknowledgement. Raises ValueError for an answer to a late arrival, which
        MUST NOT carry commands."""
        if not commands:
            return self.awaiting
        if self.last_fcnt is not None and reply_to < self.last_fcnt:
            raise ValueError("commands in an answer to a late arrival")
        if reply_to == self.reply_to:
            # Two answers to one uplink: the sensor accepted at most one of them.
            self.awaiting = [c for c in self.awaiting if c in commands]
        else:
            self.reply_to, self.awaiting = reply_to, list(commands)
        return self.awaiting

    def uplink(self, fcnt: int, counter: str, dl_ack: bool) -> list[C]:
        """Returns the commands this uplink marks delivered; counter is the
        UplinkCounter result for it."""
        if counter == "accept":
            self.last_fcnt = fcnt
        if counter not in ("accept", "accept_late") or not dl_ack:
            return []
        if self.reply_to is None or fcnt <= self.reply_to:
            return []
        delivered, self.reply_to, self.awaiting = self.awaiting, None, []
        return delivered


def unwrap(prev_raw: int, prev_total: int, raw: int, modulus: int) -> tuple[int, str]:
    """Counter unwrapping (03 section 6). Returns (new_total, how)."""
    if raw >= prev_raw:
        return prev_total + raw - prev_raw, "increase"
    if prev_raw >= modulus * 3 // 4:
        return prev_total + raw + modulus - prev_raw, "wrap"
    return prev_total + raw, "reset"


# ======================================================================== 09

# Minimal BIP-340 Schnorr signatures over secp256k1, following the BIP's
# reference code. Not constant-time: for test vectors only.
_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
      0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _tagged(tag: str, msg: bytes) -> bytes:
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + msg).digest()


def _add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and a[1] != b[1]:
        return None
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], _P - 2, _P) % _P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], _P - 2, _P) % _P
    x = (lam * lam - a[0] - b[0]) % _P
    return x, (lam * (a[0] - x) - a[1]) % _P


def _mul(pt, k: int):
    r = None
    for i in range(256):
        if (k >> i) & 1:
            r = _add(r, pt)
        pt = _add(pt, pt)
    return r


def _lift_x(x: int):
    if x >= _P:
        return None
    c = (pow(x, 3, _P) + 7) % _P
    y = pow(c, (_P + 1) // 4, _P)
    if y * y % _P != c:
        return None
    return x, y if y % 2 == 0 else _P - y


def schnorr_pub(sk: bytes) -> bytes:
    return _mul(_G, int.from_bytes(sk, "big"))[0].to_bytes(32, "big")


def schnorr_sign(msg: bytes, sk: bytes, aux: bytes = bytes(32)) -> bytes:
    d0 = int.from_bytes(sk, "big")
    if not 1 <= d0 < _N:
        raise ValueError("bad secret key")
    pt = _mul(_G, d0)
    d = d0 if pt[1] % 2 == 0 else _N - d0
    t = bytes(a ^ b for a, b in zip(d.to_bytes(32, "big"), _tagged("BIP0340/aux", aux)))
    px = pt[0].to_bytes(32, "big")
    k0 = int.from_bytes(_tagged("BIP0340/nonce", t + px + msg), "big") % _N
    if k0 == 0:
        raise ValueError("bad nonce")
    r = _mul(_G, k0)
    k = k0 if r[1] % 2 == 0 else _N - k0
    rx = r[0].to_bytes(32, "big")
    e = int.from_bytes(_tagged("BIP0340/challenge", rx + px + msg), "big") % _N
    return rx + ((k + e * d) % _N).to_bytes(32, "big")


def schnorr_verify(msg: bytes, pub: bytes, sig: bytes) -> bool:
    pt = _lift_x(int.from_bytes(pub, "big"))
    r, s_ = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if pt is None or r >= _P or s_ >= _N:
        return False
    e = int.from_bytes(_tagged("BIP0340/challenge", sig[:32] + pub + msg), "big") % _N
    rr = _add(_mul(_G, s_), _mul(pt, _N - e))
    return rr is not None and rr[1] % 2 == 0 and rr[0] == r


KIND_UPLINK = 21110
KIND_DOWNLINK_REQUEST = 21111
KIND_DOWNLINK_RESULT = 21112
FED_VERSION = 1


def nostr_event(sk: bytes, created_at: int, kind: int, tags: list, content: str) -> dict:
    pub = schnorr_pub(sk).hex()
    ser = json.dumps([0, pub, created_at, kind, tags, content], separators=(",", ":"), ensure_ascii=False)
    eid = hashlib.sha256(ser.encode()).digest()
    return {"id": eid.hex(), "pubkey": pub, "created_at": created_at, "kind": kind, "tags": tags,
            "content": content, "sig": schnorr_sign(eid, sk).hex()}


def nostr_error(ev: dict) -> str | None:
    """Why a subscriber drops an event before decoding it (09 section 6.1, NIP-01), or None."""
    ser = json.dumps([0, ev["pubkey"], ev["created_at"], ev["kind"], ev["tags"], ev["content"]],
                     separators=(",", ":"), ensure_ascii=False)
    eid = hashlib.sha256(ser.encode()).digest()
    if eid.hex() != ev["id"]:
        return "id mismatch"
    if not schnorr_verify(eid, bytes.fromhex(ev["pubkey"]), bytes.fromhex(ev["sig"])):
        return "bad signature"
    return None


def nostr_verify(ev: dict) -> bool:
    return nostr_error(ev) is None


def fed_uplink_content(frame: bytes, age_ms: int, receptions: list[tuple[bytes, float, float, int]]) -> str:
    body = bytes([FED_VERSION, len(frame)]) + frame + struct.pack(">HB", age_ms, len(receptions))
    for rx_ref, rssi, snr, flags in receptions:
        body += rx_ref + struct.pack(">hhB", round(rssi * 10), round(snr * 10), flags)
    return base64.b64encode(body).decode()


def parse_fed_uplink(content: str) -> dict[str, Any]:
    """Decode an uplink event's content (09 section 4.1); raises ValueError if malformed."""
    body = base64.b64decode(content, validate=True)
    if len(body) < 2 or body[0] != FED_VERSION:
        raise ValueError("unsupported version")
    p = 2 + body[1]
    if len(body) < p + 3:
        raise ValueError("bad length")
    age_ms, n = struct.unpack(">HB", body[p:p + 3])
    if not 1 <= n <= 8:
        raise ValueError("bad n_rx")
    p += 3
    if len(body) != p + 13 * n:
        raise ValueError("bad length")
    rx = []
    for i in range(n):
        rssi, snr, flags = struct.unpack(">hhB", body[p + 13 * i + 8:p + 13 * i + 13])
        rx.append((body[p + 13 * i:p + 13 * i + 8], rssi / 10, snr / 10, flags))
    return {"frame": body[2:2 + body[1]], "age_ms": age_ms, "receptions": rx}


def fed_downlink_content(rx_ref: bytes, frame: bytes) -> str:
    return base64.b64encode(bytes([FED_VERSION]) + rx_ref + bytes([len(frame)]) + frame).decode()


def fed_result_content(rx_ref: bytes, result: int, offset_us: int) -> str:
    return base64.b64encode(bytes([FED_VERSION]) + rx_ref + struct.pack(">Bi", result, offset_us)).decode()


# ======================================================================== airtime


def airtime_ms(payload_len: int, sf: int, bw_hz: int, cr: int = 1, preamble: int = 8,
               explicit_header: bool = True, crc: bool = True) -> float:
    """Semtech LoRa time-on-air for SF7-SF12. cr: 1..4 for 4/5..4/8."""
    tsym = 2.0 ** sf / bw_hz
    de = 1 if tsym > 0.016 else 0
    num = 8 * payload_len - 4 * sf + 28 + 16 * int(crc) - 20 * (0 if explicit_header else 1)
    n_payload = 8 + max(math.ceil(num / (4 * (sf - 2 * de))) * (cr + 4), 0)
    return ((preamble + 4.25) + n_payload) * tsym * 1000


# 01 section 3: the spreading factor and bandwidth of each region profile. Every other
# parameter airtime depends on is common to all profiles (01 section 2).
REGIONS = {"US915": (9, 500_000), "EU868": (9, 125_000)}
# 01 section 5: transmit time allowed in any rolling hour.
SENSOR_AIRTIME_MS_PER_HOUR = 36_000
PROXY_AIRTIME_MS_PER_HOUR = 72_000


def region_airtime_ms(region: str, frame_len: int) -> float:
    """Time on air of a frame_len-byte frame in a region profile (01), in ms.

    Raises ValueError for a region with no profile, reserved names included."""
    if region not in REGIONS:
        raise ValueError(f"unknown region profile {region!r}")
    sf, bw_hz = REGIONS[region]
    return airtime_ms(frame_len, sf, bw_hz)


# ======================================================================== vectors

K_ROOT = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
DEV_EUI = bytes.fromhex("c5c5000000000001")
SENSOR_PRIV = bytes.fromhex("a0" * 31 + "a1")
SERVER_PRIV = bytes.fromhex("b0" * 31 + "b1")
T0 = 1795226400  # 2026-11-21T02:00:00Z


def tag_vector(k_dev_tag: bytes, index: bytes) -> dict[str, str]:
    seed = tag_seed(k_dev_tag, index)
    pub = ed25519_pub(seed)
    return {"index": index.hex(), "seed": seed.hex(), "pub": pub.hex(), "tag": tag_of_pub(pub).hex()}


def frame_vectors() -> dict:
    root = keys_from(K_ROOT, DEV_EUI)
    s_pub, v_pub = x25519_pub(SENSOR_PRIV), x25519_pub(SERVER_PRIV)
    k_session = derive_session(K_ROOT, DEV_EUI, SENSOR_PRIV, v_pub, s_pub, v_pub)
    assert k_session == derive_session(K_ROOT, DEV_EUI, SERVER_PRIV, s_pub, s_pub, v_pub)
    sess = keys_from(k_session, DEV_EUI)
    e = epoch_of(T0)
    nt = normal_tag(sess.k_dev_tag, e)
    join_tag = bootstrap_tag(root.k_dev_tag, 1)

    def case(name, keyset, keys, ftype, ftag, fcnt, pt, note):
        return {"name": name, "note": note, "keys": keyset, "type": ftype, "fcnt": fcnt,
                "tag": ftag.hex(), "plaintext": pt.hex(), "frame": seal(keys, ftype, ftag, fcnt, pt).hex()}

    contact_open = encode_reading(0x00, 0x01, 1)
    contact_closed = encode_reading(0x00, 0x01, 0)
    battery = encode_reading(0xFF, 0x07, 95)
    return {
        "spec": "ConnectSensors frame v1 (02) and key exchange (04)",
        "inputs": {"k_root": K_ROOT.hex(), "dev_eui": DEV_EUI.hex(),
                   "sensor_ephemeral_private": SENSOR_PRIV.hex(),
                   "server_ephemeral_private": SERVER_PRIV.hex(), "time": T0, "epoch": e},
        "derived": {
            "root": {"k_enc": root.k_enc.hex(), "k_dev_tag": root.k_dev_tag.hex()},
            "sensor_ephemeral_public": s_pub.hex(), "server_ephemeral_public": v_pub.hex(),
            "k_session": k_session.hex(),
            "session": {"k_enc": sess.k_enc.hex(), "k_dev_tag": sess.k_dev_tag.hex()},
        },
        "tags": {
            "note": "02 section 6.1; index is the HMAC input after \"cs1 tag seed\"",
            "normal": [{"keys": "session", "epoch": x, **tag_vector(sess.k_dev_tag, epoch_index(x))}
                       for x in (e - 1, e, e + 1)],
            "bootstrap": [{"keys": keys, "fcnt": f, **tag_vector(ks.k_dev_tag, block_index(f))}
                          for keys, ks in (("root", root), ("session", sess)) for f in (1, 64, 65, 129)],
        },
        "frames": [
            case("join", "root", root, T_JOIN, join_tag, 1, bytes([UF_TIME_UNSURE]) + s_pub,
                 "JOIN with the sensor's ephemeral public key; root bootstrap tag of block 0"),
            case("downlink_key_exchange", "root", root, T_DOWNLINK, join_tag, 1,
                 downlink_payload(1, T0, 0, command(CMD_KEY_EXCHANGE, v_pub)),
                 "answer to JOIN, with its tag: server ephemeral public key; the sensor is now provisional"),
            case("heartbeat_first", "session", sess, T_HEARTBEAT_CONFIRMED, nt, 2,
                 bytes([UF_DL_ACK]) + contact_closed,
                 "first frame under session keys, normal tag from KEY_EXCHANGE's server_time; acknowledges "
                 "KEY_EXCHANGE; the server marks the device PAIRED"),
            case("downlink_paired", "session", sess, T_DOWNLINK, nt, 1,
                 downlink_payload(2, T0 + 3, 0, command(CMD_NOP)),
                 "answer to heartbeat_first, first downlink under this k_session: the sensor is now PAIRED. "
                 "It carries NOP, so the next uplink sets DL_ACK"),
            case("data_confirmed", "session", sess, T_DATA_CONFIRMED, nt, 3,
                 bytes([UF_DL_ACK]) + contact_open, "door opened; acknowledges the NOP"),
            case("downlink_ack", "session", sess, T_DOWNLINK, nt, 2, downlink_payload(3, T0 + 60, 0),
                 "plain acknowledgement of fcnt 3"),
            case("heartbeat", "session", sess, T_HEARTBEAT, nt, 4, bytes([0]) + contact_open + battery,
                 "heartbeat with current state and battery"),
            case("sync_after_reboot", "session", sess, T_SYNC, bootstrap_tag(sess.k_dev_tag, 65), 65,
                 bytes([UF_TIME_UNSURE]) + contact_open,
                 "clock lost on battery change; fcnt jumped to the next reserved block; session bootstrap "
                 "tag of block 1"),
        ],
        "invalid": invalid_frames(sess, nt, bytes([UF_DL_ACK]) + contact_open),
    }


def seal_raw(keys: DeviceKeys, magic: int, ver_type: int, ftag: bytes, fcnt: int,
             plaintext: bytes, direction: int) -> bytes:
    """seal() without its checks, for frames a receiver must reject."""
    hdr = bytes([magic, ver_type]) + ftag + struct.pack(">I", fcnt)
    return hdr + AESCCM(keys.k_enc, tag_length=MIC_LEN).encrypt(nonce(keys.dev_eui, fcnt, direction), plaintext, hdr)


def invalid_frames(sess: DeviceKeys, nt: bytes, pt: bytes) -> list[dict[str, Any]]:
    """Frames under the session keys that a receiver must discard. Each carries a valid
    MIC for its own header unless the MIC is the point, so only the named rule rejects it.
    Counters 5 and up are unused by the valid frames."""
    vt = (VERSION << 4) | T_DATA_CONFIRMED
    good = seal(sess, T_DATA_CONFIRMED, nt, 3, pt)
    bad_mic = good[:-1] + bytes([good[-1] ^ 0x01])
    cases = [
        ("bad_mic", bad_mic, "MIC check failed", "02 section 7", False,
         "data_confirmed from the valid frames with the last MIC bit flipped"),
        ("wrong_direction", seal_raw(sess, MAGIC, vt, nt, 5, pt, DIR_DOWN), "MIC check failed", "02 section 7",
         False, "uplink type sealed with the downlink direction byte in the nonce"),
        ("length_22", seal_raw(sess, MAGIC, vt, nt, 6, b"", DIR_UP), "frame length out of range",
         "02 section 3", True, "empty payload: 22 bytes, one short of the minimum, with a valid MIC"),
        ("length_87", seal_raw(sess, MAGIC, vt, nt, 7, pt + bytes(MAX_PAYLOAD + 1 - len(pt)), DIR_UP),
         "frame length out of range", "02 section 3", True,
         "65-byte payload: 87 bytes, one over the maximum, with a valid MIC"),
        ("bad_magic", seal_raw(sess, 0xC4, vt, nt, 8, pt, DIR_UP), "bad magic", "02 section 3", True,
         "magic 0xC4, with a valid MIC"),
        ("version_2", seal_raw(sess, MAGIC, (2 << 4) | T_DATA_CONFIRMED, nt, 9, pt, DIR_UP),
         "unsupported version", "02 section 3", True, "version 2, with a valid MIC"),
        ("type_0", seal_raw(sess, MAGIC, VERSION << 4, nt, 10, pt, DIR_UP), "reserved frame type",
         "02 sections 4 and 12", True, "reserved type 0x0, with a valid MIC"),
    ]
    return [{"name": n, "note": note, "rule": rule, "keys": "session", "frame": f.hex(), "reason": reason,
             "proxy_discards": keyless} for n, f, reason, rule, keyless, note in cases]


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
    out.append({"name": "same_kind_two_channels", "encoded": "000101" + "010100",
                "decoded": decode_readings(bytes.fromhex("000101010100")),
                "note": "the same kind on two channels is not a duplicate"})
    invalid = [
        ("truncated_value", "004008", "a 2-byte temperature with one value byte"),
        ("truncated_header", "000101" + "00", "a complete reading, then a lone channel byte"),
        ("truncated_length", "02c1", "a variable-length kind with no length byte"),
        ("truncated_variable", "02c1056869", "text of length 5 with 2 bytes"),
        ("reserved_kind", "000101" + "000001", "kind 0x00 after a valid reading"),
        ("duplicate_reading", "000101" + "000100", "(channel 0, contact) twice"),
        ("duplicate_unknown_kind", "00590102" + "00590304", "an unassigned kind is still a (channel, kind) pair"),
    ]
    bad = []
    for name, enc, note in invalid:
        try:
            decode_readings(bytes.fromhex(enc))
            raise AssertionError(name)
        except ValueError as ex:
            bad.append({"name": name, "encoded": enc, "reason": str(ex), "rule": "03 section 2", "note": note})
    return {"spec": "ConnectSensors payload v1 (03)", "readings": out, "invalid": bad}


def qr_checked(*fields: str) -> str:
    """A code from arbitrary fields with a correct CHECK, so only the field under test is wrong."""
    body = ":".join(fields)
    return body + ":" + hashlib.sha256(body.encode()).hexdigest()[:4].upper()


def pairing_vectors() -> dict:
    good = qr_encode(DEV_EUI, K_ROOT, "US915", "CS.CONTACT-1")
    bad_check = good[:-1] + ("0" if good[-1] != "0" else "1")
    eui, key = DEV_EUI.hex().upper(), b32(K_ROOT)
    step = "04 section 3.2 step "
    invalid = [
        (qr_checked("CS", "1", eui, key, "US915"), step + "2", "6 fields"),
        (qr_checked("CS", "1", eui, key, "US915", "CS.CONTACT-1", "X"), step + "2", "8 fields"),
        (qr_checked("CX", "1", eui, key, "US915", "CS.CONTACT-1"), step + "2", "prefix CX"),
        (qr_checked("CS", "2", eui, key, "US915", "CS.CONTACT-1"), step + "3", "version 2, correct CHECK"),
        (bad_check, step + "4", "last CHECK digit changed"),
        (qr_checked("CS", "1", eui[:-1], key, "US915", "CS.CONTACT-1"), step + "5", "DEV_EUI of 15 digits"),
        (qr_checked("CS", "1", eui[:-1] + "G", key, "US915", "CS.CONTACT-1"), step + "5", "DEV_EUI not hex"),
        (qr_checked("CS", "1", eui, key[:-1], "US915", "CS.CONTACT-1"), step + "5", "K_ROOT of 25 characters"),
        (qr_checked("CS", "1", eui, key[:-1] + "1", "US915", "CS.CONTACT-1"), step + "5",
         "K_ROOT with 1, not in the base32 alphabet"),
        (qr_checked("CS", "1", eui, key, "US915", ""), step + "5", "empty PROFILE"),
        (qr_checked("CS", "1", eui, key, "US915", "CS." + "X" * 30), step + "5", "PROFILE of 33 characters"),
        (qr_checked("CS", "1", eui, key, "US915", "CS_CONTACT-1"), step + "5 (03 section 9.1)",
         "_ is not allowed in PROFILE"),
    ]
    bad = []
    for code, rule, note in invalid:
        try:
            qr_parse(code)
            raise AssertionError(note)
        except ValueError as ex:
            bad.append({"code": code, "reason": str(ex), "rule": rule, "note": note})
    spaced = "  " + good + "\n"
    return {
        "spec": "ConnectSensors pairing codes (04)",
        "valid": [{"code": good, "parsed": qr_parse(good)},
                  {"code": good.lower(), "parsed": qr_parse(good.lower()), "note": "lowercase input accepted"},
                  {"code": spaced, "parsed": qr_parse(spaced), "note": "surrounding whitespace removed (step 1)"}],
        "invalid": bad,
        "region_check": {
            "rule": step + "6", "code": good,
            "cases": [{"network_region": "US915", "warn": False},
                      {"network_region": "EU868", "warn": True,
                       "note": "parses, but the server warns and asks for confirmation"}]},
        "root_floor": root_floor_vectors(),
        "provisional": provisional_vectors(),
    }


SENSOR_PRIVS = [bytes.fromhex(b * 32) for b in ("a2", "a3", "a4")]
SERVER_PRIVS = [bytes.fromhex(b * 32) for b in ("b2", "b3", "b4")]


def root_floor_vectors() -> dict:
    """The sensor's root downlink floor across re-pairing, a rolled-back server and a factory reset."""
    sensor = SensorPairing(K_ROOT, DEV_EUI)
    server, rolled_back, new_owner = (JoinResponder(K_ROOT, DEV_EUI) for _ in range(3))
    seq = []

    def join(fcnt, priv, note):
        seq.append({"event": "join", "fcnt": fcnt, "sensor_ephemeral_private": priv.hex(),
                    "frame": sensor.join(fcnt, priv).hex(), "note": note})
        return bytes.fromhex(seq[-1]["frame"])

    def downlink(frame, note):
        result = sensor.downlink(frame)
        seq.append({"event": "downlink", "frame": frame.hex(), "note": note, "result": result,
                    "root_floor": sensor.root_floor,
                    "k_session": sensor.k_session.hex() if result == "accept" else None})

    def other(event, note):
        getattr(sensor, event)()
        seq.append({"event": event, "note": note, "root_floor": sensor.root_floor})

    j = join(1, SENSOR_PRIV, "first pairing; frame-v1.json join")
    first = server.join(j, SERVER_PRIV, T0)["frame"]
    downlink(first, "KEY_EXCHANGE, root fcnt_down 1; frame-v1.json downlink_key_exchange")
    other("leave", "LEAVE: keys erased, root floor kept")
    j = join(70, SENSOR_PRIVS[0], "paired again with the same server")
    second = server.join(j, SERVER_PRIVS[0], T0 + 3600)["frame"]
    downlink(second, "KEY_EXCHANGE, root fcnt_down 2: the server never resets its root counter")
    other("leave", "LEAVE again")
    j = join(75, SENSOR_PRIVS[1], "pairing with a server whose root counter rolled back")
    downlink(rolled_back.join(j, SERVER_PRIVS[1], T0 + 7200)["frame"],
             "KEY_EXCHANGE, root fcnt_down 1: at or below the floor, discarded")
    downlink(second, "replayed KEY_EXCHANGE answering an older JOIN")
    other("factory_reset", "factory reset: root floor back to 0")
    j = join(140, SENSOR_PRIVS[2], "new owner pairs after the reset")
    downlink(new_owner.join(j, SERVER_PRIVS[2], T0 + 86400)["frame"],
             "KEY_EXCHANGE, root fcnt_down 1 from the new owner's server: accepted")
    return {"note": "inputs from frame-v1.json; a sensor in JOINING checks each downlink (02 section 10.2)",
            "sequence": seq}


def provisional_vectors() -> dict:
    """The sensor's provisional SESSION state (04 section 4.3): PAIRED on the first
    accepted session downlink, back to UNPAIRED when the first session uplink goes
    unanswered."""
    fv = frame_vectors()
    frames = {f["name"]: bytes.fromhex(f["frame"]) for f in fv["frames"]}
    sensor = SensorPairing(K_ROOT, DEV_EUI)
    server = JoinResponder(K_ROOT, DEV_EUI)
    seq = []

    def step(event: str, note: str, **kw: Any) -> None:
        seq.append({"event": event, "note": note, **kw, "state": sensor.state, "root_floor": sensor.root_floor,
                    "has_session": sensor.k_session is not None})

    step("join", "frame-v1.json join", fcnt=1, sensor_ephemeral_private=SENSOR_PRIV.hex(),
         frame=sensor.join(1, SENSOR_PRIV).hex())
    server.join(frames["join"], SERVER_PRIV, T0)
    step("downlink", "KEY_EXCHANGE: provisional", frame=frames["downlink_key_exchange"].hex(),
         result=sensor.downlink(frames["downlink_key_exchange"]))
    hb = sensor.uplink(T_HEARTBEAT_CONFIRMED, 2, T0 + 1, bytes.fromhex(
        next(f["plaintext"] for f in fv["frames"] if f["name"] == "heartbeat_first")))
    assert hb == frames["heartbeat_first"]
    step("uplink", "first session uplink, normal tag; frame-v1.json heartbeat_first", fcnt=2, unix_time=T0 + 1,
         frame=hb.hex())
    step("downlink", "a session downlink answering another fcnt: discarded, still provisional",
         frame=frames["downlink_ack"].hex(), result=sensor.downlink(frames["downlink_ack"]))
    step("downlink", "frame-v1.json downlink_paired: PAIRED", frame=frames["downlink_paired"].hex(),
         result=sensor.downlink(frames["downlink_paired"]))
    sensor.leave()
    step("leave", "LEAVE")
    j = sensor.join(70, SENSOR_PRIVS[0])
    step("join", "paired again", fcnt=70, sensor_ephemeral_private=SENSOR_PRIVS[0].hex(), frame=j.hex())
    ke = server.join(j, SERVER_PRIVS[0], T0 + 3600)["frame"]
    step("downlink", "KEY_EXCHANGE, root fcnt_down 2: provisional", frame=ke.hex(), result=sensor.downlink(ke))
    up = sensor.uplink(T_HEARTBEAT_CONFIRMED, 71, T0 + 3601, bytes([UF_DL_ACK]))
    step("uplink", "first session uplink", fcnt=71, unix_time=T0 + 3601, frame=up.hex())
    sensor.undelivered()
    step("undelivered", "no answer after its retries: k_session erased, root floor kept")
    return {"note": "inputs from frame-v1.json; server_time of each KEY_EXCHANGE sets the sensor's clock",
            "sequence": seq}


def join_vectors() -> dict:
    """Server answers to JOIN for one device (07 section 5.1)."""
    sensor = SensorPairing(K_ROOT, DEV_EUI)
    join_a, join_b, join_c = (sensor.join(f, p) for f, p in
                              ((1, SENSOR_PRIV), (2, SENSOR_PRIVS[0]), (66, SENSOR_PRIVS[1])))
    steps = [
        (join_a, SERVER_PRIV, T0, "first JOIN: new exchange (frame-v1.json downlink_key_exchange)"),
        (join_a, None, None, "retry 1: the cached frame, byte for byte"),
        (join_a, None, None, "retry 2"),
        (join_a, None, None, "retry 3, the sensor's last: answered, and the exchange is reported stalled"),
        (join_b, SERVER_PRIVS[0], T0 + 120, "button pressed again: new sensor_pub, next root value"),
        (join_b, None, None, "retry 1 of the new JOIN: same frame, same k_session"),
        (None, None, None, "first session uplink verified: device PAIRED"),
        (join_c, SERVER_PRIVS[1], T0 + 86400, "re-paired a day later: the root counter continues"),
    ]
    srv = JoinResponder(K_ROOT, DEV_EUI)
    seq = []
    for frame, priv, t, note in steps:
        if frame is None:
            srv.paired()
            seq.append({"event": "paired", "note": note})
            continue
        r = srv.join(frame, priv, t)
        seq.append({"event": "join", "join": frame.hex(), "server_ephemeral_private": priv.hex() if priv else None,
                    "server_time": t, "note": note, "action": r["action"],
                    "root_fcnt_down": parse_header(r["frame"]).fcnt, "frame": r["frame"].hex(),
                    "k_session": r["k_session"].hex(), "stalled": r["stalled"]})
    return {"stall_retransmissions": JOIN_STALL_RETRANSMISSIONS, "root_fcnt_down_before": 0,
            "note": "inputs from frame-v1.json", "sequence": seq}


PROXY_KEY = bytes.fromhex("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a")
PROXY_ID = bytes.fromhex("348518fffe000001")  # EUI-64 from MAC 34:85:18:00:00:01


def envelope_vectors() -> dict:
    fv = frame_vectors()
    frames = {f["name"]: bytes.fromhex(f["frame"]) for f in fv["frames"]}
    boot = 0x1A2B3C4D
    rx_t = 123_456_789
    nonce = 0x5EED1234
    counters = [10, 9, 1, 0, 0, 2, 0]
    msgs = [
        ("hello", M_HELLO, boot, 1,
         hello_body(CAP_DOWNLINK, "US915", 918_500_000, 9, 500, 42, counters, 7, "cs_proxy 0.1.0"),
         "proxy announces itself after boot"),
        ("hello_request", M_HELLO_REQUEST, boot, 0, hello_request_body(nonce),
         "server does not know this boot yet and asks for a HELLO echoing its nonce"),
        ("hello_answer", M_HELLO, boot, 2,
         hello_body(CAP_DOWNLINK, "US915", 918_500_000, 9, 500, 42, counters, 7, "cs_proxy 0.1.0", nonce),
         "proxy answers the HELLO_REQUEST at once"),
        ("server_status", M_SERVER_STATUS, boot, 1,
         server_status_body(T0, 2), "server switches to the boot and answers HELLO seq 2 with its time"),
        ("uplink", M_UPLINK, boot, 3, uplink_body(rx_t, -97.5, 6.3, 0, frames["data_confirmed"]),
         "proxy forwards the DATA_CONFIRMED frame heard at -97.5 dBm, SNR 6.3 dB"),
        ("downlink", M_DOWNLINK, boot, 2, downlink_msg_body(rx_t, 1_000_000, frames["downlink_ack"]),
         "server asks the proxy to transmit the acknowledgement in RX1"),
        ("tx_result", M_TX_RESULT, boot, 4, tx_result_body(2, 0, 1800),
         "proxy reports it transmitted downlink seq 2, 1.8 ms after the requested time"),
        ("uplink_ts_uncertain", M_UPLINK, boot, 5,
         uplink_body(rx_t + 30_000_000, -104.0, -2.5, UPF_TS_UNCERTAIN, frames["heartbeat"]),
         "HEARTBEAT heard after a long main-loop gap: TS_UNCERTAIN set, so the server keeps it out of RX1"),
        ("tx_result_early", M_TX_RESULT, boot, 6, tx_result_body(3, 0, -350),
         "SENT with a negative offset_us: the radio was commanded 0.35 ms before tx_at"),
    ]
    msgs += [(f"tx_result_{name.lower()}", M_TX_RESULT, boot, 6 + code, tx_result_body(3 + code, code, 0),
              f"downlink seq {3 + code} not transmitted: {name}, offset_us 0")
             for code, name in enumerate(TX_RESULTS) if code]
    return {
        "spec": "ConnectSensors proxy envelope v1 (05)",
        "inputs": {"proxy_key": PROXY_KEY.hex(), "proxy_id": PROXY_ID.hex()},
        "messages": [{"name": n, "note": note, "type": t, "boot_id": b, "seq": q, "body": body.hex(),
                      "message": envelope(PROXY_KEY, t, PROXY_ID, b, q, body).hex()}
                     for n, t, b, q, body, note in msgs],
        "invalid": invalid_envelopes(boot, frames["data_confirmed"]),
        "session": session_vectors(),
    }


def invalid_envelopes(boot: int, frame: bytes) -> list[dict[str, Any]]:
    """Messages a receiver must discard (05 section 3), or whose body it must reject (05 section 5)."""
    up = envelope(PROXY_KEY, M_UPLINK, PROXY_ID, boot, 3, uplink_body(123_456_789, -97.5, 6.3, 0, frame))
    v2 = bytes([2]) + up[1:-ENV_MAC]
    v2 += hmac.new(PROXY_KEY, v2, hashlib.sha256).digest()[:ENV_MAC]
    short_body = uplink_body(123_456_789, -97.5, 6.3, 0, frame)[:-1]
    cases = [
        ("bad_mac", up[:20] + bytes([up[20] ^ 1]) + up[21:], "bad MAC", "05 section 3", "one bit changed"),
        ("version_2", v2, "not a v1 envelope", "05 section 3", "version 2, with a valid MAC"),
        ("too_short", envelope(PROXY_KEY, M_HELLO_REQUEST, PROXY_ID, boot, 0, b"")[:-1], "not a v1 envelope",
         "05 section 3", "33 bytes, one under the minimum"),
        ("uplink_frame_len", envelope(PROXY_KEY, M_UPLINK, PROXY_ID, boot, 4, short_body), "bad UPLINK length",
         "05 section 5.1", "frame_len one more than the bytes that follow; valid MAC"),
        ("tx_result_length", envelope(PROXY_KEY, M_TX_RESULT, PROXY_ID, boot, 5, tx_result_body(2, 0, 0)[:8]),
         "bad TX_RESULT length", "05 section 5.5", "8-byte body; valid MAC"),
    ]
    return [{"name": n, "note": note, "rule": rule, "message": m.hex(), "reason": reason}
            for n, m, reason, rule, note in cases]


def envelope_error(key: bytes, data: bytes) -> str | None:
    """Why a receiver rejects a message or its body, or None."""
    try:
        m = open_envelope(key, data)
        body = bytes.fromhex(m["body"])
        if m["type"] == M_UPLINK:
            parse_uplink(body)
        elif m["type"] == M_TX_RESULT:
            parse_tx_result(body)
    except ValueError as ex:
        return str(ex)
    return None


SESSION_NONCES = [0x5EED0001, 0x5EED0002, 0x5EED0003, 0x5EED0004, 0x5EED0005]


def session_vectors() -> dict:
    """Boot handshake, server restart and resync, and replays (05 section 3.2)."""
    boot, old_boot = 0x1A2B3C4D, 0x0BADB007
    nonces = iter(SESSION_NONCES)
    proxy = ProxyLink(boot)
    server = ServerLink(lambda: next(nonces))
    pseq = 0
    steps = []

    def env(t, b, q, body):
        return envelope(PROXY_KEY, t, PROXY_ID, b, q, body)

    def hello(q, nonce=0, b=boot):
        return env(M_HELLO, b, q, hello_body(CAP_DOWNLINK, "US915", 918_500_000, 9, 500, 0, [0] * 7, 0,
                                             "cs_proxy 0.1.0", nonce))

    def nxt():
        nonlocal pseq
        pseq += 1
        return pseq

    def up(t, msg, note, sender="proxy"):
        m = open_envelope(PROXY_KEY, msg)
        if sender == "proxy":
            proxy.sent(m, t)
        steps.append({"t_ms": t, "to": "server", "from": sender, "note": note, "message": msg.hex(),
                      **server.receive(m, t)})
        return steps[-1]

    def down(t, msg, note):
        m = open_envelope(PROXY_KEY, msg)
        steps.append({"t_ms": t, "to": "proxy", "note": note, "message": msg.hex(), **proxy.receive(m, t)})
        return steps[-1]

    def status(hello_seq):
        return env(M_SERVER_STATUS, boot, server.next_seq(), server_status_body(T0, hello_seq))

    def req(b, n):
        return env(M_HELLO_REQUEST, b, 0, hello_request_body(n))

    n1 = up(0, hello(nxt()), "HELLO after boot: the server does not know this boot")["nonce"]
    down(20, req(boot, n1), "HELLO_REQUEST for the proxy's boot")
    first_hello = hello(nxt(), n1)
    up(20, first_hello, "HELLO echoing the nonce: the server switches to this boot")
    first_status = status(pseq)
    down(40, first_status, "SERVER_STATUS answering that HELLO")
    uplink = env(M_UPLINK, boot, nxt(), b"\x00")
    up(1000, uplink, "UPLINK")
    dl = env(M_DOWNLINK, boot, server.next_seq(), b"\x00")
    down(1050, dl, "DOWNLINK")
    down(1060, dl, "the same DOWNLINK replayed")
    up(1100, uplink, "the same UPLINK replayed: seq not above the highest", "replay")
    dl_a = env(M_DOWNLINK, boot, server.next_seq(), b"\x00")
    dl_b = env(M_DOWNLINK, boot, server.next_seq(), b"\x00")
    down(1200, dl_b, "DOWNLINK overtaking the one sent before it")
    down(1210, dl_a, "the earlier DOWNLINK arriving late: not above the floor (a proxy has no reorder window)")
    down(3000, status(0), "unsolicited SERVER_STATUS (hello_seq 0)")
    old = hello(9, b=old_boot)
    n_old = up(5000, old, "HELLO from an earlier boot, replayed: no switch, only a HELLO_REQUEST", "replay")["nonce"]
    up(5100, old, "replayed again within a second: no second HELLO_REQUEST", "replay")
    down(6000, req(old_boot, n_old), "that HELLO_REQUEST reaches the proxy: not its boot")

    steps.append({"t_ms": 10000, "event": "server_restart", "note": "the server restarts and forgets every session"})
    server = ServerLink(lambda: next(nonces))
    n2 = up(12000, env(M_UPLINK, boot, nxt(), b"\x00"), "UPLINK to the restarted server: unknown boot")["nonce"]
    down(12020, req(boot, n2), "HELLO_REQUEST; its seq is not checked")
    up(12020, hello(nxt(), n2), "HELLO echoing the nonce: the restarted server switches")
    st = status(pseq)
    down(12040, st, "SERVER_STATUS seq 1, at or below the proxy's floor, echoing that HELLO: resync")
    down(12045, st, "the same SERVER_STATUS replayed: its echo is used up")
    down(13000, env(M_DOWNLINK, boot, server.next_seq(), b"\x00"), "DOWNLINK from the restarted server")
    down(14000, req(boot, n2), "HELLO_REQUEST replayed: the HELLO waits until 5 s after the last requested one")
    up(17020, hello(nxt(), n2), "that HELLO: the boot is current, so it is a normal HELLO")
    down(17040, status(pseq), "SERVER_STATUS answering it")
    up(20000, old, "HELLO from the earlier boot replayed again: still no switch", "replay")
    up(21000, first_hello, "HELLO from this boot recorded before the restart: stale seq", "replay")
    down(22000, first_status, "SERVER_STATUS from before the restart replayed: its echo is used up")
    return {"boot_id": boot, "hello_echo_slots": HELLO_ECHO_SLOTS, "hello_echo_max_age_ms": HELLO_ECHO_MAX_AGE_MS,
            "hello_request_gap_ms": HELLO_REQUEST_GAP_MS, "request_nonce_ms": REQUEST_NONCE_MS,
            "request_resend_ms": REQUEST_RESEND_MS, "request_boots": REQUEST_BOOTS, "nonces": SESSION_NONCES,
            "steps": steps}


def verify_session(sv: dict) -> int:
    bad = 0
    nonces = iter(sv["nonces"])
    proxy = ProxyLink(sv["boot_id"])
    server = ServerLink(lambda: next(nonces))
    for c in sv["steps"]:
        if c.get("event") == "server_restart":
            server = ServerLink(lambda: next(nonces))
            continue
        m = open_envelope(PROXY_KEY, bytes.fromhex(c["message"]))
        if c["to"] == "server":
            if c["from"] == "proxy":
                proxy.sent(m, c["t_ms"])
            got = server.receive(m, c["t_ms"])
        else:
            got = proxy.receive(m, c["t_ms"])
        want = {k: v for k, v in c.items() if k not in ("t_ms", "to", "from", "note", "message")}
        ok = got == want
        print(f"{'ok  ' if ok else 'FAIL'} session {c['t_ms']} ms to {c['to']} -> {want['result']}")
        bad += not ok
    return bad


def server_vectors() -> dict:
    ctr = UplinkCounter(10)
    seq = [11, 13, 12, 12, 11, 30, 14, 15, 15, 29, 100000, 99990, 99984]
    fcnt_cases = [{"fcnt": f, "result": ctr.offer(f)} for f in seq]
    raws = [60000, 65000, 120, 50, 50, 900]
    total, prev = raws[0], raws[0]
    unwrap_cases = [{"raw": raws[0], "total": total, "how": "first"}]
    for r in raws[1:]:
        total, how = unwrap(prev, total, r, 65536)
        prev = r
        unwrap_cases.append({"raw": r, "total": total, "how": how})
    return {"spec": "ConnectSensors network server rules (07)",
            "uplink_counter": {"first_accepted": 10, "window": REORDER_WINDOW, "sequence": fcnt_cases},
            "counter16_unwrap": {"modulus": 65536, "sequence": unwrap_cases},
            "retransmission": retransmission_vectors(),
            "dl_ack": dl_ack_vectors(),
            "join": join_vectors(),
            "tag_table": tag_table_vectors()}


def tag_table_vectors() -> dict:
    """The home server's tag table (07 section 3) and the bootstrap fallback (07 section 4, step 4)."""
    fv = frame_vectors()
    frames = {f["name"]: bytes.fromhex(f["frame"]) for f in fv["frames"]}
    sess = keys_from(bytes.fromhex(fv["derived"]["k_session"]), DEV_EUI)
    e = epoch_of(T0)
    table = TagTable()
    table.update("device", sess.k_dev_tag, e, 4)
    far_sync = seal(sess, T_SYNC, bootstrap_tag(sess.k_dev_tag, 200), 200, bytes([UF_TIME_UNSURE]))
    late = seal(sess, T_HEARTBEAT, normal_tag(sess.k_dev_tag, e + 2), 5, bytes([0]))
    cases = [
        ("heartbeat", frames["heartbeat"], True, "normal tag of epoch e"),
        ("sync_after_reboot", frames["sync_after_reboot"], True, "fcnt 65: block 1, in the table"),
        ("sync_far", far_sync, True, "fcnt 200: block 3, past the table; heard locally, so trial decryption"),
        ("sync_far_federated", far_sync, False, "the same frame heard through federation: not tried"),
        ("join", frames["join"], True, "JOIN of a device being paired: never in the table, so trial decryption"),
        ("heartbeat_epoch_e_plus_2", late, True, "normal tag outside e-1..e+1: no fallback for normal frames"),
    ]
    out = []
    for name, frame, local, note in cases:
        route, devices = identify_route(table, frame, local)
        out.append({"name": name, "note": note, "local": local, "frame": frame.hex(), "route": route,
                    "devices": devices})
    return {"note": "the device of frame-v1.json, paired, at epoch e with last_fcnt 4", "epoch": e,
            "last_fcnt": 4, "sync_blocks_ahead": SYNC_BLOCKS_AHEAD,
            "entries": [{"kind": k, "index": i.hex(), "tag": t.hex()} for k, i, t in table.by_device["device"]],
            "lookups": out}


def dl_ack_steps(ctr: UplinkCounter, acks: CommandAcks[str], steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for s in steps:
        if s["event"] == "downlink":
            try:
                out.append({**s, "awaiting": list(acks.downlink(s["reply_to"], s["commands"]))})
            except ValueError:
                out.append({**s, "refused": True, "awaiting": list(acks.awaiting)})
        else:
            counter = ctr.offer(s["fcnt"])
            out.append({**s, "counter": counter, "delivered": acks.uplink(s["fcnt"], counter, s["dl_ack"])})
    return out


def dl_ack_vectors() -> dict:
    """DL_ACK marks commands delivered only on an uplink newer than their downlink (07 section 7)."""
    steps = [
        {"event": "uplink", "fcnt": 20, "dl_ack": False, "note": "commands queued: SET_HEARTBEAT"},
        {"event": "downlink", "reply_to": 20, "commands": ["SET_HEARTBEAT"]},
        {"event": "uplink", "fcnt": 21, "dl_ack": True, "note": "fresh fcnt above reply_to: settles"},
        {"event": "downlink", "reply_to": 21, "commands": ["SET_VALUE"], "note": "the user sets a channel value"},
        {"event": "uplink", "fcnt": 18, "dl_ack": True, "via": "relay",
         "note": "neighbor's late copy of an older frame, with DL_ACK for an older downlink: settles nothing"},
        {"event": "uplink", "fcnt": 21, "dl_ack": True,
         "note": "retransmission of 21 (duplicate): not acted on, settles nothing"},
        {"event": "uplink", "fcnt": 23, "dl_ack": False,
         "note": "arrives before 22; the sensor already sent its DL_ACK in 22: settles nothing yet"},
        {"event": "uplink", "fcnt": 22, "dl_ack": True, "note": "late arrival above reply_to: settles"},
        {"event": "uplink", "fcnt": 24, "dl_ack": False, "note": "commands queued: SET_HEARTBEAT"},
        {"event": "downlink", "reply_to": 24, "commands": ["SET_HEARTBEAT"]},
        {"event": "downlink", "reply_to": 24, "commands": ["SET_HEARTBEAT", "LEAVE"],
         "note": "answer to a retransmission of 24, after the user removed the device"},
        {"event": "uplink", "fcnt": 25, "dl_ack": True,
         "note": "acknowledges one answer to 24, not known which: LEAVE stays queued"},
        {"event": "downlink", "reply_to": 25, "commands": ["LEAVE"]},
        {"event": "uplink", "fcnt": 19, "dl_ack": False, "note": "late arrival of a confirmed uplink, which the server answers"},
        {"event": "downlink", "reply_to": 19, "commands": ["LEAVE"],
         "note": "MUST NOT carry commands: the answer to a late arrival is refused"},
        {"event": "uplink", "fcnt": 26, "dl_ack": True, "note": "the sensor's final HEARTBEAT: settles"},
    ]
    ctr = UplinkCounter(17)
    return {"first_accepted": 17, "sequence": dl_ack_steps(ctr, CommandAcks[str](), steps)}


def retransmission_vectors() -> dict:
    """A confirmed uplink whose answers are lost, retried by the sensor (08 section 5)."""
    frame = next(bytes.fromhex(f["frame"]) for f in frame_vectors()["frames"] if f["name"] == "data_confirmed")
    steps = [
        (0, 0, "proxy A", "original"),
        (60, 0, "proxy B", "second proxy, same transmission"),
        (1500, 1350, "relay", "neighbor's copy of the original"),
        (2600, 2450, "relay", "late neighbor's copy: received at 150 ms by age_ms"),
        (5000, 0, "proxy A", "retry 1: answered again"),
        (5040, 0, "proxy B", "second proxy, retry 1"),
        (13500, 0, "proxy A", "retry 2: answered again"),
        (33000, 0, "proxy A", "retry 3: answered again"),
        (33800, 700, "relay", "neighbor's copy of retry 3"),
        (36000, 0, "proxy A", "replay: already answered again 3 times"),
        (70000, 0, "proxy A", "replay after the frame is forgotten"),
    ]
    col = UplinkCollector(2)
    seq = [{"arrived_ms": t, "age_ms": age, "via": via, "note": note, **col.receive(frame, t, age)}
           for t, age, via, note in steps]
    return {"merge_window_ms": MERGE_WINDOW_MS, "frame_memory_ms": FRAME_MEMORY_MS,
            "max_answers_again": MAX_ANSWERS_AGAIN, "first_accepted": 2,
            "frame": frame.hex(), "note": "data_confirmed from frame-v1.json (fcnt 3)", "sequence": seq}


PUBLISHER_SK = bytes.fromhex("11" * 32)
OWNER_SK = bytes.fromhex("22" * 32)

# BIP-340 official test vector 0
BIP340_V0 = {"sk": "0000000000000000000000000000000000000000000000000000000000000003",
             "pub": "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
             "aux": "0" * 64, "msg": "0" * 64,
             "sig": "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
                    "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"}


def federation_vectors() -> dict:
    fv = frame_vectors()
    frames = {f["name"]: bytes.fromhex(f["frame"]) for f in fv["frames"]}
    up = frames["data_confirmed"]
    rx_ref = bytes.fromhex("0102030405060708")
    t = T0 + 60
    bucket = up[2:3].hex()
    ev_up = nostr_event(PUBLISHER_SK, t, KIND_UPLINK, [["h", bucket], ["r", "US915"], ["dl", "1"]],
                        fed_uplink_content(up, 180, [(rx_ref, -112.5, -4.0, 0)]))
    pub_hex = schnorr_pub(PUBLISHER_SK).hex()
    ev_dl = nostr_event(OWNER_SK, t, KIND_DOWNLINK_REQUEST, [["p", pub_hex]],
                        fed_downlink_content(rx_ref, frames["downlink_ack"]))
    ev_res = nostr_event(PUBLISHER_SK, t + 3, KIND_DOWNLINK_RESULT, [["p", schnorr_pub(OWNER_SK).hex()]],
                         fed_result_content(rx_ref, 0, 2100))
    multi_rx = [(bytes.fromhex("1112131415161718"), -88.0, 9.5, 0),
                (bytes.fromhex("2122232425262728"), -101.3, 2.0, 0),
                (bytes.fromhex("3132333435363738"), -117.9, -9.8, UPF_TS_UNCERTAIN)]
    hb = frames["heartbeat"]
    ev_multi = nostr_event(PUBLISHER_SK, t + 30, KIND_UPLINK, [["h", hb[2:3].hex()], ["r", "US915"]],
                           fed_uplink_content(hb, 410, multi_rx))
    bad_sig = dict(ev_up, sig=ev_up["sig"][:-2] + f"{int(ev_up['sig'][-2:], 16) ^ 1:02x}")
    edited = dict(ev_up, content=fed_uplink_content(up, 181, [(rx_ref, -112.5, -4.0, 0)]))
    no_rx = nostr_event(PUBLISHER_SK, t, KIND_UPLINK, [["h", bucket], ["r", "US915"]], fed_uplink_content(up, 180, []))
    return {"spec": "ConnectSensors federation events (09)",
            "bip340_check": BIP340_V0,
            "inputs": {"publisher_sk": PUBLISHER_SK.hex(), "owner_sk": OWNER_SK.hex(),
                       "aux_rand": "00" * 32, "note": "frames from frame-v1.json"},
            "events": [{"name": "uplink", "event": ev_up}, {"name": "downlink_request", "event": ev_dl},
                       {"name": "downlink_result", "event": ev_res},
                       {"name": "uplink_multi_reception", "event": ev_multi,
                        "note": "HEARTBEAT heard by three of the publisher's proxies, one TS_UNCERTAIN"}],
            "invalid": [
                {"name": "bad_signature", "event": bad_sig, "reason": "bad signature", "rule": "09 section 6.1",
                 "note": "the uplink event with one bit of sig changed"},
                {"name": "edited_content", "event": edited, "reason": "id mismatch", "rule": "09 section 6.1",
                 "note": "the uplink event with age_ms changed after signing"},
                {"name": "no_receptions", "event": no_rx, "reason": "bad n_rx", "rule": "09 section 4.1",
                 "note": "validly signed, but n_rx is 0"},
            ]}


def write_vectors(d: str) -> None:
    for fname, data in (("server-v1.json", server_vectors()), ("federation-v1.json", federation_vectors()), ("frame-v1.json", frame_vectors()), ("payload-v1.json", payload_vectors()),
                        ("pairing-v1.json", pairing_vectors()), ("proxy-envelope-v1.json", envelope_vectors())):
        with open(os.path.join(d, fname), "w") as f:
            json.dump(data, f, indent=2)
            f.write("\n")


def rejects(reason: str, fn: Callable[..., Any], *args: Any) -> bool:
    """fn(*args) raises ValueError with exactly reason."""
    try:
        fn(*args)
    except ValueError as ex:
        return str(ex) == reason
    return False


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
    for c in v["tags"]["normal"] + v["tags"]["bootstrap"]:
        index = epoch_index(c["epoch"]) if "epoch" in c else block_index(c["fcnt"])
        seed = tag_seed(sets[c["keys"]].k_dev_tag, index)
        pub = ed25519_pub(seed)
        ok = (index.hex(), seed.hex(), pub.hex(), tag_of_pub(pub).hex()) == (c["index"], c["seed"], c["pub"], c["tag"])
        label = f"epoch {c['epoch']}" if "epoch" in c else f"fcnt {c['fcnt']}"
        print(f"{'ok  ' if ok else 'FAIL'} tag     {c['keys']} {label}")
        bad += not ok
    answered: dict[int, bytes] = {}  # uplink fcnt -> its tag, for the downlinks answering it
    for c in v["frames"]:
        keys = sets[c["keys"]]
        h, pt = open_frame(keys, bytes.fromhex(c["frame"]))
        if is_downlink(h.ftype):
            want_tag = answered.get(struct.unpack(">I", pt[:4])[0])
        else:
            want_tag = uplink_tag(keys, h.ftype, h.fcnt, i["time"])
            answered[h.fcnt] = h.tag
        ok = (pt.hex() == c["plaintext"] and h.ftype == c["type"] and h.fcnt == c["fcnt"]
              and h.tag.hex() == c["tag"] and h.tag == want_tag)
        print(f"{'ok  ' if ok else 'FAIL'} frame   {c['name']}")
        bad += not ok
    for c in v["invalid"]:
        frame = bytes.fromhex(c["frame"])
        ok = rejects(c["reason"], open_frame, sets[c["keys"]], frame)
        ok = ok and (parse_header(frame) is None) == c["proxy_discards"]
        print(f"{'ok  ' if ok else 'FAIL'} frame   invalid {c['name']} ({c['reason']}, {c['rule']})")
        bad += not ok
    with open(os.path.join(d, "payload-v1.json")) as f:
        pv = json.load(f)
    for c in pv["readings"]:
        ok = decode_readings(bytes.fromhex(c["encoded"])) == c["decoded"]
        print(f"{'ok  ' if ok else 'FAIL'} payload {c['name']}")
        bad += not ok
    for c in pv["invalid"]:
        ok = rejects(c["reason"], decode_readings, bytes.fromhex(c["encoded"]))
        print(f"{'ok  ' if ok else 'FAIL'} payload invalid {c['name']} ({c['reason']}, {c['rule']})")
        bad += not ok
    with open(os.path.join(d, "pairing-v1.json")) as f:
        p = json.load(f)
    for c in p["valid"]:
        ok = qr_parse(c["code"]) == c["parsed"]
        print(f"{'ok  ' if ok else 'FAIL'} pairing valid {c['code']}")
        bad += not ok
    for c in p["invalid"]:
        ok = rejects(c["reason"], qr_parse, c["code"])
        print(f"{'ok  ' if ok else 'FAIL'} pairing invalid {c['note']} ({c['reason']}, {c['rule']})")
        bad += not ok
    rc = p["region_check"]
    for c in rc["cases"]:
        ok = (qr_parse(rc["code"])["region"] != c["network_region"]) == c["warn"]
        print(f"{'ok  ' if ok else 'FAIL'} pairing region on a {c['network_region']} network -> warn {c['warn']}")
        bad += not ok
    vframes = {c["name"]: c["frame"] for c in v["frames"]}
    sensor = SensorPairing(k_root, eui)
    for c in p["root_floor"]["sequence"]:
        if c["event"] == "join":
            ok = sensor.join(c["fcnt"], bytes.fromhex(c["sensor_ephemeral_private"])).hex() == c["frame"]
            label = f"JOIN fcnt {c['fcnt']}"
        elif c["event"] == "downlink":
            got = sensor.downlink(bytes.fromhex(c["frame"]))
            k = sensor.k_session.hex() if got == "accept" else None
            ok = (got, sensor.root_floor, k) == (c["result"], c["root_floor"], c["k_session"])
            label = f"downlink -> {c['result']}, floor {c['root_floor']}"
        else:
            getattr(sensor, c["event"])()
            ok = sensor.root_floor == c["root_floor"]
            label = f"{c['event']}, floor {c['root_floor']}"
        print(f"{'ok  ' if ok else 'FAIL'} root floor {label}")
        bad += not ok
    sensor = SensorPairing(k_root, eui)
    for c in p["provisional"]["sequence"]:
        ev = c["event"]
        if ev == "join":
            ok = sensor.join(c["fcnt"], bytes.fromhex(c["sensor_ephemeral_private"])).hex() == c["frame"]
        elif ev == "downlink":
            ok = sensor.downlink(bytes.fromhex(c["frame"])) == c["result"]
        elif ev == "uplink":
            frame = bytes.fromhex(c["frame"])
            h, pt = open_frame(keys_from(sensor.k_session, eui), frame)
            ok = sensor.uplink(h.ftype, h.fcnt, c["unix_time"], pt) == frame
        else:
            getattr(sensor, ev)()
            ok = True
        ok = ok and (sensor.state, sensor.root_floor, sensor.k_session is not None) == (
            c["state"], c["root_floor"], c["has_session"])
        print(f"{'ok  ' if ok else 'FAIL'} provisional {ev} -> {c['state']}")
        bad += not ok
    rf = p["root_floor"]["sequence"]
    ok = rf[0]["frame"] == vframes["join"] and rf[1]["frame"] == vframes["downlink_key_exchange"]
    print(f"{'ok  ' if ok else 'FAIL'} root floor starts from the frame-v1 exchange")
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
        body = bytes.fromhex(c["body"])
        if c["type"] == M_UPLINK:
            u = parse_uplink(body)
            ok = ok and uplink_body(u["rx_time_us"], u["rssi"], u["snr"], u["flags"], u["frame"]) == body
        elif c["type"] == M_TX_RESULT:
            t = parse_tx_result(body)
            ok = ok and tx_result_body(t["downlink_seq"], t["result"], t["offset_us"]) == body
            ok = ok and t["result"] < len(TX_RESULTS) and (t["result"] == 0 or t["offset_us"] == 0)
        print(f"{'ok  ' if ok else 'FAIL'} envelope {c['name']}")
        bad += not ok
    for c in ev["invalid"]:
        ok = envelope_error(key, bytes.fromhex(c["message"])) == c["reason"]
        print(f"{'ok  ' if ok else 'FAIL'} envelope invalid {c['name']} ({c['reason']}, {c['rule']})")
        bad += not ok
    bad += verify_session(ev["session"])
    with open(os.path.join(d, "server-v1.json")) as f:
        sv = json.load(f)
    ctr = UplinkCounter(sv["uplink_counter"]["first_accepted"])
    for c in sv["uplink_counter"]["sequence"]:
        got = ctr.offer(c["fcnt"])
        print(f"{'ok  ' if got == c['result'] else 'FAIL'} counter fcnt {c['fcnt']} -> {c['result']}")
        bad += got != c["result"]
    u = sv["counter16_unwrap"]
    prev, total = u["sequence"][0]["raw"], u["sequence"][0]["total"]
    for c in u["sequence"][1:]:
        total, how = unwrap(prev, total, c["raw"], u["modulus"])
        prev = c["raw"]
        ok = total == c["total"] and how == c["how"]
        print(f"{'ok  ' if ok else 'FAIL'} unwrap {c['raw']} -> {c['total']} ({c['how']})")
        bad += not ok
    r = sv["retransmission"]
    col = UplinkCollector(r["first_accepted"])
    frame = bytes.fromhex(r["frame"])
    for c in r["sequence"]:
        got = col.receive(frame, c["arrived_ms"], c["age_ms"])
        want = {k: c[k] for k in ("result", "counter", "answer") if k in c}
        print(f"{'ok  ' if got == want else 'FAIL'} retransmission at {c['arrived_ms']} ms -> {want}")
        bad += got != want
    da = sv["dl_ack"]
    ctr, acks = UplinkCounter(da["first_accepted"]), CommandAcks[str]()
    for c in da["sequence"]:
        if c["event"] == "downlink":
            try:
                got, refused = acks.downlink(c["reply_to"], c["commands"]), False
            except ValueError:
                got, refused = acks.awaiting, True
            ok = got == c["awaiting"] and refused == c.get("refused", False)
            print(f"{'ok  ' if ok else 'FAIL'} dl_ack downlink reply_to {c['reply_to']} -> "
                  f"{'refused' if refused else 'awaiting ' + str(c['awaiting'])}")
        else:
            counter = ctr.offer(c["fcnt"])
            got = acks.uplink(c["fcnt"], counter, c["dl_ack"])
            ok = counter == c["counter"] and got == c["delivered"]
            print(f"{'ok  ' if ok else 'FAIL'} dl_ack uplink fcnt {c['fcnt']} -> delivered {c['delivered']}")
        bad += not ok
    jv = sv["join"]
    srv = JoinResponder(k_root, eui, jv["root_fcnt_down_before"])
    sent = {}  # root fcnt_down -> plaintext: no two plaintexts may share a root nonce
    for c in jv["sequence"]:
        if c["event"] == "paired":
            srv.paired()
            continue
        priv = c["server_ephemeral_private"]
        r = srv.join(bytes.fromhex(c["join"]), bytes.fromhex(priv) if priv else None, c["server_time"])
        got = (r["action"], parse_header(r["frame"]).fcnt, r["frame"].hex(), r["k_session"].hex(), r["stalled"])
        ok = got == (c["action"], c["root_fcnt_down"], c["frame"], c["k_session"], c["stalled"])
        _, pt = open_frame(sets["root"], r["frame"])
        ok = ok and sent.setdefault(c["root_fcnt_down"], pt) == pt
        print(f"{'ok  ' if ok else 'FAIL'} join -> {c['action']}, root fcnt_down {c['root_fcnt_down']}"
              f"{', stalled' if c['stalled'] else ''}")
        bad += not ok
    ok = jv["sequence"][0]["frame"] == vframes["downlink_key_exchange"]
    print(f"{'ok  ' if ok else 'FAIL'} join starts from the frame-v1 exchange")
    bad += not ok
    tt = sv["tag_table"]
    table = TagTable()
    table.update("device", sets["session"].k_dev_tag, tt["epoch"], tt["last_fcnt"])
    ok = [{"kind": k, "index": x.hex(), "tag": t.hex()} for k, x, t in table.by_device["device"]] == tt["entries"]
    print(f"{'ok  ' if ok else 'FAIL'} tag table entries")
    bad += not ok
    for c in tt["lookups"]:
        route, devices = identify_route(table, bytes.fromhex(c["frame"]), c["local"])
        ok = (route, devices) == (c["route"], c["devices"])
        print(f"{'ok  ' if ok else 'FAIL'} tag table {c['name']} -> {c['route']}")
        bad += not ok
    with open(os.path.join(d, "federation-v1.json")) as f:
        fd = json.load(f)
    b = fd["bip340_check"]
    ok = (schnorr_pub(bytes.fromhex(b["sk"])).hex().upper() == b["pub"]
          and schnorr_sign(bytes.fromhex(b["msg"]), bytes.fromhex(b["sk"]), bytes.fromhex(b["aux"])).hex().upper() == b["sig"]
          and schnorr_verify(bytes.fromhex(b["msg"]), bytes.fromhex(b["pub"]), bytes.fromhex(b["sig"])))
    print(f"{'ok  ' if ok else 'FAIL'} BIP-340 official vector 0")
    bad += not ok
    sks = {schnorr_pub(bytes.fromhex(k)).hex(): bytes.fromhex(k)
           for k in (fd["inputs"]["publisher_sk"], fd["inputs"]["owner_sk"])}
    for c in fd["events"]:
        ev = c["event"]
        rebuilt = nostr_event(sks[ev["pubkey"]], ev["created_at"], ev["kind"], ev["tags"], ev["content"])
        ok = nostr_verify(ev) and rebuilt == ev
        if ev["kind"] == KIND_UPLINK:
            u = parse_fed_uplink(ev["content"])
            ok = ok and fed_uplink_content(u["frame"], u["age_ms"], u["receptions"]) == ev["content"]
            ok = ok and parse_header(u["frame"]) is not None
        print(f"{'ok  ' if ok else 'FAIL'} federation {c['name']}")
        bad += not ok
    for c in fd["invalid"]:
        ev = c["event"]
        ok = nostr_error(ev) == c["reason"] or (nostr_verify(ev) and rejects(
            c["reason"], parse_fed_uplink, ev["content"]))
        print(f"{'ok  ' if ok else 'FAIL'} federation invalid {c['name']} ({c['reason']}, {c['rule']})")
        bad += not ok
    print("all vectors pass" if bad == 0 else f"{bad} failures")
    return 1 if bad else 0


def airtime_table() -> None:
    print("frame_bytes  region  SF  BW_kHz  airtime_ms")
    for n in (23, 31, 55, 65, 86):
        for region, (sf, bw) in REGIONS.items():
            print(f"{n:11d}  {region:6s}  {sf:2d}  {bw // 1000:6d}  {region_airtime_ms(region, n):10.1f}")


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
