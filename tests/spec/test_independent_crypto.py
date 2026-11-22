#!/usr/bin/env python3
"""Check the frame vectors against cryptography's AES-CCM, HKDF and X25519, used directly.

csframe.py generates and verifies the vectors, so a bug in its helpers would be
written into the vectors and then confirmed by them. This test never imports
csframe: it rebuilds the key schedule (02 section 5) and the nonce (02 section 7)
from the spec's prose and checks the result against the vectors and against the
values printed in 02 section 14.

Run from anywhere:  python3 -I tests/spec/test_independent_crypto.py
"""

import json
import os
import struct
import sys

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

failures = 0


def check(ok: bool, what: str) -> None:
    global failures
    print(f"{'ok  ' if ok else 'FAIL'} {what}")
    failures += not ok


def hkdf(ikm: bytes, salt: bytes | None, info: bytes, length: int = 16) -> bytes:
    return HKDF(algorithm=SHA256(), length=length, salt=salt, info=info).derive(ikm)


def public(priv: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(priv).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def frame_nonce(dev_eui: bytes, frame: bytes) -> bytes:
    direction = 0x01 if frame[1] & 0x0F >= 0x8 else 0x00
    return dev_eui + frame[10:14] + bytes([direction])


def main() -> int:
    # RFC 5869 test case 1: the HKDF used below is plain HKDF-SHA256.
    okm = hkdf(bytes([0x0B] * 22), bytes(range(13)), bytes(range(0xF0, 0xFA)), 42)
    check(okm.hex() == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
          "HKDF-SHA256 RFC 5869 test case 1")

    with open(os.path.join(ROOT, "spec", "vectors", "frame-v1.json")) as f:
        v = json.load(f)
    i, d = v["inputs"], v["derived"]
    k_root, eui = bytes.fromhex(i["k_root"]), bytes.fromhex(i["dev_eui"])

    root_enc = hkdf(k_root, eui, b"cs1 enc")
    check(root_enc.hex() == d["root"]["k_enc"] == "ae0dafd25a2e89208090739d6df12e82", "root k_enc (02 section 5.1)")
    check(hkdf(k_root, eui, b"cs1 tag").hex() == d["root"]["k_dev_tag"], "root k_dev_tag")

    s_priv, v_priv = bytes.fromhex(i["sensor_ephemeral_private"]), bytes.fromhex(i["server_ephemeral_private"])
    s_pub, v_pub = public(s_priv), public(v_priv)
    shared = X25519PrivateKey.from_private_bytes(s_priv).exchange(X25519PublicKey.from_public_bytes(v_pub))
    k_session = hkdf(shared, k_root, b"cs1 session" + eui + s_pub + v_pub)
    check(k_session.hex() == d["k_session"] == "151466fb0522fa821caffdada6ce9d6c", "k_session (02 section 5.3)")
    sess_enc = hkdf(k_session, eui, b"cs1 enc")
    check(sess_enc.hex() == d["session"]["k_enc"] == "77a25f6ba7d210973e1a19ed70b85177", "session k_enc")
    route = hkdf(bytes.fromhex(i["k_net"]), None, b"cs1 route")
    check(route.hex() == d["k_net_route"] == "53e27722471cdf29ebcb23aabc120cfe", "k_net_route (02 section 5.2)")

    keys = {"root": root_enc, "session": sess_enc}
    for c in v["frames"]:
        frame = bytes.fromhex(c["frame"])
        ccm = AESCCM(keys[c["keys"]], tag_length=8)
        n, hdr = frame_nonce(eui, frame), frame[:14]
        try:
            pt = ccm.decrypt(n, frame[14:], hdr)
        except InvalidTag:
            pt = None
        ok = pt is not None and pt.hex() == c["plaintext"] and hdr + ccm.encrypt(n, pt, hdr) == frame
        ok = ok and struct.unpack(">I", frame[10:14])[0] == c["fcnt"] and frame[1] == 0x10 | c["type"]
        check(ok, f"AES-CCM frame {c['name']}")

    # The wrong-direction vector opens only with the other direction byte.
    wd = next(bytes.fromhex(c["frame"]) for c in v["invalid"] if c["name"] == "wrong_direction")
    ccm = AESCCM(sess_enc, tag_length=8)
    try:
        ccm.decrypt(frame_nonce(eui, wd), wd[14:], wd[:14])
        ok = False
    except InvalidTag:
        ok = True
    try:
        ccm.decrypt(eui + wd[10:14] + b"\x01", wd[14:], wd[:14])
    except InvalidTag:
        ok = False
    check(ok, "AES-CCM wrong_direction fails under its own type's direction")

    print("independent crypto check passes" if failures == 0 else f"{failures} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
