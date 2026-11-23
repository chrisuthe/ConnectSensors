#!/usr/bin/env python3
"""cs-mailbox against spec 09: every error code, every limit, the close codes, the
handshake's host binding, TLS, admission, expiry and the forward timeout.

    python3 tests/federation/test_mailbox.py

Requires: cryptography, websockets.
"""

from __future__ import annotations

import asyncio
import datetime
import os
import secrets
import sys
import tempfile
import time

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "spec", "tools"))
sys.path.insert(0, os.path.join(ROOT, "tests", "devtools"))
sys.path.insert(0, os.path.join(ROOT, "devtools"))
import csframe as cs  # noqa: E402
import cs_testserver as ts  # noqa: E402
from procwatch import Watched  # noqa: E402
from websockets.asyncio.client import connect  # noqa: E402
from websockets.exceptions import ConnectionClosed, InvalidStatus  # noqa: E402

MAILBOX = os.path.join(ROOT, "mailbox", "cs_mailbox.py")
E = {name: i for i, name in enumerate(cs.MB_ERRORS)}
K_DEV = cs.keys_from(bytes(range(16)), bytes.fromhex("c5c50000000000b1"))
failures = 0


def check(cond: bool, what: str) -> bool:
    global failures
    print(("ok   " if cond else "FAIL ") + what, flush=True)
    failures += not cond
    return cond


def start(*args: str) -> tuple[Watched, int]:
    p = Watched([sys.executable, "-I", MAILBOX, "--listen", "127.0.0.1", "--port", "0", *args])
    m = p.wait_for(r"Listening on wss?://127\.0\.0\.1:(\d+)")
    if m is None:
        raise RuntimeError("cs-mailbox did not start:\n" + p.stop())
    return p, int(m.group(1))


async def link(url: str, seed: bytes | None = None, cafile: str | None = None) -> ts.MailboxLink:
    lk = ts.MailboxLink(url, seed or secrets.token_bytes(32), cafile=cafile, insecure=url.startswith("ws:"))
    await lk.connect()
    return lk


async def expect(lk: ts.MailboxLink, mtype: int, timeout: float = 2.0) -> list | None:
    try:
        async with asyncio.timeout(timeout):
            while True:
                m = await lk.recv()
                if m[0] == mtype:
                    return m
    except (TimeoutError, ConnectionClosed):
        return None


async def raw_fatal(lk: ts.MailboxLink, data: bytes | str) -> tuple[list | None, int | None]:
    """Send raw data on an authenticated link; the error it draws and the close code."""
    await lk.ws.send(data)
    return await closing(lk.ws)


async def closing(ws) -> tuple[list | None, int | None]:
    err = None
    try:
        async with asyncio.timeout(2):
            async for msg in ws:
                m = cs.mb_decode(msg)
                if m[0] == cs.MB_ERROR:
                    err = m
    except (TimeoutError, ConnectionClosed):
        pass
    await ws.wait_closed()
    return err, ws.close_code


def frame(fcnt: int, ftype: int = cs.T_DATA_CONFIRMED, epoch: int | None = None) -> bytes:
    e = cs.epoch_of(int(time.time())) if epoch is None else epoch
    return cs.seal(K_DEV, ftype, cs.normal_tag(K_DEV.k_dev_tag, e), fcnt, b"\x00")


def entry(lk: ts.MailboxLink, expires: int | None = None, epoch: int | None = None) -> list:
    e = cs.epoch_of(int(time.time())) if epoch is None else epoch
    seed = cs.tag_seed(K_DEV.k_dev_tag, cs.epoch_index(e))
    return cs.reg_entry(seed, lk.server_id, lk.pub, expires or cs.EPOCH_SECONDS * (e + 2))


def rx(ref: bytes | None = None, age: int = 100) -> list:
    return [ref or secrets.token_bytes(8), -900, 50, age, cs.RXF_DOWNLINK]


async def handshake_errors(url: str) -> None:
    async def raw(first: bytes | str):
        ws = await connect(url, subprotocols=[ts.MB_SUBPROTOCOL])
        await ws.send(first)
        return await closing(ws)

    err, code = await raw(cs.cbor([cs.MB_HELLO, 2, secrets.token_bytes(16)]))
    check(err == [cs.MB_ERROR, 0, E["UNSUPPORTED_VERSION"]] and code == 4006,
          "hello version 2: UNSUPPORTED_VERSION, 4006")
    lk = ts.MailboxLink(url, secrets.token_bytes(32), insecure=True)
    lk.server_id, lk.nonce_s = bytes(32), bytes(16)
    err, code = await raw(cs.signed(lk.seed, bytes(32), bytes(16), [cs.MB_PING, 1]))
    check(err == [cs.MB_ERROR, 1, E["NOT_AUTHENTICATED"]] and code == 4004,
          "ping before hello: NOT_AUTHENTICATED, 4004")
    err, code = await raw(bytes([0x82, 0x18, 0x01, 0x02]))
    check(err is not None and err[2] == E["MALFORMED"] and code == 4001, "non-deterministic CBOR: MALFORMED, 4001")
    err, code = await raw("hello")
    check(err is not None and err[2] == E["MALFORMED"] and code == 4001, "a text message: MALFORMED, 4001")

    ws = await connect(url, subprotocols=[ts.MB_SUBPROTOCOL])
    nonce_c = secrets.token_bytes(16)
    await ws.send(cs.cbor([cs.MB_HELLO, 1, nonce_c]))
    g = cs.mb_decode(await ws.recv())
    seed = secrets.token_bytes(32)
    bad = cs.ed_sign(seed, cs.auth_msg(g[3], nonce_c, bytes(16), cs.ed25519_pub(seed)))  # wrong nonce_s
    await ws.send(cs.cbor([cs.MB_AUTH, cs.ed25519_pub(seed), bad]))
    err, code = await closing(ws)
    check(err == [cs.MB_ERROR, 0, E["BAD_SIGNATURE"]] and code == 4002, "auth signed over the wrong nonce_s: "
          "BAD_SIGNATURE, 4002")
    try:
        ws = await connect(url)
        await ws.close()
        check(False, "a client without the cs-mailbox.1 subprotocol is refused")
    except InvalidStatus as ex:
        check(ex.response.status_code == 400, "a client without the cs-mailbox.1 subprotocol is refused (HTTP 400)")


async def message_errors(url: str) -> None:
    lk = await link(url)
    err, code = await raw_fatal(lk, cs.signed(lk.seed, lk.server_id, lk.nonce_s, [cs.MB_PING, 2]))
    check(err == [cs.MB_ERROR, 2, E["BAD_SEQUENCE"]] and code == 4003, "seq 2 first: BAD_SEQUENCE, 4003")
    lk = await link(url)
    data = bytearray(cs.signed(lk.seed, lk.server_id, lk.nonce_s, [cs.MB_PING, 1]))
    data[-1] ^= 1
    err, code = await raw_fatal(lk, bytes(data))
    check(err == [cs.MB_ERROR, 1, E["BAD_SIGNATURE"]] and code == 4002, "a bad outer signature: BAD_SIGNATURE, 4002")
    lk = await link(url)
    err, code = await raw_fatal(lk, cs.signed(lk.seed, lk.server_id, lk.nonce_s, [cs.MB_PING, 1, 0]))
    check(err is not None and err[2] == E["MALFORMED"] and code == 4001, "an extra element: MALFORMED, 4001")
    lk = await link(url)
    err, code = await raw_fatal(lk, cs.cbor([99, 1, bytes(64)]))
    check(err is not None and err[2] == E["MALFORMED"] and code == 4001, "an unknown message type: MALFORMED, 4001")
    lk = await link(url)
    err, code = await raw_fatal(lk, cs.cbor([cs.MB_HELLO, 1, bytes(16)]))
    check(err is not None and err[2] == E["MALFORMED"] and code == 4001, "hello after welcome: MALFORMED, 4001")
    lk = await link(url)
    await lk.ws.send(cs.signed(lk.seed, lk.server_id, lk.nonce_s, [cs.MB_PING, 1]))
    pong = None
    async with asyncio.timeout(2):
        while pong is None or pong[0] != cs.MB_PONG_S:
            pong = cs.mb_decode(await lk.ws.recv())  # raw: MailboxLink.recv() consumes pong_s
    check(pong == [cs.MB_PONG_S, 1], "ping is answered by pong_s with its seq")

    limits = [
        ("33 entries in a register", [cs.MB_REGISTER, 2, [entry(lk)] * 33]),
        ("257 tags in a withdraw", [cs.MB_WITHDRAW, 2, [bytes(8)] * 257]),
        ("9 receptions in a publish", [cs.MB_PUBLISH, 2, frame(5), [rx() for _ in range(9)]]),
        ("0 receptions in a publish", [cs.MB_PUBLISH, 2, frame(5), []]),
        ("an 87-byte frame", [cs.MB_PUBLISH, 2, frame(5) + bytes(64), [rx()]]),
        ("a 22-byte frame", [cs.MB_PUBLISH, 2, frame(5)[:22], [rx()]]),
        ("a reception flag 0x04", [cs.MB_PUBLISH, 2, frame(5), [[bytes(8), 0, 0, 0, 4]]]),
        ("an age_ms above 65 535", [cs.MB_PUBLISH, 2, frame(5), [[bytes(8), 0, 0, 65536, 0]]]),
        ("seq 0", [cs.MB_PING, 0]),
    ]
    for what, m in limits:
        lk = await link(url)
        err, code = await raw_fatal(lk, cs.signed(lk.seed, lk.server_id, lk.nonce_s, m))
        check(err is not None and err[2] == E["MALFORMED"] and code == 4001, f"{what}: MALFORMED, 4001")
    lk = await link(url)
    await lk.ws.send(bytes(cs.MB_MAX_MESSAGE + 1))
    _, code = await closing(lk.ws)
    check(code == 1009, f"a message over 4 096 bytes closes the connection with 1009 ({code})")


async def routing(url: str) -> None:
    owner, other, pub = await link(url), await link(url), await link(url)
    now = int(time.time())
    e = cs.epoch_of(now)
    good = entry(owner)
    s_plus_l = (int.from_bytes(good[1][32:], "little") + cs._EL).to_bytes(32, "little")
    # pub the neutral element, R = B and S = 1: a cofactorless lax verifier accepts it for any message
    small = [(1).to_bytes(32, "little"), cs.ed_pub_point_b() + (1).to_bytes(32, "little"), now + 60]
    await owner.send([cs.MB_REGISTER, [good, entry(owner, now + cs.REG_MAX_AHEAD + 5), entry(owner, now - 1),
                                       [good[0], good[1][:32] + s_plus_l, good[2]],
                                       cs.reg_entry(secrets.token_bytes(32), owner.server_id, other.pub, now + 60),
                                       small]])
    reg = await expect(owner, cs.MB_REGISTERED)
    check(reg is not None and reg[2] == [0, E["BAD_EXPIRES"], E["BAD_EXPIRES"], E["BAD_PROOF"], E["BAD_PROOF"],
                                         E["BAD_PROOF"]],
          "register statuses: OK, BAD_EXPIRES x2, BAD_PROOF x3 (S + L, other owner, small-order pub)"
          + (f" {reg[2]}" if reg else ""))
    await expect(pub, cs.MB_PING_S, 0.5)  # answers it inside recv

    f1, r1, r2 = frame(10), secrets.token_bytes(8), secrets.token_bytes(8)
    seq = await pub.send([cs.MB_PUBLISH, frame(10, cs.T_DOWNLINK), [rx()]])
    err = await expect(pub, cs.MB_ERROR)
    check(err == [cs.MB_ERROR, seq, E["BAD_FRAME"]], "publishing a downlink: BAD_FRAME, not fatal")
    seq = await pub.send([cs.MB_PUBLISH, f1, [rx(r1), rx(r1)]])
    err = await expect(pub, cs.MB_ERROR)
    check(err == [cs.MB_ERROR, seq, E["BAD_FRAME"]], "an rx_ref twice in one publish: BAD_FRAME")
    await pub.send([cs.MB_PUBLISH, f1, [rx(r1), rx(r2)]])
    d = await expect(owner, cs.MB_DELIVER)
    check(d is not None and d[1] == f1, "a frame under a registered tag is delivered")
    check(await expect(other, cs.MB_DELIVER, 0.3) is None, "... to its registrant only")
    seq = await pub.send([cs.MB_PUBLISH, frame(11), [rx(r1)]])
    err = await expect(pub, cs.MB_ERROR)
    check(err == [cs.MB_ERROR, seq, E["BAD_FRAME"]], "a remembered rx_ref reused: BAD_FRAME")
    await pub.send([cs.MB_PUBLISH, f1, [rx()]])
    check(await expect(owner, cs.MB_DELIVER, 0.3) is None,
          "the publisher's second publish of a transmission is dropped")

    dl = cs.seal(K_DEV, cs.T_DOWNLINK, f1[2:10], 1, cs.downlink_payload(10, now, 0))
    for what, ref, down, lk, code in [
        ("an rx_ref never issued", secrets.token_bytes(8), dl, owner, "UNKNOWN_RX_REF"),
        ("an rx_ref delivered to another owner", r1, dl, other, "UNKNOWN_RX_REF"),
        ("an uplink type as the downlink", r1, frame(12), owner, "BAD_FRAME"),
        ("a downlink under another tag", r1, cs.seal(K_DEV, cs.T_DOWNLINK, bytes(8), 1, b"\x00" * 9), owner,
         "BAD_FRAME"),
    ]:
        seq = await lk.send([cs.MB_REQUEST, ref, down])
        err = await expect(lk, cs.MB_ERROR)
        check(err == [cs.MB_ERROR, seq, E[code]], f"request with {what}: {code}")

    # The forward timeout: a publisher that never answers stops blocking after 3 s.
    # A fresh transmission, so its rx_refs are well inside their 5 s at the end.
    r1, r2 = secrets.token_bytes(8), secrets.token_bytes(8)
    await pub.send([cs.MB_PUBLISH, frame(15), [rx(r1), rx(r2)]])
    await expect(owner, cs.MB_DELIVER)
    await owner.send([cs.MB_REQUEST, r1, dl])
    check((await expect(pub, cs.MB_FORWARD) or [0, b""])[1] == r1, "the request is forwarded")
    seq = await owner.send([cs.MB_REQUEST, r2, dl])
    check(await expect(owner, cs.MB_ERROR) == [cs.MB_ERROR, seq, E["ALREADY_ANSWERED"]],
          "a second request: ALREADY_ANSWERED")
    await asyncio.sleep(cs.FORWARD_TIMEOUT_MS / 1000 + 0.1)
    await pub.send([cs.MB_RESULT, r1, 2, 0])
    check(await expect(owner, cs.MB_RESULT_S, 0.2) is None, "a result after the forward timed out is ignored")
    await owner.send([cs.MB_REQUEST, r2, dl])
    check((await expect(pub, cs.MB_FORWARD) or [0, b""])[1] == r2, "after 3 s the transmission is no longer blocked")

    # NOT_REGISTRANT: delivered while registered, then withdrawn.
    r3 = secrets.token_bytes(8)
    await pub.send([cs.MB_PUBLISH, frame(13), [rx(r3)]])
    await expect(owner, cs.MB_DELIVER)
    await owner.send([cs.MB_WITHDRAW, [f1[2:10]]])
    seq = await owner.send([cs.MB_REQUEST, r3, dl])
    check(await expect(owner, cs.MB_ERROR) == [cs.MB_ERROR, seq, E["NOT_REGISTRANT"]],
          "request after withdrawing the tag: NOT_REGISTRANT")
    await pub.send([cs.MB_PUBLISH, frame(14), [rx()]])
    check(await expect(owner, cs.MB_DELIVER, 0.3) is None, "a withdrawn tag is no longer routed")

    # Expiry: a registration lasts until its expires.
    short = await link(url)
    exp = int(time.time()) + 2
    await short.send([cs.MB_REGISTER, [entry(short, exp, epoch=e + 5)]])
    await expect(short, cs.MB_REGISTERED)
    await pub.send([cs.MB_PUBLISH, frame(1, epoch=e + 5), [rx()]])
    check(await expect(short, cs.MB_DELIVER, 1) is not None, "a live registration is routed")
    await asyncio.sleep(max(0.0, exp - time.time()) + 0.05)
    await pub.send([cs.MB_PUBLISH, frame(2, epoch=e + 5), [rx()]])
    check(await expect(short, cs.MB_DELIVER, 0.3) is None, "an expired registration is not")

    # Admission (--admit-per-hour 6): four keys so far, from one address.
    refused = []
    for _ in range(3):
        try:
            await (await link(url)).close()
            refused.append(False)
        except ConnectionError as ex:
            refused.append("NOT_PERMITTED" in str(ex))
    check(refused == [False, False, True], f"the 7th new key from one address in an hour: NOT_PERMITTED {refused}")
    await (await link(url, owner.seed)).close()
    check(True, "a key already admitted still connects")


async def rate_limits(url: str) -> None:
    owner, pub = await link(url), await link(url)
    e = cs.epoch_of(int(time.time()))
    await owner.send([cs.MB_REGISTER, [entry(owner, epoch=e + x) for x in range(5)]])
    reg = await expect(owner, cs.MB_REGISTERED)
    check(reg is not None and reg[2] == [0] * 4 + [E["RATE_LIMITED"]], "live registrations over --reg-max-live 4: "
          f"RATE_LIMITED ({reg[2] if reg else None})")
    again = await link(url)
    await again.send([cs.MB_REGISTER, [entry(again)] * 9])
    reg = await expect(again, cs.MB_REGISTERED)
    check(reg is not None and reg[2] == [0] * 8 + [E["RATE_LIMITED"]], "registrations over --reg-burst 8: "
          f"RATE_LIMITED ({reg[2] if reg else None})")

    # Bursts a little past the limits, since the buckets refill while they are sent.
    for n in range(25):
        await pub.send([cs.MB_PUBLISH, frame(100 + n), [rx()]])
    errs = []
    while (m := await expect(pub, cs.MB_ERROR, 0.3)) is not None:
        errs.append(m)
    check(errs and all(m[2] == E["RATE_LIMITED"] for m in errs) and min(m[1] for m in errs) > 20,
          f"publishes past the burst of 20: RATE_LIMITED (seqs {[m[1] for m in errs]})")
    delivered = []
    while (d := await expect(owner, cs.MB_DELIVER, 0.3)) is not None:
        delivered.append(d[2][0][0])
    check(len(delivered) == 25 - len(errs), f"the others are delivered ({len(delivered)})")
    dl = cs.seal(K_DEV, cs.T_DOWNLINK, frame(1)[2:10], 1, b"\x00" * 9)
    sent = delivered[:20]
    for ref in sent:
        await owner.send([cs.MB_REQUEST, ref, dl])
    errs = []
    while (m := await expect(owner, cs.MB_ERROR, 0.3)) is not None:
        errs.append(m)
    forwards = 0
    while await expect(pub, cs.MB_FORWARD, 0.3) is not None:
        forwards += 1
    # The burst is 10; a slow machine refills a few more while the server verifies.
    check(errs and all(m[2] == E["RATE_LIMITED"] for m in errs) and 10 <= forwards < len(sent)
          and forwards + len(errs) == len(sent),
          f"requests past 10 a second: RATE_LIMITED ({forwards} forwarded, {len(errs)} refused)")


async def message_rate(url: str) -> None:
    """Against a server with --message-rate 2 (burst 4), so the bucket's refill while
    the server verifies is small next to the 30 sent, however slow the machine."""
    lk = await link(url)
    for _ in range(30):
        await lk.send([cs.MB_PING])
    refused = []
    while (m := await expect(lk, cs.MB_ERROR, 1)) is not None:
        refused.append(m)
    check(len(refused) >= 20 and all(m[2] == E["RATE_LIMITED"] for m in refused) and min(m[1] for m in refused) > 4,
          f"signed messages past --message-rate, after its burst: RATE_LIMITED ({len(refused)} of 30)")
    await asyncio.sleep(1)  # refill
    seq = await lk.send([cs.MB_PING])
    pong = None
    try:
        async with asyncio.timeout(3):
            while pong != [cs.MB_PONG_S, seq]:
                pong = cs.mb_decode(await lk.ws.recv())  # raw: MailboxLink.recv() consumes pong_s
    except (TimeoutError, ConnectionClosed):
        pass
    check(pong == [cs.MB_PONG_S, seq], "... not fatal: the seq goes on and the next ping is answered")


async def client_skips_unknown() -> None:
    class FakeWS:
        def __init__(self, msgs: list[bytes]):
            self.msgs = msgs

        async def recv(self) -> bytes:
            return self.msgs.pop(0)

    lk = ts.MailboxLink("ws://x/", bytes(32), insecure=True)
    lk.ws = FakeWS([cs.cbor([50, 1, b"future"]), cs.cbor([cs.MB_RESULT_S, bytes(8), 0, 0])])
    check(await lk.recv() == [cs.MB_RESULT_S, bytes(8), 0, 0], "the client skips a server message of unknown type")


async def hosts(port: int, port_one_host: int) -> None:
    for host in ("127.0.0.1", "localhost"):
        lk = await link(f"ws://{host}:{port}/")
        check(lk.pseudonym == cs.pseudonym(lk.server_id, lk.pub), f"greeting signed for configured host {host}")
        await lk.close()
    try:  # this server serves 127.0.0.1 only, so it never signs "localhost"
        await link(f"ws://localhost:{port_one_host}/")
        check(False, "a host the server is not configured for fails the greeting check")
    except ConnectionError as ex:
        check("bad greeting" in str(ex), "a host the server is not configured for fails the greeting check")


async def tls(port: int, cafile: str, member: bytes) -> tuple[bytes, int]:
    url = f"wss://localhost:{port}/"
    lk = await link(url, member, cafile)
    check(lk.pseudonym == cs.pseudonym(lk.server_id, lk.pub), "wss:// with a pinned certificate: welcome for a member")
    sid, gen = lk.server_id, lk.generation
    await lk.close()
    try:
        await link(url, None, cafile)
        check(False, "a key not in --members is refused")
    except ConnectionError as ex:
        check("NOT_PERMITTED" in str(ex), f"a key not in --members is refused: NOT_PERMITTED ({ex})")
    try:
        await link(url, member)
        check(False, "a certificate the client does not trust is refused")
    except Exception as ex:  # noqa: BLE001
        check("CERTIFICATE_VERIFY_FAILED" in str(ex), "a certificate the client does not trust is refused")
    try:
        ts.MailboxLink(f"ws://localhost:{port}/", member)
        check(False, "a ws:// URL without --insecure-dev is refused by the client")
    except ValueError:
        check(True, "a ws:// URL without --insecure-dev is refused by the client")
    return sid, gen


def self_signed(work: str) -> tuple[str, str]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = os.path.join(work, "cert.pem"), os.path.join(work, "key.pem")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    return cert_path, key_path


def main() -> int:
    started = time.monotonic()
    work = tempfile.mkdtemp()
    procs: list[Watched] = []
    try:
        p, port = start("--host", "127.0.0.1", "--host", "localhost", "--insecure-dev", "--reg-burst", "8",
                        "--reg-max-live", "4", "--admit-per-hour", "1000")
        procs.append(p)
        url = f"ws://127.0.0.1:{port}/"
        asyncio.run(handshake_errors(url))
        asyncio.run(message_errors(url))
        p2, port2 = start("--host", "127.0.0.1", "--insecure-dev", "--admit-per-hour", "6")
        procs.append(p2)
        asyncio.run(hosts(port, port2))
        asyncio.run(rate_limits(url))
        asyncio.run(client_skips_unknown())
        asyncio.run(routing(f"ws://127.0.0.1:{port2}/"))

        cert, key = self_signed(work)
        member = secrets.token_bytes(32)
        members = os.path.join(work, "members")
        with open(members, "w") as f:
            f.write(f"# the one member\n{cs.ed25519_pub(member).hex()}\n")
        key_file = os.path.join(work, "server.key")
        tls_args = ("--host", "localhost", "--tls-cert", cert, "--tls-key", key, "--members", members,
                    "--key-file", key_file)
        p3, port3 = start(*tls_args)
        sid, gen = asyncio.run(tls(port3, cert, member))
        p3.stop()
        p4, port4 = start(*tls_args)
        procs.append(p4)

        async def after_restart() -> None:
            lk = await link(f"wss://localhost:{port4}/", member, cert)
            check(lk.server_id == sid and lk.generation != gen,
                  "after a restart with --key-file: the same server_id and a new generation")
            await lk.close()
        asyncio.run(after_restart())
        p5, port5 = start("--host", "127.0.0.1", "--insecure-dev", "--message-rate", "2")
        procs.append(p5)
        asyncio.run(message_rate(f"ws://127.0.0.1:{port5}/"))
        bad = Watched([sys.executable, "-I", MAILBOX, "--host", "127.0.0.1", "--port", "0"])
        check(bad.wait_for(r"TLS is required") is not None, "without TLS or --insecure-dev the server will not start")
        bad.stop()
        check(time.monotonic() - started < 30, f"ran in {time.monotonic() - started:.1f} s")
    finally:
        outs = [p.stop() for p in procs]
    if failures:
        for out in outs:
            print("--- cs-mailbox ---\n" + out.strip())
    print("all checks pass" if failures == 0 else f"{failures} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
