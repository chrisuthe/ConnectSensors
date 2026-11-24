#!/usr/bin/env python3
"""Two homes and a bystander through one cs-mailbox (spec 09), end to end.

    make -C tests/host_proxy host_proxy && python3 tests/federation/test_two_homes.py

- mailbox: mailbox/cs_mailbox.py --insecure-dev
- home A: devtools/cs_testserver.py owning a simulated sensor, paired up front
  through its --state file; no proxy of A hears the sensor
- home B: devtools/cs_testserver.py --publish --federated-downlinks, with
  tests/host_proxy as its proxy, which hears the sensor
- home C: devtools/cs_testserver.py on the mailbox, registering nothing

The mailbox rules that need a misbehaving or scripted party (a second request,
release on non-SENT, a result from the wrong publisher, forged registrations) are
driven by scripted clients built on cs_testserver's MailboxLink.

Requires: cryptography, websockets, and the host_proxy binary.
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import socket
import struct
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

KEY = "5a" * 16
PROXY_ID = "348518fffe000010"  # host_proxy's default
HOST_PROXY = os.path.join(ROOT, "tests", "host_proxy", "host_proxy")
K_ROOT = bytes.fromhex("f00102030405060708090a0b0c0d0e0f")
DEV_EUI = bytes.fromhex("c5c50000000000a1")
K_ROOT_2 = bytes.fromhex("f10102030405060708090a0b0c0d0e0f")
DEV_EUI_2 = bytes.fromhex("c5c50000000000a2")
RESULT = {name: i for i, name in enumerate(cs.TX_RESULTS)}
failures = 0


def check(cond: bool, what: str) -> bool:
    global failures
    print(("ok   " if cond else "FAIL ") + what, flush=True)
    failures += not cond
    return cond


def free_port(kind: int = socket.SOCK_DGRAM) -> int:
    with socket.socket(socket.AF_INET, kind) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def paired_sensor(k_root: bytes, dev_eui: bytes) -> tuple[cs.SensorPairing, dict]:
    """A sensor through JOIN and KEY_EXCHANGE, and the server state that matches."""
    sensor, responder = cs.SensorPairing(k_root, dev_eui), cs.JoinResponder(k_root, dev_eui)
    now = int(time.time())
    r = responder.join(sensor.join(1, secrets.token_bytes(32)), secrets.token_bytes(32), now)
    assert sensor.downlink(r["frame"]) == "accept"
    responder.paired()
    return sensor, {"root_fcnt_down": responder.root_fcnt_down, "state": "PAIRED", "k_session": r["k_session"].hex(),
                    "fcnt_down": 0, "fcnt_up": 1, "last_seen": now}


def reading(contact: int) -> bytes:
    return bytes([0]) + cs.encode_reading(0x00, 0x01, contact)


# ---------------------------------------------------------------- scripted clients

async def client(url: str, seed: bytes | None = None) -> ts.MailboxLink:
    link = ts.MailboxLink(url, seed or secrets.token_bytes(32), insecure=True)
    await link.connect()
    await link.ping()
    return link


async def expect(link: ts.MailboxLink, mtype: int, timeout: float = 2.0) -> list | None:
    """The next message of mtype, skipping others."""
    try:
        async with asyncio.timeout(timeout):
            while True:
                m = await link.recv()
                if m[0] == mtype:
                    return m
    except TimeoutError:
        return None


async def quiet(link: ts.MailboxLink, timeout: float) -> list[list]:
    """Everything that arrives within timeout."""
    got: list[list] = []
    try:
        async with asyncio.timeout(timeout):
            while True:
                got.append(await link.recv())
    except TimeoutError:
        return got


async def scripted(url: str, sensor_a: cs.SensorPairing, fcnt_a: int) -> None:
    """The mailbox's request, result and registration rules (09 sections 5, 7.3, 7.5)."""
    s2, _ = paired_sensor(K_ROOT_2, DEV_EUI_2)
    keys2 = cs.keys_from(s2.k_session, DEV_EUI_2)
    owner, pub_p, pub_q = await client(url), await client(url), await client(url)
    sid = owner.server_id
    now = int(time.time())
    e = cs.epoch_of(now)
    seed2 = cs.tag_seed(keys2.k_dev_tag, cs.epoch_index(e))
    await owner.send([cs.MB_REGISTER, [cs.reg_entry(seed2, sid, owner.pub, cs.EPOCH_SECONDS * (e + 2))]])
    reg = await expect(owner, cs.MB_REGISTERED)
    check(reg is not None and reg[2] == [0], "scripted owner registers a second sensor's tag")

    up = s2.uplink(cs.T_DATA_CONFIRMED, 2, now, reading(1))
    r1, r2 = secrets.token_bytes(8), secrets.token_bytes(8)
    await quiet(pub_p, 0.2)  # answer the mailbox's ping_s, so rtt_pub is known
    await pub_p.send([cs.MB_PUBLISH, up, [[r1, -900, 75, 120, cs.RXF_DOWNLINK], [r2, -1000, 20, 130, cs.RXF_DOWNLINK]]])
    d = await expect(owner, cs.MB_DELIVER)
    check(d is not None and d[1] == up and [r[0] for r in d[2]] == [r1, r2] and d[3] == pub_p.pseudonym
          and d[4] < cs.RTT_UNKNOWN, "deliver carries the publish, the publisher's pseudonym and a known rtt_pub")
    dl = cs.seal(keys2, cs.T_DOWNLINK, up[2:10], 1, cs.downlink_payload(2, now, 0))

    await owner.send([cs.MB_REQUEST, r1, dl])
    f = await expect(pub_p, cs.MB_FORWARD)
    check(f is not None and f[1:] == [r1, dl, owner.pseudonym], "the request is forwarded to its publisher")
    seq = await owner.send([cs.MB_REQUEST, r2, dl])
    err = await expect(owner, cs.MB_ERROR)
    check(err == [cs.MB_ERROR, seq, cs.MB_ERRORS.index("ALREADY_ANSWERED")],
          "a second request for the same transmission is refused: ALREADY_ANSWERED")

    await pub_q.send([cs.MB_RESULT, r1, RESULT["BUSY"], 0])
    check(not [m for m in await quiet(owner, 0.3) if m[0] == cs.MB_RESULT_S],
          "a result from a publisher that was not asked is ignored")
    seq = await owner.send([cs.MB_REQUEST, r2, dl])
    err = await expect(owner, cs.MB_ERROR)
    check(err is not None and err[1:] == [seq, cs.MB_ERRORS.index("ALREADY_ANSWERED")],
          "... and releases nothing")

    await pub_p.send([cs.MB_RESULT, r1, RESULT["BUSY"], 0])
    res = await expect(owner, cs.MB_RESULT_S)
    check(res == [cs.MB_RESULT_S, r1, RESULT["BUSY"], 0], "the publisher's BUSY reaches the owner")
    await owner.send([cs.MB_REQUEST, r2, dl])
    f = await expect(pub_p, cs.MB_FORWARD)
    check(f is not None and f[1] == r2, "a non-SENT result releases the transmission: the next request is forwarded")
    await pub_p.send([cs.MB_RESULT, r2, RESULT["SENT"], 1200])
    res = await expect(owner, cs.MB_RESULT_S)
    check(res == [cs.MB_RESULT_S, r2, RESULT["SENT"], 1200], "SENT reaches the owner")
    seq = await owner.send([cs.MB_REQUEST, r1, dl])
    err = await expect(owner, cs.MB_ERROR)
    check(err is not None and err[1:] == [seq, cs.MB_ERRORS.index("ALREADY_ANSWERED")],
          "after SENT the transmission stays answered")

    # Forged registrations of home A's tag by someone who has heard it but holds no keys.
    keys_a = cs.keys_from(sensor_a.k_session, DEV_EUI)
    seed_a = cs.tag_seed(keys_a.k_dev_tag, cs.epoch_index(e))
    pub_a = cs.ed25519_pub(seed_a)
    forger = await client(url)
    exp = cs.EPOCH_SECONDS * (e + 2)
    msg = cs.reg_msg(sid, forger.pub, exp)
    wrong_key = cs.ed_sign(secrets.token_bytes(32), msg)
    good = cs.ed_sign(seed_a, msg)
    s_plus_l = (int.from_bytes(good[32:], "little") + cs._EL).to_bytes(32, "little")
    for_owner = cs.reg_entry(seed_a, sid, owner.pub, exp)  # a real proof, made for another owner key
    await forger.send([cs.MB_REGISTER, [[pub_a, wrong_key, exp], [pub_a, good[:32] + s_plus_l, exp], for_owner]])
    reg = await expect(forger, cs.MB_REGISTERED)
    bad = cs.MB_ERRORS.index("BAD_PROOF")
    check(reg is not None and reg[2] == [bad, bad, bad], "forged registrations of A's tag are refused: wrong key, "
          "non-canonical S, a proof made for another owner key"
          + (f" ({[cs.MB_ERRORS[x] for x in reg[2]]})" if reg else ""))
    frame = sensor_a.uplink(cs.T_DATA, fcnt_a, now, reading(0))
    await pub_q.send([cs.MB_PUBLISH, frame, [[secrets.token_bytes(8), -950, 30, 100, 0]]])
    check(not [m for m in await quiet(forger, 0.5) if m[0] == cs.MB_DELIVER], "the forger receives none of A's frames")

    join = cs.SensorPairing(K_ROOT_2, DEV_EUI_2).join(70, secrets.token_bytes(32))
    seq = await pub_q.send([cs.MB_PUBLISH, join, [[secrets.token_bytes(8), -950, 30, 100, 0]]])
    err = await expect(pub_q, cs.MB_ERROR)
    check(err == [cs.MB_ERROR, seq, cs.MB_ERRORS.index("BAD_FRAME")], "a published JOIN is refused: BAD_FRAME")
    for link in (owner, pub_p, pub_q, forger):
        await link.close()


# ---------------------------------------------------------------- the homes

def main() -> int:
    if not os.path.exists(HOST_PROXY):
        print(f"{HOST_PROXY} missing; run make -C tests/host_proxy host_proxy", file=sys.stderr)
        return 2
    started = time.monotonic()
    sensor, state_a = paired_sensor(K_ROOT, DEV_EUI)
    work = tempfile.mkdtemp()
    state_path = os.path.join(work, "home_a.json")
    with open(state_path, "w") as f:
        json.dump({DEV_EUI.hex(): state_a}, f)

    procs: dict[str, Watched] = {}
    py = [sys.executable, "-I"]
    server = [*py, os.path.join(ROOT, "devtools", "cs_testserver.py"), "--key", KEY]
    try:
        procs["mailbox"] = mb = Watched([*py, os.path.join(ROOT, "mailbox", "cs_mailbox.py"), "--host", "127.0.0.1",
                                         "--listen", "127.0.0.1", "--port", "0", "--insecure-dev"])
        m = mb.wait_for(r"Listening on ws://127\.0\.0\.1:(\d+)")
        if not check(m is not None, "cs-mailbox up"):
            return 1
        url = f"ws://127.0.0.1:{m.group(1)}/"
        fed = ["--mailbox", url, "--insecure-dev"]
        port_b = free_port()
        procs["A"] = a = Watched([*server, "--port", str(free_port()), "--device", f"{DEV_EUI.hex()}:{K_ROOT.hex()}",
                                  "--state", state_path, "--queue-nop", "1", *fed])
        procs["B"] = b = Watched([*server, "--port", str(port_b), *fed, "--publish", "--federated-downlinks"])
        procs["C"] = c = Watched([*server, "--port", str(free_port()), *fed])
        reg = a.wait_for(r"registered (\d+) tags: OK x(\d+)$")
        check(reg is not None and reg.group(1) == reg.group(2) and int(reg.group(1)) >= 7,
              "home A registers its sensor's tags: 4 epochs and a SYNC window" + (f" ({reg.group(1)})" if reg else ""))
        check(b.wait_for(r"welcome as") is not None and c.wait_for(r"welcome as") is not None,
              "homes B and C connected")
        procs["proxy"] = proxy = Watched([HOST_PROXY, "--port", str(port_b), "--key", KEY], stdin=True)
        check(proxy.wait_for(r"^connected 1$") is not None, "B's host proxy connected")
        # Connected is not enough: a loop stall on a slow machine withdraws downlinks for
        # 10 s, and B publishes without DOWNLINK until a HELLO offers them again.
        check(b.wait_latest(r" HELLO cs_proxy host", r"downlink yes", timeout=20), "B's proxy offers downlinks")

        # 1. A confirmed uplink heard only by B's proxy reaches A, and A answers in RX2 through it.
        fcnt = 2
        up = sensor.uplink(cs.T_DATA_CONFIRMED, fcnt, int(time.time()), reading(1))
        first_tx = time.monotonic()
        exchange(a, b, c, mb, proxy, sensor, up, fcnt, "first transmission", 1)

        # 2. The sensor's retry, 4 s later: a new transmission, published, requested and answered again.
        time.sleep(max(0.0, 4.0 - (time.monotonic() - first_tx)))
        exchange(a, b, c, mb, proxy, sensor, up, fcnt, "retry", 2)

        # 3. JOIN frames are never published.
        b0, m0 = b.mark(), mb.mark()
        join = cs.SensorPairing(K_ROOT_2, DEV_EUI_2).join(1, secrets.token_bytes(32))
        proxy.send("uplink " + join.hex())
        check(b.wait_for(r"JOIN not published", since=b0) is not None, "B does not publish a JOIN its proxy heard")
        check(mb.wait_for(r"publish", since=m0, timeout=0.5) is None, "... and the mailbox sees no publish")

        # 4. Scripted parties: one request per transmission, release, results, forged proofs.
        asyncio.run(scripted(url, sensor, fcnt + 1))
        check(a.wait_for(rf"UPLINK DATA fcnt {fcnt + 1} .*{DEV_EUI.hex()} .*\[federated", timeout=2) is not None,
              "A still receives its own frame that the forger tried to claim")

        out_c = c.stop()
        check("UPLINK" not in out_c and "deliver" not in out_c, "home C, which registered nothing, received nothing")
        elapsed = time.monotonic() - started
        check(elapsed < 30, f"harness ran in {elapsed:.1f} s (budget 30 s)")
    finally:
        outputs = {name: p.stop() for name, p in procs.items()}
    for name, out in outputs.items():
        print(f"--- {name} ---\n{out.strip()}")
    print("all checks pass" if failures == 0 else f"{failures} failures")
    return 1 if failures else 0


def exchange(a: Watched, b: Watched, c: Watched, mb: Watched, proxy: Watched, sensor: cs.SensorPairing,
             up: bytes, fcnt: int, what: str, tx_n: int) -> None:
    a0, b0, c0, m0, p0 = a.mark(), b.mark(), c.mark(), mb.mark(), proxy.mark()
    proxy.send("uplink " + up.hex())
    check(b.wait_for(rf"published DATA_CONFIRMED tag {up[2:10].hex()} fcnt {fcnt}, 1 receptions, DOWNLINK", since=b0)
          is not None, f"{what}: B publishes the frame it could not verify, with DOWNLINK")
    m = mb.wait_for(rf"publish tag {up[2:10].hex()} fcnt {fcnt}, 1 receptions: (\w+) transmission (\d+), "
                    r"delivered to (\d+)", since=m0)
    check(m is not None and m.group(1) == "new" and m.group(3) == "1",
          f"{what}: the mailbox takes it as a new transmission and delivers it to one owner key"
          + (f" ({m.group(0)})" if m else ""))
    counter = "accept" if tx_n == 1 else "duplicate"
    check(a.wait_for(rf"UPLINK DATA_CONFIRMED fcnt {fcnt} .*{DEV_EUI.hex()} \(session keys, by tag, {counter}\) "
                     r"\[federated via", since=a0) is not None,
          f"{what}: A receives it into its uplink path, marked federated ({counter})")
    check(a.wait_for(rf"request RX2 answer to fcnt {fcnt} through publisher .*, NOP \(1 queued\)\)$", since=a0)
          is not None, f"{what}: A requests an RX2 answer, carrying its queued NOP, within the 09 section 7.6 timing")
    dl = b.wait_for(rf"forward \w+ from \w+: {PROXY_ID} -> DOWNLINK seq (\d+) in rx2", since=b0)
    check(dl is not None, f"{what}: B passes the forwarded downlink to its proxy for RX2")
    tx = proxy.wait_for(r"^tx ([0-9a-f]+)$", since=p0)
    if check(tx is not None, f"{what}: B's proxy transmits it"):
        frame = bytes.fromhex(tx.group(1))
        h, pt = cs.open_frame(cs.keys_from(sensor.k_session, DEV_EUI), frame)
        verdict = sensor.downlink(frame)
        check(verdict == "accept" and struct.unpack(">I", pt[:4])[0] == fcnt and pt[9:] == cs.command(cs.CMD_NOP),
              f"{what}: the sensor accepts it as the answer to fcnt {fcnt}, with the NOP ({verdict})")
    if dl is not None:
        res = b.wait_for(rf"TX_RESULT seq {dl.group(1)}: (\w+), (-?[\d.]+) ms after target", since=b0)
        check(res is not None and res.group(1) == "SENT" and 0 <= float(res.group(2)) <= 40,
              f"{what}: TX_RESULT SENT within the 40 ms start window"
              + (f" ({res.group(1)} {res.group(2)} ms)" if res else ""))
    check(a.wait_for(r"result for rx_ref \w+: SENT", since=a0) is not None, f"{what}: A gets the SENT result")
    check(c.wait_for(r"UPLINK", since=c0, timeout=0.2) is None, f"{what}: C receives nothing")


if __name__ == "__main__":
    sys.exit(main())
