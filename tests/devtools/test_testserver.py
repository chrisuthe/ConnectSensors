#!/usr/bin/env python3
"""Smoke test: devtools/cs_testserver.py against a simulated proxy.

    python3 tests/devtools/test_testserver.py
"""

import os
import socket
import struct
import sys
import tempfile
import time

sys.dont_write_bytecode = True
ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "spec", "tools"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import csframe as cs  # noqa: E402
from procwatch import Watched  # noqa: E402

KEY = bytes.fromhex("5a" * 16)
PROXY_ID = bytes.fromhex("348518fffe000001")
PROXY_B = bytes.fromhex("348518fffe000002")
BOOT = 0x01020304
OLD_BOOT = 0x0BADB007
NEW_BOOT = 0x01020305


def free_port() -> int:
    """A UDP port the OS reports free, so parallel runs don't collide (#67)."""
    if os.environ.get("CS_TEST_PORT"):
        return int(os.environ["CS_TEST_PORT"])
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("", 0))  # the server binds 0.0.0.0
        return probe.getsockname()[1]


PORT = free_port()


def start_server(*extra: str) -> Watched:
    srv = Watched([sys.executable, "-I", os.path.join(ROOT, "devtools", "cs_testserver.py"), "--port", str(PORT),
                   "--key", KEY.hex(), "--ack", *extra])
    if srv.wait_for(r"Listening on UDP") is None:
        raise RuntimeError("test server did not start:\n" + srv.stop())
    return srv


def stop_server(srv: Watched) -> str:
    return srv.stop()


def now_ms() -> int:
    return int(time.monotonic() * 1000)


class SimProxy:
    """One proxy boot: its seq, and its checks on server messages (05 section 3.2)."""

    def __init__(self, sock, dest, proxy_id: bytes, boot_id: int):
        self.sock, self.dest, self.proxy_id, self.boot_id = sock, dest, proxy_id, boot_id
        self.seq = 0
        self.link = cs.ProxyLink(boot_id)

    def send(self, msg_type: int, body: bytes) -> bytes:
        self.seq += 1
        msg = cs.envelope(KEY, msg_type, self.proxy_id, self.boot_id, self.seq, body)
        self.link.sent(cs.open_envelope(KEY, msg), now_ms())
        self.sock.sendto(msg, self.dest)
        return msg

    def recv(self):
        m = cs.open_envelope(KEY, self.sock.recv(2048))
        return m, self.link.receive(m, now_ms())["result"]


def hello(nonce: int = 0) -> bytes:
    return cs.hello_body(cs.CAP_DOWNLINK, "US915", 918_500_000, 9, 500, 5, [1, 1, 0, 0, 0, 0, 0], 3,
                         "cs_proxy test", nonce)


def nonce_of(m) -> int:
    return struct.unpack(">I", bytes.fromhex(m["body"]))[0]


def hello_seq_of(m) -> int:
    return cs.parse_server_status(bytes.fromhex(m["body"]))["hello_seq"]


def main() -> int:
    port = PORT
    srv = start_server()
    out = out2 = ""
    dl_seq = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        dest = ("127.0.0.1", port)
        frames = {f["name"]: bytes.fromhex(f["frame"]) for f in cs.frame_vectors()["frames"]}
        failures = 0

        def check(cond, what):
            nonlocal failures
            print(("ok   " if cond else "FAIL ") + what)
            failures += not cond

        proxy = SimProxy(s, dest, PROXY_ID, BOOT)

        def join(px: SimProxy, what: str) -> None:
            """Boot handshake: HELLO, HELLO_REQUEST, HELLO echoing the nonce, SERVER_STATUS."""
            px.send(cs.M_HELLO, hello())
            m, res = px.recv()
            check(m["type"] == cs.M_HELLO_REQUEST and m["boot_id"] == px.boot_id and res == "hello",
                  f"{what}: first HELLO draws a HELLO_REQUEST")
            px.send(cs.M_HELLO, hello(nonce_of(m)))
            m, res = px.recv()
            check(m["type"] == cs.M_SERVER_STATUS and res == "accepted" and hello_seq_of(m) == px.seq,
                  f"{what}: HELLO echoing the nonce answered with SERVER_STATUS for this boot")

        join(proxy, "proxy A")

        rx_time = 5_000_000
        up = cs.uplink_body(rx_time, -90.0, 7.5, 0, frames["data_confirmed"])
        proxy.send(cs.M_UPLINK, up)
        m, res = proxy.recv()
        check(m["type"] == cs.M_DOWNLINK and res == "accepted", "confirmed uplink answered with DOWNLINK")
        dl_seq = m["seq"]
        body = bytes.fromhex(m["body"])
        ref, offset, flen = struct.unpack(">QIB", body[:13])
        check(ref == rx_time and offset == 1_000_000, "downlink targets RX1 on the proxy's own clock")
        device_keys = cs.keys_from(bytes.fromhex(cs.frame_vectors()["derived"]["k_session"]), cs.DEV_EUI)
        h, pt = cs.open_frame(device_keys, body[13:13 + flen])
        reply_to = struct.unpack(">I", pt[:4])[0]
        check(h.ftype == cs.T_DOWNLINK and reply_to == 3, "downlink decrypts for the device and answers fcnt 3")

        sent_at = time.monotonic()
        fcnt_down = h.fcnt

        # The same frame from a second proxy right away is a copy of that transmission: no answer.
        proxy_b = SimProxy(s, dest, PROXY_B, BOOT)
        join(proxy_b, "proxy B")
        proxy_b.send(cs.M_UPLINK, up)
        try:
            s.recv(2048)
            check(False, "copy from a second proxy not answered again")
        except socket.timeout:
            check(True, "copy from a second proxy not answered again")

        # The sensor's retry, 4 s or more later, is answered again with a new downlink (07 section 6.4).
        time.sleep(max(0.0, sent_at + 4.5 - time.monotonic()))
        last_uplink = proxy.send(cs.M_UPLINK, up)
        m, res = proxy.recv()
        check(m["type"] == cs.M_DOWNLINK and res == "accepted", "retransmission 4.5 s later answered again")
        body = bytes.fromhex(m["body"])
        flen = body[12]
        h, pt = cs.open_frame(device_keys, body[13:13 + flen])
        check(struct.unpack(">I", pt[:4])[0] == 3 and h.fcnt > fcnt_down,
              "answer to the retry is a new downlink for fcnt 3")

        # A replayed message (same seq) is ignored: no answer.
        s.sendto(last_uplink, dest)
        try:
            s.recv(2048)
            check(False, "replayed message ignored")
        except socket.timeout:
            check(True, "replayed message ignored")

        # A message with the wrong key is rejected.
        s.sendto(cs.envelope(bytes(16), cs.M_HELLO, PROXY_ID, BOOT, 99, hello()), dest)
        try:
            s.recv(2048)
            check(False, "wrong key rejected")
        except socket.timeout:
            check(True, "wrong key rejected")

        proxy.send(cs.M_TX_RESULT, cs.tx_result_body(dl_seq, 0, 1500))
        recorded_hello = proxy.send(cs.M_HELLO, hello())
        m, res = proxy.recv()
        check(m["type"] == cs.M_SERVER_STATUS and res == "accepted" and hello_seq_of(m) == proxy.seq,
              "periodic HELLO answered with SERVER_STATUS echoing it")

        # A TX_RESULT's offset_us must not leak into later downlinks: it once
        # overwrote the RX1 offset, so every downlink after the first went out early.
        time.sleep(max(0.0, sent_at + 9.0 - time.monotonic()))
        proxy.send(cs.M_UPLINK, up)
        m, res = proxy.recv()
        body = bytes.fromhex(m["body"])
        check(m["type"] == cs.M_DOWNLINK and struct.unpack(">QIB", body[:13])[1] == 1_000_000,
              "downlink after a TX_RESULT still targets RX1")
        srv.wait_for(rf"TX_RESULT seq {dl_seq}:")
        out = stop_server(srv)

        # Restart the server (#4, #5) with no clock seeding: its seq starts again at 1,
        # far below the proxy's floor. The proxy keeps its boot and its checks.
        srv = start_server("--no-seq-seed")
        proxy.send(cs.M_UPLINK, up)
        sent_at = time.monotonic()
        m, res = proxy.recv()
        check(m["type"] == cs.M_HELLO_REQUEST and res == "hello",
              "restarted server answers the first UPLINK with HELLO_REQUEST")
        check(time.monotonic() - sent_at < 1.0, "HELLO_REQUEST arrives within a second, not at the next HELLO")
        proxy.send(cs.M_HELLO, hello(nonce_of(m)))
        m, res = proxy.recv()
        check(m["type"] == cs.M_SERVER_STATUS and m["seq"] == 1 and res == "resync",
              "restarted server's SERVER_STATUS seq 1 accepted by the running proxy through the echo")
        proxy.send(cs.M_UPLINK, up)
        m, res = proxy.recv()
        check(m["type"] == cs.M_DOWNLINK and res == "accepted",
              "restarted server's DOWNLINK accepted by the running proxy")

        # A HELLO from an earlier boot, replayed, does not move the session.
        s.sendto(cs.envelope(KEY, cs.M_HELLO, PROXY_ID, OLD_BOOT, 1, hello()), dest)
        m = cs.open_envelope(KEY, s.recv(2048))
        check(m["type"] == cs.M_HELLO_REQUEST and m["boot_id"] == OLD_BOOT,
              "replayed HELLO from an earlier boot draws only a HELLO_REQUEST for that boot")
        # Even echoing a nonce the server once used, the old boot does not take over.
        s.sendto(cs.envelope(KEY, cs.M_HELLO, PROXY_ID, OLD_BOOT, 2, hello(0x5EED0001)), dest)
        try:
            m = cs.open_envelope(KEY, s.recv(2048))
            check(m["type"] == cs.M_HELLO_REQUEST, "old boot echoing a wrong nonce draws at most a HELLO_REQUEST")
        except socket.timeout:
            check(True, "old boot echoing a wrong nonce draws at most a HELLO_REQUEST")
        # This proxy's HELLO recorded before the restart is stale in the new session too.
        s.sendto(recorded_hello, dest)
        try:
            m = cs.open_envelope(KEY, s.recv(2048))
            check(False, "HELLO recorded before the restart ignored")
        except socket.timeout:
            check(True, "HELLO recorded before the restart ignored")
        proxy.send(cs.M_HELLO, hello())
        m, res = proxy.recv()
        check(m["type"] == cs.M_SERVER_STATUS and m["boot_id"] == BOOT and res == "accepted",
              "the session still belongs to the running proxy's boot")

        # A frame that is not the test device's is logged and not answered, even confirmed.
        mark = srv.mark()
        stranger = cs.keys_from(bytes(range(16)), bytes.fromhex("c5c50000000000ff"))
        foreign = cs.seal(stranger, cs.T_DATA_CONFIRMED, bytes.fromhex("61d306d301020304"), 9,
                          bytes([0]) + cs.encode_reading(0, 0x01, 1))
        proxy.send(cs.M_UPLINK, cs.uplink_body(9_000_000, -95.0, 3.0, 0, foreign))
        check(srv.wait_for(r"UPLINK DATA_CONFIRMED fcnt 9 .*\(not the test device\)", since=mark) is not None,
              "frame from another device logged as not the test device")
        check(no_reply(s), "frame from another device not answered")

        # The proxy reboots: a new boot_id takes the session over through the HELLO
        # handshake, its downlinks carry it, and the old boot gets only a HELLO_REQUEST.
        mark = srv.mark()
        rebooted = SimProxy(s, dest, PROXY_ID, NEW_BOOT)
        join(rebooted, "proxy A after a reboot")
        check(srv.wait_for(rf"{PROXY_ID.hex()}: session with boot {NEW_BOOT:08x}", since=mark) is not None,
              "server switches the session to the new boot")
        rebooted.send(cs.M_UPLINK, cs.uplink_body(11_000_000, -90.0, 7.5, 0, frames["sync_after_reboot"]))
        m, res = rebooted.recv()
        check(m["type"] == cs.M_DOWNLINK and m["boot_id"] == NEW_BOOT and res == "accepted",
              "after a reboot, the DOWNLINK carries the new boot_id")
        proxy.send(cs.M_UPLINK, up)
        m = cs.open_envelope(KEY, s.recv(2048))
        check(m["type"] == cs.M_HELLO_REQUEST and m["boot_id"] == BOOT,
              "the old boot's UPLINK draws a HELLO_REQUEST for that boot, not a DOWNLINK")
    finally:
        out2 = stop_server(srv)
    check(f"TX_RESULT seq {dl_seq}: SENT, 1.5 ms after target" in out, "TX_RESULT reported")
    check(out.count("two downlink-capable proxies share --key") == 1,
          "a second downlink-capable proxy on the one key draws one warning")
    check("share --key" not in out2, "no warning with a single proxy")
    check(f"session with boot {NEW_BOOT:08x}" in out2, "server logs the reboot's new session")
    print("--- server output ---\n" + out.strip())
    print("--- restarted server output ---\n" + out2.strip())
    print("all checks pass" if failures == 0 else f"{failures} failures")
    return 1 if failures else 0


def no_reply(s: socket.socket, wait: float = 0.5) -> bool:
    """Nothing arrives within wait. The caller has already seen the server handle the message."""
    s.settimeout(wait)
    try:
        s.recv(2048)
        return False
    except socket.timeout:
        return True
    finally:
        s.settimeout(3)


# --window rx2: a confirmed uplink is answered 3 s after it was received (07 section 6.3).
def rx2_main() -> int:
    failures = 0

    def check(cond, what):
        nonlocal failures
        print(("ok   " if cond else "FAIL ") + what)
        failures += not cond

    frame = bytes.fromhex(next(f["frame"] for f in cs.frame_vectors()["frames"] if f["name"] == "data_confirmed"))
    srv = start_server("--window", "rx2")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        proxy = SimProxy(s, ("127.0.0.1", PORT), PROXY_ID, BOOT)
        proxy.send(cs.M_HELLO, hello())
        m, _ = proxy.recv()
        proxy.send(cs.M_HELLO, hello(nonce_of(m)))
        m, res = proxy.recv()
        check(m["type"] == cs.M_SERVER_STATUS and res == "accepted", "rx2: proxy session up")
        rx_time = 8_000_000
        proxy.send(cs.M_UPLINK, cs.uplink_body(rx_time, -90.0, 7.5, 0, frame))
        m, res = proxy.recv()
        body = bytes.fromhex(m["body"])
        check(m["type"] == cs.M_DOWNLINK and res == "accepted" and struct.unpack(">QI", body[:12]) == (rx_time, 3_000_000),
              "rx2: confirmed uplink answered with a DOWNLINK 3 s after its receive time")
        srv.wait_for(r"answering fcnt 3 in rx2")
    finally:
        out = stop_server(srv)
    check("downlinks on (rx2)" in out and "answering fcnt 3 in rx2" in out, "rx2: server reports the RX2 window")
    print("rx2: all checks pass" if failures == 0 else f"rx2: {failures} failures")
    return 1 if failures else 0


# A real sensor, registered by its pairing code, pairs through a simulated proxy
# (04 section 4.4) and its traffic is answered, across a server restart with --state.
SENSOR_EUI = bytes.fromhex("c5c5000000000042")
SENSOR_ROOT = bytes.fromhex("0f0e0d0c0b0a09080706050403020100")
OTHER = "c5c5000000000043:" + "11" * 16
PAIR_BOOT = 0x0A0B0C0D
PAIR_BOOT_2 = 0x0A0B0C0E


def pairing_main() -> int:
    failures = 0

    def check(cond, what):
        nonlocal failures
        print(("ok   " if cond else "FAIL ") + what)
        failures += not cond

    def handshake(px: SimProxy) -> None:
        px.send(cs.M_HELLO, hello())
        m, _ = px.recv()
        px.send(cs.M_HELLO, hello(nonce_of(m)))
        m, res = px.recv()
        check(m["type"] == cs.M_SERVER_STATUS and res == "accepted", "pairing: proxy session up")

    def uplink(px: SimProxy, frame: bytes, rx_time: int = 7_000_000):
        """Send a frame; return the downlink frame it drew, or None."""
        px.send(cs.M_UPLINK, cs.uplink_body(rx_time, -80.0, 9.0, 0, frame))
        try:
            m, res = px.recv()
        except socket.timeout:
            return None
        body = bytes.fromhex(m["body"])
        ref, offset, flen = struct.unpack(">QIB", body[:13])
        check(m["type"] == cs.M_DOWNLINK and res == "accepted" and ref == rx_time and offset == 1_000_000,
              "pairing: answer is a DOWNLINK for RX1 of that uplink")
        return body[13:13 + flen]

    code = cs.qr_encode(SENSOR_EUI, SENSOR_ROOT, "US915", "ESPHOME")
    out = out2 = ""
    with tempfile.TemporaryDirectory() as tmp:
        state = os.path.join(tmp, "pairings.json")
        srv = start_server("--device", code, "--device", OTHER, "--state", state)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(3)
            dest = ("127.0.0.1", PORT)
            proxy = SimProxy(s, dest, PROXY_ID, PAIR_BOOT)
            handshake(proxy)

            # Steps 2-4: JOIN under the root key set, KEY_EXCHANGE back.
            sensor = cs.SensorPairing(SENSOR_ROOT, SENSOR_EUI)
            join = sensor.join(1, bytes([0x42]) * 32)
            dl = uplink(proxy, join)
            check(dl is not None and sensor.downlink(dl) == "accept",
                  "pairing: KEY_EXCHANGE accepted by the sensor")
            root_fcnt = cs.parse_header(dl).fcnt if dl else 0
            check(root_fcnt > 1_700_000_000, "pairing: root counter starts above any earlier run's")

            # 04 section 4.2: a retransmitted JOIN gets the same frame back, byte for byte.
            time.sleep(cs.MERGE_WINDOW_MS / 1000 + 0.2)
            check(uplink(proxy, join) == dl, "pairing: retransmitted JOIN answered with the cached frame")

            # Steps 5-7: the first session uplink, with a normal tag from KEY_EXCHANGE's
            # server_time and DL_ACK, is found by the tag table, marks the device PAIRED
            # and is answered under the session keys, which completes the sensor's pairing.
            _, ke_pt = cs.open_frame(sensor.root, dl) if dl else (None, bytes(9))
            server_time = struct.unpack(">I", ke_pt[4:8])[0]
            check(abs(server_time - time.time()) < 5, "pairing: server_time is the server's clock")
            session = cs.keys_from(sensor.k_session, SENSOR_EUI)
            hb = sensor.uplink(cs.T_HEARTBEAT_CONFIRMED, 2, server_time,
                               bytes([cs.UF_DL_ACK]) + cs.encode_reading(0, 0x01, 1) +
                               cs.encode_reading(0xFF, 0x42, 3700))
            dl = uplink(proxy, hb)
            check(dl is not None and sensor.downlink(dl) == "accept" and sensor.state == "PAIRED",
                  "pairing: first session uplink answered; the sensor is PAIRED")
            h, pt = cs.open_frame(session, dl)
            check(struct.unpack(">I", pt[:4])[0] == 2 and h.tag == hb[2:10],
                  "pairing: the answer carries the uplink's tag")
            last_down = h.fcnt
            srv.wait_for(r"PAIRED")
            ntag = cs.normal_tag(session.k_dev_tag, cs.epoch_of(server_time))

            # Normal traffic: a door opening, confirmed, is answered; an unconfirmed frame is not.
            data = cs.seal(session, cs.T_DATA_CONFIRMED, ntag, 4, bytes([0]) + cs.encode_reading(0, 0x01, 0))
            dl = uplink(proxy, data)
            h, pt = cs.open_frame(session, dl)
            check(struct.unpack(">I", pt[:4])[0] == 4 and h.fcnt > last_down, "pairing: DATA_CONFIRMED answered")
            last_down = h.fcnt
            plain = cs.seal(session, cs.T_DATA, ntag, 5, bytes([0]) + cs.encode_reading(0, 0x01, 1))
            check(uplink(proxy, plain) is None, "pairing: unconfirmed DATA not answered")
            srv.wait_for(r"UPLINK DATA fcnt 5 ")
        finally:
            out = stop_server(srv)
        check(f"{SENSOR_EUI.hex()} PAIRED" in out, "pairing: server reports the device PAIRED")
        check("ch0 contact=0" in out, "pairing: server decrypts the door state")

        # A restart with --state keeps the session and both counters.
        srv = start_server("--device", code, "--state", state)
        try:
            proxy = SimProxy(s, dest, PROXY_ID, PAIR_BOOT_2)
            handshake(proxy)
            data = cs.seal(session, cs.T_DATA_CONFIRMED, ntag, 6, bytes([0]) + cs.encode_reading(0, 0x01, 1))
            dl = uplink(proxy, data)
            ok = False
            if dl is not None:
                h, pt = cs.open_frame(session, dl)
                ok = struct.unpack(">I", pt[:4])[0] == 6 and h.fcnt > last_down
            check(ok, "pairing: after a restart, the stored session answers with a higher counter")
            stale = cs.seal(session, cs.T_DATA_CONFIRMED, ntag, 4, bytes([0]) + cs.encode_reading(0, 0x01, 0))
            check(uplink(proxy, stale) is None, "pairing: an old counter is not answered after a restart")

            # A SYNC far past the table's blocks is found by trial decryption (07 section 4).
            far = cs.seal(session, cs.T_SYNC, cs.bootstrap_tag(session.k_dev_tag, 1000), 1000,
                          bytes([cs.UF_TIME_UNSURE]))
            dl = uplink(proxy, far)
            check(dl is not None and cs.open_frame(session, dl)[0].tag == far[2:10],
                  "pairing: SYNC past the tag table found by the bootstrap fallback and answered")
            # A normal tag outside the table is not tried.
            late = cs.seal(session, cs.T_DATA_CONFIRMED, cs.normal_tag(session.k_dev_tag, cs.epoch_of(server_time) + 5),
                           1001, bytes([0]))
            check(uplink(proxy, late) is None, "pairing: a normal tag outside the window is not tried")
        finally:
            out2 = stop_server(srv)
    print("--- pairing server output ---\n" + out.strip())
    print("--- restarted pairing server output ---\n" + out2.strip())
    print("pairing: all checks pass" if failures == 0 else f"pairing: {failures} failures")
    return 1 if failures else 0


# --queue-nop and `nop` on stdin: NOPs go out one per downlink with PENDING while
# more remain, and DL_ACK settles them (07 section 7). In RX1 an unconfirmed
# follow-up is answered; in RX2 only a confirmed one can be (07 section 6.3).
QUEUE_BOOT = 0x0A0B0C1F


def queue_main() -> int:
    failures = 0

    def check(cond, what):
        nonlocal failures
        print(("ok   " if cond else "FAIL ") + what)
        failures += not cond

    code = cs.qr_encode(SENSOR_EUI, SENSOR_ROOT, "US915", "ESPHOME")
    outs = []
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    for window, offset in (("rx1", 1_000_000), ("rx2", 3_000_000)):
        srv = Watched([sys.executable, "-I", os.path.join(ROOT, "devtools", "cs_testserver.py"), "--port",
                       str(PORT), "--key", KEY.hex(), "--device", code, "--window", window, "--queue-nop", "2"],
                      stdin=True)
        try:
            check(srv.wait_for(r"Listening on UDP") is not None and srv.wait_for(r"2 NOP queued") is not None,
                  f"queue {window}: server up with 2 NOPs queued")
            proxy = SimProxy(s, ("127.0.0.1", PORT), PROXY_ID, QUEUE_BOOT)
            proxy.send(cs.M_HELLO, hello())
            m, _ = proxy.recv()
            proxy.send(cs.M_HELLO, hello(nonce_of(m)))
            proxy.recv()
            rx = [20_000_000]

            def uplink(frame: bytes):
                """Send a frame; return (offset, downlink frame) or None."""
                rx[0] += 10_000_000
                proxy.send(cs.M_UPLINK, cs.uplink_body(rx[0], -80.0, 9.0, 0, frame))
                try:
                    m, _ = proxy.recv()
                except socket.timeout:
                    return None
                body = bytes.fromhex(m["body"])
                _, off, flen = struct.unpack(">QIB", body[:13])
                return off, body[13:13 + flen]

            sensor = cs.SensorPairing(SENSOR_ROOT, SENSOR_EUI)
            _, dl = uplink(sensor.join(1, bytes([0x42]) * 32))
            sensor.downlink(dl)
            _, ke = cs.open_frame(sensor.root, dl)
            server_time = struct.unpack(">I", ke[4:8])[0]
            session = cs.keys_from(sensor.k_session, SENSOR_EUI)
            _, dl = uplink(sensor.uplink(cs.T_HEARTBEAT_CONFIRMED, 2, server_time, bytes([cs.UF_DL_ACK])))
            check(sensor.downlink(dl) == "accept" and sensor.state == "PAIRED", f"queue {window}: paired")
            ntag = cs.normal_tag(session.k_dev_tag, cs.epoch_of(server_time))

            def answer(got):
                """(PENDING, commands) of a downlink, checking it targets this window."""
                if got is None:
                    return None
                off, dl = got
                _, pt = cs.open_frame(session, dl)
                check(off == offset, f"queue {window}: downlink targets {window}")
                return bool(pt[8] & cs.DF_PENDING), pt[9:]

            nop = cs.command(cs.CMD_NOP)
            # A confirmed uplink draws the first NOP, with PENDING: one more remains.
            got = answer(uplink(cs.seal(session, cs.T_DATA_CONFIRMED, ntag, 3, bytes([0]))))
            check(got == (True, nop), f"queue {window}: confirmed uplink answered with NOP and PENDING")
            if window == "rx1":
                # The unconfirmed follow-up acknowledges it and draws the last NOP in RX1.
                got = answer(uplink(cs.seal(session, cs.T_HEARTBEAT, ntag, 4, bytes([cs.UF_DL_ACK]))))
                check(got == (False, nop), "queue rx1: unconfirmed follow-up answered with the last NOP")
                check(uplink(cs.seal(session, cs.T_DATA, ntag, 5, bytes([cs.UF_DL_ACK]))) is None,
                      "queue rx1: queue empty once acknowledged; unconfirmed uplink not answered")
                srv.wait_for(r"0 queued")
                # `nop` on stdin queues one more; the next unconfirmed uplink carries it.
                mark = srv.mark()
                srv.send("nop")
                check(srv.wait_for(r"1 NOP queued", since=mark) is not None, "queue rx1: stdin `nop` queues one")
                got = answer(uplink(cs.seal(session, cs.T_DATA, ntag, 6, bytes([0]))))
                check(got == (False, nop), "queue rx1: queued NOP rides on an unconfirmed uplink")
            else:
                # An unconfirmed follow-up can't be answered in RX2, but its DL_ACK still counts.
                check(uplink(cs.seal(session, cs.T_HEARTBEAT, ntag, 4, bytes([cs.UF_DL_ACK]))) is None,
                      "queue rx2: unconfirmed follow-up not answered")
                check(srv.wait_for(r"1 command\(s\) acknowledged, 1 queued") is not None,
                      "queue rx2: its DL_ACK settles the first NOP")
                # The confirmed follow-up (08 section 7) draws the last one, without PENDING.
                got = answer(uplink(cs.seal(session, cs.T_HEARTBEAT_CONFIRMED, ntag, 5, bytes([0]))))
                check(got == (False, nop), "queue rx2: confirmed follow-up answered with the last NOP")
                srv.wait_for(r"answering fcnt 5")
        finally:
            outs.append(srv.stop())
    print("--- queue server output ---\n" + "\n".join(o.strip() for o in outs))
    print("queue: all checks pass" if failures == 0 else f"queue: {failures} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    rc = main()
    rc = rx2_main() or rc
    rc = pairing_main() or rc
    sys.exit(queue_main() or rc)
