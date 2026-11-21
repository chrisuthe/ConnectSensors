#!/usr/bin/env python3
"""Smoke test: devtools/cs_testserver.py against a simulated proxy.

    python3 tests/devtools/test_testserver.py
"""

import os
import socket
import struct
import subprocess
import sys
import time

sys.dont_write_bytecode = True
ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "spec", "tools"))
import csframe as cs  # noqa: E402

KEY = bytes.fromhex("5a" * 16)
PROXY_ID = bytes.fromhex("348518fffe000001")
BOOT = 0x01020304


PORT = 47999


def start_server() -> subprocess.Popen:
    srv = subprocess.Popen(
        [sys.executable, "-I", os.path.join(ROOT, "devtools", "cs_testserver.py"), "--port", str(PORT),
         "--key", KEY.hex(), "--ack"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    time.sleep(1.0)
    return srv


def stop_server(srv: subprocess.Popen) -> str:
    srv.terminate()
    return srv.communicate(timeout=5)[0]


class SeqGuard:
    """The proxy's check on server messages (05 section 3.2, ServerSeqGuard)."""

    def __init__(self, boot_id: int):
        self.boot_id, self.last = boot_id, 0

    def accept(self, m) -> bool:
        if m["boot_id"] != self.boot_id or m["seq"] <= self.last:
            return False
        self.last = m["seq"]
        return True


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

        hello = cs.hello_body(cs.CAP_DOWNLINK, "US915", 918_500_000, 9, 500, 5, [1, 1, 0, 0, 0, 0, 0], 3,
                              "cs_proxy test")
        s.sendto(cs.envelope(KEY, cs.M_HELLO, PROXY_ID, BOOT, 1, hello), dest)
        m = cs.open_envelope(KEY, s.recv(2048))
        guard = SeqGuard(BOOT)
        check(m["type"] == cs.M_SERVER_STATUS and guard.accept(m),
              "HELLO answered with SERVER_STATUS for this boot")
        check(0 < m["seq"] <= 0xFFFFFFFF, "server seq is a uint32")

        rx_time = 5_000_000
        up = cs.uplink_body(rx_time, -90.0, 7.5, 0, frames["data_confirmed"])
        s.sendto(cs.envelope(KEY, cs.M_UPLINK, PROXY_ID, BOOT, 2, up), dest)
        m = cs.open_envelope(KEY, s.recv(2048))
        check(m["type"] == cs.M_DOWNLINK and guard.accept(m), "confirmed uplink answered with DOWNLINK")
        dl_seq = m["seq"]
        body = bytes.fromhex(m["body"])
        ref, offset, flen = struct.unpack(">QIB", body[:13])
        check(ref == rx_time and offset == 1_000_000, "downlink targets RX1 on the proxy's own clock")
        device_keys = cs.keys_from(bytes.fromhex(cs.frame_vectors()["derived"]["k_session"]), cs.DEV_EUI)
        h, pt = cs.open_frame(device_keys, body[13:13 + flen])
        reply_to = struct.unpack(">I", pt[:4])[0]
        check(h.ftype == cs.T_DOWNLINK and reply_to == 3, "downlink decrypts for the device and answers fcnt 3")

        # A replayed message (same seq) is ignored: no answer.
        s.sendto(cs.envelope(KEY, cs.M_UPLINK, PROXY_ID, BOOT, 2, up), dest)
        try:
            s.recv(2048)
            check(False, "replayed message ignored")
        except socket.timeout:
            check(True, "replayed message ignored")

        # A message with the wrong key is rejected.
        s.sendto(cs.envelope(bytes(16), cs.M_HELLO, PROXY_ID, BOOT, 3, hello), dest)
        try:
            s.recv(2048)
            check(False, "wrong key rejected")
        except socket.timeout:
            check(True, "wrong key rejected")

        s.sendto(cs.envelope(KEY, cs.M_TX_RESULT, PROXY_ID, BOOT, 4, cs.tx_result_body(dl_seq, 0, 1500)), dest)
        time.sleep(0.5)
        out = stop_server(srv)

        # Restart the server (#5). The proxy keeps its boot and its guard; the new
        # instance learns the boot from the next periodic HELLO.
        time.sleep(1.0)
        srv = start_server()
        s.sendto(cs.envelope(KEY, cs.M_HELLO, PROXY_ID, BOOT, 5, hello), dest)
        m = cs.open_envelope(KEY, s.recv(2048))
        check(m["type"] == cs.M_SERVER_STATUS and guard.accept(m),
              "restarted server's SERVER_STATUS accepted by the running proxy")
        up = cs.uplink_body(rx_time, -90.0, 7.5, 0, frames["data_confirmed"])
        s.sendto(cs.envelope(KEY, cs.M_UPLINK, PROXY_ID, BOOT, 6, up), dest)
        m = cs.open_envelope(KEY, s.recv(2048))
        check(m["type"] == cs.M_DOWNLINK and guard.accept(m),
              "restarted server's DOWNLINK accepted by the running proxy")
    finally:
        out2 = stop_server(srv)
    check(f"TX_RESULT seq {dl_seq}: SENT, 1.5 ms after target" in out, "TX_RESULT reported")
    print("--- server output ---\n" + out.strip())
    print("--- restarted server output ---\n" + out2.strip())
    print("all checks pass" if failures == 0 else f"{failures} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
