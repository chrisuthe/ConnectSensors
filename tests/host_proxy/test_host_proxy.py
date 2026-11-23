#!/usr/bin/env python3
"""The proxy engine, as a host program, against devtools/cs_testserver.py.

    make -C tests/host_proxy

Checks HELLO, UPLINK, the RX1 DOWNLINK and its TX_RESULT, then restarts the server
with its seq counting from 1 and checks the running proxy follows it (05 section 3.2).
"""

import os
import socket
import struct
import sys

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "spec", "tools"))
sys.path.insert(0, os.path.join(ROOT, "tests", "devtools"))
import csframe as cs  # noqa: E402
from procwatch import Watched  # noqa: E402

KEY = "5a" * 16
PROXY_ID = "348518fffe000010"  # host_proxy's default
BOOT = "40570001"
BINARY = os.path.join(HERE, "host_proxy")


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("", 0))
        return probe.getsockname()[1]


def main() -> int:
    if not os.path.exists(BINARY):
        print(f"{BINARY} missing; run make -C tests/host_proxy", file=sys.stderr)
        return 2
    port = free_port()
    frames = {f["name"]: f["frame"] for f in cs.frame_vectors()["frames"]}
    session = cs.keys_from(bytes.fromhex(cs.frame_vectors()["derived"]["k_session"]), cs.DEV_EUI)
    failures = 0

    def check(cond, what):
        nonlocal failures
        print(("ok   " if cond else "FAIL ") + what, flush=True)
        failures += not cond
        return cond

    def start_server(*extra: str) -> Watched:
        srv = Watched([sys.executable, "-I", os.path.join(ROOT, "devtools", "cs_testserver.py"),
                       "--port", str(port), "--key", KEY, "--ack", *extra])
        check(srv.wait_for(r"Listening on UDP") is not None, "test server up " + " ".join(extra))
        return srv

    def downlink_cycle(srv: Watched, proxy: Watched, name: str, ftype: str, fcnt: int) -> None:
        """Feed a confirmed uplink; follow it to the transmission and the TX_RESULT."""
        s0, p0 = srv.mark(), proxy.mark()
        proxy.send("uplink " + frames[name])
        check(srv.wait_for(rf"{PROXY_ID} UPLINK {ftype} fcnt {fcnt} .*test device", since=s0) is not None,
              f"{name}: UPLINK reaches the server and decrypts for the test device")
        dl = srv.wait_for(rf"{PROXY_ID} -> DOWNLINK seq (\d+) answering fcnt {fcnt} in rx1", since=s0)
        if not check(dl is not None, f"{name}: server answers with an RX1 DOWNLINK"):
            return
        seq = dl.group(1)
        tx = proxy.wait_for(r"^tx ([0-9a-f]+)$", since=p0)
        if check(tx is not None, f"{name}: the proxy transmits the downlink"):
            h, pt = cs.open_frame(session, bytes.fromhex(tx.group(1)))
            check(h.ftype == cs.T_DOWNLINK and struct.unpack(">I", pt[:4])[0] == fcnt,
                  f"{name}: transmitted frame is the device's downlink answering fcnt {fcnt}")
        res = srv.wait_for(rf"TX_RESULT seq {seq}: (\w+), (-?[\d.]+) ms after target", since=s0)
        check(res is not None and res.group(1) == "SENT" and 0 <= float(res.group(2)) <= 40,
              f"{name}: TX_RESULT SENT within 40 ms of the target (06 section 14 item 6)"
              + (f": {res.group(1)} {res.group(2)} ms" if res else ""))

    srv = start_server()
    out = out2 = ""
    proxy = Watched([BINARY, "--port", str(port), "--key", KEY, "--boot", BOOT], stdin=True)
    try:
        check(proxy.wait_for(r"^ready$") is not None, "host proxy up")

        # Boot: HELLO, HELLO_REQUEST, HELLO echoing the nonce, SERVER_STATUS.
        check(srv.wait_for(rf"{PROXY_ID} HELLO cs_proxy host, US915 918.5 MHz SF9 500 kHz.*downlink yes")
              is not None, "server logs the proxy's HELLO")
        check(proxy.wait_for(r"^connected 1$") is not None, "SERVER_STATUS connects the proxy")

        # Uplinks from the frame vectors, in counter order.
        s0 = srv.mark()
        proxy.send("uplink " + frames["join"])
        check(srv.wait_for(rf"{PROXY_ID} UPLINK JOIN fcnt 1 .*test device \(root keys", since=s0) is not None,
              "JOIN forwarded and opened under the root keys")
        downlink_cycle(srv, proxy, "heartbeat_first", "HEARTBEAT_CONFIRMED", 2)
        downlink_cycle(srv, proxy, "data_confirmed", "DATA_CONFIRMED", 3)
        s0 = srv.mark()
        proxy.send("uplink " + frames["heartbeat"])
        check(srv.wait_for(rf"{PROXY_ID} UPLINK HEARTBEAT fcnt 4 .*test device", since=s0) is not None,
              "HEARTBEAT forwarded")
        out = srv.stop()

        # Restart with the server seq from 1, far below the proxy's floor. The proxy keeps
        # running: the first UPLINK draws a HELLO_REQUEST, and the SERVER_STATUS echoing
        # its HELLO moves the floor.
        srv = start_server("--no-seq-seed")
        p0 = proxy.mark()
        stray = bytearray.fromhex(frames["data_confirmed"])
        stray[-1] ^= 1  # a fresh frame, so proxy dedupe does not hold it back
        proxy.send("uplink " + stray.hex())
        check(proxy.wait_for(r"^log Server asked for a HELLO$", since=p0) is not None,
              "restarted server answers the first UPLINK with HELLO_REQUEST")
        check(proxy.wait_for(r"^log Server restarted; following its seq from 1$", since=p0) is not None,
              "the proxy follows the restarted server's seq from 1")
        check(srv.wait_for(rf"{PROXY_ID}: session with boot {BOOT}, server seq from 1") is not None,
              "restarted server opens a session with the running proxy's boot")
        downlink_cycle(srv, proxy, "sync_after_reboot", "SYNC", 65)
        proxy.send("quit")
        check(proxy.proc.wait(timeout=5) == 0, "host proxy exits cleanly")
    finally:
        out2 = srv.stop()
        pout = proxy.stop()
    print("--- server output ---\n" + out.strip())
    print("--- restarted server output ---\n" + out2.strip())
    print("--- host proxy output ---\n" + pout.strip())
    print("all checks pass" if failures == 0 else f"{failures} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
