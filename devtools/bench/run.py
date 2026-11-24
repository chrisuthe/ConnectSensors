#!/usr/bin/env python3
"""Bench runner: drive a proxy through scenarios and assert what it does on air.

    python3 devtools/bench/run.py --simulate                  # CI: tests/host_proxy, no radio
    python3 devtools/bench/run.py --transmitter lora-test-tx.local --port 47801 --key 5a5a...

It starts devtools/cs_testserver.py with --json on --port, sends frames through a
radio, and checks the server's events and the radio's receptions:

- on the rig, the radio is the test transmitter (examples/test-transmitter-heltec-v3.yaml)
  over the ESPHome API: its send_hex action transmits, and its TX and RX timing
  text sensors give the on-air offset of every downlink (01 section 4);
- with --simulate, the radio is tests/host_proxy, the proxy engine as a host
  program, so the runner itself runs in CI.

Each run writes a record to bench/records/<date>-<commit>.json (with --simulate,
only when --record-dir is given). devtools/bench/README.md has the scenarios, the
record format and how to run a bench pass. Requires: cryptography; aioesphomeapi
on the rig.
"""

from __future__ import annotations

import argparse
import asyncio
import datetime
import json
import os
import re
import secrets
import shutil
import socket
import statistics
import struct
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "spec", "tools"))
sys.path.insert(0, os.path.join(ROOT, "devtools"))
import csframe as cs  # noqa: E402

SERVER = os.path.join(ROOT, "devtools", "cs_testserver.py")
HOST_PROXY = os.path.join(ROOT, "tests", "host_proxy", "host_proxy")
RECORD_FORMAT = 1

# 01 section 4.1, in ms after the window's delay. The proxy may start a downlink up to
# the timestamp error + its transmit window + radio start late; the sensor detects it
# `detection` later and must do so before W.
TS_ERROR_MS, TX_WINDOW_MS, RADIO_START_MS = 36, 40, 5
LATE_LIMIT_MS = TS_ERROR_MS + TX_WINDOW_MS + RADIO_START_MS
WINDOW_MS = {"US915": 150, "EU868": 200}
DETECTION_MS = {"US915": 20.7, "EU868": 82.9}
EARLY_TOLERANCE_MS = 2.0  # measurement error allowed below the delay (README: uncertainty)
DELAY_US = {"rx1": 1_000_000, "rx2": 3_000_000}
TX_RESULT_MAX_US = 40_000  # TX_RESULT SENT within 40 ms of the target (06 section 14 item 6)

BENCH_EUI = bytes.fromhex("c5c50000000000b1")  # the sensor the transmitter plays for nop-drain


class Fail(Exception):
    """A scenario cannot go on; what failed is already recorded."""


# ------------------------------------------------------------------ test server


class Server:
    """cs_testserver.py with --json: its events, collected as they arrive."""

    def __init__(self, port: int, key: bytes, extra: list[str], log_path: str):
        self.port, self.key, self.extra, self.log_path = port, key, extra, log_path
        self.events: list[dict] = []
        self.cond = threading.Condition()
        self.proc = None
        self.start()

    def start(self, more: list[str] = ()) -> None:
        log = open(self.log_path, "a")
        log.write(f"--- cs_testserver {' '.join(self.extra + list(more))}\n")
        log.flush()
        self.proc = subprocess.Popen(
            [sys.executable, "-I", SERVER, "--port", str(self.port), "--key", self.key.hex(), "--ack", "--json",
             *self.extra, *more], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log, text=True, bufsize=1)
        log.close()
        since = self.mark()
        threading.Thread(target=self._read, args=(self.proc,), daemon=True).start()
        if self.wait("LISTENING", since, 10) is None:
            raise RuntimeError(f"test server did not start; see {self.log_path}")

    def _read(self, proc) -> None:
        for line in proc.stdout:
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            with self.cond:
                self.events.append(ev)
                self.cond.notify_all()

    def mark(self) -> int:
        with self.cond:
            return len(self.events)

    def wait(self, name: str, since: int, timeout: float, **match) -> dict | None:
        """The first event called name, at or after since, whose fields include match."""
        deadline = time.monotonic() + timeout
        with self.cond:
            while True:
                for ev in self.events[since:]:
                    if ev["event"] == name and all(ev.get(k) == v for k, v in match.items()):
                        return ev
                left = deadline - time.monotonic()
                if left <= 0:
                    return None
                self.cond.wait(left)

    def find(self, name: str, since: int, **match) -> list[dict]:
        with self.cond:
            return [e for e in self.events[since:]
                    if e["event"] == name and all(e.get(k) == v for k, v in match.items())]

    def send(self, line: str) -> None:
        self.proc.stdin.write(line + "\n")
        self.proc.stdin.flush()

    def stop(self) -> None:
        if self.proc is None or self.proc.poll() is not None:
            return
        self.proc.stdin.close()
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()


# ------------------------------------------------------------------ radios


@dataclass
class Tx:
    n: int
    done_us: int  # TX done on the transmitter's clock
    ok: bool


@dataclass
class Rx:
    n: int
    at_us: int  # RX done (plus the loop delay on the rig) on the same clock
    frame: bytes
    rssi: float = 0.0
    snr: float = 0.0


class Radio:
    """Sends frames as a sensor would and hears what the proxy transmits back."""

    clock_mod: int | None = None  # the timestamps wrap at this, if anything

    def __init__(self):
        self.rx: list[Rx] = []
        self.cond = threading.Condition()

    def transmit(self, frame: bytes) -> Tx:
        raise NotImplementedError

    def burst(self, frames: list[bytes]) -> Tx:
        """Send frames back to back, as fast as the radio allows; the last one's Tx."""
        return [self.transmit(f) for f in frames][-1]

    def info(self) -> dict:
        return {}

    def close(self) -> None:
        pass

    def rx_mark(self) -> int:
        with self.cond:
            return len(self.rx)

    def wait_rx(self, frame: bytes, since: int, timeout: float) -> Rx | None:
        deadline = time.monotonic() + timeout
        with self.cond:
            while True:
                for r in self.rx[since:]:
                    if r.frame == frame:
                        return r
                left = deadline - time.monotonic()
                if left <= 0:
                    return None
                self.cond.wait(left)

    def _heard(self, r: Rx) -> None:
        with self.cond:
            self.rx.append(r)
            self.cond.notify_all()


class SimRadio(Radio):
    """tests/host_proxy: the proxy engine on the host, with a radio that completes each
    transmission after its airtime. Its clock stands in for the transmitter's: the
    uplink ends when the proxy hears it, and a downlink is received when it ends."""

    def __init__(self, port: int, key: bytes):
        super().__init__()
        if not os.path.exists(HOST_PROXY):
            raise RuntimeError(f"{HOST_PROXY} missing; run make -C tests/host_proxy")
        self.boot = secrets.randbits(32) | 1
        self.proc = subprocess.Popen([HOST_PROXY, "--port", str(port), "--key", key.hex(), "--boot",
                                      f"{self.boot:08x}"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, text=True, bufsize=1)
        self.lines: list[str] = []
        self.heard: list[int] = []
        self.n = 0
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self) -> None:
        pending: bytes | None = None
        for line in self.proc.stdout:
            line = line.rstrip("\n")
            with self.cond:
                self.lines.append(line)
                if line.startswith("heard "):
                    self.heard.append(int(line.split()[1]))
                self.cond.notify_all()
            if line.startswith("tx "):
                pending = bytes.fromhex(line[3:])
            elif line.startswith("tx_done ") and pending is not None:
                self._heard(Rx(len(self.rx) + 1, int(line.split()[1]), pending, -90.0, 7.5))
                pending = None

    def transmit(self, frame: bytes) -> Tx:
        with self.cond:
            before = len(self.heard)
        self.proc.stdin.write(f"uplink {frame.hex()}\n")
        self.proc.stdin.flush()
        deadline = time.monotonic() + 5
        with self.cond:
            while len(self.heard) == before:
                left = deadline - time.monotonic()
                if left <= 0 or self.proc.poll() is not None:
                    raise RuntimeError("host_proxy did not take the uplink")
                self.cond.wait(left)
            self.n += 1
            return Tx(self.n, self.heard[before], True)

    def info(self) -> dict:
        return {"kind": "simulated", "program": "tests/host_proxy", "boot_id": f"{self.boot:08x}"}

    def close(self) -> None:
        if self.proc.poll() is None:
            try:
                self.proc.stdin.write("quit\n")
                self.proc.stdin.flush()
                self.proc.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                self.proc.kill()


class ApiDevice:
    """An ESPHome device over its native API, on an event loop of its own so the
    scenarios can stay synchronous."""

    def __init__(self, host: str, port: int, key: str | None):
        import press
        self.loop = asyncio.new_event_loop()
        threading.Thread(target=self.loop.run_forever, daemon=True).start()
        self.press = press
        self.client = self.call(press.connect(host, port, key))
        self.entities, self.services = self.call(self.client.list_entities_services())
        self.device = self.call(self.client.device_info())
        self.states: dict[int, object] = {}
        self.on_state = None
        self.loop.call_soon_threadsafe(self.client.subscribe_states, self._state)

    def call(self, coro, timeout: float = 30):
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(timeout)

    def _state(self, st) -> None:
        self.states[st.key] = st
        if self.on_state is not None:
            self.on_state(st)

    def key_of(self, name: str) -> int | None:
        return next((e.key for e in self.entities if e.name.lower() == name.lower()), None)

    def state_of(self, substring: str):
        for e in self.entities:
            if substring.lower() in e.name.lower() and e.key in self.states:
                return getattr(self.states[e.key], "state", None)
        return None

    def info(self) -> dict:
        d = self.device
        return {k: getattr(d, k, None) for k in ("name", "esphome_version", "compilation_time", "project_name",
                                                 "project_version", "model", "mac_address")}

    def close(self) -> None:
        try:
            self.call(self.client.disconnect(), 5)
        except Exception:  # noqa: BLE001 - closing anyway
            pass
        self.loop.call_soon_threadsafe(self.loop.stop)


class RigRadio(Radio):
    """The test transmitter: send_hex, and its "TX timing" and "RX timing" text sensors
    ("<n> <tx_done_us> <len> ok|fail" and "<n> <rx_us> <rssi> <snr> <hex>")."""

    clock_mod = 1 << 32  # micros() as a uint32_t

    def __init__(self, host: str, port: int, key: str | None):
        super().__init__()
        self.dev = ApiDevice(host, port, key)
        self.tx_key, self.rx_key = self.dev.key_of("TX timing"), self.dev.key_of("RX timing")
        if self.tx_key is None or self.rx_key is None or not any(s.name == "send_hex" for s in self.dev.services):
            raise RuntimeError(f"{host}: no send_hex action or timing text sensors; flash "
                               "examples/test-transmitter-heltec-v3.yaml from this checkout")
        self.txs: list[Tx] = []
        self.rx_seen = 0
        self.tx_seen = 0
        self.dev.on_state = self._state
        time.sleep(1.0)  # the states the device sends on subscribing are history, not new events
        with self.cond:
            self.rx.clear()
            self.txs.clear()

    def _state(self, st) -> None:
        text = getattr(st, "state", "") or ""
        if st.key == self.tx_key:
            m = re.fullmatch(r"(\d+) (\d+) (\d+) (ok|fail)", text)
            if m and int(m.group(1)) != self.tx_seen:
                self.tx_seen = int(m.group(1))
                with self.cond:
                    self.txs.append(Tx(int(m.group(1)), int(m.group(2)), m.group(4) == "ok"))
                    self.cond.notify_all()
        elif st.key == self.rx_key:
            m = re.fullmatch(r"(\d+) (\d+) (\S+) (\S+) ([0-9A-Fa-f]*)", text)
            if m and int(m.group(1)) != self.rx_seen:
                self.rx_seen = int(m.group(1))
                self._heard(Rx(int(m.group(1)), int(m.group(2)), bytes.fromhex(m.group(5)), float(m.group(3)),
                               float(m.group(4))))

    def transmit(self, frame: bytes) -> Tx:
        with self.cond:
            before = len(self.txs)
        self.dev.call(self.dev.press.call_service(self.dev.client, self.dev.services, "send_hex",
                                                  {"data": frame.hex()}))
        deadline = time.monotonic() + 5
        with self.cond:
            while len(self.txs) == before:
                left = deadline - time.monotonic()
                if left <= 0:
                    raise RuntimeError("the transmitter reported no TX timing for send_hex")
                self.cond.wait(left)
            return self.txs[before]

    def burst(self, frames: list[bytes]) -> Tx:
        # Waiting for each TX report would pace the burst at the API's round trip.
        # The device batches state updates and may keep only the newest, so wait for
        # the last one's count.
        with self.cond:
            n0 = self.tx_seen
        calls = [self.dev.press.call_service(self.dev.client, self.dev.services, "send_hex", {"data": f.hex()})
                 for f in frames]

        async def all_calls():
            for c in calls:
                await c
        self.dev.call(all_calls())
        deadline = time.monotonic() + 10
        with self.cond:
            while not self.txs or self.txs[-1].n < n0 + len(frames):
                left = deadline - time.monotonic()
                if left <= 0:
                    raise RuntimeError("the transmitter did not report the whole burst")
                self.cond.wait(left)
            return self.txs[-1]

    def info(self) -> dict:
        return {"kind": "test-transmitter", **self.dev.info()}

    def close(self) -> None:
        self.dev.close()


# ------------------------------------------------------------------ scenarios


@dataclass
class Scenario:
    name: str
    checks: list[dict] = field(default_factory=list)
    measurements: list[dict] = field(default_factory=list)
    started: float = field(default_factory=time.monotonic)
    duration_s: float = 0.0

    @property
    def passed(self) -> bool:
        return all(c["ok"] for c in self.checks) and bool(self.checks)


class Bench:
    def __init__(self, args, server: Server, radio: Radio, sensor: ApiDevice | None):
        self.args, self.srv, self.radio, self.sensor = args, server, radio, sensor
        vec = cs.frame_vectors()
        self.session = cs.keys_from(bytes.fromhex(vec["derived"]["k_session"]), cs.DEV_EUI)
        self.ntag = bytes.fromhex(next(f["frame"] for f in vec["frames"] if f["name"] == "data_confirmed"))[2:10]
        self.fcnt = 100  # above every vector frame's counter
        self.sc: Scenario | None = None
        self.scenarios: list[Scenario] = []
        self.proxy: str | None = None
        self.hello: dict | None = None
        self.tx_results: list[dict] = []
        self.counters_start = self.counters_end = None
        self.started_at = datetime.datetime.now(datetime.UTC)

    # ---------------------------------------------------------- plumbing

    def check(self, cond, what: str, fatal: bool = False) -> bool:
        self.sc.checks.append({"what": what, "ok": bool(cond)})
        print(("  ok   " if cond else "  FAIL ") + what, flush=True)
        if fatal and not cond:
            raise Fail(what)
        return bool(cond)

    def fresh(self, ftype: int = cs.T_DATA_CONFIRMED) -> bytes:
        """A new frame from the test-vector device: next fcnt, a valid MIC."""
        self.fcnt += 1
        return cs.seal(self.session, ftype, self.ntag, self.fcnt, bytes([0]) + cs.encode_reading(0, 0x01, 1))

    def send(self, frame: bytes) -> Tx:
        tx = self.radio.transmit(frame)
        self.check(tx.ok, f"transmitter sent {len(frame)} bytes (fcnt {struct.unpack('>I', frame[10:14])[0]})",
                   fatal=True)
        return tx

    def on_air_offset(self, tx: Tx, rx: Rx, airtime_us: int) -> int:
        d = rx.at_us - tx.done_us
        if self.radio.clock_mod:
            d %= self.radio.clock_mod
        return d - airtime_us

    def counters(self) -> dict:
        """The proxy's counters from a HELLO it is asked for now."""
        mark = self.srv.mark()
        self.srv.send("hello")
        ev = self.srv.wait("HELLO", mark, 10, proxy=self.proxy)
        self.check(ev is not None, "proxy answers a HELLO_REQUEST with its counters", fatal=True)
        self.hello = ev
        return ev["counters"]

    def uplink(self, frame: bytes, since: int, timeout: float = 5, **match) -> dict | None:
        return self.srv.wait("UPLINK", since, timeout, frame=frame.hex(), **match)

    def answered(self, tx: Tx, frame: bytes, since: int, rx_since: int, window: str, what: str = "") -> dict | None:
        """The server answers frame, the proxy reports SENT on time, and the downlink is
        heard; records the on-air offset. Returns the DOWNLINK event."""
        fcnt = struct.unpack(">I", frame[10:14])[0]
        label = what or f"fcnt {fcnt}"
        dl = self.srv.wait("DOWNLINK", since, 5, answering=fcnt, proxy=self.proxy)
        if not self.check(dl is not None and dl["tx_offset_us"] == DELAY_US[window],
                          f"{label}: server sends a DOWNLINK for {window}"):
            return None
        res = self.srv.wait("TX_RESULT", since, DELAY_US[window] / 1e6 + 3, seq=dl["seq"], proxy=self.proxy)
        self.check(res is not None and res["result"] == "SENT" and 0 <= res["offset_us"] <= TX_RESULT_MAX_US,
                   f"{label}: TX_RESULT SENT within {TX_RESULT_MAX_US // 1000} ms of the target"
                   + (f" ({res['result']}, {res['offset_us'] / 1000:.2f} ms)" if res else " (none)"))
        frame_dl = bytes.fromhex(dl["frame"])
        rx = self.radio.wait_rx(frame_dl, rx_since, 3)
        if not self.check(rx is not None, f"{label}: the downlink is received on air"):
            return dl
        offset = self.on_air_offset(tx, rx, dl["airtime_us"])
        late_ms = (offset - DELAY_US[window]) / 1000
        region = (self.hello or {}).get("region", "US915")
        margin = WINDOW_MS.get(region, 150) - DETECTION_MS.get(region, 20.7) - late_ms
        self.sc.measurements.append({
            "window": window, "fcnt": fcnt, "seq": dl["seq"], "what": dl.get("what"), "dl_len": len(frame_dl),
            "airtime_us": dl["airtime_us"], "on_air_offset_us": offset, "late_ms": round(late_ms, 3),
            "margin_ms": round(margin, 3), "tx_result_offset_us": res["offset_us"] if res else None,
            "rssi": rx.rssi, "snr": rx.snr})
        self.check(-EARLY_TOLERANCE_MS <= late_ms <= LATE_LIMIT_MS,
                   f"{label}: on air {late_ms:+.2f} ms after {window} "
                   f"(01 section 4.1 allows 0 to {LATE_LIMIT_MS} ms; {margin:.1f} ms left in W)")
        return dl

    def not_sent(self, dl: dict, frame_dl: bytes, since: int, rx_since: int, result: str | None, label: str) -> None:
        """A faulty downlink: the proxy answers result (None: nothing) and transmits nothing.
        Only events from since count: stale-seq reuses the seq of an earlier downlink."""
        wait = dl["tx_offset_us"] / 1e6 + 1.5
        res = self.srv.wait("TX_RESULT", since, wait, seq=dl["seq"], proxy=self.proxy)
        if result is None:
            self.check(res is None, f"{label}: the proxy drops it without a TX_RESULT"
                       + (f" (got {res['result']})" if res else ""))
        else:
            self.check(res is not None and res["result"] == result,
                       f"{label}: TX_RESULT {result}" + (f" (got {res['result']})" if res else " (none)"))
        self.check(self.radio.wait_rx(frame_dl, rx_since, 0.5 if res else 0.1) is None,
                   f"{label}: nothing transmitted")

    # ---------------------------------------------------------- setup

    def connect(self) -> None:
        """Wait for the proxy's session with this server instance; prime it with an
        uplink if it does not HELLO by itself (the first uplink draws HELLO_REQUEST)."""
        since = self.srv.mark() if self.proxy else 0
        for attempt in range(4):
            ev = self.srv.wait("SESSION", since, 3 if attempt == 0 else 12,
                               **({"proxy": self.proxy} if self.proxy else {}))
            if ev is not None:
                break
            self.radio.transmit(self.fresh(cs.T_HEARTBEAT))
        self.check(ev is not None, "the proxy opens a session with the server", fatal=True)
        self.proxy = ev["proxy"]
        hello = self.srv.wait("HELLO", since, 10, proxy=self.proxy)
        self.check(hello is not None and hello["downlink"], "the proxy's HELLO offers downlinks", fatal=True)
        self.hello = hello

    # ---------------------------------------------------------- the scenarios

    def s_rx1(self) -> None:
        for _ in range(self.args.repeat):
            mark, rx0 = self.srv.mark(), self.radio.rx_mark()
            frame = self.fresh()
            tx = self.send(frame)
            ev = self.uplink(frame, mark, result="transmission", answer=True)
            self.check(ev is not None and ev["device"] == "test", "UPLINK DATA_CONFIRMED from the test device")
            self.answered(tx, frame, mark, rx0, "rx1")
            time.sleep(0.5)

    def s_rx2(self) -> None:
        mark = self.srv.mark()
        self.srv.send("window rx2")
        self.check(self.srv.wait("MODE", mark, 3, window="rx2") is not None, "server switched to RX2", fatal=True)
        try:
            for _ in range(self.args.repeat):
                mark, rx0 = self.srv.mark(), self.radio.rx_mark()
                frame = self.fresh()
                tx = self.send(frame)
                self.check(self.uplink(frame, mark, result="transmission") is not None, "UPLINK reaches the server")
                self.answered(tx, frame, mark, rx0, "rx2")
                time.sleep(0.5)
        finally:
            self.srv.send("window rx1")
            self.srv.wait("MODE", mark, 3, window="rx1")

    def s_retry(self) -> None:
        mark, rx0 = self.srv.mark(), self.radio.rx_mark()
        frame = self.fresh()
        tx = self.send(frame)
        sent = time.monotonic()  # after TX done, so the gap below is never short
        self.answered(tx, frame, mark, rx0, "rx1", "first transmission")
        # Past the proxy's 2 s dedupe and the server's 2 s copy window (07 section 4),
        # as a sensor's retry is (08 section 5).
        time.sleep(max(0.0, 2.5 - (time.monotonic() - sent)))
        mark, rx0 = self.srv.mark(), self.radio.rx_mark()
        tx = self.send(frame)
        ev = self.uplink(frame, mark)
        self.check(ev is not None and ev["counter"] == "duplicate" and ev["answer"] is True,
                   "the retry reaches the server as a duplicate counter that is answered again")
        self.answered(tx, frame, mark, rx0, "rx1", "retry")

    def s_dedupe(self) -> None:
        before = self.counters()
        mark = self.srv.mark()
        frame = self.fresh(cs.T_DATA)
        self.send(frame)
        self.send(frame)
        self.check(self.uplink(frame, mark, result="transmission") is not None, "the first copy is forwarded")
        time.sleep(1.0)
        self.check(len(self.srv.find("UPLINK", mark, frame=frame.hex())) == 1,
                   "the repeat within the dedupe window is not forwarded")
        after = self.counters()
        self.check(after["duplicates"] - before["duplicates"] == 1, "proxy counts 1 duplicate")
        self.check(after["forwarded"] - before["forwarded"] == 1, "proxy counts 1 forwarded")

    def s_rate_limit(self) -> None:
        before = self.counters()
        mark = self.srv.mark()
        frames = [self.fresh(cs.T_DATA) for _ in range(10)]
        tx = self.radio.burst(frames)
        self.check(tx.ok, f"transmitter sent a burst of {len(frames)}", fatal=True)
        time.sleep(1.5)
        got = sum(1 for f in frames if self.srv.find("UPLINK", mark, frame=f.hex()))
        self.check(5 <= got < len(frames), f"a burst of {len(frames)} is cut to the per-device burst: {got} forwarded")
        after = self.counters()
        self.check(after["rate_limited"] - before["rate_limited"] == len(frames) - got,
                   f"proxy counts {len(frames) - got} rate limited")

    def fault(self, name: str, result: str | None) -> None:
        mark = self.srv.mark()
        self.srv.send(f"fault {name}")
        self.check(self.srv.wait("MODE", mark, 3, fault=name) is not None, f"server fault {name} on", fatal=True)
        try:
            mark, rx0 = self.srv.mark(), self.radio.rx_mark()
            frame = self.fresh()
            tx = self.send(frame)
            dl = self.srv.wait("DOWNLINK", mark, 5 if name != "late" else 7, fault=name, proxy=self.proxy)
            if not self.check(dl is not None, f"server sends a {name} DOWNLINK"):
                return
            if name == "busy":
                copy = self.srv.wait("DOWNLINK", mark, 2, copy_of=dl["seq"])
                self.answered(tx, frame, mark, rx0, "rx1", "busy: the first")
                if self.check(copy is not None, "busy: the server repeats the downlink"):
                    res = self.srv.wait("TX_RESULT", mark, 3, seq=copy["seq"], proxy=self.proxy)
                    self.check(res is not None and res["result"] == "BUSY",
                               "busy: the repeat draws TX_RESULT BUSY" + (f" (got {res['result']})" if res else ""))
                return
            self.not_sent(dl, bytes.fromhex(dl["frame"]), mark, rx0, result, name)
        finally:
            mark = self.srv.mark()
            self.srv.send("fault none")
            self.srv.wait("MODE", mark, 3, fault=None)

    def s_fault_bad_mac(self) -> None:
        self.fault("bad-mac", None)

    def s_fault_stale_seq(self) -> None:
        self.fault("stale-seq", None)

    def s_fault_wrong_boot(self) -> None:
        self.fault("wrong-boot", None)

    def s_fault_uplink_frame(self) -> None:
        self.fault("uplink-frame", "INVALID")

    def s_fault_late(self) -> None:
        self.fault("late", "TOO_LATE")

    def s_fault_busy(self) -> None:
        self.fault("busy", None)

    def s_restart(self) -> None:
        """The server restarts and counts its seq from 1, below the proxy's floor: the
        next uplink draws HELLO_REQUEST and the proxy follows (05 section 3.2)."""
        self.srv.stop()
        mark = self.srv.mark()
        self.srv.start(["--no-seq-seed"])
        frame = self.fresh(cs.T_HEARTBEAT)
        self.send(frame)
        self.check(self.srv.wait("HELLO_REQUEST", mark, 5, proxy=self.proxy) is not None,
                   "restarted server answers the first uplink with HELLO_REQUEST")
        ev = self.srv.wait("SESSION", mark, 12, proxy=self.proxy)
        self.check(ev is not None and ev["seq_from"] == 1, "session with the running proxy, server seq from 1",
                   fatal=True)
        mark, rx0 = self.srv.mark(), self.radio.rx_mark()
        frame = self.fresh()
        tx = self.send(frame)
        self.answered(tx, frame, mark, rx0, "rx1", "after the restart")

    def s_nop_drain(self) -> None:
        """The transmitter plays a sensor: pairs (04 section 4.4), then drains two
        queued NOPs, PENDING on the first, acknowledged with DL_ACK (07 sections 5, 7)."""
        sensor = cs.SensorPairing(self.args.bench_root, BENCH_EUI)
        eui = BENCH_EUI.hex()

        def round_trip(frame: bytes, label: str, answered: bool = True) -> bytes | None:
            mark, rx0 = self.srv.mark(), self.radio.rx_mark()
            tx = self.send(frame)
            self.check(self.uplink(frame, mark, device=eui, result="transmission") is not None,
                       f"{label}: UPLINK from the bench sensor")
            if not answered:
                time.sleep(1.5)
                self.check(not self.srv.find("DOWNLINK", mark, device=eui), f"{label}: not answered")
                return None
            dl = self.answered(tx, frame, mark, rx0, "rx1", label)
            if dl is None:
                raise Fail(label)
            ok = sensor.downlink(bytes.fromhex(dl["frame"]))
            self.check(ok == "accept", f"{label}: the sensor accepts the downlink ({ok})", fatal=True)
            return bytes.fromhex(dl["frame"])

        ke = round_trip(sensor.join(1, secrets.token_bytes(32)), "JOIN, KEY_EXCHANGE")
        server_time = struct.unpack(">I", cs.open_frame(sensor.root, ke)[1][4:8])[0]
        mark = self.srv.mark()
        round_trip(sensor.uplink(cs.T_HEARTBEAT_CONFIRMED, 2, server_time, bytes([cs.UF_DL_ACK])),
                   "first session uplink")
        self.check(self.srv.wait("PAIRED", mark, 2, device=eui) is not None and sensor.state == "PAIRED",
                   "server and sensor PAIRED", fatal=True)
        session = cs.keys_from(sensor.k_session, BENCH_EUI)

        mark = self.srv.mark()
        self.srv.send("nop 2")
        self.check(self.srv.wait("QUEUED", mark, 3, device=eui, queued=2) is not None, "2 NOPs queued")
        nop = cs.command(cs.CMD_NOP)
        dl = round_trip(sensor.uplink(cs.T_DATA_CONFIRMED, 3, server_time, bytes([0])), "confirmed uplink")
        pt = cs.open_frame(session, dl)[1]
        self.check(pt[8] & cs.DF_PENDING and pt[9:] == nop, "first NOP, with PENDING")
        mark = self.srv.mark()
        dl = round_trip(sensor.uplink(cs.T_HEARTBEAT, 4, server_time, bytes([cs.UF_DL_ACK])),
                        "unconfirmed follow-up with DL_ACK")
        pt = cs.open_frame(session, dl)[1]
        self.check(not pt[8] & cs.DF_PENDING and pt[9:] == nop, "last NOP, without PENDING")
        self.check(self.srv.wait("ACKED", mark, 2, device=eui, queued=1) is not None, "DL_ACK settles the first NOP")
        mark = self.srv.mark()
        round_trip(sensor.uplink(cs.T_DATA, 5, server_time, bytes([cs.UF_DL_ACK])), "DL_ACK for the last",
                   answered=False)
        self.check(self.srv.wait("ACKED", mark, 2, device=eui, queued=0) is not None, "queue drained")

    def s_sensor(self) -> None:
        """A real cs_sensor (--sensor-code): its next uplink is decrypted and, if
        confirmed, answered and SENT. Open and close the door to make one."""
        eui = cs.qr_parse(self.args.sensor_code)["dev_eui"]
        undelivered = self.sensor.state_of("undelivered") if self.sensor else None
        mark = self.srv.mark()
        print(f"  ... waiting up to {self.args.sensor_wait:.0f} s for an uplink from {eui}: "
              "open or close the door, or short-press PRG, now", flush=True)
        ev = self.srv.wait("UPLINK", mark, self.args.sensor_wait, device=eui, result="transmission")
        if not self.check(ev is not None, f"UPLINK {ev['type'] if ev else ''} from the cs_sensor"):
            return
        if ev["answer"]:
            dl = self.srv.wait("DOWNLINK", mark, 5, device=eui)
            res = dl and self.srv.wait("TX_RESULT", mark, 5, seq=dl["seq"], proxy=self.proxy)
            self.check(res is not None and res["result"] == "SENT", "its answer is SENT")
            time.sleep(2)
        if self.sensor is not None and undelivered is not None:
            self.check(self.sensor.state_of("undelivered") == undelivered, "no new undelivered uplinks on the sensor")

    SCENARIOS = {
        "rx1": s_rx1, "rx2": s_rx2, "retry": s_retry, "dedupe": s_dedupe, "rate-limit": s_rate_limit,
        "fault-bad-mac": s_fault_bad_mac, "fault-stale-seq": s_fault_stale_seq,
        "fault-wrong-boot": s_fault_wrong_boot, "fault-uplink-frame": s_fault_uplink_frame,
        "fault-late": s_fault_late, "fault-busy": s_fault_busy, "nop-drain": s_nop_drain, "restart": s_restart,
        "sensor": s_sensor,
    }

    def run(self, names: list[str]) -> None:
        self.sc = Scenario("setup")
        self.scenarios.append(self.sc)
        try:
            self.connect()
            self.counters_start = self.counters()
        finally:
            self.sc.duration_s = round(time.monotonic() - self.sc.started, 1)
        tx_mark = self.srv.mark()
        for name in names:
            self.sc = Scenario(name)
            self.scenarios.append(self.sc)
            print(f"{name}:", flush=True)
            try:
                self.SCENARIOS[name](self)
            except Fail:
                pass
            except Exception as ex:  # noqa: BLE001 - one broken scenario must not end the run
                self.check(False, f"{type(ex).__name__}: {ex}")
            self.sc.duration_s = round(time.monotonic() - self.sc.started, 1)
            time.sleep(0.3)
        self.sc = Scenario("counters")
        self.scenarios.append(self.sc)
        print("counters:", flush=True)
        try:
            time.sleep(1.0)
            self.counters_end = self.counters()
            results = [e for e in self.srv.find("TX_RESULT", tx_mark) if e["proxy"] == self.proxy]
            sent = sum(1 for e in results if e["result"] == "SENT")
            d = {k: self.counters_end[k] - self.counters_start[k] for k in self.counters_end}
            self.check(d["tx_ok"] == sent, f"proxy tx_ok rose by {d['tx_ok']}, the {sent} TX_RESULT SENT")
            self.check(d["tx_failed"] == len(results) - sent,
                       f"proxy tx_failed rose by {d['tx_failed']}, the {len(results) - sent} other TX_RESULTs")
        except Fail:
            pass
        self.sc.duration_s = round(time.monotonic() - self.sc.started, 1)


# ------------------------------------------------------------------ the record


def git(*a: str) -> str:
    try:
        return subprocess.run(["git", "-C", ROOT, *a], capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return ""


def summary(values: list[float]) -> dict | None:
    if not values:
        return None
    return {"n": len(values), "min": min(values), "median": round(statistics.median(values), 3), "max": max(values)}


def record(args, bench: Bench, radio: Radio, proxy_dev: ApiDevice | None, sensor: ApiDevice | None) -> dict:
    ms = [m for s in bench.scenarios for m in s.measurements]
    hello = bench.hello or {}
    # Each HELLO carries the longest gap since the one before, so take the worst.
    gaps = [e["max_loop_gap_ms"] for e in bench.srv.find("HELLO", 0, proxy=bench.proxy)]
    return {
        "format": RECORD_FORMAT,
        "date": bench.started_at.isoformat(timespec="seconds"),
        "commit": git("rev-parse", "HEAD"),
        "dirty": bool(git("status", "--porcelain")),
        "mode": "simulated" if args.simulate else "rig",
        "region": hello.get("region"),
        "server": {"port": args.port},
        "transmitter": radio.info(),
        "proxy": {"proxy_id": bench.proxy, "fw": hello.get("fw"), "max_loop_gap_ms": max(gaps, default=None),
                  "api": proxy_dev.info() if proxy_dev else None},
        "sensor": ({"code_dev_eui": cs.qr_parse(args.sensor_code)["dev_eui"] if args.sensor_code else None,
                    "api": sensor.info() if sensor else None} if args.sensor_code or sensor else None),
        "esphome_version": (radio.info().get("esphome_version")
                            or (proxy_dev.info().get("esphome_version") if proxy_dev else None)),
        "counters": {"start": bench.counters_start, "end": bench.counters_end},
        "scenarios": [{"name": s.name, "passed": s.passed, "duration_s": s.duration_s, "checks": s.checks,
                       "measurements": s.measurements} for s in bench.scenarios],
        "summary": {
            "passed": sum(s.passed for s in bench.scenarios), "failed": sum(not s.passed for s in bench.scenarios),
            "rx1_late_ms": summary([m["late_ms"] for m in ms if m["window"] == "rx1"]),
            "rx2_late_ms": summary([m["late_ms"] for m in ms if m["window"] == "rx2"]),
        },
    }


def write_record(rec: dict, directory: str) -> str:
    os.makedirs(directory, exist_ok=True)
    stem = f"{rec['date'][:10]}-{(rec['commit'] or 'nocommit')[:10]}"
    path = os.path.join(directory, stem + ".json")
    if os.path.exists(path):
        path = os.path.join(directory, f"{stem}-{rec['date'][11:19].replace(':', '')}.json")
    with open(path, "w") as f:
        json.dump(rec, f, indent=1)
        f.write("\n")
    return path


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("", 0))
        return probe.getsockname()[1]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--simulate", action="store_true", help="tests/host_proxy instead of the rig (CI)")
    ap.add_argument("--transmitter", metavar="HOST", help="the test transmitter's address (rig)")
    ap.add_argument("--api-port", type=int, default=6053, help="ESPHome API port of every device")
    ap.add_argument("--api-key", help="API encryption key of the transmitter, if any")
    ap.add_argument("--proxy", metavar="HOST", help="the cs_proxy's address, only to record its versions")
    ap.add_argument("--proxy-api-key")
    ap.add_argument("--sensor", metavar="HOST", help="a cs_sensor's address, to record it and watch its counters")
    ap.add_argument("--sensor-api-key")
    ap.add_argument("--sensor-code", metavar="CS:1:...", help="the cs_sensor's pairing code: adds the sensor scenario")
    ap.add_argument("--sensor-wait", type=float, default=120, help="seconds to wait for the cs_sensor's uplink")
    ap.add_argument("--state", metavar="FILE", help="the test server's --state file, kept across runs, so a "
                                                    "cs_sensor paired with the bench server stays paired")
    ap.add_argument("--port", type=int, help="UDP port for the test server, as in the proxy's server: config "
                                             "(default 47800; free one with --simulate)")
    ap.add_argument("--key", help="the proxy's key, 32 hex digits (default with --simulate: a fresh one)")
    ap.add_argument("--scenarios", help="comma-separated subset, in the order given (default: all)")
    ap.add_argument("--repeat", type=int, default=3, help="downlinks measured per window (default 3)")
    ap.add_argument("--record-dir", help="where the run record goes (default bench/records; none with --simulate)")
    ap.add_argument("--no-record", action="store_true", help="write no record")
    args = ap.parse_args()

    if args.simulate == bool(args.transmitter):
        ap.error("give --simulate or --transmitter HOST")
    if args.port is None:
        args.port = free_port() if args.simulate else 47800
    if not args.key and not args.simulate:
        ap.error("--key: the proxy's key (cs_proxy_key in its secrets.yaml)")
    key = bytes.fromhex(args.key) if args.key else secrets.token_bytes(16)
    names = [n for n in Bench.SCENARIOS if n != "sensor" or args.sensor_code]
    if args.scenarios:
        names = [n.strip() for n in args.scenarios.split(",") if n.strip()]
        bad = [n for n in names if n not in Bench.SCENARIOS]
        if bad:
            ap.error(f"unknown scenario(s) {', '.join(bad)}; known: {', '.join(Bench.SCENARIOS)}")
        if "sensor" in names and not args.sensor_code:
            ap.error("the sensor scenario needs --sensor-code")
    if args.simulate and "sensor" in names:
        ap.error("the sensor scenario needs the rig")
    args.bench_root = secrets.token_bytes(16)
    record_dir = None if args.no_record else args.record_dir or (None if args.simulate else
                                                                 os.path.join(ROOT, "bench", "records"))

    tmp = tempfile.mkdtemp(prefix="cs-bench-")
    log_path = os.path.join(tmp, "server.log")
    extra = ["--device", f"{BENCH_EUI.hex()}:{args.bench_root.hex()}",
             "--state", args.state or os.path.join(tmp, "state.json")]
    if args.sensor_code:
        extra += ["--device", args.sensor_code]
    print(f"bench: test server on UDP {args.port}, log {log_path}", flush=True)
    server = Server(args.port, key, extra, log_path)
    radio = proxy_dev = sensor = None
    try:
        if args.simulate:
            radio = SimRadio(args.port, key)
        else:
            try:
                radio = RigRadio(args.transmitter, args.api_port, args.api_key)
            except ImportError:
                print("the rig needs aioesphomeapi: pip install aioesphomeapi", file=sys.stderr)
                return 2
            if args.proxy:
                proxy_dev = ApiDevice(args.proxy, args.api_port, args.proxy_api_key)
            if args.sensor:
                sensor = ApiDevice(args.sensor, args.api_port, args.sensor_api_key)
        bench = Bench(args, server, radio, sensor)
        try:
            bench.run(names)
        except Fail:
            pass
        rec = record(args, bench, radio, proxy_dev, sensor)
    finally:
        server.stop()
        for d in (radio, proxy_dev, sensor):
            if d is not None:
                d.close()

    s = rec["summary"]
    for w in ("rx1", "rx2"):
        if s[f"{w}_late_ms"]:
            v = s[f"{w}_late_ms"]
            print(f"{w} on air, ms after the delay: min {v['min']:+.2f} median {v['median']:+.2f} "
                  f"max {v['max']:+.2f} (n={v['n']})")
    gap = rec["proxy"]["max_loop_gap_ms"]
    if gap is not None and gap > 30:
        print(f"note: the proxy's longest loop gap is {gap} ms; turn its logging down for timing runs")
    if record_dir:
        print("record:", write_record(rec, record_dir))
    failed = [x["name"] for x in rec["scenarios"] if not x["passed"]]
    print(f"{s['passed']} scenarios passed, {s['failed']} failed" + (f": {', '.join(failed)}" if failed else ""))
    if failed:
        print(f"server log: {log_path}")
    else:
        shutil.rmtree(tmp, ignore_errors=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
