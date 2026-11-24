#!/usr/bin/env python3
"""ConnectSensors development server for testing proxies and sensors.

Not the real network server. It speaks the proxy envelope (spec 05) to any
number of proxies sharing one key, prints what they hear, decrypts frames from
the test-vector device (spec/vectors/frame-v1.json), and with --ack answers
confirmed uplinks from that device with a real downlink in RX1. Copies of one
transmission are answered once; a sensor's retry is answered again (07 section 4).

Real sensors registered with --device are paired when their pairing button is
pressed (04 section 4.4: JOIN, KEY_EXCHANGE, then the first session uplink, which
marks the device PAIRED and is answered), and from then on their uplinks are
decrypted and their confirmed ones answered, with or without --ack. They are
found through a tag table (07 section 3); a JOIN, or a SYNC past the table's
blocks, falls back to trial decryption, at most 50 a minute (07 section 4).

--json prints one JSON object per event on stdout (HELLO, UPLINK, DOWNLINK,
TX_RESULT, PAIRED and so on; see devtools/bench/README.md) and moves the human
log to stderr. --fault makes every downlink the server answers with faulty, so a
proxy's checks can be tested on the bench: bad-mac, stale-seq and wrong-boot must
be dropped silently, uplink-frame draws INVALID, late draws TOO_LATE, and busy
sends a second copy that draws BUSY. On stdin, `window rx1|rx2`, `fault NAME|none`
and `hello` (ask every proxy for a HELLO, to read its counters) change these at run time.

--queue-nop N, or typing `nop [N]` on stdin, queues NOP commands for every paired
--device. They go out one per downlink, so PENDING stays set while more remain
and the sensor's follow-up heartbeats (08 section 7) drain the queue. A command
stays queued until an uplink acknowledges it with DL_ACK (07 section 7). With
--window rx1 the server answers an unconfirmed uplink while commands are queued;
with --window rx2 it cannot (07 section 6.3), so only confirmed follow-ups drain it.

Development only: every proxy uses the one --key. Spec 05 section 4.2 requires a
key of its own for each proxy that accepts downlinks, so sending downlinks to more
than one proxy under this key is not compliant; anyone holding it can make all of
them transmit. The server logs a warning when that happens.

    python3 devtools/cs_testserver.py                 # prints a fresh key
    python3 devtools/cs_testserver.py --key 5a5a...   # use a key you already set
    python3 devtools/cs_testserver.py --ack           # also exercise downlinks
    python3 devtools/cs_testserver.py --no-seq-seed   # server seq from 1, as after a real restart
    python3 devtools/cs_testserver.py --device CS:1:...              # a sensor, by pairing code
    python3 devtools/cs_testserver.py --device DEV_EUI:K_ROOT        # or by hex dev_eui and root key
    python3 devtools/cs_testserver.py --device ... --state pairings.json  # keep sessions across restarts
    python3 devtools/cs_testserver.py --device ... --window rx2 --queue-nop 3  # exercise PENDING
    python3 devtools/cs_testserver.py --ack --json --fault late        # events as JSON, late downlinks

Federation (spec 09) through one or more cs-mailbox servers (mailbox/), as a home
that owns its --device sensors and, with --publish, shares its proxies' coverage:

    python3 devtools/cs_testserver.py --device ... --mailbox wss://mailbox.example/      # owner
    python3 devtools/cs_testserver.py --mailbox wss://... --publish --federated-downlinks  # publisher

As owner it registers its devices' tags (normal epochs e-1 to e+2, and SYNC
windows), takes their frames from neighbors' proxies into the normal uplink path
(logged as [federated]), and requests RX2 answers by the timing rule of 09
section 7.6. As publisher it publishes frames no device of its own verified
(never JOIN), and transmits forwarded downlinks through its proxies.

Requires: cryptography (pip install cryptography); websockets for --mailbox
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import secrets
import socket
import sys
import time

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
SPEC = os.path.normpath(os.path.join(HERE, "..", "spec"))
sys.path.insert(0, os.path.join(SPEC, "tools"))
import csframe as cs  # noqa: E402

TYPE_NAMES = {0x1: "DATA", 0x2: "DATA_CONFIRMED", 0x3: "HEARTBEAT", 0x4: "HEARTBEAT_CONFIRMED",
              0x5: "JOIN", 0x6: "SYNC", 0x8: "DOWNLINK"}
CONFIRMED = {0x2, 0x4, 0x6}  # JOIN needs a key exchange; not answered here
TX_RESULTS = {0: "SENT", 1: "TOO_LATE", 2: "BUSY", 3: "DUTY_CYCLE", 4: "NOT_CAPABLE", 5: "INVALID",
              6: "RADIO_ERROR"}
FAULTS = ("bad-mac", "stale-seq", "wrong-boot", "uplink-frame", "late", "busy")
TX_WINDOW_US = 40_000  # the proxy's late tolerance (01 section 4)

LOG_STREAM = sys.stdout  # stderr with --json, so stdout carries only events
JSON_EVENTS = False


def log(msg: str) -> None:
    print(time.strftime("%H:%M:%S ") + msg, file=LOG_STREAM, flush=True)


def emit(event: str, **fields) -> None:
    """One --json event: {"event": ..., "t": unix time, ...fields}."""
    if JSON_EVENTS:
        print(json.dumps({"event": event, "t": round(time.time(), 3), **fields}), flush=True)


class TestDevice:
    """The device from the frame test vectors, with root and session keys."""

    def __init__(self):
        with open(os.path.join(SPEC, "vectors", "frame-v1.json")) as f:
            v = json.load(f)
        i = v["inputs"]
        self.dev_eui = bytes.fromhex(i["dev_eui"])
        k_root = bytes.fromhex(i["k_root"])
        self.root = cs.keys_from(k_root, self.dev_eui)
        self.session = cs.keys_from(bytes.fromhex(v["derived"]["k_session"]), self.dev_eui)
        self.fcnt_down = 1000  # above every downlink counter used in the vectors
        self.uplinks = cs.UplinkCollector(0)

    def open(self, frame: bytes):
        for name, keys in (("session", self.session), ("root", self.root)):
            try:
                h, pt = cs.open_frame(keys, frame)
                return name, keys, h, pt
            except Exception:
                continue
        return None


def seq_seed() -> int:
    """First server seq for a proxy session, minus one.

    The proxy follows a restarted server through the SERVER_STATUS echo (05 section
    3.2), so this isn't needed. It stays as extra protection: starting above the old
    instance's values closes the window in which the old instance's messages pass the
    proxy's check again (05 section 7), as long as that instance sent fewer messages
    to the proxy than seconds have passed since it started.
    """
    return int(time.time()) & 0xFFFFFFFF


def root_counter_seed() -> int:
    """First root downlink counter, minus one, when nothing is stored.

    A sensor keeps its root floor through pairing and re-pairing (02 section 8.4),
    so a server that forgot its counter must still start above every value it used
    before. Seconds since the epoch do that while it sends fewer than one
    KEY_EXCHANGE a second.
    """
    return int(time.time())


def parse_device(spec: str) -> tuple[bytes, bytes]:
    """--device: a CS:1:... pairing code, or DEV_EUI:K_ROOT in hex."""
    if spec.strip().upper().startswith("CS:"):
        code = cs.qr_parse(spec)
        return bytes.fromhex(code["dev_eui"]), bytes.fromhex(code["k_root"])
    parts = spec.split(":")
    if len(parts) != 2:
        raise ValueError("expected CS:1:... or DEV_EUI:K_ROOT")
    dev_eui, k_root = bytes.fromhex(parts[0]), bytes.fromhex(parts[1])
    if len(dev_eui) != 8 or len(k_root) != 16:
        raise ValueError("DEV_EUI is 16 hex digits and K_ROOT 32")
    return dev_eui, k_root


class RealDevice:
    """A sensor registered with --device: SCANNED, EXCHANGED or PAIRED (04 section 4.2).

    The pending exchange and the root counter come from csframe's JoinResponder. The
    10-minute and 2-minute timeouts of 04 section 4.2 are not modelled.
    """

    def __init__(self, dev_eui: bytes, k_root: bytes):
        self.dev_eui = dev_eui
        self.root = cs.keys_from(k_root, dev_eui)
        self.join = cs.JoinResponder(k_root, dev_eui, root_counter_seed())
        self.state = "SCANNED"
        self.k_session = None
        self.session = None
        self.fcnt_down = 0  # session downlink counter, from 1 with each k_session
        self.uplinks = cs.UplinkCollector(0)
        self.last_seen: int | None = None  # Unix time of the newest accepted uplink, for SYNC windows
        # Queued commands, each (serial, bytes) so equal NOPs stay distinct; not persisted.
        self.queue: list[tuple[int, bytes]] = []
        self.acks: cs.CommandAcks[tuple[int, bytes]] = cs.CommandAcks()
        self.serial = 0

    def queue_nops(self, n: int) -> None:
        for _ in range(n):
            self.serial += 1
            self.queue.append((self.serial, cs.command(cs.CMD_NOP)))

    def to_json(self) -> dict:
        return {"root_fcnt_down": self.join.root_fcnt_down, "state": self.state,
                "k_session": self.k_session.hex() if self.k_session else None,
                "fcnt_down": self.fcnt_down, "fcnt_up": self.uplinks.counter.last, "last_seen": self.last_seen}

    def load_json(self, d: dict) -> None:
        self.join.root_fcnt_down = max(self.join.root_fcnt_down, d["root_fcnt_down"])
        if d.get("k_session"):
            self.set_session(bytes.fromhex(d["k_session"]), d["state"])
            self.fcnt_down = d["fcnt_down"]
            self.uplinks = cs.UplinkCollector(d["fcnt_up"])
            self.last_seen = d.get("last_seen")

    def set_session(self, k_session: bytes, state: str) -> None:
        self.k_session = k_session
        self.session = cs.keys_from(k_session, self.dev_eui)
        self.state = state

    def open(self, frame: bytes, h) -> tuple[str, cs.DeviceKeys, bytes] | None:
        """Try this device's keys on a frame: JOIN under the root key set,
        everything else under the session key set. A JOIN is tried even when
        PAIRED, as if the code had been scanned again (04 section 4.4, step 1)."""
        if h.ftype == cs.T_JOIN:
            tries = [("root", self.root)]
        else:
            tries = [("session", self.session)] if self.session is not None else []
        for name, keys in tries:
            try:
                _, pt = cs.open_frame(keys, frame)
                return name, keys, pt
            except ValueError:
                continue
        return None


BOOTSTRAP_PER_MINUTE = 50  # trial decryptions of bootstrap frames (07 section 4, step 4)


class Devices:
    """The --device sensors and their tag table (07 section 3)."""

    def __init__(self, devices: list[RealDevice]):
        self.devices = {d.dev_eui.hex(): d for d in devices}
        self.table = cs.TagTable()
        self.epoch: int | None = None
        self.blocks: dict[str, int] = {}
        self.fallbacks: list[float] = []

    def refresh(self, now: int, dev: RealDevice | None = None) -> None:
        """Rebuild entries at an epoch change, or one device's after its keys or
        its counter block changed."""
        epoch = cs.epoch_of(now)
        todo = list(self.devices.values()) if epoch != self.epoch else [dev] if dev else []
        self.epoch = epoch
        for d in todo:
            eui = d.dev_eui.hex()
            if d.session is None:
                self.table.remove(eui)
                self.blocks.pop(eui, None)
                continue
            last = d.uplinks.counter.last
            self.table.update(eui, d.session.k_dev_tag, epoch, last)
            self.blocks[eui] = (max(last, 1) - 1) // cs.TAG_BLOCK

    def moved(self, dev: RealDevice) -> bool:
        """The device's last_fcnt moved into a new block."""
        return self.blocks.get(dev.dev_eui.hex()) != (max(dev.uplinks.counter.last, 1) - 1) // cs.TAG_BLOCK

    def identify(self, frame: bytes, h, federated: bool = False
                 ) -> tuple[RealDevice, str, cs.DeviceKeys, bytes, str] | None:
        """A federated frame is identified by table lookup only (07 section 4.4)."""
        route, candidates = cs.identify_route(self.table, frame, local=not federated)
        if route == "table":
            tries = [self.devices[c] for c in candidates]
        elif route == "fallback":
            if not self._fallback_allowed():
                return None
            tries = list(self.devices.values())
        else:
            return None
        for dev in tries:
            opened = dev.open(frame, h)
            if opened is not None:
                return (dev, *opened, route)
        if route == "table" and not federated and cs.is_bootstrap(h.ftype) and self._fallback_allowed():
            # A colliding entry: still a bootstrap frame nobody verified (07 section 4).
            for dev in self.devices.values():
                if dev not in tries:
                    opened = dev.open(frame, h)
                    if opened is not None:
                        return (dev, *opened, "fallback")
        return None

    def _fallback_allowed(self) -> bool:
        t = time.monotonic()
        self.fallbacks = [x for x in self.fallbacks if t - x < 60]
        if len(self.fallbacks) >= BOOTSTRAP_PER_MINUTE:
            return False
        self.fallbacks.append(t)
        return True


class Proxy:
    def __init__(self, proxy_id: bytes):
        self.proxy_id = proxy_id
        self.link = cs.ServerLink(lambda: int.from_bytes(secrets.token_bytes(4), "big") or 1)
        self.addr = None
        self.hello: dict | None = None
        self.hello_at = 0.0
        self.status_seq = 0  # the last SERVER_STATUS seq, which the proxy holds: --fault stale-seq replays it


def describe_payload(ftype: int, pt: bytes) -> str:
    if ftype == cs.T_JOIN:
        return f"uflags={pt[0]:02x} sensor_pub={pt[1:].hex()[:16]}..."
    flags = pt[0]
    try:
        readings = cs.decode_readings(pt[1:])
        text = ", ".join(f"ch{r['channel']} {r['name']}={r['value']}" for r in readings)
    except ValueError as ex:
        text = f"invalid readings ({ex})"
    names = [n for b, n in ((cs.UF_DL_ACK, "DL_ACK"), (cs.UF_TIME_UNSURE, "TIME_UNSURE")) if flags & b]
    return f"[{' '.join(names) or 'no flags'}] {text or 'no readings'}"


# ------------------------------------------------------------------ federation (09)

MB_SUBPROTOCOL = "cs-mailbox.1"
PING_EVERY_S = 30            # 09 section 12.5
COLLECT_MS = 150             # collection window (07 section 4.1)
PUBLISH_PER_S = 5            # 09 section 6.1, per server
FED_DOWNLINKS_PER_MIN = 10   # 09 section 7.4
HEARTBEAT_MINUTES = 60       # assumed h for SYNC windows; the device profile is not modelled
SYNC_REG_S = 86400           # SYNC registrations, renewed each epoch while in the window
RENEW_BEFORE_S = cs.EPOCH_SECONDS
FED_BOOTSTRAP_PER_MINUTE = 50  # federated SYNC limiter (07 section 4.4)
QUOTA_HALF_LIFE_S = 3600
TX_RESULT_WAIT_S = 5         # RX2 at 3 s, plus airtime and margin
RADIO_ERROR = 6              # 05 section 5.5


def error_name(code: int) -> str:
    return cs.MB_ERRORS[code] if code < len(cs.MB_ERRORS) else str(code)


class MailboxLink:
    """One client connection to a mailbox server: the handshake of 09 section 12.3,
    signed messages with seq (12.4), and replies to ping_s. Messages it does not
    handle itself are returned by recv()."""

    def __init__(self, url: str, seed: bytes, cafile: str | None = None, insecure: bool = False,
                 **connect_args: object):
        """connect_args go to websockets' connect, e.g. additional_headers or local_addr in tests."""
        from urllib.parse import urlsplit
        self.url, self.seed = url, seed
        self.connect_args = connect_args
        self.pub = cs.ed25519_pub(seed)
        parts = urlsplit(url)
        if parts.scheme not in ("wss", "ws") or not parts.hostname:
            raise ValueError(f"{url}: expected wss://host[:port]/...")
        if parts.scheme == "ws" and not insecure:
            raise ValueError(f"{url}: plain ws:// needs --insecure-dev (09 section 12.1 requires TLS)")
        self.host = parts.hostname.encode("idna").decode("ascii").lower()
        self.cafile = cafile
        self.ws = None
        self.server_id = self.server_pub = self.nonce_s = self.pseudonym = b""
        self.generation = 0
        self.seq = 0
        self.rtt_ms: int | None = None
        self.pings: dict[int, float] = {}

    async def connect(self) -> None:
        import ssl

        from websockets.asyncio.client import connect
        tls = None
        if self.url.startswith("wss:"):
            tls = ssl.create_default_context(cafile=self.cafile)
            tls.minimum_version = ssl.TLSVersion.TLSv1_3
        self.ws = await connect(self.url, ssl=tls, subprotocols=[MB_SUBPROTOCOL], max_size=cs.MB_MAX_MESSAGE,
                                compression=None, open_timeout=10, **self.connect_args)
        nonce_c = secrets.token_bytes(16)
        await self.ws.send(cs.cbor([cs.MB_HELLO, cs.MB_VERSION, nonce_c]))
        g = cs.mb_decode(await self.ws.recv())
        if g[0] == cs.MB_ERROR:
            raise ConnectionError(f"refused: {error_name(g[2])}")
        if (g[0] != cs.MB_GREETING or g[1] != cs.MB_VERSION or g[3] != cs.server_id_of(g[2])
                or cs.ed_verify_error(g[2], cs.greeting_msg(self.host, nonce_c, g[5], g[4]), g[6])):
            await self.ws.close()
            raise ConnectionError("bad greeting")
        _, _, self.server_pub, self.server_id, self.generation, self.nonce_s, _ = g
        sig = cs.ed_sign(self.seed, cs.auth_msg(self.server_id, nonce_c, self.nonce_s, self.pub))
        await self.ws.send(cs.cbor([cs.MB_AUTH, self.pub, sig]))
        w = cs.mb_decode(await self.ws.recv())
        if w[0] != cs.MB_WELCOME:
            raise ConnectionError(f"refused: {error_name(w[2]) if w[0] == cs.MB_ERROR else w}")
        self.pseudonym = w[1]
        self.seq = 0

    async def send(self, m: list) -> int:
        """Sign and send m (its type and fields, without seq or sig); returns its seq."""
        self.seq += 1
        await self.ws.send(cs.signed(self.seed, self.server_id, self.nonce_s, [m[0], self.seq, *m[1:]]))
        return self.seq

    async def ping(self) -> None:
        seq = self.seq + 1
        self.pings[seq] = time.monotonic()
        await self.send([cs.MB_PING])

    async def recv(self) -> list:
        """The next server message other than pong_s and ping_s, which are handled here.
        Messages of unknown type are skipped (09 section 12.5)."""
        while True:
            data = await self.ws.recv()
            if isinstance(data, bytes) and data[:1] and data[0] >> 5 == 4:  # an array: look at its type first
                try:
                    v = cs.uncbor(data)
                except ValueError:
                    v = None
                if isinstance(v, list) and v and type(v[0]) is int and v[0] not in cs.MB_SCHEMA:
                    continue
            m = cs.mb_decode(data)
            if m[0] == cs.MB_PING_S:
                await self.send([cs.MB_PONG, m[1]])
            elif m[0] == cs.MB_PONG_S:
                sent = self.pings.pop(m[1], None)
                if sent is not None:
                    self.rtt_ms = int((time.monotonic() - sent) * 1000)
            else:
                return m

    async def close(self) -> None:
        if self.ws is not None:
            await self.ws.close()


class Issued:
    """An rx_ref this home published (09 section 6.2), kept 5 seconds."""

    def __init__(self, pid: bytes, rx_time: int, txn: dict, downlink: bool):
        self.pid, self.rx_time, self.txn, self.downlink = pid, rx_time, txn, downlink
        self.at = time.monotonic()
        self.used = False


class FedServer:
    """This home on one mailbox server: owner and publisher on one key."""

    def __init__(self, url: str, seed: bytes):
        self.url, self.seed = url, seed
        self.link: MailboxLink | None = None
        self.up = False
        self.registered: dict[bytes, tuple[str, bytes, int]] = {}  # tag -> (device, k_session, expires)
        self.pending: dict[int, tuple] = {}  # seq -> what it was, for registered and error
        self.issued: dict[bytes, Issued] = {}
        self.published: list[float] = []
        self.quota: dict[bytes, tuple[float, float]] = {}  # requester -> (decayed airtime ms, at)


class Federation:
    """Owner and publisher of 09 for cs_testserver: registers the paired devices'
    tags, publishes frames none of them verified, takes deliveries into the uplink
    path, requests RX2 answers, and answers forwarded requests through its proxies."""

    def __init__(self, args, stored: dict, save_state, devices: Devices):
        self.args, self.stored, self.save_state, self.devices = args, stored, save_state, devices
        keys = stored.setdefault("_mailbox", {})
        self.servers = []
        for url in args.mailbox:
            k = keys.setdefault(url, {})
            if "client_seed" not in k:  # one key per server, kept while the home uses it (09 section 2.3)
                k["client_seed"] = secrets.token_bytes(32).hex()
            self.servers.append(FedServer(url, bytes.fromhex(k["client_seed"])))
        save_state()
        self.publish_pending: dict[bytes, dict] = {}  # frame key -> transmission being collected
        self.recent: dict[bytes, dict] = {}  # frame key -> last published transmission
        self.owner_pending: dict[bytes, dict] = {}  # frame key -> transmission an answer is being chosen for
        self.frequency: int | None = None
        self.last_publisher: dict[str, bytes] = {}  # device -> publisher of its last request
        self.fed_bootstrap: list[float] = []
        self.fed_downlinks: list[float] = []
        self.proxy_airtime: dict[bytes, list[tuple[float, float]]] = {}  # pid -> (at, ms), federated
        self.local_tx: dict[bytes, list[tuple[int, int]]] = {}  # pid -> (proxy-clock start, end) of own downlinks
        self.dl_map: dict[tuple[bytes, int], tuple[FedServer, bytes]] = {}  # (pid, seq) -> (server, rx_ref)
        self.send_downlink = None   # set by main: (pid, ref_rx_time_us, offset_us, frame) -> seq or None
        self.proxy_info = None      # set by main: pid -> Proxy or None
        self.deliver_handler = None  # set by main: (server, frame, h, receptions, publisher, rtt, arrived) -> answer

    # -------------------------------------------------------------- connections

    async def run(self) -> None:
        await asyncio.gather(*(self.keep(s) for s in self.servers), self.ticker())

    async def keep(self, s: FedServer) -> None:
        backoff = 1.0
        while True:
            try:
                s.link = MailboxLink(s.url, s.seed, self.args.mailbox_ca, self.args.insecure_dev)
                await s.link.connect()
                backoff = 1.0
                await self.connected(s)
                pinger = asyncio.create_task(self.pinger(s))
                try:
                    while True:
                        await self.on_message(s, await s.link.recv())
                finally:
                    pinger.cancel()
            except asyncio.CancelledError:
                raise
            except Exception as ex:  # noqa: BLE001 - any failure: log, reconnect
                log(f"mailbox {s.url}: {type(ex).__name__}: {ex}; reconnecting in {backoff:.0f} s")
            s.up = False
            await asyncio.sleep(backoff)
            backoff = min(60.0, backoff * 2)

    async def connected(self, s: FedServer) -> None:
        link = s.link
        k = self.stored["_mailbox"][s.url]
        note = ""
        if k.get("server_id") not in (None, link.server_id.hex()):
            note = " (server_id changed: treating it as a new server)"
        elif k.get("generation") not in (None, link.generation):
            note = " (generation changed: re-registering)"
        k["server_id"], k["generation"] = link.server_id.hex(), link.generation
        self.save_state()
        log(f"mailbox {s.url}: welcome as {link.pseudonym.hex()}, server_id {link.server_id.hex()[:16]}, "
            f"generation {link.generation:016x}{note}")
        s.up = True
        s.registered.clear()  # every live tag again on each connection; cheap, and covers a new generation
        s.issued.clear()
        s.pending.clear()  # seq starts again at 1
        await s.link.ping()
        await self.register(s)

    async def pinger(self, s: FedServer) -> None:
        while True:
            await asyncio.sleep(PING_EVERY_S)
            await s.link.ping()

    async def ticker(self) -> None:
        """Top up registrations each epoch and as SYNC windows move (09 sections 5.3, 5.5)."""
        while True:
            await asyncio.sleep(30)
            await self.refresh()

    async def refresh(self) -> None:
        for s in self.servers:
            if s.up:
                await self.register(s)

    # -------------------------------------------------------------- owner: registration

    def wanted(self, now: int) -> dict[bytes, tuple[bytes, int, str, bytes]]:
        """tag -> (seed, expires, device, k_session) for every tag this home keeps registered."""
        out = {}
        e = cs.epoch_of(now)
        for eui, dev in self.devices.devices.items():
            if dev.session is None:
                continue
            k = dev.session.k_dev_tag
            for x in range(e - 1, e + 3):  # normal tags, e - 1 to e + 2
                seed = cs.tag_seed(k, cs.epoch_index(x))
                out[cs.tag_of_pub(cs.ed25519_pub(seed))] = (seed, cs.EPOCH_SECONDS * (x + 2), eui, dev.k_session)
            last = max(dev.uplinks.counter.last, 1)
            silence = max(0, now - (dev.last_seen or now))
            first, end = cs.sync_window(last, silence, HEARTBEAT_MINUTES)
            for n in range(first, end + 1):
                seed = cs.tag_seed(k, cs.block_index(n * cs.TAG_BLOCK + 1))
                out[cs.tag_of_pub(cs.ed25519_pub(seed))] = (seed, now + SYNC_REG_S, eui, dev.k_session)
        return out

    async def register(self, s: FedServer) -> None:
        now = int(time.time())
        want = self.wanted(now)
        stale = [t for t, (eui, ks, _) in s.registered.items()
                 if t not in want and (eui not in self.devices.devices or self.devices.devices[eui].k_session != ks)]
        for t, (_, _, exp) in list(s.registered.items()):
            if exp <= now:
                del s.registered[t]
        if stale:  # a removed or re-paired device (09 section 5.3)
            for i in range(0, len(stale), 256):
                await s.link.send([cs.MB_WITHDRAW, stale[i:i + 256]])
            for t in stale:
                del s.registered[t]
            log(f"mailbox {s.url}: withdrew {len(stale)} tags of old sessions")
        todo = [(t, v) for t, v in want.items()
                if t not in s.registered or s.registered[t][2] - now < RENEW_BEFORE_S and v[1] > s.registered[t][2]]
        for i in range(0, len(todo), 32):
            chunk = todo[i:i + 32]
            entries = [cs.reg_entry(seed, s.link.server_id, s.link.pub, exp) for _, (seed, exp, _, _) in chunk]
            seq = await s.link.send([cs.MB_REGISTER, entries])
            s.pending[seq] = ("register", [(t, (eui, ks, exp)) for t, (_, exp, eui, ks) in chunk])
            for t, (_, exp, eui, ks) in chunk:
                s.registered[t] = (eui, ks, exp)

    # -------------------------------------------------------------- messages

    async def on_message(self, s: FedServer, m: list) -> None:
        if m[0] == cs.MB_REGISTERED:
            what = s.pending.pop(m[1], None)
            if what is None:
                return
            names = [error_name(c) for c in m[2]]
            for (t, _), name in zip(what[1], names):
                if name != "OK":
                    s.registered.pop(t, None)
            log(f"mailbox {s.url}: registered {len(names)} tags: "
                + ", ".join(f"{n} x{names.count(n)}" for n in sorted(set(names))))
        elif m[0] == cs.MB_DELIVER:
            await self.on_deliver(s, m)
        elif m[0] == cs.MB_FORWARD:
            await self.on_forward(s, m[1], m[2], m[3])
        elif m[0] == cs.MB_RESULT_S:
            await self.on_result(s, m[1], m[2], m[3])
        elif m[0] == cs.MB_ERROR:
            what = s.pending.pop(m[1], None)
            name = error_name(m[2])
            log(f"mailbox {s.url}: error {name} for seq {m[1]}" + (f" ({what[0]})" if what else ""))
            if what and what[0] == "register":  # refused whole: none of its tags is registered
                for t, _ in what[1]:
                    s.registered.pop(t, None)
            if what and what[0] == "request":
                await self.request_failed(what[1], what[2], name)
        # other types: ignored (09 section 12.5)

    # -------------------------------------------------------------- owner: deliveries and requests

    async def on_deliver(self, s: FedServer, m: list) -> None:
        _, frame, receptions, publisher, rtt_pub = m
        arrived = time.monotonic()
        h = cs.parse_header(frame)
        if h is None or h.ftype == cs.T_JOIN or cs.is_downlink(h.ftype):
            log(f"mailbox {s.url}: dropped a delivered {'JOIN' if h and h.ftype == cs.T_JOIN else 'bad'} frame")
            return
        if h.ftype == cs.T_SYNC:
            t = time.monotonic()
            self.fed_bootstrap = [x for x in self.fed_bootstrap if t - x < 60]
            if len(self.fed_bootstrap) >= FED_BOOTSTRAP_PER_MINUTE:
                log(f"mailbox {s.url}: federated SYNC over the limit, dropped")
                return
            self.fed_bootstrap.append(t)
        answer = self.deliver_handler(s, frame, h, receptions, publisher, rtt_pub, arrived)
        cands = [{"server": s, "rx_ref": r[0], "rssi": r[1], "snr": r[2], "age": r[3], "rtt_pub": rtt_pub,
                  "publisher": publisher, "arrived": arrived} for r in receptions if r[4] & cs.RXF_DOWNLINK]
        key = cs.frame_key(frame)
        pend = self.owner_pending.get(key)
        if answer is not None:  # a new transmission that needs an answer: collect, then choose
            self.owner_pending[key] = {"answer": answer, "cands": cands, "tried": set(), "requested": None,
                                       "frame": frame, "local": False}
            asyncio.get_running_loop().call_later(COLLECT_MS / 1000, lambda: asyncio.ensure_future(self.choose(key)))
        elif pend is not None and pend["requested"] is None:
            pend["cands"] += cands  # a copy within the collection window, maybe through another server

    def answered_locally(self, frame: bytes) -> None:
        """A copy from our own proxies: it answers, so no federated request (07 section 6.3)."""
        pend = self.owner_pending.get(cs.frame_key(frame))
        if pend is not None:
            pend["local"] = True

    def is_pending(self, frame: bytes) -> bool:
        pend = self.owner_pending.get(cs.frame_key(frame))
        return pend is not None and pend["requested"] is None and not pend["local"]

    async def choose(self, key: bytes) -> None:
        """Pick one reception and request through its server (09 sections 7.6, 9, 10)."""
        pend = self.owner_pending.get(key)
        if pend is None or pend["requested"] is not None:
            return
        if pend["local"]:
            self.owner_pending.pop(key, None)
            return
        t = time.monotonic()
        ok = [c for c in pend["cands"] if c["server"].up and (c["server"], c["rx_ref"]) not in pend["tried"]
              and cs.federated_request_ok(c["age"], c["rtt_pub"], c["server"].link.rtt_ms,
                                          int((t - c["arrived"]) * 1000))]
        if not ok:
            log(f"federated answer to fcnt {pend['answer']['fcnt']}: no reception qualifies for RX2 "
                f"({len(pend['cands'])} with DOWNLINK); the sensor will retry")
            self.owner_pending.pop(key, None)
            return
        # Rotation: not the publisher that took this device's last request, when
        # another qualifies; then the lowest rtt_owner + rtt_pub (09 section 10); then
        # the best SNR. Section 9's publisher records are not modelled.
        last = self.last_publisher.get(pend["answer"]["dev"])
        rotate = len({c["publisher"] for c in ok}) > 1
        ok.sort(key=lambda c: (rotate and c["publisher"] == last, c["server"].link.rtt_ms + c["rtt_pub"], -c["snr"]))
        c = ok[0]
        s = c["server"]
        pend["requested"] = c
        pend["tried"].add((s, c["rx_ref"]))
        self.last_publisher[pend["answer"]["dev"]] = c["publisher"]
        seq = await s.link.send([cs.MB_REQUEST, c["rx_ref"], pend["answer"]["downlink"]])
        s.pending[seq] = ("request", key, c["rx_ref"])
        log(f"mailbox {s.url}: request RX2 answer to fcnt {pend['answer']['fcnt']} through publisher "
            f"{c['publisher'].hex()} rx_ref {c['rx_ref'].hex()} (age {c['age']} ms, rtt_pub {c['rtt_pub']} ms, "
            f"rtt_owner {s.link.rtt_ms} ms, {pend['answer']['what']})")
        timeout = (cs.FORWARD_TIMEOUT_MS + s.link.rtt_ms) / 1000  # 09 section 7.5

        mine = s.pending[seq]

        def expire() -> None:
            if s.pending.get(seq) is mine:
                s.pending.pop(seq)
            if self.owner_pending.get(key) is pend:
                self.owner_pending.pop(key, None)
        asyncio.get_running_loop().call_later(timeout, expire)

    async def request_failed(self, key: bytes, rx_ref: bytes, why: str) -> None:
        pend = self.owner_pending.get(key)
        if pend is None or pend["requested"] is None or pend["requested"]["rx_ref"] != rx_ref:
            return
        pend["requested"] = None
        if why != "ALREADY_ANSWERED":
            await self.choose(key)

    async def on_result(self, s: FedServer, rx_ref: bytes, code: int, offset_us: int) -> None:
        name = TX_RESULTS.get(code, str(code))
        hit = next(((k, p) for k, p in self.owner_pending.items()
                    if p["requested"] is not None and p["requested"]["rx_ref"] == rx_ref), None)
        log(f"mailbox {s.url}: result for rx_ref {rx_ref.hex()}: {name}, {offset_us / 1000:.1f} ms after target"
            + ("" if hit else " (no pending request)"))
        if hit is None:
            return
        key, pend = hit
        if code == 0:
            return
        pend["requested"] = None  # a non-SENT result releases the transmission (09 section 7.5)
        log(f"federated answer to fcnt {pend['answer']['fcnt']}: released by {name}, trying another publisher")
        await self.choose(key)

    # -------------------------------------------------------------- publisher

    def heard(self, p, frame: bytes, h, u: dict) -> None:
        """A frame from our proxies that no device of ours verified (09 section 6.1)."""
        if not self.args.publish or not self.servers:
            return
        if cs.is_downlink(h.ftype):
            return
        if h.ftype == cs.T_JOIN:
            log(f"{p.proxy_id.hex()}: JOIN not published (09 section 8)")
            return
        hello = p.hello
        if hello is not None and self.frequency is None:
            self.frequency = hello["frequency_hz"]  # no configured channel: the first proxy's is the network's
        if hello is None or hello["region"] != self.args.region or hello["frequency_hz"] != self.frequency or \
                (hello["sf"], hello["bw_khz"] * 1000) != cs.REGIONS.get(self.args.region):
            log(f"{p.proxy_id.hex()}: not published: proxy profile unknown or not the network's "
                f"({self.args.region}, {self.frequency} Hz)")
            return
        t = time.monotonic()
        key = cs.frame_key(frame)
        rec = {"pid": p.proxy_id, "rx_time": u["rx_time_us"], "rssi": u["rssi"], "snr": u["snr"],
               "flags": u["flags"], "at": t}
        txn = self.publish_pending.get(key)
        if txn is not None and t - txn["first"] <= cs.MERGE_WINDOW_MS / 1000:
            txn["recs"].append(rec)
            return
        prev = self.recent.get(key)
        if prev is not None and t - prev["first"] <= cs.MERGE_WINDOW_MS / 1000:
            return  # a late copy of a transmission already published
        txn = {"frame": frame, "h": h, "first": t, "recs": [rec], "answered": False}
        self.publish_pending[key] = txn
        asyncio.get_running_loop().call_later(COLLECT_MS / 1000, lambda: asyncio.ensure_future(self.flush(key)))

    async def flush(self, key: bytes) -> None:
        txn = self.publish_pending.pop(key, None)
        if txn is None:
            return
        self.recent = {k: v for k, v in self.recent.items() if time.monotonic() - v["first"] < 60}
        self.recent[key] = txn
        h = txn["h"]
        recs = sorted(txn["recs"], key=lambda r: -r["snr"])[:8]
        for s in self.servers:
            if not s.up:
                continue
            t = time.monotonic()
            s.published = [x for x in s.published if t - x < 1]
            if len(s.published) >= PUBLISH_PER_S:
                log(f"mailbox {s.url}: over {PUBLISH_PER_S} publishes a second, dropped")
                continue
            s.published.append(t)
            s.issued = {r: v for r, v in s.issued.items() if t - v.at < cs.RX_REF_MS / 1000}
            out = []
            for r in recs:
                rx_ref = secrets.token_bytes(8)  # fresh per reception and server (09 section 6.2)
                dl = bool(self.args.federated_downlinks and h.ftype in CONFIRMED and self.candidate(r["pid"]))
                s.issued[rx_ref] = Issued(r["pid"], r["rx_time"], txn, dl)
                flags = ((cs.RXF_TS_UNCERTAIN if r["flags"] & cs.UPF_TS_UNCERTAIN else 0)
                         | (cs.RXF_DOWNLINK if dl else 0))
                out.append([rx_ref, max(-32768, min(32767, round(r["rssi"] * 10))),
                            max(-32768, min(32767, round(r["snr"] * 10))),
                            min(65535, int((t - r["at"]) * 1000)), flags])
            await s.link.send([cs.MB_PUBLISH, txn["frame"], out])
            log(f"mailbox {s.url}: published {TYPE_NAMES.get(h.ftype, h.ftype)} tag {h.tag.hex()} fcnt {h.fcnt}, "
                f"{len(out)} receptions{', DOWNLINK' if any(o[4] & cs.RXF_DOWNLINK for o in out) else ''}")

    def candidate(self, pid: bytes) -> bool:
        """07 section 6.1, as far as the test server knows: downlink capable and heard
        from in the last 180 s. (Every proxy here shares --key, which 05 section 4.2
        forbids outside development.)"""
        p = self.proxy_info(pid)
        return p is not None and p.hello is not None and p.hello["caps"] & cs.CAP_DOWNLINK != 0 \
            and time.monotonic() - p.hello_at < 180

    def local_downlink(self, pid: bytes, ref_rx_time: int, offset_us: int, frame_len: int, region: str) -> None:
        start = ref_rx_time + offset_us
        end = start + int(cs.region_airtime_ms(region, frame_len) * 1000)
        self.local_tx[pid] = [x for x in self.local_tx.get(pid, []) if x[1] > start - 10_000_000] + [(start, end)]

    async def on_forward(self, s: FedServer, rx_ref: bytes, downlink: bytes, requester: bytes) -> None:
        """09 section 7.4: the publisher's checks, in order, then transmit."""
        t = time.monotonic()
        iss = s.issued.get(rx_ref)
        code, why, airtime = 0, "", 0.0
        p = self.proxy_info(iss.pid) if iss else None
        region = p.hello["region"] if p is not None and p.hello else self.args.region
        if iss is None or t - iss.at > cs.RX_REF_MS / 1000 or iss.used:
            code, why = 5, "rx_ref unknown, expired or used"
        elif not iss.downlink or not self.args.federated_downlinks or p is None:
            code, why = 4, "no DOWNLINK on that reception"
        else:
            hd = cs.parse_header(downlink)
            if hd is None or not cs.is_downlink(hd.ftype) or downlink[2:10] != iss.txn["frame"][2:10]:
                code, why = 5, "not a downlink for that frame"
            elif iss.txn["answered"]:
                code, why = 2, "transmission already answered"
            else:
                airtime = cs.region_airtime_ms(region, len(downlink))
                why = self.over_budget(s, iss.pid, requester, airtime, t)
                if why:
                    code = 3
                else:
                    start = iss.rx_time + 3_000_000
                    if any(a < start + airtime * 1000 and start < b for a, b in self.local_tx.get(iss.pid, [])):
                        code, why = 2, "own downlink on that proxy"
        if iss is not None:
            iss.used = True
        if code:
            log(f"mailbox {s.url}: forward {rx_ref.hex()} from {requester.hex()} refused: "
                f"{TX_RESULTS[code]} ({why})")
            await s.link.send([cs.MB_RESULT, rx_ref, code, 0])
            return
        seq = self.send_downlink(iss.pid, iss.rx_time, 3_000_000, downlink)
        iss.txn["answered"] = True
        self.fed_downlinks.append(t)
        self.proxy_airtime.setdefault(iss.pid, []).append((t, airtime))
        amount, at = s.quota.get(requester, (0.0, t))
        s.quota[requester] = (amount * 0.5 ** ((t - at) / QUOTA_HALF_LIFE_S) + airtime, t)
        self.dl_map[(iss.pid, seq)] = (s, rx_ref)
        # Exactly one result per forward (09 section 7.5), even if the proxy never
        # reports: by then the server's forward timeout has passed, so it releases nothing.
        asyncio.get_running_loop().call_later(
            TX_RESULT_WAIT_S, lambda: asyncio.ensure_future(self.tx_result(iss.pid, seq, RADIO_ERROR, 0, rx_ref)))
        log(f"mailbox {s.url}: forward {rx_ref.hex()} from {requester.hex()}: {iss.pid.hex()} -> DOWNLINK seq {seq} "
            f"in rx2 for a neighbor's sensor")

    def over_budget(self, s: FedServer, pid: bytes, requester: bytes, airtime: float, t: float) -> str:
        """Federated airtime limits (09 section 7.4, check 5), or "" if within them."""
        budget = self.args.fed_budget_pct / 100 * 3600_000
        hist = [x for x in self.proxy_airtime.get(pid, []) if t - x[0] < 3600]
        self.proxy_airtime[pid] = hist
        used = sum(a for _, a in hist)
        if used + airtime > budget:
            return "proxy's federated budget"
        self.fed_downlinks = [x for x in self.fed_downlinks if t - x < 60]
        if len(self.fed_downlinks) >= FED_DOWNLINKS_PER_MIN:
            return f"{FED_DOWNLINKS_PER_MIN} federated downlinks a minute"
        if used > budget / 2:
            active = [r for r, (_, at) in s.quota.items() if t - at < 3600] or [requester]
            amount, at = s.quota.get(requester, (0.0, t))
            if amount * 0.5 ** ((t - at) / QUOTA_HALF_LIFE_S) > budget / len(set(active) | {requester}):
                return "requester's share"
        return ""

    async def tx_result(self, pid: bytes, seq: int, result: int, offset_us: int, only: bytes | None = None) -> None:
        """Pass a TX_RESULT on as the result; with only, just for that rx_ref."""
        hit = self.dl_map.get((pid, seq))
        if hit is None or only is not None and hit[1] != only:
            return
        del self.dl_map[(pid, seq)]
        s, rx_ref = hit
        if s.up:
            await s.link.send([cs.MB_RESULT, rx_ref, result, offset_us])
            log(f"mailbox {s.url}: result for {rx_ref.hex()}: {TX_RESULTS.get(result, result)}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=47800)
    ap.add_argument("--key", help="proxy key shared by every proxy, 32 hex digits (default: generate one); "
                                  "development only, see above")
    ap.add_argument("--ack", action="store_true", help="answer confirmed uplinks from the test device")
    ap.add_argument("--window", choices=("rx1", "rx2"), default="rx1")
    ap.add_argument("--no-seq-seed", action="store_true",
                    help="count the server seq from 1 in each session instead of seeding it from the clock")
    ap.add_argument("--device", action="append", default=[], metavar="CODE",
                    help="a sensor to pair: its CS:1:... pairing code, or DEV_EUI:K_ROOT in hex (repeatable)")
    ap.add_argument("--state", metavar="FILE",
                    help="keep the devices' sessions and counters in FILE, so a restart needs no re-pairing")
    ap.add_argument("--queue-nop", type=int, default=0, metavar="N",
                    help="queue N NOP commands for each --device, sent one per downlink with PENDING "
                         "(type `nop [N]` on stdin to queue more)")
    ap.add_argument("--json", action="store_true",
                    help="one JSON object per event on stdout; the human log goes to stderr")
    ap.add_argument("--fault", choices=FAULTS,
                    help="make every downlink answering an uplink faulty, to test a proxy's checks")
    fg = ap.add_argument_group("federation (spec 09); needs: pip install websockets")
    fg.add_argument("--mailbox", action="append", default=[], metavar="URL",
                    help="a mailbox server's wss:// URL (repeatable): register the --device sensors' tags there "
                         "and take their frames from neighbors' proxies")
    fg.add_argument("--mailbox-ca", metavar="PEM",
                    help="trust only this certificate (or CA) for the mailbox URLs, instead of the system's")
    fg.add_argument("--insecure-dev", action="store_true",
                    help="allow plain ws:// mailbox URLs; for tests with cs_mailbox.py --insecure-dev only")
    fg.add_argument("--publish", action="store_true",
                    help="share coverage: publish frames our proxies heard that none of our devices verified "
                         "(never JOIN)")
    fg.add_argument("--federated-downlinks", action="store_true",
                    help="let neighbors' sensors use our proxies for RX2 replies (with --publish)")
    fg.add_argument("--region", default="US915", choices=sorted(cs.REGIONS),
                    help="network profile; frames from proxies on another profile are not published")
    fg.add_argument("--fed-budget-pct", type=float, default=0.5,
                    help="federated airtime per proxy, percent of a rolling hour (09 section 11, mode 4)")
    args = ap.parse_args()
    if args.queue_nop < 0:
        print("--queue-nop must not be negative", file=sys.stderr)
        return 2
    if (args.publish or args.federated_downlinks) and not args.mailbox:
        ap.error("--publish and --federated-downlinks need --mailbox")
    global LOG_STREAM, JSON_EVENTS
    if args.json:
        LOG_STREAM, JSON_EVENTS = sys.stderr, True

    key = bytes.fromhex(args.key) if args.key else secrets.token_bytes(16)
    if len(key) != 16:
        print("--key must be 32 hex digits", file=sys.stderr)
        return 2
    if not args.key:
        log(f"Generated proxy key: {key.hex()}")
        log("Put it in the proxy's secrets.yaml as cs_proxy_key, or restart with --key.")

    device = TestDevice()
    real: list[RealDevice] = []
    for spec in args.device:
        try:
            dev_eui, k_root = parse_device(spec)
        except ValueError as ex:
            print(f"--device {spec}: {ex}", file=sys.stderr)
            return 2
        real.append(RealDevice(dev_eui, k_root))
    stored = {}
    if args.state and os.path.exists(args.state):
        with open(args.state) as f:
            stored = json.load(f)
    for dev in real:
        if dev.dev_eui.hex() in stored:
            dev.load_json(stored[dev.dev_eui.hex()])
        dev.queue_nops(args.queue_nop)
        log(f"Device {dev.dev_eui.hex()}: {dev.state}" + (f", {len(dev.queue)} NOP queued" if dev.queue else ""))
    devices = Devices(real)
    devices.refresh(int(time.time()))

    def save_state() -> None:
        if not args.state:
            return
        stored.update({dev.dev_eui.hex(): dev.to_json() for dev in real})
        tmp = args.state + ".tmp"
        with open(tmp, "w") as f:
            json.dump(stored, f, indent=1)
        os.replace(tmp, args.state)

    fed = Federation(args, stored, save_state, devices) if args.mailbox else None
    proxies: dict[bytes, Proxy] = {}
    downlink_proxies: set[bytes] = set()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", args.port))
    log(f"Listening on UDP {args.port}; downlinks {'on (' + args.window + ')' if args.ack else 'off'}"
        + (f"; fault {args.fault}" if args.fault else ""))
    emit("LISTENING", port=args.port, ack=args.ack, window=args.window, fault=args.fault,
         devices=[d.dev_eui.hex() for d in real])

    def send(p: Proxy, msg_type: int, body: bytes) -> int:
        seq = p.link.next_seq() & 0xFFFFFFFF
        sock.sendto(cs.envelope(key, msg_type, p.proxy_id, p.link.boot_id, seq, body), p.addr)
        return seq

    def send_downlink(p: Proxy, rx_time: int, tx_offset: int, frame: bytes, uplink: bytes | None = None,
                      **info) -> int | None:
        """A downlink of our own; a federated one may not displace it (09 section 7.4).

        With --fault, a downlink answering uplink is sent faulty, and a late one is
        sent later: then the seq is None here and in the DOWNLINK event it is real."""
        fault = args.fault if uplink is not None else None
        if fault == "uplink-frame":
            frame = uplink
        if fed is not None:
            fed.local_downlink(p.proxy_id, rx_time, tx_offset, len(frame),
                               p.hello["region"] if p.hello else args.region)
        region = p.hello["region"] if p.hello and p.hello["region"] in cs.REGIONS else args.region
        event = {"proxy": p.proxy_id.hex(), "ref_rx_time_us": rx_time, "tx_offset_us": tx_offset,
                 "frame": frame.hex(), "airtime_us": round(cs.region_airtime_ms(region, len(frame)) * 1000),
                 "fault": fault, **info}
        body = cs.downlink_msg_body(rx_time, tx_offset, frame)
        if fault == "late":
            # Past tx_at plus the proxy's window, so it must answer TOO_LATE.
            def later() -> None:
                emit("DOWNLINK", seq=send(p, cs.M_DOWNLINK, body), **event)
            asyncio.get_running_loop().call_later((tx_offset + TX_WINDOW_US) / 1e6 + 0.1, later)
            log(f"{p.proxy_id.hex()}: fault late: DOWNLINK held past its window")
            return None
        if fault in ("bad-mac", "stale-seq", "wrong-boot"):
            seq = p.status_seq if fault == "stale-seq" else p.link.next_seq() & 0xFFFFFFFF
            boot = p.link.boot_id ^ 0x5A5A5A5A if fault == "wrong-boot" else p.link.boot_id
            msg = bytearray(cs.envelope(key, cs.M_DOWNLINK, p.proxy_id, boot, seq, body))
            if fault == "bad-mac":
                msg[-1] ^= 0x01
            sock.sendto(bytes(msg), p.addr)
            log(f"{p.proxy_id.hex()}: fault {fault}: DOWNLINK seq {seq} sent faulty; the proxy must drop it")
        else:
            seq = send(p, cs.M_DOWNLINK, body)
        emit("DOWNLINK", seq=seq, **event)
        if fault == "busy":
            # A second downlink for the same slot: the proxy must refuse it with BUSY.
            seq2 = send(p, cs.M_DOWNLINK, body)
            emit("DOWNLINK", seq=seq2, **{**event, "copy_of": seq})
            log(f"{p.proxy_id.hex()}: fault busy: DOWNLINK seq {seq2} repeats seq {seq}")
        return seq

    def rx_offset() -> int:
        return 1_000_000 if args.window == "rx1" else 3_000_000

    def real_uplink(p: Proxy, pid: bytes, line: str, frame: bytes, h, rx_time: int, now: int, ev: dict) -> bool:
        """A registered sensor's uplink: pairing (04 section 4.4) or normal traffic."""
        devices.refresh(now)
        found = devices.identify(frame, h)
        if found is None:
            return False
        dev, keyset, keys, pt, route = found
        eui = dev.dev_eui.hex()
        got = dev.uplinks.receive(frame, int(time.monotonic() * 1000))
        if got["result"] == "copy":
            log(line + f" {eui}: copy of the same transmission")
            emit("UPLINK", **ev, device=eui, result="copy")
            if fed is not None and fed.is_pending(frame):
                # Our own proxy heard it before the federated request went out: it
                # answers instead (07 section 6.3).
                dl = fed.owner_pending[cs.frame_key(frame)]["answer"]["downlink"]
                fed.answered_locally(frame)
                send_downlink(p, rx_time, rx_offset(), dl, answering=h.fcnt, device=eui, what="ack",
                              window=args.window)
                log(f"{pid.hex()} -> DOWNLINK ack to {eui} answering fcnt {h.fcnt} in {args.window}, "
                    f"instead of a federated request")
            return True
        how = "by tag" if route == "table" else "by trial decryption"
        log(line + f" {eui} ({keyset} keys, {how}, {got['counter']}): {describe_payload(h.ftype, pt)}")
        emit("UPLINK", **ev, device=eui, keys=keyset, route=route, result="transmission", counter=got["counter"],
             answer=got["answer"], payload=describe_payload(h.ftype, pt))
        if got["counter"] in ("accept", "accept_late"):
            dev.last_seen = now
            if devices.moved(dev):
                devices.refresh(now, dev)
        settle_acks(dev, h, pt, got["counter"])
        # 07 section 5: queued commands ride on any fresh uplink, but an unconfirmed one
        # only gets RX1 (07 section 6.3).
        carry = dev.state == "PAIRED" and bool(dev.queue) and got["counter"] != "accept_late"
        if not got["answer"]:
            if not (carry and got["counter"] == "accept" and h.ftype != cs.T_JOIN):
                return True
            if args.window != "rx1":
                log(f"{eui}: {len(dev.queue)} queued; an unconfirmed uplink cannot be answered in RX2")
                return True
        if h.ftype == cs.T_JOIN:
            # 04 section 4.4 step 3; a retransmitted JOIN gets the same frame back (4.2).
            r = dev.join.join(frame, secrets.token_bytes(32), now)
            if r["action"] == "new_exchange":
                dev.set_session(r["k_session"], "EXCHANGED")
                dev.fcnt_down = 0
                devices.refresh(now, dev)  # the pending k_session's tags (07 section 3)
                if fed is not None:  # and on the mailboxes at once (09 section 5.3, fresh keys)
                    asyncio.ensure_future(fed.refresh())
            save_state()
            send_downlink(p, rx_time, rx_offset(), r["frame"], frame, answering=h.fcnt, device=eui,
                          what="KEY_EXCHANGE", window=args.window)
            stalled = " (stalled: the sensor keeps repeating JOIN)" if r["stalled"] else ""
            log(f"{pid.hex()} -> DOWNLINK KEY_EXCHANGE to {eui} ({r['action']}, root counter "
                f"{dev.join.root_fcnt_down}){stalled}")
            return True
        if dev.state == "EXCHANGED":
            # 04 section 4.4 step 6: the first session uplink verified; answering it
            # completes pairing on the sensor.
            dev.state = "PAIRED"
            dev.join.paired()
            log(f"{eui} PAIRED")
            emit("PAIRED", device=eui)
        if h.ftype in CONFIRMED or carry:
            dl, what = answer_frame(dev, keys, h, now, carry)
            send_downlink(p, rx_time, rx_offset(), dl, frame, answering=h.fcnt, device=eui, what=what,
                          window=args.window)
            log(f"{pid.hex()} -> DOWNLINK {what} to {eui} answering fcnt {h.fcnt} in {args.window}")
        save_state()
        return True

    def settle_acks(dev: RealDevice, h, pt: bytes, counter: str) -> None:
        if h.ftype != cs.T_JOIN and dev.state == "PAIRED" and counter in ("accept", "accept_late"):
            # 07 section 7: DL_ACK in a newer uplink settles the commands awaiting it.
            done = dev.acks.uplink(h.fcnt, counter, bool(pt[0] & cs.UF_DL_ACK))
            if done:
                dev.queue = [c for c in dev.queue if c not in done]
                log(f"{dev.dev_eui.hex()}: {len(done)} command(s) acknowledged, {len(dev.queue)} queued")
                emit("ACKED", device=dev.dev_eui.hex(), commands=len(done), queued=len(dev.queue))

    def answer_frame(dev: RealDevice, keys: cs.DeviceKeys, h, now: int, carry: bool) -> tuple[bytes, str]:
        """The downlink answering h, with the next queued command if carry."""
        # One command per downlink, so PENDING is exercised (a real server sends
        # as many as fit, 07 section 5).
        cmds = dev.queue[:1] if carry else []
        flags = cs.DF_PENDING if len(dev.queue) > len(cmds) else 0
        if cmds:
            dev.acks.downlink(h.fcnt, cmds)
        dev.fcnt_down += 1
        dl = cs.seal(keys, cs.T_DOWNLINK, h.tag, dev.fcnt_down,
                     cs.downlink_payload(h.fcnt, now, flags, b"".join(c for _, c in cmds)))
        return dl, (f"NOP{' PENDING' if flags else ''} ({len(dev.queue)} queued)" if cmds else "ack")

    def command_line(line: str) -> None:
        words = line.split()
        if not words:
            return
        if words[0] == "nop" and len(words) <= 2 and (len(words) == 1 or words[1].isdigit()):
            n = int(words[1]) if len(words) == 2 else 1
            for dev in real:
                dev.queue_nops(n)
                log(f"{dev.dev_eui.hex()}: {len(dev.queue)} NOP queued")
                emit("QUEUED", device=dev.dev_eui.hex(), queued=len(dev.queue))
            if not real:
                log("nop: no --device to queue for")
        elif words[0] == "window" and len(words) == 2 and words[1] in ("rx1", "rx2"):
            args.window = words[1]
            log(f"downlinks now in {args.window}")
            emit("MODE", window=args.window, fault=args.fault)
        elif words[0] == "fault" and len(words) == 2 and words[1] in (*FAULTS, "none"):
            args.fault = None if words[1] == "none" else words[1]
            log(f"fault now {args.fault or 'none'}")
            emit("MODE", window=args.window, fault=args.fault)
        elif words == ["hello"]:
            # A HELLO_REQUEST in each proxy's current session draws a HELLO with fresh
            # counters (the proxy sends at most one requested HELLO per 5 s).
            for p in proxies.values():
                if p.addr is not None and p.link.boot_id is not None:
                    sock.sendto(cs.envelope(key, cs.M_HELLO_REQUEST, p.proxy_id, p.link.boot_id, 0,
                                            cs.hello_request_body(secrets.randbits(32) | 1)), p.addr)
                    log(f"{p.proxy_id.hex()}: sent HELLO_REQUEST for its counters")
        else:
            log(f"unknown command {line.strip()!r}; try `nop [N]`, `window rx1|rx2`, `fault NAME|none` or `hello`")

    def federated_uplink(s, frame: bytes, h, receptions: list, publisher: bytes, rtt_pub: int,
                         arrived: float) -> dict | None:
        """A deliver: processed as a copy from step 2 of 07 section 4, marked federated
        (07 section 4.4). Returns the downlink to request if it needs an answer."""
        now = int(time.time())
        devices.refresh(now)
        r0 = receptions[0]
        line = (f"mailbox {publisher.hex()} UPLINK {TYPE_NAMES.get(h.ftype, h.ftype)} fcnt {h.fcnt} "
                f"rssi {r0[1] / 10:.1f} snr {r0[2] / 10:.1f} age {r0[3]} ms")
        found = devices.identify(frame, h, federated=True)
        if found is None:
            log(line + " (no device of ours verified it; dropped)")
            return None
        dev, keyset, keys, pt, _ = found
        eui = dev.dev_eui.hex()
        got = dev.uplinks.receive(frame, int(arrived * 1000), max(r[3] for r in receptions))
        if got["result"] == "copy":
            log(line + f" {eui}: copy of the same transmission [federated]")
            return None
        log(line + f" {eui} ({keyset} keys, by tag, {got['counter']}) [federated via {s.url}]: "
                   f"{describe_payload(h.ftype, pt)}")
        if got["counter"] in ("accept", "accept_late"):
            dev.last_seen = now
            if devices.moved(dev):
                devices.refresh(now, dev)
        settle_acks(dev, h, pt, got["counter"])
        if dev.state == "EXCHANGED":
            dev.state = "PAIRED"
            dev.join.paired()
            log(f"{eui} PAIRED")
            emit("PAIRED", device=eui)
        answer = None
        if got["answer"] and h.ftype in CONFIRMED:
            # Federation answers confirmed uplinks only, in RX2, so queued commands
            # wait for those (09 section 7.7).
            carry = dev.state == "PAIRED" and bool(dev.queue) and got["counter"] != "accept_late"
            dl, what = answer_frame(dev, keys, h, now, carry)
            answer = {"fcnt": h.fcnt, "downlink": dl, "dev": eui, "what": what}
        save_state()
        return answer

    def handle(data: bytes, addr) -> None:
        try:
            m = cs.open_envelope(key, data)
        except ValueError as ex:
            log(f"{addr[0]}: rejected {len(data)} bytes ({ex})")
            emit("REJECTED", addr=addr[0], len=len(data), reason=str(ex))
            return
        pid = bytes.fromhex(m["proxy_id"])
        p = proxies.setdefault(pid, Proxy(pid))
        got = p.link.receive(m, int(time.monotonic() * 1000))
        if got["result"] == "hello_request":
            # Not our session's boot: ask for a HELLO echoing a nonce, at the source of
            # this message, without touching the session (05 section 3.2).
            sock.sendto(cs.envelope(key, cs.M_HELLO_REQUEST, pid, m["boot_id"], 0,
                                    cs.hello_request_body(got["nonce"])), addr)
            log(f"{pid.hex()}: message type 0x{m['type']:02x} from boot {m['boot_id']:08x}, "
                f"not this session's; sent HELLO_REQUEST")
            emit("HELLO_REQUEST", proxy=pid.hex(), boot_id=m["boot_id"], msg_type=m["type"])
            return
        if got["result"] == "ignored":
            log(f"{pid.hex()}: ignored message type 0x{m['type']:02x} boot {m['boot_id']:08x} seq {m['seq']}")
            emit("IGNORED", proxy=pid.hex(), boot_id=m["boot_id"], seq=m["seq"], msg_type=m["type"])
            return
        if got["result"] == "switched":
            if not args.no_seq_seed:
                p.link.seq = seq_seed()
            log(f"{pid.hex()}: session with boot {m['boot_id']:08x}, server seq from {p.link.seq + 1}")
            emit("SESSION", proxy=pid.hex(), boot_id=m["boot_id"], seq_from=p.link.seq + 1)
        p.addr = addr
        body = bytes.fromhex(m["body"])
        now = int(time.time())

        if m["type"] == cs.M_HELLO:
            h = cs.parse_hello(body)
            p.hello, p.hello_at = h, time.monotonic()
            log(f"{pid.hex()} HELLO {h['fw']}, {h['region']} {h['frequency_hz'] / 1e6:g} MHz SF{h['sf']} "
                f"{h['bw_khz']} kHz, up {h['uptime_s']}s, downlink {'yes' if h['caps'] & 1 else 'no'}, "
                f"loop gap {h['max_loop_gap_ms']} ms, "
                f"heard/fwd/dup/invalid/rl/tx_ok/tx_fail = {'/'.join(map(str, h['counters']))}")
            emit("HELLO", proxy=pid.hex(), boot_id=m["boot_id"], seq=m["seq"], fw=h["fw"], region=h["region"],
                 frequency_hz=h["frequency_hz"], sf=h["sf"], bw_khz=h["bw_khz"], uptime_s=h["uptime_s"],
                 downlink=bool(h["caps"] & 1), max_loop_gap_ms=h["max_loop_gap_ms"],
                 counters=dict(zip(("heard", "forwarded", "duplicates", "invalid", "rate_limited", "tx_ok",
                                    "tx_failed"), h["counters"])))
            p.status_seq = send(p, cs.M_SERVER_STATUS, cs.server_status_body(now, m["seq"]))
            if h["caps"] & 1 and (args.ack or real) and pid not in downlink_proxies:
                downlink_proxies.add(pid)
                if len(downlink_proxies) == 2:
                    log("WARNING: two downlink-capable proxies share --key; development only. A real "
                        "server gives each its own key (05 section 4.2).")

        elif m["type"] == cs.M_UPLINK:
            u = cs.parse_uplink(body)
            rx_time, frame = u["rx_time_us"], u["frame"]
            h = cs.parse_header(frame)
            name = TYPE_NAMES.get(h.ftype, f"type {h.ftype}") if h else "invalid"
            line = (f"{pid.hex()} UPLINK {name} fcnt {h.fcnt if h else '?'} rssi {u['rssi']:.1f} "
                    f"snr {u['snr']:.1f}{' TS_UNCERTAIN' if u['flags'] & cs.UPF_TS_UNCERTAIN else ''}")
            ev = {"proxy": pid.hex(), "type": name, "fcnt": h.fcnt if h else None, "rssi": u["rssi"],
                  "snr": u["snr"], "ts_uncertain": bool(u["flags"] & cs.UPF_TS_UNCERTAIN), "rx_time_us": rx_time,
                  "frame": frame.hex()}
            if h and real_uplink(p, pid, line, frame, h, rx_time, now, ev):
                return
            opened = device.open(frame) if h else None
            if opened is None:
                log(line + " (not the test device)")
                emit("UPLINK", **ev, device=None, result="unknown")
                if h and fed is not None:
                    fed.heard(p, frame, h, u)
                return
            keyset, keys, h, pt = opened
            got = device.uplinks.receive(frame, int(time.monotonic() * 1000))
            if got["result"] == "copy":
                log(line + " test device: copy of the same transmission")
                emit("UPLINK", **ev, device="test", result="copy")
                return
            log(line + f" test device ({keyset} keys, {got['counter']}): {describe_payload(h.ftype, pt)}")
            emit("UPLINK", **ev, device="test", keys=keyset, result="transmission", counter=got["counter"],
                 answer=bool(args.ack and h.ftype in CONFIRMED and got["answer"]),
                 payload=describe_payload(h.ftype, pt))
            if args.ack and h.ftype in CONFIRMED and got["answer"]:
                device.fcnt_down += 1
                dl_pt = cs.downlink_payload(h.fcnt, now, 0)
                dl = cs.seal(keys, cs.T_DOWNLINK, h.tag, device.fcnt_down, dl_pt)
                seq = send_downlink(p, rx_time, rx_offset(), dl, frame, answering=h.fcnt, device="test", what="ack",
                                    window=args.window)
                log(f"{pid.hex()} -> DOWNLINK seq {seq if seq is not None else 'later'} answering fcnt {h.fcnt} "
                    f"in {args.window}")

        elif m["type"] == cs.M_TX_RESULT:
            t = cs.parse_tx_result(body)
            log(f"{pid.hex()} TX_RESULT seq {t['downlink_seq']}: {TX_RESULTS.get(t['result'], t['result'])}, "
                f"{t['offset_us'] / 1000:.1f} ms after target")
            emit("TX_RESULT", proxy=pid.hex(), seq=t["downlink_seq"], result=TX_RESULTS.get(t["result"], t["result"]),
                 offset_us=t["offset_us"])
            if fed is not None:
                asyncio.ensure_future(fed.tx_result(pid, t["downlink_seq"], t["result"], t["offset_us"]))
        else:
            log(f"{pid.hex()} message type 0x{m['type']:02x} ignored")

    async def serve() -> None:
        sock.setblocking(False)

        def readable() -> None:
            while True:
                try:
                    data, addr = sock.recvfrom(2048)
                except BlockingIOError:
                    return
                handle(data, addr)

        loop = asyncio.get_running_loop()
        loop.add_reader(sock.fileno(), readable)
        if sys.stdin is not None and not sys.stdin.closed:
            fd, pending = sys.stdin.fileno(), [b""]

            def typed() -> None:
                chunk = os.read(fd, 4096)
                if not chunk:
                    loop.remove_reader(fd)  # EOF: keep serving without it
                    return
                pending[0] += chunk
                while b"\n" in pending[0]:
                    line, pending[0] = pending[0].split(b"\n", 1)
                    command_line(line.decode(errors="replace"))

            try:
                loop.add_reader(fd, typed)
            except PermissionError:  # a regular file or /dev/null: epoll cannot wait on it, nor need to
                for line in sys.stdin:
                    command_line(line)
        if fed is None:
            await asyncio.Event().wait()
        fed.send_downlink = lambda pid, rx_time, tx_offset, frame: send_downlink(proxies[pid], rx_time, tx_offset,
                                                                                 frame)
        fed.proxy_info = proxies.get
        fed.deliver_handler = federated_uplink
        await fed.run()

    asyncio.run(serve())
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        pass
