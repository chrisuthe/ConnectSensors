#!/usr/bin/env python3
"""cs-mailbox: the reference mailbox server for ConnectSensors federation (spec 09).

Routes published frames by tag to the owner keys that proved them, and requests
and results between owners and publishers. It holds no device keys, reads no
payloads and stores nothing on disk except, optionally, its own server key.
Registrations live in memory, so every start picks a new `generation` (09
section 5.3).

    cs_mailbox.py --host mailbox.example --tls-cert cert.pem --tls-key key.pem
    cs_mailbox.py --host 127.0.0.1 --insecure-dev        # plain ws://, tests only

The protocol rules (schemas, deterministic CBOR, strict Ed25519, proofs, the
transmission rule) come from the connectsensors package, whose code is
spec/tools/csframe.py; this file is the server around them. See mailbox/README.md.

Requires: cryptography, websockets
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import os
import secrets
import signal
import ssl
import sys
import time
from typing import Any

sys.dont_write_bytecode = True


# Run in place (the checkout, or the container, which keeps its layout), take
# connectsensors from ../python; it loads spec/tools/csframe.py there. Installed, take
# the installed package.
_PYTHON = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "python"))
if os.path.exists(os.path.join(_PYTHON, "connectsensors", "__init__.py")):
    sys.path.insert(0, _PYTHON)

import connectsensors as cs  # noqa: E402

from websockets.asyncio.server import ServerConnection, serve  # noqa: E402
from websockets.exceptions import ConnectionClosed  # noqa: E402

SUBPROTOCOL = "cs-mailbox.1"
PING_INTERVAL_S = 30
SWEEP_INTERVAL_S = 10
OUT_QUEUE = 256           # server messages waiting for a client; a client that falls this far behind is closed
KEY_MEMORY_S = 86400      # an admitted key is remembered this long after its last connection
CODE = {name: i for i, name in enumerate(cs.MB_ERRORS)}


def log(msg: str) -> None:
    print(time.strftime("%H:%M:%S ") + msg, flush=True)


def now_ms() -> int:
    return int(time.monotonic() * 1000)


class Bucket:
    """A token bucket: burst tokens, refilled at rate per second."""

    def __init__(self, rate: float, burst: float):
        self.rate, self.burst = rate, burst
        self.tokens, self.at = burst, time.monotonic()

    def take(self, n: float = 1) -> bool:
        t = time.monotonic()
        self.tokens = min(self.burst, self.tokens + (t - self.at) * self.rate)
        self.at = t
        if self.tokens < n:
            return False
        self.tokens -= n
        return True


class Fatal(Exception):
    def __init__(self, code: str, seq: int = 0):
        super().__init__(code)
        self.code, self.seq = code, seq


class KeyState:
    """Limits per client key, shared by all its connections (09 section 11)."""

    def __init__(self, args: argparse.Namespace):
        self.messages = Bucket(args.message_rate, 2 * args.message_rate)
        self.publish = Bucket(args.publish_rate, args.publish_burst)
        self.request = Bucket(args.request_rate, args.request_rate)
        self.register = Bucket(args.reg_per_hour / 3600, args.reg_burst)
        self.seen = time.monotonic()


class Client:
    """One authenticated connection."""

    def __init__(self, ws: ServerConnection, nonce_s: bytes, pub: bytes, pseud: bytes, key: KeyState):
        self.ws, self.nonce_s, self.pub, self.pseud, self.key = ws, nonce_s, pub, pseud, key
        self.name = pseud.hex()
        self.seq = 0  # last accepted seq (09 section 12.4)
        self.rtt_ms = cs.RTT_UNKNOWN
        self.ping: tuple[int, int] | None = None  # (nonce, sent at ms)
        self.out: asyncio.Queue[bytes] = asyncio.Queue(OUT_QUEUE)
        self.closing = False

    def post(self, msg: list[Any]) -> None:
        """Queue a server message; a writer task sends them in order, so a slow
        client never holds up another's handler, and one that stops reading is
        closed rather than buffered without end."""
        if self.closing:
            return
        try:
            self.out.put_nowait(cs.cbor(msg))
        except asyncio.QueueFull:
            self.closing = True
            log(f"{self.name}: not reading, closing")
            asyncio.ensure_future(self.ws.close(1008, "not reading"))


class Mailbox:
    def __init__(self, args: argparse.Namespace, seed: bytes):
        self.args = args
        self.seed = seed
        self.pub = cs.ed25519_pub(seed)
        self.server_id = cs.server_id_of(self.pub)
        self.generation = int.from_bytes(secrets.token_bytes(8), "big")
        self.hosts = [h.lower() for h in args.host]
        self.members = load_members(args.members) if args.members else None
        # tag -> owner pub -> expires (Unix seconds)
        self.regs: dict[bytes, dict[bytes, int]] = {}
        self.live: dict[bytes, int] = {}  # owner pub -> live registrations
        self.conns: dict[bytes, set[Client]] = {}
        self.tx = cs.MailboxTransmissions()
        # rx_ref -> owner pubs it was delivered to, when, the frame's tag, and the
        # publishing connection (09 section 7.3, checks 1 and 2)
        self.refs: dict[bytes, dict[str, Any]] = {}
        self.requested_by: dict[bytes, bytes] = {}  # rx_ref -> requesting owner pub
        self.keys: dict[bytes, KeyState] = {}  # admitted client keys
        self.admissions: dict[str, list[float]] = {}  # source network -> admission times

    # ---------------------------------------------------------------- connection

    async def handler(self, ws: ServerConnection) -> None:
        peer = f"{ws.remote_address[0]}:{ws.remote_address[1]}" if ws.remote_address else "?"
        client: Client | None = None
        tasks: list[asyncio.Task[None]] = []
        try:
            client = await self.handshake(ws, peer)
            if client is None:
                return
            self.conns.setdefault(client.pub, set()).add(client)
            tasks = [asyncio.create_task(self.writer(client)), asyncio.create_task(self.pinger(client))]
            async for data in ws:
                if isinstance(data, str):
                    raise Fatal("MALFORMED")
                await self.message(client, data)
        except Fatal as f:
            await self.fatal(ws, f, client.name if client else peer, client)
        except ConnectionClosed:
            pass
        finally:
            for t in tasks:
                t.cancel()
            if client is not None:
                self.conns.get(client.pub, set()).discard(client)
                if not self.conns.get(client.pub):
                    self.conns.pop(client.pub, None)
                client.key.seen = time.monotonic()
                log(f"{client.name} disconnected")

    async def fatal(self, ws: ServerConnection, f: Fatal, who: str, c: Client | None) -> None:
        log(f"{who}: {f.code}, closing")
        err = [cs.MB_ERROR, f.seq, CODE[f.code]]
        try:
            if c is None:
                await ws.send(cs.cbor(err))
            else:  # behind what is already queued, so replies keep their order
                c.post(err)
                await asyncio.wait_for(c.out.join(), 2)
            await ws.close(4000 + CODE[f.code], f.code)
        except (ConnectionClosed, TimeoutError):
            pass

    async def writer(self, c: Client) -> None:
        while True:
            data = await c.out.get()
            try:
                await c.ws.send(data)
            except ConnectionClosed:
                return
            finally:
                c.out.task_done()

    async def pinger(self, c: Client) -> None:
        """ping_s at once, so rtt_pub is known from the start, then every 30 s
        (09 section 12.5)."""
        while True:
            nonce = int.from_bytes(secrets.token_bytes(8), "big")
            c.ping = (nonce, now_ms())
            c.post([cs.MB_PING_S, nonce])
            await asyncio.sleep(self.args.ping_interval)

    async def handshake(self, ws: ServerConnection, peer: str) -> Client | None:
        """09 section 12.3. Returns the client after welcome, or None if it left."""
        try:
            data = await asyncio.wait_for(ws.recv(), self.args.handshake_timeout)
        except (TimeoutError, ConnectionClosed):
            return None
        if isinstance(data, str):
            raise Fatal("MALFORMED")
        try:
            hello = cs.open_hello(data)
        except ValueError as ex:
            code = {"not authenticated": "NOT_AUTHENTICATED",
                    "unsupported version": "UNSUPPORTED_VERSION"}.get(str(ex), "MALFORMED")
            m = cs.mb_decode(data) if code == "NOT_AUTHENTICATED" else []
            raise Fatal(code, m[1] if m and m[0] in cs.MB_SIGNED else 0) from None
        nonce_c = hello[2]
        host = self.greeting_host(ws)
        nonce_s = secrets.token_bytes(16)
        sig = cs.ed_sign(self.seed, cs.greeting_msg(host, nonce_c, nonce_s, self.generation))
        await ws.send(cs.cbor([cs.MB_GREETING, cs.MB_VERSION, self.pub, self.server_id, self.generation,
                               nonce_s, sig]))
        try:
            data = await asyncio.wait_for(ws.recv(), self.args.handshake_timeout)
        except (TimeoutError, ConnectionClosed):
            return None
        if isinstance(data, str):
            raise Fatal("MALFORMED")
        try:
            auth = cs.mb_decode(data)
        except ValueError:
            raise Fatal("MALFORMED") from None
        if auth[0] != cs.MB_AUTH:
            raise Fatal("NOT_AUTHENTICATED", auth[1] if auth[0] in cs.MB_SIGNED else 0)
        client_pub = auth[1]
        if cs.ed_verify_error(client_pub, cs.auth_msg(self.server_id, nonce_c, nonce_s, client_pub), auth[2]):
            raise Fatal("BAD_SIGNATURE")
        key = self.admit(client_pub, ws.remote_address[0] if ws.remote_address else "")
        if key is None:
            raise Fatal("NOT_PERMITTED")
        pseud = cs.pseudonym(self.server_id, client_pub)
        await ws.send(cs.cbor([cs.MB_WELCOME, pseud]))
        c = Client(ws, nonce_s, client_pub, pseud, key)
        log(f"{c.name} welcome from {peer} (host {host})")
        return c

    def greeting_host(self, ws: ServerConnection) -> str:
        """The configured name the client asked for, else the first configured one.
        The client's Host header only selects among configured names; a name the
        server is not configured for is never signed (09 section 12.3)."""
        asked = (ws.request.headers.get("Host", "") if ws.request else "").lower()
        if asked.startswith("["):
            asked = asked[1:asked.find("]")]
        elif asked.count(":") == 1:
            asked = asked.split(":")[0]
        return asked if asked in self.hosts else self.hosts[0]

    def admit(self, pub: bytes, addr: str) -> KeyState | None:
        """Admission (09 sections 5.4 and 11): a member list, or open admission with
        new keys rate-limited per source network. Returns the key's state, or None."""
        if pub in self.keys:
            self.keys[pub].seen = time.monotonic()  # so the sweeper keeps it through the handshake
            return self.keys[pub]
        if self.members is not None:
            if pub not in self.members:
                return None
        else:
            net = source_network(addr)
            t = time.monotonic()
            recent = [x for x in self.admissions.get(net, []) if t - x < 3600]
            if len(recent) >= self.args.admit_per_hour:
                return None
            self.admissions[net] = recent + [t]
        self.keys[pub] = KeyState(self.args)
        return self.keys[pub]

    # ---------------------------------------------------------------- messages

    async def message(self, c: Client, data: bytes) -> None:
        try:
            m = cs.mb_decode(data)
        except ValueError:
            raise Fatal("MALFORMED") from None
        if m[0] not in cs.MB_SIGNED:  # a handshake or server message type from a client
            raise Fatal("MALFORMED")
        if not c.key.messages.take():
            # Refused before the (costly) signature check; the seq still has to follow.
            if m[1] != c.seq + 1:
                raise Fatal("BAD_SEQUENCE", m[1])
            c.seq = m[1]
            return self.error(c, m[1], "RATE_LIMITED")
        try:
            m = cs.open_signed(data, c.pub, self.server_id, c.nonce_s, c.seq + 1)
        except ValueError as ex:
            reason = str(ex)
            if reason == "bad signature":
                raise Fatal("BAD_SIGNATURE", m[1]) from None
            if reason == "bad sequence":
                raise Fatal("BAD_SEQUENCE", m[1]) from None
            if reason != "bad frame":
                raise Fatal("MALFORMED", m[1]) from None
            c.seq = m[1]
            log(f"{c.name} publish refused: BAD_FRAME")
            return self.error(c, m[1], "BAD_FRAME")
        c.seq = m[1]
        {cs.MB_REGISTER: self.register, cs.MB_WITHDRAW: self.withdraw, cs.MB_REQUEST: self.request,
         cs.MB_PING: self.ping, cs.MB_PUBLISH: self.publish, cs.MB_RESULT: self.result,
         cs.MB_PONG: self.pong}[m[0]](c, m)

    def error(self, c: Client, seq: int, code: str) -> None:
        c.post([cs.MB_ERROR, seq, CODE[code]])

    def register(self, c: Client, m: list[Any]) -> None:
        """09 section 5.2, one status per entry."""
        now = int(time.time())
        self.sweep_regs(now)
        statuses = []
        for entry in m[2]:
            tag = cs.tag_of_pub(entry[0])
            replaces = c.pub in self.regs.get(tag, {})
            # Every entry is charged before its proof is checked, so failing proofs
            # cannot buy unlimited verification time.
            if not c.key.register.take():
                status = "RATE_LIMITED"
            else:
                status = cs.check_entry(entry, self.server_id, c.pub, now)
                if status == "OK" and not replaces and self.live.get(c.pub, 0) >= self.args.reg_max_live:
                    status = "RATE_LIMITED"
            if status == "OK":
                self.regs.setdefault(tag, {})[c.pub] = entry[2]
                if not replaces:
                    self.live[c.pub] = self.live.get(c.pub, 0) + 1
            statuses.append(CODE[status])
        c.post([cs.MB_REGISTERED, m[1], statuses])
        summary = ", ".join(f"{cs.MB_ERRORS[s]} x{statuses.count(s)}" for s in sorted(set(statuses)))
        log(f"{c.name} register {len(statuses)}: {summary}")

    def drop_reg(self, tag: bytes, owner: bytes) -> None:
        owners = self.regs.get(tag)
        if owners is not None and owners.pop(owner, None) is not None:
            self.live[owner] -= 1
            if not self.live[owner]:
                del self.live[owner]
            if not owners:
                del self.regs[tag]

    def sweep_regs(self, now: int) -> None:
        """Registrations are dropped once their expires has passed (09 section 5.3)."""
        for tag in list(self.regs):
            for owner, expires in list(self.regs[tag].items()):
                if expires <= now:
                    self.drop_reg(tag, owner)

    def live_owners(self, tag: bytes, now: int) -> list[bytes]:
        return [o for o, exp in self.regs.get(tag, {}).items() if exp > now]

    def withdraw(self, c: Client, m: list[Any]) -> None:
        n = sum(c.pub in self.regs.get(t, {}) for t in m[2])
        for t in m[2]:
            self.drop_reg(t, c.pub)
        log(f"{c.name} withdraw {len(m[2])} tags, {n} registered")

    def ping(self, c: Client, m: list[Any]) -> None:
        c.post([cs.MB_PONG_S, m[1]])

    def pong(self, c: Client, m: list[Any]) -> None:
        if c.ping is not None and m[2] == c.ping[0]:
            c.rtt_ms = min(cs.RTT_UNKNOWN - 1, now_ms() - c.ping[1])
            c.ping = None

    def publish(self, c: Client, m: list[Any]) -> None:
        """09 sections 4, 6 and 7.2. open_signed has already refused JOIN, downlink
        types, frames failing the keyless checks and repeated rx_refs within the
        message."""
        _, seq, frame, receptions, _ = m
        if not c.key.publish.take():
            log(f"{c.name} publish refused: RATE_LIMITED")
            return self.error(c, seq, "RATE_LIMITED")
        t = now_ms()
        self.sweep_refs(t)
        n, status = self.tx.publish(t, frame, c.name, [(r[0], r[3]) for r in receptions])
        if status == "BAD_FRAME":
            log(f"{c.name} publish refused: BAD_FRAME (rx_ref reused)")
            return self.error(c, seq, "BAD_FRAME")
        if status == "dropped":
            log(f"{c.name} publish of transmission {n} again: dropped")
            return
        tag = frame[2:10]
        owners = self.live_owners(tag, int(time.time()))
        sent, reached = 0, set()
        for owner in owners:
            for oc in self.conns.get(owner, ()):
                oc.post([cs.MB_DELIVER, frame, receptions, c.pseud, c.rtt_ms])
                sent += 1
                reached.add(owner)
        for r in receptions:
            self.refs[r[0]] = {"owners": reached, "at": t, "tag": tag, "publisher": c}
        log(f"{c.name} publish tag {tag.hex()} fcnt {int.from_bytes(frame[10:14], 'big')}, "
            f"{len(receptions)} receptions: {status} transmission {n}, delivered to {sent}")

    def sweep_refs(self, t: int) -> None:
        for ref in [r for r, v in self.refs.items() if t - v["at"] > cs.RX_REF_MS]:
            del self.refs[ref]
            self.requested_by.pop(ref, None)

    def request(self, c: Client, m: list[Any]) -> None:
        """09 section 7.3: the checks in order, then forward."""
        _, seq, rx_ref, downlink, _ = m
        within_rate = c.key.request.take()
        t = now_ms()
        self.sweep_refs(t)
        ref = self.refs.get(rx_ref)
        status = "forward"
        gone = ref is not None and ref["publisher"] not in self.conns.get(ref["publisher"].pub, ())
        if ref is None or c.pub not in ref["owners"] or gone:
            status = "UNKNOWN_RX_REF"  # including a publisher that has gone: nobody to forward to
        elif self.regs.get(ref["tag"], {}).get(c.pub, 0) <= int(time.time()):
            status = "NOT_REGISTRANT"
        else:
            h = cs.parse_header(downlink)
            if h is None or not cs.is_downlink(h.ftype) or downlink[2:10] != ref["tag"]:
                status = "BAD_FRAME"
            else:
                status = self.tx.check_request(t, rx_ref)
                if status == "forward" and not within_rate:
                    status = "RATE_LIMITED"
        if status != "forward":
            log(f"{c.name} request {rx_ref.hex()}: {status}")
            return self.error(c, seq, status)
        forwarded = self.tx.request(t, rx_ref)
        assert forwarded == "forward"
        self.requested_by[rx_ref] = c.pub
        ref["publisher"].post([cs.MB_FORWARD, rx_ref, downlink, c.pseud])
        log(f"{c.name} request {rx_ref.hex()}: forwarded to {ref['publisher'].name}")

    def result(self, c: Client, m: list[Any]) -> None:
        """09 section 7.5: one result per forward, from its publisher, in time."""
        _, _, rx_ref, code, offset_us, _ = m
        t = now_ms()
        if self.tx.result(t, c.name, rx_ref, code) != "accepted":
            log(f"{c.name} result {rx_ref.hex()} {code}: ignored")
            return
        owner = self.requested_by.get(rx_ref)
        sent = 0
        for oc in self.conns.get(owner, ()) if owner else ():
            oc.post([cs.MB_RESULT_S, rx_ref, code, offset_us])
            sent += 1
        name = cs.TX_RESULTS[code] if code < len(cs.TX_RESULTS) else str(code)
        log(f"{c.name} result {rx_ref.hex()} {name}: passed to {sent}")

    async def sweeper(self) -> None:
        while True:
            await asyncio.sleep(SWEEP_INTERVAL_S)
            self.sweep_regs(int(time.time()))
            self.sweep_refs(now_ms())
            t = time.monotonic()
            self.admissions = {n: v for n, v in self.admissions.items() if t - v[-1] < 3600}
            self.keys = {k: v for k, v in self.keys.items() if k in self.conns or t - v.seen < KEY_MEMORY_S}


def source_network(addr: str) -> str:
    """What admission counts by: the address, or its /64 for IPv6, where one
    host commonly holds a whole /64."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return addr
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return str(ip.ipv4_mapped)
        return str(ipaddress.ip_network(f"{ip}/64", strict=False))
    return str(ip)


def load_members(path: str) -> set[bytes]:
    with open(path) as f:
        keys = {bytes.fromhex(line.split("#")[0].strip()) for line in f if line.split("#")[0].strip()}
    if any(len(k) != 32 for k in keys):
        raise ValueError(f"{path}: each line is a 32-byte client public key in hex")
    return keys


def load_seed(path: str | None) -> bytes:
    """The server key's seed. Kept in path if given (created on first start), else
    fresh on every start, which makes clients treat the server as new."""
    if path is None:
        log("No --key-file: using a fresh server key; clients will see a new server_id")
        return secrets.token_bytes(32)
    if os.path.exists(path):
        with open(path) as f:
            seed = bytes.fromhex(f.read().strip())
        if len(seed) != 32:
            raise ValueError(f"{path}: expected 64 hex digits")
        return seed
    seed = secrets.token_bytes(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(seed.hex() + "\n")
    log(f"Created server key {path}")
    return seed


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", action="append", required=True, metavar="NAME",
                    help="a host name clients use in the server's URL, signed in the greeting (repeatable; "
                         "lowercase, A-label form for internationalized names)")
    ap.add_argument("--listen", default="0.0.0.0", help="address to listen on (default 0.0.0.0)")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--tls-cert", metavar="PEM", help="certificate chain for wss://")
    ap.add_argument("--tls-key", metavar="PEM", help="private key for --tls-cert")
    ap.add_argument("--insecure-dev", action="store_true",
                    help="serve plain ws:// without TLS; for tests only, never in production (09 section 12.1)")
    ap.add_argument("--key-file", metavar="FILE", help="server key seed in hex, created if missing")
    ap.add_argument("--members", metavar="FILE",
                    help="admit only these client public keys, one hex key per line (modes 2 and 3)")
    lim = ap.add_argument_group("limits (defaults: mode 4, 09 section 11)")
    lim.add_argument("--reg-burst", type=int, default=2048, help="registrations per owner key, burst")
    lim.add_argument("--reg-per-hour", type=int, default=512, help="registrations per owner key, steady rate")
    lim.add_argument("--reg-max-live", type=int, default=4096, help="live registrations per owner key")
    lim.add_argument("--publish-rate", type=float, default=5, help="publishes per second per client key")
    lim.add_argument("--publish-burst", type=int, default=20, help="publish burst per client key")
    lim.add_argument("--request-rate", type=float, default=10, help="requests per second per client key")
    lim.add_argument("--message-rate", type=float, default=50,
                     help="signed messages of any kind per second per client key (burst twice that)")
    lim.add_argument("--admit-per-hour", type=int, default=20,
                     help="new client keys admitted per source address per hour, without --members")
    ap.add_argument("--ping-interval", type=float, default=PING_INTERVAL_S, help=argparse.SUPPRESS)
    ap.add_argument("--handshake-timeout", type=float, default=10, help=argparse.SUPPRESS)
    args = ap.parse_args(argv)
    if bool(args.tls_cert) != bool(args.tls_key):
        ap.error("--tls-cert and --tls-key go together")
    if not args.tls_cert and not args.insecure_dev:
        ap.error("TLS is required: give --tls-cert and --tls-key (or --insecure-dev for tests)")
    for h in args.host:
        try:
            h.encode("ascii")
        except UnicodeEncodeError:
            ap.error(f"--host {h}: use the A-label (xn--) form")
        if not 0 < len(h) < 256:
            ap.error(f"--host {h}: length out of range")
    return args


async def run(args: argparse.Namespace) -> None:
    mailbox = Mailbox(args, load_seed(args.key_file))
    tls = None
    if args.tls_cert:
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.minimum_version = ssl.TLSVersion.TLSv1_3
        tls.load_cert_chain(args.tls_cert, args.tls_key)
    async with serve(mailbox.handler, args.listen, args.port, ssl=tls, subprotocols=[SUBPROTOCOL],
                     max_size=cs.MB_MAX_MESSAGE, compression=None) as server:
        port = server.sockets[0].getsockname()[1] if server.sockets else args.port
        log(f"cs-mailbox server_id {mailbox.server_id.hex()} generation {mailbox.generation:016x}")
        log(f"Listening on {'wss' if tls else 'ws'}://{args.listen}:{port} for {', '.join(mailbox.hosts)}"
            + ("" if tls else " (INSECURE, development only)"))
        # As PID 1 in a container nothing else turns SIGTERM into an exit.
        stop = asyncio.Event()
        for sig in (signal.SIGTERM, signal.SIGINT):
            asyncio.get_running_loop().add_signal_handler(sig, stop.set)
        sweeper = asyncio.create_task(mailbox.sweeper())
        await stop.wait()
        sweeper.cancel()
        log("Stopping")


def main(argv: list[str] | None = None) -> int:
    asyncio.run(run(parse_args(argv)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
