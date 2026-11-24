#!/usr/bin/env python3
"""cs-mailbox behind a TLS-terminating reverse proxy (--trusted-proxy, 09 section
12.1): only the proxy may use the plain port, and admission counts clients by the
address the proxy reports, never by headers from anyone else.

The proxy is played by crafted request headers from 127.0.0.1; an untrusted peer
connects from 127.0.0.2, which Linux routes over loopback like 127.0.0.1.

    python3 tests/federation/test_trusted_proxy.py

Requires: cryptography, websockets.
"""

from __future__ import annotations

import asyncio
import os
import secrets
import socket
import sys
import time

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "spec", "tools"))
sys.path.insert(0, os.path.join(ROOT, "tests", "devtools"))
sys.path.insert(0, os.path.join(ROOT, "devtools"))
import cs_testserver as ts  # noqa: E402
from procwatch import Watched  # noqa: E402
from websockets.exceptions import InvalidStatus  # noqa: E402

MAILBOX = os.path.join(ROOT, "mailbox", "cs_mailbox.py")
UNTRUSTED = "127.0.0.2"
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


async def attempt(url: str, headers: dict[str, str] | list[tuple[str, str]] | None = None,
                  source: str | None = None) -> str:
    """Connect with a new key: "welcome", the refusal's error name, or "http <status>"
    if the server refused the WebSocket handshake itself."""
    args: dict[str, object] = {}
    if headers:
        args["additional_headers"] = headers
    if source:
        args["local_addr"] = (source, 0)
    lk = ts.MailboxLink(url, secrets.token_bytes(32), insecure=True, **args)
    try:
        await lk.connect()
    except InvalidStatus as ex:
        return f"http {ex.response.status_code}"
    except ConnectionError as ex:
        return str(ex).removeprefix("refused: ")
    await lk.close()
    return "welcome"


def xff(addr: str) -> dict[str, str]:
    return {"X-Forwarded-For": addr}


async def trusted_proxy(p: Watched, url: str) -> None:
    """Against --trusted-proxy 127.0.0.1/32 --admit-per-hour 2."""
    mark = p.mark()
    got = [await attempt(url, xff("198.51.100.9, 203.0.113.1")) for _ in range(3)]
    check(got == ["welcome", "welcome", "NOT_PERMITTED"],
          f"the rightmost X-Forwarded-For entry is the client: its third new key is refused {got}")
    check(p.wait_for(r"welcome from 203\.0\.113\.1 via 127\.0\.0\.1:\d+", since=mark) is not None,
          "the log names the forwarded client and the proxy")
    got = [await attempt(url, xff("203.0.113.2")) for _ in range(2)]
    check(got == ["welcome", "welcome"], f"another forwarded address has its own admission budget {got}")
    got = [await attempt(url, [("X-Forwarded-For", "203.0.113.1"), ("X-Forwarded-For", "203.0.113.3")])]
    check(got == ["welcome"], f"of repeated X-Forwarded-For headers, the last entry counts {got}")
    mark = p.mark()
    got = [await attempt(url, {"X-Real-IP": "2001:db8::1"})]
    check(got == ["welcome"] and p.wait_for(r"welcome from 2001:db8::1 via", since=mark) is not None,
          f"without X-Forwarded-For, X-Real-IP is the client {got}")

    # A malformed value falls back to the proxy's own address, which plain
    # connections without headers also count against.
    mark = p.mark()
    got = [await attempt(url, xff("203.0.113.4, not-an-address")),
           await attempt(url, {"X-Real-IP": "300.1.2.3"}),
           await attempt(url)]
    check(got == ["welcome", "welcome", "NOT_PERMITTED"],
          f"malformed X-Forwarded-For or X-Real-IP falls back to the proxy's address {got}")
    check(p.wait_for(r"malformed X-Forwarded-For 'not-an-address', using the proxy's address", since=mark)
          is not None, "a malformed header is logged")


async def untrusted_peer(p: Watched, url: str) -> None:
    mark = p.mark()
    got = [await attempt(url, source=UNTRUSTED), await attempt(url, xff("127.0.0.1"), source=UNTRUSTED)]
    check(got == ["http 403", "http 403"],
          f"a peer outside the trusted ranges is refused before the WebSocket handshake, "
          f"whatever its X-Forwarded-For says {got}")
    check(p.wait_for(rf"{UNTRUSTED}: not a trusted proxy, refused", since=mark) is not None,
          "the refusal is logged")
    time.sleep(0.2)
    n = sum("not a trusted proxy" in line for line in p.lines[mark:])
    check(n == 1, f"repeated refusals of one peer are logged once ({n})")


async def headers_ignored_without_proxy(url: str) -> None:
    """Against --insecure-dev --admit-per-hour 2: no proxy is trusted, so no
    header is read."""
    got = [await attempt(url, xff(f"203.0.113.{i}")) for i in (10, 11, 12)]
    check(got == ["welcome", "welcome", "NOT_PERMITTED"],
          f"without --trusted-proxy, X-Forwarded-For is ignored: admission counts the peer {got}")


def can_bind(addr: str) -> bool:
    try:
        with socket.socket() as s:
            s.bind((addr, 0))
        return True
    except OSError:
        return False


def refuses(*args: str, pattern: str, what: str) -> None:
    p = Watched([sys.executable, "-I", MAILBOX, "--host", "127.0.0.1", "--port", "0", *args])
    check(p.wait_for(pattern) is not None, what)
    p.stop()


def main() -> int:
    procs: list[Watched] = []
    try:
        p, port = start("--host", "127.0.0.1", "--trusted-proxy", "127.0.0.1/32", "--admit-per-hour", "2")
        procs.append(p)
        check(p.wait_for(r"Listening on ws://127\.0\.0\.1:\d+ for 127\.0\.0\.1 behind trusted proxies 127\.0\.0\.1/32$")
              is not None, "the startup line says the server is behind trusted proxies")
        url = f"ws://127.0.0.1:{port}/"
        asyncio.run(trusted_proxy(p, url))
        if can_bind(UNTRUSTED):
            asyncio.run(untrusted_peer(p, url))
        else:
            print(f"skip untrusted peer: cannot bind {UNTRUSTED} on this system", flush=True)

        p2, port2 = start("--host", "127.0.0.1", "--insecure-dev", "--admit-per-hour", "2")
        procs.append(p2)
        asyncio.run(headers_ignored_without_proxy(f"ws://127.0.0.1:{port2}/"))

        refuses("--trusted-proxy", "127.0.0.1/32", "--tls-cert", "c.pem", "--tls-key", "k.pem",
                pattern=r"--trusted-proxy is its own mode", what="--trusted-proxy with --tls-cert will not start")
        refuses("--trusted-proxy", "127.0.0.1/32", "--insecure-dev",
                pattern=r"--trusted-proxy is its own mode", what="--trusted-proxy with --insecure-dev will not start")
        refuses("--trusted-proxy", "proxy.lan",
                pattern=r"--trusted-proxy proxy\.lan: not an address range", what="a malformed range will not start")
    finally:
        outs = [p.stop() for p in procs]
    if failures:
        for out in outs:
            print("--- cs-mailbox ---\n" + out.strip())
    print("all checks pass" if failures == 0 else f"{failures} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
