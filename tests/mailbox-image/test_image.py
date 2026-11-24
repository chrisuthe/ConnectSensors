#!/usr/bin/env python3
"""The cs-mailbox container image: build it, run it with built-in TLS and behind a
(simulated) trusted proxy, and drive two clients through greeting, auth, register,
publish and deliver in each. Also checks the user, the key in /data across a
restart, the healthcheck, and that arguments win over CS_MAILBOX_* variables.

    python3 tests/mailbox-image/test_image.py

CONTAINER_ENGINE picks docker or podman (default docker). IMAGE skips the build
and tests that image instead.

Requires: cryptography, websockets, and the engine.
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "tests", "federation"))
sys.path.insert(0, os.path.join(ROOT, "mailbox"))
import container_entry  # noqa: E402
import test_mailbox as tm  # noqa: E402  the federation harness's client helpers
from test_mailbox import cs, entry, expect, frame, link, rx, self_signed  # noqa: E402

ENGINE = os.environ.get("CONTAINER_ENGINE", "docker")
TAG = "cs-mailbox:smoke-test"
RUN = secrets.token_hex(4)
failures = 0


def check(cond: bool, what: str) -> bool:
    global failures
    print(("ok   " if cond else "FAIL ") + what, flush=True)
    failures += not cond
    return cond


def engine(*args: str, check_rc: bool = True) -> str:
    r = subprocess.run([ENGINE, *args], capture_output=True, text=True)
    if check_rc and r.returncode:
        raise RuntimeError(f"{ENGINE} {' '.join(args)}: exit {r.returncode}\n{r.stdout}{r.stderr}")
    return r.stdout.strip()


def build() -> str:
    image = os.environ.get("IMAGE")
    if image:
        return image
    # podman's default OCI format drops HEALTHCHECK
    fmt = ["--format", "docker"] if os.path.basename(ENGINE) == "podman" else []
    subprocess.run([ENGINE, "build", *fmt, "-f", "mailbox/Dockerfile", "-t", TAG, "."], cwd=ROOT, check=True)
    return TAG


def entry_args() -> None:
    b = container_entry.build
    env = {"CS_MAILBOX_HOST": "a.example, b.example", "CS_MAILBOX_PORT": "9000",
           "CS_MAILBOX_TLS_CERT": "/tls/c.pem", "CS_MAILBOX_TLS_KEY": "/tls/k.pem", "CS_MAILBOX_MEMBERS": ""}
    check(b(env, []) == ["--key-file", "/data/server.key", "--host", "a.example", "--host", "b.example",
                         "--port", "9000", "--tls-cert", "/tls/c.pem", "--tls-key", "/tls/k.pem"],
          "entrypoint: variables become options, comma-separated ones repeated, empty ones skipped")
    check(b(env, ["--host=c.example", "--port", "9001"]) ==
          ["--key-file", "/data/server.key", "--tls-cert", "/tls/c.pem", "--tls-key", "/tls/k.pem",
           "--host=c.example", "--port", "9001"],
          "entrypoint: an option given as an argument drops its variable")
    check(b(env | {"CS_MAILBOX_TRUSTED_PROXY": "10.0.0.0/8"}, ["--insecure-dev"]) ==
          ["--key-file", "/data/server.key", "--host", "a.example", "--host", "b.example", "--port", "9000",
           "--insecure-dev"],
          "entrypoint: a mode given as an argument drops every TLS and proxy variable")


def start(name: str, image: str, *args: str, env: dict[str, str], publish: bool = True,
          mounts: tuple[str, ...] = ()) -> None:
    opts = ["--name", name, "-d"]
    opts += ["-p", "127.0.0.1::8443"] if publish else ["--network", "host"]
    for k, v in env.items():
        opts += ["-e", f"{k}={v}"]
    for m in mounts:
        opts += ["-v", m]
    engine("run", *opts, image, *args)


def wait_log(name: str, pattern: str, timeout: float = 20) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        r = subprocess.run([ENGINE, "logs", name], capture_output=True, text=True)
        if pattern in r.stdout + r.stderr:
            return True
        if engine("inspect", "--format", "{{.State.Running}}", name) != "true":
            return False
        time.sleep(0.3)
    return False


def healthy(name: str, timeout: float = 40) -> bool:
    if os.path.basename(ENGINE) == "podman":
        # podman runs checks from systemd timers, absent in some CI containers: run one.
        return subprocess.run([ENGINE, "healthcheck", "run", name], capture_output=True).returncode == 0
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = engine("inspect", "--format", "{{json .State.Health.Status}}", name)
        if json.loads(status) == "healthy":
            return True
        time.sleep(1)
    return False


def host_port(name: str) -> int:
    return int(engine("port", name, "8443/tcp").splitlines()[0].rsplit(":", 1)[1])


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def exchange(url: str, cafile: str | None = None,
                   headers: dict[str, str] | None = None) -> tuple[bytes, int]:
    """Greeting and auth for two clients, then an owner registers a tag, a publisher
    publishes a frame under it, and the owner gets it. The server_id and generation."""
    extra = {"additional_headers": headers} if headers else {}
    owner, pub = (tm.ts.MailboxLink(url, secrets.token_bytes(32), cafile=cafile, insecure=url.startswith("ws:"),
                                    **extra) for _ in range(2))
    for lk in (owner, pub):
        await lk.connect()
    check(owner.pseudonym == cs.pseudonym(owner.server_id, owner.pub) and pub.server_id == owner.server_id,
          "two clients pass greeting and auth")
    await owner.send([cs.MB_REGISTER, [entry(owner)]])
    reg = await expect(owner, cs.MB_REGISTERED)
    check(reg is not None and reg[2] == [0], f"the owner registers its tag {reg and reg[2]}")
    f = frame(1)
    await pub.send([cs.MB_PUBLISH, f, [rx()]])
    d = await expect(owner, cs.MB_DELIVER, 5)
    check(d is not None and d[1] == f, "the publisher's frame is delivered to the owner")
    sid, gen = owner.server_id, owner.generation
    for lk in (owner, pub):
        await lk.close()
    return sid, gen


def tls_mode(image: str, work: str) -> None:
    cert, key = self_signed(work)
    # The container's user must read them through the bind mount.
    os.chmod(work, 0o755)
    for p in (cert, key):
        os.chmod(p, 0o644)
    name, volume = f"cs-mailbox-tls-{RUN}", f"cs-mailbox-data-{RUN}"
    env = {"CS_MAILBOX_HOST": "localhost", "CS_MAILBOX_TLS_CERT": "/tls/cert.pem",
           "CS_MAILBOX_TLS_KEY": "/tls/key.pem"}
    mounts = (f"{work}:/tls:ro,z", f"{volume}:/data")
    try:
        start(name, image, env=env, mounts=mounts)
        check(wait_log(name, "Listening on wss://0.0.0.0:8443 for localhost"),
              "built-in TLS from CS_MAILBOX_* variables: listening on wss://")
        check(engine("exec", name, "id", "-u") == "10001", "runs as uid 10001")
        check(subprocess.run([ENGINE, "exec", name, "test", "-s", "/data/server.key"]).returncode == 0,
              "the server key is in /data")
        check(healthy(name), "healthy with built-in TLS")
        url = f"wss://localhost:{host_port(name)}/"
        sid, gen = asyncio.run(exchange(url, cafile=cert))
        engine("stop", name)
        engine("rm", name)
        start(name, image, env=env, mounts=mounts)
        wait_log(name, "Listening on")

        async def again() -> None:
            lk = await link(f"wss://localhost:{host_port(name)}/", cafile=cert)
            check(lk.server_id == sid and lk.generation != gen,
                  "a new container on the same /data volume: the same server_id, a new generation")
            await lk.close()
        asyncio.run(again())
    finally:
        dump(name)
        engine("rm", "-f", name, check_rc=False)
        engine("volume", "rm", "-f", volume, check_rc=False)


def proxy_mode(image: str) -> None:
    # Host networking, so the "proxy" (this test, adding X-Forwarded-For) connects
    # from 127.0.0.1 whatever the engine's port driver does with source addresses.
    name, port = f"cs-mailbox-proxy-{RUN}", free_port()
    # The TLS variables are set as a compose file might; the mode in the arguments wins.
    env = {"CS_MAILBOX_PORT": str(port), "CS_MAILBOX_TLS_CERT": "/tls/cert.pem", "CS_MAILBOX_TLS_KEY": "/tls/key.pem"}
    try:
        start(name, image, "--host", "127.0.0.1", "--listen", "127.0.0.1", "--trusted-proxy", "127.0.0.1/32",
              env=env, publish=False)
        check(wait_log(name, f"Listening on ws://127.0.0.1:{port} for 127.0.0.1 behind trusted proxies 127.0.0.1/32"),
              "trusted-proxy mode from arguments, over TLS variables: listening on ws://")
        check(healthy(name), "healthy in trusted-proxy mode")
        asyncio.run(exchange(f"ws://127.0.0.1:{port}/", headers={"X-Forwarded-For": "203.0.113.7"}))
        check(wait_log(name, "welcome from 203.0.113.7 via 127.0.0.1", 5), "the forwarded client address is used")
    finally:
        dump(name)
        engine("rm", "-f", name, check_rc=False)


def dump(name: str) -> None:
    if failures:
        r = subprocess.run([ENGINE, "logs", name], capture_output=True, text=True)
        print(f"--- {name} ---\n{(r.stdout + r.stderr).strip()}", flush=True)


def main() -> int:
    if shutil.which(ENGINE) is None:
        print(f"{ENGINE} not found; set CONTAINER_ENGINE", file=sys.stderr)
        return 2
    entry_args()
    image = build()
    work = tempfile.mkdtemp()
    try:
        tls_mode(image, work)
        proxy_mode(image)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    print("all checks pass" if failures == 0 else f"{failures} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
