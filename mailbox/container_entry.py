#!/usr/bin/env python3
"""The container's entrypoint: cs_mailbox.py with the server key in /data, options
from CS_MAILBOX_* variables, then the container's own arguments.

    CS_MAILBOX_HOST           --host, comma-separated for several names
    CS_MAILBOX_PORT           --port (also the port the healthcheck probes)
    CS_MAILBOX_TLS_CERT       --tls-cert
    CS_MAILBOX_TLS_KEY        --tls-key
    CS_MAILBOX_TRUSTED_PROXY  --trusted-proxy, comma-separated for several ranges
    CS_MAILBOX_MEMBERS        --members

Arguments win: a variable is dropped when the arguments give its option, and the
TLS and proxy variables all are when the arguments choose a mode themselves, so
variables baked into a compose file never collide with a mode given on the
command line. An empty variable counts as unset.
"""

from __future__ import annotations

import os
import sys

MAILBOX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cs_mailbox.py")
KEY_FILE = "/data/server.key"
# variable, option, comma-separated
ENV = [
    ("CS_MAILBOX_HOST", "--host", True),
    ("CS_MAILBOX_PORT", "--port", False),
    ("CS_MAILBOX_TLS_CERT", "--tls-cert", False),
    ("CS_MAILBOX_TLS_KEY", "--tls-key", False),
    ("CS_MAILBOX_TRUSTED_PROXY", "--trusted-proxy", True),
    ("CS_MAILBOX_MEMBERS", "--members", False),
]
MODE = {"--tls-cert", "--tls-key", "--trusted-proxy", "--insecure-dev"}


def build(environ: dict[str, str], argv: list[str]) -> list[str]:
    given = {a.split("=", 1)[0] for a in argv if a.startswith("--")}
    out = ["--key-file", KEY_FILE]
    for var, opt, multi in ENV:
        value = environ.get(var, "").strip()
        if not value or opt in given or (opt in MODE and given & MODE):
            continue
        for v in (s.strip() for s in value.split(",")) if multi else [value]:
            if v:
                out += [opt, v]
    return out + argv


def main() -> None:
    args = [sys.executable, "-I", MAILBOX, *build(dict(os.environ), sys.argv[1:])]
    os.execv(sys.executable, args)


if __name__ == "__main__":
    main()
