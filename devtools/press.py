#!/usr/bin/env python3
"""Press buttons and call actions on an ESPHome device over its native API.

    python3 devtools/press.py HOST                         # list buttons and actions
    python3 devtools/press.py HOST "DATA_CONFIRMED" JOIN   # press buttons by name substring
    python3 devtools/press.py HOST --service send_hex data=c512b08e...

Buttons are pressed in order, --gap seconds apart (default 4, or $GAP), so each
downlink window passes before the next frame. Action arguments are converted to
the types the device declares. Requires: pip install aioesphomeapi
"""

from __future__ import annotations

import argparse
import asyncio
import inspect
import os
import sys


async def connect(host: str, port: int = 6053, key: str | None = None):
    from aioesphomeapi import APIClient
    client = APIClient(host, port, None, noise_psk=key or None, client_info="cs-bench")
    await client.connect(login=True)
    return client


def convert(arg_type, value: str):
    """A KEY=VALUE string as the type an action argument declares."""
    from aioesphomeapi import UserServiceArgType as T
    one = {T.BOOL: lambda v: v.lower() in ("1", "true", "yes", "on"), T.INT: int, T.FLOAT: float, T.STRING: str}
    many = {T.BOOL_ARRAY: T.BOOL, T.INT_ARRAY: T.INT, T.FLOAT_ARRAY: T.FLOAT, T.STRING_ARRAY: T.STRING}
    if arg_type in many:
        return [one[many[arg_type]](v) for v in value.split(",") if v]
    return one[arg_type](value)


async def call_service(client, services, name: str, args: dict[str, str]) -> None:
    svc = next((s for s in services if s.name == name), None)
    if svc is None:
        raise SystemExit(f"no action {name!r}; the device has: {', '.join(s.name for s in services) or 'none'}")
    types = {a.name: a.type for a in svc.args}
    unknown = set(args) - set(types)
    if unknown:
        raise SystemExit(f"{name}: unknown argument(s) {', '.join(sorted(unknown))}; it takes {', '.join(types)}")
    r = client.execute_service(svc, {k: convert(types[k], v) for k, v in args.items()})
    if inspect.isawaitable(r):  # a coroutine in newer aioesphomeapi
        await r


async def main(a) -> int:
    from aioesphomeapi import ButtonInfo
    client = await connect(a.host, a.port, a.key)
    try:
        entities, services = await client.list_entities_services()
        buttons = [e for e in entities if isinstance(e, ButtonInfo)]
        if not a.wanted and not a.service:
            for b in buttons:
                print("button", b.key, b.name)
            for s in services:
                print("action", s.name, " ".join(f"{x.name}:{x.type.name.lower()}" for x in s.args))
        for i, w in enumerate(a.wanted):
            b = next((b for b in buttons if w.lower() in b.name.lower()), None)
            if b is None:
                raise SystemExit(f"no button matching {w!r}")
            print("press", b.name, flush=True)
            client.button_command(b.key)
            if i + 1 < len(a.wanted) or a.service:
                await asyncio.sleep(a.gap)
        for i, (name, *kv) in enumerate(a.service or []):
            args = dict(x.split("=", 1) for x in kv)
            print("call", name, " ".join(kv), flush=True)
            await call_service(client, services, name, args)
            if i + 1 < len(a.service):
                await asyncio.sleep(a.gap)
        await asyncio.sleep(0.5)  # let the last command reach the device before disconnecting
    finally:
        await client.disconnect()
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("host")
    ap.add_argument("wanted", nargs="*", metavar="SUBSTRING", help="press the first button whose name contains it")
    ap.add_argument("--port", type=int, default=6053)
    ap.add_argument("--key", help="the device's API encryption key, if it has one")
    ap.add_argument("--gap", type=float, default=float(os.environ.get("GAP", "4")), help="seconds between commands")
    ap.add_argument("--service", nargs="+", action="append", metavar=("NAME", "KEY=VALUE"),
                    help="call an action with arguments (repeatable)")
    try:
        sys.exit(asyncio.run(main(ap.parse_args())))
    except ImportError:
        sys.exit("press.py needs aioesphomeapi: pip install aioesphomeapi")
