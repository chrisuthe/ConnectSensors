# connectsensors

The [ConnectSensors](https://github.com/chrisuthe/ConnectSensors) v1 protocol for
Python network servers: sensor frames, the proxy envelope and sessions, uplink
deduplication, JOIN handling, reading payloads and pairing codes.

```
pip install connectsensors
```

Python 3.13 or later. The only dependency is `cryptography`.

The code is the specification's reference implementation,
[`spec/tools/csframe.py`](https://github.com/chrisuthe/ConnectSensors/blob/main/spec/tools/csframe.py),
shipped unchanged as `connectsensors._csframe`; the test vectors are generated and
verified with the same file. Where it disagrees with the
[specification](https://github.com/chrisuthe/ConnectSensors/tree/main/spec), the
specification wins. `connectsensors` re-exports the supported surface under
csframe's names, so code reads the same as the spec's examples. The package is
typed (`py.typed`).

The protocol is a draft, and so is this API: expect breaking changes before 1.0.

**0.4.0 breaks pairing compatibility.** Frame tags are now one 8-byte key
fingerprint instead of `net_tag` and `dev_tag`, the network key and `SET_NETWORK`
are gone, and pairing ends on the first session uplink instead of a `SYNC` and
`SET_NETWORK`. A server on 0.4.0 can't pair or read sensors built for 0.3.x, and the
other way round: re-flash the sensors and proxies, then pair the sensors again.

## API

Section numbers refer to the specification documents.

**Radio profiles (01).** `region_airtime_ms(region, frame_len)` is a frame's time on
air in a region profile (`"US915"`, `"EU868"`), in ms, and raises `ValueError` for any
other name. `REGIONS` maps each profile to its spreading factor and bandwidth in Hz.
`airtime_ms(payload_len, sf, bw_hz, ...)` is the underlying Semtech formula. The
rolling-hour budgets of 01 section 5 are `SENSOR_AIRTIME_MS_PER_HOUR` (36 s) and
`PROXY_AIRTIME_MS_PER_HOUR` (72 s); a server can sum `region_airtime_ms` over the
downlinks it sent through a proxy in the last hour to stay under the proxy's.

**Frames (02).** `keys_from(base, dev_eui)` derives a `DeviceKeys` from `k_root` or
`k_session`. `seal(keys, ftype, tag, fcnt, plaintext)` builds a frame;
`open_frame(keys, frame)` checks its MIC and returns `(ParsedHeader, plaintext)`, or
raises `ValueError` with the reason. `parse_header(frame)` does a proxy's keyless
checks and returns `None` for anything that isn't a v1 frame, including type `0x0`.
Tags (02 section 6) are 8-byte key fingerprints: `normal_tag(keys.k_dev_tag,
epoch_of(unix))` for normal frames, `bootstrap_tag(keys.k_dev_tag, fcnt)` for `JOIN`
and `SYNC` (`is_bootstrap(ftype)`), and `uplink_tag(keys, ftype, fcnt, unix)` picks
one. A downlink carries the tag of the uplink it answers. The steps are exposed too:
`epoch_index`, `block_index`, `tag_seed`, `ed25519_pub`, `tag_of_pub` and
`tag(k_dev_tag, index)`. Downlinks:
`downlink_payload(reply_to, server_time, flags, commands)` and `command(cmd_id, args)`.
Key exchange: `x25519_pub(priv)`, `derive_session(...)`. Constants: frame types
`T_*`, uplink and downlink flags `UF_*` and `DF_*`, commands `CMD_*`, sizes
`HEADER_LEN`, `MIC_LEN`, `MAX_PAYLOAD`, `MIN_FRAME`, `MAX_FRAME`.

**Payloads (03).** `decode_readings(data)` returns one dict per reading (`channel`,
`kind`, `name`, `value`) and keeps unknown kinds as hex. It raises `ValueError` for
an invalid payload: truncated, kind `0x00`, or a repeated `(channel, kind)`.
`encode_reading(channel, kind, value)` encodes one. `KINDS` maps kind codes to names. `unwrap(...)` unwraps
16-bit counters.

**Pairing (04).** `qr_parse(code)` returns `dev_eui`, `k_root` (hex), `region` and
`profile`, or raises `ValueError` with the reason; `qr_encode(...)` builds a code.
`JoinResponder(k_root, dev_eui, root_fcnt_down, pending=None)` answers JOINs for one
device: `join(frame, server_priv, server_time)` returns `action` (`"new_exchange"` or
`"resend"`), `frame`, `k_session` and `stalled`. Persist its `root_fcnt_down` and keep
it after the device is removed: the root counter never resets. A retransmitted JOIN
gets the cached answer back byte for byte. Call `paired()` once the first uplink
under the pending `k_session` verifies: the device is then `PAIRED` (04 section 4.2),
and that uplink is answered like any other.

The cached answer is `pending`, a `PendingExchange` (`sensor_pub`, `frame`,
`k_session`, `retransmissions`, `sent`), or `None`. Persist it whenever `join()` or
`sent()` changes it, a new exchange before its frame is sent (04 section 4.6, 07
section 10), and pass it back as `pending=` after a restart. `to_dict()` and
`PendingExchange.from_dict(d)` convert it to and from JSON-safe values; `k_session`
is in there, so store it as a secret.

`stalled` turns true on the `JOIN_STALL_RETRANSMISSIONS`th (3) retransmission of
the pending exchange's JOIN (07 section 5.1). The spec counts only retransmissions that
arrive after the KEY_EXCHANGE was reported `SENT`. To follow it, construct with
`count_after_sent=True` and call `sent(frame)` on a `TX_RESULT` `SENT` for that
downlink; it returns whether `frame` is the pending exchange's, so a late result for
an older one changes nothing. Without `count_after_sent`, every retransmission counts.

**Proxy envelope (05).** `open_envelope(key, data)` checks the MAC and returns `type`,
`proxy_id` (hex), `boot_id`, `seq` and `body` (hex); `envelope(key, type, proxy_id,
boot_id, seq, body)` builds one. Bodies: `parse_uplink`, `parse_hello`,
`parse_tx_result` for messages from a proxy; `server_status_body`,
`hello_request_body`, `downlink_msg_body` for messages to it (and the inverse of each,
for tests). Message types `M_*`, capabilities `CAP_*`, `UPF_TS_UNCERTAIN`.

`ServerLink(new_nonce)` is a server's session with one proxy, in memory only. Feed it
every opened envelope with a monotonic millisecond clock; `receive` returns
`{"result": ...}`:

- `accepted`: a message of the current session; handle it.
- `switched`: a HELLO echoing the server's nonce started a session with a new boot;
  handle it (answer the HELLO).
- `hello_request`: a boot the server has no session with; send a `M_HELLO_REQUEST`
  carrying `nonce` to the sender, with that message's `boot_id` and seq 0.
- `ignored`: a replay, or a rate-limited request; drop it.

Number the messages you send with `next_seq()`. `new_nonce` returns a random nonzero
32-bit nonce.

**Network server (07).** `UplinkCollector(first_fcnt)` per device groups copies of a
transmission heard by several proxies and decides when to answer: `receive(frame,
arrived_ms)` returns `{"result": "copy"}` for a copy of a transmission already
handled, or `{"result": "transmission", "counter": "accept" | "accept_late" |
"duplicate" | "too_old", "answer": bool}`. A retransmitted confirmed frame is answered
again, up to `MAX_ANSWERS_AGAIN` times. `UplinkCounter` is its counter check alone.
Persist `collector.counter.last` and `collector.counter.seen` (the late arrivals
accepted below it; 07 section 10) and restore with `UplinkCollector(last, seen)`, or
`UplinkCounter(last, seen)`. Which copies were merged is held in memory only.

`TagTable()` maps tags to devices (07 section 3). Call `update(device, k_dev_tag,
epoch, last_fcnt)` whenever a device's session key or `last_fcnt` changes and at each
epoch boundary; it keeps the normal tags of `epoch - 1` to `epoch + 1` and the `SYNC`
tags of the block holding `last_fcnt` and the `SYNC_BLOCKS_AHEAD` (2) after it. For an
`EXCHANGED` device, use the pending `k_session`. `identify_route(table, frame, local)`
says how to find a frame's device: `("table", candidates)` to try in turn,
`("fallback", [])` for a locally heard `JOIN` or `SYNC` that missed the table, which
is identified by trial decryption under the bootstrap limit (07 section 4), or
`("drop", [])`.

`CommandAcks()` per device settles queued commands on `DL_ACK` (07 section 7). Call
`downlink(reply_to, commands)` for each downlink sent with commands, and
`uplink(fcnt, counter, dl_ack)` for each frame the collector accepts; it returns the
commands that frame marks delivered. Only an uplink whose `fcnt` is above the
downlink's `reply_to` settles anything, so a late arrival or a federated copy of an
earlier frame cannot. `downlink()` raises `ValueError` if commands ride on an answer
to a late arrival. Persist `reply_to`, `awaiting` and `last_fcnt` and restore with
`CommandAcks(reply_to, awaiting, last_fcnt)`.

**For tests.** `ProxyLink(boot_id)` is the proxy's side of the envelope session and
`SensorPairing(k_root, dev_eui)` the sensor's side of pairing, including the
provisional state before the first session downlink, so a
server's tests can simulate both on the public API.

## Server-side example

One proxy, one paired device whose session key is known. Error handling and the tag
table are left out.

```python
import secrets
import time

import connectsensors as cs

proxy_key = bytes.fromhex("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a")
link = cs.ServerLink(lambda: secrets.randbits(32) or 1)
session = cs.keys_from(k_session, dev_eui)
uplinks = cs.UplinkCollector(first_fcnt)
fcnt_down = 0


def handle(data: bytes, reply) -> None:
    global fcnt_down
    m = cs.open_envelope(proxy_key, data)  # raises ValueError on a bad MAC
    pid = bytes.fromhex(m["proxy_id"])
    now_ms = time.monotonic_ns() // 1_000_000
    got = link.receive(m, now_ms)

    def send(msg_type: int, body: bytes) -> None:
        reply(cs.envelope(proxy_key, msg_type, pid, m["boot_id"], link.next_seq(), body))

    if got["result"] == "hello_request":
        reply(cs.envelope(proxy_key, cs.M_HELLO_REQUEST, pid, m["boot_id"], 0,
                          cs.hello_request_body(got["nonce"])))
        return
    if got["result"] == "ignored":
        return

    body = bytes.fromhex(m["body"])
    if m["type"] == cs.M_HELLO:
        send(cs.M_SERVER_STATUS, cs.server_status_body(int(time.time()), m["seq"]))
    elif m["type"] == cs.M_UPLINK:
        u = cs.parse_uplink(body)
        h = cs.parse_header(u["frame"])
        if h is None:
            return
        got = uplinks.receive(u["frame"], now_ms)
        if got["result"] == "copy" or got["counter"] == "too_old":
            return
        h, plaintext = cs.open_frame(session, u["frame"])
        if h.ftype in (cs.T_DATA, cs.T_DATA_CONFIRMED):
            print(cs.decode_readings(plaintext[1:]))  # after the uplink flags byte
        if got["answer"]:
            fcnt_down += 1  # persist it
            ack = cs.seal(session, cs.T_DOWNLINK, h.tag, fcnt_down,
                          cs.downlink_payload(h.fcnt, int(time.time()), 0))
            send(cs.M_DOWNLINK, cs.downlink_msg_body(u["rx_time_us"], 1_000_000, ack))  # RX1
```

The development server,
[`devtools/cs_testserver.py`](https://github.com/chrisuthe/ConnectSensors/blob/main/devtools/cs_testserver.py),
is a complete example, including pairing.

## Development

The package is built from the repository root (`pyproject.toml`). There is no copy of
the protocol code under `python/`: the wheel takes `spec/tools/csframe.py` and installs
it as `connectsensors/_csframe.py`. Change the protocol there, and keep the names this
package re-exports. An editable install (`pip install -e .`) has no `_csframe.py`, so
it loads `spec/tools/csframe.py` in place.

```
tests/package/check.sh
```

builds the sdist and the wheel (from the sdist), installs the wheel into a clean
Python 3.13 venv, runs `tests/package/smoke_test.py` against it from outside the
checkout, runs `tests/package/api_test.py` the same way, and type-checks both with
`mypy --strict --warn-unreachable`. It needs
[uv](https://docs.astral.sh/uv/).

## Releasing

The version lives in `python/connectsensors/__init__.py` (`__version__`). Bump it,
merge, then push a tag `v<version>`; the `Release` workflow
(`.github/workflows/release.yml`) checks that the tag matches, builds, and publishes
to PyPI with trusted publishing. No API token is stored anywhere.

One-time setup, before the first release:

1. On PyPI, under *Your projects → Publishing*, add a **pending publisher** (GitHub):
   - PyPI project name: `connectsensors`
   - Owner: `chrisuthe`
   - Repository name: `ConnectSensors`
   - Workflow name: `release.yml`
   - Environment name: `pypi`
2. On GitHub, under *Settings → Environments*, create the environment `pypi`.
   Optionally restrict it to `v*` tags and require a reviewer.

The first tagged release creates the project on PyPI and turns the pending publisher
into a regular one.
