# 05 - Proxy Envelope

Status: Draft
Version: 1.0-draft.4

This document defines the messages between a proxy and its owner's server on the
local network: how a proxy delivers the frames it hears, how a server asks a
proxy to transmit a downlink, and how the two keep track of each other. Federation
between homes is defined separately in 09.

## 1. Goals (informative)

- Simple enough for an ESP32 to implement in a few hundred lines.
- No clock synchronization between proxy and server, yet downlinks hit the
  sensor's receive windows.
- A device on the LAN that does not know a proxy's key cannot inject uplinks or
  make a proxy transmit.
- The same bytes work over UDP and MQTT.

## 2. Transports

### 2.1 UDP (default)

- The server listens on UDP port 47800 (configurable).
- A proxy sends each message as one datagram from any local port to the server's
  address and port.
- The server sends messages for a proxy to the source address and port of the
  most recent authenticated message from that proxy.
- A server MAY advertise itself by mDNS/DNS-SD as `_connectsensors._udp`. A proxy
  configured without a server address SHOULD use the first such service it
  finds.

### 2.2 MQTT

- Proxy to server: topic `connectsensors/v1/<proxy_id>/up`.
- Server to proxy: topic `connectsensors/v1/<proxy_id>/down`.
- `<proxy_id>` is 16 lowercase hex digits.
- Payload: one message, exactly as in section 3. QoS 0, not retained.

MQTT adds broker latency. A proxy using MQTT SHOULD NOT advertise downlink
capability unless the broker is on the LAN.

## 3. Message format

Every message, in both directions:

```
Offset  Size  Field
0       1     version   = 1
1       1     msg_type
2       8     proxy_id
10      4     boot_id
14      4     seq
18      N     body
18+N    16    mac       = trunc16(HMAC-SHA256(proxy_key, bytes 0 .. 17+N))
```

`trunc16(x)` is `x[0:16]`.

| Field | Meaning |
|---|---|
| `proxy_id` | The proxy's identifier, in both directions (section 4.1) |
| `boot_id` | Random `uint32` the proxy picks at every boot. Server messages carry the proxy's current `boot_id`. |
| `seq` | Sender's message counter for this `boot_id`, starting at 1. The proxy and the server each keep their own. A `HELLO_REQUEST` carries 0 (section 5.6). |

A receiver MUST discard a message that is shorter than 34 bytes, has an unknown
`version`, or fails the MAC check. MAC comparison MUST be constant-time.

### 3.1 Message types

| `msg_type` | Name | Direction |
|---|---|---|
| `0x01` | `UPLINK` | Proxy to server |
| `0x02` | `HELLO` | Proxy to server |
| `0x03` | `TX_RESULT` | Proxy to server |
| `0x81` | `SERVER_STATUS` | Server to proxy |
| `0x82` | `DOWNLINK` | Server to proxy |
| `0x83` | `HELLO_REQUEST` | Server to proxy |

The high bit gives the direction. A receiver MUST ignore message types it does not
know (after checking the MAC), so new types can be added.

### 3.2 Replay protection and sessions

The server tracks one *session* per proxy: the proxy's current `boot_id` and the
`seq` values in each direction. Neither side persists any of it, and neither
relies on the other's clock. A proxy reboot or a server restart is recovered by a
short handshake instead.

**Server, for messages from a proxy:**

- It keeps the proxy's current `boot_id` and the highest `seq` received for it. It
  MUST discard a message from that boot whose `seq` is not greater, except that it
  MAY accept up to 16 values below the highest that it has not yet seen, to
  tolerate UDP reordering.
- It MUST switch to another `boot_id` only on a `HELLO` from that boot whose
  `request_nonce` equals the nonce of a `HELLO_REQUEST` it sent for that boot
  within the last 30 seconds. The `HELLO`'s `seq` becomes the highest received,
  and the server's own `seq` for the proxy starts again, at 1 or at any higher
  value (section 7).
- Any other message from a `boot_id` that is not current (the proxy rebooted, the
  server restarted, or the message is a replay) changes no state, not even the
  proxy's address. The server answers it with a `HELLO_REQUEST` for that
  `boot_id`, sent to the message's source address. It keeps one nonce per
  `boot_id` for 30 seconds and reuses it for repeated requests, keeps nonces for
  at least the 4 most recent such `boot_id`s per proxy, and sends at most one
  `HELLO_REQUEST` per `boot_id` per second.

A rebooted proxy is therefore known after one extra round trip: `HELLO`,
`HELLO_REQUEST`, `HELLO` echoing the nonce, `SERVER_STATUS`. A restarted server
learns a running proxy's boot the same way from the proxy's next message,
usually an `UPLINK`, rather than waiting for its next periodic `HELLO`.

**Proxy, for messages from the server:**

- It MUST discard a message whose `boot_id` is not its own current `boot_id`.
- It keeps a *floor*: the highest server `seq` accepted in this boot, initially 0.
  It MUST discard a message whose `seq` is not above the floor, with two
  exceptions:
  - A `SERVER_STATUS` whose `hello_seq` (section 5.3) is the `seq` of one of the
    proxy's last 3 `HELLO`s, sent within the last 120 seconds and not echoed by a
    `SERVER_STATUS` it already accepted, is accepted whatever its `seq`, and the
    floor becomes that `seq`. This is how a proxy follows a restarted server,
    whose `seq` starts again at 1, without rebooting.
  - A `HELLO_REQUEST` is not checked against the floor and does not move it
    (section 5.6).
- Accepting a `SERVER_STATUS` either way uses up its `hello_seq`, so a replayed
  copy is held to the floor.

Replayed uplinks would be harmless anyway, since the server's frame counter rules
(02 section 8.5) reject them, but replay protection stops a recorded `DOWNLINK`
from being used to waste a proxy's airtime.

## 4. Proxy identity and keys

### 4.1 `proxy_id`

8 bytes. A proxy SHOULD use an EUI-64 derived from its primary MAC address by
inserting `FFFE` in the middle (MAC `34:85:18:00:00:01` becomes
`348518fffe000001`). It MUST stay the same across reboots and firmware updates.

### 4.2 `proxy_key`

16 bytes, used only for the MAC in this document. It is never used for sensor
frames.

- The server generates a key when the user adds a proxy, and shows it in a form
  ready to paste into the proxy's configuration (06). The server stores it
  against the `proxy_id` once the first `HELLO` with that key arrives.
- A server MAY offer a *shared key*: one key that any proxy may use, for users who
  prefer not to enrol proxies one by one. A server using a shared key MUST show
  each newly seen `proxy_id` to the user and let them block it.
- A proxy that accepts downlinks MUST have its own key, held by no other proxy. A
  shared key is only for proxies configured not to accept downlinks (06 section
  3.2, `downlink.enabled: false`).
- A server MUST NOT send a `DOWNLINK` to a proxy whose key another proxy also
  holds. If such a proxy advertises downlink capability (section 5.2), the server
  MUST warn the user and offer to give it a key of its own.
- Removing a proxy in the server deletes its key; its messages then fail the MAC
  check. A shared key is not deleted when one of its proxies is removed: the
  server blocks that `proxy_id` instead, and the key stays valid for every other
  proxy holding it.

The MAC shows only that the sender holds the key, and `proxy_id`, `boot_id` and
`seq` travel in the clear. Anyone holding a key can therefore send messages as
any proxy that uses it, in either direction. A proxy with its own key is exposed
only if that key leaks. With a shared key, any holder, such as anyone with one of
the proxies that use it, can send uplinks and `HELLO`s in the name of every proxy
on that key, take over their sessions on the server (section 3.2), and send
`DOWNLINK`s to any of them that accepts downlinks. A proxy with downlinks enabled
cannot tell whether its key is shared, so this rule is kept by the user and the
server.

The key is text in the proxy's configuration: 32 hex digits.

## 5. Messages

All lengths are in bytes. Integers are big-endian.

### 5.1 `UPLINK` (0x01)

Sent for each frame that passes the proxy's checks (02 section 12).

```
rx_time_us  uint64  proxy's monotonic microsecond clock at reception
rssi_x10    int16   RSSI in 0.1 dBm
snr_x10     int16   SNR in 0.1 dB
flags       uint8
frame_len   uint8
frame       frame_len bytes, the LoRa frame unchanged
```

`flags`:

| Bit | Name | Meaning |
|---|---|---|
| 0 | `TS_UNCERTAIN` | `rx_time_us` may be late by more than 36 ms (01 section 4, 06 section 7) |
| 1-7 | reserved | 0 |

`rx_time_us` comes from a clock that starts at boot and never jumps. The server
does not interpret it except to hand it back in a `DOWNLINK`.

### 5.2 `HELLO` (0x02)

Sent by the proxy right after boot, then every 60 seconds, and in answer to a
`HELLO_REQUEST` (section 5.6). It doubles as a keepalive and a status report.

```
caps           uint8   bit 0 downlink capable; bits 1-7 reserved (0)
region_len     uint8
region         region profile name (01), ASCII
frequency_hz   uint32
sf             uint8
bw_khz         uint16
uptime_s       uint32
heard          uint32  packets received from the radio since boot
forwarded      uint32  UPLINK messages sent since boot
duplicates     uint32  frames dropped as duplicates
invalid        uint32  packets dropped by the keyless checks
rate_limited   uint32  frames dropped by rate limits
tx_ok          uint32  downlinks transmitted
tx_failed      uint32  downlinks not transmitted, any reason
max_loop_gap_ms uint16 longest main-loop gap since the previous HELLO (06 section 7)
request_nonce  uint32  nonce of the HELLO_REQUEST this answers; 0 if none
fw_len         uint8
fw             firmware name and version, ASCII, for example "cs_proxy 0.1.0"
```

The server SHOULD warn the user if a proxy's region, frequency, spreading factor
or bandwidth does not match the network's region profile, and MUST NOT send
downlinks through such a proxy.

### 5.3 `SERVER_STATUS` (0x81)

Sent by the server in reply to every `HELLO` from the proxy's current boot,
including the one that makes it current (section 3.2), and to every connected
proxy within 10 seconds after each epoch boundary.

```
server_time  uint32  Unix time
hello_seq    uint32  seq of the HELLO this answers; 0 at an epoch boundary
n_tags       uint8   0-32
tags         n_tags x 4 bytes: the net_tag values the server owns for epochs
             e-1, e and e+1, for all its networks
```

The proxy MAY use `tags` for diagnostics, for example to count how many of the
frames it hears belong to its own server's networks. It MUST still send every
frame to its server (02 section 12); federation is the server's job (09 section
5.1).

A proxy that receives no `SERVER_STATUS` for 3 consecutive `HELLO` intervals
considers itself disconnected (shown as a diagnostic, 06). It keeps forwarding
frames to the configured address.

### 5.4 `DOWNLINK` (0x82)

Asks the proxy to transmit a frame.

```
ref_rx_time_us  uint64  rx_time_us of the UPLINK this downlink answers,
                        as reported by this proxy
tx_offset_us    uint32  delay after ref_rx_time_us at which to start transmitting
frame_len       uint8
frame           frame_len bytes
```

- For RX1, `tx_offset_us` = 1 000 000; for RX2, 3 000 000 (01 section 4).
- The proxy transmits at `tx_at = ref_rx_time_us + tx_offset_us` on its own clock.
  No clock synchronization is needed, because both values are in the proxy's
  clock.
- `ref_rx_time_us` MUST come from an `UPLINK` sent by the same proxy in its
  current boot. A server MUST NOT send a downlink to a proxy that did not hear the
  uplink being answered.

A proxy MUST reject a `DOWNLINK`, with the result code given, if:

| Condition | Result |
|---|---|
| The proxy is not downlink capable | `NOT_CAPABLE` |
| The frame fails the keyless checks or its type is not a downlink type (`0x8`-`0xF`) | `INVALID` |
| `tx_at` is more than 5 s in the future | `INVALID` |
| `tx_at` is already more than 40 ms in the past when the message arrives | `TOO_LATE` |
| Transmitting would exceed the proxy's airtime budget (01 section 5) | `DUTY_CYCLE` |
| It overlaps a downlink already scheduled | `BUSY` |

### 5.5 `TX_RESULT` (0x03)

Sent once for every `DOWNLINK` the proxy accepted or rejected.

```
downlink_seq  uint32  seq of the DOWNLINK message
result        uint8
offset_us     int32   time the radio was commanded to transmit minus tx_at,
                      for result SENT; 0 otherwise
```

`offset_us` is taken on the proxy's clock once the frame is in the radio and the
transmit command has been issued. It covers the wait for `tx_at`, any lateness of
the proxy's main loop, and the time to load the frame and command the radio. It
excludes the radio's own ramp-up from that command to the first preamble symbol on
air, so it is not an on-air time. Because the window check (06 section 8.2) runs
before the radio is loaded, a `SENT` close to the window's end can report slightly
more than 40 000.

For scale (informative): a Heltec WiFi LoRa 32 V3 (SX1262 with TCXO) on a healthy
main loop reports a steady `offset_us` of about 1 800, most of it the frame load and
the radio's transmit command.

| `result` | Name | Meaning |
|---|---|---|
| 0 | `SENT` | Transmission started within the window |
| 1 | `TOO_LATE` | The window had passed |
| 2 | `BUSY` | The radio or the schedule was busy until the window closed |
| 3 | `DUTY_CYCLE` | Airtime budget exhausted |
| 4 | `NOT_CAPABLE` | Downlinks disabled on this proxy |
| 5 | `INVALID` | Frame or timing parameters invalid |
| 6 | `RADIO_ERROR` | The radio reported an error |

Servers use `offset_us` and the result codes to decide which proxies to trust for
RX1 (07).

### 5.6 `HELLO_REQUEST` (0x83)

Asks the proxy for a `HELLO` echoing a nonce, so the server can start a session
with the proxy's boot (section 3.2).

```
nonce  uint32  random, not 0
```

The header's `seq` is 0; the proxy does not check it. The proxy accepts a
`HELLO_REQUEST` that passes the MAC check, carries its current `boot_id`, and has
a 4-byte body with a nonce other than 0. It then sends a `HELLO` with that
`request_nonce`:

- at once, unless it sent a `HELLO` in answer to a `HELLO_REQUEST` within the last
  5 seconds; then when those 5 seconds are up;
- echoing the most recent nonce, if several requests arrive meanwhile.

That `HELLO` counts as the periodic one: the next follows 60 seconds later.

## 6. Sizes (informative)

| Message | Size |
|---|---|
| `UPLINK` with an 86-byte frame | 134 bytes |
| `HELLO` | about 104 bytes |
| `DOWNLINK` with an 86-byte frame | 133 bytes |

All messages fit in one UDP datagram with no fragmentation on any normal network.

## 7. Security considerations

| Concern | Handling |
|---|---|
| Fake uplinks injected on the LAN | MAC with the proxy key; and the frames themselves are authenticated end to end (02) |
| Using a proxy as a jammer | `DOWNLINK` requires the proxy key, and a proxy that accepts downlinks has a key of its own (section 4.2), so no other proxy's key reaches it; a server flags a proxy left on a shared key with downlinks enabled; replay protection; frames must be valid downlink-type frames; airtime budget |
| Reading traffic on the LAN | Envelopes are not encrypted. They expose what a proxy already exposes over the air: frame bytes, signal strength and timing. |
| Stolen proxy with its own key | It holds only its own key, which lets the thief act as that proxy alone. Removing the proxy in the server revokes it. |
| Stolen proxy with a shared key | The thief can act as every proxy on that key: send uplinks and `HELLO`s in their names, and keep taking over their sessions (section 3.2) so that the server discards their messages while it holds them. It can make one of them transmit only if that proxy was left with downlinks enabled against section 4.2, which the server flags; sensor frames stay authenticated end to end (02). Blocking the stolen `proxy_id` does not revoke the key: the user replaces the shared key on every proxy that uses it. |
| Replaying an old `HELLO` to move the server to a stale boot or address | The server switches boot only on a `HELLO` echoing a `HELLO_REQUEST` nonce from the last 30 seconds (section 3.2). A recorded `HELLO` carries an old nonce or none, and messages from other boots change no state. This holds right after a server restart too. |
| Replaying a `HELLO_REQUEST` | It is checked only for the MAC and the proxy's `boot_id`, so it can be replayed within a boot. It can only make the proxy send a `HELLO`, at most one per 5 seconds beyond its periodic ones. The `HELLO` goes to the configured server, not to the request's source. |
| Replaying server messages after a server restart | Once the proxy has followed the restarted server, its floor is the new server's low `seq`. A message the old server instance sent in this boot with a higher `seq` would pass the check again, until the new `seq` overtakes it. A `DOWNLINK` among them targets a time in this boot that has long passed, so the proxy rejects it as `TOO_LATE` without transmitting. A `SERVER_STATUS` only refreshes diagnostics. A server MAY start its `seq` above any value it used before, for example from its clock, to close this window. |

## 8. Test vectors

`vectors/proxy-envelope-v1.json` has one message of each type, built with a fixed
key and `proxy_id`. The `UPLINK` and `DOWNLINK` carry frames from
`vectors/frame-v1.json`. The reference tool also checks that a one-bit change to
any message fails the MAC check.

Its `session` sequence walks section 3.2 from both ends: a boot handshake, a
replayed `HELLO` from an earlier boot, a server restart recovered by
`HELLO_REQUEST` and the `SERVER_STATUS` echo, and replays of each kind of
message. Each step gives the time, the message, which side receives it and that
side's result. Its nonces are fixed so the sequence is reproducible; real nonces
are random.
