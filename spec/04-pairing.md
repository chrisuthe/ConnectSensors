# 04 - Pairing

Status: Draft
Version: 1.0-draft.1

This document defines the pairing code a sensor ships with, how a server and
sensor go from "never met" to "paired", how a device leaves a network, and how a
network key is rotated. The frames involved are defined in 02.

## 1. Goals (informative)

- One scan and one button press.
- The pairing code is the only secret a user handles.
- A sensor paired a second time, for example after being sold, starts a session
  the previous owner cannot read, even if they kept the code.
- Works with no internet connection.

## 2. Device identity material

Each sensor is provisioned, at manufacture or when flashed, with:

| Item | Size | Rules |
|---|---|---|
| `dev_eui` | 8 bytes | Unique. MAY be the MCU's or radio's EUI-64, or random. |
| `k_root` | 16 bytes | From a cryptographically secure RNG. Unique per device. |
| Region profile | name | The radio profile the firmware is built for (01). |
| Device profile | identifier | The model's profile (03 section 9). |

`k_root` MUST be stored where the sensor's firmware can read it but users cannot
read it over the air. It MUST NOT be changed by a factory reset.

## 3. Pairing code

### 3.1 Format

```
CS:1:<DEV_EUI>:<K_ROOT>:<REGION>:<PROFILE>:<CHECK>
```

| Field | Encoding |
|---|---|
| `CS` | Literal |
| `1` | Pairing code version |
| `DEV_EUI` | 16 uppercase hex digits |
| `K_ROOT` | 26 characters: RFC 4648 base32, uppercase, padding removed |
| `REGION` | Region profile name, for example `US915` |
| `PROFILE` | Device profile identifier (03 section 9.1) |
| `CHECK` | 4 uppercase hex digits: the first 2 bytes of SHA-256 over everything before the last `:` |

Example (the test vector key, never use it on a real device):

```
CS:1:C5C5000000000001:AAAQEAYEAUDAOCAJBIFQYDIOB4:US915:CS.CONTACT-1:C1FB
```

Every character is in the QR code alphanumeric set (`0-9 A-Z $%*+-./:` and
space), so the code fits a compact QR code (version 4 at error correction level
M).

### 3.2 Parsing

A server MUST:

1. Convert the input to uppercase and remove surrounding whitespace.
2. Reject it unless it has exactly 7 fields separated by `:` and starts with
   `CS`.
3. Reject an unknown version.
4. Reject it if `CHECK` does not match, with a message suggesting the user
   re-scan or re-type it.
5. Reject it if `DEV_EUI` is not 16 hex digits, `K_ROOT` is not 26 valid base32
   characters, or `PROFILE` is not a valid identifier.
6. Warn, and require confirmation, if `REGION` differs from the network's region.

The checksum catches typing mistakes. It gives no security.

### 3.3 Where the code goes

- The code is a credential. It SHOULD be printed inside the battery compartment
  or on an insert, not on the outside of the case.
- It MAY also be stored in an NFC tag as an NDEF text record with the same
  string.
- Servers MUST NOT log the code or `k_root`, and MUST store `k_root` only in
  their protected key storage.

## 4. Pairing procedure

### 4.1 Overview

```
User            Server                          Sensor
 | scan code ->   | device: SCANNED              |
 | press button ---------------------------------> |
 |                | <---- JOIN (root keys, sensor_pub)
 |                | KEY_EXCHANGE (root keys, server_pub) ---->
 |                | device: EXCHANGED            | derives k_session
 |                | <---- SYNC (session keys, DL_ACK)
 |                | SET_NETWORK (session keys) --------------->
 |                | device: PAIRED               | uses normal tags
 |                | <---- HEARTBEAT (full state) |
```

All four frames before the heartbeat are confirmed exchanges using bootstrap
tags, so any of the owner's proxies can carry them. On US915 the exchange
normally completes within 5 seconds.

### 4.2 Server states per device

| State | Entered when | Leaves when |
|---|---|---|
| `SCANNED` | The user enters a valid pairing code | A `JOIN` from the device verifies, or 10 minutes pass (device discarded) |
| `EXCHANGED` | The server sends `KEY_EXCHANGE` | An uplink with normal tags and `DL_ACK` acknowledges `SET_NETWORK` (`PAIRED`), or 2 minutes pass (back to `SCANNED`, keeping the 10-minute deadline) |
| `PAIRED` | As above | The device is removed (section 6) |

While a device is `EXCHANGED`, the server MUST also go on accepting a
retransmitted `JOIN` and answer it with the same `KEY_EXCHANGE` (same
`server_pub`), because the sensor may not have received the first answer.

A server MUST NOT have more than one pending session per device. A new `JOIN`
with a different `sensor_pub` replaces the pending exchange.

### 4.3 Sensor states

| State | Behavior |
|---|---|
| `UNPAIRED` | No session. Sends `JOIN` when the user presses the pairing button (section 4.5). |
| `JOINING` | Has sent `JOIN` and holds its ephemeral private key. |
| `SESSION` | Has `k_session`, no `k_net_route` yet. Sends `SYNC` to fetch `SET_NETWORK`. |
| `PAIRED` | Has `k_session` and `k_net_route`. Normal operation (08). |

### 4.4 Steps

1. **Scan.** The user enters the code in the server (for example, scanning it
   with the Home Assistant companion app). The server parses it (3.2), derives
   the root key set (02 section 5.1) and puts the device in `SCANNED`. If a
   device with that `dev_eui` is already paired, the server MUST ask the user
   whether to re-pair it, and on confirmation keep the old record until the new
   pairing completes.
2. **JOIN.** The user presses the sensor's pairing button. The sensor generates
   a fresh X25519 key pair, sends `JOIN` (02 section 11.1) under its root key set
   with bootstrap tags, and enters `JOINING`. It resets its stored last-accepted
   `fcnt_down` to 0.
3. **KEY_EXCHANGE.** The server identifies the frame by trying the root key sets
   of `SCANNED` devices (02 section 11.3). It generates its own ephemeral key
   pair, derives `k_session` (02 section 5.3), resets the device's `fcnt_down`,
   and answers with a `DOWNLINK` under the root key set, bootstrap tags,
   `reply_to` = the `JOIN`'s `fcnt`, containing `KEY_EXCHANGE`. It keeps its
   ephemeral private key only until `k_session` is derived.
4. **Session.** The sensor accepts the downlink (02 section 10.2), derives
   `k_session`, erases its ephemeral private key, switches to the session key
   set, and enters `SESSION`.
5. **SYNC.** The sensor sends `SYNC` under the session key set with `DL_ACK` set
   (it accepted a command).
6. **SET_NETWORK.** The server identifies the `SYNC` by trying the session key
   sets of `EXCHANGED` and `PAIRED` devices and answers with a `DOWNLINK`
   containing `SET_NETWORK` and the current `server_time`.
7. **Paired.** The sensor stores `k_net_route`, enters `PAIRED`, computes normal
   tags from `server_time`, and sends a confirmed uplink with `DL_ACK` set. This
   SHOULD be a `HEARTBEAT_CONFIRMED` with its full state (03 section 5), unless a
   state change is already waiting to be sent. When that uplink verifies, the
   server marks the device `PAIRED`, discards any old record kept in step 1, and
   creates its entities.

Retries and timeouts within each step follow the confirmed-uplink rules in 08.
If the sensor gets no answer to `JOIN` after its retries, it MUST discard the
ephemeral key pair and return to `UNPAIRED`. Pressing the button again starts
over with a new key pair.

### 4.5 Pairing button

- A short press while `UNPAIRED` starts pairing.
- A short press while `PAIRED` SHOULD send a `DATA_CONFIRMED` with the current
  state, so the user can test range without disturbing anything.
- A long press (RECOMMENDED: 10 seconds) is a factory reset (section 6.2).
- A sensor MUST NOT send `JOIN` on its own while `UNPAIRED`, except that it MAY
  send one `JOIN` after its very first power-on, to make out-of-the-box pairing
  one step shorter.

### 4.6 Persistence

The sensor MUST write `k_session`, `k_net_route` and its state to non-volatile
storage before sending the uplink in step 7, and MUST NOT write the ephemeral
private key to non-volatile storage at all. The server MUST persist `k_session`
and the device record before answering in step 6.

## 5. Proxies during pairing (informative)

Proxies forward `JOIN` and `SYNC` like any other uplink and transmit the answers
like any other downlink. Relays cannot route bootstrap frames (02 section 11.4),
so at least one of the owner's own proxies MUST be within range of the sensor
during pairing. Users can pair a sensor next to a proxy and then install it.

## 6. Leaving a network

### 6.1 Removal by the owner

When the user removes a device in the server:

1. If the device is reachable, the server queues `LEAVE` and sends it in reply
   to the device's next uplink.
2. The sensor, on accepting `LEAVE`, erases `k_session` and `k_net_route`,
   returns to `UNPAIRED`, and sends nothing more until its button is pressed.
3. The server deletes the device record when the next uplink acknowledges
   `LEAVE` with `DL_ACK`, or after 48 hours, whichever comes first. The user MAY
   delete it immediately; the sensor then keeps sending frames that nobody reads
   until it is reset.

### 6.2 Factory reset on the device

A factory reset erases `k_session`, `k_net_route` and user settings, and returns
the sensor to `UNPAIRED`. It MUST NOT erase `dev_eui`, `k_root`, or the frame
counter reservation (02 section 8.2). The old server sees the device go silent
and raises its supervision alarm (07) until the user removes it.

### 6.3 Changing owners

The new owner scans the same pairing code and pairs normally. The new session is
independent of the old one. The previous owner, if they still hold the code,
cannot read the new session passively, but could try to interfere actively
during the pairing (02 section 13). A new owner who wants to rule that out
re-flashes the device with a new `k_root` and a new pairing code.

## 7. Network key rotation

The owner can replace `k_net`, for example after a server compromise or simply
on a schedule.

1. The server generates a new `k_net` and its `k_net_route`.
2. For every paired device it queues `SET_NETWORK` with the new routing key and
   sends it in reply to the device's next uplink.
3. Until every device has acknowledged the new key with `DL_ACK`, or for 7 days,
   whichever is shorter, the server recognizes both the old and the new
   `net_tag`s and gives both sets to its proxies (05).
4. Devices that never acknowledge within 7 days are marked as needing attention.
   They can still reach the server with `SYNC`, which is identified without a
   network tag, and get the new key in reply.

`k_session` is not affected by network key rotation. To renew a device's
session, the owner re-pairs it.

## 8. Security considerations

| Concern | Handling |
|---|---|
| Someone sees the pairing code | They can attempt an active attack during a future pairing, nothing more (02 section 13). Keep the code inside the case. |
| Someone records the pairing exchange | Without the ephemeral private keys they cannot derive `k_session`, even with `k_root`. |
| Rogue `JOIN` frames | Only devices in `SCANNED` are tried, so an attacker needs a code the user has just scanned. Bootstrap processing is rate-limited (02 section 11.3). |
| Replayed `KEY_EXCHANGE` | Rejected by `reply_to` binding (02 section 10.2). |
| Pairing to the wrong network | The user scans a specific code; a sensor only accepts a `KEY_EXCHANGE` answering its own `JOIN` under its own `k_root`. |
| Ephemeral key left in storage | Forbidden (4.6). |

## 9. Test vectors

- `vectors/pairing-v1.json`: pairing codes that MUST parse, with their fields,
  and codes that MUST be rejected, with the reason.
- `vectors/frame-v1.json`: the complete pairing exchange from `JOIN` to
  `SET_NETWORK`, with fixed ephemeral keys so the frames are reproducible.
