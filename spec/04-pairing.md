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
  the previous owner cannot read, even if they kept the code. A factory reset
  before the new pairing erases the previous owner's keys from the device.
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
space), so the code fits a compact QR code at error correction level M. The
example (72 characters) fits version 4. A code with a 32-character profile
identifier is 92 characters, more than version 4 holds (90), and needs version 5
(up to 122).

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
| `EXCHANGED` | The server sends `KEY_EXCHANGE` | An uplink with normal tags and `DL_ACK` acknowledges `SET_NETWORK` as in 07 section 7 (`PAIRED`), a `JOIN` with a new `sensor_pub` verifies (a new pending exchange, and `EXCHANGED` again), or 2 minutes pass (back to `SCANNED`, keeping the 10-minute deadline) |
| `PAIRED` | As above | The device is removed (section 6) |

A device has at most one *pending exchange*: the `sensor_pub` of the `JOIN` it
answers, the `KEY_EXCHANGE` frame the server built for it, and the `k_session`
derived from it. The server keeps it while the device is `SCANNED` or
`EXCHANGED`, including after `EXCHANGED` times out back to `SCANNED`, and discards
it when the device is `PAIRED` or discarded.

- A `JOIN` whose `sensor_pub` equals the pending exchange's is a retransmission,
  because a sensor never reuses an ephemeral key (02 section 5.3). The server
  MUST answer it with the cached `KEY_EXCHANGE` frame, byte for byte: same root
  counter value, same `server_pub`, same `server_time`. It MUST NOT build a new
  frame, change `k_session` or reset any counter. The sensor may simply not have
  received the first answer, and resending the same bytes is not nonce reuse. A
  replayed `JOIN` therefore cannot knock a pairing in progress off its key.
- A `JOIN` with a different `sensor_pub` replaces the pending exchange with a new
  one, built with the next root counter value (02 section 8.4).

If the sensor keeps retransmitting a `JOIN` that has been answered, the exchange
has stalled; the server tells the user what to do (07 section 5.1).

### 4.3 Sensor states

| State | Behavior | Leaves when |
|---|---|---|
| `UNPAIRED` | No session. Sends `JOIN` when the user presses the pairing button (section 4.5). | The button is pressed (`JOINING`) |
| `JOINING` | Has sent `JOIN` and holds its ephemeral private key. | It accepts `KEY_EXCHANGE` (`SESSION`), or the `JOIN` goes unanswered (`UNPAIRED`, section 4.4) |
| `SESSION` | Has `k_session`, no `k_net_route` yet. Sends `SYNC` to fetch `SET_NETWORK`. | It accepts `SET_NETWORK` (`PAIRED`), pairing fails (below), or it accepts `LEAVE` (`UNPAIRED`, section 6.1) |
| `PAIRED` | Has `k_session` and `k_net_route`. Normal operation (08). | It accepts `LEAVE` (`UNPAIRED`, section 6.1) |

A factory reset (section 6.2) returns the sensor to `UNPAIRED` from every state.
Every other return to `UNPAIRED` keeps the root floor.

**Pairing fails in `SESSION`.** The sensor MUST erase `k_session` and return to
`UNPAIRED` when:

- a `SYNC` goes unanswered after its retries (08 section 5); or
- 4 `SYNC`s in all have been answered without `SET_NETWORK`. After each such
  answer the sensor sends a new `SYNC` (a new `fcnt`); it MUST NOT send more
  than 4 in one `SESSION`, not counting retries (08 section 5).

The user then presses the button again, which starts over with a new key pair.
These `SYNC`s do not count as undelivered uplinks for 08 section 6, which applies
to a paired sensor.

Each `SYNC` and its retries take under a minute (08 section 5), so a sensor
leaves `SESSION` within a few minutes at most. The server stops identifying the
device's `SYNC` when its `EXCHANGED` state times out after 2 minutes (section 4.2,
07 section 4), so a sensor still in `SESSION` by then gets no answer and fails as
above; a sensor never waits in `SESSION` for a server that has given up.

**Restart.** Only `PAIRED` is kept across a restart (section 4.6). A sensor that
restarts in `JOINING` or `SESSION` MUST come back in `UNPAIRED`, keeping its root
floor; the ephemeral private key and any `k_session` from the unfinished pairing
are gone. The next button press sends a `JOIN` with a new `sensor_pub`, which
replaces the server's pending exchange (section 4.2).

### 4.4 Steps

1. **Scan.** The user enters the code in the server (for example, scanning it
   with the Home Assistant companion app). The server parses it (3.2), derives
   the root key set (02 section 5.1) and puts the device in `SCANNED`. If a
   device with that `dev_eui` is already paired, the server MUST ask the user
   whether to re-pair it, and on confirmation keep the old record until the new
   pairing completes.
2. **JOIN.** The user presses the sensor's pairing button. The sensor generates
   a fresh X25519 key pair, sends `JOIN` (02 section 11.1) under its root key set
   with bootstrap tags, and enters `JOINING`. It keeps its root floor (02 section
   8.4): only a factory reset clears it.
3. **KEY_EXCHANGE.** The server identifies the frame by trying the root key sets
   of `SCANNED` and `EXCHANGED` devices (02 section 11.3). It generates its own
   ephemeral key pair, derives `k_session` (02 section 5.3), and answers with a
   `DOWNLINK` under the root key set, bootstrap tags, the next value of the
   device's root downlink counter, `reply_to` = the `JOIN`'s `fcnt`, containing
   `KEY_EXCHANGE`. It keeps its ephemeral private key only until `k_session` is derived, and the
   frame and `k_session` as the pending exchange (4.2). The session downlink
   counter for the new `k_session` starts at 1. A retransmitted `JOIN` is
   answered as in 4.2.
4. **Session.** The sensor accepts the downlink (02 section 10.2), which
   requires its counter to be above the root floor, and stores that counter as
   the new root floor. It derives `k_session`, erases its ephemeral private key,
   sets its session floor to 0, switches to the session key set, and enters
   `SESSION`.
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
- A short press while `JOINING` or `SESSION` MUST NOT send a frame or change the
  pairing state. Pairing is already under way and ends on its own (section 4.3),
  after which a press starts over. Restarting `JOIN` instead would discard an
  exchange that may be about to complete and spend a root counter value on the
  server (02 section 8.4) for every press.
- Holding the button for 10 seconds is a factory reset (section 6.2), in every
  state. The sensor MUST carry out the reset when the 10 seconds have passed,
  while the button is still held, and SHOULD confirm it (08 section 11) so the
  user knows to let go. A press released earlier is not a reset.
- A sensor MUST NOT send `JOIN` on its own while `UNPAIRED`, except that it MAY
  send one `JOIN` after its very first power-on, to make out-of-the-box pairing
  one step shorter.

10 seconds is long enough that a short press, a press held while fitting the
batteries or mounting the device, or a child playing with it does not erase the
pairing by accident, and short enough to do on purpose without a tool. A device
whose only button is hard to hold that long MAY use another physical gesture
(for example holding the button while inserting the batteries), but the reset
MUST need physical access: no command or frame can trigger it.

### 4.6 Persistence

The sensor MUST write its new root floor to non-volatile storage before sending
`SYNC` in step 5. It MUST write `k_session`, `k_net_route` and its state to
non-volatile storage before sending the uplink in step 7, and MUST NOT write the
ephemeral private key to non-volatile storage at all.

The server MUST persist the root counter reservation (02 section 8.4) and the
pending exchange (4.2) before sending `KEY_EXCHANGE` in step 3, so that a
restart cannot make it answer a retransmitted `JOIN` with a different frame. It
MUST persist `k_session` and the device record before answering in step 6.

## 5. Proxies during pairing (informative)

Proxies forward `JOIN` and `SYNC` like any other uplink and transmit the answers
like any other downlink. Relays cannot route bootstrap frames (02 section 11.4),
so pairing works only with at least one of the owner's own proxies within range
of the sensor. Users can pair a sensor next to a proxy and then install it.

## 6. Leaving a network

### 6.1 Removal by the owner

When the user removes a device in the server:

1. If the device is reachable, the server queues `LEAVE` and sends it in reply
   to the device's next uplink.
2. The sensor, on accepting `LEAVE`, erases `k_session` and `k_net_route`,
   returns to `UNPAIRED`, and sends nothing more until its button is pressed.
   A `PAIRED` sensor first acknowledges it in one final `HEARTBEAT` (08 section
   8). A sensor in `SESSION` erases `k_session` at once and sends nothing: it has
   no `k_net_route` yet, so it cannot compute the normal tags that heartbeat
   needs.
3. The server deletes the device record when an uplink acknowledges `LEAVE`
   with `DL_ACK` (07 section 7), or after 48 hours, whichever comes first. The user MAY
   delete it immediately; the sensor then keeps sending frames that nobody reads
   until it is reset.

`LEAVE` does not clear the sensor's root floor, and deleting the record does not
clear the server's root downlink counter for the device (02 section 8.4), so the
same server can pair the device again without a factory reset.

### 6.2 Factory reset on the device

A factory reset (the 10-second hold of 4.5) returns the sensor to `UNPAIRED`. It
MUST erase:

- `k_session`, `k_net_route`, and any ephemeral private key held while `JOINING`;
- the root floor and the session floor (02 section 8.4);
- all other pairing state and user settings, such as the heartbeat interval and
  values set by application commands.

It MUST NOT erase `dev_eui`, `k_root`, or the uplink counter reservation (02
section 8.2). The old server sees the device go silent and raises its
supervision alarm (07) until the user removes it.

Erasing the keys is also a privacy property: once reset, the device holds
nothing of its previous owner's network. In particular `k_net_route` is gone, so
whoever gets the device next cannot extract it and use it to recognize the
previous owner's devices by their network tags.

Clearing the root floor is what lets a different server pair the device: its
root downlink counter starts again at 1 (02 section 8.4). The cost, reuse of root
nonce values across servers, is accepted in 02 section 13.1.

### 6.3 Changing owners

A change of owner REQUIRES a factory reset (6.2) before the new owner pairs the
device. The reset erases the previous owner's keys (6.2) and clears the root
floor, without which the sensor would reject the new server's `KEY_EXCHANGE`
(its root counter starts below the floor). A new server that sees the exchange
stall prompts the user to do the reset (07 section 5.1). Settings do not carry
over: the new owner's server or device profile sets them.

The previous owner SHOULD remove the device from their server first (6.1). The
new owner then scans the same pairing code and pairs normally. The new session is
independent of the old one. The previous owner, if they still hold the code,
cannot read the new session passively, but could try to interfere actively
during the pairing (02 section 13). A new owner who wants to rule that out
re-flashes the device with a new `k_root` and a new pairing code.

The same applies when the owner's own server loses its state, for example Home
Assistant reinstalled, or restored from a backup older than the last pairing:
its root downlink counter has rolled back, and the sensor needs a factory reset
before it pairs again.

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
| Rogue `JOIN` frames | Only devices in `SCANNED` or `EXCHANGED` are tried, so an attacker needs a code the user has just scanned. Bootstrap processing is rate-limited (02 section 11.3). |
| Replayed `KEY_EXCHANGE` | Rejected by `reply_to` binding and the root floor (02 section 10.2). |
| Nonce reuse under `k_root` | The server's root downlink counter never resets, and a retransmitted `JOIN` gets the identical frame (4.2). Reuse across servers after a factory reset is accepted (02 section 13.1). |
| Replayed `JOIN` | While the exchange is pending, it draws the identical frame and changes nothing (4.2). Otherwise it is not answered (07 section 4, step 5). |
| Previous owner's keys on a sold device | Erased by the factory reset a change of owner requires (6.2, 6.3). |
| Pairing to the wrong network | The user scans a specific code; a sensor only accepts a `KEY_EXCHANGE` answering its own `JOIN` under its own `k_root`. |
| Ephemeral key left in storage | Forbidden (4.6). |

## 9. Test vectors

- `vectors/pairing-v1.json`: pairing codes that MUST parse, with their fields,
  and codes that MUST be rejected, with the reason.
- `vectors/pairing-v1.json` (`root_floor`): a sensor's root floor across a
  re-pairing with the same server, a `KEY_EXCHANGE` from a server whose counter
  rolled back (discarded), a replayed one (discarded), and a factory reset after
  which a new server's root downlink 1 is accepted.
- `vectors/server-v1.json` (`join`): a server answering `JOIN`: retransmissions
  answered with the identical frame and `k_session`, the stall flagged on the
  last retry, and new `sensor_pub` values and re-pairing taking the next root
  counter value.
- `vectors/frame-v1.json`: the complete pairing exchange from `JOIN` to
  `SET_NETWORK`, with fixed ephemeral keys so the frames are reproducible.
