# 09 - Federation Through Mailboxes

Status: Draft
Version: 1.0-draft.2

This document specifies how ConnectSensors homes carry each other's frames
through *mailbox servers*: how an owner proves which frames are its own, how a
mailbox routes each frame to its owner alone, how a neighbor's proxy transmits a
downlink for someone else's sensor, and the protocol between them.

Federation is optional and off by default. Nothing in 00-08 depends on it.
Pairing is never federated (section 8).

## 1. Goals (informative)

- A paired sensor that only a neighbor's proxy can hear still reaches its owner,
  and can be answered in RX2.
- A mailbox routes each frame to its owner without knowing who the owner is,
  holding no device keys and reading no payloads.
- Only the holders of a device's session key set can receive its frames from a
  mailbox, or ask a publisher to answer them (section 13.1).
- Anyone can run a mailbox, and no central coordinator is needed.
- Works behind NAT: every home connects outward to its mailboxes.

## 2. Modes and roles

### 2.1 Operating modes

| Mode | Mailbox server | Membership | Uplinks | Downlinks (acks, commands) |
|---|---|---|---|---|
| 1 Standalone | none | - | own proxies | own proxies |
| 2 Private | a group's own server | invite or admin | routed | yes |
| 3 Public | a large operator's server | operator accounts | routed | yes |
| 4 Open | any server | none | routed | yes, best effort (section 13.1) |

Modes 2-4 use the same protocol (section 12) and the same reference server,
`cs-mailbox`. They differ only in admission and policy (section 11).

### 2.2 Roles

| Role | Who | Does |
|---|---|---|
| Publisher | A home server | Publishes frames its proxies heard that are not its own (section 6), and optionally transmits federated downlinks through its proxies (section 7.4). |
| Owner | A home server | Registers the tags of its own devices (section 5), receives their frames, and may request downlinks (section 7). |
| Mailbox server | `cs-mailbox` or another implementation of this document | Routes frames by tag to their registrants, and requests and results between owners and publishers. Stores no frames: only registrations, and for a minute at most the transmissions and `rx_ref`s of section 7.2. |

A home server is usually both publisher and owner, on one connection with one
key. Proxies take no part in federation: they send every frame to their own
server (02 section 12, 06), which decides what to publish.

### 2.3 Keys and identifiers

| Item | Definition |
|---|---|
| Server key | The mailbox server's long-term Ed25519 key pair (RFC 8032). |
| `server_id` | `SHA-256(server_pub)`, 32 bytes, where `server_pub` is the server key's 32-byte public key. It names the server in every signature bound to it. |
| Client key | Each home's long-term Ed25519 key pair for one mailbox server, generated when the home first connects to it and kept for as long as it uses that server. A home uses a different client key on each server. As an owner this is the *owner key* (section 5.4). |
| Pseudonym | `trunc64(SHA-256("cs1 mbx pseud" \| server_id \| client_pub))`, 8 bytes. The only name the server shows one client for another. |
| `generation` | A `uint64` the server picks at random whenever its registration table starts empty (section 5.3). |
| `rx_ref` | 8 random bytes naming one reception on one server (section 6.2). |

`trunc64(x)` is `x[0:8]`. SHA-256 is FIPS 180-4.

## 3. Tags

Every frame's header carries one 8-byte routing `tag`, derived per device from
the key set the frame is sent under. 02 section 6.1 defines it; in short:

```
index = "e" | uint32(epoch)              normal frames
      | "b" | uint32((fcnt - 1) / 64)    bootstrap frames (JOIN, SYNC)
seed  = HMAC-SHA256(k_dev_tag, "cs1 tag seed" | index)       32 bytes
pub   = Ed25519 public key for the private key seed (RFC 8032 section 5.1.5)
tag   = trunc64(SHA-256("cs1 tag fp" | pub))
```

`seed` is an Ed25519 private key. Whoever holds the key set can derive it and
sign with it. A mailbox server never sees `seed` or the key set: it is given
`pub`, computes `tag` from it, and checks a signature made with `seed`
(section 5.1).

Federation uses two kinds of tag:

- **Normal tags,** for epoch `x`, from the session key set.
- **`SYNC` tags,** for block `n`, from the session key set. A `SYNC` block
  covers `fcnt` values `64n + 1` to `64n + 64`.

`JOIN` tags derive from the root key set and are never registered (section 8).

## 4. Mailbox routing

A mailbox server keeps a registration table from `tag` to the owner keys that
registered it, each with an expiry (section 5).

- When a publisher publishes a frame (section 6), the server reads its `tag`
  (header bytes 2 to 9) and delivers the frame to every owner key with a live
  registration for that tag that is connected at that moment (section 12.5,
  `deliver`). A frame whose tag has no live registration is dropped.
- The server MUST NOT deliver a frame to anyone else, and MUST NOT store frames.
  A frame for an owner that is not connected is dropped.
- The server holds no device keys and reads no payloads.

Two devices can share a tag: for `T` live tags, about `T^2 / 2^65` collisions are
expected. Each registrant receives the frame and its MIC decides (07 section 4);
a frame that verifies for none of an owner's devices is dropped there.

## 5. Registration

### 5.1 The proof

To register a tag, an owner presents the tag's `pub` and a signature made with
its `seed`:

```
reg_msg = "cs1 reg" | server_id | owner_pub | uint32(expires)     75 bytes
proof   = Ed25519-Sign(seed, reg_msg)                              64 bytes
entry   = (pub, proof, expires)
```

- `server_id` is the server's (section 2.3), as presented and proved in its
  greeting (section 12.3). A proof made for one server is useless on another.
- `owner_pub` is the 32-byte public owner key that the registering connection
  authenticated with (section 12.3). A proof made for one owner is useless to
  another.
- `expires` is a Unix time in seconds (00 section 3).

Entries travel in a `register` message (section 12.5). That whole message,
including its type, its sequence number and every entry, is also signed by the
owner key (the outer signature, section 12.4), so a registration cannot be
replayed on another connection, reordered, or cut from its message.

Someone who has only heard a tag cannot register it: they would need a `pub`
whose fingerprint matches, which is a 64-bit preimage, and then its private key.
Only the sensor and its home server hold the session key set, so only they can
register a device's normal and `SYNC` tags.

### 5.2 Verification

For each entry, the server:

1. Checks that `pub` is a canonical encoding of a point that is not of small
   order (below).
2. Computes `tag = trunc64(SHA-256("cs1 tag fp" | pub))`.
3. Verifies `proof` over `reg_msg`, built from its own `server_id`, the
   connection's owner key and the entry's `expires`, with the strict rules below.
4. Checks `expires` (section 5.3).
5. Applies the owner key's limits (section 5.4).
6. Stores `tag -> (owner key, expires)`, replacing any registration of the same
   tag by the same owner key.

It answers with one status per entry (section 12.5, `registered`). One failed
entry does not affect the others.

**Strict verification.** An Ed25519 verification under this document MUST
fail unless all of these hold:

- `pub` and the signature's `R` decode as points under RFC 8032 section 5.1.3,
  with canonical encodings: the encoded `y` is less than `p = 2^255 - 19`, and
  the sign bit is 0 when `x` is 0 (RFC 8032 requires this; some verifiers skip
  it).
- `S`, read as a little-endian integer, is less than `L = 2^252 +
  27742317777372353535851937790883648493` (RFC 8032 section 5.1.7; older
  verifiers skip it).
- Neither `pub` nor `R` is of small order: `[8]P` is not the neutral element.
  This is an addition to RFC 8032.
- The cofactorless equation `[S]B = R + [k]A` holds, with `k = SHA-512(R | pub |
  msg)` reduced modulo `L`. RFC 8032 allows either this or the cofactored
  equation; this document requires the cofactorless one, so every conforming
  verifier gives the same answer.

This removes the malleability and the small-order forgeries that lax verifiers
accept. The vectors include a non-canonical `S` and a small-order `pub`, each
with a signature that a lax verifier accepts (section 14).

**Brute force (informative).** An attacker can try random seeds until a `pub`
fingerprints to *some* live tag. Against `T` live tags this costs about `2^64 / T`
key generations, hours to days of GPU time at `T` = 10^6 when incrementing a
scalar, and buys one random device's `rx_ref`s until that registration expires,
at most two epochs. A radio
attacker targeting a device it hears faces about 2^54 work within one epoch.
This is accepted.

### 5.3 Lifetime and `generation`

A proof is valid whenever it is presented; there is no registration deadline.
A registration lasts until its `expires`, whether or not the owner stays
connected.

| Tag | Registered | `expires` |
|---|---|---|
| Normal, epoch `x` | Epochs `e - 1` to `e + 2` are kept registered, where `e` is the owner's current epoch. At each epoch boundary the owner registers the new `e + 2`. | MUST NOT be later than the end of epoch `x + 1`, `3600 (x + 2)` |
| `SYNC`, block `n` | The window of section 5.5 | MUST NOT be more than 7 days after the registration is sent. Renewed while the block stays in the window. |

- The server MUST reject (`BAD_EXPIRES`) an entry whose `expires` is not after
  its current time, or is more than 604 800 seconds (7 days) after it. It cannot
  tell normal tags from `SYNC` tags, so the tighter cap on normal tags is the
  owner's to keep.
- The server MUST drop a registration once its `expires` has passed.
- **Fresh keys.** An owner registers a new `k_session`'s tags as soon as it
  derives the session (04), so there is no gap before a newly paired device can
  be routed.
- **Withdrawal.** When a device is removed or re-paired, its owner SHOULD
  withdraw its tags (section 12.5, `withdraw`). A withdrawal affects only the
  caller's own registrations.
- **`generation`.** The server's greeting carries `generation` (section 12.3).
  A server MUST choose a new random `generation` whenever its registration table
  starts empty or may have lost entries, for example after a restart without
  persistent storage. An owner remembers the last `generation` of each server;
  when a greeting carries a different one, it re-registers every live tag on that
  server before relying on it. A server MAY persist its registrations and keep
  its `generation`.
- An offline owner's frames are dropped, since the server stores nothing.
  Keeping registrations short limits what a stale registration reveals.

### 5.4 Owner keys and limits

- **Owner key.** The client key a home uses on a server (section 2.3). It signs
  every message the home sends there. It is pseudonymous: nothing in this
  document links it to a person or place.
- Using a different key on each server does **not** unlink a home across
  servers, because the same tags appear on every server it uses. Servers that
  compare tables can link the home's owner keys.
- **A compromised owner key** is replaced by connecting with a new key and
  registering every live tag under it; the old registrations expire within 7
  days. An owner key alone cannot prove any tag.
- **Limits.** A server MUST limit registrations per owner key: a burst allowance
  for an initial fill, then a steady rate (section 11 gives defaults). It counts
  entries, not devices. A home needs about 4 entries per device per epoch at
  worst, plus its `SYNC` windows. An entry over the limit gets `RATE_LIMITED` and
  is not stored.
- **Admission in mode 4.** A mode 4 server MUST rate-limit how many new client
  keys it admits, for example per source address per hour. The mechanism is the
  operator's choice.
- **Padding.** The number of an owner's live registrations reveals roughly how
  many devices it has. An owner MAY add registrations for the `pub`s of random
  seeds to hide the count.

### 5.5 `SYNC` windows

An owner keeps a window of `SYNC` blocks registered for each paired device, so
that a sensor whose clock is lost or that is in lost contact (08 sections 6 and
9) still reaches it:

```
b_last  = (last_fcnt - 1) / 64                  block of the newest frame seen
s       = t_now - t_last                        seconds since that frame
m       = floor(s / (60 h))                     heartbeats since then; h in minutes (08 section 4.2)
boots   = 1 + floor(s / 86400)                  one boot, plus one per full day of silence
ahead   = min(16, max(2, ceil(2 m / 64) + boots))
window  = blocks b_last to b_last + ahead
```

- `last_fcnt` and `t_last` are those of the newest frame the owner has accepted
  from the device, through any path. Any newer frame moves the window.
- While the device is heard normally, `ahead` is 2: the block holding the last
  `fcnt` and the next 2.
- As silence grows, the window grows to cover the uplinks the owner may have
  missed: `m` doubled for the extra `SYNC` attempts of 08 section 6, plus one
  block for each boot it cannot rule out, since a boot moves the counter to the
  next reserved block (02 section 8.2). It is capped at 16 blocks beyond the
  last (1 024 frames).
- The owner recomputes the window at least once an epoch, registers blocks that
  entered it, and lets blocks that left it expire.

Because the window depends only on what the owner has seen, it needs no signal
from the sensor.

## 6. Publishing

### 6.1 What is published

Publishing is opt-in. The user interface MUST present it as an explicit choice
(for example "Share my coverage with neighbors"), off until the user turns it on.

A home server with publishing enabled:

1. Processes every frame from its proxies as in 07 section 4.
2. Publishes a frame only if it passes the keyless checks of 02 section 12, has
   an uplink type, and no device of its own verified it. This includes `SYNC`
   frames that matched none of its devices.
3. MUST NOT publish `JOIN` frames (section 8).
4. MUST NOT publish frames from proxies whose region, frequency, spreading factor
   or bandwidth differ from its network's profile (07 section 6.1).
5. Waits for its collection window (07 section 4.1) and publishes all its
   receptions of one transmission in one `publish` message, at most once per
   transmission (07 section 4, step 3) and server, to every server it publishes
   to. A sensor's retransmission is a new transmission and is published again.
6. Publishes at most 5 frames per second to each server, dropping the newest
   beyond that.

### 6.2 Receptions

Each reception in a `publish` message carries:

| Field | Meaning |
|---|---|
| `rx_ref` | 8 random bytes. MUST come from a cryptographic random generator, MUST be different for each reception and each server, and MUST NOT be derived from the proxy, the time or the frame. |
| `rssi_x10`, `snr_x10` | As reported by the proxy (05 section 5.1): RSSI in 0.1 dBm, SNR in 0.1 dB. A publisher MAY coarsen them (section 13.2). |
| `age_ms` | Milliseconds from this reception to sending the `publish`, capped at 65 535 |
| `flags` | `TS_UNCERTAIN` (0x01) as in 05 section 5.1; `DOWNLINK` (0x02), below. Other bits MUST be 0. |

`DOWNLINK` is set only if all of these hold:

- the publisher accepts federated downlinks (section 7.4);
- the proxy that made the reception is a candidate under 07 section 6.1;
- the frame has a confirmed type (`DATA_CONFIRMED`, `HEARTBEAT_CONFIRMED` or
  `SYNC`). A sensor opens RX2 only after a confirmed uplink (01 section 4).

The publisher remembers each `rx_ref` with its proxy, its `ref_rx_time_us` and
the transmission it belongs to, for 5 seconds after the reception, then forgets
it.

## 7. Downlinks

Federated downlinks use RX2 only (`tx_offset_us = 3 000 000`, 01 section 4).
Federation never requests RX1.

### 7.1 Flow

1. **Publish.** A publisher sends `publish(frame, receptions)` (section 6).
2. **Deliver.** The server sends `deliver(frame, receptions, publisher, rtt_pub)`
   to each registrant of the frame's tag (section 4). `publisher` is the
   publisher's pseudonym; `rtt_pub` is the server's latest round-trip time to the
   publisher (section 12.5, `ping`).
3. **Request.** The owner processes the frame as a federated copy (07 section
   4.4). If it decides to answer (07 section 5) and no proxy of its own can
   (07 section 6), it picks a reception (section 9) and sends `request(rx_ref,
   downlink)` through the server that delivered that reception.
4. **Forward.** The server checks the request (section 7.3) and sends
   `forward(rx_ref, downlink, requester)` to the publisher, where `requester` is
   the owner's pseudonym.
5. **Transmit.** The publisher checks the forward (section 7.4) and sends a
   `DOWNLINK` message (05 section 5.4) to the proxy of that reception, with
   `tx_offset_us = 3 000 000`.
6. **Result.** The publisher sends `result(rx_ref, result, offset_us)` with the
   proxy's `TX_RESULT` (05 section 5.5), or its own refusal (section 7.4). The
   server passes it to the requester.

Neither side learns the other's key or identity, only its pseudonym on that
server.

### 7.2 Transmissions

A *transmission* is one radio transmission of a frame: an original or one
sensor retry (02 section 8.3). The rules below allow one downlink request per
transmission. Retries are the same bytes, so a transmission is told apart by
time.

**At the server.** The server identifies transmissions on its own clock, at the
moment each `publish` arrives:

```
key   = trunc64(SHA-256(frame))                 07 section 4, step 3
t_rx  = t_arrival - max(age_ms of the publish's receptions)
```

Values of `age_ms` above 1 500 are taken as 1 500 here: the age is the
publisher's claim, and the cap stops a publisher from passing a retry, at least
4 seconds later, off as a copy of the original. A genuine copy is still merged
unless its age is above about 3 500 ms; then it is taken for a new
transmission, which costs at most one redundant request (07 section 4.3).

A `publish` with the same `key` as a remembered transmission, and a `t_rx`
within 2 000 ms of that transmission's first `t_rx` (before or after), belongs to
it. Otherwise it starts a new transmission. The server remembers each
transmission for 60 seconds after its first `t_rx`. A sensor retry comes at
least 4 seconds after the transmission before it (08 section 5), so the 2-second
rule separates copies from retries as in 07 section 4.3.

A second `publish` of one transmission by the same publisher is dropped. A
`publish` reusing an `rx_ref` the server still remembers (section 12.7) is
refused (`BAD_FRAME`).

**At the owner.** The owner identifies transmissions with its own 07 section 4,
step 3 rule, taking each federated copy as received `age_ms` before its delivery
arrived (07 section 4.3).

### 7.3 Requests and server checks

An owner MUST NOT send more than one request per transmission, across all its
servers, unless a non-`SENT` result has released it (section 7.5). It MUST NOT
request through federation a transmission it is answering, or has answered,
through its own proxies: there is one downlink per RX2 window in total (07
section 6.3).

On a `request`, the server checks, in order, and refuses with the error in
brackets (section 12.6):

1. The `rx_ref` is one it delivered to this owner key in the last 5 seconds,
   and its publisher is still connected (`UNKNOWN_RX_REF`).
2. The owner key has a live registration for the frame's tag
   (`NOT_REGISTRANT`).
3. The downlink passes the keyless checks of 02 section 12 with a downlink type,
   and its tag equals the uplink's (`BAD_FRAME`).
4. No request for this transmission has been forwarded, except one released by a
   non-`SENT` result (`ALREADY_ANSWERED`).
5. The owner key's request rate is within its limit (`RATE_LIMITED`).

If all pass, it forwards the request to the publisher of that `rx_ref` and marks
the transmission requested. The server forwards at most one request per
transmission at a time, whichever of its publishers the `rx_ref`s belong to.

### 7.4 Publisher checks

Accepting federated downlinks is a separate opt-in from publishing ("Let
neighbors' sensors use my proxies to receive replies"), off by default.

On a `forward`, the publisher checks, and refuses with the result code in
brackets (05 section 5.5):

1. The `rx_ref` is one it issued to this server, is still remembered (section
   6.2), and has not been used by an earlier forward (`INVALID`).
2. Its reception has `DOWNLINK` set, and the publisher still accepts federated
   downlinks (`NOT_CAPABLE`).
3. The downlink passes the keyless checks of 02 section 12 with a downlink type,
   and its tag equals the uplink's (`INVALID`).
4. The transmission has not been answered yet: not through any server, and not
   by its own local answer path. There is one downlink per RX2 window in total,
   local and federated together (07 section 6.3) (`BUSY`).
5. Its federated airtime budget allows the downlink (`DUTY_CYCLE`):
   - per proxy, at most the mode's federated budget (section 11) in any rolling
     hour, within the proxy's own budget (06 section 3.2);
   - at most 10 federated downlinks per minute in total;
   - per requester pseudonym, a quota: the publisher keeps each requester's
     federated airtime, decaying with a half-life of 1 hour. While more than half
     of a proxy's federated budget is in use, it refuses requesters whose decayed
     airtime is above an equal share of the budget among the requesters of the
     last hour. A quota lowers a requester's priority; it never bans it.
6. Its own traffic has priority: it MUST NOT let a federated downlink displace a
   downlink of its own on the same proxy, and refuses the federated one
   (`BUSY`).

It then sends the `DOWNLINK` message, and marks the transmission answered. A
refusal is reported as a `result` with that code and `offset_us` 0, and does not
mark the transmission answered.

### 7.5 Results

- A publisher MUST send exactly one `result` for each `forward`: the proxy's
  `TX_RESULT` (05 section 5.5) when it arrives, or its refusal.
- The server accepts one `result` per `forward`: from the publisher it was
  forwarded to, for that `rx_ref`, once. It ignores any other `result`, so a
  publisher cannot release a transmission it was not asked to answer. It passes
  each accepted `result` to the requester.
- **Release.** An accepted non-`SENT` result releases the transmission at the
  server and at the owner, so the owner MAY request it again through another
  publisher if the timing still allows (section 7.6).
- A `SENT` result leaves the transmission answered, until the timeout below.
- **Timeout.** A forward stops blocking requests for its transmission 3 000 ms
  after the server sent it, whatever its result. Every transmission it could
  have answered was received before the forward, so its RX2 window has passed
  by then, and a later request can only answer a later retry. This stops a
  publisher that published late, with a small `age_ms` so that the sensor's next
  retry merges into the same transmission, from blocking the request for that
  retry by never answering. A result for a forward that has timed out, or for an
  `rx_ref` the server has forgotten (section 12.7), is ignored.
- The owner times out its own record of a request 3 000 ms plus `rtt_owner`
  after sending it, so it does not re-request before the server's timeout. An
  `ALREADY_ANSWERED` near that boundary is expected.

A publisher that falsely reports non-`SENT` after transmitting could put two
downlinks into one RX2 window. That is the same class of misbehavior as dropping
a request; section 9 counts it as a soft failure.

### 7.6 Timing

RX2 opens 3 s after the end of the uplink. The owner measures from the moment a
delivery arrives, for the reception it is about to request:

```
t_first = age_ms + rtt_pub / 2 + rtt_owner / 2 + 150 ms   (margin)
t_back  = rtt_owner / 2 + rtt_pub / 2 + 300 ms

request only if  t_first + (t_now - t_delivery) + t_back  <=  2 700 ms
```

- `t_first` is the time already spent before the delivery arrived: the reception's
  age at publishing, which includes the publisher's collection window, and the
  publisher-to-server and server-to-owner legs. The 150 ms is margin for clock
  and processing error on those legs.
- `t_back` is the time still to come: owner to server to publisher, plus 300 ms
  for the publisher-to-proxy hop and the proxy's scheduling.
- The last 300 ms before 3 000 ms are reserved for the proxy's 40 ms start window
  (01 section 4.1) and jitter.
- `rtt_owner` is the owner's own round-trip time to the server, measured with
  `ping` (section 12.5); until it has one, the owner MUST NOT request through
  that server. `rtt_pub` comes with each delivery; if it is unknown (65 535), the
  owner MUST NOT request through that delivery.
- If the check fails for every reception, the owner sends no request. The sensor
  retries the uplink (08 section 5), and the retry is a new transmission.

### 7.7 Commands and first-command latency

Federated downlinks only answer confirmed uplinks, in RX2, so:

- A device heard only through federation receives queued commands, and clock
  corrections, only in answers to its confirmed uplinks: a confirmed state
  change, or the confirmed heartbeat at least every 4 hours (RECOMMENDED; at most
  24 hours, 08 section 4.2). The first queued command can wait that long. 07
  section 7 states this for the user.
- An answer carrying `PENDING` arrives in RX2, so the sensor's follow-up 2 to 4
  seconds later is a `HEARTBEAT_CONFIRMED` (08 section 7). It is published and
  answered like any confirmed uplink, so the next queued commands follow within
  seconds, for up to 4 follow-ups in a row. The sensor doesn't retry a
  follow-up. If one goes unanswered, or the 4 are used up, the remaining
  commands wait for the next confirmed uplink.

Section 9's credit needs a downlink that carries a command; the owner MAY send
`NOP` (02 section 10.3) when it has no command to send.

## 8. Pairing is never federated

Pairing is always done through one of the owner's own proxies, in every mode
(04). After pairing, the sensor can be moved anywhere a federated publisher hears
it.

- Publishers MUST NOT publish `JOIN` frames (section 6.1). A mailbox server MUST
  drop a published `JOIN` frame (`BAD_FRAME`).
- Owners MUST NOT register `JOIN` tags.
- So a `JOIN` heard by a neighbor goes nowhere, no federated party can answer or
  race a pairing, and the RX2 fallback for `KEY_EXCHANGE` stays local.

`JOIN` tags derive from `k_root`, which is printed on the device label. Anyone who
has seen it (a reseller, the factory, someone who photographed the label, a
previous owner) could prove `JOIN` tags. Keeping pairing local leaves them the
exposure of 02 section 13: they must be in radio range during the pairing. Users
SHOULD have `k_root` re-flashed on second-hand or untrusted devices for full
protection.

## 9. Choosing a publisher

In mode 4, anyone with a radio can publish a frame it heard, claim a good SNR,
and then drop the request. An owner SHOULD keep a record per publisher, and pick
publishers with it. The record is best effort.

A *publisher* here is one pseudonym on one server.

**Credit.** A publisher earns 1 credit from an exchange in which all of these
hold:

- exactly one downlink answered the frame, across all its transmissions;
- that downlink carried at least one command, or `NOP`;
- the sensor's next new uplink (02 section 8.5) has `DL_ACK` set.

If several publishers answered the same frame, none is credited or blamed.

**Failure.**

- *Hard* (weight 1): the downlink carried a command or `NOP`, its result was
  `SENT`, and the uplink with `fcnt = reply_to + 1` arrives without `DL_ACK`.
- *Soft* (weight 0.5): a non-`SENT` result, or no result within 5 seconds of the
  request.

**Phantom retries.** A retransmission of a frame is ignored for credit and
failure if the publisher that reported the original did not also report the
retransmission. A replayed "retry" then cannot void an honest publisher's credit.

**Decay.** Credits and failures each decay with a half-life of 7 days:

```
C = sum over credits  of            2^(-age / 7 days)
F = sum over failures of  weight *  2^(-age / 7 days)
```

**Classes and order.**

| Class | Condition | Order within the class |
|---|---|---|
| Proven | `C >= 1` and `F < C / 2` | best SNR first |
| Unknown | not proven, and `F < 0.5` | random |
| Failed | not proven, and `F >= 0.5` | highest `C - F` first |

The owner considers proven publishers first, then unknown, then failed, among
receptions with `DOWNLINK` set that pass the timing check (section 7.6).

- **Rotation.** Across a frame's retries, the owner picks a different publisher
  each time when another qualifies. Retries are at least 4 seconds apart and RX2
  is at 3 seconds, so each try ends before the next transmission.
- **Implausible signal.** An SNR below the profile's demodulation floor minus
  5 dB, or above +20 dB, or an RSSI above -20 dBm, is ignored and ranked as the
  floor. The floor is `-2.5 (SF - 4)` dB for the profile's spreading factor (01).

**Supervision.**

- A federated path is one publisher on one server.
- The server shows federated paths separately from its own proxies, and they
  never clear the single-path flag (07 section 8.2).

## 10. Several servers

A home MAY use several mailbox servers. It registers its tags on each, with
proofs bound to each `server_id`.

- **Owner.** Requests each transmission through one server only: among those
  that delivered a qualifying reception, the one with the lowest `rtt_owner +
  rtt_pub`.
- **Publisher.** Publishes to each server with distinct `rx_ref`s, and answers
  each transmission at most once, across all servers and its own local path
  (section 7.4).
- Only session key holders receive `rx_ref`s, so two homes cannot both request
  the same frame.

## 11. Mode policies

The protocol defines the mechanisms; the table gives RECOMMENDED defaults per
mode. Operators MAY set others.

| | Mode 2 Private | Mode 3 Public | Mode 4 Open |
|---|---|---|---|
| Who may connect, publish and register | members (invite or admin) | account holders | anyone, admission rate-limited (section 5.4) |
| Registrations per owner key | operator default | operator default | burst 2 048, then 512 per hour; at most 4 096 live |
| Publishes per publisher | 5 per second | 5 per second | 5 per second, burst 20 |
| Requests per owner key | 10 per second | 10 per second | 10 per second |
| Federated downlink budget per publisher proxy | group default, generous | operator default | 0.5% airtime per rolling hour, shared by requester quotas (section 7.4) |
| Removing abusers | admin | operator | none; owners rely on records (section 9) |
| What the server sees | metadata (section 13.2) | metadata | metadata |

The budget row is the publisher's own setting. The mode tells it which default
applies.

## 12. Protocol

### 12.1 Transport

- A client connects to a server's `wss://` URL: a WebSocket (RFC 6455) over TLS
  1.3 (RFC 8446), with the subprotocol `cs-mailbox.1`.
- The client MUST validate the server's TLS certificate for the URL's host,
  through the public PKI or a certificate the user pinned for that URL.
- Each WebSocket message is a binary message holding exactly one CBOR data item
  (section 12.2). A text message is a `MALFORMED` error.
- Messages are at most 4 096 bytes. A larger one closes the connection with
  WebSocket close code 1009.

**TLS at a reverse proxy.** A server MAY have a reverse proxy that its operator
controls terminate TLS for it. The proxy then holds the certificate for the URL's
host, and the rules above apply between the client and the proxy. Behind it:

- The hop from the proxy to the server MUST be private to the operator: loopback,
  a container network, or a network segment no one else can reach or observe.
  Nothing protects it but that.
- The server MUST refuse plain connections from anyone but the proxy, before the
  greeting, so the plain port cannot be used to bypass TLS or the proxy.
- Where the server needs a client's address, for open admission (sections 5.4
  and 11), it MUST use the address the proxy reports for the
  connection, and MUST NOT take a reported address from anyone but the proxy.

Clients do not change: they connect to `wss://` and validate the certificate as
above, and cannot tell a proxy is there.

### 12.2 Encoding

Messages are CBOR (RFC 8949) arrays whose first element is the message type. They
MUST use the core deterministic encoding of RFC 8949 section 4.2.1: integers and
lengths in their shortest form, definite lengths only. Only unsigned and negative
integers, byte strings and arrays occur. A receiver MUST reject anything else,
including a non-deterministic encoding, trailing bytes, or an array with the
wrong number of elements, as `MALFORMED`.

The schema in CDDL (RFC 8610):

```cddl
; client to server
hello      = [1, version: uint .le 255, nonce_c: bstr .size 16]
auth       = [2, client_pub: bstr .size 32, sig]
register   = [16, seq, entries: [1*32 reg_entry], sig]
withdraw   = [17, seq, tags: [1*256 tag], sig]
request    = [18, seq, rx_ref, downlink: frame, sig]
ping       = [19, seq, sig]
publish    = [20, seq, uplink: frame, receptions: [1*8 reception], sig]
result     = [21, seq, rx_ref, code: uint .le 255, offset_us: int32, sig]
pong       = [22, seq, nonce: uint64, sig]

; server to client
greeting   = [32, version: uint .le 255, server_pub: bstr .size 32, server_id: bstr .size 32,
              generation: uint64, nonce_s: bstr .size 16, sig]
welcome    = [33, pseudonym]
registered = [34, seq, statuses: [1*32 uint .le 255]]
pong_s     = [35, seq]
ping_s     = [36, nonce: uint64]
deliver    = [37, uplink: frame, receptions: [1*8 reception], publisher: pseudonym,
              rtt_pub_ms: uint .le 65535]
forward    = [38, rx_ref, downlink: frame, requester: pseudonym]
result_s   = [39, rx_ref, code: uint .le 255, offset_us: int32]
error      = [40, seq: uint32, code: uint .le 255]

reg_entry  = [pub: bstr .size 32, proof: bstr .size 64, expires: uint32]
reception  = [rx_ref, rssi_x10: int16, snr_x10: int16, age_ms: uint .le 65535,
              flags: uint .le 3]
frame      = bstr .size (23..86)        ; 02 section 3
tag        = bstr .size 8
rx_ref     = bstr .size 8
pseudonym  = bstr .size 8
sig        = bstr .size 64
seq        = uint32 .ge 1
uint32     = uint .le 4294967295
uint64     = uint .le 18446744073709551615
int16      = int .ge -32768 .le 32767
int32      = int .ge -2147483648 .le 2147483647
```

`entries` in `register` and `statuses` in `registered` have the same length and
order. `registered` carries the `seq` of the `register` it answers.

### 12.3 Handshake

1. The client sends `hello` with the protocol version it speaks (1) and a fresh
   random `nonce_c`. A server that does not speak that version answers `error`
   (`UNSUPPORTED_VERSION`) and closes.
2. The server answers `greeting` with the version (1), its public key,
   `server_id`, `generation`, a fresh random `nonce_s`, and
   `sig = Ed25519-Sign(server key, "cs1 mbx greeting" | uint8(len(host)) | host | nonce_c | nonce_s | uint64(generation))`.
   `host` is the host name of the URL, in lowercase ASCII without a port, with
   an internationalized name in its A-label form. The server signs only host
   names it is configured to serve. One configured for several names MAY use the
   client's SNI or `Host` header to choose among them, but never signs a name
   taken from them that it is not configured for, so a malicious server cannot
   relay another server's greeting under its own name.
3. The client checks the version, that `server_id = SHA-256(server_pub)`, and
   `sig`, strictly (section 5.2), with the host of the URL it connected to and
   its own `nonce_c`. It closes the connection if any check fails. The
   signature shows that the holder of the server key answered this `nonce_c`
   for this host, and the validated TLS certificate (section 12.1) shows that
   the connection reached that host, or its operator's reverse proxy, so
   `server_id` is safe to sign proofs for.
4. The client sends `auth` with its client key's public key and
   `sig = Ed25519-Sign(client key, "cs1 mbx auth" | server_id | nonce_c | nonce_s | client_pub)`.
5. The server verifies it strictly, applies its admission policy (section 11),
   and answers `welcome` with the client's own pseudonym, or `error`
   (`BAD_SIGNATURE` or `NOT_PERMITTED`) and closes.

A client SHOULD remember each URL's `server_id`. If it changes, the client
treats the server as new: it SHOULD warn the user in modes 2 and 3, and it
re-registers every live tag. Any message before `welcome` other than the
handshake's is `NOT_AUTHENTICATED`.

### 12.4 Signed messages

Every client message after `auth` carries `seq` and, as its last element, `sig`:

```
sig = Ed25519-Sign(client key, "cs1 mbx msg" | server_id | nonce_s | cbor(m))
```

where `cbor(m)` is the deterministic encoding of the message array without its
last element. `seq` starts at 1 for the first such message on a connection and
increases by exactly 1 with each. The server verifies `sig` strictly, with the
connection's `nonce_s`, and checks `seq`. A failure is `BAD_SIGNATURE` or
`BAD_SEQUENCE`.

For `register` this is the owner signature of section 5.1: it covers the message
type, `seq` and every entry, and `nonce_s` binds it to the connection.

Server messages are not signed. The greeting binds the server key to the TLS
session (section 12.3), and TLS protects everything after it as far as the
server, or as far as its operator's reverse proxy, whose hop to the server is
private to the operator (section 12.1). Client messages remain signed end to end
either way.

### 12.5 Messages

| Message | Direction | Meaning |
|---|---|---|
| `register` | owner to server | Register tags (section 5). Answered by `registered`. |
| `withdraw` | owner to server | Remove the caller's registrations of these tags. Tags it has not registered are ignored. No answer. |
| `request` | owner to server | Request a downlink (section 7.3). Answered only by `error`, or later by `result_s`. |
| `ping` | client to server | Answered at once by `pong_s` with the same `seq`. The owner sends one right after `welcome` and then every 30 seconds, and takes `rtt_owner` from the last answer. |
| `publish` | publisher to server | A frame and its receptions (section 6). No answer unless refused. |
| `result` | publisher to server | The result for an `rx_ref` (section 7.5). |
| `pong` | client to server | Answer to `ping_s`, sent at once, echoing its `nonce`. |
| `greeting`, `welcome` | server to client | Handshake (section 12.3). |
| `registered` | server to owner | One status per entry: 0 if stored, otherwise an error code (section 12.6). |
| `ping_s` | server to client | Sent to every client right after `welcome` and then every 30 seconds, with a fresh random `nonce`, so a client cannot answer early. The server takes `rtt_pub` for a publisher from its last `pong`, in milliseconds, or 65 535 while it has none. |
| `deliver` | server to owner | A published frame for one of the owner's tags (section 4), with the receptions exactly as published. |
| `forward` | server to publisher | A checked request (section 7.3). |
| `result_s` | server to owner | The result for an `rx_ref` the owner requested. |
| `error` | server to client | A refused message, by its `seq` (0 for `hello` and `auth`). |

The server MUST check each `publish`: the frame passes the keyless checks of 02
section 12 with an uplink type other than `JOIN`, and its `rx_ref`s are distinct
from each other and from every `rx_ref` the server still remembers (`BAD_FRAME`
otherwise).

A client MUST ignore server messages of unknown type. A server MUST treat a
client message of unknown type, or a `hello` or `auth` after `welcome`, as
`MALFORMED`.

### 12.6 Errors

| Code | Name | Meaning | Fatal |
|---|---|---|---|
| 0 | `OK` | Status only: the entry was stored | |
| 1 | `MALFORMED` | Not a valid message (section 12.2) | yes |
| 2 | `BAD_SIGNATURE` | The message, `auth` or greeting signature failed | yes |
| 3 | `BAD_SEQUENCE` | `seq` is not the previous one plus 1 | yes |
| 4 | `NOT_AUTHENTICATED` | A message before `welcome` | yes |
| 5 | `NOT_PERMITTED` | Refused by policy: admission, or a role the key may not use | yes for `auth` |
| 6 | `UNSUPPORTED_VERSION` | `hello` with a version the server does not speak | yes |
| 7 | `RATE_LIMITED` | Over a limit (sections 5.4, 11) | |
| 8 | `BAD_PROOF` | A registration entry's `pub` or `proof` failed (section 5.2) | |
| 9 | `BAD_EXPIRES` | A registration entry's `expires` is out of range (section 5.3) | |
| 10 | `UNKNOWN_RX_REF` | Unknown, expired, or not delivered to this owner | |
| 11 | `ALREADY_ANSWERED` | The transmission already has a request | |
| 12 | `NOT_REGISTRANT` | The owner has no live registration for the frame's tag | |
| 13 | `BAD_FRAME` | A frame failed the checks of sections 7.3 or 12.5 | |

After a fatal error, the server sends `error` and closes the connection with
WebSocket close code `4000 + code`. Registrations survive the connection.

### 12.7 Limits

| Item | Limit |
|---|---|
| Message size | 4 096 bytes |
| Entries per `register` | 32 |
| Tags per `withdraw` | 256 |
| Receptions per `publish` and `deliver` | 1 to 8 |
| Frame | 23 to 86 bytes (02 section 3) |
| `rx_ref` lifetime | 5 seconds, at the publisher and at the server |
| Transmission memory at the server | 60 seconds |
| `expires` | at most 7 days ahead |

## 13. Threat model

### 13.1 Invariant

**Only holders of a device's session key set, the sensor and its home server,
can register its tags. So only they receive its frames' `rx_ref`s through a
mailbox.** Hearing a frame by radio, or seeing it through a server, grants no
routing or downlink access. `JOIN` is never federated, so holders of `k_root`
gain nothing from mailboxes.

The exceptions:

- **A malicious server** can misroute, drop, delay or leak `rx_ref`s to an
  accomplice, but only for homes that use it, and it cannot replay proofs on
  another server (section 5.1).
- **A publisher** can drop or delay the frames it publishes. Section 9 handles
  this for downlinks. For uplinks it remains, and is handled by marking (07
  section 4.4).
- **Brute force** for a random live tag (section 5.2).
- **Local pairing exposure:** an attacker in radio range during pairing who holds
  `k_root`, as without federation.

What remains for a radio attacker near a device is jamming, as in any LoRa
system.

### 13.2 Threats

| Threat | Mitigation |
|---|---|
| A server reads readings | It cannot: payloads are encrypted under device keys. |
| A server links a home's registrations and traffic | Inherent: they are signed by the owner key, tags are the same on every server, and `fcnt` is clear (02 section 13). The server sees per-owner timing, the frame type and length. Documented. |
| Linking a device's frames by counter | `fcnt` is in the clear. Without federation only someone in radio range sees it; through a mailbox, the server and the device's owner see it. Owners see only their own frames. |
| Mapping proxies with a moving sensor | Stable publisher pseudonyms plus signal values reveal roughly where a publisher's proxies are. Publishers MAY coarsen RSSI and SNR. Documented. |
| Black-holed downlinks | Only session key holders get `rx_ref`s (13.1). One request per transmission, released on a non-`SENT` result (section 7). |
| A publisher claiming a good SNR and dropping requests | Section 9: credit, hard and soft failures, decay, the phantom-retry rule, random order among unknowns, rotation, and the signal cap. |
| Bootstrap floods | `JOIN` is not federated. `SYNC` is routed by tag to its owner only. The server drops a publisher's second `publish` of a transmission and rate-limits publishers (section 11). Owners identify federated frames by lookup only, under a federated bootstrap limiter separate from the local one (07 section 4.4). |
| Remote pairing attacks by `k_root` holders | `JOIN` is not federated (section 8). |
| Draining a publisher's airtime | Only key holders can request. Per-proxy budget, rate cap and decaying requester quotas (section 7.4). |
| Two downlinks in one RX2 window | One request per transmission at the owner and the server, one answer per transmission at the publisher, local and federated together (sections 7.3, 7.4, 10). |
| A malicious server | Limited to homes that use it. Its proofs are bound to its `server_id` (section 5.1). |
| A sole-path publisher or server delays frames | Frames carry no time. Receptions that came only through federation are marked, and users can ignore events from them (07 section 4.4). Documented. |
| Replay of client messages | Every message is signed over the connection's `nonce_s` and a strictly increasing `seq` (section 12.4). |
| A forged server greeting | The greeting signature covers the client's nonce and the TLS host name (section 12.3). |
| A server behind a TLS-terminating proxy that leaves its plain port reachable | The server refuses plain connections from anyone but its proxy, before the greeting, and reads reported client addresses only from the proxy (section 12.1). Without that, anyone who reaches the port could connect without TLS and, if the server read their headers, choose the address that open admission counts them by. Clients are not exposed by it: they connect only through `wss://` (section 12.1), and their messages stay signed and bound to `nonce_s` (section 12.4). |

## 14. Test vectors

`vectors/federation-v1.json` contains, with fixed keys:

- the tags of the session key set of `vectors/frame-v1.json` for one epoch and
  two `SYNC` blocks: `seed`, `pub` and `tag` (section 3);
- registration entries: `reg_msg`, `proof` and the computed tag;
- `invalid` registration entries a server rejects, each with its status: a
  non-canonical `S` (`S + L`), a small-order `pub` with a signature that a
  cofactorless lax verifier accepts, a proof made for another `server_id`, a
  proof made for another owner key, an `expires` too far ahead and one already
  reached;
- the handshake (`hello`, `greeting`, `auth`, `welcome`) and its signatures;
- the CBOR encoding of every message type in section 12.2;
- a full exchange: `register`, `registered`, `publish`, `deliver`, `request`,
  `forward`, `result`, `result_s`, where the published frame is a
  `DATA_CONFIRMED` under the registered tag and the requested downlink answers it;
- `invalid` messages a receiver rejects: a non-deterministic integer encoding, a
  wrong element count, a bad outer signature, a wrong `seq`, and a `publish` of a
  `JOIN` frame and of a `DOWNLINK` frame;
- `transmissions`: publishes with their arrival times and ages, and requests and
  results, with whether each publish starts a new transmission (section 7.2) and
  whether each request is forwarded (section 7.3), including release after a
  non-`SENT` result, an ignored result from a publisher that was not asked, the
  `age_ms` cap, a reused `rx_ref`, the forward timeout against a publisher
  that published late and never answers, and a result that arrives after its
  forward timed out;
- `sync_window`: inputs and the resulting block range of section 5.5;
- `request_timing`: an owner's inputs to the check of section 7.6, and whether it
  may request.
