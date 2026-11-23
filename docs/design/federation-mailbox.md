# Design note: federation through blind mailboxes

Status: proposal, revision 2, for review. If accepted, it replaces the Nostr
design of `spec/09-federation-relay.md` and most of `spec/10-control-plane.md`
sections 5-7.

Revision 2 answers review round 1 (PR #90). Its main changes:
- routing on the 64-bit tag pair (section 3);
- a registration *deadline* instead of first sighting (section 4);
- durable registrations keyed to an owner (section 4.3);
- salted per-server registration (section 4.4);
- bootstrap tags derived from the device's own key set (section 5);
- downlink hardening (section 6) and publisher choice by `DL_ACK` only (section 8);
- an explicit residual-risk invariant (section 10.1).

## 1. Why

The Phase 0 review of spec 09 (#77-#88, tracked in #89) traced most problems to
two root causes:

1. **Anyone can take part anonymously.** Any Nostr key can publish, request
   downlinks or flood a bucket. This causes #78, #79, #80, #84 and #86.
2. **Relays are dumb and untrusted.** They can't route a frame to its owner, so
   owners hide in broad buckets (#81), and every publisher has to defend itself.

This note proposes servers that route frames to their owners without knowing who
the owners are, and without any central coordinator.

## 2. Operating modes

| Mode | Server | Membership | Uplinks | Downlinks (acks, commands) |
|---|---|---|---|---|
| 1 Standalone | none | - | own proxies | own proxies |
| 2 Private | a group's own mailbox server | invite or admin | routed | yes |
| 3 Public | a large operator's mailbox server | operator accounts | routed | yes |
| 4 Open | any mailbox server | none | routed | yes, best effort (10.1) |

Modes 2-4 share one protocol and one reference server, `cs-mailbox`. They differ
only in admission policy and defaults (section 9). Mode 4 needs nobody's
permission, so there is no control plane anyone has to answer to.

## 3. Core idea: route by the tag pair

Every normal frame carries two rotating tags (02 section 6):

```
net_tag = trunc32(HMAC(k_net_route, "net" | epoch))   per network
dev_tag = trunc32(HMAC(k_dev_tag,   "dev" | epoch))   per device (session key set)
epoch   = floor(unix_time / 3600)
```

Without the keys, both look random, can't be linked across hours, and **can't be
predicted**. A mailbox server routes each frame by its 64-bit **pair**
`(net_tag, dev_tag)`:

- **A publisher**, a home server whose proxy heard a frame none of its devices
  verified, hands the frame to the server.
- **An owner** registers the pairs its devices will use (section 4). The server
  delivers each frame only to the registrants of its pair.
- **The server** holds no device keys and reads no payloads, which stay
  encrypted under device keys (02 section 5).

There are no buckets, decoys or broadcast. Each owner receives only its own
devices' frames, and the server does one table lookup per frame.

**Why the pair and not `net_tag` alone:** `net_tag` is shared by every device in
a network. If routing used it alone, hearing any one device on air would expose
the whole network's routing for that hour, remote devices included (round 1, H2).
With the pair, a frame heard on air exposes only that one device.

**Collisions:** with `D` registered devices, the expected number of colliding
pairs per epoch is about `D^2 / 2^65`, which is negligible even at 10^8 devices.

## 4. Ownership by registering ahead

### 4.1 The deadline rule

The pair for epoch `x` can be computed only with the device's keys. The server
enforces:

- A registration names a target epoch `x` and a pair hash (4.4).
- **It is accepted only while the server's epoch is less than `x - 1`.** So the
  registration must arrive before epoch `x - 1` starts.
- It is **live** during epochs `x - 1`, `x` and `x + 1`. That matches the 02
  section 6.3 tag window, which accepts sensor clocks up to an hour off.
- Several registrations of the same hash are all accepted, and the server
  delivers to every live registrant.

An attacker who hears a pair on air can register it only for a *later* target
epoch, because the deadline for the current one has passed. That later
registration goes live one epoch later, when the device has moved on to a new
pair. The only frames it can still catch are from that device while its clock is
an hour or more slow. A device whose clock is an hour fast exposes its next pair
early, and an attacker who hears that can register it and catch the next epoch.
Both cases are local to a device the attacker can hear (10.1).

The rule needs no sighting state, so a reconnect, an owner restart or a server
restart never locks an owner out (round 1, H3 and M2).

### 4.2 Horizon

- The owner keeps registrations for a **horizon** of epochs `e + 2` to `e + H`.
  The default `H` is 48, so two days ahead.
- Each epoch it tops up one new epoch for each device.
- If the owner is offline longer than the horizon, its next registrations can
  only target `e + 2` onward. Federated frames from up to two epochs are lost.
  Local traffic is unaffected. This is documented, and the horizon is
  configurable.
- **Network key rotation** (04 section 7) changes `net_tag`. During the overlap
  the owner registers pairs under both keys.

### 4.3 Owner identity, durability, limits

- Each home has a long-lived **owner key** per server, an Ed25519 key pair. It
  signs registrations and requests, and it is pseudonymous. A home MAY use a
  different key on each server.
- **Registrations are durable.** The server keeps them until they expire (end of
  epoch `x + 1`), across reconnects and its own restarts. A server that lost its
  state accepts re-registrations under the normal deadline. Only the epochs
  inside the deadline are lost.
- **Limits are per owner key per day**, sized for the horizon: devices × epochs.
  For example, 100 devices × 24 new epochs a day is 2 400 registrations a day.
  A mode 4 server rate-limits new owner keys, for example with proof of work or
  slow admission. Modes 2 and 3 tie owner keys to members.
- **Padding:** the number of registrations reveals the number of devices. An
  owner MAY pad with random hashes up to a round number.

### 4.4 Salted per-server registration

A registration carries `reg = SHA-256("cs-reg" | server_salt | x | net_tag | dev_tag)`,
not the pair itself:
- `server_salt` is a public random value per server.
- On each published frame, the server computes `reg` for the frame's pair and the
  current epochs, and looks it up.

A server therefore learns a pair only when the pair is on air. That is past the
deadline, so it can't pre-register an owner's future pairs on other servers
(round 1, M1). A malicious server can still misroute or drop frames for homes that
use it (10.2).

## 5. Bootstrap frames

`JOIN` and `SYNC` use all-zero tags today (02 section 11), because a sensor
without a clock can't compute an epoch. A mailbox can't route them, and after 3
undelivered confirmed uplinks a sensor sends every confirmed attempt as `SYNC`
(08 section 6). So a device heard only through federation would become
unroutable just when it needs help.

### 5.1 Counter-based bootstrap tags

The tags come from the frame's own key set, not a network key, and from its
uplink counter instead of the clock:

```
block   = floor(fcnt / B)                 B = 16 (open: section 12)
net_tag = trunc32(HMAC(k_dev_tag, "boot-net" | uint32(block)))
dev_tag = trunc32(HMAC(k_dev_tag, "boot-dev" | uint32(block)))
```

`k_dev_tag` is the key set's own:
- the root key set for `JOIN`;
- the session key set for `SYNC`, which is what 04 section 4.3 and 02 section
  5.1 already use for it.

No network key is needed, so this works in `JOIN`, in `SESSION`, and for a device
that missed a key rotation (04 section 7).

- A computed value of `00000000` becomes `00000001`, as in 02 section 6.2.
- **Privacy:** `fcnt` is already clear in the header (02 section 2), so the
  bootstrap tags add no linkability.
- **Mode 1** benefits too: a server identifies bootstrap frames by lookup instead
  of trial decryption.

### 5.2 Registering bootstrap tags

Bootstrap tags have no epoch, so they use **standing registrations**: no target
epoch and no deadline, valid until the owner withdraws them. The owner keeps
these registered:
- **A paired device:** the blocks from the one holding the last `fcnt` seen
  through `W` blocks beyond it. `W` starts at 6, because a boot can skip up to 64
  counter values (02 section 8.2), which is 4 blocks, plus margin. It grows by 1
  for every `B` uplinks the owner expects the device sent while it heard nothing,
  capped at 32.
- **A device being paired:** the first blocks after the pairing code is entered,
  covering `fcnt` 1 onward. New devices start at 1 (02 section 8.1).

An attacker who hears a bootstrap frame can register its block and catch the
`rx_ref`s of that device's later frames in the same block, at most `B` frames.
That is device-local (10.1).

### 5.3 Second-hand devices

A factory reset keeps `fcnt` (02 section 8). The new owner can't predict a used
device's bootstrap blocks. **The first pairing of a second-hand device MUST be
done near one of the owner's own proxies**, which needs no registration. After
that the owner knows `fcnt` and federation works.

The previous owner knows `k_root` and so can register the `JOIN` blocks. That is
the same exposure 02 section 13 already accepts for a previous owner during
re-pairing. Local pairing limits it to the time the pairing takes.

## 6. Downlinks: `rx_ref` capabilities

1. **Publish.** The publisher hands the server `(frame, receptions)`. Each
   reception carries:
   - a random `rx_ref`, issued per server;
   - SNR, RSSI, `age_ms`, and the `TS_UNCERTAIN` flag;
   - a downlink-capable flag, set only when that proxy is a 07 section 6.1
     candidate and the frame is a confirmed type.
2. **Deliver.** The server sends the frame and its `rx_ref`s **only to live
   registrants** of the frame's pair.
3. **Request.** The owner decides to answer (07 section 5) and sends one signed
   `(rx_ref, DOWNLINK)`.
   - **The server accepts at most one request per frame hash,** across all
     `rx_ref`s and requesters, then forwards it to the publisher that issued the
     `rx_ref`.
4. **Check.** The publisher checks:
   - the `rx_ref` is known, unused and fresh;
   - the keyless checks pass, with the same tags as the uplink;
   - **the transmission hasn't already been answered through any server**, which
     it tracks by frame hash;
   - its federated airtime budget, both per proxy and **per requester
     pseudonym**, allows it.
   It then sends the `DOWNLINK` with `tx_offset_us = 3 000 000` (RX2). Its own
   traffic has priority.
5. **Result.** The publisher returns the `TX_RESULT` through the server.
6. **Requester records.** If the publisher's own proxy hears the same frame
   retransmitted after it transmitted a downlink for it, the sensor didn't accept
   that downlink. The publisher demotes that requester pseudonym: lower priority,
   then refusal.

Neither side learns the other's identity: the server gives each a stable
pseudonym derived from its key.

### 6.1 Timing

Federated downlinks use RX2 only, which opens 3 s after the uplink (01 section 4).

| Step | Time |
|---|---|
| Publisher's collection window (07 section 4.1) | 150 ms |
| Publisher to server to owner | about 50-300 ms |
| Owner decides and builds the downlink | under 50 ms |
| Owner to server to publisher to proxy | about 50-300 ms |
| Proxy transmits | 3 s after the uplink, inside its 40 ms start window (01 section 4.1) |

How the owner estimates timing:
- **Elapsed time** is `age_ms` plus the time since the event arrived.
- **Transit back** is measured as the round-trip time of the server connection,
  using application-level pings every 30 s, and halved.
- The owner requests only if `elapsed + transit_back + 300 ms ≤ 2800 ms`.
  Otherwise it doesn't request; the sensor retries.

### 6.2 Commands and `PENDING`

Today a queued command sets `PENDING`, which makes the sensor send an unconfirmed
`HEARTBEAT` (08 section 7). That heartbeat opens only RX1, which federation can't
use (#85).

**Proposal:**
- When a downlink carrying `PENDING` is received in **RX2**, the follow-up
  `HEARTBEAT` is confirmed, so it opens RX2.
- This also applies after a local RX2 fallback (07 section 6.3). That is a small
  change in local behaviour, and only after an RX2 answer.
- An unanswered follow-up does **not** count as an undelivered uplink for 08
  section 6, so a federation path that fails mid-drain can't push the sensor into
  lost contact.

**Latency:** a device heard only through federation gets its *first* queued
command on its next confirmed uplink: a state change, or the confirmed heartbeat,
which is every 4 h recommended and 24 h at most (08 section 4.2). After that,
`PENDING` drains the queue promptly. This is documented in 07.

## 7. Commissioning

1. **A pre-sold sensor near your own proxy:** unchanged. Scan the QR code (or
   type the `CS:1:…` code) in **Add device**, press the button, and it is paired.
   No ESPHome build server is involved.
2. **A pre-sold sensor heard only by a neighbour:** the steps you take are the
   same.
   - Entering the code lets the integration compute the root key set and
     register the first bootstrap blocks, as standing registrations.
   - The `JOIN` is routed to you alone, and `KEY_EXCHANGE` and `SET_NETWORK` go
     out in RX2 through the neighbour's proxy.
   - From then on you register normal pairs ahead.
3. **A second-hand sensor:** pair it locally first (5.3).
4. **A proxy:** not part of federation. Today it is adopted in ESPHome and given
   the `cs_proxy:` snippet. Plug-and-play proxies would need Improv Wi-Fi plus
   mDNS discovery (06 section 3.2), which is tracked separately.

## 8. Choosing a publisher

In mode 4, an attacker with a radio can republish a frame it heard, claim a good
SNR, and then drop the request (#79). The owner keeps a **success record per
publisher pseudonym**:

- **Success is counted only on `DL_ACK`.** A downlink counts as delivered only
  when the sensor's next new uplink sets `DL_ACK` (07 section 7). `DL_ACK` exists
  only for downlinks carrying a command (02 section 10.2), so the owner MAY add a
  new no-op command, `NOP` (0x05, no arguments, no effect), to a downlink when it
  needs the evidence. That is a small 02 and `sensor_core` addition. Silence and
  missing retransmissions count as nothing.
- **Order:** proven publishers by SNR, then unknown publishers, then failed ones.
  A failure ranks *below* unknown.
- **Rotation:** across a sensor's retries of one frame, the owner picks a
  different publisher each time, so one bad publisher can't hold every attempt.
- **SNR cap:** values outside the profile's physical range are ignored.
- **Pseudonyms** are derived by the server from the publisher's key, so
  reconnecting doesn't reset a record.

A Sybil key starts unknown and can win at most the first attempt, then ranks
below unknown. Mode 4 downlinks stay best effort against a local radio attacker
(10.1).

**Supervision (#84):** a federated path is one publisher pseudonym on one
server. Federated paths are shown separately from the home's own proxies, and
**never clear the single-path flag**. Only paths through the home's own proxies
count toward it.

## 9. Mode policies

| | Mode 2 Private | Mode 3 Public | Mode 4 Open |
|---|---|---|---|
| Who may connect, publish and register | members (invite) | account holders | anyone, admission rate-limited |
| Downlink budget per publisher proxy | group default, generous | operator default | 0.5% airtime per hour, split per requester |
| Removing abusers | admin | operator | none; owners rely on records |
| What the server sees | metadata (10.2) | metadata | metadata |

The protocol defines the mechanisms. The spec gives recommended defaults per
mode, and operators MAY set others.

## 10. Threat model

### 10.1 Invariant

**Without radio reception of a device, an attacker can't affect that device's
federated traffic, beyond what the server the owner chose can do.**

With radio reception, an attacker can disrupt downlinks for that device in narrow
cases:
- when the device's clock is skewed by an hour or more (4.1);
- within the bootstrap block it heard (5.2).

That is comparable to jamming the device, which any LoRa system has to accept.

### 10.2 Threats

| Threat | Mitigation |
|---|---|
| A server reads readings | It can't: payloads are encrypted under device keys. |
| A server links an owner's registrations | Inherent: registrations are signed by the owner key. Clear `fcnt` continuity also links frames (02 section 13). Documented, not solved. Owners may use separate keys on separate servers. |
| A server sees each home's event timeline | It sees, per owner key, the time, type nibble and length of each delivered frame. Documented. Modes 2 and 3 choose a trusted operator. |
| A server or publisher maps proxies with a sensor | Stable publisher pseudonyms plus signal values let someone moving a sensor around map proxies. Documented. Publishers MAY coarsen RSSI and SNR to 1 dB steps. |
| An attacker black-holes downlinks (#78) | Requests need an `rx_ref`, which only live registrants get. Registering needs foreknowledge before the deadline. A radio attacker is limited to the device it hears (10.1). |
| Fake publisher SNR (#79) | Success counted on `DL_ACK` only, failures ranked below unknown, rotation across retries, SNR cap (section 8). |
| Bootstrap flood (#80) | Bootstrap frames are routed by pair, so a replayed frame reaches only its owner. The server dedupes by frame hash and rate-limits per publisher. Federated bootstrap frames use a separate limiter from local ones in 07 section 4. |
| Airtime drain by registrants (M5) | Per-requester budgets, one request per frame hash at the server, one answer per transmission at the publisher, and demotion by heard retransmission (6.6). In mode 4, Sybil requesters near a proxy can exhaust its federated budget, which is a local, radio-present attack. |
| A malicious server | Misroutes, drops or delays frames for homes that use it, and can leak `rx_ref`s to an accomplice. It can't learn future pairs (4.4). Homes MAY use several servers, since publishers enforce one answer per transmission. |
| A sole-path publisher or server delays frames (#83) | Receptions that came only through federation are marked. Users can exclude late federated events. Documented. |
| Random registration | Needs a hit in a 64-bit space before the deadline. Negligible. |

## 11. Protocol sketch (for implementers)

WebSocket over TLS. CBOR messages, each signed by the sender's key unless noted.
Message types:
- **owner to server:** `register(x, reg[])`, `register_standing(reg[])`,
  `withdraw(reg[])`, `request(rx_ref, downlink)`, `ping`
- **publisher to server:** `publish(frame, receptions[])`,
  `result(rx_ref, result, offset_us)`
- **server to owner:** `deliver(frame, receptions[])` with publisher pseudonyms,
  `result(...)`
- **server to publisher:** `forward(rx_ref, downlink, requester pseudonym)`

Error codes cover a late registration, rate limits, an unknown `rx_ref`, and a
transmission already answered. The wire format, sizes and test vectors are for
the spec rewrite.

## 12. Open questions

1. **Bootstrap block size `B`:** 16 bounds the attacker to 16 frames of a heard
   device, and costs `W` standing registrations per device. Is 8 better?
2. **Horizon `H` and per-day limits:** are 48 epochs and the rate limits right
   for mode 3 scale?
3. **Mode 4 admission:** proof of work, slow admission, or both?
4. **Several servers:** a frame's `rx_ref`s arrive through each server. Should
   the owner request through the server with the best measured round-trip time?
5. **Fallback if the deadline rule fails review:** hash-preimage tags, where the
   pair is `trunc64(H(token_x))` and registering means revealing `token_x`. That
   is a cryptographic ownership proof with no timing, but it needs both tags from
   one hash, so `net_tag` would no longer be per network. Proxies filter by
   `net_tag` (05), so this would be a deeper frame redesign.
6. **Federated RX1:** out of scope for v1.

## 13. Impact

**Specs:**
- 09: rewritten as mailbox federation.
- 02:
  - counter-based bootstrap tags in section 11;
  - `NOP` command 0x05.
- 07: registration and publishing hooks, the separate federated bootstrap
  limiter, supervision paths, and command latency.
- 08: confirmed follow-up heartbeat after an RX2 `PENDING`, which doesn't count
  as undelivered.
- 10: trust and coverage records reduced or dropped. Device profiles stay.

**Code:**
- `sensor_core`: bootstrap tags, follow-up heartbeat, `NOP`
- `csframe.py` and vectors
- `cs_testserver`
- the new `cs-mailbox` reference server
- the Home Assistant integration's federation client

**Issues:**
- Moot or retargeted: #77, #78, #79, #80, #81, #84, #86, and most of #87 and
  #88.
- Stay in revised form: #82, #83, #85.

**Out of v1:** standalone-proxy publishing (09 section 5.2), federated RX1, and
mailbox-to-mailbox federation.
