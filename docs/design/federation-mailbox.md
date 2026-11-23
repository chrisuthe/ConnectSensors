# Design note: federation through blind mailboxes

Status: proposal, revision 3, for review. If accepted, it replaces the Nostr
design of `spec/09-federation-relay.md`, changes how frame tags are derived (02
sections 6 and 11), and removes most of `spec/10-control-plane.md` sections 5-7.

Revision history:
- **Revision 1:** first-sighting ownership. Review round 1 broke it: a radio
  beats the server.
- **Revision 2:** a registration deadline on per-device tag pairs. Review round 2
  found skew exposure, cold-start gaps, brute-forceable registration hashes and
  unprotected bootstrap blocks.
- **Revision 3 (this one):** **ownership by cryptographic proof**. Every frame's
  tags are the hash of a public key derived from the device's key set.
  Registering means proving you hold the matching private key. There is no
  deadline, no timing race and no special case for bootstrap frames.

## 1. Why

The Phase 0 review of spec 09 (#77-#88, tracked in #89) traced most problems to
two causes:
- **Anonymous participation:** any key can publish, request or flood.
- **Dumb, untrusted relays:** they can't route a frame to its owner, so owners
  hide in buckets (#81), and every publisher has to defend itself.

This note proposes servers that route frames to their owners without knowing who
the owners are, and without any central coordinator.

## 2. Operating modes

| Mode | Server | Membership | Uplinks | Downlinks (acks, commands) |
|---|---|---|---|---|
| 1 Standalone | none | - | own proxies | own proxies |
| 2 Private | a group's own mailbox server | invite or admin | routed | yes |
| 3 Public | a large operator's mailbox server | operator accounts | routed | yes |
| 4 Open | any mailbox server | none | routed | yes, best effort (11.1) |

Modes 2-4 share one protocol and one reference server, `cs-mailbox`. They differ
only in admission policy and defaults (section 10). Mode 4 needs nobody's
permission, so there is no control plane anyone has to answer to.

## 3. Tags become key fingerprints

### 3.1 Derivation (replaces 02 sections 6.1 and 11)

The header's two 4-byte tag fields become one 8-byte routing `tag`, derived per
device:

```
index = "e" | uint32(epoch)          normal frames, epoch = floor(unix_time / 3600)
      | "b" | uint32(fcnt / 64)      bootstrap frames (JOIN, SYNC); 64 = 02 section 8.2's block
seed  = HMAC-SHA256(k_dev_tag, "cs1 tag key" | index)        32 bytes
pub   = Ed25519 public key for seed (RFC 8032)
tag   = trunc64(SHA-256("cs1 tag" | pub))
```

`k_dev_tag` is from the key set the frame is sent under (02 section 5.1):
- the root key set for `JOIN`;
- the session key set for everything else.

There is no network key in the derivation.

Properties:
- **Unpredictable and unlinkable without `k_dev_tag`.** This is unchanged from
  today, and better in one respect: devices of the same network no longer share
  a `net_tag`, so an observer can't group them.
- **Possession can be proved without revealing `k_dev_tag`.** The holder can
  derive `seed`, so it can sign with the key behind `pub`. Someone who only heard
  `tag` would need a 64-bit SHA-256 preimage to find a usable `pub`.
- **Bootstrap frames get real tags.** They're routable and identifiable by lookup
  instead of trial decryption, which helps mode 1 too. The block size is 64,
  matching 02 section 8.2's counter reservation. `fcnt` is clear in the header
  already, so a block-wide tag adds no linkability.
- **Cost on the sensor:** one Ed25519 key generation per epoch, plus one per
  64-counter block while sending bootstrap frames. That is milliseconds on ESP32
  and nRF52, and it can be precomputed before the epoch boundary.
- **Cost on the home server:** three key generations per device per epoch for
  the 02 section 6.3 window (`e - 1`, `e`, `e + 1`). That is trivial.

### 3.2 Consequences for the rest of the spec

- **`k_net_route` and its tag role disappear.** `SET_NETWORK` no longer carries a
  routing key. Pairing shortens:
  - `KEY_EXCHANGE` already sets the sensor's clock (`server_time` in every
    downlink, 02 section 10).
  - So after accepting it, the sensor can compute normal tags at once. Its next
    uplink, with `DL_ACK`, completes pairing.
  - The `SYNC` / `SET_NETWORK` step and network-key rotation (04 section 7) go
    away. To renew a device's keys, renew `k_session`; that mechanism already
    exists.
  - The exact 04 state-machine edits belong in the spec rewrite.
- **Lookups move to the 8-byte tag.** The home server keeps a table from `tag` to
  device, three entries per device. Proxies key rate limiting and dedupe on
  `tag` (06 sections 3 and 8; today they use `dev_tag`). The bootstrap limiter
  (06, keyed on `dev_tag` 0 today) keys on frame type instead.
- **No zero substitution:** a computed all-zero tag is legal. 02 section 6.2 goes.
- **Versioning:** v1 is still a draft with no deployed devices, so the change is
  made in place. No compatibility mode.

## 4. Mailbox routing

A mailbox server routes each frame by its `tag`:
- **A publisher**, a home server whose proxy heard a frame none of its devices
  verified, hands the frame to the server.
- **An owner** registers the tags its devices will use (section 5). The server
  delivers each frame only to that tag's registrants.
- **The server** holds no device keys and reads no payloads.

There are no buckets, decoys or broadcast. Each owner receives only its own
devices' frames, and the server does one table lookup per frame.

**Collisions:** with `T` live tags, the chance that any two collide is about
`T^2 / 2^65`, negligible even at 10^8.

## 5. Registration by proof

### 5.1 The registration

```
register(pub, sig, expires)
  sig = Ed25519-Sign(seed-key, "cs1 reg" | server_salt | owner_pub | uint32(expires))
```

- `server_salt` is a public random value per server, sent in its greeting.
- `owner_pub` is the registering home's owner key (5.3). The message as a whole
  is also signed by the owner key.

The server verifies `sig` under `pub` and computes `tag` from `pub`. It then
stores `tag → owner` until `expires`, which is capped (5.2).

Why this holds:
- **Someone who heard `tag` can't register it.** They'd need a `pub` whose hash
  matches, which is a 64-bit preimage, and then the private key behind it.
- **A server can't replay a registration** to another server or for another
  owner: the signature binds `server_salt` and `owner_pub`.
- **Brute force** for *any* live tag among `T` costs about `2^64 / T` Ed25519 key
  generations: about 2^44 at a million live tags. That is days of GPU time per
  hit, and it buys one random device's `rx_ref`s for less than an hour. Normal
  tags rotate every epoch, and bootstrap tags are rarely live. Accepted, and
  documented.

Several homes may hold a valid proof for one tag only in one case: a previous
owner who kept `k_root` can prove `JOIN` tags (5.4). The server delivers to every
valid registrant.

### 5.2 Timing and lifetime

There is no deadline. A proof is valid whenever it is presented, including late.

| Tag | When registered | `expires` cap |
|---|---|---|
| Normal, epoch `x` | any time; the owner keeps `e - 1` to `e + 2` registered and tops up each epoch | end of epoch `x + 1` |
| Bootstrap block | while the device is pairing or might send `SYNC` (5.4) | 7 days, renewable |

- **Fresh keys** (pairing, re-keying): the owner registers the new session
  key's tags the moment it derives `k_session`. There is no cold-start gap.
- **A mailbox that lost its state** says so with a new `generation` value in its
  greeting, and owners re-register.
- **Owners offline:** frames for an offline owner are dropped anyway, because the
  server stores nothing. Registering far ahead buys nothing, so registrations
  stay short and reveal less.

### 5.3 Owner keys and limits

- Each home has a long-lived, pseudonymous **owner key** (Ed25519) per server. It
  signs every message the home sends. Homes MAY use different keys on different
  servers.
- **Owner-key lifecycle:**
  - `withdraw` affects only the caller's own registrations.
  - A compromised owner key is replaced by registering under a new key and
    letting the old registrations expire. Proofs of device tags can't be forged
    with an owner key alone.
- **Limits per owner key:**
  - a burst for the initial fill, about 4 × devices;
  - then a steady rate of about 1 per device per epoch, plus bootstrap blocks.
  - Mode 4 servers rate-limit new owner keys (proof of work or slow admission).
- **Padding:** the count of live registrations reveals roughly how many devices a
  home has. Owners MAY pad with registrations for random keys.

### 5.4 Bootstrap windows and second-hand devices

The owner keeps bootstrap blocks registered whenever a device might send `JOIN`
or `SYNC`:
- **A device being paired:**
  - `JOIN` blocks for the root key set, covering `fcnt` from 1 to 64 × 8. That
    allows for boots in factory QA, since every boot skips up to 64 (02 section
    8.2).
  - The session key's `SYNC` blocks once `k_session` exists.
- **A paired device:**
  - Normally, the `SYNC` block holding the last `fcnt` seen, plus the next 2.
  - In lost contact (07 section 8), the window grows by one block for every 64
    uplinks the owner expects it missed, capped at 16 blocks.

**Second-hand devices:**
- A factory reset keeps `fcnt`, so the new owner can't predict the `JOIN` blocks
  of a used device.
- The previous owner, who knows `k_root`, *can* prove `JOIN` tags. They could
  race the new owner's federated pairing.
- **So the first pairing of a second-hand device MUST be done near one of the
  owner's own proxies.**
- Local pairing needs no registration and gives a new `k_session`. From then on
  only the new owner can prove the device's tags.

## 6. Downlinks: `rx_ref` capabilities

1. **Publish.** The publisher hands the server `(frame, receptions)`. Each
   reception has:
   - a random `rx_ref`, issued per server;
   - SNR, RSSI and `age_ms`;
   - the `TS_UNCERTAIN` flag;
   - a downlink-capable flag. It is set only when that proxy is a 07 section 6.1
     candidate and the frame is a confirmed type.
2. **Deliver.** The server sends the frame and its `rx_ref`s **only to the
   registrants** of the frame's `tag`. With each delivery it includes its
   measured round-trip time to the publisher.
3. **Request.** The owner decides to answer (07 section 5), then sends a signed
   `(rx_ref, DOWNLINK)`.
   - The owner sends at most **one request per transmission**, through one
     server.
   - A *transmission* is a frame hash plus the 2 s rule of 07 section 4.3. So a
     retry (the same bytes, at least 4 s later) is a new transmission.
4. **Server check.** At most one request per transmission is forwarded.
5. **Publisher check.** The publisher verifies:
   - the `rx_ref` is known, unused and fresh;
   - the keyless checks pass, with the same `tag` as the uplink;
   - it hasn't already answered this transmission through any server;
   - its federated airtime budget allows it, per proxy and per requester
     pseudonym. The per-requester share is a decaying quota that lowers
     priority, never a ban.

   It then sends the `DOWNLINK` with `tx_offset_us = 3 000 000` (RX2). Its own
   traffic has priority.
6. **Result.** The `TX_RESULT` goes back through the server. A non-`SENT` result
   releases the transmission's slot at the server, so the owner may retry
   through another publisher if time allows.

Neither side learns the other's identity: the server gives each a stable
pseudonym derived from its key. Requests need an `rx_ref`, and only holders of
the device's key set ever receive one (section 11.1).

### 6.1 Timing

Federated downlinks use RX2, which opens 3 s after the uplink. The owner
requests only if this holds:

```
elapsed + rtt_owner/2 + rtt_pub/2 + 300 ms  <=  2700 ms
elapsed = age_ms + publisher→server leg (rtt_pub/2) + time since delivery
```

- `rtt_owner` is the owner's own measured round-trip time to the server, from a
  ping every 30 s.
- `rtt_pub` is the server's measured round-trip time to the publisher, sent with
  each delivery.
- The 300 ms margin covers the publisher-to-proxy hop and the proxy's scheduling.
  The proxy still enforces its own 40 ms start window (01 section 4.1).

If the check fails, the owner doesn't request, and the sensor retries.

### 6.2 Commands and `PENDING`

- **Follow-up heartbeats:**
  - When a downlink carrying `PENDING` arrives in RX2, the follow-up `HEARTBEAT`
    is **confirmed**, so it opens RX2. This also applies after a local RX2
    fallback, a small local change.
  - An unanswered follow-up doesn't count as undelivered for 08 section 6.
- **First-command latency:** a device heard only through federation gets its
  first queued command on its next confirmed uplink. That is a state change, or
  the confirmed heartbeat, which is 4 h recommended and 24 h at most (08 section
  4.2). Clock corrections wait the same way. This is documented in 07.
- **`NOP` (0x05)** gets reserved in 02 section 10.3.
  - No firmware change is needed: an unknown command is skipped and still sets
    `DL_ACK` (02 section 10.2).
  - Owners add it when they need delivery evidence (section 8).

## 7. Commissioning

1. **A pre-sold sensor near your own proxy:** unchanged. Scan the QR code (or
   type the code) in **Add device**, press the button, and it's paired. No
   ESPHome build server is involved.
2. **A pre-sold sensor heard only by a neighbour:** the same steps.
   - Entering the code lets the integration register the `JOIN` blocks (5.4).
   - The `JOIN` is routed to you, and `KEY_EXCHANGE` goes out in RX2 through the
     neighbour's proxy.
   - You register the new session key's tags at once, so the sensor's next
     uplink, with `DL_ACK`, completes pairing.
3. **A second-hand sensor:** pair locally first (5.4).
4. **Proxies:** not part of federation. Plug-and-play proxies would need Improv
   Wi-Fi plus mDNS discovery. That's tracked separately.

## 8. Choosing a publisher

In mode 4, anyone with a radio can publish a frame it heard, claim a good SNR,
and then drop the request (#79). The owner keeps a **record per publisher
pseudonym**. It is best effort:

- **Credit** comes only from an exchange where exactly one downlink answered the
  frame, across all its transmissions, and the sensor's next new uplink sets
  `DL_ACK`. The owner adds `NOP` when the downlink carries no command and it
  wants evidence. If several publishers answered the same frame, nobody is
  credited and nobody blamed.
- **Failure** is counted only when the uplink with `fcnt = reply_to + 1`
  arrives without `DL_ACK`. Silence, lost uplinks and missing retries count as
  nothing.
- **Order:**
  - proven publishers, by SNR;
  - then unknowns, picked at random. The server may attest a key's age in
    coarse buckets, and older keys are preferred.
  - then failed publishers.
- **Rotation:** across a frame's retries, the owner picks a different publisher
  each time. Retries are at least 4 s apart, and RX2 is at 3 s, so this fits.
- **SNR cap:** values outside the profile's physical range are ignored.
- **Phantom retries** are possible: a publisher republishes a delivered frame as
  a "retry". Under the credit rule, that makes the exchange ambiguous. It can
  deny an honest publisher credit, but can't earn the attacker any. Accepted.

**Supervision (#84):**
- A federated path is one publisher pseudonym on one server.
- Federated paths are shown separately from the home's own proxies, and **never
  clear the single-path flag**.

## 9. Several servers

A home MAY use several servers. Each issues its own `rx_ref`s:
- **The owner** requests each transmission through one server only, the one
  with the lowest `rtt_owner + rtt_pub`.
- **Publishers** answer each transmission at most once across servers.
- Since only the device's key holders receive `rx_ref`s, two homes can't both
  request the same frame, except in the second-hand `JOIN` case (5.4). That is
  why the local-pairing rule exists.

## 10. Mode policies

| | Mode 2 Private | Mode 3 Public | Mode 4 Open |
|---|---|---|---|
| Who may connect, publish and register | members (invite) | account holders | anyone, admission rate-limited |
| Federated downlink budget per publisher proxy | group default, generous | operator default | 0.5% airtime per hour, shared by decaying per-requester quotas |
| Removing abusers | admin | operator | none; owners rely on records |
| What the server sees | metadata (11.2) | metadata | metadata |

The protocol defines the mechanisms. The spec gives recommended defaults per
mode, and operators MAY set others.

## 11. Threat model

### 11.1 Invariant

**Only holders of a device's key set can register its tags, so only they receive
its frames' `rx_ref`s through a mailbox.** Hearing a frame by radio, or seeing it
through a server, doesn't grant routing or downlink access. The exceptions are
explicit:
- **A previous owner holding `k_root`** can prove `JOIN` tags. It is handled by
  local pairing (5.4).
- **A malicious server** can misroute, drop, delay or leak `rx_ref`s to an
  accomplice, but only for homes that use it.
- **A publisher** can drop or delay the frames it publishes. Section 8 counters
  this for downlinks; for uplinks it remains (#83).
- **Brute force** for a random live tag costs about `2^64 / T` key generations
  (5.1).

What remains for a radio attacker near a device is jamming, as in any LoRa
system.

### 11.2 Threats

| Threat | Mitigation |
|---|---|
| A server reads readings | It can't: payloads are encrypted under device keys. |
| A server links a home's registrations and traffic | Inherent: they're signed by the owner key. Clear `fcnt` also links frames (02 section 13). The server sees per-owner timing, type nibble and length. Documented. Owners MAY use separate keys per server. |
| Proxy mapping with a moving sensor | Stable publisher pseudonyms plus signal values. Documented. Publishers MAY coarsen RSSI and SNR. |
| Black-holed downlinks (#78) | Only key holders get `rx_ref`s (11.1). One request per transmission, released on failure. |
| Fake publisher SNR (#79) | Credit and failure rules, random choice among unknowns, rotation, SNR cap (section 8). |
| Bootstrap flood (#80) | Bootstrap frames are routed by `tag` to their owner only. The server dedupes by transmission and rate-limits per publisher. A separate federated bootstrap limiter in 07 section 4 keeps local pairing unaffected. |
| Airtime drain | Per-proxy budget split into decaying per-requester quotas. Only key holders can request at all. Sybil requesters would need their own devices transmitting near the proxy. |
| A malicious server | Limited to homes that use it. It can't replay proofs elsewhere (5.1). |
| A sole-path publisher or server delays frames (#83) | Receptions that came only through federation are marked, and users can exclude late federated events. Documented. |

## 12. Protocol sketch

WebSocket over TLS, with CBOR messages signed by the sender's key. The server's
greeting carries `server_salt` and `generation`.

| Direction | Messages |
|---|---|
| owner → server | `register(pub, sig, expires)[]`, `withdraw(tag[])`, `request(rx_ref, downlink)`, `ping` |
| publisher → server | `publish(frame, receptions[])`, `result(rx_ref, result, offset_us)` |
| server → owner | `deliver(frame, receptions[], publisher pseudonym, rtt_pub)`, `result(...)` |
| server → publisher | `forward(rx_ref, downlink, requester pseudonym)` |

Errors cover a bad proof, rate limits, an unknown `rx_ref` and an
already-answered transmission. The wire format, sizes and vectors are for the
spec rewrite.

## 13. Open questions

1. **Ed25519 on nRF52:** key generation time on the XIAO nRF52840, and whether
   hardware acceleration (CryptoCell) is usable from ESPHome's nRF52 platform.
   This needs measuring (#38).
2. **The 8-byte tag in the header:** keep two 4-byte fields named `tag_hi` and
   `tag_lo`, or one field? It is cosmetic. This note assumes one.
3. **Mode 4 admission:** proof of work, slow admission, or both?
4. **Attested key age (section 8):** is it worth the metadata it gives the server?
5. **Federated RX1:** out of scope for v1.

## 14. Impact

**Specs:**
- 02: tag derivation (sections 6 and 11), the 8-byte header field, section 6.2
  removed, `NOP` reserved, `k_net_route` removed.
- 04: shorter pairing (no `SYNC` / `SET_NETWORK` step), section 7 rotation
  removed.
- 05 and 06: lookups, rate limits and dedupe keyed on the 8-byte tag, the
  bootstrap limiter keyed by frame type, and the 05 section 5.3 diagnostics tag
  list updated.
- 07:
  - the tag table;
  - the federated bootstrap limiter;
  - registration and publishing hooks;
  - supervision paths;
  - command latency.
- 08: the confirmed follow-up heartbeat after an RX2 `PENDING`, which doesn't
  count as undelivered.
- 09: rewritten as mailbox federation.
- 10: trust and coverage records reduced or dropped. Device profiles stay.

**Code:**
- `sensor_core`: tags, pairing, follow-up heartbeat
- `cs_proxy` and `proxy_core`: tag width, limiter
- `csframe.py`, vectors, `cs_testserver`
- the Home Assistant integration: tag table and pairing
- a new `cs-mailbox`, and the integration's federation client

**Issues:**
- Moot or retargeted: #77, #78, #79, #80, #81, #84, #86, and most of #87 and #88.
- Stay in revised form: #82, #83, #85.

**Out of v1:** standalone-proxy publishing, federated RX1, and
mailbox-to-mailbox federation.
