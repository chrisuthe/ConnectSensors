# Design note: federation through blind mailboxes

Status: **accepted and implemented** (revision 3.1, PR #90). The normative text is
now in the spec: frame tags and pairing in 02, 04, 05, 06 and 07 (PR #94), mailbox
federation in `spec/09-federation-relay.md` (PR #93), and the confirmed follow-up
heartbeat in 08 (PR #98). The reference mailbox is `mailbox/` (PR #99), and the Home
Assistant integration implements the client (connect-sensors-ha PR #15). This
note keeps the rationale, the review history and the threat model; where it and
the spec differ, the spec wins.

**Revision history:**
- **1:** first-sighting ownership. Broken by round 1: a radio beats the server.
- **2:** a registration deadline on per-device tag pairs. Round 2 found skew
  exposure, cold-start gaps, brute-forceable registration hashes and unprotected
  bootstrap blocks.
- **3:** ownership by cryptographic proof. Every frame's tag is the hash of a
  public key derived from the device's key set.
- **3.1 (this one):** round 3's fixes, and a decision:
  - **Pairing is always local.** `JOIN` frames are never federated.
  - The pairing state machine keeps a provisional state.
  - Locally heard bootstrap frames fall back to trial decryption.
  - Hardened success records, corrected block arithmetic, and several smaller
    fixes.

## 1. Why

The Phase 0 review of spec 09 (#77-#88, tracked in #89) traced most problems to
two causes:
- **Anonymous participation:** any key can publish, request or flood.
- **Dumb, untrusted relays:** they can't route a frame to its owner, so owners
  hide in buckets (#81) and every publisher defends itself.

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

In every mode, **pairing is done through one of the owner's own proxies**
(section 7). Federation carries the device's traffic after it is paired.

## 3. Tags become key fingerprints

### 3.1 Derivation (replaces 02 sections 6.1 and 11)

The header's two 4-byte tag fields become one 8-byte routing `tag`, derived per
device:

```
index = "e" | uint32(epoch)              normal frames; epoch = floor(unix_time / 3600)
      | "b" | uint32((fcnt - 1) / 64)    bootstrap frames (JOIN, SYNC); 64 = 02 section 8.2's block
seed  = HMAC-SHA256(k_dev_tag, "cs1 tag seed" | index)       32 bytes
pub   = Ed25519 public key for seed (RFC 8032)
tag   = trunc64(SHA-256("cs1 tag fp" | pub))
```

- **Which key:** `k_dev_tag` is from the key set the frame is sent under (02
  section 5.1). That is the root key set for `JOIN` and the session key set for
  everything else. There is no network key in the derivation.
- **Block alignment:** `fcnt` starts at 1, and each boot starts on a reservation
  boundary (1, 65, 129, …). So `(fcnt - 1) / 64` makes one tag block equal one
  reservation block.

Properties:
- **Unpredictable and unlinkable without `k_dev_tag`,** as today. Devices of the
  same network no longer share a `net_tag`, so an observer can't group them.
- **Provable.** The holder can derive `seed`, so it can sign with the key behind
  `pub`. Someone who only heard `tag` would need a 64-bit SHA-256 preimage to
  find a usable `pub`.
- **Bootstrap frames get real tags.** Mailboxes can route `SYNC`, and a home
  server can identify bootstrap frames by lookup (with a fallback, 3.3). `fcnt`
  is clear in the header already, so a block-wide tag adds no linkability.
- **Cost on the sensor:** one Ed25519 key generation per epoch in which it
  transmits, plus one per block while sending bootstrap frames. It never signs.
  Milliseconds on ESP32; nRF52 to be measured (section 13).
- **Cost on the home server:** three key generations per device per epoch, for
  the 02 section 6.3 window (`e - 1`, `e`, `e + 1`).

### 3.2 Consequences for pairing and keys

- **`k_net_route` and `SET_NETWORK` disappear.** `KEY_EXCHANGE` already sets the
  sensor's clock (`server_time` is in every downlink, 02 section 10), so after
  accepting it the sensor can compute normal tags at once.
- **A provisional state stays.** This is today's `SESSION` with a new exit rule.
  It stops a sensor pairing to a server that has given up (round 3, H2):
  - after accepting `KEY_EXCHANGE`, the sensor holds `k_session` and sends
    confirmed uplinks with normal tags;
  - it becomes `PAIRED` only when it accepts a downlink under the session key
    set;
  - if none arrives within the existing pairing limits (04 sections 4.3-4.4), it
    erases `k_session` and returns to `UNPAIRED`, keeping its counters;
  - the server marks the device `PAIRED` when the first session uplink verifies,
    and answers it, which completes pairing for the sensor too.

  The rewrite of 04 must restate:
  - the persistence points (04 section 4.6);
  - the button rule (04 section 4.5);
  - `LEAVE` in the provisional state;
  - the server's `PAIRED` trigger. The `DL_ACK` on that first session uplink
    acknowledges a root-key downlink, which 07 section 7 doesn't cover yet.

  `SYNC` stays, for a sensor whose clock is lost or that is in lost contact (08
  section 6).
- **No network-key rotation.** 04 section 7 goes. It only ever protected tag
  linkability, which per-device tags now handle. **v1 has no remote re-key:**
  renewing a device's `k_session` means re-pairing it locally, with a button
  press.
- **Lookups move to the 8-byte tag.**
  - **Home server:** keeps a table from `tag` to device, three normal entries per
    device plus the bootstrap blocks (3.3).
  - **Proxies:** key rate limiting and dedupe on `tag` (06 sections 3 and 8).
  - **Bootstrap limiter:** keys on frame type instead of `dev_tag` 0.
  - **05 section 5.3:** the server-status `tags` field is dropped, because a
    per-device list doesn't fit in it.
- **No zero substitution:** an all-zero tag is legal, so 02 section 6.2 goes.
- **Versioning:** v1 is still a draft with no deployed devices, so the change is
  made in place.

### 3.3 Bootstrap identification on the home server

- **Table:** the home server keeps bootstrap tags in its table for each paired
  device, from the block holding the last `fcnt` seen through 2 blocks beyond
  it.
- **Fallback (round 3, M1):** when a **locally heard** bootstrap frame misses the
  table, the server falls back to today's trial decryption, under the existing
  50-per-minute bootstrap limiter (07 section 4). It can also compute the block
  from the clear `fcnt` and derive the tag for candidate devices. This is how a
  clock-lost sensor far past its last `fcnt`, or a device being paired at an
  unknown `fcnt`, is still found.
- **Federation:** only `SYNC` blocks are registered with mailboxes (5.4), never
  `JOIN`.

## 4. Mailbox routing

A mailbox server routes each frame by its `tag`:
- **A publisher**, a home server whose proxy heard a frame none of its devices
  verified, hands the frame to the server. **Publishers never publish `JOIN`
  frames** (section 7).
- **An owner** registers the tags its devices will use (section 5). The server
  delivers each frame only to that tag's registrants.
- **The server** holds no device keys and reads no payloads.

There are no buckets, decoys or broadcast. Each owner receives only its own
devices' frames, and the server does one table lookup per frame.

**Collisions:** about `T^2 / 2^65` for `T` live tags. That is negligible, and
harmless anyway, because the MIC decides.

## 5. Registration by proof

### 5.1 The registration

```
register(pub, sig, expires)
  sig = Ed25519-Sign(seed-key, "cs1 reg" | server_id | owner_pub | uint32(expires))
```

- **`server_id`:** the SHA-256 of the server's long-term public key, which the
  server presents in its greeting and proves in the TLS-authenticated session.
  Binding the server's identity, rather than a self-declared salt, stops a
  hostile server replaying a registration elsewhere (round 3, L2).
- **Owner signature:** the whole message is also signed by the home's owner key
  (5.3). That outer signature covers the message type, the list of entries and a
  per-connection sequence number.
- **Verification:** the server verifies with **strict RFC 8032 rules**:
  canonical encodings, and small-order points rejected. It then computes `tag`
  from `pub` and stores `tag → owner` until `expires`, which is capped (5.2).

Why this holds:
- **Someone who heard `tag` can't register it.** They'd need a `pub` with a
  matching hash (a 64-bit preimage), and then its private key.
- **A server can't replay a registration** to another server or for another
  owner.
- **Brute force** against *any* live tag:
  - Against the server's full set it costs about `2^64 / T` key generations,
    which is hours to days of GPU time at `T` = 10^6, by incrementing a scalar.
    It buys one random device's `rx_ref`s for less than an hour.
  - A radio attacker knows only the tags it hears, which is about 2^54 work
    within one epoch.
  - Accepted, and documented.

Only holders of the session key set can prove a device's normal and `SYNC` tags.
That is the sensor and its home server.

### 5.2 Timing and lifetime

There is no deadline. A proof is valid whenever it is presented.

| Tag | Registered | `expires` cap |
|---|---|---|
| Normal, epoch `x` | the owner keeps `e - 1` to `e + 2` registered and tops up each epoch | end of epoch `x + 1` |
| `SYNC` block | per the window in 5.4 | 7 days, renewable |

- **Fresh keys:** the owner registers a new `k_session`'s tags the moment it
  derives it. There is no cold-start gap.
- **A mailbox that lost its state** announces a new `generation` in its greeting,
  and owners re-register.
- **An offline owner:** its frames are dropped anyway, because the server stores
  nothing. Registrations stay short, so they reveal less.

### 5.3 Owner keys and limits

- **Owner key:** each home has a long-lived pseudonymous owner key (Ed25519) per
  server, which signs everything it sends.
  - Separate keys per server do **not** unlink a home across servers, because
    the same tags appear on every server (round 3, L5). Documented.
- **Lifecycle:**
  - `withdraw` affects only the caller's registrations.
  - A compromised owner key is replaced by registering under a new key and
    letting the old registrations expire. Device tags can't be proved with an
    owner key alone.
- **Limits per owner key:** a burst allowance for an initial fill, then a steady
  rate sized to about 4 registrations per tag-proving device per epoch, plus
  `SYNC` blocks. The server counts registrations; it doesn't need to know the
  number of devices.
  - Mode 4 servers also rate-limit new owner keys, by proof of work or slow
    admission.
- **Padding:** the number of live registrations reveals roughly how many devices
  a home has. Owners MAY pad with registrations for random keys.

### 5.4 `SYNC` windows

- **Normal operation:** the owner keeps registered the `SYNC` block holding the
  last `fcnt` seen, plus the next 2.
- **Lost contact (07 section 8):** the window grows to cover the uplinks the
  owner expects it missed: `ceil(expected / 64)` blocks beyond the last seen,
  capped at 16 blocks (1 024 frames).
  - `expected` is computed from the time since the last frame, divided by the
    device's heartbeat interval.
  - It is doubled for the 08 section 6 retry pattern, plus 1 per boot the owner
    can't rule out.
  - Any later frame with a normal tag re-centres the window.

`JOIN` blocks are never registered (section 7).

## 6. Downlinks: `rx_ref` capabilities

1. **Publish.** The publisher hands the server `(frame, receptions)`. Each
   reception carries:
   - a random `rx_ref`, issued per server;
   - SNR, RSSI and `age_ms`;
   - the `TS_UNCERTAIN` flag;
   - a downlink-capable flag. It is set only if that proxy is a 07 section 6.1
     candidate and the frame is a confirmed type.
2. **Deliver.** The server sends the frame and its `rx_ref`s **only to the
   registrants** of the frame's `tag`. With each delivery it includes its own
   measured round-trip time to the publisher, `rtt_pub`.
3. **Request.** The owner decides to answer (07 section 5) and sends a signed
   `(rx_ref, DOWNLINK)`.
   - It sends at most **one request per transmission**, through one server.
   - A *transmission* is a frame hash plus 07 section 4.3's 2 s rule, measured on
     the server's clock at publish time. A retry carries the same bytes but comes
     at least 4 s later, so it is a new transmission.
4. **Server check.** At most one request per transmission is forwarded.
5. **Publisher check.**
   - The `rx_ref` is known, unused and fresh.
   - The downlink passes the keyless checks, with the same `tag`.
   - This transmission hasn't been answered yet: not through any server, and not
     by its own local answer path. **There is one downlink per RX2 window in
     total (07 section 6.3), local and federated together** (round 3, L6).
   - Its federated airtime budget allows it, per proxy and per requester
     pseudonym. The requester share is a decaying quota that lowers priority,
     never a ban.

   It then transmits in RX2 (`tx_offset_us = 3 000 000`). Its own traffic has
   priority.
6. **Result.** The `TX_RESULT` goes back through the server. A non-`SENT` result
   releases the transmission's slot, so the owner may retry through another
   publisher if time allows. A publisher that falsely reports non-`SENT` after
   transmitting could put two frames into one RX2. That is the same class of
   problem as a publisher dropping requests; section 8 records count it as a soft
   failure.

Neither side learns the other's identity: the server gives each a stable
pseudonym derived from its key. Only holders of the device's session key set
ever receive `rx_ref`s (11.1).

### 6.1 Timing

Federated downlinks use RX2, which opens 3 s after the uplink. The owner
measures from the moment a delivery arrives:

```
t_first   = age_ms + rtt_pub/2 + rtt_owner/2 + 150 ms   time already spent before delivery:
                                                         age, publisher→server, server→owner,
                                                         and the publisher's collection window
t_back    = rtt_owner/2 + rtt_pub/2 + 300 ms             owner→server→publisher, plus the
                                                         publisher→proxy hop and proxy scheduling
request only if  t_first + (now - delivery_time) + t_back  <=  2700 ms
```

- `rtt_owner` is measured by the owner's ping every 30 s.
- `rtt_pub` comes with each delivery.
- The 300 ms margin sits inside the 2700 ms. The last 300 ms before RX2 is
  reserved for the proxy's own 40 ms start window (01 section 4.1) and jitter.
- If the check fails, the owner doesn't request, and the sensor retries.

### 6.2 Commands and `PENDING`

- **Follow-up heartbeat:**
  - When a downlink carrying `PENDING` arrives in RX2, the follow-up `HEARTBEAT`
    is **confirmed**, so it opens RX2. This also applies after a local RX2
    fallback.
  - An unanswered follow-up doesn't count as undelivered for 08 section 6.
- **First-command latency:** a device heard only through federation gets its
  first queued command, or a clock correction, on its next confirmed uplink.
  That is a state change, or the confirmed heartbeat: 4 h recommended, 24 h at
  most (08 section 4.2). Documented in 07.
- **`NOP` (0x05)** gets reserved in 02 section 10.3. It needs no firmware change,
  because an unknown command is skipped and still sets `DL_ACK` (02 section
  10.2; `sensor_core.cpp` sets `had_command` before the command switch).

## 7. Commissioning: pairing is always local

**Pairing is done through one of the owner's own proxies, in every mode.**
- Scan the QR code (or type the code) in **Add device**, then press the button
  near your own proxy.
- No ESPHome build server is involved.
- After pairing, the sensor can be moved anywhere a federated publisher hears
  it.

**Rules:**
- **Publishers never publish `JOIN` frames,** and owners never register `JOIN`
  blocks.
- A `JOIN` heard by a neighbour goes nowhere. So a federated party can never
  answer a pairing, and can't race a local one whose RX1 missed. The RX2
  fallback for `KEY_EXCHANGE` stays local.

**Why:** `JOIN` tags derive from `k_root`, which is printed on the label. Anyone
who has seen it could prove `JOIN` tags: a reseller, the factory, someone who
photographed the label, a previous owner. Federating `JOIN` would let them
watch, block or race pairings remotely (round 3, H1).

Keeping pairing local returns this to today's exposure (02 section 13): an
attacker must be **in radio range during the pairing**. The spec SHOULD advise
re-flashing `k_root` on second-hand or untrusted devices for full protection.

**Proxies:** not part of federation. Plug-and-play proxies would need Improv
Wi-Fi plus mDNS discovery. Tracked separately.

**Possible later extension:** federated pairing in modes 2 and 3, where members
are known. Out of v1.

## 8. Choosing a publisher

In mode 4, anyone with a radio can publish a frame it heard, claim a good SNR,
and then drop the request (#79). The owner keeps a **record per publisher
pseudonym**. It is best effort:

- **Credit:**
  - Earned only from an exchange where exactly one downlink answered the frame,
    across all its transmissions, the downlink carried a command or `NOP`, and
    the sensor's next new uplink sets `DL_ACK`.
  - If several publishers answered the same frame, nobody is credited or blamed.
- **Failure:**
  - **Hard:** the downlink carried a command or `NOP`, and the uplink with
    `fcnt = reply_to + 1` arrives without `DL_ACK`.
  - **Soft:** a non-`SENT` result, or no result.
  - Both kinds decay with a half-life of 7 days, so one radio loss doesn't
    demote an honest publisher for good.
- **Phantom retries:** a "retry" of a frame is ignored for credit and failure if
  the publisher that reported the original didn't also report it. That stops a
  phantom retry from voiding an honest publisher's credit.
- **Order:**
  1. proven publishers, by SNR;
  2. unknowns, picked at random;
  3. failed publishers, by decayed score.

  Open question: the server could attest a key's age in coarse buckets.
- **Rotation:** across a frame's retries, the owner picks a different publisher
  each time. Retries are at least 4 s apart and RX2 is at 3 s, so this fits.
- **SNR cap:** values outside the profile's physical range are ignored.

**Supervision (#84):**
- A federated path is one publisher pseudonym on one server.
- Federated paths are shown separately from the home's own proxies, and **never
  clear the single-path flag**.

## 9. Several servers

A home MAY use several servers. Each issues its own `rx_ref`s.
- **The owner** requests each transmission through one server only: the one with
  the lowest `rtt_owner + rtt_pub`.
- **Publishers** answer each transmission at most once, across all servers and
  their own local path.
- Only session-key holders receive `rx_ref`s, so two homes can't both request
  the same frame.

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

**Only holders of a device's session key set (the sensor and its home server)
can register its tags, so only they receive its frames' `rx_ref`s through a
mailbox.** Hearing a frame by radio, or seeing it through a server, grants no
routing or downlink access. `JOIN` is never federated, so `k_root` holders gain
nothing from mailboxes.

The exceptions are explicit:
- **A malicious server:** can misroute, drop, delay or leak `rx_ref`s to an
  accomplice, but only for homes that use it.
- **A publisher:** can drop or delay frames it publishes. Section 8 handles this
  for downlinks; for uplinks it remains (#83).
- **Brute force** for a random live tag, as in 5.1.
- **Local pairing exposure:** an attacker in radio range during pairing who holds
  `k_root`. This is unchanged from today.

What's left for a radio attacker near a device is jamming, as in any LoRa system.

### 11.2 Threats

| Threat | Mitigation |
|---|---|
| A server reads readings | It can't: payloads are encrypted under device keys. |
| A server links a home's registrations and traffic | Inherent: they're signed by the owner key, tags are global across servers, and `fcnt` is clear (02 section 13). The server sees per-owner timing, type nibble and length. Documented. |
| Proxy mapping with a moving sensor | Stable publisher pseudonyms plus signal values. Documented. Publishers MAY coarsen RSSI and SNR. |
| Black-holed downlinks (#78) | Only session-key holders get `rx_ref`s. One request per transmission, released on failure. |
| Fake publisher SNR (#79) | Section 8: credit, hard and soft failures, decay, phantom-retry rule, random unknowns, rotation, SNR cap. |
| Bootstrap flood (#80) | `JOIN` isn't federated. `SYNC` is routed by `tag` to its owner only. Transmission dedupe and per-publisher rate limits at the server. A federated bootstrap limiter separate from the local one (07 section 4). |
| Remote pairing attacks by `k_root` holders | `JOIN` isn't federated (section 7). |
| Airtime drain | Per-proxy budget with decaying per-requester quotas. Only key holders can request. |
| A malicious server | Limited to homes that use it, and it can't replay proofs elsewhere (5.1). |
| A sole-path publisher or server delays frames (#83) | Receptions that came only through federation are marked, and users can exclude late federated events. Documented. |

## 12. Protocol sketch

WebSocket over TLS. CBOR messages, signed by the sender's key. The server's
greeting carries its public key, `server_id` and `generation`.

| Direction | Messages |
|---|---|
| owner → server | `register(pub, sig, expires)[]`, `withdraw(tag[])`, `request(rx_ref, downlink)`, `ping` |
| publisher → server | `publish(frame, receptions[])`, `result(rx_ref, result, offset_us)` |
| server → owner | `deliver(frame, receptions[], publisher pseudonym, rtt_pub)`, `result(...)` |
| server → publisher | `forward(rx_ref, downlink, requester pseudonym)` |

Errors: bad proof, rate limited, unknown `rx_ref`, already answered. The wire
format, sizes and vectors are for the spec rewrite.

## 13. Open questions

1. **Ed25519 on nRF52:** key generation time on the XIAO nRF52840, and whether
   CryptoCell acceleration is reachable from ESPHome's nRF52 platform. Measure
   during #38.
2. **The header's 8-byte tag:** one field, or two fields (`tag_hi`, `tag_lo`)?
   It's cosmetic. This note assumes one.
3. **Mode 4 admission:** proof of work, slow admission, or both?
4. **Attested key age (section 8):** is it worth the metadata it gives the server?
5. **Federated pairing in modes 2 and 3:** a later extension.
6. **Federated RX1:** out of scope for v1.

## 14. Spec rewrite checklist

**Sections to change** (from round 3):
- **00:** the definition of "network".
- **02:**
  - section 2, the layout with the 8-byte `tag`;
  - the section 4 table;
  - section 5.2, `k_net_route` removed;
  - section 6, the tags, with 6.2 removed;
  - section 10.3, `NOP` reserved and `SET_NETWORK` removed;
  - sections 11 and 11.3-11.4, bootstrap tags and identification;
  - section 13, privacy;
  - section 14, the examples.
- **04:**
  - section 4 in full, the provisional state and the shorter flow;
  - sections 5, 6.1-6.2 and 8, consistency;
  - section 7, removed;
  - section 9, vectors.
- **05:** section 5.3, drop `tags`; tag width wherever `dev_tag` appears.
- **06:** config and logs, with rate limit, dedupe and limiter keyed on `tag` or
  frame type.
- **07:**
  - sections 2.1 and 3, the tag table and state;
  - section 4, the lookup, the bootstrap fallback and the federated bootstrap
    limiter;
  - the section 5 table;
  - section 6.3, one downlink per RX2 window including federated ones;
  - section 7, the `DL_ACK` that acknowledges the root-key downlink at pairing;
  - section 8, federated paths;
  - section 11.1;
  - section 11.4, `rotate_network_key` removed;
  - command latency.
- **08:**
  - sections 2 and 3.2;
  - section 7, the follow-up heartbeat;
  - section 8.
- **09:** rewritten as mailbox federation.
- **10:** trust and coverage records reduced or dropped; device profiles stay.

**Details the rewrite must pin down:**
- the home server's bootstrap table size and fallback;
- the server clock used for the 2 s transmission rule;
- the lost-contact window formula (5.4);
- the half-life of record decay;
- the `server_id` format and the outer signature's coverage;
- strict Ed25519 verification;
- the CBOR wire format.

**Vectors needed:**
- seed, `pub` and `tag` for epoch indices, and for block indices at `fcnt` 1,
  64, 65 and 129;
- root and session bootstrap tags;
- a registration signature, with strict-verification negatives (non-canonical
  `S`, a small-order `pub`);
- the shortened pairing sequence;
- a `NOP` downlink followed by `DL_ACK`.

**Code:**
- `sensor_core`: tags, the provisional state, the follow-up heartbeat
- `cs_proxy` and `proxy_core`: tag width, limiter
- `csframe.py`, vectors, `cs_testserver`
- the Home Assistant integration: the tag table, pairing, the bootstrap fallback
- `cs-mailbox`
- the integration's federation client

**Issues:**
- Moot or retargeted: #77, #78, #79, #80, #81, #84, #86, and most of #87 and #88.
- Stay in revised form: #82, #83, #85.
