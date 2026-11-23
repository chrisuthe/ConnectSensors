# Design note: federation through blind mailboxes

Status: proposal for review. If accepted, it replaces the Nostr design of
`spec/09-federation-relay.md` and most of `spec/10-control-plane.md` sections 5-7.

## 1. Why

The Phase 0 review of spec 09 (#77-#88, tracked in #89) found that most of its
problems come from two root causes:

1. **Anyone can take part anonymously.** Any Nostr key can publish frames, send
   downlink requests or flood a bucket. This causes black-holed downlinks (#78),
   fake-SNR selection (#79), bootstrap floods (#80), Sybil paths (#84) and
   verification load (#86).
2. **Relays are dumb and untrusted.** They can't route a frame to its owner, so
   owners subscribe to broad buckets and try to hide in them (#81), and every
   publisher has to defend itself.

Patching each issue would keep the Nostr shape and add allow lists, budgets,
reputation, per-request keys and encrypted requests on top. This note proposes a
different shape that removes most of those problems instead of mitigating them,
and that works without any central coordinator.

## 2. Operating modes

| Mode | Server | Membership | Uplinks | Downlinks (acks, commands) |
|---|---|---|---|---|
| 1 Standalone | none | - | own proxies | own proxies |
| 2 Private | a group's own mailbox server | invite or admin | routed by tag | yes |
| 3 Public | a large operator's mailbox server | operator accounts | routed by tag | yes |
| 4 Open | any mailbox server | none | routed by tag | yes |

Modes 2-4 use the same protocol and the same reference server (`cs-mailbox`). They
differ only in admission policy and defaults (section 8). Mode 4 needs nobody's
permission: running or choosing a server is enough, so the project needs no
control plane anyone has to answer to.

## 3. Core idea: rotating tags are blind addresses

Every normal frame carries `net_tag = trunc32(HMAC(k_net_route, "net" | epoch))`
with `epoch = floor(unix_time / 3600)` (02 section 6). Without the network key,
tags look random, can't be linked across hours, and **can't be predicted**.

A mailbox server routes frames by `net_tag`:

- **A publisher** (a home server whose proxy heard a frame none of its devices
  verified) hands the frame to the server.
- **An owner** registers the tags it expects. The server delivers each frame only
  to that tag's registrants.
- **The server** holds no device keys and reads no payloads: sensor payloads stay
  encrypted end to end under device keys (02 section 5).

There are no buckets, no decoys and no broadcast. An owner receives only its own
frames, and the server does one table lookup per frame, so it scales to mode 3
sizes.

## 4. Ownership by registering first

### 4.1 Rule

Only the network key can predict a future epoch's tags, so registering a tag
before it appears on air proves ownership without revealing anything else.

- An owner registers its tags for epochs `e + 1` and `e + 2` during epoch `e`
  (`e + 2` covers clock skew and reconnects). This is two to three tags per
  network.
- The server records, for each tag, the time it first saw a published frame
  carrying it (*first sighting*).
- **A registration for a tag that was already sighted is refused** (within a
  retention window, section 4.3).
- Several registrations of an unsighted tag are all accepted (section 4.2).

An attacker with a radio learns a tag only when the sensor transmits it. By then
the owner's registration exists, and the attacker's is refused.

### 4.2 Collisions

Tags are 32 bits. With `N` networks, about `N^2 / 2^33` pairs share a tag per
epoch, which is about 116 pairs at a million networks. Accepting several
pre-sighting registrants handles this: the server delivers to all of them. Each
owner verifies the MIC and ignores frames that aren't its own. An honest
collision partner never requests a downlink for a frame it can't verify, so
`rx_ref` capabilities (section 5) stay safe in practice.

### 4.3 Server state and limits

- **Sightings** are kept for 3 epochs, which is enough for the refusal rule,
  because registrations only target `e + 1` and `e + 2`.
- **Registrations** expire at the end of their epoch.
- **Rate limits per connection** stop an attacker from pre-registering a large
  share of the 2^32 tag space. Example: at most 64 registrations per epoch, which
  covers about 20 networks with skew margin.

### 4.4 Bootstrap frames need predictable tags

`JOIN` and `SYNC` use all-zero tags today (02 section 11), because a sensor
without a clock can't compute an epoch. A mailbox can't route those. That
matters beyond pairing: after 3 undelivered confirmed uplinks, a sensor sends
every confirmed attempt as `SYNC` (08 section 6). So a device heard only through
federation would become unroutable just when it needs help.

**Proposal: counter-based bootstrap tags.** The tags come from the frame's own
uplink counter in blocks, not from the clock:

```
block   = floor(fcnt / 16)
net_tag = trunc32(HMAC(k_net_route_bootstrap, "boot-net" | uint32(block)))
dev_tag = trunc32(HMAC(k_dev_tag,             "boot-dev" | uint32(block)))
```

The key set is the one the frame is sent under: root keys for `JOIN`, session or
network keys for `SYNC`.

- **The owner can predict them.** For a paired device it knows the last `fcnt`
  seen, and registers the next few blocks (sections 6.2-6.3). For a new device it
  registers the first blocks after the pairing code is entered.
- **Outsiders can't.** Without the key, the tags look random.
- **Privacy is not reduced.** `fcnt` already travels in clear in the header (02
  section 2).
- **The cost is real:** a frame-format change in 02 section 11, `sensor_core`,
  `csframe.py`, the vectors and the test server. It also helps mode 1: a server
  no longer has to trial-decrypt every zero-tag frame.

## 5. Downlinks: `rx_ref` capabilities

1. **Publish.** The publisher hands the server `(frame, receptions)`. Each
   reception carries a random `rx_ref` that names a proxy and a receive time
   without revealing either, plus SNR, RSSI, `age_ms` and a downlink-capable flag.
   The flag is set only when that proxy is a 07 section 6.1 candidate and the
   frame is a confirmed type.
2. **Deliver.** The server sends the frame and its `rx_ref`s **only to the tag's
   registrants**. Outsiders never see an `rx_ref`, so they have nothing to forge
   a request against.
3. **Request.** The owner decides to answer (07 section 5). It sends one
   `(rx_ref, DOWNLINK frame)` per transmission, choosing the reception as in
   section 7.
4. **Forward.** The server forwards the request to the publisher that issued the
   `rx_ref`.
5. **Check and transmit.** The publisher checks that the `rx_ref` is known,
   unused and fresh, that the `DOWNLINK` passes the keyless checks with the same
   tags as the uplink, and that its federated airtime budget allows it. It then
   sends the `DOWNLINK` to its proxy with `tx_offset_us = 3 000 000` (RX2). Its
   own traffic has priority.
6. **Result.** The publisher returns the `TX_RESULT` through the server.

The server gives publishers and owners per-connection pseudonyms, so neither
learns the other's identity. An owner can only request replies to its own
sensors' real frames, at most one per transmission, so a greedy owner's airtime
use is bounded by its own sensors' traffic.

### 5.1 Timing

Federated downlinks use RX2 only, which opens 3 s after the uplink (01 section
4). The budget, typical values to be measured:

| Step | Time |
|---|---|
| Publisher's collection window (07 section 4.1) | 150 ms |
| Publisher to server, server to owner | about 50-300 ms |
| Owner decides and builds the downlink | under 50 ms |
| Owner to server, server to publisher, publisher to proxy | about 50-300 ms |
| Proxy schedules the transmit | under 3 s, with margin for the proxy's 40 ms start window (01 section 4.1) |

The owner SHOULD NOT request when more than 2000 ms have passed since first
reception. That figure now includes measured transit, rather than leaving it to
the proxy's `TOO_LATE` as 09 does today (#87).

### 5.2 Commands

Today a queued command sets `PENDING`, which makes the sensor send an
*unconfirmed* `HEARTBEAT` (08 section 7). That heartbeat opens RX1 only, so it
can't be answered through federation (#85).

**Proposal:** when the downlink that set `PENDING` was received in RX2, the
sensor makes that follow-up `HEARTBEAT` confirmed. It then opens RX2, and
federation can deliver the next command. This is a small `sensor_core` and 08
change. It applies only after RX2 downlinks, so local behaviour is unchanged.

## 6. Commissioning

### 6.1 A pre-sold sensor near your own proxy

This is unchanged:
1. Scan the QR code (or type the `CS:1:…` code) in **Add device**.
2. Press the button.
3. *Paired.*

No ESPHome build server is involved.

### 6.2 A pre-sold sensor heard only by a neighbour

The steps the user takes are the same as 6.1:

1. When the code is entered, the integration knows `k_root` and pre-registers the
   sensor's first bootstrap blocks (section 4.4) with its mailbox servers. This
   happens before the button press, so register-before-sighting holds.
2. The button sends `JOIN`. The neighbour's proxy hears it, and the mailbox
   routes it to the owner alone.
3. The owner answers `KEY_EXCHANGE` in RX2 through the neighbour's proxy, then
   `SET_NETWORK` the same way.
4. From then on the owner pre-registers normal tags every epoch.

### 6.3 Second-hand sensors

A factory reset keeps the uplink counter (02 section 8, #6). The new owner can't
know where the previous owner left `fcnt`, so it can't predict the bootstrap
blocks.

- **(a)** Register a wide, coarse window of blocks. For example, 64 blocks spread
  over `fcnt` values up to about 10^5, covering years of use. The cost is the
  registration rate limit (section 4.3).
- **(b)** For `JOIN` only, add the sensor's coarse `fcnt` range to the pairing
  label.
- **(c)** First pairing near your own proxy, which always works because a local
  proxy needs no registration.

Recommendation: (a), with (c) as the fallback. Open question.

### 6.4 Proxies (separate from federation)

A proxy is an ESPHome Wi-Fi device. Today it is adopted in ESPHome and given the
`cs_proxy:` snippet. Plug-and-play pre-sold proxies would need Improv Wi-Fi setup
plus mDNS discovery by the integration (06 section 3.2 lists mDNS as not accepted
yet). This is tracked separately.

## 7. Choosing a publisher for a downlink

An attacker with a radio can republish a frame it heard, claiming a better SNR,
then drop the request (#79). In mode 4 nothing stops it from publishing, so the
owner keeps a **success record for each publisher pseudonym**:

- A downlink counts as delivered only when the sensor's next uplink carries
  `DL_ACK` (07 section 7) or stops retransmitting. An attacker can't fake that.
- **Choice order:** a proven publisher by SNR first, then unknown publishers.
  Publishers whose requests were followed by a retransmission of the same frame
  are demoted.
- **Pseudonyms must be stable for this to work.** A publisher's pseudonym is
  derived by the server from a long-lived publisher key, so reconnecting doesn't
  reset its record. A Sybil can create new keys, but new keys have no record and
  come last.
- **Capped plausible SNR.** Values above the profile's physical range are ignored.

## 8. Mode policies

| | Mode 2 Private | Mode 3 Public | Mode 4 Open |
|---|---|---|---|
| Who may connect | members (invite) | account holders | anyone |
| Who may publish | members | account holders | anyone |
| Downlink budget per publisher proxy | group default, generous | operator default | 0.5% airtime per hour |
| Removing abusers | admin | operator | none; owners rely on success records |
| What the server operator sees | metadata (section 9) | metadata | metadata |

The protocol defines the mechanisms. The spec gives recommended defaults per
mode, and operators MAY set others.

## 9. Threat model

| Threat | Mitigation |
|---|---|
| A server reads readings | It can't: payloads are encrypted under device keys. |
| A server links an owner's tags across epochs | An owner with one long-lived connection is linkable by connection or IP. Mitigations: a fresh connection per epoch, several servers, or Tor/VPN. Documented, not solved. |
| A server sees who hears whom | It sees publisher pseudonyms and owner connections per frame, which locates owners near publishers. Documented. Modes 2 and 3 accept it by choosing a trusted operator. |
| An attacker black-holes downlinks (#78) | Requests need an `rx_ref`, which only registrants receive. Registration is refused once a tag is sighted. |
| Fake publisher SNR (#79) | Success records, stable pseudonyms, SNR caps (section 7). |
| Bootstrap flood blocks pairing (#80) | Bootstrap frames now have tags, so a flood reaches only the owner whose tag it copies. Per-publisher rate limits apply at the server. |
| An attacker pre-registers many tags | Per-connection registration limits. 2^32 is far beyond any limit. |
| A malicious server drops, delays or leaks `rx_ref`s | It affects only homes that use it, and homes MAY use several. A leaked `rx_ref` lets one junk request per reception race the owner's. Mitigation: a server-independent `rx_ref` MAC (open question). |
| A sole-path publisher or server delays frames (#83) | Mark receptions that came only through federation, let users exclude late events, and document the limit. |
| A collision partner requests a downlink | It would have to request for a frame it can't verify. Honest software never does. A malicious partner is equivalent to a leaked `rx_ref`. |

## 10. Open questions for review

1. **Is register-before-sighting sound?** Look for races at epoch boundaries, a
   server that lies about sightings, a sensor whose clock is more than 1 h ahead
   (so its frames use a tag the owner hasn't registered yet), and reconnects.
2. **A refused registration is a signal.** It tells the registrant the tag was
   already sighted. Does that leak anything useful?
3. **Second-hand bootstrap prediction** (section 6.3): (a), (b) or (c)?
4. **`rx_ref` binding against a leaking server:** should the publisher MAC the
   `rx_ref` with a key only the owner could derive? It can't, because it doesn't
   know the owner. Is there a cheap construction, or do we accept server trust
   here?
5. **Several servers:** with several mailboxes, the same frame and its `rx_ref`s
   reach the owner through each. Requests should go through one server; does the
   publisher need to tie `rx_ref`s to the server they were issued through?
6. **Transport:** WebSocket over TLS with a small binary or CBOR protocol. Is
   there an existing protocol worth reusing (MQTT 5 with per-topic ACLs, or
   Nostr with NIP-42 and custom routing)?
7. **Federated RX1:** is a 1 s round trip realistic on a local mode 2 server,
   making RX1 possible? Out of scope for v1.

## 11. Impact

**Specs:**
- 09: rewritten as mailbox federation. The parts that stay are the downlink path
  ideas and the limits.
- 02 section 11: counter-based bootstrap tags.
- 08: confirmed follow-up heartbeat after an RX2 downlink with `PENDING`.
- 07: registration and publishing hooks.
- 10: trust and coverage records dropped or reduced. Device profiles stay.

**Code:**
- `sensor_core` (bootstrap tags, confirmed follow-up)
- `csframe.py` and vectors
- `cs_testserver`
- a new `cs-mailbox` reference server
- the Home Assistant integration's federation client

**Issues:**
- These become moot or are retargeted: #77, #78, #79, #80, #81, #84, #86, most of
  #87 and #88.
- These stay, in revised form: #82, #83, #85.
