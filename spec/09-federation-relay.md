# 09 - Federation Relay

Status: Draft
Version: 1.0-draft.1

This document specifies how ConnectSensors homes carry each other's frames: what
is published, how owners find their own frames, how a neighbor's proxy can
transmit a downlink for someone else's sensor, and what a relay must do. It uses
the Nostr event and relay protocol (NIP-01) as transport.

Federation is optional and off by default. Nothing in 00-08 depends on it.

## 1. Goals (informative)

- A sensor that only a neighbor's proxy can hear still reaches its owner.
- No central operator: anyone can run a relay, and publishers and owners use
  several.
- Works behind NAT: every participant connects outward to relays.
- Relays store nothing and learn as little as practical.

## 2. Roles

| Role | Who | Does |
|---|---|---|
| Publisher | A home server (5.1) or a standalone proxy (5.2) | Publishes frames it heard that are not its own. Optionally transmits downlinks for others. |
| Subscriber | A home server | Receives frames for its own networks from relays and, if needed, asks a publisher to transmit a downlink. |
| Relay | Any server running a relay that meets section 7 | Passes events between publishers and subscribers without storing them. |

A home server is usually both publisher and subscriber.

## 3. Identity

Every publisher and subscriber has a secp256k1 key pair, used as its Nostr
identity (BIP-340 Schnorr signatures, as NIP-01 requires).

- A home server generates one federation key when federation is first enabled,
  separate from all other keys in this specification.
- A standalone proxy generates its key on first boot and keeps it in
  non-volatile storage.
- Federation keys are pseudonymous. Linking one to a person or a location is
  optional (10).

## 4. Events

All events follow NIP-01: `id`, `pubkey`, `created_at`, `kind`, `tags`, `content`,
`sig`. `content` is standard base64 (RFC 4648 section 4, with padding) of a binary
body defined below. All three kinds are in the ephemeral range (20000-29999), so
relays forward them and do not store them.

The kind numbers below are provisional until registered through the NIP process.

| Kind | Name | From | To |
|---|---|---|---|
| 21110 | Uplink | Publisher | Anyone subscribed to its bucket |
| 21111 | Downlink request | Subscriber | One publisher |
| 21112 | Downlink result | Publisher | The requesting subscriber |

### 4.1 Uplink (21110)

Tags:

| Tag | Value |
|---|---|
| `["h", <bucket>]` | First byte of the frame's `net_tag`, as 2 lowercase hex digits (section 6.2) |
| `["r", <region>]` | Region profile name (01), for example `US915` |
| `["dl", "1"]` | Present only if the publisher accepts downlink requests for this frame |

Content body:

```
version     uint8   = 1
frame_len   uint8
frame       frame_len bytes, unchanged
age_ms      uint16  time from the first reception to publishing, capped at 65535
n_rx        uint8   1-8
n_rx times:
  rx_ref    8 bytes  random reference for this reception (section 4.4)
  rssi_x10  int16
  snr_x10   int16
  flags     uint8    as in 05 section 5.1 (TS_UNCERTAIN)
```

One event carries all of the publisher's receptions of one frame (several of its
proxies may have heard it).

### 4.2 Downlink request (21111)

Tags: `["p", <publisher pubkey hex>]`.

```
version     uint8   = 1
rx_ref      8 bytes  the reception to answer
frame_len   uint8
frame       the DOWNLINK frame
```

### 4.3 Downlink result (21112)

Tags: `["p", <subscriber pubkey hex>]`.

```
version     uint8   = 1
rx_ref      8 bytes
result      uint8   result codes of 05 section 5.5
offset_us   int32   as in 05 section 5.5
```

### 4.4 `rx_ref`

`rx_ref` lets a publisher find the proxy and receive time of a reception without
publishing them. It MUST be random (not derived from the proxy or the time) and
MUST be remembered for 5 seconds, then forgotten.

## 5. Publishing

### 5.1 By a home server (default)

Proxies already send every frame to their server (02 section 12), so the server
decides what to publish; proxies need no federation support.

A server with publishing enabled:

1. Processes every frame as in 07 section 4.
2. Publishes a frame only if no device of its own verified it. This includes
   bootstrap frames that matched none of its devices.
3. Publishes after its collection window (07 section 4.1), with all its
   receptions in one event.
4. Publishes each transmission of a frame (07 section 4, step 3) at most once,
   to every relay in its list, so a sensor's retransmission reaches its owner
   like the original.
5. Publishes at most 5 events per second; beyond that it drops the newest.
6. Does not publish frames from proxies whose region settings do not match
   (07 section 6.1).

The user interface MUST present publishing as an explicit choice, for example
"Share my coverage with neighbors", off until the user turns it on.

### 5.2 By a standalone proxy

A proxy with no home server can publish directly (06 section 3.2,
`federation.enabled`). It treats every frame as foreign. It needs a TLS WebSocket
client and BIP-340 signatures, so an ESP32-S3 with PSRAM is RECOMMENDED. It
applies the same rules as 5.1, items 3-5, with its own receptions only.

## 6. Subscribing

### 6.1 Subscriber behavior

A server with subscribing enabled ("Receive my sensors through neighbors"):

- Keeps a subscription on every relay in its list, with the filter
  `{"kinds": [21110], "#h": [<buckets>], "#r": [<region>]}`.
- Verifies each event's signature, decodes it, and feeds the frame into its
  normal uplink pipeline (07 section 4), recording each reception as coming from
  `(publisher pubkey, rx_ref)`. Frames that do not verify for any of its devices
  are dropped without further processing; most frames in a bucket belong to other
  networks.
- Deduplicates across local and federated copies by frame hash and reception
  time, taking a federated copy as received `age_ms` before its event arrived
  (07 section 4.3). Federated copies usually arrive after the local decision;
  they then only add receptions to the history. A federated retransmission is a
  new transmission and is answered again like a local one. A federated copy
  marks commands delivered under the same rule as a local frame (07 section 7):
  only if its `fcnt` is greater than the `reply_to` of the downlink awaiting
  acknowledgement.
- Counts federated receptions for supervision (07 section 8) and coverage (07
  section 9), so a device heard only through a neighbor is reachable but
  single-path.

### 6.2 Buckets

A subscriber does not subscribe to its exact `net_tag`s. It subscribes to their
first bytes ("buckets"), so a relay sees only that the subscriber is interested in
1/256 of all traffic, not which network is its own.

- The buckets are the first bytes of the subscriber's `net_tag`s for epochs
  `e - 1`, `e` and `e + 1`, for all its networks.
- A subscriber SHOULD add 2 random decoy buckets per epoch.
- At each epoch boundary the subscriber opens the new subscription before closing
  the old one, so nothing is missed.
- Bucket `00` contains bootstrap frames (whose `net_tag` is all zeros) as well as
  normal frames whose tag starts with `00`. A subscriber SHOULD subscribe to `00`
  only while it has a device pairing (04) or a device in lost contact (08 section
  6), and MUST apply its bootstrap rate limit (07 section 4) to frames from it.

### 6.3 Federated downlinks

When a subscriber decides to answer a confirmed uplink (07 section 5) and no
local proxy can transmit:

1. It considers receptions from events carrying `["dl", "1"]`.
2. It skips any that cannot make RX2: the uplink was first received
   `age_ms` + (now - event arrival) milliseconds ago, and the downlink must reach
   the publisher's proxy well before 3 seconds. A subscriber SHOULD NOT request a
   downlink if more than 2000 ms have already passed.
3. It picks the reception with the best SNR and sends a downlink request to that
   publisher, on the relays where it received the uplink.
4. It never requests RX1 through federation.
5. It sends at most one request per transmission (07 section 4, step 3).

## 7. Publisher handling of downlink requests

Accepting downlink requests is a separate opt-in ("Let neighbors' sensors use my
proxies to receive replies"), off by default.

A publisher that accepts requests:

1. Verifies the event signature.
2. Looks up `rx_ref`. Unknown or expired references are ignored.
3. Checks the frame: keyless checks (02 section 12), a downlink type, and the
   same `net_tag` and `dev_tag` as the uplink it answers (07 section 5).
4. Accepts at most one request per `rx_ref`; later ones are ignored.
5. Applies limits: at most 10 federated downlinks per minute in total, and a
   federated airtime budget per proxy of at most 0.5% per hour, within the proxy's
   overall budget.
6. MAY accept requests only from subscriber keys on an allow list (10 section
   5).
7. Sends a `DOWNLINK` message (05 section 5.4) to the proxy that made the
   reception, with `tx_offset_us` = 3 000 000.
8. Publishes a downlink result when the proxy's `TX_RESULT` arrives.

A standalone proxy does the same with its own radio.

## 8. Relays

### 8.1 Requirements

A relay used for ConnectSensors MUST:

- implement NIP-01, including tag filters on single-letter tags;
- treat kinds 21110-21112 as ephemeral: forward to matching subscriptions, never
  store;
- reject events of these kinds whose `content` decodes to more than 256 bytes;
- apply per-pubkey rate limits (RECOMMENDED: 10 events per second, burst 50).

A relay SHOULD support NIP-42 authentication, so its operator can restrict who
publishes, and MAY refuse subscriptions with more than 16 buckets.

### 8.2 `cs-relay`

`cs-relay` is the reference relay: a minimal Nostr relay that accepts only kinds
21110-21112, keeps nothing on disk, and enforces section 8.1. It is meant to run
as a Home Assistant add-on or a small container, so neighborhoods can run their
own.

### 8.3 Relay lists

- The integration ships with a default list of community relays (to be decided)
  and lets the user add or remove relays.
- Publishers and subscribers SHOULD use at least 2 relays.
- Two neighbors only find each other if they share at least one relay. A
  neighborhood relay that both list is the most reliable arrangement.

## 9. Security and privacy

| Concern | Handling |
|---|---|
| Relay reads frames | It sees what anyone near a proxy can receive over the air: encrypted frames with hourly tags. It cannot decrypt them. |
| Relay links a subscriber to its network | Buckets and decoys (6.2) blur it. With few networks in a region, a bucket may hold only one network's frames, so a determined relay operator can still learn when that network's sensors transmit. Using a relay you or your neighborhood runs avoids this. |
| Relay links publishers to places | Publisher keys are stable and the relay sees their IP addresses. Publishing tells the relay "this home hears these frames". |
| Fake uplink events | Signed by the publisher, but the frame itself is what matters: it is authenticated end to end (02), so fakes fail the MIC check. |
| Downlink request abuse | `rx_ref` is public, so anyone can request a downlink for a reception. Requests must carry a valid-looking downlink frame with matching tags, only the first request per reception counts, and limits cap the airtime (section 7). The worst case is a wasted downlink or a blocked RX2 answer, which sensor retries cover. Publishers worried about this can use an allow list. |
| Flooding relays | Per-pubkey rate limits; NIP-42 authentication. |
| Tracking a home through its publisher key | A home can rotate its federation key at any time, at the cost of breaking allow lists that name it. |

## 10. Test vectors

`vectors/federation-v1.json` contains:

- BIP-340 official test vector 0, which the reference tool checks its own Schnorr
  implementation against;
- a signed uplink event carrying the `DATA_CONFIRMED` frame from
  `vectors/frame-v1.json`, a downlink request carrying the matching `DOWNLINK`,
  and a downlink result, all with fixed keys and the BIP-340 auxiliary random
  value set to zeros so the signatures are reproducible.
