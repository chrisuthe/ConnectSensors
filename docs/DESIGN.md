# ConnectSensors - Design

Status: draft v0.1 (November 2026)

ConnectSensors is an open, freely distributed sensor network for Home Assistant.
Battery sensors talk LoRa. Any ESPHome node with a LoRa radio forwards every
ConnectSensors frame it hears, without being able to read it. The owner's Home
Assistant deduplicates, verifies and decrypts. Neighbors' proxies can optionally
carry each other's traffic through community relays, so every proxy extends
coverage for everyone.

---

## 1. Background

### 1.1 ESPHome today (2026.11.0)

- Native radio drivers: `sx126x`, `sx127x`, `cc1101`, with an `on_packet` trigger
  (raw bytes, RSSI, SNR) and a `send_packet` action.
- `packet_transport` runs over these radios, but it is node-to-node state sync,
  not a forwarding network.
- Recent releases add proxy-style components (`serial_proxy`, `bridge`,
  `uart_mux`, `ezsp_proxy_tap`), alongside the long-standing Bluetooth proxy.
  ConnectSensors follows the same pattern: cheap nodes forward raw radio traffic,
  Home Assistant does the work.
- The drivers are single-channel and use one spreading factor at a time. The
  protocol is designed around that.

---

## 2. Goals and non-goals

### Goals

1. Any ESPHome node with an SX126x/SX127x can be a proxy with a few lines of YAML.
2. Proxies never hold keys and learn nothing beyond "a frame with tag T was heard".
3. Multiple proxies hearing the same frame is a feature (diversity), not a problem.
4. Works fully offline within one home. Federation between homes is opt-in.
5. Battery sensors last years on AA or coin cells.
6. Pairing is a QR scan in Home Assistant.
7. Everything (spec, firmware, component, integration, relay) is open source.

### Non-goals

- Decrypting, injecting or retransmitting any other vendor's proprietary traffic.
- Replacing LoRaWAN for commercial deployments. A LoRaWAN compatibility mode may
  come later (Section 12).
- Certified life-safety alarming. ConnectSensors is a home-automation network.

---

## 3. Architecture

```
                 LoRa                       LAN (UDP)
[sensor] ----------------> [proxy A] -------------------+
         \---------------> [proxy B] -------------------+--> [HA integration]
          \--------------> [neighbor proxy C]           |     dedupe, verify,
                              |                         |     decrypt, entities,
                              | WebSocket (outbound)    |     downlink scheduler
                              v                         |
                        [community relay(s)] <----------+  (outbound subscribe
                         ephemeral, signed                 by current net tags)
```

Components:

| Component | Runs on | Role |
|---|---|---|
| Sensor firmware | nRF52840 or ESP32 + SX1262 | Measures, encrypts, transmits, retries |
| `cs_proxy` | ESPHome node + SX126x/SX127x | Filters, dedupes, forwards; transmits downlinks |
| `connect_sensors` integration | Home Assistant | Network server: dedupe, crypto, entities, pairing |
| `cs-relay` | Any small server | Store-nothing pub/sub for federation between homes |
| Control plane (optional) | AT Protocol / ActivityPub | Identity, device profiles, coverage maps |

---

## 4. Radio layer

The normative definition is
[spec/01-radio-profiles.md](../spec/01-radio-profiles.md). Summary:

- One channel and one spreading factor per region profile, for uplinks and
  downlinks, because ESPHome proxies are single-channel receivers.
- `US915`: 918.5 MHz (provisional), 500 kHz, SF9, intended to operate as a
  digital transmission system under FCC 15.247 without hopping. The channel sits
  between the LoRaWAN US915 uplink and downlink ranges and away from Z-Wave.
- `EU868`: 125 kHz, SF9, frequency still open; untested.
- Private sync word; the frame magic byte does the real filtering.
- Sensors limited to 1% airtime per hour, proxies to 2% for downlinks. A
  minimum-size uplink is about 52 ms on US915.

---

## 5. Frame format (v1)

The normative definition is [spec/02-frame-v1.md](../spec/02-frame-v1.md), with
radio parameters in [spec/01-radio-profiles.md](../spec/01-radio-profiles.md).
Summary:

- 14-byte cleartext header (magic `0xC5`, version/type, `net_tag`, `dev_tag`,
  `fcnt`), 1-64 bytes of AES-128-CCM ciphertext, 8-byte MIC. Frames are 23-86
  bytes.
- Uplink types `0x1`-`0x7` (`DATA`, `DATA_CONFIRMED`, `HEARTBEAT`,
  `HEARTBEAT_CONFIRMED`, `JOIN`, `SYNC`); downlink types `0x8`-`0xF` (`DOWNLINK`).
  Proxies forward uplink types and drop downlink types.
- Per-device `k_root` and `dev_eui` from the pairing QR code; `k_enc` and
  `k_dev_tag` derived with HKDF. A per-network `k_net_route` is given to sensors
  with `SET_NETWORK`.
- Hourly rotating tags from HMAC-SHA256. `JOIN` and `SYNC` use all-zero bootstrap
  tags and are identified by the server by trial decryption.
- Uplink counters persist by block reservation and never repeat, even across a
  factory reset. Retransmissions are identical bytes.
- Every downlink carries `reply_to` (the uplink it answers), `server_time` and
  TLV commands, which prevents downlink replay and keeps sensor clocks set.
- Receive windows RX1 at 1 s and RX2 at 3 s, same channel and spreading factor.

---

## 6. ESPHome proxy: `cs_proxy`

The normative definitions are
[spec/05-proxy-envelope.md](../spec/05-proxy-envelope.md) (messages between
proxy and server) and
[spec/06-cs-proxy-component.md](../spec/06-cs-proxy-component.md) (the ESPHome
component). Summary:

- An ESPHome external component that registers as a listener on an existing
  `sx126x` or `sx127x` radio and never changes its configuration. Compile-time
  validation rejects radio settings that do not match the region profile.
- Pipeline: keyless checks, dedupe on a hash of the frame bytes, token-bucket
  rate limits, then an `UPLINK` message to the server.
- Messages to and from the server use one binary envelope over UDP (port 47800)
  or MQTT, authenticated with a per-proxy key (HMAC-SHA256), with boot IDs and
  sequence numbers against replay.
- Downlinks need no clock sync: the server hands back the proxy's own receive
  timestamp plus an offset (1 s for RX1, 3 s for RX2), and the proxy reports
  each result with its timing error.
- Because ESPHome delivers packets from the main loop, the proxy flags uplinks
  whose timestamp may be late and withdraws its downlink capability when the
  loop is unhealthy.
- Airtime budget of 2% per hour for downlinks, enforced by the proxy.
- Diagnostic entities for traffic, signal strength, loop health, airtime and
  server connection.

### 6.1 Upstreaming

External components cannot add new ESPHome native API messages, so v1 uses
UDP/MQTT. Once the protocol is stable, propose a generic `lora_proxy` component
upstream that forwards raw frames over the native API, like `bluetooth_proxy`
does for BLE advertisements, plus a receive timestamp in the radio listener
interface. `cs_proxy` would then become a thin filter on top of it.

---

## 7. Home Assistant integration: `connect_sensors`

The normative definitions are
[spec/07-network-server.md](../spec/07-network-server.md) (server behavior and
the Home Assistant integration) and
[spec/08-sensor-behavior.md](../spec/08-sensor-behavior.md) (what sensors do).
Pairing is in [spec/04-pairing.md](../spec/04-pairing.md) and readings in
[spec/03-payload-v1.md](../spec/03-payload-v1.md). Summary:

- **Uplinks:** every copy from every proxy is collected for 150 ms, the device is
  identified by tag lookup (or trial decryption for bootstrap frames), counters
  are checked, readings applied once.
- **Answers:** confirmed uplinks, queued commands and clock corrections get a
  downlink. RX1 goes through the proxy with the best SNR among those with good
  timing; failures fall back to RX2 through another proxy.
- **Commands** are queued per device and resent until the sensor's next uplink
  acknowledges them.
- **Supervision:** a device silent for three heartbeat intervals is unreachable
  and its state entities become unavailable. Silence is never shown as "closed"
  or "dry". Devices heard by only one proxy are flagged.
- **Home Assistant:** config flow for the network, proxies (with a generated key
  and YAML snippet) and devices (pairing code); profile-driven entities; proxies
  merge with their ESPHome devices; actions, events and repair issues.
- **Sensors:** debounced state changes, heartbeats with full state and jitter, a
  confirmed uplink at least daily, up to three retries, automatic `SYNC` after
  repeated failures, never giving up. A contact sensor uses about 80 mAh a year.

---

## 8. Federation between homes (data plane)

### 8.1 Why not ActivityPub or AT Protocol for frames

| Need | ActivityPub | AT Protocol | Nostr-style relay |
|---|---|---|---|
| Works behind NAT/CGNAT | No, inbox must be reachable | Partly | Yes, outbound WebSocket |
| Ephemeral (not stored) | No | No, records are permanent | Yes, ephemeral kinds |
| Low latency | Retry queues, no guarantee | Firehose is seconds | Sub-second typical |
| Small frames | JSON-LD overhead large | Repo/record overhead | Small JSON event |
| No central operator | Yes | Relays are heavy to run | Many small relays |
| Signed messages | HTTP Signatures | Repo signing | Event signatures |

Publishing every sensor frame permanently (AT Protocol) leaks activity timing even
when payloads are encrypted. ActivityPub requires public inboxes, which most homes
do not have. Both are kept for the control plane (Section 9).

### 8.2 How it works

The normative definitions are
[spec/09-federation-relay.md](../spec/09-federation-relay.md) and
[spec/10-control-plane.md](../spec/10-control-plane.md). Summary:

- **The home server federates, not the proxy.** Proxies already send every frame
  to their server, so the server publishes the frames none of its devices
  verify, signed with its own federation key. A standalone proxy with no server
  can publish directly, to donate coverage.
- **Events:** three ephemeral Nostr kinds (provisionally 21110-21112): uplink,
  downlink request and downlink result. Relays forward and never store them.
- **Finding your frames:** subscribers filter by one-byte buckets of their
  `net_tag`s plus random decoys, so a relay learns that a subscriber wants
  1/256 of the traffic, not which network is theirs.
- **Federated downlinks:** RX2 only, through the publisher's proxy, referenced by
  a random `rx_ref` so publishers never reveal proxy timing. Publishing and
  accepting downlinks are separate opt-ins, both off by default, with airtime
  caps and optional allow lists.
- **Relays:** any NIP-01 relay that treats these kinds as ephemeral and rate
  limits per key; `cs-relay` is a minimal reference relay for neighborhoods.

---

## 9. Control plane (optional)

Defined in [spec/10-control-plane.md](../spec/10-control-plane.md), with
lexicons in `spec/lexicons/`:

- **Device profiles** published as AT Protocol records and fetched from profile
  sources the user trusts, so a new sensor design works without an integration
  release. Changes that alter entities need the user's approval.
- **Trust:** local allow and block lists for federation keys, optionally
  published and importable.
- **Coverage statements:** opt-in, limited to about 5 km, listing the relays a
  home uses.
- **Identity links** between a DID and a federation key, valid only when stated
  in both directions.
- The NSID authority `org.connectsensors` is provisional until the project has
  a domain.

---

## 10. Threat model

| Threat | Mitigation |
|---|---|
| Spoofed sensor frames | AES-CCM MIC with per-device key |
| Replay | Monotonic `fcnt` with small reorder window |
| Malicious proxy drops or delays frames | Path diversity; supervision alarms on missing heartbeats |
| Malicious proxy floods server/relay | Proxy HMAC (LAN) or signatures (relay); rate limits; blocklists |
| Jamming | Cannot be prevented; detected via supervision timeouts |
| Tracking devices over time | Hourly rotating `net_tag` and `dev_tag` |
| Relay operator traffic analysis | Ephemeral events; multiple independent relays; optional cover traffic |
| Lost/compromised device key | Per-device keys; remove device and re-pair |
| Compromised `K_net` | Rotate network key via `COMMAND(set_network)` to every device |
| Nonce reuse after reset | Flash-persisted `fcnt` with jump-ahead |

---

## 11. Reference hardware

Proxies (ESPHome):

- Heltec WiFi LoRa 32 V3 (ESP32-S3 + SX1262)
- LilyGO T3-S3 (ESP32-S3 + SX1262 or SX1276)
- Seeed XIAO ESP32-S3 + Wio-SX1262
- Any ESP32 board with a mains supply and an external antenna; proxies are
  always-on receivers.

Sensors (battery):

- RAK4631 (nRF52840 + SX1262) - preferred for battery life
- Seeed XIAO nRF52840 + Wio-SX1262
- Heltec Mesh Node T114
- ESP32 + SX1262 only for mains-powered or rarely-reporting sensors

Sensor firmware: Zephyr (or Arduino with RadioLib) for v1. ESPHome's nRF52
support is worth evaluating so sensors can also be configured in YAML.

---

## 12. Roadmap

| Phase | Deliverable | Done when |
|---|---|---|
| 0 | Spec freeze for frame v1 and region profiles | This document reviewed; test vectors published |
| 1 | `cs_proxy` sniffer mode + reference sensor firmware (contact + temp) | Frames from one sensor logged in HA via two proxies |
| 2 | `connect_sensors` integration: pairing, crypto, dedupe, entities, supervision | A paired sensor shows up as entities; replay/spoof tests pass |
| 3 | Downlinks: ACK, COMMAND, proxy selection, confirmed uplinks | 99% of confirmed frames acked within RX1/RX2 at -115 dBm |
| 4 | `cs-relay` + federation client + federated downlinks | Sensor in home A delivered via a proxy in home B only |
| 5 | Control plane: device profiles, coverage map, DIDs | New sensor type works from a published profile alone |
| 6 | Upstream `lora_proxy` proposal to ESPHome | PR opened |
| Later | LoRaWAN compatibility mode (multi-channel gateways), cover traffic | - |

---

## 13. Open questions

1. US channel choice and whether 500 kHz SF9 gives enough range indoors, or a
   125 kHz hopping plan is worth the complexity.
2. Is one shared channel enough for a dense neighborhood once federation is on?
   May need two channels and SF diversity.
3. Default relay operators and governance: who runs the bootstrap relays?
4. Registering the provisional event kinds 21110-21112 through the NIP process.
5. Whether to hide `fcnt` per epoch to reduce traffic analysis.
6. Battery-sensor firmware: Zephyr vs. ESPHome nRF52.
7. License for code outside `spec/` (the spec is CC BY 4.0, its tools and vectors MIT).
8. The project's domain, which fixes the lexicon NSID authority (currently the
   provisional `org.connectsensors`).
9. Whether bucket-level subscriptions give enough privacy while few networks
   exist in a region, or whether relays should be neighborhood-run by default.

---

## 14. Repository layout (proposed)

```
ConnectSensors/
  docs/DESIGN.md                    this document
  spec/                             protocol specification (self-contained,
                                    may move to its own repository)
  components/cs_proxy/              ESPHome external component
  custom_components/connect_sensors/ Home Assistant integration
  firmware/sensor/                  reference sensor firmware
  relay/                            cs-relay (Nostr-compatible ephemeral relay)
  examples/                         proxy YAML for reference boards
```
