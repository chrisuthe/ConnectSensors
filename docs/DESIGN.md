# ConnectSensors - Design

Status: draft v0.1 (November 2026)

ConnectSensors is an open, freely distributed sensor network for Home Assistant.
Battery sensors talk LoRa. Any ESPHome node with a LoRa radio forwards every
ConnectSensors frame it hears, without being able to read it. The owner's Home
Assistant deduplicates, verifies and decrypts. Neighbors' proxies can optionally
carry each other's traffic through mailbox servers, so every proxy extends
coverage for everyone.

---

## 1. Background

### 1.1 ESPHome today (2026.12, `dev`)

- Native radio drivers: `sx126x`, `sx127x`, `cc1101`, with an `on_packet` trigger
  (raw bytes, RSSI, SNR) and a `send_packet` action.
- 2026.12 adds asynchronous transmit (`start_transmit_async`), so a packet goes
  out without blocking the main loop. `cs_proxy` and `cs_sensor` use it and
  require 2026.12 or later.
- A layered packet stack runs over these radios and over `udp`, `tcp` and `uart`
  (`esphome/components/packet_interface/`, with a link in each radio's
  `packet_interface/` subdirectory). Its optional layers are XXTEA encryption
  with an optional rolling code, HDLC-style reliability, sessions, 16-bit
  addressing and fragmentation. `radio_link.h` and `listen_before_talk.h` add
  half-duplex turn-taking and a cap on how long a busy radio can hold a send
  back. `entity_transport` (`esphome/components/entity_transport/`) sends
  sensor and binary sensor states over it, and `packet_transport` runs over it
  through an adapter (`packet_interface/packet_transport/`).
- ConnectSensors does not build on that stack. It shares entity state between
  ESPHome nodes that are all built with one key text in their config, and names
  the sending device in its dictionary packets, in the clear unless the XXTEA
  layer is on. The addressing header is always in the clear. ConnectSensors
  needs sensors that are not ESPHome API devices, proxies that forward frames
  they hold no key for, AEAD with keys agreed at pairing (X25519 from a QR code,
  04), rotating tags instead of fixed addresses (02), a network server that
  dedupes across proxies (07) and federation between homes (09). None of those
  fit as a layer of the stack.
- Other look-alikes, and why they differ:
  - `udp` (and `packet_transport` over it) syncs states between ESPHome nodes on
    one LAN; the proxy's link to the server is UDP, but with its own envelope
    (05).
  - `preferences` stores flash state; `cs_sensor` uses it for its counters and
    keys, but it has nothing to do with the air protocol.
  - `sntp` and `homeassistant` time set a node's clock; sensors take theirs
    from the server's `KEY_EXCHANGE` and downlinks instead (08 section 3).
  - `mdns` only advertises the node and cannot browse, so the server discovery
    of 05 section 2.1 is not implemented and `server.host` is required (06).
  - There is no LoRa or LoRaWAN component; the radio drivers carry raw packets
    only.
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
7. Everything (spec, firmware, component, integration, mailbox server) is open source.

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
          \--------------> [neighbor proxy C]                 dedupe, verify,
                              | LAN                           decrypt, entities,
                              v                               downlink scheduler
                        [neighbor's HA]                              ^
                              | publish (outbound WebSocket)         | deliver
                              v                                      |
                        [mailbox server] ----------------------------+
                         routes by tag,       (the owner registers its devices' tags)
                         stores nothing
```

Components:

| Component | Runs on | Role |
|---|---|---|
| Sensor firmware (`cs_sensor`) | ESPHome node + SX126x/SX127x, mains or battery | Measures, encrypts, transmits, retries |
| `cs_proxy` | ESPHome node + SX126x/SX127x | Filters, dedupes, forwards; transmits downlinks |
| `connect_sensors` integration | Home Assistant | Network server: dedupe, crypto, entities, pairing |
| `cs-mailbox` | Any small server | Routes frames between homes by tag to their registered owners; stores nothing |
| Control plane (optional) | AT Protocol | Device profiles |

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

- 14-byte cleartext header (magic `0xC5`, version/type, an 8-byte `tag`,
  `fcnt`), 1-64 bytes of AES-128-CCM ciphertext, 8-byte MIC. Frames are 23-86
  bytes.
- Uplink types `0x1`-`0x7` (`DATA`, `DATA_CONFIRMED`, `HEARTBEAT`,
  `HEARTBEAT_CONFIRMED`, `JOIN`, `SYNC`); downlink types `0x8`-`0xF` (`DOWNLINK`).
  Proxies forward uplink types and drop downlink types.
- Per-device `k_root` and `dev_eui` from the pairing QR code; `k_enc` and
  `k_dev_tag` derived with HKDF. There is no network key.
- Tags are key fingerprints: the hash of an Ed25519 public key derived from
  `k_dev_tag`, per hour for normal frames and per block of 64 counter values for
  `JOIN` and `SYNC`. Only the key holder can prove a tag is its own. The server
  finds devices through a tag table, with trial decryption as the fallback for
  locally heard bootstrap frames.
- Uplink counters persist by block reservation and never repeat, even across a
  factory reset. Retransmissions are identical bytes.
- Every downlink carries `reply_to` (the uplink it answers), `server_time` and
  TLV commands, which prevents downlink replay and keeps sensor clocks set.
- Downlink counters are per key. The root counter, used only for `KEY_EXCHANGE`,
  never resets, so one server never reuses a root nonce; a sensor clears its root
  floor only on a factory reset (hold the button 10 s), which a change of owner
  requires.
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
- Pipeline: keyless checks, dedupe on a hash of the frame bytes within 2 s (so
  sensor retries still get through), token-bucket rate limits, then an `UPLINK`
  message to the server.
- Messages to and from the server use one binary envelope over UDP (port 47800)
  or MQTT, authenticated with a per-proxy key (HMAC-SHA256), with boot IDs and
  sequence numbers against replay. Nothing about a session is persisted: the
  server asks for a `HELLO` echoing a nonce before it accepts a new boot, and the
  proxy follows a restarted server through the `SERVER_STATUS` echo of its
  `HELLO`.
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
  downlink. A sensor's retry of a confirmed uplink (4 s or more later) is a new
  transmission and is answered again. RX1 goes through the proxy with the best
  SNR among those with good timing; for confirmed uplinks, failures fall back to
  RX2 through another proxy.
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

The normative definition is
[spec/09-federation-relay.md](../spec/09-federation-relay.md); the reasoning and
review history are in [design/federation-mailbox.md](design/federation-mailbox.md).
Summary:

- **Modes.** 1 standalone (no federation), 2 private (a group's own mailbox
  server), 3 public (a large operator's), 4 open (anyone's). Modes 2-4 share one
  protocol and one reference server, `cs-mailbox`, and differ only in admission
  and defaults.
- **The home server federates, not the proxy.** Proxies send every frame to their
  own server. The server publishes the frames none of its devices verify, except
  `JOIN`, to its mailbox servers.
- **Tags are key fingerprints.** Each frame's 8-byte tag is the hash of an
  Ed25519 public key derived from the device's session keys. An owner registers
  a tag by signing with that key, bound to the server and the owner's key, so
  only the sensor and its home server can claim a device's frames.
- **Routing.** A mailbox delivers each frame only to the registrants of its tag.
  It holds no device keys, reads no payloads and stores no frames.
- **Federated downlinks.** RX2 only, through the publisher's proxy, named by a
  random `rx_ref` that only the frame's owner receives. One request per
  transmission, released if the publisher reports it was not sent. Owners rank
  publishers by their record of acknowledged downlinks.
- **Pairing is always local.** `JOIN` frames are never published, so a holder of
  a device's printed root key gains nothing from mailboxes.
- **Wire protocol.** WebSocket over TLS, deterministic CBOR messages signed by
  the client's key; the server's greeting proves its key for the session.

An earlier draft used Nostr relays with bucketed subscriptions. Relays could not
route a frame to its owner, so owners hid in buckets and every publisher had to
defend itself against anonymous requesters. The Phase 0 review (#77-#88) traced
most of its problems to that, and the mailbox design replaced it.

---

## 9. Control plane (optional)

Defined in [spec/10-control-plane.md](../spec/10-control-plane.md), with the
lexicon in `spec/lexicons/`:

- **Device profiles** published as AT Protocol records and fetched from profile
  sources the user trusts, so a new sensor design works without an integration
  release. Changes that alter entities need the user's approval.
- The NSID authority `org.connectsensors` is provisional until the project has
  a domain.

Trust lists, coverage statements and identity links were dropped with the Nostr
design: mailbox federation needs none of them.

---

## 10. Threat model

| Threat | Mitigation |
|---|---|
| Spoofed sensor frames | AES-CCM MIC with per-device key |
| Replay | Monotonic `fcnt` with small reorder window |
| Malicious proxy drops or delays frames | Path diversity; supervision alarms on missing heartbeats |
| Malicious proxy floods the server | Proxy HMAC on the LAN; rate limits; blocklists |
| Stolen proxy key used to forge downlinks | A proxy that accepts downlinks has a key of its own; an optional shared key is only for receive-only proxies (spec 05 section 4.2) |
| Jamming | Cannot be prevented; detected via supervision timeouts |
| Tracking devices over time | Hourly rotating per-device key-fingerprint tags; nothing shared between a network's devices |
| A stranger claiming a device's frames through a mailbox | Registration needs a signature from the tag's key, which only session key holders can derive (spec 09 section 5) |
| Mailbox operator traffic analysis | Payloads are encrypted; the operator sees per-owner timing, frame type and length, and `fcnt`. Use a mailbox you trust; documented (spec 09 section 13) |
| A neighbor's publisher dropping or delaying frames | Owners' publisher records; federated paths never count as redundancy; federation-only frames are marked (spec 07 section 4.4) |
| Lost/compromised device key | Per-device keys; remove device and re-pair |
| Nonce reuse after reset | Flash-persisted `fcnt` with jump-ahead; root downlink counter never reset (spec 02 section 13.1) |

---

## 11. Reference hardware

Proxies (ESPHome):

- Heltec WiFi LoRa 32 V3 (ESP32-S3 + SX1262)
- LilyGO T3-S3 (ESP32-S3 + SX1262 or SX1276)
- Seeed XIAO ESP32-S3 + Wio-SX1262
- Any ESP32 board with a mains supply and an external antenna; proxies are
  always-on receivers.

Sensors (mains or battery):

- RAK4631 (nRF52840 + SX1262) - preferred for battery life
- Seeed XIAO nRF52840 + Wio-SX1262
- Heltec Mesh Node T114
- ESP32 + SX1262 only for mains-powered or rarely-reporting sensors

Sensor firmware: ESPHome, with the `cs_sensor` external component, on any chip
ESPHome supports with an SX126x or SX127x radio, mains or battery. A sensor is
built in YAML like a proxy; battery operation is ESPHome's `deep_sleep`. The
protocol lives in `sensor_core`, an ESPHome-free library host-tested against the
spec vectors (`components/cs_sensor/`), with its crypto in the component so
ESP32 and nRF52 run identical code. The ESPHome glue runs on ESP32 first; on
ESP32 a deep-sleep wake keeps the core's state in RTC memory and is not a boot
(08 section 9).

ESPHome on nRF52 is feasible: on ESPHome `dev`, a probe for the Seeed XIAO
nRF52840 with SPI, `sx126x` on the US915 profile, `deep_sleep` and a GPIO binary
sensor compiles, using 16% of flash (131 KB of 812 KB) and 11% of RAM (28.5 KB of
256 KB). Running `sx126x` on nRF52, sleep current, waking on a GPIO edge, and
flash wear from counter reservation are still to be checked on hardware.

---

## 12. Roadmap

| Phase | Deliverable | Done when |
|---|---|---|
| 0 | Spec freeze for frame v1 and region profiles | This document reviewed; test vectors published |
| 1 | `cs_proxy` sniffer mode + reference sensor firmware (contact + temp) | Frames from one sensor logged in HA via two proxies |
| 2 | `connect_sensors` integration: pairing, crypto, dedupe, entities, supervision | A paired sensor shows up as entities; replay/spoof tests pass |
| 3 | Downlinks: ACK, COMMAND, proxy selection, confirmed uplinks | 99% of confirmed frames acked within RX1/RX2 at -115 dBm |
| 4 | `cs-mailbox` + federation client + federated downlinks | Sensor in home A delivered via a proxy in home B only |
| 5 | Control plane: device profiles | New sensor type works from a published profile alone |
| 6 | Upstream `lora_proxy` proposal to ESPHome | PR opened |
| Later | LoRaWAN compatibility mode (multi-channel gateways), cover traffic | - |

---

## 13. Open questions

1. US channel choice and whether 500 kHz SF9 gives enough range indoors, or a
   125 kHz hopping plan is worth the complexity.
2. Is one shared channel enough for a dense neighborhood once federation is on?
   May need two channels and SF diversity.
3. Who runs mode 3 and mode 4 mailbox servers, and how mode 4 admits new keys
   (proof of work, slow admission, or both).
4. Ed25519 key generation time on nRF52, which sensors need once per epoch
   (spec 09 section 3).
5. Whether to hide `fcnt` per epoch to reduce traffic analysis.
6. Battery life of ESPHome sensors on nRF52 against the budget in spec 08,
   measured on hardware.
7. License for code outside `spec/` (the spec is CC BY 4.0, its tools and vectors MIT).
8. The project's domain, which fixes the lexicon NSID authority (currently the
   provisional `org.connectsensors`).
9. Federated pairing in modes 2 and 3, where members are known; out of v1.

---

## 14. Repository layout (proposed)

```
ConnectSensors/
  docs/DESIGN.md                    this document
  spec/                             protocol specification (self-contained,
                                    may move to its own repository)
  components/cs_proxy/              ESPHome external component
  custom_components/connect_sensors/ Home Assistant integration
  components/cs_sensor/             sensor firmware: sensor_core, then ESPHome glue
  mailbox/                          cs-mailbox (federation mailbox server)
  examples/                         proxy YAML for reference boards
```
