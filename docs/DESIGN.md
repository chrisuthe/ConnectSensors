# ConnectSensors - Design

Status: draft v0.1 (November 2026)

ConnectSensors is an open, freely distributed sensor network for Home Assistant.
Battery sensors talk LoRa. Any ESPHome node with a LoRa radio forwards every
ConnectSensors frame it hears, without being able to read it. The owner's Home
Assistant deduplicates, verifies and decrypts. Neighbors' proxies can optionally
carry each other's traffic through community relays, which is the open version of
YoLink's "every hub forwards every device's packets" behavior.

---

## 1. Background

### 1.1 What YoLink does, and why we cannot simply join it

- YoLink sensors use LoRa in the US 902-928 MHz band. A 2021 capture showed
  SF7 at 910.3 MHz, with what looks like a cleartext header (likely device ID
  and a frame counter) followed by about 32 bytes of ciphertext
  (anthonykirby/lora-packet#74).
- Cloud-mode YoLink hubs forward any YoLink packet they hear to the YoLink cloud,
  which routes it to the device's owner. Hubs do not decrypt. Users report that a
  neighbor's hub extends their range for this reason.
- The YoLink Local Hub (YS1606) offers a local HTTP + MQTT API and Matter, but
  devices paired to it are keyed to that single hub. Local and cloud cannot be
  mixed, and multiple local hubs give no redundancy. Going local loses the
  "any hub forwards" behavior.
- Per-device keys live in the YoLink cloud or the Local Hub. There is no public
  way to obtain them and no API that accepts forwarded packets. Bishop Fox's 2025
  review of hub firmware 0382 (CVE-2025-59448..59452) found issues YoLink has since
  fixed; key extraction is not a foundation for an open project.

Conclusion: ConnectSensors copies YoLink's architecture (dumb forwarders,
end-to-end encryption, server-side dedupe), not its protocol. YoLink interop is
limited to an optional passive observer (Section 10).

### 1.2 ESPHome today (2026.11.0)

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

- Decrypting, injecting or retransmitting YoLink (or any other vendor's) traffic.
- Replacing LoRaWAN for commercial deployments. A LoRaWAN compatibility mode may
  come later (Section 13).
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

### 4.1 Regional profiles

The whole network shares one channel and one spreading factor per region profile.
Values below are proposals and must be checked against current regulations
before release (this is not legal advice).

| Profile | Frequency | Bandwidth | SF | Notes |
|---|---|---|---|---|
| `US915` | 904.6 MHz (TBD) | 500 kHz | SF9 | 500 kHz LoRa qualifies as digital modulation (DTS) under FCC 15.247, so a fixed channel is allowed without hopping. Subject to the 8 dBm/3 kHz PSD limit. Costs about 6 dB of sensitivity versus 125 kHz. |
| `US915_LP` | configurable | 125 kHz | SF7-SF9 | Low-power mode under 15.249 field-strength limits, for dense indoor installs. |
| `EU868` | 869.525 MHz | 125 kHz | SF9 | 869.4-869.65 MHz sub-band: 10% duty cycle, 500 mW ERP. Good for downlinks too. |
| `AU915` | TBD | 500 kHz | SF9 | Mirror US approach, verify locally. |

Other parameters:

- Explicit header, CRC on, preamble 8.
- Private sync word (sx126x `sync_value: [0x14, 0x24]`). This is shared with many
  private LoRa networks, so the magic byte (5.1) does the real filtering.
- Do not sit on frequencies known to be used by YoLink or Meshtastic defaults.

### 4.2 Airtime budget

A 40-byte frame at SF9/500 kHz is about 50 ms; at SF9/125 kHz about 200 ms.
Sensors send a heartbeat every 10-30 minutes and events as they happen.
A home with 50 sensors uses well under 1% of channel time.

---

## 5. Frame format (v1)

All multi-byte integers big-endian.

### 5.1 Uplink frame

```
Offset Size Field
0      1    magic = 0xC5
1      1    ver (high nibble, = 1) | type (low nibble)
2      4    net_tag   - rotating network tag (5.3)
6      4    dev_tag   - rotating device tag (5.3)
10     4    fcnt      - frame counter, monotonic per device
14     N    payload   - AES-128-CCM ciphertext
14+N   8    mic       - CCM tag (64-bit)
```

Header overhead: 22 bytes. Header bytes 0-13 are the CCM additional data, so they
are authenticated but not encrypted.

Types:

| Type | Name | Direction |
|---|---|---|
| 0x1 | `DATA` | uplink, no ack requested |
| 0x2 | `DATA_CONFIRMED` | uplink, ack requested |
| 0x3 | `HEARTBEAT` | uplink, battery + supervision |
| 0x4 | `JOIN_HELLO` | uplink, first frame after pairing |
| 0x8 | `ACK` | downlink |
| 0x9 | `COMMAND` | downlink (config change, actuator) |

### 5.2 Nonce

```
nonce (13 bytes) = dev_eui (8) | fcnt (4) | dir (1)
```

`dev_eui` is the device's permanent 64-bit ID, never sent in the clear.
`dir` is 0x00 uplink, 0x01 downlink. Nonces never repeat as long as `fcnt` never
repeats.

Frame counter persistence: the sensor writes `fcnt` to flash every 64 frames and on
boot jumps ahead by 64, so a reset can never reuse a counter.

Retransmissions resend the identical bytes (same fcnt, same ciphertext). This is
safe and lets dedupe work.

### 5.3 Rotating tags (privacy)

Fixed IDs on the air would let anyone track a device's presence and activity.
Tags rotate every hour (`epoch = floor(unix_time / 3600)`):

```
net_tag = trunc32(HMAC-SHA256(K_net_route, "net" | epoch))
dev_tag = trunc32(HMAC-SHA256(K_dev_tag,   "dev" | epoch))
```

- Sensors need a rough clock. They learn the epoch from the first `ACK` after
  boot and keep it with the RTC. Drift of minutes is fine: the server accepts
  `epoch - 1`, `epoch` and `epoch + 1`.
- The server precomputes the tag table for those three epochs for every device it
  owns, so a lookup is a hash-table hit.
- A 32-bit tag can collide. A collision only costs a failed MIC check on the
  wrong candidate; the server tries every candidate with that tag.
- `fcnt` stays in the clear. It reveals how many frames a device has sent, but
  not which device across epochs. A per-epoch random offset could hide it in a
  later version.

### 5.4 Keys

Each device has a 128-bit root key `K_root` and a permanent `dev_eui`, both in its
pairing QR code. Derived with HKDF-SHA256:

| Key | Info string | Use |
|---|---|---|
| `K_enc` | `"cs1 enc"` | AES-CCM payload and MIC |
| `K_dev_tag` | `"cs1 tag"` | dev_tag derivation |

Each Home Assistant install has one network key `K_net` (random, 128-bit), from
which `K_net_route = HKDF(K_net, "cs1 route")`. It is given to the sensor during
pairing (in the first `COMMAND` frame after `JOIN_HELLO`, encrypted with
`K_enc`).

Proxies hold no keys.

### 5.5 Payload

Plaintext payload is a list of readings:

```
reading = channel (1) | kind (1) | value (1, 2 or 4 bytes, by kind)
```

`kind` values (initial set): contact, motion, leak, temperature (int16, 0.01 C),
humidity (uint16, 0.01 %), battery (uint8 %), battery_mv (uint16), button event,
vibration, tamper, illuminance, distance, raw (length-prefixed).

A device profile (Section 9.3) maps `channel` numbers to Home Assistant entities.

### 5.6 Downlink

- `ACK` echoes the acknowledged `fcnt` and carries the current epoch and any
  pending-command flag.
- Receive windows (LoRaWAN Class A style): RX1 opens 1.0 s after uplink end,
  RX2 opens 3.0 s after (for downlinks routed through a relay).
- Commands that miss both windows wait in the server queue and go out after the
  device's next uplink.
- `DATA_CONFIRMED` retries: up to 3, at 2 s, 6 s and 15 s plus random jitter.

---

## 6. ESPHome proxy: `cs_proxy`

An ESPHome external component that attaches to an existing radio component. It
registers as a packet listener on `sx126x`/`sx127x` (the same hook
`packet_transport` uses), so the radio YAML stays standard.

### 6.1 Configuration

```yaml
external_components:
  - source: github://chrisuthe/ConnectSensors@main
    components: [cs_proxy]

sx126x:
  id: radio
  hw_version: sx1262
  cs_pin: GPIO8
  rst_pin: GPIO12
  busy_pin: GPIO13
  dio1_pin: GPIO14
  rf_switch: true
  tcxo_voltage: 1_8V
  modulation: LORA
  frequency: 904.6MHz
  bandwidth: 500_0kHz
  spreading_factor: 9
  coding_rate: CR_4_5
  sync_value: [0x14, 0x24]
  preamble_size: 8
  crc_enable: true
  pa_power: 14

cs_proxy:
  radio_id: radio
  region: US915
  server:                     # local Home Assistant
    transport: udp            # udp | mqtt
    host: homeassistant.local
    port: 47800
    key: !secret cs_proxy_key # authenticates proxy <-> server on the LAN
  dedupe_window: 30s
  max_forward_rate: 20/s
  downlink: true              # allow this proxy to transmit ACK/COMMAND
  federation:
    enabled: false            # opt in to carry neighbors' frames
    relays:
      - wss://relay1.connectsensors.example
      - wss://relay2.connectsensors.example
```

Diagnostic entities created automatically: frames heard, frames forwarded,
duplicates dropped, foreign frames relayed, last RSSI, downlinks sent.

### 6.2 Receive path

1. Radio delivers `(bytes, rssi, snr)`.
2. Drop if `len < 22` or `bytes[0] != 0xC5` or version unknown.
3. Dedupe on `(net_tag, dev_tag, fcnt, type)` within `dedupe_window`.
4. Rate-limit per `dev_tag` and globally.
5. If `net_tag` is in the local tag set (pushed by the server, 6.4), send to the
   local server.
6. Otherwise, if federation is enabled, publish to relays (Section 8).
   If not, drop.

### 6.3 Proxy-to-server envelope (UDP)

```
0   1   envelope version = 1
1   1   msg type: 0x01 uplink, 0x02 tag-set request, 0x81 downlink, 0x82 tag-set
2   8   proxy_id (from ESPHome MAC / name hash)
10  4   seq
14  8   rx_time_us (proxy uptime clock)
22  2   rssi x10 (int16)
24  2   snr x10 (int16)
26  2   freq_err_hz (int16)
28  N   raw LoRa frame
28+N 16 HMAC-SHA256-128(proxy_key, bytes 0..27+N)
```

Downlink messages (0x81) carry the frame plus a transmit deadline relative to the
proxy's `rx_time_us` of the triggering uplink, so the proxy can hit RX1 without
clock sync.

MQTT transport uses the same binary envelope on `connectsensors/<proxy_id>/up` and
`.../down`.

### 6.4 Local tag set

The server sends each proxy the set of `net_tag`s it owns for epochs
`e-1..e+1` (normally one tag per epoch, more if the home runs several networks)
on connect and at every epoch boundary. That is how a proxy decides "local or
foreign" without keys.

### 6.5 Upstreaming

External components cannot add new ESPHome native API messages. v1 therefore uses
UDP/MQTT. Once the protocol is stable, propose a `lora_proxy` component upstream
that forwards raw frames over the native API, like `bluetooth_proxy` does for BLE
advertisements. ConnectSensors would then become one decoder on top of it.

---

## 7. Home Assistant integration: `connect_sensors`

### 7.1 Responsibilities

- UDP/MQTT listener for proxies; proxy registry and per-proxy keys.
- Frame pipeline: tag lookup -> candidate devices -> MIC check -> replay check
  (`fcnt` must exceed the last accepted; small reorder window of 4) -> decrypt
  -> decode via device profile -> update entities.
- Dedupe across proxies: first valid copy wins; later copies within 2 s only add
  `(proxy, rssi, snr)` to the reception record.
- Downlink scheduler: picks the proxy with the best recent SNR for that device
  that has `downlink: true` and can make RX1; falls back to RX2 or the next uplink.
- Supervision: each device declares a heartbeat interval. Missing 3 in a row
  raises a `problem` binary sensor ("unreachable"). Silence from a security
  sensor is treated as a fault, never as "closed" or "dry".
- Coverage: per-device list of proxies that hear it, with RSSI history. A
  "weakest link" repair view suggests where to add a proxy.
- Federation client (Section 8): outbound WebSocket subscriptions for its own
  `net_tag`s.

### 7.2 Pairing

Sensor QR code:

```
CS:1:<dev_eui hex>:<K_root base32>:<profile id>
```

Flow:

1. User scans the QR code in the Home Assistant companion app (or types it).
2. Integration stores the device, derives keys, starts listening for `JOIN_HELLO`
   under its tag.
3. User presses the sensor's button. It sends `JOIN_HELLO` with a well-known
   bootstrap `net_tag` (all-zero) since it has no network key yet.
4. Server replies with `COMMAND(set_network)` carrying `K_net_route` and the epoch.
5. Sensor switches to normal tags. Pairing done.

Re-pairing to a different home is a factory reset plus a new scan. The QR code is
the secret: printed inside the battery cover, not on the outside.

### 7.3 Storage

Keys in Home Assistant's `.storage` (included in HA backups, which are encrypted).
Last `fcnt` per device persisted at least every 16 frames, with a jump-ahead
on restart.

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

### 8.2 Relay protocol

Use the Nostr event and relay model (NIP-01), with a dedicated ephemeral event kind
in the 20000-29999 range (number to be registered through a NIP).

- Each proxy generates a secp256k1 keypair (Nostr identity) on first boot and
  stores it in flash.
- Foreign frame published as:

```json
{
  "kind": 2xxxx,
  "pubkey": "<proxy pubkey>",
  "created_at": 1795226690,
  "tags": [["h", "<net_tag hex>"], ["r", "US915"]],
  "content": "<base64: raw frame | rssi | snr | freq_err>",
  "sig": "<schnorr sig>"
}
```

- Owner's HA subscribes with filter `{"kinds":[2xxxx], "#h":[tags for e-1..e+1]}`
  on several relays and updates the filter each epoch.
- Relays store nothing (ephemeral kind) and apply per-pubkey rate limits.
- Proxies publish to at least two relays. Owners subscribe to the same set.
  A default relay list ships with the integration; anyone can run `cs-relay`.

### 8.3 Federated downlinks

A neighbor's proxy may be the only one that hears a device. Downlinks to it go
back over the relay as a second ephemeral kind tagged `["p", "<proxy pubkey>"]`.
They are always too slow for RX1 and usually make RX2; otherwise they wait for
the next uplink. Proxies only transmit federated downlinks if
`federation.downlink: true` (off by default) and subject to the region's
duty-cycle budget.

### 8.4 What a relay operator or neighbor learns

- That some device with an hourly-changing tag sent a frame at time T, heard by
  proxy P at signal strength S.
- Not which home it belongs to, what it measured, or which device it is across
  hours.
- Residual leak: a neighbor can correlate "frames appear when someone walks past
  my window". Optional cover traffic (dummy heartbeats) is a later mitigation.

---

## 9. Control plane (optional)

These are useful but not required for the network to work.

### 9.1 Identity

Owners and proxies may publish a DID (`did:plc` or `did:web`). Linking a proxy's
Nostr pubkey to its owner's DID lets other owners trust or block proxies by owner,
and keeps that trust when keys rotate.

### 9.2 Coverage map

Opt-in records (AT Protocol lexicon `org.connectsensors.proxy`):
coarse location (geohash precision 5, roughly 5 km), region profile, uptime,
relay set. Lets people see where community coverage exists, like a non-token
Helium map.

### 9.3 Device profiles

Lexicon `org.connectsensors.deviceProfile`: maps `channel`/`kind` to Home Assistant
entity type, device class, unit, name and icon, plus heartbeat interval and
firmware version. Profiles are signed by their author and pulled by the
integration, so a new sensor design works in everyone's Home Assistant without
an integration release.

ActivityPub is a reasonable alternative for 9.2 and 9.3 if a fediverse community
prefers it; the integration should treat the control plane as pluggable.

---

## 10. YoLink observer mode (optional, receive-only)

For people with YoLink devices who want to know where their coverage is weak:

- `cs_proxy` option `yolink_observer: true` with its own frequency/SF settings
  (it needs a second radio or time-slicing, since the radio has one channel).
- Logs the cleartext header prefix and RSSI of frames that look like YoLink.
  It does not decrypt, store payloads, retransmit or transmit anything on YoLink
  frequencies.
- Reported to Home Assistant as "YoLink frames heard per proxy" diagnostics only.
- The header layout is inferred from a handful of public captures and may be
  wrong; treat the output as a heuristic.

---

## 11. Threat model

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

## 12. Reference hardware

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

## 13. Roadmap

| Phase | Deliverable | Done when |
|---|---|---|
| 0 | Spec freeze for frame v1 and region profiles | This document reviewed; test vectors published |
| 1 | `cs_proxy` sniffer mode + reference sensor firmware (contact + temp) | Frames from one sensor logged in HA via two proxies |
| 2 | `connect_sensors` integration: pairing, crypto, dedupe, entities, supervision | A paired sensor shows up as entities; replay/spoof tests pass |
| 3 | Downlinks: ACK, COMMAND, proxy selection, confirmed uplinks | 99% of confirmed frames acked within RX1/RX2 at -115 dBm |
| 4 | `cs-relay` + federation client + federated downlinks | Sensor in home A delivered via a proxy in home B only |
| 5 | Control plane: device profiles, coverage map, DIDs | New sensor type works from a published profile alone |
| 6 | Upstream `lora_proxy` proposal to ESPHome | PR opened |
| Later | LoRaWAN compatibility mode (multi-channel gateways), cover traffic, YoLink observer | - |

---

## 14. Open questions

1. US channel choice and whether 500 kHz SF9 gives enough range indoors, or a
   125 kHz hopping plan is worth the complexity.
2. Is one shared channel enough for a dense neighborhood once federation is on?
   May need two channels and SF diversity.
3. Default relay operators and governance: who runs the bootstrap relays?
4. Ephemeral event kind number and NIP process.
5. Whether to hide `fcnt` per epoch to reduce traffic analysis.
6. Battery-sensor firmware: Zephyr vs. ESPHome nRF52.
7. Licensing: MIT for code, CC BY 4.0 for the spec?

---

## 15. Repository layout (proposed)

```
ConnectSensors/
  docs/DESIGN.md                    this document
  spec/frame-v1.md                  normative wire format + test vectors
  components/cs_proxy/              ESPHome external component
  custom_components/connect_sensors/ Home Assistant integration
  firmware/sensor/                  reference sensor firmware
  relay/                            cs-relay (Nostr-compatible ephemeral relay)
  examples/                         proxy YAML for reference boards
```
