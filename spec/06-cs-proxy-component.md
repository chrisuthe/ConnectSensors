# 06 - `cs_proxy` ESPHome Component

Status: Draft
Version: 1.0-draft.3

This document specifies `cs_proxy`, the ESPHome external component that turns a
node with a LoRa radio into a ConnectSensors proxy. It covers configuration,
behavior and the diagnostics it exposes. The wire formats it uses are in 02
(frames) and 05 (proxy envelope).

## 1. Scope

`cs_proxy` attaches to an existing ESPHome `sx126x` or `sx127x` component. It
adds no radio driver of its own and never changes the radio's configuration. It:

- validates and deduplicates received frames without keys (02 section 12);
- forwards them to the server (05);
- transmits downlinks on request, inside the sensor's receive windows;
- reports its health as ESPHome entities.

Federation is normally done by the home server, which already receives every
frame (09 section 5.1), so a proxy attached to a server never talks to relays.
A proxy with no server can instead publish directly to relays as a *standalone
proxy* (09 section 5.2, and section 3.4 below).

## 2. Requirements

| Item | Requirement |
|---|---|
| Chip | ESP32 family (ESP32, -S2, -S3, -C3, -C6). Other targets MAY be supported later. |
| Framework | ESP-IDF or Arduino, as supported by the radio component |
| Network | Wi-Fi or Ethernet, on the same LAN as the server for UDP |
| Radio | Exactly one `sx126x` or `sx127x` component in LoRa mode |
| ESPHome | 2026.12.0 or later: the radio components provide `register_listener` and `start_transmit_async` (section 8.2). |

The radio MUST be configured with `rx_start: true` (the default), so it returns
to receive after every transmission.

## 3. Configuration

### 3.1 Example

```yaml
external_components:
  - source: github://chrisuthe/ConnectSensors@main
    components: [cs_proxy]

cs_proxy:
  radio_id: lora
  region: US915
  server:
    host: homeassistant.local
    key: !secret cs_proxy_key
```

A complete board example is in section 13.

### 3.2 Options

| Option | Type | Default | Meaning |
|---|---|---|---|
| `id` | ID | generated | |
| `radio_id` | ID of `sx126x` or `sx127x` | required | The radio to use |
| `region` | `US915` or `EU868` | required | Region profile (01) |
| `server.transport` | `udp` or `mqtt` | `udp` | 05 section 2 |
| `server.host` | hostname or IP | none | Server address for UDP. If omitted, mDNS discovery (05 section 2.1). |
| `server.port` | int | 47800 | Server UDP port |
| `server.key` | 32 hex digits | required unless standalone | The proxy key (05 section 4.2) |
| `proxy_id` | 16 hex digits | from MAC | Override only when the MAC is not stable |
| `downlink.enabled` | bool | `true` | Accept `DOWNLINK` messages |
| `downlink.airtime_budget` | percent | 2% | Transmit budget per rolling hour; MUST NOT exceed 2% (01 section 5) |
| `dedupe_window` | time | 30 s | 5 s to 120 s |
| `dedupe_cache_size` | int | 64 | 16 to 256 entries |
| `rate_limit.global` | rate | 20/s | Token bucket, burst equal to the rate |
| `rate_limit.per_device` | rate | 2/s | Per `dev_tag`, burst 5 |
| `rate_limit.bootstrap` | rate | 5/s | Shared by all bootstrap frames (`dev_tag` 0), burst 5 |
| `federation.enabled` | bool | `false` | Standalone mode (section 3.4); only allowed without `server` |
| `federation.relays` | list of `wss://` URLs | none | Required in standalone mode; at least 2 RECOMMENDED |
| `federation.downlinks` | bool | `false` | Accept downlink requests from relays (09 section 7) |
| `federation.allow` | list of pubkeys | none | If set, accept downlink requests only from these subscriber keys |

`transport: mqtt` requires ESPHome's `mqtt` component; `host` and `port` are then
ignored.

### 3.3 Validation at compile time

The component's final validation MUST fail with a clear message if:

1. `radio_id` is not an `sx126x` or `sx127x` component.
2. The radio's `modulation` is not `LORA`.
3. Any of the radio's `frequency`, `bandwidth`, `spreading_factor`,
   `coding_rate`, `preamble_size`, `sync_value` or `crc_enable` differs from the
   region profile (01 section 2 and 3). The message MUST give the expected value.
4. The radio's `rx_start` is `false`.
5. The radio's `pa_power` exceeds the profile's maximum.
6. `server.key` is not exactly 32 hex digits.
7. `downlink.airtime_budget` is above 2%.
8. Both `server` and `federation.enabled: true` are given, or neither is.
9. `federation.enabled: true` without at least one relay.

ESPHome's final-validation hook (`FINAL_VALIDATE_SCHEMA`) gives access to the
radio's configuration for these checks.

### 3.4 Standalone mode

A standalone proxy has no server and donates coverage to its neighbors.

- It publishes every valid frame as an uplink event (09 section 4.1) to its
  relays, signed with a key it generates on first boot and keeps in non-volatile
  storage. The public key is logged at `INFO` and exposed as a text sensor so
  neighbors can add it to allow lists.
- With `federation.downlinks: true` it handles downlink requests itself
  (09 section 7), scheduling them as in section 8.
- It needs a TLS WebSocket client and BIP-340 signatures (for example
  libsecp256k1). An ESP32-S3 with PSRAM is RECOMMENDED.
- There is no `HELLO`, `SERVER_STATUS` or envelope traffic in this mode.

## 4. Startup

1. Determine `proxy_id`: the configured override, or the EUI-64 of the primary
   MAC (05 section 4.1).
2. Pick `boot_id` from the hardware random number generator. It MUST NOT be 0.
3. Register as a listener on the radio and as its transmit listener.
4. Once the network is up, send `HELLO` (05 section 5.2), then every 60 seconds.

Frames received before the network is up are counted as heard and dropped
(section 5, step 4).

## 5. Receive pipeline

For each packet the radio delivers, in this order:

1. Take the timestamp (section 7) before anything else.
2. Increment `heard`.
3. Apply the keyless checks of 02 section 12 (length, magic, version, uplink type).
   On failure increment `invalid` and stop.
4. If the network is down or no server address is known yet, stop. The frame is
   only counted as heard: it MUST NOT be inserted into the dedupe cache or spend
   rate-limit tokens, so a retransmission heard once connected is forwarded.
5. Look up the frame in the dedupe cache (section 6). If present and younger than
   `dedupe_window`, increment `duplicates` and stop.
6. Apply the rate limits (section 6). If a bucket is empty, increment
   `rate_limited` and stop.
7. Insert the frame into the dedupe cache.
8. Build and send `UPLINK` (05 section 5.1). Increment `forwarded`.
9. In standalone mode, publish to relays as in 09 section 5.2 instead of step 8.

The packet buffer belongs to the radio component and is only valid during the
callback; the component MUST copy what it keeps. The whole pipeline MUST NOT
block: UDP sends are non-blocking, and MQTT publishes are queued.

## 6. Dedupe and rate limits

- Dedupe key: the first 8 bytes of SHA-256 over the complete frame. The cache is
  a fixed-size table of `(key, time)`; when full, the oldest entry is replaced.
- Rate limits are token buckets, refilled continuously. The per-device buckets are
  kept in a table of 32 entries keyed by `dev_tag`, least recently used replaced.
- Frames dropped by rate limits are not inserted into the dedupe cache, so a
  retransmission can still get through once tokens return.

## 7. Timestamps and loop gaps

ESPHome radio components deliver packets from the main loop, not from the radio
interrupt, so the component cannot know exactly when a packet finished arriving.
The listener callback runs soon after the interrupt when the main loop is
healthy, but a slow component elsewhere can delay it.

- `rx_time_us` MUST be taken from the ESP's monotonic microsecond clock
  (`esp_timer_get_time()`) at the start of the listener callback.
- The component runs its own `loop()` every main-loop pass and records the time
  of each pass. When a packet arrives, if more than the main-loop interval
  (`App.get_loop_interval()`, normally 16 ms) plus 20 ms has passed since the
  component's previous pass, the main loop was stalled and the packet may have
  waited. The component MUST then set `TS_UNCERTAIN` in the `UPLINK`. The loop
  interval is allowed for because an idle main loop sleeps between passes; the
  radio interrupt wakes it, so sleeping does not delay packet delivery.
- The component tracks the longest gap between its own loop passes and reports it
  in `HELLO` as `max_loop_gap_ms`, then resets it.
- If `max_loop_gap_ms` for the last interval exceeded 100 ms, the component MUST
  clear the downlink-capable bit in the next `HELLO`, and set it again after an
  interval below 100 ms.

Servers prefer proxies with good timing for RX1 (07).

## 8. Transmit scheduling

### 8.1 Accepting a `DOWNLINK`

On a `DOWNLINK` message that passes the envelope checks (05 section 3), the
component applies the rejection rules of 05 section 5.4, then:

1. Computes the frame's airtime from the radio settings (01 section 5.1 formula).
2. Checks the airtime budget: the sum of transmit time in the last 60 one-minute
   buckets plus this frame MUST NOT exceed `airtime_budget` of an hour.
3. Checks the schedule: at most 4 downlinks may be scheduled, and none may
   overlap another one's `[tx_at, tx_at + airtime + 100 ms]`.
4. Schedules the transmission for `tx_at`.

Rejections are reported immediately with `TX_RESULT`.

### 8.2 Transmitting

- A one-shot high-resolution timer (`esp_timer`) fires 2 ms before `tx_at`. Its
  callback only wakes the main loop (`enable_loop_soon_any_context()`); the main
  loop waits out the last 2 ms and starts the transmission itself.
- The component transmits if the current time is in `[tx_at, tx_at + 100 ms]`.
  This uses the radio's `start_transmit_async`, which returns once the frame is
  in the radio and reports completion from a later loop pass, so the main loop
  is not held for the frame's airtime (about 60 to 125 ms on US915). A radio
  answer of `BUSY` (a received packet is waiting) is retried on the next loop
  pass until `tx_at + 100 ms`, then reported as `BUSY`.
- If the window has passed, it reports `TOO_LATE` and does not transmit.
- On transmit completion it reports `SENT` with `offset_us` = actual start time
  minus `tx_at`, and adds the airtime to the budget. On a radio error it reports
  `RADIO_ERROR`.
- The radio cannot receive while it transmits. Frames sent by sensors during that
  time are lost to this proxy; other proxies and sensor retransmissions cover
  that.

The component MUST NOT transmit anything except frames received in `DOWNLINK`
messages. It never originates or modifies frames.

## 9. Connection state

- The proxy is *connected* while it has received a `SERVER_STATUS` within the last
  3 `HELLO` intervals (180 s).
- The latest `SERVER_STATUS` tag set is kept in memory for diagnostics (05 section 5.3).
- When disconnected, the proxy keeps forwarding to the configured address and
  keeps accepting `DOWNLINK` messages that pass the envelope checks.
- With mDNS discovery, a proxy that has been disconnected for 5 minutes repeats
  discovery.

## 10. Entities

### 10.1 Sensors

```yaml
sensor:
  - platform: cs_proxy
    cs_proxy_id: proxy        # optional when there is one cs_proxy
    frames_heard:
      name: "LoRa frames heard"
    frames_forwarded:
      name: "LoRa frames forwarded"
    last_rssi:
      name: "LoRa last RSSI"
```

| Key | Unit | State class | Meaning |
|---|---|---|---|
| `frames_heard` | - | total increasing | Packets from the radio |
| `frames_forwarded` | - | total increasing | `UPLINK` messages sent |
| `duplicates` | - | total increasing | Dropped as duplicates |
| `invalid` | - | total increasing | Dropped by keyless checks |
| `rate_limited` | - | total increasing | Dropped by rate limits |
| `downlinks_sent` | - | total increasing | `SENT` results |
| `downlinks_failed` | - | total increasing | Any other result |
| `last_rssi` | dBm | measurement | RSSI of the last valid frame |
| `last_snr` | dB | measurement | SNR of the last valid frame |
| `max_loop_gap` | ms | measurement | Value reported in the last `HELLO` |
| `airtime_used` | % | measurement | Transmit time in the last hour, as a percentage |

All are diagnostic entities. Counters publish at every `HELLO`; `last_rssi` and
`last_snr` publish at most once every 10 seconds.

### 10.2 Binary sensor

```yaml
binary_sensor:
  - platform: cs_proxy
    server_connected:
      name: "ConnectSensors server connected"
```

Device class `connectivity`, diagnostic.

## 11. Logging

- `INFO`: startup (`proxy_id`, region, server address), connection changes.
- `DEBUG`: one line per forwarded frame: type, tags, `fcnt`, RSSI, SNR. One line
  per downlink result.
- `VERBOSE`: frame hex.
- The proxy key MUST NOT be logged at any level.

## 12. Resources (informative)

| Item | Approximate size |
|---|---|
| Dedupe cache, 64 entries | 1 KB |
| Rate-limit table, 32 entries | 0.5 KB |
| Downlink schedule, 4 entries | 0.5 KB |
| Airtime buckets, 60 entries | 0.25 KB |
| Code | 15-25 KB flash |

SHA-256 and HMAC-SHA256 come from mbedTLS, which ESP-IDF already includes.

## 13. Example: Heltec WiFi LoRa 32 V3 (informative)

Pin numbers are from the board's published pinout; check them against your
board revision.

```yaml
esphome:
  name: lora-proxy-garage

esp32:
  board: heltec_wifi_lora_32_V3
  framework:
    type: esp-idf

wifi:
  ssid: !secret wifi_ssid
  password: !secret wifi_password

api:
logger:
ota:
  - platform: esphome

external_components:
  - source: github://chrisuthe/ConnectSensors@main
    components: [cs_proxy]

spi:
  clk_pin: GPIO9
  mosi_pin: GPIO10
  miso_pin: GPIO11

sx126x:
  id: lora
  hw_version: sx1262
  cs_pin: GPIO8
  rst_pin: GPIO12
  busy_pin: GPIO13
  dio1_pin: GPIO14
  rf_switch: true
  tcxo_voltage: 1_8V
  tcxo_delay: 5ms
  modulation: LORA
  frequency: 918.5MHz
  bandwidth: 500_0kHz
  spreading_factor: 9
  coding_rate: CR_4_5
  preamble_size: 8
  sync_value: [0x14, 0x24]
  crc_enable: true
  pa_power: 20
  rx_start: true

cs_proxy:
  id: proxy
  radio_id: lora
  region: US915
  server:
    host: homeassistant.local
    key: !secret cs_proxy_key

sensor:
  - platform: cs_proxy
    frames_forwarded:
      name: "LoRa frames forwarded"
    last_rssi:
      name: "LoRa last RSSI"
    max_loop_gap:
      name: "Main loop max gap"

binary_sensor:
  - platform: cs_proxy
    server_connected:
      name: "ConnectSensors server connected"
```

## 14. Conformance tests

An implementation of this component MUST pass at least the following, which can
be run against a test server built from the reference tool:

1. Every frame in `vectors/frame-v1.json` with an uplink type is forwarded
   unchanged; frames with a downlink type are not.
2. A frame sent twice within `dedupe_window` is forwarded once; sent again after
   the window, it is forwarded again.
3. Packets with a wrong magic byte, wrong version, type `0x0`, or a length outside
   23-86 bytes are counted as `invalid` and not forwarded.
4. The `UPLINK`, `HELLO` and `TX_RESULT` messages it produces parse and pass the
   MAC check with the reference tool (`open_envelope`) and the configured key, and
   their layout matches `vectors/proxy-envelope-v1.json`.
5. A `DOWNLINK` with a bad MAC, a stale server `seq`, a different `boot_id`, or an
   uplink-type frame is not transmitted.
6. A `DOWNLINK` for RX1 is transmitted with `offset_us` between 0 and 100 000 when
   the main loop is healthy.
7. Downlinks that would exceed the airtime budget are rejected with `DUTY_CYCLE`.
8. A configuration whose radio settings differ from the region profile fails to
   compile.
9. A frame heard while the network is down or no server address is known is not
   forwarded; the same frame heard again once connected, within `dedupe_window`,
   is forwarded.

## 15. Upstream improvements (informative)

These ESPHome changes would make proxies better. None is required by v1.

- **Receive timestamp.** Capturing the time in the radio's interrupt handler and
  passing it to listeners would remove the uncertainty in section 7.
- **IQ inversion.** An option to invert IQ on transmit would let a later profile
  version separate uplinks and downlinks at the physical layer, as LoRaWAN does.
- **A generic `lora_proxy`.** A component that forwards raw LoRa packets over the
  native API, as `bluetooth_proxy` does for BLE, would let Home Assistant receive
  frames without a separate UDP path. `cs_proxy` could then become a thin filter
  on top of it.
