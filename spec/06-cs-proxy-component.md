# 06 - `cs_proxy` ESPHome Component

Status: Draft
Version: 1.0-draft.1

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

Federation (forwarding to relays) is specified in 09. Until 09 is implemented,
the component MUST reject `federation: enabled: true`.

## 2. Requirements

| Item | Requirement |
|---|---|
| Chip | ESP32 family (ESP32, -S2, -S3, -C3, -C6). Other targets MAY be supported later. |
| Framework | ESP-IDF or Arduino, as supported by the radio component |
| Network | Wi-Fi or Ethernet, on the same LAN as the server for UDP |
| Radio | Exactly one `sx126x` or `sx127x` component in LoRa mode |
| ESPHome | A release whose radio component provides `register_listener` and `start_transmit_async`. Both are in ESPHome's development branch as of November 2026; the minimum release is to be confirmed. |

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
| `server.key` | 32 hex digits | required | The proxy key (05 section 4.2) |
| `proxy_id` | 16 hex digits | from MAC | Override only when the MAC is not stable |
| `downlink.enabled` | bool | `true` | Accept `DOWNLINK` messages |
| `downlink.airtime_budget` | percent | 2% | Transmit budget per rolling hour; MUST NOT exceed 2% (01 section 5) |
| `dedupe_window` | time | 30 s | 5 s to 120 s |
| `dedupe_cache_size` | int | 64 | 16 to 256 entries |
| `rate_limit.global` | rate | 20/s | Token bucket, burst equal to the rate |
| `rate_limit.per_device` | rate | 2/s | Per `dev_tag`, burst 5 |
| `rate_limit.bootstrap` | rate | 5/s | Shared by all bootstrap frames (`dev_tag` 0), burst 5 |
| `federation.enabled` | bool | `false` | Reserved for 09 |

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
8. `federation.enabled` is `true` (until 09).

ESPHome's final-validation hook (`FINAL_VALIDATE_SCHEMA`) gives access to the
radio's configuration for these checks.

## 4. Startup

1. Determine `proxy_id`: the configured override, or the EUI-64 of the primary
   MAC (05 section 4.1).
2. Pick `boot_id` from the hardware random number generator. It MUST NOT be 0.
3. Register as a listener on the radio and as its transmit listener.
4. Once the network is up, send `HELLO` (05 section 5.2), then every 60 seconds.

Frames received before the network is up are counted as heard and dropped.

## 5. Receive pipeline

For each packet the radio delivers, in this order:

1. Take the timestamp (section 7) before anything else.
2. Increment `heard`.
3. Apply the keyless checks of 02 section 12 (length, magic, version, uplink type).
   On failure increment `invalid` and stop.
4. Look up the frame in the dedupe cache (section 6). If present and younger than
   `dedupe_window`, increment `duplicates` and stop.
5. Apply the rate limits (section 6). If a bucket is empty, increment
   `rate_limited` and stop.
6. Insert the frame into the dedupe cache.
7. Build and send `UPLINK` (05 section 5.1). Increment `forwarded`.
8. (09, later) If federation is enabled and `net_tag` is not in the server's tag
   set, also send to relays.

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
  of each pass. When a packet arrives, if more than 20 ms have passed since the
  component's previous pass, the main loop was stalled and the packet may have
  waited. The component MUST then set `TS_UNCERTAIN` in the `UPLINK`.
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

- A one-shot high-resolution timer (`esp_timer`) fires at `tx_at`. Its callback
  only wakes the main loop (`enable_loop_soon_any_context()`); the transmission
  itself starts from the main loop.
- In the main loop, the component calls the radio's `start_transmit_async` if the
  current time is in `[tx_at, tx_at + 100 ms]`.
- If the radio answers `BUSY` (a received packet is waiting), the component
  retries on the next loop pass until `tx_at + 100 ms`, then reports `BUSY`.
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
- The latest `SERVER_STATUS` tag set is kept in memory for federation decisions.
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
