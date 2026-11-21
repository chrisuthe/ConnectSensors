# `cs_proxy` ESPHome component

Turns an ESP32 with an SX126x or SX127x LoRa radio into a ConnectSensors proxy:
it forwards every ConnectSensors frame it hears to your server, and transmits
downlinks for the server inside the sensors' receive windows. The proxy holds no
sensor keys and cannot read the frames it forwards.

Specification: [spec/06-cs-proxy-component.md](../../spec/06-cs-proxy-component.md)
(component) and [spec/05-proxy-envelope.md](../../spec/05-proxy-envelope.md)
(messages to the server).

## Status

Version 0.2.0, early development. Implemented:

- Region profile `US915`, with compile-time checks that the radio settings match
- `sx126x` and `sx127x` radios
- UDP transport with per-proxy keys, `HELLO`, `SERVER_STATUS`, `UPLINK`,
  `DOWNLINK`, `TX_RESULT`, replay protection
- Keyless frame checks, dedupe, rate limits, airtime budget, transmit scheduling
- Asynchronous downlink transmit, so a downlink does not hold the main loop for
  its airtime
- Timestamp-uncertainty flag and downlink withdrawal when the main loop stalls
- Server hostname or IP address (resolved without blocking)
- Diagnostic sensors and the `server_connected` binary sensor

Not yet implemented (rejected at compile time where configurable):

- `EU868` (the profile's frequency is not decided)
- MQTT transport
- mDNS discovery of the server (`server.host` is required)
- Standalone federation (spec 09 section 5.2)

## Requirements

- ESPHome 2026.12 or later; until it is released, ESPHome's `dev` branch
  (`pip install "esphome @ git+https://github.com/esphome/esphome@dev"`)
- ESP32 family
- An `sx126x` or `sx127x` component in LoRa mode with the region's settings

## Quick start

1. Run the development server on a computer on the same network:

   ```
   pip install cryptography
   python3 devtools/cs_testserver.py
   ```

   It prints a proxy key.

2. Flash [examples/proxy-heltec-v3.yaml](../../examples/proxy-heltec-v3.yaml)
   with `cs_proxy_key` set to that key in `secrets.yaml` and `server_host` set to
   the computer's IP address.

3. The server shows a `HELLO` from the proxy within a few seconds.

4. To see frames without a sensor, flash
   [examples/test-transmitter-heltec-v3.yaml](../../examples/test-transmitter-heltec-v3.yaml)
   on a second board and press its buttons. Run the server with `--ack` to have
   it answer confirmed frames, which exercises the downlink path.

## Configuration

```yaml
external_components:
  - source: github://chrisuthe/ConnectSensors@main
    components: [cs_proxy]

cs_proxy:
  radio_id: lora          # an sx126x or sx127x component
  region: US915
  server:
    host: 192.168.1.10    # or a hostname
    port: 47800           # default
    key: !secret cs_proxy_key
  downlink:
    enabled: true         # default
    airtime_budget: 2%    # default and maximum
  dedupe_window: 30s
  dedupe_cache_size: 64
  rate_limit:
    global: 20/s
    per_device: 2/s
    bootstrap: 5/s
```

Sensors (all optional, all diagnostic): `frames_heard`, `frames_forwarded`,
`duplicates`, `invalid`, `rate_limited`, `downlinks_sent`, `downlinks_failed`,
`last_rssi`, `last_snr`, `max_loop_gap`, `airtime_used`. Binary sensor:
`server_connected`.

## Code layout

| File | Contents |
|---|---|
| `proxy_core.h/.cpp` | All protocol logic, with no ESPHome dependency |
| `cs_sha256.h/.cpp` | SHA-256 and HMAC-SHA256 |
| `cs_proxy.h/.cpp` | ESPHome glue: radio listener, UDP, timers, entities |
| `__init__.py` | Configuration schema, region checks, code generation |
| `sensor.py`, `binary_sensor.py` | Entity platforms |

The core is unit-tested on a computer against the specification's test vectors:

```
make -C tests/proxy_core
```
