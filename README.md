# ConnectSensors

An open LoRa sensor network for Home Assistant. Battery sensors transmit encrypted
frames; any ESPHome node with a LoRa radio forwards every frame it hears without
being able to read it; the owner's Home Assistant deduplicates, verifies and
decrypts. Neighbors can optionally carry each other's traffic through community
relays.

## Status

Early development: the spec is a draft and there are no releases.

- **Proxy (`cs_proxy`):** working on a Heltec V3 bench rig. It forwards uplinks,
  sends downlinks on time, and recovers from server restarts.
- **Sensor (`cs_sensor`):** working on ESP32 (Heltec V3). It pairs, sends confirmed
  state changes and deep-sleeps. It builds for nRF52; hardware testing is next
  ([#38](https://github.com/chrisuthe/ConnectSensors/issues/38)).
- **Network server:** only the development server (`devtools/cs_testserver.py`).
  The Home Assistant integration isn't started.
- **Not implemented:** federation and relays, EU868, MQTT transport.
- **Requires ESPHome 2026.12**, which means the `dev` branch until it's released.

## Repository

| Path | Contents |
|---|---|
| [`docs/DESIGN.md`](docs/DESIGN.md) | Design overview and open questions |
| [`spec/`](spec/) | The protocol specification, self-contained, with test vectors and a reference implementation in Python |
| [`components/cs_proxy/`](components/cs_proxy/) | ESPHome external component: the proxy |
| [`components/cs_sensor/`](components/cs_sensor/) | ESPHome external component: the sensor, on the host-tested protocol core (`sensor_core`) |
| [`components/ssd1306_paced/`](components/ssd1306_paced/) | ESPHome external component: an SSD1306 display driver that never blocks the main loop for a whole frame |
| [`devtools/cs_testserver.py`](devtools/cs_testserver.py) | Development server for testing proxies and pairing sensors |
| [`examples/`](examples/) | ESPHome configurations for a proxy, sensors (mains and deep sleep) and a test transmitter |
| [`tests/`](tests/) | Unit tests for the proxy and sensor cores and a smoke test for the test server |

## Running the tests

```
pip install cryptography
python3 spec/tools/csframe.py verify spec/vectors   # spec test vectors
make -C tests/proxy_core                            # proxy core, C++
make -C tests/sensor_core                           # sensor core, C++
python3 tests/devtools/test_testserver.py           # test server
```

## Trying a proxy

See [`components/cs_proxy/README.md`](components/cs_proxy/README.md).

## Building a sensor

See [`components/cs_sensor/README.md`](components/cs_sensor/README.md).
