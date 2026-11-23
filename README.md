# ConnectSensors

An open LoRa sensor network for Home Assistant. Battery sensors transmit encrypted
frames; any ESPHome node with a LoRa radio forwards every frame it hears without
being able to read it; the owner's Home Assistant deduplicates, verifies and
decrypts. Neighbors can optionally carry each other's traffic through community
relays.

## Status

Early development: the spec is a draft and nothing is ready for real deployments yet.

- **Proxy (`cs_proxy`):** working on a Heltec V3 bench rig. It forwards uplinks,
  sends downlinks on time, and recovers from server restarts.
- **Sensor (`cs_sensor`):** working on ESP32 (Heltec V3). It pairs, sends confirmed
  state changes and deep-sleeps. It builds for nRF52; hardware testing is next
  ([#38](https://github.com/chrisuthe/ConnectSensors/issues/38)).
- **Network server:** the Home Assistant integration
  ([connect-sensors-ha](https://github.com/chrisuthe/connect-sensors-ha)),
  [0.1.0](https://github.com/chrisuthe/connect-sensors-ha/releases/tag/v0.1.0) on
  HACS as a custom repository. It pairs sensors and turns their readings into
  entities. It also chooses between proxies, supervises devices, sends commands and
  raises repairs. Tested on the bench rig. `devtools/cs_testserver.py` remains for
  development.
- **Python package:** [`connectsensors`](https://pypi.org/project/connectsensors/)
  on PyPI, the reference implementation packaged for network servers.
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
| [`python/`](python/) | The `connectsensors` Python package: the reference implementation, packaged for network servers such as the Home Assistant integration |
| [`devtools/cs_testserver.py`](devtools/cs_testserver.py) | Development server for testing proxies and pairing sensors |
| [`examples/`](examples/) | ESPHome configurations for a proxy, sensors (mains and deep sleep) and a test transmitter |
| [`tests/`](tests/) | Unit tests for the proxy and sensor cores, a smoke test for the test server, and the proxy engine run as a host program against it |

## Running the tests

```
pip install cryptography
python3 spec/tools/csframe.py verify spec/vectors   # spec test vectors
make -C tests/proxy_core                            # proxy core, C++
make -C tests/sensor_core                           # sensor core, C++
python3 tests/devtools/test_testserver.py           # test server
make -C tests/host_proxy                            # proxy engine on the host against the test server
tests/package/check.sh                              # Python package build and smoke test (needs uv)
```

CI runs each of these as its own job in [`.github/workflows/tests.yml`](.github/workflows/tests.yml),
along with ESPHome config validation and compiles against ESPHome `dev`.

## Trying a proxy

See [`components/cs_proxy/README.md`](components/cs_proxy/README.md).

## Building a sensor

See [`components/cs_sensor/README.md`](components/cs_sensor/README.md).
