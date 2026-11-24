# ConnectSensors

An open LoRa sensor network for Home Assistant. Battery sensors transmit encrypted
frames; any ESPHome node with a LoRa radio forwards every frame it hears without
being able to read it; the owner's Home Assistant deduplicates, verifies and
decrypts. Neighbors can optionally carry each other's traffic through mailbox
servers.

## Status

Early development: the spec is a draft and nothing is ready for real deployments yet.

- **Proxy (`cs_proxy`):** working on a Heltec V3 bench rig. It forwards uplinks,
  sends downlinks on time, and recovers from server restarts. Measured on air with
  the bench runner ([`devtools/bench/`](devtools/bench/)), downlinks start a median
  6.6 ms after their receive window opens, against a 0-81 ms budget (spec 01
  section 4.1).
- **Sensor (`cs_sensor`):** working on ESP32 (Heltec V3). It pairs, sends confirmed
  state changes and deep-sleeps. Its key work (tags, the pairing key exchange) runs
  in slices of about 4 ms per loop pass, so it never blocks ESPHome's loop. It builds for nRF52; hardware testing is next
  ([#38](https://github.com/chrisuthe/ConnectSensors/issues/38)).
- **Network server:** the Home Assistant integration
  ([connect-sensors-ha](https://github.com/chrisuthe/connect-sensors-ha)),
  [0.2.3](https://github.com/chrisuthe/connect-sensors-ha/releases/tag/v0.2.3) on
  HACS as a custom repository. It pairs sensors and turns their readings into
  entities. It also chooses between proxies, supervises devices, sends commands and
  raises repairs. Tested on the bench rig. `devtools/cs_testserver.py` remains for
  development.
- **Federation:** working end to end through mailbox servers
  ([spec 09](spec/09-federation-relay.md)). A sensor heard only by a neighbour's proxy
  reaches its owner, with acknowledgements and queued commands going back through
  that proxy. Pairing always stays local. The reference server is
  [`mailbox/`](mailbox/), published as the container image
  [`ghcr.io/chrisuthe/cs-mailbox`](mailbox/README.md#container-image) (built-in TLS
  or behind a reverse proxy such as Nginx Proxy Manager) and packaged as a Home
  Assistant app in [HAOS-cs-mailbox](https://github.com/chrisuthe/HAOS-cs-mailbox). Tested on the
  bench with two Home Assistant instances and the app on HA OS, and in CI with
  simulated homes.
- **Python package:** [`connectsensors`](https://pypi.org/project/connectsensors/)
  on PyPI (0.4.3), the reference implementation packaged for network servers,
  including the federation helpers.
- **Not implemented:** EU868, MQTT transport, mDNS discovery, device-profile
  distribution (spec 10).
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
| [`devtools/cs_testserver.py`](devtools/cs_testserver.py) | Development server for testing proxies and pairing sensors, and a federation home (`--mailbox`) |
| [`devtools/bench/`](devtools/bench/) | Bench runner: scenarios against a proxy with the test transmitter, measuring downlink timing on air, and run records |
| [`devtools/press.py`](devtools/press.py) | Press ESPHome API buttons and call actions from the command line |
| [`mailbox/`](mailbox/) | `cs-mailbox`, the reference mailbox server for federation (spec 09), and its container image |
| [`examples/`](examples/) | ESPHome configurations for a proxy, sensors (mains and deep sleep) and a test transmitter |
| [`tests/`](tests/) | Unit tests for the proxy and sensor cores, a smoke test for the test server, the proxy engine run as a host program against it, homes federating through `cs-mailbox`, and its container image |

## Running the tests

```
pip install cryptography
python3 spec/tools/csframe.py verify spec/vectors   # spec test vectors
make -C tests/proxy_core                            # proxy core, C++
make -C tests/sensor_core                           # sensor core, C++
python3 tests/devtools/test_testserver.py           # test server
make -C tests/host_proxy                            # proxy engine on the host against the test server, and the bench runner simulated
make -C tests/federation                            # cs-mailbox against 09, and two homes through it (needs websockets)
make -C tests/mailbox-image                         # the cs-mailbox image in both modes (docker, or CONTAINER_ENGINE=podman)
tests/package/check.sh                              # Python package build and smoke test (needs uv)
```

CI runs each of these as its own job in [`.github/workflows/tests.yml`](.github/workflows/tests.yml),
along with ESPHome config validation and compiles against ESPHome `dev`.

## Trying a proxy

See [`components/cs_proxy/README.md`](components/cs_proxy/README.md).

## Building a sensor

See [`components/cs_sensor/README.md`](components/cs_sensor/README.md).
