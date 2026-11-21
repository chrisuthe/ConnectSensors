# ConnectSensors

An open LoRa sensor network for Home Assistant. Battery sensors transmit encrypted
frames; any ESPHome node with a LoRa radio forwards every frame it hears without
being able to read it; the owner's Home Assistant deduplicates, verifies and
decrypts. Neighbors can optionally carry each other's traffic through community
relays.

Status: early development. The protocol is drafted in full; the ESPHome proxy
component is the first implementation.

## Repository

| Path | Contents |
|---|---|
| [`docs/DESIGN.md`](docs/DESIGN.md) | Design overview and open questions |
| [`spec/`](spec/) | The protocol specification, self-contained, with test vectors and a reference implementation in Python |
| [`components/cs_proxy/`](components/cs_proxy/) | ESPHome external component: the proxy |
| [`devtools/cs_testserver.py`](devtools/cs_testserver.py) | Development server for testing proxies |
| [`examples/`](examples/) | ESPHome configurations for a proxy and a test transmitter |
| [`tests/`](tests/) | Unit tests for the proxy core and a smoke test for the test server |

## Running the tests

```
pip install cryptography
python3 spec/tools/csframe.py verify spec/vectors   # spec test vectors
make -C tests/proxy_core                            # proxy core, C++
python3 tests/devtools/test_testserver.py           # test server
```

## Trying a proxy

See [`components/cs_proxy/README.md`](components/cs_proxy/README.md).
