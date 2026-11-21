# ConnectSensors Protocol Specification

This folder is the normative specification of the ConnectSensors protocol. It is
self-contained: nothing here depends on files outside `spec/`, so it can be moved
to its own repository without changes.

## Documents

| # | Document | Status |
|---|---|---|
| 00 | [Conventions](00-conventions.md) | Draft |
| 01 | [Radio profiles](01-radio-profiles.md) | Draft |
| 02 | [Frame format v1](02-frame-v1.md) | Draft |
| 03 | [Payload v1](03-payload-v1.md) | Draft |
| 04 | [Pairing](04-pairing.md) | Draft |
| 05 | Proxy envelope (proxy to server) | Planned |
| 06 | `cs_proxy` ESPHome component | Planned |
| 07 | Network server behavior | Planned |
| 08 | Sensor behavior | Planned |
| 09 | Federation relay | Planned |
| 10 | Control plane | Planned |

## Supporting material

- [`vectors/`](vectors/) - test vectors. An implementation that does not
  reproduce them byte for byte is not conformant.
- [`tools/csframe.py`](tools/csframe.py) - informative reference implementation
  of frames, payloads, pairing codes and the key exchange. It generates and
  checks the vectors.

```
cd tools
python3 csframe.py verify ../vectors
```

## Licensing

- Specification documents (`*.md`): Creative Commons Attribution 4.0
  International, see [LICENSE](LICENSE).
- Code and test vectors (`tools/`, `vectors/`): MIT, see
  [LICENSE-CODE](LICENSE-CODE), so they can be copied into implementations
  under any license.

## Contributing

Changes to anything marked Draft are open for discussion. Every change to the
wire format MUST update the test vectors in the same commit.
