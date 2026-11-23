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
| 05 | [Proxy envelope](05-proxy-envelope.md) | Draft |
| 06 | [`cs_proxy` ESPHome component](06-cs-proxy-component.md) | Draft |
| 07 | [Network server](07-network-server.md) | Draft |
| 08 | [Sensor behavior](08-sensor-behavior.md) | Draft |
| 09 | [Federation through mailboxes](09-federation-relay.md) | Draft |
| 10 | [Control plane](10-control-plane.md) | Draft |

## Supporting material

- [`lexicons/`](lexicons/) - the AT Protocol lexicon for device profiles (10).
- [`vectors/`](vectors/) - test vectors. An implementation that does not
  reproduce them byte for byte is not conformant.
- [`tools/csframe.py`](tools/csframe.py) - informative reference implementation
  of frames, payloads, pairing codes, the key exchange, the proxy envelope, and
  the server's counter rules, and mailbox federation (key-fingerprint tags,
  strict Ed25519 verification and the CBOR messages). It generates and
  checks the vectors, and is published unchanged as the
  [`connectsensors`](../python/README.md) Python package.

```
cd tools
python3 csframe.py verify ../vectors
```

## Licensing

- Specification documents (`*.md`): Creative Commons Attribution 4.0
  International, see [LICENSE](LICENSE).
- Code, test vectors and lexicons (`tools/`, `vectors/`, `lexicons/`): MIT, see
  [LICENSE-CODE](LICENSE-CODE), so they can be copied into implementations
  under any license.

## Contributing

Changes to anything marked Draft are open for discussion. Every change to the
wire format MUST update the test vectors in the same commit.
