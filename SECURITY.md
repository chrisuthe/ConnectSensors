# Security policy

ConnectSensors carries sensor data that people rely on (doors, leaks, motion), so
we take reports about its protocol and code seriously.

## Reporting a vulnerability

Please report privately through GitHub:
**[Report a vulnerability](https://github.com/chrisuthe/ConnectSensors/security/advisories/new)**
(the repository's *Security* tab, then *Report a vulnerability*).

Please don't open a public issue or pull request for a vulnerability until it has
been fixed.

A useful report says what is affected (a spec section, `cs_proxy`, `cs_sensor`,
`ssd1306_paced`, the reference implementation in `spec/tools/csframe.py`, or the
dev tools), what an attacker can do and from where (on the LoRa channel, on the
LAN, through a relay), and how to reproduce it. A test vector or a short script
is ideal.

## Scope

In scope:

- The protocol specification in `spec/`: framing and cryptography (02), pairing
  (04), the proxy envelope (05), network server rules (07) and federation (09).
  Design flaws count, not only implementation bugs.
- The ESPHome components in `components/` and the reference implementation.

Out of scope:

- `devtools/cs_testserver.py`, a development aid that is not meant for real
  deployments, unless the issue also affects the specification.
- Weaknesses the specification already documents and accepts, for example the
  residual root nonce reuse after a factory reset (02 section 13) or the shared
  proxy key trade-off (05 section 7). Arguments that one of these should not be
  accepted are welcome as ordinary issues.
- Attacks that need physical access to a sensor's or proxy's flash.

## Status and supported versions

The project is in early development and the specification is a draft. There are no
releases yet; fixes land on `main`. Responses are best effort.
