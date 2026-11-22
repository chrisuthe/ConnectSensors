# 00 - Conventions

Status: Draft
Version: 1.0-draft.2

This document defines terms and notation used by every other ConnectSensors
specification.

## 1. Requirement language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" are to be
interpreted as described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they
appear in all capitals.

Sections marked *informative* contain no requirements.

## 2. Roles

| Term | Meaning |
|---|---|
| Sensor | A battery or mains device that originates uplink frames. Also called a device. |
| Proxy | A receiver (normally an ESPHome node) that forwards frames without holding any keys. |
| Server | The network server that owns a network: verifies, decrypts and acts on frames. Normally a Home Assistant integration. |
| Owner | The person or system that controls a server and its keys. |
| Network | The set of sensors paired to one server, sharing one network key. |
| Relay | A federation service that passes frames between proxies and servers in different homes. |
| Uplink | A frame sent by a sensor. |
| Downlink | A frame sent by a server, transmitted by a proxy, to a sensor. |
| Epoch | A one-hour period, numbered as `floor(unix_time / 3600)`. |

## 3. Notation

- All multi-byte integers are unsigned and big-endian unless stated otherwise.
- `a | b` is byte-string concatenation.
- `x[i:j]` is bytes `i` to `j - 1` of `x`, zero-based.
- `trunc32(x)` is `x[0:4]`.
- `uint8`, `uint16`, `uint32` are unsigned integers of 1, 2 and 4 bytes.
- `int16` is a two's-complement signed integer of 2 bytes.
- String literals in key derivation, such as `"cs1 enc"`, are ASCII bytes with no
  terminator.
- Byte values are written in hex with a `0x` prefix; byte strings in lowercase hex
  without separators.
- Time values are Unix time in seconds, UTC, as `uint32`. This rolls over in 2106.

## 4. Cryptographic primitives

| Name | Definition |
|---|---|
| AES-128-CCM | NIST SP 800-38C / RFC 3610, 13-byte nonce, 8-byte tag |
| HMAC-SHA256 | RFC 2104 with SHA-256 (FIPS 180-4) |
| HKDF-SHA256 | RFC 5869 with SHA-256. A missing salt means the RFC's default (32 zero bytes). |
| X25519 | RFC 7748 Diffie-Hellman over Curve25519, 32-byte keys |
| Base32 | RFC 4648 section 6 alphabet, uppercase |

## 5. Versioning

- Each document carries a version `MAJOR.MINOR` plus an optional `-draft.N`.
- The wire format carries its own version number (see 02). A change that an
  existing receiver would misinterpret MUST increase the wire version.
- Additive changes (a new frame type, a new command, a new reading kind) MUST be
  designed so that existing receivers can safely ignore them.
- Document status is one of: Draft (may change incompatibly), Candidate (only
  changes driven by implementation experience), Stable (only errata).

## 6. Test vectors

Normative documents that define encodings MUST have test vectors in `vectors/`.
When the prose and the vectors disagree, the disagreement is a specification bug
and MUST be resolved before the document leaves Draft.

Where an encoding has inputs a receiver must reject, its vector file has an
`invalid` array. Each entry gives the input, the `reason` the reference tool
reports and the `rule` (document and section) it breaks. Entries are built so
that only the named rule fails: a frame with a bad version still carries a valid
MIC, a pairing code with a bad field still has a correct checksum. The reference
tool's `verify` command checks that it rejects each one for that reason.

The vectors are generated and verified by the same reference implementation, so
`tests/spec/test_independent_crypto.py` also checks the key schedule and every
frame with AES-CCM, HKDF and X25519 called directly, without the reference
tool's helpers.
