# `cs_sensor`: ConnectSensors sensor firmware

The sensor side of the ConnectSensors protocol, for any chip ESPHome supports with
an SX126x or SX127x radio.

This directory holds `sensor_core`, a C++ library with no ESPHome dependency. The
ESPHome component that wraps it (`cs_sensor` in YAML) is not written yet: it is
phase 2 of the sensor firmware work (#37), so this directory has no `__init__.py`
and ESPHome cannot load it yet.

Specification: [02 Frame format](../../spec/02-frame-v1.md),
[03 Payload](../../spec/03-payload-v1.md), [04 Pairing](../../spec/04-pairing.md)
and [08 Sensor behaviour](../../spec/08-sensor-behavior.md).

## Files

| File | Contents |
|---|---|
| `sensor_core.h/.cpp` | Frames, readings, pairing and sensor behaviour, plus the platform interfaces |
| `cs_crypto.h/.cpp` | AES-128, AES-128-CCM with an 8-byte tag, HKDF-SHA256 |
| `cs_x25519.h/.cpp` | X25519 |
| `cs_sha256.h/.cpp` | SHA-256 and HMAC-SHA256, copied from `cs_proxy` |

Tests: [`tests/sensor_core`](../../tests/sensor_core), run with
`make -C tests/sensor_core`. They build with plain `g++` under ASan and UBSan.

## What the core does

- **Frames (02):** key derivation for the root and session key sets, net and dev
  tags with epochs and the reserved-value substitution, bootstrap tags, sealing
  uplinks, and opening and checking downlinks (02 section 10.2).
- **Counters:** uplink counter reservation in blocks of 64 (02 section 8.2),
  and the session and root downlink floors (02 section 8.4). The root floor
  survives `JOIN`, pairing and `LEAVE`; only a factory reset clears it.
- **Readings (03):** encoding, with duplicate `(channel, kind)` pairs and
  oversized lists refused; decoding, which `SET_VALUE` (`0x40`) uses.
- **Behaviour (08):** state-change frames, heartbeats with the full state and
  `firmware_version` in the first one after boot, confirmed uplinks with the
  retry schedule, RX1 and RX2, `DL_ACK`, `PENDING`, contact loss and `SYNC`, clock
  keeping and `TIME_UNSURE`, the 1% airtime budget, and boot.
- **Pairing (04):** `UNPAIRED`, `JOINING`, `SESSION` and `PAIRED`, the
  `JOIN`, `KEY_EXCHANGE`, `SYNC` and `SET_NETWORK` exchange, `LEAVE`, and the
  factory reset.
- **Pairing code (04 section 3):** builds the `CS:1:...` string, so firmware can
  print its own code.

## Platform interfaces

The core never calls the platform directly; the ESPHome component supplies:

| Interface | Provides |
|---|---|
| `Clock` | Monotonic microseconds, and Unix time from the RTC (or "unknown") |
| `Radio` | `transmit`, `start_receive`, `stop_receive`, `receiving` (a packet is arriving), and the frame airtime |
| `Storage` | Load, save and erase of five small blobs; `save` returns true only once the write is durable |
| `Random` | A CSPRNG; it makes the ephemeral X25519 keys |

The platform calls `begin()` once after boot, `loop()` often, `on_tx_done()` when
a transmission ends and `on_receive()` for each received packet. While `hold()`
is true the core is transmitting, inside or waiting for an RX window, or holding
retries, and the device must stay awake. `next_wake_us()` says when the next
timer is due, for example the next heartbeat.

The application sets state readings with `set_state()`, asks for a frame with
`report()` and sends events (a button press) with `send_event()`. The pairing
button maps to `short_press()` and, after a 10-second hold, `factory_reset()`.
`on_set_value`, `on_command` and `on_event` call back into the application.

## Crypto provenance

| Primitive | Source | Licence |
|---|---|---|
| AES-128, AES-CCM, HKDF | Written for this repository | The repository's |
| X25519 | TweetNaCl `crypto_scalarmult` (Bernstein et al.), adapted to C++ without undefined behaviour | Public domain |
| SHA-256, HMAC | `components/cs_proxy/cs_sha256.*` | The repository's |

None of it uses platform crypto APIs, so ESP32 and nRF52 run the same code. The
tests check AES against FIPS 197, CCM against RFC 3610, HKDF against RFC 5869,
X25519 against RFC 7748, and all of them against the spec vectors.

## Why `cs_sha256` is copied, not shared

Sharing it would need a third component, say `cs_common`, that both components
`AUTO_LOAD`. ESPHome's `external_components` only loads the components a
configuration lists when it has a `components:` list, and every proxy
configuration lists exactly `[cs_proxy]` (or `[cs_proxy, ssd1306_paced]`), so
moving the code would break every existing proxy configuration until its owner
adds `cs_common`. The copy differs only in its namespace, and
`make -C tests/sensor_core` fails if the two drift apart.

The other shared parts are small: header parsing and the airtime formula. The
sensor parses downlink headers inside `open_frame`, and the platform supplies
airtime through `Radio::airtime_us`.

## Readings of the spec

Where the spec is silent or ambiguous, the core takes the conservative reading:

- A short press in `JOINING` or `SESSION` is ignored (04 section 4.5 leaves it
  undefined).
- Only `PAIRED` is stored. A restart in `JOINING` or `SESSION` returns to
  `UNPAIRED` with the root floor kept, so the user presses the button again.
- A `SYNC` in `SESSION` that gets no answer after its retries returns the
  sensor to `UNPAIRED`, keeping the root floor, like an unanswered `JOIN`. A
  `SYNC` answered without `SET_NETWORK` is sent again, up to 4 times in all,
  and then pairing fails the same way.
- After 3 undelivered confirmed uplinks, every confirmed attempt is a `SYNC`
  until a downlink is accepted, not only the next one (08 section 6).
- A state change abandons pending retries. The abandoned uplink does not count
  as undelivered, because 08 section 5 reserves that for an uplink whose last
  retry went unanswered. A frame carrying an event (a button press) is never
  abandoned, because the new frame would deliver the event again under a new
  counter.
- Heartbeats are scheduled at `h` plus or minus 10% (08 section 4.2), but never
  more than 24 hours after the last confirmed uplink (08 section 3.3). With `h`
  near 1440 minutes the two conflict, and the 24-hour MUST wins.
- `firmware_version` rides on heartbeats until one carrying it is answered, or
  goes out unconfirmed.
- Without a clock, unconfirmed frames are sent as `SYNC` too, since normal tags
  cannot be computed (08 section 3.2).
- On `LEAVE`, the keys are erased when the final `HEARTBEAT` finishes
  transmitting. Its RX1 still opens, but nothing in it can verify. Commands
  after `LEAVE` in the same downlink still run, in order. A `LEAVE` received in
  `SESSION` erases the keys without the final heartbeat, which would need
  normal tags.
- A truncated command ends command processing for that downlink.
- Downlink tags are not checked: the MIC covers them, and 02 section 10.2 does
  not list them.
- The uplink counter never uses `0xFFFFFFFF`.
- A storage that cannot erase gets the blob overwritten with zeros, which load
  as absent, so a factory reset still forgets the keys.

## Not done yet

For the ESPHome component (#37) and the nRF52 work (#38):

- Mapping a deep-sleep wake to a boot or not. As written, `begin()` is a boot: it
  reserves a new counter block and sets `TIME_UNSURE` until a downlink arrives.
- Channel activity detection before transmitting (08 section 4.3, a SHOULD).
- X25519 cost on nRF52, not measured yet: TweetNaCl is small but among the
  slowest X25519 implementations, and pairing does two operations, one of them
  inside `on_receive`.
- Flash wear: the session floor is written on every accepted downlink.
