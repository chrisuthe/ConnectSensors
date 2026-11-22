# `cs_sensor`: ConnectSensors sensor firmware

The sensor side of the ConnectSensors protocol as an ESPHome external component:
a ConnectSensors sensor is a YAML file. It runs on ESP32 with an SX126x or SX127x
radio, mains powered or on ESP32 `deep_sleep`. nRF52 is next (#38).

Specification: [02 Frame format](../../spec/02-frame-v1.md),
[03 Payload](../../spec/03-payload-v1.md), [04 Pairing](../../spec/04-pairing.md)
and [08 Sensor behaviour](../../spec/08-sensor-behavior.md).

## Building a sensor

Start from [`examples/sensor-heltec-v3.yaml`](../../examples/sensor-heltec-v3.yaml)
(mains) or
[`examples/sensor-heltec-v3-deep-sleep.yaml`](../../examples/sensor-heltec-v3-deep-sleep.yaml)
(battery). Both are a contact sensor on a Heltec WiFi LoRa 32 V3 with a reed
switch on GPIO6 and PRG as the pairing button.

1. Make the identity: a `dev_eui` (16 hex digits, unique per device) and a
   `root_key` (`openssl rand -hex 16`). Put them in `secrets.yaml`.
2. `esphome compile` prints the pairing code (`CS:1:...`). It holds the root
   key, so treat it like one.
3. Give the code to the server. For the development server:
   `python3 devtools/cs_testserver.py --key <proxy key> --device CS:1:... --state pairings.json`,
   with a [proxy](../cs_proxy/README.md) running.
4. Flash the sensor and press the pairing button. The server logs `JOIN`,
   `KEY_EXCHANGE`, `SYNC`, `SET_NETWORK` and `PAIRED`, then every uplink
   decrypted.

### Configuration

```yaml
cs_sensor:
  radio_id: lora               # an sx126x or sx127x, set to the region profile
  region: US915
  dev_eui: !secret cs_dev_eui  # or pairing_code: "CS:1:..." instead of both
  root_key: !secret cs_root_key
  profile: ESPHOME             # profile id in the pairing code (default ESPHOME)
  heartbeat: 60min             # 1 to 1440 minutes; SET_HEARTBEAT overrides it
  firmware_version: "1.0.0"    # optional, sent in the first heartbeat after boot
  battery: batt_percent        # optional sensor, 0-100 %, or
  battery_voltage: batt_volts  # optional sensor, in volts; both ride on heartbeats only
  pairing_button: pair_btn     # binary sensor: short press pairs, 10 s hold resets
  deep_sleep_id: sleeper       # optional; see "Deep sleep"
  pairing_window: 60s          # deep sleep: awake this long after a reset or a button wake
  max_sleep: 15min             # deep sleep: optional cap, so polled sensors get read
  readings:
    - channel: 0
      kind: contact            # a kind from 03 section 4
      binary_sensor: door      # binary kinds take a binary_sensor, the others a sensor
      confirmed: true          # default true for contact, motion, leak and tamper
      min_interval: 0s         # at most one frame per interval for this reading
    - channel: 1
      kind: temperature
      sensor: temp             # in degrees Celsius; sent in 0.01 degree steps
      delta: 0.5               # report when it moved this far from what the server has
      min_interval: 5min
```

- Each reading's value is scaled from the ESPHome unit to the wire unit of its
  kind (degrees to 0.01 degrees, volts to millivolts, metres to millimetres,
  hPa to 0.1 hPa, % to 0.01 % for humidity and moisture). `multiply:` overrides
  the factor. A sensor with no value (NaN) sends the kind's "unknown" value.
- A change is reported when the value differs from what the server last saw by
  `delta` or more (any change without `delta`), and `min_interval` has passed
  since that reading last caused a frame. Every frame carries the full state.
- `button`, `firmware_version`, `raw` and `text` cannot be readings; channel
  `0xFF` belongs to the battery.
- The readings, battery and `firmware_version` must fit in one frame (63 bytes,
  16 readings); validation says so if they do not.
- The radio must match the region profile, as for `cs_proxy`, including
  `rx_start: true`. That lets the driver report a packet that is still arriving,
  so an RX window stays open until it ends (01 section 4). `cs_sensor` puts the
  radio to sleep outside its RX windows, so it never listens all the time.

Diagnostic entities, all optional:

```yaml
sensor:
  - platform: cs_sensor
    uplink_counter: {name: "LoRa uplink counter"}
    undelivered: {name: "LoRa undelivered uplinks"}
    last_rssi: {name: "LoRa last downlink RSSI"}
    last_snr: {name: "LoRa last downlink SNR"}
text_sensor:
  - platform: cs_sensor
    pairing_state: {name: "LoRa pairing state"}   # unpaired, joining, session, paired
```

### Deep sleep

With `deep_sleep_id`, `cs_sensor` decides when to sleep and for how long, so the
`deep_sleep` component must have no `run_duration` or `sleep_duration`. It stays
awake while the core holds (transmitting, RX1 and RX2, retries, work to send),
while the pairing button is down, and for `pairing_window` after a reset or a
wake by an `esp32_ext1_wakeup` pin (the pairing button). Otherwise it sleeps
until the core's next timer (the heartbeat), a reading's `min_interval`, or
`max_sleep`, whichever comes first. Wake it on the reading inputs with
`deep_sleep`'s `wakeup_pin` (`wakeup_pin_mode: INVERT_WAKEUP` for a contact, so
both edges wake it), and on the pairing button with `esp32_ext1_wakeup`.

**A deep-sleep wake is not a boot.** Before sleeping, the component stores the
core's RAM state (`SensorCore::suspend()`, a `WarmState`), what the server last
saw of each reading, and the clocks, in 1.7 KB of RTC memory. After a wake,
`SensorCore::resume()` takes the place of `begin()`:

- **Counter block:** it carries on with the block reserved before the sleep, so
  a wake writes nothing to flash. The stored reservation is always ahead of every
  counter used, so a power loss later still starts above them (02 section 8.2).
- **`TIME_UNSURE`:** the ESP32 RTC keeps Unix time through deep sleep, so a
  clock that was valid stays valid (08 section 3.1), and no boot uplink is sent
  (08 section 9). The heartbeat schedule and the 24-hour confirmed uplink go on.
- **Monotonic clock:** `esp_timer` restarts at every wake, so the component adds
  an offset: the monotonic time at sleep plus the RTC time slept. The core's
  timers stay on one clock.

A wake is a boot instead whenever any of that is missing: a reset other than a
deep-sleep wake, a snapshot that fails its check or was taken with work pending,
storage that no longer matches it (a different counter reservation or pairing
state), or an RTC that went backwards. The core then runs `begin()` as after a
power-on. Spec 08 section 9 states the rule. `tests/sensor_core` covers resume,
each rejection, and a lost RTC across the sleep.

### Flash wear

Storage is one ESPHome preference (NVS) per blob, committed before `save()`
returns. Writes happen on a counter reservation (every 64 uplinks, and at each
boot), on pairing, on `SET_HEARTBEAT`, and on every accepted downlink (the
session floor). A contact sensor with 10 events and 6 confirmed heartbeats a day
writes about 20 small records a day. NVS spreads them over its pages, so wear is
negligible at that rate. A sensor answered many times a minute could defer the
floor until before it sleeps, as 08 section 2 allows; the core does not yet.

### Randomness

The core needs a CSPRNG for its ephemeral X25519 keys and retry jitter. ESP-IDF's
RNG is only pseudo-random unless Wi-Fi or Bluetooth is running, which a battery
sensor does not do. So, in its constructor, before any component sets up the
ADC, the component takes a 32-byte seed from the SAR ADC noise source
(`bootloader_random_enable()`). Each request then hashes the seed, a counter and
fresh `esp_fill_random()` output with SHA-256, and the seed is ratcheted forward.
`rand()` is never used.

## Protocol core

This directory also holds `sensor_core`, a C++ library with no ESPHome
dependency, which the component wraps.

## Files

| File | Contents |
|---|---|
| `__init__.py`, `sensor.py`, `text_sensor.py` | YAML schema, validation and code generation |
| `cs_sensor.h/.cpp` | The ESPHome component: platform interfaces, readings, button, deep sleep |
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

The core never calls the platform directly; the ESPHome component supplies
(on ESP32):

| Interface | Provides | ESPHome component |
|---|---|---|
| `Clock` | Monotonic microseconds, and Unix time from the RTC (or "unknown") | `esp_timer_get_time()` plus the deep-sleep offset; `gettimeofday` / `settimeofday` |
| `Radio` | `transmit`, `start_receive`, `stop_receive`, `receiving` (a packet is arriving), and the frame airtime | `start_transmit_async` with a transmit listener, `set_mode_rx` / `set_mode_sleep`, `is_receiving()`, the LoRa airtime formula |
| `Storage` | Load, save and erase of five small blobs; `save` returns true only once the write is durable | ESPHome preferences in NVS, then `sync()` |
| `Random` | A CSPRNG; it makes the ephemeral X25519 keys | See "Randomness" |

The platform calls `begin()` once after boot (or `resume()` after a deep-sleep
wake), `loop()` often, `on_tx_done()` when
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

## Why `cs_sha256` and the region table are copied, not shared

Sharing it would need a third component, say `cs_common`, that both components
`AUTO_LOAD`. ESPHome's `external_components` only loads the components a
configuration lists when it has a `components:` list, and every proxy
configuration lists exactly `[cs_proxy]` (or `[cs_proxy, ssd1306_paced]`), so
moving the code would break every existing proxy configuration until its owner
adds `cs_common`. The copy differs only in its namespace. The region profiles in
`__init__.py` (`REGIONS`, `PENDING_REGIONS`) are copied the same way.
`make -C tests/sensor_core` fails if either copy drifts.

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

- nRF52 (#38): its clock, storage and sleep notes. The component is ESP32-only
  until then.
- Channel activity detection before transmitting (08 section 4.3, a SHOULD).
- X25519 cost on nRF52, not measured yet: TweetNaCl is small but among the
  slowest X25519 implementations, and pairing does two operations, one of them
  inside `on_receive`.
- User feedback on an LED (08 section 11). The events are logged; there is no
  automation trigger yet.
