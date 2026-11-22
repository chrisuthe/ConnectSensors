# 03 - Payload v1

Status: Draft
Version: 1.0-draft.1

This document defines how sensor readings are encoded inside uplink payloads
(after the `uflags` byte, 02 section 9), the generic actuator command, and device
profiles, which tell a server how to present a device's readings.

## 1. Goals (informative)

- Compact: a contact sensor's state is 3 bytes.
- Self-delimiting: a receiver can skip any reading it does not understand, so new
  reading kinds never break old servers.
- Useful without a profile: every kind has a default meaning, unit and Home
  Assistant mapping.

## 2. Reading encoding

A payload's readings are a sequence of readings with no separator and no count:

```
reading = channel (uint8) | kind (uint8) | value
```

The size of `value` follows from the top two bits of `kind`:

| `kind` range | Size class | `value` |
|---|---|---|
| `0x00`-`0x3F` | 0 | 1 byte |
| `0x40`-`0x7F` | 1 | 2 bytes |
| `0x80`-`0xBF` | 2 | 4 bytes |
| `0xC0`-`0xFF` | 3 | `len` (uint8) followed by `len` bytes, `len` <= 60 |

- `kind` `0x00` is reserved and MUST NOT be sent. A receiver that meets it MUST
  discard the rest of the payload.
- `channel` identifies a sensing element on the device (for example, the second
  of two temperature probes). Channels `0x00`-`0xFE` are defined by the device's
  profile. Channel `0xFF` is the device itself and carries diagnostics: battery,
  firmware version, uptime.
- A payload MUST NOT contain the same `(channel, kind)` pair twice.
- A truncated reading (the payload ends inside one) makes the whole payload
  invalid. A server MUST NOT apply any reading from an invalid payload.

## 3. Unknown kinds

A receiver MUST skip a reading whose `kind` it does not know, using the size
class, and continue with the next reading. It SHOULD record that an unknown
kind was seen, for diagnostics.

## 4. Reading kinds

Values are integers in network byte order unless stated. "Unknown" is the value a
sensor sends when it has a channel but no valid measurement (sensor fault,
warming up).

### 4.1 Size class 0 (1 byte)

| Kind | Name | Type | Meaning | Unknown |
|---|---|---|---|---|
| `0x01` | `contact` | uint8 | 0 closed, 1 open | `0xFF` |
| `0x02` | `motion` | uint8 | 0 clear, 1 detected | `0xFF` |
| `0x03` | `leak` | uint8 | 0 dry, 1 wet | `0xFF` |
| `0x04` | `tamper` | uint8 | 0 normal, 1 tampered | `0xFF` |
| `0x05` | `vibration` | uint8 | 0 none, 1 detected | `0xFF` |
| `0x06` | `binary` | uint8 | Generic on/off, 0 or 1 | `0xFF` |
| `0x07` | `battery_percent` | uint8 | 0-100 % | `0xFF` |
| `0x08` | `button` | uint8 | Event: 1 press, 2 double press, 3 long press, 4 release | - |
| `0x09` | `enum` | uint8 | Generic enumeration; labels from the profile | `0xFF` |
| `0x0A` | `percent` | uint8 | Generic 0-100 % | `0xFF` |

### 4.2 Size class 1 (2 bytes)

| Kind | Name | Type | Unit and scale | Unknown |
|---|---|---|---|---|
| `0x40` | `temperature` | int16 | 0.01 degrees Celsius | `0x8000` |
| `0x41` | `humidity` | uint16 | 0.01 % relative humidity | `0xFFFF` |
| `0x42` | `battery_voltage` | uint16 | millivolts | `0xFFFF` |
| `0x43` | `illuminance` | uint16 | lux | `0xFFFF` |
| `0x44` | `distance` | uint16 | millimetres | `0xFFFF` |
| `0x45` | `pressure` | uint16 | 0.1 hPa | `0xFFFF` |
| `0x46` | `co2` | uint16 | ppm | `0xFFFF` |
| `0x47` | `moisture` | uint16 | 0.01 % (soil or material) | `0xFFFF` |
| `0x48` | `voltage` | uint16 | millivolts (generic) | `0xFFFF` |
| `0x49` | `counter16` | uint16 | Count, wraps at 65536 | - |
| `0x4A` | `int16` | int16 | Generic; scale from the profile | `0x8000` |

### 4.3 Size class 2 (4 bytes)

| Kind | Name | Type | Unit and scale | Unknown |
|---|---|---|---|---|
| `0x80` | `counter32` | uint32 | Count, wraps at 2^32 | - |
| `0x81` | `energy` | uint32 | watt-hours, cumulative | `0xFFFFFFFF` |
| `0x82` | `water` | uint32 | millilitres, cumulative | `0xFFFFFFFF` |
| `0x83` | `uptime` | uint32 | seconds since boot | - |
| `0x84` | `float32` | IEEE 754 binary32, big-endian | Generic; unit from the profile | NaN |
| `0x85` | `int32` | int32 | Generic; scale from the profile | `0x80000000` |

### 4.4 Size class 3 (variable)

| Kind | Name | Content |
|---|---|---|
| `0xC0` | `raw` | Opaque bytes, interpreted by the profile |
| `0xC1` | `text` | UTF-8 text |
| `0xC2` | `firmware_version` | `len = 3`: major, minor, patch as uint8 |

All other kinds are unassigned. New kinds are assigned by revising this table;
experimental use SHOULD use `0x3F`, `0x7F`, `0xBF` or `0xFF`, which will never be
assigned.

## 5. What sensors send

- Every `HEARTBEAT` and `HEARTBEAT_CONFIRMED` MUST include the current value of
  every state reading the device has (contact, leak, temperature, and so on), so
  a server recovers the full state from any one heartbeat.
- Every heartbeat MUST include `battery_percent` or `battery_voltage` on channel
  `0xFF`, unless the device is mains powered.
- A sensor SHOULD include `firmware_version` on channel `0xFF` in the first
  heartbeat after boot.
- State changes that matter for safety or security (contact, leak, motion,
  tamper) SHOULD be sent as `DATA_CONFIRMED`.
- `button` is an event, not a state. It MUST NOT appear in heartbeats. Because a
  retransmitted frame is identical (02 section 8.3), the server's counter rules
  stop a retried button press from firing twice.

## 6. Server handling of values

- Scaled integers are converted to real units by the server, for example
  `temperature` 2153 is 21.53 degrees Celsius.
- An unknown value sets the entity to unknown (in Home Assistant terms,
  `unknown`), not to a number.
- Counters (`counter16`, `counter32`) are unwrapped into a running total. When a
  new value is lower than the previous one, the server treats it as a wrap if the
  previous value was in the top quarter of the range, and otherwise as a device
  reset that started the counter again from zero.
- Cumulative kinds (`energy`, `water`) that go down are treated as a device reset.

## 7. Default Home Assistant mapping

Used when a device's profile does not override a channel (section 9).

| Kind | Platform | Device class | Unit | Notes |
|---|---|---|---|---|
| `contact` | `binary_sensor` | `opening` | - | |
| `motion` | `binary_sensor` | `motion` | - | |
| `leak` | `binary_sensor` | `moisture` | - | |
| `tamper` | `binary_sensor` | `tamper` | - | Diagnostic |
| `vibration` | `binary_sensor` | `vibration` | - | |
| `binary` | `binary_sensor` | none | - | |
| `battery_percent` | `sensor` | `battery` | % | Diagnostic |
| `button` | `event` | `button` | - | Event types `press`, `double_press`, `long_press`, `release` |
| `enum` | `sensor` | `enum` | - | Options from the profile |
| `percent` | `sensor` | none | % | |
| `temperature` | `sensor` | `temperature` | Celsius | State class measurement |
| `humidity` | `sensor` | `humidity` | % | Measurement |
| `battery_voltage` | `sensor` | `voltage` | mV | Diagnostic |
| `illuminance` | `sensor` | `illuminance` | lx | Measurement |
| `distance` | `sensor` | `distance` | mm | Measurement |
| `pressure` | `sensor` | `atmospheric_pressure` | hPa | Measurement |
| `co2` | `sensor` | `carbon_dioxide` | ppm | Measurement |
| `moisture` | `sensor` | `moisture` | % | Measurement |
| `voltage` | `sensor` | `voltage` | mV | Measurement |
| `counter16`, `counter32` | `sensor` | none | - | Total increasing (after unwrapping) |
| `energy` | `sensor` | `energy` | Wh | Total increasing |
| `water` | `sensor` | `water` | L | Converted from mL; total increasing |
| `uptime` | `sensor` | `duration` | s | Diagnostic |
| `float32`, `int16`, `int32` | `sensor` | none | from profile | |
| `raw`, `text` | none | - | - | Not shown unless a profile says how |
| `firmware_version` | device info | - | - | Shown as the device's software version |

This table is informative for servers other than Home Assistant.

## 8. Actuator command

Application command `0x40` (02 section 10.3) sets a value on a device that has
outputs (a relay, a valve, an LED):

```
cmd_id = 0x40 | len | channel (uint8) | kind (uint8) | value
```

`value` uses the reading encoding for `kind` (section 2). The device MUST apply
it and SHOULD report the resulting state in its next uplink. Devices that accept
`0x40` MUST list the writable channels in their profile. Commands `0x41`-`0x7F`
are defined by individual profiles.

## 9. Device profiles

A profile describes one device model. Its identifier appears in the pairing code
(04), so the server knows what it is pairing before the first frame arrives.

### 9.1 Profile identifier

1 to 32 characters from `A`-`Z`, `0`-`9`, `.` and `-`, for example
`CS.CONTACT-1`. Identifiers starting with `CS.` are reserved for profiles
published with this specification. Others SHOULD start with a prefix identifying
the publisher.

### 9.2 Profile document

A JSON document:

```json
{
  "profile": "CS.CONTACT-1",
  "name": "ConnectSensors contact sensor",
  "manufacturer": "ConnectSensors reference design",
  "model": "Contact v1",
  "power": "battery",
  "heartbeat_minutes": 30,
  "channels": [
    { "channel": 0, "kind": "contact", "name": "Door" },
    { "channel": 0, "kind": "tamper", "name": "Tamper" },
    { "channel": 255, "kind": "battery_percent" }
  ],
  "commands": []
}
```

This specification publishes two profiles: `CS.CONTACT-1` above, and
`CS.CLIMATE-1` for a temperature and humidity sensor:

```json
{
  "profile": "CS.CLIMATE-1",
  "name": "ConnectSensors climate sensor",
  "manufacturer": "ConnectSensors reference design",
  "model": "Climate v1",
  "power": "battery",
  "heartbeat_minutes": 30,
  "channels": [
    { "channel": 0, "kind": "temperature" },
    { "channel": 0, "kind": "humidity" },
    { "channel": 255, "kind": "battery_percent" }
  ],
  "commands": []
}
```

A climate sensor reports changes as they happen (08 section 4.1), so its
heartbeat only supervises it and refreshes a steady state, as for a contact
sensor.

Fields:

| Field | Required | Meaning |
|---|---|---|
| `profile` | yes | Identifier (9.1) |
| `name`, `manufacturer`, `model` | yes | Shown to the user |
| `power` | yes | `battery` or `mains` |
| `heartbeat_minutes` | yes | Default heartbeat interval; supervision uses it (07) |
| `channels` | yes | One entry per `(channel, kind)` the device sends |
| `channels[].name` | no | Entity name; defaults to the kind's name |
| `channels[].device_class`, `unit`, `scale` | no | Override section 7, for generic kinds |
| `channels[].options` | for `enum` | Labels for values 0, 1, 2 and so on |
| `channels[].writable` | no | `true` if the channel accepts command `0x40` |
| `commands` | no | Profile-defined commands `0x41`-`0x7F`: `id`, `name`, argument layout |

Kinds are written by name in profiles, as in section 4.

### 9.3 Missing profiles

A server that does not have a device's profile MUST still accept the device and
MUST create entities from section 7 for each `(channel, kind)` it sees. How
profiles are published and shared is defined in 10 (Control plane).

## 10. Test vectors

`vectors/payload-v1.json` has encoded reading lists with their decoded values,
including a negative temperature, an unknown value, diagnostics on channel
`0xFF`, a variable-length reading, an unassigned kind that the decoder skips, and
one kind on two channels. Its `invalid` payloads break section 2: truncated in a
reading header, a length byte or a value, kind `0x00`, and a repeated
`(channel, kind)`, also for an unassigned kind. A server applies no reading from
any of them.
For example, temperature 21.53 C and humidity 45.20 % on channel 0:

```
00 40 0869  00 41 11a8
```
