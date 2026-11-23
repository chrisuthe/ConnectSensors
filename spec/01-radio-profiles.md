# 01 - Radio Profiles

Status: Draft
Version: 1.0-draft.2

A radio profile fixes every physical-layer parameter for a region. All sensors and
proxies in an area using the same profile can hear each other. A network uses
exactly one profile.

## 1. Design constraints (informative)

- Proxies are single-channel receivers built on ESPHome's `sx126x` and `sx127x`
  components, which listen on one frequency at one spreading factor. Profiles
  therefore use one channel and one spreading factor for both uplink and
  downlink.
- Uplinks and downlinks use normal (non-inverted) IQ, because the ESPHome
  components do not expose IQ inversion. Direction is carried in the frame type
  instead (02, section 4).
- Channels are chosen away from other common LoRa networks.

## 2. Common parameters

These apply to every profile.

| Parameter | Value |
|---|---|
| Modulation | LoRa |
| Header | Explicit |
| Payload CRC | On |
| Coding rate | 4/5 |
| Preamble | 8 symbols |
| Sync word | Private, `0x12` (SX127x register value) = `0x1424` (SX126x register value) |
| IQ | Normal, both directions |
| Low data rate optimization | As required by the chip for the profile's symbol time (off for all current profiles) |
| Maximum frame length | 86 bytes (02, section 3) |

The private sync word is shared with many other private LoRa networks. Receivers
MUST NOT rely on it for filtering; the frame magic byte (02) does that.

ESPHome example for the radio portion (US915):

```yaml
sx126x:
  modulation: LORA
  frequency: 918.5MHz
  bandwidth: 500_0kHz
  spreading_factor: 9
  coding_rate: CR_4_5
  preamble_size: 8
  sync_value: [0x14, 0x24]
  crc_enable: true
```

## 3. Profiles

### 3.1 `US915` (primary)

| Parameter | Value |
|---|---|
| Center frequency | 918.5 MHz (provisional, see 3.1.1) |
| Bandwidth | 500 kHz |
| Spreading factor | 9 |
| Symbol time | 1.024 ms |
| Max conducted power | +20 dBm (SX1262 limit +22 dBm) |
| Duty cycle | No regulatory limit; fairness limits in section 5 apply |

#### 3.1.1 Channel choice (informative)

918.5 MHz with 500 kHz bandwidth occupies 918.25-918.75 MHz. This sits in the gap
between LoRaWAN US915 uplink channels (902.3-914.9 MHz) and downlink channels
(923.3-927.5 MHz), away from the Z-Wave US frequencies (908.4 and 916 MHz) and
Z-Wave Long Range channels (912 and 920 MHz), and away from Meshtastic's default
US slot. The value stays provisional until a field survey confirms the band is
quiet in typical homes.

#### 3.1.2 Regulatory notes (informative, not legal advice)

- The intent is to operate under FCC 47 CFR 15.247 as a digital transmission
  system. That requires a 6 dB bandwidth of at least 500 kHz
  (15.247(a)(2)) and a power spectral density of at most 8 dBm in any 3 kHz
  (15.247(e)). A fixed channel without hopping is then permitted.
- Whether a specific radio and module meets the 500 kHz 6 dB bandwidth
  requirement in LoRa 500 kHz mode, and under which module grant, MUST be
  verified before a product claims compliance. If it does not, the profile must
  move to a hopping channel plan, which single-channel proxies cannot follow.
- Antennas with more than 6 dBi gain reduce the permitted conducted power
  (15.247(b)(4)).

### 3.2 `EU868` (provisional)

| Parameter | Value |
|---|---|
| Center frequency | TBD (candidate 865.2 MHz) |
| Bandwidth | 125 kHz |
| Spreading factor | 9 |
| Symbol time | 4.096 ms |
| Max power | Per the sub-band chosen |
| Duty cycle | Per the sub-band chosen; also section 5 |

The frequency is open. Constraints for choosing it:

- Avoid 869.525 MHz: it is the LoRaWAN EU868 RX2 channel and the Meshtastic EU
  default.
- Avoid 868.1, 868.3 and 868.5 MHz (LoRaWAN default channels) and 867.1-867.9 MHz
  (common LoRaWAN extra channels).
- Avoid the high-power RFID channels at 865.7, 866.3, 866.9 and 867.5 MHz.
- Confirm the power and duty-cycle limits of the chosen sub-band against
  ERC/REC 70-03 and ETSI EN 300 220 before the profile leaves Draft.

The profile is untested and MUST NOT be presented to users as ready.

### 3.3 Reserved profile names

`AU915`, `AS923`, `IN865`, `KR920` are reserved for future profiles.

## 4. Receive windows

After a sensor finishes transmitting an uplink, it opens up to two receive windows
on the same channel and spreading factor:

| Window | Delay after end of uplink | Use |
|---|---|---|
| RX1 | 1.000 s | Downlinks from a proxy that heard the uplink directly on the LAN path |
| RX2 | 3.000 s | Downlinks that took longer, for example through a mailbox server (09) |

Each profile sets how long after `delay` the sensor's receiver stays open (`W`).
Section 4.1 derives it.

| Profile | `W` |
|---|---|
| `US915` | 150 ms |
| `EU868` | 200 ms |

Sensor requirements:

- The sensor MUST have its receiver running from `delay - 20 ms` until at least
  `delay + W`. If a preamble is detected in that time, the sensor MUST keep
  receiving until the frame completes or fails.
- A sensor MUST open RX1 after every uplink.
- A sensor MUST open RX2 after a confirmed uplink (02, section 4) when RX1 did not
  deliver a valid downlink. It MAY skip RX2 after an unconfirmed uplink.
- Delay is measured from the sensor's TX-done event.

Proxy requirements:

- A proxy transmitting a downlink MUST start transmission no earlier than `delay`
  and no later than `delay + 40 ms` after the end of the uplink being answered.
- The proxy measures the end of the uplink from its RX-done event. A proxy that
  can only timestamp a packet later than the RX-done event (for example, from a
  main-loop callback) MUST either compensate for that latency or flag every
  reception whose timestamp may be more than 36 ms late (`TS_UNCERTAIN`, 05
  section 5.1). Otherwise it MUST NOT offer downlinks.
- A proxy that cannot meet a window MUST drop the downlink rather than transmit
  late.

### 4.1 Timing budget

A downlink is received only if the sensor detects it before its window closes.
For every profile, the latest detection MUST fall inside `W`:

timestamp error + transmit start tolerance + radio start + detection ≤ `W`

All values are milliseconds after `delay`.

| Term | Source | `US915` | `EU868` |
|---|---|---|---|
| Timestamp error, unflagged | 06 section 7: at most 16 ms loop interval + 20 ms | 36 | 36 |
| Transmit start window | Proxy requirements above; 06 section 8.2 | 40 | 40 |
| Radio start: frame load, transmit command and ramp-up to the first preamble symbol | Allowance; about 1.8 ms measured to the command (05 section 5.5) | 5 | 5 |
| Detection: 8 preamble symbols, 4.25 sync symbols, 8 header symbols (20.25 symbols) | Section 2, symbol time from section 3 | 20.7 | 82.9 |
| Latest detection | Sum | 101.7 | 163.9 |
| Sensor receive window `W` | Above | 150 | 200 |
| Margin | | 48.3 | 36.1 |

Notes (informative):

- Detection is counted to the valid header, because that is when the ESPHome
  `sx126x` component reports a reception in progress. SX127x radios report a
  signal a few preamble symbols in, so they have more margin.
- On the early side, a downlink never starts before `delay`: the proxy's timestamp
  is never early and it does not transmit before `tx_at` (06 section 8.2). The
  sensor's 20 ms lead covers its own TX-done and receiver-start latency.
- Crystal drift over 3 s (at most 40 ppm, 0.12 ms) is negligible.
- `US915` keeps the 150 ms that sensors already use; the margin covers on-air
  offsets that have not been measured yet. `EU868` needs a longer window because
  its 4.096 ms symbols make detection four times slower; tightening the proxy
  further could not cover that without leaving no room for a retry after a
  `BUSY` radio (06 section 8.2). At 6 mA, the extra 50 ms costs about 0.3 mAs per
  uplink, small next to `EU868`'s transmit cost.
- A downlink answering a `TS_UNCERTAIN` reception (RX2 fallback only, 07 section
  6.3) is outside this budget and best effort.

## 5. Airtime and fairness limits

These limits apply in every profile, in addition to regulation.

| Role | Limit |
|---|---|
| Sensor | At most 36 s of transmit time in any rolling hour (1%) |
| Proxy (downlinks) | At most 72 s of transmit time in any rolling hour (2%) |

Where regulation is stricter, regulation wins.

### 5.1 Reference airtimes (informative)

Computed with the Semtech time-on-air formula, explicit header, CRC on, CR 4/5,
8-symbol preamble.

| Frame length | US915 (SF9, 500 kHz) | EU868 (SF9, 125 kHz) |
|---|---|---|
| 23 bytes (smallest uplink) | 51.5 ms | 205.8 ms |
| 31 bytes (plain acknowledgement) | 61.7 ms | 246.8 ms |
| 55 bytes (`JOIN`) | 87.3 ms | 349.2 ms |
| 65 bytes (`KEY_EXCHANGE` downlink) | 97.5 ms | 390.1 ms |
| 86 bytes (maximum) | 123.1 ms | 492.5 ms |

`tools/csframe.py airtime` prints this table.
