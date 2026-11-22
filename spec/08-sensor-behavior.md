# 08 - Sensor Behavior

Status: Draft
Version: 1.0-draft.1

This document specifies how a sensor's firmware behaves: what it stores, how it
keeps time, when it transmits, how it retries, how it handles downlinks, and what
it does when it loses contact. It is independent of the hardware and firmware
platform. Frames are defined in 02, readings in 03 and pairing in 04.

## 1. Goals (informative)

- Important events (a door opening, a leak) reach the server within seconds, even
  if some frames are lost.
- Battery life measured in years.
- A sensor recovers on its own from lost clocks, lost proxies and server outages.

## 2. Stored state

| Item | Storage | Written when |
|---|---|---|
| `dev_eui`, `k_root` | Read-only, provisioned | Never by firmware |
| Uplink counter reservation | Non-volatile | 02 section 8.2 |
| Pairing state, `k_session`, `k_net_route` | Non-volatile | 04 section 4.6 |
| Root floor: last accepted root downlink counter | Non-volatile | On accepting `KEY_EXCHANGE`, before sending `SYNC` (04 section 4.6). Kept through `LEAVE` and re-pairing; cleared only by a factory reset (02 section 8.4) |
| Session floor: last accepted session `fcnt_down` | Non-volatile | On each accepted downlink, or at least before sleeping after one. Set to 0 with each new `k_session` |
| Heartbeat interval | Non-volatile | On `SET_HEARTBEAT` |
| Settings from application commands | Non-volatile | As the profile defines |
| Clock | RTC, kept through sleep | Section 3 |
| Ephemeral X25519 private key | RAM only | Never stored (04 section 4.6) |

A sensor SHOULD use the platform's read-out protection (for example APPROTECT on
nRF52, flash encryption on ESP32) so that `k_root` and `k_session` cannot be read
from a stolen device.

## 3. Clock

### 3.1 Requirements

- A paired sensor keeps Unix time with a real-time clock that runs during sleep.
  Its drift SHOULD be under 100 ppm (about 9 seconds per day).
- The clock is *valid* if it was set by an accepted downlink and has run without
  interruption since.
- `TIME_UNSURE` (02 section 9) MUST be set in every uplink until a downlink has
  been accepted since boot, even if the RTC survived the reboot.

### 3.2 Using the clock

- With a valid clock, or an RTC that survived the reboot, the sensor computes
  normal tags (02 section 6).
- Without either (for example after the batteries were removed and the RTC has no
  backup), the sensor cannot compute tags and MUST use `SYNC` (02 section 11.2)
  until a downlink sets its clock.
- On every accepted downlink the sensor sets its clock to `server_time`. It
  SHOULD NOT add an estimate of the transmission delay; the error is well under a
  second and tags only need the hour.

### 3.3 Staying in sync

A paired sensor MUST send at least one confirmed uplink every 24 hours. This
corrects drift, tells the sensor its link is working (section 6), and gives the
server a chance to deliver commands. The confirmed heartbeat (section 4.2)
normally covers it.

## 4. When to transmit

### 4.1 State changes

- Inputs MUST be debounced (the time is device-specific; for a reed switch,
  RECOMMENDED 50 ms).
- A sensor MAY gather changes that occur within 1 second into one frame.
- Changes that matter for safety or security MUST be sent as `DATA_CONFIRMED`
  (03 section 5); other changes MAY use `DATA`.
- A frame for a state change SHOULD carry the current value of every state
  reading, not just the one that changed, when they fit.
- A state reading whose first value since boot arrives after the boot uplink went
  out (a slow input, or one with no state yet) MUST be sent as a state change:
  the server has not seen it.

### 4.2 Heartbeats

- The interval `h` comes from the device profile, or from `SET_HEARTBEAT` once
  received. Allowed range: 1 to 1440 minutes.
- Each heartbeat is scheduled `h` after the previous one, with a random offset of
  up to plus or minus 10% so that sensors do not stay in step.
- A heartbeat carries the full state and battery (03 section 5).
- A heartbeat is sent as `HEARTBEAT_CONFIRMED` if no confirmed uplink has been
  answered in the last 4 hours (RECOMMENDED; at most 24 hours, section 3.3), and
  as `HEARTBEAT` otherwise.
- A sensor MAY skip a heartbeat if a frame carrying the full state was sent less
  than `h / 2` earlier.

### 4.3 Channel access

The radio profiles have no listen-before-talk requirement. A sensor SHOULD use
channel activity detection before transmitting: if the channel is busy, wait a
random 20 to 200 ms and try again, up to 3 times, then transmit anyway.

### 4.4 Airtime budget

A sensor MUST NOT exceed 1% transmit time in any rolling hour (01 section 5), or
the regulatory limit if lower. If a frame would exceed it, the sensor postpones
the frame until the budget allows, and replaces postponed state frames with one
frame carrying the latest state. In normal use the budget is far away: a
29-byte frame takes about 57 ms on US915, so 1% allows over 600 frames an hour.

## 5. Confirmed uplinks and retries

After a confirmed uplink, the sensor opens RX1 and, if RX1 brought nothing valid,
RX2 (01 section 4). If neither brings a downlink that it accepts (02 section 10.2),
the uplink is unanswered and the sensor retransmits it.

| Attempt | Sent at (after the end of the original transmission) |
|---|---|
| Original | 0 |
| Retry 1 | 4 s plus a random 0-2 s |
| Retry 2 | 12 s plus a random 0-4 s |
| Retry 3 | 30 s plus a random 0-10 s |

- A retry is the identical frame (02 section 8.3). Each retry is followed by RX1
  and RX2 as usual. Proxies forward it (06 section 6) and the server answers it
  again (07 section 4, step 5), so a lost answer is recovered by the next retry.
- If the state changes while retries are pending, the sensor abandons them and
  sends a new confirmed frame (new `fcnt`) with the latest state. The server
  only needs the latest state.
- After the last retry the uplink is *undelivered*. A state change will still
  reach the server in the next heartbeat, which carries the full state. A
  `button` event is lost.
- Unconfirmed uplinks are never retried.

## 6. Losing contact

The sensor counts *consecutive undelivered confirmed uplinks* (section 5). Any
accepted downlink resets the count to 0.

| Count | Behavior |
|---|---|
| 3 | The sensor's tags or clock may be wrong. The next confirmed attempt MUST be a `SYNC` instead (02 section 11.2), carrying the full state as readings. |
| 3 or more | Confirmed heartbeats are attempted at 1, 5, 15 and 60 minutes after the last failure, then every `h`. Normal state-change frames continue as usual. |

A sensor MUST NOT stop transmitting because it has lost contact, and MUST NOT
forget its pairing because of it. Only `LEAVE` or a factory reset (the
10-second button hold of 04 section 4.5) unpairs it (04 section 6).

## 7. Receiving downlinks

- Receive windows follow 01 section 4: RX1 after every uplink, RX2 after a
  confirmed uplink that RX1 did not answer.
- A received downlink is accepted only under 02 section 10.2. Anything else is
  discarded silently.
- On acceptance the sensor sets its clock (section 3.2), marks the uplink
  answered, and executes the commands in order (section 8). It MUST set `DL_ACK`
  in its next uplink if the downlink contained at least one command.
- If the downlink has `PENDING` set, the sensor SHOULD send a `HEARTBEAT` 2 to 4
  seconds later (random), so the server can deliver the next command. It MUST
  NOT do this more than 4 times in a row.

## 8. Commands

| Command | Sensor behavior |
|---|---|
| `SET_NETWORK` | Store `k_net_route`, switch to normal tags, enter `PAIRED` if pairing (04) |
| `SET_HEARTBEAT` | Store the new interval; reschedule the next heartbeat from now |
| `LEAVE` | Erase `k_session` and `k_net_route`, enter `UNPAIRED` (04 section 6.1). Keep the root floor and the uplink counter reservation. When `PAIRED`, the `DL_ACK` for it goes in one final unconfirmed `HEARTBEAT`, sent under the old keys before they are erased; in `SESSION`, nothing is sent (04 section 6.1). |
| `KEY_EXCHANGE` | Only valid in `JOINING` (04 section 4.4), in a downlink under the root key set whose counter is above the root floor; ignored otherwise |
| `0x40` (set value) | Apply to a writable channel (03 section 8), then report the new state in the next uplink |
| `0x41`-`0x7F` | As the device profile defines |
| Unknown | Skip, using the length byte (02 section 10.3) |

Commands are idempotent, so a repeated one is applied again without harm.

## 9. Boot

1. Load stored state. Reserve a new block of uplink counters (02 section 8.2).
2. If `UNPAIRED`: wait for the pairing button (04 section 4.5). After the very
   first power-on the sensor MAY send one `JOIN`.
3. If `PAIRED`:
   - with a clock from a surviving RTC: send a `HEARTBEAT_CONFIRMED` with the
     full state, battery and `firmware_version`, with `TIME_UNSURE` set;
   - without one: send `SYNC` with the same readings.
4. Continue normally once that confirmed uplink is answered, or after its
   retries (section 5) and the contact-loss rules (section 6).

A wake from sleep is not a boot if the sensor kept its working state through the
sleep (in retained RAM, or a snapshot of it) along with a monotonic clock and its
RTC. Such a sensor goes on using the counter block it had reserved, keeps its
heartbeat schedule and the validity of its clock (section 3.1), and sends no boot
uplink. This is safe because the stored reservation is always ahead of every
counter used. A wake that lost any of these is a boot.

## 10. Power (informative)

### 10.1 Design notes

- Sleep with the radio in its sleep mode and the RTC running; only the RTC and
  input interrupts wake the MCU.
- RX1 costs about 170 ms of receiver time after every uplink. That is the price
  of being able to receive commands without confirmed uplinks.
- Measure the battery under load (just after a transmission) for an honest
  reading.
- Transmit power: use the profile's maximum only if needed; sensors close to a
  proxy can save a great deal at lower power. Adaptive power control is left
  to a later version.

### 10.2 Example budget

A contact sensor on US915 at +20 dBm, with a 30-minute heartbeat, 10 door events a
day (confirmed), and 6 confirmed heartbeats a day:

| Item | Assumption | Per day |
|---|---|---|
| Transmit | 58 frames of 29 bytes (57 ms) at 110 mA | 361 mAs |
| RX1 windows | 58 x 170 ms at 6 mA | 59 mAs |
| Receiving downlinks | 16 x 62 ms at 6 mA | 6 mAs |
| MCU awake | 58 x 50 ms at 8 mA | 23 mAs |
| Sleep | 4 uA | 346 mAs |
| Total | | about 0.22 mAh |

That is about 80 mAh a year. Two AA cells or one CR123A last many years, limited
mainly by the cells' shelf life. A CR2032 coin cell cannot supply 110 mA pulses
and is only suitable at much lower transmit power.

## 11. User feedback (informative)

Devices with an LED SHOULD show:

| Situation | Pattern |
|---|---|
| Pairing in progress | Slow blink |
| Paired successfully | 3 quick blinks |
| Pairing failed | One long blink |
| Button press while paired, uplink answered | One quick blink |
| Button press while paired, no answer | Two long blinks |
| Factory reset done (button held 10 seconds, 04 section 4.5) | Solid for 2 seconds |

Feedback for a button press waits for the answer to the confirmed uplink, so it
doubles as a range test.

## 12. Firmware updates

Over-the-air firmware updates over LoRa are out of scope for v1. Sensors are
updated over USB, Bluetooth or another local interface, as the device allows. An
update MUST preserve all of section 2's stored state.

## 13. Conformance tests

A sensor implementation MUST pass at least:

1. Its frames decode with the reference tool using its pairing code and the
   server's keys, and match the formats in 02 and 03.
2. After a power cycle, its first uplink counter is greater than every counter it
   used before (02 section 8.2), including after a factory reset.
3. With no server answering, a confirmed uplink is sent 4 times in total at the
   times in section 5, as identical bytes.
4. After 3 undelivered confirmed uplinks, the next confirmed attempt is `SYNC`.
5. A downlink with a wrong `reply_to`, a stale `fcnt_down`, or a bad MIC is
   ignored.
6. `SET_HEARTBEAT` changes the heartbeat interval, and `LEAVE` unpairs the
   device without erasing `k_root`, the counter reservation or the root floor.
7. It never exceeds 1% airtime per hour, even with an input toggling
   continuously.
8. It reproduces the `root_floor` sequence of `vectors/pairing-v1.json`: after
   pairing, `LEAVE` and a power cycle, a `KEY_EXCHANGE` whose root counter is at
   or below the last accepted one is ignored, and a higher one is accepted.
9. Holding the button for 10 seconds factory-resets it in every pairing state:
   it erases `k_session`, `k_net_route`, both downlink floors and settings, keeps
   `k_root` and the uplink counter reservation, and then accepts a
   `KEY_EXCHANGE` with root counter 1.
10. A state reading that has no value when the boot uplink goes out is sent in a
    state-change frame when its first value arrives, confirmed if the reading's
    changes are confirmed.
11. In `SESSION` (04 section 4.3), it returns to `UNPAIRED` with the root floor
    kept when a `SYNC` goes unanswered after its retries, after 4 `SYNC`s
    answered without `SET_NETWORK`, on `LEAVE` (sending nothing), and after a
    restart. A short press in `JOINING` or `SESSION` sends nothing.
