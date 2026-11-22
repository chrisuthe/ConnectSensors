# 07 - Network Server

Status: Draft
Version: 1.0-draft.3

This document specifies what a network server does: the state it keeps, how it
processes uplinks, how it answers them, how it picks which proxy transmits, how
it supervises devices and proxies, and how it presents all of this in Home
Assistant. Frames are defined in 02, readings in 03, pairing in 04 and proxy
messages in 05.

The reference server is the Home Assistant integration `connect_sensors`.
Sections 1-10 apply to any server. Section 11 is specific to Home Assistant.

## 1. Goals (informative)

- Every valid frame is acted on once, however many proxies heard it.
- Confirmed uplinks are answered in RX1 whenever any good proxy heard them.
- A device that goes quiet is reported as a problem, never as "closed" or "dry".
- The server survives restarts without accepting replayed frames or losing
  commands.

## 2. State

### 2.1 Per network

| Item | Notes |
|---|---|
| `k_net`, `k_net_route` | 02 section 5.2. During a key rotation, also the previous pair (04 section 7). |
| Region profile | 01 |
| Tag table | Section 3 |

A server MAY run several networks; each has its own keys. Most homes have one.

### 2.2 Per device

| Item | Persisted | Notes |
|---|---|---|
| `dev_eui`, `k_root`, profile identifier | yes | From the pairing code |
| Pairing state | yes | 04 section 4.2 |
| `k_session` and the derived key set | yes | |
| `last_fcnt` and the late-arrival record | yes (section 10) | 02 section 8.5 |
| Root downlink counter reservation | yes | 02 section 8.4. Never reset. Kept, keyed by `dev_eui`, after the device is removed or discarded |
| Pending exchange | yes | 04 section 4.2: `sensor_pub`, the `KEY_EXCHANGE` frame, `k_session`, and the retransmission count of section 5.1 |
| Session `fcnt_down` reservation | yes | 02 section 8.4. Starts at 1 for each new `k_session` |
| Heartbeat interval | yes | From the profile or the last `SET_HEARTBEAT` |
| Command queue and the commands awaiting acknowledgement | yes | Section 7 |
| Last uplink time, last confirmed-uplink time | yes | Supervision, section 8 |
| Reception history | no | Section 9 |
| Current reading values and counter totals | yes | 03 section 6 |

### 2.3 Per proxy

| Item | Persisted | Notes |
|---|---|---|
| `proxy_id`, `proxy_key` | yes | 05 section 4 |
| Whether the key is shared | yes | 05 section 4.2. A proxy on a shared key never gets downlinks (section 6.1). |
| Last address and port | no | 05 section 2.1 |
| Current `boot_id`, last received `seq`, server `seq` | no | 05 section 3.2. After a restart they are rebuilt by `HELLO_REQUEST`. |
| Outstanding `HELLO_REQUEST` nonces, per `boot_id` | no | 05 section 3.2 |
| Capabilities and radio settings from the last `HELLO` | no | |
| Timing record: the last 20 `TX_RESULT`s | no | Section 6 |
| Last `HELLO` time | no | Section 8.2 |

## 3. Tag table

- The server keeps a table from `(net_tag, dev_tag)` to devices, for epochs
  `e - 1`, `e` and `e + 1` of every paired device on every network (02 section
  6.3), including the previous network key during a rotation.
- At each epoch boundary the server drops epoch `e - 2`, adds `e + 2` (the new
  `e + 1`), and sends `SERVER_STATUS` with `hello_seq` 0 to every connected
  proxy within 10 seconds (05 section 5.3).
- If the system clock jumps by more than 60 seconds, the server rebuilds the whole
  table.
- The server's clock MUST be synchronized to UTC (for example by NTP). A server
  whose clock is not synchronized SHOULD warn the user, because sensors take
  their time from it.

## 4. Uplink processing

For each `UPLINK` message:

1. **Envelope.** Verify it (05 section 3). Discard on failure. An `UPLINK` from
   a boot that is not the proxy's current one is discarded too, after answering
   it with `HELLO_REQUEST` (05 section 3.2); the frame is usually also heard by
   other proxies or retransmitted by the sensor.
2. **Header.** Apply the keyless checks of 02 section 12. Discard downlink types.
3. **Collect.** Compute the dedupe key (the first 8 bytes of SHA-256 over the
   frame) and the copy's reception time (section 4.3). If the same frame has an
   entry whose first copy was received within 2 seconds of this one (before or
   after it), the copy is part of that transmission: add this proxy's reception
   (proxy, `rx_time_us`, RSSI, SNR, flags) to the entry's reception list and
   stop.
   Otherwise this is a new transmission, either a first copy or a sensor's
   retransmission (02 section 8.3): start a new entry and wait for the
   collection window (section 4.1) before step 8.
4. **Identify.** Find the device:
   - normal tags: look up `(net_tag, dev_tag)` in the tag table and try each
     candidate's session key set until a MIC verifies (02 section 6.4);
   - `JOIN`: try the root key set of each `SCANNED` or `EXCHANGED` device;
   - `SYNC`: try the session key set of each `EXCHANGED` or `PAIRED` device.

   Bootstrap frames are limited to 50 per minute per server (02 section 11.3);
   beyond that they are dropped unprocessed. A frame no device verifies is
   counted as foreign and dropped.
5. **Counter.** Apply 02 section 8.5. A `too_old` frame is dropped. A
   `duplicate` is not acted on again (steps 6 and 7 are skipped), but if it is a
   confirmed type the server answers it again (section 5) so the sensor stops
   retrying. To bound what a replayed frame can cost, the server answers a
   duplicate only if the frame's first transmission was received less than 60
   seconds ago, and sends at most 3 such answers per frame, one per sensor retry
   (08 section 5). A duplicate it cannot answer in time (for example a federated
   copy past the 09 section 6.3 deadline) does not count toward the 3.
6. **Payload.** Decrypt, read `uflags`, decode the readings (03). If the readings
   are invalid (03 section 2), keep the frame for counter and supervision
   purposes, apply no readings, and log a device error.
7. **Act.**
   - `DL_ACK`: mark the commands awaiting acknowledgement as delivered, but only
     if the frame's `fcnt` is greater than their downlink's `reply_to` (section
     7). A late arrival can carry `DL_ACK` for an earlier downlink.
   - Readings: update states, unwrap counters, fire `button` events.
   - `JOIN`, `SYNC`: advance the pairing state machine (04) as applicable. A
     `JOIN` is answered as in section 5.1.
   - Record the uplink time for supervision.
   - Note clock skew: if the frame's tags matched epoch `e - 1` or `e + 1` rather
     than `e`, and the frame arrived more than 5 minutes from an epoch boundary,
     the sensor's clock is off.
8. **Answer.** After the collection window, decide whether to send a downlink
   (section 5) and through which proxy (section 6).

### 4.1 Collection window

The server waits 150 ms after the first copy of a transmission arrives, so that
copies from other proxies can be compared before choosing one to answer through.
Copies of the same transmission that arrive later (step 3) are still recorded in
the reception history.

### 4.2 Latency budget (informative)

| Step | Typical |
|---|---|
| Proxy timestamp to server | 5-50 ms |
| Collection window | 150 ms |
| Identification, decryption, decision | under 20 ms |
| `DOWNLINK` to proxy | 5-50 ms |
| Margin before RX1 | over 700 ms |

A `DOWNLINK` for RX1 MUST be sent no later than 800 ms after the first copy of the
uplink arrived. Later than that, the server uses RX2 if the uplink is confirmed,
and otherwise does not answer it (section 6.3).

### 4.3 Reception time

Step 3 compares the times at which copies were received over the air, not when
they reached the server:

- A copy from a proxy counts as received when its `UPLINK` arrived.
- A federated copy (09 section 6.1) counts as received `age_ms` before its event
  arrived. That takes out the publisher's collection window, the bulk of a
  neighbor's delay, so a neighbor's copy of the original is not mistaken for a
  retransmission.

Neither estimate removes network or relay transit time. A copy delayed by more
than about 1.8 seconds in transit is taken for a retransmission; the cost is a
redundant downlink sent while the sensor is not listening, and one of the 3
answers of section 4, step 5.

The server remembers each frame for 60 seconds after the first copy of its first
transmission, which covers the whole retry schedule (08 section 5): when the
current transmission's first copy was received (step 3) and how many times the
frame was answered again (step 5). A frame it no longer remembers is not answered
again. Copies of one transmission arrive within a few hundred milliseconds of
each other, while a retransmission comes at least 4 seconds after the original,
so the 2-second limit separates them with a margin on both sides.

`spec/vectors/server-v1.json` (`retransmission`) has a worked sequence.

## 5. When and what to answer

The server sends a downlink in reply to an uplink when any of these hold:

- the uplink is a confirmed type (`DATA_CONFIRMED`, `HEARTBEAT_CONFIRMED`,
  `JOIN`, `SYNC`), including a retransmitted duplicate of one within the limits
  of section 4, step 5;
- the device has undelivered commands (section 7) and the uplink is not a late
  arrival;
- the device's clock needs correcting: `TIME_UNSURE` is set, or step 4.7 found
  skew.

It does not answer unconfirmed uplinks otherwise. Sensors open RX1 after every
uplink (01 section 4), so commands and clock corrections can ride on any uplink,
in RX1; only confirmed uplinks get RX2 (section 6.3).

The downlink:

| Field | Value |
|---|---|
| Type | `DOWNLINK` |
| `net_tag`, `dev_tag` | The same as the uplink it answers |
| `fcnt` | The next value of the key set's downlink counter: root or session (02 section 8.4) |
| Key set | Root for an answer to `JOIN`, session otherwise |
| `reply_to` | The uplink's `fcnt` |
| `server_time` | Current Unix time, taken when the downlink is built |
| `PENDING` | Set if commands remain queued after this downlink |
| Commands | As many queued commands as fit in 55 bytes, in queue order. None in an answer to a late arrival (section 7) |

An answer to `JOIN` carries only `KEY_EXCHANGE` (02 section 11.1) and follows
section 5.1.

### 5.1 Answering `JOIN`

- A `JOIN` with a new `sensor_pub` gets a new `KEY_EXCHANGE`, built with the next
  value of the device's root downlink counter, which the server never resets (02
  section 8.4). The server persists the counter reservation and the pending
  exchange before sending it (04 section 4.6).
- A `JOIN` with the pending exchange's `sensor_pub` is a retransmission. Within
  the limits of section 4, step 5, the server answers it with the cached
  `KEY_EXCHANGE`, byte for byte, and changes nothing else (04 section 4.2).

So no two different `KEY_EXCHANGE` plaintexts are encrypted under one root nonce
by one server.

**Stalled exchange.** A sensor rejects a `KEY_EXCHANGE` whose root counter is not
above its root floor, without any answer. That happens when the server's counter
is behind the floor: the sensor was paired by another server and not factory
reset, or this server lost its counter (reinstalled, or restored from a backup
older than the last pairing). The server sees it as a `JOIN` that keeps being
retransmitted although it was answered.

- The server counts retransmissions of the pending exchange's `JOIN` that arrive
  after at least one transmission of its `KEY_EXCHANGE` was reported `SENT` (05
  section 5.5).
- When the count reaches 3, the sensor's last retry (08 section 5), the exchange
  has stalled. The server MUST then tell the user, in the pairing flow (section
  11.1), to factory-reset the sensor and pair again, and SHOULD keep the device
  `SCANNED` so that pressing the button again after the reset just works.
- The same symptom comes from a sensor that cannot hear the proxies' downlinks,
  so the prompt also suggests moving the sensor closer to a proxy.

A new `JOIN` (new `sensor_pub`) starts the count again. Each button press uses
the next root counter value, so a server only slightly behind the floor catches
up after a few presses; the prompt covers the general case.

## 6. Choosing a proxy

### 6.1 Candidates

A proxy is a candidate for answering a frame if all of these hold:

- it reported the frame in this boot (its `ref_rx_time_us` is known);
- its last `HELLO` advertised downlink capability and arrived within 180 s;
- it has a key of its own, not a shared key (05 section 4.2);
- its region, frequency, spreading factor and bandwidth match the network's
  profile (05 section 5.2).

### 6.2 RX1

For RX1 the server excludes receptions flagged `TS_UNCERTAIN` and proxies whose
timing record shows, among their last 20 results, any `SENT` with `offset_us`
above 30 000 or more than 2 `TOO_LATE` or `BUSY`. Among the rest it picks the
reception with the highest SNR. On equal SNR (within 1 dB) it prefers higher
RSSI, then the proxy with fewer recent failures.

### 6.3 RX2 and fallback

RX2 is only for answers to confirmed uplinks: sensors are only required to open it
after a confirmed uplink that RX1 did not answer (01 section 4, 08 section 7).

- If the uplink is confirmed and no candidate qualifies for RX1, or the 800 ms
  deadline has passed, the server uses RX2 (`tx_offset_us` = 3 000 000) with the
  best candidate by SNR, now including `TS_UNCERTAIN` receptions.
- If the uplink is confirmed and the RX1 proxy answers `TX_RESULT` with anything
  but `SENT`, the server sends the same downlink for RX2 through the next best
  candidate, or through the same proxy if it is the only one.
- The server MUST NOT use RX2 to answer an unconfirmed uplink. If RX1 is not
  possible or fails, it sends nothing; queued commands and a clock correction
  wait for the next uplink.
- If both windows fail for a confirmed uplink, the server does nothing more. The
  sensor retries confirmed uplinks itself (08 section 5), and commands stay queued.
- The server MUST NOT ask more than one proxy to transmit in the same window.

### 6.4 Rebuilding a downlink

A downlink sent for RX2 after an RX1 failure is the same frame (same
`fcnt_down`), so the sensor accepts at most one of the two. A downlink that
answers a retransmitted uplink is a new frame with a new `fcnt_down`, except the
answer to a retransmitted `JOIN`, which is the cached `KEY_EXCHANGE` frame
(section 5.1).

## 7. Command queue

- Each device has an ordered queue of commands. Actions in the user interface
  (section 11.4) and the protocol itself (`SET_NETWORK` in a key rotation, `LEAVE`
  on removal) add to it.
- Commands are sent in downlinks as in section 5. A command stays queued, and
  goes out again in each later downlink, until it is delivered.
- **Awaiting acknowledgement.** When the server sends a downlink with commands,
  it records that downlink's `reply_to` and its commands as *awaiting
  acknowledgement*, replacing any earlier record. If the record already has the
  same `reply_to` (an answer to a retransmission, section 6.4), the server keeps
  only the commands that both downlinks carried, because the sensor accepted at
  most one of them and the server cannot tell which.
- The server MUST NOT put commands in an answer to a late arrival (`accept_late`,
  02 section 8.5). The sensor has already sent a newer frame, so it rejects that
  answer (02 section 10.2), and recording it would move the record back to a
  `reply_to` that older uplinks are above.
- **Delivery.** An accepted uplink (02 section 8.5) with `DL_ACK` set and an
  `fcnt` greater than the record's `reply_to` marks the recorded commands
  delivered, and the record is cleared. A sensor accepts only a downlink that
  answers its most recent uplink, and sets `DL_ACK` in the next new frame it
  builds (02 section 10.2), so such an uplink acknowledges a downlink with that
  `reply_to` and no other.
- An uplink whose `fcnt` is not greater than the record's `reply_to` MUST NOT
  mark commands delivered, whether or not it has `DL_ACK`. This covers late
  arrivals (02 section 8.5) and federated copies (09 section 6.1) of frames sent
  before the downlink. A retransmission is never acted on again (section 4,
  step 5).
- An uplink with a greater `fcnt` but no `DL_ACK` means the sensor did not accept
  the downlink. Its commands stay queued and go out again in the next downlink.
  Since commands are idempotent (02 section 10.3), the worst case of these rules
  is a command executed twice, never one marked delivered that the sensor did not
  receive.
- Adding a command that replaces an earlier queued one of the same kind (for
  example a second `SET_HEARTBEAT`, or `0x40` for the same channel) removes the
  earlier one.
- A command not delivered within 7 days is dropped and the user is told.
  `LEAVE` follows 04 section 6.1 instead (48 hours).

## 8. Supervision

### 8.1 Devices

Each device has a heartbeat interval `h` (minutes).

| Condition | Result |
|---|---|
| No valid uplink for `3 h + 5` minutes | Device *unreachable* |
| For 24 hours, every confirmed uplink the server answered was then retransmitted by the sensor, or followed by a `SYNC` (08 section 6) | Device *one-way*: it is heard but does not receive the answers |
| Any valid uplink | Clears *unreachable*; the device's state entities return to their last reported values only when that uplink carries them |
| `battery_percent` at or below 10 | *Low battery* |

While a device is unreachable, its state entities MUST be shown as unavailable,
not as their last value. A leak sensor that has gone quiet is not dry; a contact
sensor that has gone quiet is not closed.

### 8.2 Proxies

- A proxy is *offline* when no `HELLO` has arrived for 180 s.
- A device is *single-path* when, over the last 24 hours, only one proxy has heard
  it. The server SHOULD show this so the user can add coverage.

## 9. Reception history and coverage

For each device the server keeps the last 50 receptions (proxy, time, RSSI, SNR)
and derives:

- the best RSSI and SNR of the last frame;
- the number of proxies that heard it in the last 24 hours;
- per proxy, the share of the device's frames it heard in the last 24 hours.

This history is diagnostic and is not persisted.

## 10. Persistence

- Device and network records MUST be persisted when they change state (04 section
  4.6).
- `last_fcnt` and the late-arrival record MUST be persisted within 10 seconds of
  any accepted frame and on clean shutdown. After a crash, a frame accepted in the
  last 10 seconds before the crash could be accepted a second time if an attacker
  replays it; this is an accepted risk.
- The root and session downlink counters use the reservation scheme of 02
  section 8.2, so downlink counters never repeat. The root counter of a device is
  kept after the device is removed or discarded, so pairing it again continues
  the counter (02 section 8.4).
- The pending exchange MUST be persisted before its `KEY_EXCHANGE` is sent (04
  section 4.6).
- The command queue MUST be persisted whenever it changes.

## 11. Home Assistant integration

### 11.1 Configuration flow

| Step | What the user does |
|---|---|
| Add the integration | Chooses the region profile. The integration creates the network and its `k_net`. |
| Add a proxy | Gets a generated proxy key and a ready-to-paste `cs_proxy` YAML snippet (06). The proxy appears when its first `HELLO` arrives. |
| Add a device | Scans or types a pairing code, gives the device a name and area, then presses the device's button (04). The flow says that a second-hand device must be factory reset first (04 section 6.3). If the exchange stalls (section 5.1), the flow asks the user to hold the device's button for 10 seconds to factory-reset it and then press it again, or to move it closer to a proxy. |

The integration listens for proxies on UDP port 47800 and advertises
`_connectsensors._udp` by mDNS.

### 11.2 Devices and entities

- Each sensor is a device in the device registry, identified by its `dev_eui`,
  with manufacturer, model and name from its profile and the software version from
  `firmware_version` (03 section 4.4).
- Entities come from the profile, or from the default mapping (03 section 7) for
  channels the profile does not cover or when there is no profile.
- Per-device diagnostic entities: *reachable* (connectivity), last seen, best
  RSSI, best SNR, proxies hearing it, frame counter.
- Each proxy is a device identified by its `proxy_id`, with a MAC connection, so
  Home Assistant merges it with the same node's ESPHome device. Diagnostic
  entities: online, frames received by the server, downlinks sent and failed.

### 11.3 Events

- `button` readings fire the device's event entity.
- The integration fires `connect_sensors_device_unreachable` and
  `connect_sensors_device_reachable` events, so automations can react to
  supervision changes.

### 11.4 Actions

| Action | Effect |
|---|---|
| `connect_sensors.set_value` | Queue command `0x40` (03 section 8) for a writable channel |
| `connect_sensors.set_heartbeat` | Queue `SET_HEARTBEAT` |
| `connect_sensors.rotate_network_key` | Start a network key rotation (04 section 7) |

### 11.5 Repairs

The integration raises a repair issue when:

- a proxy's radio settings do not match the network's profile;
- a new proxy appears using the shared key (if enabled), for the user to accept
  or block;
- a proxy on the shared key advertises downlink capability: it gets no downlinks
  and anyone holding the shared key could make it transmit, so the repair offers
  to generate a key of its own (05 section 4.2);
- a key rotation has devices that did not acknowledge within 7 days;
- the server clock is not synchronized;
- a device is one-way (section 8.1).

### 11.6 Storage

Keys live in the integration's private storage, which Home Assistant includes in
its encrypted backups. Pairing codes, keys and decrypted payloads MUST NOT be
written to logs. Diagnostics downloads MUST redact keys.

## 12. Security considerations

| Concern | Handling |
|---|---|
| CPU exhaustion with bootstrap frames | 50 per minute limit (section 4) |
| CPU exhaustion with normal frames | Tag lookups are hash-table hits; at most a few MIC checks per frame |
| Replay after restart | Section 10 |
| Proxy sessions after restart | Not persisted. The proxy's next message draws a `HELLO_REQUEST`, and the proxy follows the server's new `seq` through the `SERVER_STATUS` echo (05 section 3.2). |
| Replayed `JOIN` during pairing | Answered with the cached frame; `k_session` and the counters are unchanged (section 5.1) |
| Root nonce reuse | The root downlink counter is never reset and is kept after removal (section 10). Reuse by a different server after a factory reset is accepted (02 section 13.1) |
| Replaying a captured confirmed frame to draw downlinks | Proxies filter it only within `dedupe_window` (06 section 6); the server answers a frame again at most 3 times, within 60 s (section 4, step 5), and proxy airtime budgets cap the rest |
| A malicious proxy reporting false RSSI to win downlinks | It can only drop the downlink, which the RX2 fallback and sensor retries cover for confirmed uplinks; queued commands wait for the next uplink. Remove the proxy if it misbehaves. |
| Forged `DOWNLINK`s to make a proxy transmit | Only a holder of the proxy's key can send one. Downlinks go only through proxies with a key of their own (section 6.1, 05 section 4.2), so a stolen proxy exposes no other proxy's transmitter. A proxy left on the shared key with downlinks enabled is the exception: any holder of the shared key can make it transmit, so the server warns the user (05 section 4.2; a repair in Home Assistant, section 11.5) until it gets a key of its own or its downlinks are turned off. |
| A stolen proxy on a shared key | Its holder can act as every proxy on that key (05 section 7): report false receptions, which only skews the coverage figures of section 9, since none of those proxies is a downlink candidate, and keep taking over their sessions (05 section 3.2), so the server discards their frames while it holds them. Blocking its `proxy_id` does not stop this; the user replaces the shared key on all of them. Single-path and unreachable alarms (section 8) show the loss. |
| Leaking state through Home Assistant | Out of scope: Home Assistant's own access control applies |

## 13. Test vectors

`vectors/server-v1.json` has a sequence of uplink counter values with the expected
result for each (`accept`, `accept_late`, `duplicate`, `too_old`), a
`counter16` sequence with the expected totals and whether each step was an
increase, a wrap or a reset, and a `retransmission` sequence: copies of a
confirmed uplink and its retries from proxies and a relay, with whether each is
a new transmission (section 4, step 3) and whether it is answered (step 5), a
`dl_ack` sequence (section 7): downlinks with commands and uplinks with and
without `DL_ACK`, including late arrivals and two answers to one uplink, with
the commands each uplink marks delivered, and a
`join` sequence (section 5.1): the root downlink counter value, the
`KEY_EXCHANGE` frame and `k_session` for each `JOIN`, including byte-identical
answers to retransmissions and the stall on the last one.
The proxy sessions of 05 section 3.2, including a server restart, are in the
`session` sequence of `vectors/proxy-envelope-v1.json`.
