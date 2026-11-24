# Bench runner

`run.py` drives a proxy through a fixed set of scenarios and checks what it does,
on air as well as over the network. It starts `devtools/cs_testserver.py --json`,
sends frames through a radio, and checks the server's events against the radio's
receptions. It also measures how far after each uplink a downlink really starts on
air, which is the only check of spec 01 section 4 that covers the whole path.

There are two radios:

- **On the rig**, the test transmitter (`examples/test-transmitter-heltec-v3.yaml`)
  over the ESPHome API. Its `send_hex` action transmits any frame, and its
  `TX timing` and `RX timing` text sensors time every transmission and reception.
- **With `--simulate`**, `tests/host_proxy`, the proxy engine as a host program.
  CI runs every scenario this way (`make -C tests/host_proxy`), so the runner is
  tested without a radio.

## Running a bench pass

The rig has three Heltec WiFi LoRa 32 V3 boards and a laptop:

| Board | Firmware | Role in a pass |
|---|---|---|
| Proxy | `examples/proxy-heltec-v3.yaml` (`cs_proxy`) | The device under test |
| Test transmitter | `examples/test-transmitter-heltec-v3.yaml` | Plays the sensor and times the air |
| Sensor (optional) | `examples/sensor-heltec-v3.yaml` (`cs_sensor`) | A real sensor, for the `sensor` scenario |

1. **Pick a UDP port.** The proxy sends to the `server:` host and port in its YAML
   (47800 by default). If something else on the laptop already holds 47800, such as
   a Home Assistant instance or a long-running `cs_testserver.py`, use another port,
   for example 47801. Leave the other server running, and point the proxy at the
   laptop and the new port:

   ```yaml
   substitutions:
     server_host: "192.168.1.10"  # the laptop
   cs_proxy:
     server:
       port: 47801
   ```

2. **Quiet the proxy.** Chatty logging, `runtime_stats`, or an open `esphome logs`
   session stalls the proxy's main loop for 160-270 ms. That withdraws its downlinks
   (issue #9) and spoils the timing. For a timing run, set `logger: level: INFO` (or
   `WARN`) on the proxy, leave `runtime_stats` out, and close any log viewers. Then
   flash it.

3. **Flash the test transmitter** from this checkout. It needs the `send_hex` action
   and the timing sensors, so an older build won't do:

   ```
   uvx --python 3.13 --from 'git+https://github.com/esphome/esphome@dev' \
       esphome run examples/test-transmitter-heltec-v3.yaml
   ```

   Put the boards a metre or more apart. `pa_power: 2` is plenty at that range.

4. **Run the pass** with the proxy's key (`cs_proxy_key` in its `secrets.yaml`):

   ```
   uv run --no-project --python 3.13 --with cryptography --with aioesphomeapi \
       python3 devtools/bench/run.py --transmitter lora-test-tx.local --port 47801 \
       --key <cs_proxy_key> --proxy lora-proxy.local
   ```

   `--proxy` is optional and only records the proxy's ESPHome version. To include a
   real sensor, add `--sensor-code CS:1:...` (its pairing code) and optionally
   `--sensor lora-door.local`. The run then waits for one uplink from the sensor, so
   open or close the door when it asks. A pass takes about two minutes.
   `--scenarios rx1,rx2` runs a subset, and `--repeat N` (default 3) sets how many
   downlinks are measured in each window.

5. **Read the result.** Each check prints `ok` or `FAIL`, and the run ends with the
   measured offsets and a count:

   ```
   rx1:
     ok   transmitter sent 26 bytes (fcnt 101)
     ok   UPLINK DATA_CONFIRMED from the test device
     ok   fcnt 101: server sends a DOWNLINK for rx1
     ok   fcnt 101: TX_RESULT SENT within 40 ms of the target (SENT, 0.21 ms)
     ok   fcnt 101: the downlink is received on air
     ok   fcnt 101: on air +3.10 ms after rx1 (01 section 4.1 allows 0 to 81 ms; 126.2 ms left in W)
   ...
   rx1 on air, ms after the delay: min +2.90 median +3.10 max +3.60 (n=11)
   rx2 on air, ms after the delay: min +2.80 median +3.00 max +3.20 (n=3)
   record: bench/records/2026-11-24-0123456789.json
   15 scenarios passed, 0 failed
   ```

   The figures above show the format. They are not measurements. A healthy proxy
   puts every downlink a few milliseconds after the delay: its RX-done timestamp
   lag plus radio start. Anything near the 81 ms limit points to a slow main loop.

6. **Commit the record** (`bench/records/<date>-<commit>.json`) when the pass is
   one worth keeping, such as a release or a timing change. Commit the code first,
   so the record's commit is the one that was measured. `dirty: true` means the
   checkout had uncommitted changes.

## Scenarios

| Name | What it checks |
|---|---|
| `rx1` | A fresh confirmed uplink is forwarded, answered in RX1 and `SENT` within 40 ms of the target, and heard on air within 01 section 4.1's budget (`--repeat` times) |
| `rx2` | The same with the server in RX2 (`window rx2`) |
| `retry` | The same frame again after 2.3 s, past the proxy's dedupe and the server's copy window, is answered again (07 section 4) |
| `dedupe` | The same frame twice back to back is forwarded once, and the proxy's `duplicates` counter rises by one |
| `rate-limit` | A burst of 8 frames from one tag is cut to the per-device burst of 5 (plus refill), and `rate_limited` counts the rest |
| `fault-bad-mac`, `fault-stale-seq`, `fault-wrong-boot` | A downlink with a bad MAC, a seq the proxy already holds, or another boot's `boot_id` is dropped silently: no `TX_RESULT` and nothing on air (05 section 3.2) |
| `fault-uplink-frame` | A `DOWNLINK` carrying an uplink-type frame draws `INVALID` and nothing on air |
| `fault-late` | A `DOWNLINK` that arrives after its window draws `TOO_LATE` |
| `fault-busy` | A second downlink for the same slot draws `BUSY`. The first is sent on time |
| `nop-drain` | The transmitter plays a sensor. It pairs (`JOIN`, `KEY_EXCHANGE`, first session uplink, `PAIRED`), then drains two queued `NOP`s: the first carries `PENDING`, the unconfirmed follow-up gets the last in RX1, and `DL_ACK` settles both (07 sections 5 and 7) |
| `restart` | The server restarts with its seq from 1, below the proxy's floor. The next uplink draws `HELLO_REQUEST`, the proxy follows the new session, and RX1 works again (05 section 3.2) |
| `sensor` | Only with `--sensor-code`. A real `cs_sensor`'s uplink is decrypted and, if confirmed, answered and `SENT`. With `--sensor`, its undelivered counter must not rise |

Setup comes first: it waits for the proxy's session, priming it with an uplink if
needed, and checks that its HELLO offers downlinks. At the end, the proxy's
`tx_ok` and `tx_failed` counters must have risen by exactly the number of `SENT`
and other `TX_RESULT`s. Each scenario's frames are fresh: the test-vector device's
session keys, a new `fcnt`, and a valid MIC.

The fault modes come from `cs_testserver.py`: `--fault NAME` at start, or
`fault NAME|none` on stdin, as the runner uses it. No scenario provokes
`DUTY_CYCLE`. The proxy's 2% budget (01 section 5) allows about 1 200 `US915`
downlinks an hour, which is far more than a pass sends. To test it, build the
proxy with `downlink: airtime_budget: 0.1%` (3.6 s an hour, about 58 downlinks),
then run `--scenarios rx1 --repeat 70` and expect the last ones to fail with
`DUTY_CYCLE`.

## How the on-air offset is measured

The transmitter timestamps two events with `micros()`:

- **TX done:** `send_packet` blocks until the radio raises TX_DONE, and the
  timestamp is taken as it returns.
- **RX:** taken first thing in `on_packet`.

For each downlink, the runner computes

    on_air_offset = rx_us - tx_done_us - airtime(downlink)

which is how long after the uplink ended that the downlink started on air. It
compares that with the window's delay: 1 000 000 µs for RX1 or 3 000 000 µs for
RX2. The airtime is the Semtech time-on-air for the profile, as the server reports
it. The check passes when the downlink starts between 2 ms early (the measurement
tolerance) and 81 ms late. 81 ms is the late side of 01 section 4.1's budget:
36 ms timestamp error, a 40 ms transmit window and 5 ms radio start. The record
also keeps the margin left in the sensor's window: `W` minus detection minus the
lateness, so 129.3 ms minus the lateness on `US915`.

How exact this is, in plain words:

- **`on_packet` runs late.** The radio raises RX_DONE when the frame's last
  symbol is decoded. The component reads the packet in its next `loop()` pass,
  which the DIO1 interrupt wakes. With an idle transmitter, that is well under a
  millisecond. A long loop pass delays it, and it makes the measured offset too
  *large*, never too small. The transmitter skips its screen redraws for 3.5 s
  after each transmission so they cannot land in a window. API traffic during a
  window, such as a state push, can still add a little.
- **TX done is a little late too.** `send_packet` polls DIO1 and then clears the
  IRQ over SPI, a few tens of microseconds. That makes the offset slightly too
  *small*.
- **Decoding takes time.** The SX1262 raises RX_DONE a fraction of a symbol after
  the frame ends on air. On `US915` (SF9, 500 kHz) a symbol is 1.024 ms. The same
  lag applies at the proxy, whose RX-done timestamp is the reference for its
  downlink, so it is part of what a sensor experiences and belongs in the result.
- **Airtime is computed, not measured.** The formula is exact for the frame's
  length and the profile. A misconfigured radio would show up as a large
  constant error.
- **The two clocks are one.** Both timestamps come from the transmitter's clock,
  so neither crystal drift (at most 40 ppm, 0.12 ms over 3 s) nor the proxy's
  clock matters. `micros()` wraps every 71.6 minutes, and the runner works modulo
  2³².

All told, a single measurement is good to about ±1 ms when the transmitter is
idle, and any larger error makes the downlink look later than it was. The record
keeps each downlink's `TX_RESULT` offset alongside: how late the proxy *commanded*
the transmission against its own target. `late_ms` minus that offset is the
proxy's RX-timestamp lag plus radio start, as seen from outside.

In simulation, `tests/host_proxy` reports when it heard the uplink and when its
fake radio finished each transmission, on its own clock. The same check runs on
those times. They test the runner and the engine's scheduling, not the air.

## Run records

Each run writes `bench/records/<date>-<commit>.json` (`<commit>` is the first 10
hex digits; a second run that day adds the time). `--record-dir` puts it elsewhere,
and `--no-record` skips it. With `--simulate`, a record is written only when
`--record-dir` is given. Format 1:

| Field | Contents |
|---|---|
| `format` | `1` |
| `date` | Start of the record, UTC, ISO 8601 |
| `commit`, `dirty` | `git rev-parse HEAD` of the checkout, and whether it had uncommitted changes |
| `mode` | `rig` or `simulated` |
| `region` | The proxy's region profile, from its HELLO |
| `server` | `{"port": ...}` |
| `transmitter` | The transmitter's ESPHome device info: `name`, `esphome_version`, `compilation_time`, `project_name`, `project_version`, `model`, `mac_address`. In simulation: `{"kind": "simulated", ...}` |
| `proxy` | `proxy_id` and `fw` (`cs_proxy <version>`) from its HELLO, `max_loop_gap_ms`, and `api`: its device info with `--proxy`, else `null` |
| `sensor` | `null`, or the `--sensor-code`'s `code_dev_eui` and `api`: device info with `--sensor` |
| `esphome_version` | The transmitter's ESPHome version, else the proxy's |
| `counters` | The proxy's HELLO counters (`heard`, `forwarded`, `duplicates`, `invalid`, `rate_limited`, `tx_ok`, `tx_failed`) at `start` and `end` |
| `scenarios` | One per scenario, in order, with `setup` first and `counters` last: `name`, `passed`, `duration_s`, `checks` (`[{"what", "ok"}]`), `measurements` |
| `summary` | `passed` and `failed` scenario counts, and `rx1_late_ms` / `rx2_late_ms`: `{n, min, median, max}` of the measured lateness, or `null` |

Each measurement is one downlink heard on air:

| Field | Contents |
|---|---|
| `window` | `rx1` or `rx2` |
| `fcnt`, `seq`, `what` | The uplink it answers, the `DOWNLINK` seq, and what the server sent (`ack`, `KEY_EXCHANGE`, `NOP PENDING (2 queued)`, ...) |
| `dl_len`, `airtime_us` | Downlink length in bytes and its airtime |
| `on_air_offset_us` | `rx_us - tx_done_us - airtime_us` |
| `late_ms` | `on_air_offset_us` minus the delay, in ms |
| `margin_ms` | `W` minus detection minus `late_ms` (01 section 4.1) |
| `tx_result_offset_us` | The proxy's `TX_RESULT` offset: transmit commanded after its target |
| `rssi`, `snr` | The downlink as the transmitter heard it |

## Other tools

`devtools/press.py` presses API buttons and calls actions by hand:

```
python3 devtools/press.py lora-test-tx.local                        # list buttons and actions
python3 devtools/press.py lora-test-tx.local DATA_CONFIRMED JOIN    # press two buttons, 4 s apart
python3 devtools/press.py lora-test-tx.local --service send_hex data=c512b08e...
```

`cs_testserver.py --json` prints one JSON object per event on stdout (`LISTENING`,
`HELLO`, `HELLO_REQUEST`, `SESSION`, `UPLINK`, `DOWNLINK`, `TX_RESULT`, `PAIRED`,
`ACKED`, `QUEUED`, `MODE`, `IGNORED`, `REJECTED`), each with `event` and `t` (Unix
time). The human log moves to stderr.
