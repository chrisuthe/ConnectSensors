"""ConnectSensors sensor (spec/08-sensor-behavior.md), on sensor_core."""

import base64
import hashlib
import logging
import re

import esphome.codegen as cg
from esphome.components import binary_sensor, deep_sleep, sensor, sx126x
import esphome.config_validation as cv
from esphome.const import (
    CONF_BATTERY_VOLTAGE,
    CONF_BINARY_SENSOR,
    CONF_CHANNEL,
    CONF_DELTA,
    CONF_HEARTBEAT,
    CONF_ID,
    CONF_MULTIPLY,
    CONF_RUN_DURATION,
    CONF_SENSOR,
    CONF_SLEEP_DURATION,
)
import esphome.final_validate as fv

CONF_CS_SENSOR_ID = "cs_sensor_id"
CONF_RADIO_ID = "radio_id"
CONF_REGION = "region"
CONF_DEV_EUI = "dev_eui"
CONF_ROOT_KEY = "root_key"
CONF_PAIRING_CODE = "pairing_code"
CONF_PROFILE = "profile"
CONF_BATTERY = "battery"
CONF_FIRMWARE_VERSION = "firmware_version"
CONF_PAIRING_BUTTON = "pairing_button"
CONF_DEEP_SLEEP_ID = "deep_sleep_id"
CONF_PAIRING_WINDOW = "pairing_window"
CONF_MAX_SLEEP = "max_sleep"
CONF_READINGS = "readings"
CONF_KIND = "kind"
CONF_CONFIRMED = "confirmed"
CONF_MIN_INTERVAL = "min_interval"

AUTO_LOAD = ["sensor", "binary_sensor"]

_LOGGER = logging.getLogger(__name__)

cs_sensor_ns = cg.esphome_ns.namespace("cs_sensor")
CSSensor = cs_sensor_ns.class_("CSSensor", cg.Component)

RADIO_KINDS = ("sx126x", "sx127x")

# Region profiles, spec/01-radio-profiles.md. Values use the radio components'
# own configuration names so they can be compared directly.
REGIONS = {
    "US915": {
        "frequency": 918_500_000,
        "bandwidth": "500_0kHz",
        "bandwidth_hz": 500_000,
        "spreading_factor": 9,
        "coding_rate": "CR_4_5",
        "preamble_size": 8,
        "crc_enable": True,
        "rx_start": True,
        "modulation": "LORA",
        "sync_value": {"sx126x": [0x14, 0x24], "sx127x": [0x12]},
        "max_pa_power": 20,
    },
}
PENDING_REGIONS = {
    "EU868": "the EU868 frequency is not decided yet (spec/01-radio-profiles.md section 3.2)",
}
# The tables above are copies of cs_proxy's: ESPHome loads only the components a
# configuration lists, so neither can import the other. `make -C tests/sensor_core`
# fails if they drift apart.

# Reading kinds a YAML reading may use (spec/03-payload-v1.md section 4): name ->
# (kind, default multiplier from the ESPHome unit to the wire unit). button is an
# event and firmware_version comes from `firmware_version:`, so neither is listed;
# raw and text have no ESPHome sensor to come from.
BINARY_KINDS = {
    "contact": 0x01,
    "motion": 0x02,
    "leak": 0x03,
    "tamper": 0x04,
    "vibration": 0x05,
    "binary": 0x06,
}
NUMERIC_KINDS = {
    "battery_percent": (0x07, 1),
    "enum": (0x09, 1),
    "percent": (0x0A, 1),
    "temperature": (0x40, 100),  # degrees Celsius -> 0.01
    "humidity": (0x41, 100),  # % -> 0.01 %
    "battery_voltage": (0x42, 1000),  # V -> mV
    "illuminance": (0x43, 1),
    "distance": (0x44, 1000),  # m -> mm
    "pressure": (0x45, 10),  # hPa -> 0.1 hPa
    "co2": (0x46, 1),
    "moisture": (0x47, 100),  # % -> 0.01 %
    "voltage": (0x48, 1000),  # V -> mV
    "counter16": (0x49, 1),
    "int16": (0x4A, 1),
    "counter32": (0x80, 1),
    "energy": (0x81, 1),
    "water": (0x82, 1),
    "uptime": (0x83, 1),
    "float32": (0x84, 1),
    "int32": (0x85, 1),
}
# Safety and security changes go confirmed (03 section 5, 08 section 4.1).
CONFIRMED_BY_DEFAULT = {"contact", "motion", "leak", "tamper"}
BATTERY_CHANNEL = 0xFF
READINGS_MAX = 63  # sensor_core.h: PAYLOAD_MAX - uflags
STATE_SLOTS = 16  # sensor_core.h
FIRMWARE_READING_SIZE = 2 + 1 + 3


def _encoded_size(kind):
    return 2 + {0: 1, 1: 2, 2: 4}[kind >> 6]


def _region(value):
    value = cv.string_strict(value).upper()
    if value in PENDING_REGIONS:
        raise cv.Invalid(f"Region {value} is not available: {PENDING_REGIONS[value]}")
    if value not in REGIONS:
        raise cv.Invalid(f"Unknown region {value}; available: {', '.join(REGIONS)}")
    return value


def _hex_bytes(length):
    def validator(value):
        value = cv.string_strict(value).strip().lower()
        if not re.fullmatch(r"[0-9a-f]{%d}" % (2 * length), value):
            raise cv.Invalid(f"Must be exactly {2 * length} hex digits")
        return [int(value[i : i + 2], 16) for i in range(0, len(value), 2)]

    return validator


def _pairing_code(value):
    """Validate a CS:1:... pairing code (04 section 3.2), keeping it a string so
    ESPHome can mask it; _identity() parses it."""
    code = cv.string_strict(value).strip().upper()
    _parse_pairing_code(code)
    return code


def _parse_pairing_code(code):
    if not set(code) <= set("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ.-:"):
        raise cv.Invalid("A pairing code holds only A-Z, 0-9, '.', '-' and ':'")
    parts = code.split(":")
    if len(parts) != 7 or parts[0] != "CS":
        raise cv.Invalid("Not a ConnectSensors pairing code (CS:1:<DEV_EUI>:<K_ROOT>:<REGION>:<PROFILE>:<CHECK>)")
    if parts[1] != "1":
        raise cv.Invalid(f"Unsupported pairing code version {parts[1]}")
    body = ":".join(parts[:6])
    if hashlib.sha256(body.encode()).hexdigest()[:4].upper() != parts[6]:
        raise cv.Invalid("Pairing code checksum mismatch")
    try:
        dev_eui = bytes.fromhex(parts[2])
        k_root = base64.b32decode(parts[3] + "=" * (-len(parts[3]) % 8))
    except ValueError as ex:
        raise cv.Invalid(f"Bad pairing code field: {ex}") from ex
    if len(dev_eui) != 8 or len(k_root) != 16 or len(parts[3]) != 26:
        raise cv.Invalid("Bad pairing code field length")
    if not 1 <= len(parts[5]) <= 32:
        raise cv.Invalid("Bad profile id in the pairing code")
    return {
        CONF_DEV_EUI: list(dev_eui),
        # A masked hex string, like a root_key given directly (cv.bind_key).
        CONF_ROOT_KEY: cv.sensitive()(k_root.hex().upper()),
        CONF_REGION: parts[4],
        CONF_PROFILE: parts[5],
    }


def _profile(value):
    value = cv.string_strict(value).upper()
    if not re.fullmatch(r"[0-9A-Z.\-]{1,32}", value):
        raise cv.Invalid("A profile id is 1 to 32 of A-Z, 0-9, '.' and '-' (spec/04-pairing.md section 3.1)")
    return value


def _firmware_version(value):
    m = re.fullmatch(r"\s*(\d+)\.(\d+)\.(\d+)\s*", cv.string_strict(value))
    if m is None or any(int(x) > 255 for x in m.groups()):
        raise cv.Invalid("firmware_version must look like 1.2.3, each part 0-255")
    return [int(x) for x in m.groups()]


def _kind(value):
    value = cv.string_strict(value).lower()
    if value in BINARY_KINDS or value in NUMERIC_KINDS:
        return value
    if value in ("button", "firmware_version", "raw", "text"):
        raise cv.Invalid(f"Kind {value} cannot be a reading here (see components/cs_sensor/README.md)")
    raise cv.Invalid(f"Unknown kind {value}; one of {', '.join([*BINARY_KINDS, *NUMERIC_KINDS])}")


def _reading(config):
    kind = config[CONF_KIND]
    if (CONF_SENSOR in config) == (CONF_BINARY_SENSOR in config):
        raise cv.Invalid("A reading needs exactly one of sensor or binary_sensor")
    if kind in BINARY_KINDS:
        if CONF_BINARY_SENSOR not in config:
            raise cv.Invalid(f"Kind {kind} takes a binary_sensor", path=[CONF_KIND])
        for key in (CONF_DELTA, CONF_MULTIPLY):
            if key in config:
                raise cv.Invalid(f"{key} applies only to numeric kinds", path=[key])
    elif CONF_SENSOR not in config:
        raise cv.Invalid(f"Kind {kind} takes a sensor", path=[CONF_KIND])
    if CONF_CONFIRMED not in config:
        config[CONF_CONFIRMED] = kind in CONFIRMED_BY_DEFAULT
    if kind in NUMERIC_KINDS and CONF_DELTA not in config and not config[CONF_MIN_INTERVAL].total_milliseconds:
        _LOGGER.warning(
            "cs_sensor reading on channel %s (%s) has neither delta nor min_interval, so every change "
            "of one wire step sends a frame; a noisy sensor will spend its airtime budget",
            config[CONF_CHANNEL],
            kind,
        )
    return config


READING_SCHEMA = cv.All(
    cv.Schema(
        {
            cv.Optional(CONF_SENSOR): cv.use_id(sensor.Sensor),
            cv.Optional(CONF_BINARY_SENSOR): cv.use_id(binary_sensor.BinarySensor),
            cv.Required(CONF_CHANNEL): cv.int_range(min=0, max=0xFE),
            cv.Required(CONF_KIND): _kind,
            cv.Optional(CONF_CONFIRMED): cv.boolean,
            cv.Optional(CONF_MIN_INTERVAL, default="0s"): cv.positive_time_period_milliseconds,
            cv.Optional(CONF_DELTA): cv.positive_float,
            cv.Optional(CONF_MULTIPLY): cv.float_,
        }
    ),
    _reading,
)


def _identity(config):
    has_code = CONF_PAIRING_CODE in config
    has_keys = CONF_DEV_EUI in config or CONF_ROOT_KEY in config
    if has_code == has_keys:
        raise cv.Invalid(f"Set either {CONF_PAIRING_CODE}, or both {CONF_DEV_EUI} and {CONF_ROOT_KEY}")
    if has_code:
        code = _parse_pairing_code(config.pop(CONF_PAIRING_CODE))
        if code[CONF_REGION] != config[CONF_REGION]:
            raise cv.Invalid(
                f"The pairing code is for {code[CONF_REGION]}, the sensor for {config[CONF_REGION]}",
                path=[CONF_PAIRING_CODE],
            )
        if CONF_PROFILE in config and config[CONF_PROFILE] != code[CONF_PROFILE]:
            raise cv.Invalid(
                f"The pairing code names profile {code[CONF_PROFILE]}", path=[CONF_PROFILE]
            )
        config[CONF_DEV_EUI] = code[CONF_DEV_EUI]
        config[CONF_ROOT_KEY] = code[CONF_ROOT_KEY]
        config[CONF_PROFILE] = code[CONF_PROFILE]
    elif CONF_DEV_EUI not in config or CONF_ROOT_KEY not in config:
        raise cv.Invalid(f"Set both {CONF_DEV_EUI} and {CONF_ROOT_KEY}")
    config.setdefault(CONF_PROFILE, "ESPHOME")
    if not any(bytes.fromhex(config[CONF_ROOT_KEY])):
        raise cv.Invalid("root_key must not be all zeros", path=[CONF_ROOT_KEY])
    return config


def _fits(config):
    """The full state rides on every heartbeat, so it must fit one frame (03 section 5)."""
    seen = {}
    size = 0
    slots = 0
    entries = []
    for i, r in enumerate(config[CONF_READINGS]):
        kind = BINARY_KINDS.get(r[CONF_KIND]) or NUMERIC_KINDS[r[CONF_KIND]][0]
        entries.append((r[CONF_CHANNEL], kind, [CONF_READINGS, i]))
    if CONF_BATTERY in config:
        entries.append((BATTERY_CHANNEL, 0x07, [CONF_BATTERY]))
    if CONF_BATTERY_VOLTAGE in config:
        entries.append((BATTERY_CHANNEL, 0x42, [CONF_BATTERY_VOLTAGE]))
    for channel, kind, path in entries:
        if (channel, kind) in seen:
            raise cv.Invalid(f"Channel {channel} already has a reading of this kind", path=path)
        seen[(channel, kind)] = True
        size += _encoded_size(kind)
        slots += 1
    if CONF_FIRMWARE_VERSION in config:
        size += FIRMWARE_READING_SIZE
    if size > READINGS_MAX or slots > STATE_SLOTS:
        raise cv.Invalid(
            f"The readings take {size} bytes in {slots} slots; one frame holds {READINGS_MAX} bytes "
            f"and the core {STATE_SLOTS} readings",
            path=[CONF_READINGS],
        )
    return config


CONFIG_SCHEMA = cv.All(
    cv.Schema(
        {
            cv.GenerateID(): cv.declare_id(CSSensor),
            cv.Required(CONF_RADIO_ID): cv.use_id(cg.Component),
            cv.Required(CONF_REGION): _region,
            cv.Optional(CONF_DEV_EUI): _hex_bytes(8),
            cv.Optional(CONF_ROOT_KEY): cv.bind_key(name=CONF_ROOT_KEY),
            cv.Optional(CONF_PAIRING_CODE): cv.sensitive(_pairing_code),
            cv.Optional(CONF_PROFILE): _profile,
            cv.Optional(CONF_HEARTBEAT, default="60min"): cv.All(
                cv.positive_time_period_minutes,
                cv.Range(min=cv.TimePeriod(minutes=1), max=cv.TimePeriod(minutes=1440)),
            ),
            cv.Optional(CONF_BATTERY): cv.use_id(sensor.Sensor),
            cv.Optional(CONF_BATTERY_VOLTAGE): cv.use_id(sensor.Sensor),
            cv.Optional(CONF_FIRMWARE_VERSION): _firmware_version,
            cv.Optional(CONF_PAIRING_BUTTON): cv.use_id(binary_sensor.BinarySensor),
            cv.Optional(CONF_DEEP_SLEEP_ID): cv.use_id(deep_sleep.DeepSleepComponent),
            cv.Optional(CONF_PAIRING_WINDOW, default="60s"): cv.positive_time_period_milliseconds,
            cv.Optional(CONF_MAX_SLEEP): cv.All(
                cv.positive_time_period_milliseconds, cv.Range(min=cv.TimePeriod(seconds=10))
            ),
            cv.Optional(CONF_READINGS, default=[]): cv.ensure_list(READING_SCHEMA),
        }
    ).extend(cv.COMPONENT_SCHEMA),
    _identity,
    _fits,
    # nRF52 (#38) adds its clock and storage notes and lifts this.
    cv.only_on_esp32,
    # Asynchronous radio transmit (start_transmit_async) arrived in 2026.12.
    cv.require_esphome_version(2026, 12, 0),
)


def _find_radio(full_config, radio_id):
    """Return (kind, radio_config) for the radio with this ID, or (None, None)."""
    try:
        path = full_config.get_path_for_id(radio_id)
    except KeyError:
        return None, None
    if path[0] not in RADIO_KINDS:
        return None, None
    return path[0], full_config.get_config_for_path(path[:-1])


def _final_validate(config):
    full = fv.full_config.get()
    kind, radio = _find_radio(full, config[CONF_RADIO_ID])
    if kind is None:
        raise cv.Invalid(
            f"{CONF_RADIO_ID} must be the ID of an sx126x or sx127x component", path=[CONF_RADIO_ID]
        )
    profile = REGIONS[config[CONF_REGION]]
    region = config[CONF_REGION]
    problems = []

    def expect(key, wanted, shown=None):
        got = radio.get(key)
        if got != wanted:
            problems.append(f"{kind}.{key} must be {shown if shown is not None else wanted} for {region} (is {got})")

    expect("modulation", profile["modulation"])
    expect("frequency", profile["frequency"], f"{profile['frequency'] / 1e6:g}MHz")
    expect("bandwidth", profile["bandwidth"])
    expect("spreading_factor", profile["spreading_factor"])
    expect("coding_rate", profile["coding_rate"])
    expect("preamble_size", profile["preamble_size"])
    expect("crc_enable", profile["crc_enable"])
    # rx_start must be true so the driver can tell a packet is arriving (is_receiving),
    # which keeps an RX window open to the end of it; cs_sensor puts the radio to sleep
    # outside its windows, so it never listens all the time.
    expect("rx_start", profile["rx_start"])
    sync = profile["sync_value"][kind]
    if list(radio.get("sync_value", [])) != sync:
        problems.append(
            f"{kind}.sync_value must be [{', '.join(f'0x{b:02X}' for b in sync)}] for {region}"
        )
    if radio.get("pa_power", 0) > profile["max_pa_power"]:
        problems.append(f"{kind}.pa_power must be at most {profile['max_pa_power']} for {region}")
    if problems:
        raise cv.Invalid(
            "The radio does not match the ConnectSensors region profile "
            "(spec/01-radio-profiles.md):\n  " + "\n  ".join(problems)
        )

    if CONF_DEEP_SLEEP_ID in config:
        # cv.use_id(DeepSleepComponent) already checked the type.
        ds = full.get_config_for_path(full.get_path_for_id(config[CONF_DEEP_SLEEP_ID])[:-1])
        for key in (CONF_RUN_DURATION, CONF_SLEEP_DURATION):
            if key in ds:
                raise cv.Invalid(
                    f"deep_sleep: remove {key}. cs_sensor decides when to sleep and for how long, "
                    "so that it never sleeps through a transmission, an RX window or a retry.",
                    path=[CONF_DEEP_SLEEP_ID],
                )
    elif CONF_MAX_SLEEP in config:
        raise cv.Invalid(f"{CONF_MAX_SLEEP} needs deep_sleep_id", path=[CONF_MAX_SLEEP])
    return config


FINAL_VALIDATE_SCHEMA = _final_validate


async def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)

    radio_id, radio = await cg.get_variable_with_full_id(config[CONF_RADIO_ID])
    if radio_id.type.inherits_from(sx126x.SX126x):
        cg.add_define("USE_CS_SENSOR_SX126X")
        cg.add(var.set_sx126x(radio))
    else:
        cg.add_define("USE_CS_SENSOR_SX127X")
        cg.add(var.set_sx127x(radio))

    profile = REGIONS[config[CONF_REGION]]
    cr = int(profile["coding_rate"][-1]) - 4  # CR_4_5 -> 1
    cg.add(var.set_region(config[CONF_REGION]))
    cg.add(
        var.set_radio_params(
            profile["spreading_factor"],
            profile["bandwidth_hz"],
            cr,
            profile["preamble_size"],
        )
    )

    cg.add(var.set_identity(config[CONF_DEV_EUI], list(bytes.fromhex(config[CONF_ROOT_KEY])), config[CONF_PROFILE]))
    # The pairing code holds the root key, so it never goes to the build log.
    _LOGGER.info(
        "cs_sensor dev_eui %s; print its pairing code with devtools/cs_pairing_code.py",
        bytes(config[CONF_DEV_EUI]).hex(),
    )
    cg.add(var.set_heartbeat_minutes(int(config[CONF_HEARTBEAT].total_minutes)))
    if CONF_FIRMWARE_VERSION in config:
        cg.add(var.set_firmware_version(*config[CONF_FIRMWARE_VERSION]))

    # Battery rides on heartbeats only (03 section 5): a negative delta never reports.
    if CONF_BATTERY in config:
        s = await cg.get_variable(config[CONF_BATTERY])
        cg.add(var.add_sensor_reading(s, BATTERY_CHANNEL, 0x07, 1.0, False, 0, -1.0))
    if CONF_BATTERY_VOLTAGE in config:
        s = await cg.get_variable(config[CONF_BATTERY_VOLTAGE])
        cg.add(var.add_sensor_reading(s, BATTERY_CHANNEL, 0x42, 1000.0, False, 0, -1.0))

    for r in config[CONF_READINGS]:
        interval = r[CONF_MIN_INTERVAL].total_milliseconds
        if r[CONF_KIND] in BINARY_KINDS:
            bs = await cg.get_variable(r[CONF_BINARY_SENSOR])
            cg.add(
                var.add_binary_reading(bs, r[CONF_CHANNEL], BINARY_KINDS[r[CONF_KIND]], r[CONF_CONFIRMED], interval)
            )
        else:
            kind_id, scale = NUMERIC_KINDS[r[CONF_KIND]]
            s = await cg.get_variable(r[CONF_SENSOR])
            cg.add(
                var.add_sensor_reading(
                    s,
                    r[CONF_CHANNEL],
                    kind_id,
                    r.get(CONF_MULTIPLY, float(scale)),
                    r[CONF_CONFIRMED],
                    interval,
                    r.get(CONF_DELTA, 0.0),
                )
            )

    if CONF_PAIRING_BUTTON in config:
        button = await cg.get_variable(config[CONF_PAIRING_BUTTON])
        cg.add(var.set_pairing_button(button))

    if CONF_DEEP_SLEEP_ID in config:
        cg.add_define("USE_CS_SENSOR_DEEP_SLEEP")
        ds = await cg.get_variable(config[CONF_DEEP_SLEEP_ID])
        cg.add(var.set_deep_sleep(ds))
        cg.add(var.set_pairing_window(config[CONF_PAIRING_WINDOW].total_milliseconds))
        if CONF_MAX_SLEEP in config:
            cg.add(var.set_max_sleep(config[CONF_MAX_SLEEP].total_milliseconds))
