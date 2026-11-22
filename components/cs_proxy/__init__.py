"""ConnectSensors proxy (spec/06-cs-proxy-component.md)."""

import logging
import re

import esphome.codegen as cg
from esphome.components import socket, sx126x
import esphome.config_validation as cv
from esphome.const import CONF_ID, CONF_KEY, CONF_PORT, CONF_REBOOT_TIMEOUT
import esphome.final_validate as fv

DEPENDENCIES = ["network"]
AUTO_LOAD = ["socket"]

CONF_CS_PROXY_ID = "cs_proxy_id"
CONF_ENABLED = "enabled"
CONF_RADIO_ID = "radio_id"
CONF_REGION = "region"
CONF_SERVER = "server"
CONF_HOST = "host"
CONF_PROXY_ID = "proxy_id"
CONF_DOWNLINK = "downlink"
CONF_AIRTIME_BUDGET = "airtime_budget"
CONF_DEDUPE_WINDOW = "dedupe_window"
CONF_DEDUPE_CACHE_SIZE = "dedupe_cache_size"
CONF_RATE_LIMIT = "rate_limit"
CONF_GLOBAL = "global"
CONF_PER_DEVICE = "per_device"
CONF_BOOTSTRAP = "bootstrap"

_LOGGER = logging.getLogger(__name__)

cs_proxy_ns = cg.esphome_ns.namespace("cs_proxy")
CSProxy = cs_proxy_ns.class_("CSProxy", cg.Component)

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


def _rate(value):
    """A rate such as 20, 20/s or 2.5/s, in frames per second."""
    if isinstance(value, (int, float)):
        rate = float(value)
    else:
        m = re.fullmatch(r"\s*([0-9]+(?:\.[0-9]+)?)\s*(?:/\s*s)?\s*", str(value))
        if m is None:
            raise cv.Invalid("Rate must look like 20/s")
        rate = float(m.group(1))
    if not 0.1 <= rate <= 1000:
        raise cv.Invalid("Rate must be between 0.1/s and 1000/s")
    return rate


_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.IGNORECASE)


def _server_host(value):
    """An IPv4 address or a DNS name. cv.domain() would refuse a bare LAN name such
    as "cs-server" and accept IPv6, which the IPv4-only resolver cannot use."""
    value = cv.string_strict(value).strip()
    try:
        return str(cv.ipv4address(value))
    except cv.Invalid:
        pass
    if ":" in value:
        raise cv.Invalid("server.host must be a hostname or an IPv4 address; IPv6 is not supported")
    labels = (value[:-1] if value.endswith(".") else value).split(".")
    if (
        len(value) > 253
        or not all(_DNS_LABEL.fullmatch(label) for label in labels)
        or all(label.isdigit() for label in labels)
    ):
        raise cv.Invalid(f"server.host must be a hostname or an IPv4 address, not {value!r}")
    return value


SERVER_SCHEMA = cv.Schema(
    {
        cv.Required(CONF_HOST): _server_host,
        cv.Optional(CONF_PORT, default=47800): cv.port,
        cv.Required(CONF_KEY): cv.bind_key(name=CONF_KEY),
    }
)

CONFIG_SCHEMA = cv.All(
    cv.Schema(
        {
            cv.GenerateID(): cv.declare_id(CSProxy),
            cv.Required(CONF_RADIO_ID): cv.use_id(cg.Component),
            cv.Required(CONF_REGION): _region,
            cv.Required(CONF_SERVER): SERVER_SCHEMA,
            cv.Optional(CONF_PROXY_ID): _hex_bytes(8),
            cv.Optional(CONF_DOWNLINK, default={}): cv.Schema(
                {
                    cv.Optional(CONF_ENABLED, default=True): cv.boolean,
                    cv.Optional(CONF_AIRTIME_BUDGET, default="2%"): cv.All(
                        cv.percentage, cv.Range(min=0.001, max=0.02)
                    ),
                }
            ),
            # Below the sensor's earliest retry (4 s), so retransmissions get through (06 section 6).
            # Keep the maximum in step with DEDUPE_WINDOW_MAX_US in proxy_core.h.
            cv.Optional(CONF_DEDUPE_WINDOW, default="2s"): cv.All(
                cv.positive_time_period_milliseconds,
                cv.Range(min=cv.TimePeriod(seconds=1), max=cv.TimePeriod(seconds=3)),
            ),
            cv.Optional(CONF_DEDUPE_CACHE_SIZE, default=64): cv.int_range(min=16, max=256),
            cv.Optional(CONF_RATE_LIMIT, default={}): cv.Schema(
                {
                    cv.Optional(CONF_GLOBAL, default="20/s"): _rate,
                    cv.Optional(CONF_PER_DEVICE, default="2/s"): _rate,
                    cv.Optional(CONF_BOOTSTRAP, default="5/s"): _rate,
                }
            ),
        }
    ).extend(cv.COMPONENT_SCHEMA),
    cv.only_on_esp32,
    # Asynchronous radio transmit (start_transmit_async) arrived in 2026.12.
    cv.require_esphome_version(2026, 12, 0),
    socket.consume_sockets(1, "cs_proxy", socket.SocketType.UDP),
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
    _warn_api_reboot_timeout(full)
    return config


def _warn_api_reboot_timeout(full):
    # Fine for a proxy Home Assistant keeps connected; otherwise each reboot drops
    # scheduled downlinks and leaves the proxy deaf for several seconds (06 section 9).
    timeout = full.get("api", {}).get(CONF_REBOOT_TIMEOUT)
    if timeout is not None and timeout.total_milliseconds:
        _LOGGER.warning(
            "api: reboot_timeout is %s: this proxy reboots whenever no API client has been "
            "connected that long. Set it to 0s unless Home Assistant stays connected "
            "(spec/06-cs-proxy-component.md section 9).",
            timeout,
        )


FINAL_VALIDATE_SCHEMA = _final_validate


async def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)

    radio_id, radio = await cg.get_variable_with_full_id(config[CONF_RADIO_ID])
    if radio_id.type.inherits_from(sx126x.SX126x):
        cg.add_define("USE_CS_PROXY_SX126X")
        cg.add(var.set_sx126x(radio))
    else:
        cg.add_define("USE_CS_PROXY_SX127X")
        cg.add(var.set_sx127x(radio))

    profile = REGIONS[config[CONF_REGION]]
    cr = int(profile["coding_rate"][-1]) - 4  # CR_4_5 -> 1
    cg.add(var.set_region(config[CONF_REGION]))
    cg.add(
        var.set_radio_params(
            profile["frequency"],
            profile["spreading_factor"],
            profile["bandwidth_hz"],
            cr,
            profile["preamble_size"],
        )
    )

    server = config[CONF_SERVER]
    socket.require_ipv4_resolve()
    cg.add(var.set_server(server[CONF_HOST], server[CONF_PORT]))
    cg.add(var.set_key(list(bytes.fromhex(server[CONF_KEY]))))
    if CONF_PROXY_ID in config:
        cg.add(var.set_proxy_id(config[CONF_PROXY_ID]))

    downlink = config[CONF_DOWNLINK]
    cg.add(var.set_downlink_enabled(downlink[CONF_ENABLED]))
    cg.add(var.set_airtime_budget_permille(round(downlink[CONF_AIRTIME_BUDGET] * 1000)))
    cg.add(var.set_dedupe(config[CONF_DEDUPE_WINDOW].total_milliseconds, config[CONF_DEDUPE_CACHE_SIZE]))
    rate = config[CONF_RATE_LIMIT]
    cg.add(var.set_rate_limits(rate[CONF_GLOBAL], rate[CONF_PER_DEVICE], rate[CONF_BOOTSTRAP]))
