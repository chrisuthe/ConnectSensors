import esphome.codegen as cg
from esphome.components import sensor
import esphome.config_validation as cv
from esphome.const import (
    DEVICE_CLASS_SIGNAL_STRENGTH,
    ENTITY_CATEGORY_DIAGNOSTIC,
    STATE_CLASS_MEASUREMENT,
    STATE_CLASS_TOTAL_INCREASING,
    UNIT_DECIBEL,
    UNIT_DECIBEL_MILLIWATT,
    UNIT_MILLISECOND,
    UNIT_PERCENT,
)

from . import CONF_CS_PROXY_ID, CSProxy

DEPENDENCIES = ["cs_proxy"]

CONF_FRAMES_HEARD = "frames_heard"
CONF_FRAMES_FORWARDED = "frames_forwarded"
CONF_DUPLICATES = "duplicates"
CONF_INVALID = "invalid"
CONF_RATE_LIMITED = "rate_limited"
CONF_DOWNLINKS_SENT = "downlinks_sent"
CONF_DOWNLINKS_FAILED = "downlinks_failed"
CONF_LAST_RSSI = "last_rssi"
CONF_LAST_SNR = "last_snr"
CONF_MAX_LOOP_GAP = "max_loop_gap"
CONF_AIRTIME_USED = "airtime_used"

COUNTERS = (
    CONF_FRAMES_HEARD,
    CONF_FRAMES_FORWARDED,
    CONF_DUPLICATES,
    CONF_INVALID,
    CONF_RATE_LIMITED,
    CONF_DOWNLINKS_SENT,
    CONF_DOWNLINKS_FAILED,
)


def _counter():
    return sensor.sensor_schema(
        accuracy_decimals=0,
        state_class=STATE_CLASS_TOTAL_INCREASING,
        entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
        icon="mdi:counter",
    )


CONFIG_SCHEMA = cv.Schema(
    {
        cv.GenerateID(CONF_CS_PROXY_ID): cv.use_id(CSProxy),
        **{cv.Optional(name): _counter() for name in COUNTERS},
        cv.Optional(CONF_LAST_RSSI): sensor.sensor_schema(
            unit_of_measurement=UNIT_DECIBEL_MILLIWATT,
            accuracy_decimals=1,
            device_class=DEVICE_CLASS_SIGNAL_STRENGTH,
            state_class=STATE_CLASS_MEASUREMENT,
            entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
        ),
        cv.Optional(CONF_LAST_SNR): sensor.sensor_schema(
            unit_of_measurement=UNIT_DECIBEL,
            accuracy_decimals=1,
            state_class=STATE_CLASS_MEASUREMENT,
            entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
            icon="mdi:signal",
        ),
        cv.Optional(CONF_MAX_LOOP_GAP): sensor.sensor_schema(
            unit_of_measurement=UNIT_MILLISECOND,
            accuracy_decimals=0,
            state_class=STATE_CLASS_MEASUREMENT,
            entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
            icon="mdi:timer-alert-outline",
        ),
        cv.Optional(CONF_AIRTIME_USED): sensor.sensor_schema(
            unit_of_measurement=UNIT_PERCENT,
            accuracy_decimals=2,
            state_class=STATE_CLASS_MEASUREMENT,
            entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
            icon="mdi:radio-tower",
        ),
    }
)


async def to_code(config):
    parent = await cg.get_variable(config[CONF_CS_PROXY_ID])
    for name in (*COUNTERS, CONF_LAST_RSSI, CONF_LAST_SNR, CONF_MAX_LOOP_GAP, CONF_AIRTIME_USED):
        if name in config:
            s = await sensor.new_sensor(config[name])
            cg.add(getattr(parent, f"set_{name}_sensor")(s))
