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

COUNTERS = (
    "frames_heard",
    "frames_forwarded",
    "duplicates",
    "invalid",
    "rate_limited",
    "downlinks_sent",
    "downlinks_failed",
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
        cv.Optional("last_rssi"): sensor.sensor_schema(
            unit_of_measurement=UNIT_DECIBEL_MILLIWATT,
            accuracy_decimals=1,
            device_class=DEVICE_CLASS_SIGNAL_STRENGTH,
            state_class=STATE_CLASS_MEASUREMENT,
            entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
        ),
        cv.Optional("last_snr"): sensor.sensor_schema(
            unit_of_measurement=UNIT_DECIBEL,
            accuracy_decimals=1,
            state_class=STATE_CLASS_MEASUREMENT,
            entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
            icon="mdi:signal",
        ),
        cv.Optional("max_loop_gap"): sensor.sensor_schema(
            unit_of_measurement=UNIT_MILLISECOND,
            accuracy_decimals=0,
            state_class=STATE_CLASS_MEASUREMENT,
            entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
            icon="mdi:timer-alert-outline",
        ),
        cv.Optional("airtime_used"): sensor.sensor_schema(
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
    for name in (*COUNTERS, "last_rssi", "last_snr", "max_loop_gap", "airtime_used"):
        if name in config:
            s = await sensor.new_sensor(config[name])
            cg.add(getattr(parent, f"set_{name}_sensor")(s))
