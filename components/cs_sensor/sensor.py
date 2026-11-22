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
)

from . import CONF_CS_SENSOR_ID, CSSensor

DEPENDENCIES = ["cs_sensor"]

CONF_UPLINK_COUNTER = "uplink_counter"
CONF_UNDELIVERED = "undelivered"
CONF_LAST_RSSI = "last_rssi"
CONF_LAST_SNR = "last_snr"

CONFIG_SCHEMA = cv.Schema(
    {
        cv.GenerateID(CONF_CS_SENSOR_ID): cv.use_id(CSSensor),
        cv.Optional(CONF_UPLINK_COUNTER): sensor.sensor_schema(
            accuracy_decimals=0,
            state_class=STATE_CLASS_TOTAL_INCREASING,
            entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
            icon="mdi:counter",
        ),
        cv.Optional(CONF_UNDELIVERED): sensor.sensor_schema(
            accuracy_decimals=0,
            state_class=STATE_CLASS_MEASUREMENT,
            entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
            icon="mdi:email-alert-outline",
        ),
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
    }
)


async def to_code(config):
    parent = await cg.get_variable(config[CONF_CS_SENSOR_ID])
    for key in (CONF_UPLINK_COUNTER, CONF_UNDELIVERED, CONF_LAST_RSSI, CONF_LAST_SNR):
        if key in config:
            s = await sensor.new_sensor(config[key])
            cg.add(getattr(parent, f"set_{key}_sensor")(s))
