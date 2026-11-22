import esphome.codegen as cg
from esphome.components import text_sensor
import esphome.config_validation as cv
from esphome.const import ENTITY_CATEGORY_DIAGNOSTIC

from . import CONF_CS_SENSOR_ID, CSSensor

DEPENDENCIES = ["cs_sensor"]

CONFIG_SCHEMA = cv.Schema(
    {
        cv.GenerateID(CONF_CS_SENSOR_ID): cv.use_id(CSSensor),
        cv.Optional("pairing_state"): text_sensor.text_sensor_schema(
            entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
            icon="mdi:link-variant",
        ),
    }
)


async def to_code(config):
    parent = await cg.get_variable(config[CONF_CS_SENSOR_ID])
    if "pairing_state" in config:
        s = await text_sensor.new_text_sensor(config["pairing_state"])
        cg.add(parent.set_pairing_state_text_sensor(s))
