import esphome.codegen as cg
from esphome.components import binary_sensor
import esphome.config_validation as cv
from esphome.const import DEVICE_CLASS_CONNECTIVITY, ENTITY_CATEGORY_DIAGNOSTIC

from . import CONF_CS_PROXY_ID, CSProxy

DEPENDENCIES = ["cs_proxy"]

CONF_SERVER_CONNECTED = "server_connected"

CONFIG_SCHEMA = cv.Schema(
    {
        cv.GenerateID(CONF_CS_PROXY_ID): cv.use_id(CSProxy),
        cv.Optional(CONF_SERVER_CONNECTED): binary_sensor.binary_sensor_schema(
            device_class=DEVICE_CLASS_CONNECTIVITY,
            entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
        ),
    }
)


async def to_code(config):
    parent = await cg.get_variable(config[CONF_CS_PROXY_ID])
    if CONF_SERVER_CONNECTED in config:
        s = await binary_sensor.new_binary_sensor(config[CONF_SERVER_CONNECTED])
        cg.add(parent.set_server_connected_binary_sensor(s))
