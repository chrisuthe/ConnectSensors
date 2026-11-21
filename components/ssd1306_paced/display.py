import esphome.codegen as cg
from esphome.components import i2c, ssd1306_base
from esphome.components.ssd1306_base import _validate
import esphome.config_validation as cv
from esphome.const import CONF_ID, CONF_LAMBDA, CONF_MODEL, CONF_PAGES
from esphome.types import ConfigType

AUTO_LOAD = ["ssd1306_base"]
DEPENDENCIES = ["i2c"]

ssd1306_paced_ns = cg.esphome_ns.namespace("ssd1306_paced")
PacedSSD1306 = ssd1306_paced_ns.class_("PacedSSD1306", ssd1306_base.SSD1306, i2c.I2CDevice)


def _horizontal_addressing_only(value: ConfigType) -> ConfigType:
    # Paged flushing relies on the SSD1306/SSD1305 column and page address windows.
    if value[CONF_MODEL].startswith(("SH1106", "SH1107")):
        raise cv.Invalid("ssd1306_paced supports SSD1306 and SSD1305 models; use ssd1306_i2c for SH1106/SH1107")
    return value


CONFIG_SCHEMA = cv.All(
    ssd1306_base.SSD1306_SCHEMA.extend(
        {
            cv.GenerateID(): cv.declare_id(PacedSSD1306),
        }
    )
    .extend(cv.COMPONENT_SCHEMA)
    .extend(i2c.i2c_device_schema(0x3C)),
    cv.has_at_most_one_key(CONF_PAGES, CONF_LAMBDA),
    _validate,
    _horizontal_addressing_only,
)


async def to_code(config: ConfigType) -> None:
    var = cg.new_Pvariable(config[CONF_ID])
    await ssd1306_base.setup_ssd1306(var, config)
    await i2c.register_i2c_device(var, config)
