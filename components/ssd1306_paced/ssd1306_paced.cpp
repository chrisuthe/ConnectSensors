#include "ssd1306_paced.h"
#include "esphome/core/log.h"

#include <cstring>

namespace esphome::ssd1306_paced {

ESPHOME_LOG_TAG(TAG, "ssd1306_paced");

static constexpr uint8_t CONTROL_COMMANDS = 0x00;
static constexpr uint8_t CONTROL_DATA = 0x40;
static constexpr uint8_t COMMAND_COLUMN_ADDRESS = 0x21;
static constexpr uint8_t COMMAND_PAGE_ADDRESS = 0x22;

void PacedSSD1306::setup() {
  this->init_reset_();

  auto err = this->write(nullptr, 0);
  if (!this->setup_check(err == i2c::ERROR_OK))
    return;

  SSD1306::setup();
  this->disable_loop();  // nothing to flush until the first render
}

void PacedSSD1306::update() {
  this->do_update_();
  this->enable_loop();
}

void PacedSSD1306::loop() {
  const size_t pages = this->get_height_internal() / 8;
  for (size_t i = 0; i < pages; i++) {
    const size_t page = (this->next_page_ + i) % pages;
    if (this->page_dirty_(page)) {
      this->send_page_(page);
      this->next_page_ = (page + 1) % pages;
      return;  // one page per pass
    }
  }
  this->disable_loop();
}

void PacedSSD1306::dump_config() {
  LOG_DISPLAY("", "Paced I2C SSD1306", this);
  ESP_LOGCONFIG(TAG,
                "  Model: %s\n"
                "  External VCC: %s\n"
                "  Flip X: %s\n"
                "  Flip Y: %s\n"
                "  Offset X: %d\n"
                "  Offset Y: %d\n"
                "  Inverted Color: %s\n"
                "  Flush: one changed page per loop pass",
                LOG_STR_ARG(this->model_str_()), YESNO(this->external_vcc_), YESNO(this->flip_x_), YESNO(this->flip_y_),
                this->offset_x_, this->offset_y_, YESNO(this->invert_));
  LOG_I2C_DEVICE(this);
  LOG_PIN("  Reset Pin: ", this->reset_pin_);
  LOG_UPDATE_INTERVAL(this);
}

void PacedSSD1306::command(uint8_t value) { this->write_byte(CONTROL_COMMANDS, value); }

void PacedSSD1306::write_display_data() {
  const size_t len = this->get_buffer_length_();
  const size_t width = this->get_width_internal();
  if (this->sent_ == nullptr)
    this->sent_ = std::make_unique<uint8_t[]>(len);
  // The base class has already set the address window to the whole panel.
  for (size_t i = 0; i < len; i += width)
    this->write_bytes(CONTROL_DATA, this->buffer_ + i, width);
  std::memcpy(this->sent_.get(), this->buffer_, len);
}

uint8_t PacedSSD1306::column_start_() const {
  // Same column origins as SSD1306::display().
  switch (this->model_) {
    case ssd1306_base::SSD1306_MODEL_64_48:
    case ssd1306_base::SSD1306_MODEL_64_32:
      return 0x20 + this->offset_x_;
    case ssd1306_base::SSD1306_MODEL_72_40:
      return 0x1C + this->offset_x_;
    default:
      return this->offset_x_;
  }
}

bool PacedSSD1306::page_dirty_(size_t page) {
  const size_t width = this->get_width_internal();
  return std::memcmp(this->buffer_ + page * width, this->sent_.get() + page * width, width) != 0;
}

void PacedSSD1306::send_page_(size_t page) {
  const size_t width = this->get_width_internal();
  const uint8_t col = this->column_start_();
  const uint8_t window[] = {COMMAND_COLUMN_ADDRESS, col, uint8_t(col + width - 1),
                            COMMAND_PAGE_ADDRESS,   uint8_t(page), uint8_t(page)};
  this->write_bytes(CONTROL_COMMANDS, window, sizeof(window));
  this->write_bytes(CONTROL_DATA, this->buffer_ + page * width, width);
  std::memcpy(this->sent_.get() + page * width, this->buffer_ + page * width, width);
}

}  // namespace esphome::ssd1306_paced
