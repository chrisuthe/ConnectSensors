#pragma once

// SSD1306 over I2C that never pushes a whole frame in one main-loop pass.
//
// ESPHome runs every component in one loop task, and ssd1306_i2c sends the full
// 1 KB frame synchronously (about 22 ms at 800 kHz on an ESP32-S3), delaying the
// radio and the network. Here update() only renders into the buffer; loop() then
// sends one changed 8-row page per pass (about 2 ms), so the display is what waits.

#include "esphome/core/component.h"
#include "esphome/components/ssd1306_base/ssd1306_base.h"
#include "esphome/components/i2c/i2c.h"

#include <memory>

namespace esphome::ssd1306_paced {

class PacedSSD1306 final : public ssd1306_base::SSD1306, public i2c::I2CDevice {
 public:
  void setup() override;
  void loop() override;
  void update() override;
  void dump_config() override;

 protected:
  void command(uint8_t value) override;
  // Full blocking push; the base class uses it once in setup() to clear the panel.
  void write_display_data() override;

  uint8_t column_start_() const;
  bool page_dirty_(size_t page);
  void send_page_(size_t page);

  // What the panel's RAM holds, to find the pages a render changed.
  std::unique_ptr<uint8_t[]> sent_;
  size_t next_page_{0};
};

}  // namespace esphome::ssd1306_paced
