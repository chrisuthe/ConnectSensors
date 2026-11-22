#pragma once

// The 64-bit monotonic microsecond clock, one function per platform. ESPHome's
// micros() is 32-bit and wraps after about 71 minutes.

#include "esphome/core/defines.h"

#include <cstdint>

#ifdef USE_ESP32
#include <esp_timer.h>
#elif defined(USE_ZEPHYR)
#include <zephyr/kernel.h>
#endif

namespace esphome::cs_proxy {

inline uint64_t monotonic_us() {
#ifdef USE_ESP32
  return uint64_t(esp_timer_get_time());
#elif defined(USE_ZEPHYR)
  // Kernel tick resolution: about 30 us with nRF52's 32768 Hz tick.
  return k_ticks_to_us_floor64(k_uptime_ticks());
#else
#error "No 64-bit microsecond clock for this platform"
#endif
}

}  // namespace esphome::cs_proxy
