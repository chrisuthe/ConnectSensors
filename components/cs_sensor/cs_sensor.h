#pragma once

// ESPHome glue for the ConnectSensors sensor (spec 08). Behaviour lives in
// SensorCore (sensor_core.h); this file adapts it to the radio, ESPHome sensors,
// preferences, the clock and deep sleep. Everything platform-specific is in the
// "platform" section of cs_sensor.cpp.

#include "esphome/core/component.h"
#include "esphome/core/defines.h"
#include "esphome/core/preferences.h"

#include "esphome/components/binary_sensor/binary_sensor.h"
#include "esphome/components/sensor/sensor.h"
#ifdef USE_TEXT_SENSOR
#include "esphome/components/text_sensor/text_sensor.h"
#endif
#ifdef USE_CS_SENSOR_SX126X
#include "esphome/components/sx126x/sx126x.h"
#endif
#ifdef USE_CS_SENSOR_SX127X
#include "esphome/components/sx127x/sx127x.h"
#endif
#ifdef USE_CS_SENSOR_DEEP_SLEEP
#include "esphome/components/deep_sleep/deep_sleep_component.h"
#endif

#include "sensor_core.h"

#include <esp_timer.h>
#include <memory>
#include <vector>

namespace esphome::cs_sensor {

static constexpr const char *CS_SENSOR_VERSION = "0.1.0";

class CSSensor;

// 64-bit monotonic microseconds that carry on through a deep sleep, and Unix time
// from the RTC.
class PlatformClock : public Clock {
 public:
  uint64_t now_us() override;
  bool unix_time(uint32_t &out) override;
  void set_unix_time(uint32_t t) override;
  // Microseconds on the RTC, which keeps counting through deep sleep.
  static int64_t rtc_us();
  void set_offset(uint64_t offset_us) { this->offset_us_ = offset_us; }

 protected:
  uint64_t offset_us_{0};
};

class PlatformRadio : public Radio {
 public:
  explicit PlatformRadio(CSSensor *parent) : parent_(parent) {}
  bool transmit(const uint8_t *frame, size_t len) override;
  void start_receive() override;
  void stop_receive() override;
  bool receiving() override;
  uint32_t airtime_us(size_t len) override;

 protected:
  CSSensor *parent_;
};

// One ESPHome preference per blob, in flash, committed before save() returns.
class PreferenceStorage : public Storage {
 public:
  void set_base_key(uint32_t key) { this->base_key_ = key; }
  bool load(Blob id, uint8_t *buf, size_t len) override;
  bool save(Blob id, const uint8_t *buf, size_t len) override;
  // Preferences cannot be deleted; the core then writes zeros, which load as absent.
  bool erase(Blob id) override { return false; }

 protected:
  struct Slot {
    ESPPreferenceObject pref;
    size_t len{0};
  };
  ESPPreferenceObject &pref_(Blob id, size_t len);
  uint32_t base_key_{0};
  Slot slots_[8];
};

// The platform RNG, mixed through SHA-256 with a seed taken at boot from an
// entropy source that does not need the RF subsystem (see the README).
class PlatformRandom : public Random {
 public:
  void seed();
  void fill(uint8_t *buf, size_t len) override;

 protected:
  uint8_t seed_[32]{};
  uint64_t counter_{0};
};

class CSSensor : public Component
#ifdef USE_CS_SENSOR_SX126X
    ,
                 public sx126x::SX126xListener,
                 public sx126x::SX126xTransmitListener
#endif
#ifdef USE_CS_SENSOR_SX127X
    ,
                 public sx127x::SX127xListener,
                 public sx127x::SX127xTransmitListener
#endif
{
 public:
  CSSensor();
  void setup() override;
  void loop() override;
  void dump_config() override;
  // After the radio (PROCESSOR) and the sensors whose readings it sends.
  float get_setup_priority() const override { return setup_priority::PROCESSOR - 1.0f; }

  void on_packet(const std::vector<uint8_t> &packet, float rssi, float snr) override;
#ifdef USE_CS_SENSOR_SX126X
  void on_transmit_complete(sx126x::SX126xError result) override {
    this->tx_complete_(result == sx126x::SX126xError::SX126X_ERROR_NONE);
  }
  void set_sx126x(sx126x::SX126x *radio) { this->sx126x_ = radio; }
#endif
#ifdef USE_CS_SENSOR_SX127X
  void on_transmit_complete(sx127x::SX127xError result) override {
    this->tx_complete_(result == sx127x::SX127xError::SX127X_ERROR_NONE);
  }
  void set_sx127x(sx127x::SX127x *radio) { this->sx127x_ = radio; }
#endif

  void set_region(const char *region) { this->region_ = region; }
  void set_radio_params(uint8_t sf, uint32_t bw_hz, uint8_t cr, uint16_t preamble) {
    this->sf_ = sf;
    this->bw_hz_ = bw_hz;
    this->cr_ = cr;
    this->preamble_ = preamble;
  }
  void set_identity(const std::vector<uint8_t> &dev_eui, const std::vector<uint8_t> &k_root, const char *profile);
  void set_heartbeat_minutes(uint16_t minutes) { this->config_.heartbeat_minutes = minutes; }
  void set_firmware_version(uint8_t major, uint8_t minor, uint8_t patch) {
    this->config_.has_firmware_version = true;
    this->config_.firmware_version[0] = major;
    this->config_.firmware_version[1] = minor;
    this->config_.firmware_version[2] = patch;
  }
  // delta < 0: the value rides on heartbeats and frames sent for other readings,
  // but never causes a frame itself (battery).
  void add_sensor_reading(sensor::Sensor *s, uint8_t channel, uint8_t kind, float scale, bool confirmed,
                          uint32_t min_interval_ms, float delta);
  void add_binary_reading(binary_sensor::BinarySensor *s, uint8_t channel, uint8_t kind, bool confirmed,
                          uint32_t min_interval_ms);
  void set_pairing_button(binary_sensor::BinarySensor *button);
#ifdef USE_CS_SENSOR_DEEP_SLEEP
  void set_deep_sleep(deep_sleep::DeepSleepComponent *ds) { this->deep_sleep_ = ds; }
#endif
  void set_pairing_window(uint32_t ms) { this->pairing_window_ms_ = ms; }
  void set_max_sleep(uint32_t ms) { this->max_sleep_ms_ = ms; }

  void set_uplink_counter_sensor(sensor::Sensor *s) { this->uplink_counter_sensor_ = s; }
  void set_undelivered_sensor(sensor::Sensor *s) { this->undelivered_sensor_ = s; }
  void set_last_rssi_sensor(sensor::Sensor *s) { this->last_rssi_sensor_ = s; }
  void set_last_snr_sensor(sensor::Sensor *s) { this->last_snr_sensor_ = s; }
#ifdef USE_TEXT_SENSOR
  void set_pairing_state_text_sensor(text_sensor::TextSensor *s) { this->pairing_state_sensor_ = s; }
#endif

 protected:
  friend class PlatformRadio;

  struct ReadingSource {
    sensor::Sensor *sensor{nullptr};
    binary_sensor::BinarySensor *binary{nullptr};
    uint8_t channel{0};
    uint8_t kind{0};
    float scale{1};
    bool confirmed{false};
    uint32_t min_interval_ms{0};
    float delta{0};
    // Latest value from the ESPHome entity, and whether loop() has taken it yet.
    bool has_value{false};
    bool fresh{false};
    float value{NAN};
    // What the server last saw from this reading (kept through deep sleep).
    bool has_sent{false};
    float sent{NAN};
    uint64_t sent_us{0};
  };

  bool make_reading_(const ReadingSource &src, Reading &out) const;
  bool changed_(const ReadingSource &src) const;
  void take_readings_(uint64_t now);
  void handle_button_(uint64_t now);
  void tx_complete_(bool ok);
  void on_event_(SensorEvent e);
  void publish_diagnostics_();
  void arm_timer_(uint64_t wake_us);
  static void timer_cb_(void *arg);
  uint64_t glue_wake_us_() const;
  bool readings_ready_() const;
  void maybe_sleep_(uint64_t now);
  bool restore_warm_();
  void save_warm_();

  // Radio
#ifdef USE_CS_SENSOR_SX126X
  sx126x::SX126x *sx126x_{nullptr};
#endif
#ifdef USE_CS_SENSOR_SX127X
  sx127x::SX127x *sx127x_{nullptr};
#endif
  const char *region_{""};
  const char *profile_{""};
  uint8_t sf_{9};
  uint32_t bw_hz_{500000};
  uint8_t cr_{1};
  uint16_t preamble_{8};
  bool tx_busy_{false};

  // Core and platform
  SensorConfig config_;
  PlatformClock clock_;
  PlatformRadio radio_{this};
  PreferenceStorage storage_;
  PlatformRandom random_;
  std::unique_ptr<SensorCore> core_;
  esp_timer_handle_t timer_{nullptr};

  std::vector<ReadingSource> readings_;
  binary_sensor::BinarySensor *button_{nullptr};
  bool button_down_{false};
  bool button_event_{false};
  bool button_reset_done_{false};
  uint64_t button_down_us_{0};

  uint64_t started_us_{0};
  bool running_{false};
  bool warm_{false};
  float last_rssi_{NAN};
  float last_snr_{NAN};
  bool signal_fresh_{false};

  // Deep sleep
#ifdef USE_CS_SENSOR_DEEP_SLEEP
  deep_sleep::DeepSleepComponent *deep_sleep_{nullptr};
#endif
  uint32_t pairing_window_ms_{60000};
  uint32_t max_sleep_ms_{0};
  uint64_t awake_until_us_{0};

  // Diagnostics
  sensor::Sensor *uplink_counter_sensor_{nullptr};
  sensor::Sensor *undelivered_sensor_{nullptr};
  sensor::Sensor *last_rssi_sensor_{nullptr};
  sensor::Sensor *last_snr_sensor_{nullptr};
#ifdef USE_TEXT_SENSOR
  text_sensor::TextSensor *pairing_state_sensor_{nullptr};
#endif
  int last_state_published_{-1};
  int64_t last_counter_published_{-1};
  int last_undelivered_published_{-1};
};

}  // namespace esphome::cs_sensor
