#pragma once

// ESPHome glue for the ConnectSensors proxy (spec 06). Protocol logic lives in
// proxy_core; this file connects it to the radio, the network and entities.

#include "esphome/core/component.h"
#include "esphome/core/defines.h"
#include "esphome/components/socket/socket.h"
#include "esphome/components/socket/ipv4_resolve.h"

#ifdef USE_SENSOR
#include "esphome/components/sensor/sensor.h"
#endif
#ifdef USE_BINARY_SENSOR
#include "esphome/components/binary_sensor/binary_sensor.h"
#endif
#ifdef USE_CS_PROXY_SX126X
#include "esphome/components/sx126x/sx126x.h"
#endif
#ifdef USE_CS_PROXY_SX127X
#include "esphome/components/sx127x/sx127x.h"
#endif

#include "proxy_core.h"

#include <esp_timer.h>
#include <memory>
#include <string>
#include <vector>

namespace esphome::cs_proxy {

static constexpr const char *CS_PROXY_VERSION = "0.1.0";

class CSProxy : public Component
#ifdef USE_CS_PROXY_SX126X
    ,
                public sx126x::SX126xListener
#endif
#ifdef USE_CS_PROXY_SX127X
    ,
                public sx127x::SX127xListener
#endif
{
 public:
  void setup() override;
  void loop() override;
  void dump_config() override;
  float get_setup_priority() const override { return setup_priority::AFTER_WIFI; }

  // Radio listener (both radio components use this signature).
  void on_packet(const std::vector<uint8_t> &packet, float rssi, float snr) override;

#ifdef USE_CS_PROXY_SX126X
  void set_sx126x(sx126x::SX126x *radio) { this->sx126x_ = radio; }
#endif
#ifdef USE_CS_PROXY_SX127X
  void set_sx127x(sx127x::SX127x *radio) { this->sx127x_ = radio; }
#endif
  void set_region(const char *region) { this->region_ = region; }
  void set_radio_params(uint32_t frequency_hz, uint8_t sf, uint32_t bw_hz, uint8_t cr, uint16_t preamble) {
    this->frequency_hz_ = frequency_hz;
    this->sf_ = sf;
    this->bw_hz_ = bw_hz;
    this->cr_ = cr;
    this->preamble_ = preamble;
  }
  void set_server(const char *host, uint16_t port) {
    this->server_host_ = host;
    this->server_port_ = port;
  }
  void set_key(const std::vector<uint8_t> &key) { this->key_ = key; }
  void set_proxy_id(const std::vector<uint8_t> &id) { this->proxy_id_override_ = id; }
  void set_downlink_enabled(bool enabled) { this->downlink_enabled_ = enabled; }
  void set_airtime_budget_permille(uint32_t permille) { this->budget_permille_ = permille; }
  void set_dedupe(uint32_t window_ms, uint16_t cache_size) {
    this->dedupe_window_us_ = uint64_t(window_ms) * 1000;
    this->dedupe_size_ = cache_size;
  }
  void set_rate_limits(float global, float per_device, float bootstrap) {
    this->rate_global_ = global;
    this->rate_device_ = per_device;
    this->rate_bootstrap_ = bootstrap;
  }

#ifdef USE_SENSOR
  void set_frames_heard_sensor(sensor::Sensor *s) { this->frames_heard_sensor_ = s; }
  void set_frames_forwarded_sensor(sensor::Sensor *s) { this->frames_forwarded_sensor_ = s; }
  void set_duplicates_sensor(sensor::Sensor *s) { this->duplicates_sensor_ = s; }
  void set_invalid_sensor(sensor::Sensor *s) { this->invalid_sensor_ = s; }
  void set_rate_limited_sensor(sensor::Sensor *s) { this->rate_limited_sensor_ = s; }
  void set_downlinks_sent_sensor(sensor::Sensor *s) { this->downlinks_sent_sensor_ = s; }
  void set_downlinks_failed_sensor(sensor::Sensor *s) { this->downlinks_failed_sensor_ = s; }
  void set_last_rssi_sensor(sensor::Sensor *s) { this->last_rssi_sensor_ = s; }
  void set_last_snr_sensor(sensor::Sensor *s) { this->last_snr_sensor_ = s; }
  void set_max_loop_gap_sensor(sensor::Sensor *s) { this->max_loop_gap_sensor_ = s; }
  void set_airtime_used_sensor(sensor::Sensor *s) { this->airtime_used_sensor_ = s; }
#endif
#ifdef USE_BINARY_SENSOR
  void set_server_connected_binary_sensor(binary_sensor::BinarySensor *s) { this->server_connected_sensor_ = s; }
#endif

 protected:
  static uint64_t now_us_() { return uint64_t(esp_timer_get_time()); }
  static void tx_timer_cb_(void *arg);

  bool radio_transmit_(const uint8_t *data, size_t len);
  void handle_message_(const uint8_t *data, size_t len, uint64_t now);
  void handle_downlink_(const Envelope &e, uint64_t now);
  void run_due_transmissions_();
  void arm_tx_timer_();
  void send_(uint8_t type, const std::vector<uint8_t> &body);
  void send_tx_result_(uint32_t seq, uint8_t result, int32_t offset_us);
  void send_hello_();
  void poll_server_address_(uint64_t now);
  void set_connected_(bool connected);
  void publish_counters_();

  // Configuration
#ifdef USE_CS_PROXY_SX126X
  sx126x::SX126x *sx126x_{nullptr};
#endif
#ifdef USE_CS_PROXY_SX127X
  sx127x::SX127x *sx127x_{nullptr};
#endif
  const char *region_{""};
  uint32_t frequency_hz_{0};
  uint8_t sf_{9};
  uint32_t bw_hz_{500000};
  uint8_t cr_{1};
  uint16_t preamble_{8};
  const char *server_host_{""};
  uint16_t server_port_{47800};
  std::vector<uint8_t> key_;
  std::vector<uint8_t> proxy_id_override_;
  bool downlink_enabled_{true};
  uint32_t budget_permille_{20};
  uint64_t dedupe_window_us_{30000000};
  uint16_t dedupe_size_{64};
  float rate_global_{20};
  float rate_device_{2};
  float rate_bootstrap_{5};

  // State
  uint8_t proxy_id_[8]{};
  uint32_t boot_id_{0};
  uint32_t seq_{0};
  std::unique_ptr<EnvelopeCodec> codec_;
  std::unique_ptr<ServerSeqGuard> seq_guard_;
  std::unique_ptr<DedupeCache> dedupe_;
  std::unique_ptr<RateLimiter> rate_;
  std::unique_ptr<AirtimeBudget> budget_;
  TxScheduler scheduler_;
  esp_timer_handle_t tx_timer_{nullptr};
  uint64_t tx_timer_at_{0};

  std::unique_ptr<socket::UDPSocket> socket_;
  socket::Ipv4Resolve resolver_;
  struct sockaddr_storage server_addr_ {};
  socklen_t server_addr_len_{0};
  uint64_t resolve_retry_at_{0};
  bool resolving_{false};

  bool connected_{false};
  uint64_t last_status_us_{0};
  uint64_t disconnected_since_us_{0};
  bool hello_sent_{false};
  uint64_t next_hello_us_{0};

  uint64_t last_loop_us_{0};
  uint64_t max_gap_us_{0};
  bool degraded_{false};
  uint64_t last_rssi_publish_us_{0};
  std::vector<uint32_t> server_tags_;

  uint32_t heard_{0};
  uint32_t forwarded_{0};
  uint32_t duplicates_{0};
  uint32_t invalid_{0};
  uint32_t rate_limited_{0};
  uint32_t tx_ok_{0};
  uint32_t tx_failed_{0};
  float last_rssi_{0};
  float last_snr_{0};

#ifdef USE_SENSOR
  sensor::Sensor *frames_heard_sensor_{nullptr};
  sensor::Sensor *frames_forwarded_sensor_{nullptr};
  sensor::Sensor *duplicates_sensor_{nullptr};
  sensor::Sensor *invalid_sensor_{nullptr};
  sensor::Sensor *rate_limited_sensor_{nullptr};
  sensor::Sensor *downlinks_sent_sensor_{nullptr};
  sensor::Sensor *downlinks_failed_sensor_{nullptr};
  sensor::Sensor *last_rssi_sensor_{nullptr};
  sensor::Sensor *last_snr_sensor_{nullptr};
  sensor::Sensor *max_loop_gap_sensor_{nullptr};
  sensor::Sensor *airtime_used_sensor_{nullptr};
#endif
#ifdef USE_BINARY_SENSOR
  binary_sensor::BinarySensor *server_connected_sensor_{nullptr};
#endif
};

}  // namespace esphome::cs_proxy
