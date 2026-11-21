#include "cs_proxy.h"

#include "esphome/core/application.h"
#include "esphome/core/helpers.h"
#include "esphome/core/log.h"
#include "esphome/components/network/util.h"

namespace esphome::cs_proxy {

static const char *const TAG = "cs_proxy";

static constexpr uint64_t RESOLVE_RETRY_US = 10000000ULL;

void CSProxy::setup() {
  if (!this->proxy_id_override_.empty()) {
    std::copy(this->proxy_id_override_.begin(), this->proxy_id_override_.end(), this->proxy_id_);
  } else {
    uint8_t mac[6];
    get_mac_address_raw(mac);
    eui64_from_mac(mac, this->proxy_id_);
  }
  ProxyConfig config;
  do {
    if (!random_bytes(reinterpret_cast<uint8_t *>(&config.boot_id), sizeof(config.boot_id)))
      config.boot_id = random_uint32();
  } while (config.boot_id == 0);
  std::copy_n(this->key_.begin(), std::min(this->key_.size(), sizeof(config.key)), config.key);
  std::copy(this->proxy_id_, this->proxy_id_ + sizeof(this->proxy_id_), config.proxy_id);
  config.region = this->region_;
  config.frequency_hz = this->frequency_hz_;
  config.sf = this->sf_;
  config.bw_hz = this->bw_hz_;
  config.cr = this->cr_;
  config.preamble = this->preamble_;
  config.downlink_enabled = this->downlink_enabled_;
  config.budget_permille = this->budget_permille_;
  config.dedupe_window_us = this->dedupe_window_us_;
  config.dedupe_size = this->dedupe_size_;
  config.rate_global = this->rate_global_;
  config.rate_device = this->rate_device_;
  config.rate_bootstrap = this->rate_bootstrap_;
  config.firmware = std::string("cs_proxy ") + CS_PROXY_VERSION;
  ProxyIo &io = *this;  // the base is protected, so convert here and not inside make_unique
  this->engine_ = std::make_unique<ProxyEngine>(config, io);

  this->socket_ = socket::socket_ip_udp_loop_monitored(IPPROTO_IP);
  if (this->socket_ == nullptr) {
    ESP_LOGE(TAG, "Could not create UDP socket");
    this->mark_failed();
    return;
  }
  this->socket_->setblocking(false);
  struct sockaddr_storage any {};
  socklen_t any_len = socket::set_sockaddr_any(reinterpret_cast<struct sockaddr *>(&any), sizeof(any), 0);
  if (this->socket_->bind(reinterpret_cast<struct sockaddr *>(&any), any_len) != 0) {
    ESP_LOGE(TAG, "Could not bind UDP socket: errno %d", errno);
    this->mark_failed();
    return;
  }

  esp_timer_create_args_t args{};
  args.callback = &CSProxy::tx_timer_cb_;
  args.arg = this;
  args.name = "cs_proxy_tx";
  if (esp_timer_create(&args, &this->tx_timer_) != ESP_OK) {
    ESP_LOGW(TAG, "No high-resolution transmit timer; downlink timing relies on the main loop");
    this->tx_timer_ = nullptr;
  }

#ifdef USE_CS_PROXY_SX126X
  if (this->sx126x_ != nullptr)
    this->sx126x_->register_listener(this);
#endif
#ifdef USE_CS_PROXY_SX127X
  if (this->sx127x_ != nullptr)
    this->sx127x_->register_listener(this);
#endif
  this->on_connected(false);
}

void CSProxy::dump_config() {
  char id_hex[17];
  format_hex_to(id_hex, this->proxy_id_, sizeof(this->proxy_id_));
  ESP_LOGCONFIG(TAG,
                "ConnectSensors proxy %s:\n"
                "  Proxy ID: %s\n"
                "  Region: %s (%" PRIu32 " Hz, SF%u, %" PRIu32 " Hz)\n"
                "  Server: %s:%u\n"
                "  Downlinks: %s, airtime budget %.1f%%\n"
                "  Dedupe: %" PRIu32 " ms, %u entries",
                CS_PROXY_VERSION, id_hex, this->region_, this->frequency_hz_, this->sf_, this->bw_hz_,
                this->server_host_, this->server_port_, YESNO(this->downlink_enabled_),
                this->budget_permille_ / 10.0f, uint32_t(this->dedupe_window_us_ / 1000), this->dedupe_size_);
}

// ------------------------------------------------------------------------ radio and loop

void CSProxy::on_packet(const std::vector<uint8_t> &packet, float rssi, float snr) {
  this->engine_->on_packet(packet.data(), packet.size(), rssi, snr);
}

void CSProxy::loop() {
  const uint64_t now = this->engine_->loop_start();
  this->poll_server_address_(now);

  // Messages from the server.
  if (this->socket_ != nullptr) {
    uint8_t buf[256];
    for (int i = 0; i < 8 && this->socket_->ready(); i++) {
      ssize_t n = this->socket_->read(buf, sizeof(buf));
      if (n <= 0)
        break;
      this->engine_->on_datagram(buf, size_t(n), now);
    }
  }

  this->engine_->loop_end();
}

void CSProxy::poll_server_address_(uint64_t now) {
  if (this->server_addr_len_ != 0 || !network::is_connected())
    return;
  if (this->resolver_.ready()) {
    this->server_addr_len_ = this->resolver_.to_sockaddr(reinterpret_cast<struct sockaddr *>(&this->server_addr_),
                                                         sizeof(this->server_addr_), this->server_port_);
    if (this->server_addr_len_ != 0)
      ESP_LOGI(TAG, "Server %s resolved", this->server_host_);
    this->resolving_ = false;
    return;
  }
  if (this->resolver_.consume_failure()) {
    this->resolving_ = false;
    this->resolve_retry_at_ = now + RESOLVE_RETRY_US;
    ESP_LOGW(TAG, "Could not resolve server %s; retrying", this->server_host_);
    return;
  }
  if (!this->resolving_ && now >= this->resolve_retry_at_) {
    this->resolving_ = true;
    this->resolver_.start(this->server_host_, this->server_port_, TAG);
  }
}

// ------------------------------------------------------------------------ ProxyIo

void CSProxy::wait_until(uint64_t t_us) {
  while (this->now_us() < t_us) {
  }
}

uint64_t CSProxy::loop_interval_us() { return uint64_t(App.get_loop_interval()) * 1000; }

bool CSProxy::network_up() { return network::is_connected(); }

void CSProxy::send_datagram(const uint8_t *data, size_t len) {
  ssize_t sent = this->socket_->sendto(data, len, 0, reinterpret_cast<struct sockaddr *>(&this->server_addr_),
                                       this->server_addr_len_);
  if (sent < 0)
    ESP_LOGW(TAG, "sendto() failed: errno %d", errno);
}

void CSProxy::rediscover() {
  this->resolver_.forget();
  this->server_addr_len_ = 0;
  this->resolving_ = false;
}

void CSProxy::tx_timer_cb_(void *arg) { static_cast<CSProxy *>(arg)->enable_loop_soon_any_context(); }

void CSProxy::arm_timer(uint64_t wake_us) {
  if (this->tx_timer_ == nullptr)
    return;
  esp_timer_stop(this->tx_timer_);
  const uint64_t now = this->now_us();
  esp_timer_start_once(this->tx_timer_, wake_us > now ? wake_us - now : 1);
}

uint8_t CSProxy::start_transmit(const uint8_t *frame, size_t len, uint32_t timeout_ms) {
#ifdef USE_CS_PROXY_SX126X
  if (this->sx126x_ != nullptr) {
    switch (this->sx126x_->start_transmit_async(this, frame, len, timeout_ms)) {
      case sx126x::SX126xError::SX126X_ERROR_NONE:
        return TX_SENT;
      case sx126x::SX126xError::SX126X_ERROR_BUSY:
        return TX_BUSY;
      default:
        return TX_RADIO_ERROR;
    }
  }
#endif
#ifdef USE_CS_PROXY_SX127X
  if (this->sx127x_ != nullptr) {
    switch (this->sx127x_->start_transmit_async(this, frame, len, timeout_ms)) {
      case sx127x::SX127xError::SX127X_ERROR_NONE:
        return TX_SENT;
      case sx127x::SX127xError::SX127X_ERROR_BUSY:
        return TX_BUSY;
      default:
        return TX_RADIO_ERROR;
    }
  }
#endif
  return TX_RADIO_ERROR;
}

bool CSProxy::log_enabled(LogLevel level) { return int(level) <= ESPHOME_LOG_LEVEL; }

void CSProxy::vlog(LogLevel level, const char *fmt, va_list args) {
  esp_log_vprintf_(int(level), TAG, __LINE__, fmt, args);
}

// ------------------------------------------------------------------------ entities

void CSProxy::on_connected(bool connected) {
#ifdef USE_BINARY_SENSOR
  if (this->server_connected_sensor_ != nullptr)
    this->server_connected_sensor_->publish_state(connected);
#endif
}

void CSProxy::on_signal(float rssi, float snr) {
#ifdef USE_SENSOR
  if (this->last_rssi_sensor_ != nullptr)
    this->last_rssi_sensor_->publish_state(rssi);
  if (this->last_snr_sensor_ != nullptr)
    this->last_snr_sensor_->publish_state(snr);
#endif
}

void CSProxy::on_hello(uint16_t max_loop_gap_ms) {
#ifdef USE_SENSOR
  if (this->max_loop_gap_sensor_ != nullptr)
    this->max_loop_gap_sensor_->publish_state(max_loop_gap_ms);
#endif
  this->publish_counters_();
}

void CSProxy::publish_counters_() {
#ifdef USE_SENSOR
  auto pub = [](sensor::Sensor *s, float v) {
    if (s != nullptr)
      s->publish_state(v);
  };
  const ProxyCounters &c = this->engine_->counters();
  pub(this->frames_heard_sensor_, c.heard);
  pub(this->frames_forwarded_sensor_, c.forwarded);
  pub(this->duplicates_sensor_, c.duplicates);
  pub(this->invalid_sensor_, c.invalid);
  pub(this->rate_limited_sensor_, c.rate_limited);
  pub(this->downlinks_sent_sensor_, c.tx_ok);
  pub(this->downlinks_failed_sensor_, c.tx_failed);
  if (this->airtime_used_sensor_ != nullptr) {
    float pct = float(this->engine_->airtime_used_us()) / 3600e6f * 100.0f;
    this->airtime_used_sensor_->publish_state(pct);
  }
#endif
}

}  // namespace esphome::cs_proxy
