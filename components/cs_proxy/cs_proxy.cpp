#include "cs_proxy.h"

#include "esphome/core/application.h"
#include "esphome/core/helpers.h"
#include "esphome/core/log.h"
#include "esphome/components/network/util.h"

namespace esphome::cs_proxy {

static const char *const TAG = "cs_proxy";

static constexpr uint64_t HELLO_INTERVAL_US = 60000000ULL;      // 05 section 5.2
static constexpr uint64_t CONNECT_TIMEOUT_US = 180000000ULL;    // 06 section 9
static constexpr uint64_t REDISCOVER_AFTER_US = 300000000ULL;   // 06 section 9
static constexpr uint64_t RESOLVE_RETRY_US = 10000000ULL;
static constexpr uint64_t TS_UNCERTAIN_EXTRA_US = 20000;        // 06 section 7
static constexpr uint64_t DEGRADED_GAP_US = 100000;             // 06 section 7
static constexpr uint64_t RSSI_PUBLISH_INTERVAL_US = 10000000ULL;
static constexpr uint64_t TIMER_LEAD_US = 2000;

void CSProxy::setup() {
  if (!this->proxy_id_override_.empty()) {
    std::copy(this->proxy_id_override_.begin(), this->proxy_id_override_.end(), this->proxy_id_);
  } else {
    uint8_t mac[6];
    get_mac_address_raw(mac);
    eui64_from_mac(mac, this->proxy_id_);
  }
  do {
    if (!random_bytes(reinterpret_cast<uint8_t *>(&this->boot_id_), sizeof(this->boot_id_)))
      this->boot_id_ = random_uint32();
  } while (this->boot_id_ == 0);

  this->codec_ = std::make_unique<EnvelopeCodec>(this->key_.data(), this->proxy_id_);
  this->seq_guard_ = std::make_unique<ServerSeqGuard>(this->boot_id_);
  this->dedupe_ = std::make_unique<DedupeCache>(this->dedupe_size_);
  this->rate_ = std::make_unique<RateLimiter>(this->rate_global_, this->rate_device_, 5, this->rate_bootstrap_);
  this->budget_ = std::make_unique<AirtimeBudget>(this->budget_permille_);

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
  this->set_connected_(false);
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
                "  Dedupe: %" PRIu32 " s, %u entries",
                CS_PROXY_VERSION, id_hex, this->region_, this->frequency_hz_, this->sf_, this->bw_hz_,
                this->server_host_, this->server_port_, YESNO(this->downlink_enabled_),
                this->budget_permille_ / 10.0f, uint32_t(this->dedupe_window_us_ / 1000000), this->dedupe_size_);
}

// ------------------------------------------------------------------------ receive

void CSProxy::on_packet(const std::vector<uint8_t> &packet, float rssi, float snr) {
  const uint64_t now = now_us_();  // first, before anything else (06 section 5)
  const uint64_t gap = this->last_loop_us_ == 0 ? 0 : now - this->last_loop_us_;
  this->heard_++;

  const bool online = this->server_addr_len_ != 0 && network::is_connected();
  const RxVerdict verdict =
      classify_uplink(packet.data(), packet.size(), online, *this->dedupe_, *this->rate_, now, this->dedupe_window_us_);
  if (verdict == RxVerdict::INVALID) {
    this->invalid_++;
    ESP_LOGV(TAG, "Ignored packet of %u bytes (not a ConnectSensors uplink)", unsigned(packet.size()));
    return;
  }
  const FrameHeader h = parse_header(packet.data());
  switch (verdict) {
    case RxVerdict::OFFLINE:
      ESP_LOGD(TAG, "No server address or network; frame fcnt %" PRIu32 " dropped", h.fcnt);
      return;
    case RxVerdict::DUPLICATE:
      this->duplicates_++;
      ESP_LOGV(TAG, "Duplicate frame fcnt %" PRIu32, h.fcnt);
      return;
    case RxVerdict::RATE_LIMITED:
      this->rate_limited_++;
      ESP_LOGD(TAG, "Rate limited frame from dev_tag %08" PRIx32, h.dev_tag);
      return;
    default:
      break;
  }
  this->last_rssi_ = rssi;
  this->last_snr_ = snr;

#ifdef USE_SENSOR
  if (now - this->last_rssi_publish_us_ >= RSSI_PUBLISH_INTERVAL_US || this->last_rssi_publish_us_ == 0) {
    this->last_rssi_publish_us_ = now;
    if (this->last_rssi_sensor_ != nullptr)
      this->last_rssi_sensor_->publish_state(rssi);
    if (this->last_snr_sensor_ != nullptr)
      this->last_snr_sensor_->publish_state(snr);
  }
#endif

  const uint64_t loop_interval_us = uint64_t(App.get_loop_interval()) * 1000;
  const uint8_t flags = gap > loop_interval_us + TS_UNCERTAIN_EXTRA_US ? UPLINK_TS_UNCERTAIN : 0;
  this->send_(MSG_UPLINK, uplink_body(now, rssi, snr, flags, packet.data(), packet.size()));
  this->forwarded_++;
  ESP_LOGD(TAG, "Forwarded type %u net %08" PRIx32 " dev %08" PRIx32 " fcnt %" PRIu32 " rssi %.1f snr %.1f%s",
           h.type, h.net_tag, h.dev_tag, h.fcnt, rssi, snr, flags ? " (timestamp uncertain)" : "");
#if ESPHOME_LOG_LEVEL >= ESPHOME_LOG_LEVEL_VERBOSE
  char frame_hex[2 * FRAME_MAX + 1];
  format_hex_to(frame_hex, packet.data(), packet.size());
  ESP_LOGV(TAG, "Frame %s", frame_hex);
#endif
}

// ------------------------------------------------------------------------ loop

void CSProxy::loop() {
  uint64_t now = now_us_();
  if (this->last_loop_us_ != 0) {
    uint64_t gap = now - this->last_loop_us_;
    if (gap > this->max_gap_us_)
      this->max_gap_us_ = gap;
  }
  this->last_loop_us_ = now;

  this->poll_server_address_(now);

  // Messages from the server.
  if (this->socket_ != nullptr) {
    uint8_t buf[256];
    for (int i = 0; i < 8 && this->socket_->ready(); i++) {
      ssize_t n = this->socket_->read(buf, sizeof(buf));
      if (n <= 0)
        break;
      this->handle_message_(buf, size_t(n), now);
    }
  }

  this->run_due_transmissions_();

  // HELLO right after the server address is known, then every 60 s.
  now = now_us_();
  if (this->server_addr_len_ != 0 && network::is_connected() &&
      (!this->hello_sent_ || now >= this->next_hello_us_)) {
    this->send_hello_();
  }

  if (this->connected_ && now - this->last_status_us_ > CONNECT_TIMEOUT_US) {
    ESP_LOGW(TAG, "No SERVER_STATUS for %" PRIu32 " s; server considered disconnected",
             uint32_t(CONNECT_TIMEOUT_US / 1000000));
    this->set_connected_(false);
    this->disconnected_since_us_ = now;
  }
  // Re-resolve a hostname after a long disconnect, in case its address changed.
  if (!this->connected_ && this->hello_sent_ && this->disconnected_since_us_ != 0 &&
      now - this->disconnected_since_us_ > REDISCOVER_AFTER_US) {
    ESP_LOGI(TAG, "Resolving server address again");
    this->resolver_.forget();
    this->server_addr_len_ = 0;
    this->resolving_ = false;
    this->disconnected_since_us_ = now;
  }
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

// ------------------------------------------------------------------------ messages

void CSProxy::send_(uint8_t type, const std::vector<uint8_t> &body) {
  if (this->socket_ == nullptr || this->server_addr_len_ == 0)
    return;
  auto msg = this->codec_->build(type, this->boot_id_, ++this->seq_, body);
  ssize_t sent = this->socket_->sendto(msg.data(), msg.size(), 0,
                                       reinterpret_cast<struct sockaddr *>(&this->server_addr_),
                                       this->server_addr_len_);
  if (sent < 0)
    ESP_LOGW(TAG, "sendto() failed: errno %d", errno);
}

void CSProxy::send_tx_result_(uint32_t seq, uint8_t result, int32_t offset_us) {
  this->send_(MSG_TX_RESULT, tx_result_body(seq, result, offset_us));
}

void CSProxy::send_hello_() {
  const uint64_t now = now_us_();
  // Downlink capability is withdrawn while the main loop is unhealthy (06 section 7).
  this->degraded_ = this->max_gap_us_ > DEGRADED_GAP_US;
  HelloInfo h;
  h.caps = (this->downlink_enabled_ && !this->degraded_) ? CAP_DOWNLINK : 0;
  h.region = this->region_;
  h.frequency_hz = this->frequency_hz_;
  h.sf = this->sf_;
  h.bw_khz = uint16_t(this->bw_hz_ / 1000);
  h.uptime_s = uint32_t(now / 1000000);
  h.heard = this->heard_;
  h.forwarded = this->forwarded_;
  h.duplicates = this->duplicates_;
  h.invalid = this->invalid_;
  h.rate_limited = this->rate_limited_;
  h.tx_ok = this->tx_ok_;
  h.tx_failed = this->tx_failed_;
  uint64_t gap_ms = this->max_gap_us_ / 1000;
  h.max_loop_gap_ms = uint16_t(gap_ms > 65535 ? 65535 : gap_ms);
  h.firmware = std::string("cs_proxy ") + CS_PROXY_VERSION;
  this->send_(MSG_HELLO, hello_body(h));
  if (this->degraded_)
    ESP_LOGW(TAG, "Main loop stalled for %u ms; downlinks withdrawn until it recovers", h.max_loop_gap_ms);
#ifdef USE_SENSOR
  if (this->max_loop_gap_sensor_ != nullptr)
    this->max_loop_gap_sensor_->publish_state(h.max_loop_gap_ms);
#endif
  this->max_gap_us_ = 0;
  this->hello_sent_ = true;
  this->next_hello_us_ = now + HELLO_INTERVAL_US;
  this->publish_counters_();
}

void CSProxy::handle_message_(const uint8_t *data, size_t len, uint64_t now) {
  Envelope e{};
  if (!this->codec_->open(data, len, e)) {
    ESP_LOGV(TAG, "Ignored %u-byte datagram (bad MAC, version or proxy ID)", unsigned(len));
    return;
  }
  if ((e.type & 0x80) == 0)
    return;  // not a server-to-proxy message
  if (!this->seq_guard_->accept(e.boot_id, e.seq)) {
    ESP_LOGD(TAG, "Ignored stale or replayed server message seq %" PRIu32, e.seq);
    return;
  }
  switch (e.type) {
    case MSG_SERVER_STATUS: {
      ServerStatus st;
      if (!parse_server_status(e.body, e.body_len, st)) {
        ESP_LOGW(TAG, "Malformed SERVER_STATUS");
        return;
      }
      this->server_tags_ = st.tags;
      this->last_status_us_ = now;
      if (!this->connected_)
        ESP_LOGI(TAG, "Connected to server (%u network tags)", unsigned(st.tags.size()));
      this->set_connected_(true);
      this->disconnected_since_us_ = 0;
      break;
    }
    case MSG_DOWNLINK:
      this->handle_downlink_(e, now);
      break;
    default:
      ESP_LOGV(TAG, "Ignored unknown message type 0x%02X", e.type);
      break;
  }
}

// ------------------------------------------------------------------------ transmit

void CSProxy::handle_downlink_(const Envelope &e, uint64_t now) {
  DownlinkRequest req;
  if (!parse_downlink(e.body, e.body_len, req)) {
    this->tx_failed_++;
    this->send_tx_result_(e.seq, TX_INVALID, 0);
    return;
  }
  const uint64_t tx_at = req.ref_rx_time_us + req.tx_offset_us;
  const uint32_t airtime = lora_airtime_us(req.frame.size(), this->sf_, this->bw_hz_, this->cr_, this->preamble_);
  const bool capable = this->downlink_enabled_ && !this->degraded_;
  uint8_t result = this->scheduler_.admit(e.seq, tx_at, req.frame.data(), req.frame.size(), airtime, now, capable,
                                          *this->budget_);
  if (result != TX_SENT) {
    this->tx_failed_++;
    ESP_LOGD(TAG, "Downlink seq %" PRIu32 " rejected: result %u", e.seq, result);
    this->send_tx_result_(e.seq, result, 0);
    return;
  }
  ESP_LOGD(TAG, "Downlink seq %" PRIu32 " scheduled in %" PRId64 " ms", e.seq, int64_t(tx_at - now) / 1000);
  this->arm_tx_timer_();
}

void CSProxy::tx_timer_cb_(void *arg) { static_cast<CSProxy *>(arg)->enable_loop_soon_any_context(); }

void CSProxy::arm_tx_timer_() {
  if (this->tx_timer_ == nullptr)
    return;
  const uint64_t next = this->scheduler_.next_tx_at();
  if (next == 0 || next == this->tx_timer_at_)
    return;
  esp_timer_stop(this->tx_timer_);
  const uint64_t now = now_us_();
  const uint64_t wake = next > TIMER_LEAD_US ? next - TIMER_LEAD_US : next;
  esp_timer_start_once(this->tx_timer_, wake > now ? wake - now : 1);
  this->tx_timer_at_ = next;
}

void CSProxy::run_due_transmissions_() {
  // The radio is ours until the in-flight frame completes; the schedule keeps frames
  // at least an airtime plus the window apart, so the next one is not due yet.
  if (this->tx_in_flight_ != nullptr)
    return;
  for (;;) {
    uint64_t now = now_us_();
    // Busy-wait the last couple of milliseconds so the transmission starts on time.
    const uint64_t next = this->scheduler_.next_tx_at();
    if (next != 0 && next > now && next - now <= TIMER_LEAD_US) {
      while (now_us_() < next) {
      }
      now = now_us_();
    }
    ScheduledTx *slot = this->scheduler_.due(now);
    if (slot == nullptr)
      break;
    if (now > slot->tx_at_us + TX_WINDOW_US) {
      const uint8_t result = expired_result(*slot);
      this->tx_failed_++;
      ESP_LOGW(TAG, "Downlink seq %" PRIu32 " missed its window by %" PRIu32 " ms (result %u)", slot->seq,
               uint32_t((now - slot->tx_at_us) / 1000), result);
      this->send_tx_result_(slot->seq, result, 0);
      this->scheduler_.release(slot);
      continue;
    }
    const int32_t offset = int32_t(now - slot->tx_at_us);
    const uint8_t started = this->radio_start_transmit_(*slot);
    if (started == TX_SENT) {
      this->scheduler_.start(slot);
      this->tx_in_flight_ = slot;
      this->tx_offset_us_ = offset;
      this->tx_timer_at_ = 0;
      return;  // tx_complete_() reports the result and re-arms the timer
    }
    if (started == TX_BUSY) {
      // A received packet is waiting; the radio delivers it in its own loop() and the
      // next pass retries until the window closes.
      slot->saw_busy = true;
      break;
    }
    this->tx_failed_++;
    ESP_LOGW(TAG, "Radio refused downlink seq %" PRIu32, slot->seq);
    this->send_tx_result_(slot->seq, TX_RADIO_ERROR, 0);
    this->scheduler_.release(slot);
  }
  this->tx_timer_at_ = 0;
  this->arm_tx_timer_();
}

uint8_t CSProxy::radio_start_transmit_(const ScheduledTx &slot) {
  // The radio fails the operation if it has not completed well after the airtime.
  const uint32_t timeout_ms = slot.airtime_us / 1000 + 100;
#ifdef USE_CS_PROXY_SX126X
  if (this->sx126x_ != nullptr) {
    switch (this->sx126x_->start_transmit_async(this, slot.frame, slot.len, timeout_ms)) {
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
    switch (this->sx127x_->start_transmit_async(this, slot.frame, slot.len, timeout_ms)) {
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

void CSProxy::tx_complete_(bool ok) {
  ScheduledTx *slot = this->tx_in_flight_;
  if (slot == nullptr)
    return;
  this->tx_in_flight_ = nullptr;
  if (ok) {
    this->budget_->spend(slot->airtime_us, now_us_());
    this->tx_ok_++;
    ESP_LOGD(TAG, "Downlink seq %" PRIu32 " sent, %.1f ms after target", slot->seq, this->tx_offset_us_ / 1000.0f);
    this->send_tx_result_(slot->seq, TX_SENT, this->tx_offset_us_);
  } else {
    this->tx_failed_++;
    ESP_LOGW(TAG, "Radio error sending downlink seq %" PRIu32, slot->seq);
    this->send_tx_result_(slot->seq, TX_RADIO_ERROR, 0);
  }
  this->scheduler_.release(slot);
  this->tx_timer_at_ = 0;
  this->arm_tx_timer_();
  // Anything that came due while the radio was busy goes out now, not at the next wake.
  this->enable_loop_soon_any_context();
}

// ------------------------------------------------------------------------ entities

void CSProxy::set_connected_(bool connected) {
  this->connected_ = connected;
#ifdef USE_BINARY_SENSOR
  if (this->server_connected_sensor_ != nullptr)
    this->server_connected_sensor_->publish_state(connected);
#endif
}

void CSProxy::publish_counters_() {
#ifdef USE_SENSOR
  auto pub = [](sensor::Sensor *s, float v) {
    if (s != nullptr)
      s->publish_state(v);
  };
  pub(this->frames_heard_sensor_, this->heard_);
  pub(this->frames_forwarded_sensor_, this->forwarded_);
  pub(this->duplicates_sensor_, this->duplicates_);
  pub(this->invalid_sensor_, this->invalid_);
  pub(this->rate_limited_sensor_, this->rate_limited_);
  pub(this->downlinks_sent_sensor_, this->tx_ok_);
  pub(this->downlinks_failed_sensor_, this->tx_failed_);
  if (this->airtime_used_sensor_ != nullptr) {
    float pct = float(this->budget_->used_us(now_us_())) / 3600e6f * 100.0f;
    this->airtime_used_sensor_->publish_state(pct);
  }
#endif
}

}  // namespace esphome::cs_proxy
