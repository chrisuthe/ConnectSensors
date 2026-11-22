#include "proxy_engine.h"

#include <algorithm>
#include <cinttypes>

namespace esphome::cs_proxy {

ProxyEngine::ProxyEngine(const ProxyConfig &config, ProxyIo &io)
    : config_(config),
      io_(io),
      codec_(config.key, config.proxy_id),
      seq_guard_(config.boot_id),
      dedupe_(config.dedupe_size),
      rate_(config.rate_global, config.rate_device, 5, config.rate_bootstrap),
      budget_(config.budget_permille) {}

void ProxyEngine::log_(LogLevel level, const char *fmt, ...) {
  if (!this->io_.log_enabled(level))
    return;
  va_list args;
  va_start(args, fmt);
  this->io_.vlog(level, fmt, args);
  va_end(args);
}

// ------------------------------------------------------------------------ receive

void ProxyEngine::on_packet(const uint8_t *data, size_t len, float rssi, float snr) {
  const uint64_t now = this->io_.now_us();  // first, before anything else (06 section 5)
  const uint64_t gap = this->last_loop_us_ == 0 ? 0 : now - this->last_loop_us_;
  this->counters_.heard++;

  const bool online = this->io_.server_known() && this->io_.network_up();
  const RxVerdict verdict =
      classify_uplink(data, len, online, this->dedupe_, this->rate_, now, this->config_.dedupe_window_us);
  if (verdict == RxVerdict::INVALID) {
    this->counters_.invalid++;
    this->log_(LogLevel::Verbose, "Ignored packet of %u bytes (not a ConnectSensors uplink)", unsigned(len));
    return;
  }
  const FrameHeader h = parse_header(data);
  switch (verdict) {
    case RxVerdict::DUPLICATE:
      this->counters_.duplicates++;
      this->log_(LogLevel::Verbose, "Duplicate frame fcnt %" PRIu32, h.fcnt);
      return;
    case RxVerdict::RATE_LIMITED:
      this->counters_.rate_limited++;
      this->log_(LogLevel::Debug, "Rate limited frame from dev_tag %08" PRIx32, h.dev_tag);
      return;
    default:
      break;
  }
  // Offline frames still update RSSI/SNR: those sensors help debug coverage while
  // the server is unreachable.
  if (now - this->last_rssi_publish_us_ >= RSSI_PUBLISH_INTERVAL_US || this->last_rssi_publish_us_ == 0) {
    this->last_rssi_publish_us_ = now;
    this->io_.on_signal(rssi, snr);
  }

  if (verdict == RxVerdict::OFFLINE) {
    this->log_(LogLevel::Debug, "No server address or network; frame fcnt %" PRIu32 " dropped", h.fcnt);
    return;
  }
  const uint64_t allowed = std::min(this->io_.loop_interval_us(), TS_LOOP_INTERVAL_CAP_US) + TS_UNCERTAIN_EXTRA_US;
  const uint8_t flags = gap > allowed ? UPLINK_TS_UNCERTAIN : 0;
  uplink_body(this->body_buf_, now, rssi, snr, flags, data, len);
  this->send_(MSG_UPLINK, this->body_buf_.data(), this->body_buf_.size());
  this->counters_.forwarded++;
  this->log_(LogLevel::Debug,
             "Forwarded type %u net %08" PRIx32 " dev %08" PRIx32 " fcnt %" PRIu32 " rssi %.1f snr %.1f%s", h.type,
             h.net_tag, h.dev_tag, h.fcnt, rssi, snr, flags ? " (timestamp uncertain)" : "");
  if (this->io_.log_enabled(LogLevel::Verbose)) {
    static const char *const digits = "0123456789abcdef";
    char frame_hex[2 * FRAME_MAX + 1];
    size_t n = len > FRAME_MAX ? FRAME_MAX : len;
    for (size_t i = 0; i < n; i++) {
      frame_hex[2 * i] = digits[data[i] >> 4];
      frame_hex[2 * i + 1] = digits[data[i] & 15];
    }
    frame_hex[2 * n] = '\0';
    this->log_(LogLevel::Verbose, "Frame %s", frame_hex);
  }
}

// ------------------------------------------------------------------------ loop

uint64_t ProxyEngine::loop_start() {
  const uint64_t now = this->io_.now_us();
  if (this->last_loop_us_ != 0) {
    uint64_t gap = now - this->last_loop_us_;
    if (gap > this->max_gap_us_)
      this->max_gap_us_ = gap;
  }
  this->last_loop_us_ = now;
  return now;
}

void ProxyEngine::loop_end() {
  this->run_due_transmissions_();

  const uint64_t now = this->io_.now_us();
  if (!this->counters_published_ || now - this->last_counters_us_ >= COUNTERS_PUBLISH_INTERVAL_US) {
    this->counters_published_ = true;
    this->last_counters_us_ = now;
    this->io_.on_counters();
  }

  // HELLO right after the server address is known, then every 60 s.
  if (this->io_.server_known() && this->io_.network_up() && (!this->hello_sent_ || now >= this->next_hello_us_))
    this->send_hello_();

  if (this->connected_ && now - this->last_status_us_ > CONNECT_TIMEOUT_US) {
    this->log_(LogLevel::Warn, "No SERVER_STATUS for %" PRIu32 " s; server considered disconnected",
               uint32_t(CONNECT_TIMEOUT_US / 1000000));
    this->set_connected_(false);
    this->disconnected_since_us_ = now;
  }
  // Re-resolve a hostname after a long disconnect, in case its address changed.
  if (!this->connected_ && this->hello_sent_ && this->disconnected_since_us_ != 0 &&
      now - this->disconnected_since_us_ > REDISCOVER_AFTER_US) {
    this->log_(LogLevel::Info, "Resolving server address again");
    this->io_.rediscover();
    this->disconnected_since_us_ = now;
  }
}

// ------------------------------------------------------------------------ messages

bool ProxyEngine::send_(uint8_t type, const uint8_t *body, size_t body_len) {
  if (!this->io_.server_known())
    return false;
  this->codec_.build(this->msg_buf_, type, this->config_.boot_id, ++this->seq_, body, body_len);
  this->io_.send_datagram(this->msg_buf_.data(), this->msg_buf_.size());
  return true;
}

void ProxyEngine::send_tx_result_(uint32_t seq, uint8_t result, int32_t offset_us) {
  this->send_(MSG_TX_RESULT, tx_result_body(seq, result, offset_us));
}

void ProxyEngine::send_hello_() {
  const uint64_t now = this->io_.now_us();
  // Downlink capability is withdrawn while the main loop is unhealthy (06 section 7).
  this->degraded_ = this->max_gap_us_ > DEGRADED_GAP_US;
  HelloInfo h;
  h.caps = (this->config_.downlink_enabled && !this->degraded_) ? CAP_DOWNLINK : 0;
  h.region = this->config_.region;
  h.frequency_hz = this->config_.frequency_hz;
  h.sf = this->config_.sf;
  h.bw_khz = uint16_t(this->config_.bw_hz / 1000);
  h.uptime_s = uint32_t(now / 1000000);
  h.heard = this->counters_.heard;
  h.forwarded = this->counters_.forwarded;
  h.duplicates = this->counters_.duplicates;
  h.invalid = this->counters_.invalid;
  h.rate_limited = this->counters_.rate_limited;
  h.tx_ok = this->counters_.tx_ok;
  h.tx_failed = this->counters_.tx_failed;
  uint64_t gap_ms = this->max_gap_us_ / 1000;
  h.max_loop_gap_ms = uint16_t(gap_ms > 65535 ? 65535 : gap_ms);
  h.firmware = this->config_.firmware;
  h.request_nonce = this->request_nonce_;
  if (this->send_(MSG_HELLO, hello_body(h))) {
    this->hello_echoes_.sent(this->seq_, now);
    if (h.request_nonce != 0) {
      this->requested_hello_sent_ = true;
      this->requested_hello_us_ = now;
      this->request_nonce_ = 0;
    }
  }
  if (this->degraded_)
    this->log_(LogLevel::Warn, "Main loop stalled for %u ms; downlinks withdrawn until it recovers",
               h.max_loop_gap_ms);
  this->max_gap_us_ = 0;
  this->hello_sent_ = true;
  this->next_hello_us_ = now + HELLO_INTERVAL_US;
  this->io_.on_hello(h.max_loop_gap_ms);
}

void ProxyEngine::on_datagram(const uint8_t *data, size_t len, uint64_t now) {
  Envelope e{};
  if (!this->codec_.open(data, len, e)) {
    this->log_(LogLevel::Verbose, "Ignored %u-byte datagram (bad MAC, version or proxy ID)", unsigned(len));
    return;
  }
  if ((e.type & 0x80) == 0)
    return;  // not a server-to-proxy message
  if (!this->seq_guard_.current_boot(e.boot_id)) {
    this->log_(LogLevel::Debug, "Ignored server message for boot %08" PRIx32, e.boot_id);
    return;
  }
  // These two have their own rules for the server seq (05 section 3.2).
  if (e.type == MSG_HELLO_REQUEST) {
    this->handle_hello_request_(e, now);
    return;
  }
  if (e.type == MSG_SERVER_STATUS) {
    this->handle_server_status_(e, now);
    return;
  }
  if (!this->seq_guard_.accept(e.boot_id, e.seq)) {
    this->log_(LogLevel::Debug, "Ignored stale or replayed server message seq %" PRIu32, e.seq);
    return;
  }
  switch (e.type) {
    case MSG_DOWNLINK:
      this->handle_downlink_(e, now);
      break;
    default:
      this->log_(LogLevel::Verbose, "Ignored unknown message type 0x%02X", e.type);
      break;
  }
}

void ProxyEngine::handle_server_status_(const Envelope &e, uint64_t now) {
  ServerStatus st;
  if (!parse_server_status(e.body, e.body_len, st)) {
    this->log_(LogLevel::Warn, "Malformed SERVER_STATUS");
    return;
  }
  if (this->seq_guard_.accept(e.boot_id, e.seq)) {
    this->hello_echoes_.take(st.hello_seq, now);
  } else if (this->hello_echoes_.take(st.hello_seq, now)) {
    // A restarted server counts from 1 again; its echo of a HELLO we just sent proves
    // the message is fresh, so its seq becomes the floor.
    this->seq_guard_.resync(e.seq);
    this->log_(LogLevel::Info, "Server restarted; following its seq from %" PRIu32, e.seq);
  } else {
    this->log_(LogLevel::Debug, "Ignored stale or replayed SERVER_STATUS seq %" PRIu32, e.seq);
    return;
  }
  this->server_tags_ = st.tags;
  this->last_status_us_ = now;
  if (!this->connected_)
    this->log_(LogLevel::Info, "Connected to server (%u network tags)", unsigned(st.tags.size()));
  this->set_connected_(true);
  this->disconnected_since_us_ = 0;
}

void ProxyEngine::handle_hello_request_(const Envelope &e, uint64_t now) {
  // Not checked against the server seq: a server that does not know our boot has no
  // floor to match. A replay can only bring a HELLO forward, at most one per 5 s.
  uint32_t nonce;
  if (!parse_hello_request(e.body, e.body_len, nonce)) {
    this->log_(LogLevel::Debug, "Malformed HELLO_REQUEST");
    return;
  }
  this->request_nonce_ = nonce;
  uint64_t due = now;
  if (this->requested_hello_sent_ && this->requested_hello_us_ + HELLO_REQUEST_GAP_US > due)
    due = this->requested_hello_us_ + HELLO_REQUEST_GAP_US;
  if (!this->hello_sent_ || due < this->next_hello_us_)
    this->next_hello_us_ = due;
  this->log_(LogLevel::Debug, "Server asked for a HELLO");
}

void ProxyEngine::set_connected_(bool connected) {
  this->connected_ = connected;
  this->io_.on_connected(connected);
}

// ------------------------------------------------------------------------ transmit

void ProxyEngine::handle_downlink_(const Envelope &e, uint64_t now) {
  DownlinkRequest req;
  if (!parse_downlink(e.body, e.body_len, req)) {
    this->counters_.tx_failed++;
    this->send_tx_result_(e.seq, TX_INVALID, 0);
    return;
  }
  const uint64_t tx_at = req.ref_rx_time_us + req.tx_offset_us;
  const uint32_t airtime = lora_airtime_us(req.frame.size(), this->config_.sf, this->config_.bw_hz,
                                           this->config_.cr, this->config_.preamble);
  const bool capable = this->config_.downlink_enabled && !this->degraded_;
  uint8_t result =
      this->scheduler_.admit(e.seq, tx_at, req.frame.data(), req.frame.size(), airtime, now, capable, this->budget_);
  if (result != TX_SENT) {
    this->counters_.tx_failed++;
    this->log_(LogLevel::Debug, "Downlink seq %" PRIu32 " rejected: result %u", e.seq, result);
    this->send_tx_result_(e.seq, result, 0);
    return;
  }
  this->log_(LogLevel::Debug, "Downlink seq %" PRIu32 " scheduled in %" PRId64 " ms", e.seq,
             int64_t(tx_at - now) / 1000);
  this->arm_timer_();
}

void ProxyEngine::arm_timer_() {
  const uint64_t next = this->scheduler_.next_tx_at();
  if (next == 0 || next == this->timer_at_)
    return;
  this->io_.arm_timer(next > TIMER_LEAD_US ? next - TIMER_LEAD_US : next);
  this->timer_at_ = next;
}

void ProxyEngine::run_due_transmissions_() {
  // The radio is ours until the in-flight frame completes; the schedule keeps frames
  // at least an airtime plus the window apart, so the next one is not due yet.
  if (this->tx_in_flight_ != nullptr)
    return;
  for (;;) {
    uint64_t now = this->io_.now_us();
    // Wait out the last couple of milliseconds so the transmission starts on time.
    const uint64_t next = this->scheduler_.next_tx_at();
    if (next != 0 && next > now && next - now <= TIMER_LEAD_US) {
      this->io_.wait_until(next);
      now = this->io_.now_us();
    }
    ScheduledTx *slot = this->scheduler_.due(now);
    if (slot == nullptr)
      break;
    if (now > slot->tx_at_us + TX_WINDOW_US) {
      const uint8_t result = expired_result(*slot);
      this->counters_.tx_failed++;
      this->log_(LogLevel::Warn, "Downlink seq %" PRIu32 " missed its window by %" PRIu32 " ms (result %u)",
                 slot->seq, uint32_t((now - slot->tx_at_us) / 1000), result);
      this->send_tx_result_(slot->seq, result, 0);
      this->scheduler_.release(slot);
      continue;
    }
    // The radio fails the operation if it has not completed well after the airtime.
    const uint32_t timeout_ms = slot->airtime_us / 1000 + 100;
    const uint8_t started = this->io_.start_transmit(slot->frame, slot->len, timeout_ms);
    if (started == TX_SENT) {
      this->scheduler_.start(slot, this->io_.now_us());
      this->tx_in_flight_ = slot;
      this->timer_at_ = 0;
      return;  // on_transmit_complete() reports the result and re-arms the timer
    }
    if (started == TX_BUSY) {
      // A received packet is waiting; the radio delivers it in its own loop() and the
      // next pass retries until the window closes.
      slot->saw_busy = true;
      break;
    }
    this->counters_.tx_failed++;
    this->log_(LogLevel::Warn, "Radio refused downlink seq %" PRIu32, slot->seq);
    this->send_tx_result_(slot->seq, TX_RADIO_ERROR, 0);
    this->scheduler_.release(slot);
  }
  this->timer_at_ = 0;
  this->arm_timer_();
}

void ProxyEngine::on_transmit_complete(bool ok) {
  ScheduledTx *slot = this->tx_in_flight_;
  if (slot == nullptr)
    return;
  this->tx_in_flight_ = nullptr;
  // The radio accepted the frame, so it may have sent some or all of it whatever the
  // result: the airtime counts either way (06 section 8.2).
  this->budget_.spend(slot->airtime_us, this->io_.now_us());
  if (ok) {
    this->counters_.tx_ok++;
    this->log_(LogLevel::Debug, "Downlink seq %" PRIu32 " sent, TX commanded %.2f ms after target", slot->seq,
               slot->offset_us / 1000.0f);
    this->send_tx_result_(slot->seq, TX_SENT, slot->offset_us);
  } else {
    this->counters_.tx_failed++;
    this->log_(LogLevel::Warn, "Radio error sending downlink seq %" PRIu32, slot->seq);
    this->send_tx_result_(slot->seq, TX_RADIO_ERROR, 0);
  }
  this->scheduler_.release(slot);
  this->timer_at_ = 0;
  this->arm_timer_();
  // Anything that came due while the radio was busy goes out now, not at the next wake.
  this->io_.request_loop();
}

}  // namespace esphome::cs_proxy
