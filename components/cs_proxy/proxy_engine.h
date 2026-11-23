#pragma once

// The proxy's runtime behaviour (spec 06 sections 5-9): the receive pipeline and its
// counters, loop-gap tracking, HELLO and the connection state, server messages and
// the asynchronous transmit state machine. Like proxy_core it has no ESPHome
// dependency; everything platform-specific goes through ProxyIo, so the whole
// engine runs on the host under tests/proxy_core.

#include "proxy_core.h"

#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace esphome::cs_proxy {

static constexpr uint64_t HELLO_INTERVAL_US = 60000000ULL;     // 05 section 5.2
static constexpr uint64_t HELLO_REQUEST_GAP_US = 5000000ULL;   // 05 section 5.6
static constexpr uint64_t HELLO_CHANGE_GAP_US = 5000000ULL;    // 05 section 5.2, 06 section 7
static constexpr uint64_t CONNECT_TIMEOUT_US = 180000000ULL;   // 06 section 9
static constexpr uint64_t REDISCOVER_AFTER_US = 300000000ULL;  // 06 section 9
static constexpr uint64_t TS_UNCERTAIN_EXTRA_US = 20000;       // 06 section 7
// A longer configured loop interval would let the unflagged timestamp error grow past
// the 36 ms in the timing budget (01 section 4.1).
static constexpr uint64_t TS_LOOP_INTERVAL_CAP_US = 16000;
static constexpr uint64_t DEGRADED_GAP_US = 100000;            // 06 section 7
static constexpr uint64_t DEGRADED_WINDOW_US = 10000000ULL;    // 06 section 7
static constexpr uint64_t RSSI_PUBLISH_INTERVAL_US = 10000000ULL;
static constexpr uint64_t COUNTERS_PUBLISH_INTERVAL_US = 10000000ULL;  // 06 section 10.1
static constexpr uint64_t TIMER_LEAD_US = 2000;  // 06 section 8.2
// Allowed on top of the loop interval for the pass that sends a held downlink: its
// radio read and transmit command (06 section 8.2).
static constexpr uint64_t RX_HOLD_SLACK_US = 2000;

// Same numbers as ESPHOME_LOG_LEVEL_*, so the glue passes them straight through.
// Mixed case: ERROR, DEBUG and friends are macros on some platforms.
enum class LogLevel : uint8_t { Error = 1, Warn = 2, Info = 3, Debug = 5, Verbose = 6 };

class ProxyIo {
 public:
  virtual ~ProxyIo() = default;

  // Monotonic microsecond clock.
  virtual uint64_t now_us() = 0;
  // Return once now_us() >= t. Only asked for the last TIMER_LEAD_US before a transmission.
  virtual void wait_until(uint64_t t_us) = 0;
  // Current main-loop interval (App.get_loop_interval()).
  virtual uint64_t loop_interval_us() = 0;

  // A server address is known and a datagram can be sent to it.
  virtual bool server_known() = 0;
  // The network interface is up.
  virtual bool network_up() = 0;
  virtual void send_datagram(const uint8_t *data, size_t len) = 0;
  // Forget the resolved address so it is looked up again.
  virtual void rediscover() = 0;

  // A frame is arriving, or a received packet has not been delivered yet (the
  // radio's is_receiving()). Asked only while a downlink is due.
  virtual bool is_receiving() { return false; }
  // TX_SENT when the radio accepted the frame, TX_BUSY when a received packet is
  // waiting, TX_RADIO_ERROR otherwise. Completion comes back through
  // ProxyEngine::on_transmit_complete().
  virtual uint8_t start_transmit(const uint8_t *frame, size_t len, uint32_t timeout_ms) = 0;
  // Run a main-loop pass at about wake_us, replacing any earlier request. Early is
  // fine: a pass more than TIMER_LEAD_US early only arms the timer again.
  virtual void arm_timer(uint64_t wake_us) = 0;
  // Run the main loop again soon.
  virtual void request_loop() = 0;

  // Entities.
  virtual void on_connected(bool /*connected*/) {}
  virtual void on_signal(float /*rssi*/, float /*snr*/) {}
  // A HELLO went out, reporting max_loop_gap_ms for the interval it closes.
  virtual void on_hello(uint16_t /*max_loop_gap_ms*/) {}
  // Every COUNTERS_PUBLISH_INTERVAL_US, whether or not the server is reachable:
  // the counters matter most while it is not.
  virtual void on_counters() {}

  virtual bool log_enabled(LogLevel /*level*/) { return true; }
  virtual void vlog(LogLevel /*level*/, const char * /*fmt*/, va_list /*args*/) {}
};

struct ProxyConfig {
  uint8_t key[16]{};
  uint8_t proxy_id[8]{};
  uint32_t boot_id{0};
  std::string region;
  uint32_t frequency_hz{0};
  uint8_t sf{9};
  uint32_t bw_hz{500000};
  uint8_t cr{1};
  uint16_t preamble{8};
  bool downlink_enabled{true};
  uint32_t budget_permille{20};
  uint64_t dedupe_window_us{DEDUPE_WINDOW_DEFAULT_US};
  uint16_t dedupe_size{64};
  float rate_global{20};
  float rate_device{2};
  float rate_bootstrap{5};
  std::string firmware;
};

struct ProxyCounters {
  uint32_t heard{0};
  uint32_t forwarded{0};
  uint32_t duplicates{0};
  uint32_t invalid{0};
  uint32_t rate_limited{0};
  uint32_t tx_ok{0};
  uint32_t tx_failed{0};
};

class ProxyEngine {
 public:
  ProxyEngine(const ProxyConfig &config, ProxyIo &io);

  // Radio listener callback.
  void on_packet(const uint8_t *data, size_t len, float rssi, float snr);
  // Radio transmit-complete callback.
  void on_transmit_complete(bool ok);

  // A main-loop pass is split around the glue's own work (address resolution and
  // reading the socket): loop_start() first, then any on_datagram(), then loop_end().
  uint64_t loop_start();
  void on_datagram(const uint8_t *data, size_t len, uint64_t now_us);
  void loop_end();

  const ProxyCounters &counters() const { return this->counters_; }
  bool connected() const { return this->connected_; }
  // A main-loop gap over DEGRADED_GAP_US ended within the last DEGRADED_WINDOW_US.
  bool degraded() const { return this->degraded_at_(this->io_.now_us()); }
  const std::vector<uint32_t> &server_tags() const { return this->server_tags_; }
  uint64_t airtime_used_us() { return this->budget_.used_us(this->io_.now_us()); }

 protected:
  void handle_downlink_(const Envelope &e, uint64_t now);
  void handle_server_status_(const Envelope &e, uint64_t now);
  void handle_hello_request_(const Envelope &e, uint64_t now);
  void run_due_transmissions_();
  void arm_timer_();
  bool send_(uint8_t type, const std::vector<uint8_t> &body) { return this->send_(type, body.data(), body.size()); }
  bool send_(uint8_t type, const uint8_t *body, size_t body_len);
  void send_tx_result_(uint32_t seq, uint8_t result, int32_t offset_us);
  // scheduled: the periodic or requested HELLO. Otherwise it announces a capability
  // change and leaves the schedule and any pending request alone.
  void send_hello_(bool scheduled = true);
  void set_connected_(bool connected);
  bool degraded_at_(uint64_t now) const {
    return this->last_stall_us_ != 0 && now - this->last_stall_us_ < DEGRADED_WINDOW_US;
  }
  uint8_t caps_at_(uint64_t now) const {
    return (this->config_.downlink_enabled && !this->degraded_at_(now)) ? CAP_DOWNLINK : 0;
  }
  void log_(LogLevel level, const char *fmt, ...) __attribute__((format(printf, 3, 4)));

  ProxyConfig config_;
  ProxyIo &io_;
  EnvelopeCodec codec_;
  ServerSeqGuard seq_guard_;
  HelloEchoes hello_echoes_;
  DedupeCache dedupe_;
  RateLimiter rate_;
  AirtimeBudget budget_;
  TxScheduler scheduler_;
  uint32_t seq_{0};
  uint64_t timer_at_{0};
  ScheduledTx *tx_in_flight_{nullptr};

  bool connected_{false};
  uint64_t last_status_us_{0};
  uint64_t disconnected_since_us_{0};
  bool hello_sent_{false};
  uint64_t next_hello_us_{0};
  uint32_t request_nonce_{0};  // to echo in the next HELLO
  bool requested_hello_sent_{false};
  uint64_t requested_hello_us_{0};
  uint8_t advertised_caps_{0};  // caps in the last HELLO
  bool change_hello_sent_{false};
  uint64_t change_hello_us_{0};

  uint64_t last_loop_us_{0};
  // The last two completed gaps between this component's passes, newest first. A
  // packet can have arrived as early as the pass before the previous one (06 section 7).
  uint64_t recent_gaps_us_[2]{};
  uint64_t max_gap_us_{0};  // since the last HELLO, for reporting only
  uint64_t last_stall_us_{0};  // end of the last gap over DEGRADED_GAP_US
  uint64_t last_rssi_publish_us_{0};
  bool counters_published_{false};
  uint64_t last_counters_us_{0};
  std::vector<uint32_t> server_tags_;

  ProxyCounters counters_;
  // Reused for every forwarded frame, so the receive path does not allocate.
  std::vector<uint8_t> body_buf_;
  std::vector<uint8_t> msg_buf_;
};

}  // namespace esphome::cs_proxy
