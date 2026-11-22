#pragma once

// Platform-independent sensor side of the ConnectSensors protocol: frames (spec 02),
// payloads (03), pairing (04) and sensor behaviour (08). Nothing here touches
// ESPHome or a radio driver; the platform is injected through the interfaces below,
// so the core is unit-tested on the host (tests/sensor_core) with a fake clock.
//
// Times are microseconds on a monotonic 64-bit clock unless named otherwise.

#include <cstddef>
#include <cstdint>
#include <functional>

namespace esphome::cs_sensor {

// ---------------------------------------------------------------- frames (02)

constexpr uint8_t FRAME_MAGIC = 0xC5;
constexpr uint8_t FRAME_VERSION = 1;
constexpr size_t FRAME_HEADER = 14;
constexpr size_t FRAME_MIC = 8;
constexpr size_t FRAME_MIN = 23;
constexpr size_t FRAME_MAX = 86;
constexpr size_t PAYLOAD_MAX = 64;
constexpr size_t READINGS_MAX = PAYLOAD_MAX - 1;  // after uflags

enum FrameType : uint8_t {
  T_DATA = 0x1,
  T_DATA_CONFIRMED = 0x2,
  T_HEARTBEAT = 0x3,
  T_HEARTBEAT_CONFIRMED = 0x4,
  T_JOIN = 0x5,
  T_SYNC = 0x6,
  T_DOWNLINK = 0x8,
};

constexpr uint8_t UF_DL_ACK = 0x01;
constexpr uint8_t UF_TIME_UNSURE = 0x02;
constexpr uint8_t DF_PENDING = 0x01;

enum Command : uint8_t {
  CMD_SET_NETWORK = 0x01,
  CMD_SET_HEARTBEAT = 0x02,
  CMD_LEAVE = 0x03,
  CMD_KEY_EXCHANGE = 0x04,
  CMD_SET_VALUE = 0x40,
};

constexpr uint32_t EPOCH_SECONDS = 3600;
inline uint32_t epoch_of(uint32_t unix_time) { return unix_time / EPOCH_SECONDS; }

// k_enc and k_dev_tag derived from a base key (02 section 5.1).
struct KeySet {
  uint8_t dev_eui[8];
  uint8_t k_enc[16];
  uint8_t k_dev_tag[16];
};
void derive_keys(const uint8_t base[16], const uint8_t dev_eui[8], KeySet &out);
void derive_net_route(const uint8_t k_net[16], uint8_t out[16]);
// k_session from an X25519 exchange (02 section 5.3). False on an all-zero shared value.
bool derive_session(const uint8_t k_root[16], const uint8_t dev_eui[8], const uint8_t own_private[32],
                    const uint8_t peer_public[32], const uint8_t sensor_pub[32], const uint8_t server_pub[32],
                    uint8_t out[16]);

// 4-byte tags, big-endian as sent, with the reserved-value substitution (02 section 6).
uint32_t net_tag(const uint8_t k_net_route[16], uint32_t epoch);
uint32_t dev_tag(const uint8_t k_dev_tag[16], uint32_t epoch);

struct FrameHeader {
  uint8_t type;
  uint32_t net_tag;
  uint32_t dev_tag;
  uint32_t fcnt;
};

// Builds a whole frame into out (FRAME_HEADER + len + FRAME_MIC bytes). The
// direction byte of the nonce follows the type. False if len is out of range.
bool seal_frame(const KeySet &keys, uint8_t type, uint32_t ntag, uint32_t dtag, uint32_t fcnt,
                const uint8_t *plaintext, size_t len, uint8_t *out, size_t &out_len);
// Structural checks (02 section 3), then the MIC. Writes the plaintext.
enum class OpenResult : uint8_t { OK, BAD_FRAME, BAD_MIC };
OpenResult open_frame(const KeySet &keys, const uint8_t *frame, size_t len, FrameHeader &hdr, uint8_t *plaintext,
                      size_t &pt_len);

// ---------------------------------------------------------------- readings (03)

constexpr size_t READING_VALUE_MAX = 60;

// 0..2 fixed size classes (1, 2, 4 bytes); 3 is length-prefixed.
inline uint8_t size_class(uint8_t kind) { return kind >> 6; }

struct Reading {
  uint8_t channel{0};
  uint8_t kind{0};
  uint8_t len{0};  // value bytes, without the class 3 length prefix
  uint8_t value[READING_VALUE_MAX]{};

  // Big-endian values; false if the kind's size class does not match.
  static bool make(uint8_t channel, uint8_t kind, const uint8_t *value, size_t len, Reading &out);
  static Reading u8(uint8_t channel, uint8_t kind, uint8_t v);
  static Reading u16(uint8_t channel, uint8_t kind, uint16_t v);
  static Reading i16(uint8_t channel, uint8_t kind, int16_t v);
  static Reading u32(uint8_t channel, uint8_t kind, uint32_t v);
  static Reading i32(uint8_t channel, uint8_t kind, int32_t v);
  static Reading f32(uint8_t channel, uint8_t kind, float v);
  size_t encoded_size() const { return 2 + (size_class(this->kind) == 3 ? 1 : 0) + this->len; }
  bool same_key(const Reading &o) const { return o.channel == this->channel && o.kind == this->kind; }
  // Unsigned big-endian value of a fixed-size reading, sign-extended for the
  // signed kinds of 03 section 4.
  int64_t as_int() const;
};

// A reading list being built: rejects kind 0, duplicate (channel, kind) pairs and
// anything that would not fit (03 section 2).
class ReadingWriter {
 public:
  explicit ReadingWriter(size_t capacity = READINGS_MAX) : cap_(capacity < READINGS_MAX ? capacity : READINGS_MAX) {}
  bool add(const Reading &r);
  bool contains(uint8_t channel, uint8_t kind) const;
  bool fits(const Reading &r) const { return this->len_ + r.encoded_size() <= this->cap_; }
  const uint8_t *data() const { return this->buf_; }
  size_t size() const { return this->len_; }

 private:
  size_t cap_;
  uint8_t buf_[READINGS_MAX]{};
  size_t len_{0};
};

// Walks an encoded reading list. False if it is invalid (truncated, or kind 0);
// the callback has then seen only the readings before the fault.
bool decode_readings(const uint8_t *data, size_t len, const std::function<void(const Reading &)> &cb);

// ---------------------------------------------------------------- pairing code (04 section 3)

// "CS:1:<DEV_EUI>:<K_ROOT>:<REGION>:<PROFILE>:<CHECK>"; out needs 100 bytes.
bool pairing_code(const uint8_t dev_eui[8], const uint8_t k_root[16], const char *region, const char *profile,
                  char *out, size_t cap);

// ---------------------------------------------------------------- platform interfaces

class Clock {
 public:
  virtual ~Clock() = default;
  virtual uint64_t now_us() = 0;
  // Unix time from the RTC. False if the RTC has no time (for example the
  // batteries were out and it has no backup).
  virtual bool unix_time(uint32_t &out) = 0;
  virtual void set_unix_time(uint32_t t) = 0;
};

class Radio {
 public:
  virtual ~Radio() = default;
  // Start transmitting; the platform calls SensorCore::on_tx_done when it ends.
  // False if the radio refused, in which case the core tries again shortly.
  virtual bool transmit(const uint8_t *frame, size_t len) = 0;
  virtual void start_receive() = 0;
  virtual void stop_receive() = 0;
  // A packet is being received right now (preamble or header seen), so a window
  // must stay open until it completes (01 section 4).
  virtual bool receiving() { return false; }
  virtual uint32_t airtime_us(size_t len) = 0;
};

enum class Blob : uint8_t {
  COUNTER = 1,        // uint32 reserved uplink counter (02 section 8.2)
  ROOT_FLOOR = 2,     // uint32 (02 section 8.4)
  SESSION = 3,        // pairing state, k_session, k_net_route (04 section 4.6)
  SESSION_FLOOR = 4,  // uint32
  SETTINGS = 5,       // heartbeat interval
};

class Storage {
 public:
  virtual ~Storage() = default;
  // False if the blob is absent or not exactly len bytes.
  virtual bool load(Blob id, uint8_t *buf, size_t len) = 0;
  // True only once the write is durable.
  virtual bool save(Blob id, const uint8_t *buf, size_t len) = 0;
  virtual bool erase(Blob id) = 0;
};

class Random {
 public:
  virtual ~Random() = default;
  // Must be a CSPRNG: it makes the ephemeral X25519 keys.
  virtual void fill(uint8_t *buf, size_t len) = 0;
};

// ---------------------------------------------------------------- sensor core

enum class PairingState : uint8_t { UNPAIRED = 0, JOINING = 1, SESSION = 2, PAIRED = 3 };

// Why a received downlink was or was not accepted (02 section 10.2).
enum class DownlinkResult : uint8_t {
  ACCEPT,
  NO_WINDOW,       // not in an RX window of our latest uplink
  BAD_FRAME,       // structure, or not a DOWNLINK
  NO_KEYS,         // nothing to verify it with
  BAD_MIC,
  WRONG_REPLY_TO,
  AT_OR_BELOW_FLOOR,
  NO_KEY_EXCHANGE,  // JOINING, and the answer has no usable KEY_EXCHANGE
  EXCHANGE_FAILED,  // all-zero shared secret, or the new state could not be stored
};
const char *downlink_result_str(DownlinkResult r);

// For user feedback (08 section 11) and the platform's logging.
enum class SensorEvent : uint8_t {
  PAIRING_STARTED,
  PAIRED,
  PAIRING_FAILED,
  UPLINK_ANSWERED,     // a confirmed uplink was acknowledged
  UPLINK_UNDELIVERED,  // a confirmed uplink ran out of retries
  LEFT,                // LEAVE executed
  FACTORY_RESET,
  STORAGE_FAILED,      // a required write failed; the core stops transmitting what depends on it
  COUNTER_EXHAUSTED,   // 02 section 8.1
};

struct SensorConfig {
  uint8_t dev_eui[8]{};
  uint8_t k_root[16]{};
  // From the device profile; SET_HEARTBEAT overrides it (08 section 4.2).
  uint16_t heartbeat_minutes{60};
  bool has_firmware_version{false};
  uint8_t firmware_version[3]{};
  // 1% of an hour (01 section 5).
  uint32_t airtime_budget_us{36000000};
  // A paired sensor sends a confirmed heartbeat if none was answered for this long
  // (08 section 4.2, at most 24 hours).
  uint32_t confirm_interval_s{4 * 3600};
};

// Receive windows and retries (01 section 4, 08 section 5).
constexpr uint64_t RX1_DELAY_US = 1000000;
constexpr uint64_t RX2_DELAY_US = 3000000;
constexpr uint64_t RX_EARLY_US = 20000;
constexpr uint64_t RX_LATE_US = 150000;
constexpr uint64_t RX_EXTEND_MAX_US = 600000;  // longest frame at the slowest profile, with margin
constexpr uint64_t TX_TIMEOUT_US = 2000000;
constexpr uint64_t TX_REFUSED_BACKOFF_US = 100000;
constexpr uint8_t MAX_RETRIES = 3;
constexpr uint64_t RETRY_BASE_US[MAX_RETRIES] = {4000000, 12000000, 30000000};
constexpr uint64_t RETRY_JITTER_US[MAX_RETRIES] = {2000000, 4000000, 10000000};
constexpr uint8_t SYNC_AFTER_UNDELIVERED = 3;
constexpr uint64_t LOST_CONTACT_BACKOFF_US[4] = {60000000ULL, 300000000ULL, 900000000ULL, 3600000000ULL};
constexpr uint8_t MAX_PENDING_HEARTBEATS = 4;
constexpr uint32_t COUNTER_BLOCK = 64;
constexpr size_t STATE_SLOTS = 16;
constexpr size_t EVENT_SLOTS = 4;

class SensorCore {
 public:
  SensorCore(const SensorConfig &config, Clock &clock, Radio &radio, Storage &storage, Random &random);
  ~SensorCore();

  // Callbacks for application commands (03 section 8 and profile commands).
  std::function<void(const Reading &)> on_set_value;
  std::function<void(uint8_t cmd_id, const uint8_t *args, size_t len)> on_command;
  std::function<void(SensorEvent)> on_event;

  // Loads stored state and reserves a counter block (08 section 9). Call once after
  // a power-on or reset, after setting the initial state readings.
  void begin();
  // Drives timers and windows; call often while hold() is true.
  void loop();
  // From the radio.
  void on_tx_done();
  void on_tx_done(uint64_t at_us);
  void on_receive(const uint8_t *data, size_t len);

  // Current value of a state reading (contact, temperature, battery on channel
  // 0xFF...). The full state rides on every heartbeat (03 section 5). False if it
  // is not a valid reading or the full state would no longer fit in one frame.
  bool set_state(const Reading &r);
  // Queue a frame with the full state. Confirmed requests win when merged.
  void report(bool confirmed);
  // An event reading such as a button press: sent once, never in heartbeats.
  bool send_event(const Reading &r, bool confirmed = true);

  // Pairing button (04 section 4.5). factory_reset is for the platform to call once
  // the button has been held for 10 seconds.
  void short_press();
  void factory_reset();

  // Sleep hint: true while the core is transmitting, inside or waiting for an RX
  // window, holding retries, or about to send. The platform must not deep-sleep
  // through any of that.
  bool hold() const;
  // When loop() next has work: the next window edge, retry, or heartbeat.
  uint64_t next_wake_us() const;

  PairingState state() const { return this->state_; }
  uint32_t root_floor() const { return this->root_floor_; }
  uint32_t session_floor() const { return this->session_floor_; }
  uint32_t next_fcnt() const { return this->next_fcnt_; }
  uint16_t heartbeat_minutes() const { return this->heartbeat_minutes_; }
  uint8_t undelivered() const { return this->undelivered_; }
  bool time_sure() const { return this->time_sure_; }
  // For tests: the session key, or nullptr without one.
  const uint8_t *session_key() const { return this->has_session_ ? this->k_session_ : nullptr; }
  DownlinkResult last_downlink_result() const { return this->last_result_; }

 private:
  enum class Phase : uint8_t { IDLE, TX, WAIT_RX, RX, WAIT_RETRY };
  enum class Purpose : uint8_t { JOIN, SESSION_SYNC, STATE, HEARTBEAT, LEAVE_HEARTBEAT };

  struct Uplink {
    Purpose purpose{Purpose::STATE};
    uint8_t type{0};
    bool confirmed{false};
    bool has_event{false};
    uint32_t fcnt{0};
    uint8_t attempts{0};  // transmissions so far
    uint64_t first_done_us{0};
    uint64_t last_done_us{0};
    uint8_t len{0};
    uint8_t frame[FRAME_MAX]{};
  };

  void emit_(SensorEvent e);
  bool immediate_work_() const;
  void load_();
  bool reserve_(uint32_t fcnt);
  bool alloc_fcnt_(uint32_t &out);
  bool save_u32_(Blob id, uint32_t v);
  bool save_session_();
  void erase_session_();
  void wipe_ephemeral_();
  bool clock_known_();

  void start_next_(uint64_t now);
  bool build_(Purpose purpose, bool confirmed, uint64_t now);
  void encode_state_(ReadingWriter &w, bool events, bool firmware, bool &took_events);
  void transmit_(uint64_t now);
  void window_closed_(uint64_t now);
  void finish_answered_(uint64_t now);
  void finish_undelivered_(uint64_t now);
  void finish_unconfirmed_();
  void schedule_heartbeat_(uint64_t now);
  uint64_t jitter_(uint64_t range);
  bool budget_allows_(uint32_t airtime, uint64_t now);
  void budget_spend_(uint32_t airtime, uint64_t now);

  DownlinkResult process_downlink_(const uint8_t *data, size_t len, uint64_t now);
  void execute_commands_(const uint8_t *cmds, size_t len, bool &had_command, uint64_t now);
  void paired_(uint64_t now);
  void leave_now_();

  SensorConfig config_;
  Clock &clock_;
  Radio &radio_;
  Storage &storage_;
  Random &random_;
  KeySet root_keys_{};
  KeySet session_keys_{};

  // Persistent state.
  PairingState state_{PairingState::UNPAIRED};
  uint8_t k_session_[16]{};
  uint8_t k_net_route_[16]{};
  bool has_session_{false};
  bool has_route_{false};
  uint32_t root_floor_{0};
  uint32_t session_floor_{0};
  uint32_t reserved_{1};
  uint32_t next_fcnt_{1};
  bool counter_ok_{false};
  uint16_t heartbeat_minutes_{60};

  // Pairing in progress (RAM only, 04 section 4.6).
  uint8_t ephemeral_private_[32]{};
  uint8_t ephemeral_public_[32]{};
  bool has_ephemeral_{false};

  // Transmission cycle.
  Phase phase_{Phase::IDLE};
  Uplink cur_{};
  uint8_t rx_index_{0};
  bool rx_extended_{false};
  uint64_t tx_started_us_{0};
  uint64_t rx_open_us_{0};
  uint64_t rx_close_us_{0};
  uint64_t retry_at_us_{0};
  uint64_t tx_blocked_until_us_{0};

  // Work waiting to be sent.
  bool want_join_{false};
  bool want_session_sync_{false};
  bool want_state_{false};
  bool want_state_confirmed_{false};
  bool want_leave_heartbeat_{false};
  bool boot_uplink_{false};
  bool want_pending_hb_{false};
  uint64_t pending_hb_at_us_{0};
  uint8_t pending_hb_count_{0};
  bool hb_armed_{false};
  uint64_t next_hb_us_{0};

  // Readings.
  Reading state_readings_[STATE_SLOTS]{};
  size_t state_count_{0};
  Reading events_[EVENT_SLOTS]{};
  size_t event_count_{0};
  bool events_confirmed_{false};

  // Link and time.
  bool time_sure_{false};
  bool dl_ack_{false};
  bool firmware_sent_{false};
  uint8_t undelivered_{0};
  bool answered_ever_{false};
  uint64_t last_answered_us_{0};
  bool full_state_sent_{false};
  uint64_t last_full_state_us_{0};
  bool stopped_{false};  // counter exhausted
  DownlinkResult last_result_{DownlinkResult::NO_WINDOW};

  // Airtime: one bucket per minute over the last hour (08 section 4.4).
  uint32_t air_buckets_[60]{};
  uint64_t air_minute_{0};
  bool air_started_{false};
};

}  // namespace esphome::cs_sensor
