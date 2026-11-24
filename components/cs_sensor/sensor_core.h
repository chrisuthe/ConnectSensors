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

#include "cs_ed25519.h"

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
  CMD_SET_HEARTBEAT = 0x02,
  CMD_LEAVE = 0x03,
  CMD_KEY_EXCHANGE = 0x04,
  CMD_NOP = 0x05,
  CMD_SET_VALUE = 0x40,
};

constexpr uint32_t EPOCH_SECONDS = 3600;
inline uint32_t epoch_of(uint32_t unix_time) { return unix_time / EPOCH_SECONDS; }

constexpr size_t TAG_LEN = 8;
constexpr uint32_t TAG_BLOCK = 64;  // one bootstrap tag per counter reservation block (02 section 6.1)
inline bool is_bootstrap(uint8_t type) { return type == T_JOIN || type == T_SYNC; }
inline uint32_t tag_block(uint32_t fcnt) { return (fcnt - 1) / TAG_BLOCK; }

// k_enc and k_dev_tag derived from a base key (02 section 5.1).
struct KeySet {
  uint8_t dev_eui[8];
  uint8_t k_enc[16];
  uint8_t k_dev_tag[16];
};
void derive_keys(const uint8_t base[16], const uint8_t dev_eui[8], KeySet &out);
// k_session from an X25519 exchange (02 section 5.3). False on an all-zero shared value.
bool derive_session(const uint8_t k_root[16], const uint8_t dev_eui[8], const uint8_t own_private[32],
                    const uint8_t peer_public[32], const uint8_t sensor_pub[32], const uint8_t server_pub[32],
                    uint8_t out[16]);

// Key-fingerprint tags (02 section 6.1): one Ed25519 key generation each.
// Normal frames take the epoch's tag, JOIN and SYNC the counter block's.
void normal_tag(const uint8_t k_dev_tag[16], uint32_t epoch, uint8_t out[TAG_LEN]);
void bootstrap_tag(const uint8_t k_dev_tag[16], uint32_t fcnt, uint8_t out[TAG_LEN]);

struct FrameHeader {
  uint8_t type;
  uint8_t tag[TAG_LEN];
  uint32_t fcnt;
};

// Builds a whole frame into out (FRAME_HEADER + len + FRAME_MIC bytes). The
// direction byte of the nonce follows the type. False if len is out of range.
bool seal_frame(const KeySet &keys, uint8_t type, const uint8_t tag[TAG_LEN], uint32_t fcnt,
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

// When a new value of a state reading is worth a frame of its own (08 section 4.1).
// The platform feeds it the values its sensor publishes; the core only sees the
// frames that result.
struct ReportedReading {
  float scale{1};  // to wire units; with delta 0, one wire step is a change
  bool confirmed{false};
  uint32_t min_interval_ms{0};
  float delta{0};  // < 0: rides on frames sent for other reasons, never causes one

  bool has_value{false};
  float value{0};
  // The last value a frame carried, if one has since boot.
  bool has_sent{false};
  float sent{0};
  uint64_t sent_us{0};  // min_interval runs from here

  // The value differs from what a frame last carried, or none has carried one.
  bool changed() const;
  bool due(uint64_t now_us) const { return this->changed() && now_us - this->sent_us >= this->min_interval_us(); }
  // When due() turns true if the value stays as it is.
  uint64_t due_at_us() const { return this->sent_us + this->min_interval_us(); }
  // A frame with the current value has been queued.
  void carried() {
    if (this->has_value) {
      this->has_sent = true;
      this->sent = this->value;
    }
  }
  // Boot: the boot uplink carries the values there are now (08 section 9); a value
  // that first comes later is reported as a change.
  void boot(uint64_t now_us) {
    this->has_sent = false;
    this->sent_us = now_us;
    this->carried();
  }
  uint64_t min_interval_us() const { return uint64_t(this->min_interval_ms) * 1000; }
};

// ---------------------------------------------------------------- pairing code (04 section 3)

// "CS:1:<DEV_EUI>:<K_ROOT>:<REGION>:<PROFILE>:<CHECK>"; out needs 100 bytes.
bool pairing_code(const uint8_t dev_eui[8], const uint8_t k_root[16], const char *region, const char *profile,
                  char *out, size_t cap);

// ---------------------------------------------------------------- airtime (01 section 5.1)

// Semtech LoRa time on air, explicit header and CRC on, rounded up. cr is 1..4 for
// 4/5..4/8. Low data rate optimization above a 16 ms symbol, as the radio sets it.
uint32_t lora_airtime_us(size_t len, uint8_t sf, uint32_t bw_hz, uint8_t cr = 1, uint16_t preamble = 8);

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
  SESSION = 3,        // pairing state, k_session; only once PAIRED (04 section 4.6)
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
  // (08 section 4.2); values above 24 hours are treated as 24 (08 section 3.3).
  uint32_t confirm_interval_s{4 * 3600};
};

// Receive windows and retries (01 section 4, 08 section 5).
constexpr uint64_t RX1_DELAY_US = 1000000;
constexpr uint64_t RX2_DELAY_US = 3000000;
constexpr uint64_t RX_EARLY_US = 20000;
constexpr uint64_t RX_LATE_US = 150000;  // W for US915, the only profile built; EU868 needs 200 ms (01 section 4)
constexpr uint64_t RX_EXTEND_MAX_US = 600000;  // longest frame at the slowest profile, with margin
constexpr uint64_t TX_TIMEOUT_US = 2000000;
constexpr uint64_t TX_REFUSED_BACKOFF_US = 100000;
// A radio refusing every transmission for this long has the attempt counted as made
// (08 section 4.3), so a wedged radio cannot hold the sensor on one frame.
constexpr uint64_t TX_REFUSED_MAX_US = 2000000;
constexpr uint8_t MAX_RETRIES = 3;
constexpr uint64_t RETRY_BASE_US[MAX_RETRIES] = {4000000, 12000000, 30000000};
constexpr uint64_t RETRY_JITTER_US[MAX_RETRIES] = {2000000, 4000000, 10000000};
constexpr uint8_t SYNC_AFTER_UNDELIVERED = 3;
constexpr uint64_t LOST_CONTACT_BACKOFF_US[4] = {60000000ULL, 300000000ULL, 900000000ULL, 3600000000ULL};
constexpr uint8_t MAX_PENDING_HEARTBEATS = 4;
// Compute the next epoch's tag this long before the boundary (08 section 3.2).
constexpr uint32_t TAG_PRECOMPUTE_LEAD_S = 300;
// Tags and the JOIN key pair are computed a slice at a time, at most this long per
// loop() pass, so key generation never blocks the loop.
constexpr uint64_t KEY_SLICE_US = 4000;
constexpr uint64_t MAX_CONFIRMED_GAP_US = 24ULL * 3600 * 1000000;
constexpr uint32_t COUNTER_BLOCK = 64;
constexpr size_t STATE_SLOTS = 16;
constexpr size_t EVENT_SLOTS = 4;

// The RAM state of an idle core, kept across a deep sleep (in RTC memory on ESP32)
// so that a wake carries on instead of booting: no new counter block, no boot
// uplink, no TIME_UNSURE, and the heartbeat schedule continues. Keys and anything
// else in Storage are loaded again, not copied. Plain bytes: the platform stores it
// as it is, and resume() rejects it if the check or the stored state disagrees.
struct WarmState {
  uint32_t magic;
  uint16_t version;
  uint16_t size;
  uint64_t saved_us;
  uint64_t last_answered_us;
  uint64_t last_confirmed_sent_us;
  uint64_t last_full_state_us;
  uint64_t next_hb_us;
  uint64_t tx_blocked_until_us;
  uint64_t air_minute;
  uint32_t air_buckets[61];
  uint32_t next_fcnt;
  uint32_t reserved;
  uint8_t state;
  uint8_t flags;
  uint8_t undelivered;
  uint8_t pending_hb_count;
  uint8_t state_count;
  uint8_t pad[3];
  Reading state_readings[STATE_SLOTS];
  // Normal tags already computed, so a wake does not repeat the key generation
  // (02 section 6.1). key_check ties them to the session key they came from.
  uint8_t tag_count;
  uint8_t pad2[3];
  uint8_t tag_key_check[4];
  uint32_t tag_epochs[2];
  uint8_t tags[2][TAG_LEN];
  uint32_t check;
};

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
  // Deep sleep. suspend() snapshots an idle core and is false while hold() is true.
  // After the wake, resume() takes the place of begin(); it is false, and the caller
  // must call begin() instead, if the snapshot is invalid, does not match storage,
  // or the monotonic clock did not carry on through the sleep.
  bool suspend(WarmState &out) const;
  bool resume(const WarmState &in);
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
  // window, holding retries, about to send, or computing a key. The platform must
  // not deep-sleep through any of that.
  bool hold() const;
  // When loop() next has work: the next window edge, retry or heartbeat, and with
  // precompute, also when the window opens for computing the next epoch's tag ahead
  // (08 section 3.2). A deep-sleep platform leaves that out: a wake just for it
  // costs more than the frame that may later wait a few passes for its tag.
  uint64_t next_wake_us(bool precompute = true) const;

  PairingState state() const { return this->state_; }
  uint32_t root_floor() const { return this->root_floor_; }
  uint32_t session_floor() const { return this->session_floor_; }
  uint32_t next_fcnt() const { return this->next_fcnt_; }
  uint16_t heartbeat_minutes() const { return this->heartbeat_minutes_; }
  uint8_t undelivered() const { return this->undelivered_; }
  bool time_sure() const { return this->time_sure_; }
  // The tag a new uplink of this type would carry now: the epoch's, or the block
  // of next_fcnt(). False without the keys or, for a normal tag, a clock.
  bool current_tag(uint8_t type, uint8_t out[TAG_LEN]);
  // For tests: Ed25519 key generations so far, cache misses only.
  uint32_t tag_computations() const { return this->tag_computations_; }
  // Key work, for the platform's debug log. Key generations done in slices: how
  // many so far, and the last one's time spent computing, slices (one or two per
  // loop pass) and longest slice.
  struct KeyWork {
    uint32_t jobs{0};
    bool last_was_tag{false};
    uint32_t last_us{0};
    uint32_t last_slices{0};
    uint32_t last_max_slice_us{0};
    // Frames whose tag was not ready and had to be computed at once. build_() waits
    // for a tag instead, so this stays 0 unless something is wrong.
    uint32_t sync_tags{0};
    // The X25519 shared secret for a KEY_EXCHANGE, computed at once when it arrives.
    uint32_t exchanges{0};
    uint32_t last_exchange_us{0};
  };
  const KeyWork &key_work() const { return this->key_work_stats_; }
  // For tests: the session key, or nullptr without one.
  const uint8_t *session_key() const { return this->has_session_ ? this->k_session_ : nullptr; }
  DownlinkResult last_downlink_result() const { return this->last_result_; }

 private:
  enum class Phase : uint8_t { IDLE, TX, WAIT_RX, RX, WAIT_RETRY };
  // SESSION_FIRST: the confirmed uplink of the provisional state (04 section 4.4 step 5).
  // FOLLOW_UP: the HEARTBEAT that PENDING asks for (08 section 7).
  enum class Purpose : uint8_t { JOIN, SESSION_FIRST, STATE, HEARTBEAT, LEAVE_HEARTBEAT, FOLLOW_UP };

  // Recently computed tags. Keygens are milliseconds, so they are not repeated
  // for every frame of an epoch or block.
  struct TagEntry {
    bool used{false};
    bool root{false};
    bool bootstrap{false};
    uint32_t n{0};  // epoch, or block
    uint32_t stamp{0};
    uint8_t tag[TAG_LEN]{};
  };
  static constexpr size_t TAG_CACHE = 4;

  struct Uplink {
    Purpose purpose{Purpose::STATE};
    uint8_t type{0};
    bool confirmed{false};
    bool has_event{false};
    bool has_firmware{false};
    uint32_t fcnt{0};
    uint8_t attempts{0};  // transmissions so far
    uint64_t refused_since_us{0};  // first refusal of the current attempt, 0 if none
    uint64_t first_done_us{0};
    uint64_t last_done_us{0};
    uint8_t len{0};
    uint8_t frame[FRAME_MAX]{};
  };

  void emit_(SensorEvent e);
  bool immediate_work_() const;
  void load_();
  void load_stored_();
  bool reserve_(uint32_t fcnt);
  bool alloc_fcnt_(uint32_t &out);
  bool save_u32_(Blob id, uint32_t v);
  bool save_session_();
  void erase_session_();
  void erase_blob_(Blob id, size_t len);
  void wipe_ephemeral_();
  bool clock_known_();
  int tag_index_(bool root, bool bootstrap, uint32_t n) const;  // -1 if not cached
  TagEntry &store_tag_(bool root, bool bootstrap, uint32_t n, const uint8_t tag[TAG_LEN]);
  void tag_for_(bool root, bool bootstrap, uint32_t n, uint8_t out[TAG_LEN]);
  void forget_session_tags_();
  void tag_key_check_(uint8_t out[4]) const;

  // Key work: what loop() computes next, a slice at a time.
  struct KeyTarget {
    enum class Kind : uint8_t { NONE, EPHEMERAL, TAG } kind{Kind::NONE};
    bool root{false};
    bool bootstrap{false};
    uint32_t n{0};  // epoch, or block
  };
  bool next_key_target_(KeyTarget &out) const;
  bool key_target_valid_(const KeyTarget &t) const;
  void key_work_(uint64_t deadline);
  void cancel_key_job_();
  bool key_work_pending_() const;
  // True if the tag is ready; otherwise asks loop() for it, and the frame waits.
  bool tag_ready_(bool root, bool bootstrap, uint32_t n);
  uint64_t precompute_wake_us_() const;

  void start_next_(uint64_t now);
  bool build_(Purpose purpose, bool confirmed, uint64_t now);
  void encode_state_(ReadingWriter &w, bool events, bool firmware, bool &took_events, bool &took_firmware);
  void transmit_(uint64_t now);
  void window_closed_(uint64_t now);
  void finish_answered_(uint64_t now);
  void finish_undelivered_(uint64_t now);
  void finish_unconfirmed_();
  void schedule_heartbeat_(uint64_t now);
  uint64_t cap_heartbeat_(uint64_t at) const;
  uint64_t jitter_(uint64_t range);
  bool budget_allows_(uint32_t airtime, uint64_t now);
  void budget_spend_(uint32_t airtime, uint64_t now);

  DownlinkResult process_downlink_(const uint8_t *data, size_t len, uint64_t now);
  void execute_commands_(const uint8_t *cmds, size_t len, bool &had_command, uint64_t now);
  bool paired_(uint64_t now);
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
  bool has_session_{false};
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
  bool ephemeral_pending_{false};  // private key drawn, public key being computed

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
  bool want_session_first_{false};
  bool want_state_{false};
  bool want_state_confirmed_{false};
  bool want_leave_heartbeat_{false};
  bool boot_uplink_{false};
  bool want_pending_hb_{false};
  bool pending_hb_confirmed_{false};
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
  bool confirmed_sent_{false};
  uint64_t last_confirmed_sent_us_{0};
  bool full_state_sent_{false};
  uint64_t last_full_state_us_{0};
  bool stopped_{false};  // counter exhausted
  DownlinkResult last_result_{DownlinkResult::NO_WINDOW};

  TagEntry tag_cache_[TAG_CACHE]{};
  uint32_t tag_stamp_{0};
  uint32_t tag_computations_{0};

  // Key work in progress, and the tag a frame is waiting for.
  BaseMulJob keygen_{};
  KeyTarget key_job_{};
  KeyTarget wanted_tag_{};
  KeyWork key_work_stats_{};
  uint32_t job_us_{0};
  uint32_t job_slices_{0};
  uint32_t job_max_slice_us_{0};

  // Airtime: one bucket per minute; 61 so the sum always covers a whole hour (08 section 4.4).
  uint32_t air_buckets_[61]{};
  uint64_t air_minute_{0};
  bool air_started_{false};
};

}  // namespace esphome::cs_sensor
