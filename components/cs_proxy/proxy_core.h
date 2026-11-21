#pragma once

// Platform-independent logic of the ConnectSensors proxy (spec 02 section 12,
// spec 05, spec 06). Nothing here touches ESPHome, the radio or the network, so
// it is unit-tested on the host (tests/proxy_core).
//
// Times are microseconds on a monotonic 64-bit clock.

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace esphome::cs_proxy {

// ---------------------------------------------------------------- frames (02)

constexpr uint8_t FRAME_MAGIC = 0xC5;
constexpr uint8_t FRAME_VERSION = 1;
constexpr size_t FRAME_MIN = 23;
constexpr size_t FRAME_MAX = 86;

enum class FrameCheck : uint8_t { OK, BAD_LENGTH, BAD_MAGIC, BAD_VERSION, BAD_TYPE };

struct FrameHeader {
  uint8_t type;
  uint32_t net_tag;
  uint32_t dev_tag;
  uint32_t fcnt;
};

// Keyless checks for a received packet: an uplink type is required.
FrameCheck check_uplink(const uint8_t *data, size_t len);
// Keyless checks for a frame the server asks us to transmit: a downlink type is required.
bool is_valid_downlink(const uint8_t *data, size_t len);
// Header fields; only call after a successful check.
FrameHeader parse_header(const uint8_t *data);
bool is_bootstrap(const FrameHeader &h);
// First 8 bytes of SHA-256 over the whole frame, big-endian.
uint64_t frame_key(const uint8_t *data, size_t len);

// ---------------------------------------------------------------- dedupe (06 section 6)

class DedupeCache {
 public:
  explicit DedupeCache(size_t capacity) : entries_(capacity) {}
  // True if key was inserted less than window_us ago.
  bool contains(uint64_t key, uint64_t now_us, uint64_t window_us) const;
  void insert(uint64_t key, uint64_t now_us);

 private:
  struct Entry {
    uint64_t key{0};
    uint64_t time_us{0};
    bool used{false};
  };
  std::vector<Entry> entries_;
};

// ---------------------------------------------------------------- rate limits (06 section 6)

class TokenBucket {
 public:
  TokenBucket(float rate_per_s = 1, float burst = 1) : rate_(rate_per_s), burst_(burst), tokens_(burst) {}
  bool take(uint64_t now_us);

 private:
  float rate_;
  float burst_;
  float tokens_;
  uint64_t last_us_{0};
  bool started_{false};
};

class RateLimiter {
 public:
  RateLimiter(float global_rate, float device_rate, float device_burst, float bootstrap_rate);
  bool allow(const FrameHeader &h, uint64_t now_us);

 private:
  static constexpr size_t DEVICE_SLOTS = 32;
  struct Slot {
    uint32_t dev_tag{0};
    uint64_t last_used_us{0};
    bool used{false};
    TokenBucket bucket;
  };
  TokenBucket global_;
  TokenBucket bootstrap_;
  float device_rate_;
  float device_burst_;
  std::array<Slot, DEVICE_SLOTS> slots_{};
};

// ---------------------------------------------------------------- receive pipeline (06 section 5)

enum class RxVerdict : uint8_t { INVALID, OFFLINE, DUPLICATE, RATE_LIMITED, FORWARD };

// Steps 3-7 of the receive pipeline, in that order. online: a server address is
// known and the network is up. Only a FORWARD frame is inserted into the dedupe
// cache, and an INVALID or OFFLINE frame spends no rate-limit tokens.
RxVerdict classify_uplink(const uint8_t *data, size_t len, bool online, DedupeCache &dedupe, RateLimiter &rate,
                          uint64_t now_us, uint64_t window_us);

// ---------------------------------------------------------------- airtime (01 section 5)

// Semtech LoRa time-on-air. cr is 1..4 for 4/5..4/8. Explicit header.
uint32_t lora_airtime_us(size_t payload_len, uint8_t sf, uint32_t bw_hz, uint8_t cr = 1, uint16_t preamble = 8,
                         bool crc = true);

class AirtimeBudget {
 public:
  // budget_permille: allowed transmit time per hour in 1/1000 (20 = 2%).
  explicit AirtimeBudget(uint32_t budget_permille) : budget_us_(uint64_t(3600000000ULL) * budget_permille / 1000) {}
  uint64_t used_us(uint64_t now_us);
  bool can_spend(uint64_t airtime_us, uint64_t now_us, uint64_t reserved_us = 0);
  void spend(uint64_t airtime_us, uint64_t now_us);
  uint64_t budget_us() const { return this->budget_us_; }

 private:
  void roll_(uint64_t now_us);
  uint64_t budget_us_;
  std::array<uint64_t, 60> buckets_{};
  uint64_t current_minute_{0};
  bool started_{false};
};

// ---------------------------------------------------------------- envelope (05)

constexpr uint8_t ENV_VERSION = 1;
constexpr size_t ENV_HEADER = 18;
constexpr size_t ENV_MAC = 16;
constexpr size_t ENV_MIN = ENV_HEADER + ENV_MAC;

enum MsgType : uint8_t {
  MSG_UPLINK = 0x01,
  MSG_HELLO = 0x02,
  MSG_TX_RESULT = 0x03,
  MSG_SERVER_STATUS = 0x81,
  MSG_DOWNLINK = 0x82,
};

constexpr uint8_t UPLINK_TS_UNCERTAIN = 0x01;
constexpr uint8_t CAP_DOWNLINK = 0x01;

enum TxResult : uint8_t {
  TX_SENT = 0,
  TX_TOO_LATE = 1,
  TX_BUSY = 2,
  TX_DUTY_CYCLE = 3,
  TX_NOT_CAPABLE = 4,
  TX_INVALID = 5,
  TX_RADIO_ERROR = 6,
};

// Little helper for building big-endian bodies.
class ByteWriter {
 public:
  void u8(uint8_t v) { this->buf.push_back(v); }
  void u16(uint16_t v);
  void u32(uint32_t v);
  void u64(uint64_t v);
  void i16(int16_t v) { this->u16(uint16_t(v)); }
  void i32(int32_t v) { this->u32(uint32_t(v)); }
  void bytes(const uint8_t *p, size_t n) { this->buf.insert(this->buf.end(), p, p + n); }
  std::vector<uint8_t> buf;
};

struct Envelope {
  uint8_t type;
  uint32_t boot_id;
  uint32_t seq;
  const uint8_t *body;
  size_t body_len;
};

class EnvelopeCodec {
 public:
  EnvelopeCodec(const uint8_t key[16], const uint8_t proxy_id[8]);
  std::vector<uint8_t> build(uint8_t type, uint32_t boot_id, uint32_t seq, const std::vector<uint8_t> &body) const;
  // Checks version, MAC and proxy_id. Body points into data.
  bool open(const uint8_t *data, size_t len, Envelope &out) const;
  const uint8_t *proxy_id() const { return this->proxy_id_; }

 private:
  uint8_t key_[16];
  uint8_t proxy_id_[8];
};

int16_t to_x10(float v);
std::vector<uint8_t> uplink_body(uint64_t rx_time_us, float rssi, float snr, uint8_t flags, const uint8_t *frame,
                                 size_t frame_len);

struct HelloInfo {
  uint8_t caps{0};
  std::string region;
  uint32_t frequency_hz{0};
  uint8_t sf{0};
  uint16_t bw_khz{0};
  uint32_t uptime_s{0};
  uint32_t heard{0};
  uint32_t forwarded{0};
  uint32_t duplicates{0};
  uint32_t invalid{0};
  uint32_t rate_limited{0};
  uint32_t tx_ok{0};
  uint32_t tx_failed{0};
  uint16_t max_loop_gap_ms{0};
  std::string firmware;
};
std::vector<uint8_t> hello_body(const HelloInfo &h);
std::vector<uint8_t> tx_result_body(uint32_t downlink_seq, uint8_t result, int32_t offset_us);

struct ServerStatus {
  uint32_t server_time;
  std::vector<uint32_t> tags;
};
bool parse_server_status(const uint8_t *body, size_t len, ServerStatus &out);

struct DownlinkRequest {
  uint64_t ref_rx_time_us;
  uint32_t tx_offset_us;
  std::vector<uint8_t> frame;
};
bool parse_downlink(const uint8_t *body, size_t len, DownlinkRequest &out);

// Replay protection for messages from the server (05 section 3.2).
class ServerSeqGuard {
 public:
  explicit ServerSeqGuard(uint32_t boot_id) : boot_id_(boot_id) {}
  bool accept(uint32_t boot_id, uint32_t seq);

 private:
  uint32_t boot_id_;
  uint32_t last_seq_{0};
};

// ---------------------------------------------------------------- transmit scheduling (06 section 8)

constexpr uint64_t TX_WINDOW_US = 100000;       // late tolerance after tx_at
constexpr uint64_t TX_MAX_AHEAD_US = 5000000;  // tx_at must be within 5 s
constexpr size_t TX_SLOTS = 4;

struct ScheduledTx {
  bool active{false};
  bool in_flight{false};  // handed to the radio, awaiting completion
  bool saw_busy{false};   // the radio refused it at least once with a received packet waiting
  uint32_t seq{0};
  uint64_t tx_at_us{0};
  uint32_t airtime_us{0};
  uint8_t len{0};
  uint8_t frame[FRAME_MAX]{};
};

// Result for a slot whose transmit window passed without a transmission: BUSY if the
// radio kept refusing it, TOO_LATE otherwise (06 section 8.2).
inline uint8_t expired_result(const ScheduledTx &slot) { return slot.saw_busy ? TX_BUSY : TX_TOO_LATE; }

class TxScheduler {
 public:
  // Returns TX_SENT when the downlink was scheduled, or the rejection result.
  uint8_t admit(uint32_t seq, uint64_t tx_at_us, const uint8_t *frame, size_t len, uint32_t airtime_us,
                uint64_t now_us, bool capable, AirtimeBudget &budget);
  // The earliest waiting slot whose tx_at has passed, or nullptr. In-flight slots are
  // not returned but still occupy the schedule and the budget reservation.
  ScheduledTx *due(uint64_t now_us);
  // Earliest waiting tx_at, or 0 if none.
  uint64_t next_tx_at() const;
  void start(ScheduledTx *slot) { slot->in_flight = true; }
  void release(ScheduledTx *slot) {
    slot->active = false;
    slot->in_flight = false;
    slot->saw_busy = false;
  }

 private:
  uint64_t reserved_us_() const;
  std::array<ScheduledTx, TX_SLOTS> slots_{};
};

// EUI-64 from a 48-bit MAC (05 section 4.1).
void eui64_from_mac(const uint8_t mac[6], uint8_t out[8]);

}  // namespace esphome::cs_proxy
