#include "proxy_core.h"

#include "cs_sha256.h"

#include <cmath>
#include <cstring>

namespace esphome::cs_proxy {

namespace {

uint32_t be32(const uint8_t *p) {
  return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | uint32_t(p[3]);
}

uint64_t be64(const uint8_t *p) { return (uint64_t(be32(p)) << 32) | be32(p + 4); }

}  // namespace

// ---------------------------------------------------------------- frames

static FrameCheck check_common(const uint8_t *data, size_t len) {
  if (len < FRAME_MIN || len > FRAME_MAX)
    return FrameCheck::BAD_LENGTH;
  if (data[0] != FRAME_MAGIC)
    return FrameCheck::BAD_MAGIC;
  if ((data[1] >> 4) != FRAME_VERSION)
    return FrameCheck::BAD_VERSION;
  return FrameCheck::OK;
}

FrameCheck check_uplink(const uint8_t *data, size_t len) {
  FrameCheck c = check_common(data, len);
  if (c != FrameCheck::OK)
    return c;
  uint8_t type = data[1] & 0x0F;
  if (type == 0x0 || type >= 0x8)
    return FrameCheck::BAD_TYPE;
  return FrameCheck::OK;
}

bool is_valid_downlink(const uint8_t *data, size_t len) {
  return check_common(data, len) == FrameCheck::OK && (data[1] & 0x0F) >= 0x8;
}

FrameHeader parse_header(const uint8_t *data) {
  return FrameHeader{uint8_t(data[1] & 0x0F), be32(data + 2), be32(data + 6), be32(data + 10)};
}

bool is_bootstrap(const FrameHeader &h) { return h.net_tag == 0 && h.dev_tag == 0; }

uint64_t frame_key(const uint8_t *data, size_t len) {
  uint8_t digest[32];
  sha256(data, len, digest);
  return be64(digest);
}

// ---------------------------------------------------------------- dedupe

bool DedupeCache::contains(uint64_t key, uint64_t now_us, uint64_t window_us) const {
  for (const auto &e : this->entries_) {
    if (e.used && e.key == key && now_us - e.time_us < window_us)
      return true;
  }
  return false;
}

void DedupeCache::insert(uint64_t key, uint64_t now_us) {
  Entry *target = nullptr;
  for (auto &e : this->entries_) {
    if (e.used && e.key == key) {  // refresh an existing entry
      target = &e;
      break;
    }
  }
  if (target == nullptr) {
    for (auto &e : this->entries_) {
      if (!e.used) {  // otherwise a free entry
        target = &e;
        break;
      }
    }
  }
  if (target == nullptr) {
    for (auto &e : this->entries_) {  // otherwise the oldest
      if (target == nullptr || e.time_us < target->time_us)
        target = &e;
    }
  }
  if (target == nullptr)
    return;
  target->key = key;
  target->time_us = now_us;
  target->used = true;
}

// ---------------------------------------------------------------- rate limits

bool TokenBucket::take(uint64_t now_us) {
  if (this->started_) {
    float elapsed_s = float(now_us - this->last_us_) / 1e6f;
    this->tokens_ += elapsed_s * this->rate_;
    if (this->tokens_ > this->burst_)
      this->tokens_ = this->burst_;
  }
  this->started_ = true;
  this->last_us_ = now_us;
  if (this->tokens_ >= 1.0f) {
    this->tokens_ -= 1.0f;
    return true;
  }
  return false;
}

RateLimiter::RateLimiter(float global_rate, float device_rate, float device_burst, float bootstrap_rate)
    : global_(global_rate, global_rate), bootstrap_(bootstrap_rate, 5), device_rate_(device_rate),
      device_burst_(device_burst) {}

bool RateLimiter::allow(const FrameHeader &h, uint64_t now_us) {
  // Per-device or bootstrap bucket first, so a noisy device does not drain the global bucket.
  if (is_bootstrap(h)) {
    if (!this->bootstrap_.take(now_us))
      return false;
  } else {
    Slot *slot = nullptr;
    for (auto &s : this->slots_) {
      if (s.used && s.dev_tag == h.dev_tag) {
        slot = &s;
        break;
      }
    }
    if (slot == nullptr) {
      for (auto &s : this->slots_) {
        if (!s.used) {
          slot = &s;
          break;
        }
      }
    }
    if (slot == nullptr) {
      slot = &this->slots_[0];
      for (auto &s : this->slots_) {
        if (s.last_used_us < slot->last_used_us)
          slot = &s;
      }
    }
    if (!slot->used || slot->dev_tag != h.dev_tag) {
      slot->used = true;
      slot->dev_tag = h.dev_tag;
      slot->bucket = TokenBucket(this->device_rate_, this->device_burst_);
    }
    slot->last_used_us = now_us;
    if (!slot->bucket.take(now_us))
      return false;
  }
  return this->global_.take(now_us);
}

// ---------------------------------------------------------------- receive pipeline

RxVerdict classify_uplink(const uint8_t *data, size_t len, bool online, DedupeCache &dedupe, RateLimiter &rate,
                          uint64_t now_us, uint64_t window_us) {
  if (check_uplink(data, len) != FrameCheck::OK)
    return RxVerdict::INVALID;
  // Before dedupe and rate limits, so a frame heard offline cannot block its own
  // retransmission once connected.
  if (!online)
    return RxVerdict::OFFLINE;
  const uint64_t key = frame_key(data, len);
  if (dedupe.contains(key, now_us, window_us))
    return RxVerdict::DUPLICATE;
  if (!rate.allow(parse_header(data), now_us))
    return RxVerdict::RATE_LIMITED;
  dedupe.insert(key, now_us);
  return RxVerdict::FORWARD;
}

// ---------------------------------------------------------------- airtime

uint32_t lora_airtime_us(size_t payload_len, uint8_t sf, uint32_t bw_hz, uint8_t cr, uint16_t preamble, bool crc) {
  double tsym = double(1u << sf) / double(bw_hz);
  int de = tsym > 0.016 ? 1 : 0;
  double num = 8.0 * double(payload_len) - 4.0 * sf + 28 + (crc ? 16 : 0);
  double n_payload = 8 + std::fmax(std::ceil(num / (4.0 * (sf - 2 * de))) * (cr + 4), 0.0);
  return uint32_t(std::lround(((preamble + 4.25) + n_payload) * tsym * 1e6));
}

void AirtimeBudget::roll_(uint64_t now_us) {
  uint64_t minute = now_us / 60000000ULL;
  if (!this->started_) {
    this->started_ = true;
    this->current_minute_ = minute;
    return;
  }
  uint64_t steps = minute - this->current_minute_;
  if (steps >= 60) {
    this->buckets_.fill(0);
  } else {
    for (uint64_t i = 1; i <= steps; i++)
      this->buckets_[(this->current_minute_ + i) % 60] = 0;
  }
  this->current_minute_ = minute;
}

uint64_t AirtimeBudget::used_us(uint64_t now_us) {
  this->roll_(now_us);
  uint64_t total = 0;
  for (auto b : this->buckets_)
    total += b;
  return total;
}

bool AirtimeBudget::can_spend(uint64_t airtime_us, uint64_t now_us, uint64_t reserved_us) {
  return this->used_us(now_us) + reserved_us + airtime_us <= this->budget_us_;
}

void AirtimeBudget::spend(uint64_t airtime_us, uint64_t now_us) {
  this->roll_(now_us);
  this->buckets_[this->current_minute_ % 60] += airtime_us;
}

// ---------------------------------------------------------------- envelope

void ByteWriter::u16(uint16_t v) {
  this->u8(uint8_t(v >> 8));
  this->u8(uint8_t(v));
}
void ByteWriter::u32(uint32_t v) {
  this->u16(uint16_t(v >> 16));
  this->u16(uint16_t(v));
}
void ByteWriter::u64(uint64_t v) {
  this->u32(uint32_t(v >> 32));
  this->u32(uint32_t(v));
}

EnvelopeCodec::EnvelopeCodec(const uint8_t key[16], const uint8_t proxy_id[8]) {
  std::memcpy(this->key_, key, 16);
  std::memcpy(this->proxy_id_, proxy_id, 8);
}

std::vector<uint8_t> EnvelopeCodec::build(uint8_t type, uint32_t boot_id, uint32_t seq,
                                          const std::vector<uint8_t> &body) const {
  std::vector<uint8_t> out;
  this->build(out, type, boot_id, seq, body.data(), body.size());
  return out;
}

void EnvelopeCodec::build(std::vector<uint8_t> &out, uint8_t type, uint32_t boot_id, uint32_t seq,
                          const uint8_t *body, size_t body_len) const {
  ByteWriter w(out);
  w.u8(ENV_VERSION);
  w.u8(type);
  w.bytes(this->proxy_id_, 8);
  w.u32(boot_id);
  w.u32(seq);
  w.bytes(body, body_len);
  uint8_t mac[32];
  hmac_sha256(this->key_, 16, w.buf.data(), w.buf.size(), mac);
  w.bytes(mac, ENV_MAC);
}

bool EnvelopeCodec::open(const uint8_t *data, size_t len, Envelope &out) const {
  if (len < ENV_MIN || data[0] != ENV_VERSION)
    return false;
  uint8_t mac[32];
  hmac_sha256(this->key_, 16, data, len - ENV_MAC, mac);
  if (!ct_equal(mac, data + len - ENV_MAC, ENV_MAC))
    return false;
  if (std::memcmp(data + 2, this->proxy_id_, 8) != 0)
    return false;
  out.type = data[1];
  out.boot_id = be32(data + 10);
  out.seq = be32(data + 14);
  out.body = data + ENV_HEADER;
  out.body_len = len - ENV_MIN;
  return true;
}

int16_t to_x10(float v) {
  float x = std::round(v * 10.0f);
  if (x > 32767.0f)
    x = 32767.0f;
  if (x < -32768.0f)
    x = -32768.0f;
  return int16_t(x);
}

std::vector<uint8_t> uplink_body(uint64_t rx_time_us, float rssi, float snr, uint8_t flags, const uint8_t *frame,
                                 size_t frame_len) {
  std::vector<uint8_t> out;
  uplink_body(out, rx_time_us, rssi, snr, flags, frame, frame_len);
  return out;
}

void uplink_body(std::vector<uint8_t> &out, uint64_t rx_time_us, float rssi, float snr, uint8_t flags,
                 const uint8_t *frame, size_t frame_len) {
  ByteWriter w(out);
  w.u64(rx_time_us);
  w.i16(to_x10(rssi));
  w.i16(to_x10(snr));
  w.u8(flags);
  w.u8(uint8_t(frame_len));
  w.bytes(frame, frame_len);
}

std::vector<uint8_t> hello_body(const HelloInfo &h) {
  ByteWriter w;
  w.u8(h.caps);
  w.u8(uint8_t(h.region.size()));
  w.bytes(reinterpret_cast<const uint8_t *>(h.region.data()), h.region.size());
  w.u32(h.frequency_hz);
  w.u8(h.sf);
  w.u16(h.bw_khz);
  w.u32(h.uptime_s);
  w.u32(h.heard);
  w.u32(h.forwarded);
  w.u32(h.duplicates);
  w.u32(h.invalid);
  w.u32(h.rate_limited);
  w.u32(h.tx_ok);
  w.u32(h.tx_failed);
  w.u16(h.max_loop_gap_ms);
  w.u32(h.request_nonce);
  size_t fw_len = h.firmware.size() > 255 ? 255 : h.firmware.size();
  w.u8(uint8_t(fw_len));
  w.bytes(reinterpret_cast<const uint8_t *>(h.firmware.data()), fw_len);
  return w.buf;
}

std::vector<uint8_t> tx_result_body(uint32_t downlink_seq, uint8_t result, int32_t offset_us) {
  ByteWriter w;
  w.u32(downlink_seq);
  w.u8(result);
  w.i32(offset_us);
  return w.buf;
}

bool parse_server_status(const uint8_t *body, size_t len, ServerStatus &out) {
  if (len < 9)
    return false;
  uint8_t n = body[8];
  if (n > 32 || len != 9 + size_t(n) * 4)
    return false;
  out.server_time = be32(body);
  out.hello_seq = be32(body + 4);
  out.tags.clear();
  for (uint8_t i = 0; i < n; i++)
    out.tags.push_back(be32(body + 9 + 4 * i));
  return true;
}

bool parse_hello_request(const uint8_t *body, size_t len, uint32_t &nonce) {
  if (len != 4)
    return false;
  nonce = be32(body);
  return nonce != 0;
}

bool parse_downlink(const uint8_t *body, size_t len, DownlinkRequest &out) {
  if (len < 13)
    return false;
  uint8_t frame_len = body[12];
  if (len != 13 + size_t(frame_len))
    return false;
  out.ref_rx_time_us = be64(body);
  out.tx_offset_us = be32(body + 8);
  out.frame.assign(body + 13, body + 13 + frame_len);
  return true;
}

bool ServerSeqGuard::accept(uint32_t boot_id, uint32_t seq) {
  if (boot_id != this->boot_id_ || seq <= this->last_seq_)
    return false;
  this->last_seq_ = seq;
  return true;
}

void HelloEchoes::sent(uint32_t seq, uint64_t now_us) {
  this->slots_[this->next_] = {seq, now_us};
  this->next_ = (this->next_ + 1) % HELLO_ECHO_SLOTS;
}

bool HelloEchoes::take(uint32_t hello_seq, uint64_t now_us) {
  if (hello_seq == 0)
    return false;
  for (auto &s : this->slots_) {
    if (s.seq == hello_seq && now_us - s.sent_us <= HELLO_ECHO_MAX_AGE_US) {
      s.seq = 0;
      return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------- transmit scheduling

uint64_t TxScheduler::reserved_us_() const {
  uint64_t total = 0;
  for (const auto &s : this->slots_) {
    if (s.active)
      total += s.airtime_us;
  }
  return total;
}

uint8_t TxScheduler::admit(uint32_t seq, uint64_t tx_at_us, const uint8_t *frame, size_t len, uint32_t airtime_us,
                           uint64_t now_us, bool capable, AirtimeBudget &budget) {
  if (!capable)
    return TX_NOT_CAPABLE;
  if (!is_valid_downlink(frame, len))
    return TX_INVALID;
  if (tx_at_us > now_us + TX_MAX_AHEAD_US)
    return TX_INVALID;
  if (tx_at_us + TX_WINDOW_US < now_us)
    return TX_TOO_LATE;
  if (!budget.can_spend(airtime_us, now_us, this->reserved_us_()))
    return TX_DUTY_CYCLE;
  ScheduledTx *free_slot = nullptr;
  for (auto &s : this->slots_) {
    if (!s.active) {
      if (free_slot == nullptr)
        free_slot = &s;
      continue;
    }
    // Each transmission occupies [tx_at, tx_at + airtime + window].
    uint64_t a0 = s.tx_at_us, a1 = s.tx_at_us + s.airtime_us + TX_WINDOW_US;
    uint64_t b0 = tx_at_us, b1 = tx_at_us + airtime_us + TX_WINDOW_US;
    if (a0 < b1 && b0 < a1)
      return TX_BUSY;
  }
  if (free_slot == nullptr)
    return TX_BUSY;
  free_slot->active = true;
  free_slot->seq = seq;
  free_slot->tx_at_us = tx_at_us;
  free_slot->airtime_us = airtime_us;
  free_slot->len = uint8_t(len);
  std::memcpy(free_slot->frame, frame, len);
  return TX_SENT;
}

ScheduledTx *TxScheduler::due(uint64_t now_us) {
  ScheduledTx *best = nullptr;
  for (auto &s : this->slots_) {
    if (s.active && !s.in_flight && s.tx_at_us <= now_us && (best == nullptr || s.tx_at_us < best->tx_at_us))
      best = &s;
  }
  return best;
}

uint64_t TxScheduler::next_tx_at() const {
  uint64_t best = 0;
  for (const auto &s : this->slots_) {
    if (s.active && !s.in_flight && (best == 0 || s.tx_at_us < best))
      best = s.tx_at_us;
  }
  return best;
}

void eui64_from_mac(const uint8_t mac[6], uint8_t out[8]) {
  out[0] = mac[0];
  out[1] = mac[1];
  out[2] = mac[2];
  out[3] = 0xFF;
  out[4] = 0xFE;
  out[5] = mac[3];
  out[6] = mac[4];
  out[7] = mac[5];
}

}  // namespace esphome::cs_proxy
