#include "sensor_core.h"

#include "cs_crypto.h"
#include "cs_ed25519.h"
#include "cs_sha256.h"
#include "cs_x25519.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>

namespace esphome::cs_sensor {

namespace {

constexpr uint8_t SESSION_BLOB_FORMAT = 2;
constexpr size_t SESSION_BLOB_LEN = 2 + 16;
constexpr uint32_t FCNT_LAST = 0xFFFFFFFF;

uint32_t be32(const uint8_t *p) { return uint32_t(p[0]) << 24 | uint32_t(p[1]) << 16 | uint32_t(p[2]) << 8 | p[3]; }

void put32(uint8_t *p, uint32_t v) {
  p[0] = uint8_t(v >> 24);
  p[1] = uint8_t(v >> 16);
  p[2] = uint8_t(v >> 8);
  p[3] = uint8_t(v);
}

bool is_downlink(uint8_t type) { return type >= 0x8; }

// 02 section 6.1: seed = HMAC(k_dev_tag, "cs1 tag seed" | kind | n), tag =
// SHA-256("cs1 tag fp" | Ed25519 public key of seed), first 8 bytes.
void tag_seed(const uint8_t k_dev_tag[16], bool bootstrap, uint32_t n, uint8_t seed[32]) {
  uint8_t msg[12 + 1 + 4];
  std::memcpy(msg, "cs1 tag seed", 12);
  msg[12] = uint8_t(bootstrap ? 'b' : 'e');
  put32(msg + 13, n);
  hmac_sha256(k_dev_tag, 16, msg, sizeof(msg), seed);
}

void tag_fingerprint(const uint8_t pub[32], uint8_t out[TAG_LEN]) {
  uint8_t fp[10 + 32];
  std::memcpy(fp, "cs1 tag fp", 10);
  std::memcpy(fp + 10, pub, 32);
  uint8_t digest[32];
  sha256(fp, sizeof(fp), digest);
  std::memcpy(out, digest, TAG_LEN);
}

void tag_of(const uint8_t k_dev_tag[16], bool bootstrap, uint32_t n, uint8_t out[TAG_LEN]) {
  uint8_t seed[32], pub[32];
  tag_seed(k_dev_tag, bootstrap, n, seed);
  cs_ed25519_public_key(seed, pub);
  secure_zero(seed, sizeof(seed));
  tag_fingerprint(pub, out);
}

}  // namespace

// ---------------------------------------------------------------- keys and frames (02)

void derive_keys(const uint8_t base[16], const uint8_t dev_eui[8], KeySet &out) {
  std::memcpy(out.dev_eui, dev_eui, 8);
  hkdf_sha256(base, 16, dev_eui, 8, reinterpret_cast<const uint8_t *>("cs1 enc"), 7, out.k_enc, 16);
  hkdf_sha256(base, 16, dev_eui, 8, reinterpret_cast<const uint8_t *>("cs1 tag"), 7, out.k_dev_tag, 16);
}

bool derive_session(const uint8_t k_root[16], const uint8_t dev_eui[8], const uint8_t own_private[32],
                    const uint8_t peer_public[32], const uint8_t sensor_pub[32], const uint8_t server_pub[32],
                    uint8_t out[16]) {
  uint8_t shared[32];
  x25519(shared, own_private, peer_public);
  static const uint8_t ZERO[32] = {0};
  if (ct_equal(shared, ZERO, 32)) {
    secure_zero(shared, sizeof(shared));
    return false;
  }
  uint8_t info[11 + 8 + 32 + 32];
  std::memcpy(info, "cs1 session", 11);
  std::memcpy(info + 11, dev_eui, 8);
  std::memcpy(info + 19, sensor_pub, 32);
  std::memcpy(info + 51, server_pub, 32);
  bool ok = hkdf_sha256(shared, 32, k_root, 16, info, sizeof(info), out, 16);
  secure_zero(shared, sizeof(shared));
  return ok;
}

void normal_tag(const uint8_t k_dev_tag[16], uint32_t epoch, uint8_t out[TAG_LEN]) { tag_of(k_dev_tag, false, epoch, out); }
void bootstrap_tag(const uint8_t k_dev_tag[16], uint32_t fcnt, uint8_t out[TAG_LEN]) {
  tag_of(k_dev_tag, true, tag_block(fcnt), out);
}

static void make_nonce(const KeySet &keys, uint32_t fcnt, uint8_t type, uint8_t nonce[13]) {
  std::memcpy(nonce, keys.dev_eui, 8);
  put32(nonce + 8, fcnt);
  nonce[12] = is_downlink(type) ? 0x01 : 0x00;
}

bool seal_frame(const KeySet &keys, uint8_t type, const uint8_t tag[TAG_LEN], uint32_t fcnt,
                const uint8_t *plaintext, size_t len, uint8_t *out, size_t &out_len) {
  if (len < 1 || len > PAYLOAD_MAX || type == 0 || type > 0xF)
    return false;
  out[0] = FRAME_MAGIC;
  out[1] = uint8_t(FRAME_VERSION << 4 | type);
  std::memcpy(out + 2, tag, TAG_LEN);
  put32(out + 10, fcnt);
  uint8_t nonce[13];
  make_nonce(keys, fcnt, type, nonce);
  ccm_seal(keys.k_enc, nonce, out, FRAME_HEADER, plaintext, len, out + FRAME_HEADER);
  out_len = FRAME_HEADER + len + FRAME_MIC;
  return true;
}

OpenResult open_frame(const KeySet &keys, const uint8_t *frame, size_t len, FrameHeader &hdr, uint8_t *plaintext,
                      size_t &pt_len) {
  if (len < FRAME_MIN || len > FRAME_MAX || frame[0] != FRAME_MAGIC || frame[1] >> 4 != FRAME_VERSION)
    return OpenResult::BAD_FRAME;
  hdr.type = frame[1] & 0x0F;
  std::memcpy(hdr.tag, frame + 2, TAG_LEN);
  hdr.fcnt = be32(frame + 10);
  uint8_t nonce[13];
  make_nonce(keys, hdr.fcnt, hdr.type, nonce);
  pt_len = len - FRAME_HEADER - FRAME_MIC;
  if (!ccm_open(keys.k_enc, nonce, frame, FRAME_HEADER, frame + FRAME_HEADER, pt_len, plaintext))
    return OpenResult::BAD_MIC;
  return OpenResult::OK;
}

// ---------------------------------------------------------------- readings (03)

namespace {
constexpr uint8_t FIXED_SIZE[3] = {1, 2, 4};
}

bool Reading::make(uint8_t channel, uint8_t kind, const uint8_t *value, size_t len, Reading &out) {
  if (kind == 0)
    return false;
  uint8_t cls = size_class(kind);
  if (cls == 3 ? len > READING_VALUE_MAX : len != FIXED_SIZE[cls])
    return false;
  out = Reading{};
  out.channel = channel;
  out.kind = kind;
  out.len = uint8_t(len);
  if (len)
    std::memcpy(out.value, value, len);
  return true;
}

Reading Reading::u8(uint8_t channel, uint8_t kind, uint8_t v) {
  Reading r;
  make(channel, kind, &v, 1, r);
  return r;
}

Reading Reading::u16(uint8_t channel, uint8_t kind, uint16_t v) {
  uint8_t b[2] = {uint8_t(v >> 8), uint8_t(v)};
  Reading r;
  make(channel, kind, b, 2, r);
  return r;
}

Reading Reading::i16(uint8_t channel, uint8_t kind, int16_t v) { return u16(channel, kind, uint16_t(v)); }

Reading Reading::u32(uint8_t channel, uint8_t kind, uint32_t v) {
  uint8_t b[4];
  put32(b, v);
  Reading r;
  make(channel, kind, b, 4, r);
  return r;
}

Reading Reading::i32(uint8_t channel, uint8_t kind, int32_t v) { return u32(channel, kind, uint32_t(v)); }

Reading Reading::f32(uint8_t channel, uint8_t kind, float v) {
  uint32_t bits;
  static_assert(sizeof(bits) == sizeof(v), "float is not 32 bits");
  std::memcpy(&bits, &v, 4);
  return u32(channel, kind, bits);
}

int64_t Reading::as_int() const {
  uint64_t u = 0;
  for (size_t i = 0; i < this->len && i < 8; i++)
    u = (u << 8) | this->value[i];
  switch (this->kind) {
    case 0x40:  // temperature
    case 0x4A:  // int16
      return int16_t(uint16_t(u));
    case 0x85:  // int32
      return int32_t(uint32_t(u));
    default:
      return int64_t(u);
  }
}

bool ReadingWriter::contains(uint8_t channel, uint8_t kind) const {
  bool found = false;
  decode_readings(this->buf_, this->len_, [&](const Reading &r) {
    if (r.channel == channel && r.kind == kind)
      found = true;
  });
  return found;
}

bool ReadingWriter::add(const Reading &r) {
  if (r.kind == 0 || !this->fits(r) || this->contains(r.channel, r.kind))
    return false;
  uint8_t *p = this->buf_ + this->len_;
  *p++ = r.channel;
  *p++ = r.kind;
  if (size_class(r.kind) == 3)
    *p++ = r.len;
  std::memcpy(p, r.value, r.len);
  this->len_ += r.encoded_size();
  return true;
}

bool decode_readings(const uint8_t *data, size_t len, const std::function<void(const Reading &)> &cb) {
  size_t i = 0;
  while (i < len) {
    if (i + 2 > len)
      return false;
    uint8_t channel = data[i], kind = data[i + 1];
    if (kind == 0)
      return false;  // 03 section 2: discard the rest
    i += 2;
    size_t size;
    if (size_class(kind) == 3) {
      if (i >= len)
        return false;
      size = data[i++];
      if (size > READING_VALUE_MAX)
        return false;
    } else {
      size = FIXED_SIZE[size_class(kind)];
    }
    if (i + size > len)
      return false;
    Reading r;
    Reading::make(channel, kind, data + i, size, r);
    cb(r);
    i += size;
  }
  return true;
}

bool ReportedReading::changed() const {
  if (!this->has_value || this->delta < 0)
    return false;
  if (!this->has_sent)
    return true;
  if (std::isnan(this->value) || std::isnan(this->sent))
    return std::isnan(this->value) != std::isnan(this->sent);
  if (this->delta == 0)  // any change the wire can show
    return std::round(this->value * this->scale) != std::round(this->sent * this->scale);
  return std::fabs(this->value - this->sent) >= this->delta;
}

// ---------------------------------------------------------------- pairing code (04 section 3)

bool pairing_code(const uint8_t dev_eui[8], const uint8_t k_root[16], const char *region, const char *profile,
                  char *out, size_t cap) {
  static const char *B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  char root32[27];
  size_t n = 0;
  uint32_t acc = 0;
  int bits = 0;
  for (int i = 0; i < 16; i++) {
    acc = (acc << 8) | k_root[i];
    bits += 8;
    while (bits >= 5) {
      root32[n++] = B32[(acc >> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0)
    root32[n++] = B32[(acc << (5 - bits)) & 31];
  root32[n] = 0;
  int len = std::snprintf(out, cap, "CS:1:%02X%02X%02X%02X%02X%02X%02X%02X:%s:%s:%s", dev_eui[0], dev_eui[1],
                          dev_eui[2], dev_eui[3], dev_eui[4], dev_eui[5], dev_eui[6], dev_eui[7], root32, region,
                          profile);
  if (len < 0 || size_t(len) + 5 >= cap)
    return false;
  uint8_t digest[32];
  sha256(reinterpret_cast<const uint8_t *>(out), size_t(len), digest);
  std::snprintf(out + len, cap - size_t(len), ":%02X%02X", digest[0], digest[1]);
  return true;
}

const char *downlink_result_str(DownlinkResult r) {
  switch (r) {
    case DownlinkResult::ACCEPT:
      return "accept";
    case DownlinkResult::NO_WINDOW:
      return "no_window";
    case DownlinkResult::BAD_FRAME:
      return "bad_frame";
    case DownlinkResult::NO_KEYS:
      return "no_keys";
    case DownlinkResult::BAD_MIC:
      return "bad_mic";
    case DownlinkResult::WRONG_REPLY_TO:
      return "wrong_reply_to";
    case DownlinkResult::AT_OR_BELOW_FLOOR:
      return "at_or_below_root_floor";
    case DownlinkResult::NO_KEY_EXCHANGE:
      return "no_key_exchange";
    case DownlinkResult::EXCHANGE_FAILED:
      return "exchange_failed";
  }
  return "?";
}

// ---------------------------------------------------------------- airtime (01 section 5.1)

uint32_t lora_airtime_us(size_t len, uint8_t sf, uint32_t bw_hz, uint8_t cr, uint16_t preamble) {
  const double tsym = double(1u << sf) / double(bw_hz);
  const int de = tsym > 0.016 ? 1 : 0;
  const int num = 8 * int(len) - 4 * sf + 28 + 16;
  const int den = 4 * (sf - 2 * de);
  // Truncating division rounds a negative num toward 0, which the max clamps anyway.
  const int n_payload = 8 + std::max((num + den - 1) / den * (cr + 4), 0);
  return uint32_t(std::ceil((preamble + 4.25 + n_payload) * tsym * 1e6));
}

// ---------------------------------------------------------------- sensor core

SensorCore::SensorCore(const SensorConfig &config, Clock &clock, Radio &radio, Storage &storage, Random &random)
    : config_(config), clock_(clock), radio_(radio), storage_(storage), random_(random) {
  derive_keys(this->config_.k_root, this->config_.dev_eui, this->root_keys_);
  this->heartbeat_minutes_ = this->config_.heartbeat_minutes;
}

SensorCore::~SensorCore() {
  secure_zero(this->k_session_, sizeof(this->k_session_));
  secure_zero(&this->root_keys_, sizeof(this->root_keys_));
  secure_zero(&this->session_keys_, sizeof(this->session_keys_));
  this->wipe_ephemeral_();
}

void SensorCore::emit_(SensorEvent e) {
  if (this->on_event)
    this->on_event(e);
}

// ---- persistence

bool SensorCore::save_u32_(Blob id, uint32_t v) {
  uint8_t b[4];
  put32(b, v);
  return this->storage_.save(id, b, 4);
}

bool SensorCore::reserve_(uint32_t fcnt) {
  uint32_t want = fcnt > FCNT_LAST - COUNTER_BLOCK ? FCNT_LAST : fcnt + COUNTER_BLOCK;
  if (!this->save_u32_(Blob::COUNTER, want))
    return false;
  this->reserved_ = want;
  return true;
}

bool SensorCore::alloc_fcnt_(uint32_t &out) {
  // 02 section 8.1: never wrap; the last value is never used.
  if (this->next_fcnt_ >= FCNT_LAST) {
    if (!this->stopped_) {
      this->stopped_ = true;
      this->emit_(SensorEvent::COUNTER_EXHAUSTED);
    }
    return false;
  }
  if (this->next_fcnt_ >= this->reserved_ && !this->reserve_(this->next_fcnt_)) {
    this->emit_(SensorEvent::STORAGE_FAILED);
    return false;
  }
  out = this->next_fcnt_++;
  return true;
}

bool SensorCore::save_session_() {
  uint8_t b[SESSION_BLOB_LEN];
  b[0] = SESSION_BLOB_FORMAT;
  b[1] = uint8_t(this->state_);
  std::memcpy(b + 2, this->k_session_, 16);
  bool ok = this->storage_.save(Blob::SESSION, b, sizeof(b));
  secure_zero(b, sizeof(b));
  return ok;
}

void SensorCore::load_() {
  uint8_t b[SESSION_BLOB_LEN];
  this->reserved_ = this->storage_.load(Blob::COUNTER, b, 4) ? be32(b) : 1;
  if (this->reserved_ == 0)
    this->reserved_ = 1;
  // 02 section 8.2 step 3: continue from the stored reservation and reserve a new block.
  this->next_fcnt_ = this->reserved_;
  this->counter_ok_ = this->reserve_(this->next_fcnt_);
  if (!this->counter_ok_)
    this->emit_(SensorEvent::STORAGE_FAILED);
  this->load_stored_();
}

void SensorCore::load_stored_() {
  uint8_t b[SESSION_BLOB_LEN];
  this->root_floor_ = this->storage_.load(Blob::ROOT_FLOOR, b, 4) ? be32(b) : 0;

  this->heartbeat_minutes_ = this->config_.heartbeat_minutes;
  if (this->storage_.load(Blob::SETTINGS, b, 2)) {
    uint16_t h = uint16_t(b[0] << 8 | b[1]);
    if (h >= 1 && h <= 1440)
      this->heartbeat_minutes_ = h;
  }

  // Only PAIRED is stored: a sensor that restarts mid-pairing starts the pairing over.
  this->state_ = PairingState::UNPAIRED;
  if (this->storage_.load(Blob::SESSION, b, SESSION_BLOB_LEN) && b[0] == SESSION_BLOB_FORMAT &&
      b[1] == uint8_t(PairingState::PAIRED)) {
    std::memcpy(this->k_session_, b + 2, 16);
    derive_keys(this->k_session_, this->config_.dev_eui, this->session_keys_);
    this->forget_session_tags_();
    this->has_session_ = true;
    this->state_ = PairingState::PAIRED;
    uint8_t f[4];
    this->session_floor_ = this->storage_.load(Blob::SESSION_FLOOR, f, 4) ? be32(f) : 0;
  }
  secure_zero(b, sizeof(b));
}

void SensorCore::wipe_ephemeral_() {
  if (this->key_job_.kind == KeyTarget::Kind::EPHEMERAL)
    this->cancel_key_job_();
  secure_zero(this->ephemeral_private_, sizeof(this->ephemeral_private_));
  secure_zero(this->ephemeral_public_, sizeof(this->ephemeral_public_));
  this->has_ephemeral_ = false;
  this->ephemeral_pending_ = false;
}

// Zeros load as "absent" for every blob, so they stand in for an erase that failed.
void SensorCore::erase_blob_(Blob id, size_t len) {
  static const uint8_t ZEROS[SESSION_BLOB_LEN] = {0};
  if (!this->storage_.erase(id) && !this->storage_.save(id, ZEROS, len))
    this->emit_(SensorEvent::STORAGE_FAILED);
}

void SensorCore::erase_session_() {
  secure_zero(this->k_session_, sizeof(this->k_session_));
  secure_zero(&this->session_keys_, sizeof(this->session_keys_));
  this->forget_session_tags_();
  this->has_session_ = false;
  this->session_floor_ = 0;
  this->erase_blob_(Blob::SESSION, SESSION_BLOB_LEN);
  this->erase_blob_(Blob::SESSION_FLOOR, 4);
  this->state_ = PairingState::UNPAIRED;
  this->want_join_ = this->want_session_first_ = this->want_state_ = this->want_state_confirmed_ = false;
  this->want_leave_heartbeat_ = this->boot_uplink_ = this->want_pending_hb_ = false;
  this->hb_armed_ = false;
  this->event_count_ = 0;
  this->events_confirmed_ = false;
  this->dl_ack_ = false;
  this->undelivered_ = 0;
  this->pending_hb_count_ = 0;
}

bool SensorCore::clock_known_() {
  uint32_t t;
  return this->clock_.unix_time(t);
}

// ---- tags

int SensorCore::tag_index_(bool root, bool bootstrap, uint32_t n) const {
  for (size_t i = 0; i < TAG_CACHE; i++) {
    const TagEntry &e = this->tag_cache_[i];
    if (e.used && e.root == root && e.bootstrap == bootstrap && e.n == n)
      return int(i);
  }
  return -1;
}

// Into an unused entry, or over the least recently used one.
SensorCore::TagEntry &SensorCore::store_tag_(bool root, bool bootstrap, uint32_t n, const uint8_t tag[TAG_LEN]) {
  TagEntry *slot = &this->tag_cache_[0];
  for (auto &e : this->tag_cache_) {
    if (!e.used || (slot->used && e.stamp < slot->stamp))
      slot = &e;
  }
  slot->used = true;
  slot->root = root;
  slot->bootstrap = bootstrap;
  slot->n = n;
  slot->stamp = ++this->tag_stamp_;
  std::memcpy(slot->tag, tag, TAG_LEN);
  return *slot;
}

// From the cache, or computed now, all at once.
void SensorCore::tag_for_(bool root, bool bootstrap, uint32_t n, uint8_t out[TAG_LEN]) {
  int i = this->tag_index_(root, bootstrap, n);
  if (i >= 0) {
    TagEntry &e = this->tag_cache_[i];
    e.stamp = ++this->tag_stamp_;
    std::memcpy(out, e.tag, TAG_LEN);
    return;
  }
  const uint8_t *key = root ? this->root_keys_.k_dev_tag : this->session_keys_.k_dev_tag;
  tag_of(key, bootstrap, n, out);
  this->tag_computations_++;
  this->store_tag_(root, bootstrap, n, out);
}

void SensorCore::forget_session_tags_() {
  for (auto &e : this->tag_cache_) {
    if (!e.root)
      e = TagEntry{};
  }
  // A session tag in progress, or waited for, belongs to keys that are gone.
  if (this->key_job_.kind == KeyTarget::Kind::TAG && !this->key_job_.root)
    this->cancel_key_job_();
  if (this->wanted_tag_.kind == KeyTarget::Kind::TAG && !this->wanted_tag_.root)
    this->wanted_tag_ = KeyTarget{};
}

bool SensorCore::current_tag(uint8_t type, uint8_t out[TAG_LEN]) {
  bool root = type == T_JOIN;
  if (!root && !this->has_session_)
    return false;
  if (is_bootstrap(type)) {
    this->tag_for_(root, true, tag_block(this->next_fcnt_), out);
    return true;
  }
  uint32_t t;
  if (!this->clock_.unix_time(t))
    return false;
  this->tag_for_(false, false, epoch_of(t), out);
  return true;
}

void SensorCore::tag_key_check_(uint8_t out[4]) const {
  uint8_t d[32];
  sha256(this->session_keys_.k_dev_tag, 16, d);
  std::memcpy(out, d, 4);
}

// ---- key work
//
// Each key generation runs in slices of at most KEY_SLICE_US per loop() pass. A
// frame whose tag is not ready waits for it (tag_ready_) rather than computing it on
// the spot, and the tags a frame is likely to need are computed ahead: the JOIN's key
// pair and tag right after the press, the next epoch's before the boundary, and a
// SYNC's block while SYNC is likely. The steps are the same for every key, so where
// a slice ends reveals nothing about it.

bool SensorCore::key_target_valid_(const KeyTarget &t) const {
  switch (t.kind) {
    case KeyTarget::Kind::EPHEMERAL:
      return this->ephemeral_pending_;
    case KeyTarget::Kind::TAG:
      return t.root || this->has_session_;
    default:
      return false;
  }
}

// Work in progress or due, which holds the core so the platform keeps calling loop().
bool SensorCore::key_work_pending_() const {
  KeyTarget t;
  return this->key_job_.kind != KeyTarget::Kind::NONE || this->next_key_target_(t);
}

bool SensorCore::tag_ready_(bool root, bool bootstrap, uint32_t n) {
  if (this->tag_index_(root, bootstrap, n) >= 0)
    return true;
  this->wanted_tag_ = KeyTarget{KeyTarget::Kind::TAG, root, bootstrap, n};
  return false;
}

bool SensorCore::next_key_target_(KeyTarget &out) const {
  using Kind = KeyTarget::Kind;
  auto want = [&](bool root, bool bootstrap, uint32_t n) {
    if (this->tag_index_(root, bootstrap, n) >= 0)
      return false;
    out = KeyTarget{Kind::TAG, root, bootstrap, n};
    return true;
  };
  // The JOIN key pair first, then the tag a frame is waiting for.
  if (this->ephemeral_pending_) {
    out = KeyTarget{Kind::EPHEMERAL};
    return true;
  }
  const KeyTarget &w = this->wanted_tag_;
  if (this->key_target_valid_(w) && want(w.root, w.bootstrap, w.n))
    return true;
  // Then ahead of need: the JOIN's tag (02 section 6.1),
  if (this->state_ == PairingState::JOINING && this->want_join_ && want(true, true, tag_block(this->next_fcnt_)))
    return true;
  if (!this->has_session_ || (this->state_ != PairingState::PAIRED && this->state_ != PairingState::SESSION))
    return false;
  uint32_t t;
  bool clock = this->clock_.unix_time(t);
  // the next epoch's before the boundary (08 section 3.2),
  if (clock && EPOCH_SECONDS - t % EPOCH_SECONDS <= TAG_PRECOMPUTE_LEAD_S && want(false, false, epoch_of(t) + 1))
    return true;
  // and, while frames go out as SYNC (08 sections 3.2 and 6), the block's of the next one.
  return (!clock || this->undelivered_ >= SYNC_AFTER_UNDELIVERED) && want(false, true, tag_block(this->next_fcnt_));
}

void SensorCore::cancel_key_job_() {
  this->keygen_.clear();
  this->key_job_ = KeyTarget{};
}

// Steps key generations until the deadline, but always at least one step.
void SensorCore::key_work_(uint64_t deadline) {
  using Kind = KeyTarget::Kind;
  for (bool first = true;; first = false) {
    const uint64_t start = this->clock_.now_us();
    if (!first && start >= deadline)
      return;
    if (this->key_job_.kind != Kind::NONE && !this->key_target_valid_(this->key_job_))
      this->cancel_key_job_();
    if (this->key_job_.kind == Kind::NONE) {
      KeyTarget t;
      if (!this->next_key_target_(t))
        return;
      this->key_job_ = t;
      this->job_us_ = this->job_slices_ = this->job_max_slice_us_ = 0;
      if (t.kind == Kind::EPHEMERAL) {
        this->keygen_.start_x25519(this->ephemeral_private_);
      } else {
        uint8_t seed[32];
        tag_seed(t.root ? this->root_keys_.k_dev_tag : this->session_keys_.k_dev_tag, t.bootstrap, t.n, seed);
        this->keygen_.start_ed25519(seed);
        secure_zero(seed, sizeof(seed));
      }
    }
    bool finished;
    uint64_t now;
    do {
      finished = this->keygen_.step();
      now = this->clock_.now_us();
    } while (!finished && now < deadline);
    const uint32_t slice = uint32_t(now - start);
    this->job_us_ += slice;
    this->job_slices_++;
    if (slice > this->job_max_slice_us_)
      this->job_max_slice_us_ = slice;
    if (!finished)
      return;

    const KeyTarget &j = this->key_job_;
    if (j.kind == Kind::EPHEMERAL) {
      std::memcpy(this->ephemeral_public_, this->keygen_.result(), 32);
      this->has_ephemeral_ = true;
      this->ephemeral_pending_ = false;
    } else {
      uint8_t tag[TAG_LEN];
      tag_fingerprint(this->keygen_.result(), tag);
      this->store_tag_(j.root, j.bootstrap, j.n, tag);
      this->tag_computations_++;
    }
    KeyWork &k = this->key_work_stats_;
    k.jobs++;
    k.last_was_tag = j.kind == Kind::TAG;
    k.last_us = this->job_us_;
    k.last_slices = this->job_slices_;
    k.last_max_slice_us = this->job_max_slice_us_;
    this->cancel_key_job_();
  }
}

// ---- public API

void SensorCore::begin() {
  this->load_();
  this->time_sure_ = false;  // 08 section 3.1: until a downlink is accepted since boot
  if (this->state_ == PairingState::PAIRED) {
    // 08 section 9: HEARTBEAT_CONFIRMED, or SYNC without a clock, with firmware_version.
    this->boot_uplink_ = true;
    this->schedule_heartbeat_(this->clock_.now_us());
  }
}

namespace {

constexpr uint32_t WARM_MAGIC = 0x43535753;  // "CSWS"
constexpr uint16_t WARM_VERSION = 2;
constexpr uint8_t WF_TIME_SURE = 0x01, WF_DL_ACK = 0x02, WF_FIRMWARE_SENT = 0x04, WF_ANSWERED_EVER = 0x08,
                  WF_CONFIRMED_SENT = 0x10, WF_FULL_STATE_SENT = 0x20, WF_HB_ARMED = 0x40, WF_AIR_STARTED = 0x80;

uint32_t warm_check(const WarmState &w) {
  // FNV-1a: this guards against stale or half-written RTC memory, not an attacker.
  const auto *p = reinterpret_cast<const uint8_t *>(&w);
  uint32_t h = 2166136261u;
  for (size_t i = 0; i < offsetof(WarmState, check); i++)
    h = (h ^ p[i]) * 16777619u;
  return h;
}

}  // namespace

bool SensorCore::suspend(WarmState &out) const {
  if (this->hold() || !this->counter_ok_ || this->stopped_ ||
      (this->state_ != PairingState::UNPAIRED && this->state_ != PairingState::PAIRED))
    return false;
  std::memset(static_cast<void *>(&out), 0, sizeof(out));  // padding too, for the check
  out.magic = WARM_MAGIC;
  out.version = WARM_VERSION;
  out.size = uint16_t(sizeof(WarmState));
  out.saved_us = this->clock_.now_us();
  out.last_answered_us = this->last_answered_us_;
  out.last_confirmed_sent_us = this->last_confirmed_sent_us_;
  out.last_full_state_us = this->last_full_state_us_;
  out.next_hb_us = this->next_hb_us_;
  out.tx_blocked_until_us = this->tx_blocked_until_us_;
  out.air_minute = this->air_minute_;
  std::memcpy(out.air_buckets, this->air_buckets_, sizeof(out.air_buckets));
  out.next_fcnt = this->next_fcnt_;
  out.reserved = this->reserved_;
  out.state = uint8_t(this->state_);
  out.flags = uint8_t((this->time_sure_ ? WF_TIME_SURE : 0) | (this->dl_ack_ ? WF_DL_ACK : 0) |
                      (this->firmware_sent_ ? WF_FIRMWARE_SENT : 0) | (this->answered_ever_ ? WF_ANSWERED_EVER : 0) |
                      (this->confirmed_sent_ ? WF_CONFIRMED_SENT : 0) |
                      (this->full_state_sent_ ? WF_FULL_STATE_SENT : 0) | (this->hb_armed_ ? WF_HB_ARMED : 0) |
                      (this->air_started_ ? WF_AIR_STARTED : 0));
  out.undelivered = this->undelivered_;
  out.pending_hb_count = this->pending_hb_count_;
  out.state_count = uint8_t(this->state_count_);
  for (size_t i = 0; i < this->state_count_; i++)
    out.state_readings[i] = this->state_readings_[i];
  if (this->has_session_) {
    // The two most recent normal tags: normally this epoch's and, near the boundary, the next.
    const TagEntry *pick[2] = {nullptr, nullptr};
    for (const auto &e : this->tag_cache_) {
      if (!e.used || e.root || e.bootstrap)
        continue;
      if (pick[0] == nullptr || e.stamp > pick[0]->stamp) {
        pick[1] = pick[0];
        pick[0] = &e;
      } else if (pick[1] == nullptr || e.stamp > pick[1]->stamp) {
        pick[1] = &e;
      }
    }
    for (const TagEntry *e : pick) {
      if (e == nullptr)
        continue;
      out.tag_epochs[out.tag_count] = e->n;
      std::memcpy(out.tags[out.tag_count], e->tag, TAG_LEN);
      out.tag_count++;
    }
    this->tag_key_check_(out.tag_key_check);
  }
  out.check = warm_check(out);
  return true;
}

bool SensorCore::resume(const WarmState &in) {
  if (in.magic != WARM_MAGIC || in.version != WARM_VERSION || in.size != sizeof(WarmState) ||
      in.check != warm_check(in) || in.state_count > STATE_SLOTS || in.tag_count > 2)
    return false;
  if (in.state != uint8_t(PairingState::UNPAIRED) && in.state != uint8_t(PairingState::PAIRED))
    return false;
  // Every time in the snapshot is on the monotonic clock, so it must not have restarted.
  if (this->clock_.now_us() < in.saved_us)
    return false;
  uint8_t b[4];
  // The reservation in storage is what a boot would continue from; a mismatch means
  // storage changed under the snapshot, so boot instead.
  if (!this->storage_.load(Blob::COUNTER, b, 4) || be32(b) != in.reserved || in.next_fcnt == 0 ||
      in.next_fcnt > in.reserved)
    return false;
  this->load_stored_();
  if (uint8_t(this->state_) != in.state) {
    secure_zero(this->k_session_, sizeof(this->k_session_));
    secure_zero(&this->session_keys_, sizeof(this->session_keys_));
    this->forget_session_tags_();
    this->has_session_ = false;
    this->state_ = PairingState::UNPAIRED;
    return false;
  }
  uint8_t key_check[4];
  if (this->has_session_ && in.tag_count) {
    this->tag_key_check_(key_check);
    if (std::memcmp(key_check, in.tag_key_check, 4) == 0) {
      // A fresh core's cache is empty. Oldest first, so the newest keeps the highest stamp.
      for (uint8_t i = in.tag_count; i-- > 0;) {
        TagEntry &e = this->tag_cache_[i];
        e.used = true;
        e.root = e.bootstrap = false;
        e.n = in.tag_epochs[i];
        e.stamp = ++this->tag_stamp_;
        std::memcpy(e.tag, in.tags[i], TAG_LEN);
      }
    }
  }
  this->reserved_ = in.reserved;
  this->next_fcnt_ = in.next_fcnt;
  this->counter_ok_ = true;
  this->last_answered_us_ = in.last_answered_us;
  this->last_confirmed_sent_us_ = in.last_confirmed_sent_us;
  this->last_full_state_us_ = in.last_full_state_us;
  this->next_hb_us_ = in.next_hb_us;
  this->tx_blocked_until_us_ = in.tx_blocked_until_us;
  this->air_minute_ = in.air_minute;
  std::memcpy(this->air_buckets_, in.air_buckets, sizeof(this->air_buckets_));
  // 08 section 3.1 is about a clock lost with the power; one kept through the sleep
  // stays sure, unless the RTC lost it after all.
  this->time_sure_ = (in.flags & WF_TIME_SURE) && this->clock_known_();
  this->dl_ack_ = in.flags & WF_DL_ACK;
  this->firmware_sent_ = in.flags & WF_FIRMWARE_SENT;
  this->answered_ever_ = in.flags & WF_ANSWERED_EVER;
  this->confirmed_sent_ = in.flags & WF_CONFIRMED_SENT;
  this->full_state_sent_ = in.flags & WF_FULL_STATE_SENT;
  this->hb_armed_ = (in.flags & WF_HB_ARMED) && this->state_ == PairingState::PAIRED;
  this->air_started_ = in.flags & WF_AIR_STARTED;
  this->undelivered_ = in.undelivered;
  this->pending_hb_count_ = in.pending_hb_count;
  // Readings set before resume() are newer than the snapshot's.
  for (size_t i = 0; i < in.state_count; i++) {
    bool newer = false;
    for (size_t j = 0; j < this->state_count_; j++)
      newer = newer || this->state_readings_[j].same_key(in.state_readings[i]);
    if (!newer)
      this->set_state(in.state_readings[i]);
  }
  return true;
}

bool SensorCore::set_state(const Reading &r) {
  if (r.kind == 0 || r.len > READING_VALUE_MAX)
    return false;
  size_t total = 0, slot = STATE_SLOTS;
  for (size_t i = 0; i < this->state_count_; i++) {
    if (this->state_readings_[i].same_key(r)) {
      slot = i;
    } else {
      total += this->state_readings_[i].encoded_size();
    }
  }
  if (total + r.encoded_size() > READINGS_MAX)
    return false;
  if (slot == STATE_SLOTS) {
    if (this->state_count_ == STATE_SLOTS)
      return false;
    slot = this->state_count_++;
  }
  this->state_readings_[slot] = r;
  return true;
}

void SensorCore::report(bool confirmed) {
  if (this->state_ != PairingState::PAIRED && this->state_ != PairingState::SESSION)
    return;
  this->want_state_ = true;
  this->want_state_confirmed_ = this->want_state_confirmed_ || confirmed;
}

bool SensorCore::send_event(const Reading &r, bool confirmed) {
  if ((this->state_ != PairingState::PAIRED && this->state_ != PairingState::SESSION) || r.kind == 0 ||
      this->event_count_ == EVENT_SLOTS)
    return false;
  this->events_[this->event_count_++] = r;
  this->events_confirmed_ = this->events_confirmed_ || confirmed;
  return true;
}

void SensorCore::short_press() {
  switch (this->state_) {
    case PairingState::UNPAIRED:
      // 04 section 4.4 step 2: a fresh key pair for every JOIN. loop() computes the
      // public key, and the JOIN goes out once it and the JOIN's tag are ready.
      this->wipe_ephemeral_();
      this->random_.fill(this->ephemeral_private_, 32);
      this->ephemeral_pending_ = true;
      this->state_ = PairingState::JOINING;
      this->want_join_ = true;
      this->emit_(SensorEvent::PAIRING_STARTED);
      break;
    case PairingState::PAIRED:
      // 04 section 4.5: a range test that disturbs nothing.
      this->report(true);
      break;
    default:
      // 04 section 4.5: pairing is under way and ends on its own.
      break;
  }
}

void SensorCore::factory_reset() {
  if (this->phase_ == Phase::RX || this->phase_ == Phase::WAIT_RX)
    this->radio_.stop_receive();
  this->phase_ = Phase::IDLE;
  this->wipe_ephemeral_();
  this->erase_session_();
  // 04 section 6.2: floors and settings go; dev_eui, k_root and the counter stay.
  this->root_floor_ = 0;
  this->erase_blob_(Blob::ROOT_FLOOR, 4);
  this->erase_blob_(Blob::SETTINGS, 2);
  this->heartbeat_minutes_ = this->config_.heartbeat_minutes;
  this->emit_(SensorEvent::FACTORY_RESET);
}

bool SensorCore::immediate_work_() const {
  if (this->stopped_ || !this->counter_ok_)
    return false;
  switch (this->state_) {
    case PairingState::JOINING:
      return this->want_join_;
    case PairingState::SESSION:
      return this->want_session_first_;
    case PairingState::PAIRED:
      return this->want_state_ || this->event_count_ || this->want_leave_heartbeat_ || this->boot_uplink_;
    default:
      return false;
  }
}

bool SensorCore::hold() const {
  return this->phase_ != Phase::IDLE || this->immediate_work_() || this->key_work_pending_() ||
         (this->state_ == PairingState::PAIRED && this->want_pending_hb_ && !this->stopped_);
}

uint64_t SensorCore::next_wake_us() const {
  switch (this->phase_) {
    case Phase::TX:
      return this->tx_started_us_ + TX_TIMEOUT_US;
    case Phase::WAIT_RX:
      return this->rx_open_us_;
    case Phase::RX:
      return this->rx_close_us_;
    case Phase::WAIT_RETRY:
      return this->retry_at_us_;
    case Phase::IDLE:
      break;
  }
  if (this->key_work_pending_())
    return 0;
  if (this->immediate_work_())
    return this->tx_blocked_until_us_;
  uint64_t t = UINT64_MAX;
  if (this->state_ == PairingState::PAIRED && !this->stopped_ && this->counter_ok_) {
    if (this->want_pending_hb_ && this->pending_hb_at_us_ < t)
      t = this->pending_hb_at_us_;
    if (this->hb_armed_ && this->next_hb_us_ < t)
      t = this->next_hb_us_;
  }
  if (t != UINT64_MAX && this->tx_blocked_until_us_ > t)
    t = this->tx_blocked_until_us_;
  return t;
}

// ---- transmission cycle

void SensorCore::loop() {
  uint64_t now = this->clock_.now_us();
  switch (this->phase_) {
    case Phase::IDLE: {
      const uint64_t deadline = now + KEY_SLICE_US;
      this->key_work_(deadline);
      this->start_next_(this->clock_.now_us());
      // A frame that found its tag missing waits for it; with time left, carry on now.
      if (this->phase_ == Phase::IDLE && this->key_work_pending_() && this->clock_.now_us() < deadline) {
        this->key_work_(deadline);
        this->start_next_(this->clock_.now_us());
      }
      break;
    }
    case Phase::TX:
      // A lost TX-done: assume it went, so a window still opens and retries go on.
      if (now - this->tx_started_us_ >= TX_TIMEOUT_US)
        this->on_tx_done(now);
      break;
    case Phase::WAIT_RX:
      if (now >= this->rx_open_us_) {
        this->radio_.start_receive();
        this->phase_ = Phase::RX;
      }
      break;
    case Phase::RX:
      if (now >= this->rx_close_us_) {
        // 01 section 4: a packet that started in the window is received to the end.
        if (this->radio_.receiving() && now < this->rx_close_us_ + RX_EXTEND_MAX_US)
          break;
        this->radio_.stop_receive();
        this->window_closed_(now);
      }
      break;
    case Phase::WAIT_RETRY: {
      bool can_abandon = this->cur_.attempts > 0 && !this->cur_.has_event &&
                         (this->cur_.purpose == Purpose::STATE || this->cur_.purpose == Purpose::HEARTBEAT ||
                          this->cur_.purpose == Purpose::FOLLOW_UP);
      if (can_abandon && this->want_state_) {
        // 08 section 5: newer state replaces pending retries, as a new confirmed frame.
        // Abandoned is not undelivered: that needs the last retry to go unanswered.
        this->want_state_confirmed_ = true;
        this->phase_ = Phase::IDLE;
        this->start_next_(now);
      } else if (now >= this->retry_at_us_) {
        if (!this->budget_allows_(this->radio_.airtime_us(this->cur_.len), now)) {
          this->retry_at_us_ = now + 1000000;
          break;
        }
        this->transmit_(now);
      }
      break;
    }
  }
}

void SensorCore::start_next_(uint64_t now) {
  if (this->stopped_ || !this->counter_ok_ || now < this->tx_blocked_until_us_)
    return;
  switch (this->state_) {
    case PairingState::JOINING:
      if (this->want_join_ && this->build_(Purpose::JOIN, true, now))
        this->want_join_ = false;
      return;
    case PairingState::SESSION:
      if (this->want_session_first_ && this->build_(Purpose::SESSION_FIRST, true, now))
        this->want_session_first_ = false;
      return;
    case PairingState::PAIRED:
      break;
    default:
      return;
  }
  if (this->want_leave_heartbeat_) {
    if (this->build_(Purpose::LEAVE_HEARTBEAT, false, now))
      this->want_leave_heartbeat_ = false;
    return;
  }
  if (this->want_state_ || this->event_count_) {
    bool confirmed = this->want_state_confirmed_ || (this->event_count_ && this->events_confirmed_);
    if (this->build_(Purpose::STATE, confirmed, now)) {
      this->want_state_ = this->want_state_confirmed_ = false;
    }
    return;
  }
  if (this->boot_uplink_) {
    if (this->build_(Purpose::HEARTBEAT, true, now)) {
      this->boot_uplink_ = false;
      this->schedule_heartbeat_(now);
    }
    return;
  }
  if (this->want_pending_hb_ && now >= this->pending_hb_at_us_) {
    if (this->build_(Purpose::FOLLOW_UP, this->pending_hb_confirmed_, now))
      this->want_pending_hb_ = false;
    return;
  }
  if (this->hb_armed_ && now >= this->next_hb_us_) {
    uint64_t confirm_us = uint64_t(this->config_.confirm_interval_s) * 1000000;
    if (confirm_us > MAX_CONFIRMED_GAP_US)
      confirm_us = MAX_CONFIRMED_GAP_US;
    bool confirmed = !this->answered_ever_ || now - this->last_answered_us_ >= confirm_us ||
                     this->undelivered_ >= SYNC_AFTER_UNDELIVERED ||
                     (this->confirmed_sent_ && now + 60000000 >= this->last_confirmed_sent_us_ + MAX_CONFIRMED_GAP_US);
    uint64_t half = uint64_t(this->heartbeat_minutes_) * 30000000;
    if (!confirmed && this->full_state_sent_ && now - this->last_full_state_us_ < half) {
      this->schedule_heartbeat_(now);  // 08 section 4.2: MAY skip
      return;
    }
    if (this->build_(Purpose::HEARTBEAT, confirmed, now))
      this->schedule_heartbeat_(now);
  }
}

void SensorCore::encode_state_(ReadingWriter &w, bool events, bool firmware, bool &took_events,
                               bool &took_firmware) {
  took_events = false;
  took_firmware = false;
  if (events) {
    // Events first; one whose (channel, kind) is already in the frame waits for the next.
    size_t keep = 0;
    for (size_t i = 0; i < this->event_count_; i++) {
      if (w.add(this->events_[i])) {
        took_events = true;
      } else {
        this->events_[keep++] = this->events_[i];
      }
    }
    this->event_count_ = keep;
    if (keep == 0)
      this->events_confirmed_ = false;
  }
  bool full = true;
  for (size_t i = 0; i < this->state_count_; i++) {
    const Reading &r = this->state_readings_[i];
    if (!w.contains(r.channel, r.kind) && !w.add(r))
      full = false;
  }
  if (full) {
    this->full_state_sent_ = true;
    this->last_full_state_us_ = this->clock_.now_us();
  }
  if (firmware && this->config_.has_firmware_version) {
    Reading fw;
    Reading::make(0xFF, 0xC2, this->config_.firmware_version, 3, fw);
    took_firmware = w.add(fw);
  }
}

bool SensorCore::build_(Purpose purpose, bool confirmed, uint64_t now) {
  uint8_t pt[PAYLOAD_MAX];
  size_t pt_len = 1;
  const KeySet *keys = &this->session_keys_;
  uint8_t type;
  uint32_t epoch = 0;
  uint8_t uflags = this->time_sure_ ? 0 : UF_TIME_UNSURE;
  bool took_events = false, took_firmware = false;

  // Taking readings out of the queue is undone if the frame cannot go out yet; it
  // is then rebuilt with the latest state.
  Reading saved_events[EVENT_SLOTS];
  size_t saved_count = this->event_count_;
  for (size_t i = 0; i < saved_count; i++)
    saved_events[i] = this->events_[i];
  bool saved_events_confirmed = this->events_confirmed_, saved_full = this->full_state_sent_;
  uint64_t saved_full_us = this->last_full_state_us_;
  auto undo = [&]() {
    for (size_t i = 0; i < saved_count; i++)
      this->events_[i] = saved_events[i];
    this->event_count_ = saved_count;
    this->events_confirmed_ = saved_events_confirmed;
    this->full_state_sent_ = saved_full;
    this->last_full_state_us_ = saved_full_us;
    this->tx_blocked_until_us_ = now + 1000000;
    secure_zero(pt, sizeof(pt));
    return false;
  };

  if (purpose == Purpose::JOIN) {
    // 02 section 11.1: TIME_UNSURE is always set in JOIN.
    if (!this->has_ephemeral_ || !this->tag_ready_(true, true, tag_block(this->next_fcnt_)))
      return false;
    keys = &this->root_keys_;
    type = T_JOIN;
    pt[0] = UF_TIME_UNSURE;
    std::memcpy(pt + 1, this->ephemeral_public_, 32);
    pt_len = 33;
  } else {
    if (!this->has_session_)
      return false;
    uint32_t unix_time;
    bool clock = this->clock_.unix_time(unix_time);
    if (purpose == Purpose::LEAVE_HEARTBEAT) {
      // 08 section 8: the DL_ACK for LEAVE needs a normal tag; without a clock, just leave.
      if (!clock) {
        this->leave_now_();
        return false;
      }
      type = T_HEARTBEAT;
    } else if (!clock || (confirmed && this->undelivered_ >= SYNC_AFTER_UNDELIVERED)) {
      // 08 sections 3.2 and 6: no normal tag without a clock, and SYNC after lost contact.
      type = T_SYNC;
      confirmed = true;
    } else if (purpose == Purpose::STATE) {
      type = confirmed ? T_DATA_CONFIRMED : T_DATA;
    } else {
      // HEARTBEAT, and SESSION_FIRST: a confirmed heartbeat with the full state (04 section 4.4 step 5).
      type = confirmed ? T_HEARTBEAT_CONFIRMED : T_HEARTBEAT;
    }
    if (clock)
      epoch = epoch_of(unix_time);
    // Without its tag the frame waits, before anything is taken from the queues.
    if (!(is_bootstrap(type) ? this->tag_ready_(false, true, tag_block(this->next_fcnt_))
                             : this->tag_ready_(false, false, epoch)))
      return false;
    if (this->dl_ack_ || purpose == Purpose::LEAVE_HEARTBEAT)
      uflags |= UF_DL_ACK;
    pt[0] = uflags;
    ReadingWriter w;
    bool firmware = (purpose == Purpose::HEARTBEAT || purpose == Purpose::FOLLOW_UP ||
                     purpose == Purpose::SESSION_FIRST) &&
                    !this->firmware_sent_;
    this->encode_state_(w, purpose == Purpose::STATE, firmware, took_events, took_firmware);
    std::memcpy(pt + 1, w.data(), w.size());
    pt_len = 1 + w.size();
  }

  if (!this->budget_allows_(this->radio_.airtime_us(FRAME_HEADER + pt_len + FRAME_MIC), now))
    return undo();
  uint32_t fcnt;
  if (!this->alloc_fcnt_(fcnt))
    return undo();

  Uplink &u = this->cur_;
  u = Uplink{};
  u.purpose = purpose;
  u.type = type;
  u.confirmed = confirmed;
  u.has_event = took_events;
  u.has_firmware = took_firmware;
  u.fcnt = fcnt;
  if (confirmed) {
    this->confirmed_sent_ = true;
    this->last_confirmed_sent_us_ = now;
  }
  uint8_t tag[TAG_LEN];
  const bool root = purpose == Purpose::JOIN, bootstrap = is_bootstrap(type);
  const uint32_t n = bootstrap ? tag_block(fcnt) : epoch;
  // Checked above for this fcnt, so always cached; computed at once only as a fallback.
  if (this->tag_index_(root, bootstrap, n) < 0)
    this->key_work_stats_.sync_tags++;
  this->tag_for_(root, bootstrap, n, tag);
  this->wanted_tag_ = KeyTarget{};
  size_t len = 0;
  seal_frame(*keys, type, tag, fcnt, pt, pt_len, u.frame, len);
  u.len = uint8_t(len);
  if (purpose != Purpose::JOIN && (pt[0] & UF_DL_ACK))
    this->dl_ack_ = false;
  secure_zero(pt, sizeof(pt));
  this->transmit_(now);
  return true;
}

void SensorCore::transmit_(uint64_t now) {
  Uplink &u = this->cur_;
  if (!this->radio_.transmit(u.frame, u.len)) {
    if (u.refused_since_us == 0)
      u.refused_since_us = now;
    if (now - u.refused_since_us < TX_REFUSED_MAX_US) {
      this->phase_ = Phase::WAIT_RETRY;
      this->retry_at_us_ = now + TX_REFUSED_BACKOFF_US;
      return;
    }
    // Nothing went on air, so no airtime is spent; the attempt goes unanswered as
    // a sent one would, and the retry schedule and newer state take over.
    u.refused_since_us = 0;
    this->phase_ = Phase::TX;
    this->tx_started_us_ = now;
    this->on_tx_done(now);
    return;
  }
  u.refused_since_us = 0;
  this->budget_spend_(this->radio_.airtime_us(u.len), now);
  this->phase_ = Phase::TX;
  this->tx_started_us_ = now;
}

void SensorCore::on_tx_done() { this->on_tx_done(this->clock_.now_us()); }

void SensorCore::on_tx_done(uint64_t at_us) {
  if (this->phase_ != Phase::TX)
    return;
  Uplink &u = this->cur_;
  if (u.attempts == 0)
    u.first_done_us = at_us;
  u.attempts++;
  u.last_done_us = at_us;
  if (u.purpose == Purpose::LEAVE_HEARTBEAT) {
    // The keys go now; RX1 still opens (01 section 4), though nothing in it can verify.
    this->leave_now_();
  }
  this->rx_index_ = 1;
  this->rx_open_us_ = at_us + RX1_DELAY_US - RX_EARLY_US;
  this->rx_close_us_ = at_us + RX1_DELAY_US + RX_LATE_US;
  this->phase_ = Phase::WAIT_RX;
}

void SensorCore::window_closed_(uint64_t now) {
  Uplink &u = this->cur_;
  if (this->rx_index_ == 1 && u.confirmed) {
    this->rx_index_ = 2;
    this->rx_open_us_ = u.last_done_us + RX2_DELAY_US - RX_EARLY_US;
    this->rx_close_us_ = u.last_done_us + RX2_DELAY_US + RX_LATE_US;
    this->phase_ = Phase::WAIT_RX;
    return;
  }
  if (!u.confirmed) {
    this->finish_unconfirmed_();
    return;
  }
  if (u.purpose == Purpose::FOLLOW_UP && u.type != T_SYNC) {
    // 08 section 7: never retried and never undelivered. The next answered uplink
    // brings PENDING again if commands are still queued. A SYNC (no clock) is
    // retried like any SYNC (08 section 3.2).
    this->phase_ = Phase::IDLE;
    return;
  }
  uint8_t retries_done = uint8_t(u.attempts - 1);
  if (retries_done < MAX_RETRIES) {
    // 08 section 5: measured from the end of the original transmission.
    this->retry_at_us_ =
        u.first_done_us + RETRY_BASE_US[retries_done] + this->jitter_(RETRY_JITTER_US[retries_done]);
    this->phase_ = Phase::WAIT_RETRY;
    return;
  }
  this->finish_undelivered_(now);
}

void SensorCore::finish_unconfirmed_() {
  this->phase_ = Phase::IDLE;
  if (this->cur_.has_firmware)
    this->firmware_sent_ = true;
}

void SensorCore::finish_answered_(uint64_t now) {
  (void) now;
  this->phase_ = Phase::IDLE;
  if (this->cur_.has_firmware)
    this->firmware_sent_ = true;
  if (this->cur_.confirmed && (this->cur_.purpose == Purpose::STATE || this->cur_.purpose == Purpose::HEARTBEAT ||
                               this->cur_.purpose == Purpose::FOLLOW_UP))
    this->emit_(SensorEvent::UPLINK_ANSWERED);
}

void SensorCore::finish_undelivered_(uint64_t now) {
  this->phase_ = Phase::IDLE;
  switch (this->cur_.purpose) {
    case Purpose::JOIN:
      // 04 section 4.4: discard the key pair and wait for the button again.
      this->wipe_ephemeral_();
      this->state_ = PairingState::UNPAIRED;
      this->emit_(SensorEvent::PAIRING_FAILED);
      return;
    case Purpose::SESSION_FIRST:
      // 04 section 4.3: pairing fails, keeping the root floor.
      this->erase_session_();
      this->emit_(SensorEvent::PAIRING_FAILED);
      return;
    default:
      break;
  }
  if (this->undelivered_ < 255)
    this->undelivered_++;
  this->emit_(SensorEvent::UPLINK_UNDELIVERED);
  if (this->undelivered_ >= SYNC_AFTER_UNDELIVERED) {
    // 08 section 6: confirmed heartbeats 1, 5, 15 and 60 minutes after the last failure, then every h.
    size_t i = this->undelivered_ - SYNC_AFTER_UNDELIVERED;
    uint64_t h = uint64_t(this->heartbeat_minutes_) * 60000000;
    this->next_hb_us_ = this->cap_heartbeat_(now + (i < 4 ? LOST_CONTACT_BACKOFF_US[i] : h));
    this->hb_armed_ = true;
  }
}

void SensorCore::schedule_heartbeat_(uint64_t now) {
  // 08 section 4.2: h after the previous one, +-10% at random.
  uint64_t h = uint64_t(this->heartbeat_minutes_) * 60000000;
  this->next_hb_us_ = this->cap_heartbeat_(now + h - h / 10 + this->jitter_(h / 5));
  this->hb_armed_ = true;
}

// 08 section 3.3: a confirmed uplink at least every 24 hours, whatever h is.
uint64_t SensorCore::cap_heartbeat_(uint64_t at) const {
  if (this->confirmed_sent_ && at > this->last_confirmed_sent_us_ + MAX_CONFIRMED_GAP_US)
    return this->last_confirmed_sent_us_ + MAX_CONFIRMED_GAP_US;
  return at;
}

uint64_t SensorCore::jitter_(uint64_t range) {
  if (range == 0)
    return 0;
  uint8_t b[8];
  this->random_.fill(b, sizeof(b));
  uint64_t v = 0;
  for (uint8_t x : b)
    v = (v << 8) | x;
  return v % (range + 1);
}

bool SensorCore::budget_allows_(uint32_t airtime, uint64_t now) {
  this->budget_spend_(0, now);
  uint64_t used = 0;
  for (uint32_t b : this->air_buckets_)
    used += b;
  return used + airtime <= this->config_.airtime_budget_us;
}

void SensorCore::budget_spend_(uint32_t airtime, uint64_t now) {
  uint64_t minute = now / 60000000;
  if (!this->air_started_) {
    this->air_started_ = true;
    this->air_minute_ = minute;
  }
  // Clear the minutes that rolled out of the hour.
  constexpr uint64_t N = sizeof(this->air_buckets_) / sizeof(this->air_buckets_[0]);
  for (uint64_t m = this->air_minute_ + 1; m <= minute && m <= this->air_minute_ + N; m++)
    this->air_buckets_[m % N] = 0;
  if (minute > this->air_minute_)
    this->air_minute_ = minute;
  this->air_buckets_[minute % N] += airtime;
}

// ---- receiving

void SensorCore::on_receive(const uint8_t *data, size_t len) {
  uint64_t now = this->clock_.now_us();
  DownlinkResult r = this->process_downlink_(data, len, now);
  this->last_result_ = r;
  if (r == DownlinkResult::ACCEPT) {
    this->radio_.stop_receive();
    this->finish_answered_(now);
  } else if (r == DownlinkResult::EXCHANGE_FAILED) {
    this->radio_.stop_receive();
    this->phase_ = Phase::IDLE;
  }
}

DownlinkResult SensorCore::process_downlink_(const uint8_t *data, size_t len, uint64_t now) {
  if (this->phase_ != Phase::RX)
    return DownlinkResult::NO_WINDOW;
  if (len < FRAME_MIN || len > FRAME_MAX || (data[1] & 0x0F) != T_DOWNLINK)
    return DownlinkResult::BAD_FRAME;
  bool root = this->state_ == PairingState::JOINING;
  if (root ? !this->has_ephemeral_ : !this->has_session_)
    return DownlinkResult::NO_KEYS;
  const KeySet &keys = root ? this->root_keys_ : this->session_keys_;

  FrameHeader h;
  uint8_t pt[PAYLOAD_MAX];
  struct Wipe {
    uint8_t *p;
    ~Wipe() { secure_zero(this->p, PAYLOAD_MAX); }
  } wipe{pt};
  size_t pt_len;
  OpenResult o = open_frame(keys, data, len, h, pt, pt_len);
  if (o == OpenResult::BAD_FRAME)
    return DownlinkResult::BAD_FRAME;
  if (o == OpenResult::BAD_MIC)
    return DownlinkResult::BAD_MIC;
  if (pt_len < 9)
    return DownlinkResult::BAD_FRAME;
  // 02 section 10.2, in the reference tool's order.
  if (be32(pt) != this->cur_.fcnt)
    return DownlinkResult::WRONG_REPLY_TO;
  if (h.fcnt <= (root ? this->root_floor_ : this->session_floor_))
    return DownlinkResult::AT_OR_BELOW_FLOOR;
  uint32_t server_time = be32(pt + 4);
  uint8_t dflags = pt[8];
  const uint8_t *cmds = pt + 9;
  size_t cmds_len = pt_len - 9;

  if (root) {
    // Only KEY_EXCHANGE is ever sent under the root key set (02 section 11.1).
    const uint8_t *server_pub = nullptr;
    for (size_t i = 0; i + 2 <= cmds_len && i + 2 + cmds[i + 1] <= cmds_len; i += 2 + cmds[i + 1]) {
      if (cmds[i] == CMD_KEY_EXCHANGE && cmds[i + 1] == 32) {
        server_pub = cmds + i + 2;
        break;
      }
    }
    if (server_pub == nullptr)
      return DownlinkResult::NO_KEY_EXCHANGE;
    uint8_t k[16];
    const uint64_t t0 = this->clock_.now_us();
    bool ok = derive_session(this->config_.k_root, this->config_.dev_eui, this->ephemeral_private_, server_pub,
                             this->ephemeral_public_, server_pub, k);
    this->key_work_stats_.exchanges++;
    this->key_work_stats_.last_exchange_us = uint32_t(this->clock_.now_us() - t0);
    this->wipe_ephemeral_();
    // 04 section 4.6: the new root floor is durable before SYNC goes out.
    if (ok && !this->save_u32_(Blob::ROOT_FLOOR, h.fcnt)) {
      this->emit_(SensorEvent::STORAGE_FAILED);
      ok = false;
    }
    if (!ok) {
      secure_zero(k, sizeof(k));
      this->state_ = PairingState::UNPAIRED;
      this->emit_(SensorEvent::PAIRING_FAILED);
      return DownlinkResult::EXCHANGE_FAILED;
    }
    this->root_floor_ = h.fcnt;
    std::memcpy(this->k_session_, k, 16);
    secure_zero(k, sizeof(k));
    derive_keys(this->k_session_, this->config_.dev_eui, this->session_keys_);
    this->forget_session_tags_();
    this->has_session_ = true;
    this->session_floor_ = 0;
    // 04 section 4.4 step 4: provisional until a session downlink is accepted.
    this->state_ = PairingState::SESSION;
    this->want_session_first_ = true;
    this->dl_ack_ = true;
  } else {
    this->session_floor_ = h.fcnt;
    if (this->state_ == PairingState::SESSION) {
      // 04 section 4.3: PAIRED before the downlink's commands run.
      if (!this->paired_(now))
        return DownlinkResult::EXCHANGE_FAILED;
    } else if (!this->save_u32_(Blob::SESSION_FLOOR, h.fcnt)) {
      this->emit_(SensorEvent::STORAGE_FAILED);
    }
  }

  this->clock_.set_unix_time(server_time);
  this->time_sure_ = true;
  this->undelivered_ = 0;
  if (this->cur_.confirmed) {
    this->answered_ever_ = true;
    this->last_answered_us_ = now;
  }
  if (!root) {
    bool had_command = false;
    this->execute_commands_(cmds, cmds_len, had_command, now);
    if (had_command)
      this->dl_ack_ = true;
    // 08 section 7: PENDING asks for a HEARTBEAT in 2-4 s, at most 4 times in a row.
    // After RX2 it is confirmed, so its own RX2 opens for a server that only uses RX2.
    // A row restarts with any answered uplink that was not itself a follow-up.
    if (this->cur_.purpose != Purpose::FOLLOW_UP)
      this->pending_hb_count_ = 0;
    if ((dflags & DF_PENDING) && this->state_ == PairingState::PAIRED && !this->want_leave_heartbeat_ &&
        this->pending_hb_count_ < MAX_PENDING_HEARTBEATS) {
      this->pending_hb_count_++;
      this->want_pending_hb_ = true;
      this->pending_hb_confirmed_ = this->rx_index_ == 2;
      this->pending_hb_at_us_ = now + 2000000 + this->jitter_(2000000);
    } else if (!(dflags & DF_PENDING)) {
      this->pending_hb_count_ = 0;
    }
  }
  return DownlinkResult::ACCEPT;
}

void SensorCore::execute_commands_(const uint8_t *cmds, size_t len, bool &had_command, uint64_t now) {
  size_t i = 0;
  while (i + 2 <= len) {
    uint8_t id = cmds[i], n = cmds[i + 1];
    if (i + 2 + n > len)
      break;  // truncated: nothing after it can be trusted to line up
    const uint8_t *args = cmds + i + 2;
    i += 2 + n;
    had_command = true;
    switch (id) {
      case CMD_SET_HEARTBEAT: {
        if (n != 2)
          break;
        uint16_t h = uint16_t(args[0] << 8 | args[1]);
        if (h < 1 || h > 1440)
          break;
        this->heartbeat_minutes_ = h;
        if (!this->storage_.save(Blob::SETTINGS, args, 2))
          this->emit_(SensorEvent::STORAGE_FAILED);
        if (this->state_ == PairingState::PAIRED)
          this->schedule_heartbeat_(now);
        break;
      }
      case CMD_LEAVE:
        if (this->state_ == PairingState::PAIRED) {
          this->want_leave_heartbeat_ = true;
        } else {
          this->leave_now_();
        }
        break;
      case CMD_KEY_EXCHANGE:
        break;  // only valid in JOINING, under the root key set (08 section 8)
      case CMD_SET_VALUE: {
        // 03 section 8: channel | kind | value in the reading encoding, exactly.
        if (n < 2)
          break;
        uint8_t kind = args[1];
        const uint8_t *value = args + 2;
        size_t vlen = n - 2;
        if (size_class(kind) == 3) {
          if (vlen < 1 || value[0] != vlen - 1)
            break;
          value++;
          vlen--;
        }
        Reading r;
        if (Reading::make(args[0], kind, value, vlen, r) && this->on_set_value)
          this->on_set_value(r);
        break;
      }
      default:
        if (id >= 0x41 && id <= 0x7F && this->on_command)
          this->on_command(id, args, n);
        break;
    }
  }
}

bool SensorCore::paired_(uint64_t now) {
  this->state_ = PairingState::PAIRED;
  // 04 section 4.6: keys, state and floor are durable before another uplink.
  if (!this->save_session_() || !this->save_u32_(Blob::SESSION_FLOOR, this->session_floor_)) {
    this->emit_(SensorEvent::STORAGE_FAILED);
    this->erase_session_();
    this->emit_(SensorEvent::PAIRING_FAILED);
    return false;
  }
  this->emit_(SensorEvent::PAIRED);
  // The first session uplink carried the full state; a change queued since goes out next.
  this->schedule_heartbeat_(now);
  return true;
}

void SensorCore::leave_now_() {
  this->erase_session_();
  this->emit_(SensorEvent::LEFT);
}

}  // namespace esphome::cs_sensor
