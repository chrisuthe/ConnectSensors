#include "cs_sensor.h"

#include "esphome/core/helpers.h"
#include "esphome/core/log.h"

#include "cs_crypto.h"
#include "cs_sha256.h"

#include <algorithm>
#include <cinttypes>
#include <cmath>
#include <cstring>
#include <sys/time.h>

#ifdef USE_ESP32
#include <bootloader_random.h>
#include <esp_attr.h>
#include <esp_idf_version.h>
#include <esp_random.h>
#include <esp_sleep.h>
#include <esp_system.h>
#include <soc/soc_caps.h>
#endif

namespace esphome::cs_sensor {

static const char *const TAG = "cs_sensor";

static constexpr uint64_t BUTTON_RESET_US = 10000000;  // 04 section 4.5
static constexpr uint64_t READINGS_WAIT_US = 5000000;  // longest wait for first values at start
static constexpr uint64_t MIN_SLEEP_US = 3000000;      // shorter waits stay awake
static constexpr uint64_t NOTHING_PLANNED_SLEEP_US = 24ULL * 3600 * 1000000;
static constexpr uint32_t RADIO_TX_TIMEOUT_MS = 1500;  // below the core's TX_TIMEOUT_US
// The RTC is taken as set once it is past this (2025-01-01); a cold ESP32 starts at 1970.
static constexpr uint32_t MIN_VALID_UNIX = 1735689600;

// ======================================================================== platform

uint64_t PlatformClock::now_us() { return monotonic_us() + this->offset_us_; }

int64_t PlatformClock::rtc_us() {
  struct timeval tv;
  gettimeofday(&tv, nullptr);
  return int64_t(tv.tv_sec) * 1000000 + tv.tv_usec;
}

bool PlatformClock::unix_time(uint32_t &out) {
  struct timeval tv;
  gettimeofday(&tv, nullptr);
  if (tv.tv_sec < MIN_VALID_UNIX)
    return false;
  out = uint32_t(tv.tv_sec);
  return true;
}

void PlatformClock::set_unix_time(uint32_t t) {
  struct timeval tv {};
  tv.tv_sec = time_t(t);
  settimeofday(&tv, nullptr);
}

ESPPreferenceObject &PreferenceStorage::pref_(Blob id, size_t len) {
  Slot &slot = this->slots_[uint8_t(id) & 7];
  if (slot.len != len) {
    slot.pref = global_preferences->make_preference(len, fnv1_hash_extend(this->base_key_, uint8_t(id)), true);
    slot.len = len;
  }
  return slot.pref;
}

bool PreferenceStorage::load(Blob id, uint8_t *buf, size_t len) { return this->pref_(id, len).load(buf, len); }

bool PreferenceStorage::save(Blob id, const uint8_t *buf, size_t len) {
  // sync() commits to flash on every save: the core relies on a true return being
  // durable, since a lost counter reservation would let uplink counters repeat
  // (02 section 8.2). It saves only a few times a day.
  return this->pref_(id, len).save(buf, len) && global_preferences->sync();
}

void PlatformRandom::seed() {
#ifdef USE_ESP32
  // Without Wi-Fi or Bluetooth running, ESP-IDF's RNG is only pseudo-random; with
  // the SAR ADC noise source enabled it is not. That source takes over the ADC and
  // powers it down when disabled, so this must run before any ADC sensor sets up
  // (CSSensor::get_setup_priority) and never while one samples.
  bootloader_random_enable();
  esp_fill_random(this->seed_, sizeof(this->seed_));
  bootloader_random_disable();
#endif
  // On nRF52, random_bytes() is the hardware TRNG, so fill() needs no seed.
}

void PlatformRandom::fill(uint8_t *buf, size_t len) {
  while (len > 0) {
    uint8_t hw[32], block[32], ctr[8];
    random_bytes(hw, sizeof(hw));
    for (int i = 0; i < 8; i++)
      ctr[i] = uint8_t(this->counter_ >> (56 - 8 * i));
    this->counter_++;
    Sha256 h;
    h.update(this->seed_, sizeof(this->seed_));
    h.update(ctr, sizeof(ctr));
    h.update(hw, sizeof(hw));
    h.finish(block);
    // Ratchet the seed so earlier output cannot be recomputed from a later state.
    Sha256 r;
    r.update(block, sizeof(block));
    r.update(this->seed_, sizeof(this->seed_));
    r.finish(this->seed_);
    size_t n = std::min(len, sizeof(block));
    std::memcpy(buf, block, n);
    buf += n;
    len -= n;
    secure_zero(block, sizeof(block));
    secure_zero(hw, sizeof(hw));
  }
}

// ---- deep sleep state in RTC memory

#if defined(USE_CS_SENSOR_DEEP_SLEEP) && defined(USE_ESP32) && SOC_RTC_MEM_SUPPORTED
#define CS_SENSOR_WARM_STATE

namespace {

constexpr uint32_t WARM_BLOCK_MAGIC = 0x43534742;  // "CSGB"

struct ReadingMemo {
  float sent;
  uint64_t sent_us;
  uint8_t has_sent;
  uint8_t pad[3];
};

struct WarmBlock {
  uint32_t magic;
  uint32_t size;
  int64_t rtc_us;   // the RTC when it went to sleep
  uint64_t mono_us;  // the monotonic clock at the same moment
  uint32_t readings;
  uint32_t pad;
  ReadingMemo memo[STATE_SLOTS];
  WarmState core;
  uint32_t check;
};

// Not cleared by a reset; the magic, the size, the check and the reset reason
// together decide whether it holds a snapshot.
RTC_NOINIT_ATTR uint64_t s_warm[(sizeof(WarmBlock) + 7) / 8];

uint32_t block_check(const WarmBlock &b) {
  const auto *p = reinterpret_cast<const uint8_t *>(&b);
  uint32_t h = FNV1_OFFSET_BASIS;
  for (size_t i = 0; i < offsetof(WarmBlock, check); i++)
    h = fnv1a_hash_extend(h, p[i]);
  return h;
}

std::unique_ptr<WarmBlock> s_wake;  // the snapshot this boot woke with

}  // namespace
#endif

// ======================================================================== radio

bool PlatformRadio::transmit(const uint8_t *frame, size_t len) {
  CSSensor *p = this->parent_;
#ifdef USE_CS_SENSOR_SX126X
  if (p->sx126x_ != nullptr) {
    auto r = p->sx126x_->start_transmit_async(p, frame, len, RADIO_TX_TIMEOUT_MS);
    p->tx_busy_ = r == sx126x::SX126xError::SX126X_ERROR_NONE;
    if (!p->tx_busy_)
      ESP_LOGW(TAG, "Radio refused the transmission (%d)", int(r));
    return p->tx_busy_;
  }
#endif
#ifdef USE_CS_SENSOR_SX127X
  if (p->sx127x_ != nullptr) {
    auto r = p->sx127x_->start_transmit_async(p, frame, len, RADIO_TX_TIMEOUT_MS);
    p->tx_busy_ = r == sx127x::SX127xError::SX127X_ERROR_NONE;
    if (!p->tx_busy_)
      ESP_LOGW(TAG, "Radio refused the transmission (%d)", int(r));
    return p->tx_busy_;
  }
#endif
  return false;
}

void PlatformRadio::start_receive() {
#ifdef USE_CS_SENSOR_SX126X
  if (this->parent_->sx126x_ != nullptr)
    this->parent_->sx126x_->set_mode_rx();
#endif
#ifdef USE_CS_SENSOR_SX127X
  if (this->parent_->sx127x_ != nullptr)
    this->parent_->sx127x_->set_mode_rx();
#endif
}

void PlatformRadio::stop_receive() {
#ifdef USE_CS_SENSOR_SX126X
  if (this->parent_->sx126x_ != nullptr)
    this->parent_->sx126x_->set_mode_sleep();
#endif
#ifdef USE_CS_SENSOR_SX127X
  if (this->parent_->sx127x_ != nullptr)
    this->parent_->sx127x_->set_mode_sleep();
#endif
}

bool PlatformRadio::receiving() {
#ifdef USE_CS_SENSOR_SX126X
  if (this->parent_->sx126x_ != nullptr)
    return this->parent_->sx126x_->is_receiving();
#endif
#ifdef USE_CS_SENSOR_SX127X
  if (this->parent_->sx127x_ != nullptr)
    return this->parent_->sx127x_->is_receiving();
#endif
  return false;
}

uint32_t PlatformRadio::airtime_us(size_t len) {
  const CSSensor *p = this->parent_;
  return lora_airtime_us(len, p->sf_, p->bw_hz_, p->cr_, p->preamble_);
}

// ======================================================================== component

void CSSensor::set_identity(const std::vector<uint8_t> &dev_eui, const std::vector<uint8_t> &k_root,
                            const char *profile) {
  std::copy_n(dev_eui.begin(), std::min<size_t>(dev_eui.size(), 8), this->config_.dev_eui);
  std::copy_n(k_root.begin(), std::min<size_t>(k_root.size(), 16), this->config_.k_root);
  this->profile_ = profile;
  // Keyed by dev_eui, so flashing another identity starts from clean storage.
  uint32_t key = fnv1_hash("cs_sensor");
  for (uint8_t b : this->config_.dev_eui)
    key = fnv1_hash_extend(key, b);
  this->storage_.set_base_key(key);
}

void CSSensor::add_sensor_reading(sensor::Sensor *s, uint8_t channel, uint8_t kind, float scale, bool confirmed,
                                  uint32_t min_interval_ms, float delta) {
  ReadingSource src;
  src.sensor = s;
  src.channel = channel;
  src.kind = kind;
  src.scale = scale;
  src.confirmed = confirmed;
  src.min_interval_ms = min_interval_ms;
  src.delta = delta;
  size_t index = this->readings_.size();
  this->readings_.push_back(src);
  s->add_on_state_callback([this, index](float v) {
    ReadingSource &r = this->readings_[index];
    r.value = v;
    r.has_value = r.fresh = true;
    this->enable_loop_soon_any_context();
  });
}

void CSSensor::add_binary_reading(binary_sensor::BinarySensor *s, uint8_t channel, uint8_t kind, bool confirmed,
                                  uint32_t min_interval_ms) {
  ReadingSource src;
  src.binary = s;
  src.channel = channel;
  src.kind = kind;
  src.confirmed = confirmed;
  src.min_interval_ms = min_interval_ms;
  size_t index = this->readings_.size();
  this->readings_.push_back(src);
  // Full-state callbacks, because add_on_state_callback skips a binary sensor's
  // first state unless trigger_on_initial_state is set, and YAML defaults it off.
  s->add_full_state_callback([this, index](optional<bool> /*previous*/, optional<bool> current) {
    if (!current.has_value())
      return;
    ReadingSource &r = this->readings_[index];
    r.value = *current ? 1.0f : 0.0f;
    r.has_value = r.fresh = true;
    this->enable_loop_soon_any_context();
  });
}

void CSSensor::set_pairing_button(binary_sensor::BinarySensor *button) {
  this->button_ = button;
  // Full-state callback: a template or API-driven button's first press is its
  // first state, which add_on_state_callback would skip.
  button->add_full_state_callback([this](optional<bool> /*previous*/, optional<bool> current) {
    if (!current.has_value())
      return;
    const bool pressed = *current;
    uint64_t now = this->clock_.now_us();
    if (pressed && !this->button_down_) {
      this->button_down_ = true;
      this->button_down_us_ = now;
    } else if (!pressed && this->button_down_) {
      this->button_down_ = false;
      // A press released before the reset is a short press; the release after a
      // reset is not.
      if (!this->button_reset_done_)
        this->button_event_ = true;
      this->button_reset_done_ = false;
    }
    this->enable_loop_soon_any_context();
  });
}

void CSSensor::setup() {
  this->random_.seed();
  this->started_us_ = this->clock_.now_us();
  // Only adds to a list, so it is fine before the radio has set up.
#ifdef USE_CS_SENSOR_SX126X
  if (this->sx126x_ != nullptr)
    this->sx126x_->register_listener(this);
#endif
#ifdef USE_CS_SENSOR_SX127X
  if (this->sx127x_ != nullptr)
    this->sx127x_->register_listener(this);
#endif

  this->core_ = std::make_unique<SensorCore>(this->config_, this->clock_, this->radio_, this->storage_, this->random_);
  this->core_->on_event = [this](SensorEvent e) { this->on_event_(e); };

#ifdef USE_CS_SENSOR_DEEP_SLEEP
  if (this->deep_sleep_ != nullptr) {
    // Sleep only when this component says so (maybe_sleep_).
    this->deep_sleep_->prevent_deep_sleep();
    bool woke = false;
#ifdef USE_ESP32
    woke = esp_reset_reason() == ESP_RST_DEEPSLEEP;
    // A cold start, or a wake by a pin other than the wakeup_pin (ext1, the pairing
    // button), stays awake long enough to press the pairing button.
#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(6, 0, 0)
    const bool by_ext1 = esp_sleep_get_wakeup_causes() & (1u << ESP_SLEEP_WAKEUP_EXT1);
#else
    const bool by_ext1 = esp_sleep_get_wakeup_cause() == ESP_SLEEP_WAKEUP_EXT1;
#endif
    if (!woke || by_ext1)
      this->awake_until_us_ = this->started_us_ + uint64_t(this->pairing_window_ms_) * 1000;
#endif
#ifdef CS_SENSOR_WARM_STATE
    WarmBlock &b = *reinterpret_cast<WarmBlock *>(s_warm);
    if (woke && b.magic == WARM_BLOCK_MAGIC && b.size == sizeof(WarmBlock) && b.check == block_check(b) &&
        b.readings == this->readings_.size()) {
      const int64_t rtc_now = PlatformClock::rtc_us();
      const uint64_t timer_now = monotonic_us();
      if (rtc_now >= b.rtc_us && b.mono_us + uint64_t(rtc_now - b.rtc_us) >= timer_now) {
        this->clock_.set_offset(b.mono_us + uint64_t(rtc_now - b.rtc_us) - timer_now);
        this->started_us_ = this->clock_.now_us();
        if (this->awake_until_us_ != 0)
          this->awake_until_us_ = this->started_us_ + uint64_t(this->pairing_window_ms_) * 1000;
        s_wake = std::make_unique<WarmBlock>();
        std::memcpy(static_cast<void *>(s_wake.get()), &b, sizeof(WarmBlock));
      }
    }
    b.magic = 0;  // used once
#endif
  }
#endif
}

bool CSSensor::restore_warm_() {
#ifdef CS_SENSOR_WARM_STATE
  if (!s_wake)
    return false;
  std::unique_ptr<WarmBlock> b = std::move(s_wake);
  if (!this->core_->resume(b->core))
    return false;
  for (size_t i = 0; i < this->readings_.size(); i++) {
    this->readings_[i].has_sent = b->memo[i].has_sent;
    this->readings_[i].sent = b->memo[i].sent;
    this->readings_[i].sent_us = b->memo[i].sent_us;
  }
  return true;
#else
  return false;
#endif
}

void CSSensor::save_warm_() {
#ifdef CS_SENSOR_WARM_STATE
  auto b = std::make_unique<WarmBlock>();
  std::memset(static_cast<void *>(b.get()), 0, sizeof(WarmBlock));
  WarmBlock &rtc = *reinterpret_cast<WarmBlock *>(s_warm);
  rtc.magic = 0;
  if (!this->core_->suspend(b->core)) {
    ESP_LOGW(TAG, "Nothing to keep through this sleep; the wake will be a boot");
    return;
  }
  b->magic = WARM_BLOCK_MAGIC;
  b->size = sizeof(WarmBlock);
  b->mono_us = this->clock_.now_us();
  b->rtc_us = PlatformClock::rtc_us();
  b->readings = uint32_t(this->readings_.size());
  for (size_t i = 0; i < this->readings_.size() && i < STATE_SLOTS; i++) {
    b->memo[i].has_sent = this->readings_[i].has_sent;
    b->memo[i].sent = this->readings_[i].sent;
    b->memo[i].sent_us = this->readings_[i].sent_us;
  }
  b->check = block_check(*b);
  std::memcpy(s_warm, b.get(), sizeof(WarmBlock));
#endif
}

void CSSensor::dump_config() {
  char eui[17];
  format_hex_to(eui, this->config_.dev_eui, sizeof(this->config_.dev_eui));
  ESP_LOGCONFIG(TAG,
                "ConnectSensors sensor %s:\n"
                "  DevEUI: %s\n"
                "  Region: %s (SF%u, %" PRIu32 " Hz)\n"
                "  Profile: %s\n"
                "  Heartbeat: %u min\n"
                "  Readings: %u\n"
                "  Pairing button: %s",
                CS_SENSOR_VERSION, eui, this->region_, this->sf_, this->bw_hz_, this->profile_,
                this->config_.heartbeat_minutes, unsigned(this->readings_.size()), YESNO(this->button_ != nullptr));
  for (const auto &r : this->readings_) {
    ESP_LOGCONFIG(TAG, "    channel %u kind 0x%02X%s, min interval %" PRIu32 " ms%s", r.channel, r.kind,
                  r.confirmed ? " confirmed" : "", r.min_interval_ms, r.delta < 0 ? ", heartbeats only" : "");
  }
#ifdef USE_CS_SENSOR_DEEP_SLEEP
  if (this->deep_sleep_ != nullptr) {
    ESP_LOGCONFIG(TAG, "  Deep sleep: yes, pairing window %" PRIu32 " ms, max sleep %" PRIu32 " ms",
                  this->pairing_window_ms_, this->max_sleep_ms_);
  }
#endif
}

// ---- readings

bool CSSensor::make_reading_(const ReadingSource &src, Reading &out) const {
  const uint8_t cls = size_class(src.kind);
  if (src.binary != nullptr || cls == 0) {
    uint8_t v = 0xFF;  // unknown (03 section 4.1)
    if (!std::isnan(src.value)) {
      float x = std::round(src.value * src.scale);
      v = uint8_t(std::clamp(x, 0.0f, 254.0f));
    }
    out = Reading::u8(src.channel, src.kind, v);
    return true;
  }
  const bool is_signed = src.kind == 0x40 || src.kind == 0x4A || src.kind == 0x85;
  const bool has_unknown = src.kind != 0x49 && src.kind != 0x80 && src.kind != 0x83;
  if (std::isnan(src.value) && !has_unknown)
    return false;
  const double x = std::isnan(src.value) ? 0.0 : std::round(double(src.value) * src.scale);
  if (cls == 1) {
    if (is_signed) {
      int16_t v = std::isnan(src.value) ? INT16_MIN : int16_t(std::clamp(x, -32767.0, 32767.0));
      out = Reading::i16(src.channel, src.kind, v);
    } else {
      uint16_t v = std::isnan(src.value) ? 0xFFFF : uint16_t(std::clamp(x, 0.0, has_unknown ? 65534.0 : 65535.0));
      out = Reading::u16(src.channel, src.kind, v);
    }
    return true;
  }
  if (src.kind == 0x84) {
    out = Reading::f32(src.channel, src.kind, std::isnan(src.value) ? NAN : float(double(src.value) * src.scale));
    return true;
  }
  if (is_signed) {
    int32_t v = std::isnan(src.value) ? INT32_MIN : int32_t(std::clamp(x, -2147483647.0, 2147483647.0));
    out = Reading::i32(src.channel, src.kind, v);
  } else {
    uint32_t v =
        std::isnan(src.value) ? 0xFFFFFFFF : uint32_t(std::clamp(x, 0.0, has_unknown ? 4294967294.0 : 4294967295.0));
    out = Reading::u32(src.channel, src.kind, v);
  }
  return true;
}

void CSSensor::take_readings_(uint64_t now) {
  for (auto &src : this->readings_) {
    if (!src.fresh)
      continue;
    src.fresh = false;
    Reading r;
    if (this->make_reading_(src, r) && !this->core_->set_state(r))
      ESP_LOGW(TAG, "Reading on channel %u kind 0x%02X refused", src.channel, src.kind);
  }
  bool want = false, confirmed = false;
  for (auto &src : this->readings_) {
    // A first value after the boot uplink is due too: no frame has carried it.
    if (!src.due(now))
      continue;
    want = true;
    confirmed = confirmed || src.confirmed;
    src.sent_us = now;
  }
  if (!want)
    return;
  // The frame carries every state reading, so the server sees all current values.
  for (auto &src : this->readings_)
    src.carried();
  ESP_LOGD(TAG, "State changed; reporting%s", confirmed ? " (confirmed)" : "");
  this->core_->report(confirmed);
}

bool CSSensor::readings_ready_() const {
  return std::all_of(this->readings_.begin(), this->readings_.end(),
                     [](const ReadingSource &r) { return r.has_value; });
}

uint64_t CSSensor::glue_wake_us_() const {
  uint64_t t = UINT64_MAX;
  for (const auto &src : this->readings_) {
    if (src.changed())
      t = std::min(t, src.due_at_us());
  }
  return t;
}

// ---- pairing button

void CSSensor::handle_button_(uint64_t now) {
  if (this->button_down_ && !this->button_reset_done_ && now - this->button_down_us_ >= BUTTON_RESET_US) {
    // 04 section 4.5: reset while the button is still held.
    this->button_reset_done_ = true;
    this->core_->factory_reset();
  }
  if (this->button_event_) {
    this->button_event_ = false;
    this->core_->short_press();
  }
}

// ---- radio events

void CSSensor::tx_complete_(bool ok) {
  this->tx_busy_ = false;
  if (!ok)
    ESP_LOGW(TAG, "Transmission did not complete cleanly");
  // The driver goes back to receiving after a send; sleep until RX1 opens.
  this->radio_.stop_receive();
  if (this->running_)
    this->core_->on_tx_done(this->clock_.now_us());
  this->enable_loop_soon_any_context();
}

void CSSensor::on_packet(const std::vector<uint8_t> &packet, float rssi, float snr) {
  if (!this->running_)
    return;
  this->core_->on_receive(packet.data(), packet.size());
  DownlinkResult r = this->core_->last_downlink_result();
  if (r == DownlinkResult::ACCEPT) {
    this->last_rssi_ = rssi;
    this->last_snr_ = snr;
    this->signal_fresh_ = true;
    ESP_LOGD(TAG, "Downlink accepted (RSSI %.1f dBm, SNR %.1f dB)", rssi, snr);
  } else if (r != DownlinkResult::NO_WINDOW) {
    ESP_LOGD(TAG, "Downlink rejected: %s", downlink_result_str(r));
  }
  this->enable_loop_soon_any_context();  // the core moved on; publish and plan the next wake
}

void CSSensor::on_event_(SensorEvent e) {
  switch (e) {
    case SensorEvent::PAIRING_STARTED:
      ESP_LOGI(TAG, "Pairing: JOIN");
      break;
    case SensorEvent::PAIRED:
      ESP_LOGI(TAG, "Paired");
      break;
    case SensorEvent::PAIRING_FAILED:
      ESP_LOGW(TAG, "Pairing failed; press the button to try again");
      break;
    case SensorEvent::UPLINK_ANSWERED:
      ESP_LOGD(TAG, "Uplink answered");
      break;
    case SensorEvent::UPLINK_UNDELIVERED:
      ESP_LOGW(TAG, "Uplink undelivered after its retries");
      break;
    case SensorEvent::LEFT:
      ESP_LOGI(TAG, "Left the network");
      break;
    case SensorEvent::FACTORY_RESET:
      ESP_LOGW(TAG, "Factory reset; let go of the button");
      break;
    case SensorEvent::STORAGE_FAILED:
      ESP_LOGE(TAG, "A required write to flash failed");
      this->status_set_warning();
      break;
    case SensorEvent::COUNTER_EXHAUSTED:
      ESP_LOGE(TAG, "Uplink counter exhausted; the sensor stops transmitting");
      this->status_set_error();
      break;
  }
}

// Key work timings, to check on a device that none of it blocks the loop for long.
void CSSensor::log_key_work_() {
  const SensorCore::KeyWork &k = this->core_->key_work();
  SensorCore::KeyWork &seen = this->key_work_logged_;
  if (k.jobs != seen.jobs) {
    ESP_LOGD(TAG, "%s computed: %" PRIu32 " us in %" PRIu32 " slices, longest %" PRIu32 " us",
             k.last_was_tag ? "Tag" : "JOIN key pair", k.last_us, k.last_slices, k.last_max_slice_us);
  }
  if (k.sync_tags != seen.sync_tags)
    ESP_LOGW(TAG, "A frame's tag was not ready and was computed at once");
  if (k.exchanges != seen.exchanges)
    ESP_LOGD(TAG, "Key exchange: shared secret in %" PRIu32 " us", k.last_exchange_us);
  seen = k;
}

void CSSensor::publish_diagnostics_() {
  int state = int(this->core_->state());
#ifdef USE_TEXT_SENSOR
  static const char *const STATES[] = {"unpaired", "joining", "session", "paired"};
  if (this->pairing_state_sensor_ != nullptr && state != this->last_state_published_)
    this->pairing_state_sensor_->publish_state(STATES[state & 3]);
#endif
  this->last_state_published_ = state;
  int64_t counter = int64_t(this->core_->next_fcnt()) - 1;
  if (this->uplink_counter_sensor_ != nullptr && counter != this->last_counter_published_)
    this->uplink_counter_sensor_->publish_state(float(counter));
  this->last_counter_published_ = counter;
  int undelivered = this->core_->undelivered();
  if (this->undelivered_sensor_ != nullptr && undelivered != this->last_undelivered_published_)
    this->undelivered_sensor_->publish_state(undelivered);
  this->last_undelivered_published_ = undelivered;
  if (this->signal_fresh_) {
    this->signal_fresh_ = false;
    if (this->last_rssi_sensor_ != nullptr)
      this->last_rssi_sensor_->publish_state(this->last_rssi_);
    if (this->last_snr_sensor_ != nullptr)
      this->last_snr_sensor_->publish_state(this->last_snr_);
  }
}

Component *CSSensor::radio_component_() const {
#ifdef USE_CS_SENSOR_SX126X
  if (this->sx126x_ != nullptr)
    return this->sx126x_;
#endif
#ifdef USE_CS_SENSOR_SX127X
  if (this->sx127x_ != nullptr)
    return this->sx127x_;
#endif
  return nullptr;
}

void CSSensor::schedule_wake_(uint64_t wake_us) {
  if (wake_us == UINT64_MAX) {
    if (this->wake_pending_)
      this->cancel_timeout("wake");
    this->wake_pending_ = false;
    return;
  }
  if (this->wake_pending_ && wake_us == this->wake_at_)
    return;
  this->wake_pending_ = true;
  this->wake_at_ = wake_us;
  // The main loop never sleeps past the next scheduled item, but the scheduler alone
  // does not run component loops before the loop interval is up, so the callback
  // asks for a pass now. Rounding down makes a wake early rather than late; an early
  // pass just schedules the rest.
  const uint64_t now = this->clock_.now_us();
  const uint32_t ms = wake_us > now ? uint32_t(std::min<uint64_t>((wake_us - now) / 1000, UINT32_MAX)) : 0;
  this->set_timeout("wake", ms, [this]() {
    this->wake_pending_ = false;
    this->enable_loop_soon_any_context();
  });
}

// ---- main loop

// The loop runs while there is work: waiting for the radio to set up, and while the
// core holds (a transmission, an RX window and its end-of-packet extension, or
// retries), which it needs polled often. Otherwise it is disabled, and reading,
// button and radio callbacks or the wake timeout bring it back.
void CSSensor::loop() {
  if (!this->radio_up_) {
    Component *radio = this->radio_component_();
    if (radio == nullptr || radio->is_failed()) {
      ESP_LOGE(TAG, "No working radio");
      this->mark_failed();
      return;
    }
    if (!radio->is_ready())
      return;
    // The region profile keeps rx_start on (see __init__.py); listen only in RX windows.
    this->radio_.stop_receive();
    this->radio_up_ = true;
  }

  const uint64_t now = this->clock_.now_us();
  if (!this->running_) {
    // Wait briefly for every reading's first value, so the first frame is complete.
    if (!this->readings_ready_() && now - this->started_us_ < READINGS_WAIT_US) {
      this->schedule_wake_(this->started_us_ + READINGS_WAIT_US);
      this->disable_loop();
      return;
    }
    this->running_ = true;
    // The values read now go to the core before begin(), for the boot heartbeat.
    for (auto &src : this->readings_) {
      Reading r;
      if (src.has_value && this->make_reading_(src, r))
        this->core_->set_state(r);
      src.fresh = false;
    }
    this->warm_ = this->restore_warm_();
    if (!this->warm_) {
      for (auto &src : this->readings_)
        src.boot(now);
      this->core_->begin();
    }
    ESP_LOGI(TAG, "%s, %s", this->warm_ ? "Woke from deep sleep" : "Started",
             this->core_->state() == PairingState::PAIRED ? "paired" : "not paired");
  }

  this->take_readings_(now);
  this->handle_button_(now);
  this->core_->loop();
  this->log_key_work_();
  this->publish_diagnostics_();

  const uint64_t after = this->clock_.now_us();
  uint64_t wake = this->core_->next_wake_us();
  if (!this->core_->hold())
    wake = std::min(wake, this->glue_wake_us_());
  if (this->button_down_ && !this->button_reset_done_)
    wake = std::min(wake, this->button_down_us_ + BUTTON_RESET_US);
  if (this->awake_until_us_ > after)
    wake = std::min(wake, this->awake_until_us_);  // the deep-sleep decision then
  this->schedule_wake_(wake);
  this->maybe_sleep_(after);
  if (!this->core_->hold())
    this->disable_loop();
}

void CSSensor::maybe_sleep_(uint64_t now) {
#ifdef USE_CS_SENSOR_DEEP_SLEEP
  if (this->deep_sleep_ == nullptr || !this->running_)
    return;
  if (this->core_->hold() || this->tx_busy_ || this->button_down_ || this->button_event_ ||
      now < this->awake_until_us_)
    return;
  uint64_t wake = std::min(this->core_->next_wake_us(), this->glue_wake_us_());
  if (this->max_sleep_ms_ != 0)
    wake = std::min(wake, now + uint64_t(this->max_sleep_ms_) * 1000);
  if (wake == UINT64_MAX)
    wake = now + NOTHING_PLANNED_SLEEP_US;  // nothing planned: the wakeup pins do the rest
  if (wake <= now + MIN_SLEEP_US)
    return;
  this->save_warm_();
  this->radio_.stop_receive();
  const uint64_t ms = std::min<uint64_t>((wake - now) / 1000, UINT32_MAX);
  ESP_LOGI(TAG, "Deep sleep for %" PRIu64 " s", ms / 1000);
  this->deep_sleep_->set_sleep_duration(uint32_t(ms));
  this->deep_sleep_->begin_sleep(true);
#else
  (void) now;
#endif
}

}  // namespace esphome::cs_sensor
