// Host unit tests for the cs_sensor core. Build and run with:  make -C tests/sensor_core

#include <cmath>
#include <cstdio>
#include <cstring>
#include <deque>
#include <initializer_list>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "cs_crypto.h"
#include "cs_sha256.h"
#include "cs_x25519.h"
#include "sensor_core.h"
#include "vectors.inc"

using namespace esphome::cs_sensor;

static int failures = 0;
static int checks = 0;

#define CHECK(cond)                                                     \
  do {                                                                  \
    checks++;                                                           \
    if (!(cond)) {                                                      \
      failures++;                                                       \
      std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);       \
    }                                                                   \
  } while (0)

using Bytes = std::vector<uint8_t>;

static Bytes unhex(const char *s) {
  Bytes out;
  for (size_t i = 0; s[i] && s[i + 1]; i += 2) {
    unsigned v;
    std::sscanf(s + i, "%2x", &v);
    out.push_back(uint8_t(v));
  }
  return out;
}

static std::string hex(const uint8_t *p, size_t n) {
  static const char *d = "0123456789abcdef";
  std::string s;
  for (size_t i = 0; i < n; i++) {
    s += d[p[i] >> 4];
    s += d[p[i] & 15];
  }
  return s;
}

static std::string hex(const Bytes &v) { return hex(v.data(), v.size()); }

static std::string tag_hex(uint32_t t) {
  uint8_t b[4] = {uint8_t(t >> 24), uint8_t(t >> 16), uint8_t(t >> 8), uint8_t(t)};
  return hex(b, 4);
}

static const FrameVector &fv(const char *name) {
  for (const auto &v : FRAME_VECTORS) {
    if (std::strcmp(v.name, name) == 0)
      return v;
  }
  std::printf("missing frame %s\n", name);
  return FRAME_VECTORS[0];
}

static constexpr uint64_t MS = 1000;
static constexpr uint64_t S = 1000000;
static constexpr uint64_t MIN = 60 * S;

// ---------------------------------------------------------------- crypto

static void test_crypto() {
  // FIPS 197 appendix C.1
  Bytes key = unhex("000102030405060708090a0b0c0d0e0f"), out(16);
  Aes128(key.data()).encrypt_block(unhex("00112233445566778899aabbccddeeff").data(), out.data());
  CHECK(hex(out) == "69c4e0d86a7b0430d8cdb78070b4c55a");

  // RFC 3610 packet vector 1: 13-byte nonce, 8-byte tag
  Bytes k = unhex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"), nonce = unhex("00000003020100a0a1a2a3a4a5");
  Bytes aad = unhex("0001020304050607"), pt = unhex("08090a0b0c0d0e0f101112131415161718191a1b1c1d1e");
  Bytes ct(pt.size() + 8), back(pt.size());
  ccm_seal(k.data(), nonce.data(), aad.data(), aad.size(), pt.data(), pt.size(), ct.data());
  CHECK(hex(ct) == "588c979a61c663d2f066d0c2c0f989806d5f6b61dac38417e8d12cfdf926e0");
  CHECK(ccm_open(k.data(), nonce.data(), aad.data(), aad.size(), ct.data(), pt.size(), back.data()));
  CHECK(back == pt);
  ct[3] ^= 1;
  CHECK(!ccm_open(k.data(), nonce.data(), aad.data(), aad.size(), ct.data(), pt.size(), back.data()));
  CHECK(back == Bytes(pt.size(), 0));

  // RFC 5869 test case 1
  Bytes ikm(22, 0x0b), salt = unhex("000102030405060708090a0b0c"), info = unhex("f0f1f2f3f4f5f6f7f8f9"), okm(42);
  CHECK(hkdf_sha256(ikm.data(), ikm.size(), salt.data(), salt.size(), info.data(), info.size(), okm.data(), 42));
  CHECK(hex(okm) == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");

  // RFC 7748 section 5.2 and 6.1
  Bytes q(32);
  x25519(q.data(), unhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4").data(),
         unhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c").data());
  CHECK(hex(q) == "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
  Bytes alice = unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
  Bytes bob = unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
  Bytes alice_pub(32), bob_pub(32), s1(32), s2(32);
  x25519_base(alice_pub.data(), alice.data());
  x25519_base(bob_pub.data(), bob.data());
  CHECK(hex(alice_pub) == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
  CHECK(hex(bob_pub) == "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
  x25519(s1.data(), alice.data(), bob_pub.data());
  x25519(s2.data(), bob.data(), alice_pub.data());
  CHECK(hex(s1) == "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
  CHECK(s1 == s2);

  // The copied SHA-256 still works.
  uint8_t d[32];
  sha256(reinterpret_cast<const uint8_t *>("abc"), 3, d);
  CHECK(hex(d, 32) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

// ---------------------------------------------------------------- frame-v1.json

static void test_frame_vectors() {
  Bytes k_root = unhex(V_K_ROOT), eui = unhex(V_DEV_EUI);
  KeySet root, session;
  derive_keys(k_root.data(), eui.data(), root);
  CHECK(hex(root.k_enc, 16) == V_ROOT_K_ENC);
  CHECK(hex(root.k_dev_tag, 16) == V_ROOT_K_DEV_TAG);

  Bytes s_priv = unhex(V_SENSOR_EPHEMERAL_PRIVATE), v_priv = unhex(V_SERVER_EPHEMERAL_PRIVATE);
  Bytes s_pub(32), v_pub(32), k1(16), k2(16);
  x25519_base(s_pub.data(), s_priv.data());
  x25519_base(v_pub.data(), v_priv.data());
  CHECK(hex(s_pub) == V_SENSOR_PUB);
  CHECK(hex(v_pub) == V_SERVER_PUB);
  CHECK(derive_session(k_root.data(), eui.data(), s_priv.data(), v_pub.data(), s_pub.data(), v_pub.data(), k1.data()));
  CHECK(derive_session(k_root.data(), eui.data(), v_priv.data(), s_pub.data(), s_pub.data(), v_pub.data(), k2.data()));
  CHECK(hex(k1) == V_K_SESSION);
  CHECK(k1 == k2);
  // 02 section 5.3: an all-zero shared value is refused (the point 0 forces one).
  Bytes zero_point(32, 0);
  CHECK(!derive_session(k_root.data(), eui.data(), s_priv.data(), zero_point.data(), s_pub.data(),
                        zero_point.data(), k2.data()));

  derive_keys(k1.data(), eui.data(), session);
  CHECK(hex(session.k_enc, 16) == V_SESSION_K_ENC);
  CHECK(hex(session.k_dev_tag, 16) == V_SESSION_K_DEV_TAG);

  Bytes route(16);
  derive_net_route(unhex(V_K_NET).data(), route.data());
  CHECK(hex(route) == V_K_NET_ROUTE);
  CHECK(epoch_of(V_TIME) == V_EPOCH);
  for (const auto &t : TAG_VECTORS) {
    CHECK(tag_hex(net_tag(route.data(), t.epoch)) == t.net);
    CHECK(tag_hex(dev_tag(session.k_dev_tag, t.epoch)) == t.dev);
  }

  for (const auto &v : FRAME_VECTORS) {
    const KeySet &keys = v.root ? root : session;
    Bytes pt = unhex(v.plaintext), frame(FRAME_MAX);
    size_t len = 0;
    uint32_t nt = uint32_t(std::stoul(v.net_tag, nullptr, 16)), dt = uint32_t(std::stoul(v.dev_tag, nullptr, 16));
    CHECK(seal_frame(keys, uint8_t(v.type), nt, dt, v.fcnt, pt.data(), pt.size(), frame.data(), len));
    frame.resize(len);
    CHECK(hex(frame) == v.frame);
    FrameHeader h;
    Bytes back(PAYLOAD_MAX);
    size_t back_len = 0;
    Bytes wire = unhex(v.frame);
    CHECK(open_frame(keys, wire.data(), wire.size(), h, back.data(), back_len) == OpenResult::OK);
    back.resize(back_len);
    CHECK(back == pt);
    CHECK(h.type == v.type && h.fcnt == v.fcnt && h.net_tag == nt && h.dev_tag == dt);
    wire[wire.size() - 1] ^= 0x80;
    CHECK(open_frame(keys, wire.data(), wire.size(), h, back.data(), back_len) == OpenResult::BAD_MIC);
  }
  // Out of range lengths are refused before any crypto (02 section 3).
  Bytes big(PAYLOAD_MAX + 1, 0), frame(FRAME_MAX + 8);
  size_t len;
  CHECK(!seal_frame(root, T_DATA, 0, 0, 1, big.data(), big.size(), frame.data(), len));
  CHECK(!seal_frame(root, T_DATA, 0, 0, 1, big.data(), 0, frame.data(), len));
  FrameHeader h;
  size_t pt_len;
  Bytes short_frame(22, 0xC5);
  CHECK(open_frame(root, short_frame.data(), short_frame.size(), h, big.data(), pt_len) == OpenResult::BAD_FRAME);

  // open_frame leaves the type to its caller: type 0 opens, and the downlink path
  // drops everything but T_DOWNLINK before opening.
  for (const auto &v : INVALID_FRAME_VECTORS) {
    Bytes wire = unhex(v.frame), back(FRAME_MAX);
    OpenResult r = open_frame(session, wire.data(), wire.size(), h, back.data(), pt_len);
    if (std::strcmp(v.reason, "reserved frame type") == 0)
      CHECK(r == OpenResult::OK && h.type == 0);
    else
      CHECK(r != OpenResult::OK);
  }
}

// ---------------------------------------------------------------- payload-v1.json

static void test_payload_vectors() {
  for (const auto &v : PAYLOAD_VECTORS) {
    ReadingWriter w;
    for (int i = 0; i < v.count; i++) {
      const DecodedReading &d = v.readings[i];
      Bytes raw = unhex(d.raw);
      Reading r;
      CHECK(Reading::make(uint8_t(d.channel), uint8_t(d.kind), raw.data(), raw.size(), r));
      CHECK(w.add(r));
    }
    CHECK(hex(w.data(), w.size()) == v.encoded);

    Bytes enc = unhex(v.encoded);
    std::vector<Reading> got;
    CHECK(decode_readings(enc.data(), enc.size(), [&](const Reading &r) { got.push_back(r); }));
    CHECK(int(got.size()) == v.count);
    for (int i = 0; i < v.count && i < int(got.size()); i++) {
      const DecodedReading &d = v.readings[i];
      CHECK(got[i].channel == d.channel && got[i].kind == d.kind);
      CHECK(hex(got[i].value, got[i].len) == d.raw);
      if (d.is_int)
        CHECK(got[i].as_int() == d.value);
    }
  }

  // Typed constructors give the vector encodings.
  ReadingWriter w;
  CHECK(w.add(Reading::i16(1, 0x40, -1250)));
  CHECK(w.add(Reading::u32(0, 0x82, 123456)));
  CHECK(w.add(Reading::u8(0, 0x01, 1)));
  CHECK(hex(w.data(), w.size()) == "0140fb1e" "00820001e240" "000101");
  CHECK(Reading::f32(0, 0x84, 1.5f).as_int() == 0x3fc00000);
  CHECK(Reading::i32(0, 0x85, -2).as_int() == -2);

  // 03 section 2: no duplicate (channel, kind), no kind 0, no class mismatch, and a size limit.
  CHECK(!w.add(Reading::u8(0, 0x01, 0)));
  CHECK(w.add(Reading::u8(1, 0x01, 0)));
  Reading bad;
  CHECK(!Reading::make(0, 0x00, nullptr, 0, bad));
  uint8_t two[2] = {1, 2};
  CHECK(!Reading::make(0, 0x01, two, 2, bad));
  Bytes long_value(61, 'x');
  CHECK(!Reading::make(0, 0xC0, long_value.data(), long_value.size(), bad));
  ReadingWriter tight(5);
  CHECK(tight.add(Reading::u8(0, 0x01, 1)));
  CHECK(!tight.add(Reading::u8(0, 0x02, 1)));

  // Truncated payloads and kind 0 are invalid.
  Bytes trunc = unhex("004008");
  CHECK(!decode_readings(trunc.data(), trunc.size(), [](const Reading &) {}));
  Bytes trunc_var = unhex("02c1056869");
  CHECK(!decode_readings(trunc_var.data(), trunc_var.size(), [](const Reading &) {}));
  int seen = 0;
  Bytes kind0 = unhex("000101000001");
  CHECK(!decode_readings(kind0.data(), kind0.size(), [&](const Reading &) { seen++; }));
  CHECK(seen == 1);

  // decode_readings does not check for a repeated (channel, kind) (03 section 2); a
  // sensor only decodes payloads it built with ReadingWriter, which refuses one.
  for (const auto &v : INVALID_PAYLOAD_VECTORS) {
    Bytes enc = unhex(v.encoded);
    bool ok = decode_readings(enc.data(), enc.size(), [](const Reading &) {});
    CHECK(ok == (std::strcmp(v.reason, "duplicate (channel, kind)") == 0));
  }
}

static void test_pairing_code() {
  char code[100];
  CHECK(pairing_code(unhex(V_DEV_EUI).data(), unhex(V_K_ROOT).data(), V_PAIRING_REGION, V_PAIRING_PROFILE, code,
                     sizeof(code)));
  CHECK(std::string(code) == V_PAIRING_CODE);
  CHECK(!pairing_code(unhex(V_DEV_EUI).data(), unhex(V_K_ROOT).data(), V_PAIRING_REGION, V_PAIRING_PROFILE, code,
                      40));
}

// ---------------------------------------------------------------- fakes

struct FakeClock : Clock {
  uint64_t now = 1 * S;
  bool rtc = true;
  uint32_t base = V_TIME - 600;
  uint64_t base_at = 0;
  uint64_t now_us() override { return this->now; }
  bool unix_time(uint32_t &out) override {
    if (!this->rtc)
      return false;
    out = this->base + uint32_t((this->now - this->base_at) / S);
    return true;
  }
  void set_unix_time(uint32_t t) override {
    this->rtc = true;
    this->base = t;
    this->base_at = this->now;
  }
};

struct Tx {
  Bytes frame;
  uint64_t start_us;
  uint64_t done_us;
};

struct FakeRadio : Radio {
  FakeClock *clock{nullptr};
  std::vector<Tx> sent;
  bool busy{false};
  uint64_t end_us{0};
  bool rx{false};
  bool refuse{false};
  bool preamble{false};
  int tx_while_rx{0};
  bool transmit(const uint8_t *f, size_t len) override {
    if (this->refuse)
      return false;
    if (this->rx)
      this->tx_while_rx++;
    this->sent.push_back({Bytes(f, f + len), this->clock->now, 0});
    this->busy = true;
    this->end_us = this->clock->now + this->airtime_us(len);
    return true;
  }
  void start_receive() override { this->rx = true; }
  void stop_receive() override { this->rx = false; }
  bool receiving() override { return this->preamble; }
  uint32_t airtime_us(size_t len) override { return uint32_t(40000 + 1000 * len); }
};

struct FakeStorage : Storage {
  std::map<Blob, Bytes> blobs;
  bool fail{false};
  int saves{0};
  bool load(Blob id, uint8_t *buf, size_t len) override {
    auto it = this->blobs.find(id);
    if (it == this->blobs.end() || it->second.size() != len)
      return false;
    std::memcpy(buf, it->second.data(), len);
    return true;
  }
  bool save(Blob id, const uint8_t *buf, size_t len) override {
    if (this->fail)
      return false;
    this->saves++;
    this->blobs[id] = Bytes(buf, buf + len);
    return true;
  }
  bool erase(Blob id) override {
    this->blobs.erase(id);
    return true;
  }
  bool has(Blob id) const { return this->blobs.count(id) != 0; }
  uint32_t u32(Blob id) const {
    auto it = this->blobs.find(id);
    if (it == this->blobs.end() || it->second.size() != 4)
      return 0;
    const Bytes &b = it->second;
    return uint32_t(b[0]) << 24 | uint32_t(b[1]) << 16 | uint32_t(b[2]) << 8 | b[3];
  }
  void set_u32(Blob id, uint32_t v) {
    this->blobs[id] = {uint8_t(v >> 24), uint8_t(v >> 16), uint8_t(v >> 8), uint8_t(v)};
  }
};

// Scripted 32-byte fills are the ephemeral keys; everything else is a fixed PRNG.
struct FakeRandom : Random {
  std::deque<Bytes> keys;
  uint64_t state{0x9E3779B97F4A7C15ULL};
  void fill(uint8_t *buf, size_t len) override {
    if (len == 32 && !this->keys.empty()) {
      std::memcpy(buf, this->keys.front().data(), 32);
      this->keys.pop_front();
      return;
    }
    for (size_t i = 0; i < len; i++) {
      this->state ^= this->state << 13;
      this->state ^= this->state >> 7;
      this->state ^= this->state << 17;
      buf[i] = uint8_t(this->state);
    }
  }
};

struct Rig {
  FakeClock clock;
  FakeRadio radio;
  FakeStorage storage;
  FakeRandom random;
  SensorConfig cfg;
  std::unique_ptr<SensorCore> core;
  std::vector<SensorEvent> events;
  std::vector<Reading> set_values;
  std::vector<std::pair<uint8_t, Bytes>> commands;

  Rig() {
    this->radio.clock = &this->clock;
    Bytes eui = unhex(V_DEV_EUI), k = unhex(V_K_ROOT);
    std::memcpy(this->cfg.dev_eui, eui.data(), 8);
    std::memcpy(this->cfg.k_root, k.data(), 16);
    this->cfg.heartbeat_minutes = 30;
  }

  // A power-on: RAM state goes, storage and the RTC (unless lost) stay.
  void boot(std::initializer_list<Reading> state = {}) {
    this->core.reset();
    this->radio.busy = this->radio.rx = false;
    this->core.reset(new SensorCore(this->cfg, this->clock, this->radio, this->storage, this->random));
    this->core->on_event = [this](SensorEvent e) { this->events.push_back(e); };
    this->core->on_set_value = [this](const Reading &r) { this->set_values.push_back(r); };
    this->core->on_command = [this](uint8_t id, const uint8_t *a, size_t n) {
      this->commands.push_back({id, Bytes(a, a + n)});
    };
    for (const Reading &r : state)
      CHECK(this->core->set_state(r));
    this->core->begin();
  }

  // A deep sleep and wake: RAM goes, the snapshot (RTC memory), storage and both
  // clocks stay. Returns whether the core resumed; if not, it booted.
  bool sleep_wake(uint64_t sleep_us, std::initializer_list<Reading> state = {}) {
    WarmState w;
    bool snap = this->core->suspend(w);
    this->clock.now += sleep_us;
    this->core.reset();
    this->radio.busy = this->radio.rx = false;
    this->core.reset(new SensorCore(this->cfg, this->clock, this->radio, this->storage, this->random));
    this->core->on_event = [this](SensorEvent e) { this->events.push_back(e); };
    for (const Reading &r : state)
      CHECK(this->core->set_state(r));
    if (snap && this->core->resume(w))
      return true;
    this->core->begin();
    return false;
  }

  void tick_to(uint64_t t) {
    while (this->clock.now < t) {
      uint64_t next = this->clock.now + MS;
      // Jump through idle stretches such as the wait for a heartbeat.
      if (!this->radio.busy && !this->core->hold()) {
        uint64_t wake = this->core->next_wake_us();
        if (wake > next)
          next = wake;
      }
      if (next > t)
        next = t;
      this->clock.now = next;
      if (this->radio.busy && this->clock.now >= this->radio.end_us) {
        this->radio.busy = false;
        this->radio.sent.back().done_us = this->radio.end_us;
        this->core->on_tx_done(this->radio.end_us);
      }
      this->core->loop();
    }
  }
  void run(uint64_t us) { this->tick_to(this->clock.now + us); }

  // Runs until transmission n (1-based) has finished.
  Tx wait_tx(size_t n, uint64_t limit = 2 * 3600 * S) {
    uint64_t end = this->clock.now + limit;
    while (this->clock.now < end && (this->radio.sent.size() < n || this->radio.sent[n - 1].done_us == 0))
      this->tick_to(this->clock.now + MS);
    if (this->radio.sent.size() < n) {
      std::printf("no transmission %zu\n", n);
      return Tx{};
    }
    return this->radio.sent[n - 1];
  }

  // Delivers a frame offset after the end of a transmission.
  DownlinkResult deliver_after(const Tx &t, uint64_t offset, const Bytes &frame) {
    this->tick_to(t.done_us + offset);
    this->core->on_receive(frame.data(), frame.size());
    return this->core->last_downlink_result();
  }
  DownlinkResult in_rx1(const Tx &t, const Bytes &frame) { return this->deliver_after(t, RX1_DELAY_US, frame); }

  bool saw(SensorEvent e) const {
    for (SensorEvent x : this->events) {
      if (x == e)
        return true;
    }
    return false;
  }
};

// The server's side, for building downlinks.
struct Server {
  KeySet keys{};
  uint32_t fcnt{0};
  Bytes downlink(uint32_t reply_to, uint32_t server_time, uint8_t dflags = 0, const Bytes &cmds = {},
                 uint32_t use_fcnt = 0) {
    Bytes pt = {uint8_t(reply_to >> 24), uint8_t(reply_to >> 16), uint8_t(reply_to >> 8), uint8_t(reply_to),
                uint8_t(server_time >> 24), uint8_t(server_time >> 16), uint8_t(server_time >> 8),
                uint8_t(server_time), dflags};
    pt.insert(pt.end(), cmds.begin(), cmds.end());
    Bytes out(FRAME_MAX);
    size_t len = 0;
    seal_frame(this->keys, T_DOWNLINK, 0, 0, use_fcnt ? use_fcnt : ++this->fcnt, pt.data(), pt.size(), out.data(),
               len);
    out.resize(len);
    return out;
  }
};

struct Opened {
  FrameHeader h{};
  Bytes pt;
  bool ok{false};
};

static Opened open_up(const KeySet &keys, const Bytes &frame) {
  Opened o;
  o.pt.resize(PAYLOAD_MAX);
  size_t len = 0;
  o.ok = open_frame(keys, frame.data(), frame.size(), o.h, o.pt.data(), len) == OpenResult::OK;
  o.pt.resize(len);
  return o;
}

static uint32_t fcnt_of(const Tx &t) {
  return uint32_t(t.frame[10]) << 24 | uint32_t(t.frame[11]) << 16 | uint32_t(t.frame[12]) << 8 | t.frame[13];
}
static uint8_t type_of(const Tx &t) { return t.frame[1] & 0x0F; }

static Reading contact(uint8_t v) { return Reading::u8(0, 0x01, v); }
static Reading battery(uint8_t v) { return Reading::u8(0xFF, 0x07, v); }

static KeySet session_keys(const uint8_t *k_session) {
  KeySet k;
  derive_keys(k_session, unhex(V_DEV_EUI).data(), k);
  return k;
}

// Drives the whole frame-v1.json sequence through the core, checking every frame
// byte for byte, and leaves the sensor PAIRED with fcnt 3 answered. Returns the
// server's view of the session.
static Server pair_with_vectors(Rig &rig) {
  rig.boot();
  rig.random.keys.push_back(unhex(V_SENSOR_EPHEMERAL_PRIVATE));
  rig.core->short_press();
  CHECK(rig.core->state() == PairingState::JOINING);
  const Tx &join = rig.wait_tx(1);
  CHECK(hex(join.frame) == fv("join").frame);

  CHECK(rig.in_rx1(join, unhex(fv("downlink_key_exchange").frame)) == DownlinkResult::ACCEPT);
  CHECK(rig.core->state() == PairingState::SESSION);
  CHECK(rig.core->root_floor() == 1);
  CHECK(rig.core->session_key() && hex(rig.core->session_key(), 16) == V_K_SESSION);
  CHECK(rig.storage.u32(Blob::ROOT_FLOOR) == 1);

  const Tx &sync = rig.wait_tx(2);
  CHECK(hex(sync.frame) == fv("sync_after_exchange").frame);

  // A state change waits while pairing finishes (04 section 4.4 step 7).
  CHECK(rig.core->set_state(contact(1)));
  rig.core->report(true);
  CHECK(rig.in_rx1(sync, unhex(fv("downlink_set_network").frame)) == DownlinkResult::ACCEPT);
  CHECK(rig.core->state() == PairingState::PAIRED);
  CHECK(rig.saw(SensorEvent::PAIRED));
  CHECK(rig.storage.has(Blob::SESSION));

  const Tx &data = rig.wait_tx(3);
  CHECK(hex(data.frame) == fv("data_confirmed").frame);
  CHECK(rig.in_rx1(data, unhex(fv("downlink_ack").frame)) == DownlinkResult::ACCEPT);
  CHECK(rig.core->session_floor() == 2);

  Server server;
  if (rig.core->session_key())
    server.keys = session_keys(rig.core->session_key());
  server.fcnt = 2;
  return server;
}

// ---------------------------------------------------------------- vector flows

static void test_frame_vector_flow() {
  Rig rig;
  pair_with_vectors(rig);
  // The heartbeat: unconfirmed (an answer came recently), full state and battery.
  CHECK(rig.core->set_state(battery(95)));
  const Tx &hb = rig.wait_tx(4);
  CHECK(hex(hb.frame) == fv("heartbeat").frame);
  CHECK(hb.start_us - rig.radio.sent[2].start_us >= 27 * MIN);
  CHECK(hb.start_us - rig.radio.sent[2].start_us <= 33 * MIN + S);

  // Battery change with a dead RTC: the counter jumps to the next block and SYNC
  // replaces the boot heartbeat (08 section 9).
  rig.clock.rtc = false;
  rig.boot({contact(1)});
  const Tx &sync = rig.wait_tx(5);
  CHECK(hex(sync.frame) == fv("sync_after_reboot").frame);
  CHECK(rig.radio.tx_while_rx == 0);
}

static void test_root_floor_vectors() {
  Rig rig;
  rig.boot();
  Tx last{};
  for (size_t i = 0; i < sizeof(ROOT_FLOOR_STEPS) / sizeof(ROOT_FLOOR_STEPS[0]); i++) {
    const RootFloorStep &st = ROOT_FLOOR_STEPS[i];
    std::string ev = st.event;
    if (ev == "join") {
      // A power cycle with the counter reservation at the vector's fcnt.
      rig.storage.set_u32(Blob::COUNTER, st.fcnt);
      rig.boot();
      CHECK(rig.core->state() == PairingState::UNPAIRED);
      rig.random.keys.push_back(unhex(st.priv));
      rig.core->short_press();
      last = rig.wait_tx(rig.radio.sent.size() + 1);
      CHECK(hex(last.frame) == st.frame);
    } else if (ev == "downlink") {
      rig.tick_to(last.done_us + RX1_DELAY_US);
      Bytes f = unhex(st.frame);
      rig.core->on_receive(f.data(), f.size());
      CHECK(std::string(downlink_result_str(rig.core->last_downlink_result())) == st.result);
      CHECK(rig.core->root_floor() == st.root_floor);
      CHECK(rig.storage.u32(Blob::ROOT_FLOOR) == st.root_floor);
      if (st.k_session) {
        CHECK(rig.core->state() == PairingState::SESSION);
        CHECK(rig.core->session_key() && hex(rig.core->session_key(), 16) == st.k_session);
      } else {
        CHECK(rig.core->state() == PairingState::JOINING);
        CHECK(rig.core->session_key() == nullptr);
      }
    } else if (ev == "leave") {
      // Finish pairing, then the server sends LEAVE.
      if (!rig.core->session_key())
        break;
      Server server;
      server.keys = session_keys(rig.core->session_key());
      const Tx &sync = rig.wait_tx(rig.radio.sent.size() + 1);
      Bytes route = unhex(V_K_NET_ROUTE), cmd = {CMD_SET_NETWORK, 16};
      cmd.insert(cmd.end(), route.begin(), route.end());
      CHECK(rig.in_rx1(sync, server.downlink(fcnt_of(sync), V_TIME, 0, cmd)) == DownlinkResult::ACCEPT);
      const Tx &hb = rig.wait_tx(rig.radio.sent.size() + 1);
      CHECK(type_of(hb) == T_HEARTBEAT_CONFIRMED);
      CHECK(rig.in_rx1(hb, server.downlink(fcnt_of(hb), V_TIME, 0, {CMD_LEAVE, 0})) == DownlinkResult::ACCEPT);
      rig.wait_tx(rig.radio.sent.size() + 1);
      CHECK(rig.core->state() == PairingState::UNPAIRED);
      CHECK(rig.core->root_floor() == st.root_floor);
      CHECK(rig.storage.u32(Blob::ROOT_FLOOR) == st.root_floor);
    } else if (ev == "factory_reset") {
      rig.core->factory_reset();
      CHECK(rig.core->root_floor() == st.root_floor);
      CHECK(!rig.storage.has(Blob::ROOT_FLOOR));
    } else {
      std::printf("unknown root_floor event %s\n", st.event);
      CHECK(false);
    }
  }
}

// ---------------------------------------------------------------- scenarios

static void test_rx_windows_and_answer_in_rx1() {
  Rig rig;
  Server server = pair_with_vectors(rig);
  size_t n = rig.radio.sent.size();
  rig.core->report(true);
  const Tx &t = rig.wait_tx(n + 1);
  CHECK(type_of(t) == T_DATA_CONFIRMED);
  // 01 section 4: receiver on from delay - 20 ms to at least delay + W (150 ms on US915).
  CHECK(RX_EARLY_US == 20 * MS && RX_LATE_US == 150 * MS);
  rig.tick_to(t.done_us + 979 * MS);
  CHECK(!rig.radio.rx);
  rig.tick_to(t.done_us + 981 * MS);
  CHECK(rig.radio.rx);
  CHECK(rig.core->hold());
  // Received at the latest detection the timing budget allows (01 section 4.1).
  CHECK(rig.deliver_after(t, RX1_DELAY_US + 102 * MS, server.downlink(fcnt_of(t), V_TIME + 100)) ==
        DownlinkResult::ACCEPT);
  CHECK(!rig.radio.rx);
  CHECK(rig.saw(SensorEvent::UPLINK_ANSWERED));
  // No RX2 and no retry after an answer in RX1.
  rig.tick_to(t.done_us + 3 * S);
  CHECK(!rig.radio.rx);
  rig.run(60 * S);
  CHECK(rig.radio.sent.size() == n + 1);
  CHECK(!rig.core->hold());
}

static void test_answer_in_rx2() {
  Rig rig;
  Server server = pair_with_vectors(rig);
  size_t n = rig.radio.sent.size();
  rig.core->report(true);
  const Tx &t = rig.wait_tx(n + 1);
  rig.tick_to(t.done_us + 1149 * MS);
  CHECK(rig.radio.rx);
  rig.tick_to(t.done_us + 1152 * MS);
  CHECK(!rig.radio.rx);
  rig.tick_to(t.done_us + 2979 * MS);
  CHECK(!rig.radio.rx);
  rig.tick_to(t.done_us + 2981 * MS);
  CHECK(rig.radio.rx);
  CHECK(rig.deliver_after(t, RX2_DELAY_US + 20 * MS, server.downlink(fcnt_of(t), V_TIME + 100)) ==
        DownlinkResult::ACCEPT);
  rig.run(60 * S);
  CHECK(rig.radio.sent.size() == n + 1);
  CHECK(rig.core->undelivered() == 0);
}

static void test_unanswered_retries() {
  Rig rig;
  pair_with_vectors(rig);
  size_t n = rig.radio.sent.size();
  rig.core->report(true);
  const Tx first = rig.wait_tx(n + 1);
  rig.run(50 * S);
  CHECK(rig.radio.sent.size() == n + 4);
  // 08 section 5: identical bytes at 4+0..2 s, 12+0..4 s and 30+0..10 s after the original.
  const uint64_t lo[3] = {4 * S, 12 * S, 30 * S}, hi[3] = {6 * S, 16 * S, 40 * S};
  for (size_t i = 0; i < 3 && n + 1 + i < rig.radio.sent.size(); i++) {
    const Tx &r = rig.radio.sent[n + 1 + i];
    CHECK(r.frame == first.frame);
    CHECK(r.start_us >= first.done_us + lo[i]);
    CHECK(r.start_us <= first.done_us + hi[i] + MS);
  }
  // Each retry gets its own RX1 and RX2; after the last one the uplink is undelivered.
  CHECK(rig.saw(SensorEvent::UPLINK_UNDELIVERED));
  CHECK(rig.core->undelivered() == 1);
  CHECK(!rig.core->hold());
  CHECK(rig.radio.tx_while_rx == 0);
}

static void test_retry_window_answer() {
  // A lost answer is recovered by the retry's own RX1.
  Rig rig;
  Server server = pair_with_vectors(rig);
  size_t n = rig.radio.sent.size();
  rig.core->report(true);
  rig.wait_tx(n + 1);
  const Tx retry = rig.wait_tx(n + 2);
  CHECK(fcnt_of(retry) == fcnt_of(rig.radio.sent[n]));
  CHECK(rig.in_rx1(retry, server.downlink(fcnt_of(retry), V_TIME + 100)) == DownlinkResult::ACCEPT);
  rig.run(60 * S);
  CHECK(rig.radio.sent.size() == n + 2);
}

static void test_downlink_checks() {
  Rig rig;
  Server server = pair_with_vectors(rig);
  size_t n = rig.radio.sent.size();
  rig.core->report(true);
  const Tx &t = rig.wait_tx(n + 1);
  uint32_t f = fcnt_of(t);
  // Outside a window.
  rig.tick_to(t.done_us + 500 * MS);
  Bytes good = server.downlink(f, V_TIME + 100, 0, {}, 5);
  rig.core->on_receive(good.data(), good.size());
  CHECK(rig.core->last_downlink_result() == DownlinkResult::NO_WINDOW);
  // 08 section 13 item 5: wrong reply_to, stale counter, bad MIC.
  CHECK(rig.in_rx1(t, server.downlink(f - 1, V_TIME + 100, 0, {}, 6)) == DownlinkResult::WRONG_REPLY_TO);
  CHECK(rig.in_rx1(t, server.downlink(f, V_TIME + 100, 0, {}, 2)) == DownlinkResult::AT_OR_BELOW_FLOOR);
  CHECK(rig.in_rx1(t, server.downlink(f, V_TIME + 100, 0, {}, 1)) == DownlinkResult::AT_OR_BELOW_FLOOR);
  Bytes forged = good;
  forged[15] ^= 1;
  CHECK(rig.in_rx1(t, forged) == DownlinkResult::BAD_MIC);
  Bytes uplink_type = good;
  uplink_type[1] = 0x12;
  CHECK(rig.in_rx1(t, uplink_type) == DownlinkResult::BAD_FRAME);
  // The frame vector downlinks are old and bound to other uplinks.
  CHECK(rig.in_rx1(t, unhex(fv("downlink_ack").frame)) == DownlinkResult::WRONG_REPLY_TO);
  CHECK(rig.core->session_floor() == 2);
  CHECK(rig.in_rx1(t, good) == DownlinkResult::ACCEPT);
  CHECK(rig.core->session_floor() == 5);
  CHECK(rig.storage.u32(Blob::SESSION_FLOOR) == 5);

  // The session floor survives a reboot.
  rig.boot({contact(1)});
  const Tx &boot = rig.wait_tx(n + 2);
  CHECK(type_of(boot) == T_HEARTBEAT_CONFIRMED);
  CHECK(rig.in_rx1(boot, server.downlink(fcnt_of(boot), V_TIME + 200, 0, {}, 5)) ==
        DownlinkResult::AT_OR_BELOW_FLOOR);
  CHECK(rig.in_rx1(boot, server.downlink(fcnt_of(boot), V_TIME + 200, 0, {}, 6)) == DownlinkResult::ACCEPT);
}

static void test_counter_reservation() {
  Rig rig;
  rig.boot();
  // 02 section 8.2: the first boot reserves 1..64.
  CHECK(rig.core->next_fcnt() == 1);
  CHECK(rig.storage.u32(Blob::COUNTER) == 65);
  rig.boot();
  CHECK(rig.core->next_fcnt() == 65);
  CHECK(rig.storage.u32(Blob::COUNTER) == 129);

  Rig r1;
  pair_with_vectors(r1);
  CHECK(fcnt_of(r1.radio.sent[0]) == 1);
  r1.storage.set_u32(Blob::COUNTER, 200);
  r1.boot({contact(1)});
  r1.run(10 * S);  // boot heartbeat at 200, unanswered retries pending
  CHECK(fcnt_of(r1.radio.sent.back()) == 200);
  r1.core->factory_reset();
  size_t before = r1.radio.sent.size();
  uint32_t highest = 0;
  for (const Tx &t : r1.radio.sent)
    highest = fcnt_of(t) > highest ? fcnt_of(t) : highest;
  // 08 section 13 item 2: after a factory reset and a power cycle the counter still moves on.
  r1.boot();
  r1.random.keys.push_back(Bytes(32, 0x42));
  r1.core->short_press();
  const Tx &join = r1.wait_tx(before + 1);
  CHECK(fcnt_of(join) > highest);
  CHECK(fcnt_of(join) == 264);

  // Crossing a block boundary while running.
  Rig r2;
  r2.storage.set_u32(Blob::COUNTER, 1);
  Server s2 = pair_with_vectors(r2);
  for (int i = 0; i < 62; i++) {
    r2.core->report(false);
    r2.wait_tx(r2.radio.sent.size() + 1);
  }
  CHECK(fcnt_of(r2.radio.sent.back()) == 65);
  CHECK(r2.storage.u32(Blob::COUNTER) == 129);
  (void) s2;
}

static void test_storage_failure() {
  Rig rig;
  rig.storage.fail = true;
  rig.boot();
  CHECK(rig.saw(SensorEvent::STORAGE_FAILED));
  rig.random.keys.push_back(Bytes(32, 0x42));
  rig.core->short_press();
  rig.run(10 * S);
  CHECK(rig.radio.sent.empty());
}

static void test_factory_reset() {
  for (int where = 0; where < 3; where++) {
    // 08 section 13 item 9: in every pairing state.
    Rig rig;
    pair_with_vectors(rig);
    rig.storage.save(Blob::SETTINGS, Bytes{0, 5}.data(), 2);
    if (where == 1) {
      rig.core->factory_reset();
      rig.random.keys.push_back(Bytes(32, 0x33));
      rig.core->short_press();
      CHECK(rig.core->state() == PairingState::JOINING);
    } else if (where == 2) {
      rig.core->factory_reset();
      rig.random.keys.push_back(Bytes(32, 0x33));
      rig.core->short_press();
      const Tx &join = rig.wait_tx(rig.radio.sent.size() + 1);
      // A server whose root counter is at 9 answers; the sensor moves to SESSION.
      KeySet root;
      derive_keys(unhex(V_K_ROOT).data(), unhex(V_DEV_EUI).data(), root);
      Opened j = open_up(root, join.frame);
      Bytes v_priv(32, 0x55), v_pub(32);
      x25519_base(v_pub.data(), v_priv.data());
      Server rs;
      rs.keys = root;
      Bytes cmd = {CMD_KEY_EXCHANGE, 32};
      cmd.insert(cmd.end(), v_pub.begin(), v_pub.end());
      CHECK(rig.in_rx1(join, rs.downlink(fcnt_of(join), V_TIME, 0, cmd, 9)) == DownlinkResult::ACCEPT);
      CHECK(rig.core->state() == PairingState::SESSION);
    }
    uint32_t counter = rig.storage.u32(Blob::COUNTER);
    rig.core->factory_reset();
    CHECK(rig.saw(SensorEvent::FACTORY_RESET));
    CHECK(rig.core->state() == PairingState::UNPAIRED);
    CHECK(rig.core->root_floor() == 0);
    CHECK(rig.core->session_floor() == 0);
    CHECK(rig.core->session_key() == nullptr);
    CHECK(!rig.storage.has(Blob::SESSION));
    CHECK(!rig.storage.has(Blob::ROOT_FLOOR));
    CHECK(!rig.storage.has(Blob::SESSION_FLOOR));
    CHECK(!rig.storage.has(Blob::SETTINGS));
    CHECK(rig.storage.u32(Blob::COUNTER) == counter);
    CHECK(!rig.core->hold());

    // Nothing is sent until the button, and then a KEY_EXCHANGE with root counter 1 is accepted.
    size_t n = rig.radio.sent.size();
    rig.run(3600 * S);
    CHECK(rig.radio.sent.size() == n);
    rig.boot();
    CHECK(rig.core->state() == PairingState::UNPAIRED);
    Bytes s_priv(32, 0x77), v_priv(32, 0x66), v_pub(32), s_pub(32);
    rig.random.keys.push_back(s_priv);
    rig.core->short_press();
    const Tx &join = rig.wait_tx(n + 1);
    KeySet root;
    derive_keys(unhex(V_K_ROOT).data(), unhex(V_DEV_EUI).data(), root);
    Opened j = open_up(root, join.frame);
    CHECK(j.ok && type_of(join) == T_JOIN && j.pt.size() == 33 && j.pt[0] == UF_TIME_UNSURE);
    x25519_base(s_pub.data(), s_priv.data());
    CHECK(Bytes(j.pt.begin() + 1, j.pt.end()) == s_pub);
    x25519_base(v_pub.data(), v_priv.data());
    Server rs;
    rs.keys = root;
    Bytes cmd = {CMD_KEY_EXCHANGE, 32};
    cmd.insert(cmd.end(), v_pub.begin(), v_pub.end());
    CHECK(rig.in_rx1(join, rs.downlink(fcnt_of(join), V_TIME, 0, cmd, 1)) == DownlinkResult::ACCEPT);
    CHECK(rig.core->root_floor() == 1);
    Bytes k(16);
    CHECK(derive_session(unhex(V_K_ROOT).data(), unhex(V_DEV_EUI).data(), v_priv.data(), s_pub.data(),
                         s_pub.data(), v_pub.data(), k.data()));
    CHECK(rig.core->session_key() && hex(rig.core->session_key(), 16) == hex(k));
    CHECK(rig.core->heartbeat_minutes() == 30);
  }
}

static void test_join_unanswered() {
  Rig rig;
  rig.boot();
  rig.random.keys.push_back(unhex(V_SENSOR_EPHEMERAL_PRIVATE));
  rig.core->short_press();
  rig.run(60 * S);
  CHECK(rig.radio.sent.size() == 4);
  for (const Tx &t : rig.radio.sent)
    CHECK(hex(t.frame) == fv("join").frame);
  // 04 section 4.4: back to UNPAIRED, and a new press uses a new key pair.
  CHECK(rig.core->state() == PairingState::UNPAIRED);
  CHECK(rig.saw(SensorEvent::PAIRING_FAILED));
  rig.core->short_press();
  const Tx &again = rig.wait_tx(5);
  CHECK(type_of(again) == T_JOIN);
  CHECK(fcnt_of(again) == 2);
  CHECK(Bytes(again.frame.begin() + 14, again.frame.end()) !=
        Bytes(rig.radio.sent[0].frame.begin() + 14, rig.radio.sent[0].frame.end()));
  // The answer to the old JOIN is not accepted for the new one.
  CHECK(rig.in_rx1(again, unhex(fv("downlink_key_exchange").frame)) == DownlinkResult::WRONG_REPLY_TO);
}

static void test_session_sync_unanswered() {
  Rig rig;
  rig.boot();
  rig.random.keys.push_back(unhex(V_SENSOR_EPHEMERAL_PRIVATE));
  rig.core->short_press();
  const Tx &join = rig.wait_tx(1);
  CHECK(rig.in_rx1(join, unhex(fv("downlink_key_exchange").frame)) == DownlinkResult::ACCEPT);
  rig.run(60 * S);
  CHECK(rig.radio.sent.size() == 5);  // JOIN, then SYNC and three retries
  CHECK(rig.core->state() == PairingState::UNPAIRED);
  CHECK(rig.core->session_key() == nullptr);
  CHECK(rig.core->root_floor() == 1);  // kept: only a factory reset clears it
  // A restart in SESSION also starts over.
  Rig r2;
  r2.boot();
  r2.random.keys.push_back(unhex(V_SENSOR_EPHEMERAL_PRIVATE));
  r2.core->short_press();
  const Tx &j2 = r2.wait_tx(1);
  CHECK(r2.in_rx1(j2, unhex(fv("downlink_key_exchange").frame)) == DownlinkResult::ACCEPT);
  r2.boot();
  CHECK(r2.core->state() == PairingState::UNPAIRED);
  CHECK(r2.core->root_floor() == 1);
}

static void test_pairing_button_and_leave_mid_pairing() {
  // 04 section 4.5: a short press in JOINING or SESSION changes nothing.
  Rig rig;
  rig.boot();
  rig.random.keys.push_back(unhex(V_SENSOR_EPHEMERAL_PRIVATE));
  rig.core->short_press();
  const Tx &join = rig.wait_tx(1);
  rig.core->short_press();
  CHECK(rig.core->state() == PairingState::JOINING);
  CHECK(rig.in_rx1(join, unhex(fv("downlink_key_exchange").frame)) == DownlinkResult::ACCEPT);
  CHECK(rig.core->state() == PairingState::SESSION);
  rig.core->short_press();
  CHECK(rig.core->state() == PairingState::SESSION);
  const Tx &sync = rig.wait_tx(2);
  CHECK(type_of(sync) == T_SYNC);
  for (const Tx &t : rig.radio.sent)
    CHECK(type_of(t) != T_JOIN || hex(t.frame) == fv("join").frame);

  // 04 section 6.1: LEAVE in SESSION unpairs at once, with no final HEARTBEAT.
  Server server;
  server.keys = session_keys(rig.core->session_key());
  CHECK(rig.in_rx1(sync, server.downlink(fcnt_of(sync), V_TIME, 0, {CMD_LEAVE, 0})) == DownlinkResult::ACCEPT);
  CHECK(rig.core->state() == PairingState::UNPAIRED);
  CHECK(rig.saw(SensorEvent::LEFT));
  CHECK(rig.core->session_key() == nullptr);
  CHECK(rig.core->root_floor() == 1);
  rig.run(3600 * S);
  CHECK(rig.radio.sent.size() == 2);
}

static void test_time_unsure_and_sync() {
  Rig rig;
  Server server = pair_with_vectors(rig);
  KeySet keys = server.keys;

  // RTC survived: HEARTBEAT_CONFIRMED with normal tags and TIME_UNSURE.
  size_t n = rig.radio.sent.size();
  rig.cfg.has_firmware_version = true;
  rig.cfg.firmware_version[0] = 1;
  rig.cfg.firmware_version[1] = 2;
  rig.boot({contact(0), battery(80)});
  const Tx &hb = rig.wait_tx(n + 1);
  Opened o = open_up(keys, hb.frame);
  CHECK(o.ok && type_of(hb) == T_HEARTBEAT_CONFIRMED);
  CHECK(o.h.net_tag != 0 && o.h.dev_tag != 0);
  CHECK(hex(o.pt) == "02" "000100" "ff0750" "ffc203010200");
  CHECK(!rig.core->time_sure());
  CHECK(rig.in_rx1(hb, server.downlink(fcnt_of(hb), V_TIME + 7300)) == DownlinkResult::ACCEPT);
  CHECK(rig.core->time_sure());
  rig.core->report(false);
  const Tx &d = rig.wait_tx(n + 2);
  o = open_up(keys, d.frame);
  CHECK(o.ok && type_of(d) == T_DATA && o.pt[0] == 0);
  // The tags follow the clock the downlink set: two epochs on.
  uint8_t route[16];
  std::memcpy(route, unhex(V_K_NET_ROUTE).data(), 16);
  CHECK(o.h.net_tag == net_tag(route, V_EPOCH + 2));
  CHECK(o.h.dev_tag == dev_tag(keys.k_dev_tag, V_EPOCH + 2));

  // RTC lost: every uplink is SYNC with bootstrap tags until a downlink sets the clock.
  rig.clock.rtc = false;
  rig.boot({contact(1)});
  const Tx &s = rig.wait_tx(n + 3);
  o = open_up(keys, s.frame);
  CHECK(o.ok && type_of(s) == T_SYNC && o.h.net_tag == 0 && o.h.dev_tag == 0);
  CHECK(hex(o.pt) == "02000101" "ffc203010200");
  rig.run(60 * S);  // unanswered: retries, then undelivered
  rig.core->report(false);
  const Tx &s2 = rig.wait_tx(n + 7);
  CHECK(type_of(s2) == T_SYNC);
  CHECK(rig.in_rx1(s2, server.downlink(fcnt_of(s2), V_TIME + 3600)) == DownlinkResult::ACCEPT);
  rig.core->report(false);
  const Tx &d2 = rig.wait_tx(n + 8);
  o = open_up(keys, d2.frame);
  CHECK(type_of(d2) == T_DATA && o.pt[0] == 0);
  CHECK(o.h.dev_tag == dev_tag(keys.k_dev_tag, V_EPOCH + 1));
}

static void test_lost_contact() {
  Rig rig;
  Server server = pair_with_vectors(rig);
  for (int i = 0; i < 3; i++) {
    rig.core->report(true);
    rig.run(50 * S);
  }
  CHECK(rig.core->undelivered() == 3);
  size_t n = rig.radio.sent.size();
  CHECK(n == 3 + 12);
  // Unconfirmed state changes continue as usual.
  rig.core->report(false);
  const Tx &d = rig.wait_tx(n + 1);
  CHECK(type_of(d) == T_DATA);
  // 08 section 6: a confirmed heartbeat, as SYNC with the full state, 1 minute after the last failure.
  uint64_t failed_at = rig.radio.sent[n - 1].done_us + RX2_DELAY_US + RX_LATE_US;
  const Tx &s = rig.wait_tx(n + 2);
  CHECK(type_of(s) == T_SYNC);
  CHECK(s.start_us >= failed_at + MIN - MS && s.start_us <= failed_at + MIN + 2 * S);
  Opened o = open_up(server.keys, s.frame);
  CHECK(hex(o.pt) == "00000101");
  // Unanswered again: the next tries come 5 and 15 minutes after each failure.
  rig.wait_tx(n + 5);
  uint64_t f2 = rig.radio.sent[n + 4].done_us + RX2_DELAY_US + RX_LATE_US;
  const Tx &s2 = rig.wait_tx(n + 6);
  CHECK(type_of(s2) == T_SYNC);
  CHECK(s2.start_us >= f2 + 5 * MIN - MS && s2.start_us <= f2 + 5 * MIN + 2 * S);
  CHECK(rig.core->undelivered() == 4);
  // A confirmed state change is a SYNC too, and an answer ends it.
  rig.wait_tx(n + 9);
  rig.core->report(true);
  const Tx &s3 = rig.wait_tx(n + 10);
  CHECK(type_of(s3) == T_SYNC);
  CHECK(rig.in_rx1(s3, server.downlink(fcnt_of(s3), V_TIME + 1000)) == DownlinkResult::ACCEPT);
  CHECK(rig.core->undelivered() == 0);
  rig.core->report(true);
  CHECK(type_of(rig.wait_tx(n + 11)) == T_DATA_CONFIRMED);
  CHECK(rig.core->state() == PairingState::PAIRED);
}

static void test_commands() {
  Rig rig;
  Server server = pair_with_vectors(rig);
  size_t n = rig.radio.sent.size();
  rig.core->report(true);
  const Tx &t = rig.wait_tx(n + 1);
  Bytes cmds = {
      0x30, 2, 9, 9,                    // reserved network command: skipped
      CMD_SET_HEARTBEAT, 2, 0, 5,       // 5 minutes
      CMD_SET_VALUE, 3, 1, 0x06, 1,     // channel 1 binary = 1
      CMD_SET_VALUE, 4, 2, 0xC0, 1, 7,  // variable length with its length byte
      CMD_SET_VALUE, 3, 1, 0x40, 1,     // wrong size for the kind: ignored
      0x41, 1, 0xAA,                    // profile command
      CMD_KEY_EXCHANGE, 0,              // not valid here
  };
  CHECK(rig.in_rx1(t, server.downlink(fcnt_of(t), V_TIME + 100, 0, cmds)) == DownlinkResult::ACCEPT);
  CHECK(rig.core->heartbeat_minutes() == 5);
  CHECK(rig.storage.has(Blob::SETTINGS));
  CHECK(rig.set_values.size() == 2);
  if (rig.set_values.size() == 2) {
    CHECK(rig.set_values[0].channel == 1 && rig.set_values[0].kind == 0x06 && rig.set_values[0].as_int() == 1);
    CHECK(rig.set_values[1].kind == 0xC0 && rig.set_values[1].len == 1 && rig.set_values[1].value[0] == 7);
  }
  CHECK(rig.commands.size() == 1 && rig.commands[0].first == 0x41 && rig.commands[0].second == Bytes{0xAA});
  CHECK(rig.core->state() == PairingState::PAIRED);

  // SET_HEARTBEAT reschedules from now, and the next uplink carries DL_ACK.
  uint64_t at = rig.clock.now;
  const Tx &hb = rig.wait_tx(n + 2);
  CHECK(hb.start_us >= at + 4 * MIN + 30 * S && hb.start_us <= at + 5 * MIN + 30 * S + MS);
  Opened o = open_up(server.keys, hb.frame);
  CHECK(o.pt[0] == UF_DL_ACK);
  CHECK(rig.in_rx1(hb, server.downlink(fcnt_of(hb), V_TIME + 400)) == DownlinkResult::ACCEPT);
  rig.core->report(false);
  const Tx &d = rig.wait_tx(n + 3);
  CHECK(open_up(server.keys, d.frame).pt[0] == 0);

  // SET_HEARTBEAT survives a reboot; out of range values are ignored.
  rig.boot({contact(1)});
  CHECK(rig.core->heartbeat_minutes() == 5);
  const Tx &boot = rig.wait_tx(n + 4);
  CHECK(rig.in_rx1(boot, server.downlink(fcnt_of(boot), V_TIME + 500, 0, {CMD_SET_HEARTBEAT, 2, 0x05, 0xA1})) ==
        DownlinkResult::ACCEPT);
  CHECK(rig.core->heartbeat_minutes() == 5);
}

static void test_leave() {
  Rig rig;
  Server server = pair_with_vectors(rig);
  CHECK(rig.core->set_state(battery(90)));
  size_t n = rig.radio.sent.size();
  uint32_t counter = rig.storage.u32(Blob::COUNTER);
  rig.core->report(true);
  const Tx &t = rig.wait_tx(n + 1);
  CHECK(rig.in_rx1(t, server.downlink(fcnt_of(t), V_TIME + 100, 0, {CMD_LEAVE, 0, CMD_SET_HEARTBEAT, 2, 0, 9})) ==
        DownlinkResult::ACCEPT);
  // 08 section 8: one final unconfirmed HEARTBEAT with DL_ACK under the old keys.
  const Tx &last = rig.wait_tx(n + 2);
  Opened o = open_up(server.keys, last.frame);
  CHECK(o.ok && type_of(last) == T_HEARTBEAT && o.h.net_tag != 0);
  CHECK(hex(o.pt) == "01" "000101" "ff075a");
  CHECK(rig.core->state() == PairingState::UNPAIRED);
  CHECK(rig.saw(SensorEvent::LEFT));
  // RX1 still opens after it (01 section 4); nothing in it verifies any more.
  rig.tick_to(last.done_us + RX1_DELAY_US);
  CHECK(rig.radio.rx);
  CHECK(rig.in_rx1(last, server.downlink(fcnt_of(last), V_TIME + 200)) == DownlinkResult::NO_KEYS);
  rig.tick_to(last.done_us + RX1_DELAY_US + RX_LATE_US + MS);
  CHECK(!rig.radio.rx);
  CHECK(!rig.core->hold());
  CHECK(rig.core->session_key() == nullptr);
  CHECK(!rig.storage.has(Blob::SESSION));
  CHECK(rig.core->root_floor() == 1 && rig.storage.u32(Blob::ROOT_FLOOR) == 1);
  CHECK(rig.storage.u32(Blob::COUNTER) == counter);
  CHECK(rig.core->heartbeat_minutes() == 9);  // commands run in order, after LEAVE too (02 section 10.2)
  // 04 section 6.1: silent until the button.
  rig.core->report(true);
  rig.run(3 * 3600 * S);
  CHECK(rig.radio.sent.size() == n + 2);
  rig.boot();
  CHECK(rig.core->state() == PairingState::UNPAIRED);
}

static void test_pending() {
  Rig rig;
  Server server = pair_with_vectors(rig);
  size_t n = rig.radio.sent.size();
  rig.core->report(true);
  Tx t = rig.wait_tx(n + 1);
  for (int i = 0; i < 5; i++) {
    CHECK(rig.in_rx1(t, server.downlink(fcnt_of(t), V_TIME + 100, DF_PENDING)) == DownlinkResult::ACCEPT);
    uint64_t at = rig.clock.now;
    if (i < 4) {
      // 08 section 7: a HEARTBEAT 2 to 4 s later.
      t = rig.wait_tx(n + 2 + size_t(i), 5 * S);
      CHECK(type_of(t) == T_HEARTBEAT);
      CHECK(t.start_us >= at + 2 * S && t.start_us <= at + 4 * S + MS);
    } else {
      // At most 4 in a row.
      rig.run(6 * S);
      CHECK(rig.radio.sent.size() == n + 5);
    }
  }
}

static void test_abandon_retries() {
  Rig rig;
  Server server = pair_with_vectors(rig);
  size_t n = rig.radio.sent.size();
  rig.core->report(true);
  const Tx first = rig.wait_tx(n + 1);
  rig.tick_to(first.done_us + 3500 * MS);  // RX2 over, waiting for retry 1
  CHECK(rig.core->hold());
  CHECK(rig.core->set_state(contact(0)));
  rig.core->report(false);
  const Tx &next = rig.wait_tx(n + 2);
  // 08 section 5: a new confirmed frame with a new counter and the latest state.
  CHECK(fcnt_of(next) == fcnt_of(first) + 1);
  CHECK(type_of(next) == T_DATA_CONFIRMED);
  CHECK(hex(open_up(server.keys, next.frame).pt) == "00000100");
  CHECK(next.start_us < first.done_us + 4 * S);
  // Abandoned is not undelivered (08 section 5).
  CHECK(rig.core->undelivered() == 0);
  CHECK(!rig.saw(SensorEvent::UPLINK_UNDELIVERED));

  // A frame carrying an event finishes its retries first.
  CHECK(rig.in_rx1(next, server.downlink(fcnt_of(next), V_TIME + 100)) == DownlinkResult::ACCEPT);
  CHECK(rig.core->send_event(Reading::u8(0, 0x08, 1)));
  const Tx ev = rig.wait_tx(n + 3);
  CHECK(hex(open_up(server.keys, ev.frame).pt) == "00" "000801" "000100");
  rig.tick_to(ev.done_us + 3500 * MS);
  rig.core->report(true);
  const Tx &r1 = rig.wait_tx(n + 4);
  CHECK(r1.frame == ev.frame);
  CHECK(rig.in_rx1(r1, server.downlink(fcnt_of(r1), V_TIME + 100)) == DownlinkResult::ACCEPT);
  const Tx &after = rig.wait_tx(n + 5);
  CHECK(fcnt_of(after) == fcnt_of(ev) + 1);
  // Events never go in heartbeats; two of the same key go in separate frames.
  CHECK(rig.in_rx1(after, server.downlink(fcnt_of(after), V_TIME + 100)) == DownlinkResult::ACCEPT);
  CHECK(rig.core->send_event(Reading::u8(0, 0x08, 1)));
  CHECK(rig.core->send_event(Reading::u8(0, 0x08, 2)));
  const Tx &e1 = rig.wait_tx(n + 6);
  CHECK(hex(open_up(server.keys, e1.frame).pt) == "00" "000801" "000100");
  CHECK(rig.in_rx1(e1, server.downlink(fcnt_of(e1), V_TIME + 100)) == DownlinkResult::ACCEPT);
  const Tx &e2 = rig.wait_tx(n + 7);
  CHECK(hex(open_up(server.keys, e2.frame).pt) == "00" "000802" "000100");
}

static void test_airtime_budget() {
  Rig rig;
  rig.cfg.airtime_budget_us = 300000;  // fits three 66 ms frames after pairing's
  Server server = pair_with_vectors(rig);
  size_t n = rig.radio.sent.size();
  uint64_t start = rig.clock.now;
  for (int i = 0; i < 6; i++) {
    CHECK(rig.core->set_state(contact(uint8_t(i & 1))));
    rig.core->report(false);
    rig.run(3 * S);
  }
  uint64_t used = 0;
  for (const Tx &t : rig.radio.sent)
    used += rig.radio.airtime_us(t.frame.size());
  CHECK(used <= rig.cfg.airtime_budget_us);
  CHECK(rig.radio.sent.size() < n + 6);
  // Postponed frames collapse into one with the latest state once the hour rolls on.
  size_t sent = rig.radio.sent.size();
  rig.tick_to(start + 3700 * S);
  CHECK(rig.radio.sent.size() >= sent + 1);
  const Tx &late = rig.radio.sent[sent];
  CHECK(hex(open_up(server.keys, late.frame).pt) == "00000101");
}

static void test_state_limits_and_hints() {
  Rig rig;
  rig.boot();
  CHECK(!rig.core->hold());
  CHECK(rig.core->next_wake_us() == UINT64_MAX);
  // A short press means nothing in JOINING; reports are dropped while unpaired.
  rig.core->report(true);
  CHECK(!rig.core->hold());
  CHECK(!rig.core->send_event(Reading::u8(0, 0x08, 1)));
  // set_state replaces by (channel, kind) and refuses what would not fit in one frame.
  CHECK(rig.core->set_state(contact(1)));
  CHECK(rig.core->set_state(contact(0)));
  Bytes big(55, 'x');
  Reading text;
  CHECK(Reading::make(2, 0xC1, big.data(), big.size(), text));
  CHECK(rig.core->set_state(text));  // 3 + 58 = 61 bytes
  CHECK(!rig.core->set_state(battery(50)));
  Reading zero;
  CHECK(!rig.core->set_state(zero));

  Rig paired;
  Server server = pair_with_vectors(paired);
  CHECK(!paired.core->hold());
  uint64_t wake = paired.core->next_wake_us();
  CHECK(wake > paired.clock.now + 26 * MIN && wake < paired.clock.now + 34 * MIN);
  paired.core->short_press();  // range test: confirmed state frame
  CHECK(paired.core->hold());
  const Tx &t = paired.wait_tx(paired.radio.sent.size() + 1);
  CHECK(type_of(t) == T_DATA_CONFIRMED);
  CHECK(paired.core->next_wake_us() == t.done_us + RX1_DELAY_US - RX_EARLY_US);
  // A refused transmit is tried again shortly with the same frame.
  paired.radio.refuse = true;
  paired.run(10 * S);
  paired.radio.refuse = false;
  const Tx &again = paired.wait_tx(paired.radio.sent.size() + 1);
  CHECK(again.frame == t.frame);
  // A preamble at the window end keeps the receiver on.
  paired.tick_to(again.done_us + RX1_DELAY_US + RX_LATE_US - MS);
  paired.radio.preamble = true;
  paired.run(100 * MS);
  CHECK(paired.radio.rx);
  CHECK(paired.deliver_after(again, RX1_DELAY_US + RX_LATE_US + 120 * MS,
                             server.downlink(fcnt_of(again), V_TIME + 100)) == DownlinkResult::ACCEPT);
  paired.radio.preamble = false;
  // A preamble that never ends does not hold the window open for ever.
  paired.core->report(true);
  const Tx &third = paired.wait_tx(paired.radio.sent.size() + 1);
  paired.radio.preamble = true;
  paired.tick_to(third.done_us + RX1_DELAY_US + RX_LATE_US + RX_EXTEND_MAX_US + 5 * MS);
  CHECK(!paired.radio.rx);
  paired.radio.preamble = false;
}

static void test_confirmed_every_24h() {
  // 08 section 3.3 caps 08 section 4.2's h + 10% at 24 hours.
  Rig rig;
  rig.cfg.confirm_interval_s = 48 * 3600;  // clamped to 24 h
  Server server = pair_with_vectors(rig);
  size_t n = rig.radio.sent.size();
  rig.core->report(true);
  Tx t = rig.wait_tx(n + 1);
  CHECK(rig.in_rx1(t, server.downlink(fcnt_of(t), V_TIME + 100, 0, {CMD_SET_HEARTBEAT, 2, 0x05, 0xA0})) ==
        DownlinkResult::ACCEPT);
  CHECK(rig.core->heartbeat_minutes() == 1440);
  uint64_t last_confirmed = t.start_us;
  int confirmed = 0;
  for (size_t i = 0; confirmed < 3 && i < 8; i++) {
    Tx hb = rig.wait_tx(n + 2 + i, 30 * 3600 * S);
    if (type_of(hb) != T_HEARTBEAT_CONFIRMED)
      continue;
    CHECK(hb.start_us <= last_confirmed + 24 * 3600 * S + MS);
    CHECK(rig.in_rx1(hb, server.downlink(fcnt_of(hb), V_TIME + 100)) == DownlinkResult::ACCEPT);
    last_confirmed = hb.start_us;
    confirmed++;
  }
  CHECK(confirmed == 3);
}

static void test_session_resync() {
  // A SYNC answered without SET_NETWORK is sent again, a bounded number of times.
  Rig rig;
  rig.boot();
  rig.random.keys.push_back(unhex(V_SENSOR_EPHEMERAL_PRIVATE));
  rig.core->short_press();
  Tx join = rig.wait_tx(1);
  CHECK(rig.in_rx1(join, unhex(fv("downlink_key_exchange").frame)) == DownlinkResult::ACCEPT);
  Server server;
  server.keys = session_keys(rig.core->session_key());
  for (uint8_t i = 0; i < MAX_SESSION_SYNCS; i++) {
    Tx sync = rig.wait_tx(2 + i, 10 * S);
    CHECK(type_of(sync) == T_SYNC);
    CHECK(rig.in_rx1(sync, server.downlink(fcnt_of(sync), V_TIME, DF_PENDING, {CMD_SET_HEARTBEAT, 2, 0, 7})) ==
          DownlinkResult::ACCEPT);
  }
  CHECK(rig.core->state() == PairingState::UNPAIRED);
  CHECK(rig.saw(SensorEvent::PAIRING_FAILED));
  rig.run(60 * S);
  CHECK(rig.radio.sent.size() == 1 + MAX_SESSION_SYNCS);
  CHECK(!rig.core->hold());

  // One stray answer, then SET_NETWORK: paired as usual.
  Rig r2;
  r2.boot();
  r2.random.keys.push_back(unhex(V_SENSOR_EPHEMERAL_PRIVATE));
  r2.core->short_press();
  join = r2.wait_tx(1);
  CHECK(r2.in_rx1(join, unhex(fv("downlink_key_exchange").frame)) == DownlinkResult::ACCEPT);
  server.fcnt = 0;
  Tx s1 = r2.wait_tx(2);
  CHECK(r2.in_rx1(s1, server.downlink(fcnt_of(s1), V_TIME)) == DownlinkResult::ACCEPT);
  Tx s2 = r2.wait_tx(3, 10 * S);
  Bytes route = unhex(V_K_NET_ROUTE), cmd = {CMD_SET_NETWORK, 16};
  cmd.insert(cmd.end(), route.begin(), route.end());
  CHECK(r2.in_rx1(s2, server.downlink(fcnt_of(s2), V_TIME, 0, cmd)) == DownlinkResult::ACCEPT);
  CHECK(r2.core->state() == PairingState::PAIRED);
}

static void test_firmware_until_delivered() {
  Rig rig;
  Server server = pair_with_vectors(rig);
  rig.cfg.has_firmware_version = true;
  rig.cfg.firmware_version[0] = 3;
  size_t n = rig.radio.sent.size();
  rig.boot({contact(1)});
  rig.run(60 * S);  // boot heartbeat with firmware_version, never answered
  CHECK(rig.radio.sent.size() == n + 4);
  CHECK(hex(open_up(server.keys, rig.radio.sent[n].frame).pt) == "02" "000101" "ffc203030000");
  // The next heartbeat carries it again.
  Tx hb = rig.wait_tx(n + 5);
  CHECK(hex(open_up(server.keys, hb.frame).pt) == "02" "000101" "ffc203030000");
  CHECK(rig.in_rx1(hb, server.downlink(fcnt_of(hb), V_TIME + 100)) == DownlinkResult::ACCEPT);
  rig.core->report(false);
  CHECK(hex(open_up(server.keys, rig.wait_tx(n + 6).frame).pt) == "00" "000101");
  Tx hb2 = rig.wait_tx(n + 7);
  CHECK(hex(open_up(server.keys, hb2.frame).pt) == "00" "000101");
}

struct NoEraseStorage : FakeStorage {
  bool erase(Blob) override { return false; }
};

static void test_factory_reset_without_erase() {
  // A store that cannot erase gets zeros, which load as absent.
  Rig rig;
  pair_with_vectors(rig);
  NoEraseStorage store;
  store.blobs = rig.storage.blobs;
  SensorCore core(rig.cfg, rig.clock, rig.radio, store, rig.random);
  core.begin();
  CHECK(core.state() == PairingState::PAIRED);
  core.factory_reset();
  SensorCore again(rig.cfg, rig.clock, rig.radio, store, rig.random);
  again.begin();
  CHECK(again.state() == PairingState::UNPAIRED);
  CHECK(again.root_floor() == 0);
  CHECK(again.session_key() == nullptr);
}

// A deep-sleep wake is not a boot: the counter, the clock's standing and the
// heartbeat schedule carry on (components/cs_sensor/README.md, "Deep sleep").
static void test_deep_sleep_resume() {
  Rig rig;
  Server server = pair_with_vectors(rig);
  CHECK(rig.core->set_state(battery(90)));
  rig.run(10 * S);
  CHECK(!rig.core->hold());
  CHECK(rig.core->time_sure());
  size_t n = rig.radio.sent.size();
  uint32_t next = rig.core->next_fcnt();
  uint32_t reserved = rig.storage.u32(Blob::COUNTER);
  CHECK(next < reserved);
  int saves = rig.storage.saves;
  uint64_t hb_at = rig.core->next_wake_us();
  CHECK(hb_at != UINT64_MAX && hb_at > rig.clock.now);

  // Asleep until a contact change wakes it: nothing is written, nothing is sent.
  CHECK(rig.sleep_wake(5 * MIN, {contact(0)}));
  CHECK(rig.core->state() == PairingState::PAIRED);
  CHECK(rig.core->time_sure());
  CHECK(rig.core->next_fcnt() == next);
  CHECK(rig.storage.saves == saves);
  CHECK(rig.storage.u32(Blob::COUNTER) == reserved);
  CHECK(rig.core->next_wake_us() == hb_at);
  CHECK(!rig.core->hold());
  rig.run(5 * S);
  CHECK(rig.radio.sent.size() == n);

  // The contact change goes out with the next counter value, normal tags and no TIME_UNSURE.
  rig.core->report(true);
  CHECK(rig.core->hold());
  WarmState w;
  CHECK(!rig.core->suspend(w));  // not while there is work
  const Tx &d = rig.wait_tx(n + 1);
  Opened o = open_up(server.keys, d.frame);
  CHECK(o.ok && type_of(d) == T_DATA_CONFIRMED && fcnt_of(d) == next);
  CHECK(o.pt.size() > 0 && (o.pt[0] & UF_TIME_UNSURE) == 0);
  CHECK(hex(o.pt) == "00" "000100" "ff075a");  // battery kept from before the sleep
  CHECK(rig.in_rx1(d, server.downlink(fcnt_of(d), V_TIME + 400)) == DownlinkResult::ACCEPT);
  rig.run(5 * S);

  // A timer wake for the heartbeat sends it when it was due, with no boot uplink first.
  uint64_t due = rig.core->next_wake_us();
  CHECK(due == hb_at);
  CHECK(rig.sleep_wake(due - rig.clock.now));
  rig.core->loop();
  const Tx &hb = rig.wait_tx(n + 2);
  CHECK(fcnt_of(hb) == next + 1);
  CHECK(type_of(hb) == T_HEARTBEAT);
  CHECK(hb.start_us >= due && hb.start_us < due + S);
  rig.run(10 * S);

  // A snapshot that fails its check, a clock that started over, or a counter
  // reservation that moved on is a boot.
  {
    WarmState snap;
    rig.run(10 * S);
    CHECK(rig.core->suspend(snap));
    snap.next_fcnt++;
    rig.core.reset(new SensorCore(rig.cfg, rig.clock, rig.radio, rig.storage, rig.random));
    CHECK(!rig.core->resume(snap));
    snap.next_fcnt--;
    rig.clock.now = snap.saved_us - 1;
    CHECK(!rig.core->resume(snap));
    rig.clock.now = snap.saved_us + S;
    rig.storage.set_u32(Blob::COUNTER, snap.reserved + COUNTER_BLOCK);
    CHECK(!rig.core->resume(snap));
    rig.storage.set_u32(Blob::COUNTER, snap.reserved);
    CHECK(rig.core->resume(snap));
    CHECK(rig.core->next_fcnt() == snap.next_fcnt);
  }

  // A boot after all: a new counter block and the boot heartbeat with TIME_UNSURE.
  uint32_t stored = rig.storage.u32(Blob::COUNTER);
  CHECK(stored > rig.core->next_fcnt());
  rig.boot({contact(0)});
  CHECK(rig.storage.u32(Blob::COUNTER) == stored + COUNTER_BLOCK);
  const Tx &boot = rig.wait_tx(rig.radio.sent.size() + 1);
  o = open_up(server.keys, boot.frame);
  CHECK(o.ok && type_of(boot) == T_HEARTBEAT_CONFIRMED && (o.pt[0] & UF_TIME_UNSURE));
  CHECK(fcnt_of(boot) == stored);
}

static void test_deep_sleep_unpaired_and_lost_session() {
  // An unpaired sensor sleeps and wakes unpaired, and can still pair.
  Rig rig;
  rig.boot();
  CHECK(!rig.core->hold());
  CHECK(rig.core->next_wake_us() == UINT64_MAX);
  CHECK(rig.sleep_wake(3600 * S));
  CHECK(rig.core->state() == PairingState::UNPAIRED);
  rig.random.keys.push_back(Bytes(32, 0x42));
  rig.core->short_press();
  CHECK(rig.core->hold());
  rig.wait_tx(1);
  CHECK(type_of(rig.radio.sent[0]) == T_JOIN);

  // A paired snapshot whose session storage was wiped (for example a reflash) boots.
  Rig r2;
  pair_with_vectors(r2);
  r2.run(10 * S);
  WarmState snap;
  CHECK(r2.core->suspend(snap));
  r2.storage.erase(Blob::SESSION);
  r2.core.reset(new SensorCore(r2.cfg, r2.clock, r2.radio, r2.storage, r2.random));
  CHECK(!r2.core->resume(snap));
  CHECK(r2.core->state() == PairingState::UNPAIRED);
  CHECK(r2.core->session_key() == nullptr);

  // A lost RTC across the sleep: resumed, but no longer time-sure, so uplinks are SYNC.
  Rig r3;
  pair_with_vectors(r3);
  r3.run(10 * S);
  r3.clock.rtc = false;
  CHECK(r3.sleep_wake(MIN));
  CHECK(!r3.core->time_sure());
  r3.core->report(true);
  const Tx &s = r3.wait_tx(r3.radio.sent.size() + 1);
  CHECK(type_of(s) == T_SYNC);
}

static void test_airtime_window_is_an_hour() {
  // A JOIN (95 ms) spent late in a minute against a 100 ms budget.
  Rig rig;
  rig.cfg.airtime_budget_us = 100000;
  rig.boot();
  rig.clock.now = 3600 * S + 59 * S;
  rig.random.keys.push_back(Bytes(32, 0x11));
  rig.core->short_press();
  Tx j = rig.wait_tx(1, 2 * S);
  rig.run(60 * S);  // retries are postponed: the budget is spent
  CHECK(rig.radio.sent.size() == 1);
  // Not before a whole hour after the spend.
  rig.tick_to(j.start_us + 3600 * S - S);
  CHECK(rig.radio.sent.size() == 1);
  rig.tick_to(j.start_us + 3600 * S + 70 * S);
  CHECK(rig.radio.sent.size() >= 2);
}

// ---------------------------------------------------------------- reported readings

static void test_reading_first_value_after_boot() {
  // #48: a reading with no value at boot is not in the boot uplink, so its first
  // value is reported when it comes, confirmed if the reading is.
  const uint64_t t0 = 5 * S;
  ReportedReading door;  // a template binary sensor with no state yet
  door.confirmed = true;
  ReportedReading temp;  // has a value at boot
  temp.scale = 100;
  temp.min_interval_ms = 60000;
  temp.has_value = true;
  temp.value = 21.5f;
  ReportedReading battery;  // heartbeats only
  battery.delta = -1;
  battery.has_value = true;
  battery.value = 90;
  for (auto *r : {&door, &temp, &battery})
    r->boot(t0);
  CHECK(!door.due(t0) && !temp.due(t0) && !battery.due(t0));
  CHECK(temp.has_sent && !door.has_sent);

  // 15 s after boot the door opens: due at once (min_interval 0) and confirmed.
  const uint64_t t1 = t0 + 15 * S;
  door.has_value = true;
  door.value = 1;
  CHECK(door.changed() && door.due(t1) && door.confirmed);
  CHECK(!temp.due(t1) && !battery.due(t1));
  // The glue queues one frame carrying every value.
  door.sent_us = t1;
  for (auto *r : {&door, &temp, &battery})
    r->carried();
  CHECK(!door.due(t1) && door.has_sent && door.sent == 1);

  // The close after it is a change like any other.
  door.value = 0;
  CHECK(door.due(t1 + 2 * S));

  // A first value is subject to min_interval, counted from boot.
  ReportedReading slow;
  slow.min_interval_ms = 30000;
  slow.boot(t0);
  slow.has_value = true;
  slow.value = 7;
  CHECK(slow.changed() && !slow.due(t0 + 10 * S) && slow.due(t0 + 30 * S));
  CHECK(slow.due_at_us() == t0 + 30 * S);

  // A heartbeats-only reading never causes a frame, even its first value.
  ReportedReading volts;
  volts.delta = -1;
  volts.boot(t0);
  volts.has_value = true;
  volts.value = 3.7f;
  CHECK(!volts.changed() && !volts.due(t0 + MIN));

  // Unknown (NaN) to known is a change; one wire step is one with delta 0.
  temp.value = NAN;
  CHECK(temp.changed());
  temp.carried();
  temp.value = 21.0f;
  CHECK(temp.changed());
  temp.carried();
  temp.value = 21.004f;
  CHECK(!temp.changed());
  temp.value = 21.01f;
  CHECK(temp.changed());
}

int main() {
  test_crypto();
  test_frame_vectors();
  test_payload_vectors();
  test_pairing_code();
  test_frame_vector_flow();
  test_root_floor_vectors();
  test_rx_windows_and_answer_in_rx1();
  test_answer_in_rx2();
  test_unanswered_retries();
  test_retry_window_answer();
  test_downlink_checks();
  test_counter_reservation();
  test_storage_failure();
  test_factory_reset();
  test_join_unanswered();
  test_session_sync_unanswered();
  test_pairing_button_and_leave_mid_pairing();
  test_time_unsure_and_sync();
  test_lost_contact();
  test_commands();
  test_leave();
  test_pending();
  test_abandon_retries();
  test_airtime_budget();
  test_state_limits_and_hints();
  test_confirmed_every_24h();
  test_session_resync();
  test_firmware_until_delivered();
  test_factory_reset_without_erase();
  test_airtime_window_is_an_hour();
  test_deep_sleep_resume();
  test_deep_sleep_unpaired_and_lost_session();
  test_reading_first_value_after_boot();
  std::printf("%d checks, %d failures\n", checks, failures);
  return failures ? 1 : 0;
}
