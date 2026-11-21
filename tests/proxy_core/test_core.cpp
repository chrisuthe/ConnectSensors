// Host unit tests for the cs_proxy core. Build and run with:  make -C tests/proxy_core

#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "cs_sha256.h"
#include "proxy_core.h"
#include "proxy_engine.h"
#include "vectors.inc"

using namespace esphome::cs_proxy;

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

static std::vector<uint8_t> unhex(const char *s) {
  std::vector<uint8_t> out;
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

static std::string hex(const std::vector<uint8_t> &v) { return hex(v.data(), v.size()); }

static const EnvelopeVector &env(const char *name) {
  for (const auto &v : ENVELOPE_VECTORS) {
    if (std::strcmp(v.name, name) == 0)
      return v;
  }
  std::printf("missing vector %s\n", name);
  return ENVELOPE_VECTORS[0];
}

static std::vector<uint8_t> frame(const char *name) {
  for (const auto &v : FRAME_VECTORS) {
    if (std::strcmp(v.name, name) == 0)
      return unhex(v.hex);
  }
  std::printf("missing frame %s\n", name);
  return {};
}

static void test_sha256() {
  uint8_t d[32];
  sha256(reinterpret_cast<const uint8_t *>("abc"), 3, d);
  CHECK(hex(d, 32) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  sha256(nullptr, 0, d);
  CHECK(hex(d, 32) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  std::string m = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  sha256(reinterpret_cast<const uint8_t *>(m.data()), m.size(), d);
  CHECK(hex(d, 32) == "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
  // RFC 4231 test case 1 and 2
  std::vector<uint8_t> key(20, 0x0b);
  hmac_sha256(key.data(), key.size(), reinterpret_cast<const uint8_t *>("Hi There"), 8, d);
  CHECK(hex(d, 32) == "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
  hmac_sha256(reinterpret_cast<const uint8_t *>("Jefe"), 4,
              reinterpret_cast<const uint8_t *>("what do ya want for nothing?"), 28, d);
  CHECK(hex(d, 32) == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
}

static void test_frames() {
  for (const auto &v : FRAME_VECTORS) {
    auto f = unhex(v.hex);
    bool downlink = v.type >= 8;
    CHECK((check_uplink(f.data(), f.size()) == FrameCheck::OK) == !downlink);
    CHECK(is_valid_downlink(f.data(), f.size()) == downlink);
    FrameHeader h = parse_header(f.data());
    CHECK(h.type == v.type);
  }
  auto f = frame("data_confirmed");
  FrameHeader h = parse_header(f.data());
  CHECK(h.net_tag == 0x61d306d3u && h.dev_tag == 0x452268f4u && h.fcnt == 3);
  CHECK(!is_bootstrap(h));
  auto j = frame("join");
  CHECK(is_bootstrap(parse_header(j.data())));

  auto bad = f;
  bad[0] = 0xC4;
  CHECK(check_uplink(bad.data(), bad.size()) == FrameCheck::BAD_MAGIC);
  bad = f;
  bad[1] = 0x22;
  CHECK(check_uplink(bad.data(), bad.size()) == FrameCheck::BAD_VERSION);
  bad = f;
  bad[1] = 0x10;
  CHECK(check_uplink(bad.data(), bad.size()) == FrameCheck::BAD_TYPE);
  bad = f;
  bad[1] = 0x17;  // reserved uplink type: forwarded (02 section 12)
  CHECK(check_uplink(bad.data(), bad.size()) == FrameCheck::OK);
  CHECK(check_uplink(f.data(), 22) == FrameCheck::BAD_LENGTH);
  std::vector<uint8_t> big(87, 0);
  big[0] = 0xC5;
  big[1] = 0x11;
  CHECK(check_uplink(big.data(), big.size()) == FrameCheck::BAD_LENGTH);
  big.resize(86);
  CHECK(check_uplink(big.data(), big.size()) == FrameCheck::OK);

  CHECK(frame_key(f.data(), f.size()) != frame_key(j.data(), j.size()));
  CHECK(frame_key(f.data(), f.size()) == frame_key(f.data(), f.size()));
}

static void test_envelope() {
  auto key = unhex(PROXY_KEY_HEX);
  auto pid = unhex(PROXY_ID_HEX);
  EnvelopeCodec codec(key.data(), pid.data());
  for (const auto &v : ENVELOPE_VECTORS) {
    auto body = unhex(v.body);
    auto msg = codec.build(uint8_t(v.type), v.boot_id, v.seq, body);
    CHECK(hex(msg) == v.message);
    Envelope e{};
    CHECK(codec.open(msg.data(), msg.size(), e));
    CHECK(e.type == v.type && e.boot_id == v.boot_id && e.seq == v.seq);
    CHECK(hex(e.body, e.body_len) == v.body);
    auto tampered = msg;
    tampered[20] ^= 1;
    CHECK(!codec.open(tampered.data(), tampered.size(), e));
  }
  // A message for another proxy is rejected even with the right key.
  auto other = pid;
  other[7] ^= 1;
  EnvelopeCodec other_codec(key.data(), other.data());
  auto msg = unhex(env("downlink").message);
  Envelope e{};
  CHECK(!other_codec.open(msg.data(), msg.size(), e));
  CHECK(!codec.open(msg.data(), ENV_MIN - 1, e));

  // Bodies built by the core match the vectors byte for byte.
  auto up = frame("data_confirmed");
  CHECK(hex(uplink_body(123456789, -97.5f, 6.3f, 0, up.data(), up.size())) == env("uplink").body);

  HelloInfo h;
  h.caps = CAP_DOWNLINK;
  h.region = "US915";
  h.frequency_hz = 918500000;
  h.sf = 9;
  h.bw_khz = 500;
  h.uptime_s = 42;
  h.heard = 10;
  h.forwarded = 9;
  h.duplicates = 1;
  h.invalid = 0;
  h.rate_limited = 0;
  h.tx_ok = 2;
  h.tx_failed = 0;
  h.max_loop_gap_ms = 7;
  h.firmware = "cs_proxy 0.1.0";
  CHECK(hex(hello_body(h)) == env("hello").body);
  auto hr = unhex(env("hello_request").body);
  uint32_t nonce = 0;
  CHECK(parse_hello_request(hr.data(), hr.size(), nonce) && nonce == 0x5EED1234u);
  CHECK(!parse_hello_request(hr.data(), hr.size() - 1, nonce));
  const uint8_t zero[4] = {0, 0, 0, 0};
  CHECK(!parse_hello_request(zero, 4, nonce));
  h.request_nonce = 0x5EED1234u;
  CHECK(hex(hello_body(h)) == env("hello_answer").body);
  CHECK(hex(tx_result_body(2, TX_SENT, 1800)) == env("tx_result").body);

  auto ss = unhex(env("server_status").body);
  ServerStatus st{};
  CHECK(parse_server_status(ss.data(), ss.size(), st));
  CHECK(st.server_time == 1795226400u && st.hello_seq == 2 && st.tags.size() == 3 && st.tags[1] == 0x61d306d3u);
  CHECK(!parse_server_status(ss.data(), ss.size() - 1, st));

  auto dl = unhex(env("downlink").body);
  DownlinkRequest r{};
  CHECK(parse_downlink(dl.data(), dl.size(), r));
  CHECK(r.ref_rx_time_us == 123456789u && r.tx_offset_us == 1000000u);
  CHECK(hex(r.frame) == hex(frame("downlink_ack")));
  CHECK(!parse_downlink(dl.data(), dl.size() - 1, r));

  CHECK(to_x10(-97.5f) == -975 && to_x10(6.3f) == 63 && to_x10(1e9f) == 32767);
}

static void test_seq_guard() {
  ServerSeqGuard g(0x1A2B3C4D);
  CHECK(g.accept(0x1A2B3C4D, 1));
  CHECK(!g.accept(0x1A2B3C4D, 1));
  CHECK(g.accept(0x1A2B3C4D, 5));
  CHECK(!g.accept(0x1A2B3C4D, 4));
  CHECK(!g.accept(0x11111111, 6));
}

static void test_hello_echoes() {
  HelloEchoes h;
  const uint64_t t = 1000000000;
  h.sent(1, t);
  h.sent(2, t);
  CHECK(!h.take(0, t));
  CHECK(!h.take(3, t));  // never sent
  CHECK(h.take(2, t));
  CHECK(!h.take(2, t));  // used up
  // Only the last three are kept.
  h.sent(3, t);
  h.sent(4, t);
  h.sent(5, t);
  CHECK(!h.take(1, t));
  CHECK(h.take(3, t) && h.take(5, t));
  // And only for two HELLO intervals.
  CHECK(!h.take(4, t + HELLO_ECHO_MAX_AGE_US + 1));
  h.sent(6, t);
  CHECK(h.take(6, t + HELLO_ECHO_MAX_AGE_US));

  ServerSeqGuard g(0x1A2B3C4D);
  CHECK(g.accept(0x1A2B3C4D, 10));
  g.resync(1);
  CHECK(g.accept(0x1A2B3C4D, 2) && !g.accept(0x1A2B3C4D, 2));
  CHECK(g.current_boot(0x1A2B3C4D) && !g.current_boot(0x1A2B3C4E));
}

static void test_dedupe() {
  DedupeCache c(4);
  const uint64_t W = 30000000;
  c.insert(1, 1000);
  CHECK(c.contains(1, 1000 + W - 1, W));
  CHECK(!c.contains(1, 1000 + W, W));
  CHECK(!c.contains(2, 1000, W));
  for (uint64_t k = 2; k <= 5; k++)
    c.insert(k, 1000 + k);  // 5 evicts the oldest (1)
  CHECK(!c.contains(1, 2000, W));
  CHECK(c.contains(5, 2000, W) && c.contains(2, 2000, W));
}

// A sensor's retry is the same bytes 4 s or more later (08 section 5); the
// default window must merge near-simultaneous copies but forward the retry.
static void test_dedupe_lets_retries_through() {
  const uint64_t t0 = 10000000;
  for (uint64_t w : {DEDUPE_WINDOW_DEFAULT_US, DEDUPE_WINDOW_MAX_US}) {
    DedupeCache d(64);
    d.insert(7, t0);
    CHECK(d.contains(7, t0 + 200000, w));                  // an echo of the same transmission
    CHECK(!d.contains(7, t0 + SENSOR_FIRST_RETRY_US, w));  // retry 1 at its earliest
  }
  // Walk the whole retry schedule as the pipeline does: look up, then insert if forwarded.
  DedupeCache c(64);
  const uint64_t retries[] = {0, 4000000, 12000000, 30000000};
  int forwarded = 0;
  for (uint64_t at : retries) {
    if (!c.contains(7, t0 + at, DEDUPE_WINDOW_DEFAULT_US)) {
      forwarded++;
      c.insert(7, t0 + at);
    }
  }
  CHECK(forwarded == 4);
  CHECK(c.contains(7, t0 + 30000000 + 1999999, DEDUPE_WINDOW_DEFAULT_US));
}

static void test_rate_limits() {
  RateLimiter rl(20, 2, 5, 5);
  FrameHeader dev{2, 0x11111111, 0x22222222, 1};
  int ok = 0;
  for (int i = 0; i < 10; i++)
    ok += rl.allow(dev, 1000000);
  CHECK(ok == 5);                      // burst 5
  CHECK(rl.allow(dev, 1000000 + 500000));   // 2/s refills one token in 0.5 s
  CHECK(!rl.allow(dev, 1000000 + 500001));
  FrameHeader other{2, 0x11111111, 0x33333333, 1};
  CHECK(rl.allow(other, 1000000));     // a different device has its own bucket
  FrameHeader boot{5, 0, 0, 1};
  ok = 0;
  for (int i = 0; i < 10; i++)
    ok += rl.allow(boot, 5000000);
  CHECK(ok == 5);

  // Global limit: 20 distinct devices pass, the 21st does not.
  RateLimiter g(20, 2, 5, 5);
  ok = 0;
  for (uint32_t i = 0; i < 25; i++) {
    FrameHeader h{2, 1, 100 + i, 1};
    ok += g.allow(h, 1000);
  }
  CHECK(ok == 20);
}

static void test_receive_pipeline() {
  const uint64_t W = 30000000;
  DedupeCache dedupe(8);
  RateLimiter rate(1, 1, 1, 5);  // one token each, global and per device, 1/s refill
  auto f = frame("data_confirmed");
  auto g = frame("heartbeat");
  auto bad = f;
  bad[0] ^= 0xff;

  // Offline: nothing touches the dedupe cache or the buckets (issue #15).
  for (int i = 0; i < 3; i++) {
    CHECK(classify_uplink(f.data(), f.size(), false, dedupe, rate, 1000, W) == RxVerdict::OFFLINE);
    CHECK(classify_uplink(g.data(), g.size(), false, dedupe, rate, 1000, W) == RxVerdict::OFFLINE);
  }
  CHECK(classify_uplink(bad.data(), bad.size(), false, dedupe, rate, 1000, W) == RxVerdict::INVALID);

  // The same frame heard once connected is forwarded, then deduped.
  CHECK(classify_uplink(f.data(), f.size(), true, dedupe, rate, 2000, W) == RxVerdict::FORWARD);
  CHECK(classify_uplink(f.data(), f.size(), true, dedupe, rate, 3000, W) == RxVerdict::DUPLICATE);

  // The buckets are now empty; a rate-limited frame is not inserted, so it
  // gets through once the token returns.
  CHECK(classify_uplink(g.data(), g.size(), true, dedupe, rate, 3000, W) == RxVerdict::RATE_LIMITED);
  CHECK(classify_uplink(g.data(), g.size(), true, dedupe, rate, 2003000, W) == RxVerdict::FORWARD);
  CHECK(classify_uplink(bad.data(), bad.size(), true, dedupe, rate, 2003000, W) == RxVerdict::INVALID);
}

static void test_airtime() {
  for (const auto &v : AIRTIME_VECTORS) {
    uint32_t got = lora_airtime_us(v.len, uint8_t(v.sf), uint32_t(v.bw));
    int64_t diff = int64_t(got) - int64_t(v.us);
    CHECK(diff >= -1 && diff <= 1);
  }
}

static void test_budget() {
  AirtimeBudget b(20);  // 2% = 72 s per hour
  CHECK(b.budget_us() == 72000000u);
  uint64_t t = 1000000;
  CHECK(b.can_spend(1000000, t));
  b.spend(71900000, t);
  CHECK(!b.can_spend(200000, t));
  CHECK(b.can_spend(100000, t));
  CHECK(b.used_us(t + 59ULL * 60000000) == 71900000u);
  CHECK(b.used_us(t + 61ULL * 60000000) == 0);
  CHECK(b.can_spend(200000, t + 61ULL * 60000000));
}

static void test_scheduler() {
  auto f = frame("downlink_ack");
  uint32_t air = lora_airtime_us(f.size(), 9, 500000);
  AirtimeBudget budget(20);
  TxScheduler s;
  uint64_t now = 10000000;
  CHECK(s.admit(1, now + 1000000, f.data(), f.size(), air, now, false, budget) == TX_NOT_CAPABLE);
  auto up = frame("data_confirmed");
  CHECK(s.admit(1, now + 1000000, up.data(), up.size(), air, now, true, budget) == TX_INVALID);
  CHECK(s.admit(1, now + 6000000, f.data(), f.size(), air, now, true, budget) == TX_INVALID);
  CHECK(s.admit(1, now - 200000, f.data(), f.size(), air, now, true, budget) == TX_TOO_LATE);
  CHECK(s.admit(2, now + 1000000, f.data(), f.size(), air, now, true, budget) == TX_SENT);
  CHECK(s.admit(3, now + 1050000, f.data(), f.size(), air, now, true, budget) == TX_BUSY);
  CHECK(s.admit(4, now + 3000000, f.data(), f.size(), air, now, true, budget) == TX_SENT);
  CHECK(s.next_tx_at() == now + 1000000);
  CHECK(s.due(now + 999999) == nullptr);
  ScheduledTx *d = s.due(now + 1000000);
  CHECK(d != nullptr && d->seq == 2 && d->len == f.size() && std::memcmp(d->frame, f.data(), f.size()) == 0);
  s.release(d);
  CHECK(s.next_tx_at() == now + 3000000);

  // In flight: no longer due or next, but still occupies the schedule and the budget.
  ScheduledTx *f4 = s.due(now + 3000000);
  CHECK(f4 != nullptr && f4->seq == 4);
  // The offset is taken when the radio was commanded, not when the slot came due.
  s.start(f4, now + 3000000 + 850);
  CHECK(f4->in_flight && f4->offset_us == 850);
  CHECK(s.due(now + 3000000) == nullptr);
  CHECK(s.next_tx_at() == 0);
  CHECK(s.admit(5, now + 3050000, f.data(), f.size(), air, now, true, budget) == TX_BUSY);
  AirtimeBudget one_frame(1);  // 0.1% = 3.6 s
  one_frame.spend(3600000 - air - air / 2, now);
  CHECK(s.admit(6, now + 4500000, f.data(), f.size(), air, now, true, one_frame) == TX_DUTY_CYCLE);
  s.release(f4);
  CHECK(!f4->in_flight && !f4->saw_busy && f4->offset_us == 0);
  CHECK(s.admit(6, now + 4500000, f.data(), f.size(), air, now, true, one_frame) == TX_SENT);

  ScheduledTx expired;
  CHECK(expired_result(expired) == TX_TOO_LATE);
  expired.saw_busy = true;
  CHECK(expired_result(expired) == TX_BUSY);

  AirtimeBudget tiny(1);  // 0.1% = 3.6 s
  TxScheduler s2;
  tiny.spend(3600000 - air / 2, now);
  CHECK(s2.admit(1, now + 1000000, f.data(), f.size(), air, now, true, tiny) == TX_DUTY_CYCLE);
}

static void test_eui64() {
  uint8_t mac[6] = {0x34, 0x85, 0x18, 0x00, 0x00, 0x01};
  uint8_t out[8];
  eui64_from_mac(mac, out);
  CHECK(hex(out, 8) == PROXY_ID_HEX);
}

// ---------------------------------------------------------------- engine (06 sections 5-9)

static uint32_t rd32(const uint8_t *p) { return uint32_t(p[0]) << 24 | uint32_t(p[1]) << 16 | uint32_t(p[2]) << 8 | p[3]; }

// Clock, radio, socket and entities for one ProxyEngine, plus the server's side of
// the envelope. Time only moves when a test says so.
struct FakeIo : ProxyIo {
  uint64_t t = 1000000000;
  uint64_t loop_interval = 16000;
  bool server = true;
  bool network = true;
  std::vector<std::vector<uint8_t>> datagrams;
  struct Tx {
    std::vector<uint8_t> frame;
    uint32_t timeout_ms;
    uint64_t at;
  };
  std::vector<Tx> transmits;
  std::vector<uint8_t> radio_answers;  // consumed per start_transmit; TX_SENT once empty
  uint64_t start_cost_us = 0;          // clock advance inside start_transmit
  uint64_t timer = 0;
  int loop_requests = 0;
  int rediscovers = 0;
  std::vector<bool> connected_events;
  std::vector<uint16_t> hello_gaps;

  uint64_t now_us() override { return t; }
  void wait_until(uint64_t at) override {
    if (t < at)
      t = at;
  }
  uint64_t loop_interval_us() override { return loop_interval; }
  bool server_known() override { return server; }
  bool network_up() override { return network; }
  void send_datagram(const uint8_t *data, size_t len) override { datagrams.emplace_back(data, data + len); }
  void rediscover() override {
    rediscovers++;
    server = false;
  }
  uint8_t start_transmit(const uint8_t *frame, size_t len, uint32_t timeout_ms) override {
    uint8_t answer = TX_SENT;
    if (!radio_answers.empty()) {
      answer = radio_answers.front();
      radio_answers.erase(radio_answers.begin());
    }
    if (answer == TX_SENT) {
      t += start_cost_us;
      transmits.push_back({std::vector<uint8_t>(frame, frame + len), timeout_ms, t});
    }
    return answer;
  }
  void arm_timer(uint64_t wake_us) override { timer = wake_us; }
  void request_loop() override { loop_requests++; }
  void on_connected(bool c) override { connected_events.push_back(c); }
  void on_hello(uint16_t gap_ms) override { hello_gaps.push_back(gap_ms); }
  std::vector<std::string> logs;
  void vlog(LogLevel, const char *fmt, va_list args) override {
    char line[256];
    std::vsnprintf(line, sizeof(line), fmt, args);
    logs.emplace_back(line);
  }
  size_t logged(const char *needle) const {
    size_t n = 0;
    for (const auto &l : logs)
      n += l.find(needle) != std::string::npos;
    return n;
  }
};

struct Sent {
  uint8_t type;
  uint32_t seq;
  std::vector<uint8_t> body;
};

struct Rig {
  static constexpr uint32_t BOOT = 0x0B007001;
  FakeIo io;
  ProxyConfig cfg;
  std::unique_ptr<ProxyEngine> engine;
  std::unique_ptr<EnvelopeCodec> server;
  uint32_t server_seq = 0;
  size_t read_pos = 0;

  explicit Rig(void (*tweak)(ProxyConfig &) = nullptr) {
    auto key = unhex(PROXY_KEY_HEX);
    auto pid = unhex(PROXY_ID_HEX);
    std::memcpy(cfg.key, key.data(), 16);
    std::memcpy(cfg.proxy_id, pid.data(), 8);
    cfg.boot_id = BOOT;
    cfg.region = "US915";
    cfg.frequency_hz = 918500000;
    cfg.sf = 9;
    cfg.bw_hz = 500000;
    cfg.firmware = "cs_proxy test";
    if (tweak != nullptr)
      tweak(cfg);
    engine = std::make_unique<ProxyEngine>(cfg, io);
    server = std::make_unique<EnvelopeCodec>(cfg.key, cfg.proxy_id);
  }

  // One healthy main-loop pass, delivering any datagrams in between.
  void loop(const std::vector<std::vector<uint8_t>> &in = {}) {
    uint64_t now = engine->loop_start();
    for (const auto &d : in)
      engine->on_datagram(d.data(), d.size(), now);
    engine->loop_end();
  }
  // Healthy loop passes every 16 ms until t.
  void run_until(uint64_t until) {
    while (io.t + io.loop_interval <= until) {
      io.t += io.loop_interval;
      loop();
    }
    if (io.t < until) {
      io.t = until;
      loop();
    }
  }

  std::vector<uint8_t> msg(uint8_t type, const std::vector<uint8_t> &body, uint32_t boot = BOOT) {
    return server->build(type, boot, ++server_seq, body);
  }
  static std::vector<uint8_t> status_body(uint32_t hello_seq = 0) {
    ByteWriter w;
    w.u32(1795226400);
    w.u32(hello_seq);
    w.u8(1);
    w.u32(0x61d306d3);
    return w.buf;
  }
  std::vector<uint8_t> status(uint32_t hello_seq = 0) { return msg(MSG_SERVER_STATUS, status_body(hello_seq)); }
  std::vector<uint8_t> hello_request(uint32_t nonce, uint32_t boot = BOOT) {
    ByteWriter w;
    w.u32(nonce);
    return server->build(MSG_HELLO_REQUEST, boot, 0, w.buf);
  }
  static std::vector<uint8_t> downlink_body(uint64_t ref, uint32_t offset, const std::vector<uint8_t> &f) {
    ByteWriter w;
    w.u64(ref);
    w.u32(offset);
    w.u8(uint8_t(f.size()));
    w.bytes(f.data(), f.size());
    return w.buf;
  }
  std::vector<uint8_t> downlink(uint64_t ref, uint32_t offset, const std::vector<uint8_t> &f) {
    return msg(MSG_DOWNLINK, downlink_body(ref, offset, f));
  }

  // Messages the proxy sent since the last call, opened with the server's codec.
  std::vector<Sent> take() {
    std::vector<Sent> out;
    for (; read_pos < io.datagrams.size(); read_pos++) {
      const auto &d = io.datagrams[read_pos];
      Envelope e{};
      bool ok = server->open(d.data(), d.size(), e);
      CHECK(ok);
      CHECK(e.boot_id == BOOT);
      if (ok)
        out.push_back({e.type, e.seq, std::vector<uint8_t>(e.body, e.body + e.body_len)});
    }
    return out;
  }
  std::vector<Sent> take(uint8_t type) {
    std::vector<Sent> out;
    for (auto &m : take()) {
      if (m.type == type)
        out.push_back(m);
    }
    return out;
  }

  void hear(const std::vector<uint8_t> &f, float rssi = -90, float snr = 5) {
    engine->on_packet(f.data(), f.size(), rssi, snr);
  }
};

struct TxRes {
  uint32_t seq;
  uint8_t result;
  int32_t offset_us;
};
static TxRes tx_res(const Sent &m) {
  return {rd32(m.body.data()), m.body[4], int32_t(rd32(m.body.data() + 5))};
}

// Conformance items 1 and 3, the counters and the uplink layout.
static void test_engine_forwarding() {
  Rig r;
  r.loop();
  r.take();  // HELLO
  int uplinks = 0;
  for (const auto &v : FRAME_VECTORS) {
    auto f = unhex(v.hex);
    r.io.t += 1000;
    r.hear(f, -97.5f, 6.3f);
    auto out = r.take();
    if (v.type >= 8) {
      CHECK(out.empty());
      continue;
    }
    uplinks++;
    CHECK(out.size() == 1 && out[0].type == MSG_UPLINK);
    if (out.size() == 1)
      CHECK(hex(out[0].body) == hex(uplink_body(r.io.t, -97.5f, 6.3f, 0, f.data(), f.size())));
  }
  const int downlinks = int(sizeof(FRAME_VECTORS) / sizeof(FRAME_VECTORS[0])) - uplinks;
  CHECK(uplinks > 0 && downlinks > 0);

  // Item 3: wrong magic, wrong version, type 0, too short, too long.
  auto good = frame("data_confirmed");
  std::vector<std::vector<uint8_t>> bad(5, good);
  bad[0][0] = 0xC4;
  bad[1][1] = 0x21;
  bad[2][1] = 0x10;
  bad[3].resize(FRAME_MIN - 1);
  bad[4].resize(FRAME_MAX + 1);
  for (auto &b : bad)
    r.hear(b);
  CHECK(r.take().empty());

  const ProxyCounters &c = r.engine->counters();
  CHECK(c.heard == uint32_t(uplinks + downlinks + 5));
  CHECK(c.forwarded == uint32_t(uplinks));
  CHECK(c.invalid == uint32_t(downlinks + 5));
  CHECK(c.duplicates == 0 && c.rate_limited == 0);

  // The next HELLO carries those counters.
  r.run_until(r.io.t + HELLO_INTERVAL_US);
  auto hello = r.take(MSG_HELLO);
  CHECK(hello.size() == 1);
  if (hello.size() == 1) {
    const uint8_t *p = hello[0].body.data() + 2 + 5 + 4 + 1 + 2 + 4;
    CHECK(rd32(p) == c.heard && rd32(p + 4) == c.forwarded && rd32(p + 12) == c.invalid);
  }
}

// Conformance items 2 and 9, plus the rate limit counter.
static void test_engine_dedupe_and_offline() {
  Rig r;
  r.loop();
  r.take();
  auto f = frame("data_confirmed");
  const uint64_t t0 = r.io.t;
  r.hear(f);
  r.io.t = t0 + 1500000;
  r.hear(f);  // inside the 2 s window
  CHECK(r.take(MSG_UPLINK).size() == 1);
  CHECK(r.engine->counters().duplicates == 1);
  r.io.t = t0 + SENSOR_FIRST_RETRY_US;  // a sensor's earliest retry
  r.hear(f);
  CHECK(r.take(MSG_UPLINK).size() == 1);

  // Offline: not forwarded, not counted as a duplicate, and the frame does not
  // block itself once the server is back.
  auto g = frame("heartbeat");
  r.io.network = false;
  r.hear(g);
  r.io.network = true;
  r.io.server = false;
  r.hear(g);
  CHECK(r.take().empty());
  r.io.server = true;
  r.io.t += 100000;
  r.hear(g);
  CHECK(r.take(MSG_UPLINK).size() == 1);
  const ProxyCounters &c = r.engine->counters();
  CHECK(c.heard == 6 && c.forwarded == 3 && c.duplicates == 1 && c.invalid == 0);

  // Per-device burst of 5: distinct frames from one device, the sixth is limited.
  Rig q;
  auto base = frame("data_confirmed");
  for (int i = 0; i < 6; i++) {
    auto x = base;
    x[13] = uint8_t(0x40 + i);  // fcnt low byte: a different frame each time
    q.hear(x);
  }
  CHECK(q.engine->counters().forwarded == 5 && q.engine->counters().rate_limited == 1);
}

static void test_engine_ts_uncertain() {
  Rig r;
  auto f = frame("data_confirmed");
  auto g = frame("heartbeat");
  r.loop();
  r.take();
  // Just inside loop interval + 20 ms: certain.
  r.io.t += r.io.loop_interval + TS_UNCERTAIN_EXTRA_US;
  r.hear(f);
  auto up = r.take(MSG_UPLINK);
  CHECK(up.size() == 1 && up[0].body[12] == 0);
  // One microsecond more: the main loop was stalled.
  r.loop();
  r.io.t += r.io.loop_interval + TS_UNCERTAIN_EXTRA_US + 1;
  r.hear(g);
  up = r.take(MSG_UPLINK);
  CHECK(up.size() == 1 && up[0].body[12] == UPLINK_TS_UNCERTAIN);
  // A longer configured loop interval moves the threshold with it.
  r.io.loop_interval = 50000;
  r.loop();
  r.io.t += 60000;
  auto h = frame("sync_after_reboot");
  r.hear(h);
  up = r.take(MSG_UPLINK);
  CHECK(up.size() == 1 && up[0].body[12] == 0);
}

static uint8_t hello_caps(Rig &r) {
  auto hello = r.take(MSG_HELLO);
  CHECK(hello.size() == 1);
  return hello.empty() ? 0xFF : hello[0].body[0];
}

static void test_engine_hello_and_capability() {
  Rig r;
  // No HELLO before the server address is known or while the network is down.
  r.io.server = false;
  r.loop();
  r.io.server = true;
  r.io.network = false;
  r.loop();
  CHECK(r.take().empty());
  r.io.network = true;
  const uint64_t first = r.io.t + 16000;
  r.run_until(first);
  CHECK(hello_caps(r) == CAP_DOWNLINK);
  // Then every 60 s, not sooner.
  r.run_until(first + HELLO_INTERVAL_US - 1);
  CHECK(r.take(MSG_HELLO).empty());
  r.run_until(first + HELLO_INTERVAL_US);
  CHECK(hello_caps(r) == CAP_DOWNLINK);
  CHECK(r.io.hello_gaps.size() == 2 && r.io.hello_gaps[1] == 16);

  // A stall over 100 ms: the next HELLO withdraws downlinks and reports the gap.
  r.run_until(r.io.t + 30000000);
  r.io.t += 150000;
  r.loop();
  r.run_until(first + 2 * HELLO_INTERVAL_US);
  CHECK(hello_caps(r) == 0);
  CHECK(r.io.hello_gaps.back() == 150);
  CHECK(r.engine->degraded());

  // While withdrawn, a DOWNLINK is refused as NOT_CAPABLE.
  r.loop({r.downlink(r.io.t, 1000000, frame("downlink_ack"))});
  auto res = r.take(MSG_TX_RESULT);
  CHECK(res.size() == 1 && tx_res(res[0]).result == TX_NOT_CAPABLE);

  // A healthy interval brings the capability back. Exactly 100 ms is still healthy.
  r.run_until(r.io.t + 20000000);
  r.io.t += DEGRADED_GAP_US;
  r.loop();
  r.run_until(first + 3 * HELLO_INTERVAL_US);
  CHECK(hello_caps(r) == CAP_DOWNLINK);
  CHECK(!r.engine->degraded());

  // downlink: false never advertises the capability.
  Rig off([](ProxyConfig &c) { c.downlink_enabled = false; });
  off.loop();
  CHECK(hello_caps(off) == 0);
}

static void test_engine_connection() {
  Rig r;
  r.loop();
  CHECK(!r.engine->connected());
  r.loop({r.status()});
  CHECK(r.engine->connected() && r.engine->server_tags().size() == 1);
  CHECK(r.io.connected_events.size() == 1 && r.io.connected_events[0]);
  const uint64_t last = r.io.t;
  // Still connected at exactly 180 s; disconnected just after.
  r.run_until(last + CONNECT_TIMEOUT_US);
  CHECK(r.engine->connected());
  r.run_until(last + CONNECT_TIMEOUT_US + 1);
  CHECK(!r.engine->connected());
  CHECK(r.io.connected_events.back() == false);
  // Disconnected: frames are still forwarded to the configured address.
  r.take();
  r.hear(frame("data_confirmed"));
  CHECK(r.take(MSG_UPLINK).size() == 1);
  // Five more minutes without a SERVER_STATUS: resolve the address again.
  const uint64_t lost = r.io.t;
  r.run_until(lost + REDISCOVER_AFTER_US);
  CHECK(r.io.rediscovers == 0);
  r.run_until(lost + REDISCOVER_AFTER_US + 16000);
  CHECK(r.io.rediscovers == 1);
  // A SERVER_STATUS reconnects.
  r.io.server = true;
  r.loop({r.status()});
  CHECK(r.engine->connected());
}

// Conformance item 5 and the other envelope paths.
static void test_engine_envelope_checks() {
  Rig r;
  r.loop({r.status()});
  r.take();
  auto f = frame("downlink_ack");
  const uint64_t ref = r.io.t;

  auto bad_mac = r.downlink(ref, 1000000, f);
  bad_mac[bad_mac.size() - 1] ^= 1;
  auto wrong_boot = r.msg(MSG_DOWNLINK, Rig::downlink_body(ref, 1000000, f), Rig::BOOT ^ 1);
  auto uplink_type = r.downlink(ref, 1000000, frame("data_confirmed"));
  auto good = r.downlink(ref, 1000000, f);
  auto replay = good;
  // A message type the proxy sends, and one it does not know.
  auto own_type = r.msg(MSG_HELLO, {});
  auto unknown = r.msg(0x8F, {1, 2, 3});
  ByteWriter w;
  w.u32(1);
  w.u8(3);  // three tags promised, none present
  auto bad_status = r.msg(MSG_SERVER_STATUS, w.buf);
  // An older seq than one already accepted.
  auto stale = r.server->build(MSG_DOWNLINK, Rig::BOOT, 1, Rig::downlink_body(ref, 1000000, f));
  r.loop({bad_mac, wrong_boot, uplink_type, good, replay, own_type, unknown, bad_status, stale});

  auto out = r.take();
  // Only the uplink-type frame draws a TX_RESULT (INVALID); the rest are dropped silently.
  CHECK(out.size() == 1 && out[0].type == MSG_TX_RESULT);
  if (!out.empty()) {
    TxRes x = tx_res(out[0]);
    CHECK(x.result == TX_INVALID && x.offset_us == 0);
  }
  // The good one is transmitted once, the replay is not.
  r.run_until(ref + 1000000);
  CHECK(r.io.transmits.size() == 1);
  r.engine->on_transmit_complete(true);
  out = r.take(MSG_TX_RESULT);
  CHECK(out.size() == 1 && tx_res(out[0]).result == TX_SENT);
  CHECK(r.engine->counters().tx_ok == 1 && r.engine->counters().tx_failed == 1);

  // A DOWNLINK body that does not parse: INVALID.
  r.loop({r.msg(MSG_DOWNLINK, {1, 2, 3})});
  out = r.take(MSG_TX_RESULT);
  CHECK(out.size() == 1 && tx_res(out[0]).result == TX_INVALID && tx_res(out[0]).seq == r.server_seq);
}

// Conformance item 6: the frame goes out on time and offset_us says how late.
static void test_engine_rx1_offset() {
  Rig r;
  r.loop({r.status()});
  r.take();
  auto f = frame("downlink_ack");
  const uint64_t ref = r.io.t - 300000;  // the uplink was heard 300 ms ago
  const uint64_t tx_at = ref + 1000000;
  r.loop({r.downlink(ref, 1000000, f)});
  CHECK(r.take().empty());
  CHECK(r.io.timer == tx_at - TIMER_LEAD_US);
  // The timer wakes the loop 2 ms early; the engine waits out the rest.
  r.io.t = tx_at - TIMER_LEAD_US;
  r.io.start_cost_us = 850;
  r.loop();
  CHECK(r.io.transmits.size() == 1);
  if (!r.io.transmits.empty()) {
    CHECK(hex(r.io.transmits[0].frame) == hex(f));
    CHECK(r.io.transmits[0].at == tx_at + 850);
    CHECK(r.io.transmits[0].timeout_ms == lora_airtime_us(f.size(), 9, 500000) / 1000 + 100);
  }
  CHECK(r.take().empty());  // nothing until the radio reports completion
  r.io.t += 70000;
  r.engine->on_transmit_complete(true);
  auto out = r.take(MSG_TX_RESULT);
  CHECK(out.size() == 1);
  if (!out.empty()) {
    TxRes x = tx_res(out[0]);
    CHECK(x.seq == r.server_seq && x.result == TX_SENT && x.offset_us == 850);
    CHECK(x.offset_us >= 0 && x.offset_us <= 100000);
  }
  CHECK(r.io.loop_requests == 1);
  CHECK(r.engine->airtime_used_us() == lora_airtime_us(f.size(), 9, 500000));
  // A late completion call with nothing in flight is ignored.
  r.engine->on_transmit_complete(true);
  CHECK(r.take().empty() && r.engine->counters().tx_ok == 1);
}

// Conformance item 7.
static void test_engine_duty_cycle() {
  Rig r([](ProxyConfig &c) { c.budget_permille = 1; });  // 3.6 s per hour
  r.loop({r.status()});
  r.take();
  auto f = frame("downlink_ack");
  const uint32_t air = lora_airtime_us(f.size(), 9, 500000);
  const uint32_t fit = 3600000 / air;
  uint32_t sent = 0;
  for (uint32_t i = 0; i <= fit; i++) {
    r.loop({r.downlink(r.io.t, 500000, f)});
    r.run_until(r.io.t + 500000);
    r.engine->on_transmit_complete(true);
    for (auto &m : r.take(MSG_TX_RESULT)) {
      TxRes x = tx_res(m);
      if (x.result == TX_SENT)
        sent++;
      else
        CHECK(x.result == TX_DUTY_CYCLE && i == fit);
    }
  }
  CHECK(sent == fit);
  CHECK(r.engine->counters().tx_ok == fit && r.engine->counters().tx_failed == 1);
}

static void test_engine_busy_retry() {
  Rig r;
  r.loop({r.status()});
  r.take();
  auto f = frame("downlink_ack");
  const uint64_t tx_at = r.io.t + 1000000;
  r.loop({r.downlink(r.io.t, 1000000, f)});
  // The radio stays BUSY: retried every pass until the window closes, then BUSY.
  r.io.radio_answers.assign(100, TX_BUSY);
  r.run_until(tx_at + TX_WINDOW_US);
  CHECK(r.take(MSG_TX_RESULT).empty());
  CHECK(r.io.radio_answers.size() < 100 - 5);  // several attempts inside the window
  CHECK(r.io.timer <= r.io.t);                  // the timer keeps the loop coming back
  r.run_until(tx_at + TX_WINDOW_US + 1);
  auto out = r.take(MSG_TX_RESULT);
  CHECK(out.size() == 1 && tx_res(out[0]).result == TX_BUSY);
  CHECK(r.io.transmits.empty());

  // BUSY once, then accepted inside the window: SENT with the later offset.
  Rig q;
  q.loop({q.status()});
  q.take();
  const uint64_t at = q.io.t + 1000000;
  q.loop({q.downlink(q.io.t, 1000000, f)});
  q.io.t = at;
  q.io.radio_answers = {TX_BUSY};
  q.loop();
  CHECK(q.io.transmits.empty());
  q.io.t = at + 16000;
  q.loop();
  CHECK(q.io.transmits.size() == 1);
  q.engine->on_transmit_complete(true);
  out = q.take(MSG_TX_RESULT);
  CHECK(out.size() == 1 && tx_res(out[0]).result == TX_SENT && tx_res(out[0]).offset_us == 16000);

  // Never attempted (the loop was stalled past the window): TOO_LATE, not BUSY.
  Rig s;
  s.loop({s.status()});
  s.take();
  const uint64_t when = s.io.t + 1000000;
  s.loop({s.downlink(s.io.t, 1000000, f)});
  s.io.t = when + TX_WINDOW_US + 1;
  s.loop();
  out = s.take(MSG_TX_RESULT);
  CHECK(out.size() == 1 && tx_res(out[0]).result == TX_TOO_LATE);
  CHECK(s.io.transmits.empty());
}

static void test_engine_in_flight_and_errors() {
  auto f = frame("downlink_ack");
  const uint32_t air = lora_airtime_us(f.size(), 9, 500000);
  // Two downlinks as close as the schedule allows. The first stays in flight past the
  // second's window, so the second is reported TOO_LATE once the radio is free.
  Rig r;
  r.loop({r.status()});
  r.take();
  const uint64_t ref = r.io.t;
  const uint32_t gap = air + uint32_t(TX_WINDOW_US) + 1;
  r.loop({r.downlink(ref, 1000000, f), r.downlink(ref, 1000000 + gap, f)});
  CHECK(r.take().empty());
  const uint32_t second = r.server_seq;
  r.run_until(ref + 1000000);
  CHECK(r.io.transmits.size() == 1);
  r.run_until(ref + 1000000 + gap + TX_WINDOW_US + 1);
  CHECK(r.io.transmits.size() == 1);  // one in flight at a time
  CHECK(r.take().empty());
  r.engine->on_transmit_complete(false);  // and it failed
  auto out = r.take(MSG_TX_RESULT);
  CHECK(out.size() == 1 && tx_res(out[0]).result == TX_RADIO_ERROR && tx_res(out[0]).offset_us == 0);
  CHECK(r.engine->airtime_used_us() == 0);  // a failed transmission spends no budget
  r.loop();
  out = r.take(MSG_TX_RESULT);
  CHECK(out.size() == 1 && tx_res(out[0]).seq == second && tx_res(out[0]).result == TX_TOO_LATE);
  CHECK(r.engine->counters().tx_failed == 2 && r.engine->counters().tx_ok == 0);

  // The radio refuses outright: RADIO_ERROR at once, and the next downlink still goes.
  Rig q;
  q.loop({q.status()});
  q.take();
  const uint64_t base = q.io.t;
  q.loop({q.downlink(base, 1000000, f), q.downlink(base, 2000000, f)});
  q.io.radio_answers = {TX_RADIO_ERROR};
  q.run_until(base + 1000000);
  out = q.take(MSG_TX_RESULT);
  CHECK(out.size() == 1 && tx_res(out[0]).result == TX_RADIO_ERROR);
  CHECK(q.io.timer == base + 2000000 - TIMER_LEAD_US);
  q.run_until(base + 2000000);
  CHECK(q.io.transmits.size() == 1);
  q.engine->on_transmit_complete(true);
  out = q.take(MSG_TX_RESULT);
  CHECK(out.size() == 1 && tx_res(out[0]).result == TX_SENT);
}

static uint32_t hello_nonce(const Sent &m) {
  const size_t at = 2 + m.body[1] + 41;  // after region and the fixed fields up to max_loop_gap_ms
  return at + 4 <= m.body.size() ? rd32(m.body.data() + at) : 0xFFFFFFFFu;
}

static std::vector<uint8_t> two_tag_status(uint32_t hello_seq) {
  ByteWriter w;
  w.u32(1795226400);
  w.u32(hello_seq);
  w.u8(2);
  w.u32(0x11111111);
  w.u32(0x22222222);
  return w.buf;
}

// Conformance item 10: a restarted server is followed through the SERVER_STATUS echo.
static void test_engine_server_restart() {
  Rig r;
  r.loop();
  auto hellos = r.take(MSG_HELLO);
  CHECK(hellos.size() == 1);
  const uint32_t h1 = hellos.empty() ? 0 : hellos[0].seq;
  r.loop({r.status(h1)});
  CHECK(r.engine->connected());
  for (int i = 0; i < 5; i++)
    r.loop({r.status()});
  const size_t stale = r.io.logged("Ignored stale or replayed SERVER_STATUS");

  // The server restarts and counts from 1 again, with no clock seeding.
  r.server_seq = 0;
  r.loop({r.msg(MSG_DOWNLINK, {1, 2, 3})});
  CHECK(r.take(MSG_TX_RESULT).empty());
  // Unsolicited, echoing a HELLO already echoed, or one never sent: all held to the floor.
  r.loop({r.msg(MSG_SERVER_STATUS, two_tag_status(0)), r.msg(MSG_SERVER_STATUS, two_tag_status(h1)),
          r.msg(MSG_SERVER_STATUS, two_tag_status(h1 + 100))});
  CHECK(r.engine->server_tags().size() == 1);
  CHECK(r.io.logged("Ignored stale or replayed SERVER_STATUS") == stale + 3);

  // Its HELLO_REQUEST draws a HELLO at once, and its answer resyncs the floor.
  r.loop({r.hello_request(0xABCD0001)});
  hellos = r.take(MSG_HELLO);
  CHECK(hellos.size() == 1 && hello_nonce(hellos[0]) == 0xABCD0001u);
  const uint32_t h2 = hellos.empty() ? 0 : hellos[0].seq;
  r.server_seq = 0;
  auto st = r.msg(MSG_SERVER_STATUS, two_tag_status(h2));
  r.loop({st});
  CHECK(r.engine->server_tags().size() == 2 && r.engine->connected());
  CHECK(r.io.logged("Server restarted") == 1);
  // A replay of it finds its echo used up.
  r.loop({st});
  CHECK(r.io.logged("Ignored stale or replayed SERVER_STATUS") == stale + 4);
  CHECK(r.io.logged("Server restarted") == 1);
  // The restarted server's next messages pass the strict rule, with no reboot.
  r.loop({r.msg(MSG_DOWNLINK, {1, 2, 3})});
  auto out = r.take(MSG_TX_RESULT);
  CHECK(out.size() == 1 && tx_res(out[0]).result == TX_INVALID && tx_res(out[0]).seq == 2);
  r.loop({r.status()});
  CHECK(r.engine->server_tags().size() == 1);
}

// Conformance item 11.
static void test_engine_hello_request() {
  Rig r;
  r.loop();
  r.take();
  r.loop({r.status(1)});
  for (int i = 0; i < 3; i++)
    r.loop({r.status()});

  auto bad_mac = r.hello_request(7);
  bad_mac.back() ^= 1;
  r.loop({r.hello_request(7, Rig::BOOT ^ 1), r.hello_request(0),
          r.server->build(MSG_HELLO_REQUEST, Rig::BOOT, 0, {1, 2, 3}), bad_mac});
  CHECK(r.take(MSG_HELLO).empty());

  // Answered at once although its seq (0) is below the floor, which it leaves alone.
  const uint64_t t1 = r.io.t;
  r.loop({r.hello_request(0x11)});
  auto h = r.take(MSG_HELLO);
  CHECK(h.size() == 1 && hello_nonce(h[0]) == 0x11u);
  r.loop({r.msg(MSG_DOWNLINK, {1, 2, 3})});
  CHECK(r.take(MSG_TX_RESULT).size() == 1);

  // More within 5 s: one HELLO 5 s after the first, echoing the latest nonce.
  r.io.t += 1000000;
  r.loop({r.hello_request(0x22), r.hello_request(0x33)});
  CHECK(r.take(MSG_HELLO).empty());
  r.run_until(t1 + HELLO_REQUEST_GAP_US - 1);
  CHECK(r.take(MSG_HELLO).empty());
  r.run_until(t1 + HELLO_REQUEST_GAP_US);
  h = r.take(MSG_HELLO);
  CHECK(h.size() == 1 && hello_nonce(h[0]) == 0x33u);

  // That HELLO counts as the periodic one, and the next carries no nonce.
  const uint64_t t2 = r.io.t;
  r.run_until(t2 + HELLO_INTERVAL_US - 1);
  CHECK(r.take(MSG_HELLO).empty());
  r.run_until(t2 + HELLO_INTERVAL_US);
  h = r.take(MSG_HELLO);
  CHECK(h.size() == 1 && hello_nonce(h[0]) == 0);

  // Once 5 s have passed since the last requested HELLO, a request is answered at once.
  r.loop({r.hello_request(0x44)});
  h = r.take(MSG_HELLO);
  CHECK(h.size() == 1 && hello_nonce(h[0]) == 0x44u);
}

int main() {
  test_sha256();
  test_frames();
  test_envelope();
  test_seq_guard();
  test_hello_echoes();
  test_dedupe();
  test_dedupe_lets_retries_through();
  test_rate_limits();
  test_receive_pipeline();
  test_airtime();
  test_budget();
  test_scheduler();
  test_eui64();
  test_engine_forwarding();
  test_engine_dedupe_and_offline();
  test_engine_ts_uncertain();
  test_engine_hello_and_capability();
  test_engine_connection();
  test_engine_envelope_checks();
  test_engine_server_restart();
  test_engine_hello_request();
  test_engine_rx1_offset();
  test_engine_duty_cycle();
  test_engine_busy_retry();
  test_engine_in_flight_and_errors();
  std::printf("%d checks, %d failures\n", checks, failures);
  return failures == 0 ? 0 : 1;
}
