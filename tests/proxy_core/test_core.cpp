// Host unit tests for the cs_proxy core. Build and run with:  make -C tests/proxy_core

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "cs_sha256.h"
#include "proxy_core.h"
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
  CHECK(hex(tx_result_body(2, TX_SENT, 1800)) == env("tx_result").body);

  auto ss = unhex(env("server_status").body);
  ServerStatus st{};
  CHECK(parse_server_status(ss.data(), ss.size(), st));
  CHECK(st.server_time == 1795226400u && st.tags.size() == 3 && st.tags[1] == 0x61d306d3u);
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
  s.start(f4);
  CHECK(s.due(now + 3000000) == nullptr);
  CHECK(s.next_tx_at() == 0);
  CHECK(s.admit(5, now + 3050000, f.data(), f.size(), air, now, true, budget) == TX_BUSY);
  AirtimeBudget one_frame(1);  // 0.1% = 3.6 s
  one_frame.spend(3600000 - air - air / 2, now);
  CHECK(s.admit(6, now + 4500000, f.data(), f.size(), air, now, true, one_frame) == TX_DUTY_CYCLE);
  s.release(f4);
  CHECK(!f4->in_flight && !f4->saw_busy);
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

int main() {
  test_sha256();
  test_frames();
  test_envelope();
  test_seq_guard();
  test_dedupe();
  test_rate_limits();
  test_receive_pipeline();
  test_airtime();
  test_budget();
  test_scheduler();
  test_eui64();
  std::printf("%d checks, %d failures\n", checks, failures);
  return failures == 0 ? 0 : 1;
}
