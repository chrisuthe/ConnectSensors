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

  // A proxy has no keys: it drops the structurally invalid frames and forwards the bad MICs.
  for (const auto &v : INVALID_FRAME_VECTORS) {
    auto inv = unhex(v.hex);
    CHECK((check_uplink(inv.data(), inv.size()) != FrameCheck::OK) == v.proxy_discards);
  }

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
  // At most 32 tags (05 section 5.3): 32 parse, 33 do not, even with the length right.
  for (uint32_t n : {32u, 33u, 255u}) {
    ByteWriter w;
    w.u32(1795226400);
    w.u32(0);
    w.u8(uint8_t(n));
    for (uint32_t i = 0; i < n; i++)
      w.u32(0x1000 + i);
    ServerStatus many;
    const bool ok = parse_server_status(w.buf.data(), w.buf.size(), many);
    CHECK(ok == (n <= 32));
    if (ok)
      CHECK(many.tags.size() == n && many.tags[n - 1] == 0x1000 + n - 1);
  }

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

// Inserting a key already cached refreshes it in place: its window restarts and it
// becomes the newest entry, so it outlives keys inserted after its first copy.
static void test_dedupe_reinsert() {
  const uint64_t W = 2000000;
  DedupeCache c(2);
  c.insert(1, 1000);
  c.insert(2, 2000);
  c.insert(1, 1000 + W - 1);
  CHECK(c.contains(1, 1000 + W, W));  // would have expired counting from the first insert
  CHECK(c.contains(2, 1000 + W, W));  // and took no second entry
  c.insert(3, 1000 + W);              // evicts 2, now the oldest
  CHECK(c.contains(1, 1000 + W, W) && c.contains(3, 1000 + W, W) && !c.contains(2, 1000 + W, W));
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

// 32 per-device buckets; the 33rd dev_tag takes the least recently used one, and a
// device that comes back after losing its slot starts with a full bucket.
static void test_rate_limit_eviction() {
  RateLimiter rl(1000, 2, 5, 5);  // global out of the way
  auto dev = [](uint32_t tag) { return FrameHeader{2, 1, tag, 1}; };
  uint64_t t = 1000000;
  // 1 is drained first, 2 last; the slots fill with 1..32.
  for (int i = 0; i < 5; i++)
    CHECK(rl.allow(dev(1), t));
  for (uint32_t tag = 3; tag <= 32; tag++)
    CHECK(rl.allow(dev(tag), ++t));
  for (int i = 0; i < 5; i++)
    CHECK(rl.allow(dev(2), ++t));
  CHECK(!rl.allow(dev(1), ++t) && !rl.allow(dev(2), t));  // both drained; 1 is used again
  // The 33rd evicts the least recently used: 3, not 1 or 2.
  CHECK(rl.allow(dev(33), ++t));
  CHECK(!rl.allow(dev(1), ++t) && !rl.allow(dev(2), t));
  int ok = 0;
  for (int i = 0; i < 6; i++)
    ok += rl.allow(dev(3), t);
  CHECK(ok == 5);  // 3 lost its slot (to 33) and got a fresh one (evicting 4)
  ok = 0;
  for (int i = 0; i < 6; i++)
    ok += rl.allow(dev(33), t);
  CHECK(ok == 4);  // 33 kept its slot: one token spent above
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

// The budget is a sliding hour in one-minute buckets: each minute's airtime leaves
// the total 60 minutes after the minute it was spent in, one bucket at a time.
static void test_budget_rollover() {
  const uint64_t MIN = 60000000ULL;
  const uint64_t t0 = 100 * MIN;  // a minute boundary
  AirtimeBudget b(20);
  for (uint64_t m = 0; m < 5; m++)
    b.spend(1000 * (m + 1), t0 + m * MIN + 30000000);  // mid-minute
  CHECK(b.used_us(t0 + 59 * MIN + 59999999) == 15000u);
  CHECK(b.used_us(t0 + 60 * MIN) == 14000u);  // minute 0 has left
  CHECK(b.used_us(t0 + 61 * MIN) == 12000u);
  // Skipping minutes drops every bucket passed over, and only those.
  CHECK(b.used_us(t0 + 63 * MIN + 1) == 5000u);
  b.spend(700, t0 + 63 * MIN + 2);
  CHECK(b.used_us(t0 + 64 * MIN) == 700u);
  // A spend lands in the current minute, after its bucket was cleared of the old hour.
  b.spend(300, t0 + 64 * MIN);
  CHECK(b.used_us(t0 + 122 * MIN + 59999999) == 1000u);
  CHECK(b.used_us(t0 + 123 * MIN) == 300u);
  CHECK(b.used_us(t0 + 124 * MIN) == 0u);
  // An idle gap of an hour or more clears everything at once.
  b.spend(500, t0 + 200 * MIN);
  CHECK(b.used_us(t0 + 200 * MIN + 1) == 500u);
  CHECK(b.used_us(t0 + 400 * MIN) == 0u);
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

  // Airtime is reserved at admit: a downlink still waiting for its tx_at counts against
  // the budget although nothing is spent yet, and a released slot frees it (06 section 8.1).
  AirtimeBudget room(1);
  room.spend(3600000 - air - air / 2, now);  // room for one more frame
  TxScheduler s3;
  CHECK(s3.admit(1, now + 1000000, f.data(), f.size(), air, now, true, room) == TX_SENT);
  CHECK(room.used_us(now) == 3600000 - air - air / 2);
  CHECK(s3.admit(2, now + 3000000, f.data(), f.size(), air, now, true, room) == TX_DUTY_CYCLE);
  s3.release(s3.due(now + 1000000));
  CHECK(s3.admit(2, now + 3000000, f.data(), f.size(), air, now, true, room) == TX_SENT);
}

// Four transmit slots: a fifth downlink is BUSY even when its time is free, until a
// slot is released.
static void test_scheduler_slots_full() {
  auto f = frame("downlink_ack");
  const uint32_t air = lora_airtime_us(f.size(), 9, 500000);
  AirtimeBudget budget(20);
  TxScheduler s;
  const uint64_t now = 10000000;
  for (uint32_t i = 0; i < TX_SLOTS; i++)
    CHECK(s.admit(i + 1, now + 500000 * (i + 1), f.data(), f.size(), air, now, true, budget) == TX_SENT);
  const uint64_t free_time = now + 500000 * (TX_SLOTS + 1);
  CHECK(s.admit(9, free_time, f.data(), f.size(), air, now, true, budget) == TX_BUSY);
  // An in-flight slot is still taken.
  ScheduledTx *first = s.due(now + 500000);
  CHECK(first != nullptr && first->seq == 1);
  s.start(first, now + 500000);
  CHECK(s.admit(9, free_time, f.data(), f.size(), air, now, true, budget) == TX_BUSY);
  s.release(first);
  CHECK(s.admit(9, free_time, f.data(), f.size(), air, now, true, budget) == TX_SENT);
  CHECK(s.admit(10, free_time + 500000, f.data(), f.size(), air, now, true, budget) == TX_BUSY);
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
  int receiving_checks = 0;            // is_receiving() calls
  int receiving_answers = 0;           // that many calls report a frame arriving
  uint64_t timer = 0;
  int loop_requests = 0;
  int rediscovers = 0;
  std::vector<bool> connected_events;
  std::vector<uint16_t> hello_gaps;
  std::vector<uint64_t> counter_publishes;  // times of on_counters()

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
  bool is_receiving() override {
    receiving_checks++;
    if (receiving_answers == 0)
      return false;
    receiving_answers--;
    return true;
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
  void on_counters() override { counter_publishes.push_back(t); }
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

// Two short healthy passes, so the gaps the flag looks back over are all small.
static void settle(Rig &r) {
  for (int i = 0; i < 2; i++) {
    r.io.t += 1000;
    r.loop();
  }
}

// Each call varies the MIC byte so dedupe never hides a frame; the keyless checks
// do not look at it.
static uint8_t heard_flags(Rig &r, const char *name) {
  static uint8_t n = 0;
  auto f = frame(name);
  f.back() ^= ++n;
  r.hear(f);
  auto up = r.take(MSG_UPLINK);
  CHECK(up.size() == 1);
  return up.empty() ? 0xFF : up[0].body[12];
}

static void test_engine_ts_uncertain() {
  Rig r;
  r.loop();
  r.take();
  // Since the last pass: just inside loop interval + 20 ms is certain.
  settle(r);
  r.io.t += r.io.loop_interval + TS_UNCERTAIN_EXTRA_US;
  CHECK(heard_flags(r, "data_confirmed") == 0);
  // One microsecond more: the main loop was stalled.
  settle(r);
  r.io.t += r.io.loop_interval + TS_UNCERTAIN_EXTRA_US + 1;
  CHECK(heard_flags(r, "heartbeat") == UPLINK_TS_UNCERTAIN);

  // The radio usually runs after this component in a pass, so a packet heard just after
  // a pass may have waited through the gap before it (an interval lambda stalling the
  // scheduler, say), or through the one before that (06 section 7).
  const uint64_t stall = r.io.loop_interval + TS_UNCERTAIN_EXTRA_US + 1;
  settle(r);
  r.io.t += stall;
  r.loop();
  r.io.t += 1000;
  CHECK(heard_flags(r, "sync_after_reboot") == UPLINK_TS_UNCERTAIN);
  settle(r);
  r.io.t += stall;
  r.loop();
  r.io.t += 1000;
  r.loop();
  r.io.t += 1000;
  CHECK(heard_flags(r, "sync_after_exchange") == UPLINK_TS_UNCERTAIN);
  // Three passes on, the stall cannot have delayed a packet heard now.
  r.io.t += 1000;
  r.loop();
  r.io.t += 1000;
  CHECK(heard_flags(r, "join") == 0);
  // Exactly at the limit is still healthy.
  settle(r);
  r.io.t += r.io.loop_interval + TS_UNCERTAIN_EXTRA_US;
  r.loop();
  r.io.t += 1000;
  CHECK(heard_flags(r, "data_confirmed") == 0);

  // A longer configured loop interval counts as 16 ms, so the unflagged error stays
  // within the 36 ms of the timing budget (01 section 4.1).
  r.io.loop_interval = 50000;
  settle(r);
  r.io.t += 36000;
  CHECK(heard_flags(r, "heartbeat") == 0);
  settle(r);
  r.io.t += 36001;
  CHECK(heard_flags(r, "sync_after_reboot") == UPLINK_TS_UNCERTAIN);
  // A shorter one tightens the threshold.
  r.io.loop_interval = 8000;
  settle(r);
  r.io.t += 28001;
  CHECK(heard_flags(r, "join") == UPLINK_TS_UNCERTAIN);
}

// 01 section 4.1: the latest detection of a downlink stays inside the sensor's window.
static void test_timing_budget() {
  CHECK(TX_WINDOW_US == 40000);
  const uint64_t ts_error = TS_LOOP_INTERVAL_CAP_US + TS_UNCERTAIN_EXTRA_US;
  CHECK(ts_error == 36000);
  const uint64_t radio_start = 5000;
  // Preamble, sync word and header: 8 + 4.25 + 8 symbols.
  auto detection = [](uint8_t sf, uint32_t bw_hz) { return uint64_t(20.25 * (1u << sf) * 1e6 / bw_hz); };
  const uint64_t us915 = ts_error + TX_WINDOW_US + radio_start + detection(9, 500000);
  const uint64_t eu868 = ts_error + TX_WINDOW_US + radio_start + detection(9, 125000);
  CHECK(us915 / 100 == 1017 && us915 + 40000 <= 150000);
  CHECK(eu868 / 100 == 1639 && eu868 + 30000 <= 200000);
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

  // A stall over 100 ms withdraws downlinks and is announced at once with a HELLO that
  // reports it (06 section 7).
  r.run_until(r.io.t + 30000000);
  r.io.t += 150000;
  r.loop();
  const uint64_t first_stall = r.io.t;
  CHECK(r.engine->degraded());
  CHECK(r.io.logged("downlinks withdrawn for 10 s") == 1);
  CHECK(hello_caps(r) == 0);
  CHECK(r.io.hello_gaps.back() == 150);
  // Ten seconds on, the window closes and another HELLO offers downlinks again.
  r.run_until(first_stall + DEGRADED_WINDOW_US - 1);
  CHECK(r.take(MSG_HELLO).empty());
  r.run_until(first_stall + DEGRADED_WINDOW_US);
  CHECK(hello_caps(r) == CAP_DOWNLINK);
  CHECK(r.io.logged("downlinks offered again") == 1);
  CHECK(!r.engine->degraded());
  // The periodic HELLO keeps its schedule.
  r.run_until(first + 2 * HELLO_INTERVAL_US - 1);
  CHECK(r.take(MSG_HELLO).empty());
  r.run_until(first + 2 * HELLO_INTERVAL_US);
  CHECK(hello_caps(r) == CAP_DOWNLINK);
  CHECK(r.io.hello_gaps.back() == 16);

  // A stall just before a periodic HELLO: announced at once, and the periodic one
  // still goes out on time, without the bit.
  r.run_until(first + 3 * HELLO_INTERVAL_US - 1000000);
  r.io.t += 200000;
  r.loop();
  const uint64_t stalled = r.io.t;
  CHECK(hello_caps(r) == 0);
  CHECK(r.io.hello_gaps.back() == 200);
  r.run_until(first + 3 * HELLO_INTERVAL_US);
  CHECK(hello_caps(r) == 0);

  // Another stall inside the window extends it but is neither logged nor announced.
  r.run_until(stalled + 5000000);
  r.io.t += 120000;
  r.loop();
  const uint64_t again = r.io.t;
  CHECK(r.io.logged("downlinks withdrawn") == 2);
  CHECK(r.take(MSG_HELLO).empty());
  // While withdrawn, a DOWNLINK is refused as NOT_CAPABLE, up to the end of the window.
  r.run_until(again + DEGRADED_WINDOW_US - 16000);
  r.loop({r.downlink(r.io.t, 1000000, frame("downlink_ack"))});
  auto res = r.take(MSG_TX_RESULT);
  CHECK(res.size() == 1 && tx_res(res[0]).result == TX_NOT_CAPABLE);
  r.run_until(again + DEGRADED_WINDOW_US - 1);
  CHECK(r.engine->degraded());
  CHECK(r.take(MSG_HELLO).empty());
  r.io.t = again + DEGRADED_WINDOW_US;
  CHECK(!r.engine->degraded());
  // Once the window has passed, downlinks are accepted again, announced in the same pass.
  r.loop({r.downlink(r.io.t, 1000000, frame("downlink_ack"))});
  auto out = r.take();
  CHECK(out.size() == 1 && out[0].type == MSG_HELLO && out[0].body[0] == CAP_DOWNLINK);
  r.run_until(r.io.t + 1000000);
  CHECK(r.io.transmits.size() == 1);

  // Exactly 100 ms is still healthy.
  r.io.t += DEGRADED_GAP_US;
  r.loop();
  CHECK(!r.engine->degraded());

  // downlink: false never advertises the capability.
  Rig off([](ProxyConfig &c) { c.downlink_enabled = false; });
  off.loop();
  CHECK(hello_caps(off) == 0);
}

static uint32_t hello_nonce(const Sent &m);

// Capability HELLOs are rate-limited and never move the periodic schedule (06 section 7).
static void test_engine_capability_hello_rate() {
  Rig r;
  const uint64_t first = r.io.t + 16000;
  r.run_until(first);
  CHECK(hello_caps(r) == CAP_DOWNLINK);
  // A stall, then the window closes: two HELLOs.
  r.run_until(first + 20000000);
  r.io.t += 150000;
  r.loop();
  CHECK(hello_caps(r) == 0);
  const uint64_t closed = r.io.t + DEGRADED_WINDOW_US;
  r.run_until(closed);
  CHECK(hello_caps(r) == CAP_DOWNLINK);
  // A stall 1 s after that announcement waits until 5 s have passed since it.
  r.run_until(closed + 1000000);
  r.io.t += 150000;
  r.loop();
  const uint64_t stall2 = r.io.t;
  CHECK(r.engine->degraded());
  r.run_until(closed + HELLO_CHANGE_GAP_US - 1);
  CHECK(r.take(MSG_HELLO).empty());
  r.run_until(closed + HELLO_CHANGE_GAP_US);
  CHECK(hello_caps(r) == 0);
  CHECK(r.io.hello_gaps.back() == 150);  // the stall, kept since the last HELLO
  // Its window closes more than 5 s later, so that is announced at once.
  r.run_until(stall2 + DEGRADED_WINDOW_US);
  CHECK(hello_caps(r) == CAP_DOWNLINK);
  // Five HELLOs so far; the periodic one is still due 60 s after the first.
  CHECK(r.io.hello_gaps.size() == 5);
  r.run_until(first + HELLO_INTERVAL_US - 1);
  CHECK(r.take(MSG_HELLO).empty());
  r.run_until(first + HELLO_INTERVAL_US);
  CHECK(hello_caps(r) == CAP_DOWNLINK);
  r.run_until(first + 2 * HELLO_INTERVAL_US - 1);
  CHECK(r.take(MSG_HELLO).empty());
  r.run_until(first + 2 * HELLO_INTERVAL_US);
  CHECK(hello_caps(r) == CAP_DOWNLINK);

  // A capability HELLO leaves a deferred HELLO_REQUEST alone: it carries no nonce, and
  // the requested HELLO still goes out on its own schedule.
  r.loop({r.hello_request(0x55)});
  auto h = r.take(MSG_HELLO);
  CHECK(h.size() == 1 && hello_nonce(h[0]) == 0x55u);
  const uint64_t requested = r.io.t;
  r.run_until(r.io.t + 1000000);
  r.loop({r.hello_request(0x66)});
  CHECK(r.take(MSG_HELLO).empty());
  r.run_until(r.io.t + 1000000);
  r.io.t += 150000;
  r.loop();
  h = r.take(MSG_HELLO);
  CHECK(h.size() == 1 && hello_nonce(h[0]) == 0 && h[0].body[0] == 0);
  r.run_until(requested + HELLO_REQUEST_GAP_US);
  h = r.take(MSG_HELLO);
  CHECK(h.size() == 1 && hello_nonce(h[0]) == 0x66u);

  // downlink: false never changes capability, so stalls draw no extra HELLO.
  Rig off([](ProxyConfig &c) { c.downlink_enabled = false; });
  off.loop();
  CHECK(hello_caps(off) == 0);
  off.run_until(off.io.t + 1000000);
  off.io.t += 150000;
  off.loop();
  off.run_until(off.io.t + DEGRADED_WINDOW_US);
  CHECK(off.take(MSG_HELLO).empty());
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
  // The HELLO goes out as soon as the address is known again, not at the 60 s tick.
  r.take();
  r.run_until(r.io.t + 1000000);
  CHECK(r.take(MSG_HELLO).empty());  // still resolving
  r.io.server = true;
  r.loop();
  CHECK(r.take(MSG_HELLO).size() == 1);
  // A SERVER_STATUS reconnects.
  r.loop({r.status()});
  CHECK(r.engine->connected());
}

// Rediscovery also covers a proxy that never connected: a wrong address resolved at
// boot is not kept forever (06 section 9). Only time with an address counts.
static void test_engine_rediscover_never_connected() {
  Rig r;
  r.io.server = false;
  r.run_until(r.io.t + 2 * REDISCOVER_AFTER_US);  // no address at all: nothing to forget
  CHECK(r.io.rediscovers == 0);
  r.io.server = true;
  const uint64_t known = r.io.t + 16000;
  r.run_until(known);
  CHECK(r.take(MSG_HELLO).size() == 1);
  r.run_until(known + REDISCOVER_AFTER_US);
  CHECK(r.io.rediscovers == 0);
  r.run_until(known + REDISCOVER_AFTER_US + 16000);
  CHECK(r.io.rediscovers == 1 && !r.engine->connected());
  // A lookup slower than the interval does not trigger the next rediscovery at once.
  r.run_until(r.io.t + REDISCOVER_AFTER_US + 1000000);
  CHECK(r.io.rediscovers == 1);
  r.take();
  r.io.server = true;
  const uint64_t again = r.io.t + 16000;
  r.run_until(again);
  CHECK(r.take(MSG_HELLO).size() == 1 && r.io.rediscovers == 1);
  r.run_until(again + REDISCOVER_AFTER_US + 16000);
  CHECK(r.io.rediscovers == 2);
  // Once connected, none until the connection is lost.
  r.io.server = true;
  r.loop({r.status()});
  CHECK(r.engine->connected());
  r.run_until(r.io.t + CONNECT_TIMEOUT_US);
  CHECK(r.io.rediscovers == 2);
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
  r.run_until(tx_at - TIMER_LEAD_US - 1000);
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
  CHECK(r.io.radio_answers.size() <= 100 - 3);  // a retry every 16 ms pass inside the window
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

// A frame arriving when a downlink is due holds it while the next pass can still send
// inside the window, then the downlink goes out anyway (06 section 8.2).
static void test_engine_rx_hold() {
  auto f = frame("downlink_ack");
  auto setup = [&](Rig &r) {
    r.loop({r.status()});
    r.take();
    const uint64_t tx_at = r.io.t + 1000000;
    r.loop({r.downlink(r.io.t, 1000000, f)});
    return tx_at;
  };

  // Held for two passes, sent on the third once the frame has finished.
  Rig r;
  const uint64_t tx_at = setup(r);
  CHECK(r.io.receiving_checks == 0);  // the radio is only asked while a downlink is due
  r.io.receiving_answers = 2;
  r.io.t = tx_at;
  r.loop();
  CHECK(r.io.transmits.empty());
  CHECK(r.io.timer <= r.io.t);  // the timer keeps the loop coming back
  r.io.t = tx_at + 8000;
  r.loop();
  CHECK(r.io.transmits.empty());
  r.io.t = tx_at + 15000;
  r.loop();
  CHECK(r.io.transmits.size() == 1 && r.io.transmits[0].at == tx_at + 15000);
  CHECK(r.io.receiving_checks == 3);
  CHECK(r.io.logged("held 15.00 ms for an arriving frame") == 1);
  r.engine->on_transmit_complete(true);
  auto out = r.take(MSG_TX_RESULT);
  CHECK(out.size() == 1 && tx_res(out[0]).result == TX_SENT && tx_res(out[0]).offset_us == 15000);

  // Still receiving: held while one more 16 ms pass plus the slack fits in the
  // window, then forced, inside the window.
  Rig q;
  const uint64_t at = setup(q);
  q.io.receiving_answers = 100;
  const uint64_t last_hold = at + TX_WINDOW_US - q.io.loop_interval - RX_HOLD_SLACK_US;
  CHECK(last_hold == at + 22000);
  for (uint64_t t : {at, at + 16000, last_hold}) {
    q.io.t = t;
    q.loop();
  }
  CHECK(q.io.transmits.empty());
  q.io.t = last_hold + 1;
  q.loop();
  CHECK(q.io.transmits.size() == 1);
  CHECK(q.io.logged("sent over a frame still arriving") == 1);
  q.engine->on_transmit_complete(true);
  out = q.take(MSG_TX_RESULT);
  CHECK(out.size() == 1 && tx_res(out[0]).result == TX_SENT && tx_res(out[0]).offset_us == 22001);
  CHECK(tx_res(out[0]).offset_us <= int32_t(TX_WINDOW_US));

  // Healthy passes every 16 ms with the frame arriving throughout: the forced send
  // still lands in the window.
  Rig h;
  const uint64_t h_at = setup(h);
  h.io.receiving_answers = 100;
  h.run_until(h_at + TX_WINDOW_US);
  CHECK(h.io.transmits.size() == 1);
  CHECK(h.io.transmits[0].at >= h_at && h.io.transmits[0].at <= h_at + TX_WINDOW_US);

  // A loop interval that leaves no room for another pass in the window: no hold.
  Rig l;
  const uint64_t l_at = setup(l);
  l.io.loop_interval = TX_WINDOW_US - RX_HOLD_SLACK_US + 1;
  l.io.receiving_answers = 100;
  l.io.t = l_at;
  l.loop();
  CHECK(l.io.transmits.size() == 1 && l.io.transmits[0].at == l_at);

  // Held, then the loop stalls past the window: BUSY, as for a refusing radio.
  Rig s;
  const uint64_t s_at = setup(s);
  s.io.receiving_answers = 1;
  s.io.t = s_at;
  s.loop();
  s.io.t = s_at + TX_WINDOW_US + 1;
  s.loop();
  out = s.take(MSG_TX_RESULT);
  CHECK(out.size() == 1 && tx_res(out[0]).result == TX_BUSY);
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
  // The radio had the frame and may have sent it: the airtime is spent (06 section 8.2).
  CHECK(r.engine->airtime_used_us() == air);
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
  CHECK(q.engine->airtime_used_us() == 0);  // never accepted, so nothing went on air
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
  r.run_until(r.io.t + 1000000);
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

static void test_engine_counters_offline() {
  // Counter sensors keep updating while the server is unreachable (06 section 10.1).
  Rig r;
  r.io.server = false;
  const uint64_t t0 = r.io.t;
  r.loop();
  CHECK(r.io.counter_publishes.size() == 1);  // at the first pass
  r.hear(frame("heartbeat"));
  r.run_until(t0 + 35 * 1000000ULL);
  CHECK(r.take().empty());  // no HELLO, nothing forwarded
  CHECK(r.io.hello_gaps.empty());
  CHECK(r.io.counter_publishes.size() == 4);  // 0, 10, 20 and 30 s
  for (size_t i = 1; i < r.io.counter_publishes.size(); i++) {
    uint64_t d = r.io.counter_publishes[i] - r.io.counter_publishes[i - 1];
    CHECK(d >= COUNTERS_PUBLISH_INTERVAL_US && d < COUNTERS_PUBLISH_INTERVAL_US + r.io.loop_interval);
  }
  CHECK(r.engine->counters().heard == 1 && r.engine->counters().forwarded == 0);

  // The cadence does not follow HELLO once the server is known.
  r.io.server = true;
  r.run_until(t0 + 41 * 1000000ULL);
  CHECK(r.io.hello_gaps.size() == 1);
  CHECK(r.io.counter_publishes.size() == 5);
}

int main() {
  test_sha256();
  test_frames();
  test_envelope();
  test_seq_guard();
  test_hello_echoes();
  test_dedupe();
  test_dedupe_reinsert();
  test_dedupe_lets_retries_through();
  test_rate_limits();
  test_rate_limit_eviction();
  test_receive_pipeline();
  test_airtime();
  test_budget();
  test_budget_rollover();
  test_scheduler();
  test_scheduler_slots_full();
  test_eui64();
  test_engine_forwarding();
  test_engine_dedupe_and_offline();
  test_engine_counters_offline();
  test_engine_ts_uncertain();
  test_timing_budget();
  test_engine_hello_and_capability();
  test_engine_capability_hello_rate();
  test_engine_connection();
  test_engine_rediscover_never_connected();
  test_engine_envelope_checks();
  test_engine_server_restart();
  test_engine_hello_request();
  test_engine_rx1_offset();
  test_engine_duty_cycle();
  test_engine_busy_retry();
  test_engine_rx_hold();
  test_engine_in_flight_and_errors();
  std::printf("%d checks, %d failures\n", checks, failures);
  return failures == 0 ? 0 : 1;
}
