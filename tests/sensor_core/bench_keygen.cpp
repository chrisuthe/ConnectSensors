// Host micro-benchmark for #95: key generation old (TweetNaCl, ref_tweetnacl.h)
// against new (fixed-base comb on the radix 2^25.5 field). Built at -Os, as the
// firmware is, without sanitizers. Output only, not a pass/fail gate: host times
// do not carry over to an MCU, but the ratios and the step sizes are indicative.

#include <chrono>
#include <cstdio>

#include "cs_ed25519.h"
#include "cs_x25519.h"
#include "ref_tweetnacl.h"

using namespace esphome::cs_sensor;
using Clock = std::chrono::steady_clock;

template<typename F> static double us_per_call(F f) {
  for (int i = 0; i < 20; i++)
    f();
  const int n = 500;
  auto t0 = Clock::now();
  for (int i = 0; i < n; i++)
    f();
  return std::chrono::duration<double, std::micro>(Clock::now() - t0).count() / n;
}

int main() {
  uint8_t s[32], p[32], out[32];
  for (int i = 0; i < 32; i++) {
    s[i] = uint8_t(17 * i + 3);
    p[i] = uint8_t(29 * i + 11);
  }
  const uint8_t nine[32] = {9};
  struct {
    const char *name;
    double old_us, new_us;
  } rows[] = {
      {"Ed25519 key generation (tag)", us_per_call([&] { ref_tweetnacl::ed25519_public_key(s, out); }),
       us_per_call([&] { cs_ed25519_public_key(s, out); })},
      {"X25519 public key (JOIN)", us_per_call([&] { ref_tweetnacl::x25519(out, s, nine); }),
       us_per_call([&] { x25519_base(out, s); })},
      {"X25519 shared secret", us_per_call([&] { ref_tweetnacl::x25519(out, s, p); }),
       us_per_call([&] { x25519(out, s, p); })},
  };
  std::printf("keygen benchmark (host, -Os; not a gate)\n");
  for (const auto &r : rows)
    std::printf("  %-30s old %8.1f us  new %7.1f us  %5.1fx\n", r.name, r.old_us, r.new_us, r.old_us / r.new_us);

  // The sliced job: how many steps, and the longest, which bounds a slice's overrun.
  BaseMulJob job;
  job.start_ed25519(s);
  int steps = 0;
  double longest = 0;
  while (job.busy()) {
    auto t0 = Clock::now();
    job.step();
    double d = std::chrono::duration<double, std::micro>(Clock::now() - t0).count();
    longest = d > longest ? d : longest;
    steps++;
  }
  std::printf("  sliced Ed25519 job: %d steps, longest %.1f us\n", steps, longest);
  return 0;
}
