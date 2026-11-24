#include "cs_x25519.h"

#include <cstring>

#include "cs_crypto.h"
#include "cs_ed25519.h"
#include "cs_fe25519.h"

namespace esphome::cs_sensor {

using namespace fe25519;

// The Montgomery ladder of RFC 7748 section 5, a24 = 121665.
void x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]) {
  uint8_t z[32];
  fe x, a, b, c, d, e, f;
  std::memcpy(z, scalar, 32);
  z[31] = uint8_t((z[31] & 127) | 64);
  z[0] &= 248;
  frombytes(x, point);
  copy(b, x);
  one(a);
  zero(c);
  one(d);
  for (int i = 254; i >= 0; --i) {
    uint32_t r = (z[i >> 3] >> (i & 7)) & 1;
    cswap(a, b, r);
    cswap(c, d, r);
    add(e, a, c);
    sub(a, a, c);
    add(c, b, d);
    sub(b, b, d);
    sq(d, e);
    sq(f, a);
    mul(a, c, a);
    mul(c, b, e);
    add(e, a, c);
    sub(a, a, c);
    sq(b, a);
    sub(c, d, f);
    mul_small(a, c, 121665);
    add(a, a, d);
    mul(c, c, a);
    mul(a, d, f);
    mul(d, b, x);
    sq(b, e);
    cswap(a, b, r);
    cswap(c, d, r);
  }
  invert(c, c);
  mul(a, a, c);
  tobytes(out, a);
  secure_zero(z, sizeof(z));
  secure_zero(a, sizeof(a));
  secure_zero(b, sizeof(b));
  secure_zero(c, sizeof(c));
  secure_zero(d, sizeof(d));
  secure_zero(e, sizeof(e));
  secure_zero(f, sizeof(f));
}

void x25519_base(uint8_t out[32], const uint8_t scalar[32]) {
  BaseMulJob job;
  job.start_x25519(scalar);
  while (!job.step()) {
  }
  std::memcpy(out, job.result(), 32);
}

}  // namespace esphome::cs_sensor
