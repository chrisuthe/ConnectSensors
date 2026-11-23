#include "cs_x25519.h"

#include "cs_crypto.h"
#include "cs_fe25519.h"

namespace esphome::cs_sensor {

namespace {

using namespace fe25519;

const gf GF_121665 = {0xDB41, 1};

}  // namespace

void x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]) {
  uint8_t z[32];
  gf x, a, b, c, d, e, f;
  for (int i = 0; i < 31; i++)
    z[i] = scalar[i];
  z[31] = uint8_t((scalar[31] & 127) | 64);
  z[0] &= 248;
  unpack25519(x, point);
  for (int i = 0; i < 16; i++) {
    b[i] = x[i];
    d[i] = a[i] = c[i] = 0;
  }
  a[0] = d[0] = 1;
  for (int i = 254; i >= 0; --i) {
    int64_t r = (z[i >> 3] >> (i & 7)) & 1;
    sel25519(a, b, r);
    sel25519(c, d, r);
    add(e, a, c);
    sub(a, a, c);
    add(c, b, d);
    sub(b, b, d);
    sqr(d, e);
    sqr(f, a);
    mul(a, c, a);
    mul(c, b, e);
    add(e, a, c);
    sub(a, a, c);
    sqr(b, a);
    sub(c, d, f);
    mul(a, c, GF_121665);
    add(a, a, d);
    mul(c, c, a);
    mul(a, d, f);
    mul(d, b, x);
    sqr(b, e);
    sel25519(a, b, r);
    sel25519(c, d, r);
  }
  inv25519(c, c);
  mul(a, a, c);
  pack25519(out, a);
  secure_zero(z, sizeof(z));
  secure_zero(a, sizeof(a));
  secure_zero(b, sizeof(b));
  secure_zero(c, sizeof(c));
  secure_zero(d, sizeof(d));
  secure_zero(e, sizeof(e));
  secure_zero(f, sizeof(f));
}

void x25519_base(uint8_t out[32], const uint8_t scalar[32]) {
  static const uint8_t BASE[32] = {9};
  x25519(out, scalar, BASE);
}

}  // namespace esphome::cs_sensor
