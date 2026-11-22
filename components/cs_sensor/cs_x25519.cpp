#include "cs_x25519.h"

#include "cs_crypto.h"

namespace esphome::cs_sensor {

namespace {

// Field elements mod 2^255 - 19 as 16 limbs of 16 bits, with headroom for carries.
using gf = int64_t[16];

const gf GF_121665 = {0xDB41, 1};

void car25519(gf o) {
  for (int i = 0; i < 16; i++) {
    o[i] += int64_t(1) << 16;
    int64_t c = o[i] >> 16;
    o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
    o[i] -= c * 65536;
  }
}

// Swap p and q when b is 1, without branching on b.
void sel25519(gf p, gf q, int64_t b) {
  int64_t c = ~(b - 1);
  for (int i = 0; i < 16; i++) {
    int64_t t = c & (p[i] ^ q[i]);
    p[i] ^= t;
    q[i] ^= t;
  }
}

void pack25519(uint8_t *o, const gf n) {
  gf m, t;
  for (int i = 0; i < 16; i++)
    t[i] = n[i];
  car25519(t);
  car25519(t);
  car25519(t);
  for (int j = 0; j < 2; j++) {
    m[0] = t[0] - 0xffed;
    for (int i = 1; i < 15; i++) {
      m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
      m[i - 1] &= 0xffff;
    }
    m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
    int64_t b = (m[15] >> 16) & 1;
    m[14] &= 0xffff;
    sel25519(t, m, 1 - b);
  }
  for (int i = 0; i < 16; i++) {
    o[2 * i] = uint8_t(t[i] & 0xff);
    o[2 * i + 1] = uint8_t(t[i] >> 8);
  }
}

void unpack25519(gf o, const uint8_t *n) {
  for (int i = 0; i < 16; i++)
    o[i] = n[2 * i] + (int64_t(n[2 * i + 1]) << 8);
  o[15] &= 0x7fff;
}

void add(gf o, const gf a, const gf b) {
  for (int i = 0; i < 16; i++)
    o[i] = a[i] + b[i];
}

void sub(gf o, const gf a, const gf b) {
  for (int i = 0; i < 16; i++)
    o[i] = a[i] - b[i];
}

void mul(gf o, const gf a, const gf b) {
  int64_t t[31] = {0};
  for (int i = 0; i < 16; i++) {
    for (int j = 0; j < 16; j++)
      t[i + j] += a[i] * b[j];
  }
  for (int i = 0; i < 15; i++)
    t[i] += 38 * t[i + 16];
  for (int i = 0; i < 16; i++)
    o[i] = t[i];
  car25519(o);
  car25519(o);
}

void sqr(gf o, const gf a) { mul(o, a, a); }

void inv25519(gf o, const gf in) {
  gf c;
  for (int a = 0; a < 16; a++)
    c[a] = in[a];
  for (int a = 253; a >= 0; a--) {
    sqr(c, c);
    if (a != 2 && a != 4)
      mul(c, c, in);
  }
  for (int a = 0; a < 16; a++)
    o[a] = c[a];
}

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
