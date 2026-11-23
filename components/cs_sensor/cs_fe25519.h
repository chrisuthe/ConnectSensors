#pragma once

// Arithmetic mod 2^255 - 19 shared by X25519 (cs_x25519.cpp) and Ed25519 key
// generation (cs_ed25519.cpp). Internal to the component.
//
// Provenance: TweetNaCl (public domain, https://tweetnacl.cr.yp.to), adapted to
// C++ with left shifts of negative values replaced by multiplications so it is
// free of undefined behaviour. Constant time: no branches or indices on secrets.

#include <cstdint>

namespace esphome::cs_sensor::fe25519 {

// Field elements mod 2^255 - 19 as 16 limbs of 16 bits, with headroom for carries.
using gf = int64_t[16];

inline void car25519(gf o) {
  for (int i = 0; i < 16; i++) {
    o[i] += int64_t(1) << 16;
    int64_t c = o[i] >> 16;
    o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
    o[i] -= c * 65536;
  }
}

// Swap p and q when b is 1, without branching on b.
inline void sel25519(gf p, gf q, int64_t b) {
  int64_t c = ~(b - 1);
  for (int i = 0; i < 16; i++) {
    int64_t t = c & (p[i] ^ q[i]);
    p[i] ^= t;
    q[i] ^= t;
  }
}

inline void pack25519(uint8_t *o, const gf n) {
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

inline void unpack25519(gf o, const uint8_t *n) {
  for (int i = 0; i < 16; i++)
    o[i] = n[2 * i] + (int64_t(n[2 * i + 1]) << 8);
  o[15] &= 0x7fff;
}

inline void add(gf o, const gf a, const gf b) {
  for (int i = 0; i < 16; i++)
    o[i] = a[i] + b[i];
}

inline void sub(gf o, const gf a, const gf b) {
  for (int i = 0; i < 16; i++)
    o[i] = a[i] - b[i];
}

inline void mul(gf o, const gf a, const gf b) {
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

inline void sqr(gf o, const gf a) { mul(o, a, a); }

inline void inv25519(gf o, const gf in) {
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

}  // namespace esphome::cs_sensor::fe25519
