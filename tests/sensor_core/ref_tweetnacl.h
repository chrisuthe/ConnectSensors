#pragma once

// Test-only reference: the TweetNaCl-style Ed25519 key generation and X25519 that
// the sensor used before the fixed-base comb (#95), unchanged but for namespaces.
// The tests check the new code against it on random inputs and time old against new.
//
// Provenance: TweetNaCl (public domain, https://tweetnacl.cr.yp.to).

#include <cstdint>
#include <cstring>

#include "cs_sha512.h"

namespace ref_tweetnacl {
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


namespace ed {
// Extended twisted Edwards coordinates (X, Y, Z, T).
using point = gf[4];

inline const gf GF0 = {0};
inline const gf GF1 = {1};
inline const gf D2 = {0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0,
               0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406};
inline const gf BX = {0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c,
               0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169};
inline const gf BY = {0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
               0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666};

inline void set25519(gf r, const gf a) {
  for (int i = 0; i < 16; i++)
    r[i] = a[i];
}

inline int par25519(const gf a) {
  uint8_t d[32];
  pack25519(d, a);
  return d[0] & 1;
}

// p += q
inline void point_add(point p, point q) {
  gf a, b, c, d, t, e, f, g, h;
  sub(a, p[1], p[0]);
  sub(t, q[1], q[0]);
  mul(a, a, t);
  add(b, p[0], p[1]);
  add(t, q[0], q[1]);
  mul(b, b, t);
  mul(c, p[3], q[3]);
  mul(c, c, D2);
  mul(d, p[2], q[2]);
  add(d, d, d);
  sub(e, b, a);
  sub(f, d, c);
  add(g, d, c);
  add(h, b, a);
  mul(p[0], e, f);
  mul(p[1], h, g);
  mul(p[2], g, f);
  mul(p[3], e, h);
}

inline void cswap(point p, point q, int64_t b) {
  for (int i = 0; i < 4; i++)
    sel25519(p[i], q[i], b);
}

inline void pack_point(uint8_t r[32], point p) {
  gf tx, ty, zi;
  inv25519(zi, p[2]);
  mul(tx, p[0], zi);
  mul(ty, p[1], zi);
  pack25519(r, ty);
  r[31] ^= uint8_t(par25519(tx) << 7);
}

// p = s * B, by a constant-time double-and-add ladder over all 256 bits.
inline void scalarbase(point p, const uint8_t s[32]) {
  point q;
  set25519(q[0], BX);
  set25519(q[1], BY);
  set25519(q[2], GF1);
  mul(q[3], BX, BY);
  set25519(p[0], GF0);
  set25519(p[1], GF1);
  set25519(p[2], GF1);
  set25519(p[3], GF0);
  for (int i = 255; i >= 0; --i) {
    int64_t b = (s[i / 8] >> (i & 7)) & 1;
    cswap(p, q, b);
    point_add(q, p);
    point_add(p, p);
    cswap(p, q, b);
  }

}

}  // namespace ed

inline void ed25519_public_key(const uint8_t seed[32], uint8_t pub[32]) {
  uint8_t h[64];
  esphome::cs_sensor::sha512(seed, 32, h);
  h[0] &= 248;
  h[31] &= 127;
  h[31] |= 64;
  ed::point p;
  ed::scalarbase(p, h);
  ed::pack_point(pub, p);
}

inline void x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]) {
  static const gf GF_121665 = {0xDB41, 1};
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
}

}  // namespace ref_tweetnacl
