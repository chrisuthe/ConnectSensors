#include "cs_ed25519.h"

#include "cs_crypto.h"
#include "cs_fe25519.h"
#include "cs_sha512.h"

namespace esphome::cs_sensor {

namespace {

using namespace fe25519;

// Extended twisted Edwards coordinates (X, Y, Z, T).
using point = gf[4];

const gf GF0 = {0};
const gf GF1 = {1};
const gf D2 = {0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0,
               0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406};
const gf BX = {0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c,
               0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169};
const gf BY = {0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
               0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666};

void set25519(gf r, const gf a) {
  for (int i = 0; i < 16; i++)
    r[i] = a[i];
}

int par25519(const gf a) {
  uint8_t d[32];
  pack25519(d, a);
  return d[0] & 1;
}

// p += q
void point_add(point p, point q) {
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

void cswap(point p, point q, int64_t b) {
  for (int i = 0; i < 4; i++)
    sel25519(p[i], q[i], b);
}

void pack_point(uint8_t r[32], point p) {
  gf tx, ty, zi;
  inv25519(zi, p[2]);
  mul(tx, p[0], zi);
  mul(ty, p[1], zi);
  pack25519(r, ty);
  r[31] ^= uint8_t(par25519(tx) << 7);
}

// p = s * B, by a constant-time double-and-add ladder over all 256 bits.
void scalarbase(point p, const uint8_t s[32]) {
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
  secure_zero(q, sizeof(q));
}

}  // namespace

void cs_ed25519_public_key(const uint8_t seed[32], uint8_t pub[32]) {
  uint8_t h[64];
  sha512(seed, 32, h);
  h[0] &= 248;
  h[31] &= 127;
  h[31] |= 64;
  point p;
  scalarbase(p, h);
  pack_point(pub, p);
  secure_zero(h, sizeof(h));
  secure_zero(p, sizeof(p));
}

}  // namespace esphome::cs_sensor
