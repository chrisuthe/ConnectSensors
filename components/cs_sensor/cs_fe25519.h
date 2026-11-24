#pragma once

// Arithmetic mod p = 2^255 - 19 shared by X25519 (cs_x25519.cpp) and Ed25519 key
// generation (cs_ed25519.cpp). Internal to the component.
//
// Provenance: the radix 2^25.5 representation and carry chains of ref10 (Bernstein,
// Duif, Lange, Schwabe, Yang; public domain, SUPERCOP crypto_sign/ed25519/ref10).
// Ten 32-bit limbs and 32x32->64 products suit 32-bit MCUs (ESP32, nRF52), where
// the 64x64 products of a 16-limb TweetNaCl field cost several multiplies each.
// Constant time: no branches or indices on secrets.
//
// Limb i holds bits from ceil(25.5 i): 26 bits for even i, 25 for odd. Products and
// squares come out carried (|limb| <= 2^25 even, 2^24 odd, roughly); add and sub do
// not carry, and as in ref10 a mul input may be the sum or difference of two
// carried values but no more.

#include <cstdint>

namespace esphome::cs_sensor::fe25519 {

using fe = int32_t[10];

inline void copy(fe h, const fe f) {
  for (int i = 0; i < 10; i++)
    h[i] = f[i];
}

inline void zero(fe h) {
  for (int i = 0; i < 10; i++)
    h[i] = 0;
}

inline void one(fe h) {
  zero(h);
  h[0] = 1;
}

inline void add(fe h, const fe f, const fe g) {
  for (int i = 0; i < 10; i++)
    h[i] = f[i] + g[i];
}

inline void sub(fe h, const fe f, const fe g) {
  for (int i = 0; i < 10; i++)
    h[i] = f[i] - g[i];
}

inline void neg(fe h, const fe f) {
  for (int i = 0; i < 10; i++)
    h[i] = -f[i];
}

// f = g if b is 1, unchanged if 0, without branching on b.
inline void cmov(fe f, const fe g, uint32_t b) {
  int32_t mask = -int32_t(b);
  for (int i = 0; i < 10; i++)
    f[i] ^= mask & (f[i] ^ g[i]);
}

// Swap f and g if b is 1, without branching on b.
inline void cswap(fe f, fe g, uint32_t b) {
  int32_t mask = -int32_t(b);
  for (int i = 0; i < 10; i++) {
    int32_t t = mask & (f[i] ^ g[i]);
    f[i] ^= t;
    g[i] ^= t;
  }
}

void mul(fe h, const fe f, const fe g);
void sq(fe h, const fe f);
void sq2(fe h, const fe f);  // 2 f^2
void mul_small(fe h, const fe f, int32_t n);  // n < 2^17
// Bit 255 is ignored, as RFC 7748 and RFC 8032 decoding both do.
void frombytes(fe h, const uint8_t s[32]);
// The canonical encoding, fully reduced mod p.
void tobytes(uint8_t s[32], const fe h);
// Bit 0 of the canonical encoding: the "sign" of RFC 8032.
uint32_t isnegative(const fe f);

// 1/z = z^(p-2), by ref10's addition chain (254 squarings, 11 multiplications), in
// steps so a key generation can be spread across loop passes. invert() runs it all.
class Inverter {
 public:
  void start(const fe z);
  // At most max_squarings squarings, or one multiplication. True once done.
  bool step(int max_squarings);
  bool done() const { return this->op_ >= OPS; }
  const int32_t *result() const { return this->r_[R_OUT]; }
  void wipe();

 private:
  static constexpr uint8_t OPS = 12;
  enum : uint8_t { R_Z, R_T0, R_T1, R_T2, R_OUT = R_T1 };
  fe r_[4];
  fe acc_;
  uint8_t op_{OPS};
  uint8_t left_{0};
  bool loaded_{false};
};

void invert(fe out, const fe z);

}  // namespace esphome::cs_sensor::fe25519
