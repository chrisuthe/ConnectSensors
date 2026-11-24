#include "cs_fe25519.h"

#include "cs_crypto.h"

namespace esphome::cs_sensor::fe25519 {

namespace {

constexpr int width(int i) { return (i & 1) ? 25 : 26; }

// Moves limb i's excess, rounded to nearest, into the next limb; limb 9 wraps to
// limb 0 times 19, since 2^255 = 19 mod p. Multiplies stand in for left shifts of
// negative values, which are undefined before C++20.
inline void carry(int64_t h[10], int i) {
  const int w = width(i);
  int64_t c = (h[i] + (int64_t(1) << (w - 1))) >> w;
  h[i] -= c * (int64_t(1) << w);
  if (i == 9) {
    h[0] += c * 19;
  } else {
    h[i + 1] += c;
  }
}

// ref10's order: two interleaved chains, so each limb is carried after it last grows.
void reduce(fe out, int64_t h[10]) {
  static const uint8_t ORDER[12] = {0, 4, 1, 5, 2, 6, 3, 7, 4, 8, 9, 0};
  for (uint8_t i : ORDER)
    carry(h, i);
  for (int i = 0; i < 10; i++)
    out[i] = int32_t(h[i]);
}

// Limb i sits at bit ceil(25.5 i), so the product of limbs i and j sits at
// bit ceil(25.5 (i + j)) + 1 when both are odd; and limb i + j >= 10 wraps
// to limb i + j - 10 times 19, as in carry().
void square(fe out, const fe f, bool twice) {
  int32_t f19[10];
  for (int i = 0; i < 10; i++)
    f19[i] = 19 * f[i];
  int64_t h[10] = {0};
  for (int i = 0; i < 10; i++) {
    // f[i] f[j] and f[j] f[i] both, for j > i; doubled again when both are odd.
    const int32_t f_even = 2 * f[i], f_odd = (i & 1) ? 4 * f[i] : 2 * f[i];
    h[(2 * i) % 10] += int64_t((i & 1) ? 2 * f[i] : f[i]) * (2 * i >= 10 ? f19[i] : f[i]);
    for (int j = i + 1; j < 10 - i; j++)
      h[i + j] += int64_t((j & 1) ? f_odd : f_even) * f[j];
    for (int j = (10 - i > i + 1 ? 10 - i : i + 1); j < 10; j++)
      h[i + j - 10] += int64_t((j & 1) ? f_odd : f_even) * f19[j];
  }
  if (twice) {
    for (auto &v : h)
      v *= 2;
  }
  reduce(out, h);
}

}  // namespace

void mul(fe out, const fe f, const fe g) {
  int32_t g19[10];
  for (int i = 0; i < 10; i++)
    g19[i] = 19 * g[i];
  int64_t h[10] = {0};
  for (int i = 0; i < 10; i++) {
    // Odd j takes f[i] doubled when i is odd too.
    const int32_t f_even = f[i], f_odd = (i & 1) ? 2 * f[i] : f[i];
    for (int j = 0; j < 10 - i; j++)
      h[i + j] += int64_t((j & 1) ? f_odd : f_even) * g[j];
    for (int j = 10 - i; j < 10; j++)
      h[i + j - 10] += int64_t((j & 1) ? f_odd : f_even) * g19[j];
  }
  reduce(out, h);
}

void sq(fe out, const fe f) { square(out, f, false); }

void sq2(fe out, const fe f) { square(out, f, true); }

void mul_small(fe out, const fe f, int32_t n) {
  int64_t h[10];
  for (int i = 0; i < 10; i++)
    h[i] = int64_t(f[i]) * n;
  reduce(out, h);
}

void frombytes(fe h, const uint8_t s[32]) {
  int pos = 0;
  for (int i = 0; i < 10; i++) {
    // Up to 26 bits from a shift of up to 7 always fit in the 4 bytes read.
    int b = pos >> 3;
    uint32_t v = 0;
    for (int k = 0; k < 4 && b + k < 32; k++)
      v |= uint32_t(s[b + k]) << (8 * k);
    h[i] = int32_t((v >> (pos & 7)) & ((uint32_t(1) << width(i)) - 1));
    pos += width(i);
  }
}

void tobytes(uint8_t s[32], const fe f) {
  int64_t h[10];
  for (int i = 0; i < 10; i++)
    h[i] = f[i];
  // ref10: q is 1 if h >= p and 0 otherwise, for a carried h; h + 19q then drops
  // 2^255 to give h - pq, in [0, p).
  int64_t q = (19 * h[9] + (int64_t(1) << 24)) >> 25;
  for (int i = 0; i < 10; i++)
    q = (h[i] + q) >> width(i);
  h[0] += 19 * q;
  for (int i = 0; i < 9; i++) {
    int64_t c = h[i] >> width(i);
    h[i + 1] += c;
    h[i] -= c * (int64_t(1) << width(i));
  }
  h[9] &= (int64_t(1) << 25) - 1;
  uint64_t acc = 0;
  int bits = 0, o = 0;
  for (int i = 0; i < 10; i++) {
    acc |= uint64_t(h[i]) << bits;
    bits += width(i);
    while (bits >= 8) {
      s[o++] = uint8_t(acc);
      acc >>= 8;
      bits -= 8;
    }
  }
  s[o] = uint8_t(acc);  // the last 7 bits; bit 255 is 0
}

uint32_t isnegative(const fe f) {
  uint8_t s[32];
  tobytes(s, f);
  return s[0] & 1;
}

// ---- inversion

namespace {

constexpr uint8_t NONE = 0xFF;

// dst = src^(2^nsq) * mul.
struct Op {
  uint8_t dst, src, nsq, mul;
};

// ref10's chain for z^(2^255 - 21), registers z, t0, t1, t2.
constexpr Op CHAIN[12] = {
    {1, 0, 1, NONE},  // t0 = z^2
    {2, 1, 2, 0},     // t1 = z^9
    {1, 1, 0, 2},     // t0 = z^11
    {2, 1, 1, 2},     // t1 = z^(2^5 - 1)
    {2, 2, 5, 2},     // t1 = z^(2^10 - 1)
    {3, 2, 10, 2},    // t2 = z^(2^20 - 1)
    {3, 3, 20, 3},    // t2 = z^(2^40 - 1)
    {2, 3, 10, 2},    // t1 = z^(2^50 - 1)
    {3, 2, 50, 2},    // t2 = z^(2^100 - 1)
    {3, 3, 100, 3},   // t2 = z^(2^200 - 1)
    {2, 3, 50, 2},    // t1 = z^(2^250 - 1)
    {2, 2, 5, 1},     // t1 = z^(2^255 - 21) = z^(p - 2)
};

}  // namespace

void Inverter::start(const fe z) {
  copy(this->r_[R_Z], z);
  this->op_ = 0;
  this->loaded_ = false;
}

bool Inverter::step(int max_squarings) {
  if (this->done())
    return true;
  const Op &o = CHAIN[this->op_];
  if (!this->loaded_) {
    copy(this->acc_, this->r_[o.src]);
    this->left_ = o.nsq;
    this->loaded_ = true;
  }
  if (this->left_ > 0) {
    int n = this->left_ < max_squarings ? this->left_ : max_squarings;
    for (int i = 0; i < n; i++)
      sq(this->acc_, this->acc_);
    this->left_ = uint8_t(this->left_ - n);
    if (this->left_ > 0 || o.mul != NONE)
      return false;
  }
  if (o.mul != NONE) {
    mul(this->r_[o.dst], this->acc_, this->r_[o.mul]);
  } else {
    copy(this->r_[o.dst], this->acc_);
  }
  this->loaded_ = false;
  this->op_++;
  return this->done();
}

void Inverter::wipe() {
  secure_zero(this->r_, sizeof(this->r_));
  secure_zero(this->acc_, sizeof(this->acc_));
  this->op_ = OPS;
  this->loaded_ = false;
}

void invert(fe out, const fe z) {
  Inverter inv;
  inv.start(z);
  while (!inv.step(255)) {
  }
  copy(out, inv.result());
  inv.wipe();
}

}  // namespace esphome::cs_sensor::fe25519
