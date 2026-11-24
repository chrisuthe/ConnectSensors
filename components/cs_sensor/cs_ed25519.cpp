#include "cs_ed25519.h"

#include <cstring>

#include "cs_crypto.h"
#include "cs_ed25519_table.h"
#include "cs_sha512.h"

namespace esphome::cs_sensor {

namespace {

using namespace fe25519;
using P3 = BaseMulJob::P3;
using ed25519_table::COMB;
using ed25519_table::STRIDE;
using ed25519_table::TABLES;

// A sum or a doubling before its last four multiplications: x = X/Z, y = Y/T.
struct P1P1 {
  fe X, Y, Z, T;
};

// An affine point ready for mixed addition.
struct Precomp {
  fe yplusx, yminusx, xy2d;
};

// Squarings per inversion step: about as costly as a comb step.
constexpr int INVERT_SQUARINGS = 8;

void p1p1_to_p3(P3 &r, const P1P1 &p) {
  mul(r.X, p.X, p.T);
  mul(r.Y, p.Y, p.Z);
  mul(r.Z, p.Z, p.T);
  mul(r.T, p.X, p.Y);
}

// r = 2p, from X, Y, Z alone (ref10 ge_p2_dbl).
void dbl(P1P1 &r, const P3 &p) {
  fe t0;
  sq(r.X, p.X);
  sq(r.Z, p.Y);
  sq2(r.T, p.Z);
  add(r.Y, p.X, p.Y);
  sq(t0, r.Y);
  add(r.Y, r.Z, r.X);
  sub(r.Z, r.Z, r.X);
  sub(r.X, t0, r.Y);
  sub(r.T, r.T, r.Z);
}

// r = p + q (ref10 ge_madd).
void madd(P1P1 &r, const P3 &p, const Precomp &q) {
  fe t0;
  add(r.X, p.Y, p.X);
  sub(r.Y, p.Y, p.X);
  mul(r.Z, r.X, q.yplusx);
  mul(r.Y, r.Y, q.yminusx);
  mul(r.T, q.xy2d, p.T);
  add(t0, p.Z, p.Z);
  sub(r.X, r.Z, r.Y);
  add(r.Y, r.Z, r.Y);
  add(r.Z, t0, r.T);
  sub(r.T, t0, r.T);
}

// 1 if b == c, else 0, for b and c in [0, 15], without branching.
uint32_t equal(uint32_t b, uint32_t c) { return ((b ^ c) - 1) >> 31; }

// 1 if b < 0, without branching.
uint32_t negative(int8_t b) { return uint32_t(uint64_t(int64_t(b)) >> 63); }

void words_to_fe(fe h, const uint32_t w[8]) {
  uint8_t s[32];
  for (int i = 0; i < 8; i++) {
    s[4 * i] = uint8_t(w[i]);
    s[4 * i + 1] = uint8_t(w[i] >> 8);
    s[4 * i + 2] = uint8_t(w[i] >> 16);
    s[4 * i + 3] = uint8_t(w[i] >> 24);
  }
  frombytes(h, s);
}

// t = b * (table k's point), for a secret digit b in [-8, 8]: every entry is read,
// and the one wanted is kept by masks, not by its index.
void select(Precomp &t, int k, int8_t b) {
  uint32_t bneg = negative(b);
  uint32_t babs = uint32_t(b) - ((uint32_t(0) - bneg) & uint32_t(b)) * 2;
  uint32_t w[24] = {1, 0, 0, 0, 0, 0, 0, 0, 1};  // the neutral point: (1, 1, 0)
  for (uint32_t j = 0; j < 8; j++) {
    uint32_t mask = uint32_t(0) - equal(babs & 0xFF, j + 1);
    for (int i = 0; i < 24; i++)
      w[i] ^= mask & (w[i] ^ COMB[k][j][i]);
  }
  words_to_fe(t.yplusx, w);
  words_to_fe(t.yminusx, w + 8);
  words_to_fe(t.xy2d, w + 16);
  // -(x, y) = (-x, y): swap y + x with y - x and negate 2dxy.
  Precomp minus;
  copy(minus.yplusx, t.yminusx);
  copy(minus.yminusx, t.yplusx);
  neg(minus.xy2d, t.xy2d);
  cmov(t.yplusx, minus.yplusx, bneg);
  cmov(t.yminusx, minus.yminusx, bneg);
  cmov(t.xy2d, minus.xy2d, bneg);
  secure_zero(w, sizeof(w));
  secure_zero(&minus, sizeof(minus));
}

}  // namespace

void BaseMulJob::start_ed25519(const uint8_t seed[32]) {
  this->clear();
  std::memcpy(this->scalar_, seed, 32);
  this->x25519_ = false;
  this->stage_ = Stage::PREPARE;
}

void BaseMulJob::start_x25519(const uint8_t scalar[32]) {
  this->clear();
  std::memcpy(this->scalar_, scalar, 32);
  this->x25519_ = true;
  this->stage_ = Stage::PREPARE;
}

void BaseMulJob::clear() {
  secure_zero(this->scalar_, sizeof(this->scalar_));
  secure_zero(this->e_, sizeof(this->e_));
  secure_zero(&this->h_, sizeof(this->h_));
  secure_zero(this->out_, sizeof(this->out_));
  this->inv_.wipe();
  this->stage_ = Stage::IDLE;
}

void BaseMulJob::prepare_() {
  if (!this->x25519_) {
    // RFC 8032 section 5.1.5: the scalar is the clamped first half of SHA-512(seed).
    uint8_t h[64];
    sha512(this->scalar_, 32, h);
    std::memcpy(this->scalar_, h, 32);
    secure_zero(h, sizeof(h));
  }
  // The same clamp for both (RFC 8032 section 5.1.5, RFC 7748 section 5). Bit 255
  // clear keeps the top digit in range below.
  this->scalar_[0] &= 248;
  this->scalar_[31] &= 127;
  this->scalar_[31] |= 64;
  // Signed radix 16: scalar = sum of e[i] 16^i with e[i] in [-8, 8).
  for (int i = 0; i < 32; i++) {
    this->e_[2 * i] = int8_t(this->scalar_[i] & 15);
    this->e_[2 * i + 1] = int8_t(this->scalar_[i] >> 4);
  }
  int8_t carry = 0;
  for (int i = 0; i < 63; i++) {
    this->e_[i] = int8_t(this->e_[i] + carry);
    carry = int8_t((this->e_[i] + 8) >> 4);
    this->e_[i] = int8_t(this->e_[i] - carry * 16);
  }
  this->e_[63] = int8_t(this->e_[63] + carry);
  secure_zero(this->scalar_, sizeof(this->scalar_));
  // h = 0, the neutral point.
  zero(this->h_.X);
  one(this->h_.Y);
  one(this->h_.Z);
  zero(this->h_.T);
  this->sweep_ = STRIDE - 1;
  this->table_ = 0;
  this->doublings_ = 0;
}

// scalar * B = sum over passes r of 16^r * sum over tables k of e[STRIDE k + r] * T_k,
// with T_k = 16^(STRIDE k) * B: Horner's rule in r, four doublings between passes.
bool BaseMulJob::step() {
  switch (this->stage_) {
    case Stage::IDLE:
      return false;
    case Stage::DONE:
      return true;
    case Stage::PREPARE:
      this->prepare_();
      this->stage_ = Stage::COMB;
      return false;
    case Stage::COMB: {
      P1P1 r;
      if (this->doublings_ > 0) {
        dbl(r, this->h_);
        this->doublings_--;
      } else {
        Precomp t;
        select(t, this->table_, this->e_[STRIDE * this->table_ + this->sweep_]);
        madd(r, this->h_, t);
        secure_zero(&t, sizeof(t));
        if (++this->table_ == TABLES) {
          this->table_ = 0;
          if (this->sweep_ == 0) {
            this->stage_ = Stage::INVERT;
          } else {
            this->sweep_--;
            this->doublings_ = 4;
          }
        }
      }
      p1p1_to_p3(this->h_, r);
      secure_zero(&r, sizeof(r));
      if (this->stage_ == Stage::INVERT) {
        secure_zero(this->e_, sizeof(this->e_));
        if (this->x25519_) {
          fe d;
          sub(d, this->h_.Z, this->h_.Y);
          this->inv_.start(d);
          secure_zero(d, sizeof(d));
        } else {
          this->inv_.start(this->h_.Z);
        }
      }
      return false;
    }
    case Stage::INVERT:
      if (this->inv_.step(INVERT_SQUARINGS))
        this->stage_ = Stage::FINISH;
      return false;
    case Stage::FINISH: {
      const int32_t *zi = this->inv_.result();
      if (this->x25519_) {
        // u = (Z + Y) / (Z - Y). Never 0/0: a clamped scalar is not a multiple of
        // the group order, so the point is not the neutral one (Y = Z).
        fe n, u;
        add(n, this->h_.Z, this->h_.Y);
        mul(u, n, zi);
        tobytes(this->out_, u);
        secure_zero(n, sizeof(n));
        secure_zero(u, sizeof(u));
      } else {
        fe x, y;
        mul(x, this->h_.X, zi);
        mul(y, this->h_.Y, zi);
        tobytes(this->out_, y);
        this->out_[31] ^= uint8_t(isnegative(x) << 7);
        secure_zero(x, sizeof(x));
        secure_zero(y, sizeof(y));
      }
      secure_zero(&this->h_, sizeof(this->h_));
      this->inv_.wipe();
      this->stage_ = Stage::DONE;
      return true;
    }
  }
  return false;
}

void cs_ed25519_public_key(const uint8_t seed[32], uint8_t pub[32]) {
  BaseMulJob job;
  job.start_ed25519(seed);
  while (!job.step()) {
  }
  std::memcpy(pub, job.result(), 32);
}

}  // namespace esphome::cs_sensor
