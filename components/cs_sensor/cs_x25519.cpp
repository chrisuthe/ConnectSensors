#include "cs_x25519.h"

#include <cstring>

#include "cs_crypto.h"
#include "cs_ed25519.h"

namespace esphome::cs_sensor {

using namespace fe25519;

namespace {

// Squarings per inversion step: about as costly as a ladder rung.
constexpr int INVERT_SQUARINGS = 8;

}  // namespace

void X25519Job::start(const uint8_t scalar[32], const uint8_t point[32]) {
  this->clear();
  std::memcpy(this->scalar_, scalar, 32);
  this->scalar_[31] = uint8_t((this->scalar_[31] & 127) | 64);
  this->scalar_[0] &= 248;
  frombytes(this->x_, point);
  copy(this->b_, this->x_);
  one(this->a_);
  zero(this->c_);
  one(this->d_);
  this->bit_ = 254;
  this->stage_ = Stage::LADDER;
}

void X25519Job::clear() {
  secure_zero(this->scalar_, sizeof(this->scalar_));
  secure_zero(this->x_, sizeof(this->x_));
  secure_zero(this->a_, sizeof(this->a_));
  secure_zero(this->b_, sizeof(this->b_));
  secure_zero(this->c_, sizeof(this->c_));
  secure_zero(this->d_, sizeof(this->d_));
  secure_zero(this->out_, sizeof(this->out_));
  this->inv_.wipe();
  this->bit_ = 0;
  this->stage_ = Stage::IDLE;
}

bool X25519Job::step() {
  switch (this->stage_) {
    case Stage::IDLE:
      return false;
    case Stage::DONE:
      return true;
    case Stage::LADDER: {
      // One rung of the ladder of RFC 7748 section 5, a24 = 121665.
      fe &a = this->a_, &b = this->b_, &c = this->c_, &d = this->d_;
      fe e, f;
      const int i = this->bit_;
      uint32_t r = (this->scalar_[i >> 3] >> (i & 7)) & 1;
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
      mul(d, b, this->x_);
      sq(b, e);
      cswap(a, b, r);
      cswap(c, d, r);
      secure_zero(e, sizeof(e));
      secure_zero(f, sizeof(f));
      if (this->bit_-- == 0) {
        secure_zero(this->scalar_, sizeof(this->scalar_));
        this->inv_.start(c);
        this->stage_ = Stage::INVERT;
      }
      return false;
    }
    case Stage::INVERT:
      if (this->inv_.step(INVERT_SQUARINGS))
        this->stage_ = Stage::FINISH;
      return false;
    case Stage::FINISH: {
      fe u;
      mul(u, this->a_, this->inv_.result());
      tobytes(this->out_, u);
      secure_zero(u, sizeof(u));
      secure_zero(this->x_, sizeof(this->x_));
      secure_zero(this->a_, sizeof(this->a_));
      secure_zero(this->b_, sizeof(this->b_));
      secure_zero(this->c_, sizeof(this->c_));
      secure_zero(this->d_, sizeof(this->d_));
      this->inv_.wipe();
      this->stage_ = Stage::DONE;
      return true;
    }
  }
  return false;
}

void x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]) {
  X25519Job job;
  job.start(scalar, point);
  while (!job.step()) {
  }
  std::memcpy(out, job.result(), 32);
}

void x25519_base(uint8_t out[32], const uint8_t scalar[32]) {
  BaseMulJob job;
  job.start_x25519(scalar);
  while (!job.step()) {
  }
  std::memcpy(out, job.result(), 32);
}

}  // namespace esphome::cs_sensor
