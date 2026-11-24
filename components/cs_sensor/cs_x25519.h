#pragma once

// X25519 (RFC 7748) for the pairing key exchange (spec 02 section 5.3).
//
// Provenance: the Montgomery ladder of crypto_scalarmult from TweetNaCl (Bernstein,
// van Gastel, Janssen, Lange, Schwabe, Smetsers; public domain,
// https://tweetnacl.cr.yp.to), on the field code in cs_fe25519.h. Constant time: no
// branches or indices on secrets.

#include <cstdint>

#include "cs_fe25519.h"

namespace esphome::cs_sensor {

// out = X25519(scalar, point). The scalar is clamped inside, as RFC 7748 does.
void x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]);
// out = X25519(scalar, 9): the public key for a private key.
void x25519_base(uint8_t out[32], const uint8_t scalar[32]);

// X25519(scalar, point) in bounded steps, so the KEY_EXCHANGE shared secret can be
// spread across loop passes. A step is one ladder rung or one inversion step, about
// ten field multiplications at most. The sequence of steps is the same for every
// scalar and point, so where the caller splits it reveals nothing.
class X25519Job {
 public:
  ~X25519Job() { this->clear(); }
  void start(const uint8_t scalar[32], const uint8_t point[32]);
  // Runs one step; true once result() holds the shared value.
  bool step();
  bool busy() const { return this->stage_ != Stage::IDLE && this->stage_ != Stage::DONE; }
  bool done() const { return this->stage_ == Stage::DONE; }
  const uint8_t *result() const { return this->out_; }
  // Wipes the scalar, the ladder and the result, and goes idle.
  void clear();

 private:
  enum class Stage : uint8_t { IDLE, LADDER, INVERT, FINISH, DONE };

  Stage stage_{Stage::IDLE};
  int16_t bit_{0};       // next ladder bit, counting down from 254
  uint8_t scalar_[32]{};  // clamped
  fe25519::fe x_{}, a_{}, b_{}, c_{}, d_{};
  fe25519::Inverter inv_{};
  uint8_t out_[32]{};
};

}  // namespace esphome::cs_sensor
