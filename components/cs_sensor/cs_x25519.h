#pragma once

// X25519 (RFC 7748) for the pairing key exchange (spec 02 section 5.3).
//
// Provenance: crypto_scalarmult from TweetNaCl (Bernstein, van Gastel, Janssen,
// Lange, Schwabe, Smetsers; public domain, https://tweetnacl.cr.yp.to), adapted to
// C++ with left shifts of negative values replaced by multiplications so it is
// free of undefined behaviour. Constant time: no branches or indices on secrets.

#include <cstdint>

namespace esphome::cs_sensor {

// out = X25519(scalar, point). The scalar is clamped inside, as RFC 7748 does.
void x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]);
// out = X25519(scalar, 9): the public key for a private key.
void x25519_base(uint8_t out[32], const uint8_t scalar[32]);

}  // namespace esphome::cs_sensor
