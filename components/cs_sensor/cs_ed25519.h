#pragma once

// Ed25519 public-key generation (RFC 8032 section 5.1.5), for key-fingerprint
// tags (spec 02 section 6). The sensor never signs, so only key generation is here.
//
// Provenance: crypto_sign_keypair's point arithmetic from TweetNaCl (public
// domain, https://tweetnacl.cr.yp.to), on the field code in cs_fe25519.h.
// Constant time: no branches or indices on secrets.

#include <cstdint>

namespace esphome::cs_sensor {

// pub = the Ed25519 public key for the 32-byte private key (seed).
void cs_ed25519_public_key(const uint8_t seed[32], uint8_t pub[32]);

}  // namespace esphome::cs_sensor
