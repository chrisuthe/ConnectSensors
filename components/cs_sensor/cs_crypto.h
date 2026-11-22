#pragma once

// AES-128 (FIPS 197), AES-128-CCM (NIST SP 800-38C, RFC 3610) and HKDF-SHA256
// (RFC 5869), as spec 00 section 4 uses them.
//
// Provenance: written for this repository, with no third-party code, under the
// repository's licence. No platform crypto APIs, so ESP32 and nRF52 run the same
// code. The AES S-box lookups are indexed by secret bytes: a timing channel where
// the table sits behind a cache (ESP32 flash), but one that needs an attacker
// timing code on the device itself, not over the radio.

#include <cstddef>
#include <cstdint>

namespace esphome::cs_sensor {

class Aes128 {
 public:
  explicit Aes128(const uint8_t key[16]);
  ~Aes128();
  void encrypt_block(const uint8_t in[16], uint8_t out[16]) const;

 private:
  uint8_t rk_[176];
};

constexpr size_t CCM_NONCE_LEN = 13;
constexpr size_t CCM_TAG_LEN = 8;

// out receives ciphertext | tag (len + 8 bytes). aad_len must be below 0xFF00.
void ccm_seal(const uint8_t key[16], const uint8_t nonce[CCM_NONCE_LEN], const uint8_t *aad, size_t aad_len,
              const uint8_t *plaintext, size_t len, uint8_t *out);
// in is ciphertext | tag; len counts the ciphertext only. On success writes len
// bytes of plaintext. On a bad tag returns false and leaves out zeroed.
bool ccm_open(const uint8_t key[16], const uint8_t nonce[CCM_NONCE_LEN], const uint8_t *aad, size_t aad_len,
              const uint8_t *in, size_t len, uint8_t *out);

// salt == nullptr means the RFC's default salt. out_len <= 64; info_len <= 128.
bool hkdf_sha256(const uint8_t *ikm, size_t ikm_len, const uint8_t *salt, size_t salt_len, const uint8_t *info,
                 size_t info_len, uint8_t *out, size_t out_len);

// Overwrite secrets in a way the optimizer keeps.
void secure_zero(void *p, size_t len);

}  // namespace esphome::cs_sensor
