#pragma once

// Self-contained SHA-256 (FIPS 180-4) and HMAC-SHA256 (RFC 2104).
// No platform dependencies, so the proxy core builds and tests on any host.

#include <cstddef>
#include <cstdint>

namespace esphome::cs_proxy {

class Sha256 {
 public:
  Sha256() { this->reset(); }
  void reset();
  void update(const uint8_t *data, size_t len);
  void finish(uint8_t out[32]);

 private:
  void block_(const uint8_t *p);
  uint32_t h_[8];
  uint8_t buf_[64];
  size_t buf_len_;
  uint64_t total_len_;
};

void sha256(const uint8_t *data, size_t len, uint8_t out[32]);
void hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len, uint8_t out[32]);

// Constant-time comparison of two equal-length buffers.
bool ct_equal(const uint8_t *a, const uint8_t *b, size_t len);

}  // namespace esphome::cs_proxy
