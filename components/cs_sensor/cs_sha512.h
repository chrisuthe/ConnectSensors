#pragma once

// Self-contained SHA-512 (FIPS 180-4), for Ed25519 key generation (cs_ed25519.h).
// No platform dependencies, so the core builds and tests on any host.

#include <cstddef>
#include <cstdint>

namespace esphome::cs_sensor {

class Sha512 {
 public:
  Sha512() { this->reset(); }
  void reset();
  void update(const uint8_t *data, size_t len);
  void finish(uint8_t out[64]);

 private:
  void block_(const uint8_t *p);
  uint64_t h_[8];
  uint8_t buf_[128];
  size_t buf_len_;
  uint64_t total_len_;
};

void sha512(const uint8_t *data, size_t len, uint8_t out[64]);

}  // namespace esphome::cs_sensor
