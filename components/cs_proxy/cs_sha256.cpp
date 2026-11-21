#include "cs_sha256.h"

#include <cstring>

namespace esphome::cs_proxy {

namespace {

constexpr uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

}  // namespace

void Sha256::reset() {
  static constexpr uint32_t INIT[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                       0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
  std::memcpy(this->h_, INIT, sizeof(INIT));
  this->buf_len_ = 0;
  this->total_len_ = 0;
}

void Sha256::block_(const uint8_t *p) {
  uint32_t w[64];
  for (int i = 0; i < 16; i++) {
    w[i] = (uint32_t(p[4 * i]) << 24) | (uint32_t(p[4 * i + 1]) << 16) | (uint32_t(p[4 * i + 2]) << 8) |
           uint32_t(p[4 * i + 3]);
  }
  for (int i = 16; i < 64; i++) {
    uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
    uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }
  uint32_t a = this->h_[0], b = this->h_[1], c = this->h_[2], d = this->h_[3];
  uint32_t e = this->h_[4], f = this->h_[5], g = this->h_[6], h = this->h_[7];
  for (int i = 0; i < 64; i++) {
    uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
    uint32_t ch = (e & f) ^ (~e & g);
    uint32_t t1 = h + s1 + ch + K[i] + w[i];
    uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
    uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    uint32_t t2 = s0 + maj;
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }
  this->h_[0] += a;
  this->h_[1] += b;
  this->h_[2] += c;
  this->h_[3] += d;
  this->h_[4] += e;
  this->h_[5] += f;
  this->h_[6] += g;
  this->h_[7] += h;
}

void Sha256::update(const uint8_t *data, size_t len) {
  this->total_len_ += len;
  while (len > 0) {
    size_t take = 64 - this->buf_len_;
    if (take > len)
      take = len;
    std::memcpy(this->buf_ + this->buf_len_, data, take);
    this->buf_len_ += take;
    data += take;
    len -= take;
    if (this->buf_len_ == 64) {
      this->block_(this->buf_);
      this->buf_len_ = 0;
    }
  }
}

void Sha256::finish(uint8_t out[32]) {
  uint64_t bits = this->total_len_ * 8;
  uint8_t pad = 0x80;
  this->update(&pad, 1);
  uint8_t zero = 0;
  while (this->buf_len_ != 56)
    this->update(&zero, 1);
  uint8_t len_be[8];
  for (int i = 0; i < 8; i++)
    len_be[i] = uint8_t(bits >> (56 - 8 * i));
  this->update(len_be, 8);
  for (int i = 0; i < 8; i++) {
    out[4 * i] = uint8_t(this->h_[i] >> 24);
    out[4 * i + 1] = uint8_t(this->h_[i] >> 16);
    out[4 * i + 2] = uint8_t(this->h_[i] >> 8);
    out[4 * i + 3] = uint8_t(this->h_[i]);
  }
  this->reset();
}

void sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
  Sha256 s;
  s.update(data, len);
  s.finish(out);
}

void hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len, uint8_t out[32]) {
  uint8_t k[64] = {0};
  if (key_len > 64) {
    sha256(key, key_len, k);
  } else {
    std::memcpy(k, key, key_len);
  }
  uint8_t pad[64];
  for (int i = 0; i < 64; i++)
    pad[i] = k[i] ^ 0x36;
  Sha256 inner;
  inner.update(pad, 64);
  inner.update(msg, msg_len);
  uint8_t inner_hash[32];
  inner.finish(inner_hash);
  for (int i = 0; i < 64; i++)
    pad[i] = k[i] ^ 0x5c;
  Sha256 outer;
  outer.update(pad, 64);
  outer.update(inner_hash, 32);
  outer.finish(out);
}

bool ct_equal(const uint8_t *a, const uint8_t *b, size_t len) {
  uint8_t diff = 0;
  for (size_t i = 0; i < len; i++)
    diff |= a[i] ^ b[i];
  return diff == 0;
}

}  // namespace esphome::cs_proxy
