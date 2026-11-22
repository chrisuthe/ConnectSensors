#include "cs_crypto.h"

#include "cs_sha256.h"

#include <cstring>

namespace esphome::cs_sensor {

namespace {

const uint8_t SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

inline uint8_t xtime(uint8_t x) { return uint8_t((x << 1) ^ ((x >> 7) * 0x1b)); }

void xor_block(uint8_t *dst, const uint8_t *src, size_t n) {
  for (size_t i = 0; i < n; i++)
    dst[i] ^= src[i];
}

}  // namespace

void secure_zero(void *p, size_t len) {
  volatile uint8_t *v = static_cast<volatile uint8_t *>(p);
  while (len--)
    *v++ = 0;
}

// ---------------------------------------------------------------- AES-128

Aes128::Aes128(const uint8_t key[16]) {
  std::memcpy(this->rk_, key, 16);
  uint8_t rcon = 1;
  for (int i = 16; i < 176; i += 4) {
    uint8_t t[4] = {this->rk_[i - 4], this->rk_[i - 3], this->rk_[i - 2], this->rk_[i - 1]};
    if (i % 16 == 0) {
      uint8_t first = t[0];
      t[0] = uint8_t(SBOX[t[1]] ^ rcon);
      t[1] = SBOX[t[2]];
      t[2] = SBOX[t[3]];
      t[3] = SBOX[first];
      rcon = xtime(rcon);
    }
    for (int j = 0; j < 4; j++)
      this->rk_[i + j] = uint8_t(this->rk_[i - 16 + j] ^ t[j]);
  }
}

Aes128::~Aes128() { secure_zero(this->rk_, sizeof(this->rk_)); }

void Aes128::encrypt_block(const uint8_t in[16], uint8_t out[16]) const {
  // State is column-major, as the bytes come: s[4 * col + row].
  uint8_t s[16];
  for (int i = 0; i < 16; i++)
    s[i] = uint8_t(in[i] ^ this->rk_[i]);
  for (int round = 1; round <= 10; round++) {
    uint8_t t[16];
    // SubBytes and ShiftRows: row r moves left by r columns.
    for (int col = 0; col < 4; col++) {
      for (int row = 0; row < 4; row++)
        t[4 * col + row] = SBOX[s[4 * ((col + row) % 4) + row]];
    }
    if (round < 10) {
      for (int col = 0; col < 4; col++) {
        uint8_t *c = t + 4 * col;
        uint8_t all = uint8_t(c[0] ^ c[1] ^ c[2] ^ c[3]);
        uint8_t c0 = c[0];
        c[0] = uint8_t(c[0] ^ all ^ xtime(uint8_t(c[0] ^ c[1])));
        c[1] = uint8_t(c[1] ^ all ^ xtime(uint8_t(c[1] ^ c[2])));
        c[2] = uint8_t(c[2] ^ all ^ xtime(uint8_t(c[2] ^ c[3])));
        c[3] = uint8_t(c[3] ^ all ^ xtime(uint8_t(c[3] ^ c0)));
      }
    }
    for (int i = 0; i < 16; i++)
      s[i] = uint8_t(t[i] ^ this->rk_[16 * round + i]);
  }
  std::memcpy(out, s, 16);
  secure_zero(s, sizeof(s));
}

// ---------------------------------------------------------------- AES-CCM

namespace {

// L = 15 - 13 = 2 length bytes; M = 8 tag bytes.
constexpr uint8_t CCM_L = 15 - CCM_NONCE_LEN;

void ccm_counter_block(const uint8_t nonce[CCM_NONCE_LEN], uint16_t i, uint8_t out[16]) {
  out[0] = CCM_L - 1;
  std::memcpy(out + 1, nonce, CCM_NONCE_LEN);
  out[14] = uint8_t(i >> 8);
  out[15] = uint8_t(i);
}

// CBC-MAC over B0 | encoded aad | plaintext, each part zero-padded to 16 bytes.
void ccm_mac(const Aes128 &aes, const uint8_t nonce[CCM_NONCE_LEN], const uint8_t *aad, size_t aad_len,
             const uint8_t *pt, size_t len, uint8_t tag[16]) {
  uint8_t x[16];
  x[0] = uint8_t((aad_len ? 0x40 : 0) | (((CCM_TAG_LEN - 2) / 2) << 3) | (CCM_L - 1));
  std::memcpy(x + 1, nonce, CCM_NONCE_LEN);
  x[14] = uint8_t(len >> 8);
  x[15] = uint8_t(len);
  aes.encrypt_block(x, x);

  if (aad_len) {
    uint8_t block[16] = {uint8_t(aad_len >> 8), uint8_t(aad_len)};
    size_t fill = 2;
    for (size_t i = 0; i < aad_len; i++) {
      block[fill++] = aad[i];
      if (fill == 16) {
        xor_block(x, block, 16);
        aes.encrypt_block(x, x);
        fill = 0;
      }
    }
    if (fill) {
      std::memset(block + fill, 0, 16 - fill);
      xor_block(x, block, 16);
      aes.encrypt_block(x, x);
    }
  }
  for (size_t off = 0; off < len; off += 16) {
    size_t n = len - off < 16 ? len - off : 16;
    xor_block(x, pt + off, n);
    aes.encrypt_block(x, x);
  }
  std::memcpy(tag, x, 16);
}

void ccm_ctr(const Aes128 &aes, const uint8_t nonce[CCM_NONCE_LEN], const uint8_t *in, size_t len, uint8_t *out) {
  uint8_t a[16], s[16];
  for (size_t off = 0, i = 1; off < len; off += 16, i++) {
    ccm_counter_block(nonce, uint16_t(i), a);
    aes.encrypt_block(a, s);
    size_t n = len - off < 16 ? len - off : 16;
    for (size_t j = 0; j < n; j++)
      out[off + j] = uint8_t(in[off + j] ^ s[j]);
  }
  secure_zero(s, sizeof(s));
}

void ccm_tag_mask(const Aes128 &aes, const uint8_t nonce[CCM_NONCE_LEN], uint8_t tag[16]) {
  uint8_t a[16], s0[16];
  ccm_counter_block(nonce, 0, a);
  aes.encrypt_block(a, s0);
  xor_block(tag, s0, CCM_TAG_LEN);
}

}  // namespace

void ccm_seal(const uint8_t key[16], const uint8_t nonce[CCM_NONCE_LEN], const uint8_t *aad, size_t aad_len,
              const uint8_t *plaintext, size_t len, uint8_t *out) {
  Aes128 aes(key);
  uint8_t tag[16];
  ccm_mac(aes, nonce, aad, aad_len, plaintext, len, tag);
  ccm_tag_mask(aes, nonce, tag);
  ccm_ctr(aes, nonce, plaintext, len, out);
  std::memcpy(out + len, tag, CCM_TAG_LEN);
}

bool ccm_open(const uint8_t key[16], const uint8_t nonce[CCM_NONCE_LEN], const uint8_t *aad, size_t aad_len,
              const uint8_t *in, size_t len, uint8_t *out) {
  Aes128 aes(key);
  ccm_ctr(aes, nonce, in, len, out);
  uint8_t tag[16];
  ccm_mac(aes, nonce, aad, aad_len, out, len, tag);
  ccm_tag_mask(aes, nonce, tag);
  if (!ct_equal(tag, in + len, CCM_TAG_LEN)) {
    secure_zero(out, len);
    return false;
  }
  return true;
}

// ---------------------------------------------------------------- HKDF

bool hkdf_sha256(const uint8_t *ikm, size_t ikm_len, const uint8_t *salt, size_t salt_len, const uint8_t *info,
                 size_t info_len, uint8_t *out, size_t out_len) {
  if (out_len > 64 || info_len > 128)
    return false;
  static const uint8_t ZERO_SALT[32] = {0};
  if (salt == nullptr) {
    salt = ZERO_SALT;
    salt_len = sizeof(ZERO_SALT);
  }
  uint8_t prk[32];
  hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
  // T(i) = HMAC(PRK, T(i-1) | info | i)
  uint8_t msg[32 + 128 + 1];
  uint8_t t[32];
  size_t t_len = 0, done = 0;
  for (uint8_t i = 1; done < out_len; i++) {
    std::memcpy(msg, t, t_len);
    std::memcpy(msg + t_len, info, info_len);
    msg[t_len + info_len] = i;
    hmac_sha256(prk, 32, msg, t_len + info_len + 1, t);
    t_len = 32;
    size_t n = out_len - done < 32 ? out_len - done : 32;
    std::memcpy(out + done, t, n);
    done += n;
  }
  secure_zero(prk, sizeof(prk));
  secure_zero(t, sizeof(t));
  secure_zero(msg, sizeof(msg));
  return true;
}

}  // namespace esphome::cs_sensor
