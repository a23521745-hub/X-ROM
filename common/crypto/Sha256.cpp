/*
 * Copyright (C) 2026 The X-ROM Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "Sha256.h"

#include <cstdio>
#include <cstring>
#include <memory>

namespace xrom::crypto {
namespace {

// FIPS 180-4 section 5.3.3: the first 32 bits of the fractional parts of the
// square roots of the first nine primes.
constexpr uint32_t kInitialState[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
};

// FIPS 180-4 section 4.2.2: the first 32 bits of the fractional parts of the
// cube roots of the first 64 primes.
constexpr uint32_t kRoundConstants[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u,
    0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u,
    0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au,
    0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

inline uint32_t RotateRight(uint32_t value, unsigned bits) {
  return (value >> bits) | (value << (32 - bits));
}
inline uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
inline uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
inline uint32_t BigSigma0(uint32_t x) {
  return RotateRight(x, 2) ^ RotateRight(x, 13) ^ RotateRight(x, 22);
}
inline uint32_t BigSigma1(uint32_t x) {
  return RotateRight(x, 6) ^ RotateRight(x, 11) ^ RotateRight(x, 25);
}
inline uint32_t SmallSigma0(uint32_t x) { return RotateRight(x, 7) ^ RotateRight(x, 18) ^ (x >> 3); }
inline uint32_t SmallSigma1(uint32_t x) {
  return RotateRight(x, 17) ^ RotateRight(x, 19) ^ (x >> 10);
}

inline uint32_t LoadBigEndian32(const uint8_t* p) {
  return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

inline void StoreBigEndian32(uint8_t* p, uint32_t value) {
  p[0] = static_cast<uint8_t>(value >> 24);
  p[1] = static_cast<uint8_t>(value >> 16);
  p[2] = static_cast<uint8_t>(value >> 8);
  p[3] = static_cast<uint8_t>(value);
}

int HexValue(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

}  // namespace

void Sha256::Reset() {
  std::memcpy(state_, kInitialState, sizeof(state_));
  buffer_length_ = 0;
  bytes_hashed_ = 0;
}

void Sha256::Transform(const uint8_t block[kSha256BlockSize]) {
  uint32_t w[64];
  for (int i = 0; i < 16; ++i) {
    w[i] = LoadBigEndian32(block + 4 * i);
  }
  for (int i = 16; i < 64; ++i) {
    w[i] = SmallSigma1(w[i - 2]) + w[i - 7] + SmallSigma0(w[i - 15]) + w[i - 16];
  }

  uint32_t a = state_[0];
  uint32_t b = state_[1];
  uint32_t c = state_[2];
  uint32_t d = state_[3];
  uint32_t e = state_[4];
  uint32_t f = state_[5];
  uint32_t g = state_[6];
  uint32_t h = state_[7];

  for (int i = 0; i < 64; ++i) {
    const uint32_t t1 = h + BigSigma1(e) + Ch(e, f, g) + kRoundConstants[i] + w[i];
    const uint32_t t2 = BigSigma0(a) + Maj(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }

  state_[0] += a;
  state_[1] += b;
  state_[2] += c;
  state_[3] += d;
  state_[4] += e;
  state_[5] += f;
  state_[6] += g;
  state_[7] += h;
}

void Sha256::Update(const void* data, size_t length) {
  if (length == 0) {
    // Returning early keeps a zero-length update legal even when |data| is null.
    // memcpy(dst, nullptr, 0) is undefined behaviour by the letter of the
    // standard, and callers legitimately reach it when they hash a stream of
    // frames one of which happens to be empty.
    return;
  }
  const uint8_t* cursor = static_cast<const uint8_t*>(data);
  bytes_hashed_ += length;

  if (buffer_length_ > 0) {
    const size_t space = kSha256BlockSize - buffer_length_;
    const size_t take = length < space ? length : space;
    std::memcpy(buffer_ + buffer_length_, cursor, take);
    buffer_length_ += take;
    cursor += take;
    length -= take;
    if (buffer_length_ == kSha256BlockSize) {
      Transform(buffer_);
      buffer_length_ = 0;
    }
  }

  while (length >= kSha256BlockSize) {
    Transform(cursor);
    cursor += kSha256BlockSize;
    length -= kSha256BlockSize;
  }

  if (length > 0) {
    std::memcpy(buffer_, cursor, length);
    buffer_length_ = length;
  }
}

Sha256Digest Sha256::Finalize() {
  // Captured before padding: Update() counts the padding bytes too.
  const uint64_t bit_length = bytes_hashed_ * 8;

  uint8_t byte = 0x80;
  Update(&byte, 1);
  byte = 0x00;
  // Length occupies the final 8 bytes, so zero-fill until 56 mod 64. When the
  // message ended exactly at 56..63 this spills into a second block, which is
  // the case the padding-boundary tests pin down.
  while (buffer_length_ != (kSha256BlockSize - 8)) {
    Update(&byte, 1);
  }

  uint8_t length_be[8];
  for (int i = 0; i < 8; ++i) {
    length_be[i] = static_cast<uint8_t>(bit_length >> (56 - 8 * i));
  }
  Update(length_be, sizeof(length_be));

  Sha256Digest digest;
  for (int i = 0; i < 8; ++i) {
    StoreBigEndian32(digest.data() + 4 * i, state_[i]);
  }
  Reset();
  return digest;
}

Sha256Digest Sha256::Hash(const void* data, size_t length) {
  Sha256 context;
  context.Update(data, length);
  return context.Finalize();
}

bool Sha256::HashFile(const std::string& path, Sha256Digest* out, std::string* error) {
  std::unique_ptr<FILE, int (*)(FILE*)> file(fopen(path.c_str(), "rb"), fclose);
  if (file == nullptr) {
    if (error != nullptr) {
      *error = "cannot open the file for hashing";
    }
    return false;
  }

  Sha256 context;
  uint8_t chunk[64 * 1024];
  while (true) {
    const size_t got = fread(chunk, 1, sizeof(chunk), file.get());
    if (got > 0) {
      context.Update(chunk, got);
    }
    if (got < sizeof(chunk)) {
      if (ferror(file.get())) {
        if (error != nullptr) {
          *error = "read error while hashing the file";
        }
        return false;
      }
      break;
    }
  }
  *out = context.Finalize();
  return true;
}

std::string Sha256::ToHex(const Sha256Digest& digest) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string out;
  out.resize(digest.size() * 2);
  for (size_t i = 0; i < digest.size(); ++i) {
    out[2 * i] = kDigits[digest[i] >> 4];
    out[2 * i + 1] = kDigits[digest[i] & 0x0f];
  }
  return out;
}

bool Sha256::FromHex(const std::string& hex, Sha256Digest* out) {
  if (hex.size() != kSha256DigestSize * 2) {
    return false;
  }
  Sha256Digest digest{};
  for (size_t i = 0; i < kSha256DigestSize; ++i) {
    const int high = HexValue(hex[2 * i]);
    const int low = HexValue(hex[2 * i + 1]);
    if (high < 0 || low < 0) {
      return false;
    }
    digest[i] = static_cast<uint8_t>((high << 4) | low);
  }
  *out = digest;
  return true;
}

bool Sha256::Equal(const Sha256Digest& a, const Sha256Digest& b) {
  uint8_t difference = 0;
  for (size_t i = 0; i < a.size(); ++i) {
    difference |= static_cast<uint8_t>(a[i] ^ b[i]);
  }
  return difference == 0;
}

}  // namespace xrom::crypto
