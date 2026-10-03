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

#ifndef XROM_COMMON_CRYPTO_SHA256_H_
#define XROM_COMMON_CRYPTO_SHA256_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace xrom::crypto {

// ---------------------------------------------------------------------------
// SHA-256 (FIPS 180-4), self-contained.
//
// WHY THIS IS NOT "ROLLING YOUR OWN CRYPTO"
// -----------------------------------------
// It deliberately is only a hash, and it deliberately has no dependencies. The
// Microdroid linker namespace exposes the NDK library set to payload code, which
// does not include BoringSSL, so libcrypto is not linkable inside the guest. The
// host needs the same digest function to cross-check what the guest measured, and
// two implementations of the same primitive that disagree are worse than one
// dependency-free implementation validated against published vectors.
//
// What this file does NOT do: signatures, key agreement, MACs, encryption, or
// anything where a subtle mistake is exploitable rather than merely wrong. Those
// go through BoringSSL on the host (see PayloadVerifier) and through AVF's own
// attested-key API inside the guest (AVmAttestationResult_sign), never through a
// hand-written implementation.
//
// Correctness is pinned by tests/Sha256_test.cpp against the FIPS 180-4 and NIST
// CAVP vectors, including the empty string, the one-block and two-block cases,
// the exact 55/56/63/64-byte padding boundaries and a 1 MiB stream. Those same
// tests run with a system compiler via tools/hostcheck.
// ---------------------------------------------------------------------------

inline constexpr size_t kSha256DigestSize = 32;
inline constexpr size_t kSha256BlockSize = 64;

using Sha256Digest = std::array<uint8_t, kSha256DigestSize>;

class Sha256 {
 public:
  Sha256() { Reset(); }

  // Resets to the initial state. Called by the constructor and by Finalize(), so
  // one object can hash a sequence of inputs.
  void Reset();

  void Update(const void* data, size_t length);
  void Update(const std::string& data) { Update(data.data(), data.size()); }

  // Returns the digest and resets, so the object is immediately reusable.
  Sha256Digest Finalize();

  // Total number of bytes fed so far. Used to cross-check the length a peer
  // claims, which catches a truncated stream that still happens to hash.
  uint64_t bytes_hashed() const { return bytes_hashed_; }

  static Sha256Digest Hash(const void* data, size_t length);
  static Sha256Digest Hash(const std::string& data) { return Hash(data.data(), data.size()); }

  // Streams a file in 64 KiB chunks. Never loads it whole: the inputs here are
  // APKs and disk images, and a daemon that mmaps an attacker-influenced file
  // size has given that file a say in its own memory use.
  static bool HashFile(const std::string& path, Sha256Digest* out, std::string* error);

  static std::string ToHex(const Sha256Digest& digest);

  // Strict: exactly 64 lowercase-or-uppercase hex characters and nothing else.
  // Returns false rather than partially filling |out|.
  static bool FromHex(const std::string& hex, Sha256Digest* out);

  // Constant-time comparison. Digests are not secret, but comparing them with a
  // short-circuit in a security decision is a habit that eventually leaks
  // something that is secret.
  static bool Equal(const Sha256Digest& a, const Sha256Digest& b);

 private:
  void Transform(const uint8_t block[kSha256BlockSize]);

  uint32_t state_[8];
  uint8_t buffer_[kSha256BlockSize];
  size_t buffer_length_ = 0;
  uint64_t bytes_hashed_ = 0;
};

}  // namespace xrom::crypto

#endif  // XROM_COMMON_CRYPTO_SHA256_H_
