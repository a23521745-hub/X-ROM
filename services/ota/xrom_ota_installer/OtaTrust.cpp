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

#include "OtaTrust.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <memory>

#include <android-base/file.h>
#include <openssl/evp.h>
#include <openssl/mem.h>

#include "OtaManifest.h"

namespace xrom::ota_installer {
namespace {

// Ceilings, not guesses. A trust file is kilobytes and a signature is at most a few
// hundred bytes; refusing to read megabytes means a file that is not the trust
// material cannot be used to exhaust the installer before it has verified anything.
constexpr size_t kMaxTrustBytes = 64 * 1024;
constexpr size_t kMaxSignatureBytes = 4 * 1024;
constexpr size_t kMaxManifestBytes = 64 * 1024;
constexpr size_t kMaxAnchors = 32;

int HexValue(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

bool HexToBytes(const std::string& hex, std::string* out) {
  if (hex.size() % 2 != 0) {
    return false;
  }
  out->clear();
  out->reserve(hex.size() / 2);
  for (size_t i = 0; i < hex.size(); i += 2) {
    const int high = HexValue(hex[i]);
    const int low = HexValue(hex[i + 1]);
    if (high < 0 || low < 0) {
      return false;
    }
    out->push_back(static_cast<char>((high << 4) | low));
  }
  return true;
}

// base64 decode for the DER public keys. Written here rather than pulled from a
// library because the input is a trusted, read-only file and the only property that
// matters is that a malformed entry is rejected rather than half-parsed.
bool Base64ToBytes(const std::string& text, std::string* out) {
  auto value = [](char c) -> int {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
  };
  out->clear();
  int accumulator = 0;
  int bits = 0;
  for (char c : text) {
    if (c == '=' ) break;
    if (std::isspace(static_cast<unsigned char>(c))) continue;
    const int v = value(c);
    if (v < 0) {
      return false;
    }
    accumulator = (accumulator << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out->push_back(static_cast<char>((accumulator >> bits) & 0xFF));
    }
  }
  return !out->empty();
}

bool StripPem(const std::string& text, std::string* der) {
  // Accepts a bare base64 body as well as a PEM block, because the tooling that
  // produces the trust file emits PEM and a hand-edited file may not.
  const size_t begin = text.find("-----BEGIN");
  if (begin == std::string::npos) {
    return Base64ToBytes(text, der);
  }
  const size_t body = text.find('\n', begin);
  const size_t end = text.find("-----END", body);
  if (body == std::string::npos || end == std::string::npos || end <= body) {
    return false;
  }
  return Base64ToBytes(text.substr(body + 1, end - body - 1), der);
}

}  // namespace

std::string TrustLoadResult::Describe() const {
  if (ok) {
    std::string out = std::to_string(anchors.size()) + " anchor(s) loaded";
    if (!dropped.empty()) {
      out += ", " + std::to_string(dropped.size()) + " dropped: ";
      for (size_t i = 0; i < dropped.size(); ++i) {
        if (i != 0) out += "; ";
        out += dropped[i];
      }
    }
    return out;
  }
  std::string out = "trust material rejected: ";
  for (size_t i = 0; i < errors.size(); ++i) {
    if (i != 0) out += "; ";
    out += errors[i];
  }
  return out;
}

TrustLoadResult LoadTrustAnchors(const std::string& path) {
  TrustLoadResult result;

  std::string content;
  if (!android::base::ReadFileToString(path, &content, static_cast<unsigned>(kMaxTrustBytes))) {
    result.errors.push_back("cannot read " + path +
                            "; without pinned keys there is nothing to verify against and the "
                            "installer must not write anything");
    return result;
  }
  if (content.size() >= kMaxTrustBytes) {
    result.errors.push_back(path + " exceeds the " + std::to_string(kMaxTrustBytes) +
                            " byte ceiling for a trust file");
    return result;
  }

  Json::Value root;
  Json::CharReaderBuilder builder;
  builder.settings_["collectComments"] = false;
  std::string parse_error;
  const std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
  if (!reader->parse(content.data(), content.data() + content.size(), &root, &parse_error)) {
    result.errors.push_back(path + " is not valid JSON: " + parse_error);
    return result;
  }
  if (!root.isObject() || !root.isMember("anchors") || !root["anchors"].isArray()) {
    result.errors.push_back(path + " must be an object with an \"anchors\" array");
    return result;
  }

  const Json::Value& anchors = root["anchors"];
  if (anchors.size() > kMaxAnchors) {
    result.errors.push_back("more than " + std::to_string(kMaxAnchors) + " anchors");
    return result;
  }

  for (const Json::Value& entry : anchors) {
    if (!entry.isObject()) {
      result.dropped.push_back("an anchor entry is not an object");
      continue;
    }
    if (!entry.isMember("key_id") || !entry["key_id"].isString() ||
        !entry.isMember("algorithm") || !entry["algorithm"].isString() ||
        !entry.isMember("public_key") || !entry["public_key"].isString()) {
      result.dropped.push_back("an anchor entry is missing key_id, algorithm or public_key");
      continue;
    }

    ::xrom::ota::OtaKeyAnchor anchor;
    anchor.key_id = entry["key_id"].asString();
    const std::string algorithm = entry["algorithm"].asString();
    if (algorithm == "ED25519") {
      anchor.algorithm = ::xrom::ota::SignatureAlgorithm::kEd25519;
    } else if (algorithm == "RSA4096_SHA256") {
      anchor.algorithm = ::xrom::ota::SignatureAlgorithm::kRsa4096Sha256;
    } else {
      result.dropped.push_back("anchor '" + anchor.key_id + "' names an unknown algorithm '" +
                               algorithm + "'");
      continue;
    }
    if (!StripPem(entry["public_key"].asString(), &anchor.public_key_der)) {
      result.dropped.push_back("anchor '" + anchor.key_id + "' has a public_key that is not "
                               "valid base64 or PEM");
      continue;
    }
    anchor.enabled = !entry.isMember("enabled") || entry["enabled"].asBool();
    anchor.min_security_version =
        entry.isMember("min_security_version") ? entry["min_security_version"].asUInt() : 0;

    // Validated at load, not at use. An anchor whose DER does not match the algorithm
    // its entry claims would otherwise turn "verify with Ed25519" into "verify with
    // whatever this blob is", and finding that out during an incident is too late.
    const auto validation = ::xrom::ota::ValidateAnchor(anchor);
    if (!validation.ok) {
      result.dropped.push_back("anchor '" + anchor.key_id + "' is unusable: " + validation.reason);
      continue;
    }
    if (!anchor.enabled) {
      // Kept in the list, disabled. VerifySignatures refuses a disabled anchor and
      // says so, which is more informative than the anchor having vanished.
      result.dropped.push_back("anchor '" + anchor.key_id + "' is present but disabled");
    }
    result.anchors.push_back(std::move(anchor));
  }

  // Zero usable anchors is fatal, not permissive. An installer with nothing to verify
  // against must not fall back to "accept anything"; VerifySignatures fails closed on
  // an empty anchor list, and so does this.
  bool any_enabled = false;
  for (const auto& anchor : result.anchors) {
    if (anchor.enabled) {
      any_enabled = true;
      break;
    }
  }
  if (!any_enabled) {
    result.errors.push_back("no enabled anchor survived validation, so nothing can be "
                            "verified; refusing to install anything");
    return result;
  }

  result.ok = true;
  return result;
}

bool ReadSignatureFile(const std::string& path, ::xrom::ota::SignatureAlgorithm algorithm,
                       const std::string& key_id, ::xrom::ota::DetachedSignature* out,
                       std::string* error) {
  std::string content;
  if (!android::base::ReadFileToString(path, &content,
                                       static_cast<unsigned>(kMaxSignatureBytes))) {
    if (error != nullptr) *error = "cannot read the signature file " + path;
    return false;
  }
  if (content.size() >= kMaxSignatureBytes) {
    if (error != nullptr) *error = path + " is too large to be a detached signature";
    return false;
  }

  // Hex if it looks like hex, base64 otherwise. The signing tool writes hex; accepting
  // base64 too means a signature produced by another tool is not silently rejected for
  // a formatting reason that has nothing to do with whether it verifies.
  std::string bytes;
  const bool looks_hex = std::all_of(content.begin(), content.end(), [](char c) {
    return std::isxdigit(static_cast<unsigned char>(c)) || std::isspace(static_cast<unsigned char>(c));
  });
  if (looks_hex && !HexToBytes(content, &bytes)) {
    if (error != nullptr) *error = path + " is not valid hex";
    return false;
  }
  if (bytes.empty() && !Base64ToBytes(content, &bytes)) {
    if (error != nullptr) *error = path + " is neither valid hex nor valid base64";
    return false;
  }

  // Length checked against the algorithm before anything is handed to the crypto
  // library. An Ed25519 signature is 64 bytes and an RSA-4096 PKCS#1 v1.5 signature is
  // 512; a blob of any other length is not a signature of that kind, and passing it on
  // turns a formatting error into an opaque verification failure.
  const size_t expected = algorithm == ::xrom::ota::SignatureAlgorithm::kEd25519 ? 64 : 512;
  if (bytes.size() != expected) {
    if (error != nullptr) {
      *error = path + " holds " + std::to_string(bytes.size()) + " bytes but a " +
               ::xrom::ota::SignatureAlgorithmName(algorithm) + " signature is " +
               std::to_string(expected);
    }
    return false;
  }

  out->algorithm = algorithm;
  out->key_id = key_id;
  out->signature = std::move(bytes);
  return true;
}

ManifestReadResult ReadManifest(const std::string& path) {
  ManifestReadResult result;

  std::string content;
  if (!android::base::ReadFileToString(path, &content, static_cast<unsigned>(kMaxManifestBytes))) {
    result.error = "cannot read " + path;
    return result;
  }
  if (content.size() >= kMaxManifestBytes) {
    result.error = path + " exceeds the ceiling for update.json";
    return result;
  }
  // The bytes are kept verbatim: they are what the signature covers, and the parsed
  // structure is checked against them by re-serialisation inside the verifier.
  result.bytes = content;

  Json::Value root;
  Json::CharReaderBuilder builder;
  builder.settings_["collectComments"] = false;
  std::string parse_error;
  const std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
  if (!reader->parse(content.data(), content.data() + content.size(), &root, &parse_error)) {
    result.error = path + " is not valid JSON: " + parse_error;
    return result;
  }
  if (!root.isObject()) {
    result.error = path + " must contain a JSON object";
    return result;
  }

  auto& m = result.manifest;
  m = ::xrom::ota::OtaManifest{};
  const auto str = [&root](const char* key, std::string* out) {
    if (root.isMember(key) && root[key].isString()) *out = root[key].asString();
  };
  const auto num = [&root](const char* key, uint64_t* out) {
    if (root.isMember(key) && root[key].isNumeric()) *out = root[key].asUInt64();
  };
  const auto boolean = [&root](const char* key, bool* out) {
    if (root.isMember(key) && root[key].isBool()) *out = root[key].asBool();
  };

  uint64_t version = 0;
  num("manifest_version", &version);
  m.manifest_version = static_cast<uint32_t>(version);
  str("package_url", &m.package_url);
  str("package_sha256", &m.package_sha256);
  num("package_bytes", &m.package_bytes);
  uint64_t security_version = 0;
  num("security_version", &security_version);
  m.security_version = static_cast<uint32_t>(security_version);
  str("build_fingerprint", &m.build_fingerprint);
  str("target_fingerprint", &m.target_fingerprint);
  str("expected_hashtree_root_sha256", &m.expected_hashtree_root_sha256);
  uint64_t battery = 0;
  num("min_battery_percent", &battery);
  m.min_battery_percent = static_cast<uint32_t>(battery);
  int64_t issued = 0;
  int64_t not_after = 0;
  if (root.isMember("issued_at_unix") && root["issued_at_unix"].isNumeric()) {
    issued = root["issued_at_unix"].asInt64();
  }
  if (root.isMember("not_after_unix") && root["not_after_unix"].isNumeric()) {
    not_after = root["not_after_unix"].asInt64();
  }
  m.issued_at_unix = issued;
  m.not_after_unix = not_after;
  boolean("updates_vault", &m.updates_vault);

  result.ok = true;
  return result;
}

::xrom::ota::BackendResult BoringSslBackend::Verify(::xrom::ota::SignatureAlgorithm algorithm,
                                                    const std::string& public_key_der,
                                                    const std::string& artifact,
                                                    const std::string& signature) {
  ::xrom::ota::BackendResult result;

  // The DER is parsed fresh for every verification rather than cached as an EVP_PKEY.
  // Parsing 44 or 550 bytes is nothing next to an RSA-4096 verify, and a cached key
  // would be a long-lived object holding key material that outlives the check it was
  // loaded for.
  const uint8_t* der = reinterpret_cast<const uint8_t*>(public_key_der.data());
  EVP_PKEY* raw = nullptr;
  if (d2i_PUBKEY(&raw, &der, static_cast<long>(public_key_der.size())) == nullptr ||
      raw == nullptr) {
    result.verified = false;
    result.detail = "the pinned public key is not a parseable DER SubjectPublicKeyInfo";
    return result;
  }
  std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(raw, EVP_PKEY_free);

  // The declared algorithm and the key's own type must agree. Without this check a
  // configuration that pairs an Ed25519 signature with an RSA anchor produces a
  // confusing verification failure instead of a clear one — and in the other direction
  // it could let an anchor be used with a primitive it was never issued for.
  const int expected_id = algorithm == ::xrom::ota::SignatureAlgorithm::kEd25519 ? EVP_PKEY_ED25519
                                                                                : EVP_PKEY_RSA;
  if (EVP_PKEY_id(key.get()) != expected_id) {
    result.verified = false;
    result.detail = "the anchor's key type does not match the algorithm it is pinned for";
    return result;
  }

  std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context(EVP_MD_CTX_new(),
                                                                  EVP_MD_CTX_free);
  if (context == nullptr) {
    result.verified = false;
    result.detail = "EVP_MD_CTX_new failed";
    return result;
  }

  // Ed25519 takes a NULL md and is a single-shot operation; RSA-4096 uses SHA-256 with
  // PKCS#1 v1.5 padding, which is what tools/xrom_sign_ota.py produces. Neither path
  // canonicalises the artifact: the signature covers the exact bytes on disk.
  const EVP_MD* md = algorithm == ::xrom::ota::SignatureAlgorithm::kEd25519 ? nullptr : EVP_sha256();
  if (EVP_DigestVerifyInit(context.get(), nullptr, md, nullptr, key.get()) != 1) {
    result.verified = false;
    result.detail = "EVP_DigestVerifyInit failed";
    return result;
  }
  const int verified = EVP_DigestVerify(
      context.get(), reinterpret_cast<const uint8_t*>(signature.data()), signature.size(),
      reinterpret_cast<const uint8_t*>(artifact.data()), artifact.size());

  result.verified = (verified == 1);
  if (!result.verified) {
    result.detail = verified == 0 ? "the signature does not match the artifact"
                                  : "EVP_DigestVerify errored";
  }
  return result;
}

}  // namespace xrom::ota_installer
