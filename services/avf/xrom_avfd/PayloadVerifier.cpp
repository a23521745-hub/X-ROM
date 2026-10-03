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

#include "PayloadVerifier.h"

#include <sys/stat.h>

#include <cerrno>
#include <chrono>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <json/json.h>

#include <openssl/base.h>
#include <openssl/base64.h>
#include <openssl/evp.h>
#include <openssl/mem.h>

namespace xrom::avf {
namespace {

using ::xrom::crypto::Sha256;
using ::xrom::crypto::Sha256Digest;

// Hard ceilings on the trust material. A file bigger than this is a mistake or an
// attack, and in either case parsing it is not worth the risk.
constexpr size_t kMaxTrustConfigBytes = 64 * 1024;
constexpr size_t kMaxManifestBytes = 64 * 1024;
constexpr size_t kMaxSignatureBytes = 1024;         // RSA-4096 is 512
constexpr size_t kMaxPublicKeyDerBytes = 1024;      // SPKI: Ed25519 44, RSA-4096 550
constexpr size_t kMaxAnchors = 32;

// An EVP_PKEY that frees itself, so every early return is safe.
struct PkeyDeleter {
  void operator()(EVP_PKEY* key) const { EVP_PKEY_free(key); }
};
using PkeyPtr = std::unique_ptr<EVP_PKEY, PkeyDeleter>;

struct MdCtxDeleter {
  void operator()(EVP_MD_CTX* ctx) const { EVP_MD_CTX_free(ctx); }
};
using MdCtxPtr = std::unique_ptr<EVP_MD_CTX, MdCtxDeleter>;

int64_t NowUnix() {
  return std::chrono::duration_cast<std::chrono::seconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

bool ReadCappedFile(const std::string& path, size_t max_bytes, std::string* out,
                    std::string* error) {
  struct stat st {};
  if (stat(path.c_str(), &st) != 0) {
    *error = "cannot stat " + path + ": " + strerror(errno);
    return false;
  }
  if (st.st_size < 0 || static_cast<size_t>(st.st_size) > max_bytes) {
    *error = android::base::StringPrintf("%s is %lld bytes, over the %zu byte limit",
                                         path.c_str(), static_cast<long long>(st.st_size),
                                         max_bytes);
    return false;
  }
  if (!android::base::ReadFileToString(path, out)) {
    *error = "cannot read " + path + ": " + strerror(errno);
    return false;
  }
  return true;
}

bool ParseJsonObject(const std::string& content, const std::string& path, Json::Value* root,
                     std::string* error) {
  Json::CharReaderBuilder builder;
  builder.settings_["collectComments"] = false;
  const std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
  std::string parse_errors;
  if (reader == nullptr ||
      !reader->parse(content.data(), content.data() + content.size(), root, &parse_errors)) {
    *error = "malformed JSON in " + path + ": " + parse_errors;
    return false;
  }
  if (!root->isObject()) {
    *error = path + " must contain a single JSON object";
    return false;
  }
  return true;
}

bool DecodeBase64(const std::string& encoded, std::vector<uint8_t>* out, size_t max_bytes,
                  std::string* error) {
  // Whitespace inside the encoded blob is legal base64 and appears in every
  // 64-column wrapped PEM-style signature file, so strip it before measuring.
  std::string compact;
  compact.reserve(encoded.size());
  for (const char c : encoded) {
    if (c != '\n' && c != '\r' && c != ' ' && c != '\t') {
      compact.push_back(c);
    }
  }
  const size_t expected = EVP_DecodedBase64Length(compact.size());
  if (expected > max_bytes) {
    *error = android::base::StringPrintf("decoded length %zu exceeds the %zu byte limit", expected,
                                         max_bytes);
    return false;
  }
  out->resize(expected);
  size_t actual = 0;
  if (EVP_DecodeBase64(out->data(), &actual, out->size(),
                       reinterpret_cast<const uint8_t*>(compact.data()), compact.size()) != 1) {
    *error = "not valid base64";
    return false;
  }
  out->resize(actual);
  return true;
}

}  // namespace

PayloadVerifier::PayloadVerifier(const std::string& trust_config)
    : trust_config_(trust_config) {}

const TrustAnchor* PayloadVerifier::FindAnchor(const std::string& key_id,
                                               const std::string& algorithm) const {
  for (const TrustAnchor& anchor : anchors_) {
    if (anchor.enabled && anchor.key_id == key_id && anchor.algorithm == algorithm) {
      return &anchor;
    }
  }
  return nullptr;
}

bool PayloadVerifier::LoadTrustAnchors(std::vector<std::string>* errors) {
  anchors_.clear();
  const auto fail = [errors](const std::string& message) {
    LOG(ERROR) << "xrom_avfd: trust anchors: " << message;
    if (errors != nullptr) {
      errors->push_back(message);
    }
    return false;
  };

  std::string content;
  std::string error;
  if (!ReadCappedFile(trust_config_, kMaxTrustConfigBytes, &content, &error)) {
    return fail(error);
  }

  Json::Value root;
  if (!ParseJsonObject(content, trust_config_, &root, &error)) {
    return fail(error);
  }

  const Json::Value& array = root["trust_anchors"];
  if (!array.isArray() || array.empty()) {
    return fail(trust_config_ + " contains no trust_anchors array: failing closed");
  }
  if (array.size() > static_cast<Json::ArrayIndex>(kMaxAnchors)) {
    return fail(android::base::StringPrintf("trust_anchors has %u entries, over the %zu limit",
                                            array.size(), kMaxAnchors));
  }

  std::vector<std::string> problems;
  size_t enabled_count = 0;
  for (const Json::Value& entry : array) {
    TrustAnchor anchor;
    if (!entry.isObject()) {
      problems.push_back("a trust anchor entry is not an object");
      continue;
    }
    const Json::Value& id = entry["key_id"];
    const Json::Value& algo = entry["algorithm"];
    const Json::Value& key_b64 = entry["public_key_base64"];
    if (!id.isString() || id.asString().empty() || id.asString().size() > 64) {
      problems.push_back("a trust anchor has an invalid key_id");
      continue;
    }
    anchor.key_id = id.asString();
    if (!algo.isString() || (algo.asString() != kAlgorithmEd25519 &&
                             algo.asString() != kAlgorithmRsa4096Sha256)) {
      problems.push_back("trust anchor " + anchor.key_id + " has an unsupported algorithm");
      continue;
    }
    anchor.algorithm = algo.asString();
    if (!key_b64.isString() || key_b64.asString().empty()) {
      problems.push_back("trust anchor " + anchor.key_id + " has no public_key_base64");
      continue;
    }
    if (!DecodeBase64(key_b64.asString(), &anchor.public_key_der, kMaxPublicKeyDerBytes, &error)) {
      problems.push_back("trust anchor " + anchor.key_id + ": public key " + error);
      continue;
    }
    if (anchor.public_key_der.empty()) {
      problems.push_back("trust anchor " + anchor.key_id + ": empty public key");
      continue;
    }
    // An anchor whose key does not even parse as SubjectPublicKeyInfo is dropped
    // here rather than at verification time, so a broken anchor cannot turn into
    // a confusing "signature invalid" error later.
    const uint8_t* cursor = anchor.public_key_der.data();
    PkeyPtr parsed(EVP_parse_public_key(&cursor, anchor.public_key_der.size()));
    if (parsed == nullptr) {
      problems.push_back("trust anchor " + anchor.key_id +
                         ": public key is not a valid DER SubjectPublicKeyInfo");
      continue;
    }
    if (anchor.algorithm == kAlgorithmEd25519 && EVP_PKEY_id(parsed.get()) != EVP_PKEY_ED25519) {
      problems.push_back("trust anchor " + anchor.key_id + " declares ED25519 but the key is not");
      continue;
    }
    if (anchor.algorithm == kAlgorithmRsa4096Sha256 && EVP_PKEY_id(parsed.get()) != EVP_PKEY_RSA) {
      problems.push_back("trust anchor " + anchor.key_id + " declares RSA but the key is not");
      continue;
    }
    if (anchor.algorithm == kAlgorithmRsa4096Sha256 && EVP_PKEY_bits(parsed.get()) < 4096) {
      problems.push_back(android::base::StringPrintf(
          "trust anchor %s: RSA key is %d bits, below the 4096 bit minimum", anchor.key_id.c_str(),
          EVP_PKEY_bits(parsed.get())));
      continue;
    }

    const Json::Value& min_version = entry["min_security_version"];
    anchor.min_security_version = min_version.isIntegral() ? min_version.asInt() : 0;
    const Json::Value& enabled = entry["enabled"];
    anchor.enabled = enabled.isBool() ? enabled.asBool() : true;
    if (anchor.enabled) {
      ++enabled_count;
    }
    anchors_.push_back(std::move(anchor));
  }

  if (!problems.empty()) {
    for (const std::string& problem : problems) {
      fail(problem);
    }
    return false;
  }
  if (enabled_count == 0) {
    return fail("every trust anchor in " + trust_config_ + " is disabled: failing closed");
  }
  LOG(INFO) << "xrom_avfd: loaded " << enabled_count << " enabled payload trust anchor(s) from "
            << trust_config_;
  return true;
}

bool PayloadVerifier::LoadTrustAnchors() { return LoadTrustAnchors(nullptr); }

bool PayloadVerifier::VerifySignature(const TrustAnchor& anchor, const std::string& message,
                                      const std::vector<uint8_t>& signature,
                                      std::string* detail) const {
  const uint8_t* cursor = anchor.public_key_der.data();
  PkeyPtr key(EVP_parse_public_key(&cursor, anchor.public_key_der.size()));
  if (key == nullptr) {
    *detail = "the anchor's public key could not be parsed";
    return false;
  }

  MdCtxPtr ctx(EVP_MD_CTX_new());
  if (ctx == nullptr) {
    *detail = "out of memory allocating a digest context";
    return false;
  }

  // Ed25519 is a pre-hashed-by-construction scheme: BoringSSL requires the
  // EVP_MD argument to be NULL and only the one-shot EVP_DigestVerify form.
  // RSA uses RSASSA-PKCS1-v1_5 over SHA-256, matching the signing tool.
  const EVP_MD* md = nullptr;
  if (anchor.algorithm == kAlgorithmRsa4096Sha256) {
    md = EVP_sha256();
  }
  if (EVP_DigestVerifyInit(ctx.get(), nullptr, md, nullptr, key.get()) != 1) {
    *detail = "EVP_DigestVerifyInit failed for algorithm " + anchor.algorithm;
    return false;
  }
  const int result = EVP_DigestVerify(
      ctx.get(), signature.data(), signature.size(),
      reinterpret_cast<const uint8_t*>(message.data()), message.size());
  if (result != 1) {
    *detail = "the signature does not verify over the manifest bytes";
    return false;
  }
  return true;
}

bool PayloadVerifier::Verify(const VmSpec& spec, VerifiedPayload* out,
                             std::vector<std::string>* errors) {
  if (out == nullptr || errors == nullptr) {
    LOG(ERROR) << "xrom_avfd: PayloadVerifier::Verify called with a null output";
    return false;
  }
  *out = VerifiedPayload{};
  const auto fail = [errors](const std::string& message) {
    LOG(ERROR) << "xrom_avfd: payload verification failed: " << message;
    errors->push_back(message);
  };

  // Reload when the spec names a different trust config than the one the anchors
  // were loaded from, and when nothing has been loaded yet. Trusting a cached
  // anchor set against a spec that pointed somewhere else would let the two
  // disagree silently.
  if (anchors_.empty() || spec.trust_config_path != trust_config_) {
    trust_config_ = spec.trust_config_path;
    if (!LoadTrustAnchors(errors)) {
      return false;
    }
  }

  // --- 1. read the manifest and its detached signature --------------------
  std::string manifest_bytes;
  std::string error;
  if (!ReadCappedFile(spec.payload_manifest_path, kMaxManifestBytes, &manifest_bytes, &error)) {
    fail(error);
    return false;
  }
  std::string signature_b64;
  if (!ReadCappedFile(spec.payload_manifest_sig_path, 2 * kMaxSignatureBytes, &signature_b64,
                      &error)) {
    fail(error);
    return false;
  }

  // --- 2. parse just enough to find out which key to use ------------------
  Json::Value root;
  if (!ParseJsonObject(manifest_bytes, spec.payload_manifest_path, &root, &error)) {
    fail(error);
    return false;
  }
  const Json::Value& key_id = root["key_id"];
  const Json::Value& algorithm = root["signature_algorithm"];
  if (!key_id.isString() || !algorithm.isString()) {
    fail("the manifest has no string key_id or signature_algorithm");
    return false;
  }

  // The anchor is selected by id AND algorithm. Requiring both stops a manifest
  // from downgrading an Ed25519 anchor to a weaker scheme.
  const TrustAnchor* anchor = FindAnchor(key_id.asString(), algorithm.asString());
  if (anchor == nullptr) {
    fail("no enabled trust anchor for key_id=" + key_id.asString() +
         " algorithm=" + algorithm.asString());
    return false;
  }

  // --- 3. verify the signature over the exact manifest bytes --------------
  std::vector<uint8_t> signature;
  if (!DecodeBase64(signature_b64, &signature, kMaxSignatureBytes, &error)) {
    fail("manifest signature: " + error);
    return false;
  }
  if (signature.empty()) {
    fail("manifest signature is empty");
    return false;
  }
  std::string detail;
  if (!VerifySignature(*anchor, manifest_bytes, signature, &detail)) {
    fail("manifest signature rejected (key_id=" + anchor->key_id + "): " + detail);
    return false;
  }

  // --- 4. parse and structurally validate ---------------------------------
  PayloadManifest manifest;
  manifest.manifest_version =
      root["manifest_version"].isIntegral() ? root["manifest_version"].asInt() : 0;
  const auto as_string = [&root](const char* key) {
    return root[key].isString() ? root[key].asString() : std::string();
  };
  const auto as_int64 = [&root](const char* key) -> int64_t {
    return root[key].isIntegral() ? root[key].asInt64() : 0;
  };
  manifest.payload_name = as_string("payload_name");
  manifest.payload_apk_filename = as_string("payload_apk_filename");
  manifest.payload_library = as_string("payload_library");
  manifest.signature_algorithm = as_string("signature_algorithm");
  manifest.key_id = as_string("key_id");
  manifest.issued_at_unix = as_int64("issued_at_unix");
  manifest.not_after_unix = as_int64("not_after_unix");
  manifest.security_version = root["security_version"].isIntegral()
                                  ? root["security_version"].asInt()
                                  : 0;

  const Json::Value& classes = root["allowed_task_classes"];
  if (classes.isArray()) {
    for (const Json::Value& value : classes) {
      if (value.isIntegral()) {
        manifest.allowed_task_classes.push_back(value.asInt());
      }
    }
  }

  Sha256Digest digest{};
  // Sha256::FromHex is strict about length and alphabet, which is what a pinned
  // digest needs: a short or non-hex value must be a hard error, not a truncated
  // digest that happens to compare equal to something else.
  const auto parse_digest = [&digest](const Json::Value& value, Sha256Digest* out) {
    return value.isString() && Sha256::FromHex(value.asString(), out);
  };
  if (!parse_digest(root["apk_sha256"], &digest)) {
    fail("apk_sha256 is not 64 hex characters");
    return false;
  }
  manifest.apk_sha256 = digest;
  if (!parse_digest(root["vm_config_sha256"], &digest)) {
    fail("vm_config_sha256 is not 64 hex characters");
    return false;
  }
  manifest.vm_config_sha256 = digest;
  if (!parse_digest(root["payload_lib_sha256"], &digest)) {
    fail("payload_lib_sha256 is not 64 hex characters");
    return false;
  }
  manifest.payload_lib_sha256 = digest;

  for (const std::string& problem : manifest.Validate()) {
    fail("manifest: " + problem);
  }
  if (!errors->empty()) {
    return false;
  }

  // --- 5. anti-rollback ---------------------------------------------------
  if (manifest.security_version < anchor->min_security_version) {
    fail(android::base::StringPrintf(
        "manifest security_version %d is below the %d required by anchor %s",
        manifest.security_version, anchor->min_security_version, anchor->key_id.c_str()));
    return false;
  }

  // --- 6. validity window -------------------------------------------------
  const int64_t now = NowUnix();
  if (manifest.IsNotYetValid(now)) {
    fail("manifest is not valid yet (issued_at_unix is in the future)");
    return false;
  }
  if (manifest.IsExpired(now)) {
    fail("manifest has expired");
    return false;
  }

  // --- 7. the APK on disk must be the pinned APK --------------------------
  // Recomputed here, at launch time, over the bytes the daemon is about to hand
  // to AVF. Pinning this in the manifest rather than trusting AVF alone is what
  // distinguishes "an APK this ROM signed" from "an APK X-ROM chose to ship".
  Sha256Digest apk_digest{};
  if (!Sha256::HashFile(spec.payload_apk_path, &apk_digest, &error)) {
    fail("cannot measure " + spec.payload_apk_path + ": " + error);
    return false;
  }
  if (apk_digest != manifest.apk_sha256) {
    fail("sha256(" + spec.payload_apk_path + ") does not match the pinned apk_sha256");
    return false;
  }

  out->manifest = std::move(manifest);
  out->apk_sha256_recomputed = apk_digest;
  out->anchor_key_id = anchor->key_id;
  out->verified_at_unix = now;
  LOG(INFO) << "xrom_avfd: payload manifest verified: " << out->manifest.ToString();
  return true;
}

}  // namespace xrom::avf
