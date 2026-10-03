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

#include "OtaVerifier.h"

#include <cstring>

namespace xrom::ota {
namespace {

constexpr size_t kMaxDerBytes = 4096;

// Reads a DER tag and definite-form length. Returns false on anything this file
// does not understand, including indefinite length and overlong length encodings:
// a parser that accepts two encodings of the same length is a parser whose idea of
// where a field ends can be made to differ from the crypto library's.
bool ReadDerHeader(const uint8_t* data, size_t size, size_t* offset, uint8_t* tag,
                   size_t* content_length) {
  if (*offset + 2 > size) {
    return false;
  }
  *tag = data[*offset];
  uint8_t first = data[*offset + 1];
  *offset += 2;
  if ((first & 0x80) == 0) {
    *content_length = first;
    return true;
  }
  const size_t num_bytes = first & 0x7F;
  if (num_bytes == 0 || num_bytes > 4 || *offset + num_bytes > size) {
    // num_bytes == 0 is indefinite length, which is not valid DER.
    return false;
  }
  size_t length = 0;
  for (size_t i = 0; i < num_bytes; ++i) {
    length = (length << 8) | data[*offset + i];
  }
  *offset += num_bytes;
  // Reject a multi-byte encoding that could have been written shorter. Not a
  // security hole on its own, but accepting it means two different byte strings
  // describe the same structure, and that is the kind of ambiguity this parser
  // exists to refuse.
  if (length < 0x80 || (num_bytes == 2 && length < 0x100) ||
      (num_bytes == 3 && length < 0x10000) || (num_bytes == 4 && length < 0x1000000)) {
    return false;
  }
  *content_length = length;
  return true;
}

bool ContainsBytes(const uint8_t* haystack, size_t haystack_size, const uint8_t* needle,
                   size_t needle_size) {
  if (needle_size > haystack_size) {
    return false;
  }
  for (size_t i = 0; i + needle_size <= haystack_size; ++i) {
    if (std::memcmp(haystack + i, needle, needle_size) == 0) {
      return true;
    }
  }
  return false;
}

// Bit length of a DER INTEGER's value, given its content bytes. A leading 0x00 is
// a sign pad and does not count.
uint32_t DerIntegerBits(const uint8_t* content, size_t length) {
  size_t i = 0;
  while (i + 1 < length && content[i] == 0x00) {
    ++i;
  }
  if (i >= length) {
    return 0;
  }
  const uint8_t top = content[i];
  uint32_t top_bits = 0;
  for (uint32_t b = 8; b > 0; --b) {
    if ((top >> (b - 1)) & 0x01) {
      top_bits = b;
      break;
    }
  }
  return static_cast<uint32_t>((length - i - 1) * 8 + top_bits);
}

// Walks an RSA SPKI far enough to report the modulus size.
// SEQUENCE { SEQUENCE { OID, NULL }, BIT STRING { SEQUENCE { INTEGER n, INTEGER e } } }
uint32_t RsaModulusBits(const uint8_t* der, size_t size) {
  size_t offset = 0;
  uint8_t tag = 0;
  size_t length = 0;

  if (!ReadDerHeader(der, size, &offset, &tag, &length) || tag != 0x30) {
    return 0;
  }
  if (offset + length > size) {
    return 0;
  }
  const size_t spki_end = offset + length;

  // AlgorithmIdentifier
  if (!ReadDerHeader(der, spki_end, &offset, &tag, &length) || tag != 0x30) {
    return 0;
  }
  offset += length;  // skip it; the OID was already located by the caller

  // BIT STRING holding the RSAPublicKey
  if (!ReadDerHeader(der, spki_end, &offset, &tag, &length) || tag != 0x03) {
    return 0;
  }
  if (length < 1 || offset + length > spki_end) {
    return 0;
  }
  if (der[offset] != 0x00) {
    return 0;  // unused bits must be zero for a DER BIT STRING wrapping a SEQUENCE
  }
  const uint8_t* inner = der + offset + 1;
  const size_t inner_size = length - 1;

  size_t inner_offset = 0;
  if (!ReadDerHeader(inner, inner_size, &inner_offset, &tag, &length) || tag != 0x30) {
    return 0;
  }
  if (inner_offset + length > inner_size) {
    return 0;
  }
  const size_t seq_end = inner_offset + length;

  if (!ReadDerHeader(inner, seq_end, &inner_offset, &tag, &length) || tag != 0x02) {
    return 0;
  }
  if (inner_offset + length > seq_end) {
    return 0;
  }
  return DerIntegerBits(inner + inner_offset, length);
}

bool StartsWithPrefix(const std::string& der, const uint8_t* prefix, size_t prefix_size) {
  return der.size() >= prefix_size &&
         std::memcmp(der.data(), prefix, prefix_size) == 0;
}

std::string ToLower(const std::string& value) {
  std::string out = value;
  for (char& c : out) {
    if (c >= 'A' && c <= 'Z') {
      c = static_cast<char>(c - 'A' + 'a');
    }
  }
  return out;
}

}  // namespace

const char* SignatureAlgorithmName(SignatureAlgorithm algorithm) {
  switch (algorithm) {
    case SignatureAlgorithm::kEd25519:
      return "ED25519";
    case SignatureAlgorithm::kRsa4096Sha256:
      return "RSA4096_SHA256";
  }
  return "INVALID";
}

const char* OtaStageName(OtaStage stage) {
  switch (stage) {
    case OtaStage::kManifestSignature:
      return "manifest-signature";
    case OtaStage::kManifestFormat:
      return "manifest-format";
    case OtaStage::kAntiRollback:
      return "anti-rollback";
    case OtaStage::kValidityWindow:
      return "validity-window";
    case OtaStage::kSizeCeiling:
      return "size-ceiling";
    case OtaStage::kFetch:
      return "fetch";
    case OtaStage::kPackageDigest:
      return "package-digest";
    case OtaStage::kInstall:
      return "install";
    case OtaStage::kHashtreeRoot:
      return "hashtree-root";
  }
  return "invalid";
}

const char* OtaVerdictName(OtaVerdict verdict) {
  switch (verdict) {
    case OtaVerdict::kProceed:
      return "proceed";
    case OtaVerdict::kRejectToVault:
      return "reject-to-vault";
  }
  return "invalid";
}

AnchorValidation ValidateAnchor(const OtaKeyAnchor& anchor) {
  AnchorValidation result;

  if (anchor.key_id.empty() || anchor.key_id.size() > kMaxKeyIdLength) {
    result.ok = false;
    result.reason = "key_id must be 1.." + std::to_string(kMaxKeyIdLength) + " characters";
    return result;
  }
  if (anchor.public_key_der.empty()) {
    result.ok = false;
    result.reason = "public_key_der is empty";
    return result;
  }
  if (anchor.public_key_der.size() > kMaxDerBytes) {
    result.ok = false;
    result.reason = "public_key_der is implausibly large";
    return result;
  }

  const uint8_t* der = reinterpret_cast<const uint8_t*>(anchor.public_key_der.data());
  const size_t size = anchor.public_key_der.size();

  if (anchor.algorithm == SignatureAlgorithm::kEd25519) {
    // An Ed25519 SPKI is a fixed 44 bytes with a fixed prefix. Anything else is
    // not an Ed25519 public key, whatever the entry claims.
    if (size != kDerSpkiEd25519Length ||
        !StartsWithPrefix(anchor.public_key_der, kDerSpkiEd25519Prefix,
                          sizeof(kDerSpkiEd25519Prefix))) {
      result.ok = false;
      result.reason = "public_key_der is not a 44-byte Ed25519 SubjectPublicKeyInfo";
      return result;
    }
    result.ok = true;
    return result;
  }

  if (!ContainsBytes(der, size, kDerSpkiRsaOid, sizeof(kDerSpkiRsaOid))) {
    result.ok = false;
    result.reason = "public_key_der does not contain the rsaEncryption OID";
    return result;
  }
  const uint32_t bits = RsaModulusBits(der, size);
  if (bits == 0) {
    result.ok = false;
    result.reason = "the RSA modulus could not be parsed out of public_key_der";
    return result;
  }
  if (bits < kMinRsaModulusBits) {
    result.ok = false;
    result.reason = "the RSA modulus is " + std::to_string(bits) + " bits, below the " +
                    std::to_string(kMinRsaModulusBits) + " bit floor";
    return result;
  }
  result.ok = true;
  return result;
}

std::string SignatureVerification::Describe() const {
  std::string out = ok ? "signatures verified" : "signature verification failed";
  out += " [ed25519=";
  out += ed25519_satisfied ? "yes" : "no";
  out += " rsa=";
  out += rsa_satisfied ? "yes" : "no";
  out += "]";
  if (!problems.empty()) {
    out += ": ";
    for (size_t i = 0; i < problems.size(); ++i) {
      if (i != 0) {
        out += "; ";
      }
      out += problems[i];
    }
  }
  return out;
}

SignatureVerification VerifySignatures(SignatureBackend* backend,
                                       const std::vector<OtaKeyAnchor>& anchors,
                                       const std::vector<DetachedSignature>& signatures,
                                       const std::string& artifact,
                                       const DualSignaturePolicy& policy) {
  SignatureVerification result;

  if (backend == nullptr) {
    result.problems.push_back("no signature backend");
    return result;
  }
  if (artifact.empty()) {
    // Signing an empty artifact is not a thing that should ever be offered. A
    // backend that verifies it is a backend that will verify anything.
    result.problems.push_back("the artifact to verify is empty");
    return result;
  }
  if (signatures.empty()) {
    result.problems.push_back("no detached signatures were supplied");
    return result;
  }
  if (anchors.empty()) {
    // Zero anchors means the device has no idea whose signature to accept. Failing
    // closed here is the difference between "trust nothing" and "trust whatever
    // arrives", and the configuration mistake that produces it should be loud.
    result.problems.push_back("no key anchors are configured; failing closed");
    return result;
  }

  for (const DetachedSignature& signature : signatures) {
    const char* algorithm_name = SignatureAlgorithmName(signature.algorithm);
    if (signature.signature.empty()) {
      result.problems.push_back(std::string("the ") + algorithm_name + " signature is empty");
      continue;
    }

    // Selected by key_id AND algorithm. See the header for why either alone is a
    // different and worse policy.
    const OtaKeyAnchor* match = nullptr;
    for (const OtaKeyAnchor& anchor : anchors) {
      if (anchor.key_id == signature.key_id && anchor.algorithm == signature.algorithm) {
        match = &anchor;
        break;
      }
    }
    if (match == nullptr) {
      result.problems.push_back(std::string("no anchor matches key_id '") + signature.key_id +
                                "' with algorithm " + algorithm_name);
      continue;
    }
    if (!match->enabled) {
      result.problems.push_back("anchor '" + match->key_id + "' is disabled");
      continue;
    }
    const AnchorValidation anchor_check = ValidateAnchor(*match);
    if (!anchor_check.ok) {
      // Dropped at verification time rather than at load time only because the
      // anchors arrive already parsed; the effect is the same, and the log says why
      // instead of reporting a bare signature failure.
      result.problems.push_back("anchor '" + match->key_id + "' is unusable: " +
                                anchor_check.reason);
      continue;
    }

    const BackendResult verified =
        backend->Verify(match->algorithm, match->public_key_der, artifact, signature.signature);
    if (!verified.verified) {
      result.problems.push_back(std::string("the ") + algorithm_name + " signature over the " +
                                "manifest did not verify under anchor '" + match->key_id + "'" +
                                (verified.detail.empty() ? "" : (": " + verified.detail)));
      continue;
    }

    if (match->algorithm == SignatureAlgorithm::kEd25519) {
      result.ed25519_satisfied = true;
    } else {
      result.rsa_satisfied = true;
    }
    // Anti-rollback is enforced from the anchor, never from the manifest, so the
    // highest floor among the anchors that actually matched is the one that
    // applies. A manifest cannot lower it by naming a different key.
    if (match->min_security_version > result.effective_min_security_version) {
      result.effective_min_security_version = match->min_security_version;
    }
    bool already_listed = false;
    for (const std::string& id : result.satisfied_key_ids) {
      if (id == match->key_id) {
        already_listed = true;
        break;
      }
    }
    if (!already_listed) {
      result.satisfied_key_ids.push_back(match->key_id);
    }
  }

  const bool dual_ok = result.ed25519_satisfied && result.rsa_satisfied;
  const bool single_ok = result.ed25519_satisfied || result.rsa_satisfied;

  if (policy.require_dual && !dual_ok) {
    // Spelled out rather than reported as a bare failure, because "one of two
    // signatures was missing" and "both were present and one did not verify" have
    // completely different causes: the first is a serving or packaging bug, the
    // second is an attack or a key rotation that went wrong.
    std::string missing;
    if (!result.ed25519_satisfied && !result.rsa_satisfied) {
      missing = "neither signature verified";
    } else if (!result.ed25519_satisfied) {
      missing = "the Ed25519 signature is missing or did not verify";
    } else {
      missing = "the RSA-4096 signature is missing or did not verify";
    }
    result.problems.push_back("dual signature is required but " + missing);
    result.ok = false;
    return result;
  }
  if (!policy.require_dual && !single_ok) {
    result.problems.push_back("no signature verified");
    result.ok = false;
    return result;
  }
  if (policy.require_distinct_keys && dual_ok && result.satisfied_key_ids.size() < 2) {
    result.problems.push_back(
        "both signatures verified under the same key, which is one key counted "
        "twice rather than two independent signatures");
    result.ok = false;
    return result;
  }

  result.ok = true;
  return result;
}

StageResult AuthorizeDownload(const std::vector<OtaKeyAnchor>& anchors, SignatureBackend* backend,
                              const std::string& manifest_bytes,
                              const std::vector<DetachedSignature>& signatures,
                              const OtaManifest& parsed, const VerifierPolicy& policy) {
  StageResult result;

  // --- stage 1: the signatures ------------------------------------------------
  //
  // Before anything in the manifest is treated as data. A manifest that has not
  // been signed by the pinned keys is not a document to be interpreted, it is
  // bytes from a network the recovery engine has only provisionally decided to
  // trust.
  result.stage = OtaStage::kManifestSignature;
  const SignatureVerification verification =
      VerifySignatures(backend, anchors, signatures, manifest_bytes, policy.signatures);
  if (!verification.ok) {
    result.verdict = OtaVerdict::kRejectToVault;
    result.reason = verification.Describe();
    return result;
  }

  // --- stage 2: the format, and whether the parse is faithful ------------------
  result.stage = OtaStage::kManifestFormat;

  // Re-serialising the parsed manifest and comparing to the bytes that were signed
  // is the check that catches a JSON layer disagreeing with itself: duplicate keys,
  // a number parsed into the wrong width, a field the parser silently dropped. The
  // signature covers manifest_bytes, so manifest_bytes is what has to correspond
  // to the structure being acted on.
  const std::string reserialized = parsed.Serialize();
  if (reserialized != manifest_bytes) {
    result.verdict = OtaVerdict::kRejectToVault;
    result.reason =
        "the parsed manifest does not re-serialise to the bytes that were signed "
        "(" + std::to_string(manifest_bytes.size()) + " signed vs " +
        std::to_string(reserialized.size()) +
        " re-serialised); refusing to act on a parse that is not faithful to the "
        "signed artifact";
    return result;
  }

  const OtaManifestValidation format = Validate(parsed);
  if (!format.ok) {
    result.verdict = OtaVerdict::kRejectToVault;
    result.reason = "the signed manifest is not well formed: " + format.Describe();
    return result;
  }

  if (policy.enforce_target_fingerprint &&
      parsed.target_fingerprint != policy.running_fingerprint) {
    result.verdict = OtaVerdict::kRejectToVault;
    result.reason = "the package targets " + parsed.target_fingerprint +
                    " but the running build is " + policy.running_fingerprint +
                    "; applying it would produce an image built on a base it was "
                    "never signed for";
    return result;
  }

  // --- stage 3: anti-rollback --------------------------------------------------
  result.stage = OtaStage::kAntiRollback;
  if (parsed.security_version <= verification.effective_min_security_version) {
    result.verdict = OtaVerdict::kRejectToVault;
    result.reason = "the package's security_version " +
                    std::to_string(parsed.security_version) +
                    " does not exceed the pinned floor " +
                    std::to_string(verification.effective_min_security_version) +
                    "; a validly signed old package is what a downgrade attack "
                    "presents";
    return result;
  }
  if (parsed.security_version <= policy.installed_security_version) {
    result.verdict = OtaVerdict::kRejectToVault;
    result.reason = "the package's security_version " +
                    std::to_string(parsed.security_version) +
                    " does not exceed the installed " +
                    std::to_string(policy.installed_security_version);
    return result;
  }

  // --- stage 4: the validity window --------------------------------------------
  result.stage = OtaStage::kValidityWindow;
  if (policy.now_unix <= 0) {
    // No clock, no window check. Proceeding would mean accepting a manifest that
    // expired years ago, and a device in recovery has just come out of a reboot
    // that may well have been caused by a flat battery — exactly the state in
    // which the clock is wrong. Refusing is the fail-secure choice and it is also
    // the recoverable one: the vault path needs no clock at all.
    result.verdict = OtaVerdict::kRejectToVault;
    result.reason =
        "the current time is unknown, so the manifest's validity window cannot be "
        "checked; refusing rather than accepting a package that may have expired";
    return result;
  }
  if (policy.now_unix < parsed.issued_at_unix) {
    result.verdict = OtaVerdict::kRejectToVault;
    result.reason = "the manifest claims to have been issued in the future (" +
                    std::to_string(parsed.issued_at_unix) + " > now " +
                    std::to_string(policy.now_unix) +
                    "), which means either the device clock is wrong or the "
                    "manifest was not produced by the signing tool";
    return result;
  }
  if (policy.now_unix > parsed.not_after_unix) {
    result.verdict = OtaVerdict::kRejectToVault;
    result.reason = "the manifest expired at " + std::to_string(parsed.not_after_unix) +
                    " and it is now " + std::to_string(policy.now_unix);
    return result;
  }

  // --- stage 5: the size ceiling and the battery floor --------------------------
  //
  // Last of the pre-download checks and the only one that is about capacity rather
  // than authenticity. Everything above this line is cheap; the next step is not.
  result.stage = OtaStage::kSizeCeiling;
  const SizeDecision size = DecidePackageSize(parsed.package_bytes, policy.max_package_bytes);
  if (!size.accepted) {
    result.verdict = OtaVerdict::kRejectToVault;
    result.reason = size.reason;
    return result;
  }
  if (policy.battery_percent < parsed.min_battery_percent) {
    result.verdict = OtaVerdict::kRejectToVault;
    result.reason = "the battery is at " + std::to_string(policy.battery_percent) +
                    "% and the manifest requires " +
                    std::to_string(parsed.min_battery_percent) +
                    "%; an install that dies mid-write leaves the device with "
                    "neither its old image nor a new one";
    return result;
  }

  result.stage = OtaStage::kSizeCeiling;
  result.verdict = OtaVerdict::kProceed;

  // Joined rather than indexed: under a single-signature policy there is only one
  // satisfied key, and reading [1] unconditionally would be an out-of-bounds read
  // on exactly the path that is least often exercised.
  std::string keys;
  for (size_t i = 0; i < verification.satisfied_key_ids.size(); ++i) {
    if (i != 0) {
      keys += ", ";
    }
    keys += verification.satisfied_key_ids[i];
  }
  result.reason = std::string(policy.signatures.require_dual ? "both signatures" : "a signature") +
                  " verified under the pinned key(s) (" + keys +
                  "), the manifest is well formed and applies to this build, security_version " +
                  std::to_string(parsed.security_version) +
                  " is current, the window is open, and " +
                  std::to_string(parsed.package_bytes) + " bytes is within the ceiling";
  return result;
}

StageResult CheckDeliveredPackage(const OtaManifest& manifest, uint64_t received_bytes,
                                  const std::string& delivered_sha256_hex,
                                  const VerifierPolicy& policy) {
  StageResult result;

  // Length first. A short download is detectable without hashing anything, and
  // hashing a truncated file only to report a digest mismatch sends the operator
  // looking for tampering when the actual problem was a dropped connection.
  result.stage = OtaStage::kFetch;
  if (received_bytes != manifest.package_bytes) {
    result.verdict = OtaVerdict::kRejectToVault;
    result.reason = "received " + std::to_string(received_bytes) + " bytes but the manifest " +
                    "declared " + std::to_string(manifest.package_bytes);
    return result;
  }
  // Re-check the ceiling against what actually arrived rather than only against
  // what was declared. The length check above cannot catch this case, because the
  // length is exactly what the manifest said; it fires when the ceiling itself was
  // tightened between authorising the download and checking it, or when this stage
  // is entered without going through AuthorizeDownload at all.
  if (policy.max_package_bytes != 0 && received_bytes > policy.max_package_bytes) {
    result.verdict = OtaVerdict::kRejectToVault;
    result.reason = "received " + std::to_string(received_bytes) +
                    " bytes, above the ceiling, despite a compliant declaration";
    return result;
  }

  result.stage = OtaStage::kPackageDigest;
  if (delivered_sha256_hex.empty()) {
    result.verdict = OtaVerdict::kRejectToVault;
    result.reason = "no digest was computed for the delivered package";
    return result;
  }
  if (ToLower(delivered_sha256_hex) != ToLower(manifest.package_sha256)) {
    result.verdict = OtaVerdict::kRejectToVault;
    result.reason = "the delivered package hashes to " + ToLower(delivered_sha256_hex) +
                    " but the signed manifest declared " + ToLower(manifest.package_sha256);
    return result;
  }

  result.verdict = OtaVerdict::kProceed;
  result.reason = "the delivered package matches the declared length and digest";
  return result;
}

StageResult CheckInstalledImage(const OtaManifest& manifest,
                                const std::string& produced_hashtree_root_hex,
                                const VerifierPolicy& policy) {
  StageResult result;
  result.stage = OtaStage::kHashtreeRoot;
  (void)policy;

  if (produced_hashtree_root_hex.empty()) {
    result.verdict = OtaVerdict::kRejectToVault;
    result.reason =
        "the installer did not report a hashtree root for the image it produced, "
        "so there is nothing to compare against the manifest";
    return result;
  }
  if (ToLower(produced_hashtree_root_hex) != ToLower(manifest.expected_hashtree_root_sha256)) {
    result.verdict = OtaVerdict::kRejectToVault;
    result.reason = "the installed image's hashtree root is " +
                    ToLower(produced_hashtree_root_hex) + " but the signed manifest " +
                    "promised " + ToLower(manifest.expected_hashtree_root_sha256) +
                    "; the package verified and installed, and still produced an "
                    "image that was not the one that was signed";
    return result;
  }

  result.verdict = OtaVerdict::kProceed;
  result.reason = "the installed image matches the hashtree root the manifest promised";
  return result;
}

}  // namespace xrom::ota
