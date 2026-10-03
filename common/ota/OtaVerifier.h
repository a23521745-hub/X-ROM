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

#ifndef XROM_OTA_OTA_VERIFIER_H_
#define XROM_OTA_OTA_VERIFIER_H_

#include <cstdint>
#include <string>
#include <vector>

#include "OtaManifest.h"

namespace xrom::ota {

// ---------------------------------------------------------------------------
// The order in which an OTA is accepted, and what each refusal costs.
//
// WHY ORDER IS THE SECURITY PROPERTY HERE
// ---------------------------------------
// Every check in this file is individually simple. What makes the sequence safe is
// that nothing expensive or irreversible happens before everything cheap and
// decisive has already passed. Concretely:
//
//   1. both detached signatures over the manifest are verified, before a single
//      field of the manifest is read as data;
//   2. the manifest's own format is validated, because a signed manifest is still
//      a manifest and a signing key that was used carelessly signs careless
//      content;
//   3. anti-rollback and the validity window are checked against the pinned
//      anchors, not against the manifest's own claims;
//   4. the declared size is checked against the ceiling — before any byte of the
//      package is fetched, because fetching is the expensive part and a 4 GB
//      package on a metered link is a cost the device pays before discovering it
//      cannot install it;
//   5. only then is the download authorised;
//   6. the delivered bytes are checked against the declared digest and the
//      declared length, as they arrive and again at the end;
//   7. after the write, the resulting image's hashtree root is checked against the
//      manifest's expectation, because a package can verify, install cleanly, and
//      still produce an image that is not the one that was signed.
//
// A refusal at any step sends the device to the vault. There is no partial
// acceptance: a manifest that fails step 4 is not "installed anyway with a
// warning", because the vault exists precisely so that refusing is free.
//
// WHAT DUAL SIGNATURE DOES AND DOES NOT BUY
// -----------------------------------------
// Requiring both an Ed25519 and an RSA-4096 signature over the same bytes is an
// AND, and it is worth being honest about what an AND defends against. It does not
// defend against "Ed25519 being broken" in any practical sense: if the elliptic
// curve primitives fail, the RSA key is protecting a verification path that has
// already been shown to be fragile, and an attacker with that capability has
// better options than forging an OTA. What it does defend against is the two
// failures that actually happen — a bug in one verification path, and the
// compromise of one signing key. Those are independent, they are common, and an
// AND over two different implementations and two different key ceremonies closes
// both.
//
// The cost is real and should be stated rather than buried: two keys, two
// ceremonies, two rotation schedules, and a signing tool that fails if either one
// is missing. That is why it is policy (require_dual_signature) and not hardcoded,
// and why the default is on for a ROM whose whole premise is that the update path
// is the last thing an attacker should be able to touch.
//
// KEYS ARE COMPILED IN AND NEVER LOADED AT RUNTIME
// ------------------------------------------------
// The anchors below carry DER public keys that are embedded in the image at build
// time. There is no code path that adds an anchor from a file fetched over the
// network, from a partition that the OTA itself writes, or from a system property.
// A runtime-loadable trust anchor is not a trust anchor; it is a suggestion.
// ---------------------------------------------------------------------------

enum class SignatureAlgorithm : int32_t {
  kEd25519 = 0,
  kRsa4096Sha256 = 1,
};

const char* SignatureAlgorithmName(SignatureAlgorithm algorithm);

// DER SubjectPublicKeyInfo prefixes, matched byte for byte. Used to reject an
// anchor whose key is not the algorithm its entry claims, which is the mistake
// that turns "verify with Ed25519" into "verify with whatever this blob is".
constexpr uint8_t kDerSpkiEd25519Prefix[] = {0x30, 0x2a, 0x30, 0x05, 0x06, 0x03,
                                             0x2b, 0x65, 0x70, 0x03, 0x21, 0x00};
constexpr size_t kDerSpkiEd25519Length = 44;

// The RSA OID 1.2.840.113549.1.1.1 as it appears in an RSA SPKI.
constexpr uint8_t kDerSpkiRsaOid[] = {0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
                                      0xf7, 0x0d, 0x01, 0x01, 0x01};
constexpr uint32_t kMinRsaModulusBits = 4096;

struct OtaKeyAnchor {
  std::string key_id;
  SignatureAlgorithm algorithm = SignatureAlgorithm::kEd25519;
  // DER SubjectPublicKeyInfo, exactly as it will be handed to the crypto backend.
  std::string public_key_der;
  bool enabled = true;
  // Refuses packages at or below this version even when the signature is valid.
  uint32_t min_security_version = 0;
};

// Whether an anchor is structurally acceptable: non-empty id, DER that matches the
// claimed algorithm, and an RSA modulus of at least 4096 bits. Pure byte
// inspection, no crypto library, so it runs on the host and so a malformed anchor
// is dropped at load rather than at the moment it is needed.
struct AnchorValidation {
  bool ok = false;
  std::string reason;
};
AnchorValidation ValidateAnchor(const OtaKeyAnchor& anchor);

// --- the crypto seam ---------------------------------------------------------

struct BackendResult {
  bool verified = false;
  std::string detail;
};

// Implemented with BoringSSL's EVP_DigestVerify in the production adapter, and
// with a fake in tests. Keeping verification behind one method means the entire
// ordering above — including the branches that only fire when a signature fails —
// can be exercised on a build host, which is the only place it will ever be
// exercised before it runs on a device in recovery.
class SignatureBackend {
 public:
  virtual ~SignatureBackend() = default;
  virtual BackendResult Verify(SignatureAlgorithm algorithm, const std::string& public_key_der,
                               const std::string& artifact, const std::string& signature) = 0;
};

struct DetachedSignature {
  SignatureAlgorithm algorithm = SignatureAlgorithm::kEd25519;
  std::string key_id;
  // Raw signature bytes, not hex: Ed25519 is 64 bytes, RSA-4096 PKCS#1 v1.5 is
  // 512. The file on disk is hex or base64; the adapter decodes it.
  std::string signature;
};

struct DualSignaturePolicy {
  // Both signatures required. When false, either one suffices — which is what a
  // device in the middle of migrating from a single key to a dual key needs, and
  // nothing else.
  bool require_dual = true;
  // The two signatures must come from different keys. Two Ed25519 signatures from
  // the same key are one signature counted twice.
  bool require_distinct_keys = true;
};

struct SignatureVerification {
  bool ok = false;
  // Which algorithms were satisfied, so that a failure says which half is missing
  // rather than reporting a bare false.
  bool ed25519_satisfied = false;
  bool rsa_satisfied = false;
  std::vector<std::string> problems;

  // The key_ids whose signature verified. Two entries means two independent keys
  // were satisfied, which is what require_distinct_keys is checking.
  std::vector<std::string> satisfied_key_ids;

  // The highest min_security_version among the anchors that actually matched.
  // Anti-rollback is enforced from the pinned anchors and never from the manifest,
  // so the caller needs this value back: a manifest cannot lower its own floor by
  // naming a different key.
  uint32_t effective_min_security_version = 0;

  std::string Describe() const;
};

// Verifies a detached signature set over an artifact against a set of anchors.
//
// The anchor is selected by key_id AND algorithm. Selecting by id alone is how a
// manifest ends up verified with the wrong primitive; selecting by algorithm alone
// is how a revoked key keeps working. Both must match, and an anchor that is
// disabled or that failed ValidateAnchor is never eligible.
SignatureVerification VerifySignatures(SignatureBackend* backend,
                                       const std::vector<OtaKeyAnchor>& anchors,
                                       const std::vector<DetachedSignature>& signatures,
                                       const std::string& artifact,
                                       const DualSignaturePolicy& policy);

// --- the staged checks -------------------------------------------------------

enum class OtaStage : int32_t {
  kManifestSignature = 0,
  kManifestFormat = 1,
  kAntiRollback = 2,
  kValidityWindow = 3,
  kSizeCeiling = 4,
  kFetch = 5,
  kPackageDigest = 6,
  kInstall = 7,
  kHashtreeRoot = 8,
};

const char* OtaStageName(OtaStage stage);

// What the device is allowed to do next. There is no "proceed with caution": an
// OTA either passes every check up to this point or the device goes to the vault.
enum class OtaVerdict : int32_t {
  kProceed = 0,
  kRejectToVault = 1,
};

const char* OtaVerdictName(OtaVerdict verdict);

struct VerifierPolicy {
  uint64_t max_package_bytes = kDefaultMaxPackageBytes;
  DualSignaturePolicy signatures;
  // The current time, supplied by the caller. A verifier that reads the clock
  // itself cannot be tested for an expired manifest without waiting for it to
  // expire.
  int64_t now_unix = 0;
  // ro.build.fingerprint of the running image.
  std::string running_fingerprint;
  // security_version of the installed image.
  uint32_t installed_security_version = 0;
  // Battery percentage, 0..100.
  uint32_t battery_percent = 100;
  // When false, a package whose target_fingerprint does not match the running
  // build is refused. There is no situation in which turning this off is correct,
  // and it exists only so that the check can be demonstrated to fire.
  bool enforce_target_fingerprint = true;
};

struct StageResult {
  OtaStage stage = OtaStage::kManifestSignature;
  OtaVerdict verdict = OtaVerdict::kRejectToVault;
  std::string reason;

  bool Proceeds() const { return verdict == OtaVerdict::kProceed; }
};

// Runs stages kManifestSignature through kSizeCeiling — everything that can be
// decided before a single byte of the package is fetched. Returns the first
// refusal, or kProceed at kSizeCeiling when the download may start.
//
// |manifest_bytes| are the exact bytes received, and they are what gets signed.
// The parsed manifest is passed alongside rather than re-parsed here so that the
// caller controls JSON handling; the verifier checks that the parse is faithful by
// re-serialising and comparing, because a manifest that parses to something other
// than what was signed is the one failure mode a JSON layer introduces that no
// signature can catch.
StageResult AuthorizeDownload(const std::vector<OtaKeyAnchor>& anchors, SignatureBackend* backend,
                              const std::string& manifest_bytes,
                              const std::vector<DetachedSignature>& signatures,
                              const OtaManifest& parsed, const VerifierPolicy& policy);

// Runs kPackageDigest: the delivered bytes against the declared digest and the
// declared length. |received_bytes| is the count actually read, which may differ
// from the declared size if the connection ended early.
StageResult CheckDeliveredPackage(const OtaManifest& manifest, uint64_t received_bytes,
                                  const std::string& delivered_sha256_hex,
                                  const VerifierPolicy& policy);

// Runs kHashtreeRoot: the image the installer produced against the image the
// manifest promised.
StageResult CheckInstalledImage(const OtaManifest& manifest,
                                const std::string& produced_hashtree_root_hex,
                                const VerifierPolicy& policy);

}  // namespace xrom::ota

#endif  // XROM_OTA_OTA_VERIFIER_H_
