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

#ifndef XROM_OTA_INSTALLER_OTA_TRUST_H_
#define XROM_OTA_INSTALLER_OTA_TRUST_H_

#include <memory>
#include <string>
#include <vector>

#include "OtaVerifier.h"

namespace xrom::ota_installer {

// ---------------------------------------------------------------------------
// The trust material, and the two things this file is responsible for that the
// pure verifier is not: getting keys out of DER on a read-only partition, and
// handing BoringSSL to the SignatureBackend seam.
//
// KEYS ARE READ FROM A READ-ONLY PARTITION AND NOWHERE ELSE
// ----------------------------------------------------------
// The anchor file lives at /system_ext/etc/xrom/ota-trust/ota_trust_anchors.json,
// inside an AVB-verified, dm-verity-covered, read-only partition, and is labelled
// xrom_ota_trust_file. There is no code path that adds an anchor from a fetched file,
// from a partition the OTA itself writes, or from a system property. A trust anchor
// that can be loaded at runtime is not a trust anchor; it is a suggestion.
//
// It is a separate label from xrom_payload_trust_file rather than a shared one, and
// sepolicy denies xrom_ota_installer access to the payload anchors. The two sets of
// keys sign different things, are rotated on different schedules, and a compromise of
// the OTA path should not reach the keys that decide what may run inside a pVM.
//
// WHY THE BACKEND LIVES HERE AND NOT IN common/ota
// ------------------------------------------------
// common/ota is host-testable, which means it cannot link BoringSSL. The verifier
// takes a SignatureBackend so that the entire staged order runs on a build host
// against a fake; this file is the real implementation of that one method, and it is
// the only place in the OTA path that calls into a crypto library.
// ---------------------------------------------------------------------------

// Loads and validates the pinned anchors.
//
// Every anchor that fails ValidateAnchor is dropped with its reason recorded, and an
// empty result is a fatal error rather than a permissive one: zero anchors means the
// installer has no idea whose signature to accept, and VerifySignatures fails closed
// on that, so the installer refuses to write anything.
struct TrustLoadResult {
  bool ok = false;
  std::vector<::xrom::ota::OtaKeyAnchor> anchors;
  // Anchors that were present but unusable, with the reason. Reported rather than
  // silently dropped, because a key that stops validating after a build change is
  // usually a build change that was not meant to touch it.
  std::vector<std::string> dropped;
  std::vector<std::string> errors;

  std::string Describe() const;
};

TrustLoadResult LoadTrustAnchors(const std::string& path);

// Reads a detached signature file. The wire format is hex, because a signature has to
// survive being copied by tools that are not binary safe; the bytes are what the
// backend verifies.
bool ReadSignatureFile(const std::string& path, ::xrom::ota::SignatureAlgorithm algorithm,
                       const std::string& key_id, ::xrom::ota::DetachedSignature* out,
                       std::string* error);

// Reads update.json and parses it into an OtaManifest, returning BOTH the exact bytes
// received and the parsed structure. The verifier compares them by re-serialising,
// which is the check that catches a JSON layer disagreeing with itself about what was
// signed.
struct ManifestReadResult {
  bool ok = false;
  std::string bytes;
  ::xrom::ota::OtaManifest manifest;
  std::string error;
};

ManifestReadResult ReadManifest(const std::string& path);

// The production SignatureBackend: BoringSSL's EVP_DigestVerify, over the exact bytes
// of the artifact, with no canonicalisation. Ed25519 uses a NULL md; RSA-4096 uses
// SHA-256 with PKCS#1 v1.5 padding, matching what the signing tool produces.
class BoringSslBackend : public ::xrom::ota::SignatureBackend {
 public:
  ::xrom::ota::BackendResult Verify(::xrom::ota::SignatureAlgorithm algorithm,
                                    const std::string& public_key_der, const std::string& artifact,
                                    const std::string& signature) override;
};

}  // namespace xrom::ota_installer

#endif  // XROM_OTA_INSTALLER_OTA_TRUST_H_
