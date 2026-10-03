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

#ifndef XROM_AVF_PAYLOAD_VERIFIER_H_
#define XROM_AVF_PAYLOAD_VERIFIER_H_

#include <cstdint>
#include <string>
#include <vector>

#include "PayloadManifest.h"
#include "Sha256.h"
#include "VmSpec.h"

namespace xrom::avf {

// ---------------------------------------------------------------------------
// Signature and measurement verification of the Microdroid payload.
//
// This is the gate the daemon refuses to skip. Verify() either returns a
// VerifiedPayload whose digests the host recomputed itself, or a list of reasons.
// There is no "warn but continue" path, no development bypass and no property to
// turn it off: a payload whose manifest does not verify is never handed to AVF.
//
// The four independent things that have to agree before a VM is launched:
//
//   1. The manifest's detached signature verifies against a key id pinned in
//      trust_anchors.json. Selecting the key by id (rather than trying every
//      anchor until one verifies) means an attacker who can write to the trust
//      directory cannot make an unknown key authoritative simply by adding it.
//   2. The manifest passes PayloadManifest::Validate(): version, name, validity
//      window, algorithm, non-zero digests, a non-empty task class list.
//   3. security_version is at least the anchor's minimum, so a validly signed but
//      superseded manifest cannot be replayed after a security fix.
//   4. sha256() of the APK bytes on disk equals the pinned apk_sha256. This one is
//      recomputed at runtime rather than trusted from the build, so swapping the
//      APK under a valid manifest is detected here even though AVF would still
//      boot it.
//
// Steps 1-4 all happen BEFORE AvfController::Launch, so a rejected payload never
// reaches pvmfw, never gets a VM allocation and never touches /dev/kvm.
//
// What this does NOT claim: it is a host-side check over files the host can read.
// Proof that the bytes the GUEST is executing are those bytes comes from the
// guest's own kGuestHello measurement, compared in IsolationService against the
// same manifest. The two together are what kMeasurementOnly attestation means.
// ---------------------------------------------------------------------------

// One pinned signing key. Loaded from trust_anchors.json, which lives under
// /system_ext/etc/xrom/trust/ and is read-only to the daemon's SELinux domain.
struct TrustAnchor {
  std::string key_id;
  std::string algorithm;                     // PayloadManifest::kAlgorithm*
  std::vector<uint8_t> public_key_der;       // DER SubjectPublicKeyInfo
  int32_t min_security_version = 0;
  bool enabled = true;
};

// A manifest whose signature and digests have been checked.
struct VerifiedPayload {
  PayloadManifest manifest;
  ::xrom::crypto::Sha256Digest apk_sha256_recomputed{};
  ::xrom::crypto::Sha256Digest idsig_sha256{};  // recorded after AVF generates it
  std::string anchor_key_id;
  int64_t verified_at_unix = 0;

  bool IsValid() const { return verified_at_unix != 0; }
};

class PayloadVerifier {
 public:
  // trust_config: path to trust_anchors.json. Kept a parameter (rather than a
  // constant) so that tests and the preflight tool can point it at a fixture.
  explicit PayloadVerifier(const std::string& trust_config = kDefaultTrustConfigPath);

  // Loads the trust anchors. Returns false if the file is missing, unparsable or
  // yields no enabled anchor — in which case the daemon must fail closed.
  bool LoadTrustAnchors();
  bool LoadTrustAnchors(std::vector<std::string>* errors);

  // The full gate described above. On success |out| is populated; on failure
  // |errors| lists every reason, so an operator sees the whole problem at once.
  bool Verify(const VmSpec& spec, VerifiedPayload* out, std::vector<std::string>* errors);

  const std::vector<TrustAnchor>& anchors() const { return anchors_; }

 private:
  const TrustAnchor* FindAnchor(const std::string& key_id, const std::string& algorithm) const;
  bool VerifySignature(const TrustAnchor& anchor, const std::string& message,
                       const std::vector<uint8_t>& signature, std::string* detail) const;

  std::string trust_config_;
  std::vector<TrustAnchor> anchors_;
};

}  // namespace xrom::avf

#endif  // XROM_AVF_PAYLOAD_VERIFIER_H_
