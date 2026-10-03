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

// Tests for common/ota/OtaVerifier.cpp.
//
// Signature verification itself is BoringSSL's job and is not re-tested here. What
// is tested is everything around it, which is the part this project wrote and
// therefore the part that can be wrong:
//
//   * anchor selection is by key_id AND algorithm, so a manifest cannot be
//     verified with the wrong primitive or with a key that was rotated out;
//   * dual signature is an AND over two distinct keys, and one key counted twice
//     is not two signatures;
//   * the staged order holds — a manifest that fails the size ceiling is refused
//     before a byte is fetched, and a manifest whose signature fails is refused
//     before a field is read as data;
//   * anti-rollback is enforced from the pinned anchors, never from the manifest;
//   * a parse that is not faithful to the signed bytes is refused, which is the
//     one failure mode a JSON layer introduces that no signature can catch.
//
// The DER fixtures below are real. The Ed25519 and RSA-4096 keys were produced by
// `openssl genpkey` / `openssl pkey -pubout -outform DER` and are pasted as hex,
// which is the only check in this file that the DER walker handles genuine
// openssl output including its multi-byte length forms. The synthetic RSA keys
// exist for the boundary cases — 4095, 4096 and 4097 bits — where a real key
// cannot be aimed precisely.

#include "OtaVerifier.h"

#include <cstring>
#include <map>
#include <string>
#include <vector>

#include "gtest/gtest.h"

namespace {

using ::xrom::ota::AuthorizeDownload;
using ::xrom::ota::CheckDeliveredPackage;
using ::xrom::ota::CheckInstalledImage;
using ::xrom::ota::DetachedSignature;
using ::xrom::ota::OtaKeyAnchor;
using ::xrom::ota::OtaManifest;
using ::xrom::ota::OtaStage;
using ::xrom::ota::OtaVerdict;
using ::xrom::ota::SignatureAlgorithm;
using ::xrom::ota::ValidateAnchor;
using ::xrom::ota::VerifierPolicy;
using ::xrom::ota::VerifySignatures;

// --- DER fixtures -----------------------------------------------------------

std::string HexToBytes(const std::string& hex) {
  std::string out;
  out.reserve(hex.size() / 2);
  for (size_t i = 0; i + 1 < hex.size(); i += 2) {
    auto nibble = [](char c) -> int {
      if (c >= '0' && c <= '9') return c - '0';
      if (c >= 'a' && c <= 'f') return c - 'a' + 10;
      if (c >= 'A' && c <= 'F') return c - 'A' + 10;
      return -1;
    };
    const int high = nibble(hex[i]);
    const int low = nibble(hex[i + 1]);
    if (high < 0 || low < 0) {
      return "";
    }
    out.push_back(static_cast<char>((high << 4) | low));
  }
  return out;
}

// A real Ed25519 SubjectPublicKeyInfo, 44 bytes, from `openssl pkey -pubout
// -outform DER`. Its prefix is the constant the verifier matches against.
const char* const kRealEd25519SpkiHex =
    "302a300506032b657003210037a5602abf81ac23034e2cfec92dc4522c8c4e1e"
    "2775a9ff8435b65d3d7fd436";

// A real RSA-4096 SubjectPublicKeyInfo, 550 bytes, same provenance. Deliberately
// included in full: it exercises the two-byte length form (30 82 02 22) and the
// nested BIT STRING wrapping, which are exactly the places a hand-written DER
// walker goes wrong and a synthetic fixture would hide.
const char* const kRealRsa4096SpkiHex =
    "30820222300d06092a864886f70d01010105000382020f003082020a02820201"
    "00d6e17aaeae225adb4333efd4cca542ad7c5f4ce0fd40d660e2bcc88d4a0721"
    "eab075fdc52c1cf9a81059f875c995ac0a5bf775b57bb918e550532790c42c24"
    "8824b79d288d388cc6536ab13fad488818325dd8dac1cfd7d35493f6f34ea26e"
    "bdd134dc042e2b873872bd0aa5b5ae7d262b82987bec51becbc5845f49dc9ef2"
    "820aebb48803024fe95f8c12f2a191ba56471b61062bc1f70a1cf2636490ff7f"
    "fc65690371a5483205a0c92689c959013c0ece966be677e6d125a27300d9a640"
    "5be13e223c5040a33fcddd442cc712f5a2417004be1585010810613e2b362a2d"
    "2228868c6745bcebede049d14522483b3d6ddc5efa5261c98676711c55b4791e"
    "0e95cda8188a5d6b720800f35be391dcad6313014ac10b63510ab622a738a9b0"
    "0a72c1123e718d0e8231025ba15480da162147e22063a941b1352d2b2d3d22db"
    "4b348e6d42f57cdeb217329b21a93bc7039d26d4ba89c41e676fce8139e264e3"
    "2488c2de015ff63e4694ba427361bd9950485c1ade3c90642e3d9a5d9cdd871a"
    "5f1601c179ac39e9306a38d9062657b17cdb45ba15bb987077993bbf521dad40"
    "5d7907cadf52d719b161a28fcf4e332ef42b26a0ef06daf00aee47b5cc233b89"
    "6fea301e923b002748d87586189b84c5dc9e0956379e159702f0b21314d759ac"
    "f95b7ff5ea446a0b86e2b3854f51eb26538217db51b412eb8043c68f342e6336"
    "ad0203010001";

std::string RealEd25519Der() { return HexToBytes(kRealEd25519SpkiHex); }
std::string RealRsa4096Der() { return HexToBytes(kRealRsa4096SpkiHex); }

// Builds an RSA SubjectPublicKeyInfo whose modulus has exactly |bits| bits.
std::string SyntheticRsaSpki(uint32_t bits) {
  auto der_length = [](size_t length) {
    if (length < 0x80) {
      return std::string(1, static_cast<char>(length));
    }
    std::string body;
    while (length != 0) {
      body.insert(body.begin(), static_cast<char>(length & 0xFF));
      length >>= 8;
    }
    return std::string(1, static_cast<char>(0x80 | body.size())) + body;
  };
  auto tlv = [&der_length](uint8_t tag, const std::string& content) {
    return std::string(1, static_cast<char>(tag)) + der_length(content.size()) + content;
  };

  const size_t bytes = (bits + 7) / 8;
  const uint32_t top_bits = bits - static_cast<uint32_t>((bytes - 1) * 8);
  const uint8_t top = static_cast<uint8_t>((1u << top_bits) - 1u);

  std::string modulus(bytes, '\x55');
  modulus[0] = static_cast<char>(top);
  if (top & 0x80) {
    // DER INTEGER is signed; a leading 0x00 keeps a high-bit value positive.
    modulus.insert(modulus.begin(), '\0');
  }
  const std::string exponent("\x01\x00\x01", 3);  // 65537

  const std::string rsa_public_key = tlv(0x30, tlv(0x02, modulus) + tlv(0x02, exponent));
  const std::string algorithm_identifier =
      tlv(0x30, tlv(0x06, HexToBytes("2a864886f70d010101")) + tlv(0x05, ""));
  const std::string bit_string = tlv(0x03, std::string(1, '\0') + rsa_public_key);
  return tlv(0x30, algorithm_identifier + bit_string);
}

// --- the crypto seam --------------------------------------------------------

// Verifies a signature when its bytes equal the configured "good" value for that
// algorithm, and records what it was asked to verify so that the tests can assert
// the right anchor key and the right artifact bytes reached the backend.
class FakeBackend : public ::xrom::ota::SignatureBackend {
 public:
  struct Call {
    SignatureAlgorithm algorithm = SignatureAlgorithm::kEd25519;
    std::string public_key_der;
    std::string artifact;
    std::string signature;
  };

  std::string good_ed25519 = "ED-SIG";
  std::string good_rsa = "RSA-SIG";
  bool ed25519_verifies = true;
  bool rsa_verifies = true;
  std::vector<Call> calls;

  ::xrom::ota::BackendResult Verify(SignatureAlgorithm algorithm,
                                    const std::string& public_key_der,
                                    const std::string& artifact,
                                    const std::string& signature) override {
    Call call;
    call.algorithm = algorithm;
    call.public_key_der = public_key_der;
    call.artifact = artifact;
    call.signature = signature;
    calls.push_back(call);

    ::xrom::ota::BackendResult result;
    if (algorithm == SignatureAlgorithm::kEd25519) {
      result.verified = ed25519_verifies && signature == good_ed25519;
    } else {
      result.verified = rsa_verifies && signature == good_rsa;
    }
    result.detail = result.verified ? "" : "the signature bytes did not match";
    return result;
  }
};

// --- fixtures ---------------------------------------------------------------

OtaManifest ValidManifest() {
  OtaManifest manifest;
  manifest.package_url = "https://update.xrom.example/releases/x1/ota-0008.zip";
  manifest.package_sha256 = "0f3a9c1d4e5b6a7988a0b1c2d3e4f5061728394a5b6c7d8e9f0a1b2c3d4e5f60";
  manifest.package_bytes = 268435456;
  manifest.security_version = 8;
  manifest.build_fingerprint = "X-ROM/x1/16/AP1A.000000.008/8:user/release-keys";
  manifest.target_fingerprint = "X-ROM/x1/16/AP1A.000000.007/7:user/release-keys";
  manifest.expected_hashtree_root_sha256 =
      "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
  manifest.min_battery_percent = 30;
  manifest.issued_at_unix = 1767225600;
  manifest.not_after_unix = 1774915200;
  return manifest;
}

OtaKeyAnchor Ed25519Anchor(const std::string& key_id = "xrom-ota-ed25519-01") {
  OtaKeyAnchor anchor;
  anchor.key_id = key_id;
  anchor.algorithm = SignatureAlgorithm::kEd25519;
  anchor.public_key_der = RealEd25519Der();
  anchor.min_security_version = 3;
  return anchor;
}

OtaKeyAnchor RsaAnchor(const std::string& key_id = "xrom-ota-rsa4096-01") {
  OtaKeyAnchor anchor;
  anchor.key_id = key_id;
  anchor.algorithm = SignatureAlgorithm::kRsa4096Sha256;
  anchor.public_key_der = RealRsa4096Der();
  anchor.min_security_version = 1;
  return anchor;
}

std::vector<OtaKeyAnchor> BothAnchors() { return {Ed25519Anchor(), RsaAnchor()}; }

std::vector<DetachedSignature> BothSignatures() {
  DetachedSignature ed;
  ed.algorithm = SignatureAlgorithm::kEd25519;
  ed.key_id = "xrom-ota-ed25519-01";
  ed.signature = "ED-SIG";
  DetachedSignature rsa;
  rsa.algorithm = SignatureAlgorithm::kRsa4096Sha256;
  rsa.key_id = "xrom-ota-rsa4096-01";
  rsa.signature = "RSA-SIG";
  return {ed, rsa};
}

VerifierPolicy ValidPolicy() {
  VerifierPolicy policy;
  policy.now_unix = 1767312000;  // 2026-01-02, inside the window
  policy.running_fingerprint = "X-ROM/x1/16/AP1A.000000.007/7:user/release-keys";
  policy.installed_security_version = 7;
  policy.battery_percent = 80;
  return policy;
}

bool Proceeds(const ::xrom::ota::StageResult& result) {
  return result.verdict == OtaVerdict::kProceed;
}

}  // namespace

// ---------------------------------------------------------------------------
// Anchor validation: DER inspection with no crypto library involved
// ---------------------------------------------------------------------------

TEST(OtaAnchor, ARealEd25519SpkiIsAccepted) {
  const auto validation = ValidateAnchor(Ed25519Anchor());
  EXPECT_TRUE(validation.ok);
  EXPECT_EQ(RealEd25519Der().size(), 44u);
}

TEST(OtaAnchor, ARealRsa4096SpkiIsAccepted) {
  const auto validation = ValidateAnchor(RsaAnchor());
  EXPECT_TRUE(validation.ok);
  // The DER walker had to get through openssl's real output, including the
  // two-byte length form on the outer SEQUENCE and the nested BIT STRING.
  EXPECT_EQ(RealRsa4096Der().size(), 550u);
}

TEST(OtaAnchor, TheRsaModulusFloorIsExactly4096Bits) {
  OtaKeyAnchor at_floor = RsaAnchor();
  at_floor.public_key_der = SyntheticRsaSpki(4096);
  EXPECT_TRUE(ValidateAnchor(at_floor).ok);

  OtaKeyAnchor below = RsaAnchor();
  below.public_key_der = SyntheticRsaSpki(4095);
  const auto rejected = ValidateAnchor(below);
  EXPECT_FALSE(rejected.ok);
  EXPECT_TRUE(rejected.reason.find("4095 bits") != std::string::npos);

  OtaKeyAnchor above = RsaAnchor();
  above.public_key_der = SyntheticRsaSpki(4097);
  EXPECT_TRUE(ValidateAnchor(above).ok);
}

TEST(OtaAnchor, ACommon2048BitKeyIsRejected) {
  // Not a hypothetical: 2048-bit RSA is what a key generated with the openssl
  // default looks like, and an anchor entry that claims RSA4096_SHA256 while
  // holding one is the mistake this check exists to catch.
  OtaKeyAnchor anchor = RsaAnchor();
  anchor.public_key_der = SyntheticRsaSpki(2048);
  const auto validation = ValidateAnchor(anchor);
  EXPECT_FALSE(validation.ok);
  EXPECT_TRUE(validation.reason.find("2048 bits") != std::string::npos);
}

TEST(OtaAnchor, TheAlgorithmHasToMatchTheDer) {
  // An Ed25519 entry holding an RSA key, and the reverse. Either one turns
  // "verify with Ed25519" into "verify with whatever this blob is".
  OtaKeyAnchor wrong_way = Ed25519Anchor();
  wrong_way.public_key_der = RealRsa4096Der();
  EXPECT_FALSE(ValidateAnchor(wrong_way).ok);

  OtaKeyAnchor other_way = RsaAnchor();
  other_way.public_key_der = RealEd25519Der();
  EXPECT_FALSE(ValidateAnchor(other_way).ok);
}

TEST(OtaAnchor, ATruncatedDerIsRejected) {
  OtaKeyAnchor anchor = RsaAnchor();
  anchor.public_key_der = RealRsa4096Der().substr(0, 100);
  EXPECT_FALSE(ValidateAnchor(anchor).ok);

  anchor = Ed25519Anchor();
  anchor.public_key_der = RealEd25519Der().substr(0, 43);
  EXPECT_FALSE(ValidateAnchor(anchor).ok);
}

TEST(OtaAnchor, IndefiniteLengthDerIsRejected) {
  // 0x80 as a length byte means "ends at an EOC marker", which is BER and not
  // DER. A parser that accepts two encodings of the same structure is a parser
  // whose idea of where a field ends can be made to differ from the crypto
  // library's.
  OtaKeyAnchor anchor = RsaAnchor();
  anchor.public_key_der = std::string("\x30\x80", 2) + RealRsa4096Der().substr(4);
  EXPECT_FALSE(ValidateAnchor(anchor).ok);
}

TEST(OtaAnchor, OverlongLengthEncodingsAreRejected) {
  // The outer SEQUENCE of the real key is 30 82 02 22 — a two-byte length for
  // 546. Writing the same length in four bytes describes the same structure with
  // different bytes, and the signature covers bytes.
  OtaKeyAnchor anchor = RsaAnchor();
  const std::string real = RealRsa4096Der();
  anchor.public_key_der = std::string("\x30\x84\x00\x00\x02\x22", 6) + real.substr(4);
  EXPECT_FALSE(ValidateAnchor(anchor).ok);
}

TEST(OtaAnchor, EmptyAndOversizedBlobsAreRejected) {
  OtaKeyAnchor empty_der = Ed25519Anchor();
  empty_der.public_key_der = "";
  EXPECT_FALSE(ValidateAnchor(empty_der).ok);

  OtaKeyAnchor huge = Ed25519Anchor();
  huge.public_key_der = std::string(8192, '\0');
  EXPECT_TRUE(ValidateAnchor(huge).reason.find("implausibly large") != std::string::npos);

  OtaKeyAnchor no_id = Ed25519Anchor();
  no_id.key_id = "";
  EXPECT_FALSE(ValidateAnchor(no_id).ok);

  OtaKeyAnchor long_id = Ed25519Anchor();
  long_id.key_id = std::string(65, 'k');
  EXPECT_FALSE(ValidateAnchor(long_id).ok);
}

// ---------------------------------------------------------------------------
// VerifySignatures
// ---------------------------------------------------------------------------

TEST(OtaSignatures, TwoDistinctKeysBothVerify) {
  FakeBackend backend;
  const auto result =
      VerifySignatures(&backend, BothAnchors(), BothSignatures(), "manifest-bytes",
                       ::xrom::ota::DualSignaturePolicy{});
  EXPECT_TRUE(result.ok);
  EXPECT_TRUE(result.ed25519_satisfied);
  EXPECT_TRUE(result.rsa_satisfied);
  EXPECT_EQ(result.satisfied_key_ids.size(), 2u);
  EXPECT_TRUE(result.Describe().find("ed25519=yes") != std::string::npos);
}

TEST(OtaSignatures, TheBackendReceivesTheAnchorKeyAndTheExactArtifactBytes) {
  // The whole point of selecting an anchor by id AND algorithm is that the key
  // handed to the crypto library is the pinned one. If the adapter passed anything
  // else, the pin would be decoration.
  FakeBackend backend;
  const std::string artifact = "these exact bytes";
  VerifySignatures(&backend, BothAnchors(), BothSignatures(), artifact,
                   ::xrom::ota::DualSignaturePolicy{});
  EXPECT_EQ(backend.calls.size(), 2u);
  for (const auto& call : backend.calls) {
    EXPECT_EQ(call.artifact, artifact);
    const bool is_ed = call.algorithm == SignatureAlgorithm::kEd25519;
    EXPECT_EQ(call.public_key_der, is_ed ? RealEd25519Der() : RealRsa4096Der());
  }
}

TEST(OtaSignatures, MissingOneOfTheTwoFailsWhenDualIsRequired) {
  FakeBackend backend;
  ::xrom::ota::DualSignaturePolicy policy;

  std::vector<DetachedSignature> only_ed = BothSignatures();
  only_ed.pop_back();
  const auto no_rsa = VerifySignatures(&backend, BothAnchors(), only_ed, "m", policy);
  EXPECT_FALSE(no_rsa.ok);
  EXPECT_TRUE(no_rsa.Describe().find("RSA-4096 signature is missing") != std::string::npos);

  std::vector<DetachedSignature> only_rsa = BothSignatures();
  only_rsa.erase(only_rsa.begin());
  const auto no_ed = VerifySignatures(&backend, BothAnchors(), only_rsa, "m", policy);
  EXPECT_FALSE(no_ed.ok);
  EXPECT_TRUE(no_ed.Describe().find("Ed25519 signature is missing") != std::string::npos);
}

TEST(OtaSignatures, OneBadSignatureOutOfTwoStillFails) {
  // An AND, not a majority vote. The failure message has to distinguish "one was
  // absent" from "one was present and did not verify", because the first is a
  // packaging bug and the second is an attack or a rotation that went wrong.
  FakeBackend backend;
  backend.rsa_verifies = false;
  const auto result =
      VerifySignatures(&backend, BothAnchors(), BothSignatures(), "m",
                       ::xrom::ota::DualSignaturePolicy{});
  EXPECT_FALSE(result.ok);
  EXPECT_TRUE(result.ed25519_satisfied);
  EXPECT_FALSE(result.rsa_satisfied);
  EXPECT_TRUE(result.Describe().find("did not verify") != std::string::npos);
}

TEST(OtaSignatures, NeitherVerifyingIsReportedAsNeither) {
  FakeBackend backend;
  backend.ed25519_verifies = false;
  backend.rsa_verifies = false;
  const auto result =
      VerifySignatures(&backend, BothAnchors(), BothSignatures(), "m",
                       ::xrom::ota::DualSignaturePolicy{});
  EXPECT_FALSE(result.ok);
  EXPECT_TRUE(result.Describe().find("neither signature verified") != std::string::npos);
}

TEST(OtaSignatures, TwoAlgorithmsUnderOneKeyIdAreNotTwoKeys) {
  // The scenario this catches is an anchor list that reuses a single key_id for
  // both algorithms. Both signatures then verify, both algorithms are satisfied,
  // and require_dual_signature would pass — while the actual number of
  // independent key ceremonies behind the manifest is one.
  FakeBackend backend;
  OtaKeyAnchor shared_ed = Ed25519Anchor("xrom-ota-shared-01");
  OtaKeyAnchor shared_rsa = RsaAnchor("xrom-ota-shared-01");
  std::vector<DetachedSignature> signatures = BothSignatures();
  signatures[0].key_id = "xrom-ota-shared-01";
  signatures[1].key_id = "xrom-ota-shared-01";

  const auto result = VerifySignatures(&backend, {shared_ed, shared_rsa}, signatures, "m",
                                       ::xrom::ota::DualSignaturePolicy{});
  EXPECT_TRUE(result.ed25519_satisfied);
  EXPECT_TRUE(result.rsa_satisfied);
  EXPECT_FALSE(result.ok);
  EXPECT_EQ(result.satisfied_key_ids.size(), 1u);
  EXPECT_TRUE(result.Describe().find("same key") != std::string::npos);

  // And the same anchors are fine when the policy does not ask for two keys.
  ::xrom::ota::DualSignaturePolicy relaxed;
  relaxed.require_distinct_keys = false;
  EXPECT_TRUE(VerifySignatures(&backend, {shared_ed, shared_rsa}, signatures, "m", relaxed).ok);
}

TEST(OtaSignatures, AnUnknownKeyIdIsRejected) {
  FakeBackend backend;
  std::vector<DetachedSignature> signatures = BothSignatures();
  signatures[0].key_id = "xrom-ota-ed25519-99";
  const auto result = VerifySignatures(&backend, BothAnchors(), signatures, "m",
                                       ::xrom::ota::DualSignaturePolicy{});
  EXPECT_FALSE(result.ok);
  EXPECT_TRUE(result.Describe().find("no anchor matches key_id") != std::string::npos);
}

TEST(OtaSignatures, ADisabledAnchorIsRejected) {
  // Rotation works by disabling the old anchor, so a disabled anchor has to stop
  // verifying immediately rather than at the next build.
  FakeBackend backend;
  std::vector<OtaKeyAnchor> anchors = BothAnchors();
  anchors[1].enabled = false;
  const auto result = VerifySignatures(&backend, anchors, BothSignatures(), "m",
                                       ::xrom::ota::DualSignaturePolicy{});
  EXPECT_FALSE(result.ok);
  EXPECT_TRUE(result.Describe().find("disabled") != std::string::npos);
}

TEST(OtaSignatures, TheAlgorithmHasToMatchTheKeyWithThatId) {
  // The same key_id offered with the other algorithm. Selecting by id alone would
  // verify an Ed25519 signature with an RSA public key, or accept a signature
  // under a rotated-out algorithm while the id still looks familiar.
  FakeBackend backend;
  std::vector<DetachedSignature> signatures = BothSignatures();
  signatures[0].algorithm = SignatureAlgorithm::kRsa4096Sha256;  // id still says ed25519
  const auto result = VerifySignatures(&backend, BothAnchors(), signatures, "m",
                                       ::xrom::ota::DualSignaturePolicy{});
  EXPECT_FALSE(result.ok);
  EXPECT_TRUE(result.Describe().find("no anchor matches key_id") != std::string::npos);
}

TEST(OtaSignatures, AnAnchorWithUnusableDerIsRefusedEvenIfTheIdMatches) {
  FakeBackend backend;
  std::vector<OtaKeyAnchor> anchors = BothAnchors();
  anchors[1].public_key_der = SyntheticRsaSpki(2048);  // below the floor
  const auto result = VerifySignatures(&backend, anchors, BothSignatures(), "m",
                                       ::xrom::ota::DualSignaturePolicy{});
  EXPECT_FALSE(result.ok);
  EXPECT_TRUE(result.Describe().find("unusable") != std::string::npos);
  EXPECT_TRUE(result.Describe().find("4096 bit floor") != std::string::npos);
}

TEST(OtaSignatures, ZeroAnchorsFailsClosed) {
  // The difference between "trust nothing" and "trust whatever arrives". A build
  // that ships no anchors must not become a build that accepts any signature.
  FakeBackend backend;
  const auto result = VerifySignatures(&backend, {}, BothSignatures(), "m",
                                       ::xrom::ota::DualSignaturePolicy{});
  EXPECT_FALSE(result.ok);
  EXPECT_TRUE(result.Describe().find("failing closed") != std::string::npos);
  EXPECT_EQ(backend.calls.size(), 0u);  // nothing was even offered to the backend
}

TEST(OtaSignatures, AnEmptyArtifactIsNeverVerified) {
  FakeBackend backend;
  const auto result = VerifySignatures(&backend, BothAnchors(), BothSignatures(), "",
                                       ::xrom::ota::DualSignaturePolicy{});
  EXPECT_FALSE(result.ok);
  EXPECT_EQ(backend.calls.size(), 0u);
}

TEST(OtaSignatures, NoSuppliedSignaturesIsAFailureNotAVacuousPass) {
  FakeBackend backend;
  const auto result =
      VerifySignatures(&backend, BothAnchors(), {}, "m", ::xrom::ota::DualSignaturePolicy{});
  EXPECT_FALSE(result.ok);
  EXPECT_TRUE(result.Describe().find("no detached signatures") != std::string::npos);
}

TEST(OtaSignatures, AMissingBackendIsAFailure) {
  const auto result = VerifySignatures(nullptr, BothAnchors(), BothSignatures(), "m",
                                       ::xrom::ota::DualSignaturePolicy{});
  EXPECT_FALSE(result.ok);
}

TEST(OtaSignatures, TheAntiRollbackFloorComesFromTheAnchorsNotTheManifest) {
  // The highest floor among the anchors that matched is what applies, so a
  // manifest cannot lower its own floor by naming a permissive key.
  FakeBackend backend;
  std::vector<OtaKeyAnchor> anchors = BothAnchors();
  anchors[0].min_security_version = 3;
  anchors[1].min_security_version = 6;
  const auto result = VerifySignatures(&backend, anchors, BothSignatures(), "m",
                                       ::xrom::ota::DualSignaturePolicy{});
  EXPECT_TRUE(result.ok);
  EXPECT_EQ(result.effective_min_security_version, 6u);
}

TEST(OtaSignatures, SingleSignaturePolicyAcceptsOneKey) {
  FakeBackend backend;
  ::xrom::ota::DualSignaturePolicy policy;
  policy.require_dual = false;
  std::vector<DetachedSignature> only_ed = BothSignatures();
  only_ed.pop_back();
  EXPECT_TRUE(VerifySignatures(&backend, BothAnchors(), only_ed, "m", policy).ok);

  std::vector<DetachedSignature> only_rsa = BothSignatures();
  only_rsa.erase(only_rsa.begin());
  EXPECT_TRUE(VerifySignatures(&backend, BothAnchors(), only_rsa, "m", policy).ok);
}

TEST(OtaSignatures, SingleSignaturePolicyStillRejectsWhenNothingVerifies) {
  FakeBackend backend;
  backend.ed25519_verifies = false;
  backend.rsa_verifies = false;
  ::xrom::ota::DualSignaturePolicy policy;
  policy.require_dual = false;
  const auto result = VerifySignatures(&backend, BothAnchors(), BothSignatures(), "m", policy);
  EXPECT_FALSE(result.ok);
  EXPECT_TRUE(result.Describe().find("no signature verified") != std::string::npos);
}

// ---------------------------------------------------------------------------
// AuthorizeDownload: the staged order
// ---------------------------------------------------------------------------

TEST(OtaAuthorize, AFullyAuthorizedManifestProceeds) {
  const OtaManifest manifest = ValidManifest();
  const std::string bytes = manifest.Serialize();
  FakeBackend backend;
  const auto result = AuthorizeDownload(BothAnchors(), &backend, bytes, BothSignatures(),
                                        manifest, ValidPolicy());
  EXPECT_TRUE(Proceeds(result));
  EXPECT_EQ(static_cast<int>(result.stage), static_cast<int>(OtaStage::kSizeCeiling));
  EXPECT_TRUE(result.reason.find("xrom-ota-ed25519-01") != std::string::npos);
  EXPECT_TRUE(result.reason.find("xrom-ota-rsa4096-01") != std::string::npos);
}

TEST(OtaAuthorize, AnUnsignedManifestIsRefusedAtTheFirstStage) {
  const OtaManifest manifest = ValidManifest();
  const std::string bytes = manifest.Serialize();
  FakeBackend backend;
  backend.ed25519_verifies = false;
  const auto result =
      AuthorizeDownload(BothAnchors(), &backend, bytes, BothSignatures(), manifest,
                        ValidPolicy());
  EXPECT_FALSE(Proceeds(result));
  EXPECT_EQ(static_cast<int>(result.stage), static_cast<int>(OtaStage::kManifestSignature));
}

TEST(OtaAuthorize, AParseThatIsNotFaithfulToTheSignedBytesIsRefused) {
  // The signature covers the bytes on the wire. If the structure being acted on
  // does not re-serialise to those bytes, then something between the JSON layer
  // and this code changed the meaning — a duplicate key, a number parsed into the
  // wrong width, a field silently dropped. No signature can catch that, which is
  // why the check exists.
  const OtaManifest manifest = ValidManifest();
  const std::string signed_bytes = manifest.Serialize();
  OtaManifest parsed_differently = manifest;
  parsed_differently.package_bytes = 1;  // the parser "read" a different size

  FakeBackend backend;
  const auto result = AuthorizeDownload(BothAnchors(), &backend, signed_bytes,
                                        BothSignatures(), parsed_differently, ValidPolicy());
  EXPECT_FALSE(Proceeds(result));
  EXPECT_EQ(static_cast<int>(result.stage), static_cast<int>(OtaStage::kManifestFormat));
  EXPECT_TRUE(result.reason.find("does not re-serialise") != std::string::npos);
}

TEST(OtaAuthorize, ASignedButMalformedManifestIsRefused) {
  // A signing key used carelessly signs careless content. Format is checked after
  // the signature rather than instead of it.
  OtaManifest manifest = ValidManifest();
  manifest.min_battery_percent = 200;
  const std::string bytes = manifest.Serialize();
  FakeBackend backend;
  const auto result =
      AuthorizeDownload(BothAnchors(), &backend, bytes, BothSignatures(), manifest,
                        ValidPolicy());
  EXPECT_FALSE(Proceeds(result));
  EXPECT_EQ(static_cast<int>(result.stage), static_cast<int>(OtaStage::kManifestFormat));
}

TEST(OtaAuthorize, APackageForADifferentBuildIsRefused) {
  // Applying an incremental package to the wrong base produces an image that
  // boots to nothing, and every signature on it is perfectly valid.
  const OtaManifest manifest = ValidManifest();
  const std::string bytes = manifest.Serialize();
  VerifierPolicy policy = ValidPolicy();
  policy.running_fingerprint = "X-ROM/x1/16/AP1A.000000.005/5:user/release-keys";

  FakeBackend backend;
  const auto result =
      AuthorizeDownload(BothAnchors(), &backend, bytes, BothSignatures(), manifest, policy);
  EXPECT_FALSE(Proceeds(result));
  EXPECT_EQ(static_cast<int>(result.stage), static_cast<int>(OtaStage::kManifestFormat));
  EXPECT_TRUE(result.reason.find("never signed for") != std::string::npos);
}

TEST(OtaAuthorize, ADowngradeIsRefusedEvenWhenTheSignatureIsValid) {
  // A valid signature on an old image is exactly what a downgrade attack presents.
  const OtaManifest manifest = ValidManifest();  // security_version 8
  const std::string bytes = manifest.Serialize();
  VerifierPolicy policy = ValidPolicy();
  policy.installed_security_version = 8;  // already here

  FakeBackend backend;
  const auto result =
      AuthorizeDownload(BothAnchors(), &backend, bytes, BothSignatures(), manifest, policy);
  EXPECT_FALSE(Proceeds(result));
  EXPECT_EQ(static_cast<int>(result.stage), static_cast<int>(OtaStage::kAntiRollback));
}

TEST(OtaAuthorize, ThePinnedAnchorFloorOverridesTheManifestsOwnVersion) {
  OtaManifest manifest = ValidManifest();
  manifest.security_version = 4;  // above the installed 3, below the pinned floor
  const std::string bytes = manifest.Serialize();
  VerifierPolicy policy = ValidPolicy();
  policy.installed_security_version = 3;

  std::vector<OtaKeyAnchor> anchors = BothAnchors();
  anchors[0].min_security_version = 5;

  FakeBackend backend;
  const auto result =
      AuthorizeDownload(anchors, &backend, bytes, BothSignatures(), manifest, policy);
  EXPECT_FALSE(Proceeds(result));
  EXPECT_EQ(static_cast<int>(result.stage), static_cast<int>(OtaStage::kAntiRollback));
  EXPECT_TRUE(result.reason.find("pinned floor") != std::string::npos);
}

TEST(OtaAuthorize, AManifestWithNoClockIsRefused) {
  // A device in recovery has just come out of a reboot that may have been caused
  // by a flat battery — exactly the state in which the clock is wrong. Refusing is
  // both the fail-secure choice and the recoverable one, because the vault path
  // needs no clock at all.
  const OtaManifest manifest = ValidManifest();
  const std::string bytes = manifest.Serialize();
  VerifierPolicy policy = ValidPolicy();
  policy.now_unix = 0;

  FakeBackend backend;
  const auto result =
      AuthorizeDownload(BothAnchors(), &backend, bytes, BothSignatures(), manifest, policy);
  EXPECT_FALSE(Proceeds(result));
  EXPECT_EQ(static_cast<int>(result.stage), static_cast<int>(OtaStage::kValidityWindow));
  EXPECT_TRUE(result.reason.find("current time is unknown") != std::string::npos);
}

TEST(OtaAuthorize, AnExpiredManifestIsRefused) {
  const OtaManifest manifest = ValidManifest();
  const std::string bytes = manifest.Serialize();
  VerifierPolicy policy = ValidPolicy();
  policy.now_unix = manifest.not_after_unix + 1;

  FakeBackend backend;
  const auto result =
      AuthorizeDownload(BothAnchors(), &backend, bytes, BothSignatures(), manifest, policy);
  EXPECT_FALSE(Proceeds(result));
  EXPECT_EQ(static_cast<int>(result.stage), static_cast<int>(OtaStage::kValidityWindow));
  EXPECT_TRUE(result.reason.find("expired") != std::string::npos);
}

TEST(OtaAuthorize, AManifestIssuedInTheFutureIsRefused) {
  const OtaManifest manifest = ValidManifest();
  const std::string bytes = manifest.Serialize();
  VerifierPolicy policy = ValidPolicy();
  policy.now_unix = manifest.issued_at_unix - 1;

  FakeBackend backend;
  const auto result =
      AuthorizeDownload(BothAnchors(), &backend, bytes, BothSignatures(), manifest, policy);
  EXPECT_FALSE(Proceeds(result));
  EXPECT_TRUE(result.reason.find("future") != std::string::npos);
}

TEST(OtaAuthorize, TheWindowIsInclusiveAtBothEnds) {
  const OtaManifest manifest = ValidManifest();
  const std::string bytes = manifest.Serialize();
  FakeBackend backend;

  VerifierPolicy at_open = ValidPolicy();
  at_open.now_unix = manifest.issued_at_unix;
  EXPECT_TRUE(Proceeds(AuthorizeDownload(BothAnchors(), &backend, bytes, BothSignatures(),
                                         manifest, at_open)));

  VerifierPolicy at_close = ValidPolicy();
  at_close.now_unix = manifest.not_after_unix;
  EXPECT_TRUE(Proceeds(AuthorizeDownload(BothAnchors(), &backend, bytes, BothSignatures(),
                                         manifest, at_close)));
}

TEST(OtaAuthorize, AnOversizedPackageIsRefusedBeforeAnythingIsFetched) {
  // The whole reason the manifest declares a size. Fetching is the expensive
  // step: a 4 GB package on a metered link is a cost the device pays before
  // discovering it cannot install it, and a download that fills the partition is
  // how a network path becomes a brick.
  OtaManifest manifest = ValidManifest();
  manifest.package_bytes = 4ull * 1024 * 1024 * 1024;
  const std::string bytes = manifest.Serialize();

  FakeBackend backend;
  const auto result =
      AuthorizeDownload(BothAnchors(), &backend, bytes, BothSignatures(), manifest,
                        ValidPolicy());
  EXPECT_FALSE(Proceeds(result));
  EXPECT_EQ(static_cast<int>(result.stage), static_cast<int>(OtaStage::kSizeCeiling));
  EXPECT_TRUE(result.reason.find("falling back to the vault") != std::string::npos);
}

TEST(OtaAuthorize, TheCeilingCanBeTightenedPerDevice) {
  OtaManifest manifest = ValidManifest();  // 256 MiB
  const std::string bytes = manifest.Serialize();
  VerifierPolicy policy = ValidPolicy();
  policy.max_package_bytes = 100ull * 1024 * 1024;

  FakeBackend backend;
  EXPECT_FALSE(Proceeds(AuthorizeDownload(BothAnchors(), &backend, bytes, BothSignatures(),
                                          manifest, policy)));
}

TEST(OtaAuthorize, ALowBatteryIsRefusedBeforeTheDownload) {
  // An install that dies at 3% leaves the device with neither its old image nor a
  // new one. The requirement is signed, so whoever serves the manifest cannot
  // relax it.
  const OtaManifest manifest = ValidManifest();  // requires 30%
  const std::string bytes = manifest.Serialize();
  VerifierPolicy policy = ValidPolicy();
  policy.battery_percent = 29;

  FakeBackend backend;
  const auto result =
      AuthorizeDownload(BothAnchors(), &backend, bytes, BothSignatures(), manifest, policy);
  EXPECT_FALSE(Proceeds(result));
  EXPECT_EQ(static_cast<int>(result.stage), static_cast<int>(OtaStage::kSizeCeiling));
  EXPECT_TRUE(result.reason.find("battery") != std::string::npos);
}

TEST(OtaAuthorize, TheFirstFailingStageIsTheOneReported) {
  // A manifest that is unsigned, oversized and expired is reported as unsigned.
  // Diagnosing one thing at a time in a fixed order is what makes the log readable;
  // reporting the last failure found would make the earliest and cheapest one
  // invisible.
  OtaManifest manifest = ValidManifest();
  manifest.package_bytes = 9ull * 1024 * 1024 * 1024;
  const std::string bytes = manifest.Serialize();
  VerifierPolicy policy = ValidPolicy();
  policy.now_unix = manifest.not_after_unix + 1000;

  FakeBackend backend;
  backend.ed25519_verifies = false;
  const auto result =
      AuthorizeDownload(BothAnchors(), &backend, bytes, BothSignatures(), manifest, policy);
  EXPECT_EQ(static_cast<int>(result.stage), static_cast<int>(OtaStage::kManifestSignature));
}

TEST(OtaAuthorize, EveryStageHasADistinctPrintableName) {
  const std::vector<OtaStage> stages = {
      OtaStage::kManifestSignature, OtaStage::kManifestFormat, OtaStage::kAntiRollback,
      OtaStage::kValidityWindow,    OtaStage::kSizeCeiling,    OtaStage::kFetch,
      OtaStage::kPackageDigest,     OtaStage::kInstall,        OtaStage::kHashtreeRoot};
  for (OtaStage stage : stages) {
    EXPECT_NE(std::string(::xrom::ota::OtaStageName(stage)), "invalid");
  }
  EXPECT_NE(std::string(::xrom::ota::OtaVerdictName(OtaVerdict::kProceed)),
            std::string(::xrom::ota::OtaVerdictName(OtaVerdict::kRejectToVault)));
  EXPECT_NE(std::string(::xrom::ota::SignatureAlgorithmName(SignatureAlgorithm::kEd25519)),
            std::string(::xrom::ota::SignatureAlgorithmName(SignatureAlgorithm::kRsa4096Sha256)));
}

// ---------------------------------------------------------------------------
// The delivered package
// ---------------------------------------------------------------------------

TEST(OtaDelivery, MatchingLengthAndDigestProceed) {
  const OtaManifest manifest = ValidManifest();
  const auto result = CheckDeliveredPackage(manifest, manifest.package_bytes,
                                            manifest.package_sha256, ValidPolicy());
  EXPECT_TRUE(Proceeds(result));
}

TEST(OtaDelivery, AShortDownloadIsReportedAsALengthProblemNotADigestProblem) {
  // Detectable without hashing anything. Reporting it as a digest mismatch sends
  // the operator looking for tampering when the actual problem was a dropped
  // connection.
  const OtaManifest manifest = ValidManifest();
  const auto result = CheckDeliveredPackage(manifest, manifest.package_bytes - 1,
                                            manifest.package_sha256, ValidPolicy());
  EXPECT_FALSE(Proceeds(result));
  EXPECT_EQ(static_cast<int>(result.stage), static_cast<int>(OtaStage::kFetch));
  EXPECT_TRUE(result.reason.find("received") != std::string::npos);
}

TEST(OtaDelivery, AnOverlongDownloadIsRefused) {
  const OtaManifest manifest = ValidManifest();
  const auto result = CheckDeliveredPackage(manifest, manifest.package_bytes + 1,
                                            manifest.package_sha256, ValidPolicy());
  EXPECT_FALSE(Proceeds(result));
}

TEST(OtaDelivery, AWrongDigestIsRefusedAtTheDigestStage) {
  const OtaManifest manifest = ValidManifest();
  const auto result = CheckDeliveredPackage(manifest, manifest.package_bytes,
                                            std::string(64, '0'), ValidPolicy());
  EXPECT_FALSE(Proceeds(result));
  EXPECT_EQ(static_cast<int>(result.stage), static_cast<int>(OtaStage::kPackageDigest));
}

TEST(OtaDelivery, AReceivedSizeAboveTheCeilingIsRefusedEvenIfTheLengthMatches) {
  // Reachable when the declaration and the delivery agree but both are over the
  // ceiling — which happens if the ceiling was tightened between authorising the
  // download and checking it, or if this stage is entered without going through
  // AuthorizeDownload at all. The length check above cannot catch it, because the
  // length is exactly what was declared.
  OtaManifest manifest = ValidManifest();
  manifest.package_bytes = 2048;
  VerifierPolicy policy = ValidPolicy();
  policy.max_package_bytes = 1024;
  const auto result =
      CheckDeliveredPackage(manifest, 2048, manifest.package_sha256, policy);
  EXPECT_FALSE(Proceeds(result));
  EXPECT_EQ(static_cast<int>(result.stage), static_cast<int>(OtaStage::kFetch));
  EXPECT_TRUE(result.reason.find("despite a compliant declaration") != std::string::npos);
}

TEST(OtaDelivery, DigestComparisonIsCaseInsensitive) {
  // Hex casing is a formatting choice made by whoever produced the digest, not a
  // property of the bytes. Refusing an uppercase digest would be a false alarm on
  // a correct download.
  const OtaManifest manifest = ValidManifest();
  std::string uppercase = manifest.package_sha256;
  for (char& c : uppercase) {
    if (c >= 'a' && c <= 'f') {
      c = static_cast<char>(c - 'a' + 'A');
    }
  }
  EXPECT_NE(uppercase, manifest.package_sha256);
  EXPECT_TRUE(Proceeds(
      CheckDeliveredPackage(manifest, manifest.package_bytes, uppercase, ValidPolicy())));
}

TEST(OtaDelivery, AMissingDigestIsRefused) {
  const OtaManifest manifest = ValidManifest();
  const auto result =
      CheckDeliveredPackage(manifest, manifest.package_bytes, "", ValidPolicy());
  EXPECT_FALSE(Proceeds(result));
  EXPECT_TRUE(result.reason.find("no digest") != std::string::npos);
}

// ---------------------------------------------------------------------------
// The installed image
// ---------------------------------------------------------------------------

TEST(OtaInstall, TheInstalledImageHasToMatchWhatTheManifestPromised) {
  const OtaManifest manifest = ValidManifest();
  EXPECT_TRUE(Proceeds(CheckInstalledImage(
      manifest, manifest.expected_hashtree_root_sha256, ValidPolicy())));

  // A package can verify, download intact, install cleanly, and still produce an
  // image that is not the one that was signed. This is the check that catches it.
  const auto wrong =
      CheckInstalledImage(manifest, std::string(64, 'b'), ValidPolicy());
  EXPECT_FALSE(Proceeds(wrong));
  EXPECT_EQ(static_cast<int>(wrong.stage), static_cast<int>(OtaStage::kHashtreeRoot));
  EXPECT_TRUE(wrong.reason.find("still produced an image") != std::string::npos);
}

TEST(OtaInstall, AnUnreportedHashtreeRootIsRefused) {
  const OtaManifest manifest = ValidManifest();
  const auto result = CheckInstalledImage(manifest, "", ValidPolicy());
  EXPECT_FALSE(Proceeds(result));
  EXPECT_TRUE(result.reason.find("nothing to compare") != std::string::npos);
}
