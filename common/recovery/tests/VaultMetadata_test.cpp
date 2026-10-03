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

// Tests for common/recovery/VaultMetadata.cpp.
//
// The comparison under test is over vbmeta hashtree root digests rather than over
// SHA-256 of every byte of /system, and the tests assert the consequences of that
// choice:
//
//   * a mismatch has to say WHICH side moved, because "restore from the vault" and
//     "rewrite the vault" are different remedies and an incident log that cannot
//     tell them apart cannot be acted on;
//   * "the vault is empty" is inconclusive, not a mismatch — a device that has
//     never had an OTA installed has no fallback, and reporting that as tampering
//     would train everyone to ignore the real alarm;
//   * a record that fails to parse is inconclusive for the same reason, and the
//     parse failure has to reach the log.
//
// Also asserted: an erased partition reads as 0xFF, so the empty record is
// deliberately not all zeroes. A zeroed record and an erased one are different
// facts and the second is more suspicious.

#include "VaultMetadata.h"

#include <cstring>
#include <string>

#include "gtest/gtest.h"

namespace {

using ::xrom::recovery::CompareImages;
using ::xrom::recovery::DigestsEqual;
using ::xrom::recovery::DigestToHex;
using ::xrom::recovery::IntegrityDepth;
using ::xrom::recovery::IntegrityVerdict;
using ::xrom::recovery::MakeEmptyRecord;
using ::xrom::recovery::VaultRecord;
using ::xrom::recovery::VaultState;

void Fill(uint8_t (&digest)[32], uint8_t seed) {
  for (size_t i = 0; i < sizeof(digest); ++i) {
    digest[i] = static_cast<uint8_t>(seed + i);
  }
}

// A record describing a completed, verified install.
VaultRecord InstalledRecord() {
  VaultRecord record;
  MakeEmptyRecord(&record);
  record.state = VaultState::kVerified;
  Fill(record.vault_hashtree_root, 0x10);
  std::memcpy(record.system_hashtree_root, record.vault_hashtree_root, 32);
  Fill(record.package_sha256, 0x80);
  record.package_bytes = 256ull * 1024 * 1024;
  record.security_version = 7;
  std::memcpy(record.build_fingerprint, "X-ROM/x1/16/AP1A.000000.000/1:user/release-keys", 48);
  record.written_unix = 1767225600;
  record.integrity_failures = 0;
  return record;
}

}  // namespace

// ---------------------------------------------------------------------------
// Layout and serialisation
// ---------------------------------------------------------------------------

TEST(VaultMetadata, RecordIsExactlyTheDeclaredSize) {
  EXPECT_EQ(sizeof(VaultRecord), xrom::recovery::kVaultRecordBytes);
  EXPECT_EQ(alignof(VaultRecord), 1u);
  EXPECT_EQ(offsetof(VaultRecord, magic), 0u);
}

TEST(VaultMetadata, EmptyRecordIsValidAndIsNotAllZeroes) {
  VaultRecord record;
  MakeEmptyRecord(&record);
  EXPECT_TRUE(xrom::recovery::Validate(record).ok);
  EXPECT_EQ(static_cast<int>(record.state), static_cast<int>(VaultState::kEmpty));

  // The reserved tail carries the sentinel pattern, so an erased partition and an
  // initialised one are distinguishable.
  EXPECT_NE(static_cast<int>(record.reserved[0]), 0);
  EXPECT_EQ(static_cast<int>(record.reserved[0]), 0xA5);
}

TEST(VaultMetadata, AnErasedPartitionDoesNotParseAsAValidRecord) {
  // Fresh flash reads as all 0xFF. If that parsed as a valid empty vault, the
  // sentinel could never tell "never written" from "written and then erased".
  VaultRecord record;
  std::memset(&record, 0xFF, sizeof(record));
  const auto validation = xrom::recovery::Validate(record);
  EXPECT_FALSE(validation.ok);
  EXPECT_TRUE(validation.reason.find("magic") != std::string::npos);
}

TEST(VaultMetadata, RoundTripsThroughBytes) {
  const VaultRecord original = InstalledRecord();
  const std::string bytes = xrom::recovery::ToBytes(original);
  EXPECT_EQ(bytes.size(), xrom::recovery::kVaultRecordBytes);

  VaultRecord restored;
  std::memset(&restored, 0, sizeof(restored));
  EXPECT_TRUE(xrom::recovery::FromBytes(bytes, &restored));
  EXPECT_EQ(std::memcmp(&original, &restored, sizeof(original)), 0);
}

TEST(VaultMetadata, FromBytesRejectsTheWrongLength) {
  VaultRecord record;
  EXPECT_FALSE(xrom::recovery::FromBytes("", &record));
  EXPECT_FALSE(xrom::recovery::FromBytes(std::string(xrom::recovery::kVaultRecordBytes - 1, '\0'),
                                        &record));
  EXPECT_FALSE(xrom::recovery::FromBytes(std::string(xrom::recovery::kVaultRecordBytes + 1, '\0'),
                                        &record));
  EXPECT_FALSE(xrom::recovery::FromBytes(std::string(xrom::recovery::kVaultRecordBytes, '\0'),
                                        nullptr));
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

TEST(VaultMetadata, ValidateRejectsAVersionItDoesNotKnow) {
  VaultRecord record = InstalledRecord();
  record.record_version = xrom::recovery::kVaultRecordVersion + 1;
  const auto validation = xrom::recovery::Validate(record);
  EXPECT_FALSE(validation.ok);
  EXPECT_TRUE(validation.reason.find("version") != std::string::npos);
}

TEST(VaultMetadata, ValidateRejectsAnUnknownStateByte) {
  VaultRecord record = InstalledRecord();
  record.state = static_cast<VaultState>(99);
  EXPECT_FALSE(xrom::recovery::Validate(record).ok);
  EXPECT_FALSE(xrom::recovery::IsValidVaultState(record.state));
}

TEST(VaultMetadata, ValidateRejectsAnEmptyStateThatStillDescribesAnInstall) {
  // Resetting the state without clearing the digests would let a stale digest be
  // compared against a fresh system, and the comparison would look meaningful.
  VaultRecord record = InstalledRecord();
  record.state = VaultState::kEmpty;
  const auto validation = xrom::recovery::Validate(record);
  EXPECT_FALSE(validation.ok);
  EXPECT_TRUE(validation.reason.find("hashtree roots are not cleared") != std::string::npos);
}

TEST(VaultMetadata, ValidateRejectsAHalfWrittenRecord) {
  const struct {
    const char* what;
    void (*break_it)(VaultRecord*);
  } cases[] = {
      {"zeroed vault root",
       [](VaultRecord* r) { std::memset(r->vault_hashtree_root, 0, 32); }},
      {"zeroed system root",
       [](VaultRecord* r) { std::memset(r->system_hashtree_root, 0, 32); }},
      {"zeroed package digest", [](VaultRecord* r) { std::memset(r->package_sha256, 0, 32); }},
      {"zero package size", [](VaultRecord* r) { r->package_bytes = 0; }},
      {"zero timestamp", [](VaultRecord* r) { r->written_unix = 0; }},
      {"negative timestamp", [](VaultRecord* r) { r->written_unix = -1; }},
      {"empty fingerprint", [](VaultRecord* r) { r->build_fingerprint[0] = '\0'; }},
  };
  for (const auto& test_case : cases) {
    VaultRecord record = InstalledRecord();
    test_case.break_it(&record);
    EXPECT_FALSE(xrom::recovery::Validate(record).ok);
  }
}

TEST(VaultMetadata, ValidateRejectsAnUnterminatedFingerprint) {
  // The fingerprint is logged by code that treats it as a C string. Trusting the
  // writer to have left a NUL is how a fixed buffer becomes a read past its end.
  VaultRecord record = InstalledRecord();
  std::memset(record.build_fingerprint, 'A', xrom::recovery::kVaultFingerprintBytes);
  const auto validation = xrom::recovery::Validate(record);
  EXPECT_FALSE(validation.ok);
  EXPECT_TRUE(validation.reason.find("NUL") != std::string::npos);
}

TEST(VaultMetadata, EveryNamedStateHasADistinctName) {
  const VaultState states[] = {VaultState::kEmpty,      VaultState::kWritten,
                               VaultState::kVerified,   VaultState::kMismatch,
                               VaultState::kRolledBack};
  for (VaultState state : states) {
    EXPECT_TRUE(xrom::recovery::IsValidVaultState(state));
    EXPECT_NE(std::string(xrom::recovery::VaultStateName(state)), "invalid");
  }
}

// ---------------------------------------------------------------------------
// Digest helpers
// ---------------------------------------------------------------------------

TEST(VaultMetadata, DigestToHexIsLowercaseAndComplete) {
  uint8_t digest[32];
  for (size_t i = 0; i < sizeof(digest); ++i) {
    digest[i] = static_cast<uint8_t>(i);
  }
  const std::string hex = DigestToHex(digest);
  EXPECT_EQ(hex.size(), 64u);
  EXPECT_EQ(hex, "000102030405060708090a0b0c0d0e0f"
                 "101112131415161718191a1b1c1d1e1f");
}

TEST(VaultMetadata, DigestsEqualComparesAllThirtyTwoBytes) {
  uint8_t a[32];
  uint8_t b[32];
  Fill(a, 0x40);
  Fill(b, 0x40);
  EXPECT_TRUE(DigestsEqual(a, b));

  b[0] ^= 0x01;
  EXPECT_FALSE(DigestsEqual(a, b));
  b[0] ^= 0x01;
  b[31] ^= 0x80;
  EXPECT_FALSE(DigestsEqual(a, b));
}

// ---------------------------------------------------------------------------
// The post-boot comparison
// ---------------------------------------------------------------------------

TEST(VaultIntegrity, MatchingImagesReportAMatch) {
  const VaultRecord record = InstalledRecord();
  const auto report = CompareImages(record.system_hashtree_root, record.vault_hashtree_root,
                                    record, IntegrityDepth::kHashtreeRoots);
  EXPECT_EQ(static_cast<int>(report.verdict), static_cast<int>(IntegrityVerdict::kMatch));
  EXPECT_TRUE(report.have_system_digest);
  EXPECT_TRUE(report.have_vault_digest);
  EXPECT_EQ(report.system_digest_hex, report.vault_digest_hex);
  EXPECT_EQ(static_cast<int>(report.recorded_state), static_cast<int>(VaultState::kVerified));
}

TEST(VaultIntegrity, TwoIdenticalLiveImagesStillFailIfNeitherIsWhatWasInstalled) {
  // /system and xrom_vault agreeing is not the same as them being right. Both
  // could have been replaced by the same tampered image, and a comparison that
  // only looked at the two live digests would call that a match.
  const VaultRecord record = InstalledRecord();
  uint8_t replaced[32];
  Fill(replaced, 0xC0);

  const auto report =
      CompareImages(replaced, replaced, record, IntegrityDepth::kHashtreeRoots);
  EXPECT_EQ(static_cast<int>(report.verdict), static_cast<int>(IntegrityVerdict::kMismatch));
  EXPECT_TRUE(report.reason.find("neither") != std::string::npos);
}

TEST(VaultIntegrity, AChangedRunningSlotIsIdentifiedAsTheChangedSide) {
  // The remedy here is to restore from the vault, and the log has to say so.
  const VaultRecord record = InstalledRecord();
  uint8_t tampered_slot[32];
  std::memcpy(tampered_slot, record.system_hashtree_root, 32);
  tampered_slot[7] ^= 0xFF;

  const auto report = CompareImages(tampered_slot, record.vault_hashtree_root, record,
                                    IntegrityDepth::kHashtreeRoots);
  EXPECT_EQ(static_cast<int>(report.verdict), static_cast<int>(IntegrityVerdict::kMismatch));
  EXPECT_TRUE(report.reason.find("running slot no longer holds") != std::string::npos);
  EXPECT_TRUE(report.reason.find("restoring from it is the remedy") != std::string::npos);
  EXPECT_NE(report.system_digest_hex, report.vault_digest_hex);
}

TEST(VaultIntegrity, AChangedVaultIsIdentifiedAndExplicitlyNotRecommendedAsAFallback) {
  // The opposite remedy. The device is fine and the safety net is not, so the
  // report has to say "rewrite it" and specifically warn against restoring.
  const VaultRecord record = InstalledRecord();
  uint8_t tampered_vault[32];
  std::memcpy(tampered_vault, record.vault_hashtree_root, 32);
  tampered_vault[3] ^= 0x01;

  const auto report = CompareImages(record.system_hashtree_root, tampered_vault, record,
                                    IntegrityDepth::kHashtreeRoots);
  EXPECT_EQ(static_cast<int>(report.verdict), static_cast<int>(IntegrityVerdict::kMismatch));
  EXPECT_TRUE(report.reason.find("vault no longer holds") != std::string::npos);
  EXPECT_TRUE(report.reason.find("not restored from") != std::string::npos);
}

TEST(VaultIntegrity, ARecordWhoseOwnTwoRootsDisagreeIsCalledMisWritten) {
  // The installer writes one image to both partitions, so the record's two roots
  // are one value stored twice. If they differ the record does not describe a
  // coherent install, and reporting that as "the vault changed" would send an
  // operator hunting for tampering in a vault that was written wrong.
  VaultRecord record = InstalledRecord();
  record.vault_hashtree_root[0] ^= 0x01;

  const auto report = CompareImages(record.system_hashtree_root, record.vault_hashtree_root,
                                    record, IntegrityDepth::kHashtreeRoots);
  EXPECT_EQ(static_cast<int>(report.verdict), static_cast<int>(IntegrityVerdict::kMismatch));
  EXPECT_TRUE(report.reason.find("mis-written") != std::string::npos);
}

TEST(VaultIntegrity, AnEmptyVaultIsInconclusiveNotAMismatch) {
  // A device that has never had an OTA installed has no fallback. Reporting that
  // as tampering would make every fresh device alarm on first boot.
  VaultRecord record;
  MakeEmptyRecord(&record);
  uint8_t system_root[32];
  uint8_t vault_root[32];
  Fill(system_root, 0x30);
  Fill(vault_root, 0x40);

  const auto report =
      CompareImages(system_root, vault_root, record, IntegrityDepth::kHashtreeRoots);
  EXPECT_EQ(static_cast<int>(report.verdict), static_cast<int>(IntegrityVerdict::kInconclusive));
  EXPECT_TRUE(report.reason.find("holds no image") != std::string::npos);
  EXPECT_FALSE(report.have_system_digest);
  EXPECT_FALSE(report.have_vault_digest);
}

TEST(VaultIntegrity, AnUnparseableRecordIsInconclusiveAndSaysWhy) {
  VaultRecord record = InstalledRecord();
  record.record_version = 99;
  uint8_t digest[32];
  Fill(digest, 0x30);

  const auto report = CompareImages(digest, digest, record, IntegrityDepth::kHashtreeRoots);
  EXPECT_EQ(static_cast<int>(report.verdict), static_cast<int>(IntegrityVerdict::kInconclusive));
  EXPECT_TRUE(report.reason.find("not usable") != std::string::npos);
  EXPECT_TRUE(report.reason.find("version") != std::string::npos);
}

TEST(VaultIntegrity, AWrittenButNeverConfirmedRecordIsStillCompared) {
  // The comparison is performed and its result reported, but the report has to
  // say the record's own claim was never confirmed: a kWritten record that
  // matches is weaker evidence than a kVerified one that matches.
  VaultRecord record = InstalledRecord();
  record.state = VaultState::kWritten;

  const auto report = CompareImages(record.system_hashtree_root, record.vault_hashtree_root,
                                    record, IntegrityDepth::kHashtreeRoots);
  EXPECT_EQ(static_cast<int>(report.verdict), static_cast<int>(IntegrityVerdict::kMatch));
  EXPECT_TRUE(report.reason.find("no read-back comparison") != std::string::npos);
}

TEST(VaultIntegrity, TheDepthIsCarriedIntoTheReport) {
  // A log entry that says "the images matched" has to also say what kind of
  // digest was compared, or a cheap hashtree-root check reads like a full one.
  const VaultRecord record = InstalledRecord();
  const auto deep = CompareImages(record.system_hashtree_root, record.vault_hashtree_root,
                                  record, IntegrityDepth::kDeep);
  EXPECT_EQ(static_cast<int>(deep.depth), static_cast<int>(IntegrityDepth::kDeep));
  EXPECT_TRUE(deep.Describe().find("depth=deep") != std::string::npos);

  const auto cheap = CompareImages(record.system_hashtree_root, record.vault_hashtree_root,
                                   record, IntegrityDepth::kHashtreeRoots);
  EXPECT_TRUE(cheap.Describe().find("depth=hashtree-roots") != std::string::npos);
}

TEST(VaultIntegrity, DescribeCarriesTheDigestsTheNotificationNeeds) {
  const VaultRecord record = InstalledRecord();
  uint8_t tampered_slot[32];
  std::memcpy(tampered_slot, record.system_hashtree_root, 32);
  tampered_slot[0] ^= 0x01;

  const std::string description = CompareImages(tampered_slot, record.vault_hashtree_root,
                                                record, IntegrityDepth::kHashtreeRoots)
                                      .Describe();
  EXPECT_TRUE(description.find("integrity=mismatch") != std::string::npos);
  // The user is told the images differ; the log carries the actual values so that
  // the report can be checked against the manifest later.
  EXPECT_TRUE(description.find("system=" + DigestToHex(tampered_slot)) != std::string::npos);
  EXPECT_TRUE(description.find("vault=" + DigestToHex(record.vault_hashtree_root)) !=
              std::string::npos);
  EXPECT_TRUE(description.find("vault-state=verified") != std::string::npos);
}

TEST(VaultIntegrity, MismatchAndMatchProduceDifferentVerdictNames) {
  EXPECT_NE(std::string(xrom::recovery::IntegrityVerdictName(IntegrityVerdict::kMatch)),
            std::string(xrom::recovery::IntegrityVerdictName(IntegrityVerdict::kMismatch)));
  EXPECT_NE(std::string(xrom::recovery::IntegrityVerdictName(IntegrityVerdict::kMismatch)),
            std::string(xrom::recovery::IntegrityVerdictName(IntegrityVerdict::kInconclusive)));
  EXPECT_NE(std::string(xrom::recovery::IntegrityVerdictName(IntegrityVerdict::kInconclusive)),
            "invalid");
}

TEST(VaultIntegrity, IntegrityFailureCountIsEchoedForTheBootLoopGuard) {
  VaultRecord record = InstalledRecord();
  record.integrity_failures = 2;
  const auto report = CompareImages(record.system_hashtree_root, record.vault_hashtree_root,
                                    record, IntegrityDepth::kHashtreeRoots);
  EXPECT_EQ(report.integrity_failures, 2u);
  EXPECT_TRUE(report.Describe().find("integrity-failures=2") != std::string::npos);
}
