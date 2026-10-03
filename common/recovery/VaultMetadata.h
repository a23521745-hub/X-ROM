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

#ifndef XROM_RECOVERY_VAULT_METADATA_H_
#define XROM_RECOVERY_VAULT_METADATA_H_

#include <cstdint>
#include <cstddef>
#include <string>

namespace xrom::recovery {

// ---------------------------------------------------------------------------
// The record the OTA installer leaves behind on the xrom_vault partition, and the
// post-boot comparison that reads it.
//
// WHAT IS ACTUALLY COMPARED, AND WHY NOT A SHA-256 OF /system
// -----------------------------------------------------------
// The obvious implementation of "hash both partitions and compare" is to read
// every byte of /system and every byte of xrom_vault and compare the digests. That
// is several gigabytes of flash I/O on every boot, on a device that is about to
// start an app, and it buys almost nothing: /system is already covered by AVB's
// hashtree, which the bootloader authenticated before the kernel started, and
// dm-verity, which re-checks every block as it is read. Recomputing a digest over
// blocks that dm-verity has already verified is paying twice for one guarantee.
//
// So the primary comparison here is over the authenticated root digests — the
// vbmeta hashtree root of the image the installer wrote, and the vbmeta hashtree
// root of the image now on the vault. Those are 32 bytes each, already computed by
// the AVB tooling, and comparing them answers the real question: is the vault
// holding the same system image the running slot holds? A full-content digest is
// still supported (kDeep) and is still useful, but it is opt-in and it is used
// when the cheap comparison has already found something worth explaining, not as
// the thing that gates boot.
//
// THE RECORD IS SELF-DESCRIBING AND VERSIONED
// -------------------------------------------
// A vault that survives a factory reset of /data, or that is read by a recovery
// image from a different build, has to say what it is before it can be trusted.
// Hence a magic, a version, an explicit state, and a reserved tail so that a later
// record can grow without invalidating an older one. The record is fixed size and
// written with the same read-modify-write discipline as the BCB: a partial write
// here is a vault that looks empty rather than a vault that looks corrupt, which is
// the failure mode that is survivable.
// ---------------------------------------------------------------------------

// "XROMVLT" plus a NUL. Compared byte for byte; never parsed as a string.
constexpr uint8_t kVaultRecordMagic[8] = {'X', 'R', 'O', 'M', 'V', 'L', 'T', '\0'};
constexpr uint32_t kVaultRecordVersion = 1;
constexpr size_t kVaultRecordBytes = 384;
constexpr size_t kVaultFingerprintBytes = 96;

// Where the vault stands. Transitions are one-directional except for the reset
// back to kEmpty, and the sentinel refuses to treat kWritten as kVerified: a
// record that says the bytes were written but not that they were read back and
// compared is a record whose claim has not been checked.
enum class VaultState : uint8_t {
  // Nothing has ever been written, or the record failed to parse. Both are treated
  // as "the vault cannot be used as a fallback", which pushes every recovery
  // decision toward trying to fix the running slot instead.
  kEmpty = 0,
  // The installer wrote the image and the record, but no read-back comparison has
  // been completed.
  kWritten = 1,
  // Written, read back, and matching the running slot at the time of writing.
  kVerified = 2,
  // A post-boot comparison found a difference. Sticky: it is only cleared by a
  // successful restore, never by a boot that happened to look fine.
  kMismatch = 3,
  // The vault was used to restore the running slot.
  kRolledBack = 4,
};

const char* VaultStateName(VaultState state);
bool IsValidVaultState(VaultState state);

struct __attribute__((packed, aligned(1))) VaultRecord {
  uint8_t magic[8];
  uint32_t record_version;
  VaultState state;

  // vbmeta hashtree root digest of the system image written to the vault. This is
  // the authoritative "what is in here" value.
  uint8_t vault_hashtree_root[32];

  // vbmeta hashtree root digest of the running slot at the moment of writing.
  // Comparing these two is the cheap post-boot integrity check.
  uint8_t system_hashtree_root[32];

  // SHA-256 of the signed OTA package exactly as it was received, before it was
  // unpacked. Distinct from the hashtree roots on purpose: this identifies the
  // artifact that was installed, which is what has to match the manifest, while
  // the hashtree roots identify the resulting images.
  uint8_t package_sha256[32];

  uint64_t package_bytes;
  uint32_t security_version;

  // ro.build.fingerprint of the image written, truncated to 95 characters and NUL
  // terminated. Used for the anti-rollback check and for the incident log; not
  // trusted on its own, because a fingerprint is a claim and the digests are the
  // evidence.
  char build_fingerprint[kVaultFingerprintBytes];

  int64_t written_unix;

  // Boot-loop accounting owned by the sentinel. See BootAttemptPolicy.h for why
  // this is a separate counter from the bootloader's.
  uint32_t integrity_failures;

  uint8_t reserved[155];
};

static_assert(sizeof(VaultRecord) == kVaultRecordBytes,
              "VaultRecord must be exactly kVaultRecordBytes; the reserved tail "
              "absorbs growth so that an older record still parses");
static_assert(offsetof(VaultRecord, magic) == 0, "VaultRecord must start with the magic");

// Fills a record with the empty-vault state. Deliberately NOT all zeroes: an
// erased flash partition reads as 0xFF, and a zeroed record would be
// indistinguishable from "someone wrote zeroes here", which is a different and
// more suspicious fact.
void MakeEmptyRecord(VaultRecord* out);

// Serialises and deserialises. ToBytes always writes exactly kVaultRecordBytes.
std::string ToBytes(const VaultRecord& record);
bool FromBytes(const std::string& bytes, VaultRecord* out);

// Whether a parsed record is internally consistent: magic, version, state, and the
// ordering of the fields that have an order.
struct RecordValidation {
  bool ok = false;
  std::string reason;
};
RecordValidation Validate(const VaultRecord& record);

bool DigestsEqual(const uint8_t (&a)[32], const uint8_t (&b)[32]);
std::string DigestToHex(const uint8_t (&digest)[32]);

// --- the post-boot integrity check ------------------------------------------

enum class IntegrityDepth : int32_t {
  // Compare the authenticated hashtree roots only. Cheap, and it is the default.
  kHashtreeRoots = 0,
  // Also read both partitions in full and compare SHA-256. Opt-in: gigabytes of
  // I/O, used to explain a mismatch that kHashtreeRoots already found, or on an
  // explicit operator request.
  kDeep = 1,
};

enum class IntegrityVerdict : int32_t {
  // The vault and the running slot hold the same system image.
  kMatch = 0,
  // They differ. The user is notified and the event is logged; the device keeps
  // running, because a mismatch means the fallback is wrong, not that the running
  // slot is — the running slot is authenticated by AVB on every boot.
  kMismatch = 1,
  // The comparison could not be completed. Reported as its own verdict rather
  // than being folded into kMismatch, because "I could not check" has a different
  // remedy from "I checked and they differ", and conflating them makes the
  // incident log useless for triage.
  kInconclusive = 2,
};

const char* IntegrityVerdictName(IntegrityVerdict verdict);

struct IntegrityReport {
  IntegrityVerdict verdict = IntegrityVerdict::kInconclusive;
  IntegrityDepth depth = IntegrityDepth::kHashtreeRoots;
  std::string reason;

  // Present whenever both sides could be read, even on a mismatch, so that the
  // notification and the log carry the actual values rather than just a flag.
  bool have_system_digest = false;
  bool have_vault_digest = false;
  std::string system_digest_hex;
  std::string vault_digest_hex;

  // The record's own view, echoed for the log.
  VaultState recorded_state = VaultState::kEmpty;
  uint32_t integrity_failures = 0;

  std::string Describe() const;
};

// Compares what is live on both partitions against what the record says was
// written to them. Pure: the caller reads the partitions and the record, this
// function decides. Keeping the decision separate from the I/O is what makes
// "notify the user on mismatch" testable without a device.
//
// BOTH live digests are inputs, and that is not redundant. The record stores the
// roots as they were at install time, so it can prove that something changed but
// cannot say which partition changed — reading only /system and comparing it to a
// stored value cannot distinguish a tampered slot from a tampered vault. The
// remedies are opposite: restore FROM the vault in the first case, and in the
// second case absolutely do not, because the vault is the thing that is wrong.
//
// |depth| says what kind of digest the two inputs are. At kHashtreeRoots they are
// the AVB hashtree roots, which are cheap and already authenticated. At kDeep they
// are SHA-256 over every byte of each partition, which is gigabytes of I/O and is
// opt-in.
IntegrityReport CompareImages(const uint8_t (&live_system_digest)[32],
                              const uint8_t (&live_vault_digest)[32], const VaultRecord& record,
                              IntegrityDepth depth);

}  // namespace xrom::recovery

#endif  // XROM_RECOVERY_VAULT_METADATA_H_
