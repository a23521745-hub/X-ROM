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

#include "VaultMetadata.h"

#include <cstring>

namespace xrom::recovery {
namespace {

bool AllSame(const uint8_t (&digest)[32], uint8_t value) {
  for (size_t i = 0; i < sizeof(digest); ++i) {
    if (digest[i] != value) {
      return false;
    }
  }
  return true;
}

char HexNibble(uint8_t nibble) {
  return static_cast<char>(nibble < 10 ? ('0' + nibble) : ('a' + (nibble - 10)));
}

}  // namespace

const char* VaultStateName(VaultState state) {
  switch (state) {
    case VaultState::kEmpty:
      return "empty";
    case VaultState::kWritten:
      return "written";
    case VaultState::kVerified:
      return "verified";
    case VaultState::kMismatch:
      return "mismatch";
    case VaultState::kRolledBack:
      return "rolled-back";
  }
  return "invalid";
}

bool IsValidVaultState(VaultState state) {
  switch (state) {
    case VaultState::kEmpty:
    case VaultState::kWritten:
    case VaultState::kVerified:
    case VaultState::kMismatch:
    case VaultState::kRolledBack:
      return true;
  }
  return false;
}

void MakeEmptyRecord(VaultRecord* out) {
  if (out == nullptr) {
    return;
  }
  // 0xA5 rather than 0x00: an erased partition reads as 0xFF and a deliberately
  // zeroed one reads as 0x00, so a sentinel pattern makes "initialised by us"
  // distinguishable from both.
  std::memset(out, 0xA5, sizeof(*out));
  std::memcpy(out->magic, kVaultRecordMagic, sizeof(kVaultRecordMagic));
  out->record_version = kVaultRecordVersion;
  out->state = VaultState::kEmpty;
  std::memset(out->vault_hashtree_root, 0, sizeof(out->vault_hashtree_root));
  std::memset(out->system_hashtree_root, 0, sizeof(out->system_hashtree_root));
  std::memset(out->package_sha256, 0, sizeof(out->package_sha256));
  out->package_bytes = 0;
  out->security_version = 0;
  std::memset(out->build_fingerprint, 0, sizeof(out->build_fingerprint));
  out->written_unix = 0;
  out->integrity_failures = 0;
  // The reserved tail keeps the 0xA5 sentinel. An erased partition reads as 0xFF
  // and a deliberately zeroed one as 0x00, so a third pattern is what makes
  // "initialised by X-ROM" distinguishable from both.
  std::memset(out->reserved, 0xA5, sizeof(out->reserved));
}

std::string ToBytes(const VaultRecord& record) {
  return std::string(reinterpret_cast<const char*>(&record), sizeof(record));
}

bool FromBytes(const std::string& bytes, VaultRecord* out) {
  if (out == nullptr || bytes.size() != sizeof(VaultRecord)) {
    return false;
  }
  std::memcpy(out, bytes.data(), sizeof(*out));
  return true;
}

RecordValidation Validate(const VaultRecord& record) {
  RecordValidation result;

  if (std::memcmp(record.magic, kVaultRecordMagic, sizeof(kVaultRecordMagic)) != 0) {
    // Not a fatal condition on its own: an erased or never-written vault has no
    // magic. The caller turns this into VaultState::kEmpty.
    result.ok = false;
    result.reason = "magic is not XROMVLT";
    return result;
  }
  if (record.record_version != kVaultRecordVersion) {
    result.ok = false;
    result.reason = "unsupported record version " + std::to_string(record.record_version);
    return result;
  }
  if (!IsValidVaultState(record.state)) {
    result.ok = false;
    result.reason = "state byte " + std::to_string(static_cast<int>(record.state)) +
                    " is not a known VaultState";
    return result;
  }

  // An empty record must not claim to describe an image. This catches a record
  // whose state was reset without clearing the digests, which would otherwise let
  // a stale digest be compared against a fresh system.
  if (record.state == VaultState::kEmpty) {
    if (!AllSame(record.vault_hashtree_root, 0) || !AllSame(record.system_hashtree_root, 0)) {
      result.ok = false;
      result.reason = "state is empty but hashtree roots are not cleared";
      return result;
    }
    if (record.package_bytes != 0 || record.written_unix != 0) {
      result.ok = false;
      result.reason = "state is empty but the record describes an install";
      return result;
    }
    result.ok = true;
    return result;
  }

  // Anything past kEmpty describes an install, so it has to be complete. A record
  // that names a size but not a digest, or a digest but not a time, is a record
  // that was written halfway.
  if (AllSame(record.vault_hashtree_root, 0)) {
    result.ok = false;
    result.reason = "vault hashtree root is all zeroes for a non-empty state";
    return result;
  }
  if (AllSame(record.system_hashtree_root, 0)) {
    result.ok = false;
    result.reason = "system hashtree root is all zeroes for a non-empty state";
    return result;
  }
  if (AllSame(record.package_sha256, 0)) {
    result.ok = false;
    result.reason = "package sha256 is all zeroes for a non-empty state";
    return result;
  }
  if (record.package_bytes == 0) {
    result.ok = false;
    result.reason = "package_bytes is zero for a non-empty state";
    return result;
  }
  if (record.written_unix <= 0) {
    result.ok = false;
    result.reason = "written_unix must be positive for a non-empty state";
    return result;
  }
  if (record.build_fingerprint[0] == '\0') {
    result.ok = false;
    result.reason = "build_fingerprint is empty for a non-empty state";
    return result;
  }
  // The fingerprint is a fixed buffer read by code that will log it. Guarantee the
  // NUL rather than trusting the writer.
  if (record.build_fingerprint[kVaultFingerprintBytes - 1] != '\0') {
    result.ok = false;
    result.reason = "build_fingerprint is not NUL terminated";
    return result;
  }
  if (std::strlen(record.build_fingerprint) >= kVaultFingerprintBytes) {
    result.ok = false;
    result.reason = "build_fingerprint overruns its buffer";
    return result;
  }

  result.ok = true;
  return result;
}

bool DigestsEqual(const uint8_t (&a)[32], const uint8_t (&b)[32]) {
  // memcmp rather than a byte loop with early exit: not because of timing, since
  // neither digest is a secret, but because a loop that returns early is easy to
  // write wrong and this one line cannot be.
  return std::memcmp(a, b, sizeof(a)) == 0;
}

std::string DigestToHex(const uint8_t (&digest)[32]) {
  std::string hex;
  hex.resize(sizeof(digest) * 2);
  for (size_t i = 0; i < sizeof(digest); ++i) {
    hex[i * 2] = HexNibble(static_cast<uint8_t>(digest[i] >> 4));
    hex[i * 2 + 1] = HexNibble(static_cast<uint8_t>(digest[i] & 0x0F));
  }
  return hex;
}

const char* IntegrityVerdictName(IntegrityVerdict verdict) {
  switch (verdict) {
    case IntegrityVerdict::kMatch:
      return "match";
    case IntegrityVerdict::kMismatch:
      return "mismatch";
    case IntegrityVerdict::kInconclusive:
      return "inconclusive";
  }
  return "invalid";
}

std::string IntegrityReport::Describe() const {
  std::string out = std::string("integrity=") + IntegrityVerdictName(verdict);
  out += " depth=";
  out += (depth == IntegrityDepth::kDeep) ? "deep" : "hashtree-roots";
  out += " vault-state=";
  out += VaultStateName(recorded_state);
  out += " integrity-failures=" + std::to_string(integrity_failures);
  if (have_system_digest) {
    out += " system=" + system_digest_hex;
  }
  if (have_vault_digest) {
    out += " vault=" + vault_digest_hex;
  }
  if (!reason.empty()) {
    out += " (" + reason + ")";
  }
  return out;
}

IntegrityReport CompareImages(const uint8_t (&live_system_digest)[32],
                              const uint8_t (&live_vault_digest)[32], const VaultRecord& record,
                              IntegrityDepth depth) {
  IntegrityReport report;
  report.depth = depth;
  report.recorded_state = record.state;
  report.integrity_failures = record.integrity_failures;

  const RecordValidation validation = Validate(record);
  if (!validation.ok) {
    // An unparseable record is not a mismatch. The vault simply cannot vouch for
    // anything, so there is nothing to compare and the honest verdict is that the
    // check could not be made. Folding this into kMismatch would make every device
    // with an unreadable record look tampered with, and the first few of those in
    // the field would teach everyone to ignore the alarm.
    report.verdict = IntegrityVerdict::kInconclusive;
    report.reason = "the vault record is not usable: " + validation.reason;
    return report;
  }

  if (record.state == VaultState::kEmpty) {
    report.verdict = IntegrityVerdict::kInconclusive;
    report.reason =
        "the vault holds no image, so there is no fallback to compare against; "
        "this is not a failure of the running slot";
    return report;
  }

  if (record.state == VaultState::kWritten) {
    // Written but never read back. The comparison below is still performed and its
    // result still reported, but the report has to say that the record's own claim
    // was never confirmed, because a kWritten record that matches is weaker
    // evidence than a kVerified one that matches.
    report.reason =
        "the vault record says the image was written but no read-back comparison "
        "was ever completed; ";
  }

  report.have_system_digest = true;
  report.have_vault_digest = true;
  report.system_digest_hex = DigestToHex(live_system_digest);
  report.vault_digest_hex = DigestToHex(live_vault_digest);

  // The installer writes one signed image to both partitions, so at the moment of
  // writing there is one digest and the record's two fields hold it twice. If they
  // differ, the record does not describe a coherent install and no comparison
  // against it means anything.
  //
  // Checked first, rather than as a branch inside the mismatch handling below: a
  // record whose two roots disagree makes the live images match at most one of
  // them, so the failure would otherwise be reported as "the vault changed" or
  // "neither matches" — both of which send an operator hunting for tampering in a
  // vault that was simply written wrong.
  if (!DigestsEqual(record.system_hashtree_root, record.vault_hashtree_root)) {
    report.verdict = IntegrityVerdict::kMismatch;
    report.reason +=
        "the record's own two hashtree roots disagree, so the two partitions were "
        "not holding the same image when it was written; this is a mis-written "
        "vault, and restoring from it would install whatever it actually contains";
    return report;
  }

  const uint8_t (&recorded)[32] = record.system_hashtree_root;
  const bool system_matches = DigestsEqual(live_system_digest, recorded);
  const bool vault_matches = DigestsEqual(live_vault_digest, recorded);

  if (system_matches && vault_matches) {
    report.verdict = IntegrityVerdict::kMatch;
    report.reason += "the vault and the running slot hold the same image, and it is "
                     "the one that was installed";
    return report;
  }

  report.verdict = IntegrityVerdict::kMismatch;
  if (vault_matches && !system_matches) {
    // The fallback is good and the running image is not. This is the one case
    // where restoring from the vault is the right remedy, and it is the only case
    // in which it is.
    report.reason +=
        "the running slot no longer holds the image that was installed while the "
        "vault still does; the vault is a valid fallback and restoring from it is "
        "the remedy";
  } else if (system_matches && !vault_matches) {
    // The opposite. The device is fine and the safety net is not, so the correct
    // response is to rewrite the vault — and specifically NOT to restore from it,
    // which would replace a good system image with an unknown one.
    report.reason +=
        "the vault no longer holds the image that was installed while the running "
        "slot still does; the device is running a valid image and the vault must "
        "be rewritten, not restored from";
  } else {
    report.reason +=
        "neither the running slot nor the vault holds the image that was "
        "installed; there is no known-good local copy left and recovery has to "
        "come from outside the device";
  }
  return report;
}

}  // namespace xrom::recovery
