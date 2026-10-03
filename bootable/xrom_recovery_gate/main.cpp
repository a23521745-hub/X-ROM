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

// xrom_recovery_gate — decides where recovery installs from, and says why.
//
// Runs inside the recovery image. It is woken by the BCB, finds out why from the
// --xrom-reason option that xrom_sentineld appended, gathers the signals it can gather
// in an environment with no /data and no daemon to ask, and hands the resulting
// RecoverySignals to xrom::recovery::Decide() — the same function, in the same library,
// that the sentinel previews from a running system.
//
// FAIL-SECURE IS THE DEFAULT AND THE ONLY DEFAULT
// -----------------------------------------------
// Decide() answers kUseVault unless every signal is kClean. A default-constructed
// RecoverySignals is all-kUnknown and therefore decides vault. That is the property this
// gate depends on, because in recovery almost everything can fail to be determinable:
// there may be no network, no resolver, no route to the update host, and no clock. Each
// of those is an unknown, and unknown means vault.
//
// WHAT THIS FILE DELIBERATELY DOES NOT DO
// ---------------------------------------
// It does not download anything itself. It decides, reports, and then either restores
// from the vault or hands off to the OTA installer with a package the recovery's own
// download path has already fetched and staged. The installer has no network access at
// all, so the trust boundary between "fetched" and "written" is a file boundary as well
// as a process boundary.
//
// The transport probes — TLS pin, gateway MAC, captive portal — are the parts that need
// a network stack recovery may not have. Each one is left kUnknown unless this build
// provides it, and kUnknown is a doubt. A gate that guessed would be worse than one
// that says it could not tell, because the guess would be believed.

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/strings.h>

#include "BcbMessage.h"
#include "BootAttemptPolicy.h"
#include "RecoveryDecision.h"
#include "VaultMetadata.h"

namespace {

using ::xrom::recovery::BootloaderMessage;
using ::xrom::recovery::Decide;
using ::xrom::recovery::ParseRecoveryOptions;
using ::xrom::recovery::RecoveryDecision;
using ::xrom::recovery::RecoveryPolicy;
using ::xrom::recovery::RecoverySignals;
using ::xrom::recovery::Signal;
using ::xrom::recovery::VaultRecord;

constexpr char kMiscDevice[] = "/dev/block/by-name/misc";
constexpr char kVaultDevice[] = "/dev/block/by-name/xrom_vault";
constexpr char kVaultMetaDevice[] = "/dev/block/by-name/xrom_vault_meta";

// Reads the BCB straight off the partition. In recovery, libbootloader_message is
// available and is what should be used to WRITE; reading the first 2048 bytes directly
// is done here so that the gate can still find out why it was woken up if that library
// is not linked into a minimal recovery image.
bool ReadBcb(BootloaderMessage* out, std::string* error) {
  std::string bytes;
  if (!android::base::ReadFileToString(kMiscDevice, &bytes, 2048) || bytes.size() < 2048) {
    *error = "cannot read the BCB from " + std::string(kMiscDevice);
    return false;
  }
  return xrom::recovery::FromBytes(reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size(),
                                   out);
}

bool ReadVaultRecord(VaultRecord* out, std::string* error) {
  std::string bytes;
  if (!android::base::ReadFileToString(kVaultMetaDevice, &bytes,
                                       xrom::recovery::kVaultRecordBytes) ||
      bytes.size() < xrom::recovery::kVaultRecordBytes) {
    *error = "cannot read the vault record from " + std::string(kVaultMetaDevice);
    return false;
  }
  if (!xrom::recovery::FromBytes(bytes, out)) {
    *error = "the vault record is not the expected length";
    return false;
  }
  const auto validation = xrom::recovery::Validate(*out);
  if (!validation.ok) {
    *error = validation.reason;
    return false;
  }
  return true;
}

// The signals this build can actually determine. Everything else stays kUnknown, which
// Decide() treats as a doubt and which therefore pushes toward the vault.
RecoverySignals GatherSignals(const VaultRecord& record, bool vault_usable) {
  RecoverySignals signals;  // every field kUnknown

  // Whether a usable fallback exists is not one of the twelve signals; it is policy. A
  // device with no vault has nothing to fall back to, and vault_unavailable permits the
  // engine to answer kFetchRemote instead of refusing — it relaxes no check.
  (void)record;
  (void)vault_usable;

  // Network presence. In recovery the only honest source is whether an interface is up,
  // which is what this probe reads; a resolved route to the update host is a stronger
  // claim and is left to the TLS probe.
  const bool network_up =
      android::base::GetBoolProperty("sys.xrom.recovery.network_up", false);
  signals.wifi_available = network_up ? Signal::kClean : Signal::kSuspicious;

  // DNS range check. WEAK BY CONSTRUCTION and kept only because it can push a decision
  // toward the vault and never toward the network: a CIDR verifies the shape of a DNS
  // answer, not the identity of the host, and whoever controls the resolver can return
  // any address inside it. It is also brittle, because these ranges belong to whoever
  // operates the update host and change without notice. See correction #6 in docs/05.
  const std::string resolved =
      android::base::GetProperty("sys.xrom.recovery.update_host_address", "");
  if (!resolved.empty()) {
    const std::string cidrs =
        android::base::GetProperty("ro.xrom.recovery.pinned_cidrs", "");
    uint32_t address = 0;
    bool any_match = false;
    bool parsed_address = xrom::recovery::ParseIpv4(resolved, &address);
    if (parsed_address && !cidrs.empty()) {
      for (const std::string& entry : android::base::Split(cidrs, ",")) {
        xrom::recovery::Ipv4Range range;
        if (xrom::recovery::ParseIpv4Range(entry, &range) &&
            xrom::recovery::Ipv4InRange(address, range)) {
          any_match = true;
          break;
        }
      }
      signals.dns_answer_in_pinned_range = any_match ? Signal::kClean : Signal::kSuspicious;
    }
    // Unparseable address or an empty pin list leaves the signal kUnknown, which is a
    // doubt. Forgetting to configure the pins must fail toward the vault.
  }

  // The TLS public-key pin. THIS is the check that carries the weight at the transport
  // layer: a SHA-256 over the presented certificate's public key, compared against a pin
  // compiled into the recovery image. Reported by the download path, which is the only
  // component that performs a handshake.
  const std::string tls = android::base::GetProperty("sys.xrom.recovery.tls_pin", "");
  if (tls == "matched") {
    signals.tls_pin_matched = Signal::kClean;
  } else if (tls == "mismatched") {
    signals.tls_pin_matched = Signal::kSuspicious;
  }

  // The gateway MAC against a value learned during a previously trusted setup. Catches
  // an evil-twin access point on a known network, which the DNS and TLS checks can both
  // miss when the twin proxies correctly.
  const std::string mac = android::base::GetProperty("sys.xrom.recovery.gateway_mac", "");
  if (mac == "matches-learned") {
    signals.gateway_mac_matches = Signal::kClean;
  } else if (mac == "differs-from-learned") {
    signals.gateway_mac_matches = Signal::kSuspicious;
  }

  const std::string portal =
      android::base::GetProperty("sys.xrom.recovery.captive_portal", "");
  if (portal == "absent") {
    signals.captive_portal_absent = Signal::kClean;
  } else if (portal == "present") {
    signals.captive_portal_absent = Signal::kSuspicious;
  }

  // The manifest and package signals are set by whoever fetched and verified them,
  // before this gate is asked to decide. A gate that re-derived them from the same
  // properties would be trusting the component it is supposed to be checking.
  const auto read_verification = [&signals](const char* property, Signal* out) {
    const std::string value = android::base::GetProperty(property, "");
    if (value == "valid") {
      *out = Signal::kClean;
    } else if (value == "invalid") {
      *out = Signal::kSuspicious;
    }
  };
  read_verification("sys.xrom.recovery.manifest_ed25519", &signals.manifest_ed25519_valid);
  read_verification("sys.xrom.recovery.manifest_rsa4096", &signals.manifest_rsa4096_valid);
  read_verification("sys.xrom.recovery.package_ed25519", &signals.package_ed25519_valid);
  read_verification("sys.xrom.recovery.package_rsa4096", &signals.package_rsa4096_valid);
  read_verification("sys.xrom.recovery.package_matches_manifest",
                    &signals.package_matches_manifest);
  read_verification("sys.xrom.recovery.declared_size_within_limit",
                    &signals.declared_size_within_limit);

  return signals;
}

RecoveryPolicy PolicyFromProperties(bool vault_usable) {
  RecoveryPolicy policy;
  for (const std::string& entry :
       android::base::Split(android::base::GetProperty("ro.xrom.recovery.pinned_cidrs", ""), ",")) {
    if (!entry.empty()) {
      policy.pinned_cidrs.push_back(entry);
    }
  }
  policy.max_package_bytes = static_cast<uint64_t>(android::base::GetUintProperty(
      "ro.xrom.recovery.max_package_bytes", 500ull * 1024 * 1024));
  policy.require_dual_signature =
      android::base::GetBoolProperty("ro.xrom.recovery.require_dual_signature", true);
  policy.vault_unavailable = !vault_usable;
  policy.skip_dns_range_check =
      android::base::GetBoolProperty("ro.xrom.recovery.skip_dns_range_check", false);
  return policy;
}

}  // namespace

int main(int argc, char** argv) {
  android::base::InitLogging(argv);
  LOG(INFO) << "xrom_recovery_gate: starting";

  // --- why were we woken up ---------------------------------------------------
  BootloaderMessage bcb{};
  std::string error;
  std::string reason;
  if (ReadBcb(&bcb, &error)) {
    reason = xrom::recovery::XromReason(bcb);
    const auto options = ParseRecoveryOptions(bcb);
    LOG(INFO) << "xrom_recovery_gate: BCB command='" << std::string(bcb.command)
              << "' xrom-reason='" << reason << "' options=" << options.size();
    for (const std::string& option : options) {
      LOG(INFO) << "xrom_recovery_gate:   --" << option;
    }
  } else {
    LOG(WARNING) << "xrom_recovery_gate: " << error;
  }

  // --- is there a fallback ----------------------------------------------------
  VaultRecord record;
  bool vault_usable = false;
  if (ReadVaultRecord(&record, &error)) {
    vault_usable = record.state != xrom::recovery::VaultState::kEmpty;
    LOG(INFO) << "xrom_recovery_gate: vault state="
              << xrom::recovery::VaultStateName(record.state)
              << " integrity_failures=" << record.integrity_failures
              << " fingerprint=" << record.build_fingerprint;
    if (record.state == xrom::recovery::VaultState::kMismatch) {
      // Sticky, and it changes the answer. A vault that a previous boot found to be
      // wrong must not be restored from, because restoring would replace a possibly
      // good system image with a known-bad one. The honest response is to say so and
      // prefer the remote path if — and only if — every signal is clean.
      LOG(WARNING) << "xrom_recovery_gate: the vault was previously found mismatched; it "
                      "must not be restored from until it is rewritten";
      vault_usable = false;
    }
  } else {
    LOG(WARNING) << "xrom_recovery_gate: vault record unusable: " << error;
  }

  // --- decide ------------------------------------------------------------------
  const RecoverySignals signals = GatherSignals(record, vault_usable);
  const RecoveryPolicy policy = PolicyFromProperties(vault_usable);
  const RecoveryDecision decision = Decide(signals, policy);

  LOG(INFO) << "xrom_recovery_gate: DECISION "
            << (decision.IsRemote() ? "fetch-remote" : "use-vault");
  LOG(INFO) << "xrom_recovery_gate: reason: " << decision.Reason();
  for (const std::string& doubt : decision.doubts) {
    LOG(INFO) << "xrom_recovery_gate:   doubt: " << doubt;
  }
  for (const std::string& clean : decision.clean) {
    LOG(INFO) << "xrom_recovery_gate:   clean: " << clean;
  }

  // Published so that the recovery UI, the log and a later post-mortem all read the
  // same answer rather than each recomputing it from properties that may have moved.
  android::base::SetProperty("sys.xrom.recovery.decision",
                             decision.IsRemote() ? "fetch-remote" : "use-vault");
  android::base::SetProperty("sys.xrom.recovery.decision_reason", decision.Reason());

  if (decision.IsRemote()) {
    // Hand off to the download path and then to xrom_ota_installer. The installer has no
    // network access at all, so the fetched package reaches it as a file that has already
    // been verified, and the boundary between "fetched" and "written" is a process
    // boundary as well as a file boundary.
    LOG(INFO) << "xrom_recovery_gate: proceeding with the remote path; the fetched "
                 "package must be handed to xrom_ota_installer, which re-verifies it "
                 "against the pinned anchors before writing anything";
    return 0;
  }

  if (!vault_usable) {
    // No fallback and no clean network. This is the corner the design has to name rather
    // than paper over: there is no automatic remedy. Recovery reports it and stays put,
    // because attempting a download with a suspicious signal is exactly what the engine
    // refused, and reinstalling from a vault that is not usable is not a thing that can
    // be done.
    LOG(ERROR) << "xrom_recovery_gate: NO REMEDY AVAILABLE. The vault is not usable and "
                  "the network signals are not clean, so neither source can be trusted. "
                  "Operator intervention is required; recovery will not attempt a "
                  "download it has just refused.";
    android::base::SetProperty("sys.xrom.recovery.outcome", "no-remedy");
    return 1;
  }

  LOG(INFO) << "xrom_recovery_gate: restoring from the vault at " << kVaultDevice
            << " (state=" << xrom::recovery::VaultStateName(record.state) << ")";
  android::base::SetProperty("sys.xrom.recovery.outcome", "restore-from-vault");
  return 0;
}
