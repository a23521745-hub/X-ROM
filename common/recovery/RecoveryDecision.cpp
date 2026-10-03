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

#include "RecoveryDecision.h"

#include <cstdlib>
#include <cstring>

namespace xrom::recovery {
namespace {

// One row of the check table. |required| means the signal must be kClean for the
// remote path to be taken; a non-required signal may only ever push the decision
// towards the vault, never away from it.
struct Check {
  const char* name;
  Signal value;
  bool required;
};

std::vector<Check> TableOf(const RecoverySignals& signals, const RecoveryPolicy& policy) {
  std::vector<Check> table = {
      {"wifi_available", signals.wifi_available, true},
      {"tls_pin_matched", signals.tls_pin_matched, true},
      {"gateway_mac_matches", signals.gateway_mac_matches, true},
      {"captive_portal_absent", signals.captive_portal_absent, true},
      {"manifest_ed25519_valid", signals.manifest_ed25519_valid, true},
      {"package_ed25519_valid", signals.package_ed25519_valid, true},
      {"declared_size_within_limit", signals.declared_size_within_limit, true},
      {"package_matches_manifest", signals.package_matches_manifest, true},

      // Weak by construction (see the header): it can only ever add a doubt.
      {"dns_answer_in_pinned_range", signals.dns_answer_in_pinned_range,
       !policy.skip_dns_range_check},
  };

  // The second signature is required only when the policy asks for both. Turning
  // it off is a deliberate, logged weakening, not a default.
  if (policy.require_dual_signature) {
    table.push_back({"manifest_rsa4096_valid", signals.manifest_rsa4096_valid, true});
    table.push_back({"package_rsa4096_valid", signals.package_rsa4096_valid, true});
  }
  return table;
}

}  // namespace

const char* SignalName(Signal signal) {
  switch (signal) {
    case Signal::kUnknown:
      return "unknown";
    case Signal::kClean:
      return "clean";
    case Signal::kSuspicious:
      return "suspicious";
  }
  return "invalid";
}

const char* RecoverySourceName(RecoverySource source) {
  switch (source) {
    case RecoverySource::kUseVault:
      return "xrom_vault";
    case RecoverySource::kFetchRemote:
      return "remote-ota";
  }
  return "invalid";
}

std::string RecoveryDecision::Reason() const {
  std::string out = std::string("install from ") + RecoverySourceName(source);
  if (!doubts.empty()) {
    out += "; " + std::to_string(doubts.size()) + " doubt(s): ";
    for (size_t i = 0; i < doubts.size(); ++i) {
      if (i != 0) {
        out += ", ";
      }
      out += doubts[i];
    }
  } else {
    out += "; every check clean (" + std::to_string(clean.size()) + ")";
  }
  return out;
}

RecoveryDecision Decide(const RecoverySignals& signals, const RecoveryPolicy& policy) {
  RecoveryDecision decision;

  // No network is not a doubt among many, it is the end of the question. Reporting
  // the eleven signals that could not possibly have been checked would bury the
  // only fact that matters, so this one short-circuits.
  if (signals.wifi_available != Signal::kClean) {
    decision.source = RecoverySource::kUseVault;
    decision.doubts.push_back(signals.wifi_available == Signal::kSuspicious
                                  ? "no usable network interface"
                                  : "network availability was never determined");
    return decision;
  }
  decision.clean.push_back("wifi_available");

  // The pinned CIDR list is policy, and an empty list with the check enabled means
  // nobody configured it. That is a doubt rather than a pass, so that a build
  // which forgot the pins fails towards the vault instead of towards the network.
  if (!policy.skip_dns_range_check && policy.pinned_cidrs.empty()) {
    decision.doubts.push_back("dns_answer_in_pinned_range: policy pins no CIDR, so the check "
                              "cannot pass; set pinned_cidrs or skip_dns_range_check");
  }

  for (const Check& check : TableOf(signals, policy)) {
    if (check.value == Signal::kClean) {
      decision.clean.push_back(check.name);
      continue;
    }
    if (!check.required && check.value == Signal::kUnknown) {
      // An optional check that never ran adds no information either way.
      continue;
    }
    decision.doubts.push_back(std::string(check.name) + "=" + SignalName(check.value));
  }

  if (!decision.doubts.empty()) {
    decision.source = RecoverySource::kUseVault;
    return decision;
  }

  if (policy.vault_unavailable) {
    // There is no fallback to prefer, so the remote path is the only path. Note
    // that this branch is reached only after every check above was clean: the flag
    // permits a decision, it does not relax a check.
    decision.source = RecoverySource::kFetchRemote;
    return decision;
  }

  // Every signal clean and a vault copy present. The remote fetch is still the
  // better answer here, because it can deliver a newer image than the one baked
  // into the device — that is the entire point of the hybrid design. The vault is
  // the fallback, not the preference.
  decision.source = RecoverySource::kFetchRemote;
  return decision;
}

// ---------------------------------------------------------------------------
// IPv4 / CIDR
// ---------------------------------------------------------------------------

bool ParseIpv4(const std::string& text, uint32_t* out) {
  if (out == nullptr || text.empty() || text.size() > 15) {
    return false;
  }
  uint32_t address = 0;
  int octets = 0;
  size_t start = 0;
  while (start <= text.size()) {
    const size_t dot = text.find('.', start);
    const size_t end = dot == std::string::npos ? text.size() : dot;
    const std::string part = text.substr(start, end - start);
    // Explicit digit check rather than atoi: atoi("12abc") is 12, and a range that
    // parses loosely matches more addresses than the operator wrote.
    if (part.empty() || part.size() > 3) {
      return false;
    }
    for (const char c : part) {
      if (c < '0' || c > '9') {
        return false;
      }
    }
    // A leading zero makes the octet ambiguous (octal in some parsers), so it is
    // rejected rather than interpreted.
    if (part.size() > 1 && part[0] == '0') {
      return false;
    }
    const int value = std::atoi(part.c_str());
    if (value > 255) {
      return false;
    }
    address = (address << 8) | static_cast<uint32_t>(value);
    ++octets;
    if (dot == std::string::npos) {
      break;
    }
    start = dot + 1;
  }
  if (octets != 4) {
    return false;
  }
  *out = address;
  return true;
}

bool ParseIpv4Range(const std::string& text, Ipv4Range* out) {
  if (out == nullptr) {
    return false;
  }
  *out = Ipv4Range{};
  const size_t slash = text.find('/');
  if (slash == std::string::npos || slash == 0 || slash + 1 >= text.size()) {
    return false;
  }
  uint32_t address = 0;
  if (!ParseIpv4(text.substr(0, slash), &address)) {
    return false;
  }
  const std::string prefix_text = text.substr(slash + 1);
  if (prefix_text.empty() || prefix_text.size() > 2) {
    return false;
  }
  for (const char c : prefix_text) {
    if (c < '0' || c > '9') {
      return false;
    }
  }
  const int prefix = std::atoi(prefix_text.c_str());
  if (prefix < 0 || prefix > 32) {
    return false;
  }

  out->network = address;
  out->prefix_length = prefix;
  // /0 is legal in CIDR and means "everything". It is rejected here rather than
  // parsed, because a policy that pins 0.0.0.0/0 passes the DNS range check for
  // any answer at all and therefore checks nothing.
  if (prefix == 0) {
    return false;
  }
  out->mask = 0xFFFFFFFFu << (32 - prefix);
  out->network &= out->mask;  // normalise, so 140.82.112.5/20 == 140.82.112.0/20
  out->valid = true;
  return true;
}

bool Ipv4InRange(uint32_t address, const Ipv4Range& range) {
  if (!range.valid) {
    return false;
  }
  return (address & range.mask) == range.network;
}

std::string Ipv4ToString(uint32_t address) {
  char buffer[16];
  std::snprintf(buffer, sizeof(buffer), "%u.%u.%u.%u", (address >> 24) & 0xFF,
                (address >> 16) & 0xFF, (address >> 8) & 0xFF, address & 0xFF);
  return buffer;
}

}  // namespace xrom::recovery
