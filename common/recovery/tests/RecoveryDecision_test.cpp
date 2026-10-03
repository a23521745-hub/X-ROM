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

// Tests for common/recovery/RecoveryDecision.cpp.
//
// The property under test is fail-secure, and it is asserted the only way that
// means anything: by setting ONE signal to a non-clean value at a time, across
// every signal the engine reads, and requiring the decision to fall back to the
// vault each time. A decision tree with eleven inputs has eleven ways to be wrong,
// and a test that only checks the happy path and one obvious failure covers two of
// them.
//
// The second property is that "unknown" is not "clean". A check that never ran
// because the network went away halfway through, or because a library was missing,
// must count against the remote path. The tests assert this by starting from a
// default-constructed RecoverySignals — every field kUnknown — and requiring the
// vault.
//
// The CIDR tests use published values rather than ones chosen to pass. The range
// in the requirement, 140.82.112.0/20, is GitHub's; the boundary cases below are
// the first and last addresses of that block and the first address outside it.

#include "RecoveryDecision.h"

#include <string>
#include <utility>
#include <vector>

#include "gtest/gtest.h"

namespace {

using ::xrom::recovery::Decide;
using ::xrom::recovery::Ipv4InRange;
using ::xrom::recovery::Ipv4ToString;
using ::xrom::recovery::ParseIpv4;
using ::xrom::recovery::ParseIpv4Range;
using ::xrom::recovery::RecoveryPolicy;
using ::xrom::recovery::RecoverySignals;
using ::xrom::recovery::RecoverySource;
using ::xrom::recovery::Signal;

// Every signal clean, and a policy that actually pins something.
RecoverySignals AllClean() {
  RecoverySignals signals;
  signals.wifi_available = Signal::kClean;
  signals.dns_answer_in_pinned_range = Signal::kClean;
  signals.tls_pin_matched = Signal::kClean;
  signals.gateway_mac_matches = Signal::kClean;
  signals.captive_portal_absent = Signal::kClean;
  signals.manifest_ed25519_valid = Signal::kClean;
  signals.manifest_rsa4096_valid = Signal::kClean;
  signals.declared_size_within_limit = Signal::kClean;
  signals.package_ed25519_valid = Signal::kClean;
  signals.package_rsa4096_valid = Signal::kClean;
  signals.package_matches_manifest = Signal::kClean;
  return signals;
}

RecoveryPolicy PinnedPolicy() {
  RecoveryPolicy policy;
  policy.pinned_cidrs = {"140.82.112.0/20"};
  return policy;
}

bool UsesVault(const RecoverySignals& signals, const RecoveryPolicy& policy) {
  return Decide(signals, policy).source == RecoverySource::kUseVault;
}

}  // namespace

// ---------------------------------------------------------------------------
// The default state
// ---------------------------------------------------------------------------

TEST(RecoveryDecision, ADefaultConstructedSignalsStructDecidesVault) {
  // Nothing was checked, so nothing is trusted. This is the state a recovery gate
  // is in when it crashes halfway through its own probes, and it must not be the
  // state that permits a download.
  const auto decision = Decide(RecoverySignals{}, PinnedPolicy());
  EXPECT_FALSE(decision.IsRemote());
  EXPECT_FALSE(decision.doubts.empty());
}

TEST(RecoveryDecision, NoNetworkEndsTheQuestionWithOneDoubt) {
  // Reporting the ten signals that could not possibly have been checked would
  // bury the only fact that matters.
  RecoverySignals signals;
  signals.wifi_available = Signal::kSuspicious;
  const auto decision = Decide(signals, PinnedPolicy());
  EXPECT_FALSE(decision.IsRemote());
  EXPECT_EQ(decision.doubts.size(), 1u);
  EXPECT_TRUE(decision.doubts[0].find("no usable network") != std::string::npos);
  EXPECT_TRUE(decision.clean.empty());
}

TEST(RecoveryDecision, UnknownNetworkAvailabilityIsNotTreatedAsAvailable) {
  RecoverySignals signals = AllClean();
  signals.wifi_available = Signal::kUnknown;
  EXPECT_TRUE(UsesVault(signals, PinnedPolicy()));
}

// ---------------------------------------------------------------------------
// The happy path
// ---------------------------------------------------------------------------

TEST(RecoveryDecision, EverySignalCleanPermitsTheRemotePath) {
  const auto decision = Decide(AllClean(), PinnedPolicy());
  EXPECT_TRUE(decision.IsRemote());
  EXPECT_TRUE(decision.doubts.empty());
  // wifi_available is reported once, as the short-circuit check, and every other
  // signal is listed as clean rather than silently accepted.
  EXPECT_GE(decision.clean.size(), 11u);
}

TEST(RecoveryDecision, TheVaultIsTheFallbackNotThePreference) {
  // With every signal clean and a vault copy present, the remote fetch still wins:
  // it can deliver an image newer than the one baked into the device, which is the
  // entire point of a hybrid design. A decision engine that preferred the vault
  // whenever it existed would never update anything.
  const auto decision = Decide(AllClean(), PinnedPolicy());
  EXPECT_EQ(static_cast<int>(decision.source), static_cast<int>(RecoverySource::kFetchRemote));
}

// ---------------------------------------------------------------------------
// Fail-secure: one doubt at a time, across every signal
// ---------------------------------------------------------------------------

TEST(RecoveryDecision, AnySingleSuspiciousSignalFallsBackToTheVault) {
  const std::vector<std::pair<const char*, Signal RecoverySignals::*>> fields = {
      {"wifi_available", &RecoverySignals::wifi_available},
      {"dns_answer_in_pinned_range", &RecoverySignals::dns_answer_in_pinned_range},
      {"tls_pin_matched", &RecoverySignals::tls_pin_matched},
      {"gateway_mac_matches", &RecoverySignals::gateway_mac_matches},
      {"captive_portal_absent", &RecoverySignals::captive_portal_absent},
      {"manifest_ed25519_valid", &RecoverySignals::manifest_ed25519_valid},
      {"manifest_rsa4096_valid", &RecoverySignals::manifest_rsa4096_valid},
      {"declared_size_within_limit", &RecoverySignals::declared_size_within_limit},
      {"package_ed25519_valid", &RecoverySignals::package_ed25519_valid},
      {"package_rsa4096_valid", &RecoverySignals::package_rsa4096_valid},
      {"package_matches_manifest", &RecoverySignals::package_matches_manifest},
  };
  EXPECT_EQ(fields.size(), 11u);

  for (const auto& field : fields) {
    RecoverySignals signals = AllClean();
    signals.*(field.second) = Signal::kSuspicious;
    const auto decision = Decide(signals, PinnedPolicy());
    EXPECT_FALSE(decision.IsRemote());
    // wifi short-circuits and is reported by its own wording; everything else is
    // reported as name=value.
    if (std::string(field.first) != "wifi_available") {
      bool named = false;
      for (const std::string& doubt : decision.doubts) {
        if (doubt.find(std::string(field.first) + "=suspicious") != std::string::npos) {
          named = true;
        }
      }
      EXPECT_TRUE(named);
    }
  }
}

TEST(RecoveryDecision, AnySingleUnknownSignalFallsBackToTheVault) {
  // "The check did not run" is not "the check passed". This is the branch that a
  // missing library, a dead interface or a crash halfway through the probes would
  // hit, and it is the branch most likely to be wrong in an implementation that
  // only tested the happy path.
  const std::vector<Signal RecoverySignals::*> fields = {
      &RecoverySignals::dns_answer_in_pinned_range,
      &RecoverySignals::tls_pin_matched,
      &RecoverySignals::gateway_mac_matches,
      &RecoverySignals::captive_portal_absent,
      &RecoverySignals::manifest_ed25519_valid,
      &RecoverySignals::manifest_rsa4096_valid,
      &RecoverySignals::declared_size_within_limit,
      &RecoverySignals::package_ed25519_valid,
      &RecoverySignals::package_rsa4096_valid,
      &RecoverySignals::package_matches_manifest,
  };
  for (Signal RecoverySignals::*field : fields) {
    RecoverySignals signals = AllClean();
    signals.*field = Signal::kUnknown;
    EXPECT_TRUE(UsesVault(signals, PinnedPolicy()));
  }
}

TEST(RecoveryDecision, EveryDoubtIsReportedNotJustTheFirst) {
  // A recovery that fell back for three reasons is a different incident from one
  // that fell back for one, and an operator cannot tell them apart from a boolean.
  RecoverySignals signals = AllClean();
  signals.tls_pin_matched = Signal::kSuspicious;
  signals.gateway_mac_matches = Signal::kUnknown;
  signals.package_matches_manifest = Signal::kSuspicious;

  const auto decision = Decide(signals, PinnedPolicy());
  EXPECT_FALSE(decision.IsRemote());
  EXPECT_EQ(decision.doubts.size(), 3u);
}

TEST(RecoveryDecision, CleanSignalsAreRecordedAlongsideTheDoubts) {
  RecoverySignals signals = AllClean();
  signals.package_ed25519_valid = Signal::kSuspicious;
  const auto decision = Decide(signals, PinnedPolicy());
  // One doubt, and the rest of the work is still visible: the TLS pin matched,
  // which is the fact that makes "the package signature failed" an interesting
  // incident rather than a broken network.
  EXPECT_EQ(decision.doubts.size(), 1u);
  EXPECT_GE(decision.clean.size(), 9u);
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

TEST(RecoveryDecision, AnUnconfiguredCidrListIsADoubtNotAPass) {
  // A build that forgot to populate pinned_cidrs must fail towards the vault. If
  // an empty list meant "nothing to check", forgetting the pins would silently
  // disable the check.
  RecoveryPolicy policy;
  EXPECT_TRUE(policy.pinned_cidrs.empty());
  const auto decision = Decide(AllClean(), policy);
  EXPECT_FALSE(decision.IsRemote());
  EXPECT_EQ(decision.doubts.size(), 1u);
  EXPECT_TRUE(decision.doubts[0].find("pins no CIDR") != std::string::npos);
}

TEST(RecoveryDecision, SkippingTheDnsCheckIsExplicitAndLogged) {
  RecoveryPolicy policy;
  policy.skip_dns_range_check = true;
  RecoverySignals signals = AllClean();
  signals.dns_answer_in_pinned_range = Signal::kUnknown;  // never ran

  const auto decision = Decide(signals, policy);
  EXPECT_TRUE(decision.IsRemote());
  EXPECT_TRUE(decision.doubts.empty());
}

TEST(RecoveryDecision, SkippingTheDnsCheckDoesNotSkipATlsFailure) {
  // The CIDR check is the weak one. Turning it off must not turn off the check
  // that actually decides anything at the transport layer.
  RecoveryPolicy policy;
  policy.skip_dns_range_check = true;
  RecoverySignals signals = AllClean();
  signals.tls_pin_matched = Signal::kSuspicious;
  EXPECT_TRUE(UsesVault(signals, policy));
}

TEST(RecoveryDecision, VaultUnavailablePermitsADecisionButRelaxesNoCheck) {
  RecoveryPolicy policy = PinnedPolicy();
  policy.vault_unavailable = true;

  // With everything clean, there is no fallback to prefer, so the remote path is
  // taken — the flag permits a decision rather than changing one.
  EXPECT_TRUE(Decide(AllClean(), policy).IsRemote());

  // With one doubt, the answer is still the vault even though the vault is
  // unusable. There is no third option, and inventing one here would mean
  // installing an image that failed a check.
  RecoverySignals signals = AllClean();
  signals.manifest_ed25519_valid = Signal::kSuspicious;
  EXPECT_FALSE(Decide(signals, policy).IsRemote());
}

TEST(RecoveryDecision, TurningOffDualSignatureStopsConsultingTheRsaSignalsEntirely) {
  // Asserted rather than assumed, because the consequence is easy to miss: with
  // require_dual_signature off, an RSA signature that was checked and FAILED does
  // not produce a doubt, because the check is not in the table at all. Turning the
  // policy off is therefore a real weakening and has to be a deliberate, logged
  // one — not a knob somebody flips to make a build pass.
  RecoveryPolicy policy = PinnedPolicy();
  policy.require_dual_signature = false;

  RecoverySignals unknown_rsa = AllClean();
  unknown_rsa.manifest_rsa4096_valid = Signal::kUnknown;
  unknown_rsa.package_rsa4096_valid = Signal::kUnknown;
  EXPECT_TRUE(Decide(unknown_rsa, policy).IsRemote());

  RecoverySignals failed_rsa = AllClean();
  failed_rsa.manifest_rsa4096_valid = Signal::kSuspicious;
  failed_rsa.package_rsa4096_valid = Signal::kSuspicious;
  EXPECT_TRUE(Decide(failed_rsa, policy).IsRemote());

  // And with the policy on, the same signals are decisive.
  EXPECT_TRUE(UsesVault(unknown_rsa, PinnedPolicy()));
  EXPECT_TRUE(UsesVault(failed_rsa, PinnedPolicy()));
}

TEST(RecoveryDecision, ReasonNamesTheSourceAndTheDoubts) {
  RecoverySignals signals = AllClean();
  signals.gateway_mac_matches = Signal::kSuspicious;
  const std::string reason = Decide(signals, PinnedPolicy()).Reason();
  EXPECT_TRUE(reason.find("vault") != std::string::npos);
  EXPECT_TRUE(reason.find("gateway_mac_matches") != std::string::npos);

  const std::string remote_reason = Decide(AllClean(), PinnedPolicy()).Reason();
  EXPECT_TRUE(remote_reason.find("remote") != std::string::npos);
}

TEST(RecoveryDecision, EnumNamesAreDistinctAndNeverInvalid) {
  EXPECT_NE(std::string(xrom::recovery::SignalName(Signal::kClean)),
            std::string(xrom::recovery::SignalName(Signal::kSuspicious)));
  EXPECT_NE(std::string(xrom::recovery::SignalName(Signal::kUnknown)), "invalid");
  EXPECT_NE(std::string(xrom::recovery::RecoverySourceName(RecoverySource::kUseVault)),
            std::string(xrom::recovery::RecoverySourceName(RecoverySource::kFetchRemote)));
}

// ---------------------------------------------------------------------------
// CIDR parsing and matching
// ---------------------------------------------------------------------------

TEST(Ipv4Range, ParsesThePinnedGithubBlock) {
  xrom::recovery::Ipv4Range range;
  EXPECT_TRUE(ParseIpv4Range("140.82.112.0/20", &range));
  EXPECT_TRUE(range.valid);
  EXPECT_EQ(range.prefix_length, 20);
  EXPECT_EQ(Ipv4ToString(range.network), "140.82.112.0");
  EXPECT_EQ(range.mask, 0xFFFFF000u);
}

TEST(Ipv4Range, MatchesTheFirstAndLastAddressButNotTheNextOne) {
  xrom::recovery::Ipv4Range range;
  EXPECT_TRUE(ParseIpv4Range("140.82.112.0/20", &range));

  uint32_t address = 0;
  EXPECT_TRUE(ParseIpv4("140.82.112.0", &address));
  EXPECT_TRUE(Ipv4InRange(address, range));
  EXPECT_TRUE(ParseIpv4("140.82.127.255", &address));
  EXPECT_TRUE(Ipv4InRange(address, range));
  EXPECT_TRUE(ParseIpv4("140.82.118.42", &address));
  EXPECT_TRUE(Ipv4InRange(address, range));

  EXPECT_TRUE(ParseIpv4("140.82.128.0", &address));
  EXPECT_FALSE(Ipv4InRange(address, range));
  EXPECT_TRUE(ParseIpv4("140.82.111.255", &address));
  EXPECT_FALSE(Ipv4InRange(address, range));
  EXPECT_TRUE(ParseIpv4("8.8.8.8", &address));
  EXPECT_FALSE(Ipv4InRange(address, range));
}

TEST(Ipv4Range, NormalisesTheNetworkAddress) {
  // "140.82.113.5/20" names the same block as "140.82.112.0/20". Storing the
  // host bits would make two spellings of one pin compare unequal, and a pin
  // list that depends on exact spelling is a pin list that breaks on the first
  // edit.
  xrom::recovery::Ipv4Range range;
  EXPECT_TRUE(ParseIpv4Range("140.82.113.5/20", &range));
  EXPECT_EQ(Ipv4ToString(range.network), "140.82.112.0");
}

TEST(Ipv4Range, RejectsAPrefixThatWouldMatchEverything) {
  // /0 is not a pin, it is the absence of one. Accepting it would let a
  // configuration that looks pinned match any address on the internet.
  xrom::recovery::Ipv4Range range;
  EXPECT_FALSE(ParseIpv4Range("0.0.0.0/0", &range));
  EXPECT_FALSE(ParseIpv4Range("140.82.112.0/0", &range));
  EXPECT_FALSE(range.valid);
}

TEST(Ipv4Range, RejectsLooseSpellings) {
  const std::vector<std::string> bad = {
      "",
      "140.82.112.0",        // no prefix: a bare address is not a range
      "140.82.112.0/",       // empty prefix
      "140.82.112.0/20 ",    // trailing space
      " 140.82.112.0/20",    // leading space
      "140.82.112.0/33",     // prefix longer than the address
      "140.82.112.0/-1",     // negative prefix
      "140.82.112.256/20",   // octet over 255
      "140.82.112/20",       // too few octets
      "140.82.112.0.0/20",   // too many octets
      "140.82.0112.0/20",    // leading zero: octal to inet_aton, decimal to us
      "140.82.11a.0/20",     // non-digit
      "140.82.112.0/20/8",   // two prefixes
      "140.82.112.0/20junk", // trailing junk
      "::1/128",             // IPv6 is not supported here
      "github.com/20",       // a name is not an address
  };
  for (const std::string& text : bad) {
    xrom::recovery::Ipv4Range range;
    EXPECT_FALSE(ParseIpv4Range(text, &range));
  }
}

TEST(Ipv4Range, AcceptsThePrefixLengthsARealPinListUses) {
  const std::vector<std::string> good = {"10.0.0.0/8",    "172.16.0.0/12", "192.168.1.0/24",
                                         "140.82.112.0/20", "8.8.8.8/32",   "0.0.0.0/1"};
  for (const std::string& text : good) {
    xrom::recovery::Ipv4Range range;
    EXPECT_TRUE(ParseIpv4Range(text, &range));
    EXPECT_TRUE(range.valid);
  }
}

TEST(Ipv4Range, AHostPrefixMatchesExactlyOneAddress) {
  xrom::recovery::Ipv4Range range;
  EXPECT_TRUE(ParseIpv4Range("140.82.121.4/32", &range));
  uint32_t address = 0;
  EXPECT_TRUE(ParseIpv4("140.82.121.4", &address));
  EXPECT_TRUE(Ipv4InRange(address, range));
  EXPECT_TRUE(ParseIpv4("140.82.121.5", &address));
  EXPECT_FALSE(Ipv4InRange(address, range));
}

TEST(Ipv4Range, AnInvalidRangeMatchesNothing) {
  // The important half of the rejection: refusing to parse is not enough, because
  // a caller that ignores the return value would otherwise get a range object
  // whose mask happens to match something.
  xrom::recovery::Ipv4Range range;
  EXPECT_FALSE(ParseIpv4Range("140.82.112.0/0", &range));
  uint32_t address = 0;
  EXPECT_TRUE(ParseIpv4("140.82.112.1", &address));
  EXPECT_FALSE(Ipv4InRange(address, range));
}

TEST(Ipv4, RoundTripsThroughToString) {
  const std::vector<std::string> addresses = {"0.0.0.0",        "1.2.3.4", "140.82.112.0",
                                              "255.255.255.255", "10.0.0.1"};
  for (const std::string& text : addresses) {
    uint32_t address = 0;
    EXPECT_TRUE(ParseIpv4(text, &address));
    EXPECT_EQ(Ipv4ToString(address), text);
  }
}

TEST(Ipv4, RejectsTheSameLooseSpellingsTheRangeParserDoes) {
  const std::vector<std::string> bad = {"",       "1.2.3",      "1.2.3.4.5", "1.2.3.256",
                                        "01.2.3.4", "1.2.3.-4", "1.2.3.4 ", " 1.2.3.4",
                                        "1.2.3.4/24", "a.b.c.d"};
  for (const std::string& text : bad) {
    uint32_t address = 0;
    EXPECT_FALSE(ParseIpv4(text, &address));
  }
}
