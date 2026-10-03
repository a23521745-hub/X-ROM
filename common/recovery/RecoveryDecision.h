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

#ifndef XROM_RECOVERY_RECOVERY_DECISION_H_
#define XROM_RECOVERY_RECOVERY_DECISION_H_

#include <cstdint>
#include <string>
#include <vector>

namespace xrom::recovery {

// ---------------------------------------------------------------------------
// The hybrid recovery decision engine: fetch the update from the network, or
// fall back to the xrom_vault partition.
//
// THE WHOLE POLICY IS "ONE DOUBT MEANS LOCAL"
// -------------------------------------------
// A remote fetch is a convenience. The vault copy is already on the device,
// already signed, already measured, and cannot be intercepted, redirected or
// served by an attacker. So the question is never "is the network probably fine?"
// but "is there any reason at all to prefer the thing that cannot be tampered
// with in transit?". The answer to that is asymmetric on purpose: a false
// negative costs a slower recovery from a partition that is on the device anyway,
// while a false positive installs an attacker's image.
//
// That asymmetry is why every signal below is TRI-STATE rather than boolean.
// "Not checked yet" must not be representable as "clean", or a stage that was
// skipped for any reason — a probe that timed out, a code path that forgot to
// fill a field, a default-initialised struct — would silently count as a pass.
// A default-constructed RecoverySignals is all-unknown and therefore decides
// kUseVault. That is the correct answer for a struct nobody filled in.
//
// WHY THE IP RANGE CHECK IS THE WEAKEST SIGNAL HERE
// -------------------------------------------------
// A pinned CIDR for an update host is close to worthless on its own and is kept
// only because it is cheap and because it occasionally catches the crudest
// redirect. DNS answers are trivially spoofable on an open network; a /20 owned
// by a large provider changes membership without notice; and an attacker who
// controls DNS can answer with any address inside the pinned range that they also
// control, or simply with a real one and let TLS do the work. The load-bearing
// check is the TLS public-key pin, and after that the Ed25519 signature on the
// manifest and the package. Treat the CIDR as a tiebreaker that can only ever
// push towards the vault, never as evidence of safety.
// ---------------------------------------------------------------------------

enum class Signal : int32_t {
  kUnknown = 0,   // not checked, or the check could not complete
  kClean = 1,     // checked and passed
  kSuspicious = 2  // checked and failed
};

const char* SignalName(Signal signal);

// What the recovery gate observed, stage by stage. Fields are filled in as the
// gate progresses; anything still kUnknown at decision time is treated as a
// failure to establish trust, not as a pass.
struct RecoverySignals {
  // --- stage 1: is there a network at all --------------------------------
  Signal wifi_available = Signal::kUnknown;

  // --- stage 2: is the network the one we think it is --------------------
  // The resolved address fell inside a pinned CIDR. Weak; see the header.
  Signal dns_answer_in_pinned_range = Signal::kUnknown;
  // The TLS certificate presented by the update host carried a public key whose
  // SHA-256 matches the pin compiled into the recovery image. This is the check
  // that actually decides anything at the transport layer.
  Signal tls_pin_matched = Signal::kUnknown;
  // The gateway's MAC equals one learned during a previously trusted setup and
  // stored encrypted in the vault. Catches an evil-twin AP on a known network.
  Signal gateway_mac_matches = Signal::kUnknown;
  // An HTTP redirect to a login page, or a TLS handshake that completed against
  // something that is not the update host. Both mean the network is not what it
  // claims to be, whatever the DNS answer said.
  Signal captive_portal_absent = Signal::kUnknown;

  // --- stage 3: is the manifest trustworthy ------------------------------
  Signal manifest_ed25519_valid = Signal::kUnknown;
  Signal manifest_rsa4096_valid = Signal::kUnknown;
  // The manifest's declared package size is inside the configured ceiling.
  // Checked BEFORE downloading: a hostile server can otherwise make recovery
  // fill the partition with a package it will reject anyway.
  Signal declared_size_within_limit = Signal::kUnknown;

  // --- stage 4: is the package trustworthy -------------------------------
  Signal package_ed25519_valid = Signal::kUnknown;
  Signal package_rsa4096_valid = Signal::kUnknown;
  // The bytes actually downloaded match the size and digest the manifest declared.
  Signal package_matches_manifest = Signal::kUnknown;
};

// Which source recovery should install from.
enum class RecoverySource : int32_t {
  // Install from the xrom_vault partition. The default, and the answer whenever
  // anything is unknown or suspicious.
  kUseVault = 0,
  // Fetch and install the remote OTA. Requires every signal to be kClean.
  kFetchRemote = 1,
};

const char* RecoverySourceName(RecoverySource source);

// Compiled-in policy. Every value here comes from the recovery image, never from
// anything fetched: a limit that a server could raise is not a limit.
struct RecoveryPolicy {
  // Pinned CIDRs for the update host. Empty means the DNS range check is
  // reported as kUnknown and therefore blocks the remote path — an operator who
  // wants to skip that check must say so explicitly below.
  std::vector<std::string> pinned_cidrs;

  // A server that declares an oversized package is either broken or hostile, and
  // in both cases the vault copy is the better answer.
  uint64_t max_package_bytes = 500ull * 1024 * 1024;

  // Require BOTH signatures on the manifest and on the package. This is an AND,
  // not an OR: the point is that a bug in one verification path, or the compromise
  // of one signing key, does not by itself produce an accepted image. It is not a
  // claim that RSA-4096 is a fallback for a broken Ed25519 — nobody breaks
  // Ed25519 by accident — and it does cost a second key ceremony.
  bool require_dual_signature = true;

  // Set only when the device has no usable vault copy, in which case there is no
  // fallback and the remote path is the only path. Even then every signal must be
  // clean; this flag relaxes nothing about the checks, it only permits the
  // decision to be kFetchRemote instead of refusing outright.
  bool vault_unavailable = false;

  // Set when the DNS range check should be skipped rather than blocking. Off by
  // default: forgetting to populate pinned_cidrs must fail towards the vault.
  bool skip_dns_range_check = false;
};

struct RecoveryDecision {
  RecoverySource source = RecoverySource::kUseVault;

  // Every signal that was not clean, with its name. Kept as a list rather than a
  // single reason so that an operator sees the whole picture at once: a recovery
  // that fell back for three reasons is a different incident from one that fell
  // back for one.
  std::vector<std::string> doubts;

  // Signals that were checked and passed. Recorded because "it used the vault"
  // with an empty list and "it used the vault" after eleven clean checks and one
  // doubt are different situations.
  std::vector<std::string> clean;

  bool IsRemote() const { return source == RecoverySource::kFetchRemote; }

  // One line for the recovery log.
  std::string Reason() const;
};

// The decision. Pure: no clock, no file I/O, no network, no globals. Every input
// is in |signals| and |policy|, so every branch is reachable from a test.
RecoveryDecision Decide(const RecoverySignals& signals, const RecoveryPolicy& policy);

// ---------------------------------------------------------------------------
// CIDR matching, kept here because the decision engine is its only consumer and
// because a hand-rolled parser is exactly the sort of thing that needs tests.
// IPv4 only: recovery's transport pins an IPv4 host, and adding a second address
// family doubles the parser without doubling the security.
// ---------------------------------------------------------------------------
struct Ipv4Range {
  uint32_t network = 0;  // host byte order
  uint32_t mask = 0;     // host byte order
  int prefix_length = 0;
  bool valid = false;
};

// Parses "a.b.c.d/n". Rejects octets over 255, a prefix over 32, a missing
// prefix, and anything with trailing junk — a range that parses loosely is a
// range that matches more than it should.
bool ParseIpv4Range(const std::string& text, Ipv4Range* out);
bool ParseIpv4(const std::string& text, uint32_t* out);
bool Ipv4InRange(uint32_t address, const Ipv4Range& range);
std::string Ipv4ToString(uint32_t address);

}  // namespace xrom::recovery

#endif  // XROM_RECOVERY_RECOVERY_DECISION_H_
