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

#ifndef XROM_SENTINELD_NETD_COMPAT_H_
#define XROM_SENTINELD_NETD_COMPAT_H_

// ---------------------------------------------------------------------------
// Every netd AIDL type and constant this daemon uses, named in one file.
//
// This follows the AvfCompat.h pattern already in the tree, for the same reason:
// netd's interface is not a frozen vendor contract, its chain numbering is an
// internal detail, and when it moves one file should move rather than a search
// across the daemon.
//
// ⚠️ MUST BE CONFIRMED ON A REAL DEVICE
// -------------------------------------
// Two things here cannot be verified in a source tree and are NOT assumptions this
// project is entitled to make silently:
//
//   1. THE OEM CHAIN IDS. netd exposes a small number of OEM firewall chains for
//      exactly this use, but the numeric ids are not part of a frozen public
//      contract and differ between netd versions. kFirewallChainOemBase below is a
//      starting point that has to be checked against the target's
//      system/netd/aidl/android/net/INetd.aidl before the network layer is trusted.
//      tools/xrom_avf_verify.sh section 13 prints what the device actually accepts.
//
//   2. WHETHER NETD WORKS AT ALL ON THIS KERNEL. X-ROM builds with
//      CONFIG_BPF_SYSCALL off, and netd on Android 12+ uses eBPF for parts of its
//      own operation while bpfloader is an early-init service. If netd is not
//      functional, this layer fails on every boot and the property layer becomes the
//      primary mechanism. That is an open risk recorded in docs/05, not a solved
//      problem, and it is the reason NetworkQuarantine attempts every enabled layer
//      instead of stopping at the first success: the log from a real device is what
//      answers the question.
//
// Neither uncertainty is allowed to become a silent failure. Every attempt returns a
// LayerResult with its own detail string, so a broken netd shows up in the incident
// log as a named degradation rather than as a quarantine that quietly did less than
// it claimed.
// ---------------------------------------------------------------------------

#include <android/net/INetd.h>

namespace xrom::sentinel::netd_compat {

using INetd = ::android::net::INetd;

// netd's own chains: DOZABLE = 1, STANDBY = 2, POWERSAVE = 3. X-ROM does not reuse
// them. Each has semantics and an owner of its own — DOZABLE in particular is driven
// by device idle, and a chain that something else enables and disables is not a
// chain a quarantine can rely on still being enabled five seconds later.
constexpr int32_t kFirewallChainDozable = 1;
constexpr int32_t kFirewallChainStandby = 2;
constexpr int32_t kFirewallChainPowersave = 3;

// Base id for the OEM chains, which netd reserves for vendor-defined policy.
// netd_oem_chain in the configuration is 1..3 and maps to base + (n - 1).
// ⚠️ See the warning above: confirm against the target's INetd.aidl.
constexpr int32_t kFirewallChainOemBase = 100;

inline int32_t OemChainId(int32_t oem_chain_number) {
  return kFirewallChainOemBase + (oem_chain_number - 1);
}

// The service name netd registers under.
constexpr char kNetdServiceName[] = "netd";

}  // namespace xrom::sentinel::netd_compat

#endif  // XROM_SENTINELD_NETD_COMPAT_H_
