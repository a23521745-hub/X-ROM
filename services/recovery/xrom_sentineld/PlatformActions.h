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

#ifndef XROM_SENTINELD_PLATFORM_ACTIONS_H_
#define XROM_SENTINELD_PLATFORM_ACTIONS_H_

#include <cstdint>
#include <string>
#include <vector>

#include "BcbMessage.h"
#include "BootAttemptPolicy.h"
#include "VaultMetadata.h"

namespace xrom::sentinel {

// ---------------------------------------------------------------------------
// Everything in this daemon that touches the platform, in one place.
//
// WHY ONE FILE
// ------------
// The decisions live in common/recovery and common/ota and are pure functions of
// structs, which is what makes them testable. This file is the other half: it reads
// /misc through libbootloader_message, talks to netd over binder, opens a block
// device, and asks init to reboot. None of that can be unit tested, and none of it
// should contain a decision.
//
// Grouping it means the boundary is visible in one diff. A reviewer asking "what
// does this daemon actually touch on this device?" reads one file, and a future
// change that smuggles a policy decision into the platform layer has to do it here,
// where it is obvious.
// ---------------------------------------------------------------------------

// --- the BCB ---------------------------------------------------------------

// Reads and writes /misc through AOSP's libbootloader_message.
//
// WHY NOT A RAW BLOCK WRITE
// -------------------------
// Opening /dev/block/by-name/misc and writing 2048 bytes at offset 0 works, and it
// is wrong. The recovery field is a shared channel: uncrypt, RecoverySystem,
// update_engine and the A/B slot logic all queue commands in it, and a pending
// command from any of them is meaningful. A read-modify-write through the platform
// library is what preserves them; a raw write silently discards a queued wipe or an
// interrupted OTA, and the device then does the wrong thing at the next reboot with
// no record of what was lost. See correction #1 in docs/05.
//
// The merge itself is done by xrom::recovery::Render in the pure core, because
// libbootloader_message cannot be unit tested without a misc partition and the merge
// is exactly the part worth testing. This class is the thin layer that gets the
// bytes in and out.
class BcbWriter {
 public:
  explicit BcbWriter(const std::string& misc_device);

  // Reads the current BCB. Returns false with |error| set when /misc cannot be read.
  // A failed read is not treated as "misc is empty": rendering onto a blank struct
  // and writing it back would erase whatever was there.
  bool Read(::xrom::recovery::BootloaderMessage* out, std::string* error) const;

  // Renders |request| onto the current BCB and writes it back only if something
  // changed. Writing an unchanged BCB is not harmless: it costs a flash erase cycle
  // on a partition with a finite write budget, and on some controllers an
  // interrupted write to misc is not recoverable.
  //
  // |changed| reports whether a write actually happened, so that the caller can log
  // "armed recovery boot" and "recovery boot was already armed" as different events.
  bool Write(const ::xrom::recovery::BcbRequest& request, bool* changed, std::string* error) const;

  // Reads bootloader_control for the active slot, which is where the platform's own
  // boot-attempt counter lives.
  //
  // The CRC over bootloader_control is deliberately not verified here, and that is a
  // considered choice rather than an oversight: X-ROM never writes this structure, so
  // the value is advisory — it is read to decide whether to arm recovery, and a
  // corrupted counter degrades to available=false through the magic and version
  // checks plus a bound that is stronger than a range check: tries_remaining is a
  // 3-bit bitfield, so it cannot hold an implausible value in the first place.
  // Reimplementing the bootloader's CRC in a daemon that does not own the structure
  // would be more code trusting the same bytes, not less.
  //
  // The other slot's bootability is derived from this same structure rather than asked
  // of the boot control HAL, so that this path carries one binder dependency (netd)
  // instead of two and no vendor HAL at all. The derivation is conservative — see the
  // comment in the implementation — so it can cost an option and never invent one.
  bool ReadSlotSnapshot(::xrom::recovery::SlotSnapshot* out, std::string* error) const;

 private:
  std::string misc_device_;
};

// --- the network cut --------------------------------------------------------

// One attempted mechanism and what happened to it.
struct LayerResult {
  std::string name;
  bool attempted = false;
  bool succeeded = false;
  std::string detail;
};

// The outcome of trying every enabled layer.
struct NetworkCutResult {
  // True when at least one layer reported success. A cut that no layer confirms is
  // not a cut, and the quarantine step has to say so rather than proceed as though
  // the network were down.
  bool network_cut = false;

  // True when some enabled layer failed. Recorded separately from network_cut,
  // because "the netd chain failed but the property layer worked" is a degraded
  // success that an operator needs to see: it means one of the two mechanisms is
  // broken on this device and will still be broken during the next incident.
  bool degraded = false;

  std::vector<LayerResult> layers;

  std::string Describe() const;
};

// Decides the outcome from the layer results. Pure: it takes the results and returns
// the verdict, with no netd types and no binder, so the layering rule can be tested
// without a device.
//
// The rule is deliberately not "all layers must succeed". Layers are independent
// mechanisms, not steps in a sequence, and requiring all of them would mean a device
// with a broken netd cannot quarantine at all. But "at least one succeeded" has to
// come with the degradation flag, or a half-broken network cut reads in the log
// exactly like a complete one.
//
// An empty layer list is NOT a success. A configuration that disables every layer
// produces network_cut=false, because reporting a cut that nothing performed is
// precisely the silent failure this function exists to prevent.
NetworkCutResult EvaluateNetworkCut(std::vector<LayerResult> layers);

// Drops every network path.
//
// WHAT "KERNEL LEVEL" MEANS HERE
// ------------------------------
// The filtering happens in the kernel — netd programs nftables, which is a kernel
// subsystem. What is not true is that this is a kernel patch, and the difference
// matters for the threat model: the policy is set from userspace over binder, so a
// process that can reach netd with sufficient privilege can undo it. That is why the
// cut is one layer of the response and not the response: the BCB and the reboot do
// not depend on it, and the evidence is preserved before it happens. See correction
// #10 in docs/05.
//
// OPEN RISK, NOT A SOLVED PROBLEM
// -------------------------------
// X-ROM builds with CONFIG_BPF_SYSCALL off (device/x1/kernel/gki_xrom_pkvm.fragment).
// netd on Android 12+ uses eBPF for parts of its own operation and bpfloader is an
// early-init service, so whether netd functions normally on this kernel is NOT known
// and cannot be determined without a device. If it does not, the netd layer will fail
// on every boot and the property layer becomes the primary mechanism.
//
// This is why each layer reports independently instead of the first success ending
// the attempt: the log from a real device is what will answer the question, and a
// design that stops at the first success would never produce that evidence.
// tools/xrom_avf_verify.sh has a section that measures it; docs/05 records it as an
// open risk.
class NetworkQuarantine {
 public:
  NetworkQuarantine(bool use_netd_chain, bool use_interface_down, bool use_property,
                    int32_t netd_oem_chain);

  // Attempts every enabled layer and returns the combined result. Never throws and
  // never aborts: a quarantine that stops because netd did not answer leaves the
  // device both compromised and connected.
  NetworkCutResult Cut();

  // Reverses Cut(). Only ever called when a quarantine was cancelled by an
  // authenticated user inside the window, or when the arming step failed and the
  // device is staying up. Both are logged.
  NetworkCutResult Restore();

 private:
  LayerResult CutNetdChain();
  LayerResult CutInterfaces(bool down);
  LayerResult CutProperty();
  LayerResult RestoreNetdChain();
  LayerResult RestoreProperty();

  bool use_netd_chain_;
  bool use_interface_down_;
  bool use_property_;
  int32_t netd_oem_chain_;
};

// --- the vault --------------------------------------------------------------

// Reads the xrom_vault image partition and the record on xrom_vault_meta.
//
// TWO DEVICES, AND THE SPLIT IS THE POINT
// ---------------------------------------
// The vault image partition is read-only to this daemon and writable by exactly one
// domain, xrom_ota_installer. The record that describes it — state, digests, the
// sentinel's own boot-loop counter — lives on a separate 64 KiB partition that this
// daemon may write.
//
// They cannot share a device. The sentinel has to increment its counter, so it needs
// write somewhere on the vault; if the record sat at offset 0 of the image partition,
// granting that write would mean granting write to the image, because SELinux labels
// block devices and cannot distinguish one offset from another. The neverallow that
// makes "only the OTA installer can write the vault" true would then have to name the
// sentinel as an exception, and the property the requirement actually asks for would
// be gone. Sixty-four kilobytes of partition is cheaper than that.
//
// See correction #5 in docs/05.
class VaultPartition {
 public:
  VaultPartition(const std::string& image_device, const std::string& meta_device,
                 uint64_t record_offset);

  // Reads and validates the record. An absent device, a short read and an
  // unparseable record are all reported as "not usable" with a reason, and all three
  // mean the same thing to the decision engine: there is no fallback.
  bool ReadRecord(::xrom::recovery::VaultRecord* out, std::string* error) const;

  // Increments the sentinel's own boot-loop counter in the record. This is the one
  // write this class performs and it is the one field X-ROM owns; the platform's
  // tries_remaining is never written. See correction #4.
  bool RecordIntegrityFailure(std::string* error) const;

  // Resets the counter after a boot that passed the integrity comparison, so that
  // three failures spread over a year do not add up to a boot loop.
  bool ClearIntegrityFailures(std::string* error) const;

  // Computes the digest of the running slot and of the vault for the post-boot
  // comparison. At hashtree-root depth this reads the vbmeta the bootloader already
  // authenticated; at deep depth it hashes every byte of the partition.
  //
  // Returns false when the digest could not be produced, which the caller turns into
  // IntegrityVerdict::kInconclusive rather than kMismatch: "I could not check" has a
  // different remedy from "I checked and they differ".
  bool ComputeDigest(const std::string& device_path, bool deep, uint8_t (*out)[32],
                     std::string* error) const;

 private:
  bool WriteRecord(const ::xrom::recovery::VaultRecord& record, std::string* error) const;

  std::string image_device_;
  std::string meta_device_;
  uint64_t record_offset_;
};

// --- the reboot -------------------------------------------------------------

// Asks init to reboot through android.sys.powerctl, which is the supported path and
// the one that lets init stop services in order. Returns false when the property
// could not be set; note that a successful set does not return, because the device
// goes down.
bool RequestReboot(const std::string& target, std::string* error);

// Current battery percentage, 0..100, or false when it cannot be determined. A
// device that cannot report its battery is not assumed to be charged: the caller
// decides, and the shipped default is to refuse to reboot rather than to risk dying
// mid-reboot with an armed BCB.
bool ReadBatteryPercent(uint32_t* out);

}  // namespace xrom::sentinel

#endif  // XROM_SENTINELD_PLATFORM_ACTIONS_H_
