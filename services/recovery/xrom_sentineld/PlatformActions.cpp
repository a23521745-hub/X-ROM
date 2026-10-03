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

#include "PlatformActions.h"

#include <dirent.h>
#include <fcntl.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

#include <android-base/file.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <bootloader_message/bootloader_message.h>
#include <binder/IServiceManager.h>
#include <binder/Status.h>

#include "NetdCompat.h"
#include "Sha256.h"

namespace xrom::sentinel {
namespace {

// tries_remaining is a 3-bit bitfield in slot_metadata, so it cannot exceed 7 by
// construction. That is the plausibility bound ReadSlotSnapshot relies on instead of
// verifying bootloader_control's CRC: X-ROM never writes the structure, and a
// corrupted counter is caught by the magic and version checks plus the fact that the
// field physically cannot hold an implausible value.
constexpr uint32_t kMaxTriesRemaining = 7;

std::vector<std::string> ListNetworkInterfaces() {
  std::vector<std::string> interfaces;
  ::android::base::unique_fd dir(::opendir("/sys/class/net"));
  if (dir.get() == nullptr) {
    return interfaces;
  }
  struct dirent* entry = nullptr;
  while ((entry = ::readdir(dir.get())) != nullptr) {
    const std::string name = entry->d_name;
    if (name == "." || name == "..") {
      continue;
    }
    // The loopback interface is left up. Bringing it down does nothing to egress and
    // breaks every local socket the daemon itself still needs — including the binder
    // connection it uses to report what it did.
    if (name == "lo") {
      continue;
    }
    interfaces.push_back(name);
  }
  return interfaces;
}

}  // namespace

// ---------------------------------------------------------------------------
// BcbWriter
// ---------------------------------------------------------------------------

BcbWriter::BcbWriter(const std::string& misc_device) : misc_device_(misc_device) {}

bool BcbWriter::Read(::xrom::recovery::BootloaderMessage* out, std::string* error) const {
  if (out == nullptr) {
    if (error != nullptr) *error = "null output";
    return false;
  }
  ::bootloader_message message{};
  static_assert(sizeof(::bootloader_message) == sizeof(*out),
                "the AOSP bootloader_message and X-ROM's mirror must be the same size; "
                "if this fails, AOSP changed the layout and every offset in "
                "common/recovery/BcbMessage.h has to be re-checked");
  if (!::read_bootloader_message(&message, error)) {
    return false;
  }
  std::memcpy(out, &message, sizeof(*out));
  return true;
}

bool BcbWriter::Write(const ::xrom::recovery::BcbRequest& request, bool* changed,
                      std::string* error) const {
  if (changed != nullptr) {
    *changed = false;
  }

  // Read first, always. Rendering onto a blank struct and writing it back would
  // erase whatever uncrypt, RecoverySystem or update_engine had queued, and the
  // device would do the wrong thing at the next reboot with no record of what was
  // lost. See correction #1 in docs/05.
  ::xrom::recovery::BootloaderMessage existing{};
  if (!Read(&existing, error)) {
    return false;
  }

  ::xrom::recovery::BcbImage image;
  std::vector<std::string> render_errors;
  if (!::xrom::recovery::Render(request, existing, &image, &render_errors)) {
    if (error != nullptr) {
      *error = ::android::base::Join(render_errors, "; ");
    }
    return false;
  }
  if (!image.changed) {
    // Nothing to write. Reported distinctly from a successful write, because "armed
    // the recovery boot" and "the recovery boot was already armed" are different
    // facts and an incident log that cannot tell them apart cannot say whether this
    // daemon did anything at all.
    return true;
  }

  ::bootloader_message message{};
  std::memcpy(&message, &image.message, sizeof(message));
  if (!::write_bootloader_message(message, error)) {
    return false;
  }
  if (changed != nullptr) {
    *changed = true;
  }
  return true;
}

bool BcbWriter::ReadSlotSnapshot(::xrom::recovery::SlotSnapshot* out, std::string* error) const {
  if (out == nullptr) {
    if (error != nullptr) *error = "null output";
    return false;
  }
  *out = ::xrom::recovery::SlotSnapshot{};  // available == false

  ::bootloader_message_ab ab{};
  if (!::read_bootloader_message_ab(&ab, error)) {
    return false;
  }

  ::bootloader_control control{};
  static_assert(sizeof(ab.slot_suffix) >= sizeof(::bootloader_control),
                "bootloader_control lives inside slot_suffix; if AOSP shrinks that "
                "field the reinterpret below reads past it");
  std::memcpy(&control, ab.slot_suffix, sizeof(control));

  // BOOT_CTRL_MAGIC is 0x42414342 and control.magic is a char[4], so the comparison
  // is against its little-endian byte spelling. Spelled out locally rather than
  // through the macro because the macro holds an integer and memcmp-ing an integer
  // against four chars is the kind of line that compiles and is wrong.
  static constexpr char kBootCtrlMagic[4] = {'B', 'C', 'A', 'B'};
  static constexpr uint8_t kBootCtrlVersion = 1;
  if (std::memcmp(control.magic, kBootCtrlMagic, sizeof(kBootCtrlMagic)) != 0) {
    if (error != nullptr) *error = "bootloader_control magic does not match";
    return false;
  }
  if (control.version != kBootCtrlVersion) {
    if (error != nullptr) {
      *error = "bootloader_control version " + std::to_string(control.version) + " is not " +
               std::to_string(kBootCtrlVersion);
    }
    return false;
  }

  // The active slot comes from the bootloader, not from this structure. Reading it
  // back out of bootloader_control would be circular: the whole question is what the
  // bootloader thinks about the slot it just tried.
  const std::string slot_suffix = ::android::base::GetProperty("ro.boot.slot_suffix", "");
  if (slot_suffix.size() != 2 || slot_suffix[0] != '_') {
    if (error != nullptr) {
      *error = "ro.boot.slot_suffix is not set to _a or _b, so the active slot cannot "
               "be identified (this is normal on a non-A/B device, where the "
               "platform boot counter does not apply)";
    }
    return false;
  }
  const uint32_t slot_index = static_cast<uint32_t>(slot_suffix[1] - 'a');
  if (slot_index >= control.nb_slot || slot_index >= 4) {
    if (error != nullptr) {
      *error = "slot index " + std::to_string(slot_index) + " is outside the " +
               std::to_string(control.nb_slot) + " slots bootloader_control describes";
    }
    return false;
  }

  const ::slot_metadata& slot = control.slot_info[slot_index];
  out->available = true;
  out->slot_index = slot_index;
  out->tries_remaining = slot.tries_remaining;
  out->successful_boot = slot.successful_boot != 0;
  out->verity_corrupted = slot.verity_corrupted != 0;
  out->priority = slot.priority;
  out->recovery_tries_remaining = control.recovery_tries_remaining;

  // 3-bit field, so it cannot exceed 7. A value above the maximum the bootloader
  // ever writes means the bytes are not what they claim to be, and the honest
  // response is to report the counter as unavailable rather than to act on it.
  if (out->tries_remaining > kMaxTriesRemaining) {
    out->available = false;
    if (error != nullptr) {
      *error = "tries_remaining is " + std::to_string(out->tries_remaining) +
               ", which a 3-bit field cannot hold";
    }
    return false;
  }

  // The other slot's bootability is DERIVED from the same structure rather than asked
  // of the boot control HAL, and that is a deliberate trade-off worth recording.
  //
  // The HAL is the supported accessor, but reaching it means a second binder
  // dependency — in this case a vendor HAL, so a second binder flavour as well — on a
  // code path whose entire purpose is to work while the system is degraded. A
  // quarantine that cannot decide anything because a vendor service is not up has
  // failed at exactly the moment it exists for.
  //
  // The derivation is conservative: a slot counts as bootable only if the bootloader
  // has recorded a successful boot on it or still has tries left. A slot with neither
  // is treated as unbootable, which makes EvaluateBootLoop refuse to arm a switch,
  // which is the fail-secure reading of "I am not sure". The HAL could answer
  // differently only in the direction of "bootable", so the error here costs an
  // option and never invents one.
  out->other_slot_bootable = false;
  const uint32_t other = slot_index == 0 ? 1 : 0;
  if (other < control.nb_slot && other < 4) {
    const ::slot_metadata& other_slot = control.slot_info[other];
    out->other_slot_bootable =
        other_slot.successful_boot != 0 || other_slot.tries_remaining > 0;
  }
  return true;
}

// ---------------------------------------------------------------------------
// NetworkQuarantine
// ---------------------------------------------------------------------------

std::string NetworkCutResult::Describe() const {
  std::string out = network_cut ? "network cut" : "NETWORK NOT CUT";
  if (degraded) {
    out += " (degraded)";
  }
  out += " [";
  for (size_t i = 0; i < layers.size(); ++i) {
    if (i != 0) {
      out += ", ";
    }
    out += layers[i].name;
    out += layers[i].attempted ? (layers[i].succeeded ? "=ok" : "=FAILED") : "=skipped";
    if (!layers[i].detail.empty()) {
      out += "(" + layers[i].detail + ")";
    }
  }
  out += "]";
  return out;
}

NetworkCutResult EvaluateNetworkCut(std::vector<LayerResult> layers) {
  NetworkCutResult result;
  result.layers = std::move(layers);
  for (const LayerResult& layer : result.layers) {
    if (layer.attempted && layer.succeeded) {
      result.network_cut = true;
    }
    if (layer.attempted && !layer.succeeded) {
      result.degraded = true;
    }
  }
  // An empty list is not a success. A configuration that disables every layer must
  // report "the network was not cut", because reporting a cut that nothing performed
  // is exactly the silent failure this evaluation exists to prevent.
  return result;
}

NetworkQuarantine::NetworkQuarantine(bool use_netd_chain, bool use_interface_down, bool use_property,
                                     int32_t netd_oem_chain)
    : use_netd_chain_(use_netd_chain),
      use_interface_down_(use_interface_down),
      use_property_(use_property),
      netd_oem_chain_(netd_oem_chain) {}

LayerResult NetworkQuarantine::CutNetdChain() {
  LayerResult layer;
  layer.name = "netd-firewall-chain";
  if (!use_netd_chain_) {
    layer.detail = "disabled by configuration";
    return layer;
  }
  layer.attempted = true;

  const int32_t chain = netd_compat::OemChainId(netd_oem_chain_);
  auto netd = ::android::interface_cast<netd_compat::INetd>(
      ::android::defaultServiceManager()->checkService(netd_compat::kNetdServiceName));
  if (netd == nullptr) {
    layer.succeeded = false;
    layer.detail = "netd is not registered; on a kernel with CONFIG_BPF_SYSCALL off "
                   "this is the expected symptom and is why the interface-down layer "
                   "exists";
    return layer;
  }

  const ::android::binder::Status status = netd->firewallEnableChain(chain);
  layer.succeeded = status.isOk();
  if (!layer.succeeded) {
    layer.detail = "firewallEnableChain(" + std::to_string(chain) + ") failed with "
                   "binder exception code " + std::to_string(status.exceptionCode());
    return layer;
  }
  // Reported honestly: a successful binder call means netd accepted the request. It
  // does not prove that traffic stopped, because that also depends on the chain
  // having been provisioned as default-deny. tools/xrom_avf_verify.sh measures the
  // actual egress on a device rather than trusting this return value.
  layer.detail = "chain " + std::to_string(chain) + " enabled";
  return layer;
}

LayerResult NetworkQuarantine::CutInterfaces(bool down) {
  LayerResult layer;
  layer.name = down ? "interface-down" : "interface-up";
  if (!use_interface_down_) {
    layer.detail = "disabled by configuration";
    return layer;
  }
  layer.attempted = true;

  // This is the layer that works without netd: a direct SIOCSIFFLAGS ioctl on an
  // AF_INET socket, requiring CAP_NET_ADMIN and nothing else. It is also the layer
  // whose effect is observable without a packet capture — the interface is
  // administratively down, and `ip link` says so.
  ::android::base::unique_fd sock(::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0));
  if (sock.get() < 0) {
    layer.succeeded = false;
    layer.detail = std::string("cannot open an AF_INET socket: ") + std::strerror(errno);
    return layer;
  }

  const std::vector<std::string> interfaces = ListNetworkInterfaces();
  if (interfaces.empty()) {
    // No interfaces other than loopback. Nothing to bring down, and reporting
    // failure here would make a device with no network hardware look like a device
    // whose quarantine broke.
    layer.succeeded = true;
    layer.detail = "no non-loopback interfaces present";
    return layer;
  }

  size_t succeeded = 0;
  std::vector<std::string> failures;
  for (const std::string& name : interfaces) {
    struct ifreq request {};
    std::strncpy(request.ifr_name, name.c_str(), IFNAMSIZ - 1);
    if (::ioctl(sock.get(), SIOCGIFFLAGS, &request) != 0) {
      failures.push_back(name + ": " + std::strerror(errno));
      continue;
    }
    const short original = request.ifr_flags;
    const short wanted = down ? static_cast<short>(original & ~IFF_UP)
                              : static_cast<short>(original | IFF_UP);
    if (wanted == original) {
      ++succeeded;  // already in the desired state
      continue;
    }
    request.ifr_flags = wanted;
    if (::ioctl(sock.get(), SIOCSIFFLAGS, &request) != 0) {
      failures.push_back(name + ": " + std::strerror(errno));
      continue;
    }
    ++succeeded;
  }

  layer.succeeded = failures.empty();
  layer.detail = std::to_string(succeeded) + "/" + std::to_string(interfaces.size()) +
                 " interfaces";
  if (!failures.empty()) {
    layer.detail += ", failed: " + ::android::base::Join(failures, ", ");
  }
  return layer;
}

LayerResult NetworkQuarantine::CutProperty() {
  LayerResult layer;
  layer.name = "quarantine-property";
  if (!use_property_) {
    layer.detail = "disabled by configuration";
    return layer;
  }
  layer.attempted = true;

  // Stated plainly: setting a property is not itself a network cut. It does two
  // things that matter — it records the quarantine durably enough for the recovery
  // image and the next boot to see that it happened, and it is the signal the device
  // tree's init trigger acts on. If that trigger is not provisioned, this layer is
  // decorative, which is why it is one of three and never the only one.
  const bool ok = ::android::base::SetProperty("sys.xrom.network.quarantined", "1");
  layer.succeeded = ok;
  layer.detail = ok ? "sys.xrom.network.quarantined=1"
                    : "SetProperty failed; the property may not be writable by this domain";
  return layer;
}

LayerResult NetworkQuarantine::RestoreNetdChain() {
  LayerResult layer;
  layer.name = "netd-firewall-chain-restore";
  if (!use_netd_chain_) {
    layer.detail = "disabled by configuration";
    return layer;
  }
  layer.attempted = true;
  auto netd = ::android::interface_cast<netd_compat::INetd>(
      ::android::defaultServiceManager()->checkService(netd_compat::kNetdServiceName));
  if (netd == nullptr) {
    layer.succeeded = false;
    layer.detail = "netd is not registered";
    return layer;
  }
  const ::android::binder::Status status =
      netd->firewallDisableChain(netd_compat::OemChainId(netd_oem_chain_));
  layer.succeeded = status.isOk();
  if (!layer.succeeded) {
    layer.detail = "binder exception code " + std::to_string(status.exceptionCode());
  }
  return layer;
}

LayerResult NetworkQuarantine::RestoreProperty() {
  LayerResult layer;
  layer.name = "quarantine-property-restore";
  if (!use_property_) {
    layer.detail = "disabled by configuration";
    return layer;
  }
  layer.attempted = true;
  layer.succeeded = ::android::base::SetProperty("sys.xrom.network.quarantined", "0");
  if (!layer.succeeded) {
    layer.detail = "SetProperty failed";
  }
  return layer;
}

NetworkCutResult NetworkQuarantine::Cut() {
  // Every enabled layer is attempted, in order, and no early exit on success. Two
  // reasons, and the second is the one that matters for this project:
  //
  //   * layers are independent mechanisms, not steps in a sequence, so a failure in
  //     one does not invalidate another;
  //   * whether netd functions at all on a kernel with CONFIG_BPF_SYSCALL off is an
  //     open question (see NetdCompat.h). Stopping at the first success would mean a
  //     device where netd is broken and the ioctl layer works produces a log that
  //     looks identical to a healthy one, and the question would never get answered.
  std::vector<LayerResult> layers;
  layers.push_back(CutNetdChain());
  layers.push_back(CutInterfaces(/*down=*/true));
  layers.push_back(CutProperty());
  return EvaluateNetworkCut(std::move(layers));
}

NetworkCutResult NetworkQuarantine::Restore() {
  std::vector<LayerResult> layers;
  layers.push_back(RestoreNetdChain());
  layers.push_back(CutInterfaces(/*down=*/false));
  layers.push_back(RestoreProperty());
  // Restore uses the same evaluation, so a device that came back up with an
  // interface still down reports it instead of looking restored.
  return EvaluateNetworkCut(std::move(layers));
}

// ---------------------------------------------------------------------------
// VaultPartition
// ---------------------------------------------------------------------------

VaultPartition::VaultPartition(const std::string& image_device, const std::string& meta_device,
                               uint64_t record_offset)
    : image_device_(image_device), meta_device_(meta_device), record_offset_(record_offset) {}

bool VaultPartition::ReadRecord(::xrom::recovery::VaultRecord* out, std::string* error) const {
  if (out == nullptr) {
    if (error != nullptr) *error = "null output";
    return false;
  }
  ::xrom::recovery::MakeEmptyRecord(out);

  // O_RDONLY and no O_CREAT: this daemon never creates the vault device, and opening
  // a block device that does not exist must fail rather than appear to succeed on a
  // zero-length regular file.
  ::android::base::unique_fd fd(
      ::open(meta_device_.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
  if (fd.get() < 0) {
    if (error != nullptr) {
      *error = "cannot open " + meta_device_ + ": " + std::strerror(errno) +
               "; the vault metadata is absent or this domain lacks read access, and "
               "either way there is no fallback";
    }
    return false;
  }
  if (::lseek64(fd.get(), static_cast<off64_t>(record_offset_), SEEK_SET) < 0) {
    if (error != nullptr) {
      *error = "cannot seek to the vault record: " + std::strerror(errno);
    }
    return false;
  }

  std::string bytes(::xrom::recovery::kVaultRecordBytes, '\0');
  if (!::android::base::ReadFully(fd.get(), bytes.data(), bytes.size())) {
    if (error != nullptr) {
      *error = "short read of the vault record: " + std::strerror(errno);
    }
    return false;
  }
  if (!::xrom::recovery::FromBytes(bytes, out)) {
    if (error != nullptr) *error = "the vault record is not the expected length";
    return false;
  }
  const auto validation = ::xrom::recovery::Validate(*out);
  if (!validation.ok) {
    // An erased or never-written vault is not an error condition on a fresh device;
    // it means there is no fallback. The caller turns both into
    // IntegrityVerdict::kInconclusive, never into kMismatch.
    if (error != nullptr) *error = "the vault record is not usable: " + validation.reason;
    return false;
  }
  return true;
}

bool VaultPartition::WriteRecord(const ::xrom::recovery::VaultRecord& record,
                                 std::string* error) const {
  const auto validation = ::xrom::recovery::Validate(record);
  if (!validation.ok) {
    if (error != nullptr) {
      *error = "refusing to write an invalid vault record: " + validation.reason;
    }
    return false;
  }
  ::android::base::unique_fd fd(
      ::open(meta_device_.c_str(), O_WRONLY | O_CLOEXEC | O_NOFOLLOW));
  if (fd.get() < 0) {
    if (error != nullptr) {
      *error = "cannot open " + meta_device_ + " for writing: " + std::strerror(errno) +
               "; this is the metadata partition, which xrom_sentineld does own. "
               "Write access to the vault IMAGE is held by xrom_ota_installer alone "
               "and that is enforced by a neverallow, not by this class";
    }
    return false;
  }
  if (::lseek64(fd.get(), static_cast<off64_t>(record_offset_), SEEK_SET) < 0) {
    if (error != nullptr) *error = "cannot seek to the vault record: " + std::strerror(errno);
    return false;
  }
  const std::string bytes = ::xrom::recovery::ToBytes(record);
  if (!::android::base::WriteFully(fd.get(), bytes.data(), bytes.size())) {
    if (error != nullptr) *error = "short write of the vault record: " + std::strerror(errno);
    return false;
  }
  // A record that is in the page cache but not on the media is a record that does not
  // survive the reboot this daemon is about to trigger.
  if (::fsync(fd.get()) != 0) {
    if (error != nullptr) *error = "cannot flush the vault record: " + std::strerror(errno);
    return false;
  }
  return true;
}

bool VaultPartition::RecordIntegrityFailure(std::string* error) const {
  ::xrom::recovery::VaultRecord record;
  if (!ReadRecord(&record, error)) {
    // Cannot increment a counter in a record that cannot be read. The caller still
    // arms recovery on the strength of the failure it just observed; what it cannot
    // do is remember it for the next boot, and that has to be in the log.
    return false;
  }
  // Saturating rather than wrapping: a counter that overflows to zero would let a
  // device loop forever by being unlucky about the number of failures.
  if (record.integrity_failures < UINT32_MAX) {
    ++record.integrity_failures;
  }
  return WriteRecord(record, error);
}

bool VaultPartition::ClearIntegrityFailures(std::string* error) const {
  ::xrom::recovery::VaultRecord record;
  if (!ReadRecord(&record, error)) {
    return false;
  }
  if (record.integrity_failures == 0) {
    return true;  // nothing to do, and not worth a write to the flash
  }
  record.integrity_failures = 0;
  return WriteRecord(record, error);
}

bool VaultPartition::ComputeDigest(const std::string& device_path, bool deep, uint8_t (*out)[32],
                                   std::string* error) const {
  if (out == nullptr) {
    if (error != nullptr) *error = "null digest output";
    return false;
  }
  std::memset(out, 0, sizeof(*out));

  if (!deep) {
    // THE ASYMMETRY HERE IS REAL AND IS THE POINT OF CORRECTIONS #5 AND #9.
    //
    // For the running slot there is a cheap authenticated digest: the bootloader
    // verified the AVB vbmeta chain before the kernel started and passed its digest
    // up, so ro.boot.vbmeta.digest is a value that was already paid for and already
    // authenticated. Reading it costs one property lookup.
    //
    // For the vault there is no such value UNLESS the vault has its own AVB hashtree
    // descriptor in the vbmeta chain. An unmounted partition that is not covered by
    // AVB has no cheap digest at all: hashing it is the expensive path, and trusting
    // the digest stored in its own record proves nothing about its current content,
    // because whoever changed the content could change the record too.
    //
    // So this returns false for the vault on a build that has not chained it, and the
    // caller turns that into kInconclusive with a reason that says what to do about
    // it. Reporting a number that means nothing would be worse than reporting
    // nothing.
    const bool is_vault = device_path == image_device_;
    if (is_vault) {
      if (error != nullptr) {
        *error = "the vault is not covered by AVB on this build, so no cheap "
                 "authenticated digest exists for it; either add an xrom_vault "
                 "hashtree descriptor to the vbmeta chain or request the deep "
                 "comparison, which hashes the partition in full";
      }
      return false;
    }
    const std::string hex = ::android::base::GetProperty("ro.boot.vbmeta.digest", "");
    if (hex.empty()) {
      if (error != nullptr) {
        *error = "ro.boot.vbmeta.digest is not set, so the running slot has no cheap "
                 "authenticated digest either; this device may not be AVB-enabled";
      }
      return false;
    }
    ::xrom::crypto::Sha256Digest digest{};
    if (!::xrom::crypto::Sha256::FromHex(hex, &digest)) {
      if (error != nullptr) {
        *error = "ro.boot.vbmeta.digest is not 64 hex characters: " + hex;
      }
      return false;
    }
    std::memcpy(out, digest.data(), digest.size());
    return true;
  }

  // Deep: SHA-256 over every byte of the partition. Delegated to Sha256::HashFile
  // rather than open-coded here, so the streaming loop is the one that is already
  // covered by the published test vectors in common/tests/Sha256_test.cpp. This is
  // gigabytes of flash I/O and duplicates work dm-verity already does on every read
  // of the running slot; it is opt-in and is for explaining a mismatch the cheap
  // comparison already found. See correction #9.
  ::xrom::crypto::Sha256Digest digest{};
  if (!::xrom::crypto::Sha256::HashFile(device_path, &digest, error)) {
    return false;
  }
  std::memcpy(out, digest.data(), digest.size());
  return true;
}

// ---------------------------------------------------------------------------
// Reboot and battery
// ---------------------------------------------------------------------------

bool RequestReboot(const std::string& target, std::string* error) {
  // android.sys.powerctl is the supported path: init sees it, stops services in
  // order, syncs, and hands the device to the bootloader. Rebooting any other way —
  // a direct syscall, killing init — skips the orderly shutdown, and skipping it on a
  // device that has just written to /misc is how a partially committed BCB happens.
  const std::string value = target.empty() ? "reboot" : ("reboot," + target);
  const bool ok = ::android::base::SetProperty("android.sys.powerctl", value);
  if (!ok && error != nullptr) {
    *error = "could not set android.sys.powerctl to " + value +
             "; the device will not reboot and the armed BCB will take effect at "
             "whatever the next reboot happens to be";
  }
  return ok;
}

bool ReadBatteryPercent(uint32_t* out) {
  if (out == nullptr) {
    return false;
  }
  // The health service publishes capacity as a percentage. When it is absent the
  // caller must not assume the device is charged: dying mid-reboot with an armed BCB
  // leaves the next boot's behaviour unpredictable, and waiting for a charger is the
  // safer state.
  const int32_t capacity = ::android::base::GetIntProperty("sys.battery.capacity", -1);
  if (capacity < 0 || capacity > 100) {
    return false;
  }
  *out = static_cast<uint32_t>(capacity);
  return true;
}

}  // namespace xrom::sentinel
