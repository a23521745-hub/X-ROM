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

#include "SentinelConfig.h"

#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

#include <android-base/file.h>
#include <json/json.h>

namespace xrom::sentinel {
namespace {

enum class FileStatus {
  kRead,
  kMissing,
  kTooLarge,
  kError,
};

// Reads a whole file with a ceiling. A configuration file is kilobytes; refusing to
// read megabytes is not a performance concern but a statement that this input is
// bounded, so a file that is not the configuration cannot be used to exhaust the
// daemon before it has decided anything.
//
// The three failure modes are distinguished by an enum rather than by errno. Reading
// errno after a helper that may have made several syscalls is how "the file is too
// large" turns into "the file is absent", and the two have opposite meanings here:
// absent means run the shipped defaults, too large means refuse to start.
FileStatus ReadFileCapped(const std::string& path, size_t max_bytes, std::string* out,
                          std::string* error) {
  struct stat info {};
  if (::stat(path.c_str(), &info) != 0) {
    if (errno == ENOENT) {
      return FileStatus::kMissing;
    }
    *error = std::string("cannot stat ") + path + ": " + std::strerror(errno);
    return FileStatus::kError;
  }
  if (!S_ISREG(info.st_mode)) {
    *error = path + " is not a regular file";
    return FileStatus::kError;
  }
  if (static_cast<size_t>(info.st_size) > max_bytes) {
    *error = path + " is " + std::to_string(info.st_size) + " bytes, above the " +
             std::to_string(max_bytes) + " byte ceiling for a configuration file";
    return FileStatus::kTooLarge;
  }
  std::string content;
  if (!android::base::ReadFileToString(path, &content, static_cast<unsigned>(max_bytes))) {
    *error = "cannot read " + path + ": " + std::strerror(errno);
    return FileStatus::kError;
  }
  *out = std::move(content);
  return FileStatus::kRead;
}

// The small typed accessors below exist so that a wrong-typed or out-of-range value
// produces a named error instead of a silent default. Reading JSON by hand at every
// call site is how a policy file ends up meaning something other than what it says.
template <typename T>
bool GetNumber(const Json::Value& node, const char* key, T* out, std::vector<std::string>* errors,
               T minimum, T maximum) {
  if (!node.isMember(key)) {
    return true;  // absent means "keep the default", which is not an error
  }
  const Json::Value& value = node[key];
  if (!value.isNumeric()) {
    errors->push_back(std::string(key) + " must be a number");
    return false;
  }
  const auto as_double = value.asDouble();
  const auto as_int = static_cast<T>(as_double);
  if (static_cast<double>(as_int) != as_double) {
    errors->push_back(std::string(key) + " must be an integer");
    return false;
  }
  if (as_int < minimum || as_int > maximum) {
    errors->push_back(std::string(key) + " must be within " + std::to_string(minimum) + ".." +
                      std::to_string(maximum) + ", got " + std::to_string(as_int));
    return false;
  }
  *out = as_int;
  return true;
}

bool GetBool(const Json::Value& node, const char* key, bool* out,
             std::vector<std::string>* errors) {
  if (!node.isMember(key)) {
    return true;
  }
  if (!node[key].isBool()) {
    errors->push_back(std::string(key) + " must be a boolean");
    return false;
  }
  *out = node[key].asBool();
  return true;
}

bool GetString(const Json::Value& node, const char* key, std::string* out,
               std::vector<std::string>* errors, bool must_be_absolute_path) {
  if (!node.isMember(key)) {
    return true;
  }
  if (!node[key].isString()) {
    errors->push_back(std::string(key) + " must be a string");
    return false;
  }
  const std::string value = node[key].asString();
  if (value.empty()) {
    errors->push_back(std::string(key) + " must not be empty");
    return false;
  }
  if (must_be_absolute_path) {
    // An absolute path with no traversal. These paths are opened by a daemon that
    // holds block-device and reboot authority, so a relative path resolved against
    // an attacker-influenced cwd is not a hypothetical.
    if (value[0] != '/' || value.find("..") != std::string::npos) {
      errors->push_back(std::string(key) + " must be an absolute path with no '..': " + value);
      return false;
    }
  }
  *out = value;
  return true;
}

bool GetUidList(const Json::Value& node, const char* key, std::vector<uint32_t>* out,
                std::vector<std::string>* errors) {
  if (!node.isMember(key)) {
    return true;
  }
  const Json::Value& array = node[key];
  if (!array.isArray()) {
    errors->push_back(std::string(key) + " must be an array of uids");
    return false;
  }
  out->clear();
  for (const Json::Value& entry : array) {
    if (!entry.isNumeric()) {
      errors->push_back(std::string(key) + " contains a non-numeric uid");
      return false;
    }
    const auto uid = static_cast<uint32_t>(entry.asUInt64());
    bool duplicate = false;
    for (uint32_t existing : *out) {
      if (existing == uid) {
        duplicate = true;
        break;
      }
    }
    if (duplicate) {
      // Not a security problem, but a list with duplicates is a list somebody
      // edited without reading, and the rest of it deserves scrutiny.
      errors->push_back(std::string(key) + " contains duplicate uid " + std::to_string(uid));
      return false;
    }
    out->push_back(uid);
  }
  return true;
}

bool GetCidrList(const Json::Value& node, const char* key, std::vector<std::string>* out,
                 std::vector<std::string>* errors) {
  if (!node.isMember(key)) {
    return true;
  }
  const Json::Value& array = node[key];
  if (!array.isArray()) {
    errors->push_back(std::string(key) + " must be an array of CIDR strings");
    return false;
  }
  out->clear();
  for (const Json::Value& entry : array) {
    if (!entry.isString()) {
      errors->push_back(std::string(key) + " contains a non-string entry");
      return false;
    }
    // Parsed here rather than at decision time, so that a typo in the configuration
    // is reported when the daemon starts instead of becoming a silent doubt during
    // an incident. A range that does not parse can only push a decision toward the
    // vault, which is safe but is not what the operator asked for.
    ::xrom::recovery::Ipv4Range range;
    if (!::xrom::recovery::ParseIpv4Range(entry.asString(), &range)) {
      errors->push_back(std::string(key) + " contains an invalid IPv4 CIDR: " + entry.asString() +
                        " (leading zeros, a /0 prefix and trailing junk are all rejected)");
      return false;
    }
    out->push_back(::xrom::recovery::Ipv4ToString(range.network) + "/" +
                   std::to_string(range.prefix_length));
  }
  return true;
}

}  // namespace

std::string ConfigLoadResult::Describe() const {
  if (ok) {
    return "configuration loaded";
  }
  std::string out = "configuration rejected (" + std::to_string(errors.size()) + "): ";
  for (size_t i = 0; i < errors.size(); ++i) {
    if (i != 0) {
      out += "; ";
    }
    out += errors[i];
  }
  return out;
}

ConfigLoadResult LoadConfig(const std::string& path) {
  ConfigLoadResult result;
  result.config = SentinelConfig{};  // the shipped defaults are the starting point

  std::string content;
  std::string read_error;
  const FileStatus status = ReadFileCapped(path, 256 * 1024, &content, &read_error);
  if (status == FileStatus::kMissing) {
    // A missing file is not a misconfiguration. The defaults in SentinelConfig are
    // the shipped policy and they are documented as such, so a build without the
    // file behaves exactly as described.
    result.ok = true;
    return result;
  }
  if (status != FileStatus::kRead) {
    result.errors.push_back(read_error);
    return result;
  }

  Json::Value root;
  Json::CharReaderBuilder builder;
  builder.settings_["collectComments"] = false;
  std::string parse_error;
  const std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
  if (!reader->parse(content.data(), content.data() + content.size(), &root, &parse_error)) {
    // A file that exists and does not parse is a configuration somebody wrote and
    // got wrong. Falling back to defaults here would mean the device runs a policy
    // nobody chose and the log does not mention it.
    result.errors.push_back(path + " is not valid JSON: " + parse_error);
    return result;
  }
  if (!root.isObject()) {
    result.errors.push_back(path + " must contain a JSON object");
    return result;
  }

  // Reject unknown keys. A configuration file for a security daemon that silently
  // ignores a misspelled setting is a file that reports "configured" while running
  // the default, and the operator has no way to notice.
  static const std::vector<std::string> kKnownKeys = {
      "reporter_uids",
      "allow_root_reporter",
      "allow_shell_reporter",
      "quarantine",
      "boot_attempts",
      "recovery",
      "monitored_dir",
      "state_dir",
      "vault_block_device",
      "vault_meta_block_device",
      "vault_record_offset",
      "check_integrity_on_boot",
      "deep_integrity_on_boot",
      "use_netd_firewall_chain",
      "use_interface_down",
      "use_quarantine_property",
      "netd_oem_chain",
      "stash_evidence_in_pvm",
      "evidence_vm_timeout_ms",
      "reboot_target",
      "min_battery_percent_for_reboot",
  };
  for (const std::string& key : root.getMemberNames()) {
    bool known = false;
    for (const std::string& candidate : kKnownKeys) {
      if (candidate == key) {
        known = true;
        break;
      }
    }
    if (!known) {
      result.errors.push_back("unknown key \"" + key + "\"; a misspelled setting would "
                                                            "otherwise be ignored silently and "
                                                            "the default would apply");
    }
  }

  auto& config = result.config;
  auto& errors = result.errors;

  GetUidList(root, "reporter_uids", &config.reporter_uids, &errors);
  GetBool(root, "allow_root_reporter", &config.allow_root_reporter, &errors);
  GetBool(root, "allow_shell_reporter", &config.allow_shell_reporter, &errors);

  GetString(root, "monitored_dir", &config.monitored_dir, &errors, /*absolute=*/true);
  GetString(root, "state_dir", &config.state_dir, &errors, /*absolute=*/true);
  GetString(root, "vault_block_device", &config.vault_block_device, &errors, /*absolute=*/true);
  GetString(root, "vault_meta_block_device", &config.vault_meta_block_device, &errors,
            /*absolute=*/true);
  GetNumber<uint64_t>(root, "vault_record_offset", &config.vault_record_offset, &errors, 0,
                      1024 * 1024);

  GetBool(root, "check_integrity_on_boot", &config.check_integrity_on_boot, &errors);
  GetBool(root, "deep_integrity_on_boot", &config.deep_integrity_on_boot, &errors);
  GetBool(root, "use_netd_firewall_chain", &config.use_netd_firewall_chain, &errors);
  GetBool(root, "use_interface_down", &config.use_interface_down, &errors);
  GetBool(root, "use_quarantine_property", &config.use_quarantine_property, &errors);
  GetNumber<int32_t>(root, "netd_oem_chain", &config.netd_oem_chain, &errors, 1, 3);
  GetBool(root, "stash_evidence_in_pvm", &config.stash_evidence_in_pvm, &errors);
  GetNumber<int32_t>(root, "evidence_vm_timeout_ms", &config.evidence_vm_timeout_ms, &errors, 1000,
                     60000);
  GetString(root, "reboot_target", &config.reboot_target, &errors, /*absolute=*/false);
  GetNumber<uint32_t>(root, "min_battery_percent_for_reboot",
                      &config.min_battery_percent_for_reboot, &errors, 0, 100);

  // --- nested: quarantine ----------------------------------------------------
  if (root.isMember("quarantine")) {
    const Json::Value& node = root["quarantine"];
    if (!node.isObject()) {
      errors.push_back("quarantine must be an object");
    } else {
      GetNumber<int32_t>(node, "cancel_window_seconds", &config.quarantine.cancel_window_seconds,
                         &errors, 0, 300);
      GetBool(node, "cancel_requires_authentication",
              &config.quarantine.cancel_requires_authentication, &errors);
      GetBool(node, "allow_cancel_at_critical", &config.quarantine.allow_cancel_at_critical,
              &errors);
      int32_t threshold = static_cast<int32_t>(config.quarantine.reboot_threshold);
      GetNumber<int32_t>(node, "reboot_threshold", &threshold, &errors, 0, 3);
      config.quarantine.reboot_threshold =
          static_cast<::xrom::recovery::ThreatSeverity>(threshold);
      GetNumber<int32_t>(node, "total_budget_ms", &config.quarantine.total_budget_ms, &errors, 1000,
                         300000);
      GetString(node, "staging_log_path", &config.quarantine.staging_log_path, &errors,
                /*absolute=*/true);
    }
  }

  // --- nested: boot_attempts ---------------------------------------------------
  if (root.isMember("boot_attempts")) {
    const Json::Value& node = root["boot_attempts"];
    if (!node.isObject()) {
      errors.push_back("boot_attempts must be an object");
    } else {
      GetNumber<uint32_t>(node, "max_integrity_failures",
                          &config.boot_attempts.max_integrity_failures, &errors, 1, 100);
      // The floor may not be zero: at zero the bootloader has already marked the
      // slot unbootable and is falling back, so waiting for zero means X-ROM never
      // gets to say anything about a slot that is dying. See correction #4.
      GetNumber<uint32_t>(node, "tries_remaining_floor", &config.boot_attempts.tries_remaining_floor,
                          &errors, 1, 7);
      GetBool(node, "verity_corruption_counts", &config.boot_attempts.verity_corruption_counts,
              &errors);
      GetBool(node, "respect_recovery_tries", &config.boot_attempts.respect_recovery_tries,
              &errors);
      GetBool(node, "require_bootable_other_slot", &config.boot_attempts.require_bootable_other_slot,
              &errors);
    }
  }

  // --- nested: recovery ---------------------------------------------------------
  if (root.isMember("recovery")) {
    const Json::Value& node = root["recovery"];
    if (!node.isObject()) {
      errors.push_back("recovery must be an object");
    } else {
      GetCidrList(node, "pinned_cidrs", &config.recovery.pinned_cidrs, &errors);
      GetNumber<uint64_t>(node, "max_package_bytes", &config.recovery.max_package_bytes, &errors, 0,
                          4ull * 1024 * 1024 * 1024);
      GetBool(node, "require_dual_signature", &config.recovery.require_dual_signature, &errors);
      GetBool(node, "vault_unavailable", &config.recovery.vault_unavailable, &errors);
      GetBool(node, "skip_dns_range_check", &config.recovery.skip_dns_range_check, &errors);
      // A ceiling of zero disables network installs entirely rather than allowing
      // anything, which is the reading DecidePackageSize gives it. Warn so that a
      // zero entered as a placeholder does not silently mean "never update".
      if (config.recovery.max_package_bytes == 0) {
        errors.push_back("recovery.max_package_bytes is 0, which disables network "
                         "installs entirely; if that is intended, set "
                         "skip_dns_range_check as well so the intent is explicit");
      }
    }
  }

  // An empty reporter list would make the daemon unreachable, which is fail-secure
  // but is not what anybody configuring it meant.
  if (config.reporter_uids.empty() && !config.allow_root_reporter &&
      !config.allow_shell_reporter) {
    errors.push_back("no uid is authorised to report a threat; the daemon would be "
                     "unreachable and no detection could ever trigger a response");
  }

  result.ok = errors.empty();
  return result;
}

bool IsAuthorisedReporter(const SentinelConfig& config, uint32_t calling_uid,
                          bool debuggable_build) {
  constexpr uint32_t kAidRoot = 0;
  constexpr uint32_t kAidShell = 2000;

  // Root is checked before the list, and only when both the configuration and the
  // build allow it. On a production build nothing runs as root that should be
  // reporting threats, and allowing it would make the uid list decorative for
  // anyone who gets root.
  if (calling_uid == kAidRoot) {
    return config.allow_root_reporter && debuggable_build;
  }
  // Shell is an adb-reachable threat reporter, which on a production build is a
  // remote reboot button. main.cpp passes debuggable_build from ro.debuggable, so
  // this cannot be enabled by the configuration file alone.
  if (calling_uid == kAidShell) {
    return config.allow_shell_reporter && debuggable_build;
  }
  for (uint32_t uid : config.reporter_uids) {
    if (uid == calling_uid) {
      return true;
    }
  }
  return false;
}

}  // namespace xrom::sentinel
