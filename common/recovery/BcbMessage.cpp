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

#include "BcbMessage.h"

#include <algorithm>
#include <cstring>
#include <set>

namespace xrom::recovery {
namespace {

// Copies into a fixed, NUL-terminated wire buffer. Returns false when the value
// does not fit, including its terminator: a truncated command field is read by
// the bootloader as a different command, which is the failure mode this exists to
// prevent.
bool ToFixed(const std::string& value, char* buffer, size_t buffer_size) {
  if (value.size() >= buffer_size) {
    return false;
  }
  std::memset(buffer, 0, buffer_size);
  std::memcpy(buffer, value.data(), value.size());
  return true;
}

std::string FromFixed(const char* buffer, size_t buffer_size) {
  size_t length = 0;
  while (length < buffer_size && buffer[length] != '\0') {
    ++length;
  }
  return std::string(buffer, length);
}

bool IsAllowedCommand(const std::string& command) {
  return command == kCommandBootRecovery || command == kCommandBootFastboot ||
         command == kCommandBootonceBootloader;
}

bool IsAllowedReason(const std::string& reason) {
  return reason == kReasonThreatDetected || reason == kReasonBootLoop ||
         reason == kReasonIntegrityMismatch || reason == kReasonOperatorRequest;
}

// Recovery options end up on a command line that recovery's argument parser
// splits on newlines. A newline, a space or a control byte inside an option would
// either inject a second option or truncate this one, so the alphabet is
// deliberately narrow: everything a legitimate option needs (= / . : - _ @ + and
// alphanumerics) and nothing else.
bool IsAllowedOption(const std::string& option) {
  if (option.empty() || option.size() > 200) {
    return false;
  }
  if (option.rfind("--", 0) == 0) {
    return false;  // callers pass options without the leading dashes
  }
  return std::all_of(option.begin(), option.end(), [](char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
           c == '=' || c == '/' || c == '.' || c == ':' || c == '-' || c == '_' ||
           c == '@' || c == '+';
  });
}

bool IsAllowedStage(const std::string& stage) {
  // "n/m", both non-empty and numeric. Recovery renders this as a progress
  // indicator, so a malformed stage is a cosmetic bug — but an arbitrary string
  // in a fixed 32-byte field is not worth the risk.
  const size_t slash = stage.find('/');
  if (slash == std::string::npos || slash == 0 || slash + 1 >= stage.size()) {
    return false;
  }
  const auto numeric = [](const std::string& part) {
    return !part.empty() && part.size() <= 8 &&
           std::all_of(part.begin(), part.end(), [](char c) { return c >= '0' && c <= '9'; });
  };
  return numeric(stage.substr(0, slash)) && numeric(stage.substr(slash + 1));
}

}  // namespace

std::vector<std::string> Validate(const BcbRequest& request) {
  std::vector<std::string> problems;
  const auto add = [&problems](const std::string& p) { problems.push_back(p); };

  // An empty command means "leave the bootloader's instruction alone", which is a
  // legitimate thing to want when only the recovery options matter.
  if (!request.command.empty() && !IsAllowedCommand(request.command)) {
    add("command \"" + request.command +
        "\" is not one X-ROM will write; a typo here puts the device in an "
        "undefined boot state with no log to read afterwards");
  }
  if (!request.reason.empty() && !IsAllowedReason(request.reason)) {
    add("reason \"" + request.reason + "\" is not a known X-ROM recovery reason");
  }
  if (!request.stage.empty() && !IsAllowedStage(request.stage)) {
    add("stage must be \"n/m\" with numeric halves");
  }
  if (request.recovery_options.size() > 32) {
    add("more than 32 recovery options; the recovery field is 768 bytes");
  }
  for (const std::string& option : request.recovery_options) {
    if (!IsAllowedOption(option)) {
      add("recovery option \"" + option +
          "\" contains a byte recovery's parser would split on, or is too long");
    }
  }
  return problems;
}

std::vector<std::string> ParseRecoveryOptions(const BootloaderMessage& message) {
  std::vector<std::string> options;
  const std::string field = FromFixed(message.recovery, sizeof(message.recovery));

  size_t start = 0;
  bool first_line = true;
  while (start <= field.size()) {
    const size_t newline = field.find('\n', start);
    const size_t end = newline == std::string::npos ? field.size() : newline;
    const std::string line = field.substr(start, end - start);
    if (first_line) {
      // The first line is the literal "recovery" marker. Recovery's parser
      // requires it and ignores the field without it, so it is skipped here and
      // re-added by Render().
      first_line = false;
    } else if (!line.empty()) {
      options.push_back(line.rfind("--", 0) == 0 ? line.substr(2) : line);
    }
    if (newline == std::string::npos) {
      break;
    }
    start = newline + 1;
  }
  return options;
}

bool RequestsRecovery(const BootloaderMessage& message) {
  return FromFixed(message.command, sizeof(message.command)) == kCommandBootRecovery;
}

std::string XromReason(const BootloaderMessage& message) {
  const std::string prefix = "xrom-reason=";
  for (const std::string& option : ParseRecoveryOptions(message)) {
    if (option.rfind(prefix, 0) == 0) {
      return option.substr(prefix.size());
    }
  }
  return "";
}

bool Render(const BcbRequest& request, const BootloaderMessage& existing, BcbImage* out,
            std::vector<std::string>* errors) {
  if (out == nullptr || errors == nullptr) {
    return false;
  }
  for (const std::string& problem : Validate(request)) {
    errors->push_back(problem);
  }
  if (!errors->empty()) {
    return false;
  }

  BootloaderMessage rendered = existing;

  if (!request.command.empty() &&
      !ToFixed(request.command, rendered.command, sizeof(rendered.command))) {
    errors->push_back("command does not fit in 32 bytes");
    return false;
  }
  if (!request.stage.empty() && !ToFixed(request.stage, rendered.stage, sizeof(rendered.stage))) {
    errors->push_back("stage does not fit in 32 bytes");
    return false;
  }

  // Merge, do not replace. Existing options are kept in their original order and
  // new ones are appended only if absent, so that rendering the same request twice
  // is a no-op and a queued command from uncrypt or update_engine survives.
  std::vector<std::string> merged = ParseRecoveryOptions(existing);
  const std::set<std::string> already(merged.begin(), merged.end());
  for (const std::string& option : request.recovery_options) {
    if (already.count(option) == 0) {
      merged.push_back(option);
    }
  }
  if (!request.reason.empty()) {
    const std::string reason_option = std::string("xrom-reason=") + request.reason;
    // A second reason replaces the first: the most recent trigger is the one
    // recovery should see, and two --xrom-reason flags would make the field
    // ambiguous to anything that reads it.
    merged.erase(std::remove_if(merged.begin(), merged.end(),
                                [](const std::string& option) {
                                  return option.rfind("xrom-reason=", 0) == 0;
                                }),
                 merged.end());
    merged.push_back(reason_option);
  }

  std::string field = std::string(kRecoveryHeaderLine) + "\n";
  for (const std::string& option : merged) {
    field += "--" + option + "\n";
  }
  // One byte is reserved for the terminator, so the usable length is 767.
  if (field.size() >= sizeof(rendered.recovery)) {
    errors->push_back("the merged recovery field is " + std::to_string(field.size()) +
                      " bytes and does not fit in 768; refusing to truncate it, "
                      "because a truncated option is a different option");
    return false;
  }
  std::memset(rendered.recovery, 0, sizeof(rendered.recovery));
  std::memcpy(rendered.recovery, field.data(), field.size());

  out->message = rendered;
  out->changed = std::memcmp(&rendered, &existing, sizeof(rendered)) != 0;
  return true;
}

std::vector<uint8_t> ToBytes(const BootloaderMessage& message) {
  const uint8_t* begin = reinterpret_cast<const uint8_t*>(&message);
  return std::vector<uint8_t>(begin, begin + sizeof(message));
}

bool FromBytes(const uint8_t* data, size_t size, BootloaderMessage* out) {
  if (data == nullptr || out == nullptr || size < sizeof(BootloaderMessage)) {
    return false;
  }
  // Copied rather than reinterpret_cast onto the buffer: misc is read from a block
  // device into a byte vector, and pointing a packed struct at arbitrary memory
  // whose alignment nobody checked is the kind of shortcut that works on one
  // architecture and faults on another.
  std::memcpy(out, data, sizeof(BootloaderMessage));
  return true;
}

}  // namespace xrom::recovery
