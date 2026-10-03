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

#include "OtaManifest.h"

namespace xrom::ota {
namespace {

constexpr char kHexDigits[] = "0123456789abcdef";

// Appends a JSON string literal escaped the way Python's json.dumps does with
// ensure_ascii=True: the short escapes for the five named control characters,
// \u00XX for the rest of the C0 range, and \uXXXX for anything non-ASCII.
//
// This has to match tools/xrom_sign_ota.py byte for byte, because the signature
// covers the serialised manifest and a signer that escapes differently from a
// verifier produces signatures that are valid over bytes nobody ever sends. The
// matching is asserted by tools/tests/ota_signing_roundtrip.sh, which serialises
// the same manifest both ways and compares.
void AppendJsonString(std::string* out, const std::string& value) {
  out->push_back('"');
  for (unsigned char c : value) {
    switch (c) {
      case '"':
        out->append("\\\"");
        break;
      case '\\':
        out->append("\\\\");
        break;
      case '\b':
        out->append("\\b");
        break;
      case '\f':
        out->append("\\f");
        break;
      case '\n':
        out->append("\\n");
        break;
      case '\r':
        out->append("\\r");
        break;
      case '\t':
        out->append("\\t");
        break;
      default:
        if (c < 0x20 || c > 0x7E) {
          char buf[7];
          buf[0] = '\\';
          buf[1] = 'u';
          buf[2] = '0';
          buf[3] = '0';
          buf[4] = kHexDigits[(c >> 4) & 0x0F];
          buf[5] = kHexDigits[c & 0x0F];
          buf[6] = '\0';
          out->append(buf);
        } else {
          out->push_back(static_cast<char>(c));
        }
        break;
    }
  }
  out->push_back('"');
}

void AppendField(std::string* out, bool* first, const char* key, const std::string& value) {
  out->append(*first ? "  " : ",\n  ");
  *first = false;
  AppendJsonString(out, key);
  out->append(": ");
  AppendJsonString(out, value);
}

void AppendField(std::string* out, bool* first, const char* key, uint64_t value) {
  out->append(*first ? "  " : ",\n  ");
  *first = false;
  AppendJsonString(out, key);
  out->append(": ");
  out->append(std::to_string(value));
}

void AppendField(std::string* out, bool* first, const char* key, int64_t value) {
  AppendField(out, first, key, static_cast<uint64_t>(value));
}

void AppendField(std::string* out, bool* first, const char* key, bool value) {
  out->append(*first ? "  " : ",\n  ");
  *first = false;
  AppendJsonString(out, key);
  out->append(": ");
  out->append(value ? "true" : "false");
}

bool StartsWith(const std::string& value, const std::string& prefix) {
  return value.size() >= prefix.size() && value.compare(0, prefix.size(), prefix) == 0;
}

bool IsPlainHostname(const std::string& host) {
  // Letters, digits, hyphen and dot; no leading or trailing hyphen in a label; at
  // least one dot so that a bare name cannot resolve through a search domain the
  // attacker happens to control; and a final label that is not entirely digits.
  //
  // That last rule is what rejects an IPv4 literal. It is not a cosmetic
  // preference: a pinned certificate has a subject name to match against and an
  // address does not, so a URL naming an address bypasses the pin entirely and
  // leaves only whatever the certificate authority decided. IPv6 literals are
  // already rejected because '[' is not in the allowed alphabet.
  //
  // A real hostname's top-level label is never all digits, so this does not reject
  // any legitimate update host — but it does reject "host.123", which is not a
  // legitimate host either.
  if (host.empty() || host.size() > 253) {
    return false;
  }
  if (host.find('.') == std::string::npos) {
    return false;
  }

  size_t label_start = 0;
  // Two flags, because the loop terminates the final label with a synthetic dot:
  // |current| accumulates over the label being scanned and is folded into |last|
  // when the label ends. Resetting a single flag at the dot would clear it after
  // the final label had already been scanned, which is the bug this pair exists to
  // avoid.
  bool current_label_all_digits = true;
  bool last_label_all_digits = true;
  for (size_t i = 0; i <= host.size(); ++i) {
    const bool at_end = (i == host.size());
    const char c = at_end ? '.' : host[i];
    if (c == '.') {
      const size_t label_len = i - label_start;
      if (label_len == 0 || label_len > 63) {
        return false;
      }
      if (host[label_start] == '-' || host[i - 1] == '-') {
        return false;
      }
      last_label_all_digits = current_label_all_digits;
      current_label_all_digits = true;
      label_start = i + 1;
      continue;
    }
    const bool digit = (c >= '0' && c <= '9');
    const bool ok_char = digit || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-';
    if (!ok_char) {
      return false;
    }
    if (!digit) {
      current_label_all_digits = false;
    }
  }
  // The loop above has already validated every label, including the synthetic
  // trailing one, so all that is left is to require a dot and a non-numeric
  // final label. (An earlier version also compared label_start against
  // host.size(); after the synthetic trailing dot label_start is always
  // host.size() + 1, so that comparison was always false and every hostname was
  // rejected. The test suite caught it, which is the only reason it was caught.)
  return !last_label_all_digits;
}

}  // namespace

bool IsLowercaseHex64(const std::string& value) {
  if (value.size() != 64) {
    return false;
  }
  for (char c : value) {
    const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    if (!ok) {
      return false;
    }
  }
  return true;
}

std::string OtaManifest::Serialize() const {
  std::string out = "{\n";
  bool first = true;
  AppendField(&out, &first, "manifest_version", static_cast<uint64_t>(manifest_version));
  AppendField(&out, &first, "package_url", package_url);
  AppendField(&out, &first, "package_sha256", package_sha256);
  AppendField(&out, &first, "package_bytes", package_bytes);
  AppendField(&out, &first, "security_version", static_cast<uint64_t>(security_version));
  AppendField(&out, &first, "build_fingerprint", build_fingerprint);
  AppendField(&out, &first, "target_fingerprint", target_fingerprint);
  AppendField(&out, &first, "expected_hashtree_root_sha256", expected_hashtree_root_sha256);
  AppendField(&out, &first, "min_battery_percent", static_cast<uint64_t>(min_battery_percent));
  AppendField(&out, &first, "issued_at_unix", issued_at_unix);
  AppendField(&out, &first, "not_after_unix", not_after_unix);
  AppendField(&out, &first, "updates_vault", updates_vault);
  out.append("\n}\n");
  return out;
}

std::string OtaManifestValidation::Describe() const {
  if (ok) {
    return "valid";
  }
  std::string out = "invalid (" + std::to_string(errors.size()) + "): ";
  for (size_t i = 0; i < errors.size(); ++i) {
    if (i != 0) {
      out += "; ";
    }
    out += errors[i];
  }
  return out;
}

OtaManifestValidation Validate(const OtaManifest& manifest) {
  OtaManifestValidation result;
  auto& errors = result.errors;
  auto add = [&errors](const std::string& message) { errors.push_back(message); };

  if (manifest.manifest_version != kOtaManifestVersion) {
    add("manifest_version must be " + std::to_string(kOtaManifestVersion) + ", got " +
        std::to_string(manifest.manifest_version));
  }

  // --- the URL ---------------------------------------------------------------
  //
  // Checked structurally rather than by handing it to a URL parser, because the
  // parser in the recovery image and the parser here are not guaranteed to agree
  // on what counts as a host, and a disagreement between "what the verifier
  // thought it approved" and "what the downloader fetched" is the entire attack.
  if (manifest.package_url.empty()) {
    add("package_url must not be empty");
  } else if (manifest.package_url.size() > kMaxUrlLength) {
    add("package_url exceeds " + std::to_string(kMaxUrlLength) + " characters");
  } else if (!StartsWith(manifest.package_url, "https://")) {
    add("package_url must use https://; a plaintext fetch means the signature "
        "covers bytes that were not the bytes received");
  } else {
    const std::string rest = manifest.package_url.substr(8);
    const size_t path_start = rest.find('/');
    const std::string authority =
        path_start == std::string::npos ? rest : rest.substr(0, path_start);
    const size_t at = authority.rfind('@');
    if (at != std::string::npos) {
      // user:pass@host. The part before the @ is credentials and the part after is
      // the real host, and a verifier that reads the whole thing as a host approves
      // https://trusted.example@evil.example/. Reject rather than parse.
      add("package_url must not contain userinfo; an authority with '@' makes the "
          "real host ambiguous to different URL parsers");
    } else {
      size_t colon = authority.find(':');
      std::string host = authority;
      if (colon != std::string::npos) {
        host = authority.substr(0, colon);
        const std::string port = authority.substr(colon + 1);
        if (port.empty() || port.size() > 5) {
          add("package_url has an invalid port");
        } else {
          for (char c : port) {
            if (c < '0' || c > '9') {
              add("package_url has a non-numeric port");
              break;
            }
          }
          if (port != "443") {
            add("package_url must use port 443; a non-standard port is a proxy "
                "that the pinned certificate was not issued for");
          }
        }
      }
      if (!IsPlainHostname(host)) {
        add("package_url host must be a dotted hostname, not an IP literal or a "
            "bare name, so that certificate pinning has a subject to match");
      }
      if (path_start == std::string::npos) {
        add("package_url must include a path");
      }
      if (manifest.package_url.find("..") != std::string::npos) {
        add("package_url must not contain '..'");
      }
    }
  }

  // --- the digests -----------------------------------------------------------
  if (!IsLowercaseHex64(manifest.package_sha256)) {
    add("package_sha256 must be 64 lowercase hex characters");
  }
  if (!IsLowercaseHex64(manifest.expected_hashtree_root_sha256)) {
    add("expected_hashtree_root_sha256 must be 64 lowercase hex characters");
  }

  // --- the size --------------------------------------------------------------
  if (manifest.package_bytes == 0) {
    add("package_bytes must be non-zero: a manifest that does not declare a size "
        "cannot be size-gated, and an ungated download is how a recovery image "
        "runs out of partition");
  }

  // --- the fingerprints ------------------------------------------------------
  if (manifest.build_fingerprint.empty() ||
      manifest.build_fingerprint.size() > kMaxFingerprintLength) {
    add("build_fingerprint must be 1.." + std::to_string(kMaxFingerprintLength) + " characters");
  }
  if (manifest.target_fingerprint.empty() ||
      manifest.target_fingerprint.size() > kMaxFingerprintLength) {
    add("target_fingerprint must be 1.." + std::to_string(kMaxFingerprintLength) + " characters");
  }
  // An incremental package whose target equals its own output is not incremental,
  // and a full package that claims a target is claiming a base it does not need.
  // Neither is fatal on its own, but the two being equal means somebody filled the
  // fields in without thinking, and the anti-rollback check that depends on them
  // is then meaningless.
  if (!manifest.target_fingerprint.empty() &&
      manifest.target_fingerprint == manifest.build_fingerprint) {
    add("target_fingerprint must differ from build_fingerprint");
  }

  // --- the counters and the window -------------------------------------------
  if (manifest.min_battery_percent > 100) {
    add("min_battery_percent must be 0..100");
  }
  if (manifest.issued_at_unix <= 0) {
    add("issued_at_unix must be positive");
  }
  if (manifest.not_after_unix <= 0) {
    add("not_after_unix must be positive");
  }
  if (manifest.issued_at_unix > 0 && manifest.not_after_unix > 0 &&
      manifest.not_after_unix <= manifest.issued_at_unix) {
    add("not_after_unix must be after issued_at_unix");
  }
  // A validity window longer than a year is a manifest that can be replayed for a
  // year. The signing tool caps it; the verifier refuses to accept one that did not
  // come from the signing tool.
  if (manifest.issued_at_unix > 0 && manifest.not_after_unix > 0 &&
      manifest.not_after_unix - manifest.issued_at_unix > 366 * 24 * 3600) {
    add("the validity window exceeds 366 days");
  }

  result.ok = errors.empty();
  return result;
}

SizeDecision DecidePackageSize(uint64_t declared_bytes, uint64_t max_bytes) {
  SizeDecision decision;
  if (max_bytes == 0) {
    decision.accepted = false;
    decision.reason = "the size ceiling is zero, which disables network installs "
                      "entirely rather than allowing anything";
    return decision;
  }
  if (declared_bytes == 0) {
    decision.accepted = false;
    decision.reason = "the manifest does not declare a size";
    return decision;
  }
  if (declared_bytes > max_bytes) {
    decision.accepted = false;
    decision.reason = "the declared package is " + std::to_string(declared_bytes) +
                      " bytes, above the " + std::to_string(max_bytes) +
                      " byte ceiling; falling back to the vault rather than "
                      "attempting a download that cannot be completed safely";
    return decision;
  }
  decision.accepted = true;
  decision.reason = "the declared package is " + std::to_string(declared_bytes) +
                    " bytes, within the " + std::to_string(max_bytes) + " byte ceiling";
  return decision;
}

}  // namespace xrom::ota
