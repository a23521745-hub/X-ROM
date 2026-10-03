#!/usr/bin/env bash
#
# Copyright (C) 2026 The X-ROM Project
# SPDX-License-Identifier: Apache-2.0
#
# End-to-end check of the OTA signing chain.
#
# THE TEST THAT MATTERS MOST IS STEP 4
# ------------------------------------
# tools/xrom_sign_ota.py produces update.json in Python and common/ota/OtaManifest.cpp
# re-serialises it in C++ to check that the parse is faithful to the bytes that were
# signed. Those two implementations must agree byte for byte — field order, indent,
# separators, escaping, trailing newline — or every signature produced by the tool is
# valid over bytes the device will never reconstruct. The refusal is correct and safe,
# but it looks like a broken key, and it will be diagnosed as one.
#
# Step 4 compiles a C++ program that builds the same manifest from the same field values
# and compares OtaManifest::Serialize() against the file the Python tool actually wrote.
# That is a real cross-check of two independent implementations, not a Python test that
# agrees with itself.
#
# Keys are generated into a temporary directory and never written into the repository.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

PASSED=0
FAILED=0

ok()   { echo "  [ OK ] $1"; PASSED=$((PASSED + 1)); }
bad()  { echo "  [FAIL] $1"; FAILED=$((FAILED + 1)); }
check() { if [ "$1" -eq 0 ]; then ok "$2"; else bad "$2"; fi; }

cd "${REPO_ROOT}"

echo "=== 1. keys and a package ==="
openssl genpkey -algorithm ed25519 -out "${WORK}/ed.pem" 2>/dev/null
check $? "generated an Ed25519 signing key"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out "${WORK}/rsa.pem" 2>/dev/null
check $? "generated an RSA-4096 signing key"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "${WORK}/rsa2048.pem" 2>/dev/null
check $? "generated an RSA-2048 key (for the rejection test)"

head -c 300000 /dev/urandom > "${WORK}/package.zip"
check $? "created a 300000 byte package"

# A trust file built from the freshly generated public halves, in the same shape as
# security/ota_trust/ota_trust_anchors.json.
python3 - "$WORK" <<'PY'
import json, subprocess, sys
work = sys.argv[1]
def pub(p):
    return subprocess.run(['openssl','pkey','-in',p,'-pubout'],
                          capture_output=True, text=True, check=True).stdout
json.dump({"anchors":[
  {"key_id":"rt-ed25519-01","algorithm":"ED25519","enabled":True,
   "min_security_version":0,"public_key":pub(f"{work}/ed.pem").strip()},
  {"key_id":"rt-rsa4096-01","algorithm":"RSA4096_SHA256","enabled":True,
   "min_security_version":0,"public_key":pub(f"{work}/rsa.pem").strip()},
]}, open(f"{work}/anchors.json","w"), indent=4)
PY
check $? "built a temporary trust file from the fresh public halves"

echo
echo "=== 2. sign ==="
python3 tools/xrom_sign_ota.py \
    --ed25519-key "${WORK}/ed.pem" --rsa-key "${WORK}/rsa.pem" \
    --package "${WORK}/package.zip" \
    --url "https://update.xrom.example/releases/x1/ota-0009.zip" \
    --security-version 9 \
    --build-fingerprint "X-ROM/x1/16/AP1A.000000.009/9:user/release-keys" \
    --target-fingerprint "X-ROM/x1/16/AP1A.000000.008/8:user/release-keys" \
    --hashtree-root "$(printf 'a%.0s' $(seq 64))" \
    --min-battery 30 --valid-days 90 --now 1767225600 \
    --out-dir "${WORK}/out" > "${WORK}/sign.log" 2>&1
check $? "xrom_sign_ota.py signed with both keys"
grep -q "signed ED25519" "${WORK}/sign.log" && ok "an Ed25519 signature was written" \
                                              || bad "no Ed25519 signature"
grep -q "signed RSA4096_SHA256" "${WORK}/sign.log" && ok "an RSA-4096 signature was written" \
                                                    || bad "no RSA-4096 signature"
[ -s "${WORK}/out/update.json" ] && ok "update.json exists and is non-empty" \
                                 || bad "update.json is missing or empty"
[ "$(stat -c%s "${WORK}/out/update.json.ed25519.sig" 2>/dev/null || echo 0)" -ge 128 ] \
    && ok "the Ed25519 signature file holds 64 bytes of hex" \
    || bad "the Ed25519 signature file is the wrong size"
[ "$(stat -c%s "${WORK}/out/update.json.rsa4096.sig" 2>/dev/null || echo 0)" -ge 1024 ] \
    && ok "the RSA signature file holds 512 bytes of hex" \
    || bad "the RSA signature file is the wrong size"

echo
echo "=== 3. verify ==="
python3 tools/xrom_verify_ota.py --manifest "${WORK}/out/update.json" \
    --trust "${WORK}/anchors.json" --installed-security-version 8 \
    --running-fingerprint "X-ROM/x1/16/AP1A.000000.008/8:user/release-keys" \
    --battery 80 --now 1767312000 > "${WORK}/verify.log" 2>&1
check $? "xrom_verify_ota.py accepted the manifest through every stage"
grep -q "verified under rt-ed25519-01" "${WORK}/verify.log" \
    && ok "the Ed25519 signature verified under the pinned anchor" || bad "ed25519 anchor not used"
grep -q "verified under rt-rsa4096-01" "${WORK}/verify.log" \
    && ok "the RSA signature verified under the pinned anchor" || bad "rsa anchor not used"

echo
echo "=== 4. the C++ serialiser agrees with the Python one, byte for byte ==="
# Build a C++ program that constructs the SAME manifest from the SAME field values read
# out of the file the Python tool wrote, then compares OtaManifest::Serialize() against
# those bytes. Two independent implementations of one artifact format.
python3 - "$WORK" <<'PY'
import json, sys
work = sys.argv[1]
m = json.load(open(f"{work}/out/update.json"))
def s(v): return json.dumps(v)
open(f"{work}/crosscheck.cpp","w").write(f'''
#include "OtaManifest.h"
#include <cstdio>
#include <fstream>
#include <sstream>
// argc is unnamed rather than unused-parameter-suppressed: the whole point of this
// program is to be compiled with the same -Wall -Wextra -Werror the library is, and a
// warning that had to be turned off here would be a warning nobody notices there.
int main(int, char** argv) {{
  xrom::ota::OtaManifest manifest;
  manifest.manifest_version = {m["manifest_version"]};
  manifest.package_url = {s(m["package_url"])};
  manifest.package_sha256 = {s(m["package_sha256"])};
  manifest.package_bytes = {m["package_bytes"]};
  manifest.security_version = {m["security_version"]};
  manifest.build_fingerprint = {s(m["build_fingerprint"])};
  manifest.target_fingerprint = {s(m["target_fingerprint"])};
  manifest.expected_hashtree_root_sha256 = {s(m["expected_hashtree_root_sha256"])};
  manifest.min_battery_percent = {m["min_battery_percent"]};
  manifest.issued_at_unix = {m["issued_at_unix"]};
  manifest.not_after_unix = {m["not_after_unix"]};
  manifest.updates_vault = {str(m["updates_vault"]).lower()};
  const std::string produced = manifest.Serialize();
  std::ifstream in(argv[1], std::ios::binary);
  std::stringstream buffer; buffer << in.rdbuf();
  const std::string on_disk = buffer.str();
  const auto validation = xrom::ota::Validate(manifest);
  std::printf("%zu %zu %d\\n", produced.size(), on_disk.size(), validation.ok ? 1 : 0);
  return produced == on_disk ? 0 : 1;
}}
''')
PY
check $? "generated the cross-check program from the signed manifest"
g++ -std=c++17 -Wall -Wextra -Werror -I"${REPO_ROOT}/common/ota" \
    -o "${WORK}/crosscheck" "${WORK}/crosscheck.cpp" \
    "${REPO_ROOT}/common/ota/OtaManifest.cpp" 2>"${WORK}/crosscheck-build.log"
check $? "the cross-check program compiled against common/ota"
"${WORK}/crosscheck" "${WORK}/out/update.json" > "${WORK}/crosscheck.log" 2>&1
check $? "OtaManifest::Serialize() reproduces the Python tool's bytes exactly ($(cat "${WORK}/crosscheck.log" 2>/dev/null))"

echo
echo "=== 5. negative cases ==="
cp -r "${WORK}/out" "${WORK}/tampered"
python3 - "$WORK" <<'PY'
import sys
work = sys.argv[1]
path = f"{work}/tampered/update.json"
data = bytearray(open(path, "rb").read())
# Flip one byte inside the package_sha256 value.
idx = data.index(b'"package_sha256"') + 20
data[idx] = ord('b') if data[idx:idx+1] == b'a' else ord('a')
open(path, "wb").write(bytes(data))
PY
python3 tools/xrom_verify_ota.py --manifest "${WORK}/tampered/update.json" \
    --trust "${WORK}/anchors.json" --now 1767312000 > "${WORK}/neg1.log" 2>&1
[ $? -ne 0 ] && ok "a single flipped byte in the manifest is refused" \
             || bad "a tampered manifest was ACCEPTED"
grep -q "manifest-signature" "${WORK}/neg1.log" \
    && ok "and it is refused at the signature stage, before any field is read" \
    || bad "the tampered manifest was refused at the wrong stage"

python3 tools/xrom_verify_ota.py --manifest "${WORK}/out/update.json" \
    --trust "${WORK}/anchors.json" --now 1767312000 \
    --installed-security-version 9 > "${WORK}/neg2.log" 2>&1
[ $? -ne 0 ] && ok "a downgrade to the installed security_version is refused" \
             || bad "a downgrade was ACCEPTED"
grep -q "anti-rollback" "${WORK}/neg2.log" && ok "at the anti-rollback stage" \
                                            || bad "refused at the wrong stage"

python3 tools/xrom_verify_ota.py --manifest "${WORK}/out/update.json" \
    --trust "${WORK}/anchors.json" --now 1767312000 --installed-security-version 8 \
    --battery 5 > "${WORK}/neg3.log" 2>&1
[ $? -ne 0 ] && ok "a battery below the manifest's floor is refused" \
             || bad "a low battery was ACCEPTED"

python3 tools/xrom_verify_ota.py --manifest "${WORK}/out/update.json" \
    --trust "${WORK}/anchors.json" --now 1767312000 --installed-security-version 8 \
    --max-package-bytes 1000 > "${WORK}/neg4.log" 2>&1
[ $? -ne 0 ] && ok "a package above the ceiling is refused before it would be fetched" \
             || bad "an oversized package was ACCEPTED"
grep -q "size-ceiling" "${WORK}/neg4.log" && ok "at the size-ceiling stage" \
                                           || bad "refused at the wrong stage"

python3 tools/xrom_verify_ota.py --manifest "${WORK}/out/update.json" \
    --trust "${WORK}/anchors.json" --now 1767312000 --installed-security-version 8 \
    --running-fingerprint "X-ROM/x1/16/AP1A.000000.001/1:user/release-keys" \
    > "${WORK}/neg5.log" 2>&1
[ $? -ne 0 ] && ok "a package for a different build is refused" \
             || bad "a wrong-target package was ACCEPTED"

python3 tools/xrom_verify_ota.py --manifest "${WORK}/out/update.json" \
    --trust "${WORK}/anchors.json" --now 1900000000 --installed-security-version 8 \
    > "${WORK}/neg6.log" 2>&1
[ $? -ne 0 ] && ok "an expired manifest is refused" || bad "an expired manifest was ACCEPTED"
grep -q "validity-window" "${WORK}/neg6.log" && ok "at the validity-window stage" \
                                             || bad "refused at the wrong stage"

mkdir -p "${WORK}/single"
cp "${WORK}/out/update.json" "${WORK}/out/update.json.ed25519.sig" "${WORK}/single/"
python3 tools/xrom_verify_ota.py --manifest "${WORK}/single/update.json" \
    --trust "${WORK}/anchors.json" --now 1767312000 --installed-security-version 8 \
    > "${WORK}/neg7.log" 2>&1
[ $? -ne 0 ] && ok "a manifest with only one signature is refused" \
             || bad "a single-signature manifest was ACCEPTED"
grep -q "dual signature is required" "${WORK}/neg7.log" \
    && ok "and the refusal says which half is missing" || bad "the refusal is not specific"

python3 tools/xrom_verify_ota.py --manifest "${WORK}/single/update.json" \
    --trust "${WORK}/anchors.json" --now 1767312000 --installed-security-version 8 \
    --single-signature > "${WORK}/neg8.log" 2>&1
check $? "--single-signature accepts one, as a deliberate logged weakening"
grep -q "WARNING single-signature mode" "${WORK}/neg8.log" \
    && ok "and warns that it is a weakening rather than a default" || bad "no warning"

echo
echo "=== 6. the signing tool refuses bad inputs ==="
python3 tools/xrom_sign_ota.py --ed25519-key "${WORK}/rsa.pem" --rsa-key "${WORK}/ed.pem" \
    --package "${WORK}/package.zip" --url "https://update.xrom.example/x.zip" \
    --security-version 9 --build-fingerprint "a/1" --target-fingerprint "a/0" \
    --hashtree-root "$(printf 'b%.0s' $(seq 64))" --out-dir "${WORK}/swap" \
    > "${WORK}/neg9.log" 2>&1
[ $? -ne 0 ] && ok "swapped keys are refused rather than silently adapted" \
             || bad "swapped keys were accepted"

python3 tools/xrom_sign_ota.py --ed25519-key "${WORK}/ed.pem" --rsa-key "${WORK}/rsa2048.pem" \
    --package "${WORK}/package.zip" --url "https://update.xrom.example/x.zip" \
    --security-version 9 --build-fingerprint "a/1" --target-fingerprint "a/0" \
    --hashtree-root "$(printf 'b%.0s' $(seq 64))" --out-dir "${WORK}/weak" \
    > "${WORK}/neg10.log" 2>&1
[ $? -ne 0 ] && ok "a 2048-bit RSA key is refused for OTA signing" \
             || bad "a 2048-bit RSA key was accepted"
grep -q "at least 4096" "${WORK}/neg10.log" && ok "and says why" || bad "no reason given"

python3 tools/xrom_sign_ota.py --ed25519-key "${WORK}/ed.pem" --rsa-key "${WORK}/rsa.pem" \
    --package "${WORK}/package.zip" --url "https://update.xrom.example@evil.example/x.zip" \
    --security-version 9 --build-fingerprint "a/1" --target-fingerprint "a/0" \
    --hashtree-root "$(printf 'b%.0s' $(seq 64))" --out-dir "${WORK}/userinfo" \
    > "${WORK}/neg11.log" 2>&1
[ $? -ne 0 ] && ok "a URL with userinfo is refused" || bad "a userinfo URL was accepted"

python3 tools/xrom_sign_ota.py --ed25519-key "${WORK}/ed.pem" --rsa-key "${WORK}/rsa.pem" \
    --package "${WORK}/package.zip" --url "https://140.82.121.4/x.zip" \
    --security-version 9 --build-fingerprint "a/1" --target-fingerprint "a/0" \
    --hashtree-root "$(printf 'b%.0s' $(seq 64))" --out-dir "${WORK}/ipliteral" \
    > "${WORK}/neg12.log" 2>&1
[ $? -ne 0 ] && ok "an IP-literal URL is refused (no subject name to pin a certificate to)" \
             || bad "an IP-literal URL was accepted"

echo
echo "=== 7. no private key reaches the repository ==="
if git status --porcelain | grep -q "\.pem"; then
    bad "a .pem file appeared in the working tree"
else
    ok "no .pem file was written into the repository"
fi

echo
echo "OTA signing round trip: ${PASSED} passed, ${FAILED} failed"
if [ "${FAILED}" -ne 0 ]; then
    echo "OTA SIGNING ROUND TRIP FAILED"
    exit 1
fi
echo "OTA SIGNING ROUND TRIP PASSED"
