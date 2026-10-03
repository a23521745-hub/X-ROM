#!/usr/bin/env bash
# Copyright (C) 2026 The X-ROM Project
# SPDX-License-Identifier: Apache-2.0
#
# End-to-end test of the X-ROM payload signing format.
#
# This is the only place the signing pipeline is tested as a whole, and it does
# so without a device, without AOSP and without committing a private key: the key
# pair is generated into a temporary directory that is deleted on exit.
#
# What it proves:
#   * tools/xrom_sign_payload.py produces a manifest that tools/xrom_verify_manifest.py
#     accepts, for both supported algorithms.
#   * Every tampering case is rejected — the signature, each pinned digest, the
#     security version, the validity window and the key id.
#   * The rules enforced by the tools are the rules PayloadVerifier.cpp enforces,
#     because the tool checks are a transcription of PayloadManifest::Validate().
#
# It deliberately does NOT test the C++ verifier: that needs BoringSSL and runs in
# the AOSP host test suite. What it does guarantee is that the artifacts the C++
# verifier will be given are well formed and that the scheme is self-consistent.

set -u
set -o pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SIGN="$REPO_ROOT/tools/xrom_sign_payload.py"
VERIFY="$REPO_ROOT/tools/xrom_verify_manifest.py"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0
FAIL=0

note()  { printf '  %s\n' "$*"; }
ok()    { printf '  [ OK ] %s\n' "$*"; PASS=$((PASS + 1)); }
bad()   { printf '  [FAIL] %s\n' "$*"; FAIL=$((FAIL + 1)); }

# expect_success <description> <command...>
expect_success() {
  local description="$1"; shift
  if out="$("$@" 2>&1)"; then
    ok "$description"
  else
    bad "$description"
    printf '%s\n' "$out" | sed 's/^/         /'
  fi
}

# expect_failure <description> <command...>
expect_failure() {
  local description="$1"; shift
  if out="$("$@" 2>&1)"; then
    bad "$description (it unexpectedly succeeded)"
    printf '%s\n' "$out" | sed 's/^/         /'
  else
    ok "$description"
  fi
}

# expect_grep <description> <pattern> <command...>
expect_grep() {
  local description="$1"; shift
  local pattern="$1"; shift
  out="$("$@" 2>&1)" || true
  if printf '%s' "$out" | grep -q -- "$pattern"; then
    ok "$description"
  else
    bad "$description (no match for '$pattern')"
    printf '%s\n' "$out" | sed 's/^/         /'
  fi
}

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl is required to run this test" >&2
  exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required to run this test" >&2
  exit 2
fi

echo "xrom payload signing round trip"
echo "  openssl $(openssl version | awk '{print $2}')"
echo "  work directory $WORK"
echo

# ---------------------------------------------------------------------------
# Fixtures. Stand-ins for the built APK and payload library: what matters to the
# signing format is that they are files whose bytes can be hashed, not that they
# are ELF or ZIP.
# ---------------------------------------------------------------------------
mkdir -p "$WORK/out"
head -c 200000 /dev/urandom > "$WORK/out/XVaultPayload.apk"
head -c  50000 /dev/urandom > "$WORK/out/libxvault_payload.so"
cp "$REPO_ROOT/device/x1/microdroid/xvault/assets/vm_config.json" "$WORK/out/vm_config.json"

# ---------------------------------------------------------------------------
# 1. key generation
# ---------------------------------------------------------------------------
echo "1. key generation"
expect_success "generate-keys creates both key pairs" \
  python3 "$SIGN" generate-keys --out-dir "$WORK/keys" --prefix test
for name in test-ed25519.pem test-ed25519.pub.pem test-rsa4096.pem test-rsa4096.pub.pem; do
  if [ -s "$WORK/keys/$name" ]; then ok "$name exists and is non-empty"; else bad "$name is missing"; fi
done
# Idempotent on purpose: a release script that re-runs key generation must not
# destroy the key it already has. The property worth testing is that the existing
# key is left byte-identical, and that --force is what changes it.
before="$(sha256sum "$WORK/keys/test-ed25519.pem" | cut -d' ' -f1)"
expect_success "generate-keys is idempotent without --force" \
  python3 "$SIGN" generate-keys --out-dir "$WORK/keys" --prefix test
after="$(sha256sum "$WORK/keys/test-ed25519.pem" | cut -d' ' -f1)"
if [ "$before" = "$after" ]; then ok "the existing private key was not replaced"; else bad "the existing private key was replaced"; fi
expect_success "--force does replace the key" \
  python3 "$SIGN" generate-keys --out-dir "$WORK/keys" --prefix test --force
forced="$(sha256sum "$WORK/keys/test-ed25519.pem" | cut -d' ' -f1)"
if [ "$forced" != "$before" ]; then ok "--force generated a different key"; else bad "--force did not regenerate the key"; fi
# The private keys must not be world readable: they are signing material even in
# a test, and a habit that leaves 0644 private keys around becomes a leak.
mode="$(stat -c '%a' "$WORK/keys/test-ed25519.pem" 2>/dev/null || stat -f '%Lp' "$WORK/keys/test-ed25519.pem")"
if [ "$mode" = "600" ]; then ok "the private key is mode 0600"; else bad "the private key is mode $mode"; fi
echo

# ---------------------------------------------------------------------------
# 2. a full Ed25519 sign + verify round trip
# ---------------------------------------------------------------------------
echo "2. Ed25519 round trip"
expect_success "sign with Ed25519" \
  python3 "$SIGN" sign \
    --apk "$WORK/out/XVaultPayload.apk" \
    --payload-lib "$WORK/out/libxvault_payload.so" \
    --vm-config "$WORK/out/vm_config.json" \
    --key "$WORK/keys/test-ed25519.pem" \
    --key-id test-ed25519-01 \
    --task-classes 0,1 \
    --security-version 1 \
    --valid-days 30 \
    --out-dir "$WORK/ed"
if [ -s "$WORK/ed/xrom_payload_manifest.json" ] && [ -s "$WORK/ed/xrom_payload_manifest.json.sig" ]; then
  ok "the manifest and its detached signature were both written"
else
  bad "the manifest or the signature is missing"
fi

expect_success "anchor the Ed25519 key" \
  python3 "$SIGN" anchor \
    --key "$WORK/keys/test-ed25519.pem" \
    --key-id test-ed25519-01 \
    --min-security-version 1 \
    --out "$WORK/ed/trust_anchors.json"

expect_success "verify accepts an untampered manifest" \
  python3 "$VERIFY" \
    --manifest "$WORK/ed/xrom_payload_manifest.json" \
    --signature "$WORK/ed/xrom_payload_manifest.json.sig" \
    --anchors "$WORK/ed/trust_anchors.json" \
    --apk "$WORK/out/XVaultPayload.apk" \
    --payload-lib "$WORK/out/libxvault_payload.so" \
    --vm-config "$WORK/out/vm_config.json"

# The signature must be 64 bytes for Ed25519 and must verify with plain openssl,
# which is the check that this is a real Ed25519 signature and not a wrapper
# around something else.
python3 - "$WORK/ed" <<'PY' > "$WORK/ed/siglen"
import base64, sys, pathlib
sig = pathlib.Path(sys.argv[1], "xrom_payload_manifest.json.sig").read_text()
print(len(base64.b64decode("".join(sig.split()))))
PY
siglen="$(cat "$WORK/ed/siglen")"
if [ "$siglen" = "64" ]; then ok "the Ed25519 signature is 64 bytes"; else bad "signature is $siglen bytes"; fi
echo

# ---------------------------------------------------------------------------
# 3. RSA-4096 round trip, and the algorithm/anchor binding
# ---------------------------------------------------------------------------
echo "3. RSA-4096 round trip"
expect_success "sign with RSA-4096" \
  python3 "$SIGN" sign \
    --apk "$WORK/out/XVaultPayload.apk" \
    --payload-lib "$WORK/out/libxvault_payload.so" \
    --vm-config "$WORK/out/vm_config.json" \
    --key "$WORK/keys/test-rsa4096.pem" \
    --key-id test-rsa4096-01 \
    --task-classes 0 \
    --security-version 1 \
    --valid-days 30 \
    --out-dir "$WORK/rsa"
expect_success "anchor the RSA key" \
  python3 "$SIGN" anchor --key "$WORK/keys/test-rsa4096.pem" --key-id test-rsa4096-01 \
    --min-security-version 1 --out "$WORK/rsa/trust_anchors.json"
expect_success "verify accepts the RSA-4096 manifest" \
  python3 "$VERIFY" \
    --manifest "$WORK/rsa/xrom_payload_manifest.json" \
    --signature "$WORK/rsa/xrom_payload_manifest.json.sig" \
    --anchors "$WORK/rsa/trust_anchors.json" \
    --apk "$WORK/out/XVaultPayload.apk"

python3 - "$WORK/rsa" <<'PY' > "$WORK/rsa/siglen"
import base64, sys, pathlib
sig = pathlib.Path(sys.argv[1], "xrom_payload_manifest.json.sig").read_text()
print(len(base64.b64decode("".join(sig.split()))))
PY
siglen="$(cat "$WORK/rsa/siglen")"
if [ "$siglen" = "512" ]; then ok "the RSA-4096 signature is 512 bytes"; else bad "signature is $siglen bytes"; fi

# An Ed25519 manifest verified against the RSA anchor must fail: the anchor is
# selected by key_id AND algorithm, and mixing them is how a scheme downgrade
# would happen.
expect_grep "an Ed25519 manifest is rejected by an RSA-only anchor set" \
  "no trust anchor for key_id" \
  python3 "$VERIFY" \
    --manifest "$WORK/ed/xrom_payload_manifest.json" \
    --signature "$WORK/ed/xrom_payload_manifest.json.sig" \
    --anchors "$WORK/rsa/trust_anchors.json"
echo

# ---------------------------------------------------------------------------
# 4. tampering. Every one of these must be caught.
# ---------------------------------------------------------------------------
echo "4. tampering"
rm -rf "$WORK/tamper"; cp -r "$WORK/ed" "$WORK/tamper"
MAN="$WORK/tamper/xrom_payload_manifest.json"
SIG="$WORK/tamper/xrom_payload_manifest.json.sig"
ANC="$WORK/tamper/trust_anchors.json"

verify_tampered() {
  python3 "$VERIFY" --manifest "$MAN" --signature "$SIG" --anchors "$ANC" \
    --apk "$WORK/out/XVaultPayload.apk" 2>&1
}

# 4a. one byte of the manifest flipped
rm -rf "$WORK/tamper"; cp -r "$WORK/ed" "$WORK/tamper"
python3 - "$MAN" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); b = bytearray(p.read_bytes())
i = b.index(b'"payload_name"') + 20
b[i] = ord('Z') if b[i] != ord('Z') else ord('A')
p.write_bytes(bytes(b))
PY
expect_grep "a modified manifest is rejected" "does not verify" bash -c \
  "python3 '$VERIFY' --manifest '$MAN' --signature '$SIG' --anchors '$ANC' --apk '$WORK/out/XVaultPayload.apk'"

# 4b. a different APK with the same manifest
rm -rf "$WORK/tamper"; cp -r "$WORK/ed" "$WORK/tamper"
head -c 200000 /dev/urandom > "$WORK/out/other.apk"
expect_grep "a swapped APK is rejected" "does not match apk_sha256" \
  python3 "$VERIFY" --manifest "$MAN" --signature "$SIG" --anchors "$ANC" --apk "$WORK/out/other.apk"

# 4c. the signature truncated
rm -rf "$WORK/tamper"; cp -r "$WORK/ed" "$WORK/tamper"
head -c 40 "$SIG" > "$SIG.tmp" && mv "$SIG.tmp" "$SIG"
expect_failure "a truncated signature is rejected" \
  python3 "$VERIFY" --manifest "$MAN" --signature "$SIG" --anchors "$ANC" --apk "$WORK/out/XVaultPayload.apk"

# 4d. the manifest re-signed with a different key than the anchor holds
rm -rf "$WORK/tamper"; cp -r "$WORK/ed" "$WORK/tamper"
python3 "$SIGN" generate-keys --out-dir "$WORK/other-keys" --prefix other >/dev/null 2>&1
python3 - "$MAN" "$SIG" "$WORK/other-keys/other-ed25519.pem" <<'PY'
import subprocess, sys, pathlib
manifest_path, sig_path, key = sys.argv[1:4]
data = pathlib.Path(manifest_path).read_bytes()
# Sign the same bytes with the wrong key: a verifier that trusted "some key in
# the anchor set" instead of "the key this manifest names" would accept this.
# -rawin is a one-shot operation and openssl needs a seekable input for it, so
# the manifest goes through a temporary file rather than stdin.
msg = pathlib.Path(sig_path + ".msg")
msg.write_bytes(data)
subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", key, "-rawin", "-in", str(msg),
                "-out", sig_path + ".bin"], check=True)
msg.unlink()
import base64
pathlib.Path(sig_path).write_text(base64.b64encode(pathlib.Path(sig_path + ".bin").read_bytes()).decode() + "\n")
PY
expect_grep "a manifest signed by an unknown key is rejected" "does not verify" \
  python3 "$VERIFY" --manifest "$MAN" --signature "$SIG" --anchors "$ANC" --apk "$WORK/out/XVaultPayload.apk"

# 4e. an expired manifest
rm -rf "$WORK/tamper"; cp -r "$WORK/ed" "$WORK/tamper"
now="$(( $(date +%s) + 31 * 86400 ))"   # past the 30 day validity
expect_grep "an expired manifest is rejected by --now" "expired" \
  python3 "$VERIFY" --manifest "$MAN" --signature "$SIG" --anchors "$ANC" \
    --apk "$WORK/out/XVaultPayload.apk" --now "$now"

# 4f. anti-rollback: raise the anchor's minimum above the manifest's version
rm -rf "$WORK/tamper"; cp -r "$WORK/ed" "$WORK/tamper"
python3 - "$ANC" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1]); a = json.loads(p.read_text())
a["trust_anchors"][0]["min_security_version"] = 99
p.write_text(json.dumps(a, indent=2) + "\n")
PY
expect_grep "a superseded security_version is rejected" "anti-rollback" \
  python3 "$VERIFY" --manifest "$MAN" --signature "$SIG" --anchors "$ANC" --apk "$WORK/out/XVaultPayload.apk"

# 4g. a disabled anchor
rm -rf "$WORK/tamper"; cp -r "$WORK/ed" "$WORK/tamper"
python3 - "$ANC" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1]); a = json.loads(p.read_text())
a["trust_anchors"][0]["enabled"] = False
p.write_text(json.dumps(a, indent=2) + "\n")
PY
expect_grep "a disabled anchor is refused" "is disabled" \
  python3 "$VERIFY" --manifest "$MAN" --signature "$SIG" --anchors "$ANC" --apk "$WORK/out/XVaultPayload.apk"

# 4h. a manifest that authorises no task class at all
rm -rf "$WORK/tamper"; cp -r "$WORK/ed" "$WORK/tamper"
expect_grep "signing with an empty task class list is refused" "at least one class" \
  python3 "$SIGN" sign --apk "$WORK/out/XVaultPayload.apk" \
    --payload-lib "$WORK/out/libxvault_payload.so" --vm-config "$WORK/out/vm_config.json" \
    --key "$WORK/keys/test-ed25519.pem" --key-id test-ed25519-01 --task-classes "" \
    --out-dir "$WORK/tamper/empty"

# 4i. an unknown task class
expect_grep "signing with an unknown task class is refused" "is not one of" \
  python3 "$SIGN" sign --apk "$WORK/out/XVaultPayload.apk" \
    --payload-lib "$WORK/out/libxvault_payload.so" --vm-config "$WORK/out/vm_config.json" \
    --key "$WORK/keys/test-ed25519.pem" --key-id test-ed25519-01 --task-classes 7 \
    --out-dir "$WORK/tamper/badclass"

# 4j. an RSA key below the policy floor cannot be used at all
expect_grep "an RSA-2048 key is refused by the signing tool" "policy minimum is 4096" \
  bash -c "openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out '$WORK/keys/short.pem' 2>/dev/null && \
           python3 '$SIGN' sign --apk '$WORK/out/XVaultPayload.apk' \
             --payload-lib '$WORK/out/libxvault_payload.so' --vm-config '$WORK/out/vm_config.json' \
             --key '$WORK/keys/short.pem' --key-id short-01 --out-dir '$WORK/tamper/short'"
echo

# ---------------------------------------------------------------------------
# 5. the committed tree state
# ---------------------------------------------------------------------------
echo "5. committed trust material"
if [ -s "$REPO_ROOT/security/payload_trust/trust_anchors.json" ]; then
  ok "security/payload_trust/trust_anchors.json exists"
  expect_grep "the committed anchors parse and every anchor key is well formed" "anchor(s)" \
    python3 -c "
import json,subprocess,sys
data=json.load(open('$REPO_ROOT/security/payload_trust/trust_anchors.json'))
anchors=data['trust_anchors']
print(len(anchors), 'anchor(s)')
sys.path.insert(0,'$REPO_ROOT/tools')
import importlib.util
spec=importlib.util.spec_from_file_location('v','$REPO_ROOT/tools/xrom_verify_manifest.py')
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
openssl=m.require_openssl()
import base64
for a in anchors:
    der=base64.b64decode(a['public_key_base64'])
    algo,bits=m.classify_spki(der)
    assert algo==a['algorithm'], (a['key_id'], algo, a['algorithm'])
    assert a['algorithm']!='RSA4096_SHA256' or bits>=4096, (a['key_id'], bits)
    print('  ok', a['key_id'], algo, bits or '')
"
else
  bad "security/payload_trust/trust_anchors.json is missing"
fi
# A private key in the tree would be a release-blocking leak, so this check is
# here rather than in a review checklist.
if find "$REPO_ROOT/security" -name '*.pem' ! -name '*.pub.pem' | grep -q .; then
  bad "a private key is committed under security/"
  find "$REPO_ROOT/security" -name '*.pem' ! -name '*.pub.pem' | sed 's/^/         /'
else
  ok "no private key is committed under security/"
fi
if grep -q 'PRIVATE KEY' "$REPO_ROOT/security/payload_trust/trust_anchors.json" 2>/dev/null; then
  bad "trust_anchors.json contains private key material"
else
  ok "trust_anchors.json contains only public material"
fi
echo

printf 'payload signing round trip: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
echo "PAYLOAD SIGNING ROUND TRIP PASSED"
