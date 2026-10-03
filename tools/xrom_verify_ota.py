#!/usr/bin/env python3
#
# Copyright (C) 2026 The X-ROM Project
# SPDX-License-Identifier: Apache-2.0
#
# Verifies a signed update.json against the pinned OTA trust anchors.
#
# This is the host-side mirror of what xrom_ota_installer does on the device, and it
# exists so that a manifest can be checked before it is served rather than after a
# device has refused it. The authoritative implementation is the C++ one in
# common/ota/OtaVerifier.cpp; this script follows the same staged order and reports the
# same stage names, so that a refusal here and a refusal on a device read alike.
#
# It verifies BOTH signatures and requires them to come from two DISTINCT key ids. One
# key satisfying both algorithms is one key counted twice, and accepting it would make
# the dual-signature requirement a formality.

import argparse
import json
import os
import re
import subprocess
import sys
import time

FIELD_ORDER = [
    "manifest_version", "package_url", "package_sha256", "package_bytes",
    "security_version", "build_fingerprint", "target_fingerprint",
    "expected_hashtree_root_sha256", "min_battery_percent", "issued_at_unix",
    "not_after_unix", "updates_vault",
]

STAGES = ["manifest-signature", "manifest-format", "anti-rollback", "validity-window",
          "size-ceiling"]


def fail(stage, reason):
    print(f"REFUSED at {stage}: {reason}")
    return 1


def load_anchors(path):
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    anchors = []
    dropped = []
    for entry in data.get("anchors", []):
        key_id = entry.get("key_id", "")
        algorithm = entry.get("algorithm", "")
        if algorithm not in ("ED25519", "RSA4096_SHA256"):
            dropped.append(f"{key_id}: unknown algorithm {algorithm}")
            continue
        pem = entry.get("public_key", "")
        der = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "DER"],
                             input=pem.encode(), capture_output=True, check=False)
        if der.returncode != 0:
            dropped.append(f"{key_id}: public_key does not parse as a PEM public key")
            continue
        blob = der.stdout
        if algorithm == "ED25519":
            if len(blob) != 44 or blob[:12].hex() != "302a300506032b6570032100":
                dropped.append(f"{key_id}: not a 44-byte Ed25519 SubjectPublicKeyInfo")
                continue
        else:
            if bytes.fromhex("06092a864886f70d010101") not in blob:
                dropped.append(f"{key_id}: does not contain the rsaEncryption OID")
                continue
            match = re.search(rb"(\d+)\s*bit", subprocess.run(
                ["openssl", "pkey", "-pubin", "-noout", "-text"],
                input=pem.encode(), capture_output=True, check=True).stdout)
            if not match or int(match.group(1)) < 4096:
                bits = int(match.group(1)) if match else 0
                dropped.append(f"{key_id}: {bits}-bit RSA modulus, below the 4096 floor")
                continue
        anchors.append({
            "key_id": key_id,
            "algorithm": algorithm,
            "pem": pem,
            "enabled": entry.get("enabled", True),
            "min_security_version": entry.get("min_security_version", 0),
        })
    for reason in dropped:
        print(f"  dropped anchor: {reason}")
    if not any(a["enabled"] for a in anchors):
        raise SystemExit("no enabled anchor survived validation; nothing can be verified")
    return anchors


def find_anchor(anchors, key_id, algorithm):
    """Select by key_id AND algorithm. Either alone is a different and worse policy."""
    for anchor in anchors:
        if anchor["key_id"] == key_id and anchor["algorithm"] == algorithm:
            return anchor
    return None


def verify_signature(anchor, artifact: bytes, signature: bytes) -> str:
    """Returns '' on success, or a reason on failure."""
    import tempfile
    sig_fd, sig_path = tempfile.mkstemp(prefix="xrom-ota-sig-")
    key_fd, key_path = tempfile.mkstemp(prefix="xrom-ota-key-")
    art_fd, art_path = tempfile.mkstemp(prefix="xrom-ota-art-")
    try:
        with os.fdopen(sig_fd, "wb") as handle:
            handle.write(signature)
        with os.fdopen(key_fd, "w") as handle:
            handle.write(anchor["pem"])
        with os.fdopen(art_fd, "wb") as handle:
            handle.write(artifact)
        # The mirror of what xrom_sign_ota.py does, invocation for invocation: Ed25519
        # verifies the artifact directly with pkeyutl -rawin, RSA verifies with
        # `dgst -sha256 -verify`. Using pkeyutl for the RSA half would expect a
        # pre-computed digest as input and would not verify a signature made over raw
        # bytes.
        if anchor["algorithm"] == "ED25519":
            result = subprocess.run(
                ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", key_path,
                 "-rawin", "-in", art_path, "-sigfile", sig_path],
                capture_output=True, check=False)
            if result.returncode == 0 and b"Signature Verified Successfully" in result.stdout:
                return ""
        else:
            result = subprocess.run(
                ["openssl", "dgst", "-sha256", "-verify", key_path,
                 "-signature", sig_path, art_path],
                capture_output=True, check=False)
            if result.returncode == 0 and b"Verified OK" in result.stdout:
                return ""
        return (result.stdout + result.stderr).decode(errors="replace").strip() or "did not verify"
    finally:
        for path in (sig_path, key_path, art_path):
            if os.path.exists(path):
                os.unlink(path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--manifest", required=True, help="update.json")
    parser.add_argument("--signature-prefix", default=None,
                        help="prefix of the .sig files (default: the manifest path)")
    parser.add_argument("--trust", default="security/ota_trust/ota_trust_anchors.json")
    parser.add_argument("--installed-security-version", type=int, default=0)
    parser.add_argument("--running-fingerprint", default=None)
    parser.add_argument("--battery", type=int, default=100)
    parser.add_argument("--max-package-bytes", type=int, default=500 * 1024 * 1024)
    parser.add_argument("--now", type=int, default=None)
    parser.add_argument("--single-signature", action="store_true",
                        help="accept one signature instead of both (a deliberate weakening)")
    args = parser.parse_args()

    prefix = args.signature_prefix or args.manifest
    anchors = load_anchors(args.trust)
    print(f"loaded {len([a for a in anchors if a['enabled']])} enabled anchor(s) from {args.trust}")

    with open(args.manifest, "rb") as handle:
        artifact = handle.read()

    # --- stage 1: the signatures ------------------------------------------------
    satisfied = {}
    problems = []
    for name, algorithm, expected_len in (("ed25519", "ED25519", 64),
                                          ("rsa4096", "RSA4096_SHA256", 512)):
        path = f"{prefix}.{name}.sig"
        if not os.path.isfile(path):
            problems.append(f"no {algorithm} signature at {path}")
            continue
        raw = bytes.fromhex(open(path, encoding="utf-8").read().strip())
        if len(raw) != expected_len:
            problems.append(f"{path} holds {len(raw)} bytes, a {algorithm} signature is "
                            f"{expected_len}")
            continue
        # The key id is taken from the anchors that match the algorithm, because the
        # signature file does not carry it. With more than one anchor per algorithm this
        # becomes a trial over candidates, which is what the on-device verifier does too
        # when the manifest's neighbour files do not name the key.
        matched = None
        for anchor in anchors:
            if anchor["algorithm"] != algorithm or not anchor["enabled"]:
                continue
            reason = verify_signature(anchor, artifact, raw)
            if reason == "":
                matched = anchor
                break
        if matched is None:
            problems.append(f"the {algorithm} signature did not verify under any pinned anchor")
            continue
        satisfied[algorithm] = matched
        print(f"  {algorithm}: verified under {matched['key_id']}")

    dual = not args.single_signature
    if dual and len(satisfied) < 2:
        return fail("manifest-signature",
                    "dual signature is required but " +
                    ("neither signature verified" if not satisfied else
                     f"only {'/'.join(satisfied)} verified; " + "; ".join(problems)))
    if not dual and not satisfied:
        return fail("manifest-signature", "no signature verified; " + "; ".join(problems))
    if args.single_signature:
        print("  WARNING single-signature mode: this is a deliberate weakening, not a default")
    if len({a["key_id"] for a in satisfied.values()}) < len(satisfied):
        return fail("manifest-signature",
                    "both algorithms verified under the same key id, which is one key "
                    "counted twice rather than two independent signatures")

    # --- stage 2: format, and whether the file is what was signed ---------------
    try:
        manifest = json.loads(artifact.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        return fail("manifest-format", f"update.json is not valid JSON: {exc}")

    if list(manifest.keys()) != FIELD_ORDER:
        return fail("manifest-format",
                    "the field order does not match FIELD_ORDER, so the bytes on disk are "
                    "not the bytes OtaManifest::Serialize() would produce and the "
                    "signature covers an artifact the device will not reconstruct")
    reserialised = (json.dumps({k: manifest[k] for k in FIELD_ORDER}, indent=2,
                               sort_keys=False, ensure_ascii=True) + "\n").encode()
    if reserialised != artifact:
        return fail("manifest-format",
                    "re-serialising the parsed manifest does not reproduce the signed bytes")

    problems = []
    url = manifest["package_url"]
    if not url.startswith("https://"):
        problems.append("package_url must use https://")
    else:
        authority = url[len("https://"):].split("/", 1)[0]
        if "@" in authority:
            problems.append("package_url must not contain userinfo")
        host = authority.split(":", 1)[0]
        labels = host.split(".")
        if len(labels) < 2:
            problems.append("package_url host must be a dotted hostname")
        elif labels[-1].isdigit():
            problems.append("package_url host must not be an IP literal")
    for field in ("package_sha256", "expected_hashtree_root_sha256"):
        value = str(manifest[field])
        if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            problems.append(f"{field} must be 64 lowercase hex characters")
    if manifest["package_bytes"] <= 0:
        problems.append("package_bytes must be non-zero")
    if manifest["target_fingerprint"] == manifest["build_fingerprint"]:
        problems.append("target_fingerprint must differ from build_fingerprint")
    if manifest["not_after_unix"] <= manifest["issued_at_unix"]:
        problems.append("not_after_unix must be after issued_at_unix")
    if problems:
        return fail("manifest-format", "; ".join(problems))

    if args.running_fingerprint is not None and \
            manifest["target_fingerprint"] != args.running_fingerprint:
        return fail("manifest-format",
                    f"the package targets {manifest['target_fingerprint']} but the running "
                    f"build is {args.running_fingerprint}")

    # --- stage 3: anti-rollback, from the anchors, not the manifest -------------
    floor = max(a["min_security_version"] for a in satisfied.values())
    if manifest["security_version"] <= floor:
        return fail("anti-rollback",
                    f"security_version {manifest['security_version']} does not exceed the "
                    f"pinned floor {floor}")
    if manifest["security_version"] <= args.installed_security_version:
        return fail("anti-rollback",
                    f"security_version {manifest['security_version']} does not exceed the "
                    f"installed {args.installed_security_version}")

    # --- stage 4: the validity window -------------------------------------------
    now = args.now if args.now is not None else int(time.time())
    if now < manifest["issued_at_unix"]:
        return fail("validity-window", "the manifest claims to have been issued in the future")
    if now > manifest["not_after_unix"]:
        return fail("validity-window",
                    f"the manifest expired at {manifest['not_after_unix']} and it is {now}")

    # --- stage 5: the size ceiling and the battery floor -------------------------
    if manifest["package_bytes"] > args.max_package_bytes:
        return fail("size-ceiling",
                    f"the declared package is {manifest['package_bytes']} bytes, above the "
                    f"{args.max_package_bytes} ceiling; a device refuses this and falls back "
                    f"to the vault")
    if args.battery < manifest["min_battery_percent"]:
        return fail("size-ceiling",
                    f"battery {args.battery}% is below the required "
                    f"{manifest['min_battery_percent']}%")

    print(f"\nACCEPTED through {STAGES[-1]}")
    print(f"  package sha256    : {manifest['package_sha256']}")
    print(f"  declared size     : {manifest['package_bytes']} bytes")
    print(f"  security_version  : {manifest['security_version']} (floor {floor})")
    print(f"  hashtree root     : {manifest['expected_hashtree_root_sha256']}")
    print(f"  updates vault     : {manifest['updates_vault']}")
    print("\nThe remaining stages happen on the device: fetch, package-digest, install and")
    print("hashtree-root. This script cannot perform them, and a manifest that passes here")
    print("is authorised to be downloaded, not installed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
