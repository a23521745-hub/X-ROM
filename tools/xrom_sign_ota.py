#!/usr/bin/env python3
#
# Copyright (C) 2026 The X-ROM Project
# SPDX-License-Identifier: Apache-2.0
#
# Signs an OTA manifest with BOTH pinned keys and writes the detached signatures.
#
# THE SERIALISED MANIFEST IS THE SIGNED ARTIFACT
# ----------------------------------------------
# There is no canonicalisation step, and that is deliberate. update.json is signed
# exactly as it is written to disk, byte for byte, and the verifier re-serialises what
# it parsed and compares against those bytes. Any scheme where the signer and the
# verifier each decide which fields are covered, in what order, with what whitespace, is
# a scheme where the two can agree to disagree without either one being obviously
# broken.
#
# That makes the field order and the exact JSON formatting part of the artifact. This
# script and OtaManifest::Serialize() in common/ota/OtaManifest.cpp must produce
# identical bytes, and tools/tests/ota_signing_roundtrip.sh fails if they ever diverge.
# If you add a field, you add it to BOTH, in the same position, or every signature
# already issued stops verifying.
#
# WHY BOTH SIGNATURES, EVERY TIME
# -------------------------------
# require_dual_signature defaults to on, so a manifest signed with one key will be
# refused by the verifier. Signing both here is not convenience: a signing tool that
# could produce a single-signature manifest would be a tool that could produce a manifest
# the device accepts under a weaker policy than the one shipped.
#
# No private key is ever written into this repository. The keys are named on the command
# line and tools/xrom_preflight.py fails the build if a private key appears under
# security/.

import argparse
import json
import os
import subprocess
import sys
import time

# The field order is the artifact. Do not reorder, do not sort, do not add without also
# adding to OtaManifest::Serialize().
FIELD_ORDER = [
    "manifest_version",
    "package_url",
    "package_sha256",
    "package_bytes",
    "security_version",
    "build_fingerprint",
    "target_fingerprint",
    "expected_hashtree_root_sha256",
    "min_battery_percent",
    "issued_at_unix",
    "not_after_unix",
    "updates_vault",
]

MANIFEST_VERSION = 1
MAX_VALIDITY_DAYS = 366


def serialise(manifest: dict) -> bytes:
    """Produce the exact bytes that get signed.

    indent=2 with json.dumps defaults to separators (',', ': '), which is what
    OtaManifest::Serialize() emits: two-space indent, ", " between members after a
    newline, ": " between key and value, and a trailing newline after the closing brace.
    """
    ordered = {key: manifest[key] for key in FIELD_ORDER}
    missing = [key for key in FIELD_ORDER if key not in manifest]
    if missing:
        raise SystemExit(f"manifest is missing required fields: {', '.join(missing)}")
    extra = [key for key in manifest if key not in FIELD_ORDER]
    if extra:
        # Rejected rather than dropped. A field this script silently ignored would be a
        # field the signer thought was covered by the signature and the verifier never
        # looked at.
        raise SystemExit(f"manifest has fields not in FIELD_ORDER: {', '.join(extra)}")
    return (json.dumps(ordered, indent=2, sort_keys=False, ensure_ascii=True) + "\n").encode()


def validate(manifest: dict) -> None:
    """Mirror the checks in common/ota/OtaManifest.cpp Validate().

    Duplicated on purpose: the tool must refuse to produce an artifact the device will
    refuse to accept, and discovering that after the keys have been used is a wasted
    ceremony. The authoritative copy is the C++ one, and the round-trip test compares
    their behaviour on the same inputs.
    """
    problems = []
    if manifest["manifest_version"] != MANIFEST_VERSION:
        problems.append(f"manifest_version must be {MANIFEST_VERSION}")
    url = manifest["package_url"]
    if not url.startswith("https://"):
        problems.append("package_url must use https://")
    else:
        authority = url[len("https://"):].split("/", 1)[0]
        if "@" in authority:
            problems.append("package_url must not contain userinfo")
        host = authority.split(":", 1)[0]
        if ":" in authority and authority.split(":", 1)[1] not in ("443",):
            problems.append("package_url must use port 443")
        labels = host.split(".")
        if len(labels) < 2 or any(not label or len(label) > 63 for label in labels):
            problems.append("package_url host must be a dotted hostname")
        elif labels[-1].isdigit():
            problems.append("package_url host must not end in an all-numeric label "
                            "(an IP literal has no subject name to pin a certificate to)")
        elif any(label.startswith("-") or label.endswith("-") for label in labels):
            problems.append("package_url host labels must not start or end with '-'")
        if "/" not in url[len("https://"):]:
            problems.append("package_url must include a path")
        if ".." in url:
            problems.append("package_url must not contain '..'")
    for field in ("package_sha256", "expected_hashtree_root_sha256"):
        value = manifest[field]
        if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            problems.append(f"{field} must be 64 lowercase hex characters")
    if manifest["package_bytes"] <= 0:
        problems.append("package_bytes must be non-zero")
    if manifest["target_fingerprint"] == manifest["build_fingerprint"]:
        problems.append("target_fingerprint must differ from build_fingerprint")
    if not 0 <= manifest["min_battery_percent"] <= 100:
        problems.append("min_battery_percent must be 0..100")
    if manifest["issued_at_unix"] <= 0 or manifest["not_after_unix"] <= 0:
        problems.append("issued_at_unix and not_after_unix must be positive")
    elif manifest["not_after_unix"] <= manifest["issued_at_unix"]:
        problems.append("not_after_unix must be after issued_at_unix")
    elif manifest["not_after_unix"] - manifest["issued_at_unix"] > MAX_VALIDITY_DAYS * 86400:
        problems.append(f"the validity window exceeds {MAX_VALIDITY_DAYS} days")
    if problems:
        for problem in problems:
            print(f"  ERROR {problem}", file=sys.stderr)
        raise SystemExit(f"{len(problems)} problem(s); refusing to sign")


def sha256_file(path: str) -> str:
    import hashlib
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sign(private_key: str, artifact: bytes, algorithm: str) -> bytes:
    """Produce a detached signature with the openssl CLI.

    The openssl CLI rather than a Python crypto binding, because the binding is not
    guaranteed present and a signing tool that silently produces nothing when its
    dependency is missing is worse than one that fails loudly.
    """
    if not os.path.isfile(private_key):
        raise SystemExit(f"private key not found: {private_key}")
    # TWO DIFFERENT OPENSSL INVOCATIONS, AND MIXING THEM UP FAILS LOUDLY BUT LATELY.
    #
    # Ed25519 is a single-shot scheme and signs the artifact directly: pkeyutl -rawin
    # with no digest. openssl 3.x spells it -rawin where 1.1.1 used -raw.
    #
    # RSA cannot use the same shape. `pkeyutl -sign -pkeyopt digest:sha256` expects its
    # input to ALREADY BE a 32-byte digest, and handing it a manifest produces
    # "The input data looks too long to be a hash". Signing raw bytes with RSA and
    # SHA-256 is `dgst -sha256 -sign`, which hashes and signs in one step. This is the
    # same invocation tools/xrom_sign_payload.py already uses for payload manifests, so
    # the two signing tools agree and one recipe does not have to be remembered twice.
    if algorithm not in ("ED25519", "RSA4096_SHA256"):
        raise SystemExit(f"unsupported algorithm: {algorithm}")

    import tempfile
    artifact_path = signature_path = None
    try:
        handle, artifact_path = tempfile.mkstemp(prefix="xrom-ota-art-")
        with os.fdopen(handle, "wb") as stream:
            stream.write(artifact)

        if algorithm == "ED25519":
            # -rawin cannot read non-seekable stdin, so the artifact goes through a
            # temporary file rather than a pipe.
            result = subprocess.run(
                ["openssl", "pkeyutl", "-sign", "-inkey", private_key, "-rawin",
                 "-in", artifact_path],
                capture_output=True, check=False)
            if result.returncode != 0:
                raise SystemExit(f"openssl failed for {algorithm}: "
                                 f"{result.stderr.decode(errors='replace').strip()}")
            return result.stdout

        handle, signature_path = tempfile.mkstemp(prefix="xrom-ota-sig-")
        os.close(handle)
        result = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", private_key,
             "-out", signature_path, artifact_path],
            capture_output=True, check=False)
        if result.returncode != 0:
            raise SystemExit(f"openssl failed for {algorithm}: "
                             f"{result.stderr.decode(errors='replace').strip()}")
        with open(signature_path, "rb") as stream:
            return stream.read()
    finally:
        for path in (artifact_path, signature_path):
            if path and os.path.exists(path):
                os.unlink(path)


def key_algorithm(private_key: str) -> str:
    """Determine the key type from its DER, not from its filename."""
    result = subprocess.run(["openssl", "pkey", "-in", private_key, "-pubout", "-outform", "DER"],
                            capture_output=True, check=False)
    if result.returncode != 0:
        raise SystemExit(f"cannot read {private_key}: "
                         f"{result.stderr.decode(errors='replace').strip()}")
    der = result.stdout
    # Ed25519 SPKI is a fixed 44 bytes with a fixed prefix. Anything else is not an
    # Ed25519 public key whatever the file was called.
    if len(der) == 44 and der[:12].hex() == "302a300506032b6570032100":
        return "ED25519"
    if bytes.fromhex("06092a864886f70d010101") in der:
        # The modulus size is checked rather than trusted: 2048-bit RSA is what openssl
        # produces by default and it is exactly the mistake this check catches.
        text = subprocess.run(["openssl", "pkey", "-in", private_key, "-noout", "-text"],
                              capture_output=True, check=True).stdout.decode()
        import re
        match = re.search(r"(\d+)\s*bit", text)
        if not match:
            raise SystemExit(f"cannot determine the modulus size of {private_key}")
        bits = int(match.group(1))
        if bits < 4096:
            raise SystemExit(f"{private_key} is a {bits}-bit RSA key; OTA signing "
                             f"requires at least 4096")
        return "RSA4096_SHA256"
    raise SystemExit(f"{private_key} is neither Ed25519 nor RSA")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--ed25519-key", required=True, help="private Ed25519 PEM")
    parser.add_argument("--rsa-key", required=True, help="private RSA-4096 PEM")
    parser.add_argument("--package", required=True, help="the OTA package to be shipped")
    parser.add_argument("--url", required=True, help="https:// URL the package will be served from")
    parser.add_argument("--security-version", type=int, required=True)
    parser.add_argument("--build-fingerprint", required=True, help="fingerprint this package produces")
    parser.add_argument("--target-fingerprint", required=True, help="fingerprint it applies to")
    parser.add_argument("--hashtree-root", required=True,
                        help="64-hex vbmeta hashtree root of the resulting image")
    parser.add_argument("--min-battery", type=int, default=30)
    parser.add_argument("--valid-days", type=int, default=90)
    parser.add_argument("--no-vault", action="store_true",
                        help="this package must not be written to the vault")
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--now", type=int, default=None, help="override issued_at_unix (testing)")
    args = parser.parse_args()

    package_bytes = os.path.getsize(args.package)
    issued = args.now if args.now is not None else int(time.time())

    manifest = {
        "manifest_version": MANIFEST_VERSION,
        "package_url": args.url,
        "package_sha256": sha256_file(args.package),
        "package_bytes": package_bytes,
        "security_version": args.security_version,
        "build_fingerprint": args.build_fingerprint,
        "target_fingerprint": args.target_fingerprint,
        "expected_hashtree_root_sha256": args.hashtree_root.lower(),
        "min_battery_percent": args.min_battery,
        "issued_at_unix": issued,
        "not_after_unix": issued + args.valid_days * 86400,
        "updates_vault": not args.no_vault,
    }
    validate(manifest)

    artifact = serialise(manifest)
    os.makedirs(args.out_dir, exist_ok=True)
    manifest_path = os.path.join(args.out_dir, "update.json")
    with open(manifest_path, "wb") as handle:
        handle.write(artifact)

    signatures = {}
    for flag, path in (("ED25519", args.ed25519_key), ("RSA4096_SHA256", args.rsa_key)):
        detected = key_algorithm(path)
        if detected != flag:
            # Refusing rather than adapting. A key handed to the wrong flag is almost
            # always a copy-paste error, and signing anyway produces a signature pair
            # that looks complete and verifies under the wrong anchor.
            raise SystemExit(f"{path} is a {detected} key but was passed as the {flag} key")
        raw = sign(path, artifact, flag)
        expected = 64 if flag == "ED25519" else 512
        if len(raw) != expected:
            raise SystemExit(f"{flag} signature is {len(raw)} bytes, expected {expected}")
        # Explicit names, not a derivation from the algorithm string. The previous
        # version lower-cased the algorithm and substituted the digest suffix, which
        # turned RSA4096_SHA256 into "rsa40964096" — a file the verifier never looks
        # for, so every manifest signed by this tool was missing half its signature pair
        # and was refused at the signature stage for a reason that looked like a bad key.
        filename = {"ED25519": "update.json.ed25519.sig",
                    "RSA4096_SHA256": "update.json.rsa4096.sig"}[flag]
        out = os.path.join(args.out_dir, filename)
        with open(out, "w") as handle:
            handle.write(raw.hex() + "\n")
        signatures[flag] = (out, raw.hex())
        print(f"  signed {flag}: {out} ({len(raw)} bytes)")

    print(f"\nwrote {manifest_path} ({len(artifact)} bytes)")
    print(f"package sha256 : {manifest['package_sha256']}")
    print(f"package size   : {package_bytes} bytes")
    print(f"valid          : {issued} .. {manifest['not_after_unix']}")
    print("\nShip all three files together. A manifest without both signatures is")
    print("refused by the verifier, and the refusal does not say which one is missing")
    print("unless the log is read.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
