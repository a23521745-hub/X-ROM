#!/usr/bin/env python3
# Copyright (C) 2026 The X-ROM Project
# SPDX-License-Identifier: Apache-2.0
"""Verify an X-ROM payload manifest exactly the way xrom_avfd does.

This is the host-side gate from services/avf/xrom_avfd/PayloadVerifier.cpp,
reimplemented against the openssl CLI so that it can run on a build machine, in
CI, or against a device pulled with `adb pull`. It exists for two reasons:

  * A release can be checked before it reaches a device. A manifest that will be
    rejected at launch is much cheaper to find here.
  * It is an independent second implementation of the same rules. When the two
    agree, a failure on-device points at the device's state rather than at the
    format. When they disagree, one of them has a bug, and this script is the
    one that is easy to read.

The checks run in the same order as the daemon's, and each one reports rather
than stops: an operator fixing a release wants the whole list of problems.

    ./tools/xrom_verify_manifest.py \\
        --manifest   security/payload_trust/manifest/xrom_payload_manifest.json \\
        --signature  security/payload_trust/manifest/xrom_payload_manifest.json.sig \\
        --anchors    security/payload_trust/trust_anchors.json \\
        --apk        out/target/product/x1/system_ext/app/XVaultPayload/XVaultPayload.apk

Exit status is 0 only when every applicable check passes.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

MANIFEST_VERSION = 1
ED25519 = "ED25519"
RSA4096_SHA256 = "RSA4096_SHA256"
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
RSA_ENCRYPTION_OID = bytes.fromhex("06092a864886f70d010101")
MIN_RSA_BITS = 4096
MAX_MANIFEST_BYTES = 64 * 1024
MAX_SIGNATURE_BYTES = 1024
MAX_PUBLIC_KEY_BYTES = 1024
TASK_CLASS_NAMES = {0: "STATIC_ANALYSIS", 1: "INTEGRITY_CHECK", 2: "ATTESTATION",
                    3: "CRYPTO_OPERATION"}


class Report:
    """Collects pass/fail/warn lines so that nothing stops at the first error."""

    def __init__(self) -> None:
        self.lines: list = []
        self.failures = 0
        self.warnings = 0

    def ok(self, message: str) -> None:
        self.lines.append(("PASS", message))

    def fail(self, message: str) -> None:
        self.lines.append(("FAIL", message))
        self.failures += 1

    def warn(self, message: str) -> None:
        self.lines.append(("WARN", message))
        self.warnings += 1

    def info(self, message: str) -> None:
        self.lines.append(("    ", message))

    def emit(self) -> int:
        for status, message in self.lines:
            print(f"  [{status}] {message}")
        print()
        print(f"  {self.failures} failure(s), {self.warnings} warning(s)")
        return 1 if self.failures else 0


def require_openssl() -> str:
    path = shutil.which("openssl")
    if path is None:
        print("error: openssl is required and was not found on PATH", file=sys.stderr)
        raise SystemExit(2)
    return path


def read_capped(path: str, limit: int, report: Report) -> bytes | None:
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        report.fail(f"cannot stat {path}: {exc}")
        return None
    if size > limit:
        report.fail(f"{path} is {size} bytes, over the {limit} byte limit")
        return None
    with open(path, "rb") as handle:
        return handle.read()


def sha256_file(path: str) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def decode_base64(text: str) -> bytes | None:
    """Base64 with whitespace stripped, matching the daemon's DecodeBase64."""
    compact = "".join(ch for ch in text if ch not in "\n\r \t")
    try:
        return base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError):
        return None


def write_spki_to_temp(der: bytes) -> str:
    handle = tempfile.NamedTemporaryFile(suffix=".der", delete=False)
    handle.write(der)
    handle.close()
    return handle.name


def classify_spki(der: bytes) -> tuple:
    """Return (algorithm, rsa_bits_or_zero) from a DER SubjectPublicKeyInfo."""
    if der.startswith(ED25519_SPKI_PREFIX) and len(der) == 44:
        return ED25519, 0
    if RSA_ENCRYPTION_OID in der:
        # Bit length is in the BIT STRING-wrapped RSAPublicKey; openssl reports it
        # without us having to parse ASN.1 by hand.
        path = write_spki_to_temp(der)
        try:
            pem_path = path + ".pem"
            subprocess.run(["openssl", "pkey", "-pubin", "-inform", "DER", "-in", path,
                            "-out", pem_path], check=True, capture_output=True)
            text = subprocess.run(["openssl", "pkey", "-pubin", "-in", pem_path, "-noout",
                                   "-text"], check=True, capture_output=True,
                                  text=True).stdout
            bits = 0
            for line in text.splitlines():
                if "Public-Key:" in line or "Private-Key:" in line:
                    match = re.search(r"(\d+)\s*bit", line)
                    if match:
                        bits = int(match.group(1))
                        break
            os.unlink(pem_path)
            return RSA4096_SHA256, bits
        except subprocess.CalledProcessError:
            return RSA4096_SHA256, 0
        finally:
            os.unlink(path)
    return "UNKNOWN", 0


def verify_signature(openssl: str, algorithm: str, spki_der: bytes, manifest: bytes,
                     signature: bytes) -> tuple:
    """Return (verified, detail). Mirrors PayloadVerifier::VerifySignature."""
    pub_path = write_spki_to_temp(spki_der)
    msg_path = write_spki_to_temp(manifest)
    sig_path = write_spki_to_temp(signature)
    try:
        if algorithm == ED25519:
            for flag in ("-rawin", "-raw"):
                result = subprocess.run(
                    [openssl, "pkeyutl", "-verify", "-pubin", "-inkey", pub_path, flag,
                     "-in", msg_path, "-sigfile", sig_path],
                    capture_output=True, text=True)
                if result.returncode == 0:
                    return True, "signature verified"
                if "Unknown option" not in (result.stderr or ""):
                    return False, (result.stderr or result.stdout or "").strip()
            return False, "openssl accepted neither -rawin nor -raw"
        if algorithm == RSA4096_SHA256:
            result = subprocess.run(
                [openssl, "dgst", "-sha256", "-verify", pub_path, "-signature", sig_path,
                 msg_path], capture_output=True, text=True)
            if result.returncode == 0:
                return True, "signature verified"
            return False, (result.stderr or result.stdout or "").strip()
        return False, f"unsupported algorithm {algorithm}"
    finally:
        for path in (pub_path, msg_path, sig_path):
            os.unlink(path)


def check_structure(manifest: dict, report: Report, now: int) -> None:
    """PayloadManifest::Validate(), rule for rule."""
    def need(condition: bool, message: str) -> None:
        if condition:
            report.ok(message)
        else:
            report.fail(message)

    need(manifest.get("manifest_version") == MANIFEST_VERSION,
         f"manifest_version is {MANIFEST_VERSION}")
    name = manifest.get("payload_name", "")
    need(isinstance(name, str) and 1 <= len(name) <= 64, "payload_name is 1..64 characters")
    for key in ("payload_apk_filename", "payload_library"):
        value = manifest.get(key, "")
        bad = (not isinstance(value, str) or not value or len(value) > 128 or
               value.startswith(".") or ".." in value or
               any(ch in value for ch in "/\\:*") or
               any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value))
        need(not bad, f"{key} is a plain file name with no separators or traversal")
    need(manifest.get("signature_algorithm") in (ED25519, RSA4096_SHA256),
         f"signature_algorithm is {manifest.get('signature_algorithm')!r}")
    key_id = manifest.get("key_id", "")
    need(isinstance(key_id, str) and 1 <= len(key_id) <= 64, "key_id is 1..64 characters")

    for digest_key in ("apk_sha256", "vm_config_sha256", "payload_lib_sha256"):
        value = manifest.get(digest_key, "")
        good = isinstance(value, str) and len(value) == 64
        if good:
            try:
                decoded = bytes.fromhex(value)
                good = decoded != b"\x00" * 32
            except ValueError:
                good = False
        need(good, f"{digest_key} is 64 hex characters and not all zeroes")

    classes = manifest.get("allowed_task_classes", [])
    need(isinstance(classes, list) and len(classes) > 0,
         "allowed_task_classes is a non-empty list")
    if isinstance(classes, list) and classes:
        need(len(classes) <= 16, "allowed_task_classes has at most 16 entries")
        need(len(set(classes)) == len(classes), "allowed_task_classes has no duplicates")
        need(all(isinstance(c, int) and c in TASK_CLASS_NAMES for c in classes),
             "every allowed task class is a known TaskClass")
        report.info("classes: " + ", ".join(
            f"{c}={TASK_CLASS_NAMES.get(c, '?')}" for c in sorted(set(classes))))

    need(isinstance(manifest.get("security_version"), int) and
         manifest["security_version"] >= 0, "security_version is a non-negative integer")
    issued = manifest.get("issued_at_unix", 0)
    expires = manifest.get("not_after_unix", 0)
    need(isinstance(issued, int) and isinstance(expires, int) and issued > 0 and expires > 0,
         "issued_at_unix and not_after_unix are positive timestamps")
    need(isinstance(expires, int) and isinstance(issued, int) and expires > issued,
         "not_after_unix is after issued_at_unix")

    if isinstance(issued, int) and isinstance(expires, int) and issued > 0:
        if now < issued:
            report.fail(f"manifest is not valid yet (issued_at_unix is {issued - now}s in the "
                        f"future); check the signing machine's clock")
        elif now >= expires:
            report.fail(f"manifest expired {now - expires}s ago")
        else:
            days_left = (expires - now) // 86400
            report.ok(f"manifest is inside its validity window ({days_left} day(s) left)")
            if days_left < 30:
                report.warn("the manifest expires in under 30 days; re-sign before release")


def main(argv: list) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--signature", required=True,
                        help="detached base64 signature; defaults to <manifest>.sig")
    parser.add_argument("--anchors", required=True, help="trust_anchors.json")
    parser.add_argument("--apk", help="recompute sha256 over this APK and compare")
    parser.add_argument("--payload-lib", help="recompute sha256 over the built payload .so")
    parser.add_argument("--vm-config", help="recompute sha256 over assets/vm_config.json")
    parser.add_argument("--now", type=int, default=0,
                        help="override the current UNIX time (for testing expiry)")
    args = parser.parse_args(argv)

    openssl = require_openssl()
    report = Report()
    if args.now:
        print(f"  (using --now {args.now} instead of the system clock)")

    # --- anchors ---------------------------------------------------------
    anchor_bytes = read_capped(args.anchors, MAX_MANIFEST_BYTES, report)
    if anchor_bytes is None:
        return report.emit()
    try:
        anchors = json.loads(anchor_bytes)["trust_anchors"]
    except (ValueError, KeyError, TypeError) as exc:
        report.fail(f"{args.anchors} is not a trust_anchors file: {exc}")
        return report.emit()
    report.ok(f"{args.anchors} parsed, {len(anchors)} anchor(s)")

    # --- manifest and signature -----------------------------------------
    manifest_bytes = read_capped(args.manifest, MAX_MANIFEST_BYTES, report)
    signature_text = read_capped(args.signature, 2 * MAX_SIGNATURE_BYTES, report)
    if manifest_bytes is None or signature_text is None:
        return report.emit()
    try:
        manifest = json.loads(manifest_bytes)
    except ValueError as exc:
        report.fail(f"{args.manifest} is not valid JSON: {exc}")
        return report.emit()
    signature = decode_base64(signature_text.decode("utf-8", errors="replace"))
    if signature is None:
        report.fail(f"{args.signature} is not valid base64")
        return report.emit()
    if not signature or len(signature) > MAX_SIGNATURE_BYTES:
        report.fail(f"the decoded signature is {len(signature)} bytes, which is outside 1.."
                    f"{MAX_SIGNATURE_BYTES}")
        return report.emit()
    report.ok(f"signature is {len(signature)} bytes of valid base64")

    # --- select the anchor by id AND algorithm ---------------------------
    key_id = manifest.get("key_id")
    algorithm = manifest.get("signature_algorithm")
    match = None
    for anchor in anchors:
        if anchor.get("key_id") == key_id and anchor.get("algorithm") == algorithm:
            match = anchor
            break
    if match is None:
        report.fail(f"no trust anchor for key_id={key_id!r} algorithm={algorithm!r}")
        report.info("anchors present: " + ", ".join(
            f"{a.get('key_id')}/{a.get('algorithm')}" for a in anchors))
        return report.emit()
    if match.get("enabled") is False:
        report.fail(f"the anchor {key_id} is disabled")
        return report.emit()
    report.ok(f"anchor {key_id} ({algorithm}) found and enabled")

    der = decode_base64(match.get("public_key_base64", ""))
    if der is None or not der or len(der) > MAX_PUBLIC_KEY_BYTES:
        report.fail("the anchor's public_key_base64 is not a usable DER blob")
        return report.emit()
    detected, bits = classify_spki(der)
    if detected != algorithm:
        report.fail(f"the anchor declares {algorithm} but its key is {detected}")
        return report.emit()
    if algorithm == RSA4096_SHA256 and bits < MIN_RSA_BITS:
        report.fail(f"the anchor's RSA key is {bits} bits, below the {MIN_RSA_BITS} minimum")
        return report.emit()
    report.ok(f"the anchor's public key is a valid {algorithm} SubjectPublicKeyInfo"
              + (f" ({bits} bits)" if bits else ""))

    # --- the signature itself -------------------------------------------
    verified, detail = verify_signature(openssl, algorithm, der, manifest_bytes, signature)
    if verified:
        report.ok(f"the signature verifies over the {len(manifest_bytes)} manifest bytes")
    else:
        report.fail(f"the signature does not verify: {detail}")
        report.info("a signature that fails here but verifies on-device means the two files")
        report.info("were regenerated after signing; re-sign them together.")
        return report.emit()

    # --- structure, then the artifacts ----------------------------------
    now = args.now if args.now else int(time.time())
    check_structure(manifest, report, now)

    min_version = match.get("min_security_version", 0)
    security_version = manifest.get("security_version", 0)
    if isinstance(security_version, int) and isinstance(min_version, int):
        if security_version < min_version:
            report.fail(f"security_version {security_version} is below the {min_version} the "
                        f"anchor requires (anti-rollback)")
        else:
            report.ok(f"security_version {security_version} >= the anchor's {min_version}")

    for label, path, key in (("APK", args.apk, "apk_sha256"),
                             ("payload library", args.payload_lib, "payload_lib_sha256"),
                             ("vm_config.json", args.vm_config, "vm_config_sha256")):
        if not path:
            continue
        if not os.path.isfile(path):
            report.fail(f"the {label} at {path} does not exist")
            continue
        actual = sha256_file(path)
        pinned = manifest.get(key, "")
        if actual == pinned:
            report.ok(f"the {label} matches the pinned {key}")
        else:
            report.fail(f"the {label} does not match {key}")
            report.info(f"  pinned   {pinned}")
            report.info(f"  actual   {actual}")
        if label == "APK" and os.path.basename(path) != manifest.get("payload_apk_filename"):
            report.warn(f"the APK is named {os.path.basename(path)} but the manifest pins "
                        f"{manifest.get('payload_apk_filename')!r}")
    if not args.apk:
        report.warn("no --apk given: the digest that the daemon recomputes at launch time "
                    "was not checked")

    return report.emit()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
