#!/usr/bin/env python3
# Copyright (C) 2026 The X-ROM Project
# SPDX-License-Identifier: Apache-2.0
"""Sign and inspect X-ROM Microdroid payload manifests.

The daemon (services/avf/xrom_avfd/PayloadVerifier.cpp) refuses to launch a
payload whose manifest does not carry a valid signature from a key pinned in
trust_anchors.json. This tool is the other half of that arrangement: it is what
produces the manifest, the detached signature and the trust anchors.

WHY THE SIGNATURE IS DETACHED
-----------------------------
xrom_payload_manifest.sig signs the exact bytes of xrom_payload_manifest.json.
There is no canonicalisation step, so there is nothing for the signing tool and
the verifier to disagree about: the tool hashes what it wrote, and the verifier
verifies what it read. A JSON canonicalisation scheme (JCS, sorted-key
re-encoding) would put two independent serialisers on either side of a security
decision, and the difference between them would be the attack surface.

WHY THIS SHELLS OUT TO openssl
------------------------------
Asymmetric operations need a real implementation. Python's stdlib has hashlib
(SHA-256) but no Ed25519 or RSA signing, and the `cryptography` package is not a
build dependency of an Android tree. The openssl CLI is, so the asymmetric part
is delegated to it and the digest part stays in hashlib. Nothing here implements
a signature scheme.

USAGE
-----
    # one-time, offline, on a signing machine
    ./tools/xrom_sign_payload.py generate-keys --out-dir /secure/keys

    # at release time
    ./tools/xrom_sign_payload.py sign \\
        --apk out/target/product/x1/system_ext/app/XVaultPayload/XVaultPayload.apk \\
        --payload-lib out/.../libxvault_payload.so \\
        --vm-config device/x1/microdroid/xvault/assets/vm_config.json \\
        --key /secure/keys/xrom-payload-ed25519.pem \\
        --key-id xrom-payload-root-01 \\
        --task-classes 0,1 \\
        --security-version 1 \\
        --valid-days 365 \\
        --out-dir security/payload_trust/manifest

    # anywhere, no private key needed
    ./tools/xrom_verify_manifest.py --manifest ... --signature ... --anchors ...
"""

from __future__ import annotations

import argparse
import base64
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
TASK_CLASS_NAMES = {
    0: "STATIC_ANALYSIS",
    1: "INTEGRITY_CHECK",
    2: "ATTESTATION",
    3: "CRYPTO_OPERATION",
}


def die(message: str) -> "NoReturn":  # noqa: F821
    print(f"xrom_sign_payload: error: {message}", file=sys.stderr)
    raise SystemExit(1)


def run(cmd: list, **kwargs) -> subprocess.CompletedProcess:
    """Run a command, turning a failure into a readable error."""
    try:
        return subprocess.run(cmd, check=True, capture_output=True, text=True, **kwargs)
    except FileNotFoundError:
        die(f"{cmd[0]} not found on PATH")
    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or "").strip()
        die(f"{' '.join(cmd)} failed ({exc.returncode}): {stderr}")


def require_openssl() -> str:
    path = shutil.which("openssl")
    if path is None:
        die("openssl is required and was not found on PATH")
    version = run([path, "version"]).stdout.strip()
    # Ed25519 support landed in 1.1.1; anything older cannot sign for this tool.
    if " 1.0." in version or " 1.1.0" in version:
        die(f"{version} is too old: Ed25519 needs OpenSSL 1.1.1 or later")
    return path


def sha256_file(path: str) -> str:
    """SHA-256 of a file, streamed. Returns lowercase hex."""
    hasher = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


# DER prefixes, which identify a key unambiguously across OpenSSL versions.
# `openssl pkey -noout -text` prints "ED25519 Private-Key:" on 3.x and
# "Private-Key: (4096 bit, 2 primes)" for RSA — no algorithm name — so parsing
# that text would break on one version or the other.
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")  # id-Ed25519 SPKI
RSA_ENCRYPTION_OID = bytes.fromhex("06092a864886f70d010101")      # rsaEncryption


def public_key_der(openssl: str, key_path: str) -> bytes:
    """DER SubjectPublicKeyInfo. This is exactly what EVP_parse_public_key reads."""
    result = subprocess.run(
        [openssl, "pkey", "-in", key_path, "-pubout", "-outform", "DER"],
        capture_output=True,
    )
    if result.returncode != 0:
        die(f"{key_path} is not a readable PEM key: {result.stderr.decode(errors='replace').strip()}")
    return result.stdout


def public_key_der_base64(openssl: str, key_path: str) -> str:
    return base64.b64encode(public_key_der(openssl, key_path)).decode("ascii")


def rsa_key_bits(openssl: str, key_path: str) -> int:
    text = run([openssl, "pkey", "-in", key_path, "-noout", "-text"]).stdout
    for line in text.splitlines():
        if "Private-Key:" in line or "Public-Key:" in line:
            match = re.search(r"(\d+)\s*bit", line)
            if match:
                return int(match.group(1))
    return 0


def key_algorithm(openssl: str, key_path: str) -> str:
    """Ask the key what it is, rather than trusting a command-line flag."""
    der = public_key_der(openssl, key_path)
    if der.startswith(ED25519_SPKI_PREFIX) and len(der) == 44:
        return ED25519
    if RSA_ENCRYPTION_OID in der:
        bits = rsa_key_bits(openssl, key_path)
        # Refused here rather than silently accepted: the daemon enforces a
        # 4096-bit floor when it loads the anchor, and a manifest signed with a
        # shorter key would then be rejected at launch time on a device, which is
        # the most expensive possible moment to discover a policy violation.
        if bits < 4096:
            die(f"{key_path} is an RSA-{bits} key; the X-ROM policy minimum is 4096 bits")
        return RSA4096_SHA256
    die(f"{key_path} is neither Ed25519 nor RSA (SPKI is {len(der)} bytes)")
    return ""  # unreachable


def sign_bytes(openssl: str, key_path: str, algorithm: str, message: bytes) -> bytes:
    """Produce a raw signature over exactly these bytes.

    RSA uses `openssl dgst -sha256 -sign`, which is byte-identical to
    `pkeyutl -sign -rawin -digest sha256` and works on every OpenSSL since 1.0.
    Ed25519 has no digest step, so it goes through pkeyutl; the flag spelling
    changed between 1.1.1 (-raw) and 3.x (-rawin), so both are tried.
    """
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as handle:
        handle.write(message)
        message_path = handle.name
    try:
        if algorithm == RSA4096_SHA256:
            result = subprocess.run(
                [openssl, "dgst", "-sha256", "-sign", key_path, "-out", "/dev/stdout",
                 message_path],
                capture_output=True,
            )
            if result.returncode != 0:
                die(f"openssl could not sign with {key_path}: "
                    f"{result.stderr.decode(errors='replace').strip()}")
            return result.stdout

        if algorithm == ED25519:
            for flag in ("-rawin", "-raw"):
                result = subprocess.run(
                    [openssl, "pkeyutl", "-sign", "-inkey", key_path, flag, "-in", message_path],
                    capture_output=True,
                )
                if result.returncode == 0:
                    return result.stdout
            die(f"openssl could not produce an Ed25519 signature with {key_path}: "
                f"{result.stderr.decode(errors='replace').strip()}")

        die(f"unsupported algorithm {algorithm}")
        return b""
    finally:
        os.unlink(message_path)


def write_text(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)
    print(f"  wrote {path}")


# ---------------------------------------------------------------------------
# generate-keys
# ---------------------------------------------------------------------------


def cmd_generate_keys(args: argparse.Namespace) -> int:
    openssl = require_openssl()
    os.makedirs(args.out_dir, exist_ok=True)

    for name, generate in (
        (f"{args.prefix}-ed25519.pem", [openssl, "genpkey", "-algorithm", "ED25519"]),
        (f"{args.prefix}-rsa4096.pem",
         [openssl, "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:4096"]),
    ):
        private_path = os.path.join(args.out_dir, name)
        if os.path.exists(private_path) and not args.force:
            print(f"  {private_path} already exists; leaving it alone (use --force to replace)")
            continue
        der = subprocess.run(generate, check=True, capture_output=True).stdout
        with open(private_path, "wb") as handle:
            handle.write(der)
        os.chmod(private_path, 0o600)
        print(f"  wrote {private_path}")

        public_path = private_path.replace(".pem", ".pub.pem")
        pub_der = subprocess.run(
            [openssl, "pkey", "-in", private_path, "-pubout"], check=True, capture_output=True
        ).stdout
        with open(public_path, "wb") as handle:
            handle.write(pub_der)
        os.chmod(public_path, 0o644)
        print(f"  wrote {public_path}")

    print()
    print("The private keys are signing material. They belong on an offline machine")
    print("or in an HSM, never in the source tree, and never in a build artifact.")
    print("Only the *.pub.pem files are committed.")
    return 0


# ---------------------------------------------------------------------------
# sign
# ---------------------------------------------------------------------------


def cmd_sign(args: argparse.Namespace) -> int:
    openssl = require_openssl()

    for path in (args.apk, args.payload_lib, args.vm_config, args.key):
        if not os.path.isfile(path):
            die(f"{path} does not exist or is not a file")

    algorithm = args.algorithm
    if algorithm == "auto":
        algorithm = key_algorithm(openssl, args.key)
    elif key_algorithm(openssl, args.key) != algorithm:
        die(f"--algorithm {algorithm} does not match {args.key}, which is "
            f"{key_algorithm(openssl, args.key)}")

    try:
        classes = sorted({int(value) for value in args.task_classes.split(",") if value != ""})
    except ValueError:
        die("--task-classes must be a comma separated list of integers")
    for value in classes:
        if value not in TASK_CLASS_NAMES:
            die(f"task class {value} is not one of {sorted(TASK_CLASS_NAMES)}")
    if not classes:
        die("--task-classes must name at least one class; a payload authorised for "
            "nothing cannot run anything")

    apk_digest = sha256_file(args.apk)
    lib_digest = sha256_file(args.payload_lib)
    config_digest = sha256_file(args.vm_config)

    issued_at = int(args.issued_at if args.issued_at else time.time())
    not_after = issued_at + args.valid_days * 86400
    if not_after <= issued_at:
        die("not_after must be after issued_at")

    manifest = {
        "manifest_version": MANIFEST_VERSION,
        "payload_name": args.payload_name,
        "payload_apk_filename": os.path.basename(args.apk),
        "apk_sha256": apk_digest,
        "payload_library": os.path.basename(args.payload_lib),
        "payload_lib_sha256": lib_digest,
        "vm_config_sha256": config_digest,
        "allowed_task_classes": classes,
        "security_version": args.security_version,
        "signature_algorithm": algorithm,
        "key_id": args.key_id,
        "issued_at_unix": issued_at,
        "not_after_unix": not_after,
    }

    # json.dumps with a fixed key order and indent. Whatever bytes this writes are
    # the bytes that get signed, so the ordering is part of the artifact and must
    # not depend on dict iteration or locale.
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=False, ensure_ascii=True) + "\n")
    signature = sign_bytes(openssl, args.key, algorithm, manifest_bytes.encode("utf-8"))

    out_dir = args.out_dir
    manifest_path = os.path.join(out_dir, args.manifest_name)
    signature_path = os.path.join(out_dir, args.manifest_name + ".sig")
    write_text(manifest_path, manifest_bytes)
    write_text(signature_path, base64.b64encode(signature).decode("ascii") + "\n")

    print()
    print(f"  algorithm        {algorithm}")
    print(f"  key id           {args.key_id}")
    print(f"  signature        {len(signature)} bytes")
    print(f"  apk_sha256       {apk_digest}")
    print(f"  payload_lib      {lib_digest}")
    print(f"  vm_config        {config_digest}")
    print(f"  task classes     {classes} "
          f"({', '.join(TASK_CLASS_NAMES[c] for c in classes)})")
    print(f"  valid            {time.strftime('%Y-%m-%d', time.gmtime(issued_at))} .. "
          f"{time.strftime('%Y-%m-%d', time.gmtime(not_after))}")
    print()
    print("Add the corresponding trust anchor with the `anchor` subcommand, then")
    print("verify the pair with tools/xrom_verify_manifest.py before shipping.")
    return 0


# ---------------------------------------------------------------------------
# anchor
# ---------------------------------------------------------------------------


def cmd_anchor(args: argparse.Namespace) -> int:
    openssl = require_openssl()
    if not os.path.isfile(args.key):
        die(f"{args.key} does not exist")

    algorithm = key_algorithm(openssl, args.key)
    entry = {
        "key_id": args.key_id,
        "algorithm": algorithm,
        "public_key_base64": public_key_der_base64(openssl, args.key),
        "min_security_version": args.min_security_version,
        "enabled": True,
        "description": args.description or f"X-ROM payload signing key {args.key_id}",
    }

    anchors = {"trust_anchors": []}
    if os.path.isfile(args.out):
        with open(args.out, "r", encoding="utf-8") as handle:
            anchors = json.load(handle)
        if not isinstance(anchors.get("trust_anchors"), list):
            die(f"{args.out} does not contain a trust_anchors array")

    existing = [a for a in anchors["trust_anchors"] if a.get("key_id") == args.key_id]
    if existing:
        if not args.force:
            die(f"an anchor with key_id {args.key_id!r} already exists in {args.out} "
                f"(use --force to replace it)")
        anchors["trust_anchors"] = [
            a for a in anchors["trust_anchors"] if a.get("key_id") != args.key_id
        ]
    anchors["trust_anchors"].append(entry)

    write_text(args.out, json.dumps(anchors, indent=2) + "\n")
    print()
    print(f"  anchor {args.key_id}: {algorithm}, "
          f"min_security_version={args.min_security_version}")
    print("  The private key was not read for anything beyond deriving the public")
    print("  half; only the public key is written into the anchor file.")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)

    keys = sub.add_parser("generate-keys", help="create a new Ed25519 and RSA-4096 key pair")
    keys.add_argument("--out-dir", required=True, help="directory for the key files")
    keys.add_argument("--prefix", default="xrom-payload", help="file name prefix")
    keys.add_argument("--force", action="store_true", help="replace existing keys")
    keys.set_defaults(func=cmd_generate_keys)

    sign = sub.add_parser("sign", help="hash the payload artifacts and sign a manifest")
    sign.add_argument("--apk", required=True, help="the built payload APK")
    sign.add_argument("--payload-lib", required=True, help="the built payload .so")
    sign.add_argument("--vm-config", required=True, help="assets/vm_config.json source")
    sign.add_argument("--key", required=True, help="private key (PEM)")
    sign.add_argument("--key-id", required=True, help="must match a trust anchor key_id")
    sign.add_argument("--algorithm", default="auto",
                      choices=["auto", ED25519, RSA4096_SHA256])
    sign.add_argument("--payload-name", default="xvault")
    sign.add_argument("--task-classes", default="0,1",
                      help="comma separated TaskClass values this payload may serve")
    sign.add_argument("--security-version", type=int, default=1)
    sign.add_argument("--valid-days", type=int, default=365)
    sign.add_argument("--issued-at", type=int, default=0,
                      help="UNIX timestamp; defaults to now")
    sign.add_argument("--out-dir", required=True)
    sign.add_argument("--manifest-name", default="xrom_payload_manifest.json")
    sign.set_defaults(func=cmd_sign)

    anchor = sub.add_parser("anchor", help="add or replace an entry in trust_anchors.json")
    anchor.add_argument("--key", required=True, help="public or private key (PEM)")
    anchor.add_argument("--key-id", required=True)
    anchor.add_argument("--min-security-version", type=int, default=0)
    anchor.add_argument("--description", default="")
    anchor.add_argument("--out", required=True, help="trust_anchors.json to update")
    anchor.add_argument("--force", action="store_true")
    anchor.set_defaults(func=cmd_anchor)

    return parser


def main(argv: list) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
