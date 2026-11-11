"""Authenticated checkpoint encryption.

Format v1 uses scrypt for key derivation and AES-256-GCM for authenticated
encryption.  The manifest is authenticated as additional data, so a checkpoint
cannot be silently re-labelled or have its counts changed.  The passphrase is
never persisted or logged.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from typing import Any

from ..common.errors import CheckpointError

FORMAT = "hermes-continuum-checkpoint"
FORMAT_VERSION = 1
MIN_PASSPHRASE_LENGTH = 8
MAX_PASSPHRASE_LENGTH = 1024
_KDF_N = 2**14
_KDF_R = 8
_KDF_P = 1
_SALT_BYTES = 16
_NONCE_BYTES = 12
_KEY_BYTES = 32


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(value: str, field: str) -> bytes:
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except Exception as exc:  # noqa: BLE001 - normalised below
        raise CheckpointError(f"Checkpoint field {field} is not valid base64.") from exc


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _aesgcm():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except Exception as exc:  # noqa: BLE001
        raise CheckpointError(
            "Checkpoint encryption requires the 'cryptography' package. "
            "Install the plugin's declared dependencies and try again."
        ) from exc
    return AESGCM


def _scrypt():
    try:
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    except Exception as exc:  # noqa: BLE001
        raise CheckpointError(
            "Checkpoint key derivation requires the 'cryptography' package."
        ) from exc
    return Scrypt


def validate_passphrase(passphrase: str) -> None:
    if not isinstance(passphrase, str) or not passphrase:
        raise CheckpointError("A checkpoint passphrase is required.")
    if len(passphrase) < MIN_PASSPHRASE_LENGTH:
        raise CheckpointError(
            f"Checkpoint passphrase must be at least {MIN_PASSPHRASE_LENGTH} characters."
        )
    if len(passphrase.encode("utf-8")) > MAX_PASSPHRASE_LENGTH:
        raise CheckpointError("Checkpoint passphrase is too long.")


def _derive_key(passphrase: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    validate_passphrase(passphrase)
    Scrypt = _scrypt()
    try:
        return Scrypt(salt=salt, length=_KEY_BYTES, n=n, r=r, p=p).derive(
            passphrase.encode("utf-8")
        )
    except Exception as exc:  # noqa: BLE001
        raise CheckpointError("Checkpoint key derivation failed.") from exc


def encrypt_bundle(
    manifest: dict[str, Any],
    payload: bytes,
    passphrase: str,
) -> dict[str, Any]:
    validate_passphrase(passphrase)
    if not isinstance(manifest, dict):
        raise CheckpointError("Checkpoint manifest must be an object.")
    salt = os.urandom(_SALT_BYTES)
    nonce = os.urandom(_NONCE_BYTES)
    key = _derive_key(passphrase, salt, _KDF_N, _KDF_R, _KDF_P)
    header: dict[str, Any] = {
        "format": FORMAT,
        "format_version": FORMAT_VERSION,
        "kdf": {
            "name": "scrypt",
            "n": _KDF_N,
            "r": _KDF_R,
            "p": _KDF_P,
            "salt_b64": _b64(salt),
        },
        "cipher": {
            "name": "AES-256-GCM",
            "nonce_b64": _b64(nonce),
        },
        "manifest": manifest,
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
    }
    AESGCM = _aesgcm()
    try:
        ciphertext = AESGCM(key).encrypt(nonce, payload, _canonical(header))
    except Exception as exc:  # noqa: BLE001
        raise CheckpointError("Checkpoint encryption failed.") from exc
    result = dict(header)
    result["ciphertext_b64"] = _b64(ciphertext)
    return result


def _validate_header(bundle: dict[str, Any]) -> tuple[dict[str, Any], bytes, bytes]:
    if not isinstance(bundle, dict):
        raise CheckpointError("Checkpoint bundle is not an object.")
    expected_keys = {
        "format",
        "format_version",
        "kdf",
        "cipher",
        "manifest",
        "payload_sha256",
        "ciphertext_b64",
    }
    if set(bundle.keys()) != expected_keys:
        raise CheckpointError("Checkpoint bundle has an unsupported shape.")
    if bundle.get("format") != FORMAT:
        raise CheckpointError("This file is not a Hermes Continuum checkpoint.")
    if int(bundle.get("format_version", 0)) != FORMAT_VERSION:
        raise CheckpointError(
            f"Checkpoint format version {bundle.get('format_version')!r} is not supported."
        )
    kdf = bundle.get("kdf")
    cipher = bundle.get("cipher")
    manifest = bundle.get("manifest")
    if not isinstance(kdf, dict) or not isinstance(cipher, dict) or not isinstance(manifest, dict):
        raise CheckpointError("Checkpoint header is malformed.")
    if set(kdf.keys()) != {"name", "n", "r", "p", "salt_b64"}:
        raise CheckpointError("Checkpoint KDF header is malformed.")
    if kdf.get("name") != "scrypt":
        raise CheckpointError("Unsupported checkpoint KDF.")
    try:
        n = int(kdf["n"])
        r = int(kdf["r"])
        p = int(kdf["p"])
    except (TypeError, ValueError) as exc:
        raise CheckpointError("Checkpoint KDF parameters are invalid.") from exc
    if not (2**12 <= n <= 2**17) or not (1 <= r <= 16) or not (1 <= p <= 4):
        raise CheckpointError("Checkpoint KDF parameters are outside safe bounds.")
    salt = _unb64(str(kdf["salt_b64"]), "kdf.salt_b64")
    if not 16 <= len(salt) <= 64:
        raise CheckpointError("Checkpoint salt length is invalid.")
    if set(cipher.keys()) != {"name", "nonce_b64"}:
        raise CheckpointError("Checkpoint cipher header is malformed.")
    if cipher.get("name") != "AES-256-GCM":
        raise CheckpointError("Unsupported checkpoint cipher.")
    nonce = _unb64(str(cipher["nonce_b64"]), "cipher.nonce_b64")
    if len(nonce) != _NONCE_BYTES:
        raise CheckpointError("Checkpoint nonce length is invalid.")
    payload_hash = bundle.get("payload_sha256")
    if not isinstance(payload_hash, str) or len(payload_hash) != 64:
        raise CheckpointError("Checkpoint payload hash is invalid.")
    return bundle, salt, nonce


def decrypt_bundle(bundle: dict[str, Any], passphrase: str) -> tuple[dict[str, Any], bytes]:
    validate_passphrase(passphrase)
    header, salt, nonce = _validate_header(bundle)
    kdf = header["kdf"]
    key = _derive_key(passphrase, salt, int(kdf["n"]), int(kdf["r"]), int(kdf["p"]))
    ciphertext = _unb64(str(header["ciphertext_b64"]), "ciphertext_b64")
    if len(ciphertext) < 16:
        raise CheckpointError("Checkpoint ciphertext is truncated.")
    authenticated = {
        "format": header["format"],
        "format_version": header["format_version"],
        "kdf": header["kdf"],
        "cipher": header["cipher"],
        "manifest": header["manifest"],
        "payload_sha256": header["payload_sha256"],
    }
    AESGCM = _aesgcm()
    try:
        payload = AESGCM(key).decrypt(nonce, ciphertext, _canonical(authenticated))
    except Exception as exc:  # noqa: BLE001 - InvalidTag and malformed inputs
        raise CheckpointError(
            "Checkpoint authentication failed: wrong passphrase or tampered bundle."
        ) from exc
    if hashlib.sha256(payload).hexdigest() != header["payload_sha256"]:
        raise CheckpointError("Checkpoint payload integrity check failed.")
    return header, payload


def bundle_bytes(bundle: dict[str, Any]) -> bytes:
    return json.dumps(
        bundle,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def parse_bundle_bytes(data: bytes) -> dict[str, Any]:
    try:
        parsed = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise CheckpointError("Checkpoint file is not valid JSON.") from exc
    if not isinstance(parsed, dict):
        raise CheckpointError("Checkpoint file is not an object.")
    return parsed


def file_checksum(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
