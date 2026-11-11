"""Stable identifiers and hashes."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from typing import Any

_ID_SAFE = re.compile(r"[^a-zA-Z0-9_.:-]+")


def new_id(prefix: str) -> str:
    """Return a short, opaque identifier with a human-readable prefix."""
    clean = _ID_SAFE.sub("-", prefix.strip())[:24] or "id"
    return f"{clean}_{uuid.uuid4().hex}"


def new_event_id() -> str:
    return new_id("evt")


def stable_hash(value: Any, *, length: int = 64) -> str:
    """Hash arbitrary JSON-compatible data deterministically.

    The input is redacted by callers before hashing when it may contain
    secrets.  Hashing is only used for deduplication and integrity, never as a
    substitute for authenticated encryption.
    """
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
    except (TypeError, ValueError):
        encoded = repr(value).encode("utf-8", errors="replace")
    return hashlib.sha256(encoded).hexdigest()[:length]
