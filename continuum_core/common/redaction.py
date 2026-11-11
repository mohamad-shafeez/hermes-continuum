"""Best-effort redaction and minimisation.

This is a deterministic safety net, not a guarantee that arbitrary text can
never contain a secret.  Continuum therefore also avoids persisting full tool
results, commands and conversation transcripts.
"""

from __future__ import annotations

import json
import re
from typing import Any

_REDACTED = "[REDACTED]"

# Patterns that are precise enough to redact without destroying ordinary prose.
_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----", re.S),
        "[REDACTED_PRIVATE_KEY]",
    ),
    (re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_-]{12,}\b"), "[REDACTED_API_KEY]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"\bASIA[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/\-=]{8,}"), "Bearer [REDACTED]"),
    (
        re.compile(
            r"(?i)\b(api[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token|"
            r"client[_-]?secret|secret|password|passwd|pwd|authorization|cookie)"
            r"(\s*[:=]\s*)([\"']?)([^\s\"',;}{]{4,})\3"
        ),
        r"\1\2[REDACTED]",
    ),
    (
        re.compile(
            r"(?i)\b(OPENAI_API_KEY|ANTHROPIC_API_KEY|AWS_SECRET_ACCESS_KEY|"
            r"AWS_ACCESS_KEY_ID|GITHUB_TOKEN|GH_TOKEN|SLACK_TOKEN|"
            r"HERMES_[A-Z0-9_]*KEY|HERMES_[A-Z0-9_]*TOKEN)\s*=\s*[^\s\"']+"
        ),
        r"\1=[REDACTED]",
    ),
    (
        re.compile(
            r"(?i)([?&](?:token|key|api_key|access_token|secret|password)=)[^&\s\"']+"
        ),
        r"\1[REDACTED]",
    ),
)

_SENSITIVE_KEY_PARTS = (
    "token",
    "secret",
    "password",
    "passwd",
    "pwd",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "private_key",
    "client_secret",
    "credential",
    "session_key",
)

# A conservative canary check used to keep obvious credentials out of memory.
_SECRET_HINT = re.compile(
    r"(?i)(sk-(?:ant-)?[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{20,}|"
    r"AKIA[0-9A-Z]{16}|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|"
    r"bearer\s+[A-Za-z0-9._~+/\-=]{8,})"
)


def redact_text(value: Any, *, max_chars: int | None = None) -> str:
    """Return a redacted, optionally truncated string.

    Non-string values are converted with ``str``.  The result is always safe to
    persist as a preview; it is never used as an authorization decision.
    """
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    if max_chars is not None and len(text) > max_chars:
        text = text[: max(0, max_chars - 1)] + "…"
    return text


def contains_secret(value: Any) -> bool:
    """Return True when a string contains a high-confidence credential shape."""
    if value is None:
        return False
    text = value if isinstance(value, str) else str(value)
    return bool(_SECRET_HINT.search(text))


def truncate(value: str, max_chars: int) -> str:
    if max_chars <= 0:
        return ""
    if len(value) <= max_chars:
        return value
    return value[: max(0, max_chars - 1)] + "…"


def safe_preview(value: Any, *, max_chars: int = 240) -> Any:
    """Describe a value without persisting its full contents.

    Scalars are returned in a small typed envelope; containers expose only
    their type and shape.  This is used by observer hooks and audit records.
    """
    if isinstance(value, str):
        return {
            "type": "str",
            "length": len(value),
            "preview": redact_text(value, max_chars=max_chars),
        }
    if isinstance(value, (list, tuple, set)):
        return {"type": type(value).__name__, "length": len(value)}
    if isinstance(value, dict):
        return {
            "type": "dict",
            "keys": sorted(str(key) for key in value.keys())[:30],
            "length": len(value),
        }
    if isinstance(value, bool):
        return {"type": "bool", "value": value}
    if isinstance(value, (int, float)):
        return {"type": type(value).__name__, "value": value}
    if value is None:
        return {"type": "null"}
    return {
        "type": type(value).__name__,
        "preview": redact_text(value, max_chars=max_chars),
    }


def redact_mapping(
    value: Any,
    *,
    max_string: int = 500,
    max_items: int = 80,
    depth: int = 0,
) -> Any:
    """Recursively redact and minimise a mapping for storage or export.

    Sensitive keys are replaced entirely; strings are redacted and truncated;
    containers are bounded so a hostile tool result cannot grow the database
    without limit.
    """
    if depth > 8:
        return "[MAX_DEPTH]"
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= max_items:
                result["[TRUNCATED]"] = f"{len(value) - max_items} more keys"
                break
            key_text = str(key)
            lowered = key_text.lower()
            if any(part in lowered for part in _SENSITIVE_KEY_PARTS):
                result[key_text] = _REDACTED
            else:
                result[key_text] = redact_mapping(
                    item,
                    max_string=max_string,
                    max_items=max_items,
                    depth=depth + 1,
                )
        return result
    if isinstance(value, (list, tuple, set)):
        items = list(value)
        result_list = [
            redact_mapping(
                item,
                max_string=max_string,
                max_items=max_items,
                depth=depth + 1,
            )
            for item in items[:max_items]
        ]
        if len(items) > max_items:
            result_list.append(f"[TRUNCATED {len(items) - max_items} items]")
        return result_list
    if isinstance(value, str):
        return redact_text(value, max_chars=max_string)
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return redact_text(value, max_chars=max_string)


def json_preview(value: Any, *, max_chars: int = 1200) -> str:
    """Serialize a redacted value for a safe audit field."""
    try:
        text = json.dumps(redact_mapping(value), ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        text = redact_text(repr(value))
    return truncate(text, max_chars)
