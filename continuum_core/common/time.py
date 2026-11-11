"""UTC time helpers.

Every persisted timestamp is an ISO-8601 UTC string with a ``Z`` suffix.  Using
one representation keeps SQLite range queries predictable and makes checkpoint
manifests portable.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    return utc_now().isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_utc(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def utc_minus_days(days: int) -> str:
    return (utc_now() - timedelta(days=max(0, int(days)))).isoformat(
        timespec="milliseconds"
    ).replace("+00:00", "Z")
