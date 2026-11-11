"""Small, provenance-aware recall injection.

Only confirmed facts are presented as established.  Candidates are explicitly
labelled unverified.  The function is deliberately bounded and never depends on
an unverified session-finalisation return channel.
"""

from __future__ import annotations

from typing import Any

from ..common.config import ContinuumConfig
from ..common.redaction import truncate
from ..spine.store import SpineStore


class RecallService:
    def __init__(self, store: SpineStore, config: ContinuumConfig | None = None):
        self.store = store
        self.config = (config or ContinuumConfig()).clamped()

    def build_context(
        self,
        user_message: Any,
        *,
        session_id: str | None = None,
    ) -> str | None:
        query = _text(user_message)
        facts = self.store.recall_candidates(
            query=query,
            limit=self.config.recall_limit,
            include_candidates=True,
        )
        resume = self.store.active_resume_brief()
        include_resume = bool(
            resume
            and resume.get("active")
            and resume.get("last_injected_session") != (session_id or "")
        )
        if not facts and not include_resume:
            return None
        lines: list[str] = ["[Hermes Continuum recall]"]
        if include_resume and resume is not None:
            lines.append(
                "Resume brief (imported checkpoint; no external actions were replayed):"
            )
            lines.append(truncate(str(resume.get("brief") or ""), 700))
        confirmed = [
            fact
            for fact in facts
            if fact.get("status") == "confirmed" and not fact.get("superseded_by")
        ]
        candidates = [fact for fact in facts if fact.get("status") == "candidate"]
        if confirmed:
            lines.append("Established memory (confirmed):")
            for fact in confirmed:
                lines.append(_format_fact(fact, confirmed=True))
        if candidates:
            lines.append("Unverified candidates (do not treat as established fact):")
            for fact in candidates:
                lines.append(_format_fact(fact, confirmed=False))
        lines.append("[End Continuum recall]")
        text = "\n".join(lines)
        if len(text) > self.config.max_recall_chars:
            # Keep the header, resume, and confirmed facts; drop candidates
            # before truncating so an unverified note never crowds out a
            # confirmed fact.
            compact: list[str] = ["[Hermes Continuum recall]"]
            if include_resume and resume is not None:
                compact.append(
                    "Resume brief (imported checkpoint; no external actions were replayed):"
                )
                compact.append(truncate(str(resume.get("brief") or ""), 700))
            if confirmed:
                compact.append("Established memory (confirmed):")
                compact.extend(_format_fact(fact, confirmed=True) for fact in confirmed)
            compact.append("[End Continuum recall]")
            text = "\n".join(compact)
        text = truncate(text, self.config.max_recall_chars)
        if include_resume and resume is not None:
            self.store.mark_resume_injected(resume["id"], session_id or "")
        return text

    def recall(self, query: str, *, limit: int | None = None) -> list[dict[str, Any]]:
        return self.store.recall_candidates(
            query=query,
            limit=limit or self.config.recall_limit,
            include_candidates=True,
        )


def _format_fact(fact: dict[str, Any], *, confirmed: bool) -> str:
    key = str(fact.get("fact_key") or "note")
    value = str(fact.get("value") or "")
    provenance = str(fact.get("provenance") or "UNKNOWN")
    observed = str(fact.get("first_observed_utc") or "")[:10]
    confidence = float(fact.get("confidence") or 0.0)
    label = "confirmed" if confirmed else "UNVERIFIED CANDIDATE"
    return (
        f"- {key}: {value} — {label}; source: {provenance}; "
        f"observed: {observed}; confidence: {confidence:.2f}"
    )


def _text(message: Any) -> str:
    if message is None:
        return ""
    if isinstance(message, str):
        return message
    if isinstance(message, (list, tuple)):
        parts: list[str] = []
        for item in message:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                text = item.get("text") or item.get("content")
                if isinstance(text, str):
                    parts.append(text)
        return "\n".join(parts)
    if isinstance(message, dict):
        text = message.get("text") or message.get("content")
        if isinstance(text, str):
            return text
    return str(message)
