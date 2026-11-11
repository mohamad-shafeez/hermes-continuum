"""Oneiros: provenance-aware, reviewable memory candidates.

Nothing extracted from a conversation is silently promoted to established
memory.  User corrections create a new versioned candidate and leave the older
version visible; confirmation is an explicit review action.
"""

from __future__ import annotations

import re
from typing import Any

from ..common.config import ContinuumConfig
from ..common.ids import stable_hash
from ..common.redaction import contains_secret, redact_text, truncate
from ..spine.store import SpineStore

_MEMORY_INTENT = re.compile(
    r"(?i)\b(remember|don't forget|do not forget|actually|correction|update:|"
    r"note that|from now on|going forward|"
    r"(?:i|we)\s+(?:prefer|like|use|always|never|work on)|"
    r"(?:our|my|this|the)\s+[A-Za-z0-9][A-Za-z0-9 ._/-]{1,60}?\s+"
    r"(?:is|are|uses|requires|deploys|runs))\b"
)
_PREFIXES = (
    "please remember that",
    "please remember",
    "remember that",
    "remember",
    "don't forget that",
    "don't forget",
    "do not forget that",
    "do not forget",
    "correction:",
    "correction",
    "actually,",
    "actually",
    "update:",
    "note that",
    "note:",
    "from now on,",
    "from now on",
    "going forward,",
    "going forward",
)
_STATEMENT = re.compile(
    r"(?i)^(?:this|the|our|my)\s+(?P<key>[A-Za-z0-9][A-Za-z0-9 ._/-]{1,60}?)\s+"
    r"(?P<verb>is|are|was|were|uses|use|requires|deploys|runs|happens|"
    r"is scheduled|are scheduled)\s+(?:on\s+|at\s+|in\s+)?(?P<value>.+)$"
)
_STATEMENT_BARE = re.compile(
    r"(?i)^(?!(?:i|we|you|they|he|she|it)\b)"
    r"(?P<key>[A-Za-z0-9][A-Za-z0-9 ._/-]{1,60}?)\s+"
    r"(?:is|are|uses|use|requires|deploys|runs)\s+(?P<value>.+)$"
)
_PREFERENCE = re.compile(
    r"(?i)^(?:i|we)\s+(?P<adv>prefer|like|use|work on|always|never)\s+"
    r"(?P<value>.+)$"
)
_FROM_NOW = re.compile(r"(?i)^(?:from now on|going forward)\s*[,:]?\s*(?P<value>.+)$")
_USE_PREFERENCE = re.compile(r"(?i)^(?:use|prefer)\s+(?P<value>.+)$")
_VALUE_LEADING_VERB = re.compile(r"(?i)^(?:use|using|prefer|preferring)\s+")
_NOT_VALUE = re.compile(r"(?i)(?:,\s*)?\bnot\s+(.+?)(?:[.;]|$)")
_INSTEAD_OF = re.compile(r"(?i)\binstead of\s+(.+?)(?:[.;]|$)")


def _normalise(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip()


def _strip_prefixes(text: str) -> str:
    result = _normalise(text).strip(" \t\"'`")
    changed = True
    while changed:
        changed = False
        lowered = result.lower()
        for prefix in _PREFIXES:
            if lowered.startswith(prefix):
                result = result[len(prefix) :].lstrip(" :,-")
                changed = True
                break
    return result.strip()


def _normalise_key(key: str) -> str:
    key = _normalise(key).lower().strip(" .,:;!?\"'`")
    key = re.sub(r"^(?:the|this|that|our|my|a|an)\s+", "", key)
    key = re.sub(r"\s+", " ", key).strip(" .,:;!?\"'`")
    return truncate(key or "note", 100)


def _split_old_value(value: str) -> tuple[str, str | None]:
    text = _normalise(value)
    match = _NOT_VALUE.search(text)
    if match and match.start() > 0:
        old = match.group(1).strip(" .,:;!?\"'`")
        new = text[: match.start()].strip(" ,;:.")
        if new:
            return new, old
    match = _INSTEAD_OF.search(text)
    if match:
        old = match.group(1).strip(" .,:;!?\"'`")
        new = text[: match.start()].strip(" ,;:.")
        if new:
            return new, old
    return text.strip(" .,:;!?\"'`"), None


def _preference_parts(text: str) -> tuple[str, str | None] | None:
    """Return ``(value, old_value)`` for a preference phrase, or ``None``."""

    match = _PREFERENCE.match(text)
    adverb = ""
    if match:
        adverb = match.group("adv").lower()
        raw = match.group("value")
    else:
        match = _USE_PREFERENCE.match(text)
        if match is None:
            return None
        raw = match.group("value")
    value, old_value = _split_old_value(raw)
    value = _VALUE_LEADING_VERB.sub("", value).strip()
    if adverb == "never":
        value = "not " + value
    return value, old_value


def _preference_key(value: str, old_value: str | None) -> str:
    """Derive a stable key per preference, not one shared "user preference".

    Unrelated preferences must not supersede each other.  A correction keeps the
    key of the value it corrects so the version chain stays intact.  Negation is
    removed from the key anchor because "never use tabs" and "use tabs" are the
    same subject with contradictory values, not two unrelated preferences.
    """

    anchor = _normalise(old_value or value).lower().strip(" .,:;!?\"'`")
    anchor = re.sub(r"(?i)^not\s+", "", anchor)
    anchor = truncate(anchor, 70).strip(" .,:;!?\"'`")
    return f"user preference: {anchor}" if anchor else "user preference"


def extract_fact_candidate(user_message: str) -> dict[str, Any] | None:
    """Extract a candidate fact from a user message, or return ``None``.

    This is intentionally conservative.  It never stores a value that looks like
    a credential, and it does not decide that a candidate is true.
    """
    original = _normalise(user_message)
    if not original or not _MEMORY_INTENT.search(original):
        return None
    if contains_secret(original):
        return None
    text = _strip_prefixes(original)
    if not text:
        return None
    lowered = original.lower()
    correction = bool(
        re.search(r"(?i)\b(?:actually|correction|instead of)\b", original)
        or re.search(r"(?i)\bnot\s+\S", original)
        or "from now on" in lowered
        or "going forward" in lowered
    )
    key = ""
    value = ""
    old_value: str | None = None
    match = _STATEMENT.match(text) or _STATEMENT_BARE.match(text)
    if match:
        key = _normalise_key(match.group("key"))
        value, old_value = _split_old_value(match.group("value"))
    else:
        from_now = _FROM_NOW.match(text)
        source = from_now.group("value") if from_now else text
        if from_now:
            statement = _STATEMENT.match(source) or _STATEMENT_BARE.match(source)
        else:
            statement = None
        if statement:
            key = _normalise_key(statement.group("key"))
            value, old_value = _split_old_value(statement.group("value"))
        else:
            preference = _preference_parts(source)
            if preference is not None:
                value, old_value = preference
                key = _preference_key(value, old_value)
            else:
                key = "note: " + truncate(text, 70)
                value, old_value = _split_old_value(text)
    value = _normalise(value).strip(" .,:;!?\"'`")
    if len(value) < 2:
        return None
    if contains_secret(value):
        return None
    if correction:
        reason = "correction"
        confidence = 0.7
    elif "remember" in lowered or "don't forget" in lowered or "do not forget" in lowered:
        reason = "explicit_memory"
        confidence = 0.85
    elif key.startswith("user preference"):
        reason = "preference"
        confidence = 0.6
    else:
        reason = "statement"
        confidence = 0.5
    return {
        "fact_key": key,
        "value": value,
        "old_value": old_value,
        "reason": reason,
        "confidence": confidence,
        "is_correction": correction,
        "source_hash": stable_hash({"message": redact_text(original, max_chars=1200)}),
    }


class MemoryService:
    def __init__(self, store: SpineStore, config: ContinuumConfig | None = None):
        self.store = store
        self.config = (config or ContinuumConfig()).clamped()

    # ------------------------------------------------------------------
    # Capture
    # ------------------------------------------------------------------
    def capture_turn(
        self,
        *,
        user_message: Any,
        assistant_message: Any = "",
        session_id: str | None = None,
        turn_id: str | None = None,
        task_id: str | None = None,
        source_ref: str | None = None,
    ) -> dict[str, Any] | None:
        if not self.config.enable_memory_capture:
            return None
        user_text = _message_text(user_message)
        assistant_text = _message_text(assistant_message)
        if not user_text:
            return None
        candidate = extract_fact_candidate(user_text)
        if candidate is None and not _MEMORY_INTENT.search(user_text):
            return None
        excerpt_limit = self.config.max_episode_excerpt_chars
        reason = candidate["reason"] if candidate else "memory_intent"
        episode = self.store.record_episode(
            reason=reason,
            user_excerpt=truncate(redact_text(user_text), excerpt_limit),
            assistant_excerpt=truncate(redact_text(assistant_text), excerpt_limit),
            session_id=session_id,
            turn_id=turn_id,
            task_id=task_id,
            source_ref=source_ref,
            trust_label="USER_AUTHORED",
            sensitivity="internal",
            metadata={
                "memory_intent": True,
                "correction": bool(candidate and candidate["is_correction"]),
                "has_source_ref": bool(source_ref),
            },
        )
        if reason in {"correction", "explicit_memory"}:
            self.store.append_event(
                "user_correction" if reason == "correction" else "session_observed",
                "User correction captured for review"
                if reason == "correction"
                else "Explicit memory request captured for review",
                session_id=session_id,
                turn_id=turn_id,
                task_id=task_id,
                source_ref=source_ref,
                trust_label="USER_AUTHORED",
                details={
                    "episode_id": episode["id"],
                    "reason": reason,
                },
                idempotency_key=f"user-memory-intent:{episode['id']}",
            )
        if candidate is None:
            return {"episode": episode, "candidate": None, "needs_review": False}
        existing = self.store.find_fact_by_episode(episode["id"])
        if existing is not None and existing.get("value") == candidate["value"]:
            return {
                "episode": episode,
                "candidate": existing,
                "contradicts_fact_id": existing.get("contradicts_fact_id"),
                "needs_review": existing.get("status") == "candidate",
            }
        same = self.store.find_fact_by_key_value(
            candidate["fact_key"], candidate["value"]
        )
        if (
            same is not None
            and not same.get("superseded_by")
            and same.get("status") in {"candidate", "confirmed"}
        ):
            # Repeating a known fact refreshes its observation time instead of
            # creating another version.  The episode is marked processed so a
            # later Dream pass does not recreate the same candidate.
            self.store.touch_fact(same["id"])
            self.store.mark_episodes_processed([episode["id"]], "capture-dedupe")
            return {
                "episode": episode,
                "candidate": same,
                "contradicts_fact_id": same.get("contradicts_fact_id"),
                "needs_review": same.get("status") == "candidate",
                "deduplicated": True,
            }
        contradiction = self._find_contradiction(candidate)
        fact = self.store.add_memory_fact(
            fact_key=candidate["fact_key"],
            value=candidate["value"],
            status="candidate",
            confidence=candidate["confidence"],
            source_ref=source_ref,
            source_event_id=episode.get("event_id"),
            episode_id=episode["id"],
            provenance="USER_AUTHORED",
            notes=f"{candidate['reason']} extracted from user message",
            contradicts_fact_id=contradiction["id"] if contradiction else None,
            event_type="memory_candidate_created",
        )
        return {
            "episode": episode,
            "candidate": fact,
            "contradicts_fact_id": contradiction["id"] if contradiction else None,
            "contradicts_fact": contradiction,
            "needs_review": True,
        }

    def _find_contradiction(self, candidate: dict[str, Any]) -> dict[str, Any] | None:
        key = candidate["fact_key"]
        old_value = candidate.get("old_value")
        if old_value:
            old = self.store.find_fact_by_key_value(key, old_value)
            if old is not None:
                return old
        current = self.store.find_current_fact(key)
        if current is None:
            # A correction can arrive before any version is confirmed.  Link it
            # to the latest unreviewed proposal for the same subject so the
            # contradiction is visible during review.
            current = self.store.find_latest_fact(key)
        if current is not None and current["value"].strip().lower() != candidate["value"].strip().lower():
            return current
        return None

    # ------------------------------------------------------------------
    # Review
    # ------------------------------------------------------------------
    def list(self, *, status: str | None = None, query: str | None = None) -> list[dict[str, Any]]:
        return self.store.list_memory(status=status, query=query)

    def confirm(self, fact_id: str) -> dict[str, Any]:
        return self.store.confirm_fact(fact_id)

    def reject(self, fact_id: str) -> dict[str, Any]:
        return self.store.reject_fact(fact_id)

    def edit(self, fact_id: str, value: str) -> dict[str, Any]:
        return self.store.edit_fact(fact_id, value=value)

    def forget(self, fact_id: str) -> dict[str, Any]:
        return self.store.delete_fact(fact_id)

    def recall(self, query: str, *, limit: int | None = None) -> list[dict[str, Any]]:
        return self.store.recall_candidates(
            query=query,
            limit=limit or self.config.recall_limit,
            include_candidates=True,
        )


def _message_text(message: Any) -> str:
    if message is None:
        return ""
    if isinstance(message, str):
        return _normalise(message)
    if isinstance(message, (list, tuple)):
        parts: list[str] = []
        for item in message:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                text = item.get("text") or item.get("content")
                if isinstance(text, str):
                    parts.append(text)
        return _normalise("\n".join(parts))
    if isinstance(message, dict):
        text = message.get("text") or message.get("content")
        if isinstance(text, str):
            return _normalise(text)
    return ""
