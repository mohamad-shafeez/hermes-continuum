"""Append-only Event Spine storage.

The store owns the plugin's SQLite connection and is the only module allowed to
write the core tables directly.  Higher-level services call these methods; they
never mutate another subsystem's private tables.

All writes are serialised with a re-entrant lock and wrapped in SQLite
transactions.  Reads are bounded and parameterised.  A malformed or unavailable
database raises :class:`StorageError`; enforcement callers decide how to fail
closed without silently granting permission.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import timedelta
from typing import Any, Iterable, Iterator

from ..common.errors import StorageError
from ..common.ids import new_event_id, new_id, stable_hash
from ..common.redaction import (
    contains_secret,
    json_preview,
    redact_mapping,
    redact_text,
    truncate,
)
from ..common.time import parse_utc, utc_now, utc_now_iso
from ..constants import (
    EVENT_TYPES,
    MEMORY_STATUSES,
    POLICY_VERSION,
    SCHEMA_VERSION,
    SECURITY_OUTCOMES,
    module_for_event,
)
from .schema import migrate


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


def _loads(value: str | None, default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


def _row(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row is not None else None


_JSON_COLUMNS: tuple[str, ...] = (
    "details_json",
    "fingerprint_json",
    "changed_json",
    "unverified_json",
    "receipt_json",
    "required_evidence_json",
    "metadata_json",
    "constraints_json",
    "success_criteria_json",
    "subgoals_json",
    "criteria_json",
    "evidence_json",
    "targets_json",
    "creates_json",
    "modifies_json",
    "deletes_json",
    "external_json",
    "irreversible_json",
    "unknowns_json",
    "alternatives_json",
    "trace_json",
    "blueprint_json",
    "allowed_tools_json",
    "allowed_paths_json",
    "allowed_domains_json",
)


def _decode_system_row(item: dict[str, Any]) -> dict[str, Any]:
    """Attach friendly decoded values while retaining the raw JSON columns."""

    result = dict(item)
    for column in _JSON_COLUMNS:
        if column in result:
            friendly = column[:-5] if column.endswith("_json") else column
            result[friendly] = _loads(result.get(column), {})
    return result


def _decode_system_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [_decode_system_row(row) for row in rows]


class SpineStore:
    """Thin repository over the plugin-owned SQLite database."""

    def __init__(self, connection: sqlite3.Connection, *, owns_connection: bool = False):
        if not isinstance(connection, sqlite3.Connection):
            raise StorageError("Continuum storage requires a sqlite3 connection.")
        self._conn = connection
        self._owns_connection = owns_connection
        self._lock = threading.RLock()
        try:
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA busy_timeout = 5000")
            self._conn.execute("PRAGMA foreign_keys = ON")
            try:
                self._conn.execute("PRAGMA journal_mode = WAL")
            except sqlite3.DatabaseError:
                # Network filesystems may refuse WAL; the host's open_db helper
                # normally makes this decision, so a refusal is not fatal.
                pass
            migrate(self._conn)
            self._ensure_meta()
        except StorageError:
            raise
        except sqlite3.Error as exc:
            raise StorageError(f"Continuum storage could not be initialised: {exc}") from exc

    # ------------------------------------------------------------------
    # Lifecycle and metadata
    # ------------------------------------------------------------------
    def close(self) -> None:
        if self._owns_connection:
            with self._lock:
                if self._owns_connection:
                    self._owns_connection = False
                    self._conn.close()

    @property
    def database_path(self) -> str:
        """Return the SQLite main database path without mutating state."""

        with self._lock:
            try:
                row = self._conn.execute("PRAGMA database_list").fetchone()
            except sqlite3.Error:
                return ""
        if row is None:
            return ""
        try:
            return str(row["file"] or "")
        except (KeyError, IndexError, TypeError):
            try:
                return str(row[2] or "")
            except (IndexError, TypeError):
                return ""

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            try:
                with self._conn:
                    yield self._conn
            except sqlite3.Error as exc:
                raise StorageError(f"Continuum storage write failed: {exc}") from exc

    def _ensure_meta(self) -> None:
        now = utc_now_iso()
        with self._write() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES('installation_id', ?)",
                (f"inst_{uuid.uuid4().hex}",),
            )
            conn.execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES('created_at', ?)", (now,)
            )
            conn.execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )
            conn.execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES('policy_version', ?)",
                (POLICY_VERSION,),
            )

    def get_meta(self, key: str, default: str | None = None) -> str | None:
        with self._lock:
            row = self._conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return str(row["value"]) if row is not None else default

    def set_meta(self, key: str, value: str) -> None:
        with self._write() as conn:
            conn.execute(
                "INSERT INTO meta(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, str(value)),
            )

    @property
    def installation_id(self) -> str:
        return self.get_meta("installation_id") or "inst_unknown"

    @property
    def schema_version(self) -> int:
        return int(self.get_meta("schema_version", str(SCHEMA_VERSION)) or SCHEMA_VERSION)

    @property
    def policy_version(self) -> str:
        return self.get_meta("policy_version", POLICY_VERSION) or POLICY_VERSION

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------
    def append_event(
        self,
        event_type: str,
        summary: str,
        *,
        session_id: str | None = None,
        turn_id: str | None = None,
        task_id: str | None = None,
        tool_call_id: str | None = None,
        device_id: str | None = None,
        source_ref: str | None = None,
        trust_label: str | None = None,
        sensitivity: str | None = None,
        memory_ref: str | None = None,
        security_decision: str | None = None,
        checkpoint_ref: str | None = None,
        payload_ref: str | None = None,
        details: Any = None,
        idempotency_key: str | None = None,
    ) -> str:
        """Append one event, or return the existing event for an idempotency key."""
        if event_type not in EVENT_TYPES:
            raise ValueError(f"unknown Continuum event type: {event_type!r}")
        if security_decision is not None and security_decision not in SECURITY_OUTCOMES:
            raise ValueError(f"unknown security outcome: {security_decision!r}")
        safe_summary = redact_text(summary or event_type, max_chars=500)
        safe_details = redact_mapping(details or {})
        details_json = _json(safe_details)
        if len(details_json.encode("utf-8")) > 32 * 1024:
            details_json = _json(
                {
                    "truncated": True,
                    "preview": json_preview(safe_details, max_chars=4000),
                }
            )
        now = utc_now_iso()
        event_id = new_event_id()
        with self._write() as conn:
            try:
                cursor = conn.execute(
                    """
                    INSERT OR IGNORE INTO events(
                        event_id, event_type, timestamp_utc, session_id, turn_id,
                        task_id, tool_call_id, device_id, source_ref, trust_label,
                        sensitivity, memory_ref, security_decision, checkpoint_ref,
                        payload_ref, schema_version, summary, details_json,
                        idempotency_key, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event_id,
                        event_type,
                        now,
                        session_id or None,
                        turn_id or None,
                        task_id or None,
                        tool_call_id or None,
                        device_id or self.installation_id,
                        source_ref or None,
                        trust_label or None,
                        sensitivity or None,
                        memory_ref or None,
                        security_decision or None,
                        checkpoint_ref or None,
                        payload_ref or None,
                        SCHEMA_VERSION,
                        safe_summary,
                        details_json,
                        idempotency_key or None,
                        now,
                    ),
                )
                if cursor.rowcount:
                    return event_id
            except sqlite3.Error as exc:
                raise StorageError(f"Continuum event append failed: {exc}") from exc
            # A unique conflict means another writer won the race (or this is a
            # retry). Return the existing row instead of creating a duplicate.
            if idempotency_key:
                existing = conn.execute(
                    "SELECT event_id FROM events WHERE idempotency_key = ?",
                    (idempotency_key,),
                ).fetchone()
                if existing is not None:
                    return str(existing["event_id"])
            existing = conn.execute(
                "SELECT event_id FROM events WHERE event_id = ?", (event_id,)
            ).fetchone()
            if existing is not None:
                return str(existing["event_id"])
            raise StorageError("Continuum event append did not produce a row.")

    def get_event(self, event_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM events WHERE event_id = ?", (event_id,)
            ).fetchone()
        result = _row(row)
        if result is not None:
            result["details"] = _loads(result.pop("details_json", "{}"), {})
            result["module"] = module_for_event(result["event_type"])
        return result

    def list_events(
        self,
        *,
        limit: int = 100,
        event_type: str | None = None,
        module: str | None = None,
        session_id: str | None = None,
        source_ref: str | None = None,
        since: str | None = None,
        until: str | None = None,
        search: str | None = None,
        before_id: int | None = None,
    ) -> list[dict[str, Any]]:
        limit = max(1, min(500, int(limit)))
        clauses: list[str] = []
        params: list[Any] = []
        if event_type:
            clauses.append("event_type = ?")
            params.append(event_type)
        if module:
            from ..constants import event_types_for_module

            types = event_types_for_module(module)
            if not types:
                return []
            clauses.append("event_type IN (" + ",".join("?" for _ in types) + ")")
            params.extend(types)
        if session_id:
            clauses.append("session_id = ?")
            params.append(session_id)
        if source_ref:
            clauses.append("source_ref = ?")
            params.append(source_ref)
        if since:
            clauses.append("timestamp_utc >= ?")
            params.append(since)
        if until:
            clauses.append("timestamp_utc <= ?")
            params.append(until)
        if search:
            clauses.append("(summary LIKE ? OR event_type LIKE ?)")
            needle = f"%{search[:120]}%"
            params.extend([needle, needle])
        if before_id:
            clauses.append("id < ?")
            params.append(int(before_id))
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM events{where} ORDER BY id DESC LIMIT ?", params
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["details"] = _loads(item.pop("details_json", "{}"), {})
            item["module"] = module_for_event(item["event_type"])
            result.append(item)
        return result

    def event_counts(self) -> dict[str, int]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT event_type, COUNT(*) AS count FROM events GROUP BY event_type"
            ).fetchall()
        return {str(row["event_type"]): int(row["count"]) for row in rows}

    def total_events(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS count FROM events").fetchone()
        return int(row["count"]) if row else 0

    def last_event_at(self) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT timestamp_utc FROM events ORDER BY id DESC LIMIT 1"
            ).fetchone()
        return str(row["timestamp_utc"]) if row else None

    # ------------------------------------------------------------------
    # Sources
    # ------------------------------------------------------------------
    def record_source(
        self,
        *,
        tool_name: str,
        source_type: str,
        reference: str = "",
        trust_label: str,
        provenance_confidence: str = "DIRECT",
        sensitivity: str = "unknown",
        session_id: str | None = None,
        turn_id: str | None = None,
        task_id: str | None = None,
        tool_call_id: str | None = None,
        details: Any = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """Record a source and its ``source_labeled`` event idempotently."""
        source_id = new_id("src")
        safe_reference = redact_text(reference, max_chars=600)
        key = idempotency_key or stable_hash(
            {
                "tool_name": tool_name,
                "session_id": session_id,
                "tool_call_id": tool_call_id,
                "reference": safe_reference,
            }
        )
        event_id = self.append_event(
            "source_labeled",
            f"{tool_name} result labeled {trust_label}",
            session_id=session_id,
            turn_id=turn_id,
            task_id=task_id,
            tool_call_id=tool_call_id,
            source_ref=source_id,
            trust_label=trust_label,
            sensitivity=sensitivity,
            details={
                "tool_name": tool_name,
                "source_type": source_type,
                "reference": safe_reference,
                "provenance_confidence": provenance_confidence,
            },
            idempotency_key=f"source-event:{key}",
        )
        existing = self.get_source_by_event(event_id)
        if existing is not None:
            return existing
        now = utc_now_iso()
        with self._write() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO sources(
                    id, event_id, session_id, turn_id, task_id, tool_call_id,
                    tool_name, source_type, reference, trust_label,
                    provenance_confidence, sensitivity, first_seen_utc,
                    last_seen_utc, details_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    source_id,
                    event_id,
                    session_id or None,
                    turn_id or None,
                    task_id or None,
                    tool_call_id or None,
                    tool_name,
                    source_type,
                    safe_reference or None,
                    trust_label,
                    provenance_confidence,
                    sensitivity,
                    now,
                    now,
                    _json(redact_mapping(details or {})),
                ),
            )
            row = conn.execute(
                "SELECT * FROM sources WHERE event_id = ?", (event_id,)
            ).fetchone()
        if row is None:
            raise StorageError("Continuum source record was not stored.")
        return self._source_row(dict(row))

    @staticmethod
    def _source_row(item: dict[str, Any]) -> dict[str, Any]:
        item["details"] = _loads(item.pop("details_json", "{}"), {})
        return item

    def get_source_by_event(self, event_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM sources WHERE event_id = ?", (event_id,)
            ).fetchone()
        return self._source_row(dict(row)) if row is not None else None

    def get_source(self, source_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM sources WHERE id = ?", (source_id,)
            ).fetchone()
        return self._source_row(dict(row)) if row is not None else None

    def latest_source_for_session(
        self,
        session_id: str,
        *,
        window_minutes: int = 30,
        trust_label: str | None = None,
    ) -> dict[str, Any] | None:
        if not session_id:
            return None
        cutoff = (
            utc_now() - timedelta(minutes=max(1, int(window_minutes)))
        ).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        query = (
            "SELECT * FROM sources WHERE session_id = ? AND first_seen_utc >= ?"
        )
        params: list[Any] = [session_id, cutoff]
        if trust_label is not None:
            query += " AND trust_label = ?"
            params.append(trust_label)
        query += " ORDER BY first_seen_utc DESC LIMIT 1"
        with self._lock:
            row = self._conn.execute(query, params).fetchone()
        return self._source_row(dict(row)) if row is not None else None

    def list_sources(self, *, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM sources ORDER BY first_seen_utc DESC LIMIT ?",
                (max(1, min(500, int(limit))),),
            ).fetchall()
        return [self._source_row(dict(row)) for row in rows]

    # ------------------------------------------------------------------
    # Episodes
    # ------------------------------------------------------------------
    def record_episode(
        self,
        *,
        reason: str,
        user_excerpt: str = "",
        assistant_excerpt: str = "",
        session_id: str | None = None,
        turn_id: str | None = None,
        task_id: str | None = None,
        source_ref: str | None = None,
        trust_label: str | None = None,
        sensitivity: str = "unknown",
        metadata: Any = None,
        content_hash: str | None = None,
    ) -> dict[str, Any]:
        safe_user = redact_text(user_excerpt, max_chars=1200)
        safe_assistant = redact_text(assistant_excerpt, max_chars=1200)
        digest = content_hash or stable_hash(
            {
                "session_id": session_id,
                "turn_id": turn_id,
                "reason": reason,
                "user": safe_user,
                "assistant": safe_assistant,
            }
        )
        episode_id = new_id("ep")
        now = utc_now_iso()
        event_id = self.append_event(
            "episode_captured",
            f"Episode captured: {redact_text(reason, max_chars=80)}",
            session_id=session_id,
            turn_id=turn_id,
            task_id=task_id,
            source_ref=source_ref,
            trust_label=trust_label,
            sensitivity=sensitivity,
            details={
                "episode_id": episode_id,
                "reason": reason,
                "user_length": len(safe_user),
                "assistant_length": len(safe_assistant),
            },
            idempotency_key=f"episode:{digest}",
        )
        existing = self.get_episode_by_hash(digest)
        if existing is not None:
            return existing
        with self._write() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO episodes(
                    id, event_id, session_id, turn_id, task_id, captured_at,
                    reason, user_excerpt, assistant_excerpt, source_ref,
                    trust_label, sensitivity, content_hash, metadata_json,
                    created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    episode_id,
                    event_id,
                    session_id or None,
                    turn_id or None,
                    task_id or None,
                    now,
                    reason,
                    safe_user,
                    safe_assistant,
                    source_ref or None,
                    trust_label or None,
                    sensitivity,
                    digest,
                    _json(redact_mapping(metadata or {})),
                    now,
                ),
            )
            row = conn.execute(
                "SELECT * FROM episodes WHERE content_hash = ?", (digest,)
            ).fetchone()
        if row is None:
            raise StorageError("Continuum episode record was not stored.")
        return self._episode_row(dict(row))

    @staticmethod
    def _episode_row(item: dict[str, Any]) -> dict[str, Any]:
        item["metadata"] = _loads(item.pop("metadata_json", "{}"), {})
        return item

    def get_episode(self, episode_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM episodes WHERE id = ?", (episode_id,)
            ).fetchone()
        return self._episode_row(dict(row)) if row is not None else None

    def get_episode_by_hash(self, content_hash: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM episodes WHERE content_hash = ?", (content_hash,)
            ).fetchone()
        return self._episode_row(dict(row)) if row is not None else None

    def list_episodes(self, *, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM episodes ORDER BY captured_at DESC LIMIT ?",
                (max(1, min(500, int(limit))),),
            ).fetchall()
        return [self._episode_row(dict(row)) for row in rows]

    def unprocessed_episodes(self, *, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM episodes WHERE dream_run_id IS NULL "
                "ORDER BY captured_at ASC LIMIT ?",
                (max(1, min(500, int(limit))),),
            ).fetchall()
        return [self._episode_row(dict(row)) for row in rows]

    def mark_episodes_processed(self, episode_ids: Iterable[str], run_id: str) -> int:
        ids = [str(item) for item in episode_ids if item]
        if not ids:
            return 0
        placeholders = ",".join("?" for _ in ids)
        with self._write() as conn:
            cursor = conn.execute(
                f"UPDATE episodes SET dream_run_id = ? WHERE id IN ({placeholders})",
                [run_id, *ids],
            )
            return int(cursor.rowcount or 0)

    # ------------------------------------------------------------------
    # Memory facts
    # ------------------------------------------------------------------
    def _next_fact_version(self, conn: sqlite3.Connection, fact_key: str) -> int:
        row = conn.execute(
            "SELECT COALESCE(MAX(version), 0) AS version FROM memory_facts WHERE fact_key = ?",
            (fact_key,),
        ).fetchone()
        return int(row["version"] if row else 0) + 1

    def add_memory_fact(
        self,
        *,
        fact_key: str,
        value: str,
        status: str = "candidate",
        confidence: float = 0.6,
        source_ref: str | None = None,
        source_event_id: str | None = None,
        episode_id: str | None = None,
        provenance: str = "USER_AUTHORED",
        notes: str | None = None,
        contradicts_fact_id: str | None = None,
        event_type: str = "memory_candidate_created",
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        if status not in MEMORY_STATUSES:
            raise ValueError(f"unknown memory status: {status!r}")
        safe_key = redact_text(fact_key, max_chars=160).strip() or "note"
        safe_value = redact_text(value, max_chars=2000).strip()
        if not safe_value:
            raise ValueError("memory fact value cannot be empty")
        if contains_secret(safe_value):
            # The redactor may not know every credential shape.  Refuse the
            # value rather than silently promoting a probable secret to memory.
            raise ValueError("memory fact value looks like a credential")
        now = utc_now_iso()
        superseded_candidates: list[str] = []
        with self._write() as conn:
            if idempotency_key:
                existing = conn.execute(
                    "SELECT * FROM memory_facts WHERE id = ?",
                    (idempotency_key,),
                ).fetchone()
                if existing is not None:
                    return self._memory_row(dict(existing))
            if episode_id:
                existing = conn.execute(
                    "SELECT * FROM memory_facts WHERE episode_id = ? AND fact_key = ? "
                    "AND value = ? ORDER BY version DESC LIMIT 1",
                    (episode_id, safe_key, safe_value),
                ).fetchone()
                if existing is not None:
                    return self._memory_row(dict(existing))
            version = self._next_fact_version(conn, safe_key)
            fact_id = idempotency_key or new_id("mem")
            if status in {"candidate", "confirmed"}:
                # A new version replaces older *unreviewed* proposals for the
                # same key.  Older confirmed facts stay current until the new
                # version is explicitly confirmed, and the full version history
                # remains visible.
                older = conn.execute(
                    "SELECT id FROM memory_facts WHERE fact_key = ? "
                    "AND status IN ('candidate', 'contradicted') "
                    "AND superseded_by IS NULL",
                    (safe_key,),
                ).fetchall()
                for old in older:
                    old_id = str(old["id"])
                    superseded_candidates.append(old_id)
                    conn.execute(
                        "UPDATE memory_facts SET status = 'superseded', "
                        "superseded_by = ?, updated_at = ? WHERE id = ?",
                        (fact_id, now, old_id),
                    )
            conn.execute(
                """
                INSERT INTO memory_facts(
                    id, fact_key, value, status, confidence, source_ref,
                    source_event_id, episode_id, first_observed_utc,
                    last_observed_utc, confirmed_at, superseded_by,
                    contradicts_fact_id, version, provenance, notes, created_at,
                    updated_at, reviewed_by
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    fact_id,
                    safe_key,
                    safe_value,
                    status,
                    max(0.0, min(1.0, float(confidence))),
                    source_ref or None,
                    source_event_id or None,
                    episode_id or None,
                    now,
                    now,
                    now if status == "confirmed" else None,
                    None,
                    contradicts_fact_id or None,
                    version,
                    provenance,
                    redact_text(notes or "", max_chars=600) or None,
                    now,
                    now,
                    "user" if status == "confirmed" else None,
                ),
            )
            row = conn.execute(
                "SELECT * FROM memory_facts WHERE id = ?", (fact_id,)
            ).fetchone()
        if row is None:
            raise StorageError("Continuum memory fact was not stored.")
        fact = self._memory_row(dict(row))
        for old_id in superseded_candidates:
            self.append_event(
                "memory_superseded",
                f"Memory superseded by {safe_key} v{version}",
                source_ref=source_ref,
                trust_label=provenance,
                memory_ref=old_id,
                details={
                    "fact_id": old_id,
                    "superseded_by": fact_id,
                    "fact_key": safe_key,
                    "version": version,
                },
                idempotency_key=f"memory-superseded:{old_id}:{fact_id}",
            )
        self.append_event(
            event_type,
            f"Memory {status}: {safe_key} v{version}",
            source_ref=source_ref,
            trust_label=provenance,
            memory_ref=fact_id,
            details={
                "fact_id": fact_id,
                "fact_key": safe_key,
                "status": status,
                "version": version,
                "provenance": provenance,
                "episode_id": episode_id,
                "contradicts_fact_id": contradicts_fact_id,
            },
            idempotency_key=(
                f"memory-event:{fact_id}:{event_type}"
                if event_type in {"memory_candidate_created", "memory_confirmed"}
                else None
            ),
        )
        return fact

    @staticmethod
    def _memory_row(item: dict[str, Any]) -> dict[str, Any]:
        return item

    def get_fact(self, fact_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM memory_facts WHERE id = ?", (fact_id,)
            ).fetchone()
        return dict(row) if row is not None else None

    def touch_fact(self, fact_id: str) -> bool:
        """Record that an already-known fact was observed again.

        Only the observation timestamp changes; the value, status, and review
        state are untouched, so a repeated statement can never silently promote
        or rewrite a fact.
        """

        now = utc_now_iso()
        with self._write() as conn:
            cursor = conn.execute(
                "UPDATE memory_facts SET last_observed_utc = ?, updated_at = ? "
                "WHERE id = ?",
                (now, now, fact_id),
            )
            return int(cursor.rowcount or 0) > 0

    def find_fact_by_episode(self, episode_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM memory_facts WHERE episode_id = ? "
                "ORDER BY version DESC LIMIT 1",
                (episode_id,),
            ).fetchone()
        return dict(row) if row is not None else None

    def find_current_fact(self, fact_key: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM memory_facts WHERE fact_key = ? AND status = 'confirmed' "
                "AND superseded_by IS NULL ORDER BY version DESC LIMIT 1",
                (fact_key,),
            ).fetchone()
        return dict(row) if row is not None else None

    def find_fact_by_key_version(self, fact_key: str, version: int) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM memory_facts WHERE fact_key = ? AND version = ?",
                (fact_key, int(version)),
            ).fetchone()
        return dict(row) if row is not None else None

    def max_fact_version(self, fact_key: str) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COALESCE(MAX(version), 0) AS version FROM memory_facts "
                "WHERE fact_key = ?",
                (fact_key,),
            ).fetchone()
        return int(row["version"]) if row is not None else 0

    def find_latest_fact(
        self, fact_key: str, *, include_candidates: bool = True
    ) -> dict[str, Any] | None:
        statuses = ["confirmed", "candidate", "contradicted"]
        if not include_candidates:
            statuses = ["confirmed"]
        placeholders = ",".join("?" for _ in statuses)
        with self._lock:
            row = self._conn.execute(
                f"SELECT * FROM memory_facts WHERE fact_key = ? "
                f"AND status IN ({placeholders}) AND superseded_by IS NULL "
                f"ORDER BY version DESC LIMIT 1",
                [fact_key, *statuses],
            ).fetchone()
        return dict(row) if row is not None else None

    def find_fact_by_key_value(
        self, fact_key: str, value: str, *, include_candidates: bool = True
    ) -> dict[str, Any] | None:
        statuses = ["confirmed", "candidate", "contradicted"]
        if not include_candidates:
            statuses = ["confirmed"]
        placeholders = ",".join("?" for _ in statuses)
        with self._lock:
            row = self._conn.execute(
                f"SELECT * FROM memory_facts WHERE fact_key = ? AND lower(value) = lower(?) "
                f"AND status IN ({placeholders}) ORDER BY version DESC LIMIT 1",
                [fact_key, value, *statuses],
            ).fetchone()
        return dict(row) if row is not None else None

    def list_stale_facts(self, *, days: int = 30, limit: int = 50) -> list[dict[str, Any]]:
        cutoff = (
            utc_now() - timedelta(days=max(1, int(days)))
        ).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM memory_facts WHERE status = 'confirmed' "
                "AND superseded_by IS NULL AND last_observed_utc < ? "
                "ORDER BY last_observed_utc ASC LIMIT ?",
                (cutoff, max(1, min(200, int(limit)))),
            ).fetchall()
        return [dict(row) for row in rows]

    def event_row_range(self) -> tuple[int | None, int | None]:
        with self._lock:
            row = self._conn.execute(
                "SELECT MIN(id) AS first_id, MAX(id) AS last_id FROM events"
            ).fetchone()
        if row is None:
            return None, None
        return (
            int(row["first_id"]) if row["first_id"] is not None else None,
            int(row["last_id"]) if row["last_id"] is not None else None,
        )

    def list_memory(
        self,
        *,
        status: str | None = None,
        query: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM memory_facts ORDER BY fact_key ASC, version DESC LIMIT ?",
                (max(1, min(2000, int(limit) * 5)),),
            ).fetchall()
        facts = [dict(row) for row in rows]
        if status:
            matching_keys = {
                fact["fact_key"]
                for fact in facts
                if fact["status"] == status
            }
            facts = [fact for fact in facts if fact["fact_key"] in matching_keys]
        if query:
            needle = query.strip().lower()
            matching_keys = {
                fact["fact_key"]
                for fact in facts
                if needle in fact["fact_key"].lower()
                or needle in fact["value"].lower()
            }
            facts = [fact for fact in facts if fact["fact_key"] in matching_keys]
        # Compute latest/current markers after filtering so the UI can render
        # a fact card and its complete version history together.
        by_key: dict[str, list[dict[str, Any]]] = {}
        for fact in facts:
            by_key.setdefault(fact["fact_key"], []).append(fact)
        result: list[dict[str, Any]] = []
        for key, versions in by_key.items():
            versions.sort(key=lambda item: int(item["version"]), reverse=True)
            latest_version = int(versions[0]["version"])
            confirmed_versions = [
                item
                for item in versions
                if item["status"] == "confirmed" and not item.get("superseded_by")
            ]
            current_confirmed_id = (
                str(confirmed_versions[0]["id"]) if confirmed_versions else None
            )
            for fact in versions:
                fact["is_latest"] = int(fact["version"]) == latest_version
                fact["is_current_confirmed"] = fact["id"] == current_confirmed_id
                result.append(fact)
        result.sort(
            key=lambda item: (
                0 if item["is_current_confirmed"] else 1,
                item["fact_key"],
                -int(item["version"]),
            )
        )
        return result[: max(1, min(2000, int(limit) * 5))]

    def memory_counts(self) -> dict[str, int]:
        counts = {status: 0 for status in MEMORY_STATUSES}
        with self._lock:
            rows = self._conn.execute(
                "SELECT status, COUNT(*) AS count FROM memory_facts GROUP BY status"
            ).fetchall()
        for row in rows:
            counts[str(row["status"])] = int(row["count"])
        return counts

    def confirm_fact(self, fact_id: str, *, reviewed_by: str = "user") -> dict[str, Any]:
        now = utc_now_iso()
        superseded: list[str] = []
        with self._write() as conn:
            row = conn.execute(
                "SELECT * FROM memory_facts WHERE id = ?", (fact_id,)
            ).fetchone()
            if row is None:
                raise StorageError("Memory fact not found.")
            fact = dict(row)
            prior = conn.execute(
                "SELECT * FROM memory_facts WHERE fact_key = ? AND id != ? "
                "AND status = 'confirmed' AND superseded_by IS NULL "
                "ORDER BY version DESC",
                (fact["fact_key"], fact_id),
            ).fetchall()
            for old in prior:
                old_id = str(old["id"])
                superseded.append(old_id)
                conn.execute(
                    "UPDATE memory_facts SET status = 'superseded', superseded_by = ?, "
                    "updated_at = ? WHERE id = ?",
                    (fact_id, now, old_id),
                )
            conn.execute(
                "UPDATE memory_facts SET status = 'confirmed', confirmed_at = ?, "
                "reviewed_by = ?, updated_at = ?, last_observed_utc = ? WHERE id = ?",
                (now, reviewed_by, now, now, fact_id),
            )
            updated = conn.execute(
                "SELECT * FROM memory_facts WHERE id = ?", (fact_id,)
            ).fetchone()
        if updated is None:
            raise StorageError("Memory fact disappeared during confirmation.")
        updated_fact = dict(updated)
        for old_id in superseded:
            self.append_event(
                "memory_superseded",
                f"Memory superseded by {fact['fact_key']} v{fact['version']}",
                memory_ref=old_id,
                details={"fact_id": old_id, "superseded_by": fact_id},
                idempotency_key=f"memory-superseded:{old_id}:{fact_id}",
            )
        self.append_event(
            "memory_confirmed",
            f"Memory confirmed: {fact['fact_key']} v{fact['version']}",
            memory_ref=fact_id,
            details={
                "fact_id": fact_id,
                "fact_key": fact["fact_key"],
                "version": fact["version"],
                "superseded": superseded,
            },
            idempotency_key=f"memory-confirm:{fact_id}",
        )
        return updated_fact

    def reject_fact(self, fact_id: str, *, reviewed_by: str = "user") -> dict[str, Any]:
        now = utc_now_iso()
        with self._write() as conn:
            row = conn.execute(
                "SELECT * FROM memory_facts WHERE id = ?", (fact_id,)
            ).fetchone()
            if row is None:
                raise StorageError("Memory fact not found.")
            fact = dict(row)
            conn.execute(
                "UPDATE memory_facts SET status = 'rejected', reviewed_by = ?, "
                "updated_at = ? WHERE id = ?",
                (reviewed_by, now, fact_id),
            )
            updated = conn.execute(
                "SELECT * FROM memory_facts WHERE id = ?", (fact_id,)
            ).fetchone()
        self.append_event(
            "memory_rejected",
            f"Memory rejected: {fact['fact_key']} v{fact['version']}",
            memory_ref=fact_id,
            details={"fact_id": fact_id, "fact_key": fact["fact_key"]},
            idempotency_key=f"memory-reject:{fact_id}",
        )
        return dict(updated) if updated is not None else fact

    def edit_fact(
        self,
        fact_id: str,
        *,
        value: str,
        reviewed_by: str = "user",
    ) -> dict[str, Any]:
        original = self.get_fact(fact_id)
        if original is None:
            raise StorageError("Memory fact not found.")
        new_fact = self.add_memory_fact(
            fact_key=original["fact_key"],
            value=value,
            status="candidate",
            confidence=max(0.5, float(original.get("confidence") or 0.5)),
            source_ref=original.get("source_ref"),
            source_event_id=original.get("source_event_id"),
            episode_id=original.get("episode_id"),
            provenance="USER_EDITED",
            notes=f"Edited from {fact_id} by {reviewed_by}",
            contradicts_fact_id=original.get("contradicts_fact_id"),
            event_type="memory_edited",
        )
        self.append_event(
            "memory_edited",
            f"Memory edited: {original['fact_key']} v{new_fact['version']}",
            memory_ref=new_fact["id"],
            details={
                "fact_id": new_fact["id"],
                "from_fact_id": fact_id,
                "fact_key": original["fact_key"],
                "version": new_fact["version"],
            },
            idempotency_key=f"memory-edit:{new_fact['id']}",
        )
        return new_fact

    def delete_fact(self, fact_id: str, *, delete_episode: bool = True) -> dict[str, Any]:
        """Forget a fact key and every version of it.

        A memory is presented to the user as one fact with a version history.
        Deleting only the selected version would let an older version reappear,
        so ``forget`` removes the whole key.  Episodes are removed only when no
        remaining fact (from any key) still references them.
        """

        with self._write() as conn:
            row = conn.execute(
                "SELECT * FROM memory_facts WHERE id = ?", (fact_id,)
            ).fetchone()
            if row is None:
                raise StorageError("Memory fact not found.")
            fact = dict(row)
            versions = conn.execute(
                "SELECT id, episode_id FROM memory_facts WHERE fact_key = ?",
                (fact["fact_key"],),
            ).fetchall()
            fact_ids = [str(item["id"]) for item in versions]
            episode_ids = sorted(
                {str(item["episode_id"]) for item in versions if item["episode_id"]}
            )
            placeholders = ",".join("?" for _ in fact_ids)
            conn.execute(
                f"DELETE FROM memory_facts WHERE id IN ({placeholders})",
                fact_ids,
            )
            episodes_deleted: list[str] = []
            if delete_episode:
                for episode_id in episode_ids:
                    remaining = conn.execute(
                        "SELECT COUNT(*) AS count FROM memory_facts WHERE episode_id = ?",
                        (episode_id,),
                    ).fetchone()
                    if remaining is None or int(remaining["count"]) == 0:
                        conn.execute(
                            "DELETE FROM episodes WHERE id = ?", (episode_id,)
                        )
                        episodes_deleted.append(episode_id)
        self.append_event(
            "memory_deleted",
            f"Memory deleted: {fact['fact_key']}",
            memory_ref=fact_id,
            details={
                "fact_id": fact_id,
                "fact_key": fact["fact_key"],
                "deleted_fact_ids": fact_ids,
                "versions_deleted": len(fact_ids),
                "episodes_deleted": episodes_deleted,
                "episode_deleted": bool(episodes_deleted),
            },
            idempotency_key=f"memory-delete:{fact_id}",
        )
        self.append_event(
            "data_deleted",
            "Plugin-owned memory deleted at user request",
            details={
                "scope": "memory",
                "fact_id": fact_id,
                "fact_key": fact["fact_key"],
                "versions_deleted": len(fact_ids),
                "episodes_deleted": episodes_deleted,
            },
            idempotency_key=f"data-deleted:memory:{fact_id}",
        )
        return {
            "deleted": True,
            "fact_id": fact_id,
            "fact_key": fact["fact_key"],
            "deleted_fact_ids": fact_ids,
            "versions_deleted": len(fact_ids),
            "episodes_deleted": episodes_deleted,
            "episode_deleted": bool(episodes_deleted),
        }

    def recall_candidates(
        self,
        *,
        query: str,
        limit: int = 5,
        include_candidates: bool = True,
    ) -> list[dict[str, Any]]:
        """Return a small, provenance-aware recall set.

        Confirmed facts are preferred.  Candidates are included only when no
        confirmed match exists and are clearly marked by the caller.
        """
        tokens = [
            token.lower()
            for token in str(query or "").replace("\n", " ").split()
            if len(token) > 2
        ][:8]
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM memory_facts WHERE status IN ('confirmed', 'candidate') "
                "ORDER BY last_observed_utc DESC LIMIT 1000"
            ).fetchall()
        facts = [dict(row) for row in rows]
        if tokens:
            def score(fact: dict[str, Any]) -> int:
                haystack = f"{fact['fact_key']} {fact['value']}".lower()
                return sum(1 for token in tokens if token in haystack)

            facts = [fact for fact in facts if score(fact) > 0]
            facts.sort(key=lambda fact: (score(fact), fact["last_observed_utc"]), reverse=True)
        else:
            facts = []
        confirmed = [
            fact
            for fact in facts
            if fact["status"] == "confirmed" and not fact.get("superseded_by")
        ][: max(1, min(50, int(limit)))]
        if confirmed or not include_candidates:
            return confirmed
        return [
            fact
            for fact in facts
            if fact["status"] == "candidate" and not fact.get("superseded_by")
        ][: max(1, min(50, int(limit)))]

    # ------------------------------------------------------------------
    # Security decisions
    # ------------------------------------------------------------------
    def record_decision(
        self,
        *,
        tool_name: str,
        outcome: str,
        rule_key: str,
        category: str,
        reason: str,
        evidence: Any,
        args: Any,
        session_id: str | None = None,
        tool_call_id: str | None = None,
        turn_id: str | None = None,
        source_ref: str | None = None,
        trust_label: str | None = None,
    ) -> dict[str, Any]:
        if outcome not in SECURITY_OUTCOMES:
            raise ValueError(f"unknown security outcome: {outcome!r}")
        safe_args = redact_mapping(args or {})
        redacted_args_json = _json(safe_args)
        arg_keys = (
            sorted(str(key) for key in args.keys())[:30]
            if isinstance(args, dict)
            else []
        )
        safe_evidence = redact_mapping(evidence or {})
        event_type = {
            "block": "action_blocked",
            "approve": "approval_requested",
            "allow": "action_evaluated",
        }[outcome]
        decision_id = new_id("dec")
        key = stable_hash(
            {
                "tool_name": tool_name,
                "session_id": session_id,
                "tool_call_id": tool_call_id,
                "rule_key": rule_key,
                "outcome": outcome,
                "args": safe_args,
            }
        )
        event_id = self.append_event(
            event_type,
            f"{tool_name}: {outcome} ({rule_key})",
            session_id=session_id,
            turn_id=turn_id,
            tool_call_id=tool_call_id,
            source_ref=source_ref,
            trust_label=trust_label,
            security_decision=outcome,
            details={
                "decision_id": decision_id,
                "rule_key": rule_key,
                "category": category,
                "outcome": outcome,
                "policy_version": self.policy_version,
                "reason": reason,
                "evidence": safe_evidence,
                "arg_keys": arg_keys,
                "args_hash": stable_hash(safe_args),
                "args_preview": safe_args,
            },
            idempotency_key=f"decision:{key}",
        )
        existing = self.get_decision_by_event(event_id)
        if existing is not None:
            return existing
        now = utc_now_iso()
        with self._write() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO security_decisions(
                    id, event_id, rule_key, policy_version, tool_name,
                    action_category, outcome, reason, evidence_json,
                    redacted_args_json, session_id, tool_call_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    decision_id,
                    event_id,
                    rule_key,
                    self.policy_version,
                    tool_name,
                    category,
                    outcome,
                    redact_text(reason, max_chars=600),
                    _json(safe_evidence),
                    redacted_args_json,
                    session_id or None,
                    tool_call_id or None,
                    now,
                ),
            )
            row = conn.execute(
                "SELECT * FROM security_decisions WHERE event_id = ?", (event_id,)
            ).fetchone()
        if row is None:
            raise StorageError("Continuum security decision was not stored.")
        return self._decision_row(dict(row))

    @staticmethod
    def _decision_row(item: dict[str, Any]) -> dict[str, Any]:
        item["evidence"] = _loads(item.pop("evidence_json", "{}"), {})
        item["redacted_args"] = _loads(item.pop("redacted_args_json", "{}"), {})
        return item

    def get_decision_by_event(self, event_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM security_decisions WHERE event_id = ?", (event_id,)
            ).fetchone()
        return self._decision_row(dict(row)) if row is not None else None

    def list_decisions(
        self,
        *,
        outcome: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        clauses = ""
        params: list[Any] = []
        if outcome:
            clauses = " WHERE outcome = ?"
            params.append(outcome)
        params.append(max(1, min(500, int(limit))))
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM security_decisions{clauses} "
                "ORDER BY created_at DESC LIMIT ?",
                params,
            ).fetchall()
        return [self._decision_row(dict(row)) for row in rows]

    def decision_counts(self) -> dict[str, int]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT outcome, COUNT(*) AS count FROM security_decisions GROUP BY outcome"
            ).fetchall()
        return {str(row["outcome"]): int(row["count"]) for row in rows}

    # ------------------------------------------------------------------
    # Dream runs
    # ------------------------------------------------------------------
    def record_dream_run(
        self,
        *,
        status: str,
        from_event_id: int | None,
        to_event_id: int | None,
        episodes_processed: int,
        candidates_created: int,
        contradictions: Any,
        report: Any,
        run_id: str | None = None,
        started_at: str | None = None,
    ) -> dict[str, Any]:
        run_id = run_id or new_id("dream")
        started_at = started_at or utc_now_iso()
        completed_at = utc_now_iso()
        with self._write() as conn:
            conn.execute(
                """
                INSERT INTO dream_runs(
                    id, started_at, completed_at, status, from_event_id,
                    to_event_id, episodes_processed, candidates_created,
                    contradictions_json, report_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    started_at,
                    completed_at,
                    status,
                    from_event_id,
                    to_event_id,
                    episodes_processed,
                    candidates_created,
                    _json(redact_mapping(contradictions or [])),
                    _json(redact_mapping(report or {})),
                ),
            )
            row = conn.execute(
                "SELECT * FROM dream_runs WHERE id = ?", (run_id,)
            ).fetchone()
        if row is None:
            raise StorageError("Dream run was not stored.")
        event_type = "dream_completed" if status == "completed" else "dream_skipped"
        self.append_event(
            event_type,
            f"Dream {status}: {episodes_processed} episodes, "
            f"{candidates_created} candidates",
            details={
                "run_id": run_id,
                "status": status,
                "episodes_processed": episodes_processed,
                "candidates_created": candidates_created,
                "contradictions": len(contradictions or []),
            },
            idempotency_key=f"dream-event:{run_id}:{event_type}",
        )
        return self._dream_row(dict(row))

    @staticmethod
    def _dream_row(item: dict[str, Any]) -> dict[str, Any]:
        item["contradictions"] = _loads(item.pop("contradictions_json", "[]"), [])
        item["report"] = _loads(item.pop("report_json", "{}"), {})
        return item

    def last_dream_run(self) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM dream_runs ORDER BY started_at DESC LIMIT 1"
            ).fetchone()
        return self._dream_row(dict(row)) if row is not None else None

    def list_dream_runs(self, *, limit: int = 20) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM dream_runs ORDER BY started_at DESC LIMIT ?",
                (max(1, min(100, int(limit))),),
            ).fetchall()
        return [self._dream_row(dict(row)) for row in rows]

    # ------------------------------------------------------------------
    # Attack Lab
    # ------------------------------------------------------------------
    def record_attack_lab(
        self,
        *,
        policy_version: str,
        results: list[dict[str, Any]],
        suite: str = "tripwire",
        run_id: str | None = None,
    ) -> dict[str, Any]:
        run_id = run_id or new_id("lab")
        total = len(results)
        passed = sum(1 for item in results if item.get("passed"))
        now = utc_now_iso()
        safe_suite = str(suite or "tripwire").strip().lower()[:40] or "tripwire"
        with self._write() as conn:
            conn.execute(
                """
                INSERT INTO attack_lab_runs(
                    id, run_at, policy_version, suite, total, passed, results_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (run_id, now, policy_version, safe_suite, total, passed, _json(results)),
            )
            row = conn.execute(
                "SELECT * FROM attack_lab_runs WHERE id = ?", (run_id,)
            ).fetchone()
        if row is None:
            raise StorageError("Attack Lab result was not stored.")
        self.append_event(
            "attack_lab_completed",
            f"Attack Lab ({safe_suite}): {passed}/{total} deterministic cases passed",
            details={
                "run_id": run_id,
                "suite": safe_suite,
                "passed": passed,
                "total": total,
            },
            idempotency_key=f"attack-lab:{run_id}",
        )
        return self._lab_row(dict(row))

    @staticmethod
    def _lab_row(item: dict[str, Any]) -> dict[str, Any]:
        item["results"] = _loads(item.pop("results_json", "[]"), [])
        return item

    def last_attack_lab(self, *, suite: str | None = None) -> dict[str, Any] | None:
        with self._lock:
            if suite:
                row = self._conn.execute(
                    "SELECT * FROM attack_lab_runs WHERE suite = ? "
                    "ORDER BY run_at DESC LIMIT 1",
                    (str(suite).strip().lower(),),
                ).fetchone()
            else:
                row = self._conn.execute(
                    "SELECT * FROM attack_lab_runs ORDER BY run_at DESC LIMIT 1"
                ).fetchone()
        return self._lab_row(dict(row)) if row is not None else None

    def list_attack_labs(
        self, *, limit: int = 20, suite: str | None = None
    ) -> list[dict[str, Any]]:
        with self._lock:
            if suite:
                rows = self._conn.execute(
                    "SELECT * FROM attack_lab_runs WHERE suite = ? "
                    "ORDER BY run_at DESC LIMIT ?",
                    (str(suite).strip().lower(), max(1, min(100, int(limit)))),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM attack_lab_runs ORDER BY run_at DESC LIMIT ?",
                    (max(1, min(100, int(limit))),),
                ).fetchall()
        return [self._lab_row(dict(row)) for row in rows]

    # ------------------------------------------------------------------
    # Hephaestus: forged playbooks and safety leases
    # ------------------------------------------------------------------
    def list_session_events(
        self, session_id: str, *, limit: int = 5000
    ) -> list[dict[str, Any]]:
        """Return one session's events in chronological order for distillation."""

        bounded = max(1, min(10000, int(limit)))
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM events WHERE session_id = ? "
                "ORDER BY id ASC LIMIT ?",
                (str(session_id or ""), bounded),
            ).fetchall()
        return _decode_system_rows([dict(row) for row in rows])

    def create_playbook(
        self,
        *,
        playbook_id: str,
        slug: str,
        name: str,
        version: int,
        description: str = "",
        status: str = "forged",
        source_session_id: str | None = None,
        source_task_id: str | None = None,
        source_event_start: int | None = None,
        source_event_end: int | None = None,
        confidence: float = 0.0,
        steps_attempted: int = 0,
        steps_succeeded: int = 0,
        trace_hash: str = "",
        trace: dict[str, Any] | None = None,
        skill_path: str | None = None,
        skill_sha256: str | None = None,
        blueprint_key: str | None = None,
        blueprint: dict[str, Any] | None = None,
        lease_id: str | None = None,
        environment_hash: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = utc_now_iso()
        with self._write() as conn:
            conn.execute(
                """
                INSERT INTO playbooks(
                    id, slug, name, version, description, status,
                    source_session_id, source_task_id, source_event_start,
                    source_event_end, confidence, steps_attempted,
                    steps_succeeded, trace_hash, trace_json, skill_path,
                    skill_sha256, blueprint_key, blueprint_json, lease_id,
                    environment_hash, metadata_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    playbook_id,
                    slug,
                    redact_text(name, max_chars=160),
                    int(version),
                    redact_text(description, max_chars=1000),
                    str(status or "forged"),
                    source_session_id,
                    source_task_id,
                    source_event_start,
                    source_event_end,
                    max(0.0, min(1.0, float(confidence))),
                    int(steps_attempted),
                    int(steps_succeeded),
                    trace_hash,
                    _json(redact_mapping(trace or {})),
                    skill_path,
                    skill_sha256,
                    blueprint_key,
                    _json(redact_mapping(blueprint or {})),
                    lease_id,
                    environment_hash,
                    _json(redact_mapping(metadata or {})),
                    now,
                    now,
                ),
            )
            row = conn.execute(
                "SELECT * FROM playbooks WHERE id = ?", (playbook_id,)
            ).fetchone()
        if row is None:
            raise StorageError("Hephaestus playbook was not stored.")
        return _decode_system_row(dict(row))

    def get_playbook(self, playbook_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM playbooks WHERE id = ?", (playbook_id,)
            ).fetchone()
        return _decode_system_row(dict(row)) if row is not None else None

    def get_playbook_by_slug(self, slug: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM playbooks WHERE slug = ?", (str(slug or ""),)
            ).fetchone()
        return _decode_system_row(dict(row)) if row is not None else None

    def list_playbooks(
        self,
        *,
        status: str | None = None,
        source_session_id: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if status:
            clauses.append("status = ?")
            params.append(str(status))
        if source_session_id:
            clauses.append("source_session_id = ?")
            params.append(str(source_session_id))
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(max(1, min(500, int(limit))))
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM playbooks{where} "
                "ORDER BY created_at DESC, version DESC LIMIT ?",
                params,
            ).fetchall()
        return _decode_system_rows([dict(row) for row in rows])

    def update_playbook(
        self,
        playbook_id: str,
        *,
        status: str | None = None,
        lease_id: str | None = None,
        skill_sha256: str | None = None,
        quarantine_reason: str | None = None,
        environment_hash: str | None = None,
        blueprint: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        fields: list[str] = ["updated_at = ?"]
        params: list[Any] = [utc_now_iso()]
        if status is not None:
            fields.append("status = ?")
            params.append(str(status))
        if lease_id is not None:
            fields.append("lease_id = ?")
            params.append(lease_id)
        if skill_sha256 is not None:
            fields.append("skill_sha256 = ?")
            params.append(skill_sha256)
        if quarantine_reason is not None:
            fields.append("quarantine_reason = ?")
            params.append(redact_text(quarantine_reason, max_chars=1000))
        if environment_hash is not None:
            fields.append("environment_hash = ?")
            params.append(environment_hash)
        if blueprint is not None:
            fields.append("blueprint_json = ?")
            params.append(_json(redact_mapping(blueprint)))
        if metadata is not None:
            fields.append("metadata_json = ?")
            params.append(_json(redact_mapping(metadata)))
        params.append(playbook_id)
        with self._write() as conn:
            conn.execute(
                f"UPDATE playbooks SET {', '.join(fields)} WHERE id = ?", params
            )
            row = conn.execute(
                "SELECT * FROM playbooks WHERE id = ?", (playbook_id,)
            ).fetchone()
        return _decode_system_row(dict(row)) if row is not None else None

    def create_safety_lease(
        self,
        *,
        lease_id: str,
        playbook_id: str,
        lease_hash: str,
        allowed_tools: list[str] | None = None,
        allowed_paths: list[str] | None = None,
        allowed_domains: list[str] | None = None,
        allow_opaque_tools: bool = False,
        max_tool_calls: int = 200,
        max_file_writes: int = 50,
        max_external_calls: int = 50,
        cron_job_id: str | None = None,
        environment_hash: str | None = None,
        issued_by: str = "user",
        issued_at: str | None = None,
        expires_at: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = issued_at or utc_now_iso()
        with self._write() as conn:
            conn.execute(
                """
                INSERT INTO safety_leases(
                    id, playbook_id, status, lease_hash, allowed_tools_json,
                    allowed_paths_json, allowed_domains_json, allow_opaque_tools,
                    max_tool_calls, max_file_writes, max_external_calls,
                    cron_job_id, environment_hash, issued_by, issued_at,
                    expires_at, metadata_json
                ) VALUES (?, ?, 'active', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    lease_id,
                    playbook_id,
                    lease_hash,
                    _json(sorted({str(item) for item in (allowed_tools or [])})),
                    _json(sorted({str(item) for item in (allowed_paths or [])})),
                    _json(sorted({str(item).lower() for item in (allowed_domains or [])})),
                    1 if allow_opaque_tools else 0,
                    max(1, int(max_tool_calls)),
                    max(0, int(max_file_writes)),
                    max(0, int(max_external_calls)),
                    cron_job_id,
                    environment_hash,
                    redact_text(issued_by or "user", max_chars=80),
                    now,
                    expires_at,
                    _json(redact_mapping(metadata or {})),
                ),
            )
            row = conn.execute(
                "SELECT * FROM safety_leases WHERE id = ?", (lease_id,)
            ).fetchone()
        if row is None:
            raise StorageError("Hephaestus safety lease was not stored.")
        return _decode_system_row(dict(row))

    def get_safety_lease(self, lease_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM safety_leases WHERE id = ?", (lease_id,)
            ).fetchone()
        return _decode_system_row(dict(row)) if row is not None else None

    def list_safety_leases(
        self,
        *,
        playbook_id: str | None = None,
        status: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if playbook_id:
            clauses.append("playbook_id = ?")
            params.append(playbook_id)
        if status:
            clauses.append("status = ?")
            params.append(status)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(max(1, min(500, int(limit))))
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM safety_leases{where} "
                "ORDER BY issued_at DESC LIMIT ?",
                params,
            ).fetchall()
        return _decode_system_rows([dict(row) for row in rows])

    def active_lease_for_playbook(self, playbook_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM safety_leases WHERE playbook_id = ? "
                "AND status = 'active' ORDER BY issued_at DESC LIMIT 1",
                (playbook_id,),
            ).fetchone()
        return _decode_system_row(dict(row)) if row is not None else None

    def list_active_leases_with_playbooks(self, *, limit: int = 200) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT sl.*, p.slug AS playbook_slug, p.name AS playbook_name,
                       p.status AS playbook_status, p.blueprint_key AS playbook_blueprint_key
                FROM safety_leases sl
                JOIN playbooks p ON p.id = sl.playbook_id
                WHERE sl.status = 'active'
                ORDER BY sl.issued_at DESC LIMIT ?
                """,
                (max(1, min(500, int(limit))),),
            ).fetchall()
        return _decode_system_rows([dict(row) for row in rows])

    def revoke_safety_lease(
        self, lease_id: str, *, reason: str = "Revoked by user"
    ) -> dict[str, Any] | None:
        with self._write() as conn:
            conn.execute(
                "UPDATE safety_leases SET status = 'revoked', revoked_at = ?, "
                "revoked_reason = ? WHERE id = ? AND status = 'active'",
                (
                    utc_now_iso(),
                    redact_text(reason, max_chars=1000),
                    lease_id,
                ),
            )
            row = conn.execute(
                "SELECT * FROM safety_leases WHERE id = ?", (lease_id,)
            ).fetchone()
        return _decode_system_row(dict(row)) if row is not None else None

    def expire_safety_lease(self, lease_id: str) -> None:
        with self._write() as conn:
            conn.execute(
                "UPDATE safety_leases SET status = 'expired' "
                "WHERE id = ? AND status = 'active'",
                (lease_id,),
            )

    def get_lease_usage(self, lease_id: str, run_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM safety_lease_usage WHERE lease_id = ? AND run_id = ?",
                (lease_id, run_id),
            ).fetchone()
        return _decode_system_row(dict(row)) if row is not None else None

    def list_lease_usage(
        self, *, lease_id: str | None = None, limit: int = 100
    ) -> list[dict[str, Any]]:
        params: list[Any] = []
        where = ""
        if lease_id:
            where = " WHERE lease_id = ?"
            params.append(lease_id)
        params.append(max(1, min(500, int(limit))))
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM safety_lease_usage{where} "
                "ORDER BY updated_at DESC LIMIT ?",
                params,
            ).fetchall()
        return _decode_system_rows([dict(row) for row in rows])

    def consume_lease_usage(
        self,
        *,
        lease_id: str,
        run_id: str,
        cron_job_id: str | None,
        tool_name: str,
        max_tool_calls: int,
        max_file_writes: int,
        max_external_calls: int,
        file_write: bool = False,
        external: bool = False,
    ) -> dict[str, Any]:
        """Atomically reserve one tool call and its write/external counters.

        The check and increment happen in one write transaction.  A block never
        increments a counter, so a denied attempt cannot be used to exhaust a
        lease.  A caller that later fails before execution has still consumed a
        call; this is intentionally conservative.
        """

        now = utc_now_iso()
        with self._write() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO safety_lease_usage(
                    id, lease_id, run_id, cron_job_id, tool_calls, file_writes,
                    external_calls, first_seen_at, updated_at, last_tool,
                    metadata_json
                ) VALUES (?, ?, ?, ?, 0, 0, 0, ?, ?, NULL, '{}')
                """,
                (new_id("use"), lease_id, run_id, cron_job_id, now, now),
            )
            row = conn.execute(
                "SELECT * FROM safety_lease_usage WHERE lease_id = ? AND run_id = ?",
                (lease_id, run_id),
            ).fetchone()
            if row is None:
                raise StorageError("Hephaestus lease usage row was not stored.")
            calls = int(row["tool_calls"] or 0) + 1
            writes = int(row["file_writes"] or 0) + (1 if file_write else 0)
            externals = int(row["external_calls"] or 0) + (1 if external else 0)
            limit_key: str | None = None
            if calls > max(1, int(max_tool_calls)):
                limit_key = "max_tool_calls"
            elif writes > max(0, int(max_file_writes)):
                limit_key = "max_file_writes"
            elif externals > max(0, int(max_external_calls)):
                limit_key = "max_external_calls"
            if limit_key is not None:
                return {
                    "allowed": False,
                    "reason": f"Safety lease {limit_key} would be exceeded.",
                    "limit": limit_key,
                    "usage": _decode_system_row(dict(row)),
                }
            conn.execute(
                "UPDATE safety_lease_usage SET tool_calls = ?, file_writes = ?, "
                "external_calls = ?, updated_at = ?, last_tool = ? WHERE id = ?",
                (
                    calls,
                    writes,
                    externals,
                    now,
                    redact_text(tool_name, max_chars=120),
                    row["id"],
                ),
            )
            updated = conn.execute(
                "SELECT * FROM safety_lease_usage WHERE id = ?", (row["id"],)
            ).fetchone()
        return {
            "allowed": True,
            "reason": None,
            "limit": None,
            "usage": _decode_system_row(dict(updated)),
        }

    def hephaestus_counts(self) -> dict[str, int]:
        with self._lock:
            playbooks = int(
                self._conn.execute("SELECT COUNT(*) AS c FROM playbooks").fetchone()["c"]
            )
            active_playbooks = int(
                self._conn.execute(
                    "SELECT COUNT(*) AS c FROM playbooks WHERE status IN ('active', 'forged')"
                ).fetchone()["c"]
            )
            quarantined = int(
                self._conn.execute(
                    "SELECT COUNT(*) AS c FROM playbooks WHERE status = 'quarantined'"
                ).fetchone()["c"]
            )
            active_leases = int(
                self._conn.execute(
                    "SELECT COUNT(*) AS c FROM safety_leases WHERE status = 'active'"
                ).fetchone()["c"]
            )
            expired_leases = int(
                self._conn.execute(
                    "SELECT COUNT(*) AS c FROM safety_leases WHERE status = 'expired'"
                ).fetchone()["c"]
            )
            lease_usage = int(
                self._conn.execute(
                    "SELECT COUNT(*) AS c FROM safety_lease_usage"
                ).fetchone()["c"]
            )
        return {
            "playbooks": playbooks,
            "active_playbooks": active_playbooks,
            "quarantined": quarantined,
            "active_leases": active_leases,
            "expired_leases": expired_leases,
            "lease_usage_runs": lease_usage,
        }

    # ------------------------------------------------------------------
    # Checkpoints and resume briefs
    # ------------------------------------------------------------------
    def record_checkpoint(
        self,
        *,
        checkpoint_id: str,
        filename: str,
        format_version: int,
        source_installation_id: str,
        counts: Any,
        excluded: Any,
        checksum: str | None,
        status: str,
        metadata: Any = None,
        imported_at: str | None = None,
        resume_brief_id: str | None = None,
    ) -> dict[str, Any]:
        now = utc_now_iso()
        with self._write() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO checkpoints(
                    id, created_at, filename, format_version,
                    source_installation_id, counts_json, excluded_json,
                    checksum, status, imported_at, metadata_json, resume_brief_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    checkpoint_id,
                    now,
                    filename,
                    format_version,
                    source_installation_id,
                    _json(redact_mapping(counts or {})),
                    _json(redact_mapping(excluded or [])),
                    checksum,
                    status,
                    imported_at,
                    _json(redact_mapping(metadata or {})),
                    resume_brief_id,
                ),
            )
            row = conn.execute(
                "SELECT * FROM checkpoints WHERE id = ?", (checkpoint_id,)
            ).fetchone()
        if row is None:
            raise StorageError("Checkpoint metadata was not stored.")
        event_type = {
            "exported": "checkpoint_exported",
            "imported": "checkpoint_imported",
            "created": "checkpoint_created",
            "failed": "checkpoint_failed",
        }.get(status, "checkpoint_created")
        self.append_event(
            event_type,
            f"Checkpoint {status}: {filename}",
            checkpoint_ref=checkpoint_id,
            details={
                "checkpoint_id": checkpoint_id,
                "filename": filename,
                "format_version": format_version,
                "counts": counts,
                "status": status,
            },
            idempotency_key=f"checkpoint-event:{checkpoint_id}:{status}",
        )
        return self._checkpoint_row(dict(row))

    @staticmethod
    def _checkpoint_row(item: dict[str, Any]) -> dict[str, Any]:
        item["counts"] = _loads(item.pop("counts_json", "{}"), {})
        item["excluded"] = _loads(item.pop("excluded_json", "[]"), [])
        item["metadata"] = _loads(item.pop("metadata_json", "{}"), {})
        return item

    def get_checkpoint(self, checkpoint_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM checkpoints WHERE id = ?", (checkpoint_id,)
            ).fetchone()
        return self._checkpoint_row(dict(row)) if row is not None else None

    def find_imported_checkpoint_by_checksum(self, checksum: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM checkpoints WHERE checksum = ? AND status = 'imported' "
                "ORDER BY created_at DESC LIMIT 1",
                (checksum,),
            ).fetchone()
        return self._checkpoint_row(dict(row)) if row is not None else None

    def list_checkpoints(self, *, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM checkpoints ORDER BY created_at DESC LIMIT ?",
                (max(1, min(200, int(limit))),),
            ).fetchall()
        return [self._checkpoint_row(dict(row)) for row in rows]

    def record_resume_brief(
        self,
        *,
        checkpoint_id: str | None,
        brief: str,
        metadata: Any = None,
        brief_id: str | None = None,
    ) -> dict[str, Any]:
        brief_id = brief_id or new_id("resume")
        now = utc_now_iso()
        with self._write() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO resume_briefs("
                "id, checkpoint_id, created_at, brief, metadata_json, active"
                ") VALUES (?, ?, ?, ?, ?, 1)",
                (
                    brief_id,
                    checkpoint_id,
                    now,
                    redact_text(brief, max_chars=6000),
                    _json(redact_mapping(metadata or {})),
                ),
            )
            row = conn.execute(
                "SELECT * FROM resume_briefs WHERE id = ?", (brief_id,)
            ).fetchone()
        if row is None:
            raise StorageError("Resume brief was not stored.")
        self.append_event(
            "restore_brief_created",
            "Resume brief created from imported checkpoint",
            checkpoint_ref=checkpoint_id,
            details={"brief_id": brief_id, "checkpoint_id": checkpoint_id},
            idempotency_key=f"resume-brief:{brief_id}",
        )
        return self._resume_row(dict(row))

    @staticmethod
    def _resume_row(item: dict[str, Any]) -> dict[str, Any]:
        item["metadata"] = _loads(item.pop("metadata_json", "{}"), {})
        item["active"] = bool(item.get("active"))
        return item

    def active_resume_brief(self) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM resume_briefs WHERE active = 1 "
                "ORDER BY created_at DESC LIMIT 1"
            ).fetchone()
        return self._resume_row(dict(row)) if row is not None else None

    def mark_resume_injected(self, brief_id: str, session_id: str) -> None:
        with self._write() as conn:
            conn.execute(
                "UPDATE resume_briefs SET last_injected_session = ? WHERE id = ?",
                (session_id or "", brief_id),
            )

    def dismiss_resume_brief(self, brief_id: str) -> None:
        with self._write() as conn:
            conn.execute(
                "UPDATE resume_briefs SET active = 0, dismissed_at = ? WHERE id = ?",
                (utc_now_iso(), brief_id),
            )

    # ------------------------------------------------------------------
    # Checkpoint snapshot import/export
    # ------------------------------------------------------------------
    _EXPORT_TABLES: tuple[tuple[str, str, int], ...] = (
        ("events", "id ASC", 5000),
        ("sources", "first_seen_utc ASC", 2000),
        ("episodes", "captured_at ASC", 2000),
        ("memory_facts", "created_at ASC", 2000),
        ("security_decisions", "created_at ASC", 2000),
        ("checkpoints", "created_at ASC", 500),
        ("dream_runs", "started_at ASC", 500),
        ("attack_lab_runs", "run_at ASC", 200),
        ("resume_briefs", "created_at ASC", 200),
        ("kairos_snapshots", "captured_at ASC", 200),
        ("kairos_diffs", "checked_at ASC", 200),
        ("aletheia_receipts", "created_at ASC", 2000),
        ("aletheia_protected", "created_at ASC", 500),
        ("aletheia_challenges", "created_at ASC", 500),
        ("telos_charters", "created_at ASC", 500),
        ("telos_amendments", "created_at ASC", 500),
        ("telos_drift", "created_at ASC", 500),
        ("telos_completions", "created_at ASC", 500),
        ("moirai_previews", "created_at ASC", 500),
        ("metis_failures", "created_at ASC", 2000),
        ("metis_circuits", "created_at ASC", 500),
        ("playbooks", "created_at ASC", 500),
        ("safety_leases", "issued_at ASC", 1000),
        ("safety_lease_usage", "first_seen_at ASC", 2000),
    )

    def export_snapshot(self) -> dict[str, Any]:
        """Return a bounded, redacted snapshot of plugin-owned tables.

        Raw tool results and Hermes private session data are never in these
        tables.  The caller encrypts the returned payload before writing it.
        """
        data: dict[str, list[dict[str, Any]]] = {}
        counts: dict[str, int] = {}
        available: dict[str, int] = {}
        truncated: dict[str, int] = {}
        with self._lock:
            for table, order, limit in self._EXPORT_TABLES:
                total_row = self._conn.execute(
                    f"SELECT COUNT(*) AS c FROM {table}"
                ).fetchone()
                total = int(total_row["c"]) if total_row else 0
                rows = self._conn.execute(
                    f"SELECT * FROM {table} ORDER BY {order} LIMIT ?", (limit,)
                ).fetchall()
                available[table] = total
                data[table] = [dict(row) for row in rows]
                counts[table] = len(rows)
                if total > len(rows):
                    truncated[table] = total - len(rows)
        return {
            "data": data,
            "counts": counts,
            "available": available,
            "truncated": truncated,
        }

    _IMPORT_COLUMNS: dict[str, tuple[str, ...]] = {
        "events": (
            "event_id",
            "event_type",
            "timestamp_utc",
            "session_id",
            "turn_id",
            "task_id",
            "tool_call_id",
            "device_id",
            "source_ref",
            "trust_label",
            "sensitivity",
            "memory_ref",
            "security_decision",
            "checkpoint_ref",
            "payload_ref",
            "schema_version",
            "summary",
            "details_json",
            "idempotency_key",
            "created_at",
        ),
        "sources": (
            "id",
            "event_id",
            "session_id",
            "turn_id",
            "task_id",
            "tool_call_id",
            "tool_name",
            "source_type",
            "reference",
            "trust_label",
            "provenance_confidence",
            "sensitivity",
            "first_seen_utc",
            "last_seen_utc",
            "details_json",
        ),
        "episodes": (
            "id",
            "event_id",
            "session_id",
            "turn_id",
            "task_id",
            "captured_at",
            "reason",
            "user_excerpt",
            "assistant_excerpt",
            "source_ref",
            "trust_label",
            "sensitivity",
            "content_hash",
            "metadata_json",
            "dream_run_id",
            "created_at",
        ),
        "memory_facts": (
            "id",
            "fact_key",
            "value",
            "status",
            "confidence",
            "source_ref",
            "source_event_id",
            "episode_id",
            "first_observed_utc",
            "last_observed_utc",
            "confirmed_at",
            "superseded_by",
            "contradicts_fact_id",
            "version",
            "provenance",
            "notes",
            "created_at",
            "updated_at",
            "reviewed_by",
            "verification_state",
            "evidence_ref",
        ),
        "security_decisions": (
            "id",
            "event_id",
            "rule_key",
            "policy_version",
            "tool_name",
            "action_category",
            "outcome",
            "reason",
            "evidence_json",
            "redacted_args_json",
            "session_id",
            "tool_call_id",
            "created_at",
        ),
        "checkpoints": (
            "id",
            "created_at",
            "filename",
            "format_version",
            "source_installation_id",
            "counts_json",
            "excluded_json",
            "checksum",
            "status",
            "imported_at",
            "metadata_json",
            "resume_brief_id",
        ),
        "dream_runs": (
            "id",
            "started_at",
            "completed_at",
            "status",
            "from_event_id",
            "to_event_id",
            "episodes_processed",
            "candidates_created",
            "contradictions_json",
            "report_json",
        ),
        "attack_lab_runs": (
            "id",
            "run_at",
            "policy_version",
            "suite",
            "total",
            "passed",
            "results_json",
        ),
        "resume_briefs": (
            "id",
            "checkpoint_id",
            "created_at",
            "brief",
            "metadata_json",
            "active",
            "last_injected_session",
            "dismissed_at",
        ),
        "kairos_snapshots": (
            "id",
            "event_id",
            "session_id",
            "task_id",
            "checkpoint_ref",
            "label",
            "scope_path",
            "captured_at",
            "fingerprint_hash",
            "fingerprint_json",
            "details_json",
            "created_at",
        ),
        "kairos_diffs": (
            "id",
            "event_id",
            "snapshot_id",
            "checkpoint_id",
            "session_id",
            "task_id",
            "checked_at",
            "level",
            "changed_json",
            "unverified_json",
            "summary",
            "details_json",
            "created_at",
        ),
        "aletheia_receipts": (
            "id",
            "event_id",
            "session_id",
            "task_id",
            "artifact_ref",
            "artifact_type",
            "verification_method",
            "observed_result",
            "scope",
            "content_hash",
            "environment_hash",
            "environment_snapshot_id",
            "source_ref",
            "trust_label",
            "provenance",
            "verified",
            "status",
            "receipt_json",
            "memory_ref",
            "superseded_by",
            "stale_reason",
            "verified_at",
            "staled_at",
            "created_at",
        ),
        "aletheia_protected": (
            "id",
            "event_id",
            "artifact_ref",
            "artifact_type",
            "receipt_id",
            "scope",
            "active",
            "created_at",
            "released_at",
            "release_reason",
            "metadata_json",
        ),
        "aletheia_challenges": (
            "id",
            "event_id",
            "artifact_ref",
            "protected_id",
            "tool_name",
            "action_ref",
            "reason",
            "status",
            "required_evidence_json",
            "resolution",
            "created_at",
            "resolved_at",
            "metadata_json",
        ),
        "telos_charters": (
            "id",
            "root_id",
            "session_id",
            "task_id",
            "version",
            "parent_id",
            "original_request",
            "constraints_json",
            "success_criteria_json",
            "subgoals_json",
            "status",
            "provenance",
            "source_ref",
            "metadata_json",
            "created_at",
            "updated_at",
        ),
        "telos_amendments": (
            "id",
            "event_id",
            "charter_id",
            "prior_charter_id",
            "amendment",
            "rationale",
            "approved_by",
            "trust_label",
            "created_at",
        ),
        "telos_drift": (
            "id",
            "event_id",
            "charter_id",
            "kind",
            "severity",
            "detail",
            "tool_name",
            "status",
            "created_at",
        ),
        "telos_completions": (
            "id",
            "event_id",
            "charter_id",
            "claimed_complete",
            "outcome",
            "score",
            "criteria_json",
            "evidence_json",
            "created_at",
        ),
        "moirai_previews": (
            "id",
            "event_id",
            "session_id",
            "task_id",
            "tool_name",
            "action_category",
            "level",
            "proposed_action",
            "targets_json",
            "creates_json",
            "modifies_json",
            "deletes_json",
            "external_json",
            "payload_summary",
            "irreversible_json",
            "unknowns_json",
            "confidence",
            "adapter",
            "evidence_json",
            "status",
            "created_at",
        ),
        "metis_failures": (
            "id",
            "event_id",
            "session_id",
            "task_id",
            "tool_name",
            "signature",
            "args_hash",
            "error_category",
            "error_signature",
            "target_ref",
            "attempt_count",
            "made_progress",
            "details_json",
            "created_at",
        ),
        "metis_circuits": (
            "id",
            "event_id",
            "signature",
            "args_hash",
            "tool_name",
            "target_ref",
            "status",
            "failure_count",
            "threshold",
            "reason",
            "alternatives_json",
            "opened_at",
            "last_failure_at",
            "expires_at",
            "closed_at",
            "created_at",
            "updated_at",
        ),
        "playbooks": (
            "id",
            "slug",
            "name",
            "version",
            "description",
            "status",
            "source_session_id",
            "source_task_id",
            "source_event_start",
            "source_event_end",
            "confidence",
            "steps_attempted",
            "steps_succeeded",
            "trace_hash",
            "trace_json",
            "skill_path",
            "skill_sha256",
            "blueprint_key",
            "blueprint_json",
            "lease_id",
            "environment_hash",
            "quarantine_reason",
            "metadata_json",
            "created_at",
            "updated_at",
        ),
        "safety_leases": (
            "id",
            "playbook_id",
            "status",
            "lease_hash",
            "allowed_tools_json",
            "allowed_paths_json",
            "allowed_domains_json",
            "allow_opaque_tools",
            "max_tool_calls",
            "max_file_writes",
            "max_external_calls",
            "cron_job_id",
            "environment_hash",
            "issued_by",
            "issued_at",
            "expires_at",
            "revoked_at",
            "revoked_reason",
            "metadata_json",
        ),
        "safety_lease_usage": (
            "id",
            "lease_id",
            "run_id",
            "cron_job_id",
            "tool_calls",
            "file_writes",
            "external_calls",
            "first_seen_at",
            "updated_at",
            "last_tool",
            "metadata_json",
        ),
    }

    @staticmethod
    def _coerce_import_row(table: str, row: dict[str, Any]) -> dict[str, Any] | None:
        if not isinstance(row, dict):
            return None
        result = dict(row)
        # Accept both raw column names and the friendly names returned by some
        # older snapshots.  Serialize structured values into their JSON column.
        json_aliases = {
            "details": "details_json",
            "metadata": "metadata_json",
            "counts": "counts_json",
            "excluded": "excluded_json",
            "contradictions": "contradictions_json",
            "report": "report_json",
            "results": "results_json",
            "evidence": "evidence_json",
            "redacted_args": "redacted_args_json",
            "trace": "trace_json",
            "blueprint": "blueprint_json",
            "allowed_tools": "allowed_tools_json",
            "allowed_paths": "allowed_paths_json",
            "allowed_domains": "allowed_domains_json",
        }
        for friendly, column in json_aliases.items():
            if column not in result and friendly in result:
                value = result[friendly]
                result[column] = _json(value) if not isinstance(value, str) else value
        for column in (
            "details_json",
            "metadata_json",
            "counts_json",
            "excluded_json",
            "contradictions_json",
            "report_json",
            "results_json",
            "evidence_json",
            "redacted_args_json",
            "trace_json",
            "blueprint_json",
            "allowed_tools_json",
            "allowed_paths_json",
            "allowed_domains_json",
        ):
            value = result.get(column)
            if isinstance(value, (dict, list)):
                result[column] = _json(value)
        if table == "events":
            result.pop("id", None)
            if not result.get("event_id"):
                return None
            if not result.get("event_type"):
                return None
            result.setdefault("timestamp_utc", utc_now_iso())
            result.setdefault("created_at", result["timestamp_utc"])
            result.setdefault("summary", str(result["event_type"]))
            result.setdefault("schema_version", SCHEMA_VERSION)
            result.setdefault("device_id", "inst_unknown")
        else:
            if not result.get("id"):
                return None
        if table == "resume_briefs":
            result["active"] = 0
        if table == "checkpoints":
            result["status"] = "imported"
            result["imported_at"] = utc_now_iso()
        return result

    def import_snapshot(self, data: dict[str, Any]) -> dict[str, Any]:
        """Import a decrypted snapshot without replaying any side effect.

        Existing rows win.  This is a restore of records, not an execution of
        historical actions.
        """
        if not isinstance(data, dict):
            raise StorageError("Checkpoint payload is not an object.")
        inserted: dict[str, int] = {}
        skipped: dict[str, int] = {}
        with self._write() as conn:
            for table, columns in self._IMPORT_COLUMNS.items():
                rows = data.get(table) or []
                if not isinstance(rows, list):
                    raise StorageError(f"Checkpoint table {table} is not a list.")
                table_inserted = 0
                table_skipped = 0
                for raw_row in rows:
                    row = self._coerce_import_row(table, raw_row)
                    if row is None:
                        table_skipped += 1
                        continue
                    usable_columns = [column for column in columns if column in row]
                    if not usable_columns:
                        table_skipped += 1
                        continue
                    placeholders = ",".join("?" for _ in usable_columns)
                    column_sql = ",".join(usable_columns)
                    try:
                        cursor = conn.execute(
                            f"INSERT OR IGNORE INTO {table}({column_sql}) "
                            f"VALUES ({placeholders})",
                            [row[column] for column in usable_columns],
                        )
                    except sqlite3.Error as exc:
                        raise StorageError(
                            f"Checkpoint import failed for table {table}: {exc}"
                        ) from exc
                    if cursor.rowcount:
                        table_inserted += 1
                    else:
                        table_skipped += 1
                inserted[table] = table_inserted
                skipped[table] = table_skipped
        return {"inserted": inserted, "skipped": skipped}


    # ------------------------------------------------------------------
    # Kairos: environment fingerprints and reality diffs
    # ------------------------------------------------------------------
    def record_kairos_snapshot(
        self,
        *,
        snapshot_id: str,
        captured_at: str,
        scope_path: str,
        fingerprint_hash: str,
        fingerprint: dict[str, Any],
        label: str = "",
        session_id: str | None = None,
        task_id: str | None = None,
        checkpoint_ref: str | None = None,
        details: dict[str, Any] | None = None,
        event_id: str | None = None,
    ) -> dict[str, Any]:
        now = utc_now_iso()
        with self._write() as conn:
            conn.execute(
                """
                INSERT INTO kairos_snapshots(
                    id, event_id, session_id, task_id, checkpoint_ref, label,
                    scope_path, captured_at, fingerprint_hash, fingerprint_json,
                    details_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot_id,
                    event_id,
                    session_id,
                    task_id,
                    checkpoint_ref,
                    redact_text(label, max_chars=120),
                    redact_text(scope_path, max_chars=500),
                    captured_at,
                    fingerprint_hash,
                    _json(redact_mapping(fingerprint)),
                    _json(redact_mapping(details or {})),
                    now,
                ),
            )
            row = conn.execute(
                "SELECT * FROM kairos_snapshots WHERE id = ?", (snapshot_id,)
            ).fetchone()
        return _decode_system_row(dict(row))

    def link_kairos_checkpoint(self, snapshot_id: str, checkpoint_id: str) -> None:
        with self._write() as conn:
            conn.execute(
                "UPDATE kairos_snapshots SET checkpoint_ref = ? WHERE id = ?",
                (checkpoint_id, snapshot_id),
            )

    def get_kairos_snapshot(self, snapshot_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM kairos_snapshots WHERE id = ?", (snapshot_id,)
            ).fetchone()
        return _decode_system_row(dict(row)) if row is not None else None

    def latest_kairos_snapshot(self) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM kairos_snapshots ORDER BY captured_at DESC, id DESC LIMIT 1"
            ).fetchone()
        return _decode_system_row(dict(row)) if row is not None else None

    def list_kairos_snapshots(self, *, limit: int = 50) -> list[dict[str, Any]]:
        limit = max(1, min(500, int(limit)))
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM kairos_snapshots ORDER BY captured_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return _decode_system_rows([dict(row) for row in rows])

    def record_kairos_diff(
        self,
        *,
        diff_id: str,
        checked_at: str,
        level: str,
        changed: list[dict[str, Any]],
        unverified: list[str],
        summary: str,
        snapshot_id: str | None = None,
        checkpoint_id: str | None = None,
        session_id: str | None = None,
        task_id: str | None = None,
        details: dict[str, Any] | None = None,
        event_id: str | None = None,
    ) -> dict[str, Any]:
        with self._write() as conn:
            conn.execute(
                """
                INSERT INTO kairos_diffs(
                    id, event_id, snapshot_id, checkpoint_id, session_id, task_id,
                    checked_at, level, changed_json, unverified_json, summary,
                    details_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    diff_id,
                    event_id,
                    snapshot_id,
                    checkpoint_id,
                    session_id,
                    task_id,
                    checked_at,
                    level,
                    _json(redact_mapping(changed)),
                    _json([redact_text(item, max_chars=300) for item in unverified]),
                    redact_text(summary, max_chars=1000),
                    _json(redact_mapping(details or {})),
                    utc_now_iso(),
                ),
            )
            row = conn.execute(
                "SELECT * FROM kairos_diffs WHERE id = ?", (diff_id,)
            ).fetchone()
        return _decode_system_row(dict(row))

    def get_kairos_diff(self, diff_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM kairos_diffs WHERE id = ?", (diff_id,)
            ).fetchone()
        return _decode_system_row(dict(row)) if row is not None else None

    def list_kairos_diffs(self, *, limit: int = 50) -> list[dict[str, Any]]:
        limit = max(1, min(500, int(limit)))
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM kairos_diffs ORDER BY checked_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return _decode_system_rows([dict(row) for row in rows])

    # ------------------------------------------------------------------
    # Aletheia: evidence receipts, protections, and challenges
    # ------------------------------------------------------------------
    def record_evidence_receipt(
        self,
        *,
        receipt_id: str,
        artifact_ref: str,
        artifact_type: str,
        verification_method: str,
        observed_result: str,
        scope: str,
        verified: bool,
        status: str,
        content_hash: str | None = None,
        environment_hash: str | None = None,
        environment_snapshot_id: str | None = None,
        source_ref: str | None = None,
        trust_label: str = "PLUGIN_GENERATED",
        provenance: str = "PLUGIN_GENERATED",
        receipt: dict[str, Any] | None = None,
        memory_ref: str | None = None,
        session_id: str | None = None,
        task_id: str | None = None,
        event_id: str | None = None,
    ) -> dict[str, Any]:
        now = utc_now_iso()
        with self._write() as conn:
            conn.execute(
                """
                INSERT INTO aletheia_receipts(
                    id, event_id, session_id, task_id, artifact_ref, artifact_type,
                    verification_method, observed_result, scope, content_hash,
                    environment_hash, environment_snapshot_id, source_ref,
                    trust_label, provenance, verified, status, receipt_json,
                    memory_ref, verified_at, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    receipt_id,
                    event_id,
                    session_id,
                    task_id,
                    redact_text(artifact_ref, max_chars=1000),
                    redact_text(artifact_type, max_chars=80),
                    redact_text(verification_method, max_chars=120),
                    redact_text(observed_result, max_chars=2000),
                    redact_text(scope, max_chars=1000),
                    content_hash,
                    environment_hash,
                    environment_snapshot_id,
                    source_ref,
                    trust_label,
                    provenance,
                    1 if verified else 0,
                    status,
                    _json(redact_mapping(receipt or {})),
                    memory_ref,
                    now if verified else None,
                    now,
                ),
            )
            row = conn.execute(
                "SELECT * FROM aletheia_receipts WHERE id = ?", (receipt_id,)
            ).fetchone()
        return _decode_system_row(dict(row))

    def update_evidence_receipt(
        self,
        receipt_id: str,
        *,
        status: str | None = None,
        verified: bool | None = None,
        stale_reason: str | None = None,
        superseded_by: str | None = None,
    ) -> dict[str, Any] | None:
        fields: list[str] = []
        params: list[Any] = []
        if status is not None:
            fields.append("status = ?")
            params.append(status)
            if status == "stale":
                fields.append("staled_at = ?")
                params.append(utc_now_iso())
        if verified is not None:
            fields.append("verified = ?")
            params.append(1 if verified else 0)
            if verified:
                fields.append("verified_at = COALESCE(verified_at, ?)")
                params.append(utc_now_iso())
        if stale_reason is not None:
            fields.append("stale_reason = ?")
            params.append(redact_text(stale_reason, max_chars=1000))
        if superseded_by is not None:
            fields.append("superseded_by = ?")
            params.append(superseded_by)
        if not fields:
            return self.get_evidence_receipt(receipt_id)
        params.append(receipt_id)
        with self._write() as conn:
            conn.execute(
                f"UPDATE aletheia_receipts SET {', '.join(fields)} WHERE id = ?",
                params,
            )
            row = conn.execute(
                "SELECT * FROM aletheia_receipts WHERE id = ?", (receipt_id,)
            ).fetchone()
        return _decode_system_row(dict(row)) if row is not None else None

    def get_evidence_receipt(self, receipt_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM aletheia_receipts WHERE id = ?", (receipt_id,)
            ).fetchone()
        return _decode_system_row(dict(row)) if row is not None else None

    def list_evidence_receipts(
        self,
        *,
        artifact_ref: str | None = None,
        status: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        limit = max(1, min(500, int(limit)))
        clauses: list[str] = []
        params: list[Any] = []
        if artifact_ref:
            clauses.append("artifact_ref = ?")
            params.append(artifact_ref)
        if status:
            clauses.append("status = ?")
            params.append(status)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM aletheia_receipts{where} "
                "ORDER BY created_at DESC LIMIT ?",
                params,
            ).fetchall()
        return _decode_system_rows([dict(row) for row in rows])

    def stale_evidence_for_environment(
        self, environment_hash: str, *, reason: str
    ) -> list[dict[str, Any]]:
        now = utc_now_iso()
        with self._write() as conn:
            rows = conn.execute(
                "SELECT * FROM aletheia_receipts WHERE environment_hash = ? "
                "AND status = 'current'",
                (environment_hash,),
            ).fetchall()
            ids = [str(row["id"]) for row in rows]
            if ids:
                placeholders = ",".join("?" for _ in ids)
                conn.execute(
                    f"UPDATE aletheia_receipts SET status = 'stale', staled_at = ?, "
                    f"stale_reason = ? WHERE id IN ({placeholders})",
                    [now, redact_text(reason, max_chars=1000), *ids],
                )
        return [
            _decode_system_row({**dict(row), "status": "stale", "staled_at": now, "stale_reason": reason})
            for row in rows
        ]

    def protect_artifact(
        self,
        *,
        protected_id: str,
        artifact_ref: str,
        artifact_type: str = "artifact",
        receipt_id: str | None = None,
        scope: str = "",
        metadata: dict[str, Any] | None = None,
        event_id: str | None = None,
    ) -> dict[str, Any] | None:
        now = utc_now_iso()
        with self._write() as conn:
            existing = conn.execute(
                "SELECT * FROM aletheia_protected WHERE artifact_ref = ? AND active = 1",
                (artifact_ref,),
            ).fetchone()
            if existing is not None:
                return _decode_system_row(dict(existing))
            conn.execute(
                """
                INSERT INTO aletheia_protected(
                    id, event_id, artifact_ref, artifact_type, receipt_id, scope,
                    active, created_at, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
                """,
                (
                    protected_id,
                    event_id,
                    redact_text(artifact_ref, max_chars=1000),
                    redact_text(artifact_type, max_chars=80),
                    receipt_id,
                    redact_text(scope, max_chars=1000),
                    now,
                    _json(redact_mapping(metadata or {})),
                ),
            )
            row = conn.execute(
                "SELECT * FROM aletheia_protected WHERE id = ?", (protected_id,)
            ).fetchone()
        return _decode_system_row(dict(row))

    def get_protected_artifact(self, protected_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM aletheia_protected WHERE id = ?", (protected_id,)
            ).fetchone()
        return _decode_system_row(dict(row)) if row is not None else None

    def find_active_protection(self, artifact_ref: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM aletheia_protected WHERE artifact_ref = ? AND active = 1",
                (artifact_ref,),
            ).fetchone()
        return _decode_system_row(dict(row)) if row is not None else None

    def list_protected_artifacts(self, *, limit: int = 100) -> list[dict[str, Any]]:
        limit = max(1, min(500, int(limit)))
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM aletheia_protected ORDER BY active DESC, created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return _decode_system_rows([dict(row) for row in rows])

    def release_protected_artifact(
        self, protected_id: str, *, reason: str = ""
    ) -> dict[str, Any] | None:
        with self._write() as conn:
            conn.execute(
                "UPDATE aletheia_protected SET active = 0, released_at = ?, "
                "release_reason = ? WHERE id = ?",
                (utc_now_iso(), redact_text(reason, max_chars=1000), protected_id),
            )
            row = conn.execute(
                "SELECT * FROM aletheia_protected WHERE id = ?", (protected_id,)
            ).fetchone()
        return _decode_system_row(dict(row)) if row is not None else None

    def record_evidence_challenge(
        self,
        *,
        challenge_id: str,
        artifact_ref: str,
        reason: str,
        status: str = "held",
        protected_id: str | None = None,
        tool_name: str | None = None,
        action_ref: str | None = None,
        required_evidence: list[Any] | None = None,
        metadata: dict[str, Any] | None = None,
        event_id: str | None = None,
    ) -> dict[str, Any]:
        with self._write() as conn:
            conn.execute(
                """
                INSERT INTO aletheia_challenges(
                    id, event_id, artifact_ref, protected_id, tool_name, action_ref,
                    reason, status, required_evidence_json, created_at, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    challenge_id,
                    event_id,
                    redact_text(artifact_ref, max_chars=1000),
                    protected_id,
                    tool_name,
                    action_ref,
                    redact_text(reason, max_chars=2000),
                    status,
                    _json(redact_mapping(required_evidence or [])),
                    utc_now_iso(),
                    _json(redact_mapping(metadata or {})),
                ),
            )
            row = conn.execute(
                "SELECT * FROM aletheia_challenges WHERE id = ?", (challenge_id,)
            ).fetchone()
        return _decode_system_row(dict(row))

    def resolve_evidence_challenge(
        self, challenge_id: str, *, status: str, resolution: str = ""
    ) -> dict[str, Any] | None:
        with self._write() as conn:
            conn.execute(
                "UPDATE aletheia_challenges SET status = ?, resolution = ?, "
                "resolved_at = ? WHERE id = ?",
                (status, redact_text(resolution, max_chars=2000), utc_now_iso(), challenge_id),
            )
            row = conn.execute(
                "SELECT * FROM aletheia_challenges WHERE id = ?", (challenge_id,)
            ).fetchone()
        return _decode_system_row(dict(row)) if row is not None else None

    def list_evidence_challenges(self, *, limit: int = 100) -> list[dict[str, Any]]:
        limit = max(1, min(500, int(limit)))
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM aletheia_challenges ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return _decode_system_rows([dict(row) for row in rows])

    # ------------------------------------------------------------------
    # Telos: charters, amendments, drift, completion
    # ------------------------------------------------------------------
    def record_charter(
        self,
        *,
        charter_id: str,
        root_id: str,
        original_request: str,
        constraints: list[str],
        success_criteria: list[str],
        subgoals: list[dict[str, Any]],
        version: int = 1,
        parent_id: str | None = None,
        session_id: str | None = None,
        task_id: str | None = None,
        status: str = "active",
        provenance: str = "USER_AUTHORED",
        source_ref: str | None = None,
        metadata: dict[str, Any] | None = None,
        event_id: str | None = None,
    ) -> dict[str, Any]:
        now = utc_now_iso()
        with self._write() as conn:
            conn.execute(
                """
                INSERT INTO telos_charters(
                    id, root_id, session_id, task_id, version, parent_id,
                    original_request, constraints_json, success_criteria_json,
                    subgoals_json, status, provenance, source_ref, metadata_json,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    charter_id,
                    root_id,
                    session_id,
                    task_id,
                    int(version),
                    parent_id,
                    redact_text(original_request, max_chars=4000),
                    _json([redact_text(item, max_chars=500) for item in constraints[:30]]),
                    _json([redact_text(item, max_chars=500) for item in success_criteria[:30]]),
                    _json(redact_mapping(subgoals[:30])),
                    status,
                    provenance,
                    source_ref,
                    _json(redact_mapping(metadata or {})),
                    now,
                    now,
                ),
            )
            row = conn.execute(
                "SELECT * FROM telos_charters WHERE id = ?", (charter_id,)
            ).fetchone()
        return _decode_system_row(dict(row))

    def get_charter(self, charter_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM telos_charters WHERE id = ?", (charter_id,)
            ).fetchone()
        return _decode_system_row(dict(row)) if row is not None else None

    def find_active_charter(
        self, *, session_id: str | None = None, task_id: str | None = None
    ) -> dict[str, Any] | None:
        clauses = ["status = 'active'"]
        params: list[Any] = []
        if session_id:
            clauses.append("session_id = ?")
            params.append(session_id)
        if task_id:
            clauses.append("task_id = ?")
            params.append(task_id)
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM telos_charters WHERE "
                + " AND ".join(clauses)
                + " ORDER BY version DESC, updated_at DESC LIMIT 1",
                params,
            ).fetchone()
        return _decode_system_row(dict(row)) if row is not None else None

    def latest_charter_for_root(self, root_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM telos_charters WHERE root_id = ? "
                "ORDER BY version DESC, updated_at DESC LIMIT 1",
                (root_id,),
            ).fetchone()
        return _decode_system_row(dict(row)) if row is not None else None

    def list_charters(self, *, limit: int = 100) -> list[dict[str, Any]]:
        limit = max(1, min(500, int(limit)))
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM telos_charters ORDER BY updated_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return _decode_system_rows([dict(row) for row in rows])

    def mark_charter_status(self, charter_id: str, status: str) -> None:
        with self._write() as conn:
            conn.execute(
                "UPDATE telos_charters SET status = ?, updated_at = ? WHERE id = ?",
                (status, utc_now_iso(), charter_id),
            )

    def update_charter_subgoals(
        self, charter_id: str, subgoals: list[dict[str, Any]]
    ) -> None:
        with self._write() as conn:
            conn.execute(
                "UPDATE telos_charters SET subgoals_json = ?, updated_at = ? WHERE id = ?",
                (_json(redact_mapping(subgoals[:30])), utc_now_iso(), charter_id),
            )

    def record_charter_amendment(
        self,
        *,
        amendment_id: str,
        charter_id: str,
        amendment: str,
        rationale: str = "",
        prior_charter_id: str | None = None,
        approved_by: str = "user",
        trust_label: str = "USER_AUTHORED",
        event_id: str | None = None,
    ) -> dict[str, Any]:
        with self._write() as conn:
            conn.execute(
                """
                INSERT INTO telos_amendments(
                    id, event_id, charter_id, prior_charter_id, amendment,
                    rationale, approved_by, trust_label, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    amendment_id,
                    event_id,
                    charter_id,
                    prior_charter_id,
                    redact_text(amendment, max_chars=4000),
                    redact_text(rationale, max_chars=2000),
                    approved_by,
                    trust_label,
                    utc_now_iso(),
                ),
            )
            row = conn.execute(
                "SELECT * FROM telos_amendments WHERE id = ?", (amendment_id,)
            ).fetchone()
        return _decode_system_row(dict(row))

    def list_charter_amendments(self, *, limit: int = 100) -> list[dict[str, Any]]:
        limit = max(1, min(500, int(limit)))
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM telos_amendments ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return _decode_system_rows([dict(row) for row in rows])

    def record_telos_drift(
        self,
        *,
        drift_id: str,
        charter_id: str,
        kind: str,
        detail: str,
        severity: str = "low",
        tool_name: str | None = None,
        status: str = "open",
        event_id: str | None = None,
    ) -> dict[str, Any]:
        with self._write() as conn:
            conn.execute(
                """
                INSERT INTO telos_drift(
                    id, event_id, charter_id, kind, severity, detail, tool_name,
                    status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    drift_id,
                    event_id,
                    charter_id,
                    kind,
                    severity,
                    redact_text(detail, max_chars=2000),
                    tool_name,
                    status,
                    utc_now_iso(),
                ),
            )
            row = conn.execute(
                "SELECT * FROM telos_drift WHERE id = ?", (drift_id,)
            ).fetchone()
        return _decode_system_row(dict(row))

    def list_telos_drift(
        self, *, charter_id: str | None = None, limit: int = 100
    ) -> list[dict[str, Any]]:
        limit = max(1, min(500, int(limit)))
        if charter_id:
            with self._lock:
                rows = self._conn.execute(
                    "SELECT * FROM telos_drift WHERE charter_id = ? "
                    "ORDER BY created_at DESC LIMIT ?",
                    (charter_id, limit),
                ).fetchall()
        else:
            with self._lock:
                rows = self._conn.execute(
                    "SELECT * FROM telos_drift ORDER BY created_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
        return _decode_system_rows([dict(row) for row in rows])

    def record_completion_assessment(
        self,
        *,
        assessment_id: str,
        charter_id: str,
        claimed_complete: bool,
        outcome: str,
        score: int,
        criteria: list[dict[str, Any]],
        evidence: list[Any],
        event_id: str | None = None,
    ) -> dict[str, Any]:
        with self._write() as conn:
            conn.execute(
                """
                INSERT INTO telos_completions(
                    id, event_id, charter_id, claimed_complete, outcome, score,
                    criteria_json, evidence_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    assessment_id,
                    event_id,
                    charter_id,
                    1 if claimed_complete else 0,
                    outcome,
                    max(0, min(100, int(score))),
                    _json(redact_mapping(criteria)),
                    _json(redact_mapping(evidence)),
                    utc_now_iso(),
                ),
            )
            row = conn.execute(
                "SELECT * FROM telos_completions WHERE id = ?", (assessment_id,)
            ).fetchone()
        return _decode_system_row(dict(row))

    def list_completion_assessments(self, *, limit: int = 100) -> list[dict[str, Any]]:
        limit = max(1, min(500, int(limit)))
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM telos_completions ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return _decode_system_rows([dict(row) for row in rows])

    # ------------------------------------------------------------------
    # Moirai: impact previews
    # ------------------------------------------------------------------
    def record_impact_preview(
        self,
        *,
        preview_id: str,
        tool_name: str,
        action_category: str,
        level: str,
        proposed_action: str,
        targets: list[Any],
        creates: list[Any],
        modifies: list[Any],
        deletes: list[Any],
        external: list[Any],
        payload_summary: str,
        irreversible: list[Any],
        unknowns: list[Any],
        confidence: float,
        adapter: str,
        evidence: list[Any],
        session_id: str | None = None,
        task_id: str | None = None,
        status: str = "advisory",
        event_id: str | None = None,
    ) -> dict[str, Any]:
        with self._write() as conn:
            conn.execute(
                """
                INSERT INTO moirai_previews(
                    id, event_id, session_id, task_id, tool_name, action_category,
                    level, proposed_action, targets_json, creates_json,
                    modifies_json, deletes_json, external_json, payload_summary,
                    irreversible_json, unknowns_json, confidence, adapter,
                    evidence_json, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    preview_id,
                    event_id,
                    session_id,
                    task_id,
                    redact_text(tool_name, max_chars=120),
                    action_category,
                    level,
                    redact_text(proposed_action, max_chars=1000),
                    _json(redact_mapping(targets[:200])),
                    _json(redact_mapping(creates[:200])),
                    _json(redact_mapping(modifies[:200])),
                    _json(redact_mapping(deletes[:200])),
                    _json(redact_mapping(external[:200])),
                    redact_text(payload_summary, max_chars=2000),
                    _json(redact_mapping(irreversible[:100])),
                    _json(redact_mapping(unknowns[:100])),
                    max(0.0, min(1.0, float(confidence))),
                    adapter,
                    _json(redact_mapping(evidence[:100])),
                    status,
                    utc_now_iso(),
                ),
            )
            row = conn.execute(
                "SELECT * FROM moirai_previews WHERE id = ?", (preview_id,)
            ).fetchone()
        return _decode_system_row(dict(row))

    def get_impact_preview(self, preview_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM moirai_previews WHERE id = ?", (preview_id,)
            ).fetchone()
        return _decode_system_row(dict(row)) if row is not None else None

    def list_impact_previews(self, *, limit: int = 100) -> list[dict[str, Any]]:
        limit = max(1, min(500, int(limit)))
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM moirai_previews ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return _decode_system_rows([dict(row) for row in rows])

    # ------------------------------------------------------------------
    # Metis: failures and circuits
    # ------------------------------------------------------------------
    def record_failure_observation(
        self,
        *,
        observation_id: str,
        tool_name: str,
        signature: str,
        args_hash: str,
        error_category: str,
        error_signature: str,
        attempt_count: int,
        target_ref: str | None = None,
        made_progress: bool = False,
        session_id: str | None = None,
        task_id: str | None = None,
        details: dict[str, Any] | None = None,
        event_id: str | None = None,
    ) -> dict[str, Any]:
        with self._write() as conn:
            conn.execute(
                """
                INSERT INTO metis_failures(
                    id, event_id, session_id, task_id, tool_name, signature,
                    args_hash, error_category, error_signature, target_ref,
                    attempt_count, made_progress, details_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    observation_id,
                    event_id,
                    session_id,
                    task_id,
                    redact_text(tool_name, max_chars=120),
                    signature,
                    args_hash,
                    error_category,
                    redact_text(error_signature, max_chars=300),
                    redact_text(target_ref or "", max_chars=1000) or None,
                    int(attempt_count),
                    1 if made_progress else 0,
                    _json(redact_mapping(details or {})),
                    utc_now_iso(),
                ),
            )
            row = conn.execute(
                "SELECT * FROM metis_failures WHERE id = ?", (observation_id,)
            ).fetchone()
        return _decode_system_row(dict(row))

    def count_failures(
        self, signature: str, *, since: str | None = None
    ) -> int:
        with self._lock:
            if since:
                row = self._conn.execute(
                    "SELECT COUNT(*) AS c FROM metis_failures WHERE signature = ? "
                    "AND created_at >= ?",
                    (signature, since),
                ).fetchone()
            else:
                row = self._conn.execute(
                    "SELECT COUNT(*) AS c FROM metis_failures WHERE signature = ?",
                    (signature,),
                ).fetchone()
        return int(row["c"]) if row else 0

    def list_failure_observations(
        self, *, tool_name: str | None = None, limit: int = 100
    ) -> list[dict[str, Any]]:
        limit = max(1, min(500, int(limit)))
        if tool_name:
            with self._lock:
                rows = self._conn.execute(
                    "SELECT * FROM metis_failures WHERE tool_name = ? "
                    "ORDER BY created_at DESC LIMIT ?",
                    (tool_name, limit),
                ).fetchall()
        else:
            with self._lock:
                rows = self._conn.execute(
                    "SELECT * FROM metis_failures ORDER BY created_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
        return _decode_system_rows([dict(row) for row in rows])

    def upsert_circuit(
        self,
        *,
        circuit_id: str,
        signature: str,
        args_hash: str,
        tool_name: str,
        failure_count: int,
        threshold: int,
        reason: str,
        alternatives: list[str],
        target_ref: str | None = None,
        expires_at: str | None = None,
        status: str = "open",
        event_id: str | None = None,
    ) -> dict[str, Any]:
        now = utc_now_iso()
        with self._write() as conn:
            conn.execute(
                """
                INSERT INTO metis_circuits(
                    id, event_id, signature, args_hash, tool_name, target_ref,
                    status, failure_count, threshold, reason, alternatives_json,
                    opened_at, last_failure_at, expires_at, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(signature) DO UPDATE SET
                    status = excluded.status,
                    args_hash = excluded.args_hash,
                    failure_count = excluded.failure_count,
                    threshold = excluded.threshold,
                    reason = excluded.reason,
                    alternatives_json = excluded.alternatives_json,
                    last_failure_at = excluded.last_failure_at,
                    expires_at = excluded.expires_at,
                    opened_at = excluded.opened_at,
                    closed_at = NULL,
                    updated_at = excluded.updated_at
                """,
                (
                    circuit_id,
                    event_id,
                    signature,
                    args_hash,
                    redact_text(tool_name, max_chars=120),
                    redact_text(target_ref or "", max_chars=1000) or None,
                    status,
                    int(failure_count),
                    int(threshold),
                    redact_text(reason, max_chars=1000),
                    _json([redact_text(item, max_chars=300) for item in alternatives[:20]]),
                    now,
                    now,
                    expires_at,
                    now,
                    now,
                ),
            )
            row = conn.execute(
                "SELECT * FROM metis_circuits WHERE signature = ?", (signature,)
            ).fetchone()
        return _decode_system_row(dict(row))

    def get_open_circuit(self, signature: str, *, now: str | None = None) -> dict[str, Any] | None:
        now = now or utc_now_iso()
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM metis_circuits WHERE signature = ? AND status = 'open' "
                "AND (expires_at IS NULL OR expires_at > ?)",
                (signature, now),
            ).fetchone()
        return _decode_system_row(dict(row)) if row is not None else None

    def get_open_circuit_for_args(
        self, tool_name: str, args_hash: str
    ) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM metis_circuits WHERE tool_name = ? AND args_hash = ? "
                "AND status = 'open' AND (expires_at IS NULL OR expires_at > ?) "
                "ORDER BY updated_at DESC LIMIT 1",
                (tool_name, args_hash, utc_now_iso()),
            ).fetchone()
        return _decode_system_row(dict(row)) if row is not None else None

    def find_open_circuit_for_tool(self, tool_name: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM metis_circuits WHERE tool_name = ? AND status = 'open' "
                "AND (expires_at IS NULL OR expires_at > ?) "
                "ORDER BY updated_at DESC LIMIT 1",
                (tool_name, utc_now_iso()),
            ).fetchone()
        return _decode_system_row(dict(row)) if row is not None else None

    def get_circuit(self, circuit_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM metis_circuits WHERE id = ?", (circuit_id,)
            ).fetchone()
        return _decode_system_row(dict(row)) if row is not None else None

    def list_circuits(self, *, status: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        limit = max(1, min(500, int(limit)))
        if status:
            with self._lock:
                rows = self._conn.execute(
                    "SELECT * FROM metis_circuits WHERE status = ? "
                    "ORDER BY updated_at DESC LIMIT ?",
                    (status, limit),
                ).fetchall()
        else:
            with self._lock:
                rows = self._conn.execute(
                    "SELECT * FROM metis_circuits ORDER BY updated_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
        return _decode_system_rows([dict(row) for row in rows])

    def close_circuit(
        self, circuit_id: str, *, reason: str = "", status: str = "closed"
    ) -> dict[str, Any] | None:
        now = utc_now_iso()
        with self._write() as conn:
            conn.execute(
                "UPDATE metis_circuits SET status = ?, reason = ?, closed_at = ?, "
                "updated_at = ? WHERE id = ?",
                (status, redact_text(reason, max_chars=1000), now, now, circuit_id),
            )
            row = conn.execute(
                "SELECT * FROM metis_circuits WHERE id = ?", (circuit_id,)
            ).fetchone()
        return _decode_system_row(dict(row)) if row is not None else None

    # ------------------------------------------------------------------
    # Oneiros evidence-aware re-verification
    # ------------------------------------------------------------------
    def mark_fact_reverification(
        self, fact_id: str, *, reason: str, evidence_ref: str | None = None
    ) -> dict[str, Any] | None:
        with self._write() as conn:
            row = conn.execute(
                "SELECT * FROM memory_facts WHERE id = ?", (fact_id,)
            ).fetchone()
            if row is None:
                return None
            notes = str(row["notes"] or "")
            marker = f"[needs re-verification: {redact_text(reason, max_chars=300)}]"
            if marker not in notes:
                notes = (notes + " " + marker).strip()
            conn.execute(
                "UPDATE memory_facts SET verification_state = 'needs_reverification', "
                "evidence_ref = COALESCE(?, evidence_ref), notes = ?, updated_at = ? "
                "WHERE id = ?",
                (evidence_ref, notes, utc_now_iso(), fact_id),
            )
            updated = conn.execute(
                "SELECT * FROM memory_facts WHERE id = ?", (fact_id,)
            ).fetchone()
        return self._memory_row(dict(updated))

    def mark_facts_for_evidence(
        self, evidence_ref: str, *, reason: str
    ) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id FROM memory_facts WHERE evidence_ref = ?", (evidence_ref,)
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            updated = self.mark_fact_reverification(
                str(row["id"]), reason=reason, evidence_ref=evidence_ref
            )
            if updated is not None:
                result.append(updated)
        return result

    def set_fact_evidence(self, fact_id: str, evidence_ref: str) -> bool:
        with self._write() as conn:
            cursor = conn.execute(
                "UPDATE memory_facts SET evidence_ref = ?, "
                "verification_state = 'supported', updated_at = ? WHERE id = ?",
                (evidence_ref, utc_now_iso(), fact_id),
            )
        return bool(cursor.rowcount)

    def apply_retention(self, days: int = 30) -> dict[str, int]:
        """Prune old episodes, sources, and non-essential events.

        Memory facts, security decisions, and checkpoint/import records are
        retained.  Retention is a bounded maintenance action and is audited.
        """

        days = max(1, min(3650, int(days)))
        cutoff = (
            utc_now() - timedelta(days=days)
        ).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        with self._write() as conn:
            episode_cursor = conn.execute(
                "DELETE FROM episodes WHERE captured_at < ?", (cutoff,)
            )
            source_cursor = conn.execute(
                "DELETE FROM sources WHERE first_seen_utc < ?", (cutoff,)
            )
            event_cursor = conn.execute(
                "DELETE FROM events WHERE timestamp_utc < ? AND event_type NOT IN "
                "('data_deleted', 'checkpoint_imported', 'checkpoint_exported')",
                (cutoff,),
            )
        counts = {
            "episodes_deleted": int(episode_cursor.rowcount or 0),
            "sources_deleted": int(source_cursor.rowcount or 0),
            "events_deleted": int(event_cursor.rowcount or 0),
        }
        self.append_event(
            "retention_applied",
            f"Retention applied: {days} day window",
            details={"days": days, **counts},
            idempotency_key=f"retention:{cutoff}",
        )
        return counts

    def stats(self) -> dict[str, Any]:
        with self._lock:
            events = int(
                self._conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"]
            )
            sources = int(
                self._conn.execute("SELECT COUNT(*) AS c FROM sources").fetchone()["c"]
            )
            episodes = int(
                self._conn.execute("SELECT COUNT(*) AS c FROM episodes").fetchone()["c"]
            )
            facts = int(
                self._conn.execute("SELECT COUNT(*) AS c FROM memory_facts").fetchone()["c"]
            )
            decisions = int(
                self._conn.execute(
                    "SELECT COUNT(*) AS c FROM security_decisions"
                ).fetchone()["c"]
            )
            checkpoints = int(
                self._conn.execute("SELECT COUNT(*) AS c FROM checkpoints").fetchone()["c"]
            )
            playbooks = int(
                self._conn.execute("SELECT COUNT(*) AS c FROM playbooks").fetchone()["c"]
            )
            active_leases = int(
                self._conn.execute(
                    "SELECT COUNT(*) AS c FROM safety_leases WHERE status = 'active'"
                ).fetchone()["c"]
            )
        return {
            "events": events,
            "sources": sources,
            "episodes": episodes,
            "memory_facts": facts,
            "security_decisions": decisions,
            "checkpoints": checkpoints,
            "playbooks": playbooks,
            "active_leases": active_leases,
            "installation_id": self.installation_id,
            "schema_version": self.schema_version,
            "policy_version": self.policy_version,
        }
