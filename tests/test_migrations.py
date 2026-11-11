"""Schema v1 -> v2 -> v3 migration behavior and rollback guarantees.

These tests use only a temporary SQLite database.  They prove that an existing
v0.1 Event Spine is upgraded in place, that data is preserved, that Hephaestus
tables are added, and that a failed upgrade never stamps an incomplete schema.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from continuum_core.common.errors import StorageError
from continuum_core.constants import SCHEMA_VERSION
from continuum_core.spine.schema import (
    MIGRATIONS,
    SCHEMA_V1,
    SCHEMA_V2,
    SCHEMA_V3,
    _statements,
    migrate,
)
from continuum_core.spine.store import SpineStore

V2_TABLES = {
    "kairos_snapshots",
    "kairos_diffs",
    "aletheia_receipts",
    "aletheia_protected",
    "aletheia_challenges",
    "telos_charters",
    "telos_amendments",
    "telos_drift",
    "telos_completions",
    "moirai_previews",
    "metis_failures",
    "metis_circuits",
}
V3_TABLES = {
    "playbooks",
    "safety_leases",
    "safety_lease_usage",
}
V1_TABLES = {
    "meta",
    "events",
    "sources",
    "episodes",
    "memory_facts",
    "security_decisions",
    "checkpoints",
    "dream_runs",
    "attack_lab_runs",
    "resume_briefs",
}


def _connect(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(str(path), check_same_thread=False)
    connection.row_factory = sqlite3.Row
    return connection


def _create_v1_database(path: Path) -> sqlite3.Connection:
    connection = _connect(path)
    for statement in _statements(SCHEMA_V1):
        connection.execute(statement)
    connection.execute("PRAGMA user_version = 1")
    connection.execute(
        "INSERT INTO meta(key, value) VALUES ('installation_id', 'inst_legacy')"
    )
    connection.execute("INSERT INTO meta(key, value) VALUES ('schema_version', '1')")
    connection.execute(
        """
        INSERT INTO events(
            event_id, event_type, timestamp_utc, device_id, schema_version, summary, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "evt_legacy",
            "session_started",
            "2026-01-01T00:00:00.000Z",
            "inst_legacy",
            1,
            "legacy event",
            "2026-01-01T00:00:00.000Z",
        ),
    )
    connection.execute(
        """
        INSERT INTO memory_facts(
            id, fact_key, value, status, confidence, first_observed_utc,
            last_observed_utc, version, provenance, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "fact_legacy",
            "deployment region",
            "Frankfurt",
            "confirmed",
            0.9,
            "2026-01-01T00:00:00.000Z",
            "2026-01-01T00:00:00.000Z",
            1,
            "USER_AUTHORED",
            "2026-01-01T00:00:00.000Z",
            "2026-01-01T00:00:00.000Z",
        ),
    )
    connection.commit()
    return connection


def _table_names(connection: sqlite3.Connection) -> set[str]:
    return {
        str(row["name"])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()
    }


def _columns(connection: sqlite3.Connection, table: str) -> set[str]:
    return {str(row["name"]) for row in connection.execute(f"PRAGMA table_info({table})")}


def test_fresh_install_creates_current_schema(tmp_path: Path) -> None:
    connection = _connect(tmp_path / "fresh.db")
    store = SpineStore(connection, owns_connection=True)
    try:
        assert store.schema_version == SCHEMA_VERSION == 3
        assert V1_TABLES | V2_TABLES | V3_TABLES <= _table_names(connection)
        assert {"verification_state", "evidence_ref"} <= _columns(
            connection, "memory_facts"
        )
        assert "args_hash" in _columns(connection, "metis_circuits")
        assert "suite" in _columns(connection, "attack_lab_runs")
        assert "confidence" in _columns(connection, "playbooks")
        assert "environment_hash" in _columns(connection, "safety_leases")
        assert int(connection.execute("PRAGMA user_version").fetchone()[0]) == 3
    finally:
        store.close()


def test_v1_upgrade_preserves_rows_installation_and_is_idempotent(
    tmp_path: Path,
) -> None:
    path = tmp_path / "upgrade.db"
    connection = _create_v1_database(path)
    assert V2_TABLES.isdisjoint(_table_names(connection))
    assert V3_TABLES.isdisjoint(_table_names(connection))
    store = SpineStore(connection, owns_connection=True)
    try:
        assert store.schema_version == 3
        assert store.installation_id == "inst_legacy"
        assert store.total_events() == 1
        fact = connection.execute(
            "SELECT value, verification_state FROM memory_facts WHERE id = 'fact_legacy'"
        ).fetchone()
        assert fact["value"] == "Frankfurt"
        assert fact["verification_state"] == "unverified"
        assert V2_TABLES <= _table_names(connection)
        assert V3_TABLES <= _table_names(connection)
    finally:
        store.close()

    reopened = _connect(path)
    store = SpineStore(reopened, owns_connection=True)
    try:
        assert store.schema_version == 3
        assert store.installation_id == "inst_legacy"
        assert store.total_events() == 1
        assert (
            reopened.execute(
                "SELECT COUNT(*) AS c FROM memory_facts WHERE id = 'fact_legacy'"
            ).fetchone()["c"]
            == 1
        )
    finally:
        store.close()


def test_failed_migration_rolls_back_tables_and_version(tmp_path: Path) -> None:
    path = tmp_path / "rollback.db"
    connection = _connect(path)
    migrate(connection, ((1, SCHEMA_V1),))
    connection.execute(
        "INSERT INTO meta(key, value) VALUES ('installation_id', 'inst_rollback')"
    )
    connection.commit()
    assert int(connection.execute("PRAGMA user_version").fetchone()[0]) == 1

    broken = (
        (1, SCHEMA_V1),
        (
            2,
            """
            -- This table would be visible if the migration were partially applied.
            CREATE TABLE should_rollback (id TEXT PRIMARY KEY);
            INSERT INTO missing_table_that_does_not_exist(id) VALUES ('boom');
            """,
        ),
    )
    with pytest.raises(StorageError):
        migrate(connection, broken)

    assert int(connection.execute("PRAGMA user_version").fetchone()[0]) == 1
    assert "should_rollback" not in _table_names(connection)
    assert V2_TABLES.isdisjoint(_table_names(connection))
    assert V3_TABLES.isdisjoint(_table_names(connection))
    meta = dict(connection.execute("SELECT key, value FROM meta").fetchall())
    assert meta["schema_version"] == "1"
    connection.close()


def test_newer_schema_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "newer.db"
    connection = _connect(path)
    for statement in _statements(SCHEMA_V1):
        connection.execute(statement)
    connection.execute("PRAGMA user_version = 99")
    connection.commit()
    with pytest.raises(StorageError):
        SpineStore(connection, owns_connection=True)
    connection.close()


def test_migration_plan_is_ordered_and_statements_keep_leading_tables() -> None:
    assert [version for version, _ in MIGRATIONS] == [1, 2, 3]
    statements = list(_statements(SCHEMA_V2))
    assert statements
    assert statements[0].lstrip().upper().startswith("CREATE TABLE")
    assert any("kairos_snapshots" in statement for statement in statements)
    v3_statements = list(_statements(SCHEMA_V3))
    assert v3_statements
    assert v3_statements[0].lstrip().upper().startswith("CREATE TABLE")
    assert any("playbooks" in statement for statement in v3_statements)
    assert any("safety_leases" in statement for statement in v3_statements)
    # The v1 script itself starts with CREATE TABLE meta; the old bug skipped
    # the first statement of every comment-prefixed chunk.
    assert next(iter(_statements(SCHEMA_V1))).lstrip().upper().startswith(
        "CREATE TABLE"
    )
