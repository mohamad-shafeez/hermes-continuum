"""Profile-scoped storage isolation and checkpoint source identity."""

from __future__ import annotations

import sqlite3
import sys
import types
from pathlib import Path

from continuum_core.service import ContinuumService


def _service(path: Path) -> ContinuumService:
    return ContinuumService.from_path(
        path / "data.db", checkpoint_dir=path / "checkpoints"
    )


def test_two_profiles_do_not_share_events_memory_or_identity(tmp_path: Path) -> None:
    first = _service(tmp_path / "profile-a")
    second = _service(tmp_path / "profile-b")
    try:
        fact = first.capture_turn(
            user_message="The deployment region is Frankfurt",
            session_id="a",
            turn_id="1",
        )["candidate"]
        first.confirm_memory(fact["id"])
        first.store.append_event("session_started", "profile A only", session_id="a")

        assert first.store.installation_id != second.store.installation_id
        assert first.store.total_events() > 0
        assert second.store.total_events() == 0
        assert second.memory_list() == []
        assert second.store.find_current_fact("deployment region") is None
        assert first.store.database_path != second.store.database_path
        assert first.checkpoint_service.checkpoint_dir != second.checkpoint_service.checkpoint_dir
    finally:
        first.close()
        second.close()


def test_checkpoint_records_source_installation_and_can_move_data(tmp_path: Path) -> None:
    source = _service(tmp_path / "source")
    target = _service(tmp_path / "target")
    try:
        fact = source.capture_turn(
            user_message="I prefer dark mode", session_id="s", turn_id="1"
        )["candidate"]
        source.confirm_memory(fact["id"])
        exported = source.export_checkpoint("correct horse battery staple")

        imported = target.import_checkpoint(
            exported["path"], "correct horse battery staple", confirm=True
        )
        assert imported["status"] == "imported"
        assert target.store.find_current_fact("user preference: dark mode")["value"] == "dark mode"
        records = target.list_checkpoints()
        assert records
        record = records[0]
        assert record["source_installation_id"] == source.store.installation_id
        assert record["source_installation_id"] != target.store.installation_id
        assert record["counts"]["memory_facts"] >= 1
        # The source profile is unchanged by the import into the target.
        assert source.store.total_events() > 0
        assert target.store.total_events() > 0
    finally:
        source.close()
        target.close()


def test_from_plugin_storage_uses_profile_scoped_api(tmp_path: Path, monkeypatch) -> None:
    data_dir = tmp_path / "plugin-data"
    data_dir.mkdir()
    connection = sqlite3.connect(
        str(data_dir / "data.db"), check_same_thread=False
    )
    calls: dict[str, object] = {}

    package = types.ModuleType("plugins")
    package.__path__ = []  # type: ignore[attr-defined]
    storage = types.ModuleType("plugins.plugin_storage")

    def plugin_db(plugin_id: str):
        calls["plugin_db"] = plugin_id
        return connection

    def plugin_data_dir(plugin_id: str):
        calls["plugin_data_dir"] = plugin_id
        return data_dir

    storage.plugin_db = plugin_db  # type: ignore[attr-defined]
    storage.plugin_data_dir = plugin_data_dir  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "plugins", package)
    monkeypatch.setitem(sys.modules, "plugins.plugin_storage", storage)

    service = ContinuumService.from_plugin_storage()
    try:
        assert calls == {
            "plugin_db": "hermes-continuum",
            "plugin_data_dir": "hermes-continuum",
        }
        assert Path(service.checkpoint_service.checkpoint_dir) == data_dir / "checkpoints"
        service.store.append_event("session_started", "profile-scoped")
        assert service.store.total_events() == 1
    finally:
        service.close()


def test_store_never_targets_private_session_storage(tmp_path: Path) -> None:
    service = _service(tmp_path / "profile")
    try:
        database = str(service.store.database_path or "").replace("\\", "/")
        assert database.endswith("/data.db")
        assert "/sessions/" not in database
        assert "plugin-data" in database or "profile" in database
        doctor = service.status()
        assert doctor["stats"]["events"] == 0
    finally:
        service.close()
