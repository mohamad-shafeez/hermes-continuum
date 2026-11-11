"""Kairos environmental fingerprints, reality diffs, and evidence staleness."""

from __future__ import annotations

import json
from pathlib import Path

from continuum_core.kairos import service as kairos_module


def _workspace(tmp_path: Path) -> Path:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "notes.txt").write_text("version one", encoding="utf-8")
    (workspace / ".env").write_text("TOP-SECRET-VALUE", encoding="utf-8")
    return workspace


def test_snapshot_is_bounded_and_never_stores_file_contents(
    service, tmp_path: Path
) -> None:
    workspace = _workspace(tmp_path)
    snapshot = service.reality_snapshot(
        scope=str(workspace),
        paths=["notes.txt", ".env", "../outside.txt"],
        label="unit",
        required_tools=["python"],
        preconditions={"ticket_open": True, "owner": "team-a"},
    )

    assert snapshot["id"].startswith("env_")
    assert snapshot["fingerprint_hash"]
    fingerprint = snapshot["fingerprint"]
    assert fingerprint["workspace"]["root"] == str(workspace.resolve())
    assert set(fingerprint["files"]) == {"notes.txt"}
    serialized = json.dumps(fingerprint, sort_keys=True)
    assert "version one" not in serialized
    assert "TOP-SECRET-VALUE" not in serialized
    assert ".env" not in fingerprint["files"]
    assert fingerprint["preconditions"]["ticket_open"] is True
    assert fingerprint["preconditions"]["owner"] == "team-a"
    assert any("remote" in item or "network" in item for item in fingerprint["unverified"])
    assert service.store.list_kairos_snapshots()[0]["id"] == snapshot["id"]
    assert any(
        event["event_type"] == "world.snapshotted"
        for event in service.store.list_events(limit=20)
    )


def test_reality_diff_green_amber_red_and_deletion(service, tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    notes = workspace / "notes.txt"
    snapshot = service.reality_snapshot(
        scope=str(workspace), paths=[str(notes)], label="baseline"
    )

    unchanged = service.reality_diff(snapshot["id"])
    assert unchanged["level"] == "GREEN"
    assert unchanged["changed"] == []
    assert "unverified" in unchanged["summary"].lower()

    notes.write_text("version two", encoding="utf-8")
    changed = service.reality_diff(snapshot["id"])
    assert changed["level"] == "AMBER"
    assert [item["key"] for item in changed["changed"]] == ["files.notes.txt"]
    assert changed["changed"][0]["severity"] == "amber"
    assert changed["stale_evidence"] == []

    notes.unlink()
    missing = service.reality_diff(snapshot["id"])
    assert missing["level"] == "RED"
    assert missing["changed"][0]["severity"] == "red"
    assert "missing" in missing["changed"][0]["message"].lower()
    event_types = {event["event_type"] for event in service.store.list_events(limit=40)}
    assert {"reality.diffed", "precondition.failed"} <= event_types


def test_precondition_change_is_red_and_records_precondition_failure(
    service, tmp_path: Path
) -> None:
    workspace = _workspace(tmp_path)
    snapshot = service.reality_snapshot(
        scope=str(workspace),
        paths=["notes.txt"],
        preconditions={"ticket_open": True},
    )

    diff = service.reality_diff(
        snapshot["id"], preconditions={"ticket_open": False}
    )

    assert diff["level"] == "RED"
    assert diff["changed"][0]["key"] == "preconditions.ticket_open"
    precondition_events = [
        event
        for event in service.store.list_events(limit=30)
        if event["event_type"] == "precondition.failed"
    ]
    assert precondition_events


def test_required_tool_disappearance_is_red(
    service, tmp_path: Path, monkeypatch
) -> None:
    workspace = _workspace(tmp_path)
    monkeypatch.setattr(kairos_module.shutil, "which", lambda name: "/usr/bin/python")
    snapshot = service.reality_snapshot(
        scope=str(workspace), paths=["notes.txt"], required_tools=["python"]
    )
    monkeypatch.setattr(kairos_module.shutil, "which", lambda name: None)

    diff = service.reality_diff(snapshot["id"])

    assert diff["level"] == "RED"
    assert any(item["key"] == "tools.python.present" for item in diff["changed"])


def test_environment_change_stales_verified_evidence_and_memory(
    service, tmp_path: Path
) -> None:
    workspace = _workspace(tmp_path)
    notes = workspace / "notes.txt"
    fact = service.capture_turn(
        user_message="The notes document is the authoritative release note",
        session_id="s",
        turn_id="1",
    )["candidate"]
    service.confirm_memory(fact["id"])
    snapshot = service.reality_snapshot(
        scope=str(workspace), paths=[str(notes)], label="before evidence"
    )
    receipt = service.record_evidence_file(
        notes, scope="notes integrity", memory_ref=fact["id"]
    )
    assert receipt["status"] == "current"
    assert receipt["environment_snapshot_id"] == snapshot["id"]

    notes.write_text("version two", encoding="utf-8")
    diff = service.reality_diff(snapshot["id"])

    assert diff["level"] == "AMBER"
    assert [item["id"] for item in diff["stale_evidence"]] == [receipt["id"]]
    assert service.aletheia.get_receipt(receipt["id"])["status"] == "stale"
    updated_fact = service.store.get_fact(fact["id"])
    assert updated_fact["verification_state"] == "needs_reverification"
