"""Moirai side-effect-free impact previews across work domains."""

from __future__ import annotations

from pathlib import Path

from continuum_core.moirai.service import PARTIAL, UNSUPPORTED, VERIFIED


def test_read_only_and_unknown_previews_make_honest_claims(service) -> None:
    read = service.preview_action("read_file", {"path": "notes.txt"})
    assert read["level"] == VERIFIED
    assert read["action_category"] == "read_only"
    assert read["targets"] == []
    assert read["creates"] == read["modifies"] == read["deletes"] == []

    unknown = service.preview_action(
        "quantum_teleport", {"payload": "not classifiable"}
    )
    assert unknown["level"] == UNSUPPORTED
    assert unknown["action_category"] == "unknown"
    assert unknown["confidence"] <= 0.2
    assert unknown["unknowns"]


def test_file_write_preview_is_side_effect_free_and_omits_content(
    service, tmp_path: Path
) -> None:
    target = tmp_path / "new-report.txt"
    preview = service.preview_action(
        "write_file",
        {
            "path": str(target),
            "content": "TOP SECRET DRAFT BODY",
            "api_key": "sk-ant-should-never-appear",
        },
    )

    assert preview["level"] == VERIFIED
    assert preview["action_category"] == "file_write"
    assert preview["creates"] and not preview["modifies"]
    assert preview["targets"][0]["exists"] is False
    assert not target.exists()
    serialized = str(preview)
    assert "TOP SECRET DRAFT BODY" not in serialized
    assert "sk-ant-should-never-appear" not in serialized
    assert "content" not in preview["payload_summary"]
    assert preview["unknowns"] == []

    target.write_text("existing", encoding="utf-8")
    existing = service.preview_action(
        "edit_file", {"path": str(target), "content": "replacement"}
    )
    assert existing["action_category"] == "file_write"
    assert existing["modifies"] and not existing["creates"]


def test_delete_move_copy_and_external_previews(service, tmp_path: Path) -> None:
    target = tmp_path / "archive.txt"
    target.write_text("content", encoding="utf-8")

    deleted = service.preview_action("delete_file", {"path": str(target)})
    assert deleted["level"] == VERIFIED
    assert deleted["action_category"] == "file_delete"
    assert deleted["deletes"]
    assert deleted["irreversible"]
    assert target.exists()

    moved = service.preview_action(
        "move_file",
        {"source": str(target), "destination": str(tmp_path / "moved.txt")},
    )
    assert moved["action_category"] == "file_move"
    assert len(moved["targets"]) == 2

    copy = service.preview_action(
        "copy_file",
        {"source": str(target), "destination": str(tmp_path / "copy.txt")},
    )
    assert copy["action_category"] == "file_copy"
    assert not (tmp_path / "copy.txt").exists()

    sent = service.preview_action(
        "send_email",
        {
            "to": ["customer@example.invalid"],
            "subject": "Report",
            "body": "TOP SECRET BODY",
        },
    )
    assert sent["level"] == PARTIAL
    assert sent["action_category"] == "external_action"
    assert sent["external"]
    assert "TOP SECRET BODY" not in str(sent)

    issue = service.preview_action(
        "create_issue", {"repo": "owner/project", "title": "Bug"}
    )
    assert issue["action_category"] == "external_action"
    assert issue["level"] == PARTIAL


def test_database_previews_distinguish_reads_broad_writes_and_unknowns(
    service,
) -> None:
    read = service.preview_action(
        "database_query",
        {"database": "app", "query": "SELECT * FROM users WHERE id = 1"},
    )
    assert read["level"] == VERIFIED
    assert read["action_category"] == "database_read"

    broad = service.preview_action(
        "database_execute",
        {"database": "app", "query": "DELETE FROM users"},
    )
    assert broad["level"] == PARTIAL
    assert broad["action_category"] == "database_write"
    assert broad["deletes"]
    assert broad["irreversible"]
    assert any("where" in item.lower() for item in broad["unknowns"])

    scoped = service.preview_action(
        "database_execute",
        {"database": "app", "query": "UPDATE users SET active = 1 WHERE id = 2"},
    )
    assert scoped["action_category"] == "database_write"
    assert scoped["modifies"]
    assert scoped["irreversible"] == []

    unknown = service.preview_action(
        "database_execute", {"database": "app", "query": "CALL rotate_keys()"}
    )
    assert unknown["level"] == UNSUPPORTED
    assert unknown["action_category"] == "database_unknown"


def test_shell_previews_handle_rm_execute_and_unsafe_pipelines(
    service, tmp_path: Path
) -> None:
    target = tmp_path / "build"
    target.mkdir()

    preview = service.preview_action(
        "terminal", {"command": f'rm -rf "{target}"'}
    )
    assert preview["level"] == PARTIAL
    assert preview["action_category"] == "shell_file_operation"
    assert preview["deletes"]
    assert preview["irreversible"]
    assert target.exists()

    # ``execute`` must be treated as a shell tool even though the broad
    # database adapter also matches the word in its name.
    execute = service.preview_action(
        "execute", {"command": "rm -rf build"}
    )
    assert execute["action_category"] == "shell_file_operation"

    pipeline = service.preview_action(
        "terminal", {"command": "rm -rf build | tee deletion.log"}
    )
    assert pipeline["level"] == UNSUPPORTED
    assert pipeline["action_category"] == "shell_complex"
    assert pipeline["targets"] == []


def test_preview_links_verified_evidence_and_is_recorded(
    service, tmp_path: Path
) -> None:
    target = tmp_path / "verified.txt"
    target.write_text("verified", encoding="utf-8")
    receipt = service.record_evidence_file(target, scope="verified source")
    preview = service.preview_action(
        "write_file",
        {"path": str(target.resolve()), "content": "new"},
        action_ref="call_123",
    )
    assert preview["evidence"]
    assert preview["evidence"][0]["receipt_id"] == receipt["id"]
    assert preview["evidence"][0]["status"] == "current"
    assert preview["summary"].startswith(VERIFIED)
    assert service.moirai.get_preview(preview["id"])["id"] == preview["id"]
    assert service.previews()["previews"]

    second = service.preview_action(
        "write_file",
        {"path": str(target.resolve()), "content": "new"},
        action_ref="call_123",
    )
    assert second["id"] != preview["id"]
    preview_events = [
        event
        for event in service.store.list_events(limit=50)
        if event["event_type"] == "action.previewed"
    ]
    assert len(preview_events) == 1
