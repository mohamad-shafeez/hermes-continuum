"""Model-facing tool handlers, CLI dispatch, and slash command behavior."""

from __future__ import annotations

import argparse
import io
import json
from pathlib import Path

import pytest

from continuum_core.adapters import cli, tools
from continuum_core.runtime import ContinuumRuntime
from continuum_core.service import ContinuumService


class _Ctx:
    def get_config(self, key: str, default=None):
        return default


def _runtime(service) -> ContinuumRuntime:
    runtime = ContinuumRuntime(_Ctx())
    runtime._service = service
    runtime._config = service.config
    return runtime


def _payload(raw: str) -> dict:
    assert isinstance(raw, str)
    return json.loads(raw)


def test_tool_schemas_are_exact_and_do_not_accept_passphrases() -> None:
    names = [schema["name"] for schema in tools.TOOL_SCHEMAS]
    assert names == [
        "continuum_status",
        "continuum_recall",
        "continuum_memory_review",
        "continuum_dream",
        "continuum_checkpoint",
        "continuum_reality",
        "continuum_evidence",
        "continuum_charter",
        "continuum_preview",
        "continuum_execution",
        "continuum_forge",
        "continuum_lease",
    ]
    for schema in tools.TOOL_SCHEMAS:
        assert schema["parameters"]["type"] == "object"
        assert schema["parameters"].get("additionalProperties") is False
        assert "passphrase" not in schema["parameters"].get("properties", {})


def test_tool_handlers_status_and_recall(service) -> None:
    runtime = _runtime(service)
    handlers = tools.build_tool_handlers(runtime)
    status = _payload(handlers["continuum_status"]({}))
    assert status["ok"] is True
    assert status["read_only"] is True
    assert status["stats"]["events"] >= 0

    missing = _payload(handlers["continuum_recall"]({}))
    assert missing["ok"] is False
    assert missing["error"] == "invalid_query"

    fact = service.capture_turn(
        user_message="The deployment region is Frankfurt", session_id="s", turn_id="1"
    )["candidate"]
    service.confirm_memory(fact["id"])
    recalled = _payload(
        handlers["continuum_recall"]({"query": "deployment region", "limit": 999})
    )
    assert recalled["ok"] is True
    assert recalled["count"] == 1
    assert recalled["facts"][0]["value"] == "Frankfurt"
    assert "unverified" in recalled["note"].lower()


def test_tool_memory_review_actions_and_validation(service) -> None:
    runtime = _runtime(service)
    handler = tools.build_tool_handlers(runtime)["continuum_memory_review"]
    fact = service.capture_turn(
        user_message="I prefer dark mode", session_id="s", turn_id="1"
    )["candidate"]

    listed = _payload(handler({"action": "list", "status": "candidate"}))
    assert listed["ok"] is True
    assert listed["counts"]["candidate"] == 1
    assert listed["facts"][0]["id"] == fact["id"]

    invalid = _payload(handler({"action": "list", "status": "bogus"}))
    assert invalid["error"] == "invalid_status"
    assert "contradicted" in invalid["message"]

    confirmed = _payload(handler({"action": "confirm", "fact_id": fact["id"]}))
    assert confirmed["fact"]["status"] == "confirmed"

    edited = _payload(
        handler({"action": "edit", "fact_id": fact["id"], "value": "light mode"})
    )
    assert edited["fact"]["status"] == "candidate"
    assert edited["fact"]["value"] == "light mode"

    rejected = _payload(
        handler({"action": "reject", "fact_id": edited["fact"]["id"]})
    )
    assert rejected["fact"]["status"] == "rejected"

    forget_without_confirm = _payload(
        handler({"action": "forget", "fact_id": fact["id"]})
    )
    assert forget_without_confirm["error"] == "confirmation_required"
    forgotten = _payload(
        handler({"action": "forget", "fact_id": fact["id"], "confirm": True})
    )
    assert forgotten["deleted"]["deleted"] is True
    assert _payload(handler({"action": "bogus"}))["error"] == "invalid_action"
    assert _payload(handler({"action": "confirm"}))["error"] == "invalid_fact_id"


def test_tool_dream_is_bounded_and_returns_json(service) -> None:
    runtime = _runtime(service)
    handler = tools.build_tool_handlers(runtime)["continuum_dream"]
    first = _payload(handler({}))
    assert first["ok"] is True
    assert first["dream"]["status"] == "no_new_episodes"
    second = _payload(handler({}))
    assert second["dream"]["status"] == "no_new_episodes"


def test_tool_reality_snapshot_diff_and_preconditions(service, tmp_path: Path) -> None:
    runtime = _runtime(service)
    handler = tools.build_tool_handlers(runtime)["continuum_reality"]
    workspace = tmp_path / "reality-workspace"
    workspace.mkdir()
    artifact = workspace / "notes.txt"
    artifact.write_text("first version", encoding="utf-8")

    snap = _payload(
        handler(
            {
                "action": "snapshot",
                "scope": str(workspace),
                "paths": [str(artifact)],
                "label": "tool test",
            }
        )
    )
    assert snap["ok"] is True
    assert snap["action"] == "snapshot"
    snapshot_id = snap["id"]
    assert snap["label"] == "tool test"
    assert "first version" not in json.dumps(snap)

    listed = _payload(handler({"action": "list"}))
    assert listed["ok"] is True
    assert any(item["id"] == snapshot_id for item in listed["snapshots"])

    artifact.write_text("second version", encoding="utf-8")
    changed = _payload(handler({"action": "diff", "snapshot_id": snapshot_id}))
    assert changed["ok"] is True
    assert changed["level"] in {"AMBER", "RED"}
    assert changed["changed"]

    unverified = _payload(
        handler(
            {
                "action": "diff",
                "snapshot_id": snapshot_id,
                "preconditions": {"approved_budget": 100},
            }
        )
    )
    assert unverified["level"] in {"AMBER", "RED"}
    assert unverified["unverified"]
    assert _payload(handler({"action": "bogus"}))["error"] == "invalid_action"


def test_tool_evidence_confirmation_and_protection(
    service, tmp_path: Path
) -> None:
    runtime = _runtime(service)
    handler = tools.build_tool_handlers(runtime)["continuum_evidence"]
    artifact = tmp_path / "evidence.txt"
    artifact.write_text("authentic content", encoding="utf-8")

    recorded = _payload(
        handler(
            {
                "action": "record_file",
                "path": str(artifact),
                "scope": "test artifact",
            }
        )
    )
    assert recorded["ok"] is True
    receipt_id = recorded["receipt"]["id"]
    assert recorded["receipt"]["verified"]
    assert recorded["receipt"]["status"] == "current"

    assert (
        _payload(handler({"action": "confirm"}))["error"]
        == "confirmation_required"
    )
    assert (
        _payload(handler({"action": "confirm", "receipt_id": receipt_id}))["error"]
        == "confirmation_required"
    )
    confirmed = _payload(
        handler({"action": "confirm", "receipt_id": receipt_id, "confirm": True})
    )
    assert confirmed["receipt"]["id"] == receipt_id

    shown = _payload(handler({"action": "show", "receipt_id": receipt_id}))
    assert shown["receipt"]["artifact_ref"].endswith("evidence.txt")

    assert (
        _payload(
            handler(
                {
                    "action": "protect",
                    "artifact_ref": str(artifact),
                    "receipt_id": receipt_id,
                }
            )
        )["error"]
        == "confirmation_required"
    )
    protected = _payload(
        handler(
            {
                "action": "protect",
                "artifact_ref": str(artifact),
                "receipt_id": receipt_id,
                "confirm": True,
            }
        )
    )
    protected_id = protected["protected"]["id"]
    assert protected["protected"]["active"]

    listed = _payload(handler({"action": "list"}))
    assert any(item["id"] == receipt_id for item in listed["receipts"])
    assert any(item["id"] == protected_id for item in listed["protected"])
    assert _payload(handler({"action": "challenges"}))["challenges"] == []

    assert (
        _payload(
            handler({"action": "release", "protected_id": protected_id})
        )["error"]
        == "confirmation_required"
    )
    released = _payload(
        handler(
            {
                "action": "release",
                "protected_id": protected_id,
                "reason": "user replaced the artifact",
                "confirm": True,
            }
        )
    )
    assert not released["protected"]["active"]
    assert _payload(handler({"action": "show", "receipt_id": "missing"}))[
        "error"
    ] == "not_found"


def test_tool_charter_actions_and_user_confirmation_gates(
    service,
) -> None:
    runtime = _runtime(service)
    handler = tools.build_tool_handlers(runtime)["continuum_charter"]
    charter = service.ensure_charter(
        "Compare three suppliers. Do not send emails. Produce a comparison report.",
        session_id="s-charter-tool",
    )
    assert charter is not None
    charter_id = charter["id"]

    active = _payload(handler({"action": "active", "session_id": "s-charter-tool"}))
    assert active["charter"]["id"] == charter_id
    shown = _payload(handler({"action": "show", "charter_id": charter_id}))
    assert "Telos task charter" in shown["context"]
    assert any(item["id"] == charter_id for item in _payload(handler({"action": "list"}))["charters"])

    assert (
        _payload(
            handler(
                {
                    "action": "amend",
                    "charter_id": charter_id,
                    "amendment": "Also include delivery costs.",
                }
            )
        )["error"]
        == "confirmation_required"
    )
    amended = _payload(
        handler(
            {
                "action": "amend",
                "charter_id": charter_id,
                "amendment": "Also include delivery costs.",
                "rationale": "User updated the objective.",
                "confirm": True,
            }
        )
    )
    assert amended["charter"]["version"] == 2

    subgoal = amended["charter"]["subgoals"][0]
    advanced = _payload(
        handler(
            {
                "action": "advance",
                "charter_id": charter_id,
                "subgoal_id": subgoal["id"],
                "completed": True,
            }
        )
    )
    assert advanced["charter"]["subgoals"][0]["status"] == "completed"

    assert (
        _payload(handler({"action": "complete", "charter_id": charter_id}))["error"]
        == "confirmation_required"
    )
    completed = _payload(
        handler(
            {
                "action": "complete",
                "charter_id": charter_id,
                "claimed_complete": True,
                "confirm": True,
            }
        )
    )
    assert completed["assessment"]["outcome"] == "complete"
    assert completed["assessment"]["score"] == 100
    assert (
        _payload(
            handler(
                {
                    "action": "advance",
                    "charter_id": charter_id,
                    "subgoal_id": "missing",
                }
            )
        )["error"]
        == "internal_error"
    )


def test_tool_preview_is_side_effect_free_and_execution_reset_is_gated(
    service, tmp_path: Path
) -> None:
    runtime = _runtime(service)
    handlers = tools.build_tool_handlers(runtime)
    destination = tmp_path / "planned.txt"

    preview = _payload(
        handlers["continuum_preview"](
            {
                "action": "preview",
                "tool_name": "write_file",
                "args": {
                    "path": str(destination),
                    "content": "planned",
                    "api_key": "sk-ant-secret-value",
                },
            }
        )
    )
    assert preview["ok"] is True
    assert preview["action"] == "preview"
    assert preview["preview"]["tool_name"] == "write_file"
    assert "sk-ant-secret-value" not in json.dumps(preview)
    assert destination.exists() is False
    listed = _payload(handlers["continuum_preview"]({"action": "list"}))
    assert listed["previews"]
    assert (
        _payload(handlers["continuum_preview"]({"action": "preview"}))["error"]
        == "invalid_tool_name"
    )

    args = {"path": "planned.txt", "content": "same attempt"}
    for index in range(3):
        service.metis.observe_result(
            "write_file",
            args,
            status="failed",
            result={"error": "permission denied"},
            tool_call_id=f"tool-circuit-{index}",
        )
    circuit = _payload(handlers["continuum_execution"]({"action": "list"}))["circuits"][0]
    status = _payload(
        handlers["continuum_execution"](
            {"action": "status", "circuit_id": circuit["id"]}
        )
    )
    assert status["circuit"]["status"] == "open"
    assert (
        _payload(
            handlers["continuum_execution"](
                {"action": "reset", "circuit_id": circuit["id"]}
            )
        )["error"]
        == "confirmation_required"
    )
    reset = _payload(
        handlers["continuum_execution"](
            {
                "action": "reset",
                "circuit_id": circuit["id"],
                "reason": "user changed strategy",
                "confirm": True,
            }
        )
    )
    assert reset["circuit"]["status"] == "closed"
    assert (
        _payload(
            handlers["continuum_execution"](
                {"action": "status", "circuit_id": "missing"}
            )
        )["error"]
        == "not_found"
    )
    assert (
        _payload(handlers["continuum_execution"]({"action": "bogus"}))["error"]
        == "invalid_action"
    )


def test_tool_checkpoint_requires_out_of_band_passphrase(service, monkeypatch) -> None:
    runtime = _runtime(service)
    handler = tools.build_tool_handlers(runtime)["continuum_checkpoint"]

    monkeypatch.delenv(tools.PASSPHRASE_ENV, raising=False)
    missing = _payload(handler({"action": "export"}))
    assert missing["error"] == "passphrase_required"
    assert tools.PASSPHRASE_ENV in missing["message"]

    monkeypatch.setenv(tools.PASSPHRASE_ENV, "short")
    assert _payload(handler({"action": "export"}))["error"] == "passphrase_required"

    monkeypatch.setenv(tools.PASSPHRASE_ENV, "correct horse battery staple")
    rejected_destination = _payload(
        handler({"action": "export", "destination": "C:/tmp/out.hcc"})
    )
    assert rejected_destination["error"] == "destination_not_allowed"

    exported = _payload(handler({"action": "export"}))
    assert exported["ok"] is True
    assert exported["status"] == "exported"
    path = exported["path"]

    listed = _payload(handler({"action": "list"}))
    assert listed["ok"] is True
    assert listed["records"]

    inspected = _payload(handler({"action": "inspect", "path": path}))
    assert inspected["ok"] is True
    assert inspected["status"] == "preview"

    preview = _payload(handler({"action": "import", "path": path}))
    assert preview["ok"] is True
    assert preview["status"] == "preview"
    assert "confirm: true" in preview["message"]

    imported = _payload(handler({"action": "import", "path": path, "confirm": True}))
    assert imported["ok"] is True
    assert imported["status"] == "imported"
    again = _payload(handler({"action": "import", "path": path, "confirm": True}))
    assert again["status"] == "already_imported"

    assert _payload(handler({"action": "inspect"}))["error"] == "invalid_path"
    assert _payload(handler({"action": "bogus"}))["error"] == "invalid_action"


def test_tool_handlers_never_raise(monkeypatch, service) -> None:
    runtime = _runtime(service)

    def broken():
        raise RuntimeError("storage offline")

    monkeypatch.setattr(runtime, "service", broken)
    valid_args = {
        "continuum_status": {},
        "continuum_recall": {"query": "deployment"},
        "continuum_memory_review": {"action": "list"},
        "continuum_dream": {},
        "continuum_checkpoint": {"action": "list"},
        "continuum_reality": {"action": "fingerprint"},
        "continuum_evidence": {"action": "list"},
        "continuum_charter": {"action": "status"},
        "continuum_preview": {"action": "list"},
        "continuum_execution": {"action": "status"},
        "continuum_forge": {"action": "list"},
        "continuum_lease": {"action": "list"},
    }
    handlers = tools.build_tool_handlers(runtime)
    for name, handler in handlers.items():
        payload = _payload(handler(valid_args[name]))
        assert payload["ok"] is False
        assert payload["error"] == "internal_error"
        assert "storage offline" not in payload["message"]


def test_cli_recall_and_resume_compatibility(service) -> None:
    fact = service.capture_turn(
        user_message="The deployment region is Frankfurt", session_id="s", turn_id="1"
    )["candidate"]
    service.confirm_memory(fact["id"])

    parser = argparse.ArgumentParser()
    cli.setup_cli(parser)
    recalled = cli._dispatch(
        service, parser.parse_args(["recall", "deployment", "region"])
    )
    assert recalled["ok"] is True
    assert recalled["count"] == 1
    assert recalled["facts"][0]["value"] == "Frankfurt"
    assert "unverified" in recalled["note"].lower()

    brief = service.store.record_resume_brief(
        checkpoint_id=None, brief="Resume context from an earlier session."
    )
    parser = argparse.ArgumentParser()
    cli.setup_cli(parser)
    shown = cli._dispatch(service, parser.parse_args(["resume", "show"]))
    assert shown["ok"] is True
    assert shown["brief"]["id"] == brief["id"]

    parser = argparse.ArgumentParser()
    cli.setup_cli(parser)
    dismissed = cli._dispatch(
        service, parser.parse_args(["resume", "dismiss", brief["id"]])
    )
    assert dismissed == {"ok": True, "dismissed": brief["id"]}
    assert service.active_resume_brief() is None


def test_cli_retention_requires_confirmation(service, monkeypatch) -> None:
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO(""))
    parser = argparse.ArgumentParser()
    cli.setup_cli(parser)
    cancelled = cli._dispatch(service, parser.parse_args(["retention", "--days", "30"]))
    assert cancelled["ok"] is False
    assert cancelled["error"] == "confirmation_required"

    parser = argparse.ArgumentParser()
    cli.setup_cli(parser)
    applied = cli._dispatch(
        service, parser.parse_args(["retention", "--days", "30", "--yes"])
    )
    assert applied["ok"] is True
    assert isinstance(applied["retention"], dict)


def test_cli_parser_and_dispatch(service, capsys) -> None:
    parser = argparse.ArgumentParser()
    cli.setup_cli(parser)
    args = parser.parse_args(["memory", "list", "--status", "bogus"])
    payload = cli._dispatch(service, args)
    assert payload["error"] == "invalid_status"

    parser = argparse.ArgumentParser()
    cli.setup_cli(parser)
    args = parser.parse_args(["attack-lab"])
    payload = cli._dispatch(service, args)
    assert payload["passed"] == payload["total"] == 12
    assert payload["suite"] == "tripwire"

    parser = argparse.ArgumentParser()
    cli.setup_cli(parser)
    args = parser.parse_args(["attack-lab", "--suite", "hephaestus"])
    payload = cli._dispatch(service, args)
    assert payload["passed"] == payload["total"] == 4
    assert payload["suite"] == "hephaestus"

    parser = argparse.ArgumentParser()
    cli.setup_cli(parser)
    args = parser.parse_args(["doctor"])
    payload = cli._dispatch(service, args)
    assert payload["ok"] is True
    assert {check["name"] for check in payload["checks"]} >= {
        "storage",
        "crypto",
        "checkpoint_dir",
        "attack_lab",
        "data_isolation",
    }

    # run_cli owns and closes the service, so run it after the direct calls.
    parser = argparse.ArgumentParser()
    cli.setup_cli(parser)
    args = parser.parse_args(["status"])
    assert cli.run_cli(args, lambda: service) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["ok"] is True
    assert output["version"] == "0.3.0"
    assert "stats" in output


def test_cli_memory_edit_and_forget_confirmation(service, monkeypatch) -> None:
    parser = argparse.ArgumentParser()
    cli.setup_cli(parser)
    fact = service.capture_turn(
        user_message="The deployment region is Frankfurt", session_id="s", turn_id="1"
    )["candidate"]

    args = parser.parse_args(["memory", "edit", fact["id"], "Berlin", "office"])
    edited = cli._dispatch(service, args)
    assert edited["fact"]["value"] == "Berlin office"

    compatibility_fact = service.capture_turn(
        user_message="The backup region is Paris", session_id="s", turn_id="2"
    )["candidate"]
    args = parser.parse_args(
        ["memory", "edit", compatibility_fact["id"], "--value", "Lyon", "office"]
    )
    edited = cli._dispatch(service, args)
    assert edited["fact"]["value"] == "Lyon office"

    monkeypatch.setattr(cli.sys, "stdin", io.StringIO(""))
    args = parser.parse_args(["memory", "forget", fact["id"]])
    cancelled = cli._dispatch(service, args)
    assert cancelled["error"] == "confirmation_required"

    args = parser.parse_args(["memory", "forget", fact["id"], "--yes"])
    deleted = cli._dispatch(service, args)
    assert deleted["deleted"]["deleted"] is True


def test_cli_checkpoint_passphrase_stdin(service, monkeypatch, tmp_path: Path) -> None:
    parser = argparse.ArgumentParser()
    cli.setup_cli(parser)
    out = tmp_path / "handoff.hcc"

    monkeypatch.setattr("sys.stdin", io.StringIO("correct horse battery staple\n"))
    args = parser.parse_args(
        ["checkpoint", "export", "--out", str(out), "--passphrase-stdin"]
    )
    exported = cli._dispatch(service, args)
    assert exported["status"] == "exported"
    assert Path(exported["path"]).is_file()

    monkeypatch.setattr("sys.stdin", io.StringIO("correct horse battery staple\n"))
    args = parser.parse_args(
        ["checkpoint", "inspect", str(out), "--passphrase-stdin"]
    )
    inspected = cli._dispatch(service, args)
    assert inspected["status"] == "preview"
    assert inspected["manifest"]["checkpoint_id"] == exported["checkpoint_id"]


def test_cli_checkpoint_import_requires_yes_after_preview(service, monkeypatch) -> None:
    parser = argparse.ArgumentParser()
    cli.setup_cli(parser)
    exported = service.export_checkpoint("correct horse battery staple")
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("correct horse battery staple\n"))
    args = parser.parse_args(
        ["checkpoint", "import", exported["path"], "--passphrase-stdin"]
    )
    payload = cli._dispatch(service, args)
    assert payload["error"] == "confirmation_required"
    assert payload["preview"]["can_import"] is True

    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("correct horse battery staple\n"))
    args = parser.parse_args(
        [
            "checkpoint",
            "import",
            exported["path"],
            "--passphrase-stdin",
            "--confirm",
        ]
    )
    payload = cli._dispatch(service, args)
    assert payload["status"] == "imported"


def test_cli_eight_system_groups(service, tmp_path: Path) -> None:
    parser = argparse.ArgumentParser()
    cli.setup_cli(parser)
    workspace = tmp_path / "cli-workspace"
    workspace.mkdir()
    artifact = workspace / "contract.txt"
    artifact.write_text("signed contract", encoding="utf-8")

    args = parser.parse_args(
        [
            "reality",
            "snapshot",
            "--scope",
            str(workspace),
            "--label",
            "cli reality",
            "--path",
            str(artifact),
        ]
    )
    snapshot = cli._dispatch(service, args)
    assert snapshot["ok"] is True
    assert snapshot["snapshot"]["label"] == "cli reality"
    snapshot_id = snapshot["snapshot"]["id"]
    assert cli._dispatch(
        service, parser.parse_args(["reality", "list"])
    )["snapshots"]
    diff = cli._dispatch(
        service, parser.parse_args(["reality", "diff", snapshot_id])
    )
    assert diff["diff"]["level"] == "GREEN"

    recorded = cli._dispatch(
        service,
        parser.parse_args(
            [
                "evidence",
                "record-file",
                str(artifact),
                "--scope",
                "signed contract",
            ]
        ),
    )
    receipt_id = recorded["receipt"]["id"]
    assert recorded["receipt"]["verified"]
    assert cli._dispatch(
        service, parser.parse_args(["evidence", "list"])
    )["receipts"]
    assert cli._dispatch(
        service, parser.parse_args(["evidence", "show", receipt_id])
    )["receipt"]["id"] == receipt_id
    confirmed = cli._dispatch(
        service,
        parser.parse_args(["evidence", "confirm", receipt_id, "--yes"]),
    )
    assert confirmed["receipt"]["id"] == receipt_id
    protected = cli._dispatch(
        service,
        parser.parse_args(
            [
                "evidence",
                "protect",
                str(artifact),
                "--receipt-id",
                receipt_id,
                "--yes",
            ]
        ),
    )
    protected_id = protected["protected"]["id"]
    assert cli._dispatch(
        service, parser.parse_args(["evidence", "challenges"])
    )["challenges"] == []
    released = cli._dispatch(
        service,
        parser.parse_args(
            [
                "evidence",
                "release",
                protected_id,
                "--reason",
                "user replaced artifact",
                "--yes",
            ]
        ),
    )
    assert not released["protected"]["active"]

    charter = service.ensure_charter(
        "Compare three suppliers. Do not send emails. Produce a report.",
        session_id="s-cli-charter",
    )
    assert charter is not None
    active = cli._dispatch(
        service,
        parser.parse_args(["charter", "active", "--session", "s-cli-charter"]),
    )
    assert active["charter"]["id"] == charter["id"]
    assert cli._dispatch(
        service, parser.parse_args(["charter", "list"])
    )["charters"]
    amended = cli._dispatch(
        service,
        parser.parse_args(
            [
                "charter",
                "amend",
                charter["id"],
                "Also include delivery costs.",
                "--rationale",
                "User updated objective.",
                "--yes",
            ]
        ),
    )
    assert amended["charter"]["version"] == 2
    subgoal = amended["charter"]["subgoals"][0]
    advanced = cli._dispatch(
        service,
        parser.parse_args(
            [
                "charter",
                "advance",
                charter["id"],
                subgoal["id"],
                "--completed",
            ]
        ),
    )
    assert advanced["charter"]["subgoals"][0]["status"] == "completed"
    completed = cli._dispatch(
        service,
        parser.parse_args(["charter", "complete", charter["id"], "--yes"]),
    )
    assert completed["assessment"]["outcome"] == "complete"

    preview = cli._dispatch(
        service,
        parser.parse_args(
            [
                "preview",
                "run",
                "write_file",
                "--args-json",
                json.dumps(
                    {
                        "path": str(workspace / "planned.txt"),
                        "content": "planned",
                    }
                ),
            ]
        ),
    )
    assert preview["preview"]["tool_name"] == "write_file"
    assert (workspace / "planned.txt").exists() is False
    assert cli._dispatch(
        service, parser.parse_args(["preview", "list"])
    )["previews"]

    circuit_args = {"path": "cli/planned.txt", "content": "same attempt"}
    for index in range(3):
        service.metis.observe_result(
            "write_file",
            circuit_args,
            status="failed",
            result={"error": "permission denied"},
            tool_call_id=f"cli-circuit-{index}",
        )
    circuits = cli._dispatch(
        service, parser.parse_args(["execution", "list"])
    )["circuits"]
    circuit_id = circuits[0]["id"]
    assert cli._dispatch(
        service, parser.parse_args(["execution", "status", circuit_id])
    )["circuit"]["status"] == "open"
    reset = cli._dispatch(
        service,
        parser.parse_args(
            [
                "execution",
                "reset",
                circuit_id,
                "--reason",
                "user changed strategy",
                "--yes",
            ]
        ),
    )
    assert reset["circuit"]["status"] == "closed"


def test_slash_handler_commands(tmp_path: Path) -> None:
    database = tmp_path / "slash.db"
    checkpoints = tmp_path / "slash-checkpoints"

    def factory():
        return ContinuumService.from_path(database, checkpoint_dir=checkpoints)

    handler = cli.build_slash_handler(factory)
    status = handler("status")
    assert "Continuum v" in status
    assert "confirmed" in status
    assert "Usage: /continuum recall" in handler("recall")
    assert "No candidate memory facts" in handler("memory list")
    assert "Attack Lab (tripwire): 12/12" in handler("attack-lab")
    assert "Attack Lab (hephaestus): 4/4" in handler("attack-lab --suite hephaestus")
    assert "Checkpoints:" in handler("checkpoint")
    assert "Continuum commands" in handler("help")
    assert "Continuum commands" in handler("nonsense")


def test_slash_handler_reports_unavailable(monkeypatch) -> None:
    def broken():
        raise RuntimeError("offline")

    handler = cli.build_slash_handler(broken)
    assert "Continuum unavailable" in handler("status")
    assert "offline" not in handler("status")


def test_cli_register_declares_continuum(service) -> None:
    calls = {}

    class Ctx:
        def register_cli_command(self, **kwargs):
            calls.update(kwargs)

    cli.register_cli(ctx=Ctx(), service_factory=lambda: service)
    assert calls["name"] == "continuum"
    assert calls["setup_fn"] is cli.setup_cli
    assert callable(calls["handler_fn"])
