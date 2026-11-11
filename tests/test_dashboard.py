"""Continuum Console dashboard API routes, errors, and secret handling."""

from __future__ import annotations

import contextlib
import importlib.util
import json
import re
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
PREFIX = "/api/plugins/hermes-continuum"
PASSPHRASE = "correct horse battery staple"


def _load_api():
    path = PLUGIN_ROOT / "dashboard" / "plugin_api.py"
    spec = importlib.util.spec_from_file_location("continuum_dashboard_api_test", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def api(service, monkeypatch):
    module = _load_api()

    @contextlib.contextmanager
    def fake_service():
        yield service

    monkeypatch.setattr(module, "_service", fake_service)
    app = FastAPI()
    app.include_router(module.router, prefix=PREFIX)
    return module, TestClient(app)


def test_health_status_and_overview(api) -> None:
    _, client = api
    health = client.get(f"{PREFIX}/health")
    assert health.status_code == 200
    assert health.json()["ok"] is True
    assert health.json()["plugin"] == "hermes-continuum"

    status = client.get(f"{PREFIX}/status")
    assert status.status_code == 200
    payload = status.json()
    assert payload["ok"] is True
    assert payload["read_only"] is True
    assert payload["schema_version"] == 3

    overview = client.get(f"{PREFIX}/overview")
    assert overview.status_code == 200
    body = overview.json()
    assert "status" in body
    assert "recent_events" in body
    assert "checkpoint_files" in body
    assert "config" in body


def test_timeline_memory_security_and_checkpoints(api, service) -> None:
    _, client = api
    fact = service.capture_turn(
        user_message="The deployment region is Frankfurt", session_id="s", turn_id="1"
    )["candidate"]
    service.confirm_memory(fact["id"])
    service.store.append_event("session_started", "test", session_id="s")

    timeline = client.get(f"{PREFIX}/timeline?limit=10")
    assert timeline.status_code == 200
    assert timeline.json()["count"] >= 1
    event_id = timeline.json()["events"][0]["event_id"]
    detail = client.get(f"{PREFIX}/events/{event_id}")
    assert detail.status_code == 200
    assert detail.json()["event"]["event_id"] == event_id
    assert client.get(f"{PREFIX}/events/missing").status_code == 404

    memory = client.get(f"{PREFIX}/memory?status=confirmed")
    assert memory.status_code == 200
    assert memory.json()["facts"][0]["value"] == "Frankfurt"
    assert client.get(f"{PREFIX}/memory?status=bogus").status_code == 400

    security = client.get(f"{PREFIX}/security")
    assert security.status_code == 200
    assert "counts" in security.json()

    checkpoints = client.get(f"{PREFIX}/checkpoints")
    assert checkpoints.status_code == 200
    assert "checkpoint_dir" in checkpoints.json()


def test_memory_actions_and_validation(api, service) -> None:
    _, client = api
    fact = service.capture_turn(
        user_message="I prefer dark mode", session_id="s", turn_id="1"
    )["candidate"]

    confirmed = client.post(f"{PREFIX}/memory/{fact['id']}/confirm")
    assert confirmed.status_code == 200
    assert confirmed.json()["fact"]["status"] == "confirmed"

    edited = client.post(
        f"{PREFIX}/memory/{fact['id']}/edit", json={"value": "light mode"}
    )
    assert edited.status_code == 200
    assert edited.json()["fact"]["value"] == "light mode"
    assert client.post(f"{PREFIX}/memory/{fact['id']}/edit", json={}).status_code == 400

    rejected = client.post(f"{PREFIX}/memory/{edited.json()['fact']['id']}/reject")
    assert rejected.status_code == 200
    assert rejected.json()["fact"]["status"] == "rejected"

    assert client.post(f"{PREFIX}/memory/{fact['id']}/forget", json={}).status_code == 400
    forgotten = client.post(
        f"{PREFIX}/memory/{fact['id']}/forget", json={"confirm": True}
    )
    assert forgotten.status_code == 200
    assert forgotten.json()["deleted"]["deleted"] is True


def test_dream_attack_lab_and_retention(api) -> None:
    _, client = api
    dream = client.post(f"{PREFIX}/dream")
    assert dream.status_code == 200
    assert dream.json()["dream"]["status"] == "no_new_episodes"

    lab = client.post(f"{PREFIX}/attack-lab/run")
    assert lab.status_code == 200
    assert lab.json()["passed"] == lab.json()["total"] == 12

    retention = client.post(f"{PREFIX}/retention", json={"days": 30})
    assert retention.status_code == 200
    assert "episodes_deleted" in retention.json()["retention"]
    assert client.post(f"{PREFIX}/retention", json={"days": "nope"}).status_code == 400


def test_eight_system_read_routes(api, service, tmp_path: Path) -> None:
    _, client = api
    workspace = tmp_path / "dashboard-workspace"
    workspace.mkdir()
    artifact = workspace / "artifact.txt"
    artifact.write_text("dashboard artifact", encoding="utf-8")

    snapshot = client.post(
        f"{PREFIX}/reality/snapshot",
        json={
            "scope": str(workspace),
            "paths": [str(artifact)],
            "label": "dashboard",
        },
    )
    assert snapshot.status_code == 200
    snapshot_id = snapshot.json()["snapshot"]["id"]

    pillars = client.get(f"{PREFIX}/pillars")
    assert pillars.status_code == 200
    assert pillars.json()["ok"] is True
    assert {item["id"] for item in pillars.json()["pillars"]} >= {
        "continuity",
        "memory",
        "intent",
        "resilience",
    }

    reality = client.get(f"{PREFIX}/reality")
    assert reality.status_code == 200
    assert reality.json()["latest_snapshot"]["id"] == snapshot_id

    diff = client.post(f"{PREFIX}/reality/diff", json={"snapshot_id": snapshot_id})
    assert diff.status_code == 200
    assert diff.json()["diff"]["level"] == "GREEN"

    evidence = client.get(f"{PREFIX}/evidence")
    assert evidence.status_code == 200
    assert evidence.json()["ok"] is True
    assert "receipts" in evidence.json()

    charters = client.get(f"{PREFIX}/charters")
    assert charters.status_code == 200
    assert charters.json()["ok"] is True

    previews = client.get(f"{PREFIX}/previews")
    assert previews.status_code == 200
    assert previews.json()["ok"] is True

    execution = client.get(f"{PREFIX}/execution")
    assert execution.status_code == 200
    assert execution.json()["ok"] is True


def test_eight_system_console_actions(api, service, tmp_path: Path) -> None:
    _, client = api
    artifact = tmp_path / "console-artifact.txt"
    artifact.write_text("console evidence", encoding="utf-8")

    recorded = client.post(
        f"{PREFIX}/evidence/record-file",
        json={"path": str(artifact), "scope": "console test"},
    )
    assert recorded.status_code == 200
    receipt_id = recorded.json()["receipt"]["id"]
    confirmed = client.post(f"{PREFIX}/evidence/{receipt_id}/confirm")
    assert confirmed.status_code == 200
    assert confirmed.json()["receipt"]["id"] == receipt_id
    protected = client.post(
        f"{PREFIX}/evidence/protect",
        json={"artifact_ref": str(artifact), "receipt_id": receipt_id},
    )
    assert protected.status_code == 200
    protected_id = protected.json()["protected"]["id"]
    released = client.post(
        f"{PREFIX}/evidence/protected/{protected_id}/release",
        json={"reason": "user replaced the artifact"},
    )
    assert released.status_code == 200
    assert not released.json()["protected"]["active"]
    assert client.post(f"{PREFIX}/evidence/protect", json={}).status_code == 400

    charter = service.ensure_charter(
        "Compare three suppliers. Do not send emails. Produce a report.",
        session_id="s-dashboard",
    )
    assert charter is not None
    amended = client.post(
        f"{PREFIX}/charters/{charter['id']}/amend",
        json={"amendment": "Also include delivery costs."},
    )
    assert amended.status_code == 200
    assert amended.json()["charter"]["version"] == 2
    assert (
        client.post(f"{PREFIX}/charters/{charter['id']}/amend", json={}).status_code
        == 400
    )
    completed = client.post(
        f"{PREFIX}/charters/{charter['id']}/complete",
        json={"claimed_complete": True, "evidence_ids": []},
    )
    assert completed.status_code == 200
    assert completed.json()["assessment"]["outcome"] == "complete"
    assert (
        client.post(
            f"{PREFIX}/charters/{charter['id']}/complete",
            json={"evidence_ids": "bogus"},
        ).status_code
        == 400
    )

    destination = tmp_path / "dashboard-planned.txt"
    preview = client.post(
        f"{PREFIX}/previews",
        json={
            "tool_name": "write_file",
            "args": {"path": str(destination), "content": "planned"},
        },
    )
    assert preview.status_code == 200
    assert preview.json()["preview"]["tool_name"] == "write_file"
    assert destination.exists() is False
    assert client.post(f"{PREFIX}/previews", json={}).status_code == 400

    circuit_args = {"path": "console/planned.txt", "content": "same attempt"}
    for index in range(3):
        service.metis.observe_result(
            "write_file",
            circuit_args,
            status="failed",
            result={"error": "permission denied"},
            tool_call_id=f"dashboard-circuit-{index}",
        )
    circuit = service.metis.list_circuits(status="open")[0]
    reset = client.post(
        f"{PREFIX}/execution/{circuit['id']}/reset",
        json={"reason": "user changed strategy"},
    )
    assert reset.status_code == 200
    assert reset.json()["circuit"]["status"] == "closed"


def test_checkpoint_export_rejects_destination_and_never_returns_passphrase(api) -> None:
    _, client = api
    missing = client.post(f"{PREFIX}/checkpoints/export", json={})
    assert missing.status_code == 400
    assert missing.json()["detail"]["error"] == "invalid_request"

    destination = client.post(
        f"{PREFIX}/checkpoints/export",
        json={"passphrase": PASSPHRASE, "destination": "C:/tmp/out.hcc"},
    )
    assert destination.status_code == 400
    assert destination.json()["detail"]["error"] == "invalid_request"

    exported = client.post(
        f"{PREFIX}/checkpoints/export", json={"passphrase": PASSPHRASE}
    )
    assert exported.status_code == 200
    body = exported.json()
    assert body["ok"] is True
    assert body["status"] == "exported"
    assert PASSPHRASE not in json.dumps(body)
    path = body["path"]

    inspected = client.post(
        f"{PREFIX}/checkpoints/inspect",
        json={"passphrase": PASSPHRASE, "path": path},
    )
    assert inspected.status_code == 200
    assert inspected.json()["preview"]["status"] == "preview"
    assert PASSPHRASE not in json.dumps(inspected.json())

    assert (
        client.post(
            f"{PREFIX}/checkpoints/inspect", json={"passphrase": PASSPHRASE}
        ).status_code
        == 400
    )
    assert (
        client.post(
            f"{PREFIX}/checkpoints/inspect",
            json={"passphrase": "short", "path": path},
        ).status_code
        == 400
    )

    preview = client.post(
        f"{PREFIX}/checkpoints/import",
        json={"passphrase": PASSPHRASE, "path": path},
    )
    assert preview.status_code == 200
    assert preview.json()["status"] == "preview"

    imported = client.post(
        f"{PREFIX}/checkpoints/import",
        json={"passphrase": PASSPHRASE, "path": path, "confirm": True},
    )
    assert imported.status_code == 200
    assert imported.json()["status"] == "imported"
    assert PASSPHRASE not in json.dumps(imported.json())


def test_resume_brief_dismiss(api, service) -> None:
    _, client = api
    exported = service.export_checkpoint(PASSPHRASE)
    imported = service.import_checkpoint(exported["path"], PASSPHRASE, confirm=True)
    brief_id = imported["resume_brief_id"]
    assert brief_id
    dismissed = client.post(f"{PREFIX}/resume-brief/{brief_id}/dismiss")
    assert dismissed.status_code == 200
    assert dismissed.json()["dismissed"] == brief_id
    assert service.active_resume_brief() is None


def test_hephaestus_forge_and_lease_routes(api, service) -> None:
    _, client = api
    session = "dashboard-forge"
    for call_id, tool, args, status in (
        ("dash-read", "read_file", {"path": "workspace/output/input.md"}, "completed"),
        (
            "dash-write",
            "write_file",
            {"path": "workspace/output/report.md", "content": "x"},
            "completed",
        ),
    ):
        service.store.append_event(
            "tool_result_observed",
            f"{tool} {status}",
            session_id=session,
            tool_call_id=call_id,
            details={
                "tool_name": tool,
                "args_preview": args,
                "status": status,
                "result_hash": f"hash-{call_id}",
            },
        )

    read_model = client.get(f"{PREFIX}/forge")
    assert read_model.status_code == 200
    assert read_model.json()["ok"] is True
    assert read_model.json()["counts"]["playbooks"] == 0

    options = {
        "session_id": session,
        "name": "Dashboard report",
        "allowed_tools": ["read_file", "write_file"],
        "allowed_paths": ["workspace/output"],
        "cron_job_id": "dashboard-job",
        "max_tool_calls": 2,
    }
    preview = client.post(f"{PREFIX}/forge/preview", json=options)
    assert preview.status_code == 200
    assert preview.json()["can_forge"] is True
    assert preview.json()["status"] == "preview"

    gated = client.post(f"{PREFIX}/forge", json=options)
    assert gated.status_code == 400
    assert gated.json()["detail"]["error"] == "confirmation_required"
    assert service.store.list_playbooks() == []

    forged = client.post(f"{PREFIX}/forge", json={**options, "confirm": True})
    assert forged.status_code == 200
    playbook = forged.json()["playbook"]
    lease = forged.json()["lease"]
    assert playbook["status"] == "forged"
    assert lease["status"] == "active"

    quarantined = client.post(
        f"{PREFIX}/forge/{playbook['id']}/quarantine",
        json={"reason": "dashboard review", "confirm": True},
    )
    assert quarantined.status_code == 200
    assert quarantined.json()["playbook"]["status"] == "quarantined"
    assert service.store.list_safety_leases(status="active") == []
    assert client.post(
        f"{PREFIX}/forge/{playbook['id']}/unquarantine", json={}
    ).status_code == 400

    released = client.post(
        f"{PREFIX}/forge/{playbook['id']}/unquarantine",
        json={"confirm": True},
    )
    assert released.status_code == 200
    assert released.json()["playbook"]["status"] == "forged"

    issued = client.post(
        f"{PREFIX}/leases",
        json={
            "playbook_id": playbook["id"],
            "allowed_tools": ["read_file", "write_file"],
            "allowed_paths": ["workspace/output"],
            "cron_job_id": "dashboard-job",
            "confirm": True,
        },
    )
    assert issued.status_code == 200
    new_lease_id = issued.json()["lease"]["id"]
    assert client.post(
        f"{PREFIX}/leases/{new_lease_id}/revoke", json={}
    ).status_code == 400
    revoked = client.post(
        f"{PREFIX}/leases/{new_lease_id}/revoke",
        json={"reason": "dashboard test", "confirm": True},
    )
    assert revoked.status_code == 200
    assert revoked.json()["lease"]["status"] == "revoked"

    lab = client.post(f"{PREFIX}/attack-lab/run", json={"suite": "hephaestus"})
    assert lab.status_code == 200
    assert lab.json()["suite"] == "hephaestus"
    assert lab.json()["passed"] == lab.json()["total"] == 4


def test_desktop_console_calls_real_backend_routes(api) -> None:
    module, _ = api
    routes = {route.path for route in module.router.routes}
    source = (PLUGIN_ROOT / "desktop" / "plugin.js").read_text(encoding="utf-8")
    calls = set(re.findall(r"ctx\.rest\('(/[A-Za-z0-9_./-]+)'", source))
    assert calls
    assert calls <= routes, sorted(calls - routes)
    for dynamic in (
        "/memory/{fact_id}/confirm",
        "/memory/{fact_id}/reject",
        "/memory/{fact_id}/edit",
        "/memory/{fact_id}/forget",
        "/events/{event_id}",
        "/resume-brief/{brief_id}/dismiss",
        "/execution/{circuit_id}/reset",
        "/forge/{playbook_id}/quarantine",
        "/forge/{playbook_id}/unquarantine",
        "/leases/{lease_id}/revoke",
    ):
        assert dynamic in routes
    for path in (
        "/pillars",
        "/reality/snapshot",
        "/reality/diff",
        "/previews",
        "/forge",
        "/forge/preview",
        "/leases",
    ):
        assert path in calls
        assert path in routes


def test_unexpected_errors_are_generic(api, service, monkeypatch) -> None:
    _, client = api

    def broken():
        raise RuntimeError("database password=hunter2")

    monkeypatch.setattr(service, "status", broken)
    response = client.get(f"{PREFIX}/status")
    assert response.status_code == 500
    body = response.json()
    assert body["detail"]["error"] == "internal_error"
    assert "hunter2" not in json.dumps(body)
    assert "database password" not in json.dumps(body)
