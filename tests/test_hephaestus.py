"""Hephaestus: trace distillation, forging, leases, quarantine, and Attack Lab.

Every test is offline.  Artifacts are written to a temporary directory, and the
recording host context stands in for the verified Hermes registration surface.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from continuum_core.common.config import ContinuumConfig
from continuum_core.hephaestus.artifacts import is_within
from continuum_core.hephaestus import service as hephaestus_service
from continuum_core.runtime import ContinuumRuntime, PluginHostRegistrar
from continuum_core.service import ContinuumService

from conftest import RecordingContext

PASSPHRASE = "correct horse battery staple"


def _service(
    tmp_path: Path,
    name: str = "hephaestus",
    *,
    context: RecordingContext | None = None,
    **settings: object,
) -> tuple[ContinuumService, RecordingContext]:
    ctx = context or RecordingContext()
    service = ContinuumService.from_path(
        tmp_path / f"{name}.db",
        config=ContinuumConfig(**settings),
        checkpoint_dir=tmp_path / f"{name}-checkpoints",
        hephaestus_artifact_dir=tmp_path / f"{name}-artifacts",
        host_registrar=PluginHostRegistrar(ctx),
    )
    return service, ctx


def _result(
    service: ContinuumService,
    session_id: str,
    call_id: str,
    tool_name: str,
    args: dict[str, object],
    *,
    status: str = "completed",
    trust: str = "LOCAL_TOOL_OUTPUT",
    error_type: str | None = None,
) -> None:
    details: dict[str, object] = {
        "tool_name": tool_name,
        "args_preview": args,
        "status": status,
        "result_hash": f"hash-{call_id}",
    }
    if error_type:
        details["error_type"] = error_type
    service.store.append_event(
        "tool_result_observed",
        f"{tool_name} {status}",
        session_id=session_id,
        tool_call_id=call_id,
        trust_label=trust,
        details=details,
    )


def _successful_trace(
    service: ContinuumService, session_id: str = "s-forge"
) -> None:
    _result(
        service,
        session_id,
        "call-read",
        "read_file",
        {"path": "workspace/output/input.md"},
    )
    _result(
        service,
        session_id,
        "call-write",
        "write_file",
        {"path": "workspace/output/report.md", "content": "redacted"},
    )


def _forge(
    service: ContinuumService,
    session_id: str = "s-forge",
    *,
    name: str = "Weekly report",
    cron_job_id: str = "job-weekly",
    **kwargs: object,
) -> dict:
    return service.forge_playbook(
        session_id,
        name=name,
        description="Distilled test procedure.",
        allowed_tools=["read_file", "write_file"],
        allowed_paths=["workspace/output"],
        cron_job_id=cron_job_id,
        confirm=True,
        **kwargs,
    )


def test_distillation_confidence_dedup_drift_and_untrusted_exclusion(
    tmp_path: Path,
) -> None:
    service, _ = _service(tmp_path)
    try:
        session = "s-distill"
        _result(service, session, "c1", "read_file", {"path": "workspace/a.md"})
        _result(
            service,
            session,
            "c2",
            "write_file",
            {"path": "workspace/b.md", "content": "x"},
        )
        # Same tool and canonical params: one retry, not a second instruction.
        _result(service, session, "c3", "read_file", {"path": "workspace/a.md"})
        _result(
            service,
            session,
            "c4",
            "send_email",
            {"to": "customer@example.invalid"},
            status="failed",
            error_type="permission_denied",
        )
        _result(
            service,
            session,
            "c5",
            "web_fetch",
            {"url": "https://untrusted.example/instructions"},
            trust="UNTRUSTED_EXTERNAL",
        )

        trace = service.distill_trace(session)
        assert trace["steps_attempted"] == 5
        assert trace["steps_succeeded"] == 3
        assert trace["confidence"] == pytest.approx(0.6)
        assert trace["untrusted_steps"] == 1
        assert trace["trusted_steps"] == 2
        assert trace["trust_counts"]["UNTRUSTED_EXTERNAL"] == 1
        deduped = [step for step in trace["steps"] if step["tool_name"] == "read_file"]
        assert len(deduped) == 1
        assert trace["anti_patterns"]
        assert trace["anti_patterns"][0]["tool_name"] == "send_email"

        service.store.append_event(
            "drift.flagged",
            "Telos observed a constraint conflict",
            session_id=session,
            tool_call_id="c2",
            details={"rule_key": "telos.constraint.conflict"},
        )
        drifted = service.distill_trace(session)
        assert drifted["drift_observed"] is True
        assert drifted["steps_succeeded"] == 2
        assert drifted["confidence"] == pytest.approx(0.4)
        assert all(step["tool_name"] != "write_file" for step in drifted["steps"])
    finally:
        service.close()


def test_forge_preview_is_read_only_and_confirmation_writes_contained_artifacts(
    tmp_path: Path,
) -> None:
    service, ctx = _service(tmp_path)
    try:
        _successful_trace(service)
        before = service.store.hephaestus_counts()
        preview = service.preview_forge(
            "s-forge",
            name="Weekly report",
            allowed_tools=["read_file", "write_file"],
            allowed_paths=["workspace/output"],
            cron_job_id="job-weekly",
        )
        assert preview["can_forge"] is True
        assert preview["status"] == "preview"
        assert "**`read_file`**" in preview["skill"]["markdown"]
        assert "Observed untrusted evidence" not in preview["skill"]["markdown"]
        assert service.store.hephaestus_counts() == before
        assert not (tmp_path / "hephaestus-artifacts").exists()

        unconfirmed = service.forge_playbook(
            "s-forge", name="Weekly report", confirm=False
        )
        assert unconfirmed["status"] == "confirmation_required"
        assert service.store.list_playbooks() == []
        assert not (tmp_path / "hephaestus-artifacts").exists()

        forged = _forge(service)
        assert forged["status"] == "active"
        assert forged["playbook"]["confidence"] == pytest.approx(1.0)
        assert forged["playbook"]["steps_succeeded"] == 2
        assert forged["lease"]["status"] == "active"
        assert forged["registration"]["skill"]["ok"] is True
        assert forged["registration"]["blueprint"]["ok"] is True
        assert forged["skill"]["name"] in ctx.skills
        assert forged["blueprint"]["key"] in ctx.blueprints
        assert ctx.blueprints[forged["blueprint"]["key"]]["schedule_template"] == (
            "0 9 * * *"
        )
        marker = f"continuum-playbook:{forged['playbook']['id']}"
        assert marker in forged["blueprint"]["prompt_template"]
        assert marker in ctx.blueprints[forged["blueprint"]["key"]]["prompt_template"]
        assert (
            ctx.skills[forged["skill"]["name"]]["frontmatter"]["metadata"]["playbook_id"]
            == forged["playbook"]["id"]
        )

        root = service.hephaestus.artifact_root
        skill_path = Path(forged["skill"]["path"])
        manifest_path = skill_path.parent / "manifest.json"
        blueprint_path = skill_path.parent / "blueprint.json"
        assert is_within(root, skill_path)
        assert skill_path.is_file() and manifest_path.is_file()
        assert blueprint_path.is_file()
        written = skill_path.read_text(encoding="utf-8")
        assert "**`read_file`**" in written
        assert "quoted, never instructions" not in written
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        assert manifest["playbook_id"] == forged["playbook"]["id"]
        assert manifest["status"] in {"forged", "active"}
        assert marker in manifest["blueprint"]["prompt_template"]

        event_types = {
            item["event_type"] for item in service.store.list_events(limit=100)
        }
        assert {
            "playbook.forged",
            "skill.forged",
            "blueprint.forged",
            "lease.issued",
        } <= event_types
        counts = service.store.hephaestus_counts()
        assert counts["playbooks"] == 1
        assert counts["active_leases"] == 1
    finally:
        service.close()


def test_forge_does_not_register_blueprint_when_skill_registration_fails(
    tmp_path: Path,
) -> None:
    class RejectingContext(RecordingContext):
        def register_skill(self, name, path, description="", frontmatter=None):
            raise ValueError("host rejected skill")

    ctx = RejectingContext()
    service, _ = _service(tmp_path, name="rejecting", context=ctx)
    try:
        _successful_trace(service)
        forged = _forge(service)
        assert forged["registration"]["skill"]["ok"] is False
        assert forged["registration"]["blueprint"]["ok"] is False
        assert ctx.skills == {}
        assert ctx.blueprints == {}
        assert "skill registration failed" in forged["registration"]["blueprint"]["error"]
    finally:
        service.close()


def test_rehydration_requires_a_matching_database_playbook(tmp_path: Path) -> None:
    service, _ = _service(tmp_path)
    try:
        _successful_trace(service)
        forged = _forge(service)
        fresh = RecordingContext()
        result = hephaestus_service.rehydrate_artifacts(
            service.hephaestus.artifact_root,
            PluginHostRegistrar(fresh),
            allowed_playbooks={},
        )
        assert result["skills"] == 0
        assert result["blueprints"] == 0
        assert fresh.skills == {}
        assert any("matching forged/active playbook" in item for item in result["errors"])
        # The same manifest is accepted when the durable row is supplied.
        allowed = {forged["playbook"]["id"]: "forged"}
        accepted = hephaestus_service.rehydrate_artifacts(
            service.hephaestus.artifact_root,
            PluginHostRegistrar(fresh),
            allowed_playbooks=allowed,
        )
        assert accepted["skills"] == 1
        assert accepted["blueprints"] == 1
        assert forged["playbook"]["slug"] in fresh.skills
    finally:
        service.close()


def test_quarantine_blocks_skill_view_and_cron_management_until_review(
    tmp_path: Path,
) -> None:
    service, ctx = _service(tmp_path)
    runtime = ContinuumRuntime(ctx)
    runtime._service = service
    runtime._config = service.config
    try:
        _successful_trace(service)
        forged = _forge(service)
        playbook_id = forged["playbook"]["id"]
        slug = forged["playbook"]["slug"]
        qualified = f"hermes-continuum:{slug}"
        service.quarantine_playbook(playbook_id, reason="review", confirmed=True)

        skill_block = runtime.pre_tool_call(
            "skill_view",
            {"name": qualified},
            session_id="s-quarantine",
            tool_call_id="call-view",
        )
        assert skill_block["action"] == "block"
        assert skill_block["rule_key"] == "hephaestus.artifact.quarantined"

        cron_block = runtime.pre_tool_call(
            "cronjob_manage",
            {
                "action": "create",
                "schedule": "0 9 * * *",
                "prompt": f"Use {qualified} ({forged['blueprint']['prompt_template'][:80]})",
                "skills": [qualified],
            },
            session_id="s-quarantine",
            tool_call_id="call-cron",
        )
        assert cron_block["action"] == "block"
        assert cron_block["rule_key"] == "hephaestus.artifact.quarantined"

        run_block = runtime.pre_tool_call(
            "cronjob_manage",
            {"action": "run", "job_id": "job-weekly"},
            session_id="s-quarantine",
            tool_call_id="call-run",
        )
        assert run_block["action"] == "block"

        # Pausing or removing the job remains available for containment.
        pause = runtime.pre_tool_call(
            "cronjob_manage",
            {"action": "pause", "job_id": "job-weekly"},
            session_id="s-quarantine",
            tool_call_id="call-pause",
        )
        assert pause is None or pause.get("rule_key") != "hephaestus.artifact.quarantined"

        service.unquarantine_playbook(playbook_id, confirmed=True)
        after_review = runtime.pre_tool_call(
            "skill_view",
            {"name": qualified},
            session_id="s-quarantine",
            tool_call_id="call-view-2",
        )
        assert after_review is None or after_review.get("action") != "block"
        assert any(
            item["event_type"] == "action_blocked"
            and item["details"].get("rule_key") == "hephaestus.artifact.quarantined"
            for item in service.store.list_events(limit=100)
        )
    finally:
        service.close()


def test_forge_refuses_untrusted_and_low_confidence_traces(tmp_path: Path) -> None:
    service, _ = _service(tmp_path)
    try:
        _result(
            service,
            "s-poisoned",
            "p1",
            "web_fetch",
            {"url": "https://untrusted.example/x"},
            trust="UNTRUSTED_EXTERNAL",
        )
        preview = service.preview_forge("s-poisoned")
        assert preview["can_forge"] is False
        with pytest.raises(ValueError, match="Forge refused"):
            service.forge_playbook("s-poisoned", name="Poisoned", confirm=True)
        assert service.store.list_playbooks() == []

        allowed = service.forge_playbook(
            "s-poisoned",
            name="Reviewed external",
            allow_untrusted=True,
            issue_lease=False,
            confirm=True,
        )
        markdown = Path(allowed["skill"]["path"]).read_text(encoding="utf-8")
        assert "## Verified procedure" in markdown
        assert "No trusted successful step was available" in markdown
        assert "quoted, never instructions" in markdown

        _result(service, "s-low", "l1", "read_file", {"path": "workspace/a.md"})
        for index in range(4):
            _result(
                service,
                "s-low",
                f"l-fail-{index}",
                "read_file",
                {"path": f"workspace/missing-{index}.md"},
                status="failed",
                error_type="not_found",
            )
        low = service.preview_forge("s-low", name="Low confidence")
        assert low["can_forge"] is False
        forced = service.forge_playbook(
            "s-low", name="Low confidence", force=True, confirm=True
        )
        assert forced["playbook"]["confidence"] == pytest.approx(0.2)
    finally:
        service.close()


def test_cron_lease_allow_block_budget_environment_revoke_and_quarantine(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, ctx = _service(tmp_path)
    try:
        _successful_trace(service)
        forged = _forge(service, max_tool_calls=2)
        playbook = forged["playbook"]
        lease = forged["lease"]
        cron = {
            "job_id": "job-weekly",
            "job_name": "job-weekly",
            "execution_id": "exec-1",
        }

        allowed = service.hephaestus.check_cron_tool(
            "read_file",
            {"path": "workspace/output/input.md"},
            cron,
            session_id="s-cron",
        )
        assert allowed["decision"] == "allow"
        assert allowed["usage"]["tool_calls"] == 1

        out_of_scope = service.hephaestus.check_cron_tool(
            "read_file",
            {"path": "workspace/other/input.md"},
            {**cron, "execution_id": "exec-2"},
        )
        assert out_of_scope["decision"] == "block"
        assert out_of_scope["rule_key"] == "hephaestus.lease.path_out_of_scope"

        opaque = service.hephaestus.check_cron_tool(
            "terminal",
            {"command": "curl https://untrusted.example"},
            {**cron, "execution_id": "exec-3"},
        )
        assert opaque["decision"] == "block"
        assert opaque["rule_key"] == "hephaestus.lease.tool_not_allowed"

        second = service.hephaestus.check_cron_tool(
            "write_file",
            {"path": "workspace/output/report.md", "content": "x"},
            {**cron, "execution_id": "exec-4"},
        )
        assert second["decision"] == "allow"
        third = service.hephaestus.check_cron_tool(
            "read_file",
            {"path": "workspace/output/input.md"},
            {**cron, "execution_id": "exec-4"},
        )
        assert third["decision"] == "allow"
        exhausted = service.hephaestus.check_cron_tool(
            "read_file",
            {"path": "workspace/output/input.md"},
            {**cron, "execution_id": "exec-4"},
        )
        assert exhausted["decision"] == "block"
        assert exhausted["rule_key"] == "hephaestus.lease.budget"
        events = {
            item["event_type"] for item in service.store.list_events(limit=100)
        }
        assert {"lease.checked", "lease.violation"} <= events

        # Environment drift is a coarse fingerprint mismatch.
        _successful_trace(service, "s-drift")
        drifted = _forge(
            service,
            session_id="s-drift",
            name="Drift report",
            cron_job_id="job-drift",
        )
        monkeypatch.setattr(
            hephaestus_service, "environment_fingerprint", lambda: "host-drifted"
        )
        drift = service.hephaestus.check_cron_tool(
            "read_file",
            {"path": "workspace/output/input.md"},
            {**cron, "job_id": "job-drift", "job_name": "job-drift", "execution_id": "exec-drift"},
        )
        assert drift["decision"] == "block"
        assert drift["rule_key"] == "hephaestus.lease.environment_changed"
        monkeypatch.undo()

        # A revoked lease must not silently unscope the job it was bound to.
        service.revoke_lease(lease["id"], reason="test revoke", confirmed=True)
        after_revoke = service.hephaestus.check_cron_tool(
            "read_file",
            {"path": "workspace/output/input.md"},
            {**cron, "execution_id": "exec-5"},
        )
        assert after_revoke["decision"] == "block"
        assert after_revoke["rule_key"] == "hephaestus.lease.missing"

        # Quarantine revokes the other active lease and blocks new leases.
        service.quarantine_playbook(
            drifted["playbook"]["id"], reason="review", confirmed=True
        )
        with pytest.raises(ValueError, match="quarantined"):
            service.issue_lease(
                drifted["playbook"]["id"],
                allowed_tools=["read_file"],
                allowed_paths=["workspace/output"],
                confirmed=True,
            )
        service.unquarantine_playbook(drifted["playbook"]["id"], confirmed=True)
        assert service.store.get_playbook(drifted["playbook"]["id"])["status"] == "forged"

        # Rehydration skips quarantined database rows even if a stale manifest exists.
        service.quarantine_playbook(playbook["id"], reason="review", confirmed=True)
        ctx.skills.clear()
        ctx.blueprints.clear()
        result = service.hephaestus.rehydrate()
        assert result["skills"] == 1
        assert playbook["slug"] not in ctx.skills
        assert drifted["playbook"]["slug"] in ctx.skills

        fresh = RecordingContext()
        rehydrated = hephaestus_service.rehydrate_artifacts(
            service.hephaestus.artifact_root,
            PluginHostRegistrar(fresh),
            excluded_slugs={str(playbook["slug"])},
        )
        assert rehydrated["skills"] == 1
        assert playbook["slug"] not in fresh.skills
        assert drifted["playbook"]["slug"] in fresh.skills
    finally:
        service.close()


def test_skill_write_quarantine_uses_recorded_untrusted_context(tmp_path: Path) -> None:
    service, _ = _service(tmp_path)
    try:
        trusted = service.hephaestus.skill_write_check(
            "write_file",
            {"path": "C:/profile/skills/example/SKILL.md", "content": "x"},
            session_id="s-trusted",
        )
        assert trusted["allowed"] is True

        service.store.record_source(
            tool_name="web_fetch",
            source_type="external",
            reference="https://untrusted.example/page",
            trust_label="UNTRUSTED_EXTERNAL",
            session_id="s-untrusted",
        )
        blocked = service.hephaestus.skill_write_check(
            "write_file",
            {"path": "C:/profile/skills/example/SKILL.md", "content": "x"},
            session_id="s-untrusted",
            tool_call_id="call-skill",
        )
        assert blocked["allowed"] is False
        assert blocked["rule_key"] == "hephaestus.skill.untrusted_write"
        normal = service.hephaestus.skill_write_check(
            "write_file",
            {"path": "workspace/output/report.md", "content": "x"},
            session_id="s-untrusted",
        )
        assert normal["allowed"] is True
        assert any(
            item["event_type"] == "skill.quarantined"
            for item in service.store.list_events(limit=50)
        )
    finally:
        service.close()


def test_hephaestus_attack_lab_is_four_deterministic_cases(tmp_path: Path) -> None:
    service, _ = _service(tmp_path)
    try:
        first = service.hephaestus.run_attack_lab()
        second = service.hephaestus.run_attack_lab()
        assert first["suite"] == "hephaestus"
        assert first["total"] == 4
        assert first["passed"] == 4
        assert [case["id"] for case in first["results"]] == [
            case["id"] for case in second["results"]
        ]
        assert all(case["passed"] for case in first["results"])
        assert {case["expected"] for case in first["results"]} == {"block", "excluded"}
        assert service.store.last_attack_lab(suite="hephaestus")["suite"] == "hephaestus"
        tripwire = service.run_attack_lab()
        assert tripwire["suite"] == "tripwire"
        assert tripwire["total"] == 12
    finally:
        service.close()


def test_model_tools_gate_forge_and_lease_actions(tmp_path: Path) -> None:
    service, _ = _service(tmp_path)
    ctx = RecordingContext()
    runtime = ContinuumRuntime(ctx)
    runtime._service = service
    runtime._config = service.config
    try:
        from continuum_core.adapters import tools

        handlers = tools.build_tool_handlers(runtime)
        _successful_trace(service)
        preview = json.loads(
            handlers["continuum_forge"](
                {
                    "action": "preview",
                    "session_id": "s-forge",
                    "name": "Tool report",
                    "allowed_tools": ["read_file", "write_file"],
                    "allowed_paths": ["workspace/output"],
                }
            )
        )
        assert preview["ok"] is True
        assert preview["can_forge"] is True

        unconfirmed = json.loads(
            handlers["continuum_forge"](
                {
                    "action": "forge",
                    "session_id": "s-forge",
                    "name": "Tool report",
                    "allowed_tools": ["read_file", "write_file"],
                    "allowed_paths": ["workspace/output"],
                }
            )
        )
        assert unconfirmed["status"] == "confirmation_required"
        assert service.store.list_playbooks() == []

        forged = json.loads(
            handlers["continuum_forge"](
                {
                    "action": "forge",
                    "session_id": "s-forge",
                    "name": "Tool report",
                    "allowed_tools": ["read_file", "write_file"],
                    "allowed_paths": ["workspace/output"],
                    "confirm": True,
                }
            )
        )
        assert forged["ok"] is True
        playbook_id = forged["playbook"]["id"]
        lease_id = forged["lease"]["id"]

        listed = json.loads(handlers["continuum_lease"]({"action": "list"}))
        assert listed["ok"] is True
        assert any(item["id"] == lease_id for item in listed["leases"])
        refused = json.loads(
            handlers["continuum_lease"](
                {"action": "revoke", "lease_id": lease_id}
            )
        )
        assert refused["error"] == "confirmation_required"
        revoked = json.loads(
            handlers["continuum_lease"](
                {
                    "action": "revoke",
                    "lease_id": lease_id,
                    "reason": "test",
                    "confirm": True,
                }
            )
        )
        assert revoked["lease"]["status"] == "revoked"
        quarantined = json.loads(
            handlers["continuum_lease"](
                {
                    "action": "quarantine",
                    "playbook_id": playbook_id,
                    "confirm": True,
                }
            )
        )
        assert quarantined["playbook"]["status"] == "quarantined"
        assert json.loads(
            handlers["continuum_forge"]({"action": "show", "playbook_id": playbook_id})
        )["playbook"]["status"] == "quarantined"
    finally:
        service.close()


def test_checkpoint_carries_hephaestus_tables(tmp_path: Path) -> None:
    source, _ = _service(tmp_path, "h-source")
    try:
        _successful_trace(source)
        forged = _forge(source, max_tool_calls=3)
        source.hephaestus.check_cron_tool(
            "read_file",
            {"path": "workspace/output/input.md"},
            {"job_id": "job-weekly", "job_name": "job-weekly", "execution_id": "e1"},
        )
        exported = source.export_checkpoint(PASSPHRASE)
        for table in ("playbooks", "safety_leases", "safety_lease_usage"):
            assert exported["counts"][table] >= 1
    finally:
        source.close()

    restored, _ = _service(tmp_path, "h-restored")
    try:
        imported = restored.import_checkpoint(exported["path"], PASSPHRASE, confirm=True)
        assert imported["status"] == "imported"
        assert imported["imported"]["inserted"]["playbooks"] >= 1
        assert restored.store.list_playbooks()
        leases = restored.store.list_safety_leases()
        assert any(item["id"] == forged["lease"]["id"] for item in leases)
        assert restored.store.list_lease_usage()
    finally:
        restored.close()
