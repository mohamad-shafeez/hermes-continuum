"""Runtime, checkpoint, and old-bundle integration for the eight systems."""

from __future__ import annotations

import json
from pathlib import Path

from continuum_core.checkpoint import crypto
from continuum_core.common.config import ContinuumConfig
from continuum_core.common.ids import new_id
from continuum_core.runtime import ContinuumRuntime
from continuum_core.service import ContinuumService

from conftest import RecordingContext

PASSPHRASE = "correct horse battery staple"
REQUEST = (
    "Research three suppliers and compare pricing. Do not send emails. "
    "Produce a comparison report."
)


def _runtime(service: ContinuumService) -> ContinuumRuntime:
    runtime = ContinuumRuntime(RecordingContext())
    runtime._service = service
    runtime._config = service.config
    return runtime


def _service(tmp_path: Path, name: str, **config: object) -> ContinuumService:
    config["kairos_scope"] = str(tmp_path / "workspace")
    config["kairos_max_files"] = 20
    return ContinuumService.from_path(
        tmp_path / f"{name}.db",
        config=ContinuumConfig(**config),
        checkpoint_dir=tmp_path / f"{name}-checkpoints",
    )


def test_runtime_creates_telos_context_and_holds_constraint_conflicts(
    tmp_path: Path,
) -> None:
    (tmp_path / "workspace").mkdir()
    service = _service(tmp_path, "runtime-telos")
    runtime = _runtime(service)
    try:
        injected = runtime.pre_llm_call(session_id="s-telos", user_message=REQUEST)
        assert injected is not None
        assert "Telos task charter v1" in injected["context"]
        charter = service.telos.active_charter(session_id="s-telos")
        assert charter is not None

        decision = runtime.pre_tool_call(
            "send_email",
            {"to": "customer@example.invalid", "body": "report"},
            session_id="s-telos",
            tool_call_id="call-telos",
        )
        assert decision is not None
        assert decision["action"] == "approve"
        assert decision["rule_key"] == "telos.constraint.conflict"
        assert "Impact preview:" in decision["message"]

        runtime.post_tool_call(
            "send_email",
            {"to": "customer@example.invalid", "body": "report"},
            {"ok": True},
            session_id="s-telos",
            tool_call_id="call-telos",
            status="completed",
        )
        drift = service.telos.list_drift(charter_id=charter["id"])
        assert drift and drift[0]["kind"] == "constraint_violation"
    finally:
        service.close()


def test_runtime_aletheia_holds_protected_work_and_resolves_after_execution(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = workspace / "contract.txt"
    target.write_text("signed contract", encoding="utf-8")
    service = _service(tmp_path, "runtime-aletheia")
    receipt = service.record_evidence_file(target, scope="contract text")
    protected = service.protect_artifact(
        str(target.resolve()), receipt_id=receipt["id"]
    )
    runtime = _runtime(service)
    try:
        args = {"path": str(target), "content": "silent replacement"}
        first = runtime.pre_tool_call(
            "write_file", args, session_id="s-evidence", tool_call_id="call-evidence"
        )
        second = runtime.pre_tool_call(
            "write_file", args, session_id="s-evidence", tool_call_id="call-evidence"
        )
        assert first["action"] == "approve"
        assert first["rule_key"] == "aletheia.protected_artifact"
        assert second["rule_key"] == "aletheia.protected_artifact"
        challenges = service.aletheia.list_challenges()
        assert len(challenges) == 1
        assert challenges[0]["protected_id"] == protected["id"]
        assert challenges[0]["status"] == "held"

        runtime.post_tool_call(
            "write_file",
            args,
            {"ok": True},
            session_id="s-evidence",
            tool_call_id="call-evidence",
            status="completed",
        )
        challenge = service.aletheia.list_challenges()[0]
        assert challenge["status"] == "executed"
        assert service.aletheia.get_receipt(receipt["id"])["status"] == "stale"
    finally:
        service.close()


def test_runtime_metis_blocks_repeated_operation_and_reset_restores_it(
    tmp_path: Path,
) -> None:
    (tmp_path / "workspace").mkdir()
    service = _service(tmp_path, "runtime-metis")
    args = {"path": "workspace/report.txt", "content": "same attempt"}
    for index in range(3):
        service.metis.observe_result(
            "write_file",
            {"path": "workspace/report.txt", "content": "same attempt"},
            status="failed",
            result={"error": "permission denied"},
            tool_call_id=f"metis-{index}",
        )
    circuit = service.metis.list_circuits(status="open")[0]
    runtime = _runtime(service)
    try:
        blocked = runtime.pre_tool_call(
            "write_file", args, session_id="s-metis", tool_call_id="call-metis"
        )
        assert blocked["action"] == "block"
        assert blocked["rule_key"] == "metis.circuit.open"
        assert "Change the strategy" in blocked["message"]

        changed = runtime.pre_tool_call(
            "write_file",
            {"path": "workspace/other.txt", "content": "different attempt"},
            session_id="s-metis",
            tool_call_id="call-other",
        )
        assert changed is None

        service.reset_circuit(circuit["id"], reason="user changed strategy")
        restored = runtime.pre_tool_call(
            "write_file", args, session_id="s-metis", tool_call_id="call-metis"
        )
        assert restored is None
    finally:
        service.close()


def test_checkpoint_carries_all_new_systems_and_produces_resume_context(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = workspace / "report.txt"
    target.write_text("report v1", encoding="utf-8")
    source = _service(tmp_path, "checkpoint-source")
    try:
        snapshot = source.reality_snapshot(
            scope=str(workspace), paths=[str(target)], label="source"
        )
        receipt = source.record_evidence_file(target, scope="report")
        source.protect_artifact(str(target.resolve()), receipt_id=receipt["id"])
        charter = source.ensure_charter(REQUEST, session_id="s-checkpoint")
        source.preview_action(
            "write_file", {"path": str(target), "content": "new"}
        )
        source.metis.observe_result(
            "write_file",
            {"path": str(target), "content": "new"},
            status="failed",
            result={"error": "permission denied"},
            tool_call_id="cp-failure",
        )
        exported = source.export_checkpoint(PASSPHRASE)
    finally:
        source.close()

    manifest = exported["manifest"]
    assert manifest["format_version"] == 2
    assert manifest["environment_fingerprint_hash"] == snapshot["fingerprint_hash"]
    assert manifest["environment_fingerprint"]
    for table in (
        "kairos_snapshots",
        "aletheia_receipts",
        "aletheia_protected",
        "telos_charters",
        "moirai_previews",
        "metis_failures",
    ):
        assert exported["counts"][table] >= 1

    restored = _service(tmp_path, "checkpoint-restored")
    try:
        imported = restored.import_checkpoint(
            exported["path"], PASSPHRASE, confirm=True
        )
        assert imported["status"] == "imported"
        assert imported["imported"]["inserted"]["telos_charters"] >= 1
        assert imported["imported"]["inserted"]["aletheia_receipts"] >= 1
        assert imported["imported"]["inserted"]["moirai_previews"] >= 1
        assert restored.telos.list_charters()
        assert restored.aletheia.list_receipts()
        assert restored.aletheia.list_protected()
        assert restored.moirai.list_previews()
        assert restored.metis.list_failures()
        assert restored.store.list_kairos_snapshots()
        # Importing into a different installation correctly produces AMBER:
        # the saved environment belongs to the source installation.
        assert imported["reality_diff"]["level"] == "AMBER"
        assert any(
            item["key"] == "installation_id"
            for item in imported["reality_diff"]["changed"]
        )
        assert imported["resume_brief_id"]
        assert "Active user charter" in imported["resume_brief"]
        assert "Reality" in imported["resume_brief"]
        assert imported["manifest"]["environment_fingerprint_hash"]
        assert charter["id"]
    finally:
        restored.close()


def test_old_payload_schema_one_bundle_is_accepted_without_new_tables(
    tmp_path: Path,
) -> None:
    source = _service(tmp_path, "old-source")
    try:
        fact = source.capture_turn(
            user_message="The approved region is Frankfurt",
            session_id="s-old",
            turn_id="1",
        )["candidate"]
        source.confirm_memory(fact["id"])
        snapshot = source.store.export_snapshot()
    finally:
        source.close()

    old_tables = {
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
    data = {name: rows for name, rows in snapshot["data"].items() if name in old_tables}
    assert not {"playbooks", "safety_leases", "safety_lease_usage"} & set(data)
    counts = {name: len(rows) for name, rows in data.items()}
    checkpoint_id = new_id("ckpt")
    installation_id = "inst_old_export"
    manifest = {
        "format": crypto.FORMAT,
        "format_version": 1,
        "checkpoint_id": checkpoint_id,
        "counts": counts,
        "source_installation_id": installation_id,
        "plugin_version": "0.1.0",
        "schema_version": 1,
        "excluded": [],
    }
    payload = {
        "payload_schema": 1,
        "checkpoint_id": checkpoint_id,
        "source_installation_id": installation_id,
        "plugin_version": "0.1.0",
        "data": data,
        "counts": counts,
        "available": snapshot["available"],
        "truncated": snapshot["truncated"],
    }
    bundle = crypto.encrypt_bundle(
        manifest,
        json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8"),
        PASSPHRASE,
    )
    path = tmp_path / "old-version.hcc"
    path.write_bytes(crypto.bundle_bytes(bundle))

    restored = _service(tmp_path, "old-restored")
    try:
        imported = restored.import_checkpoint(str(path), PASSPHRASE, confirm=True)
        assert imported["status"] == "imported"
        assert imported["reality_diff"] is None
        assert restored.store.total_events() >= 1
        assert any(
            item["fact_key"] == "region" or "Frankfurt" in str(item.get("value"))
            for item in restored.memory_list()
        )
        assert imported["resume_brief"]
    finally:
        restored.close()
