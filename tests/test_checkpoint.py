"""Continuum checkpoint encryption, preview/import, conflicts, and resume briefs."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from continuum_core.checkpoint import crypto
from continuum_core.common.errors import CheckpointError
from continuum_core.common.ids import new_id
from continuum_core.service import ContinuumService

PASSPHRASE = "correct horse battery staple"
SECRET = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789"


def _second_service(tmp_path: Path, name: str) -> ContinuumService:
    return ContinuumService.from_path(
        tmp_path / f"{name}.db",
        checkpoint_dir=tmp_path / f"{name}-checkpoints",
    )


def test_crypto_roundtrip_and_wrong_passphrase() -> None:
    manifest = {
        "format": crypto.FORMAT,
        "format_version": crypto.FORMAT_VERSION,
        "checkpoint_id": new_id("ckpt"),
        "counts": {"events": 1},
    }
    payload = {"data": {"events": [{"id": 1}]}}
    bundle = crypto.encrypt_bundle(manifest, json.dumps(payload).encode(), PASSPHRASE)
    header, plaintext = crypto.decrypt_bundle(bundle, PASSPHRASE)
    assert header["manifest"]["checkpoint_id"] == manifest["checkpoint_id"]
    assert json.loads(plaintext) == payload
    with pytest.raises(CheckpointError):
        crypto.decrypt_bundle(bundle, "wrong passphrase")


def test_crypto_rejects_short_passphrase() -> None:
    with pytest.raises(CheckpointError):
        crypto.validate_passphrase("short")


def test_crypto_rejects_tampered_ciphertext() -> None:
    manifest = {"format": crypto.FORMAT, "format_version": 1, "checkpoint_id": "x"}
    bundle = crypto.encrypt_bundle(manifest, b"payload", PASSPHRASE)
    raw = bytearray(crypto.bundle_bytes(bundle))
    # Flip a byte in the encrypted body, not the magic/header.
    raw[-1] ^= 0x01
    with pytest.raises(CheckpointError):
        crypto.parse_bundle_bytes(bytes(raw))


def test_crypto_rejects_tampered_manifest() -> None:
    manifest = {"format": crypto.FORMAT, "format_version": 1, "checkpoint_id": "x"}
    bundle = crypto.encrypt_bundle(manifest, b"payload", PASSPHRASE)
    bundle["manifest"]["checkpoint_id"] = "tampered"
    with pytest.raises(CheckpointError):
        crypto.decrypt_bundle(bundle, PASSPHRASE)


def test_export_inspect_and_preview_do_not_write(service, tmp_path: Path) -> None:
    fact = service.capture_turn(
        user_message="The deployment region is Frankfurt", session_id="s", turn_id="1"
    )["candidate"]
    service.confirm_memory(fact["id"])
    before_events = service.store.total_events()
    before_facts = len(service.memory_list())

    exported = service.export_checkpoint(PASSPHRASE)
    assert exported["status"] == "exported"
    path = Path(exported["path"])
    assert path.is_file()
    assert path.suffix == ".hcc"
    assert exported["manifest"]["format"] == "hermes-continuum-checkpoint"
    assert exported["manifest"]["source_installation_id"] == service.store.installation_id
    assert exported["counts"]["memory_facts"] >= 1

    # The export itself is recorded in the spine; preview/inspect must not add
    # import events or mutate memory.
    after_export_events = service.store.total_events()
    # Export records the Kairos environment snapshot and the checkpoint itself.
    assert after_export_events == before_events + 2
    after_export_facts = len(service.memory_list())
    assert after_export_facts == before_facts

    inspected = service.inspect_checkpoint(path, PASSPHRASE)
    assert inspected["status"] == "preview"
    assert inspected["can_import"] is True
    assert inspected["manifest"]["checkpoint_id"] == exported["checkpoint_id"]

    preview = service.import_checkpoint(path, PASSPHRASE, confirm=False)
    assert preview["status"] == "preview"
    assert preview["can_import"] is True
    assert service.store.total_events() == after_export_events
    assert len(service.memory_list()) == after_export_facts


def test_wrong_passphrase_and_checksum_mismatch_are_rejected(service) -> None:
    exported = service.export_checkpoint(PASSPHRASE)
    path = exported["path"]
    with pytest.raises(CheckpointError):
        service.inspect_checkpoint(path, "wrong passphrase")
    with pytest.raises(CheckpointError):
        service.inspect_checkpoint(
            path, PASSPHRASE, expected_checksum="0" * 64
        )


def test_import_confirm_is_idempotent(service, tmp_path: Path) -> None:
    fact = service.capture_turn(
        user_message="I prefer dark mode", session_id="s", turn_id="1"
    )["candidate"]
    service.confirm_memory(fact["id"])
    exported = service.export_checkpoint(PASSPHRASE)
    path = exported["path"]

    target = _second_service(tmp_path, "target")
    try:
        first = target.import_checkpoint(path, PASSPHRASE, confirm=True)
        assert first["status"] == "imported"
        assert first["imported"]["inserted"]["memory_facts"] >= 1
        assert first["resume_brief_id"]
        brief = target.active_resume_brief()
        assert brief is not None
        assert brief["active"] == 1
        assert "resume brief" in brief["brief"].lower()
        assert "context, not authorization" in brief["brief"].lower()

        second = target.import_checkpoint(path, PASSPHRASE, confirm=True)
        assert second["status"] == "already_imported"
        assert second["source_checkpoint_id"] == first["source_checkpoint_id"]
    finally:
        target.close()


def test_import_conflict_preserves_local_confirmed_value(service, tmp_path: Path) -> None:
    source_fact = service.capture_turn(
        user_message="The deployment region is Frankfurt", session_id="s", turn_id="1"
    )["candidate"]
    service.confirm_memory(source_fact["id"])
    exported = service.export_checkpoint(PASSPHRASE)

    target = _second_service(tmp_path, "target-conflict")
    try:
        local_fact = target.capture_turn(
            user_message="The deployment region is Berlin", session_id="s", turn_id="1"
        )["candidate"]
        target.confirm_memory(local_fact["id"])
        preview = target.import_checkpoint(exported["path"], PASSPHRASE, confirm=False)
        assert preview["conflicts"]
        assert preview["conflicts"][0]["fact_key"] == "deployment region"
        assert preview["conflicts"][0]["imported_value"] == "Frankfurt"
        assert preview["conflicts"][0]["local_value"] == "Berlin"

        imported = target.import_checkpoint(exported["path"], PASSPHRASE, confirm=True)
        assert imported["status"] == "imported"
        current = target.store.find_current_fact("deployment region")
        assert current["value"] == "Berlin"
        assert current["status"] == "confirmed"
        candidates = target.memory_list(status="candidate")
        imported_candidate = [fact for fact in candidates if fact["value"] == "Frankfurt"]
        assert imported_candidate
        assert imported_candidate[0]["contradicts_fact_id"] == local_fact["id"]
        assert imported_candidate[0]["version"] > local_fact["version"]
    finally:
        target.close()


def test_export_excludes_secret_canaries(service) -> None:
    service.store.append_event(
        "session_observed",
        f"secret {SECRET}",
        details={"password": "hunter2", "nested": {"token": SECRET}},
    )
    exported = service.export_checkpoint(PASSPHRASE)
    raw = Path(exported["path"]).read_bytes()
    bundle = crypto.parse_bundle_bytes(raw)
    header, plaintext = crypto.decrypt_bundle(bundle, PASSPHRASE)
    payload = json.loads(plaintext)
    rendered = json.dumps(payload)
    assert SECRET not in rendered
    assert "hunter2" not in rendered
    assert header["manifest"]["excluded"]


def test_export_to_directory_uses_generated_filename(service, tmp_path: Path) -> None:
    destination = tmp_path / "exports"
    destination.mkdir()
    exported = service.export_checkpoint(PASSPHRASE, destination=destination)
    assert Path(exported["path"]).parent == destination
    assert Path(exported["path"]).name.startswith("continuum-")
    assert Path(exported["path"]).suffix == ".hcc"


def test_resume_brief_can_be_dismissed(service, tmp_path: Path) -> None:
    exported = service.export_checkpoint(PASSPHRASE)
    target = _second_service(tmp_path, "brief-target")
    try:
        imported = target.import_checkpoint(exported["path"], PASSPHRASE, confirm=True)
        brief_id = imported["resume_brief_id"]
        assert target.active_resume_brief() is not None
        target.dismiss_resume_brief(brief_id)
        assert target.active_resume_brief() is None
    finally:
        target.close()


def test_checkpoint_file_size_limit(service) -> None:
    from continuum_core.common.config import ContinuumConfig

    exported = service.export_checkpoint(PASSPHRASE)
    # Bypass clamping for this test so a tiny real bundle exceeds the limit.
    service.checkpoint_service.config = ContinuumConfig(checkpoint_max_bytes=1)
    with pytest.raises(CheckpointError):
        service.inspect_checkpoint(exported["path"], PASSPHRASE)


def test_import_rejects_missing_file(service, tmp_path: Path) -> None:
    with pytest.raises(CheckpointError):
        service.import_checkpoint(tmp_path / "missing.hcc", PASSPHRASE, confirm=True)


def test_checkpoint_list_and_files(service) -> None:
    exported = service.export_checkpoint(PASSPHRASE)
    assert service.list_checkpoints()
    assert service.checkpoint_files()
    assert service.checkpoint_files()[0]["filename"] == exported["filename"]
