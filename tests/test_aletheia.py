"""Aletheia evidence receipts, protection, and challenge honesty."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_test_evidence_requires_a_real_positive_test_run(service) -> None:
    passed = service.aletheia.record_receipt(
        artifact_ref="pytest output",
        verification_method="test_run",
        observed_result="125 passed in 94 seconds",
    )
    assert passed["verified"] == 1
    assert passed["status"] == "current"

    zero = service.aletheia.record_receipt(
        artifact_ref="empty pytest output",
        verification_method="test_run",
        observed_result="collected 0 items; 0 tests ran",
    )
    assert zero["verified"] == 0
    assert zero["status"] == "rejected"
    assert "zero tests" in zero["receipt"]["reason"].lower()

    failed = service.aletheia.record_receipt(
        artifact_ref="failed pytest output",
        verification_method="test_run",
        observed_result="3 passed, 1 failed",
    )
    assert failed["verified"] == 0
    assert failed["status"] == "rejected"

    exit_only = service.aletheia.record_receipt(
        artifact_ref="command result",
        verification_method="command_exit",
        observed_result="exit code 0",
    )
    assert exit_only["verified"] == 0
    assert exit_only["status"] == "unverified"

    assertion = service.aletheia.record_receipt(
        artifact_ref="model assertion",
        verification_method="user_confirmation",
        observed_result="The model says the work is complete.",
    )
    assert assertion["verified"] == 0
    assert assertion["status"] == "unverified"
    assert "model assertion" in assertion["receipt"]["reason"].lower()


def test_file_verification_and_hash_mismatch(service, tmp_path: Path) -> None:
    target = tmp_path / "report.txt"
    target.write_text("verified contents", encoding="utf-8")

    receipt = service.record_evidence_file(
        target, expected_sha256=_sha256(target), scope="report contents"
    )
    assert receipt["verified"] == 1
    assert receipt["status"] == "current"
    assert receipt["artifact_ref"] == str(target.resolve())
    assert receipt["verification_method"] == "file_sha256"

    mismatch = service.record_evidence_file(
        target, expected_sha256="0" * 64, scope="deliberate mismatch"
    )
    assert mismatch["verified"] == 0
    assert mismatch["status"] == "rejected"
    assert "did not match" in mismatch["receipt"]["reason"].lower()

    with pytest.raises(ValueError):
        service.record_evidence_file(tmp_path / "missing.txt")


def test_protection_challenge_matches_windows_json_paths_and_resolves(
    service, tmp_path: Path
) -> None:
    target = tmp_path / "protected.txt"
    target.write_text("original", encoding="utf-8")
    receipt = service.record_evidence_file(target, scope="protected work")
    protected = service.protect_artifact(
        str(target.resolve()), receipt_id=receipt["id"], scope="do not silently edit"
    )
    assert protected["active"] == 1

    challenges = service.aletheia.challenges_for_action(
        "write_file", {"path": str(target), "content": "silent replacement"}
    )
    assert len(challenges) == 1
    challenge = challenges[0]
    assert challenge["status"] == "held"
    assert challenge["artifact_ref"] == str(target.resolve())
    assert challenge["protected_id"] == protected["id"]
    assert challenge["evidence"]["id"] == receipt["id"]

    # Reading or listing the protected file is not a destructive action.
    assert (
        service.aletheia.challenges_for_action(
            "read_file", {"path": str(target)}
        )
        == []
    )

    resolved = service.aletheia.resolve_challenges_for_action(
        challenge["action_ref"], executed=True, resolution="user approved the edit"
    )
    assert len(resolved) == 1
    assert resolved[0]["status"] == "executed"
    assert service.aletheia.get_receipt(receipt["id"])["status"] == "stale"
    assert any(
        item["id"] == receipt["id"]
        for item in service.aletheia.list_receipts(status="stale")
    )


def test_duplicate_protection_is_not_created_and_release_is_audited(
    service, tmp_path: Path
) -> None:
    target = tmp_path / "keep.txt"
    target.write_text("keep", encoding="utf-8")
    receipt = service.record_evidence_file(target)
    first = service.protect_artifact(str(target.resolve()), receipt_id=receipt["id"])
    second = service.protect_artifact(str(target.resolve()), receipt_id=receipt["id"])

    assert first["id"] == second["id"]
    assert len(service.aletheia.list_protected()) == 1

    released = service.release_artifact(first["id"], reason="user requested")
    assert released["active"] == 0
    assert released["release_reason"] == "user requested"
    assert (
        service.aletheia.challenges_for_action(
            "write_file", {"path": str(target), "content": "new"}
        )
        == []
    )
    event_types = {event["event_type"] for event in service.store.list_events(limit=50)}
    assert {"work.protected", "work.released"} <= event_types


def test_unverified_accusation_does_not_erase_protection(
    service, tmp_path: Path
) -> None:
    target = tmp_path / "work.txt"
    target.write_text("trusted copy", encoding="utf-8")
    receipt = service.record_evidence_file(target)
    protected = service.protect_artifact(
        str(target.resolve()), receipt_id=receipt["id"]
    )

    accusation = service.aletheia.record_accusation(
        artifact_ref=str(target.resolve()),
        claim="An external page says this file is forged.",
        source_ref="https://untrusted.invalid/claim",
    )

    assert accusation["protected"]["id"] == protected["id"]
    assert accusation["fact"]["status"] == "candidate"
    assert service.aletheia.get_receipt(receipt["id"])["status"] == "current"
    assert any(
        item["id"] == protected["id"] and item["active"] == 1
        for item in service.aletheia.list_protected()
    )
