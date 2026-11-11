"""Oneiros extraction, review, dream, recall, and deletion semantics."""

from __future__ import annotations

import pytest

from continuum_core.oneiros.memory import extract_fact_candidate


def test_extract_statement_preference_note_and_correction() -> None:
    statement = extract_fact_candidate("The deployment region is Frankfurt")
    assert statement is not None
    assert statement["fact_key"] == "deployment region"
    assert statement["value"] == "Frankfurt"
    assert statement["reason"] == "statement"

    preference = extract_fact_candidate("I prefer dark mode")
    assert preference is not None
    assert preference["fact_key"] == "user preference: dark mode"
    assert preference["value"] == "dark mode"

    note = extract_fact_candidate("Remember to check the wiki before launch")
    assert note is not None
    assert note["fact_key"].startswith("note:")

    correction = extract_fact_candidate(
        "Actually I prefer light mode instead of dark mode"
    )
    assert correction is not None
    assert correction["fact_key"] == "user preference: dark mode"
    assert correction["value"] == "light mode"
    assert correction["old_value"] == "dark mode"
    assert correction["is_correction"] is True


def test_extraction_is_conservative() -> None:
    assert extract_fact_candidate("What is the weather today?") is None
    assert extract_fact_candidate("I prefer sk-ant-api03-abcdefghijklmnopqrstuvwxyz") is None
    assert extract_fact_candidate("") is None


def test_unrelated_preferences_do_not_supersede(service) -> None:
    first = service.capture_turn(
        user_message="I prefer dark mode", session_id="s", turn_id="1"
    )
    second = service.capture_turn(
        user_message="I prefer tabs over spaces", session_id="s", turn_id="2"
    )
    assert first["candidate"]["fact_key"] == "user preference: dark mode"
    assert second["candidate"]["fact_key"] == "user preference: tabs over spaces"
    assert service.store.get_fact(first["candidate"]["id"])["status"] == "candidate"
    assert service.store.get_fact(second["candidate"]["id"])["status"] == "candidate"


def test_correction_supersedes_only_after_confirmation(service) -> None:
    first = service.capture_turn(
        user_message="I prefer dark mode", session_id="s", turn_id="1"
    )
    service.confirm_memory(first["candidate"]["id"])
    correction = service.capture_turn(
        user_message="Actually I prefer light mode instead of dark mode",
        session_id="s",
        turn_id="2",
    )
    assert correction["candidate"]["fact_key"] == "user preference: dark mode"
    assert correction["candidate"]["value"] == "light mode"
    assert correction["contradicts_fact_id"] == first["candidate"]["id"]
    # The confirmed value remains current until the correction is confirmed.
    assert service.store.find_current_fact("user preference: dark mode")["value"] == "dark mode"
    service.confirm_memory(correction["candidate"]["id"])
    old = service.store.get_fact(first["candidate"]["id"])
    assert old["status"] == "superseded"
    assert old["superseded_by"] == correction["candidate"]["id"]
    assert service.store.find_current_fact("user preference: dark mode")["value"] == "light mode"


def test_negated_preference_is_same_subject_with_contradictory_value(service) -> None:
    negative = service.capture_turn(
        user_message="I never use tabs", session_id="s", turn_id="1"
    )
    positive = service.capture_turn(
        user_message="Actually I use tabs", session_id="s", turn_id="2"
    )
    assert negative["candidate"]["fact_key"] == "user preference: tabs"
    assert negative["candidate"]["value"] == "not tabs"
    assert positive["candidate"]["fact_key"] == "user preference: tabs"
    assert positive["contradicts_fact_id"] == negative["candidate"]["id"]


def test_repeated_capture_dedupes_and_marks_episode_processed(service) -> None:
    first = service.capture_turn(
        user_message="Remember the deployment region is Frankfurt",
        session_id="s",
        turn_id="1",
    )
    second = service.capture_turn(
        user_message="Remember the deployment region is Frankfurt",
        session_id="s",
        turn_id="2",
    )
    assert second.get("deduplicated") is True
    assert second["candidate"]["id"] == first["candidate"]["id"]
    assert service.store.max_fact_version("deployment region") == 1
    episode = service.store.get_episode(second["episode"]["id"])
    assert episode["dream_run_id"] == "capture-dedupe"


def test_edit_creates_new_candidate_version(service) -> None:
    first = service.capture_turn(
        user_message="The deployment region is Frankfurt", session_id="s", turn_id="1"
    )
    edited = service.edit_memory(first["candidate"]["id"], "Berlin")
    assert edited["id"] != first["candidate"]["id"]
    assert edited["version"] == 2
    assert edited["status"] == "candidate"
    assert edited["value"] == "Berlin"
    old = service.store.get_fact(first["candidate"]["id"])
    assert old["status"] == "superseded"
    assert old["superseded_by"] == edited["id"]


def test_reject_keeps_version_history(service) -> None:
    fact = service.capture_turn(
        user_message="The deployment region is Frankfurt", session_id="s", turn_id="1"
    )["candidate"]
    rejected = service.reject_memory(fact["id"])
    assert rejected["status"] == "rejected"
    assert service.store.get_fact(fact["id"])["status"] == "rejected"
    assert service.store.find_current_fact("deployment region") is None


def test_forget_removes_all_versions_and_episodes(service) -> None:
    first = service.capture_turn(
        user_message="The deployment region is Frankfurt", session_id="s", turn_id="1"
    )
    service.confirm_memory(first["candidate"]["id"])
    second = service.capture_turn(
        user_message="Actually the deployment region is Berlin", session_id="s", turn_id="2"
    )
    service.confirm_memory(second["candidate"]["id"])
    result = service.forget_memory(first["candidate"]["id"])
    assert result["deleted"] is True
    assert result["versions_deleted"] >= 2
    assert service.store.get_fact(first["candidate"]["id"]) is None
    assert service.store.get_fact(second["candidate"]["id"]) is None
    assert service.store.find_current_fact("deployment region") is None
    assert service.store.get_episode(first["episode"]["id"]) is None


def test_recall_prefers_confirmed_and_excludes_superseded(service) -> None:
    first = service.capture_turn(
        user_message="I prefer dark mode", session_id="s", turn_id="1"
    )["candidate"]
    service.confirm_memory(first["id"])
    correction = service.capture_turn(
        user_message="Actually I prefer light mode instead of dark mode",
        session_id="s",
        turn_id="2",
    )["candidate"]
    service.confirm_memory(correction["id"])
    facts = service.recall("dark mode")
    assert facts
    assert all(fact["status"] == "confirmed" for fact in facts)
    assert all(not fact.get("superseded_by") for fact in facts)
    assert facts[0]["value"] == "light mode"
    assert all(fact["id"] != first["id"] for fact in facts)


def test_recall_labels_candidates_as_unverified(service) -> None:
    candidate = service.capture_turn(
        user_message="The deployment region is Frankfurt", session_id="s", turn_id="1"
    )["candidate"]
    facts = service.recall("deployment region")
    assert facts and facts[0]["id"] == candidate["id"]
    assert facts[0]["status"] == "candidate"


def test_dream_is_idempotent_with_no_new_episodes(service) -> None:
    first = service.dream()
    assert first["status"] == "no_new_episodes"
    second = service.dream()
    assert second["status"] == "no_new_episodes"
    assert first["candidates_created"] == 0


def test_dream_processes_episodes_and_links_contradiction(service) -> None:
    confirmed = service.capture_turn(
        user_message="The deployment region is Frankfurt", session_id="s", turn_id="1"
    )["candidate"]
    service.confirm_memory(confirmed["id"])
    # Simulate an episode that capture did not process (for example, an imported
    # or backfilled episode).
    service.store.record_episode(
        reason="memory_intent",
        user_excerpt="Actually the deployment region is Berlin",
        session_id="s",
        turn_id="2",
    )
    result = service.dream()
    assert result["status"] == "completed"
    assert result["report"]["candidates_created"] >= 1
    candidates = service.memory_list(status="candidate")
    berlin = [fact for fact in candidates if fact["value"] == "Berlin"]
    assert berlin
    assert berlin[0]["contradicts_fact_id"] == confirmed["id"]
    # A second run has no new work.
    second = service.dream()
    assert second["status"] == "no_new_episodes"


def test_memory_capture_can_be_disabled(tmp_path) -> None:
    from continuum_core.common.config import ContinuumConfig
    from continuum_core.service import ContinuumService

    service = ContinuumService.from_path(
        tmp_path / "disabled.db",
        config=ContinuumConfig(enable_memory_capture=False),
        checkpoint_dir=tmp_path / "checkpoints",
    )
    try:
        assert service.capture_turn(user_message="I prefer dark mode", session_id="s", turn_id="1") is None
        assert service.store.total_events() == 0
    finally:
        service.close()


def test_memory_status_counts_after_review(service) -> None:
    fact = service.capture_turn(
        user_message="The deployment region is Frankfurt", session_id="s", turn_id="1"
    )["candidate"]
    assert service.memory_counts()["candidate"] == 1
    service.confirm_memory(fact["id"])
    counts = service.memory_counts()
    assert counts["candidate"] == 0
    assert counts["confirmed"] == 1
