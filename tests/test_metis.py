"""Metis failure fingerprints, retry circuits, budgets, and reset behavior."""

from __future__ import annotations

import json
from datetime import timedelta

from continuum_core.common.time import utc_now, utc_now_iso
from continuum_core.constants import PLUGIN_VERSION


def _fail(service, path: str, *, status: str = "failed", error: str = "permission denied", call: str = "c1"):
    return service.metis.observe_result(
        "write_file",
        {"path": path, "content": "same attempt"},
        status=status,
        result={"error": error},
        tool_call_id=call,
    )


def test_args_hash_is_stable_redacted_and_sensitive(service) -> None:
    left = service.metis.args_hash(
        {"path": "a.txt", "api_key": "sk-ant-secret-value", "nested": {"b": 1, "a": 2}}
    )
    right = service.metis.args_hash(
        {"nested": {"a": 2, "b": 1}, "api_key": "sk-ant-secret-value", "path": "a.txt"}
    )
    different = service.metis.args_hash({"path": "b.txt"})
    assert left == right
    assert left != different
    assert "sk-ant-secret-value" not in left


def test_three_identical_failures_open_a_circuit_and_new_args_are_allowed(
    service,
) -> None:
    target = "reports/quarterly.txt"
    first = _fail(service, target, call="c1")
    second = _fail(service, target, call="c2")
    third = _fail(service, target, call="c3")

    assert first["attempt_count"] == 1
    assert second["attempt_count"] == 2
    assert third["attempt_count"] == 3
    assert third["circuit"] is not None
    circuit = third["circuit"]
    assert circuit["status"] == "open"
    assert circuit["failure_count"] == 3
    assert circuit["threshold"] == service.config.metis_failure_threshold
    assert circuit["alternatives"]

    blocked = service.metis.preflight(
        "write_file", {"path": target, "content": "same attempt"}
    )
    assert blocked is not None
    assert blocked["circuit_id"] == circuit["id"]
    assert service.metis.preflight(
        "write_file", {"path": "reports/other.txt", "content": "same attempt"}
    ) is None
    assert service.metis.preflight("read_file", {"path": target}) is None
    assert service.metis.circuit_note()

    event_types = [event["event_type"] for event in service.store.list_events(limit=60)]
    assert "execution.failure_observed" in event_types
    assert "execution.loop_detected" in event_types
    assert "execution.budget_exhausted" in event_types
    assert "execution.circuit_opened" in event_types


def test_successful_retry_closes_circuits_and_reset_is_audited(service) -> None:
    target = "reports/retry.txt"
    for index in range(3):
        result = _fail(service, target, call=f"retry-{index}")
    circuit = result["circuit"]
    assert circuit is not None

    closed = service.metis.observe_result(
        "write_file",
        {"path": target, "content": "same attempt"},
        status="success",
        result={"ok": True},
    )
    assert closed["failure"] is False
    assert closed["closed_circuits"] == 1
    assert service.metis.preflight(
        "write_file", {"path": target, "content": "same attempt"}
    ) is None
    assert service.store.get_circuit(circuit["id"])["status"] == "closed"

    for index in range(3):
        result = _fail(service, "reports/reset.txt", call=f"reset-{index}")
    reset_target = result["circuit"]
    assert reset_target is not None
    reset = service.reset_circuit(reset_target["id"], reason="user changed strategy")
    assert reset["status"] == "closed"
    assert service.metis.preflight(
        "write_file", {"path": "reports/reset.txt", "content": "same attempt"}
    ) is None
    assert any(
        event["event_type"] == "execution.circuit_closed"
        and "reset" in event["summary"].lower()
        for event in service.store.list_events(limit=80)
    )


def test_made_progress_does_not_open_a_circuit(service) -> None:
    target = "reports/progress.txt"
    for index in range(3):
        result = service.metis.observe_result(
            "write_file",
            {"path": target, "content": "same attempt"},
            status="failed",
            result={"error": "permission denied"},
            tool_call_id=f"progress-{index}",
            made_progress=True,
        )
        assert result["failure"] is True
        assert result["circuit"] is None
    assert service.store.list_circuits(status="open") == []


def test_failure_categories_and_secret_redaction(service) -> None:
    rate = service.metis.observe_result(
        "http_request",
        {"url": "https://example.invalid/endpoint"},
        status="failed",
        result={"status_code": 429, "error": "rate limit exceeded"},
        tool_call_id="http-1",
    )
    assert rate["observation"]["error_category"] == "http_429"

    denied = service.metis.observe_result(
        "write_file",
        {"path": "protected.txt", "content": "x"},
        status="failed",
        result={"error": "permission denied: password=super-secret-value"},
        tool_call_id="secret-1",
    )
    serialized = json.dumps(denied["observation"], sort_keys=True)
    assert "super-secret-value" not in serialized
    assert "[REDACTED]" in serialized or "[redacted]" in serialized

    success = service.metis.observe_result(
        "read_file", {"path": "x"}, status="success", result={"ok": True}
    )
    assert success["failure"] is False


def test_expired_circuit_is_not_returned_by_preflight(service) -> None:
    args = {"path": "expired.txt", "content": "same attempt"}
    arg_hash = service.metis.args_hash(args)
    expired = service.store.upsert_circuit(
        circuit_id="circ_expired",
        signature="sig_expired",
        args_hash=arg_hash,
        tool_name="write_file",
        failure_count=3,
        threshold=3,
        reason="old circuit",
        alternatives=["change strategy"],
        expires_at=(utc_now() - timedelta(minutes=1))
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z"),
    )
    assert expired["status"] == "open"
    assert service.metis.preflight("write_file", args) is None
    # An explicit reset remains possible for an expired but still-open record.
    assert service.metis.get_circuit("circ_expired")["expires_at"] < utc_now_iso()
