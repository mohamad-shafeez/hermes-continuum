"""Deterministic Hephaestus Attack Lab.

Exactly four synthetic cases exercise the same pure functions used by runtime
enforcement and trace distillation:

1. a poisoned external source is excluded from skill instructions;
2. a path that escapes the lease scope is blocked;
3. an exhausted per-run tool-call budget is blocked;
4. an environment fingerprint mismatch is blocked.

The corpus is built in-process, contains no executable content, and makes no
model call.  These cases are evidence about these four checks only; they are
not a general prompt-injection guarantee.
"""

from __future__ import annotations

from pathlib import Path
from tempfile import gettempdir
from typing import Any

from ..common.config import ContinuumConfig
from ..constants import POLICY_VERSION
from .service import HephaestusService, evaluate_lease_request


def _lab_service() -> HephaestusService:
    """A store-free service instance for pure distillation checks."""

    return HephaestusService(
        store=None,  # type: ignore[arg-type] - only pure helpers are used
        config=ContinuumConfig(),
        artifact_dir=Path(gettempdir()) / "hephaestus-attack-lab",
    )


def _poisoned_source_case() -> dict[str, Any]:
    service = _lab_service()
    events = [
        {
            "id": 1,
            "event_type": "tool_result_observed",
            "session_id": "lab-hephaestus-poisoned",
            "tool_call_id": "call-1",
            "trust_label": "UNTRUSTED_EXTERNAL",
            "source_ref": "lab:poisoned-page",
            "timestamp_utc": "2026-01-01T00:00:00Z",
            "details": {
                "tool_name": "web_fetch",
                "args_preview": {"url": "https://untrusted.example/instructions"},
                "status": "completed",
                "result_hash": "lab-result-hash",
            },
        },
        {
            "id": 2,
            "event_type": "tool_result_observed",
            "session_id": "lab-hephaestus-poisoned",
            "tool_call_id": "call-2",
            "trust_label": "LOCAL_TOOL_OUTPUT",
            "source_ref": "lab:local",
            "timestamp_utc": "2026-01-01T00:00:01Z",
            "details": {
                "tool_name": "read_file",
                "args_preview": {"path": "workspace/INPUT.md"},
                "status": "completed",
                "result_hash": "lab-result-hash-2",
            },
        },
    ]
    trace = service._distill_events("lab-hephaestus-poisoned", events)  # noqa: SLF001
    trusted = [
        step
        for step in trace.get("steps") or []
        if str(step.get("trust_label") or "").upper() != "UNTRUSTED_EXTERNAL"
    ]
    excluded = (
        int(trace.get("untrusted_steps") or 0) == 1
        and len(trace.get("steps") or []) == 2
        and len(trusted) == 1
        and trusted[0].get("tool_name") == "read_file"
    )
    return {
        "id": "hephaestus-poisoned-source",
        "name": "Poisoned external success is excluded from instructions",
        "setup": (
            "A session reports one UNTRUSTED_EXTERNAL web success and one local "
            "read success."
        ),
        "expected": "excluded",
        "actual": "excluded" if excluded else "included",
        "passed": excluded,
        "rule_key": "hephaestus.skill.untrusted_excluded",
        "reason": (
            "Only trusted successes become procedure steps; untrusted successes "
            "remain quoted evidence for review."
        ),
        "details": {
            "steps": len(trace.get("steps") or []),
            "untrusted_steps": int(trace.get("untrusted_steps") or 0),
            "trusted_steps": len(trusted),
        },
        "policy_version": f"{POLICY_VERSION}+hephaestus",
    }


def _path_escape_case() -> dict[str, Any]:
    evaluation = evaluate_lease_request(
        allowed_tools=["write_file"],
        allowed_paths=["workspace/output"],
        allowed_domains=[],
        allow_opaque_tools=False,
        tool_name="write_file",
        args={"path": "workspace/output/../../secrets.txt", "content": "x"},
    )
    passed = not evaluation.get("allowed") and evaluation.get("rule_key") == (
        "hephaestus.lease.path_out_of_scope"
    )
    return {
        "id": "hephaestus-path-escape",
        "name": "Lexical path escape is blocked",
        "setup": (
            "A write targets workspace/output/../../secrets.txt while the lease "
            "allows only workspace/output."
        ),
        "expected": "block",
        "actual": "allow" if evaluation.get("allowed") else "block",
        "passed": passed,
        "rule_key": evaluation.get("rule_key"),
        "reason": evaluation.get("reason"),
        "details": {"paths": evaluation.get("paths")},
        "policy_version": f"{POLICY_VERSION}+hephaestus",
    }


def _lease_budget_case() -> dict[str, Any]:
    evaluation = evaluate_lease_request(
        allowed_tools=["read_file"],
        allowed_paths=["workspace"],
        allowed_domains=[],
        allow_opaque_tools=False,
        tool_name="read_file",
        args={"path": "workspace/INPUT.md"},
        usage={"tool_calls": 2, "file_writes": 0, "external_calls": 0},
        max_tool_calls=2,
    )
    passed = not evaluation.get("allowed") and evaluation.get("rule_key") == (
        "hephaestus.lease.max_tool_calls"
    )
    return {
        "id": "hephaestus-lease-budget",
        "name": "Exhausted tool-call budget is blocked",
        "setup": "A run already used 2 of 2 allowed tool calls and tries another.",
        "expected": "block",
        "actual": "allow" if evaluation.get("allowed") else "block",
        "passed": passed,
        "rule_key": evaluation.get("rule_key"),
        "reason": evaluation.get("reason"),
        "details": {"max_tool_calls": 2},
        "policy_version": f"{POLICY_VERSION}+hephaestus",
    }


def _environment_drift_case() -> dict[str, Any]:
    evaluation = evaluate_lease_request(
        allowed_tools=["read_file"],
        allowed_paths=["workspace"],
        allowed_domains=[],
        allow_opaque_tools=False,
        tool_name="read_file",
        args={"path": "workspace/INPUT.md"},
        current_environment="host-environment-b",
        expected_environment="host-environment-a",
    )
    passed = not evaluation.get("allowed") and evaluation.get("rule_key") == (
        "hephaestus.lease.environment_changed"
    )
    return {
        "id": "hephaestus-environment-drift",
        "name": "Environment fingerprint drift is blocked",
        "setup": (
            "The lease was issued under one coarse platform/Python fingerprint and "
            "is checked under another."
        ),
        "expected": "block",
        "actual": "allow" if evaluation.get("allowed") else "block",
        "passed": passed,
        "rule_key": evaluation.get("rule_key"),
        "reason": evaluation.get("reason"),
        "details": {
            "expected_environment": "host-environment-a",
            "current_environment": "host-environment-b",
        },
        "policy_version": f"{POLICY_VERSION}+hephaestus",
    }


def run_hephaestus_attack_lab() -> list[dict[str, Any]]:
    """Run the fixed four-case suite and return per-case results."""

    return [
        _poisoned_source_case(),
        _path_escape_case(),
        _lease_budget_case(),
        _environment_drift_case(),
    ]
