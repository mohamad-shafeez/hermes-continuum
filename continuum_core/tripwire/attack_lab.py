"""Deterministic Attack Lab.

The case corpus lives in ``fixtures/attack_lab_cases.json``.  That file
deliberately contains hostile synthetic strings as *data* so the lab can prove
the policy rejects or gates them; nothing in the corpus is executed and no
model is called.  The fixture lives under a top-level ``fixtures/`` tree so
install-time scanners classify its strings as inert test data rather than
runtime shell instructions.

The lab exercises the same :func:`continuum_core.tripwire.policy.evaluate`
function used by the live ``pre_tool_call`` hook.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..constants import POLICY_VERSION
from .policy import evaluate

_FIXTURE_PATH = (
    Path(__file__).resolve().parents[2] / "fixtures" / "attack_lab_cases.json"
)
_CACHED_CASES: list[dict[str, Any]] | None = None


def _load_cases() -> list[dict[str, Any]]:
    """Load and validate the fixed corpus exactly once per process."""

    global _CACHED_CASES
    if _CACHED_CASES is not None:
        return _CACHED_CASES
    try:
        payload = json.loads(_FIXTURE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeError(
            f"Attack Lab fixture is unavailable ({type(exc).__name__})."
        ) from exc
    if not isinstance(payload, list) or not payload:
        raise RuntimeError("Attack Lab fixture must be a non-empty JSON array.")
    cases: list[dict[str, Any]] = []
    for item in payload:
        if not isinstance(item, dict):
            raise RuntimeError("Every Attack Lab case must be a JSON object.")
        case_id = item.get("id")
        tool_name = item.get("tool_name")
        args = item.get("args")
        expected = item.get("expected")
        if not isinstance(case_id, str) or not case_id:
            raise RuntimeError("Every Attack Lab case needs a string id.")
        if not isinstance(tool_name, str) or not tool_name:
            raise RuntimeError(f"Attack Lab case {case_id} needs a tool_name.")
        if not isinstance(args, dict):
            raise RuntimeError(f"Attack Lab case {case_id} needs an args object.")
        if expected not in {"allow", "approve", "block"}:
            raise RuntimeError(f"Attack Lab case {case_id} has an invalid expectation.")
        context_trust = item.get("context_trust")
        if context_trust is not None and not isinstance(context_trust, str):
            raise RuntimeError(f"Attack Lab case {case_id} has an invalid context_trust.")
        cases.append(
            {
                "id": case_id,
                "name": str(item.get("name") or case_id),
                "setup": str(item.get("setup") or ""),
                "source_label": str(item.get("source_label") or "UNKNOWN"),
                "tool_name": tool_name,
                "args": args,
                "expected": expected,
                "context_trust": context_trust,
            }
        )
    _CACHED_CASES = cases
    return cases


def run_attack_lab() -> list[dict[str, Any]]:
    """Run the fixed deterministic suite and return per-case results."""

    results: list[dict[str, Any]] = []
    for case in _load_cases():
        decision = evaluate(
            case["tool_name"],
            case["args"],
            context_trust=case.get("context_trust"),
            source_ref=f"lab:{case['id']}",
        )
        actual = decision.outcome
        results.append(
            {
                "id": case["id"],
                "name": case["name"],
                "setup": case["setup"],
                "source_label": case["source_label"],
                "proposed_action": {
                    "tool_name": case["tool_name"],
                    "args": case["args"],
                },
                "expected": case["expected"],
                "actual": actual,
                "passed": actual == case["expected"],
                "rule_key": decision.rule_key,
                "category": decision.category,
                "reason": decision.reason,
                "evidence": decision.evidence,
                "policy_version": POLICY_VERSION,
            }
        )
    return results
