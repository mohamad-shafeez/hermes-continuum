"""Metis: failure fingerprints and retry-loop circuit breaking.

Metis observes failed tool executions and opens a short-lived circuit when the
same operation fails repeatedly without progress.  The circuit is keyed to the
tool, target, normalised arguments, and error shape.  A changed strategy (new
arguments) is therefore not blocked.  A user can close a circuit from the
Console or CLI.  Circuits expire automatically and never become a permanent
denial of legitimate work.
"""

from __future__ import annotations

import json
import re
from datetime import timedelta
from typing import Any

from ..common.config import ContinuumConfig
from ..common.ids import new_id, stable_hash
from ..common.redaction import redact_mapping, redact_text, truncate
from ..common.time import utc_now, utc_now_iso
from ..spine.store import SpineStore

_FAIL_STATUSES = {
    "error",
    "failed",
    "failure",
    "timeout",
    "timed_out",
    "timedout",
    "exception",
    "cancelled",
    "canceled",
}
_SUCCESS_STATUSES = {"success", "succeeded", "completed", "complete", "ok", "allowed", "executed"}
_HTTP = re.compile(r"(?i)\b(?:http|status|code)?\s*([45]\d\d)\b")
_SENSITIVE = re.compile(r"(?i)(?:password|secret|token|api[_-]?key|authorization|cookie)\s*[=:]\s*\S+")


class MetisService:
    def __init__(
        self,
        store: SpineStore,
        config: ContinuumConfig | None = None,
    ):
        self.store = store
        self.config = (config or ContinuumConfig()).clamped()

    def args_hash(self, args: Any) -> str:
        try:
            safe = redact_mapping(args)
        except (TypeError, ValueError):
            safe = redact_text(args, max_chars=4000)
        return stable_hash(safe)

    def signature(
        self,
        tool_name: str,
        args: Any,
        *,
        error_category: str,
        error_text: str,
    ) -> str:
        return stable_hash(
            {
                "tool": str(tool_name or ""),
                "args": self.args_hash(args),
                "target": _target_ref(args),
                "error_category": error_category,
                "error_signature": _error_signature(error_text),
            }
        )

    def observe_result(
        self,
        tool_name: str,
        args: Any,
        *,
        status: str | None,
        result: Any = None,
        error_type: str | None = None,
        session_id: str | None = None,
        task_id: str | None = None,
        tool_call_id: str | None = None,
        made_progress: bool = False,
    ) -> dict[str, Any]:
        failure, error_text = _is_failure(status, result, error_type)
        if not failure:
            closed = self.close_circuits_for_tool(
                tool_name,
                reason="A later execution of this tool succeeded.",
                session_id=session_id,
                task_id=task_id,
            )
            return {"failure": False, "closed_circuits": len(closed)}
        arg_hash = self.args_hash(args)
        target = _target_ref(args)
        category = _error_category(error_text, status)
        normalized_error = _error_signature(error_text)
        signature = self.signature(
            tool_name,
            args,
            error_category=category,
            error_text=error_text,
        )
        since = (utc_now() - timedelta(minutes=self.config.metis_window_minutes)).isoformat(
            timespec="milliseconds"
        ).replace("+00:00", "Z")
        previous = self.store.count_failures(signature, since=since)
        attempt = previous + 1
        observation_id = new_id("fail")
        event_id = self.store.append_event(
            "execution.failure_observed",
            f"Execution failure #{attempt}: {truncate(str(tool_name), 100)} ({category})",
            session_id=session_id,
            task_id=task_id,
            tool_call_id=tool_call_id,
            details={
                "observation_id": observation_id,
                "tool_name": redact_text(tool_name, max_chars=120),
                "error_category": category,
                "attempt_count": attempt,
                "signature": signature,
                "made_progress": bool(made_progress),
            },
            idempotency_key=(
                f"metis-failure:{tool_call_id}:{signature}" if tool_call_id else None
            ),
        )
        observation = self.store.record_failure_observation(
            observation_id=observation_id,
            tool_name=tool_name,
            signature=signature,
            args_hash=arg_hash,
            error_category=category,
            error_signature=normalized_error,
            attempt_count=attempt,
            target_ref=target,
            made_progress=made_progress,
            session_id=session_id,
            task_id=task_id,
            details={
                "status": redact_text(status, max_chars=80),
                "error_observed": truncate(error_text, 300),
            },
            event_id=event_id,
        )
        result_payload: dict[str, Any] = {
            "failure": True,
            "observation": observation,
            "attempt_count": attempt,
            "signature": signature,
            "circuit": None,
        }
        if made_progress:
            # A failure that made progress is not the same unproductive loop.
            return result_payload
        threshold = self.config.metis_failure_threshold
        if attempt < threshold:
            return result_payload
        alternatives = _alternatives(category)
        expires = (
            utc_now() + timedelta(minutes=self.config.metis_circuit_minutes)
        ).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        reason = (
            f"The same {tool_name} operation failed {attempt} times without recorded "
            f"progress ({category}). Change the strategy or arguments before retrying."
        )
        circuit = self.store.upsert_circuit(
            circuit_id=new_id("circ"),
            signature=signature,
            args_hash=arg_hash,
            tool_name=tool_name,
            target_ref=target,
            failure_count=attempt,
            threshold=threshold,
            reason=reason,
            alternatives=alternatives,
            expires_at=expires,
            status="open",
        )
        self.store.append_event(
            "execution.loop_detected",
            f"Retry loop detected for {truncate(str(tool_name), 100)}",
            session_id=session_id,
            task_id=task_id,
            tool_call_id=tool_call_id,
            details={
                "circuit_id": circuit.get("id"),
                "signature": signature,
                "attempt_count": attempt,
                "threshold": threshold,
            },
            idempotency_key=f"metis-loop:{signature}:{attempt}",
        )
        self.store.append_event(
            "execution.budget_exhausted",
            f"Attempt budget exhausted for {truncate(str(tool_name), 100)}",
            session_id=session_id,
            task_id=task_id,
            tool_call_id=tool_call_id,
            details={
                "circuit_id": circuit.get("id"),
                "attempt_count": attempt,
                "threshold": threshold,
            },
            idempotency_key=f"metis-budget:{signature}:{attempt}",
        )
        self.store.append_event(
            "execution.circuit_opened",
            f"Metis circuit opened for {truncate(str(tool_name), 100)}",
            session_id=session_id,
            task_id=task_id,
            tool_call_id=tool_call_id,
            details={
                "circuit_id": circuit.get("id"),
                "signature": signature,
                "expires_at": expires,
                "reason": reason,
                "alternatives": alternatives,
            },
            idempotency_key=f"metis-circuit-opened:{signature}:{circuit.get('opened_at')}",
        )
        result_payload["circuit"] = circuit
        return result_payload

    def close_circuits_for_tool(
        self,
        tool_name: str,
        *,
        reason: str,
        session_id: str | None = None,
        task_id: str | None = None,
    ) -> list[dict[str, Any]]:
        closed: list[dict[str, Any]] = []
        for circuit in self.store.list_circuits(status="open", limit=200):
            if str(circuit.get("tool_name") or "") != str(tool_name or ""):
                continue
            updated = self.store.close_circuit(
                str(circuit["id"]),
                reason=reason,
                status="closed",
            )
            if updated is None:
                continue
            self.store.append_event(
                "execution.circuit_closed",
                f"Metis circuit closed for {truncate(str(tool_name), 100)}",
                session_id=session_id,
                task_id=task_id,
                details={
                    "circuit_id": updated.get("id"),
                    "tool_name": redact_text(tool_name, max_chars=120),
                    "reason": truncate(reason, 300),
                },
                idempotency_key=f"metis-circuit-closed:{updated.get('id')}",
            )
            self.store.append_event(
                "execution.strategy_changed",
                f"Strategy change observed for {truncate(str(tool_name), 100)}",
                session_id=session_id,
                task_id=task_id,
                details={
                    "circuit_id": updated.get("id"),
                    "tool_name": redact_text(tool_name, max_chars=120),
                },
                idempotency_key=f"metis-strategy:{updated.get('id')}",
            )
            closed.append(updated)
        return closed

    def preflight(
        self, tool_name: str, args: Any
    ) -> dict[str, Any] | None:
        """Return an active circuit for this exact operation, if any."""

        arg_hash = self.args_hash(args)
        circuit = self.store.get_open_circuit_for_args(str(tool_name or ""), arg_hash)
        if circuit is None:
            return None
        return {
            "circuit_id": circuit.get("id"),
            "signature": circuit.get("signature"),
            "tool_name": circuit.get("tool_name"),
            "reason": circuit.get("reason"),
            "alternatives": circuit.get("alternatives") or [],
            "expires_at": circuit.get("expires_at"),
        }

    def reset_circuit(
        self, circuit_id: str, *, reason: str = "Reset by user", actor: str = "user"
    ) -> dict[str, Any]:
        circuit = self.store.get_circuit(circuit_id)
        if circuit is None:
            raise ValueError("Metis circuit not found.")
        updated = self.store.close_circuit(
            circuit_id, reason=reason, status="closed"
        )
        if updated is None:
            raise ValueError("Metis circuit not found.")
        self.store.append_event(
            "execution.circuit_closed",
            f"Metis circuit reset by {redact_text(actor, max_chars=60)}",
            details={
                "circuit_id": circuit_id,
                "tool_name": circuit.get("tool_name"),
                "reason": truncate(reason, 300),
                "actor": redact_text(actor, max_chars=60),
            },
            idempotency_key=f"metis-circuit-reset:{circuit_id}:{utc_now_iso()}",
        )
        return updated

    def circuit_note(self, *, limit: int = 3) -> str:
        circuits = self.store.list_circuits(status="open", limit=limit)
        if not circuits:
            return ""
        parts = [
            f"{item.get('tool_name')} (expires {item.get('expires_at') or 'when reset'})"
            for item in circuits
        ]
        return (
            "Metis: a retry circuit is open for " + ", ".join(parts) + ". "
            "Do not repeat the same failing operation; change the strategy or ask "
            "the user. The Telos charter remains authoritative."
        )

    def list_failures(
        self, *, tool_name: str | None = None, limit: int = 100
    ) -> list[dict[str, Any]]:
        return self.store.list_failure_observations(tool_name=tool_name, limit=limit)

    def list_circuits(
        self, *, status: str | None = None, limit: int = 100
    ) -> list[dict[str, Any]]:
        return self.store.list_circuits(status=status, limit=limit)

    def get_circuit(self, circuit_id: str) -> dict[str, Any] | None:
        return self.store.get_circuit(circuit_id)


def _is_failure(status: str | None, result: Any, error_type: str | None) -> tuple[bool, str]:
    if error_type:
        return True, str(error_type)
    status_key = str(status or "").strip().casefold()
    if status_key in _FAIL_STATUSES:
        if isinstance(result, dict):
            detail = _result_error_text(result)
        elif result not in (None, ""):
            detail = truncate(str(result), 400)
        else:
            detail = ""
        return True, f"{status_key}: {detail}" if detail else status_key
    if status_key in _SUCCESS_STATUSES:
        return False, ""
    if isinstance(result, dict):
        if result.get("ok") is False:
            return True, _result_error_text(result)
        error_value = result.get("error")
        if error_value and not (isinstance(error_value, dict) and error_value.get("ok") is True):
            return True, _result_error_text(result)
    return False, ""


def _result_error_text(result: dict[str, Any]) -> str:
    values: list[str] = []
    for key in ("error_type", "error", "code", "status_code", "status", "message", "detail"):
        value = result.get(key)
        if value in (None, ""):
            continue
        if isinstance(value, (dict, list, tuple)):
            value = json.dumps(value, ensure_ascii=False, default=str)
        values.append(str(value))
        if len(values) >= 3:
            break
    return truncate("; ".join(values) or "unspecified failure", 400)


def _error_category(text: str, status: str | None) -> str:
    lowered = f"{text} {status or ''}".casefold()
    http = _HTTP.search(lowered)
    if http:
        return f"http_{http.group(1)}"
    for token, category in (
        ("rate limit", "rate_limit"),
        ("429", "rate_limit"),
        ("timeout", "timeout"),
        ("timed out", "timeout"),
        ("permission", "permission"),
        ("access denied", "permission"),
        ("unauthorized", "authentication"),
        ("forbidden", "authorization"),
        ("not found", "not_found"),
        ("404", "not_found"),
        ("connection", "network"),
        ("network", "network"),
        ("validation", "validation"),
        ("invalid", "validation"),
        ("conflict", "conflict"),
        ("no such file", "not_found"),
        ("does not exist", "not_found"),
    ):
        if token in lowered:
            return category
    return "execution_error"


def _error_signature(text: str) -> str:
    safe = _SENSITIVE.sub("[REDACTED]", redact_text(text, max_chars=1000)).casefold()
    safe = re.sub(r"\b[0-9a-f]{8}-[0-9a-f-]{27,}\b", "<id>", safe)
    safe = re.sub(r"\b[0-9a-f]{16,}\b", "<id>", safe)
    safe = re.sub(r"\b\d{4,}\b", "<n>", safe)
    safe = re.sub(r"\s+", " ", safe).strip()
    return truncate(safe or "unspecified failure", 300)


def _target_ref(args: Any) -> str | None:
    if not isinstance(args, dict):
        text = _SENSITIVE.sub("[REDACTED]", redact_text(args, max_chars=500))
        return text or None
    for key in (
        "path",
        "file_path",
        "filename",
        "file",
        "destination",
        "url",
        "endpoint",
        "recipient",
        "channel",
        "table",
        "query",
        "command",
    ):
        value = args.get(key)
        if isinstance(value, str) and value.strip():
            return redact_text(value.strip(), max_chars=500)
    return None


def _alternatives(category: str) -> list[str]:
    common = [
        "Inspect the exact error and change one variable before retrying.",
        "Use a different tool or a narrower request.",
        "Ask the user for the missing condition or authorization.",
    ]
    specific = {
        "http_401": ["Refresh the integration's authentication outside the model loop."],
        "http_403": ["Request the required permission or use a permitted target."],
        "http_404": ["Verify the identifier or create the missing resource first."],
        "http_409": ["Resolve the conflicting state before retrying."],
        "http_429": ["Wait for the service's rate-limit window; do not retry immediately."],
        "permission": ["Request permission from the host/user; do not retry unchanged."],
        "authentication": ["Re-authenticate through the host; do not retry unchanged."],
        "network": ["Check connectivity, then use a different endpoint or strategy."],
        "timeout": ["Reduce the request scope or use an asynchronous alternative."],
        "not_found": ["Correct the target reference or create the resource first."],
        "validation": ["Change the input to satisfy the validated schema."],
        "conflict": ["Resolve the state conflict before retrying."],
    }
    return specific.get(category, []) + common
