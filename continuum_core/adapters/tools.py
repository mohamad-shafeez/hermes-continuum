"""Model-facing tools for Hermes Continuum.

Handlers never raise: every path returns a JSON string so the host's tool
contract stays satisfied even when storage or crypto is unavailable.  Secrets
are never accepted in tool arguments; checkpoint export/import reads the
passphrase from ``HERMES_CONTINUUM_PASSPHRASE`` only.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Callable

from ..checkpoint import MIN_PASSPHRASE_LENGTH
from ..common.errors import CheckpointError, ContinuumError, StorageError
from ..common.redaction import truncate

PASSPHRASE_ENV = "HERMES_CONTINUUM_PASSPHRASE"
_MAX_ERROR_CHARS = 400
_MAX_LIST = 50


def _json(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)


def _error(code: str, message: str, **extra: Any) -> str:
    payload = {
        "ok": False,
        "error": code,
        "message": truncate(message, _MAX_ERROR_CHARS),
    }
    payload.update(extra)
    return _json(payload)


def _safe_message(exc: BaseException) -> str:
    if isinstance(exc, (CheckpointError, StorageError, ContinuumError)):
        return str(exc)
    return f"{type(exc).__name__} while reading Continuum state."


def _as_dict(args: Any) -> dict[str, Any]:
    return args if isinstance(args, dict) else {}


def _bounded_int(value: Any, default: int, low: int, high: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = default
    return max(low, min(high, number))


def _clean_text(value: Any, *, limit: int = 2000) -> str:
    return str(value or "").strip()[:limit]


def _fingerprint_summary(fingerprint: Any) -> dict[str, Any] | None:
    if not isinstance(fingerprint, dict) or not fingerprint:
        return None
    files = fingerprint.get("files")
    if not isinstance(files, dict):
        files = {}
    sample = dict(list(files.items())[:_MAX_LIST])
    tools = fingerprint.get("tools")
    if isinstance(tools, list):
        tools = tools[:_MAX_LIST]
    return {
        "format": fingerprint.get("format"),
        "captured_at": fingerprint.get("captured_at"),
        "workspace": fingerprint.get("workspace"),
        "git": fingerprint.get("git"),
        "preconditions": fingerprint.get("preconditions") or {},
        "file_count": len(files),
        "files_tested": sample,
        "files_truncated": len(files) > len(sample),
        "tools": tools or [],
        "unverified": (fingerprint.get("unverified") or [])[:20],
        "note": (
            "File entries are metadata/hash observations, not file contents. "
            "Unobserved remote state remains unverified."
        ),
    }


def _passphrase_from_env() -> str | None:
    value = os.environ.get(PASSPHRASE_ENV, "")
    if not value:
        return None
    if len(value) < MIN_PASSPHRASE_LENGTH:
        return None
    return value


def _passphrase_error() -> str:
    return _error(
        "passphrase_required",
        (
            "Checkpoint encryption requires a passphrase. Set the "
            f"{PASSPHRASE_ENV} environment variable in the Hermes process, or "
            "use `hermes continuum checkpoint ...` (interactive prompt) or the "
            "Continuum Console. Passphrases are never accepted in tool arguments."
        ),
    )


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------
def _status(runtime: Any, args: dict[str, Any]) -> str:
    del args
    service = runtime.service()
    payload = service.status()
    payload["read_only"] = True
    return _json(payload)


def _recall(runtime: Any, args: dict[str, Any]) -> str:
    query = _clean_text(args.get("query"), limit=500)
    if not query:
        return _error("invalid_query", "A non-empty `query` is required.")
    limit = _bounded_int(args.get("limit"), 5, 1, 10)
    service = runtime.service()
    facts = service.recall(query, limit=limit)
    return _json(
        {
            "ok": True,
            "query": query,
            "count": len(facts),
            "facts": facts,
            "note": (
                "Facts marked candidate are unverified proposals and must not "
                "be treated as established."
            ),
        }
    )


def _memory_review(runtime: Any, args: dict[str, Any]) -> str:
    action = _clean_text(args.get("action") or "list", limit=40).lower()
    service = runtime.service()
    if action == "list":
        status = _clean_text(args.get("status"), limit=20).lower() or None
        allowed = {"candidate", "confirmed", "rejected", "superseded", "contradicted"}
        if status is not None and status not in allowed:
            return _error(
                "invalid_status",
                "`status` must be candidate, confirmed, rejected, superseded, "
                "or contradicted.",
            )
        query = _clean_text(args.get("query"), limit=300) or None
        limit = _bounded_int(args.get("limit"), 20, 1, 100)
        facts = service.memory_list(status=status, query=query)[:limit]
        return _json(
            {
                "ok": True,
                "action": "list",
                "counts": service.memory_counts(),
                "facts": facts,
            }
        )

    if action not in {"confirm", "reject", "edit", "forget"}:
        return _error(
            "invalid_action",
            "`action` must be list, confirm, reject, edit, or forget.",
        )

    fact_id = _clean_text(args.get("fact_id"), limit=120)
    if not fact_id:
        return _error("invalid_fact_id", "`fact_id` is required for this action.")

    if action == "confirm":
        return _json({"ok": True, "action": action, "fact": service.confirm_memory(fact_id)})
    if action == "reject":
        return _json({"ok": True, "action": action, "fact": service.reject_memory(fact_id)})
    if action == "edit":
        value = _clean_text(args.get("value"), limit=2000)
        if not value:
            return _error("invalid_value", "`value` is required for the edit action.")
        return _json(
            {
                "ok": True,
                "action": action,
                "fact": service.edit_memory(fact_id, value=value),
            }
        )
    if action == "forget":
        if args.get("confirm") is not True:
            return _error(
                "confirmation_required",
                "Deleting a memory fact requires `confirm: true` and an explicit "
                "user request.",
            )
        return _json(
            {
                "ok": True,
                "action": action,
                "deleted": service.forget_memory(fact_id),
            }
        )
    return _error(
        "invalid_action",
        "`action` must be list, confirm, reject, edit, or forget.",
    )


def _dream(runtime: Any, args: dict[str, Any]) -> str:
    del args
    service = runtime.service()
    return _json({"ok": True, "dream": service.dream()})


def _checkpoint(runtime: Any, args: dict[str, Any]) -> str:
    action = _clean_text(args.get("action") or "list", limit=40).lower()
    service = runtime.service()

    if action == "list":
        return _json(
            {
                "ok": True,
                "action": "list",
                "checkpoint_dir": str(service.checkpoint_service.checkpoint_dir),
                "records": service.list_checkpoints()[:_MAX_LIST],
                "files": service.checkpoint_files(),
                "note": (
                    "Export and import require a passphrase supplied through "
                    f"{PASSPHRASE_ENV}; they are never accepted in tool arguments."
                ),
            }
        )

    if action not in {"export", "inspect", "import"}:
        return _error(
            "invalid_action",
            "`action` must be list, export, inspect, or import.",
        )

    passphrase = _passphrase_from_env()
    if passphrase is None:
        return _passphrase_error()

    if action == "export":
        if args.get("destination"):
            return _error(
                "destination_not_allowed",
                "Tool exports write only to the plugin checkpoint directory. "
                "Use the CLI or Console to choose another destination.",
            )
        result = service.export_checkpoint(passphrase)
        return _json({"ok": True, "action": "export", **result})

    path = _clean_text(args.get("path"), limit=1000)
    if not path:
        return _error("invalid_path", "`path` is required for inspect and import.")
    expected_checksum = _clean_text(args.get("expected_checksum"), limit=200) or None

    if action == "inspect":
        result = service.inspect_checkpoint(
            path, passphrase, expected_checksum=expected_checksum
        )
        return _json({"ok": True, "action": "inspect", **result})

    if args.get("confirm") is not True:
        preview = service.import_checkpoint(
            path,
            passphrase,
            confirm=False,
            expected_checksum=expected_checksum,
        )
        return _json(
            {
                "ok": True,
                "action": "import",
                "status": "preview",
                "preview": preview,
                "message": (
                    "No data was imported. Call again with `confirm: true` after "
                    "reviewing the preview and only on explicit user request."
                ),
            }
        )
    result = service.import_checkpoint(
        path,
        passphrase,
        confirm=True,
        expected_checksum=expected_checksum,
    )
    return _json({"ok": True, "action": "import", **result})


def _reality(runtime: Any, args: dict[str, Any]) -> str:
    action = _clean_text(args.get("action") or "list", limit=40).lower()
    service = runtime.service()
    if action == "list":
        return _json({"ok": True, "action": "list", **service.reality()})
    if action not in {"snapshot", "diff"}:
        return _error("invalid_action", "`action` must be list, snapshot, or diff.")
    if action == "diff":
        snapshot_id = _clean_text(args.get("snapshot_id"), limit=120) or None
        preconditions = args.get("preconditions")
        result = service.reality_diff(
            snapshot_id,
            session_id=_clean_text(args.get("session_id"), limit=120) or None,
            preconditions=preconditions if isinstance(preconditions, dict) else None,
        )
        result["current_fingerprint"] = _fingerprint_summary(
            result.get("current_fingerprint")
        )
        result["changed"] = (result.get("changed") or [])[:100]
        return _json({"ok": True, "action": "diff", **result})
    scope = _clean_text(args.get("scope"), limit=1000) or None
    if scope:
        target = Path(scope).expanduser().resolve()
        if target.parent == target:
            return _error(
                "scope_too_broad",
                "Refusing to fingerprint an entire filesystem root. Supply a concrete workspace directory.",
            )
    paths = [
        str(item)[:1000]
        for item in (args.get("paths") or [])[:100]
        if isinstance(item, (str, Path))
    ]
    preconditions = args.get("preconditions")
    result = service.reality_snapshot(
        scope=scope,
        paths=paths,
        label=_clean_text(args.get("label"), limit=120),
        session_id=_clean_text(args.get("session_id"), limit=120) or None,
        task_id=_clean_text(args.get("task_id"), limit=120) or None,
        preconditions=preconditions if isinstance(preconditions, dict) else None,
    )
    result["fingerprint"] = _fingerprint_summary(result.get("fingerprint"))
    return _json(
        {
            "ok": True,
            "action": "snapshot",
            **result,
            "note": (
                "The fingerprint stores path hashes and small observations only; it "
                "does not store file contents and cannot prove unobserved remote state."
            ),
        }
    )


def _evidence(runtime: Any, args: dict[str, Any]) -> str:
    action = _clean_text(args.get("action") or "list", limit=40).lower()
    service = runtime.service()
    if action == "list":
        artifact_ref = _clean_text(args.get("artifact_ref"), limit=1000) or None
        status = _clean_text(args.get("status"), limit=40).lower() or None
        receipts = service.aletheia.list_receipts(
            artifact_ref=artifact_ref,
            status=status,
            limit=_bounded_int(args.get("limit"), 50, 1, 100),
        )
        return _json(
            {
                "ok": True,
                "action": "list",
                "receipts": receipts,
                "protected": service.aletheia.list_protected(limit=100),
                "challenges": service.aletheia.list_challenges(limit=100),
            }
        )
    if action == "show":
        receipt_id = _clean_text(args.get("receipt_id"), limit=120)
        if not receipt_id:
            return _error("invalid_receipt_id", "`receipt_id` is required.")
        receipt = service.aletheia.get_receipt(receipt_id)
        if receipt is None:
            return _error("not_found", "Evidence receipt not found.")
        return _json({"ok": True, "action": "show", "receipt": receipt})
    if action == "record_file":
        path = _clean_text(args.get("path"), limit=1000)
        if not path:
            return _error("invalid_path", "`path` is required for record_file.")
        receipt = service.record_evidence_file(
            path,
            expected_sha256=_clean_text(args.get("expected_sha256"), limit=200)
            or None,
            scope=_clean_text(args.get("scope"), limit=500),
            memory_ref=_clean_text(args.get("memory_ref"), limit=120) or None,
            session_id=_clean_text(args.get("session_id"), limit=120) or None,
            task_id=_clean_text(args.get("task_id"), limit=120) or None,
        )
        return _json({"ok": True, "action": action, "receipt": receipt})
    if action == "confirm":
        if args.get("confirm") is not True:
            return _error(
                "confirmation_required",
                "Confirming evidence requires `confirm: true` and an explicit user request.",
            )
        receipt_id = _clean_text(args.get("receipt_id"), limit=120)
        if not receipt_id:
            return _error("invalid_receipt_id", "`receipt_id` is required.")
        return _json(
            {
                "ok": True,
                "action": action,
                "receipt": service.confirm_evidence(receipt_id),
            }
        )
    if action in {"protect", "release"}:
        if args.get("confirm") is not True:
            return _error(
                "confirmation_required",
                f"{action} requires `confirm: true` and an explicit user request.",
            )
        if action == "protect":
            artifact_ref = _clean_text(args.get("artifact_ref"), limit=1000)
            if not artifact_ref:
                return _error("invalid_artifact_ref", "`artifact_ref` is required.")
            protected = service.protect_artifact(
                artifact_ref,
                receipt_id=_clean_text(args.get("receipt_id"), limit=120) or None,
                scope=_clean_text(args.get("scope"), limit=500),
            )
            return _json({"ok": True, "action": action, "protected": protected})
        protected_id = _clean_text(args.get("protected_id"), limit=120)
        if not protected_id:
            return _error("invalid_protected_id", "`protected_id` is required.")
        return _json(
            {
                "ok": True,
                "action": action,
                "protected": service.release_artifact(
                    protected_id, reason=_clean_text(args.get("reason"), limit=500)
                ),
            }
        )
    if action == "challenges":
        return _json(
            {
                "ok": True,
                "action": action,
                "challenges": service.aletheia.list_challenges(limit=100),
            }
        )
    return _error(
        "invalid_action",
        "`action` must be list, show, record_file, confirm, protect, release, or challenges.",
    )


def _charter(runtime: Any, args: dict[str, Any]) -> str:
    action = _clean_text(args.get("action") or "show", limit=40).lower()
    service = runtime.service()
    if action == "list":
        return _json({"ok": True, "action": "list", **service.charters()})
    if action == "active":
        charter = service.telos.active_charter(
            session_id=_clean_text(args.get("session_id"), limit=120) or None
        )
        return _json({"ok": True, "action": "active", "charter": charter})
    if action == "show":
        charter_id = _clean_text(args.get("charter_id"), limit=120)
        charter = (
            service.telos.get_charter(charter_id)
            if charter_id
            else service.telos.active_charter(
                session_id=_clean_text(args.get("session_id"), limit=120) or None
            )
        )
        if charter is None:
            return _error("not_found", "Task charter not found.")
        return _json(
            {
                "ok": True,
                "action": "show",
                "charter": charter,
                "context": service.telos.context(charter),
            }
        )
    if action == "amend":
        if args.get("confirm") is not True:
            return _error(
                "confirmation_required",
                "Amending a charter requires `confirm: true` and an explicit user request.",
            )
        charter_id = _clean_text(args.get("charter_id"), limit=120)
        if not charter_id:
            return _error("invalid_charter_id", "`charter_id` is required.")
        amendment = _clean_text(args.get("amendment"), limit=4000)
        if not amendment:
            return _error("invalid_amendment", "`amendment` is required.")
        return _json(
            {
                "ok": True,
                "action": action,
                "charter": service.amend_charter(
                    charter_id,
                    amendment,
                    rationale=_clean_text(args.get("rationale"), limit=1000),
                    confirmed=True,
                ),
            }
        )
    if action == "complete":
        if args.get("confirm") is not True:
            return _error(
                "confirmation_required",
                "Completion scoring requires `confirm: true` and an explicit user request.",
            )
        charter_id = _clean_text(args.get("charter_id"), limit=120)
        if not charter_id:
            return _error("invalid_charter_id", "`charter_id` is required.")
        evidence_ids = [
            str(item)[:120]
            for item in (args.get("evidence_ids") or [])[:50]
            if isinstance(item, str)
        ]
        return _json(
            {
                "ok": True,
                "action": action,
                "assessment": service.assess_completion(
                    charter_id,
                    claimed_complete=bool(args.get("claimed_complete", True)),
                    evidence_ids=evidence_ids,
                    user_confirmed=True,
                ),
            }
        )
    if action == "advance":
        charter_id = _clean_text(args.get("charter_id"), limit=120)
        subgoal_id = _clean_text(args.get("subgoal_id"), limit=40)
        if not charter_id or not subgoal_id:
            return _error(
                "invalid_subgoal",
                "`charter_id` and `subgoal_id` are required for advance.",
            )
        return _json(
            {
                "ok": True,
                "action": action,
                "charter": service.telos.advance_subgoal(
                    charter_id,
                    subgoal_id=subgoal_id,
                    completed=bool(args.get("completed")),
                ),
            }
        )
    return _error(
        "invalid_action",
        "`action` must be list, show, active, amend, complete, or advance.",
    )


def _preview(runtime: Any, args: dict[str, Any]) -> str:
    action = _clean_text(args.get("action") or "preview", limit=40).lower()
    service = runtime.service()
    if action == "list":
        return _json({"ok": True, "action": "list", **service.previews()})
    if action != "preview":
        return _error("invalid_action", "`action` must be preview or list.")
    tool_name = _clean_text(args.get("tool_name"), limit=120)
    if not tool_name:
        return _error("invalid_tool_name", "`tool_name` is required.")
    proposed_args = args.get("args") if isinstance(args.get("args"), dict) else {}
    preview = service.preview_action(
        tool_name,
        proposed_args,
        session_id=_clean_text(args.get("session_id"), limit=120) or None,
        task_id=_clean_text(args.get("task_id"), limit=120) or None,
    )
    return _json(
        {
            "ok": True,
            "action": "preview",
            "preview": preview,
            "note": "Preview only. No proposed action was executed.",
        }
    )


def _execution(runtime: Any, args: dict[str, Any]) -> str:
    action = _clean_text(args.get("action") or "list", limit=40).lower()
    service = runtime.service()
    if action == "list":
        return _json({"ok": True, "action": "list", **service.execution()})
    if action == "status":
        circuit_id = _clean_text(args.get("circuit_id"), limit=120)
        if not circuit_id:
            return _error("invalid_circuit_id", "`circuit_id` is required.")
        circuit = service.metis.get_circuit(circuit_id)
        if circuit is None:
            return _error("not_found", "Metis circuit not found.")
        return _json({"ok": True, "action": "status", "circuit": circuit})
    if action == "reset":
        if args.get("confirm") is not True:
            return _error(
                "confirmation_required",
                "Resetting a circuit requires `confirm: true` and an explicit user request.",
            )
        circuit_id = _clean_text(args.get("circuit_id"), limit=120)
        if not circuit_id:
            return _error("invalid_circuit_id", "`circuit_id` is required.")
        return _json(
            {
                "ok": True,
                "action": "reset",
                "circuit": service.reset_circuit(
                    circuit_id,
                    reason=_clean_text(args.get("reason"), limit=500)
                    or "Reset by user from a model tool",
                ),
            }
        )
    return _error("invalid_action", "`action` must be list, status, or reset.")


def _forge_options(args: dict[str, Any]) -> dict[str, Any]:
    """Extract optional lease and forge fields shared by preview and forge."""

    options: dict[str, Any] = {}
    for key in ("name", "description", "schedule", "expires_at", "cron_job_id"):
        if key in args:
            options[key] = _clean_text(args.get(key), limit=4000 if key == "description" else 500)
    for key in ("allowed_tools", "allowed_paths", "allowed_domains"):
        if isinstance(args.get(key), list):
            options[key] = [
                str(item)[:500]
                for item in args[key][:200]
                if isinstance(item, str)
            ]
    for key in ("max_tool_calls", "max_file_writes", "max_external_calls", "ttl_minutes"):
        if args.get(key) is not None:
            options[key] = _bounded_int(args.get(key), 1, 0, 10000)
    for key in ("allow_opaque_tools", "allow_untrusted", "force", "issue_lease"):
        if key in args:
            options[key] = bool(args.get(key))
    return options


def _forge(runtime: Any, args: dict[str, Any]) -> str:
    action = _clean_text(args.get("action") or "list", limit=40).lower()
    service = runtime.service()
    if action == "list":
        status = _clean_text(args.get("status"), limit=40).lower() or None
        return _json(
            {
                "ok": True,
                "action": "list",
                "playbooks": service.hephaestus.list_playbooks(status=status),
                "counts": service.store.hephaestus_counts(),
                "note": (
                    "A forged skill is a reusable procedure derived from observed "
                    "successes, not proof that the action is safe elsewhere."
                ),
            }
        )
    if action == "show":
        playbook_id = _clean_text(args.get("playbook_id"), limit=120)
        if not playbook_id:
            return _error("invalid_playbook_id", "`playbook_id` is required.")
        playbook = service.hephaestus.playbook(playbook_id)
        if playbook is None:
            return _error("not_found", "Hephaestus playbook not found.")
        return _json({"ok": True, "action": "show", "playbook": playbook})
    session_id = _clean_text(args.get("session_id"), limit=120)
    if action in {"distill", "preview", "forge"} and not session_id:
        return _error(
            "invalid_session_id",
            "An explicit `session_id` is required for trace distillation.",
        )
    if action == "distill":
        return _json(
            {
                "ok": True,
                "action": "distill",
                "trace": service.distill_trace(session_id),
                "note": "Read-only trace analysis. No artifact or lease was created.",
            }
        )
    if action == "preview":
        try:
            preview = service.preview_forge(session_id, **_forge_options(args))
        except ValueError as exc:
            return _error("invalid_request", str(exc))
        return _json({"ok": True, "action": "preview", **preview})
    if action == "forge":
        if args.get("confirm") is not True:
            try:
                preview = service.preview_forge(session_id, **_forge_options(args))
            except ValueError as exc:
                return _error("invalid_request", str(exc))
            return _json(
                {
                    "ok": True,
                    "action": "forge",
                    "status": "confirmation_required",
                    "preview": {
                        "can_forge": preview.get("can_forge"),
                        "warnings": preview.get("warnings"),
                        "playbook": preview.get("playbook"),
                        "lease": preview.get("lease"),
                    },
                    "message": (
                        "No artifact was forged. Call again with `confirm: true` "
                        "after reviewing the trace and only on explicit user request."
                    ),
                }
            )
        try:
            result = service.forge_playbook(
                session_id, confirm=True, **_forge_options(args)
            )
        except ValueError as exc:
            return _error("forge_refused", str(exc))
        return _json({"ok": True, "action": "forge", **result})
    return _error(
        "invalid_action", "`action` must be list, show, distill, preview, or forge."
    )


def _lease(runtime: Any, args: dict[str, Any]) -> str:
    action = _clean_text(args.get("action") or "list", limit=40).lower()
    service = runtime.service()
    if action == "list":
        status = _clean_text(args.get("status"), limit=40).lower() or None
        playbook_id = _clean_text(args.get("playbook_id"), limit=120) or None
        return _json(
            {
                "ok": True,
                "action": "list",
                "leases": service.store.list_safety_leases(
                    playbook_id=playbook_id, status=status, limit=100
                ),
                "usage": service.store.list_lease_usage(limit=100),
                "counts": service.store.hephaestus_counts(),
                "note": (
                    "Safety leases bound unattended Cron runs. They never grant "
                    "approval; Tripwire and the host remain authoritative."
                ),
            }
        )
    if action in {"issue", "revoke", "quarantine", "unquarantine"}:
        if args.get("confirm") is not True:
            return _error(
                "confirmation_required",
                f"`{action}` requires `confirm: true` and an explicit user request.",
            )
    if action == "issue":
        playbook_id = _clean_text(args.get("playbook_id"), limit=120)
        if not playbook_id:
            return _error("invalid_playbook_id", "`playbook_id` is required.")
        options = _forge_options(args)
        options.pop("name", None)
        options.pop("description", None)
        options.pop("schedule", None)
        options.pop("allow_untrusted", None)
        options.pop("force", None)
        options.pop("issue_lease", None)
        try:
            lease = service.issue_lease(playbook_id, confirmed=True, **options)
        except ValueError as exc:
            return _error("invalid_request", str(exc))
        return _json(
            {
                "ok": True,
                "action": "issue",
                "lease": lease,
            }
        )
    if action == "revoke":
        lease_id = _clean_text(args.get("lease_id"), limit=120)
        if not lease_id:
            return _error("invalid_lease_id", "`lease_id` is required.")
        try:
            lease = service.revoke_lease(
                lease_id,
                reason=_clean_text(args.get("reason"), limit=500)
                or "Revoked by user from a model tool",
                confirmed=True,
            )
        except ValueError as exc:
            return _error("invalid_request", str(exc))
        return _json(
            {
                "ok": True,
                "action": "revoke",
                "lease": lease,
            }
        )
    if action in {"quarantine", "unquarantine"}:
        playbook_id = _clean_text(args.get("playbook_id"), limit=120)
        if not playbook_id:
            return _error("invalid_playbook_id", "`playbook_id` is required.")
        try:
            if action == "quarantine":
                playbook = service.quarantine_playbook(
                    playbook_id,
                    reason=_clean_text(args.get("reason"), limit=500)
                    or "Quarantined by user from a model tool",
                    confirmed=True,
                )
            else:
                playbook = service.unquarantine_playbook(
                    playbook_id, confirmed=True
                )
        except ValueError as exc:
            return _error("invalid_request", str(exc))
        return _json(
            {
                "ok": True,
                "action": action,
                "playbook": playbook,
            }
        )
    return _error(
        "invalid_action",
        "`action` must be list, issue, revoke, quarantine, or unquarantine.",
    )


_HANDLERS: dict[str, Callable[[Any, dict[str, Any]], str]] = {
    "continuum_status": _status,
    "continuum_recall": _recall,
    "continuum_memory_review": _memory_review,
    "continuum_dream": _dream,
    "continuum_checkpoint": _checkpoint,
    "continuum_reality": _reality,
    "continuum_evidence": _evidence,
    "continuum_charter": _charter,
    "continuum_preview": _preview,
    "continuum_execution": _execution,
    "continuum_forge": _forge,
    "continuum_lease": _lease,
}


TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "name": "continuum_status",
        "description": (
            "Read Hermes Continuum's local status: event/memory/security counts, "
            "policy and schema versions, last dream and Attack Lab runs, and the "
            "active resume brief. Read-only; no prompts or credentials are returned."
        ),
        "parameters": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
    {
        "name": "continuum_recall",
        "description": (
            "Search Continuum's provenance-aware memory for facts relevant to a "
            "query. Confirmed and candidate facts are labelled; candidates are "
            "unverified. Read-only."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "What to recall, in natural language.",
                    "minLength": 1,
                    "maxLength": 500,
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum facts to return (1-10, default 5).",
                    "minimum": 1,
                    "maximum": 10,
                },
            },
            "required": ["query"],
            "additionalProperties": False,
        },
    },
    {
        "name": "continuum_memory_review",
        "description": (
            "List or review Continuum memory candidates. Actions: list, confirm, "
            "reject, edit, forget. Confirmed facts become eligible for recall. "
            "Use only on explicit user request; forget additionally requires "
            "confirm=true."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["list", "confirm", "reject", "edit", "forget"],
                    "description": "Review action (default list).",
                },
                "status": {
                    "type": "string",
                    "enum": [
                        "candidate",
                        "confirmed",
                        "rejected",
                        "superseded",
                        "contradicted",
                    ],
                    "description": "Status filter for list.",
                },
                "query": {
                    "type": "string",
                    "description": "Optional search filter for list.",
                    "maxLength": 300,
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum facts to list (1-100, default 20).",
                    "minimum": 1,
                    "maximum": 100,
                },
                "fact_id": {
                    "type": "string",
                    "description": "Fact id for confirm, reject, edit, or forget.",
                    "maxLength": 120,
                },
                "value": {
                    "type": "string",
                    "description": "Replacement value for the edit action.",
                    "maxLength": 2000,
                },
                "confirm": {
                    "type": "boolean",
                    "description": "Must be true to delete a fact with forget.",
                },
            },
            "required": ["action"],
            "additionalProperties": False,
        },
    },
    {
        "name": "continuum_dream",
        "description": (
            "Run Oneiros' manual consolidation pass: review recent captured "
            "episodes and propose candidate facts, contradiction links, and a "
            "report. Candidates are never auto-confirmed. This is bounded by the "
            "configured episode limit."
        ),
        "parameters": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
    {
        "name": "continuum_checkpoint",
        "description": (
            "Inspect Continuum checkpoints. Actions: list, export, inspect, import. "
            "Export/import read the passphrase from HERMES_CONTINUUM_PASSPHRASE; "
            "passphrases are never accepted in arguments. Import previews unless "
            "confirm=true. Checkpoints contain plugin-owned records only, never "
            "Hermes sessions, credentials, or live process state."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["list", "export", "inspect", "import"],
                    "description": "Checkpoint action (default list).",
                },
                "path": {
                    "type": "string",
                    "description": "Absolute path to a .hcc file for inspect/import.",
                    "maxLength": 1000,
                },
                "expected_checksum": {
                    "type": "string",
                    "description": "Optional expected SHA-256 checksum.",
                    "maxLength": 200,
                },
                "confirm": {
                    "type": "boolean",
                    "description": "Must be true to apply an import.",
                },
            },
            "required": ["action"],
            "additionalProperties": False,
        },
    },
    {
        "name": "continuum_reality",
        "description": (
            "Kairos reality checks: list, snapshot, or diff the explicitly scoped "
            "workspace environment. Fingerprints include path hashes, git state, "
            "tool presence, and caller-supplied preconditions; file contents are "
            "never stored. A diff reports observed changes and explicitly labels "
            "unobservable conditions as unverified."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["list", "snapshot", "diff"],
                    "description": "Reality action (default list).",
                },
                "scope": {
                    "type": "string",
                    "description": "Directory to fingerprint (default: current workspace).",
                    "maxLength": 1000,
                },
                "paths": {
                    "type": "array",
                    "description": "Additional explicit paths to observe.",
                    "items": {"type": "string", "maxLength": 1000},
                    "maxItems": 100,
                },
                "label": {
                    "type": "string",
                    "description": "Short human label for the snapshot.",
                    "maxLength": 120,
                },
                "snapshot_id": {
                    "type": "string",
                    "description": "Snapshot to diff; defaults to the latest.",
                    "maxLength": 120,
                },
                "session_id": {
                    "type": "string",
                    "description": "Optional session scoping.",
                    "maxLength": 120,
                },
                "task_id": {
                    "type": "string",
                    "description": "Optional task scoping.",
                    "maxLength": 120,
                },
                "preconditions": {
                    "type": "object",
                    "description": (
                        "Small caller-supplied conditions to observe (for example "
                        "{\"approved_budget\": 100}). Non-scalar values are stored "
                        "as hashes; values are redacted and bounded."
                    ),
                    "additionalProperties": True,
                },
            },
            "required": ["action"],
            "additionalProperties": False,
        },
    },
    {
        "name": "continuum_evidence",
        "description": (
            "Aletheia evidence receipts: list, show, record_file, confirm, protect, "
            "release, or list challenges. record_file hashes an explicit local file "
            "without storing its contents. Confirm/protect/release require "
            "confirm=true and an explicit user request; host approval remains "
            "authoritative. A receipt describes an observation, not proof that "
            "unobserved external state is correct."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": [
                        "list",
                        "show",
                        "record_file",
                        "confirm",
                        "protect",
                        "release",
                        "challenges",
                    ],
                    "description": "Evidence action (default list).",
                },
                "artifact_ref": {
                    "type": "string",
                    "description": "File path, URL, or other artifact reference.",
                    "maxLength": 1000,
                },
                "receipt_id": {
                    "type": "string",
                    "description": "Receipt id for show, confirm, or protect.",
                    "maxLength": 120,
                },
                "protected_id": {
                    "type": "string",
                    "description": "Protected-artifact id for release.",
                    "maxLength": 120,
                },
                "path": {
                    "type": "string",
                    "description": "Local file path for record_file.",
                    "maxLength": 1000,
                },
                "expected_sha256": {
                    "type": "string",
                    "description": "Optional expected SHA-256 for record_file.",
                    "maxLength": 200,
                },
                "scope": {
                    "type": "string",
                    "description": "Optional scope description for the receipt.",
                    "maxLength": 500,
                },
                "memory_ref": {
                    "type": "string",
                    "description": "Optional memory fact id supported by the evidence.",
                    "maxLength": 120,
                },
                "status": {
                    "type": "string",
                    "enum": ["current", "stale", "superseded", "failed"],
                    "description": "Receipt status filter for list.",
                },
                "reason": {
                    "type": "string",
                    "description": "Reason for releasing a protected artifact.",
                    "maxLength": 500,
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum receipts to list (1-100, default 50).",
                    "minimum": 1,
                    "maximum": 100,
                },
                "session_id": {
                    "type": "string",
                    "description": "Optional session scoping.",
                    "maxLength": 120,
                },
                "task_id": {
                    "type": "string",
                    "description": "Optional task scoping.",
                    "maxLength": 120,
                },
                "confirm": {
                    "type": "boolean",
                    "description": "Must be true for confirm, protect, and release.",
                },
            },
            "required": ["action"],
            "additionalProperties": False,
        },
    },
    {
        "name": "continuum_charter",
        "description": (
            "Telos task charters: list, show, active, amend, complete, or advance. "
            "A charter is created only from user-authored input. External content "
            "cannot amend it. Amend/complete require confirm=true and an explicit "
            "user request; completion is scored against recorded criteria and "
            "evidence and never claimed merely because many actions occurred."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": [
                        "list",
                        "show",
                        "active",
                        "amend",
                        "complete",
                        "advance",
                    ],
                    "description": "Charter action (default show).",
                },
                "charter_id": {
                    "type": "string",
                    "description": "Charter id for show, amend, complete, or advance.",
                    "maxLength": 120,
                },
                "session_id": {
                    "type": "string",
                    "description": "Optional session scoping for active/show.",
                    "maxLength": 120,
                },
                "amendment": {
                    "type": "string",
                    "description": "User-authorised amendment text.",
                    "maxLength": 4000,
                },
                "rationale": {
                    "type": "string",
                    "description": "Why the charter changed.",
                    "maxLength": 1000,
                },
                "evidence_ids": {
                    "type": "array",
                    "description": "Receipts supporting the completion claim.",
                    "items": {"type": "string", "maxLength": 120},
                    "maxItems": 50,
                },
                "claimed_complete": {
                    "type": "boolean",
                    "description": "Whether the task claims to be complete.",
                },
                "subgoal_id": {
                    "type": "string",
                    "description": "Subgoal id for advance.",
                    "maxLength": 40,
                },
                "completed": {
                    "type": "boolean",
                    "description": "New subgoal completion state for advance.",
                },
                "confirm": {
                    "type": "boolean",
                    "description": "Must be true for amend and complete.",
                },
            },
            "required": ["action"],
            "additionalProperties": False,
        },
    },
    {
        "name": "continuum_preview",
        "description": (
            "Moirai impact previews: preview or list. A preview is side-effect-free "
            "and deterministic; it describes plausible local file, database, shell, "
            "or external effects at VERIFIED, PARTIAL, or UNSUPPORTED confidence. "
            "It never executes the proposed action and never authorizes it. Use the "
            "host's approval mechanism when approval is required."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["preview", "list"],
                    "description": "Preview action (default preview).",
                },
                "tool_name": {
                    "type": "string",
                    "description": "Tool whose impact should be previewed.",
                    "maxLength": 120,
                },
                "args": {
                    "type": "object",
                    "description": "Proposed tool arguments (redacted into the preview).",
                    "additionalProperties": True,
                },
                "session_id": {
                    "type": "string",
                    "description": "Optional session scoping.",
                    "maxLength": 120,
                },
                "task_id": {
                    "type": "string",
                    "description": "Optional task scoping.",
                    "maxLength": 120,
                },
            },
            "required": ["action"],
            "additionalProperties": False,
        },
    },
    {
        "name": "continuum_execution",
        "description": (
            "Metis execution resilience: list failure fingerprints/circuits, show "
            "one circuit, or reset a circuit. Reset requires confirm=true and an "
            "explicit user request; host approval remains authoritative. Circuits "
            "are temporary and do not permanently deny a legitimate action."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["list", "status", "reset"],
                    "description": "Execution action (default list).",
                },
                "circuit_id": {
                    "type": "string",
                    "description": "Circuit id for status or reset.",
                    "maxLength": 120,
                },
                "reason": {
                    "type": "string",
                    "description": "Reason for resetting the circuit.",
                    "maxLength": 500,
                },
                "confirm": {
                    "type": "boolean",
                    "description": "Must be true to reset a circuit.",
                },
            },
            "required": ["action"],
            "additionalProperties": False,
        },
    },
    {
        "name": "continuum_forge",
        "description": (
            "Hephaestus trace distillation: list, show, distill, preview, or forge. "
            "distill/preview are read-only. forge requires confirm=true and an "
            "explicit user request; it writes a SKILL.md, an automation blueprint, "
            "and a bounded safety lease inside the plugin artifact directory. Only "
            "successful tool results become procedure steps; untrusted external "
            "successes are excluded from instructions. A forged artifact is an "
            "observation, not proof of safety in another environment."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["list", "show", "distill", "preview", "forge"],
                    "description": "Forge action (default list).",
                },
                "playbook_id": {
                    "type": "string",
                    "description": "Playbook id for show.",
                    "maxLength": 120,
                },
                "session_id": {
                    "type": "string",
                    "description": "Session whose Event Spine trace is distilled.",
                    "maxLength": 120,
                },
                "status": {
                    "type": "string",
                    "enum": ["forged", "active", "quarantined"],
                    "description": "Status filter for list.",
                },
                "name": {
                    "type": "string",
                    "description": "Playbook name; defaults from the session id.",
                    "maxLength": 200,
                },
                "description": {
                    "type": "string",
                    "description": "Short description shown in SKILL.md.",
                    "maxLength": 4000,
                },
                "schedule": {
                    "type": "string",
                    "description": "Single-line cron schedule template.",
                    "maxLength": 120,
                },
                "allowed_tools": {
                    "type": "array",
                    "description": "Tools the lease may allow; must be verified trace successes.",
                    "items": {"type": "string", "maxLength": 120},
                    "maxItems": 200,
                },
                "allowed_paths": {
                    "type": "array",
                    "description": "Lexical path prefixes allowed by the lease.",
                    "items": {"type": "string", "maxLength": 500},
                    "maxItems": 200,
                },
                "allowed_domains": {
                    "type": "array",
                    "description": "External domains allowed by the lease.",
                    "items": {"type": "string", "maxLength": 200},
                    "maxItems": 200,
                },
                "allow_opaque_tools": {
                    "type": "boolean",
                    "description": "Allow tools whose scope cannot be verified lexically.",
                },
                "max_tool_calls": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 10000,
                    "description": "Per-run tool-call budget.",
                },
                "max_file_writes": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 5000,
                    "description": "Per-run file-write budget.",
                },
                "max_external_calls": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 5000,
                    "description": "Per-run external-call budget.",
                },
                "ttl_minutes": {
                    "type": "integer",
                    "minimum": 5,
                    "maximum": 43200,
                    "description": "Lease lifetime when expires_at is not supplied.",
                },
                "expires_at": {
                    "type": "string",
                    "description": "Explicit ISO-8601 UTC lease expiry.",
                    "maxLength": 60,
                },
                "cron_job_id": {
                    "type": "string",
                    "description": "Optional Cron job id this lease is bound to.",
                    "maxLength": 120,
                },
                "allow_untrusted": {
                    "type": "boolean",
                    "description": "Allow forging when untrusted external successes are present.",
                },
                "force": {
                    "type": "boolean",
                    "description": "Allow forging below the configured confidence minimum.",
                },
                "issue_lease": {
                    "type": "boolean",
                    "description": "Issue a lease with the forged playbook (default true).",
                },
                "confirm": {
                    "type": "boolean",
                    "description": "Must be true to write artifacts.",
                },
            },
            "required": ["action"],
            "additionalProperties": False,
        },
    },
    {
        "name": "continuum_lease",
        "description": (
            "Hephaestus safety leases: list, issue, revoke, quarantine, or "
            "unquarantine. A lease bounds unattended Cron tool calls by tools, "
            "paths, domains, budgets, expiry, and a coarse environment fingerprint. "
            "Issue/revoke/quarantine/unquarantine require confirm=true and an "
            "explicit user request. A lease never grants approval and never "
            "replaces Tripwire or the host."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["list", "issue", "revoke", "quarantine", "unquarantine"],
                    "description": "Lease action (default list).",
                },
                "playbook_id": {
                    "type": "string",
                    "description": "Playbook id for issue, quarantine, or unquarantine.",
                    "maxLength": 120,
                },
                "lease_id": {
                    "type": "string",
                    "description": "Lease id for revoke.",
                    "maxLength": 120,
                },
                "allowed_tools": {
                    "type": "array",
                    "items": {"type": "string", "maxLength": 120},
                    "maxItems": 200,
                    "description": "Tools allowed for this lease.",
                },
                "allowed_paths": {
                    "type": "array",
                    "items": {"type": "string", "maxLength": 500},
                    "maxItems": 200,
                    "description": "Lexical path prefixes allowed for this lease.",
                },
                "allowed_domains": {
                    "type": "array",
                    "items": {"type": "string", "maxLength": 200},
                    "maxItems": 200,
                    "description": "External domains allowed for this lease.",
                },
                "allow_opaque_tools": {
                    "type": "boolean",
                    "description": "Allow opaque tools whose scope cannot be verified.",
                },
                "max_tool_calls": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 10000,
                },
                "max_file_writes": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 5000,
                },
                "max_external_calls": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 5000,
                },
                "ttl_minutes": {
                    "type": "integer",
                    "minimum": 5,
                    "maximum": 43200,
                },
                "expires_at": {
                    "type": "string",
                    "maxLength": 60,
                    "description": "Explicit ISO-8601 UTC lease expiry.",
                },
                "cron_job_id": {
                    "type": "string",
                    "maxLength": 120,
                    "description": "Optional Cron job id this lease is bound to.",
                },
                "reason": {
                    "type": "string",
                    "maxLength": 500,
                    "description": "Reason for revoke or quarantine.",
                },
                "status": {
                    "type": "string",
                    "enum": ["active", "revoked", "expired"],
                    "description": "Status filter for list.",
                },
                "confirm": {
                    "type": "boolean",
                    "description": "Must be true for issue, revoke, quarantine, or unquarantine.",
                },
            },
            "required": ["action"],
            "additionalProperties": False,
        },
    },
]


def build_tool_handlers(runtime: Any) -> dict[str, Callable[..., str]]:
    """Bind the runtime into host-compatible ``handler(args, **kwargs)`` closures."""

    def make(name: str) -> Callable[..., str]:
        handler = _HANDLERS[name]

        def wrapped(args: Any = None, **kwargs: Any) -> str:
            del kwargs
            try:
                return handler(runtime, _as_dict(args))
            except Exception as exc:  # noqa: BLE001 - tools must never raise
                return _error("internal_error", _safe_message(exc))

        return wrapped

    return {name: make(name) for name in _HANDLERS}
