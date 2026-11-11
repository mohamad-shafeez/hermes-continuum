"""Continuum Console backend routes.

Loaded by the Hermes dashboard loader with ``spec_from_file_location`` and
mounted at ``/api/plugins/hermes-continuum/``.  This file is intentionally
self-contained at import time: it adds the plugin root to ``sys.path`` only to
reach ``continuum_core`` (the same code the plugin process uses), and it reads
the profile-scoped plugin storage at request time so ``?profile=`` works.

Secrets: checkpoint passphrases arrive in POST bodies, are used once, and are
never logged, cached, or returned.  Every response is JSON.
"""

from __future__ import annotations

import contextlib
import importlib
import sqlite3
import sys
from pathlib import Path
from typing import Any, Iterator

from fastapi import APIRouter, Body, HTTPException, Query

router = APIRouter()

PLUGIN_ID = "hermes-continuum"
PLUGIN_ROOT = Path(__file__).resolve().parent.parent
_CORE: Any = None


# ---------------------------------------------------------------------------
# Imports and storage
# ---------------------------------------------------------------------------
def _import_core() -> Any:
    """Import ``continuum_core`` from the host package or the plugin root."""

    global _CORE
    if _CORE is not None:
        return _CORE
    try:
        import continuum_core  # type: ignore

        _CORE = continuum_core
        return _CORE
    except ImportError:
        pass

    # A gateway may already have loaded the plugin under its namespaced module.
    for name, module in list(sys.modules.items()):
        if name == "continuum_core" or name.endswith(".continuum_core"):
            _CORE = module
            return _CORE

    root = str(PLUGIN_ROOT)
    if root not in sys.path:
        sys.path.append(root)
    import continuum_core  # type: ignore

    _CORE = continuum_core
    return _CORE


def _core_module(name: str) -> Any:
    """Import a submodule relative to the resolved core package."""

    core = _import_core()
    return importlib.import_module(f"{core.__name__}.{name}")


def _hermes_home() -> Path:
    try:
        from hermes_constants import get_hermes_home

        return Path(get_hermes_home())
    except Exception:
        import os

        home = os.environ.get("HERMES_HOME")
        if home:
            return Path(home)
        return Path.home() / ".hermes"


def _load_config() -> Any:
    ContinuumConfig = _core_module("common.config").ContinuumConfig
    try:
        from hermes_cli.config import load_config_readonly

        config = load_config_readonly() or {}
        entries = config.get("plugins", {}).get("entries", {})
        entry = entries.get(PLUGIN_ID) if isinstance(entries, dict) else None
        settings = None
        if isinstance(entry, dict):
            settings = entry.get("settings") or entry.get("config")
        if isinstance(settings, dict):
            return ContinuumConfig(
                **{
                    key: value
                    for key, value in settings.items()
                    if key in ContinuumConfig.__dataclass_fields__
                }
            ).clamped()
    except Exception:
        pass
    return ContinuumConfig()


def _open_storage() -> tuple[Any, Path]:
    """Return ``(connection, data_dir)``; prefer the host's plugin storage."""

    try:
        from plugins.plugin_storage import plugin_data_dir, plugin_db

        return plugin_db(PLUGIN_ID), plugin_data_dir(PLUGIN_ID)
    except Exception:
        data_dir = _hermes_home() / "plugin-data" / PLUGIN_ID
        data_dir.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(
            str(data_dir / "data.db"), check_same_thread=False, timeout=10.0
        )
        return connection, data_dir


@contextlib.contextmanager
def _service() -> Iterator[Any]:
    config = _load_config()
    connection, data_dir = _open_storage()
    configured_dir = str(getattr(config, "checkpoint_dir", "") or "").strip()
    if configured_dir:
        checkpoint_dir = Path(configured_dir).expanduser()
        if not checkpoint_dir.is_absolute():
            checkpoint_dir = data_dir / checkpoint_dir
    else:
        checkpoint_dir = data_dir / "checkpoints"
    service = _core_module("service").ContinuumService(
        _core_module("spine.store").SpineStore(connection, owns_connection=True),
        config=config,
        checkpoint_dir=checkpoint_dir,
        hephaestus_artifact_dir=data_dir / "hephaestus",
    )
    try:
        yield service
    finally:
        try:
            service.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Error helpers
# ---------------------------------------------------------------------------
def _fail(status_code: int, code: str, message: str) -> HTTPException:
    return HTTPException(
        status_code=status_code,
        detail={"ok": False, "error": code, "message": message[:500]},
    )


@contextlib.contextmanager
def _mapped_errors() -> Iterator[None]:
    errors = _core_module("common.errors")
    CheckpointError = errors.CheckpointError
    StorageError = errors.StorageError
    try:
        yield
    except HTTPException:
        raise
    except CheckpointError as exc:
        raise _fail(400, "checkpoint_error", str(exc)) from exc
    except StorageError as exc:
        raise _fail(400, "storage_error", str(exc)) from exc
    except ValueError as exc:
        raise _fail(400, "invalid_request", str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise _fail(500, "internal_error", f"{type(exc).__name__} while handling the request.") from exc


def _body(value: dict[str, Any] | None) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise _fail(400, "invalid_body", "The request body must be a JSON object.")
    return value


def _require_text(body: dict[str, Any], key: str, *, limit: int = 1000) -> str:
    value = body.get(key)
    if not isinstance(value, str) or not value.strip():
        raise _fail(400, "invalid_request", f"`{key}` is required.")
    return value.strip()[:limit]


def _optional_checksum(body: dict[str, Any]) -> str | None:
    value = body.get("expected_checksum")
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise _fail(400, "invalid_request", "`expected_checksum` must be a string.")
    return value.strip()[:200]


# ---------------------------------------------------------------------------
# Read routes
# ---------------------------------------------------------------------------
@router.get("/health")
async def health() -> dict[str, Any]:
    with _mapped_errors(), _service() as service:
        status = service.status()
    return {
        "ok": True,
        "plugin": PLUGIN_ID,
        "version": status["version"],
        "schema_version": status["schema_version"],
    }


@router.get("/status")
async def status() -> dict[str, Any]:
    with _mapped_errors(), _service() as service:
        payload = service.status()
    payload["read_only"] = True
    return payload


@router.get("/overview")
async def overview() -> dict[str, Any]:
    with _mapped_errors(), _service() as service:
        payload = service.overview()
        payload["checkpoint_files"] = service.checkpoint_files()
        payload["config"] = service.config_dict()
    return payload


@router.get("/timeline")
async def timeline(
    limit: int = Query(default=100, ge=1, le=500),
    event_type: str | None = Query(default=None, alias="type"),
    module: str | None = Query(default=None),
    session_id: str | None = Query(default=None),
    search: str | None = Query(default=None),
    before_id: int | None = Query(default=None, ge=1),
) -> dict[str, Any]:
    with _mapped_errors(), _service() as service:
        events = service.timeline(
            limit=limit,
            event_type=event_type,
            module=module,
            session_id=session_id,
            search=search,
            before_id=before_id,
        )
    return {"ok": True, "events": events, "count": len(events)}


@router.get("/events/{event_id}")
async def event_detail(event_id: str) -> dict[str, Any]:
    with _mapped_errors(), _service() as service:
        event = service.get_event(event_id)
    if event is None:
        raise _fail(404, "not_found", "Event not found.")
    return {"ok": True, "event": event}


@router.get("/memory")
async def memory(
    status: str | None = Query(default=None),
    query: str | None = Query(default=None),
    limit: int = Query(default=200, ge=1, le=1000),
) -> dict[str, Any]:
    allowed = {"candidate", "confirmed", "rejected", "superseded", "contradicted"}
    if status is not None and status not in allowed:
        raise _fail(400, "invalid_status", "Unknown memory status.")
    with _mapped_errors(), _service() as service:
        facts = service.memory_list(status=status, query=query)[:limit]
        counts = service.memory_counts()
    return {"ok": True, "facts": facts, "counts": counts, "count": len(facts)}


@router.get("/security")
async def security() -> dict[str, Any]:
    with _mapped_errors(), _service() as service:
        payload = service.security()
        payload["attack_lab_results"] = service.last_attack_lab()
    return payload


@router.get("/checkpoints")
async def checkpoints() -> dict[str, Any]:
    with _mapped_errors(), _service() as service:
        payload = {
            "ok": True,
            "checkpoint_dir": str(service.checkpoint_service.checkpoint_dir),
            "records": service.list_checkpoints(),
            "files": service.checkpoint_files(),
        }
    return payload


@router.get("/pillars")
async def pillars() -> dict[str, Any]:
    with _mapped_errors(), _service() as service:
        payload = service.pillars()
    return payload


@router.get("/reality")
async def reality() -> dict[str, Any]:
    with _mapped_errors(), _service() as service:
        payload = service.reality()
    return payload


@router.get("/evidence")
async def evidence(
    artifact_ref: str | None = Query(default=None, alias="artifact"),
    status: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    with _mapped_errors(), _service() as service:
        receipts = service.aletheia.list_receipts(
            artifact_ref=artifact_ref, status=status, limit=limit
        )
        protected = service.aletheia.list_protected(limit=limit)
        challenges = service.aletheia.list_challenges(limit=limit)
    return {
        "ok": True,
        "receipts": receipts,
        "protected": protected,
        "challenges": challenges,
        "count": len(receipts),
    }


@router.get("/charters")
async def charters() -> dict[str, Any]:
    with _mapped_errors(), _service() as service:
        payload = service.charters()
        payload["active"] = service.telos.active_charter()
    return payload


@router.get("/previews")
async def previews(
    limit: int = Query(default=100, ge=1, le=500)
) -> dict[str, Any]:
    with _mapped_errors(), _service() as service:
        items = service.store.list_impact_previews(limit=limit)
    return {"ok": True, "previews": items, "count": len(items)}


@router.get("/execution")
async def execution(
    limit: int = Query(default=100, ge=1, le=500)
) -> dict[str, Any]:
    with _mapped_errors(), _service() as service:
        failures = service.store.list_failure_observations(limit=limit)
        circuits = service.store.list_circuits(limit=limit)
    return {
        "ok": True,
        "failures": failures,
        "circuits": circuits,
        "count": len(failures),
    }


@router.get("/forge")
async def forge_read_model() -> dict[str, Any]:
    with _mapped_errors(), _service() as service:
        payload = service.forge_read_model()
    return payload


# ---------------------------------------------------------------------------
# Memory actions
# ---------------------------------------------------------------------------
@router.post("/memory/{fact_id}/confirm")
async def confirm_memory(fact_id: str) -> dict[str, Any]:
    with _mapped_errors(), _service() as service:
        fact = service.confirm_memory(fact_id)
    return {"ok": True, "fact": fact}


@router.post("/memory/{fact_id}/reject")
async def reject_memory(fact_id: str) -> dict[str, Any]:
    with _mapped_errors(), _service() as service:
        fact = service.reject_memory(fact_id)
    return {"ok": True, "fact": fact}


@router.post("/memory/{fact_id}/edit")
async def edit_memory(
    fact_id: str, body: dict[str, Any] | None = Body(default=None)
) -> dict[str, Any]:
    payload = _body(body)
    value = _require_text(payload, "value", limit=2000)
    with _mapped_errors(), _service() as service:
        fact = service.edit_memory(fact_id, value=value)
    return {"ok": True, "fact": fact}


@router.post("/memory/{fact_id}/forget")
async def forget_memory(
    fact_id: str, body: dict[str, Any] | None = Body(default=None)
) -> dict[str, Any]:
    payload = _body(body)
    if payload.get("confirm") is not True:
        raise _fail(
            400,
            "confirmation_required",
            "Deleting a memory fact requires confirm=true.",
        )
    with _mapped_errors(), _service() as service:
        deleted = service.forget_memory(fact_id)
    return {"ok": True, "deleted": deleted}


@router.post("/dream")
async def run_dream() -> dict[str, Any]:
    with _mapped_errors(), _service() as service:
        result = service.dream()
    return {"ok": True, "dream": result}


@router.post("/retention")
async def retention(
    body: dict[str, Any] | None = Body(default=None)
) -> dict[str, Any]:
    payload = _body(body)
    days = payload.get("days")
    if days is not None:
        try:
            days = max(1, min(3650, int(days)))
        except (TypeError, ValueError):
            raise _fail(400, "invalid_request", "`days` must be an integer.")
    with _mapped_errors(), _service() as service:
        result = service.apply_retention(days)
    return {"ok": True, "retention": result}


# ---------------------------------------------------------------------------
# Security actions
# ---------------------------------------------------------------------------
@router.post("/attack-lab/run")
async def run_attack_lab(
    body: dict[str, Any] | None = Body(default=None)
) -> dict[str, Any]:
    payload = _body(body)
    suite = str(payload.get("suite") or "tripwire").strip().lower()
    with _mapped_errors(), _service() as service:
        result = service.run_attack_lab(suite=suite)
    return result


# ---------------------------------------------------------------------------
# Checkpoint actions
# ---------------------------------------------------------------------------
@router.post("/checkpoints/export")
async def export_checkpoint(
    body: dict[str, Any] | None = Body(default=None)
) -> dict[str, Any]:
    payload = _body(body)
    passphrase = _require_text(payload, "passphrase", limit=1024)
    if "destination" in payload:
        raise _fail(
            400,
            "invalid_request",
            "Checkpoint exports are written to the plugin checkpoint directory.",
        )
    with _mapped_errors(), _service() as service:
        result = service.export_checkpoint(passphrase)
    # The passphrase is intentionally dropped here; nothing retains it.
    return {"ok": True, **result}


@router.post("/checkpoints/inspect")
async def inspect_checkpoint(
    body: dict[str, Any] | None = Body(default=None)
) -> dict[str, Any]:
    payload = _body(body)
    passphrase = _require_text(payload, "passphrase", limit=1024)
    path = _require_text(payload, "path", limit=1000)
    with _mapped_errors(), _service() as service:
        result = service.inspect_checkpoint(
            path, passphrase, expected_checksum=_optional_checksum(payload)
        )
    return {"ok": True, "preview": result}


@router.post("/checkpoints/import")
async def import_checkpoint(
    body: dict[str, Any] | None = Body(default=None)
) -> dict[str, Any]:
    payload = _body(body)
    passphrase = _require_text(payload, "passphrase", limit=1024)
    path = _require_text(payload, "path", limit=1000)
    confirm = payload.get("confirm") is True
    with _mapped_errors(), _service() as service:
        result = service.import_checkpoint(
            path,
            passphrase,
            confirm=confirm,
            expected_checksum=_optional_checksum(payload),
        )
    status = "imported" if confirm else "preview"
    return {"ok": True, "status": status, "result": result}


@router.post("/resume-brief/{brief_id}/dismiss")
async def dismiss_resume_brief(brief_id: str) -> dict[str, Any]:
    with _mapped_errors(), _service() as service:
        service.dismiss_resume_brief(brief_id)
    return {"ok": True, "dismissed": brief_id}


# ---------------------------------------------------------------------------
# Eight-system actions
# ---------------------------------------------------------------------------
@router.post("/reality/snapshot")
async def create_reality_snapshot(
    body: dict[str, Any] | None = Body(default=None),
) -> dict[str, Any]:
    payload = _body(body)
    scope = payload.get("scope")
    if scope is not None and not isinstance(scope, str):
        raise _fail(400, "invalid_request", "`scope` must be a string.")
    paths = payload.get("paths") or []
    if not isinstance(paths, list) or any(not isinstance(item, str) for item in paths):
        raise _fail(400, "invalid_request", "`paths` must be an array of strings.")
    with _mapped_errors(), _service() as service:
        snapshot = service.reality_snapshot(
            scope=(scope or "").strip() or None,
            paths=paths[:100],
            label=str(payload.get("label") or "").strip()[:120],
        )
    return {"ok": True, "snapshot": snapshot}


@router.post("/reality/diff")
async def create_reality_diff(
    body: dict[str, Any] | None = Body(default=None),
) -> dict[str, Any]:
    payload = _body(body)
    snapshot_id = payload.get("snapshot_id")
    if snapshot_id is not None and not isinstance(snapshot_id, str):
        raise _fail(400, "invalid_request", "`snapshot_id` must be a string.")
    with _mapped_errors(), _service() as service:
        result = service.reality_diff((snapshot_id or "").strip() or None)
    return {"ok": True, "diff": result}


@router.post("/evidence/record-file")
async def record_file_evidence(
    body: dict[str, Any] | None = Body(default=None),
) -> dict[str, Any]:
    payload = _body(body)
    path = _require_text(payload, "path", limit=1000)
    expected = payload.get("expected_sha256")
    with _mapped_errors(), _service() as service:
        receipt = service.record_evidence_file(
            path,
            expected_sha256=(str(expected).strip() if expected else None),
            scope=str(payload.get("scope") or "").strip()[:500],
            memory_ref=(str(payload.get("memory_ref") or "").strip() or None),
        )
    return {"ok": True, "receipt": receipt}


@router.post("/evidence/{receipt_id}/confirm")
async def confirm_evidence(receipt_id: str) -> dict[str, Any]:
    with _mapped_errors(), _service() as service:
        receipt = service.confirm_evidence(receipt_id)
    return {"ok": True, "receipt": receipt}


@router.post("/evidence/protect")
async def protect_evidence(
    body: dict[str, Any] | None = Body(default=None),
) -> dict[str, Any]:
    payload = _body(body)
    artifact_ref = _require_text(payload, "artifact_ref", limit=1000)
    with _mapped_errors(), _service() as service:
        protected = service.protect_artifact(
            artifact_ref,
            receipt_id=(str(payload.get("receipt_id") or "").strip() or None),
            scope=str(payload.get("scope") or "").strip()[:500],
        )
    return {"ok": True, "protected": protected}


@router.post("/evidence/protected/{protected_id}/release")
async def release_evidence(
    protected_id: str, body: dict[str, Any] | None = Body(default=None)
) -> dict[str, Any]:
    payload = _body(body)
    with _mapped_errors(), _service() as service:
        protected = service.release_artifact(
            protected_id, reason=str(payload.get("reason") or "")[:500]
        )
    return {"ok": True, "protected": protected}


@router.post("/charters/{charter_id}/amend")
async def amend_charter(
    charter_id: str, body: dict[str, Any] | None = Body(default=None)
) -> dict[str, Any]:
    payload = _body(body)
    amendment = _require_text(payload, "amendment", limit=4000)
    with _mapped_errors(), _service() as service:
        charter = service.amend_charter(
            charter_id,
            amendment,
            rationale=str(payload.get("rationale") or "")[:1000],
            confirmed=True,
        )
    return {"ok": True, "charter": charter}


@router.post("/charters/{charter_id}/complete")
async def complete_charter(
    charter_id: str, body: dict[str, Any] | None = Body(default=None)
) -> dict[str, Any]:
    payload = _body(body)
    evidence_ids = payload.get("evidence_ids") or []
    if not isinstance(evidence_ids, list) or any(
        not isinstance(item, str) for item in evidence_ids
    ):
        raise _fail(400, "invalid_request", "`evidence_ids` must be an array of strings.")
    with _mapped_errors(), _service() as service:
        assessment = service.assess_completion(
            charter_id,
            claimed_complete=bool(payload.get("claimed_complete", True)),
            evidence_ids=evidence_ids[:50],
            user_confirmed=True,
        )
    return {"ok": True, "assessment": assessment}


@router.post("/previews")
async def preview_action(
    body: dict[str, Any] | None = Body(default=None),
) -> dict[str, Any]:
    payload = _body(body)
    tool_name = _require_text(payload, "tool_name", limit=120)
    proposed = payload.get("args") or {}
    if not isinstance(proposed, dict):
        raise _fail(400, "invalid_request", "`args` must be an object.")
    with _mapped_errors(), _service() as service:
        preview = service.preview_action(tool_name, proposed)
    return {"ok": True, "preview": preview, "note": "Preview only; nothing was executed."}


@router.post("/execution/{circuit_id}/reset")
async def reset_circuit(
    circuit_id: str, body: dict[str, Any] | None = Body(default=None)
) -> dict[str, Any]:
    payload = _body(body)
    with _mapped_errors(), _service() as service:
        circuit = service.reset_circuit(
            circuit_id, reason=str(payload.get("reason") or "Reset from Console")[:500]
        )
    return {"ok": True, "circuit": circuit}


# ---------------------------------------------------------------------------
# Hephaestus actions
# ---------------------------------------------------------------------------
def _forge_kwargs(payload: dict[str, Any]) -> dict[str, Any]:
    kwargs: dict[str, Any] = {}
    for key in ("name", "description", "schedule", "expires_at", "cron_job_id"):
        value = payload.get(key)
        if value is not None:
            kwargs[key] = str(value)[:4000 if key == "description" else 500]
    for key in ("allowed_tools", "allowed_paths", "allowed_domains"):
        value = payload.get(key)
        if isinstance(value, list):
            kwargs[key] = [
                str(item)[:500] for item in value[:200] if isinstance(item, str)
            ]
    for key in (
        "max_tool_calls",
        "max_file_writes",
        "max_external_calls",
        "ttl_minutes",
    ):
        value = payload.get(key)
        if value is not None:
            try:
                kwargs[key] = int(value)
            except (TypeError, ValueError) as exc:
                raise _fail(400, "invalid_request", f"`{key}` must be an integer.") from exc
    for key in ("allow_opaque_tools", "allow_untrusted", "force", "issue_lease"):
        if key in payload:
            kwargs[key] = bool(payload.get(key))
    return kwargs


@router.post("/forge/preview")
async def preview_forge(
    body: dict[str, Any] | None = Body(default=None),
) -> dict[str, Any]:
    payload = _body(body)
    session_id = _require_text(payload, "session_id", limit=120)
    with _mapped_errors(), _service() as service:
        preview = service.preview_forge(session_id, **_forge_kwargs(payload))
    return {"ok": True, **preview}


@router.post("/forge")
async def forge_playbook(
    body: dict[str, Any] | None = Body(default=None),
) -> dict[str, Any]:
    payload = _body(body)
    session_id = _require_text(payload, "session_id", limit=120)
    if payload.get("confirm") is not True:
        raise _fail(
            400,
            "confirmation_required",
            "Forging artifacts requires confirm=true and an explicit user request.",
        )
    with _mapped_errors(), _service() as service:
        result = service.forge_playbook(
            session_id, confirm=True, **_forge_kwargs(payload)
        )
    return {"ok": True, **result}


@router.post("/forge/{playbook_id}/quarantine")
async def quarantine_playbook(
    playbook_id: str, body: dict[str, Any] | None = Body(default=None)
) -> dict[str, Any]:
    payload = _body(body)
    if payload.get("confirm") is not True:
        raise _fail(400, "confirmation_required", "Quarantine requires confirm=true.")
    with _mapped_errors(), _service() as service:
        playbook = service.quarantine_playbook(
            playbook_id,
            reason=str(payload.get("reason") or "Quarantined from Console")[:500],
            confirmed=True,
        )
    return {"ok": True, "playbook": playbook}


@router.post("/forge/{playbook_id}/unquarantine")
async def unquarantine_playbook(
    playbook_id: str, body: dict[str, Any] | None = Body(default=None)
) -> dict[str, Any]:
    payload = _body(body)
    if payload.get("confirm") is not True:
        raise _fail(400, "confirmation_required", "Unquarantine requires confirm=true.")
    with _mapped_errors(), _service() as service:
        playbook = service.unquarantine_playbook(playbook_id, confirmed=True)
    return {"ok": True, "playbook": playbook}


@router.post("/leases")
async def issue_lease(
    body: dict[str, Any] | None = Body(default=None),
) -> dict[str, Any]:
    payload = _body(body)
    playbook_id = _require_text(payload, "playbook_id", limit=120)
    if payload.get("confirm") is not True:
        raise _fail(400, "confirmation_required", "Issuing a lease requires confirm=true.")
    kwargs = _forge_kwargs(payload)
    for key in ("name", "description", "schedule", "allow_untrusted", "force", "issue_lease"):
        kwargs.pop(key, None)
    with _mapped_errors(), _service() as service:
        lease = service.issue_lease(playbook_id, confirmed=True, **kwargs)
    return {"ok": True, "lease": lease}


@router.post("/leases/{lease_id}/revoke")
async def revoke_lease(
    lease_id: str, body: dict[str, Any] | None = Body(default=None)
) -> dict[str, Any]:
    payload = _body(body)
    if payload.get("confirm") is not True:
        raise _fail(400, "confirmation_required", "Revoking a lease requires confirm=true.")
    with _mapped_errors(), _service() as service:
        lease = service.revoke_lease(
            lease_id,
            reason=str(payload.get("reason") or "Revoked from Console")[:500],
            confirmed=True,
        )
    return {"ok": True, "lease": lease}
