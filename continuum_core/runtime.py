"""Host-facing runtime: verified hook adapters and lazy plugin storage.

Every observer hook is best-effort and never changes the host's result.  The
enforcement hook (``pre_tool_call``) is fail-closed: a policy error returns an
explicit block, and a storage failure requires approval for sensitive actions
rather than silently granting them.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Any

from .common.config import ContinuumConfig
from .common.ids import stable_hash
from .common.redaction import redact_mapping, redact_text
from .common.time import utc_now_iso
from .constants import NO_LABEL_TOOLS, PLUGIN_ID
from .service import ContinuumService
from .tripwire import (
    annotate_result,
    classify_source,
    evaluate,
    is_external_tool,
    is_sensitive_sink,
    is_sensitive_tool,
)

logger = logging.getLogger(__name__)


class PluginHostRegistrar:
    """Narrow adapter over the verified Hermes v0.22.2 registration contract.

    Failures are returned as data so a forged artifact can still be reviewed in
    the Console.  This adapter never grants an approval or executes a skill.
    """

    def __init__(self, ctx: Any):
        self.ctx = ctx
        self.available = bool(
            callable(getattr(ctx, "register_skill", None))
            and callable(getattr(ctx, "register_automation_blueprint", None))
        )

    def register_skill(
        self,
        name: str,
        path: Path,
        description: str = "",
        frontmatter: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            result = self.ctx.register_skill(
                name,
                Path(path),
                description=description,
                frontmatter=frontmatter,
            )
        except Exception as exc:  # noqa: BLE001 - one artifact must not stop load
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}"[:500]}
        return {"ok": result is not None}

    def register_blueprint(self, key: str, **fields: Any) -> dict[str, Any]:
        required = ("title", "description", "schedule_template", "prompt_template")
        missing = [name for name in required if not str(fields.get(name) or "").strip()]
        if missing:
            return {"ok": False, "error": "missing fields: " + ", ".join(missing)}
        try:
            result = self.ctx.register_automation_blueprint(key, **fields)
        except Exception as exc:  # noqa: BLE001 - one artifact must not stop load
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}"[:500]}
        return {"ok": result is not None}


class ContinuumRuntime:
    def __init__(self, ctx: Any):
        self.ctx = ctx
        self._lock = threading.RLock()
        self._service: ContinuumService | None = None
        self._config = self._read_config()
        self._registrar = PluginHostRegistrar(ctx)
        self._rehydrated = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def _read_config(self) -> ContinuumConfig:
        getter = getattr(self.ctx, "get_config", None)
        if callable(getter):
            try:
                return ContinuumConfig.from_getter(getter)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Continuum could not read plugin configuration (%s); using safe defaults.",
                    type(exc).__name__,
                )
        return ContinuumConfig()

    def refresh_config(self) -> None:
        with self._lock:
            if self._service is not None:
                try:
                    self._service.close()
                except Exception:
                    pass
            self._config = self._read_config()
            self._service = None
            self._rehydrated = False

    def service(self) -> ContinuumService:
        with self._lock:
            if self._service is None:
                self._service = ContinuumService.from_plugin_storage(
                    config=self._config, host_registrar=self._registrar
                )
            if not self._rehydrated:
                self._rehydrated = True
                try:
                    result = self._service.hephaestus.rehydrate()
                    if result.get("errors"):
                        logger.warning(
                            "Hephaestus rehydrated %s skill(s) and %s blueprint(s) "
                            "with %s skipped artifact(s).",
                            result.get("skills", 0),
                            result.get("blueprints", 0),
                            len(result.get("errors") or []),
                        )
                except Exception as exc:  # noqa: BLE001 - load must not fail
                    logger.warning(
                        "Hephaestus artifact rehydration skipped (%s).",
                        type(exc).__name__,
                    )
            return self._service

    def _cron_execution(self) -> Any:
        getter = getattr(self.ctx, "current_cron_execution", None)
        if not callable(getter):
            return None
        try:
            return getter()
        except Exception as exc:  # noqa: BLE001 - an unavailable cron context is interactive
            logger.warning(
                "Continuum could not read the Cron execution identity (%s).",
                type(exc).__name__,
            )
            return None

    def close(self) -> None:
        with self._lock:
            if self._service is not None:
                try:
                    self._service.close()
                except Exception:
                    pass
                self._service = None
            self._rehydrated = False

    # ------------------------------------------------------------------
    # Enforcement
    # ------------------------------------------------------------------
    def pre_tool_call(
        self,
        tool_name: str,
        args: Any,
        task_id: str = "",
        **kwargs: Any,
    ) -> dict[str, str] | None:
        session_id = str(kwargs.get("session_id") or task_id or "")
        turn_id = str(kwargs.get("turn_id") or "")
        tool_call_id = str(kwargs.get("tool_call_id") or "")
        source = None
        context_trust = "UNKNOWN"
        try:
            service = self.service()
            if session_id:
                source = service.store.latest_source_for_session(
                    session_id,
                    window_minutes=self._config.context_trust_window_minutes,
                )
                # A later local read must not mask earlier untrusted external
                # content.  If any external source is inside the window, the
                # enforcement context stays untrusted even when the newest
                # source is local.
                untrusted = service.store.latest_source_for_session(
                    session_id,
                    window_minutes=self._config.context_trust_window_minutes,
                    trust_label="UNTRUSTED_EXTERNAL",
                )
                if untrusted is not None:
                    source = untrusted
            if source is not None:
                context_trust = str(source.get("trust_label") or "UNKNOWN")
            decision = evaluate(
                tool_name,
                args,
                context_trust=context_trust,
                source_ref=source.get("id") if source else None,
            )
            should_audit = decision.outcome != "allow" or (
                self._config.tripwire_audit_allowed
                and (is_sensitive_tool(tool_name) or is_sensitive_sink(tool_name, args))
            )
            if should_audit:
                try:
                    service.store.record_decision(
                        tool_name=str(tool_name or "unknown"),
                        outcome=decision.outcome,
                        rule_key=decision.rule_key,
                        category=decision.category,
                        reason=decision.reason,
                        evidence=decision.evidence,
                        args=args,
                        session_id=session_id or None,
                        tool_call_id=tool_call_id or None,
                        turn_id=turn_id or None,
                        source_ref=source.get("id") if source else None,
                        trust_label=context_trust,
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "Continuum could not write a security audit record (%s). "
                        "The policy decision is unchanged.",
                        type(exc).__name__,
                    )
            action_ref = _action_ref(tool_call_id, tool_name, args)
            if self._config.enable_metis:
                try:
                    circuit = service.metis.preflight(tool_name, args)
                    if circuit is not None and decision.outcome != "block":
                        alternatives = circuit.get("alternatives") or []
                        return {
                            "action": "block",
                            "message": (
                                "Metis stopped a repeated, unproductive operation before "
                                f"execution. {circuit.get('reason') or 'A retry circuit is open.'} "
                                "Change the strategy or arguments, or reset the circuit in "
                                "the Continuum Console after inspecting the failure. "
                                + (
                                    "Alternatives: " + "; ".join(str(item) for item in alternatives[:4])
                                    if alternatives
                                    else ""
                                )
                            ).strip()[:1500],
                            "rule_key": "metis.circuit.open",
                        }
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "Metis preflight skipped (%s); Tripwire's decision is unchanged.",
                        type(exc).__name__,
                    )
            if decision.outcome == "block":
                return decision.host_result()
            cron = self._cron_execution()
            if self._config.enable_hephaestus:
                # A quarantined forged artifact must not be consumable while the
                # host still holds its registry entry.  This is an additive block
                # only; it never approves the action or unregisters the host item.
                try:
                    artifact_decision = service.hephaestus.quarantined_artifact_check(
                        tool_name,
                        args,
                        session_id=session_id or None,
                        tool_call_id=tool_call_id or None,
                    )
                    if artifact_decision.get("decision") == "block":
                        return {
                            "action": "block",
                            "message": (
                                "Hephaestus blocked use of a quarantined artifact. "
                                f"{artifact_decision.get('reason') or 'The artifact is quarantined.'} "
                                "Review it in the Continuum Console and unquarantine it "
                                "only after an explicit decision."
                            )[:1500],
                            "rule_key": str(
                                artifact_decision.get("rule_key")
                                or "hephaestus.artifact.quarantined"
                            ),
                        }
                except Exception as exc:  # noqa: BLE001 - fail closed for quarantined use
                    logger.warning(
                        "Hephaestus quarantined-artifact check failed (%s); "
                        "blocking the action fail-closed.",
                        type(exc).__name__,
                    )
                    return {
                        "action": "block",
                        "message": (
                            "Hephaestus could not verify whether this action uses a "
                            "quarantined artifact, so it blocked the action fail-closed."
                        ),
                        "rule_key": "hephaestus.artifact.unavailable",
                    }
                if cron is not None:
                    try:
                        lease_decision = service.hephaestus.check_cron_tool(
                            tool_name,
                            args,
                            cron,
                            session_id=session_id or None,
                            tool_call_id=tool_call_id or None,
                        )
                        if lease_decision.get("decision") == "block":
                            return {
                                "action": "block",
                                "message": (
                                    "Hephaestus blocked this unattended Cron action. "
                                    f"{lease_decision.get('reason') or 'The action is outside the safety lease.'} "
                                    "Safety leases never grant approval; update the "
                                    "lease in the Continuum Console after review."
                                )[:1500],
                                "rule_key": str(
                                    lease_decision.get("rule_key")
                                    or "hephaestus.lease.violation"
                                ),
                            }
                    except Exception as exc:  # noqa: BLE001 - fail closed for Cron
                        logger.warning(
                            "Hephaestus Cron lease check failed (%s); blocking "
                            "unattended execution fail-closed.",
                            type(exc).__name__,
                        )
                        return {
                            "action": "block",
                            "message": (
                                "Hephaestus could not verify the safety lease for this "
                                "unattended Cron action, so it blocked it fail-closed."
                            ),
                            "rule_key": "hephaestus.lease.unavailable",
                        }
                # Skill-write quarantine applies to interactive and Cron tool
                # calls alike.  A Cron lease permits scope, not an untrusted
                # skill write.
                try:
                    skill_decision = service.hephaestus.skill_write_check(
                        tool_name,
                        args,
                        session_id=session_id or None,
                        tool_call_id=tool_call_id or None,
                    )
                    if not skill_decision.get("allowed", True):
                        return {
                            "action": "block",
                            "message": (
                                "Hephaestus quarantined a skill write. "
                                f"{skill_decision.get('reason') or 'The session contains untrusted external content.'} "
                                "Review the source session before writing a skill."
                            )[:1500],
                            "rule_key": str(
                                skill_decision.get("rule_key")
                                or "hephaestus.skill.untrusted_write"
                            ),
                        }
                except Exception as exc:  # noqa: BLE001 - fail closed for skill writes
                    logger.warning(
                        "Hephaestus skill-write quarantine check failed (%s); "
                        "blocking the skill write fail-closed.",
                        type(exc).__name__,
                    )
                    return {
                        "action": "block",
                        "message": (
                            "Hephaestus could not verify the trust context for a "
                            "skill write, so it blocked it fail-closed."
                        ),
                        "rule_key": "hephaestus.skill.unavailable",
                    }
            holds: list[dict[str, Any]] = []
            if self._config.enable_aletheia:
                try:
                    challenges = service.aletheia.challenges_for_action(
                        tool_name,
                        args,
                        action_ref=action_ref,
                        session_id=session_id or None,
                        task_id=task_id or None,
                        source_ref=source.get("id") if source else None,
                        trust_label=context_trust,
                    )
                    for challenge in challenges:
                        holds.append(
                            {
                                "rule_key": "aletheia.protected_artifact",
                                "reason": str(challenge.get("reason") or "Protected artifact challenge."),
                                "challenge_id": challenge.get("id"),
                            }
                        )
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "Aletheia protection check skipped (%s).",
                        type(exc).__name__,
                    )
            if self._config.enable_telos:
                try:
                    charter = service.telos.active_charter(
                        session_id=session_id or None,
                        task_id=task_id or None,
                    )
                    conflicts = service.telos.constraint_conflicts(
                        charter, tool_name, args
                    )
                    for conflict in conflicts:
                        holds.append(
                            {
                                "rule_key": "telos.constraint.conflict",
                                "reason": (
                                    "Telos found a conflict with the user's explicit "
                                    f"constraint: {conflict.get('constraint')}. "
                                    f"{conflict.get('reason')}"
                                ),
                            }
                        )
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "Telos constraint check skipped (%s).",
                        type(exc).__name__,
                    )
            preview: dict[str, Any] | None = None
            if (
                self._config.enable_moirai
                and (
                    decision.outcome == "approve"
                    or is_sensitive_tool(tool_name)
                    or is_sensitive_sink(tool_name, args)
                )
            ):
                try:
                    preview = service.moirai.preview(
                        tool_name,
                        args,
                        session_id=session_id or None,
                        task_id=task_id or None,
                        action_ref=action_ref,
                        source_ref=source.get("id") if source else None,
                        trust_label=context_trust,
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "Moirai impact preview skipped (%s).",
                        type(exc).__name__,
                    )
            result = decision.host_result()
            if holds:
                messages = [
                    str(result.get("message") if result else "")
                    or "This action requires explicit user approval.",
                ]
                messages.extend(item["reason"] for item in holds[:2])
                if preview is not None:
                    messages.append(f"Impact preview: {preview.get('summary')}")
                return {
                    "action": "approve",
                    "message": " ".join(item for item in messages if item)[:1800],
                    "rule_key": str(holds[0].get("rule_key") or "continuum.approval"),
                }
            if result is not None and result.get("action") == "approve":
                result = dict(result)
                if preview is not None:
                    result["message"] = (
                        str(result.get("message") or "")
                        + f" Impact preview: {preview.get('summary')}"
                    )[:1800]
            return result
        except Exception as exc:  # noqa: BLE001
            # Storage or source lookup failed.  Static policy can still run;
            # sensitive sinks require explicit approval in this degraded mode.
            logger.warning(
                "Continuum enforcement is running without its audit store (%s).",
                type(exc).__name__,
            )
            try:
                decision = evaluate(tool_name, args, context_trust="UNKNOWN")
            except Exception:
                return {
                    "action": "block",
                    "message": (
                        "Tripwire could not evaluate this action safely and "
                        "blocked it fail-closed."
                    ),
                    "rule_key": "tripwire.internal.policy_error",
                }
            if decision.outcome == "allow" and is_sensitive_sink(tool_name, args):
                return {
                    "action": "approve",
                    "message": (
                        "Tripwire's audit store is unavailable, so this sensitive "
                        "action requires approval. Restore plugin storage before "
                        "relying on the audit history."
                    ),
                    "rule_key": "tripwire.storage.unavailable",
                }
            return decision.host_result()

    # ------------------------------------------------------------------
    # Observer hooks
    # ------------------------------------------------------------------
    def post_tool_call(
        self,
        tool_name: str,
        args: Any,
        result: Any,
        task_id: str = "",
        **kwargs: Any,
    ) -> None:
        try:
            session_id = str(kwargs.get("session_id") or task_id or "")
            turn_id = str(kwargs.get("turn_id") or "")
            tool_call_id = str(kwargs.get("tool_call_id") or "")
            status = str(kwargs.get("status") or kwargs.get("outcome") or "completed")
            duration_ms = _safe_int(kwargs.get("duration_ms"))
            error_type = kwargs.get("error_type") or kwargs.get("error")
            error_name = (
                str(error_type)[:80]
                if isinstance(error_type, str)
                else type(error_type).__name__ if error_type else None
            )
            service = self.service()
            source = None
            source_desc = classify_source(tool_name, args, result)
            if (
                is_external_tool(tool_name)
                or str(tool_name or "").strip().lower()
                in {"read_file", "file_read", "view_file", "terminal", "process_manage"}
            ):
                try:
                    source = service.store.record_source(
                        tool_name=str(tool_name or "unknown"),
                        source_type=source_desc["source_type"],
                        reference=source_desc["reference"],
                        trust_label=source_desc["trust_label"],
                        provenance_confidence=source_desc["provenance_confidence"],
                        sensitivity=source_desc["sensitivity"],
                        session_id=session_id or None,
                        turn_id=turn_id or None,
                        task_id=task_id or None,
                        tool_call_id=tool_call_id or None,
                        details={
                            "result_length": _safe_length(result),
                            "status": status,
                        },
                        idempotency_key=_source_key(
                            session_id, tool_call_id, tool_name, source_desc["reference"]
                        ),
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "Continuum could not record a source label (%s).",
                        type(exc).__name__,
                    )
            result_hash = stable_hash(
                {
                    "tool_name": tool_name,
                    "length": _safe_length(result),
                    "preview": redact_text(result, max_chars=200),
                }
            )
            service.store.append_event(
                "tool_result_observed",
                f"{tool_name} {status}" + (f" in {duration_ms} ms" if duration_ms is not None else ""),
                session_id=session_id or None,
                turn_id=turn_id or None,
                task_id=task_id or None,
                tool_call_id=tool_call_id or None,
                source_ref=source.get("id") if source else None,
                trust_label=source.get("trust_label") if source else None,
                sensitivity=source.get("sensitivity") if source else None,
                details={
                    "tool_name": str(tool_name or "unknown"),
                    "status": status,
                    "duration_ms": duration_ms,
                    "result_length": _safe_length(result),
                    "result_hash": result_hash,
                    "error_type": error_name,
                    "source_ref": source.get("id") if source else None,
                    "args_preview": redact_mapping(
                        args, max_string=300, max_items=40
                    ),
                },
                idempotency_key=f"tool-result:{_source_key(session_id, tool_call_id, tool_name, result_hash)}",
            )
            action_ref = _action_ref(tool_call_id, tool_name, args)
            metis_result: dict[str, Any] = {}
            if self._config.enable_metis:
                try:
                    metis_result = service.metis.observe_result(
                        tool_name,
                        args,
                        status=status,
                        result=result,
                        error_type=error_name,
                        session_id=session_id or None,
                        task_id=task_id or None,
                        tool_call_id=tool_call_id or None,
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "Metis failure observation skipped (%s).",
                        type(exc).__name__,
                    )
            if self._config.enable_aletheia:
                try:
                    service.aletheia.resolve_challenges_for_action(
                        action_ref,
                        executed=str(status).casefold()
                        not in {"blocked", "denied", "cancelled", "canceled"},
                        resolution=f"Tool result status: {status}",
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "Aletheia challenge resolution skipped (%s).",
                        type(exc).__name__,
                    )
            if self._config.enable_telos:
                try:
                    charter = service.telos.active_charter(
                        session_id=session_id or None,
                        task_id=task_id or None,
                    )
                    if charter is not None:
                        service.telos.observe_action(
                            str(charter["id"]),
                            tool_name=tool_name,
                            args=args,
                            success=not bool(metis_result.get("failure")),
                            session_id=session_id or None,
                            task_id=task_id or None,
                            tool_call_id=tool_call_id or None,
                        )
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "Telos drift observation skipped (%s).",
                        type(exc).__name__,
                    )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Continuum post_tool_call observer skipped (%s).",
                type(exc).__name__,
            )

    def transform_tool_result(
        self,
        tool_name: str,
        args: Any,
        result: Any,
        task_id: str = "",
        **kwargs: Any,
    ) -> str | None:
        try:
            if not self._config.enable_source_labels:
                return None
            if str(tool_name or "").strip().lower() in NO_LABEL_TOOLS:
                return None
            if str(tool_name or "").startswith("continuum_"):
                return None
            if not is_external_tool(tool_name):
                return None
            if not isinstance(result, str):
                return None
            session_id = str(kwargs.get("session_id") or task_id or "")
            turn_id = str(kwargs.get("turn_id") or "")
            tool_call_id = str(kwargs.get("tool_call_id") or "")
            service = self.service()
            descriptor = classify_source(tool_name, args, result)
            source = service.store.record_source(
                tool_name=str(tool_name or "unknown"),
                source_type=descriptor["source_type"],
                reference=descriptor["reference"],
                trust_label=descriptor["trust_label"],
                provenance_confidence=descriptor["provenance_confidence"],
                sensitivity=descriptor["sensitivity"],
                session_id=session_id or None,
                turn_id=turn_id or None,
                task_id=task_id or None,
                tool_call_id=tool_call_id or None,
                details={"result_length": _safe_length(result), "label": True},
                idempotency_key=_source_key(
                    session_id, tool_call_id, tool_name, descriptor["reference"]
                ),
            )
            return annotate_result(tool_name, args, result, source)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Continuum source label skipped (%s).",
                type(exc).__name__,
            )
            return None

    def pre_llm_call(
        self,
        session_id: str = "",
        user_message: Any = "",
        **kwargs: Any,
    ) -> dict[str, str] | None:
        try:
            service = self.service()
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Continuum recall injection skipped (%s).",
                type(exc).__name__,
            )
            return None
        parts: list[str] = []
        if self._config.enable_telos:
            try:
                charter = service.ensure_charter(
                    user_message,
                    session_id=session_id or None,
                    task_id=str(kwargs.get("task_id") or "") or None,
                    trust_label="USER_AUTHORED",
                )
                circuit_note = ""
                if self._config.enable_metis:
                    circuit_note = service.metis.circuit_note()
                context = service.telos.context(charter, circuit_note=circuit_note)
                if context:
                    parts.append(context)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Telos charter context skipped (%s).",
                    type(exc).__name__,
                )
        try:
            context = service.recall_context(user_message, session_id=session_id)
            if context:
                parts.append(context)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Continuum recall injection skipped (%s).",
                type(exc).__name__,
            )
        if parts:
            return {"context": "\n\n".join(parts)[:6000]}
        return None

    def post_llm_call(
        self,
        session_id: str = "",
        user_message: Any = "",
        assistant_response: Any = "",
        **kwargs: Any,
    ) -> None:
        try:
            service = self.service()
            source = None
            if session_id:
                try:
                    source = service.store.latest_source_for_session(
                        session_id,
                        window_minutes=self._config.context_trust_window_minutes,
                    )
                except Exception:
                    source = None
            service.capture_turn(
                user_message=user_message,
                assistant_message=assistant_response,
                session_id=session_id or None,
                turn_id=str(kwargs.get("turn_id") or "") or None,
                task_id=str(kwargs.get("task_id") or "") or None,
                source_ref=source.get("id") if source else None,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Continuum memory capture skipped (%s).",
                type(exc).__name__,
            )

    def on_session_start(
        self,
        session_id: str = "",
        model: str = "",
        platform: str = "",
        **kwargs: Any,
    ) -> None:
        self._append_event(
            "session_started",
            f"Session started on {platform or 'unknown platform'}",
            session_id=session_id or None,
            details={"model": redact_text(model, max_chars=120), "platform": platform},
            idempotency_key=f"session-start:{session_id or 'unknown'}",
        )

    def on_session_end(
        self,
        session_id: str = "",
        completed: bool = False,
        interrupted: bool = False,
        **kwargs: Any,
    ) -> None:
        turn_id = str(kwargs.get("turn_id") or "")
        status = "completed" if completed else ("interrupted" if interrupted else "failed")
        key = f"session-end:{session_id or 'unknown'}:{turn_id or utc_now_iso()}"
        self._append_event(
            "session_ended",
            f"Session turn {status}",
            session_id=session_id or None,
            turn_id=turn_id or None,
            details={
                "completed": bool(completed),
                "interrupted": bool(interrupted),
                "model": redact_text(kwargs.get("model") or "", max_chars=120),
                "platform": kwargs.get("platform") or "",
            },
            idempotency_key=key,
        )

    def on_session_finalize(
        self,
        session_id: str | None = None,
        platform: str = "",
        **kwargs: Any,
    ) -> None:
        # Observer only.  We deliberately do not use the return-message channel.
        self._append_event(
            "session_finalized",
            "Session finalized",
            session_id=session_id or None,
            details={"platform": platform, "reason": kwargs.get("reason") or ""},
            idempotency_key=f"session-finalize:{session_id or 'none'}:{kwargs.get('reason') or ''}",
        )

    def on_session_reset(
        self,
        session_id: str = "",
        platform: str = "",
        **kwargs: Any,
    ) -> None:
        self._append_event(
            "session_reset",
            "Session reset",
            session_id=session_id or None,
            details={
                "platform": platform,
                "reason": kwargs.get("reason") or "",
                "old_session_id": kwargs.get("old_session_id"),
                "new_session_id": kwargs.get("new_session_id"),
            },
            idempotency_key=f"session-reset:{session_id or 'unknown'}:{kwargs.get('reason') or ''}",
        )

    def pre_approval_request(
        self,
        command: str = "",
        description: str = "",
        pattern_key: str = "",
        pattern_keys: Any = None,
        session_key: str = "",
        surface: str = "",
        **kwargs: Any,
    ) -> None:
        self._append_event(
            "approval_observed",
            f"Approval requested: {pattern_key or 'unknown'} ({surface or 'unknown'})",
            session_id=session_key or None,
            details={
                "pattern_key": pattern_key,
                "pattern_keys": pattern_keys if isinstance(pattern_keys, list) else [],
                "surface": surface,
                "description_present": bool(description),
                "command_present": bool(command),
                "event": "request",
            },
            idempotency_key=f"approval-request:{session_key}:{pattern_key}:{surface}:{stable_hash({'c': bool(command), 'd': bool(description)})}",
        )

    def post_approval_response(
        self,
        command: str = "",
        description: str = "",
        pattern_key: str = "",
        pattern_keys: Any = None,
        session_key: str = "",
        surface: str = "",
        choice: str = "",
        **kwargs: Any,
    ) -> None:
        self._append_event(
            "approval_observed",
            f"Approval response: {choice or 'unknown'} ({pattern_key or 'unknown'})",
            session_id=session_key or None,
            details={
                "pattern_key": pattern_key,
                "pattern_keys": pattern_keys if isinstance(pattern_keys, list) else [],
                "surface": surface,
                "choice": choice,
                "decided_by": kwargs.get("decided_by"),
                "event": "response",
            },
            idempotency_key=f"approval-response:{session_key}:{pattern_key}:{surface}:{choice}",
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _append_event(self, event_type: str, summary: str, **kwargs: Any) -> None:
        try:
            service = self.service()
            service.store.append_event(event_type, summary, **kwargs)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Continuum event observer skipped for %s (%s).",
                event_type,
                type(exc).__name__,
            )


def _source_key(
    session_id: str, tool_call_id: str, tool_name: str, reference: str
) -> str:
    return stable_hash(
        {
            "session_id": session_id,
            "tool_call_id": tool_call_id,
            "tool_name": tool_name,
            "reference": reference,
        }
    )


def _action_ref(tool_call_id: str, tool_name: str, args: Any) -> str:
    if tool_call_id:
        return tool_call_id
    return "call_" + stable_hash({"tool_name": tool_name, "args": args})[:32]


def _safe_length(value: Any) -> int:
    try:
        return len(value) if value is not None else 0
    except TypeError:
        return 0


def _safe_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
