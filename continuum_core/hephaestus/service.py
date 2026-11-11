"""Hephaestus: verified trace distillation, forged artifacts, and safety leases.

The service is deliberately conservative:

* only tool results the host reported as successful become procedure steps;
* retries are deduplicated by ``(tool_name, json.dumps(params, sort_keys=True))``;
* source-labelled untrusted successes are excluded from instructions;
* an unattended Cron call is checked against an explicit, expiring lease;
* a lease never grants an approval and never replaces Tripwire or the host.
"""

from __future__ import annotations

import fnmatch
import json
import os
import platform
import posixpath
import re
import sys
from datetime import timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ..common.config import ContinuumConfig
from ..common.ids import new_id, stable_hash
from ..common.redaction import redact_text, truncate
from ..common.time import parse_utc, utc_now, utc_now_iso
from ..constants import PLUGIN_ID, POLICY_VERSION
from ..spine.store import SpineStore
from .artifacts import (
    atomic_write_text,
    is_within,
    playbook_dir,
    render_blueprint_spec,
    render_manifest,
    render_skill_markdown,
    rehydrate_artifacts,
    sha256_text,
    slugify,
    update_manifest_status,
)

SUCCESS_STATUSES = frozenset(
    {"completed", "complete", "success", "succeeded", "ok", "done", "allowed", "applied"}
)
FAILURE_STATUSES = frozenset(
    {
        "blocked",
        "denied",
        "cancelled",
        "canceled",
        "failed",
        "failure",
        "error",
        "timeout",
        "timed_out",
        "rejected",
        "partial",
        "interrupted",
    }
)
WRITE_TOOLS = frozenset(
    {
        "write_file",
        "patch",
        "file_write",
        "file_edit",
        "apply_patch",
        "create_file",
        "append_file",
        "delete_file",
        "remove_file",
        "move_file",
        "copy_file",
        "rename_file",
        "skill_manage",
    }
)
READ_PATH_TOOLS = frozenset(
    {
        "read_file",
        "file_read",
        "view_file",
        "list_dir",
        "list_files",
        "glob",
        "grep",
        "search_files",
        "read_text_file",
    }
)
PATH_TOOLS = WRITE_TOOLS | READ_PATH_TOOLS
OPAQUE_TOOLS = frozenset(
    {
        "terminal",
        "shell",
        "powershell",
        "bash",
        "python",
        "execute_code",
        "browser",
        "browser_use",
        "browser_cdp",
        "browser_exec",
        "browser_dialog",
        "browser_vault",
        "process_manage",
        "skill_manage",
        "send_email",
        "send_message",
        "post_message",
        "upload_file",
        "webhook",
        "deploy",
        "publish",
        "docker",
        "kubernetes",
    }
)
EXTERNAL_TOOLS = frozenset(
    {
        "web_fetch",
        "web_extract",
        "web_search",
        "web_crawl",
        "browser",
        "browser_exec",
        "browser_cdp",
        "browser_dialog",
        "browser_vault",
        "browser_use",
        "http_request",
        "fetch",
        "download_file",
        "upload_file",
        "send_email",
        "send_message",
        "post_message",
        "webhook",
    }
)
DOMAIN_REQUIRED_TOOLS = EXTERNAL_TOOLS - {"web_search"}
SKILL_WRITE_TOOLS = frozenset(
    {"skill_manage", "write_file", "patch", "file_write", "file_edit", "apply_patch"}
)
TRACE_EVENT_TYPES = frozenset(
    {
        "tool_result_observed",
        "action_blocked",
        "action_evaluated",
        "approval_requested",
        "drift.flagged",
        "telos.drift_flagged",
    }
)
_PATH_KEYS = frozenset(
    {
        "path",
        "paths",
        "file",
        "files",
        "filename",
        "destination",
        "target",
        "source",
        "directory",
        "dir",
        "cwd",
        "workdir",
        "folder",
    }
)
_URL_KEYS = frozenset(
    {
        "url",
        "uri",
        "endpoint",
        "href",
        "webhook",
        "domain",
        "host",
        "hostname",
        "base_url",
    }
)


class NullHostRegistrar:
    """Used by CLI/Console paths that are not allowed to touch host registry."""

    available = False

    def register_skill(
        self,
        name: str,
        path: Path,
        description: str = "",
        frontmatter: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        del name, path, description, frontmatter
        return {
            "ok": False,
            "error": "host registrar unavailable; artifact will be registered on next plugin load",
        }

    def register_blueprint(self, key: str, **fields: Any) -> dict[str, Any]:
        del key, fields
        return {
            "ok": False,
            "error": "host registrar unavailable; artifact will be registered on next plugin load",
        }


def _cron_value(cron: Any, name: str) -> str:
    if cron is None:
        return ""
    if isinstance(cron, dict):
        value = cron.get(name)
    else:
        value = getattr(cron, name, "")
    return str(value or "")


def _normal_text(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(value or "").casefold()).strip()


def _normal_tool(value: Any) -> str:
    return str(value or "").strip().casefold()


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _skill_frontmatter(
    *,
    slug: str,
    description: str,
    playbook_id: str = "",
    source_session_id: str = "",
    source_task_id: str = "",
    trace_hash: str = "",
) -> dict[str, Any]:
    """Host-visible metadata for a registered forged skill.

    The generated ``SKILL.md`` remains the authoritative document.  This mapping
    only lets the host expose the same provenance without re-reading the file.
    """

    metadata: dict[str, Any] = {
        "continuum_plugin": PLUGIN_ID,
        "continuum_system": "Hephaestus",
    }
    if playbook_id:
        metadata["playbook_id"] = playbook_id
    if source_session_id:
        metadata["source_session"] = source_session_id
    if source_task_id:
        metadata["source_task"] = source_task_id
    if trace_hash:
        metadata["trace_hash"] = trace_hash
    return {
        "name": slug,
        "description": truncate(str(description or ""), 500),
        "metadata": metadata,
    }


def _dedup_key(tool_name: str, params: Any) -> str:
    """The required retry identity: tool name plus canonical JSON params."""

    safe_params = params if isinstance(params, (dict, list)) else {}
    try:
        rendered = json.dumps(safe_params, sort_keys=True, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        rendered = "{}"
    return f"{_normal_tool(tool_name)}|{rendered}"


def _is_success(status: Any, error_type: Any = None) -> bool:
    if error_type:
        return False
    text = str(status or "").strip().casefold()
    if text in FAILURE_STATUSES:
        return False
    return text in SUCCESS_STATUSES


def _bounded_int(value: Any, default: int, low: int, high: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = default
    return max(low, min(high, number))


def _string_list(value: Any, *, lower: bool = False, limit: int = 100) -> list[str]:
    if isinstance(value, str):
        items = re.split(r"[,\n]", value)
    elif isinstance(value, (list, tuple, set)):
        items = list(value)
    else:
        items = []
    result: list[str] = []
    for item in items:
        text = str(item or "").strip()
        if not text:
            continue
        result.append(text.lower() if lower else text)
    return sorted(set(result))[:limit]


def _normalize_path(value: str) -> str:
    text = str(value or "").strip().replace("\\", "/")
    if not text:
        return ""
    if os.name == "nt":
        text = text.casefold()
    normalized = posixpath.normpath(text)
    return normalized


def _matches_path(path: str, patterns: list[str]) -> bool:
    normalized = _normalize_path(path)
    if not normalized or normalized == ".." or normalized.startswith("../"):
        return False
    for pattern in patterns:
        candidate = _normalize_path(pattern)
        if not candidate:
            continue
        if candidate == "*" or candidate == "**":
            return True
        if fnmatch.fnmatchcase(normalized, candidate):
            return True
        if not any(char in candidate for char in "*?["):
            if normalized == candidate or normalized.startswith(candidate.rstrip("/") + "/"):
                return True
        if candidate.endswith("/") and normalized.startswith(candidate):
            return True
    return False


def _domain_from_value(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if "://" not in text and "/" not in text and " " not in text:
        text = "https://" + text
    try:
        parsed = urlparse(text)
    except ValueError:
        return ""
    host = (parsed.hostname or "").strip().casefold()
    return host


def _domain_refs(args: Any) -> list[str]:
    found: list[str] = []

    def walk(value: Any, key: str = "", depth: int = 0) -> None:
        if depth > 6 or len(found) >= 50:
            return
        if isinstance(value, dict):
            for child_key, child in value.items():
                walk(child, str(child_key), depth + 1)
            return
        if isinstance(value, (list, tuple, set)):
            for item in value:
                walk(item, key, depth + 1)
            return
        if not isinstance(value, str):
            return
        lowered = key.casefold()
        if any(part in lowered for part in _URL_KEYS):
            host = _domain_from_value(value)
            if host:
                found.append(host)
            return
        for match in re.findall(r"https?://[^\s\"'<>]+", value, flags=re.IGNORECASE):
            host = _domain_from_value(match)
            if host:
                found.append(host)

    walk(args)
    return sorted(set(found))


def _path_refs(args: Any) -> list[str]:
    found: list[str] = []

    def walk(value: Any, key: str = "", depth: int = 0) -> None:
        if depth > 6 or len(found) >= 100:
            return
        if isinstance(value, dict):
            for child_key, child in value.items():
                walk(child, str(child_key), depth + 1)
            return
        if isinstance(value, (list, tuple, set)):
            for item in value:
                walk(item, key, depth + 1)
            return
        if not isinstance(value, str):
            return
        if key.casefold() in _PATH_KEYS and value.strip():
            found.append(value.strip())

    walk(args)
    return sorted(set(found))


def _domain_allowed(host: str, allowed: list[str]) -> bool:
    normalized = str(host or "").strip().casefold()
    if not normalized:
        return False
    for pattern in allowed:
        candidate = str(pattern or "").strip().casefold()
        if not candidate:
            continue
        if candidate == "*":
            return True
        if candidate.startswith("*."):
            suffix = candidate[1:]
            if normalized.endswith(suffix):
                return True
            continue
        if normalized == candidate or normalized.endswith("." + candidate):
            return True
    return False


def environment_fingerprint() -> str:
    """Stable host-environment identity used only as a coarse drift guard."""

    return stable_hash(
        {
            "platform": sys.platform,
            "machine": platform.machine(),
            "python": f"{sys.version_info.major}.{sys.version_info.minor}",
            "plugin": PLUGIN_ID,
        }
    )[:32]


def evaluate_lease_request(
    *,
    allowed_tools: list[str] | None,
    allowed_paths: list[str] | None,
    allowed_domains: list[str] | None,
    allow_opaque_tools: bool,
    tool_name: str,
    args: Any,
    usage: dict[str, Any] | None = None,
    max_tool_calls: int | None = None,
    max_file_writes: int | None = None,
    max_external_calls: int | None = None,
    current_environment: str | None = None,
    expected_environment: str | None = None,
) -> dict[str, Any]:
    """Pure scope evaluation shared by runtime enforcement and Attack Lab."""

    normalized_tool = _normal_tool(tool_name)
    allowed = {_normal_tool(item) for item in (allowed_tools or []) if str(item).strip()}
    paths = _string_list(allowed_paths, limit=200)
    domains = _string_list(allowed_domains, lower=True, limit=200)
    result: dict[str, Any] = {
        "allowed": False,
        "rule_key": "hephaestus.lease.tool_not_allowed",
        "reason": f"Tool {normalized_tool or 'unknown'} is not in the active safety lease.",
        "file_write": normalized_tool in WRITE_TOOLS,
        "external": normalized_tool in EXTERNAL_TOOLS,
        "paths": [],
        "domains": [],
    }
    if current_environment and expected_environment and current_environment != expected_environment:
        result.update(
            {
                "rule_key": "hephaestus.lease.environment_changed",
                "reason": (
                    "The host environment fingerprint differs from the environment "
                    "recorded when this safety lease was issued."
                ),
            }
        )
        return result
    if not normalized_tool or normalized_tool not in allowed:
        return result
    if normalized_tool in OPAQUE_TOOLS and not allow_opaque_tools:
        result.update(
            {
                "rule_key": "hephaestus.lease.opaque_tool",
                "reason": (
                    f"Tool {normalized_tool} is opaque and this lease does not allow "
                    "opaque tools. Scope cannot be verified lexically."
                ),
            }
        )
        return result

    refs = _path_refs(args)
    result["paths"] = refs
    if normalized_tool in PATH_TOOLS:
        if not refs:
            result.update(
                {
                    "rule_key": "hephaestus.lease.path_unscoped",
                    "reason": (
                        f"Tool {normalized_tool} requires an explicit path, but no "
                        "path argument could be verified."
                    ),
                }
            )
            return result
        if not paths:
            result.update(
                {
                    "rule_key": "hephaestus.lease.path_unscoped",
                    "reason": "This lease has no allowed paths for a path-bearing tool.",
                }
            )
            return result
        for path in refs:
            if not _matches_path(path, paths):
                result.update(
                    {
                        "rule_key": "hephaestus.lease.path_out_of_scope",
                        "reason": f"Path {truncate(path, 200)} is outside the active safety lease.",
                    }
                )
                return result

    found_domains = _domain_refs(args)
    result["domains"] = found_domains
    if normalized_tool in DOMAIN_REQUIRED_TOOLS:
        if not found_domains:
            result.update(
                {
                    "rule_key": "hephaestus.lease.domain_unscoped",
                    "reason": (
                        f"Tool {normalized_tool} is external, but no verifiable domain "
                        "was present in its arguments."
                    ),
                }
            )
            return result
        if not domains:
            result.update(
                {
                    "rule_key": "hephaestus.lease.domain_unscoped",
                    "reason": "This lease has no allowed domains for an external tool.",
                }
            )
            return result
        for host in found_domains:
            if not _domain_allowed(host, domains):
                result.update(
                    {
                        "rule_key": "hephaestus.lease.domain_out_of_scope",
                        "reason": f"Domain {host} is outside the active safety lease.",
                    }
                )
                return result

    safe_usage = usage or {}
    if max_tool_calls is not None:
        if int(safe_usage.get("tool_calls") or 0) >= max(1, int(max_tool_calls)):
            result.update(
                {
                    "rule_key": "hephaestus.lease.max_tool_calls",
                    "reason": "The safety lease tool-call budget is exhausted.",
                }
            )
            return result
    if max_file_writes is not None and result["file_write"]:
        if int(safe_usage.get("file_writes") or 0) >= max(0, int(max_file_writes)):
            result.update(
                {
                    "rule_key": "hephaestus.lease.max_file_writes",
                    "reason": "The safety lease file-write budget is exhausted.",
                }
            )
            return result
    if max_external_calls is not None and result["external"]:
        if int(safe_usage.get("external_calls") or 0) >= max(0, int(max_external_calls)):
            result.update(
                {
                    "rule_key": "hephaestus.lease.max_external_calls",
                    "reason": "The safety lease external-call budget is exhausted.",
                }
            )
            return result

    result.update(
        {
            "allowed": True,
            "rule_key": "hephaestus.lease.allow",
            "reason": "The action is inside the active safety lease.",
        }
    )
    return result


class HephaestusService:
    def __init__(
        self,
        store: SpineStore,
        config: ContinuumConfig | None = None,
        *,
        artifact_dir: Path | str | None = None,
        host_registrar: Any = None,
    ):
        self.store = store
        self.config = (config or ContinuumConfig()).clamped()
        self._base_artifact_dir = Path(
            artifact_dir or (Path.cwd() / "hephaestus-artifacts")
        ).resolve()
        self.host_registrar = host_registrar or NullHostRegistrar()
        self._registrar_available = bool(
            getattr(self.host_registrar, "available", True)
            and hasattr(self.host_registrar, "register_skill")
            and hasattr(self.host_registrar, "register_blueprint")
        )

    # ------------------------------------------------------------------
    # Artifact location and read models
    # ------------------------------------------------------------------
    @property
    def artifact_root(self) -> Path:
        configured = str(self.config.hephaestus_artifact_dir or "").strip()
        if configured:
            path = Path(configured).expanduser()
            if not path.is_absolute():
                path = self._base_artifact_dir / path
        else:
            path = self._base_artifact_dir
        return path.resolve()

    def read_model(self) -> dict[str, Any]:
        leases = self.store.list_safety_leases(limit=200)
        lease_jobs = {
            str(item.get("id")): item.get("cron_job_id") for item in leases
        }
        playbooks = []
        for item in self.store.list_playbooks(limit=200):
            summary = self._playbook_summary(item)
            summary["cron_job_id"] = lease_jobs.get(str(summary.get("lease_id") or ""))
            playbooks.append(summary)
        usage = self.store.list_lease_usage(limit=100)
        counts = self.store.hephaestus_counts()
        return {
            "ok": True,
            "counts": counts,
            "playbooks": playbooks,
            "leases": leases,
            "usage": usage,
            "attack_lab": self.store.last_attack_lab(suite="hephaestus"),
            "safety": {
                "cron_enforcement": bool(self.config.hephaestus_cron_enforce),
                "default_lease_minutes": self.config.hephaestus_lease_minutes,
                "max_lease_days": self.config.hephaestus_max_lease_days,
                "artifact_root": str(self.artifact_root),
                "note": (
                    "Leases are bounded guardrails for unattended Cron runs. They "
                    "never grant approval; Tripwire and the host remain authoritative."
                ),
            },
        }

    @staticmethod
    def _playbook_summary(item: dict[str, Any]) -> dict[str, Any]:
        blueprint = item.get("blueprint") or {}
        return {
            "id": item.get("id"),
            "slug": item.get("slug"),
            "name": item.get("name"),
            "version": item.get("version"),
            "description": item.get("description"),
            "status": item.get("status"),
            "source_session_id": item.get("source_session_id"),
            "source_task_id": item.get("source_task_id"),
            "confidence": item.get("confidence"),
            "confidence_percent": int(round(float(item.get("confidence") or 0.0) * 100)),
            "steps_attempted": item.get("steps_attempted"),
            "steps_succeeded": item.get("steps_succeeded"),
            "trace_hash": item.get("trace_hash"),
            "skill_path": item.get("skill_path"),
            "blueprint_key": item.get("blueprint_key"),
            "blueprint_title": blueprint.get("title") if isinstance(blueprint, dict) else None,
            "lease_id": item.get("lease_id"),
            "quarantine_reason": item.get("quarantine_reason"),
            "created_at": item.get("created_at"),
            "updated_at": item.get("updated_at"),
        }

    def playbook(self, playbook_id: str) -> dict[str, Any] | None:
        return self.store.get_playbook(playbook_id)

    def list_playbooks(self, *, status: str | None = None) -> list[dict[str, Any]]:
        return [self._playbook_summary(item) for item in self.store.list_playbooks(status=status, limit=500)]

    def list_leases(self, *, status: str | None = None) -> list[dict[str, Any]]:
        return self.store.list_safety_leases(status=status, limit=500)

    # ------------------------------------------------------------------
    # Trace distillation
    # ------------------------------------------------------------------
    def distill(self, session_id: str, *, events: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        session_id = str(session_id or "").strip()
        if not session_id:
            raise ValueError("An explicit session_id is required for trace distillation.")
        rows = (
            events
            if events is not None
            else self.store.list_session_events(
                session_id, limit=self.config.hephaestus_max_trace_events
            )
        )
        result = self._distill_events(session_id, rows)
        return result

    def _distill_events(
        self, session_id: str, rows: list[dict[str, Any]]
    ) -> dict[str, Any]:
        events = [item for item in rows if isinstance(item, dict)]
        result_call_ids: set[str] = set()
        drift_call_ids: set[str] = set()
        for event in events:
            details = _as_dict(event.get("details"))
            call_id = str(event.get("tool_call_id") or "")
            event_type = str(event.get("event_type") or "")
            if event_type == "tool_result_observed" and call_id:
                result_call_ids.add(call_id)
            if event_type in {"drift.flagged", "telos.drift_flagged"} and call_id:
                drift_call_ids.add(call_id)

        attempts: list[dict[str, Any]] = []
        for event in events:
            event_type = str(event.get("event_type") or "")
            details = _as_dict(event.get("details"))
            call_id = str(event.get("tool_call_id") or "")
            if event_type == "tool_result_observed":
                tool_name = str(details.get("tool_name") or "unknown")
                params = details.get("args_preview")
                if not isinstance(params, (dict, list)):
                    params = {}
                status = str(details.get("status") or "completed")
                if call_id in drift_call_ids:
                    status = "drift"
                success = _is_success(status, details.get("error_type"))
                attempts.append(
                    {
                        "tool_name": tool_name,
                        "tool_call_id": call_id or None,
                        "params_preview": params,
                        "status": status,
                        "success": success,
                        "trust_label": str(event.get("trust_label") or "UNKNOWN"),
                        "source_ref": event.get("source_ref"),
                        "result_hash": details.get("result_hash"),
                        "reason": details.get("reason") or details.get("error_type") or "",
                        "dedup_key": _dedup_key(tool_name, params),
                        "timestamp_utc": event.get("timestamp_utc"),
                    }
                )
            elif event_type == "action_blocked":
                if call_id and call_id in result_call_ids:
                    continue
                tool_name = str(
                    details.get("tool_name")
                    or str(event.get("summary") or "").split(":", 1)[0]
                    or "unknown"
                )
                params = details.get("args_preview")
                if not isinstance(params, (dict, list)):
                    params = {}
                attempts.append(
                    {
                        "tool_name": tool_name,
                        "tool_call_id": call_id or None,
                        "params_preview": params,
                        "status": "blocked",
                        "success": False,
                        "trust_label": str(event.get("trust_label") or "UNKNOWN"),
                        "source_ref": event.get("source_ref"),
                        "result_hash": None,
                        "reason": details.get("rule_key") or details.get("reason") or "blocked",
                        "dedup_key": _dedup_key(tool_name, params),
                        "timestamp_utc": event.get("timestamp_utc"),
                    }
                )

        steps: list[dict[str, Any]] = []
        seen_success: set[str] = set()
        anti: dict[str, dict[str, Any]] = {}
        for attempt in attempts:
            key = str(attempt["dedup_key"])
            if attempt.get("success"):
                if key in seen_success:
                    continue
                seen_success.add(key)
                steps.append(
                    {
                        "tool_name": attempt["tool_name"],
                        "params_preview": attempt["params_preview"],
                        "status": attempt["status"],
                        "trust_label": attempt["trust_label"],
                        "source_ref": attempt.get("source_ref"),
                        "result_hash": attempt.get("result_hash"),
                        "tool_call_id": attempt.get("tool_call_id"),
                        "dedup_key": key,
                    }
                )
            else:
                current = anti.get(key)
                if current is None:
                    anti[key] = {
                        "tool_name": attempt["tool_name"],
                        "params_preview": attempt["params_preview"],
                        "status": attempt["status"],
                        "reason": truncate(str(attempt.get("reason") or ""), 400),
                        "count": 1,
                        "first_seen": attempt.get("timestamp_utc"),
                    }
                else:
                    current["count"] = int(current.get("count") or 0) + 1
                    current["status"] = attempt["status"]
                    current["reason"] = truncate(
                        str(attempt.get("reason") or current.get("reason") or ""), 400
                    )

        steps = steps[: self.config.hephaestus_max_steps]
        anti_patterns = sorted(
            anti.values(), key=lambda item: int(item.get("count") or 0), reverse=True
        )[:20]
        trust_counts: dict[str, int] = {}
        for attempt in attempts:
            label = str(attempt.get("trust_label") or "UNKNOWN")
            trust_counts[label] = trust_counts.get(label, 0) + 1
        untrusted_steps = sum(
            1 for step in steps if step.get("trust_label") == "UNTRUSTED_EXTERNAL"
        )
        trusted_steps = len(steps) - untrusted_steps
        attempts_total = len(attempts)
        confidence = (len(steps) / attempts_total) if attempts_total else 0.0
        trace_hash = stable_hash(
            {
                "session_id": session_id,
                "steps": [
                    {
                        "tool_name": step.get("tool_name"),
                        "dedup_key": step.get("dedup_key"),
                        "status": step.get("status"),
                    }
                    for step in steps
                ],
                "anti_patterns": anti_patterns,
            }
        )
        warnings: list[str] = []
        if not steps:
            warnings.append("No successful tool step was found in this session.")
        if attempts_total and confidence < self.config.hephaestus_min_confidence:
            warnings.append(
                f"Confidence {confidence:.2f} is below the configured minimum "
                f"{self.config.hephaestus_min_confidence:.2f}."
            )
        if untrusted_steps:
            warnings.append(
                f"{untrusted_steps} successful step(s) came from untrusted external "
                "content and are excluded from the skill instructions."
            )
        if drift_call_ids:
            warnings.append("Telos drift was observed; drift-marked calls are excluded as failures.")
        event_ids = [int(event.get("id") or 0) for event in events if event.get("id")]
        return {
            "ok": True,
            "session_id": session_id,
            "task_id": next(
                (
                    str(event.get("task_id"))
                    for event in reversed(events)
                    if event.get("task_id")
                ),
                None,
            ),
            "event_count": len(events),
            "event_start": min(event_ids) if event_ids else None,
            "event_end": max(event_ids) if event_ids else None,
            "steps_attempted": attempts_total,
            "steps_succeeded": len(steps),
            "confidence": confidence,
            "confidence_percent": int(round(confidence * 100)),
            "trace_hash": trace_hash,
            "steps": steps,
            "anti_patterns": anti_patterns,
            "attempts": attempts[:200],
            "attempts_truncated": max(0, attempts_total - 200),
            "trust_counts": trust_counts,
            "untrusted_steps": untrusted_steps,
            "trusted_steps": trusted_steps,
            "drift_observed": bool(drift_call_ids),
            "warnings": warnings,
            "generated_at": utc_now_iso(),
        }

    # ------------------------------------------------------------------
    # Forge preview and confirmation
    # ------------------------------------------------------------------
    def _version_for_name(self, name: str) -> int:
        rows = self.store.list_playbooks(limit=500)
        target = _normal_text(name)
        return 1 + sum(1 for item in rows if _normal_text(item.get("name")) == target)

    def _slug_for(self, name: str, version: int) -> str:
        base = slugify(name)
        if version <= 1:
            candidate = base
        else:
            candidate = f"{base[:56]}-v{version}"
        existing = self.store.get_playbook_by_slug(candidate)
        if existing is None:
            return candidate
        return f"{base[:48]}-v{version}-{stable_hash({'name': name, 'version': version})[:6]}"

    def _lease_defaults(
        self,
        trace: dict[str, Any],
        *,
        allowed_tools: Any = None,
        allowed_paths: Any = None,
        allowed_domains: Any = None,
        allow_opaque_tools: bool = False,
        max_tool_calls: int | None = None,
        max_file_writes: int | None = None,
        max_external_calls: int | None = None,
        expires_at: str | None = None,
        ttl_minutes: int | None = None,
        cron_job_id: str | None = None,
    ) -> dict[str, Any]:
        step_tools = [
            str(step.get("tool_name"))
            for step in trace.get("steps") or []
            if isinstance(step, dict) and step.get("tool_name")
        ]
        tools = _string_list(allowed_tools) if allowed_tools else sorted(set(step_tools))
        if allowed_tools:
            unknown = sorted(set(tools) - set(step_tools))
            if unknown:
                raise ValueError(
                    "A lease cannot grant tools that were not successful in the trace: "
                    + ", ".join(unknown)
                )
        paths = _string_list(allowed_paths, limit=200)
        domains = _string_list(allowed_domains, lower=True, limit=200)
        minutes = _bounded_int(
            ttl_minutes,
            int(self.config.hephaestus_lease_minutes),
            5,
            int(self.config.hephaestus_max_lease_days) * 1440,
        )
        if expires_at:
            parsed = parse_utc(str(expires_at))
            if parsed is None:
                raise ValueError("expires_at must be an ISO-8601 UTC timestamp.")
            now = utc_now()
            if parsed <= now:
                raise ValueError("expires_at must be in the future.")
            if parsed > now + timedelta(days=self.config.hephaestus_max_lease_days):
                raise ValueError("expires_at exceeds the configured maximum lease duration.")
            expires = parsed.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        else:
            expires = (utc_now() + timedelta(minutes=minutes)).isoformat(
                timespec="milliseconds"
            ).replace("+00:00", "Z")
        return {
            "allowed_tools": tools,
            "allowed_paths": paths,
            "allowed_domains": domains,
            "allow_opaque_tools": bool(allow_opaque_tools),
            "max_tool_calls": _bounded_int(max_tool_calls, 200, 1, 10000),
            "max_file_writes": _bounded_int(max_file_writes, 50, 0, 5000),
            "max_external_calls": _bounded_int(max_external_calls, 50, 0, 5000),
            "expires_at": expires,
            "cron_job_id": str(cron_job_id or "").strip() or None,
            "environment_hash": environment_fingerprint(),
        }

    def _forge_assessment(
        self,
        trace: dict[str, Any],
        *,
        allow_untrusted: bool = False,
        force: bool = False,
    ) -> tuple[bool, list[str]]:
        warnings = list(trace.get("warnings") or [])
        steps = trace.get("steps") or []
        if not steps:
            warnings.append("Refusing to forge a skill with no successful step.")
            return False, warnings
        if trace.get("untrusted_steps") and not allow_untrusted:
            warnings.append(
                "The trace contains untrusted external successes. Re-run with "
                "allow_untrusted after reviewing them, or forge from a trusted session."
            )
            return False, warnings
        confidence = float(trace.get("confidence") or 0.0)
        if confidence < self.config.hephaestus_min_confidence and not force:
            warnings.append(
                "Confidence is below the configured minimum; pass force=true only "
                "after reviewing the trace manually."
            )
            return False, warnings
        return True, warnings

    def preview_forge(
        self,
        session_id: str,
        *,
        name: str = "",
        description: str = "",
        schedule: str = "0 9 * * *",
        allowed_tools: Any = None,
        allowed_paths: Any = None,
        allowed_domains: Any = None,
        allow_opaque_tools: bool = False,
        max_tool_calls: int | None = None,
        max_file_writes: int | None = None,
        max_external_calls: int | None = None,
        expires_at: str | None = None,
        ttl_minutes: int | None = None,
        cron_job_id: str | None = None,
        allow_untrusted: bool = False,
        force: bool = False,
    ) -> dict[str, Any]:
        trace = self.distill(session_id)
        can_forge, warnings = self._forge_assessment(
            trace, allow_untrusted=allow_untrusted, force=force
        )
        final_name = str(name or "").strip() or (
            f"Trace playbook {str(session_id)[:10]}"
        )
        version = self._version_for_name(final_name)
        slug = self._slug_for(final_name, version)
        safe_schedule = str(schedule or "0 9 * * *").strip()
        if "\n" in safe_schedule or "\r" in safe_schedule or len(safe_schedule) > 120:
            raise ValueError("schedule must be a single-line cron template.")
        lease_draft = self._lease_defaults(
            trace,
            allowed_tools=allowed_tools,
            allowed_paths=allowed_paths,
            allowed_domains=allowed_domains,
            allow_opaque_tools=allow_opaque_tools,
            max_tool_calls=max_tool_calls,
            max_file_writes=max_file_writes,
            max_external_calls=max_external_calls,
            expires_at=expires_at,
            ttl_minutes=ttl_minutes,
            cron_job_id=cron_job_id,
        )
        provisional = {
            "id": "preview",
            "slug": slug,
            "name": final_name,
            "version": version,
            "description": description,
            "status": "preview",
            "source_session_id": session_id,
            "source_task_id": trace.get("task_id"),
            "confidence": trace.get("confidence"),
            "steps_attempted": trace.get("steps_attempted"),
            "steps_succeeded": trace.get("steps_succeeded"),
            "trace_hash": trace.get("trace_hash"),
            "created_at": utc_now_iso(),
        }
        skill_markdown = render_skill_markdown(
            playbook=provisional, trace=trace, lease=lease_draft
        )
        host_skill_name = f"{PLUGIN_ID}:{slug}"
        blueprint = render_blueprint_spec(
            playbook=provisional,
            schedule_template=safe_schedule,
            skill_name=host_skill_name,
        )
        return {
            "ok": True,
            "status": "preview",
            "session_id": session_id,
            "trace": trace,
            "playbook": provisional,
            "skill": {
                "name": slug,
                "host_name": host_skill_name,
                "sha256": sha256_text(skill_markdown),
                "markdown": skill_markdown,
            },
            "blueprint": blueprint,
            "lease": lease_draft,
            "can_forge": can_forge,
            "confirmation_required": True,
            "warnings": warnings,
            "disclaimer": (
                "Preview only. No file, database row, host skill, blueprint, or lease "
                "was created. A successful trace is an observation, not proof that "
                "the same action is safe in another environment."
            ),
        }

    def forge(
        self,
        session_id: str,
        *,
        name: str = "",
        description: str = "",
        schedule: str = "0 9 * * *",
        allowed_tools: Any = None,
        allowed_paths: Any = None,
        allowed_domains: Any = None,
        allow_opaque_tools: bool = False,
        max_tool_calls: int | None = None,
        max_file_writes: int | None = None,
        max_external_calls: int | None = None,
        expires_at: str | None = None,
        ttl_minutes: int | None = None,
        cron_job_id: str | None = None,
        issue_lease: bool = True,
        allow_untrusted: bool = False,
        force: bool = False,
        confirm: bool = False,
    ) -> dict[str, Any]:
        if not confirm:
            preview = self.preview_forge(
                session_id,
                name=name,
                description=description,
                schedule=schedule,
                allowed_tools=allowed_tools,
                allowed_paths=allowed_paths,
                allowed_domains=allowed_domains,
                allow_opaque_tools=allow_opaque_tools,
                max_tool_calls=max_tool_calls,
                max_file_writes=max_file_writes,
                max_external_calls=max_external_calls,
                expires_at=expires_at,
                ttl_minutes=ttl_minutes,
                cron_job_id=cron_job_id,
                allow_untrusted=allow_untrusted,
                force=force,
            )
            preview["status"] = "confirmation_required"
            return preview
        preview = self.preview_forge(
            session_id,
            name=name,
            description=description,
            schedule=schedule,
            allowed_tools=allowed_tools,
            allowed_paths=allowed_paths,
            allowed_domains=allowed_domains,
            allow_opaque_tools=allow_opaque_tools,
            max_tool_calls=max_tool_calls,
            max_file_writes=max_file_writes,
            max_external_calls=max_external_calls,
            expires_at=expires_at,
            ttl_minutes=ttl_minutes,
            cron_job_id=cron_job_id,
            allow_untrusted=allow_untrusted,
            force=force,
        )
        if not preview.get("can_forge"):
            raise ValueError(
                "Forge refused: " + " ".join(preview.get("warnings") or ["trace is not eligible"])
            )
        trace = preview["trace"]
        provisional = preview["playbook"]
        lease_draft = preview["lease"]
        skill_markdown = preview["skill"]["markdown"]
        blueprint = preview["blueprint"]
        root = self.artifact_root
        directory = playbook_dir(root, provisional["slug"])
        playbook_id = new_id("play")
        provisional["id"] = playbook_id
        provisional["status"] = "forged"
        provisional["created_at"] = utc_now_iso()
        # Re-render after the durable id exists.  The preview necessarily used
        # the placeholder id; the registered blueprint and manifest must point
        # at the final playbook so quarantine and Cron matching can resolve it.
        blueprint = render_blueprint_spec(
            playbook=provisional,
            schedule_template=str(preview["blueprint"].get("schedule_template") or ""),
            skill_name=f"{PLUGIN_ID}:{provisional['slug']}",
        )
        skill_text = render_skill_markdown(
            playbook=provisional, trace=trace, lease=lease_draft
        )
        skill_sha = sha256_text(skill_text)
        manifest = render_manifest(
            playbook=provisional, skill_sha256=skill_sha, blueprint=blueprint
        )
        skill_path = directory / "SKILL.md"
        blueprint_path = directory / "blueprint.json"
        manifest_path = directory / "manifest.json"
        try:
            atomic_write_text(skill_path, skill_text)
            atomic_write_text(
                blueprint_path,
                json.dumps(blueprint, ensure_ascii=False, indent=2, sort_keys=True)
                + "\n",
            )
            atomic_write_text(
                manifest_path,
                json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True)
                + "\n",
            )
        except Exception:
            for path in (skill_path, blueprint_path, manifest_path):
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    pass
            raise
        try:
            playbook = self.store.create_playbook(
                playbook_id=playbook_id,
                slug=provisional["slug"],
                name=provisional["name"],
                version=int(provisional.get("version") or 1),
                description=provisional.get("description") or "",
                status="forged",
                source_session_id=session_id,
                source_task_id=trace.get("task_id"),
                source_event_start=trace.get("event_start"),
                source_event_end=trace.get("event_end"),
                confidence=float(trace.get("confidence") or 0.0),
                steps_attempted=int(trace.get("steps_attempted") or 0),
                steps_succeeded=int(trace.get("steps_succeeded") or 0),
                trace_hash=str(trace.get("trace_hash") or ""),
                trace=trace,
                skill_path=str(skill_path),
                skill_sha256=skill_sha,
                blueprint_key=blueprint.get("key"),
                blueprint=blueprint,
                environment_hash=environment_fingerprint(),
                metadata={
                    "warnings": preview.get("warnings") or [],
                    "trust_counts": trace.get("trust_counts") or {},
                    "untrusted_steps": trace.get("untrusted_steps") or 0,
                    "drift_observed": trace.get("drift_observed") or False,
                    "manifest_path": str(manifest_path),
                },
            )
        except Exception:
            for path in (skill_path, blueprint_path, manifest_path):
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    pass
            raise

        lease: dict[str, Any] | None = None
        if issue_lease:
            lease = self.issue_lease(
                playbook_id,
                allowed_tools=lease_draft["allowed_tools"],
                allowed_paths=lease_draft["allowed_paths"],
                allowed_domains=lease_draft["allowed_domains"],
                allow_opaque_tools=lease_draft["allow_opaque_tools"],
                max_tool_calls=lease_draft["max_tool_calls"],
                max_file_writes=lease_draft["max_file_writes"],
                max_external_calls=lease_draft["max_external_calls"],
                expires_at=lease_draft["expires_at"],
                cron_job_id=lease_draft["cron_job_id"],
                confirmed=True,
            )
        registration: dict[str, Any] = {
            "skill": {"ok": False, "error": "not attempted"},
            "blueprint": {"ok": False, "error": "not attempted"},
        }
        frontmatter = _skill_frontmatter(
            slug=str(provisional["slug"]),
            description=str(provisional.get("description") or ""),
            playbook_id=playbook_id,
            source_session_id=str(session_id or ""),
            source_task_id=str(trace.get("task_id") or ""),
            trace_hash=str(trace.get("trace_hash") or ""),
        )
        registration["skill"] = self.host_registrar.register_skill(
            provisional["slug"],
            skill_path,
            description=truncate(provisional["name"], 300),
            frontmatter=frontmatter,
        )
        if registration["skill"].get("ok"):
            registration["blueprint"] = self.host_registrar.register_blueprint(
                blueprint["key"], **self._blueprint_fields(blueprint)
            )
        else:
            registration["blueprint"] = {
                "ok": False,
                "error": "skipped because the skill registration failed",
            }
        registered = bool(registration["skill"].get("ok") and registration["blueprint"].get("ok"))
        status = "active" if registered else "forged"
        metadata = dict(playbook.get("metadata") or {})
        metadata["registration"] = registration
        playbook = self.store.update_playbook(
            playbook_id,
            status=status,
            lease_id=(lease or {}).get("id"),
            metadata=metadata,
        ) or playbook

        self.store.append_event(
            "playbook.forged",
            f"Hephaestus forged {playbook.get('name')} at {int(round(float(trace.get('confidence') or 0) * 100))}% confidence",
            session_id=session_id,
            details={
                "playbook_id": playbook_id,
                "slug": provisional["slug"],
                "confidence": trace.get("confidence"),
                "steps_attempted": trace.get("steps_attempted"),
                "steps_succeeded": trace.get("steps_succeeded"),
                "trace_hash": trace.get("trace_hash"),
                "status": status,
                "warnings": preview.get("warnings") or [],
            },
            idempotency_key=f"playbook-forged:{playbook_id}",
        )
        self.store.append_event(
            "skill.forged",
            f"Forged SKILL.md for {provisional['slug']}",
            session_id=session_id,
            details={
                "playbook_id": playbook_id,
                "skill_name": provisional["slug"],
                "host_name": f"{PLUGIN_ID}:{provisional['slug']}",
                "skill_path": str(skill_path),
                "sha256": skill_sha,
                "registered": bool(registration["skill"].get("ok")),
            },
            idempotency_key=f"skill-forged:{playbook_id}",
        )
        self.store.append_event(
            "blueprint.forged",
            f"Forged automation blueprint {blueprint['key']}",
            session_id=session_id,
            details={
                "playbook_id": playbook_id,
                "key": blueprint["key"],
                "host_key": f"{PLUGIN_ID}:{blueprint['key']}",
                "schedule_template": blueprint.get("schedule_template"),
                "registered": bool(registration["blueprint"].get("ok")),
            },
            idempotency_key=f"blueprint-forged:{playbook_id}",
        )
        return {
            "ok": True,
            "status": status,
            "playbook": playbook,
            "lease": lease,
            "skill": {
                "name": provisional["slug"],
                "host_name": f"{PLUGIN_ID}:{provisional['slug']}",
                "path": str(skill_path),
                "sha256": skill_sha,
            },
            "blueprint": {
                **blueprint,
                "host_key": f"{PLUGIN_ID}:{blueprint['key']}",
                "path": str(blueprint_path),
            },
            "registration": registration,
            "warnings": preview.get("warnings") or [],
            "disclaimer": (
                "Forged artifacts are plugin-generated records. Registration depends "
                "on host support and successful artifact checks. A safety lease does "
                "not grant approval and does not guarantee safe execution."
            ),
        }

    @staticmethod
    def _blueprint_fields(blueprint: dict[str, Any]) -> dict[str, Any]:
        return {
            name: blueprint.get(name)
            for name in (
                "title",
                "description",
                "schedule_template",
                "prompt_template",
                "category",
                "slots",
                "deliver_default",
                "skills",
                "tags",
            )
            if blueprint.get(name) is not None
        }

    # ------------------------------------------------------------------
    # Safety leases
    # ------------------------------------------------------------------
    def issue_lease(
        self,
        playbook_id: str,
        *,
        allowed_tools: Any = None,
        allowed_paths: Any = None,
        allowed_domains: Any = None,
        allow_opaque_tools: bool = False,
        max_tool_calls: int | None = None,
        max_file_writes: int | None = None,
        max_external_calls: int | None = None,
        expires_at: str | None = None,
        ttl_minutes: int | None = None,
        cron_job_id: str | None = None,
        issued_by: str = "user",
        confirmed: bool = False,
    ) -> dict[str, Any]:
        if not confirmed:
            raise ValueError("An explicit confirmation is required to issue a safety lease.")
        playbook = self.store.get_playbook(playbook_id)
        if playbook is None:
            raise ValueError("Playbook not found.")
        if str(playbook.get("status")) == "quarantined":
            raise ValueError("A quarantined playbook cannot receive a safety lease.")
        if self.store.active_lease_for_playbook(playbook_id) is not None:
            raise ValueError("This playbook already has an active safety lease. Revoke it first.")
        trace = playbook.get("trace") or {}
        draft = self._lease_defaults(
            trace,
            allowed_tools=allowed_tools,
            allowed_paths=allowed_paths,
            allowed_domains=allowed_domains,
            allow_opaque_tools=allow_opaque_tools,
            max_tool_calls=max_tool_calls,
            max_file_writes=max_file_writes,
            max_external_calls=max_external_calls,
            expires_at=expires_at,
            ttl_minutes=ttl_minutes,
            cron_job_id=cron_job_id,
        )
        if not draft["allowed_tools"]:
            raise ValueError("A safety lease must allow at least one verified tool.")
        lease_id = new_id("lease")
        lease_hash = stable_hash(
            {
                "playbook_id": playbook_id,
                "allowed_tools": draft["allowed_tools"],
                "allowed_paths": draft["allowed_paths"],
                "allowed_domains": draft["allowed_domains"],
                "allow_opaque_tools": draft["allow_opaque_tools"],
                "max_tool_calls": draft["max_tool_calls"],
                "max_file_writes": draft["max_file_writes"],
                "max_external_calls": draft["max_external_calls"],
                "expires_at": draft["expires_at"],
                "cron_job_id": draft["cron_job_id"],
                "environment_hash": draft["environment_hash"],
            }
        )
        lease = self.store.create_safety_lease(
            lease_id=lease_id,
            playbook_id=playbook_id,
            lease_hash=lease_hash,
            allowed_tools=draft["allowed_tools"],
            allowed_paths=draft["allowed_paths"],
            allowed_domains=draft["allowed_domains"],
            allow_opaque_tools=draft["allow_opaque_tools"],
            max_tool_calls=draft["max_tool_calls"],
            max_file_writes=draft["max_file_writes"],
            max_external_calls=draft["max_external_calls"],
            cron_job_id=draft["cron_job_id"],
            environment_hash=draft["environment_hash"],
            issued_by=issued_by,
            expires_at=draft["expires_at"],
            metadata={
                "playbook_slug": playbook.get("slug"),
                "source_session_id": playbook.get("source_session_id"),
            },
        )
        self.store.update_playbook(playbook_id, lease_id=lease_id)
        self.store.append_event(
            "lease.issued",
            f"Safety lease issued for {playbook.get('slug')}",
            details={
                "lease_id": lease_id,
                "playbook_id": playbook_id,
                "allowed_tools": draft["allowed_tools"],
                "allowed_paths": draft["allowed_paths"],
                "allowed_domains": draft["allowed_domains"],
                "allow_opaque_tools": draft["allow_opaque_tools"],
                "max_tool_calls": draft["max_tool_calls"],
                "max_file_writes": draft["max_file_writes"],
                "max_external_calls": draft["max_external_calls"],
                "expires_at": draft["expires_at"],
                "cron_job_id": draft["cron_job_id"],
            },
            idempotency_key=f"lease-issued:{lease_id}",
        )
        return lease

    def revoke_lease(
        self, lease_id: str, *, reason: str = "Revoked by user", confirmed: bool = False
    ) -> dict[str, Any]:
        if not confirmed:
            raise ValueError("An explicit confirmation is required to revoke a safety lease.")
        lease = self.store.get_safety_lease(lease_id)
        if lease is None:
            raise ValueError("Safety lease not found.")
        updated = self.store.revoke_safety_lease(lease_id, reason=reason)
        if updated is None:
            raise ValueError("Safety lease was not found.")
        self.store.append_event(
            "lease.revoked",
            f"Safety lease {lease_id} revoked",
            details={
                "lease_id": lease_id,
                "playbook_id": lease.get("playbook_id"),
                "reason": redact_text(reason, max_chars=500),
                "status": updated.get("status"),
            },
            idempotency_key=f"lease-revoked:{lease_id}:{updated.get('revoked_at')}",
        )
        return updated

    def quarantine_playbook(
        self,
        playbook_id: str,
        *,
        reason: str = "Quarantined by user",
        confirmed: bool = False,
    ) -> dict[str, Any]:
        if not confirmed:
            raise ValueError("An explicit confirmation is required to quarantine a playbook.")
        playbook = self.store.get_playbook(playbook_id)
        if playbook is None:
            raise ValueError("Playbook not found.")
        lease = self.store.active_lease_for_playbook(playbook_id)
        if lease is not None:
            self.revoke_lease(
                str(lease["id"]),
                reason=f"Playbook quarantined: {reason}",
                confirmed=True,
            )
        updated = self.store.update_playbook(
            playbook_id,
            status="quarantined",
            quarantine_reason=reason,
        )
        update_manifest_status(self.artifact_root, str(playbook.get("slug") or ""), "quarantined")
        self.store.append_event(
            "skill.quarantined",
            f"Hephaestus quarantined {playbook.get('slug')}",
            details={
                "playbook_id": playbook_id,
                "slug": playbook.get("slug"),
                "reason": redact_text(reason, max_chars=500),
                "lease_revoked": bool(lease),
                "note": (
                    "Quarantine blocks new leases and Cron lease checks. The host may "
                    "retain an already-loaded skill entry until the next plugin reload."
                ),
            },
            idempotency_key=f"skill-quarantined:{playbook_id}:{utc_now_iso()}",
        )
        return updated or playbook

    def unquarantine_playbook(
        self, playbook_id: str, *, confirmed: bool = False
    ) -> dict[str, Any]:
        if not confirmed:
            raise ValueError("An explicit confirmation is required to unquarantine a playbook.")
        playbook = self.store.get_playbook(playbook_id)
        if playbook is None:
            raise ValueError("Playbook not found.")
        if str(playbook.get("status")) != "quarantined":
            return playbook
        updated = self.store.update_playbook(playbook_id, status="forged")
        update_manifest_status(self.artifact_root, str(playbook.get("slug") or ""), "forged")
        self.store.append_event(
            "skill.unquarantined",
            f"Hephaestus unquarantined {playbook.get('slug')}",
            details={"playbook_id": playbook_id, "slug": playbook.get("slug")},
            idempotency_key=f"skill-unquarantined:{playbook_id}:{utc_now_iso()}",
        )
        return updated or playbook

    # ------------------------------------------------------------------
    # Runtime enforcement
    # ------------------------------------------------------------------
    def check_cron_tool(
        self,
        tool_name: str,
        args: Any,
        cron: Any,
        *,
        session_id: str | None = None,
        tool_call_id: str | None = None,
    ) -> dict[str, Any]:
        if not self.config.enable_hephaestus or not self.config.hephaestus_cron_enforce:
            return {"decision": "allow", "scope": "disabled", "rule_key": "hephaestus.disabled"}
        job_id = _cron_value(cron, "job_id")
        job_name = _cron_value(cron, "job_name")
        execution_id = _cron_value(cron, "execution_id")
        run_id = execution_id or "cron-" + stable_hash(
            {"job_id": job_id, "job_name": job_name, "started_at": _cron_value(cron, "started_at")}
        )[:24]
        lease = self._find_lease_for_cron(job_id=job_id, job_name=job_name)
        if lease is not None and str(lease.get("playbook_status") or "") == "quarantined":
            reason = (
                f"Playbook {lease.get('playbook_slug')} is quarantined. "
                "Unattended execution is blocked."
            )
            self._log_violation(
                str(lease.get("id")),
                str(lease.get("playbook_id")),
                run_id,
                job_id,
                job_name,
                tool_name,
                "hephaestus.lease.quarantined",
                reason,
                session_id,
                tool_call_id,
            )
            return {
                "decision": "block",
                "scope": "lease",
                "lease_id": str(lease.get("id")),
                "playbook_id": str(lease.get("playbook_id")),
                "run_id": run_id,
                "rule_key": "hephaestus.lease.quarantined",
                "reason": reason,
            }
        if lease is None:
            blocked = self._playbook_without_lease(job_id=job_id, job_name=job_name)
            if blocked is not None:
                reason = (
                    f"Playbook {blocked.get('slug')} is {blocked.get('status')} but has "
                    "no active safety lease. Unattended execution is blocked."
                )
                self._log_violation(
                    None,
                    blocked.get("id"),
                    run_id,
                    job_id,
                    job_name,
                    tool_name,
                    "hephaestus.lease.missing",
                    reason,
                    session_id,
                    tool_call_id,
                )
                return {
                    "decision": "block",
                    "scope": "lease",
                    "rule_key": "hephaestus.lease.missing",
                    "reason": reason,
                }
            return {
                "decision": "allow",
                "scope": "unscoped",
                "rule_key": "hephaestus.lease.unscoped",
                "reason": "No forged playbook matched this unattended job.",
            }
        lease_id = str(lease.get("id"))
        playbook_id = str(lease.get("playbook_id"))
        expires = parse_utc(str(lease.get("expires_at") or ""))
        if expires is not None and expires <= utc_now():
            self.store.expire_safety_lease(lease_id)
            reason = "The safety lease for this unattended job has expired."
            self._log_violation(
                lease_id,
                playbook_id,
                run_id,
                job_id,
                job_name,
                tool_name,
                "hephaestus.lease.expired",
                reason,
                session_id,
                tool_call_id,
            )
            return {
                "decision": "block",
                "scope": "lease",
                "lease_id": lease_id,
                "playbook_id": playbook_id,
                "run_id": run_id,
                "rule_key": "hephaestus.lease.expired",
                "reason": reason,
            }
        evaluation = evaluate_lease_request(
            allowed_tools=lease.get("allowed_tools") or [],
            allowed_paths=lease.get("allowed_paths") or [],
            allowed_domains=lease.get("allowed_domains") or [],
            allow_opaque_tools=bool(lease.get("allow_opaque_tools")),
            tool_name=tool_name,
            args=args,
            current_environment=environment_fingerprint(),
            expected_environment=str(lease.get("environment_hash") or ""),
        )
        if not evaluation.get("allowed"):
            reason = str(evaluation.get("reason") or "Safety lease scope violation.")
            self._log_violation(
                lease_id,
                playbook_id,
                run_id,
                job_id,
                job_name,
                tool_name,
                str(evaluation.get("rule_key") or "hephaestus.lease.violation"),
                reason,
                session_id,
                tool_call_id,
            )
            return {
                "decision": "block",
                "scope": "lease",
                "lease_id": lease_id,
                "playbook_id": playbook_id,
                "run_id": run_id,
                "rule_key": evaluation.get("rule_key"),
                "reason": reason,
            }
        consumed = self.store.consume_lease_usage(
            lease_id=lease_id,
            run_id=run_id,
            cron_job_id=job_id or None,
            tool_name=_normal_tool(tool_name),
            max_tool_calls=int(lease.get("max_tool_calls") or 200),
            max_file_writes=int(lease.get("max_file_writes") or 0),
            max_external_calls=int(lease.get("max_external_calls") or 0),
            file_write=bool(evaluation.get("file_write")),
            external=bool(evaluation.get("external")),
        )
        if not consumed.get("allowed"):
            reason = str(consumed.get("reason") or "Safety lease budget exceeded.")
            self._log_violation(
                lease_id,
                playbook_id,
                run_id,
                job_id,
                job_name,
                tool_name,
                "hephaestus.lease.budget",
                reason,
                session_id,
                tool_call_id,
            )
            return {
                "decision": "block",
                "scope": "lease",
                "lease_id": lease_id,
                "playbook_id": playbook_id,
                "run_id": run_id,
                "rule_key": "hephaestus.lease.budget",
                "reason": reason,
            }
        self._log_checked(
            lease_id,
            playbook_id,
            run_id,
            job_id,
            job_name,
            tool_name,
            "allow",
            "hephaestus.lease.allow",
            consumed.get("usage") or {},
            session_id,
            tool_call_id,
        )
        return {
            "decision": "allow",
            "scope": "lease",
            "lease_id": lease_id,
            "playbook_id": playbook_id,
            "run_id": run_id,
            "rule_key": "hephaestus.lease.allow",
            "usage": consumed.get("usage") or {},
        }

    def _find_lease_for_cron(
        self, *, job_id: str, job_name: str
    ) -> dict[str, Any] | None:
        rows = self.store.list_active_leases_with_playbooks(limit=500)
        if job_id:
            for row in rows:
                if str(row.get("cron_job_id") or "") == job_id:
                    return row
        normalized_job = f" {_normal_text(job_name)} "
        if not normalized_job.strip():
            return None
        candidates: list[tuple[int, dict[str, Any]]] = []
        for row in rows:
            slug = _normal_text(row.get("playbook_slug"))
            name = _normal_text(row.get("playbook_name"))
            score = 0
            if slug and f" {slug} " in normalized_job:
                score = max(score, 1000 + len(slug))
            if name and f" {name} " in normalized_job:
                score = max(score, 2000 + len(name))
            if slug and normalized_job.strip() == slug:
                score = max(score, 3000 + len(slug))
            if name and normalized_job.strip() == name:
                score = max(score, 4000 + len(name))
            if score:
                candidates.append((score, row))
        if not candidates:
            return None
        candidates.sort(key=lambda item: item[0], reverse=True)
        return candidates[0][1]

    def _playbook_without_lease(
        self, *, job_id: str = "", job_name: str = ""
    ) -> dict[str, Any] | None:
        # A revoked or expired lease still identifies the playbook bound to this
        # unattended job; losing the active lease must not silently unscope the job.
        if job_id:
            for lease in self.store.list_safety_leases(limit=500):
                if str(lease.get("cron_job_id") or "") != job_id:
                    continue
                playbook = self.store.get_playbook(str(lease.get("playbook_id") or ""))
                if playbook is not None:
                    return playbook
        normalized_job = f" {_normal_text(job_name)} "
        if not normalized_job.strip():
            return None
        best: tuple[int, dict[str, Any]] | None = None
        for playbook in self.store.list_playbooks(limit=500):
            slug = _normal_text(playbook.get("slug"))
            name = _normal_text(playbook.get("name"))
            score = 0
            if slug and f" {slug} " in normalized_job:
                score = max(score, 1000 + len(slug))
            if name and f" {name} " in normalized_job:
                score = max(score, 2000 + len(name))
            if score and (best is None or score > best[0]):
                best = (score, playbook)
        return best[1] if best else None

    def _log_checked(
        self,
        lease_id: str,
        playbook_id: str,
        run_id: str,
        job_id: str,
        job_name: str,
        tool_name: str,
        decision: str,
        rule_key: str,
        usage: dict[str, Any],
        session_id: str | None,
        tool_call_id: str | None,
    ) -> None:
        self.store.append_event(
            "lease.checked",
            f"Lease checked: {_normal_tool(tool_name)} {decision}",
            session_id=session_id,
            tool_call_id=tool_call_id,
            details={
                "lease_id": lease_id,
                "playbook_id": playbook_id,
                "run_id": run_id,
                "job_id": job_id,
                "job_name": truncate(job_name, 160),
                "tool_name": _normal_tool(tool_name),
                "decision": decision,
                "rule_key": rule_key,
                "usage": {
                    "tool_calls": usage.get("tool_calls"),
                    "file_writes": usage.get("file_writes"),
                    "external_calls": usage.get("external_calls"),
                },
            },
            idempotency_key=(
                f"lease-check:{lease_id}:{run_id}:"
                f"{stable_hash({'tool': tool_name, 'call': tool_call_id or '', 'decision': decision})[:20]}"
            ),
        )

    def _log_violation(
        self,
        lease_id: str | None,
        playbook_id: str | None,
        run_id: str,
        job_id: str,
        job_name: str,
        tool_name: str,
        rule_key: str,
        reason: str,
        session_id: str | None,
        tool_call_id: str | None,
    ) -> None:
        self.store.append_event(
            "lease.violation",
            f"Lease violation: {_normal_tool(tool_name)} ({rule_key})",
            session_id=session_id,
            tool_call_id=tool_call_id,
            details={
                "lease_id": lease_id,
                "playbook_id": playbook_id,
                "run_id": run_id,
                "job_id": job_id,
                "job_name": truncate(job_name, 160),
                "tool_name": _normal_tool(tool_name),
                "rule_key": rule_key,
                "reason": truncate(reason, 600),
            },
            idempotency_key=(
                f"lease-violation:{lease_id or 'none'}:{run_id}:"
                f"{stable_hash({'tool': tool_name, 'rule': rule_key, 'call': tool_call_id or ''})[:20]}"
            ),
        )

    def skill_write_check(
        self,
        tool_name: str,
        args: Any,
        *,
        session_id: str | None = None,
        tool_call_id: str | None = None,
    ) -> dict[str, Any]:
        if not self.config.enable_hephaestus or not self.config.hephaestus_quarantine_untrusted_skill_writes:
            return {"allowed": True, "rule_key": "hephaestus.skill.disabled"}
        normalized = _normal_tool(tool_name)
        if normalized not in SKILL_WRITE_TOOLS:
            return {"allowed": True, "rule_key": "hephaestus.skill.not_a_skill_write"}
        refs = _path_refs(args)
        targets_skill = normalized == "skill_manage"
        for path in refs:
            lowered = path.replace("\\", "/").casefold()
            if (
                "/.hermes/skills/" in lowered
                or lowered.endswith("/skills/skill.md")
                or lowered.endswith("skill.md")
                or "/plugins/" in lowered and "/skills/" in lowered
            ):
                targets_skill = True
        if not targets_skill:
            return {"allowed": True, "rule_key": "hephaestus.skill.not_a_skill_path"}
        if not session_id:
            return {"allowed": True, "rule_key": "hephaestus.skill.no_session"}
        source = self.store.latest_source_for_session(
            session_id,
            window_minutes=self.config.context_trust_window_minutes,
            trust_label="UNTRUSTED_EXTERNAL",
        )
        if source is None:
            return {"allowed": True, "rule_key": "hephaestus.skill.trusted_context"}
        reason = (
            "A skill was being written while this session still contains source-labelled "
            "untrusted external content. Hephaestus quarantined the write for review."
        )
        self.store.append_event(
            "skill.quarantined",
            f"Skill write quarantined for {normalized}",
            session_id=session_id,
            tool_call_id=tool_call_id,
            source_ref=source.get("id"),
            details={
                "tool_name": normalized,
                "rule_key": "hephaestus.skill.untrusted_write",
                "reason": reason,
                "source_ref": source.get("id"),
                "source_tool": source.get("tool_name"),
            },
            idempotency_key=(
                f"skill-write-quarantine:{session_id}:"
                f"{stable_hash({'tool': normalized, 'call': tool_call_id or ''})[:20]}"
            ),
        )
        return {
            "allowed": False,
            "rule_key": "hephaestus.skill.untrusted_write",
            "reason": reason,
        }

    def quarantined_artifact_check(
        self,
        tool_name: str,
        args: Any,
        *,
        session_id: str | None = None,
        tool_call_id: str | None = None,
    ) -> dict[str, Any]:
        """Block consumption of a quarantined artifact through host tools.

        Hermes v0.22.2 exposes no plugin API for unregistering a skill or
        blueprint that is already present in the host registry.  This additive
        enforcement point blocks the normal model-facing consumption paths:
        ``skill_view`` for a quarantined forged skill, and ``cronjob_manage``
        create/update/resume/run actions that reference a quarantined playbook
        or one of its Cron jobs.  The host registry entry itself is left in
        place; the Console documents that limitation.
        """

        if not self.config.enable_hephaestus:
            return {"decision": "allow", "rule_key": "hephaestus.artifact.disabled"}
        quarantined = self.store.list_playbooks(status="quarantined", limit=500)
        if not quarantined:
            return {"decision": "allow", "rule_key": "hephaestus.artifact.none"}

        normalized = _normal_tool(tool_name)
        payload = _as_dict(args)
        matched: dict[str, Any] | None = None
        matched_reason = ""

        if normalized == "skill_view":
            requested = str(payload.get("name") or "").strip()
            for row in quarantined:
                slug = str(row.get("slug") or "")
                qualified = f"{PLUGIN_ID}:{slug}".casefold()
                if requested.casefold() == qualified:
                    matched = row
                    matched_reason = (
                        f"Skill {qualified} belongs to a quarantined Hephaestus playbook."
                    )
                    break

        if normalized in {"cronjob_manage", "cronjob"}:
            action = _normal_tool(payload.get("action"))
            job_id = str(payload.get("job_id") or "").strip()
            rendered = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str).casefold()
            for row in quarantined:
                playbook_id = str(row.get("id") or "")
                slug = str(row.get("slug") or "")
                markers = [
                    f"continuum-playbook:{playbook_id}".casefold(),
                    f"{PLUGIN_ID}:{slug}".casefold(),
                ]
                if action in {"create", "add", "update", "edit", "resume", "run"} and any(
                    marker and marker in rendered for marker in markers
                ):
                    matched = row
                    matched_reason = (
                        "Cron action references a quarantined Hephaestus playbook or skill."
                    )
                    break
                if job_id and action in {"resume", "run", "update", "edit"}:
                    leases = self.store.list_safety_leases(
                        playbook_id=playbook_id, limit=200
                    )
                    if any(str(lease.get("cron_job_id") or "") == job_id for lease in leases):
                        matched = row
                        matched_reason = (
                            "Cron job is bound to a quarantined Hephaestus playbook."
                        )
                        break

        if matched is None:
            return {"decision": "allow", "rule_key": "hephaestus.artifact.allowed"}

        reason = truncate(matched_reason, 600)
        self.store.append_event(
            "action_blocked",
            f"Hephaestus blocked a quarantined artifact use: {normalized}",
            session_id=session_id,
            tool_call_id=tool_call_id,
            details={
                "playbook_id": matched.get("id"),
                "slug": matched.get("slug"),
                "tool_name": normalized,
                "rule_key": "hephaestus.artifact.quarantined",
                "reason": reason,
            },
            idempotency_key=(
                f"quarantined-artifact:{matched.get('id')}:{normalized}:"
                f"{stable_hash({'args': payload, 'call': tool_call_id or ''})[:20]}"
            ),
        )
        return {
            "decision": "block",
            "rule_key": "hephaestus.artifact.quarantined",
            "reason": reason,
            "playbook_id": matched.get("id"),
            "slug": matched.get("slug"),
        }

    # ------------------------------------------------------------------
    # Attack Lab
    # ------------------------------------------------------------------
    def run_attack_lab(self) -> dict[str, Any]:
        from .attack_lab import run_hephaestus_attack_lab

        results = run_hephaestus_attack_lab()
        record = self.store.record_attack_lab(
            policy_version=f"{POLICY_VERSION}+hephaestus",
            results=results,
            suite="hephaestus",
        )
        return {
            "ok": True,
            "status": "completed",
            "suite": "hephaestus",
            "run": record,
            "results": results,
            "passed": record["passed"],
            "total": record["total"],
            "disclaimer": (
                "Deterministic synthetic cases only. They exercise Hephaestus scope, "
                "budget, environment, and poisoning checks without executing tools or "
                "providing a general prompt-injection guarantee."
            ),
        }

    # ------------------------------------------------------------------
    # Load-time registration
    # ------------------------------------------------------------------
    def rehydrate(self) -> dict[str, Any]:
        if not self.config.enable_hephaestus:
            return {"skills": 0, "blueprints": 0, "skipped": 0, "errors": []}
        playbooks = self.store.list_playbooks(limit=500)
        quarantined = {
            str(item.get("slug") or "")
            for item in playbooks
            if str(item.get("status")) == "quarantined"
        }
        allowed_playbooks = {
            str(item.get("id")): str(item.get("status"))
            for item in playbooks
            if str(item.get("status")) in {"forged", "active"}
        }
        return rehydrate_artifacts(
            self.artifact_root,
            self.host_registrar,
            excluded_slugs=quarantined,
            allowed_playbooks=allowed_playbooks,
        )
