"""Moirai: deterministic, side-effect-free impact previews.

A preview describes what a proposed action would plausibly touch.  It never
executes the action, never connects to an external service, and never reads file
contents.  The three levels are deliberate:

* ``VERIFIED PREVIEW`` - the local file operation is understood.
* ``PARTIAL PREVIEW`` - the request shape is known, but remote or row-level
  consequences cannot be verified without executing it.
* ``UNSUPPORTED PREVIEW`` - the tool's effects cannot be safely predicted.

Tripwire and the host approval flow remain the only authorization mechanisms.
"""

from __future__ import annotations

import json
import os
import re
import shlex
from pathlib import Path
from typing import Any, Iterable

from ..common.config import ContinuumConfig
from ..common.ids import new_id, stable_hash
from ..common.redaction import json_preview, redact_mapping, redact_text, truncate
from ..spine.store import SpineStore

VERIFIED = "VERIFIED PREVIEW"
PARTIAL = "PARTIAL PREVIEW"
UNSUPPORTED = "UNSUPPORTED PREVIEW"

_READ_ONLY_TOOLS = re.compile(
    r"(?i)^(?:read|get|list|search|find|fetch|query|status|inspect|show|view|"
    r"recall|memory_review|dream|checkpoint_preview|browser_read|web_search)"
    r"(?:_[a-z0-9]+)*$"
)
_MUTATING_NAME = re.compile(
    r"(?i)(?:write|append|delete|remove|edit|patch|replace|create|update|"
    r"send|upload|move|rename|copy|execute|run|terminal|shell|drop|alter)"
)
_FILE_WRITE = re.compile(r"(?i)(?:^|_)(?:write|append|save|create|edit|patch|replace|truncate)(?:_|$)")
_FILE_DELETE = re.compile(r"(?i)(?:^|_)(?:delete|remove|erase)(?:_|$)")
_FILE_MOVE = re.compile(r"(?i)(?:^|_)(?:move|rename)(?:_|$)")
_FILE_COPY = re.compile(r"(?i)(?:^|_)(?:copy|duplicate)(?:_|$)")
_EXTERNAL = re.compile(
    r"(?i)(?:send|email|message|notify|publish|deploy|upload|webhook|slack|"
    r"discord|telegram|http|api|post|put|request|browser_exec|push|"
    r"create_issue|create_pr|pull_request|git_push)"
)
_DATABASE = re.compile(r"(?i)(?:database|db_|sql|postgres|mysql|sqlite|mongo|query|execute)")
_MUTATING_SQL = re.compile(r"(?i)^\s*(?:insert|update|delete|replace|alter|drop|create|truncate|grant|revoke)\b")
_READ_SQL = re.compile(r"(?i)^\s*(?:select|pragma|explain|with|show|describe)\b")
_EXTERNAL_TARGET_KEYS = (
    "url",
    "endpoint",
    "recipient",
    "recipients",
    "to",
    "channel",
    "webhook",
    "host",
    "repo",
    "repository",
)
_PATH_KEYS = (
    "path",
    "file_path",
    "filename",
    "file",
    "destination",
    "dest",
    "target",
    "source",
    "src",
)
_CONTENT_KEYS = ("content", "text", "data", "body", "new_text", "patch")
_SHELL_WRITE = re.compile(
    r"(?i)\b(?:rm|del|erase|rmdir|move|mv|copy|cp|rename|mkdir|md|"
    r"set-content|add-content|out-file|tee|new-item|remove-item|move-item|copy-item)\b"
)


class MoiraiService:
    def __init__(
        self,
        store: SpineStore,
        config: ContinuumConfig | None = None,
        *,
        aletheia: Any = None,
    ):
        self.store = store
        self.config = (config or ContinuumConfig()).clamped()
        self.aletheia = aletheia

    def preview(
        self,
        tool_name: str,
        args: Any,
        *,
        session_id: str | None = None,
        task_id: str | None = None,
        action_ref: str | None = None,
        source_ref: str | None = None,
        trust_label: str = "UNKNOWN",
    ) -> dict[str, Any]:
        name = str(tool_name or "").strip()
        if not name:
            raise ValueError("A tool name is required for an impact preview.")
        target_map = args if isinstance(args, dict) else {}
        level, category, proposed, targets, creates, modifies, deletes, external, irreversible, unknowns, confidence, adapter = self._predict(
            name, args, target_map
        )
        payload_summary = self._payload_summary(args)
        evidence = self._evidence_for_targets(targets)
        preview_id = new_id("prev")
        event_id: str | None = None
        if action_ref:
            event_id = self.store.append_event(
                _event_for_level(level),
                f"Impact preview {level}: {truncate(proposed, 220)}",
                session_id=session_id,
                task_id=task_id,
                tool_call_id=action_ref if action_ref.startswith("call") else None,
                source_ref=source_ref,
                trust_label=trust_label,
                details={
                    "preview_id": preview_id,
                    "tool_name": name,
                    "level": level,
                    "target_count": len(targets),
                    "external_count": len(external),
                    "unknown_count": len(unknowns),
                },
                idempotency_key=f"moirai-preview:{action_ref}",
            )
        else:
            event_id = self.store.append_event(
                _event_for_level(level),
                f"Impact preview {level}: {truncate(proposed, 220)}",
                session_id=session_id,
                task_id=task_id,
                source_ref=source_ref,
                trust_label=trust_label,
                details={
                    "preview_id": preview_id,
                    "tool_name": name,
                    "level": level,
                    "target_count": len(targets),
                    "external_count": len(external),
                    "unknown_count": len(unknowns),
                },
            )
        preview = self.store.record_impact_preview(
            preview_id=preview_id,
            event_id=event_id,
            session_id=session_id,
            task_id=task_id,
            tool_name=name,
            action_category=category,
            level=level,
            proposed_action=proposed,
            targets=targets,
            creates=creates,
            modifies=modifies,
            deletes=deletes,
            external=external,
            payload_summary=payload_summary,
            irreversible=irreversible,
            unknowns=unknowns,
            confidence=confidence,
            adapter=adapter,
            evidence=evidence,
        )
        preview["summary"] = self.summary(preview)
        return preview

    def _predict(
        self, name: str, args: Any, target_map: dict[str, Any]
    ) -> tuple[
        str,
        str,
        str,
        list[dict[str, Any]],
        list[dict[str, Any]],
        list[dict[str, Any]],
        list[dict[str, Any]],
        list[dict[str, Any]],
        list[dict[str, Any]],
        list[str],
        float,
        str,
    ]:
        empty: list[dict[str, Any]] = []
        if _READ_ONLY_TOOLS.search(name) and not _MUTATING_NAME.search(name):
            return (
                VERIFIED,
                "read_only",
                f"{name} is classified as read-only; no local mutation is expected.",
                empty,
                empty,
                empty,
                empty,
                empty,
                empty,
                [],
                0.8,
                "read_only",
            )
        # ``execute`` is a shell tool even though its name also contains a word
        # matched by the database adapter.  Resolve shell names before the
        # broader database regex.
        if _shell_tool(name):
            return self._shell_preview(name, args)
        if _DATABASE.search(name):
            sql = str(target_map.get("query") or target_map.get("sql") or target_map.get("statement") or "")
            target = _db_target(target_map)
            target_entry = {
                "kind": "database",
                "ref": redact_text(target, max_chars=300),
                "verified": False,
            }
            if _READ_SQL.search(sql):
                return (
                    VERIFIED,
                    "database_read",
                    f"{name} appears to run a read-only database query.",
                    [target_entry],
                    empty,
                    empty,
                    empty,
                    empty,
                    empty,
                    ["Row contents and remote database state were not inspected."],
                    0.55,
                    "database_shape",
                )
            if _MUTATING_SQL.search(sql):
                effect = _sql_effect(sql)
                no_where = re.search(r"(?i)^\s*(?:update|delete)\b", sql) and not re.search(r"(?i)\bwhere\b", sql)
                modifies = [{"kind": "database_rows", "ref": target, "operation": effect}]
                deletes = [{"kind": "database_rows", "ref": target, "operation": effect}] if effect in {"delete", "drop", "truncate"} else empty
                risks = ["exact rows affected, triggers, and remote state are unknown"]
                if no_where:
                    risks.append("the statement has no WHERE clause and may affect every row")
                    irreversible = [{"reason": "broad database mutation without a WHERE clause"}]
                else:
                    irreversible = empty
                return (
                    PARTIAL,
                    "database_write",
                    f"{name} would perform a database {effect}.",
                    [target_entry],
                    empty,
                    modifies,
                    deletes,
                    empty,
                    irreversible,
                    risks,
                    0.6 if not no_where else 0.75,
                    "database_shape",
                )
            return (
                UNSUPPORTED,
                "database_unknown",
                f"{name} proposes a database action whose statement or effect is unknown.",
                [target_entry],
                empty,
                empty,
                empty,
                empty,
                empty,
                ["The database tool's behavior cannot be classified safely."],
                0.2,
                "database_unknown",
            )
        if _EXTERNAL.search(name):
            return self._external_preview(name, target_map)
        if _FILE_WRITE.search(name) or _FILE_DELETE.search(name) or _FILE_MOVE.search(name) or _FILE_COPY.search(name):
            return self._file_preview(name, target_map)
        path = _first_path(target_map)
        if path:
            return self._file_preview("file_operation", target_map)
        return (
            UNSUPPORTED,
            "unknown",
            f"The effects of {name} cannot be predicted by a supported Moirai adapter.",
            empty,
            empty,
            empty,
            empty,
            empty,
            empty,
            ["Unsupported tool: the preview intentionally makes no claim about side effects."],
            0.1,
            "unsupported",
        )

    def _file_preview(
        self, name: str, target_map: dict[str, Any]
    ) -> tuple[Any, ...]:
        path = _first_path(target_map)
        if not path:
            return (
                UNSUPPORTED,
                "file_unknown",
                f"{name} looks like a file operation but no target path was supplied.",
                [],
                [],
                [],
                [],
                [],
                [],
                ["No target path could be identified."],
                0.2,
                "file",
            )
        target = _stat_target(path)
        if _FILE_DELETE.search(name):
            target_kind = "directory" if target.get("is_dir") else "file"
            deletes = [{"kind": target_kind, "ref": target["ref"], "exists": target.get("exists")}]
            irreversible = [{"reason": "deleted content may not be recoverable"}]
            unknowns = ["whether the target is a directory with nested content"] if target.get("is_dir") else []
            if not target.get("exists"):
                unknowns.append("the target does not currently exist")
            return (
                VERIFIED,
                "file_delete",
                f"Would delete {target['ref']}.",
                [target],
                [],
                [],
                deletes,
                [],
                irreversible,
                unknowns,
                0.85,
                "file",
            )
        if _FILE_MOVE.search(name):
            destination = _first_path(target_map, prefer=("destination", "dest", "target"))
            switches = [target]
            if destination:
                switches.append(_stat_target(destination))
            return (
                VERIFIED,
                "file_move",
                f"Would move or rename {target['ref']} to {destination or 'an unspecified destination'}.",
                switches,
                [{"kind": "path", "ref": destination, "exists": None}] if destination else [],
                [{"kind": "file", "ref": target["ref"]}],
                [{"kind": "file", "ref": target["ref"]}],
                [],
                [],
                ["The final destination state was not modified for the preview."],
                0.8,
                "file",
            )
        if _FILE_COPY.search(name):
            destination = _first_path(target_map, prefer=("destination", "dest", "target"))
            return (
                VERIFIED,
                "file_copy",
                f"Would copy {target['ref']} to {destination or 'an unspecified destination'}.",
                [target, _stat_target(destination)] if destination else [target],
                [{"kind": "path", "ref": destination, "exists": None}] if destination else [],
                [{"kind": "path", "ref": destination, "exists": None}] if destination else [],
                [],
                [],
                [],
                ["The final destination state was not modified for the preview."],
                0.75,
                "file",
            )
        content = _first_content(target_map)
        content_note = ""
        if content is not None:
            content_note = f" Content length: {len(str(content))} characters (content not stored in the preview)."
        creates = [{"kind": "file", "ref": target["ref"]}] if not target.get("exists") else []
        modifies = [{"kind": "file", "ref": target["ref"]}] if target.get("exists") else []
        return (
            VERIFIED,
            "file_write",
            f"Would write {target['ref']}.{content_note}",
            [target],
            creates,
            modifies,
            [],
            [],
            [],
            [] if target.get("exists") or target.get("parent_exists") else ["the parent directory is missing"],
            0.9 if target.get("parent_exists") else 0.55,
            "file",
        )

    def _external_preview(self, name: str, target_map: dict[str, Any]) -> tuple[Any, ...]:
        destinations: list[dict[str, Any]] = []
        for key in _EXTERNAL_TARGET_KEYS:
            value = target_map.get(key)
            if value in (None, "", []):
                continue
            if isinstance(value, (list, tuple, set)):
                for item in list(value)[:20]:
                    destinations.append({"kind": "external", "ref": truncate(str(item), 300)})
            else:
                destinations.append({"kind": "external", "ref": truncate(str(value), 300)})
        if not destinations:
            destinations = [{"kind": "external", "ref": "destination not explicit"}]
        unknown = [
            "Remote acceptance, delivery, and downstream effects cannot be verified without executing the action.",
            "Authentication, rate limits, and service state were not inspected.",
        ]
        return (
            PARTIAL,
            "external_action",
            f"{name} would contact an external system or recipient.",
            destinations,
            [],
            [],
            [],
            destinations,
            [{"reason": "external delivery generally cannot be undone"}],
            unknown,
            0.55,
            "external_shape",
        )

    def _shell_preview(self, name: str, args: Any) -> tuple[Any, ...]:
        command = str(args.get("command") or args.get("cmd") or "") if isinstance(args, dict) else str(args or "")
        if not command:
            return (
                UNSUPPORTED,
                "shell_unknown",
                "The shell action has no readable command.",
                [], [], [], [], [], [], ["The command could not be inspected."], 0.1, "shell_unknown",
            )
        if not _SHELL_WRITE.search(command) or re.search(r"(?i)[|&;><`$]|\\b(?:python|node|pwsh|powershell|bash|sh)\\b", command):
            return (
                UNSUPPORTED,
                "shell_complex",
                f"Shell command effects are not safely predictable: {truncate(command, 240)}",
                [], [], [], [], [], [],
                [
                    "This preview does not execute the command or infer script effects.",
                    "Shell pipelines, redirections, substitutions, and interpreters are unsupported.",
                ],
                0.1,
                "shell_shape",
            )
        try:
            tokens = shlex.split(command, posix=False)
        except ValueError:
            tokens = command.split()
        tokens = [token.strip("\"'") for token in tokens if token.strip("\"'")]
        recursive = any(
            token.lower() in {"-r", "-rf", "-fr", "-recurse", "/s", "/q", "--recursive"}
            for token in tokens
        )
        flag = re.compile(r"^(?:-{1,2}[A-Za-z][\w-]*|/[A-Za-z])$")
        paths = [token for token in tokens[1:] if not flag.match(token)]
        if not paths:
            paths = [token for token in tokens[1:] if not token.startswith("-")]
        if not paths:
            return (
                UNSUPPORTED,
                "shell_complex",
                f"Shell command targets are not explicit: {truncate(command, 240)}",
                [], [], [], [], [], [],
                ["The target path could not be identified."],
                0.2,
                "shell_shape",
            )
        targets = [_stat_target(item) for item in paths[:20]]
        deleting = any(token.lower() in {"rm", "del", "erase", "rmdir", "remove-item"} for token in tokens)
        deletes = [{"kind": target["kind"], "ref": target["ref"]} for target in targets] if deleting else []
        modifies = [] if deleting else [{"kind": target["kind"], "ref": target["ref"]} for target in targets]
        return (
            PARTIAL if recursive else VERIFIED,
            "shell_file_operation",
            f"Shell file operation: {truncate(command, 300)}",
            targets,
            [],
            modifies,
            deletes,
            [],
            [{"reason": "shell file operations can affect multiple paths"}] if recursive else [],
            ["Shell expansion and glob behavior may affect more paths than listed."] if recursive else [],
            0.65 if recursive else 0.55,
            "shell_shape",
        )

    def _payload_summary(self, args: Any) -> str:
        if not isinstance(args, dict):
            return f"Payload type: {type(args).__name__}."
        omitted = {
            "content",
            "text",
            "body",
            "data",
            "token",
            "secret",
            "password",
            "api_key",
        }
        summary: dict[str, Any] = {}
        for key, value in list(args.items())[:25]:
            if str(key).casefold() in omitted:
                continue
            if isinstance(value, str) and len(value) > 120:
                summary[str(key)] = f"{len(value)} chars"
            elif isinstance(value, (dict, list, tuple)):
                summary[str(key)] = json_preview(value, max_chars=400)
            else:
                summary[str(key)] = value
        return truncate(json.dumps(redact_mapping(summary), ensure_ascii=False, sort_keys=True, default=str), 1600)

    def _evidence_for_targets(self, targets: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
        if self.aletheia is None:
            return []
        evidence: list[dict[str, Any]] = []
        for target in list(targets)[:20]:
            ref = str(target.get("ref") or "")
            if not ref:
                continue
            for receipt in self.aletheia.list_receipts(artifact_ref=ref, limit=5):
                evidence.append(
                    {
                        "artifact_ref": ref,
                        "receipt_id": receipt.get("id"),
                        "status": receipt.get("status"),
                        "method": receipt.get("verification_method"),
                        "scope": receipt.get("scope"),
                    }
                )
        return evidence

    def summary(self, preview: dict[str, Any]) -> str:
        level = str(preview.get("level") or UNSUPPORTED)
        parts = [f"{level} ({preview.get('action_category') or 'unknown'})"]
        targets = preview.get("targets") or []
        if targets:
            parts.append("targets: " + ", ".join(str(item.get("ref")) for item in targets[:5]))
        for key, label in (("creates", "creates"), ("modifies", "modifies"), ("deletes", "deletes")):
            values = preview.get(key) or []
            if values:
                parts.append(f"{label} {len(values)}")
        external = preview.get("external") or []
        if external:
            parts.append(f"external contact: {len(external)}")
        unknowns = preview.get("unknowns") or []
        if unknowns:
            parts.append(f"unknown: {truncate(str(unknowns[0]), 180)}")
        return truncate("; ".join(parts), 1200)

    def list_previews(self, *, limit: int = 100) -> list[dict[str, Any]]:
        return self.store.list_impact_previews(limit=limit)

    def get_preview(self, preview_id: str) -> dict[str, Any] | None:
        return self.store.get_impact_preview(preview_id)


def _event_for_level(level: str) -> str:
    if level == VERIFIED:
        return "action.previewed"
    if level == PARTIAL:
        return "action.preview_limited"
    return "action.preview_unsupported"


def _shell_tool(name: str) -> bool:
    lowered = name.casefold()
    return lowered in {
        "terminal",
        "shell",
        "execute",
        "run_command",
        "bash",
        "powershell",
        "pwsh",
        "cmd",
    } or lowered.startswith("terminal")


def _first_path(target_map: dict[str, Any], *, prefer: tuple[str, ...] | None = None) -> str | None:
    keys = list(prefer or []) + list(_PATH_KEYS)
    for key in keys:
        value = target_map.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _first_content(target_map: dict[str, Any]) -> Any:
    for key in _CONTENT_KEYS:
        if key in target_map:
            return target_map[key]
    return None


def _stat_target(path: str | None) -> dict[str, Any]:
    if not path:
        return {"kind": "path", "ref": "", "exists": None}
    candidate = Path(str(path)).expanduser()
    result: dict[str, Any] = {
        "kind": "file",
        "ref": redact_text(str(candidate), max_chars=500),
        "exists": None,
        "parent_exists": candidate.parent.exists(),
    }
    try:
        exists = candidate.exists()
        result["exists"] = exists
        if exists:
            stat = candidate.stat()
            result["kind"] = "directory" if candidate.is_dir() else "file"
            result["size"] = int(stat.st_size)
            if candidate.is_dir():
                try:
                    with os.scandir(candidate) as entries:
                        count = 0
                        for _ in entries:
                            count += 1
                            if count >= 100:
                                break
                    result["direct_entries"] = count
                except OSError:
                    result["direct_entries"] = None
    except OSError:
        result["exists"] = None
    return result


def _db_target(target_map: dict[str, Any]) -> str:
    for key in ("database", "database_name", "db", "dsn", "connection", "table"):
        value = target_map.get(key)
        if value:
            return str(value)
    return "database target not explicit"


def _sql_effect(sql: str) -> str:
    match = re.match(r"(?i)^\s*([a-z]+)", sql)
    return match.group(1).lower() if match else "mutation"
