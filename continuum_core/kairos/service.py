"""Kairos: bounded, privacy-preserving environmental reality checks.

The fingerprint deliberately records hashes and small typed facts, never file
contents, credential values, or an unfiltered filesystem walk.  A diff is a
comparison of observations, not a promise that unobserved external systems are
unchanged; those conditions are reported as unverified.
"""

from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable

from ..common.config import ContinuumConfig
from ..common.ids import new_id, stable_hash
from ..common.redaction import redact_text, truncate
from ..common.time import utc_now_iso
from ..spine.store import SpineStore

_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "target",
    ".next",
    ".cache",
}
_SKIP_NAME_PARTS = (
    ".env",
    "credential",
    "secret",
    "private_key",
    "id_rsa",
    "id_ed25519",
    ".npmrc",
    ".pypirc",
    ".netrc",
    "auth.json",
    "keychain",
    "cookie",
    "token",
)
_CONFIG_NAMES = {
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "pyproject.toml",
    "requirements.txt",
    "requirements-dev.txt",
    "poetry.lock",
    "pipfile",
    "pipfile.lock",
    "setup.py",
    "setup.cfg",
    "tox.ini",
    "plugin.yaml",
    "dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "makefile",
    "tsconfig.json",
    "cargo.toml",
    "cargo.lock",
    "go.mod",
    "go.sum",
    "composer.json",
    "gemfile",
}
_TEXT_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".md",
    ".txt",
    ".csv",
    ".tsv",
    ".sql",
    ".html",
    ".css",
    ".sh",
    ".ps1",
    ".bat",
}
_SAFE_TOOL_NAMES = {
    "python",
    "python3",
    "node",
    "npm",
    "pnpm",
    "yarn",
    "git",
    "pytest",
    "docker",
    "kubectl",
    "terraform",
    "psql",
    "sqlite3",
    "curl",
    "wget",
    "pwsh",
    "powershell",
}


class KairosService:
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

    # ------------------------------------------------------------------
    # Fingerprint construction
    # ------------------------------------------------------------------
    def resolve_scope(self, scope: Path | str | None = None) -> Path:
        candidate = scope or self.config.kairos_scope or ""
        if not candidate:
            return Path.cwd().resolve()
        path = Path(candidate).expanduser()
        if not path.is_absolute():
            path = Path.cwd() / path
        return path.resolve()

    def build_fingerprint(
        self,
        *,
        scope: Path | str | None = None,
        paths: Iterable[Path | str] | None = None,
        required_tools: Iterable[str] | None = None,
        preconditions: dict[str, Any] | None = None,
        auto_discover: bool = True,
    ) -> dict[str, Any]:
        root = self.resolve_scope(scope)
        fingerprint: dict[str, Any] = {
            "format": "kairos-fingerprint/1",
            "captured_at": utc_now_iso(),
            "system": {
                "os": platform.system().lower() or sys.platform,
                "arch": platform.machine().lower(),
                "python_version": platform.python_version(),
                "python_implementation": platform.python_implementation(),
            },
            "workspace": {
                "root": str(root),
                "exists": root.is_dir(),
            },
            "installation_id": self.store.installation_id,
            "git": self._git_observation(root),
            "files": {},
            "tools": {},
            "preconditions": {},
            "unverified": [],
        }
        if not root.is_dir():
            fingerprint["unverified"].append(
                "The configured workspace does not exist, so file conditions could not be checked."
            )
        else:
            tracked = self._collect_files(root, paths=paths, auto_discover=auto_discover)
            fingerprint["files"] = self._hash_files(root, tracked)
            if len(tracked) >= self.config.kairos_max_files:
                fingerprint["unverified"].append(
                    f"File tracking was capped at {self.config.kairos_max_files} files."
                )
        fingerprint["tools"] = self._tool_observation(required_tools)
        fingerprint["preconditions"] = _safe_preconditions(preconditions or {})
        fingerprint["unverified"].extend(
            [
                "Arbitrary shell probes and network endpoints are not inspected.",
                "Process memory, open handles, and remote service state are not observable.",
            ]
        )
        return fingerprint

    def fingerprint_hash(self, fingerprint: dict[str, Any]) -> str:
        stable = dict(fingerprint)
        stable.pop("captured_at", None)
        return stable_hash(stable)

    def snapshot(
        self,
        *,
        scope: Path | str | None = None,
        paths: Iterable[Path | str] | None = None,
        required_tools: Iterable[str] | None = None,
        preconditions: dict[str, Any] | None = None,
        label: str = "",
        session_id: str | None = None,
        task_id: str | None = None,
        checkpoint_ref: str | None = None,
        auto_discover: bool = True,
    ) -> dict[str, Any]:
        fingerprint = self.build_fingerprint(
            scope=scope,
            paths=paths,
            required_tools=required_tools,
            preconditions=preconditions,
            auto_discover=auto_discover,
        )
        root = self.resolve_scope(scope)
        digest = self.fingerprint_hash(fingerprint)
        snapshot_id = new_id("env")
        event_id = self.store.append_event(
            "world.snapshotted",
            f"Environment snapshot {digest[:12]} ({len(fingerprint['files'])} files)",
            session_id=session_id,
            task_id=task_id,
            checkpoint_ref=checkpoint_ref,
            details={
                "snapshot_id": snapshot_id,
                "fingerprint_hash": digest,
                "scope": str(root),
                "file_count": len(fingerprint["files"]),
                "tool_count": len(fingerprint["tools"]),
                "label": label,
            },
            idempotency_key=(
                f"world-snapshot:{checkpoint_ref}:{digest}" if checkpoint_ref else None
            ),
        )
        record = self.store.record_kairos_snapshot(
            snapshot_id=snapshot_id,
            event_id=event_id,
            captured_at=fingerprint["captured_at"],
            scope_path=str(root),
            fingerprint_hash=digest,
            fingerprint=fingerprint,
            label=label,
            session_id=session_id,
            task_id=task_id,
            checkpoint_ref=checkpoint_ref,
            details={
                "required_tools": list(required_tools or self._configured_tools()),
                "preconditions": preconditions or {},
                "auto_discover": auto_discover,
            },
        )
        record["fingerprint"] = fingerprint
        return record

    # ------------------------------------------------------------------
    # Reality diff
    # ------------------------------------------------------------------
    def diff(
        self,
        snapshot_id: str | None = None,
        *,
        saved_fingerprint: dict[str, Any] | None = None,
        checkpoint_id: str | None = None,
        session_id: str | None = None,
        task_id: str | None = None,
        preconditions: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        snapshot = self.store.get_kairos_snapshot(snapshot_id) if snapshot_id else None
        if snapshot is None and saved_fingerprint is None:
            raise ValueError("A Kairos snapshot or saved fingerprint is required.")
        if saved_fingerprint is None:
            saved_fingerprint = (snapshot or {}).get("fingerprint") or {}
        if not isinstance(saved_fingerprint, dict) or not saved_fingerprint:
            raise ValueError("The saved environment fingerprint is unavailable.")
        details = (snapshot or {}).get("details") or {}
        scope = (snapshot or {}).get("scope_path") or saved_fingerprint.get("workspace", {}).get("root")
        tracked_paths = list((saved_fingerprint.get("files") or {}).keys())
        current = self.build_fingerprint(
            scope=scope,
            paths=tracked_paths,
            required_tools=details.get("required_tools") or self._configured_tools(),
            preconditions=(
                preconditions
                if preconditions is not None
                else details.get("preconditions") or {}
            ),
            auto_discover=False,
        )
        changed, unverified = self._compare(saved_fingerprint, current)
        # The fingerprint always carries baseline caveats (remote state, shell
        # probes).  Those are disclosed in ``unverified`` but do not by
        # themselves turn an otherwise unchanged observation AMBER.  Only new
        # unverified conditions, such as a newly unavailable workspace or a
        # capped file walk, affect the severity level.
        saved_unverified = set(saved_fingerprint.get("unverified") or [])
        new_unverified = [item for item in unverified if item not in saved_unverified]
        red = any(item["severity"] == "red" for item in changed)
        amber = bool(changed) or bool(new_unverified)
        level = "RED" if red else ("AMBER" if amber else "GREEN")
        if changed:
            summary = "; ".join(item["message"] for item in changed[:8])
        elif new_unverified:
            summary = "No observed difference; additional conditions remain unverified."
        else:
            summary = (
                "Observed environment conditions match the saved fingerprint; "
                "remote and unprobed state remains unverified."
            )
        diff_id = new_id("diff")
        event_type = "reality.diffed"
        event_id = self.store.append_event(
            event_type,
            f"Reality diff {level}: {truncate(summary, 260)}",
            session_id=session_id or (snapshot or {}).get("session_id"),
            task_id=task_id or (snapshot or {}).get("task_id"),
            checkpoint_ref=checkpoint_id,
            details={
                "diff_id": diff_id,
                "snapshot_id": snapshot_id,
                "checkpoint_id": checkpoint_id,
                "level": level,
                "changed_keys": [item["key"] for item in changed[:50]],
                "unverified_count": len(unverified),
            },
            idempotency_key=(
                f"reality-diff:{checkpoint_id}:{self.fingerprint_hash(current)}"
                if checkpoint_id
                else None
            ),
        )
        if level == "RED":
            self.store.append_event(
                "precondition.failed",
                f"Reality preconditions failed: {truncate(summary, 260)}",
                session_id=session_id or (snapshot or {}).get("session_id"),
                task_id=task_id or (snapshot or {}).get("task_id"),
                checkpoint_ref=checkpoint_id,
                details={
                    "diff_id": diff_id,
                    "changed_keys": [item["key"] for item in changed[:50]],
                },
                idempotency_key=(
                    f"precondition-failed:{checkpoint_id}:{self.fingerprint_hash(current)}"
                    if checkpoint_id
                    else None
                ),
            )
        record = self.store.record_kairos_diff(
            diff_id=diff_id,
            event_id=event_id,
            checked_at=current["captured_at"],
            level=level,
            changed=changed,
            unverified=unverified,
            summary=summary,
            snapshot_id=snapshot_id,
            checkpoint_id=checkpoint_id,
            session_id=session_id or (snapshot or {}).get("session_id"),
            task_id=task_id or (snapshot or {}).get("task_id"),
            details={
                "saved_hash": self.fingerprint_hash(saved_fingerprint),
                "current_hash": self.fingerprint_hash(current),
            },
        )
        record["current_fingerprint"] = current
        record["stale_evidence"] = self._stale_evidence(
            saved_fingerprint, level, summary, changed
        )
        return record

    def _stale_evidence(
        self,
        saved_fingerprint: dict[str, Any],
        level: str,
        summary: str,
        changed: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        if level == "GREEN" or self.aletheia is None:
            return []
        saved_hash = self.fingerprint_hash(saved_fingerprint)
        if not any(item["severity"] in {"amber", "red"} for item in changed):
            return []
        try:
            stale = self.aletheia.stale_for_environment(
                saved_hash,
                reason=f"Environment changed: {truncate(summary, 300)}",
            )
        except Exception:
            return []
        return stale

    @staticmethod
    def _compare(saved: dict[str, Any], current: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
        changed: list[dict[str, Any]] = []
        unverified = list(current.get("unverified") or [])

        def add(key: str, before: Any, after: Any, severity: str, message: str) -> None:
            if before != after:
                changed.append(
                    {
                        "key": key,
                        "before": before,
                        "after": after,
                        "severity": severity,
                        "message": message,
                    }
                )

        saved_system = saved.get("system") or {}
        current_system = current.get("system") or {}
        for key, severity, label in (
            ("os", "red", "Operating system"),
            ("arch", "red", "CPU architecture"),
            ("python_version", "amber", "Python version"),
            ("python_implementation", "amber", "Python implementation"),
        ):
            add(
                f"system.{key}",
                saved_system.get(key),
                current_system.get(key),
                severity,
                f"{label} changed",
            )

        saved_workspace = saved.get("workspace") or {}
        current_workspace = current.get("workspace") or {}
        add(
            "workspace.root",
            saved_workspace.get("root"),
            current_workspace.get("root"),
            "red",
            "Workspace root changed",
        )
        if saved_workspace.get("exists") and not current_workspace.get("exists"):
            changed.append(
                {
                    "key": "workspace.exists",
                    "before": True,
                    "after": False,
                    "severity": "red",
                    "message": "Workspace is no longer available",
                }
            )

        add(
            "installation_id",
            saved.get("installation_id"),
            current.get("installation_id"),
            "amber",
            "Environment belongs to another Continuum installation",
        )

        saved_git = saved.get("git") or {}
        current_git = current.get("git") or {}
        for key, severity, label in (
            ("branch", "amber", "Git branch"),
            ("commit", "amber", "Git commit"),
        ):
            add(
                f"git.{key}",
                saved_git.get(key),
                current_git.get(key),
                severity,
                f"{label} changed",
            )

        saved_files = saved.get("files") or {}
        current_files = current.get("files") or {}
        for name in sorted(set(saved_files) | set(current_files)):
            before = (saved_files.get(name) or {}).get("sha256")
            after = (current_files.get(name) or {}).get("sha256")
            if before == after:
                continue
            if after is None:
                changed.append(
                    {
                        "key": f"files.{name}",
                        "before": before,
                        "after": None,
                        "severity": "red",
                        "message": f"Tracked file is missing: {name}",
                    }
                )
            elif before is None:
                changed.append(
                    {
                        "key": f"files.{name}",
                        "before": None,
                        "after": after,
                        "severity": "amber",
                        "message": f"New tracked file appeared: {name}",
                    }
                )
            else:
                changed.append(
                    {
                        "key": f"files.{name}",
                        "before": before,
                        "after": after,
                        "severity": "amber",
                        "message": f"Tracked file changed: {name}",
                    }
                )

        saved_tools = saved.get("tools") or {}
        current_tools = current.get("tools") or {}
        for name in sorted(set(saved_tools) | set(current_tools)):
            before = (saved_tools.get(name) or {}).get("present")
            after = (current_tools.get(name) or {}).get("present")
            if before is True and after is not True:
                changed.append(
                    {
                        "key": f"tools.{name}.present",
                        "before": True,
                        "after": after,
                        "severity": "red",
                        "message": f"Required tool is unavailable: {name}",
                    }
                )
            elif before is False and after is True:
                changed.append(
                    {
                        "key": f"tools.{name}.present",
                        "before": False,
                        "after": True,
                        "severity": "amber",
                        "message": f"Optional tool became available: {name}",
                    }
                )

        saved_preconditions = saved.get("preconditions") or {}
        current_preconditions = current.get("preconditions") or {}
        for key in sorted(set(saved_preconditions) | set(current_preconditions)):
            before = saved_preconditions.get(key)
            after = current_preconditions.get(key)
            if before != after:
                changed.append(
                    {
                        "key": f"preconditions.{key}",
                        "before": before,
                        "after": after,
                        "severity": "red",
                        "message": f"Task precondition changed: {key}",
                    }
                )
        return changed, unverified

    # ------------------------------------------------------------------
    # Bounded observation helpers
    # ------------------------------------------------------------------
    def _configured_tools(self) -> list[str]:
        return [
            item.strip().lower()
            for item in str(self.config.kairos_required_tools or "").split(",")
            if item.strip().lower() in _SAFE_TOOL_NAMES
        ]

    def _tool_observation(self, required_tools: Iterable[str] | None) -> dict[str, Any]:
        names = {
            item.strip().lower()
            for item in (required_tools if required_tools is not None else self._configured_tools())
            if item.strip().lower() in _SAFE_TOOL_NAMES
        }
        observation: dict[str, Any] = {}
        for name in sorted(names):
            path = shutil.which(name)
            entry: dict[str, Any] = {"present": bool(path)}
            if path and name in {"python", "python3", "node"}:
                version = _safe_version([path, "--version"])
                if version:
                    entry["version"] = version
            observation[name] = entry
        return observation

    def _git_observation(self, root: Path) -> dict[str, Any]:
        git_dir = _find_git_dir(root)
        if git_dir is None:
            return {"available": False}
        result: dict[str, Any] = {"available": True, "branch": None, "commit": None}
        try:
            head = (git_dir / "HEAD").read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            return result
        if head.startswith("ref: "):
            ref = head[5:].strip()
            result["branch"] = ref.rsplit("/", 1)[-1]
            commit = _read_ref(git_dir, ref)
            result["commit"] = commit
        else:
            result["branch"] = "(detached)"
            result["commit"] = head[:64] if re.fullmatch(r"[0-9a-fA-F]{40,64}", head) else None
        return result

    def _collect_files(
        self,
        root: Path,
        *,
        paths: Iterable[Path | str] | None,
        auto_discover: bool,
    ) -> list[Path]:
        selected: list[Path] = []
        seen: set[Path] = set()
        if paths:
            for raw in list(paths)[: self.config.kairos_max_files]:
                candidate = Path(raw)
                if not candidate.is_absolute():
                    candidate = root / candidate
                candidate = candidate.resolve()
                if not _inside(root, candidate) or _sensitive_name(candidate.name):
                    continue
                if candidate.is_file() and not candidate.is_symlink():
                    selected.append(candidate)
                    seen.add(candidate)
        if auto_discover and len(selected) < self.config.kairos_max_files:
            for current_root, dirs, files in os.walk(root, topdown=True, followlinks=False):
                dirs[:] = sorted(
                    item
                    for item in dirs
                    if item.lower() not in _SKIP_DIRS and not _sensitive_name(item)
                )
                current = Path(current_root)
                for name in sorted(files):
                    candidate = current / name
                    if candidate in seen or _sensitive_name(name):
                        continue
                    if not _interesting_file(candidate):
                        continue
                    try:
                        if candidate.is_symlink() or not candidate.is_file():
                            continue
                        if candidate.stat().st_size > self.config.kairos_max_file_bytes:
                            continue
                    except OSError:
                        continue
                    selected.append(candidate)
                    seen.add(candidate)
                    if len(selected) >= self.config.kairos_max_files:
                        break
                if len(selected) >= self.config.kairos_max_files:
                    break
        return sorted(selected, key=lambda item: _relative_name(root, item))[
            : self.config.kairos_max_files
        ]

    def _hash_files(self, root: Path, files: Iterable[Path]) -> dict[str, dict[str, Any]]:
        result: dict[str, dict[str, Any]] = {}
        for path in files:
            try:
                stat = path.stat()
                if stat.st_size > self.config.kairos_max_file_bytes:
                    continue
                digest = _sha256_file(path)
            except OSError:
                continue
            result[_relative_name(root, path)] = {
                "sha256": digest,
                "size": stat.st_size,
                "modified_ns": stat.st_mtime_ns,
            }
        return result


def _sha256_file(path: Path) -> str:
    import hashlib

    handle = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            handle.update(chunk)
    return handle.hexdigest()


def _find_git_dir(root: Path) -> Path | None:
    current = root
    for _ in range(8):
        candidate = current / ".git"
        if candidate.is_dir():
            return candidate
        if current.parent == current:
            break
        current = current.parent
    return None


def _read_ref(git_dir: Path, ref: str) -> str | None:
    path = git_dir / Path(ref)
    try:
        value = path.read_text(encoding="utf-8", errors="replace").strip()
        return value if re.fullmatch(r"[0-9a-fA-F]{40,64}", value) else None
    except OSError:
        pass
    try:
        packed = (git_dir / "packed-refs").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    for line in packed.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("^"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[1] == ref and re.fullmatch(r"[0-9a-fA-F]{40,64}", parts[0]):
            return parts[0]
    return None


def _safe_version(command: list[str]) -> str | None:
    env = {
        "PATH": os.environ.get("PATH", ""),
        "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
        "HOME": os.environ.get("HOME", ""),
    }
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
            env=env,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    text = (completed.stdout or completed.stderr or "").strip().splitlines()
    return truncate(text[0], 120) if text else None


def _safe_preconditions(value: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, item in list(value.items())[:50]:
        name = redact_text(key, max_chars=100)
        if isinstance(item, (str, int, float, bool)) or item is None:
            result[name] = redact_text(item, max_chars=300) if isinstance(item, str) else item
        else:
            result[name] = stable_hash(item)
    return result


def _sensitive_name(name: str) -> bool:
    lowered = name.lower().strip()
    return any(part in lowered for part in _SKIP_NAME_PARTS)


def _interesting_file(path: Path) -> bool:
    name = path.name.lower()
    return name in _CONFIG_NAMES or path.suffix.lower() in _TEXT_EXTENSIONS


def _inside(root: Path, candidate: Path) -> bool:
    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        return False


def _relative_name(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.name
