"""Checkpoint creation, authenticated export, preview, and idempotent import.

A checkpoint contains only plugin-owned, already-redacted records.  It excludes
raw tool results, credentials, Hermes private session data, pending approvals,
and runtime state.  Import restores records; it never replays historical tool
calls or external side effects.
"""

from __future__ import annotations

import copy
import hmac
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from ..common.config import ContinuumConfig
from ..common.errors import CheckpointError, StorageError
from ..common.ids import new_id
from ..common.redaction import redact_text, truncate
from ..common.time import utc_now_iso
from ..constants import (
    CHECKPOINT_FORMAT_VERSION,
    PLUGIN_VERSION,
    SCHEMA_VERSION,
)
from ..spine.store import SpineStore
from .crypto import (
    FORMAT_VERSION,
    bundle_bytes,
    decrypt_bundle,
    encrypt_bundle,
    file_checksum,
    parse_bundle_bytes,
    validate_passphrase,
)
from .resume import build_resume_brief

EXCLUDED_CATEGORIES = (
    "credentials, API keys, and secret values",
    "raw tool results and full conversation transcripts",
    "Hermes private session database and host runtime state",
    "pending approvals and in-flight actions",
    "process memory, GUI state, and live session migration data",
)

_EXPECTED_TABLES = {
    "events",
    "sources",
    "episodes",
    "memory_facts",
    "security_decisions",
    "checkpoints",
    "dream_runs",
    "attack_lab_runs",
    "resume_briefs",
    "kairos_snapshots",
    "kairos_diffs",
    "aletheia_receipts",
    "aletheia_protected",
    "aletheia_challenges",
    "telos_charters",
    "telos_amendments",
    "telos_drift",
    "telos_completions",
    "moirai_previews",
    "metis_failures",
    "metis_circuits",
    "playbooks",
    "safety_leases",
    "safety_lease_usage",
}


class CheckpointService:
    def __init__(
        self,
        store: SpineStore,
        config: ContinuumConfig | None = None,
        *,
        checkpoint_dir: Path | str | None = None,
        kairos: Any = None,
        telos: Any = None,
    ):
        self.store = store
        self.config = (config or ContinuumConfig()).clamped()
        self.checkpoint_dir = Path(
            checkpoint_dir or (Path.cwd() / "continuum-checkpoints")
        )
        self.kairos = kairos
        self.telos = telos

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------
    def export(
        self,
        passphrase: str,
        *,
        destination: Path | str | None = None,
    ) -> dict[str, Any]:
        validate_passphrase(passphrase)
        checkpoint_id = new_id("ckpt")
        created_at = utc_now_iso()
        environment: dict[str, Any] | None = None
        environment_error = ""
        if self.kairos is not None:
            try:
                envelope = self.kairos.snapshot(
                    label="checkpoint",
                    checkpoint_ref=checkpoint_id,
                )
                environment = {
                    "snapshot_id": envelope.get("id"),
                    "fingerprint_hash": envelope.get("fingerprint_hash"),
                    "fingerprint": envelope.get("fingerprint") or {},
                }
            except Exception as exc:  # noqa: BLE001
                environment_error = f"{type(exc).__name__}: {exc}"
        snapshot = self.store.export_snapshot()
        counts = snapshot["counts"]
        manifest = {
            "format": "hermes-continuum-checkpoint",
            "format_version": CHECKPOINT_FORMAT_VERSION,
            "checkpoint_id": checkpoint_id,
            "created_at": created_at,
            "source_installation_id": self.store.installation_id,
            "plugin_version": PLUGIN_VERSION,
            "schema_version": SCHEMA_VERSION,
            "policy_version": self.store.policy_version,
            "counts": counts,
            "available": snapshot["available"],
            "truncated": snapshot["truncated"],
            "environment_fingerprint_hash": (
                environment.get("fingerprint_hash") if environment else None
            ),
            "environment_fingerprint": (
                environment.get("fingerprint") if environment else None
            ),
            "environment_error": environment_error or None,
            "excluded": list(EXCLUDED_CATEGORIES),
            "note": (
                "Restores plugin-owned records only. It does not restore Hermes "
                "sessions, credentials, live processes, or external side effects."
            ),
        }
        payload = {
            "payload_schema": 1,
            "checkpoint_id": checkpoint_id,
            "created_at": created_at,
            "source_installation_id": self.store.installation_id,
            "plugin_version": PLUGIN_VERSION,
            "environment": environment,
            "data": snapshot["data"],
            "counts": counts,
            "available": snapshot["available"],
            "truncated": snapshot["truncated"],
        }
        payload_bytes = json.dumps(
            payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        bundle = encrypt_bundle(manifest, payload_bytes, passphrase)
        raw = bundle_bytes(bundle)
        checksum = file_checksum(raw)
        target = self._target_path(destination, checkpoint_id, created_at)
        try:
            self._atomic_write(target, raw)
        except OSError as exc:
            raise CheckpointError(f"Could not write checkpoint file: {exc}") from exc
        record = self.store.record_checkpoint(
            checkpoint_id=checkpoint_id,
            filename=target.name,
            format_version=CHECKPOINT_FORMAT_VERSION,
            source_installation_id=self.store.installation_id,
            counts=counts,
            excluded=manifest["excluded"],
            checksum=checksum,
            status="exported",
            metadata={
                "path": str(target),
                "available": snapshot["available"],
                "truncated": snapshot["truncated"],
                "source_checksum": checksum,
            },
        )
        return {
            "ok": True,
            "status": "exported",
            "checkpoint_id": checkpoint_id,
            "path": str(target),
            "filename": target.name,
            "checksum": checksum,
            "manifest": manifest,
            "counts": counts,
            "available": snapshot["available"],
            "truncated": snapshot["truncated"],
            "environment": environment,
            "environment_error": environment_error or None,
            "record": record,
        }

    def _target_path(
        self, destination: Path | str | None, checkpoint_id: str, created_at: str
    ) -> Path:
        stamp = (
            created_at.replace("-", "")
            .replace(":", "")
            .replace(".", "")
            .replace("T", "-")
            .replace("Z", "")
        )[:15]
        filename = f"continuum-{stamp}-{checkpoint_id[-8:]}.hcc"
        if destination is None:
            target = self.checkpoint_dir / filename
        else:
            raw = str(destination)
            target = Path(raw).expanduser()
            if target.exists() and target.is_dir():
                target = target / filename
            elif raw.endswith(("/", "\\")):
                target = target / filename
            elif not target.suffix:
                target = target.with_suffix(".hcc")
        target.parent.mkdir(parents=True, exist_ok=True)
        return target

    @staticmethod
    def _atomic_write(target: Path, data: bytes) -> None:
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(
            prefix=".continuum-", suffix=".tmp", dir=str(target.parent)
        )
        temp_path = Path(temp_name)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.chmod(temp_path, 0o600)
            except OSError:
                pass
            os.replace(temp_path, target)
        except Exception:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise

    # ------------------------------------------------------------------
    # Preview / import
    # ------------------------------------------------------------------
    def inspect(
        self,
        path: Path | str,
        passphrase: str,
        *,
        expected_checksum: str | None = None,
    ) -> dict[str, Any]:
        loaded = self._load(path, passphrase, expected_checksum=expected_checksum)
        return self._preview(loaded)

    def import_checkpoint(
        self,
        path: Path | str,
        passphrase: str,
        *,
        confirm: bool = False,
        expected_checksum: str | None = None,
    ) -> dict[str, Any]:
        loaded = self._load(path, passphrase, expected_checksum=expected_checksum)
        preview = self._preview(loaded)
        if not confirm:
            return preview
        existing = self.store.find_imported_checkpoint_by_checksum(loaded["checksum"])
        if existing is not None:
            return {
                "ok": True,
                "status": "already_imported",
                "checkpoint_id": existing["id"],
                "source_checkpoint_id": loaded["payload"]["checkpoint_id"],
                "path": str(loaded["path"]),
                "checksum": loaded["checksum"],
                "manifest": loaded["manifest"],
                "conflicts": preview["conflicts"],
                "message": "This checkpoint file has already been imported; existing records were kept.",
            }
        prepared, conflicts = self._prepare_import_data(
            loaded["payload"]["data"], loaded["payload"]["checkpoint_id"]
        )
        imported = self.store.import_snapshot(prepared)
        local_checkpoint_id = new_id("ckpt")
        reality_diff: dict[str, Any] | None = None
        reality_error = ""
        environment = loaded["payload"].get("environment") or {}
        saved_fingerprint = (
            environment.get("fingerprint")
            if isinstance(environment, dict)
            else None
        ) or loaded["manifest"].get("environment_fingerprint")
        if self.kairos is not None and isinstance(saved_fingerprint, dict) and saved_fingerprint:
            try:
                reality_diff = self.kairos.diff(
                    saved_fingerprint=saved_fingerprint,
                    checkpoint_id=local_checkpoint_id,
                )
            except Exception as exc:  # noqa: BLE001
                reality_error = f"{type(exc).__name__}: {exc}"
        charter = self.store.find_active_charter()
        confirmed = [
            fact
            for fact in self.store.list_memory(status="confirmed")
            if fact.get("is_current_confirmed")
        ][:5]
        brief = build_resume_brief(
            loaded["manifest"],
            loaded["payload"].get("counts", {}),
            confirmed,
            conflicts,
            reality_diff=reality_diff,
            charter=charter,
            environment_error=reality_error,
        )
        resume = self.store.record_resume_brief(
            checkpoint_id=local_checkpoint_id,
            brief=brief,
            metadata={
                "source_checkpoint_id": loaded["payload"]["checkpoint_id"],
                "source_installation_id": loaded["manifest"].get("source_installation_id"),
                "conflicts": len(conflicts),
                "reality_level": (reality_diff or {}).get("level"),
                "reality_error": reality_error or None,
                "note": "No external actions were replayed during import.",
            },
        )
        record = self.store.record_checkpoint(
            checkpoint_id=local_checkpoint_id,
            filename=loaded["path"].name,
            format_version=int(
                loaded["manifest"].get("format_version", FORMAT_VERSION)
            ),
            source_installation_id=str(
                loaded["manifest"].get("source_installation_id") or "inst_unknown"
            ),
            counts=loaded["payload"].get("counts", {}),
            excluded=loaded["manifest"].get("excluded", list(EXCLUDED_CATEGORIES)),
            checksum=loaded["checksum"],
            status="imported",
            imported_at=utc_now_iso(),
            metadata={
                "source_path": str(loaded["path"]),
                "source_checkpoint_id": loaded["payload"]["checkpoint_id"],
                "source_checksum": loaded["checksum"],
                "inserted": imported["inserted"],
                "skipped": imported["skipped"],
                "conflicts": conflicts[:50],
                "reality_level": (reality_diff or {}).get("level"),
                "reality_diff_id": (reality_diff or {}).get("id"),
                "reality_error": reality_error or None,
            },
            resume_brief_id=resume["id"],
        )
        return {
            "ok": True,
            "status": "imported",
            "checkpoint_id": local_checkpoint_id,
            "source_checkpoint_id": loaded["payload"]["checkpoint_id"],
            "path": str(loaded["path"]),
            "checksum": loaded["checksum"],
            "imported": imported,
            "conflicts": conflicts,
            "reality_diff": reality_diff,
            "reality_error": reality_error or None,
            "resume_brief_id": resume["id"],
            "resume_brief": brief,
            "manifest": loaded["manifest"],
            "record": record,
        }

    def _load(
        self,
        path: Path | str,
        passphrase: str,
        *,
        expected_checksum: str | None = None,
    ) -> dict[str, Any]:
        validate_passphrase(passphrase)
        target = Path(path).expanduser()
        if not target.exists() or not target.is_file():
            raise CheckpointError("Checkpoint file not found.")
        try:
            size = target.stat().st_size
        except OSError as exc:
            raise CheckpointError(f"Could not stat checkpoint file: {exc}") from exc
        if size > self.config.checkpoint_max_bytes:
            raise CheckpointError("Checkpoint file is larger than the configured limit.")
        try:
            raw = target.read_bytes()
        except OSError as exc:
            raise CheckpointError(f"Could not read checkpoint file: {exc}") from exc
        checksum = file_checksum(raw)
        if expected_checksum and not hmac.compare_digest(checksum, expected_checksum):
            raise CheckpointError(
                "Checkpoint file changed after preview; import was cancelled."
            )
        bundle = parse_bundle_bytes(raw)
        header, payload_bytes = decrypt_bundle(bundle, passphrase)
        payload = self._parse_payload(payload_bytes, header)
        return {
            "path": target,
            "raw": raw,
            "checksum": checksum,
            "bundle": bundle,
            "header": header,
            "manifest": header["manifest"],
            "payload": payload,
        }

    @staticmethod
    def _parse_payload(payload_bytes: bytes, header: dict[str, Any]) -> dict[str, Any]:
        try:
            payload = json.loads(payload_bytes.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise CheckpointError("Checkpoint payload is not valid JSON.") from exc
        if not isinstance(payload, dict):
            raise CheckpointError("Checkpoint payload is not an object.")
        if int(payload.get("payload_schema", 0)) != 1:
            raise CheckpointError("Checkpoint payload schema is not supported.")
        manifest = header.get("manifest")
        if not isinstance(manifest, dict):
            raise CheckpointError("Checkpoint manifest is malformed.")
        if payload.get("checkpoint_id") != manifest.get("checkpoint_id"):
            raise CheckpointError("Checkpoint payload and manifest identifiers disagree.")
        if payload.get("source_installation_id") != manifest.get("source_installation_id"):
            raise CheckpointError("Checkpoint source installation identifier disagrees.")
        data = payload.get("data")
        if not isinstance(data, dict):
            raise CheckpointError("Checkpoint data is not an object.")
        unknown = set(data.keys()) - _EXPECTED_TABLES
        if unknown:
            raise CheckpointError(
                "Checkpoint contains unsupported record tables: "
                + ", ".join(sorted(unknown))
            )
        total = 0
        for table, rows in data.items():
            if not isinstance(rows, list):
                raise CheckpointError(f"Checkpoint table {table} is not a list.")
            total += len(rows)
            for row in rows:
                if not isinstance(row, dict):
                    raise CheckpointError(f"Checkpoint table {table} contains a non-object row.")
        if total > 20000:
            raise CheckpointError("Checkpoint contains too many records for a safe preview.")
        counts = payload.get("counts")
        if not isinstance(counts, dict):
            raise CheckpointError("Checkpoint counts are missing.")
        manifest_counts = manifest.get("counts")
        if isinstance(manifest_counts, dict):
            for table, rows in data.items():
                expected = manifest_counts.get(table)
                if expected is not None and int(expected) != len(rows):
                    raise CheckpointError(
                        f"Checkpoint manifest count for {table} does not match its payload."
                    )
        for table, rows in data.items():
            if table in counts and int(counts[table]) != len(rows):
                raise CheckpointError(
                    f"Checkpoint payload count for {table} does not match its records."
                )
        return payload

    def _preview(self, loaded: dict[str, Any]) -> dict[str, Any]:
        conflicts = self._memory_conflicts(loaded["payload"]["data"])
        return {
            "ok": True,
            "status": "preview",
            "path": str(loaded["path"]),
            "checksum": loaded["checksum"],
            "manifest": loaded["manifest"],
            "counts": loaded["payload"].get("counts", {}),
            "available": loaded["payload"].get("available", {}),
            "truncated": loaded["payload"].get("truncated", {}),
            "conflicts": conflicts,
            "can_import": True,
            "message": (
                "Preview only. No records were written. Conflicting imported "
                "memory becomes a reviewable candidate; older values remain visible."
            ),
        }

    def _memory_conflicts(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        conflicts: list[dict[str, Any]] = []
        for row in data.get("memory_facts", []):
            if not isinstance(row, dict):
                continue
            fact_id = str(row.get("id") or "")
            key = str(row.get("fact_key") or "")
            value = str(row.get("value") or "")
            version = int(row.get("version") or 1)
            if not fact_id or not key:
                continue
            if self.store.get_fact(fact_id) is not None:
                continue
            same_value = self.store.find_fact_by_key_value(key, value)
            if same_value is not None:
                continue
            same_version = self.store.find_fact_by_key_version(key, version)
            current = self.store.find_current_fact(key)
            if same_version is not None or (
                current is not None and current["value"].strip().lower() != value.strip().lower()
            ):
                conflicts.append(
                    {
                        "kind": "version" if same_version is not None else "value",
                        "fact_key": redact_text(key, max_chars=120),
                        "imported_fact_id": fact_id,
                        "imported_value": redact_text(value, max_chars=240),
                        "local_fact_id": (same_version or current or {}).get("id"),
                        "local_value": redact_text(
                            str((same_version or current or {}).get("value") or ""),
                            max_chars=240,
                        ),
                    }
                )
                if len(conflicts) >= 200:
                    break
        return conflicts

    def _prepare_import_data(
        self, data: dict[str, Any], source_checkpoint_id: str
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        prepared = copy.deepcopy(data)
        rows = prepared.get("memory_facts", [])
        if not isinstance(rows, list):
            raise CheckpointError("Checkpoint memory table is not a list.")
        resolved: list[dict[str, Any]] = []
        conflicts: list[dict[str, Any]] = []
        allocated: dict[str, int] = {}
        seen_versions: dict[tuple[str, int], str] = {}
        for raw in rows:
            if not isinstance(raw, dict):
                continue
            row = dict(raw)
            fact_id = str(row.get("id") or "")
            key = str(row.get("fact_key") or "")
            value = str(row.get("value") or "")
            if not fact_id or not key or not value:
                continue
            if self.store.get_fact(fact_id) is not None:
                continue
            same_value = self.store.find_fact_by_key_value(key, value)
            if same_value is not None:
                continue
            try:
                version = int(row.get("version") or 1)
            except (TypeError, ValueError):
                version = 1
            local_same_version = self.store.find_fact_by_key_version(key, version)
            local_current = self.store.find_current_fact(key)
            duplicate_in_payload = seen_versions.get((key, version)) is not None
            conflict_kind: str | None = None
            if duplicate_in_payload:
                conflict_kind = "duplicate_version"
            elif local_same_version is not None and local_same_version.get("id") != fact_id:
                conflict_kind = "version"
            elif (
                local_current is not None
                and local_current["value"].strip().lower() != value.strip().lower()
            ):
                conflict_kind = "value"
            seen_versions[(key, version)] = fact_id
            if conflict_kind:
                new_version = max(
                    allocated.get(key, self.store.max_fact_version(key)) + 1,
                    version + 1,
                )
                allocated[key] = new_version
                row["version"] = new_version
                row["status"] = "candidate"
                row["confirmed_at"] = None
                row["superseded_by"] = None
                row["reviewed_by"] = None
                if local_current is not None and local_current["value"].strip().lower() != value.strip().lower():
                    row["contradicts_fact_id"] = local_current["id"]
                row["notes"] = (
                    (str(row.get("notes") or "") + f" [imported conflict from checkpoint {source_checkpoint_id}]").strip()
                )
                now = utc_now_iso()
                row["created_at"] = now
                row["updated_at"] = now
                row.setdefault("first_observed_utc", now)
                row.setdefault("last_observed_utc", now)
                conflicts.append(
                    {
                        "kind": conflict_kind,
                        "fact_key": redact_text(key, max_chars=120),
                        "imported_fact_id": fact_id,
                        "imported_value": redact_text(value, max_chars=240),
                        "imported_version": new_version,
                        "local_fact_id": (local_same_version or local_current or {}).get("id"),
                        "local_value": redact_text(
                            str((local_same_version or local_current or {}).get("value") or ""),
                            max_chars=240,
                        ),
                        "resolution": "imported as an unconfirmed candidate",
                    }
                )
            else:
                allocated[key] = max(allocated.get(key, 0), version)
            resolved.append(row)
        prepared["memory_facts"] = resolved
        return prepared, conflicts

    # ------------------------------------------------------------------
    # Resume briefs
    # ------------------------------------------------------------------
    def dismiss_resume_brief(self, brief_id: str) -> None:
        self.store.dismiss_resume_brief(brief_id)

    def active_resume_brief(self) -> dict[str, Any] | None:
        return self.store.active_resume_brief()

    def list_checkpoints(self) -> list[dict[str, Any]]:
        return self.store.list_checkpoints()

    @staticmethod
    def _safe_path_display(path: Path) -> str:
        return truncate(str(path), 500)
