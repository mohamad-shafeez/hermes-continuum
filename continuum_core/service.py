"""Application service shared by hooks, tools, CLI, and the Console backend."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from .aletheia import AletheiaService
from .checkpoint import CheckpointService
from .common.config import ContinuumConfig
from .common.errors import StorageError
from .constants import PLUGIN_ID, PLUGIN_VERSION
from .hephaestus import HephaestusService
from .kairos import KairosService
from .metis import MetisService
from .moirai import MoiraiService
from .oneiros import DreamService, MemoryService, RecallService
from .spine.store import SpineStore
from .telos import TelosService
from .tripwire import run_attack_lab


class ContinuumService:
    def __init__(
        self,
        store: SpineStore,
        *,
        config: ContinuumConfig | None = None,
        checkpoint_dir: Path | str | None = None,
        hephaestus_artifact_dir: Path | str | None = None,
        host_registrar: Any = None,
    ):
        self.store = store
        self.config = (config or ContinuumConfig()).clamped()
        self.memory = MemoryService(store, self.config)
        self.dream_service = DreamService(store, self.config)
        self.recall_service = RecallService(store, self.config)
        self.kairos = KairosService(store, self.config)
        self.aletheia = AletheiaService(store, self.config, kairos=self.kairos)
        self.kairos.aletheia = self.aletheia
        self.telos = TelosService(store, self.config, aletheia=self.aletheia)
        self.moirai = MoiraiService(store, self.config, aletheia=self.aletheia)
        self.metis = MetisService(store, self.config)
        self.checkpoint_service = CheckpointService(
            store,
            self.config,
            checkpoint_dir=checkpoint_dir,
            kairos=self.kairos,
            telos=self.telos,
        )
        if hephaestus_artifact_dir is None:
            if checkpoint_dir is not None:
                hephaestus_artifact_dir = Path(checkpoint_dir).expanduser().parent / "hephaestus"
            else:
                hephaestus_artifact_dir = Path.cwd() / "hephaestus-artifacts"
        self.hephaestus = HephaestusService(
            store,
            self.config,
            artifact_dir=hephaestus_artifact_dir,
            host_registrar=host_registrar,
        )

    @classmethod
    def from_path(
        cls,
        db_path: Path | str,
        *,
        config: ContinuumConfig | None = None,
        checkpoint_dir: Path | str | None = None,
        hephaestus_artifact_dir: Path | str | None = None,
        host_registrar: Any = None,
    ) -> "ContinuumService":
        path = Path(db_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(
            str(path), check_same_thread=False, timeout=10.0
        )
        store = SpineStore(connection, owns_connection=True)
        if checkpoint_dir is None:
            configured_dir = str(getattr(config, "checkpoint_dir", "") or "").strip()
            if configured_dir:
                checkpoint_dir = Path(configured_dir).expanduser()
        if hephaestus_artifact_dir is None:
            hephaestus_artifact_dir = path.parent / "hephaestus"
        return cls(
            store,
            config=config,
            checkpoint_dir=checkpoint_dir,
            hephaestus_artifact_dir=hephaestus_artifact_dir,
            host_registrar=host_registrar,
        )

    @classmethod
    def from_plugin_storage(
        cls,
        *,
        config: ContinuumConfig | None = None,
        host_registrar: Any = None,
    ) -> "ContinuumService":
        try:
            from plugins.plugin_storage import plugin_data_dir, plugin_db
        except Exception as exc:  # noqa: BLE001
            raise StorageError(
                "Continuum could not locate Hermes plugin storage."
            ) from exc
        connection = plugin_db(PLUGIN_ID)
        data_dir = plugin_data_dir(PLUGIN_ID)
        configured_dir = str(getattr(config, "checkpoint_dir", "") or "").strip()
        if configured_dir:
            checkpoint_dir = Path(configured_dir).expanduser()
            if not checkpoint_dir.is_absolute():
                checkpoint_dir = data_dir / checkpoint_dir
        else:
            checkpoint_dir = data_dir / "checkpoints"
        # ``plugin_db`` returns a fresh connection owned by the caller; closing
        # the service must close it (the previous False leaked one per reload).
        return cls(
            SpineStore(connection, owns_connection=True),
            config=config,
            checkpoint_dir=checkpoint_dir,
            hephaestus_artifact_dir=data_dir / "hephaestus",
            host_registrar=host_registrar,
        )

    def close(self) -> None:
        self.store.close()

    # ------------------------------------------------------------------
    # Status and Console read models
    # ------------------------------------------------------------------
    def config_dict(self) -> dict[str, Any]:
        return {
            "recall_limit": self.config.recall_limit,
            "episode_retention_days": self.config.episode_retention_days,
            "context_trust_window_minutes": self.config.context_trust_window_minutes,
            "tripwire_audit_allowed": self.config.tripwire_audit_allowed,
            "enable_source_labels": self.config.enable_source_labels,
            "enable_memory_capture": self.config.enable_memory_capture,
            "checkpoint_dir": str(self.checkpoint_service.checkpoint_dir),
            "enable_kairos": self.config.enable_kairos,
            "kairos_scope": self.config.kairos_scope,
            "enable_aletheia": self.config.enable_aletheia,
            "enable_telos": self.config.enable_telos,
            "enable_moirai": self.config.enable_moirai,
            "enable_metis": self.config.enable_metis,
            "metis_failure_threshold": self.config.metis_failure_threshold,
            "metis_circuit_minutes": self.config.metis_circuit_minutes,
            "enable_hephaestus": self.config.enable_hephaestus,
            "hephaestus_artifact_dir": str(self.hephaestus.artifact_root),
            "hephaestus_min_confidence": self.config.hephaestus_min_confidence,
            "hephaestus_lease_minutes": self.config.hephaestus_lease_minutes,
            "hephaestus_max_lease_days": self.config.hephaestus_max_lease_days,
            "hephaestus_cron_enforce": self.config.hephaestus_cron_enforce,
            "hephaestus_quarantine_untrusted_skill_writes": (
                self.config.hephaestus_quarantine_untrusted_skill_writes
            ),
        }

    def status(self) -> dict[str, Any]:
        stats = self.store.stats()
        memory_counts = self.store.memory_counts()
        security_counts = self.store.decision_counts()
        last_dream = self.store.last_dream_run()
        last_lab = self.store.last_attack_lab(suite="tripwire")
        last_hephaestus_lab = self.store.last_attack_lab(suite="hephaestus")
        active_resume = self.store.active_resume_brief()
        return {
            "ok": True,
            "plugin": PLUGIN_ID,
            "version": PLUGIN_VERSION,
            "schema_version": self.store.schema_version,
            "policy_version": self.store.policy_version,
            "installation_id": self.store.installation_id,
            "stats": stats,
            "memory_counts": memory_counts,
            "security_counts": security_counts,
            "hephaestus_counts": self.store.hephaestus_counts(),
            "needs_review": int(memory_counts.get("candidate", 0)),
            "last_event_at": self.store.last_event_at(),
            "last_dream": _dream_summary(last_dream),
            "last_attack_lab": _lab_summary(last_lab),
            "last_hephaestus_attack_lab": _lab_summary(last_hephaestus_lab),
            "active_resume_brief": _resume_summary(active_resume),
            "config": self.config_dict(),
        }

    def overview(self) -> dict[str, Any]:
        return {
            "status": self.status(),
            "recent_events": self.store.list_events(limit=8),
            "recent_decisions": self.store.list_decisions(limit=5),
            "recent_checkpoints": self.store.list_checkpoints(limit=5),
            "sources": self.store.list_sources(limit=5),
            "pending_candidates": [
                fact
                for fact in self.store.list_memory(status="candidate")
                if fact.get("is_latest")
            ][:10],
        }

    def timeline(
        self,
        *,
        limit: int = 100,
        event_type: str | None = None,
        module: str | None = None,
        session_id: str | None = None,
        source_ref: str | None = None,
        search: str | None = None,
        before_id: int | None = None,
    ) -> list[dict[str, Any]]:
        return self.store.list_events(
            limit=limit,
            event_type=event_type,
            module=module,
            session_id=session_id,
            source_ref=source_ref,
            search=search,
            before_id=before_id,
        )

    def get_event(self, event_id: str) -> dict[str, Any] | None:
        return self.store.get_event(event_id)

    def memory_list(
        self, *, status: str | None = None, query: str | None = None
    ) -> list[dict[str, Any]]:
        return self.store.list_memory(status=status, query=query)

    def memory_counts(self) -> dict[str, int]:
        return self.store.memory_counts()

    def confirm_memory(self, fact_id: str) -> dict[str, Any]:
        return self.store.confirm_fact(fact_id)

    def reject_memory(self, fact_id: str) -> dict[str, Any]:
        return self.store.reject_fact(fact_id)

    def edit_memory(self, fact_id: str, value: str) -> dict[str, Any]:
        return self.store.edit_fact(fact_id, value=value)

    def forget_memory(self, fact_id: str) -> dict[str, Any]:
        return self.store.delete_fact(fact_id)

    def security(self) -> dict[str, Any]:
        return {
            "policy_version": self.store.policy_version,
            "counts": self.store.decision_counts(),
            "decisions": self.store.list_decisions(limit=80),
            "sources": self.store.list_sources(limit=30),
            "last_attack_lab": self.store.last_attack_lab(suite="tripwire"),
            "checkpoints": self.store.list_checkpoints(limit=20),
            "active_resume_brief": _resume_summary(self.store.active_resume_brief()),
        }

    def run_attack_lab(self, *, suite: str = "tripwire") -> dict[str, Any]:
        name = str(suite or "tripwire").strip().lower()
        if name == "hephaestus":
            return self.hephaestus.run_attack_lab()
        if name not in {"tripwire", "default", "policy"}:
            raise ValueError("suite must be tripwire or hephaestus")
        results = run_attack_lab()
        record = self.store.record_attack_lab(
            policy_version=self.store.policy_version,
            results=results,
            suite="tripwire",
        )
        return {
            "ok": True,
            "status": "completed",
            "suite": "tripwire",
            "run": record,
            "results": results,
            "passed": record["passed"],
            "total": record["total"],
            "disclaimer": (
                "Deterministic synthetic cases only. This is not a claim of perfect "
                "prompt-injection protection and does not execute any action."
            ),
        }

    def last_attack_lab(self, *, suite: str = "tripwire") -> dict[str, Any] | None:
        return self.store.last_attack_lab(suite=suite)

    def dream(self) -> dict[str, Any]:
        return self.dream_service.run()

    def recall(self, query: str, *, limit: int | None = None) -> list[dict[str, Any]]:
        return self.recall_service.recall(query, limit=limit)

    def recall_context(
        self, user_message: Any, *, session_id: str | None = None
    ) -> str | None:
        return self.recall_service.build_context(user_message, session_id=session_id)

    def capture_turn(
        self,
        *,
        user_message: Any,
        assistant_message: Any = "",
        session_id: str | None = None,
        turn_id: str | None = None,
        task_id: str | None = None,
        source_ref: str | None = None,
    ) -> dict[str, Any] | None:
        return self.memory.capture_turn(
            user_message=user_message,
            assistant_message=assistant_message,
            session_id=session_id,
            turn_id=turn_id,
            task_id=task_id,
            source_ref=source_ref,
        )

    # ------------------------------------------------------------------
    # Checkpoints
    # ------------------------------------------------------------------
    def export_checkpoint(
        self, passphrase: str, *, destination: Path | str | None = None
    ) -> dict[str, Any]:
        return self.checkpoint_service.export(passphrase, destination=destination)

    def inspect_checkpoint(
        self,
        path: Path | str,
        passphrase: str,
        *,
        expected_checksum: str | None = None,
    ) -> dict[str, Any]:
        return self.checkpoint_service.inspect(
            path, passphrase, expected_checksum=expected_checksum
        )

    def import_checkpoint(
        self,
        path: Path | str,
        passphrase: str,
        *,
        confirm: bool = False,
        expected_checksum: str | None = None,
    ) -> dict[str, Any]:
        return self.checkpoint_service.import_checkpoint(
            path,
            passphrase,
            confirm=confirm,
            expected_checksum=expected_checksum,
        )

    def list_checkpoints(self) -> list[dict[str, Any]]:
        return self.store.list_checkpoints()

    def checkpoint_files(self) -> list[dict[str, Any]]:
        """List local ``.hcc`` files without decrypting them.

        File contents, manifest fields, and passphrases are never read here.
        """

        directory = Path(self.checkpoint_service.checkpoint_dir)
        if not directory.is_dir():
            return []
        files: list[dict[str, Any]] = []
        try:
            paths = sorted(
                directory.glob("*.hcc"),
                key=lambda item: item.stat().st_mtime,
                reverse=True,
            )
        except OSError:
            return []
        for path in paths[:100]:
            try:
                stat = path.stat()
            except OSError:
                continue
            files.append(
                {
                    "filename": path.name,
                    "path": str(path),
                    "size_bytes": stat.st_size,
                    "modified_at": stat.st_mtime,
                }
            )
        return files

    def active_resume_brief(self) -> dict[str, Any] | None:
        return self.store.active_resume_brief()

    def dismiss_resume_brief(self, brief_id: str) -> None:
        self.store.dismiss_resume_brief(brief_id)

    # ------------------------------------------------------------------
    # Nine-system read model and actions
    # ------------------------------------------------------------------
    def pillars(self) -> dict[str, Any]:
        snapshots = self.store.list_kairos_snapshots(limit=3)
        diffs = self.store.list_kairos_diffs(limit=3)
        receipts = self.store.list_evidence_receipts(limit=5)
        protected = self.store.list_protected_artifacts(limit=5)
        charters = self.store.list_charters(limit=5)
        active_charter = self.store.find_active_charter()
        drift = self.store.list_telos_drift(limit=5)
        previews = self.store.list_impact_previews(limit=5)
        failures = self.store.list_failure_observations(limit=5)
        circuits = self.store.list_circuits(limit=10)
        memory_counts = self.store.memory_counts()
        security_counts = self.store.decision_counts()
        hephaestus_counts = self.store.hephaestus_counts()
        return {
            "ok": True,
            "pillars": [
                {
                    "id": "continuity",
                    "name": "Continuity & Reality",
                    "systems": ["Continuum", "Kairos"],
                    "description": "Portable work state and the environmental conditions around it.",
                    "metrics": {
                        "checkpoints": len(self.store.list_checkpoints(limit=500)),
                        "snapshots": len(self.store.list_kairos_snapshots(limit=500)),
                        "latest_level": diffs[0].get("level") if diffs else None,
                    },
                    "latest_snapshot": snapshots[0] if snapshots else None,
                    "latest_diff": diffs[0] if diffs else None,
                    "resume_brief": _resume_summary(self.store.active_resume_brief()),
                },
                {
                    "id": "memory",
                    "name": "Memory & Evidence",
                    "systems": ["Oneiros", "Aletheia"],
                    "description": "Reviewable memory backed by receipts, not assertion.",
                    "metrics": {
                        **memory_counts,
                        "protected": len(
                            [item for item in self.store.list_protected_artifacts(limit=500) if item.get("active")]
                        ),
                        "current_receipts": len(
                            self.store.list_evidence_receipts(status="current", limit=500)
                        ),
                    },
                    "receipts": receipts,
                    "protected": protected,
                },
                {
                    "id": "intent",
                    "name": "Intent & Trust",
                    "systems": ["Telos", "Tripwire"],
                    "description": "The user's charter and deterministic security decisions.",
                    "metrics": {
                        "active_charter": bool(active_charter),
                        "drift": len(self.store.list_telos_drift(limit=500)),
                        **security_counts,
                    },
                    "charter": active_charter,
                    "charters": charters,
                    "drift": drift,
                },
                {
                    "id": "resilience",
                    "name": "Foresight & Resilience",
                    "systems": ["Moirai", "Metis"],
                    "description": "Impact previews and a temporary circuit around unproductive retries.",
                    "metrics": {
                        "previews": len(self.store.list_impact_previews(limit=500)),
                        "open_circuits": len(
                            [
                                item
                                for item in self.store.list_circuits(status="open", limit=500)
                            ]
                        ),
                        "failures": len(
                            self.store.list_failure_observations(limit=500)
                        ),
                    },
                    "previews": previews,
                    "failures": failures,
                    "circuits": circuits,
                },
                {
                    "id": "forge",
                    "name": "Distillation & Autonomy",
                    "systems": ["Hephaestus"],
                    "description": (
                        "Reusable skills and automation blueprints forged from verified "
                        "traces, bounded by explicit safety leases for unattended runs."
                    ),
                    "metrics": {
                        **hephaestus_counts,
                        "playbook_total": hephaestus_counts.get("playbooks", 0),
                        "lease_total": len(self.store.list_safety_leases(limit=500)),
                    },
                    "playbooks": [
                        self.hephaestus._playbook_summary(item)
                        for item in self.store.list_playbooks(limit=10)
                    ],
                    "leases": self.store.list_safety_leases(limit=10),
                    "last_attack_lab": _lab_summary(
                        self.store.last_attack_lab(suite="hephaestus")
                    ),
                },
            ],
            "status": self.status(),
        }

    def reality_snapshot(
        self,
        *,
        scope: str | None = None,
        paths: list[str] | None = None,
        label: str = "",
        session_id: str | None = None,
        task_id: str | None = None,
        preconditions: dict[str, Any] | None = None,
        required_tools: list[str] | None = None,
    ) -> dict[str, Any]:
        return self.kairos.snapshot(
            scope=scope,
            paths=paths,
            label=label,
            session_id=session_id,
            task_id=task_id,
            preconditions=preconditions,
            required_tools=required_tools,
        )

    def reality_diff(
        self,
        snapshot_id: str | None = None,
        *,
        session_id: str | None = None,
        task_id: str | None = None,
        preconditions: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return self.kairos.diff(
            snapshot_id,
            session_id=session_id,
            task_id=task_id,
            preconditions=preconditions,
        )

    def reality(self) -> dict[str, Any]:
        return {
            "ok": True,
            "snapshots": self.store.list_kairos_snapshots(limit=20),
            "diffs": self.store.list_kairos_diffs(limit=20),
            "latest_snapshot": self.store.latest_kairos_snapshot(),
        }

    def evidence(self) -> dict[str, Any]:
        return {
            "ok": True,
            "receipts": self.store.list_evidence_receipts(limit=100),
            "protected": self.store.list_protected_artifacts(limit=100),
            "challenges": self.store.list_evidence_challenges(limit=100),
        }

    def record_evidence_file(
        self,
        path: Path | str,
        *,
        expected_sha256: str | None = None,
        scope: str = "",
        memory_ref: str | None = None,
        session_id: str | None = None,
        task_id: str | None = None,
    ) -> dict[str, Any]:
        snapshot = self.store.latest_kairos_snapshot()
        return self.aletheia.verify_file(
            path,
            expected_sha256=expected_sha256,
            scope=scope,
            environment_snapshot=snapshot,
            memory_ref=memory_ref,
            session_id=session_id,
            task_id=task_id,
        )

    def protect_artifact(
        self,
        artifact_ref: str,
        *,
        receipt_id: str | None = None,
        scope: str = "",
        confirmed_by: str = "user",
    ) -> dict[str, Any]:
        return self.aletheia.protect(
            artifact_ref,
            receipt_id=receipt_id,
            scope=scope,
            confirmed_by=confirmed_by,
        )

    def release_artifact(
        self, protected_id: str, *, reason: str = "", confirmed_by: str = "user"
    ) -> dict[str, Any]:
        return self.aletheia.release(
            protected_id, reason=reason, confirmed_by=confirmed_by
        )

    def confirm_evidence(self, receipt_id: str, *, confirmed_by: str = "user") -> dict[str, Any]:
        return self.aletheia.confirm_receipt(receipt_id, confirmed_by=confirmed_by)

    def charters(self) -> dict[str, Any]:
        return {
            "ok": True,
            "charters": self.store.list_charters(limit=100),
            "amendments": self.store.list_charter_amendments(limit=100),
            "drift": self.store.list_telos_drift(limit=100),
            "completions": self.store.list_completion_assessments(limit=100),
        }

    def ensure_charter(
        self,
        user_message: Any,
        *,
        session_id: str | None = None,
        task_id: str | None = None,
        source_ref: str | None = None,
        trust_label: str = "USER_AUTHORED",
    ) -> dict[str, Any] | None:
        return self.telos.ensure_charter(
            user_message,
            session_id=session_id,
            task_id=task_id,
            source_ref=source_ref,
            trust_label=trust_label,
        )

    def amend_charter(
        self,
        charter_id: str,
        amendment: str,
        *,
        rationale: str = "",
        confirmed: bool = False,
        source_ref: str | None = None,
    ) -> dict[str, Any]:
        if not confirmed:
            raise ValueError("An explicit confirmation is required to amend a charter.")
        return self.telos.amend(
            charter_id,
            amendment=amendment,
            rationale=rationale,
            user_confirmed=True,
            source_ref=source_ref,
        )

    def assess_completion(
        self,
        charter_id: str,
        *,
        claimed_complete: bool = True,
        evidence_ids: list[str] | None = None,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        return self.telos.assess_completion(
            charter_id,
            claimed_complete=claimed_complete,
            evidence_ids=evidence_ids,
            user_confirmed=user_confirmed,
        )

    def preview_action(
        self,
        tool_name: str,
        args: Any,
        *,
        session_id: str | None = None,
        task_id: str | None = None,
        source_ref: str | None = None,
        action_ref: str | None = None,
    ) -> dict[str, Any]:
        return self.moirai.preview(
            tool_name,
            args,
            session_id=session_id,
            task_id=task_id,
            source_ref=source_ref,
            action_ref=action_ref,
        )

    def previews(self) -> dict[str, Any]:
        return {
            "ok": True,
            "previews": self.store.list_impact_previews(limit=100),
        }

    def execution(self) -> dict[str, Any]:
        return {
            "ok": True,
            "failures": self.store.list_failure_observations(limit=100),
            "circuits": self.store.list_circuits(limit=100),
        }

    def reset_circuit(
        self, circuit_id: str, *, reason: str = "Reset by user"
    ) -> dict[str, Any]:
        return self.metis.reset_circuit(circuit_id, reason=reason)

    # ------------------------------------------------------------------
    # Hephaestus: forged playbooks and safety leases
    # ------------------------------------------------------------------
    def forge_read_model(self) -> dict[str, Any]:
        return self.hephaestus.read_model()

    def distill_trace(self, session_id: str) -> dict[str, Any]:
        return self.hephaestus.distill(session_id)

    def preview_forge(self, session_id: str, **kwargs: Any) -> dict[str, Any]:
        return self.hephaestus.preview_forge(session_id, **kwargs)

    def forge_playbook(self, session_id: str, **kwargs: Any) -> dict[str, Any]:
        return self.hephaestus.forge(session_id, **kwargs)

    def issue_lease(self, playbook_id: str, **kwargs: Any) -> dict[str, Any]:
        return self.hephaestus.issue_lease(playbook_id, **kwargs)

    def revoke_lease(self, lease_id: str, **kwargs: Any) -> dict[str, Any]:
        return self.hephaestus.revoke_lease(lease_id, **kwargs)

    def quarantine_playbook(self, playbook_id: str, **kwargs: Any) -> dict[str, Any]:
        return self.hephaestus.quarantine_playbook(playbook_id, **kwargs)

    def unquarantine_playbook(self, playbook_id: str, **kwargs: Any) -> dict[str, Any]:
        return self.hephaestus.unquarantine_playbook(playbook_id, **kwargs)

    # ------------------------------------------------------------------
    # Maintenance
    # ------------------------------------------------------------------
    def apply_retention(self, days: int | None = None) -> dict[str, int]:
        return self.store.apply_retention(
            days if days is not None else self.config.episode_retention_days
        )


def _dream_summary(run: dict[str, Any] | None) -> dict[str, Any] | None:
    if not run:
        return None
    return {
        "id": run.get("id"),
        "status": run.get("status"),
        "completed_at": run.get("completed_at"),
        "episodes_processed": run.get("episodes_processed"),
        "candidates_created": run.get("candidates_created"),
        "contradictions": len(run.get("contradictions") or []),
    }


def _lab_summary(run: dict[str, Any] | None) -> dict[str, Any] | None:
    if not run:
        return None
    return {
        "id": run.get("id"),
        "run_at": run.get("run_at"),
        "policy_version": run.get("policy_version"),
        "passed": run.get("passed"),
        "total": run.get("total"),
    }


def _resume_summary(brief: dict[str, Any] | None) -> dict[str, Any] | None:
    if not brief:
        return None
    return {
        "id": brief.get("id"),
        "checkpoint_id": brief.get("checkpoint_id"),
        "created_at": brief.get("created_at"),
        "active": brief.get("active"),
        "preview": str(brief.get("brief") or "")[:280],
    }
