"""Validated, bounded configuration for Continuum.

The host owns the settings form and the persisted ``config.yaml``.  This class
is the in-process, typed view used by hooks and services.  Invalid values fall
back to safe defaults rather than making the plugin fail to load.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any


@dataclass(frozen=True)
class ContinuumConfig:
    recall_limit: int = 5
    episode_retention_days: int = 30
    context_trust_window_minutes: int = 30
    tripwire_audit_allowed: bool = True
    enable_source_labels: bool = True
    enable_memory_capture: bool = True
    checkpoint_dir: str = ""
    max_recall_chars: int = 1800
    max_episode_excerpt_chars: int = 600
    dream_episode_limit: int = 100
    checkpoint_max_bytes: int = 32 * 1024 * 1024
    # Kairos (environmental reality)
    enable_kairos: bool = True
    kairos_scope: str = ""
    kairos_max_files: int = 200
    kairos_max_file_bytes: int = 2 * 1024 * 1024
    kairos_required_tools: str = ""
    # Aletheia (evidence protection)
    enable_aletheia: bool = True
    # Telos (goal and intent integrity)
    enable_telos: bool = True
    telos_context_chars: int = 900
    telos_drift_after_actions: int = 8
    # Moirai (impact preview)
    enable_moirai: bool = True
    moirai_max_items: int = 50
    # Metis (retry-loop governance)
    enable_metis: bool = True
    metis_failure_threshold: int = 3
    metis_window_minutes: int = 30
    metis_circuit_minutes: int = 30
    # Hephaestus (verified trace distillation and safety leases)
    enable_hephaestus: bool = True
    hephaestus_artifact_dir: str = ""
    hephaestus_min_confidence: float = 0.5
    hephaestus_max_trace_events: int = 5000
    hephaestus_max_steps: int = 80
    hephaestus_lease_minutes: int = 1440
    hephaestus_max_lease_days: int = 30
    hephaestus_cron_enforce: bool = True
    hephaestus_quarantine_untrusted_skill_writes: bool = True

    def clamped(self) -> "ContinuumConfig":
        return replace(
            self,
            recall_limit=max(1, min(10, int(self.recall_limit))),
            episode_retention_days=max(1, min(3650, int(self.episode_retention_days))),
            context_trust_window_minutes=max(
                1, min(1440, int(self.context_trust_window_minutes))
            ),
            max_recall_chars=max(400, min(6000, int(self.max_recall_chars))),
            max_episode_excerpt_chars=max(
                120, min(2000, int(self.max_episode_excerpt_chars))
            ),
            dream_episode_limit=max(1, min(500, int(self.dream_episode_limit))),
            checkpoint_max_bytes=max(
                1024 * 1024, min(128 * 1024 * 1024, int(self.checkpoint_max_bytes))
            ),
            kairos_max_files=max(1, min(2000, int(self.kairos_max_files))),
            kairos_max_file_bytes=max(
                4096, min(32 * 1024 * 1024, int(self.kairos_max_file_bytes))
            ),
            telos_context_chars=max(300, min(3000, int(self.telos_context_chars))),
            telos_drift_after_actions=max(
                3, min(100, int(self.telos_drift_after_actions))
            ),
            moirai_max_items=max(1, min(500, int(self.moirai_max_items))),
            metis_failure_threshold=max(
                2, min(20, int(self.metis_failure_threshold))
            ),
            metis_window_minutes=max(1, min(1440, int(self.metis_window_minutes))),
            metis_circuit_minutes=max(1, min(1440, int(self.metis_circuit_minutes))),
            hephaestus_artifact_dir=str(self.hephaestus_artifact_dir or "").strip(),
            hephaestus_min_confidence=max(
                0.0, min(1.0, float(self.hephaestus_min_confidence))
            ),
            hephaestus_max_trace_events=max(
                100, min(10000, int(self.hephaestus_max_trace_events))
            ),
            hephaestus_max_steps=max(1, min(200, int(self.hephaestus_max_steps))),
            hephaestus_lease_minutes=max(
                5, min(43200, int(self.hephaestus_lease_minutes))
            ),
            hephaestus_max_lease_days=max(
                1, min(365, int(self.hephaestus_max_lease_days))
            ),
        )

    @classmethod
    def from_getter(cls, getter: Any) -> "ContinuumConfig":
        """Build from ``ctx.get_config``-compatible callable.

        The callable is deliberately called with only the keys this class
        understands.  Any exception falls back to the default for that key.
        """

        def read(key: str, default: Any) -> Any:
            try:
                return getter(key, default)
            except Exception:
                return default

        return cls(
            recall_limit=_as_int(read("recall_limit", 5), 5),
            episode_retention_days=_as_int(
                read("episode_retention_days", 30), 30
            ),
            context_trust_window_minutes=_as_int(
                read("context_trust_window_minutes", 30), 30
            ),
            tripwire_audit_allowed=_as_bool(
                read("tripwire_audit_allowed", True), True
            ),
            enable_source_labels=_as_bool(
                read("enable_source_labels", True), True
            ),
            enable_memory_capture=_as_bool(
                read("enable_memory_capture", True), True
            ),
            checkpoint_dir=str(read("checkpoint_dir", "") or ""),
            max_recall_chars=_as_int(read("max_recall_chars", 1800), 1800),
            max_episode_excerpt_chars=_as_int(
                read("max_episode_excerpt_chars", 600), 600
            ),
            dream_episode_limit=_as_int(read("dream_episode_limit", 100), 100),
            checkpoint_max_bytes=_as_int(
                read("checkpoint_max_bytes", 32 * 1024 * 1024),
                32 * 1024 * 1024,
            ),
            enable_kairos=_as_bool(read("enable_kairos", True), True),
            kairos_scope=str(read("kairos_scope", "") or "").strip(),
            kairos_max_files=_as_int(read("kairos_max_files", 200), 200),
            kairos_max_file_bytes=_as_int(
                read("kairos_max_file_bytes", 2 * 1024 * 1024), 2 * 1024 * 1024
            ),
            kairos_required_tools=str(
                read("kairos_required_tools", "") or ""
            ).strip(),
            enable_aletheia=_as_bool(read("enable_aletheia", True), True),
            enable_telos=_as_bool(read("enable_telos", True), True),
            telos_context_chars=_as_int(read("telos_context_chars", 900), 900),
            telos_drift_after_actions=_as_int(
                read("telos_drift_after_actions", 8), 8
            ),
            enable_moirai=_as_bool(read("enable_moirai", True), True),
            moirai_max_items=_as_int(read("moirai_max_items", 50), 50),
            enable_metis=_as_bool(read("enable_metis", True), True),
            metis_failure_threshold=_as_int(
                read("metis_failure_threshold", 3), 3
            ),
            metis_window_minutes=_as_int(read("metis_window_minutes", 30), 30),
            metis_circuit_minutes=_as_int(read("metis_circuit_minutes", 30), 30),
            enable_hephaestus=_as_bool(read("enable_hephaestus", True), True),
            hephaestus_artifact_dir=str(
                read("hephaestus_artifact_dir", "") or ""
            ).strip(),
            hephaestus_min_confidence=_as_float(
                read("hephaestus_min_confidence", 0.5), 0.5
            ),
            hephaestus_max_trace_events=_as_int(
                read("hephaestus_max_trace_events", 5000), 5000
            ),
            hephaestus_max_steps=_as_int(read("hephaestus_max_steps", 80), 80),
            hephaestus_lease_minutes=_as_int(
                read("hephaestus_lease_minutes", 1440), 1440
            ),
            hephaestus_max_lease_days=_as_int(
                read("hephaestus_max_lease_days", 30), 30
            ),
            hephaestus_cron_enforce=_as_bool(
                read("hephaestus_cron_enforce", True), True
            ),
            hephaestus_quarantine_untrusted_skill_writes=_as_bool(
                read("hephaestus_quarantine_untrusted_skill_writes", True), True
            ),
        ).clamped()


def _as_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _as_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
    if isinstance(value, (int, float)):
        return bool(value)
    return default
