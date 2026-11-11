"""Continuum's controlled vocabulary and shared constants."""

from __future__ import annotations

PLUGIN_ID = "hermes-continuum"
PLUGIN_VERSION = "0.3.0"
SCHEMA_VERSION = 3
POLICY_VERSION = "tripwire-1"
CHECKPOINT_FORMAT_VERSION = 2

# The event vocabulary is intentionally small.  Unknown types are rejected by
# the store so a typo cannot silently create an unqueryable history.
EVENT_TYPES: frozenset[str] = frozenset(
    {
        "session_started",
        "session_observed",
        "session_ended",
        "session_finalized",
        "session_reset",
        "tool_result_observed",
        "source_labeled",
        "action_evaluated",
        "action_blocked",
        "approval_requested",
        "approval_observed",
        "user_correction",
        "episode_captured",
        "memory_candidate_created",
        "memory_confirmed",
        "memory_rejected",
        "memory_edited",
        "memory_superseded",
        "memory_deleted",
        "dream_started",
        "dream_completed",
        "dream_skipped",
        "checkpoint_created",
        "checkpoint_exported",
        "checkpoint_imported",
        "checkpoint_failed",
        "restore_brief_created",
        "attack_lab_completed",
        "retention_applied",
        "data_deleted",
        # Kairos: environmental reality.
        "world.snapshotted",
        "reality.diffed",
        "precondition.failed",
        # Aletheia: evidence and protected work.
        "evidence.recorded",
        "evidence.confirmed",
        "evidence.staled",
        "evidence.superseded",
        "evidence.rejected",
        "work.protected",
        "work.released",
        "challenge.detected",
        "action.held",
        "action.unlocked",
        # Telos: goal and intent integrity.
        "charter.created",
        "charter.amended",
        "drift.flagged",
        "subgoal.advanced",
        "completion.scored",
        # Moirai: action-impact preview.
        "action.previewed",
        "action.preview_limited",
        "action.preview_unsupported",
        # Metis: execution and retry-loop governance.
        "execution.failure_observed",
        "execution.loop_detected",
        "execution.circuit_opened",
        "execution.circuit_closed",
        "execution.strategy_changed",
        "execution.budget_exhausted",
        # Oneiros: evidence-aware re-verification.
        "memory.reverification_required",
        # Hephaestus: verified trace distillation, forged artifacts, and leases.
        "playbook.forged",
        "skill.forged",
        "blueprint.forged",
        "skill.quarantined",
        "skill.unquarantined",
        "lease.issued",
        "lease.checked",
        "lease.violation",
        "lease.revoked",
    }
)

TRUST_LABELS: frozenset[str] = frozenset(
    {
        "USER_AUTHORED",
        "UNTRUSTED_EXTERNAL",
        "LOCAL_TOOL_OUTPUT",
        "PLUGIN_GENERATED",
        "DERIVED_FROM_SOURCE",
        "UNKNOWN",
    }
)

PROVENANCE_CONFIDENCE: frozenset[str] = frozenset({"DIRECT", "DERIVED", "UNKNOWN"})
SENSITIVITY_LEVELS: frozenset[str] = frozenset(
    {"public", "internal", "sensitive", "unknown"}
)
MEMORY_STATUSES: frozenset[str] = frozenset(
    {"candidate", "confirmed", "contradicted", "superseded", "rejected"}
)
SECURITY_OUTCOMES: frozenset[str] = frozenset({"allow", "block", "approve"})

# Tools whose results may be annotated.  write_file / patch / skill_manage are
# deliberately excluded: security-guidance owns those result transformations.
NO_LABEL_TOOLS: frozenset[str] = frozenset(
    {"write_file", "patch", "skill_manage", "file_write", "file_edit"}
)
EXTERNAL_TOOLS: frozenset[str] = frozenset(
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
    }
)
LOCAL_FILE_TOOLS: frozenset[str] = frozenset(
    {"read_file", "file_read", "view_file", "terminal", "process_manage"}
)
SENSITIVE_TOOL_HINTS: frozenset[str] = frozenset(
    {
        "terminal",
        "browser_exec",
        "browser_cdp",
        "write_file",
        "patch",
        "file_write",
        "file_edit",
        "delete_file",
        "send_email",
        "send_message",
        "upload_file",
        "post_message",
        "webhook",
        "deploy",
        "publish",
    }
)

MODULE_PREFIXES: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "Tripwire",
        (
            "tool_result_observed",
            "source_labeled",
            "action_evaluated",
            "action_blocked",
            "approval_requested",
            "approval_observed",
            "attack_lab_completed",
        ),
    ),
    (
        "Oneiros",
        (
            "user_correction",
            "episode_captured",
            "memory_candidate_created",
            "memory_confirmed",
            "memory_rejected",
            "memory_edited",
            "memory_superseded",
            "memory_deleted",
            "dream_started",
            "dream_completed",
            "dream_skipped",
        ),
    ),
    (
        "Continuum",
        (
            "session_started",
            "session_observed",
            "session_ended",
            "session_finalized",
            "session_reset",
            "checkpoint_created",
            "checkpoint_exported",
            "checkpoint_imported",
            "checkpoint_failed",
            "restore_brief_created",
        ),
    ),
    (
        "Kairos",
        (
            "world.snapshotted",
            "reality.diffed",
            "precondition.failed",
        ),
    ),
    (
        "Aletheia",
        (
            "evidence.recorded",
            "evidence.confirmed",
            "evidence.staled",
            "evidence.superseded",
            "evidence.rejected",
            "work.protected",
            "work.released",
            "challenge.detected",
            "action.held",
            "action.unlocked",
        ),
    ),
    (
        "Telos",
        (
            "charter.created",
            "charter.amended",
            "drift.flagged",
            "subgoal.advanced",
            "completion.scored",
        ),
    ),
    (
        "Moirai",
        (
            "action.previewed",
            "action.preview_limited",
            "action.preview_unsupported",
        ),
    ),
    (
        "Metis",
        (
            "execution.failure_observed",
            "execution.loop_detected",
            "execution.circuit_opened",
            "execution.circuit_closed",
            "execution.strategy_changed",
            "execution.budget_exhausted",
        ),
    ),
    (
        "Hephaestus",
        (
            "playbook.forged",
            "skill.forged",
            "blueprint.forged",
            "skill.quarantined",
            "skill.unquarantined",
            "lease.issued",
            "lease.checked",
            "lease.violation",
            "lease.revoked",
        ),
    ),
)


def module_for_event(event_type: str) -> str:
    for module, types in MODULE_PREFIXES:
        if event_type in types:
            return module
    return "System"


def event_types_for_module(module: str) -> tuple[str, ...]:
    for name, types in MODULE_PREFIXES:
        if name.lower() == module.lower():
            return types
    return ()
