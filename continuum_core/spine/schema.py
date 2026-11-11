"""SQLite schema and migration definitions.

Only the plugin's own database is touched.  Hermes' private session database is
never opened or modified.  The schema is additive and versioned; future
releases can add migrations without assuming a fresh install.
"""

from __future__ import annotations

import re
from typing import Iterable

from ..common.errors import StorageError
from ..constants import SCHEMA_VERSION

SCHEMA_V1 = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    event_type TEXT NOT NULL,
    timestamp_utc TEXT NOT NULL,
    session_id TEXT,
    turn_id TEXT,
    task_id TEXT,
    tool_call_id TEXT,
    device_id TEXT NOT NULL,
    source_ref TEXT,
    trust_label TEXT,
    sensitivity TEXT,
    memory_ref TEXT,
    security_decision TEXT,
    checkpoint_ref TEXT,
    payload_ref TEXT,
    schema_version INTEGER NOT NULL,
    summary TEXT NOT NULL,
    details_json TEXT NOT NULL DEFAULT '{}',
    idempotency_key TEXT UNIQUE,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp_utc DESC);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type, timestamp_utc DESC);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id, timestamp_utc DESC);
CREATE INDEX IF NOT EXISTS idx_events_source ON events(source_ref);
CREATE INDEX IF NOT EXISTS idx_events_memory ON events(memory_ref);
CREATE INDEX IF NOT EXISTS idx_events_checkpoint ON events(checkpoint_ref);

CREATE TABLE IF NOT EXISTS sources (
    id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE,
    session_id TEXT,
    turn_id TEXT,
    task_id TEXT,
    tool_call_id TEXT,
    tool_name TEXT NOT NULL,
    source_type TEXT NOT NULL,
    reference TEXT,
    trust_label TEXT NOT NULL,
    provenance_confidence TEXT NOT NULL,
    sensitivity TEXT NOT NULL,
    first_seen_utc TEXT NOT NULL,
    last_seen_utc TEXT NOT NULL,
    details_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_sources_session ON sources(session_id, first_seen_utc DESC);
CREATE INDEX IF NOT EXISTS idx_sources_trust ON sources(trust_label, first_seen_utc DESC);

CREATE TABLE IF NOT EXISTS episodes (
    id TEXT PRIMARY KEY,
    event_id TEXT,
    session_id TEXT,
    turn_id TEXT,
    task_id TEXT,
    captured_at TEXT NOT NULL,
    reason TEXT NOT NULL,
    user_excerpt TEXT NOT NULL DEFAULT '',
    assistant_excerpt TEXT NOT NULL DEFAULT '',
    source_ref TEXT,
    trust_label TEXT,
    sensitivity TEXT NOT NULL DEFAULT 'unknown',
    content_hash TEXT NOT NULL UNIQUE,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    dream_run_id TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_episodes_captured ON episodes(captured_at DESC);
CREATE INDEX IF NOT EXISTS idx_episodes_session ON episodes(session_id, captured_at DESC);
CREATE INDEX IF NOT EXISTS idx_episodes_dream ON episodes(dream_run_id);

CREATE TABLE IF NOT EXISTS memory_facts (
    id TEXT PRIMARY KEY,
    fact_key TEXT NOT NULL,
    value TEXT NOT NULL,
    status TEXT NOT NULL,
    confidence REAL NOT NULL,
    source_ref TEXT,
    source_event_id TEXT,
    episode_id TEXT,
    first_observed_utc TEXT NOT NULL,
    last_observed_utc TEXT NOT NULL,
    confirmed_at TEXT,
    superseded_by TEXT,
    contradicts_fact_id TEXT,
    version INTEGER NOT NULL,
    provenance TEXT NOT NULL,
    notes TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    reviewed_by TEXT,
    UNIQUE(fact_key, version)
);
CREATE INDEX IF NOT EXISTS idx_memory_key ON memory_facts(fact_key, version DESC);
CREATE INDEX IF NOT EXISTS idx_memory_status ON memory_facts(status, last_observed_utc DESC);
CREATE INDEX IF NOT EXISTS idx_memory_episode ON memory_facts(episode_id);
CREATE INDEX IF NOT EXISTS idx_memory_source ON memory_facts(source_ref);

CREATE TABLE IF NOT EXISTS security_decisions (
    id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE,
    rule_key TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    action_category TEXT NOT NULL,
    outcome TEXT NOT NULL,
    reason TEXT NOT NULL,
    evidence_json TEXT NOT NULL DEFAULT '{}',
    redacted_args_json TEXT NOT NULL DEFAULT '{}',
    session_id TEXT,
    tool_call_id TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_decisions_outcome ON security_decisions(outcome, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_decisions_session ON security_decisions(session_id, created_at DESC);

CREATE TABLE IF NOT EXISTS checkpoints (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    filename TEXT NOT NULL,
    format_version INTEGER NOT NULL,
    source_installation_id TEXT NOT NULL,
    counts_json TEXT NOT NULL DEFAULT '{}',
    excluded_json TEXT NOT NULL DEFAULT '[]',
    checksum TEXT,
    status TEXT NOT NULL,
    imported_at TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    resume_brief_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_checkpoints_created ON checkpoints(created_at DESC);

CREATE TABLE IF NOT EXISTS dream_runs (
    id TEXT PRIMARY KEY,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    status TEXT NOT NULL,
    from_event_id INTEGER,
    to_event_id INTEGER,
    episodes_processed INTEGER NOT NULL DEFAULT 0,
    candidates_created INTEGER NOT NULL DEFAULT 0,
    contradictions_json TEXT NOT NULL DEFAULT '[]',
    report_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_dream_completed ON dream_runs(completed_at DESC);

CREATE TABLE IF NOT EXISTS attack_lab_runs (
    id TEXT PRIMARY KEY,
    run_at TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    total INTEGER NOT NULL,
    passed INTEGER NOT NULL,
    results_json TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS resume_briefs (
    id TEXT PRIMARY KEY,
    checkpoint_id TEXT,
    created_at TEXT NOT NULL,
    brief TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    active INTEGER NOT NULL DEFAULT 1,
    last_injected_session TEXT,
    dismissed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_resume_active ON resume_briefs(active, created_at DESC);
"""


SCHEMA_V2 = """
-- Environment fingerprints and reality diffs (Kairos).
CREATE TABLE IF NOT EXISTS kairos_snapshots (
    id TEXT PRIMARY KEY,
    event_id TEXT,
    session_id TEXT,
    task_id TEXT,
    checkpoint_ref TEXT,
    label TEXT NOT NULL DEFAULT '',
    scope_path TEXT NOT NULL,
    captured_at TEXT NOT NULL,
    fingerprint_hash TEXT NOT NULL,
    fingerprint_json TEXT NOT NULL DEFAULT '{}',
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_kairos_captured ON kairos_snapshots(captured_at DESC);
CREATE INDEX IF NOT EXISTS idx_kairos_checkpoint ON kairos_snapshots(checkpoint_ref);
CREATE INDEX IF NOT EXISTS idx_kairos_hash ON kairos_snapshots(fingerprint_hash);

CREATE TABLE IF NOT EXISTS kairos_diffs (
    id TEXT PRIMARY KEY,
    event_id TEXT,
    snapshot_id TEXT,
    checkpoint_id TEXT,
    session_id TEXT,
    task_id TEXT,
    checked_at TEXT NOT NULL,
    level TEXT NOT NULL,
    changed_json TEXT NOT NULL DEFAULT '[]',
    unverified_json TEXT NOT NULL DEFAULT '[]',
    summary TEXT NOT NULL,
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_kairos_diffs_checked ON kairos_diffs(checked_at DESC);
CREATE INDEX IF NOT EXISTS idx_kairos_diffs_checkpoint ON kairos_diffs(checkpoint_id);

-- Evidence receipts, protected artifacts, and challenges (Aletheia).
CREATE TABLE IF NOT EXISTS aletheia_receipts (
    id TEXT PRIMARY KEY,
    event_id TEXT,
    session_id TEXT,
    task_id TEXT,
    artifact_ref TEXT NOT NULL,
    artifact_type TEXT NOT NULL,
    verification_method TEXT NOT NULL,
    observed_result TEXT NOT NULL DEFAULT '',
    scope TEXT NOT NULL DEFAULT '',
    content_hash TEXT,
    environment_hash TEXT,
    environment_snapshot_id TEXT,
    source_ref TEXT,
    trust_label TEXT NOT NULL DEFAULT 'PLUGIN_GENERATED',
    provenance TEXT NOT NULL DEFAULT 'PLUGIN_GENERATED',
    verified INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'unverified',
    receipt_json TEXT NOT NULL DEFAULT '{}',
    memory_ref TEXT,
    superseded_by TEXT,
    stale_reason TEXT,
    verified_at TEXT,
    staled_at TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_aletheia_receipts_artifact
    ON aletheia_receipts(artifact_ref, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_aletheia_receipts_status
    ON aletheia_receipts(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_aletheia_receipts_env ON aletheia_receipts(environment_hash);
CREATE INDEX IF NOT EXISTS idx_aletheia_receipts_memory ON aletheia_receipts(memory_ref);

CREATE TABLE IF NOT EXISTS aletheia_protected (
    id TEXT PRIMARY KEY,
    event_id TEXT,
    artifact_ref TEXT NOT NULL,
    artifact_type TEXT NOT NULL DEFAULT 'artifact',
    receipt_id TEXT,
    scope TEXT NOT NULL DEFAULT '',
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    released_at TEXT,
    release_reason TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_aletheia_protected_active
    ON aletheia_protected(artifact_ref) WHERE active = 1;
CREATE INDEX IF NOT EXISTS idx_aletheia_protected_receipt ON aletheia_protected(receipt_id);

CREATE TABLE IF NOT EXISTS aletheia_challenges (
    id TEXT PRIMARY KEY,
    event_id TEXT,
    artifact_ref TEXT NOT NULL,
    protected_id TEXT,
    tool_name TEXT,
    action_ref TEXT,
    reason TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'held',
    required_evidence_json TEXT NOT NULL DEFAULT '[]',
    resolution TEXT,
    created_at TEXT NOT NULL,
    resolved_at TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_aletheia_challenges_created
    ON aletheia_challenges(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_aletheia_challenges_action ON aletheia_challenges(action_ref);

-- Charters, amendments, drift, and completion assessment (Telos).
CREATE TABLE IF NOT EXISTS telos_charters (
    id TEXT PRIMARY KEY,
    root_id TEXT NOT NULL,
    session_id TEXT,
    task_id TEXT,
    version INTEGER NOT NULL DEFAULT 1,
    parent_id TEXT,
    original_request TEXT NOT NULL,
    constraints_json TEXT NOT NULL DEFAULT '[]',
    success_criteria_json TEXT NOT NULL DEFAULT '[]',
    subgoals_json TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'active',
    provenance TEXT NOT NULL DEFAULT 'USER_AUTHORED',
    source_ref TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_telos_charters_root ON telos_charters(root_id, version DESC);
CREATE INDEX IF NOT EXISTS idx_telos_charters_session
    ON telos_charters(session_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_telos_charters_status ON telos_charters(status, updated_at DESC);

CREATE TABLE IF NOT EXISTS telos_amendments (
    id TEXT PRIMARY KEY,
    event_id TEXT,
    charter_id TEXT NOT NULL,
    prior_charter_id TEXT,
    amendment TEXT NOT NULL,
    rationale TEXT NOT NULL DEFAULT '',
    approved_by TEXT NOT NULL DEFAULT 'user',
    trust_label TEXT NOT NULL DEFAULT 'USER_AUTHORED',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_telos_amendments_charter ON telos_amendments(charter_id);

CREATE TABLE IF NOT EXISTS telos_drift (
    id TEXT PRIMARY KEY,
    event_id TEXT,
    charter_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'low',
    detail TEXT NOT NULL,
    tool_name TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_telos_drift_charter ON telos_drift(charter_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_telos_drift_open ON telos_drift(status, created_at DESC);

CREATE TABLE IF NOT EXISTS telos_completions (
    id TEXT PRIMARY KEY,
    event_id TEXT,
    charter_id TEXT NOT NULL,
    claimed_complete INTEGER NOT NULL DEFAULT 0,
    outcome TEXT NOT NULL,
    score INTEGER NOT NULL DEFAULT 0,
    criteria_json TEXT NOT NULL DEFAULT '[]',
    evidence_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_telos_completions_charter
    ON telos_completions(charter_id, created_at DESC);

-- Impact previews (Moirai).
CREATE TABLE IF NOT EXISTS moirai_previews (
    id TEXT PRIMARY KEY,
    event_id TEXT,
    session_id TEXT,
    task_id TEXT,
    tool_name TEXT NOT NULL,
    action_category TEXT NOT NULL,
    level TEXT NOT NULL,
    proposed_action TEXT NOT NULL,
    targets_json TEXT NOT NULL DEFAULT '[]',
    creates_json TEXT NOT NULL DEFAULT '[]',
    modifies_json TEXT NOT NULL DEFAULT '[]',
    deletes_json TEXT NOT NULL DEFAULT '[]',
    external_json TEXT NOT NULL DEFAULT '[]',
    payload_summary TEXT NOT NULL DEFAULT '',
    irreversible_json TEXT NOT NULL DEFAULT '[]',
    unknowns_json TEXT NOT NULL DEFAULT '[]',
    confidence REAL NOT NULL DEFAULT 0,
    adapter TEXT NOT NULL DEFAULT 'unknown',
    evidence_json TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'advisory',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_moirai_previews_created ON moirai_previews(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_moirai_previews_level ON moirai_previews(level, created_at DESC);

-- Failure fingerprints, circuits, and attempt budgets (Metis).
CREATE TABLE IF NOT EXISTS metis_failures (
    id TEXT PRIMARY KEY,
    event_id TEXT,
    session_id TEXT,
    task_id TEXT,
    tool_name TEXT NOT NULL,
    signature TEXT NOT NULL,
    args_hash TEXT NOT NULL,
    error_category TEXT NOT NULL,
    error_signature TEXT NOT NULL,
    target_ref TEXT,
    attempt_count INTEGER NOT NULL DEFAULT 1,
    made_progress INTEGER NOT NULL DEFAULT 0,
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_metis_failures_signature
    ON metis_failures(signature, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_metis_failures_tool ON metis_failures(tool_name, created_at DESC);

CREATE TABLE IF NOT EXISTS metis_circuits (
    id TEXT PRIMARY KEY,
    event_id TEXT,
    signature TEXT NOT NULL UNIQUE,
    args_hash TEXT NOT NULL DEFAULT '',
    tool_name TEXT NOT NULL,
    target_ref TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    failure_count INTEGER NOT NULL DEFAULT 0,
    threshold INTEGER NOT NULL DEFAULT 3,
    reason TEXT NOT NULL DEFAULT '',
    alternatives_json TEXT NOT NULL DEFAULT '[]',
    opened_at TEXT NOT NULL,
    last_failure_at TEXT NOT NULL,
    expires_at TEXT,
    closed_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_metis_circuits_status ON metis_circuits(status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_metis_circuits_tool ON metis_circuits(tool_name, status);

-- Oneiros additions: evidence-aware re-verification without deleting memory.
ALTER TABLE memory_facts ADD COLUMN verification_state TEXT NOT NULL DEFAULT 'unverified';
ALTER TABLE memory_facts ADD COLUMN evidence_ref TEXT;
CREATE INDEX IF NOT EXISTS idx_memory_verification
    ON memory_facts(verification_state, last_observed_utc DESC);
"""

# Schema v3 (Hephaestus): forged playbooks, bounded safety leases, and
# per-run lease usage.  Leases are additive guardrails for unattended Cron
# runs; they never replace Tripwire or the host approval engine.
SCHEMA_V3 = """
CREATE TABLE IF NOT EXISTS playbooks (
    id TEXT PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    description TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'draft',
    source_session_id TEXT,
    source_task_id TEXT,
    source_event_start INTEGER,
    source_event_end INTEGER,
    confidence REAL NOT NULL DEFAULT 0,
    steps_attempted INTEGER NOT NULL DEFAULT 0,
    steps_succeeded INTEGER NOT NULL DEFAULT 0,
    trace_hash TEXT NOT NULL DEFAULT '',
    trace_json TEXT NOT NULL DEFAULT '{}',
    skill_path TEXT,
    skill_sha256 TEXT,
    blueprint_key TEXT,
    blueprint_json TEXT NOT NULL DEFAULT '{}',
    lease_id TEXT,
    environment_hash TEXT,
    quarantine_reason TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_playbooks_name ON playbooks(name, version DESC);
CREATE INDEX IF NOT EXISTS idx_playbooks_status ON playbooks(status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_playbooks_source ON playbooks(source_session_id);

CREATE TABLE IF NOT EXISTS safety_leases (
    id TEXT PRIMARY KEY,
    playbook_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    lease_hash TEXT NOT NULL,
    allowed_tools_json TEXT NOT NULL DEFAULT '[]',
    allowed_paths_json TEXT NOT NULL DEFAULT '[]',
    allowed_domains_json TEXT NOT NULL DEFAULT '[]',
    allow_opaque_tools INTEGER NOT NULL DEFAULT 0,
    max_tool_calls INTEGER NOT NULL DEFAULT 200,
    max_file_writes INTEGER NOT NULL DEFAULT 50,
    max_external_calls INTEGER NOT NULL DEFAULT 50,
    cron_job_id TEXT,
    environment_hash TEXT,
    issued_by TEXT NOT NULL DEFAULT 'user',
    issued_at TEXT NOT NULL,
    expires_at TEXT,
    revoked_at TEXT,
    revoked_reason TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_safety_leases_playbook
    ON safety_leases(playbook_id, issued_at DESC);
CREATE INDEX IF NOT EXISTS idx_safety_leases_status
    ON safety_leases(status, expires_at);
CREATE INDEX IF NOT EXISTS idx_safety_leases_cron ON safety_leases(cron_job_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_safety_leases_one_active
    ON safety_leases(playbook_id) WHERE status = 'active';

CREATE TABLE IF NOT EXISTS safety_lease_usage (
    id TEXT PRIMARY KEY,
    lease_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    cron_job_id TEXT,
    tool_calls INTEGER NOT NULL DEFAULT 0,
    file_writes INTEGER NOT NULL DEFAULT 0,
    external_calls INTEGER NOT NULL DEFAULT 0,
    first_seen_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    last_tool TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE(lease_id, run_id)
);
CREATE INDEX IF NOT EXISTS idx_lease_usage_lease
    ON safety_lease_usage(lease_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_lease_usage_run ON safety_lease_usage(run_id);

ALTER TABLE attack_lab_runs ADD COLUMN suite TEXT NOT NULL DEFAULT 'tripwire';
CREATE INDEX IF NOT EXISTS idx_attack_lab_suite
    ON attack_lab_runs(suite, run_at DESC);
"""

# Ordered migrations are the only supported upgrade path.  Statements are
# executed inside one transaction per upgrade step, so a partial table set can
# never be stamped as a completed schema version.
MIGRATIONS: tuple[tuple[int, str], ...] = (
    (1, SCHEMA_V1),
    (2, SCHEMA_V2),
    (3, SCHEMA_V3),
)


def _statements(script: str) -> Iterable[str]:
    """Yield complete SQL statements without using ``executescript``.

    ``sqlite3.Connection.executescript`` may commit an open transaction before
    running, which would defeat migration rollback.  The migration scripts are
    trusted constants and contain no semicolons inside string literals.  Leading
    SQL comment lines are removed before the statement is executed; skipping a
    whole chunk because it begins with a comment would silently omit tables.
    """

    for chunk in re.split(r";\s*(?:\r?\n|$)", script):
        lines = [
            line
            for line in chunk.strip().splitlines()
            if not line.strip().startswith("--")
        ]
        statement = "\n".join(lines).strip()
        if statement:
            yield statement


def migrate(connection, migrations: tuple[tuple[int, str], ...] | None = None) -> int:
    """Bring ``connection`` to the current schema version transactionally.

    Returns the version after migration.  A database from a newer release is
    rejected rather than silently opened with an incomplete schema.  Each
    version is applied in order and the version stamp is written only after all
    statements for that step have succeeded.  Repeated calls are no-ops.
    """

    plan = migrations or MIGRATIONS
    target = max((int(version) for version, _ in plan), default=SCHEMA_VERSION)
    current = int(connection.execute("PRAGMA user_version").fetchone()[0])
    if current > SCHEMA_VERSION:
        raise StorageError(
            f"Continuum database schema {current} is newer than this plugin "
            f"supports ({SCHEMA_VERSION}). Update Hermes Continuum before opening it."
        )
    if current < target:
        # ``connection`` may already be inside an implicit transaction from the
        # store's PRAGMAs.  Close it explicitly before taking the write lock.
        connection.commit()
        try:
            connection.execute("BEGIN IMMEDIATE")
            for version, script in plan:
                if version <= current:
                    continue
                for statement in _statements(script):
                    connection.execute(statement)
                current = version
                connection.execute(f"PRAGMA user_version = {int(version)}")
            connection.execute(
                "INSERT INTO meta(key, value) VALUES('schema_version', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (str(current),),
            )
            connection.commit()
        except Exception as exc:
            try:
                connection.rollback()
            except Exception:
                pass
            if isinstance(exc, StorageError):
                raise
            raise StorageError(
                f"Continuum schema migration failed and was rolled back: {exc}"
            ) from exc
    # The meta row is additive and safe to ensure on every open of an existing
    # current database.
    if current >= 1:
        try:
            connection.execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES('schema_version', ?)",
                (str(current),),
            )
            connection.commit()
        except Exception as exc:
            raise StorageError(f"Continuum schema metadata could not be read: {exc}") from exc
    return current
